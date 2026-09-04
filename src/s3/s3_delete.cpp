#include "s3/s3fs.hpp"

#include "s3/s3_request.hpp"
#include "s3/s3_url.hpp"
#include "s3/s3_xml_response.hpp"

#include "duckdb/common/crypto/md5.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/common/types/blob.hpp"
#include "duckdb/common/unordered_map.hpp"
#include "duckdb/main/secret/secret_manager.hpp"

#include <functional>

namespace duckdb {

static void CombineDeleteHash(hash_t &result, hash_t value) {
	result ^= value + 0x9e3779b97f4a7c15ULL + (result << 6) + (result >> 2);
}

static void AddDeleteHash(hash_t &result, const string &value) {
	CombineDeleteHash(result, std::hash<string> {}(value));
}

static void AddDeleteHash(hash_t &result, idx_t value) {
	CombineDeleteHash(result, std::hash<idx_t> {}(value));
}

template <class ENUM_TYPE>
static void AddDeleteEnumHash(hash_t &result, ENUM_TYPE value) {
	AddDeleteHash(result, static_cast<idx_t>(value));
}

static void AddDeleteAuthHash(hash_t &result, const S3AuthParams &auth_params) {
	auto &provider = auth_params.GetProvider();
	auto &route = provider.GetRoute();
	AddDeleteEnumHash(result, route.type);
	AddDeleteHash(result, route.prefix);
	AddDeleteEnumHash(result, route.origin);
	AddDeleteEnumHash(result, provider.GetCompatibilityProfile());

	auto &credentials = auth_params.GetCredentials();
	AddDeleteHash(result, credentials.region);
	AddDeleteHash(result, credentials.access_key_id);
	AddDeleteHash(result, credentials.secret_access_key);
	AddDeleteHash(result, credentials.session_token);
	AddDeleteHash(result, credentials.oauth2_bearer_token);

	auto &url = auth_params.GetURLParams();
	AddDeleteHash(result, url.endpoint.GetCanonicalValue());
	AddDeleteEnumHash(result, url.endpoint_mode);
	AddDeleteEnumHash(result, url.style);
	AddDeleteHash(result, static_cast<idx_t>(url.compatibility_mode));

	auto &request_options = auth_params.GetRequestOptions();
	AddDeleteHash(result, request_options.kms_key_id);
	AddDeleteHash(result, static_cast<idx_t>(request_options.requester_pays));
	AddDeleteHash(result, request_options.user_project);
}

static void AddDeleteHTTPHash(hash_t &result, const S3RefreshableHTTPParams &http_params) {
	AddDeleteHash(result, http_params.http_proxy);
	AddDeleteHash(result, http_params.http_proxy_port);
	AddDeleteHash(result, http_params.http_proxy_username);
	AddDeleteHash(result, http_params.http_proxy_password);
	AddDeleteHash(result, static_cast<idx_t>(http_params.override_verify_ssl));
	AddDeleteHash(result, static_cast<idx_t>(http_params.verify_ssl));
	AddDeleteHash(result, http_params.bearer_token);

	hash_t headers_hash = 0;
	for (const auto &header : http_params.extra_headers) {
		hash_t header_hash = 0;
		AddDeleteHash(header_hash, header.first);
		AddDeleteHash(header_hash, header.second);
		headers_hash ^= header_hash;
	}
	CombineDeleteHash(result, headers_hash);
}

void S3FileSystem::RemoveFile(const string &path, optional_ptr<FileOpener> opener) {
	auto handle = OpenFile(path, FileFlags::FILE_FLAGS_NULL_IF_NOT_EXISTS, opener);
	if (!handle) {
		FileOpenerInfo info = {path};
		auto auth_params = S3AuthResolver::Resolve(opener, info);
		throw IOException({{"errno", "404"}}, "Could not remove file \"%s\": %s",
		                  S3Url::GetDisplayUrl(path, auth_params), string("No such file or directory"));
	}

	auto &s3fh = handle->Cast<S3FileHandle>();
	auto res = DeleteRequest(*handle, s3fh.path, {});
	if (res->HasRequestError()) {
		auto captured = s3fh.request_session->Capture();
		auto &snapshot = captured.snapshot->Cast<S3RequestSnapshot>();
		throw IOException("S3 delete request for \"%s\" could not be completed: %s",
		                  S3Url::GetDisplayUrl(path, snapshot.auth_params), res->GetRequestError());
	}
	if (res->status != HTTPStatusCode::OK_200 && res->status != HTTPStatusCode::NoContent_204) {
		throw GetHTTPError(*handle, *res, RequestType::DELETE_REQUEST, path);
	}
}

struct S3DeleteBatchUrlInfo {
	string prefix;
	string bucket_http_url;
	S3AuthParams auth_params;
};

struct S3DeleteSecretIdentity {
	string lookup_type;
	string secret_type;
	string provider;
	string name;
	string storage_mode;
	idx_t persist_type = 0;
	vector<string> scope;
	optional_idx score;

	bool operator==(const S3DeleteSecretIdentity &other) const {
		return lookup_type == other.lookup_type && secret_type == other.secret_type && provider == other.provider &&
		       name == other.name && storage_mode == other.storage_mode && persist_type == other.persist_type &&
		       scope == other.scope && score == other.score;
	}

	void AddHash(hash_t &result) const {
		AddDeleteHash(result, lookup_type);
		AddDeleteHash(result, secret_type);
		AddDeleteHash(result, provider);
		AddDeleteHash(result, name);
		AddDeleteHash(result, storage_mode);
		AddDeleteHash(result, persist_type);
		for (const auto &entry : scope) {
			AddDeleteHash(result, entry);
		}
		AddDeleteHash(result, static_cast<idx_t>(score.IsValid()));
		if (score.IsValid()) {
			AddDeleteHash(result, score.GetIndex());
		}
	}
};

struct S3DeleteBatchIdentity {
	S3DeleteBatchUrlInfo url_info;
	S3RefreshableHTTPParams http_params;
	vector<S3DeleteSecretIdentity> selected_secrets;
	bool credential_refresh_enabled = false;
	bool has_refreshable_secret = false;
	string refresh_lookup_directory;
	optional<S3AuthRefreshIdentity> refresh_identity;

	bool operator==(const S3DeleteBatchIdentity &other) const {
		return url_info.prefix == other.url_info.prefix && url_info.bucket_http_url == other.url_info.bucket_http_url &&
		       url_info.auth_params == other.url_info.auth_params && http_params == other.http_params &&
		       selected_secrets == other.selected_secrets &&
		       credential_refresh_enabled == other.credential_refresh_enabled &&
		       has_refreshable_secret == other.has_refreshable_secret &&
		       refresh_lookup_directory == other.refresh_lookup_directory && refresh_identity == other.refresh_identity;
	}

	hash_t Hash() const {
		hash_t result = 0;
		AddDeleteHash(result, url_info.prefix);
		AddDeleteHash(result, url_info.bucket_http_url);
		AddDeleteAuthHash(result, url_info.auth_params);
		AddDeleteHTTPHash(result, http_params);
		for (const auto &secret : selected_secrets) {
			secret.AddHash(result);
		}
		AddDeleteHash(result, static_cast<idx_t>(credential_refresh_enabled));
		AddDeleteHash(result, static_cast<idx_t>(has_refreshable_secret));
		AddDeleteHash(result, refresh_lookup_directory);
		AddDeleteHash(result, static_cast<idx_t>(refresh_identity.has_value()));
		if (refresh_identity) {
			AddDeleteHash(result, static_cast<idx_t>(refresh_identity->use_ssl));
		}
		return result;
	}
};

struct S3DeleteBatchIdentityHash {
	std::size_t operator()(const S3DeleteBatchIdentity &identity) const {
		return identity.Hash();
	}
};

struct S3DeleteBatchEntry {
	string key;
	string secret_lookup_path;
};

static S3DeleteSecretIdentity GetDeleteSecretIdentity(const string &lookup_type, const SecretEntry &secret_entry,
                                                      idx_t score) {
	auto &secret = *secret_entry.secret;
	return {lookup_type,
	        static_cast<const string &>(secret.GetType()),
	        static_cast<const string &>(secret.GetProvider()),
	        static_cast<const string &>(secret.GetName()),
	        secret_entry.storage_mode,
	        static_cast<idx_t>(secret_entry.persist_type),
	        secret.GetScope(),
	        score};
}

static vector<S3DeleteSecretIdentity> GetSelectedSecretIdentities(optional_ptr<FileOpener> opener, const string &path) {
	vector<S3DeleteSecretIdentity> result;
	auto secret_manager = FileOpener::TryGetSecretManager(opener);
	auto transaction = FileOpener::TryGetCatalogTransaction(opener);
	if (!secret_manager || !transaction) {
		return result;
	}

	for (const auto type : S3SecretConfig::SecretTypes()) {
		auto match = secret_manager->LookupSecret(*transaction, path, type);
		if (!match.HasMatch()) {
			result.push_back({type, {}});
			continue;
		}
		result.push_back(GetDeleteSecretIdentity(type, *match.secret_entry, NumericCast<idx_t>(match.score)));
	}
	return result;
}

static string GetDeleteBatchLookupDirectory(const string &path) {
	auto slash_pos = path.rfind('/');
	if (slash_pos == string::npos) {
		return path;
	}
	return path.substr(0, slash_pos + 1);
}

static bool HasRefreshableS3Secret(optional_ptr<FileOpener> opener, const string &path) {
	if (!opener) {
		return false;
	}
	auto secret_types = S3SecretConfig::SecretTypes();
	FileOpenerInfo info = {path};
	KeyValueSecretReader secret_reader(*opener, info, secret_types.data(), secret_types.size());
	Value refresh_info;
	return secret_reader.TryGetSecretKey("refresh_info", refresh_info);
}

static S3DeleteBatchIdentity CreateDeleteBatchIdentity(S3DeleteBatchUrlInfo url_info,
                                                       S3RefreshableHTTPParams http_params,
                                                       optional_ptr<FileOpener> opener, const string &path) {
	auto selected_secrets = GetSelectedSecretIdentities(opener, path);
	auto credential_refresh_enabled = S3RequestExecutor::CredentialRefreshEnabled(opener);
	auto has_refreshable_secret = HasRefreshableS3Secret(opener, path);
	string refresh_lookup_directory;
	optional<S3AuthRefreshIdentity> refresh_identity;
	if (credential_refresh_enabled && has_refreshable_secret) {
		refresh_lookup_directory = GetDeleteBatchLookupDirectory(path);
		refresh_identity = url_info.auth_params.GetRefreshIdentity();
	}
	return {std::move(url_info),        std::move(http_params), std::move(selected_secrets),
	        credential_refresh_enabled, has_refreshable_secret, std::move(refresh_lookup_directory),
	        std::move(refresh_identity)};
}

static string GetS3DeleteContentMD5(const string &body) {
	MD5Context md5_context;
	md5_context.Add(body);
	data_t md5_hash[MD5Context::MD5_HASH_LENGTH_BINARY];
	md5_context.Finish(md5_hash);
	string_t md5_blob(const_char_ptr_cast(md5_hash), MD5Context::MD5_HASH_LENGTH_BINARY);
	return Blob::ToBase64(md5_blob);
}

S3RequestResult S3FileSystem::RunS3BulkDeleteRequest(HTTPRequestSession &session, const string &secret_lookup_url,
                                                     const string &body, idx_t key_count, string &result) {
	auto payload_hash =
	    S3RequestUtil::GetPayloadHash(GetEncryptionUtil(), const_data_ptr_cast(body.data()), body.length());
	auto content_md5 = GetS3DeleteContentMD5(body);
	return S3RequestExecutor::RunSession(
	    GetEncryptionUtil(), session,
	    S3RequestSpec {secret_lookup_url, S3RequestOperation::DELETE_OBJECTS,
	                   [&](const ParsedS3Url &) {
		                   return S3RequestQuery({{"delete", ""}});
	                   },
	                   payload_hash, "application/xml", content_md5},
	    [&](S3RequestData &request_data) {
		    auto maximum_key_count = request_data.auth_params.GetProvider().GetBulkDeleteMaxBatchSize();
		    if (key_count > maximum_key_count) {
			    throw IOException(
			        "Cannot send S3 bulk delete with %llu keys because the current provider policy allows "
			        "at most %llu keys per request",
			        key_count, maximum_key_count);
		    }
		    result.clear();
		    auto &params = request_data.http_params->Cast<HTTPFSParams>();
		    return RunPostRequest(request_data.http_url, request_data.headers, params, result,
		                          const_data_ptr_cast(body.data()), body.length(), [&](BaseRequest &request) {
			                          return S3RequestExecutor::SendSessionRequest(session, request_data.captured,
			                                                                       params, request);
		                          });
	    });
}

void S3FileSystem::RemoveFiles(const vector<string> &paths, optional_ptr<FileOpener> opener) {
	if (paths.empty()) {
		return;
	}

	unordered_map<S3DeleteBatchIdentity, vector<S3DeleteBatchEntry>, S3DeleteBatchIdentityHash> delete_batches;

	for (auto &path : paths) {
		FileOpenerInfo info = {path};
		auto auth_params = S3AuthResolver::Resolve(opener, info);
		auto parsed_url = S3Url::Parse(path, auth_params);

		S3DeleteBatchUrlInfo url_info = {parsed_url.GetPrefix(), parsed_url.GetBucketHTTPUrl(), auth_params};
		auto refreshable_http_params = S3RequestExecutor::ReadRefreshableHTTPParams(opener, path);
		auto identity =
		    CreateDeleteBatchIdentity(std::move(url_info), std::move(refreshable_http_params), opener, path);
		auto entry = delete_batches.find(identity);
		if (entry == delete_batches.end()) {
			entry = delete_batches.emplace(std::move(identity), vector<S3DeleteBatchEntry>()).first;
		}
		entry->second.push_back({parsed_url.GetKey(), path});
	}

	for (auto &batch : delete_batches) {
		auto &url_info = batch.first.url_info;
		auto &entries = batch.second;
		auto maximum_key_count = url_info.auth_params.GetProvider().GetBulkDeleteMaxBatchSize();
		auto delete_session =
		    S3RequestExecutor::CreateSession(opener, entries.front().secret_lookup_path, url_info.auth_params);
		vector<string> keys;
		keys.reserve(entries.size());
		for (auto &entry : entries) {
			keys.push_back(entry.key);
		}

		for (idx_t batch_start = 0; batch_start < keys.size(); batch_start += maximum_key_count) {
			auto batch_end = MinValue<idx_t>(batch_start + maximum_key_count, keys.size());
			auto body = S3XMLWriter::WriteDeleteObjectsRequest(keys, batch_start, batch_end);
			string result;
			auto request_result = RunS3BulkDeleteRequest(*delete_session, entries[batch_start].secret_lookup_path, body,
			                                             batch_end - batch_start, result);
			auto &res = request_result.response;
			auto &request_context = request_result.context;

			if (res->HasRequestError()) {
				throw IOException("S3 bulk delete request for \"%s\" could not be completed: %s",
				                  request_context.display_url, res->GetRequestError());
			}
			if (res->status != HTTPStatusCode::OK_200) {
				throw S3RequestUtil::GetRequestError(request_context, *res);
			}

			S3DeleteObjectsResult delete_result;
			if (!S3XMLResponseParser::TryParseDeleteObjects(result, delete_result)) {
				throw IOException("Malformed S3 bulk delete response for \"%s\"", request_context.display_url);
			}
			if (!delete_result.errors.empty()) {
				vector<string> errors;
				for (const auto &error : delete_result.errors) {
					auto description = StringUtil::Format("\"%s\": %s", error.key, error.code);
					if (!error.message.empty()) {
						description += ": " + error.message;
					}
					errors.push_back(std::move(description));
				}
				throw IOException("S3 bulk delete for \"%s\" failed: %s", request_context.display_url,
				                  StringUtil::Join(errors, "; "));
			}
		}
	}
}

void S3FileSystem::RemoveDirectory(const string &path, optional_ptr<FileOpener> opener) {
	vector<string> files_to_remove;
	ListFiles(
	    path, [&](const string &file, bool is_dir) { files_to_remove.push_back(file); }, opener.get());

	RemoveFiles(files_to_remove, opener);
}

} // namespace duckdb
