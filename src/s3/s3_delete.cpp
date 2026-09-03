#include "s3/s3fs.hpp"

#include "s3/s3_request.hpp"
#include "s3/s3_url.hpp"
#include "s3/s3_xml_response.hpp"

#include "duckdb/common/crypto/md5.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/common/types/blob.hpp"
#include "duckdb/main/secret/secret_manager.hpp"

#include <algorithm>

namespace duckdb {

void S3FileSystem::RemoveFile(const string &path, optional_ptr<FileOpener> opener) {
	auto handle = OpenFile(path, FileFlags::FILE_FLAGS_NULL_IF_NOT_EXISTS, opener);
	if (!handle) {
		FileOpenerInfo info = {path};
		auto auth_params = S3AuthParams::ReadFrom(opener, info);
		S3Url::Resolve(path, auth_params);
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
	string http_proto;
	string host;
	string path;
	S3AuthParams auth_params;
};

struct S3DeleteBatch {
	S3DeleteBatchUrlInfo url_info;
	vector<string> keys;
	vector<string> secret_lookup_paths;
};

struct S3DeleteBatchKeyBuilder {
	void AddString(const string &value) {
		parts.push_back(StringUtil::Format("%s:%s;", to_string(value.size()), value));
	}

	void AddBool(bool value) {
		AddString(value ? string("1") : string("0"));
	}

	void AddIndex(idx_t value) {
		AddString(to_string(value));
	}

	string Build() const {
		return StringUtil::Join(parts, "");
	}

private:
	vector<string> parts;
};

static void AddDeleteBatchUrlKeyParts(S3DeleteBatchKeyBuilder &key_builder, const S3DeleteBatchUrlInfo &url_info) {
	key_builder.AddString(url_info.prefix);
	key_builder.AddString(url_info.http_proto);
	key_builder.AddString(url_info.host);
	key_builder.AddString(url_info.path);
}

static void AddDeleteBatchAuthKeyParts(S3DeleteBatchKeyBuilder &key_builder, const S3AuthParams &auth_params) {
	key_builder.AddIndex(static_cast<idx_t>(auth_params.provider_type));
	key_builder.AddString(auth_params.region);
	key_builder.AddString(auth_params.access_key_id);
	key_builder.AddString(auth_params.secret_access_key);
	key_builder.AddString(auth_params.session_token);
	key_builder.AddString(auth_params.endpoint);
	key_builder.AddIndex(static_cast<idx_t>(auth_params.endpoint_mode));
	key_builder.AddString(auth_params.kms_key_id);
	key_builder.AddString(auth_params.url_style);
	key_builder.AddBool(auth_params.use_ssl);
	key_builder.AddBool(auth_params.s3_url_compatibility_mode);
	key_builder.AddBool(auth_params.requester_pays);
	key_builder.AddString(auth_params.user_project);
	key_builder.AddString(auth_params.oauth2_bearer_token);
}

static void AddDeleteBatchHTTPKeyParts(S3DeleteBatchKeyBuilder &key_builder,
                                       const S3RefreshableHTTPParams &refreshable_http_params) {
	key_builder.AddString(refreshable_http_params.http_proxy);
	key_builder.AddIndex(refreshable_http_params.http_proxy_port);
	key_builder.AddString(refreshable_http_params.http_proxy_username);
	key_builder.AddString(refreshable_http_params.http_proxy_password);
	key_builder.AddBool(refreshable_http_params.override_verify_ssl);
	key_builder.AddBool(refreshable_http_params.verify_ssl);
	key_builder.AddString(refreshable_http_params.bearer_token);

	vector<pair<string, string>> extra_headers;
	for (auto &entry : refreshable_http_params.extra_headers) {
		extra_headers.emplace_back(entry.first, entry.second);
	}
	std::sort(extra_headers.begin(), extra_headers.end());
	for (auto &entry : extra_headers) {
		key_builder.AddString(entry.first);
		key_builder.AddString(entry.second);
	}
}

static void AddDeleteBatchSecretKeyParts(S3DeleteBatchKeyBuilder &key_builder, const SecretEntry &secret_entry) {
	auto &secret = *secret_entry.secret;
	key_builder.AddString(static_cast<const string &>(secret.GetType()));
	key_builder.AddString(static_cast<const string &>(secret.GetProvider()));
	key_builder.AddString(static_cast<const string &>(secret.GetName()));
	key_builder.AddString(secret_entry.storage_mode);
	key_builder.AddIndex(static_cast<idx_t>(secret_entry.persist_type));
	key_builder.AddIndex(secret.GetScope().size());
	for (auto &scope : secret.GetScope()) {
		key_builder.AddString(scope);
	}
}

static void AddDeleteBatchSelectedSecretKeyParts(S3DeleteBatchKeyBuilder &key_builder, optional_ptr<FileOpener> opener,
                                                 const string &path) {
	auto secret_manager = FileOpener::TryGetSecretManager(opener);
	auto transaction = FileOpener::TryGetCatalogTransaction(opener);
	if (!secret_manager || !transaction) {
		key_builder.AddString("");
		return;
	}

	for (const auto type : S3Provider::SecretTypes()) {
		key_builder.AddString(type);
		auto match = secret_manager->LookupSecret(*transaction, path, type);
		if (!match.HasMatch()) {
			key_builder.AddString("");
			continue;
		}
		key_builder.AddIndex(NumericCast<idx_t>(match.score));
		AddDeleteBatchSecretKeyParts(key_builder, *match.secret_entry);
	}
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
	auto secret_types = S3Provider::SecretTypes();
	FileOpenerInfo info = {path};
	KeyValueSecretReader secret_reader(*opener, info, secret_types.data(), secret_types.size());
	Value refresh_info;
	return secret_reader.TryGetSecretKey("refresh_info", refresh_info);
}

static void AddDeleteBatchRefreshKeyParts(S3DeleteBatchKeyBuilder &key_builder, optional_ptr<FileOpener> opener,
                                          const string &path) {
	if (S3RequestExecutor::CredentialRefreshEnabled(opener) && HasRefreshableS3Secret(opener, path)) {
		key_builder.AddString(GetDeleteBatchLookupDirectory(path));
	} else {
		key_builder.AddString("");
	}
}

static string CreateDeleteBatchKey(const S3DeleteBatchUrlInfo &url_info,
                                   const S3RefreshableHTTPParams &refreshable_http_params,
                                   optional_ptr<FileOpener> opener, const string &path) {
	S3DeleteBatchKeyBuilder key_builder;
	AddDeleteBatchUrlKeyParts(key_builder, url_info);
	AddDeleteBatchAuthKeyParts(key_builder, url_info.auth_params);
	AddDeleteBatchHTTPKeyParts(key_builder, refreshable_http_params);
	AddDeleteBatchSelectedSecretKeyParts(key_builder, opener, path);
	AddDeleteBatchRefreshKeyParts(key_builder, opener, path);
	return key_builder.Build();
}

static string GetS3DeleteContentMD5(const string &body) {
	MD5Context md5_context;
	md5_context.Add(body);
	data_t md5_hash[MD5Context::MD5_HASH_LENGTH_BINARY];
	md5_context.Finish(md5_hash);
	string_t md5_blob(const_char_ptr_cast(md5_hash), MD5Context::MD5_HASH_LENGTH_BINARY);
	return Blob::ToBase64(md5_blob);
}

unique_ptr<HTTPResponse> S3FileSystem::RunS3BulkDeleteRequest(HTTPRequestSession &session,
                                                              const string &secret_lookup_url, const string &body,
                                                              idx_t key_count, string &result,
                                                              optional_ptr<S3RequestContext> request_context) {
	auto payload_hash =
	    S3RequestUtil::GetPayloadHash(GetEncryptionUtil(), const_data_ptr_cast(body.data()), body.length());
	auto content_md5 = GetS3DeleteContentMD5(body);
	return S3RequestExecutor::RunSession(
	    GetEncryptionUtil(), session, secret_lookup_url, RequestType::POST_REQUEST, S3RequestTarget::BUCKET,
	    [&](const ParsedS3Url &) {
		    return S3RequestQuery({{"delete", ""}});
	    },
	    payload_hash, "application/xml", content_md5,
	    [&](S3RequestData &request_data) {
		    auto maximum_key_count = S3Provider::GetBulkDeleteMaxBatchSize(request_data.auth_params);
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
	    },
	    {}, request_context);
}

void S3FileSystem::RemoveFiles(const vector<string> &paths, optional_ptr<FileOpener> opener) {
	if (paths.empty()) {
		return;
	}

	unordered_map<string, S3DeleteBatch> delete_batches;

	for (auto &path : paths) {
		FileOpenerInfo info = {path};
		S3AuthParams auth_params = S3AuthParams::ReadFrom(opener, info);
		auto parsed_url = S3Url::Resolve(path, auth_params);

		auto bucket_path = parsed_url.GetBucketPath();
		S3DeleteBatchUrlInfo url_info = {parsed_url.prefix, parsed_url.http_proto, parsed_url.host, bucket_path,
		                                 auth_params};
		auto refreshable_http_params = S3RequestExecutor::ReadRefreshableHTTPParams(opener, path);
		auto batch_key = CreateDeleteBatchKey(url_info, refreshable_http_params, opener, path);
		auto entry = delete_batches.find(batch_key);
		if (entry == delete_batches.end()) {
			S3DeleteBatch batch;
			batch.url_info = std::move(url_info);
			entry = delete_batches.emplace(std::move(batch_key), std::move(batch)).first;
		}
		auto &batch = entry->second;

		batch.keys.push_back(parsed_url.key);
		batch.secret_lookup_paths.push_back(path);
	}

	for (auto &batch_entry : delete_batches) {
		auto &batch = batch_entry.second;
		const vector<string> &keys = batch.keys;
		const vector<string> &secret_lookup_paths = batch.secret_lookup_paths;
		auto &url_info = batch.url_info;
		auto maximum_key_count = S3Provider::GetBulkDeleteMaxBatchSize(url_info.auth_params);
		auto delete_session =
		    S3RequestExecutor::CreateSession(opener, secret_lookup_paths.front(), url_info.auth_params);

		for (idx_t batch_start = 0; batch_start < keys.size(); batch_start += maximum_key_count) {
			auto batch_end = MinValue<idx_t>(batch_start + maximum_key_count, keys.size());
			auto body = S3XMLWriter::WriteDeleteObjectsRequest(keys, batch_start, batch_end);
			string result;
			S3RequestContext request_context;
			auto res = RunS3BulkDeleteRequest(*delete_session, secret_lookup_paths[batch_start], body,
			                                  batch_end - batch_start, result, request_context);

			if (res->HasRequestError()) {
				throw IOException("S3 bulk delete request for \"%s\" could not be completed: %s",
				                  request_context.display_url, res->GetRequestError());
			}
			if (res->status != HTTPStatusCode::OK_200) {
				throw S3RequestUtil::GetError(request_context.auth_params, *res, request_context.request_type,
				                              "bulk-deleting from", request_context.display_url);
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
