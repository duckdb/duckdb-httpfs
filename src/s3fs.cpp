#include "s3fs.hpp"
#include "crypto.hpp"
#include "duckdb.hpp"
#include "duckdb/common/exception/http_exception.hpp"
#include "duckdb/logging/log_type.hpp"
#include "duckdb/logging/file_system_logger.hpp"
#include "duckdb/common/helper.hpp"
#include "duckdb/common/thread.hpp"
#include "duckdb/common/types/timestamp.hpp"
#include "duckdb/function/scalar/strftime_format.hpp"
#include "http_state.hpp"

#include "duckdb/common/string_util.hpp"
#include "duckdb/common/crypto/md5.hpp"
#include "duckdb/common/types/blob.hpp"
#include "duckdb/function/scalar/string_common.hpp"
#include "duckdb/main/client_context_file_opener.hpp"
#include "duckdb/main/secret/secret_manager.hpp"
#include "duckdb/storage/buffer_manager.hpp"
#include "duckdb/common/multi_file/multi_file_list.hpp"
#include "s3_multi_part_upload.hpp"

#include "create_secret_functions.hpp"

#include <algorithm>
#include <iostream>
#include <iostream>

namespace duckdb {

HTTPHeaders CreateS3Header(string url, string query, string host, string service, string method,
                           const S3AuthParams &auth_params, string date_now, string datetime_now, string payload_hash,
                           string content_type, string content_md5) {

	HTTPHeaders res;
	res["Host"] = host;
	// If access key is not set, we don't set the headers at all to allow accessing public files through s3 urls
	if (auth_params.secret_access_key.empty() && auth_params.access_key_id.empty()) {
		return res;
	}

	if (payload_hash == "") {
		payload_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"; // Empty payload hash
	}

	// we can pass date/time but this is mostly useful in testing. normally we just get the current datetime here.
	if (datetime_now.empty()) {
		auto timestamp = Timestamp::GetCurrentTimestamp();
		date_now = StrfTimeFormat::Format(timestamp, "%Y%m%d");
		datetime_now = StrfTimeFormat::Format(timestamp, "%Y%m%dT%H%M%SZ");
	}

	// Only some S3 operations supports SSE-KMS, which this "heuristic" attempts to detect.
	// https://docs.aws.amazon.com/AmazonS3/latest/userguide/specifying-kms-encryption.html#sse-request-headers-kms
	bool use_sse_kms = auth_params.kms_key_id.length() > 0 && (method == "POST" || method == "PUT") &&
	                   query.find("uploadId") == std::string::npos;

	res["x-amz-date"] = datetime_now;
	res["x-amz-content-sha256"] = payload_hash;
	if (auth_params.session_token.length() > 0) {
		res["x-amz-security-token"] = auth_params.session_token;
	}
	if (use_sse_kms) {
		res["x-amz-server-side-encryption"] = "aws:kms";
		res["x-amz-server-side-encryption-aws-kms-key-id"] = auth_params.kms_key_id;
	}

	bool use_requester_pays = auth_params.requester_pays;
	if (use_requester_pays) {
		res["x-amz-request-payer"] = "requester";
	}

	string signed_headers = "";
	hash_bytes canonical_request_hash;
	hash_str canonical_request_hash_str;
	if (content_md5.length() > 0) {
		signed_headers += "content-md5;";
		res["content-md5"] = content_md5;
	}
	if (content_type.length() > 0) {
		signed_headers += "content-type;";
		if (content_type != "application/octet-stream") {
			res["content-type"] = content_type;
		}
	}
	signed_headers += "host;x-amz-content-sha256;x-amz-date";
	if (use_requester_pays) {
		signed_headers += ";x-amz-request-payer";
	}
	if (auth_params.session_token.length() > 0) {
		signed_headers += ";x-amz-security-token";
	}
	if (use_sse_kms) {
		signed_headers += ";x-amz-server-side-encryption;x-amz-server-side-encryption-aws-kms-key-id";
	}
	auto canonical_request = method + "\n" + S3FileSystem::UrlEncode(url) + "\n" + query;
	if (content_md5.length() > 0) {
		canonical_request += "\ncontent-md5:" + content_md5;
	}
	if (content_type.length() > 0) {
		canonical_request += "\ncontent-type:" + content_type;
	}
	canonical_request += "\nhost:" + host + "\nx-amz-content-sha256:" + payload_hash + "\nx-amz-date:" + datetime_now;
	if (use_requester_pays) {
		canonical_request += "\nx-amz-request-payer:requester";
	}
	if (auth_params.session_token.length() > 0) {
		canonical_request += "\nx-amz-security-token:" + auth_params.session_token;
	}
	if (use_sse_kms) {
		canonical_request += "\nx-amz-server-side-encryption:aws:kms";
		canonical_request += "\nx-amz-server-side-encryption-aws-kms-key-id:" + auth_params.kms_key_id;
	}

	canonical_request += "\n\n" + signed_headers + "\n" + payload_hash;

	sha256(canonical_request.c_str(), canonical_request.length(), canonical_request_hash);

	hex256(canonical_request_hash, canonical_request_hash_str);
	auto string_to_sign = "AWS4-HMAC-SHA256\n" + datetime_now + "\n" + date_now + "/" + auth_params.region + "/" +
	                      service + "/aws4_request\n" + string((char *)canonical_request_hash_str, sizeof(hash_str));
	// compute signature
	hash_bytes k_date, k_region, k_service, signing_key, signature;
	hash_str signature_str;
	auto sign_key = "AWS4" + auth_params.secret_access_key;
	hmac256(date_now, sign_key.c_str(), sign_key.length(), k_date);
	hmac256(auth_params.region, k_date, k_region);
	hmac256(service, k_region, k_service);
	hmac256("aws4_request", k_service, signing_key);
	hmac256(string_to_sign, signing_key, signature);
	hex256(signature, signature_str);

	res["Authorization"] = "AWS4-HMAC-SHA256 Credential=" + auth_params.access_key_id + "/" + date_now + "/" +
	                       auth_params.region + "/" + service + "/aws4_request, SignedHeaders=" + signed_headers +
	                       ", Signature=" + string((char *)signature_str, sizeof(hash_str));

	return res;
}

string S3FileSystem::UrlDecode(string input) {
	return StringUtil::URLDecode(input, true);
}

string S3FileSystem::UrlEncode(const string &input, bool encode_slash) {
	return StringUtil::URLEncode(input, encode_slash);
}

static bool IsGCSRequest(const string &url) {
	return StringUtil::StartsWith(url, "gcs://") || StringUtil::StartsWith(url, "gs://");
}

static bool IsAuthRefreshFailure(const ErrorData &error) {
	auto &extra_info = error.ExtraInfo();
	auto entry = extra_info.find("status_code");
	if (entry == extra_info.end()) {
		return false;
	}
	if (entry->second == "401" || entry->second == "403") {
		return true;
	}
	if (entry->second != "400") {
		return false;
	}
	auto body_entry = extra_info.find("response_body");
	if (body_entry == extra_info.end()) {
		return false;
	}
	string code;
	return S3FileSystem::TryGetS3ErrorCode(body_entry->second, code) && code == "ExpiredToken";
}

static bool IsAuthRefreshFailure(const HTTPResponse &response) {
	if (response.status == HTTPStatusCode::Unauthorized_401 || response.status == HTTPStatusCode::Forbidden_403) {
		return true;
	}
	if (response.status != HTTPStatusCode::BadRequest_400) {
		return false;
	}
	string code;
	return S3FileSystem::TryGetS3ErrorCode(response.body, code) && code == "ExpiredToken";
}

static bool S3AuthParamsMatch(const S3AuthParams &left, const S3AuthParams &right) {
	return left.region == right.region && left.access_key_id == right.access_key_id &&
	       left.secret_access_key == right.secret_access_key && left.session_token == right.session_token &&
	       left.endpoint == right.endpoint && left.kms_key_id == right.kms_key_id &&
	       left.url_style == right.url_style && left.use_ssl == right.use_ssl &&
	       left.s3_url_compatibility_mode == right.s3_url_compatibility_mode &&
	       left.requester_pays == right.requester_pays && left.oauth2_bearer_token == right.oauth2_bearer_token;
}

static S3RefreshableHTTPParams SnapshotRefreshableHTTPParams(const HTTPFSParams &params) {
	S3RefreshableHTTPParams result;
	result.http_proxy = params.http_proxy;
	result.http_proxy_port = params.http_proxy.empty() ? 0 : params.http_proxy_port;
	result.http_proxy_username = params.http_proxy_username;
	result.http_proxy_password = params.http_proxy_password;
	result.extra_headers = params.extra_headers;
	result.override_verify_ssl = params.override_verify_ssl;
	result.verify_ssl = params.verify_ssl;
	result.bearer_token = params.bearer_token;
	return result;
}

static void ApplyRefreshableHTTPParams(HTTPFSParams &target, const S3RefreshableHTTPParams &source) {
	target.http_proxy = source.http_proxy;
	target.http_proxy_port = source.http_proxy.empty() ? 0 : source.http_proxy_port;
	target.http_proxy_username = source.http_proxy_username;
	target.http_proxy_password = source.http_proxy_password;
	target.extra_headers = source.extra_headers;
	target.override_verify_ssl = source.override_verify_ssl;
	target.verify_ssl = source.verify_ssl;
	target.bearer_token = source.bearer_token;
	target.pre_merged_headers = false;
}

static bool S3RefreshableHTTPParamsMatch(const S3RefreshableHTTPParams &left, const S3RefreshableHTTPParams &right) {
	return left.http_proxy == right.http_proxy && left.http_proxy_port == right.http_proxy_port &&
	       left.http_proxy_username == right.http_proxy_username &&
	       left.http_proxy_password == right.http_proxy_password && left.extra_headers == right.extra_headers &&
	       left.override_verify_ssl == right.override_verify_ssl && left.verify_ssl == right.verify_ssl &&
	       left.bearer_token == right.bearer_token;
}

static S3AuthParams ReadS3AuthParams(optional_ptr<FileOpener> opener, const string &path) {
	FileOpenerInfo info = {path};
	auto auth_params = S3AuthParams::ReadFrom(opener, info);
	auto parsed_url = S3FileSystem::S3UrlParse(path, auth_params);
	S3FileSystem::ReadQueryParams(parsed_url.query_param, auth_params);
	return auth_params;
}

static S3RefreshableHTTPParams ReadRefreshableHTTPParams(optional_ptr<FileOpener> opener, const string &path) {
	FileOpenerInfo info = {path};
	auto &http_util = HTTPFSUtil::GetHTTPUtil(opener);
	auto params = http_util.InitializeParameters(opener, info);
	return SnapshotRefreshableHTTPParams(params->Cast<HTTPFSParams>());
}

static bool TryRefreshS3SecretForPath(ClientContext &context, const string &path) {
	auto transaction = CatalogTransaction::GetSystemCatalogTransaction(context);
	bool refreshed_secret = false;
	for (const string type : {"s3", "r2", "gcs", "aws"}) {
		auto res = context.db->GetSecretManager().LookupSecret(transaction, path, type);
		if (res.HasMatch()) {
			refreshed_secret |= CreateS3SecretFunctions::TryRefreshS3Secret(context, *res.secret_entry);
		}
	}
	return refreshed_secret;
}

static bool IsS3CredentialRefreshEnabled(optional_ptr<FileOpener> opener) {
	Value value;
	if (FileOpener::TryGetCurrentSetting(opener, "httpfs_enable_credential_refresh", value)) {
		return value.GetValue<bool>();
	}
	return true;
}

static bool ReloadS3AuthMaterial(optional_ptr<FileOpener> opener, const string &path, S3AuthParams &auth_params,
                                 HTTPFSParams &http_params, const S3AuthParams &request_auth_params,
                                 const S3RefreshableHTTPParams &request_http_params, HTTPClientCache *client_cache,
                                 bool preserve_region) {
	if (!opener) {
		return false;
	}

	auto previous_region = auth_params.region;
	auto reloaded_auth_params = ReadS3AuthParams(opener, path);
	if (preserve_region && !previous_region.empty() && reloaded_auth_params.region != previous_region) {
		reloaded_auth_params.SetRegion(std::move(previous_region));
	}
	auto reloaded_http_params = ReadRefreshableHTTPParams(opener, path);

	if (S3AuthParamsMatch(reloaded_auth_params, request_auth_params) &&
	    S3RefreshableHTTPParamsMatch(reloaded_http_params, request_http_params)) {
		return false;
	}

	auth_params = std::move(reloaded_auth_params);
	ApplyRefreshableHTTPParams(http_params, reloaded_http_params);
	if (client_cache) {
		client_cache->Clear();
	}
	return true;
}

static bool TryRefreshS3AuthMaterial(optional_ptr<ClientContext> context, optional_ptr<FileOpener> opener,
                                     const string &path, S3AuthParams &auth_params, HTTPFSParams &http_params,
                                     const S3AuthParams &request_auth_params,
                                     const S3RefreshableHTTPParams &request_http_params,
                                     bool credential_refresh_enabled, HTTPClientCache *client_cache = nullptr,
                                     bool preserve_region = false) {
	if (!credential_refresh_enabled) {
		return false;
	}
	if (!S3AuthParamsMatch(auth_params, request_auth_params) ||
	    !S3RefreshableHTTPParamsMatch(SnapshotRefreshableHTTPParams(http_params), request_http_params)) {
		return true;
	}
	if (!context) {
		return false;
	}
	if (ReloadS3AuthMaterial(opener, path, auth_params, http_params, request_auth_params, request_http_params,
	                         client_cache, preserve_region)) {
		return true;
	}

	auto http_state = HTTPState::TryGetState(*context);
	lock_guard<mutex> refresh_lck(http_state->CredentialRefreshLock());
	if (ReloadS3AuthMaterial(opener, path, auth_params, http_params, request_auth_params, request_http_params,
	                         client_cache, preserve_region)) {
		return true;
	}
	if (!TryRefreshS3SecretForPath(*context, path)) {
		return false;
	}
	return ReloadS3AuthMaterial(opener, path, auth_params, http_params, request_auth_params, request_http_params,
	                            client_cache, preserve_region);
}

static void AddS3HTTPHeaders(HTTPFSParams &http_params, HTTPHeaders &headers) {
	if (!http_params.user_agent.empty()) {
		headers.Insert("User-Agent", http_params.user_agent);
	}
	for (auto &header : http_params.extra_headers) {
		headers[header.first] = header.second;
	}
	http_params.pre_merged_headers = true;
}

struct S3RequestData {
	S3AuthParams auth_params;
	S3RefreshableHTTPParams refreshable_http_params;
	unique_ptr<HTTPParams> http_params;
	string source_url;
	string http_url;
	HTTPHeaders headers;
	string etag;
	bool auto_fallback_to_full_file_download = false;
};

static S3RequestData CreateS3RequestData(const S3AuthParams &auth_params, const HTTPFSParams &http_params,
                                         const string &s3_url, const string &method, const string &query_string,
                                         const string &payload_hash = "", const string &content_type = "",
                                         const string &content_md5 = "") {
	S3RequestData result;
	result.auth_params = auth_params;
	result.http_params = http_params.Clone();
	result.source_url = s3_url;
	auto &httpfs_params = result.http_params->Cast<HTTPFSParams>();
	result.refreshable_http_params = SnapshotRefreshableHTTPParams(httpfs_params);
	auto parsed_s3_url = S3FileSystem::S3UrlParse(s3_url, result.auth_params);

	result.http_url = parsed_s3_url.GetHTTPUrl(result.auth_params, query_string);

	if (IsGCSRequest(s3_url) && !result.auth_params.oauth2_bearer_token.empty()) {
		result.headers["Authorization"] = "Bearer " + result.auth_params.oauth2_bearer_token;
		result.headers["Host"] = parsed_s3_url.host;
		if (!content_type.empty()) {
			result.headers["Content-Type"] = content_type;
		}
	} else {
		result.headers = CreateS3Header(parsed_s3_url.path, query_string, parsed_s3_url.host, "s3", method,
		                                result.auth_params, "", "", payload_hash, content_type, content_md5);
	}
	AddS3HTTPHeaders(httpfs_params, result.headers);
	return result;
}

static S3RequestData CreateS3HandleRequestData(S3FileHandle &s3_handle, const string &s3_url, const string &method,
                                               bool use_version_id) {
	S3AuthParams auth_params;
	unique_ptr<HTTPParams> http_params;
	string version_id;
	string etag;
	bool auto_fallback_to_full_file_download;
	{
		lock_guard<mutex> lck(s3_handle.mu);
		auth_params = s3_handle.auth_params;
		http_params = s3_handle.http_params.Clone();
		version_id = s3_handle.version_id;
		etag = s3_handle.etag;
		auto_fallback_to_full_file_download = s3_handle.auto_fallback_to_full_file_download;
	}

	string query_string;
	if (use_version_id && !version_id.empty()) {
		query_string = "versionId=" + S3FileSystem::UrlEncode(version_id, true);
	}

	auto result = CreateS3RequestData(auth_params, http_params->Cast<HTTPFSParams>(), s3_url, method, query_string);
	result.etag = std::move(etag);
	result.auto_fallback_to_full_file_download = auto_fallback_to_full_file_download;
	return result;
}

static optional_idx GetRegionRedirect(const HTTPResponse &response, const S3AuthParams &auth_params,
                                      string &region_out) {
	if (response.status != HTTPStatusCode::MovedPermanently_301 && response.status != HTTPStatusCode::BadRequest_400) {
		return optional_idx();
	}
	if (!response.HasHeader("x-amz-bucket-region")) {
		return optional_idx();
	}
	auto response_region = response.GetHeaderValue("x-amz-bucket-region");
	if (response_region.empty() || response_region == auth_params.region) {
		return optional_idx();
	}
	region_out = std::move(response_region);
	return optional_idx(0);
}

static optional_idx GetRegionRedirect(const ErrorData &error, const S3AuthParams &auth_params, string &region_out) {
	auto &extra_info = error.ExtraInfo();
	auto entry = extra_info.find("status_code");
	if (entry == extra_info.end() || (entry->second != "301" && entry->second != "400")) {
		return optional_idx();
	}
	auto new_region = extra_info.find("header_x-amz-bucket-region");
	if (new_region == extra_info.end() || new_region->second.empty() || new_region->second == auth_params.region) {
		return optional_idx();
	}
	region_out = new_region->second;
	return optional_idx(0);
}

// Defined later in this file.
optional_idx TryFindTagContents(const string &response, const string &tag, idx_t cur_pos, string &result);

// Core's status-based retry can't catch this: the discriminator is only in the S3 error body.
bool IsS3RequestTimeout(const HTTPResponse &response) {
	if (response.status != HTTPStatusCode::BadRequest_400 || response.body.empty()) {
		return false;
	}
	string code;
	return S3FileSystem::TryGetS3ErrorCode(response.body, code) && code == "RequestTimeout";
}

void S3FileSystem::SleepForS3RequestTimeoutRetry(const HTTPFSParams &http_params, idx_t transient_retries,
                                                 double &wait_ms) {
	if (transient_retries == 0) {
		wait_ms = static_cast<double>(http_params.retry_wait_ms);
		return;
	}
#ifndef DUCKDB_NO_THREADS
	ThreadUtil::SleepMs(static_cast<idx_t>(wait_ms));
#endif
	wait_ms *= http_params.retry_backoff;
}

template <class CREATE_DATA, class REQUEST, class REFRESH, class SET_REGION>
static unique_ptr<HTTPResponse> RunS3RequestWithAuthRefreshInternal(const string &s3_url, CREATE_DATA create_data,
                                                                    REQUEST request, REFRESH refresh_auth_params,
                                                                    SET_REGION set_region) {
	// Auth refresh and region redirect are one-shot.
	bool retried_auth_refresh = false;
	bool retried_region = false;
	for (;;) {
		auto request_data = create_data();
		try {
			auto result = request(request_data);
			if (result && !retried_auth_refresh && IsAuthRefreshFailure(*result) &&
			    refresh_auth_params(request_data.auth_params, request_data.refreshable_http_params)) {
				retried_auth_refresh = true;
				continue;
			}
			string correct_region;
			if (result && !retried_region &&
			    GetRegionRedirect(*result, request_data.auth_params, correct_region).IsValid()) {
				set_region(std::move(correct_region));
				retried_region = true;
				continue;
			}
			return result;
		} catch (std::exception &ex) {
			ErrorData error(ex);
			if (!retried_auth_refresh && IsAuthRefreshFailure(error) &&
			    refresh_auth_params(request_data.auth_params, request_data.refreshable_http_params)) {
				retried_auth_refresh = true;
				continue;
			}
			string correct_region;
			if (!retried_region && GetRegionRedirect(error, request_data.auth_params, correct_region).IsValid()) {
				set_region(std::move(correct_region));
				retried_region = true;
				continue;
			}
			throw;
		}
	}
}

template <class REQUEST>
unique_ptr<HTTPResponse>
S3FileSystem::RunS3InputRequestWithAuthRefresh(S3HTTPInput &s3_input, const string &s3_url, const string &method,
                                               const string &query_string, const string &payload_hash,
                                               const string &content_type, REQUEST request) {
	return RunS3RequestWithAuthRefreshInternal(
	    s3_url,
	    [&]() {
		    lock_guard<mutex> lck(s3_input.mu);
		    return CreateS3RequestData(s3_input.auth_params, s3_input.http_params, s3_url, method, query_string,
		                               payload_hash, content_type);
	    },
	    request,
	    [&](const S3AuthParams &request_auth_params, const S3RefreshableHTTPParams &request_http_params) {
		    return s3_input.TryRefreshAuthParams(s3_url, request_auth_params, request_http_params);
	    },
	    [&](string correct_region) {
		    lock_guard<mutex> lck(s3_input.mu);
		    s3_input.SetRegion(std::move(correct_region));
	    });
}

template <class REQUEST>
unique_ptr<HTTPResponse> S3FileSystem::RunS3HandleRequestWithAuthRefresh(S3FileHandle &s3_handle, const string &s3_url,
                                                                         const string &method, bool use_version_id,
                                                                         REQUEST request) {
	return RunS3RequestWithAuthRefreshInternal(
	    s3_url, [&]() { return CreateS3HandleRequestData(s3_handle, s3_url, method, use_version_id); }, request,
	    [&](const S3AuthParams &request_auth_params, const S3RefreshableHTTPParams &request_http_params) {
		    return s3_handle.TryRefreshAuthParams(request_auth_params, request_http_params);
	    },
	    [&](string correct_region) { s3_handle.SetRegion(std::move(correct_region)); });
}

static unique_ptr<HTTPResponse> SendS3HandleRequestWithClientCache(S3FileHandle &s3_handle, HTTPFSParams &params,
                                                                   BaseRequest &request) {
	auto client_entry = s3_handle.client_cache.GetClientWithGeneration();
	auto response = params.http_util.Request(request, client_entry.client);
	if (!s3_handle.client_cache.StoreClient(client_entry)) {
		params.http_util.CloseClient(std::move(client_entry.client));
	}
	return response;
}

static HTTPException GetS3RequestError(const S3RequestData &request_data, const HTTPResponse &response) {
	if (IsGCSRequest(request_data.source_url) && response.status == HTTPStatusCode::Forbidden_403) {
		string extra_text = S3FileSystem::GetGCSAuthError(request_data.auth_params);
		auto status_message = HTTPFSUtil::GetStatusMessage(response.status);
		return HTTPException(response, "HTTP error on '%s' (HTTP %d %s)%s", request_data.http_url, response.status,
		                     status_message, extra_text);
	}
	return S3FileSystem::GetS3Error(request_data.auth_params, response, request_data.http_url);
}

void AWSEnvironmentCredentialsProvider::SetExtensionOptionValue(string key, const char *env_var_name) {
	char *evar;

	if ((evar = std::getenv(env_var_name)) != NULL) {
		if (StringUtil::Lower(evar) == "false") {
			this->config.SetOption(key, Value(false));
		} else if (StringUtil::Lower(evar) == "true") {
			this->config.SetOption(key, Value(true));
		} else {
			this->config.SetOption(key, Value(evar));
		}
	}
}

void AWSEnvironmentCredentialsProvider::SetAll() {
	this->SetExtensionOptionValue("s3_region", DEFAULT_REGION_ENV_VAR);
	this->SetExtensionOptionValue("s3_region", REGION_ENV_VAR);
	this->SetExtensionOptionValue("s3_access_key_id", ACCESS_KEY_ENV_VAR);
	this->SetExtensionOptionValue("s3_secret_access_key", SECRET_KEY_ENV_VAR);
	this->SetExtensionOptionValue("s3_session_token", SESSION_TOKEN_ENV_VAR);
	this->SetExtensionOptionValue("s3_endpoint", DUCKDB_ENDPOINT_ENV_VAR);
	this->SetExtensionOptionValue("s3_use_ssl", DUCKDB_USE_SSL_ENV_VAR);
	this->SetExtensionOptionValue("s3_kms_key_id", DUCKDB_KMS_KEY_ID_ENV_VAR);
	this->SetExtensionOptionValue("s3_requester_pays", DUCKDB_REQUESTER_PAYS_ENV_VAR);
}

S3AuthParams S3AuthParams::ReadFrom(optional_ptr<FileOpener> opener, FileOpenerInfo &info) {

	// Without a FileOpener we can not access settings nor secrets: return empty auth params
	if (!opener) {
		return {};
	}

	const char *secret_types[] = {"s3", "r2", "gcs", "aws"};
	S3KeyValueReader secret_reader(*opener, info, secret_types, 4);

	return ReadFrom(secret_reader, info.file_path);
}

bool EndpointIsAWS(const string &endpoint) {
	if (endpoint.empty()) {
		// default (empty) endpoint is AWS
		return true;
	}
	if (StringUtil::StartsWith(endpoint, "s3.") && StringUtil::EndsWith(endpoint, ".amazonaws.com")) {
		return true;
	}
	return false;
}

void S3AuthParams::InitializeEndpoint() {
	if (!EndpointIsAWS(endpoint)) {
		return;
	}
	if (region.empty()) {
		if (access_key_id.empty()) {
			// no access key and no region - use legacy global endpoint
			endpoint = "s3.amazonaws.com";
			return;
		}
		// access key but no region - default to us-east-1
		region = "us-east-1";
	}
	endpoint = StringUtil::Format("s3.%s.amazonaws.com", region);
}

S3AuthParams S3AuthParams::ReadFrom(S3KeyValueReader &secret_reader, const string &file_path) {
	auto result = S3AuthParams();

	// These settings we just set or leave to their S3AuthParams default value
	secret_reader.TryGetSecretKeyOrSetting("region", "s3_region", result.region);
	secret_reader.TryGetSecretKeyOrSetting("key_id", "s3_access_key_id", result.access_key_id);
	secret_reader.TryGetSecretKeyOrSetting("secret", "s3_secret_access_key", result.secret_access_key);
	secret_reader.TryGetSecretKeyOrSetting("session_token", "s3_session_token", result.session_token);
	secret_reader.TryGetSecretKeyOrSetting("region", "s3_region", result.region);
	secret_reader.TryGetSecretKeyOrSetting("use_ssl", "s3_use_ssl", result.use_ssl);
	secret_reader.TryGetSecretKeyOrSetting("kms_key_id", "s3_kms_key_id", result.kms_key_id);
	secret_reader.TryGetSecretKeyOrSetting("s3_url_compatibility_mode", "s3_url_compatibility_mode",
	                                       result.s3_url_compatibility_mode);
	secret_reader.TryGetSecretKeyOrSetting("requester_pays", "s3_requester_pays", result.requester_pays);
	// Endpoint and url style are slightly more complex and require special handling for gcs and r2
	auto endpoint_result = secret_reader.TryGetSecretKeyOrSetting("endpoint", "s3_endpoint", result.endpoint);
	auto url_style_result = secret_reader.TryGetSecretKeyOrSetting("url_style", "s3_url_style", result.url_style);

	if (StringUtil::StartsWith(file_path, "gcs://") || StringUtil::StartsWith(file_path, "gs://")) {
		// For GCS urls we force the endpoint and vhost path style, allowing only to be overridden by secrets
		if (result.endpoint.empty() || !endpoint_result || endpoint_result.GetScope() != SettingScope::SECRET) {
			result.endpoint = "storage.googleapis.com";
		}
		if (result.url_style.empty() || !url_style_result || url_style_result.GetScope() != SettingScope::SECRET) {
			result.url_style = "path";
		}
		// Read bearer token for GCS
		secret_reader.TryGetSecretKey("bearer_token", result.oauth2_bearer_token);
	}
	result.InitializeEndpoint();

	return result;
}

void S3AuthParams::SetRegion(string new_region) {
	region = std::move(new_region);
	InitializeEndpoint();
}

unique_ptr<KeyValueSecret> CreateSecret(vector<string> &prefix_paths_p, string &type, string &provider, string &name,
                                        S3AuthParams &params) {
	auto return_value = make_uniq<KeyValueSecret>(prefix_paths_p, type, provider, name);

	//! Set key value map
	return_value->secret_map["region"] = params.region;
	return_value->secret_map["key_id"] = params.access_key_id;
	return_value->secret_map["secret"] = params.secret_access_key;
	return_value->secret_map["session_token"] = params.session_token;
	return_value->secret_map["endpoint"] = params.endpoint;
	return_value->secret_map["url_style"] = params.url_style;
	return_value->secret_map["use_ssl"] = params.use_ssl;
	return_value->secret_map["kms_key_id"] = params.kms_key_id;
	return_value->secret_map["s3_url_compatibility_mode"] = params.s3_url_compatibility_mode;
	return_value->secret_map["requester_pays"] = params.requester_pays;
	return_value->secret_map["bearer_token"] = params.oauth2_bearer_token;

	//! Set redact keys
	return_value->redact_keys = {"secret", "session_token"};
	if (!params.oauth2_bearer_token.empty()) {
		return_value->redact_keys.insert("bearer_token");
	}

	return return_value;
}

S3HTTPInput::S3HTTPInput(unique_ptr<HTTPParams> params_p, const S3AuthParams &auth_params_p,
                         const S3ConfigParams &config_params_p)
    : HTTPInput(std::move(params_p)), auth_params(auth_params_p), config_params(config_params_p) {
}

S3HTTPInput::~S3HTTPInput() {
}

S3FileHandle::S3FileHandle(FileSystem &fs, const OpenFileInfo &file, FileOpenFlags flags,
                           unique_ptr<HTTPParams> http_params_p, const S3AuthParams &auth_params_p,
                           const S3ConfigParams &config_params_p)
    : HTTPFileHandle(fs, file, flags,
                     make_shared_ptr<S3HTTPInput>(std::move(http_params_p), auth_params_p, config_params_p)),
      auth_params(http_input->Cast<S3HTTPInput>().auth_params),
      config_params(http_input->Cast<S3HTTPInput>().config_params) {
	auto_fallback_to_full_file_download = false;
	if (flags.OpenForReading() && flags.OpenForWriting()) {
		throw NotImplementedException("Cannot open an HTTP file for both reading and writing");
	} else if (flags.OpenForAppending()) {
		throw NotImplementedException("Cannot open an HTTP file for appending");
	}
	if (file.extended_info) {
		auto entry = file.extended_info->options.find("s3_region");
		if (entry != file.extended_info->options.end()) {
			SetRegion(entry->second.ToString());
		}
	}
	if (flags.OpenForWriting()) {
		multi_part_upload = make_shared_ptr<S3MultiPartUpload>(*this);
	}
}

S3FileHandle::~S3FileHandle() {
	if (Exception::UncaughtException()) {
		// We are in an exception, don't do anything
		return;
	}

	try {
		Close();
	} catch (...) { // NOLINT
	}
}

void S3FileHandle::SetRegion(string region_p) {
	lock_guard<mutex> lck(mu);
	auth_params.SetRegion(std::move(region_p));
	region_redirected = true;
	client_cache.Clear();
}

bool S3FileHandle::TryRefreshAuthParams(S3AuthParams request_auth_params, S3RefreshableHTTPParams request_http_params) {
	lock_guard<mutex> lck(mu);
	auto refresh_enabled = credential_refresh_enabled;
	auto context = client_context.lock();
	if (!context) {
		return TryRefreshS3AuthMaterial(nullptr, nullptr, path, auth_params, http_params, request_auth_params,
		                                request_http_params, refresh_enabled, &client_cache, region_redirected);
	}
	ClientContextFileOpener opener(*context);
	return TryRefreshS3AuthMaterial(context.get(), opener, path, auth_params, http_params, request_auth_params,
	                                request_http_params, refresh_enabled, &client_cache, region_redirected);
}

void S3HTTPInput::SetRegion(string region_p) {
	auth_params.SetRegion(std::move(region_p));
	region_redirected = true;
}

bool S3HTTPInput::TryRefreshAuthParams(const string &path, S3AuthParams request_auth_params,
                                       S3RefreshableHTTPParams request_http_params) {
	lock_guard<mutex> lck(mu);
	auto refresh_enabled = credential_refresh_enabled;
	auto context = client_context.lock();
	if (!context) {
		return TryRefreshS3AuthMaterial(nullptr, nullptr, path, auth_params, http_params, request_auth_params,
		                                request_http_params, refresh_enabled, nullptr, region_redirected);
	}
	ClientContextFileOpener opener(*context);
	return TryRefreshS3AuthMaterial(context.get(), opener, path, auth_params, http_params, request_auth_params,
	                                request_http_params, refresh_enabled, nullptr, region_redirected);
}

static bool TryRefreshS3AuthParams(optional_ptr<FileOpener> opener, const string &path, HTTPParams &http_params,
                                   S3AuthParams &auth_params, const S3AuthParams &request_auth_params,
                                   const S3RefreshableHTTPParams &request_http_params, bool preserve_region = false) {
	auto &httpfs_params = http_params.Cast<HTTPFSParams>();
	auto context = FileOpener::TryGetClientContext(opener);
	return TryRefreshS3AuthMaterial(context, opener, path, auth_params, httpfs_params, request_auth_params,
	                                request_http_params, IsS3CredentialRefreshEnabled(opener), nullptr,
	                                preserve_region);
}

S3ConfigParams S3ConfigParams::ReadFrom(optional_ptr<FileOpener> opener) {
	uint64_t uploader_max_filesize;
	uint64_t max_parts_per_file;
	uint64_t max_upload_threads;
	Value value;

	if (FileOpener::TryGetCurrentSetting(opener, "s3_uploader_max_filesize", value)) {
		uploader_max_filesize = DBConfig::ParseMemoryLimit(value.GetValue<string>());
	} else {
		uploader_max_filesize = S3ConfigParams::DEFAULT_MAX_FILESIZE;
	}

	if (FileOpener::TryGetCurrentSetting(opener, "s3_uploader_max_parts_per_file", value)) {
		max_parts_per_file = value.GetValue<uint64_t>();
	} else {
		max_parts_per_file = S3ConfigParams::DEFAULT_MAX_PARTS_PER_FILE; // AWS Default
	}

	if (FileOpener::TryGetCurrentSetting(opener, "s3_uploader_thread_limit", value)) {
		max_upload_threads = value.GetValue<uint64_t>();
	} else {
		max_upload_threads = S3ConfigParams::DEFAULT_MAX_UPLOAD_THREADS;
	}

	return {uploader_max_filesize, max_parts_per_file, max_upload_threads};
}

void S3FileHandle::Close() {
	FinalizeUpload();
}

void S3FileHandle::FinalizeUpload() {
	auto &s3fs = (S3FileSystem &)file_system;
	if (flags.OpenForWriting() && multi_part_upload) {
		multi_part_upload->Finalize();
	}
}

unique_ptr<HTTPClient> S3FileHandle::CreateClient() {
	lock_guard<mutex> lck(mu);
	auto auth_params = this->auth_params;
	auto parsed_url = S3FileSystem::S3UrlParse(path, auth_params);
	string proto_host_port = parsed_url.http_proto + parsed_url.host;
	return http_params.http_util.InitializeClient(http_params, proto_host_port);
}

// Wrapper around the BufferManager::Allocate to that allows limiting the number of buffers that will be handed out
BufferHandle S3FileSystem::Allocate(idx_t part_size, uint16_t max_threads) {
	return buffer_manager.Allocate(MemoryTag::EXTENSION, part_size);
}

void GetQueryParam(const string &key, string &param, unordered_map<string, string> &query_params) {
	auto found_param = query_params.find(key);
	if (found_param != query_params.end()) {
		param = found_param->second;
		query_params.erase(found_param);
	}
}

void S3FileSystem::ReadQueryParams(const string &url_query_param, S3AuthParams &params) {
	if (url_query_param.empty()) {
		return;
	}

	auto query_params = HTTPFSUtil::ParseGetParameters(url_query_param);

	GetQueryParam("s3_region", params.region, query_params);
	GetQueryParam("s3_access_key_id", params.access_key_id, query_params);
	GetQueryParam("s3_secret_access_key", params.secret_access_key, query_params);
	GetQueryParam("s3_session_token", params.session_token, query_params);
	GetQueryParam("s3_endpoint", params.endpoint, query_params);
	GetQueryParam("s3_url_style", params.url_style, query_params);
	auto found_param = query_params.find("s3_use_ssl");
	if (found_param != query_params.end()) {
		if (found_param->second == "true") {
			params.use_ssl = true;
		} else if (found_param->second == "false") {
			params.use_ssl = false;
		} else {
			throw IOException("Incorrect setting found for s3_use_ssl, allowed values are: 'true' or 'false'");
		}
		query_params.erase(found_param);
	}
	auto found_requester_pays_param = query_params.find("s3_requester_pays");
	if (found_requester_pays_param != query_params.end()) {
		if (found_requester_pays_param->second == "true") {
			params.requester_pays = true;
		} else if (found_requester_pays_param->second == "false") {
			params.requester_pays = false;
		} else {
			throw IOException("Incorrect setting found for s3_requester_pays, allowed values are: 'true' or 'false'");
		}
		query_params.erase(found_requester_pays_param);
	}
	if (!query_params.empty()) {
		throw IOException("Invalid query parameters found. Supported parameters are:\n's3_region', 's3_access_key_id', "
		                  "'s3_secret_access_key', 's3_session_token',\n's3_endpoint', 's3_url_style', 's3_use_ssl', "
		                  "'s3_requester_pays'");
	}
}

string S3FileSystem::TryGetPrefix(const string &url) {
	const string prefixes[] = {"s3://", "s3a://", "s3n://", "gcs://", "gs://", "r2://"};
	for (auto &prefix : prefixes) {
		if (StringUtil::StartsWith(StringUtil::Lower(url), prefix)) {
			return prefix;
		}
	}
	return {};
}

string S3FileSystem::GetPrefix(const string &url) {
	auto prefix = TryGetPrefix(url);
	if (prefix.empty()) {
		throw IOException("URL needs to start with s3://, gcs:// or r2://");
	}
	return prefix;
}

ParsedS3Url S3FileSystem::S3UrlParse(string url, const S3AuthParams &params) {
	string http_proto, prefix, host, bucket, key, path, query_param, trimmed_s3_url;

	prefix = GetPrefix(url);
	auto prefix_end_pos = url.find("//") + 2;
	auto slash_pos = url.find('/', prefix_end_pos);
	if (slash_pos == string::npos) {
		throw IOException("URL needs to contain a '/' after the host");
	}
	bucket = url.substr(prefix_end_pos, slash_pos - prefix_end_pos);
	if (bucket.empty()) {
		throw IOException("URL needs to contain a bucket name");
	}

	if (params.s3_url_compatibility_mode) {
		// In url compatibility mode, we will ignore any special chars, so query param strings are disabled
		trimmed_s3_url = url;
		key += url.substr(slash_pos);
	} else {
		// Parse query parameters
		auto question_pos = url.find_first_of('?');
		if (question_pos != string::npos) {
			query_param = url.substr(question_pos + 1);
			trimmed_s3_url = url.substr(0, question_pos);
		} else {
			trimmed_s3_url = url;
		}

		if (!query_param.empty()) {
			key += url.substr(slash_pos, question_pos - slash_pos);
		} else {
			key += url.substr(slash_pos);
		}
	}

	if (key.empty()) {
		throw IOException("URL needs to contain key");
	}

	// Derived host and path based on the endpoint
	auto sub_path_pos = params.endpoint.find_first_of('/');
	if (sub_path_pos != string::npos) {
		// Host header should conform to <host>:<port> so not include the path
		host = params.endpoint.substr(0, sub_path_pos);
		path = params.endpoint.substr(sub_path_pos);
	} else {
		host = params.endpoint;
		path = "";
	}

	// Update host and path according to the url style
	// See https://docs.aws.amazon.com/AmazonS3/latest/userguide/VirtualHosting.html
	if (params.url_style == "vhost" || params.url_style == "virtual" || params.url_style == "") {
		host = bucket + "." + host;
	} else if (params.url_style == "path") {
		path += "/" + bucket;
	}

	// Append key (including leading slash) to the path
	path += key;

	// Remove leading slash from key
	key = key.substr(1);

	http_proto = params.use_ssl ? "https://" : "http://";

	return {http_proto, prefix, host, bucket, key, path, query_param, trimmed_s3_url};
}

string S3FileSystem::GetPayloadHash(char *buffer, idx_t buffer_len) {
	if (buffer_len > 0) {
		hash_bytes payload_hash_bytes;
		hash_str payload_hash_str;
		sha256(buffer, buffer_len, payload_hash_bytes);
		hex256(payload_hash_bytes, payload_hash_str);
		return string((char *)payload_hash_str, sizeof(payload_hash_str));
	} else {
		return "";
	}
}

string ParsedS3Url::GetHTTPUrl(S3AuthParams &auth_params, const string &http_query_string) {
	string full_url = http_proto + host + S3FileSystem::UrlEncode(path);

	if (!http_query_string.empty()) {
		full_url += "?" + http_query_string;
	}
	return full_url;
}

unique_ptr<HTTPResponse> S3FileSystem::PostRequest(HTTPInput &input, string url, HTTPHeaders header_map, string &result,
                                                   char *buffer_in, idx_t buffer_in_len, string http_params) {
	auto &s3_input = input.Cast<S3HTTPInput>();
	auto payload_hash = GetPayloadHash(buffer_in, buffer_in_len);
	const string content_type = "application/octet-stream";
	return RunS3InputRequestWithAuthRefresh(
	    s3_input, url, "POST", http_params, payload_hash, content_type, [&](S3RequestData &request_data) {
		    result.clear();
		    auto &params = request_data.http_params->Cast<HTTPFSParams>();
		    auto response =
		        RunPostRequest(request_data.http_url, request_data.headers, params, result, buffer_in, buffer_in_len,
		                       [&](BaseRequest &request) { return params.http_util.Request(request); });
		    if (response) {
			    response->body = result;
		    }
		    return response;
	    });
}

unique_ptr<HTTPResponse> S3FileSystem::PutRequest(HTTPInput &input, string url, HTTPHeaders header_map, char *buffer_in,
                                                  idx_t buffer_in_len, string http_params) {
	auto &s3_input = input.Cast<S3HTTPInput>();
	auto payload_hash = GetPayloadHash(buffer_in, buffer_in_len);
	const string content_type = "application/octet-stream";
	return RunS3InputRequestWithAuthRefresh(
	    s3_input, url, "PUT", http_params, payload_hash, content_type, [&](S3RequestData &request_data) {
		    auto &params = request_data.http_params->Cast<HTTPFSParams>();
		    return RunPutRequest(request_data.http_url, request_data.headers, params, buffer_in, buffer_in_len,
		                         content_type, [&](BaseRequest &request) { return params.http_util.Request(request); });
	    });
}

unique_ptr<HTTPResponse> S3FileSystem::HeadRequest(FileHandle &handle, string s3_url, HTTPHeaders header_map) {
	auto &s3_handle = handle.Cast<S3FileHandle>();
	return RunS3HandleRequestWithAuthRefresh(s3_handle, s3_url, "HEAD", false, [&](S3RequestData &request_data) {
		auto &params = request_data.http_params->Cast<HTTPFSParams>();
		return RunHeadRequest(request_data.http_url, request_data.headers, params, [&](BaseRequest &request) {
			return SendS3HandleRequestWithClientCache(s3_handle, params, request);
		});
	});
}

unique_ptr<HTTPResponse> S3FileSystem::GetRequest(FileHandle &handle, string s3_url, HTTPHeaders header_map) {
	auto &s3_handle = handle.Cast<S3FileHandle>();
	return RunS3HandleRequestWithAuthRefresh(s3_handle, s3_url, "GET", true, [&](S3RequestData &request_data) {
		auto &params = request_data.http_params->Cast<HTTPFSParams>();
		return RunGetRequest(
		    s3_handle, request_data.http_url, request_data.headers, params,
		    [&](const HTTPResponse &response) { return GetS3RequestError(request_data, response); },
		    [&](BaseRequest &request) { return SendS3HandleRequestWithClientCache(s3_handle, params, request); });
	});
}

unique_ptr<HTTPResponse> S3FileSystem::GetRangeRequest(FileHandle &handle, string s3_url, HTTPHeaders header_map,
                                                       idx_t file_offset, char *buffer_out, idx_t buffer_out_len) {
	auto &s3_handle = handle.Cast<S3FileHandle>();
	return RunS3HandleRequestWithAuthRefresh(s3_handle, s3_url, "GET", true, [&](S3RequestData &request_data) {
		auto &params = request_data.http_params->Cast<HTTPFSParams>();
		return RunGetRangeRequest(
		    s3_handle, request_data.http_url, request_data.headers, params, request_data.etag,
		    request_data.auto_fallback_to_full_file_download, file_offset, buffer_out, buffer_out_len,
		    [&](const HTTPResponse &response) { return GetS3RequestError(request_data, response); },
		    [&](BaseRequest &request) { return SendS3HandleRequestWithClientCache(s3_handle, params, request); });
	});
}

unique_ptr<HTTPResponse> S3FileSystem::DeleteRequest(FileHandle &handle, string s3_url, HTTPHeaders header_map) {
	auto &s3_handle = handle.Cast<S3FileHandle>();
	return RunS3HandleRequestWithAuthRefresh(s3_handle, s3_url, "DELETE", false, [&](S3RequestData &request_data) {
		auto &params = request_data.http_params->Cast<HTTPFSParams>();
		return RunDeleteRequest(request_data.http_url, request_data.headers, params, [&](BaseRequest &request) {
			return SendS3HandleRequestWithClientCache(s3_handle, params, request);
		});
	});
}

unique_ptr<HTTPFileHandle> S3FileSystem::CreateHandle(const OpenFileInfo &file, FileOpenFlags flags,
                                                      optional_ptr<FileOpener> opener) {
	FileOpenerInfo info = {file.path};
	S3AuthParams auth_params = S3AuthParams::ReadFrom(opener, info);

	// Scan the query string for any s3 authentication parameters
	auto parsed_s3_url = S3UrlParse(file.path, auth_params);
	ReadQueryParams(parsed_s3_url.query_param, auth_params);

	auto &http_util = HTTPFSUtil::GetHTTPUtil(opener);
	auto params = http_util.InitializeParameters(opener, info);

	return duckdb::make_uniq<S3FileHandle>(*this, file, flags, std::move(params), auth_params,
	                                       S3ConfigParams::ReadFrom(opener));
}

void S3FileHandle::InitializeFromCacheEntry(const HTTPMetadataCacheEntry &cache_entry) {
	HTTPFileHandle::InitializeFromCacheEntry(cache_entry);
	auto entry = cache_entry.properties.find("s3_region");
	if (entry != cache_entry.properties.end()) {
		SetRegion(entry->second);
	}
}

HTTPMetadataCacheEntry S3FileHandle::GetCacheEntry() const {
	auto result = HTTPFileHandle::GetCacheEntry();
	if (!auth_params.region.empty()) {
		result.properties["s3_region"] = auth_params.region;
	}
	return result;
}

void S3FileHandle::Initialize(optional_ptr<FileOpener> opener) {
	auto context = FileOpener::TryGetClientContext(opener);
	auto refresh_enabled = IsS3CredentialRefreshEnabled(opener);
	auto &s3_input = http_input->Cast<S3HTTPInput>();
	{
		lock_guard<mutex> lck(mu);
		credential_refresh_enabled = refresh_enabled;
		if (context && refresh_enabled) {
			client_context = context->shared_from_this();
		} else {
			client_context.reset();
		}
	}
	{
		lock_guard<mutex> input_lck(s3_input.mu);
		s3_input.credential_refresh_enabled = refresh_enabled;
		if (context && refresh_enabled) {
			s3_input.client_context = context->shared_from_this();
		} else {
			s3_input.client_context.reset();
		}
	}
	try {
		HTTPFileHandle::Initialize(opener);
	} catch (std::exception &ex) {
		ErrorData error(ex);
		string correct_region;
		auto &extra_info = error.ExtraInfo();
		auto entry = extra_info.find("status_code");
		if (entry != extra_info.end()) {
			if (entry->second == "301" || entry->second == "400") {
				auto new_region = extra_info.find("header_x-amz-bucket-region");
				if (new_region != extra_info.end()) {
					correct_region = new_region->second;
				}
			}
			if (entry->second == "403") {
				// 403: FORBIDDEN
				string extra_text;
				if (IsGCSRequest(path)) {
					extra_text = S3FileSystem::GetGCSAuthError(auth_params);
				} else {
					extra_text = S3FileSystem::GetS3AuthError(auth_params);
				}
				throw Exception(extra_info, error.Type(), error.RawMessage() + extra_text);
			}
		}
		if (correct_region.empty()) {
			throw;
		}
		FileOpenerInfo info = {path};
		auth_params = S3AuthParams::ReadFrom(opener, info);
		if (!correct_region.empty()) {
			DUCKDB_LOG_WARNING(
			    logger,
			    "Read S3 file \"%s\" from incorrect region \"%s\" - retrying with updated region \"%s\".\n"
			    "Consider setting the S3 region to this explicitly to avoid extra round-trips.",
			    path, auth_params.region, correct_region);
			SetRegion(std::move(correct_region));
		}
		HTTPFileHandle::Initialize(opener);
	}

	if (flags.OpenForWriting()) {
		auto aws_minimum_part_size = 5242880; // 5 MiB https://docs.aws.amazon.com/AmazonS3/latest/userguide/qfacts.html
		auto max_part_count = config_params.max_parts_per_file;
		auto required_part_size = config_params.max_file_size / max_part_count;
		auto minimum_part_size = MaxValue<idx_t>(aws_minimum_part_size, required_part_size);

		// Round part size up to multiple of Storage::DEFAULT_BLOCK_SIZE
		multi_part_upload->part_size =
		    ((minimum_part_size + Storage::DEFAULT_BLOCK_SIZE - 1) / Storage::DEFAULT_BLOCK_SIZE) *
		    Storage::DEFAULT_BLOCK_SIZE;
		D_ASSERT(multi_part_upload->part_size * max_part_count >= config_params.max_file_size);
	}
}

bool S3FileSystem::CanHandleFile(const string &fpath) {

	return fpath.rfind("s3://", 0) * fpath.rfind("s3a://", 0) * fpath.rfind("s3n://", 0) * fpath.rfind("gcs://", 0) *
	           fpath.rfind("gs://", 0) * fpath.rfind("r2://", 0) ==
	       0;
}

void S3FileSystem::RemoveFile(const string &path, optional_ptr<FileOpener> opener) {
	auto handle = OpenFile(path, FileFlags::FILE_FLAGS_NULL_IF_NOT_EXISTS, opener);
	if (!handle) {
		throw IOException({{"errno", "404"}}, "Could not remove file \"%s\": %s", path,
		                  string("No such file or directory"));
	}

	auto &s3fh = handle->Cast<S3FileHandle>();
	auto res = DeleteRequest(*handle, s3fh.path, {});
	if (res->status != HTTPStatusCode::OK_200 && res->status != HTTPStatusCode::NoContent_204) {
		throw IOException({{"errno", to_string(static_cast<int>(res->status))}}, "Could not remove file \"%s\": %s",
		                  path, res->GetError());
	}
}

// Forward declaration for FindTagContents (defined later in file)
optional_idx FindTagContents(const string &response, const string &tag, idx_t cur_pos, string &result);

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
	key_builder.AddString(auth_params.region);
	key_builder.AddString(auth_params.access_key_id);
	key_builder.AddString(auth_params.secret_access_key);
	key_builder.AddString(auth_params.session_token);
	key_builder.AddString(auth_params.endpoint);
	key_builder.AddString(auth_params.kms_key_id);
	key_builder.AddString(auth_params.url_style);
	key_builder.AddBool(auth_params.use_ssl);
	key_builder.AddBool(auth_params.s3_url_compatibility_mode);
	key_builder.AddBool(auth_params.requester_pays);
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
	key_builder.AddString(secret.GetType());
	key_builder.AddString(secret.GetProvider());
	key_builder.AddString(secret.GetName());
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

	for (const string type : {"s3", "r2", "gcs", "aws"}) {
		key_builder.AddString(type);
		auto match = secret_manager->LookupSecret(*transaction, path, type);
		if (!match.HasMatch()) {
			key_builder.AddString("");
			continue;
		}
		key_builder.AddIndex(static_cast<idx_t>(match.score));
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
	const char *secret_types[] = {"s3", "r2", "gcs", "aws"};
	FileOpenerInfo info = {path};
	KeyValueSecretReader secret_reader(*opener, info, secret_types, 4);
	Value refresh_info;
	return secret_reader.TryGetSecretKey("refresh_info", refresh_info);
}

static void AddDeleteBatchRefreshKeyParts(S3DeleteBatchKeyBuilder &key_builder, optional_ptr<FileOpener> opener,
                                          const string &path) {
	if (IsS3CredentialRefreshEnabled(opener) && HasRefreshableS3Secret(opener, path)) {
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

static string GetS3BucketPath(const ParsedS3Url &parsed_url) {
	auto bucket_path = parsed_url.path.substr(0, parsed_url.path.length() - parsed_url.key.length());
	return bucket_path.empty() ? "/" : bucket_path;
}

void S3FileSystem::RemoveFiles(const vector<string> &paths, optional_ptr<FileOpener> opener) {
	if (paths.empty()) {
		return;
	}

	unordered_map<string, S3DeleteBatch> delete_batches;

	for (auto &path : paths) {
		FileOpenerInfo info = {path};
		S3AuthParams auth_params = S3AuthParams::ReadFrom(opener, info);
		auto parsed_url = S3UrlParse(path, auth_params);
		ReadQueryParams(parsed_url.query_param, auth_params);

		auto bucket_path = GetS3BucketPath(parsed_url);
		S3DeleteBatchUrlInfo url_info = {parsed_url.prefix, parsed_url.http_proto, parsed_url.host, bucket_path,
		                                 auth_params};
		auto refreshable_http_params = ReadRefreshableHTTPParams(opener, path);
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

	constexpr idx_t MAX_KEYS_PER_REQUEST = 1000;

	for (auto &batch_entry : delete_batches) {
		auto &batch = batch_entry.second;
		const vector<string> &keys = batch.keys;
		const vector<string> &secret_lookup_paths = batch.secret_lookup_paths;
		auto &url_info = batch.url_info;

		for (idx_t batch_start = 0; batch_start < keys.size(); batch_start += MAX_KEYS_PER_REQUEST) {
			idx_t batch_end = MinValue<idx_t>(batch_start + MAX_KEYS_PER_REQUEST, keys.size());

			std::stringstream xml_body;
			xml_body << "<?xml version=\"1.0\" encoding=\"UTF-8\"?>";
			xml_body << "<Delete xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">";

			for (idx_t i = batch_start; i < batch_end; i++) {
				xml_body << "<Object><Key>" << keys[i] << "</Key></Object>";
			}

			xml_body << "<Quiet>true</Quiet>";
			xml_body << "</Delete>";

			string body = xml_body.str();

			MD5Context md5_context;
			md5_context.Add(body);
			data_t md5_hash[MD5Context::MD5_HASH_LENGTH_BINARY];
			md5_context.Finish(md5_hash);

			string_t md5_blob(const_char_ptr_cast(md5_hash), MD5Context::MD5_HASH_LENGTH_BINARY);
			string content_md5 = Blob::ToBase64(md5_blob);

			const string http_query_param_for_sig = "delete=";
			const string http_query_param_for_url = "delete";
			auto payload_hash = GetPayloadHash(const_cast<char *>(body.data()), body.length());

			string secret_lookup_url = secret_lookup_paths[batch_start];
			string result;
			unique_ptr<HTTPResponse> res;
			bool retried_auth_refresh = false;

			while (true) {
				auto request_auth_params = url_info.auth_params;
				FileOpenerInfo info = {secret_lookup_url};
				auto &http_util = HTTPFSUtil::GetHTTPUtil(opener);
				auto http_params = http_util.InitializeParameters(opener, info);
				auto request_http_params = SnapshotRefreshableHTTPParams(http_params->Cast<HTTPFSParams>());
				auto request_url = S3UrlParse(secret_lookup_url, url_info.auth_params);
				auto request_path = GetS3BucketPath(request_url);
				auto headers =
				    CreateS3Header(request_path, http_query_param_for_sig, request_url.host, "s3", "POST",
				                   url_info.auth_params, "", "", payload_hash, "application/xml", content_md5);

				string http_url = request_url.http_proto + request_url.host + S3FileSystem::UrlEncode(request_path) +
				                  "?" + http_query_param_for_url;
				S3HTTPInput http_input(std::move(http_params), url_info.auth_params, S3ConfigParams::ReadFrom(opener));

				result.clear();
				res = HTTPFileSystem::PostRequest(http_input, http_url, headers, result,
				                                  const_cast<char *>(body.data()), body.length());
				if (res) {
					res->body = result;
				}
				if (!retried_auth_refresh && res && IsAuthRefreshFailure(*res) &&
				    TryRefreshS3AuthParams(opener, secret_lookup_url, http_input.http_params, url_info.auth_params,
				                           request_auth_params, request_http_params)) {
					retried_auth_refresh = true;
					continue;
				}
				break;
			}

			if (res->status != HTTPStatusCode::OK_200) {
				throw IOException("Failed to remove files: HTTP %d (%s)\n%s", static_cast<int>(res->status),
				                  res->GetError(), result);
			}

			idx_t cur_pos = 0;
			string error_content;
			auto error_pos = FindTagContents(result, "Error", cur_pos, error_content);
			if (error_pos.IsValid()) {
				throw IOException("Failed to remove files: %s", error_content);
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

void S3FileSystem::FileSync(FileHandle &handle) {
	auto &s3fh = handle.Cast<S3FileHandle>();
	s3fh.FinalizeUpload();
}

void S3FileSystem::Write(FileHandle &handle, void *buffer, int64_t nr_bytes, idx_t location) {
	auto &s3fh = handle.Cast<S3FileHandle>();
	if (!s3fh.flags.OpenForWriting()) {
		throw InternalException("Write called on file not opened in write mode");
	}
	int64_t bytes_written = 0;

	while (bytes_written < nr_bytes) {
		auto curr_location = location + bytes_written;

		if (curr_location != s3fh.file_offset) {
			throw InternalException("Non-sequential write not supported!");
		}

		// Find buffer for writing
		auto part_size = s3fh.multi_part_upload->part_size;
		auto write_buffer_idx = curr_location / part_size;

		// Get write buffer, may block until buffer is available
		auto write_buffer = s3fh.multi_part_upload->GetBuffer(write_buffer_idx);

		// Writing to buffer
		auto idx_to_write = curr_location - write_buffer->buffer_start;
		auto bytes_to_write = MinValue<idx_t>(nr_bytes - bytes_written, part_size - idx_to_write);
		memcpy((char *)write_buffer->Ptr() + idx_to_write, (char *)buffer + bytes_written, bytes_to_write);
		write_buffer->idx += bytes_to_write;

		// Flush to HTTP if full
		if (write_buffer->idx >= part_size) {
			s3fh.multi_part_upload->FlushBuffer(write_buffer);
		}
		s3fh.file_offset += bytes_to_write;
		s3fh.length += bytes_to_write;
		bytes_written += bytes_to_write;
	}

	DUCKDB_LOG_FILE_SYSTEM_WRITE(handle, bytes_written, s3fh.file_offset - bytes_written);
}

static bool Match(vector<string>::const_iterator key, vector<string>::const_iterator key_end,
                  vector<string>::const_iterator pattern, vector<string>::const_iterator pattern_end, bool completed) {

	if (key == key_end && !completed) {
		return true;
	}

	while (key != key_end && pattern != pattern_end) {
		if (*pattern == "**") {
			if (std::next(pattern) == pattern_end) {
				return true;
			}
			pattern++;
			while (key != key_end) {
				if (Match(key, key_end, pattern, pattern_end, completed)) {
					return true;
				}
				key++;
			}
			if (!completed)
				return true;
			return false;
		}
		if (!Glob(key->data(), key->length(), pattern->data(), pattern->length())) {
			return false;
		}
		key++;
		pattern++;
	}
	if (pattern != pattern_end && !completed) {
		return true;
	}
	return key == key_end && pattern == pattern_end;
}

enum GlobType { HIERARCHICAL, LISTING, UNKNOWN };

struct S3GlobResult : public LazyMultiFileList {
public:
	S3GlobResult(S3FileSystem &fs, const string &path, optional_ptr<FileOpener> opener);

protected:
	bool ExpandNextPath() const override;

private:
	string glob_pattern;
	optional_ptr<FileOpener> opener;
	mutable bool finished = false;
	mutable S3AuthParams s3_auth_params;
	string shared_path;
	ParsedS3Url parsed_s3_url;
	mutable string main_continuation_token;
	mutable string current_common_prefix;
	mutable string common_prefix_continuation_token;
	mutable vector<string> common_prefixes;
	mutable GlobType glob_type {UNKNOWN};
};

S3GlobResult::S3GlobResult(S3FileSystem &fs, const string &glob_pattern_p, optional_ptr<FileOpener> opener)
    : LazyMultiFileList(FileOpener::TryGetClientContext(opener)), glob_pattern(glob_pattern_p), opener(opener) {
	if (!opener) {
		throw InternalException("Cannot S3 Glob without FileOpener");
	}
	FileOpenerInfo info = {glob_pattern};

	// Trim any query parameters from the string
	s3_auth_params = S3AuthParams::ReadFrom(opener, info);

	// In url compatibility mode, we ignore globs allowing users to query files with the glob chars
	if (s3_auth_params.s3_url_compatibility_mode) {
		expanded_files.emplace_back(glob_pattern);
		finished = true;
		return;
	}

	parsed_s3_url = fs.S3UrlParse(glob_pattern, s3_auth_params);
	auto parsed_glob_url = parsed_s3_url.trimmed_s3_url;

	// AWS matches on prefix, not glob pattern, so we take a substring until the first wildcard char for the aws calls
	auto first_wildcard_pos = parsed_glob_url.find_first_of("*[\\");
	if (first_wildcard_pos == string::npos) {
		expanded_files.emplace_back(glob_pattern);
		finished = true;
		return;
	}

	shared_path = parsed_glob_url.substr(0, first_wildcard_pos);

	fs.ReadQueryParams(parsed_s3_url.query_param, s3_auth_params);
}

bool S3GlobResult::ExpandNextPath() const {
	if (finished) {
		return false;
	}

	FileOpenerInfo info = {glob_pattern};
	auto &http_util = HTTPFSUtil::GetHTTPUtil(opener);
	auto http_params = http_util.InitializeParameters(opener, info);
	const vector<string> pattern_splits = StringUtil::Split(parsed_s3_url.key, "/");

	vector<OpenFileInfo> s3_keys;
	if (!current_common_prefix.empty()) {
		// we have common prefixes left to scan - perform the request
		auto prefix_path = parsed_s3_url.prefix + parsed_s3_url.bucket + '/' + current_common_prefix;

		current_common_prefix = S3FileSystem::UrlDecode(current_common_prefix);
		vector<string> key_splits = StringUtil::Split(current_common_prefix, "/");
		const bool is_match =
		    Match(key_splits.begin(), key_splits.end(), pattern_splits.begin(), pattern_splits.end(), false);
		if (is_match) {
			prefix_path = S3FileSystem::UrlDecode(prefix_path);
			auto prefix_res = AWSListObjectV2::Request(prefix_path, *http_params, s3_auth_params,
			                                           common_prefix_continuation_token, true, optional_idx(), opener);

			AWSListObjectV2::ParseFileList(prefix_res, s3_keys);
			auto more_prefixes = AWSListObjectV2::ParseCommonPrefix(prefix_res);
			common_prefixes.insert(common_prefixes.end(), more_prefixes.begin(), more_prefixes.end());

			common_prefix_continuation_token = AWSListObjectV2::ParseContinuationToken(prefix_res);
		}

		if (common_prefix_continuation_token.empty()) {
			// we are done with the current common prefix
			// either move on to the next one, or finish up
			if (common_prefixes.empty()) {
				// done - we need to do a top-level request again next
				current_common_prefix = string();
			} else {
				// process the next prefix
				current_common_prefix = common_prefixes.back();
				common_prefixes.pop_back();
			}
		}
	} else {
		if (!common_prefixes.empty()) {
			throw InternalException("We have common prefixes but we are doing a top-level request");
		}

		Value value;
		bool allow_s3_recursive_globbing = true;
		if (FileOpener::TryGetCurrentSetting(opener, "s3_allow_recursive_globbing", value)) {
			allow_s3_recursive_globbing = value.GetValue<bool>();
		}

		const bool investigate_use_recursive_glob = !StringUtil::Contains(parsed_s3_url.key, "**") &&
		                                            allow_s3_recursive_globbing && glob_type == GlobType::UNKNOWN;
		// issue the main request

		bool perform_listing = (glob_type != GlobType::HIERARCHICAL);

		// First perform listing once (default will get back up to 1000 elements)
		string response_str =
		    AWSListObjectV2::Request(shared_path, *http_params, s3_auth_params, main_continuation_token,
		                             !perform_listing, optional_idx(), opener);

		string next_continuation_token = AWSListObjectV2::ParseContinuationToken(response_str);

		// If we could have used recursive globbing AND there are more files, check average number of files per folder
		if (investigate_use_recursive_glob && !next_continuation_token.empty()) {
			vector<OpenFileInfo> s3_keys_tmp;
			AWSListObjectV2::ParseFileList(response_str, s3_keys_tmp);
			idx_t found = 0;
			unordered_set<string> my_set;
			for (auto &s3_key : s3_keys_tmp) {
				vector<string> key_splits = StringUtil::Split(s3_key.path, "/");

				found++;
				string x = "";
				key_splits.pop_back();
				for (string y : key_splits) {
					x += y + "/";
				}
				my_set.insert(x);
			}

			if (my_set.size() * 100 < found) {
				// We have at least 100 files per folder, this should make so that hierarchical listing price is
				// amortized folder of hierarchical glob

				// Start from scratch:
				// 1. clear keys
				s3_keys_tmp.clear();
				// 2. do request again, now passing true
				response_str = AWSListObjectV2::Request(shared_path, *http_params, s3_auth_params,
				                                        main_continuation_token, true, optional_idx(), opener);

				// 3. now set next_continuation_token
				next_continuation_token = AWSListObjectV2::ParseContinuationToken(response_str);

				glob_type = GlobType::HIERARCHICAL;
			} else {
				glob_type = GlobType::LISTING;
			}
		}

		main_continuation_token = next_continuation_token;
		AWSListObjectV2::ParseFileList(response_str, s3_keys);

		// parse the list of common prefixes
		common_prefixes = AWSListObjectV2::ParseCommonPrefix(response_str);
		if (!common_prefixes.empty()) {
			// we have common prefixes - set one up for the next request
			current_common_prefix = common_prefixes.back();
			common_prefixes.pop_back();
		}
	}

	if (main_continuation_token.empty() && current_common_prefix.empty()) {
		// we are done
		finished = true;
	}

	for (auto &s3_key : s3_keys) {

		vector<string> key_splits = StringUtil::Split(s3_key.path, "/");
		bool is_match = Match(key_splits.begin(), key_splits.end(), pattern_splits.begin(), pattern_splits.end(), true);

		if (is_match) {
			auto result_full_url = parsed_s3_url.prefix + parsed_s3_url.bucket + "/" + s3_key.path;
			// if a ? char was present, we re-add it here as the url parsing will have trimmed it.
			if (!parsed_s3_url.query_param.empty()) {
				result_full_url += '?' + parsed_s3_url.query_param;
			}
			s3_key.path = std::move(result_full_url);
			if (!s3_auth_params.region.empty()) {
				s3_key.extended_info->options["s3_region"] = s3_auth_params.region;
			}
			expanded_files.push_back(std::move(s3_key));
		}
	}
	return true;
}

unique_ptr<MultiFileList> S3FileSystem::GlobFilesExtended(const string &path, const FileGlobInput &input,
                                                          optional_ptr<FileOpener> opener) {
	return make_uniq<S3GlobResult>(*this, path, opener);
}

string S3FileSystem::GetName() const {
	return "S3FileSystem";
}

bool S3FileSystem::ListFilesExtended(const string &directory, const std::function<void(OpenFileInfo &info)> &callback,
                                     optional_ptr<FileOpener> opener) {
	string trimmed_dir = directory;
	auto sep = PathSeparator(trimmed_dir);
	StringUtil::RTrim(trimmed_dir, sep);
	auto glob_res = GlobFilesExtended(JoinPath(trimmed_dir, "**"), FileGlobOptions::ALLOW_EMPTY, opener);

	if (!glob_res || glob_res->GetExpandResult() == FileExpandResult::NO_FILES) {
		return false;
	}
	auto base_path = trimmed_dir + sep;

	for (auto file : glob_res->Files()) {
		if (!StringUtil::StartsWith(file.path, base_path)) {
			throw InvalidInputException(
			    "Globbed directory \"%s\", but found file \"%s\" that does not start with base path \"%s\"", directory,
			    file.path, base_path);
		}
		file.path = file.path.substr(base_path.size());
		callback(file);
	}

	return true;
}

// Tolerant variant for error bodies: a truncated/malformed body must not escalate to a DB-invalidating
// InternalException, so an unmatched open tag is "not found".
optional_idx TryFindTagContents(const string &response, const string &tag, idx_t cur_pos, string &result) {
	string open_tag = "<" + tag + ">";
	string close_tag = "</" + tag + ">";
	auto open_tag_pos = response.find(open_tag, cur_pos);
	if (open_tag_pos == string::npos) {
		// tag not found
		return optional_idx();
	}
	auto close_tag_pos = response.find(close_tag, open_tag_pos + open_tag.size());
	if (close_tag_pos == string::npos) {
		return optional_idx();
	}
	result = response.substr(open_tag_pos + open_tag.size(), close_tag_pos - open_tag_pos - open_tag.size());
	return close_tag_pos + close_tag.size();
}

optional_idx FindTagContents(const string &response, const string &tag, idx_t cur_pos, string &result) {
	string open_tag = "<" + tag + ">";
	auto open_tag_pos = response.find(open_tag, cur_pos);
	if (open_tag_pos == string::npos) {
		// tag not found
		return optional_idx();
	}
	auto next_pos = TryFindTagContents(response, tag, cur_pos, result);
	if (!next_pos.IsValid()) {
		throw InternalException("Failed to parse S3 result: found open tag for %s but did not find matching close tag",
		                        tag);
	}
	return next_pos;
}

string S3FileSystem::GetS3BadRequestError(const S3AuthParams &s3_auth_params, string correct_region) {
	string extra_text = "\n\nBad Request - this can be caused by the S3 region being set incorrectly.";
	if (s3_auth_params.region.empty()) {
		extra_text += "\n* No region is provided.";
	} else {
		extra_text += "\n* Provided region is: \"" + s3_auth_params.region + "\"";
	}
	if (!correct_region.empty()) {
		extra_text += "\n* Correct region is: \"" + correct_region + "\"";
	}
	return extra_text;
}

string S3FileSystem::GetS3AuthError(const S3AuthParams &s3_auth_params) {
	string extra_text = "\n\nAuthentication Failure - this is usually caused by invalid or missing credentials.";
	if (s3_auth_params.secret_access_key.empty() && s3_auth_params.access_key_id.empty()) {
		extra_text += "\n* No credentials are provided.";
	} else {
		extra_text += "\n* Credentials are provided, but they did not work.";
	}
	extra_text += "\n* See https://duckdb.org/docs/stable/extensions/httpfs/s3api.html";
	return extra_text;
}

string S3FileSystem::GetGCSAuthError(const S3AuthParams &s3_auth_params) {
	string extra_text = "\n\nAuthentication Failure - GCS authentication failed.";
	if (s3_auth_params.oauth2_bearer_token.empty() && s3_auth_params.secret_access_key.empty() &&
	    s3_auth_params.access_key_id.empty()) {
		extra_text += "\n* No credentials provided.";
		extra_text += "\n* For OAuth2: CREATE SECRET (TYPE GCS, bearer_token 'your-token')";
		extra_text += "\n* For HMAC: CREATE SECRET (TYPE GCS, key_id 'key', secret 'secret')";
	} else if (!s3_auth_params.oauth2_bearer_token.empty()) {
		extra_text += "\n* Bearer token was provided but authentication failed.";
		extra_text += "\n* Ensure your OAuth2 token is valid and not expired.";
	} else {
		extra_text += "\n* HMAC credentials were provided but authentication failed.";
		extra_text += "\n* Ensure your HMAC key_id and secret are correct.";
	}
	return extra_text;
}

bool S3FileSystem::TryGetS3ErrorCode(const string &body, string &code) {
	if (body.empty()) {
		return false;
	}
	string error_xml;
	if (!TryFindTagContents(body, "Error", 0, error_xml).IsValid()) {
		return false;
	}
	return TryFindTagContents(error_xml, "Code", 0, code).IsValid();
}

string S3FileSystem::ParseS3Error(const string &error) {
	// S3 errors look like this:
	//<Error>
	//  <Code>NoSuchKey</Code>
	//  <Message>The resource you requested does not exist</Message>
	//  <Resource>/mybucket/myfoto.jpg</Resource>
	//  <RequestId>4442587FB7D0A2F9</RequestId>
	//</Error>
	if (error.empty()) {
		return string();
	}
	// find <Error> tag
	string error_xml;
	idx_t err_pos = 0;
	auto next_pos = TryFindTagContents(error, "Error", err_pos, error_xml);
	if (!next_pos.IsValid()) {
		return string();
	}
	// find <Code> and <Message>
	string error_code, error_message, extra_error_data;
	idx_t cur_pos = 0;
	next_pos = TryFindTagContents(error_xml, "Code", cur_pos, error_code);
	if (!next_pos.IsValid()) {
		return string();
	}
	cur_pos = 0;
	next_pos = TryFindTagContents(error_xml, "Message", cur_pos, error_message);
	if (!next_pos.IsValid()) {
		return string();
	}
	// depending on Code, find other info
	if (error_code == "InvalidAccessKeyId") {
		cur_pos = 0;
		next_pos = TryFindTagContents(error_xml, "AWSAccessKeyId", cur_pos, extra_error_data);
		if (next_pos.IsValid()) {
			extra_error_data = "\nInvalid Access Key: \"" + extra_error_data + "\"";
		}
	}
	return StringUtil::Format("\n\n%s: %s%s", error_code, error_message, extra_error_data);
}

HTTPException S3FileSystem::GetS3Error(const S3AuthParams &s3_auth_params, const HTTPResponse &response,
                                       const string &url) {
	string extra_text = ParseS3Error(response.body);
	if (response.status == HTTPStatusCode::BadRequest_400) {
		extra_text += GetS3BadRequestError(s3_auth_params);
	}
	if (response.status == HTTPStatusCode::Forbidden_403) {
		extra_text += GetS3AuthError(s3_auth_params);
	}
	auto status_message = HTTPFSUtil::GetStatusMessage(response.status);
	return HTTPException(response, "HTTP GET error reading '%s' in region '%s' (HTTP %d %s)%s", url,
	                     s3_auth_params.region, response.status, status_message, extra_text);
}

HTTPException S3FileSystem::GetHTTPError(FileHandle &handle, const HTTPResponse &response, const string &url) {
	auto &s3_handle = handle.Cast<S3FileHandle>();
	S3AuthParams auth_params;
	{
		lock_guard<mutex> lck(s3_handle.mu);
		auth_params = s3_handle.auth_params;
	}

	// Use GCS-specific error for GCS URLs
	if (IsGCSRequest(url) && response.status == HTTPStatusCode::Forbidden_403) {
		string extra_text = GetGCSAuthError(auth_params);
		auto status_message = HTTPFSUtil::GetStatusMessage(response.status);
		throw HTTPException(response, "HTTP error on '%s' (HTTP %d %s)%s", url, response.status, status_message,
		                    extra_text);
	}

	return GetS3Error(auth_params, response, url);
}

string AWSListObjectV2::Request(const string &path, HTTPParams &http_params, S3AuthParams &s3_auth_params,
                                string &continuation_token, bool use_delimiter, optional_idx max_keys,
                                optional_ptr<FileOpener> opener) {
	const idx_t MAX_RETRIES = 2;
	bool retried_auth_refresh = false;
	bool retried_region = false;
	for (idx_t it = 0; it <= MAX_RETRIES; it++) {
		auto request_auth_params = s3_auth_params;
		auto request_http_params = SnapshotRefreshableHTTPParams(http_params.Cast<HTTPFSParams>());
		auto parsed_url = S3FileSystem::S3UrlParse(path, s3_auth_params);

		// Construct the ListObjectsV2 call
		string req_path = parsed_url.path.substr(0, parsed_url.path.length() - parsed_url.key.length());

		map<string, string> req_params;
		// NOTE: req_params needs to be sorted before passing to sigv4 code
		if (!continuation_token.empty()) {
			req_params["continuation-token"] = S3FileSystem::UrlEncode(continuation_token, true);
		}

		if (use_delimiter) {
			req_params["delimiter"] = "%2F";
		}

		req_params["encoding-type"] = "url";
		req_params["list-type"] = "2";
		if (max_keys.IsValid()) {
			req_params["max-keys"] = to_string(max_keys.GetIndex());
		}
		req_params["prefix"] = S3FileSystem::UrlEncode(parsed_url.key, true);

		string encoded_params = "";
		for (const auto &p : req_params) {
			encoded_params += p.first + "=" + p.second + "&";
		}
		if (!encoded_params.empty()) {
			// Remove last '&'
			encoded_params.pop_back();
		}
		auto header_map =
		    CreateS3Header(req_path, encoded_params, parsed_url.host, "s3", "GET", s3_auth_params, "", "", "", "");

		// Get requests use fresh connection
		string full_host = parsed_url.http_proto + parsed_url.host;
		string listobjectv2_url = req_path + "?" + encoded_params;
		string actual_path = full_host;
		if (StringUtil::StartsWith(listobjectv2_url, full_host)) {
			actual_path = listobjectv2_url;
		} else if (listobjectv2_url[0] == '/') {
			actual_path += listobjectv2_url;
		} else {
			actual_path += "/" + listobjectv2_url;
		}
		// Buffer the response in HTTPResponse instead of streaming it through callbacks. The retry classifier needs the
		// complete S3 error body to distinguish RequestTimeout (HTTP 400), and callbacks otherwise retain per-attempt
		// state across HTTPUtil's internal retry loop.
		GetRequestInfo get_request(actual_path, header_map, http_params, nullptr, nullptr);
		auto result = http_params.http_util.Request(get_request);
		if (result->HasRequestError()) {
			throw IOException("%s error for HTTP GET to '%s'", result->GetRequestError(), listobjectv2_url);
		}
		if (!retried_auth_refresh && IsAuthRefreshFailure(*result) &&
		    TryRefreshS3AuthParams(opener, path, http_params, s3_auth_params, request_auth_params, request_http_params,
		                           retried_region)) {
			retried_auth_refresh = true;
			continue;
		}
		ErrorData error;
		if (static_cast<int>(result->status) >= 400) {
			string trimmed_path = path;
			StringUtil::RTrim(trimmed_path, "/");
			error = ErrorData(S3FileSystem::GetS3Error(s3_auth_params, *result, trimmed_path));
		}
		// check
		string updated_bucket_region;
		if (result->status == HTTPStatusCode::MovedPermanently_301) {
			string moved_error;
			if (!retried_region && result->HasHeader("x-amz-bucket-region")) {
				auto response_region = result->GetHeaderValue("x-amz-bucket-region");
				if (response_region == s3_auth_params.region) {
					moved_error = "suggested region \"" + response_region +
					              "\" is the same as the region we used to make the request";
				} else {
					updated_bucket_region = response_region;
				}
			} else {
				moved_error = "HTTP response did not contain header_x-amz-bucket-region";
			}
			if (!moved_error.empty()) {
				throw HTTPException(*result, "HTTP 301 response when running glob \"%s\" but %s", path, moved_error);
			}
		}
		if (error.HasError()) {
			if (!retried_region && result->HasHeader("x-amz-bucket-region")) {
				auto response_region = result->GetHeaderValue("x-amz-bucket-region");
				if (response_region != s3_auth_params.region) {
					updated_bucket_region = response_region;
				}
			}
			if (updated_bucket_region.empty()) {
				// no updated region found
				error.Throw();
			}
		}
		if (!updated_bucket_region.empty()) {
			DUCKDB_LOG_WARNING(
			    http_params.logger,
			    "Ran S3 glob \"%s\" from incorrect region \"%s\" - retrying with updated region \"%s\".\n"
			    "Consider setting the S3 region to this explicitly to avoid extra round-trips.",
			    path, s3_auth_params.region, updated_bucket_region);

			// bucket region was updated - update and re-run the request against the correct endpoint
			s3_auth_params.SetRegion(std::move(updated_bucket_region));
			retried_region = true;
			continue;
		}
		return std::move(result->body);
	}
	throw InvalidInputException(
	    "Exceeded retry count in AWSListObjectV2::Request while retrying region redirects or credential refresh");
}

void AWSListObjectV2::ParseFileList(string &aws_response, vector<OpenFileInfo> &result) {
	// Example S3 response:
	//	<Contents>
	//		<Key>lineitem_sf10_partitioned_shipdate/l_shipdate%3D1997-03-28/data_0.parquet</Key>
	//		<LastModified>2024-11-09T11:38:08.000Z</LastModified>
	//		<ETag>&quot;bdf10f525f8355fb80d1ff2d8c62cc8b&quot;</ETag>
	//		<Size>1127863</Size>
	//		<StorageClass>STANDARD</StorageClass>
	//	</Contents>
	idx_t cur_pos = 0;
	while (true) {
		string contents;
		auto next_pos = FindTagContents(aws_response, "Contents", cur_pos, contents);
		if (!next_pos.IsValid()) {
			// exhausted all contents
			break;
		}
		// move to the next position
		cur_pos = next_pos.GetIndex();

		// parse the contents
		string key;
		auto key_pos = FindTagContents(contents, "Key", 0, key);
		if (!key_pos.IsValid()) {
			throw InternalException("Key not found in S3 response: %s", contents);
		}
		auto parsed_path = S3FileSystem::UrlDecode(key);
		if (parsed_path.back() == '/') {
			// not a file but a directory
			continue;
		}
		// construct the file
		OpenFileInfo result_file(parsed_path);

		auto extra_info = make_shared_ptr<ExtendedOpenFileInfo>();
		// get file attributes
		string last_modified, etag, size;
		auto last_modified_pos = FindTagContents(contents, "LastModified", 0, last_modified);
		if (last_modified_pos.IsValid()) {
			extra_info->options["last_modified"] = Value(last_modified).DefaultCastAs(LogicalType::TIMESTAMP);
		}
		auto etag_pos = FindTagContents(contents, "ETag", 0, etag);
		if (etag_pos.IsValid()) {
			etag = StringUtil::Replace(etag, "&quot;", "\"");
			etag = StringUtil::Replace(etag, "&#34;", "\"");
			extra_info->options["etag"] = Value(std::move(etag));
		}
		auto size_pos = FindTagContents(contents, "Size", 0, size);
		if (size_pos.IsValid()) {
			extra_info->options["file_size"] = Value(size).DefaultCastAs(LogicalType::UBIGINT);
		}
		result_file.extended_info = std::move(extra_info);
		result.push_back(std::move(result_file));
	}
}

string AWSListObjectV2::ParseContinuationToken(string &aws_response) {

	auto open_tag_pos = aws_response.find("<NextContinuationToken>");
	if (open_tag_pos == string::npos) {
		return "";
	} else {
		auto close_tag_pos = aws_response.find("</NextContinuationToken>", open_tag_pos + 23);
		if (close_tag_pos == string::npos) {
			throw InternalException("Failed to parse S3 result");
		}
		return aws_response.substr(open_tag_pos + 23, close_tag_pos - open_tag_pos - 23);
	}
}

vector<string> AWSListObjectV2::ParseCommonPrefix(string &aws_response) {
	vector<string> s3_prefixes;
	idx_t cur_pos = 0;
	while (true) {
		cur_pos = aws_response.find("<CommonPrefixes>", cur_pos);
		if (cur_pos == string::npos) {
			break;
		}
		auto next_open_tag_pos = aws_response.find("<Prefix>", cur_pos);
		if (next_open_tag_pos == string::npos) {
			throw InternalException("Parsing error while parsing s3 listobject result");
		} else {
			auto next_close_tag_pos = aws_response.find("</Prefix>", next_open_tag_pos + 8);
			if (next_close_tag_pos == string::npos) {
				throw InternalException("Failed to parse S3 result");
			}
			auto parsed_path = aws_response.substr(next_open_tag_pos + 8, next_close_tag_pos - next_open_tag_pos - 8);
			s3_prefixes.push_back(parsed_path);
			cur_pos = next_close_tag_pos + 6;
		}
	}
	return s3_prefixes;
}

S3KeyValueReader::S3KeyValueReader(FileOpener &opener_p, optional_ptr<FileOpenerInfo> info, const char **secret_types,
                                   const idx_t secret_types_len)
    : S3KeyValueReader(KeyValueSecretReader {opener_p, info, secret_types, secret_types_len}) {
}

S3KeyValueReader::S3KeyValueReader(const KeyValueSecretReader &_reader) : reader(_reader) {
	Value use_env_vars_for_secret_info_setting;
	reader.TryGetSecretKeyOrSetting("enable_global_s3_configuration", "enable_global_s3_configuration",
	                                use_env_vars_for_secret_info_setting);
	use_env_variables_for_secret_settings = use_env_vars_for_secret_info_setting.GetValue<bool>();
}

} // namespace duckdb
