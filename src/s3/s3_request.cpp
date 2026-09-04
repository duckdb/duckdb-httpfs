#include "s3/s3_request.hpp"

#include "s3/s3fs.hpp"
#include "s3/s3_xml_response.hpp"
#include "create_secret_functions.hpp"
#include "http/http_state.hpp"

#include "duckdb/common/exception/http_exception.hpp"
#include "duckdb/common/hash_functions.hpp"
#include "duckdb/common/helper.hpp"
#include "duckdb/common/http_util.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/common/thread.hpp"
#include "duckdb/common/types/timestamp.hpp"
#include "duckdb/function/scalar/strftime_format.hpp"
#include "duckdb/logging/file_system_logger.hpp"
#include "duckdb/logging/logger.hpp"
#include "duckdb/main/client_context_file_opener.hpp"
#include "duckdb/main/secret/secret_manager.hpp"

#include <algorithm>

namespace duckdb {

S3RefreshableHTTPParams::S3RefreshableHTTPParams(const HTTPFSParams &params) {
	http_proxy = params.http_proxy;
	http_proxy_port = params.http_proxy.empty() ? 0 : params.http_proxy_port;
	http_proxy_username = params.http_proxy_username;
	http_proxy_password = params.http_proxy_password;
	extra_headers = params.extra_headers;
	override_verify_ssl = params.override_verify_ssl;
	verify_ssl = params.verify_ssl;
	bearer_token = params.bearer_token;
}

void S3RefreshableHTTPParams::Apply(HTTPFSParams &target) const {
	target.http_proxy = http_proxy;
	target.http_proxy_port = http_proxy.empty() ? 0 : http_proxy_port;
	target.http_proxy_username = http_proxy_username;
	target.http_proxy_password = http_proxy_password;
	target.extra_headers = extra_headers;
	target.override_verify_ssl = override_verify_ssl;
	target.verify_ssl = verify_ssl;
	target.bearer_token = bearer_token;
	target.pre_merged_headers = false;
}

bool S3RefreshableHTTPParams::operator==(const S3RefreshableHTTPParams &other) const {
	return http_proxy == other.http_proxy && http_proxy_port == other.http_proxy_port &&
	       http_proxy_username == other.http_proxy_username && http_proxy_password == other.http_proxy_password &&
	       extra_headers == other.extra_headers && override_verify_ssl == other.override_verify_ssl &&
	       verify_ssl == other.verify_ssl && bearer_token == other.bearer_token;
}

S3RequestQuery::S3RequestQuery(std::initializer_list<pair<string, string>> parameters_p)
    : S3RequestQuery(vector<pair<string, string>>(parameters_p)) {
}

S3RequestQuery::S3RequestQuery(vector<pair<string, string>> parameters_p) : parameters(std::move(parameters_p)) {
	vector<pair<string, string>> encoded_parameters;
	encoded_parameters.reserve(parameters.size());
	for (const auto &parameter : parameters) {
		encoded_parameters.emplace_back(S3Url::Encode(parameter.first, S3URLEncodeMode::QUERY_COMPONENT),
		                                S3Url::Encode(parameter.second, S3URLEncodeMode::QUERY_COMPONENT));
	}
	std::sort(encoded_parameters.begin(), encoded_parameters.end());
	for (const auto &parameter : encoded_parameters) {
		if (!wire_query.empty()) {
			wire_query += '&';
		}
		wire_query += parameter.first + "=" + parameter.second;
	}
	canonical_query = wire_query;
}

const string &S3RequestQuery::WireQuery() const {
	return wire_query;
}

const string &S3RequestQuery::CanonicalQuery() const {
	return canonical_query;
}

bool S3RequestQuery::HasParameter(const string &name) const {
	for (const auto &parameter : parameters) {
		if (parameter.first == name) {
			return true;
		}
	}
	return false;
}

struct HTTPFSOwnedS3Headers {
public:
	static bool Contains(const string &name, S3ProviderType provider_type) {
		return Headers().find(name) != Headers().end() ||
		       (provider_type == S3ProviderType::GCS && StringUtil::CIEquals(name, "x-goog-user-project"));
	}

	static string CanonicalName(const string &name, S3ProviderType provider_type) {
		auto entry = Headers().find(name);
		if (entry != Headers().end()) {
			return entry->second;
		}
		D_ASSERT(provider_type == S3ProviderType::GCS && StringUtil::CIEquals(name, "x-goog-user-project"));
		return "x-goog-user-project";
	}

private:
	static const case_insensitive_map_t<string> &Headers() {
		static const case_insensitive_map_t<string> headers {
		    {"Host", "Host"},
		    {"Authorization", "Authorization"},
		    {"Content-Length", "Content-Length"},
		    {"Content-Type", "Content-Type"},
		    {"Content-MD5", "Content-MD5"},
		    {"Range", "Range"},
		    {"If-Match", "If-Match"},
		    {"x-amz-date", "x-amz-date"},
		    {"x-amz-content-sha256", "x-amz-content-sha256"},
		    {"x-amz-security-token", "x-amz-security-token"},
		    {"x-amz-request-payer", "x-amz-request-payer"},
		    {"x-amz-server-side-encryption", "x-amz-server-side-encryption"},
		    {"x-amz-server-side-encryption-aws-kms-key-id", "x-amz-server-side-encryption-aws-kms-key-id"},
		};
		return headers;
	}
};

struct S3HeaderBuilder {
	struct CanonicalHeader {
		string name;
		string value;
	};

public:
	S3HeaderBuilder(EncryptionUtil &encryption_util_p, string encoded_url_p, const S3RequestQuery &query_p,
	                string host_p, string service_p, RequestType request_type_p, const S3AuthParams &auth_params_p,
	                string date_now_p, string datetime_now_p, string payload_hash_p, string content_type_p,
	                string content_md5_p, HTTPHeaders &headers_p)
	    : encryption_util(encryption_util_p), encoded_url(std::move(encoded_url_p)), query(query_p.CanonicalQuery()),
	      host(std::move(host_p)), service(std::move(service_p)), method(HTTPFSUtil::GetRequestMethod(request_type_p)),
	      auth_params(auth_params_p), date_now(std::move(date_now_p)), datetime_now(std::move(datetime_now_p)),
	      payload_hash(std::move(payload_hash_p)), content_type(std::move(content_type_p)),
	      content_md5(std::move(content_md5_p)),
	      use_sse_kms(!auth_params.kms_key_id.empty() &&
	                  (request_type_p == RequestType::POST_REQUEST || request_type_p == RequestType::PUT_REQUEST) &&
	                  !query_p.HasParameter("uploadId")),
	      headers(headers_p) {
	}

public:
	void Create() {
		headers["Host"] = host;
		InitializeDefaults();
		AddRequestHeaders();
		auto canonical_headers = BuildCanonicalHeaders();
		auto signed_headers = BuildSignedHeaders(canonical_headers);
		auto canonical_request = BuildCanonicalRequest(canonical_headers, signed_headers);
		auto signature = CreateSignature(canonical_request);
		headers["Authorization"] = "AWS4-HMAC-SHA256 Credential=" + auth_params.access_key_id + "/" +
		                           CredentialScope() + ", SignedHeaders=" + signed_headers + ", Signature=" + signature;
	}

private:
	void InitializeDefaults() {
		if (payload_hash.empty()) {
			payload_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
		}
		if (datetime_now.empty()) {
			auto timestamp = Timestamp::GetCurrentTimestamp();
			date_now = StrfTimeFormat::Format(timestamp, "%Y%m%d");
			datetime_now = StrfTimeFormat::Format(timestamp, "%Y%m%dT%H%M%SZ");
		}
	}

	void AddRequestHeaders() {
		headers["x-amz-date"] = datetime_now;
		headers["x-amz-content-sha256"] = payload_hash;
		if (!auth_params.session_token.empty()) {
			headers["x-amz-security-token"] = auth_params.session_token;
		}
		if (use_sse_kms) {
			headers["x-amz-server-side-encryption"] = "aws:kms";
			headers["x-amz-server-side-encryption-aws-kms-key-id"] = auth_params.kms_key_id;
		}
		if (auth_params.requester_pays && auth_params.provider_type != S3ProviderType::GCS) {
			headers["x-amz-request-payer"] = "requester";
		}
		if (!content_md5.empty()) {
			headers["content-md5"] = content_md5;
		}
		if (!content_type.empty() && content_type != "application/octet-stream") {
			headers["content-type"] = content_type;
		}
	}

	static bool ShouldSignHeader(const string &name) {
		return StringUtil::CIEquals(name, "host") || StringUtil::CIEquals(name, "content-md5") ||
		       StringUtil::CIEquals(name, "content-type") || StringUtil::CIStartsWith(name, "x-amz-") ||
		       StringUtil::CIStartsWith(name, "x-goog-");
	}

	static string NormalizeHeaderValue(const string &value) {
		string result;
		bool whitespace = false;
		for (const auto character : value) {
			if (character == ' ' || character == '\t') {
				whitespace = !result.empty();
				continue;
			}
			if (whitespace) {
				result += ' ';
				whitespace = false;
			}
			result += character;
		}
		return result;
	}

	vector<CanonicalHeader> BuildCanonicalHeaders() const {
		vector<CanonicalHeader> result;
		for (const auto &header : headers) {
			if (!ShouldSignHeader(header.first)) {
				continue;
			}
			auto value = header.second;
			if (!HTTPFSOwnedS3Headers::Contains(header.first, auth_params.provider_type)) {
				value = NormalizeHeaderValue(value);
			}
			result.push_back({StringUtil::Lower(header.first), std::move(value)});
		}
		if (!content_type.empty() && !headers.HasHeader("content-type")) {
			result.push_back({"content-type", content_type});
		}
		std::sort(result.begin(), result.end(),
		          [](const CanonicalHeader &left, const CanonicalHeader &right) { return left.name < right.name; });
		return result;
	}

	static string BuildSignedHeaders(const vector<CanonicalHeader> &canonical_headers) {
		string result;
		for (const auto &header : canonical_headers) {
			if (!result.empty()) {
				result += ';';
			}
			result += header.name;
		}
		return result;
	}

	string BuildCanonicalRequest(const vector<CanonicalHeader> &canonical_headers, const string &signed_headers) const {
		auto result = method + "\n" + encoded_url + "\n" + query;
		for (const auto &header : canonical_headers) {
			result += "\n" + header.name + ":" + header.value;
		}
		return result + "\n\n" + signed_headers + "\n" + payload_hash;
	}

	string CreateSignature(const string &canonical_request) const {
		SignatureV4Params sig_params;
		sig_params.canonical_request = canonical_request;
		sig_params.credential_scope = CredentialScope();
		sig_params.region = auth_params.region;
		sig_params.service = service;
		sig_params.secret_access_key = auth_params.secret_access_key;
		sig_params.date_now = date_now;
		sig_params.datetime_now = datetime_now;
		return HTTPUtil::CreateSignatureV4(encryption_util, sig_params);
	}

	string CredentialScope() const {
		return date_now + "/" + auth_params.region + "/" + service + "/aws4_request";
	}

private:
	EncryptionUtil &encryption_util;
	const string encoded_url;
	const string query;
	const string host;
	const string service;
	const string method;
	const S3AuthParams &auth_params;
	string date_now;
	string datetime_now;
	string payload_hash;
	const string content_type;
	const string content_md5;
	const bool use_sse_kms;
	HTTPHeaders &headers;
};

static HTTPHeaders CreateConfiguredS3Headers(const unordered_map<string, string> &extra_headers,
                                             const string &user_agent, S3ProviderType provider_type) {
	vector<pair<string, string>> sorted_headers;
	sorted_headers.reserve(extra_headers.size());
	for (const auto &header : extra_headers) {
		sorted_headers.emplace_back(header.first, header.second);
	}
	std::sort(sorted_headers.begin(), sorted_headers.end(), [](const auto &left, const auto &right) {
		auto left_name = StringUtil::Lower(left.first);
		auto right_name = StringUtil::Lower(right.first);
		if (left_name != right_name) {
			return left_name < right_name;
		}
		return left.first < right.first;
	});

	for (idx_t header_idx = 0; header_idx < sorted_headers.size(); header_idx++) {
		auto &header = sorted_headers[header_idx];
		if (header_idx > 0 && StringUtil::CIEquals(sorted_headers[header_idx - 1].first, header.first)) {
			throw InvalidInputException("Configured S3 headers \"%s\" and \"%s\" differ only by case",
			                            sorted_headers[header_idx - 1].first, header.first);
		}
		if (HTTPFSOwnedS3Headers::Contains(header.first, provider_type)) {
			throw InvalidInputException("Configured S3 header \"%s\" conflicts with HTTPFS-owned header \"%s\"",
			                            header.first, HTTPFSOwnedS3Headers::CanonicalName(header.first, provider_type));
		}
	}

	HTTPHeaders result;
	for (auto &header : sorted_headers) {
		result[header.first] = header.second;
	}
	if (!user_agent.empty()) {
		result.Insert("User-Agent", user_agent);
	}
	return result;
}

HTTPHeaders S3RequestUtil::CreateHeaders(EncryptionUtil &encryption_util, const ParsedS3Url &parsed_url,
                                         S3RequestTarget target, const S3RequestQuery &query, RequestType request_type,
                                         const S3AuthParams &auth_params, string date_now, string datetime_now,
                                         string payload_hash, string content_type, string content_md5,
                                         const unordered_map<string, string> &extra_headers, const string &user_agent) {
	const auto &host = parsed_url.GetHost();
	const auto &encoded_path =
	    target == S3RequestTarget::BUCKET ? parsed_url.GetEncodedBucketPath() : parsed_url.GetEncodedPath();
	auto headers = CreateConfiguredS3Headers(extra_headers, user_agent, auth_params.provider_type);
	if (auth_params.provider_type == S3ProviderType::GCS && !auth_params.user_project.empty()) {
		headers["x-goog-user-project"] = auth_params.user_project;
	}
	switch (S3Provider::GetAuthType(auth_params)) {
	case S3AuthType::ANONYMOUS: {
		headers["Host"] = host;
		return headers;
	}
	case S3AuthType::SIGV4: {
		S3HeaderBuilder(encryption_util, encoded_path, query, host, "s3", request_type, auth_params,
		                std::move(date_now), std::move(datetime_now), std::move(payload_hash), std::move(content_type),
		                std::move(content_md5), headers)
		    .Create();
		return headers;
	}
	case S3AuthType::BEARER: {
		headers["Authorization"] = "Bearer " + auth_params.oauth2_bearer_token;
		headers["Host"] = host;
		if (!content_type.empty()) {
			headers["Content-Type"] = content_type;
		}
		if (!content_md5.empty()) {
			headers["Content-MD5"] = content_md5;
		}
		return headers;
	}
	}
	throw InternalException("Unknown S3 authentication type");
}

static bool IsAuthRefreshErrorBody(const string &body) {
	S3XMLError error;
	if (!S3XMLResponseParser::TryParseError(body, error)) {
		return false;
	}
	return error.code == "ExpiredToken" || error.code == "InvalidToken" || error.code == "TokenRefreshRequired";
}

static const char *S3RequestOperation(RequestType request_type) {
	switch (request_type) {
	case RequestType::GET_REQUEST:
		return "reading";
	case RequestType::HEAD_REQUEST:
		return "checking";
	case RequestType::PUT_REQUEST:
		return "uploading to";
	case RequestType::DELETE_REQUEST:
		return "deleting";
	case RequestType::POST_REQUEST:
		return "sending a request to";
	case RequestType::OPTIONS_REQUEST:
		return "checking options for";
	}
	throw InternalException("Unsupported S3 request type");
}

static bool IsAuthRefreshStatus(const ErrorData &error) {
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
	return body_entry != extra_info.end() && IsAuthRefreshErrorBody(body_entry->second);
}

static bool IsAuthRefreshStatus(const HTTPResponse &response) {
	if (response.status == HTTPStatusCode::Unauthorized_401 || response.status == HTTPStatusCode::Forbidden_403) {
		return true;
	}
	return response.status == HTTPStatusCode::BadRequest_400 && IsAuthRefreshErrorBody(response.body);
}

static S3AuthParams ReadS3AuthParams(optional_ptr<FileOpener> opener, const string &path) {
	FileOpenerInfo info = {path};
	auto auth_params = S3AuthParams::ReadFrom(opener, info);
	S3Url::Resolve(path, auth_params);
	return auth_params;
}

S3RefreshableHTTPParams S3RequestExecutor::ReadRefreshableHTTPParams(optional_ptr<FileOpener> opener,
                                                                     const string &path) {
	FileOpenerInfo info = {path};
	auto &http_util = HTTPFSUtil::GetHTTPUtil(opener);
	auto params = http_util.InitializeParameters(opener, info);
	return S3RefreshableHTTPParams(params->Cast<HTTPFSParams>());
}

static bool TryRefreshS3SecretForPath(ClientContext &context, const string &path) {
	auto transaction = CatalogTransaction::GetSystemCatalogTransaction(context);
	bool refreshed_secret = false;
	for (const auto type : S3Provider::SecretTypes()) {
		auto res = context.db->GetSecretManager().LookupSecret(transaction, path, type);
		if (res.HasMatch()) {
			refreshed_secret |= CreateS3SecretFunctions::TryRefreshS3Secret(context, *res.secret_entry);
		}
	}
	return refreshed_secret;
}

bool S3RequestExecutor::CredentialRefreshEnabled(optional_ptr<FileOpener> opener) {
	Value value;
	if (FileOpener::TryGetCurrentSetting(opener, "httpfs_enable_credential_refresh", value)) {
		return value.GetValue<bool>();
	}
	return true;
}

static bool ReloadS3AuthMaterial(optional_ptr<FileOpener> opener, const string &path, S3AuthParams &auth_params,
                                 HTTPFSParams &http_params, bool preserve_region) {
	if (!opener) {
		return false;
	}

	auto previous_region = auth_params.region;
	auto reloaded_auth_params = ReadS3AuthParams(opener, path);
	if (preserve_region && !previous_region.empty() && reloaded_auth_params.region != previous_region) {
		reloaded_auth_params.SetRegion(std::move(previous_region));
	}
	auto reloaded_http_params = S3RequestExecutor::ReadRefreshableHTTPParams(opener, path);

	if (reloaded_auth_params == auth_params && reloaded_http_params == S3RefreshableHTTPParams(http_params)) {
		return false;
	}

	auth_params = std::move(reloaded_auth_params);
	reloaded_http_params.Apply(http_params);
	return true;
}

static bool TryRefreshS3AuthMaterial(optional_ptr<ClientContext> context, optional_ptr<FileOpener> opener,
                                     const string &path, S3AuthParams &auth_params, HTTPFSParams &http_params,
                                     bool credential_refresh_enabled, bool preserve_region = false) {
	if (!credential_refresh_enabled) {
		return false;
	}
	if (!context) {
		return false;
	}
	if (ReloadS3AuthMaterial(opener, path, auth_params, http_params, preserve_region)) {
		return true;
	}

	auto http_state = HTTPState::TryGetState(*context);
	return http_state->RunCredentialRefresh([&]() {
		if (ReloadS3AuthMaterial(opener, path, auth_params, http_params, preserve_region)) {
			return true;
		}
		if (!TryRefreshS3SecretForPath(*context, path)) {
			return false;
		}
		return ReloadS3AuthMaterial(opener, path, auth_params, http_params, preserve_region);
	});
}

S3RequestData S3RequestExecutor::CreateRequestData(EncryptionUtil &encryption_util,
                                                   const CapturedHTTPRequestSnapshot &captured, const string &s3_url,
                                                   RequestType request_type, S3RequestTarget target,
                                                   const CreateQueryCallback &create_query, const string &payload_hash,
                                                   const string &content_type, const string &content_md5) {
	auto &snapshot = captured.snapshot->Cast<S3RequestSnapshot>();
	S3RequestData result;
	result.request_type = request_type;
	result.captured = captured;
	result.auth_params = snapshot.auth_params;
	result.http_params = snapshot.CreateRequestParams();
	auto parsed_s3_url = S3Url::Parse(s3_url, result.auth_params);
	result.display_url = S3Url::GetDisplayUrl(s3_url, result.auth_params);
	auto query = create_query(parsed_s3_url);
	result.http_url = target == S3RequestTarget::BUCKET ? parsed_s3_url.GetBucketHTTPUrl(query.WireQuery())
	                                                    : parsed_s3_url.GetHTTPUrl(query.WireQuery());
	auto &http_params = result.http_params->Cast<HTTPFSParams>();
	result.headers = S3RequestUtil::CreateHeaders(encryption_util, parsed_s3_url, target, query, request_type,
	                                              result.auth_params, "", "", payload_hash, content_type, content_md5,
	                                              http_params.extra_headers, http_params.user_agent);
	return result;
}

S3RequestData S3RequestExecutor::CreateHandleRequestData(EncryptionUtil &encryption_util, S3FileHandle &s3_handle,
                                                         const string &s3_url, RequestType request_type,
                                                         const string &version_id) {
	auto captured = s3_handle.request_session->Capture();
	return S3RequestExecutor::CreateRequestData(
	    encryption_util, captured, s3_url, request_type, S3RequestTarget::OBJECT, [&](const ParsedS3Url &) {
		    return version_id.empty() ? S3RequestQuery() : S3RequestQuery({{"versionId", version_id}});
	    });
}

static optional_idx GetRegionRedirect(const HTTPResponse &response, const S3AuthParams &auth_params,
                                      string &region_out) {
	if (response.status != HTTPStatusCode::MovedPermanently_301 && response.status != HTTPStatusCode::BadRequest_400) {
		return {};
	}
	if (!response.HasHeader("x-amz-bucket-region")) {
		return {};
	}
	auto response_region = response.GetHeaderValue("x-amz-bucket-region");
	if (response_region.empty() || response_region == auth_params.region) {
		return {};
	}
	region_out = std::move(response_region);
	return {0};
}

static optional_idx GetRegionRedirect(const ErrorData &error, const S3AuthParams &auth_params, string &region_out) {
	auto &extra_info = error.ExtraInfo();
	auto entry = extra_info.find("status_code");
	if (entry == extra_info.end() || (entry->second != "301" && entry->second != "400")) {
		return {};
	}
	auto new_region = extra_info.find("header_x-amz-bucket-region");
	if (new_region == extra_info.end() || new_region->second.empty() || new_region->second == auth_params.region) {
		return {};
	}
	region_out = new_region->second;
	return {0};
}

// Core's status-based retry can't catch this: the discriminator is only in the S3 error body.
bool S3RequestUtil::IsRequestTimeout(const HTTPResponse &response) {
	if (response.status != HTTPStatusCode::BadRequest_400 || response.body.empty()) {
		return false;
	}
	S3XMLError error;
	return S3XMLResponseParser::TryParseError(response.body, error) && error.code == "RequestTimeout";
}

bool S3RequestUtil::IsRetryableReceivedResponse(const HTTPResponse &response) {
	if (response.HasRequestError()) {
		return false;
	}
	auto status = static_cast<int>(response.status);
	if (response.status == HTTPStatusCode::TooManyRequests_429 || (status >= 500 && status < 600)) {
		return true;
	}
	S3XMLError error;
	if (!S3XMLResponseParser::TryParseError(response.body, error)) {
		return false;
	}
	return error.code == "InternalError" || error.code == "OperationAborted" || error.code == "SlowDown" ||
	       error.code == "ServiceUnavailable" || error.code == "TooManyRequests" || error.code == "RequestTimeout";
}

static bool IsS3RequestTimeoutError(const ErrorData &error) {
	auto &extra_info = error.ExtraInfo();
	auto status_entry = extra_info.find("status_code");
	auto body_entry = extra_info.find("response_body");
	if (status_entry == extra_info.end() || status_entry->second != "400" || body_entry == extra_info.end()) {
		return false;
	}
	S3XMLError s3_error;
	return S3XMLResponseParser::TryParseError(body_entry->second, s3_error) && s3_error.code == "RequestTimeout";
}

void S3RequestExecutor::SleepForRetry(const HTTPParams &http_params, idx_t retries, double &wait_ms) {
	if (retries == 0) {
		wait_ms = static_cast<double>(http_params.retry_wait_ms);
		return;
	}
#ifndef DUCKDB_NO_THREADS
	ThreadUtil::SleepMs(static_cast<idx_t>(wait_ms));
#endif
	wait_ms *= http_params.retry_backoff;
}

static bool IsTransientRetryEligibleMethod(RequestType request_type) {
	return request_type == RequestType::GET_REQUEST || request_type == RequestType::HEAD_REQUEST ||
	       request_type == RequestType::PUT_REQUEST || request_type == RequestType::DELETE_REQUEST;
}

static bool ShouldRetryReceivedResponse(const S3RequestData &request_data, const HTTPResponse &response,
                                        S3PostRequestMode post_request_mode) {
	if (response.HasRequestError()) {
		return false;
	}
	if (IsTransientRetryEligibleMethod(request_data.request_type) && S3RequestUtil::IsRequestTimeout(response)) {
		return true;
	}
	return post_request_mode == S3PostRequestMode::RETRY_RECEIVED_RESPONSES &&
	       S3RequestUtil::IsRetryableReceivedResponse(response);
}

unique_ptr<HTTPResponse>
S3RequestExecutor::Run(const string &s3_url, const CreateDataCallback &create_data, const RequestCallback &request,
                       const RefreshCallback &refresh_auth_params, const SetRegionCallback &set_region,
                       const FinalRequestCallback &final_request, const FreshConnectionCallback &fresh_connection,
                       S3PostRequestMode post_request_mode, const ReceivedResponseCallback &response_callback) {
	// Auth refresh and region redirect are one-shot; transient responses follow the configured HTTP retry policy.
	bool retried_auth_refresh = false;
	bool retried_region = false;
	idx_t transient_retries = 0;
	double transient_wait_ms = 0;
	for (;;) {
		auto request_data = create_data();
		auto &http_params = request_data.http_params->Cast<HTTPFSParams>();
		try {
			auto result = request(request_data);
			auto received_response = result && !result->HasRequestError();
			if (received_response && !retried_auth_refresh && IsAuthRefreshStatus(*result) &&
			    refresh_auth_params(request_data)) {
				retried_auth_refresh = true;
				continue;
			}
			string correct_region;
			if (received_response && !retried_region &&
			    GetRegionRedirect(*result, request_data.auth_params, correct_region).IsValid()) {
				set_region(request_data, correct_region);
				retried_region = true;
				continue;
			}
			if (received_response && transient_retries < http_params.retries &&
			    ShouldRetryReceivedResponse(request_data, *result, post_request_mode)) {
				SleepForRetry(http_params, transient_retries, transient_wait_ms);
				transient_retries++;
				continue;
			}
			if (received_response && response_callback &&
			    response_callback(request_data, *result) == S3ReceivedResponseAction::RETRY_FRESH_CONNECTION &&
			    transient_retries < http_params.retries) {
				D_ASSERT(fresh_connection);
				fresh_connection(request_data);
				SleepForRetry(http_params, transient_retries, transient_wait_ms);
				transient_retries++;
				continue;
			}
			if (final_request) {
				final_request(request_data);
			}
			return result;
		} catch (std::exception &ex) {
			ErrorData error(ex);
			if (!retried_auth_refresh && IsAuthRefreshStatus(error) && refresh_auth_params(request_data)) {
				retried_auth_refresh = true;
				continue;
			}
			string correct_region;
			if (!retried_region && GetRegionRedirect(error, request_data.auth_params, correct_region).IsValid()) {
				set_region(request_data, correct_region);
				retried_region = true;
				continue;
			}
			if (IsTransientRetryEligibleMethod(request_data.request_type) && transient_retries < http_params.retries &&
			    IsS3RequestTimeoutError(error)) {
				SleepForRetry(http_params, transient_retries, transient_wait_ms);
				transient_retries++;
				continue;
			}
			throw;
		}
	}
}

bool S3RequestExecutor::TryRefreshSession(HTTPRequestSession &session, const S3RequestData &request_data) {
	auto current = session.Capture();
	auto &failed_snapshot = request_data.captured.snapshot->Cast<S3RequestSnapshot>();
	auto &current_snapshot = current.snapshot->Cast<S3RequestSnapshot>();
	if (current_snapshot.credential_generation != failed_snapshot.credential_generation) {
		return true;
	}
	if (!current_snapshot.credential_refresh_enabled) {
		return false;
	}

	auto context = current_snapshot.client_context.lock();
	if (!context) {
		return false;
	}
	ClientContextFileOpener opener(*context);
	auto refreshed_auth_params = current_snapshot.auth_params;
	auto refreshed_http_params = current_snapshot.CreateRequestParams();
	if (!TryRefreshS3AuthMaterial(context, opener, current_snapshot.refresh_path, refreshed_auth_params,
	                              *refreshed_http_params, current_snapshot.credential_refresh_enabled,
	                              current_snapshot.region_redirected)) {
		return session.Capture().snapshot->Cast<S3RequestSnapshot>().credential_generation !=
		       failed_snapshot.credential_generation;
	}
	auto refreshed_http_material = S3RefreshableHTTPParams(*refreshed_http_params);
	for (;;) {
		current = session.Capture();
		auto &latest = current.snapshot->Cast<S3RequestSnapshot>();
		if (latest.credential_generation != failed_snapshot.credential_generation) {
			return true;
		}

		auto merged_auth_params = refreshed_auth_params;
		if (latest.region_redirected) {
			merged_auth_params.SetRegion(latest.auth_params.region);
		}
		if (latest.multipart_upload_policy &&
		    !(S3Provider::GetMultipartUploadPolicy(merged_auth_params) == *latest.multipart_upload_policy)) {
			throw IOException("Cannot refresh credentials for an active S3 upload because the refreshed endpoint "
			                  "requires a different multipart upload policy");
		}
		auto merged_http_params = latest.CreateRequestParams();
		refreshed_http_material.Apply(*merged_http_params);
		auto replacement = make_shared_ptr<S3RequestSnapshot>(
		    *merged_http_params, merged_auth_params, latest.refresh_path, latest.client_context,
		    latest.credential_refresh_enabled, latest.region_redirected, latest.credential_generation + 1,
		    latest.multipart_upload_policy);
		auto publication = session.TryPublish(current.snapshot, std::move(replacement));
		if (publication.published) {
			return true;
		}
	}
}

bool S3RequestExecutor::SetSessionRegion(HTTPRequestSession &session, const string &correct_region,
                                         string &previous_region) {
	for (;;) {
		auto current = session.Capture();
		auto &snapshot = current.snapshot->Cast<S3RequestSnapshot>();
		if (snapshot.auth_params.region == correct_region) {
			return false;
		}

		auto auth_params = snapshot.auth_params;
		previous_region = auth_params.region;
		auth_params.SetRegion(correct_region);
		auto http_params = snapshot.CreateRequestParams();
		auto replacement =
		    make_shared_ptr<S3RequestSnapshot>(*http_params, auth_params, snapshot.refresh_path,
		                                       snapshot.client_context, snapshot.credential_refresh_enabled, true,
		                                       snapshot.credential_generation, snapshot.multipart_upload_policy);
		auto publication = session.TryPublish(current.snapshot, std::move(replacement));
		if (publication.published) {
			return true;
		}
	}
}

unique_ptr<HTTPResponse>
S3RequestExecutor::RunSession(EncryptionUtil &encryption_util, HTTPRequestSession &session, const string &s3_url,
                              RequestType request_type, S3RequestTarget target, const CreateQueryCallback &create_query,
                              const string &payload_hash, const string &content_type, const string &content_md5,
                              const RequestCallback &request, const RegionRedirectCallback &region_redirect,
                              optional_ptr<S3RequestContext> request_context, S3PostRequestMode post_request_mode,
                              const ReceivedResponseCallback &response_callback) {
	return S3RequestExecutor::Run(
	    s3_url,
	    [&]() {
		    return S3RequestExecutor::CreateRequestData(encryption_util, session.Capture(), s3_url, request_type,
		                                                target, create_query, payload_hash, content_type, content_md5);
	    },
	    request,
	    [&](const S3RequestData &request_data) { return S3RequestExecutor::TryRefreshSession(session, request_data); },
	    [&](const S3RequestData &request_data, const string &correct_region) {
		    string previous_region;
		    if (S3RequestExecutor::SetSessionRegion(session, correct_region, previous_region) && region_redirect) {
			    region_redirect(request_data, previous_region, correct_region);
		    }
	    },
	    [&](const S3RequestData &request_data) {
		    if (request_context) {
			    request_context->request_type = request_data.request_type;
			    request_context->auth_params = request_data.auth_params;
			    request_context->display_url = request_data.display_url;
		    }
	    },
	    [&](const S3RequestData &request_data) {
		    auto &params = request_data.http_params->Cast<HTTPFSParams>();
		    S3RequestExecutor::InvalidateSessionConnections(session, params);
	    },
	    post_request_mode, response_callback);
}

unique_ptr<HTTPResponse> S3RequestExecutor::RunHandle(EncryptionUtil &encryption_util, S3FileHandle &s3_handle,
                                                      const string &s3_url, RequestType request_type,
                                                      const string &version_id, const RequestCallback &request) {
	return S3RequestExecutor::Run(
	    s3_url,
	    [&]() {
		    return S3RequestExecutor::CreateHandleRequestData(encryption_util, s3_handle, s3_url, request_type,
		                                                      version_id);
	    },
	    request,
	    [&](const S3RequestData &request_data) {
		    return S3RequestExecutor::TryRefreshSession(*s3_handle.request_session, request_data);
	    },
	    [&](const S3RequestData &request_data, const string &correct_region) {
		    string previous_region;
		    if (S3RequestExecutor::SetSessionRegion(*s3_handle.request_session, correct_region, previous_region)) {
			    auto &params = request_data.http_params->Cast<HTTPFSParams>();
			    DUCKDB_LOG_WARNING(
			        params.logger,
			        "Read S3 file \"%s\" from incorrect region \"%s\" - retrying with updated region \"%s\".\n"
			        "Consider setting the S3 region to this explicitly to avoid extra round-trips.",
			        request_data.display_url, previous_region, correct_region);
		    }
	    },
	    {}, {}, S3PostRequestMode::DEFAULT);
}

void S3RequestExecutor::InvalidateSessionConnections(HTTPRequestSession &session, HTTPFSParams &params) {
	session.InvalidateClients();
	if (params.httpfs_util) {
		params.httpfs_util->ClearCachedConnections();
	}
}

unique_ptr<HTTPResponse> S3RequestExecutor::SendSessionRequest(HTTPRequestSession &session,
                                                               const CapturedHTTPRequestSnapshot &captured,
                                                               HTTPFSParams &params, BaseRequest &request) {
	auto lease = session.AcquireClient(captured, params, request.proto_host_port);
	try {
		auto response = params.http_util.Request(request, lease.Client());
		auto request_timeout = response && S3RequestUtil::IsRequestTimeout(*response);
		// A completed S3 response leaves the transport reusable unless it reports a stalled connection.
		if (response && (request_timeout || response->HasRequestError())) {
			lease.Invalidate();
		}
		if (request_timeout) {
			InvalidateSessionConnections(session, params);
		}
		return response;
	} catch (std::exception &ex) {
		lease.Invalidate();
		if (IsS3RequestTimeoutError(ErrorData(ex))) {
			InvalidateSessionConnections(session, params);
		}
		throw;
	} catch (...) {
		lease.Invalidate();
		throw;
	}
}

unique_ptr<HTTPResponse> S3RequestExecutor::SendHandleRequest(S3FileHandle &s3_handle,
                                                              const CapturedHTTPRequestSnapshot &captured,
                                                              HTTPFSParams &params, BaseRequest &request) {
	return S3RequestExecutor::SendSessionRequest(*s3_handle.request_session, captured, params, request);
}

HTTPException S3RequestUtil::GetRequestError(const S3RequestData &request_data, const HTTPResponse &response) {
	return S3RequestUtil::GetError(request_data.auth_params, response, request_data.request_type,
	                               S3RequestOperation(request_data.request_type), request_data.display_url);
}

S3RequestSnapshot::S3RequestSnapshot(const HTTPFSParams &http_params, const S3AuthParams &auth_params_p,
                                     string refresh_path_p, weak_ptr<ClientContext> client_context_p,
                                     bool credential_refresh_enabled_p, bool region_redirected_p,
                                     idx_t credential_generation_p,
                                     optional<S3MultipartUploadPolicy> multipart_upload_policy_p)
    : HTTPRequestSnapshot(http_params, TYPE), auth_params(auth_params_p), refresh_path(std::move(refresh_path_p)),
      client_context(std::move(client_context_p)), credential_refresh_enabled(credential_refresh_enabled_p),
      region_redirected(region_redirected_p), credential_generation(credential_generation_p),
      multipart_upload_policy(std::move(multipart_upload_policy_p)) {
}

string S3RequestUtil::GetPayloadHash(EncryptionUtil &encryption_util, const_data_ptr_t buffer, idx_t buffer_len) {
	if (buffer_len > 0) {
		hash_bytes payload_hash_bytes;
		hash_str payload_hash_str;
		sha256(encryption_util, buffer, buffer_len, payload_hash_bytes);
		hex256(payload_hash_bytes, payload_hash_str);
		return string(const_char_ptr_cast(payload_hash_str), sizeof(payload_hash_str));
	} else {
		return "";
	}
}

unique_ptr<HTTPResponse> S3FileSystem::PostRequest(HTTPRequestSession &session, const string &url, string &result,
                                                   const_data_ptr_t buffer_in, idx_t buffer_in_len,
                                                   const S3RequestQuery &query, S3PostRequestMode mode,
                                                   optional_ptr<S3RequestContext> request_context) {
	auto payload_hash = S3RequestUtil::GetPayloadHash(GetEncryptionUtil(), buffer_in, buffer_in_len);
	const string content_type = "application/octet-stream";
	return S3RequestExecutor::RunSession(
	    GetEncryptionUtil(), session, url, RequestType::POST_REQUEST, S3RequestTarget::OBJECT,
	    [&](const ParsedS3Url &) { return query; }, payload_hash, content_type, "",
	    [&](S3RequestData &request_data) {
		    result.clear();
		    auto &params = request_data.http_params->Cast<HTTPFSParams>();
		    return RunPostRequest(request_data.http_url, request_data.headers, params, result, buffer_in, buffer_in_len,
		                          [&](BaseRequest &request) {
			                          request.try_request = true;
			                          return S3RequestExecutor::SendSessionRequest(session, request_data.captured,
			                                                                       params, request);
		                          });
	    },
	    {}, request_context, mode);
}

unique_ptr<HTTPResponse> S3FileSystem::PutRequest(HTTPRequestSession &session, const string &url,
                                                  const_data_ptr_t buffer_in, idx_t buffer_in_len,
                                                  const S3RequestQuery &query,
                                                  optional_ptr<S3RequestContext> request_context) {
	auto payload_hash = S3RequestUtil::GetPayloadHash(GetEncryptionUtil(), buffer_in, buffer_in_len);
	const string content_type = "application/octet-stream";
	return S3RequestExecutor::RunSession(
	    GetEncryptionUtil(), session, url, RequestType::PUT_REQUEST, S3RequestTarget::OBJECT,
	    [&](const ParsedS3Url &) { return query; }, payload_hash, content_type, "",
	    [&](S3RequestData &request_data) {
		    auto &params = request_data.http_params->Cast<HTTPFSParams>();
		    return RunPutRequest(request_data.http_url, request_data.headers, params, buffer_in, buffer_in_len,
		                         content_type, [&](BaseRequest &request) {
			                         request.try_request = true;
			                         return S3RequestExecutor::SendSessionRequest(session, request_data.captured,
			                                                                      params, request);
		                         });
	    },
	    {}, request_context);
}

unique_ptr<HTTPResponse> S3FileSystem::HeadRequest(FileHandle &handle, const string &s3_url, HTTPHeaders header_map) {
	auto &s3_handle = handle.Cast<S3FileHandle>();
	return S3RequestExecutor::RunHandle(
	    GetEncryptionUtil(), s3_handle, s3_url, RequestType::HEAD_REQUEST, {}, [&](S3RequestData &request_data) {
		    auto &params = request_data.http_params->Cast<HTTPFSParams>();
		    return RunHeadRequest(request_data.http_url, request_data.headers, params, [&](BaseRequest &request) {
			    return S3RequestExecutor::SendHandleRequest(s3_handle, request_data.captured, params, request);
		    });
	    });
}

unique_ptr<HTTPResponse> S3FileSystem::GetRequest(FileHandle &handle, string s3_url, HTTPHeaders header_map,
                                                  const HTTPReadConfig &read_config, CachedFileDownload &download) {
	auto &s3_handle = handle.Cast<S3FileHandle>();
	const auto version_id =
	    read_config.condition.type == HTTPReadConditionType::S3_VERSION_ID ? read_config.condition.value : string();
	return S3RequestExecutor::RunHandle(
	    GetEncryptionUtil(), s3_handle, s3_url, RequestType::GET_REQUEST, version_id, [&](S3RequestData &request_data) {
		    auto &params = request_data.http_params->Cast<HTTPFSParams>();
		    return RunGetRequest(
		        s3_handle, request_data.http_url, request_data.headers, params, read_config, download,
		        [&](const HTTPResponse &response) { return S3RequestUtil::GetRequestError(request_data, response); },
		        [&](BaseRequest &request) {
			        return S3RequestExecutor::SendHandleRequest(s3_handle, request_data.captured, params, request);
		        });
	    });
}

unique_ptr<HTTPResponse> S3FileSystem::GetRangeRequest(FileHandle &handle, string s3_url, HTTPHeaders header_map,
                                                       const HTTPReadConfig &read_config, idx_t file_offset,
                                                       data_ptr_t buffer_out, idx_t buffer_out_len) {
	auto &s3_handle = handle.Cast<S3FileHandle>();
	const auto version_id =
	    read_config.condition.type == HTTPReadConditionType::S3_VERSION_ID ? read_config.condition.value : string();
	return S3RequestExecutor::RunHandle(
	    GetEncryptionUtil(), s3_handle, s3_url, RequestType::GET_REQUEST, version_id, [&](S3RequestData &request_data) {
		    auto &params = request_data.http_params->Cast<HTTPFSParams>();
		    return RunGetRangeRequest(
		        s3_handle, request_data.http_url, request_data.headers, params, read_config, file_offset, buffer_out,
		        buffer_out_len,
		        [&](const HTTPResponse &response) { return S3RequestUtil::GetRequestError(request_data, response); },
		        [&](BaseRequest &request) {
			        return S3RequestExecutor::SendHandleRequest(s3_handle, request_data.captured, params, request);
		        });
	    });
}

unique_ptr<HTTPResponse> S3FileSystem::DeleteRequest(FileHandle &handle, const string &s3_url, HTTPHeaders header_map) {
	auto &s3_handle = handle.Cast<S3FileHandle>();
	return S3RequestExecutor::RunHandle(
	    GetEncryptionUtil(), s3_handle, s3_url, RequestType::DELETE_REQUEST, {}, [&](S3RequestData &request_data) {
		    auto &params = request_data.http_params->Cast<HTTPFSParams>();
		    return RunDeleteRequest(request_data.http_url, request_data.headers, params, [&](BaseRequest &request) {
			    return S3RequestExecutor::SendHandleRequest(s3_handle, request_data.captured, params, request);
		    });
	    });
}

unique_ptr<HTTPResponse> S3FileSystem::DeleteRequest(HTTPRequestSession &session, const string &s3_url,
                                                     const S3RequestQuery &query,
                                                     optional_ptr<S3RequestContext> request_context) {
	return S3RequestExecutor::RunSession(
	    GetEncryptionUtil(), session, s3_url, RequestType::DELETE_REQUEST, S3RequestTarget::OBJECT,
	    [&](const ParsedS3Url &) { return query; }, "", "", "",
	    [&](S3RequestData &request_data) {
		    auto &params = request_data.http_params->Cast<HTTPFSParams>();
		    return RunDeleteRequest(request_data.http_url, request_data.headers, params, [&](BaseRequest &request) {
			    return S3RequestExecutor::SendSessionRequest(session, request_data.captured, params, request);
		    });
	    },
	    {}, request_context);
}

string S3RequestUtil::ParseError(const string &error) {
	S3XMLError parsed_error;
	if (!S3XMLResponseParser::TryParseError(error, parsed_error) || parsed_error.code.empty()) {
		return string();
	}
	string result = "\n\n" + parsed_error.code;
	if (!parsed_error.message.empty()) {
		result += ": " + parsed_error.message;
	}
	if (parsed_error.code == "InvalidAccessKeyId" && !parsed_error.access_key_id.empty()) {
		result += "\nInvalid Access Key: \"" + parsed_error.access_key_id + "\"";
	}
	return result;
}

HTTPException S3RequestUtil::GetError(const S3AuthParams &s3_auth_params, const HTTPResponse &response,
                                      RequestType request_type, const string &operation, const string &display_url) {
	string extra_text = S3RequestUtil::ParseError(response.body);
	if (response.status == HTTPStatusCode::BadRequest_400) {
		extra_text += S3Provider::GetBadRequestError(s3_auth_params);
	}
	if (response.status == HTTPStatusCode::Unauthorized_401 || response.status == HTTPStatusCode::Forbidden_403) {
		extra_text += S3Provider::GetAuthError(s3_auth_params);
	}
	return HTTPFSUtil::GetHTTPStatusError(response, request_type, operation, display_url, extra_text);
}

HTTPException S3FileSystem::GetHTTPError(FileHandle &handle, const HTTPResponse &response, RequestType request_type,
                                         const string &url) {
	auto &s3_handle = handle.Cast<S3FileHandle>();
	auto captured = s3_handle.request_session->Capture();
	auto auth_params = captured.snapshot->Cast<S3RequestSnapshot>().auth_params;
	return S3RequestUtil::GetError(auth_params, response, request_type, S3RequestOperation(request_type),
	                               S3Url::GetDisplayUrl(url, auth_params));
}

shared_ptr<HTTPRequestSession> S3RequestExecutor::CreateSession(optional_ptr<FileOpener> opener, const string &path,
                                                                const S3AuthParams &auth_params) {
	FileOpenerInfo info = {path};
	auto &http_util = HTTPFSUtil::GetHTTPUtil(opener);
	auto http_params = http_util.InitializeParameters(opener, info);
	weak_ptr<ClientContext> weak_context;
	auto context = FileOpener::TryGetClientContext(opener);
	auto refresh_enabled = CredentialRefreshEnabled(opener);
	if (context && refresh_enabled) {
		weak_context = context->shared_from_this();
	}
	return make_shared_ptr<HTTPRequestSession>(make_shared_ptr<S3RequestSnapshot>(
	    http_params->Cast<HTTPFSParams>(), auth_params, path, std::move(weak_context), refresh_enabled));
}

} // namespace duckdb
