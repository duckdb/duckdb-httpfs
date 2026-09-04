#pragma once

#include "http/httpfs.hpp"
#include "s3/s3_url.hpp"

#include "duckdb/common/encryption_state.hpp"

#include <functional>
#include <initializer_list>
#include <unordered_map>

namespace duckdb {

class ClientContext;
class S3FileHandle;

struct S3RefreshableHTTPParams {
public:
	S3RefreshableHTTPParams() = default;
	explicit S3RefreshableHTTPParams(const HTTPFSParams &params);

public:
	void Apply(HTTPFSParams &target) const;
	bool operator==(const S3RefreshableHTTPParams &other) const;

public:
	string http_proxy;
	idx_t http_proxy_port = 0;
	string http_proxy_username;
	string http_proxy_password;
	unordered_map<string, string> extra_headers;
	bool override_verify_ssl = false;
	bool verify_ssl = true;
	string bearer_token;
};

enum class S3RequestTarget : uint8_t { OBJECT, BUCKET };
enum class S3PostRequestMode : uint8_t { DEFAULT, RETRY_RECEIVED_RESPONSES };
enum class S3ReceivedResponseAction : uint8_t { ACCEPT, RETRY_FRESH_CONNECTION };

struct S3RequestQuery {
	S3RequestQuery() = default;
	S3RequestQuery(std::initializer_list<pair<string, string>> parameters);
	explicit S3RequestQuery(vector<pair<string, string>> parameters);

public:
	const string &WireQuery() const;
	const string &CanonicalQuery() const;
	bool HasParameter(const string &name) const;

private:
	vector<pair<string, string>> parameters;
	string wire_query;
	string canonical_query;
};

struct S3RequestSnapshot : public HTTPRequestSnapshot {
public:
	S3RequestSnapshot(const HTTPFSParams &http_params, const S3AuthParams &auth_params_p, string refresh_path_p,
	                  weak_ptr<ClientContext> client_context_p = {}, bool credential_refresh_enabled_p = true,
	                  bool region_redirected_p = false, idx_t credential_generation_p = 0,
	                  optional<S3MultipartUploadPolicy> multipart_upload_policy_p = {});

public:
	static constexpr HTTPRequestSnapshotType TYPE = HTTPRequestSnapshotType::S3;
	S3AuthParams auth_params;
	string refresh_path;
	weak_ptr<ClientContext> client_context;
	bool credential_refresh_enabled;
	bool region_redirected;
	idx_t credential_generation;
	optional<S3MultipartUploadPolicy> multipart_upload_policy;
};

struct S3RequestContext {
	RequestType request_type = RequestType::GET_REQUEST;
	S3AuthParams auth_params;
	string display_url;
};

struct S3RequestData {
	RequestType request_type = RequestType::GET_REQUEST;
	S3AuthParams auth_params;
	unique_ptr<HTTPParams> http_params;
	CapturedHTTPRequestSnapshot captured;
	string http_url;
	string display_url;
	HTTPHeaders headers;
};

struct S3RequestUtil {
	static HTTPHeaders CreateHeaders(EncryptionUtil &encryption_util, const ParsedS3Url &parsed_url,
	                                 S3RequestTarget target, const S3RequestQuery &query, RequestType request_type,
	                                 const S3AuthParams &auth_params, string date_now = "", string datetime_now = "",
	                                 string payload_hash = "", string content_type = "", string content_md5 = "",
	                                 const unordered_map<string, string> &extra_headers = {},
	                                 const string &user_agent = "");
	static string GetPayloadHash(EncryptionUtil &encryption_util, const_data_ptr_t buffer, idx_t buffer_len);
	static bool IsRequestTimeout(const HTTPResponse &response);
	static bool IsRetryableReceivedResponse(const HTTPResponse &response);

	static string ParseError(const string &error);
	static HTTPException GetError(const S3AuthParams &auth_params, const HTTPResponse &response,
	                              RequestType request_type, const string &operation, const string &display_url);
	static HTTPException GetRequestError(const S3RequestData &request_data, const HTTPResponse &response);
};

struct S3RequestExecutor {
	using RequestCallback = std::function<unique_ptr<HTTPResponse>(S3RequestData &)>;
	using CreateQueryCallback = std::function<S3RequestQuery(const ParsedS3Url &)>;
	using RegionRedirectCallback = std::function<void(const S3RequestData &, const string &, const string &)>;
	using ReceivedResponseCallback =
	    std::function<S3ReceivedResponseAction(const S3RequestData &, const HTTPResponse &)>;

	static unique_ptr<HTTPResponse> RunSession(EncryptionUtil &encryption_util, HTTPRequestSession &session,
	                                           const string &s3_url, RequestType request_type, S3RequestTarget target,
	                                           const CreateQueryCallback &create_query, const string &payload_hash,
	                                           const string &content_type, const string &content_md5,
	                                           const RequestCallback &request,
	                                           const RegionRedirectCallback &region_redirect = {},
	                                           optional_ptr<S3RequestContext> request_context = nullptr,
	                                           S3PostRequestMode post_request_mode = S3PostRequestMode::DEFAULT,
	                                           const ReceivedResponseCallback &response_callback = {});
	static unique_ptr<HTTPResponse> RunHandle(EncryptionUtil &encryption_util, S3FileHandle &handle,
	                                          const string &s3_url, RequestType request_type, const string &version_id,
	                                          const RequestCallback &request);

	static bool SetSessionRegion(HTTPRequestSession &session, const string &correct_region, string &previous_region);
	static bool CredentialRefreshEnabled(optional_ptr<FileOpener> opener);
	static S3RefreshableHTTPParams ReadRefreshableHTTPParams(optional_ptr<FileOpener> opener, const string &path);
	static shared_ptr<HTTPRequestSession> CreateSession(optional_ptr<FileOpener> opener, const string &path,
	                                                    const S3AuthParams &auth_params);
	static void SleepForRetry(const HTTPParams &http_params, idx_t retries, double &wait_ms);

	static unique_ptr<HTTPResponse> SendSessionRequest(HTTPRequestSession &session,
	                                                   const CapturedHTTPRequestSnapshot &captured,
	                                                   HTTPFSParams &params, BaseRequest &request);
	static unique_ptr<HTTPResponse> SendHandleRequest(S3FileHandle &handle, const CapturedHTTPRequestSnapshot &captured,
	                                                  HTTPFSParams &params, BaseRequest &request);

private:
	using CreateDataCallback = std::function<S3RequestData()>;
	using FinalRequestCallback = std::function<void(const S3RequestData &)>;
	using FreshConnectionCallback = std::function<void(const S3RequestData &)>;
	using RefreshCallback = std::function<bool(const S3RequestData &)>;
	using SetRegionCallback = std::function<void(const S3RequestData &, const string &)>;

	static unique_ptr<HTTPResponse> Run(const string &s3_url, const CreateDataCallback &create_data,
	                                    const RequestCallback &request, const RefreshCallback &refresh_auth_params,
	                                    const SetRegionCallback &set_region, const FinalRequestCallback &final_request,
	                                    const FreshConnectionCallback &fresh_connection,
	                                    S3PostRequestMode post_request_mode = S3PostRequestMode::DEFAULT,
	                                    const ReceivedResponseCallback &response_callback = {});
	static bool TryRefreshSession(HTTPRequestSession &session, const S3RequestData &request_data);
	static void InvalidateSessionConnections(HTTPRequestSession &session, HTTPFSParams &params);
	static S3RequestData CreateRequestData(EncryptionUtil &encryption_util, const CapturedHTTPRequestSnapshot &captured,
	                                       const string &s3_url, RequestType request_type, S3RequestTarget target,
	                                       const CreateQueryCallback &create_query, const string &payload_hash = "",
	                                       const string &content_type = "", const string &content_md5 = "");
	static S3RequestData CreateHandleRequestData(EncryptionUtil &encryption_util, S3FileHandle &handle,
	                                             const string &s3_url, RequestType request_type,
	                                             const string &version_id);
};

} // namespace duckdb
