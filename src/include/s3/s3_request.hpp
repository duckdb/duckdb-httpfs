#pragma once

#include "http/httpfs.hpp"
#include "s3/s3_url.hpp"

#include "duckdb/common/encryption_state.hpp"

#include <functional>
#include <initializer_list>
#include <unordered_map>

namespace duckdb {

class ClientContext;
class HTTPRetryBudget;
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
enum class S3RequestOperation : uint8_t {
	HEAD_OBJECT,
	GET_OBJECT,
	PUT_OBJECT,
	DELETE_OBJECT,
	LIST_OBJECTS,
	DELETE_OBJECTS,
	CREATE_MULTIPART_UPLOAD,
	UPLOAD_PART,
	COMPLETE_MULTIPART_UPLOAD,
	ABORT_MULTIPART_UPLOAD
};
enum class S3ReceivedResponseAction : uint8_t { ACCEPT, RETRY_FRESH_CONNECTION };
//! What the operation's handler makes of a received response, decided before the retry quota is settled: only a
//! validated SUCCESS refunds the retry the operation consumed; a FAILURE (an S3 error document, a final status) and
//! an UNKNOWN outcome (a body the handler cannot read) keep it charged. The handler still reports an unknown outcome
//! to its caller as before; the executor only never mistakes it for a success.
enum class S3OperationOutcome : uint8_t { SUCCESS, FAILURE, UNKNOWN };

struct S3RequestOperationInfo {
	RequestType request_type;
	S3RequestTarget target;
	const char *description;
	bool retry_timeout;
	bool retry_received_response;
	bool uses_kms_headers;
	bool uses_sse_customer_headers;
};

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
	S3RequestOperation operation;
	CapturedHTTPRequestSnapshot captured;
	string display_url;
	//! Retries admitted for HTTP 429 or 503 responses.
	idx_t throttled_retries = 0;

	const S3AuthParams &GetAuthParams() const {
		D_ASSERT(captured.snapshot);
		return captured.snapshot->Cast<S3RequestSnapshot>().auth_params;
	}
};

struct S3RequestResult {
	unique_ptr<HTTPResponse> response;
	S3RequestContext context;
	//! The operation's validated outcome (S3RequestExecutor::ValidateCallback), kept for the handling that follows;
	//! FAILURE when no response was received or the last one was retryable but could not be retried.
	S3OperationOutcome outcome = S3OperationOutcome::FAILURE;
};

struct S3RequestSpec {
	using CreateQueryCallback = std::function<S3RequestQuery(const ParsedS3Url &)>;

	string url;
	S3RequestOperation operation;
	CreateQueryCallback create_query;
	string payload_hash;
	string content_type;
	string content_md5;
	HTTPObjectVersion object_version;
	HTTPReadCondition read_condition;
};

struct S3RequestData {
	friend struct S3RequestExecutor;

private:
	S3RequestData(S3RequestOperation operation_p, S3AuthParams auth_params_p, HTTPRetryBudget &retry_budget_p)
	    : operation(operation_p), auth_params(std::move(auth_params_p)), retry_budget(retry_budget_p) {
	}
	S3RequestData(S3RequestData &&) = default;

public:
	S3RequestOperation operation;
	S3AuthParams auth_params;
	unique_ptr<HTTPParams> http_params;
	CapturedHTTPRequestSnapshot captured;
	string http_url;
	string display_url;
	HTTPHeaders headers;

private:
	//! Borrowed from the executor for this operation, including all reconstructed requests.
	HTTPRetryBudget &retry_budget;
};

struct S3RequestUtil {
	static const S3RequestOperationInfo &GetOperationInfo(S3RequestOperation operation);
	static HTTPHeaders CreateHeaders(EncryptionUtil &encryption_util, const ParsedS3Url &parsed_url,
	                                 S3RequestOperation operation, const S3RequestQuery &query,
	                                 const S3AuthParams &auth_params, string date_now = "", string datetime_now = "",
	                                 string payload_hash = "", string content_type = "", string content_md5 = "",
	                                 const HTTPConfiguredHeaders &configured_headers = {},
	                                 const HTTPReadCondition &read_condition = {});
	static string GetPayloadHash(EncryptionUtil &encryption_util, const_data_ptr_t buffer, idx_t buffer_len);
	static bool IsRequestTimeout(const HTTPResponse &response);
	static bool IsRetryableReceivedResponse(const HTTPResponse &response);
	//! The validation of an operation whose outcome is its status alone (S3 answers these with an error status, never
	//! with an error document behind a 2xx): a received response with one of the operation's accepted statuses is a
	//! success, anything else a failure. Operations that read a document or a required header validate those too.
	static S3OperationOutcome ValidateStatus(const HTTPResponse &response,
	                                         std::initializer_list<HTTPStatusCode> accepted_statuses);
	//! Whether a raised request error carries a throttling status, matching core's throttled retry admission.
	static bool IsThrottledError(const ErrorData &error);

	static string ParseError(const string &error);
	static HTTPException GetError(const S3AuthParams &s3_auth_params, const HTTPResponse &response,
	                              RequestType request_type, const string &operation, const string &display_url);
	static HTTPException GetRequestError(const S3RequestContext &request_context, const HTTPResponse &response);
	static HTTPException GetRequestError(const S3RequestData &request_data, const HTTPResponse &response);
};

struct S3RequestExecutor {
	//! Callbacks run synchronously and must not retain request data.
	using RequestCallback = std::function<unique_ptr<HTTPResponse>(S3RequestData &)>;
	using RegionRedirectCallback = std::function<void(const S3RequestData &, const string &, const string &)>;
	using ReceivedResponseCallback =
	    std::function<S3ReceivedResponseAction(const S3RequestData &, const HTTPResponse &)>;
	//! The operation's authoritative validation of a received response the executor does not retry (its accepted
	//! statuses, required headers or result document), run once before the host quota is settled. Every operation
	//! supplies one; what it parses it keeps for the handling that follows, so nothing is read twice.
	using ValidateCallback = std::function<S3OperationOutcome(const S3RequestData &, const HTTPResponse &)>;

	static S3RequestResult RunSession(EncryptionUtil &encryption_util, HTTPRequestSession &session,
	                                  const S3RequestSpec &spec, const RequestCallback &request,
	                                  const ValidateCallback &validate,
	                                  const RegionRedirectCallback &region_redirect = {},
	                                  const ReceivedResponseCallback &response_callback = {});
	static S3RequestResult RunHandle(EncryptionUtil &encryption_util, S3FileHandle &handle, const S3RequestSpec &spec,
	                                 const RequestCallback &request, const ValidateCallback &validate);

	static bool SetSessionRegion(HTTPRequestSession &session, const string &correct_region, string &previous_region);
	static bool CredentialRefreshEnabled(optional_ptr<FileOpener> opener);
	static S3RefreshableHTTPParams ReadRefreshableHTTPParams(HTTPFSUtil &http_util, optional_ptr<FileOpener> opener,
	                                                         const string &path);
	static shared_ptr<HTTPRequestSession> CreateSession(optional_ptr<FileOpener> opener, const string &path,
	                                                    const S3AuthParams &auth_params);
	static unique_ptr<HTTPResponse> SendSessionRequest(HTTPRequestSession &session, S3RequestData &request_data,
	                                                   BaseRequest &request);
	static unique_ptr<HTTPResponse> SendHandleRequest(S3FileHandle &handle, S3RequestData &request_data,
	                                                  BaseRequest &request);

private:
	using FreshConnectionCallback = std::function<void(const S3RequestData &)>;
	using RefreshCallback = std::function<bool(const S3RequestData &)>;
	using SetRegionCallback = std::function<void(const S3RequestData &, const string &)>;

	static S3RequestResult Run(EncryptionUtil &encryption_util, HTTPRequestSession &session, const S3RequestSpec &spec,
	                           const RequestCallback &request, const RefreshCallback &refresh_auth_params,
	                           const SetRegionCallback &set_region, const FreshConnectionCallback &fresh_connection,
	                           const ReceivedResponseCallback &response_callback, const ValidateCallback &validate);
	static bool TryRefreshSession(HTTPRequestSession &session, const S3RequestData &request_data);
	static void InvalidateSessionConnections(HTTPRequestSession &session);
	static S3RequestData CreateRequestData(EncryptionUtil &encryption_util, const CapturedHTTPRequestSnapshot &captured,
	                                       const S3RequestSpec &spec, HTTPRetryBudget &retry_budget);
};

} // namespace duckdb
