#pragma once

#include "duckdb/common/common.hpp"
#include "duckdb/common/optional_idx.hpp"

namespace duckdb {

enum class MockS3RefreshTarget : uint8_t {
	HEAD,
	FULL_GET,
	RANGE_GET,
	PUT,
	MULTIPART_INITIATE_POST,
	MULTIPART_COMPLETE_POST,
	BULK_DELETE_POST,
	DELETE_OBJECT,
	LIST_OBJECTS_GET
};

enum class MockS3RangeBehavior : uint8_t { NORMAL, IGNORE_RANGE, TRUNCATE_TRANSFER, SHORT_SUCCESS };

enum class MockS3MalformedListBehavior : uint8_t { TRUNCATED_XML, FOREIGN_NAMESPACE_KEY };

enum class MockS3MultipartInitializationBehavior : uint8_t {
	SUCCESS,
	NAMESPACED_ESCAPED_SUCCESS,
	MALFORMED_SUCCESS,
	CREATE_THEN_DISCONNECT
};

enum class MockS3MultipartCompletionBehavior : uint8_t {
	SUCCESS,
	EMBEDDED_ERROR,
	EMPTY_SUCCESS,
	UNKNOWN_SUCCESS,
	MALFORMED_SUCCESS,
	COMMIT_THEN_DISCONNECT
};

enum class MockS3MultipartAbortBehavior : uint8_t { SUCCESS, ERROR };

enum class MockS3MultipartGeometry : uint8_t { FLEXIBLE, FIXED_EQUAL };

enum class MockS3ETagBehavior : uint8_t { VALUE, EMPTY, OMIT };

struct MockS3ObjectConfig {
	string bucket = "refresh-bucket";
	string key = "object.bin";
	string data = "abcdefghijklmnopqrstuvwxyz0123456789";
};

struct MockS3AuthConfig {
	string stale_key_id = "STALE_KEY";
	string stale_authorization;
	int stale_status = 403;
	string stale_error_code = "AccessDenied";
	string required_region;
	MockS3RefreshTarget refresh_target = MockS3RefreshTarget::HEAD;
};

struct MockS3MetadataConfig {
	string etag = "\"httpfs-refresh-test-etag\"";
	//! ETag returned by GET; use etag when empty
	string get_etag;
	//! S3 version ID returned by selected metadata/data responses
	string version_id;
	bool version_on_head = false;
	bool version_on_get = false;
	//! Reject GETs whose If-Match does not equal the GET ETag
	bool enforce_if_match = false;
	//! Override the Content-Length reported by HEAD while keeping the GET body unchanged
	optional_idx head_content_length;
	//! Extra HEAD response headers, including repeated field lines
	vector<std::pair<string, string>> response_headers;
	//! Write empty response fields without optional whitespace after the colon
	bool exact_empty_response_headers = false;
	//! Emit one HTTP redirect before the successful HEAD response
	bool redirect_head = false;
	vector<std::pair<string, string>> redirect_response_headers;
};

struct MockS3CompletionFaultConfig {
	//! Number of leading multipart-completion responses to replace
	idx_t count = 0;
	int status = 200;
	string code = "InternalError";
	string message = "Injected multipart completion failure";
};

struct MockS3FailureConfig {
	//! Answer this many leading ListObjectsV2 requests with HTTP 503 SlowDown
	idx_t transient_503_lists = 0;
	//! Answer this many leading ListObjectsV2 requests with HTTP 400
	idx_t transient_400_lists = 0;
	//! Answer this many leading ListObjectsV2 requests with malformed HTTP 200 bodies
	idx_t malformed_success_lists = 0;
	MockS3MalformedListBehavior malformed_list_behavior = MockS3MalformedListBehavior::TRUNCATED_XML;
	//! Number of object PUTs to fail with a 400 before succeeding
	idx_t transient_put_failures = 0;
	//! Number of object GETs to fail with a 400 before succeeding
	idx_t transient_get_failures = 0;
	//! Number of object HEADs to fail with a 400 before succeeding
	idx_t transient_head_failures = 0;
	//! Number of object HEADs to answer with 404 before succeeding
	idx_t head_not_found_requests = 0;
	//! Number of object DELETEs to fail with a 400 before succeeding
	idx_t transient_delete_failures = 0;
	//! Number of multipart-init POSTs (uploads=) to fail before succeeding
	idx_t transient_post_failures = 0;
	//! HTTP status used for injected multipart-init failures
	int transient_post_status = 400;
	//! Leading multipart-completion response fault
	MockS3CompletionFaultConfig completion_fault;
	//! Whether injected 400s carry S3's retryable RequestTimeout code or a generic (non-retryable) code
	bool failure_is_request_timeout = true;
	//! Whether injected 400 bodies are truncated mid-XML (an open <Code> with no closing tag)
	bool truncated_failure_body = false;
};

struct MockS3ListConfig {
	//! Return a truncated first page before the final object page
	bool paginate = false;
};

struct MockS3BulkDeleteConfig {
	//! Reject DeleteObjects requests containing more than this many keys
	optional_idx maximum_key_count;
};

struct MockS3RangeConfig {
	MockS3RangeBehavior behavior = MockS3RangeBehavior::NORMAL;
	//! Number of leading range GETs affected by transient range behaviors
	idx_t behavior_requests = 0;
	//! Number of bytes to omit from an injected truncated range response
	idx_t truncated_bytes = 1;
	//! Advertise byte-range support on HEAD responses
	bool advertise = true;
	//! Hold the first range response body until a second range request arrives
	bool block_first_body_until_second = false;
	//! Hold this exact range response body until release_range has emitted its body
	string blocked;
	string release;
};

struct MockS3FullGetConfig {
	//! Send successful responses with chunked transfer encoding and no Content-Length
	bool chunked = false;
	//! Hold the response body until ReleaseFullGet is called
	bool block_until_released = false;
};

struct MockS3PutResponseConfig {
	int status = 200;
	MockS3ETagBehavior etag = MockS3ETagBehavior::VALUE;
};

struct MockS3HTTPResponseConfig {
	string object_put_body;
	string object_delete_body;
	string options_body;
};

struct MockS3UploadConfig {
	//! PUT response behavior
	MockS3PutResponseConfig object_put;
	MockS3PutResponseConfig multipart_part_put;

	//! Existing object preserved when an upload is abandoned
	string initial_published_object;
	//! Multipart upload ID returned by the mock server
	string upload_id = "refresh-test-upload-id";
	//! Hold these one-based part numbers until ReleasePartUploads is called
	vector<idx_t> blocked_part_numbers;
	//! Fail these one-based part numbers with a non-retryable HTTP 400
	vector<idx_t> failed_part_numbers;
	//! Hold multipart initialization until ReleaseMultipartInitialization is called
	bool block_initialization = false;
	MockS3MultipartInitializationBehavior initialization_behavior = MockS3MultipartInitializationBehavior::SUCCESS;
	MockS3MultipartCompletionBehavior completion_behavior = MockS3MultipartCompletionBehavior::SUCCESS;
	//! HTTP status sent before disconnecting a multipart-completion response body
	int completion_disconnect_status = 200;
	MockS3MultipartAbortBehavior abort_behavior = MockS3MultipartAbortBehavior::SUCCESS;
	MockS3MultipartGeometry geometry = MockS3MultipartGeometry::FLEXIBLE;
};

struct MockS3ServerConfig {
	//! Path prefix configured as part of the endpoint, without a trailing slash
	string endpoint_base_path;
	MockS3ObjectConfig object;
	MockS3AuthConfig auth;
	MockS3MetadataConfig metadata;
	MockS3FailureConfig failures;
	MockS3ListConfig list;
	MockS3BulkDeleteConfig bulk_delete;
	MockS3RangeConfig range;
	MockS3FullGetConfig full_get;
	MockS3UploadConfig upload;
	MockS3HTTPResponseConfig http_response;
};

struct MockS3RequestObservation {
	vector<std::pair<string, string>> headers;
	string method;
	string path;
	string target;
	string range;
	string if_match;
	string version_id;
	string authorization;
	string key_id;
	string region;
	string user_agent;
	string session_header;
	string upload_id;
	string server_side_encryption;
	string kms_key_id;
	string body_digest;
	optional_idx part_number;
	idx_t body_size = 0;
	idx_t delete_key_count = 0;
	idx_t user_agent_count = 0;
	idx_t session_header_count = 0;
	int status = 0;
	bool multipart_upload_published = false;
	//! Client's ephemeral source port; a new connection shows a new port
	int remote_port = 0;
};

class MockS3Server {
public:
	explicit MockS3Server(MockS3ServerConfig config);
	~MockS3Server();

	MockS3Server(const MockS3Server &) = delete;
	MockS3Server &operator=(const MockS3Server &) = delete;

public:
	string Endpoint() const;
	string HTTPPath() const;
	string S3Path() const;
	const string &ObjectData() const;
	string UploadedObject() const;
	string CompletionBody() const;
	vector<MockS3RequestObservation> Observations() const;
	idx_t MaximumConcurrentPartUploads() const;
	bool WaitForPartUpload(idx_t part_number);
	void ReleasePartUpload(idx_t part_number);
	void ReleasePartUploads();
	bool WaitForMultipartInitialization();
	void ReleaseMultipartInitialization();
	bool WaitForFullGet();
	void ReleaseFullGet();

private:
	struct Impl;
	unique_ptr<Impl> impl;
};

string MockS3RefreshTargetName(MockS3RefreshTarget target);

bool MockS3HasObservation(const vector<MockS3RequestObservation> &observations, const string &method,
                          const string &key_id, int status, const string &range = string(),
                          const string &target_contains = string());
vector<string> MockS3HeaderValues(const MockS3RequestObservation &observation, const string &name);
string MockS3DescribeObservations(const vector<MockS3RequestObservation> &observations);

} // namespace duckdb
