#pragma once

#include "duckdb/common/common.hpp"
#include "duckdb/common/optional_idx.hpp"

namespace duckdb {

enum class MockS3RefreshTarget : uint8_t {
	HEAD,
	HEAD_AND_RANGE_GET,
	FULL_GET,
	RANGE_GET,
	PUT,
	MULTIPART_INITIATE_POST,
	MULTIPART_COMPLETE_POST,
	BULK_DELETE_POST,
	DELETE_OBJECT,
	LIST_OBJECTS_GET
};

enum class MockS3AuthFailure : uint8_t { ACCESS_DENIED_403, EXPIRED_TOKEN_400 };

enum class MockS3RangeBehavior : uint8_t { NORMAL, IGNORE_RANGE, TRUNCATE_TRANSFER, SHORT_SUCCESS };

struct MockS3ServerConfig {
	string bucket = "refresh-bucket";
	string object_key = "object.bin";
	string object_data = "abcdefghijklmnopqrstuvwxyz0123456789";
	string stale_key_id = "STALE_KEY";
	string fresh_key_id = "FRESH_KEY";
	bool reject_fresh_credentials = false;
	string etag = "\"httpfs-refresh-test-etag\"";
	MockS3RefreshTarget refresh_target = MockS3RefreshTarget::HEAD;
	MockS3AuthFailure auth_failure = MockS3AuthFailure::ACCESS_DENIED_403;
	//! Answer this many leading ListObjectsV2 requests with HTTP 503 SlowDown
	idx_t transient_503_lists = 0;
	//! Answer this many leading ListObjectsV2 requests with HTTP 400
	idx_t transient_400_lists = 0;
	//! Number of object PUTs to fail with a 400 before succeeding
	idx_t transient_put_failures = 0;
	//! Number of object GETs to fail with a 400 before succeeding
	idx_t transient_get_failures = 0;
	//! Range response behavior to inject
	MockS3RangeBehavior range_behavior = MockS3RangeBehavior::NORMAL;
	//! Number of leading range GETs affected by transient range behaviors
	idx_t range_behavior_requests = 0;
	//! Number of bytes to omit from an injected truncated range response
	idx_t truncated_range_bytes = 1;
	//! Override the Content-Length reported by HEAD while keeping the GET body unchanged
	optional_idx head_content_length;
	//! Number of object HEADs to fail with a 400 before succeeding
	idx_t transient_head_failures = 0;
	//! Number of object DELETEs to fail with a 400 before succeeding
	idx_t transient_delete_failures = 0;
	//! Number of multipart-init POSTs (uploads=) to fail with a 400 before succeeding
	idx_t transient_post_failures = 0;
	//! Number of multipart-complete POSTs (uploadId=) to fail with a 400 before succeeding
	idx_t transient_complete_post_failures = 0;
	//! Number of multipart-complete POSTs (uploadId=) to answer with an HTTP 200 whose body carries an error before
	//! succeeding
	idx_t transient_complete_post_200_errors = 0;
	//! Whether injected 400s carry S3's retryable RequestTimeout code or a generic (non-retryable) code
	bool failure_is_request_timeout = true;
	//! Whether injected 400 bodies are truncated mid-XML (an open <Code> with no closing tag)
	bool truncated_failure_body = false;
	//! Whether injected 400s carry no response body
	bool bodyless_failure = false;
	//! Hold stale auth failures until this many matching requests are concurrently waiting
	idx_t auth_failure_barrier_count = 0;
};

struct MockS3RequestObservation {
	string method;
	string path;
	string target;
	string range;
	string key_id;
	int status = 0;
	//! Client's ephemeral source port; a new connection shows a new port
	int remote_port = 0;
};

class MockS3Server {
public:
	explicit MockS3Server(MockS3ServerConfig config);
	~MockS3Server();

	MockS3Server(const MockS3Server &) = delete;
	MockS3Server &operator=(const MockS3Server &) = delete;

	string Endpoint() const;
	string HTTPPath() const;
	string S3Path() const;
	const string &ObjectData() const;
	vector<MockS3RequestObservation> Observations() const;

private:
	struct Impl;
	unique_ptr<Impl> impl;
};

string MockS3RefreshTargetName(MockS3RefreshTarget target);

bool MockS3HasObservation(const vector<MockS3RequestObservation> &observations, const string &method,
                          const string &key_id, int status, const string &range = string(),
                          const string &target_contains = string());
string MockS3DescribeObservations(const vector<MockS3RequestObservation> &observations);

} // namespace duckdb
