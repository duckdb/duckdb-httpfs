#include "catch.hpp"

#include "s3/mock_s3_server.hpp"
#include "s3/s3_test_helper.hpp"

#include "s3/s3fs.hpp"

#include "duckdb.hpp"
#include "duckdb/common/file_system.hpp"
#include "duckdb/common/string_util.hpp"

namespace duckdb {

namespace {

static void RunTransientPutRetryScenario(const string &client_implementation) {
	MockS3ServerConfig config;
	config.object.bucket = S3TestHelper::BUCKET;
	config.object.key = S3TestHelper::OBJECT_KEY;
	config.auth.stale_key_id = S3TestHelper::STALE_KEY_ID;
	// Use a refresh target that writes never exercise, so credential refresh never triggers here.
	config.auth.refresh_target = MockS3RefreshTarget::DELETE_OBJECT;
	config.failures.transient_put_failures = 2;
	MockS3Server server(std::move(config));

	DuckDB db(nullptr);
	Connection con(db);
	S3TestHelper::ConfigureRefresh(db, con, server, client_implementation, false);

	S3TestHelper::RequireQueryOk(con, "SET http_retries=3");
	S3TestHelper::RequireQueryOk(con, "SET http_retry_wait_ms=1");
	S3TestHelper::RequireQueryOk(con, "BEGIN TRANSACTION");
	S3TestHelper::WriteMultipartPayload(con);
	S3TestHelper::RequireQueryOk(con, "COMMIT");

	auto observations = server.Observations();
	INFO(MockS3DescribeObservations(observations));
	// The transient RequestTimeout 400s were surfaced, retried, and the same part eventually succeeded.
	REQUIRE(MockS3HasObservation(observations, "PUT", S3TestHelper::STALE_KEY_ID, 400, string(), "partNumber"));
	REQUIRE(MockS3HasObservation(observations, "PUT", S3TestHelper::STALE_KEY_ID, 200, string(), "partNumber"));
	// The multipart upload completed successfully.
	REQUIRE(MockS3HasObservation(observations, "POST", S3TestHelper::STALE_KEY_ID, 200, string(), "uploadId"));
}

static idx_t CountObservationsTarget(const vector<MockS3RequestObservation> &observations, const string &method,
                                     int status, const string &target_contains) {
	idx_t result = 0;
	for (auto &observation : observations) {
		if (observation.method == method && observation.status == status &&
		    (target_contains.empty() || observation.target.find(target_contains) != string::npos)) {
			result++;
		}
	}
	return result;
}

template <class CALLBACK>
static string RequireError(CALLBACK callback, optional_ptr<ErrorData> error_data = nullptr) {
	try {
		callback();
	} catch (std::exception &ex) {
		if (error_data) {
			*error_data = ErrorData(ex);
		}
		return ex.what();
	}
	FAIL("Expected operation to throw");
	return string();
}

static unique_ptr<FileHandle> OpenWriter(Connection &con) {
	auto &fs = FileSystem::GetFileSystem(*con.context);
	return fs.OpenFile(S3TestHelper::S3_PATH, FileFlags::FILE_FLAGS_WRITE | FileFlags::FILE_FLAGS_FILE_CREATE_NEW);
}

static string MultipartPayload() {
	return string(10ULL * 1024ULL * 1024ULL + 1, 'x');
}

static string ConfigureUploadTest(DuckDB &db, Connection &con, MockS3Server &server,
                                  const string &client_implementation, idx_t retries) {
	auto test_id = S3TestHelper::ConfigureRefresh(db, con, server, client_implementation, false);
	S3TestHelper::RequireQueryOk(con, "SET s3_uploader_max_filesize='50GB'");
	S3TestHelper::RequireQueryOk(con, "SET http_retries=" + to_string(retries));
	S3TestHelper::RequireQueryOk(con, "SET http_retry_wait_ms=1");
	return test_id;
}

static void RunRecoveringCompletionFaultScenario(const string &client_implementation,
                                                 MockS3CompletionFaultConfig completion_fault, idx_t retries) {
	MockS3ServerConfig config;
	config.object.bucket = S3TestHelper::BUCKET;
	config.object.key = S3TestHelper::OBJECT_KEY;
	config.auth.refresh_target = MockS3RefreshTarget::DELETE_OBJECT;
	config.upload.initial_published_object = "existing object";
	auto expected_attempts = completion_fault.count + 1;
	auto expected_fault_status = completion_fault.status;
	config.failures.completion_fault = std::move(completion_fault);
	MockS3Server server(std::move(config));

	DuckDB db(nullptr);
	Connection con(db);
	ConfigureUploadTest(db, con, server, client_implementation, retries);
	S3TestHelper::RequireQueryOk(con, "BEGIN TRANSACTION");
	auto handle = OpenWriter(con);
	auto payload = MultipartPayload();
	handle->Write(QueryContext(*con.context), data_ptr_cast(payload.data()), payload.size());
	handle->Close();
	handle.reset();
	S3TestHelper::RequireQueryOk(con, "COMMIT");

	auto observations = server.Observations();
	INFO(MockS3DescribeObservations(observations));
	S3TestHelper::RequireCompletionIdentity(observations, expected_attempts);
	auto completions = S3TestHelper::CompletionObservations(observations);
	for (idx_t attempt = 0; attempt < completions.size() - 1; attempt++) {
		REQUIRE(completions[attempt].status == expected_fault_status);
		REQUIRE_FALSE(completions[attempt].multipart_upload_published);
	}
	REQUIRE(completions.back().status == 200);
	REQUIRE(completions.back().multipart_upload_published);
	REQUIRE(CountObservationsTarget(observations, "DELETE", 204, "uploadId") == 0);
	REQUIRE(server.UploadedObject() == payload);
}

static void RunFailedCompletionFaultScenario(const string &client_implementation,
                                             MockS3CompletionFaultConfig completion_fault, idx_t retries,
                                             idx_t expected_attempts) {
	MockS3ServerConfig config;
	config.object.bucket = S3TestHelper::BUCKET;
	config.object.key = S3TestHelper::OBJECT_KEY;
	config.auth.refresh_target = MockS3RefreshTarget::DELETE_OBJECT;
	config.upload.initial_published_object = "existing object";
	auto expected_status = completion_fault.status;
	auto expected_code = completion_fault.code;
	config.failures.completion_fault = std::move(completion_fault);
	MockS3Server server(std::move(config));

	DuckDB db(nullptr);
	Connection con(db);
	ConfigureUploadTest(db, con, server, client_implementation, retries);
	S3TestHelper::RequireQueryOk(con, "BEGIN TRANSACTION");
	auto handle = OpenWriter(con);
	auto payload = MultipartPayload();
	handle->Write(QueryContext(*con.context), data_ptr_cast(payload.data()), payload.size());
	ErrorData error;
	auto first_error = RequireError([&]() { handle->Sync(); }, error);
	auto second_error = RequireError([&]() { handle->Close(); });
	REQUIRE(second_error == first_error);
	handle.reset();
	S3TestHelper::RequireQueryOk(con, "ROLLBACK");

	auto observations = server.Observations();
	INFO(MockS3DescribeObservations(observations));
	S3TestHelper::RequireCompletionIdentity(observations, expected_attempts);
	for (const auto &completion : S3TestHelper::CompletionObservations(observations)) {
		REQUIRE(completion.status == expected_status);
		REQUIRE_FALSE(completion.multipart_upload_published);
	}
	REQUIRE(error.Type() == ExceptionType::HTTP);
	REQUIRE(error.ExtraInfo().at("status_code") == to_string(expected_status));
	REQUIRE(StringUtil::Contains(error.ExtraInfo().at("response_body"), expected_code));
	REQUIRE(CountObservationsTarget(observations, "DELETE", 204, "uploadId") == 1);
	REQUIRE(server.UploadedObject() == "existing object");
}

// A generic (non-RequestTimeout) 400 must fail on the first try. Uses a single-shot PUT so exactly one
// request is expected, distinguishing "not retried" from "retried N times and still failed".
static void RunGenericErrorNotRetriedScenario(const string &client_implementation) {
	MockS3ServerConfig config;
	config.object.bucket = S3TestHelper::BUCKET;
	config.object.key = S3TestHelper::OBJECT_KEY;
	config.auth.stale_key_id = S3TestHelper::STALE_KEY_ID;
	config.auth.refresh_target = MockS3RefreshTarget::DELETE_OBJECT;
	config.failures.transient_put_failures = 1000;
	config.failures.failure_is_request_timeout = false;
	MockS3Server server(std::move(config));

	DuckDB db(nullptr);
	Connection con(db);
	S3TestHelper::ConfigureRefresh(db, con, server, client_implementation, false);

	S3TestHelper::RequireQueryOk(con, "SET http_retries=3");
	S3TestHelper::RequireQueryOk(con, "SET http_retry_wait_ms=1");
	S3TestHelper::RequireQueryOk(con, "BEGIN TRANSACTION");
	REQUIRE_THROWS(S3TestHelper::WriteSinglePutPayload(con));
	S3TestHelper::RequireQueryOk(con, "ROLLBACK");

	auto observations = server.Observations();
	INFO(MockS3DescribeObservations(observations));
	REQUIRE(S3TestHelper::CountObservations(observations, "PUT", S3TestHelper::STALE_KEY_ID, 400) == 1);
}

// A truncated error body (an open <Code> with no closing tag) must degrade to a plain HTTP error:
// not classified as transient (no retry) and never escalated to a DB-invalidating InternalException.
static void RunTruncatedErrorBodyScenario(const string &client_implementation) {
	MockS3ServerConfig config;
	config.object.bucket = S3TestHelper::BUCKET;
	config.object.key = S3TestHelper::OBJECT_KEY;
	config.auth.stale_key_id = S3TestHelper::STALE_KEY_ID;
	config.auth.refresh_target = MockS3RefreshTarget::DELETE_OBJECT;
	config.failures.transient_put_failures = 1000;
	config.failures.truncated_failure_body = true;
	MockS3Server server(std::move(config));

	DuckDB db(nullptr);
	Connection con(db);
	S3TestHelper::ConfigureRefresh(db, con, server, client_implementation, false);

	S3TestHelper::RequireQueryOk(con, "SET http_retries=3");
	S3TestHelper::RequireQueryOk(con, "SET http_retry_wait_ms=1");
	S3TestHelper::RequireQueryOk(con, "BEGIN TRANSACTION");
	bool threw = false;
	bool threw_internal = false;
	try {
		S3TestHelper::WriteSinglePutPayload(con);
	} catch (std::exception &ex) {
		threw = true;
		ErrorData error(ex);
		threw_internal = error.Type() == ExceptionType::INTERNAL || error.Type() == ExceptionType::FATAL;
	}
	REQUIRE(threw);
	REQUIRE_FALSE(threw_internal);
	// The database must still be usable (an InternalException would have invalidated it).
	S3TestHelper::RequireQueryOk(con, "ROLLBACK");

	auto observations = server.Observations();
	INFO(MockS3DescribeObservations(observations));
	REQUIRE(S3TestHelper::CountObservations(observations, "PUT", S3TestHelper::STALE_KEY_ID, 400) == 1);
}

// Even a retryable RequestTimeout must NOT replay a multipart-init POST (it would orphan an upload id).
static void RunMultipartInitNotRetriedScenario(const string &client_implementation) {
	MockS3ServerConfig config;
	config.object.bucket = S3TestHelper::BUCKET;
	config.object.key = S3TestHelper::OBJECT_KEY;
	config.auth.stale_key_id = S3TestHelper::STALE_KEY_ID;
	config.auth.refresh_target = MockS3RefreshTarget::DELETE_OBJECT;
	config.failures.transient_post_failures = 1000;
	MockS3Server server(std::move(config));

	DuckDB db(nullptr);
	Connection con(db);
	S3TestHelper::ConfigureRefresh(db, con, server, client_implementation, false);

	S3TestHelper::RequireQueryOk(con, "SET http_retries=3");
	S3TestHelper::RequireQueryOk(con, "SET http_retry_wait_ms=1");
	S3TestHelper::RequireQueryOk(con, "BEGIN TRANSACTION");
	REQUIRE_THROWS(S3TestHelper::WriteMultipartPayload(con));
	S3TestHelper::RequireQueryOk(con, "ROLLBACK");

	auto observations = server.Observations();
	INFO(MockS3DescribeObservations(observations));
	REQUIRE(CountObservationsTarget(observations, "POST", 400, "uploads") == 1);
}

// A RequestTimeout retry must run on a fresh connection instead of the stalled one.
static void RunFreshConnectionRetryScenario(const string &client_implementation, bool connection_caching) {
	MockS3ServerConfig config;
	config.object.bucket = S3TestHelper::BUCKET;
	config.object.key = S3TestHelper::OBJECT_KEY;
	config.auth.stale_key_id = S3TestHelper::STALE_KEY_ID;
	config.auth.refresh_target = MockS3RefreshTarget::DELETE_OBJECT;
	config.failures.transient_put_failures = 1;
	MockS3Server server(std::move(config));

	DuckDB db(nullptr);
	Connection con(db);
	S3TestHelper::ConfigureRefresh(db, con, server, client_implementation, connection_caching);

	S3TestHelper::RequireQueryOk(con, "SET http_retries=3");
	S3TestHelper::RequireQueryOk(con, "SET http_retry_wait_ms=1");
	S3TestHelper::RequireQueryOk(con, "BEGIN TRANSACTION");
	S3TestHelper::WriteSinglePutPayload(con);
	S3TestHelper::RequireQueryOk(con, "COMMIT");

	auto observations = server.Observations();
	INFO(MockS3DescribeObservations(observations));
	int failed_port = 0;
	int success_port = 0;
	for (auto &observation : observations) {
		if (observation.method != "PUT") {
			continue;
		}
		if (observation.status == 400) {
			failed_port = observation.remote_port;
		} else if (observation.status == 200) {
			success_port = observation.remote_port;
		}
	}
	REQUIRE(failed_port != 0);
	REQUIRE(success_port != 0);
	REQUIRE(failed_port != success_port);
}

// A RequestTimeout that never clears exhausts exactly http_retries retries (one initial + http_retries).
static void RunRetryBudgetScenario(const string &client_implementation) {
	MockS3ServerConfig config;
	config.object.bucket = S3TestHelper::BUCKET;
	config.object.key = S3TestHelper::OBJECT_KEY;
	config.auth.stale_key_id = S3TestHelper::STALE_KEY_ID;
	config.auth.refresh_target = MockS3RefreshTarget::DELETE_OBJECT;
	config.failures.transient_put_failures = 1000;
	MockS3Server server(std::move(config));

	DuckDB db(nullptr);
	Connection con(db);
	S3TestHelper::ConfigureRefresh(db, con, server, client_implementation, false);

	S3TestHelper::RequireQueryOk(con, "SET http_retries=2");
	S3TestHelper::RequireQueryOk(con, "SET http_retry_wait_ms=1");
	S3TestHelper::RequireQueryOk(con, "BEGIN TRANSACTION");
	REQUIRE_THROWS(S3TestHelper::WriteSinglePutPayload(con));
	S3TestHelper::RequireQueryOk(con, "ROLLBACK");

	auto observations = server.Observations();
	INFO(MockS3DescribeObservations(observations));
	// One initial attempt plus http_retries (2) retries.
	REQUIRE(S3TestHelper::CountObservations(observations, "PUT", S3TestHelper::STALE_KEY_ID, 400) == 3);
}

static void RunTransientGetRetryScenario(const string &client_implementation) {
	MockS3ServerConfig config;
	config.object.bucket = S3TestHelper::BUCKET;
	config.object.key = S3TestHelper::OBJECT_KEY;
	config.auth.stale_key_id = S3TestHelper::STALE_KEY_ID;
	config.auth.refresh_target = MockS3RefreshTarget::DELETE_OBJECT;
	config.failures.transient_get_failures = 2;
	auto object_data = config.object.data;
	MockS3Server server(std::move(config));

	DuckDB db(nullptr);
	Connection con(db);
	S3TestHelper::ConfigureRefresh(db, con, server, client_implementation, false);

	S3TestHelper::RequireQueryOk(con, "SET http_retries=3");
	S3TestHelper::RequireQueryOk(con, "SET http_retry_wait_ms=1");
	S3TestHelper::RequireQueryOk(con, "SET force_download=true");
	S3TestHelper::RequireQueryOk(con, "BEGIN TRANSACTION");
	auto &fs = FileSystem::GetFileSystem(*con.context);
	auto handle = fs.OpenFile(S3TestHelper::S3_PATH, FileFlags::FILE_FLAGS_READ);
	string buffer(8, '\0');
	handle->Read(QueryContext(*con.context), &buffer[0], buffer.size(), 0);
	REQUIRE(buffer == object_data.substr(0, buffer.size()));
	S3TestHelper::RequireQueryOk(con, "COMMIT");

	auto observations = server.Observations();
	INFO(MockS3DescribeObservations(observations));
	// The read hit transient RequestTimeout 400s and was retried until it succeeded.
	REQUIRE(MockS3HasObservation(observations, "GET", S3TestHelper::STALE_KEY_ID, 400));
	REQUIRE(MockS3HasObservation(observations, "GET", S3TestHelper::STALE_KEY_ID, 200));
}

static void RunTransientDeleteRetryScenario(const string &client_implementation) {
	MockS3ServerConfig config;
	config.object.bucket = S3TestHelper::BUCKET;
	config.object.key = S3TestHelper::OBJECT_KEY;
	config.auth.stale_key_id = S3TestHelper::STALE_KEY_ID;
	// Use a refresh target that deletes never exercise, so credential refresh never triggers here.
	config.auth.refresh_target = MockS3RefreshTarget::PUT;
	config.failures.transient_delete_failures = 2;
	MockS3Server server(std::move(config));

	DuckDB db(nullptr);
	Connection con(db);
	S3TestHelper::ConfigureRefresh(db, con, server, client_implementation, false);

	S3TestHelper::RequireQueryOk(con, "SET http_retries=3");
	S3TestHelper::RequireQueryOk(con, "SET http_retry_wait_ms=1");
	S3TestHelper::RequireQueryOk(con, "BEGIN TRANSACTION");
	auto &fs = FileSystem::GetFileSystem(*con.context);
	fs.RemoveFile(S3TestHelper::S3_PATH);
	S3TestHelper::RequireQueryOk(con, "COMMIT");

	auto observations = server.Observations();
	INFO(MockS3DescribeObservations(observations));
	REQUIRE(S3TestHelper::CountObservations(observations, "DELETE", S3TestHelper::STALE_KEY_ID, 400) == 2);
	REQUIRE(S3TestHelper::CountObservations(observations, "DELETE", S3TestHelper::STALE_KEY_ID, 204) == 1);
}

// HEAD responses carry no body, so a RequestTimeout 400 cannot be classified as transient:
// the HEAD is not retried and the open recovers through httpfs's range-GET fallback instead.
static void RunHeadNotRetriedScenario(const string &client_implementation) {
	MockS3ServerConfig config;
	config.object.bucket = S3TestHelper::BUCKET;
	config.object.key = S3TestHelper::OBJECT_KEY;
	config.auth.stale_key_id = S3TestHelper::STALE_KEY_ID;
	config.auth.refresh_target = MockS3RefreshTarget::DELETE_OBJECT;
	config.failures.transient_head_failures = 1000;
	MockS3Server server(std::move(config));

	DuckDB db(nullptr);
	Connection con(db);
	S3TestHelper::ConfigureRefresh(db, con, server, client_implementation, false);

	S3TestHelper::RequireQueryOk(con, "SET http_retries=3");
	S3TestHelper::RequireQueryOk(con, "SET http_retry_wait_ms=1");
	S3TestHelper::RequireQueryOk(con, "BEGIN TRANSACTION");
	auto &fs = FileSystem::GetFileSystem(*con.context);
	auto handle = fs.OpenFile(S3TestHelper::S3_PATH, FileFlags::FILE_FLAGS_READ | FileFlags::FILE_FLAGS_DIRECT_IO);
	REQUIRE(handle);
	S3TestHelper::RequireQueryOk(con, "COMMIT");

	auto observations = server.Observations();
	INFO(MockS3DescribeObservations(observations));
	REQUIRE(S3TestHelper::CountObservations(observations, "HEAD", S3TestHelper::STALE_KEY_ID, 400) == 1);
	REQUIRE(MockS3HasObservation(observations, "GET", S3TestHelper::STALE_KEY_ID, 206, "bytes=0-1"));
}

// A received RequestTimeout response permits multipart completion to use its explicit S3 retry budget.
static void RunMultipartCompleteRequestTimeoutRetryScenario(const string &client_implementation) {
	RunFailedCompletionFaultScenario(client_implementation,
	                                 {1000, 400, "RequestTimeout", "Injected completion timeout"}, 3, 4);
}

static void RunCompletionErrorCodeRecoveryScenarios(const string &client_implementation) {
	for (const auto &code :
	     {"InternalError", "OperationAborted", "SlowDown", "ServiceUnavailable", "TooManyRequests", "RequestTimeout"}) {
		INFO("S3 error code: " << code);
		RunRecoveringCompletionFaultScenario(client_implementation,
		                                     {2, 200, code, "Injected retryable multipart completion error"}, 3);
	}
}

static void RunCompletionStatusRecoveryScenarios(const string &client_implementation) {
	for (const auto status : {429, 500, 502, 503}) {
		INFO("HTTP status: " << status);
		RunRecoveringCompletionFaultScenario(
		    client_implementation, {1, status, "PermanentError", "Injected status-classified completion error"}, 1);
	}
}

static void RunPermanentCompletionFailureScenarios(const string &client_implementation) {
	RunFailedCompletionFaultScenario(client_implementation,
	                                 {1000, 400, "InvalidRequest", "Injected permanent completion error"}, 3, 1);
	RunFailedCompletionFaultScenario(client_implementation,
	                                 {1000, 200, "internalerror", "Retry codes are case-sensitive"}, 3, 1);
}

static void RunCompletionWithoutRetriesScenario(const string &client_implementation) {
	RunFailedCompletionFaultScenario(client_implementation, {1000, 503, "SlowDown", "No completion retries configured"},
	                                 0, 1);
}

static void RunMultipartInitializationThrottleScenario(const string &client_implementation) {
	MockS3ServerConfig config;
	config.object.bucket = S3TestHelper::BUCKET;
	config.object.key = S3TestHelper::OBJECT_KEY;
	config.auth.refresh_target = MockS3RefreshTarget::DELETE_OBJECT;
	config.failures.transient_post_failures = 1000;
	config.failures.transient_post_status = 429;
	MockS3Server server(std::move(config));

	DuckDB db(nullptr);
	Connection con(db);
	ConfigureUploadTest(db, con, server, client_implementation, 3);
	S3TestHelper::RequireQueryOk(con, "BEGIN TRANSACTION");
	auto handle = OpenWriter(con);
	auto payload = MultipartPayload();
	auto first_error = RequireError(
	    [&]() { handle->Write(QueryContext(*con.context), data_ptr_cast(payload.data()), payload.size()); });
	auto second_error = RequireError([&]() { handle->Close(); });
	REQUIRE(second_error == first_error);
	handle.reset();
	S3TestHelper::RequireQueryOk(con, "ROLLBACK");

	auto observations = server.Observations();
	INFO(MockS3DescribeObservations(observations));
	REQUIRE(CountObservationsTarget(observations, "POST", 429, "uploads") == 1);
	REQUIRE(CountObservationsTarget(observations, "POST", 200, "uploadId") == 0);
	REQUIRE(CountObservationsTarget(observations, "DELETE", 204, "uploadId") == 0);
}

static void RunCompletionRefreshThenRetryScenario(const string &client_implementation) {
	MockS3ServerConfig config;
	config.object.bucket = S3TestHelper::BUCKET;
	config.object.key = S3TestHelper::OBJECT_KEY;
	config.auth.refresh_target = MockS3RefreshTarget::MULTIPART_COMPLETE_POST;
	config.upload.initial_published_object = "existing object";
	config.failures.completion_fault = {1, 503, "SlowDown", "Retry after refreshing credentials"};
	MockS3Server server(std::move(config));

	DuckDB db(nullptr);
	Connection con(db);
	auto test_id = ConfigureUploadTest(db, con, server, client_implementation, 1);
	S3TestHelper::RequireQueryOk(con, "BEGIN TRANSACTION");
	auto handle = OpenWriter(con);
	auto payload = MultipartPayload();
	handle->Write(QueryContext(*con.context), data_ptr_cast(payload.data()), payload.size());
	handle->Close();
	handle.reset();
	S3TestHelper::RequireQueryOk(con, "COMMIT");

	S3TestHelper::AssertSingleRefresh(test_id);
	auto observations = server.Observations();
	INFO(MockS3DescribeObservations(observations));
	S3TestHelper::RequireCompletionIdentity(observations, 3);
	auto completions = S3TestHelper::CompletionObservations(observations);
	REQUIRE(completions[0].status == 403);
	REQUIRE(completions[0].key_id == S3TestHelper::STALE_KEY_ID);
	REQUIRE_FALSE(completions[0].multipart_upload_published);
	REQUIRE(completions[1].status == 503);
	REQUIRE(completions[1].key_id == S3TestHelper::FRESH_KEY_ID);
	REQUIRE_FALSE(completions[1].multipart_upload_published);
	REQUIRE(completions[2].status == 200);
	REQUIRE(completions[2].key_id == S3TestHelper::FRESH_KEY_ID);
	REQUIRE(completions[2].multipart_upload_published);
	REQUIRE(CountObservationsTarget(observations, "DELETE", 204, "uploadId") == 0);
	REQUIRE(server.UploadedObject() == payload);
}

static void RunAllTransientRetryScenarios(const string &client_implementation) {
	SECTION("multipart part upload retries and completes") {
		RunTransientPutRetryScenario(client_implementation);
	}
	SECTION("object read retries and completes") {
		RunTransientGetRetryScenario(client_implementation);
	}
	SECTION("object delete retries and completes") {
		RunTransientDeleteRetryScenario(client_implementation);
	}
	SECTION("a generic 400 is not retried") {
		RunGenericErrorNotRetriedScenario(client_implementation);
	}
	SECTION("a truncated error body is not retried and does not invalidate the database") {
		RunTruncatedErrorBodyScenario(client_implementation);
	}
	SECTION("multipart initialization does not retry a received RequestTimeout") {
		RunMultipartInitNotRetriedScenario(client_implementation);
	}
	SECTION("multipart initialization does not receive core throttle retries") {
		RunMultipartInitializationThrottleScenario(client_implementation);
	}
	SECTION("multipart completion retries a received RequestTimeout within the configured budget") {
		RunMultipartCompleteRequestTimeoutRetryScenario(client_implementation);
	}
	SECTION("multipart completion retries every configured S3 error code") {
		RunCompletionErrorCodeRecoveryScenarios(client_implementation);
	}
	SECTION("multipart completion retries HTTP throttle and server-error statuses") {
		RunCompletionStatusRecoveryScenarios(client_implementation);
	}
	SECTION("multipart completion does not retry permanent errors") {
		RunPermanentCompletionFailureScenarios(client_implementation);
	}
	SECTION("multipart completion honors http_retries=0") {
		RunCompletionWithoutRetriesScenario(client_implementation);
	}
	SECTION("credential refresh preserves the multipart completion retry budget") {
		RunCompletionRefreshThenRetryScenario(client_implementation);
	}
	SECTION("a HEAD 400 is not retried because HEAD responses carry no error body") {
		RunHeadNotRetriedScenario(client_implementation);
	}
	SECTION("retries are bounded by http_retries") {
		RunRetryBudgetScenario(client_implementation);
	}
}

static void ConfigureListRetryTest(DuckDB &db, Connection &con, MockS3Server &server,
                                   const string &client_implementation, idx_t retries,
                                   bool connection_caching = false) {
	S3TestHelper::LoadExtension(db);

	S3TestHelper::RequireQueryOk(con,
	                             StringUtil::Format("SET httpfs_client_implementation='%s'", client_implementation));
	S3TestHelper::RequireQueryOk(
	    con, StringUtil::Format("SET httpfs_connection_caching=%s", connection_caching ? "true" : "false"));
	S3TestHelper::RequireQueryOk(con, "SET http_retries=" + to_string(retries));
	S3TestHelper::RequireQueryOk(con, "SET http_retry_wait_ms=1");
	S3TestHelper::RequireQueryOk(con, "SET http_retry_backoff=2");
	S3TestHelper::RequireQueryOk(con, StringUtil::Format(R"(
CREATE SECRET list_retry_s3 (
	TYPE S3,
	PROVIDER CONFIG,
	SCOPE 's3://refresh-bucket/',
	KEY_ID 'FRESH_KEY',
	SECRET 'S3TestHelper::FRESH_SECRET',
	REGION 'us-east-1',
	ENDPOINT '%s',
	USE_SSL false,
	URL_STYLE 'path'
))",
	                                                     server.Endpoint()));
}

static idx_t CountListObservations(const vector<MockS3RequestObservation> &observations, int status) {
	idx_t result = 0;
	for (auto &observation : observations) {
		if (observation.method == "GET" && observation.target.find("list-type=2") != string::npos &&
		    observation.status == status) {
			result++;
		}
	}
	return result;
}

static vector<MockS3RequestObservation> GetListObservations(const vector<MockS3RequestObservation> &observations) {
	vector<MockS3RequestObservation> result;
	for (auto &observation : observations) {
		if (observation.method == "GET" && observation.target.find("list-type=2") != string::npos) {
			result.push_back(observation);
		}
	}
	return result;
}

static void RequireIdenticalFreshListAttempts(const vector<MockS3RequestObservation> &observations,
                                              idx_t expected_attempts) {
	auto lists = GetListObservations(observations);
	REQUIRE(lists.size() == expected_attempts);
	for (idx_t i = 0; i < lists.size(); i++) {
		REQUIRE(lists[i].target == lists[0].target);
		REQUIRE(lists[i].remote_port != 0);
		if (i > 0) {
			REQUIRE(lists[i].remote_port != lists[i - 1].remote_port);
		}
	}
}

static void RunMalformedListRecoveryTest(const string &client_implementation, bool connection_caching) {
	MockS3ServerConfig config;
	config.failures.malformed_success_lists = 2;
	MockS3Server server(std::move(config));

	DuckDB db(nullptr);
	Connection con(db);
	ConfigureListRetryTest(db, con, server, client_implementation, 2, connection_caching);

	auto result = con.Query("SELECT file FROM glob('s3://refresh-bucket/*.bin') ORDER BY file");
	REQUIRE(result);
	auto observations = server.Observations();
	INFO((result->HasError() ? result->GetError() : string()));
	INFO(MockS3DescribeObservations(observations));
	REQUIRE_FALSE(result->HasError());
	REQUIRE(result->RowCount() == 1);
	REQUIRE(result->GetValue(0, 0).ToString() == "s3://refresh-bucket/object.bin");
	RequireIdenticalFreshListAttempts(observations, 3);
}

static void RunNamespaceMismatchListRecoveryTest(const string &client_implementation) {
	MockS3ServerConfig config;
	config.failures.malformed_success_lists = 1;
	config.failures.malformed_list_behavior = MockS3MalformedListBehavior::FOREIGN_NAMESPACE_KEY;
	MockS3Server server(std::move(config));

	DuckDB db(nullptr);
	Connection con(db);
	ConfigureListRetryTest(db, con, server, client_implementation, 1);

	auto result = con.Query("SELECT file FROM glob('s3://refresh-bucket/*.bin') ORDER BY file");
	REQUIRE(result);
	auto observations = server.Observations();
	INFO((result->HasError() ? result->GetError() : string()));
	INFO(MockS3DescribeObservations(observations));
	REQUIRE_FALSE(result->HasError());
	REQUIRE(result->RowCount() == 1);
	REQUIRE(result->GetValue(0, 0).ToString() == "s3://refresh-bucket/object.bin");
	RequireIdenticalFreshListAttempts(observations, 2);
}

static void RunMalformedPaginatedListRecoveryTest() {
	MockS3ServerConfig config;
	config.failures.malformed_success_lists = 2;
	config.list.paginate = true;
	MockS3Server server(std::move(config));

	DuckDB db(nullptr);
	Connection con(db);
	ConfigureListRetryTest(db, con, server, "httplib", 2);

	auto result = con.Query("SELECT file FROM glob('s3://refresh-bucket/*.bin') ORDER BY file");
	REQUIRE(result);
	auto observations = server.Observations();
	INFO((result->HasError() ? result->GetError() : string()));
	INFO(MockS3DescribeObservations(observations));
	REQUIRE_FALSE(result->HasError());
	REQUIRE(result->RowCount() == 2);
	REQUIRE(result->GetValue(0, 0).ToString() == "s3://refresh-bucket/first-page.bin");
	REQUIRE(result->GetValue(0, 1).ToString() == "s3://refresh-bucket/object.bin");

	auto lists = GetListObservations(observations);
	REQUIRE(lists.size() == 4);
	REQUIRE(lists[0].target.find("continuation-token=") == string::npos);
	vector<MockS3RequestObservation> second_page_attempts(lists.begin() + 1, lists.end());
	REQUIRE(second_page_attempts[0].target.find("continuation-token=") != string::npos);
	RequireIdenticalFreshListAttempts(second_page_attempts, 3);
}

static void RunMalformedListExhaustionTest(const string &client_implementation) {
	MockS3ServerConfig config;
	config.failures.malformed_success_lists = 1000;
	MockS3Server server(std::move(config));

	DuckDB db(nullptr);
	Connection con(db);
	ConfigureListRetryTest(db, con, server, client_implementation, 2);

	auto result = con.Query("SELECT file FROM glob('s3://refresh-bucket/*.bin')");
	REQUIRE(result);
	REQUIRE(result->HasError());
	REQUIRE(StringUtil::Contains(result->GetError(), "Malformed S3 list response"));

	auto observations = server.Observations();
	INFO(MockS3DescribeObservations(observations));
	RequireIdenticalFreshListAttempts(observations, 3);
}

static void RunMalformedListWithoutRetriesTest(const string &client_implementation) {
	MockS3ServerConfig config;
	config.failures.malformed_success_lists = 1;
	MockS3Server server(std::move(config));

	DuckDB db(nullptr);
	Connection con(db);
	ConfigureListRetryTest(db, con, server, client_implementation, 0);

	auto result = con.Query("SELECT file FROM glob('s3://refresh-bucket/*.bin')");
	REQUIRE(result);
	REQUIRE(result->HasError());
	REQUIRE(StringUtil::Contains(result->GetError(), "Malformed S3 list response"));

	auto observations = server.Observations();
	INFO(MockS3DescribeObservations(observations));
	REQUIRE(GetListObservations(observations).size() == 1);
}

static void RunMixedListRetryBudgetTest(const string &client_implementation) {
	MockS3ServerConfig config;
	config.failures.transient_400_lists = 1;
	config.failures.malformed_success_lists = 1;
	MockS3Server server(std::move(config));

	DuckDB db(nullptr);
	Connection con(db);
	ConfigureListRetryTest(db, con, server, client_implementation, 1);

	auto result = con.Query("SELECT file FROM glob('s3://refresh-bucket/*.bin')");
	REQUIRE(result);
	REQUIRE(result->HasError());
	REQUIRE(StringUtil::Contains(result->GetError(), "Malformed S3 list response"));

	auto observations = server.Observations();
	INFO(MockS3DescribeObservations(observations));
	auto lists = GetListObservations(observations);
	REQUIRE(lists.size() == 2);
	REQUIRE(lists[0].status == 400);
	REQUIRE(lists[1].status == 200);
	REQUIRE(lists[0].target == lists[1].target);
}

static void RunRecoveringListRetryTest(const string &client_implementation, int status) {
	MockS3ServerConfig config;
	if (status == 503) {
		config.failures.transient_503_lists = 1;
	} else {
		D_ASSERT(status == 400);
		config.failures.transient_400_lists = 1;
	}
	MockS3Server server(std::move(config));

	DuckDB db(nullptr);
	Connection con(db);
	ConfigureListRetryTest(db, con, server, client_implementation, 2);

	auto result = con.Query("SELECT file FROM glob('s3://refresh-bucket/*.bin') ORDER BY file");
	REQUIRE(result);
	auto observations = server.Observations();
	INFO((result->HasError() ? result->GetError() : string()));
	INFO(MockS3DescribeObservations(observations));
	REQUIRE_FALSE(result->HasError());
	REQUIRE(result->RowCount() == 1);
	REQUIRE(result->GetValue(0, 0).ToString() == "s3://refresh-bucket/object.bin");

	REQUIRE(CountListObservations(observations, status) == 1);
	REQUIRE(CountListObservations(observations, 200) >= 1);
}

static void RunExhaustedListRetryTest(const string &client_implementation, int status) {
	MockS3ServerConfig config;
	if (status == 503) {
		config.failures.transient_503_lists = 1000;
	} else {
		D_ASSERT(status == 400);
		config.failures.transient_400_lists = 1000;
	}
	MockS3Server server(std::move(config));

	DuckDB db(nullptr);
	Connection con(db);
	ConfigureListRetryTest(db, con, server, client_implementation, 2);

	auto result = con.Query("SELECT file FROM glob('s3://refresh-bucket/*.bin')");
	REQUIRE(result);
	REQUIRE(result->HasError());
	REQUIRE(StringUtil::Contains(result->GetError(), to_string(status)));

	auto observations = server.Observations();
	INFO(MockS3DescribeObservations(observations));
	// Core grants five extra retries to 503 throttling responses.
	const idx_t expected_attempts = status == 503 ? 8 : 3;
	REQUIRE(CountListObservations(observations, status) == expected_attempts);
	REQUIRE(CountListObservations(observations, 200) == 0);
}

static void RunGeneric400ListTest(const string &client_implementation) {
	MockS3ServerConfig config;
	config.failures.transient_400_lists = 1000;
	config.failures.failure_is_request_timeout = false;
	MockS3Server server(std::move(config));

	DuckDB db(nullptr);
	Connection con(db);
	ConfigureListRetryTest(db, con, server, client_implementation, 2);

	auto result = con.Query("SELECT file FROM glob('s3://refresh-bucket/*.bin')");
	REQUIRE(result);
	REQUIRE(result->HasError());
	REQUIRE(StringUtil::Contains(result->GetError(), "InvalidRequest"));

	auto observations = server.Observations();
	INFO(MockS3DescribeObservations(observations));
	REQUIRE(CountListObservations(observations, 400) == 1);
	REQUIRE(CountListObservations(observations, 200) == 0);
}

} // namespace

TEST_CASE("HTTPFS retries transient S3 RequestTimeout across request types", "[httpfs][s3][upload]") {
	SECTION("httplib") {
		RunAllTransientRetryScenarios("httplib");
	}
	SECTION("curl") {
		RunAllTransientRetryScenarios("curl");
	}
	SECTION("httplib retries RequestTimeout on a fresh connection") {
		RunFreshConnectionRetryScenario("httplib", false);
	}
	SECTION("session-local curl retries RequestTimeout on a fresh connection") {
		RunFreshConnectionRetryScenario("curl", false);
	}
	SECTION("shared curl retries RequestTimeout on a fresh connection") {
		RunFreshConnectionRetryScenario("curl", true);
	}
}

TEST_CASE("S3 glob recovers from transient ListObjectsV2 errors", "[httpfs][s3][retry]") {
	SECTION("httplib retries 503") {
		RunRecoveringListRetryTest("httplib", 503);
	}
	SECTION("curl retries 503") {
		RunRecoveringListRetryTest("curl", 503);
	}
	SECTION("httplib retries 400 RequestTimeout") {
		RunRecoveringListRetryTest("httplib", 400);
	}
	SECTION("curl retries 400 RequestTimeout") {
		RunRecoveringListRetryTest("curl", 400);
	}
}

TEST_CASE("S3 glob exhausts retries for persistent transient ListObjectsV2 errors", "[httpfs][s3][retry]") {
	SECTION("httplib exhausts 503 retries") {
		RunExhaustedListRetryTest("httplib", 503);
	}
	SECTION("curl exhausts 503 retries") {
		RunExhaustedListRetryTest("curl", 503);
	}
	SECTION("httplib exhausts 400 RequestTimeout retries") {
		RunExhaustedListRetryTest("httplib", 400);
	}
	SECTION("curl exhausts 400 RequestTimeout retries") {
		RunExhaustedListRetryTest("curl", 400);
	}
}

TEST_CASE("S3 glob does not retry a generic ListObjectsV2 400", "[httpfs][s3][retry]") {
	SECTION("httplib") {
		RunGeneric400ListTest("httplib");
	}
	SECTION("curl") {
		RunGeneric400ListTest("curl");
	}
}

TEST_CASE("S3 glob retries malformed successful ListObjectsV2 responses", "[httpfs][s3][retry]") {
	SECTION("httplib uses fresh session-local connections") {
		RunMalformedListRecoveryTest("httplib", false);
	}
	SECTION("curl uses fresh session-local connections") {
		RunMalformedListRecoveryTest("curl", false);
	}
	SECTION("curl clears shared cached connections") {
		RunMalformedListRecoveryTest("curl", true);
	}
	SECTION("replays the exact paginated request") {
		RunMalformedPaginatedListRecoveryTest();
	}
	SECTION("httplib rejects required fields from a foreign namespace") {
		RunNamespaceMismatchListRecoveryTest("httplib");
	}
	SECTION("curl rejects required fields from a foreign namespace") {
		RunNamespaceMismatchListRecoveryTest("curl");
	}
}

TEST_CASE("S3 glob exhausts malformed successful ListObjectsV2 retries", "[httpfs][s3][retry]") {
	SECTION("httplib") {
		RunMalformedListExhaustionTest("httplib");
	}
	SECTION("curl") {
		RunMalformedListExhaustionTest("curl");
	}
}

TEST_CASE("S3 glob honors zero retries for malformed successful ListObjectsV2 responses", "[httpfs][s3][retry]") {
	SECTION("httplib") {
		RunMalformedListWithoutRetriesTest("httplib");
	}
	SECTION("curl") {
		RunMalformedListWithoutRetriesTest("curl");
	}
}

TEST_CASE("S3 ListObjectsV2 response failures share one retry budget", "[httpfs][s3][retry]") {
	SECTION("httplib") {
		RunMixedListRetryBudgetTest("httplib");
	}
	SECTION("curl") {
		RunMixedListRetryBudgetTest("curl");
	}
}

} // namespace duckdb
