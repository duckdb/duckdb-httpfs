#include "catch.hpp"

#include "s3/mock_s3_server.hpp"
#include "s3/s3_test_helper.hpp"

#include "duckdb.hpp"
#include "duckdb/common/file_system.hpp"
#include "duckdb/common/string_util.hpp"

#include <atomic>
#include <thread>

namespace duckdb {

namespace {

struct S3UploadLifecycleTest {
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
		return string(12ULL * 1024ULL * 1024ULL + 1, 'x');
	}

	static void Configure(DuckDB &db, Connection &con, MockS3Server &server, const string &client_implementation,
	                      idx_t retries = 0) {
		S3TestHelper::ConfigureRefresh(db, con, server, client_implementation, false);
		S3TestHelper::RequireQueryOk(con, "SET s3_uploader_max_filesize='50GB'");
		S3TestHelper::RequireQueryOk(con, "SET http_retries=" + to_string(retries));
		S3TestHelper::RequireQueryOk(con, "SET http_retry_wait_ms=1");
	}

	static idx_t Count(const vector<MockS3RequestObservation> &observations, const string &method,
	                   const string &target_contains = string(), optional_idx status = optional_idx()) {
		idx_t result = 0;
		for (const auto &observation : observations) {
			if (observation.method == method &&
			    (target_contains.empty() || StringUtil::Contains(observation.target, target_contains)) &&
			    (!status.IsValid() || observation.status == NumericCast<int>(status.GetIndex()))) {
				result++;
			}
		}
		return result;
	}

	static void RequireStableError(FileHandle &handle, const string &first_error) {
		auto second_error = RequireError([&]() { handle.Close(); });
		REQUIRE(second_error == first_error);
	}

	static void RunAbortFailure(const string &client_implementation) {
		MockS3ServerConfig config;
		config.object.bucket = S3TestHelper::BUCKET;
		config.object.key = S3TestHelper::OBJECT_KEY;
		config.auth.refresh_target = MockS3RefreshTarget::HEAD;
		config.failures.transient_put_failures = 1000;
		config.failures.failure_is_request_timeout = false;
		config.upload.abort_behavior = MockS3MultipartAbortBehavior::ERROR;
		auto upload_id = config.upload.upload_id;
		MockS3Server server(std::move(config));

		DuckDB db(nullptr);
		Connection con(db);
		Configure(db, con, server, client_implementation);
		S3TestHelper::RequireQueryOk(con, "BEGIN TRANSACTION");
		auto handle = OpenWriter(con);
		auto payload = MultipartPayload();
		ErrorData primary_error;
		auto first_error = RequireError(
		    [&]() { handle->Write(QueryContext(*con.context), data_ptr_cast(payload.data()), payload.size()); },
		    primary_error);
		RequireStableError(*handle, first_error);
		auto abort_error = RequireError([&]() { handle->AbortWrite(); });
		REQUIRE(abort_error == first_error);
		handle->AbortWrite();
		REQUIRE(StringUtil::Contains(first_error, "Additionally"));
		REQUIRE(StringUtil::Contains(first_error, "Failed to abort S3 multipart upload"));
		REQUIRE_FALSE(StringUtil::Contains(first_error, upload_id));
		REQUIRE_FALSE(StringUtil::Contains(first_error, "?uploadId"));
		REQUIRE(primary_error.Type() == ExceptionType::HTTP);
		REQUIRE(primary_error.ExtraInfo().at("status_code") == "400");
		REQUIRE(StringUtil::Contains(primary_error.ExtraInfo().at("response_body"), "<Error>"));
		handle.reset();
		S3TestHelper::RequireQueryOk(con, "ROLLBACK");

		auto observations = server.Observations();
		INFO(MockS3DescribeObservations(observations));
		REQUIRE(Count(observations, "POST", "uploads") == 1);
		REQUIRE(Count(observations, "PUT", "partNumber") == 1);
		REQUIRE(Count(observations, "DELETE", "uploadId", optional_idx(400)) == 1);
	}

	static void RunEmbeddedCompletionError(const string &client_implementation) {
		MockS3ServerConfig config;
		config.object.bucket = S3TestHelper::BUCKET;
		config.object.key = S3TestHelper::OBJECT_KEY;
		config.auth.refresh_target = MockS3RefreshTarget::HEAD;
		config.upload.completion_behavior = MockS3MultipartCompletionBehavior::EMBEDDED_ERROR;
		MockS3Server server(std::move(config));

		DuckDB db(nullptr);
		Connection con(db);
		Configure(db, con, server, client_implementation);
		S3TestHelper::RequireQueryOk(con, "BEGIN TRANSACTION");
		auto handle = OpenWriter(con);
		auto payload = MultipartPayload();
		handle->Write(QueryContext(*con.context), data_ptr_cast(payload.data()), payload.size());
		auto first_error = RequireError([&]() { handle->Sync(); });
		RequireStableError(*handle, first_error);
		REQUIRE(StringUtil::Contains(first_error, "InternalError"));
		handle.reset();
		S3TestHelper::RequireQueryOk(con, "ROLLBACK");

		auto observations = server.Observations();
		INFO(MockS3DescribeObservations(observations));
		REQUIRE(Count(observations, "POST", "uploadId", optional_idx(200)) == 1);
		REQUIRE(Count(observations, "DELETE", "uploadId", optional_idx(204)) == 1);
	}

	static void RunAmbiguousCompletion(const string &client_implementation, MockS3MultipartCompletionBehavior behavior,
	                                   const string &error_fragment, bool leading_retryable_response = false) {
		MockS3ServerConfig config;
		config.object.bucket = S3TestHelper::BUCKET;
		config.object.key = S3TestHelper::OBJECT_KEY;
		config.auth.refresh_target = MockS3RefreshTarget::HEAD;
		config.upload.completion_behavior = behavior;
		if (behavior == MockS3MultipartCompletionBehavior::COMMIT_THEN_DISCONNECT) {
			config.upload.completion_disconnect_status = 503;
		}
		if (leading_retryable_response) {
			config.failures.completion_fault = {1, 503, "SlowDown", "Retry before an ambiguous completion"};
		}
		auto upload_id = config.upload.upload_id;
		MockS3Server server(std::move(config));

		DuckDB db(nullptr);
		Connection con(db);
		Configure(db, con, server, client_implementation, 3);
		S3TestHelper::RequireQueryOk(con, "BEGIN TRANSACTION");
		auto handle = OpenWriter(con);
		auto payload = MultipartPayload();
		handle->Write(QueryContext(*con.context), data_ptr_cast(payload.data()), payload.size());
		auto first_error = RequireError([&]() { handle->Sync(); });
		RequireStableError(*handle, first_error);
		auto abort_error = RequireError([&]() { handle->AbortWrite(); });
		REQUIRE(abort_error == first_error);
		handle->AbortWrite();
		REQUIRE(StringUtil::Contains(first_error, error_fragment));
		REQUIRE_FALSE(StringUtil::Contains(first_error, upload_id));
		handle.reset();
		S3TestHelper::RequireQueryOk(con, "ROLLBACK");

		auto observations = server.Observations();
		INFO(MockS3DescribeObservations(observations));
		auto expected_attempts = leading_retryable_response ? 2 : 1;
		S3TestHelper::RequireCompletionIdentity(observations, expected_attempts);
		auto completions = S3TestHelper::CompletionObservations(observations);
		for (idx_t attempt = 0; attempt < completions.size() - 1; attempt++) {
			REQUIRE_FALSE(completions[attempt].multipart_upload_published);
		}
		REQUIRE(completions.back().multipart_upload_published);
		if (leading_retryable_response) {
			REQUIRE(completions[0].status == 503);
			REQUIRE(completions[1].status == 503);
		}
		REQUIRE(Count(observations, "DELETE") == 0);
		REQUIRE(server.UploadedObject() == payload);
	}

	static void RunAmbiguousInitialization(const string &client_implementation,
	                                       MockS3MultipartInitializationBehavior behavior,
	                                       const string &error_fragment) {
		MockS3ServerConfig config;
		config.object.bucket = S3TestHelper::BUCKET;
		config.object.key = S3TestHelper::OBJECT_KEY;
		config.auth.refresh_target = MockS3RefreshTarget::HEAD;
		config.upload.initialization_behavior = behavior;
		MockS3Server server(std::move(config));

		DuckDB db(nullptr);
		Connection con(db);
		Configure(db, con, server, client_implementation, 3);
		S3TestHelper::RequireQueryOk(con, "BEGIN TRANSACTION");
		auto handle = OpenWriter(con);
		auto payload = MultipartPayload();
		auto first_error = RequireError(
		    [&]() { handle->Write(QueryContext(*con.context), data_ptr_cast(payload.data()), payload.size()); });
		RequireStableError(*handle, first_error);
		REQUIRE(StringUtil::Contains(first_error, error_fragment));
		handle.reset();
		S3TestHelper::RequireQueryOk(con, "ROLLBACK");

		auto observations = server.Observations();
		INFO(MockS3DescribeObservations(observations));
		REQUIRE(Count(observations, "POST", "uploads") == 1);
		REQUIRE(Count(observations, "PUT") == 0);
		REQUIRE(Count(observations, "DELETE") == 0);
	}

	static void RunSmallKMSPut(const string &client_implementation) {
		MockS3ServerConfig config;
		config.object.bucket = S3TestHelper::BUCKET;
		config.object.key = S3TestHelper::OBJECT_KEY;
		config.auth.refresh_target = MockS3RefreshTarget::HEAD;
		MockS3Server server(std::move(config));

		DuckDB db(nullptr);
		Connection con(db);
		Configure(db, con, server, client_implementation);
		S3TestHelper::RequireQueryOk(con, "SET s3_kms_key_id='test-kms-key'");
		S3TestHelper::RequireQueryOk(con, "BEGIN TRANSACTION");
		auto handle = OpenWriter(con);
		string payload = "small encrypted object";
		handle->Write(QueryContext(*con.context), data_ptr_cast(payload.data()), payload.size());
		handle->Close();
		handle->AbortWrite();
		handle->Close();
		handle.reset();
		S3TestHelper::RequireQueryOk(con, "COMMIT");

		auto observations = server.Observations();
		INFO(MockS3DescribeObservations(observations));
		REQUIRE(Count(observations, "PUT") == 1);
		REQUIRE(Count(observations, "POST") == 0);
		for (const auto &observation : observations) {
			if (observation.method == "PUT") {
				REQUIRE(observation.server_side_encryption == "aws:kms");
				REQUIRE(observation.kms_key_id == "test-kms-key");
			}
		}
	}

	static void RunSkippedClose(const string &client_implementation) {
		MockS3ServerConfig config;
		config.object.bucket = S3TestHelper::BUCKET;
		config.object.key = S3TestHelper::OBJECT_KEY;
		config.auth.refresh_target = MockS3RefreshTarget::HEAD;
		config.upload.initial_published_object = "existing object";
		MockS3Server server(std::move(config));

		DuckDB db(nullptr);
		Connection con(db);
		Configure(db, con, server, client_implementation);
		S3TestHelper::RequireQueryOk(con, "BEGIN TRANSACTION");
		{
			auto handle = OpenWriter(con);
			auto payload = MultipartPayload();
			handle->Write(QueryContext(*con.context), data_ptr_cast(payload.data()), payload.size());
		}
		S3TestHelper::RequireQueryOk(con, "ROLLBACK");

		auto observations = server.Observations();
		INFO(MockS3DescribeObservations(observations));
		REQUIRE(Count(observations, "POST", "uploads") == 1);
		REQUIRE(Count(observations, "PUT", "partNumber") > 0);
		REQUIRE(Count(observations, "POST", "uploadId") == 0);
		REQUIRE(Count(observations, "DELETE", "uploadId") == 0);
		REQUIRE(server.UploadedObject() == "existing object");
	}

	static void RunAbortBeforeInitialization(const string &client_implementation) {
		MockS3ServerConfig config;
		config.object.bucket = S3TestHelper::BUCKET;
		config.object.key = S3TestHelper::OBJECT_KEY;
		config.auth.refresh_target = MockS3RefreshTarget::HEAD;
		config.upload.initial_published_object = "existing object";
		MockS3Server server(std::move(config));

		DuckDB db(nullptr);
		Connection con(db);
		Configure(db, con, server, client_implementation);
		S3TestHelper::RequireQueryOk(con, "BEGIN TRANSACTION");
		auto handle = OpenWriter(con);
		handle->AbortWrite();
		handle->AbortWrite();
		string payload = "not published";
		auto write_error = RequireError(
		    [&]() { handle->Write(QueryContext(*con.context), data_ptr_cast(payload.data()), payload.size()); });
		auto close_error = RequireError([&]() { handle->Close(); });
		REQUIRE(StringUtil::Contains(write_error, "Cannot write to an aborted S3 upload"));
		REQUIRE(StringUtil::Contains(close_error, "Cannot finalize an aborted S3 upload"));
		handle.reset();
		S3TestHelper::RequireQueryOk(con, "ROLLBACK");

		auto observations = server.Observations();
		INFO(MockS3DescribeObservations(observations));
		REQUIRE(Count(observations, "PUT") == 0);
		REQUIRE(Count(observations, "POST") == 0);
		REQUIRE(Count(observations, "DELETE") == 0);
		REQUIRE(server.UploadedObject() == "existing object");
	}

	static void RunBufferedAbort(const string &client_implementation) {
		MockS3ServerConfig config;
		config.object.bucket = S3TestHelper::BUCKET;
		config.object.key = S3TestHelper::OBJECT_KEY;
		config.auth.refresh_target = MockS3RefreshTarget::HEAD;
		config.upload.initial_published_object = "existing object";
		MockS3Server server(std::move(config));

		DuckDB db(nullptr);
		Connection con(db);
		Configure(db, con, server, client_implementation);
		S3TestHelper::RequireQueryOk(con, "BEGIN TRANSACTION");
		auto handle = OpenWriter(con);
		string payload = "buffered replacement";
		handle->Write(QueryContext(*con.context), data_ptr_cast(payload.data()), payload.size());
		handle->AbortWrite();
		handle->AbortWrite();
		handle.reset();
		S3TestHelper::RequireQueryOk(con, "ROLLBACK");

		auto observations = server.Observations();
		INFO(MockS3DescribeObservations(observations));
		REQUIRE(Count(observations, "PUT") == 0);
		REQUIRE(Count(observations, "POST") == 0);
		REQUIRE(Count(observations, "DELETE") == 0);
		REQUIRE(server.UploadedObject() == "existing object");
	}

	static void RunMultipartAbort(const string &client_implementation) {
		MockS3ServerConfig config;
		config.object.bucket = S3TestHelper::BUCKET;
		config.object.key = S3TestHelper::OBJECT_KEY;
		config.auth.refresh_target = MockS3RefreshTarget::HEAD;
		config.upload.initial_published_object = "existing object";
		auto upload_id = config.upload.upload_id;
		MockS3Server server(std::move(config));

		DuckDB db(nullptr);
		Connection con(db);
		Configure(db, con, server, client_implementation);
		S3TestHelper::RequireQueryOk(con, "BEGIN TRANSACTION");
		auto handle = OpenWriter(con);
		auto payload = MultipartPayload();
		handle->Write(QueryContext(*con.context), data_ptr_cast(payload.data()), payload.size());
		handle->AbortWrite();
		handle->AbortWrite();
		handle.reset();
		S3TestHelper::RequireQueryOk(con, "ROLLBACK");

		auto observations = server.Observations();
		INFO(MockS3DescribeObservations(observations));
		REQUIRE(Count(observations, "POST", "uploads") == 1);
		REQUIRE(Count(observations, "PUT", "partNumber") > 0);
		REQUIRE(Count(observations, "POST", "uploadId") == 0);
		REQUIRE(Count(observations, "DELETE", "uploadId", optional_idx(204)) == 1);
		for (const auto &observation : observations) {
			if (observation.method == "DELETE") {
				REQUIRE(observation.upload_id == upload_id);
			}
		}
		REQUIRE(server.UploadedObject() == "existing object");
	}

	static void RunExplicitAbortFailure(const string &client_implementation) {
		MockS3ServerConfig config;
		config.object.bucket = S3TestHelper::BUCKET;
		config.object.key = S3TestHelper::OBJECT_KEY;
		config.auth.refresh_target = MockS3RefreshTarget::HEAD;
		config.upload.abort_behavior = MockS3MultipartAbortBehavior::ERROR;
		config.upload.initial_published_object = "existing object";
		MockS3Server server(std::move(config));

		DuckDB db(nullptr);
		Connection con(db);
		Configure(db, con, server, client_implementation);
		S3TestHelper::RequireQueryOk(con, "BEGIN TRANSACTION");
		auto handle = OpenWriter(con);
		auto payload = MultipartPayload();
		handle->Write(QueryContext(*con.context), data_ptr_cast(payload.data()), payload.size());
		auto abort_error = RequireError([&]() { handle->AbortWrite(); });
		REQUIRE(StringUtil::Contains(abort_error, "Failed to abort S3 multipart upload"));
		handle->AbortWrite();
		auto close_error = RequireError([&]() { handle->Close(); });
		REQUIRE(StringUtil::Contains(close_error, "Cannot finalize an aborted S3 upload"));
		handle.reset();
		S3TestHelper::RequireQueryOk(con, "ROLLBACK");

		auto observations = server.Observations();
		INFO(MockS3DescribeObservations(observations));
		REQUIRE(Count(observations, "DELETE", "uploadId", optional_idx(400)) == 1);
		REQUIRE(Count(observations, "POST", "uploadId") == 0);
		REQUIRE(server.UploadedObject() == "existing object");
	}

	static void RunBlockedPartAbort(const string &client_implementation) {
		MockS3ServerConfig config;
		config.object.bucket = S3TestHelper::BUCKET;
		config.object.key = S3TestHelper::OBJECT_KEY;
		config.auth.refresh_target = MockS3RefreshTarget::HEAD;
		config.upload.blocked_part_numbers = {1};
		MockS3Server server(std::move(config));

		DuckDB db(nullptr);
		Connection con(db);
		Configure(db, con, server, client_implementation);
		S3TestHelper::RequireQueryOk(con, "BEGIN TRANSACTION");
		auto handle = OpenWriter(con);
		auto payload = MultipartPayload();
		string write_error;
		string abort_error;
		std::atomic<bool> abort_finished(false);

		std::thread writer([&]() {
			try {
				handle->Write(QueryContext(*con.context), data_ptr_cast(payload.data()), payload.size());
			} catch (std::exception &ex) {
				write_error = ex.what();
			}
		});
		REQUIRE(server.WaitForPartUpload(1));
		std::thread aborter([&]() {
			try {
				handle->AbortWrite();
			} catch (std::exception &ex) {
				abort_error = ex.what();
			}
			abort_finished.store(true);
		});
		std::this_thread::sleep_for(std::chrono::milliseconds(50));
		auto observations_before_release = server.Observations();
		REQUIRE_FALSE(abort_finished.load());
		REQUIRE(Count(observations_before_release, "DELETE", "uploadId") == 0);
		server.ReleasePartUpload(1);
		writer.join();
		aborter.join();
		REQUIRE(write_error.empty());
		REQUIRE(abort_error.empty());
		handle.reset();
		S3TestHelper::RequireQueryOk(con, "ROLLBACK");

		auto observations = server.Observations();
		INFO(MockS3DescribeObservations(observations));
		REQUIRE(Count(observations, "DELETE", "uploadId", optional_idx(204)) == 1);
		REQUIRE(Count(observations, "POST", "uploadId") == 0);
	}

	static void RunExceptionUnwinding(const string &client_implementation) {
		MockS3ServerConfig config;
		config.object.bucket = S3TestHelper::BUCKET;
		config.object.key = S3TestHelper::OBJECT_KEY;
		config.auth.refresh_target = MockS3RefreshTarget::HEAD;
		MockS3Server server(std::move(config));

		DuckDB db(nullptr);
		Connection con(db);
		Configure(db, con, server, client_implementation);
		S3TestHelper::RequireQueryOk(con, "BEGIN TRANSACTION");
		auto payload = MultipartPayload();
		try {
			auto handle = OpenWriter(con);
			handle->Write(QueryContext(*con.context), data_ptr_cast(payload.data()), payload.size());
			throw IOException("Trigger stack unwinding");
		} catch (IOException &) {
		}
		S3TestHelper::RequireQueryOk(con, "ROLLBACK");

		auto observations = server.Observations();
		INFO(MockS3DescribeObservations(observations));
		REQUIRE(Count(observations, "POST", "uploads") == 1);
		REQUIRE(Count(observations, "PUT", "partNumber") == 1);
		REQUIRE(Count(observations, "POST", "uploadId") == 0);
		REQUIRE(Count(observations, "DELETE") == 0);
	}

	static void RunLocalFailureAbort(const string &client_implementation) {
		MockS3ServerConfig config;
		config.object.bucket = S3TestHelper::BUCKET;
		config.object.key = S3TestHelper::OBJECT_KEY;
		config.auth.refresh_target = MockS3RefreshTarget::HEAD;
		MockS3Server server(std::move(config));

		DuckDB db(nullptr);
		Connection con(db);
		Configure(db, con, server, client_implementation);
		S3TestHelper::RequireQueryOk(con, "BEGIN TRANSACTION");
		auto handle = OpenWriter(con);
		auto payload = MultipartPayload();
		handle->Write(QueryContext(*con.context), data_ptr_cast(payload.data()), payload.size());
		string extra = "x";
		auto first_error = RequireError([&]() {
			handle->Write(QueryContext(*con.context), data_ptr_cast(extra.data()), extra.size(), payload.size() - 1);
		});
		RequireStableError(*handle, first_error);
		REQUIRE(StringUtil::Contains(first_error, "S3 writes must be sequential"));
		handle.reset();
		S3TestHelper::RequireQueryOk(con, "ROLLBACK");

		auto observations = server.Observations();
		INFO(MockS3DescribeObservations(observations));
		REQUIRE(Count(observations, "DELETE", "uploadId", optional_idx(204)) == 1);
		REQUIRE(Count(observations, "POST", "uploadId") == 0);
	}

	static void RunBlockedInitializationFailure(const string &client_implementation,
	                                            MockS3MultipartInitializationBehavior behavior, bool expect_abort) {
		MockS3ServerConfig config;
		config.object.bucket = S3TestHelper::BUCKET;
		config.object.key = S3TestHelper::OBJECT_KEY;
		config.auth.refresh_target = MockS3RefreshTarget::HEAD;
		config.upload.block_initialization = true;
		config.upload.initialization_behavior = behavior;
		MockS3Server server(std::move(config));

		DuckDB db(nullptr);
		Connection con(db);
		Configure(db, con, server, client_implementation);
		S3TestHelper::RequireQueryOk(con, "BEGIN TRANSACTION");
		auto handle = OpenWriter(con);
		auto payload = MultipartPayload();
		string first_error;
		string second_error;
		std::atomic<bool> second_started(false);
		std::atomic<bool> second_finished(false);

		std::thread first([&]() {
			try {
				handle->Write(QueryContext(*con.context), data_ptr_cast(payload.data()), payload.size(), 0);
			} catch (std::exception &ex) {
				first_error = ex.what();
			}
		});
		auto initialization_started = server.WaitForMultipartInitialization();
		string duplicate = "x";
		std::thread second([&]() {
			second_started.store(true);
			try {
				handle->Write(QueryContext(*con.context), data_ptr_cast(duplicate.data()), duplicate.size(), 0);
			} catch (std::exception &ex) {
				second_error = ex.what();
			}
			second_finished.store(true);
		});
		while (!second_started.load()) {
			std::this_thread::yield();
		}
		std::this_thread::sleep_for(std::chrono::milliseconds(50));
		auto second_waited_for_initialization = !second_finished.load();
		auto observations_before_release = server.Observations();
		server.ReleaseMultipartInitialization();
		first.join();
		second.join();

		REQUIRE(initialization_started);
		REQUIRE(second_waited_for_initialization);
		REQUIRE(Count(observations_before_release, "DELETE", "uploadId") == 0);
		REQUIRE_FALSE(first_error.empty());
		REQUIRE(first_error == second_error);
		REQUIRE(StringUtil::Contains(first_error, "S3 writes must be sequential"));
		RequireStableError(*handle, first_error);
		handle.reset();
		S3TestHelper::RequireQueryOk(con, "ROLLBACK");

		auto observations = server.Observations();
		INFO(MockS3DescribeObservations(observations));
		REQUIRE(Count(observations, "POST", "uploads") == 1);
		REQUIRE(Count(observations, "PUT", "partNumber") == 0);
		REQUIRE(Count(observations, "DELETE", "uploadId") == (expect_abort ? 1 : 0));
		REQUIRE(Count(observations, "POST", "uploadId") == 0);
	}

	static void RunNamespacedEscapedUploadID(const string &client_implementation) {
		MockS3ServerConfig config;
		config.object.bucket = S3TestHelper::BUCKET;
		config.object.key = S3TestHelper::OBJECT_KEY;
		config.auth.refresh_target = MockS3RefreshTarget::HEAD;
		config.upload.upload_id = "opaque&id";
		config.upload.initialization_behavior = MockS3MultipartInitializationBehavior::NAMESPACED_ESCAPED_SUCCESS;
		MockS3Server server(std::move(config));

		DuckDB db(nullptr);
		Connection con(db);
		Configure(db, con, server, client_implementation);
		S3TestHelper::RequireQueryOk(con, "BEGIN TRANSACTION");
		auto handle = OpenWriter(con);
		auto payload = MultipartPayload();
		handle->Write(QueryContext(*con.context), data_ptr_cast(payload.data()), payload.size());
		handle->Close();
		handle.reset();
		S3TestHelper::RequireQueryOk(con, "COMMIT");

		auto observations = server.Observations();
		INFO(MockS3DescribeObservations(observations));
		REQUIRE(Count(observations, "POST", "uploads") == 1);
		REQUIRE(Count(observations, "PUT", "uploadId") > 0);
		REQUIRE(Count(observations, "POST", "uploadId") == 1);
		for (const auto &observation : observations) {
			if (!observation.upload_id.empty()) {
				REQUIRE(observation.upload_id == "opaque&id");
				REQUIRE(StringUtil::Contains(observation.target, "uploadId=opaque%26id"));
			}
		}
		REQUIRE(server.UploadedObject() == payload);
	}

	static void Run(const string &client_implementation) {
		SECTION("abort before initialization does not publish") {
			RunAbortBeforeInitialization(client_implementation);
		}
		SECTION("buffered abort preserves an existing object") {
			RunBufferedAbort(client_implementation);
		}
		SECTION("multipart abort uses the upload ID exactly once") {
			RunMultipartAbort(client_implementation);
		}
		SECTION("explicit abort failure still detaches the upload") {
			RunExplicitAbortFailure(client_implementation);
		}
		SECTION("abort waits for an active part upload") {
			RunBlockedPartAbort(client_implementation);
		}
		SECTION("skipped close destruction does not publish") {
			RunSkippedClose(client_implementation);
		}
		SECTION("abort failures are secondary and stable") {
			RunAbortFailure(client_implementation);
		}
		SECTION("embedded completion errors abort the upload") {
			RunEmbeddedCompletionError(client_implementation);
		}
		SECTION("completion transport loss is ambiguous") {
			RunAmbiguousCompletion(client_implementation, MockS3MultipartCompletionBehavior::COMMIT_THEN_DISCONNECT,
			                       "unknown outcome");
		}
		SECTION("a retryable completion response followed by transport loss is ambiguous") {
			RunAmbiguousCompletion(client_implementation, MockS3MultipartCompletionBehavior::COMMIT_THEN_DISCONNECT,
			                       "unknown outcome", true);
		}
		SECTION("empty completion success is ambiguous") {
			RunAmbiguousCompletion(client_implementation, MockS3MultipartCompletionBehavior::EMPTY_SUCCESS,
			                       "malformed XML");
		}
		SECTION("unknown completion success is ambiguous") {
			RunAmbiguousCompletion(client_implementation, MockS3MultipartCompletionBehavior::UNKNOWN_SUCCESS,
			                       "unrecognized response");
		}
		SECTION("malformed completion success is ambiguous") {
			RunAmbiguousCompletion(client_implementation, MockS3MultipartCompletionBehavior::MALFORMED_SUCCESS,
			                       "malformed XML");
		}
		SECTION("initialization transport loss is ambiguous") {
			RunAmbiguousInitialization(client_implementation,
			                           MockS3MultipartInitializationBehavior::CREATE_THEN_DISCONNECT,
			                           "unknown outcome");
		}
		SECTION("malformed initialization success is ambiguous") {
			RunAmbiguousInitialization(client_implementation, MockS3MultipartInitializationBehavior::MALFORMED_SUCCESS,
			                           "malformed XML");
		}
		SECTION("small KMS uploads use one PUT") {
			RunSmallKMSPut(client_implementation);
		}
		SECTION("destructors do not finalize during exception unwinding") {
			RunExceptionUnwinding(client_implementation);
		}
		SECTION("local failures abort active multipart uploads") {
			RunLocalFailureAbort(client_implementation);
		}
		SECTION("late initialization success is aborted after a concurrent local failure") {
			RunBlockedInitializationFailure(client_implementation, MockS3MultipartInitializationBehavior::SUCCESS,
			                                true);
		}
		SECTION("ambiguous initialization suppresses abort after a concurrent local failure") {
			RunBlockedInitializationFailure(client_implementation,
			                                MockS3MultipartInitializationBehavior::MALFORMED_SUCCESS, false);
		}
		SECTION("namespaced initialization decodes the upload ID") {
			RunNamespacedEscapedUploadID(client_implementation);
		}
	}
};

} // namespace

TEST_CASE("S3 upload lifecycle safety", "[httpfs][s3][upload]") {
	SECTION("curl") {
		S3UploadLifecycleTest::Run("curl");
	}
	SECTION("httplib") {
		S3UploadLifecycleTest::Run("httplib");
	}
}

} // namespace duckdb
