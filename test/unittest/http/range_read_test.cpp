#include "catch.hpp"

#include "http/http_test_helper.hpp"
#include "http/httpfs.hpp"

#include <atomic>
#include <thread>

namespace duckdb {

namespace {

static void RunPersistentShortRead() {
	static constexpr idx_t READ_OFFSET = 113;
	static constexpr idx_t READ_LENGTH = 1024;
	const string expected_range = "bytes=113-1136";

	MockS3ServerConfig config;
	config.object.data = string(8192, 'x');
	config.range.behavior = MockS3RangeBehavior::TRUNCATE_TRANSFER;
	config.range.behavior_requests = 4;
	config.range.truncated_bytes = 17;
	MockS3Server server(std::move(config));

	DuckDB db(nullptr);
	Connection con(db);
	HTTPTestHelper::Configure(db, con, 3);

	HTTPTestHelper::RequireQueryOk(con, "BEGIN TRANSACTION");
	auto outcome = HTTPTestHelper::TryReadRange(con, server.HTTPPath(), READ_OFFSET, READ_LENGTH);
	HTTPTestHelper::RequireQueryOk(con, "ROLLBACK");
	auto observations = server.Observations();
	INFO(MockS3DescribeObservations(observations));
	INFO(outcome.error);
	REQUIRE(outcome.failed);
	REQUIRE_FALSE(outcome.internal_error);
	REQUIRE(HTTPTestHelper::CountRequests(observations, "GET", 206, expected_range) == 4);
}

static void RunTransientShortRead() {
	static constexpr idx_t READ_OFFSET = 113;
	static constexpr idx_t READ_LENGTH = 1024;
	const string expected_range = "bytes=113-1136";

	MockS3ServerConfig config;
	config.object.data = string(8192, 'x');
	config.range.behavior = MockS3RangeBehavior::TRUNCATE_TRANSFER;
	config.range.behavior_requests = 1;
	config.range.truncated_bytes = 17;
	auto expected = config.object.data.substr(READ_OFFSET, READ_LENGTH);
	MockS3Server server(std::move(config));

	DuckDB db(nullptr);
	Connection con(db);
	HTTPTestHelper::Configure(db, con, 1);

	HTTPTestHelper::RequireQueryOk(con, "BEGIN TRANSACTION");
	auto actual = HTTPTestHelper::ReadRange(con, server.HTTPPath(), READ_OFFSET, READ_LENGTH);
	HTTPTestHelper::RequireQueryOk(con, "COMMIT");
	REQUIRE(actual == expected);
	auto observations = server.Observations();
	INFO(MockS3DescribeObservations(observations));
	REQUIRE(HTTPTestHelper::CountRequests(observations, "GET", 206, expected_range) == 2);
}

static void RunSuccessfulShortResponse() {
	static constexpr idx_t READ_OFFSET = 113;
	static constexpr idx_t READ_LENGTH = 1024;
	const string expected_range = "bytes=113-1136";

	MockS3ServerConfig config;
	config.object.data = string(8192, 'x');
	config.range.behavior = MockS3RangeBehavior::SHORT_SUCCESS;
	config.range.behavior_requests = 1;
	config.range.truncated_bytes = 17;
	MockS3Server server(std::move(config));

	DuckDB db(nullptr);
	Connection con(db);
	HTTPTestHelper::Configure(db, con, 0);

	HTTPTestHelper::RequireQueryOk(con, "BEGIN TRANSACTION");
	auto outcome = HTTPTestHelper::TryReadRange(con, server.HTTPPath(), READ_OFFSET, READ_LENGTH);
	HTTPTestHelper::RequireQueryOk(con, "ROLLBACK");
	auto observations = server.Observations();
	INFO(MockS3DescribeObservations(observations));
	INFO(outcome.error);
	REQUIRE(outcome.failed);
	REQUIRE_FALSE(outcome.internal_error);
	REQUIRE(outcome.error.find("Short read for HTTP GET") != string::npos);
	REQUIRE(HTTPTestHelper::CountRequests(observations, "GET", 206, expected_range) == 1);
}

static void RunParallelRangeHeaderRelease(const string &client_implementation) {
	MockS3ServerConfig config;
	config.object.data = string(8192, 'x');
	config.range.advertise = false;
	config.range.block_first_body_until_second = true;
	MockS3Server server(std::move(config));

	DuckDB db(nullptr);
	Connection con(db);
	HTTPTestHelper::Configure(db, con, 0, client_implementation);
	HTTPTestHelper::RequireQueryOk(con, "BEGIN TRANSACTION");

	auto &fs = FileSystem::GetFileSystem(*con.context);
	auto first_handle = fs.OpenFile(server.HTTPPath(), FileFlags::FILE_FLAGS_READ | FileFlags::FILE_FLAGS_DIRECT_IO);
	auto second_handle = fs.OpenFile(server.HTTPPath(), FileFlags::FILE_FLAGS_READ | FileFlags::FILE_FLAGS_DIRECT_IO);

	std::atomic<bool> start {false};
	HTTPReadOutcome first_outcome;
	HTTPReadOutcome second_outcome;
	std::thread first_reader([&]() {
		while (!start.load()) {
			std::this_thread::yield();
		}
		first_outcome = HTTPTestHelper::TryReadHandle(con, *first_handle, 0, 1024);
	});
	std::thread second_reader([&]() {
		while (!start.load()) {
			std::this_thread::yield();
		}
		second_outcome = HTTPTestHelper::TryReadHandle(con, *second_handle, 1024, 1024);
	});
	start = true;
	first_reader.join();
	second_reader.join();

	auto observations = server.Observations();
	INFO(first_outcome.error);
	INFO(second_outcome.error);
	INFO(MockS3DescribeObservations(observations));
	REQUIRE_FALSE(first_outcome.failed);
	REQUIRE_FALSE(second_outcome.failed);
	REQUIRE(HTTPTestHelper::CountRequests(observations, "GET", 206, "bytes=0-1023") == 1);
	REQUIRE(HTTPTestHelper::CountRequests(observations, "GET", 206, "bytes=1024-2047") == 1);
	HTTPTestHelper::RequireQueryOk(con, "COMMIT");
}

static void RunFullDownloadSingleFlight(const string &client_implementation, bool shared_handle) {
	static constexpr idx_t READ_LENGTH = 1024;
	const vector<idx_t> offsets {0, 2048, 4096, 6144};

	MockS3ServerConfig config;
	config.object.data.resize(8192);
	for (idx_t i = 0; i < config.object.data.size(); i++) {
		config.object.data[i] = NumericCast<char>('a' + (i % 26));
	}
	const auto expected_data = config.object.data;
	config.range.advertise = false;
	config.range.behavior = MockS3RangeBehavior::IGNORE_RANGE;
	config.full_get.block_until_released = true;
	MockS3Server server(std::move(config));

	DuckDB db(nullptr);
	Connection con(db);
	HTTPTestHelper::Configure(db, con, 0, client_implementation);
	HTTPTestHelper::RequireQueryOk(con, "BEGIN TRANSACTION");

	auto &fs = FileSystem::GetFileSystem(*con.context);
	const auto flags =
	    FileFlags::FILE_FLAGS_READ | FileFlags::FILE_FLAGS_DIRECT_IO | FileFlags::FILE_FLAGS_PARALLEL_ACCESS;
	vector<unique_ptr<FileHandle>> handles;
	const auto handle_count = shared_handle ? 1 : offsets.size();
	for (idx_t i = 0; i < handle_count; i++) {
		handles.push_back(fs.OpenFile(server.HTTPPath(), flags));
	}

	std::atomic<bool> start {false};
	vector<HTTPReadOutcome> outcomes(offsets.size());
	vector<std::thread> readers;
	for (idx_t i = 0; i < offsets.size(); i++) {
		readers.emplace_back([&, i]() {
			while (!start.load()) {
				std::this_thread::yield();
			}
			auto &handle = shared_handle ? *handles[0] : *handles[i];
			outcomes[i] = HTTPTestHelper::TryReadHandle(con, handle, offsets[i], READ_LENGTH);
		});
	}
	start = true;
	const auto full_get_started = server.WaitForFullGet();
	server.ReleaseFullGet();
	for (auto &reader : readers) {
		reader.join();
	}

	REQUIRE(full_get_started);
	for (idx_t i = 0; i < outcomes.size(); i++) {
		INFO(outcomes[i].error);
		REQUIRE_FALSE(outcomes[i].failed);
		REQUIRE(outcomes[i].data == expected_data.substr(offsets[i], READ_LENGTH));
	}
	auto observations = server.Observations();
	INFO(MockS3DescribeObservations(observations));
	REQUIRE(HTTPTestHelper::CountRangeRequests(observations, 200) == 1);
	REQUIRE(HTTPTestHelper::CountRequests(observations, "GET", 200) == 1);
	HTTPTestHelper::RequireQueryOk(con, "COMMIT");
}

} // namespace

TEST_CASE("HTTP range reads reject truncated response bodies", "[httpfs][short-read]") {
	SECTION("persistent transfer truncation exhausts retries") {
		RunPersistentShortRead();
	}
	SECTION("transient transfer truncation is replaced by a complete retry") {
		RunTransientShortRead();
	}
	SECTION("a cleanly terminated short response is rejected") {
		RunSuccessfulShortResponse();
	}
}

TEST_CASE("HTTP range readers resume after the first response headers", "[httpfs][range-probe]") {
	SECTION("curl") {
		RunParallelRangeHeaderRelease("curl");
	}
	SECTION("httplib") {
		RunParallelRangeHeaderRelease("httplib");
	}
}

TEST_CASE("HTTP full-download fallback is single-flight", "[httpfs][full-download][range-probe]") {
	SECTION("curl with separate handles") {
		RunFullDownloadSingleFlight("curl", false);
	}
	SECTION("curl with a shared handle") {
		RunFullDownloadSingleFlight("curl", true);
	}
	SECTION("httplib with separate handles") {
		RunFullDownloadSingleFlight("httplib", false);
	}
	SECTION("httplib with a shared handle") {
		RunFullDownloadSingleFlight("httplib", true);
	}
}

TEST_CASE("HTTP full-download fallback rejects HEAD and GET length mismatches", "[httpfs][full-download][issue-354]") {
	MockS3ServerConfig config;
	config.object.data = "AB";
	config.metadata.head_content_length = 3;
	config.range.behavior = MockS3RangeBehavior::IGNORE_RANGE;
	MockS3Server server(std::move(config));

	DuckDB db(nullptr);
	Connection con(db);
	HTTPTestHelper::Configure(db, con, 0);
	HTTPTestHelper::RequireQueryOk(con, "SET enable_http_metadata_cache=true");

	HTTPTestHelper::RequireQueryOk(con, "BEGIN TRANSACTION");
	auto initial_outcome = HTTPTestHelper::TryReadRange(con, server.HTTPPath(), 0, 1);
	auto observations = server.Observations();
	INFO(MockS3DescribeObservations(observations));
	INFO(initial_outcome.error);
	REQUIRE(initial_outcome.failed);
	REQUIRE_FALSE(initial_outcome.internal_error);
	REQUIRE(initial_outcome.error.find("size reported by HEAD") != string::npos);
	REQUIRE(initial_outcome.error.find("full GET downloaded") != string::npos);
	REQUIRE(HTTPTestHelper::CountRequests(observations, "HEAD", 200) == 1);
	REQUIRE(HTTPTestHelper::CountRequests(observations, "GET", 200, "bytes=0-0") == 1);
	REQUIRE(HTTPTestHelper::CountRequests(observations, "GET", 200) == 1);

	auto &fs = FileSystem::GetFileSystem(*con.context);
	auto reopened = fs.OpenFile(server.HTTPPath(), FileFlags::FILE_FLAGS_READ | FileFlags::FILE_FLAGS_DIRECT_IO);
	REQUIRE(reopened->Cast<HTTPFileHandle>().etag == "\"httpfs-refresh-test-etag\"");
	auto reopened_outcome = HTTPTestHelper::TryReadHandle(con, *reopened, 0, 1);
	INFO(reopened_outcome.error);
	REQUIRE(reopened_outcome.failed);
	REQUIRE_FALSE(reopened_outcome.internal_error);

	observations = server.Observations();
	INFO(MockS3DescribeObservations(observations));
	REQUIRE(HTTPTestHelper::CountRequests(observations, "HEAD", 200) == 1);
	REQUIRE(HTTPTestHelper::CountRequests(observations, "GET", 200, "bytes=0-0") == 2);
	REQUIRE(HTTPTestHelper::CountRequests(observations, "GET", 200) == 2);
	HTTPTestHelper::RequireQueryOk(con, "SELECT 42");

	HTTPTestHelper::RequireQueryOk(con, "SET force_download=true");
	REQUIRE(HTTPTestHelper::ReadRange(con, server.HTTPPath(), 0, 2) == "AB");
	HTTPTestHelper::RequireQueryOk(con, "COMMIT");
}

} // namespace duckdb
