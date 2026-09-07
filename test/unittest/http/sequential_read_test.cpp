#include "catch.hpp"

#include "http/http_test_helper.hpp"

namespace duckdb {

namespace {

static void RunExactSequentialReadGeometry(const string &client_implementation, FileOpenFlags flags) {
	MockS3ServerConfig config;
	config.object.data = HTTPTestHelper::CreateObjectData(8192);
	auto expected_data = config.object.data;
	MockS3Server server(std::move(config));

	DuckDB db(nullptr);
	Connection con(db);
	HTTPTestHelper::Configure(db, con, 0, client_implementation);
	HTTPTestHelper::RequireQueryOk(con, "SET enable_external_file_cache=false");
	HTTPTestHelper::RequireQueryOk(con, "BEGIN TRANSACTION");

	auto &fs = FileSystem::GetFileSystem(*con.context);
	auto handle = fs.OpenFile(server.HTTPPath(), flags);

	REQUIRE(HTTPTestHelper::ReadSequential(con, *handle, 13) == expected_data.substr(0, 13));
	REQUIRE(HTTPTestHelper::ReadSequential(con, *handle, 17) == expected_data.substr(13, 17));
	REQUIRE(handle->SeekPosition() == 30);

	handle->Seek(1024);
	REQUIRE(HTTPTestHelper::ReadSequential(con, *handle, 19) == expected_data.substr(1024, 19));
	REQUIRE(handle->SeekPosition() == 1043);

	auto observations_before_empty_reads = server.Observations();
	REQUIRE(HTTPTestHelper::ReadSequential(con, *handle, 0).empty());
	handle->Seek(expected_data.size());
	REQUIRE(HTTPTestHelper::ReadSequential(con, *handle, 1).empty());
	REQUIRE(server.Observations().size() == observations_before_empty_reads.size());

	auto observations = server.Observations();
	INFO(MockS3DescribeObservations(observations));
	REQUIRE(HTTPTestHelper::CountRequests(observations, "GET", 206, "bytes=0-12") == 1);
	REQUIRE(HTTPTestHelper::CountRequests(observations, "GET", 206, "bytes=13-29") == 1);
	REQUIRE(HTTPTestHelper::CountRequests(observations, "GET", 206, "bytes=1024-1042") == 1);
	REQUIRE(HTTPTestHelper::CountRangeRequests(observations, 206) == 3);
	HTTPTestHelper::RequireQueryOk(con, "COMMIT");
}

static void RunSequentialFailureKeepsPosition(const string &client_implementation) {
	static constexpr idx_t READ_OFFSET = 113;
	static constexpr idx_t READ_LENGTH = 1024;

	MockS3ServerConfig config;
	config.object.data = HTTPTestHelper::CreateObjectData(8192);
	auto expected_data = config.object.data;
	config.range.behavior = MockS3RangeBehavior::TRUNCATE_TRANSFER;
	config.range.behavior_requests = 1;
	config.range.truncated_bytes = 17;
	MockS3Server server(std::move(config));

	DuckDB db(nullptr);
	Connection con(db);
	HTTPTestHelper::Configure(db, con, 0, client_implementation);
	HTTPTestHelper::RequireQueryOk(con, "SET enable_external_file_cache=false");
	HTTPTestHelper::RequireQueryOk(con, "BEGIN TRANSACTION");

	auto &fs = FileSystem::GetFileSystem(*con.context);
	auto handle = fs.OpenFile(server.HTTPPath(), FileFlags::FILE_FLAGS_READ);
	handle->Seek(READ_OFFSET);

	HTTPReadOutcome outcome;
	try {
		HTTPTestHelper::ReadSequential(con, *handle, READ_LENGTH);
	} catch (std::exception &ex) {
		outcome.failed = true;
		outcome.error = ex.what();
		ErrorData error(ex);
		outcome.internal_error = error.Type() == ExceptionType::INTERNAL || error.Type() == ExceptionType::FATAL;
	}
	INFO(outcome.error);
	REQUIRE(outcome.failed);
	REQUIRE_FALSE(outcome.internal_error);
	REQUIRE(handle->SeekPosition() == READ_OFFSET);

	REQUIRE(HTTPTestHelper::ReadSequential(con, *handle, 31) == expected_data.substr(READ_OFFSET, 31));
	REQUIRE(handle->SeekPosition() == READ_OFFSET + 31);

	auto observations = server.Observations();
	INFO(MockS3DescribeObservations(observations));
	REQUIRE(HTTPTestHelper::CountRequests(observations, "GET", 206, "bytes=113-1136") == 1);
	REQUIRE(HTTPTestHelper::CountRequests(observations, "GET", 206, "bytes=113-143") == 1);
	HTTPTestHelper::RequireQueryOk(con, "COMMIT");
}

static void RunSequentialFullDownloadFallback(const string &client_implementation) {
	MockS3ServerConfig config;
	config.object.data = HTTPTestHelper::CreateObjectData(8192);
	auto expected_data = config.object.data;
	config.range.advertise = false;
	config.range.behavior = MockS3RangeBehavior::IGNORE_RANGE;
	MockS3Server server(std::move(config));

	DuckDB db(nullptr);
	Connection con(db);
	HTTPTestHelper::Configure(db, con, 0, client_implementation);
	HTTPTestHelper::RequireQueryOk(con, "SET enable_external_file_cache=false");
	HTTPTestHelper::RequireQueryOk(con, "BEGIN TRANSACTION");

	auto &fs = FileSystem::GetFileSystem(*con.context);
	auto handle = fs.OpenFile(server.HTTPPath(), FileFlags::FILE_FLAGS_READ);
	REQUIRE(HTTPTestHelper::ReadSequential(con, *handle, 17) == expected_data.substr(0, 17));
	REQUIRE(handle->SeekPosition() == 17);
	REQUIRE(HTTPTestHelper::ReadSequential(con, *handle, 11) == expected_data.substr(17, 11));
	REQUIRE(handle->SeekPosition() == 28);

	auto observations = server.Observations();
	INFO(MockS3DescribeObservations(observations));
	REQUIRE(HTTPTestHelper::CountRequests(observations, "GET", 200, "bytes=0-16") == 1);
	REQUIRE(HTTPTestHelper::CountRequests(observations, "GET", 200) == 1);
	HTTPTestHelper::RequireQueryOk(con, "COMMIT");
}

} // namespace

TEST_CASE("HTTP sequential reads issue exact ranges without read-ahead", "[httpfs][read-ahead]") {
	SECTION("curl default flags") {
		RunExactSequentialReadGeometry("curl", FileFlags::FILE_FLAGS_READ);
	}
	SECTION("curl DirectIO") {
		RunExactSequentialReadGeometry("curl", FileFlags::FILE_FLAGS_READ | FileFlags::FILE_FLAGS_DIRECT_IO);
	}
	SECTION("curl parallel access") {
		RunExactSequentialReadGeometry("curl", FileFlags::FILE_FLAGS_READ | FileFlags::FILE_FLAGS_PARALLEL_ACCESS);
	}
	SECTION("httplib default flags") {
		RunExactSequentialReadGeometry("httplib", FileFlags::FILE_FLAGS_READ);
	}
	SECTION("httplib DirectIO") {
		RunExactSequentialReadGeometry("httplib", FileFlags::FILE_FLAGS_READ | FileFlags::FILE_FLAGS_DIRECT_IO);
	}
	SECTION("httplib parallel access") {
		RunExactSequentialReadGeometry("httplib", FileFlags::FILE_FLAGS_READ | FileFlags::FILE_FLAGS_PARALLEL_ACCESS);
	}
}

TEST_CASE("HTTP sequential read failures leave the cursor unchanged", "[httpfs][read-ahead][short-read]") {
	SECTION("curl") {
		RunSequentialFailureKeepsPosition("curl");
	}
	SECTION("httplib") {
		RunSequentialFailureKeepsPosition("httplib");
	}
}

TEST_CASE("HTTP sequential reads retain full-download fallback", "[httpfs][read-ahead][full-download]") {
	SECTION("curl") {
		RunSequentialFullDownloadFallback("curl");
	}
	SECTION("httplib") {
		RunSequentialFullDownloadFallback("httplib");
	}
}

} // namespace duckdb
