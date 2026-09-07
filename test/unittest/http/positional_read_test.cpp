#include "catch.hpp"

#include "s3/mock_s3_server.hpp"

#include "http/httpfs.hpp"
#include "httpfs_extension.hpp"

#include "duckdb.hpp"
#include "duckdb/common/error_data.hpp"
#include "duckdb/common/file_system.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/main/extension/extension_loader.hpp"

#include <atomic>
#include <thread>

namespace duckdb {

namespace {

static void LoadHTTPFSExtension(DuckDB &db) {
	if (db.ExtensionIsLoaded("httpfs")) {
		return;
	}
	ExtensionInfo extension_info;
	ExtensionActiveLoad load_info(*db.instance, extension_info, "httpfs", "");
	ExtensionLoader loader(load_info);
	HttpfsExtension extension;
	extension.Load(loader);
}

static void RequireQueryOk(Connection &con, const string &query) {
	auto result = con.Query(query);
	REQUIRE(result);
	INFO((result->HasError() ? result->GetError() : string()));
	REQUIRE_FALSE(result->HasError());
}

static void ConfigureHTTPReadTest(DuckDB &db, Connection &con, const string &client_implementation, idx_t retries = 0) {
	LoadHTTPFSExtension(db);
	RequireQueryOk(con, "SET httpfs_client_implementation='" + client_implementation + "'");
	RequireQueryOk(con, "SET httpfs_connection_caching=false");
	RequireQueryOk(con, "SET enable_external_file_cache=false");
	RequireQueryOk(con, "SET http_retries=" + to_string(retries));
	RequireQueryOk(con, "SET http_retry_wait_ms=1");
	RequireQueryOk(con, "SET http_retry_backoff=1");
}

static void ConfigureS3ReadTest(DuckDB &db, Connection &con, MockS3Server &server, const string &client_implementation,
                                idx_t retries = 0) {
	ConfigureHTTPReadTest(db, con, client_implementation, retries);
	RequireQueryOk(con, StringUtil::Format(R"(
CREATE SECRET positional_read_s3 (
	TYPE S3,
	PROVIDER CONFIG,
	SCOPE 's3://refresh-bucket/',
	KEY_ID 'POSITIONAL_KEY',
	SECRET 'POSITIONAL_SECRET',
	REGION 'us-east-1',
	ENDPOINT '%s',
	USE_SSL false,
	URL_STYLE 'path'
))",
	                                       server.Endpoint()));
}

struct ReadOutcome {
	bool failed = false;
	bool internal_error = false;
	string error;
	string data;
};

static ReadOutcome TryReadHandle(Connection &con, FileHandle &handle, idx_t offset, idx_t length) {
	ReadOutcome result;
	try {
		result.data.resize(length, '?');
		handle.Read(QueryContext(*con.context), result.data.data(), length, offset);
	} catch (std::exception &ex) {
		result.failed = true;
		result.error = ex.what();
		ErrorData error(ex);
		result.internal_error = error.Type() == ExceptionType::INTERNAL || error.Type() == ExceptionType::FATAL;
	}
	return result;
}

static string ReadSequential(Connection &con, FileHandle &handle, idx_t length) {
	string result(length, '?');
	auto read_count = handle.Read(QueryContext(*con.context), result.data(), length);
	result.resize(NumericCast<idx_t>(read_count));
	return result;
}

static vector<MockS3RequestObservation> RangeObservations(const MockS3Server &server) {
	vector<MockS3RequestObservation> result;
	for (auto &observation : server.Observations()) {
		if (observation.method == "GET" && !observation.range.empty()) {
			result.push_back(observation);
		}
	}
	return result;
}

static void RunConcurrentPositionalRead(const string &client_implementation, bool s3, bool parallel_access) {
	static constexpr idx_t READ_SIZE = 64 * 1024;
	static constexpr idx_t SECOND_OFFSET = READ_SIZE / 2;
	MockS3ServerConfig config;
	config.object.data.resize(READ_SIZE * 2);
	for (idx_t i = 0; i < config.object.data.size(); i++) {
		config.object.data[i] = NumericCast<char>('a' + (i % 26));
	}
	config.range.blocked = StringUtil::Format("bytes=0-%llu", static_cast<unsigned long long>(READ_SIZE - 1));
	config.range.release = StringUtil::Format("bytes=%llu-%llu", static_cast<unsigned long long>(SECOND_OFFSET),
	                                          static_cast<unsigned long long>(SECOND_OFFSET + READ_SIZE - 1));
	config.metadata.version_id = "version-concurrent";
	config.metadata.version_on_head = s3;
	auto expected_data = config.object.data;
	auto blocked_range = config.range.blocked;
	auto release_range = config.range.release;
	MockS3Server server(std::move(config));

	DuckDB db(nullptr);
	Connection con(db);
	if (s3) {
		ConfigureS3ReadTest(db, con, server, client_implementation);
		RequireQueryOk(con, "SET s3_version_id_pinning=true");
	} else {
		ConfigureHTTPReadTest(db, con, client_implementation);
	}
	RequireQueryOk(con, "BEGIN TRANSACTION");

	auto &fs = FileSystem::GetFileSystem(*con.context);
	auto flags = FileFlags::FILE_FLAGS_READ | FileFlags::FILE_FLAGS_DIRECT_IO;
	if (parallel_access) {
		flags |= FileFlags::FILE_FLAGS_PARALLEL_ACCESS;
	}
	auto handle = fs.OpenFile(s3 ? server.S3Path() : server.HTTPPath(), flags);
	handle->Seek(17);

	std::atomic<bool> start {false};
	ReadOutcome first;
	ReadOutcome second;
	std::thread first_reader([&]() {
		while (!start.load()) {
			std::this_thread::yield();
		}
		first = TryReadHandle(con, *handle, 0, READ_SIZE);
	});
	std::thread second_reader([&]() {
		while (!start.load()) {
			std::this_thread::yield();
		}
		second = TryReadHandle(con, *handle, SECOND_OFFSET, READ_SIZE);
	});
	start = true;
	first_reader.join();
	second_reader.join();

	INFO(first.error);
	INFO(second.error);
	REQUIRE_FALSE(first.failed);
	REQUIRE_FALSE(second.failed);
	REQUIRE(first.data == expected_data.substr(0, READ_SIZE));
	REQUIRE(second.data == expected_data.substr(SECOND_OFFSET, READ_SIZE));
	REQUIRE(handle->SeekPosition() == 17);

	auto observations = RangeObservations(server);
	INFO(MockS3DescribeObservations(observations));
	REQUIRE(observations.size() == 2);
	for (auto &observation : observations) {
		REQUIRE((observation.range == blocked_range || observation.range == release_range));
		if (s3) {
			REQUIRE(observation.version_id == "version-concurrent");
			REQUIRE(observation.if_match.empty());
		} else {
			REQUIRE(observation.if_match == "\"httpfs-refresh-test-etag\"");
			REQUIRE(observation.version_id.empty());
		}
	}

	NetworkThroughputEstimate estimate;
	REQUIRE(handle->TryGetNetworkThroughput(estimate));
	REQUIRE(estimate.latency_seconds > 0);
	REQUIRE(estimate.bandwidth_bytes_per_s > 0);
	RequireQueryOk(con, "COMMIT");
}

static void RunSequentialPositionalSeparation(const string &client_implementation) {
	MockS3ServerConfig config;
	config.object.data = "abcdefghijklmnopqrstuvwxyz0123456789";
	auto expected_data = config.object.data;
	MockS3Server server(std::move(config));

	DuckDB db(nullptr);
	Connection con(db);
	ConfigureHTTPReadTest(db, con, client_implementation);
	RequireQueryOk(con, "BEGIN TRANSACTION");

	auto &fs = FileSystem::GetFileSystem(*con.context);
	auto handle = fs.OpenFile(server.HTTPPath(), FileFlags::FILE_FLAGS_READ | FileFlags::FILE_FLAGS_DIRECT_IO);
	REQUIRE(ReadSequential(con, *handle, 5) == expected_data.substr(0, 5));
	REQUIRE(TryReadHandle(con, *handle, 20, 4).data == expected_data.substr(20, 4));
	REQUIRE(handle->SeekPosition() == 5);
	REQUIRE(ReadSequential(con, *handle, 5) == expected_data.substr(5, 5));
	REQUIRE(handle->SeekPosition() == 10);
	RequireQueryOk(con, "COMMIT");
}

static void RunETagConditionCase(const string &etag, const string &expected_if_match, bool disable_checks = false) {
	MockS3ServerConfig config;
	config.metadata.etag = etag;
	MockS3Server server(std::move(config));

	DuckDB db(nullptr);
	Connection con(db);
	ConfigureHTTPReadTest(db, con, "curl");
	if (disable_checks) {
		RequireQueryOk(con, "SET unsafe_disable_etag_checks=true");
	}
	RequireQueryOk(con, "BEGIN TRANSACTION");

	auto &fs = FileSystem::GetFileSystem(*con.context);
	auto handle = fs.OpenFile(server.HTTPPath(), FileFlags::FILE_FLAGS_READ | FileFlags::FILE_FLAGS_DIRECT_IO);
	auto outcome = TryReadHandle(con, *handle, 2, 5);
	INFO(outcome.error);
	REQUIRE_FALSE(outcome.failed);

	auto observations = RangeObservations(server);
	REQUIRE(observations.size() == 1);
	REQUIRE(observations[0].if_match == expected_if_match);
	RequireQueryOk(con, "COMMIT");
}

static void RunConfiguredReadHeaderCollision() {
	MockS3ServerConfig config;
	config.object.data = "abcdefghijklmnopqrstuvwxyz";
	auto expected_data = config.object.data;
	MockS3Server server(std::move(config));

	DuckDB db(nullptr);
	Connection con(db);
	ConfigureHTTPReadTest(db, con, "curl");
	RequireQueryOk(con, StringUtil::Format(R"(
CREATE SECRET positional_read_headers (
	TYPE HTTP,
	SCOPE '%s',
	EXTRA_HTTP_HEADERS MAP {
		'Range': 'bytes=10-14'
	}
))",
	                                       server.HTTPPath()));
	RequireQueryOk(con, "BEGIN TRANSACTION");

	auto &fs = FileSystem::GetFileSystem(*con.context);
	auto handle = fs.OpenFile(server.HTTPPath(), FileFlags::FILE_FLAGS_READ | FileFlags::FILE_FLAGS_DIRECT_IO);
	auto outcome = TryReadHandle(con, *handle, 2, 5);
	INFO(outcome.error);
	CHECK_FALSE(outcome.failed);
	if (!outcome.failed) {
		CHECK(outcome.data == expected_data.substr(2, 5));
	}

	auto observations = RangeObservations(server);
	INFO(MockS3DescribeObservations(observations));
	CHECK(observations.size() == 1);
	for (auto &observation : observations) {
		CHECK(observation.range == "bytes=2-6");
	}
	RequireQueryOk(con, "COMMIT");
}

static void RunConfiguredIfMatchCollision() {
	MockS3ServerConfig config;
	config.metadata.enforce_if_match = true;
	MockS3Server server(std::move(config));

	DuckDB db(nullptr);
	Connection con(db);
	ConfigureHTTPReadTest(db, con, "curl");
	RequireQueryOk(con, StringUtil::Format(R"(
CREATE SECRET positional_read_headers (
	TYPE HTTP,
	SCOPE '%s',
	EXTRA_HTTP_HEADERS MAP {
		'If-Match': '"configured-etag"'
	}
))",
	                                       server.HTTPPath()));
	RequireQueryOk(con, "BEGIN TRANSACTION");

	auto &fs = FileSystem::GetFileSystem(*con.context);
	auto handle = fs.OpenFile(server.HTTPPath(), FileFlags::FILE_FLAGS_READ | FileFlags::FILE_FLAGS_DIRECT_IO);
	auto outcome = TryReadHandle(con, *handle, 2, 5);
	INFO(outcome.error);
	CHECK_FALSE(outcome.failed);

	auto observations = RangeObservations(server);
	INFO(MockS3DescribeObservations(observations));
	REQUIRE(observations.size() == 1);
	CHECK(observations[0].if_match == "\"httpfs-refresh-test-etag\"");
	RequireQueryOk(con, "COMMIT");
}

static void RunPreconditionFailure(const string &client_implementation) {
	MockS3ServerConfig config;
	config.metadata.etag = "\"opened-etag\"";
	config.metadata.get_etag = "\"changed-etag\"";
	config.metadata.enforce_if_match = true;
	MockS3Server server(std::move(config));

	DuckDB db(nullptr);
	Connection con(db);
	ConfigureHTTPReadTest(db, con, client_implementation, 3);
	RequireQueryOk(con, "BEGIN TRANSACTION");

	auto &fs = FileSystem::GetFileSystem(*con.context);
	auto handle = fs.OpenFile(server.HTTPPath(), FileFlags::FILE_FLAGS_READ | FileFlags::FILE_FLAGS_DIRECT_IO);
	handle->Seek(9);
	auto outcome = TryReadHandle(con, *handle, 2, 5);
	INFO(outcome.error);
	REQUIRE(outcome.failed);
	REQUIRE_FALSE(outcome.internal_error);
	REQUIRE(outcome.error.find("changed after it was opened") != string::npos);
	REQUIRE(handle->SeekPosition() == 9);

	auto observations = RangeObservations(server);
	INFO(MockS3DescribeObservations(observations));
	REQUIRE(observations.size() == 1);
	REQUIRE(observations[0].status == 412);
	REQUIRE(observations[0].if_match == "\"opened-etag\"");
	RequireQueryOk(con, "COMMIT");
}

static void RunImmutableS3ReadCondition(const string &client_implementation, bool disable_etag_checks) {
	MockS3ServerConfig config;
	config.metadata.version_id = "version-from-get";
	config.metadata.version_on_get = true;
	MockS3Server server(std::move(config));

	DuckDB db(nullptr);
	Connection con(db);
	ConfigureS3ReadTest(db, con, server, client_implementation);
	RequireQueryOk(con, "SET s3_version_id_pinning=true");
	if (disable_etag_checks) {
		RequireQueryOk(con, "SET unsafe_disable_etag_checks=true");
	}
	RequireQueryOk(con, "BEGIN TRANSACTION");

	auto &fs = FileSystem::GetFileSystem(*con.context);
	auto handle = fs.OpenFile(server.S3Path(), FileFlags::FILE_FLAGS_READ | FileFlags::FILE_FLAGS_DIRECT_IO);
	REQUIRE_FALSE(TryReadHandle(con, *handle, 0, 5).failed);
	REQUIRE_FALSE(TryReadHandle(con, *handle, 5, 5).failed);

	auto observations = RangeObservations(server);
	INFO(MockS3DescribeObservations(observations));
	REQUIRE(observations.size() == 2);
	REQUIRE(observations[0].version_id.empty());
	REQUIRE(observations[1].version_id.empty());
	if (disable_etag_checks) {
		REQUIRE(observations[0].if_match.empty());
		REQUIRE(observations[1].if_match.empty());
	} else {
		REQUIRE(observations[0].if_match == "\"httpfs-refresh-test-etag\"");
		REQUIRE(observations[1].if_match == "\"httpfs-refresh-test-etag\"");
	}
	RequireQueryOk(con, "COMMIT");
}

static void RunConditionalFullDownload(const string &client_implementation) {
	MockS3ServerConfig config;
	config.range.behavior = MockS3RangeBehavior::IGNORE_RANGE;
	MockS3Server server(std::move(config));

	DuckDB db(nullptr);
	Connection con(db);
	ConfigureHTTPReadTest(db, con, client_implementation);
	RequireQueryOk(con, "BEGIN TRANSACTION");

	auto &fs = FileSystem::GetFileSystem(*con.context);
	auto handle = fs.OpenFile(server.HTTPPath(), FileFlags::FILE_FLAGS_READ | FileFlags::FILE_FLAGS_DIRECT_IO);
	handle->Seek(11);
	auto outcome = TryReadHandle(con, *handle, 2, 5);
	INFO(outcome.error);
	REQUIRE_FALSE(outcome.failed);
	REQUIRE(handle->SeekPosition() == 11);

	auto observations = server.Observations();
	INFO(MockS3DescribeObservations(observations));
	idx_t conditional_gets = 0;
	for (auto &observation : observations) {
		if (observation.method == "GET") {
			REQUIRE(observation.if_match == "\"httpfs-refresh-test-etag\"");
			conditional_gets++;
		}
	}
	REQUIRE(conditional_gets == 2);
	RequireQueryOk(con, "COMMIT");
}

static void RunConditionSurvivesRetry(const string &client_implementation, bool s3) {
	MockS3ServerConfig config;
	config.failures.transient_get_failures = 1;
	config.metadata.version_id = "version-retry";
	config.metadata.version_on_head = s3;
	MockS3Server server(std::move(config));

	DuckDB db(nullptr);
	Connection con(db);
	if (s3) {
		ConfigureS3ReadTest(db, con, server, client_implementation, 1);
		RequireQueryOk(con, "SET s3_version_id_pinning=true");
	} else {
		ConfigureHTTPReadTest(db, con, client_implementation, 1);
	}
	RequireQueryOk(con, "BEGIN TRANSACTION");

	auto &fs = FileSystem::GetFileSystem(*con.context);
	auto handle = fs.OpenFile(s3 ? server.S3Path() : server.HTTPPath(),
	                          FileFlags::FILE_FLAGS_READ | FileFlags::FILE_FLAGS_DIRECT_IO);
	auto outcome = TryReadHandle(con, *handle, 2, 5);
	INFO(outcome.error);
	REQUIRE_FALSE(outcome.failed);

	auto observations = RangeObservations(server);
	INFO(MockS3DescribeObservations(observations));
	REQUIRE(observations.size() == 2);
	REQUIRE(observations[0].status == 400);
	REQUIRE(observations[1].status == 206);
	for (auto &observation : observations) {
		if (s3) {
			REQUIRE(observation.version_id == "version-retry");
			REQUIRE(observation.if_match.empty());
		} else {
			REQUIRE(observation.version_id.empty());
			REQUIRE(observation.if_match == "\"httpfs-refresh-test-etag\"");
		}
	}
	RequireQueryOk(con, "COMMIT");
}

static void RunS3ThresholdFullDownload(const string &client_implementation) {
	MockS3ServerConfig config;
	config.metadata.version_id = "version-threshold";
	config.metadata.version_on_head = true;
	MockS3Server server(std::move(config));

	DuckDB db(nullptr);
	Connection con(db);
	ConfigureS3ReadTest(db, con, server, client_implementation);
	RequireQueryOk(con, "SET s3_version_id_pinning=true");
	RequireQueryOk(con, "SET force_download_threshold=1024");
	RequireQueryOk(con, "BEGIN TRANSACTION");

	auto &fs = FileSystem::GetFileSystem(*con.context);
	auto handle = fs.OpenFile(server.S3Path(), FileFlags::FILE_FLAGS_READ);
	REQUIRE(handle);

	auto observations = server.Observations();
	INFO(MockS3DescribeObservations(observations));
	idx_t full_gets = 0;
	for (auto &observation : observations) {
		if (observation.method == "GET" && observation.range.empty()) {
			REQUIRE(observation.version_id == "version-threshold");
			REQUIRE(observation.if_match.empty());
			full_gets++;
		}
	}
	REQUIRE(full_gets == 1);
	RequireQueryOk(con, "COMMIT");
}

} // namespace

TEST_CASE("HTTP positional reads are independent on one handle", "[httpfs][positional-read]") {
	for (auto &client : {"curl", "httplib"}) {
		DYNAMIC_SECTION(client << " generic default flags") {
			RunConcurrentPositionalRead(client, false, false);
		}
		DYNAMIC_SECTION(client << " generic parallel-access flag") {
			RunConcurrentPositionalRead(client, false, true);
		}
		DYNAMIC_SECTION(client << " S3 default flags") {
			RunConcurrentPositionalRead(client, true, false);
		}
		DYNAMIC_SECTION(client << " S3 parallel-access flag") {
			RunConcurrentPositionalRead(client, true, true);
		}
	}
}

TEST_CASE("HTTP positional reads do not move the sequential cursor", "[httpfs][positional-read]") {
	RunSequentialPositionalSeparation("curl");
	RunSequentialPositionalSeparation("httplib");
}

TEST_CASE("HTTP reads select only usable ETag conditions", "[httpfs][positional-read][etag]") {
	RunETagConditionCase("\"strong\"", "\"strong\"");
	RunETagConditionCase("W/\"weak\"", "");
	RunETagConditionCase("malformed", "");
	RunETagConditionCase("", "");
	RunETagConditionCase("\"strong\"", "", true);
}

TEST_CASE("configured headers do not override positional read headers", "[httpfs][positional-read][headers]") {
	RunConfiguredReadHeaderCollision();
	RunConfiguredIfMatchCollision();
}

TEST_CASE("HTTP ETag precondition failures are terminal", "[httpfs][positional-read][etag]") {
	RunPreconditionFailure("curl");
	RunPreconditionFailure("httplib");
}

TEST_CASE("HTTP read conditions survive transport retries", "[httpfs][positional-read][retry]") {
	for (auto &client : {"curl", "httplib"}) {
		DYNAMIC_SECTION(client << " generic HTTP") {
			RunConditionSurvivesRetry(client, false);
		}
		DYNAMIC_SECTION(client << " S3") {
			RunConditionSurvivesRetry(client, true);
		}
	}
}

TEST_CASE("S3 GET responses do not change the handle's read condition", "[httpfs][positional-read][s3-version]") {
	RunImmutableS3ReadCondition("curl", false);
	RunImmutableS3ReadCondition("httplib", false);
	RunImmutableS3ReadCondition("curl", true);
	RunImmutableS3ReadCondition("httplib", true);
}

TEST_CASE("HTTP full downloads retain their read condition", "[httpfs][positional-read][full-download]") {
	RunConditionalFullDownload("curl");
	RunConditionalFullDownload("httplib");
	RunS3ThresholdFullDownload("curl");
	RunS3ThresholdFullDownload("httplib");
}

} // namespace duckdb
