#include "catch.hpp"

#include "s3/s3_test_helper.hpp"
#include "duckdb/common/file_system.hpp"
#include "duckdb/common/multi_file/multi_file_list.hpp"
#include "duckdb/common/string_util.hpp"
#include "http/httpfs.hpp"

namespace duckdb {
namespace {

static constexpr const char *LISTED_ETAG = "\"etag-one\"";
static constexpr const char *LISTED_DATA = "aaaaaaaaaa";

static MockS3ServerConfig VersionedConfig() {
	MockS3ServerConfig config;
	config.object.versions = {{"v1", {LISTED_ETAG, LISTED_DATA}}, {"v2", {"\"etag-two\"", "bbbbbbbbbbbbbbbbbbbb"}}};
	config.object.version = "v1";
	return config;
}

static void ConfigurePinningTest(DuckDB &db, Connection &con, const MockS3Server &server, const string &client,
                                 bool pinning) {
	S3TestHelper::LoadExtension(db);
	S3TestHelper::RequireQueryOk(con, "SET httpfs_client_implementation='" + client + "'");
	S3TestHelper::RequireQueryOk(con, "SET http_retries=1");
	S3TestHelper::RequireQueryOk(con, "SET http_retry_wait_ms=1");
	S3TestHelper::RequireQueryOk(con, StringUtil::Format("SET s3_version_id_pinning=%s", pinning ? "true" : "false"));
	S3TestHelper::RequireQueryOk(
	    con, StringUtil::Format("CREATE SECRET pinning_test (TYPE S3, KEY_ID 'FRESH_KEY', SECRET 'FRESH_SECRET', "
	                            "REGION 'us-east-1', ENDPOINT '%s', URL_STYLE 'path', USE_SSL false)",
	                            server.Endpoint()));
}

static OpenFileInfo ListObject(FileSystem &fs) {
	auto files = fs.Glob("s3://refresh-bucket/*.bin", FileGlobOptions::ALLOW_EMPTY, nullptr)->GetAllFiles();
	REQUIRE(files.size() == 1);
	REQUIRE(files[0].extended_info);
	return files[0];
}

static string ReadAt(Connection &con, FileHandle &handle, idx_t offset, idx_t length) {
	string data(length, '?');
	handle.Read(QueryContext(*con.context), &data[0], length, offset);
	return data;
}

static vector<MockS3RequestObservation> ObjectGets(const vector<MockS3RequestObservation> &observations) {
	vector<MockS3RequestObservation> result;
	for (const auto &observation : observations) {
		if (observation.method == "GET" && !StringUtil::Contains(observation.target, "list-type=2")) {
			result.push_back(observation);
		}
	}
	return result;
}

static void RequireNoHead(const vector<MockS3RequestObservation> &observations) {
	for (const auto &observation : observations) {
		REQUIRE(observation.method != "HEAD");
	}
}

} // namespace

TEST_CASE("S3 version pinning learns a listed file's version from its first read", "[httpfs][s3][version-pinning]") {
	for (const string client : {"curl", "httplib"}) {
		CAPTURE(client);
		MockS3Server server(VersionedConfig());
		DuckDB db(nullptr);
		Connection con(db);
		ConfigurePinningTest(db, con, server, client, true);
		S3TestHelper::RequireQueryOk(con, "BEGIN");
		auto &fs = FileSystem::GetFileSystem(*con.context);
		auto listed = ListObject(fs);
		const auto flags = FileFlags::FILE_FLAGS_READ | FileFlags::FILE_FLAGS_DIRECT_IO;
		auto handle = fs.OpenFile(listed, flags);
		REQUIRE(ReadAt(con, *handle, 0, 5) == "aaaaa");

		// Overwritten after the first read: later reads, from any handle on the listing, stay on the listed version
		server.SetObjectVersion("v2");
		REQUIRE(ReadAt(con, *handle, 5, 5) == "aaaaa");
		auto second = fs.OpenFile(listed, flags);
		REQUIRE(ReadAt(con, *second, 0, 5) == "aaaaa");
		S3TestHelper::RequireQueryOk(con, "COMMIT");

		auto observations = server.Observations();
		INFO(MockS3DescribeObservations(observations));
		RequireNoHead(observations);
		auto gets = ObjectGets(observations);
		REQUIRE(gets.size() == 3);
		REQUIRE(gets[0].if_match == LISTED_ETAG);
		REQUIRE(gets[0].version_id.empty());
		for (idx_t i = 1; i < gets.size(); i++) {
			REQUIRE(gets[i].version_id == "v1");
			REQUIRE(gets[i].if_match.empty());
			REQUIRE(gets[i].status == 206);
		}
	}
}

TEST_CASE("S3 version pinning does not learn a suspended bucket's null version", "[httpfs][s3][version-pinning]") {
	for (const string client : {"curl", "httplib"}) {
		CAPTURE(client);
		MockS3ServerConfig config;
		config.object.versions = {{"null", {LISTED_ETAG, LISTED_DATA}}};
		config.object.version = "null";
		MockS3Server server(config);
		DuckDB db(nullptr);
		Connection con(db);
		ConfigurePinningTest(db, con, server, client, true);
		S3TestHelper::RequireQueryOk(con, "BEGIN");
		auto &fs = FileSystem::GetFileSystem(*con.context);
		auto handle = fs.OpenFile(ListObject(fs), FileFlags::FILE_FLAGS_READ | FileFlags::FILE_FLAGS_DIRECT_IO);
		REQUIRE(ReadAt(con, *handle, 0, 5) == "aaaaa");
		REQUIRE(ReadAt(con, *handle, 5, 5) == "aaaaa");
		S3TestHelper::RequireQueryOk(con, "COMMIT");

		auto observations = server.Observations();
		INFO(MockS3DescribeObservations(observations));
		auto gets = ObjectGets(observations);
		REQUIRE(gets.size() == 2);
		for (const auto &get : gets) {
			REQUIRE(get.if_match == LISTED_ETAG);
			REQUIRE(get.version_id.empty());
		}
	}
}

TEST_CASE("S3 version pinning skips listed files when ETag checks are disabled", "[httpfs][s3][version-pinning]") {
	for (const string client : {"curl", "httplib"}) {
		CAPTURE(client);
		MockS3Server server(VersionedConfig());
		DuckDB db(nullptr);
		Connection con(db);
		ConfigurePinningTest(db, con, server, client, true);
		S3TestHelper::RequireQueryOk(con, "SET unsafe_disable_etag_checks=true");
		S3TestHelper::RequireQueryOk(con, "BEGIN");
		auto &fs = FileSystem::GetFileSystem(*con.context);
		auto handle = fs.OpenFile(ListObject(fs), FileFlags::FILE_FLAGS_READ | FileFlags::FILE_FLAGS_DIRECT_IO);
		REQUIRE(ReadAt(con, *handle, 0, 5) == "aaaaa");
		server.SetObjectVersion("v2");
		REQUIRE(ReadAt(con, *handle, 5, 5) == "bbbbb");
		S3TestHelper::RequireQueryOk(con, "COMMIT");

		auto observations = server.Observations();
		INFO(MockS3DescribeObservations(observations));
		auto gets = ObjectGets(observations);
		REQUIRE(gets.size() == 2);
		for (const auto &get : gets) {
			REQUIRE(get.if_match.empty());
			REQUIRE(get.version_id.empty());
		}
	}
}

TEST_CASE("S3 listed files overwritten before the first read fail", "[httpfs][s3][version-pinning]") {
	for (const string client : {"curl", "httplib"}) {
		for (const bool pinning : {false, true}) {
			CAPTURE(client, pinning);
			MockS3Server server(VersionedConfig());
			DuckDB db(nullptr);
			Connection con(db);
			ConfigurePinningTest(db, con, server, client, pinning);
			S3TestHelper::RequireQueryOk(con, "BEGIN");
			auto &fs = FileSystem::GetFileSystem(*con.context);
			auto listed = ListObject(fs);
			server.SetObjectVersion("v2");
			auto handle = fs.OpenFile(listed, FileFlags::FILE_FLAGS_READ | FileFlags::FILE_FLAGS_DIRECT_IO);
			REQUIRE_THROWS_WITH(ReadAt(con, *handle, 0, 10), Catch::Contains("changed after it was opened"));
			S3TestHelper::RequireQueryOk(con, "ROLLBACK");

			auto observations = server.Observations();
			INFO(MockS3DescribeObservations(observations));
			RequireNoHead(observations);
			auto gets = ObjectGets(observations);
			REQUIRE(gets.size() == 1);
			REQUIRE(gets[0].if_match == LISTED_ETAG);
			REQUIRE(gets[0].version_id.empty());
			REQUIRE(gets[0].status == 412);
		}
	}
}

} // namespace duckdb
