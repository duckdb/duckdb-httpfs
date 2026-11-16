#include "catch.hpp"
#include "duckdb.hpp"
#include "duckdb/common/file_system.hpp"
#include "duckdb/common/multi_file/multi_file_list.hpp"
#include "duckdb/common/string_util.hpp"
#include "mock_s3_server.hpp"
#include "s3_test_helper.hpp"

using namespace duckdb;

namespace {

struct SignHttpUrlsFixture {
	SignHttpUrlsFixture() : server(MakeConfig()), db(nullptr), con(db) {
		S3TestHelper::LoadExtension(db);
		S3TestHelper::RequireQueryOk(con, "SET httpfs_connection_caching=false");
		S3TestHelper::RequireQueryOk(con, "SET enable_global_s3_configuration=false");
	}

	static MockS3ServerConfig MakeConfig() {
		MockS3ServerConfig config;
		config.auth.stale_key_id = "NEVER_STALE";
		config.list.paginate = true;
		return config;
	}

	string HttpObjectUrl() const {
		return "http://" + server.Endpoint() + "/" + S3TestHelper::BUCKET + "/" + S3TestHelper::OBJECT_KEY;
	}

	void CreateSecret(const string &name, const string &extra_options) {
		S3TestHelper::RequireQueryOk(con,
		                             StringUtil::Format(R"(
CREATE SECRET %s (
	TYPE S3,
	SCOPE 'http://%s/',
	KEY_ID '%s',
	SECRET '%s',
	REGION 'us-east-1',
	ENDPOINT '%s',
	USE_SSL false,
	URL_STYLE 'path'%s
))",
		                                                name, server.Endpoint(), S3TestHelper::FRESH_KEY_ID,
		                                                S3TestHelper::FRESH_SECRET, server.Endpoint(), extra_options));
	}

	string ReadFirstByte(const string &url) {
		auto &fs = FileSystem::GetFileSystem(*con.context);
		auto handle = fs.OpenFile(url, FileFlags::FILE_FLAGS_READ | FileFlags::FILE_FLAGS_DIRECT_IO);
		char result;
		handle->Read(QueryContext(*con.context), &result, 1, 0);
		return string(1, result);
	}

	MockS3Server server;
	DuckDB db;
	Connection con;
};

} // namespace

TEST_CASE("An http url inside an S3 secret's scope is plain http unless the secret opted in", "[s3][sign_http_urls]") {
	SignHttpUrlsFixture f;
	// the scope covers the url, but without SIGN_HTTP_URLS the secret does not apply to it: the request is the HTTP
	// file system's, and carries no signature
	f.CreateSecret("plain", "");
	S3TestHelper::RequireQueryOk(f.con, "BEGIN TRANSACTION");
	REQUIRE(f.ReadFirstByte(f.HttpObjectUrl()) == f.server.ObjectData().substr(0, 1));
	S3TestHelper::RequireQueryOk(f.con, "COMMIT");
	auto observations = f.server.Observations();
	INFO(MockS3DescribeObservations(observations));
	REQUIRE(!observations.empty());
	for (auto &observation : observations) {
		REQUIRE(observation.authorization.empty());
	}
}

TEST_CASE("An http url inside an opted-in S3 secret's scope is signed as an S3 request", "[s3][sign_http_urls]") {
	SignHttpUrlsFixture f;
	f.CreateSecret("signed", ",\n\tSIGN_HTTP_URLS true");

	S3TestHelper::RequireQueryOk(f.con, "BEGIN TRANSACTION");
	REQUIRE(f.ReadFirstByte(f.HttpObjectUrl()) == f.server.ObjectData().substr(0, 1));
	// a glob lists the bucket through the same signed path
	auto &fs = FileSystem::GetFileSystem(*f.con.context);
	auto glob = fs.Glob("http://" + f.server.Endpoint() + "/" + S3TestHelper::BUCKET + "/*.bin",
	                    FileGlobOptions::ALLOW_EMPTY, nullptr);
	REQUIRE(glob->GetAllFiles().size() == 2);
	S3TestHelper::RequireQueryOk(f.con, "COMMIT");

	auto observations = f.server.Observations();
	INFO(MockS3DescribeObservations(observations));
	REQUIRE(!observations.empty());
	bool saw_get = false;
	bool saw_list = false;
	for (auto &observation : observations) {
		// the host is the one in the url, the path is bucket and key, and the request is signed with the secret's key
		REQUIRE(MockS3HeaderValues(observation, "Host") == vector<string> {f.server.Endpoint()});
		REQUIRE(StringUtil::StartsWith(observation.path, string("/") + S3TestHelper::BUCKET));
		REQUIRE(StringUtil::Contains(observation.authorization, "Credential=" + string(S3TestHelper::FRESH_KEY_ID)));
		REQUIRE(StringUtil::Contains(observation.authorization, "SignedHeaders="));
		saw_get |= observation.method == "GET" && !StringUtil::Contains(observation.target, "list-type=2");
		saw_list |= observation.method == "GET" && StringUtil::Contains(observation.target, "list-type=2");
	}
	REQUIRE(saw_get);
	REQUIRE(saw_list);
}

TEST_CASE("An opted-in secret only signs urls on its endpoint or a bucket below it", "[s3][sign_http_urls]") {
	SignHttpUrlsFixture f;
	// a scope wide enough to cover another host: the url is routed to S3, which refuses to sign for a host it cannot
	// read a bucket off
	S3TestHelper::RequireQueryOk(f.con, StringUtil::Format(R"(
CREATE SECRET wide (
	TYPE S3,
	SCOPE 'http://',
	KEY_ID '%s',
	SECRET '%s',
	REGION 'us-east-1',
	ENDPOINT '%s',
	USE_SSL false,
	URL_STYLE 'path',
	SIGN_HTTP_URLS true
))",
	                                                       S3TestHelper::FRESH_KEY_ID, S3TestHelper::FRESH_SECRET,
	                                                       f.server.Endpoint()));
	S3TestHelper::RequireQueryOk(f.con, "BEGIN TRANSACTION");
	string error;
	try {
		f.ReadFirstByte("http://other.example/bucket/key");
	} catch (std::exception &ex) {
		error = ex.what();
	}
	S3TestHelper::RequireQueryOk(f.con, "ROLLBACK");
	INFO(error);
	REQUIRE(StringUtil::Contains(error, "neither the endpoint of the secret that covers it"));
	REQUIRE(f.server.Observations().empty());
}
