#include "catch.hpp"

#include "s3/s3_test_helper.hpp"
#include "duckdb/common/file_system.hpp"
#include "duckdb/common/string_util.hpp"

namespace duckdb {
namespace {

static void ConfigureGenerationTest(DuckDB &db, Connection &con, const MockS3Server &server, const string &client,
                                    bool bearer) {
	S3TestHelper::LoadExtension(db);
	S3TestHelper::RequireQueryOk(con, "SET httpfs_client_implementation='" + client + "'");
	S3TestHelper::RequireQueryOk(con, "SET http_retries=1");
	S3TestHelper::RequireQueryOk(con, "SET http_retry_wait_ms=1");
	S3TestHelper::RequireQueryOk(con, "SET http_retry_backoff=1");
	S3TestHelper::RequireQueryOk(con, "SET enable_http_metadata_cache=true");
	S3TestHelper::RequireQueryOk(con, "SET enable_external_file_cache=true");
	S3TestHelper::RequireQueryOk(
	    con, StringUtil::Format(
	             "CREATE SECRET generation_test (TYPE GCS, %s, ENDPOINT '%s', URL_STYLE 'path', USE_SSL false)",
	             bearer ? "BEARER_TOKEN 'generation-token'" : "KEY_ID 'GENERATION_KEY', SECRET 'generation-secret'",
	             server.Endpoint()));
}

static string ReadObject(Connection &con, const string &path) {
	auto result = con.Query("SELECT content::VARCHAR FROM read_blob('" + path + "')");
	REQUIRE(result);
	INFO((result->HasError() ? result->GetError() : ""));
	REQUIRE_FALSE(result->HasError());
	return result->GetValue(0, 0).ToString();
}

} // namespace

TEST_CASE("GCS explicit generations select historical objects on every read", "[httpfs][s3][gcs-generation]") {
	for (const string client : {"curl", "httplib"}) {
		for (const bool bearer : {false, true}) {
			for (const string scheme : {"gs", "gcs"}) {
				for (const bool full_download : {false, true}) {
					CAPTURE(client, bearer, scheme, full_download);
					MockS3ServerConfig config;
					config.object.generations = {{"123", "historical object"}, {"456", "another generation"}};
					config.failures.transient_get_failures = 1;
					MockS3Server server(std::move(config));
					DuckDB db(nullptr);
					Connection con(db);
					ConfigureGenerationTest(db, con, server, client, bearer);
					S3TestHelper::RequireQueryOk(con,
					                             string("SET force_download=") + (full_download ? "true" : "false"));
					S3TestHelper::RequireQueryOk(con, "BEGIN");
					const auto path = scheme + "://refresh-bucket/object.bin?gcs_generation=123";
					for (const bool unsafe : {false, true}) {
						CAPTURE(unsafe);
						S3TestHelper::RequireQueryOk(con, string("SET unsafe_disable_etag_checks=") +
						                                      (unsafe ? "true" : "false"));
						auto &fs = FileSystem::GetFileSystem(*con.context);
						auto handle = fs.OpenFile(path, full_download ? FileFlags::FILE_FLAGS_READ
						                                              : FileFlags::FILE_FLAGS_READ |
						                                                    FileFlags::FILE_FLAGS_DIRECT_IO);
						REQUIRE(handle->GetFileSize() == 17);
						string data(10, '?');
						handle->Read(QueryContext(*con.context), &data[0], 5, 0);
						handle->Read(QueryContext(*con.context), &data[5], 5, 5);
						REQUIRE(data == "historical");
					}
					auto observations = server.Observations();
					INFO(MockS3DescribeObservations(observations));
					REQUIRE(observations.size() >= 2);
					bool saw_retry = false;
					bool saw_head = false;
					for (auto &observation : observations) {
						REQUIRE(observation.target == "/refresh-bucket/object.bin?generation=123");
						REQUIRE(observation.if_match.empty());
						REQUIRE(observation.version_id.empty());
						if (bearer) {
							REQUIRE(observation.authorization == "Bearer generation-token");
						} else {
							REQUIRE(observation.key_id == "GENERATION_KEY");
						}
						saw_retry |= observation.status == 400;
						saw_head |= observation.method == "HEAD";
					}
					REQUIRE(saw_retry);
					REQUIRE(saw_head == !full_download);
					// Reopen both versions and the live object through the metadata and external-file caches.
					for (idx_t i = 0; i < 2; i++) {
						REQUIRE(ReadObject(con, path) == "historical object");
						REQUIRE(ReadObject(con, scheme + "://refresh-bucket/object.bin?gcs_generation=456") ==
						        "another generation");
						REQUIRE(ReadObject(con, scheme + "://refresh-bucket/object.bin") == server.ObjectData());
					}
					S3TestHelper::RequireQueryOk(con, "COMMIT");
				}
			}
		}
	}
}

TEST_CASE("GCS generation selection survives credential refresh", "[httpfs][s3][gcs-generation]") {
	for (const string client : {"curl", "httplib"}) {
		for (const auto target :
		     {MockS3RefreshTarget::HEAD, MockS3RefreshTarget::RANGE_GET, MockS3RefreshTarget::FULL_GET}) {
			CAPTURE(client, target);
			MockS3ServerConfig config;
			config.auth.refresh_target = target;
			config.object.generations = {{"123", "historical object"}};
			MockS3Server server(std::move(config));
			DuckDB db(nullptr);
			Connection con(db);
			ConfigureGenerationTest(db, con, server, client, false);
			S3TestHelper::RegisterRefreshProvider(db);
			S3TestHelper::RequireQueryOk(con, "SET s3_use_ssl=false");
			const auto test_id = S3TestHelper::NextTestId();
			S3TestHelper::RequireQueryOk(con,
			                             StringUtil::Format(R"(
CREATE OR REPLACE SECRET generation_test (
    TYPE GCS, PROVIDER httpfs_refresh_test, KEY_ID 'STALE_KEY', SECRET 'STALE_SECRET', TEST_ID '%s',
    ENDPOINT '%s', URL_STYLE 'path', USE_SSL false,
    REFRESH_INFO MAP {'KEY_ID': 'FRESH_KEY', 'SECRET': 'FRESH_SECRET', 'TEST_ID': '%s',
                      'ENDPOINT': '%s', 'URL_STYLE': 'path'}
))",
			                                                test_id, server.Endpoint(), test_id, server.Endpoint()));
			S3TestHelper::RequireQueryOk(con, string("SET force_download=") +
			                                      (target == MockS3RefreshTarget::FULL_GET ? "true" : "false"));
			S3TestHelper::RequireQueryOk(con, "BEGIN");
			auto &fs = FileSystem::GetFileSystem(*con.context);
			auto handle = fs.OpenFile("gcs://refresh-bucket/object.bin?gcs_generation=123",
			                          FileFlags::FILE_FLAGS_READ | FileFlags::FILE_FLAGS_DIRECT_IO);
			string data(10, '?');
			handle->Read(QueryContext(*con.context), &data[0], data.size(), 0);
			REQUIRE(data == "historical");
			S3TestHelper::AssertSingleRefresh(test_id);
			for (auto &observation : server.Observations()) {
				REQUIRE(observation.target == "/refresh-bucket/object.bin?generation=123");
			}
			S3TestHelper::RequireQueryOk(con, "COMMIT");
		}
	}
}

TEST_CASE("GCS generation deletes are rejected before dispatch", "[httpfs][s3][gcs-generation]") {
	MockS3Server server {MockS3ServerConfig()};
	DuckDB db(nullptr);
	Connection con(db);
	ConfigureGenerationTest(db, con, server, "curl", false);
	S3TestHelper::RequireQueryOk(con, "BEGIN");
	auto &fs = FileSystem::GetFileSystem(*con.context);
	const string path = "gcs://refresh-bucket/object.bin?gcs_generation=123";
	REQUIRE_THROWS_WITH(fs.RemoveFile(path), Catch::Contains("gcs_generation is only supported for reading"));
	REQUIRE_THROWS_WITH(fs.RemoveFiles({"gcs://refresh-bucket/other.bin", path}),
	                    Catch::Contains("gcs_generation is only supported for reading"));
	REQUIRE(server.Observations().empty());
	S3TestHelper::RequireQueryOk(con, "COMMIT");
}

} // namespace duckdb
