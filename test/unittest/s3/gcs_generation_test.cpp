#include "catch.hpp"

#include "s3/s3_test_helper.hpp"
#include "duckdb/common/file_system.hpp"
#include "duckdb/common/string_util.hpp"
#include "http/httpfs.hpp"
#include "duckdb/storage/external_file_cache/caching_file_system.hpp"

#include <thread>

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

TEST_CASE("GCS generation checks reject replacement between reads", "[httpfs][s3][gcs-generation]") {
	for (const string client : {"curl", "httplib"}) {
		for (const bool bearer : {false, true}) {
			for (const bool full_download : {false, true}) {
				for (const bool enforce : {false, true}) {
					CAPTURE(client, bearer, full_download, enforce);
					MockS3ServerConfig config;
					config.object.generation = "123";
					config.object.generations = {{"123", "aaaaaaaaaa"}, {"456", "bbbbbbbbbb"}};
					config.metadata.enforce_generation_match = enforce;
					config.failures.transient_get_failures = 1;
					MockS3Server server(std::move(config));
					DuckDB db(nullptr);
					Connection con(db);
					ConfigureGenerationTest(db, con, server, client, bearer);
					S3TestHelper::RequireQueryOk(con, "BEGIN");
					auto &fs = FileSystem::GetFileSystem(*con.context);
					auto handle = fs.OpenFile("gcs://refresh-bucket/object.bin",
					                          FileFlags::FILE_FLAGS_READ | FileFlags::FILE_FLAGS_DIRECT_IO);
					auto &http_handle = handle->Cast<HTTPFileHandle>();
					REQUIRE(http_handle.GetReadConfig().condition.type == HTTPReadConditionType::GCS_GENERATION_MATCH);
					REQUIRE(fs.GetVersionTag(*handle) == "gcs-generation:123");
					REQUIRE(handle->Stats().version_tag == fs.GetVersionTag(*handle));
					auto cached = fs.OpenFile("gcs://refresh-bucket/object.bin",
					                          FileFlags::FILE_FLAGS_READ | FileFlags::FILE_FLAGS_DIRECT_IO);
					REQUIRE(cached->Cast<HTTPFileHandle>().GetReadConfig().condition.value == "123");
					REQUIRE(server.Observations().size() == 1);
					string data(5, '?');
					handle->Read(QueryContext(*con.context), &data[0], 5, 0);
					REQUIRE(data == "aaaaa");
					server.SetObjectGeneration("456");
					if (full_download) {
						bool write_cache = false;
						REQUIRE_THROWS(handle->file_system.Cast<HTTPFileSystem>().FullDownload(
						    http_handle, http_handle.GetReadConfig(), write_cache));
					} else {
						data = "?????";
						REQUIRE_THROWS(handle->Read(QueryContext(*con.context), &data[0], 5, 5));
						REQUIRE(data == "?????");
					}
					REQUIRE(http_handle.GetReadConfig().condition.value == "123");
					for (auto &observation : server.Observations()) {
						REQUIRE(observation.target == "/refresh-bucket/object.bin");
						if (observation.method == "GET") {
							REQUIRE(MockS3HeaderValues(observation, "x-goog-if-generation-match") ==
							        vector<string> {"123"});
							REQUIRE(observation.if_match.empty());
							if (!bearer) {
								REQUIRE(StringUtil::Contains(observation.authorization, "x-goog-if-generation-match"));
							}
						}
					}
					// A failed read invalidates global metadata; reopening observes the replacement.
					auto reopened = fs.OpenFile("gcs://refresh-bucket/object.bin",
					                            FileFlags::FILE_FLAGS_READ | FileFlags::FILE_FLAGS_DIRECT_IO);
					REQUIRE(fs.GetVersionTag(*reopened) == "gcs-generation:456");
					S3TestHelper::RequireQueryOk(con, "COMMIT");
				}
			}
		}
	}
}

TEST_CASE("GCS automatic checks can be disabled without disabling explicit selection", "[httpfs][s3][gcs-generation]") {
	for (const string client : {"curl", "httplib"}) {
		MockS3ServerConfig config;
		config.object.generation = "123";
		config.object.generations = {{"123", "old bytes"}, {"456", "new bytes"}};
		MockS3Server server(std::move(config));
		DuckDB db(nullptr);
		Connection con(db);
		ConfigureGenerationTest(db, con, server, client, true);
		S3TestHelper::RequireQueryOk(con, "SET unsafe_disable_etag_checks=true");
		S3TestHelper::RequireQueryOk(con, "BEGIN");
		auto &fs = FileSystem::GetFileSystem(*con.context);
		auto handle =
		    fs.OpenFile("gs://refresh-bucket/object.bin", FileFlags::FILE_FLAGS_READ | FileFlags::FILE_FLAGS_DIRECT_IO);
		server.SetObjectGeneration("456");
		string data(9, '?');
		handle->Read(QueryContext(*con.context), &data[0], data.size(), 0);
		REQUIRE(data == "new bytes");
		REQUIRE(ReadObject(con, "gs://refresh-bucket/object.bin?gcs_generation=123") == "old bytes");
		for (auto &observation : server.Observations()) {
			REQUIRE(MockS3HeaderValues(observation, "x-goog-if-generation-match").empty());
		}
		S3TestHelper::RequireQueryOk(con, "COMMIT");
	}
}

TEST_CASE("GCS missing generation metadata falls back to ETags", "[httpfs][s3][gcs-generation]") {
	for (const string client : {"curl", "httplib"}) {
		MockS3ServerConfig config;
		config.metadata.enforce_if_match = true;
		MockS3Server server(std::move(config));
		DuckDB db(nullptr);
		Connection con(db);
		ConfigureGenerationTest(db, con, server, client, false);
		REQUIRE(ReadObject(con, "gcs://refresh-bucket/object.bin") == server.ObjectData());
		for (auto &observation : server.Observations()) {
			REQUIRE(MockS3HeaderValues(observation, "x-goog-if-generation-match").empty());
			if (observation.method == "GET") {
				REQUIRE(observation.if_match == "\"httpfs-refresh-test-etag\"");
			}
		}
	}
}

TEST_CASE("GCS full downloads preserve metadata when reopened without extra HEADs", "[httpfs][s3][gcs-generation]") {
	for (const string client : {"curl", "httplib"}) {
		for (const bool chunked : {false, true}) {
			for (const bool force_download : {false, true}) {
				CAPTURE(client, chunked, force_download);
				MockS3ServerConfig config;
				config.object.generation = "123";
				config.object.generations = {{"123", "old bytes"}};
				config.full_get.chunked = chunked;
				MockS3Server server(std::move(config));
				DuckDB db(nullptr);
				Connection con(db);
				ConfigureGenerationTest(db, con, server, client, false);
				S3TestHelper::RequireQueryOk(con, string("SET force_download=") + (force_download ? "true" : "false"));
				S3TestHelper::RequireQueryOk(con, "SET force_download_threshold=1024");
				S3TestHelper::RequireQueryOk(con, "BEGIN");
				auto &fs = FileSystem::GetFileSystem(*con.context);
				auto handle = fs.OpenFile("gs://refresh-bucket/object.bin", FileFlags::FILE_FLAGS_READ);
				REQUIRE(fs.GetVersionTag(*handle) == "gcs-generation:123");
				REQUIRE(handle->Stats().version_tag == fs.GetVersionTag(*handle));
				const auto request_count = force_download ? 1 : 2;
				REQUIRE(server.Observations().size() == request_count);
				REQUIRE(server.Observations().back().method == "GET");
				auto reopened = fs.OpenFile("gs://refresh-bucket/object.bin", FileFlags::FILE_FLAGS_READ);
				REQUIRE(reopened->Stats().version_tag == handle->Stats().version_tag);
				REQUIRE(reopened->GetFileSize() == handle->GetFileSize());
				string data(9, '?');
				reopened->Read(QueryContext(*con.context), &data[0], data.size(), 0);
				REQUIRE(data == "old bytes");
				REQUIRE(server.Observations().size() == request_count);
				S3TestHelper::RequireQueryOk(con, "COMMIT");
			}
		}
	}
}

TEST_CASE("GCS concurrent forced downloads publish bytes and metadata together",
          "[httpfs][s3][gcs-generation][full-download]") {
	for (const string client : {"curl", "httplib"}) {
		MockS3ServerConfig config;
		config.object.generation = "123";
		config.object.generations = {{"123", "old bytes"}};
		config.metadata.get_response_headers = {{"Cache-Control", "no-store"},
		                                        {"Last-Modified", "Tue, 08 Sep 2026 10:00:00 GMT"}};
		config.full_get.block_until_released = true;
		config.failures.transient_get_failures = 1;
		MockS3Server server(std::move(config));
		DuckDB db(nullptr);
		Connection con(db);
		ConfigureGenerationTest(db, con, server, client, false);
		S3TestHelper::RequireQueryOk(con, "SET enable_external_file_cache=false");
		S3TestHelper::RequireQueryOk(con, "SET force_download=true");
		S3TestHelper::RequireQueryOk(con, "BEGIN");
		auto &fs = FileSystem::GetFileSystem(*con.context);
		vector<unique_ptr<FileHandle>> handles(2);
		vector<string> errors(2);
		vector<std::thread> readers;
		atomic<bool> start {false};
		for (idx_t i = 0; i < handles.size(); i++) {
			readers.emplace_back([&, i]() {
				while (!start.load()) {
					std::this_thread::yield();
				}
				try {
					handles[i] = fs.OpenFile("gcs://refresh-bucket/object.bin", FileFlags::FILE_FLAGS_READ);
				} catch (const std::exception &ex) {
					errors[i] = ex.what();
				}
			});
		}
		start = true;
		auto full_get_started = server.WaitForFullGet();
		server.ReleaseFullGet();
		for (auto &reader : readers) {
			reader.join();
		}
		REQUIRE(full_get_started);
		for (idx_t i = 0; i < handles.size(); i++) {
			INFO(errors[i]);
			REQUIRE(errors[i].empty());
			REQUIRE(handles[i]);
			auto &http = handles[i]->Cast<HTTPFileHandle>();
			REQUIRE(fs.GetVersionTag(http) == "gcs-generation:123");
			REQUIRE(http.length == 9);
			REQUIRE(http.etag == "\"httpfs-refresh-test-etag\"");
			REQUIRE(http.last_modified == handles[0]->Cast<HTTPFileHandle>().last_modified);
			REQUIRE(http.GetCacheValidUntil());
			REQUIRE(*http.GetCacheValidUntil() == timestamp_t::ninfinity());
			string data(9, '?');
			http.Read(QueryContext(*con.context), &data[0], data.size(), 0);
			REQUIRE(data == "old bytes");
		}
		const auto observations = server.Observations();
		REQUIRE(observations.size() == 2);
		REQUIRE(observations[0].status == 400);
		REQUIRE(observations[1].status == 200);
		for (auto &observation : observations) {
			REQUIRE(observation.method == "GET");
		}
		S3TestHelper::RequireQueryOk(con, "COMMIT");
	}
}

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

TEST_CASE("GCS generation selection and checks survive credential refresh", "[httpfs][s3][gcs-generation]") {
	for (const string client : {"curl", "httplib"}) {
		for (const bool explicit_selection : {false, true}) {
			for (const auto target :
			     {MockS3RefreshTarget::HEAD, MockS3RefreshTarget::RANGE_GET, MockS3RefreshTarget::FULL_GET}) {
				CAPTURE(client, target, explicit_selection);
				MockS3ServerConfig config;
				config.auth.refresh_target = target;
				config.object.generation = "123";
				config.object.generations = {{"123", "historical object"}};
				MockS3Server server(std::move(config));
				DuckDB db(nullptr);
				Connection con(db);
				ConfigureGenerationTest(db, con, server, client, false);
				S3TestHelper::RegisterRefreshProvider(db);
				S3TestHelper::RequireQueryOk(con, "SET s3_use_ssl=false");
				const auto test_id = S3TestHelper::NextTestId();
				S3TestHelper::RequireQueryOk(con, StringUtil::Format(R"(
CREATE OR REPLACE SECRET generation_test (
    TYPE GCS, PROVIDER httpfs_refresh_test, KEY_ID 'STALE_KEY', SECRET 'STALE_SECRET', TEST_ID '%s',
    ENDPOINT '%s', URL_STYLE 'path', USE_SSL false,
    REFRESH_INFO MAP {'KEY_ID': 'FRESH_KEY', 'SECRET': 'FRESH_SECRET', 'TEST_ID': '%s',
                      'ENDPOINT': '%s', 'URL_STYLE': 'path'}
))",
				                                                     test_id, server.Endpoint(), test_id,
				                                                     server.Endpoint()));
				S3TestHelper::RequireQueryOk(con, string("SET force_download=") +
				                                      (target == MockS3RefreshTarget::FULL_GET ? "true" : "false"));
				S3TestHelper::RequireQueryOk(con, "BEGIN");
				auto &fs = FileSystem::GetFileSystem(*con.context);
				const string selector = explicit_selection ? "?gcs_generation=123" : "";
				auto handle = fs.OpenFile("gcs://refresh-bucket/object.bin" + selector,
				                          FileFlags::FILE_FLAGS_READ | FileFlags::FILE_FLAGS_DIRECT_IO);
				string data(10, '?');
				handle->Read(QueryContext(*con.context), &data[0], data.size(), 0);
				REQUIRE(data == "historical");
				S3TestHelper::AssertSingleRefresh(test_id);
				for (auto &observation : server.Observations()) {
					REQUIRE(observation.target ==
					        string("/refresh-bucket/object.bin") + (explicit_selection ? "?generation=123" : ""));
					const bool conditional =
					    !explicit_selection && target != MockS3RefreshTarget::FULL_GET && observation.method == "GET";
					REQUIRE(MockS3HeaderValues(observation, "x-goog-if-generation-match") ==
					        (conditional ? vector<string> {"123"} : vector<string>()));
				}
				S3TestHelper::RequireQueryOk(con, "COMMIT");
			}
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

TEST_CASE("GCS generation metadata rejects malformed and conflicting responses", "[httpfs][s3][gcs-generation]") {
	for (const string client : {"curl", "httplib"}) {
		for (const string invalid : {"", "0", "-1", "1.0", "abc", "18446744073709551616", "123,456"}) {
			CAPTURE(client, invalid);
			MockS3ServerConfig config;
			config.metadata.response_headers = {{"x-goog-generation", invalid}};
			MockS3Server server(std::move(config));
			DuckDB db(nullptr);
			Connection con(db);
			ConfigureGenerationTest(db, con, server, client, false);
			auto result = con.Query("SELECT * FROM read_blob('gcs://refresh-bucket/object.bin')");
			REQUIRE(result->HasError());
			REQUIRE(StringUtil::Contains(result->GetError(), "positive uint64 decimal"));
		}
		for (const bool conflicting : {false, true}) {
			MockS3ServerConfig config;
			config.metadata.response_headers = {{"x-goog-generation", "123"},
			                                    {"x-goog-generation", conflicting ? "456" : "123"}};
			config.metadata.get_response_headers = {{"x-goog-generation", "123"}};
			config.metadata.enforce_generation_match = false;
			MockS3Server server(std::move(config));
			DuckDB db(nullptr);
			Connection con(db);
			ConfigureGenerationTest(db, con, server, client, false);
			auto result = con.Query("SELECT * FROM read_blob('gcs://refresh-bucket/object.bin')");
			INFO((result->HasError() ? result->GetError() : ""));
			REQUIRE(result->HasError() == conflicting);
		}
	}
}

TEST_CASE("GCS invalid GET generation metadata fails before publishing data", "[httpfs][s3][gcs-generation]") {
	for (const string client : {"curl", "httplib"}) {
		for (const string value : {"invalid", "456"}) {
			for (const bool full_download : {false, true}) {
				CAPTURE(client, value, full_download);
				MockS3ServerConfig config;
				config.object.generation = "123";
				config.object.generations = {{"123", "old bytes"}, {"456", "new bytes"}};
				config.metadata.get_response_headers = {{"x-goog-generation", value}};
				MockS3Server server(std::move(config));
				DuckDB db(nullptr);
				Connection con(db);
				ConfigureGenerationTest(db, con, server, client, false);
				S3TestHelper::RequireQueryOk(con, "BEGIN");
				auto &fs = FileSystem::GetFileSystem(*con.context);
				auto handle = fs.OpenFile("gcs://refresh-bucket/object.bin",
				                          FileFlags::FILE_FLAGS_READ | FileFlags::FILE_FLAGS_DIRECT_IO);
				if (full_download) {
					bool write_cache = false;
					auto &http = handle->Cast<HTTPFileHandle>();
					REQUIRE_THROWS(handle->file_system.Cast<HTTPFileSystem>().FullDownload(http, http.GetReadConfig(),
					                                                                       write_cache));
				} else {
					string data(9, '?');
					REQUIRE_THROWS(handle->Read(QueryContext(*con.context), &data[0], data.size(), 0));
					REQUIRE(data == string(9, '?'));
				}
				server.SetObjectGeneration("456");
				auto reopened = fs.OpenFile("gcs://refresh-bucket/object.bin",
				                            FileFlags::FILE_FLAGS_READ | FileFlags::FILE_FLAGS_DIRECT_IO);
				REQUIRE(fs.GetVersionTag(*reopened) == "gcs-generation:456");
				S3TestHelper::RequireQueryOk(con, "COMMIT");
			}
		}
	}
}

TEST_CASE("GCS generation metadata roundtrips through extended file information", "[httpfs][s3][gcs-generation]") {
	MockS3ServerConfig config;
	config.object.generation = "123";
	config.object.generations = {{"123", "old bytes"}};
	MockS3Server server(std::move(config));
	DuckDB db(nullptr);
	Connection con(db);
	ConfigureGenerationTest(db, con, server, "curl", true);
	S3TestHelper::RequireQueryOk(con, "BEGIN");
	auto &fs = FileSystem::GetFileSystem(*con.context);
	auto initial =
	    fs.OpenFile("gcs://refresh-bucket/object.bin", FileFlags::FILE_FLAGS_READ | FileFlags::FILE_FLAGS_DIRECT_IO);
	auto &http = initial->Cast<HTTPFileHandle>();
	OpenFileInfo info("gcs://refresh-bucket/object.bin?s3_region=auto");
	info.extended_info = make_shared_ptr<ExtendedOpenFileInfo>();
	info.extended_info->options["last_modified"] = Value::TIMESTAMP(http.last_modified);
	info.extended_info->options["file_size"] = Value::UBIGINT(http.length);
	info.extended_info->options["etag"] = http.etag;
	info.extended_info->options["gcs_generation"] = http.GetObjectVersion().GetValue();
	auto restored = fs.OpenFile(info, FileFlags::FILE_FLAGS_READ | FileFlags::FILE_FLAGS_DIRECT_IO);
	REQUIRE(restored->Cast<HTTPFileHandle>().GetReadConfig().condition.value == "123");
	REQUIRE(restored->Stats().version_tag == initial->Stats().version_tag);
	REQUIRE(server.Observations().size() == 1);
	string data(9, '?');
	restored->Read(QueryContext(*con.context), &data[0], data.size(), 0);
	REQUIRE(data == "old bytes");
	S3TestHelper::RequireQueryOk(con, "COMMIT");
}

TEST_CASE("GCS cached metadata remains stable during full downloads", "[httpfs][s3][gcs-generation]") {
	for (const string client : {"curl", "httplib"}) {
		MockS3ServerConfig config;
		config.metadata.response_headers = {{"x-goog-generation", "123"}};
		config.metadata.enforce_generation_match = false;
		MockS3Server server(std::move(config));
		DuckDB db(nullptr);
		Connection con(db);
		ConfigureGenerationTest(db, con, server, client, false);
		S3TestHelper::RequireQueryOk(con, "BEGIN");
		auto &fs = FileSystem::GetFileSystem(*con.context);
		auto initial = fs.OpenFile("gcs://refresh-bucket/object.bin",
		                           FileFlags::FILE_FLAGS_READ | FileFlags::FILE_FLAGS_DIRECT_IO);
		auto cached = fs.OpenFile("gcs://refresh-bucket/object.bin",
		                          FileFlags::FILE_FLAGS_READ | FileFlags::FILE_FLAGS_DIRECT_IO);
		REQUIRE(server.Observations().size() == 1);
		REQUIRE(fs.GetVersionTag(*cached) == "gcs-generation:123");
		auto &http = cached->Cast<HTTPFileHandle>();
		bool write_cache = false;
		cached->file_system.Cast<HTTPFileSystem>().FullDownload(http, http.GetReadConfig(), write_cache);
		string data(5, '?');
		cached->Read(QueryContext(*con.context), &data[0], data.size(), 0);
		REQUIRE(data == server.ObjectData().substr(0, data.size()));
		REQUIRE(fs.GetVersionTag(*cached) == "gcs-generation:123");
		REQUIRE(cached->Stats().version_tag == fs.GetVersionTag(*cached));
		REQUIRE(cached->Cast<HTTPFileHandle>().GetReadConfig().condition.value == "123");
		bool saw_full_get = false;
		for (auto &observation : server.Observations()) {
			if (observation.method == "GET") {
				saw_full_get |= observation.range.empty();
				REQUIRE(MockS3HeaderValues(observation, "x-goog-if-generation-match") == vector<string> {"123"});
			}
		}
		REQUIRE(saw_full_get);
		S3TestHelper::RequireQueryOk(con, "COMMIT");
	}
}

TEST_CASE("GCS cached full downloads cannot bypass another handle's generation check",
          "[httpfs][s3][gcs-generation][full-download]") {
	for (const string client : {"curl", "httplib"}) {
		for (const bool unsafe : {false, true}) {
			CAPTURE(client, unsafe);
			MockS3ServerConfig config;
			config.object.generation = "123";
			config.object.generations = {{"123", "aaaaaaaaaa"}, {"456", "bbbbbbbbbb"}};
			config.metadata.response_headers = {{"Cache-Control", "no-store"}};
			MockS3Server server(std::move(config));
			DuckDB db(nullptr);
			Connection con(db);
			ConfigureGenerationTest(db, con, server, client, false);
			S3TestHelper::RequireQueryOk(con, "SET enable_http_metadata_cache=false");
			S3TestHelper::RequireQueryOk(con, "SET enable_external_file_cache=false");
			S3TestHelper::RequireQueryOk(con, "SET force_download_threshold=0");
			S3TestHelper::RequireQueryOk(con, string("SET unsafe_disable_etag_checks=") + (unsafe ? "true" : "false"));
			S3TestHelper::RequireQueryOk(con, "BEGIN");
			auto &fs = FileSystem::GetFileSystem(*con.context);
			const auto flags = FileFlags::FILE_FLAGS_READ | FileFlags::FILE_FLAGS_DIRECT_IO;
			auto old_handle = fs.OpenFile("gcs://refresh-bucket/object.bin", flags);
			string data(5, '?');
			old_handle->Read(QueryContext(*con.context), &data[0], data.size(), 0);
			REQUIRE(data == "aaaaa");
			server.SetObjectGeneration("456");
			auto new_handle = fs.OpenFile("gcs://refresh-bucket/object.bin", flags);
			REQUIRE(fs.GetVersionTag(*new_handle) == "gcs-generation:456");
			auto &new_http = new_handle->Cast<HTTPFileHandle>();
			bool write_cache = false;
			new_handle->file_system.Cast<HTTPFileSystem>().FullDownload(new_http, new_http.GetReadConfig(),
			                                                            write_cache);
			const auto request_count = server.Observations().size();
			auto &old_http = old_handle->Cast<HTTPFileHandle>();
			auto reuse_download = [&]() {
				return old_handle->file_system.Cast<HTTPFileSystem>().FullDownload(old_http, old_http.GetReadConfig(),
				                                                                   write_cache);
			};
			data.assign(5, '?');
			if (unsafe) {
				old_handle->Read(QueryContext(*con.context), &data[0], data.size(), 5);
				REQUIRE(data == "bbbbb");
				REQUIRE(reuse_download()->GetMetadata().object_version.GetValue() == "456");
			} else {
				REQUIRE_THROWS_WITH(old_handle->Read(QueryContext(*con.context), &data[0], data.size(), 5),
				                    Catch::Contains("do not match the version"));
				REQUIRE(data == "?????");
				REQUIRE_THROWS_WITH(reuse_download(), Catch::Contains("do not match the version"));
			}
			REQUIRE(fs.GetVersionTag(*old_handle) == "gcs-generation:123");
			new_handle->Read(QueryContext(*con.context), &data[0], data.size(), 5);
			REQUIRE(data == "bbbbb");
			REQUIRE(server.Observations().size() == request_count);
			S3TestHelper::RequireQueryOk(con, "COMMIT");
		}
	}
}

TEST_CASE("GCS unsafe full downloads publish response metadata without changing the handle",
          "[httpfs][s3][gcs-generation][full-download]") {
	for (const string client : {"curl", "httplib"}) {
		MockS3ServerConfig config;
		config.object.generation = "123";
		config.object.generations = {{"123", "old bytes"}, {"456", "new bytes"}};
		config.metadata.response_headers = {{"Cache-Control", "no-store"}};
		MockS3Server server(std::move(config));
		DuckDB db(nullptr);
		Connection con(db);
		ConfigureGenerationTest(db, con, server, client, false);
		S3TestHelper::RequireQueryOk(con, "SET enable_http_metadata_cache=false");
		S3TestHelper::RequireQueryOk(con, "SET enable_external_file_cache=false");
		S3TestHelper::RequireQueryOk(con, "SET unsafe_disable_etag_checks=true");
		S3TestHelper::RequireQueryOk(con, "BEGIN");
		auto &fs = FileSystem::GetFileSystem(*con.context);
		auto handle = fs.OpenFile("gcs://refresh-bucket/object.bin",
		                          FileFlags::FILE_FLAGS_READ | FileFlags::FILE_FLAGS_DIRECT_IO);
		REQUIRE(fs.GetVersionTag(*handle) == "gcs-generation:123");
		server.SetObjectGeneration("456");
		auto &http = handle->Cast<HTTPFileHandle>();
		bool write_cache = false;
		auto cached = handle->file_system.Cast<HTTPFileSystem>().FullDownload(http, http.GetReadConfig(), write_cache);
		REQUIRE(string(cached->GetData(), cached->GetSize()) == "new bytes");
		REQUIRE(cached->GetMetadata().object_version.GetValue() == "456");
		REQUIRE(fs.GetVersionTag(*handle) == "gcs-generation:123");
		auto reopened = fs.OpenFile("gcs://refresh-bucket/object.bin", FileFlags::FILE_FLAGS_READ);
		REQUIRE(fs.GetVersionTag(*reopened) == "gcs-generation:456");
		REQUIRE(server.Observations().size() == 2);
		S3TestHelper::RequireQueryOk(con, "COMMIT");
	}
}

TEST_CASE("GCS external data cache distinguishes generations with the same ETag and size",
          "[httpfs][s3][gcs-generation]") {
	for (const string client : {"curl", "httplib"}) {
		MockS3ServerConfig config;
		config.object.generation = "123";
		config.object.generations = {{"123", string(4 * 1024 * 1024, 'a')}, {"456", string(4 * 1024 * 1024, 'b')}};
		MockS3Server server(std::move(config));
		DuckDB db(nullptr);
		Connection con(db);
		ConfigureGenerationTest(db, con, server, client, false);
		S3TestHelper::RequireQueryOk(con, "SET enable_http_metadata_cache=false");
		for (const string generation : {"123", "123", "456"}) {
			server.SetObjectGeneration(generation);
			S3TestHelper::RequireQueryOk(con, "BEGIN");
			{
				auto fs = CachingFileSystem::Get(*con.context);
				auto handle = fs.OpenFile(OpenFileInfo("gcs://refresh-bucket/object.bin"), FileFlags::FILE_FLAGS_READ);
				string data(16, '?');
				auto buffer = handle->Read(16, 0);
				buffer.CopyTo(data_ptr_cast(&data[0]), data.size());
				REQUIRE(data == string(16, generation == "123" ? 'a' : 'b'));
				REQUIRE(handle->GetVersionTag() == "gcs-generation:" + generation);
			}
			S3TestHelper::RequireQueryOk(con, "COMMIT");
		}
		idx_t get_count = 0;
		for (auto &observation : server.Observations()) {
			if (observation.method == "GET") {
				get_count++;
				REQUIRE(observation.range != "bytes=0-4194303");
			}
		}
		REQUIRE(get_count == 2);
	}
}

} // namespace duckdb
