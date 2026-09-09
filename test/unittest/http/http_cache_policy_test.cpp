#include "catch.hpp"

#include "http/http_test_helper.hpp"
#include "http/httpfs.hpp"

namespace duckdb {

TEST_CASE("HTTP cache policy preserves repeated response headers", "[httpfs][cache]") {
	for (const auto &client : {"curl", "httplib"}) {
		INFO(client);
		MockS3ServerConfig config;
		config.metadata.response_headers = {{"Cache-Control", "max-age=3600"}, {"Cache-Control", "no-cache"}};
		MockS3Server server(std::move(config));
		DuckDB db(nullptr);
		Connection con(db);
		HTTPTestHelper::Configure(db, con, 0, client);
		HTTPTestHelper::RequireQueryOk(con, "BEGIN TRANSACTION");
		auto &fs = FileSystem::GetFileSystem(*con.context);
		auto handle = fs.OpenFile(server.HTTPPath(), FileFlags::FILE_FLAGS_READ | FileFlags::FILE_FLAGS_DIRECT_IO);
		auto deadline = handle->Cast<HTTPFileHandle>().GetCacheValidUntil();
		REQUIRE(deadline);
		REQUIRE(*deadline == timestamp_t::ninfinity());
		REQUIRE_FALSE(handle->Cast<HTTPFileHandle>().CanReuseCachedData());
		handle.reset();
		handle = fs.OpenFile(server.HTTPPath(), FileFlags::FILE_FLAGS_READ | FileFlags::FILE_FLAGS_DIRECT_IO);
		REQUIRE(HTTPTestHelper::CountRequests(server.Observations(), "HEAD", 200) == 2);
		handle.reset();
		HTTPTestHelper::RequireQueryOk(con, "ROLLBACK");
	}
}

TEST_CASE("HTTP metadata cache lifetime is controlled by its setting", "[httpfs][cache]") {
	HTTPMetadataCacheEntry entry;
	entry.length = 42;
	entry.cache_valid_until = timestamp_t::ninfinity();
	for (const auto mode : {HTTPMetadataCacheMode::QUERY_LOCAL, HTTPMetadataCacheMode::GLOBAL}) {
		HTTPMetadataCache cache(mode);
		cache.Insert("expired", entry);
		HTTPMetadataCacheEntry result;
		const auto &lookup = cache;
		REQUIRE(lookup.Find("expired", result) == (mode == HTTPMetadataCacheMode::GLOBAL));
		entry.cache_valid_until = timestamp_t::infinity();
		cache.Insert("fresh", entry);
		REQUIRE(lookup.Find("fresh", result));
		REQUIRE(result.length == 42);
		entry.cache_valid_until = timestamp_t::ninfinity();
	}
}

TEST_CASE("Explicit cache settings preserve legacy reuse", "[httpfs][cache]") {
	MockS3ServerConfig config;
	config.metadata.response_headers = {{"Cache-Control", "no-store, max-age=0"}, {"Vary", "Origin"}};
	MockS3Server server(std::move(config));
	DuckDB db(nullptr);
	Connection con(db);
	HTTPTestHelper::Configure(db, con, 0);
	HTTPTestHelper::RequireQueryOk(con, "SET enable_http_metadata_cache=true");
	HTTPTestHelper::RequireQueryOk(con, "SET enable_external_file_cache=true");

	for (idx_t i = 0; i < 2; i++) {
		auto result = con.Query("SELECT content FROM read_blob('" + server.HTTPPath() + "')");
		REQUIRE_FALSE(result->HasError());
		REQUIRE(result->GetValue(0, 0).GetValue<string>() == server.ObjectData());
	}
	auto observations = server.Observations();
	REQUIRE(HTTPTestHelper::CountRequests(observations, "HEAD", 200) == 1);
	REQUIRE(HTTPTestHelper::CountRangeRequests(observations, 206) == 1);
}

TEST_CASE("HTTP cache validation follows file options and session settings", "[httpfs][cache]") {
	MockS3ServerConfig config;
	config.metadata.response_headers = {{"Cache-Control", "no-store, max-age=0"}, {"Vary", "*"}};
	MockS3Server server(std::move(config));
	DuckDB db(nullptr);
	Connection con(db);
	HTTPTestHelper::Configure(db, con, 0);
	HTTPTestHelper::RequireQueryOk(con, "BEGIN TRANSACTION");
	auto &fs = FileSystem::GetFileSystem(*con.context);
	OpenFileInfo file(server.HTTPPath());
	file.extended_info = make_shared_ptr<ExtendedOpenFileInfo>();
	bool can_reuse = true;
	bool invalid_option = false;
	SECTION("per-file validation is disabled") {
		file.extended_info->options["validate_external_file_cache"] = Value::BOOLEAN(false);
	}
	SECTION("session validation is disabled") {
		HTTPTestHelper::RequireQueryOk(con, "SET validate_external_file_cache='NO_VALIDATION'");
	}
	SECTION("per-file validation overrides the session") {
		HTTPTestHelper::RequireQueryOk(con, "SET validate_external_file_cache='NO_VALIDATION'");
		file.extended_info->options["validate_external_file_cache"] = Value::BOOLEAN(true);
		can_reuse = false;
	}
	SECTION("NULL per-file validation is rejected") {
		file.extended_info->options["validate_external_file_cache"] = Value();
		invalid_option = true;
	}
	if (invalid_option) {
		REQUIRE_THROWS_WITH(fs.OpenFile(file, FileFlags::FILE_FLAGS_READ | FileFlags::FILE_FLAGS_DIRECT_IO),
		                    Catch::Contains("validate_external_file_cache") && Catch::Contains("expected a BOOLEAN"));
		REQUIRE(server.Observations().empty());
		HTTPTestHelper::RequireQueryOk(con, "ROLLBACK");
		return;
	}
	auto handle = fs.OpenFile(file, FileFlags::FILE_FLAGS_READ | FileFlags::FILE_FLAGS_DIRECT_IO);
	REQUIRE(handle->Cast<HTTPFileHandle>().CanReuseCachedData() == can_reuse);
	handle.reset();
	HTTPTestHelper::RequireQueryOk(con, "ROLLBACK");
}

} // namespace duckdb
