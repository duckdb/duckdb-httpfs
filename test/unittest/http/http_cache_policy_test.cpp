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
		HTTPTestHelper::RequireQueryOk(con, "ROLLBACK");
	}
}

TEST_CASE("HTTP metadata cache evicts expired entries", "[httpfs][cache]") {
	HTTPMetadataCache cache(HTTPMetadataCacheMode::GLOBAL);
	HTTPMetadataCacheEntry entry;
	entry.length = 42;
	entry.cache_valid_until = timestamp_t::ninfinity();
	cache.Insert("expired", entry);
	HTTPMetadataCacheEntry result;
	const auto &lookup = cache;
	REQUIRE_FALSE(lookup.Find("expired", result));
	entry.cache_valid_until = timestamp_t::infinity();
	cache.Insert("fresh", entry);
	REQUIRE(lookup.Find("fresh", result));
	REQUIRE(result.length == 42);
}

} // namespace duckdb
