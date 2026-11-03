#include "catch.hpp"

#include "s3/s3_auth.hpp"
#include "s3/s3_url.hpp"
#include "s3/s3_test_helper.hpp"
#include "s3/s3_request.hpp"
#include "s3/s3fs.hpp"
#include "crypto.hpp"
#include "duckdb/common/file_system.hpp"
#include "duckdb/common/error_data.hpp"
#include "duckdb/common/multi_file/multi_file_list.hpp"
#include "duckdb/main/client_context_file_opener.hpp"

namespace duckdb {

TEST_CASE("Ordinary S3 filenames agree across direct reads glob reads and filename predicates",
          "[httpfs][s3][url-boundary]") {
	for (const string client : {"curl", "httplib"}) {
		for (const string key :
		     {"data/My Report.csv", "data/a+b.csv", "data/a%20b.csv", "data/a#b.csv", "data/p=a%20b/file.csv"}) {
			CAPTURE(client, key);
			MockS3ServerConfig config;
			config.object.key = key;
			config.object.data = "value\n42\n";
			MockS3Server server(config);
			DuckDB db(nullptr);
			Connection con(db);
			S3TestHelper::LoadExtension(db);
			S3TestHelper::RequireQueryOk(con, "SET httpfs_client_implementation='" + client + "'");
			S3TestHelper::RequireQueryOk(con,
			                             "CREATE SECRET reader (TYPE S3, KEY_ID 'id', SECRET 'secret', ENDPOINT '" +
			                                 server.Endpoint() + "', URL_STYLE 'path', USE_SSL false)");
			auto listed = con.Query("SELECT file FROM glob('s3://refresh-bucket/data/**')");
			INFO((listed->HasError() ? listed->GetError() : ""));
			REQUIRE_FALSE(listed->HasError());
			REQUIRE(listed->Collection().GetValue(0, 0).ToString() == server.S3Path());
			for (const string input : {server.S3Path(), string("s3://refresh-bucket/data/**")}) {
				auto result = con.Query("SELECT filename, value FROM read_csv(?, filename=true) WHERE filename=?",
				                        Value(input), Value(server.S3Path()));
				INFO((result->HasError() ? result->GetError() : ""));
				REQUIRE_FALSE(result->HasError());
				REQUIRE(result->Collection().Count() == 1);
				REQUIRE(result->Collection().GetValue(0, 0).ToString() == server.S3Path());
				REQUIRE(result->Collection().GetValue(1, 0).GetValue<int64_t>() == 42);
			}
			auto leaf = key.substr(key.rfind('/') + 1);
			auto name = con.Query("SELECT parse_filename(file) FROM glob('s3://refresh-bucket/data/**')");
			REQUIRE_FALSE(name->HasError());
			REQUIRE(name->Collection().GetValue(0, 0).ToString() == leaf);
		}
	}
}

TEST_CASE("S3 compatibility mode never interprets marker-looking keys as routing options",
          "[httpfs][s3][url-boundary]") {
	for (const string client : {"curl", "httplib"}) {
		for (const bool authenticated : {false, true}) {
			CAPTURE(client, authenticated);
			MockS3Server receiver {MockS3ServerConfig()};
			MockS3ServerConfig config;
			config.object.key = "a%3F?s3_path_encoding=percent&s3_endpoint=" + receiver.Endpoint() +
			                    "&s3_use_ssl=false&s3_url_style=path";
			MockS3Server origin(config);
			DuckDB db(nullptr);
			Connection con(db);
			S3TestHelper::LoadExtension(db);
			S3TestHelper::RequireQueryOk(con, "SET s3_enable_deprecated_url_parameters=true");
			S3TestHelper::RequireQueryOk(con, "SET httpfs_client_implementation='" + client + "'");
			S3TestHelper::RequireQueryOk(con, "CREATE SECRET reader (TYPE S3, ENDPOINT '" + origin.Endpoint() +
			                                      "', URL_STYLE 'path', USE_SSL false, URL_COMPATIBILITY_MODE true" +
			                                      (authenticated ? ", KEY_ID 'id', SECRET 'secret'" : "") + ")");
			auto result = con.Query("SELECT filename, content FROM read_blob(?)", Value(origin.S3Path()));
			INFO((result->HasError() ? result->GetError() : ""));
			REQUIRE_FALSE(result->HasError());
			REQUIRE(result->Collection().GetValue(0, 0).ToString() == origin.S3Path());
			REQUIRE(StringValue::Get(result->Collection().GetValue(1, 0)) == origin.ObjectData());
			REQUIRE_FALSE(origin.Observations().empty());
			REQUIRE(receiver.Observations().empty());
		}
	}
}

TEST_CASE("A sole terminal question mark preserves the directly named S3 object", "[httpfs][s3][url-boundary]") {
	for (const string client : {"curl", "httplib"}) {
		CAPTURE(client);
		MockS3ServerConfig config;
		config.object.key = "data/file?";
		MockS3Server server(config);
		DuckDB db(nullptr);
		Connection con(db);
		S3TestHelper::LoadExtension(db);
		S3TestHelper::RequireQueryOk(con, "SET httpfs_client_implementation='" + client + "'");
		S3TestHelper::RequireQueryOk(con, "CREATE SECRET reader (TYPE S3, KEY_ID 'id', SECRET 'secret', ENDPOINT '" +
		                                      server.Endpoint() + "', URL_STYLE 'path', USE_SSL false)");
		const auto direct_path = server.S3Path();
		auto listed = con.Query("SELECT file FROM glob('s3://refresh-bucket/data/**')");
		INFO((listed->HasError() ? listed->GetError() : ""));
		REQUIRE_FALSE(listed->HasError());
		const auto listed_path = listed->Collection().GetValue(0, 0).ToString();
		REQUIRE(listed_path == direct_path);
		for (const auto &path : {direct_path, listed_path}) {
			auto result = con.Query("SELECT filename, content FROM read_blob(?)", Value(path));
			INFO((result->HasError() ? result->GetError() : ""));
			REQUIRE_FALSE(result->HasError());
			REQUIRE(result->Collection().GetValue(0, 0).ToString() == path);
			REQUIRE(StringValue::Get(result->Collection().GetValue(1, 0)) == server.ObjectData());
		}
		bool read_exact_key = false;
		for (const auto &observation : server.Observations()) {
			if (observation.target.find("list-type=") != string::npos) {
				continue;
			}
			REQUIRE(observation.target == "/refresh-bucket/data/file%3F");
			read_exact_key |= observation.method == "GET";
		}
		REQUIRE(read_exact_key);

		S3TestHelper::RequireQueryOk(
		    con, "COPY (SELECT 42 AS value, 7 AS payload WHERE false) TO 's3://refresh-bucket/data' "
		         "(FORMAT CSV, PARTITION_BY(value), OVERWRITE)");
		bool deleted_exact_key = false;
		for (const auto &observation : server.Observations()) {
			if (observation.method == "POST") {
				const string expected = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
				                        "<Delete xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">"
				                        "<Object><Key>data/file?</Key></Object><Quiet>true</Quiet></Delete>";
				REQUIRE(observation.body_digest == MockS3DigestBody(expected));
				deleted_exact_key = true;
			}
		}
		REQUIRE(deleted_exact_key);
	}
}

TEST_CASE("S3 globbed configuration-looking keys remain literal", "[httpfs][s3][url-boundary]") {
	for (const string client : {"curl", "httplib"}) {
		CAPTURE(client);
		MockS3Server receiver {MockS3ServerConfig()};
		MockS3ServerConfig server_config;
		server_config.auth.stale_key_id = "NEVER_STALE";
		server_config.object.key =
		    "data/x.csv?s3_endpoint=" + receiver.Endpoint() + "&s3_use_ssl=false&s3_url_style=path&s3_region=x.csv";
		server_config.object.data = "value\n42\n";
		MockS3Server origin(std::move(server_config));
		DuckDB db(nullptr);
		Connection con(db);
		S3TestHelper::LoadExtension(db);
		S3TestHelper::RequireQueryOk(con, "SET httpfs_client_implementation='" + client + "'");
		S3TestHelper::RequireQueryOk(con, "CREATE SECRET glob_reader (TYPE S3, KEY_ID 'TEST_READER', "
		                                  "SECRET 'test_secret', SESSION_TOKEN 'TEST_TOKEN', ENDPOINT '" +
		                                      origin.Endpoint() + "', URL_STYLE 'path', USE_SSL false)");
		auto result = con.Query("SELECT value FROM read_csv('s3://refresh-bucket/data/*.csv')");
		REQUIRE(result);
		INFO((result->HasError() ? result->GetError() : ""));
		REQUIRE_FALSE(result->HasError());
		REQUIRE(result->Collection().GetValue(0, 0).GetValue<int64_t>() == 42);
		REQUIRE(receiver.Observations().empty());
		auto projection = con.Query("SELECT file FROM glob('s3://refresh-bucket/data/*.csv')");
		REQUIRE_FALSE(projection->HasError());
		auto reopened = con.Query("SELECT content FROM read_blob(?)", projection->Collection().GetValue(0, 0));
		INFO((reopened->HasError() ? reopened->GetError() : ""));
		REQUIRE_FALSE(reopened->HasError());
		REQUIRE(StringValue::Get(reopened->Collection().GetValue(0, 0)) == "value\n42\n");
		REQUIRE(receiver.Observations().empty());
	}
}

TEST_CASE("Derived S3 authorities validate their components", "[httpfs][s3][url-boundary]") {
	S3AuthConfig config;
	config.credentials.region = "us-east-1";
	auto params = S3AuthResolver::Resolve(config, "s3://bucket/key");
	REQUIRE(params.WithRegion("eu-west-1").GetURLParams().endpoint.GetHost() == "s3.eu-west-1.amazonaws.com");
	for (const string region : {"bad/region", "bad@region", "bad:region", "bad\\region", "bad?region"}) {
		CAPTURE(region);
		REQUIRE_THROWS(params.WithRegion(region));
		config.credentials.region = region;
		REQUIRE_THROWS(S3AuthResolver::Resolve(config, "s3://bucket/key"));
	}
	for (const string bucket : {"bad@bucket", "bad:bucket", "bad\\bucket", "bad#bucket"}) {
		CAPTURE(bucket);
		REQUIRE_THROWS(S3Url::Parse("s3://" + bucket + "/key", params));
	}
	config.credentials.region = "us-east-1";
	config.use_ssl = false;
	params = S3AuthResolver::Resolve(config, "s3://bucket/key");
	REQUIRE_THROWS(S3Url::Parse("s3://example.invalid#/key", params));
	config.enable_deprecated_url_parameters = true;
	REQUIRE_THROWS(S3AuthResolver::Resolve(config, "s3://bucket/key?s3_region=x%40example.invalid%23"));
}

TEST_CASE("COPY overwrite removes literal S3 keys without interpreting their contents", "[httpfs][s3][url-boundary]") {
	MockS3Server receiver {MockS3ServerConfig()};
	MockS3ServerConfig config;
	config.object.key = "directory/old.csv?s3_endpoint=" + receiver.Endpoint() + "&s3_use_ssl=false&s3_url_style=path";
	MockS3Server origin(config);
	DuckDB db(nullptr);
	Connection con(db);
	S3TestHelper::LoadExtension(db);
	S3TestHelper::RequireQueryOk(con, "CREATE SECRET writer (TYPE S3, KEY_ID 'id', SECRET 'secret', ENDPOINT '" +
	                                      origin.Endpoint() + "', URL_STYLE 'path', USE_SSL false)");
	auto result = con.Query("COPY (SELECT 42 AS value, 7 AS payload WHERE false) TO 's3://refresh-bucket/directory' "
	                        "(FORMAT CSV, PARTITION_BY(value), OVERWRITE)");
	INFO((result->HasError() ? result->GetError() : ""));
	REQUIRE_FALSE(result->HasError());
	bool deleted = false;
	for (const auto &observation : origin.Observations()) {
		if (observation.method == "POST") {
			REQUIRE(observation.status == 200);
			REQUIRE(observation.delete_key_count == 1);
			deleted = true;
		}
	}
	REQUIRE(deleted);
	REQUIRE(receiver.Observations().empty());
}

TEST_CASE("COPY overwrite preserves literal directory prefixes", "[httpfs][s3][url-boundary]") {
	for (const string directory : {"dir+", "dir%20", "dir#"}) {
		CAPTURE(directory);
		auto prefix = directory.back() == '/' ? directory : directory + '/';
		auto removed_key = prefix + "remove.csv";
		MockS3ServerConfig config;
		config.list.keys = {removed_key, "dirX/keep.csv", "dir/keep.csv"};
		MockS3Server server(config);
		DuckDB db(nullptr);
		Connection con(db);
		S3TestHelper::LoadExtension(db);
		S3TestHelper::RequireQueryOk(con, "CREATE SECRET writer (TYPE S3, ENDPOINT '" + server.Endpoint() +
		                                      "', URL_STYLE 'path', USE_SSL false)");
		S3TestHelper::RequireQueryOk(con,
		                             "COPY (SELECT 42 AS value, 7 AS payload WHERE false) TO 's3://refresh-bucket/" +
		                                 directory + "' (FORMAT CSV, PARTITION_BY(value), OVERWRITE)");
		bool deleted = false;
		for (const auto &observation : server.Observations()) {
			if (observation.method == "POST") {
				const string expected = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
				                        "<Delete xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">"
				                        "<Object><Key>" +
				                        removed_key + "</Key></Object><Quiet>true</Quiet></Delete>";
				REQUIRE(observation.body_digest == MockS3DigestBody(expected));
				deleted = true;
			}
		}
		INFO(MockS3DescribeObservations(server.Observations()));
		REQUIRE(deleted);
	}
}

TEST_CASE("COPY overwrite rejects directory paths that cannot be joined literally", "[httpfs][s3][url-boundary]") {
	for (const string compatibility_source : {"default", "setting", "secret"}) {
		CAPTURE(compatibility_source);
		MockS3ServerConfig config;
		config.list.keys = {"di?r/old.csv", "di/keep.csv"};
		MockS3Server server(config);
		DuckDB db(nullptr);
		Connection con(db);
		S3TestHelper::LoadExtension(db);
		if (compatibility_source == "setting") {
			S3TestHelper::RequireQueryOk(con, "SET s3_url_compatibility_mode=true");
		}
		S3TestHelper::RequireQueryOk(
		    con, "CREATE SECRET writer (TYPE S3, ENDPOINT '" + server.Endpoint() +
		             "', URL_STYLE 'path', USE_SSL false" +
		             (compatibility_source == "secret" ? ", URL_COMPATIBILITY_MODE true" : "") + ")");
		auto result = con.Query("COPY (SELECT 42 AS value, 7 AS payload WHERE false) TO 's3://refresh-bucket/di?r' "
		                        "(FORMAT CSV, PARTITION_BY(value), OVERWRITE)");
		REQUIRE(result->HasError());
		REQUIRE(StringUtil::Contains(result->GetError(), "directory path cannot be represented literally"));
		REQUIRE(StringUtil::Contains(result->GetError(), "opt in with SET s3_enable_deprecated_url_parameters = true"));
		REQUIRE(StringUtil::Contains(result->GetError(), "URL compatibility mode must also be disabled"));
		REQUIRE(server.Observations().empty());
	}
}

TEST_CASE("S3 COPY preserves ordinary legacy and direct literal writes", "[httpfs][s3][url-boundary]") {
	for (const string client : {"curl", "httplib"}) {
		for (const string kind : {"directory", "legacy-directory", "literal-object", "new-literal-object"}) {
			CAPTURE(client, kind);
			const bool missing = kind == "new-literal-object";
			const bool direct = kind == "literal-object" || missing;
			const bool legacy = kind == "legacy-directory";
			MockS3ServerConfig config;
			config.object.key = direct ? "dir?literal" : "dir/value=42/data_0.csv";
			config.failures.head_not_found_requests = missing ? 1 : 0;
			MockS3Server server(config);
			DuckDB db(nullptr);
			Connection con(db);
			S3TestHelper::LoadExtension(db);
			S3TestHelper::RequireQueryOk(con, "SET enable_global_s3_configuration=false");
			S3TestHelper::RequireQueryOk(con, "SET httpfs_client_implementation='" + client + "'");
			S3TestHelper::RequireQueryOk(con,
			                             "CREATE SECRET writer (TYPE S3, KEY_ID 'id', SECRET 'secret', ENDPOINT '" +
			                                 server.Endpoint() + "', URL_STYLE 'path', USE_SSL false)");
			if (legacy) {
				S3TestHelper::RequireQueryOk(con, "SET s3_enable_deprecated_url_parameters=true");
			}
			const string suffix = direct ? "?literal" : legacy ? "?s3_requester_pays=true" : "/";
			S3TestHelper::RequireQueryOk(con, "COPY (SELECT 42 AS value, 7 AS payload) TO 's3://refresh-bucket/dir" +
			                                      suffix + "' (FORMAT CSV" +
			                                      (direct ? "" : ", PARTITION_BY(value), OVERWRITE_OR_IGNORE") + ")");
			idx_t puts = 0;
			idx_t not_found = 0;
			for (const auto &request : server.Observations()) {
				if (request.method == "HEAD" && request.status == 404) {
					not_found++;
				}
				if (request.method != "PUT") {
					continue;
				}
				puts++;
				REQUIRE(request.path == "/" + config.object.bucket + "/" + config.object.key);
				REQUIRE(request.body_digest == MockS3DigestBody(direct ? "value,payload\n42,7\n" : "payload\n7\n"));
				if (legacy) {
					REQUIRE(MockS3HeaderValues(request, "x-amz-request-payer") == vector<string> {"requester"});
				}
			}
			REQUIRE(puts == 1);
			// Remote COPY no longer probes whether its output already exists.
			REQUIRE(not_found == 0);
		}
	}
}

TEST_CASE("Ordinary S3 glob and direct writes share HTTP metadata cache invalidation", "[httpfs][s3][url-boundary]") {
	MockS3ServerConfig config;
	config.object.key = "My Report%20+.csv";
	MockS3Server server(config);
	DuckDB db(nullptr);
	Connection con(db);
	S3TestHelper::LoadExtension(db);
	S3TestHelper::RequireQueryOk(con, "CREATE SECRET reader (TYPE S3, ENDPOINT '" + server.Endpoint() +
	                                      "', URL_STYLE 'path', USE_SSL false)");
	S3TestHelper::RequireQueryOk(con, "SET enable_http_metadata_cache=true");
	S3TestHelper::RequireQueryOk(con, "BEGIN");
	auto &fs = FileSystem::GetFileSystem(*con.context);
	auto files = fs.GlobFiles("s3://refresh-bucket/*.csv");
	REQUIRE(files.size() == 1);
	auto handle = fs.OpenFile(files[0], FileFlags::FILE_FLAGS_READ);
	auto cache = handle->file_system.Cast<HTTPFileSystem>().GetGlobalCache();
	REQUIRE(cache);
	HTTPMetadataCacheEntry cached;
	REQUIRE(cache->Find(server.S3Path(), cached));
	handle->Close();
	S3TestHelper::RequireQueryOk(con, "COMMIT");
	S3TestHelper::RequireQueryOk(con, "COPY (SELECT 42 AS value) TO '" + server.S3Path() + "' (FORMAT CSV)");
	REQUIRE_FALSE(cache->Find(server.S3Path(), cached));
}

TEST_CASE("COPY overwrite rejects S3 dot segments before deleting any objects", "[httpfs][s3][url-boundary]") {
	for (const string client : {"curl", "httplib"}) {
		for (const string key : {"data/../victim.csv", "data/./victim.csv"}) {
			CAPTURE(client, key);
			MockS3ServerConfig config;
			config.list.keys = {"data/ordinary.csv", key, "victim.csv"};
			MockS3Server server(config);
			DuckDB db(nullptr);
			Connection con(db);
			S3TestHelper::LoadExtension(db);
			S3TestHelper::RequireQueryOk(con, "SET httpfs_client_implementation='" + client + "'");
			S3TestHelper::RequireQueryOk(con,
			                             "CREATE SECRET writer (TYPE S3, KEY_ID 'id', SECRET 'secret', ENDPOINT '" +
			                                 server.Endpoint() + "', URL_STYLE 'path', USE_SSL false)");
			auto result = con.Query("COPY (SELECT 42 AS value, 7 AS payload WHERE false) TO 's3://refresh-bucket/data' "
			                        "(FORMAT CSV, PARTITION_BY(value), OVERWRITE)");
			REQUIRE(result->HasError());
			INFO(result->GetError());
			REQUIRE(StringUtil::Contains(result->GetError(), "cannot be represented"));
			REQUIRE_FALSE(StringUtil::Contains(result->GetError(), "opt in with SET"));
			auto observations = server.Observations();
			REQUIRE_FALSE(observations.empty());
			for (const auto &observation : observations) {
				REQUIRE(observation.method == "GET");
				REQUIRE(observation.status == 200);
			}
		}
	}
}

TEST_CASE("S3 anonymous redirects remain available on both HTTP clients", "[httpfs][s3][url-boundary]") {
	for (const string client : {"curl", "httplib"}) {
		CAPTURE(client);
		MockS3Server receiver {MockS3ServerConfig()};
		MockS3ServerConfig config;
		config.metadata.redirect_head = true;
		config.metadata.redirect_location = receiver.HTTPPath();
		MockS3Server origin(config);
		DuckDB db(nullptr);
		Connection con(db);
		S3TestHelper::LoadExtension(db);
		S3TestHelper::RequireQueryOk(con, "SET enable_global_s3_configuration=false");
		S3TestHelper::RequireQueryOk(con, "SET httpfs_client_implementation='" + client + "'");
		S3TestHelper::RequireQueryOk(con, "CREATE SECRET reader (TYPE S3, ENDPOINT '" + origin.Endpoint() +
		                                      "', URL_STYLE 'path', USE_SSL false, REQUESTER_PAYS true)");
		auto result = con.Query("SELECT content FROM read_blob(?)", Value(origin.S3Path()));
		INFO((result->HasError() ? result->GetError() : ""));
		REQUIRE_FALSE(result->HasError());
		REQUIRE_FALSE(receiver.Observations().empty());
		for (const auto &request : receiver.Observations()) {
			REQUIRE(request.authorization.empty());
			REQUIRE(request.session_header.empty());
		}
	}
}

} // namespace duckdb
