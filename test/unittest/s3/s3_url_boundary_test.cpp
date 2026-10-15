#include "catch.hpp"

#include "s3/s3_auth.hpp"
#include "s3/s3_url.hpp"
#include "s3/s3_test_helper.hpp"
#include "s3/s3_request.hpp"
#include "s3/s3fs.hpp"
#include "crypto.hpp"
#include "duckdb/common/file_system.hpp"
#include "duckdb/common/multi_file/multi_file_list.hpp"
#include "duckdb/main/client_context_file_opener.hpp"

namespace duckdb {

TEST_CASE("S3 literal keys use a final query boundary without rewriting ordinary names", "[httpfs][s3][url-boundary]") {
	S3AuthConfig config;
	config.endpoint = "objects.example";
	config.endpoint_mode = S3EndpointMode::EXPLICIT;
	config.url_style = "path";
	for (const string query : {"", "s3_version_id=v%3Fpart&s3_requester_pays=true"}) {
		auto input = "s3://bucket/prefix/*" + (query.empty() ? "" : "?" + query);
		auto parsed = S3Url::Parse(input, S3AuthResolver::Resolve(config, input));
		for (const string key : {"plain.csv", "My Report.csv", "a+b.csv", "p=a%20b/data.csv", "a#b.csv", "a[b].csv",
		                         "a?b.csv", "a?", "a??", "a?s3_endpoint=elsewhere"}) {
			CAPTURE(key, query);
			auto saved = parsed.GetObjectUrl(key);
			auto reopened = S3Url::Parse(saved, S3AuthResolver::Resolve(config, saved));
			REQUIRE(reopened.GetKey() == key);
			REQUIRE(reopened.GetQueryString() == query);
			if (query.empty() && key.find('?') == string::npos) {
				REQUIRE(saved == "s3://bucket/" + key);
			}
			if (!query.empty()) {
				REQUIRE(reopened.GetObjectVersion().GetValue() == "v?part");
			}
		}
	}
	config.query_mode = S3URLQueryMode::LITERAL_KEY;
	const string literal = "s3://bucket/a%3F?s3_path_encoding=percent&s3_endpoint=elsewhere";
	auto parsed_literal = S3Url::Parse(literal, S3AuthResolver::Resolve(config, literal));
	REQUIRE(parsed_literal.GetKey() == "a%3F?s3_path_encoding=percent&s3_endpoint=elsewhere");
	REQUIRE(parsed_literal.GetObjectUrl(parsed_literal.GetKey()) == literal);
}

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

TEST_CASE("Anonymous S3 routing retains public request options", "[httpfs][s3][url-boundary]") {
	S3AuthConfig config;
	config.request_options.kms_key_id = "public-key-identifier";
	config.request_options.requester_pays = true;
	auto params = S3AuthResolver::Resolve(config, "s3://bucket/key?s3_endpoint=objects.example&s3_url_style=path");
	REQUIRE(params.GetURLParams().endpoint.GetHost() == "objects.example");
	REQUIRE(params.GetRequestOptions().kms_key_id == config.request_options.kms_key_id);
	REQUIRE(params.GetRequestOptions().requester_pays);
}

TEST_CASE("S3 URL routing cannot relocate inherited sensitive configuration", "[httpfs][s3][url-boundary]") {
	for (idx_t material = 0; material < 5; material++) {
		S3AuthConfig config;
		config.endpoint = "objects.example/base";
		config.endpoint_mode = S3EndpointMode::EXPLICIT;
		config.url_style = "path";
		switch (material) {
		case 0:
			config.credentials.access_key_id = "test-id";
			config.credentials.secret_access_key = "test-secret";
			break;
		case 1:
			config.credentials.session_token = "test-token";
			break;
		case 2:
			config.route = S3UrlScheme::Match("gcs://");
			config.credentials.oauth2_bearer_token = "test-bearer";
			break;
		case 3:
			config.credentials.secret_access_key = "test-secret";
			break;
		default:
			config.credentials.access_key_id = "test-id";
			config.credentials.secret_access_key = "test-secret";
			config.request_options.sse_customer_key =
			    S3SSECustomerKey::Create("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");
			break;
		}
		auto prefix = material == 2 ? "gcs://" : "s3://";
		for (const string options :
		     {"s3_endpoint=other.example", "s3_endpoint=https%3A%2F%2Fobjects.example%2Fother",
		      "s3_endpoint=http%3A%2F%2Fobjects.example%2Fbase", "s3_use_ssl=false", "s3_url_style=vhost"}) {
			CAPTURE(material, options);
			REQUIRE_THROWS(S3AuthResolver::Resolve(config, string(prefix) + "bucket/key?" + options));
		}
		auto unchanged = S3AuthResolver::Resolve(
		    config, string(prefix) + "bucket/key?s3_endpoint=https%3A%2F%2Fobjects.example%2Fbase"
		                             "&s3_url_style=path&s3_region=us-east-1");
		REQUIRE(unchanged.GetURLParams().endpoint.GetCanonicalValue() == "https://objects.example/base");
		REQUIRE(unchanged.GetCredentials().region == "us-east-1");
	}
	S3AuthConfig anonymous;
	auto explicit_url =
	    S3AuthResolver::Resolve(anonymous, "s3://bucket/key?s3_endpoint=objects.example&s3_url_style=path");
	REQUIRE(explicit_url.GetURLParams().endpoint.GetHost() == "objects.example");
}

TEST_CASE("S3 URL routing preserves validated AWS region selection", "[httpfs][s3][url-boundary]") {
	S3AuthConfig config;
	config.credentials.access_key_id = "configured-id";
	config.credentials.secret_access_key = "configured-secret";
	auto params = S3AuthResolver::Resolve(config, "s3://bucket/key?s3_region=eu-west-1&s3_url_style=path");
	REQUIRE(params.GetURLParams().endpoint.GetHost() == "s3.eu-west-1.amazonaws.com");
	REQUIRE(params.GetURLParams().style == S3URLStyle::PATH);
	REQUIRE_THROWS(S3AuthResolver::Resolve(config, "s3://bucket/key?s3_region=eu-west-1&s3_use_ssl=false"));
	REQUIRE_THROWS(S3AuthResolver::Resolve(config, "s3://bucket/key?s3_endpoint=other.example"));
}

TEST_CASE("S3 self-contained URL authentication leaves no inherited headers", "[httpfs][s3][url-boundary]") {
	S3AuthConfig config;
	config.credentials.access_key_id = "configured-id";
	config.credentials.secret_access_key = "configured-secret";
	config.credentials.session_token = "configured-token";
	const string path = "s3://bucket/key?s3_endpoint=objects.example&s3_url_style=path"
	                    "&s3_access_key_id=url-id&s3_secret_access_key=url-secret";
	REQUIRE_THROWS(S3AuthResolver::Resolve(config, path));
	auto params = S3AuthResolver::Resolve(config, path + "&s3_session_token=url-token");
	REQUIRE(params.GetCredentials().access_key_id == "url-id");
	REQUIRE(params.GetCredentials().session_token == "url-token");
	REQUIRE_THROWS(params.ValidateInheritedMaterial(true));
	params = S3AuthResolver::Resolve(config, path + "&s3_session_token=");
	REQUIRE(params.GetCredentials().session_token.empty());
	config.request_options.sse_customer_key = S3SSECustomerKey::Create("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");
	REQUIRE_THROWS(S3AuthResolver::Resolve(config, path + "&s3_session_token="));
	params = S3AuthResolver::Resolve(config, path + "&s3_session_token=&s3_sse_c_key=");
	REQUIRE_FALSE(params.GetRequestOptions().sse_customer_key);
}

TEST_CASE("S3 secret routing overrides are rejected before transport", "[httpfs][s3][url-boundary]") {
	for (const string client : {"curl", "httplib"}) {
		CAPTURE(client);
		MockS3ServerConfig server_config;
		server_config.auth.stale_key_id = "NEVER_STALE";
		MockS3Server receiver(std::move(server_config));
		DuckDB db(nullptr);
		Connection con(db);
		S3TestHelper::LoadExtension(db);
		S3TestHelper::RequireQueryOk(con, "SET httpfs_client_implementation='" + client + "'");
		S3TestHelper::RequireQueryOk(con, "CREATE SECRET reader (TYPE S3, KEY_ID 'TEST_READER', SECRET 'test_secret', "
		                                  "SESSION_TOKEN 'TEST_TOKEN', REGION 'us-east-1')");
		auto result = con.Query("FROM read_csv('" + receiver.S3Path() + "?s3_endpoint=" + receiver.Endpoint() +
		                        "&s3_use_ssl=false&s3_url_style=path')");
		REQUIRE(result->HasError());
		REQUIRE(StringUtil::Contains(result->GetError(), "cannot change the destination"));
		REQUIRE(receiver.Observations().empty());
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

TEST_CASE("S3 URL routing binds the actual captured HTTP request configuration", "[httpfs][s3][url-boundary]") {
	::AESStateSSLFactory encryption_util;
	S3AuthConfig config;
	config.endpoint = "objects.example";
	config.endpoint_mode = S3EndpointMode::EXPLICIT;
	config.url_style = "path";
	const string changed_path = "s3://bucket/key?s3_endpoint=other.example";
	auto params = S3AuthResolver::Resolve(config, changed_path);
	HTTPFSUtil http_util;
	HTTPFSParams http_params(http_util);
	// The headers arrive after S3 authentication has been resolved.
	http_params.extra_headers["X-Configured-Header"] = "configured-value";
	auto snapshot =
	    make_shared_ptr<S3RequestSnapshot>(http_params, params, changed_path, weak_ptr<ClientContext>(), false);
	HTTPRequestSession session(snapshot);
	S3RequestSpec spec {changed_path, S3RequestOperation::GET_OBJECT};
	idx_t requests = 0;
	REQUIRE_THROWS(S3RequestExecutor::RunSession(encryption_util, session, spec, [&](S3RequestData &) {
		requests++;
		return make_uniq<HTTPResponse>(HTTPStatusCode::OK_200);
	}));
	REQUIRE(requests == 0);
	const string unchanged_path = "s3://bucket/key?s3_endpoint=objects.example";
	params = S3AuthResolver::Resolve(config, unchanged_path);
	snapshot =
	    make_shared_ptr<S3RequestSnapshot>(http_params, params, unchanged_path, weak_ptr<ClientContext>(), false);
	HTTPRequestSession unchanged_session(snapshot);
	spec.url = unchanged_path;
	S3RequestExecutor::RunSession(encryption_util, unchanged_session, spec, [&](S3RequestData &) {
		requests++;
		return make_uniq<HTTPResponse>(HTTPStatusCode::OK_200);
	});
	REQUIRE(requests == 1);

	// Transport policy alone does not bind anonymous requests to an endpoint.
	http_params.extra_headers.clear();
	http_params.http_proxy = "proxy.example";
	http_params.override_verify_ssl = true;
	http_params.verify_ssl = false;
	params = S3AuthResolver::Resolve(config, changed_path);
	snapshot = make_shared_ptr<S3RequestSnapshot>(http_params, params, changed_path, weak_ptr<ClientContext>(), false);
	HTTPRequestSession anonymous_session(snapshot);
	spec.url = changed_path;
	S3RequestExecutor::RunSession(encryption_util, anonymous_session, spec, [&](S3RequestData &) {
		requests++;
		return make_uniq<HTTPResponse>(HTTPStatusCode::OK_200);
	});
	REQUIRE(requests == 2);

	http_params.bearer_token = "configured-token";
	snapshot = make_shared_ptr<S3RequestSnapshot>(http_params, params, changed_path, weak_ptr<ClientContext>(), false);
	HTTPRequestSession bearer_session(snapshot);
	REQUIRE_THROWS(S3RequestExecutor::RunSession(encryption_util, bearer_session, spec, [&](S3RequestData &) {
		requests++;
		return make_uniq<HTTPResponse>(HTTPStatusCode::OK_200);
	}));
	REQUIRE(requests == 2);
}

TEST_CASE("An invalid configured route cannot authorize inherited request material", "[httpfs][s3][url-boundary]") {
	for (const string prefix : {"s3://", "r2://", "custom://"}) {
		CAPTURE(prefix);
		S3AuthConfig config;
		config.route = S3UrlScheme::MatchRoutedUrl(prefix);
		if (prefix == "s3://") {
			config.endpoint = "ftp://invalid.example";
			config.endpoint_mode = S3EndpointMode::EXPLICIT;
		}
		const string path = prefix + "bucket/key?s3_endpoint=objects.example&s3_url_style=path";
		auto anonymous = S3AuthResolver::Resolve(config, path);
		REQUIRE(anonymous.GetURLParams().endpoint.GetHost() == "objects.example");
		REQUIRE_THROWS(anonymous.ValidateInheritedMaterial(true));
		config.credentials.secret_access_key = "configured-secret";
		REQUIRE_THROWS(S3AuthResolver::Resolve(config, path));
		auto explicit_auth =
		    S3AuthResolver::Resolve(config, path + "&s3_access_key_id=url-id&s3_secret_access_key=url-secret");
		REQUIRE(explicit_auth.GetCredentials().secret_access_key == "url-secret");
	}
}

TEST_CASE("Anonymous S3 requests preserve configured redirect behavior", "[httpfs][s3][url-boundary]") {
	::AESStateSSLFactory encryption_util;
	S3AuthConfig config;
	auto params = S3AuthResolver::Resolve(config, "s3://bucket/key");
	HTTPFSUtil http_util;
	HTTPFSParams http_params(http_util);
	http_params.follow_location = true;
	CapturedHTTPRequestSnapshot captured {
	    make_shared_ptr<S3RequestSnapshot>(http_params, params, "s3://bucket/key", weak_ptr<ClientContext>(), false)};
	HTTPRequestSession session(captured.snapshot);
	S3RequestSpec spec {"s3://bucket/key", S3RequestOperation::GET_OBJECT};
	bool called = false;
	S3RequestExecutor::RunSession(encryption_util, session, spec, [&](S3RequestData &request) {
		REQUIRE(request.http_params->follow_location);
		called = true;
		return make_uniq<HTTPResponse>(HTTPStatusCode::OK_200);
	});
	REQUIRE(called);
	REQUIRE(captured.snapshot->Params().follow_location);
}

TEST_CASE("S3 Location redirects never forward configured headers", "[httpfs][s3][url-boundary]") {
	for (const string client : {"curl", "httplib"}) {
		CAPTURE(client);
		MockS3Server receiver {MockS3ServerConfig()};
		MockS3ServerConfig server_config;
		server_config.auth.stale_key_id = "NEVER_STALE";
		server_config.metadata.redirect_head = true;
		server_config.metadata.redirect_location = receiver.HTTPPath();
		MockS3Server origin(std::move(server_config));
		DuckDB db(nullptr);
		Connection con(db);
		S3TestHelper::LoadExtension(db);
		S3TestHelper::RequireQueryOk(con, "SET httpfs_client_implementation='" + client + "'");
		S3TestHelper::RequireQueryOk(
		    con, "CREATE SECRET redirect_reader (TYPE S3, KEY_ID 'TEST_READER', SECRET 'test_secret', "
		         "SESSION_TOKEN 'TEST_TOKEN', ENDPOINT '" +
		             origin.Endpoint() +
		             "', URL_STYLE 'path', USE_SSL false, EXTRA_HTTP_HEADERS MAP {'X-Test-Private': 'test-value'})");
		auto result = con.Query("FROM read_blob('" + origin.S3Path() + "')");
		REQUIRE_FALSE(result->HasError());
		REQUIRE(result->Collection().GetValue(1, 0).ToString() == origin.ObjectData());
		REQUIRE_FALSE(origin.Observations().empty());
		REQUIRE(receiver.Observations().empty());
		REQUIRE(MockS3HasObservation(origin.Observations(), "HEAD", "TEST_READER", 302));
		bool read_origin = false;
		for (const auto &request : origin.Observations()) {
			if (request.method == "GET") {
				REQUIRE(request.key_id == "TEST_READER");
				REQUIRE((request.status == 200 || request.status == 206));
				read_origin = true;
			}
		}
		REQUIRE(read_origin);
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

TEST_CASE("Derived S3 authorities validate their components", "[httpfs][s3][url-boundary]") {
	S3AuthConfig config;
	config.credentials.region = "us-east-1";
	auto params = S3AuthResolver::Resolve(config, "s3://bucket/key");
	REQUIRE(params.WithRegion("eu-west-1").GetURLParams().endpoint.GetHost() == "s3.eu-west-1.amazonaws.com");
	for (const string region :
	     {"bad/region", "bad@region", "bad:region", "bad\\region", "bad?region", "bad.region", "bad_region"}) {
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
	for (const string directory : {"dir*", "dir[ab]"}) {
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
		REQUIRE(deleted);
	}
}

TEST_CASE("S3 credential refresh preserves escaped literal paths", "[httpfs][s3][url-boundary]") {
	for (const string client : {"curl", "httplib"}) {
		CAPTURE(client);
		MockS3ServerConfig config;
		config.object.key = "object?s3_region=literal.bin";
		MockS3Server server(config);
		DuckDB db(nullptr);
		Connection con(db);
		auto test_id = S3TestHelper::ConfigureRefresh(db, con, server, client, true);
		auto result = con.Query("SELECT content FROM read_blob(?)", Value(server.S3Path() + "?"));
		INFO((result->HasError() ? result->GetError() : ""));
		REQUIRE_FALSE(result->HasError());
		REQUIRE(StringValue::Get(result->Collection().GetValue(0, 0)) == server.ObjectData());
		S3TestHelper::AssertSingleRefresh(test_id);
		REQUIRE(MockS3HasObservation(server.Observations(), "HEAD", S3TestHelper::FRESH_KEY_ID, 200));
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

TEST_CASE("S3 directory adapters reject path normalization before deletion", "[httpfs][s3][url-boundary]") {
	MockS3ServerConfig config;
	config.list.keys = {"dir/a//remove.csv", "dir/a/remove.csv"};
	MockS3Server server(config);
	DuckDB db(nullptr);
	Connection con(db);
	S3TestHelper::LoadExtension(db);
	S3TestHelper::RequireQueryOk(con, "CREATE SECRET reader (TYPE S3, ENDPOINT '" + server.Endpoint() +
	                                      "', URL_STYLE 'path', USE_SSL false)");
	auto result = con.Query("COPY (SELECT 42 AS value, 7 AS payload WHERE false) TO 's3://refresh-bucket/dir' "
	                        "(FORMAT CSV, PARTITION_BY(value), OVERWRITE)");
	REQUIRE(result->HasError());
	INFO(result->GetError());
	REQUIRE(StringUtil::Contains(result->GetError(), "cannot be represented"));
	for (const auto &observation : server.Observations()) {
		REQUIRE(observation.method == "GET");
	}
	S3TestHelper::RequireQueryOk(con, "BEGIN");
	auto &fs = FileSystem::GetFileSystem(*con.context);
	fs.RemoveDirectory("s3://refresh-bucket/dir/a//");
	S3TestHelper::RequireQueryOk(con, "COMMIT");
	bool deleted = false;
	for (const auto &observation : server.Observations()) {
		if (observation.method == "POST") {
			const string expected = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
			                        "<Delete xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">"
			                        "<Object><Key>dir/a//remove.csv</Key></Object><Quiet>true</Quiet></Delete>";
			REQUIRE(observation.body_digest == MockS3DigestBody(expected));
			deleted = true;
		}
	}
	REQUIRE(deleted);
}

TEST_CASE("S3 directory listing accepts bucket roots and ignores directory markers", "[httpfs][s3][url-boundary]") {
	MockS3ServerConfig config;
	config.list.keys = {"data/", "data/file.csv"};
	MockS3Server server(config);
	DuckDB db(nullptr);
	Connection con(db);
	S3TestHelper::LoadExtension(db);
	S3TestHelper::RequireQueryOk(con, "CREATE SECRET reader (TYPE S3, ENDPOINT '" + server.Endpoint() +
	                                      "', URL_STYLE 'path', USE_SSL false)");
	S3TestHelper::RequireQueryOk(con, "BEGIN");
	auto &fs = FileSystem::GetFileSystem(*con.context);
	for (const string directory :
	     {"s3://refresh-bucket", "s3://refresh-bucket/", "s3://refresh-bucket/data", "s3://refresh-bucket/data/"}) {
		CAPTURE(directory);
		vector<string> files;
		REQUIRE(fs.ListFiles(directory, [&](OpenFileInfo &file) { files.push_back(file.path); }));
		REQUIRE(files.size() == 1);
		REQUIRE(fs.JoinPath(directory, files[0]) == "s3://refresh-bucket/data/file.csv");
	}
	S3TestHelper::RequireQueryOk(con, "COMMIT");
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
			auto observations = server.Observations();
			REQUIRE_FALSE(observations.empty());
			for (const auto &observation : observations) {
				REQUIRE(observation.method == "GET");
				REQUIRE(observation.status == 200);
			}
		}
	}
}

TEST_CASE("S3 empty bucket-root listing preserves query options and configured authentication",
          "[httpfs][s3][url-boundary]") {
	for (const string client : {"curl", "httplib"}) {
		for (const bool use_headers : {false, true}) {
			CAPTURE(client, use_headers);
			MockS3ServerConfig config;
			config.object.key = "directory/";
			MockS3Server server(config);
			DuckDB db(nullptr);
			Connection con(db);
			S3TestHelper::LoadExtension(db);
			S3TestHelper::RequireQueryOk(con, "SET httpfs_client_implementation='" + client + "'");
			const string authentication = use_headers ? ", EXTRA_HTTP_HEADERS MAP {'X-Test-Private': 'test-value'}"
			                                          : ", KEY_ID 'id', SECRET 'secret'";
			S3TestHelper::RequireQueryOk(con, "CREATE SECRET writer (TYPE S3, ENDPOINT '" + server.Endpoint() +
			                                      "', URL_STYLE 'path', USE_SSL false" + authentication + ")");
			S3TestHelper::RequireQueryOk(
			    con, "COPY (SELECT 42 AS k, 1 AS v WHERE false) TO 's3://refresh-bucket?s3_requester_pays=true' "
			         "(FORMAT CSV, PARTITION_BY(k), OVERWRITE)");
			auto observations = server.Observations();
			REQUIRE_FALSE(observations.empty());
			for (const auto &observation : observations) {
				REQUIRE(observation.method == "GET");
				REQUIRE(observation.status == 200);
				if (use_headers) {
					bool found_header = false;
					for (const auto &header : observation.headers) {
						if (StringUtil::CIEquals(header.first, "X-Test-Private") && header.second == "test-value") {
							found_header = true;
						}
					}
					REQUIRE(found_header);
				} else {
					REQUIRE(observation.key_id == "id");
				}
			}
		}
	}
}

TEST_CASE("COPY overwrite refuses non-empty S3 directories with query options before deleting",
          "[httpfs][s3][url-boundary]") {
	for (const string client : {"curl", "httplib"}) {
		for (const string directory : {"s3://refresh-bucket", "s3://refresh-bucket/data"}) {
			CAPTURE(client, directory);
			MockS3ServerConfig config;
			config.list.keys = {"data/ordinary.csv", "data/another.csv"};
			MockS3Server server(config);
			DuckDB db(nullptr);
			Connection con(db);
			S3TestHelper::LoadExtension(db);
			S3TestHelper::RequireQueryOk(con, "SET httpfs_client_implementation='" + client + "'");
			S3TestHelper::RequireQueryOk(con,
			                             "CREATE SECRET writer (TYPE S3, KEY_ID 'id', SECRET 'secret', ENDPOINT '" +
			                                 server.Endpoint() + "', URL_STYLE 'path', USE_SSL false)");
			auto result = con.Query("COPY (SELECT 42 AS k, 1 AS v WHERE false) TO '" + directory +
			                        "?s3_requester_pays=true' (FORMAT CSV, PARTITION_BY(k), OVERWRITE)");
			REQUIRE(result->HasError());
			INFO(result->GetError());
			REQUIRE(StringUtil::Contains(result->GetError(), "directory URL options"));
			auto observations = server.Observations();
			REQUIRE_FALSE(observations.empty());
			for (const auto &observation : observations) {
				REQUIRE(observation.method == "GET");
				REQUIRE(observation.status == 200);
			}
		}
	}
}

TEST_CASE("S3 glob query options preserve ordinary filenames", "[httpfs][s3][url-boundary]") {
	MockS3ServerConfig config;
	config.object.key = "My Report%20+.csv";
	config.object.data = "value\n42\n";
	MockS3Server server(config);
	DuckDB db(nullptr);
	Connection con(db);
	S3TestHelper::LoadExtension(db);
	S3TestHelper::RequireQueryOk(con, "CREATE SECRET reader (TYPE S3, KEY_ID 'id', SECRET 'secret', ENDPOINT '" +
	                                      server.Endpoint() + "', URL_STYLE 'path', USE_SSL false)");
	const string options = "?s3_requester_pays=true";
	const auto expected = server.S3Path() + options;
	auto listed = con.Query("SELECT file FROM glob(?)", Value("s3://refresh-bucket/*.csv" + options));
	INFO((listed->HasError() ? listed->GetError() : ""));
	REQUIRE_FALSE(listed->HasError());
	REQUIRE(listed->Collection().GetValue(0, 0).ToString() == expected);
	auto result = con.Query("SELECT filename, value FROM read_csv(?, filename=true) WHERE filename=?",
	                        Value("s3://refresh-bucket/*.csv" + options), Value(expected));
	INFO((result->HasError() ? result->GetError() : ""));
	REQUIRE_FALSE(result->HasError());
	REQUIRE(result->Collection().Count() == 1);
	REQUIRE(result->Collection().GetValue(1, 0).GetValue<int64_t>() == 42);
}

} // namespace duckdb
