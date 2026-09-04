#include "catch.hpp"

#include "s3/mock_s3_server.hpp"
#include "s3/s3_test_helper.hpp"

#include "http/httpfs.hpp"
#include "http/httpfs_client.hpp"
#include "crypto.hpp"
#include "s3/s3_provider.hpp"
#include "s3/s3_request.hpp"
#include "s3/s3_settings.hpp"
#include "s3/s3_url.hpp"
#include "s3/s3_xml_response.hpp"
#include "s3/s3fs.hpp"

#include "duckdb.hpp"
#include "duckdb/common/array.hpp"
#include "duckdb/common/error_data.hpp"
#include "duckdb/common/file_system.hpp"
#include "duckdb/common/multi_file/multi_file_list.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/main/client_context.hpp"
#include "duckdb/main/client_context_file_opener.hpp"
#include "duckdb/main/secret/secret.hpp"

#include <new>

namespace duckdb {

namespace {

static S3AuthConfig TestAuthConfig(S3ProviderType provider_type = S3ProviderType::S3, bool scheme_is_alias = false) {
	S3AuthConfig config;
	const char *prefix = provider_type == S3ProviderType::GCS  ? "gcs://"
	                     : provider_type == S3ProviderType::R2 ? "r2://"
	                                                           : "s3://";
	config.route = {provider_type, scheme_is_alias ? "alias://" : prefix,
	                scheme_is_alias ? S3UrlSchemeOrigin::ALIAS : S3UrlSchemeOrigin::BUILTIN};
	if (provider_type == S3ProviderType::R2) {
		config.endpoint = "account.r2.cloudflarestorage.com";
		config.endpoint_mode = S3EndpointMode::EXPLICIT;
	}
	return config;
}

static S3AuthParams ResolveTestAuth(S3AuthConfig config, string path = "") {
	if (path.empty()) {
		path = config.route.prefix + "bucket/key";
	}
	return S3AuthResolver::Resolve(std::move(config), path);
}

static ParsedS3Url ParseTestS3Url(const string &url, const string &endpoint, const string &url_style) {
	auto config = TestAuthConfig();
	config.endpoint = endpoint;
	config.endpoint_mode = endpoint.empty() ? S3EndpointMode::AUTOMATIC : S3EndpointMode::EXPLICIT;
	config.url_style = url_style;
	auto auth_params = ResolveTestAuth(std::move(config), url);
	return S3Url::Parse(url, auth_params);
}

static void RunFullGetErrorBodyScenario(const string &client_implementation) {
	MockS3ServerConfig config;
	config.object.bucket = S3TestHelper::BUCKET;
	config.object.key = S3TestHelper::OBJECT_KEY;
	config.auth.stale_key_id = S3TestHelper::STALE_KEY_ID;
	config.auth.refresh_target = MockS3RefreshTarget::FULL_GET;
	MockS3Server server(std::move(config));

	DuckDB db(nullptr);
	Connection con(db);
	auto test_id = S3TestHelper::ConfigureRefresh(db, con, server, client_implementation, false, false);

	S3TestHelper::RequireQueryOk(con, "SET force_download=true");
	S3TestHelper::RequireQueryOk(con, "BEGIN TRANSACTION");
	string error;
	try {
		auto &fs = FileSystem::GetFileSystem(*con.context);
		fs.OpenFile(S3TestHelper::S3_PATH, FileFlags::FILE_FLAGS_READ);
	} catch (std::exception &ex) {
		error = ex.what();
	}
	INFO(error);
	REQUIRE(error.find("AccessDenied: stale credentials") != string::npos);
	S3TestHelper::RequireQueryOk(con, "ROLLBACK");

	auto observations = server.Observations();
	INFO(MockS3DescribeObservations(observations));
	REQUIRE(MockS3HasObservation(observations, "GET", S3TestHelper::STALE_KEY_ID, 403));
	REQUIRE_FALSE(S3TestHelper::HasRequestWithKey(observations, S3TestHelper::FRESH_KEY_ID));
	S3TestHelper::AssertNoRefresh(test_id);
}

static void RunChunkedFullGetScenario(const string &client_implementation) {
	MockS3ServerConfig config;
	config.object.bucket = S3TestHelper::BUCKET;
	config.object.key = S3TestHelper::OBJECT_KEY;
	config.auth.stale_key_id = S3TestHelper::STALE_KEY_ID;
	config.auth.refresh_target = MockS3RefreshTarget::DELETE_OBJECT;
	config.full_get.chunked = true;
	auto object_data = config.object.data;
	MockS3Server server(std::move(config));

	DuckDB db(nullptr);
	Connection con(db);
	auto test_id = S3TestHelper::ConfigureRefresh(db, con, server, client_implementation, false);

	S3TestHelper::RequireQueryOk(con, "SET force_download=true");
	S3TestHelper::RequireQueryOk(con, "BEGIN TRANSACTION");
	auto &fs = FileSystem::GetFileSystem(*con.context);
	auto handle = fs.OpenFile(S3TestHelper::S3_PATH, FileFlags::FILE_FLAGS_READ);
	string result(object_data.size(), '\0');
	handle->Read(QueryContext(*con.context), &result[0], result.size(), 0);
	REQUIRE(result == object_data);
	S3TestHelper::RequireQueryOk(con, "COMMIT");

	auto observations = server.Observations();
	INFO(MockS3DescribeObservations(observations));
	REQUIRE(MockS3HasObservation(observations, "GET", S3TestHelper::STALE_KEY_ID, 200));
	S3TestHelper::AssertNoRefresh(test_id);
}

static void RunS3HeaderScenario(const string &client_implementation) {
	MockS3ServerConfig config;
	config.auth.stale_key_id = "NEVER_STALE";
	MockS3Server server(std::move(config));

	DuckDB db(nullptr);
	Connection con(db);
	S3TestHelper::LoadExtension(db);
	S3TestHelper::RequireQueryOk(con,
	                             StringUtil::Format("SET httpfs_client_implementation='%s'", client_implementation));
	S3TestHelper::RequireQueryOk(con, "SET httpfs_connection_caching=false");
	S3TestHelper::RequireQueryOk(con, StringUtil::Format(R"(
CREATE SECRET s3_headers (
	TYPE S3,
	SCOPE '%s',
	KEY_ID 'FRESH_KEY',
	SECRET 'S3TestHelper::FRESH_SECRET',
	REGION 'us-east-1',
	ENDPOINT '%s',
	USE_SSL false,
	URL_STYLE 'path',
	EXTRA_HTTP_HEADERS MAP {
		'X-HTTPFS-Session': 'present',
		'X-AmZ-Meta-Color': 'blue',
		'x-GoOg-Meta-Mode': 'fast',
		'X-AmZ-Meta-Empty': '',
		'x-GoOg-Meta-Whitespace': '   '
	}
))",
	                                                     S3TestHelper::S3_PATH, server.Endpoint()));

	S3TestHelper::RequireQueryOk(con, "BEGIN TRANSACTION");
	auto &fs = FileSystem::GetFileSystem(*con.context);
	{
		auto handle = fs.OpenFile(S3TestHelper::S3_PATH, FileFlags::FILE_FLAGS_READ | FileFlags::FILE_FLAGS_DIRECT_IO);
		REQUIRE(handle);
	}
	S3TestHelper::RequireQueryOk(con, "COMMIT");

	auto observations = server.Observations();
	INFO(MockS3DescribeObservations(observations));
	REQUIRE_FALSE(observations.empty());
	for (const auto &observation : observations) {
		REQUIRE(observation.user_agent_count == 1);
		REQUIRE_FALSE(observation.user_agent.empty());
		REQUIRE(observation.session_header_count == 1);
		REQUIRE(observation.session_header == "present");
		REQUIRE(MockS3HeaderValues(observation, "X-AmZ-Meta-Color") == vector<string> {"blue"});
		REQUIRE(MockS3HeaderValues(observation, "x-GoOg-Meta-Mode") == vector<string> {"fast"});
		REQUIRE(MockS3HeaderValues(observation, "X-AmZ-Meta-Empty") == vector<string> {""});
		REQUIRE(MockS3HeaderValues(observation, "x-GoOg-Meta-Whitespace") == vector<string> {""});
		REQUIRE(StringUtil::Contains(observation.authorization, "x-amz-meta-color"));
		REQUIRE(StringUtil::Contains(observation.authorization, "x-amz-meta-empty"));
		REQUIRE(StringUtil::Contains(observation.authorization, "x-goog-meta-mode"));
		REQUIRE(StringUtil::Contains(observation.authorization, "x-goog-meta-whitespace"));
		REQUIRE_FALSE(StringUtil::Contains(observation.authorization, "x-httpfs-session"));
		REQUIRE_FALSE(StringUtil::Contains(observation.authorization, "user-agent"));

		bool found_amz_spelling = false;
		bool found_goog_spelling = false;
		for (const auto &header : observation.headers) {
			found_amz_spelling |= header.first == "X-AmZ-Meta-Color";
			found_goog_spelling |= header.first == "x-GoOg-Meta-Mode";
		}
		REQUIRE(found_amz_spelling);
		REQUIRE(found_goog_spelling);
	}
}

static void RunNormalizedEndpointWireScenario(const string &client_implementation) {
	MockS3ServerConfig config;
	config.endpoint_base_path = "//gateway/base";
	config.auth.stale_key_id = "NEVER_STALE";
	config.list.paginate = true;
	MockS3Server server(std::move(config));

	DuckDB db(nullptr);
	Connection con(db);
	S3TestHelper::LoadExtension(db);
	S3TestHelper::RequireQueryOk(con,
	                             StringUtil::Format("SET httpfs_client_implementation='%s'", client_implementation));
	S3TestHelper::RequireQueryOk(con, "SET httpfs_connection_caching=false");
	S3TestHelper::RequireQueryOk(con, "SET enable_global_s3_configuration=false");
	S3TestHelper::RequireQueryOk(con, StringUtil::Format(R"(
CREATE SECRET normalized_endpoint (
	TYPE S3,
	SCOPE 's3://refresh-bucket/',
	KEY_ID 'FRESH_KEY',
	SECRET 'FRESH_SECRET',
	REGION 'us-east-1',
	ENDPOINT 'HTTP://%s//gateway/base///',
	USE_SSL true,
	URL_STYLE 'path'
))",
	                                                     server.Endpoint()));

	auto &fs = FileSystem::GetFileSystem(*con.context);
	S3TestHelper::RequireQueryOk(con, "BEGIN TRANSACTION");
	{
		auto handle = fs.OpenFile(S3TestHelper::S3_PATH, FileFlags::FILE_FLAGS_READ | FileFlags::FILE_FLAGS_DIRECT_IO);
		char result;
		handle->Read(QueryContext(*con.context), &result, 1, 0);
		REQUIRE(result == server.ObjectData()[0]);
	}
	auto glob_result = fs.Glob("s3://refresh-bucket/*.bin", FileGlobOptions::ALLOW_EMPTY, nullptr);
	REQUIRE(glob_result->GetAllFiles().size() == 2);
	S3TestHelper::WriteSinglePutPayload(con);
	auto legacy_endpoint = server.Endpoint() + "//gateway/base/";
	auto uri_endpoint = "http://" + server.Endpoint() + "//gateway/base";
	fs.RemoveFiles(
	    {string(S3TestHelper::S3_PATH) + "?s3_endpoint=" +
	         S3Url::Encode(legacy_endpoint, S3URLEncodeMode::QUERY_COMPONENT) + "&s3_use_ssl=false&s3_url_style=path",
	     "s3://refresh-bucket/another.bin?s3_endpoint=" +
	         S3Url::Encode(uri_endpoint, S3URLEncodeMode::QUERY_COMPONENT) + "&s3_use_ssl=true&s3_url_style=path"});
	S3TestHelper::RequireQueryOk(con, "COMMIT");

	auto observations = server.Observations();
	INFO(MockS3DescribeObservations(observations));
	bool saw_read = false;
	bool saw_list = false;
	bool saw_put = false;
	idx_t bulk_delete_count = 0;
	for (const auto &observation : observations) {
		REQUIRE(StringUtil::StartsWith(observation.path, "//gateway/base/"));
		REQUIRE(MockS3HeaderValues(observation, "Host") == vector<string> {server.Endpoint()});
		REQUIRE(StringUtil::Contains(observation.authorization, "SignedHeaders="));
		REQUIRE(StringUtil::Contains(observation.authorization, "host"));
		saw_read |= observation.method == "HEAD" || observation.method == "GET";
		saw_list |= observation.method == "GET" && StringUtil::Contains(observation.target, "list-type=2");
		saw_put |= observation.method == "PUT";
		if (observation.method == "POST" && StringUtil::Contains(observation.target, "delete=")) {
			bulk_delete_count++;
			REQUIRE(observation.delete_key_count == 2);
		}
	}
	REQUIRE(saw_read);
	REQUIRE(saw_list);
	REQUIRE(saw_put);
	REQUIRE(bulk_delete_count == 1);
	REQUIRE(server.UploadedObject() == "single-shot payload");
}

static void RunS3RejectedHeaderScenario(const string &client_implementation) {
	MockS3ServerConfig config;
	config.auth.stale_key_id = "NEVER_STALE";
	MockS3Server server(std::move(config));

	DuckDB db(nullptr);
	Connection con(db);
	S3TestHelper::LoadExtension(db);
	S3TestHelper::RequireQueryOk(con,
	                             StringUtil::Format("SET httpfs_client_implementation='%s'", client_implementation));
	S3TestHelper::RequireQueryOk(con, "SET httpfs_connection_caching=false");
	S3TestHelper::RequireQueryOk(con, StringUtil::Format(R"(
CREATE SECRET s3_rejected_headers (
	TYPE S3,
	SCOPE '%s',
	KEY_ID 'FRESH_KEY',
	SECRET 'S3TestHelper::FRESH_SECRET',
	REGION 'us-east-1',
	ENDPOINT '%s',
	USE_SSL false,
	URL_STYLE 'path'
))",
	                                                     S3TestHelper::S3_PATH, server.Endpoint()));

	auto capture_open_error = [&]() {
		S3TestHelper::RequireQueryOk(con, "BEGIN TRANSACTION");
		string error;
		try {
			auto &fs = FileSystem::GetFileSystem(*con.context);
			fs.OpenFile(S3TestHelper::S3_PATH, FileFlags::FILE_FLAGS_READ | FileFlags::FILE_FLAGS_DIRECT_IO);
		} catch (std::exception &ex) {
			error = ex.what();
		}
		S3TestHelper::RequireQueryOk(con, "ROLLBACK");
		return error;
	};
	const vector<pair<string, string>> protected_headers {
	    {"hOsT", "Host"},
	    {"AUTHORIZATION", "Authorization"},
	    {"content-LENGTH", "Content-Length"},
	    {"CONTENT-type", "Content-Type"},
	    {"content-md5", "Content-MD5"},
	    {"RANGE", "Range"},
	    {"if-match", "If-Match"},
	    {"X-AMZ-DATE", "x-amz-date"},
	    {"X-AMZ-CONTENT-SHA256", "x-amz-content-sha256"},
	    {"X-AMZ-SECURITY-TOKEN", "x-amz-security-token"},
	    {"X-AMZ-REQUEST-PAYER", "x-amz-request-payer"},
	    {"X-AMZ-SERVER-SIDE-ENCRYPTION", "x-amz-server-side-encryption"},
	    {"X-AMZ-SERVER-SIDE-ENCRYPTION-AWS-KMS-KEY-ID", "x-amz-server-side-encryption-aws-kms-key-id"},
	};
	for (const auto &protected_header : protected_headers) {
		S3TestHelper::RequireQueryOk(
		    con, StringUtil::Format("SET extra_http_headers=MAP {'%s': 'override'}", protected_header.first));
		auto error = capture_open_error();
		INFO(client_implementation);
		INFO(protected_header.first);
		REQUIRE(StringUtil::Contains(error, protected_header.first));
		REQUIRE(StringUtil::Contains(error, protected_header.second));
		REQUIRE(server.Observations().empty());
	}

	S3TestHelper::RequireQueryOk(
	    con, "SET extra_http_headers=MAP {'X-Amz-Meta-Duplicate': 'one', 'x-amz-meta-duplicate': 'two'}");
	auto raw_duplicate_error = capture_open_error();
	REQUIRE(StringUtil::Contains(raw_duplicate_error, "X-Amz-Meta-Duplicate"));
	REQUIRE(StringUtil::Contains(raw_duplicate_error, "x-amz-meta-duplicate"));
	REQUIRE(server.Observations().empty());

	S3TestHelper::RequireQueryOk(con, "SET extra_http_headers=MAP {'X-Amz-Meta-Layer': 'setting'}");
	S3TestHelper::RequireQueryOk(con, StringUtil::Format(R"(
CREATE OR REPLACE SECRET s3_rejected_headers (
	TYPE S3,
	SCOPE '%s',
	KEY_ID 'FRESH_KEY',
	SECRET 'S3TestHelper::FRESH_SECRET',
	REGION 'us-east-1',
	ENDPOINT '%s',
	USE_SSL false,
	URL_STYLE 'path',
	EXTRA_HTTP_HEADERS MAP {'x-amz-meta-layer': 'secret'}
))",
	                                                     S3TestHelper::S3_PATH, server.Endpoint()));
	auto layered_duplicate_error = capture_open_error();
	REQUIRE(StringUtil::Contains(layered_duplicate_error, "X-Amz-Meta-Layer"));
	REQUIRE(StringUtil::Contains(layered_duplicate_error, "x-amz-meta-layer"));
	REQUIRE(server.Observations().empty());
}

static void RunS3RegionRedirectScenario(const string &client_implementation, bool list_request) {
	MockS3ServerConfig config;
	config.auth.stale_key_id = "NEVER_STALE";
	config.auth.required_region = "us-east-1";
	MockS3Server server(std::move(config));

	DuckDB db(nullptr);
	Connection con(db);
	S3TestHelper::LoadExtension(db);
	S3TestHelper::RequireQueryOk(con,
	                             StringUtil::Format("SET httpfs_client_implementation='%s'", client_implementation));
	S3TestHelper::RequireQueryOk(con, "SET httpfs_connection_caching=false");
	S3TestHelper::RequireQueryOk(con, "SET enable_logging=true");
	if (!list_request) {
		S3TestHelper::RequireQueryOk(con, "SET enable_http_metadata_cache=true");
	}
	S3TestHelper::RequireQueryOk(con, StringUtil::Format(R"(
CREATE SECRET s3_region_redirect (
	TYPE S3,
	SCOPE 's3://refresh-bucket/',
	KEY_ID 'FRESH_KEY',
	SECRET 'S3TestHelper::FRESH_SECRET',
	REGION 'eu-west-1',
	ENDPOINT '%s',
	USE_SSL false,
	URL_STYLE 'path',
	EXTRA_HTTP_HEADERS MAP {'X-AmZ-Meta-Region': 'region-value'}
))",
	                                                     server.Endpoint()));

	if (list_request) {
		auto result = con.Query("SELECT file FROM glob('s3://refresh-bucket/*.bin')");
		REQUIRE(result);
		INFO((result->HasError() ? result->GetError() : string()));
		REQUIRE_FALSE(result->HasError());
		REQUIRE(result->RowCount() == 1);
	} else {
		S3TestHelper::RequireQueryOk(con, "BEGIN TRANSACTION");
		auto &fs = FileSystem::GetFileSystem(*con.context);
		{
			auto handle =
			    fs.OpenFile(S3TestHelper::S3_PATH, FileFlags::FILE_FLAGS_READ | FileFlags::FILE_FLAGS_DIRECT_IO);
			REQUIRE(handle);
		}
		S3TestHelper::RequireQueryOk(con, "COMMIT");

		S3TestHelper::RequireQueryOk(con, "BEGIN TRANSACTION");
		auto handle = fs.OpenFile(S3TestHelper::S3_PATH, FileFlags::FILE_FLAGS_READ | FileFlags::FILE_FLAGS_DIRECT_IO);
		char result;
		handle->Read(QueryContext(*con.context), &result, 1, 0);
		REQUIRE(result == server.ObjectData()[0]);
		S3TestHelper::RequireQueryOk(con, "COMMIT");
	}

	auto observations = server.Observations();
	INFO(MockS3DescribeObservations(observations));
	bool saw_redirect = false;
	bool saw_success = false;
	bool saw_cached_region_get = false;
	idx_t head_count = 0;
	for (const auto &observation : observations) {
		REQUIRE(MockS3HeaderValues(observation, "X-AmZ-Meta-Region") == vector<string> {"region-value"});
		REQUIRE(StringUtil::Contains(observation.authorization, "x-amz-meta-region"));
		head_count += observation.method == "HEAD";
		if (observation.status == 301 && observation.region == "eu-west-1") {
			saw_redirect = true;
		}
		if (observation.status == 200 && observation.region == "us-east-1") {
			saw_success = true;
		}
		if (observation.method == "GET" && observation.region == "us-east-1") {
			saw_cached_region_get = true;
		}
	}
	REQUIRE(saw_redirect);
	REQUIRE(saw_success);
	if (!list_request) {
		REQUIRE(head_count == 2);
		REQUIRE(saw_cached_region_get);
	}

	auto logs = con.Query("SELECT count(*) FROM duckdb_logs WHERE message LIKE '%incorrect region%'");
	REQUIRE(logs);
	INFO((logs->HasError() ? logs->GetError() : string()));
	REQUIRE_FALSE(logs->HasError());
	REQUIRE(logs->GetValue(0, 0).GetValue<int64_t>() == 1);
}

static void ConfigureGCSClient(Connection &con, const string &client_implementation) {
	S3TestHelper::RequireQueryOk(con,
	                             StringUtil::Format("SET httpfs_client_implementation='%s'", client_implementation));
	S3TestHelper::RequireQueryOk(con, "SET httpfs_connection_caching=false");
}

static void ConfigureGCSBearer(Connection &con, MockS3Server &server, const string &client_implementation,
                               const string &user_project = string()) {
	ConfigureGCSClient(con, client_implementation);
	auto project_option = user_project.empty() ? string() : StringUtil::Format(",\n\tUSER_PROJECT '%s'", user_project);
	S3TestHelper::RequireQueryOk(con, StringUtil::Format(R"(
CREATE SECRET gcs_bearer (
	TYPE GCS,
	SCOPE 'gcs://refresh-bucket/',
	BEARER_TOKEN 'gcs-test-token',
	ENDPOINT '%s',
	USE_SSL false,
	URL_STYLE 'path'%s
))",
	                                                     server.Endpoint(), project_option));
}

static void RunGCSHMACDefaultRegionScenario(const string &client_implementation) {
	MockS3ServerConfig config;
	config.auth.stale_key_id = "NEVER_STALE";
	MockS3Server server(std::move(config));

	DuckDB db(nullptr);
	Connection con(db);
	S3TestHelper::LoadExtension(db);
	ConfigureGCSClient(con, client_implementation);
	S3TestHelper::RequireQueryOk(con, "SET enable_global_s3_configuration=false");
	S3TestHelper::RequireQueryOk(con, "SET enable_http_metadata_cache=true");
	S3TestHelper::RequireQueryOk(con, StringUtil::Format(R"(
CREATE SECRET gcs_hmac (
	TYPE GCS,
	SCOPE 'gcs://refresh-bucket/',
	KEY_ID 'FRESH_KEY',
	SECRET 'FRESH_SECRET',
	ENDPOINT '%s',
	USE_SSL false,
	URL_STYLE 'path'
))",
	                                                     server.Endpoint()));

	const string gcs_path = "gcs://refresh-bucket/object.bin";
	auto &fs = FileSystem::GetFileSystem(*con.context);
	S3TestHelper::RequireQueryOk(con, "BEGIN TRANSACTION");
	auto glob_result = fs.Glob("gcs://refresh-bucket/*.bin", FileGlobOptions::ALLOW_EMPTY, nullptr);
	auto listed_files = glob_result->GetAllFiles();
	REQUIRE(listed_files.size() == 1);
	REQUIRE(listed_files[0].extended_info);
	REQUIRE(listed_files[0].extended_info->options.count("s3_region") == 0);
	S3TestHelper::RequireQueryOk(con, "COMMIT");

	auto read_byte = [&](const OpenFileInfo &file, idx_t offset) {
		S3TestHelper::RequireQueryOk(con, "BEGIN TRANSACTION");
		auto handle = fs.OpenFile(file, FileFlags::FILE_FLAGS_READ | FileFlags::FILE_FLAGS_DIRECT_IO);
		REQUIRE(handle);
		char result;
		handle->Read(QueryContext(*con.context), &result, 1, offset);
		REQUIRE(result == server.ObjectData()[offset]);
		S3TestHelper::RequireQueryOk(con, "COMMIT");
	};
	read_byte(OpenFileInfo(gcs_path), 0);

	S3TestHelper::RequireQueryOk(con, StringUtil::Format(R"(
CREATE OR REPLACE SECRET gcs_hmac (
	TYPE GCS,
	SCOPE 'gcs://refresh-bucket/',
	KEY_ID 'FRESH_KEY',
	SECRET 'FRESH_SECRET',
	REGION 'eu-west-1',
	ENDPOINT '%s',
	USE_SSL false,
	URL_STYLE 'path'
))",
	                                                     server.Endpoint()));
	read_byte(listed_files[0], 1);

	auto observations = server.Observations();
	INFO(client_implementation);
	INFO(MockS3DescribeObservations(observations));
	idx_t head_count = 0;
	bool saw_auto_get = false;
	bool saw_explicit_get = false;
	for (const auto &observation : observations) {
		if (observation.target.find("object.bin") == string::npos) {
			continue;
		}
		if (observation.method == "HEAD") {
			head_count++;
			REQUIRE(observation.region == "auto");
			REQUIRE(StringUtil::Contains(observation.authorization, "/auto/s3/aws4_request"));
		} else if (observation.method == "GET") {
			if (observation.region == "auto") {
				saw_auto_get = true;
				REQUIRE(StringUtil::Contains(observation.authorization, "/auto/s3/aws4_request"));
			} else if (observation.region == "eu-west-1") {
				saw_explicit_get = true;
				REQUIRE(StringUtil::Contains(observation.authorization, "/eu-west-1/s3/aws4_request"));
			}
		}
	}
	REQUIRE(head_count == 1);
	REQUIRE(saw_auto_get);
	REQUIRE(saw_explicit_get);
}

static void RunGCSBearerRequestScenario(const string &client_implementation) {
	MockS3ServerConfig config;
	config.auth.stale_key_id = "NEVER_STALE";
	MockS3Server server(std::move(config));

	DuckDB db(nullptr);
	Connection con(db);
	S3TestHelper::LoadExtension(db);
	ConfigureGCSBearer(con, server, client_implementation, "billing-project");

	const string gcs_path = "gcs://refresh-bucket/object.bin";
	S3TestHelper::RequireQueryOk(con, "BEGIN TRANSACTION");
	auto &fs = FileSystem::GetFileSystem(*con.context);
	auto handle = fs.OpenFile(gcs_path, FileFlags::FILE_FLAGS_READ | FileFlags::FILE_FLAGS_DIRECT_IO);
	REQUIRE(handle);
	char result;
	handle->Read(QueryContext(*con.context), &result, 1, 0);
	REQUIRE(result == server.ObjectData()[0]);
	handle.reset();

	auto list_result = con.Query("SELECT file FROM glob('gcs://refresh-bucket/*.bin')");
	REQUIRE(list_result);
	INFO((list_result->HasError() ? list_result->GetError() : string()));
	REQUIRE_FALSE(list_result->HasError());
	REQUIRE(list_result->RowCount() == 1);

	fs.RemoveFile(gcs_path);
	fs.RemoveFiles({gcs_path, "gcs://refresh-bucket/another.bin"});
	S3TestHelper::RequireQueryOk(con, "COMMIT");

	auto observations = server.Observations();
	INFO(MockS3DescribeObservations(observations));
	bool saw_object = false;
	bool saw_read = false;
	bool saw_list = false;
	bool saw_single_delete = false;
	bool saw_bulk_delete = false;
	for (const auto &observation : observations) {
		REQUIRE(MockS3HeaderValues(observation, "x-goog-user-project") == vector<string> {"billing-project"});
		REQUIRE(MockS3HeaderValues(observation, "x-amz-request-payer").empty());
		if (observation.authorization != "Bearer gcs-test-token") {
			continue;
		}
		saw_object |= observation.method == "HEAD" && observation.target.find("object.bin") != string::npos;
		saw_read |= observation.method == "GET" && !observation.range.empty();
		if (observation.method == "GET" && observation.target.find("list-type=2") != string::npos) {
			saw_list = true;
			REQUIRE(observation.target.find("?encoding-type=url&list-type=2&prefix=") != string::npos);
		}
		if (observation.method == "POST" && observation.target.find("delete") != string::npos) {
			saw_bulk_delete = true;
			REQUIRE(StringUtil::EndsWith(observation.target, "?delete="));
		}
		saw_single_delete |= observation.method == "DELETE";
	}
	REQUIRE(saw_object);
	REQUIRE(saw_read);
	REQUIRE(saw_list);
	REQUIRE(saw_single_delete);
	REQUIRE(saw_bulk_delete);
}

static void RunBulkDeleteSecretIdentityScenario(const string &client_implementation) {
	MockS3ServerConfig config;
	config.auth.stale_key_id = "NEVER_STALE";
	MockS3Server server(std::move(config));

	DuckDB db(nullptr);
	Connection con(db);
	S3TestHelper::LoadExtension(db);
	S3TestHelper::RegisterRefreshProvider(db);
	S3TestHelper::RequireQueryOk(con,
	                             StringUtil::Format("SET httpfs_client_implementation='%s'", client_implementation));
	S3TestHelper::RequireQueryOk(con, "SET httpfs_connection_caching=false");
	for (const auto &entry :
	     {pair<string, string> {"delete_identity_a", "a"}, pair<string, string> {"delete_identity_b", "b"}}) {
		auto test_id = S3TestHelper::NextTestId();
		S3TestHelper::RequireQueryOk(con, StringUtil::Format(R"(
CREATE SECRET %s (
	TYPE S3,
	PROVIDER %s,
	SCOPE 's3://refresh-bucket/%s/',
	KEY_ID '%s',
	SECRET '%s',
	REGION 'us-east-1',
	ENDPOINT '%s',
	USE_SSL false,
	URL_STYLE 'path',
	TEST_ID '%s',
	REFRESH_INFO MAP {
		'KEY_ID': '%s',
		'SECRET': '%s',
		'TEST_ID': '%s'
	}
))",
		                                                     entry.first, S3TestHelper::TEST_PROVIDER, entry.second,
		                                                     S3TestHelper::STALE_KEY_ID, S3TestHelper::STALE_SECRET,
		                                                     server.Endpoint(), test_id, S3TestHelper::FRESH_KEY_ID,
		                                                     S3TestHelper::FRESH_SECRET, test_id));
	}

	S3TestHelper::RequireQueryOk(con, "BEGIN TRANSACTION");
	auto &fs = FileSystem::GetFileSystem(*con.context);
	fs.RemoveFiles({"s3://refresh-bucket/a/object.bin", "s3://refresh-bucket/b/object.bin"});
	S3TestHelper::RequireQueryOk(con, "COMMIT");

	auto observations = server.Observations();
	INFO(MockS3DescribeObservations(observations));
	idx_t bulk_delete_requests = 0;
	for (const auto &observation : observations) {
		if (observation.method == "POST" && StringUtil::EndsWith(observation.target, "?delete=")) {
			bulk_delete_requests++;
		}
	}
	REQUIRE(bulk_delete_requests == 2);
}

static void RunGCSBulkDeleteProjectIdentityScenario(const string &client_implementation) {
	MockS3ServerConfig config;
	config.auth.stale_key_id = "NEVER_STALE";
	MockS3Server server(std::move(config));

	DuckDB db(nullptr);
	Connection con(db);
	S3TestHelper::LoadExtension(db);
	ConfigureGCSClient(con, client_implementation);
	S3TestHelper::RequireQueryOk(con, "SET enable_global_s3_configuration=false");
	S3TestHelper::RequireQueryOk(con, StringUtil::Format(R"(
CREATE SECRET gcs_delete_project (
	TYPE GCS,
	SCOPE 'gcs://refresh-bucket/',
	KEY_ID 'GCS_KEY',
	SECRET 'GCS_SECRET',
	ENDPOINT '%s',
	USE_SSL false,
	URL_STYLE 'path'
))",
	                                                     server.Endpoint()));

	S3TestHelper::RequireQueryOk(con, "BEGIN TRANSACTION");
	auto &fs = FileSystem::GetFileSystem(*con.context);
	fs.RemoveFiles({"gcs://refresh-bucket/a.bin?gcs_user_project=project-a",
	                "gcs://refresh-bucket/b.bin?gcs_user_project=project-b"});
	S3TestHelper::RequireQueryOk(con, "COMMIT");

	auto observations = server.Observations();
	INFO(MockS3DescribeObservations(observations));
	::AESStateSSLFactory encryption_util;
	auto get_delete_body_hash = [&](const string &key) {
		auto body = S3XMLWriter::WriteDeleteObjectsRequest({key}, 0, 1);
		return S3RequestUtil::GetPayloadHash(encryption_util, const_data_ptr_cast(body.data()), body.size());
	};
	const unordered_map<string, string> expected_payload_hashes {{"project-a", get_delete_body_hash("a.bin")},
	                                                             {"project-b", get_delete_body_hash("b.bin")}};
	idx_t bulk_delete_requests = 0;
	idx_t project_a_requests = 0;
	idx_t project_b_requests = 0;
	for (const auto &observation : observations) {
		if (observation.method != "POST" || !StringUtil::EndsWith(observation.target, "?delete=")) {
			continue;
		}
		bulk_delete_requests++;
		auto project_headers = MockS3HeaderValues(observation, "x-goog-user-project");
		REQUIRE(project_headers.size() == 1);
		REQUIRE(MockS3HeaderValues(observation, "x-amz-content-sha256") ==
		        vector<string> {expected_payload_hashes.at(project_headers[0])});
		project_a_requests += project_headers[0] == "project-a";
		project_b_requests += project_headers[0] == "project-b";
		REQUIRE(StringUtil::Contains(observation.authorization, "x-goog-user-project"));
	}
	REQUIRE(bulk_delete_requests == 2);
	REQUIRE(project_a_requests == 1);
	REQUIRE(project_b_requests == 1);
}

static void RunBulkDeleteEndpointModeIdentityScenario(const string &client_implementation) {
	MockS3ServerConfig config;
	config.auth.stale_key_id = "NEVER_STALE";
	MockS3Server server(std::move(config));

	DuckDB db(nullptr);
	Connection con(db);
	S3TestHelper::LoadExtension(db);
	S3TestHelper::RequireQueryOk(con,
	                             StringUtil::Format("SET httpfs_client_implementation='%s'", client_implementation));
	S3TestHelper::RequireQueryOk(con, "SET httpfs_connection_caching=false");
	S3TestHelper::RequireQueryOk(con, StringUtil::Format("SET http_proxy='http://%s'", server.Endpoint()));
	S3TestHelper::RequireQueryOk(con, R"(
CREATE SECRET delete_endpoint_mode (
	TYPE S3,
	SCOPE 's3://refresh-bucket/',
	KEY_ID 'FRESH_KEY',
	SECRET 'S3TestHelper::FRESH_SECRET',
	REGION 'us-east-1',
	USE_SSL false,
	URL_STYLE 'path'
))");

	auto automatic_path = "s3://refresh-bucket/a/object.bin";
	auto explicit_path = "s3://refresh-bucket/b/object.bin?s3_endpoint=s3.us-east-1.amazonaws.com";
	S3TestHelper::RequireQueryOk(con, "BEGIN TRANSACTION");
	auto &fs = FileSystem::GetFileSystem(*con.context);
	fs.RemoveFiles({automatic_path, explicit_path});
	S3TestHelper::RequireQueryOk(con, "COMMIT");

	auto observations = server.Observations();
	INFO(MockS3DescribeObservations(observations));
	idx_t bulk_delete_requests = 0;
	for (const auto &observation : observations) {
		if (observation.method == "POST" && StringUtil::EndsWith(observation.target, "?delete=")) {
			bulk_delete_requests++;
		}
	}
	REQUIRE(bulk_delete_requests == 2);
}

enum class BulkDeleteProviderProfile : uint8_t { S3, R2_SCHEME, R2_ENDPOINT };

static void RunBulkDeleteBatchLimitScenario(const string &client_implementation, BulkDeleteProviderProfile profile) {
	const bool uses_r2_profile = profile != BulkDeleteProviderProfile::S3;
	const auto key_count = uses_r2_profile ? 701 : 1000;

	MockS3ServerConfig config;
	config.auth.stale_key_id = "NEVER_STALE";
	config.bulk_delete.maximum_key_count = uses_r2_profile ? 700 : 1000;
	MockS3Server server(std::move(config));

	DuckDB db(nullptr);
	Connection con(db);
	S3TestHelper::LoadExtension(db);
	S3TestHelper::RequireQueryOk(con,
	                             StringUtil::Format("SET httpfs_client_implementation='%s'", client_implementation));
	S3TestHelper::RequireQueryOk(con, "SET httpfs_connection_caching=false");
	S3TestHelper::RequireQueryOk(con, "SET enable_global_s3_configuration=false");

	const auto uses_r2_endpoint = profile == BulkDeleteProviderProfile::R2_ENDPOINT;
	auto endpoint = uses_r2_endpoint ? "account.r2.cloudflarestorage.com" : server.Endpoint();
	if (uses_r2_endpoint) {
		S3TestHelper::RequireQueryOk(con, StringUtil::Format("SET http_proxy='http://%s'", server.Endpoint()));
	}
	auto secret_type = profile == BulkDeleteProviderProfile::R2_SCHEME ? "R2" : "S3";
	auto scheme = profile == BulkDeleteProviderProfile::R2_SCHEME ? "r2" : "s3";
	auto region = uses_r2_profile ? "auto" : "us-east-1";
	S3TestHelper::RequireQueryOk(con, StringUtil::Format(R"(
CREATE SECRET delete_batch_limit (
	TYPE %s,
	KEY_ID 'FRESH_KEY',
	SECRET 'FRESH_SECRET',
	REGION '%s',
	ENDPOINT '%s',
	USE_SSL false,
	URL_STYLE 'path'
))",
	                                                     secret_type, region, endpoint));

	S3TestHelper::RequireQueryOk(con, "BEGIN TRANSACTION");
	auto &fs = FileSystem::GetFileSystem(*con.context);
	fs.RemoveFiles(S3TestHelper::CreateBulkDeletePaths(scheme, key_count));
	S3TestHelper::RequireQueryOk(con, "COMMIT");

	auto observations = server.Observations();
	INFO(MockS3DescribeObservations(observations));
	vector<idx_t> observed_batch_sizes;
	for (const auto &observation : observations) {
		if (observation.method == "POST" && StringUtil::EndsWith(observation.target, "?delete=")) {
			observed_batch_sizes.push_back(observation.delete_key_count);
		}
	}
	if (uses_r2_profile) {
		REQUIRE(observed_batch_sizes == vector<idx_t> {700, 1});
	} else {
		REQUIRE(observed_batch_sizes == vector<idx_t> {1000});
	}
}

static void RunGCSListAuthErrorScenario(const string &client_implementation) {
	MockS3ServerConfig config;
	config.auth.stale_authorization = "Bearer gcs-test-token";
	config.auth.refresh_target = MockS3RefreshTarget::LIST_OBJECTS_GET;
	MockS3Server server(std::move(config));

	DuckDB db(nullptr);
	Connection con(db);
	S3TestHelper::LoadExtension(db);
	ConfigureGCSBearer(con, server, client_implementation);

	auto result = con.Query("SELECT file FROM glob('gcs://refresh-bucket/*.bin')");
	REQUIRE(result);
	REQUIRE(result->HasError());
	INFO(result->GetError());
	REQUIRE(result->GetError().find("Authentication Failure - GCS authentication failed") != string::npos);
}

static S3AuthParams ReadSecretAuthParams(Connection &con, KeyValueSecret &secret,
                                         const string &path = "s3://bucket/key") {
	ClientContextFileOpener opener(*con.context);
	S3KeyValueReader secret_reader {KeyValueSecretReader(secret, opener)};
	return S3AuthResolver::Resolve(secret_reader, path);
}

} // namespace

TEST_CASE("S3 provider policy resolves URL aliases and default scopes", "[httpfs][s3][provider]") {
	for (const auto &entry : {pair<string, S3ProviderType> {"s3://bucket/key", S3ProviderType::S3},
	                          pair<string, S3ProviderType> {"S3A://bucket/key", S3ProviderType::S3},
	                          pair<string, S3ProviderType> {"s3n://bucket/key", S3ProviderType::S3},
	                          pair<string, S3ProviderType> {"gcs://bucket/key", S3ProviderType::GCS},
	                          pair<string, S3ProviderType> {"GS://bucket/key", S3ProviderType::GCS},
	                          pair<string, S3ProviderType> {"r2://bucket/key", S3ProviderType::R2}}) {
		auto provider_match = S3UrlScheme::Match(entry.first);
		REQUIRE(provider_match.type == entry.second);
	}
	REQUIRE_FALSE(S3UrlScheme::TryMatch("https://bucket/key"));
	REQUIRE_FALSE(S3UrlScheme::TryMatch("aws://bucket/key"));
	REQUIRE(S3SecretConfig::DefaultSecretScope("s3") == vector<string> {"s3://", "s3n://", "s3a://"});
	REQUIRE(S3SecretConfig::DefaultSecretScope("gcs") == vector<string> {"gcs://", "gs://"});
	REQUIRE(S3SecretConfig::DefaultSecretScope("r2") == vector<string> {"r2://"});
	REQUIRE(S3SecretConfig::DefaultSecretScope("aws") == vector<string> {""});
	try {
		S3UrlScheme::Match("https://bucket/key");
		FAIL("Unsupported URL should fail");
	} catch (std::exception &ex) {
		auto error = string(ex.what());
		REQUIRE(error.find("s3a://") != string::npos);
		REQUIRE(error.find("s3n://") != string::npos);
		REQUIRE(error.find("gs://") != string::npos);
	}
}

TEST_CASE("S3 provider selects multipart upload policy", "[httpfs][s3][provider][upload]") {
	static constexpr idx_t MIB = 1024ULL * 1024ULL;
	static constexpr idx_t GIB = 1024ULL * MIB;
	const S3MultipartUploadPolicy adaptive_policy {S3MultipartPartSizeStrategy::ADAPTIVE, 5ULL * MIB, 5ULL * GIB, 10000,
	                                               optional_idx()};
	const S3MultipartUploadPolicy fixed_policy {S3MultipartPartSizeStrategy::FIXED, 8ULL * MIB, 5115ULL * MIB, 10000,
	                                            5115ULL * GIB};
	auto require_policy = [](S3ProviderType provider_type, const string &endpoint,
	                         const S3MultipartUploadPolicy &expected, bool scheme_is_alias = false) {
		auto config = TestAuthConfig(provider_type, scheme_is_alias);
		config.endpoint = endpoint;
		config.endpoint_mode = S3EndpointMode::EXPLICIT;
		auto auth_params = ResolveTestAuth(std::move(config));
		INFO(endpoint);
		auto policy = auth_params.GetProvider().GetMultipartUploadPolicy();
		REQUIRE(policy.part_size_strategy == expected.part_size_strategy);
		REQUIRE(policy.minimum_part_size == expected.minimum_part_size);
		REQUIRE(policy.maximum_part_size == expected.maximum_part_size);
		REQUIRE(policy.maximum_part_count == expected.maximum_part_count);
		REQUIRE(policy.maximum_object_size == expected.maximum_object_size);
	};

	require_policy(S3ProviderType::R2, "localhost:9000", fixed_policy);
	require_policy(S3ProviderType::S3, "account.r2.cloudflarestorage.com", fixed_policy);
	require_policy(S3ProviderType::S3, "account.eu.r2.cloudflarestorage.com", fixed_policy);
	require_policy(S3ProviderType::S3, "ACCOUNT.FEDRAMP.R2.CLOUDFLARESTORAGE.COM:443/path", fixed_policy);
	require_policy(S3ProviderType::S3, "https://ACCOUNT.EU.R2.CLOUDFLARESTORAGE.COM:443/path", fixed_policy);
	require_policy(S3ProviderType::S3, "account.us.r2.cloudflarestorage.com", fixed_policy, true);

	require_policy(S3ProviderType::S3, "s3.amazonaws.com", adaptive_policy);
	require_policy(S3ProviderType::GCS, "account.r2.cloudflarestorage.com", adaptive_policy);
	require_policy(S3ProviderType::S3, "r2.cloudflarestorage.com", adaptive_policy);
	require_policy(S3ProviderType::S3, "account.r2.cloudflarestorage.com.example.com", adaptive_policy);
	require_policy(S3ProviderType::S3, "evilr2.cloudflarestorage.com", adaptive_policy);
	require_policy(S3ProviderType::S3, "objects.example.com", adaptive_policy);
	require_policy(S3ProviderType::S3, "a.b.r2.cloudflarestorage.com", adaptive_policy);
}

TEST_CASE("S3 provider selects bulk delete limits", "[httpfs][s3][provider][delete]") {
	auto require_limit = [](S3ProviderType provider_type, const string &endpoint, idx_t expected) {
		auto config = TestAuthConfig(provider_type);
		config.endpoint = endpoint;
		config.endpoint_mode = S3EndpointMode::EXPLICIT;
		auto auth_params = ResolveTestAuth(std::move(config));
		INFO(endpoint);
		REQUIRE(auth_params.GetProvider().GetBulkDeleteMaxBatchSize() == expected);
	};

	require_limit(S3ProviderType::R2, "localhost:9000", 700);
	require_limit(S3ProviderType::S3, "account.r2.cloudflarestorage.com", 700);
	require_limit(S3ProviderType::S3, "account.eu.r2.cloudflarestorage.com", 700);
	require_limit(S3ProviderType::S3, "ACCOUNT.FEDRAMP.R2.CLOUDFLARESTORAGE.COM:443/path", 700);
	require_limit(S3ProviderType::S3, "https://ACCOUNT.EU.R2.CLOUDFLARESTORAGE.COM:443/path", 700);

	require_limit(S3ProviderType::S3, "s3.amazonaws.com", 1000);
	require_limit(S3ProviderType::GCS, "account.r2.cloudflarestorage.com", 1000);
	require_limit(S3ProviderType::S3, "r2.cloudflarestorage.com", 1000);
	require_limit(S3ProviderType::S3, "account.r2.cloudflarestorage.com.example.com", 1000);
	require_limit(S3ProviderType::S3, "evilr2.cloudflarestorage.com", 1000);
	require_limit(S3ProviderType::S3, "a.b.r2.cloudflarestorage.com", 1000);
}

TEST_CASE("S3 endpoint provenance controls AWS endpoint derivation", "[httpfs][s3][provider][endpoint]") {
	SECTION("automatic endpoints retain the existing region defaults") {
		auto anonymous_config = TestAuthConfig();
		anonymous_config.endpoint = "  ";
		auto anonymous = ResolveTestAuth(std::move(anonymous_config));
		REQUIRE(anonymous.GetURLParams().endpoint_mode == S3EndpointMode::AUTOMATIC);
		REQUIRE(anonymous.GetCredentials().region.empty());
		REQUIRE(anonymous.GetURLParams().endpoint.GetHost() == "s3.amazonaws.com");

		auto credentialed_config = TestAuthConfig();
		credentialed_config.endpoint = "s3.amazonaws.com";
		credentialed_config.endpoint_mode = S3EndpointMode::EXPLICIT;
		credentialed_config.credentials.access_key_id = "key";
		auto credentialed = ResolveTestAuth(std::move(credentialed_config));
		REQUIRE(credentialed.GetURLParams().endpoint_mode == S3EndpointMode::AUTOMATIC);
		REQUIRE(credentialed.GetCredentials().region == "us-east-1");
		REQUIRE(credentialed.GetURLParams().endpoint.GetHost() == "s3.us-east-1.amazonaws.com");
	}

	SECTION("explicit endpoints keep their host") {
		for (const auto &endpoint : {"s3.dualstack.us-east-1.amazonaws.com", "s3-fips.us-east-1.amazonaws.com",
		                             "s3.eu-west-1.amazonaws.com", "storage.example.com"}) {
			auto config = TestAuthConfig();
			config.endpoint = endpoint;
			config.endpoint_mode = S3EndpointMode::EXPLICIT;
			auto auth_params = ResolveTestAuth(std::move(config));
			INFO(endpoint);
			REQUIRE(auth_params.GetURLParams().endpoint_mode == S3EndpointMode::EXPLICIT);
			REQUIRE(auth_params.GetURLParams().endpoint.GetHost() == endpoint);
			REQUIRE(auth_params.GetCredentials().region.empty());
			auth_params = auth_params.WithRegion("ap-southeast-2");
			REQUIRE(auth_params.GetURLParams().endpoint.GetHost() == endpoint);
		}
	}

	SECTION("AWS-shaped explicit endpoints retain the old credentialed region fallback") {
		auto dualstack_config = TestAuthConfig();
		dualstack_config.endpoint = "s3.dualstack.us-east-1.amazonaws.com";
		dualstack_config.endpoint_mode = S3EndpointMode::EXPLICIT;
		dualstack_config.credentials.access_key_id = "key";
		auto dualstack = ResolveTestAuth(std::move(dualstack_config));
		REQUIRE(dualstack.GetCredentials().region == "us-east-1");
		REQUIRE(dualstack.GetURLParams().endpoint.GetHost() == "s3.dualstack.us-east-1.amazonaws.com");

		auto fips_config = TestAuthConfig();
		fips_config.endpoint = "s3-fips.us-east-1.amazonaws.com";
		fips_config.endpoint_mode = S3EndpointMode::EXPLICIT;
		fips_config.credentials.access_key_id = "key";
		auto fips = ResolveTestAuth(std::move(fips_config));
		REQUIRE(fips.GetCredentials().region.empty());
		REQUIRE(fips.GetURLParams().endpoint.GetHost() == "s3-fips.us-east-1.amazonaws.com");
	}

	SECTION("endpoint mode participates in authentication identity") {
		auto automatic_config = TestAuthConfig();
		automatic_config.credentials.region = "us-east-1";
		auto automatic = ResolveTestAuth(std::move(automatic_config));
		auto explicit_config = TestAuthConfig();
		explicit_config.credentials.region = "us-east-1";
		explicit_config.endpoint = "s3.us-east-1.amazonaws.com";
		explicit_config.endpoint_mode = S3EndpointMode::EXPLICIT;
		auto explicit_endpoint = ResolveTestAuth(std::move(explicit_config));
		REQUIRE(automatic.GetURLParams().endpoint.GetHost() == explicit_endpoint.GetURLParams().endpoint.GetHost());
		REQUIRE_FALSE(automatic == explicit_endpoint);
	}
}

TEST_CASE("S3 endpoints are normalized once for routing and signing", "[httpfs][s3][provider][endpoint]") {
	SECTION("full URI schemes override the legacy SSL flag") {
		auto config = TestAuthConfig();
		config.use_ssl = false;
		config.url_style = "path";
		config.endpoint = "HTTPS://Storage.EXAMPLE.com:443/gateway/%2f//base///";
		config.endpoint_mode = S3EndpointMode::EXPLICIT;
		auto auth_params = ResolveTestAuth(std::move(config));

		REQUIRE(auth_params.GetURLParams().endpoint.UsesSSL());
		REQUIRE(auth_params.GetURLParams().endpoint.GetHost() == "storage.example.com");
		REQUIRE(auth_params.GetURLParams().endpoint.GetAuthority() == "storage.example.com");
		REQUIRE(auth_params.GetURLParams().endpoint.GetBasePath() == "/gateway/%2f//base");

		auto parsed_url = S3Url::Parse("s3://bucket/key with space", auth_params);
		REQUIRE(parsed_url.GetEncodedBucketPath() == "/gateway/%2f//base/bucket/");
		REQUIRE(parsed_url.GetEncodedPath() == "/gateway/%2f//base/bucket/key%20with%20space");
		REQUIRE(parsed_url.GetHTTPUrl() == "https://storage.example.com/gateway/%2f//base/bucket/key%20with%20space");
	}

	SECTION("schemeless endpoints retain the SSL fallback and non-default ports") {
		auto config = TestAuthConfig();
		config.use_ssl = false;
		config.url_style = "path";
		config.endpoint = "Storage.EXAMPLE.com:8443/base/";
		config.endpoint_mode = S3EndpointMode::EXPLICIT;
		auto auth_params = ResolveTestAuth(std::move(config));
		auto parsed_url = S3Url::Parse("s3://bucket/key", auth_params);
		REQUIRE(parsed_url.GetHost() == "storage.example.com:8443");
		REQUIRE(parsed_url.GetHTTPUrl() == "http://storage.example.com:8443/base/bucket/key");
	}

	SECTION("legacy base paths remain opaque when they contain URI-like text") {
		auto config = TestAuthConfig();
		config.use_ssl = false;
		config.url_style = "path";
		config.endpoint = "storage.example.com/gateway/http://mirror";
		config.endpoint_mode = S3EndpointMode::EXPLICIT;
		auto auth_params = ResolveTestAuth(std::move(config));
		auto parsed_url = S3Url::Parse("s3://bucket/key", auth_params);
		REQUIRE(auth_params.GetURLParams().endpoint.GetBasePath() == "/gateway/http://mirror");
		REQUIRE(parsed_url.GetHTTPUrl() == "http://storage.example.com/gateway/http%3A//mirror/bucket/key");
	}

	SECTION("valid port boundaries are preserved") {
		for (const auto &endpoint : {"storage.example.com:1", "storage.example.com:65535"}) {
			auto config = TestAuthConfig();
			config.endpoint = endpoint;
			config.endpoint_mode = S3EndpointMode::EXPLICIT;
			auto auth_params = ResolveTestAuth(std::move(config));
			REQUIRE(auth_params.GetURLParams().endpoint.GetAuthority() == endpoint);
		}
	}

	SECTION("virtual-hosted endpoints keep their base path separate from the bucket") {
		auto config = TestAuthConfig();
		config.use_ssl = true;
		config.url_style = "virtual";
		config.endpoint = "http://storage.example.com:80/gateway/base/";
		config.endpoint_mode = S3EndpointMode::EXPLICIT;
		auto auth_params = ResolveTestAuth(std::move(config));
		auto parsed_url = S3Url::Parse("s3://bucket/key", auth_params);
		REQUIRE(parsed_url.GetHost() == "bucket.storage.example.com");
		REQUIRE(parsed_url.GetEncodedPath() == "/gateway/base/key");
		REQUIRE(parsed_url.GetEncodedBucketPath() == "/gateway/base/");
		REQUIRE(parsed_url.GetHTTPUrl() == "http://bucket.storage.example.com/gateway/base/key");
	}

	SECTION("full default AWS endpoints retain automatic region derivation") {
		auto config = TestAuthConfig();
		config.use_ssl = false;
		config.credentials.access_key_id = "key";
		config.endpoint = "HTTPS://S3.AMAZONAWS.COM:443/";
		config.endpoint_mode = S3EndpointMode::EXPLICIT;
		auto auth_params = ResolveTestAuth(std::move(config));
		REQUIRE(auth_params.GetURLParams().endpoint_mode == S3EndpointMode::AUTOMATIC);
		REQUIRE(auth_params.GetCredentials().region == "us-east-1");
		REQUIRE(auth_params.GetURLParams().endpoint.GetHost() == "s3.us-east-1.amazonaws.com");
		REQUIRE(auth_params.GetURLParams().endpoint.GetProtocol() == "https://");
		REQUIRE(auth_params.GetURLParams().endpoint.GetAuthority() == "s3.us-east-1.amazonaws.com");
	}

	SECTION("canonical endpoint forms share authentication identity") {
		auto legacy_config = TestAuthConfig();
		legacy_config.url_style = "path";
		legacy_config.endpoint = "STORAGE.EXAMPLE.COM:443/base/";
		legacy_config.endpoint_mode = S3EndpointMode::EXPLICIT;
		auto legacy = ResolveTestAuth(std::move(legacy_config));

		auto uri_config = TestAuthConfig();
		uri_config.use_ssl = false;
		uri_config.url_style = "path";
		uri_config.endpoint = "https://storage.example.com/base";
		uri_config.endpoint_mode = S3EndpointMode::EXPLICIT;
		auto uri = ResolveTestAuth(std::move(uri_config));
		REQUIRE(legacy == uri);
	}

	SECTION("a URL override replaces an invalid lower-precedence endpoint") {
		auto config = TestAuthConfig();
		config.endpoint = "ftp://invalid.example.com";
		config.endpoint_mode = S3EndpointMode::EXPLICIT;
		auto url = string("s3://bucket/key?s3_endpoint=http%3A%2F%2Fstorage.example.com%3A80%2Fbase&") +
		           "s3_use_ssl=true&s3_url_style=path";
		auto auth_params = ResolveTestAuth(std::move(config), url);
		auto parsed_url = S3Url::Parse(url, auth_params);
		REQUIRE(parsed_url.GetHost() == "storage.example.com");
		REQUIRE(parsed_url.GetEncodedPath() == "/base/bucket/key");
		REQUIRE(parsed_url.GetHTTPUrl() == "http://storage.example.com/base/bucket/key");
	}

	SECTION("bracketed IPv6 is supported only with path-style addressing") {
		auto path_config = TestAuthConfig();
		path_config.url_style = "path";
		path_config.endpoint = "http://[2001:DB8::1]:80/base";
		path_config.endpoint_mode = S3EndpointMode::EXPLICIT;
		auto path_style = ResolveTestAuth(std::move(path_config));
		auto parsed_url = S3Url::Parse("s3://bucket/key", path_style);
		REQUIRE(parsed_url.GetHost() == "[2001:db8::1]");
		REQUIRE(parsed_url.GetHTTPUrl() == "http://[2001:db8::1]/base/bucket/key");

		auto vhost_config = TestAuthConfig();
		vhost_config.endpoint = "http://[::1]";
		vhost_config.endpoint_mode = S3EndpointMode::EXPLICIT;
		auto vhost_style = ResolveTestAuth(std::move(vhost_config));
		REQUIRE_THROWS(S3Url::Parse("s3://bucket/key", vhost_style));
	}
}

TEST_CASE("Invalid S3 endpoints fail before request construction", "[httpfs][s3][provider][endpoint]") {
	for (const auto &endpoint :
	     {"ftp://storage.example.com", "http://", "http://user@storage.example.com",
	      "http://storage.example.com?query=value", "http://storage.example.com#fragment", "storage.example.com:0",
	      "storage.example.com:65536", "storage.example.com:", "storage.example.com:port", "storage.example.com\\base",
	      "storage.example.com/base/%", "storage.example.com/base/./key", "storage.example.com/base/../key",
	      "2001:db8::1", "http://[fe80::1%25lo0]", "http://[2001:db8::1"}) {
		auto config = TestAuthConfig();
		config.endpoint = endpoint;
		config.endpoint_mode = S3EndpointMode::EXPLICIT;
		INFO(endpoint);
		REQUIRE_THROWS(ResolveTestAuth(std::move(config)));
	}
}

TEST_CASE("S3 provider endpoint precedence is preserved", "[httpfs][s3][provider][endpoint][secret]") {
	DuckDB db(nullptr);
	Connection con(db);
	S3TestHelper::LoadExtension(db);
	S3TestHelper::RequireQueryOk(con, "SET s3_endpoint='setting.example.com'");

	SECTION("GCS ignores the endpoint setting") {
		KeyValueSecret secret({"gcs://"}, Identifier("gcs"), Identifier("config"), Identifier("gcs_default"));
		auto auth_params = ReadSecretAuthParams(con, secret, "gcs://bucket/key");
		REQUIRE(auth_params.GetURLParams().endpoint.GetHost() == "storage.googleapis.com");
		REQUIRE(auth_params.GetURLParams().endpoint_mode == S3EndpointMode::AUTOMATIC);
	}

	SECTION("GCS accepts a secret endpoint") {
		KeyValueSecret secret({"gcs://"}, Identifier("gcs"), Identifier("config"), Identifier("gcs_explicit"));
		secret.secret_map["endpoint"] = "gcs.example.com";
		auto auth_params = ReadSecretAuthParams(con, secret, "gcs://bucket/key");
		REQUIRE(auth_params.GetURLParams().endpoint.GetHost() == "gcs.example.com");
		REQUIRE(auth_params.GetURLParams().endpoint_mode == S3EndpointMode::EXPLICIT);
	}
}

TEST_CASE("GCS billing projects follow provider configuration precedence",
          "[httpfs][s3][gcs][provider][requester-pays]") {
	DuckDB db(nullptr);
	Connection con(db);
	S3TestHelper::LoadExtension(db);
	S3TestHelper::RequireQueryOk(con, "SET gcs_user_project='setting-project'");

	KeyValueSecret secret({"gcs://"}, Identifier("gcs"), Identifier("config"), Identifier("gcs_billing"));
	auto auth_params = ReadSecretAuthParams(con, secret, "gcs://bucket/key");
	REQUIRE(auth_params.GetRequestOptions().user_project == "setting-project");

	secret.secret_map["user_project"] = "secret-project";
	auth_params = ReadSecretAuthParams(con, secret, "gcs://bucket/key");
	REQUIRE(auth_params.GetRequestOptions().user_project == "secret-project");

	auth_params = ReadSecretAuthParams(con, secret, "gcs://bucket/key?gcs_user_project=url%2Dproject");
	REQUIRE(auth_params.GetRequestOptions().user_project == "url-project");

	auth_params = ReadSecretAuthParams(con, secret, "gcs://bucket/key?gcs_user_project=");
	REQUIRE(auth_params.GetRequestOptions().user_project.empty());

	auto distinct_project = ReadSecretAuthParams(con, secret, "gcs://bucket/key?gcs_user_project=different-project");
	REQUIRE_FALSE(auth_params == distinct_project);

	SECTION("the setting does not enter S3 or R2 authentication state") {
		KeyValueSecret s3_secret({"s3://"}, Identifier("s3"), Identifier("config"), Identifier("s3_billing"));
		REQUIRE(ReadSecretAuthParams(con, s3_secret).GetRequestOptions().user_project.empty());

		KeyValueSecret r2_secret({"r2://"}, Identifier("r2"), Identifier("config"), Identifier("r2_billing"));
		r2_secret.secret_map["endpoint"] = "account.r2.cloudflarestorage.com";
		REQUIRE(ReadSecretAuthParams(con, r2_secret, "r2://bucket/key").GetRequestOptions().user_project.empty());
	}

	SECTION("the URL parameter is GCS-only") {
		REQUIRE_THROWS(ResolveTestAuth(TestAuthConfig(), "s3://bucket/key?gcs_user_project=project"));

		auto r2_config = TestAuthConfig(S3ProviderType::R2);
		r2_config.endpoint = "account.r2.cloudflarestorage.com";
		r2_config.endpoint_mode = S3EndpointMode::EXPLICIT;
		REQUIRE_THROWS(ResolveTestAuth(std::move(r2_config), "r2://bucket/key?gcs_user_project=project"));
	}

	SECTION("legacy requester-pays requires a project after URL overrides") {
		auto require_missing_project_error = [](const string &url, S3AuthConfig config) {
			string error;
			try {
				ResolveTestAuth(std::move(config), url);
			} catch (std::exception &ex) {
				error = ex.what();
			}
			REQUIRE(StringUtil::Contains(error, "GCS Requester Pays requires a billing project"));
			REQUIRE(StringUtil::Contains(error, "USER_PROJECT in the GCS secret"));
			REQUIRE(StringUtil::Contains(error, "set gcs_user_project"));
			REQUIRE(StringUtil::Contains(error, "pass gcs_user_project in the URL"));
		};

		auto requester_pays = TestAuthConfig(S3ProviderType::GCS);
		requester_pays.request_options.requester_pays = true;
		require_missing_project_error("gcs://bucket/key", requester_pays);

		requester_pays.request_options.user_project = "secret-project";
		require_missing_project_error("gcs://bucket/key?gcs_user_project=", requester_pays);

		auto resolved = ResolveTestAuth(std::move(requester_pays), "gcs://bucket/key");
		REQUIRE(resolved.GetRequestOptions().user_project == "secret-project");
	}
}

TEST_CASE("S3 URL styles share one validation policy", "[httpfs][s3][provider][url-style]") {
	for (const auto &url_style : {"", "vhost", "virtual"}) {
		INFO(url_style);
		REQUIRE(S3AuthURLParams::ParseStyle(url_style) == S3URLStyle::VIRTUAL_HOSTED);
	}
	REQUIRE(S3AuthURLParams::ParseStyle("path") == S3URLStyle::PATH);
	for (const auto &url_style : {"default", "VHOST", "handwritten"}) {
		INFO(url_style);
		REQUIRE_THROWS(S3AuthURLParams::ParseStyle(url_style));
	}

	SECTION("invalid configuration is rejected before a runtime value is created") {
		auto config = TestAuthConfig();
		config.url_style = "handwritten";
		REQUIRE_THROWS(ResolveTestAuth(std::move(config)));
	}

	SECTION("URL query values remain case-sensitive") {
		REQUIRE_THROWS(ResolveTestAuth(TestAuthConfig(), "s3://bucket/key?s3_url_style=VHOST"));
	}

	SECTION("compatibility mode keeps query-looking key text literal") {
		auto config = TestAuthConfig();
		config.compatibility_mode = true;
		auto auth_params = ResolveTestAuth(std::move(config));
		auto parsed = S3Url::Parse("s3://bucket/key?s3_url_style=handwritten", auth_params);
		REQUIRE(parsed.GetQueryString().empty());
		REQUIRE(parsed.GetKey() == "key?s3_url_style=handwritten");
	}

	SECTION("dotted buckets use path style over TLS") {
		auto config = TestAuthConfig();
		config.url_style = "virtual";
		auto auth_params = ResolveTestAuth(std::move(config));
		auto parsed = S3Url::Parse("s3://bucket.with.dots/key", auth_params);
		REQUIRE(parsed.GetHost() == "s3.amazonaws.com");
		REQUIRE(parsed.GetEncodedPath() == "/bucket.with.dots/key");
	}
}

TEST_CASE("S3 URL style validation happens before request dispatch", "[httpfs][s3][url-style][request]") {
	MockS3ServerConfig config;
	config.auth.stale_key_id = "NEVER_STALE";
	MockS3Server server(std::move(config));
	DuckDB db(nullptr);
	Connection con(db);
	S3TestHelper::LoadExtension(db);
	S3TestHelper::RequireQueryOk(con, StringUtil::Format("SET s3_endpoint='%s'", server.Endpoint()));
	S3TestHelper::RequireQueryOk(con, "SET s3_region='us-east-1'");
	S3TestHelper::RequireQueryOk(con, "SET s3_use_ssl=false");

	for (const auto &url_style : {"", "vhost", "virtual", "path"}) {
		auto result = con.Query(StringUtil::Format("SET s3_url_style='%s'", url_style));
		INFO(url_style);
		REQUIRE(result);
		REQUIRE_FALSE(result->HasError());
	}
	for (const auto &url_style : {"default", "VHOST", "handwritten"}) {
		auto result = con.Query(StringUtil::Format("SET s3_url_style='%s'", url_style));
		INFO(url_style);
		REQUIRE(result);
		REQUIRE(result->HasError());
	}

	S3TestHelper::RequireQueryOk(con, "SET s3_url_style='path'");
	S3TestHelper::RequireQueryOk(con, "BEGIN TRANSACTION");
	auto &fs = FileSystem::GetFileSystem(*con.context);
	REQUIRE_THROWS(fs.OpenFile(string(S3TestHelper::S3_PATH) + "?s3_url_style=VHOST",
	                           FileFlags::FILE_FLAGS_READ | FileFlags::FILE_FLAGS_DIRECT_IO));
	REQUIRE(server.Observations().empty());
	S3TestHelper::RequireQueryOk(con, "ROLLBACK");

	DBConfig::GetConfig(*db.instance).SetOptionByName("s3_url_style", Value("handwritten"));
	Connection invalid_con(db);
	S3TestHelper::RequireQueryOk(invalid_con, "BEGIN TRANSACTION");
	auto &invalid_fs = FileSystem::GetFileSystem(*invalid_con.context);
	REQUIRE_THROWS(invalid_fs.OpenFile(string(S3TestHelper::S3_PATH) + "?s3_url_style=path",
	                                   FileFlags::FILE_FLAGS_READ | FileFlags::FILE_FLAGS_DIRECT_IO));
	REQUIRE(server.Observations().empty());
	S3TestHelper::RequireQueryOk(invalid_con, "ROLLBACK");
}

TEST_CASE("GCS Requester Pays validates the billing project before dispatch",
          "[httpfs][s3][gcs][requester-pays][request]") {
	MockS3ServerConfig config;
	config.auth.stale_key_id = "NEVER_STALE";
	MockS3Server server(std::move(config));
	DuckDB db(nullptr);
	Connection con(db);
	S3TestHelper::LoadExtension(db);
	S3TestHelper::RequireQueryOk(con, StringUtil::Format(R"(
CREATE SECRET invalid_gcs_requester_pays (
	TYPE GCS,
	SCOPE 'gcs://refresh-bucket/',
	KEY_ID 'GCS_KEY',
	SECRET 'GCS_SECRET',
	REQUESTER_PAYS true,
	ENDPOINT '%s',
	USE_SSL false,
	URL_STYLE 'path'
))",
	                                                     server.Endpoint()));

	S3TestHelper::RequireQueryOk(con, "BEGIN TRANSACTION");
	string error;
	try {
		auto &fs = FileSystem::GetFileSystem(*con.context);
		fs.OpenFile("gcs://refresh-bucket/object.bin", FileFlags::FILE_FLAGS_READ | FileFlags::FILE_FLAGS_DIRECT_IO);
	} catch (std::exception &ex) {
		error = ex.what();
	}
	REQUIRE(StringUtil::Contains(error, "GCS Requester Pays requires a billing project"));
	REQUIRE(StringUtil::Contains(error, "USER_PROJECT in the GCS secret"));
	REQUIRE(StringUtil::Contains(error, "set gcs_user_project"));
	REQUIRE(StringUtil::Contains(error, "pass gcs_user_project in the URL"));
	REQUIRE(server.Observations().empty());
	S3TestHelper::RequireQueryOk(con, "ROLLBACK");
}

TEST_CASE("S3 URL query settings are resolved independently of the HTTP client", "[httpfs][s3][url]") {
	SECTION("query credentials initialize the AWS region and endpoint") {
		auto config = TestAuthConfig();
		config.endpoint = "s3.amazonaws.com";
		auto auth_params = ResolveTestAuth(
		    std::move(config), "s3://bucket/key?s3_access_key_id=hello+world&s3_secret_access_key=secret%2Bvalue");
		auto parsed_url = S3Url::Parse("s3://bucket/key", auth_params);
		REQUIRE(auth_params.GetCredentials().access_key_id == "hello world");
		REQUIRE(auth_params.GetCredentials().secret_access_key == "secret+value");
		REQUIRE(auth_params.GetCredentials().region == "us-east-1");
		REQUIRE(auth_params.GetURLParams().endpoint.GetHost() == "s3.us-east-1.amazonaws.com");
		REQUIRE(parsed_url.GetHost() == "bucket.s3.us-east-1.amazonaws.com");
	}

	SECTION("routing overrides are reflected in the parsed URL") {
		auto config = TestAuthConfig();
		config.credentials.region = "us-west-2";
		config.endpoint = "s3.us-west-2.amazonaws.com";
		auto auth_params =
		    ResolveTestAuth(std::move(config), "s3://bucket/key?s3_region=eu-west-1&s3_endpoint=s3.amazonaws.com&"
		                                       "s3_use_ssl=false&s3_url_style=path");
		auto parsed_url = S3Url::Parse("s3://bucket/key", auth_params);
		REQUIRE(auth_params.GetCredentials().region == "eu-west-1");
		REQUIRE(auth_params.GetURLParams().endpoint.GetHost() == "s3.eu-west-1.amazonaws.com");
		REQUIRE(auth_params.GetURLParams().endpoint_mode == S3EndpointMode::AUTOMATIC);
		REQUIRE(parsed_url.GetHost() == "s3.eu-west-1.amazonaws.com");
		REQUIRE(parsed_url.GetEncodedPath() == "/bucket/key");
		REQUIRE(parsed_url.GetHTTPUrl() == "http://s3.eu-west-1.amazonaws.com/bucket/key");
	}

	SECTION("an endpoint override can switch from automatic to explicit") {
		auto config = TestAuthConfig();
		config.credentials.region = "us-east-1";
		auto auth_params =
		    ResolveTestAuth(std::move(config), "s3://bucket/key?s3_endpoint=s3.dualstack.us-east-1.amazonaws.com");
		auto parsed_url = S3Url::Parse("s3://bucket/key", auth_params);
		REQUIRE(auth_params.GetURLParams().endpoint_mode == S3EndpointMode::EXPLICIT);
		REQUIRE(auth_params.GetURLParams().endpoint.GetHost() == "s3.dualstack.us-east-1.amazonaws.com");
		REQUIRE(parsed_url.GetHost() == "bucket.s3.dualstack.us-east-1.amazonaws.com");
	}

	SECTION("empty GCS routing overrides restore provider defaults") {
		auto config = TestAuthConfig(S3ProviderType::GCS);
		config.endpoint = "storage.googleapis.com";
		config.url_style = "path";
		auto auth_params = ResolveTestAuth(std::move(config), "gcs://bucket/key?s3_endpoint=&s3_url_style=");
		auto parsed_url = S3Url::Parse("gcs://bucket/key", auth_params);
		REQUIRE(auth_params.GetURLParams().endpoint.GetHost() == "storage.googleapis.com");
		REQUIRE(auth_params.GetURLParams().style == S3URLStyle::PATH);
		REQUIRE(parsed_url.GetHost() == "storage.googleapis.com");
		REQUIRE(parsed_url.GetEncodedPath() == "/bucket/key");
	}

	SECTION("empty R2 endpoints fail instead of routing to AWS") {
		auto config = TestAuthConfig(S3ProviderType::R2);
		config.endpoint = "account.r2.cloudflarestorage.com";
		config.url_style = "path";
		REQUIRE_THROWS(ResolveTestAuth(std::move(config), "r2://bucket/key?s3_endpoint="));
	}

	SECTION("empty values are accepted") {
		auto config = TestAuthConfig();
		config.endpoint = "s3.amazonaws.com";
		auto auth_params = ResolveTestAuth(std::move(config), "s3://bucket/key?s3_access_key_id&s3_secret_access_key=");
		REQUIRE(auth_params.GetCredentials().access_key_id.empty());
		REQUIRE(auth_params.GetCredentials().secret_access_key.empty());
	}

	SECTION("duplicate decoded keys are rejected") {
		REQUIRE_THROWS(ResolveTestAuth(TestAuthConfig(), "s3://bucket/key?s3_region=one&s3%5Fregion=two"));
	}

	SECTION("query keys remain case-sensitive") {
		REQUIRE_THROWS(ResolveTestAuth(TestAuthConfig(), "s3://bucket/key?S3_region=one"));
	}

	SECTION("display URLs redact parameters unless compatibility mode treats them as key bytes") {
		auto auth_params = ResolveTestAuth(TestAuthConfig());
		REQUIRE(S3Url::GetDisplayUrl("s3://bucket/key?s3_secret_access_key=secret", auth_params) == "s3://bucket/key");
		auto compatibility_config = TestAuthConfig();
		compatibility_config.compatibility_mode = true;
		auto compatibility_params = ResolveTestAuth(std::move(compatibility_config));
		REQUIRE(S3Url::GetDisplayUrl("s3://bucket/key?literal", compatibility_params) == "s3://bucket/key?literal");
	}
}

TEST_CASE("S3 URL compatibility mode reads canonical and legacy secret keys", "[httpfs][s3][secret]") {
	DuckDB db(nullptr);
	Connection con(db);
	S3TestHelper::LoadExtension(db);

	SECTION("canonical key") {
		KeyValueSecret secret({"s3://"}, Identifier("s3"), Identifier("config"), Identifier("canonical"));
		secret.secret_map["url_compatibility_mode"] = Value(true);
		REQUIRE(ReadSecretAuthParams(con, secret).GetURLParams().compatibility_mode);
	}

	SECTION("canonical key takes precedence") {
		KeyValueSecret secret({"s3://"}, Identifier("s3"), Identifier("config"), Identifier("precedence"));
		secret.secret_map["url_compatibility_mode"] = Value(false);
		secret.secret_map["s3_url_compatibility_mode"] = Value(true);
		REQUIRE_FALSE(ReadSecretAuthParams(con, secret).GetURLParams().compatibility_mode);
	}

	SECTION("legacy key") {
		KeyValueSecret secret({"s3://"}, Identifier("s3"), Identifier("config"), Identifier("legacy"));
		secret.secret_map["s3_url_compatibility_mode"] = Value(true);
		REQUIRE(ReadSecretAuthParams(con, secret).GetURLParams().compatibility_mode);
	}

	SECTION("global setting fallback") {
		S3TestHelper::RequireQueryOk(con, "SET s3_url_compatibility_mode=true");
		KeyValueSecret secret({"s3://"}, Identifier("s3"), Identifier("config"), Identifier("setting"));
		REQUIRE(ReadSecretAuthParams(con, secret).GetURLParams().compatibility_mode);
	}

	SECTION("invalid legacy URL style") {
		KeyValueSecret secret({"s3://"}, Identifier("s3"), Identifier("config"), Identifier("invalid_url_style"));
		secret.secret_map["url_style"] = "handwritten";
		REQUIRE_THROWS(ReadSecretAuthParams(con, secret));
	}
}

TEST_CASE("GCS HMAC signing region follows provider defaults", "[httpfs][s3][gcs][provider][signing]") {
	SECTION("regionless HMAC uses auto") {
		auto config = TestAuthConfig(S3ProviderType::GCS);
		config.credentials.access_key_id = "key";
		config.credentials.secret_access_key = "secret";
		auto auth_params = ResolveTestAuth(std::move(config));
		REQUIRE(auth_params.GetCredentials().region == "auto");
		REQUIRE(auth_params.GetURLParams().endpoint.GetHost() == "storage.googleapis.com");
		REQUIRE(auth_params.GetURLParams().style == S3URLStyle::PATH);
	}

	SECTION("explicit regions win") {
		auto config = TestAuthConfig(S3ProviderType::GCS);
		config.credentials.access_key_id = "key";
		config.credentials.secret_access_key = "secret";
		config.credentials.region = "eu-west-1";
		auto auth_params = ResolveTestAuth(std::move(config));
		REQUIRE(auth_params.GetCredentials().region == "eu-west-1");
	}

	SECTION("partial HMAC material still selects signing") {
		for (const auto &use_key_id : {false, true}) {
			auto config = TestAuthConfig(S3ProviderType::GCS);
			if (use_key_id) {
				config.credentials.access_key_id = "key";
			} else {
				config.credentials.secret_access_key = "secret";
			}
			auto auth_params = ResolveTestAuth(std::move(config));
			REQUIRE(auth_params.GetProvider().GetAuthType(auth_params) == S3AuthType::SIGV4);
			REQUIRE(auth_params.GetCredentials().region == "auto");
		}
	}

	SECTION("URL overrides reapply or replace the default") {
		auto empty_config = TestAuthConfig(S3ProviderType::GCS);
		empty_config.credentials.access_key_id = "key";
		empty_config.credentials.secret_access_key = "secret";
		empty_config.credentials.region = "eu-west-1";
		auto empty_override = ResolveTestAuth(std::move(empty_config), "gcs://bucket/key?s3_region=");
		REQUIRE(empty_override.GetCredentials().region == "auto");

		auto explicit_config = TestAuthConfig(S3ProviderType::GCS);
		explicit_config.credentials.access_key_id = "key";
		explicit_config.credentials.secret_access_key = "secret";
		auto explicit_override = ResolveTestAuth(std::move(explicit_config), "gcs://bucket/key?s3_region=asia-east1");
		REQUIRE(explicit_override.GetCredentials().region == "asia-east1");
	}

	SECTION("URL credentials receive the default during finalization") {
		auto auth_params = ResolveTestAuth(TestAuthConfig(S3ProviderType::GCS),
		                                   "gcs://bucket/key?s3_access_key_id=key&s3_secret_access_key=secret");
		REQUIRE(auth_params.GetCredentials().region == "auto");
	}

	SECTION("authentication modes that do not sign remain unchanged") {
		auto bearer_config = TestAuthConfig(S3ProviderType::GCS);
		bearer_config.credentials.oauth2_bearer_token = "token";
		bearer_config.credentials.access_key_id = "key";
		bearer_config.credentials.secret_access_key = "secret";
		auto bearer = ResolveTestAuth(std::move(bearer_config));
		REQUIRE(bearer.GetProvider().GetAuthType(bearer) == S3AuthType::BEARER);
		REQUIRE(bearer.GetCredentials().region.empty());

		auto anonymous = ResolveTestAuth(TestAuthConfig(S3ProviderType::GCS));
		REQUIRE(anonymous.GetProvider().GetAuthType(anonymous) == S3AuthType::ANONYMOUS);
		REQUIRE(anonymous.GetCredentials().region.empty());
	}

	SECTION("region publication retains the GCS endpoint") {
		auto config = TestAuthConfig(S3ProviderType::GCS);
		config.credentials.oauth2_bearer_token = "token";
		auto auth_params = ResolveTestAuth(std::move(config)).WithRegion("eu-west-1");
		REQUIRE(auth_params.GetCredentials().region == "eu-west-1");
		REQUIRE(auth_params.GetURLParams().endpoint.GetHost() == "storage.googleapis.com");
		REQUIRE(auth_params.GetProvider().GetType() == S3ProviderType::GCS);
		REQUIRE(auth_params.GetProvider().GetAuthType(auth_params) == S3AuthType::BEARER);
	}

	SECTION("other providers retain their custom-endpoint behavior") {
		for (const auto provider_type : {S3ProviderType::S3, S3ProviderType::R2}) {
			auto config = TestAuthConfig(provider_type);
			config.credentials.access_key_id = "key";
			config.credentials.secret_access_key = "secret";
			config.endpoint = "storage.example.com";
			config.endpoint_mode = S3EndpointMode::EXPLICIT;
			auto auth_params = ResolveTestAuth(std::move(config));
			REQUIRE(auth_params.GetCredentials().region.empty());
		}
	}
}

TEST_CASE("S3 request operations define transport and retry policy", "[httpfs][s3][request][retry]") {
	struct ExpectedOperationInfo {
		S3RequestOperation operation;
		RequestType request_type;
		S3RequestTarget target;
		bool retry_timeout;
		bool retry_received_response;
		bool uses_kms_headers;
	};
	const array<ExpectedOperationInfo, 10> expected {{
	    {S3RequestOperation::HEAD_OBJECT, RequestType::HEAD_REQUEST, S3RequestTarget::OBJECT, true, false, false},
	    {S3RequestOperation::GET_OBJECT, RequestType::GET_REQUEST, S3RequestTarget::OBJECT, true, false, false},
	    {S3RequestOperation::PUT_OBJECT, RequestType::PUT_REQUEST, S3RequestTarget::OBJECT, true, false, true},
	    {S3RequestOperation::DELETE_OBJECT, RequestType::DELETE_REQUEST, S3RequestTarget::OBJECT, true, false, false},
	    {S3RequestOperation::LIST_OBJECTS, RequestType::GET_REQUEST, S3RequestTarget::BUCKET, true, false, false},
	    {S3RequestOperation::DELETE_OBJECTS, RequestType::POST_REQUEST, S3RequestTarget::BUCKET, false, false, false},
	    {S3RequestOperation::CREATE_MULTIPART_UPLOAD, RequestType::POST_REQUEST, S3RequestTarget::OBJECT, false, false,
	     true},
	    {S3RequestOperation::UPLOAD_PART, RequestType::PUT_REQUEST, S3RequestTarget::OBJECT, true, false, false},
	    {S3RequestOperation::COMPLETE_MULTIPART_UPLOAD, RequestType::POST_REQUEST, S3RequestTarget::OBJECT, false, true,
	     false},
	    {S3RequestOperation::ABORT_MULTIPART_UPLOAD, RequestType::DELETE_REQUEST, S3RequestTarget::OBJECT, true, false,
	     false},
	}};

	for (const auto &entry : expected) {
		auto &info = S3RequestUtil::GetOperationInfo(entry.operation);
		REQUIRE(info.request_type == entry.request_type);
		REQUIRE(info.target == entry.target);
		REQUIRE(info.retry_timeout == entry.retry_timeout);
		REQUIRE(info.retry_received_response == entry.retry_received_response);
		REQUIRE(info.uses_kms_headers == entry.uses_kms_headers);
	}
}

TEST_CASE("S3 provider policy selects request authentication", "[httpfs][s3][provider][signing]") {
	::AESStateSSLFactory encryption_util;
	auto parsed_url = ParseTestS3Url("s3://bucket/key", "storage.example.com", "path");

	SECTION("anonymous") {
		auto auth_params = ResolveTestAuth(TestAuthConfig());
		auto headers = S3RequestUtil::CreateHeaders(encryption_util, parsed_url, S3RequestOperation::GET_OBJECT,
		                                            S3RequestQuery(), auth_params);
		REQUIRE(headers.GetHeaderValue("Host") == parsed_url.GetHost());
		REQUIRE_FALSE(headers.HasHeader("Authorization"));
	}

	for (const auto provider_type : {S3ProviderType::S3, S3ProviderType::R2, S3ProviderType::GCS}) {
		auto config = TestAuthConfig(provider_type);
		config.credentials.region = "auto";
		config.credentials.access_key_id = "key";
		config.credentials.secret_access_key = "secret";
		auto auth_params = ResolveTestAuth(std::move(config));
		auto headers = S3RequestUtil::CreateHeaders(encryption_util, parsed_url, S3RequestOperation::GET_OBJECT,
		                                            S3RequestQuery(), auth_params, "20260806", "20260806T120000Z");
		REQUIRE(StringUtil::StartsWith(headers.GetHeaderValue("Authorization"), "AWS4-HMAC-SHA256"));
	}

	SECTION("GCS bearer takes precedence over HMAC") {
		auto config = TestAuthConfig(S3ProviderType::GCS);
		config.credentials.access_key_id = "key";
		config.credentials.secret_access_key = "secret";
		config.credentials.oauth2_bearer_token = "token";
		auto auth_params = ResolveTestAuth(std::move(config));
		auto headers = S3RequestUtil::CreateHeaders(encryption_util, parsed_url, S3RequestOperation::DELETE_OBJECTS,
		                                            S3RequestQuery({{"delete", ""}}), auth_params, "", "", "payload",
		                                            "application/xml", "content-md5");
		REQUIRE(headers.GetHeaderValue("Authorization") == "Bearer token");
		REQUIRE(headers.GetHeaderValue("Content-Type") == "application/xml");
		REQUIRE(headers.GetHeaderValue("Content-MD5") == "content-md5");
		REQUIRE_FALSE(headers.HasHeader("x-amz-date"));
	}
}

TEST_CASE("S3 configured headers are validated before request authentication", "[httpfs][s3][headers]") {
	::AESStateSSLFactory encryption_util;
	auto parsed_url = ParseTestS3Url("s3://bucket/key", "storage.example.com", "path");

	auto signed_config = TestAuthConfig();
	signed_config.credentials.region = "us-east-1";
	signed_config.credentials.access_key_id = "key";
	signed_config.credentials.secret_access_key = "secret";
	auto bearer_config = TestAuthConfig(S3ProviderType::GCS);
	bearer_config.credentials.oauth2_bearer_token = "token";
	vector<S3AuthParams> auth_params;
	auth_params.push_back(ResolveTestAuth(TestAuthConfig()));
	auth_params.push_back(ResolveTestAuth(std::move(signed_config)));
	auth_params.push_back(ResolveTestAuth(std::move(bearer_config)));

	auto create_headers = [&](const S3AuthParams &auth, const unordered_map<string, string> &extra_headers,
	                          const string &user_agent = "httpfs-agent") {
		return S3RequestUtil::CreateHeaders(encryption_util, parsed_url, S3RequestOperation::GET_OBJECT,
		                                    S3RequestQuery(), auth, "", "", "", "", "",
		                                    HTTPConfiguredHeaders {user_agent, extra_headers});
	};
	auto capture_error = [&](const S3AuthParams &auth, const unordered_map<string, string> &extra_headers) {
		try {
			create_headers(auth, extra_headers);
			return string();
		} catch (std::exception &ex) {
			return string(ex.what());
		}
	};

	SECTION("allowed headers are merged once for every authentication mode") {
		unordered_map<string, string> extra_headers {
		    {"X-HTTPFS-Session", "present"}, {"x-amz-meta-test", "metadata"}, {"uSeR-aGeNt", "custom-agent"}};
		for (idx_t auth_idx = 0; auth_idx < auth_params.size(); auth_idx++) {
			auto headers = create_headers(auth_params[auth_idx], extra_headers);
			REQUIRE(headers.GetHeaderValue("X-HTTPFS-Session") == "present");
			REQUIRE(headers.GetHeaderValue("x-amz-meta-test") == "metadata");
			REQUIRE(headers.GetHeaderValue("User-Agent") == "custom-agent");
			if (auth_idx == 0) {
				REQUIRE_FALSE(headers.HasHeader("Authorization"));
			} else if (auth_idx == 1) {
				auto authorization = headers.GetHeaderValue("Authorization");
				REQUIRE_FALSE(StringUtil::Contains(authorization, "x-httpfs-session"));
				REQUIRE_FALSE(StringUtil::Contains(authorization, "user-agent"));
			} else {
				REQUIRE(headers.GetHeaderValue("Authorization") == "Bearer token");
			}
		}
	}

	SECTION("case variants fail deterministically") {
		unordered_map<string, string> extra_headers {{"X-Amz-Meta-Test", "first"}, {"x-amz-meta-test", "second"}};
		for (const auto &auth : auth_params) {
			auto error = capture_error(auth, extra_headers);
			REQUIRE(StringUtil::Contains(error, "X-Amz-Meta-Test"));
			REQUIRE(StringUtil::Contains(error, "x-amz-meta-test"));
		}
	}

	SECTION("HTTPFS-owned headers fail case-insensitively") {
		const vector<pair<string, string>> protected_headers {
		    {"hOsT", "Host"},
		    {"AUTHORIZATION", "Authorization"},
		    {"content-LENGTH", "Content-Length"},
		    {"CONTENT-type", "Content-Type"},
		    {"content-md5", "Content-MD5"},
		    {"RANGE", "Range"},
		    {"if-match", "If-Match"},
		    {"X-AMZ-DATE", "x-amz-date"},
		    {"X-AMZ-CONTENT-SHA256", "x-amz-content-sha256"},
		    {"X-AMZ-SECURITY-TOKEN", "x-amz-security-token"},
		    {"X-AMZ-REQUEST-PAYER", "x-amz-request-payer"},
		    {"X-AMZ-SERVER-SIDE-ENCRYPTION", "x-amz-server-side-encryption"},
		    {"X-AMZ-SERVER-SIDE-ENCRYPTION-AWS-KMS-KEY-ID", "x-amz-server-side-encryption-aws-kms-key-id"},
		};
		for (const auto &auth : auth_params) {
			for (const auto &protected_header : protected_headers) {
				auto error = capture_error(auth, {{protected_header.first, "override"}});
				INFO(protected_header.first);
				REQUIRE(StringUtil::Contains(error, protected_header.first));
				REQUIRE(StringUtil::Contains(error, protected_header.second));
			}
		}
	}
}

TEST_CASE("S3 rejects configured header conflicts before request dispatch", "[httpfs][s3][headers][request-session]") {
	HTTPFSUtil http_util;
	HTTPFSParams http_params(http_util);
	http_params.extra_headers["hOsT"] = "override";
	auto config = TestAuthConfig();
	config.credentials.region = "us-east-1";
	config.endpoint = "s3.amazonaws.com";
	config.credentials.access_key_id = "key";
	config.credentials.secret_access_key = "secret";
	auto auth_params = ResolveTestAuth(std::move(config));
	auto snapshot = make_shared_ptr<S3RequestSnapshot>(http_params, auth_params, "s3://bucket/key",
	                                                   weak_ptr<ClientContext>(), false);
	HTTPRequestSession session(snapshot);
	::AESStateSSLFactory encryption_util;
	idx_t request_count = 0;

	S3RequestSpec spec {"s3://bucket/key",
	                    S3RequestOperation::GET_OBJECT,
	                    [](const ParsedS3Url &) { return S3RequestQuery(); },
	                    "",
	                    "",
	                    ""};
	REQUIRE_THROWS(S3RequestExecutor::RunSession(encryption_util, session, spec, [&](S3RequestData &) {
		request_count++;
		return make_uniq<HTTPResponse>(HTTPStatusCode::OK_200);
	}));
	REQUIRE(request_count == 0);
}

TEST_CASE("S3 HTTP errors preserve metadata and provider-specific context", "[httpfs][s3][error]") {
	HTTPResponse response(HTTPStatusCode::Forbidden_403);
	response.reason = "Forbidden by test";
	response.body = "<Error><Code>InvalidAccessKeyId</Code><Message>bad credentials</Message>"
	                "<AWSAccessKeyId>test-key</AWSAccessKeyId></Error>";
	response.headers.Insert("x-test-request-id", "request-42");

	auto config = TestAuthConfig();
	config.credentials.region = "eu-west-1";
	auto auth_params = ResolveTestAuth(std::move(config));
	auto display_url = S3Url::GetDisplayUrl("s3://bucket/key?s3_secret_access_key=hidden", auth_params);
	auto error =
	    ErrorData(S3RequestUtil::GetError(auth_params, response, RequestType::GET_REQUEST, "reading", display_url));

	CHECK(error.Type() == ExceptionType::HTTP);
	CHECK(error.ExtraInfo().at("status_code") == "403");
	CHECK(error.ExtraInfo().at("reason") == response.reason);
	CHECK(error.ExtraInfo().at("response_body") == response.body);
	CHECK(error.ExtraInfo().at("header_x-test-request-id") == "request-42");
	CHECK(StringUtil::Contains(error.RawMessage(), "HTTP GET error reading 's3://bucket/key'"));
	CHECK(StringUtil::Contains(error.RawMessage(), "InvalidAccessKeyId: bad credentials"));
	CHECK(StringUtil::Contains(error.RawMessage(), "Invalid Access Key: \"test-key\""));
	CHECK(StringUtil::Contains(error.RawMessage(), "Authentication Failure"));
	CHECK_FALSE(StringUtil::Contains(error.RawMessage(), "hidden"));
}

TEST_CASE("S3 HTTP diagnostics stay within their provider", "[httpfs][s3][provider][error]") {
	HTTPResponse bad_request(HTTPStatusCode::BadRequest_400);
	bad_request.reason = "Bad Request";
	bad_request.body = "not XML";

	for (const auto provider_type : {S3ProviderType::S3, S3ProviderType::GCS, S3ProviderType::R2}) {
		auto config = TestAuthConfig(provider_type);
		config.credentials.region = "test-region";
		auto auth_params = ResolveTestAuth(std::move(config));
		auto error = ErrorData(S3RequestUtil::GetError(auth_params, bad_request, RequestType::POST_REQUEST, "listing",
		                                               "provider://bucket"));
		CHECK(StringUtil::Contains(error.RawMessage(), "Bad Request - this can be caused by the S3 region") ==
		      (provider_type == S3ProviderType::S3));
		CHECK_FALSE(StringUtil::Contains(error.RawMessage(), "not XML"));
	}

	HTTPResponse unauthorized(HTTPStatusCode::Unauthorized_401);
	unauthorized.reason = "Unauthorized";
	for (const auto &entry : {pair<S3ProviderType, string> {S3ProviderType::S3, "invalid or missing credentials"},
	                          pair<S3ProviderType, string> {S3ProviderType::GCS, "GCS authentication failed"},
	                          pair<S3ProviderType, string> {S3ProviderType::R2, "R2 authentication failed"}}) {
		auto auth_params = ResolveTestAuth(TestAuthConfig(entry.first));
		auto error = ErrorData(S3RequestUtil::GetError(auth_params, unauthorized, RequestType::HEAD_REQUEST, "checking",
		                                               "provider://bucket/key"));
		CHECK(StringUtil::Contains(error.RawMessage(), entry.second));
	}
}

TEST_CASE("S3 error classification requires valid XML but accepts code-only errors", "[httpfs][s3][error]") {
	HTTPResponse response(HTTPStatusCode::BadRequest_400);
	response.body = "<Error><Code>RequestTimeout</Code></Error>";
	CHECK(S3RequestUtil::IsRequestTimeout(response));
	CHECK(S3RequestUtil::ParseError(response.body) == "\n\nRequestTimeout");

	response.body = "<Error><Code>RequestTimeout";
	CHECK_FALSE(S3RequestUtil::IsRequestTimeout(response));
	CHECK(S3RequestUtil::ParseError(response.body).empty());
}

TEST_CASE("S3 request error context belongs to the final attempt", "[httpfs][s3][error][request-session]") {
	HTTPFSUtil http_util;
	HTTPFSParams http_params(http_util);
	auto config = TestAuthConfig();
	config.credentials.region = "request-region";
	config.endpoint = "s3.request-region.amazonaws.com";
	auto auth_params = ResolveTestAuth(std::move(config));
	auto snapshot = make_shared_ptr<S3RequestSnapshot>(http_params, auth_params, "s3://bucket/key",
	                                                   weak_ptr<ClientContext>(), false);
	HTTPRequestSession session(snapshot);
	::AESStateSSLFactory encryption_util;
	S3RequestSpec spec {"s3://bucket/key?s3_secret_access_key=hidden",
	                    S3RequestOperation::GET_OBJECT,
	                    [](const ParsedS3Url &) { return S3RequestQuery(); },
	                    "",
	                    "",
	                    ""};
	auto result = S3RequestExecutor::RunSession(encryption_util, session, spec, [&](S3RequestData &request_data) {
		CHECK(request_data.auth_params.GetCredentials().region == "request-region");
		string previous_region;
		REQUIRE(S3RequestExecutor::SetSessionRegion(session, "published-region", previous_region));
		auto result = make_uniq<HTTPResponse>(HTTPStatusCode::BadRequest_400);
		result->reason = "Bad Request";
		result->body = "<Error><Code>InvalidRequest</Code></Error>";
		return result;
	});

	REQUIRE(result.response);
	CHECK(session.Capture().snapshot->Cast<S3RequestSnapshot>().auth_params.GetCredentials().region ==
	      "published-region");
	CHECK(result.context.GetAuthParams().GetCredentials().region == "request-region");
	CHECK(result.context.display_url == "s3://bucket/key");
	auto error = ErrorData(S3RequestUtil::GetRequestError(result.context, *result.response));
	CHECK(StringUtil::Contains(error.RawMessage(), "Provided region is: \"request-region\""));
	CHECK_FALSE(StringUtil::Contains(error.RawMessage(), "published-region"));
	CHECK_FALSE(StringUtil::Contains(error.RawMessage(), "hidden"));
}

TEST_CASE("S3 request signing remains deterministic", "[httpfs][s3][signing]") {
	::AESStateSSLFactory encryption_util;
	auto config = TestAuthConfig();
	config.credentials.region = "us-east-1";
	config.credentials.access_key_id = "AKIAIOSFODNN7EXAMPLE";
	config.credentials.secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
	auto auth_params = ResolveTestAuth(std::move(config));
	auto parsed_url = ParseTestS3Url("s3://examplebucket/test.txt", "s3.amazonaws.com", "virtual");

	auto headers = S3RequestUtil::CreateHeaders(encryption_util, parsed_url, S3RequestOperation::GET_OBJECT,
	                                            S3RequestQuery(), auth_params, "20130524", "20130524T000000Z");

	REQUIRE(headers.GetHeaderValue("Host") == "examplebucket.s3.amazonaws.com");
	REQUIRE(headers.GetHeaderValue("x-amz-content-sha256") ==
	        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
	REQUIRE(headers.GetHeaderValue("Authorization") ==
	        "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, "
	        "SignedHeaders=host;x-amz-content-sha256;x-amz-date, "
	        "Signature=df548e2ce037944d03f3e68682813b093763996d597cf890ca3d9037fd231eb4");
}

TEST_CASE("S3 request signing includes optional headers", "[httpfs][s3][signing]") {
	::AESStateSSLFactory encryption_util;
	auto config = TestAuthConfig();
	config.credentials.region = "eu-west-1";
	config.credentials.access_key_id = "key";
	config.credentials.secret_access_key = "secret";
	config.credentials.session_token = "token";
	config.request_options.kms_key_id = "kms-key";
	config.request_options.requester_pays = true;
	auto auth_params = ResolveTestAuth(std::move(config));
	auto parsed_url = ParseTestS3Url("s3://bucket/key", "bucket.example.com", "path");

	auto headers = S3RequestUtil::CreateHeaders(encryption_util, parsed_url, S3RequestOperation::PUT_OBJECT,
	                                            S3RequestQuery(), auth_params, "20260730", "20260730T120000Z", "",
	                                            "application/octet-stream", "content-md5");

	REQUIRE(headers.GetHeaderValue("x-amz-security-token") == "token");
	REQUIRE(headers.GetHeaderValue("x-amz-request-payer") == "requester");
	REQUIRE(headers.GetHeaderValue("x-amz-server-side-encryption") == "aws:kms");
	REQUIRE(headers.GetHeaderValue("x-amz-server-side-encryption-aws-kms-key-id") == "kms-key");
	REQUIRE(headers.GetHeaderValue("Authorization") ==
	        "AWS4-HMAC-SHA256 Credential=key/20260730/eu-west-1/s3/aws4_request, "
	        "SignedHeaders=content-md5;content-type;host;x-amz-content-sha256;x-amz-date;x-amz-request-payer;"
	        "x-amz-security-token;x-amz-server-side-encryption;x-amz-server-side-encryption-aws-kms-key-id, "
	        "Signature=303dcf01c2ad19bf52fe539998ff6fa5d6a5d3ee54c6eb8cf6275ed5128e89b0");

	SECTION("KMS headers are limited to operations that create object encryption state") {
		const array<S3RequestOperation, 8> operations_without_kms {S3RequestOperation::HEAD_OBJECT,
		                                                           S3RequestOperation::GET_OBJECT,
		                                                           S3RequestOperation::DELETE_OBJECT,
		                                                           S3RequestOperation::LIST_OBJECTS,
		                                                           S3RequestOperation::DELETE_OBJECTS,
		                                                           S3RequestOperation::UPLOAD_PART,
		                                                           S3RequestOperation::COMPLETE_MULTIPART_UPLOAD,
		                                                           S3RequestOperation::ABORT_MULTIPART_UPLOAD};
		for (const auto operation : operations_without_kms) {
			auto operation_headers = S3RequestUtil::CreateHeaders(
			    encryption_util, parsed_url, operation, S3RequestQuery(), auth_params, "20260730", "20260730T120000Z");
			REQUIRE_FALSE(operation_headers.HasHeader("x-amz-server-side-encryption"));
			REQUIRE_FALSE(operation_headers.HasHeader("x-amz-server-side-encryption-aws-kms-key-id"));
		}

		auto create_headers =
		    S3RequestUtil::CreateHeaders(encryption_util, parsed_url, S3RequestOperation::CREATE_MULTIPART_UPLOAD,
		                                 S3RequestQuery(), auth_params, "20260730", "20260730T120000Z");
		REQUIRE(create_headers.GetHeaderValue("x-amz-server-side-encryption") == "aws:kms");
		REQUIRE(create_headers.GetHeaderValue("x-amz-server-side-encryption-aws-kms-key-id") == "kms-key");
	}
}

TEST_CASE("GCS billing projects are applied across authentication modes", "[httpfs][s3][gcs][requester-pays]") {
	::AESStateSSLFactory encryption_util;
	auto parsed_url = ParseTestS3Url("s3://bucket/key", "storage.googleapis.com", "path");
	const array<S3RequestOperation, 5> operations {
	    S3RequestOperation::GET_OBJECT, S3RequestOperation::HEAD_OBJECT, S3RequestOperation::PUT_OBJECT,
	    S3RequestOperation::CREATE_MULTIPART_UPLOAD, S3RequestOperation::DELETE_OBJECT};

	SECTION("HMAC signs the billing project for every request verb") {
		auto config = TestAuthConfig(S3ProviderType::GCS);
		config.credentials.region = "auto";
		config.credentials.access_key_id = "key";
		config.credentials.secret_access_key = "secret";
		config.request_options.requester_pays = true;
		config.request_options.user_project = "billing-project";
		auto auth_params = ResolveTestAuth(std::move(config));
		for (const auto operation : operations) {
			auto headers = S3RequestUtil::CreateHeaders(encryption_util, parsed_url, operation, S3RequestQuery(),
			                                            auth_params, "20260902", "20260902T120000Z");
			REQUIRE(headers.GetHeaderValue("x-goog-user-project") == "billing-project");
			REQUIRE_FALSE(headers.HasHeader("x-amz-request-payer"));
			REQUIRE(StringUtil::Contains(headers.GetHeaderValue("Authorization"), "x-goog-user-project"));
		}
	}

	SECTION("bearer and anonymous requests retain their authentication behavior") {
		auto bearer_config = TestAuthConfig(S3ProviderType::GCS);
		bearer_config.credentials.oauth2_bearer_token = "gcs-token";
		bearer_config.request_options.user_project = "billing-project";
		auto bearer = ResolveTestAuth(std::move(bearer_config));
		for (const auto operation : operations) {
			auto headers =
			    S3RequestUtil::CreateHeaders(encryption_util, parsed_url, operation, S3RequestQuery(), bearer);
			REQUIRE(headers.GetHeaderValue("x-goog-user-project") == "billing-project");
			REQUIRE(headers.GetHeaderValue("Authorization") == "Bearer gcs-token");
			REQUIRE_FALSE(headers.HasHeader("x-amz-request-payer"));
		}

		auto anonymous_config = TestAuthConfig(S3ProviderType::GCS);
		anonymous_config.request_options.user_project = "billing-project";
		auto anonymous = ResolveTestAuth(std::move(anonymous_config));
		auto headers = S3RequestUtil::CreateHeaders(encryption_util, parsed_url, S3RequestOperation::GET_OBJECT,
		                                            S3RequestQuery(), anonymous);
		REQUIRE(headers.GetHeaderValue("x-goog-user-project") == "billing-project");
		REQUIRE_FALSE(headers.HasHeader("Authorization"));
	}

	SECTION("unconfigured GCS requests remain unchanged") {
		auto config = TestAuthConfig(S3ProviderType::GCS);
		config.credentials.oauth2_bearer_token = "gcs-token";
		auto auth_params = ResolveTestAuth(std::move(config));
		auto headers = S3RequestUtil::CreateHeaders(encryption_util, parsed_url, S3RequestOperation::GET_OBJECT,
		                                            S3RequestQuery(), auth_params);
		REQUIRE_FALSE(headers.HasHeader("x-goog-user-project"));
	}

	SECTION("the billing header is owned only for GCS") {
		unordered_map<string, string> extra_headers {{"X-GoOg-UsEr-PrOjEcT", "configured-project"}};
		auto gcs = ResolveTestAuth(TestAuthConfig(S3ProviderType::GCS));
		REQUIRE_THROWS(S3RequestUtil::CreateHeaders(encryption_util, parsed_url, S3RequestOperation::GET_OBJECT,
		                                            S3RequestQuery(), gcs, "", "", "", "", "",
		                                            HTTPConfiguredHeaders {"", extra_headers}));

		auto s3 = ResolveTestAuth(TestAuthConfig());
		auto headers =
		    S3RequestUtil::CreateHeaders(encryption_util, parsed_url, S3RequestOperation::GET_OBJECT, S3RequestQuery(),
		                                 s3, "", "", "", "", "", HTTPConfiguredHeaders {"", extra_headers});
		REQUIRE(headers.GetHeaderValue("X-GoOg-UsEr-PrOjEcT") == "configured-project");
	}

	SECTION("R2 retains the AWS requester-pays header") {
		auto config = TestAuthConfig(S3ProviderType::R2);
		config.credentials.region = "auto";
		config.credentials.access_key_id = "key";
		config.credentials.secret_access_key = "secret";
		config.request_options.requester_pays = true;
		auto auth_params = ResolveTestAuth(std::move(config));
		auto headers = S3RequestUtil::CreateHeaders(encryption_util, parsed_url, S3RequestOperation::GET_OBJECT,
		                                            S3RequestQuery(), auth_params, "20260902", "20260902T120000Z");
		REQUIRE(headers.GetHeaderValue("x-amz-request-payer") == "requester");
		REQUIRE_FALSE(headers.HasHeader("x-goog-user-project"));
	}
}

TEST_CASE("S3 request signing canonicalizes configured extension headers", "[httpfs][s3][signing][headers]") {
	::AESStateSSLFactory encryption_util;
	auto config = TestAuthConfig();
	config.credentials.region = "us-east-1";
	config.credentials.access_key_id = "key";
	config.credentials.secret_access_key = "secret";
	auto auth_params = ResolveTestAuth(std::move(config));
	auto parsed_url = ParseTestS3Url("s3://bucket/key", "bucket.example.com", "path");
	unordered_map<string, string> raw_headers {
	    {"X-AmZ-Meta-Color", "\t blue  green \t"}, {"x-GoOg-Meta-Mode", "  fast\tmode  "}, {"X-Ordinary", "value"}};
	unordered_map<string, string> normalized_headers {
	    {"x-amz-meta-color", "blue green"}, {"X-GOOG-META-MODE", "fast mode"}, {"X-Ordinary", "value"}};

	auto raw = S3RequestUtil::CreateHeaders(encryption_util, parsed_url, S3RequestOperation::GET_OBJECT,
	                                        S3RequestQuery(), auth_params, "20260831", "20260831T120000Z", "", "", "",
	                                        HTTPConfiguredHeaders {"httpfs-agent", raw_headers});
	auto normalized = S3RequestUtil::CreateHeaders(encryption_util, parsed_url, S3RequestOperation::GET_OBJECT,
	                                               S3RequestQuery(), auth_params, "20260831", "20260831T120000Z", "",
	                                               "", "", HTTPConfiguredHeaders {"httpfs-agent", normalized_headers});

	const auto &authorization = raw.GetHeaderValue("Authorization");
	REQUIRE(authorization == normalized.GetHeaderValue("Authorization"));
	REQUIRE(authorization == "AWS4-HMAC-SHA256 Credential=key/20260831/us-east-1/s3/aws4_request, "
	                         "SignedHeaders=host;x-amz-content-sha256;x-amz-date;x-amz-meta-color;x-goog-meta-mode, "
	                         "Signature=3ed4748c9e12b8756c2328d76892759de1d0bea864f52926473f594f2c38e89d");
	REQUIRE_FALSE(StringUtil::Contains(authorization, "x-ordinary"));
	REQUIRE_FALSE(StringUtil::Contains(authorization, "user-agent"));
	REQUIRE(raw.GetHeaderValue("X-AmZ-Meta-Color") == "\t blue  green \t");
	REQUIRE(raw.GetHeaderValue("x-GoOg-Meta-Mode") == "  fast\tmode  ");

	bool found_amz_spelling = false;
	bool found_goog_spelling = false;
	for (const auto &header : raw) {
		found_amz_spelling |= header.first == "X-AmZ-Meta-Color";
		found_goog_spelling |= header.first == "x-GoOg-Meta-Mode";
	}
	REQUIRE(found_amz_spelling);
	REQUIRE(found_goog_spelling);
}

TEST_CASE("S3 request signing preserves empty configured extension headers", "[httpfs][s3][signing][headers]") {
	::AESStateSSLFactory encryption_util;
	auto config = TestAuthConfig();
	config.credentials.region = "us-east-1";
	config.credentials.access_key_id = "key";
	config.credentials.secret_access_key = "secret";
	auto auth_params = ResolveTestAuth(std::move(config));
	auto parsed_url = ParseTestS3Url("s3://bucket/key", "bucket.example.com", "path");
	unordered_map<string, string> raw_headers {{"X-AmZ-Meta-Empty", ""}, {"x-GoOg-Meta-Whitespace", "\t  \t"}};
	unordered_map<string, string> normalized_headers {{"x-amz-meta-empty", ""}, {"X-GOOG-META-WHITESPACE", ""}};

	auto raw = S3RequestUtil::CreateHeaders(encryption_util, parsed_url, S3RequestOperation::GET_OBJECT,
	                                        S3RequestQuery(), auth_params, "20260831", "20260831T120000Z", "", "", "",
	                                        HTTPConfiguredHeaders {"", raw_headers});
	auto normalized = S3RequestUtil::CreateHeaders(encryption_util, parsed_url, S3RequestOperation::GET_OBJECT,
	                                               S3RequestQuery(), auth_params, "20260831", "20260831T120000Z", "",
	                                               "", "", HTTPConfiguredHeaders {"", normalized_headers});

	const auto &authorization = raw.GetHeaderValue("Authorization");
	REQUIRE(authorization == normalized.GetHeaderValue("Authorization"));
	REQUIRE(authorization ==
	        "AWS4-HMAC-SHA256 Credential=key/20260831/us-east-1/s3/aws4_request, "
	        "SignedHeaders=host;x-amz-content-sha256;x-amz-date;x-amz-meta-empty;x-goog-meta-whitespace, "
	        "Signature=5455a5d0c5002b36bdd90eb1719e3620ce3df4cfb1bd7d73e295721f96a7d787");
	REQUIRE(raw.GetHeaderValue("X-AmZ-Meta-Empty").empty());
	REQUIRE(raw.GetHeaderValue("x-GoOg-Meta-Whitespace") == "\t  \t");
}

TEST_CASE("S3 request signing changes configured headers after a region redirect", "[httpfs][s3][signing][headers]") {
	::AESStateSSLFactory encryption_util;
	auto config = TestAuthConfig();
	config.credentials.region = "us-east-1";
	config.credentials.access_key_id = "key";
	config.credentials.secret_access_key = "secret";
	auto auth_params = ResolveTestAuth(std::move(config));
	auto parsed_url = ParseTestS3Url("s3://bucket/key", "bucket.example.com", "path");
	unordered_map<string, string> extra_headers {{"X-AmZ-Meta-Region", "region-value"}};

	auto us_east_1 = S3RequestUtil::CreateHeaders(encryption_util, parsed_url, S3RequestOperation::GET_OBJECT,
	                                              S3RequestQuery(), auth_params, "20260831", "20260831T120000Z", "", "",
	                                              "", HTTPConfiguredHeaders {"", extra_headers});
	auth_params = auth_params.WithRegion("eu-west-1");
	auto eu_west_1 = S3RequestUtil::CreateHeaders(encryption_util, parsed_url, S3RequestOperation::GET_OBJECT,
	                                              S3RequestQuery(), auth_params, "20260831", "20260831T120000Z", "", "",
	                                              "", HTTPConfiguredHeaders {"", extra_headers});

	const auto &us_authorization = us_east_1.GetHeaderValue("Authorization");
	const auto &eu_authorization = eu_west_1.GetHeaderValue("Authorization");
	REQUIRE(us_authorization == "AWS4-HMAC-SHA256 Credential=key/20260831/us-east-1/s3/aws4_request, "
	                            "SignedHeaders=host;x-amz-content-sha256;x-amz-date;x-amz-meta-region, "
	                            "Signature=826c88e7c2fb7eaac361dd8c8c3d82d8cad1b0e873fa424c7077c8c32e564595");
	REQUIRE(eu_authorization == "AWS4-HMAC-SHA256 Credential=key/20260831/eu-west-1/s3/aws4_request, "
	                            "SignedHeaders=host;x-amz-content-sha256;x-amz-date;x-amz-meta-region, "
	                            "Signature=63d1e86e39a4cc2c815cbd349d1dbc7358240af72d2b82a0a27045a76ff704fb");
	REQUIRE(us_authorization != eu_authorization);
}

TEST_CASE("S3 request queries share canonical and wire encoding", "[httpfs][s3][query][signing]") {
	SECTION("path and query components encode slashes according to their wire context") {
		REQUIRE(S3Url::Encode("a/b c", S3URLEncodeMode::PATH) == "a/b%20c");
		REQUIRE(S3Url::Encode("a/b c", S3URLEncodeMode::QUERY_COMPONENT) == "a%2Fb%20c");
	}

	SECTION("raw parameters are encoded and sorted once") {
		S3RequestQuery query {{"z", "a b"}, {"empty", ""}, {"slash", "a/b"}, {"amp", "x&y"}, {"a", "1"}};
		const string expected = "a=1&amp=x%26y&empty=&slash=a%2Fb&z=a%20b";
		REQUIRE(query.WireQuery() == expected);
		REQUIRE(query.CanonicalQuery() == expected);
		REQUIRE(query.HasParameter("empty"));
		REQUIRE_FALSE(query.HasParameter("missing"));
	}

	SECTION("operation-specific parameters retain their wire contracts") {
		REQUIRE(S3RequestQuery({{"delete", ""}}).WireQuery() == "delete=");
		REQUIRE(S3RequestQuery({{"uploads", ""}}).WireQuery() == "uploads=");
		REQUIRE(S3RequestQuery({{"versionId", "opaque&id /"}}).WireQuery() == "versionId=opaque%26id%20%2F");
		REQUIRE(S3RequestQuery({{"uploadId", "opaque&id"}, {"partNumber", "12"}}).WireQuery() ==
		        "partNumber=12&uploadId=opaque%26id");
	}

	SECTION("signing is independent of raw parameter order") {
		::AESStateSSLFactory encryption_util;
		auto config = TestAuthConfig();
		config.credentials.region = "us-east-1";
		config.credentials.access_key_id = "key";
		config.credentials.secret_access_key = "secret";
		auto auth_params = ResolveTestAuth(std::move(config));
		auto parsed_url = ParseTestS3Url("s3://bucket/key", "bucket.example.com", "path");
		auto first = S3RequestUtil::CreateHeaders(encryption_util, parsed_url, S3RequestOperation::UPLOAD_PART,
		                                          S3RequestQuery({{"uploadId", "opaque&id"}, {"partNumber", "12"}}),
		                                          auth_params, "20260806", "20260806T120000Z");
		auto second = S3RequestUtil::CreateHeaders(encryption_util, parsed_url, S3RequestOperation::UPLOAD_PART,
		                                           S3RequestQuery({{"partNumber", "12"}, {"uploadId", "opaque&id"}}),
		                                           auth_params, "20260806", "20260806T120000Z");
		REQUIRE(first.GetHeaderValue("Authorization") == second.GetHeaderValue("Authorization"));
		REQUIRE(first.GetHeaderValue("Authorization") ==
		        "AWS4-HMAC-SHA256 Credential=key/20260806/us-east-1/s3/aws4_request, "
		        "SignedHeaders=host;x-amz-content-sha256;x-amz-date, "
		        "Signature=7d31006078e4c8754eb70f96358af8f4c84a60186bf8e8fe1605b9bb90fcffad");
		auto empty_query = S3RequestUtil::CreateHeaders(encryption_util, parsed_url, S3RequestOperation::UPLOAD_PART,
		                                                S3RequestQuery(), auth_params, "20260806", "20260806T120000Z");
		REQUIRE(first.GetHeaderValue("Authorization") != empty_query.GetHeaderValue("Authorization"));
	}
}

TEST_CASE("HTTPFS preserves S3 error bodies for streamed GETs", "[httpfs][s3][errors]") {
	SECTION("httplib") {
		RunFullGetErrorBodyScenario("httplib");
	}
	SECTION("curl") {
		RunFullGetErrorBodyScenario("curl");
	}
}

TEST_CASE("HTTPFS streams full GETs without Content-Length", "[httpfs][s3][streaming]") {
	SECTION("httplib") {
		RunChunkedFullGetScenario("httplib");
	}
	SECTION("curl") {
		RunChunkedFullGetScenario("curl");
	}
}

TEST_CASE("HTTPFS initializes and clones parameters without a configured proxy", "[httpfs][s3][params]") {
	alignas(HTTPFSParams) array<uint8_t, sizeof(HTTPFSParams)> storage;
	storage.fill(0xA5);

	HTTPFSUtil http_util;
	auto params = new (storage.data()) HTTPFSParams(http_util);
	REQUIRE(params->http_proxy.empty());
	REQUIRE(params->http_proxy_port == 0);
	auto clone = params->Clone();
	params->~HTTPFSParams();

	auto &cloned_params = clone->Cast<HTTPFSParams>();
	REQUIRE(cloned_params.http_proxy.empty());
	REQUIRE(cloned_params.http_proxy_port == 0);
}

TEST_CASE("HTTP request sessions merge configured headers once", "[httpfs][s3][request-session][headers]") {
	SECTION("httplib") {
		RunS3HeaderScenario("httplib");
	}
	SECTION("curl") {
		RunS3HeaderScenario("curl");
	}
}

TEST_CASE("S3 request sessions publish region redirects", "[httpfs][request-session][s3][region]") {
	SECTION("httplib HEAD") {
		RunS3RegionRedirectScenario("httplib", false);
	}
	SECTION("curl HEAD") {
		RunS3RegionRedirectScenario("curl", false);
	}
	SECTION("httplib LIST") {
		RunS3RegionRedirectScenario("httplib", true);
	}
	SECTION("curl LIST") {
		RunS3RegionRedirectScenario("curl", true);
	}
}

TEST_CASE("GCS bearer authentication is shared by object, list and bulk-delete requests", "[httpfs][s3][gcs][bearer]") {
	SECTION("httplib") {
		RunGCSBearerRequestScenario("httplib");
	}
	SECTION("curl") {
		RunGCSBearerRequestScenario("curl");
	}
}

TEST_CASE("GCS HMAC signing defaults to the auto region", "[httpfs][s3][gcs][signing]") {
	SECTION("httplib") {
		RunGCSHMACDefaultRegionScenario("httplib");
	}
	SECTION("curl") {
		RunGCSHMACDefaultRegionScenario("curl");
	}
}

TEST_CASE("S3 bulk delete preserves selected secret identity", "[httpfs][s3][delete][secret]") {
	SECTION("httplib") {
		RunBulkDeleteSecretIdentityScenario("httplib");
	}
	SECTION("curl") {
		RunBulkDeleteSecretIdentityScenario("curl");
	}
}

TEST_CASE("GCS bulk delete separates billing projects", "[httpfs][s3][gcs][delete][requester-pays]") {
	SECTION("httplib") {
		RunGCSBulkDeleteProjectIdentityScenario("httplib");
	}
	SECTION("curl") {
		RunGCSBulkDeleteProjectIdentityScenario("curl");
	}
}

TEST_CASE("S3 bulk delete preserves endpoint provenance", "[httpfs][s3][delete][endpoint]") {
	SECTION("httplib") {
		RunBulkDeleteEndpointModeIdentityScenario("httplib");
	}
	SECTION("curl") {
		RunBulkDeleteEndpointModeIdentityScenario("curl");
	}
}

TEST_CASE("S3 bulk delete follows provider batch limits", "[httpfs][s3][delete][provider]") {
	for (const string client_implementation : {"httplib", "curl"}) {
		DYNAMIC_SECTION(client_implementation << " keeps the S3 batch limit") {
			RunBulkDeleteBatchLimitScenario(client_implementation, BulkDeleteProviderProfile::S3);
		}
		DYNAMIC_SECTION(client_implementation << " applies the R2 scheme batch limit") {
			RunBulkDeleteBatchLimitScenario(client_implementation, BulkDeleteProviderProfile::R2_SCHEME);
		}
		DYNAMIC_SECTION(client_implementation << " recognizes the R2 endpoint batch limit") {
			RunBulkDeleteBatchLimitScenario(client_implementation, BulkDeleteProviderProfile::R2_ENDPOINT);
		}
	}
}

TEST_CASE("GCS list failures use provider-specific authentication diagnostics", "[httpfs][s3][gcs][errors]") {
	SECTION("httplib") {
		RunGCSListAuthErrorScenario("httplib");
	}
	SECTION("curl") {
		RunGCSListAuthErrorScenario("curl");
	}
}

TEST_CASE("S3 request sessions reject conflicting configured headers before HTTP",
          "[httpfs][s3][request-session][headers]") {
	SECTION("httplib") {
		RunS3RejectedHeaderScenario("httplib");
	}
	SECTION("curl") {
		RunS3RejectedHeaderScenario("curl");
	}
}

TEST_CASE("S3 full HTTP endpoints route every request through the normalized base path",
          "[httpfs][s3][endpoint][request]") {
	SECTION("httplib") {
		RunNormalizedEndpointWireScenario("httplib");
	}
	SECTION("curl") {
		RunNormalizedEndpointWireScenario("curl");
	}
}

} // namespace duckdb
