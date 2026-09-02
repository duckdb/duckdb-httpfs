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

static void ConfigureGCSBearer(Connection &con, MockS3Server &server, const string &client_implementation) {
	ConfigureGCSClient(con, client_implementation);
	S3TestHelper::RequireQueryOk(con, StringUtil::Format(R"(
CREATE SECRET gcs_bearer (
	TYPE GCS,
	SCOPE 'gcs://refresh-bucket/',
	BEARER_TOKEN 'gcs-test-token',
	ENDPOINT '%s',
	USE_SSL false,
	URL_STYLE 'path'
))",
	                                                     server.Endpoint()));
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
	ConfigureGCSBearer(con, server, client_implementation);

	const string gcs_path = "gcs://refresh-bucket/object.bin";
	S3TestHelper::RequireQueryOk(con, "BEGIN TRANSACTION");
	auto &fs = FileSystem::GetFileSystem(*con.context);
	auto handle = fs.OpenFile(gcs_path, FileFlags::FILE_FLAGS_READ | FileFlags::FILE_FLAGS_DIRECT_IO);
	REQUIRE(handle);

	auto list_result = con.Query("SELECT file FROM glob('gcs://refresh-bucket/*.bin')");
	REQUIRE(list_result);
	INFO((list_result->HasError() ? list_result->GetError() : string()));
	REQUIRE_FALSE(list_result->HasError());
	REQUIRE(list_result->RowCount() == 1);

	fs.RemoveFiles({gcs_path});
	S3TestHelper::RequireQueryOk(con, "COMMIT");

	auto observations = server.Observations();
	INFO(MockS3DescribeObservations(observations));
	bool saw_object = false;
	bool saw_list = false;
	bool saw_bulk_delete = false;
	for (const auto &observation : observations) {
		if (observation.authorization != "Bearer gcs-test-token") {
			continue;
		}
		saw_object |= observation.method == "HEAD" && observation.target.find("object.bin") != string::npos;
		if (observation.method == "GET" && observation.target.find("list-type=2") != string::npos) {
			saw_list = true;
			REQUIRE(observation.target.find("?encoding-type=url&list-type=2&prefix=") != string::npos);
		}
		if (observation.method == "POST" && observation.target.find("delete") != string::npos) {
			saw_bulk_delete = true;
			REQUIRE(StringUtil::EndsWith(observation.target, "?delete="));
		}
	}
	REQUIRE(saw_object);
	REQUIRE(saw_list);
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
	return S3AuthParams::ReadFrom(secret_reader, path);
}

} // namespace

TEST_CASE("S3 provider policy resolves URL aliases and default scopes", "[httpfs][s3][provider]") {
	for (const auto &entry : {pair<string, S3ProviderType> {"s3://bucket/key", S3ProviderType::S3},
	                          pair<string, S3ProviderType> {"S3A://bucket/key", S3ProviderType::S3},
	                          pair<string, S3ProviderType> {"s3n://bucket/key", S3ProviderType::S3},
	                          pair<string, S3ProviderType> {"gcs://bucket/key", S3ProviderType::GCS},
	                          pair<string, S3ProviderType> {"GS://bucket/key", S3ProviderType::GCS},
	                          pair<string, S3ProviderType> {"r2://bucket/key", S3ProviderType::R2}}) {
		auto provider_match = S3Provider::MatchUrl(entry.first);
		REQUIRE(provider_match.type == entry.second);
	}
	REQUIRE_FALSE(S3Provider::TryMatchUrl("https://bucket/key"));
	REQUIRE_FALSE(S3Provider::TryMatchUrl("aws://bucket/key"));
	REQUIRE(S3Provider::DefaultSecretScope("s3") == vector<string> {"s3://", "s3n://", "s3a://"});
	REQUIRE(S3Provider::DefaultSecretScope("gcs") == vector<string> {"gcs://", "gs://"});
	REQUIRE(S3Provider::DefaultSecretScope("r2") == vector<string> {"r2://"});
	REQUIRE(S3Provider::DefaultSecretScope("aws") == vector<string> {""});
	try {
		S3Provider::MatchUrl("https://bucket/key");
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
		S3AuthParams auth_params;
		auth_params.provider_type = provider_type;
		auth_params.scheme_is_alias = scheme_is_alias;
		auth_params.endpoint = endpoint;
		INFO(endpoint);
		auto policy = S3Provider::GetMultipartUploadPolicy(auth_params);
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
	require_policy(S3ProviderType::S3, "account.us.r2.cloudflarestorage.com", fixed_policy, true);

	require_policy(S3ProviderType::S3, "s3.amazonaws.com", adaptive_policy);
	require_policy(S3ProviderType::GCS, "account.r2.cloudflarestorage.com", adaptive_policy);
	require_policy(S3ProviderType::S3, "r2.cloudflarestorage.com", adaptive_policy);
	require_policy(S3ProviderType::S3, "account.r2.cloudflarestorage.com.example.com", adaptive_policy);
	require_policy(S3ProviderType::S3, "evilr2.cloudflarestorage.com", adaptive_policy);
	require_policy(S3ProviderType::S3, "objects.example.com", adaptive_policy);
	require_policy(S3ProviderType::S3, "a.b.r2.cloudflarestorage.com", adaptive_policy);
}

TEST_CASE("S3 endpoint provenance controls AWS endpoint derivation", "[httpfs][s3][provider][endpoint]") {
	SECTION("automatic endpoints retain the existing region defaults") {
		S3AuthParams anonymous;
		anonymous.SetEndpoint("  ");
		S3Provider::InitializeAuthParams(anonymous);
		REQUIRE(anonymous.endpoint_mode == S3EndpointMode::AUTOMATIC);
		REQUIRE(anonymous.region.empty());
		REQUIRE(anonymous.endpoint == "s3.amazonaws.com");

		S3AuthParams credentialed;
		credentialed.SetEndpoint("s3.amazonaws.com");
		credentialed.access_key_id = "key";
		S3Provider::InitializeAuthParams(credentialed);
		REQUIRE(credentialed.endpoint_mode == S3EndpointMode::AUTOMATIC);
		REQUIRE(credentialed.region == "us-east-1");
		REQUIRE(credentialed.endpoint == "s3.us-east-1.amazonaws.com");
	}

	SECTION("explicit endpoints keep their host") {
		for (const auto &endpoint : {"s3.dualstack.us-east-1.amazonaws.com", "s3-fips.us-east-1.amazonaws.com",
		                             "s3.eu-west-1.amazonaws.com", "storage.example.com"}) {
			S3AuthParams auth_params;
			auth_params.SetEndpoint(endpoint);
			S3Provider::InitializeAuthParams(auth_params);
			INFO(endpoint);
			REQUIRE(auth_params.endpoint_mode == S3EndpointMode::EXPLICIT);
			REQUIRE(auth_params.endpoint == endpoint);
			REQUIRE(auth_params.region.empty());
			auth_params.SetRegion("ap-southeast-2");
			REQUIRE(auth_params.endpoint == endpoint);
		}
	}

	SECTION("AWS-shaped explicit endpoints retain the old credentialed region fallback") {
		S3AuthParams dualstack;
		dualstack.SetEndpoint("s3.dualstack.us-east-1.amazonaws.com");
		dualstack.access_key_id = "key";
		S3Provider::InitializeAuthParams(dualstack);
		REQUIRE(dualstack.region == "us-east-1");
		REQUIRE(dualstack.endpoint == "s3.dualstack.us-east-1.amazonaws.com");

		S3AuthParams fips;
		fips.SetEndpoint("s3-fips.us-east-1.amazonaws.com");
		fips.access_key_id = "key";
		S3Provider::InitializeAuthParams(fips);
		REQUIRE(fips.region.empty());
		REQUIRE(fips.endpoint == "s3-fips.us-east-1.amazonaws.com");
	}

	SECTION("endpoint mode participates in authentication identity") {
		S3AuthParams automatic;
		automatic.region = "us-east-1";
		S3Provider::InitializeAuthParams(automatic);
		S3AuthParams explicit_endpoint;
		explicit_endpoint.region = "us-east-1";
		explicit_endpoint.SetEndpoint("s3.us-east-1.amazonaws.com");
		S3Provider::InitializeAuthParams(explicit_endpoint);
		REQUIRE(automatic.endpoint == explicit_endpoint.endpoint);
		REQUIRE_FALSE(automatic == explicit_endpoint);
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
		REQUIRE(auth_params.endpoint == "storage.googleapis.com");
		REQUIRE(auth_params.endpoint_mode == S3EndpointMode::AUTOMATIC);
	}

	SECTION("GCS accepts a secret endpoint") {
		KeyValueSecret secret({"gcs://"}, Identifier("gcs"), Identifier("config"), Identifier("gcs_explicit"));
		secret.secret_map["endpoint"] = "gcs.example.com";
		auto auth_params = ReadSecretAuthParams(con, secret, "gcs://bucket/key");
		REQUIRE(auth_params.endpoint == "gcs.example.com");
		REQUIRE(auth_params.endpoint_mode == S3EndpointMode::EXPLICIT);
	}
}

TEST_CASE("S3 URL styles share one validation policy", "[httpfs][s3][provider][url-style]") {
	for (const auto &url_style : {"", "vhost", "virtual"}) {
		INFO(url_style);
		REQUIRE(S3Provider::ParseURLStyle(url_style) == S3URLStyle::VIRTUAL_HOSTED);
	}
	REQUIRE(S3Provider::ParseURLStyle("path") == S3URLStyle::PATH);
	for (const auto &url_style : {"default", "VHOST", "handwritten"}) {
		INFO(url_style);
		REQUIRE_THROWS(S3Provider::ParseURLStyle(url_style));
	}

	SECTION("defensive URL parsing rejects invalid runtime state") {
		S3AuthParams auth_params;
		auth_params.url_style = "handwritten";
		REQUIRE_THROWS(S3Provider::FinalizeAuthParams(auth_params));
		REQUIRE_THROWS(S3Url::Parse("s3://bucket/key", auth_params));
		REQUIRE_THROWS(S3Url::Resolve("s3://bucket/key?s3_url_style=path", auth_params));
	}

	SECTION("URL query values remain case-sensitive") {
		S3AuthParams auth_params;
		S3Provider::InitializeAuthParams(auth_params);
		REQUIRE_THROWS(S3Url::Resolve("s3://bucket/key?s3_url_style=VHOST", auth_params));
	}

	SECTION("compatibility mode keeps query-looking key text literal") {
		S3AuthParams auth_params;
		auth_params.s3_url_compatibility_mode = true;
		S3Provider::InitializeAuthParams(auth_params);
		auto parsed = S3Url::Resolve("s3://bucket/key?s3_url_style=handwritten", auth_params);
		REQUIRE(parsed.query_param.empty());
		REQUIRE(parsed.key == "key?s3_url_style=handwritten");
	}

	SECTION("dotted buckets use path style over TLS") {
		S3AuthParams auth_params;
		auth_params.url_style = "virtual";
		S3Provider::InitializeAuthParams(auth_params);
		auto parsed = S3Url::Parse("s3://bucket.with.dots/key", auth_params);
		REQUIRE(parsed.host == "s3.amazonaws.com");
		REQUIRE(parsed.path == "/bucket.with.dots/key");
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

TEST_CASE("S3 URL query settings are resolved independently of the HTTP client", "[httpfs][s3][url]") {
	SECTION("query credentials initialize the AWS region and endpoint") {
		S3AuthParams auth_params;
		auth_params.SetEndpoint("s3.amazonaws.com");
		auto parsed_url = S3Url::Resolve(
		    "s3://bucket/key?s3_access_key_id=hello+world&s3_secret_access_key=secret%2Bvalue", auth_params);
		REQUIRE(auth_params.access_key_id == "hello world");
		REQUIRE(auth_params.secret_access_key == "secret+value");
		REQUIRE(auth_params.region == "us-east-1");
		REQUIRE(auth_params.endpoint == "s3.us-east-1.amazonaws.com");
		REQUIRE(parsed_url.host == "bucket.s3.us-east-1.amazonaws.com");
	}

	SECTION("routing overrides are reflected in the parsed URL") {
		S3AuthParams auth_params;
		auth_params.region = "us-west-2";
		auth_params.SetEndpoint("s3.us-west-2.amazonaws.com");
		auto parsed_url = S3Url::Resolve("s3://bucket/key?s3_region=eu-west-1&s3_endpoint=s3.amazonaws.com&"
		                                 "s3_use_ssl=false&s3_url_style=path",
		                                 auth_params);
		REQUIRE(auth_params.region == "eu-west-1");
		REQUIRE(auth_params.endpoint == "s3.eu-west-1.amazonaws.com");
		REQUIRE(auth_params.endpoint_mode == S3EndpointMode::AUTOMATIC);
		REQUIRE(parsed_url.http_proto == "http://");
		REQUIRE(parsed_url.host == "s3.eu-west-1.amazonaws.com");
		REQUIRE(parsed_url.path == "/bucket/key");
	}

	SECTION("an endpoint override can switch from automatic to explicit") {
		S3AuthParams auth_params;
		auth_params.region = "us-east-1";
		S3Provider::InitializeAuthParams(auth_params);
		REQUIRE(auth_params.endpoint_mode == S3EndpointMode::AUTOMATIC);
		auto parsed_url =
		    S3Url::Resolve("s3://bucket/key?s3_endpoint=s3.dualstack.us-east-1.amazonaws.com", auth_params);
		REQUIRE(auth_params.endpoint_mode == S3EndpointMode::EXPLICIT);
		REQUIRE(auth_params.endpoint == "s3.dualstack.us-east-1.amazonaws.com");
		REQUIRE(parsed_url.host == "bucket.s3.dualstack.us-east-1.amazonaws.com");
	}

	SECTION("empty GCS routing overrides restore provider defaults") {
		S3AuthParams auth_params;
		auth_params.provider_type = S3ProviderType::GCS;
		auth_params.SetEndpoint("storage.googleapis.com");
		auth_params.url_style = "path";
		auto parsed_url = S3Url::Resolve("gcs://bucket/key?s3_endpoint=&s3_url_style=", auth_params);
		REQUIRE(auth_params.endpoint == "storage.googleapis.com");
		REQUIRE(auth_params.url_style == "path");
		REQUIRE(parsed_url.host == "storage.googleapis.com");
		REQUIRE(parsed_url.path == "/bucket/key");
	}

	SECTION("empty R2 endpoints fail instead of routing to AWS") {
		S3AuthParams auth_params;
		auth_params.provider_type = S3ProviderType::R2;
		auth_params.SetEndpoint("account.r2.cloudflarestorage.com");
		auth_params.url_style = "path";
		REQUIRE_THROWS(S3Url::Resolve("r2://bucket/key?s3_endpoint=", auth_params));
	}

	SECTION("empty values are accepted") {
		S3AuthParams auth_params;
		auth_params.SetEndpoint("s3.amazonaws.com");
		S3Url::Resolve("s3://bucket/key?s3_access_key_id&s3_secret_access_key=", auth_params);
		REQUIRE(auth_params.access_key_id.empty());
		REQUIRE(auth_params.secret_access_key.empty());
	}

	SECTION("duplicate decoded keys are rejected") {
		S3AuthParams auth_params;
		auth_params.SetEndpoint("s3.amazonaws.com");
		REQUIRE_THROWS(S3Url::Resolve("s3://bucket/key?s3_region=one&s3%5Fregion=two", auth_params));
	}

	SECTION("query keys remain case-sensitive") {
		S3AuthParams auth_params;
		auth_params.SetEndpoint("s3.amazonaws.com");
		REQUIRE_THROWS(S3Url::Resolve("s3://bucket/key?S3_region=one", auth_params));
	}

	SECTION("display URLs redact parameters unless compatibility mode treats them as key bytes") {
		S3AuthParams auth_params;
		REQUIRE(S3Url::GetDisplayUrl("s3://bucket/key?s3_secret_access_key=secret", auth_params) == "s3://bucket/key");
		auth_params.s3_url_compatibility_mode = true;
		REQUIRE(S3Url::GetDisplayUrl("s3://bucket/key?literal", auth_params) == "s3://bucket/key?literal");
	}
}

TEST_CASE("S3 URL compatibility mode reads canonical and legacy secret keys", "[httpfs][s3][secret]") {
	DuckDB db(nullptr);
	Connection con(db);
	S3TestHelper::LoadExtension(db);

	SECTION("canonical key") {
		KeyValueSecret secret({"s3://"}, Identifier("s3"), Identifier("config"), Identifier("canonical"));
		secret.secret_map["url_compatibility_mode"] = Value(true);
		REQUIRE(ReadSecretAuthParams(con, secret).s3_url_compatibility_mode);
	}

	SECTION("canonical key takes precedence") {
		KeyValueSecret secret({"s3://"}, Identifier("s3"), Identifier("config"), Identifier("precedence"));
		secret.secret_map["url_compatibility_mode"] = Value(false);
		secret.secret_map["s3_url_compatibility_mode"] = Value(true);
		REQUIRE_FALSE(ReadSecretAuthParams(con, secret).s3_url_compatibility_mode);
	}

	SECTION("legacy key") {
		KeyValueSecret secret({"s3://"}, Identifier("s3"), Identifier("config"), Identifier("legacy"));
		secret.secret_map["s3_url_compatibility_mode"] = Value(true);
		REQUIRE(ReadSecretAuthParams(con, secret).s3_url_compatibility_mode);
	}

	SECTION("global setting fallback") {
		S3TestHelper::RequireQueryOk(con, "SET s3_url_compatibility_mode=true");
		KeyValueSecret secret({"s3://"}, Identifier("s3"), Identifier("config"), Identifier("setting"));
		REQUIRE(ReadSecretAuthParams(con, secret).s3_url_compatibility_mode);
	}

	SECTION("invalid legacy URL style") {
		KeyValueSecret secret({"s3://"}, Identifier("s3"), Identifier("config"), Identifier("invalid_url_style"));
		secret.secret_map["url_style"] = "handwritten";
		REQUIRE_THROWS(ReadSecretAuthParams(con, secret));
	}
}

TEST_CASE("GCS HMAC signing region follows provider defaults", "[httpfs][s3][gcs][provider][signing]") {
	SECTION("regionless HMAC uses auto") {
		S3AuthParams auth_params;
		auth_params.provider_type = S3ProviderType::GCS;
		auth_params.access_key_id = "key";
		auth_params.secret_access_key = "secret";
		S3Provider::InitializeAuthParams(auth_params);
		REQUIRE(auth_params.region == "auto");
		REQUIRE(auth_params.endpoint == "storage.googleapis.com");
		REQUIRE(auth_params.url_style == "path");
	}

	SECTION("explicit regions win") {
		S3AuthParams auth_params;
		auth_params.provider_type = S3ProviderType::GCS;
		auth_params.access_key_id = "key";
		auth_params.secret_access_key = "secret";
		auth_params.region = "eu-west-1";
		S3Provider::InitializeAuthParams(auth_params);
		REQUIRE(auth_params.region == "eu-west-1");
	}

	SECTION("partial HMAC material still selects signing") {
		for (const auto &use_key_id : {false, true}) {
			S3AuthParams auth_params;
			auth_params.provider_type = S3ProviderType::GCS;
			if (use_key_id) {
				auth_params.access_key_id = "key";
			} else {
				auth_params.secret_access_key = "secret";
			}
			S3Provider::InitializeAuthParams(auth_params);
			REQUIRE(S3Provider::GetAuthType(auth_params) == S3AuthType::SIGV4);
			REQUIRE(auth_params.region == "auto");
		}
	}

	SECTION("URL overrides reapply or replace the default") {
		S3AuthParams empty_override;
		empty_override.provider_type = S3ProviderType::GCS;
		empty_override.access_key_id = "key";
		empty_override.secret_access_key = "secret";
		empty_override.region = "eu-west-1";
		S3Provider::InitializeAuthParams(empty_override);
		S3Url::Resolve("gcs://bucket/key?s3_region=", empty_override);
		REQUIRE(empty_override.region == "auto");

		S3AuthParams explicit_override;
		explicit_override.provider_type = S3ProviderType::GCS;
		explicit_override.access_key_id = "key";
		explicit_override.secret_access_key = "secret";
		S3Provider::InitializeAuthParams(explicit_override);
		S3Url::Resolve("gcs://bucket/key?s3_region=asia-east1", explicit_override);
		REQUIRE(explicit_override.region == "asia-east1");
	}

	SECTION("URL credentials receive the default during finalization") {
		S3AuthParams auth_params;
		auth_params.provider_type = S3ProviderType::GCS;
		S3Provider::InitializeAuthParams(auth_params);
		REQUIRE(auth_params.region.empty());
		S3Url::Resolve("gcs://bucket/key?s3_access_key_id=key&s3_secret_access_key=secret", auth_params);
		REQUIRE(auth_params.region == "auto");
	}

	SECTION("authentication modes that do not sign remain unchanged") {
		S3AuthParams bearer;
		bearer.provider_type = S3ProviderType::GCS;
		bearer.oauth2_bearer_token = "token";
		bearer.access_key_id = "key";
		bearer.secret_access_key = "secret";
		S3Provider::InitializeAuthParams(bearer);
		REQUIRE(S3Provider::GetAuthType(bearer) == S3AuthType::BEARER);
		REQUIRE(bearer.region.empty());

		S3AuthParams anonymous;
		anonymous.provider_type = S3ProviderType::GCS;
		S3Provider::InitializeAuthParams(anonymous);
		REQUIRE(S3Provider::GetAuthType(anonymous) == S3AuthType::ANONYMOUS);
		REQUIRE(anonymous.region.empty());
	}

	SECTION("other providers retain their custom-endpoint behavior") {
		for (const auto provider_type : {S3ProviderType::S3, S3ProviderType::R2}) {
			S3AuthParams auth_params;
			auth_params.provider_type = provider_type;
			auth_params.access_key_id = "key";
			auth_params.secret_access_key = "secret";
			auth_params.SetEndpoint("storage.example.com");
			S3Provider::InitializeAuthParams(auth_params);
			REQUIRE(auth_params.region.empty());
		}
	}
}

TEST_CASE("S3 provider policy selects request authentication", "[httpfs][s3][provider][signing]") {
	::AESStateSSLFactory encryption_util;
	ParsedS3Url parsed_url;
	parsed_url.path = "/bucket/key";
	parsed_url.host = "storage.example.com";

	SECTION("anonymous") {
		S3AuthParams auth_params;
		auto headers = S3RequestUtil::CreateHeaders(encryption_util, parsed_url, S3RequestQuery(),
		                                            RequestType::GET_REQUEST, auth_params);
		REQUIRE(headers.GetHeaderValue("Host") == parsed_url.host);
		REQUIRE_FALSE(headers.HasHeader("Authorization"));
	}

	for (const auto provider_type : {S3ProviderType::S3, S3ProviderType::R2, S3ProviderType::GCS}) {
		S3AuthParams auth_params;
		auth_params.provider_type = provider_type;
		auth_params.region = "auto";
		auth_params.access_key_id = "key";
		auth_params.secret_access_key = "secret";
		auto headers =
		    S3RequestUtil::CreateHeaders(encryption_util, parsed_url, S3RequestQuery(), RequestType::GET_REQUEST,
		                                 auth_params, "20260806", "20260806T120000Z");
		REQUIRE(StringUtil::StartsWith(headers.GetHeaderValue("Authorization"), "AWS4-HMAC-SHA256"));
	}

	SECTION("GCS bearer takes precedence over HMAC") {
		S3AuthParams auth_params;
		auth_params.provider_type = S3ProviderType::GCS;
		auth_params.access_key_id = "key";
		auth_params.secret_access_key = "secret";
		auth_params.oauth2_bearer_token = "token";
		auto headers = S3RequestUtil::CreateHeaders(encryption_util, parsed_url, S3RequestQuery({{"delete", ""}}),
		                                            RequestType::POST_REQUEST, auth_params, "", "", "payload",
		                                            "application/xml", "content-md5");
		REQUIRE(headers.GetHeaderValue("Authorization") == "Bearer token");
		REQUIRE(headers.GetHeaderValue("Content-Type") == "application/xml");
		REQUIRE(headers.GetHeaderValue("Content-MD5") == "content-md5");
		REQUIRE_FALSE(headers.HasHeader("x-amz-date"));
	}
}

TEST_CASE("S3 configured headers are validated before request authentication", "[httpfs][s3][headers]") {
	::AESStateSSLFactory encryption_util;
	ParsedS3Url parsed_url;
	parsed_url.path = "/bucket/key";
	parsed_url.host = "storage.example.com";

	vector<S3AuthParams> auth_params(3);
	auth_params[1].region = "us-east-1";
	auth_params[1].access_key_id = "key";
	auth_params[1].secret_access_key = "secret";
	auth_params[2].provider_type = S3ProviderType::GCS;
	auth_params[2].oauth2_bearer_token = "token";

	auto create_headers = [&](const S3AuthParams &auth, const unordered_map<string, string> &extra_headers,
	                          const string &user_agent = "httpfs-agent") {
		return S3RequestUtil::CreateHeaders(encryption_util, parsed_url, S3RequestQuery(), RequestType::GET_REQUEST,
		                                    auth, "", "", "", "", "", extra_headers, user_agent);
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
	S3AuthParams auth_params;
	auth_params.region = "us-east-1";
	auth_params.SetEndpoint("s3.amazonaws.com");
	auth_params.access_key_id = "key";
	auth_params.secret_access_key = "secret";
	auto snapshot = make_shared_ptr<S3RequestSnapshot>(http_params, auth_params, "s3://bucket/key",
	                                                   weak_ptr<ClientContext>(), false);
	HTTPRequestSession session(snapshot);
	::AESStateSSLFactory encryption_util;
	idx_t request_count = 0;

	REQUIRE_THROWS(S3RequestExecutor::RunSession(
	    encryption_util, session, "s3://bucket/key", RequestType::GET_REQUEST, S3RequestTarget::OBJECT,
	    [](const ParsedS3Url &) { return S3RequestQuery(); }, "", "", "",
	    [&](S3RequestData &) {
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

	S3AuthParams auth_params;
	auth_params.provider_type = S3ProviderType::S3;
	auth_params.region = "eu-west-1";
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
		S3AuthParams auth_params;
		auth_params.provider_type = provider_type;
		auth_params.region = "test-region";
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
		S3AuthParams auth_params;
		auth_params.provider_type = entry.first;
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
	S3AuthParams auth_params;
	auth_params.provider_type = S3ProviderType::S3;
	auth_params.region = "request-region";
	auth_params.SetEndpoint("s3.request-region.amazonaws.com");
	auto snapshot = make_shared_ptr<S3RequestSnapshot>(http_params, auth_params, "s3://bucket/key",
	                                                   weak_ptr<ClientContext>(), false);
	HTTPRequestSession session(snapshot);
	::AESStateSSLFactory encryption_util;
	S3RequestContext request_context;

	auto response = S3RequestExecutor::RunSession(
	    encryption_util, session, "s3://bucket/key?s3_secret_access_key=hidden", RequestType::GET_REQUEST,
	    S3RequestTarget::OBJECT, [](const ParsedS3Url &) { return S3RequestQuery(); }, "", "", "",
	    [&](S3RequestData &request_data) {
		    CHECK(request_data.auth_params.region == "request-region");
		    string previous_region;
		    REQUIRE(S3RequestExecutor::SetSessionRegion(session, "published-region", previous_region));
		    auto result = make_uniq<HTTPResponse>(HTTPStatusCode::BadRequest_400);
		    result->reason = "Bad Request";
		    result->body = "<Error><Code>InvalidRequest</Code></Error>";
		    return result;
	    },
	    {}, request_context);

	REQUIRE(response);
	CHECK(session.Capture().snapshot->Cast<S3RequestSnapshot>().auth_params.region == "published-region");
	CHECK(request_context.auth_params.region == "request-region");
	CHECK(request_context.display_url == "s3://bucket/key");
	auto error = ErrorData(S3RequestUtil::GetError(request_context.auth_params, *response, request_context.request_type,
	                                               "reading", request_context.display_url));
	CHECK(StringUtil::Contains(error.RawMessage(), "Provided region is: \"request-region\""));
	CHECK_FALSE(StringUtil::Contains(error.RawMessage(), "published-region"));
	CHECK_FALSE(StringUtil::Contains(error.RawMessage(), "hidden"));
}

TEST_CASE("S3 request signing remains deterministic", "[httpfs][s3][signing]") {
	::AESStateSSLFactory encryption_util;
	S3AuthParams auth_params;
	auth_params.region = "us-east-1";
	auth_params.access_key_id = "AKIAIOSFODNN7EXAMPLE";
	auth_params.secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
	ParsedS3Url parsed_url;
	parsed_url.path = "/test.txt";
	parsed_url.host = "examplebucket.s3.amazonaws.com";

	auto headers = S3RequestUtil::CreateHeaders(encryption_util, parsed_url, S3RequestQuery(), RequestType::GET_REQUEST,
	                                            auth_params, "20130524", "20130524T000000Z");

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
	S3AuthParams auth_params;
	auth_params.region = "eu-west-1";
	auth_params.access_key_id = "key";
	auth_params.secret_access_key = "secret";
	auth_params.session_token = "token";
	auth_params.kms_key_id = "kms-key";
	auth_params.requester_pays = true;
	ParsedS3Url parsed_url;
	parsed_url.path = "/bucket/key";
	parsed_url.host = "bucket.example.com";

	auto headers = S3RequestUtil::CreateHeaders(encryption_util, parsed_url, S3RequestQuery(), RequestType::PUT_REQUEST,
	                                            auth_params, "20260730", "20260730T120000Z", "",
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
}

TEST_CASE("S3 request signing canonicalizes configured extension headers", "[httpfs][s3][signing][headers]") {
	::AESStateSSLFactory encryption_util;
	S3AuthParams auth_params;
	auth_params.region = "us-east-1";
	auth_params.access_key_id = "key";
	auth_params.secret_access_key = "secret";
	ParsedS3Url parsed_url;
	parsed_url.path = "/bucket/key";
	parsed_url.host = "bucket.example.com";
	unordered_map<string, string> raw_headers {
	    {"X-AmZ-Meta-Color", "\t blue  green \t"}, {"x-GoOg-Meta-Mode", "  fast\tmode  "}, {"X-Ordinary", "value"}};
	unordered_map<string, string> normalized_headers {
	    {"x-amz-meta-color", "blue green"}, {"X-GOOG-META-MODE", "fast mode"}, {"X-Ordinary", "value"}};

	auto raw = S3RequestUtil::CreateHeaders(encryption_util, parsed_url, S3RequestQuery(), RequestType::GET_REQUEST,
	                                        auth_params, "20260831", "20260831T120000Z", "", "", "", raw_headers,
	                                        "httpfs-agent");
	auto normalized = S3RequestUtil::CreateHeaders(encryption_util, parsed_url, S3RequestQuery(),
	                                               RequestType::GET_REQUEST, auth_params, "20260831",
	                                               "20260831T120000Z", "", "", "", normalized_headers, "httpfs-agent");

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
	S3AuthParams auth_params;
	auth_params.region = "us-east-1";
	auth_params.access_key_id = "key";
	auth_params.secret_access_key = "secret";
	ParsedS3Url parsed_url;
	parsed_url.path = "/bucket/key";
	parsed_url.host = "bucket.example.com";
	unordered_map<string, string> raw_headers {{"X-AmZ-Meta-Empty", ""}, {"x-GoOg-Meta-Whitespace", "\t  \t"}};
	unordered_map<string, string> normalized_headers {{"x-amz-meta-empty", ""}, {"X-GOOG-META-WHITESPACE", ""}};

	auto raw = S3RequestUtil::CreateHeaders(encryption_util, parsed_url, S3RequestQuery(), RequestType::GET_REQUEST,
	                                        auth_params, "20260831", "20260831T120000Z", "", "", "", raw_headers);
	auto normalized =
	    S3RequestUtil::CreateHeaders(encryption_util, parsed_url, S3RequestQuery(), RequestType::GET_REQUEST,
	                                 auth_params, "20260831", "20260831T120000Z", "", "", "", normalized_headers);

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
	S3AuthParams auth_params;
	auth_params.region = "us-east-1";
	auth_params.access_key_id = "key";
	auth_params.secret_access_key = "secret";
	ParsedS3Url parsed_url;
	parsed_url.path = "/bucket/key";
	parsed_url.host = "bucket.example.com";
	unordered_map<string, string> extra_headers {{"X-AmZ-Meta-Region", "region-value"}};

	auto us_east_1 =
	    S3RequestUtil::CreateHeaders(encryption_util, parsed_url, S3RequestQuery(), RequestType::GET_REQUEST,
	                                 auth_params, "20260831", "20260831T120000Z", "", "", "", extra_headers);
	auth_params.region = "eu-west-1";
	auto eu_west_1 =
	    S3RequestUtil::CreateHeaders(encryption_util, parsed_url, S3RequestQuery(), RequestType::GET_REQUEST,
	                                 auth_params, "20260831", "20260831T120000Z", "", "", "", extra_headers);

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
		S3AuthParams auth_params;
		auth_params.region = "us-east-1";
		auth_params.access_key_id = "key";
		auth_params.secret_access_key = "secret";
		ParsedS3Url parsed_url;
		parsed_url.path = "/bucket/key";
		parsed_url.host = "bucket.example.com";
		auto first = S3RequestUtil::CreateHeaders(
		    encryption_util, parsed_url, S3RequestQuery({{"uploadId", "opaque&id"}, {"partNumber", "12"}}),
		    RequestType::PUT_REQUEST, auth_params, "20260806", "20260806T120000Z");
		auto second = S3RequestUtil::CreateHeaders(
		    encryption_util, parsed_url, S3RequestQuery({{"partNumber", "12"}, {"uploadId", "opaque&id"}}),
		    RequestType::PUT_REQUEST, auth_params, "20260806", "20260806T120000Z");
		REQUIRE(first.GetHeaderValue("Authorization") == second.GetHeaderValue("Authorization"));
		REQUIRE(first.GetHeaderValue("Authorization") ==
		        "AWS4-HMAC-SHA256 Credential=key/20260806/us-east-1/s3/aws4_request, "
		        "SignedHeaders=host;x-amz-content-sha256;x-amz-date, "
		        "Signature=7d31006078e4c8754eb70f96358af8f4c84a60186bf8e8fe1605b9bb90fcffad");
		auto empty_query =
		    S3RequestUtil::CreateHeaders(encryption_util, parsed_url, S3RequestQuery(), RequestType::PUT_REQUEST,
		                                 auth_params, "20260806", "20260806T120000Z");
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

TEST_CASE("S3 bulk delete preserves endpoint provenance", "[httpfs][s3][delete][endpoint]") {
	SECTION("httplib") {
		RunBulkDeleteEndpointModeIdentityScenario("httplib");
	}
	SECTION("curl") {
		RunBulkDeleteEndpointModeIdentityScenario("curl");
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

} // namespace duckdb
