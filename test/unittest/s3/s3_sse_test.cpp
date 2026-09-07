#include "catch.hpp"

#include "s3/mock_s3_server.hpp"
#include "s3/s3_test_helper.hpp"

#include "s3/s3_auth.hpp"
#include "s3/s3_provider.hpp"

#include "duckdb.hpp"
#include "duckdb/catalog/catalog_transaction.hpp"
#include "duckdb/common/file_system.hpp"
#include "duckdb/common/multi_file/multi_file_list.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/main/client_context_file_opener.hpp"
#include "duckdb/main/secret/secret.hpp"
#include "duckdb/main/secret/secret_manager.hpp"
#include "test_helpers.hpp"

#include <algorithm>
#include <cstring>

namespace duckdb {

namespace {

static constexpr const char *SSE_C_KEY = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=";
static constexpr const char *SSE_C_KEY_MD5 = "hRasmdxgYDKV3nvbahU1MA==";
static constexpr const char *REFRESHED_SSE_C_KEY = "ZmVkY2JhOTg3NjU0MzIxMGZlZGNiYTk4NzY1NDMyMTA=";
static constexpr const char *REFRESHED_SSE_C_KEY_MD5 = "dT1y7SEiqn6YCJ3QeqwoIw==";
static constexpr const char *SSE_C_ALGORITHM_HEADER = "x-amz-server-side-encryption-customer-algorithm";
static constexpr const char *SSE_C_KEY_HEADER = "x-amz-server-side-encryption-customer-key";
static constexpr const char *SSE_C_KEY_MD5_HEADER = "x-amz-server-side-encryption-customer-key-md5";

static string RequireQueryError(Connection &con, const string &query) {
	auto result = con.Query(query);
	REQUIRE(result);
	REQUIRE(result->HasError());
	return result->GetError();
}

template <class CALLBACK>
static void RequireExceptionContains(CALLBACK callback, const string &expected) {
	string error;
	try {
		callback();
	} catch (std::exception &ex) {
		error = ex.what();
	}
	REQUIRE(StringUtil::Contains(error, expected));
}

static int64_t QueryCount(Connection &con, const string &query) {
	auto result = con.Query(query);
	REQUIRE(result);
	INFO((result->HasError() ? result->GetError() : string()));
	REQUIRE_FALSE(result->HasError());
	REQUIRE(result->RowCount() == 1);
	return result->GetValue(0, 0).GetValue<int64_t>();
}

static void ConfigureClient(Connection &con, const string &client_implementation) {
	S3TestHelper::RequireQueryOk(con,
	                             StringUtil::Format("SET httpfs_client_implementation='%s'", client_implementation));
	S3TestHelper::RequireQueryOk(con, "SET httpfs_connection_caching=false");
	S3TestHelper::RequireQueryOk(con, "SET enable_global_s3_configuration=false");
	S3TestHelper::RequireQueryOk(con, "SET enable_curl_server_cert_verification=false");
	S3TestHelper::RequireQueryOk(con, "SET enable_server_cert_verification=false");
}

static void CreateSSESecret(Connection &con, const string &name, const string &scope, const string &endpoint,
                            const string &key = SSE_C_KEY, const string &extra_options = string()) {
	S3TestHelper::RequireQueryOk(con, StringUtil::Format(R"(
CREATE OR REPLACE SECRET %s (
	TYPE S3,
	SCOPE '%s',
	KEY_ID 'SSE_TEST_KEY',
	SECRET 'SSE_TEST_SECRET',
	REGION 'us-east-1',
	ENDPOINT '%s',
	USE_SSL false,
	VERIFY_SSL false,
	URL_STYLE 'path',
	SSE_C_KEY '%s'%s
))",
	                                                     name, scope, endpoint, key, extra_options));
}

static string ReadOneByte(Connection &con, const string &path, bool force_download) {
	S3TestHelper::RequireQueryOk(con, StringUtil::Format("SET force_download=%s", force_download ? "true" : "false"));
	auto &fs = FileSystem::GetFileSystem(*con.context);
	auto flags = FileFlags::FILE_FLAGS_READ;
	if (!force_download) {
		flags |= FileFlags::FILE_FLAGS_DIRECT_IO;
	}
	auto handle = fs.OpenFile(path, flags);
	string result(1, '\0');
	handle->Read(QueryContext(*con.context), &result[0], result.size(), 0);
	return result;
}

static void WriteObject(Connection &con, const string &path, idx_t size) {
	auto &fs = FileSystem::GetFileSystem(*con.context);
	auto handle = fs.OpenFile(path, FileFlags::FILE_FLAGS_WRITE | FileFlags::FILE_FLAGS_FILE_CREATE_NEW);
	string payload(size, 'x');
	handle->Write(QueryContext(*con.context), &payload[0], payload.size());
	handle->Close();
}

static vector<string> SignedHeaders(const MockS3RequestObservation &observation) {
	static constexpr const char *PREFIX = "SignedHeaders=";
	auto position = observation.authorization.find(PREFIX);
	if (position == string::npos) {
		return {};
	}
	position += strlen(PREFIX);
	auto end = observation.authorization.find(',', position);
	return StringUtil::Split(observation.authorization.substr(position, end - position), ";");
}

static idx_t CountValue(const vector<string> &values, const string &value) {
	return NumericCast<idx_t>(std::count(values.begin(), values.end(), value));
}

static bool KeyMatches(const S3SSECustomerKey &key, const string &expected_key, const string &expected_md5) {
	return key.GetKey() == expected_key && key.GetKeyMD5() == expected_md5;
}

static bool UsesSSECustomerHeaders(const MockS3RequestObservation &observation) {
	if (observation.method == "HEAD" || observation.method == "PUT") {
		return true;
	}
	if (observation.method == "GET") {
		return !StringUtil::Contains(observation.target, "list-type=2");
	}
	if (observation.method == "POST") {
		return StringUtil::Contains(observation.target, "uploads") ||
		       StringUtil::Contains(observation.target, "uploadId");
	}
	return false;
}

static void RequireSSECustomerHeaders(const MockS3RequestObservation &observation, const string &expected_md5) {
	auto signed_headers = SignedHeaders(observation);
	if (UsesSSECustomerHeaders(observation)) {
		REQUIRE(observation.sse_customer_algorithm == "AES256");
		REQUIRE(observation.sse_customer_key_md5 == expected_md5);
		REQUIRE(observation.has_sse_customer_key);
		REQUIRE(observation.sse_customer_key_matches);
		REQUIRE(MockS3HeaderValues(observation, SSE_C_KEY_HEADER) == vector<string> {"redacted"});
		REQUIRE(CountValue(signed_headers, SSE_C_ALGORITHM_HEADER) == 1);
		REQUIRE(CountValue(signed_headers, SSE_C_KEY_HEADER) == 1);
		REQUIRE(CountValue(signed_headers, SSE_C_KEY_MD5_HEADER) == 1);
	} else {
		REQUIRE(observation.sse_customer_algorithm.empty());
		REQUIRE(observation.sse_customer_key_md5.empty());
		REQUIRE_FALSE(observation.has_sse_customer_key);
		REQUIRE_FALSE(observation.sse_customer_key_matches);
		REQUIRE(MockS3HeaderValues(observation, SSE_C_KEY_HEADER).empty());
		REQUIRE(CountValue(signed_headers, SSE_C_ALGORITHM_HEADER) == 0);
		REQUIRE(CountValue(signed_headers, SSE_C_KEY_HEADER) == 0);
		REQUIRE(CountValue(signed_headers, SSE_C_KEY_MD5_HEADER) == 0);
	}
}

static S3AuthConfig SSEAuthConfig(S3ProviderType provider_type, const string &endpoint) {
	S3AuthConfig config;
	const char *prefix = provider_type == S3ProviderType::GCS  ? "gcs://"
	                     : provider_type == S3ProviderType::R2 ? "r2://"
	                                                           : "s3://";
	config.route = {provider_type, prefix, S3UrlSchemeOrigin::BUILTIN};
	config.endpoint = endpoint;
	config.endpoint_mode = S3EndpointMode::EXPLICIT;
	config.credentials.access_key_id = "key";
	config.credentials.secret_access_key = "secret";
	config.request_options.sse_customer_key = S3SSECustomerKey::Create(SSE_C_KEY);
	return config;
}

static string RequireOpenError(Connection &con, const string &path) {
	string error;
	try {
		auto &fs = FileSystem::GetFileSystem(*con.context);
		fs.OpenFile(path, FileFlags::FILE_FLAGS_READ | FileFlags::FILE_FLAGS_DIRECT_IO);
	} catch (std::exception &ex) {
		error = ex.what();
	}
	REQUIRE_FALSE(error.empty());
	return error;
}

static void RunSSECustomerMatrix(const string &client_implementation) {
	MockS3ServerConfig config;
	config.use_ssl = true;
	config.auth.stale_key_id = "NEVER_STALE";
	config.sse_customer.accepted_keys = {SSE_C_KEY};
	MockS3Server server(std::move(config));

	DuckDB db(nullptr);
	Connection con(db);
	S3TestHelper::LoadExtension(db);
	ConfigureClient(con, client_implementation);
	CreateSSESecret(con, "sse_customer", "s3://refresh-bucket/", "https://" + server.Endpoint());
	S3TestHelper::RequireQueryOk(con, "CALL enable_logging('HTTP')");

	auto &fs = FileSystem::GetFileSystem(*con.context);
	S3TestHelper::RequireQueryOk(con, "BEGIN TRANSACTION");
	REQUIRE(ReadOneByte(con, S3TestHelper::S3_PATH, false) == server.ObjectData().substr(0, 1));
	REQUIRE(ReadOneByte(con, S3TestHelper::S3_PATH, true) == server.ObjectData().substr(0, 1));
	WriteObject(con, S3TestHelper::S3_PATH, 32);
	S3TestHelper::RequireQueryOk(con, "SET s3_uploader_max_filesize='50GB'");
	WriteObject(con, S3TestHelper::S3_PATH, 10ULL * 1024ULL * 1024ULL + 1);
	auto glob_result = fs.Glob("s3://refresh-bucket/*.bin", FileGlobOptions::ALLOW_EMPTY, nullptr);
	REQUIRE(glob_result->GetAllFiles().size() == 1);
	fs.RemoveFile(S3TestHelper::S3_PATH);
	fs.RemoveFiles({S3TestHelper::S3_PATH, "s3://refresh-bucket/another.bin"});
	{
		auto handle =
		    fs.OpenFile(S3TestHelper::S3_PATH, FileFlags::FILE_FLAGS_WRITE | FileFlags::FILE_FLAGS_FILE_CREATE_NEW);
		string payload(10ULL * 1024ULL * 1024ULL + 1, 'a');
		handle->Write(QueryContext(*con.context), &payload[0], payload.size());
		handle->AbortWrite();
	}
	S3TestHelper::RequireQueryOk(con, "COMMIT");

	auto observations = server.Observations();
	auto description = MockS3DescribeObservations(observations);
	INFO(description);
	REQUIRE_FALSE(observations.empty());
	REQUIRE_FALSE(StringUtil::Contains(description, SSE_C_KEY));
	bool saw_head = false;
	bool saw_range_get = false;
	bool saw_full_get = false;
	bool saw_single_put = false;
	bool saw_multipart_init = false;
	bool saw_upload_part = false;
	bool saw_multipart_complete = false;
	bool saw_list = false;
	bool saw_object_delete = false;
	bool saw_bulk_delete = false;
	bool saw_multipart_abort = false;
	for (const auto &observation : observations) {
		RequireSSECustomerHeaders(observation, SSE_C_KEY_MD5);
		saw_head |= observation.method == "HEAD";
		saw_range_get |= observation.method == "GET" && !observation.range.empty();
		saw_full_get |= observation.method == "GET" && observation.range.empty() &&
		                !StringUtil::Contains(observation.target, "list-type=2");
		saw_single_put |= observation.method == "PUT" && !observation.part_number.IsValid();
		saw_multipart_init |= observation.method == "POST" && StringUtil::Contains(observation.target, "uploads");
		saw_upload_part |= observation.method == "PUT" && observation.part_number.IsValid();
		saw_multipart_complete |= observation.method == "POST" && StringUtil::Contains(observation.target, "uploadId");
		saw_list |= observation.method == "GET" && StringUtil::Contains(observation.target, "list-type=2");
		saw_object_delete |= observation.method == "DELETE" && observation.upload_id.empty();
		saw_bulk_delete |= observation.method == "POST" && StringUtil::Contains(observation.target, "delete");
		saw_multipart_abort |= observation.method == "DELETE" && !observation.upload_id.empty();
	}
	REQUIRE(saw_head);
	REQUIRE(saw_range_get);
	REQUIRE(saw_full_get);
	REQUIRE(saw_single_put);
	REQUIRE(saw_multipart_init);
	REQUIRE(saw_upload_part);
	REQUIRE(saw_multipart_complete);
	REQUIRE(saw_list);
	REQUIRE(saw_object_delete);
	REQUIRE(saw_bulk_delete);
	REQUIRE(saw_multipart_abort);

	REQUIRE(QueryCount(con, StringUtil::Format("SELECT count(*) FROM duckdb_logs WHERE contains(message, '%s')",
	                                           SSE_C_KEY)) == 0);
	REQUIRE(QueryCount(con, StringUtil::Format(R"(
SELECT count(*) FROM duckdb_logs_parsed('HTTP')
WHERE request.headers['%s'] = 'redacted'
)",
	                                           SSE_C_KEY_HEADER)) > 0);
}

static void RunSSECustomerAlias(const string &client_implementation) {
	MockS3ServerConfig config;
	config.use_ssl = true;
	config.auth.stale_key_id = "NEVER_STALE";
	config.sse_customer.accepted_keys = {SSE_C_KEY};
	MockS3Server server(std::move(config));

	DuckDB db(nullptr);
	Connection con(db);
	S3TestHelper::LoadExtension(db);
	ConfigureClient(con, client_implementation);
	S3TestHelper::RequireQueryOk(con, "SET s3_url_scheme_aliases=['oss']");
	CreateSSESecret(con, "sse_alias", "oss://refresh-bucket/", "https://" + server.Endpoint());
	S3TestHelper::RequireQueryOk(con, "BEGIN TRANSACTION");
	REQUIRE(ReadOneByte(con, "oss://refresh-bucket/object.bin", false) == server.ObjectData().substr(0, 1));
	S3TestHelper::RequireQueryOk(con, "COMMIT");
	for (const auto &observation : server.Observations()) {
		RequireSSECustomerHeaders(observation, SSE_C_KEY_MD5);
	}
}

static void RunSSECustomerValidation(const string &client_implementation) {
	MockS3ServerConfig config;
	config.use_ssl = true;
	config.auth.stale_key_id = "NEVER_STALE";
	MockS3Server server(std::move(config));

	DuckDB db(nullptr);
	Connection con(db);
	S3TestHelper::LoadExtension(db);
	ConfigureClient(con, client_implementation);
	auto https_endpoint = "https://" + server.Endpoint();
	S3TestHelper::RequireQueryOk(con, "BEGIN TRANSACTION");

	CreateSSESecret(con, "invalid_sse", "s3://refresh-bucket/", https_endpoint, SSE_C_KEY, ",\n\tKMS_KEY_ID 'kms-key'");
	REQUIRE(StringUtil::Contains(RequireOpenError(con, S3TestHelper::S3_PATH),
	                             "SSE_C_KEY and KMS_KEY_ID cannot be configured together"));
	REQUIRE(server.Observations().empty());

	S3TestHelper::RequireQueryOk(con, StringUtil::Format(R"(
CREATE OR REPLACE SECRET invalid_sse (
	TYPE S3, SCOPE 's3://refresh-bucket/', KEY_ID '', SECRET '', REGION 'us-east-1', ENDPOINT '%s',
	USE_SSL false, VERIFY_SSL false, URL_STYLE 'path', SSE_C_KEY '%s'
))",
	                                                     https_endpoint, SSE_C_KEY));
	REQUIRE(StringUtil::Contains(RequireOpenError(con, S3TestHelper::S3_PATH),
	                             "SSE_C_KEY requires both KEY_ID and SECRET"));
	REQUIRE(server.Observations().empty());

	S3TestHelper::RequireQueryOk(con, StringUtil::Format(R"(
CREATE OR REPLACE SECRET invalid_sse (
	TYPE S3, SCOPE 's3://refresh-bucket/', KEY_ID '', SECRET 'secret', REGION 'us-east-1', ENDPOINT '%s',
	USE_SSL false, VERIFY_SSL false, URL_STYLE 'path', SSE_C_KEY '%s'
))",
	                                                     https_endpoint, SSE_C_KEY));
	REQUIRE(StringUtil::Contains(RequireOpenError(con, S3TestHelper::S3_PATH),
	                             "SSE_C_KEY requires both KEY_ID and SECRET"));
	REQUIRE(server.Observations().empty());

	S3TestHelper::RequireQueryOk(con, StringUtil::Format(R"(
CREATE OR REPLACE SECRET invalid_sse (
	TYPE S3, SCOPE 's3://refresh-bucket/', KEY_ID 'key', SECRET '', REGION 'us-east-1', ENDPOINT '%s',
	USE_SSL false, VERIFY_SSL false, URL_STYLE 'path', SSE_C_KEY '%s'
))",
	                                                     https_endpoint, SSE_C_KEY));
	REQUIRE(StringUtil::Contains(RequireOpenError(con, S3TestHelper::S3_PATH),
	                             "SSE_C_KEY requires both KEY_ID and SECRET"));
	REQUIRE(server.Observations().empty());

	S3TestHelper::RequireQueryOk(con, StringUtil::Format(R"(
CREATE OR REPLACE SECRET invalid_sse (
	TYPE S3, SCOPE 's3://refresh-bucket/', KEY_ID 'key', SECRET 'secret', REGION 'us-east-1',
	ENDPOINT 'http://%s', USE_SSL true, URL_STYLE 'path', SSE_C_KEY '%s'
))",
	                                                     server.Endpoint(), SSE_C_KEY));
	REQUIRE(StringUtil::Contains(RequireOpenError(con, S3TestHelper::S3_PATH), "SSE_C_KEY requires an HTTPS endpoint"));
	REQUIRE(server.Observations().empty());

	CreateSSESecret(con, "invalid_sse", "s3://refresh-bucket/", "account.r2.cloudflarestorage.com");
	REQUIRE(StringUtil::Contains(RequireOpenError(con, S3TestHelper::S3_PATH),
	                             "SSE_C_KEY is only supported for S3-compatible endpoints"));
	REQUIRE(server.Observations().empty());
	S3TestHelper::RequireQueryOk(con, "ROLLBACK");
}

static void RunSSECustomerRefresh(const string &client_implementation) {
	MockS3ServerConfig config;
	config.use_ssl = true;
	config.auth.stale_key_id = S3TestHelper::STALE_KEY_ID;
	config.auth.refresh_target = MockS3RefreshTarget::HEAD;
	config.sse_customer.accepted_keys = {SSE_C_KEY, REFRESHED_SSE_C_KEY};
	MockS3Server server(std::move(config));

	DuckDB db(nullptr);
	Connection con(db);
	S3TestHelper::LoadExtension(db);
	S3TestHelper::RegisterRefreshProvider(db);
	ConfigureClient(con, client_implementation);
	S3TestHelper::RequireQueryOk(con, "SET httpfs_enable_credential_refresh=true");
	auto test_id = S3TestHelper::NextTestId();
	auto endpoint = "https://" + server.Endpoint();
	S3TestHelper::RequireQueryOk(con, StringUtil::Format(R"(
CREATE SECRET refresh_sse (
	TYPE S3,
	PROVIDER %s,
	SCOPE 's3://refresh-bucket/',
	KEY_ID '%s',
	SECRET '%s',
	REGION 'us-east-1',
	ENDPOINT '%s',
	USE_SSL false,
	VERIFY_SSL false,
	URL_STYLE 'path',
	SSE_C_KEY '%s',
	TEST_ID '%s',
	REFRESH_INFO MAP {
		'KEY_ID': '%s',
		'SECRET': '%s',
		'REGION': 'us-east-1',
		'ENDPOINT': '%s',
		'URL_STYLE': 'path',
		'SSE_C_KEY': '%s',
		'TEST_ID': '%s'
	}
))",
	                                                     S3TestHelper::TEST_PROVIDER, S3TestHelper::STALE_KEY_ID,
	                                                     S3TestHelper::STALE_SECRET, endpoint, SSE_C_KEY, test_id,
	                                                     S3TestHelper::FRESH_KEY_ID, S3TestHelper::FRESH_SECRET,
	                                                     endpoint, REFRESHED_SSE_C_KEY, test_id));

	S3TestHelper::RequireQueryOk(con, "BEGIN TRANSACTION");
	REQUIRE(ReadOneByte(con, S3TestHelper::S3_PATH, false) == server.ObjectData().substr(0, 1));
	S3TestHelper::RequireQueryOk(con, "COMMIT");
	auto observations = server.Observations();
	INFO(MockS3DescribeObservations(observations));
	REQUIRE(observations.size() >= 2);
	REQUIRE(observations[0].key_id == S3TestHelper::STALE_KEY_ID);
	REQUIRE(observations[0].sse_customer_key_md5 == SSE_C_KEY_MD5);
	REQUIRE(observations[1].key_id == S3TestHelper::FRESH_KEY_ID);
	REQUIRE(observations[1].sse_customer_key_md5 == REFRESHED_SSE_C_KEY_MD5);
	for (idx_t i = 0; i < observations.size(); i++) {
		auto &observation = observations[i];
		REQUIRE(observation.sse_customer_key_matches);
		REQUIRE_FALSE(StringUtil::Contains(MockS3DescribeObservations({observation}), SSE_C_KEY));
		REQUIRE_FALSE(StringUtil::Contains(MockS3DescribeObservations({observation}), REFRESHED_SSE_C_KEY));
		if (i > 0) {
			REQUIRE(observation.key_id == S3TestHelper::FRESH_KEY_ID);
			REQUIRE(observation.sse_customer_key_md5 == REFRESHED_SSE_C_KEY_MD5);
		}
	}
	S3TestHelper::AssertSingleRefresh(test_id);
}

} // namespace

TEST_CASE("S3 SSE-C key validation derives the required digest", "[httpfs][s3][sse-c][secret]") {
	auto key = S3SSECustomerKey::Create(SSE_C_KEY);
	REQUIRE(KeyMatches(key, SSE_C_KEY, SSE_C_KEY_MD5));
	REQUIRE(key == S3SSECustomerKey::Create(SSE_C_KEY));
	REQUIRE_FALSE(key == S3SSECustomerKey::Create(REFRESHED_SSE_C_KEY));

	const string invalid_sentinel = "SSE_C_KEY_SENTINEL_NOT_BASE64!";
	try {
		S3SSECustomerKey::Create(invalid_sentinel);
		FAIL("Expected invalid base64 to throw");
	} catch (std::exception &ex) {
		REQUIRE_FALSE(StringUtil::Contains(ex.what(), invalid_sentinel));
	}
	RequireExceptionContains([&]() { S3SSECustomerKey::Create("MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZQ=="); },
	                         "SSE_C_KEY must be a valid base64-encoded 256-bit key");
}

TEST_CASE("S3 SSE-C is limited to S3 secrets and plain S3 profiles", "[httpfs][s3][sse-c][secret]") {
	DuckDB db(nullptr);
	Connection con(db);
	S3TestHelper::LoadExtension(db);
	for (const auto secret_type : {"AWS", "R2", "GCS"}) {
		auto error = RequireQueryError(con, StringUtil::Format("CREATE SECRET invalid_%s (TYPE %s, SSE_C_KEY '%s')",
		                                                       StringUtil::Lower(secret_type), secret_type, SSE_C_KEY));
		REQUIRE(StringUtil::Contains(StringUtil::Lower(error), "sse_c_key"));
	}
	REQUIRE(QueryCount(con, "SELECT count(*) FROM duckdb_settings() WHERE name = 's3_sse_c_key'") == 0);

	auto gcs = SSEAuthConfig(S3ProviderType::GCS, "https://storage.googleapis.com");
	RequireExceptionContains([&]() { S3AuthResolver::Resolve(std::move(gcs), "gcs://bucket/key"); },
	                         "SSE_C_KEY is only supported for S3-compatible endpoints");
	auto r2 = SSEAuthConfig(S3ProviderType::R2, "https://account.r2.cloudflarestorage.com");
	RequireExceptionContains([&]() { S3AuthResolver::Resolve(std::move(r2), "r2://bucket/key"); },
	                         "SSE_C_KEY is only supported for S3-compatible endpoints");
}

TEST_CASE("S3 SSE-C secret display redacts direct and refresh material", "[httpfs][s3][sse-c][secret]") {
	DBConfig config;
	config.SetOptionByName("allow_unredacted_secrets", Value(true));
	DuckDB db(nullptr, &config);
	Connection con(db);
	S3TestHelper::LoadExtension(db);
	CreateSSESecret(con, "direct_sse", "s3://direct/", "https://storage.example.com");
	CreateSSESecret(con, "automatic_sse", "s3://automatic/", "https://storage.example.com", SSE_C_KEY,
	                ",\n\tREFRESH AUTO");
	CreateSSESecret(con, "explicit_sse", "s3://explicit/", "https://storage.example.com", SSE_C_KEY,
	                StringUtil::Format(",\n\tREFRESH_INFO MAP {'SSE_C_KEY': '%s'}", REFRESHED_SSE_C_KEY));

	for (const auto name : {"direct_sse", "automatic_sse", "explicit_sse"}) {
		REQUIRE(QueryCount(con, StringUtil::Format(R"(
SELECT count(*) FROM duckdb_secrets()
WHERE name = '%s' AND NOT contains(secret_string, '%s') AND NOT contains(secret_string, '%s')
)",
		                                           name, SSE_C_KEY, REFRESHED_SSE_C_KEY)) == 1);
		REQUIRE(QueryCount(con, StringUtil::Format(R"(
SELECT count(*) FROM duckdb_secrets(redact=false)
WHERE name = '%s' AND contains(secret_string, '%s')
)",
		                                           name, SSE_C_KEY)) == 1);
	}
	REQUIRE(QueryCount(con, R"(
SELECT count(*) FROM duckdb_secrets()
WHERE name = 'automatic_sse' AND contains(secret_string, 'refresh_info=redacted')
)") == 1);
	REQUIRE(QueryCount(con, R"(
SELECT count(*) FROM duckdb_secrets()
WHERE name = 'explicit_sse' AND contains(secret_string, 'refresh_info=redacted')
)") == 1);
	REQUIRE(QueryCount(con, StringUtil::Format(R"(
SELECT count(*) FROM duckdb_secrets(redact=false)
WHERE name = 'explicit_sse' AND contains(secret_string, '%s')
)",
	                                           REFRESHED_SSE_C_KEY)) == 1);
}

TEST_CASE("Persistent S3 SSE-C secrets preserve validated key material", "[httpfs][s3][sse-c][secret]") {
	auto secret_directory = TestCreatePath("httpfs_sse_c_persistent_" + S3TestHelper::NextTestId());
	TestDeleteDirectory(secret_directory);
	{
		DBConfig config;
		config.SetOptionByName("secret_directory", Value(secret_directory));
		config.SetOptionByName("allow_unredacted_secrets", Value(true));
		DuckDB db(nullptr, &config);
		Connection con(db);
		S3TestHelper::LoadExtension(db);
		S3TestHelper::RequireQueryOk(con, StringUtil::Format(R"(
CREATE PERSISTENT SECRET persistent_sse (
	TYPE S3, SCOPE 's3://persistent/', KEY_ID 'key', SECRET 'secret', REGION 'us-east-1',
	ENDPOINT 'https://storage.example.com', URL_STYLE 'path', SSE_C_KEY '%s',
	REFRESH_INFO MAP {'SSE_C_KEY': '%s'}
))",
		                                                     SSE_C_KEY, REFRESHED_SSE_C_KEY));
	}
	{
		DBConfig config;
		config.SetOptionByName("secret_directory", Value(secret_directory));
		config.SetOptionByName("allow_unredacted_secrets", Value(true));
		DuckDB db(nullptr, &config);
		Connection con(db);
		S3TestHelper::LoadExtension(db);
		REQUIRE(QueryCount(con, StringUtil::Format(R"(
SELECT count(*) FROM duckdb_secrets()
WHERE name = 'persistent_sse' AND NOT contains(secret_string, '%s') AND NOT contains(secret_string, '%s')
	AND contains(secret_string, 'sse_c_key=redacted') AND contains(secret_string, 'refresh_info=redacted')
)",
		                                           SSE_C_KEY, REFRESHED_SSE_C_KEY)) == 1);
		REQUIRE(QueryCount(con, StringUtil::Format(R"(
SELECT count(*) FROM duckdb_secrets(redact=false)
WHERE name = 'persistent_sse' AND contains(secret_string, '%s') AND contains(secret_string, '%s')
)",
		                                           SSE_C_KEY, REFRESHED_SSE_C_KEY)) == 1);

		auto &secret_manager = db.instance->GetSecretManager();
		S3TestHelper::RequireQueryOk(con, "BEGIN TRANSACTION");
		auto transaction = CatalogTransaction::GetSystemCatalogTransaction(*con.context);
		auto secret_entry = secret_manager.GetSecretByName(transaction, "persistent_sse");
		REQUIRE(secret_entry);
		auto &secret = secret_entry->secret->Cast<KeyValueSecret>();
		ClientContextFileOpener opener(*con.context);
		S3KeyValueReader reader {KeyValueSecretReader(secret, opener)};
		auto auth_params = S3AuthResolver::Resolve(reader, "s3://persistent/object.bin");
		REQUIRE(auth_params.GetRequestOptions().sse_customer_key);
		REQUIRE(KeyMatches(*auth_params.GetRequestOptions().sse_customer_key, SSE_C_KEY, SSE_C_KEY_MD5));
		S3TestHelper::RequireQueryOk(con, "ROLLBACK");
	}
	TestDeleteDirectory(secret_directory);
}

TEST_CASE("S3 SSE-C validates effective transport and credentials before dispatch", "[httpfs][s3][sse-c][request]") {
	for (const auto client_implementation : {"curl", "httplib"}) {
		DYNAMIC_SECTION(client_implementation) {
			RunSSECustomerValidation(client_implementation);
		}
	}
}

TEST_CASE("S3 SSE-C headers follow the object operation matrix", "[httpfs][s3][sse-c][request]") {
	for (const auto client_implementation : {"curl", "httplib"}) {
		DYNAMIC_SECTION(client_implementation) {
			RunSSECustomerMatrix(client_implementation);
		}
	}
}

TEST_CASE("S3 SSE-C supports configured URL scheme aliases", "[httpfs][s3][sse-c][alias]") {
	for (const auto client_implementation : {"curl", "httplib"}) {
		DYNAMIC_SECTION(client_implementation) {
			RunSSECustomerAlias(client_implementation);
		}
	}
}

TEST_CASE("S3 SSE-C credential refresh rebuilds the encrypted request headers", "[httpfs][s3][sse-c][refresh]") {
	for (const auto client_implementation : {"curl", "httplib"}) {
		DYNAMIC_SECTION(client_implementation) {
			RunSSECustomerRefresh(client_implementation);
		}
	}
}

} // namespace duckdb
