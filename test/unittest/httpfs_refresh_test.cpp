#include "catch.hpp"

#include "mock_s3_server.hpp"

#include "create_secret_functions.hpp"
#include "httpfs_client.hpp"
#include "httpfs_extension.hpp"

#include "duckdb.hpp"
#include "duckdb/common/file_system.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/main/client_context.hpp"
#include "duckdb/main/extension/extension_loader.hpp"
#include "duckdb/main/secret/secret.hpp"

#include <array>
#include <atomic>
#include <condition_variable>
#include <mutex>
#include <new>
#include <thread>
#include <unordered_map>

namespace duckdb {

namespace {

static constexpr const char *STALE_KEY_ID = "STALE_KEY";
static constexpr const char *FRESH_KEY_ID = "FRESH_KEY";
static constexpr const char *STALE_SECRET = "STALE_SECRET";
static constexpr const char *FRESH_SECRET = "FRESH_SECRET";
static constexpr const char *TEST_PROVIDER = "httpfs_refresh_test";
static constexpr const char *BUCKET = "refresh-bucket";
static constexpr const char *OBJECT_KEY = "object.bin";
static constexpr const char *S3_PATH = "s3://refresh-bucket/object.bin";

struct ProviderStats {
	idx_t initial_creations = 0;
	idx_t refresh_creations = 0;
	vector<string> key_ids;
};

struct ProviderRegistry {
	std::mutex lock;
	std::unordered_map<string, ProviderStats> stats;
};

static ProviderRegistry &GetProviderRegistry() {
	static ProviderRegistry registry;
	return registry;
}

static string GetOptionString(const CreateSecretInput &input, const string &key) {
	auto entry = input.options.find(key);
	if (entry == input.options.end() || entry->second.IsNull()) {
		return string();
	}
	return entry->second.ToString();
}

static void RecordProviderCall(const string &test_id, const string &key_id) {
	if (test_id.empty()) {
		return;
	}
	auto &registry = GetProviderRegistry();
	std::lock_guard<std::mutex> lock(registry.lock);
	auto &stats = registry.stats[test_id];
	stats.key_ids.push_back(key_id);
	if (key_id == STALE_KEY_ID) {
		stats.initial_creations++;
	} else if (key_id == FRESH_KEY_ID) {
		stats.refresh_creations++;
	}
}

static ProviderStats GetProviderStats(const string &test_id) {
	auto &registry = GetProviderRegistry();
	std::lock_guard<std::mutex> lock(registry.lock);
	auto entry = registry.stats.find(test_id);
	if (entry == registry.stats.end()) {
		return ProviderStats();
	}
	return entry->second;
}

struct TestS3SecretFunctions : public CreateS3SecretFunctions {
	static void SetTestNamedParams(CreateSecretFunction &function, string type) {
		SetBaseNamedParams(function, type);
		function.named_parameters["test_id"] = LogicalType::VARCHAR;
	}

	static unique_ptr<BaseSecret> CreateTestSecret(ClientContext &context, CreateSecretInput &input) {
		RecordProviderCall(GetOptionString(input, "test_id"), GetOptionString(input, "key_id"));

		auto delegated_input = input;
		auto test_id_entry = delegated_input.options.find("test_id");
		if (test_id_entry != delegated_input.options.end()) {
			delegated_input.options.erase(test_id_entry);
		}
		return CreateSecretFunctionInternal(context, delegated_input);
	}
};

static void LoadHTTPFSExtension(DuckDB &db) {
	if (db.ExtensionIsLoaded("httpfs")) {
		return;
	}
	ExtensionInfo extension_info;
	ExtensionActiveLoad load_info(*db.instance, extension_info, "httpfs");
	ExtensionLoader loader(load_info);
	HttpfsExtension extension;
	extension.Load(loader);
}

static void RegisterRefreshTestProvider(DuckDB &db) {
	ExtensionInfo extension_info;
	ExtensionActiveLoad load_info(*db.instance, extension_info, "httpfs_refresh_test");
	ExtensionLoader loader(load_info);

	CreateSecretFunction function;
	function.secret_type = "s3";
	function.provider = TEST_PROVIDER;
	function.function = TestS3SecretFunctions::CreateTestSecret;
	TestS3SecretFunctions::SetTestNamedParams(function, "s3");
	loader.RegisterFunction(function);
}

static void RequireQueryOk(Connection &con, const string &query) {
	auto result = con.Query(query);
	REQUIRE(result);
	INFO((result->HasError() ? result->GetError() : string()));
	REQUIRE_FALSE(result->HasError());
}

static string NextTestId() {
	static std::atomic<idx_t> next_id(0);
	return StringUtil::Format("httpfs_refresh_test_%llu", static_cast<unsigned long long>(++next_id));
}

static string ConfigureRefreshTest(DuckDB &db, Connection &con, MockS3Server &server,
                                   const string &client_implementation, bool connection_caching,
                                   bool refresh_enabled = true) {
	auto test_id = NextTestId();

	LoadHTTPFSExtension(db);
	RegisterRefreshTestProvider(db);

	RequireQueryOk(con, StringUtil::Format("SET httpfs_client_implementation='%s'", client_implementation));
	RequireQueryOk(con, StringUtil::Format("SET httpfs_connection_caching=%s", connection_caching ? "true" : "false"));
	RequireQueryOk(con,
	               StringUtil::Format("SET httpfs_enable_credential_refresh=%s", refresh_enabled ? "true" : "false"));
	RequireQueryOk(con, StringUtil::Format("SET s3_endpoint='%s'", server.Endpoint()));
	RequireQueryOk(con, "SET s3_region='us-east-1'");
	RequireQueryOk(con, "SET s3_use_ssl=false");
	RequireQueryOk(con, "SET s3_url_style='path'");

	RequireQueryOk(con, StringUtil::Format(R"(
CREATE SECRET refresh_s3 (
	TYPE S3,
	PROVIDER %s,
	SCOPE 's3://refresh-bucket/',
	KEY_ID '%s',
	SECRET '%s',
	TEST_ID '%s',
	REFRESH_INFO MAP {
		'KEY_ID': '%s',
		'SECRET': '%s',
		'TEST_ID': '%s'
	}
))",
	                                       TEST_PROVIDER, STALE_KEY_ID, STALE_SECRET, test_id, FRESH_KEY_ID,
	                                       FRESH_SECRET, test_id));
	return test_id;
}

static void ConfigureEndpointRefreshTest(DuckDB &db, Connection &con, MockS3Server &stale_server,
                                         MockS3Server &fresh_server, const string &client_implementation) {
	auto test_id = NextTestId();

	LoadHTTPFSExtension(db);
	RegisterRefreshTestProvider(db);

	RequireQueryOk(con, StringUtil::Format("SET httpfs_client_implementation='%s'", client_implementation));
	RequireQueryOk(con, "SET httpfs_connection_caching=false");
	RequireQueryOk(con, "SET httpfs_enable_credential_refresh=true");
	RequireQueryOk(con, "SET s3_region='us-east-1'");
	RequireQueryOk(con, "SET s3_use_ssl=false");
	RequireQueryOk(con, "SET s3_url_style='path'");

	RequireQueryOk(con, StringUtil::Format(R"(
CREATE SECRET refresh_s3 (
	TYPE S3,
	PROVIDER %s,
	SCOPE 's3://refresh-bucket/',
	KEY_ID '%s',
	SECRET '%s',
	ENDPOINT '%s',
	TEST_ID '%s',
	REFRESH_INFO MAP {
		'KEY_ID': '%s',
		'SECRET': '%s',
		'ENDPOINT': '%s',
		'TEST_ID': '%s'
	}
))",
	                                       TEST_PROVIDER, STALE_KEY_ID, STALE_SECRET, stale_server.Endpoint(), test_id,
	                                       STALE_KEY_ID, STALE_SECRET, fresh_server.Endpoint(), test_id));
}

static void AssertSingleRefresh(const string &test_id) {
	auto stats = GetProviderStats(test_id);
	REQUIRE(stats.initial_creations == 1);
	REQUIRE(stats.refresh_creations == 1);
}

static void AssertNoRefresh(const string &test_id) {
	auto stats = GetProviderStats(test_id);
	REQUIRE(stats.initial_creations == 1);
	REQUIRE(stats.refresh_creations == 0);
}

static bool HasRequestWithKey(const vector<MockS3RequestObservation> &observations, const string &key_id) {
	for (auto &observation : observations) {
		if (observation.key_id == key_id) {
			return true;
		}
	}
	return false;
}

static idx_t CountObservations(const vector<MockS3RequestObservation> &observations, const string &method,
                               const string &key_id, int status) {
	idx_t result = 0;
	for (auto &observation : observations) {
		if (observation.method == method && observation.key_id == key_id && observation.status == status) {
			result++;
		}
	}
	return result;
}

static idx_t CountExactObservations(const vector<MockS3RequestObservation> &observations, const string &method,
                                    const string &key_id, int status, const string &range = string(),
                                    const string &target_contains = string()) {
	idx_t result = 0;
	for (auto &observation : observations) {
		if (observation.method == method && observation.key_id == key_id && observation.status == status &&
		    observation.range == range &&
		    (target_contains.empty() || observation.target.find(target_contains) != string::npos)) {
			result++;
		}
	}
	return result;
}

static int AuthFailureStatus(MockS3AuthFailure auth_failure) {
	return auth_failure == MockS3AuthFailure::EXPIRED_TOKEN_400 ? 400 : 403;
}

template <class OPERATION>
static vector<MockS3RequestObservation>
RunRefreshScenario(MockS3RefreshTarget refresh_target, const string &client_implementation, bool connection_caching,
                   OPERATION operation, MockS3AuthFailure auth_failure = MockS3AuthFailure::ACCESS_DENIED_403) {
	MockS3ServerConfig config;
	config.bucket = BUCKET;
	config.object_key = OBJECT_KEY;
	config.stale_key_id = STALE_KEY_ID;
	config.refresh_target = refresh_target;
	config.auth_failure = auth_failure;
	auto object_data = config.object_data;
	MockS3Server server(std::move(config));

	DuckDB db(nullptr);
	Connection con(db);
	auto test_id = ConfigureRefreshTest(db, con, server, client_implementation, connection_caching);
	INFO(StringUtil::Format("refresh target: %s, stale status: %d, client: %s, connection caching: %s",
	                        MockS3RefreshTargetName(refresh_target), AuthFailureStatus(auth_failure),
	                        client_implementation, connection_caching ? "true" : "false"));
	RequireQueryOk(con, "BEGIN TRANSACTION");
	operation(con, object_data);
	RequireQueryOk(con, "COMMIT");
	auto observations = server.Observations();
	INFO(MockS3DescribeObservations(observations));
	AssertSingleRefresh(test_id);
	return observations;
}

static void OpenForRead(Connection &con, FileOpenFlags flags = FileFlags::FILE_FLAGS_READ) {
	auto &fs = FileSystem::GetFileSystem(*con.context);
	auto handle = fs.OpenFile(S3_PATH, flags);
	REQUIRE(handle);
}

static void RequireFullGetThrows(Connection &con) {
	bool threw = false;
	try {
		auto &fs = FileSystem::GetFileSystem(*con.context);
		auto handle = fs.OpenFile(S3_PATH, FileFlags::FILE_FLAGS_READ);
		string buffer(8, '\0');
		handle->Read(QueryContext(*con.context), &buffer[0], buffer.size(), 0);
	} catch (std::exception &) {
		threw = true;
	}
	REQUIRE(threw);
}

static void RunHeadRefreshScenario(const string &client_implementation, bool connection_caching,
                                   MockS3AuthFailure auth_failure = MockS3AuthFailure::ACCESS_DENIED_403) {
	auto observations = RunRefreshScenario(
	    MockS3RefreshTarget::HEAD, client_implementation, connection_caching,
	    [](Connection &con, const string &) {
		    OpenForRead(con, FileFlags::FILE_FLAGS_READ | FileFlags::FILE_FLAGS_DIRECT_IO);
	    },
	    auth_failure);
	REQUIRE(CountExactObservations(observations, "HEAD", STALE_KEY_ID, AuthFailureStatus(auth_failure)) == 1);
	REQUIRE(CountExactObservations(observations, "HEAD", FRESH_KEY_ID, 200) == 1);
}

static void RunFullGetRefreshScenario(const string &client_implementation, bool connection_caching,
                                      MockS3AuthFailure auth_failure = MockS3AuthFailure::ACCESS_DENIED_403) {
	auto observations = RunRefreshScenario(
	    MockS3RefreshTarget::FULL_GET, client_implementation, connection_caching,
	    [](Connection &con, const string &object_data) {
		    RequireQueryOk(con, "SET force_download=true");
		    auto &fs = FileSystem::GetFileSystem(*con.context);
		    auto handle = fs.OpenFile(S3_PATH, FileFlags::FILE_FLAGS_READ);
		    string buffer(8, '\0');
		    handle->Read(QueryContext(*con.context), &buffer[0], buffer.size(), 0);
		    REQUIRE(buffer == object_data.substr(0, buffer.size()));
	    },
	    auth_failure);
	REQUIRE(CountExactObservations(observations, "GET", STALE_KEY_ID, AuthFailureStatus(auth_failure)) == 1);
	REQUIRE(CountExactObservations(observations, "GET", FRESH_KEY_ID, 200) == 1);
}

static void RunRangeRefreshScenario(const string &client_implementation, bool connection_caching,
                                    MockS3AuthFailure auth_failure = MockS3AuthFailure::ACCESS_DENIED_403) {
	auto observations = RunRefreshScenario(
	    MockS3RefreshTarget::RANGE_GET, client_implementation, connection_caching,
	    [](Connection &con, const string &object_data) {
		    auto &fs = FileSystem::GetFileSystem(*con.context);
		    auto handle = fs.OpenFile(S3_PATH, FileFlags::FILE_FLAGS_READ | FileFlags::FILE_FLAGS_DIRECT_IO);

		    const idx_t first_offset = 7;
		    const idx_t first_read_size = 9;
		    string first_buffer(first_read_size, '\0');
		    handle->Read(QueryContext(*con.context), &first_buffer[0], first_read_size, first_offset);
		    REQUIRE(first_buffer == object_data.substr(first_offset, first_read_size));

		    const idx_t second_offset = 20;
		    const idx_t second_read_size = 5;
		    string second_buffer(second_read_size, '\0');
		    handle->Read(QueryContext(*con.context), &second_buffer[0], second_read_size, second_offset);
		    REQUIRE(second_buffer == object_data.substr(second_offset, second_read_size));
	    },
	    auth_failure);
	REQUIRE(CountExactObservations(observations, "GET", STALE_KEY_ID, AuthFailureStatus(auth_failure), "bytes=7-15") ==
	        1);
	REQUIRE(CountExactObservations(observations, "GET", FRESH_KEY_ID, 206, "bytes=7-15") == 1);
	REQUIRE(CountExactObservations(observations, "GET", FRESH_KEY_ID, 206, "bytes=20-24") == 1);
	REQUIRE(CountExactObservations(observations, "GET", STALE_KEY_ID, AuthFailureStatus(auth_failure), "bytes=20-24") ==
	        0);
}

static void RunPutRefreshScenario(const string &client_implementation, bool connection_caching,
                                  MockS3AuthFailure auth_failure = MockS3AuthFailure::ACCESS_DENIED_403) {
	auto observations = RunRefreshScenario(
	    MockS3RefreshTarget::PUT, client_implementation, connection_caching,
	    [](Connection &con, const string &) {
		    auto &fs = FileSystem::GetFileSystem(*con.context);
		    auto handle = fs.OpenFile(S3_PATH, FileFlags::FILE_FLAGS_WRITE | FileFlags::FILE_FLAGS_FILE_CREATE_NEW);
		    string payload = "hello from httpfs refresh";
		    handle->Write(QueryContext(*con.context), &payload[0], payload.size());
		    handle->Close();
	    },
	    auth_failure);
	REQUIRE(CountExactObservations(observations, "PUT", STALE_KEY_ID, AuthFailureStatus(auth_failure)) == 1);
	REQUIRE(CountExactObservations(observations, "PUT", FRESH_KEY_ID, 200) == 1);
}

static void WriteMultipartPayload(Connection &con) {
	RequireQueryOk(con, "SET s3_uploader_max_filesize='50GB'");
	RequireQueryOk(con, "SET s3_uploader_thread_limit=1");
	auto &fs = FileSystem::GetFileSystem(*con.context);
	auto handle = fs.OpenFile(S3_PATH, FileFlags::FILE_FLAGS_WRITE | FileFlags::FILE_FLAGS_FILE_CREATE_NEW);
	string payload(10 * 1024 * 1024 + 1, 'x');
	handle->Write(QueryContext(*con.context), &payload[0], payload.size());
	handle->Close();
}

// A payload small enough to be a single-shot PUT (no multipart), so the S3 request loop is the only
// retry layer and the PUT count reflects exactly that loop's behavior.
static void WriteSinglePutPayload(Connection &con) {
	auto &fs = FileSystem::GetFileSystem(*con.context);
	auto handle = fs.OpenFile(S3_PATH, FileFlags::FILE_FLAGS_WRITE | FileFlags::FILE_FLAGS_FILE_CREATE_NEW);
	string payload = "single-shot payload";
	handle->Write(QueryContext(*con.context), &payload[0], payload.size());
	handle->Close();
}

static void
RunMultipartInitiatePostRefreshScenario(const string &client_implementation, bool connection_caching,
                                        MockS3AuthFailure auth_failure = MockS3AuthFailure::ACCESS_DENIED_403) {
	auto observations = RunRefreshScenario(
	    MockS3RefreshTarget::MULTIPART_INITIATE_POST, client_implementation, connection_caching,
	    [](Connection &con, const string &) { WriteMultipartPayload(con); }, auth_failure);
	REQUIRE(CountExactObservations(observations, "POST", STALE_KEY_ID, AuthFailureStatus(auth_failure), string(),
	                               "uploads") == 1);
	REQUIRE(CountExactObservations(observations, "POST", FRESH_KEY_ID, 200, string(), "uploads") == 1);
	REQUIRE(CountExactObservations(observations, "POST", FRESH_KEY_ID, 200, string(), "uploadId") == 1);
}

static void
RunMultipartCompletePostRefreshScenario(const string &client_implementation, bool connection_caching,
                                        MockS3AuthFailure auth_failure = MockS3AuthFailure::ACCESS_DENIED_403) {
	auto observations = RunRefreshScenario(
	    MockS3RefreshTarget::MULTIPART_COMPLETE_POST, client_implementation, connection_caching,
	    [](Connection &con, const string &) { WriteMultipartPayload(con); }, auth_failure);
	REQUIRE(CountExactObservations(observations, "POST", STALE_KEY_ID, AuthFailureStatus(auth_failure), string(),
	                               "uploadId") == 1);
	REQUIRE(CountExactObservations(observations, "POST", FRESH_KEY_ID, 200, string(), "uploadId") == 1);
}

static void RunBulkDeletePostRefreshScenario(const string &client_implementation, bool connection_caching,
                                             MockS3AuthFailure auth_failure = MockS3AuthFailure::ACCESS_DENIED_403) {
	auto observations = RunRefreshScenario(
	    MockS3RefreshTarget::BULK_DELETE_POST, client_implementation, connection_caching,
	    [](Connection &con, const string &) {
		    auto &fs = FileSystem::GetFileSystem(*con.context);
		    vector<string> paths;
		    paths.push_back(S3_PATH);
		    fs.RemoveFiles(paths);
	    },
	    auth_failure);
	REQUIRE(CountExactObservations(observations, "POST", STALE_KEY_ID, AuthFailureStatus(auth_failure), string(),
	                               "delete") == 1);
	REQUIRE(CountExactObservations(observations, "POST", FRESH_KEY_ID, 200, string(), "delete") == 1);
}

static void RunBulkDeleteEndpointRefreshScenario(const string &client_implementation) {
	MockS3ServerConfig stale_config;
	stale_config.bucket = BUCKET;
	stale_config.object_key = OBJECT_KEY;
	stale_config.stale_key_id = STALE_KEY_ID;
	stale_config.refresh_target = MockS3RefreshTarget::BULK_DELETE_POST;
	MockS3Server stale_server(std::move(stale_config));

	MockS3ServerConfig fresh_config;
	fresh_config.bucket = BUCKET;
	fresh_config.object_key = OBJECT_KEY;
	fresh_config.stale_key_id = "NEVER_STALE";
	fresh_config.refresh_target = MockS3RefreshTarget::BULK_DELETE_POST;
	MockS3Server fresh_server(std::move(fresh_config));

	DuckDB db(nullptr);
	Connection con(db);
	ConfigureEndpointRefreshTest(db, con, stale_server, fresh_server, client_implementation);

	RequireQueryOk(con, "BEGIN TRANSACTION");
	auto &fs = FileSystem::GetFileSystem(*con.context);
	fs.RemoveFiles({S3_PATH});
	RequireQueryOk(con, "COMMIT");

	auto stale_observations = stale_server.Observations();
	auto fresh_observations = fresh_server.Observations();
	INFO(MockS3DescribeObservations(stale_observations));
	INFO(MockS3DescribeObservations(fresh_observations));
	REQUIRE(CountObservations(stale_observations, "POST", STALE_KEY_ID, 403) == 1);
	REQUIRE(CountObservations(fresh_observations, "POST", STALE_KEY_ID, 200) == 1);
}

static void RunDeleteRefreshScenario(const string &client_implementation, bool connection_caching,
                                     MockS3AuthFailure auth_failure = MockS3AuthFailure::ACCESS_DENIED_403) {
	auto observations = RunRefreshScenario(
	    MockS3RefreshTarget::DELETE_OBJECT, client_implementation, connection_caching,
	    [](Connection &con, const string &) {
		    auto &fs = FileSystem::GetFileSystem(*con.context);
		    fs.RemoveFile(S3_PATH);
	    },
	    auth_failure);
	REQUIRE(CountExactObservations(observations, "DELETE", STALE_KEY_ID, AuthFailureStatus(auth_failure)) == 1);
	REQUIRE(CountExactObservations(observations, "DELETE", FRESH_KEY_ID, 204) == 1);
}

static void RunListGlobRefreshScenario(const string &client_implementation, bool connection_caching,
                                       MockS3AuthFailure auth_failure = MockS3AuthFailure::ACCESS_DENIED_403) {
	auto observations = RunRefreshScenario(
	    MockS3RefreshTarget::LIST_OBJECTS_GET, client_implementation, connection_caching,
	    [](Connection &con, const string &) {
		    auto result = con.Query("SELECT file FROM glob('s3://refresh-bucket/object*.bin')");
		    REQUIRE(result);
		    INFO((result->HasError() ? result->GetError() : string()));
		    REQUIRE_FALSE(result->HasError());
		    REQUIRE(result->RowCount() == 1);
		    REQUIRE(result->GetValue(0, 0).ToString() == S3_PATH);
	    },
	    auth_failure);
	REQUIRE(CountExactObservations(observations, "GET", STALE_KEY_ID, AuthFailureStatus(auth_failure), string(),
	                               "list-type=2") == 1);
	REQUIRE(CountExactObservations(observations, "GET", FRESH_KEY_ID, 200, string(), "list-type=2") == 1);
}

static void RunAllRequestRefreshScenarios(const string &client_implementation, bool connection_caching) {
	RunHeadRefreshScenario(client_implementation, connection_caching);
	RunFullGetRefreshScenario(client_implementation, connection_caching);
	RunRangeRefreshScenario(client_implementation, connection_caching);
	RunPutRefreshScenario(client_implementation, connection_caching);
	RunMultipartInitiatePostRefreshScenario(client_implementation, connection_caching);
	RunMultipartCompletePostRefreshScenario(client_implementation, connection_caching);
	RunBulkDeletePostRefreshScenario(client_implementation, connection_caching);
	RunDeleteRefreshScenario(client_implementation, connection_caching);
	RunListGlobRefreshScenario(client_implementation, connection_caching);
}

static void RunHandleRequestRefreshScenarios(const string &client_implementation, bool connection_caching) {
	RunHeadRefreshScenario(client_implementation, connection_caching);
	RunFullGetRefreshScenario(client_implementation, connection_caching);
	RunRangeRefreshScenario(client_implementation, connection_caching);
	RunDeleteRefreshScenario(client_implementation, connection_caching);
}

static void RunExpiredTokenRefreshScenarios(const string &client_implementation, bool connection_caching) {
	auto auth_failure = MockS3AuthFailure::EXPIRED_TOKEN_400;
	RunFullGetRefreshScenario(client_implementation, connection_caching, auth_failure);
	RunRangeRefreshScenario(client_implementation, connection_caching, auth_failure);
	RunPutRefreshScenario(client_implementation, connection_caching, auth_failure);
	RunMultipartInitiatePostRefreshScenario(client_implementation, connection_caching, auth_failure);
	RunMultipartCompletePostRefreshScenario(client_implementation, connection_caching, auth_failure);
	RunBulkDeletePostRefreshScenario(client_implementation, connection_caching, auth_failure);
	RunDeleteRefreshScenario(client_implementation, connection_caching, auth_failure);
	RunListGlobRefreshScenario(client_implementation, connection_caching, auth_failure);
}

static void RunMalformedExpiredTokenNotRefreshedScenario(const string &client_implementation) {
	MockS3ServerConfig config;
	config.bucket = BUCKET;
	config.object_key = OBJECT_KEY;
	config.stale_key_id = STALE_KEY_ID;
	config.refresh_target = MockS3RefreshTarget::FULL_GET;
	config.auth_failure = MockS3AuthFailure::EXPIRED_TOKEN_400;
	config.truncated_failure_body = true;
	MockS3Server server(std::move(config));

	DuckDB db(nullptr);
	Connection con(db);
	auto test_id = ConfigureRefreshTest(db, con, server, client_implementation, false);

	RequireQueryOk(con, "SET force_download=true");
	RequireQueryOk(con, "BEGIN TRANSACTION");
	RequireFullGetThrows(con);
	RequireQueryOk(con, "ROLLBACK");

	auto observations = server.Observations();
	INFO(MockS3DescribeObservations(observations));
	REQUIRE(CountObservations(observations, "GET", STALE_KEY_ID, 400) == 1);
	REQUIRE_FALSE(HasRequestWithKey(observations, FRESH_KEY_ID));
	AssertNoRefresh(test_id);
}

static void RunPersistentExpiredTokenSingleRefreshScenario(const string &client_implementation) {
	MockS3ServerConfig config;
	config.bucket = BUCKET;
	config.object_key = OBJECT_KEY;
	config.stale_key_id = STALE_KEY_ID;
	config.refresh_target = MockS3RefreshTarget::FULL_GET;
	config.auth_failure = MockS3AuthFailure::EXPIRED_TOKEN_400;
	config.reject_fresh_credentials = true;
	MockS3Server server(std::move(config));

	DuckDB db(nullptr);
	Connection con(db);
	auto test_id = ConfigureRefreshTest(db, con, server, client_implementation, false);

	RequireQueryOk(con, "SET force_download=true");
	RequireQueryOk(con, "BEGIN TRANSACTION");
	RequireFullGetThrows(con);
	RequireQueryOk(con, "ROLLBACK");

	auto observations = server.Observations();
	INFO(MockS3DescribeObservations(observations));
	REQUIRE(CountObservations(observations, "GET", STALE_KEY_ID, 400) == 1);
	REQUIRE(CountObservations(observations, "GET", FRESH_KEY_ID, 400) == 1);
	AssertSingleRefresh(test_id);
}

enum class NegativeGetErrorBody : uint8_t { INVALID_REQUEST, TRUNCATED_XML, BODYLESS };

static void RunNegativeGetErrorScenario(const string &client_implementation, bool range_request,
                                        NegativeGetErrorBody error_body) {
	MockS3ServerConfig config;
	config.bucket = BUCKET;
	config.object_key = OBJECT_KEY;
	config.stale_key_id = STALE_KEY_ID;
	// Use an auth target the read never exercises. These failures are injected independently of credentials.
	config.refresh_target = MockS3RefreshTarget::DELETE_OBJECT;
	config.transient_get_failures = 1000;
	if (error_body == NegativeGetErrorBody::INVALID_REQUEST) {
		config.failure_is_request_timeout = false;
	} else if (error_body == NegativeGetErrorBody::TRUNCATED_XML) {
		config.truncated_failure_body = true;
	} else {
		config.bodyless_failure = true;
	}
	MockS3Server server(std::move(config));

	DuckDB db(nullptr);
	Connection con(db);
	auto test_id = ConfigureRefreshTest(db, con, server, client_implementation, false);

	RequireQueryOk(con, "SET http_retries=3");
	RequireQueryOk(con, "SET http_retry_wait_ms=1");
	if (!range_request) {
		RequireQueryOk(con, "SET force_download=true");
	}
	RequireQueryOk(con, "BEGIN TRANSACTION");
	const idx_t offset = range_request ? 7 : 0;
	const idx_t read_size = range_request ? 9 : 8;
	string buffer(read_size, '#');
	bool threw = false;
	try {
		auto &fs = FileSystem::GetFileSystem(*con.context);
		FileOpenFlags flags = FileFlags::FILE_FLAGS_READ;
		if (range_request) {
			flags |= FileFlags::FILE_FLAGS_DIRECT_IO;
		}
		auto handle = fs.OpenFile(S3_PATH, flags);
		handle->Read(QueryContext(*con.context), &buffer[0], buffer.size(), offset);
	} catch (std::exception &) {
		threw = true;
	}
	REQUIRE(threw);
	REQUIRE(buffer == string(read_size, '#'));
	RequireQueryOk(con, "ROLLBACK");

	auto observations = server.Observations();
	INFO(MockS3DescribeObservations(observations));
	auto range = range_request ? "bytes=7-15" : string();
	REQUIRE(CountExactObservations(observations, "GET", STALE_KEY_ID, 400, range) == 1);
	REQUIRE_FALSE(HasRequestWithKey(observations, FRESH_KEY_ID));
	AssertNoRefresh(test_id);
}

static void RunAllNegativeGetErrorScenarios(const string &client_implementation) {
	for (auto error_body :
	     {NegativeGetErrorBody::INVALID_REQUEST, NegativeGetErrorBody::TRUNCATED_XML, NegativeGetErrorBody::BODYLESS}) {
		RunNegativeGetErrorScenario(client_implementation, false, error_body);
		RunNegativeGetErrorScenario(client_implementation, true, error_body);
	}
}

static void RunRangeRefreshDisabledScenario(MockS3AuthFailure auth_failure = MockS3AuthFailure::ACCESS_DENIED_403) {
	MockS3ServerConfig config;
	config.bucket = BUCKET;
	config.object_key = OBJECT_KEY;
	config.stale_key_id = STALE_KEY_ID;
	config.refresh_target = MockS3RefreshTarget::RANGE_GET;
	config.auth_failure = auth_failure;
	MockS3Server server(std::move(config));

	DuckDB db(nullptr);
	Connection con(db);
	auto test_id = ConfigureRefreshTest(db, con, server, "httplib", false, false);

	RequireQueryOk(con, "BEGIN TRANSACTION");
	auto &fs = FileSystem::GetFileSystem(*con.context);
	auto handle = fs.OpenFile(S3_PATH, FileFlags::FILE_FLAGS_READ | FileFlags::FILE_FLAGS_DIRECT_IO);

	const idx_t offset = 7;
	const idx_t read_size = 9;
	string buffer(read_size, '\0');
	REQUIRE_THROWS(handle->Read(QueryContext(*con.context), &buffer[0], read_size, offset));
	RequireQueryOk(con, "ROLLBACK");

	auto observations = server.Observations();
	INFO(MockS3DescribeObservations(observations));
	REQUIRE(CountExactObservations(observations, "GET", STALE_KEY_ID, AuthFailureStatus(auth_failure), "bytes=7-15") ==
	        1);
	REQUIRE_FALSE(HasRequestWithKey(observations, FRESH_KEY_ID));
	AssertNoRefresh(test_id);
}

static void RunListGlobRefreshDisabledScenario(MockS3AuthFailure auth_failure = MockS3AuthFailure::ACCESS_DENIED_403) {
	MockS3ServerConfig config;
	config.bucket = BUCKET;
	config.object_key = OBJECT_KEY;
	config.stale_key_id = STALE_KEY_ID;
	config.refresh_target = MockS3RefreshTarget::LIST_OBJECTS_GET;
	config.auth_failure = auth_failure;
	MockS3Server server(std::move(config));

	DuckDB db(nullptr);
	Connection con(db);
	auto test_id = ConfigureRefreshTest(db, con, server, "httplib", false, false);

	RequireQueryOk(con, "BEGIN TRANSACTION");
	auto result = con.Query("SELECT file FROM glob('s3://refresh-bucket/object*.bin')");
	REQUIRE(result);
	REQUIRE(result->HasError());
	RequireQueryOk(con, "ROLLBACK");

	auto observations = server.Observations();
	INFO(MockS3DescribeObservations(observations));
	REQUIRE(CountExactObservations(observations, "GET", STALE_KEY_ID, AuthFailureStatus(auth_failure), string(),
	                               "list-type=2") == 1);
	REQUIRE_FALSE(HasRequestWithKey(observations, FRESH_KEY_ID));
	AssertNoRefresh(test_id);
}

static void RunHeadExpiredTokenFallbackScenario(const string &client_implementation) {
	MockS3ServerConfig config;
	config.bucket = BUCKET;
	config.object_key = OBJECT_KEY;
	config.stale_key_id = STALE_KEY_ID;
	config.refresh_target = MockS3RefreshTarget::HEAD_AND_RANGE_GET;
	config.auth_failure = MockS3AuthFailure::EXPIRED_TOKEN_400;
	MockS3Server server(std::move(config));

	DuckDB db(nullptr);
	Connection con(db);
	auto test_id = ConfigureRefreshTest(db, con, server, client_implementation, false);

	RequireQueryOk(con, "BEGIN TRANSACTION");
	OpenForRead(con, FileFlags::FILE_FLAGS_READ | FileFlags::FILE_FLAGS_DIRECT_IO);
	RequireQueryOk(con, "COMMIT");

	auto observations = server.Observations();
	INFO(MockS3DescribeObservations(observations));
	// HEAD bodies are unavailable, so the HEAD itself must not refresh. The stale range fallback carries the XML body.
	REQUIRE(CountExactObservations(observations, "HEAD", STALE_KEY_ID, 400) == 1);
	REQUIRE(CountExactObservations(observations, "HEAD", FRESH_KEY_ID, 200) == 0);
	REQUIRE(CountExactObservations(observations, "GET", STALE_KEY_ID, 400, "bytes=0-1") == 1);
	REQUIRE(CountExactObservations(observations, "GET", FRESH_KEY_ID, 206, "bytes=0-1") == 1);
	AssertSingleRefresh(test_id);
}

static void RunConcurrentStaleHandlesSingleRefreshScenario() {
	static constexpr idx_t HANDLE_COUNT = 4;
	MockS3ServerConfig config;
	config.bucket = BUCKET;
	config.object_key = OBJECT_KEY;
	config.stale_key_id = STALE_KEY_ID;
	config.refresh_target = MockS3RefreshTarget::RANGE_GET;
	config.auth_failure = MockS3AuthFailure::EXPIRED_TOKEN_400;
	config.auth_failure_barrier_count = HANDLE_COUNT;
	auto object_data = config.object_data;
	MockS3Server server(std::move(config));

	DuckDB db(nullptr);
	Connection con(db);
	auto test_id = ConfigureRefreshTest(db, con, server, "httplib", false);

	RequireQueryOk(con, "BEGIN TRANSACTION");
	auto &fs = FileSystem::GetFileSystem(*con.context);
	vector<unique_ptr<FileHandle>> handles;
	for (idx_t i = 0; i < HANDLE_COUNT; i++) {
		handles.push_back(fs.OpenFile(S3_PATH, FileFlags::FILE_FLAGS_READ | FileFlags::FILE_FLAGS_DIRECT_IO));
		REQUIRE(handles.back());
	}

	const idx_t offset = 7;
	const idx_t read_size = 9;
	vector<string> buffers(HANDLE_COUNT, string(read_size, '\0'));
	vector<string> errors(HANDLE_COUNT);
	std::mutex start_lock;
	std::condition_variable start_cv;
	idx_t ready = 0;
	bool start = false;
	vector<std::thread> threads;
	for (idx_t i = 0; i < HANDLE_COUNT; i++) {
		threads.emplace_back([&, i]() {
			{
				std::unique_lock<std::mutex> lock(start_lock);
				ready++;
				start_cv.notify_all();
				start_cv.wait(lock, [&]() { return start; });
			}
			try {
				handles[i]->Read(QueryContext(*con.context), &buffers[i][0], read_size, offset);
			} catch (std::exception &ex) {
				errors[i] = ex.what();
			} catch (...) {
				errors[i] = "unknown exception";
			}
		});
	}
	{
		std::unique_lock<std::mutex> lock(start_lock);
		start_cv.wait(lock, [&]() { return ready == HANDLE_COUNT; });
		start = true;
		start_cv.notify_all();
	}
	for (auto &thread : threads) {
		thread.join();
	}
	for (idx_t i = 0; i < HANDLE_COUNT; i++) {
		INFO(errors[i]);
		REQUIRE(errors[i].empty());
		REQUIRE(buffers[i] == object_data.substr(offset, read_size));
	}
	RequireQueryOk(con, "COMMIT");

	auto observations = server.Observations();
	INFO(MockS3DescribeObservations(observations));
	REQUIRE(CountExactObservations(observations, "GET", STALE_KEY_ID, 400, "bytes=7-15") == HANDLE_COUNT);
	REQUIRE(CountExactObservations(observations, "GET", FRESH_KEY_ID, 206, "bytes=7-15") == HANDLE_COUNT);
	AssertSingleRefresh(test_id);
}

static void RunTransientPutRetryScenario(const string &client_implementation) {
	MockS3ServerConfig config;
	config.bucket = BUCKET;
	config.object_key = OBJECT_KEY;
	config.stale_key_id = STALE_KEY_ID;
	// Use a refresh target that writes never exercise, so credential refresh never triggers here.
	config.refresh_target = MockS3RefreshTarget::DELETE_OBJECT;
	config.transient_put_failures = 2;
	MockS3Server server(std::move(config));

	DuckDB db(nullptr);
	Connection con(db);
	auto test_id = ConfigureRefreshTest(db, con, server, client_implementation, false);

	RequireQueryOk(con, "SET http_retries=3");
	RequireQueryOk(con, "SET http_retry_wait_ms=1");
	RequireQueryOk(con, "BEGIN TRANSACTION");
	WriteMultipartPayload(con);
	RequireQueryOk(con, "COMMIT");

	auto observations = server.Observations();
	INFO(MockS3DescribeObservations(observations));
	// The transient RequestTimeout 400s were surfaced, retried, and the same part eventually succeeded.
	REQUIRE(MockS3HasObservation(observations, "PUT", STALE_KEY_ID, 400, string(), "partNumber"));
	REQUIRE(MockS3HasObservation(observations, "PUT", STALE_KEY_ID, 200, string(), "partNumber"));
	// The multipart upload completed successfully.
	REQUIRE(MockS3HasObservation(observations, "POST", STALE_KEY_ID, 200, string(), "uploadId"));
	AssertNoRefresh(test_id);
}

static idx_t CountObservationsTarget(const vector<MockS3RequestObservation> &observations, const string &method,
                                     int status, const string &target_contains) {
	idx_t result = 0;
	for (auto &observation : observations) {
		if (observation.method == method && observation.status == status &&
		    (target_contains.empty() || observation.target.find(target_contains) != string::npos)) {
			result++;
		}
	}
	return result;
}

// A generic (non-RequestTimeout) 400 must fail on the first try. Uses a single-shot PUT so exactly one
// request is expected, distinguishing "not retried" from "retried N times and still failed".
static void RunGenericErrorNotRetriedScenario(const string &client_implementation) {
	MockS3ServerConfig config;
	config.bucket = BUCKET;
	config.object_key = OBJECT_KEY;
	config.stale_key_id = STALE_KEY_ID;
	config.refresh_target = MockS3RefreshTarget::DELETE_OBJECT;
	config.transient_put_failures = 1000;
	config.failure_is_request_timeout = false;
	MockS3Server server(std::move(config));

	DuckDB db(nullptr);
	Connection con(db);
	auto test_id = ConfigureRefreshTest(db, con, server, client_implementation, false);

	RequireQueryOk(con, "SET http_retries=3");
	RequireQueryOk(con, "SET http_retry_wait_ms=1");
	RequireQueryOk(con, "BEGIN TRANSACTION");
	REQUIRE_THROWS(WriteSinglePutPayload(con));
	RequireQueryOk(con, "ROLLBACK");

	auto observations = server.Observations();
	INFO(MockS3DescribeObservations(observations));
	REQUIRE(CountObservations(observations, "PUT", STALE_KEY_ID, 400) == 1);
	AssertNoRefresh(test_id);
}

static void RunGenericGetErrorBodyScenario(const string &client_implementation) {
	MockS3ServerConfig config;
	config.bucket = BUCKET;
	config.object_key = OBJECT_KEY;
	config.stale_key_id = STALE_KEY_ID;
	config.refresh_target = MockS3RefreshTarget::DELETE_OBJECT;
	config.transient_get_failures = 1000;
	config.failure_is_request_timeout = false;
	MockS3Server server(std::move(config));

	DuckDB db(nullptr);
	Connection con(db);
	auto test_id = ConfigureRefreshTest(db, con, server, client_implementation, false, false);

	RequireQueryOk(con, "SET http_retries=3");
	RequireQueryOk(con, "SET http_retry_wait_ms=1");
	RequireQueryOk(con, "SET force_download=true");
	RequireQueryOk(con, "BEGIN TRANSACTION");
	bool threw = false;
	string response_body;
	try {
		auto &fs = FileSystem::GetFileSystem(*con.context);
		auto handle = fs.OpenFile(S3_PATH, FileFlags::FILE_FLAGS_READ);
		string buffer(8, '\0');
		handle->Read(QueryContext(*con.context), &buffer[0], buffer.size(), 0);
	} catch (std::exception &ex) {
		threw = true;
		ErrorData error(ex);
		auto entry = error.ExtraInfo().find("response_body");
		if (entry != error.ExtraInfo().end()) {
			response_body = entry->second;
		}
	}
	REQUIRE(threw);
	REQUIRE(response_body.find("<Code>InvalidRequest</Code>") != string::npos);
	RequireQueryOk(con, "ROLLBACK");

	auto observations = server.Observations();
	INFO(MockS3DescribeObservations(observations));
	REQUIRE(CountObservations(observations, "GET", STALE_KEY_ID, 400) == 1);
	REQUIRE_FALSE(HasRequestWithKey(observations, FRESH_KEY_ID));
	AssertNoRefresh(test_id);
}

// A truncated error body (an open <Code> with no closing tag) must degrade to a plain HTTP error:
// not classified as transient (no retry) and never escalated to a DB-invalidating InternalException.
static void RunTruncatedErrorBodyScenario(const string &client_implementation) {
	MockS3ServerConfig config;
	config.bucket = BUCKET;
	config.object_key = OBJECT_KEY;
	config.stale_key_id = STALE_KEY_ID;
	config.refresh_target = MockS3RefreshTarget::DELETE_OBJECT;
	config.transient_put_failures = 1000;
	config.truncated_failure_body = true;
	MockS3Server server(std::move(config));

	DuckDB db(nullptr);
	Connection con(db);
	ConfigureRefreshTest(db, con, server, client_implementation, false);

	RequireQueryOk(con, "SET http_retries=3");
	RequireQueryOk(con, "SET http_retry_wait_ms=1");
	RequireQueryOk(con, "BEGIN TRANSACTION");
	bool threw = false;
	bool threw_internal = false;
	try {
		WriteSinglePutPayload(con);
	} catch (std::exception &ex) {
		threw = true;
		ErrorData error(ex);
		threw_internal = error.Type() == ExceptionType::INTERNAL || error.Type() == ExceptionType::FATAL;
	}
	REQUIRE(threw);
	REQUIRE_FALSE(threw_internal);
	// The database must still be usable (an InternalException would have invalidated it).
	RequireQueryOk(con, "ROLLBACK");

	auto observations = server.Observations();
	INFO(MockS3DescribeObservations(observations));
	REQUIRE(CountObservations(observations, "PUT", STALE_KEY_ID, 400) == 1);
}

// Even a retryable RequestTimeout must NOT replay a multipart-init POST (it would orphan an upload id).
static void RunMultipartInitNotRetriedScenario(const string &client_implementation) {
	MockS3ServerConfig config;
	config.bucket = BUCKET;
	config.object_key = OBJECT_KEY;
	config.stale_key_id = STALE_KEY_ID;
	config.refresh_target = MockS3RefreshTarget::DELETE_OBJECT;
	config.transient_post_failures = 1000;
	MockS3Server server(std::move(config));

	DuckDB db(nullptr);
	Connection con(db);
	ConfigureRefreshTest(db, con, server, client_implementation, false);

	RequireQueryOk(con, "SET http_retries=3");
	RequireQueryOk(con, "SET http_retry_wait_ms=1");
	RequireQueryOk(con, "BEGIN TRANSACTION");
	bool threw = false;
	string response_body;
	try {
		WriteMultipartPayload(con);
	} catch (std::exception &ex) {
		threw = true;
		ErrorData error(ex);
		auto entry = error.ExtraInfo().find("response_body");
		if (entry != error.ExtraInfo().end()) {
			response_body = entry->second;
		}
	}
	REQUIRE(threw);
	REQUIRE(response_body.find("<Code>RequestTimeout</Code>") != string::npos);
	RequireQueryOk(con, "ROLLBACK");

	auto observations = server.Observations();
	INFO(MockS3DescribeObservations(observations));
	REQUIRE(CountObservationsTarget(observations, "POST", 400, "uploads") == 1);
}

// With curl connection caching, the retry must run on a fresh connection instead of the stalled cached one.
static void RunCachedConnectionRetryScenario() {
	MockS3ServerConfig config;
	config.bucket = BUCKET;
	config.object_key = OBJECT_KEY;
	config.stale_key_id = STALE_KEY_ID;
	config.refresh_target = MockS3RefreshTarget::DELETE_OBJECT;
	config.transient_put_failures = 1;
	MockS3Server server(std::move(config));

	DuckDB db(nullptr);
	Connection con(db);
	ConfigureRefreshTest(db, con, server, "curl", true);

	RequireQueryOk(con, "SET http_retries=3");
	RequireQueryOk(con, "SET http_retry_wait_ms=1");
	RequireQueryOk(con, "BEGIN TRANSACTION");
	WriteSinglePutPayload(con);
	RequireQueryOk(con, "COMMIT");

	auto observations = server.Observations();
	INFO(MockS3DescribeObservations(observations));
	int failed_port = 0;
	int success_port = 0;
	for (auto &observation : observations) {
		if (observation.method != "PUT") {
			continue;
		}
		if (observation.status == 400) {
			failed_port = observation.remote_port;
		} else if (observation.status == 200) {
			success_port = observation.remote_port;
		}
	}
	REQUIRE(failed_port != 0);
	REQUIRE(success_port != 0);
	REQUIRE(failed_port != success_port);
}

// A RequestTimeout that never clears exhausts exactly http_retries retries (one initial + http_retries).
static void RunRetryBudgetScenario(const string &client_implementation) {
	MockS3ServerConfig config;
	config.bucket = BUCKET;
	config.object_key = OBJECT_KEY;
	config.stale_key_id = STALE_KEY_ID;
	config.refresh_target = MockS3RefreshTarget::DELETE_OBJECT;
	config.transient_put_failures = 1000;
	MockS3Server server(std::move(config));

	DuckDB db(nullptr);
	Connection con(db);
	ConfigureRefreshTest(db, con, server, client_implementation, false);

	RequireQueryOk(con, "SET http_retries=2");
	RequireQueryOk(con, "SET http_retry_wait_ms=1");
	RequireQueryOk(con, "BEGIN TRANSACTION");
	REQUIRE_THROWS(WriteSinglePutPayload(con));
	RequireQueryOk(con, "ROLLBACK");

	auto observations = server.Observations();
	INFO(MockS3DescribeObservations(observations));
	// One initial attempt plus http_retries (2) retries.
	REQUIRE(CountObservations(observations, "PUT", STALE_KEY_ID, 400) == 3);
}

static void RunTransientGetRetryScenario(const string &client_implementation) {
	MockS3ServerConfig config;
	config.bucket = BUCKET;
	config.object_key = OBJECT_KEY;
	config.stale_key_id = STALE_KEY_ID;
	config.refresh_target = MockS3RefreshTarget::DELETE_OBJECT;
	config.transient_get_failures = 2;
	auto object_data = config.object_data;
	MockS3Server server(std::move(config));

	DuckDB db(nullptr);
	Connection con(db);
	auto test_id = ConfigureRefreshTest(db, con, server, client_implementation, false);

	RequireQueryOk(con, "SET http_retries=3");
	RequireQueryOk(con, "SET http_retry_wait_ms=1");
	RequireQueryOk(con, "SET force_download=true");
	RequireQueryOk(con, "BEGIN TRANSACTION");
	auto &fs = FileSystem::GetFileSystem(*con.context);
	auto handle = fs.OpenFile(S3_PATH, FileFlags::FILE_FLAGS_READ);
	string buffer(8, '\0');
	handle->Read(QueryContext(*con.context), &buffer[0], buffer.size(), 0);
	REQUIRE(buffer == object_data.substr(0, buffer.size()));
	RequireQueryOk(con, "COMMIT");

	auto observations = server.Observations();
	INFO(MockS3DescribeObservations(observations));
	// The read hit transient RequestTimeout 400s and was retried until it succeeded.
	REQUIRE(CountExactObservations(observations, "GET", STALE_KEY_ID, 400) == 2);
	REQUIRE(CountExactObservations(observations, "GET", STALE_KEY_ID, 200) == 1);
	AssertNoRefresh(test_id);
}

static void RunTransientRangeGetRetryScenario(const string &client_implementation) {
	MockS3ServerConfig config;
	config.bucket = BUCKET;
	config.object_key = OBJECT_KEY;
	config.stale_key_id = STALE_KEY_ID;
	config.refresh_target = MockS3RefreshTarget::DELETE_OBJECT;
	config.transient_get_failures = 2;
	auto object_data = config.object_data;
	MockS3Server server(std::move(config));

	DuckDB db(nullptr);
	Connection con(db);
	auto test_id = ConfigureRefreshTest(db, con, server, client_implementation, false);

	RequireQueryOk(con, "SET http_retries=3");
	RequireQueryOk(con, "SET http_retry_wait_ms=1");
	RequireQueryOk(con, "BEGIN TRANSACTION");
	auto &fs = FileSystem::GetFileSystem(*con.context);
	auto handle = fs.OpenFile(S3_PATH, FileFlags::FILE_FLAGS_READ | FileFlags::FILE_FLAGS_DIRECT_IO);
	const idx_t offset = 7;
	const idx_t read_size = 9;
	string buffer(read_size, '\0');
	handle->Read(QueryContext(*con.context), &buffer[0], buffer.size(), offset);
	REQUIRE(buffer == object_data.substr(offset, read_size));
	RequireQueryOk(con, "COMMIT");

	auto observations = server.Observations();
	INFO(MockS3DescribeObservations(observations));
	REQUIRE(CountExactObservations(observations, "GET", STALE_KEY_ID, 400, "bytes=7-15") == 2);
	REQUIRE(CountExactObservations(observations, "GET", STALE_KEY_ID, 206, "bytes=7-15") == 1);
	AssertNoRefresh(test_id);
}

static void RunTransientDeleteRetryScenario(const string &client_implementation) {
	MockS3ServerConfig config;
	config.bucket = BUCKET;
	config.object_key = OBJECT_KEY;
	config.stale_key_id = STALE_KEY_ID;
	// Use a refresh target that deletes never exercise, so credential refresh never triggers here.
	config.refresh_target = MockS3RefreshTarget::PUT;
	config.transient_delete_failures = 2;
	MockS3Server server(std::move(config));

	DuckDB db(nullptr);
	Connection con(db);
	ConfigureRefreshTest(db, con, server, client_implementation, false);

	RequireQueryOk(con, "SET http_retries=3");
	RequireQueryOk(con, "SET http_retry_wait_ms=1");
	RequireQueryOk(con, "BEGIN TRANSACTION");
	auto &fs = FileSystem::GetFileSystem(*con.context);
	fs.RemoveFile(S3_PATH);
	RequireQueryOk(con, "COMMIT");

	auto observations = server.Observations();
	INFO(MockS3DescribeObservations(observations));
	REQUIRE(CountObservations(observations, "DELETE", STALE_KEY_ID, 400) == 2);
	REQUIRE(CountObservations(observations, "DELETE", STALE_KEY_ID, 204) == 1);
}

// HEAD responses carry no body, so a RequestTimeout 400 cannot be classified as transient:
// the HEAD is not retried and the open recovers through httpfs's range-GET fallback instead.
static void RunHeadNotRetriedScenario(const string &client_implementation) {
	MockS3ServerConfig config;
	config.bucket = BUCKET;
	config.object_key = OBJECT_KEY;
	config.stale_key_id = STALE_KEY_ID;
	config.refresh_target = MockS3RefreshTarget::DELETE_OBJECT;
	config.transient_head_failures = 1000;
	MockS3Server server(std::move(config));

	DuckDB db(nullptr);
	Connection con(db);
	ConfigureRefreshTest(db, con, server, client_implementation, false);

	RequireQueryOk(con, "SET http_retries=3");
	RequireQueryOk(con, "SET http_retry_wait_ms=1");
	RequireQueryOk(con, "BEGIN TRANSACTION");
	auto &fs = FileSystem::GetFileSystem(*con.context);
	auto handle = fs.OpenFile(S3_PATH, FileFlags::FILE_FLAGS_READ | FileFlags::FILE_FLAGS_DIRECT_IO);
	REQUIRE(handle);
	RequireQueryOk(con, "COMMIT");

	auto observations = server.Observations();
	INFO(MockS3DescribeObservations(observations));
	REQUIRE(CountObservations(observations, "HEAD", STALE_KEY_ID, 400) == 1);
	REQUIRE(MockS3HasObservation(observations, "GET", STALE_KEY_ID, 206, "bytes=0-1"));
}

// Like multipart-init, a multipart-complete POST must not be replayed even on RequestTimeout.
static void RunMultipartCompleteNotRetriedScenario(const string &client_implementation) {
	MockS3ServerConfig config;
	config.bucket = BUCKET;
	config.object_key = OBJECT_KEY;
	config.stale_key_id = STALE_KEY_ID;
	config.refresh_target = MockS3RefreshTarget::DELETE_OBJECT;
	config.transient_complete_post_failures = 1000;
	MockS3Server server(std::move(config));

	DuckDB db(nullptr);
	Connection con(db);
	ConfigureRefreshTest(db, con, server, client_implementation, false);

	RequireQueryOk(con, "SET http_retries=3");
	RequireQueryOk(con, "SET http_retry_wait_ms=1");
	RequireQueryOk(con, "BEGIN TRANSACTION");
	REQUIRE_THROWS(WriteMultipartPayload(con));
	RequireQueryOk(con, "ROLLBACK");

	auto observations = server.Observations();
	INFO(MockS3DescribeObservations(observations));
	REQUIRE(CountObservationsTarget(observations, "POST", 400, "uploadId") == 1);
}

// A CompleteMultipartUpload that returns HTTP 200 with an embedded InternalError must be retried
static void RunCompletePost200ErrorRetryScenario(const string &client_implementation) {
	MockS3ServerConfig config;
	config.bucket = BUCKET;
	config.object_key = OBJECT_KEY;
	config.stale_key_id = STALE_KEY_ID;
	// Use a refresh target that writes never exercise, so credential refresh never triggers here.
	config.refresh_target = MockS3RefreshTarget::DELETE_OBJECT;
	config.transient_complete_post_200_errors = 2;
	MockS3Server server(std::move(config));

	DuckDB db(nullptr);
	Connection con(db);
	ConfigureRefreshTest(db, con, server, client_implementation, false);

	RequireQueryOk(con, "SET http_retries=3");
	RequireQueryOk(con, "SET http_retry_wait_ms=1");
	RequireQueryOk(con, "BEGIN TRANSACTION");
	WriteMultipartPayload(con);
	RequireQueryOk(con, "COMMIT");

	auto observations = server.Observations();
	INFO(MockS3DescribeObservations(observations));
	// The two 200 with embedded error completions were retried, and the third completion succeeded: 3 complete
	// POSTs in total, all reported as HTTP 200 by S3.
	REQUIRE(CountObservationsTarget(observations, "POST", 200, "uploadId") == 3);
}

// A CompleteMultipartUpload that keeps returning a 200 OK with an embedded error must exhaust exactly http_retries
// retries
static void RunCompletePost200ErrorExhaustsBudgetScenario(const string &client_implementation) {
	MockS3ServerConfig config;
	config.bucket = BUCKET;
	config.object_key = OBJECT_KEY;
	config.stale_key_id = STALE_KEY_ID;
	config.refresh_target = MockS3RefreshTarget::DELETE_OBJECT;
	config.transient_complete_post_200_errors = 1000;
	MockS3Server server(std::move(config));

	DuckDB db(nullptr);
	Connection con(db);
	ConfigureRefreshTest(db, con, server, client_implementation, false);

	RequireQueryOk(con, "SET http_retries=3");
	RequireQueryOk(con, "SET http_retry_wait_ms=1");
	RequireQueryOk(con, "BEGIN TRANSACTION");
	REQUIRE_THROWS(WriteMultipartPayload(con));
	RequireQueryOk(con, "ROLLBACK");

	auto observations = server.Observations();
	INFO(MockS3DescribeObservations(observations));
	// http_retries=3 => 1 initial attempt + 3 retries = 4 complete POSTs, all HTTP 200 with the embedded error.
	REQUIRE(CountObservationsTarget(observations, "POST", 200, "uploadId") == 4);
}

static void RunAllTransientRetryScenarios(const string &client_implementation) {
	SECTION("multipart part upload retries and completes") {
		RunTransientPutRetryScenario(client_implementation);
	}
	SECTION("a multipart-complete 200 with an embedded transient error is retried and completes") {
		RunCompletePost200ErrorRetryScenario(client_implementation);
	}
	SECTION("a persistent multipart-complete 200-with-error is bounded by http_retries") {
		RunCompletePost200ErrorExhaustsBudgetScenario(client_implementation);
	}
	SECTION("object read retries and completes") {
		RunTransientGetRetryScenario(client_implementation);
	}
	SECTION("range read retries and completes") {
		RunTransientRangeGetRetryScenario(client_implementation);
	}
	SECTION("object delete retries and completes") {
		RunTransientDeleteRetryScenario(client_implementation);
	}
	SECTION("a generic 400 is not retried") {
		RunGenericErrorNotRetriedScenario(client_implementation);
	}
	SECTION("a generic GET 400 preserves its response body and is not retried") {
		RunGenericGetErrorBodyScenario(client_implementation);
	}
	SECTION("a truncated error body is not retried and does not invalidate the database") {
		RunTruncatedErrorBodyScenario(client_implementation);
	}
	SECTION("a multipart-init POST is not retried even on RequestTimeout") {
		RunMultipartInitNotRetriedScenario(client_implementation);
	}
	SECTION("a multipart-complete POST is not retried even on RequestTimeout") {
		RunMultipartCompleteNotRetriedScenario(client_implementation);
	}
	SECTION("a HEAD 400 is not retried because HEAD responses carry no error body") {
		RunHeadNotRetriedScenario(client_implementation);
	}
	SECTION("retries are bounded by http_retries") {
		RunRetryBudgetScenario(client_implementation);
	}
}

} // namespace

TEST_CASE("HTTPFS retries transient S3 RequestTimeout across request types", "[httpfs][s3][upload]") {
	SECTION("httplib") {
		RunAllTransientRetryScenarios("httplib");
	}
	SECTION("curl") {
		RunAllTransientRetryScenarios("curl");
	}
	SECTION("curl with connection caching retries on a fresh connection") {
		RunCachedConnectionRetryScenario();
	}
}

TEST_CASE("HTTPFS refreshes S3 credentials across request methods", "[httpfs][s3][refresh]") {
	SECTION("httplib without connection caching") {
		RunAllRequestRefreshScenarios("httplib", false);
	}
	SECTION("httplib with handle client cache reuse") {
		RunHandleRequestRefreshScenarios("httplib", false);
	}
	SECTION("curl without connection caching") {
		RunAllRequestRefreshScenarios("curl", false);
	}
}

TEST_CASE("HTTPFS refreshes expired S3 credentials across request methods", "[httpfs][s3][refresh]") {
	SECTION("httplib") {
		RunExpiredTokenRefreshScenarios("httplib", false);
	}
	SECTION("curl") {
		RunExpiredTokenRefreshScenarios("curl", false);
	}
}

TEST_CASE("HTTPFS bounds ExpiredToken credential refresh", "[httpfs][s3][refresh]") {
	SECTION("malformed httplib response") {
		RunMalformedExpiredTokenNotRefreshedScenario("httplib");
	}
	SECTION("malformed curl response") {
		RunMalformedExpiredTokenNotRefreshedScenario("curl");
	}
	SECTION("persistent httplib response") {
		RunPersistentExpiredTokenSingleRefreshScenario("httplib");
	}
	SECTION("persistent curl response") {
		RunPersistentExpiredTokenSingleRefreshScenario("curl");
	}
}

TEST_CASE("HTTPFS does not refresh non-auth S3 GET failures", "[httpfs][s3][refresh]") {
	SECTION("httplib") {
		RunAllNegativeGetErrorScenarios("httplib");
	}
	SECTION("curl") {
		RunAllNegativeGetErrorScenarios("curl");
	}
}

TEST_CASE("HTTPFS refreshes from the GET fallback after a bodyless HEAD ExpiredToken", "[httpfs][s3][refresh]") {
	SECTION("httplib") {
		RunHeadExpiredTokenFallbackScenario("httplib");
	}
	SECTION("curl") {
		RunHeadExpiredTokenFallbackScenario("curl");
	}
}

TEST_CASE("HTTPFS can disable S3 credential refresh", "[httpfs][s3][refresh]") {
	SECTION("403 range reads fail without refresh") {
		RunRangeRefreshDisabledScenario();
	}
	SECTION("403 list glob fails without refresh") {
		RunListGlobRefreshDisabledScenario();
	}
	SECTION("ExpiredToken range reads fail without refresh") {
		RunRangeRefreshDisabledScenario(MockS3AuthFailure::EXPIRED_TOKEN_400);
	}
	SECTION("ExpiredToken list glob fails without refresh") {
		RunListGlobRefreshDisabledScenario(MockS3AuthFailure::EXPIRED_TOKEN_400);
	}
}

TEST_CASE("HTTPFS single-flights concurrent S3 credential refresh", "[httpfs][s3][refresh]") {
	RunConcurrentStaleHandlesSingleRefreshScenario();
}

TEST_CASE("HTTPFS bulk delete follows a refreshed S3 endpoint", "[httpfs][s3][refresh]") {
	SECTION("httplib") {
		RunBulkDeleteEndpointRefreshScenario("httplib");
	}
	SECTION("curl") {
		RunBulkDeleteEndpointRefreshScenario("curl");
	}
}

TEST_CASE("HTTPFS initializes and clones parameters without a configured proxy", "[httpfs][s3][params]") {
	alignas(HTTPFSParams) std::array<uint8_t, sizeof(HTTPFSParams)> storage;
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

} // namespace duckdb
