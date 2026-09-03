#include "s3/s3_test_helper.hpp"

#include "catch.hpp"

#include "create_secret_functions.hpp"
#include "httpfs_extension.hpp"

#include "duckdb/common/mutex.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/common/unordered_map.hpp"
#include "duckdb/main/extension/extension_loader.hpp"

#include <atomic>

namespace duckdb {

namespace {

struct ProviderStats {
	idx_t initial_creations = 0;
	idx_t refresh_creations = 0;
	vector<string> key_ids;
};

struct ProviderRegistry {
	annotated_mutex lock;
	unordered_map<string, ProviderStats> stats DUCKDB_GUARDED_BY(lock);
	unordered_map<string, std::function<void()>> refresh_hooks DUCKDB_GUARDED_BY(lock);
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
	std::function<void()> refresh_hook;
	{
		annotated_lock_guard<annotated_mutex> lock(registry.lock);
		auto &stats = registry.stats[test_id];
		stats.key_ids.push_back(key_id);
		if (key_id == S3TestHelper::STALE_KEY_ID) {
			stats.initial_creations++;
		} else if (key_id == S3TestHelper::FRESH_KEY_ID) {
			stats.refresh_creations++;
			auto entry = registry.refresh_hooks.find(test_id);
			if (entry != registry.refresh_hooks.end()) {
				refresh_hook = entry->second;
			}
		}
	}
	if (refresh_hook) {
		refresh_hook();
	}
}

static ProviderStats GetProviderStats(const string &test_id) {
	auto &registry = GetProviderRegistry();
	annotated_lock_guard<annotated_mutex> lock(registry.lock);
	auto entry = registry.stats.find(test_id);
	if (entry == registry.stats.end()) {
		return ProviderStats();
	}
	return entry->second;
}

static void SetProviderRefreshHook(const string &test_id, std::function<void()> refresh_hook) {
	auto &registry = GetProviderRegistry();
	annotated_lock_guard<annotated_mutex> lock(registry.lock);
	registry.refresh_hooks[test_id] = std::move(refresh_hook);
}

static void ClearProviderRefreshHook(const string &test_id) {
	auto &registry = GetProviderRegistry();
	annotated_lock_guard<annotated_mutex> lock(registry.lock);
	registry.refresh_hooks.erase(test_id);
}

struct TestS3SecretFunctions : public CreateS3SecretFunctions {
	static void SetTestNamedParams(CreateSecretFunction &function, string type) {
		SetBaseNamedParams(function, type);
		function.named_parameters["test_id"] = LogicalType::VARCHAR;
		function.named_parameters["test_extra_header_name"] = LogicalType::VARCHAR;
		function.named_parameters["test_extra_header_value"] = LogicalType::VARCHAR;
	}

	static unique_ptr<BaseSecret> CreateTestSecret(ClientContext &context, CreateSecretInput &input) {
		RecordProviderCall(GetOptionString(input, "test_id"), GetOptionString(input, "key_id"));

		auto delegated_input = input;
		delegated_input.options.erase("test_id");
		auto extra_header_name = GetOptionString(delegated_input, "test_extra_header_name");
		auto extra_header_value = GetOptionString(delegated_input, "test_extra_header_value");
		delegated_input.options.erase("test_extra_header_name");
		delegated_input.options.erase("test_extra_header_value");
		if (!extra_header_name.empty()) {
			InsertionOrderPreservingMap<string> extra_headers;
			extra_headers.insert(extra_header_name, extra_header_value);
			delegated_input.options["extra_http_headers"] = Value::MAP(extra_headers);
		}
		return CreateSecretFunctionInternal(context, delegated_input);
	}
};

} // namespace

S3ProviderRefreshHook::S3ProviderRefreshHook(string test_id_p, std::function<void()> refresh_hook)
    : test_id(std::move(test_id_p)) {
	SetProviderRefreshHook(test_id, std::move(refresh_hook));
}

S3ProviderRefreshHook::~S3ProviderRefreshHook() {
	ClearProviderRefreshHook(test_id);
}

void S3TestHelper::LoadExtension(DuckDB &db) {
	if (db.ExtensionIsLoaded("httpfs")) {
		return;
	}
	ExtensionInfo extension_info;
	ExtensionActiveLoad load_info(*db.instance, extension_info, "httpfs", "");
	ExtensionLoader loader(load_info);
	HttpfsExtension extension;
	extension.Load(loader);
}

void S3TestHelper::RegisterRefreshProvider(DuckDB &db) {
	ExtensionInfo extension_info;
	ExtensionActiveLoad load_info(*db.instance, extension_info, "httpfs_refresh_test", "");
	ExtensionLoader loader(load_info);

	for (const auto secret_type : {"s3", "gcs"}) {
		CreateSecretFunction function;
		function.secret_type = secret_type;
		function.provider = S3TestHelper::TEST_PROVIDER;
		function.function = TestS3SecretFunctions::CreateTestSecret;
		TestS3SecretFunctions::SetTestNamedParams(function, secret_type);
		loader.RegisterFunction(function);
	}
}

void S3TestHelper::RequireQueryOk(Connection &con, const string &query) {
	auto result = con.Query(query);
	REQUIRE(result);
	INFO((result->HasError() ? result->GetError() : string()));
	REQUIRE_FALSE(result->HasError());
}

string S3TestHelper::NextTestId() {
	static std::atomic<idx_t> next_id(0);
	return StringUtil::Format("httpfs_refresh_test_%llu", static_cast<unsigned long long>(++next_id));
}

CreateSecretInput S3TestHelper::CreateTransactionRefreshInput(const string &test_id) {
	CreateSecretInput input;
	input.type = "s3";
	input.provider = S3TestHelper::TEST_PROVIDER;
	input.name = "transaction_refresh_s3";
	input.scope = {"s3://refresh-bucket/"};
	input.on_conflict = OnCreateConflict::REPLACE_ON_CONFLICT;
	input.persist_type = SecretPersistType::TRANSACTION;
	input.options["key_id"] = S3TestHelper::STALE_KEY_ID;
	input.options["secret"] = S3TestHelper::STALE_SECRET;
	input.options["test_id"] = test_id;

	InsertionOrderPreservingMap<string> refresh_info;
	refresh_info.insert("key_id", S3TestHelper::FRESH_KEY_ID);
	refresh_info.insert("secret", S3TestHelper::FRESH_SECRET);
	refresh_info.insert("test_id", test_id);
	input.options["refresh_info"] = Value::MAP(refresh_info);
	return input;
}

string S3TestHelper::ConfigureRefresh(DuckDB &db, Connection &con, MockS3Server &server,
                                      const string &client_implementation, bool connection_caching,
                                      bool refresh_enabled) {
	auto test_id = NextTestId();

	LoadExtension(db);
	RegisterRefreshProvider(db);

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
	                                       S3TestHelper::TEST_PROVIDER, S3TestHelper::STALE_KEY_ID,
	                                       S3TestHelper::STALE_SECRET, test_id, S3TestHelper::FRESH_KEY_ID,
	                                       S3TestHelper::FRESH_SECRET, test_id));
	return test_id;
}

void S3TestHelper::ConfigureEndpointRefresh(DuckDB &db, Connection &con, MockS3Server &stale_server,
                                            MockS3Server &fresh_server, const string &client_implementation) {
	auto test_id = NextTestId();

	LoadExtension(db);
	RegisterRefreshProvider(db);

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
	                                       S3TestHelper::TEST_PROVIDER, S3TestHelper::STALE_KEY_ID,
	                                       S3TestHelper::STALE_SECRET, stale_server.Endpoint(), test_id,
	                                       S3TestHelper::STALE_KEY_ID, S3TestHelper::STALE_SECRET,
	                                       fresh_server.Endpoint(), test_id));
}

void S3TestHelper::AssertSingleRefresh(const string &test_id) {
	auto stats = GetProviderStats(test_id);
	REQUIRE(stats.initial_creations == 1);
	REQUIRE(stats.refresh_creations == 1);
}

void S3TestHelper::AssertNoRefresh(const string &test_id) {
	auto stats = GetProviderStats(test_id);
	REQUIRE(stats.initial_creations == 1);
	REQUIRE(stats.refresh_creations == 0);
}

bool S3TestHelper::HasRequestWithKey(const vector<MockS3RequestObservation> &observations, const string &key_id) {
	for (auto &observation : observations) {
		if (observation.key_id == key_id) {
			return true;
		}
	}
	return false;
}

idx_t S3TestHelper::CountObservations(const vector<MockS3RequestObservation> &observations, const string &method,
                                      const string &key_id, int status) {
	idx_t result = 0;
	for (auto &observation : observations) {
		if (observation.method == method && observation.key_id == key_id && observation.status == status) {
			result++;
		}
	}
	return result;
}

vector<MockS3RequestObservation>
S3TestHelper::CompletionObservations(const vector<MockS3RequestObservation> &observations) {
	vector<MockS3RequestObservation> result;
	for (const auto &observation : observations) {
		if (observation.method == "POST" && StringUtil::Contains(observation.target, "uploadId")) {
			result.push_back(observation);
		}
	}
	return result;
}

void S3TestHelper::RequireCompletionIdentity(const vector<MockS3RequestObservation> &observations,
                                             idx_t expected_attempts) {
	auto completions = CompletionObservations(observations);
	REQUIRE(completions.size() == expected_attempts);
	REQUIRE(completions.front().body_size > 0);
	REQUIRE_FALSE(completions.front().body_digest.empty());
	REQUIRE_FALSE(completions.front().upload_id.empty());
	for (const auto &completion : completions) {
		REQUIRE(completion.body_size == completions.front().body_size);
		REQUIRE(completion.body_digest == completions.front().body_digest);
		REQUIRE(completion.upload_id == completions.front().upload_id);
	}
}

void S3TestHelper::WriteMultipartPayload(Connection &con) {
	RequireQueryOk(con, "SET s3_uploader_max_filesize='50GB'");
	auto &fs = FileSystem::GetFileSystem(*con.context);
	auto handle =
	    fs.OpenFile(S3TestHelper::S3_PATH, FileFlags::FILE_FLAGS_WRITE | FileFlags::FILE_FLAGS_FILE_CREATE_NEW);
	string payload(10 * 1024 * 1024 + 1, 'x');
	handle->Write(QueryContext(*con.context), &payload[0], payload.size());
	handle->Close();
}

// A payload small enough to be a single-shot PUT (no multipart), so the S3 request loop is the only
// retry layer and the PUT count reflects exactly that loop's behavior.
void S3TestHelper::WriteSinglePutPayload(Connection &con) {
	auto &fs = FileSystem::GetFileSystem(*con.context);
	auto handle =
	    fs.OpenFile(S3TestHelper::S3_PATH, FileFlags::FILE_FLAGS_WRITE | FileFlags::FILE_FLAGS_FILE_CREATE_NEW);
	string payload = "single-shot payload";
	handle->Write(QueryContext(*con.context), &payload[0], payload.size());
	handle->Close();
}

} // namespace duckdb
