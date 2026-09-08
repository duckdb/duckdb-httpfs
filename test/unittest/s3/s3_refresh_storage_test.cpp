#include "catch.hpp"
#include "test_helpers.hpp"

#include "s3/mock_s3_server.hpp"
#include "s3/s3_test_helper.hpp"

#include "create_secret_functions.hpp"

#include "duckdb.hpp"
#include "duckdb/catalog/catalog_transaction.hpp"
#include "duckdb/common/file_system.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/main/client_context.hpp"
#include "duckdb/main/secret/secret_manager.hpp"
#include "duckdb/main/secret/secret_storage.hpp"

namespace duckdb {

namespace {

constexpr const char *SHARED_STORE_NAME = "test_shared_store";
constexpr const char *SHARED_SECRET_NAME = "shared_store_s3";

//! Tie-break offset for the stand-in store. Must not collide with the built-ins (transaction 0, connection 5,
//! memory 10, local_file 20) -- the secret manager rejects a storage whose offset already exists.
constexpr int64_t SHARED_STORE_OFFSET = 30;

//! Observable state of the stand-in store, held outside the storage itself: the secret manager takes ownership of the
//! SecretStorage, so the test keeps its handle on the contents and the write count through this.
struct SharedStoreState {
	mutex lock;
	//! Every StoreSecret call, counted before the read-only check so a rejected write is still visible
	idx_t writes = 0;
	//! Simulates a session whose role cannot write to the shared store
	bool read_only = false;
	identifier_map_t<unique_ptr<SecretEntry>> secrets;
};

//! A stand-in for an extension-registered secret storage (e.g. duckdb-postgres' SECRET_STORAGE_TABLE): persistent,
//! shared between sessions, and writable only when the session's role allows it.
class SharedTestSecretStorage : public SecretStorage {
public:
	explicit SharedTestSecretStorage(shared_ptr<SharedStoreState> state_p)
	    : SecretStorage(SHARED_STORE_NAME, SHARED_STORE_OFFSET), state(std::move(state_p)) {
		persistent = true;
	}

public:
	unique_ptr<SecretEntry> StoreSecret(unique_ptr<const BaseSecret> secret, OnCreateConflict on_conflict,
	                                    optional_ptr<CatalogTransaction> transaction) override {
		lock_guard<mutex> guard(state->lock);
		state->writes++;
		if (state->read_only) {
			throw InvalidInputException("Secret storage '%s' is read-only for this session", storage_name);
		}
		auto result = make_uniq<SecretEntry>(std::move(secret));
		result->persist_type = SecretPersistType::PERSISTENT;
		result->storage_mode = storage_name;
		state->secrets[Identifier(result->secret->GetName())] = make_uniq<SecretEntry>(*result);
		return result;
	}

	vector<SecretEntry> AllSecrets(optional_ptr<CatalogTransaction> transaction) override {
		lock_guard<mutex> guard(state->lock);
		vector<SecretEntry> result;
		for (auto &entry : state->secrets) {
			result.emplace_back(*entry.second);
		}
		return result;
	}

	void DropSecretByName(const Identifier &name, OnEntryNotFound on_entry_not_found,
	                      optional_ptr<CatalogTransaction> transaction) override {
		lock_guard<mutex> guard(state->lock);
		auto entry = state->secrets.find(name);
		if (entry == state->secrets.end()) {
			if (on_entry_not_found == OnEntryNotFound::THROW_EXCEPTION) {
				throw InvalidInputException("Failed to remove non-existent secret '%s'", name);
			}
			return;
		}
		state->secrets.erase(entry);
	}

	SecretMatch LookupSecret(const string &path, const string &type,
	                         optional_ptr<CatalogTransaction> transaction) override {
		lock_guard<mutex> guard(state->lock);
		auto best_match = SecretMatch();
		for (auto &entry : state->secrets) {
			if (entry.second->secret->GetType() == type) {
				best_match = SelectBestMatch(*entry.second, path, tie_break_offset, best_match);
			}
		}
		return best_match;
	}

	unique_ptr<SecretEntry> GetSecretByName(const string &name, optional_ptr<CatalogTransaction> transaction) override {
		lock_guard<mutex> guard(state->lock);
		auto entry = state->secrets.find(Identifier(name));
		if (entry == state->secrets.end()) {
			return nullptr;
		}
		return make_uniq<SecretEntry>(*entry->second);
	}

private:
	shared_ptr<SharedStoreState> state;
};

static shared_ptr<SharedStoreState> RegisterSharedStore(DuckDB &db) {
	auto state = make_shared_ptr<SharedStoreState>();
	SecretManager::Get(*db.instance).LoadSecretStorage(make_uniq<SharedTestSecretStorage>(state));
	return state;
}

//! Seeds a refreshable S3 secret into the stand-in store, the way an operator would publish one there.
static void CreateSecretInSharedStore(Connection &con, const string &test_id) {
	S3TestHelper::RequireQueryOk(
	    con, StringUtil::Format(R"(
CREATE SECRET %s IN %s (
	TYPE S3,
	PROVIDER %s,
	SCOPE 's3://%s/',
	KEY_ID '%s',
	SECRET '%s',
	TEST_ID '%s',
	REFRESH_INFO MAP {
		'KEY_ID': '%s',
		'SECRET': '%s',
		'TEST_ID': '%s'
	}
))",
	                            SHARED_SECRET_NAME, SHARED_STORE_NAME, S3TestHelper::TEST_PROVIDER,
	                            S3TestHelper::BUCKET, S3TestHelper::STALE_KEY_ID, S3TestHelper::STALE_SECRET, test_id,
	                            S3TestHelper::FRESH_KEY_ID, S3TestHelper::FRESH_SECRET, test_id));
}

static string StoredKeyId(SharedStoreState &state, const string &name) {
	lock_guard<mutex> guard(state.lock);
	auto entry = state.secrets.find(Identifier(name));
	REQUIRE(entry != state.secrets.end());
	Value key_id;
	REQUIRE(entry->second->secret->Cast<KeyValueSecret>().TryGetValue("key_id", key_id));
	return key_id.ToString();
}

static string EntryKeyId(const SecretEntry &entry) {
	Value key_id;
	REQUIRE(entry.secret->Cast<KeyValueSecret>().TryGetValue("key_id", key_id));
	return key_id.ToString();
}

static void ConfigureS3Settings(Connection &con, MockS3Server &server) {
	S3TestHelper::RequireQueryOk(con, "SET httpfs_client_implementation='httplib'");
	S3TestHelper::RequireQueryOk(con, "SET httpfs_connection_caching=false");
	S3TestHelper::RequireQueryOk(con, "SET httpfs_enable_credential_refresh=true");
	S3TestHelper::RequireQueryOk(con, StringUtil::Format("SET s3_endpoint='%s'", server.Endpoint()));
	S3TestHelper::RequireQueryOk(con, "SET s3_region='us-east-1'");
	S3TestHelper::RequireQueryOk(con, "SET s3_use_ssl=false");
	S3TestHelper::RequireQueryOk(con, "SET s3_url_style='path'");
}

static MockS3ServerConfig RefreshServerConfig() {
	MockS3ServerConfig config;
	config.object.bucket = S3TestHelper::BUCKET;
	config.object.key = S3TestHelper::OBJECT_KEY;
	config.auth.stale_key_id = S3TestHelper::STALE_KEY_ID;
	config.auth.refresh_target = MockS3RefreshTarget::FULL_GET;
	return config;
}

//! Drives one full read through the mock server with the secret living in the stand-in store, and returns the
//! observations so the caller can assert the stale request was retried with refreshed credentials.
static vector<MockS3RequestObservation> RunSharedStoreReadScenario(DuckDB &db, Connection &con, MockS3Server &server,
                                                                   SharedStoreState &state, bool read_only) {
	S3TestHelper::LoadExtension(db);
	S3TestHelper::RegisterRefreshProvider(db);
	ConfigureS3Settings(con, server);

	auto test_id = S3TestHelper::NextTestId();
	CreateSecretInSharedStore(con, test_id);
	REQUIRE(state.writes == 1);
	{
		lock_guard<mutex> guard(state.lock);
		state.read_only = read_only;
	}

	S3TestHelper::RequireQueryOk(con, "SET force_download=true");
	S3TestHelper::RequireQueryOk(con, "BEGIN TRANSACTION");
	auto &fs = FileSystem::GetFileSystem(*con.context);
	auto handle = fs.OpenFile(S3TestHelper::S3_PATH, FileFlags::FILE_FLAGS_READ);
	REQUIRE(handle);
	S3TestHelper::RequireQueryOk(con, "COMMIT");

	S3TestHelper::AssertSingleRefresh(test_id);
	return server.Observations();
}

} // namespace

TEST_CASE("HTTPFS refreshes a shared-storage S3 secret without writing to that storage", "[httpfs][s3][refresh]") {
	DuckDB db(nullptr);
	Connection con(db);
	S3TestHelper::LoadExtension(db);
	S3TestHelper::RegisterRefreshProvider(db);

	auto state = RegisterSharedStore(db);
	auto &secret_manager = SecretManager::Get(*db.instance);

	auto test_id = S3TestHelper::NextTestId();
	CreateSecretInSharedStore(con, test_id);
	REQUIRE(state->writes == 1);

	S3TestHelper::RequireQueryOk(con, "BEGIN TRANSACTION");
	auto transaction = CatalogTransaction::GetSystemCatalogTransaction(*con.context);
	auto stored_entry = secret_manager.GetSecretByName(transaction, SHARED_SECRET_NAME);
	REQUIRE(stored_entry);
	REQUIRE(stored_entry->storage_mode == SHARED_STORE_NAME);
	REQUIRE(EntryKeyId(*stored_entry) == S3TestHelper::STALE_KEY_ID);

	REQUIRE(CreateS3SecretFunctions::TryRefreshS3Secret(*con.context, *stored_entry));
	S3TestHelper::AssertSingleRefresh(test_id);

	// The shared store took no further write, and its copy still holds the original credential material.
	REQUIRE(state->writes == 1);
	REQUIRE(StoredKeyId(*state, SHARED_SECRET_NAME) == S3TestHelper::STALE_KEY_ID);

	// The refreshed material lands in the refresh overlay and outranks the store copy on lookups.
	auto match = secret_manager.LookupSecret(transaction, S3TestHelper::S3_PATH, "s3");
	REQUIRE(match.HasMatch());
	REQUIRE(match.secret_entry->storage_mode == SecretManager::REFRESH_STORAGE_NAME);
	REQUIRE(EntryKeyId(*match.secret_entry) == S3TestHelper::FRESH_KEY_ID);

	// Two live copies of one name must not turn into a by-name ambiguity error.
	auto by_name = secret_manager.GetSecretByName(transaction, SHARED_SECRET_NAME);
	REQUIRE(by_name);
	REQUIRE(by_name->storage_mode == SecretManager::REFRESH_STORAGE_NAME);
	REQUIRE(EntryKeyId(*by_name) == S3TestHelper::FRESH_KEY_ID);

	S3TestHelper::RequireQueryOk(con, "COMMIT");

	// The overlay is session-scoped, so the refresh still holds in the next transaction -- this is what a
	// transaction-scoped refresh cannot do, and why a long-lived session re-resolves once instead of every
	// transaction. The store copy is still untouched underneath.
	S3TestHelper::RequireQueryOk(con, "BEGIN TRANSACTION");
	auto next_transaction = CatalogTransaction::GetSystemCatalogTransaction(*con.context);
	auto after_commit = secret_manager.GetSecretByName(next_transaction, SHARED_SECRET_NAME);
	REQUIRE(after_commit);
	REQUIRE(after_commit->storage_mode == SecretManager::REFRESH_STORAGE_NAME);
	REQUIRE(EntryKeyId(*after_commit) == S3TestHelper::FRESH_KEY_ID);
	REQUIRE(StoredKeyId(*state, SHARED_SECRET_NAME) == S3TestHelper::STALE_KEY_ID);

	// Dropping the secret takes the overlay copy with it, so no stale shadow outlives it.
	S3TestHelper::RequireQueryOk(con, StringUtil::Format("DROP SECRET %s", SHARED_SECRET_NAME));
	REQUIRE_FALSE(secret_manager.GetSecretByName(next_transaction, SHARED_SECRET_NAME));
	S3TestHelper::RequireQueryOk(con, "COMMIT");
}

TEST_CASE("HTTPFS refreshes a read-only shared-storage S3 secret", "[httpfs][s3][refresh]") {
	DuckDB db(nullptr);
	Connection con(db);
	S3TestHelper::LoadExtension(db);
	S3TestHelper::RegisterRefreshProvider(db);

	auto state = RegisterSharedStore(db);
	auto &secret_manager = SecretManager::Get(*db.instance);

	auto test_id = S3TestHelper::NextTestId();
	CreateSecretInSharedStore(con, test_id);
	{
		lock_guard<mutex> guard(state->lock);
		state->read_only = true;
	}

	S3TestHelper::RequireQueryOk(con, "BEGIN TRANSACTION");
	auto transaction = CatalogTransaction::GetSystemCatalogTransaction(*con.context);
	auto stored_entry = secret_manager.GetSecretByName(transaction, SHARED_SECRET_NAME);
	REQUIRE(stored_entry);

	// Before the refresh was moved off the origin storage this threw "Exception thrown while trying to refresh
	// secret", failing a read that the re-resolved credentials could have served.
	REQUIRE(CreateS3SecretFunctions::TryRefreshS3Secret(*con.context, *stored_entry));
	S3TestHelper::AssertSingleRefresh(test_id);
	REQUIRE(state->writes == 1);

	auto match = secret_manager.LookupSecret(transaction, S3TestHelper::S3_PATH, "s3");
	REQUIRE(match.HasMatch());
	REQUIRE(EntryKeyId(*match.secret_entry) == S3TestHelper::FRESH_KEY_ID);
	S3TestHelper::RequireQueryOk(con, "COMMIT");
}

TEST_CASE("HTTPFS refreshes a shared-storage S3 secret once per session", "[httpfs][s3][refresh]") {
	MockS3Server server(RefreshServerConfig());
	DuckDB db(nullptr);
	Connection con(db);
	auto state = RegisterSharedStore(db);

	S3TestHelper::LoadExtension(db);
	S3TestHelper::RegisterRefreshProvider(db);
	ConfigureS3Settings(con, server);
	auto test_id = S3TestHelper::NextTestId();
	CreateSecretInSharedStore(con, test_id);
	S3TestHelper::RequireQueryOk(con, "SET force_download=true");

	// Three reads in three separate transactions, as autocommit statements would be.
	auto &fs = FileSystem::GetFileSystem(*con.context);
	for (idx_t i = 0; i < 3; i++) {
		S3TestHelper::RequireQueryOk(con, "BEGIN TRANSACTION");
		auto handle = fs.OpenFile(S3TestHelper::S3_PATH, FileFlags::FILE_FLAGS_READ);
		REQUIRE(handle);
		handle.reset();
		S3TestHelper::RequireQueryOk(con, "COMMIT");
	}

	// The overlay survives each commit, so the credential chain runs once for the session rather than once per
	// transaction, and only the first read pays the stale-credential round-trips.
	S3TestHelper::AssertSingleRefresh(test_id);
	auto observations = server.Observations();
	INFO(MockS3DescribeObservations(observations));
	REQUIRE(S3TestHelper::CountObservations(observations, "GET", S3TestHelper::FRESH_KEY_ID, 200) == 3);
	// Only the first read pays the stale-credential round-trips; a transaction-scoped refresh pays them again in
	// every later transaction (12 here rather than 4), because its copy is dropped at each commit.
	REQUIRE(S3TestHelper::CountObservations(observations, "GET", S3TestHelper::STALE_KEY_ID, 403) == 4);
	REQUIRE(state->writes == 1);
	REQUIRE(StoredKeyId(*state, SHARED_SECRET_NAME) == S3TestHelper::STALE_KEY_ID);
}

TEST_CASE("HTTPFS refreshes a persistent S3 secret without writing to its storage", "[httpfs][s3][refresh]") {
	MockS3Server server(RefreshServerConfig());
	DuckDB db(nullptr);
	Connection con(db);
	S3TestHelper::LoadExtension(db);
	S3TestHelper::RegisterRefreshProvider(db);
	ConfigureS3Settings(con, server);

	auto secret_dir = TestCreatePath("secret_refresh_no_disk_write");
	S3TestHelper::RequireQueryOk(con, StringUtil::Format("SET secret_directory='%s'", secret_dir));
	auto test_id = S3TestHelper::NextTestId();
	S3TestHelper::RequireQueryOk(con,
	                             StringUtil::Format(R"(
CREATE PERSISTENT SECRET persistent_s3 (
	TYPE S3,
	PROVIDER %s,
	SCOPE 's3://%s/',
	KEY_ID '%s',
	SECRET '%s',
	TEST_ID '%s',
	REFRESH_INFO MAP {
		'KEY_ID': '%s',
		'SECRET': '%s',
		'TEST_ID': '%s'
	}
))",
	                                                S3TestHelper::TEST_PROVIDER, S3TestHelper::BUCKET,
	                                                S3TestHelper::STALE_KEY_ID, S3TestHelper::STALE_SECRET, test_id,
	                                                S3TestHelper::FRESH_KEY_ID, S3TestHelper::FRESH_SECRET, test_id));

	S3TestHelper::RequireQueryOk(con, "SET force_download=true");
	S3TestHelper::RequireQueryOk(con, "BEGIN TRANSACTION");
	auto &fs = FileSystem::GetFileSystem(*con.context);
	auto handle = fs.OpenFile(S3TestHelper::S3_PATH, FileFlags::FILE_FLAGS_READ);
	REQUIRE(handle);
	handle.reset();
	S3TestHelper::RequireQueryOk(con, "COMMIT");
	S3TestHelper::AssertSingleRefresh(test_id);

	// The persistent copy still holds the original material -- refreshed credentials are never written back. This is
	// the half of the problem #195 reports, where that same write fails outright for an sts-chain persistent secret.
	auto &secret_manager = SecretManager::Get(*db.instance);
	S3TestHelper::RequireQueryOk(con, "BEGIN TRANSACTION");
	auto transaction = CatalogTransaction::GetSystemCatalogTransaction(*con.context);
	auto on_disk = secret_manager.GetSecretByName(transaction, "persistent_s3", SecretManager::LOCAL_FILE_STORAGE_NAME);
	REQUIRE(on_disk);
	REQUIRE(EntryKeyId(*on_disk) == S3TestHelper::STALE_KEY_ID);

	auto overlay = secret_manager.GetSecretByName(transaction, "persistent_s3", SecretManager::REFRESH_STORAGE_NAME);
	REQUIRE(overlay);
	REQUIRE(EntryKeyId(*overlay) == S3TestHelper::FRESH_KEY_ID);
	S3TestHelper::RequireQueryOk(con, "COMMIT");

	// Both copies are visible, so a user can see that a refresh shadowed the stored secret.
	auto listed = con.Query("SELECT name, persistent, storage FROM duckdb_secrets() "
	                        "WHERE name='persistent_s3' ORDER BY storage");
	REQUIRE(listed);
	INFO((listed->HasError() ? listed->GetError() : listed->ToString()));
	REQUIRE_FALSE(listed->HasError());
	REQUIRE(listed->RowCount() == 2);
	REQUIRE(listed->GetValue(2, 0).ToString() == SecretManager::LOCAL_FILE_STORAGE_NAME);
	REQUIRE(listed->GetValue(1, 0).GetValue<bool>());
	REQUIRE(listed->GetValue(2, 1).ToString() == SecretManager::REFRESH_STORAGE_NAME);
	REQUIRE_FALSE(listed->GetValue(1, 1).GetValue<bool>());
}

TEST_CASE("HTTPFS reads through a refreshed shared-storage S3 secret", "[httpfs][s3][refresh]") {
	SECTION("writable store") {
		MockS3Server server(RefreshServerConfig());
		DuckDB db(nullptr);
		Connection con(db);
		auto state = RegisterSharedStore(db);

		auto observations = RunSharedStoreReadScenario(db, con, server, *state, false);
		INFO(MockS3DescribeObservations(observations));
		REQUIRE(MockS3HasObservation(observations, "GET", S3TestHelper::STALE_KEY_ID, 403));
		REQUIRE(MockS3HasObservation(observations, "GET", S3TestHelper::FRESH_KEY_ID, 200));
		REQUIRE(state->writes == 1);
		REQUIRE(StoredKeyId(*state, SHARED_SECRET_NAME) == S3TestHelper::STALE_KEY_ID);
	}
	SECTION("read-only store") {
		MockS3Server server(RefreshServerConfig());
		DuckDB db(nullptr);
		Connection con(db);
		auto state = RegisterSharedStore(db);

		auto observations = RunSharedStoreReadScenario(db, con, server, *state, true);
		INFO(MockS3DescribeObservations(observations));
		REQUIRE(MockS3HasObservation(observations, "GET", S3TestHelper::STALE_KEY_ID, 403));
		REQUIRE(MockS3HasObservation(observations, "GET", S3TestHelper::FRESH_KEY_ID, 200));
		REQUIRE(state->writes == 1);
	}
}

} // namespace duckdb
