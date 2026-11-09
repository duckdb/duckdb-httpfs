// A catalog-style host registers ordinary transaction secrets and names them in each resolved file's
// SECRET_OPTION. Named reads override path matching; visibility, settings and caches follow core's normal rules.
// The mock S3 server checks the key id on each request so losing a file's selected secret is observable.

#include "catch.hpp"

#include "s3/mock_s3_server.hpp"
#include "s3/s3_test_helper.hpp"
#include "s3/s3_auth.hpp"

#include "duckdb.hpp"
#include "duckdb/catalog/catalog.hpp"
#include "duckdb/catalog/catalog_entry/table_function_catalog_entry.hpp"
#include "duckdb/common/file_system.hpp"
#include "duckdb/common/limits.hpp"
#include "duckdb/common/local_file_system.hpp"
#include "duckdb/common/multi_file/multi_file_reader.hpp"
#include "duckdb/common/mutex.hpp"
#include "duckdb/common/open_file_info.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/main/client_context.hpp"
#include "duckdb/main/client_context_file_opener.hpp"
#include "duckdb/main/extension/extension_loader.hpp"
#include "duckdb/main/secret/secret.hpp"
#include "duckdb/main/secret/secret_manager.hpp"
#include "duckdb/storage/object_cache.hpp"
#include "test_helpers.hpp"

#include <atomic>
#include <chrono>
#include <fstream>
#include <sstream>
#include <thread>
#include <unistd.h>

namespace duckdb {

//! As parquet_extension.hpp and core_functions_extension.hpp declare them; not every build publishes those headers
class ParquetExtension : public Extension {
public:
	void Load(ExtensionLoader &loader) override;
	std::string Name() override;
	std::string Version() const override;
};
class CoreFunctionsExtension : public Extension {
public:
	void Load(ExtensionLoader &db) override;
	std::string Name() override;
	std::string Version() const override;
};

namespace {

//! A build may link Parquet and the core functions as static extensions that a new database does not load by itself
void LoadParquet(DuckDB &db) {
	if (!db.ExtensionIsLoaded("core_functions")) {
		db.LoadStaticExtension<CoreFunctionsExtension>();
	}
	if (!db.ExtensionIsLoaded("parquet")) {
		db.LoadStaticExtension<ParquetExtension>();
	}
}

// Key ids. The mock server reads the key id from the Authorization header and checks no signature.
constexpr const char *ORDERS_KEY = "AKIAORDERSGRANT00001";
constexpr const char *ORDERS_KEY_REFRESHED = "AKIAORDERSGRANT00002";
//! The key of a second table at the location of orders (GovernedHost::AddTableAt)
constexpr const char *ORDERS_SECOND_KEY = "AKIAORDERSSECOND0001";
constexpr const char *ITEMS_KEY = "AKIAITEMSGRANT000001";
constexpr const char *USER_KEY = "AKIAUSERPATHSECRET01";
//! The secret part of each credential is the key id with this suffix; a test looks for it in outputs
constexpr const char *SECRET_SUFFIX = "-SECRETPART";
//! and the session token is the key id with this one
constexpr const char *TOKEN_SUFFIX = "-TOKENPART";

constexpr const char *ORDERS_BUCKET = "governed-orders";
constexpr const char *ITEMS_BUCKET = "governed-items";
constexpr const char *USER_BUCKET = "user-bucket";
constexpr idx_t FILES_PER_TABLE = 3;
constexpr idx_t ROWS_PER_FILE = 6000;

string OrdersFile(idx_t i) {
	return StringUtil::Format("s3://%s/orders/part-%llu.parquet", ORDERS_BUCKET, (unsigned long long)i);
}
string ItemsFile(idx_t i) {
	return StringUtil::Format("s3://%s/items/part-%llu.parquet", ITEMS_BUCKET, (unsigned long long)i);
}
string UserFile() {
	return StringUtil::Format("s3://%s/user/part-0.parquet", USER_BUCKET);
}

//! The bytes of a Parquet file of ROWS_PER_FILE rows in row groups of 1000, written locally once
const string &ParquetBytes() {
	static string bytes = [] {
		DuckDB db(nullptr);
		LoadParquet(db);
		Connection con(db);
		auto path = "/tmp/s3-secret-table_credentials-test-" + to_string(getpid()) + ".parquet";
		auto result = con.Query(StringUtil::Format("COPY (SELECT range AS i, 'value ' || range AS s FROM range(%llu)) "
		                                           "TO '%s' (FORMAT parquet, ROW_GROUP_SIZE 1000)",
		                                           (unsigned long long)ROWS_PER_FILE, path));
		INFO((result->HasError() ? result->GetError() : string()));
		REQUIRE_FALSE(result->HasError());
		std::ifstream in(path, std::ios::binary);
		std::stringstream buffer;
		buffer << in.rdbuf();
		return buffer.str();
	}();
	return bytes;
}

MockS3ObjectConfig MakeObject(const string &bucket, const string &key) {
	MockS3ObjectConfig object;
	object.bucket = bucket;
	object.key = key;
	object.data = ParquetBytes();
	return object;
}

//! Two governed tables in buckets that answer only the table's own credentials, and a user bucket that answers
//! the user's credential
MockS3ServerConfig MakeConfig() {
	MockS3ServerConfig config;
	for (idx_t i = 0; i < FILES_PER_TABLE; i++) {
		config.extra_objects.push_back(
		    MakeObject(ORDERS_BUCKET, StringUtil::Format("orders/part-%llu.parquet", (unsigned long long)i)));
		config.extra_objects.push_back(
		    MakeObject(ITEMS_BUCKET, StringUtil::Format("items/part-%llu.parquet", (unsigned long long)i)));
	}
	config.extra_objects.push_back(MakeObject(USER_BUCKET, "user/part-0.parquet"));
	config.auth.bucket_key_ids[ORDERS_BUCKET] = {ORDERS_KEY, ORDERS_KEY_REFRESHED};
	config.auth.bucket_key_ids[ITEMS_BUCKET] = {ITEMS_KEY};
	config.auth.bucket_key_ids[USER_BUCKET] = {USER_KEY};
	config.auth.stale_status = 403;
	return config;
}

//===--------------------------------------------------------------------===//
// The host
//===--------------------------------------------------------------------===//

//! What the host knows about a governed table: where it is, and the credentials a vend returns for it
struct GovernedTable {
	string scope;
	vector<string> files;
	//! The key each vend returns: the first vend gets keys[0], the next keys[1], and so on; the last repeats
	vector<string> keys;
	idx_t vends = 0;
	//! The number of vends that succeed; the provider fails every later one
	idx_t successful_vends = NumericLimits<idx_t>::Maximum();
	//! How long every vend after the first takes, so that reads on other threads fail while a refresh runs
	idx_t refresh_delay_ms = 0;

	struct VendResult {
		string key;
		//! How long the vend takes; the caller waits after it releases the host's lock
		idx_t delay_ms;
	};
	//! Count a vend of the table `name` and return its key and delay, or throw once `successful_vends` were made
	VendResult NextVend(const string &name) {
		if (vends >= successful_vends) {
			vends++;
			throw IOException("The test host refused to vend credentials for %s", name);
		}
		// the last key repeats once every key has been vended
		auto key_index = MinValue<idx_t>(vends, keys.size() - 1);
		// the first vend is at bind; only a refresh takes refresh_delay_ms
		auto is_refresh = vends > 0;
		VendResult result {keys[key_index], is_refresh ? refresh_delay_ms : 0};
		vends++;
		return result;
	}
};

//! The name of the transaction secret selected by the table's files
using Attachment = string;

class GovernedHost {
public:
	static GovernedHost &Get() {
		static GovernedHost host;
		return host;
	}

	void Reset(const string &endpoint_p) {
		lock_guard<mutex> guard(lock);
		endpoint = endpoint_p;
		tables.clear();
		attachments.clear();
		omitted_keys.clear();
		GovernedTable orders;
		orders.scope = StringUtil::Format("s3://%s/", ORDERS_BUCKET);
		GovernedTable items;
		items.scope = StringUtil::Format("s3://%s/", ITEMS_BUCKET);
		for (idx_t i = 0; i < FILES_PER_TABLE; i++) {
			orders.files.push_back(OrdersFile(i));
			items.files.push_back(ItemsFile(i));
		}
		orders.keys = {ORDERS_KEY};
		items.keys = {ITEMS_KEY};
		tables["orders"] = orders;
		tables["items"] = items;
	}
	//! Keys the secrets the host creates from now on leave unset
	void SetOmittedKeys(vector<string> keys) {
		lock_guard<mutex> guard(lock);
		omitted_keys = std::move(keys);
	}
	void SetKeys(const string &table, vector<string> keys) {
		lock_guard<mutex> guard(lock);
		Find(table).keys = std::move(keys);
	}
	//! A table `name` at the location of `table`, whose vends return `keys`
	void AddTableAt(const string &name, const string &table, vector<string> keys) {
		lock_guard<mutex> guard(lock);
		auto added = Find(table);
		added.keys = std::move(keys);
		added.vends = 0;
		tables[name] = std::move(added);
	}
	void SetRefreshDelay(const string &table, idx_t delay_ms) {
		lock_guard<mutex> guard(lock);
		Find(table).refresh_delay_ms = delay_ms;
	}
	void FailVendsAfter(const string &table, idx_t successful_vends) {
		lock_guard<mutex> guard(lock);
		Find(table).successful_vends = successful_vends;
	}
	idx_t Vends(const string &table) {
		lock_guard<mutex> guard(lock);
		return Find(table).vends;
	}
	GovernedTable Table(const string &table) {
		lock_guard<mutex> guard(lock);
		return Find(table);
	}
	//! A vend: the next key for the table
	string Vend(const string &table) {
		GovernedTable::VendResult vend;
		{
			lock_guard<mutex> guard(lock);
			vend = Find(table).NextVend(table);
		}
		std::this_thread::sleep_for(std::chrono::milliseconds(vend.delay_ms));
		return vend.key;
	}
	unique_ptr<KeyValueSecret> MakeSecret(const vector<string> &scope, const Identifier &provider,
	                                      const Identifier &name, const string &key_id) {
		auto secret = make_uniq<KeyValueSecret>(scope, Identifier("s3"), provider, name);
		secret->secret_map[Identifier("key_id")] = Value(key_id);
		secret->secret_map[Identifier("secret")] = Value(key_id + SECRET_SUFFIX);
		secret->secret_map[Identifier("session_token")] = Value(key_id + TOKEN_SUFFIX);
		secret->secret_map[Identifier("region")] = Value("eu-central-1");
		secret->secret_map[Identifier("url_style")] = Value("path");
		secret->secret_map[Identifier("use_ssl")] = Value::BOOLEAN(false);
		secret->secret_map[Identifier("endpoint")] = Value(endpoint);
		InsertionOrderPreservingMap<string> headers;
		headers.insert("X-Host-Key", key_id);
		secret->secret_map["extra_http_headers"] = Value::MAP(headers);
		secret->redact_keys = {"key_id", "secret", "session_token", "extra_http_headers"};
		vector<string> omitted;
		{
			lock_guard<mutex> guard(lock);
			omitted = omitted_keys;
		}
		for (auto &key : omitted) {
			secret->secret_map.erase(Identifier(key));
		}
		return secret;
	}

	//! Obtain credentials for `table` for the query `context` is binding, and return what carries them
	Attachment Attach(ClientContext &context, const string &table);
	//! As Attach, with a secret whose scope is `scope` instead of the table's
	Attachment AttachWithScope(ClientContext &context, const string &table, const string &scope);
	void Apply(const Attachment &attachment, OpenFileInfo &file) {
		file.extended_info = file.extended_info ? make_shared_ptr<ExtendedOpenFileInfo>(*file.extended_info)
		                                        : make_shared_ptr<ExtendedOpenFileInfo>();
		file.extended_info->options[ExtendedOpenFileInfo::SECRET_OPTION] = Value(attachment);
	}
	void Apply(const Attachment &attachment, FileOpenerInfo &info) {
		Apply(attachment, info.file);
	}
	vector<Attachment> Attachments() {
		lock_guard<mutex> guard(lock);
		return attachments;
	}
	string Endpoint() {
		lock_guard<mutex> guard(lock);
		return endpoint;
	}

private:
	//! The table named `table`; throws for a name the host does not know. The caller holds `lock`.
	GovernedTable &Find(const string &table) {
		auto entry = tables.find(table);
		if (entry == tables.end()) {
			throw InvalidInputException("no governed table %s", table);
		}
		return entry->second;
	}

	mutex lock;
	string endpoint;
	unordered_map<string, GovernedTable> tables;
	vector<Attachment> attachments;
	vector<string> omitted_keys;
};

constexpr const char *HOST_NAME = "governed_test";

Attachment GovernedHost::Attach(ClientContext &context, const string &table) {
	return AttachWithScope(context, table, Table(table).scope);
}

Attachment GovernedHost::AttachWithScope(ClientContext &context, const string &table, const string &scope) {
	static std::atomic<idx_t> next_secret {0};
	CreateSecretInput input;
	input.type = "s3";
	input.provider = HOST_NAME;
	input.name = Identifier("governed_" + to_string(next_secret++));
	input.scope = {scope};
	input.options["table"] = Value(table);
	input.on_conflict = OnCreateConflict::ERROR_ON_CONFLICT;
	input.persist_type = SecretPersistType::TRANSACTION;
	auto entry = SecretManager::Get(context).CreateSecret(context, input);
	auto name = entry->secret->GetName().GetIdentifierName();
	lock_guard<mutex> guard(lock);
	attachments.push_back(name);
	return name;
}

unique_ptr<BaseSecret> CreateHostSecret(ClientContext &, CreateSecretInput &input) {
	auto &host = GovernedHost::Get();
	auto table = input.options.at("table").GetValue<string>();
	auto secret = host.MakeSecret(input.scope, input.provider, input.name, host.Vend(table));
	secret->secret_map["refresh_info"] = Value::STRUCT({{"table", Value(table)}});
	return std::move(secret);
}

unique_ptr<SecretEntry> GetNamedSecret(ClientContext &context, const string &name) {
	return SecretManager::Get(context).GetSecretByName(CatalogTransaction::GetSystemCatalogTransaction(context), name);
}

//! A table format resolves its manifest into files, then puts the selected secret on each file.
struct GovernedMultiFileReader : public MultiFileReader {
	shared_ptr<MultiFileList> CreateFileList(ClientContext &context, vector<OpenFileInfo> files,
	                                         const FileGlobInput &glob_input) override {
		REQUIRE(files.size() == 1);
		auto &host = GovernedHost::Get();
		auto table_name = files[0].path;
		auto table = host.Table(table_name);
		auto attachment = host.Attach(context, table_name);
		vector<OpenFileInfo> list;
		for (auto &path : table.files) {
			OpenFileInfo file(path);
			host.Apply(attachment, file);
			list.push_back(std::move(file));
		}
		return MultiFileReader::CreateFileList(context, std::move(list), glob_input);
	}
	unique_ptr<MultiFileReader> Copy() const override {
		return make_uniq<GovernedMultiFileReader>();
	}
	static unique_ptr<MultiFileReader> Create(const BoundTableFunction &) {
		return make_uniq<GovernedMultiFileReader>();
	}
};

void RegisterHost(DuckDB &db, Connection &con) {
	ExtensionInfo extension_info;
	ExtensionActiveLoad load_info(*db.instance, extension_info, "file_credentials_host_test", "");
	ExtensionLoader loader(load_info);
	CreateSecretFunction provider;
	provider.secret_type = "s3";
	provider.provider = HOST_NAME;
	provider.function = CreateHostSecret;
	provider.named_parameters["table"] = LogicalType::VARCHAR;
	loader.RegisterFunction(provider);
	TableFunction read_parquet;
	con.context->RunFunctionInTransaction([&]() {
		auto &entry =
		    Catalog::GetEntry<TableFunctionCatalogEntry>(*con.context, QualifiedName("system", "main", "read_parquet"));
		for (idx_t i = 0; i < entry.functions.Size(); i++) {
			auto function = entry.functions.GetFunctionByOffset(i);
			// the overload that takes one path
			auto &signature = function->GetSignature();
			if (signature.GetParameterCount() > 0 &&
			    signature.GetParameter(0).GetType().id() == LogicalTypeId::VARCHAR) {
				read_parquet = *function;
			}
		}
	});
	REQUIRE(read_parquet.GetSignature().GetParameterCount() > 0);
	auto scan = read_parquet;
	scan.name = "governed_scan";
	scan.get_multi_file_reader = GovernedMultiFileReader::Create;
	loader.RegisterFunction(scan);
	auto files = read_parquet;
	files.name = "governed_files";
	files.get_multi_file_reader = GovernedMultiFileReader::Create;
	loader.RegisterFunction(files);
}

//===--------------------------------------------------------------------===//
// Setup and helpers
//===--------------------------------------------------------------------===//

struct Fixture {
	explicit Fixture(MockS3ServerConfig config = MakeConfig()) : server(std::move(config)), db(nullptr), con(db) {
		LoadParquet(db);
		S3TestHelper::LoadExtension(db);
		GovernedHost::Get().Reset(server.Endpoint());
		RegisterHost(db, con);
		Configure(con);
	}
	void Configure(Connection &c) {
		// Longer scopes make ordinary path reads select user_secret even while the host holds named secrets.
		// It has no key until CreateUserSecret is called.
		Ok(c,
		   StringUtil::Format("CREATE OR REPLACE SECRET user_secret (TYPE s3, SCOPE ['s3://governed-orders/orders/', "
		                      "'s3://governed-items/items/', 's3://user-bucket/'], REGION 'eu-central-1', "
		                      "ENDPOINT '%s', URL_STYLE 'path', USE_SSL false)",
		                      server.Endpoint()));
		Ok(c, "SET enable_global_s3_configuration=true");
		Ok(c, "SET s3_url_style='path'");
		Ok(c, "SET s3_use_ssl=false");
		Ok(c, "SET s3_region='eu-central-1'");
		Ok(c, "SET http_retries=1");
		Ok(c, "SET http_retry_wait_ms=1");
		Ok(c, "SET http_retry_backoff=1");
		Ok(c, "SET enable_external_file_cache=false");
		Ok(c, "SET parquet_metadata_cache=false");
		Ok(c, "SET enable_http_metadata_cache=false");
		Ok(c, "SET threads=4");
	}
	void CreateUserSecret(Connection &c) {
		Ok(c,
		   StringUtil::Format("CREATE OR REPLACE SECRET user_secret (TYPE s3, SCOPE ['s3://governed-orders/orders/', "
		                      "'s3://governed-items/items/', 's3://user-bucket/'], KEY_ID '%s', SECRET '%s%s', "
		                      "REGION 'eu-central-1', ENDPOINT '%s', URL_STYLE 'path', USE_SSL false)",
		                      USER_KEY, USER_KEY, SECRET_SUFFIX, server.Endpoint()));
	}
	static void Ok(Connection &c, const string &query) {
		auto result = c.Query(query);
		INFO(query);
		INFO((result->HasError() ? result->GetError() : string()));
		REQUIRE_FALSE(result->HasError());
	}
	static unique_ptr<QueryResult> Run(Connection &c, const string &query) {
		return c.Query(query);
	}
	vector<MockS3RequestObservation> Since(idx_t start) {
		auto all = server.Observations();
		return vector<MockS3RequestObservation>(all.begin() + MinValue<idx_t>(start, all.size()), all.end());
	}
	idx_t Mark() {
		return server.Observations().size();
	}

	MockS3Server server;
	DuckDB db;
	Connection con;
};

bool PathIn(const MockS3RequestObservation &o, const string &bucket) {
	return StringUtil::Contains(o.path, "/" + bucket);
}
idx_t Count(const vector<MockS3RequestObservation> &os, const string &bucket, const string &key_id,
            const string &method = string(), bool success_only = false) {
	idx_t n = 0;
	for (auto &o : os) {
		if (PathIn(o, bucket) && o.key_id == key_id && (method.empty() || o.method == method) &&
		    (!success_only || o.status < 300)) {
			n++;
		}
	}
	return n;
}
idx_t CountKey(const vector<MockS3RequestObservation> &os, const string &key_id) {
	idx_t n = 0;
	for (auto &o : os) {
		n += o.key_id == key_id;
	}
	return n;
}
//! Every request to `bucket` was signed by one of `keys`
bool OnlyKeys(const vector<MockS3RequestObservation> &os, const string &bucket, const vector<string> &keys) {
	for (auto &o : os) {
		if (!PathIn(o, bucket)) {
			continue;
		}
		bool found = false;
		for (auto &k : keys) {
			found = found || o.key_id == k;
		}
		if (!found) {
			return false;
		}
	}
	return true;
}

const string EXPECTED_SUM = to_string((ROWS_PER_FILE * (ROWS_PER_FILE - 1) / 2) * FILES_PER_TABLE);
const string EXPECTED_COUNT = to_string(ROWS_PER_FILE * FILES_PER_TABLE);

void RequireOrdersResult(QueryResult &result) {
	INFO((result.HasError() ? result.GetError() : string()));
	REQUIRE_FALSE(result.HasError());
	REQUIRE(result.Collection().GetValue(0, 0).ToString() == EXPECTED_COUNT);
	REQUIRE(result.Collection().GetValue(1, 0).ToString() == EXPECTED_SUM);
}

//! Scan the table orders through governed_scan and check that every row of it is read
void RunGovernedScan(Fixture &f) {
	RequireOrdersResult(*f.con.Query("SELECT count(*), sum(i) FROM governed_scan('orders')"));
}

//! A path read of a governed object that gives the caller nothing: it fails, or it finds no file to read. A
//! glob of a single path whose HEAD is refused finds no file.
bool GotNothing(QueryResult &result) {
	if (result.HasError()) {
		return true;
	}
	return result.RowCount() == 1 && result.Collection().GetValue(0, 0).ToString() == "0";
}

//! Every file of the table was fetched with a successful GET signed by `key_id`
bool EveryFileFetchedWith(const vector<MockS3RequestObservation> &os, const vector<string> &files,
                          const string &key_id) {
	for (auto &file : files) {
		auto object_path = file.substr(string("s3:/").size());
		bool found = false;
		for (auto &o : os) {
			found = found || (o.path == object_path && o.method == "GET" && o.key_id == key_id && o.status < 300);
		}
		if (!found) {
			return false;
		}
	}
	return true;
}

//! Everything a query result says, as text
string ResultText(QueryResult &result) {
	if (result.HasError()) {
		return result.GetError();
	}
	return result.ToString();
}

//! The strings that must not appear in anything user SQL reads: the host's key ids and secret parts
vector<string> HostCredentialStrings() {
	vector<string> result;
	for (auto key : {ORDERS_KEY, ORDERS_KEY_REFRESHED, ITEMS_KEY}) {
		result.push_back(key);
		result.push_back(string(key) + SECRET_SUFFIX);
		result.push_back(string(key) + TOKEN_SUFFIX);
	}
	return result;
}

void RequireNoCredential(const string &text) {
	for (auto &s : HostCredentialStrings()) {
		INFO(text);
		INFO(s);
		REQUIRE_FALSE(StringUtil::Contains(text, s));
	}
}

} // namespace

//===--------------------------------------------------------------------===//
// [file_credentials_r1] a governed scan reads with the host's credentials
//===--------------------------------------------------------------------===//

TEST_CASE("A catalog scan opens resolved files with its named secret", "[httpfs][s3][file_credentials]") {
	Fixture f;
	f.CreateUserSecret(f.con);
	auto mark = f.Mark();
	RunGovernedScan(f);
	auto observations = f.Since(mark);
	INFO(MockS3DescribeObservations(observations));
	REQUIRE(EveryFileFetchedWith(observations, GovernedHost::Get().Table("orders").files, ORDERS_KEY));
	REQUIRE(OnlyKeys(observations, ORDERS_BUCKET, {ORDERS_KEY}));
	mark = f.Mark();
	auto result = f.con.Query("DESCRIBE SELECT * FROM governed_scan('orders')");
	REQUIRE_FALSE(result->HasError());
	REQUIRE(result->RowCount() == 2);
	REQUIRE(Count(f.Since(mark), ORDERS_BUCKET, ORDERS_KEY, "", true) > 0);
}

TEST_CASE("A prepared scan retains its named secrets within the transaction",
          "[httpfs][s3][file_credentials][file_credentials_r1]") {
	Fixture f;
	f.CreateUserSecret(f.con);
	f.con.BeginTransaction();
	// The catalog host supplies credentials for the transaction that binds the scan.
	auto prepared = f.con.Prepare("SELECT count(*), sum(i) FROM governed_scan('orders')");
	INFO((prepared->HasError() ? prepared->GetError() : string()));
	REQUIRE_FALSE(prepared->HasError());
	for (idx_t run = 0; run < 2; run++) {
		auto mark = f.Mark();
		auto result = prepared->Execute();
		RequireOrdersResult(*result);
		REQUIRE(OnlyKeys(f.Since(mark), ORDERS_BUCKET, {ORDERS_KEY}));
	}
}

//===--------------------------------------------------------------------===//
// Path reads select the more specific user secret; each catalog scan explicitly selects its own.
//===--------------------------------------------------------------------===//

TEST_CASE("User SQL by path does not read with the table's credentials",
          "[httpfs][s3][file_credentials][file_credentials_r2]") {
	Fixture f;
	f.CreateUserSecret(f.con);
	Fixture::Ok(f.con, "BEGIN TRANSACTION");
	// the table's credentials are held for this transaction from here on
	auto result = f.con.Query("SELECT count(*), sum(i) FROM governed_scan('orders')");
	RequireOrdersResult(*result);
	vector<string> queries = {
	    "SELECT count(*) FROM read_parquet('" + OrdersFile(0) + "')",
	    "SELECT count(*) FROM read_parquet('s3://" + string(ORDERS_BUCKET) + "/orders/*.parquet')",
	    "SELECT count(*) FROM read_blob('" + OrdersFile(0) + "')",
	    "SELECT sum(octet_length(content)) FROM read_blob('" + OrdersFile(0) + "')",
	    "SELECT count(*) FROM read_text('" + OrdersFile(0) + "')",
	    "SELECT count(*) FROM glob('s3://" + string(ORDERS_BUCKET) + "/orders/*')",
	    "SELECT count(*) FROM parquet_metadata('" + OrdersFile(0) + "')",
	};
	for (auto &query : queries) {
		auto mark = f.Mark();
		auto r = f.con.Query(query);
		INFO(query);
		INFO(ResultText(*r));
		auto os = f.Since(mark);
		INFO(MockS3DescribeObservations(os));
		REQUIRE(Count(os, ORDERS_BUCKET, ORDERS_KEY) == 0);
		REQUIRE(GotNothing(*r));
		Fixture::Ok(f.con, "ROLLBACK");
		Fixture::Ok(f.con, "BEGIN TRANSACTION");
		RunGovernedScan(f);
	}
	// COPY FROM into a table
	Fixture::Ok(f.con, "CREATE TABLE copied (i BIGINT, s VARCHAR)");
	auto mark = f.Mark();
	auto copy = f.con.Query("COPY copied FROM '" + OrdersFile(0) + "' (FORMAT parquet)");
	INFO(ResultText(*copy));
	REQUIRE(copy->HasError());
	REQUIRE(Count(f.Since(mark), ORDERS_BUCKET, ORDERS_KEY) == 0);
}

TEST_CASE("A catalog scan and a path read of the same files succeed together", "[httpfs][s3][file_credentials]") {
	auto config = MakeConfig();
	config.auth.bucket_key_ids[ORDERS_BUCKET].push_back(USER_KEY);
	Fixture f(config);
	f.CreateUserSecret(f.con);
	const string scan = "SELECT sum(i) FROM governed_scan('orders')";
	const string path_read = "SELECT sum(i) FROM read_parquet('s3://governed-orders/orders/*.parquet')";
	for (auto &query : {"SELECT (" + scan + "), (" + path_read + ")", "SELECT (" + path_read + "), (" + scan + ")"}) {
		auto mark = f.Mark();
		auto result = f.con.Query(query);
		INFO(ResultText(*result));
		REQUIRE_FALSE(result->HasError());
		REQUIRE(result->Collection().GetValue(0, 0).ToString() == EXPECTED_SUM);
		REQUIRE(result->Collection().GetValue(1, 0).ToString() == EXPECTED_SUM);
		// Core may share per-path data within the query; requests that are sent use one of these secrets.
		auto observations = f.Since(mark);
		REQUIRE_FALSE(observations.empty());
		REQUIRE(OnlyKeys(observations, ORDERS_BUCKET, {ORDERS_KEY, USER_KEY}));
	}
}

TEST_CASE("Another table's scan uses only its own credentials", "[httpfs][s3][file_credentials][file_credentials_r2]") {
	Fixture f;
	f.CreateUserSecret(f.con);
	auto mark = f.Mark();
	auto r = f.con.Query(
	    "SELECT (SELECT sum(i) FROM governed_scan('orders')), (SELECT sum(i) FROM governed_files('items'))");
	INFO(ResultText(*r));
	REQUIRE_FALSE(r->HasError());
	REQUIRE(r->Collection().GetValue(0, 0).ToString() == EXPECTED_SUM);
	REQUIRE(r->Collection().GetValue(1, 0).ToString() == EXPECTED_SUM);
	auto os = f.Since(mark);
	INFO(MockS3DescribeObservations(os));
	REQUIRE(OnlyKeys(os, ORDERS_BUCKET, {ORDERS_KEY}));
	REQUIRE(OnlyKeys(os, ITEMS_BUCKET, {ITEMS_KEY}));
	REQUIRE(Count(os, ITEMS_BUCKET, ITEMS_KEY, "", true) > 0);
}

TEST_CASE("Another connection does not read with a transaction's table credentials",
          "[httpfs][s3][file_credentials][file_credentials_r2]") {
	Fixture f;
	f.CreateUserSecret(f.con);
	Fixture::Ok(f.con, "BEGIN TRANSACTION");
	RunGovernedScan(f);
	Connection other(f.db);
	f.Configure(other);
	auto mark = f.Mark();
	auto r = other.Query("SELECT count(*) FROM read_parquet('" + OrdersFile(0) + "')");
	INFO(ResultText(*r));
	REQUIRE(r->HasError());
	REQUIRE(Count(f.Since(mark), ORDERS_BUCKET, ORDERS_KEY) == 0);
}

namespace {
//! A fixture whose orders bucket also answers ORDERS_SECOND_KEY, the key of the table orders_second at the same
//! location, with caches disabled so every read exercises secret selection
struct SameLocationFixture : public Fixture {
	SameLocationFixture() : Fixture(Config()) {
		GovernedHost::Get().AddTableAt("orders_second", "orders", {ORDERS_SECOND_KEY});
		ConfigureUncached(con);
	}
	static MockS3ServerConfig Config() {
		auto config = MakeConfig();
		config.auth.bucket_key_ids[ORDERS_BUCKET].push_back(ORDERS_SECOND_KEY);
		return config;
	}
	//! Disable caches so request counts measure which credentials each scan selects
	void ConfigureUncached(Connection &c) {
		Configure(c);
		Ok(c, "SET threads=1");
		Ok(c, "SET enable_external_file_cache=false");
		Ok(c, "SET parquet_metadata_cache=false");
		Ok(c, "SET enable_http_metadata_cache=false");
		Ok(c, "SET validate_external_file_cache='NO_VALIDATION'");
	}
	//! The successful requests signed with `key_id` that a scan of `table` on `c` alone sends
	idx_t RequestsAlone(Connection &c, const string &table, const string &key_id) {
		auto mark = Mark();
		RequireOrdersResult(*c.Query("SELECT count(*), sum(i) FROM governed_scan('" + table + "')"));
		return Count(Since(mark), ORDERS_BUCKET, key_id, "", true);
	}
};
} // namespace

TEST_CASE("Two tables at one location, scanned in one query, each read every file with their own credentials",
          "[httpfs][s3][file_credentials][file_credentials_r2][file_credentials_r4]") {
	SameLocationFixture f;
	f.CreateUserSecret(f.con);
	auto alone = f.RequestsAlone(f.con, "orders", ORDERS_KEY);
	auto alone_second = f.RequestsAlone(f.con, "orders_second", ORDERS_SECOND_KEY);
	REQUIRE(alone > 0);
	auto mark = f.Mark();
	auto r = f.con.Query(
	    "SELECT (SELECT sum(i) FROM governed_scan('orders')), (SELECT sum(i) FROM governed_scan('orders_second'))");
	INFO(ResultText(*r));
	REQUIRE_FALSE(r->HasError());
	REQUIRE(r->Collection().GetValue(0, 0).ToString() == EXPECTED_SUM);
	REQUIRE(r->Collection().GetValue(1, 0).ToString() == EXPECTED_SUM);
	auto os = f.Since(mark);
	INFO(MockS3DescribeObservations(os));
	REQUIRE(OnlyKeys(os, ORDERS_BUCKET, {ORDERS_KEY, ORDERS_SECOND_KEY}));
	auto files = GovernedHost::Get().Table("orders").files;
	REQUIRE(EveryFileFetchedWith(os, files, ORDERS_KEY));
	REQUIRE(EveryFileFetchedWith(os, files, ORDERS_SECOND_KEY));
	// Both scans performed I/O with their selected secret, even though ordinary per-query state may be shared.
	REQUIRE(alone_second > 0);
}

TEST_CASE("Two connections scanning tables at one location at once each read with their own credentials",
          "[httpfs][s3][file_credentials][file_credentials_r2][file_credentials_r4]") {
	SameLocationFixture f;
	Connection other(f.db);
	f.ConfigureUncached(other);
	f.CreateUserSecret(f.con);
	auto alone = f.RequestsAlone(f.con, "orders", ORDERS_KEY);
	auto alone_second = f.RequestsAlone(other, "orders_second", ORDERS_SECOND_KEY);
	constexpr idx_t RUNS = 5;
	auto mark = f.Mark();
	vector<unique_ptr<QueryResult>> results;
	vector<unique_ptr<QueryResult>> results_second;
	std::thread first([&]() {
		for (idx_t i = 0; i < RUNS; i++) {
			results.push_back(f.con.Query("SELECT count(*), sum(i) FROM governed_scan('orders')"));
		}
	});
	std::thread second([&]() {
		for (idx_t i = 0; i < RUNS; i++) {
			results_second.push_back(other.Query("SELECT count(*), sum(i) FROM governed_scan('orders_second')"));
		}
	});
	first.join();
	second.join();
	for (auto all : {&results, &results_second}) {
		for (auto &result : *all) {
			RequireOrdersResult(*result);
		}
	}
	auto os = f.Since(mark);
	INFO(MockS3DescribeObservations(os));
	// a read that took the other connection's credentials would fail; one that lost its own would use the user's key
	REQUIRE(OnlyKeys(os, ORDERS_BUCKET, {ORDERS_KEY, ORDERS_SECOND_KEY}));
	REQUIRE(Count(os, ORDERS_BUCKET, ORDERS_KEY, "", true) == alone * RUNS);
	REQUIRE(Count(os, ORDERS_BUCKET, ORDERS_SECOND_KEY, "", true) == alone_second * RUNS);
}

//===--------------------------------------------------------------------===//
// [file_credentials_r3] a read without the host's credentials behaves as today
//===--------------------------------------------------------------------===//

TEST_CASE("A path read selects its secret by path while table credentials are held",
          "[httpfs][s3][file_credentials][file_credentials_r3]") {
	Fixture f;
	f.CreateUserSecret(f.con);
	auto before = ResultText(*f.con.Query(
	    "SELECT name, type, provider, scope FROM duckdb_secrets() WHERE provider != 'governed_test' ORDER BY name"));
	auto which_before = ResultText(*f.con.Query("FROM which_secret('" + OrdersFile(0) + "', 's3')"));
	Fixture::Ok(f.con, "BEGIN TRANSACTION");
	RunGovernedScan(f);
	auto mark = f.Mark();
	auto r = f.con.Query("SELECT count(*) FROM read_parquet('" + UserFile() + "')");
	INFO(ResultText(*r));
	REQUIRE_FALSE(r->HasError());
	REQUIRE(r->Collection().GetValue(0, 0).ToString() == to_string(ROWS_PER_FILE));
	auto os = f.Since(mark);
	REQUIRE(OnlyKeys(os, USER_BUCKET, {USER_KEY}));
	REQUIRE(ResultText(*f.con.Query("SELECT name, type, provider, scope FROM duckdb_secrets() WHERE provider != "
	                                "'governed_test' ORDER BY name")) == before);
	REQUIRE(ResultText(*f.con.Query("FROM which_secret('" + OrdersFile(0) + "', 's3')")) == which_before);
}

//===--------------------------------------------------------------------===//
// Named secrets use the ordinary caches. Cache entries are keyed by path, not by the secret name.
//===--------------------------------------------------------------------===//

TEST_CASE("Named file reads use the normal external and Parquet caches", "[httpfs][s3][file_credentials]") {
	Fixture f;
	Fixture::Ok(f.con, "SET enable_external_file_cache=true");
	Fixture::Ok(f.con, "SET parquet_metadata_cache=true");
	Fixture::Ok(f.con, "SET validate_external_file_cache='NO_VALIDATION'");
	RunGovernedScan(f);
	auto entries = f.con.Query("SELECT count(*) FROM duckdb_external_file_cache() "
	                           "WHERE starts_with(path, 's3://governed-orders/')");
	REQUIRE_FALSE(entries->HasError());
	REQUIRE(entries->Collection().GetValue(0, 0).GetValue<idx_t>() > 0);
	for (auto &file : GovernedHost::Get().Table("orders").files) {
		REQUIRE(ObjectCache::GetObjectCache(*f.con.context).GetObject("parquet_metadata-" + file));
	}
	RunGovernedScan(f);
}

//===--------------------------------------------------------------------===//
// [file_credentials_r5] refresh
//===--------------------------------------------------------------------===//

namespace {
//! A server whose ORDERS_KEY is refused on range reads only, after the HEADs succeeded with it
MockS3ServerConfig MakeExpiringConfig() {
	auto config = MakeConfig();
	config.auth.stale_key_id = ORDERS_KEY;
	config.auth.refresh_target = MockS3RefreshTarget::RANGE_GET;
	return config;
}

//! Replace the user's secret for every S3 path with one that the refresh test provider created and can refresh,
//! so that a refresh by path is counted (S3TestHelper::AssertNoRefresh); returns the provider's test id. The
//! provider counts a creation with S3TestHelper's stale key id and a refresh with its fresh one.
string CreateRefreshableUserSecret(Fixture &f) {
	S3TestHelper::RegisterRefreshProvider(f.db);
	auto test_id = S3TestHelper::NextTestId();
	Fixture::Ok(f.con,
	            StringUtil::Format(
	                "CREATE OR REPLACE SECRET user_secret (TYPE s3, PROVIDER %s, SCOPE "
	                "['s3://governed-orders/orders/', 's3://governed-items/items/', 's3://user-bucket/'], KEY_ID '%s', "
	                "SECRET '%s', REGION 'eu-central-1', ENDPOINT '%s', URL_STYLE 'path', USE_SSL false, "
	                "TEST_ID '%s', REFRESH_INFO MAP {'KEY_ID': '%s', 'SECRET': '%s', 'TEST_ID': '%s'})",
	                S3TestHelper::TEST_PROVIDER, S3TestHelper::STALE_KEY_ID, S3TestHelper::STALE_SECRET,
	                f.server.Endpoint(), test_id, S3TestHelper::FRESH_KEY_ID, S3TestHelper::FRESH_SECRET, test_id));
	return test_id;
}
} // namespace

TEST_CASE("Credentials that expire during a scan are refreshed once",
          "[httpfs][s3][file_credentials][file_credentials_r5]") {
	Fixture f(MakeExpiringConfig());
	// the user's secret matches the table's paths and can refresh, so a refresh by path would be counted
	auto user_test_id = CreateRefreshableUserSecret(f);
	GovernedHost::Get().SetKeys("orders", {ORDERS_KEY, ORDERS_KEY_REFRESHED});
	Fixture::Ok(f.con, "SET threads=1");
	auto mark = f.Mark();
	auto r = f.con.Query("SELECT count(*), sum(i) FROM governed_scan('orders')");
	auto os = f.Since(mark);
	INFO(MockS3DescribeObservations(os));
	RequireOrdersResult(*r);
	REQUIRE(Count(os, ORDERS_BUCKET, ORDERS_KEY_REFRESHED, "GET", true) > 0);
	REQUIRE(OnlyKeys(os, ORDERS_BUCKET, {ORDERS_KEY, ORDERS_KEY_REFRESHED}));
	for (auto &observation : os) {
		REQUIRE(MockS3HeaderValues(observation, "X-Host-Key") == vector<string> {observation.key_id});
	}
	// one vend at bind, one refresh, however many reads were refused
	REQUIRE(GovernedHost::Get().Vends("orders") == 2);
	// the secret matched by path was not refreshed
	S3TestHelper::AssertNoRefresh(user_test_id);
}

TEST_CASE("Reads of two files refused at once refresh the table's credentials once",
          "[httpfs][s3][file_credentials][file_credentials_r5]") {
	Fixture f(MakeExpiringConfig());
	auto user_test_id = CreateRefreshableUserSecret(f);
	GovernedHost::Get().SetKeys("orders", {ORDERS_KEY, ORDERS_KEY_REFRESHED});
	// the refresh takes long enough that the second read is refused while the first one refreshes
	GovernedHost::Get().SetRefreshDelay("orders", 500);
	f.con.BeginTransaction();
	auto table_credentials = GovernedHost::Get().Attach(*f.con.context, "orders");
	// two files, so two handles with a request session each
	auto &fs = FileSystem::GetFileSystem(*f.con.context);
	vector<unique_ptr<FileHandle>> handles;
	for (idx_t i = 0; i < 2; i++) {
		OpenFileInfo file(OrdersFile(i));
		GovernedHost::Get().Apply(table_credentials, file);
		handles.push_back(fs.OpenFile(file, FileFlags::FILE_FLAGS_READ | FileFlags::FILE_FLAGS_DIRECT_IO));
	}
	auto mark = f.Mark();
	vector<string> errors(handles.size());
	vector<std::thread> readers;
	for (idx_t i = 0; i < handles.size(); i++) {
		readers.emplace_back([&, i]() {
			try {
				string buffer(1024, '\0');
				handles[i]->Read(QueryContext(*f.con.context), &buffer[0], buffer.size(), 0);
			} catch (std::exception &ex) {
				errors[i] = ex.what();
			}
		});
	}
	for (auto &reader : readers) {
		reader.join();
	}
	auto os = f.Since(mark);
	INFO(MockS3DescribeObservations(os));
	for (auto &error : errors) {
		INFO(error);
		REQUIRE(error.empty());
	}
	idx_t refused = 0;
	for (auto &o : os) {
		refused += o.key_id == ORDERS_KEY && o.status >= 400;
	}
	// each read is refused at least once before it is sent with the refreshed credentials
	REQUIRE(refused >= 2);
	REQUIRE(Count(os, ORDERS_BUCKET, ORDERS_KEY_REFRESHED, "GET", true) == 2);
	// one vend at bind and one refresh: the read that waited for the refresh used its result
	REQUIRE(GovernedHost::Get().Vends("orders") == 2);
	S3TestHelper::AssertNoRefresh(user_test_id);
	handles.clear();
	f.con.Rollback();
}

TEST_CASE("A scan whose refresh fails reads with no secret matched by path and fails",
          "[httpfs][s3][file_credentials][file_credentials_r5]") {
	Fixture f(MakeExpiringConfig());
	auto user_test_id = CreateRefreshableUserSecret(f);
	// the vend at bind succeeds; the provider fails when the secret manager calls it again to refresh
	GovernedHost::Get().SetKeys("orders", {ORDERS_KEY, ORDERS_KEY_REFRESHED});
	GovernedHost::Get().FailVendsAfter("orders", 1);
	Fixture::Ok(f.con, "SET threads=1");
	auto mark = f.Mark();
	auto r = f.con.Query("SELECT count(*), sum(i) FROM governed_scan('orders')");
	auto os = f.Since(mark);
	INFO(MockS3DescribeObservations(os));
	INFO(ResultText(*r));
	REQUIRE(r->HasError());
	REQUIRE(GovernedHost::Get().Vends("orders") == 2);
	REQUIRE(Count(os, ORDERS_BUCKET, ORDERS_KEY_REFRESHED) == 0);
	REQUIRE(OnlyKeys(os, ORDERS_BUCKET, {ORDERS_KEY}));
	S3TestHelper::AssertNoRefresh(user_test_id);
	RequireNoCredential(r->GetError());
}

TEST_CASE("Expired table credentials are not refreshed when credential refresh is off",
          "[httpfs][s3][file_credentials][file_credentials_r5]") {
	Fixture f(MakeExpiringConfig());
	auto user_test_id = CreateRefreshableUserSecret(f);
	GovernedHost::Get().SetKeys("orders", {ORDERS_KEY, ORDERS_KEY_REFRESHED});
	Fixture::Ok(f.con, "SET threads=1");
	Fixture::Ok(f.con, "SET httpfs_enable_credential_refresh=false");
	auto mark = f.Mark();
	auto r = f.con.Query("SELECT count(*), sum(i) FROM governed_scan('orders')");
	auto os = f.Since(mark);
	INFO(MockS3DescribeObservations(os));
	REQUIRE(r->HasError());
	REQUIRE(GovernedHost::Get().Vends("orders") == 1);
	REQUIRE(OnlyKeys(os, ORDERS_BUCKET, {ORDERS_KEY}));
	S3TestHelper::AssertNoRefresh(user_test_id);
}

//===--------------------------------------------------------------------===//
// [file_credentials_r6] every thread
//===--------------------------------------------------------------------===//

TEST_CASE("A parallel scan with prefetch and the file cache reads with the table's credentials",
          "[httpfs][s3][file_credentials][file_credentials_r6]") {
	Fixture f;
	f.CreateUserSecret(f.con);
	Fixture::Ok(f.con, "SET threads=8");
	Fixture::Ok(f.con, "SET enable_external_file_cache=true");
	Fixture::Ok(f.con, "SET prefetch_all_parquet_files=true");
	for (idx_t round = 0; round < 3; round++) {
		auto mark = f.Mark();
		RunGovernedScan(f);
		RequireOrdersResult(*f.con.Query("SELECT count(*), sum(i) FROM governed_files('orders')"));
		auto os = f.Since(mark);
		INFO(MockS3DescribeObservations(os));
		REQUIRE(OnlyKeys(os, ORDERS_BUCKET, {ORDERS_KEY}));
	}
}

//===--------------------------------------------------------------------===//
// Redacted output and errors omit credential material; names retain ordinary secret visibility.
//===--------------------------------------------------------------------===//

TEST_CASE("Redacted outputs and errors omit table credential material",
          "[httpfs][s3][file_credentials][file_credentials_r7]") {
	Fixture f;
	f.CreateUserSecret(f.con);
	Fixture::Ok(f.con, "SET enable_logging=true");
	Fixture::Ok(f.con, "SET logging_level='DEBUG'");
	vector<string> queries = {
	    "SELECT * FROM duckdb_secrets()",
	    "FROM which_secret('" + OrdersFile(0) + "', 's3')",
	    "EXPLAIN SELECT * FROM governed_scan('orders')",
	    "EXPLAIN ANALYZE SELECT * FROM governed_scan('orders')",
	    "SELECT DISTINCT filename FROM governed_scan('orders', filename=true)",
	    "SELECT * FROM governed_scan('nonexistent')",
	    "SELECT * FROM governed_scan('orders') WHERE i::VARCHAR::INT = 'x'",
	};
	for (auto &query : queries) {
		// each in a transaction that holds the table's credentials, and that a failing query does not abort
		// for the next one
		Fixture::Ok(f.con, "BEGIN TRANSACTION");
		RunGovernedScan(f);
		auto r = f.con.Query(query);
		INFO(query);
		auto text = ResultText(*r);
		REQUIRE_FALSE(StringUtil::Contains(text, "transaction is aborted"));
		RequireNoCredential(text);
		f.con.Query("ROLLBACK");
	}
}

// Fails in every build, with or without file credentials: with logging_level DEBUG the HTTP log records each
// request's headers. Hidden until the HTTP log type redacts them.
TEST_CASE("The log user SQL can read shows no table credentials", "[.][file_credentials_http_log]") {
	Fixture f;
	f.CreateUserSecret(f.con);
	Fixture::Ok(f.con, "SET enable_logging=true");
	Fixture::Ok(f.con, "SET logging_level='DEBUG'");
	RunGovernedScan(f);
	auto r = f.con.Query("SELECT message FROM duckdb_logs");
	REQUIRE_FALSE(r->HasError());
	REQUIRE(r->RowCount() > 0);
	RequireNoCredential(ResultText(*r));
}

TEST_CASE("A refused governed read reports no credentials", "[httpfs][s3][file_credentials][file_credentials_r7]") {
	auto config = MakeConfig();
	config.auth.bucket_key_ids[ORDERS_BUCKET] = {"AKIANOBODY0000000001"};
	Fixture f(config);
	f.CreateUserSecret(f.con);
	auto r = f.con.Query("SELECT count(*) FROM governed_scan('orders')");
	REQUIRE(r->HasError());
	RequireNoCredential(r->GetError());
}

//===--------------------------------------------------------------------===//
// A named secret overrides settings for keys it supplies; missing keys retain normal setting fallback.
//===--------------------------------------------------------------------===//

namespace {
constexpr const char *SETTING_KEY = "AKIASETTINGSKEY00001";
constexpr const char *SETTING_TOKEN = "SETTINGS-SESSION-TOKEN";
constexpr const char *SETTING_KMS_KEY = "arn:aws:kms:us-west-2:111122223333:key/settings";

//! Sets every S3 setting that could fill a key of the table's secret to a value other than the secret's,
//! with s3_endpoint naming `other_endpoint`, and sets the request options kms_key_id and
//! requester_pays
void SetConflictingSettings(Connection &con, const string &other_endpoint) {
	Fixture::Ok(con, "SET s3_endpoint='" + other_endpoint + "'");
	Fixture::Ok(con, "SET s3_use_ssl=true");
	Fixture::Ok(con, "SET s3_url_style='vhost'");
	Fixture::Ok(con, "SET s3_region='us-west-2'");
	Fixture::Ok(con, StringUtil::Format("SET s3_access_key_id='%s'", SETTING_KEY));
	Fixture::Ok(con, StringUtil::Format("SET s3_secret_access_key='%s%s'", SETTING_KEY, SECRET_SUFFIX));
	Fixture::Ok(con, StringUtil::Format("SET s3_session_token='%s'", SETTING_TOKEN));
	Fixture::Ok(con, StringUtil::Format("SET s3_kms_key_id='%s'", SETTING_KMS_KEY));
	Fixture::Ok(con, "SET s3_requester_pays=true");
}

string HeaderValue(const MockS3RequestObservation &o, const string &name) {
	for (auto &header : o.headers) {
		if (StringUtil::CIEquals(header.first, name)) {
			return header.second;
		}
	}
	return string();
}
} // namespace

TEST_CASE("Settings fill keys a named secret leaves unset",
          "[httpfs][s3][file_credentials][file_credentials_settings]") {
	Fixture f;
	MockS3Server other(MockS3ServerConfig {});
	SetConflictingSettings(f.con, other.Endpoint());
	Fixture::Ok(f.con, "SET s3_url_compatibility_mode=true");
	// the table's secret sets only its key id and secret, so every other key is left to the settings
	GovernedHost::Get().SetOmittedKeys({"region", "url_style", "use_ssl", "endpoint", "session_token"});
	f.con.BeginTransaction();
	auto table_credentials = GovernedHost::Get().Attach(*f.con.context, "orders");
	ClientContextFileOpener opener(*f.con.context);
	FileOpenerInfo info;
	info.file.path = OrdersFile(0);
	GovernedHost::Get().Apply(table_credentials, info);
	auto params = S3AuthResolver::Resolve(&opener, info);
	f.con.Rollback();

	auto &url = params.GetURLParams();
	INFO(url.endpoint.GetHost());
	REQUIRE(url.endpoint_mode == S3EndpointMode::EXPLICIT);
	REQUIRE(url.endpoint.GetAuthority() == other.Endpoint());
	REQUIRE(url.style == S3URLStyle::VIRTUAL_HOSTED);
	REQUIRE(url.compatibility_mode);
	REQUIRE(params.GetRefreshIdentity().use_ssl);
	auto &credentials = params.GetCredentials();
	REQUIRE(credentials.region == "us-west-2");
	REQUIRE(credentials.access_key_id == ORDERS_KEY);
	REQUIRE(credentials.secret_access_key == string(ORDERS_KEY) + SECRET_SUFFIX);
	REQUIRE(credentials.session_token == SETTING_TOKEN);
	auto &options = params.GetRequestOptions();
	REQUIRE(options.kms_key_id == SETTING_KMS_KEY);
	REQUIRE(options.requester_pays);
	REQUIRE(other.Observations().empty());
}

TEST_CASE("Settings supply credential fields a named secret leaves unset",
          "[httpfs][s3][file_credentials][file_credentials_settings]") {
	Fixture f;
	SetConflictingSettings(f.con, f.server.Endpoint());
	GovernedHost::Get().SetOmittedKeys({"key_id", "secret", "session_token"});
	f.con.BeginTransaction();
	auto table_credentials = GovernedHost::Get().Attach(*f.con.context, "orders");
	ClientContextFileOpener opener(*f.con.context);
	FileOpenerInfo info;
	info.file.path = OrdersFile(0);
	GovernedHost::Get().Apply(table_credentials, info);
	auto params = S3AuthResolver::Resolve(&opener, info);
	f.con.Rollback();
	auto &credentials = params.GetCredentials();
	REQUIRE(credentials.access_key_id == SETTING_KEY);
	REQUIRE(credentials.secret_access_key == string(SETTING_KEY) + SECRET_SUFFIX);
	REQUIRE(credentials.session_token == SETTING_TOKEN);
	REQUIRE(credentials.region == "eu-central-1");
}

TEST_CASE("A governed scan is sent to its secret's endpoint and signed with its key whatever the settings",
          "[httpfs][s3][file_credentials][file_credentials_settings]") {
	Fixture f;
	MockS3Server other(MockS3ServerConfig {});
	f.CreateUserSecret(f.con);
	SetConflictingSettings(f.con, other.Endpoint());
	// the table's secret leaves its region and session token to the settings
	GovernedHost::Get().SetOmittedKeys({"region", "session_token"});
	auto mark = f.Mark();
	RunGovernedScan(f);
	auto os = f.Since(mark);
	INFO(MockS3DescribeObservations(os));
	REQUIRE(other.Observations().empty());
	REQUIRE(Count(os, ORDERS_BUCKET, ORDERS_KEY, "GET", true) > 0);
	REQUIRE(OnlyKeys(os, ORDERS_BUCKET, {ORDERS_KEY}));
	for (auto &o : os) {
		INFO(o.path);
		REQUIRE(o.region == "us-west-2");
		REQUIRE(HeaderValue(o, "x-amz-security-token") == SETTING_TOKEN);
		REQUIRE(HeaderValue(o, "x-amz-request-payer") == "requester");
	}
}

namespace {
//! The request settings the resolver gives a request for `path` signed with fresh credentials of `table`
//! whose scope is `scope`
S3AuthParams ResolveWithHandle(Fixture &f, const string &table, const string &scope, const string &path) {
	f.con.BeginTransaction();
	auto table_credentials = GovernedHost::Get().AttachWithScope(*f.con.context, table, scope);
	ClientContextFileOpener opener(*f.con.context);
	FileOpenerInfo info;
	info.file.path = path;
	GovernedHost::Get().Apply(table_credentials, info);
	auto params = S3AuthResolver::Resolve(&opener, info);
	f.con.Rollback();
	return params;
}
} // namespace

TEST_CASE("gcs_user_project fills the user project a named secret leaves unset",
          "[httpfs][s3][file_credentials][file_credentials_settings]") {
	Fixture f;
	Fixture::Ok(f.con, "SET gcs_user_project='settings-project'");
	auto path = StringUtil::Format("gs://%s/orders/part-0.parquet", ORDERS_BUCKET);
	auto params = ResolveWithHandle(f, "orders", StringUtil::Format("gs://%s/orders/", ORDERS_BUCKET), path);
	REQUIRE(params.GetProvider().GetType() == S3ProviderType::GCS);
	REQUIRE(params.GetRequestOptions().user_project == "settings-project");
	REQUIRE(params.GetCredentials().access_key_id == ORDERS_KEY);
}

TEST_CASE("A request with credentials and no file opener fails",
          "[httpfs][s3][file_credentials][file_credentials_attack]") {
	Fixture f;
	f.con.BeginTransaction();
	auto table_credentials = GovernedHost::Get().Attach(*f.con.context, "orders");
	FileOpenerInfo info;
	info.file.path = OrdersFile(0);
	GovernedHost::Get().Apply(table_credentials, info);
	string error;
	try {
		S3AuthResolver::Resolve(nullptr, info);
	} catch (InvalidConfigurationException &ex) {
		error = ex.what();
	}
	INFO(error);
	REQUIRE(StringUtil::Contains(error, "without a file opener"));
	// the same call without them resolves, with no credentials
	FileOpenerInfo plain;
	plain.file.path = OrdersFile(0);
	REQUIRE(S3AuthResolver::Resolve(nullptr, plain).GetCredentials().access_key_id.empty());
	f.con.Rollback();
}

//===--------------------------------------------------------------------===//
// Transaction secrets also participate in ordinary scope matching.
//===--------------------------------------------------------------------===//

TEST_CASE("A transaction secret with the table's scope is used by a path read",
          "[httpfs][s3][file_credentials][file_credentials_existing]") {
	Fixture f;
	f.CreateUserSecret(f.con);
	Fixture::Ok(f.con, "BEGIN TRANSACTION");
	auto &host = GovernedHost::Get();
	auto scope = OrdersFile(0);
	auto secret = host.MakeSecret({scope}, Identifier("config"), Identifier("table_secret"), ORDERS_KEY);
	auto transaction = CatalogTransaction::GetSystemCatalogTransaction(*f.con.context);
	SecretManager::Get(*f.con.context)
	    .RegisterSecret(transaction, std::move(secret), OnCreateConflict::ERROR_ON_CONFLICT,
	                    SecretPersistType::TRANSACTION);
	auto mark = f.Mark();
	auto r = f.con.Query("SELECT count(*) FROM read_parquet('" + OrdersFile(0) + "')");
	INFO(ResultText(*r));
	REQUIRE_FALSE(r->HasError());
	REQUIRE(Count(f.Since(mark), ORDERS_BUCKET, ORDERS_KEY, "GET", true) > 0);
	auto listed = f.con.Query("SELECT count(*) FROM duckdb_secrets() WHERE name = 'table_secret'");
	REQUIRE(listed->Collection().GetValue(0, 0).ToString() == "1");
	f.con.Query("ROLLBACK");
}

//===--------------------------------------------------------------------===//
// [file_credentials_attack] the credentials themselves
//===--------------------------------------------------------------------===//

TEST_CASE("SQL file structs select an ordinary named transaction secret", "[httpfs][s3][file_credentials]") {
	Fixture f;
	f.CreateUserSecret(f.con);
	f.con.BeginTransaction();
	auto name = GovernedHost::Get().Attach(*f.con.context, "orders");
	auto entry = GetNamedSecret(*f.con.context, name);
	REQUIRE(entry);
	REQUIRE(entry->persist_type == SecretPersistType::TRANSACTION);
	auto listed = f.con.Query("SELECT secret_string FROM duckdb_secrets() WHERE name='" + name + "'");
	REQUIRE_FALSE(listed->HasError());
	REQUIRE(listed->RowCount() == 1);
	RequireNoCredential(ResultText(*listed));
	REQUIRE(entry->secret->Cast<KeyValueSecret>().TryGetValue("key_id").ToString() == ORDERS_KEY);
	auto mark = f.Mark();
	auto result = f.con.Query(StringUtil::Format(
	    "SELECT count(*) FROM read_parquet([{'filename': '%s', 'secret': '%s'}])", OrdersFile(0), name));
	REQUIRE_FALSE(result->HasError());
	REQUIRE(result->Collection().GetValue(0, 0).GetValue<idx_t>() == ROWS_PER_FILE);
	REQUIRE(Count(f.Since(mark), ORDERS_BUCKET, ORDERS_KEY, "GET", true) > 0);
	Fixture::Ok(f.con, "DROP SECRET " + name);
	REQUIRE_FALSE(GetNamedSecret(*f.con.context, name));
	OpenFileInfo file(OrdersFile(0));
	GovernedHost::Get().Apply(name, file);
	mark = f.Mark();
	REQUIRE_THROWS_WITH(FileSystem::GetFileSystem(*f.con.context).OpenFile(file, FileFlags::FILE_FLAGS_READ),
	                    Catch::Contains("not found"));
	REQUIRE(f.Since(mark).empty());
}

TEST_CASE("A named secret with the wrong scope or type fails before sending a request",
          "[httpfs][s3][file_credentials]") {
	Fixture f;
	f.CreateUserSecret(f.con);
	Fixture::Ok(f.con, "CREATE SECRET wrong_type (TYPE http, SCOPE 's3://')");
	f.con.BeginTransaction();
	auto wrong_scope = GovernedHost::Get().Attach(*f.con.context, "items");
	for (auto &name : {wrong_scope, string("wrong_type"), string("missing_secret")}) {
		OpenFileInfo file(OrdersFile(0));
		GovernedHost::Get().Apply(name, file);
		auto mark = f.Mark();
		REQUIRE_THROWS(FileSystem::GetFileSystem(*f.con.context).OpenFile(file, FileFlags::FILE_FLAGS_READ));
		REQUIRE(f.Since(mark).empty());
	}
}

TEST_CASE("The table's credentials serve only the transaction that loaded the table",
          "[httpfs][s3][file_credentials][file_credentials_attack]") {
	Fixture f;
	f.CreateUserSecret(f.con);
	Connection other(f.db);
	f.Configure(other);
	string outcome;
	SECTION("commit") {
		outcome = "COMMIT";
	}
	SECTION("rollback") {
		outcome = "ROLLBACK";
	}
	SECTION("error") {
		outcome = "SELECT error('a failing statement')";
	}
	Fixture::Ok(f.con, "BEGIN TRANSACTION");
	RunGovernedScan(f);
	auto table_credentials = GovernedHost::Get().Attachments()[0];
	// Another connection, explicitly given the same secret name.
	other.BeginTransaction();
	{
		ClientContextFileOpener opener(*other.context);
		REQUIRE_FALSE(GetNamedSecret(*other.context, table_credentials));
		FileOpenerInfo info;
		info.file.path = OrdersFile(0);
		GovernedHost::Get().Apply(table_credentials, info);
		REQUIRE_THROWS(S3AuthResolver::Resolve(&opener, info));
		OpenFileInfo file(OrdersFile(0));
		GovernedHost::Get().Apply(table_credentials, file);
		REQUIRE_THROWS(FileSystem::GetFileSystem(*other.context).OpenFile(file, FileFlags::FILE_FLAGS_READ));
	}
	other.Rollback();
	f.con.Query(outcome);
	if (f.con.context->transaction.HasActiveTransaction()) {
		f.con.Query("ROLLBACK");
	}
	f.con.BeginTransaction();
	REQUIRE_FALSE(GetNamedSecret(*f.con.context, table_credentials));
	OpenFileInfo file(OrdersFile(0));
	GovernedHost::Get().Apply(table_credentials, file);
	REQUIRE_THROWS(FileSystem::GetFileSystem(*f.con.context).OpenFile(file, FileFlags::FILE_FLAGS_READ));
	f.con.Rollback();
}

TEST_CASE("An autocommit governed scan's credentials end with it",
          "[httpfs][s3][file_credentials][file_credentials_attack]") {
	Fixture f;
	f.CreateUserSecret(f.con);
	RunGovernedScan(f);
	auto table_credentials = GovernedHost::Get().Attachments()[0];
	f.con.BeginTransaction();
	REQUIRE_FALSE(GetNamedSecret(*f.con.context, table_credentials));
}

TEST_CASE("Transaction secrets cannot be created through SQL", "[httpfs][s3][file_credentials]") {
	Fixture f;
	auto result = f.con.Query("CREATE SECRET minted IN transaction (TYPE s3)");
	REQUIRE(result->HasError());
	REQUIRE(StringUtil::Contains(result->GetError(), "Transaction-scoped secrets cannot be created through SQL"));
}

TEST_CASE("The table's credentials are used only for paths under its scope",
          "[httpfs][s3][file_credentials][file_credentials_attack]") {
	Fixture f;
	f.CreateUserSecret(f.con);
	Fixture::Ok(f.con, "BEGIN TRANSACTION");
	RunGovernedScan(f);
	auto table_credentials = GovernedHost::Get().Attachments()[0];
	// A manifest must not use this secret for a path outside its scope.
	for (auto &path : {ItemsFile(0), UserFile()}) {
		INFO(path);
		OpenFileInfo file(path);
		GovernedHost::Get().Apply(table_credentials, file);
		auto mark = f.Mark();
		REQUIRE_THROWS(FileSystem::GetFileSystem(*f.con.context).OpenFile(file, FileFlags::FILE_FLAGS_READ));
		REQUIRE(CountKey(f.Since(mark), ORDERS_KEY) == 0);
	}
	f.con.Query("ROLLBACK");
}

} // namespace duckdb
