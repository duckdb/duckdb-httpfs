// The host of a governed table: it vends the table's credentials into a FileCredentials object and puts that
// object on the glob input and the files of that table's scans. The same file builds against a core without file
// credentials, where the host has no way to attach them, its scans read with the secret matched to the path, and
// the cases that need the host's credentials fail.
//
// The host is played by this file: a table function per table, read_parquet with a multi-file reader that resolves the
// table to its location and attaches the credentials at bind, as a catalog extension does. The mock S3 server
// answers each governed bucket only for that table's key id.
//
// Each case is tagged with the requirement it checks:
//   [file_credentials_r1]  every read of the table's scans uses the host's credentials;
//   [file_credentials_r2]  no other read uses them (a read by path, a function in the same query, another table,
//                          another connection);
//   [file_credentials_r3]  reads without them select their secret by path, as before;
//   [file_credentials_r4]  caches do not serve data or metadata from one side to the other;
//   [file_credentials_r5]  credentials that expire during a scan are refreshed;
//   [file_credentials_r6]  the credentials reach I/O on every thread;
//   [file_credentials_r7]  nothing user SQL can read shows the credentials;
//   [file_credentials_settings]  settings do not change where a request with them goes or how it is signed;
//   [file_credentials_attack]    the credentials themselves: what SQL can reach, and where they can be used;
//   [file_credentials_existing]  why an existing mechanism, a transaction secret, does not do.

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

#if __has_include("duckdb/main/secret/file_credentials.hpp")
#define HAS_FILE_CREDENTIALS 1
#include "duckdb/main/secret/file_credentials.hpp"
#endif

namespace duckdb {

//! As parquet_extension.hpp and core_functions_extension.hpp declare them; the Brazil build does not publish those
//! headers
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

//! The Brazil build links Parquet and the core functions as static extensions that a new database does not load by
//! itself
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
	string glob;
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

#ifdef HAS_FILE_CREDENTIALS
using Attachment = shared_ptr<FileCredentials>;
#else
struct Attachment {};
#endif

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
		orders.glob = StringUtil::Format("s3://%s/orders/*.parquet", ORDERS_BUCKET);
		orders.scope = StringUtil::Format("s3://%s/orders/", ORDERS_BUCKET);
		GovernedTable items;
		items.glob = StringUtil::Format("s3://%s/items/*.parquet", ITEMS_BUCKET);
		items.scope = StringUtil::Format("s3://%s/items/", ITEMS_BUCKET);
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
		secret->redact_keys.insert("secret");
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
#ifdef HAS_FILE_CREDENTIALS
		if (!file.extended_info) {
			file.extended_info = make_shared_ptr<ExtendedOpenFileInfo>();
		}
		file.extended_info->credentials = attachment;
#endif
	}
	void Apply(const Attachment &attachment, FileGlobInput &input) {
#ifdef HAS_FILE_CREDENTIALS
		input.credentials = attachment;
#endif
	}
	void Apply(const Attachment &attachment, FileOpenerInfo &info) {
#ifdef HAS_FILE_CREDENTIALS
		info.credentials = attachment;
#endif
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

#ifdef HAS_FILE_CREDENTIALS
Attachment GovernedHost::Attach(ClientContext &context, const string &table) {
	return AttachWithScope(context, table, Table(table).scope);
}

Attachment GovernedHost::AttachWithScope(ClientContext &context, const string &table, const string &scope) {
	auto credentials = FileCredentials::Create(context, scope, [table, scope](ClientContext &) {
		auto &host = GovernedHost::Get();
		shared_ptr<const KeyValueSecret> secret =
		    host.MakeSecret({scope}, Identifier(HOST_NAME), Identifier(), host.Vend(table));
		return secret;
	});
	lock_guard<mutex> guard(lock);
	attachments.push_back(credentials);
	return credentials;
}
#else
Attachment GovernedHost::Attach(ClientContext &context, const string &table) {
	return Attachment();
}
Attachment GovernedHost::AttachWithScope(ClientContext &context, const string &table, const string &scope) {
	return Attachment();
}
#endif

//! read_parquet's multi-file reader, with the table name as its argument: the reader resolves the table to its
//! location and attaches the host's credentials to the glob (governed_scan) or to each file of the table's file
//! list, as a table format's manifest would list them (governed_files)
template <bool EXPLICIT_FILES>
struct GovernedMultiFileReader : public MultiFileReader {
	shared_ptr<MultiFileList> CreateFileList(ClientContext &context, vector<OpenFileInfo> files,
	                                         const FileGlobInput &glob_input) override {
		REQUIRE(files.size() == 1);
		auto &host = GovernedHost::Get();
		auto table_name = files[0].path;
		auto table = host.Table(table_name);
		auto attachment = host.Attach(context, table_name);
		if (EXPLICIT_FILES) {
			vector<OpenFileInfo> list;
			for (auto &path : table.files) {
				OpenFileInfo file(path);
				host.Apply(attachment, file);
				list.push_back(std::move(file));
			}
			return MultiFileReader::CreateFileList(context, std::move(list), glob_input);
		}
		auto input = glob_input;
		host.Apply(attachment, input);
		return MultiFileReader::CreateFileList(context, vector<string> {table.glob}, input);
	}
	unique_ptr<MultiFileReader> Copy() const override {
		return make_uniq<GovernedMultiFileReader<EXPLICIT_FILES>>();
	}
	static unique_ptr<MultiFileReader> Create(const BoundTableFunction &) {
		return make_uniq<GovernedMultiFileReader<EXPLICIT_FILES>>();
	}
};

void RegisterHost(DuckDB &db, Connection &con) {
	ExtensionInfo extension_info;
	ExtensionActiveLoad load_info(*db.instance, extension_info, "file_credentials_host_test", "");
	ExtensionLoader loader(load_info);
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
	scan.get_multi_file_reader = GovernedMultiFileReader<false>::Create;
	loader.RegisterFunction(scan);
	auto files = read_parquet;
	files.name = "governed_files";
	files.get_multi_file_reader = GovernedMultiFileReader<true>::Create;
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
		// every S3 read goes to the mock server: the connection's secret for every S3 path names it, and has no
		// key until a test creates the user's own secret (CreateUserSecret)
		Ok(c, StringUtil::Format("CREATE OR REPLACE SECRET user_secret (TYPE s3, SCOPE 's3://', REGION 'eu-central-1', "
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
		Ok(c, StringUtil::Format(
		          "CREATE OR REPLACE SECRET user_secret (TYPE s3, SCOPE 's3://', KEY_ID '%s', SECRET '%s%s', "
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

TEST_CASE("A governed scan lists, opens and reads with the table's credentials",
          "[httpfs][s3][file_credentials][file_credentials_r1]") {
	Fixture f;
	f.CreateUserSecret(f.con);
	SECTION("glob over the table location") {
		auto mark = f.Mark();
		auto result = f.con.Query("SELECT count(*), sum(i) FROM governed_scan('orders')");
		RequireOrdersResult(*result);
		auto os = f.Since(mark);
		INFO(MockS3DescribeObservations(os));
		// the listing, the HEAD of each file, the footer and the column chunks
		REQUIRE(Count(os, ORDERS_BUCKET, ORDERS_KEY, "GET", true) >= FILES_PER_TABLE * 2 + 1);
		REQUIRE(OnlyKeys(os, ORDERS_BUCKET, {ORDERS_KEY}));
	}
	SECTION("file list with open information, as a table format's manifest gives it") {
		auto mark = f.Mark();
		auto result = f.con.Query("SELECT count(*), sum(i) FROM governed_files('orders')");
		RequireOrdersResult(*result);
		auto os = f.Since(mark);
		INFO(MockS3DescribeObservations(os));
		REQUIRE(OnlyKeys(os, ORDERS_BUCKET, {ORDERS_KEY}));
	}
	SECTION("schema inference at bind") {
		auto mark = f.Mark();
		auto result = f.con.Query("DESCRIBE SELECT * FROM governed_scan('orders')");
		INFO(ResultText(*result));
		REQUIRE_FALSE(result->HasError());
		REQUIRE(result->RowCount() == 2);
		auto os = f.Since(mark);
		REQUIRE(Count(os, ORDERS_BUCKET, ORDERS_KEY, "", true) > 0);
		REQUIRE(OnlyKeys(os, ORDERS_BUCKET, {ORDERS_KEY}));
	}
}

TEST_CASE("A prepared governed scan runs in a later transaction",
          "[httpfs][s3][file_credentials][file_credentials_r1]") {
	Fixture f;
	f.CreateUserSecret(f.con);
	// prepared in one transaction, run in two others
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
// [file_credentials_r2] no other read can use them
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

TEST_CASE("A function in the same query as a governed scan does not read with its credentials",
          "[httpfs][s3][file_credentials][file_credentials_r2]") {
	Fixture f;
	f.CreateUserSecret(f.con);
	// the governed scan alone reads the table, so a failure below is the path read's
	RunGovernedScan(f);
	vector<string> queries = {
	    "SELECT (SELECT count(*) FROM governed_scan('orders')), (SELECT count(*) FROM read_blob('" + OrdersFile(0) +
	        "'))",
	    "SELECT count(*) FROM governed_scan('orders') g, read_parquet('" + OrdersFile(1) + "') p WHERE g.i = p.i",
	    "SELECT count(*) FROM governed_scan('orders') WHERE s IN (SELECT content FROM read_text('" + OrdersFile(2) +
	        "'))",
	    "SELECT (SELECT count(*) FROM governed_scan('orders')), (SELECT sum(octet_length(content)) FROM read_blob('" +
	        OrdersFile(0) + "'))",
	};
	for (auto &query : queries) {
		auto mark = f.Mark();
		auto r = f.con.Query(query);
		INFO(query);
		INFO(ResultText(*r));
		auto os = f.Since(mark);
		INFO(MockS3DescribeObservations(os));
		// the path read is refused by the bucket: the user's credential is the only one it was given. A
		// read_blob of one path whose HEAD is refused finds no file, so the query succeeds with a count of 0
		REQUIRE(Count(os, ORDERS_BUCKET, USER_KEY) > 0);
		if (!r->HasError()) {
			auto count = r->Collection().GetValue(r->ColumnCount() - 1, 0).ToString();
			REQUIRE(count == "0");
		}
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

//===--------------------------------------------------------------------===//
// [file_credentials_r3] a read without the host's credentials behaves as today
//===--------------------------------------------------------------------===//

TEST_CASE("A path read selects its secret by path while table credentials are held",
          "[httpfs][s3][file_credentials][file_credentials_r3]") {
	Fixture f;
	f.CreateUserSecret(f.con);
	auto before = ResultText(*f.con.Query("SELECT name, type, provider, scope FROM duckdb_secrets() ORDER BY name"));
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
	REQUIRE(ResultText(*f.con.Query("SELECT name, type, provider, scope FROM duckdb_secrets() ORDER BY name")) ==
	        before);
	REQUIRE(ResultText(*f.con.Query("FROM which_secret('" + OrdersFile(0) + "', 's3')")) == which_before);
}

//===--------------------------------------------------------------------===//
// [file_credentials_r4] caches keep the two apart
//===--------------------------------------------------------------------===//

TEST_CASE("A path read is not served what a governed scan cached",
          "[httpfs][s3][file_credentials][file_credentials_r4]") {
	Fixture f;
	f.CreateUserSecret(f.con);
	string setting;
	SECTION("external file cache") {
		setting = "enable_external_file_cache";
	}
	SECTION("Parquet metadata cache") {
		setting = "parquet_metadata_cache";
	}
	SECTION("HTTP metadata cache") {
		setting = "enable_http_metadata_cache";
	}
	SECTION("every cache, with no validation of the external file cache") {
		setting = "enable_external_file_cache";
		Fixture::Ok(f.con, "SET parquet_metadata_cache=true");
		Fixture::Ok(f.con, "SET enable_http_metadata_cache=true");
		Fixture::Ok(f.con, "SET validate_external_file_cache='NO_VALIDATION'");
	}
	Fixture::Ok(f.con, "SET " + setting + "=true");
	Fixture::Ok(f.con, "BEGIN TRANSACTION");
	RunGovernedScan(f);
	for (auto &query : {"SELECT count(*) FROM read_parquet('" + OrdersFile(0) + "')",
	                    "SELECT count(*) FROM parquet_metadata('" + OrdersFile(0) + "')",
	                    "SELECT count(*) FROM read_blob('" + OrdersFile(0) + "')",
	                    "SELECT sum(octet_length(content)) FROM read_blob('" + OrdersFile(0) + "')",
	                    "SELECT sum(size) FROM read_blob('" + OrdersFile(0) + "')",
	                    "SELECT count(last_modified) FROM read_blob('" + OrdersFile(0) + "')"}) {
		auto r = f.con.Query(query);
		INFO(setting);
		INFO(query);
		INFO(ResultText(*r));
		REQUIRE(GotNothing(*r));
		Fixture::Ok(f.con, "ROLLBACK");
		Fixture::Ok(f.con, "BEGIN TRANSACTION");
		RunGovernedScan(f);
	}
}

//! Whether the external file cache holds blocks of a file under `prefix`, and whether the Parquet metadata cache holds
//! the footer of `file`
idx_t ExternalFileCacheEntries(Connection &con, const string &prefix) {
	auto r = con.Query("SELECT count(*) FROM duckdb_external_file_cache() WHERE starts_with(path, '" + prefix + "')");
	INFO(ResultText(*r));
	REQUIRE_FALSE(r->HasError());
	return r->Collection().GetValue(0, 0).GetValue<idx_t>();
}
bool HasParquetMetadataEntry(Connection &con, const string &file) {
	// the key ObjectCache::PutWithTypePrefix<ParquetFileMetadataCache> builds for the file
	return ObjectCache::GetObjectCache(*con.context).GetObject("parquet_metadata-" + file) != nullptr;
}

TEST_CASE("A governed scan leaves nothing in the caches under its paths",
          "[httpfs][s3][file_credentials][file_credentials_r4]") {
	Fixture f;
	f.CreateUserSecret(f.con);
	Fixture::Ok(f.con, "SET enable_external_file_cache=true");
	Fixture::Ok(f.con, "SET parquet_metadata_cache=true");
	Fixture::Ok(f.con, "SET validate_external_file_cache='NO_VALIDATION'");
	// a path read of the user's own file fills both caches, so the checks below can see an entry
	Fixture::Ok(f.con, "SELECT sum(i) FROM read_parquet('" + UserFile() + "')");
	REQUIRE(ExternalFileCacheEntries(f.con, "s3://" + string(USER_BUCKET) + "/") > 0);
	REQUIRE(HasParquetMetadataEntry(f.con, UserFile()));

	Fixture::Ok(f.con, "BEGIN TRANSACTION");
	RunGovernedScan(f);
	RequireOrdersResult(*f.con.Query("SELECT count(*), sum(i) FROM governed_files('orders')"));
	REQUIRE(ExternalFileCacheEntries(f.con, "s3://" + string(ORDERS_BUCKET) + "/") == 0);
	for (auto &file : GovernedHost::Get().Table("orders").files) {
		INFO(file);
		REQUIRE_FALSE(HasParquetMetadataEntry(f.con, file));
	}
	Fixture::Ok(f.con, "COMMIT");
	REQUIRE(ExternalFileCacheEntries(f.con, "s3://" + string(ORDERS_BUCKET) + "/") == 0);
}

TEST_CASE("A governed scan is not served what a path read cached",
          "[httpfs][s3][file_credentials][file_credentials_r4]") {
	auto config = MakeConfig();
	// in this test the user's own credential may also read the table's bucket
	config.auth.bucket_key_ids[ORDERS_BUCKET].push_back(USER_KEY);
	Fixture f(config);
	f.CreateUserSecret(f.con);
	Fixture::Ok(f.con, "SET enable_external_file_cache=true");
	Fixture::Ok(f.con, "SET parquet_metadata_cache=true");
	Fixture::Ok(f.con, "SET enable_http_metadata_cache=true");
	Fixture::Ok(f.con, "SELECT sum(i) FROM read_parquet('s3://" + string(ORDERS_BUCKET) + "/orders/*.parquet')");
	auto mark = f.Mark();
	RunGovernedScan(f);
	auto os = f.Since(mark);
	INFO(MockS3DescribeObservations(os));
	// every file was fetched again with the table's credentials
	REQUIRE(EveryFileFetchedWith(os, GovernedHost::Get().Table("orders").files, ORDERS_KEY));
	REQUIRE(OnlyKeys(os, ORDERS_BUCKET, {ORDERS_KEY}));
}

namespace {
//! A server whose single object (MockS3Server::S3Path) reports one ETag on HEAD and another on GET, so that a read
//! of it finds the object changed after it was opened
MockS3ServerConfig MakeChangedObjectConfig(bool enforce_if_match) {
	auto config = MakeConfig();
	// larger than force_download_threshold, so that a read is a range GET checked against the HEAD's ETag
	config.object.data = string(4 * 1024 * 1024, 'x');
	config.metadata.etag = "\"opened-etag\"";
	config.metadata.get_etag = "\"changed-etag\"";
	config.metadata.enforce_if_match = enforce_if_match;
	return config;
}

idx_t HeadCount(const vector<MockS3RequestObservation> &os) {
	idx_t n = 0;
	for (auto &o : os) {
		n += o.method == "HEAD";
	}
	return n;
}

//! Open `file` and read a range of it; the error, or empty when the read succeeded
string OpenAndRead(Connection &con, const OpenFileInfo &file) {
	auto &fs = FileSystem::GetFileSystem(*con.context);
	try {
		auto handle = fs.OpenFile(file, FileFlags::FILE_FLAGS_READ | FileFlags::FILE_FLAGS_DIRECT_IO);
		string buffer(1024, '\0');
		handle->Read(QueryContext(*con.context), &buffer[0], buffer.size(), 0);
	} catch (std::exception &ex) {
		return ex.what();
	}
	return string();
}

//! Open `path` without reading it; returns the HEADs the open sent
idx_t OpenPathHeads(Fixture &f, const string &path) {
	auto mark = f.Mark();
	FileSystem::GetFileSystem(*f.con.context)
	    .OpenFile(path, FileFlags::FILE_FLAGS_READ | FileFlags::FILE_FLAGS_DIRECT_IO);
	return HeadCount(f.Since(mark));
}
} // namespace

//===--------------------------------------------------------------------===//
// [file_credentials_r5] refresh
//===--------------------------------------------------------------------===//

namespace {
//! A server whose ORDERS_KEY is refused on range reads only, after the listing and the HEADs succeeded with it
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
	                "CREATE OR REPLACE SECRET user_secret (TYPE s3, PROVIDER %s, SCOPE 's3://', KEY_ID '%s', "
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
// [file_credentials_r7] nothing user SQL can read shows the credentials or a reference to them
//===--------------------------------------------------------------------===//

TEST_CASE("Outputs user SQL can read show no table credentials",
          "[httpfs][s3][file_credentials][file_credentials_r7]") {
	Fixture f;
	f.CreateUserSecret(f.con);
	Fixture::Ok(f.con, "SET enable_logging=true");
	Fixture::Ok(f.con, "SET logging_level='DEBUG'");
	vector<string> queries = {
	    "SELECT * FROM duckdb_secrets()",
	    "SELECT * FROM duckdb_secrets(redact=false)",
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
// [file_credentials_settings] settings do not change where a request with credentials goes or how it is signed
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

TEST_CASE("No setting fills a key the table's credentials leave unset",
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
	info.file_path = OrdersFile(0);
	info.credentials = table_credentials;
	auto params = S3AuthResolver::Resolve(&opener, info);
	f.con.Rollback();

	auto &url = params.GetURLParams();
	INFO(url.endpoint.GetHost());
	REQUIRE(url.endpoint_mode == S3EndpointMode::AUTOMATIC);
	REQUIRE(url.endpoint.GetHost() == "s3.us-east-1.amazonaws.com");
	REQUIRE(url.style == S3URLStyle::VIRTUAL_HOSTED);
	REQUIRE_FALSE(url.compatibility_mode);
	REQUIRE(params.GetRefreshIdentity().use_ssl);
	auto &credentials = params.GetCredentials();
	REQUIRE(credentials.region == "us-east-1");
	REQUIRE(credentials.access_key_id == ORDERS_KEY);
	REQUIRE(credentials.secret_access_key == string(ORDERS_KEY) + SECRET_SUFFIX);
	REQUIRE(credentials.session_token.empty());
	auto &options = params.GetRequestOptions();
	REQUIRE(options.kms_key_id.empty());
	REQUIRE_FALSE(options.requester_pays);
	REQUIRE(other.Observations().empty());
}

TEST_CASE("Settings do not supply credentials the table's credentials leave unset",
          "[httpfs][s3][file_credentials][file_credentials_settings]") {
	Fixture f;
	SetConflictingSettings(f.con, f.server.Endpoint());
	GovernedHost::Get().SetOmittedKeys({"key_id", "secret", "session_token"});
	f.con.BeginTransaction();
	auto table_credentials = GovernedHost::Get().Attach(*f.con.context, "orders");
	ClientContextFileOpener opener(*f.con.context);
	FileOpenerInfo info;
	info.file_path = OrdersFile(0);
	info.credentials = table_credentials;
	auto params = S3AuthResolver::Resolve(&opener, info);
	f.con.Rollback();
	auto &credentials = params.GetCredentials();
	REQUIRE(credentials.access_key_id.empty());
	REQUIRE(credentials.secret_access_key.empty());
	REQUIRE(credentials.session_token.empty());
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
		REQUIRE(o.region != "us-west-2");
		REQUIRE(HeaderValue(o, "x-amz-security-token").empty());
		REQUIRE(HeaderValue(o, "x-amz-request-payer").empty());
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
	info.file_path = path;
	info.credentials = table_credentials;
	auto params = S3AuthResolver::Resolve(&opener, info);
	f.con.Rollback();
	return params;
}
} // namespace

TEST_CASE("gcs_user_project does not fill the user project the table's credentials leave unset",
          "[httpfs][s3][file_credentials][file_credentials_settings]") {
	Fixture f;
	Fixture::Ok(f.con, "SET gcs_user_project='settings-project'");
	auto path = StringUtil::Format("gs://%s/orders/part-0.parquet", ORDERS_BUCKET);
	auto params = ResolveWithHandle(f, "orders", StringUtil::Format("gs://%s/orders/", ORDERS_BUCKET), path);
	REQUIRE(params.GetProvider().GetType() == S3ProviderType::GCS);
	REQUIRE(params.GetRequestOptions().user_project.empty());
	REQUIRE(params.GetCredentials().access_key_id == ORDERS_KEY);
}

TEST_CASE("A request with credentials and no file opener fails",
          "[httpfs][s3][file_credentials][file_credentials_attack]") {
	Fixture f;
	f.con.BeginTransaction();
	auto table_credentials = GovernedHost::Get().Attach(*f.con.context, "orders");
	FileOpenerInfo info;
	info.file_path = OrdersFile(0);
	info.credentials = table_credentials;
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
	plain.file_path = OrdersFile(0);
	REQUIRE(S3AuthResolver::Resolve(nullptr, plain).GetCredentials().access_key_id.empty());
	f.con.Rollback();
}

//===--------------------------------------------------------------------===//
// Why an existing mechanism does not do: a transaction secret (SecretPersistType::TRANSACTION) holds the table's
// credentials for the transaction only, but is matched by path, so a path read in the same transaction uses it.
// This test shows that behavior; it passes when the path read DOES get the table's credentials.
//===--------------------------------------------------------------------===//

TEST_CASE("A transaction secret with the table's scope is used by a path read",
          "[httpfs][s3][file_credentials][file_credentials_existing]") {
	Fixture f;
	f.CreateUserSecret(f.con);
	Fixture::Ok(f.con, "BEGIN TRANSACTION");
	auto &host = GovernedHost::Get();
	auto scope = host.Table("orders").scope;
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

TEST_CASE("A file option in SQL does not carry the table's credentials",
          "[httpfs][s3][file_credentials][file_credentials_attack]") {
	Fixture f;
	f.CreateUserSecret(f.con);
	Fixture::Ok(f.con, "BEGIN TRANSACTION");
	RunGovernedScan(f);
	for (auto &option : {"credentials", "secret", "secret_handle"}) {
		auto mark = f.Mark();
		auto r = f.con.Query(StringUtil::Format(
		    "SELECT count(*) FROM read_parquet([{'filename': '%s', '%s': 'governed'}])", OrdersFile(0), option));
		INFO(ResultText(*r));
		REQUIRE(r->HasError());
		REQUIRE(Count(f.Since(mark), ORDERS_BUCKET, ORDERS_KEY) == 0);
		Fixture::Ok(f.con, "ROLLBACK");
		Fixture::Ok(f.con, "BEGIN TRANSACTION");
		RunGovernedScan(f);
	}
}

#ifdef HAS_FILE_CREDENTIALS

namespace {
//! Every string the outputs below show for the transaction's secrets and the governed scan
vector<string> VisibleStrings(Connection &con) {
	vector<string> result;
	for (auto &query : {"SELECT name FROM duckdb_secrets()", "SELECT secret_string FROM duckdb_secrets()",
	                    "SELECT name FROM which_secret('s3://governed-orders/orders/part-0.parquet', 's3')"}) {
		auto r = con.Query(query);
		for (idx_t row = 0; !r->HasError() && row < r->RowCount(); row++) {
			result.push_back(r->Collection().GetValue(0, row).ToString());
		}
	}
	return result;
}
} // namespace

TEST_CASE("Each scan's credentials are their own object, and no output shows them",
          "[httpfs][s3][file_credentials][file_credentials_attack]") {
	Fixture f;
	f.CreateUserSecret(f.con);
	Fixture::Ok(f.con, "BEGIN TRANSACTION");
	RunGovernedScan(f);
	RunGovernedScan(f);
	auto attached = GovernedHost::Get().Attachments();
	REQUIRE(attached.size() == 2);
	REQUIRE(attached[0] != attached[1]);
	for (auto &text : {ResultText(*f.con.Query("SELECT * FROM duckdb_secrets()")),
	                   ResultText(*f.con.Query("EXPLAIN ANALYZE SELECT * FROM governed_scan('orders')"))}) {
		RequireNoCredential(text);
		REQUIRE_FALSE(StringUtil::Contains(text, HOST_NAME));
	}
}

TEST_CASE("No SQL that takes a secret name reaches the table's credentials",
          "[httpfs][s3][file_credentials][file_credentials_attack]") {
	Fixture f;
	f.CreateUserSecret(f.con);
	Fixture::Ok(f.con, "BEGIN TRANSACTION");
	RunGovernedScan(f);
	auto table_credentials = GovernedHost::Get().Attachments()[0];
	auto &manager = SecretManager::Get(*f.con.context);
	auto transaction = CatalogTransaction::GetSystemCatalogTransaction(*f.con.context);
	ClientContextFileOpener opener(*f.con.context);
	// the host's name and every string the outputs show
	auto names = VisibleStrings(f.con);
	names.push_back("governed");
	names.push_back(HOST_NAME);
	for (auto &name : names) {
		if (name == "user_secret") {
			// the user's own secret, matched by path; it is not the table's
			continue;
		}
		INFO(name);
		REQUIRE(!manager.GetSecretByName(transaction, name));
		auto drop = f.con.Query("DROP SECRET IF EXISTS \"" + name + "\"");
		INFO(ResultText(*drop));
		auto create =
		    f.con.Query(StringUtil::Format("CREATE OR REPLACE SECRET \"%s\" (TYPE s3, SCOPE 's3://%s/', KEY_ID "
		                                   "'AKIAREPLACED00000001', SECRET 'x')",
		                                   name, ORDERS_BUCKET));
		INFO(ResultText(*create));
		// the credentials still hold the host's secret, and the governed scan still reads with it
		REQUIRE(table_credentials->GetSecret(&opener, OrdersFile(0))->TryGetValue("key_id").ToString() == ORDERS_KEY);
		f.con.Query("DROP SECRET IF EXISTS \"" + name + "\"");
	}
	auto mark = f.Mark();
	RunGovernedScan(f);
	REQUIRE(OnlyKeys(f.Since(mark), ORDERS_BUCKET, {ORDERS_KEY}));
	// no SQL statement can name the credentials: a string copied from any output is a secret name, and a secret
	// named that is matched by its scope and by name only
	for (auto &name : names) {
		if (name == "user_secret") {
			continue;
		}
		auto r = f.con.Query(
		    StringUtil::Format("SELECT count(*) FROM read_parquet('%s', secret='%s')", OrdersFile(0), name));
		INFO(ResultText(*r));
		REQUIRE(r->HasError());
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
	// another connection, with the credentials object itself
	other.BeginTransaction();
	{
		ClientContextFileOpener opener(*other.context);
		REQUIRE_THROWS(table_credentials->GetSecret(&opener, OrdersFile(0)));
		FileOpenerInfo info;
		info.file_path = OrdersFile(0);
		info.credentials = table_credentials;
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
	ClientContextFileOpener opener(*f.con.context);
	REQUIRE_THROWS(table_credentials->GetSecret(&opener, OrdersFile(0)));
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
	ClientContextFileOpener opener(*f.con.context);
	REQUIRE_THROWS_WITH(table_credentials->GetSecret(&opener, OrdersFile(0)),
	                    Catch::Contains("ended with the transaction"));
}

TEST_CASE("No SQL creates the table's credentials", "[httpfs][s3][file_credentials][file_credentials_attack]") {
	Fixture f;
	auto vends = GovernedHost::Get().Vends("orders");
	// the host registers no secret provider: CREATE SECRET has nothing that vends
	for (auto &query : {
	         StringUtil::Format("CREATE SECRET minted (TYPE s3, PROVIDER %s, TABLE 'orders')", HOST_NAME),
	         StringUtil::Format("CREATE TEMPORARY SECRET minted (TYPE s3, PROVIDER %s, SCOPE 's3://%s/')", HOST_NAME,
	                            ORDERS_BUCKET),
	         StringUtil::Format("CREATE SECRET minted IN transaction (TYPE s3, PROVIDER %s)", HOST_NAME),
	     }) {
		auto r = f.con.Query(query);
		INFO(query);
		INFO(ResultText(*r));
		REQUIRE(r->HasError());
	}
	REQUIRE(GovernedHost::Get().Vends("orders") == vends);
	REQUIRE(f.con.Query("SELECT count(*) FROM duckdb_secrets() WHERE name = 'minted'")
	            ->Collection()
	            .GetValue(0, 0)
	            .ToString() == "0");
}

TEST_CASE("The table's credentials are used only for paths under its scope",
          "[httpfs][s3][file_credentials][file_credentials_attack]") {
	Fixture f;
	f.CreateUserSecret(f.con);
	Fixture::Ok(f.con, "BEGIN TRANSACTION");
	RunGovernedScan(f);
	auto table_credentials = GovernedHost::Get().Attachments()[0];
	// a file list that names a path outside the table, as a manifest written by the table's writer could, or one
	// that leaves it with a '..' segment
	for (auto &path : {ItemsFile(0), GovernedHost::Get().Table("orders").scope + "../items/part-0.parquet"}) {
		INFO(path);
		OpenFileInfo file(path);
		GovernedHost::Get().Apply(table_credentials, file);
		auto mark = f.Mark();
		REQUIRE_THROWS(FileSystem::GetFileSystem(*f.con.context).OpenFile(file, FileFlags::FILE_FLAGS_READ));
		REQUIRE(CountKey(f.Since(mark), ORDERS_KEY) == 0);
	}
	f.con.Query("ROLLBACK");
}

#endif

} // namespace duckdb
