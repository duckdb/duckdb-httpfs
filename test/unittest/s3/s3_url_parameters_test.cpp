#include "catch.hpp"
#include "s3/s3_test_helper.hpp"
#include "s3/s3_settings.hpp"
#include "s3/s3_url.hpp"
#include "s3/s3_request.hpp"
#include "s3/s3fs.hpp"
#include "http/httpfs.hpp"
#include "crypto.hpp"
#include "duckdb/common/file_system.hpp"
#include "duckdb/main/client_context_file_opener.hpp"
#include "duckdb/storage/buffer_manager.hpp"
#include "duckdb/storage/external_file_cache/caching_file_system.hpp"

#include <atomic>
#include <thread>

namespace duckdb {
namespace {

static constexpr const char *ENABLE = "SET s3_enable_deprecated_url_parameters=true";
static constexpr const char *DISABLE = "SET s3_enable_deprecated_url_parameters=false";
static constexpr const char *RESET = "RESET s3_enable_deprecated_url_parameters";
static constexpr const char *SET_NULL = "SET s3_enable_deprecated_url_parameters=NULL";

static bool Enabled(Connection &con) {
	ClientContextFileOpener opener(*con.context);
	return S3Settings::URLParametersEnabled(&opener);
}

static string ReadBlob(Connection &con, const string &path) {
	auto result = con.Query("SELECT content FROM read_blob(?)", Value(path));
	INFO((result->HasError() ? result->GetError() : ""));
	REQUIRE_FALSE(result->HasError());
	return StringValue::Get(result->Collection().GetValue(0, 0));
}

static void Configure(Connection &con, const MockS3Server &server, const string &client) {
	S3TestHelper::RequireQueryOk(con, "SET enable_global_s3_configuration=false");
	S3TestHelper::RequireQueryOk(con, "SET httpfs_client_implementation='" + client + "'");
	S3TestHelper::RequireQueryOk(con, "CREATE SECRET reader (TYPE S3, KEY_ID 'id', SECRET 'secret', "
	                                  "SESSION_TOKEN 'token', ENDPOINT '" +
	                                      server.Endpoint() + "', URL_STYLE 'path', USE_SSL false)");
}

class ChangePolicyDuringRequest : public ClientContextFileOpener {
public:
	ChangePolicyDuringRequest(ClientContext &context, Connection &other, string statement)
	    : ClientContextFileOpener(context), other(other), statement(std::move(statement)) {
	}

	SettingLookupResult TryGetCurrentSetting(const Identifier &key, Value &result, FileOpenerInfo &info) override {
		if (!changed && key == "http_timeout") {
			changed = true;
			S3TestHelper::RequireQueryOk(other, statement);
		}
		return ClientContextFileOpener::TryGetCurrentSetting(key, result, info);
	}

	bool changed = false;
	Connection &other;
	string statement;
};

} // namespace

TEST_CASE("Only explicit S3 URL parameter opt-out is irreversible", "[httpfs][s3][url-parameters]") {
	DuckDB db(nullptr);
	Connection con(db), other(db);
	S3TestHelper::LoadExtension(db);
	REQUIRE_FALSE(Enabled(con));
	REQUIRE(con.Query("SELECT current_setting('s3_enable_deprecated_url_parameters')")
	            ->Collection()
	            .GetValue(0, 0)
	            .IsNull());
	S3TestHelper::RequireQueryOk(con, RESET);
	REQUIRE_FALSE(Enabled(other));
	S3TestHelper::RequireQueryOk(con, SET_NULL);
	REQUIRE(con.Query("SELECT current_setting('s3_enable_deprecated_url_parameters')")
	            ->Collection()
	            .GetValue(0, 0)
	            .IsNull());
	REQUIRE(con.Query("SET SESSION s3_enable_deprecated_url_parameters=true")->HasError());
	REQUIRE(con.Query("SET LOCAL s3_enable_deprecated_url_parameters=true")->HasError());
	REQUIRE(con.Query("RESET SESSION s3_enable_deprecated_url_parameters")->HasError());

	SECTION("opt in, return to the default, then permanently opt out") {
		S3TestHelper::RequireQueryOk(con, ENABLE);
		REQUIRE(Enabled(other));
		S3TestHelper::RequireQueryOk(other, ENABLE);
		S3TestHelper::RequireQueryOk(con, RESET);
		REQUIRE_FALSE(Enabled(con));
		REQUIRE_FALSE(Enabled(other));
		// Core removes NULL global extension defaults on RESET. duckdb_settings()
		// still reports NULL, even though current_setting() cannot read an unset default.
		auto settings = other.Query("SELECT value FROM duckdb_settings() "
		                            "WHERE name='s3_enable_deprecated_url_parameters'");
		REQUIRE_FALSE(settings->HasError());
		REQUIRE(settings->Collection().Count() == 1);
		REQUIRE(settings->Collection().GetValue(0, 0).IsNull());
		S3TestHelper::RequireQueryOk(other, RESET);
		S3TestHelper::RequireQueryOk(other, ENABLE);
		REQUIRE(Enabled(con));
		S3TestHelper::RequireQueryOk(con, SET_NULL);
		REQUIRE_FALSE(Enabled(other));
		S3TestHelper::RequireQueryOk(other, ENABLE);
		REQUIRE(Enabled(con));
		S3TestHelper::RequireQueryOk(other, DISABLE);
	}
	SECTION("opt out directly") {
		S3TestHelper::RequireQueryOk(con, DISABLE);
	}
	REQUIRE_FALSE(Enabled(con));
	REQUIRE_FALSE(Enabled(other));
	S3TestHelper::RequireQueryOk(other, DISABLE);
	REQUIRE(con.Query(ENABLE)->HasError());
	REQUIRE(other.Query(RESET)->HasError());
	REQUIRE(con.Query(SET_NULL)->HasError());

	DuckDB independent(nullptr);
	Connection fresh(independent);
	S3TestHelper::LoadExtension(independent);
	S3TestHelper::RequireQueryOk(fresh, ENABLE);
	REQUIRE(Enabled(fresh));
	REQUIRE_FALSE(Enabled(con));
}

TEST_CASE("Concurrent setters cannot undo explicit S3 URL parameter opt-out", "[httpfs][s3][url-parameters]") {
	const char *statement = ENABLE;
	SECTION("enable") {
	}
	SECTION("reset") {
		statement = RESET;
	}
	SECTION("set null") {
		statement = SET_NULL;
	}
	for (idx_t iteration = 0; iteration < 20; iteration++) {
		DuckDB db(nullptr);
		Connection changing(db), disabling(db);
		S3TestHelper::LoadExtension(db);
		S3TestHelper::RequireQueryOk(changing, ENABLE);
		std::atomic<bool> start {false};
		unique_ptr<QueryResult> changed_result;
		std::thread change_thread([&] {
			while (!start.load()) {
				std::this_thread::yield();
			}
			changed_result = changing.Query(statement);
		});
		start = true;
		auto disabled_result = disabling.Query(DISABLE);
		change_thread.join();
		REQUIRE(changed_result);
		REQUIRE_FALSE(disabled_result->HasError());
		REQUIRE_FALSE(Enabled(changing));
		REQUIRE(changing.Query(ENABLE)->HasError());
		REQUIRE(disabling.Query(RESET)->HasError());
		REQUIRE(changing.Query(SET_NULL)->HasError());
	}
}

TEST_CASE("S3 URL parameter registration validates startup values", "[httpfs][s3][url-parameters]") {
	for (const auto &value : {Value(), Value("true"), Value("false")}) {
		DBConfig config;
		config.SetOptionByName("s3_enable_deprecated_url_parameters", value);
		S3Settings::Register(config);
		ExtensionOption option;
		REQUIRE(config.TryGetExtensionOption("s3_enable_deprecated_url_parameters", option));
		Value stored;
		config.TryGetCurrentUserSetting(option.setting_index.GetIndex(), stored);
		REQUIRE(stored.IsNull() == value.IsNull());
		if (!stored.IsNull()) {
			REQUIRE(stored.type() == LogicalType::BOOLEAN);
			REQUIRE(stored.GetValue<bool>() == (value.ToString() == "true"));
		}
	}
	DBConfig invalid;
	invalid.SetOptionByName("s3_enable_deprecated_url_parameters", Value("not-a-boolean"));
	REQUIRE_THROWS(S3Settings::Register(invalid));
}

TEST_CASE("S3 default URL parsing treats every parameter as key bytes", "[httpfs][s3][url-parameters]") {
	for (const auto &prefix : {"s3://", "gs://", "gcs://", "r2://", "alias://"}) {
		S3AuthConfig config;
		config.route = S3UrlScheme::MatchRoutedUrl(prefix);
		config.endpoint = "storage.example";
		config.endpoint_mode = S3EndpointMode::EXPLICIT;
		config.url_style = "path";
		const string key = "dir?part/file?s3_endpoint=other.example&s3_use_ssl=false&s3_url_style=vhost"
		                   "&s3_access_key_id=id&s3_secret_access_key=secret&s3_session_token=token"
		                   "&s3_region=elsewhere&s3_requester_pays=true&s3_sse_c_key=invalid"
		                   "&gcs_user_project=project&s3_version_id=v1&gcs_generation=123";
		const auto path = string(prefix) + "bucket/" + key;
		auto params = S3AuthResolver::Resolve(config, path);
		auto parsed = S3Url::Parse(path, params);
		REQUIRE(parsed.GetKey() == key);
		REQUIRE(parsed.GetHost() == "storage.example");
		REQUIRE(parsed.GetQueryString().empty());
		REQUIRE_FALSE(parsed.GetObjectVersion().IsSet());
		REQUIRE(S3Url::GetDisplayUrl(path, params) == path);
	}
}

TEST_CASE("HTTPFS cache identity separates literal and legacy S3 paths", "[httpfs][s3][url-parameters]") {
	for (const string client : {"curl", "httplib"}) {
		for (const bool force_download : {false, true}) {
			for (const string validator : {"different", "equal", "absent"}) {
				CAPTURE(client, force_download, validator);
				MockS3ServerConfig legacy_config;
				legacy_config.object.data = "legacy--data";
				legacy_config.metadata.etag = validator == "absent" ? "" : "\"legacy-etag\"";
				MockS3Server legacy(legacy_config);
				MockS3ServerConfig literal_config;
				literal_config.object.key =
				    "object.bin?s3_endpoint=" + legacy.Endpoint() + "&s3_use_ssl=false&s3_url_style=path";
				literal_config.object.data = "literal-data";
				literal_config.metadata.etag =
				    validator == "different" ? "\"literal-etag\"" : legacy_config.metadata.etag;
				MockS3Server literal(literal_config);
				DuckDB db(nullptr);
				Connection con(db), other(db);
				S3TestHelper::LoadExtension(db);
				Configure(con, literal, client);
				S3TestHelper::RequireQueryOk(con, "SET enable_http_metadata_cache=true");
				S3TestHelper::RequireQueryOk(con, "SET enable_external_file_cache=true");
				S3TestHelper::RequireQueryOk(con, string("SET force_download=") + (force_download ? "true" : "false"));
				const auto path = literal.S3Path();
				REQUIRE(ReadBlob(con, path) == literal.ObjectData());
				REQUIRE(legacy.Observations().empty());
				S3TestHelper::RequireQueryOk(other, ENABLE);
				REQUIRE(ReadBlob(con, path) == legacy.ObjectData());
				for (const auto &request : legacy.Observations()) {
					REQUIRE(request.key_id == "id");
					REQUIRE(MockS3HeaderValues(request, "x-amz-security-token") == vector<string> {"token"});
				}
				S3TestHelper::RequireQueryOk(other, RESET);
				REQUIRE(ReadBlob(con, path) == literal.ObjectData());
				S3TestHelper::RequireQueryOk(other, ENABLE);
				REQUIRE(ReadBlob(con, path) == legacy.ObjectData());
				S3TestHelper::RequireQueryOk(other, DISABLE);
				REQUIRE(ReadBlob(con, path) == literal.ObjectData());
				REQUIRE_FALSE(Enabled(con));
			}
		}
	}
}

TEST_CASE("S3 refresh keeps the URL policy captured before explicit opt-out", "[httpfs][s3][url-parameters]") {
	for (const string client : {"curl", "httplib"}) {
		MockS3ServerConfig config;
		config.auth.stale_key_id = S3TestHelper::STALE_KEY_ID;
		config.auth.refresh_target = MockS3RefreshTarget::RANGE_GET;
		MockS3Server server(config);
		DuckDB db(nullptr);
		Connection con(db), other(db);
		auto test_id = S3TestHelper::ConfigureRefresh(db, con, server, client, false);
		S3TestHelper::RequireQueryOk(con, ENABLE);
		S3ProviderRefreshHook hook(test_id, [&] { S3TestHelper::RequireQueryOk(other, DISABLE); });
		S3TestHelper::RequireQueryOk(con, "BEGIN");
		auto &fs = FileSystem::GetFileSystem(*con.context);
		auto handle = fs.OpenFile(server.S3Path() + "?s3_version_id=v1",
		                          FileFlags::FILE_FLAGS_READ | FileFlags::FILE_FLAGS_DIRECT_IO);
		string data(5, '\0');
		handle->Read(QueryContext(*con.context), &data[0], data.size(), 0);
		REQUIRE(data == server.ObjectData().substr(0, data.size()));
		REQUIRE_FALSE(Enabled(other));
		S3TestHelper::RequireQueryOk(con, "COMMIT");
		S3TestHelper::AssertSingleRefresh(test_id);
		for (const auto &request : server.Observations()) {
			REQUIRE(request.version_id == "v1");
		}
	}
}

TEST_CASE("Open S3 handles keep separate downloads across URL policy changes", "[httpfs][s3][url-parameters]") {
	for (const string client : {"curl", "httplib"}) {
		for (const bool force_download : {false, true}) {
			CAPTURE(client, force_download);
			MockS3Server legacy {MockS3ServerConfig()};
			MockS3ServerConfig config;
			config.object.key = "object.bin?s3_endpoint=" + legacy.Endpoint();
			config.object.data = "literal bytes";
			MockS3Server literal(config);
			DuckDB db(nullptr);
			Connection con(db), other(db);
			S3TestHelper::LoadExtension(db);
			Configure(con, literal, client);
			S3TestHelper::RequireQueryOk(con, string("SET force_download=") + (force_download ? "true" : "false"));
			S3TestHelper::RequireQueryOk(con, "SET enable_http_metadata_cache=true");
			S3TestHelper::RequireQueryOk(con, "BEGIN");
			auto &fs = FileSystem::GetFileSystem(*con.context);
			auto first = fs.OpenFile(literal.S3Path(), FileFlags::FILE_FLAGS_READ);
			auto read = [&](FileHandle &handle) {
				string data(handle.GetFileSize(), '\0');
				handle.Read(QueryContext(*con.context), &data[0], data.size(), 0);
				return data;
			};
			REQUIRE(read(*first) == literal.ObjectData());
			S3TestHelper::RequireQueryOk(other, ENABLE);
			auto second = fs.OpenFile(literal.S3Path(), FileFlags::FILE_FLAGS_READ);
			REQUIRE(read(*second) == legacy.ObjectData());
			REQUIRE(read(*first) == literal.ObjectData());
			const auto literal_key = first->Cast<HTTPFileHandle>().GetCacheKey();
			const auto legacy_key = second->Cast<HTTPFileHandle>().GetCacheKey();
			REQUIRE(literal_key != legacy_key);
			auto cache = first->file_system.Cast<HTTPFileSystem>().GetGlobalCache();
			HTTPMetadataCacheEntry entry;
			if (!force_download) {
				REQUIRE(cache->Find(literal_key, entry));
				REQUIRE(cache->Find(legacy_key, entry));
			}
			S3TestHelper::RequireQueryOk(other, DISABLE);
			auto writer = fs.OpenFile(literal.S3Path(), FileFlags::FILE_FLAGS_WRITE);
			REQUIRE_FALSE(cache->Find(literal_key, entry));
			REQUIRE_FALSE(cache->Find(legacy_key, entry));
			writer->AbortWrite();
			S3TestHelper::RequireQueryOk(con, "COMMIT");
		}
	}
}

TEST_CASE("Authenticated S3 redirects require legacy opt-in", "[httpfs][s3][url-parameters]") {
	for (const string client : {"curl", "httplib"}) {
		for (const bool enabled : {false, true}) {
			MockS3Server receiver {MockS3ServerConfig()};
			MockS3ServerConfig config;
			config.metadata.redirect_head = true;
			config.metadata.redirect_location = "http://" + receiver.Endpoint() + "/refresh-bucket/object.bin";
			MockS3Server origin(config);
			DuckDB db(nullptr);
			Connection con(db);
			S3TestHelper::LoadExtension(db);
			Configure(con, origin, client);
			if (enabled) {
				S3TestHelper::RequireQueryOk(con, ENABLE);
			}
			auto result = con.Query("SELECT content FROM read_blob(?)", Value(origin.S3Path()));
			INFO((result->HasError() ? result->GetError() : ""));
			REQUIRE_FALSE(result->HasError());
			if (!enabled) {
				REQUIRE(receiver.Observations().empty());
			} else {
				REQUIRE_FALSE(receiver.Observations().empty());
			}
		}
	}
}

TEST_CASE("Core cached S3 handles cannot exchange bytes across URL policies", "[httpfs][s3][url-parameters]") {
	for (const string client : {"curl", "httplib"}) {
		for (const string validation : {"VALIDATE_ALL", "NO_VALIDATION"}) {
			for (const bool force_download : {false, true}) {
				CAPTURE(client, validation, force_download);
				MockS3ServerConfig legacy_config;
				legacy_config.object.data = "legacy--data";
				MockS3Server legacy(legacy_config);
				MockS3ServerConfig config;
				config.object.key = "object.bin?s3_endpoint=" + legacy.Endpoint();
				config.object.data = "literal-data";
				MockS3Server literal(config);
				DuckDB db(nullptr);
				Connection con(db), other(db);
				S3TestHelper::LoadExtension(db);
				Configure(con, literal, client);
				S3TestHelper::RequireQueryOk(con, "SET enable_external_file_cache=true");
				S3TestHelper::RequireQueryOk(con, "SET validate_external_file_cache='" + validation + "'");
				S3TestHelper::RequireQueryOk(con, string("SET force_download=") + (force_download ? "true" : "false"));
				S3TestHelper::RequireQueryOk(con, "BEGIN");
				auto fs = CachingFileSystem::Get(*con.context);
				auto read = [](CachingFileHandle &handle) {
					auto buffer = handle.Read(12, 0);
					string data(12, '\0');
					buffer.CopyTo(data_ptr_cast(&data[0]), data.size());
					return data;
				};
				auto first = fs.OpenFile(OpenFileInfo(literal.S3Path()), FileFlags::FILE_FLAGS_READ);
				REQUIRE(read(*first) == literal.ObjectData());
				S3TestHelper::RequireQueryOk(other, ENABLE);
				auto second = fs.OpenFile(OpenFileInfo(literal.S3Path()), FileFlags::FILE_FLAGS_READ);
				REQUIRE(read(*second) == legacy.ObjectData());
				REQUIRE(read(*first) == literal.ObjectData());
				S3TestHelper::RequireQueryOk(other, DISABLE);
				auto third = fs.OpenFile(OpenFileInfo(literal.S3Path()), FileFlags::FILE_FLAGS_READ);
				REQUIRE(read(*third) == literal.ObjectData());
				REQUIRE(read(*second) == legacy.ObjectData());
				REQUIRE(read(*first) == literal.ObjectData());
				S3TestHelper::RequireQueryOk(con, "COMMIT");
			}
		}
	}
}

TEST_CASE("S3 redirect policy covers every source of configured authentication", "[httpfs][s3][url-parameters]") {
	for (const bool enabled : {false, true}) {
		for (const string source : {"key", "secret", "token", "oauth", "sse", "header", "bearer", "anonymous"}) {
			CAPTURE(enabled, source);
			S3AuthConfig config;
			config.enable_deprecated_url_parameters = enabled;
			if (source == "key") {
				config.credentials.access_key_id = "id";
			} else if (source == "secret") {
				config.credentials.secret_access_key = "secret";
			} else if (source == "token") {
				config.credentials.session_token = "token";
			} else if (source == "oauth") {
				config.route = S3UrlScheme::MatchRoutedUrl("gcs://");
				config.credentials.oauth2_bearer_token = "token";
			} else if (source == "sse") {
				config.credentials.access_key_id = "id";
				config.credentials.secret_access_key = "secret";
				config.request_options.sse_customer_key =
				    S3SSECustomerKey::Create("MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=");
			}
			const auto path = config.route.prefix + "bucket/key";
			auto params = S3AuthResolver::Resolve(config, path);
			HTTPFSUtil http_util;
			HTTPFSParams http_params(http_util);
			http_params.follow_location = true;
			if (source == "header") {
				http_params.extra_headers["X-Private"] = "value";
			} else if (source == "bearer") {
				http_params.bearer_token = "token";
			}
			auto snapshot =
			    make_shared_ptr<S3RequestSnapshot>(http_params, params, path, weak_ptr<ClientContext>(), false);
			HTTPRequestSession session(snapshot);
			::AESStateSSLFactory encryption_util;
			S3RequestSpec spec {path, S3RequestOperation::GET_OBJECT};
			bool called = false;
			S3RequestExecutor::RunSession(encryption_util, session, spec, [&](S3RequestData &request) {
				REQUIRE(request.http_params->follow_location == (enabled || source == "anonymous"));
				called = true;
				return make_uniq<HTTPResponse>(HTTPStatusCode::OK_200);
			});
			REQUIRE(called);
			REQUIRE(snapshot->Params().follow_location);
		}
	}
}

TEST_CASE("S3 configuration errors direct users to the saved configuration", "[httpfs][s3][url-parameters]") {
	DuckDB db(nullptr);
	Connection con(db);
	S3TestHelper::LoadExtension(db);
	S3TestHelper::RequireQueryOk(con, "SET enable_global_s3_configuration=false");
	S3TestHelper::RequireQueryOk(con, "CREATE SECRET bad (TYPE S3, KEY_ID 'id', SECRET 'secret', "
	                                  "ENDPOINT 'ftp://storage.internal')");
	auto invalid = con.Query("FROM read_blob('s3://b/key?s3_endpoint=storage.internal')");
	REQUIRE(invalid->HasError());
	REQUIRE(StringUtil::Contains(invalid->GetError(), "Unsupported S3 endpoint scheme 'ftp'"));
	S3TestHelper::RequireQueryOk(con, "DROP SECRET bad");
	S3TestHelper::RequireQueryOk(con, "CREATE SECRET r2 (TYPE R2, KEY_ID 'id', SECRET 'secret')");
	auto missing = con.Query("FROM read_blob('r2://b/key?s3_endpoint=storage.internal')");
	REQUIRE(missing->HasError());
	REQUIRE(StringUtil::Contains(missing->GetError(), "set ACCOUNT_ID or ENDPOINT in the R2 secret"));
}

TEST_CASE("S3 directory removal reconstructs full object paths", "[httpfs][s3][url-parameters]") {
	MockS3ServerConfig config;
	config.object.key = "dir/literal?key.csv";
	MockS3Server server(config);
	DuckDB db(nullptr);
	Connection con(db);
	S3TestHelper::LoadExtension(db);
	Configure(con, server, "curl");
	S3TestHelper::RequireQueryOk(con, "BEGIN");
	FileSystem::GetFileSystem(*con.context).RemoveDirectory("s3://refresh-bucket/dir");
	S3TestHelper::RequireQueryOk(con, "COMMIT");
	bool deleted = false;
	for (const auto &request : server.Observations()) {
		if (request.method == "POST") {
			const string expected = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
			                        "<Delete xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">"
			                        "<Object><Key>dir/literal?key.csv</Key></Object><Quiet>true</Quiet></Delete>";
			REQUIRE(request.body_digest == MockS3DigestBody(expected));
			deleted = true;
		}
	}
	REQUIRE(deleted);
}

TEST_CASE("Bulk S3 deletion keeps the URL policy for every entry", "[httpfs][s3][url-parameters]") {
	MockS3Server server {MockS3ServerConfig()};
	DuckDB db(nullptr);
	Connection con(db), other(db);
	S3TestHelper::LoadExtension(db);
	Configure(con, server, "curl");
	S3TestHelper::RequireQueryOk(con, ENABLE);
	S3TestHelper::RequireQueryOk(con, "BEGIN");
	S3FileSystem fs(BufferManager::GetBufferManager(*db.instance));
	ChangePolicyDuringRequest opener(*con.context, other, DISABLE);
	fs.RemoveFiles(
	    {"s3://refresh-bucket/first?s3_requester_pays=true", "s3://refresh-bucket/second?s3_requester_pays=true"},
	    &opener);
	REQUIRE(opener.changed);
	REQUIRE_FALSE(Enabled(other));
	const string expected = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
	                        "<Delete xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">"
	                        "<Object><Key>first</Key></Object><Object><Key>second</Key></Object>"
	                        "<Quiet>true</Quiet></Delete>";
	idx_t requests = 0;
	for (const auto &request : server.Observations()) {
		if (request.method == "POST") {
			REQUIRE(request.body_digest == MockS3DigestBody(expected));
			requests++;
		}
	}
	REQUIRE(requests == 1);
	S3TestHelper::RequireQueryOk(con, "COMMIT");
}

TEST_CASE("S3 directory removal keeps its policy between listing and deleting", "[httpfs][s3][url-parameters]") {
	MockS3ServerConfig config;
	config.object.key = "dir/literal?s3_requester_pays=true";
	MockS3Server server(config);
	DuckDB db(nullptr);
	Connection con(db), other(db);
	S3TestHelper::LoadExtension(db);
	Configure(con, server, "curl");
	S3TestHelper::RequireQueryOk(con, "BEGIN");
	S3FileSystem fs(BufferManager::GetBufferManager(*db.instance));
	ChangePolicyDuringRequest opener(*con.context, other, ENABLE);
	fs.RemoveDirectory("s3://refresh-bucket/dir", &opener);
	REQUIRE(opener.changed);
	REQUIRE(Enabled(other));
	const string expected = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
	                        "<Delete xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">"
	                        "<Object><Key>dir/literal?s3_requester_pays=true</Key></Object>"
	                        "<Quiet>true</Quiet></Delete>";
	idx_t requests = 0;
	for (const auto &request : server.Observations()) {
		if (request.method == "POST") {
			REQUIRE(request.body_digest == MockS3DigestBody(expected));
			requests++;
		}
	}
	REQUIRE(requests == 1);
	S3TestHelper::RequireQueryOk(con, "COMMIT");
}

} // namespace duckdb
