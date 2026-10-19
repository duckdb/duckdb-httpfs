#include "catch.hpp"
#include "s3/s3_test_helper.hpp"
#include "s3/s3_settings.hpp"
#include "s3/s3_url.hpp"
#include "s3/s3_request.hpp"
#include "s3/s3fs.hpp"
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
static constexpr const char *MIGRATION_HINT = "opt in with SET s3_enable_deprecated_url_parameters = true";

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

TEST_CASE("S3 refresh keeps the URL policy captured before settings change", "[httpfs][s3][url-parameters]") {
	for (const string client : {"curl", "httplib"}) {
		MockS3ServerConfig config;
		config.auth.stale_key_id = S3TestHelper::STALE_KEY_ID;
		config.auth.refresh_target = MockS3RefreshTarget::RANGE_GET;
		MockS3Server server(config);
		DuckDB db(nullptr);
		Connection con(db), other(db);
		auto test_id = S3TestHelper::ConfigureRefresh(db, con, server, client, false);
		S3TestHelper::RequireQueryOk(con, ENABLE);
		S3ProviderRefreshHook hook(test_id, [&] {
			S3TestHelper::RequireQueryOk(other, DISABLE);
			S3TestHelper::RequireQueryOk(other, "SET GLOBAL s3_url_compatibility_mode=true");
		});
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

TEST_CASE("HTTPFS caches S3 question-mark paths under a stable URL policy", "[httpfs][s3][url-parameters]") {
	for (const string client : {"curl", "httplib"}) {
		for (const bool force_download : {false, true}) {
			for (const string policy : {"default", "enabled", "disabled"}) {
				CAPTURE(client, force_download, policy);
				MockS3ServerConfig config;
				if (policy != "enabled") {
					config.object.key += "?s3_requester_pays=true";
				}
				MockS3Server server(config);
				const auto path = policy == "enabled" ? server.S3Path() + "?s3_requester_pays=true" : server.S3Path();
				DuckDB db(nullptr);
				Connection con(db);
				S3TestHelper::LoadExtension(db);
				Configure(con, server, client);
				if (policy == "enabled") {
					S3TestHelper::RequireQueryOk(con, ENABLE);
				} else if (policy == "disabled") {
					S3TestHelper::RequireQueryOk(con, DISABLE);
				}
				S3TestHelper::RequireQueryOk(con, string("SET force_download=") + (force_download ? "true" : "false"));
				S3TestHelper::RequireQueryOk(con, "SET force_download_threshold=0");
				S3TestHelper::RequireQueryOk(con, "SET enable_http_metadata_cache=true");
				S3TestHelper::RequireQueryOk(con, "BEGIN");
				auto &fs = FileSystem::GetFileSystem(*con.context);
				for (idx_t iteration = 0; iteration < 2; iteration++) {
					auto reader = fs.OpenFile(path, FileFlags::FILE_FLAGS_READ);
					string data(reader->GetFileSize(), '\0');
					reader->Read(QueryContext(*con.context), &data[0], data.size(), 0);
					REQUIRE(data == server.ObjectData());
				}
				const auto observations = server.Observations();
				if (force_download) {
					REQUIRE(S3TestHelper::CountObservations(observations, "HEAD", "id", 200) == 0);
					REQUIRE(S3TestHelper::CountObservations(observations, "GET", "id", 200) == 1);
				} else {
					REQUIRE(S3TestHelper::CountObservations(observations, "HEAD", "id", 200) == 1);
					auto writer = fs.OpenFile(path, FileFlags::FILE_FLAGS_WRITE);
					writer->AbortWrite();
					auto reader = fs.OpenFile(path, FileFlags::FILE_FLAGS_READ);
					REQUIRE(reader->GetFileSize() == server.ObjectData().size());
					REQUIRE(S3TestHelper::CountObservations(server.Observations(), "HEAD", "id", 200) == 2);
				}
				S3TestHelper::RequireQueryOk(con, "COMMIT");
			}
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

TEST_CASE("Core caches S3 question-mark paths under a stable URL policy", "[httpfs][s3][url-parameters]") {
	for (const string client : {"curl", "httplib"}) {
		for (const string validation : {"VALIDATE_ALL", "NO_VALIDATION"}) {
			for (const string policy : {"default", "enabled", "disabled"}) {
				CAPTURE(client, validation, policy);
				MockS3ServerConfig config;
				if (policy != "enabled") {
					config.object.key += "?s3_requester_pays=true";
				}
				MockS3Server server(config);
				const auto path = policy == "enabled" ? server.S3Path() + "?s3_requester_pays=true" : server.S3Path();
				DuckDB db(nullptr);
				Connection con(db);
				S3TestHelper::LoadExtension(db);
				Configure(con, server, client);
				if (policy == "enabled") {
					S3TestHelper::RequireQueryOk(con, ENABLE);
				} else if (policy == "disabled") {
					S3TestHelper::RequireQueryOk(con, DISABLE);
				}
				S3TestHelper::RequireQueryOk(con, "SET enable_external_file_cache=true");
				S3TestHelper::RequireQueryOk(con, "SET validate_external_file_cache='" + validation + "'");
				S3TestHelper::RequireQueryOk(con, "SET force_download=false");
				S3TestHelper::RequireQueryOk(con, "SET force_download_threshold=0");
				auto fs = CachingFileSystem::Get(*con.context);
				auto read = [](CachingFileHandle &handle) {
					auto buffer = handle.Read(12, 0);
					string data(12, '\0');
					buffer.CopyTo(data_ptr_cast(&data[0]), data.size());
					return data;
				};
				for (idx_t iteration = 0; iteration < 2; iteration++) {
					S3TestHelper::RequireQueryOk(con, "BEGIN");
					auto handle = fs.OpenFile(OpenFileInfo(path), FileFlags::FILE_FLAGS_READ);
					REQUIRE(read(*handle) == server.ObjectData().substr(0, 12));
					REQUIRE(read(*handle) == server.ObjectData().substr(0, 12));
					handle.reset();
					S3TestHelper::RequireQueryOk(con, "COMMIT");
					REQUIRE(S3TestHelper::CountObservations(server.Observations(), "GET", "id", 206) == 1);
				}
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
				HTTPResponse redirect(HTTPStatusCode(307));
				redirect.headers.Insert("Location", "https://storage.example/redirected");
				redirect.body = "redirect response";
				auto error = ErrorData(S3RequestUtil::GetRequestError(request, redirect));
				REQUIRE(StringUtil::Contains(error.RawMessage(), MIGRATION_HINT) ==
				        (!enabled && source != "anonymous"));
				REQUIRE(error.ExtraInfo().at("status_code") == "307");
				REQUIRE(error.ExtraInfo().at("response_body") == redirect.body);
				S3RequestContext context {request.operation, request.captured, request.display_url};
				auto context_error = ErrorData(S3RequestUtil::GetRequestError(context, redirect));
				REQUIRE(context_error.RawMessage() == error.RawMessage());
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
	REQUIRE_FALSE(StringUtil::Contains(invalid->GetError(), MIGRATION_HINT));
	S3TestHelper::RequireQueryOk(con, "DROP SECRET bad");
	S3TestHelper::RequireQueryOk(con, "CREATE SECRET r2 (TYPE R2, KEY_ID 'id', SECRET 'secret')");
	auto missing = con.Query("FROM read_blob('r2://b/key?s3_endpoint=storage.internal')");
	REQUIRE(missing->HasError());
	REQUIRE(StringUtil::Contains(missing->GetError(), "set ACCOUNT_ID or ENDPOINT in the R2 secret"));
	REQUIRE(StringUtil::Contains(missing->GetError(), MIGRATION_HINT));
	auto without_options = con.Query("FROM read_blob('r2://b/key')");
	REQUIRE(without_options->HasError());
	REQUIRE_FALSE(StringUtil::Contains(without_options->GetError(), MIGRATION_HINT));
	S3TestHelper::RequireQueryOk(con, DISABLE);
	auto locked = con.Query("FROM read_blob('r2://b/key?s3_endpoint=storage.internal')");
	REQUIRE(locked->HasError());
	REQUIRE(StringUtil::Contains(locked->GetError(), "cannot be re-enabled in this database instance"));
}

TEST_CASE("S3 configuration migration hints respect the captured parsing policy", "[httpfs][s3][url-parameters]") {
	for (const string prefix : {"r2://", "alias://", "gcs://"}) {
		for (const bool enabled : {false, true}) {
			for (const bool compatibility : {false, true}) {
				CAPTURE(prefix, enabled, compatibility);
				S3AuthConfig config;
				config.route = S3UrlScheme::MatchRoutedUrl(prefix);
				config.enable_deprecated_url_parameters = enabled;
				config.compatibility_mode = compatibility;
				config.request_options.requester_pays = true;
				ErrorData error;
				try {
					S3AuthResolver::Resolve(config, prefix + "bucket/key?s3_region=us-east-1");
				} catch (std::exception &ex) {
					error = ErrorData(ex);
				}
				REQUIRE(error.HasError());
				REQUIRE(StringUtil::Contains(error.RawMessage(), MIGRATION_HINT) == (!enabled && !compatibility));
			}
		}
	}
}

TEST_CASE("S3 failed URL parameter reads explain how to restore legacy behavior", "[httpfs][s3][url-parameters]") {
	for (const string client : {"curl", "httplib"}) {
		for (const bool full_download : {false, true}) {
			CAPTURE(client, full_download);
			MockS3Server server {MockS3ServerConfig()};
			DuckDB db(nullptr);
			Connection con(db);
			S3TestHelper::LoadExtension(db);
			Configure(con, server, client);
			S3TestHelper::RequireQueryOk(con, string("SET force_download=") + (full_download ? "true" : "false"));
			const auto path = server.S3Path() + "?s3_requester_pays=true";
			auto failed = con.Query("SELECT content FROM read_blob(?)", Value(path));
			REQUIRE(failed->HasError());
			REQUIRE(StringUtil::Contains(failed->GetError(), MIGRATION_HINT));
			REQUIRE(StringUtil::Contains(failed->GetError(), "part of the object key"));
			S3TestHelper::RequireQueryOk(con, "SET s3_url_compatibility_mode=true");
			auto compatible = con.Query("SELECT content FROM read_blob(?)", Value(path));
			REQUIRE(compatible->HasError());
			REQUIRE_FALSE(StringUtil::Contains(compatible->GetError(), MIGRATION_HINT));
			S3TestHelper::RequireQueryOk(con, "SET s3_url_compatibility_mode=false");
			S3TestHelper::RequireQueryOk(con, ENABLE);
			REQUIRE(ReadBlob(con, path) == server.ObjectData());
			auto missing = con.Query("SELECT content FROM read_blob(?)",
			                         Value(server.S3Path() + "/missing?s3_requester_pays=true"));
			REQUIRE(missing->HasError());
			REQUIRE_FALSE(StringUtil::Contains(missing->GetError(), MIGRATION_HINT));
		}
	}
}

TEST_CASE("S3 redirect migration hints require the legacy policy to have blocked the redirect",
          "[httpfs][s3][url-parameters]") {
	S3AuthConfig config;
	config.credentials.access_key_id = "id";
	auto auth_params = S3AuthResolver::Resolve(config, "s3://bucket/key");
	HTTPFSUtil http_util;
	HTTPFSParams http_params(http_util);
	HTTPResponse response(HTTPStatusCode(307));
	response.headers.Insert("Location", "https://storage.example/redirected");
	http_params.follow_location = false;
	S3RequestSnapshot snapshot(http_params, auth_params, "s3://bucket/key");
	auto error =
	    ErrorData(S3RequestUtil::GetError(snapshot, response, RequestType::GET_REQUEST, "reading", "s3://bucket/key"));
	REQUIRE_FALSE(StringUtil::Contains(error.RawMessage(), MIGRATION_HINT));
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
	S3TestHelper::RequireQueryOk(
	    con, "CREATE SECRET literal_reader (TYPE S3, KEY_ID 'id', SECRET 'secret', ENDPOINT '" + server.Endpoint() +
	             "', URL_STYLE 'path', USE_SSL false, URL_COMPATIBILITY_MODE true, "
	             "SCOPE 's3://refresh-bucket/third')");
	S3TestHelper::RequireQueryOk(con, ENABLE);
	S3TestHelper::RequireQueryOk(con, "BEGIN");
	S3FileSystem fs(BufferManager::GetBufferManager(*db.instance));
	ChangePolicyDuringRequest opener(*con.context, other, DISABLE);
	fs.RemoveFiles({"s3://refresh-bucket/first?s3_requester_pays=true",
	                "s3://refresh-bucket/second?s3_requester_pays=true",
	                "s3://refresh-bucket/third?s3_requester_pays=true"},
	               &opener);
	REQUIRE(opener.changed);
	REQUIRE_FALSE(Enabled(other));
	const string expected = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
	                        "<Delete xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">"
	                        "<Object><Key>first</Key></Object><Object><Key>second</Key></Object>"
	                        "<Quiet>true</Quiet></Delete>";
	const string literal_expected = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
	                                "<Delete xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">"
	                                "<Object><Key>third?s3_requester_pays=true</Key></Object>"
	                                "<Quiet>true</Quiet></Delete>";
	idx_t parsed_requests = 0, literal_requests = 0;
	for (const auto &request : server.Observations()) {
		if (request.method == "POST") {
			if (request.body_digest == MockS3DigestBody(expected)) {
				parsed_requests++;
			} else {
				REQUIRE(request.body_digest == MockS3DigestBody(literal_expected));
				literal_requests++;
			}
		}
	}
	REQUIRE(parsed_requests == 1);
	REQUIRE(literal_requests == 1);
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
