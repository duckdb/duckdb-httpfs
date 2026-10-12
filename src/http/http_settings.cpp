#include "http/http_settings.hpp"

#include "http/httpfs_client.hpp"
#include "duckdb/common/local_file_system.hpp"
#include "duckdb/main/client_context.hpp"
#include "duckdb/main/client_context_file_opener.hpp"
#include "duckdb/main/config.hpp"
#include "duckdb/logging/logger.hpp"

#ifndef __EMSCRIPTEN__
#include "http/httpfs_curl_client.hpp"
#endif

namespace duckdb {

namespace {

class HTTPFSWasmUtil : public HTTPFSUtil {
public:
	HTTPFSWasmUtil(HTTPUtil &browser_util_p, DatabaseInstance &db) : HTTPFSUtil(db), browser_util(browser_util_p) {
	}

	unique_ptr<HTTPClient> InitializeClient(HTTPParams &params, const string &proto_host_port) override {
		return browser_util.InitializeClient(params, proto_host_port);
	}

	HTTPTransportReusePolicy GetTransportReusePolicy() const override {
		return HTTPTransportReusePolicy::EPHEMERAL;
	}

	string GetName() const override {
		return "HTTPFS-Wasm";
	}

private:
	bool GetDefaultVerifySSL(const HTTPFSParams &) const override {
		return true;
	}

	//! The database transport manager retains previous providers until database destruction.
	HTTPUtil &browser_util;
};

} // namespace

static void RequireGlobalScope(SetScope scope, const char *setting) {
	if (scope == SetScope::SESSION) {
		throw InvalidInputException("%s can only be set globally", setting);
	}
}

static bool ConnectionCachingEnabled(const ClientContext &context) {
	Value current_value;
	if (context.TryGetCurrentSetting("httpfs_connection_caching", current_value)) {
		return BooleanValue::Get(current_value);
	}
	return true;
}

static bool ConnectionCachingEnabled(const DBConfig &config) {
	Value current_value;
	if (config.TryGetCurrentSetting("httpfs_connection_caching", current_value)) {
		return BooleanValue::Get(current_value);
	}
	return true;
}

static void SetCACertFile(ClientContext &context, SetScope, Value &parameter) {
	if (parameter.IsNull()) {
		throw InvalidInputException("NULL is not a valid option for ca_cert_file");
	}
	auto value = StringValue::Get(parameter);
	if (value.empty()) {
		parameter = Value("");
		return;
	}
	parameter = Value(FileSystem::GetFileSystem(context).CanonicalizePath(value));
}

static void SetExtraHTTPHeaders(ClientContext &, SetScope, Value &parameter) {
	if (parameter.IsNull()) {
		throw InvalidInputException("NULL is not a valid option for extra_http_headers");
	}
	for (const auto &entry : MapValue::GetChildren(parameter)) {
		auto key_value = StructValue::GetChildren(entry);
		if (key_value[1].IsNull()) {
			throw InvalidInputException("extra_http_headers value for \"%s\" must not be NULL",
			                            key_value[0].GetValue<string>());
		}
	}
}

static void SetHTTPClientImplementation(ClientContext &context, SetScope scope, Value &parameter) {
	RequireGlobalScope(scope, "httpfs_client_implementation");
	auto &config = DBConfig::GetConfig(context);
	auto value = StringValue::Get(parameter);
	auto &http_util = config.GetHTTPUtil();
	if (http_util.GetName() == "WasmHTTPUtils" || http_util.GetName() == "HTTPFS-Wasm") {
		if (value == "wasm" || value == "default") {
			return;
		}
		throw InvalidInputException("Unsupported option for httpfs_client_implementation, only `wasm` and "
		                            "`default` are currently supported for duckdb-wasm");
	}
#ifndef __EMSCRIPTEN__
	if (value == "curl" || value == "default") {
		config.SetHTTPUtil(make_shared_ptr<HTTPFSCurlUtil>(ConnectionCachingEnabled(context), context.db.get()));
		return;
	}
	if (value == "httplib") {
		DUCKDB_LOG_WARNING(context, "The 'httplib' client implementation is deprecated and will be removed in a future "
		                            "release; use 'curl' (the default) instead.");
		config.SetHTTPUtil(make_shared_ptr<HTTPFSUtil>(context.db.get()));
		return;
	}
#endif
	throw InvalidInputException("Unsupported option for httpfs_client_implementation, only `curl`, `httplib` "
	                            "and `default` are currently supported");
}

static void SetHTTPConnectionCaching(ClientContext &context, SetScope scope, Value &parameter) {
	RequireGlobalScope(scope, "httpfs_connection_caching");
#ifndef __EMSCRIPTEN__
	auto &config = DBConfig::GetConfig(context);
	auto &http_util = config.GetHTTPUtil();
	if (http_util.GetName() == "HTTPFS-Curl") {
		config.SetHTTPUtil(make_shared_ptr<HTTPFSCurlUtil>(BooleanValue::Get(parameter), context.db.get()));
	}
#endif
}

void HTTPSettings::Register(DBConfig &config) {
	config.AddExtensionOption("http_timeout", "HTTP timeout read/write/connection/retry (in seconds)",
	                          LogicalType::UBIGINT, Value::UBIGINT(HTTPParams::DEFAULT_TIMEOUT_SECONDS));
	config.AddExtensionOption("http_retries", "HTTP retries on I/O error", LogicalType::UBIGINT,
	                          Value::UBIGINT(HTTPParams::DEFAULT_RETRIES));
	config.AddExtensionOption("http_retry_wait_ms",
	                          "Base wait before the first retry; each retry waits a random time between 0 and the "
	                          "base, which grows by http_retry_backoff per retry and is capped at 20 seconds",
	                          LogicalType::UBIGINT, Value::UBIGINT(HTTPParams::DEFAULT_RETRY_WAIT_MS));
	config.AddExtensionOption("http_retry_backoff", "Factor by which the retry wait window grows after every retry",
	                          LogicalType::FLOAT, Value(HTTPParams::DEFAULT_RETRY_BACKOFF));
	config.AddExtensionOption(
	    "http_keep_alive",
	    "Keep alive connections. Setting this to false can help when running into connection failures",
	    LogicalType::BOOLEAN, Value(HTTPParams::DEFAULT_KEEP_ALIVE));
	config.AddExtensionOption("extra_http_headers", "Extra HTTP headers added to every request",
	                          LogicalType::MAP(LogicalType::VARCHAR, LogicalType::VARCHAR),
	                          Value::MAP(LogicalType::VARCHAR, LogicalType::VARCHAR, {}, {}), SetExtraHTTPHeaders,
	                          SetScope::GLOBAL);
	config.AddExtensionOption("force_download", "Forces upfront download of file", LogicalType::BOOLEAN, Value(false));
	config.AddExtensionOption("force_download_threshold",
	                          "Forces upfront download of files smaller than the given size in bytes",
	                          LogicalType::UBIGINT, Value::UBIGINT(0));
	config.AddExtensionOption("auto_fallback_to_full_download",
	                          "Allows automatically falling back to full file downloads when possible.",
	                          LogicalType::BOOLEAN, Value(true));
	config.AddExtensionOption("allow_asterisks_in_http_paths", "Allow '*' character in URLs users can query",
	                          LogicalType::BOOLEAN, Value(false));
	config.AddExtensionOption("enable_curl_server_cert_verification",
	                          "Enable server side certificate verification for CURL backend.", LogicalType::BOOLEAN,
	                          Value(true), nullptr, SetScope::SESSION, false, true);
	config.AddExtensionOption("enable_server_cert_verification", "Enable server side certificate verification.",
	                          LogicalType::BOOLEAN, Value(false));
	config.AddExtensionOption("ca_cert_file", "Path to a custom certificate file for self-signed certificates.",
	                          LogicalType::VARCHAR, Value(""), SetCACertFile);
	config.AddExtensionOption("unsafe_disable_etag_checks", "Disable checks on ETag consistency", LogicalType::BOOLEAN,
	                          Value(false), nullptr, SetScope::SESSION, true);
	config.AddExtensionOption("hf_max_per_page", "Debug option to limit number of items returned in list requests",
	                          LogicalType::UBIGINT, Value::UBIGINT(0), nullptr, SetScope::SESSION, true);
	config.AddExtensionOption("httpfs_client_implementation", "Select which HTTP client implementation is used",
	                          LogicalType::VARCHAR, "default", SetHTTPClientImplementation, SetScope::GLOBAL);
	config.AddExtensionOption("httpfs_connection_caching", "Enable connection caching for HTTP requests",
	                          LogicalType::BOOLEAN, Value::BOOLEAN(true), SetHTTPConnectionCaching, SetScope::GLOBAL);
}

void HTTPSettings::Initialize(DatabaseInstance &db) {
	auto &config = DBConfig::GetConfig(db);
	auto &http_util = config.GetHTTPUtil();
	if (http_util.GetName() == "HTTPFS-Wasm") {
		return;
	}
	if (http_util.GetName() == "WasmHTTPUtils") {
		config.SetHTTPUtil(make_shared_ptr<HTTPFSWasmUtil>(http_util, db));
		return;
	}
#ifndef __EMSCRIPTEN__
	config.SetHTTPUtil(make_shared_ptr<HTTPFSCurlUtil>(ConnectionCachingEnabled(config), db));
#else
	config.SetHTTPUtil(make_shared_ptr<HTTPFSUtil>(db));
#endif
}

} // namespace duckdb
