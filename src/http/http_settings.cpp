#include "http/http_settings.hpp"

#include "http/httpfs_client.hpp"
#include "duckdb/common/local_file_system.hpp"
#include "duckdb/main/client_context_file_opener.hpp"
#include "duckdb/main/config.hpp"

#ifndef EMSCRIPTEN
#include "http/httpfs_curl_client.hpp"
#endif

namespace duckdb {

static void SetCACertFile(ClientContext &context, SetScope, Value &parameter) {
	if (parameter.IsNull()) {
		throw InvalidInputException("NULL is not a valid option for ca_cert_file");
	}
	auto value = StringValue::Get(parameter);
	if (value.empty()) {
		parameter = Value("");
		return;
	}
	LocalFileSystem fs;
	ClientContextFileOpener opener(context);
	parameter = Value(fs.CanonicalizePath(value, opener));
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

static void SetHTTPClientImplementation(ClientContext &context, SetScope, Value &parameter) {
	auto &config = DBConfig::GetConfig(context);
	auto value = StringValue::Get(parameter);
	auto &http_util = config.GetHTTPUtil();
	if (http_util.GetName() == "WasmHTTPUtils") {
		if (value == "wasm" || value == "default") {
			return;
		}
		throw InvalidInputException("Unsupported option for httpfs_client_implementation, only `wasm` and "
		                            "`default` are currently supported for duckdb-wasm");
	}
#ifndef EMSCRIPTEN
	if (value == "curl" || value == "default") {
		config.SetHTTPUtil(make_shared_ptr<HTTPFSCurlUtil>());
		return;
	}
	if (value == "httplib") {
		config.SetHTTPUtil(make_shared_ptr<HTTPFSUtil>());
		return;
	}
#endif
	throw InvalidInputException("Unsupported option for httpfs_client_implementation, only `curl`, `httplib` "
	                            "and `default` are currently supported");
}

static void SetHTTPConnectionCaching(ClientContext &context, SetScope, Value &parameter) {
#ifndef EMSCRIPTEN
	auto &http_util = DBConfig::GetConfig(context).GetHTTPUtil();
	if (http_util.GetName() == "HTTPFS-Curl") {
		auto &curl_util = http_util.Cast<HTTPFSCurlUtil>();
		curl_util.SetConnectionCachingEnabled(BooleanValue::Get(parameter));
	}
#endif
}

void HTTPSettings::Register(DBConfig &config) {
	config.AddExtensionOption("http_timeout", "HTTP timeout read/write/connection/retry (in seconds)",
	                          LogicalType::UBIGINT, Value::UBIGINT(HTTPParams::DEFAULT_TIMEOUT_SECONDS));
	config.AddExtensionOption("http_retries", "HTTP retries on I/O error", LogicalType::UBIGINT,
	                          Value::UBIGINT(HTTPParams::DEFAULT_RETRIES));
	config.AddExtensionOption("http_retry_wait_ms", "Time between retries", LogicalType::UBIGINT,
	                          Value::UBIGINT(HTTPParams::DEFAULT_RETRY_WAIT_MS));
	config.AddExtensionOption("http_retry_backoff", "Backoff factor for exponentially increasing retry wait time",
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
	                          Value(true));
	config.AddExtensionOption("enable_server_cert_verification", "Enable server side certificate verification.",
	                          LogicalType::BOOLEAN, Value(false));
	config.AddExtensionOption("ca_cert_file", "Path to a custom certificate file for self-signed certificates.",
	                          LogicalType::VARCHAR, Value(""), SetCACertFile);
	config.AddExtensionOption("unsafe_disable_etag_checks", "Disable checks on ETag consistency", LogicalType::BOOLEAN,
	                          Value(false));
	config.AddExtensionOption("hf_max_per_page", "Debug option to limit number of items returned in list requests",
	                          LogicalType::UBIGINT, Value::UBIGINT(0));
	config.AddExtensionOption("httpfs_client_implementation", "Select which HTTP client implementation is used",
	                          LogicalType::VARCHAR, "default", SetHTTPClientImplementation);
	config.AddExtensionOption("httpfs_connection_caching", "Enable connection caching for HTTP requests",
	                          LogicalType::BOOLEAN, Value::BOOLEAN(true), SetHTTPConnectionCaching);
}

void HTTPSettings::Initialize(DBConfig &config) {
	auto &http_util = config.GetHTTPUtil();
	if (http_util.GetName() == "WasmHTTPUtils") {
		return;
	}
#ifndef EMSCRIPTEN
	config.SetHTTPUtil(make_shared_ptr<HTTPFSCurlUtil>());
#else
	config.SetHTTPUtil(make_shared_ptr<HTTPFSUtil>());
#endif
}

} // namespace duckdb
