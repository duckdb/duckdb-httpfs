#define DUCKDB_EXTENSION_MAIN

#include "httpfs_extension.hpp"

#include "create_secret_functions.hpp"
#include "duckdb.hpp"
#include "s3fs.hpp"
#include "hffs.hpp"
#ifdef OVERRIDE_ENCRYPTION_UTILS
#include "crypto.hpp"
#endif // OVERRIDE_ENCRYPTION_UTILS

namespace duckdb {

static void SetHttpfsClientImplementation(DBConfig &config, const string &value) {
	if (config.http_util && config.http_util->GetName() == "WasmHTTPUtils") {
		if (value == "wasm" || value == "default") {
			// Already handled, do not override
			return;
		}
		throw InvalidInputException("Unsupported option for httpfs_client_implementation, only `wasm` and "
		                            "`default` are currently supported for duckdb-wasm");
	}
	if (value == "httplib" || value == "default") {
		if (!config.http_util || config.http_util->GetName() != "HTTPFSUtil") {
			config.http_util = make_shared_ptr<HTTPFSUtil>();
		}
		return;
	}
	throw InvalidInputException("Unsupported option for httpfs_client_implementation, only `curl`, `httplib` and "
	                            "`default` are currently supported");
}

static void LoadInternal(DatabaseInstance &instance) {
	auto &fs = instance.GetFileSystem();

	fs.RegisterSubSystem(make_uniq<HTTPFileSystem>());
	fs.RegisterSubSystem(make_uniq<HuggingFaceFileSystem>());
	fs.RegisterSubSystem(make_uniq<S3FileSystem>(BufferManager::GetBufferManager(instance)));

	auto &config = DBConfig::GetConfig(instance);

	// Global HTTP config
	// Single timeout value is used for all 4 types of timeouts, we could split it into 4 if users need that
	config.AddExtensionOption("http_timeout", "HTTP timeout read/write/connection/retry (in seconds)",
	                          LogicalType::UBIGINT, Value::UBIGINT(HTTPParams::DEFAULT_TIMEOUT_SECONDS));
	config.AddExtensionOption("http_retries", "HTTP retries on I/O error", LogicalType::UBIGINT, Value(3));
	config.AddExtensionOption("http_retry_wait_ms", "Time between retries", LogicalType::UBIGINT, Value(100));
	config.AddExtensionOption("force_download", "Forces upfront download of file", LogicalType::BOOLEAN, Value(false));
	// Reduces the number of requests made while waiting, for example retry_wait_ms of 50 and backoff factor of 2 will
	// result in wait times of  0 50 100 200 400...etc.
	config.AddExtensionOption("http_retry_backoff", "Backoff factor for exponentially increasing retry wait time",
	                          LogicalType::FLOAT, Value(4));
	config.AddExtensionOption(
	    "http_keep_alive",
	    "Keep alive connections. Setting this to false can help when running into connection failures",
	    LogicalType::BOOLEAN, Value(true));
	config.AddExtensionOption("enable_server_cert_verification", "Enable server side certificate verification.",
	                          LogicalType::BOOLEAN, Value(false));
	config.AddExtensionOption("ca_cert_file", "Path to a custom certificate file for self-signed certificates.",
	                          LogicalType::VARCHAR, Value(""));
	// Global S3 config
	config.AddExtensionOption("s3_region", "S3 Region", LogicalType::VARCHAR, Value("us-east-1"));
	config.AddExtensionOption("s3_access_key_id", "S3 Access Key ID", LogicalType::VARCHAR);
	config.AddExtensionOption("s3_secret_access_key", "S3 Access Key", LogicalType::VARCHAR);
	config.AddExtensionOption("s3_session_token", "S3 Session Token", LogicalType::VARCHAR);
	config.AddExtensionOption("s3_endpoint", "S3 Endpoint", LogicalType::VARCHAR);
	config.AddExtensionOption("s3_url_style", "S3 URL style", LogicalType::VARCHAR, Value("vhost"));
	config.AddExtensionOption("s3_use_ssl", "S3 use SSL", LogicalType::BOOLEAN, Value(true));
	config.AddExtensionOption("s3_kms_key_id", "S3 KMS Key ID", LogicalType::VARCHAR);
	config.AddExtensionOption("s3_sse_c_key", "S3 SSE-C Key", LogicalType::VARCHAR);
	config.AddExtensionOption("s3_sse_c_key_md5", "S3 SSE-C Key MD5", LogicalType::VARCHAR);
	config.AddExtensionOption("s3_url_compatibility_mode", "Disable Globs and Query Parameters on S3 URLs",
	                          LogicalType::BOOLEAN, Value(false));
	config.AddExtensionOption("s3_requester_pays", "S3 use requester pays mode", LogicalType::BOOLEAN, Value(false));

	// S3 Uploader config
	config.AddExtensionOption("s3_uploader_max_filesize", "S3 Uploader max filesize (between 50GB and 5TB)",
	                          LogicalType::VARCHAR, "800GB");
	config.AddExtensionOption("s3_uploader_max_parts_per_file", "S3 Uploader max parts per file (between 1 and 10000)",
	                          LogicalType::UBIGINT, Value(10000));
	config.AddExtensionOption("s3_uploader_thread_limit", "S3 Uploader global thread limit", LogicalType::UBIGINT,
	                          Value(50));

	// HuggingFace options
	config.AddExtensionOption("hf_max_per_page", "Debug option to limit number of items returned in list requests",
	                          LogicalType::UBIGINT, Value::UBIGINT(0));

	auto callback_httpfs_client_implementation = [](ClientContext &context, SetScope scope, Value &parameter) {
		auto &config = DBConfig::GetConfig(context);
		string value = StringValue::Get(parameter);
		SetHttpfsClientImplementation(config, value);
	};

	config.AddExtensionOption("httpfs_client_implementation", "Select which is the HTTPUtil implementation to be used",
	                          LogicalType::VARCHAR, "default", callback_httpfs_client_implementation);

	SetHttpfsClientImplementation(config, "default");

	auto provider = make_uniq<AWSEnvironmentCredentialsProvider>(config);
	provider->SetAll();

	CreateS3SecretFunctions::Register(instance);
	CreateBearerTokenFunctions::Register(instance);

#ifdef OVERRIDE_ENCRYPTION_UTILS
	// set pointer to OpenSSL encryption state
	config.encryption_util = make_shared_ptr<AESStateSSLFactory>();
#endif // OVERRIDE_ENCRYPTION_UTILS
}
void HttpfsExtension::Load(DuckDB &db) {
	LoadInternal(*db.instance);
}
std::string HttpfsExtension::Name() {
	return "httpfs";
}

std::string HttpfsExtension::Version() const {
#ifdef EXT_VERSION_HTTPFS
	return EXT_VERSION_HTTPFS;
#else
	return "";
#endif
}

} // namespace duckdb

extern "C" {

DUCKDB_EXTENSION_API void httpfs_init(duckdb::DatabaseInstance &db) {
	LoadInternal(db);
}

DUCKDB_EXTENSION_API const char *httpfs_version() {
	return duckdb::DuckDB::LibraryVersion();
}
}

#ifndef DUCKDB_EXTENSION_MAIN
#error DUCKDB_EXTENSION_MAIN not defined
#endif
