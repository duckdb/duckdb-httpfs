#pragma once

#include "duckdb/common/http_util.hpp"
#include "duckdb/common/mutex.hpp"
#include "duckdb/logging/log_type.hpp"

namespace duckdb {

class HTTPFSInfoLogType : public LogType {
public:
	static constexpr const char *NAME = "HTTPFSInfo";
	static constexpr LogLevel LEVEL = LogLevel::LOG_INFO;

	HTTPFSInfoLogType() : LogType(NAME, LogLevel::LOG_INFO) {
	}

	static string ConstructLogMessage(const string &type, const string &host, const string &payload = "") {
		if (payload.empty()) {
			return "{\"type\":\"" + type + "\",\"host\":\"" + host + "\"}";
		}
		return "{\"type\":\"" + type + "\",\"host\":\"" + host + "\",\"payload\":\"" + payload + "\"}";
	}
};
class HTTPLogger;
class FileOpener;
struct FileOpenerInfo;
class HTTPState;

struct HTTPFSParams : public HTTPParams {
	HTTPFSParams(HTTPUtil &http_util) : HTTPParams(http_util) {
	}

	static constexpr bool DEFAULT_ENABLE_SERVER_CERT_VERIFICATION = false;
	static constexpr uint64_t DEFAULT_HF_MAX_PER_PAGE = 0;
	static constexpr bool DEFAULT_FORCE_DOWNLOAD = false;
	static constexpr bool AUTO_FALLBACK_TO_FULL_DOWNLOAD = true;

	bool force_download = DEFAULT_FORCE_DOWNLOAD;
	bool auto_fallback_to_full_download = AUTO_FALLBACK_TO_FULL_DOWNLOAD;
	bool enable_server_cert_verification = DEFAULT_ENABLE_SERVER_CERT_VERIFICATION;
	bool enable_curl_server_cert_verification = true;
	idx_t hf_max_per_page = DEFAULT_HF_MAX_PER_PAGE;
	string ca_cert_file;
	string bearer_token;
	bool unsafe_disable_etag_checks {false};
	bool s3_version_id_pinning {false};
	shared_ptr<HTTPState> state;
	string user_agent = {""};
	bool pre_merged_headers = false;
	idx_t force_download_threshold = 0;

	// Additional fields needs to be appended at the end and need to be propagated to duckdb-wasm
	// TODO: make this unnecessary
};

class HTTPClientConnectionCache {
public:
	unique_ptr<HTTPClient> Find(const string &base_url);
	void Store(unique_ptr<HTTPClient> &&client);
	void Clear();

private:
	mutex cache_lock {};
	std::vector<unique_ptr<HTTPClient>> entries;
};

class HTTPFSUtil : public HTTPUtil {
public:
	unique_ptr<HTTPParams> InitializeParameters(optional_ptr<FileOpener> opener,
	                                            optional_ptr<FileOpenerInfo> info) override;
	unique_ptr<HTTPClient> InitializeClient(HTTPParams &http_params, const string &proto_host_port) override;

	//! Clear any cached connections
	virtual void ClearCachedConnections();

	static unordered_map<string, string> ParseGetParameters(const string &text);
	static HTTPUtil &GetHTTPUtil(optional_ptr<FileOpener> opener);

	string GetName() const override;
};

#ifndef EMSCRIPTEN

class HTTPFSCurlUtil : public HTTPFSUtil {
public:
	unique_ptr<HTTPClient> InitializeClient(HTTPParams &http_params, const string &proto_host_port) override;
	void CloseClient(unique_ptr<HTTPClient> &&client) override;
	void ClearCachedConnections() override;
	unique_ptr<HTTPResponse> SendRequest(BaseRequest &request, unique_ptr<HTTPClient> &client) override;

	static unordered_map<string, string> ParseGetParameters(const string &text);

	string GetName() const override;

	//! Whether connection caching is enabled
	bool connection_caching_enabled = false;

private:
	//! Send request with connection caching (acquire from pool, run, store back)
	unique_ptr<HTTPResponse> CachingSendRequest(BaseRequest &request, unique_ptr<HTTPClient> &client);
	//! Send request without caching (delegates to HTTPUtil::SendRequest)
	unique_ptr<HTTPResponse> BaseSendRequest(BaseRequest &request, unique_ptr<HTTPClient> &client);

	bool EnableCaching(BaseRequest &request);
	HTTPClientConnectionCache connection_cache;
};

#endif

struct HeaderCollector {
	std::vector<HTTPHeaders> header_collection;
};

} // namespace duckdb
