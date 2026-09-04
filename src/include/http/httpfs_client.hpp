#pragma once

#include "duckdb/common/http_util.hpp"
#include "duckdb/common/atomic.hpp"
#include "duckdb/common/array.hpp"
#include "duckdb/common/mutex.hpp"
#include "duckdb/common/vector.hpp"
#include "duckdb/logging/log_type.hpp"

namespace duckdb {

class HTTPFSInfoLogType : public LogType {
public:
	HTTPFSInfoLogType() : LogType(NAME, LogLevel::LOG_INFO) {
	}

public:
	static string ConstructLogMessage(const string &type, const string &host, const string &payload = "") {
		if (payload.empty()) {
			return "{\"type\":\"" + type + "\",\"host\":\"" + host + "\"}";
		}
		return "{\"type\":\"" + type + "\",\"host\":\"" + host + "\",\"payload\":\"" + payload + "\"}";
	}

public:
	static constexpr const char *NAME = "HTTPFSInfo";
	static constexpr LogLevel LEVEL = LogLevel::LOG_INFO;
};
class HTTPLogger;
class FileOpener;
struct FileOpenerInfo;
class HTTPState;
class HTTPFSUtil;
class HTTPException;

enum class HTTPClientReuseMode : uint8_t { SESSION_LOCAL, SHARED, NONE };

struct HTTPFSHeaderValue {
	static bool IsEmpty(const string &value) {
		for (const auto character : value) {
			if (character != ' ' && character != '\t') {
				return false;
			}
		}
		return true;
	}
};

struct HTTPFSParams : public HTTPParams {
public:
	explicit HTTPFSParams(HTTPUtil &http_util) : HTTPParams(http_util) {
		http_proxy_port = 0;
	}

public:
	unique_ptr<HTTPParams> Clone() const;

public:
	static constexpr bool DEFAULT_ENABLE_SERVER_CERT_VERIFICATION = false;
	static constexpr uint64_t DEFAULT_HF_MAX_PER_PAGE = 0;
	static constexpr bool DEFAULT_FORCE_DOWNLOAD = false;
	static constexpr bool AUTO_FALLBACK_TO_FULL_DOWNLOAD = true;

	//! Runtime parameters; append new fields and propagate them to duckdb-wasm
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
	idx_t force_download_threshold = 0;
	HTTPClientReuseMode client_reuse_mode = HTTPClientReuseMode::SESSION_LOCAL;
	optional_ptr<HTTPFSUtil> httpfs_util;
};

class HTTPClientConnectionCache {
public:
	unique_ptr<HTTPClient> Find(const string &base_url);
	void Store(unique_ptr<HTTPClient> &&client);
	void Clear();

private:
	struct Pool {
		annotated_mutex lock {};
		vector<unique_ptr<HTTPClient>> entries DUCKDB_GUARDED_BY(lock) {vector<unique_ptr<HTTPClient>>(POOL_SIZE)};
	};

public:
	static constexpr idx_t POOL_COUNT = 16;
	static constexpr idx_t POOL_SIZE = 32;
	static_assert((POOL_COUNT & (POOL_COUNT - 1)) == 0, "POOL_COUNT must be a power of two");

private:
	array<Pool, POOL_COUNT> pools {};
};

class HTTPFSUtil : public HTTPUtil {
public:
	unique_ptr<HTTPParams> InitializeParameters(optional_ptr<FileOpener> opener,
	                                            optional_ptr<FileOpenerInfo> info) override;
	unique_ptr<HTTPClient> InitializeClient(HTTPParams &http_params, const string &proto_host_port) override;

	//! Clear any cached connections
	virtual void ClearCachedConnections();
	virtual HTTPClientReuseMode GetClientReuseMode() const;

	static HTTPUtil &GetHTTPUtil(optional_ptr<FileOpener> opener);
	static const char *GetRequestMethod(RequestType request_type);
	static HTTPException GetHTTPStatusError(const HTTPResponse &response, RequestType request_type,
	                                        const string &operation, const string &display_url,
	                                        const string &details = "");

	string GetName() const override;
};

#ifndef EMSCRIPTEN

class HTTPFSCurlUtil : public HTTPFSUtil {
public:
	unique_ptr<HTTPClient> InitializeClient(HTTPParams &http_params, const string &proto_host_port) override;
	unique_ptr<HTTPClient> InitializeClientExtended(HTTPParams &http_params, const string &proto_host_port,
	                                                const HTTPClientInitializationOptions &options) override;
	void CloseClient(unique_ptr<HTTPClient> &&client) override;
	void ClearCachedConnections() override;
	HTTPClientReuseMode GetClientReuseMode() const override;
	void SetConnectionCachingEnabled(bool enabled);
	unique_ptr<HTTPResponse> SendRequest(BaseRequest &request, unique_ptr<HTTPClient> &client) override;

	string GetName() const override;

private:
	//! Send request with connection caching (acquire from pool, run, store back)
	unique_ptr<HTTPResponse> CachingSendRequest(BaseRequest &request, unique_ptr<HTTPClient> &client);
	//! Send request without caching (delegates to HTTPUtil::SendRequest)
	unique_ptr<HTTPResponse> BaseSendRequest(BaseRequest &request, unique_ptr<HTTPClient> &client);

	bool EnableCaching(const BaseRequest &request) const;
	bool ConnectionCachingEnabled() const;
	unique_ptr<HTTPClient> FindCachedClient(const string &base_url);
	void StoreCachedClient(unique_ptr<HTTPClient> &&client);

private:
	//! Shared connection-cache state
	atomic<bool> connection_caching_enabled {true};
	HTTPClientConnectionCache connection_cache;
};

#endif

} // namespace duckdb
