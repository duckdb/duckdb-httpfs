#pragma once

#include "duckdb/main/http/http_util.hpp"
#include "duckdb/common/mutex.hpp"
#include "duckdb/logging/log_type.hpp"
#include "http/httpfs_transport.hpp"

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
class HTTPRequestSession;
struct HTTPFSParams;

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
	}

public:
	unique_ptr<HTTPParams> Clone() const;
	void RefreshTransportReuseDomain();
	void PrepareTransportReuseDomain();
	bool CanReuseTransport() const;
	bool VerifyServerCertificate() const;

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
	//! Ignore response freshness when validation is disabled or legacy cache reuse is requested.
	bool override_response_cache_policy {false};
	shared_ptr<HTTPState> state;
	string user_agent = {""};
	idx_t force_download_threshold = 0;

private:
	friend class HTTPFSUtil;

	void SetTransportReuseConfig(const HTTPFSConnectionConfig &config, bool transport_reusable);

private:
	//! Exact configuration captured with the current reuse domain.
	HTTPFSConnectionConfig transport_reuse_config;
	//! Whether the captured domain may reuse a client.
	bool transport_reusable = false;
};

class HTTPFSUtil : public HTTPUtil {
public:
	unique_ptr<HTTPParams> InitializeParameters(optional_ptr<FileOpener> opener,
	                                            optional_ptr<FileOpenerInfo> info) override;
	//! Read HTTPFS settings without publishing a transport reuse domain.
	static unique_ptr<HTTPFSParams> InitializeRawParameters(HTTPFSUtil &http_util, optional_ptr<FileOpener> opener,
	                                                        optional_ptr<FileOpenerInfo> info);
	unique_ptr<HTTPClient> InitializeClient(HTTPParams &http_params, const string &proto_host_port) override;
	void LogRequest(BaseRequest &request, optional_ptr<HTTPResponse> response) override;
	HTTPTransportReusePolicy GetTransportReusePolicy() const override;

	static HTTPUtil &GetHTTPUtil(optional_ptr<FileOpener> opener);
	static const char *GetRequestMethod(RequestType request_type);
	static HTTPException GetHTTPStatusError(const HTTPResponse &response, RequestType request_type,
	                                        const string &operation, const string &display_url,
	                                        const string &details = "");

	string GetName() const override;

private:
	friend struct HTTPFSParams;

	void SetTransportReuseDomain(HTTPFSParams &params);
	virtual bool GetDefaultVerifySSL(const HTTPFSParams &params) const;

private:
	//! Bound retained proxy credentials and lookup cost; overflow domains cannot reuse clients.
	static constexpr idx_t MAX_TRANSPORT_REUSE_DOMAINS = 256;
	//! Protects transport domain interning.
	annotated_mutex transport_reuse_lock;
	//! Exact reusable configurations retained by this provider.
	vector<HTTPFSConnectionConfig> transport_reuse_domains DUCKDB_GUARDED_BY(transport_reuse_lock);
	//! Next non-recycled transport domain identity.
	idx_t next_transport_reuse_domain DUCKDB_GUARDED_BY(transport_reuse_lock) = 1;
};

#ifndef EMSCRIPTEN

class HTTPFSCurlUtil : public HTTPFSUtil {
public:
	explicit HTTPFSCurlUtil(bool connection_caching_enabled_p = true);

public:
	unique_ptr<HTTPClient> InitializeClient(HTTPParams &http_params, const string &proto_host_port) override;
	HTTPTransportReusePolicy GetTransportReusePolicy() const override;

	string GetName() const override;

private:
	bool GetDefaultVerifySSL(const HTTPFSParams &params) const override;

private:
	const bool connection_caching_enabled;
};

#endif

} // namespace duckdb
