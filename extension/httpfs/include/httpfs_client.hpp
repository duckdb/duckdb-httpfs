#pragma once

#include "duckdb/common/http_util.hpp"
#include <curl/curl.h>

namespace duckdb {
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

	bool force_download = DEFAULT_FORCE_DOWNLOAD;
	bool enable_server_cert_verification = DEFAULT_ENABLE_SERVER_CERT_VERIFICATION;
	idx_t hf_max_per_page = DEFAULT_HF_MAX_PER_PAGE;
	string ca_cert_file;
	string bearer_token;
	shared_ptr<HTTPState> state;
};

class HTTPFSUtil : public HTTPUtil {
public:
	unique_ptr<HTTPParams> InitializeParameters(optional_ptr<FileOpener> opener,
	                                            optional_ptr<FileOpenerInfo> info) override;
	unique_ptr<HTTPClient> InitializeClient(HTTPParams &http_params, const string &proto_host_port) override;

	static unordered_map<string, string> ParseGetParameters(const string &text);
	static shared_ptr<HTTPUtil> GetHTTPUtil(optional_ptr<FileOpener> opener);

	string GetName() const override;
};

class HTTPFSCurlUtil : public HTTPFSUtil {
public:
	unique_ptr<HTTPClient> InitializeClient(HTTPParams &http_params, const string &proto_host_port) override;

	static unordered_map<string, string> ParseGetParameters(const string &text);

	string GetName() const override;
};

class CURLHandle {
public:
	CURLHandle(const string &token, const string &cert_path);
	~CURLHandle();

public:
	operator CURL *() {
		return curl;
	}
	CURLcode Execute() {
		return curl_easy_perform(curl);
	}

private:
	CURL *curl = NULL;
};

class CURLRequestHeaders {
public:
	CURLRequestHeaders(vector<std::string> &input) {
		for (auto &header : input) {
			Add(header);
		}
	}
	CURLRequestHeaders() {}

	~CURLRequestHeaders() {
		if (headers) {
			curl_slist_free_all(headers);
		}
		headers = NULL;
	}
	operator bool() const {
		return headers != NULL;
	}

public:
	void Add(const string &header) {
		headers = curl_slist_append(headers, header.c_str());
	}

public:
	curl_slist *headers = NULL;
};

struct HeaderCollector {
	std::vector<HTTPHeaders> header_collection;
};


} // namespace duckdb
