#pragma once

#include <curl/curl.h>

#include "duckdb/common/http_util.hpp"

namespace duckdb {
class HTTPLogger;
class FileOpener;
struct FileOpenerInfo;
class HTTPState;

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
	CURLRequestHeaders() {
	}

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

} // namespace duckdb
