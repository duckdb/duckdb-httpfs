#pragma once

#include <curl/curl.h>
#include <utility>

#include "http/httpfs_client.hpp"

namespace duckdb {
class HTTPLogger;
class FileOpener;
struct FileOpenerInfo;
class HTTPState;
class HTTPFSCurlClient;

class CURLURLHandle {
private:
	explicit CURLURLHandle(CURLU *handle_p);

public:
	CURLURLHandle();
	CURLURLHandle(const CURLURLHandle &other);
	~CURLURLHandle();

	CURLURLHandle &operator=(const CURLURLHandle &) = delete;

public:
	CURLU *Get() {
		return handle;
	}

private:
	CURLU *handle;
};

class CURLHandle {
private:
	CURLHandle();

public:
	CURLHandle(const string &token, const string &cert_path, bool use_native_ca,
	           shared_ptr<CurlCertificateStoreCache> certificate_store_cache = nullptr);
	~CURLHandle();

public:
	operator CURL *() { // NOLINT(google-explicit-constructor)
		return curl;
	}
	CURLcode Execute() {
		return curl_easy_perform(curl);
	}
	void SetVerifySSL(bool verify_ssl);
	template <class T>
	void SetOption(CURLoption option, T value) {
		auto result = curl_easy_setopt(curl, option, value);
		if (result != CURLE_OK) {
			throw IOException("Failed to set curl option %d: %s", static_cast<int>(option), curl_easy_strerror(result));
		}
	}
	uint16_t GetResponseCode();

private:
	static CURLcode ConfigureSSLContext(CURL *curl, void *ssl_context, void *user_data);

private:
	//! Curl transport and the immutable CA bundle selection.
	CURL *curl = nullptr;
	shared_ptr<CurlCertificateStoreCache> certificate_store_cache;
	string cert_path;

	//! Verification is performed by the callback only on the cached path.
	bool uses_certificate_store_cache = false;
	bool verify_ssl = true;
};

class CURLRequestHeaders {
	friend class HTTPFSCurlClient;

public:
	CURLRequestHeaders() = default;
	CURLRequestHeaders(CURLRequestHeaders &&other) noexcept : headers(other.headers) {
		other.headers = nullptr;
	}
	CURLRequestHeaders &operator=(CURLRequestHeaders &&other) noexcept {
		std::swap(headers, other.headers);
		return *this;
	}
	CURLRequestHeaders(const CURLRequestHeaders &) = delete;
	CURLRequestHeaders &operator=(const CURLRequestHeaders &) = delete;
	~CURLRequestHeaders() {
		if (headers) {
			curl_slist_free_all(headers);
		}
		headers = nullptr;
	}

private:
	curl_slist *Get() const {
		return headers;
	}

public:
	void Add(const string &header) {
		auto new_headers = curl_slist_append(headers, header.c_str());
		if (!new_headers) {
			throw OutOfMemoryException("Failed to allocate curl request headers");
		}
		headers = new_headers;
	}
	void Add(const string &name, const string &value) {
		if (HTTPFSHeaderValue::IsEmpty(value)) {
			Add(name + ";");
		} else {
			Add(name + ": " + value);
		}
	}

private:
	curl_slist *headers = nullptr;
};

} // namespace duckdb
