#pragma once

#include <curl/curl.h>
#include <openssl/x509_vfy.h>
#include <functional>
#include <utility>

#include "duckdb/common/http_util.hpp"
#include "duckdb/common/mutex.hpp"

namespace duckdb {
class HTTPLogger;
class FileOpener;
struct FileOpenerInfo;
class HTTPState;
class CurlCertificateStoreCache {
public:
	struct FileIdentity {
		int64_t size = 0;
		int64_t modification_seconds = 0;
		int64_t modification_nanoseconds = 0;
		uint64_t device = 0;
		uint64_t file = 0;

		bool operator==(const FileIdentity &other) const;
	};

	using MetadataProvider = std::function<bool(const string &, FileIdentity &)>;
	using StoreLoader = std::function<CURLcode(const string &, X509_STORE *&)>;
	using Clock = std::function<int64_t()>;

	static constexpr int64_t DEFAULT_TIMEOUT_SECONDS = 24 * 60 * 60;

	CurlCertificateStoreCache();
	CurlCertificateStoreCache(MetadataProvider metadata_provider, StoreLoader store_loader, Clock clock,
	                          int64_t timeout_seconds = DEFAULT_TIMEOUT_SECONDS);
	~CurlCertificateStoreCache();

	//! Returns a reference-counted store. The caller owns the returned reference.
	CURLcode Acquire(const string &path, X509_STORE *&result);

	//! Whether the SSL_CTX callback can safely use the OpenSSL linked by this extension.
	static bool IsSupported();

private:
	struct Entry;

	shared_ptr<Entry> GetOrCreateEntry(const string &path);

	MetadataProvider metadata_provider;
	StoreLoader store_loader;
	Clock clock;
	int64_t timeout_seconds;
	annotated_mutex entries_lock;
	unordered_map<string, shared_ptr<Entry>> entries DUCKDB_GUARDED_BY(entries_lock);
};

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
public:
	CURLHandle(const string &token, const string &cert_path,
	           shared_ptr<CurlCertificateStoreCache> certificate_store_cache);
	~CURLHandle();

public:
	operator CURL *() { // NOLINT(google-explicit-constructor)
		return curl;
	}
	CURLcode Execute() {
		return curl_easy_perform(curl);
	}
	void SetVerifySSL(bool verify_ssl);

private:
	static CURLcode ConfigureSSLContext(CURL *curl, void *ssl_context, void *user_data);

	CURL *curl = nullptr;
	shared_ptr<CurlCertificateStoreCache> certificate_store_cache;
	string cert_path;
	bool uses_certificate_store_cache = false;
	bool verify_ssl = true;
};

class CURLRequestHeaders {
public:
	CURLRequestHeaders() {
	}
	CURLRequestHeaders(CURLRequestHeaders &&other) noexcept {
		headers = other.headers;
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

public:
	explicit operator bool() const {
		return headers != nullptr;
	}

	void Add(const string &header) {
		headers = curl_slist_append(headers, header.c_str());
	}

public:
	curl_slist *headers = nullptr;
};

} // namespace duckdb
