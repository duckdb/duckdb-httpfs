#pragma once

#include "duckdb/common/http_util.hpp"
#include "duckdb/common/mutex.hpp"

#include <curl/curl.h>
#include <openssl/x509_vfy.h>
#include <functional>

namespace duckdb {

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

public:
	CurlCertificateStoreCache();
	CurlCertificateStoreCache(MetadataProvider metadata_provider, StoreLoader store_loader, Clock clock,
	                          int64_t timeout_seconds = DEFAULT_TIMEOUT_SECONDS);
	~CurlCertificateStoreCache();

public:
	//! Returns a reference-counted store. The caller owns the returned reference.
	CURLcode Acquire(const string &path, X509_STORE *&result);

	//! Whether the SSL_CTX callback can safely use the OpenSSL linked by this extension.
	static bool IsSupported(CURL *handle);

private:
	struct Entry;
	static constexpr idx_t MAX_ENTRIES = 64;

	shared_ptr<Entry> GetOrCreateEntry(const string &path);

	static bool ReadFileIdentity(const string &path, FileIdentity &result);
	static CURLcode LoadStore(const string &path, X509_STORE *&result);
	static int64_t MonotonicSeconds();

private:
	//! File loading and freshness policy.
	MetadataProvider metadata_provider;
	StoreLoader store_loader;
	Clock clock;
	int64_t timeout_seconds;

	//! Shared entries; each entry serializes loading of its own bundle.
	annotated_mutex entries_lock;
	unordered_map<string, shared_ptr<Entry>> entries DUCKDB_GUARDED_BY(entries_lock);
};

} // namespace duckdb
