#include "http/curl_certificate_store_cache.hpp"

#include <openssl/crypto.h>
#include <chrono>
#include <cstring>
#include <sys/stat.h>

namespace duckdb {

struct CurlCertificateStoreCache::Entry {
	annotated_mutex lock;
	unique_ptr<X509_STORE, decltype(&X509_STORE_free)> store DUCKDB_GUARDED_BY(lock) {nullptr, X509_STORE_free};
	FileIdentity identity DUCKDB_GUARDED_BY(lock);
	int64_t loaded_at DUCKDB_GUARDED_BY(lock) = 0;
};

bool CurlCertificateStoreCache::FileIdentity::operator==(const FileIdentity &other) const {
	return size == other.size && modification_seconds == other.modification_seconds &&
	       modification_nanoseconds == other.modification_nanoseconds && device == other.device && file == other.file;
}

bool CurlCertificateStoreCache::ReadFileIdentity(const string &path, FileIdentity &result) {
	struct stat metadata;
	if (stat(path.c_str(), &metadata) != 0) {
		return false;
	}
	result.size = metadata.st_size;
	result.modification_seconds = metadata.st_mtime;
#if defined(__APPLE__)
	result.modification_nanoseconds = metadata.st_mtimespec.tv_nsec;
#elif defined(__linux__)
	result.modification_nanoseconds = metadata.st_mtim.tv_nsec;
#endif
	result.device = metadata.st_dev;
	result.file = metadata.st_ino;
	return true;
}

CURLcode CurlCertificateStoreCache::LoadStore(const string &path, X509_STORE *&result) {
	result = X509_STORE_new();
	if (!result) {
		return CURLE_OUT_OF_MEMORY;
	}
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
	if (!X509_STORE_load_file(result, path.c_str())) {
#else
	if (!X509_STORE_load_locations(result, path.c_str(), nullptr)) {
#endif
		X509_STORE_free(result);
		result = nullptr;
		return CURLE_SSL_CACERT_BADFILE;
	}
	unsigned long flags = X509_V_FLAG_TRUSTED_FIRST;
#ifdef X509_V_FLAG_PARTIAL_CHAIN
	flags |= X509_V_FLAG_PARTIAL_CHAIN;
#endif
	if (!X509_STORE_set_flags(result, flags)) {
		X509_STORE_free(result);
		result = nullptr;
		return CURLE_SSL_CACERT_BADFILE;
	}
	return CURLE_OK;
}

int64_t CurlCertificateStoreCache::MonotonicSeconds() {
	return std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now().time_since_epoch())
	    .count();
}

CurlCertificateStoreCache::CurlCertificateStoreCache()
    : CurlCertificateStoreCache(ReadFileIdentity, LoadStore, MonotonicSeconds) {
}

CurlCertificateStoreCache::CurlCertificateStoreCache(MetadataProvider metadata_provider_p, StoreLoader store_loader_p,
                                                     Clock clock_p, int64_t timeout_seconds_p)
    : metadata_provider(std::move(metadata_provider_p)), store_loader(std::move(store_loader_p)),
      clock(std::move(clock_p)), timeout_seconds(timeout_seconds_p) {
}

CurlCertificateStoreCache::~CurlCertificateStoreCache() = default;

shared_ptr<CurlCertificateStoreCache::Entry> CurlCertificateStoreCache::GetOrCreateEntry(const string &path) {
	shared_ptr<Entry> evicted;
	annotated_lock_guard<annotated_mutex> guard(entries_lock);
	auto entry = entries.find(path);
	if (entry != entries.end()) {
		return entry->second;
	}
	if (entries.size() >= MAX_ENTRIES) {
		auto victim = entries.begin();
		evicted = std::move(victim->second);
		entries.erase(victim);
	}
	auto result = make_shared_ptr<Entry>();
	entries.emplace(path, result);
	return result;
}

CURLcode CurlCertificateStoreCache::Acquire(const string &path, X509_STORE *&result) {
	result = nullptr;
	auto entry = GetOrCreateEntry(path);
	annotated_lock_guard<annotated_mutex> guard(entry->lock);
	FileIdentity current_identity;
	if (!metadata_provider(path, current_identity)) {
		return CURLE_SSL_CACERT_BADFILE;
	}
	const auto now = clock();
	const bool expired = entry->store && timeout_seconds >= 0 && now - entry->loaded_at >= timeout_seconds;
	if (!entry->store || !(entry->identity == current_identity) || expired) {
		X509_STORE *replacement = nullptr;
		auto load_result = store_loader(path, replacement);
		if (load_result != CURLE_OK) {
			if (replacement) {
				X509_STORE_free(replacement);
			}
			return load_result;
		}
		if (!replacement) {
			return CURLE_SSL_CACERT_BADFILE;
		}
		entry->store.reset(replacement);
		entry->identity = current_identity;
		entry->loaded_at = now;
	}
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
	if (!X509_STORE_up_ref(entry->store.get())) {
		return CURLE_OUT_OF_MEMORY;
	}
	result = entry->store.get();
	return CURLE_OK;
#else
	return CURLE_NOT_BUILT_IN;
#endif
}

bool CurlCertificateStoreCache::IsSupported(CURL *handle) {
#if !defined(_WIN32) && OPENSSL_VERSION_NUMBER >= 0x10100000L
	// A directory can supply additional trust anchors not present in the selected bundle.
#if LIBCURL_VERSION_NUM >= 0x075400
	char *ca_directory = nullptr;
	if (curl_easy_getinfo(handle, CURLINFO_CAPATH, &ca_directory) != CURLE_OK || (ca_directory && ca_directory[0])) {
		return false;
	}
#else
	return false;
#endif
	auto version = curl_version_info(CURLVERSION_NOW);
	if (!version || !version->ssl_version || !StringUtil::StartsWith(version->ssl_version, "OpenSSL/")) {
		return false;
	}
#if LIBCURL_VERSION_NUM >= 0x075700
	if (version->age >= CURLVERSION_ELEVENTH && version->feature_names) {
		for (auto feature = version->feature_names; *feature; feature++) {
			if (strcmp(*feature, "AppleSecTrust") == 0) {
				return false;
			}
		}
	}
#else
	return false;
#endif
	string linked_version = OpenSSL_version(OPENSSL_VERSION);
	if (!StringUtil::StartsWith(linked_version, "OpenSSL ")) {
		return false;
	}
	const auto prefix_length = strlen("OpenSSL ");
	auto version_end = linked_version.find(' ', prefix_length);
	auto expected = "OpenSSL/" + linked_version.substr(prefix_length, version_end - prefix_length);
	return version->ssl_version == expected;
#else
	return false;
#endif
}

} // namespace duckdb
