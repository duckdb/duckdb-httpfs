#pragma once

#include <cerrno>
#include <curl/curl.h>
#include <utility>

#include "http/httpfs_client.hpp"

namespace duckdb {
class HTTPLogger;
class FileOpener;
struct FileOpenerInfo;
class HTTPState;
class HTTPFSCurlClient;

//! Returns the CURLOPT_SSLVERSION value that pins the minimum TLS version to 1.2,
//! leaving the maximum at curl's default. Exposed for unit testing.
long GetCurlMinTLSVersion(); // NOLINT(google-runtime-int): curl option values are long

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
	explicit CURLHandle(bool use_native_ca, bool share_dns_cache = true);
	~CURLHandle();

public:
	operator CURL *() { // NOLINT(google-explicit-constructor)
		return curl;
	}
	CURLcode Execute() {
		errno = 0;
		auto result = curl_easy_perform(curl);
		execute_errno = errno;
		return result;
	}
	//! errno as the last transfer left it, telling apart failures curl reports by the step that failed.
	int GetExecuteErrno() const {
		return execute_errno;
	}
	template <class T>
	void SetOption(CURLoption option, T value) {
		auto result = curl_easy_setopt(curl, option, value);
		if (result != CURLE_OK) {
			throw IOException("Failed to set curl option %d: %s", static_cast<int>(option), curl_easy_strerror(result));
		}
	}
	uint16_t GetResponseCode();

private:
	CURL *curl = nullptr;
	int execute_errno = 0;
};

//! Owns a curl string list, which curl does not copy.
class CURLStringList {
public:
	CURLStringList() = default;
	CURLStringList(CURLStringList &&other) noexcept : list(other.list) {
		other.list = nullptr;
	}
	CURLStringList &operator=(CURLStringList &&other) noexcept {
		std::swap(list, other.list);
		return *this;
	}
	CURLStringList(const CURLStringList &) = delete;
	CURLStringList &operator=(const CURLStringList &) = delete;
	~CURLStringList() {
		if (list) {
			curl_slist_free_all(list);
		}
		list = nullptr;
	}

	curl_slist *Get() const {
		return list;
	}
	void Add(const string &entry) {
		auto new_list = curl_slist_append(list, entry.c_str());
		if (!new_list) {
			throw OutOfMemoryException("Failed to allocate a curl string list");
		}
		list = new_list;
	}

private:
	curl_slist *list = nullptr;
};

class CURLRequestHeaders : public CURLStringList {
public:
	using CURLStringList::Add;
	void Add(const string &name, const string &value) {
		if (HTTPFSHeaderValue::IsEmpty(value)) {
			Add(name + ";");
		} else {
			Add(name + ": " + value);
		}
	}
};

} // namespace duckdb
