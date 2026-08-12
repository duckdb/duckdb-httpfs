#include "http/httpfs_client.hpp"
#include "http/http_state.hpp"
#include "duckdb/logging/logger.hpp"

#define CPPHTTPLIB_OPENSSL_SUPPORT

#include <curl/curl.h>
#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <chrono>
#include <cstring>
#include <new>
#include <sys/stat.h>
#include "duckdb/common/exception/http_exception.hpp"

#ifndef EMSCRIPTEN
#include "http/httpfs_curl_client.hpp"
#endif

namespace duckdb {

// we statically compile in libcurl, which means the cert file location of the build machine is the
// place curl will look. But not every distro has this file in the same location, so we search a
// number of common locations and use the first one we find.
static constexpr const char *CERT_FILE_LOCATIONS[] = {
    // Arch, Debian-based, Gentoo
    "/etc/ssl/certs/ca-certificates.crt",
    // RedHat 7 based
    "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
    // Redhat 6 based
    "/etc/pki/tls/certs/ca-bundle.crt",
    // OpenSUSE
    "/etc/ssl/ca-bundle.pem",
    // Alpine
    "/etc/ssl/cert.pem"};

//! Grab the first path that exists, from a list of well-known locations
static string SelectCURLCertPath() {
	for (const auto &ca_file : CERT_FILE_LOCATIONS) {
		struct stat buf;
		if (stat(ca_file, &buf) == 0) {
			return ca_file;
		}
	}
	return string();
}

struct CurlCertificateStoreCache::Entry {
	~Entry() {
		if (store) {
			X509_STORE_free(store);
		}
	}

	annotated_mutex lock;
	X509_STORE *store DUCKDB_GUARDED_BY(lock) = nullptr;
	FileIdentity identity DUCKDB_GUARDED_BY(lock);
	int64_t loaded_at DUCKDB_GUARDED_BY(lock) = 0;
};

bool CurlCertificateStoreCache::FileIdentity::operator==(const FileIdentity &other) const {
	return size == other.size && modification_seconds == other.modification_seconds &&
	       modification_nanoseconds == other.modification_nanoseconds && device == other.device && file == other.file;
}

static bool ReadCertificateFileIdentity(const string &path, CurlCertificateStoreCache::FileIdentity &result) {
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

static CURLcode LoadCertificateStore(const string &path, X509_STORE *&result) {
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

static int64_t CertificateStoreMonotonicSeconds() {
	return std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now().time_since_epoch())
	    .count();
}

CurlCertificateStoreCache::CurlCertificateStoreCache()
    : CurlCertificateStoreCache(ReadCertificateFileIdentity, LoadCertificateStore, CertificateStoreMonotonicSeconds) {
}

CurlCertificateStoreCache::CurlCertificateStoreCache(MetadataProvider metadata_provider_p, StoreLoader store_loader_p,
                                                     Clock clock_p, int64_t timeout_seconds_p)
    : metadata_provider(std::move(metadata_provider_p)), store_loader(std::move(store_loader_p)),
      clock(std::move(clock_p)), timeout_seconds(timeout_seconds_p) {
}

CurlCertificateStoreCache::~CurlCertificateStoreCache() = default;

shared_ptr<CurlCertificateStoreCache::Entry> CurlCertificateStoreCache::GetOrCreateEntry(const string &path) {
	annotated_lock_guard<annotated_mutex> guard(entries_lock);
	auto entry = entries.find(path);
	if (entry != entries.end()) {
		return entry->second;
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
		if (entry->store) {
			X509_STORE_free(entry->store);
		}
		entry->store = replacement;
		entry->identity = current_identity;
		entry->loaded_at = now;
	}
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
	if (!X509_STORE_up_ref(entry->store)) {
		return CURLE_OUT_OF_MEMORY;
	}
	result = entry->store;
	return CURLE_OK;
#else
	return CURLE_NOT_BUILT_IN;
#endif
}

bool CurlCertificateStoreCache::IsSupported() {
#if !defined(_WIN32) && OPENSSL_VERSION_NUMBER >= 0x10100000L
	auto version = curl_version_info(CURLVERSION_NOW);
	if (!version || !version->ssl_version || !StringUtil::StartsWith(version->ssl_version, "OpenSSL/")) {
		return false;
	}
	string linked_version = OpenSSL_version(OPENSSL_VERSION);
	if (!StringUtil::StartsWith(linked_version, "OpenSSL ")) {
		return false;
	}
	const auto prefix_length = strlen("OpenSSL ");
	auto version_end = linked_version.find(' ', prefix_length);
	auto expected = "OpenSSL/" + linked_version.substr(prefix_length, version_end - prefix_length);
	return StringUtil::StartsWith(version->ssl_version, expected);
#else
	return false;
#endif
}

static size_t RequestWriteCallback(void *contents, size_t size, size_t nmemb, void *userp) {
	auto total_size = size * nmemb;
	auto &result = *static_cast<string *>(userp);
	result.append(char_ptr_cast(contents), total_size);
	return total_size;
}

static size_t RequestHeaderCallback(void *contents, size_t size, size_t nmemb, void *userp) {
	auto total_size = size * nmemb;
	string header(char_ptr_cast(contents), total_size);
	auto &header_collection = *static_cast<HeaderCollector *>(userp);

	// Trim trailing \r\n
	if (!header.empty() && header.back() == '\n') {
		header.pop_back();
		if (!header.empty() && header.back() == '\r') {
			header.pop_back();
		}
	}

	// If header starts with HTTP/... curl has followed a redirect and we have a new Header,
	// so we push back a new header_collection and store headers from the redirect there.
	if (header.rfind("HTTP/", 0) == 0) {
		header_collection.header_collection.emplace_back();
		header_collection.header_collection.back().Insert("__RESPONSE_STATUS__", header);
	}

	idx_t colon_pos = header.find(':');

	if (colon_pos != string::npos) {
		// Split the string into two parts
		string part1 = header.substr(0, colon_pos);
		string part2 = header.substr(colon_pos + 1);
		if (part2.at(0) == ' ') {
			part2.erase(0, 1);
		}

		header_collection.header_collection.back().Insert(part1, part2);
	}
	// TODO: log headers that don't follow the header format

	return total_size;
}

CURLHandle::CURLHandle(const string &token, const string &cert_path_p,
                       shared_ptr<CurlCertificateStoreCache> certificate_store_cache_p)
    : certificate_store_cache(std::move(certificate_store_cache_p)), cert_path(cert_path_p) {
	curl = curl_easy_init();
	if (!curl) {
		throw InternalException("Failed to initialize curl");
	}
	if (!token.empty()) {
		curl_easy_setopt(curl, CURLOPT_XOAUTH2_BEARER, token.c_str());
		curl_easy_setopt(curl, CURLOPT_HTTPAUTH, CURLAUTH_BEARER);
	}
	uses_certificate_store_cache =
	    !cert_path.empty() && certificate_store_cache && CurlCertificateStoreCache::IsSupported();
	if (!cert_path.empty()) {
		if (uses_certificate_store_cache) {
			curl_easy_setopt(curl, CURLOPT_SSL_CTX_FUNCTION, ConfigureSSLContext);
			curl_easy_setopt(curl, CURLOPT_SSL_CTX_DATA, this);
		} else {
			curl_easy_setopt(curl, CURLOPT_CAINFO, cert_path.c_str());
		}
	}
	long ssl_options = CURLSSLOPT_AUTO_CLIENT_CERT;
	if (!uses_certificate_store_cache) {
		ssl_options |= CURLSSLOPT_NATIVE_CA;
	}
	curl_easy_setopt(curl, CURLOPT_SSL_OPTIONS, ssl_options);
}

CURLHandle::~CURLHandle() {
	curl_easy_cleanup(curl);
}

void CURLHandle::SetVerifySSL(bool verify_ssl_p) {
	verify_ssl = verify_ssl_p;
	// libcurl populates its X509 store before invoking CURLOPT_SSL_CTX_FUNCTION. On the cached OpenSSL path, tell
	// libcurl not to populate that redundant store; ConfigureSSLContext installs the shared store and enables peer
	// verification directly on the SSL_CTX instead.
	const bool curl_verifies_peer = verify_ssl && !uses_certificate_store_cache;
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, curl_verifies_peer ? 1L : 0L);
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, verify_ssl ? 2L : 0L);
}

CURLcode CURLHandle::ConfigureSSLContext(CURL *, void *ssl_context, void *user_data) {
	auto &handle = *static_cast<CURLHandle *>(user_data);
	if (!handle.verify_ssl) {
		return CURLE_OK;
	}
	try {
		X509_STORE *store = nullptr;
		auto result = handle.certificate_store_cache->Acquire(handle.cert_path, store);
		if (result != CURLE_OK) {
			return result;
		}
		auto context = static_cast<SSL_CTX *>(ssl_context);
		SSL_CTX_set_cert_store(context, store);
		SSL_CTX_set_verify(context, SSL_VERIFY_PEER, nullptr);
		return CURLE_OK;
	} catch (std::bad_alloc &) {
		return CURLE_OUT_OF_MEMORY;
	} catch (...) {
		return CURLE_SSL_CACERT_BADFILE;
	}
}

CURLURLHandle::CURLURLHandle() : CURLURLHandle(curl_url()) {
}

CURLURLHandle::CURLURLHandle(CURLU *handle_p) : handle(handle_p) {
	if (!handle) {
		throw InternalException("Failed to initialize CURL URL");
	}
}

CURLURLHandle::CURLURLHandle(const CURLURLHandle &other) : CURLURLHandle(curl_url_dup(other.handle)) {
}

CURLURLHandle::~CURLURLHandle() {
	curl_url_cleanup(handle);
}

struct RequestInfo {
	string url = "";
	string body = "";
	uint16_t response_code = 0;
	vector<HTTPHeaders> header_collection;
};

struct CURLGlobalState {
	annotated_mutex lock;
	idx_t client_count DUCKDB_GUARDED_BY(lock) = 0;
};

static CURLGlobalState &GetCURLGlobalState() {
	static CURLGlobalState state;
	return state;
}

class HTTPFSCurlClient : public HTTPClient {
private:
	struct ClientConfigurator {
		static void Configure(HTTPFSCurlClient &client, HTTPFSParams &params) {
			client.state = params.state;
			InitializeHandle(client, params);
			client.request_info = make_uniq<RequestInfo>();
			ConfigureConnection(client, params);
			ConfigureTimeoutsAndCallbacks(client, params);
			ConfigureProxy(client, params);
		}

	private:
		static void InitializeHandle(HTTPFSCurlClient &client, const HTTPFSParams &params) {
			auto cert_file_path = params.ca_cert_file;
			if (client.curl && client.stored_bearer_token == params.bearer_token &&
			    client.stored_cert_file_path == cert_file_path) {
				return;
			}
			HTTPFSCurlClient::InitCurlGlobal();
			client.stored_cert_file_path = cert_file_path;
			if (cert_file_path.empty()) {
				cert_file_path = SelectCURLCertPath();
			}
			client.curl = make_uniq<CURLHandle>(params.bearer_token, cert_file_path, client.certificate_store_cache);
			client.stored_bearer_token = params.bearer_token;
		}

		static void ConfigureConnection(HTTPFSCurlClient &client, const HTTPFSParams &params) {
			curl_easy_setopt(*client.curl, CURLOPT_FORBID_REUSE, params.keep_alive ? 0L : 1L);
			const bool verify_ssl =
			    params.override_verify_ssl ? params.verify_ssl : params.enable_curl_server_cert_verification;
			client.curl->SetVerifySSL(verify_ssl);
		}

		static void ConfigureTimeoutsAndCallbacks(HTTPFSCurlClient &client, const HTTPFSParams &params) {
			curl_easy_setopt(*client.curl, CURLOPT_CONNECTTIMEOUT, params.timeout);
			curl_easy_setopt(*client.curl, CURLOPT_TIMEOUT, 0L);
			curl_easy_setopt(*client.curl, CURLOPT_LOW_SPEED_LIMIT, 1024L);
			curl_easy_setopt(*client.curl, CURLOPT_LOW_SPEED_TIME, params.timeout);
			curl_easy_setopt(*client.curl, CURLOPT_ACCEPT_ENCODING, nullptr);
			curl_easy_setopt(*client.curl, CURLOPT_FOLLOWLOCATION, params.follow_location ? 1L : 0L);
			curl_easy_setopt(*client.curl, CURLOPT_HEADERFUNCTION, RequestHeaderCallback);
			curl_easy_setopt(*client.curl, CURLOPT_HEADERDATA, &client.request_info->header_collection);
			curl_easy_setopt(*client.curl, CURLOPT_WRITEFUNCTION, RequestWriteCallback);
			curl_easy_setopt(*client.curl, CURLOPT_WRITEDATA, &client.request_info->body);
		}

		static void ConfigureProxy(HTTPFSCurlClient &client, const HTTPFSParams &params) {
			curl_easy_setopt(*client.curl, CURLOPT_PROXY, nullptr);
			curl_easy_setopt(*client.curl, CURLOPT_PROXYUSERNAME, nullptr);
			curl_easy_setopt(*client.curl, CURLOPT_PROXYPASSWORD, nullptr);
			if (params.http_proxy.empty()) {
				return;
			}
			curl_easy_setopt(*client.curl, CURLOPT_PROXY,
			                 StringUtil::Format("%s:%d", params.http_proxy, params.http_proxy_port).c_str());
			if (!params.http_proxy_username.empty()) {
				curl_easy_setopt(*client.curl, CURLOPT_PROXYUSERNAME, params.http_proxy_username.c_str());
				curl_easy_setopt(*client.curl, CURLOPT_PROXYPASSWORD, params.http_proxy_password.c_str());
			}
		}
	};

	class GetTransferState {
	public:
		GetTransferState(HTTPFSCurlClient &client_p, GetRequestInfo &request_p)
		    : client(client_p), request(request_p), stream_content(bool(request.content_handler)) {
			curl_easy_setopt(*client.curl, CURLOPT_HEADERFUNCTION, HeaderCallback);
			curl_easy_setopt(*client.curl, CURLOPT_HEADERDATA, this);
			curl_easy_setopt(*client.curl, CURLOPT_WRITEFUNCTION, WriteCallback);
			curl_easy_setopt(*client.curl, CURLOPT_WRITEDATA, this);
		}

		~GetTransferState() {
			curl_easy_setopt(*client.curl, CURLOPT_HEADERFUNCTION, RequestHeaderCallback);
			curl_easy_setopt(*client.curl, CURLOPT_HEADERDATA, &client.request_info->header_collection);
			curl_easy_setopt(*client.curl, CURLOPT_WRITEFUNCTION, RequestWriteCallback);
			curl_easy_setopt(*client.curl, CURLOPT_WRITEDATA, &client.request_info->body);
		}

	public:
		unique_ptr<HTTPResponse> Finish(CURLcode result) {
			curl_easy_getinfo(*client.curl, CURLINFO_RESPONSE_CODE, &client.request_info->response_code);
			const bool include_body = !stream_content || client.request_info->response_code >= 400;
			unique_ptr<HTTPResponse> response;
			try {
				if (error) {
					std::rethrow_exception(error);
				}
				if (stopped) {
					result = CURLE_OK;
				}

				if (result == CURLE_OK && !response_handler_called) {
					response_handler_called = true;
					response = client.TransformResponseCurl(result, include_body);
					if (request.response_handler) {
						request.response_handler(*response);
					}
				}
			} catch (...) {
				RecordMetrics();
				throw;
			}
			RecordMetrics();
			if (!response) {
				response = client.TransformResponseCurl(result, include_body);
			}
			return response;
		}

	private:
		static size_t HeaderCallback(void *contents, size_t size, size_t nmemb, void *userp) {
			auto &state = *static_cast<GetTransferState *>(userp);
			const auto total_size = RequestHeaderCallback(
			    contents, size, nmemb, static_cast<void *>(&state.client.request_info->header_collection));
			if (total_size == 0 || !state.IsEndOfHeaders(contents, total_size) || state.IsProxyConnectResponse()) {
				return total_size;
			}
			try {
				if (!state.response_started && !state.StartResponse()) {
					return state.stopped ? 0 : total_size;
				}
			} catch (...) {
				state.error = std::current_exception();
				return 0;
			}
			return total_size;
		}

		static size_t WriteCallback(void *contents, size_t size, size_t nmemb, void *userp) {
			auto &state = *static_cast<GetTransferState *>(userp);
			const auto total_size = size * nmemb;
			try {
				return state.Write(contents, total_size);
			} catch (...) {
				state.error = std::current_exception();
				return 0;
			}
		}

		static bool IsEndOfHeaders(void *contents, idx_t size) {
			auto header = const_char_ptr_cast(contents);
			return (size == 2 && header[0] == '\r' && header[1] == '\n') || (size == 1 && header[0] == '\n');
		}

		bool IsProxyConnectResponse() const {
			if (client.request_info->header_collection.empty()) {
				return false;
			}
			auto &headers = client.request_info->header_collection.back();
			if (!headers.HasHeader("__RESPONSE_STATUS__")) {
				return false;
			}
			auto status = StringUtil::Lower(headers.GetHeaderValue("__RESPONSE_STATUS__"));
			return status.find("connection established") != string::npos;
		}

		size_t Write(void *contents, idx_t size) {
			if (!response_started && !StartResponse()) {
				return stopped ? 0 : size;
			}
			if (!stream_content || client.request_info->response_code >= 400) {
				client.request_info->body.append(char_ptr_cast(contents), size);
			} else if (!request.content_handler(const_data_ptr_cast(contents), size)) {
				stopped = true;
				return 0;
			}
			bytes_received += size;
			return size;
		}

		bool StartResponse() {
			long response_code; // NOLINT(google-runtime-int): required by curl_easy_getinfo
			if (curl_easy_getinfo(*client.curl, CURLINFO_RESPONSE_CODE, &response_code) != CURLE_OK) {
				throw IOException("Failed to read the HTTP response status");
			}
			client.request_info->response_code = NumericCast<uint16_t>(response_code);
			if (response_code < 200 || (response_code >= 300 && response_code < 400)) {
				return false;
			}
			response_started = true;
			if (!stream_content || response_code >= 400) {
				return true;
			}
			response_handler_called = true;
			if (request.response_handler) {
				auto response = client.TransformResponseCurl(CURLE_OK, false);
				if (!request.response_handler(*response)) {
					stopped = true;
					return false;
				}
			}
			return true;
		}

		void RecordMetrics() {
			request.bytes_received = bytes_received;
			double starttransfer_seconds = 0;
			if (curl_easy_getinfo(*client.curl, CURLINFO_STARTTRANSFER_TIME, &starttransfer_seconds) == CURLE_OK &&
			    starttransfer_seconds > 0) {
				request.have_time_to_fst_byte = true;
				request.time_to_fst_byte_sec = starttransfer_seconds;
			}

			if (client.state) {
				client.state->total_bytes_received += bytes_received;
			}
		}

	private:
		HTTPFSCurlClient &client;
		GetRequestInfo &request;
		const bool stream_content;
		std::exception_ptr error;
		idx_t bytes_received = 0;
		bool response_started = false;
		bool response_handler_called = false;
		bool stopped = false;
	};

public:
	HTTPFSCurlClient(HTTPFSParams &http_params, const string &proto_host_port,
	                 shared_ptr<CurlCertificateStoreCache> certificate_store_cache_p)
	    : HTTPClient(proto_host_port), certificate_store_cache(std::move(certificate_store_cache_p)) {
		string normalized_path = NormalizePathToBeAdded(proto_host_port);
		curl_url_set(curl_base_url.Get(), CURLUPART_URL, normalized_path.c_str(), 0);
		stored_bearer_token = "";
		stored_cert_file_path = "";
		Initialize(http_params);
	}
	~HTTPFSCurlClient() override {
		DestroyCurlGlobal();
	}

public:
	static string NormalizePathToBeAdded(string added_path) {
		while (added_path.size() > 2) {
			if (StringUtil::StartsWith(added_path, "//")) {
				added_path = added_path.substr(1);
			} else if (StringUtil::StartsWith(added_path, "./")) {
				added_path = added_path.substr(1);
			} else {
				break;
			}
		}

		return added_path;
	}
	void Initialize(HTTPParams &http_p) override {
		auto &http_params = http_p.Cast<HTTPFSParams>();
		ClientConfigurator::Configure(*this, http_params);
	}
	static void AddUserAgentIfAvailable(HTTPFSParams &http_params, HTTPHeaders &header_map) {
		if (!http_params.user_agent.empty()) {
			header_map.Insert("User-Agent", http_params.user_agent);
		}
	}

	unique_ptr<HTTPResponse> Get(GetRequestInfo &info) override {
		AddUserAgentIfAvailable(info.params.Cast<HTTPFSParams>(), info.headers);
		ResetRequestInfo();
		if (state) {
			state->get_count++;
		}

		auto curl_headers = TransformHeadersCurl(info.headers, info.params);
		request_info->url = info.url;

		CURLcode res;
		{
			curl_easy_setopt(*curl, CURLOPT_NOBODY, 0L);
			curl_easy_setopt(*curl, CURLOPT_HTTPGET, 1L);
			CURLURLHandle url(curl_base_url);

			string normalized_path = NormalizePathToBeAdded(info.path);
			curl_url_set(url.Get(), CURLUPART_URL, normalized_path.c_str(), 0);

			curl_easy_setopt(*curl, CURLOPT_URL, nullptr);
			curl_easy_setopt(*curl, CURLOPT_CURLU, url.Get());
			curl_easy_setopt(*curl, CURLOPT_HTTPHEADER, curl_headers ? curl_headers.headers : nullptr);
			GetTransferState transfer(*this, info);
			res = curl->Execute();
			return transfer.Finish(res);
		}
	}

	unique_ptr<HTTPResponse> Put(PutRequestInfo &info) override {
		AddUserAgentIfAvailable(info.params.Cast<HTTPFSParams>(), info.headers);
		ResetRequestInfo();
		if (state) {
			state->put_count++;
			state->total_bytes_sent += info.buffer_in_len;
		}

		auto curl_headers = TransformHeadersCurl(info.headers, info.params);
		// Add content type header from info
		curl_headers.Add("Content-Type: " + info.content_type);
		// transform parameters
		request_info->url = info.url;

		CURLcode res;
		{
			CURLURLHandle url(curl_base_url);

			string normalized_path = NormalizePathToBeAdded(info.path);
			curl_url_set(url.Get(), CURLUPART_URL, normalized_path.c_str(), 0);

			curl_easy_setopt(*curl, CURLOPT_URL, nullptr);
			curl_easy_setopt(*curl, CURLOPT_CURLU, url.Get());

			// Perform PUT
			curl_easy_setopt(*curl, CURLOPT_CUSTOMREQUEST, "PUT");
			// Include PUT body
			curl_easy_setopt(*curl, CURLOPT_POSTFIELDS, const_char_ptr_cast(info.buffer_in));
			curl_easy_setopt(*curl, CURLOPT_POSTFIELDSIZE_LARGE, NumericCast<curl_off_t>(info.buffer_in_len));

			// Apply headers
			curl_easy_setopt(*curl, CURLOPT_HTTPHEADER, curl_headers ? curl_headers.headers : nullptr);

			res = curl->Execute();
			curl_easy_setopt(*curl, CURLOPT_CUSTOMREQUEST, nullptr);
			curl_easy_setopt(*curl, CURLOPT_POSTFIELDS, nullptr);
			curl_easy_setopt(*curl, CURLOPT_POSTFIELDSIZE_LARGE, static_cast<curl_off_t>(0));
		}

		curl_easy_getinfo(*curl, CURLINFO_RESPONSE_CODE, &request_info->response_code);

		return TransformResponseCurl(res);
	}

	unique_ptr<HTTPResponse> Head(HeadRequestInfo &info) override {
		AddUserAgentIfAvailable(info.params.Cast<HTTPFSParams>(), info.headers);
		ResetRequestInfo();
		if (state) {
			state->head_count++;
		}

		auto curl_headers = TransformHeadersCurl(info.headers, info.params);
		request_info->url = info.url;
		// transform parameters

		CURLcode res;
		{
			// Perform HEAD request instead of GET
			curl_easy_setopt(*curl, CURLOPT_NOBODY, 1L);
			curl_easy_setopt(*curl, CURLOPT_HTTPGET, 0L);

			CURLURLHandle url(curl_base_url);

			string normalized_path = NormalizePathToBeAdded(info.path);
			curl_url_set(url.Get(), CURLUPART_URL, normalized_path.c_str(), 0);

			curl_easy_setopt(*curl, CURLOPT_URL, nullptr);
			curl_easy_setopt(*curl, CURLOPT_CURLU, url.Get());

			// Add headers if any
			curl_easy_setopt(*curl, CURLOPT_HTTPHEADER, curl_headers ? curl_headers.headers : nullptr);

			// Execute HEAD request
			res = curl->Execute();
			curl_easy_setopt(*curl, CURLOPT_NOBODY, 0L);
			curl_easy_setopt(*curl, CURLOPT_HTTPGET, 1L);
		}

		curl_easy_getinfo(*curl, CURLINFO_RESPONSE_CODE, &request_info->response_code);
		return TransformResponseCurl(res);
	}

	unique_ptr<HTTPResponse> Delete(DeleteRequestInfo &info) override {
		AddUserAgentIfAvailable(info.params.Cast<HTTPFSParams>(), info.headers);
		ResetRequestInfo();
		if (state) {
			state->delete_count++;
		}
		auto curl_headers = TransformHeadersCurl(info.headers, info.params);
		// transform parameters
		request_info->url = info.url;

		CURLcode res;
		{
			CURLURLHandle url(curl_base_url);

			string normalized_path = NormalizePathToBeAdded(info.path);
			curl_url_set(url.Get(), CURLUPART_URL, normalized_path.c_str(), 0);

			curl_easy_setopt(*curl, CURLOPT_URL, nullptr);
			curl_easy_setopt(*curl, CURLOPT_CURLU, url.Get());

			// Set DELETE request method
			curl_easy_setopt(*curl, CURLOPT_CUSTOMREQUEST, "DELETE");

			// Add headers if any
			curl_easy_setopt(*curl, CURLOPT_HTTPHEADER, curl_headers ? curl_headers.headers : nullptr);

			// Execute DELETE request
			res = curl->Execute();
			curl_easy_setopt(*curl, CURLOPT_CUSTOMREQUEST, nullptr);
		}

		// Get HTTP response status code
		curl_easy_getinfo(*curl, CURLINFO_RESPONSE_CODE, &request_info->response_code);
		return TransformResponseCurl(res);
	}

	unique_ptr<HTTPResponse> Options(OptionsRequestInfo &info) override {
		ResetRequestInfo();
		auto curl_headers = TransformHeadersCurl(info.headers, info.params);
		request_info->url = info.url;

		CURLcode res;
		{
			CURLURLHandle url(curl_base_url);

			string normalized_path = NormalizePathToBeAdded(info.path);
			curl_url_set(url.Get(), CURLUPART_URL, normalized_path.c_str(), 0);

			curl_easy_setopt(*curl, CURLOPT_URL, nullptr);
			curl_easy_setopt(*curl, CURLOPT_CURLU, url.Get());

			curl_easy_setopt(*curl, CURLOPT_CUSTOMREQUEST, "OPTIONS");

			curl_easy_setopt(*curl, CURLOPT_HTTPHEADER, curl_headers ? curl_headers.headers : nullptr);

			res = curl->Execute();
			curl_easy_setopt(*curl, CURLOPT_CUSTOMREQUEST, nullptr);
		}

		curl_easy_getinfo(*curl, CURLINFO_RESPONSE_CODE, &request_info->response_code);
		return TransformResponseCurl(res);
	}

	unique_ptr<HTTPResponse> Post(PostRequestInfo &info) override {
		AddUserAgentIfAvailable(info.params.Cast<HTTPFSParams>(), info.headers);
		ResetRequestInfo();
		if (state) {
			state->post_count++;
			state->total_bytes_sent += info.buffer_in_len;
		}

		auto curl_headers = TransformHeadersCurl(info.headers, info.params);
		if (!info.headers.HasHeader("Content-Type")) {
			const string content_type = "Content-Type: application/octet-stream";
			curl_headers.Add(content_type.c_str());
		}
		// transform parameters
		request_info->url = info.url;

		CURLcode res;
		{
			CURLURLHandle url(curl_base_url);

			string normalized_path = NormalizePathToBeAdded(info.path);
			curl_url_set(url.Get(), CURLUPART_URL, normalized_path.c_str(), 0);

			curl_easy_setopt(*curl, CURLOPT_URL, nullptr);
			curl_easy_setopt(*curl, CURLOPT_CURLU, url.Get());
			if (info.send_post_as_get_request) {
				curl_easy_setopt(*curl, CURLOPT_CUSTOMREQUEST, "GET");
			} else {
				curl_easy_setopt(*curl, CURLOPT_POST, 1L);
			}
			// Set POST body
			curl_easy_setopt(*curl, CURLOPT_POSTFIELDS, const_char_ptr_cast(info.buffer_in));
			curl_easy_setopt(*curl, CURLOPT_POSTFIELDSIZE, info.buffer_in_len);

			// Add headers if any
			curl_easy_setopt(*curl, CURLOPT_HTTPHEADER, curl_headers ? curl_headers.headers : nullptr);

			// Execute POST request
			res = curl->Execute();
			curl_easy_setopt(*curl, CURLOPT_CUSTOMREQUEST, nullptr);
			curl_easy_setopt(*curl, CURLOPT_POSTFIELDS, nullptr);
			curl_easy_setopt(*curl, CURLOPT_POSTFIELDSIZE, 0);
			curl_easy_setopt(*curl, CURLOPT_POST, 0L);
		}

		curl_easy_getinfo(*curl, CURLINFO_RESPONSE_CODE, &request_info->response_code);
		info.buffer_out = request_info->body;

		const idx_t bytes_received = request_info->body.size();
		if (state) {
			state->total_bytes_received += bytes_received;
		}

		// Construct HTTPResponse
		return TransformResponseCurl(res);
	}

	void Cleanup() override {
		// Release any buffers retained from the last request before this client is parked in the connection cache.
		request_info = make_uniq<RequestInfo>();
	}

private:
	static CURLRequestHeaders TransformHeadersCurl(const HTTPHeaders &header_map, const HTTPParams &params) {
		auto &httpfs_params = params.Cast<HTTPFSParams>();

		CURLRequestHeaders curl_headers;
		for (auto &entry : header_map) {
			curl_headers.Add(entry.first + ": " + entry.second);
		}
		if (!httpfs_params.pre_merged_headers) {
			for (auto &entry : params.extra_headers) {
				curl_headers.Add(entry.first + ": " + entry.second);
			}
		}
		return curl_headers;
	}

	void ResetRequestInfo() {
		// clear headers after transform
		request_info->header_collection.clear();
		// reset request info.
		request_info->body = "";
		request_info->url = "";
		request_info->response_code = 0;
	}

	unique_ptr<HTTPResponse> TransformResponseCurl(CURLcode res, bool include_body = true) {
		auto status_code = HTTPStatusCode(request_info->response_code);
		auto response = make_uniq<HTTPResponse>(status_code);
		if (res != CURLcode::CURLE_OK) {
			response->request_error = curl_easy_strerror(res);
			return response;
		}
		if (include_body) {
			response->body = request_info->body;
		}
		response->url = request_info->url;
		response->reason = HTTPUtil::GetStatusMessage(HTTPUtil::ToStatusCode(request_info->response_code));
		if (!request_info->header_collection.empty()) {
			for (auto &header : request_info->header_collection.back()) {
				// We should not return __RESPONSE_STATUS__ to the user. It's only there for debugging.
				if (header.first == "__RESPONSE_STATUS__") {
					continue;
				}
				response->headers.Insert(header.first, header.second);
			}
		}
		// ResetRequestInfo();
		return response;
	}

	static void InitCurlGlobal() {
		auto &state = GetCURLGlobalState();
		annotated_lock_guard<annotated_mutex> lock(state.lock);
		if (state.client_count == 0) {
			curl_global_init(CURL_GLOBAL_DEFAULT);
		}
		++state.client_count;
	}

	static void DestroyCurlGlobal() {
		// TODO: when to call curl_global_cleanup()
		// calling it on client destruction causes SSL errors when verification is on (due to many requests).
		// if (state.client_count == 0) {
		// 	throw InternalException("Destroying Httpfs client that did not initialize CURL");
		// }
		// --state.client_count;
		// if (state.client_count == 0) {
		// 	curl_global_cleanup();
		// }
	}

private:
	unique_ptr<CURLHandle> curl;
	optional_ptr<HTTPState> state;
	unique_ptr<RequestInfo> request_info;
	CURLURLHandle curl_base_url;
	string stored_bearer_token;
	string stored_cert_file_path;
	shared_ptr<CurlCertificateStoreCache> certificate_store_cache;
};

unique_ptr<HTTPClient> HTTPFSCurlUtil::InitializeClient(HTTPParams &http_params, const string &proto_host_port) {
	if (connection_caching_enabled) {
		auto client = connection_cache.Find(proto_host_port);
		if (client) {
			if (http_params.logger &&
			    http_params.logger->ShouldLog(HTTPFSInfoLogType::NAME, HTTPFSInfoLogType::LEVEL)) {
				http_params.logger->WriteLog(
				    HTTPFSInfoLogType::NAME, HTTPFSInfoLogType::LEVEL,
				    HTTPFSInfoLogType::ConstructLogMessage("connection_cache_hit", proto_host_port));
			}
			client->Initialize(http_params);
			return client;
		}
		if (http_params.logger && http_params.logger->ShouldLog(HTTPFSInfoLogType::NAME, HTTPFSInfoLogType::LEVEL)) {
			http_params.logger->WriteLog(
			    HTTPFSInfoLogType::NAME, HTTPFSInfoLogType::LEVEL,
			    HTTPFSInfoLogType::ConstructLogMessage("connection_cache_miss", proto_host_port));
		}
	}
	auto client =
	    make_uniq<HTTPFSCurlClient>(http_params.Cast<HTTPFSParams>(), proto_host_port, certificate_store_cache);
	return std::move(client);
}

string HTTPFSCurlUtil::GetName() const {
	return "HTTPFS-Curl";
}

} // namespace duckdb
