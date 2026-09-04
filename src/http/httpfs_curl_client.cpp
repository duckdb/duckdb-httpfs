#include "http/httpfs_client.hpp"
#include "http/http_state.hpp"
#include "duckdb/logging/logger.hpp"

#define CPPHTTPLIB_OPENSSL_SUPPORT

#include <curl/curl.h>
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

static size_t RequestWriteCallback(void *contents, size_t size, size_t nmemb, void *userp) {
	auto total_size = size * nmemb;
	auto &result = *static_cast<string *>(userp);
	result.append(char_ptr_cast(contents), total_size);
	return total_size;
}

static size_t RequestHeaderCallback(void *contents, size_t size, size_t nmemb, void *userp) {
	auto total_size = size * nmemb;
	string header(char_ptr_cast(contents), total_size);
	auto &header_collection = *static_cast<vector<HTTPHeaders> *>(userp);

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
		header_collection.emplace_back();
		header_collection.back().Insert("__RESPONSE_STATUS__", header);
	}

	idx_t colon_pos = header.find(':');

	if (colon_pos != string::npos) {
		if (header_collection.empty()) {
			header_collection.emplace_back();
		}
		auto name = header.substr(0, colon_pos);
		auto value = header.substr(colon_pos + 1);
		if (!value.empty() && value.front() == ' ') {
			value.erase(0, 1);
		}
		header_collection.back().Append(std::move(name), std::move(value));
	}
	// TODO: log headers that don't follow the header format

	return total_size;
}

CURLHandle::CURLHandle(const string &token, const string &cert_path) {
	curl = curl_easy_init();
	if (!curl) {
		throw InternalException("Failed to initialize curl");
	}
	if (!token.empty()) {
		curl_easy_setopt(curl, CURLOPT_XOAUTH2_BEARER, token.c_str());
		curl_easy_setopt(curl, CURLOPT_HTTPAUTH, CURLAUTH_BEARER);
	}
	if (!cert_path.empty()) {
		curl_easy_setopt(curl, CURLOPT_CAINFO, cert_path.c_str());
	}
	curl_easy_setopt(curl, CURLOPT_SSL_OPTIONS, CURLSSLOPT_AUTO_CLIENT_CERT | CURLSSLOPT_NATIVE_CA);
	curl_easy_setopt(curl, CURLOPT_PATH_AS_IS, 1L);
}

CURLHandle::~CURLHandle() {
	curl_easy_cleanup(curl);
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
			client.curl = make_uniq<CURLHandle>(params.bearer_token, cert_file_path);
			client.stored_bearer_token = params.bearer_token;
		}

		static void ConfigureConnection(HTTPFSCurlClient &client, const HTTPFSParams &params) {
			curl_easy_setopt(*client.curl, CURLOPT_FORBID_REUSE, params.keep_alive ? 0L : 1L);
			const bool verify_ssl =
			    params.override_verify_ssl ? params.verify_ssl : params.enable_curl_server_cert_verification;
			curl_easy_setopt(*client.curl, CURLOPT_SSL_VERIFYPEER, verify_ssl ? 1L : 0L);
			curl_easy_setopt(*client.curl, CURLOPT_SSL_VERIFYHOST, verify_ssl ? 2L : 0L);
		}

		static void ConfigureTimeoutsAndCallbacks(HTTPFSCurlClient &client, const HTTPFSParams &params) {
			curl_easy_setopt(*client.curl, CURLOPT_CONNECTTIMEOUT, params.timeout);
			curl_easy_setopt(*client.curl, CURLOPT_TIMEOUT, 0L);
			curl_easy_setopt(*client.curl, CURLOPT_LOW_SPEED_LIMIT, 1024L);
			curl_easy_setopt(*client.curl, CURLOPT_LOW_SPEED_TIME, params.timeout);
			curl_easy_setopt(*client.curl, CURLOPT_ACCEPT_ENCODING, nullptr);
			curl_easy_setopt(*client.curl, CURLOPT_FOLLOWLOCATION, params.follow_location ? 1L : 0L);
			curl_easy_setopt(*client.curl, CURLOPT_SUPPRESS_CONNECT_HEADERS, 1L);
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
			if (total_size == 0 || !state.IsEndOfHeaders(contents, total_size)) {
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
				client.state->RecordBytesReceived(bytes_received);
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
	HTTPFSCurlClient(HTTPFSParams &http_params, const string &proto_host_port) : HTTPClient(proto_host_port) {
		auto result = curl_url_set(curl_base_url.Get(), CURLUPART_URL, proto_host_port.c_str(), 0);
		if (result != CURLUE_OK) {
			throw IOException("Failed to initialize curl URL: %s", curl_url_strerror(result));
		}
		stored_bearer_token = "";
		stored_cert_file_path = "";
		Initialize(http_params);
	}
	~HTTPFSCurlClient() override {
		DestroyCurlGlobal();
	}

public:
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
			state->RecordRequest(RequestType::GET_REQUEST);
		}

		auto curl_headers = TransformHeadersCurl(info.headers, info.params);
		request_info->url = info.url;

		CURLcode res;
		{
			curl_easy_setopt(*curl, CURLOPT_NOBODY, 0L);
			curl_easy_setopt(*curl, CURLOPT_HTTPGET, 1L);
			CURLURLHandle url(curl_base_url);
			SetRequestURL(url, info.url, info.path);

			curl_easy_setopt(*curl, CURLOPT_URL, nullptr);
			curl_easy_setopt(*curl, CURLOPT_CURLU, url.Get());
			curl_easy_setopt(*curl, CURLOPT_HTTPHEADER, curl_headers.Get());
			GetTransferState transfer(*this, info);
			res = curl->Execute();
			return transfer.Finish(res);
		}
	}

	unique_ptr<HTTPResponse> Put(PutRequestInfo &info) override {
		AddUserAgentIfAvailable(info.params.Cast<HTTPFSParams>(), info.headers);
		ResetRequestInfo();
		if (state) {
			state->RecordRequest(RequestType::PUT_REQUEST);
			state->RecordBytesSent(info.buffer_in_len);
		}

		auto curl_headers = TransformHeadersCurl(info.headers, info.params);
		// Add content type header from info
		curl_headers.Add("Content-Type: " + info.content_type);
		// transform parameters
		request_info->url = info.url;

		CURLcode res;
		{
			CURLURLHandle url(curl_base_url);
			SetRequestURL(url, info.url, info.path);

			curl_easy_setopt(*curl, CURLOPT_URL, nullptr);
			curl_easy_setopt(*curl, CURLOPT_CURLU, url.Get());

			// Perform PUT
			curl_easy_setopt(*curl, CURLOPT_CUSTOMREQUEST, "PUT");
			// Include PUT body
			curl_easy_setopt(*curl, CURLOPT_POSTFIELDS, const_char_ptr_cast(info.buffer_in));
			curl_easy_setopt(*curl, CURLOPT_POSTFIELDSIZE_LARGE, NumericCast<curl_off_t>(info.buffer_in_len));

			// Apply headers
			curl_easy_setopt(*curl, CURLOPT_HTTPHEADER, curl_headers.Get());

			res = curl->Execute();
			curl_easy_setopt(*curl, CURLOPT_CUSTOMREQUEST, nullptr);
			curl_easy_setopt(*curl, CURLOPT_POSTFIELDS, nullptr);
			curl_easy_setopt(*curl, CURLOPT_POSTFIELDSIZE_LARGE, static_cast<curl_off_t>(0));
		}

		curl_easy_getinfo(*curl, CURLINFO_RESPONSE_CODE, &request_info->response_code);

		return TransformBufferedResponseCurl(res);
	}

	unique_ptr<HTTPResponse> Head(HeadRequestInfo &info) override {
		AddUserAgentIfAvailable(info.params.Cast<HTTPFSParams>(), info.headers);
		ResetRequestInfo();
		if (state) {
			state->RecordRequest(RequestType::HEAD_REQUEST);
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
			SetRequestURL(url, info.url, info.path);

			curl_easy_setopt(*curl, CURLOPT_URL, nullptr);
			curl_easy_setopt(*curl, CURLOPT_CURLU, url.Get());

			// Add headers if any
			curl_easy_setopt(*curl, CURLOPT_HTTPHEADER, curl_headers.Get());

			// Execute HEAD request
			res = curl->Execute();
			curl_easy_setopt(*curl, CURLOPT_NOBODY, 0L);
			curl_easy_setopt(*curl, CURLOPT_HTTPGET, 1L);
		}

		curl_easy_getinfo(*curl, CURLINFO_RESPONSE_CODE, &request_info->response_code);
		return TransformBufferedResponseCurl(res);
	}

	unique_ptr<HTTPResponse> Delete(DeleteRequestInfo &info) override {
		AddUserAgentIfAvailable(info.params.Cast<HTTPFSParams>(), info.headers);
		ResetRequestInfo();
		if (state) {
			state->RecordRequest(RequestType::DELETE_REQUEST);
		}
		auto curl_headers = TransformHeadersCurl(info.headers, info.params);
		// transform parameters
		request_info->url = info.url;

		CURLcode res;
		{
			CURLURLHandle url(curl_base_url);
			SetRequestURL(url, info.url, info.path);

			curl_easy_setopt(*curl, CURLOPT_URL, nullptr);
			curl_easy_setopt(*curl, CURLOPT_CURLU, url.Get());

			// Set DELETE request method
			curl_easy_setopt(*curl, CURLOPT_CUSTOMREQUEST, "DELETE");

			// Add headers if any
			curl_easy_setopt(*curl, CURLOPT_HTTPHEADER, curl_headers.Get());

			// Execute DELETE request
			res = curl->Execute();
			curl_easy_setopt(*curl, CURLOPT_CUSTOMREQUEST, nullptr);
		}

		// Get HTTP response status code
		curl_easy_getinfo(*curl, CURLINFO_RESPONSE_CODE, &request_info->response_code);
		return TransformBufferedResponseCurl(res);
	}

	unique_ptr<HTTPResponse> Options(OptionsRequestInfo &info) override {
		ResetRequestInfo();
		if (state) {
			state->RecordRequest(RequestType::OPTIONS_REQUEST);
		}
		auto curl_headers = TransformHeadersCurl(info.headers, info.params);
		request_info->url = info.url;

		CURLcode res;
		{
			CURLURLHandle url(curl_base_url);
			SetRequestURL(url, info.url, info.path);

			curl_easy_setopt(*curl, CURLOPT_URL, nullptr);
			curl_easy_setopt(*curl, CURLOPT_CURLU, url.Get());

			curl_easy_setopt(*curl, CURLOPT_CUSTOMREQUEST, "OPTIONS");

			curl_easy_setopt(*curl, CURLOPT_HTTPHEADER, curl_headers.Get());

			res = curl->Execute();
			curl_easy_setopt(*curl, CURLOPT_CUSTOMREQUEST, nullptr);
		}

		curl_easy_getinfo(*curl, CURLINFO_RESPONSE_CODE, &request_info->response_code);
		return TransformBufferedResponseCurl(res);
	}

	unique_ptr<HTTPResponse> Post(PostRequestInfo &info) override {
		AddUserAgentIfAvailable(info.params.Cast<HTTPFSParams>(), info.headers);
		ResetRequestInfo();
		if (state) {
			state->RecordRequest(RequestType::POST_REQUEST);
			state->RecordBytesSent(info.buffer_in_len);
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
			SetRequestURL(url, info.url, info.path);

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
			curl_easy_setopt(*curl, CURLOPT_HTTPHEADER, curl_headers.Get());

			// Execute POST request
			res = curl->Execute();
			curl_easy_setopt(*curl, CURLOPT_CUSTOMREQUEST, nullptr);
			curl_easy_setopt(*curl, CURLOPT_POSTFIELDS, nullptr);
			curl_easy_setopt(*curl, CURLOPT_POSTFIELDSIZE, 0);
			curl_easy_setopt(*curl, CURLOPT_POST, 0L);
		}

		curl_easy_getinfo(*curl, CURLINFO_RESPONSE_CODE, &request_info->response_code);
		info.buffer_out = request_info->body;

		return TransformBufferedResponseCurl(res);
	}

	void Cleanup() override {
		// Release any buffers retained from the last request before this client is parked in the connection cache.
		request_info = make_uniq<RequestInfo>();
	}

private:
	static void SetRequestURL(CURLURLHandle &url, const string &request_url, const string &request_path) {
		// A leading '//' is a network-path reference to the URL API, so set the complete URL in that case.
		const auto &url_part = StringUtil::StartsWith(request_path, "//") ? request_url : request_path;
		auto result = curl_url_set(url.Get(), CURLUPART_URL, url_part.c_str(), CURLU_PATH_AS_IS);
		if (result != CURLUE_OK) {
			throw IOException("Failed to construct curl request URL: %s", curl_url_strerror(result));
		}
	}

	static CURLRequestHeaders TransformHeadersCurl(const HTTPHeaders &header_map, const HTTPParams &params) {
		CURLRequestHeaders curl_headers;
		for (auto &entry : header_map) {
			curl_headers.Add(entry.first, entry.second);
		}
		for (auto &entry : params.extra_headers) {
			curl_headers.Add(entry.first, entry.second);
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
			auto &response_headers = request_info->header_collection.back();
			for (auto &header : response_headers) {
				// We should not return __RESPONSE_STATUS__ to the user. It's only there for debugging.
				if (header.first == "__RESPONSE_STATUS__") {
					continue;
				}
				for (auto &value : response_headers.GetHeaderValues(header.first)) {
					response->headers.Append(header.first, std::move(value));
				}
			}
		}
		// ResetRequestInfo();
		return response;
	}

	unique_ptr<HTTPResponse> TransformBufferedResponseCurl(CURLcode res) {
		auto response = TransformResponseCurl(res);
		if (state) {
			state->RecordBytesReceived(request_info->body.size());
		}
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
};

unique_ptr<HTTPClient> HTTPFSCurlUtil::InitializeClient(HTTPParams &http_params, const string &proto_host_port) {
	if (ConnectionCachingEnabled()) {
		auto client = FindCachedClient(proto_host_port);
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
	auto client = make_uniq<HTTPFSCurlClient>(http_params.Cast<HTTPFSParams>(), proto_host_port);
	return std::move(client);
}

unique_ptr<HTTPClient> HTTPFSCurlUtil::InitializeClientExtended(HTTPParams &http_params, const string &proto_host_port,
                                                                const HTTPClientInitializationOptions &options) {
	if (options.cache_policy == HTTPClientCachePolicy::BYPASS_CACHE) {
		return make_uniq<HTTPFSCurlClient>(http_params.Cast<HTTPFSParams>(), proto_host_port);
	}
	return InitializeClient(http_params, proto_host_port);
}

string HTTPFSCurlUtil::GetName() const {
	return "HTTPFS-Curl";
}

} // namespace duckdb
