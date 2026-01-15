#include "httpfs_client.hpp"
#include "http_state.hpp"

#define CPPHTTPLIB_OPENSSL_SUPPORT

#include <curl/curl.h>
#include <sys/stat.h>
#include "duckdb/common/exception/http_exception.hpp"

#ifndef EMSCRIPTEN
#include "httpfs_curl_client.hpp"
#endif

namespace duckdb {

// we statically compile in libcurl, which means the cert file location of the build machine is the
// place curl will look. But not every distro has this file in the same location, so we search a
// number of common locations and use the first one we find.
static std::string certFileLocations[] = {
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
static std::string SelectCURLCertPath() {
	for (std::string &caFile : certFileLocations) {
		struct stat buf;
		if (stat(caFile.c_str(), &buf) == 0) {
			return caFile;
		}
	}
	return std::string();
}

static std::string cert_path = SelectCURLCertPath();

static size_t RequestWriteCallback(void *contents, size_t size, size_t nmemb, void *userp) {
	size_t totalSize = size * nmemb;
	std::string *str = static_cast<std::string *>(userp);
	str->append(static_cast<char *>(contents), totalSize);
	return totalSize;
}

static size_t RequestHeaderCallback(void *contents, size_t size, size_t nmemb, void *userp) {
	size_t totalSize = size * nmemb;
	std::string header(static_cast<char *>(contents), totalSize);
	HeaderCollector *header_collection = static_cast<HeaderCollector *>(userp);

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
		header_collection->header_collection.push_back(HTTPHeaders());
		header_collection->header_collection.back().Insert("__RESPONSE_STATUS__", header);
	}

	size_t colonPos = header.find(':');

	if (colonPos != std::string::npos) {
		// Split the string into two parts
		std::string part1 = header.substr(0, colonPos);
		std::string part2 = header.substr(colonPos + 1);
		if (part2.at(0) == ' ') {
			part2.erase(0, 1);
		}

		header_collection->header_collection.back().Insert(part1, part2);
	}
	// TODO: log headers that don't follow the header format

	return totalSize;
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
}

CURLHandle::~CURLHandle() {
	curl_easy_cleanup(curl);
}

struct RequestInfo {
	string url = "";
	string body = "";
	uint16_t response_code = 0;
	std::vector<HTTPHeaders> header_collection;
};

static idx_t httpfs_client_count = 0;

class HTTPFSCurlClient : public HTTPClient {
public:
	HTTPFSCurlClient(HTTPFSParams &http_params, const string &proto_host_port) {
		// FIXME: proto_host_port is not used
		Initialize(http_params);
	}
	void Initialize(HTTPParams &http_p) override {
		HTTPFSParams &http_params = (HTTPFSParams &)http_p;
		auto bearer_token = "";
		if (!http_params.bearer_token.empty()) {
			bearer_token = http_params.bearer_token.c_str();
		}
		state = http_params.state;

		// call curl_global_init if not already done by another HTTPFS Client
		InitCurlGlobal();

		curl = make_uniq<CURLHandle>(bearer_token, SelectCURLCertPath());
		request_info = make_uniq<RequestInfo>();

		// set curl options
		// follow redirects
		curl_easy_setopt(*curl, CURLOPT_FOLLOWLOCATION, 1L);

		// Curl re-uses connections by default
		if (!http_params.keep_alive) {
			curl_easy_setopt(*curl, CURLOPT_FORBID_REUSE, 1L);
		}

		if (http_params.enable_curl_server_cert_verification) {
			curl_easy_setopt(*curl, CURLOPT_SSL_VERIFYPEER, 1L); // Verify the cert
			curl_easy_setopt(*curl, CURLOPT_SSL_VERIFYHOST, 2L); // Verify that the cert matches the hostname
		} else {
			curl_easy_setopt(*curl, CURLOPT_SSL_VERIFYPEER, 0L); // Override default, don't verify the cert
			curl_easy_setopt(*curl, CURLOPT_SSL_VERIFYHOST,
			                 0L); // Override default, don't verify that the cert matches the hostname
		}

		// set read timeout
		curl_easy_setopt(*curl, CURLOPT_TIMEOUT, http_params.timeout);
		// set connection timeout
		curl_easy_setopt(*curl, CURLOPT_CONNECTTIMEOUT, http_params.timeout);
		// accept content as-is (i.e no decompressing)
		curl_easy_setopt(*curl, CURLOPT_ACCEPT_ENCODING, "identity");
		// follow redirects
		curl_easy_setopt(*curl, CURLOPT_FOLLOWLOCATION, 1L);

		// define the header callback
		curl_easy_setopt(*curl, CURLOPT_HEADERFUNCTION, RequestHeaderCallback);
		curl_easy_setopt(*curl, CURLOPT_HEADERDATA, &request_info->header_collection);
		// define the write data callback (for get requests)
		curl_easy_setopt(*curl, CURLOPT_WRITEFUNCTION, RequestWriteCallback);
		curl_easy_setopt(*curl, CURLOPT_WRITEDATA, &request_info->body);

		if (!http_params.http_proxy.empty()) {
			curl_easy_setopt(*curl, CURLOPT_PROXY,
			                 StringUtil::Format("%s:%d", http_params.http_proxy, http_params.http_proxy_port).c_str());

			if (!http_params.http_proxy_username.empty()) {
				curl_easy_setopt(*curl, CURLOPT_PROXYUSERNAME, http_params.http_proxy_username.c_str());
				curl_easy_setopt(*curl, CURLOPT_PROXYPASSWORD, http_params.http_proxy_password.c_str());
			}
		}
	}

	~HTTPFSCurlClient() {
		DestroyCurlGlobal();
	}

	static string EncodeSpaces(const string &url) {
		string out;
		out.reserve(url.size());
		for (char c : url) {
			out += (c == ' ') ? "%20" : string(1, c);
		}
		return out;
	}

	unique_ptr<HTTPResponse> Get(GetRequestInfo &info) override {
		ResetRequestInfo();
		if (state) {
			state->get_count++;
		}

		auto curl_headers = TransformHeadersCurl(info.headers, info.params);
		request_info->url = info.url;

		CURLcode res;
		{
			// If the same handle served a HEAD request, we must set NOBODY back to 0L to request content again
			curl_easy_setopt(*curl, CURLOPT_NOBODY, 0L);
			auto encoded_url = EncodeSpaces(request_info->url);
			curl_easy_setopt(*curl, CURLOPT_URL, encoded_url.c_str());
			curl_easy_setopt(*curl, CURLOPT_HTTPHEADER, curl_headers ? curl_headers.headers : nullptr);
			res = curl->Execute();
		}

		curl_easy_getinfo(*curl, CURLINFO_RESPONSE_CODE, &request_info->response_code);

		idx_t bytes_received = 0;
		if (!request_info->header_collection.empty() &&
		    request_info->header_collection.back().HasHeader("content-length")) {
			bytes_received = std::stoi(request_info->header_collection.back().GetHeaderValue("content-length"));
			D_ASSERT(bytes_received == request_info->body.size());
		} else {
			bytes_received = request_info->body.size();
		}
		if (state) {
			state->total_bytes_received += bytes_received;
		}

		if (info.response_handler) {
			auto response = TransformResponseCurl(res);
			if (!info.response_handler(*response)) {
				return response;
			}
		}

		const char *data = request_info->body.c_str();
		if (info.content_handler) {
			info.content_handler(const_data_ptr_cast(data), bytes_received);
		}

		return TransformResponseCurl(res);
	}

	unique_ptr<HTTPResponse> Put(PutRequestInfo &info) override {
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
			auto encoded_url = EncodeSpaces(request_info->url);
			curl_easy_setopt(*curl, CURLOPT_URL, encoded_url.c_str());
			// Perform PUT
			curl_easy_setopt(*curl, CURLOPT_CUSTOMREQUEST, "PUT");
			// Include PUT body
			curl_easy_setopt(*curl, CURLOPT_POSTFIELDS, const_char_ptr_cast(info.buffer_in));
			curl_easy_setopt(*curl, CURLOPT_POSTFIELDSIZE, info.buffer_in_len);

			// Apply headers
			curl_easy_setopt(*curl, CURLOPT_HTTPHEADER, curl_headers ? curl_headers.headers : nullptr);

			res = curl->Execute();
		}

		curl_easy_getinfo(*curl, CURLINFO_RESPONSE_CODE, &request_info->response_code);

		return TransformResponseCurl(res);
	}

	unique_ptr<HTTPResponse> Head(HeadRequestInfo &info) override {
		ResetRequestInfo();
		if (state) {
			state->head_count++;
		}

		auto curl_headers = TransformHeadersCurl(info.headers, info.params);
		request_info->url = info.url;
		// transform parameters

		CURLcode res;
		{
			// Set URL
			auto encoded_url = EncodeSpaces(request_info->url);
			curl_easy_setopt(*curl, CURLOPT_URL, encoded_url.c_str());

			// Perform HEAD request instead of GET
			curl_easy_setopt(*curl, CURLOPT_NOBODY, 1L);
			curl_easy_setopt(*curl, CURLOPT_HTTPGET, 0L);

			// Add headers if any
			curl_easy_setopt(*curl, CURLOPT_HTTPHEADER, curl_headers ? curl_headers.headers : nullptr);

			// Execute HEAD request
			res = curl->Execute();
		}

		curl_easy_getinfo(*curl, CURLINFO_RESPONSE_CODE, &request_info->response_code);
		return TransformResponseCurl(res);
	}

	unique_ptr<HTTPResponse> Delete(DeleteRequestInfo &info) override {
		ResetRequestInfo();
		if (state) {
			state->delete_count++;
		}

		auto curl_headers = TransformHeadersCurl(info.headers, info.params);
		// transform parameters
		request_info->url = info.url;

		CURLcode res;
		{
			// Set URL
			auto encoded_url = EncodeSpaces(request_info->url);
			curl_easy_setopt(*curl, CURLOPT_URL, encoded_url.c_str());

			// Set DELETE request method
			curl_easy_setopt(*curl, CURLOPT_CUSTOMREQUEST, "DELETE");

			// Follow redirects
			curl_easy_setopt(*curl, CURLOPT_FOLLOWLOCATION, 1L);

			// Add headers if any
			curl_easy_setopt(*curl, CURLOPT_HTTPHEADER, curl_headers ? curl_headers.headers : nullptr);

			// Execute DELETE request
			res = curl->Execute();
		}

		// Get HTTP response status code
		curl_easy_getinfo(*curl, CURLINFO_RESPONSE_CODE, &request_info->response_code);
		return TransformResponseCurl(res);
	}

	unique_ptr<HTTPResponse> Post(PostRequestInfo &info) override {
		ResetRequestInfo();
		if (state) {
			state->post_count++;
			state->total_bytes_sent += info.buffer_in_len;
		}

		auto curl_headers = TransformHeadersCurl(info.headers, info.params);
		const string content_type = "Content-Type: application/octet-stream";
		curl_headers.Add(content_type.c_str());
		// transform parameters
		request_info->url = info.url;

		CURLcode res;
		{
			auto encoded_url = EncodeSpaces(request_info->url);
			curl_easy_setopt(*curl, CURLOPT_URL, encoded_url.c_str());
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
		}

		curl_easy_getinfo(*curl, CURLINFO_RESPONSE_CODE, &request_info->response_code);
		info.buffer_out = request_info->body;
		// Construct HTTPResponse
		return TransformResponseCurl(res);
	}

private:
	CURLRequestHeaders TransformHeadersCurl(const HTTPHeaders &header_map, const HTTPParams &params) {
		auto &httpfs_params = params.Cast<HTTPFSParams>();

		std::vector<std::string> headers;
		for (auto &entry : header_map) {
			const std::string new_header = entry.first + ": " + entry.second;
			headers.push_back(new_header);
		}
		CURLRequestHeaders curl_headers;
		for (auto &header : headers) {
			curl_headers.Add(header);
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

	unique_ptr<HTTPResponse> TransformResponseCurl(CURLcode res) {
		auto status_code = HTTPStatusCode(request_info->response_code);
		auto response = make_uniq<HTTPResponse>(status_code);
		if (res != CURLcode::CURLE_OK) {
			// TODO: request error can come from HTTPS Status code toString() value.
			if (!request_info->header_collection.empty() &&
			    request_info->header_collection.back().HasHeader("__RESPONSE_STATUS__")) {
				response->request_error = request_info->header_collection.back().GetHeaderValue("__RESPONSE_STATUS__");
			} else {
				response->request_error = curl_easy_strerror(res);
			}
			return response;
		}
		response->body = request_info->body;
		response->url = request_info->url;
		response->reason = HTTPUtil::GetStatusMessage(HTTPUtil::ToStatusCode(request_info->response_code));
		if (!request_info->header_collection.empty()) {
			for (auto &header : request_info->header_collection.back()) {
				response->headers.Insert(header.first, header.second);
			}
		}
		// ResetRequestInfo();
		return response;
	}

private:
	unique_ptr<CURLHandle> curl;
	optional_ptr<HTTPState> state;
	unique_ptr<RequestInfo> request_info;

	static std::mutex &GetRefLock() {
		static std::mutex mtx;
		return mtx;
	}

	static void InitCurlGlobal() {
		GetRefLock();
		if (httpfs_client_count == 0) {
			curl_global_init(CURL_GLOBAL_DEFAULT);
		}
		++httpfs_client_count;
	}

	static void DestroyCurlGlobal() {
		// TODO: when to call curl_global_cleanup()
		// calling it on client destruction causes SSL errors when verification is on (due to many requests).
		// GetRefLock();
		// if (httpfs_client_count == 0) {
		// 	throw InternalException("Destroying Httpfs client that did not initialize CURL");
		// }
		// --httpfs_client_count;
		// if (httpfs_client_count == 0) {
		// 	curl_global_cleanup();
		// }
	}
};

unique_ptr<HTTPClient> HTTPFSCurlUtil::InitializeClient(HTTPParams &http_params, const string &proto_host_port) {
	auto client = make_uniq<HTTPFSCurlClient>(http_params.Cast<HTTPFSParams>(), proto_host_port);
	return std::move(client);
}

unordered_map<string, string> HTTPFSCurlUtil::ParseGetParameters(const string &text) {
	unordered_map<std::string, std::string> params;

	auto pos = text.find('?');
	if (pos == std::string::npos)
		return params;

	std::string query = text.substr(pos + 1);
	std::stringstream ss(query);
	std::string item;

	while (std::getline(ss, item, '&')) {
		auto eq_pos = item.find('=');
		if (eq_pos != std::string::npos) {
			std::string key = item.substr(0, eq_pos);
			std::string value = StringUtil::URLDecode(item.substr(eq_pos + 1));
			params[key] = value;
		} else {
			params[item] = ""; // key with no value
		}
	}

	return params;
}

string HTTPFSCurlUtil::GetName() const {
	return "HTTPFS-Curl";
}

} // namespace duckdb
