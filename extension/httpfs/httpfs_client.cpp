#include "httpfs_client.hpp"
#include "http_state.hpp"

#define CPPHTTPLIB_OPENSSL_SUPPORT

#include <curl/curl.h>
// #include <sys/stat.h>
#include "httplib.hpp"
#include "duckdb/common/exception/http_exception.hpp"

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
	std::string* str = static_cast<std::string*>(userp);
	str->append(static_cast<char*>(contents), totalSize);
	return totalSize;
}

static size_t RequestHeaderCallback(void *contents, size_t size, size_t nmemb, void *userp) {
	size_t totalSize = size * nmemb;
	std::string header(static_cast<char*>(contents), totalSize);
	HeaderCollector* header_collection = static_cast<HeaderCollector*>(userp);

	// Trim trailing \r\n
	if (!header.empty() && header.back() == '\n') {
		header.pop_back();
		if (!header.empty() && header.back() == '\r') {
			header.pop_back();
		}
	}

	// If header starts with HTTP/... curl has followed a redirect and we have a new Header,
	// so we clear all of the current header_collection
	if (header.rfind("HTTP/", 0) == 0) {
		header_collection->header_collection.push_back(HTTPHeaders());
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
	// TODO: some headers may not follow standard response header formats.
	//  what to do in this case? Invalid does not mean we should abort.

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


class HTTPFSClient : public HTTPClient {
public:
	HTTPFSClient(HTTPFSParams &http_params, const string &proto_host_port) {
		client = make_uniq<duckdb_httplib_openssl::Client>(proto_host_port);
		client->set_follow_location(true);
		client->set_keep_alive(http_params.keep_alive);
		if (!http_params.ca_cert_file.empty()) {
			client->set_ca_cert_path(http_params.ca_cert_file.c_str());
		}
		client->enable_server_certificate_verification(http_params.enable_server_cert_verification);
		client->set_write_timeout(http_params.timeout, http_params.timeout_usec);
		client->set_read_timeout(http_params.timeout, http_params.timeout_usec);
		client->set_connection_timeout(http_params.timeout, http_params.timeout_usec);
		client->set_decompress(false);
		if (!http_params.bearer_token.empty()) {
			client->set_bearer_token_auth(http_params.bearer_token.c_str());
		}

		if (!http_params.http_proxy.empty()) {
			client->set_proxy(http_params.http_proxy, http_params.http_proxy_port);

			if (!http_params.http_proxy_username.empty()) {
				client->set_proxy_basic_auth(http_params.http_proxy_username, http_params.http_proxy_password);
			}
		}
		state = http_params.state;

		// initializing curl
		auto bearer_token = "";
		if (!http_params.bearer_token.empty()) {
			bearer_token = http_params.bearer_token.c_str();
		}
		curl = make_uniq<CURLHandle>(bearer_token, SelectCURLCertPath());

	}


	unique_ptr<HTTPResponse> Get(GetRequestInfo &info) override {
		if (state) {
			state->get_count++;
		}

		// auto headers = TransformHeaders(info.headers, info.params);
		// if (!info.response_handler && !info.content_handler) {
		// 	return TransformResult(client->Get(info.path, headers));
		// } else {
		// 	return TransformResult(client->Get(
		// 		info.path.c_str(), headers,
		// 		[&](const duckdb_httplib_openssl::Response &response) {
		// 			auto http_response = TransformResponse(response);
		// 			return info.response_handler(*http_response);
		// 		},
		// 		[&](const char *data, size_t data_length) {
		// 			if (state) {
		// 				state->total_bytes_received += data_length;
		// 			}
		// 			return info.content_handler(const_data_ptr_cast(data), data_length);
		// 		}));
		// }

		auto curl_headers = TransformHeadersForCurl(info.headers, info.params);

		CURLcode res;
		std::string result;
		HeaderCollector response_header_collection;
		{
			// If the same handle served a HEAD request, we must set NOBODY back to 0L to request content again
			curl_easy_setopt(*curl, CURLOPT_NOBODY, 0L);

			// follow redirects
			curl_easy_setopt(*curl, CURLOPT_FOLLOWLOCATION, 1L);
			curl_easy_setopt(*curl, CURLOPT_URL, info.url.c_str());
			// write response data
			curl_easy_setopt(*curl, CURLOPT_WRITEFUNCTION, RequestWriteCallback);
			curl_easy_setopt(*curl, CURLOPT_WRITEDATA, &result);
			// write response headers (different header collection for each redirect)
			curl_easy_setopt(*curl, CURLOPT_HEADERFUNCTION, RequestHeaderCallback);
			curl_easy_setopt(*curl, CURLOPT_HEADERDATA, &response_header_collection);

			if (curl_headers) {
				curl_easy_setopt(*curl, CURLOPT_HTTPHEADER, curl_headers.headers);
			}
			res = curl->Execute();
		}

		// DUCKDB_LOG_DEBUG(context, "iceberg.Catalog.Curl.HTTPRequest", "GET %s (curl code '%s')", url,
		// 				 curl_easy_strerror(res));
		if (res != CURLcode::CURLE_OK) {
			string error = curl_easy_strerror(res);
			throw HTTPException(StringUtil::Format("Curl GET Request to '%s' failed with error: '%s'", info.url, error));
		}
		uint16_t response_code = 0;
		curl_easy_getinfo(*curl, CURLINFO_RESPONSE_CODE, &response_code);

		idx_t bytes_received = 0;
		if (response_header_collection.header_collection.back().HasHeader("content-length")) {
			bytes_received = std::stoi(response_header_collection.header_collection.back().GetHeaderValue("content-length"));
			D_ASSERT(bytes_received == result.size());
		} else {
			bytes_received = result.size();
		}
		if (state) {
			state->total_bytes_received += bytes_received;
		}

		const char* data = result.c_str();
		info.content_handler(const_data_ptr_cast(data), bytes_received);

		// Construct HTTPResponse
		auto status_code = HTTPStatusCode(response_code);
		auto return_result = make_uniq<HTTPResponse>(status_code);
		return_result->body = result;
		return_result->headers = response_header_collection.header_collection.back();
		return_result->url = info.url;
		return return_result;
	}

	unique_ptr<HTTPResponse> Put(PutRequestInfo &info) override {
		if (state) {
			state->put_count++;
			state->total_bytes_sent += info.buffer_in_len;
		}
		// auto headers = TransformHeaders(info.headers, info.params);
		// return TransformResult(client->Put(info.path, headers, const_char_ptr_cast(info.buffer_in), info.buffer_in_len,
		//                                    info.content_type));

		auto curl_headers = TransformHeadersForCurl(info.headers, info.params);
		// Optionally add headers directly
		curl_headers.headers = curl_slist_append(curl_headers.headers, "Content-Type: application/json");

		CURLcode res;
		std::string result;
		HeaderCollector response_header_collection;

		{
			curl_easy_setopt(*curl, CURLOPT_URL, info.url.c_str());

			// Perform PUT
			curl_easy_setopt(*curl, CURLOPT_CUSTOMREQUEST, "PUT");

			// Include PUT body
			curl_easy_setopt(*curl, CURLOPT_POSTFIELDS, const_char_ptr_cast(info.buffer_in));
			curl_easy_setopt(*curl, CURLOPT_POSTFIELDSIZE, info.buffer_in_len);

			// Follow redirects if needed
			curl_easy_setopt(*curl, CURLOPT_FOLLOWLOCATION, 1L);

			// Capture response body
			curl_easy_setopt(*curl, CURLOPT_WRITEFUNCTION, RequestWriteCallback);
			curl_easy_setopt(*curl, CURLOPT_WRITEDATA, &result);

			// Capture response headers
			curl_easy_setopt(*curl, CURLOPT_HEADERFUNCTION, RequestHeaderCallback);
			curl_easy_setopt(*curl, CURLOPT_HEADERDATA, &response_header_collection);

			// Apply headers
			if (curl_headers) {
				curl_easy_setopt(*curl, CURLOPT_HTTPHEADER, curl_headers.headers);
			}

			// Execute the request
			res = curl->Execute();
		}

		// Check response
		if (res != CURLcode::CURLE_OK) {
			std::string error = curl_easy_strerror(res);
			throw HTTPException(StringUtil::Format("Curl PUT Request to '%s' failed with error: '%s'", info.url, error));
		}

		uint16_t response_code = 0;
		curl_easy_getinfo(*curl, CURLINFO_RESPONSE_CODE, &response_code);

		// Construct HTTPResponse
		auto status_code = HTTPStatusCode(response_code);
		auto return_result = make_uniq<HTTPResponse>(status_code);
		return_result->body = "";
		return_result->headers = response_header_collection.header_collection.back();
		return_result->url = info.url;
		return return_result;
	}

	unique_ptr<HTTPResponse> Head(HeadRequestInfo &info) override {

		 auto curl_headers = TransformHeadersForCurl(info.headers, info.params);

		 CURLcode res;
		 std::string result;
		 HeaderCollector response_header_collection;

		 {
		 	// Set URL
		 	curl_easy_setopt(*curl, CURLOPT_URL, info.url.c_str());
			// curl_easy_setopt(*curl, CURLOPT_VERBOSE, 1L);

		 	// Perform HEAD request instead of GET
		 	curl_easy_setopt(*curl, CURLOPT_NOBODY, 1L);
		 	curl_easy_setopt(*curl, CURLOPT_HTTPGET, 0L);

		 	// Follow redirects
		 	curl_easy_setopt(*curl, CURLOPT_FOLLOWLOCATION, 1L);

		 	//  set write function to collect body — no body expected, so safe to omit
		 	curl_easy_setopt(*curl, CURLOPT_WRITEFUNCTION, RequestWriteCallback);
		 	curl_easy_setopt(*curl, CURLOPT_WRITEDATA, &result);

		 	// Collect response headers (multiple header blocks for redirects)
		 	curl_easy_setopt(*curl, CURLOPT_HEADERFUNCTION, RequestHeaderCallback);
		 	curl_easy_setopt(*curl, CURLOPT_HEADERDATA, &response_header_collection);

		 	// Add headers if any
		 	if (curl_headers) {
		 		curl_easy_setopt(*curl, CURLOPT_HTTPHEADER, curl_headers.headers);
		 	}

		 	// Execute HEAD request
		 	res = curl->Execute();
		 }

		 // Handle result
		 if (res != CURLcode::CURLE_OK) {
		 	string error = curl_easy_strerror(res);
		 	throw HTTPException(StringUtil::Format("Curl HEAD Request to '%s' failed with error: '%s'", info.url, error));
		 }
		 uint16_t response_code = 0;
		 curl_easy_getinfo(*curl, CURLINFO_RESPONSE_CODE, &response_code);
		 // Construct HTTPResponse
		 auto status_code = HTTPStatusCode(response_code);
		 auto return_result = make_uniq<HTTPResponse>(status_code);
		 return_result->body = "";
		 return_result->headers = response_header_collection.header_collection.back();
		 return_result->url = info.url;
		 return return_result;
	}

	unique_ptr<HTTPResponse> Delete(DeleteRequestInfo &info) override {
		auto curl_headers = TransformHeadersForCurl(info.headers, info.params);

		CURLcode res;
		std::string result;
		HeaderCollector response_header_collection;

		// TODO: some delete requests require a BODY
		{
			// Set URL
			curl_easy_setopt(*curl, CURLOPT_URL, info.url.c_str());

			// Set DELETE request method
			curl_easy_setopt(*curl, CURLOPT_CUSTOMREQUEST, "DELETE");

			// Follow redirects
			curl_easy_setopt(*curl, CURLOPT_FOLLOWLOCATION, 1L);

			// Set write function to collect response body
			curl_easy_setopt(*curl, CURLOPT_WRITEFUNCTION, RequestWriteCallback);
			curl_easy_setopt(*curl, CURLOPT_WRITEDATA, &result);

			// Collect response headers (multiple header blocks for redirects)
			curl_easy_setopt(*curl, CURLOPT_HEADERFUNCTION, RequestHeaderCallback);
			curl_easy_setopt(*curl, CURLOPT_HEADERDATA, &response_header_collection);

			// Add headers if any
			if (curl_headers) {
				curl_easy_setopt(*curl, CURLOPT_HTTPHEADER, curl_headers.headers);
			}

			// Execute DELETE request
			res = curl->Execute();
		}

		// Handle result
		if (res != CURLcode::CURLE_OK) {
			std::string error = curl_easy_strerror(res);
			throw HTTPException(StringUtil::Format("Curl DELETE Request to '%s' failed with error: '%s'", info.url, error));
		}

		// Get HTTP response status code
		uint16_t response_code = 0;
		curl_easy_getinfo(*curl, CURLINFO_RESPONSE_CODE, &response_code);
		// Construct HTTPResponse
		auto status_code = HTTPStatusCode(response_code);
		auto return_result = make_uniq<HTTPResponse>(status_code);
		return_result->headers = response_header_collection.header_collection.back();
		return_result->url = info.url;
		return return_result;

	}

	unique_ptr<HTTPResponse> Post(PostRequestInfo &info) override {
		if (state) {
			state->post_count++;
			state->total_bytes_sent += info.buffer_in_len;
		}

		// // We use a custom Request method here, because there is no Post call with a contentreceiver in httplib
		// duckdb_httplib_openssl::Request req;
		// req.method = "POST";
		// req.path = info.path;
		// req.headers = TransformHeaders(info.headers, info.params);
		// req.headers.emplace("Content-Type", "application/octet-stream");
		// req.content_receiver = [&](const char *data, size_t data_length, uint64_t /*offset*/,
		//                            uint64_t /*total_length*/) {
		// 	if (state) {
		// 		state->total_bytes_received += data_length;
		// 	}
		// 	info.buffer_out += string(data, data_length);
		// 	return true;
		// };
		// req.body.assign(const_char_ptr_cast(info.buffer_in), info.buffer_in_len);
		// return TransformResult(client->send(req));

		auto curl_headers = TransformHeadersForCurl(info.headers, info.params);
		curl_headers.Add("Content-Type: application/octet-stream");

		CURLcode res;
		std::string result;
		HeaderCollector response_header_collection;

		{
			curl_easy_setopt(*curl, CURLOPT_URL, info.url.c_str());
			curl_easy_setopt(*curl, CURLOPT_POST, 1L);

			// Set POST body
			curl_easy_setopt(*curl, CURLOPT_POSTFIELDS, const_char_ptr_cast(info.buffer_in));
			curl_easy_setopt(*curl, CURLOPT_POSTFIELDSIZE, info.buffer_in_len);

			// Follow redirects
			// TODO: follow redirects for POST?
			curl_easy_setopt(*curl, CURLOPT_FOLLOWLOCATION, 1L);

			// Set write function to collect response body
			curl_easy_setopt(*curl, CURLOPT_WRITEFUNCTION, RequestWriteCallback);
			curl_easy_setopt(*curl, CURLOPT_WRITEDATA, &result);

			// Collect response headers (multiple header blocks for redirects)
			curl_easy_setopt(*curl, CURLOPT_HEADERFUNCTION, RequestHeaderCallback);
			curl_easy_setopt(*curl, CURLOPT_HEADERDATA, &response_header_collection);

			// Add headers if any
			if (curl_headers) {
				curl_easy_setopt(*curl, CURLOPT_HTTPHEADER, curl_headers.headers);
			}

			// Execute POST request
			res = curl->Execute();
		}

		// Handle result
		if (res != CURLcode::CURLE_OK) {
			string error = curl_easy_strerror(res);
			throw HTTPException(StringUtil::Format("Curl POST Request to '%s' failed with error: '%s'", info.url, error));
		}
		uint16_t response_code = 0;
		curl_easy_getinfo(*curl, CURLINFO_RESPONSE_CODE, &response_code);

		info.buffer_out = result;
		// Construct HTTPResponse
		auto status_code = HTTPStatusCode(response_code);
		auto return_result = make_uniq<HTTPResponse>(status_code);
		return_result->headers = response_header_collection.header_collection.back();
		return_result->url = info.url;
		return return_result;
	}

private:
	duckdb_httplib_openssl::Headers TransformHeaders(const HTTPHeaders &header_map, const HTTPParams &params) {
		duckdb_httplib_openssl::Headers headers;
		for (auto &entry : header_map) {
			headers.insert(entry);
		}
		for (auto &entry : params.extra_headers) {
			headers.insert(entry);
		}
		return headers;
	}

	CURLRequestHeaders TransformHeadersForCurl(const HTTPHeaders &header_map, const HTTPParams &params) {
		std::vector<std::string> headers;
		for (auto &entry : header_map) {
			const std::string new_header = entry.first + ": " + entry.second;
			headers.push_back(new_header);
		}
		for (auto &entry : params.extra_headers) {
			const std::string new_header = entry.first + ": " + entry.second;
			headers.push_back(new_header);
		}
		CURLRequestHeaders curl_headers;
		for (auto &header : headers) {
			curl_headers.Add(header);
		}
		return curl_headers;
	}

	unique_ptr<HTTPResponse> TransformResponse(const duckdb_httplib_openssl::Response &response) {
		auto status_code = HTTPUtil::ToStatusCode(response.status);
		auto result = make_uniq<HTTPResponse>(status_code);
		result->body = response.body;
		result->reason = response.reason;
		for (auto &entry : response.headers) {
			result->headers.Insert(entry.first, entry.second);
		}
		return result;
	}

	unique_ptr<HTTPResponse> TransformResult(duckdb_httplib_openssl::Result &&res) {
		if (res.error() == duckdb_httplib_openssl::Error::Success) {
			auto &response = res.value();
			return TransformResponse(response);
		} else {
			auto result = make_uniq<HTTPResponse>(HTTPStatusCode::INVALID);
			result->request_error = to_string(res.error());
			return result;
		}
	}

private:
	unique_ptr<duckdb_httplib_openssl::Client> client;
	unique_ptr<CURLHandle> curl;
	CURLRequestHeaders request_headers;
	optional_ptr<HTTPState> state;
};

unique_ptr<HTTPClient> HTTPFSUtil::InitializeClient(HTTPParams &http_params, const string &proto_host_port) {
	auto client = make_uniq<HTTPFSClient>(http_params.Cast<HTTPFSParams>(), proto_host_port);
	return std::move(client);
}

unordered_map<string, string> HTTPFSUtil::ParseGetParameters(const string &text) {
	duckdb_httplib_openssl::Params query_params;
	duckdb_httplib_openssl::detail::parse_query_text(text, query_params);

	unordered_map<string, string> result;
	for (auto &entry : query_params) {
		result.emplace(std::move(entry.first), std::move(entry.second));
	}
	return result;
}

string HTTPFSUtil::GetName() const {
	return "HTTPFS";
}

} // namespace duckdb
