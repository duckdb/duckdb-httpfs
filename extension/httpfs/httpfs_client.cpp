#include "httpfs_client.hpp"
#include "http_state.hpp"

#define CPPHTTPLIB_OPENSSL_SUPPORT
#include <curl/curl.h>
#include <sys/stat.h>
#include "httplib.hpp"

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
	((std::string *)userp)->append((char *)contents, size * nmemb);
	return size * nmemb;
}

class CURLRequestHeaders {
public:
	CURLRequestHeaders(const vector<string> &input) {
		for (auto &header : input) {
			Add(header);
		}
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


class CURLHandle {
public:
	CURLHandle(const string &token, const string &cert_path) {
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
	~CURLHandle() {
		curl_easy_cleanup(curl);
	}

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
		auto bearer_token = "";
		if (!http_params.bearer_token.empty()) {
			bearer_token = http_params.bearer_token.c_str();
		}
		curl = make_uniq<CURLHandle>(bearer_token, SelectCURLCertPath());
		state = http_params.state;
	}

	void SetLogger(HTTPLogger &logger) {
		client->set_logger(logger.GetLogger<duckdb_httplib_openssl::Request, duckdb_httplib_openssl::Response>());
	}

	unique_ptr<HTTPResponse> Get(GetRequestInfo &info) override {
		auto headers = TransformHeadersForCurl(info.headers, info.params);
		CURLRequestHeaders curl_headers(headers);

		CURLcode res;
		string result;
		{
			curl_easy_setopt(*curl_handle, CURLOPT_URL, info.url.c_str());
			curl_easy_setopt(*curl_handle, CURLOPT_WRITEFUNCTION, RequestWriteCallback);
			curl_easy_setopt(*curl_handle, CURLOPT_WRITEDATA, &result);

			if (curl_headers) {
				curl_easy_setopt(*curl_handle, CURLOPT_HTTPHEADER, curl_headers.headers);
			}
			res = curl_handle->Execute();
		}

		// DUCKDB_LOG_DEBUG(context, "iceberg.Catalog.Curl.HTTPRequest", "GET %s (curl code '%s')", url,
		// 				 curl_easy_strerror(res));
		if (res != CURLcode::CURLE_OK) {
			string error = curl_easy_strerror(res);
			throw HTTPException(StringUtil::Format("Curl GET Request to '%s' failed with error: '%s'", url, error));
		}
		uint16_t response_code = 0;
		curl_easy_getinfo(*curl_handle, CURLINFO_RESPONSE_CODE, response_code);

		// TODO: replace this with better bytes received provided by curl.
		if (state) {
			state->total_bytes_received += sizeof(result);
		}

		// get the response code
		auto status_code = HTTPStatusCode(response_code);
		auto return_result = make_uniq<HTTPResponse>(status_code);
		return_result->body = result;
		return return_result;
	}

	unique_ptr<HTTPResponse> Put(PutRequestInfo &info) override {
		if (state) {
			state->put_count++;
			state->total_bytes_sent += info.buffer_in_len;
		}
		auto headers = TransformHeaders(info.headers, info.params);
		return TransformResult(client->Put(info.path, headers, const_char_ptr_cast(info.buffer_in), info.buffer_in_len,
		                                   info.content_type));
	}

	unique_ptr<HTTPResponse> Head(HeadRequestInfo &info) override {
		if (state) {
			state->head_count++;
		}
		auto headers = TransformHeaders(info.headers, info.params);
		return TransformResult(client->Head(info.path, headers));
	}

	unique_ptr<HTTPResponse> Delete(DeleteRequestInfo &info) override {
		if (state) {
			state->delete_count++;
		}
		auto headers = TransformHeaders(info.headers, info.params);
		return TransformResult(client->Delete(info.path, headers));
	}

	unique_ptr<HTTPResponse> Post(PostRequestInfo &info) override {
		if (state) {
			state->post_count++;
			state->total_bytes_sent += info.buffer_in_len;
		}
		// We use a custom Request method here, because there is no Post call with a contentreceiver in httplib
		duckdb_httplib_openssl::Request req;
		req.method = "POST";
		req.path = info.path;
		req.headers = TransformHeaders(info.headers, info.params);
		req.headers.emplace("Content-Type", "application/octet-stream");
		req.content_receiver = [&](const char *data, size_t data_length, uint64_t /*offset*/,
		                           uint64_t /*total_length*/) {
			if (state) {
				state->total_bytes_received += data_length;
			}
			info.buffer_out += string(data, data_length);
			return true;
		};
		req.body.assign(const_char_ptr_cast(info.buffer_in), info.buffer_in_len);
		return TransformResult(client->send(req));
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

	duckdb_httplib_openssl::Headers TransformHeadersForCurl(const HTTPHeaders &header_map, const HTTPParams &params) {
		 headers;
		for (auto &entry : header_map) {
			const std::string new_header = entry.first + "=" + entry.second;
			headers.insert(new_header);
		}
		for (auto &entry : params.extra_headers) {
			const std::string new_header = entry.first + "=" + entry.second;
			headers.insert(new_header);
		}
		return headers;
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
