#include "httpfs_client.hpp"
#include "http_state.hpp"
#define CPPHTTPLIB_OPENSSL_SUPPORT
#include "httplib.hpp"

namespace duckdb {

class HTTPFSClient : public HTTPClient {
public:
	HTTPFSClient(HTTPFSParams &http_params, const string &proto_host_port,
	             const string &basic_auth_username, const string &basic_auth_password) {
		client = make_uniq<duckdb_httplib_openssl::Client>(proto_host_port);
		if (!basic_auth_username.empty() || !basic_auth_password.empty()) {
			client->set_basic_auth(basic_auth_username, basic_auth_password);
		}
		Initialize(http_params);
	}
	void Initialize(HTTPParams &http_p) override {
		HTTPFSParams &http_params = (HTTPFSParams &)http_p;
		client->set_follow_location(http_params.follow_location);
		client->set_keep_alive(http_params.keep_alive);
		if (!http_params.ca_cert_file.empty()) {
			client->set_ca_cert_path(http_params.ca_cert_file.c_str());
		}
		const bool verify_ssl =
		    http_params.override_verify_ssl ? http_params.verify_ssl : http_params.enable_server_cert_verification;
		client->enable_server_certificate_verification(verify_ssl);
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
	}

	unique_ptr<HTTPResponse> Get(GetRequestInfo &info) override {
		if (state) {
			state->get_count++;
		}
		auto headers = TransformHeaders(info.headers, info.params);
		if (!info.response_handler && !info.content_handler) {
			return TransformResult(client->Get(info.path, headers));
		} else {
			return TransformResult(client->Get(
			    info.path.c_str(), headers,
			    [&](const duckdb_httplib_openssl::Response &response) {
				    auto http_response = TransformResponse(response);
				    return info.response_handler(*http_response);
			    },
			    [&](const char *data, size_t data_length) {
				    if (state) {
					    state->total_bytes_received += data_length;
				    }
				    return info.content_handler(const_data_ptr_cast(data), data_length);
			    }));
		}
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
		if (info.send_post_as_get_request) {
			req.method = "GET";
		} else {
			req.method = "POST";
		}
		req.path = info.path;
		req.headers = TransformHeaders(info.headers, info.params);
		if (req.headers.find("Content-Type") == req.headers.end()) {
			req.headers.emplace("Content-Type", "application/octet-stream");
		}
		req.content_receiver = [&](const char *data, size_t data_length, uint64_t /*offset*/,
		                           uint64_t /*total_length*/) {
			if (state) {
				state->total_bytes_received += data_length;
			}
			info.buffer_out += string(data, data_length);
			return true;
		};
		// First assign body, this is the body that will be uploaded
		req.body.assign(const_char_ptr_cast(info.buffer_in), info.buffer_in_len);
		auto transformed_req = TransformResult(client->send(req));
		// Then, after actual re-quest, re-assign body to the response value of the POST request
		transformed_req->body.assign(const_char_ptr_cast(info.buffer_in), info.buffer_in_len);
		return transformed_req;
	}

private:
	duckdb_httplib_openssl::Headers TransformHeaders(const HTTPHeaders &header_map, const HTTPParams &params) {
		auto &httpfs_params = params.Cast<HTTPFSParams>();

		duckdb_httplib_openssl::Headers headers;
		for (auto &entry : header_map) {
			headers.insert(entry);
		}
		if (!httpfs_params.pre_merged_headers) {
			for (auto &entry : params.extra_headers) {
				headers.insert(entry);
			}
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
	optional_ptr<HTTPState> state;
};

unique_ptr<HTTPClient> HTTPFSUtil::InitializeClient(HTTPParams &http_params, const string &proto_host_port) {
	auto client = make_uniq<HTTPFSClient>(http_params.Cast<HTTPFSParams>(), proto_host_port, "", "");
	return std::move(client);
}

unique_ptr<HTTPClient> HTTPFSUtil::InitializeClientWithAuth(HTTPParams &http_params, const string &proto_host_port,
                                                            const string &basic_auth_username,
                                                            const string &basic_auth_password) {
	auto client = make_uniq<HTTPFSClient>(http_params.Cast<HTTPFSParams>(), proto_host_port,
	                                      basic_auth_username, basic_auth_password);
	return std::move(client);
}

void HTTPFSUtil::ParseBasicAuth(const string &url, string &username_out, string &password_out) {
	username_out.clear();
	password_out.clear();

	// Find the scheme end (://)
	auto scheme_end = url.find("://");
	if (scheme_end == string::npos) {
		return;
	}

	// Find the path start
	auto path_start = url.find('/', scheme_end + 3);
	if (path_start == string::npos) {
		path_start = url.length();
	}

	// Extract the authority part (between scheme:// and path)
	string authority = url.substr(scheme_end + 3, path_start - scheme_end - 3);

	// Check for @ which indicates userinfo
	auto at_pos = authority.find('@');
	if (at_pos == string::npos) {
		return;
	}

	string userinfo = authority.substr(0, at_pos);

	// Parse username:password
	auto colon_pos = userinfo.find(':');
	if (colon_pos != string::npos) {
		username_out = userinfo.substr(0, colon_pos);
		password_out = userinfo.substr(colon_pos + 1);
	} else {
		username_out = userinfo;
	}
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

} // namespace duckdb
