#include "http/httpfs_client.hpp"
#include "http/http_state.hpp"
#define CPPHTTPLIB_OPENSSL_SUPPORT
#include "httplib.hpp"

namespace duckdb {

class HTTPFSClient : public HTTPClient {
private:
	class GetTransferState {
	public:
		GetTransferState(HTTPFSClient &client_p, GetRequestInfo &request_p)
		    : client(client_p), request(request_p), request_monotonic_start(TimePoint::Tick()) {
		}

	public:
		bool HandleResponse(const duckdb_httplib_openssl::Response &response) {
			auto http_response = client.TransformResponse(response);
			if (static_cast<int>(http_response->status) >= 400) {
				deferred_response = std::move(http_response);
				return true;
			}
			if (request.response_handler && !request.response_handler(*http_response)) {
				stopped_response = std::move(http_response);
				return false;
			}
			return true;
		}

		bool HandleContent(const char *data, size_t data_length) {
			RecordFirstByte();
			auto chunk_size = NumericCast<idx_t>(data_length);
			total_bytes += chunk_size;
			if (client.state) {
				client.state->RecordBytesReceived(chunk_size);
			}
			if (deferred_response) {
				deferred_response->body.append(data, data_length);
				return true;
			}
			return !request.content_handler || request.content_handler(const_data_ptr_cast(data), chunk_size);
		}

		unique_ptr<HTTPResponse> Finish(duckdb_httplib_openssl::Result result) {
			request.bytes_received = total_bytes;
			if (deferred_response) {
				if (request.response_handler) {
					request.response_handler(*deferred_response);
				}
				return std::move(deferred_response);
			}
			if (stopped_response) {
				return std::move(stopped_response);
			}
			return client.TransformResult(result);
		}

	private:
		void RecordFirstByte() {
			if (!first_chunk) {
				return;
			}
			first_chunk = false;
			request.have_time_to_fst_byte = true;
			const auto elapsed_nanos = TimePoint::ElapsedNanos(request_monotonic_start, TimePoint::Tick());
			request.time_to_fst_byte_sec = elapsed_nanos > 0 ? static_cast<double>(elapsed_nanos) / 1e9 : 0;
		}

	private:
		HTTPFSClient &client;
		GetRequestInfo &request;
		const TimePoint request_monotonic_start;
		idx_t total_bytes = 0;
		bool first_chunk = true;
		unique_ptr<HTTPResponse> deferred_response;
		unique_ptr<HTTPResponse> stopped_response;
	};

public:
	HTTPFSClient(HTTPFSParams &http_params, const string &proto_host_port) : HTTPClient(proto_host_port) {
		client = make_uniq<duckdb_httplib_openssl::Client>(proto_host_port);
		Initialize(http_params);
	}

public:
	void Initialize(HTTPParams &http_p) override {
		auto &http_params = http_p.Cast<HTTPFSParams>();
		client->set_follow_location(http_params.follow_location);
		client->set_keep_alive(http_params.keep_alive);
		if (!http_params.ca_cert_file.empty()) {
			client->set_ca_cert_path(http_params.ca_cert_file.c_str());
		} else {
			client->set_ca_cert_path("");
		}
		const bool verify_ssl =
		    http_params.override_verify_ssl ? http_params.verify_ssl : http_params.enable_server_cert_verification;
		client->enable_server_certificate_verification(verify_ssl);
		client->set_write_timeout(NumericCast<time_t>(http_params.timeout),
		                          NumericCast<time_t>(http_params.timeout_usec));
		client->set_read_timeout(NumericCast<time_t>(http_params.timeout),
		                         NumericCast<time_t>(http_params.timeout_usec));
		client->set_connection_timeout(NumericCast<time_t>(http_params.timeout),
		                               NumericCast<time_t>(http_params.timeout_usec));
		client->set_decompress(false);
		if (!http_params.bearer_token.empty()) {
			client->set_bearer_token_auth(http_params.bearer_token.c_str());
		} else {
			client->set_bearer_token_auth("");
		}

		if (!http_params.http_proxy.empty()) {
			client->set_proxy(http_params.http_proxy, NumericCast<int>(http_params.http_proxy_port));

			if (!http_params.http_proxy_username.empty()) {
				client->set_proxy_basic_auth(http_params.http_proxy_username, http_params.http_proxy_password);
			} else {
				client->set_proxy_basic_auth("", "");
			}
		} else {
			client->set_proxy("", -1);
			client->set_proxy_basic_auth("", "");
		}
		state = http_params.state;
	}

	static void AddUserAgentIfAvailable(HTTPFSParams &http_params, HTTPHeaders &header_map) {
		if (!http_params.user_agent.empty()) {
			header_map.Insert("User-Agent", http_params.user_agent);
		}
	}

	unique_ptr<HTTPResponse> Get(GetRequestInfo &info) override {
		AddUserAgentIfAvailable(info.params.Cast<HTTPFSParams>(), info.headers);
		if (state) {
			state->RecordRequest(RequestType::GET_REQUEST);
		}
		auto headers = TransformHeaders(info.headers, info.params);
		if (!info.response_handler && !info.content_handler) {
			return TransformBufferedResult(client->Get(info.path, headers));
		}
		GetTransferState transfer(*this, info);
		auto result = client->Get(
		    info.path.c_str(), headers,
		    [&](const duckdb_httplib_openssl::Response &response) { return transfer.HandleResponse(response); },
		    [&](const char *data, size_t data_length) { return transfer.HandleContent(data, data_length); });
		return transfer.Finish(std::move(result));
	}
	unique_ptr<HTTPResponse> Put(PutRequestInfo &info) override {
		AddUserAgentIfAvailable(info.params.Cast<HTTPFSParams>(), info.headers);
		if (state) {
			state->RecordRequest(RequestType::PUT_REQUEST);
			state->RecordBytesSent(info.buffer_in_len);
		}
		auto headers = TransformHeaders(info.headers, info.params);
		auto body_size = NumericCast<size_t>(info.buffer_in_len);
		auto body = info.buffer_in;
		auto content_provider = [body, body_size](size_t offset, size_t length,
		                                          duckdb_httplib_openssl::DataSink &sink) {
			if (offset > body_size || length > body_size - offset) {
				return false;
			}
			return sink.write(const_char_ptr_cast(body + NumericCast<idx_t>(offset)), length);
		};
		return TransformBufferedResult(
		    client->Put(info.path, headers, body_size, std::move(content_provider), info.content_type));
	}

	unique_ptr<HTTPResponse> Head(HeadRequestInfo &info) override {
		AddUserAgentIfAvailable(info.params.Cast<HTTPFSParams>(), info.headers);
		if (state) {
			state->RecordRequest(RequestType::HEAD_REQUEST);
		}
		auto headers = TransformHeaders(info.headers, info.params);
		return TransformBufferedResult(client->Head(info.path, headers));
	}

	unique_ptr<HTTPResponse> Delete(DeleteRequestInfo &info) override {
		AddUserAgentIfAvailable(info.params.Cast<HTTPFSParams>(), info.headers);
		if (state) {
			state->RecordRequest(RequestType::DELETE_REQUEST);
		}
		auto headers = TransformHeaders(info.headers, info.params);
		return TransformBufferedResult(client->Delete(info.path, headers));
	}

	unique_ptr<HTTPResponse> Options(OptionsRequestInfo &info) override {
		if (state) {
			state->RecordRequest(RequestType::OPTIONS_REQUEST);
		}
		auto headers = TransformHeaders(info.headers, info.params);
		return TransformBufferedResult(client->Options(info.path, headers));
	}

	unique_ptr<HTTPResponse> Post(PostRequestInfo &info) override {
		AddUserAgentIfAvailable(info.params.Cast<HTTPFSParams>(), info.headers);
		if (state) {
			state->RecordRequest(RequestType::POST_REQUEST);
			state->RecordBytesSent(info.buffer_in_len);
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
			info.buffer_out += string(data, data_length);
			return true;
		};
		// First assign body, this is the body that will be uploaded
		req.body.assign(const_char_ptr_cast(info.buffer_in), info.buffer_in_len);
		auto transformed_req = TransformResult(client->send(req));
		transformed_req->body = info.buffer_out;
		if (state) {
			state->RecordBytesReceived(info.buffer_out.size());
		}
		return transformed_req;
	}

private:
	static duckdb_httplib_openssl::Headers TransformHeaders(const HTTPHeaders &header_map, const HTTPParams &params) {
		duckdb_httplib_openssl::Headers headers;
		for (auto &entry : header_map) {
			headers.emplace(entry.first, HTTPFSHeaderValue::IsEmpty(entry.second) ? string() : entry.second);
		}
		for (auto &entry : params.extra_headers) {
			headers.emplace(entry.first, HTTPFSHeaderValue::IsEmpty(entry.second) ? string() : entry.second);
		}
		return headers;
	}

	static unique_ptr<HTTPResponse> TransformResponse(const duckdb_httplib_openssl::Response &response) {
		auto status_code = HTTPUtil::ToStatusCode(response.status);
		auto result = make_uniq<HTTPResponse>(status_code);
		result->body = response.body;
		result->reason = response.reason;
		for (auto &entry : response.headers) {
			result->headers.Insert(entry.first, entry.second);
		}
		return result;
	}

	static unique_ptr<HTTPResponse> TransformResult(const duckdb_httplib_openssl::Result &res) {
		if (res.error() == duckdb_httplib_openssl::Error::Success) {
			auto &response = res.value();
			return TransformResponse(response);
		} else {
			auto result = make_uniq<HTTPResponse>(HTTPStatusCode::INVALID);
			result->request_error = to_string(res.error());
			return result;
		}
	}

	unique_ptr<HTTPResponse> TransformBufferedResult(const duckdb_httplib_openssl::Result &res) {
		auto response = TransformResult(res);
		if (state) {
			state->RecordBytesReceived(response->body.size());
		}
		return response;
	}

private:
	unique_ptr<duckdb_httplib_openssl::Client> client;
	optional_ptr<HTTPState> state;
};

unique_ptr<HTTPClient> HTTPFSUtil::InitializeClient(HTTPParams &http_params, const string &proto_host_port) {
	auto client = make_uniq<HTTPFSClient>(http_params.Cast<HTTPFSParams>(), proto_host_port);
	return std::move(client);
}

} // namespace duckdb
