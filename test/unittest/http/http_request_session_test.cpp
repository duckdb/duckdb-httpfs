#include "catch.hpp"

#include "http/http_request_session.hpp"
#include "s3/s3fs.hpp"

#include <functional>

namespace duckdb {

namespace {

struct ClientLifecycle {
	idx_t initialized = 0;
	idx_t client_initializations = 0;
	idx_t extended_client_initializations = 0;
	idx_t closed = 0;
	idx_t destroyed = 0;
	HTTPClientCachePolicy last_cache_policy = HTTPClientCachePolicy::DEFAULT;
	shared_ptr<HTTPState> last_state;
};

class TrackingHTTPClient : public HTTPClient {
public:
	TrackingHTTPClient(const string &base_url, ClientLifecycle &lifecycle_p)
	    : HTTPClient(base_url), lifecycle(lifecycle_p) {
	}

	~TrackingHTTPClient() override {
		lifecycle.destroyed++;
	}

public:
	void Initialize(HTTPParams &params) override {
		lifecycle.client_initializations++;
		lifecycle.last_state = params.Cast<HTTPFSParams>().state;
		if (on_initialize) {
			on_initialize();
		}
	}
	unique_ptr<HTTPResponse> Get(GetRequestInfo &) override {
		return Success();
	}
	unique_ptr<HTTPResponse> Put(PutRequestInfo &) override {
		return Success();
	}
	unique_ptr<HTTPResponse> Head(HeadRequestInfo &) override {
		if (on_head) {
			return on_head();
		}
		return Success();
	}
	unique_ptr<HTTPResponse> Delete(DeleteRequestInfo &) override {
		return Success();
	}
	unique_ptr<HTTPResponse> Post(PostRequestInfo &) override {
		return Success();
	}
	unique_ptr<HTTPResponse> Options(OptionsRequestInfo &) override {
		return Success();
	}

private:
	static unique_ptr<HTTPResponse> Success() {
		return make_uniq<HTTPResponse>(HTTPStatusCode::OK_200);
	}

public:
	std::function<void()> on_initialize;
	std::function<unique_ptr<HTTPResponse>()> on_head;

private:
	ClientLifecycle &lifecycle;
};

class TrackingHTTPUtil : public HTTPFSUtil {
public:
	explicit TrackingHTTPUtil(ClientLifecycle &lifecycle_p) : lifecycle(lifecycle_p) {
	}

public:
	unique_ptr<HTTPClient> InitializeClient(HTTPParams &params, const string &proto_host_port) override {
		lifecycle.initialized++;
		if (on_initialize) {
			on_initialize();
		}
		auto result = make_uniq<TrackingHTTPClient>(proto_host_port, lifecycle);
		result->on_initialize = on_client_initialize;
		result->on_head = on_head;
		result->Initialize(params);
		return result;
	}

	unique_ptr<HTTPClient> InitializeClientExtended(HTTPParams &params, const string &proto_host_port,
	                                                const HTTPClientInitializationOptions &options) override {
		lifecycle.extended_client_initializations++;
		lifecycle.last_cache_policy = options.cache_policy;
		return InitializeClient(params, proto_host_port);
	}

	void CloseClient(unique_ptr<HTTPClient> &&client) override {
		lifecycle.closed++;
		if (on_close) {
			on_close();
		}
		client.reset();
	}

public:
	ClientLifecycle &lifecycle;
	std::function<void()> on_initialize;
	std::function<void()> on_client_initialize;
	std::function<void()> on_close;
	std::function<unique_ptr<HTTPResponse>()> on_head;
};

static HTTPFSParams CreateParams(TrackingHTTPUtil &http_util) {
	HTTPFSParams result(http_util);
	return result;
}

} // namespace

TEST_CASE("HTTP request snapshots are immutable and checked", "[httpfs][request-session]") {
	ClientLifecycle lifecycle;
	TrackingHTTPUtil http_util(lifecycle);
	auto params = CreateParams(http_util);
	params.user_agent = "httpfs-session-test";
	params.extra_headers["X-Test"] = "first";

	auto initial_snapshot = make_shared_ptr<HTTPRequestSnapshot>(params);
	auto session = make_shared_ptr<HTTPRequestSession>(initial_snapshot);
	auto initial = session->Capture();

	params.extra_headers["X-Test"] = "second";
	auto replacement = make_shared_ptr<HTTPRequestSnapshot>(params);
	auto publication = session->TryPublish(initial.snapshot, replacement);
	REQUIRE(publication.published);
	auto current = publication.current;

	auto initial_request = initial.snapshot->CreateRequest();
	REQUIRE(initial_request.headers.GetHeaderValue("User-Agent") == "httpfs-session-test");
	REQUIRE(initial_request.headers.GetHeaderValue("X-Test") == "first");
	REQUIRE(initial_request.configured_headers.user_agent == "httpfs-session-test");
	REQUIRE(initial_request.configured_headers.extra_headers.at("X-Test") == "first");
	REQUIRE(initial_request.params->user_agent.empty());
	REQUIRE(initial_request.params->extra_headers.empty());

	HTTPHeaders caller_headers;
	caller_headers["User-Agent"] = "caller-agent";
	caller_headers["X-Test"] = "caller";
	auto current_request = current.snapshot->CreateRequest(std::move(caller_headers));
	REQUIRE(current_request.headers.GetHeaderValue("User-Agent") == "caller-agent");
	REQUIRE(current_request.headers.GetHeaderValue("X-Test") == "second");

	params.extra_headers["uSeR-aGeNt"] = "extra-agent";
	auto override_snapshot = make_shared_ptr<HTTPRequestSnapshot>(params);
	HTTPHeaders overridden_headers;
	overridden_headers["USER-AGENT"] = "caller-agent";
	auto override_request = override_snapshot->CreateRequest(std::move(overridden_headers));
	REQUIRE(override_request.headers.GetHeaderValue("User-Agent") == "extra-agent");

	auto stale_replacement = make_shared_ptr<HTTPRequestSnapshot>(CreateParams(http_util));
	auto stale_publication = session->TryPublish(initial.snapshot, stale_replacement);
	REQUIRE_FALSE(stale_publication.published);
	REQUIRE(stale_publication.current.snapshot == current.snapshot);

	session->InvalidateConnections();
	auto replacement_after_invalidation = make_shared_ptr<HTTPRequestSnapshot>(CreateParams(http_util));
	auto after_invalidation = session->TryPublish(current.snapshot, replacement_after_invalidation);
	REQUIRE(after_invalidation.published);
	REQUIRE(after_invalidation.current.snapshot == replacement_after_invalidation);
	REQUIRE(after_invalidation.current.snapshot->type == HTTPRequestSnapshotType::HTTP);
}

TEST_CASE("HTTP transport retries bypass the client cache", "[httpfs][request-session]") {
	ClientLifecycle lifecycle;
	TrackingHTTPUtil http_util(lifecycle);
	auto params = CreateParams(http_util);
	params.retries = 1;
	params.retry_wait_ms = 0;
	idx_t requests = 0;
	http_util.on_head = [&]() {
		requests++;
		if (requests == 1) {
			auto response = make_uniq<HTTPResponse>(HTTPStatusCode::INVALID);
			response->request_error = "stale connection";
			return response;
		}
		REQUIRE(lifecycle.extended_client_initializations == 1);
		REQUIRE(lifecycle.last_cache_policy == HTTPClientCachePolicy::BYPASS_CACHE);
		return make_uniq<HTTPResponse>(HTTPStatusCode::OK_200);
	};

	HeadRequestInfo request("http://localhost/test", HTTPHeaders(), params);
	auto response = http_util.Request(request);
	REQUIRE(response);
	REQUIRE(response->Success());
	REQUIRE(requests == 2);
	REQUIRE(lifecycle.initialized == 2);
	REQUIRE(lifecycle.extended_client_initializations == 1);
	REQUIRE(lifecycle.last_cache_policy == HTTPClientCachePolicy::BYPASS_CACHE);
}

TEST_CASE("HTTP status retries allow cached clients", "[httpfs][request-session]") {
	ClientLifecycle lifecycle;
	TrackingHTTPUtil http_util(lifecycle);
	auto params = CreateParams(http_util);
	params.retries = 1;
	params.retry_wait_ms = 0;
	idx_t requests = 0;
	http_util.on_head = [&]() {
		requests++;
		if (requests == 1) {
			return make_uniq<HTTPResponse>(HTTPStatusCode::InternalServerError_500);
		}
		REQUIRE(lifecycle.extended_client_initializations == 1);
		REQUIRE(lifecycle.last_cache_policy == HTTPClientCachePolicy::DEFAULT);
		return make_uniq<HTTPResponse>(HTTPStatusCode::OK_200);
	};

	HeadRequestInfo request("http://localhost/test", HTTPHeaders(), params);
	auto response = http_util.Request(request);
	REQUIRE(response);
	REQUIRE(response->Success());
	REQUIRE(requests == 2);
	REQUIRE(lifecycle.initialized == 2);
	REQUIRE(lifecycle.extended_client_initializations == 1);
	REQUIRE(lifecycle.last_cache_policy == HTTPClientCachePolicy::DEFAULT);
}

TEST_CASE("HTTP request snapshots copy HTTPFS parameters through one source", "[httpfs][request-session]") {
	ClientLifecycle lifecycle;
	TrackingHTTPUtil http_util(lifecycle);
	auto params = CreateParams(http_util);
	params.timeout = 17;
	params.timeout_usec = 23;
	params.retries = 5;
	params.http_proxy = "proxy.test";
	params.http_proxy_port = 8123;
	params.http_proxy_username = "user";
	params.http_proxy_password = "password";
	params.user_agent = "snapshot-agent";
	params.extra_headers["X-Snapshot"] = "present";
	params.force_download = true;
	params.force_download_threshold = 42;
	params.hf_max_per_page = 99;
	params.state = make_shared_ptr<HTTPState>();

	HTTPRequestSnapshot snapshot(params);
	auto request = snapshot.CreateRequest();
	REQUIRE(&request.params->http_util == &http_util);
	REQUIRE(request.params->timeout == 17);
	REQUIRE(request.params->timeout_usec == 23);
	REQUIRE(request.params->retries == 5);
	REQUIRE(request.params->http_proxy == "proxy.test");
	REQUIRE(request.params->http_proxy_port == 8123);
	REQUIRE(request.params->http_proxy_username == "user");
	REQUIRE(request.params->http_proxy_password == "password");
	REQUIRE(request.params->user_agent.empty());
	REQUIRE(request.params->extra_headers.empty());
	REQUIRE(request.configured_headers.user_agent == "snapshot-agent");
	REQUIRE(request.configured_headers.extra_headers == params.extra_headers);
	REQUIRE(request.headers.GetHeaderValue("User-Agent") == "snapshot-agent");
	REQUIRE(request.headers.GetHeaderValue("X-Snapshot") == "present");
	REQUIRE(request.params->force_download);
	REQUIRE(request.params->force_download_threshold == 42);
	REQUIRE(request.params->hf_max_per_page == 99);
	REQUIRE(request.params->state == params.state);
}

} // namespace duckdb
