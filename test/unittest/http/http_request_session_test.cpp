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

	HTTPClientReuseMode GetClientReuseMode() const override {
		return reuse_mode;
	}

public:
	ClientLifecycle &lifecycle;
	HTTPClientReuseMode reuse_mode = HTTPClientReuseMode::SESSION_LOCAL;
	std::function<void()> on_initialize;
	std::function<void()> on_client_initialize;
	std::function<void()> on_close;
	std::function<unique_ptr<HTTPResponse>()> on_head;
};

static HTTPFSParams CreateParams(TrackingHTTPUtil &http_util) {
	HTTPFSParams result(http_util);
	result.client_reuse_mode = http_util.GetClientReuseMode();
	result.httpfs_util = http_util;
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

	session->InvalidateClients();
	auto stale_generation_replacement = make_shared_ptr<HTTPRequestSnapshot>(CreateParams(http_util));
	auto newer_generation = session->TryPublish(current.snapshot, stale_generation_replacement);
	REQUIRE(newer_generation.published);
	REQUIRE(newer_generation.current.snapshot == stale_generation_replacement);
	REQUIRE(newer_generation.current.client_generation > current.client_generation);
	REQUIRE(newer_generation.current.snapshot->type == HTTPRequestSnapshotType::HTTP);
}

TEST_CASE("HTTP client leases obey snapshot generations", "[httpfs][request-session]") {
	ClientLifecycle lifecycle;
	TrackingHTTPUtil http_util(lifecycle);
	TrackingHTTPUtil other_http_util(lifecycle);
	auto params = CreateParams(http_util);
	auto session = make_shared_ptr<HTTPRequestSession>(make_shared_ptr<HTTPRequestSnapshot>(params));
	auto session_ptr = session.get();

	http_util.on_initialize = [session_ptr]() {
		auto captured = session_ptr->Capture();
		REQUIRE(captured.snapshot);
	};
	http_util.on_close = [session_ptr]() {
		auto captured = session_ptr->Capture();
		REQUIRE(captured.snapshot);
	};

	{
		auto captured = session->Capture();
		auto request = captured.snapshot->CreateRequest();
		REQUIRE(&request.params->http_util == &http_util);
		auto lease = session->AcquireClient(captured, *request.params, "http://localhost");
		REQUIRE(lease.Client());
	}
	REQUIRE(lifecycle.initialized == 1);
	REQUIRE(lifecycle.closed == 0);
	REQUIRE(lifecycle.destroyed == 0);

	{
		auto captured = session->Capture();
		auto request = captured.snapshot->CreateRequest();
		auto lease = session->AcquireClient(captured, *request.params, "http://localhost");
		REQUIRE(lease.Client());
		REQUIRE(lifecycle.initialized == 1);
		lease.Invalidate();
	}
	REQUIRE(lifecycle.closed == 0);
	REQUIRE(lifecycle.destroyed == 1);

	{
		auto captured = session->Capture();
		auto request = captured.snapshot->CreateRequest();
		auto lease = session->AcquireClient(captured, *request.params, "http://localhost");
		REQUIRE(lease.Client());

		auto incompatible_params = CreateParams(other_http_util);
		auto replacement = make_shared_ptr<HTTPRequestSnapshot>(incompatible_params);
		REQUIRE(session->TryPublish(captured.snapshot, replacement).published);
	}
	REQUIRE(lifecycle.initialized == 2);
	REQUIRE(lifecycle.closed == 0);
	REQUIRE(lifecycle.destroyed == 2);

	{
		auto captured = session->Capture();
		auto request = captured.snapshot->CreateRequest();
		auto lease = session->AcquireClient(captured, *request.params, "http://localhost");
		REQUIRE(lease.Client());
	}
	REQUIRE(lifecycle.initialized == 3);
	REQUIRE(lifecycle.closed == 0);
	REQUIRE(lifecycle.destroyed == 2);

	session.reset();
	REQUIRE(lifecycle.closed == 1);
	REQUIRE(lifecycle.destroyed == 3);
}

TEST_CASE("HTTP request sessions reinitialize reused clients", "[httpfs][request-session]") {
	ClientLifecycle lifecycle;
	TrackingHTTPUtil http_util(lifecycle);
	auto params = CreateParams(http_util);
	params.state = make_shared_ptr<HTTPState>();
	auto initial_state = params.state;
	auto session = make_shared_ptr<HTTPRequestSession>(make_shared_ptr<HTTPRequestSnapshot>(params));
	auto session_ptr = session.get();
	http_util.on_client_initialize = [session_ptr]() {
		auto captured = session_ptr->Capture();
		REQUIRE(captured.snapshot);
	};

	{
		auto captured = session->Capture();
		auto request = captured.snapshot->CreateRequest();
		auto lease = session->AcquireClient(captured, *request.params, "http://localhost");
		REQUIRE(lease.Client());
	}
	REQUIRE(lifecycle.initialized == 1);
	REQUIRE(lifecycle.client_initializations == 1);
	REQUIRE(lifecycle.last_state == initial_state);

	auto replacement_params = params;
	replacement_params.state = make_shared_ptr<HTTPState>();
	auto replacement_state = replacement_params.state;
	auto captured = session->Capture();
	auto publication = session->TryPublish(captured.snapshot, make_shared_ptr<HTTPRequestSnapshot>(replacement_params));
	REQUIRE(publication.published);
	REQUIRE(publication.current.client_generation == captured.client_generation);

	{
		auto current = session->Capture();
		auto request = current.snapshot->CreateRequest();
		auto lease = session->AcquireClient(current, *request.params, "http://localhost");
		REQUIRE(lease.Client());
	}
	REQUIRE(lifecycle.initialized == 1);
	REQUIRE(lifecycle.client_initializations == 2);
	REQUIRE(lifecycle.last_state == replacement_state);
}

TEST_CASE("HTTP request sessions discard clients that fail reinitialization", "[httpfs][request-session]") {
	ClientLifecycle lifecycle;
	TrackingHTTPUtil http_util(lifecycle);
	auto params = CreateParams(http_util);
	auto session = make_shared_ptr<HTTPRequestSession>(make_shared_ptr<HTTPRequestSnapshot>(params));
	idx_t initialization_count = 0;
	http_util.on_client_initialize = [&]() {
		initialization_count++;
		if (initialization_count == 2) {
			throw IOException("reinitialization failed");
		}
	};

	{
		auto captured = session->Capture();
		auto request = captured.snapshot->CreateRequest();
		auto lease = session->AcquireClient(captured, *request.params, "http://localhost");
		REQUIRE(lease.Client());
	}

	auto captured = session->Capture();
	auto request = captured.snapshot->CreateRequest();
	REQUIRE_THROWS(session->AcquireClient(captured, *request.params, "http://localhost"));
	REQUIRE(lifecycle.initialized == 1);
	REQUIRE(lifecycle.client_initializations == 2);
	REQUIRE(lifecycle.destroyed == 1);

	captured = session->Capture();
	request = captured.snapshot->CreateRequest();
	{
		auto lease = session->AcquireClient(captured, *request.params, "http://localhost");
		REQUIRE(lease.Client());
	}
	REQUIRE(lifecycle.initialized == 2);
	REQUIRE(lifecycle.destroyed == 1);
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

TEST_CASE("HTTP client leases preserve backend reuse policy", "[httpfs][request-session]") {
	SECTION("shared clients return through the HTTP util") {
		ClientLifecycle lifecycle;
		TrackingHTTPUtil http_util(lifecycle);
		http_util.reuse_mode = HTTPClientReuseMode::SHARED;
		auto params = CreateParams(http_util);
		auto session = make_shared_ptr<HTTPRequestSession>(make_shared_ptr<HTTPRequestSnapshot>(params));

		auto captured = session->Capture();
		auto request = captured.snapshot->CreateRequest();
		{
			auto lease = session->AcquireClient(captured, *request.params, "http://localhost");
			REQUIRE(lease.Client());
		}
		REQUIRE(lifecycle.initialized == 1);
		REQUIRE(lifecycle.closed == 1);
		REQUIRE(lifecycle.destroyed == 1);
	}

	SECTION("client-free implementations do not initialize or close clients") {
		ClientLifecycle lifecycle;
		TrackingHTTPUtil http_util(lifecycle);
		http_util.reuse_mode = HTTPClientReuseMode::NONE;
		auto params = CreateParams(http_util);
		auto session = make_shared_ptr<HTTPRequestSession>(make_shared_ptr<HTTPRequestSnapshot>(params));

		auto captured = session->Capture();
		auto request = captured.snapshot->CreateRequest();
		{
			auto lease = session->AcquireClient(captured, *request.params, "http://localhost");
			REQUIRE_FALSE(lease.Client());
		}
		REQUIRE(lifecycle.initialized == 0);
		REQUIRE(lifecycle.closed == 0);
		REQUIRE(lifecycle.destroyed == 0);
	}
}

} // namespace duckdb
