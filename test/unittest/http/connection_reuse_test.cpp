#include "catch.hpp"

#include "http/http_test_helper.hpp"
#include "http/http_metadata_cache.hpp"
#include "http/http_request_session.hpp"
#include "http/http_state.hpp"
#include "http/httpfs_client.hpp"
#include "duckdb/main/config.hpp"
#include "duckdb/main/http/http_transport_manager.hpp"

namespace duckdb {

namespace {

static void RunCompletedErrorFollowup(const string &client_implementation) {
	MockS3ServerConfig config;
	config.failures.transient_head_failures = 1;
	config.failures.failure_is_request_timeout = false;
	MockS3Server server(std::move(config));

	DuckDB db(nullptr);
	Connection con(db);
	HTTPTestHelper::Configure(db, con, 0, client_implementation, true);

	HTTPTestHelper::RequireQueryOk(con, "BEGIN TRANSACTION");
	auto &fs = FileSystem::GetFileSystem(*con.context);
	auto handle = fs.OpenFile(server.HTTPPath(), FileFlags::FILE_FLAGS_READ | FileFlags::FILE_FLAGS_DIRECT_IO);
	REQUIRE(handle);
	HTTPTestHelper::RequireQueryOk(con, "COMMIT");

	auto observations = server.Observations();
	INFO(MockS3DescribeObservations(observations));
	REQUIRE(HTTPTestHelper::CountRequests(observations, "HEAD", 400) == 1);
	REQUIRE(HTTPTestHelper::CountRequests(observations, "GET", 206, "bytes=0-1") == 1);
}

static void RunCurlTerminalTransportErrorIsNotReused() {
	MockS3ServerConfig config;
	config.range.behavior = MockS3RangeBehavior::TRUNCATE_TRANSFER;
	config.range.behavior_requests = 1;
	config.failures.head_not_found_requests = 2;
	MockS3Server server(std::move(config));

	DuckDB db(nullptr);
	Connection con(db);
	HTTPTestHelper::Configure(db, con, 0, "curl", true);
	HTTPTestHelper::RequireQueryOk(con, "CALL enable_logging('HTTPFSInfo')");
	HTTPTestHelper::RequireQueryOk(con, "BEGIN TRANSACTION");

	auto session = db.instance->config.GetHTTPTransportManager().CreateSession(*con.context, server.HTTPPath());
	auto &params = session.Parameters();
	HTTPHeaders headers;
	headers.Insert("Range", "bytes=0-3");
	GetRequestInfo failed_request(server.HTTPPath(), headers, params, nullptr, nullptr);
	failed_request.try_request = true;
	auto failed_response = session.Request(failed_request);
	REQUIRE(failed_response);
	REQUIRE(failed_response->HasRequestError());

	HeadRequestInfo completed_error_request(server.HTTPPath(), HTTPHeaders(), params);
	auto completed_error_response = session.Request(completed_error_request);
	REQUIRE(completed_error_response);
	REQUIRE_FALSE(completed_error_response->HasRequestError());
	REQUIRE(completed_error_response->status == HTTPStatusCode::NotFound_404);

	auto hits = con.Query("SELECT count(*) FROM duckdb_logs WHERE message LIKE '%connection_cache_hit%'");
	REQUIRE(hits);
	REQUIRE_FALSE(hits->HasError());
	REQUIRE(hits->GetValue(0, 0).GetValue<idx_t>() == 0);

	HeadRequestInfo reused_error_request(server.HTTPPath(), HTTPHeaders(), params);
	auto reused_error_response = session.Request(reused_error_request);
	REQUIRE(reused_error_response);
	REQUIRE_FALSE(reused_error_response->HasRequestError());
	REQUIRE(reused_error_response->status == HTTPStatusCode::NotFound_404);

	hits = con.Query("SELECT count(*) FROM duckdb_logs WHERE message LIKE '%connection_cache_hit%'");
	REQUIRE(hits);
	REQUIRE_FALSE(hits->HasError());
	REQUIRE(hits->GetValue(0, 0).GetValue<idx_t>() == 1);
	HTTPTestHelper::RequireQueryOk(con, "COMMIT");
}

static void RunCurlExactEmptyResponseHeaderScenario() {
	MockS3ServerConfig config;
	config.metadata.exact_empty_response_headers = true;
	config.metadata.response_headers.emplace_back("X-Empty", "");
	MockS3Server server(std::move(config));

	HTTPFSCurlUtil http_util;
	HTTPFSParams params(http_util);
	auto client = http_util.InitializeClient(params, "http://" + server.Endpoint());
	HeadRequestInfo request(server.HTTPPath(), HTTPHeaders(), params);
	auto response = http_util.Request(request, client);
	REQUIRE(response);
	REQUIRE(response->Success());
	REQUIRE(response->headers.HasHeader("X-Empty"));
	REQUIRE(response->headers.GetHeaderValue("X-Empty").empty());
}

static void RunCurlRedirectedResponseHeaderScenario() {
	MockS3ServerConfig config;
	config.metadata.redirect_head = true;
	config.metadata.redirect_response_headers.emplace_back("X-Redirect-Only", "redirect");
	config.metadata.response_headers.emplace_back("X-Repeated", "first");
	config.metadata.response_headers.emplace_back("X-Repeated", "second");
	MockS3Server server(std::move(config));

	HTTPFSCurlUtil http_util;
	HTTPFSParams params(http_util);
	params.follow_location = true;
	auto client = http_util.InitializeClient(params, "http://" + server.Endpoint());
	HeadRequestInfo request(server.HTTPPath(), HTTPHeaders(), params);
	auto response = http_util.Request(request, client);
	REQUIRE(response);
	REQUIRE(response->Success());
	REQUIRE(response->headers.GetHeaderValues("X-Repeated") == vector<string> {"first", "second"});
	REQUIRE_FALSE(response->headers.HasHeader("X-Redirect-Only"));
}

static void RunCurlRequestHeaderScenario() {
	MockS3Server server {MockS3ServerConfig()};
	HTTPFSCurlUtil http_util;
	HTTPFSParams params(http_util);
	auto client = http_util.InitializeClient(params, "http://" + server.Endpoint());
	HTTPHeaders headers;
	headers["X-Empty"] = "";
	headers["X-Whitespace"] = " \t ";
	headers["X-Value"] = "value";
	HeadRequestInfo request(server.HTTPPath(), headers, params);
	auto response = http_util.Request(request, client);
	REQUIRE(response);
	REQUIRE(response->Success());

	auto observations = server.Observations();
	REQUIRE(observations.size() == 1);
	REQUIRE(MockS3HeaderValues(observations[0], "X-Empty") == vector<string> {""});
	REQUIRE(MockS3HeaderValues(observations[0], "X-Whitespace") == vector<string> {""});
	REQUIRE(MockS3HeaderValues(observations[0], "X-Value") == vector<string> {"value"});
}

static void RunHTTPStateCounterScenario(HTTPFSUtil &http_util) {
	MockS3ServerConfig config;
	config.http_response.object_put_body = "put response";
	config.http_response.object_delete_body = "delete response";
	config.http_response.options_body = "options response";
	MockS3Server server(std::move(config));
	auto state = make_shared_ptr<HTTPState>();
	HTTPFSParams params(http_util);
	params.state = state;
	auto client = http_util.InitializeClient(params, "http://" + server.Endpoint());
	const string put_body = "put";
	const string post_body = "post";

	HeadRequestInfo head(server.HTTPPath(), HTTPHeaders(), params);
	auto head_response = http_util.Request(head, client);
	REQUIRE(head_response);

	GetRequestInfo get(server.HTTPPath(), HTTPHeaders(), params, nullptr, nullptr);
	auto get_response = http_util.Request(get, client);
	REQUIRE(get_response);

	PutRequestInfo put(server.HTTPPath(), HTTPHeaders(), params, const_data_ptr_cast(put_body.data()), put_body.size(),
	                   "application/octet-stream");
	auto put_response = http_util.Request(put, client);
	REQUIRE(put_response);

	PostRequestInfo post(server.HTTPPath() + "?uploads=", HTTPHeaders(), params, const_data_ptr_cast(post_body.data()),
	                     post_body.size());
	auto post_response = http_util.Request(post, client);
	REQUIRE(post_response);

	DeleteRequestInfo delete_request(server.HTTPPath(), HTTPHeaders(), params);
	auto delete_response = http_util.Request(delete_request, client);
	REQUIRE(delete_response);

	OptionsRequestInfo options(server.HTTPPath(), HTTPHeaders(), params);
	auto options_response = http_util.Request(options, client);
	REQUIRE(options_response);

	auto counters = state->GetCounters();
	REQUIRE(counters.head_count == 1);
	REQUIRE(counters.get_count == 1);
	REQUIRE(counters.put_count == 1);
	REQUIRE(counters.post_count == 1);
	REQUIRE(counters.delete_count == 1);
	REQUIRE(counters.options_count == 1);
	REQUIRE(counters.total_bytes_sent == put_body.size() + post_body.size());
	REQUIRE(counters.total_bytes_received == head_response->body.size() + get_response->body.size() +
	                                             put_response->body.size() + post_response->body.size() +
	                                             delete_response->body.size() + options_response->body.size());
	REQUIRE_FALSE(state->IsEmpty());
	state->Reset();
	REQUIRE(state->IsEmpty());
}

static void RunCurlConnectionCachingPolicyScenario() {
	HTTPFSCurlUtil caching_enabled(true);
	HTTPFSCurlUtil caching_disabled(false);
	REQUIRE(caching_enabled.GetTransportReusePolicy() == HTTPTransportReusePolicy::SHARED);
	REQUIRE(caching_disabled.GetTransportReusePolicy() == HTTPTransportReusePolicy::EPHEMERAL);
}

static void RunConnectionCompatibilityScenario(HTTPFSUtil &http_util) {
	HTTPFSParams params(http_util);
	REQUIRE_FALSE(params.CanReuseTransport());
	REQUIRE_FALSE(HTTPFSConnectionConfig::Create(params).reuse_domain.IsValid());
	params.http_proxy = "proxy.test";
	params.http_proxy_port = 8080;
	params.http_proxy_username = "user";
	params.http_proxy_password = "password";
	params.override_verify_ssl = true;
	params.verify_ssl = true;
	REQUIRE(params.VerifyServerCertificate());
	auto client = http_util.InitializeClient(params, "http://localhost");
	REQUIRE(client->CanReuse(params));
	REQUIRE(params.GetTransportReuseDomain() != 0);

	HTTPFSParams equivalent(http_util);
	equivalent.http_proxy = params.http_proxy;
	equivalent.http_proxy_port = params.http_proxy_port;
	equivalent.http_proxy_username = params.http_proxy_username;
	equivalent.http_proxy_password = params.http_proxy_password;
	equivalent.override_verify_ssl = params.override_verify_ssl;
	equivalent.verify_ssl = params.verify_ssl;
	equivalent.RefreshTransportReuseDomain();
	REQUIRE(equivalent.GetTransportReuseDomain() == params.GetTransportReuseDomain());

	auto require_incompatible = [&](const std::function<void(HTTPFSParams &)> &modify) {
		auto changed = params;
		modify(changed);
		REQUIRE_FALSE(client->CanReuse(changed));
		REQUIRE_THROWS_AS(client->Initialize(changed), InvalidInputException);
	};
	require_incompatible([](HTTPFSParams &changed) { changed.http_proxy = "other-proxy.test"; });
	require_incompatible([](HTTPFSParams &changed) { changed.http_proxy_port = 8123; });
	require_incompatible([](HTTPFSParams &changed) { changed.http_proxy_username = "other-user"; });
	require_incompatible([](HTTPFSParams &changed) { changed.http_proxy_password = "other-password"; });
	require_incompatible([](HTTPFSParams &changed) { changed.http_proxy.clear(); });
	require_incompatible([](HTTPFSParams &changed) { changed.ca_cert_file = "/tmp/test-ca.pem"; });
	require_incompatible([](HTTPFSParams &changed) { changed.verify_ssl = false; });
	require_incompatible([](HTTPFSParams &changed) { changed.override_verify_ssl = false; });

	auto bearer_changed = params;
	bearer_changed.bearer_token = "token";
	bearer_changed.RefreshTransportReuseDomain();
	REQUIRE(bearer_changed.GetTransportReuseDomain() == params.GetTransportReuseDomain());
	REQUIRE(client->CanReuse(bearer_changed));

	auto ignored_backend_default = params;
	if (http_util.GetName() == "HTTPFS-Curl") {
		ignored_backend_default.enable_curl_server_cert_verification = false;
	} else {
		ignored_backend_default.enable_server_cert_verification = true;
	}
	ignored_backend_default.RefreshTransportReuseDomain();
	REQUIRE(ignored_backend_default.GetTransportReuseDomain() == params.GetTransportReuseDomain());

	HTTPFSParams backend_default(http_util);
	REQUIRE(backend_default.VerifyServerCertificate() == (http_util.GetName() == "HTTPFS-Curl"));
	backend_default.RefreshTransportReuseDomain();
	auto changed_backend_default = backend_default;
	if (http_util.GetName() == "HTTPFS-Curl") {
		changed_backend_default.enable_curl_server_cert_verification = false;
	} else {
		changed_backend_default.enable_server_cert_verification = true;
	}
	changed_backend_default.RefreshTransportReuseDomain();
	REQUIRE(changed_backend_default.VerifyServerCertificate() != backend_default.VerifyServerCertificate());
	REQUIRE(changed_backend_default.GetTransportReuseDomain() != backend_default.GetTransportReuseDomain());

	HTTPFSParams first_without_proxy(http_util);
	first_without_proxy.http_proxy_port = 1234;
	first_without_proxy.http_proxy_username = "ignored-user";
	first_without_proxy.http_proxy_password = "ignored-password";
	first_without_proxy.RefreshTransportReuseDomain();
	HTTPFSParams second_without_proxy(http_util);
	second_without_proxy.http_proxy_port = 5678;
	second_without_proxy.http_proxy_username = "other-ignored-user";
	second_without_proxy.http_proxy_password = "other-ignored-password";
	second_without_proxy.RefreshTransportReuseDomain();
	REQUIRE(first_without_proxy.GetTransportReuseDomain() == second_without_proxy.GetTransportReuseDomain());
}

static void RunTransportReuseDomainBoundScenario() {
	HTTPFSUtil http_util;
	for (idx_t domain = 0; domain < 256; domain++) {
		HTTPFSParams params(http_util);
		params.http_proxy = "proxy" + to_string(domain) + ".test";
		params.RefreshTransportReuseDomain();
		REQUIRE(params.CanReuseTransport());
	}
	HTTPFSParams overflow(http_util);
	overflow.http_proxy = "overflow-proxy.test";
	overflow.RefreshTransportReuseDomain();
	REQUIRE(overflow.GetTransportReuseDomain() != 0);
	REQUIRE_FALSE(overflow.CanReuseTransport());
	overflow.http_proxy = "changed-overflow-proxy.test";
	REQUIRE_THROWS_AS(http_util.InitializeClient(overflow, "http://localhost"), InvalidInputException);
}

static void RunRawParametersScenario() {
	HTTPFSUtil http_util;
	for (idx_t domain = 0; domain < 300; domain++) {
		auto params = HTTPFSUtil::InitializeRawParameters(http_util, nullptr, nullptr);
		params->http_proxy = "unused-proxy" + to_string(domain) + ".test";
		REQUIRE(params->GetTransportReuseDomain() == 0);
	}
	HTTPFSParams finalized(http_util);
	finalized.http_proxy = "first-finalized-proxy.test";
	finalized.RefreshTransportReuseDomain();
	REQUIRE(finalized.GetTransportReuseDomain() == 1);
}

static void RunSnapshotProviderDomainScenario() {
	HTTPFSUtil captured_provider;
	HTTPFSUtil current_provider;
	HTTPFSParams captured_params(captured_provider);
	captured_params.http_proxy = "stale-proxy.test";
	captured_params.RefreshTransportReuseDomain();
	HTTPFSParams refreshed_params(current_provider);
	refreshed_params.http_proxy = "fresh-proxy.test";
	refreshed_params.RefreshTransportReuseDomain();
	REQUIRE(captured_params.GetTransportReuseDomain() == refreshed_params.GetTransportReuseDomain());

	auto merged_params = captured_params;
	merged_params.http_proxy = refreshed_params.http_proxy;
	HTTPRequestSnapshot replacement(merged_params);
	HTTPFSParams expected(captured_provider);
	expected.http_proxy = refreshed_params.http_proxy;
	expected.RefreshTransportReuseDomain();
	REQUIRE(replacement.Params().GetTransportReuseDomain() == expected.GetTransportReuseDomain());
	REQUIRE(replacement.Params().GetTransportReuseDomain() != refreshed_params.GetTransportReuseDomain());
}

static void RunConnectionReuseScenario(const string &client_implementation) {
	MockS3Server server {MockS3ServerConfig()};
	DuckDB db(nullptr);
	Connection con(db);
	HTTPTestHelper::Configure(db, con, 0, client_implementation, true);
	HTTPTestHelper::RequireQueryOk(con, "BEGIN TRANSACTION");
	auto session = db.instance->config.GetHTTPTransportManager().CreateSession(*con.context, server.HTTPPath());
	auto &params = session.Parameters();

	for (idx_t i = 0; i < 2; i++) {
		HeadRequestInfo request(server.HTTPPath(), HTTPHeaders(), params);
		auto response = session.Request(request);
		REQUIRE(response);
		REQUIRE(response->Success());
	}

	auto observations = server.Observations();
	auto ports = HTTPTestHelper::RequestPorts(observations, "HEAD", 200);
	INFO(MockS3DescribeObservations(observations));
	REQUIRE(ports.size() == 2);
	REQUIRE(ports[0] != 0);
	REQUIRE(ports[0] == ports[1]);
	HTTPTestHelper::RequireQueryOk(con, "COMMIT");
}

} // namespace

TEST_CASE("HTTP request sessions allow follow-up requests after completed errors", "[httpfs][request-session]") {
	SECTION("httplib allows a follow-up request") {
		RunCompletedErrorFollowup("httplib");
	}
	SECTION("curl allows a follow-up request") {
		RunCompletedErrorFollowup("curl");
	}
}

TEST_CASE("Curl terminal transport errors are not reused", "[httpfs][request-session]") {
	RunCurlTerminalTransportErrorIsNotReused();
}

TEST_CASE("Curl response headers accept exact empty fields", "[httpfs][curl][headers]") {
	RunCurlExactEmptyResponseHeaderScenario();
}

TEST_CASE("Curl response headers preserve repeated fields from the final redirect", "[httpfs][curl][headers]") {
	RunCurlRedirectedResponseHeaderScenario();
}

TEST_CASE("Curl request headers preserve empty field values", "[httpfs][curl][headers]") {
	RunCurlRequestHeaderScenario();
}

TEST_CASE("HTTP PUT respects explicit Content-Type and retains the fallback", "[httpfs][headers][content-type]") {
	HTTPFSUtil httplib_util;
	HTTPFSCurlUtil curl_util;
	for (auto &http_util : {reference<HTTPFSUtil>(httplib_util), reference<HTTPFSUtil>(curl_util)}) {
		for (bool explicit_header : {false, true}) {
			DYNAMIC_SECTION(http_util.get().GetName() << " explicit=" << explicit_header) {
				MockS3Server server {MockS3ServerConfig()};
				HTTPFSParams params(http_util);
				auto client = http_util.get().InitializeClient(params, "http://" + server.Endpoint());
				const string fallback_type = "application/octet-stream";
				HTTPHeaders headers;
				if (explicit_header) {
					headers.Insert("cOnTeNt-TyPe", "application/xml");
				}
				const string body = "payload";
				PutRequestInfo request(server.HTTPPath(), headers, params, const_data_ptr_cast(body.data()),
				                       body.size(), fallback_type);
				auto response = http_util.get().Request(request, client);
				REQUIRE(response);
				REQUIRE(response->Success());
				auto observations = server.Observations();
				REQUIRE(observations.size() == 1);
				REQUIRE(MockS3HeaderValues(observations[0], "Content-Type") ==
				        vector<string> {explicit_header ? "application/xml" : fallback_type});
			}
		}
	}
}

TEST_CASE("Curl pooled bodyless requests do not inherit upload state", "[httpfs][connection-cache]") {
	for (bool put_first : {false, true}) {
		for (bool use_delete : {false, true}) {
			CAPTURE(put_first, use_delete);
			MockS3ServerConfig config;
			config.http_response.options_body = "options response";
			MockS3Server server(std::move(config));
			DuckDB db(nullptr);
			Connection con(db);
			HTTPTestHelper::Configure(db, con, 0, "curl", true);
			HTTPTestHelper::RequireQueryOk(con, "SET http_timeout=2");
			HTTPTestHelper::RequireQueryOk(con, "BEGIN TRANSACTION");
			auto session = DBConfig::GetConfig(*db.instance)
			                   .GetHTTPTransportManager()
			                   .CreateSession(*con.context, server.HTTPPath());
			auto &params = session.Parameters();
			if (put_first) {
				const string body = "payload";
				const string content_type = "application/octet-stream";
				PutRequestInfo request(server.HTTPPath(), {}, params, const_data_ptr_cast(body.data()), body.size(),
				                       content_type);
				REQUIRE(session.Request(request)->Success());
			} else {
				HeadRequestInfo request(server.HTTPPath(), {}, params);
				REQUIRE(session.Request(request)->Success());
			}
			if (use_delete) {
				DeleteRequestInfo request(server.HTTPPath(), {}, params);
				REQUIRE(session.Request(request)->Success());
			} else {
				OptionsRequestInfo request(server.HTTPPath(), {}, params);
				REQUIRE(session.Request(request)->Success());
			}
			auto observations = server.Observations();
			REQUIRE(observations.size() == 2);
			REQUIRE(observations[0].remote_port != 0);
			REQUIRE(observations[1].remote_port == observations[0].remote_port);
			REQUIRE(observations[1].method == (use_delete ? "DELETE" : "OPTIONS"));
			REQUIRE(observations[1].body_size == 0);
			for (const auto *header : {"Transfer-Encoding", "Content-Type", "Expect"}) {
				REQUIRE(MockS3HeaderValues(observations[1], header).empty());
			}
			HTTPTestHelper::RequireQueryOk(con, "ROLLBACK");
		}
	}
}

TEST_CASE("HTTP clients record request and byte counters", "[httpfs][http-state]") {
	SECTION("httplib") {
		HTTPFSUtil http_util;
		RunHTTPStateCounterScenario(http_util);
	}
	SECTION("curl") {
		HTTPFSCurlUtil http_util;
		RunHTTPStateCounterScenario(http_util);
	}
}

TEST_CASE("Curl connection caching selects the manager reuse policy", "[httpfs][connection-cache]") {
	RunCurlConnectionCachingPolicyScenario();

	SECTION("httplib checks connection configuration") {
		HTTPFSUtil http_util;
		RunConnectionCompatibilityScenario(http_util);
	}
	SECTION("curl checks connection configuration") {
		HTTPFSCurlUtil http_util;
		RunConnectionCompatibilityScenario(http_util);
	}
	SECTION("exact connection domain retention is bounded") {
		RunTransportReuseDomainBoundScenario();
	}
	SECTION("raw parameter reads do not publish connection domains") {
		RunRawParametersScenario();
	}
	SECTION("request snapshots use their captured provider's domain") {
		RunSnapshotProviderDomainScenario();
	}
	SECTION("httplib reuses its session connection") {
		RunConnectionReuseScenario("httplib");
	}
	SECTION("curl reuses its shared connection") {
		RunConnectionReuseScenario("curl");
	}
}

TEST_CASE("HTTP clients isolate request credentials across connections",
          "[httpfs][connection-cache][request-session]") {
	for (const auto &backend : {"curl", "httplib"}) {
		DYNAMIC_SECTION(backend) {
			MockS3Server server {MockS3ServerConfig()};
			DuckDB db(nullptr);
			Connection first(db);
			Connection second(db);
			HTTPTestHelper::Configure(db, first, 0, backend, true);
			HTTPTestHelper::RequireQueryOk(first, "BEGIN TRANSACTION");
			HTTPTestHelper::RequireQueryOk(second, "BEGIN TRANSACTION");
			auto &manager = db.instance->config.GetHTTPTransportManager();
			auto first_session = manager.CreateSession(*first.context, server.HTTPPath());
			auto second_session = manager.CreateSession(*second.context, server.HTTPPath());
			auto &first_params = first_session.Parameters().Cast<HTTPFSParams>();
			auto &second_params = second_session.Parameters().Cast<HTTPFSParams>();
			first_params.bearer_token = "first-token";
			first_params.extra_headers["X-Connection"] = "first";
			second_params.bearer_token = "second-token";
			second_params.extra_headers["X-Connection"] = "second";
			REQUIRE(first_params.GetTransportReuseDomain() == second_params.GetTransportReuseDomain());
			auto request = [&](HTTPTransportManager::Session &session) {
				HTTPRequestSnapshot snapshot(session.Parameters().Cast<HTTPFSParams>());
				auto request_state = snapshot.CreateRequest();
				HeadRequestInfo info(server.HTTPPath(), request_state.headers, *request_state.params);
				auto response = session.Request(info);
				REQUIRE(response);
				REQUIRE(response->Success());
			};
			request(first_session);
			request(second_session);
			second_params.bearer_token.clear();
			second_params.extra_headers.clear();
			request(second_session);
			request(first_session);
			auto observations = server.Observations();
			REQUIRE(observations.size() == 4);
			REQUIRE(MockS3HeaderValues(observations[0], "Authorization") == vector<string> {"Bearer first-token"});
			REQUIRE(MockS3HeaderValues(observations[1], "Authorization") == vector<string> {"Bearer second-token"});
			REQUIRE(MockS3HeaderValues(observations[2], "Authorization").empty());
			REQUIRE(MockS3HeaderValues(observations[3], "Authorization") == vector<string> {"Bearer first-token"});
			REQUIRE(MockS3HeaderValues(observations[0], "X-Connection") == vector<string> {"first"});
			REQUIRE(MockS3HeaderValues(observations[1], "X-Connection") == vector<string> {"second"});
			REQUIRE(MockS3HeaderValues(observations[2], "X-Connection").empty());
			REQUIRE(MockS3HeaderValues(observations[3], "X-Connection") == vector<string> {"first"});
			auto ports = HTTPTestHelper::RequestPorts(observations, "HEAD", 200);
			REQUIRE(ports.size() == 4);
			REQUIRE(ports[0] != 0);
			REQUIRE(ports[0] == ports[3]);
			REQUIRE(ports[1] == ports[2]);
			REQUIRE((ports[0] == ports[1]) == (string(backend) == "curl"));
			HTTPTestHelper::RequireQueryOk(first, "ROLLBACK");
			HTTPTestHelper::RequireQueryOk(second, "ROLLBACK");
		}
	}
}

TEST_CASE("HTTP metadata cache mode controls query-end clearing", "[httpfs][metadata-cache]") {
	DuckDB db(nullptr);
	Connection con(db);
	HTTPMetadataCacheEntry entry;
	entry.length = 42;
	entry.last_modified = timestamp_t(0);
	HTTPMetadataCacheEntry result;

	HTTPMetadataCache global_cache(HTTPMetadataCacheMode::GLOBAL);
	global_cache.Insert("global", entry);
	global_cache.QueryEnd(*con.context);
	REQUIRE(global_cache.Find("global", result));
	global_cache.Clear();
	REQUIRE_FALSE(global_cache.Find("global", result));

	HTTPMetadataCache query_cache(HTTPMetadataCacheMode::QUERY_LOCAL);
	query_cache.Insert("query", entry);
	query_cache.QueryEnd(*con.context);
	REQUIRE_FALSE(query_cache.Find("query", result));
}

} // namespace duckdb
