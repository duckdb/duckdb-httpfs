#include "catch.hpp"

#include "http/http_test_helper.hpp"
#include "http/http_metadata_cache.hpp"
#include "http/http_state.hpp"
#include "http/httpfs_client.hpp"

namespace duckdb {

namespace {

static void RunCompletedErrorFollowup(const string &client_implementation) {
	MockS3ServerConfig config;
	config.failures.transient_head_failures = 1;
	config.failures.failure_is_request_timeout = false;
	MockS3Server server(std::move(config));

	DuckDB db(nullptr);
	Connection con(db);
	HTTPTestHelper::Configure(db, con, 0, client_implementation);

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

static void RunCurlRetryClientBypassesSharedCache() {
	MockS3Server server {MockS3ServerConfig()};
	HTTPFSCurlUtil http_util;
	HTTPFSParams params(http_util);
	params.client_reuse_mode = HTTPClientReuseMode::SHARED;
	params.httpfs_util = http_util;

	auto first_client = http_util.InitializeClient(params, "http://" + server.Endpoint());
	HeadRequestInfo first_request(server.HTTPPath(), HTTPHeaders(), params);
	auto first_response = http_util.Request(first_request, first_client);
	REQUIRE(first_response);
	REQUIRE(first_response->Success());
	http_util.CloseClient(std::move(first_client));

	HTTPClientInitializationOptions options;
	options.cache_policy = HTTPClientCachePolicy::BYPASS_CACHE;
	auto retry_client = http_util.InitializeClientExtended(params, "http://" + server.Endpoint(), options);
	HeadRequestInfo retry_request(server.HTTPPath(), HTTPHeaders(), params);
	auto retry_response = http_util.Request(retry_request, retry_client);
	REQUIRE(retry_response);
	REQUIRE(retry_response->Success());

	auto observations = server.Observations();
	INFO(MockS3DescribeObservations(observations));
	auto ports = HTTPTestHelper::RequestPorts(observations, "HEAD", 200);
	REQUIRE(ports.size() == 2);
	REQUIRE(ports[0] != 0);
	REQUIRE(ports[1] != 0);
	REQUIRE(ports[0] != ports[1]);
}

static void RunCurlTerminalTransportErrorIsNotCached() {
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

	auto &http_util = HTTPUtil::Get(*db.instance);
	auto params = http_util.InitializeParameters(*con.context, server.HTTPPath());
	HTTPHeaders headers;
	headers.Insert("Range", "bytes=0-3");
	GetRequestInfo failed_request(server.HTTPPath(), headers, *params, nullptr, nullptr);
	failed_request.try_request = true;
	auto failed_response = http_util.Request(failed_request);
	REQUIRE(failed_response);
	REQUIRE(failed_response->HasRequestError());

	HeadRequestInfo completed_error_request(server.HTTPPath(), HTTPHeaders(), *params);
	auto completed_error_response = http_util.Request(completed_error_request);
	REQUIRE(completed_error_response);
	REQUIRE_FALSE(completed_error_response->HasRequestError());
	REQUIRE(completed_error_response->status == HTTPStatusCode::NotFound_404);

	auto hits = con.Query("SELECT count(*) FROM duckdb_logs WHERE message LIKE '%connection_cache_hit%'");
	REQUIRE(hits);
	REQUIRE_FALSE(hits->HasError());
	REQUIRE(hits->GetValue(0, 0).GetValue<idx_t>() == 0);

	HeadRequestInfo reused_error_request(server.HTTPPath(), HTTPHeaders(), *params);
	auto reused_error_response = http_util.Request(reused_error_request);
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

static void RunCurlConnectionCachingTransitionScenario() {
	MockS3Server server {MockS3ServerConfig()};
	HTTPFSCurlUtil http_util;
	HTTPFSParams params(http_util);

	auto first_client = http_util.InitializeClient(params, "http://" + server.Endpoint());
	HeadRequestInfo first_request(server.HTTPPath(), HTTPHeaders(), params);
	REQUIRE(http_util.Request(first_request, first_client));
	http_util.CloseClient(std::move(first_client));

	http_util.SetConnectionCachingEnabled(false);
	REQUIRE(http_util.GetClientReuseMode() == HTTPClientReuseMode::SESSION_LOCAL);
	http_util.SetConnectionCachingEnabled(true);
	REQUIRE(http_util.GetClientReuseMode() == HTTPClientReuseMode::SHARED);

	auto second_client = http_util.InitializeClient(params, "http://" + server.Endpoint());
	HeadRequestInfo second_request(server.HTTPPath(), HTTPHeaders(), params);
	REQUIRE(http_util.Request(second_request, second_client));

	auto ports = HTTPTestHelper::RequestPorts(server.Observations(), "HEAD", 200);
	REQUIRE(ports.size() == 2);
	REQUIRE(ports[0] != ports[1]);
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

TEST_CASE("Curl retries bypass the shared connection cache", "[httpfs][request-session]") {
	RunCurlRetryClientBypassesSharedCache();
}

TEST_CASE("Curl terminal transport errors are not cached", "[httpfs][request-session]") {
	RunCurlTerminalTransportErrorIsNotCached();
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

TEST_CASE("Disabling curl connection caching clears pooled clients", "[httpfs][connection-cache]") {
	RunCurlConnectionCachingTransitionScenario();
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
