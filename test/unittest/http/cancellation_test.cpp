#include "catch.hpp"

#include "http/http_test_helper.hpp"
#include "http/httpfs_client.hpp"
#include "duckdb/main/client_context.hpp"

#include <chrono>
#include <future>

namespace duckdb {

TEST_CASE("Curl cancels stalled transfers without retaining the caller", "[httpfs][cancellation]") {
	bool before_headers = true;
	bool deadline = false;
	SECTION("interruption before response headers") {
	}
	SECTION("interruption during response body") {
		before_headers = false;
	}
	SECTION("deadline before response headers") {
		deadline = true;
	}
	MockS3ServerConfig config;
	config.upload.block_initialization = before_headers;
	config.full_get.block_until_released = !before_headers;
	MockS3Server server(std::move(config));
	DuckDB db(nullptr);
	Connection con(db);
	HTTPFSCurlUtil http;
	HTTPFSParams params(http);
	params.retries = 3;
	params.retry_wait_ms = 0;
	params.timeout = 30;
	auto client = http.InitializeClient(params, "http://" + server.Endpoint());
	auto original_client = client.get();
	auto result = std::async(std::launch::async, [&]() {
		if (deadline) {
			con.context->query_deadline = NumericCast<idx_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
			                                                     std::chrono::steady_clock::now().time_since_epoch())
			                                                     .count() +
			                                                 1000);
		}
		if (before_headers) {
			PostRequestInfo request(server.HTTPPath() + "?uploads", HTTPHeaders(), params, nullptr, 0);
			request.interrupt_context = con.context.get();
			return http.Request(request, client);
		}
		GetRequestInfo request(server.HTTPPath(), HTTPHeaders(), params, nullptr, nullptr);
		request.interrupt_context = con.context.get();
		return http.Request(request, client);
	});
	auto started = before_headers ? server.WaitForMultipartInitialization() : server.WaitForFullGet();
	if (!deadline) {
		con.Interrupt();
	}
	auto completed = result.wait_for(std::chrono::seconds(3));
	// Always unblock the server and join the client before assertions can unwind the fixture.
	server.ReleaseMultipartInitialization();
	server.ReleaseFullGet();
	CHECK_THROWS_AS(result.get(), InterruptException);
	CHECK(started);
	CHECK(completed == std::future_status::ready);
	CHECK(client.get() == original_client);

	// Keep the first caller interrupted/expired. The same client must still serve an unrelated request.
	GetRequestInfo followup(server.HTTPPath(), HTTPHeaders(), params, nullptr, nullptr);
	auto response = http.Request(followup, client);
	REQUIRE(response);
	CHECK(response->Success());
	CHECK(response->body == server.ObjectData());
	CHECK(client.get() == original_client);
	CHECK(server.Observations().size() == 2);
}

} // namespace duckdb
