#include "catch.hpp"

#include "s3/mock_s3_server.hpp"
#include "s3/s3_test_helper.hpp"

#include "http/httpfs_client.hpp"

#include "duckdb.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/main/http/http_retry_budget.hpp"

namespace duckdb {

namespace {

static string HeaderValue(const MockS3RequestObservation &observation, const string &name) {
	for (auto &header : observation.headers) {
		if (StringUtil::CIEquals(header.first, name)) {
			return header.second;
		}
	}
	return string();
}

static void RunAttemptHeaderScenario(const string &client_implementation) {
	MockS3ServerConfig config;
	config.object.bucket = S3TestHelper::BUCKET;
	config.object.key = S3TestHelper::OBJECT_KEY;
	config.auth.stale_key_id = S3TestHelper::STALE_KEY_ID;
	config.auth.refresh_target = MockS3RefreshTarget::DELETE_OBJECT;
	config.failures.transient_put_failures = 2;
	MockS3Server server(std::move(config));

	DuckDB db(nullptr);
	Connection con(db);
	S3TestHelper::ConfigureRefresh(db, con, server, client_implementation, false);
	S3TestHelper::RequireQueryOk(con, "SET http_retries=3");
	S3TestHelper::RequireQueryOk(con, "SET http_retry_wait_ms=1");
	S3TestHelper::RequireQueryOk(con, "BEGIN TRANSACTION");
	S3TestHelper::WriteMultipartPayload(con);
	S3TestHelper::RequireQueryOk(con, "COMMIT");

	auto observations = server.Observations();
	INFO(MockS3DescribeObservations(observations));
	vector<MockS3RequestObservation> part_uploads;
	for (auto &observation : observations) {
		if (observation.method == "PUT" && observation.target.find("partNumber") != string::npos) {
			part_uploads.push_back(observation);
		}
	}
	// Two RequestTimeouts and the success are three attempts of one logical request; the maximum counts the first
	// attempt, http_retries and the extra retries a throttling server is granted
	REQUIRE(part_uploads.size() == 3);
	const auto max_attempts = 1 + 3 + HTTPRetryBudget::THROTTLE_EXTRA_RETRIES;
	auto invocation_id = HeaderValue(part_uploads[0], HTTPFSUtil::S3_INVOCATION_ID_HEADER);
	REQUIRE_FALSE(invocation_id.empty());
	for (idx_t i = 0; i < part_uploads.size(); i++) {
		REQUIRE(HeaderValue(part_uploads[i], HTTPFSUtil::S3_INVOCATION_ID_HEADER) == invocation_id);
		REQUIRE(HeaderValue(part_uploads[i], HTTPFSUtil::S3_ATTEMPT_HEADER) ==
		        StringUtil::Format("attempt=%llu; max=%llu", i + 1, max_attempts));
	}
	// Other operations of the same upload carry their own invocation ids
	idx_t other_operations = 0;
	for (auto &observation : observations) {
		if (observation.method == "PUT") {
			continue;
		}
		auto other_id = HeaderValue(observation, HTTPFSUtil::S3_INVOCATION_ID_HEADER);
		if (other_id.empty()) {
			continue;
		}
		REQUIRE(other_id != invocation_id);
		other_operations++;
	}
	REQUIRE(other_operations > 0);
}

} // namespace

TEST_CASE("S3 attempts carry the SDK invocation id and attempt headers", "[httpfs][s3][retry]") {
	SECTION("httplib") {
		RunAttemptHeaderScenario("httplib");
	}
	SECTION("curl") {
		RunAttemptHeaderScenario("curl");
	}
}

} // namespace duckdb
