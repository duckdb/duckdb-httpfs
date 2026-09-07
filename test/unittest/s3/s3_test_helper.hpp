#pragma once

#include "s3/mock_s3_server.hpp"

#include "duckdb.hpp"
#include "duckdb/main/secret/secret.hpp"

#include <functional>

namespace duckdb {

class S3ProviderRefreshHook {
public:
	S3ProviderRefreshHook(string test_id, std::function<void()> refresh_hook);
	~S3ProviderRefreshHook();

private:
	string test_id;
};

struct S3TestHelper {
public:
	static void LoadExtension(DuckDB &db);
	static void RegisterRefreshProvider(DuckDB &db);
	static void RequireQueryOk(Connection &con, const string &query);
	static string NextTestId();
	static CreateSecretInput CreateTransactionRefreshInput(const string &test_id);
	static string ConfigureRefresh(DuckDB &db, Connection &con, MockS3Server &server,
	                               const string &client_implementation, bool connection_caching,
	                               bool refresh_enabled = true);
	static void ConfigureEndpointRefresh(DuckDB &db, Connection &con, MockS3Server &stale_server,
	                                     MockS3Server &fresh_server, const string &client_implementation);
	static string ConfigureEndpointRefresh(DuckDB &db, Connection &con, const string &initial_endpoint,
	                                       const string &refreshed_endpoint, const string &client_implementation,
	                                       bool refresh_credentials, const string &http_proxy = "");
	static void AssertSingleRefresh(const string &test_id);
	static void AssertNoRefresh(const string &test_id);
	static bool HasRequestWithKey(const vector<MockS3RequestObservation> &observations, const string &key_id);
	static idx_t CountObservations(const vector<MockS3RequestObservation> &observations, const string &method,
	                               const string &key_id, int status);
	static vector<MockS3RequestObservation>
	CompletionObservations(const vector<MockS3RequestObservation> &observations);
	static void RequireCompletionIdentity(const vector<MockS3RequestObservation> &observations,
	                                      idx_t expected_attempts);
	static vector<string> CreateBulkDeletePaths(const string &scheme, idx_t count);
	static void WriteMultipartPayload(Connection &con);
	static void WriteSinglePutPayload(Connection &con);

public:
	static constexpr const char *STALE_KEY_ID = "STALE_KEY";
	static constexpr const char *FRESH_KEY_ID = "FRESH_KEY";
	static constexpr const char *STALE_SECRET = "STALE_SECRET";
	static constexpr const char *FRESH_SECRET = "FRESH_SECRET";
	static constexpr const char *TEST_PROVIDER = "httpfs_refresh_test";
	static constexpr const char *BUCKET = "refresh-bucket";
	static constexpr const char *OBJECT_KEY = "object.bin";
	static constexpr const char *S3_PATH = "s3://refresh-bucket/object.bin";
};

} // namespace duckdb
