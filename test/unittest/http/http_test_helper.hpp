#pragma once

#include "duckdb.hpp"
#include "s3/mock_s3_server.hpp"

namespace duckdb {

struct HTTPReadOutcome {
	bool failed = false;
	bool internal_error = false;
	string error;
	string data;
};

struct HTTPTestHelper {
	static void LoadExtension(DuckDB &db);
	static void RequireQueryOk(Connection &con, const string &query);
	static void Configure(DuckDB &db, Connection &con, idx_t retries, const string &client_implementation = "curl",
	                      bool connection_caching = false);

	static idx_t CountRequests(const vector<MockS3RequestObservation> &observations, const string &method, int status,
	                           const string &range = string());
	static vector<int> RequestPorts(const vector<MockS3RequestObservation> &observations, const string &method,
	                                int status, const string &range = string());
	static idx_t CountRangeRequests(const vector<MockS3RequestObservation> &observations, int status);

	static HTTPReadOutcome TryReadHandle(Connection &con, FileHandle &handle, idx_t offset, idx_t length);
	static HTTPReadOutcome TryReadRange(Connection &con, const string &path, idx_t offset, idx_t length);
	static string ReadRange(Connection &con, const string &path, idx_t offset, idx_t length);
	static string ReadSequential(Connection &con, FileHandle &handle, idx_t length);
	static string CreateObjectData(idx_t length);
};

} // namespace duckdb
