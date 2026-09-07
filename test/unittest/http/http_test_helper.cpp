#include "http/http_test_helper.hpp"

#include "catch.hpp"
#include "httpfs_extension.hpp"

#include "duckdb/common/error_data.hpp"
#include "duckdb/common/file_system.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/main/extension/extension_loader.hpp"

namespace duckdb {

void HTTPTestHelper::LoadExtension(DuckDB &db) {
	if (db.ExtensionIsLoaded("httpfs")) {
		return;
	}
	ExtensionInfo extension_info;
	ExtensionActiveLoad load_info(*db.instance, extension_info, "httpfs", "");
	ExtensionLoader loader(load_info);
	HttpfsExtension extension;
	extension.Load(loader);
}

void HTTPTestHelper::RequireQueryOk(Connection &con, const string &query) {
	auto result = con.Query(query);
	REQUIRE(result);
	INFO((result->HasError() ? result->GetError() : string()));
	REQUIRE_FALSE(result->HasError());
}

void HTTPTestHelper::Configure(DuckDB &db, Connection &con, idx_t retries, const string &client_implementation,
                               bool connection_caching) {
	LoadExtension(db);
	RequireQueryOk(con, "SET httpfs_client_implementation='" + client_implementation + "'");
	RequireQueryOk(con, StringUtil::Format("SET httpfs_connection_caching=%s", connection_caching ? "true" : "false"));
	RequireQueryOk(con, "SET http_retries=" + to_string(retries));
	RequireQueryOk(con, "SET http_retry_wait_ms=1");
	RequireQueryOk(con, "SET http_retry_backoff=1");
}

idx_t HTTPTestHelper::CountRequests(const vector<MockS3RequestObservation> &observations, const string &method,
                                    int status, const string &range) {
	idx_t count = 0;
	for (auto &observation : observations) {
		if (observation.method == method && observation.status == status && observation.range == range) {
			count++;
		}
	}
	return count;
}

vector<int> HTTPTestHelper::RequestPorts(const vector<MockS3RequestObservation> &observations, const string &method,
                                         int status, const string &range) {
	vector<int> result;
	for (auto &observation : observations) {
		if (observation.method == method && observation.status == status && observation.range == range) {
			result.push_back(observation.remote_port);
		}
	}
	return result;
}

idx_t HTTPTestHelper::CountRangeRequests(const vector<MockS3RequestObservation> &observations, int status) {
	idx_t count = 0;
	for (auto &observation : observations) {
		if (observation.method == "GET" && observation.status == status && !observation.range.empty()) {
			count++;
		}
	}
	return count;
}

HTTPReadOutcome HTTPTestHelper::TryReadHandle(Connection &con, FileHandle &handle, idx_t offset, idx_t length) {
	HTTPReadOutcome outcome;
	try {
		string buffer(length, '?');
		handle.Read(QueryContext(*con.context), &buffer[0], length, offset);
		outcome.data = std::move(buffer);
	} catch (std::exception &ex) {
		outcome.failed = true;
		outcome.error = ex.what();
		ErrorData error(ex);
		outcome.internal_error = error.Type() == ExceptionType::INTERNAL || error.Type() == ExceptionType::FATAL;
	} catch (...) {
		outcome.failed = true;
		outcome.error = "unknown exception";
	}
	return outcome;
}

HTTPReadOutcome HTTPTestHelper::TryReadRange(Connection &con, const string &path, idx_t offset, idx_t length) {
	auto &fs = FileSystem::GetFileSystem(*con.context);
	auto handle = fs.OpenFile(path, FileFlags::FILE_FLAGS_READ | FileFlags::FILE_FLAGS_DIRECT_IO);
	return TryReadHandle(con, *handle, offset, length);
}

string HTTPTestHelper::ReadRange(Connection &con, const string &path, idx_t offset, idx_t length) {
	auto &fs = FileSystem::GetFileSystem(*con.context);
	auto handle = fs.OpenFile(path, FileFlags::FILE_FLAGS_READ | FileFlags::FILE_FLAGS_DIRECT_IO);
	string buffer(length, '?');
	handle->Read(QueryContext(*con.context), &buffer[0], length, offset);
	return buffer;
}

string HTTPTestHelper::ReadSequential(Connection &con, FileHandle &handle, idx_t length) {
	string buffer(length, '?');
	auto read_count = handle.Read(QueryContext(*con.context), buffer.data(), length);
	buffer.resize(NumericCast<idx_t>(read_count));
	return buffer;
}

string HTTPTestHelper::CreateObjectData(idx_t length) {
	string result(length, '\0');
	for (idx_t i = 0; i < length; i++) {
		result[i] = NumericCast<char>('a' + (i % 26));
	}
	return result;
}

} // namespace duckdb
