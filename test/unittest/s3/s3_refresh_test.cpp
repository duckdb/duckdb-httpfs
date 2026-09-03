#include "catch.hpp"

#include "s3/mock_s3_server.hpp"
#include "s3/s3_test_helper.hpp"

#include "create_secret_functions.hpp"
#include "crypto.hpp"
#include "http/httpfs_client.hpp"
#include "s3/s3fs.hpp"

#include "duckdb.hpp"
#include "duckdb/catalog/catalog_transaction.hpp"
#include "duckdb/common/file_system.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/main/client_context.hpp"
#include "duckdb/main/client_context_file_opener.hpp"
#include "duckdb/main/secret/secret_manager.hpp"

#include <atomic>

namespace duckdb {

namespace {

template <class OPERATION>
static vector<MockS3RequestObservation>
RunRefreshScenario(MockS3RefreshTarget refresh_target, const string &client_implementation, bool connection_caching,
                   OPERATION operation, int stale_auth_status = 403, string stale_auth_error_code = "AccessDenied") {
	MockS3ServerConfig config;
	config.object.bucket = S3TestHelper::BUCKET;
	config.object.key = S3TestHelper::OBJECT_KEY;
	config.auth.stale_key_id = S3TestHelper::STALE_KEY_ID;
	config.auth.stale_status = stale_auth_status;
	config.auth.stale_error_code = std::move(stale_auth_error_code);
	config.auth.refresh_target = refresh_target;
	auto object_data = config.object.data;
	MockS3Server server(std::move(config));

	DuckDB db(nullptr);
	Connection con(db);
	auto test_id = S3TestHelper::ConfigureRefresh(db, con, server, client_implementation, connection_caching);
	INFO(StringUtil::Format("refresh target: %s, client: %s, connection caching: %s",
	                        MockS3RefreshTargetName(refresh_target), client_implementation,
	                        connection_caching ? "true" : "false"));
	S3TestHelper::RequireQueryOk(con, "BEGIN TRANSACTION");
	operation(con, object_data);
	S3TestHelper::RequireQueryOk(con, "COMMIT");
	auto observations = server.Observations();
	INFO(MockS3DescribeObservations(observations));
	S3TestHelper::AssertSingleRefresh(test_id);
	return observations;
}

static void OpenForRead(Connection &con, FileOpenFlags flags = FileFlags::FILE_FLAGS_READ) {
	auto &fs = FileSystem::GetFileSystem(*con.context);
	auto handle = fs.OpenFile(S3TestHelper::S3_PATH, flags);
	REQUIRE(handle);
}

static void RunHeadRefreshScenario(const string &client_implementation, bool connection_caching) {
	auto observations = RunRefreshScenario(
	    MockS3RefreshTarget::HEAD, client_implementation, connection_caching, [](Connection &con, const string &) {
		    OpenForRead(con, FileFlags::FILE_FLAGS_READ | FileFlags::FILE_FLAGS_DIRECT_IO);
	    });
	REQUIRE(MockS3HasObservation(observations, "HEAD", S3TestHelper::STALE_KEY_ID, 403));
	REQUIRE(MockS3HasObservation(observations, "HEAD", S3TestHelper::FRESH_KEY_ID, 200));
}

static void RunFullGetRefreshScenario(const string &client_implementation, bool connection_caching) {
	auto observations = RunRefreshScenario(MockS3RefreshTarget::FULL_GET, client_implementation, connection_caching,
	                                       [](Connection &con, const string &object_data) {
		                                       S3TestHelper::RequireQueryOk(con, "SET force_download=true");
		                                       auto &fs = FileSystem::GetFileSystem(*con.context);
		                                       auto handle =
		                                           fs.OpenFile(S3TestHelper::S3_PATH, FileFlags::FILE_FLAGS_READ);
		                                       string buffer(8, '\0');
		                                       handle->Read(QueryContext(*con.context), &buffer[0], buffer.size(), 0);
		                                       REQUIRE(buffer == object_data.substr(0, buffer.size()));
	                                       });
	REQUIRE(MockS3HasObservation(observations, "GET", S3TestHelper::STALE_KEY_ID, 403));
	REQUIRE(MockS3HasObservation(observations, "GET", S3TestHelper::FRESH_KEY_ID, 200));
}

static void RunRangeRefreshScenario(const string &client_implementation, bool connection_caching) {
	auto observations = RunRefreshScenario(
	    MockS3RefreshTarget::RANGE_GET, client_implementation, connection_caching,
	    [](Connection &con, const string &object_data) {
		    auto &fs = FileSystem::GetFileSystem(*con.context);
		    auto handle =
		        fs.OpenFile(S3TestHelper::S3_PATH, FileFlags::FILE_FLAGS_READ | FileFlags::FILE_FLAGS_DIRECT_IO);

		    const idx_t first_offset = 7;
		    const idx_t first_read_size = 9;
		    string first_buffer(first_read_size, '\0');
		    handle->Read(QueryContext(*con.context), &first_buffer[0], first_read_size, first_offset);
		    REQUIRE(first_buffer == object_data.substr(first_offset, first_read_size));

		    const idx_t second_offset = 20;
		    const idx_t second_read_size = 5;
		    string second_buffer(second_read_size, '\0');
		    handle->Read(QueryContext(*con.context), &second_buffer[0], second_read_size, second_offset);
		    REQUIRE(second_buffer == object_data.substr(second_offset, second_read_size));
	    });
	REQUIRE(MockS3HasObservation(observations, "GET", S3TestHelper::STALE_KEY_ID, 403, "bytes=7-15"));
	REQUIRE(MockS3HasObservation(observations, "GET", S3TestHelper::FRESH_KEY_ID, 206, "bytes=7-15"));
	REQUIRE(MockS3HasObservation(observations, "GET", S3TestHelper::FRESH_KEY_ID, 206, "bytes=20-24"));
	REQUIRE_FALSE(MockS3HasObservation(observations, "GET", S3TestHelper::STALE_KEY_ID, 403, "bytes=20-24"));
}

static void RunPutRefreshScenario(const string &client_implementation, bool connection_caching) {
	auto observations = RunRefreshScenario(
	    MockS3RefreshTarget::PUT, client_implementation, connection_caching, [](Connection &con, const string &) {
		    auto &fs = FileSystem::GetFileSystem(*con.context);
		    auto handle =
		        fs.OpenFile(S3TestHelper::S3_PATH, FileFlags::FILE_FLAGS_WRITE | FileFlags::FILE_FLAGS_FILE_CREATE_NEW);
		    string payload = "hello from httpfs refresh";
		    handle->Write(QueryContext(*con.context), &payload[0], payload.size());
		    handle->Close();
	    });
	REQUIRE(MockS3HasObservation(observations, "PUT", S3TestHelper::STALE_KEY_ID, 403));
	REQUIRE(MockS3HasObservation(observations, "PUT", S3TestHelper::FRESH_KEY_ID, 200));
}

static void RunMultipartInitiatePostRefreshScenario(const string &client_implementation, bool connection_caching) {
	auto observations =
	    RunRefreshScenario(MockS3RefreshTarget::MULTIPART_INITIATE_POST, client_implementation, connection_caching,
	                       [](Connection &con, const string &) { S3TestHelper::WriteMultipartPayload(con); });
	REQUIRE(MockS3HasObservation(observations, "POST", S3TestHelper::STALE_KEY_ID, 403, string(), "uploads"));
	REQUIRE(MockS3HasObservation(observations, "POST", S3TestHelper::FRESH_KEY_ID, 200, string(), "uploads"));
	REQUIRE(MockS3HasObservation(observations, "POST", S3TestHelper::FRESH_KEY_ID, 200, string(), "uploadId"));
}

static void RunMultipartCompletePostRefreshScenario(const string &client_implementation, bool connection_caching) {
	auto observations =
	    RunRefreshScenario(MockS3RefreshTarget::MULTIPART_COMPLETE_POST, client_implementation, connection_caching,
	                       [](Connection &con, const string &) { S3TestHelper::WriteMultipartPayload(con); });
	REQUIRE(MockS3HasObservation(observations, "POST", S3TestHelper::STALE_KEY_ID, 403, string(), "uploadId"));
	REQUIRE(MockS3HasObservation(observations, "POST", S3TestHelper::FRESH_KEY_ID, 200, string(), "uploadId"));
}

static void RunBulkDeletePostRefreshScenario(const string &client_implementation, bool connection_caching) {
	auto observations = RunRefreshScenario(MockS3RefreshTarget::BULK_DELETE_POST, client_implementation,
	                                       connection_caching, [](Connection &con, const string &) {
		                                       auto &fs = FileSystem::GetFileSystem(*con.context);
		                                       vector<string> paths;
		                                       paths.push_back(S3TestHelper::S3_PATH);
		                                       fs.RemoveFiles(paths);
	                                       });
	REQUIRE(MockS3HasObservation(observations, "POST", S3TestHelper::STALE_KEY_ID, 403, string(), "delete"));
	REQUIRE(MockS3HasObservation(observations, "POST", S3TestHelper::FRESH_KEY_ID, 200, string(), "delete"));
}

static void RunBulkDeleteEndpointRefreshScenario(const string &client_implementation) {
	MockS3ServerConfig stale_config;
	stale_config.object.bucket = S3TestHelper::BUCKET;
	stale_config.object.key = S3TestHelper::OBJECT_KEY;
	stale_config.auth.stale_key_id = S3TestHelper::STALE_KEY_ID;
	stale_config.auth.refresh_target = MockS3RefreshTarget::BULK_DELETE_POST;
	MockS3Server stale_server(std::move(stale_config));

	MockS3ServerConfig fresh_config;
	fresh_config.object.bucket = S3TestHelper::BUCKET;
	fresh_config.object.key = S3TestHelper::OBJECT_KEY;
	fresh_config.auth.stale_key_id = "NEVER_STALE";
	fresh_config.auth.refresh_target = MockS3RefreshTarget::BULK_DELETE_POST;
	MockS3Server fresh_server(std::move(fresh_config));

	DuckDB db(nullptr);
	Connection con(db);
	S3TestHelper::ConfigureEndpointRefresh(db, con, stale_server, fresh_server, client_implementation);

	S3TestHelper::RequireQueryOk(con, "BEGIN TRANSACTION");
	auto &fs = FileSystem::GetFileSystem(*con.context);
	fs.RemoveFiles({S3TestHelper::S3_PATH});
	S3TestHelper::RequireQueryOk(con, "COMMIT");

	auto stale_observations = stale_server.Observations();
	auto fresh_observations = fresh_server.Observations();
	INFO(MockS3DescribeObservations(stale_observations));
	INFO(MockS3DescribeObservations(fresh_observations));
	REQUIRE(S3TestHelper::CountObservations(stale_observations, "POST", S3TestHelper::STALE_KEY_ID, 403) == 1);
	REQUIRE(S3TestHelper::CountObservations(fresh_observations, "POST", S3TestHelper::STALE_KEY_ID, 200) == 1);
}

static void RunBulkDeleteR2PolicyRefreshScenario(const string &client_implementation, idx_t key_count) {
	MockS3ServerConfig config;
	config.auth.stale_key_id = S3TestHelper::STALE_KEY_ID;
	config.auth.refresh_target = MockS3RefreshTarget::BULK_DELETE_POST;
	config.bulk_delete.maximum_key_count = 700;
	MockS3Server server(std::move(config));

	DuckDB db(nullptr);
	Connection con(db);
	auto test_id = S3TestHelper::ConfigureEndpointRefresh(db, con, "objects.example.com",
	                                                      "account.r2.cloudflarestorage.com", client_implementation,
	                                                      true, StringUtil::Format("http://%s", server.Endpoint()));

	S3TestHelper::RequireQueryOk(con, "BEGIN TRANSACTION");
	string error;
	try {
		auto &fs = FileSystem::GetFileSystem(*con.context);
		fs.RemoveFiles(S3TestHelper::CreateBulkDeletePaths("s3", key_count));
	} catch (std::exception &ex) {
		error = ex.what();
	}
	INFO(error);
	if (key_count <= 700) {
		REQUIRE(error.empty());
		S3TestHelper::RequireQueryOk(con, "COMMIT");
	} else {
		REQUIRE(error.find("Cannot send S3 bulk delete with 1000 keys") != string::npos);
		REQUIRE(error.find("at most 700 keys per request") != string::npos);
		S3TestHelper::RequireQueryOk(con, "ROLLBACK");
	}

	auto observations = server.Observations();
	INFO(MockS3DescribeObservations(observations));
	idx_t stale_requests = 0;
	idx_t fresh_requests = 0;
	for (const auto &observation : observations) {
		if (observation.method != "POST" || !StringUtil::EndsWith(observation.target, "?delete=")) {
			continue;
		}
		if (observation.key_id == S3TestHelper::STALE_KEY_ID) {
			stale_requests++;
			REQUIRE(observation.status == 403);
			REQUIRE(observation.delete_key_count == key_count);
		} else if (observation.key_id == S3TestHelper::FRESH_KEY_ID) {
			fresh_requests++;
			REQUIRE(observation.status == 200);
			REQUIRE(observation.delete_key_count == key_count);
		}
	}
	REQUIRE(stale_requests == 1);
	REQUIRE(fresh_requests == (key_count <= 700 ? 1 : 0));
	S3TestHelper::AssertSingleRefresh(test_id);
}

static void RunDeleteRefreshScenario(const string &client_implementation, bool connection_caching) {
	auto observations = RunRefreshScenario(MockS3RefreshTarget::DELETE_OBJECT, client_implementation,
	                                       connection_caching, [](Connection &con, const string &) {
		                                       auto &fs = FileSystem::GetFileSystem(*con.context);
		                                       fs.RemoveFile(S3TestHelper::S3_PATH);
	                                       });
	REQUIRE(MockS3HasObservation(observations, "DELETE", S3TestHelper::STALE_KEY_ID, 403));
	REQUIRE(MockS3HasObservation(observations, "DELETE", S3TestHelper::FRESH_KEY_ID, 204));
}

static void RunListGlobRefreshScenario(const string &client_implementation, bool connection_caching) {
	auto observations =
	    RunRefreshScenario(MockS3RefreshTarget::LIST_OBJECTS_GET, client_implementation, connection_caching,
	                       [](Connection &con, const string &) {
		                       auto result = con.Query("SELECT file FROM glob('s3://refresh-bucket/object*.bin')");
		                       REQUIRE(result);
		                       INFO((result->HasError() ? result->GetError() : string()));
		                       REQUIRE_FALSE(result->HasError());
		                       REQUIRE(result->RowCount() == 1);
		                       REQUIRE(result->GetValue(0, 0).ToString() == S3TestHelper::S3_PATH);
	                       });
	REQUIRE(MockS3HasObservation(observations, "GET", S3TestHelper::STALE_KEY_ID, 403, string(), "list-type=2"));
	REQUIRE(MockS3HasObservation(observations, "GET", S3TestHelper::FRESH_KEY_ID, 200, string(), "list-type=2"));
}

static void RunTokenFullGetRefreshScenario(const string &client_implementation, const string &error_code) {
	auto observations = RunRefreshScenario(
	    MockS3RefreshTarget::FULL_GET, client_implementation, false,
	    [](Connection &con, const string &) {
		    S3TestHelper::RequireQueryOk(con, "SET force_download=true");
		    auto &fs = FileSystem::GetFileSystem(*con.context);
		    auto handle = fs.OpenFile(S3TestHelper::S3_PATH, FileFlags::FILE_FLAGS_READ);
		    REQUIRE(handle);
	    },
	    400, error_code);
	REQUIRE(MockS3HasObservation(observations, "GET", S3TestHelper::STALE_KEY_ID, 400));
	REQUIRE(MockS3HasObservation(observations, "GET", S3TestHelper::FRESH_KEY_ID, 200));
}

static void RunTokenListRefreshScenario(const string &client_implementation, const string &error_code) {
	auto observations = RunRefreshScenario(
	    MockS3RefreshTarget::LIST_OBJECTS_GET, client_implementation, false,
	    [](Connection &con, const string &) {
		    auto result = con.Query("SELECT file FROM glob('s3://refresh-bucket/object*.bin')");
		    REQUIRE(result);
		    INFO((result->HasError() ? result->GetError() : string()));
		    REQUIRE_FALSE(result->HasError());
		    REQUIRE(result->RowCount() == 1);
	    },
	    400, error_code);
	REQUIRE(MockS3HasObservation(observations, "GET", S3TestHelper::STALE_KEY_ID, 400, string(), "list-type=2"));
	REQUIRE(MockS3HasObservation(observations, "GET", S3TestHelper::FRESH_KEY_ID, 200, string(), "list-type=2"));
}

static void RunNonAuth400NoRefreshScenario(const string &client_implementation) {
	MockS3ServerConfig config;
	config.object.bucket = S3TestHelper::BUCKET;
	config.object.key = S3TestHelper::OBJECT_KEY;
	config.auth.stale_key_id = S3TestHelper::STALE_KEY_ID;
	config.auth.stale_status = 400;
	config.auth.stale_error_code = "InvalidRequest";
	config.auth.refresh_target = MockS3RefreshTarget::FULL_GET;
	MockS3Server server(std::move(config));

	DuckDB db(nullptr);
	Connection con(db);
	auto test_id = S3TestHelper::ConfigureRefresh(db, con, server, client_implementation, false);
	S3TestHelper::RequireQueryOk(con, "SET force_download=true");
	S3TestHelper::RequireQueryOk(con, "BEGIN TRANSACTION");
	string error;
	try {
		auto &fs = FileSystem::GetFileSystem(*con.context);
		fs.OpenFile(S3TestHelper::S3_PATH, FileFlags::FILE_FLAGS_READ);
	} catch (std::exception &ex) {
		error = ex.what();
	}
	INFO(error);
	REQUIRE(error.find("InvalidRequest") != string::npos);
	S3TestHelper::RequireQueryOk(con, "ROLLBACK");

	auto observations = server.Observations();
	INFO(MockS3DescribeObservations(observations));
	REQUIRE(MockS3HasObservation(observations, "GET", S3TestHelper::STALE_KEY_ID, 400));
	REQUIRE_FALSE(S3TestHelper::HasRequestWithKey(observations, S3TestHelper::FRESH_KEY_ID));
	S3TestHelper::AssertNoRefresh(test_id);
}

static void RunAllRequestRefreshScenarios(const string &client_implementation, bool connection_caching) {
	RunHeadRefreshScenario(client_implementation, connection_caching);
	RunFullGetRefreshScenario(client_implementation, connection_caching);
	RunRangeRefreshScenario(client_implementation, connection_caching);
	RunPutRefreshScenario(client_implementation, connection_caching);
	RunMultipartInitiatePostRefreshScenario(client_implementation, connection_caching);
	RunMultipartCompletePostRefreshScenario(client_implementation, connection_caching);
	RunBulkDeletePostRefreshScenario(client_implementation, connection_caching);
	RunDeleteRefreshScenario(client_implementation, connection_caching);
	RunListGlobRefreshScenario(client_implementation, connection_caching);
}

static void RunHandleRequestRefreshScenarios(const string &client_implementation, bool connection_caching) {
	RunHeadRefreshScenario(client_implementation, connection_caching);
	RunFullGetRefreshScenario(client_implementation, connection_caching);
	RunRangeRefreshScenario(client_implementation, connection_caching);
	RunDeleteRefreshScenario(client_implementation, connection_caching);
}

static void RunRangeRefreshDisabledScenario() {
	MockS3ServerConfig config;
	config.object.bucket = S3TestHelper::BUCKET;
	config.object.key = S3TestHelper::OBJECT_KEY;
	config.auth.stale_key_id = S3TestHelper::STALE_KEY_ID;
	config.auth.refresh_target = MockS3RefreshTarget::RANGE_GET;
	MockS3Server server(std::move(config));

	DuckDB db(nullptr);
	Connection con(db);
	auto test_id = S3TestHelper::ConfigureRefresh(db, con, server, "httplib", false, false);

	S3TestHelper::RequireQueryOk(con, "BEGIN TRANSACTION");
	auto &fs = FileSystem::GetFileSystem(*con.context);
	auto handle = fs.OpenFile(S3TestHelper::S3_PATH, FileFlags::FILE_FLAGS_READ | FileFlags::FILE_FLAGS_DIRECT_IO);

	const idx_t offset = 7;
	const idx_t read_size = 9;
	string buffer(read_size, '\0');
	REQUIRE_THROWS(handle->Read(QueryContext(*con.context), &buffer[0], read_size, offset));
	S3TestHelper::RequireQueryOk(con, "ROLLBACK");

	auto observations = server.Observations();
	INFO(MockS3DescribeObservations(observations));
	REQUIRE(MockS3HasObservation(observations, "GET", S3TestHelper::STALE_KEY_ID, 403, "bytes=7-15"));
	REQUIRE_FALSE(S3TestHelper::HasRequestWithKey(observations, S3TestHelper::FRESH_KEY_ID));
	S3TestHelper::AssertNoRefresh(test_id);
}

static void RunListGlobRefreshDisabledScenario() {
	MockS3ServerConfig config;
	config.object.bucket = S3TestHelper::BUCKET;
	config.object.key = S3TestHelper::OBJECT_KEY;
	config.auth.stale_key_id = S3TestHelper::STALE_KEY_ID;
	config.auth.refresh_target = MockS3RefreshTarget::LIST_OBJECTS_GET;
	MockS3Server server(std::move(config));

	DuckDB db(nullptr);
	Connection con(db);
	auto test_id = S3TestHelper::ConfigureRefresh(db, con, server, "httplib", false, false);

	S3TestHelper::RequireQueryOk(con, "BEGIN TRANSACTION");
	auto result = con.Query("SELECT file FROM glob('s3://refresh-bucket/object*.bin')");
	REQUIRE(result);
	REQUIRE(result->HasError());
	S3TestHelper::RequireQueryOk(con, "ROLLBACK");

	auto observations = server.Observations();
	INFO(MockS3DescribeObservations(observations));
	REQUIRE(MockS3HasObservation(observations, "GET", S3TestHelper::STALE_KEY_ID, 403, string(), "list-type=2"));
	REQUIRE_FALSE(S3TestHelper::HasRequestWithKey(observations, S3TestHelper::FRESH_KEY_ID));
	S3TestHelper::AssertNoRefresh(test_id);
}

static void RunMultipleStaleHandlesSingleRefreshScenario() {
	MockS3ServerConfig config;
	config.object.bucket = S3TestHelper::BUCKET;
	config.object.key = S3TestHelper::OBJECT_KEY;
	config.auth.stale_key_id = S3TestHelper::STALE_KEY_ID;
	config.auth.refresh_target = MockS3RefreshTarget::RANGE_GET;
	auto object_data = config.object.data;
	MockS3Server server(std::move(config));

	DuckDB db(nullptr);
	Connection con(db);
	auto test_id = S3TestHelper::ConfigureRefresh(db, con, server, "httplib", false);

	S3TestHelper::RequireQueryOk(con, "BEGIN TRANSACTION");
	auto &fs = FileSystem::GetFileSystem(*con.context);
	vector<unique_ptr<FileHandle>> handles;
	for (idx_t i = 0; i < 4; i++) {
		handles.push_back(
		    fs.OpenFile(S3TestHelper::S3_PATH, FileFlags::FILE_FLAGS_READ | FileFlags::FILE_FLAGS_DIRECT_IO));
		REQUIRE(handles.back());
	}

	const idx_t offset = 7;
	const idx_t read_size = 9;
	for (auto &handle : handles) {
		string buffer(read_size, '\0');
		handle->Read(QueryContext(*con.context), &buffer[0], read_size, offset);
		REQUIRE(buffer == object_data.substr(offset, read_size));
	}
	S3TestHelper::RequireQueryOk(con, "COMMIT");

	auto observations = server.Observations();
	INFO(MockS3DescribeObservations(observations));
	REQUIRE(S3TestHelper::CountObservations(observations, "GET", S3TestHelper::STALE_KEY_ID, 403) >= handles.size());
	REQUIRE(S3TestHelper::CountObservations(observations, "GET", S3TestHelper::FRESH_KEY_ID, 206) == handles.size());
	S3TestHelper::AssertSingleRefresh(test_id);
}

static void PublishTestS3Region(const shared_ptr<HTTPRequestSession> &session, const string &region) {
	for (;;) {
		auto captured = session->Capture();
		auto &snapshot = captured.snapshot->Cast<S3RequestSnapshot>();
		if (snapshot.auth_params.region == region) {
			return;
		}
		auto auth_params = snapshot.auth_params;
		auth_params.SetRegion(region);
		auto http_params = snapshot.CreateRequestParams();
		auto replacement = make_shared_ptr<S3RequestSnapshot>(
		    *http_params, auth_params, snapshot.refresh_path, snapshot.client_context,
		    snapshot.credential_refresh_enabled, true, snapshot.credential_generation);
		if (session->TryPublish(captured.snapshot, std::move(replacement)).published) {
			return;
		}
	}
}

static void RunRefreshPublicationScenario(const string &client_implementation, bool invalidate_clients,
                                          bool publish_region) {
	MockS3ServerConfig config;
	config.object.bucket = S3TestHelper::BUCKET;
	config.object.key = S3TestHelper::OBJECT_KEY;
	config.auth.stale_key_id = S3TestHelper::STALE_KEY_ID;
	config.auth.refresh_target = MockS3RefreshTarget::RANGE_GET;
	auto object_data = config.object.data;
	MockS3Server server(std::move(config));

	DuckDB db(nullptr);
	Connection con(db);
	auto test_id = S3TestHelper::ConfigureRefresh(db, con, server, client_implementation, false);
	S3TestHelper::RequireQueryOk(con, "BEGIN TRANSACTION");
	auto &fs = FileSystem::GetFileSystem(*con.context);
	auto handle = fs.OpenFile(S3TestHelper::S3_PATH, FileFlags::FILE_FLAGS_READ | FileFlags::FILE_FLAGS_DIRECT_IO);
	REQUIRE(handle);
	auto session = handle->Cast<S3FileHandle>().request_session;
	S3ProviderRefreshHook refresh_hook(test_id, [session, invalidate_clients, publish_region]() {
		if (invalidate_clients) {
			session->InvalidateClients();
		}
		if (publish_region) {
			PublishTestS3Region(session, "eu-west-1");
		}
	});

	const idx_t offset = 7;
	const idx_t read_size = 9;
	string buffer(read_size, '\0');
	handle->Read(QueryContext(*con.context), &buffer[0], read_size, offset);
	REQUIRE(buffer == object_data.substr(offset, read_size));
	S3TestHelper::RequireQueryOk(con, "COMMIT");

	auto &snapshot = session->Capture().snapshot->Cast<S3RequestSnapshot>();
	REQUIRE(snapshot.auth_params.access_key_id == S3TestHelper::FRESH_KEY_ID);
	REQUIRE(snapshot.credential_generation == 1);
	if (publish_region) {
		REQUIRE(snapshot.auth_params.region == "eu-west-1");
		REQUIRE(snapshot.region_redirected);
	}

	auto observations = server.Observations();
	INFO(MockS3DescribeObservations(observations));
	REQUIRE(MockS3HasObservation(observations, "GET", S3TestHelper::STALE_KEY_ID, 403, "bytes=7-15"));
	REQUIRE(MockS3HasObservation(observations, "GET", S3TestHelper::FRESH_KEY_ID, 206, "bytes=7-15"));
	if (publish_region) {
		bool saw_merged_request = false;
		for (const auto &observation : observations) {
			if (observation.method == "GET" && observation.key_id == S3TestHelper::FRESH_KEY_ID &&
			    observation.region == "eu-west-1" && observation.status == 206) {
				saw_merged_request = true;
			}
		}
		REQUIRE(saw_merged_request);
	}
	S3TestHelper::AssertSingleRefresh(test_id);
}

static void RunEndpointModeRefreshScenario(const string &initial_endpoint, const string &initial_resolved_endpoint,
                                           S3EndpointMode initial_mode, const string &refreshed_endpoint,
                                           const string &refreshed_resolved_endpoint, S3EndpointMode refreshed_mode,
                                           const string &published_region = string()) {
	DuckDB db(nullptr);
	Connection con(db);
	S3TestHelper::LoadExtension(db);
	S3TestHelper::RegisterRefreshProvider(db);
	auto test_id = S3TestHelper::NextTestId();
	S3TestHelper::RequireQueryOk(con, StringUtil::Format(R"(
CREATE SECRET refresh_s3_endpoint_mode (
	TYPE S3,
	PROVIDER %s,
	SCOPE 's3://refresh-bucket/',
	KEY_ID '%s',
	SECRET '%s',
	REGION 'us-east-1',
	ENDPOINT '%s',
	TEST_ID '%s',
	REFRESH_INFO MAP {
		'KEY_ID': '%s',
		'SECRET': '%s',
		'REGION': 'us-east-1',
		'ENDPOINT': '%s',
		'TEST_ID': '%s'
	}
))",
	                                                     S3TestHelper::TEST_PROVIDER, S3TestHelper::STALE_KEY_ID,
	                                                     S3TestHelper::STALE_SECRET, initial_endpoint, test_id,
	                                                     S3TestHelper::FRESH_KEY_ID, S3TestHelper::FRESH_SECRET,
	                                                     refreshed_endpoint, test_id));

	S3TestHelper::RequireQueryOk(con, "BEGIN TRANSACTION");
	ClientContextFileOpener opener(*con.context);
	FileOpenerInfo info = {S3TestHelper::S3_PATH};
	auto auth_params = S3AuthParams::ReadFrom(opener, info);
	REQUIRE(auth_params.endpoint_mode == initial_mode);
	auto session = S3RequestExecutor::CreateSession(opener, S3TestHelper::S3_PATH, auth_params);
	if (!published_region.empty()) {
		string previous_region;
		REQUIRE(S3RequestExecutor::SetSessionRegion(*session, published_region, previous_region));
		REQUIRE(previous_region == "us-east-1");
	}
	::AESStateSSLFactory encryption_util;
	vector<S3EndpointMode> observed_modes;
	vector<string> observed_endpoints;
	vector<string> observed_regions;
	auto response = S3RequestExecutor::RunSession(
	    encryption_util, *session, S3TestHelper::S3_PATH, RequestType::GET_REQUEST, S3RequestTarget::OBJECT,
	    [](const ParsedS3Url &) { return S3RequestQuery(); }, "", "", "",
	    [&](S3RequestData &request_data) {
		    observed_modes.push_back(request_data.auth_params.endpoint_mode);
		    observed_endpoints.push_back(request_data.auth_params.endpoint);
		    observed_regions.push_back(request_data.auth_params.region);
		    if (observed_modes.size() == 1) {
			    auto result = make_uniq<HTTPResponse>(HTTPStatusCode::Forbidden_403);
			    result->body = "<Error><Code>AccessDenied</Code><Message>stale credentials</Message></Error>";
			    return result;
		    }
		    return make_uniq<HTTPResponse>(HTTPStatusCode::OK_200);
	    });
	REQUIRE(response);
	REQUIRE(response->status == HTTPStatusCode::OK_200);
	REQUIRE(observed_modes == vector<S3EndpointMode> {initial_mode, refreshed_mode});
	REQUIRE(observed_endpoints == vector<string> {initial_resolved_endpoint, refreshed_resolved_endpoint});
	auto expected_region = published_region.empty() ? string("us-east-1") : published_region;
	REQUIRE(observed_regions == vector<string> {expected_region, expected_region});
	auto &snapshot = session->Capture().snapshot->Cast<S3RequestSnapshot>();
	REQUIRE(snapshot.auth_params.endpoint_mode == refreshed_mode);
	REQUIRE(snapshot.auth_params.endpoint == refreshed_resolved_endpoint);
	S3TestHelper::RequireQueryOk(con, "COMMIT");
	S3TestHelper::AssertSingleRefresh(test_id);
}

static void RunConfiguredHeaderRefreshScenario(const string &client_implementation, bool refresh_to_reserved_header) {
	MockS3ServerConfig config;
	config.object.bucket = S3TestHelper::BUCKET;
	config.object.key = S3TestHelper::OBJECT_KEY;
	config.auth.stale_key_id = S3TestHelper::STALE_KEY_ID;
	config.auth.refresh_target = MockS3RefreshTarget::HEAD;
	MockS3Server server(std::move(config));

	DuckDB db(nullptr);
	Connection con(db);
	S3TestHelper::LoadExtension(db);
	S3TestHelper::RegisterRefreshProvider(db);
	auto test_id = S3TestHelper::NextTestId();
	S3TestHelper::RequireQueryOk(con,
	                             StringUtil::Format("SET httpfs_client_implementation='%s'", client_implementation));
	S3TestHelper::RequireQueryOk(con, "SET httpfs_connection_caching=false");
	S3TestHelper::RequireQueryOk(con, "SET httpfs_enable_credential_refresh=true");
	S3TestHelper::RequireQueryOk(con, StringUtil::Format("SET s3_endpoint='%s'", server.Endpoint()));
	S3TestHelper::RequireQueryOk(con, "SET s3_region='us-east-1'");
	S3TestHelper::RequireQueryOk(con, "SET s3_use_ssl=false");
	S3TestHelper::RequireQueryOk(con, "SET s3_url_style='path'");
	auto fresh_header_name = refresh_to_reserved_header ? "hOsT" : "x-GoOg-Meta-Fresh";
	S3TestHelper::RequireQueryOk(con,
	                             StringUtil::Format(R"(
CREATE SECRET refresh_s3_headers (
	TYPE S3,
	PROVIDER %s,
	SCOPE 's3://refresh-bucket/',
	KEY_ID '%s',
	SECRET '%s',
	TEST_ID '%s',
	TEST_EXTRA_HEADER_NAME 'X-AmZ-Meta-Stale',
	TEST_EXTRA_HEADER_VALUE 'stale-value',
	REFRESH_INFO MAP {
		'KEY_ID': '%s',
		'SECRET': '%s',
		'TEST_ID': '%s',
		'TEST_EXTRA_HEADER_NAME': '%s',
		'TEST_EXTRA_HEADER_VALUE': 'fresh-value'
	}
))",
	                                                S3TestHelper::TEST_PROVIDER, S3TestHelper::STALE_KEY_ID,
	                                                S3TestHelper::STALE_SECRET, test_id, S3TestHelper::FRESH_KEY_ID,
	                                                S3TestHelper::FRESH_SECRET, test_id, fresh_header_name));

	S3TestHelper::RequireQueryOk(con, "BEGIN TRANSACTION");
	string error;
	try {
		OpenForRead(con, FileFlags::FILE_FLAGS_READ | FileFlags::FILE_FLAGS_DIRECT_IO);
	} catch (std::exception &ex) {
		error = ex.what();
	}
	S3TestHelper::RequireQueryOk(con, error.empty() ? "COMMIT" : "ROLLBACK");
	auto observations = server.Observations();
	INFO(client_implementation);
	INFO(MockS3DescribeObservations(observations));
	S3TestHelper::AssertSingleRefresh(test_id);
	REQUIRE(observations.size() == (refresh_to_reserved_header ? 1 : 2));
	const auto &stale_observation = observations[0];
	REQUIRE(stale_observation.key_id == S3TestHelper::STALE_KEY_ID);
	REQUIRE(stale_observation.status == 403);
	REQUIRE(MockS3HeaderValues(stale_observation, "X-AmZ-Meta-Stale") == vector<string> {"stale-value"});
	REQUIRE(StringUtil::Contains(stale_observation.authorization, "x-amz-meta-stale"));

	if (refresh_to_reserved_header) {
		REQUIRE(StringUtil::Contains(error, "hOsT"));
		REQUIRE(StringUtil::Contains(error, "Host"));
		return;
	}

	REQUIRE(error.empty());
	const auto &fresh_observation = observations[1];
	REQUIRE(fresh_observation.key_id == S3TestHelper::FRESH_KEY_ID);
	REQUIRE(fresh_observation.status == 200);
	REQUIRE(MockS3HeaderValues(fresh_observation, "x-GoOg-Meta-Fresh") == vector<string> {"fresh-value"});
	REQUIRE(MockS3HeaderValues(fresh_observation, "X-AmZ-Meta-Stale").empty());
	REQUIRE(StringUtil::Contains(fresh_observation.authorization, "x-goog-meta-fresh"));
	REQUIRE_FALSE(StringUtil::Contains(fresh_observation.authorization, "x-amz-meta-stale"));
}

} // namespace

TEST_CASE("HTTPFS refreshes S3 credentials across request methods", "[httpfs][s3][refresh]") {
	SECTION("httplib without connection caching") {
		RunAllRequestRefreshScenarios("httplib", false);
	}
	SECTION("httplib with handle client cache reuse") {
		RunHandleRequestRefreshScenarios("httplib", false);
	}
	SECTION("curl without connection caching") {
		RunAllRequestRefreshScenarios("curl", false);
	}
}

TEST_CASE("HTTPFS preserves transaction-scoped S3 secrets during refresh", "[httpfs][s3][refresh]") {
	DuckDB db(nullptr);
	Connection con(db);
	S3TestHelper::LoadExtension(db);
	S3TestHelper::RegisterRefreshProvider(db);

	S3TestHelper::RequireQueryOk(con, "BEGIN TRANSACTION");
	auto test_id = S3TestHelper::NextTestId();
	auto input = S3TestHelper::CreateTransactionRefreshInput(test_id);
	auto &secret_manager = SecretManager::Get(*db.instance);
	auto created_secret = secret_manager.CreateSecret(*con.context, input);
	REQUIRE(created_secret);
	REQUIRE(created_secret->persist_type == SecretPersistType::TRANSACTION);
	REQUIRE(created_secret->storage_mode == SecretManager::TRANSACTION_STORAGE_NAME);

	REQUIRE(CreateS3SecretFunctions::TryRefreshS3Secret(*con.context, *created_secret));
	S3TestHelper::AssertSingleRefresh(test_id);

	auto transaction = CatalogTransaction::GetSystemCatalogTransaction(*con.context);
	auto refreshed_secret = secret_manager.GetSecretByName(transaction, input.name.GetIdentifierName());
	REQUIRE(refreshed_secret);
	REQUIRE(refreshed_secret->persist_type == SecretPersistType::TRANSACTION);
	REQUIRE(refreshed_secret->storage_mode == SecretManager::TRANSACTION_STORAGE_NAME);
	auto secret_string = refreshed_secret->secret->ToString(SecretDisplayType::UNREDACTED);
	REQUIRE(StringUtil::Contains(secret_string, StringUtil::Format("key_id=%s", S3TestHelper::FRESH_KEY_ID)));
	REQUIRE_FALSE(StringUtil::Contains(secret_string, StringUtil::Format("key_id=%s", S3TestHelper::STALE_KEY_ID)));

	S3TestHelper::RequireQueryOk(con, "COMMIT");
	S3TestHelper::RequireQueryOk(con, "BEGIN TRANSACTION");
	auto next_transaction = CatalogTransaction::GetSystemCatalogTransaction(*con.context);
	REQUIRE_FALSE(secret_manager.GetSecretByName(next_transaction, input.name.GetIdentifierName()));
	S3TestHelper::RequireQueryOk(con, "ROLLBACK");
}

TEST_CASE("HTTPFS refreshes S3 credentials for token-specific HTTP 400 errors", "[httpfs][s3][refresh]") {
	for (const string client_implementation : {"httplib", "curl"}) {
		DYNAMIC_SECTION(client_implementation << " refreshes ExpiredToken during file open") {
			RunTokenFullGetRefreshScenario(client_implementation, "ExpiredToken");
		}
		DYNAMIC_SECTION(client_implementation << " refreshes InvalidToken during LIST") {
			RunTokenListRefreshScenario(client_implementation, "InvalidToken");
		}
		DYNAMIC_SECTION(client_implementation << " refreshes TokenRefreshRequired during LIST") {
			RunTokenListRefreshScenario(client_implementation, "TokenRefreshRequired");
		}
		DYNAMIC_SECTION(client_implementation << " does not refresh a generic HTTP 400") {
			RunNonAuth400NoRefreshScenario(client_implementation);
		}
	}
}

TEST_CASE("HTTPFS can disable S3 credential refresh", "[httpfs][s3][refresh]") {
	SECTION("range reads fail without refresh") {
		RunRangeRefreshDisabledScenario();
	}
	SECTION("list glob fails without refresh") {
		RunListGlobRefreshDisabledScenario();
	}
}

TEST_CASE("HTTPFS reuses one S3 credential refresh across stale handles", "[httpfs][s3][refresh]") {
	RunMultipleStaleHandlesSingleRefreshScenario();
}

TEST_CASE("S3 credential publication is independent from client invalidation", "[httpfs][s3][refresh]") {
	SECTION("httplib") {
		RunRefreshPublicationScenario("httplib", true, false);
	}
	SECTION("curl") {
		RunRefreshPublicationScenario("curl", true, false);
	}
}

TEST_CASE("S3 credential refresh composes with a concurrent region publication", "[httpfs][s3][refresh]") {
	SECTION("httplib") {
		RunRefreshPublicationScenario("httplib", false, true);
	}
	SECTION("curl") {
		RunRefreshPublicationScenario("curl", false, true);
	}
}

TEST_CASE("S3 credential refresh reconstructs endpoint provenance", "[httpfs][s3][refresh][endpoint]") {
	SECTION("explicit to automatic") {
		RunEndpointModeRefreshScenario("s3.dualstack.us-east-1.amazonaws.com", "s3.dualstack.us-east-1.amazonaws.com",
		                               S3EndpointMode::EXPLICIT, "s3.amazonaws.com", "s3.us-east-1.amazonaws.com",
		                               S3EndpointMode::AUTOMATIC);
	}
	SECTION("automatic to explicit") {
		RunEndpointModeRefreshScenario("s3.amazonaws.com", "s3.eu-west-1.amazonaws.com", S3EndpointMode::AUTOMATIC,
		                               "s3.dualstack.us-east-1.amazonaws.com", "s3.dualstack.us-east-1.amazonaws.com",
		                               S3EndpointMode::EXPLICIT, "eu-west-1");
	}
}

TEST_CASE("S3 credential refresh revalidates and re-signs configured headers", "[httpfs][s3][refresh][headers]") {
	for (const string client_implementation : {"httplib", "curl"}) {
		DYNAMIC_SECTION(client_implementation << " signs refreshed header material") {
			RunConfiguredHeaderRefreshScenario(client_implementation, false);
		}
		DYNAMIC_SECTION(client_implementation << " rejects a refreshed reserved header before dispatch") {
			RunConfiguredHeaderRefreshScenario(client_implementation, true);
		}
	}
}

TEST_CASE("HTTPFS bulk delete follows a refreshed S3 endpoint", "[httpfs][s3][refresh]") {
	SECTION("httplib") {
		RunBulkDeleteEndpointRefreshScenario("httplib");
	}
	SECTION("curl") {
		RunBulkDeleteEndpointRefreshScenario("curl");
	}
}

TEST_CASE("HTTPFS bulk delete revalidates R2 limits after endpoint refresh", "[httpfs][s3][refresh][delete]") {
	for (const string client_implementation : {"httplib", "curl"}) {
		DYNAMIC_SECTION(client_implementation << " accepts a compatible prepared batch") {
			RunBulkDeleteR2PolicyRefreshScenario(client_implementation, 700);
		}
		DYNAMIC_SECTION(client_implementation << " rejects an oversized prepared batch before dispatch") {
			RunBulkDeleteR2PolicyRefreshScenario(client_implementation, 1000);
		}
	}
}

} // namespace duckdb
