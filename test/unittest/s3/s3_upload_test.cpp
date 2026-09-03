#include "catch.hpp"

#include "s3/mock_s3_server.hpp"
#include "s3/s3_settings.hpp"
#include "s3/s3_test_helper.hpp"

#include "duckdb.hpp"
#include "duckdb/common/file_system.hpp"
#include "duckdb/common/serializer/async_file_writer.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/storage/storage_info.hpp"

#include <future>
#include <thread>

namespace duckdb {

namespace {

struct S3UploadTest {
public:
	template <class CALLBACK>
	static string RequireError(CALLBACK callback) {
		try {
			callback();
		} catch (std::exception &ex) {
			return ex.what();
		}
		FAIL("Expected operation to throw");
		return string();
	}

	static unique_ptr<FileHandle> OpenWriter(Connection &con, const string &path = S3TestHelper::S3_PATH) {
		auto &fs = FileSystem::GetFileSystem(*con.context);
		return fs.OpenFile(path, FileFlags::FILE_FLAGS_WRITE | FileFlags::FILE_FLAGS_FILE_CREATE_NEW);
	}

	static void Configure(DuckDB &db, Connection &con, MockS3Server &server, const string &client_implementation,
	                      bool use_minimum_part_size = true) {
		S3TestHelper::ConfigureRefresh(db, con, server, client_implementation, false);
		if (use_minimum_part_size) {
			S3TestHelper::RequireQueryOk(con, "SET s3_uploader_max_filesize='50GB'");
		}
		S3TestHelper::RequireQueryOk(con, "SET http_retries=0");
	}

	static void ConfigureFixed(DuckDB &db, Connection &con, MockS3Server &server, const string &client_implementation,
	                           bool s3_routed) {
		S3TestHelper::LoadExtension(db);
		S3TestHelper::RequireQueryOk(
		    con, StringUtil::Format("SET httpfs_client_implementation='%s'", client_implementation));
		S3TestHelper::RequireQueryOk(con, "SET httpfs_connection_caching=false");
		S3TestHelper::RequireQueryOk(con, "SET httpfs_enable_credential_refresh=false");
		S3TestHelper::RequireQueryOk(con, "SET http_retries=0");
		auto endpoint = s3_routed ? "account.eu.r2.cloudflarestorage.com" : server.Endpoint();
		auto secret_type = s3_routed ? "S3" : "R2";
		auto scope = s3_routed ? "s3://refresh-bucket/" : "r2://refresh-bucket/";
		S3TestHelper::RequireQueryOk(con, StringUtil::Format(R"(
CREATE SECRET fixed_upload (
	TYPE %s,
	SCOPE '%s',
	KEY_ID 'R2_KEY',
	SECRET 'R2_SECRET',
	REGION 'us-east-1',
	ENDPOINT '%s',
	USE_SSL false,
	URL_STYLE 'path'
))",
		                                                     secret_type, scope, endpoint));
		if (s3_routed) {
			S3TestHelper::RequireQueryOk(con, StringUtil::Format("SET http_proxy='http://%s'", server.Endpoint()));
		}
	}

	static void ConfigureGCS(Connection &con, MockS3Server &server, const string &client_implementation) {
		S3TestHelper::RequireQueryOk(
		    con, StringUtil::Format("SET httpfs_client_implementation='%s'", client_implementation));
		S3TestHelper::RequireQueryOk(con, "SET httpfs_connection_caching=false");
		S3TestHelper::RequireQueryOk(con, "SET httpfs_enable_credential_refresh=false");
		S3TestHelper::RequireQueryOk(con, "SET http_retries=0");
		S3TestHelper::RequireQueryOk(con, "SET s3_uploader_max_filesize='50GB'");
		S3TestHelper::RequireQueryOk(con, StringUtil::Format(R"(
CREATE SECRET gcs_upload (
	TYPE GCS,
	SCOPE 'gcs://refresh-bucket/',
	KEY_ID 'GCS_KEY',
	SECRET 'GCS_SECRET',
	USER_PROJECT 'billing-project',
	ENDPOINT '%s',
	USE_SSL false,
	URL_STYLE 'path'
))",
		                                                     server.Endpoint()));
	}

	static void RunGCSRequesterPaysUpload(const string &client_implementation, bool multipart) {
		MockS3ServerConfig config;
		config.object.bucket = S3TestHelper::BUCKET;
		config.object.key = S3TestHelper::OBJECT_KEY;
		config.auth.stale_key_id = "NEVER_STALE";
		config.auth.refresh_target = MockS3RefreshTarget::DELETE_OBJECT;
		MockS3Server server(std::move(config));

		DuckDB db(nullptr);
		Connection con(db);
		S3TestHelper::LoadExtension(db);
		ConfigureGCS(con, server, client_implementation);

		S3TestHelper::RequireQueryOk(con, "BEGIN TRANSACTION");
		auto handle = OpenWriter(con, "gcs://refresh-bucket/object.bin");
		auto payload = multipart ? CreateMultipartPayload() : string("single GCS PUT");
		handle->Write(QueryContext(*con.context), data_ptr_cast(payload.data()), payload.size());
		handle->Close();
		handle.reset();
		S3TestHelper::RequireQueryOk(con, "COMMIT");

		auto observations = server.Observations();
		INFO(MockS3DescribeObservations(observations));
		REQUIRE(server.UploadedObject() == payload);
		if (multipart) {
			REQUIRE(Count(observations, "POST", "uploads") == 1);
			REQUIRE(Count(observations, "PUT", "partNumber") >= 1);
			REQUIRE(Count(observations, "POST", "uploadId") == 1);
		} else {
			REQUIRE(Count(observations, "PUT") == 1);
			REQUIRE(Count(observations, "POST") == 0);
		}
		for (const auto &observation : observations) {
			REQUIRE(MockS3HeaderValues(observation, "x-goog-user-project") == vector<string> {"billing-project"});
			REQUIRE(MockS3HeaderValues(observation, "x-amz-request-payer").empty());
			REQUIRE(StringUtil::Contains(observation.authorization, "x-goog-user-project"));
		}
	}

	static void RunGCSRequesterPaysRefresh(const string &client_implementation) {
		MockS3ServerConfig config;
		config.object.bucket = S3TestHelper::BUCKET;
		config.object.key = S3TestHelper::OBJECT_KEY;
		config.auth.stale_key_id = S3TestHelper::STALE_KEY_ID;
		config.auth.refresh_target = MockS3RefreshTarget::MULTIPART_INITIATE_POST;
		MockS3Server server(std::move(config));

		DuckDB db(nullptr);
		Connection con(db);
		S3TestHelper::LoadExtension(db);
		S3TestHelper::RegisterRefreshProvider(db);
		auto test_id = S3TestHelper::NextTestId();
		S3TestHelper::RequireQueryOk(
		    con, StringUtil::Format("SET httpfs_client_implementation='%s'", client_implementation));
		S3TestHelper::RequireQueryOk(con, "SET httpfs_connection_caching=false");
		S3TestHelper::RequireQueryOk(con, "SET httpfs_enable_credential_refresh=true");
		S3TestHelper::RequireQueryOk(con, "SET http_retries=0");
		S3TestHelper::RequireQueryOk(con, "SET s3_use_ssl=false");
		S3TestHelper::RequireQueryOk(con, "SET s3_uploader_max_filesize='50GB'");
		S3TestHelper::RequireQueryOk(con, StringUtil::Format(R"(
CREATE SECRET gcs_refresh_upload (
	TYPE GCS,
	PROVIDER %s,
	SCOPE 'gcs://refresh-bucket/',
	KEY_ID '%s',
	SECRET '%s',
	USER_PROJECT 'stale-project',
	ENDPOINT '%s',
	TEST_ID '%s',
	REFRESH_INFO MAP {
		'KEY_ID': '%s',
		'SECRET': '%s',
		'USER_PROJECT': 'fresh-project',
		'ENDPOINT': '%s',
		'TEST_ID': '%s'
	}
))",
		                                                     S3TestHelper::TEST_PROVIDER, S3TestHelper::STALE_KEY_ID,
		                                                     S3TestHelper::STALE_SECRET, server.Endpoint(), test_id,
		                                                     S3TestHelper::FRESH_KEY_ID, S3TestHelper::FRESH_SECRET,
		                                                     server.Endpoint(), test_id));

		S3TestHelper::RequireQueryOk(con, "BEGIN TRANSACTION");
		auto handle = OpenWriter(con, "gcs://refresh-bucket/object.bin");
		auto payload = CreateMultipartPayload();
		handle->Write(QueryContext(*con.context), data_ptr_cast(payload.data()), payload.size());
		handle->Close();
		handle.reset();
		S3TestHelper::RequireQueryOk(con, "COMMIT");

		auto observations = server.Observations();
		INFO(MockS3DescribeObservations(observations));
		idx_t stale_requests = 0;
		idx_t fresh_initializations = 0;
		idx_t fresh_parts = 0;
		idx_t fresh_completions = 0;
		for (const auto &observation : observations) {
			if (observation.key_id == S3TestHelper::STALE_KEY_ID) {
				stale_requests++;
				REQUIRE(observation.method == "POST");
				REQUIRE(observation.status == 403);
				REQUIRE(StringUtil::Contains(observation.target, "uploads"));
				REQUIRE(MockS3HeaderValues(observation, "x-goog-user-project") == vector<string> {"stale-project"});
				continue;
			}
			REQUIRE(observation.key_id == S3TestHelper::FRESH_KEY_ID);
			REQUIRE(MockS3HeaderValues(observation, "x-goog-user-project") == vector<string> {"fresh-project"});
			fresh_initializations +=
			    observation.method == "POST" && StringUtil::Contains(observation.target, "uploads");
			fresh_parts += observation.method == "PUT" && observation.part_number.IsValid();
			fresh_completions += observation.method == "POST" && StringUtil::Contains(observation.target, "uploadId");
		}
		REQUIRE(stale_requests == 1);
		REQUIRE(fresh_initializations == 1);
		REQUIRE(fresh_parts >= 1);
		REQUIRE(fresh_completions == 1);
		REQUIRE(server.UploadedObject() == payload);
		S3TestHelper::AssertSingleRefresh(test_id);
	}

	static void RunUploadPolicyRefreshRejected(const string &client_implementation, bool initial_fixed) {
		MockS3ServerConfig config;
		config.object.bucket = S3TestHelper::BUCKET;
		config.object.key = S3TestHelper::OBJECT_KEY;
		config.auth.stale_key_id = S3TestHelper::STALE_KEY_ID;
		config.auth.refresh_target = MockS3RefreshTarget::MULTIPART_INITIATE_POST;
		MockS3Server server(std::move(config));

		DuckDB db(nullptr);
		Connection con(db);
		S3TestHelper::LoadExtension(db);
		S3TestHelper::RegisterRefreshProvider(db);
		auto test_id = S3TestHelper::NextTestId();
		S3TestHelper::RequireQueryOk(
		    con, StringUtil::Format("SET httpfs_client_implementation='%s'", client_implementation));
		S3TestHelper::RequireQueryOk(con, "SET httpfs_connection_caching=false");
		S3TestHelper::RequireQueryOk(con, "SET httpfs_enable_credential_refresh=true");
		S3TestHelper::RequireQueryOk(con, "SET http_retries=0");
		S3TestHelper::RequireQueryOk(con, "SET s3_region='us-east-1'");
		S3TestHelper::RequireQueryOk(con, "SET s3_use_ssl=false");
		S3TestHelper::RequireQueryOk(con, "SET s3_url_style='path'");
		S3TestHelper::RequireQueryOk(con, "SET s3_uploader_max_filesize='50GB'");
		S3TestHelper::RequireQueryOk(con, StringUtil::Format("SET http_proxy='http://%s'", server.Endpoint()));

		const string r2_endpoint = "account.eu.r2.cloudflarestorage.com";
		auto initial_endpoint = initial_fixed ? r2_endpoint : server.Endpoint();
		auto refreshed_endpoint = initial_fixed ? server.Endpoint() : r2_endpoint;
		S3TestHelper::RequireQueryOk(con, StringUtil::Format(R"(
CREATE SECRET refresh_upload_policy (
	TYPE S3,
	PROVIDER %s,
	SCOPE 's3://refresh-bucket/',
	KEY_ID '%s',
	SECRET '%s',
	ENDPOINT '%s',
	TEST_ID '%s',
	REFRESH_INFO MAP {
		'KEY_ID': '%s',
		'SECRET': '%s',
		'ENDPOINT': '%s',
		'TEST_ID': '%s'
	}
))",
		                                                     S3TestHelper::TEST_PROVIDER, S3TestHelper::STALE_KEY_ID,
		                                                     S3TestHelper::STALE_SECRET, initial_endpoint, test_id,
		                                                     S3TestHelper::FRESH_KEY_ID, S3TestHelper::FRESH_SECRET,
		                                                     refreshed_endpoint, test_id));

		S3TestHelper::RequireQueryOk(con, "BEGIN TRANSACTION");
		auto handle = OpenWriter(con);
		string payload(10ULL * 1024ULL * 1024ULL + 1, 'x');
		auto error = RequireError(
		    [&]() { handle->Write(QueryContext(*con.context), data_ptr_cast(payload.data()), payload.size()); });
		handle.reset();
		S3TestHelper::RequireQueryOk(con, "ROLLBACK");

		auto observations = server.Observations();
		INFO(error);
		INFO(MockS3DescribeObservations(observations));
		REQUIRE(StringUtil::Contains(error, "different multipart upload policy"));
		REQUIRE(S3TestHelper::CountObservations(observations, "POST", S3TestHelper::STALE_KEY_ID, 403) == 1);
		REQUIRE_FALSE(S3TestHelper::HasRequestWithKey(observations, S3TestHelper::FRESH_KEY_ID));
		S3TestHelper::AssertSingleRefresh(test_id);
	}

	static idx_t Count(const vector<MockS3RequestObservation> &observations, const string &method,
	                   const string &target_contains = string()) {
		idx_t result = 0;
		for (const auto &observation : observations) {
			if (observation.method == method &&
			    (target_contains.empty() || StringUtil::Contains(observation.target, target_contains))) {
				result++;
			}
		}
		return result;
	}

	static vector<MockS3RequestObservation> SuccessfulParts(const vector<MockS3RequestObservation> &observations) {
		vector<MockS3RequestObservation> result;
		for (const auto &observation : observations) {
			if (observation.method == "PUT" && observation.status == 200 && observation.part_number.IsValid()) {
				result.push_back(observation);
			}
		}
		return result;
	}

	static bool WaitForPartStatus(MockS3Server &server, idx_t part_number, int status) {
		auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
		while (std::chrono::steady_clock::now() < deadline) {
			for (auto &observation : server.Observations()) {
				if (observation.method == "PUT" && observation.part_number.IsValid() &&
				    observation.part_number.GetIndex() == part_number && observation.status == status) {
					return true;
				}
			}
			std::this_thread::yield();
		}
		return false;
	}

	static bool HasPartStatus(MockS3Server &server, idx_t part_number, int status) {
		for (auto &observation : server.Observations()) {
			if (observation.method == "PUT" && observation.part_number.IsValid() &&
			    observation.part_number.GetIndex() == part_number && observation.status == status) {
				return true;
			}
		}
		return false;
	}

	static void RequirePartSizes(const vector<MockS3RequestObservation> &observations,
	                             const vector<idx_t> &expected_sizes, const string &upload_id = string()) {
		auto parts = SuccessfulParts(observations);
		REQUIRE(parts.size() == expected_sizes.size());
		vector<idx_t> actual_sizes(expected_sizes.size());
		for (const auto &part : parts) {
			if (!upload_id.empty()) {
				REQUIRE(part.upload_id == upload_id);
			}
			auto part_number = part.part_number.GetIndex();
			REQUIRE(part_number >= 1);
			REQUIRE(part_number <= actual_sizes.size());
			actual_sizes[part_number - 1] = part.body_size;
			REQUIRE_FALSE(part.body_digest.empty());
		}
		REQUIRE(actual_sizes == expected_sizes);
	}

	static string CreatePayload(idx_t size) {
		string result(size, '\0');
		for (idx_t index = 0; index < result.size(); index++) {
			result[index] = NumericCast<char>('a' + index % 23);
		}
		return result;
	}

	static string CreateMultipartPayload() {
		return CreatePayload(12ULL * 1024ULL * 1024ULL + 1);
	}

	static void RunSinglePut(const string &client_implementation) {
		MockS3ServerConfig config;
		config.object.bucket = S3TestHelper::BUCKET;
		config.object.key = S3TestHelper::OBJECT_KEY;
		config.auth.refresh_target = MockS3RefreshTarget::DELETE_OBJECT;
		MockS3Server server(std::move(config));

		DuckDB db(nullptr);
		Connection con(db);
		Configure(db, con, server, client_implementation);

		S3TestHelper::RequireQueryOk(con, "BEGIN TRANSACTION");
		auto handle = OpenWriter(con);
		string payload = "single PUT upload baseline";
		handle->Write(QueryContext(*con.context), data_ptr_cast(payload.data()), payload.size());
		handle->Close();
		string extra = "x";
		auto write_after_finalize = RequireError(
		    [&]() { handle->Write(QueryContext(*con.context), data_ptr_cast(extra.data()), extra.size()); });
		REQUIRE(StringUtil::Contains(write_after_finalize, "finalized S3 upload"));
		handle->Close();
		handle.reset();
		S3TestHelper::RequireQueryOk(con, "COMMIT");

		auto observations = server.Observations();
		INFO(MockS3DescribeObservations(observations));
		REQUIRE(server.UploadedObject() == payload);
		REQUIRE(Count(observations, "PUT") == 1);
		REQUIRE(Count(observations, "POST") == 0);
		for (const auto &observation : observations) {
			if (observation.method != "PUT") {
				continue;
			}
			REQUIRE_FALSE(observation.part_number.IsValid());
			REQUIRE(observation.upload_id.empty());
			REQUIRE(observation.body_size == payload.size());
			REQUIRE_FALSE(observation.body_digest.empty());
		}
	}

	static void RunEmpty(const string &client_implementation) {
		MockS3ServerConfig config;
		config.object.bucket = S3TestHelper::BUCKET;
		config.object.key = S3TestHelper::OBJECT_KEY;
		config.auth.refresh_target = MockS3RefreshTarget::DELETE_OBJECT;
		MockS3Server server(std::move(config));

		DuckDB db(nullptr);
		Connection con(db);
		Configure(db, con, server, client_implementation);

		S3TestHelper::RequireQueryOk(con, "BEGIN TRANSACTION");
		auto handle = OpenWriter(con);
		handle->Sync();
		handle->Close();
		handle.reset();
		S3TestHelper::RequireQueryOk(con, "COMMIT");

		auto observations = server.Observations();
		INFO(MockS3DescribeObservations(observations));
		REQUIRE(server.UploadedObject().empty());
		REQUIRE(Count(observations, "PUT") == 1);
		REQUIRE(Count(observations, "POST") == 0);
		for (const auto &observation : observations) {
			if (observation.method == "PUT") {
				REQUIRE(observation.body_size == 0);
				REQUIRE_FALSE(observation.part_number.IsValid());
			}
		}
	}

	static void RunMultipart(const string &client_implementation) {
		const string upload_id = "upload-baseline-id";
		MockS3ServerConfig config;
		config.object.bucket = S3TestHelper::BUCKET;
		config.object.key = S3TestHelper::OBJECT_KEY;
		config.auth.refresh_target = MockS3RefreshTarget::DELETE_OBJECT;
		config.upload.upload_id = upload_id;
		config.upload.blocked_part_numbers = {1};
		MockS3Server server(std::move(config));

		DuckDB db(nullptr);
		Connection con(db);
		Configure(db, con, server, client_implementation);

		S3TestHelper::RequireQueryOk(con, "BEGIN TRANSACTION");
		auto handle = OpenWriter(con);
		auto payload = CreateMultipartPayload();
		std::exception_ptr write_error;
		std::thread writer([&]() {
			try {
				handle->Write(QueryContext(*con.context), data_ptr_cast(payload.data()), payload.size());
			} catch (...) {
				write_error = std::current_exception();
			}
		});
		auto part_1_started = server.WaitForPartUpload(1);
		auto concurrent_finalize_error = RequireError([&]() { handle->Close(); });
		auto cursor_future = std::async(std::launch::async, [&]() { return handle->SeekPosition(); });
		auto cursor_available = cursor_future.wait_for(std::chrono::seconds(1)) == std::future_status::ready;
		server.ReleasePartUploads();
		writer.join();
		auto cursor_position = cursor_future.get();
		if (write_error) {
			std::rethrow_exception(write_error);
		}

		auto observed_concurrency = server.MaximumConcurrentPartUploads();
		handle->Close();
		handle->Close();
		handle.reset();
		S3TestHelper::RequireQueryOk(con, "COMMIT");

		auto observations = server.Observations();
		INFO(MockS3DescribeObservations(observations));
		REQUIRE(part_1_started);
		REQUIRE(StringUtil::Contains(concurrent_finalize_error, "Concurrent S3 upload operations"));
		REQUIRE(cursor_available);
		REQUIRE(cursor_position == 0);
		REQUIRE(observed_concurrency == 1);
		REQUIRE(server.UploadedObject() == payload);
		REQUIRE(Count(observations, "POST", "uploads") == 1);
		REQUIRE(Count(observations, "POST", "uploadId") == 1);
		REQUIRE(Count(observations, "PUT", "partNumber") == 1);
		RequirePartSizes(observations, {payload.size()}, upload_id);

		const string expected_completion_body =
		    "<CompleteMultipartUpload xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">"
		    "<Part><ETag>\"mock-part-1\"</ETag><PartNumber>1</PartNumber></Part>"
		    "</CompleteMultipartUpload>";
		REQUIRE(server.CompletionBody() == expected_completion_body);
		for (const auto &observation : observations) {
			if (observation.method == "POST" && StringUtil::Contains(observation.target, "uploadId")) {
				REQUIRE(observation.upload_id == upload_id);
			}
		}
	}

	static void RunWholeWriteGeometry(const string &client_implementation, idx_t payload_size) {
		MockS3ServerConfig config;
		config.object.bucket = S3TestHelper::BUCKET;
		config.object.key = S3TestHelper::OBJECT_KEY;
		config.auth.refresh_target = MockS3RefreshTarget::DELETE_OBJECT;
		MockS3Server server(std::move(config));

		DuckDB db(nullptr);
		Connection con(db);
		Configure(db, con, server, client_implementation);

		auto payload = CreatePayload(payload_size);
		S3TestHelper::RequireQueryOk(con, "BEGIN TRANSACTION");
		auto handle = OpenWriter(con);
		handle->Write(QueryContext(*con.context), data_ptr_cast(payload.data()), payload.size());
		auto before_close = server.Observations();
		INFO(MockS3DescribeObservations(before_close));
		if (payload_size <= INITIAL_PART_SIZE) {
			REQUIRE(Count(before_close, "PUT") == 0);
			REQUIRE(Count(before_close, "POST") == 0);
		} else {
			REQUIRE(Count(before_close, "POST", "uploads") == 1);
			REQUIRE(Count(before_close, "PUT", "partNumber") == 1);
		}

		handle->Close();
		handle.reset();
		S3TestHelper::RequireQueryOk(con, "COMMIT");

		auto observations = server.Observations();
		INFO(MockS3DescribeObservations(observations));
		REQUIRE(server.UploadedObject() == payload);
		if (payload_size <= INITIAL_PART_SIZE) {
			REQUIRE(Count(observations, "PUT") == 1);
			REQUIRE(Count(observations, "POST") == 0);
		} else {
			REQUIRE(Count(observations, "POST", "uploads") == 1);
			REQUIRE(Count(observations, "POST", "uploadId") == 1);
			RequirePartSizes(observations, {payload.size()});
		}
	}

	static void RunFullPartLookbehind(const string &client_implementation) {
		MockS3ServerConfig config;
		config.object.bucket = S3TestHelper::BUCKET;
		config.object.key = S3TestHelper::OBJECT_KEY;
		config.auth.refresh_target = MockS3RefreshTarget::DELETE_OBJECT;
		MockS3Server server(std::move(config));

		DuckDB db(nullptr);
		Connection con(db);
		Configure(db, con, server, client_implementation);

		auto payload = CreatePayload(INITIAL_PART_SIZE + 1);
		S3TestHelper::RequireQueryOk(con, "BEGIN TRANSACTION");
		auto handle = OpenWriter(con);
		handle->Write(QueryContext(*con.context), data_ptr_cast(payload.data()), INITIAL_PART_SIZE);
		auto after_first_write = server.Observations();
		INFO(MockS3DescribeObservations(after_first_write));
		REQUIRE(Count(after_first_write, "PUT") == 0);
		REQUIRE(Count(after_first_write, "POST") == 0);

		handle->Write(QueryContext(*con.context), data_ptr_cast(payload.data()) + INITIAL_PART_SIZE, 1);
		auto after_second_write = server.Observations();
		INFO(MockS3DescribeObservations(after_second_write));
		REQUIRE(Count(after_second_write, "POST", "uploads") == 1);
		RequirePartSizes(after_second_write, {INITIAL_PART_SIZE});

		handle->Close();
		handle.reset();
		S3TestHelper::RequireQueryOk(con, "COMMIT");

		auto observations = server.Observations();
		INFO(MockS3DescribeObservations(observations));
		REQUIRE(server.UploadedObject() == payload);
		RequirePartSizes(observations, {INITIAL_PART_SIZE, 1});
	}

	static void RunBufferedPrefix(const string &client_implementation) {
		MockS3ServerConfig config;
		config.object.bucket = S3TestHelper::BUCKET;
		config.object.key = S3TestHelper::OBJECT_KEY;
		config.auth.refresh_target = MockS3RefreshTarget::DELETE_OBJECT;
		MockS3Server server(std::move(config));

		DuckDB db(nullptr);
		Connection con(db);
		Configure(db, con, server, client_implementation);

		const idx_t prefix_size = 1ULL * 1024ULL * 1024ULL;
		const idx_t second_write_size = 12ULL * 1024ULL * 1024ULL;
		auto payload = CreatePayload(prefix_size + second_write_size);
		S3TestHelper::RequireQueryOk(con, "BEGIN TRANSACTION");
		auto handle = OpenWriter(con);
		handle->Write(QueryContext(*con.context), data_ptr_cast(payload.data()), prefix_size);
		REQUIRE(server.Observations().empty());
		handle->Write(QueryContext(*con.context), data_ptr_cast(payload.data()) + prefix_size, second_write_size);
		RequirePartSizes(server.Observations(),
		                 {INITIAL_PART_SIZE, prefix_size + second_write_size - INITIAL_PART_SIZE});
		handle->Close();
		handle.reset();
		S3TestHelper::RequireQueryOk(con, "COMMIT");

		auto observations = server.Observations();
		INFO(MockS3DescribeObservations(observations));
		REQUIRE(server.UploadedObject() == payload);
		RequirePartSizes(observations, {INITIAL_PART_SIZE, prefix_size + second_write_size - INITIAL_PART_SIZE});
	}

	static void RunFragmentedMultipart(const string &client_implementation) {
		MockS3ServerConfig config;
		config.object.bucket = S3TestHelper::BUCKET;
		config.object.key = S3TestHelper::OBJECT_KEY;
		config.auth.refresh_target = MockS3RefreshTarget::DELETE_OBJECT;
		MockS3Server server(std::move(config));

		DuckDB db(nullptr);
		Connection con(db);
		Configure(db, con, server, client_implementation);

		auto payload = CreateMultipartPayload();
		const vector<idx_t> write_sizes {1, INITIAL_PART_SIZE - 2, 3, INITIAL_PART_SIZE,
		                                 payload.size() - 2 * INITIAL_PART_SIZE - 2};
		idx_t offset = 0;
		S3TestHelper::RequireQueryOk(con, "BEGIN TRANSACTION");
		auto handle = OpenWriter(con);
		for (auto write_size : write_sizes) {
			handle->Write(QueryContext(*con.context), data_ptr_cast(payload.data()) + offset, write_size);
			offset += write_size;
		}
		REQUIRE(offset == payload.size());
		handle->Close();
		handle.reset();
		S3TestHelper::RequireQueryOk(con, "COMMIT");

		auto observations = server.Observations();
		INFO(MockS3DescribeObservations(observations));
		REQUIRE(server.UploadedObject() == payload);
		REQUIRE(Count(observations, "POST", "uploads") == 1);
		REQUIRE(Count(observations, "POST", "uploadId") == 1);
		REQUIRE(Count(observations, "PUT", "partNumber") == 3);
		RequirePartSizes(observations, {INITIAL_PART_SIZE, INITIAL_PART_SIZE, payload.size() - 2 * INITIAL_PART_SIZE});
	}

	static void RunAsyncWriter(const string &client_implementation, idx_t async_threads) {
		MockS3ServerConfig config;
		config.object.bucket = S3TestHelper::BUCKET;
		config.object.key = S3TestHelper::OBJECT_KEY;
		config.auth.refresh_target = MockS3RefreshTarget::DELETE_OBJECT;
		MockS3Server server(std::move(config));

		DuckDB db(nullptr);
		Connection con(db);
		Configure(db, con, server, client_implementation, false);
		S3TestHelper::RequireQueryOk(con, "SET async_threads=" + to_string(async_threads));

		auto payload = CreatePayload(8ULL * 1024ULL * 1024ULL);
		auto &fs = FileSystem::GetFileSystem(*con.context);
		S3TestHelper::RequireQueryOk(con, "BEGIN TRANSACTION");
		AsyncFileWriter writer(*con.context, fs, S3TestHelper::S3_PATH,
		                       FileFlags::FILE_FLAGS_WRITE | FileFlags::FILE_FLAGS_FILE_CREATE_NEW);
		writer.WriteData(const_data_ptr_cast(payload.data()), payload.size());
		writer.Close();
		S3TestHelper::RequireQueryOk(con, "COMMIT");

		auto observations = server.Observations();
		INFO(MockS3DescribeObservations(observations));
		REQUIRE(server.UploadedObject() == payload);
		REQUIRE(server.MaximumConcurrentPartUploads() == 1);
		REQUIRE(Count(observations, "POST", "uploads") == 1);
		REQUIRE(Count(observations, "POST", "uploadId") == 1);
		RequirePartSizes(observations, {payload.size()});
	}

	static void RunConcurrentAsyncWriter(const string &client_implementation) {
		MockS3ServerConfig config;
		config.object.bucket = S3TestHelper::BUCKET;
		config.object.key = S3TestHelper::OBJECT_KEY;
		config.auth.refresh_target = MockS3RefreshTarget::DELETE_OBJECT;
		config.upload.blocked_part_numbers = {1, 2};
		MockS3Server server(std::move(config));

		DuckDB db(nullptr);
		Connection con(db);
		Configure(db, con, server, client_implementation, false);
		S3TestHelper::RequireQueryOk(con, "SET async_threads=2");

		auto write_size = 16ULL * 1024ULL * 1024ULL + 1;
		auto payload = CreatePayload(2 * write_size);
		auto &fs = FileSystem::GetFileSystem(*con.context);
		S3TestHelper::RequireQueryOk(con, "BEGIN TRANSACTION");
		AsyncFileWriter writer(*con.context, fs, S3TestHelper::S3_PATH,
		                       FileFlags::FILE_FLAGS_WRITE | FileFlags::FILE_FLAGS_FILE_CREATE_NEW);
		{
			auto batch = writer.StartBatch();
			writer.WriteData(const_data_ptr_cast(payload.data()), write_size);
			writer.WriteData(const_data_ptr_cast(payload.data()) + write_size, write_size);
			batch.Finish();
		}

		auto part_1_started = server.WaitForPartUpload(1);
		auto part_2_started = server.WaitForPartUpload(2);
		auto maximum_concurrency = server.MaximumConcurrentPartUploads();
		server.ReleasePartUpload(2);
		auto part_2_completed_first = WaitForPartStatus(server, 2, 200);
		auto part_1_completed_early = HasPartStatus(server, 1, 200);
		server.ReleasePartUpload(1);
		writer.Close();
		S3TestHelper::RequireQueryOk(con, "COMMIT");

		auto observations = server.Observations();
		INFO(MockS3DescribeObservations(observations));
		REQUIRE(part_1_started);
		REQUIRE(part_2_started);
		REQUIRE(maximum_concurrency == 2);
		REQUIRE(part_2_completed_first);
		REQUIRE_FALSE(part_1_completed_early);
		REQUIRE(server.UploadedObject() == payload);
		REQUIRE(Count(observations, "POST", "uploads") == 1);
		REQUIRE(Count(observations, "POST", "uploadId") == 1);
		RequirePartSizes(observations, {write_size, write_size});
		const string expected_completion_body =
		    "<CompleteMultipartUpload xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">"
		    "<Part><ETag>\"mock-part-1\"</ETag><PartNumber>1</PartNumber></Part>"
		    "<Part><ETag>\"mock-part-2\"</ETag><PartNumber>2</PartNumber></Part>"
		    "</CompleteMultipartUpload>";
		REQUIRE(server.CompletionBody() == expected_completion_body);
	}

	static void RunLaterOffsetFirst(const string &client_implementation) {
		MockS3ServerConfig config;
		config.object.bucket = S3TestHelper::BUCKET;
		config.object.key = S3TestHelper::OBJECT_KEY;
		config.auth.refresh_target = MockS3RefreshTarget::DELETE_OBJECT;
		config.upload.blocked_part_numbers = {1, 2};
		MockS3Server server(std::move(config));

		DuckDB db(nullptr);
		Connection con(db);
		Configure(db, con, server, client_implementation);
		auto write_size = 6ULL * 1024ULL * 1024ULL;
		auto payload = CreatePayload(2 * write_size);
		S3TestHelper::RequireQueryOk(con, "BEGIN TRANSACTION");
		auto handle = OpenWriter(con);
		std::atomic<bool> later_started(false);
		std::atomic<bool> later_finished(false);
		std::exception_ptr later_error;
		std::exception_ptr earlier_error;
		std::thread later([&]() {
			later_started.store(true);
			try {
				handle->Write(QueryContext(*con.context), data_ptr_cast(payload.data()) + write_size, write_size,
				              write_size);
			} catch (...) {
				later_error = std::current_exception();
			}
			later_finished.store(true);
		});
		while (!later_started.load()) {
			std::this_thread::yield();
		}
		std::this_thread::sleep_for(std::chrono::milliseconds(50));
		auto later_waited_for_admission = !later_finished.load() && server.Observations().empty();
		std::thread earlier([&]() {
			try {
				handle->Write(QueryContext(*con.context), data_ptr_cast(payload.data()), write_size, 0);
			} catch (...) {
				earlier_error = std::current_exception();
			}
		});

		auto part_1_started = server.WaitForPartUpload(1);
		auto part_2_started = server.WaitForPartUpload(2);
		server.ReleasePartUpload(2);
		auto part_2_completed_first = WaitForPartStatus(server, 2, 200);
		server.ReleasePartUpload(1);
		earlier.join();
		later.join();
		if (earlier_error) {
			std::rethrow_exception(earlier_error);
		}
		if (later_error) {
			std::rethrow_exception(later_error);
		}
		handle->Close();
		handle.reset();
		S3TestHelper::RequireQueryOk(con, "COMMIT");

		INFO(MockS3DescribeObservations(server.Observations()));
		REQUIRE(later_waited_for_admission);
		REQUIRE(part_1_started);
		REQUIRE(part_2_started);
		REQUIRE(part_2_completed_first);
		REQUIRE(server.UploadedObject() == payload);
	}

	static void RunConcurrentPartFailure(const string &client_implementation) {
		MockS3ServerConfig config;
		config.object.bucket = S3TestHelper::BUCKET;
		config.object.key = S3TestHelper::OBJECT_KEY;
		config.auth.refresh_target = MockS3RefreshTarget::HEAD;
		config.upload.blocked_part_numbers = {1};
		config.upload.failed_part_numbers = {2};
		MockS3Server server(std::move(config));

		DuckDB db(nullptr);
		Connection con(db);
		Configure(db, con, server, client_implementation, false);
		S3TestHelper::RequireQueryOk(con, "SET async_threads=2");
		auto write_size = 16ULL * 1024ULL * 1024ULL + 1;
		auto payload = CreatePayload(2 * write_size);
		auto &fs = FileSystem::GetFileSystem(*con.context);
		S3TestHelper::RequireQueryOk(con, "BEGIN TRANSACTION");
		AsyncFileWriter writer(*con.context, fs, S3TestHelper::S3_PATH,
		                       FileFlags::FILE_FLAGS_WRITE | FileFlags::FILE_FLAGS_FILE_CREATE_NEW);
		writer.WriteData(const_data_ptr_cast(payload.data()), write_size);
		auto part_1_started = server.WaitForPartUpload(1);
		writer.WriteData(const_data_ptr_cast(payload.data()) + write_size, write_size);
		auto part_2_started = server.WaitForPartUpload(2);
		auto part_2_failed = WaitForPartStatus(server, 2, 400);
		auto observations_before_release = server.Observations();
		server.ReleasePartUpload(1);
		auto first_error = RequireError([&]() { writer.Close(); });
		auto second_error = RequireError([&]() { writer.Close(); });
		S3TestHelper::RequireQueryOk(con, "ROLLBACK");

		auto observations = server.Observations();
		INFO(MockS3DescribeObservations(observations));
		REQUIRE(part_1_started);
		REQUIRE(part_2_started);
		REQUIRE(part_2_failed);
		REQUIRE(Count(observations_before_release, "DELETE", "uploadId") == 0);
		REQUIRE(first_error == second_error);
		REQUIRE(Count(observations, "DELETE", "uploadId") == 1);
		REQUIRE(Count(observations, "POST", "uploadId") == 0);
		REQUIRE(server.MaximumConcurrentPartUploads() == 2);
	}

	static void RunAdaptivePartSizes(const string &client_implementation) {
		MockS3ServerConfig config;
		config.object.bucket = S3TestHelper::BUCKET;
		config.object.key = S3TestHelper::OBJECT_KEY;
		config.auth.refresh_target = MockS3RefreshTarget::DELETE_OBJECT;
		MockS3Server server(std::move(config));

		DuckDB db(nullptr);
		Connection con(db);
		Configure(db, con, server, client_implementation);
		S3TestHelper::RequireQueryOk(con, "SET s3_uploader_max_parts_per_file=11");
		S3TestHelper::RequireQueryOk(con, "SET s3_uploader_max_filesize='16MiB'");

		const vector<idx_t> write_sizes {5ULL * 1024ULL * 1024ULL, 5ULL * 1024ULL * 1024ULL, 5ULL * 1024ULL * 1024ULL,
		                                 1ULL * 1024ULL * 1024ULL};
		auto payload = CreatePayload(16ULL * 1024ULL * 1024ULL);
		idx_t offset = 0;
		S3TestHelper::RequireQueryOk(con, "BEGIN TRANSACTION");
		auto handle = OpenWriter(con);
		for (auto write_size : write_sizes) {
			handle->Write(QueryContext(*con.context), data_ptr_cast(payload.data()) + offset, write_size);
			offset += write_size;
		}
		handle->Close();
		handle.reset();
		S3TestHelper::RequireQueryOk(con, "COMMIT");

		auto observations = server.Observations();
		INFO(MockS3DescribeObservations(observations));
		REQUIRE(server.UploadedObject() == payload);
		RequirePartSizes(observations, {5ULL * 1024ULL * 1024ULL, 10ULL * 1024ULL * 1024ULL, 1ULL * 1024ULL * 1024ULL});
	}

	static void RunFixedFragmented(const string &client_implementation) {
		MockS3ServerConfig config;
		config.object.bucket = S3TestHelper::BUCKET;
		config.object.key = S3TestHelper::OBJECT_KEY;
		config.auth.refresh_target = MockS3RefreshTarget::DELETE_OBJECT;
		config.upload.geometry = MockS3MultipartGeometry::FIXED_EQUAL;
		MockS3Server server(std::move(config));

		DuckDB db(nullptr);
		Connection con(db);
		ConfigureFixed(db, con, server, client_implementation, false);

		auto payload = CreatePayload(2 * FIXED_PART_SIZE + 3);
		const vector<idx_t> write_sizes {1, FIXED_PART_SIZE - 2, 3, FIXED_PART_SIZE, 1};
		idx_t offset = 0;
		S3TestHelper::RequireQueryOk(con, "BEGIN TRANSACTION");
		auto handle = OpenWriter(con, R2_PATH);
		for (auto write_size : write_sizes) {
			handle->Write(QueryContext(*con.context), data_ptr_cast(payload.data()) + offset, write_size);
			offset += write_size;
		}
		REQUIRE(offset == payload.size());
		handle->Close();
		handle.reset();
		S3TestHelper::RequireQueryOk(con, "COMMIT");

		auto observations = server.Observations();
		INFO(MockS3DescribeObservations(observations));
		REQUIRE(server.UploadedObject() == payload);
		RequirePartSizes(observations, {FIXED_PART_SIZE, FIXED_PART_SIZE, 3});
	}

	static void RunFixedOversized(const string &client_implementation, bool s3_routed) {
		MockS3ServerConfig config;
		config.object.bucket = S3TestHelper::BUCKET;
		config.object.key = S3TestHelper::OBJECT_KEY;
		config.auth.refresh_target = MockS3RefreshTarget::DELETE_OBJECT;
		config.upload.geometry = MockS3MultipartGeometry::FIXED_EQUAL;
		MockS3Server server(std::move(config));

		DuckDB db(nullptr);
		Connection con(db);
		ConfigureFixed(db, con, server, client_implementation, s3_routed);

		auto payload = CreatePayload(3 * FIXED_PART_SIZE);
		S3TestHelper::RequireQueryOk(con, "BEGIN TRANSACTION");
		auto handle = OpenWriter(con, s3_routed ? S3TestHelper::S3_PATH : R2_PATH);
		handle->Write(QueryContext(*con.context), data_ptr_cast(payload.data()), payload.size());
		try {
			handle->Close();
		} catch (...) {
			INFO(MockS3DescribeObservations(server.Observations()));
			throw;
		}
		handle.reset();
		S3TestHelper::RequireQueryOk(con, "COMMIT");

		auto observations = server.Observations();
		INFO(MockS3DescribeObservations(observations));
		REQUIRE(server.UploadedObject() == payload);
		RequirePartSizes(observations, {FIXED_PART_SIZE, FIXED_PART_SIZE, FIXED_PART_SIZE});
	}

	static void RunFixedConcurrentWrites(const string &client_implementation) {
		MockS3ServerConfig config;
		config.object.bucket = S3TestHelper::BUCKET;
		config.object.key = S3TestHelper::OBJECT_KEY;
		config.auth.refresh_target = MockS3RefreshTarget::DELETE_OBJECT;
		config.upload.geometry = MockS3MultipartGeometry::FIXED_EQUAL;
		config.upload.blocked_part_numbers = {1, 2};
		MockS3Server server(std::move(config));

		DuckDB db(nullptr);
		Connection con(db);
		ConfigureFixed(db, con, server, client_implementation, false);
		auto write_size = FIXED_PART_SIZE + 1;
		auto payload = CreatePayload(2 * write_size);
		S3TestHelper::RequireQueryOk(con, "BEGIN TRANSACTION");
		auto handle = OpenWriter(con, R2_PATH);
		std::exception_ptr first_error;
		std::exception_ptr second_error;
		std::thread first([&]() {
			try {
				handle->Write(QueryContext(*con.context), data_ptr_cast(payload.data()), write_size, 0);
			} catch (...) {
				first_error = std::current_exception();
			}
		});
		auto part_1_started = server.WaitForPartUpload(1);
		std::thread second([&]() {
			try {
				handle->Write(QueryContext(*con.context), data_ptr_cast(payload.data()) + write_size, write_size,
				              write_size);
			} catch (...) {
				second_error = std::current_exception();
			}
		});
		auto part_2_started = server.WaitForPartUpload(2);
		auto maximum_concurrency = server.MaximumConcurrentPartUploads();
		server.ReleasePartUpload(2);
		auto part_2_completed_first = WaitForPartStatus(server, 2, 200);
		auto part_1_completed_early = HasPartStatus(server, 1, 200);
		server.ReleasePartUpload(1);
		first.join();
		second.join();
		if (first_error) {
			std::rethrow_exception(first_error);
		}
		if (second_error) {
			std::rethrow_exception(second_error);
		}
		handle->Close();
		handle.reset();
		S3TestHelper::RequireQueryOk(con, "COMMIT");

		auto observations = server.Observations();
		INFO(MockS3DescribeObservations(observations));
		REQUIRE(part_1_started);
		REQUIRE(part_2_started);
		REQUIRE(maximum_concurrency == 2);
		REQUIRE(part_2_completed_first);
		REQUIRE_FALSE(part_1_completed_early);
		REQUIRE(server.UploadedObject() == payload);
		RequirePartSizes(observations, {FIXED_PART_SIZE, FIXED_PART_SIZE, 2});
	}

	static void RunMockRejectsInvalidFixedGeometry(const string &client_implementation, bool final_is_larger) {
		MockS3ServerConfig config;
		config.object.bucket = S3TestHelper::BUCKET;
		config.object.key = S3TestHelper::OBJECT_KEY;
		config.auth.refresh_target = MockS3RefreshTarget::HEAD;
		config.upload.initial_published_object = "published before invalid upload";
		config.upload.geometry = MockS3MultipartGeometry::FIXED_EQUAL;
		MockS3Server server(std::move(config));

		DuckDB db(nullptr);
		Connection con(db);
		Configure(db, con, server, client_implementation);
		vector<idx_t> write_sizes;
		vector<idx_t> expected_sizes;
		if (final_is_larger) {
			write_sizes = {5ULL * 1024ULL * 1024ULL, 6ULL * 1024ULL * 1024ULL};
			expected_sizes = write_sizes;
		} else {
			S3TestHelper::RequireQueryOk(con, "SET s3_uploader_max_parts_per_file=11");
			S3TestHelper::RequireQueryOk(con, "SET s3_uploader_max_filesize='16MiB'");
			write_sizes = {5ULL * 1024ULL * 1024ULL, 5ULL * 1024ULL * 1024ULL, 5ULL * 1024ULL * 1024ULL,
			               1ULL * 1024ULL * 1024ULL};
			expected_sizes = {5ULL * 1024ULL * 1024ULL, 10ULL * 1024ULL * 1024ULL, 1ULL * 1024ULL * 1024ULL};
		}
		idx_t payload_size = 0;
		for (auto write_size : write_sizes) {
			payload_size += write_size;
		}
		auto payload = CreatePayload(payload_size);
		idx_t offset = 0;
		S3TestHelper::RequireQueryOk(con, "BEGIN TRANSACTION");
		auto handle = OpenWriter(con);
		for (auto write_size : write_sizes) {
			handle->Write(QueryContext(*con.context), data_ptr_cast(payload.data()) + offset, write_size);
			offset += write_size;
		}
		auto error = RequireError([&]() { handle->Close(); });
		handle.reset();
		S3TestHelper::RequireQueryOk(con, "ROLLBACK");

		auto observations = server.Observations();
		INFO(error);
		INFO(MockS3DescribeObservations(observations));
		REQUIRE(StringUtil::Contains(error, "InvalidPart"));
		REQUIRE(server.UploadedObject() == "published before invalid upload");
		RequirePartSizes(observations, expected_sizes);
		REQUIRE(Count(observations, "POST", "uploadId") == 1);
		REQUIRE(Count(observations, "DELETE", "uploadId") == 1);
	}

	static void RunFixedConfigRejectedBeforeHTTP(const string &client_implementation) {
		MockS3ServerConfig config;
		config.object.bucket = S3TestHelper::BUCKET;
		config.object.key = S3TestHelper::OBJECT_KEY;
		MockS3Server server(std::move(config));

		DuckDB db(nullptr);
		Connection con(db);
		ConfigureFixed(db, con, server, client_implementation, false);

		S3TestHelper::RequireQueryOk(con, "SET s3_uploader_max_filesize='5116GiB'");
		S3TestHelper::RequireQueryOk(con, "BEGIN TRANSACTION");
		auto object_limit_error = RequireError([&]() { OpenWriter(con, R2_PATH); });
		REQUIRE(StringUtil::Contains(object_limit_error, "maximum object size"));
		S3TestHelper::RequireQueryOk(con, "ROLLBACK");

		S3TestHelper::RequireQueryOk(con, "SET s3_uploader_max_filesize='5115GiB'");
		S3TestHelper::RequireQueryOk(con, "SET s3_uploader_max_parts_per_file=1023");
		S3TestHelper::RequireQueryOk(con, "BEGIN TRANSACTION");
		auto part_limit_error = RequireError([&]() { OpenWriter(con, R2_PATH); });
		REQUIRE(StringUtil::Contains(part_limit_error, "s3_uploader_max_parts_per_file"));
		S3TestHelper::RequireQueryOk(con, "ROLLBACK");
		REQUIRE(server.Observations().empty());
	}

	static void RunExactFileSizeLimit(const string &client_implementation) {
		MockS3ServerConfig config;
		config.object.bucket = S3TestHelper::BUCKET;
		config.object.key = S3TestHelper::OBJECT_KEY;
		config.auth.refresh_target = MockS3RefreshTarget::DELETE_OBJECT;
		MockS3Server server(std::move(config));

		DuckDB db(nullptr);
		Connection con(db);
		Configure(db, con, server, client_implementation);
		S3TestHelper::RequireQueryOk(con, "SET s3_uploader_max_filesize='1MiB'");

		auto payload = CreatePayload(1ULL * 1024ULL * 1024ULL);
		S3TestHelper::RequireQueryOk(con, "BEGIN TRANSACTION");
		auto handle = OpenWriter(con);
		handle->Write(QueryContext(*con.context), data_ptr_cast(payload.data()), payload.size());
		handle->Close();
		handle.reset();
		S3TestHelper::RequireQueryOk(con, "COMMIT");

		auto observations = server.Observations();
		INFO(MockS3DescribeObservations(observations));
		REQUIRE(server.UploadedObject() == payload);
		REQUIRE(Count(observations, "PUT") == 1);
		REQUIRE(Count(observations, "POST") == 0);
	}

	static void RunFileSizeLimitBeforeHTTP(const string &client_implementation) {
		MockS3ServerConfig config;
		config.object.bucket = S3TestHelper::BUCKET;
		config.object.key = S3TestHelper::OBJECT_KEY;
		config.auth.refresh_target = MockS3RefreshTarget::DELETE_OBJECT;
		MockS3Server server(std::move(config));

		DuckDB db(nullptr);
		Connection con(db);
		Configure(db, con, server, client_implementation);
		S3TestHelper::RequireQueryOk(con, "SET s3_uploader_max_filesize='1MiB'");

		auto payload = CreatePayload(1ULL * 1024ULL * 1024ULL + 1);
		S3TestHelper::RequireQueryOk(con, "BEGIN TRANSACTION");
		auto handle = OpenWriter(con);
		auto first_error = RequireError(
		    [&]() { handle->Write(QueryContext(*con.context), data_ptr_cast(payload.data()), payload.size()); });
		auto second_error = RequireError([&]() { handle->Close(); });
		REQUIRE(second_error == first_error);
		handle.reset();
		S3TestHelper::RequireQueryOk(con, "ROLLBACK");

		INFO(MockS3DescribeObservations(server.Observations()));
		REQUIRE(server.Observations().empty());
	}

	static void RunFileSizeLimitAfterMultipart(const string &client_implementation) {
		MockS3ServerConfig config;
		config.object.bucket = S3TestHelper::BUCKET;
		config.object.key = S3TestHelper::OBJECT_KEY;
		config.auth.refresh_target = MockS3RefreshTarget::HEAD;
		MockS3Server server(std::move(config));

		DuckDB db(nullptr);
		Connection con(db);
		Configure(db, con, server, client_implementation);
		S3TestHelper::RequireQueryOk(con, "SET s3_uploader_max_filesize='6MiB'");

		auto payload = CreatePayload(INITIAL_PART_SIZE + 1);
		auto excessive_tail = CreatePayload(1ULL * 1024ULL * 1024ULL);
		S3TestHelper::RequireQueryOk(con, "BEGIN TRANSACTION");
		auto handle = OpenWriter(con);
		handle->Write(QueryContext(*con.context), data_ptr_cast(payload.data()), INITIAL_PART_SIZE);
		handle->Write(QueryContext(*con.context), data_ptr_cast(payload.data()) + INITIAL_PART_SIZE, 1);
		auto first_error = RequireError([&]() {
			handle->Write(QueryContext(*con.context), data_ptr_cast(excessive_tail.data()), excessive_tail.size());
		});
		auto second_error = RequireError([&]() { handle->Close(); });
		REQUIRE(second_error == first_error);
		handle.reset();
		S3TestHelper::RequireQueryOk(con, "ROLLBACK");

		auto observations = server.Observations();
		INFO(MockS3DescribeObservations(observations));
		REQUIRE(Count(observations, "POST", "uploads") == 1);
		REQUIRE(Count(observations, "POST", "uploadId") == 0);
		REQUIRE(Count(observations, "PUT", "partNumber") == 1);
		REQUIRE(Count(observations, "DELETE", "uploadId") == 1);
	}

	static void RunStableSinglePutFailure(const string &client_implementation) {
		MockS3ServerConfig config;
		config.object.bucket = S3TestHelper::BUCKET;
		config.object.key = S3TestHelper::OBJECT_KEY;
		config.auth.refresh_target = MockS3RefreshTarget::DELETE_OBJECT;
		config.failures.transient_put_failures = 1000;
		config.failures.failure_is_request_timeout = false;
		MockS3Server server(std::move(config));

		DuckDB db(nullptr);
		Connection con(db);
		Configure(db, con, server, client_implementation);

		S3TestHelper::RequireQueryOk(con, "BEGIN TRANSACTION");
		auto handle = OpenWriter(con);
		string payload = "failed single PUT";
		handle->Write(QueryContext(*con.context), data_ptr_cast(payload.data()), payload.size());
		auto first_error = RequireError([&]() { handle->Sync(); });
		auto second_error = RequireError([&]() { handle->Close(); });
		REQUIRE(second_error == first_error);
		handle.reset();
		S3TestHelper::RequireQueryOk(con, "ROLLBACK");

		auto observations = server.Observations();
		INFO(MockS3DescribeObservations(observations));
		REQUIRE(Count(observations, "PUT") == 1);
		REQUIRE(Count(observations, "POST") == 0);
	}

	static void RunStableCompletionFailure(const string &client_implementation) {
		MockS3ServerConfig config;
		config.object.bucket = S3TestHelper::BUCKET;
		config.object.key = S3TestHelper::OBJECT_KEY;
		config.auth.refresh_target = MockS3RefreshTarget::HEAD;
		config.failures.completion_fault = {1000, 400, "RequestTimeout", "Injected completion timeout"};
		MockS3Server server(std::move(config));

		DuckDB db(nullptr);
		Connection con(db);
		Configure(db, con, server, client_implementation);

		S3TestHelper::RequireQueryOk(con, "BEGIN TRANSACTION");
		auto handle = OpenWriter(con);
		auto payload = CreateMultipartPayload();
		handle->Write(QueryContext(*con.context), data_ptr_cast(payload.data()), payload.size());
		auto first_error = RequireError([&]() { handle->Sync(); });
		auto second_error = RequireError([&]() { handle->Close(); });
		REQUIRE(second_error == first_error);
		handle.reset();
		S3TestHelper::RequireQueryOk(con, "ROLLBACK");

		auto observations = server.Observations();
		INFO(MockS3DescribeObservations(observations));
		REQUIRE(Count(observations, "POST", "uploads") == 1);
		REQUIRE(Count(observations, "POST", "uploadId") == 1);
		REQUIRE(Count(observations, "PUT", "partNumber") == 1);
		REQUIRE(Count(observations, "DELETE") == 1);
		REQUIRE(Count(observations, "DELETE", "uploadId") == 1);
	}

	static void RunStablePartFailure(const string &client_implementation) {
		MockS3ServerConfig config;
		config.object.bucket = S3TestHelper::BUCKET;
		config.object.key = S3TestHelper::OBJECT_KEY;
		config.auth.refresh_target = MockS3RefreshTarget::HEAD;
		config.failures.transient_put_failures = 1000;
		config.failures.failure_is_request_timeout = false;
		MockS3Server server(std::move(config));

		DuckDB db(nullptr);
		Connection con(db);
		Configure(db, con, server, client_implementation);

		S3TestHelper::RequireQueryOk(con, "BEGIN TRANSACTION");
		auto handle = OpenWriter(con);
		auto payload = CreateMultipartPayload();
		auto first_error = RequireError(
		    [&]() { handle->Write(QueryContext(*con.context), data_ptr_cast(payload.data()), payload.size()); });
		auto second_error = RequireError([&]() { handle->Close(); });
		REQUIRE(second_error == first_error);
		handle.reset();
		S3TestHelper::RequireQueryOk(con, "ROLLBACK");

		auto observations = server.Observations();
		INFO(MockS3DescribeObservations(observations));
		REQUIRE(Count(observations, "POST", "uploads") == 1);
		REQUIRE(Count(observations, "POST", "uploadId") == 0);
		REQUIRE(Count(observations, "PUT", "partNumber") == 1);
		REQUIRE(Count(observations, "DELETE") == 1);
		REQUIRE(Count(observations, "DELETE", "uploadId") == 1);
	}

	static void RunDuplicateOffsetFailure(const string &client_implementation) {
		MockS3ServerConfig config;
		config.object.bucket = S3TestHelper::BUCKET;
		config.object.key = S3TestHelper::OBJECT_KEY;
		config.auth.refresh_target = MockS3RefreshTarget::DELETE_OBJECT;
		MockS3Server server(std::move(config));

		DuckDB db(nullptr);
		Connection con(db);
		Configure(db, con, server, client_implementation);

		S3TestHelper::RequireQueryOk(con, "BEGIN TRANSACTION");
		auto handle = OpenWriter(con);
		string payload = "out of order";
		handle->Write(QueryContext(*con.context), data_ptr_cast(payload.data()), 1);
		auto first_error = RequireError(
		    [&]() { handle->Write(QueryContext(*con.context), data_ptr_cast(payload.data()), payload.size(), 0); });
		auto second_error = RequireError([&]() { handle->Close(); });
		REQUIRE(second_error == first_error);
		handle.reset();
		S3TestHelper::RequireQueryOk(con, "ROLLBACK");

		auto observations = server.Observations();
		INFO(MockS3DescribeObservations(observations));
		REQUIRE(Count(observations, "PUT") == 0);
		REQUIRE(Count(observations, "POST") == 0);
	}

	static void RunFixed(const string &client_implementation) {
		SECTION("native R2 fragmented writes have a short final part") {
			RunFixedFragmented(client_implementation);
		}
		SECTION("native R2 concurrent writes retain fixed geometry") {
			RunFixedConcurrentWrites(client_implementation);
		}
		SECTION("S3-routed R2 splits an oversized write into equal parts") {
			RunFixedOversized(client_implementation, true);
		}
		SECTION("fixed geometry mock rejects unequal non-final parts") {
			RunMockRejectsInvalidFixedGeometry(client_implementation, false);
		}
		SECTION("fixed geometry mock rejects a larger final part") {
			RunMockRejectsInvalidFixedGeometry(client_implementation, true);
		}
		SECTION("R2 configuration limits fail before HTTP") {
			RunFixedConfigRejectedBeforeHTTP(client_implementation);
		}
	}

	static void Run(const string &client_implementation) {
		SECTION("empty PUT") {
			RunEmpty(client_implementation);
		}
		SECTION("single PUT") {
			RunSinglePut(client_implementation);
		}
		SECTION("multipart upload") {
			RunMultipart(client_implementation);
		}
		SECTION("write below initial part size") {
			RunWholeWriteGeometry(client_implementation, INITIAL_PART_SIZE - 1);
		}
		SECTION("write at initial part size") {
			RunWholeWriteGeometry(client_implementation, INITIAL_PART_SIZE);
		}
		SECTION("write above initial part size") {
			RunWholeWriteGeometry(client_implementation, INITIAL_PART_SIZE + 1);
		}
		SECTION("write at twice the initial part size") {
			RunWholeWriteGeometry(client_implementation, 2 * INITIAL_PART_SIZE);
		}
		SECTION("full part lookbehind") {
			RunFullPartLookbehind(client_implementation);
		}
		SECTION("buffered prefix followed by a large write") {
			RunBufferedPrefix(client_implementation);
		}
		SECTION("fragmented multipart upload") {
			RunFragmentedMultipart(client_implementation);
		}
		SECTION("synchronous async writer multipart upload") {
			RunAsyncWriter(client_implementation, 0);
		}
		SECTION("single-worker async writer multipart upload") {
			RunAsyncWriter(client_implementation, 1);
		}
		SECTION("multi-worker async writer multipart upload") {
			RunAsyncWriter(client_implementation, 2);
		}
		SECTION("multi-worker async writer overlaps ordered parts") {
			RunConcurrentAsyncWriter(client_implementation);
		}
		SECTION("later offsets wait for ordered admission") {
			RunLaterOffsetFirst(client_implementation);
		}
		SECTION("part failures wait for active requests before abort") {
			RunConcurrentPartFailure(client_implementation);
		}
		SECTION("adaptive part sizes") {
			RunAdaptivePartSizes(client_implementation);
		}
		SECTION("exact file size limit") {
			RunExactFileSizeLimit(client_implementation);
		}
		SECTION("file size limit before HTTP") {
			RunFileSizeLimitBeforeHTTP(client_implementation);
		}
		SECTION("file size limit after multipart initialization") {
			RunFileSizeLimitAfterMultipart(client_implementation);
		}
		SECTION("stable single PUT failure") {
			RunStableSinglePutFailure(client_implementation);
		}
		SECTION("stable completion failure") {
			RunStableCompletionFailure(client_implementation);
		}
		SECTION("stable part failure") {
			RunStablePartFailure(client_implementation);
		}
		SECTION("duplicate offset failure") {
			RunDuplicateOffsetFailure(client_implementation);
		}
	}

public:
	static constexpr idx_t INITIAL_PART_SIZE = 5ULL * 1024ULL * 1024ULL;
	static constexpr idx_t FIXED_PART_SIZE = 8ULL * 1024ULL * 1024ULL;
	static constexpr const char *R2_PATH = "r2://refresh-bucket/object.bin";
};

} // namespace

TEST_CASE("S3 upload request geometry", "[httpfs][s3][upload]") {
	SECTION("curl") {
		S3UploadTest::Run("curl");
	}
	SECTION("httplib") {
		S3UploadTest::Run("httplib");
	}
}

TEST_CASE("R2 upload request geometry", "[httpfs][s3][upload][r2]") {
	SECTION("curl") {
		S3UploadTest::RunFixed("curl");
	}
	SECTION("httplib") {
		S3UploadTest::RunFixed("httplib");
	}
}

TEST_CASE("S3 upload policy is stable across credential refresh", "[httpfs][s3][upload][refresh]") {
	for (const auto &client_implementation : {"curl", "httplib"}) {
		DYNAMIC_SECTION(client_implementation << " rejects adaptive-to-fixed refresh") {
			S3UploadTest::RunUploadPolicyRefreshRejected(client_implementation, false);
		}
		DYNAMIC_SECTION(client_implementation << " rejects fixed-to-adaptive refresh") {
			S3UploadTest::RunUploadPolicyRefreshRejected(client_implementation, true);
		}
	}
}

TEST_CASE("GCS billing projects are sent on single and multipart uploads",
          "[httpfs][s3][gcs][upload][requester-pays]") {
	for (const string client_implementation : {"httplib", "curl"}) {
		DYNAMIC_SECTION(client_implementation << " single PUT") {
			S3UploadTest::RunGCSRequesterPaysUpload(client_implementation, false);
		}
		DYNAMIC_SECTION(client_implementation << " multipart upload") {
			S3UploadTest::RunGCSRequesterPaysUpload(client_implementation, true);
		}
	}
}

TEST_CASE("GCS multipart uploads publish refreshed billing projects",
          "[httpfs][s3][gcs][upload][refresh][requester-pays]") {
	for (const string client_implementation : {"httplib", "curl"}) {
		DYNAMIC_SECTION(client_implementation) {
			S3UploadTest::RunGCSRequesterPaysRefresh(client_implementation);
		}
	}
}

TEST_CASE("S3 upload defaults use DuckDB scheduling", "[httpfs][s3][upload]") {
	DuckDB db(nullptr);
	S3TestHelper::LoadExtension(db);
	Connection con(db);
	auto thread_setting = con.Query("SELECT count(*) FROM duckdb_settings() WHERE name = 's3_uploader_thread_limit'");
	REQUIRE(thread_setting);
	REQUIRE_FALSE(thread_setting->HasError());
	REQUIRE(thread_setting->GetValue(0, 0).GetValue<int64_t>() == 0);

	auto max_filesize = con.Query("SELECT value FROM duckdb_settings() WHERE name = 's3_uploader_max_filesize'");
	REQUIRE(max_filesize);
	REQUIRE_FALSE(max_filesize->HasError());
	REQUIRE(max_filesize->GetValue(0, 0).ToString() == "80GB");
}

} // namespace duckdb
