// FILE_FLAGS_EXCLUSIVE_CREATE and FILE_FLAGS_NULL_IF_EXISTS on S3: an existing object is never overwritten, of
// several writers of one key only one publishes, and a writer whose conditional request is sent again after its
// answer was lost does not take its own object for another writer's.
#include "catch.hpp"

#include "s3/mock_s3_server.hpp"
#include "s3/s3_test_helper.hpp"

#include "duckdb.hpp"
#include "duckdb/common/file_system.hpp"
#include "duckdb/common/mutex.hpp"
#include "duckdb/common/string_util.hpp"

#include <cerrno>
#include <functional>
#include <thread>

namespace duckdb {

namespace {

static constexpr const char *TOKEN_HEADER = "x-amz-meta-duckdb-exclusive-create";

//! The shared mock S3 server with its conditional store (MockS3ConditionalConfig) for bucket/key.json, and the views
//! of it that these tests use
class ConditionalS3Server {
public:
	struct Request {
		string method;
		string target;
		string if_none_match;
		string token;
		int status = 0;
	};

	ConditionalS3Server() : server(Config()) {
	}

	string Endpoint() const {
		return server.Endpoint();
	}

	//! Change the store and its faults while the server runs
	void Update(const std::function<void(MockS3ConditionalState &)> &update) {
		server.UpdateConditional(update);
	}

	void SetObject(string body, string token = string()) {
		Update([&](MockS3ConditionalState &state) {
			state.exists = true;
			state.body = std::move(body);
			state.metadata.clear();
			if (!token.empty()) {
				state.metadata[TOKEN_HEADER] = token;
			}
		});
	}

	bool Exists() const {
		return server.ConditionalState().exists;
	}

	string Body() const {
		return server.ConditionalState().body;
	}

	idx_t OpenUploads() const {
		return server.OpenConditionalUploads();
	}

	vector<Request> Requests() const {
		vector<Request> result;
		for (auto &observation : server.Observations()) {
			auto if_none_match = MockS3HeaderValues(observation, "If-None-Match");
			auto token = MockS3HeaderValues(observation, TOKEN_HEADER);
			result.push_back({observation.method, observation.target, if_none_match.empty() ? "" : if_none_match[0],
			                  token.empty() ? "" : token[0], observation.status});
		}
		return result;
	}

	idx_t Count(const string &method, const string &target_contains = string(), int status = 0) const {
		idx_t result = 0;
		for (auto &request : Requests()) {
			if (request.method == method && request.target.find(target_contains) != string::npos &&
			    (status == 0 || request.status == status)) {
				result++;
			}
		}
		return result;
	}

private:
	static MockS3ServerConfig Config() {
		MockS3ServerConfig config;
		config.object.bucket = "bucket";
		config.object.key = "key.json";
		config.conditional.enabled = true;
		return config;
	}

	MockS3Server server;
};

static constexpr const char *PATH = "s3://bucket/key.json";

// Functions, not constants: FileFlags' constants live in another translation unit
static FileOpenFlags Exclusive() {
	return FileFlags::FILE_FLAGS_WRITE | FileFlags::FILE_FLAGS_FILE_CREATE | FileFlags::FILE_FLAGS_EXCLUSIVE_CREATE;
}
static FileOpenFlags NullIfExists() {
	return Exclusive() | FileFlags::FILE_FLAGS_NULL_IF_EXISTS;
}

struct ExclusiveCreateTest {
	explicit ExclusiveCreateTest(ConditionalS3Server &server, idx_t http_retries = 0) : db(nullptr), con(db) {
		S3TestHelper::LoadExtension(db);
		S3TestHelper::RequireQueryOk(con, "SET httpfs_connection_caching=false");
		S3TestHelper::RequireQueryOk(con, "SET httpfs_enable_credential_refresh=false");
		S3TestHelper::RequireQueryOk(con, StringUtil::Format("SET http_retries=%llu", http_retries));
		S3TestHelper::RequireQueryOk(con, "SET http_retry_wait_ms=1");
		S3TestHelper::RequireQueryOk(con, "SET s3_uploader_max_filesize='50GB'");
		S3TestHelper::RequireQueryOk(con, StringUtil::Format(R"(
CREATE SECRET exclusive (
	TYPE S3,
	KEY_ID 'KEY',
	SECRET 'SECRET',
	REGION 'us-east-1',
	ENDPOINT '%s',
	USE_SSL false,
	URL_STYLE 'path'
))",
		                                                     server.Endpoint()));
		S3TestHelper::RequireQueryOk(con, "BEGIN TRANSACTION");
	}

	~ExclusiveCreateTest() {
		con.Query("ROLLBACK");
	}

	unique_ptr<FileHandle> Open(FileOpenFlags flags) {
		return FileSystem::GetFileSystem(*con.context).OpenFile(PATH, flags);
	}

	static void Write(FileHandle &handle, const string &content) {
		handle.Write((void *)content.data(), content.size());
		handle.Close();
	}

	static string Multipart(char c) {
		return string(12ULL * 1024ULL * 1024ULL + 1, c);
	}

	DuckDB db;
	Connection con;
};

template <class CALLBACK>
static string RequireError(CALLBACK callback) {
	try {
		callback();
	} catch (std::exception &ex) {
		return ErrorData(ex).RawMessage();
	}
	FAIL("Expected an error");
	return string();
}

} // namespace

TEST_CASE("S3 exclusive create of a missing object", "[httpfs][s3][exclusive-create]") {
	for (auto multipart : {false, true}) {
		INFO("multipart=" << multipart);
		ConditionalS3Server server;
		ExclusiveCreateTest test(server);
		auto handle = test.Open(NullIfExists());
		REQUIRE(handle);
		auto content = multipart ? ExclusiveCreateTest::Multipart('a') : string("first");
		ExclusiveCreateTest::Write(*handle, content);
		REQUIRE(server.Body() == content);
		// The request that publishes is conditional, and the object carries a token
		for (auto &request : server.Requests()) {
			auto publishes = (request.method == "PUT" && request.target.find("partNumber") == string::npos) ||
			                 (request.method == "POST" && request.target.find("uploadId") != string::npos);
			INFO(request.method << " " << request.target);
			REQUIRE((request.if_none_match == "*") == publishes);
		}
		REQUIRE(server.Count("HEAD") == 1);
	}
}

TEST_CASE("S3 exclusive create of an existing object", "[httpfs][s3][exclusive-create]") {
	ConditionalS3Server server;
	server.SetObject("first");
	ExclusiveCreateTest test(server);
	REQUIRE_FALSE(test.Open(NullIfExists()));
	auto message = RequireError([&]() { test.Open(Exclusive()); });
	REQUIRE(message == "Unable to open URL \"s3://bucket/key.json\" for exclusive create: it already exists");
	REQUIRE(server.Body() == "first");
	REQUIRE(server.Count("PUT") == 0);

	// Not exclusive: overwritten, unconditionally, as before
	auto handle = test.Open(FileFlags::FILE_FLAGS_WRITE | FileFlags::FILE_FLAGS_FILE_CREATE_NEW);
	ExclusiveCreateTest::Write(*handle, "second");
	REQUIRE(server.Body() == "second");
	auto requests = server.Requests();
	REQUIRE(requests.back().method == "PUT");
	REQUIRE(requests.back().if_none_match.empty());
	REQUIRE(requests.back().token.empty());
}

TEST_CASE("S3 exclusive creators of one key: the first to publish wins", "[httpfs][s3][exclusive-create]") {
	for (auto multipart : {false, true}) {
		INFO("multipart=" << multipart);
		ConditionalS3Server server;
		ExclusiveCreateTest test(server);
		// All open before any publishes: each one's HEAD finds no object
		vector<unique_ptr<FileHandle>> handles;
		for (idx_t i = 0; i < 3; i++) {
			handles.push_back(test.Open(NullIfExists()));
			REQUIRE(handles.back());
		}
		auto content = [&](idx_t i) {
			return multipart ? ExclusiveCreateTest::Multipart(char('a' + i)) : "writer-" + to_string(i);
		};
		ExclusiveCreateTest::Write(*handles[1], content(1));
		for (auto i : {0, 2}) {
			auto message = RequireError([&]() { ExclusiveCreateTest::Write(*handles[i], content(i)); });
			REQUIRE(StringUtil::Contains(message, "for exclusive create: it already exists"));
		}
		REQUIRE(server.Body() == content(1));
		// The losers' multipart uploads are aborted
		REQUIRE(server.OpenUploads() == 0);
	}
}

TEST_CASE("S3 exclusive creators of one key at once: one wins", "[httpfs][s3][exclusive-create]") {
	ConditionalS3Server server;
	ExclusiveCreateTest test(server);
	const idx_t n = 8;
	vector<unique_ptr<Connection>> cons;
	for (idx_t i = 0; i < n; i++) {
		cons.push_back(make_uniq<Connection>(test.db));
		S3TestHelper::RequireQueryOk(*cons.back(), "SET http_retries=0");
	}
	std::atomic<idx_t> winners {0};
	std::atomic<idx_t> losers {0};
	vector<std::thread> threads;
	for (idx_t i = 0; i < n; i++) {
		threads.emplace_back([&, i]() {
			try {
				cons[i]->context->RunFunctionInTransaction([&]() {
					auto handle = FileSystem::GetFileSystem(*cons[i]->context).OpenFile(PATH, NullIfExists());
					if (!handle) {
						losers++;
						return;
					}
					ExclusiveCreateTest::Write(*handle, "writer-" + to_string(i));
					winners++;
				});
			} catch (std::exception &ex) {
				if (StringUtil::Contains(ErrorData(ex).RawMessage(), "it already exists")) {
					losers++;
				}
			}
		});
	}
	for (auto &thread : threads) {
		thread.join();
	}
	REQUIRE(winners == 1);
	REQUIRE(losers == n - 1);
	REQUIRE(StringUtil::StartsWith(server.Body(), "writer-"));
}

TEST_CASE("S3 exclusive create whose PUT answer was lost", "[httpfs][s3][exclusive-create]") {
	// The PUT goes through, its answer is lost, and core sends it again: the retry is refused (412), and the token
	// shows that the object is this writer's
	ConditionalS3Server server;
	server.Update([&](MockS3ConditionalState &state) { state.drop_put_answers = 1; });
	ExclusiveCreateTest test(server, 2);
	auto handle = test.Open(NullIfExists());
	REQUIRE(handle);
	ExclusiveCreateTest::Write(*handle, "first");
	REQUIRE(server.Body() == "first");
	REQUIRE(server.Count("PUT", "", 412) == 1);
	REQUIRE(server.Count("HEAD") == 2);

	// Another writer's object, found the same way, is not taken for this writer's
	ConditionalS3Server other;
	ExclusiveCreateTest other_test(other);
	auto other_handle = other_test.Open(NullIfExists());
	other.SetObject("theirs", "another-token");
	auto message = RequireError([&]() { ExclusiveCreateTest::Write(*other_handle, "mine"); });
	REQUIRE(StringUtil::Contains(message, "for exclusive create: it already exists"));
	REQUIRE(other.Body() == "theirs");
}

TEST_CASE("S3 exclusive create errors carry errno EEXIST", "[httpfs][s3][exclusive-create]") {
	ConditionalS3Server server;
	ExclusiveCreateTest test(server);
	auto handle = test.Open(NullIfExists());
	server.SetObject("theirs", "another-token");
	for (auto at_open : {true, false}) {
		try {
			if (at_open) {
				test.Open(Exclusive());
			} else {
				ExclusiveCreateTest::Write(*handle, "mine");
			}
			FAIL("Expected an error");
		} catch (std::exception &ex) {
			ErrorData error(ex);
			REQUIRE(error.Type() == ExceptionType::IO);
			REQUIRE(error.ExtraInfo().at("errno") == std::to_string(EEXIST));
		}
	}
}

TEST_CASE("S3 exclusive create when the check after a refusal fails", "[httpfs][s3][exclusive-create]") {
	// A refused publish (412) is checked with a HEAD. If the HEAD fails, whether the object is this writer's is
	// unknown: an error, never a success over another writer's object and never "exists" over our own.
	for (auto head_status : {403, 503}) {
		INFO("HEAD status " << head_status);
		ConditionalS3Server server;
		ExclusiveCreateTest test(server);
		auto handle = test.Open(NullIfExists());
		REQUIRE(handle);
		server.SetObject("theirs", "another-token");
		server.Update([&](MockS3ConditionalState &state) { state.head_statuses = {head_status}; });
		auto message = RequireError([&]() { ExclusiveCreateTest::Write(*handle, "mine"); });
		REQUIRE(StringUtil::Contains(message, "could not be checked"));
		REQUIRE(server.Body() == "theirs");
	}
	// The object is gone by the time of the check: the refusal is reported as it came
	ConditionalS3Server server;
	ExclusiveCreateTest test(server);
	auto handle = test.Open(NullIfExists());
	server.SetObject("theirs", "another-token");
	server.Update([&](MockS3ConditionalState &state) { state.head_statuses = {404}; });
	auto message = RequireError([&]() { ExclusiveCreateTest::Write(*handle, "mine"); });
	REQUIRE(StringUtil::Contains(message, "412"));
	REQUIRE_FALSE(StringUtil::Contains(message, "it already exists"));
}

TEST_CASE("S3 exclusive create when the HEAD at open fails", "[httpfs][s3][exclusive-create]") {
	// Any failure fails the open, before anything is written. A 403 (no s3:ListBucket for a missing key, or no read
	// access) says what an exclusive create needs.
	for (auto head_status : {403, 400}) {
		INFO("HEAD status " << head_status);
		ConditionalS3Server server;
		server.Update([&](MockS3ConditionalState &state) { state.head_statuses = {head_status}; });
		ExclusiveCreateTest test(server);
		auto message = RequireError([&]() { test.Open(NullIfExists()); });
		REQUIRE(StringUtil::Contains(message, to_string(head_status)));
		REQUIRE(StringUtil::Contains(message, "s3:GetObject") == (head_status == 403));
		REQUIRE(StringUtil::Contains(message, "s3:ListBucket") == (head_status == 403));
		REQUIRE(server.Count("PUT") == 0);
	}
}

TEST_CASE("S3 exclusive create answered 409 ConditionalRequestConflict", "[httpfs][s3][exclusive-create]") {
	// Another writer's object: "already exists"
	for (auto multipart : {false, true}) {
		INFO("multipart=" << multipart);
		ConditionalS3Server server;
		ExclusiveCreateTest test(server);
		auto handle = test.Open(NullIfExists());
		server.SetObject("theirs", "another-token");
		server.Update([&](MockS3ConditionalState &state) { state.conflict_answers = 1; });
		auto content = multipart ? ExclusiveCreateTest::Multipart('c') : string("mine");
		auto message = RequireError([&]() { ExclusiveCreateTest::Write(*handle, content); });
		REQUIRE(StringUtil::Contains(message, "for exclusive create: it already exists"));
		REQUIRE(server.Body() == "theirs");
	}
	// No object yet: the conflict is sent again, within the configured retries (none: the 409 is the error)
	for (idx_t retries : {0, 1}) {
		INFO("http_retries=" << retries);
		ConditionalS3Server server;
		ExclusiveCreateTest test(server, retries);
		auto handle = test.Open(NullIfExists());
		server.Update([&](MockS3ConditionalState &state) { state.conflict_answers = 1; });
		if (retries == 0) {
			auto message = RequireError([&]() { ExclusiveCreateTest::Write(*handle, "mine"); });
			REQUIRE(StringUtil::Contains(message, "409"));
			REQUIRE_FALSE(server.Exists());
		} else {
			ExclusiveCreateTest::Write(*handle, "mine");
			REQUIRE(server.Body() == "mine");
		}
		REQUIRE(server.Count("PUT", "", 409) == 1);
		REQUIRE(server.Count("PUT", "", 200) == retries);
	}
	// More conflicts than retries: the 409 is the error
	{
		ConditionalS3Server server;
		ExclusiveCreateTest test(server, 1);
		auto handle = test.Open(NullIfExists());
		server.Update([&](MockS3ConditionalState &state) { state.conflict_answers = 5; });
		auto message = RequireError([&]() { ExclusiveCreateTest::Write(*handle, "mine"); });
		REQUIRE(StringUtil::Contains(message, "409"));
		REQUIRE(server.Count("PUT", "", 409) == 2);
		REQUIRE_FALSE(server.Exists());
	}
}

TEST_CASE("S3 exclusive create whose resent PUT finds another writer's object", "[httpfs][s3][exclusive-create]") {
	// The first PUT goes through and its answer is lost; before it is resent, a writer without EXCLUSIVE_CREATE
	// replaces the object. The token is not ours: "exists", not success.
	ConditionalS3Server server;
	server.Update([&](MockS3ConditionalState &state) { state.drop_put_answers = 1; });
	server.Update([&](MockS3ConditionalState &state) { state.overwrite_after_drop = true; });
	ExclusiveCreateTest test(server, 2);
	auto handle = test.Open(NullIfExists());
	REQUIRE(handle);
	auto message = RequireError([&]() { ExclusiveCreateTest::Write(*handle, "mine"); });
	REQUIRE(StringUtil::Contains(message, "for exclusive create: it already exists"));
	REQUIRE(server.Count("PUT", "", 412) == 1);
}

TEST_CASE("S3 exclusive create whose publish went through but every answer failed", "[httpfs][s3][exclusive-create]") {
	// The publish stores the object, and it and every resend get 500: the token shows the object is this writer's
	for (auto multipart : {false, true}) {
		INFO("multipart=" << multipart);
		ConditionalS3Server server;
		server.Update([&](MockS3ConditionalState &state) { state.publish_500_answers = 100; });
		ExclusiveCreateTest test(server, 2);
		auto handle = test.Open(NullIfExists());
		REQUIRE(handle);
		auto content = multipart ? ExclusiveCreateTest::Multipart('f') : string("first");
		ExclusiveCreateTest::Write(*handle, content);
		REQUIRE(server.Body() == content);
		REQUIRE(server.Count(multipart ? "POST" : "PUT", multipart ? "uploadId" : "", 500) == 3);
		REQUIRE(server.Count("DELETE") == 0);
	}
	// Another writer's object behind the 500s: the original error, not success
	ConditionalS3Server server;
	server.Update([&](MockS3ConditionalState &state) { state.publish_500_answers = 100; });
	ExclusiveCreateTest test(server, 2);
	auto handle = test.Open(NullIfExists());
	server.SetObject("theirs", "another-token");
	auto message = RequireError([&]() { ExclusiveCreateTest::Write(*handle, "mine"); });
	REQUIRE(StringUtil::Contains(message, "500"));
	REQUIRE(server.Body() == "theirs");
}

TEST_CASE("S3 exclusive multipart create: NoSuchUpload after a lost completion, unreadable check",
          "[httpfs][s3][exclusive-create]") {
	// The completion publishes and answers 500; the resend gets NoSuchUpload; the token HEAD gets 403. Whether the
	// object is this writer's is unknown: an unknown-outcome error, and the upload is not aborted
	ConditionalS3Server server;
	server.Update([&](MockS3ConditionalState &state) { state.fail_completion_answers = 1; });
	server.Update([&](MockS3ConditionalState &state) { state.head_statuses = {0, 403}; });
	ExclusiveCreateTest test(server, 2);
	auto handle = test.Open(NullIfExists());
	REQUIRE(handle);
	auto message = RequireError([&]() { ExclusiveCreateTest::Write(*handle, ExclusiveCreateTest::Multipart('n')); });
	REQUIRE(StringUtil::Contains(message, "unknown outcome"));
	REQUIRE(server.Count("POST", "uploadId", 404) == 1);
	REQUIRE(server.Count("DELETE") == 0);
}

TEST_CASE("S3 exclusive create errors do not show URL credentials", "[httpfs][s3][exclusive-create]") {
	ConditionalS3Server server;
	server.SetObject("theirs", "another-token");
	ExclusiveCreateTest test(server);
	S3TestHelper::RequireQueryOk(test.con, "SET s3_enable_deprecated_url_parameters=true");
	auto path = string(PATH) + "?s3_access_key_id=KEY&s3_secret_access_key=VERY_SECRET_VALUE";
	auto message = RequireError([&]() { FileSystem::GetFileSystem(*test.con.context).OpenFile(path, Exclusive()); });
	REQUIRE(StringUtil::Contains(message, "for exclusive create: it already exists"));
	REQUIRE_FALSE(StringUtil::Contains(message, "VERY_SECRET_VALUE"));
}

TEST_CASE("GCS exclusive create: checked at open, written without a condition", "[httpfs][s3][exclusive-create][gcs]") {
	for (auto bearer : {false, true}) {
		for (auto multipart : {false, true}) {
			INFO("bearer=" << bearer << " multipart=" << multipart);
			ConditionalS3Server server;
			ExclusiveCreateTest test(server);
			S3TestHelper::RequireQueryOk(test.con, "SET enable_logging=true");
			S3TestHelper::RequireQueryOk(
			    test.con,
			    StringUtil::Format("CREATE SECRET gcs_exclusive (TYPE GCS, %s, ENDPOINT '%s', USE_SSL false, "
			                       "URL_STYLE 'path')",
			                       bearer ? "BEARER_TOKEN 'gcs-token'" : "KEY_ID 'GCS_KEY', SECRET 'GCS_SECRET'",
			                       server.Endpoint()));
			auto &fs = FileSystem::GetFileSystem(*test.con.context);
			const string path = "gcs://bucket/key.json";
			auto content = multipart ? ExclusiveCreateTest::Multipart('g') : string("first");

			// Missing: written without a condition or token, and one warning
			auto handle = fs.OpenFile(path, NullIfExists());
			REQUIRE(handle);
			ExclusiveCreateTest::Write(*handle, content);
			REQUIRE(server.Body() == content);
			for (auto &request : server.Requests()) {
				INFO(request.method << " " << request.target);
				REQUIRE(request.if_none_match.empty());
				REQUIRE(request.token.empty());
			}
			// Existing: nullptr, or an error, from the check at open; nothing written, no further warning
			REQUIRE_FALSE(fs.OpenFile(path, NullIfExists()));
			auto message = RequireError([&]() { fs.OpenFile(path, Exclusive()); });
			REQUIRE(StringUtil::Contains(message, "for exclusive create: it already exists"));
			REQUIRE(server.Body() == content);
			auto warnings = test.con.Query("SELECT count(*) FROM duckdb_logs WHERE log_level = 'WARNING' AND message "
			                               "LIKE '%on GCS%without a condition%'");
			REQUIRE_FALSE(warnings->HasError());
			REQUIRE(warnings->Collection().GetValue(0, 0).GetValue<idx_t>() == 1);
		}
	}
}

TEST_CASE("S3 exclusive create: a final 400, 403 or 429 after a publish that went through",
          "[httpfs][s3][exclusive-create]") {
	// The first attempt publishes and answers 500; core sends it again, and the last answer is something else. The
	// token shows that the object is this writer's.
	struct Case {
		int status;
		const char *code;
	};
	for (auto final_answer : {Case {403, "AccessDenied"}, Case {400, "InvalidRequest"}, Case {429, "SlowDown"}}) {
		for (auto multipart : {false, true}) {
			INFO("final " << final_answer.status << " multipart=" << multipart);
			ConditionalS3Server server;
			server.Update([&](MockS3ConditionalState &state) {
				state.publish_script = {{true, 500, "InternalError"},
				                        {false, final_answer.status, final_answer.code},
				                        {false, final_answer.status, final_answer.code},
				                        {false, final_answer.status, final_answer.code}};
			});
			ExclusiveCreateTest test(server, 1);
			S3TestHelper::RequireQueryOk(test.con, "SET http_retry_backoff=1");
			auto handle = test.Open(NullIfExists());
			REQUIRE(handle);
			auto content = multipart ? ExclusiveCreateTest::Multipart('r') : string("first");
			ExclusiveCreateTest::Write(*handle, content);
			REQUIRE(server.Body() == content);
			REQUIRE(server.Count("DELETE") == 0);
		}
	}
}

TEST_CASE("S3 exclusive multipart create: error documents behind HTTP 200", "[httpfs][s3][exclusive-create]") {
	// PreconditionFailed and ConditionalRequestConflict behind 200, with another writer's object: "already exists"
	for (auto code : {"PreconditionFailed", "ConditionalRequestConflict"}) {
		INFO(code);
		ConditionalS3Server server;
		ExclusiveCreateTest test(server);
		auto handle = test.Open(NullIfExists());
		server.SetObject("theirs", "another-token");
		server.Update([&](MockS3ConditionalState &state) { state.publish_script = {{false, 200, code}}; });
		auto message =
		    RequireError([&]() { ExclusiveCreateTest::Write(*handle, ExclusiveCreateTest::Multipart('e')); });
		REQUIRE(StringUtil::Contains(message, "for exclusive create: it already exists"));
		REQUIRE(server.Body() == "theirs");
	}
	// Another error document, after the completion went through: this writer's object
	ConditionalS3Server server;
	server.Update([&](MockS3ConditionalState &state) { state.publish_script = {{true, 200, "InternalError"}}; });
	ExclusiveCreateTest test(server);
	auto handle = test.Open(NullIfExists());
	auto content = ExclusiveCreateTest::Multipart('i');
	ExclusiveCreateTest::Write(*handle, content);
	REQUIRE(server.Body() == content);
}

TEST_CASE("S3 exclusive multipart create whose completion connection drops", "[httpfs][s3][exclusive-create]") {
	// CompleteMultipartUpload is not sent again after a transport loss; the token shows whether it published
	for (auto published : {true, false}) {
		INFO("published=" << published);
		ConditionalS3Server server;
		server.Update([&](MockS3ConditionalState &state) { state.publish_script = {{published, -1, ""}}; });
		ExclusiveCreateTest test(server);
		auto handle = test.Open(NullIfExists());
		auto content = ExclusiveCreateTest::Multipart('d');
		if (published) {
			ExclusiveCreateTest::Write(*handle, content);
			REQUIRE(server.Body() == content);
		} else {
			auto message = RequireError([&]() { ExclusiveCreateTest::Write(*handle, content); });
			REQUIRE(StringUtil::Contains(message, "unknown outcome"));
			REQUIRE_FALSE(server.Exists());
		}
	}
}

TEST_CASE("S3 exclusive multipart create: a 412 with an unreadable check aborts the upload",
          "[httpfs][s3][exclusive-create]") {
	// The server answered that this completion did not publish, so the upload is aborted; whose object is there is
	// unknown
	ConditionalS3Server server;
	ExclusiveCreateTest test(server);
	auto handle = test.Open(NullIfExists());
	server.SetObject("theirs", "another-token");
	server.Update([&](MockS3ConditionalState &state) { state.head_statuses = {503, 503, 503}; });
	auto message = RequireError([&]() { ExclusiveCreateTest::Write(*handle, ExclusiveCreateTest::Multipart('a')); });
	REQUIRE(StringUtil::Contains(message, "unknown outcome"));
	REQUIRE(server.Count("DELETE") == 1);
	REQUIRE(server.OpenUploads() == 0);
	REQUIRE(server.Body() == "theirs");
}

TEST_CASE("S3 exclusive multipart create whose completion answer was lost", "[httpfs][s3][exclusive-create]") {
	// CompleteMultipartUpload publishes but answers 500, and is sent again: the retry finds the upload gone (or the
	// key taken), and the token shows that the object is this writer's
	ConditionalS3Server server;
	server.Update([&](MockS3ConditionalState &state) { state.fail_completion_answers = 1; });
	ExclusiveCreateTest test(server, 2);
	auto handle = test.Open(NullIfExists());
	REQUIRE(handle);
	auto content = ExclusiveCreateTest::Multipart('m');
	ExclusiveCreateTest::Write(*handle, content);
	REQUIRE(server.Body() == content);
	REQUIRE(server.Count("POST", "uploadId", 500) == 1);
	REQUIRE(server.Count("DELETE") == 0);
}

} // namespace duckdb
