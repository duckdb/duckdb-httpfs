#include "catch.hpp"

#include "s3/mock_s3_server.hpp"
#include "s3/s3_test_helper.hpp"

#include "create_secret_functions.hpp"

#include "duckdb.hpp"
#include "duckdb/common/exception.hpp"
#include "duckdb/common/file_system.hpp"
#include "duckdb/common/json_document.hpp"
#include "duckdb/common/map.hpp"
#include "duckdb/common/mutex.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/main/client_context.hpp"
#include "duckdb/main/extension/extension_loader.hpp"

#define CPPHTTPLIB_OPENSSL_SUPPORT
#include "httplib.hpp"

#include <atomic>
#include <thread>

namespace httplib = duckdb_httplib_openssl;

namespace duckdb {

namespace {

constexpr const char *SIGNED_KEY_ID = "SIGNED_KEY";
constexpr const char *VALID_TOKEN = "valid-token";
constexpr const char *EMPTY_PAYLOAD_HASH = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

struct MockSignRequest {
	int status = 0;
	string authorization;
	string region;
	string uri;
	string method;
	map<string, string> headers;
	map<string, string> properties;
	bool has_body = false;
	string body;

	//! The path and query of the signed URI, which is what the mock S3 server records as a request's target
	string Target() const {
		auto scheme_end = uri.find("://");
		auto path_start = uri.find('/', scheme_end == string::npos ? 0 : scheme_end + 3);
		return path_start == string::npos ? "/" : uri.substr(path_start);
	}

	string Header(const string &name) const {
		for (auto &header : headers) {
			if (StringUtil::CIEquals(header.first, name)) {
				return header.second;
			}
		}
		return string();
	}

	bool HasHeader(const string &name) const {
		for (auto &header : headers) {
			if (StringUtil::CIEquals(header.first, name)) {
				return true;
			}
		}
		return false;
	}
};

//! A signing endpoint that accepts one bearer token and signs with a recognizable key ID
class MockRemoteSigner {
public:
	explicit MockRemoteSigner(string cache_control_p = "private") : cache_control(std::move(cache_control_p)) {
		accepted_token = VALID_TOKEN;
		server.Post("/v1/sign",
		            [this](const httplib::Request &request, httplib::Response &response) { Sign(request, response); });
		port = server.bind_to_any_port("127.0.0.1");
		if (port <= 0) {
			throw IOException("Failed to bind mock remote signer");
		}
		server_thread = std::thread([this]() { server.listen_after_bind(); });
		server.wait_until_ready();
	}

	~MockRemoteSigner() {
		server.stop();
		if (server_thread.joinable()) {
			server_thread.join();
		}
	}

public:
	string URL() const {
		return StringUtil::Format("http://127.0.0.1:%d/v1/sign", port);
	}

	void AcceptToken(const string &token) {
		annotated_lock_guard<annotated_mutex> guard(lock);
		accepted_token = token;
	}

	//! Answer the next signing requests with a transient error before signing again
	void FailNext(idx_t count, int status) {
		annotated_lock_guard<annotated_mutex> guard(lock);
		failures_left = count;
		failure_status = status;
	}

	vector<MockSignRequest> Requests() const {
		annotated_lock_guard<annotated_mutex> guard(lock);
		return requests;
	}

private:
	void Sign(const httplib::Request &request, httplib::Response &response) {
		auto sign_request = ParseRequest(request);
		annotated_lock_guard<annotated_mutex> guard(lock);
		if (failures_left > 0) {
			failures_left--;
			sign_request.status = failure_status;
			requests.push_back(std::move(sign_request));
			response.status = failure_status;
			response.set_content(R"({"error": {"message": "try again", "code": 503}})", "application/json");
			return;
		}
		if (sign_request.authorization != "Bearer " + accepted_token) {
			sign_request.status = 401;
			requests.push_back(std::move(sign_request));
			response.status = 401;
			response.set_content(R"({"error": {"message": "expired token", "code": 401}})", "application/json");
			return;
		}
		sign_request.status = 200;

		JSONWriter writer;
		auto root = writer.CreateObject();
		root.AddString("uri", sign_request.uri);
		auto headers = writer.CreateObject();
		AddHeader(writer, headers, "Authorization",
		          StringUtil::Format("AWS4-HMAC-SHA256 Credential=%s/20260101/%s/s3/aws4_request, "
		                             "SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=0123456789abcdef",
		                             SIGNED_KEY_ID, sign_request.region));
		AddHeader(writer, headers, "x-amz-date", "20260101T000000Z");
		AddHeader(writer, headers, "x-amz-content-sha256", sign_request.Header("x-amz-content-sha256"));
		// Some signers repeat their caching policy among the headers, which must not reach the object store
		AddHeader(writer, headers, "Cache-Control", "private");
		root.Add("headers", headers);
		writer.SetRoot(root);

		requests.push_back(std::move(sign_request));
		if (!cache_control.empty()) {
			response.set_header("Cache-Control", cache_control);
		}
		response.set_content(writer.ToString(), "application/json");
	}

	static void AddHeader(JSONWriter &writer, JSONMutableValue &headers, const string &name, const string &value) {
		auto values = writer.CreateArray();
		values.AppendString(value);
		headers.Add(name, values);
	}

	static MockSignRequest ParseRequest(const httplib::Request &request) {
		MockSignRequest result;
		result.authorization = request.get_header_value("Authorization");
		auto document = JSONDocument::Parse(request.body.c_str(), request.body.size());
		auto root = document->GetRoot();
		result.region = root.GetMember("region").GetString();
		result.uri = root.GetMember("uri").GetString();
		result.method = root.GetMember("method").GetString();
		root.GetMember("headers").IterateObject([&](const string &name, JSONValue values) {
			values.IterateArray([&](JSONValue value) { result.headers[name] = value.GetString(); });
		});
		root.GetMember("properties").IterateObject([&](const string &name, JSONValue value) {
			result.properties[name] = value.GetString();
		});
		auto body = root.GetMember("body");
		if (body.IsValid() && body.IsString()) {
			result.has_body = true;
			result.body = body.GetString();
		}
		return result;
	}

private:
	const string cache_control;
	httplib::Server server;
	std::thread server_thread;
	int port = 0;

	mutable annotated_mutex lock;
	string accepted_token DUCKDB_GUARDED_BY(lock);
	idx_t failures_left DUCKDB_GUARDED_BY(lock) = 0;
	int failure_status DUCKDB_GUARDED_BY(lock) = 0;
	vector<MockSignRequest> requests DUCKDB_GUARDED_BY(lock);
};

static MockS3ServerConfig CreateServerConfig() {
	MockS3ServerConfig config;
	config.object.bucket = S3TestHelper::BUCKET;
	config.object.key = S3TestHelper::OBJECT_KEY;
	return config;
}

static void ConfigureRemoteSigning(DuckDB &db, Connection &con, MockS3Server &server, MockRemoteSigner &signer,
                                   const string &client_implementation = "curl") {
	S3TestHelper::LoadExtension(db);
	S3TestHelper::RequireQueryOk(con,
	                             StringUtil::Format("SET httpfs_client_implementation='%s'", client_implementation));
	S3TestHelper::RequireQueryOk(con, StringUtil::Format(R"(
CREATE SECRET remote_signed (
	TYPE S3,
	SCOPE 's3://refresh-bucket/',
	SIGNER_URL '%s',
	SIGNER_HEADERS MAP {'Authorization': 'Bearer %s'},
	SIGNER_PROPERTIES MAP {'warehouse': 'demo'},
	REGION 'us-east-1',
	ENDPOINT '%s',
	URL_STYLE 'path',
	USE_SSL false
))",
	                                                     signer.URL(), VALID_TOKEN, server.Endpoint()));
}

static string DescribeSignRequests(const vector<MockSignRequest> &sign_requests) {
	string result = "sign requests:";
	for (auto &sign_request : sign_requests) {
		result += StringUtil::Format("\n  %d %s %s", sign_request.status, sign_request.method, sign_request.Target());
	}
	return result;
}

static idx_t CountSignRequests(const vector<MockSignRequest> &sign_requests, const string &method) {
	idx_t result = 0;
	for (auto &sign_request : sign_requests) {
		if (sign_request.status == 200 && sign_request.method == method) {
			result++;
		}
	}
	return result;
}

static optional_ptr<const MockSignRequest> FindSignRequest(const vector<MockSignRequest> &sign_requests,
                                                           const string &method, const string &target_contains) {
	for (auto &sign_request : sign_requests) {
		if (sign_request.status == 200 && sign_request.method == method &&
		    sign_request.Target().find(target_contains) != string::npos) {
			return &sign_request;
		}
	}
	return nullptr;
}

//! Every request that reached the object store carries the signer's credential, for exactly what was signed
static void RequireSignedAsSent(const vector<MockS3RequestObservation> &observations,
                                const vector<MockSignRequest> &sign_requests) {
	REQUIRE_FALSE(observations.empty());
	for (auto &observation : observations) {
		INFO(StringUtil::Format("request: %s %s", observation.method, observation.target));
		REQUIRE(observation.key_id == SIGNED_KEY_ID);
		REQUIRE(observation.region == "us-east-1");
		REQUIRE(MockS3HeaderValues(observation, "Cache-Control").empty());
		bool signed_as_sent = false;
		for (auto &sign_request : sign_requests) {
			if (sign_request.status != 200 || sign_request.method != observation.method ||
			    sign_request.Target() != observation.target) {
				continue;
			}
			auto sent_hash = MockS3HeaderValues(observation, "x-amz-content-sha256");
			if (sent_hash.size() == 1 && sent_hash[0] == sign_request.Header("x-amz-content-sha256")) {
				signed_as_sent = true;
			}
		}
		REQUIRE(signed_as_sent);
	}
	for (auto &sign_request : sign_requests) {
		INFO(StringUtil::Format("sign request: %s %s", sign_request.method, sign_request.Target()));
		REQUIRE(sign_request.region == "us-east-1");
		REQUIRE(sign_request.properties == map<string, string> {{"warehouse", "demo"}});
		REQUIRE(sign_request.HasHeader("Host"));
		REQUIRE(sign_request.HasHeader("x-amz-content-sha256"));
		// The signer dates the request and the client holds no credentials of its own to sign with
		REQUIRE_FALSE(sign_request.HasHeader("x-amz-date"));
		REQUIRE_FALSE(sign_request.HasHeader("Authorization"));
	}
}

//! File system calls outside of a query need a transaction to look up secrets in
template <class OPERATION>
static void RunInTransaction(Connection &con, OPERATION operation) {
	S3TestHelper::RequireQueryOk(con, "BEGIN TRANSACTION");
	operation();
	S3TestHelper::RequireQueryOk(con, "COMMIT");
}

static void ReadRanges(Connection &con, const string &object_data) {
	auto &fs = FileSystem::GetFileSystem(*con.context);
	auto handle = fs.OpenFile(S3TestHelper::S3_PATH, FileFlags::FILE_FLAGS_READ | FileFlags::FILE_FLAGS_DIRECT_IO);
	for (auto offset : {idx_t(2), idx_t(11), idx_t(25)}) {
		const idx_t read_size = 7;
		string buffer(read_size, '\0');
		handle->Read(QueryContext(*con.context), &buffer[0], read_size, offset);
		REQUIRE(buffer == object_data.substr(offset, read_size));
	}
}

static idx_t CountRangeReads(const vector<MockS3RequestObservation> &observations) {
	idx_t result = 0;
	for (auto &observation : observations) {
		if (observation.method == "GET" && !observation.range.empty()) {
			result++;
		}
	}
	return result;
}

//! Stands in for a catalog that hands out a new signer token when asked to refresh the secret
struct RemoteSignerRefreshProvider : public CreateS3SecretFunctions {
public:
	static constexpr const char *PROVIDER = "remote_signer_refresh_test";

	static void Register(DuckDB &db) {
		ExtensionInfo extension_info;
		ExtensionActiveLoad load_info(*db.instance, extension_info, "remote_signer_refresh_test", "");
		ExtensionLoader loader(load_info);
		CreateSecretFunction function;
		function.secret_type = "s3";
		function.provider = PROVIDER;
		function.function = CreateSecret;
		string type = "s3";
		SetBaseNamedParams(function, type);
		loader.RegisterFunction(function);
	}

	static void SetToken(const string &token) {
		annotated_lock_guard<annotated_mutex> guard(GetState().lock);
		GetState().token = token;
	}

	static idx_t Calls() {
		return GetState().calls.load();
	}

private:
	struct State {
		annotated_mutex lock;
		string token DUCKDB_GUARDED_BY(lock);
		std::atomic<idx_t> calls {0};
	};

	static State &GetState() {
		static State state;
		return state;
	}

	static unique_ptr<BaseSecret> CreateSecret(ClientContext &context, CreateSecretInput &input) {
		auto &state = GetState();
		state.calls++;
		string token;
		{
			annotated_lock_guard<annotated_mutex> guard(state.lock);
			token = state.token;
		}
		auto delegated_input = input;
		InsertionOrderPreservingMap<string> headers;
		headers.insert("Authorization", "Bearer " + token);
		delegated_input.options["signer_headers"] = Value::MAP(headers);
		return CreateSecretFunctionInternal(context, delegated_input);
	}
};

} // namespace

TEST_CASE("Remote signing sends S3 requests with the headers returned by the signer", "[httpfs][s3][remote_signing]") {
	for (auto client_implementation : {"curl", "httplib"}) {
		INFO(StringUtil::Format("client: %s", client_implementation));
		MockS3Server server(CreateServerConfig());
		MockRemoteSigner signer;
		DuckDB db(nullptr);
		Connection con(db);
		ConfigureRemoteSigning(db, con, server, signer, client_implementation);

		auto result = con.Query("SELECT content FROM read_text('s3://refresh-bucket/object.bin')");
		REQUIRE(result);
		INFO((result->HasError() ? result->GetError() : string()));
		REQUIRE_FALSE(result->HasError());
		REQUIRE(result->Collection().GetValue(0, 0).GetValue<string>() == server.ObjectData());

		auto observations = server.Observations();
		auto sign_requests = signer.Requests();
		INFO(MockS3DescribeObservations(observations));
		INFO(DescribeSignRequests(sign_requests));
		RequireSignedAsSent(observations, sign_requests);
		for (auto &sign_request : sign_requests) {
			REQUIRE(sign_request.authorization == StringUtil::Format("Bearer %s", VALID_TOKEN));
			REQUIRE(sign_request.Header("x-amz-content-sha256") == EMPTY_PAYLOAD_HASH);
			REQUIRE_FALSE(sign_request.has_body);
		}
	}
}

TEST_CASE("Ranged reads of an object share a signature the signer allows to be cached",
          "[httpfs][s3][remote_signing]") {
	MockS3Server server(CreateServerConfig());
	MockRemoteSigner signer("private");
	DuckDB db(nullptr);
	Connection con(db);
	ConfigureRemoteSigning(db, con, server, signer);

	RunInTransaction(con, [&]() { ReadRanges(con, server.ObjectData()); });

	auto observations = server.Observations();
	auto sign_requests = signer.Requests();
	INFO(MockS3DescribeObservations(observations));
	INFO(DescribeSignRequests(sign_requests));
	RequireSignedAsSent(observations, sign_requests);
	REQUIRE(CountRangeReads(observations) == 3);
	REQUIRE(CountSignRequests(sign_requests, "GET") == 1);
}

TEST_CASE("Reads are signed again when the signer does not allow caching", "[httpfs][s3][remote_signing]") {
	MockS3Server server(CreateServerConfig());
	MockRemoteSigner signer("no-cache");
	DuckDB db(nullptr);
	Connection con(db);
	ConfigureRemoteSigning(db, con, server, signer);

	RunInTransaction(con, [&]() { ReadRanges(con, server.ObjectData()); });

	auto observations = server.Observations();
	auto sign_requests = signer.Requests();
	INFO(MockS3DescribeObservations(observations));
	INFO(DescribeSignRequests(sign_requests));
	RequireSignedAsSent(observations, sign_requests);
	REQUIRE(CountRangeReads(observations) == 3);
	REQUIRE(CountSignRequests(sign_requests, "GET") == 3);
}

TEST_CASE("Uploads are signed over their payload hash", "[httpfs][s3][remote_signing]") {
	MockS3Server server(CreateServerConfig());
	MockRemoteSigner signer;
	DuckDB db(nullptr);
	Connection con(db);
	ConfigureRemoteSigning(db, con, server, signer);

	RunInTransaction(con, [&]() { S3TestHelper::WriteSinglePutPayload(con); });

	auto observations = server.Observations();
	auto sign_requests = signer.Requests();
	INFO(MockS3DescribeObservations(observations));
	INFO(DescribeSignRequests(sign_requests));
	RequireSignedAsSent(observations, sign_requests);
	REQUIRE(server.UploadedObject() == "single-shot payload");
	auto put = FindSignRequest(sign_requests, "PUT", "/");
	REQUIRE(put);
	REQUIRE(put->Header("x-amz-content-sha256") != EMPTY_PAYLOAD_HASH);
}

TEST_CASE("Every request of a multipart upload is signed", "[httpfs][s3][remote_signing]") {
	MockS3Server server(CreateServerConfig());
	MockRemoteSigner signer;
	DuckDB db(nullptr);
	Connection con(db);
	ConfigureRemoteSigning(db, con, server, signer);

	RunInTransaction(con, [&]() { S3TestHelper::WriteMultipartPayload(con); });

	auto observations = server.Observations();
	auto sign_requests = signer.Requests();
	INFO(MockS3DescribeObservations(observations));
	INFO(DescribeSignRequests(sign_requests));
	RequireSignedAsSent(observations, sign_requests);
	REQUIRE(server.UploadedObject() == string(10 * 1024 * 1024 + 1, 'x'));
	REQUIRE(FindSignRequest(sign_requests, "POST", "uploads"));
	REQUIRE(FindSignRequest(sign_requests, "PUT", "partNumber"));
	REQUIRE(FindSignRequest(sign_requests, "POST", "uploadId"));
}

TEST_CASE("Bulk deletes send the deleted keys to the signer", "[httpfs][s3][remote_signing]") {
	MockS3Server server(CreateServerConfig());
	MockRemoteSigner signer;
	DuckDB db(nullptr);
	Connection con(db);
	ConfigureRemoteSigning(db, con, server, signer);

	RunInTransaction(con, [&]() {
		auto &fs = FileSystem::GetFileSystem(*con.context);
		fs.RemoveFiles({S3TestHelper::S3_PATH});
	});

	auto observations = server.Observations();
	auto sign_requests = signer.Requests();
	INFO(MockS3DescribeObservations(observations));
	INFO(DescribeSignRequests(sign_requests));
	RequireSignedAsSent(observations, sign_requests);
	auto bulk_delete = FindSignRequest(sign_requests, "POST", "delete");
	REQUIRE(bulk_delete);
	REQUIRE(bulk_delete->has_body);
	REQUIRE(StringUtil::Contains(bulk_delete->body, S3TestHelper::OBJECT_KEY));
	bool body_sent = false;
	for (auto &observation : observations) {
		if (observation.method == "POST" && StringUtil::Contains(observation.target, "delete")) {
			body_sent = observation.body_digest == MockS3DigestBody(bulk_delete->body);
		}
	}
	REQUIRE(body_sent);
}

TEST_CASE("An expired signer token is refreshed through the secret provider", "[httpfs][s3][remote_signing]") {
	MockS3Server server(CreateServerConfig());
	MockRemoteSigner signer;
	signer.AcceptToken("fresh-token");
	DuckDB db(nullptr);
	Connection con(db);
	S3TestHelper::LoadExtension(db);
	RemoteSignerRefreshProvider::Register(db);
	auto calls_before = RemoteSignerRefreshProvider::Calls();

	// Settings rather than secret options, because a refresh recreates the secret from its refresh_info alone
	S3TestHelper::RequireQueryOk(con, StringUtil::Format("SET s3_endpoint='%s'", server.Endpoint()));
	S3TestHelper::RequireQueryOk(con, "SET s3_region='us-east-1'");
	S3TestHelper::RequireQueryOk(con, "SET s3_use_ssl=false");
	S3TestHelper::RequireQueryOk(con, "SET s3_url_style='path'");
	RemoteSignerRefreshProvider::SetToken("stale-token");
	S3TestHelper::RequireQueryOk(con,
	                             StringUtil::Format(R"(
CREATE SECRET refreshed_signer (
	TYPE S3,
	PROVIDER %s,
	SCOPE 's3://refresh-bucket/',
	SIGNER_URL '%s',
	SIGNER_PROPERTIES MAP {'warehouse': 'demo'},
	REFRESH_INFO MAP {'SIGNER_URL': '%s'}
))",
	                                                RemoteSignerRefreshProvider::PROVIDER, signer.URL(), signer.URL()));
	RemoteSignerRefreshProvider::SetToken("fresh-token");

	S3TestHelper::RequireQueryOk(con, "SET force_download=true");
	RunInTransaction(con, [&]() {
		auto &fs = FileSystem::GetFileSystem(*con.context);
		auto handle = fs.OpenFile(S3TestHelper::S3_PATH, FileFlags::FILE_FLAGS_READ);
		string buffer(8, '\0');
		handle->Read(QueryContext(*con.context), &buffer[0], buffer.size(), 0);
		REQUIRE(buffer == server.ObjectData().substr(0, buffer.size()));
	});

	auto sign_requests = signer.Requests();
	INFO(DescribeSignRequests(sign_requests));
	REQUIRE(RemoteSignerRefreshProvider::Calls() == calls_before + 2);
	REQUIRE(sign_requests.front().authorization == "Bearer stale-token");
	REQUIRE(sign_requests.front().status == 401);
	REQUIRE(sign_requests.back().authorization == "Bearer fresh-token");
	REQUIRE(sign_requests.back().status == 200);
	for (auto &observation : server.Observations()) {
		REQUIRE(observation.key_id == SIGNED_KEY_ID);
	}
}

TEST_CASE("A transient signer error is retried", "[httpfs][s3][remote_signing]") {
	for (auto client_implementation : {"curl", "httplib"}) {
		INFO(StringUtil::Format("client: %s", client_implementation));
		MockS3Server server(CreateServerConfig());
		MockRemoteSigner signer;
		DuckDB db(nullptr);
		Connection con(db);
		ConfigureRemoteSigning(db, con, server, signer, client_implementation);
		S3TestHelper::RequireQueryOk(con, "SET http_retry_wait_ms = 1");
		signer.FailNext(1, 503);

		auto result = con.Query("SELECT content FROM read_text('s3://refresh-bucket/object.bin')");
		REQUIRE(result);
		auto sign_requests = signer.Requests();
		INFO(DescribeSignRequests(sign_requests));
		INFO((result->HasError() ? result->GetError() : string()));
		REQUIRE_FALSE(result->HasError());
		REQUIRE(result->Collection().GetValue(0, 0).GetValue<string>() == server.ObjectData());
		REQUIRE(sign_requests.front().status == 503);
		RequireSignedAsSent(server.Observations(), sign_requests);
	}
}

TEST_CASE("A signer that keeps failing ends the request without reaching S3", "[httpfs][s3][remote_signing]") {
	MockS3Server server(CreateServerConfig());
	MockRemoteSigner signer;
	DuckDB db(nullptr);
	Connection con(db);
	ConfigureRemoteSigning(db, con, server, signer);
	S3TestHelper::RequireQueryOk(con, "SET http_retry_wait_ms = 1");
	S3TestHelper::RequireQueryOk(con, "SET http_retries = 2");
	signer.FailNext(100, 500);

	auto result = con.Query("SELECT content FROM read_text('s3://refresh-bucket/object.bin')");
	REQUIRE(result);
	auto sign_requests = signer.Requests();
	INFO(DescribeSignRequests(sign_requests));
	REQUIRE(result->HasError());
	REQUIRE(StringUtil::Contains(result->GetError(), "remote signer"));
	REQUIRE(StringUtil::Contains(result->GetError(), "500"));
	// The first request and its two retries
	REQUIRE(sign_requests.size() == 3);
	REQUIRE(server.Observations().empty());
}

} // namespace duckdb
