#include "catch.hpp"

#include "http/http_settings.hpp"
#include "http/http_request_session.hpp"
#include "http/http_test_helper.hpp"
#include "http/httpfs_client.hpp"
#include "s3/s3_test_helper.hpp"
#include "duckdb/main/client_context_file_opener.hpp"
#include "duckdb/main/config.hpp"

namespace duckdb {
namespace {

struct BrowserObservations {
	idx_t parameter_initializations = 0;
	idx_t client_initializations = 0;
	bool destroyed = false;
};

//! A core-only provider, using the native client to reach the local fixture.
class BrowserHTTPUtil : public HTTPUtil {
public:
	explicit BrowserHTTPUtil(BrowserObservations &observations_p) : observations(observations_p) {
	}

	~BrowserHTTPUtil() override {
		observations.destroyed = true;
	}

	string GetName() const override {
		return "WasmHTTPUtils";
	}

	unique_ptr<HTTPParams> InitializeParameters(optional_ptr<FileOpener> opener,
	                                            optional_ptr<FileOpenerInfo> info) override {
		observations.parameter_initializations++;
		return HTTPUtil::InitializeParameters(opener, info);
	}

	unique_ptr<HTTPClient> InitializeClient(HTTPParams &params, const string &proto_host_port) override {
		observations.client_initializations++;
		REQUIRE(params.http_util.GetName() == "HTTPFS-Wasm");
		return native_client.InitializeClient(params, proto_host_port);
	}

private:
	BrowserObservations &observations;
	HTTPFSUtil native_client;
};

} // namespace

TEST_CASE("HTTPFS owns browser parameters and preserves its provider", "[httpfs][browser-adapter]") {
	BrowserObservations observations;
	{
		MockS3Server server {MockS3ServerConfig()};
		DuckDB db(nullptr);
		Connection con(db);
		auto browser = make_shared_ptr<BrowserHTTPUtil>(observations);
		HTTPTestHelper::LoadExtension(db);
		db.instance->config.SetHTTPUtil(browser);
		HTTPSettings::Initialize(*db.instance);
		HTTPTestHelper::Configure(db, con, 0, "wasm", false);
		browser.reset();
		REQUIRE_FALSE(observations.destroyed);

		auto &adapter = db.instance->config.GetHTTPUtil();
		REQUIRE(adapter.GetName() == "HTTPFS-Wasm");
		REQUIRE(adapter.GetTransportReusePolicy() == HTTPTransportReusePolicy::EPHEMERAL);
		HTTPSettings::Initialize(*db.instance);
		REQUIRE(&db.instance->config.GetHTTPUtil() == &adapter);
		HTTPTestHelper::RequireQueryOk(con, "SET httpfs_client_implementation='default'");
		auto invalid_client = con.Query("SET httpfs_client_implementation='curl'");
		REQUIRE(invalid_client->HasError());
		REQUIRE(invalid_client->GetError().find("only `wasm` and `default`") != string::npos);

		HTTPTestHelper::RequireQueryOk(con, "SET force_download_threshold=123");
		HTTPTestHelper::RequireQueryOk(con, "SET extra_http_headers=MAP {'X-Setting': 'setting'}");
		HTTPTestHelper::RequireQueryOk(
		    con, "CREATE SECRET browser_headers (TYPE HTTP, EXTRA_HTTP_HEADERS MAP {'X-Secret': 'secret'})");
		HTTPTestHelper::RequireQueryOk(con, "BEGIN TRANSACTION");
		ClientContextFileOpener opener(*con.context);
		FileOpenerInfo info;
		info.file_path = server.HTTPPath();
		auto session = HTTPRequestSession::Create(&opener, &info);
		auto snapshot = session->Capture().snapshot;
		REQUIRE(&snapshot->Params().http_util == &adapter);
		REQUIRE(snapshot->Params().force_download_threshold == 123);
		REQUIRE(snapshot->Params().extra_headers.at("X-Setting") == "setting");
		REQUIRE(snapshot->Params().extra_headers.at("X-Secret") == "secret");
		REQUIRE(snapshot->Params().VerifyServerCertificate());

		for (idx_t i = 0; i < 2; i++) {
			auto data = snapshot->CreateRequest();
			HeadRequestInfo request(server.HTTPPath(), data.headers, *data.params);
			REQUIRE(session->Request(request)->Success());
		}
		HTTPTestHelper::RequireQueryOk(con, "COMMIT");
		REQUIRE(observations.parameter_initializations == 0);
		REQUIRE(observations.client_initializations == 2);
		auto requests = server.Observations();
		REQUIRE(requests.size() == 2);
		for (const auto &request : requests) {
			REQUIRE(MockS3HeaderValues(request, "X-Setting") == vector<string> {"setting"});
			REQUIRE(MockS3HeaderValues(request, "X-Secret") == vector<string> {"secret"});
		}
		HTTPTestHelper::RequireQueryOk(con, "SELECT 42");
	}
	REQUIRE(observations.destroyed);
}

TEST_CASE("Browser adapter supports S3 credential refresh", "[httpfs][browser-adapter][s3-refresh]") {
	const auto target = GENERATE(MockS3RefreshTarget::HEAD, MockS3RefreshTarget::BULK_DELETE_POST);
	MockS3ServerConfig config;
	config.object.bucket = S3TestHelper::BUCKET;
	config.object.key = S3TestHelper::OBJECT_KEY;
	config.auth.stale_key_id = S3TestHelper::STALE_KEY_ID;
	config.auth.refresh_target = target;
	MockS3Server server(std::move(config));

	BrowserObservations observations;
	DuckDB db(nullptr);
	Connection con(db);
	S3TestHelper::LoadExtension(db);
	db.instance->config.SetHTTPUtil(make_shared_ptr<BrowserHTTPUtil>(observations));
	HTTPSettings::Initialize(*db.instance);
	auto test_id = S3TestHelper::ConfigureRefresh(db, con, server, "wasm", false);
	S3TestHelper::RequireQueryOk(con, "BEGIN TRANSACTION");
	auto &fs = FileSystem::GetFileSystem(*con.context);
	if (target == MockS3RefreshTarget::HEAD) {
		auto handle = fs.OpenFile(S3TestHelper::S3_PATH, FileFlags::FILE_FLAGS_READ | FileFlags::FILE_FLAGS_DIRECT_IO);
		REQUIRE(handle);
	} else {
		fs.RemoveFiles({S3TestHelper::S3_PATH});
	}
	S3TestHelper::RequireQueryOk(con, "COMMIT");
	S3TestHelper::AssertSingleRefresh(test_id);
	auto requests = server.Observations();
	INFO(MockS3DescribeObservations(requests));
	const auto method = target == MockS3RefreshTarget::HEAD ? "HEAD" : "POST";
	REQUIRE(MockS3HasObservation(requests, method, S3TestHelper::STALE_KEY_ID, 403));
	REQUIRE(MockS3HasObservation(requests, method, S3TestHelper::FRESH_KEY_ID, 200));
	REQUIRE(observations.parameter_initializations == 0);
	S3TestHelper::RequireQueryOk(con, "SELECT 42");
}

} // namespace duckdb
