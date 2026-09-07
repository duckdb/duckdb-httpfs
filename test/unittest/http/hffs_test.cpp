#include "catch.hpp"

#include "hffs.hpp"
#include "http/httpfs_client.hpp"
#include "s3/mock_s3_server.hpp"

#include "duckdb/common/error_data.hpp"

namespace duckdb {

TEST_CASE("Hugging Face list results parse files and directories", "[httpfs][hffs]") {
	const string input = R"([
		{"type":"file","path":"folder/file.parquet","metadata":{"size":42}},
		{"type":"directory","path":"folder/nested"}
	])";
	vector<string> files;
	vector<string> directories;

	HuggingFaceFileSystem::ParseListResult(input, files, directories);

	REQUIRE(files == vector<string> {"/folder/file.parquet"});
	REQUIRE(directories == vector<string> {"/folder/nested"});
}

TEST_CASE("Hugging Face list results parse escaped path characters", "[httpfs][hffs]") {
	const string input = R"([{"type":"file","path":"folder/a\"b\\c.parquet"}])";
	vector<string> files;
	vector<string> directories;

	HuggingFaceFileSystem::ParseListResult(input, files, directories);

	REQUIRE(files == vector<string> {"/folder/a\"b\\c.parquet"});
	REQUIRE(directories.empty());
}

TEST_CASE("Hugging Face list results reject incomplete entries", "[httpfs][hffs]") {
	const string input = R"([{"path":"folder/file.parquet"}])";
	vector<string> files;
	vector<string> directories;

	REQUIRE_THROWS_AS(HuggingFaceFileSystem::ParseListResult(input, files, directories), IOException);
}

TEST_CASE("Hugging Face list status errors preserve HTTP metadata", "[httpfs][hffs][error]") {
	struct TestHuggingFaceFileSystem : public HuggingFaceFileSystem {
		using HuggingFaceFileSystem::ListHFRequest;
	};

	MockS3Server server {MockS3ServerConfig()};
	HTTPFSUtil http_util;
	auto params = http_util.InitializeParameters(nullptr, nullptr);
	auto &httpfs_params = params->Cast<HTTPFSParams>();
	ParsedHFUrl url;
	url.endpoint = server.Endpoint();
	string next_page_url = url.endpoint + "/missing-hugging-face-page";

	try {
		TestHuggingFaceFileSystem::ListHFRequest(url, httpfs_params, next_page_url);
		FAIL("Expected the missing page to fail");
	} catch (std::exception &ex) {
		ErrorData error(ex);
		CHECK(error.Type() == ExceptionType::HTTP);
		CHECK(error.ExtraInfo().at("status_code") == "404");
		CHECK(StringUtil::Contains(error.RawMessage(), "HTTP GET error listing"));
	}
}

} // namespace duckdb
