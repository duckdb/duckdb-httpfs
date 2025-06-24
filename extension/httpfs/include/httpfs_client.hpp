#pragma once

#include "duckdb/common/http_util.hpp"

namespace duckdb {
class HTTPLogger;
class FileOpener;
struct FileOpenerInfo;
class HTTPState;

struct HTTPFSParams : public HTTPParams {
	using HTTPParams::HTTPParams;

	static constexpr bool DEFAULT_FORCE_DOWNLOAD = false;
	static constexpr uint64_t DEFAULT_HF_MAX_PER_PAGE = 0;
	static constexpr bool DEFAULT_ENABLE_SERVER_CERT_VERIFICATION = true;

	bool force_download = DEFAULT_FORCE_DOWNLOAD;
	idx_t hf_max_per_page = DEFAULT_HF_MAX_PER_PAGE;
	bool enable_server_cert_verification = DEFAULT_ENABLE_SERVER_CERT_VERIFICATION;
	string ca_cert_file;
	bool enable_http_write = false;
	string bearer_token;
	shared_ptr<HTTPState> state;
};

class HTTPFSUtil : public HTTPUtil {
public:
	unique_ptr<HTTPParams> InitializeParameters(optional_ptr<FileOpener> opener,
	                                            optional_ptr<FileOpenerInfo> info) override;
	unique_ptr<HTTPClient> InitializeClient(HTTPParams &http_params, const string &proto_host_port) override;

	static unordered_map<string, string> ParseGetParameters(const string &text);
	static shared_ptr<HTTPUtil> GetHTTPUtil(optional_ptr<FileOpener> opener);

	string GetName() const override;
};

} // namespace duckdb
