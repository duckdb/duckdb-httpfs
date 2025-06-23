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
};

class HTTPClient {
public:
	virtual ~HTTPClient() = default;

	virtual duckdb::unique_ptr<HTTPResponse> Get(const string &url, HTTPHeaders &headers, idx_t file_offset,
	                                             char *buffer_out, idx_t buffer_out_len);
	virtual duckdb::unique_ptr<HTTPResponse> Head(const string &url, HTTPHeaders &headers);
	virtual duckdb::unique_ptr<HTTPResponse> Post(const string &url, HTTPHeaders &headers, const char *buffer_in,
	                                              idx_t buffer_in_len, string &result_p, string &params_p);
	virtual duckdb::unique_ptr<HTTPResponse> Put(const string &url, HTTPHeaders &headers, const char *buffer_in,
	                                             idx_t buffer_in_len, const string &params);
	virtual duckdb::unique_ptr<HTTPResponse> Delete(const string &url, HTTPHeaders &headers);
};

} // namespace duckdb
