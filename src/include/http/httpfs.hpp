#pragma once

#include "duckdb/common/case_insensitive_map.hpp"
#include "duckdb/common/file_system.hpp"
#include "http/http_state.hpp"
#include "duckdb/common/pair.hpp"
#include "duckdb/common/unordered_map.hpp"
#include "duckdb/common/exception/http_exception.hpp"
#include "duckdb/main/client_data.hpp"
#include "http/http_metadata_cache.hpp"
#include "http/httpfs_client.hpp"
#include "http/http_request_session.hpp"

#include <functional>

namespace duckdb {

enum class HTTPReadConditionType : uint8_t { NONE, ETAG, S3_VERSION_ID };

struct HTTPReadCondition {
	HTTPReadConditionType type = HTTPReadConditionType::NONE;
	string value;
};

struct HTTPReadConfig {
	HTTPReadCondition condition;
	string etag;
	bool validate_etag = false;
	bool auto_fallback_to_full_download = false;
};

class RangeRequestNotSupportedException {
public:
	//! Use Throw because DuckDB cannot catch this type when it is thrown directly
	explicit RangeRequestNotSupportedException() = delete;

public:
	static void Throw();

public:
	static constexpr ExceptionType TYPE = ExceptionType::HTTP;
	static constexpr const char *MESSAGE =
	    "Content-Length from server mismatches requested range, server may not support range requests. You can try to "
	    "resolve this by enabling `SET force_download=true`";
};

class HTTPFileSystem;
class S3FileSystem;

class HTTPFileHandle : public FileHandle {
	friend class HTTPFileSystem;
	friend class S3FileSystem;

public:
	HTTPFileHandle(FileSystem &fs, const OpenFileInfo &file, FileOpenFlags flags, unique_ptr<HTTPParams> params);
	~HTTPFileHandle() override;

public:
	//! Two-phase construction allows subclasses to customize setup
	virtual void Initialize(optional_ptr<FileOpener> opener);
	const HTTPReadConfig &GetReadConfig() const;
	string GetVersionId() const;
	void SetVersionId(string version_id);

	//! Record a completed range request in the network throughput estimate
	void RecordNetworkSample(double total_seconds, idx_t bytes, bool sample_has_ttfb, double ttfb_seconds)
	    DUCKDB_EXCLUDES(network_estimator_lock);
	//! Expose the network estimate to the prefetch cost model
	bool GetNetworkThroughputEstimate(NetworkThroughputEstimate &result) DUCKDB_EXCLUDES(network_estimator_lock);
	void Close() override;

protected:
	virtual shared_ptr<const HTTPRequestSnapshot> CreateRequestSnapshot(const HTTPFSParams &params) const;
	virtual HTTPReadConfig BuildReadConfig() const;
	//! Perform a HEAD request to get the file info (if not yet loaded)
	void LoadFileInfo();
	void InitializeLogger(FileOpener &opener);

	virtual void InitializeFromCacheEntry(const HTTPMetadataCacheEntry &cache_entry);
	virtual HTTPMetadataCacheEntry GetCacheEntry() const;

private:
	void FinalizeReadConfig();
	bool TryLoadFileInfoWithoutRequest();
	unique_ptr<HTTPResponse> RequestFileInfo(HTTPFileSystem &file_system);
	unique_ptr<HTTPResponse> RetryFileInfoWithRange(HTTPFileSystem &file_system);
	void ApplyFileInfo(const HTTPResponse &response);
	void InitializeRequestState(optional_ptr<FileOpener> opener);
	bool TryInitializeRead(HTTPFileSystem &file_system, optional_ptr<HTTPMetadataCache> cache,
	                       bool &should_write_cache);
	void InitializeFileInfo(HTTPFileSystem &file_system, optional_ptr<HTTPMetadataCache> cache,
	                        bool should_write_cache);

public:
	shared_ptr<HTTPRequestSession> request_session;

	//! File metadata
	FileOpenFlags flags;
	idx_t length;
	timestamp_t last_modified;
	string etag;
	bool force_full_download;
	bool initialized = false;
	bool auto_fallback_to_full_file_download = true;
	bool write_overwrite_mode = false;

	//! Per-path state shared by all handles in this query
	shared_ptr<HTTPFileState> file_state;
	optional_ptr<Allocator> buffer_allocator;

private:
	//! Sequential read/write position
	mutable annotated_mutex cursor_mutex;
	idx_t file_offset DUCKDB_GUARDED_BY(cursor_mutex);

	string version_id;
	HTTPReadConfig read_config;
	bool read_config_initialized = false;

	//! Network throughput estimate
	mutable annotated_mutex network_estimator_lock;
	double tp_latency_seconds DUCKDB_GUARDED_BY(network_estimator_lock) = 0;
	double tp_bandwidth_bps DUCKDB_GUARDED_BY(network_estimator_lock) = 0;
	idx_t tp_sample_count DUCKDB_GUARDED_BY(network_estimator_lock) = 0;
	static constexpr idx_t MIN_BANDWIDTH_SAMPLE_BYTES = 1 << 16;
};

class HTTPFileSystem : public FileSystem {
public:
	static bool TryParseLastModifiedTime(const string &timestamp, timestamp_t &result);

	//! FileSystem overrides.
	vector<OpenFileInfo> Glob(const string &path, FileOpener *opener = nullptr) override;

	void Read(FileHandle &handle, void *buffer, int64_t nr_bytes, idx_t location) override;
	int64_t Read(FileHandle &handle, void *buffer, int64_t nr_bytes) override;
	void Write(FileHandle &handle, void *buffer, int64_t nr_bytes, idx_t location) override;
	int64_t Write(FileHandle &handle, void *buffer, int64_t nr_bytes) override;
	void FileSync(FileHandle &handle) override;
	int64_t GetFileSize(FileHandle &handle) override;
	timestamp_t GetLastModifiedTime(FileHandle &handle) override;
	string GetVersionTag(FileHandle &handle) override;
	bool FileExists(const string &filename, optional_ptr<FileOpener> opener) override;
	void Seek(FileHandle &handle, idx_t location) override;
	idx_t SeekPosition(FileHandle &handle) override;
	bool CanHandleFile(const string &fpath) override;
	bool CanSeek() override;
	bool OnDiskFile(FileHandle &handle) override;
	bool TryGetNetworkThroughput(FileHandle &handle, NetworkThroughputEstimate &result) override;
	bool IsPipe(const string &filename, optional_ptr<FileOpener> opener) override;
	string GetName() const override;
	string PathSeparator(const string &path) override;

	optional_ptr<HTTPMetadataCache> GetGlobalCache();
	virtual HTTPException GetHTTPError(FileHandle &, const HTTPResponse &response, RequestType request_type,
	                                   const string &url);

	//! HTTP request overrides
	virtual unique_ptr<HTTPResponse> HeadRequest(FileHandle &handle, const string &url, HTTPHeaders header_map);
	//! GET exactly buffer_out_len bytes from the URL
	virtual unique_ptr<HTTPResponse> GetRangeRequest(FileHandle &handle, string url, HTTPHeaders header_map,
	                                                 const HTTPReadConfig &read_config, idx_t file_offset,
	                                                 data_ptr_t buffer_out, idx_t buffer_out_len);
	//! GET the complete file without a range
	virtual unique_ptr<HTTPResponse> GetRequest(FileHandle &handle, string url, HTTPHeaders header_map,
	                                            const HTTPReadConfig &read_config, CachedFileDownload &download);
	virtual unique_ptr<HTTPResponse> DeleteRequest(FileHandle &handle, const string &url, HTTPHeaders header_map);
	//! Fully download a file, or wait for an in-progress download of the same path
	unique_ptr<CachedFileHandle> FullDownload(HTTPFileHandle &handle, const HTTPReadConfig &read_config,
	                                          bool &should_write_cache);

protected:
	using HTTPSendCallback = std::function<unique_ptr<HTTPResponse>(BaseRequest &)>;
	using HTTPErrorCallback = std::function<HTTPException(const HTTPResponse &)>;

	//! FileSystem extension points used by HTTP handle setup.
	unique_ptr<FileHandle> OpenFileExtended(const OpenFileInfo &file, FileOpenFlags flags,
	                                        optional_ptr<FileOpener> opener) override;
	bool SupportsOpenFileExtended() const override;
	virtual unique_ptr<HTTPFileHandle> CreateHandle(const OpenFileInfo &file, FileOpenFlags flags,
	                                                optional_ptr<FileOpener> opener);

	//! Internal read helpers.
	bool TryRangeRequest(FileHandle &handle, const string &url, const HTTPHeaders &header_map,
	                     const HTTPReadConfig &read_config, idx_t file_offset, data_ptr_t buffer_out,
	                     idx_t buffer_out_len);
	bool ReadAt(FileHandle &handle, data_ptr_t buffer, idx_t read_size, idx_t location,
	            const HTTPReadConfig &read_config);
	void ReadAtWithFallback(FileHandle &handle, data_ptr_t buffer, idx_t read_size, idx_t location,
	                        const HTTPReadConfig &read_config);

	//! Shared request runners used by subclasses with custom request setup
	static unique_ptr<HTTPResponse> RunHeadRequest(const string &url, const HTTPHeaders &header_map,
	                                               HTTPFSParams &http_params, const HTTPSendCallback &send_request);
	static unique_ptr<HTTPResponse> RunDeleteRequest(const string &url, const HTTPHeaders &header_map,
	                                                 HTTPFSParams &http_params, const HTTPSendCallback &send_request);
	static unique_ptr<HTTPResponse> RunPostRequest(const string &url, const HTTPHeaders &header_map,
	                                               HTTPFSParams &http_params, string &result,
	                                               const_data_ptr_t buffer_in, idx_t buffer_in_len,
	                                               const HTTPSendCallback &send_request);
	static unique_ptr<HTTPResponse> RunPutRequest(const string &url, const HTTPHeaders &header_map,
	                                              HTTPFSParams &http_params, const_data_ptr_t buffer_in,
	                                              idx_t buffer_in_len, const string &content_type,
	                                              const HTTPSendCallback &send_request);
	unique_ptr<HTTPResponse> RunGetRequest(HTTPFileHandle &handle, const string &url, const HTTPHeaders &header_map,
	                                       HTTPFSParams &http_params, const HTTPReadConfig &read_config,
	                                       CachedFileDownload &download, const HTTPErrorCallback &get_error,
	                                       const HTTPSendCallback &send_request);
	unique_ptr<HTTPResponse> RunGetRangeRequest(HTTPFileHandle &handle, const string &url,
	                                            const HTTPHeaders &header_map, HTTPFSParams &http_params,
	                                            const HTTPReadConfig &read_config, idx_t file_offset,
	                                            data_ptr_t buffer_out, idx_t buffer_out_len,
	                                            const HTTPErrorCallback &get_error,
	                                            const HTTPSendCallback &send_request);

private:
	void ValidateResponseETag(HTTPFileHandle &handle, const HTTPReadConfig &read_config, const HTTPResponse &response);
	void ThrowIfReadConditionFailed(HTTPFileHandle &handle, const HTTPReadConfig &read_config,
	                                const HTTPResponse &response);
	void EraseGlobalCacheEntry(const string &path) DUCKDB_EXCLUDES(global_cache_lock);

private:
	//! Global metadata cache
	mutable annotated_mutex global_cache_lock;
	unique_ptr<HTTPMetadataCache> global_metadata_cache DUCKDB_GUARDED_BY(global_cache_lock);
};

} // namespace duckdb
