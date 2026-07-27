#pragma once

#include "duckdb/common/case_insensitive_map.hpp"
#include "duckdb/common/file_system.hpp"
#include "http_state.hpp"
#include "duckdb/common/pair.hpp"
#include "duckdb/common/unordered_map.hpp"
#include "duckdb/common/exception/http_exception.hpp"
#include "duckdb/main/client_data.hpp"
#include "http_metadata_cache.hpp"
#include "httpfs_client.hpp"

#include <functional>

namespace duckdb {

struct SuffixReadResult {
	//! Total file size parsed from the suffix response
	idx_t file_size = 0;
	//! Absolute offset where the returned suffix starts
	idx_t start_offset = 0;
	//! Number of bytes returned in the caller-provided buffer
	idx_t bytes_read = 0;
};

class RangeRequestNotSupportedException {
public:
	// Call static Throw instead: if thrown as exception DuckDB can't catch it.
	explicit RangeRequestNotSupportedException() = delete;

	static constexpr ExceptionType TYPE = ExceptionType::HTTP;
	static constexpr const char *MESSAGE =
	    "Content-Length from server mismatches requested range, server may not support range requests. You can try to "
	    "resolve this by enabling `SET force_download=true`";

	static void Throw() {
		throw HTTPException(MESSAGE);
	}
};

class HTTPClientCache {
public:
	struct Entry {
		unique_ptr<HTTPClient> client;
		idx_t generation = 0;
	};

	//! Get a client from the client cache
	unique_ptr<HTTPClient> GetClient();
	//! Get a client together with the cache generation it came from
	Entry GetClientWithGeneration();
	//! Store a client in the cache for reuse
	void StoreClient(unique_ptr<HTTPClient> client);
	//! Store a generation-tagged client if the cache was not cleared while it was checked out
	bool StoreClient(Entry &entry);
	//! Clear the stored clients
	void Clear();

protected:
	//! The cached clients
	vector<unique_ptr<HTTPClient>> clients;
	//! Incremented when the cache is cleared, invalidating checked-out clients
	idx_t generation = 0;
	//! Lock to fetch a client
	mutex lock;
};

class HTTPInput {
public:
	HTTPInput(unique_ptr<HTTPParams> params_p);
	virtual ~HTTPInput() = default;

	unique_ptr<HTTPParams> params;
	HTTPFSParams &http_params;

	template <class TARGET>
	TARGET &Cast() {
		DynamicCastCheck<TARGET>(this);
		return reinterpret_cast<TARGET &>(*this);
	}
	template <class TARGET>
	const TARGET &Cast() const {
		DynamicCastCheck<TARGET>(this);
		return reinterpret_cast<const TARGET &>(*this);
	}
};

class HTTPFileSystem;

class HTTPFileHandle : public FileHandle {
public:
	HTTPFileHandle(FileSystem &fs, const OpenFileInfo &file, FileOpenFlags flags, unique_ptr<HTTPParams> params);
	HTTPFileHandle(FileSystem &fs, const OpenFileInfo &file, FileOpenFlags flags, shared_ptr<HTTPInput> input);
	~HTTPFileHandle() override;
	// This two-phase construction allows subclasses more flexible setup.
	virtual void Initialize(optional_ptr<FileOpener> opener);

	// We keep an http client stored for connection reuse with keep-alive headers
	HTTPClientCache client_cache;

	shared_ptr<HTTPInput> http_input;
	HTTPFSParams &http_params;

	// File handle info
	FileOpenFlags flags;
	idx_t length;
	timestamp_t last_modified;
	string etag;
	string version_id;
	bool force_full_download;
	bool defer_file_info = false;
	bool initialized = false;

	bool auto_fallback_to_full_file_download = true;

	// In write overwrite mode, we are not interested in the current state of the file: we're overwriting it.
	bool write_overwrite_mode = false;

	// Per-path download and range-support state shared by all handles in this query
	shared_ptr<HTTPFileState> file_state;
	optional_ptr<Allocator> buffer_allocator;

	// Read info
	idx_t buffer_available;
	idx_t buffer_idx;
	idx_t file_offset;
	idx_t buffer_start;
	idx_t buffer_end;

	// Used when file handle created with parallel access flag specified.
	mutex mu;

	// Read buffer
	AllocatedData read_buffer;
	constexpr static idx_t INITIAL_READ_BUFFER_LEN = 1048576;
	constexpr static idx_t MAXIMUM_READ_BUFFER_LEN = 33554432;

	// Adaptively resizes read_buffer based on range_request_statistics
	void AddStatistics(idx_t read_offset, idx_t read_length, idx_t read_duration);
	void AdaptReadBufferSize(idx_t next_read_offset);

	// Record a completed range request into the network throughput estimate (latency + bandwidth)
	void RecordNetworkSample(double total_seconds, idx_t bytes, bool sample_has_ttfb, double ttfb_seconds);
	// Expose the measured network throughput estimate to the (parquet) prefetch cost model.
	bool TryGetNetworkThroughput(NetworkThroughputEstimate &result);

	void AddHeaders(HTTPHeaders &map);
	void EnsureFileInfoLoaded();

	// Get a Client to run requests over
	unique_ptr<HTTPClient> GetClient();
	// Return the client for re-use
	void StoreClient(unique_ptr<HTTPClient> client);

	// Whether to bypass the read buffer
	bool SkipBuffer() const {
		return flags.DirectIO() || flags.RequireParallelAccess();
	}

private:
	void AllocateReadBuffer(optional_ptr<FileOpener> opener);

	// Statistics that are used to adaptively grow the read_buffer
	struct RangeRequestStatistics {
		idx_t offset;
		idx_t length;
		idx_t duration;
	};
	vector<RangeRequestStatistics> range_request_statistics;

	// throughput_lock guards the throughput estimate (fed by RecordNetworkSample) and range_request_statistics against
	// concurrent prefetch reads.
	mutex throughput_lock;
	double tp_latency_seconds = 0;
	double tp_bandwidth_bps = 0;
	idx_t tp_sample_count = 0;
	// Minimum payload size for a request to contribute a bandwidth sample
	constexpr static idx_t MIN_BANDWIDTH_SAMPLE_BYTES = 1 << 16; // 64 KiB

public:
	void Close() override {
	}

protected:
	//! Create a new Client
	virtual unique_ptr<HTTPClient> CreateClient();
	//! Perform a HEAD request to get the file info (if not yet loaded)
	void LoadFileInfo();
	//! TODO: make base function virtual?
	void TryAddLogger(FileOpener &opener);

	virtual void InitializeFromCacheEntry(const HTTPMetadataCacheEntry &cache_entry);
	virtual HTTPMetadataCacheEntry GetCacheEntry() const;
};

class HTTPFileSystem : public FileSystem {
public:
	static bool TryParseLastModifiedTime(const string &timestamp, timestamp_t &result);

	//! FileSystem overrides.
	vector<OpenFileInfo> Glob(const string &path, FileOpener *opener = nullptr) override {
		if (path.find('*') != std::string::npos && opener) {
			Value setting_val;
			if (FileOpener::TryGetCurrentSetting(opener, "allow_asterisks_in_http_paths", setting_val) &&
			    !setting_val.GetValue<bool>()) {
				throw InvalidInputException("Globs (`*`) for generic HTTP file is are not supported.\nConsider `SET "
				                            "allow_asterisks_in_http_paths = true;` to allow this behaviour");
			}
		}
		return {path}; // FIXME
	}

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
	bool CanSeek() override {
		return true;
	}
	bool OnDiskFile(FileHandle &handle) override {
		return false;
	}
	bool TryGetNetworkThroughput(FileHandle &handle, NetworkThroughputEstimate &result) override {
		return handle.Cast<HTTPFileHandle>().TryGetNetworkThroughput(result);
	}
	bool IsPipe(const string &filename, optional_ptr<FileOpener> opener) override {
		return false;
	}
	string GetName() const override {
		return "HTTPFileSystem";
	}
	string PathSeparator(const string &path) override {
		return "/";
	}
	static void Verify();

	optional_ptr<HTTPMetadataCache> GetGlobalCache();
	virtual HTTPException GetHTTPError(FileHandle &, const HTTPResponse &response, const string &url);

	//! HTTP request overrides.
	virtual unique_ptr<HTTPResponse> HeadRequest(FileHandle &handle, string url, HTTPHeaders header_map);
	virtual bool TryReadSuffix(FileHandle &handle, data_ptr_t buffer, idx_t buffer_len, SuffixReadResult &result);
	// Get Request with range parameter that GETs exactly buffer_out_len bytes from the url
	virtual unique_ptr<HTTPResponse> GetRangeRequest(FileHandle &handle, string url, HTTPHeaders header_map,
	                                                 idx_t file_offset, char *buffer_out, idx_t buffer_out_len);
	// Get Request without a range (i.e., downloads full file)
	virtual unique_ptr<HTTPResponse> GetRequest(FileHandle &handle, string url, HTTPHeaders header_map,
	                                            CachedFileDownload &download);
	// Post Request that can handle variable sized responses without a content-length header (needed for s3 multipart)
	virtual unique_ptr<HTTPResponse> PostRequest(HTTPInput &input, string url, HTTPHeaders header_map, string &result,
	                                             char *buffer_in, idx_t buffer_in_len, string params = "");
	virtual unique_ptr<HTTPResponse> PutRequest(HTTPInput &input, string url, HTTPHeaders header_map, char *buffer_in,
	                                            idx_t buffer_in_len, string params = "");
	virtual unique_ptr<HTTPResponse> DeleteRequest(FileHandle &handle, string url, HTTPHeaders header_map);
	//! Fully download a file, or wait for an in-progress download of the same path
	unique_ptr<CachedFileHandle> FullDownload(HTTPFileHandle &handle, bool &should_write_cache);

protected:
	//! FileSystem extension points used by HTTP handle setup.
	unique_ptr<FileHandle> OpenFileExtended(const OpenFileInfo &file, FileOpenFlags flags,
	                                        optional_ptr<FileOpener> opener) override;
	bool SupportsOpenFileExtended() const override {
		return true;
	}
	virtual unique_ptr<HTTPFileHandle> CreateHandle(const OpenFileInfo &file, FileOpenFlags flags,
	                                                optional_ptr<FileOpener> opener);

	//! Internal read helpers shared by buffered and direct reads.
	bool TryRangeRequest(FileHandle &handle, string url, HTTPHeaders header_map, idx_t file_offset, char *buffer_out,
	                     idx_t buffer_out_len);
	bool TryReadSuffixRequest(FileHandle &handle, string url, HTTPHeaders header_map, data_ptr_t buffer,
	                          idx_t buffer_len, SuffixReadResult &result);
	bool ReadInternal(FileHandle &handle, void *buffer, int64_t nr_bytes, idx_t location);

	//! Shared request runners used by subclasses that need custom request setup/retry behavior.
	using HTTPSendCallback = std::function<unique_ptr<HTTPResponse>(BaseRequest &)>;
	using HTTPErrorCallback = std::function<HTTPException(const HTTPResponse &)>;

	unique_ptr<HTTPResponse> RunHeadRequest(string url, HTTPHeaders header_map, HTTPFSParams &http_params,
	                                        HTTPSendCallback send_request);
	unique_ptr<HTTPResponse> RunDeleteRequest(string url, HTTPHeaders header_map, HTTPFSParams &http_params,
	                                          HTTPSendCallback send_request);
	unique_ptr<HTTPResponse> RunPostRequest(string url, HTTPHeaders header_map, HTTPFSParams &http_params,
	                                        string &result, char *buffer_in, idx_t buffer_in_len,
	                                        HTTPSendCallback send_request);
	unique_ptr<HTTPResponse> RunPutRequest(string url, HTTPHeaders header_map, HTTPFSParams &http_params,
	                                       char *buffer_in, idx_t buffer_in_len, const string &content_type,
	                                       HTTPSendCallback send_request);
	unique_ptr<HTTPResponse> RunGetRequest(HTTPFileHandle &handle, string url, HTTPHeaders header_map,
	                                       HTTPFSParams &http_params, CachedFileDownload &download,
	                                       HTTPErrorCallback get_error, HTTPSendCallback send_request);
	unique_ptr<HTTPResponse> RunGetRangeRequest(HTTPFileHandle &handle, string url, HTTPHeaders header_map,
	                                            HTTPFSParams &http_params, const string &etag,
	                                            bool auto_fallback_to_full_file_download, idx_t file_offset,
	                                            char *buffer_out, idx_t buffer_out_len, HTTPErrorCallback get_error,
	                                            HTTPSendCallback send_request);
	bool RunGetSuffixRequest(HTTPFileHandle &handle, string url, HTTPHeaders header_map, HTTPFSParams &http_params,
	                         idx_t buffer_len, data_ptr_t buffer_out, SuffixReadResult &result,
	                         HTTPErrorCallback get_error, HTTPSendCallback send_request);

private:
	// Global cache
	mutex global_cache_lock;
	unique_ptr<HTTPMetadataCache> global_metadata_cache;
};

} // namespace duckdb
