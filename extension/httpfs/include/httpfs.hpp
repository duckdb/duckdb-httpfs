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

#include <mutex>

namespace duckdb {

class HTTPClientCache {
public:
	//! Get a client from the client cache
	unique_ptr<HTTPClient> GetClient();
	//! Store a client in the cache for reuse
	void StoreClient(unique_ptr<HTTPClient> client);

protected:
	//! The cached clients
	vector<unique_ptr<HTTPClient>> clients;
	//! Lock to fetch a client
	mutex lock;
};

class HTTPFileSystem;

class HTTPFileHandle : public FileHandle {
public:
	HTTPFileHandle(FileSystem &fs, const OpenFileInfo &file, FileOpenFlags flags, unique_ptr<HTTPParams> params);
	~HTTPFileHandle() override;
	// This two-phase construction allows subclasses more flexible setup.
	virtual void Initialize(optional_ptr<FileOpener> opener);

	// We keep an http client stored for connection reuse with keep-alive headers
	HTTPClientCache client_cache;

	unique_ptr<HTTPParams> params;
	HTTPFSParams &http_params;

	// File handle info
	FileOpenFlags flags;
	idx_t length;
	time_t last_modified;
	string etag;
	bool force_full_download;
	bool initialized = false;

	// When using full file download, the full file will be written to a cached file handle
	unique_ptr<CachedFileHandle> cached_file_handle;

	// Read info
	idx_t buffer_available;
	idx_t buffer_idx;
	idx_t file_offset;
	idx_t buffer_start;
	idx_t buffer_end;

	// Used when file handle created with parallel access flag specified.
	std::mutex mu;

	// Read buffer
	duckdb::unique_ptr<data_t[]> read_buffer;
	constexpr static idx_t READ_BUFFER_LEN = 1000000;

	void AddHeaders(HTTPHeaders &map);

	// Get a Client to run requests over
	unique_ptr<HTTPClient> GetClient();
	// Return the client for re-use
	void StoreClient(unique_ptr<HTTPClient> client);

public:
	void Close() override {
	}

protected:
	//! Create a new Client
	virtual unique_ptr<HTTPClient> CreateClient();
	//! Perform a HEAD request to get the file info (if not yet loaded)
	void LoadFileInfo();

private:
	//! Fully downloads a file
	void FullDownload(HTTPFileSystem &hfs, bool &should_write_cache);
};

class HTTPFileSystem : public FileSystem {
public:
	static bool TryParseLastModifiedTime(const string &timestamp, time_t &result);

	vector<OpenFileInfo> Glob(const string &path, FileOpener *opener = nullptr) override {
		return {path}; // FIXME
	}

	// HTTP Requests
	virtual duckdb::unique_ptr<HTTPResponse> HeadRequest(FileHandle &handle, string url, HTTPHeaders header_map);
	// Get Request with range parameter that GETs exactly buffer_out_len bytes from the url
	virtual duckdb::unique_ptr<HTTPResponse> GetRangeRequest(FileHandle &handle, string url, HTTPHeaders header_map,
	                                                         idx_t file_offset, char *buffer_out, idx_t buffer_out_len);
	// Get Request without a range (i.e., downloads full file)
	virtual duckdb::unique_ptr<HTTPResponse> GetRequest(FileHandle &handle, string url, HTTPHeaders header_map);
	// Post Request that can handle variable sized responses without a content-length header (needed for s3 multipart)
	virtual duckdb::unique_ptr<HTTPResponse> PostRequest(FileHandle &handle, string url, HTTPHeaders header_map,
	                                                     string &result, char *buffer_in, idx_t buffer_in_len,
	                                                     string params = "");
	virtual duckdb::unique_ptr<HTTPResponse> PutRequest(FileHandle &handle, string url, HTTPHeaders header_map,
	                                                    char *buffer_in, idx_t buffer_in_len, string params = "");

	virtual duckdb::unique_ptr<HTTPResponse> DeleteRequest(FileHandle &handle, string url, HTTPHeaders header_map);

	// FS methods
	void Read(FileHandle &handle, void *buffer, int64_t nr_bytes, idx_t location) override;
	int64_t Read(FileHandle &handle, void *buffer, int64_t nr_bytes) override;
	void Write(FileHandle &handle, void *buffer, int64_t nr_bytes, idx_t location) override;
	int64_t Write(FileHandle &handle, void *buffer, int64_t nr_bytes) override;
	void FileSync(FileHandle &handle) override;
	int64_t GetFileSize(FileHandle &handle) override;
	time_t GetLastModifiedTime(FileHandle &handle) override;
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

protected:
	unique_ptr<FileHandle> OpenFileExtended(const OpenFileInfo &file, FileOpenFlags flags,
	                                        optional_ptr<FileOpener> opener) override;
	bool SupportsOpenFileExtended() const override {
		return true;
	}

	virtual HTTPException GetHTTPError(FileHandle &, const HTTPResponse &response, const string &url);

protected:
	virtual duckdb::unique_ptr<HTTPFileHandle> CreateHandle(const OpenFileInfo &file, FileOpenFlags flags,
	                                                        optional_ptr<FileOpener> opener);

private:
	// Global cache
	mutex global_cache_lock;
	duckdb::unique_ptr<HTTPMetadataCache> global_metadata_cache;
};

} // namespace duckdb
