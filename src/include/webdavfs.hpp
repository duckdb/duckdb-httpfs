#pragma once

#include "httpfs.hpp"
#include "duckdb/common/file_opener.hpp"
#include "duckdb/common/case_insensitive_map.hpp"

namespace duckdb {

struct WebDAVAuthParams {
	string username;
	string password;

	static WebDAVAuthParams ReadFrom(optional_ptr<FileOpener> opener, FileOpenerInfo &info);
};

struct ParsedWebDAVUrl {
	string http_proto;
	string host;
	string path;

	string GetHTTPUrl() const;
};

class WebDAVFileHandle : public HTTPFileHandle {
	friend class WebDAVFileSystem;

public:
	WebDAVFileHandle(FileSystem &fs, const OpenFileInfo &file, FileOpenFlags flags,
	                 unique_ptr<HTTPParams> http_params_p, const WebDAVAuthParams &auth_params_p)
	    : HTTPFileHandle(fs, file, flags, std::move(http_params_p)), auth_params(auth_params_p) {
		if (flags.OpenForReading() && flags.OpenForWriting()) {
			throw NotImplementedException("Cannot open a WebDAV file for both reading and writing");
		} else if (flags.OpenForAppending()) {
			throw NotImplementedException("Cannot open a WebDAV file for appending");
		}
	}
	~WebDAVFileHandle() override;

	WebDAVAuthParams auth_params;

public:
	void Close() override;
	void Initialize(optional_ptr<FileOpener> opener) override;

protected:
	unique_ptr<HTTPClient> CreateClient() override;
};

class WebDAVFileSystem : public HTTPFileSystem {
public:
	WebDAVFileSystem() = default;

	string GetName() const override;

public:
	// WebDAV-specific methods
	duckdb::unique_ptr<HTTPResponse> PropfindRequest(FileHandle &handle, string url, HTTPHeaders header_map,
	                                                 int depth = 1);
	duckdb::unique_ptr<HTTPResponse> MkcolRequest(FileHandle &handle, string url, HTTPHeaders header_map);
	duckdb::unique_ptr<HTTPResponse> CustomRequest(FileHandle &handle, string url, HTTPHeaders header_map,
	                                               const string &method, char *buffer_in, idx_t buffer_in_len);

	// Override standard methods for WebDAV support
	duckdb::unique_ptr<HTTPResponse> HeadRequest(FileHandle &handle, string url, HTTPHeaders header_map) override;
	duckdb::unique_ptr<HTTPResponse> GetRequest(FileHandle &handle, string url, HTTPHeaders header_map) override;
	duckdb::unique_ptr<HTTPResponse> GetRangeRequest(FileHandle &handle, string url, HTTPHeaders header_map,
	                                                 idx_t file_offset, char *buffer_out,
	                                                 idx_t buffer_out_len) override;
	duckdb::unique_ptr<HTTPResponse> PutRequest(FileHandle &handle, string url, HTTPHeaders header_map, char *buffer_in,
	                                            idx_t buffer_in_len, string params = "") override;
	duckdb::unique_ptr<HTTPResponse> DeleteRequest(FileHandle &handle, string url, HTTPHeaders header_map) override;

	bool CanHandleFile(const string &fpath) override;
	static bool IsWebDAVUrl(const string &url);
	void RemoveFile(const string &filename, optional_ptr<FileOpener> opener = nullptr) override;
	void MoveFile(const string &source, const string &target, optional_ptr<FileOpener> opener = nullptr) override;
	void CreateDirectory(const string &directory, optional_ptr<FileOpener> opener = nullptr) override;
	void RemoveDirectory(const string &directory, optional_ptr<FileOpener> opener = nullptr) override;
	void FileSync(FileHandle &handle) override;
	void Write(FileHandle &handle, void *buffer, int64_t nr_bytes, idx_t location) override;

	bool OnDiskFile(FileHandle &handle) override {
		return false;
	}

	bool DirectoryExists(const string &directory, optional_ptr<FileOpener> opener = nullptr) override;
	vector<OpenFileInfo> Glob(const string &glob_pattern, FileOpener *opener = nullptr) override;
	bool ListFiles(const string &directory, const std::function<void(const string &, bool)> &callback,
	               FileOpener *opener = nullptr) override;

	static ParsedWebDAVUrl ParseUrl(const string &url);

protected:
	duckdb::unique_ptr<HTTPFileHandle> CreateHandle(const OpenFileInfo &file, FileOpenFlags flags,
	                                                optional_ptr<FileOpener> opener) override;

	HTTPException GetHTTPError(FileHandle &, const HTTPResponse &response, const string &url) override;

private:
	void AddAuthHeaders(HTTPHeaders &headers, const WebDAVAuthParams &auth_params);
	string Base64Encode(const string &input);
	string DirectPropfindRequest(const string &url, const WebDAVAuthParams &auth_params, int depth);
};

} // namespace duckdb
