#pragma once

#include "duckdb/common/chrono.hpp"
#include "duckdb/common/file_opener.hpp"
#include "duckdb/common/mutex.hpp"
#include "duckdb/common/serializer/deserializer.hpp"
#include "duckdb/main/config.hpp"
#include "duckdb/main/secret/secret.hpp"
#include "duckdb/main/secret/secret_manager.hpp"
#include "duckdb/storage/buffer_manager.hpp"
#include "duckdb/common/case_insensitive_map.hpp"
#include "http/httpfs.hpp"
#include "s3/s3_request.hpp"
#include "s3/s3_settings.hpp"

#include <exception>
#include <condition_variable>
#include <unordered_map>

#undef RemoveDirectory

namespace duckdb {

class S3FileSystem;
class S3UploadSession;

class S3FileHandle : public HTTPFileHandle {
	friend class S3FileSystem;

private:
	enum class UploadState : uint8_t { ACTIVE, ABORTING, ABORTED };

	class UploadClaim {
		friend class S3FileHandle;

	private:
		UploadClaim(S3FileHandle &handle, optional_ptr<S3UploadSession> session);

	public:
		UploadClaim(UploadClaim &&other) noexcept;
		UploadClaim(const UploadClaim &) = delete;
		UploadClaim &operator=(const UploadClaim &) = delete;
		~UploadClaim();

	public:
		explicit operator bool() const {
			return session != nullptr;
		}

		S3UploadSession &Get() {
			D_ASSERT(session);
			return *session;
		}

	private:
		reference<S3FileHandle> handle;
		optional_ptr<S3UploadSession> session;
	};

public:
	S3FileHandle(FileSystem &fs, const OpenFileInfo &file, FileOpenFlags flags, unique_ptr<HTTPParams> http_params_p,
	             const S3AuthParams &auth_params_p, const S3UploadConfig &upload_config,
	             optional<S3MultipartUploadPolicy> multipart_upload_policy);
	~S3FileHandle() override;

public:
	void Close() override;
	void Initialize(optional_ptr<FileOpener> opener) override;
	void FinalizeUpload();
	void AbortUpload();

protected:
	shared_ptr<const HTTPRequestSnapshot> CreateRequestSnapshot(const HTTPFSParams &params) const override;
	HTTPReadConfig BuildReadConfig() const override;
	void InitializeFromCacheEntry(const HTTPMetadataCacheEntry &cache_entry) override;
	HTTPMetadataCacheEntry GetCacheEntry() const override;

private:
	void SetRegion(const string &region);
	UploadClaim ClaimUpload(bool write);
	void ReleaseUpload();

private:
	annotated_mutex upload_lock;
	std::condition_variable upload_state_changed;
	unique_ptr<S3UploadSession> upload_session;
	UploadState upload_state DUCKDB_GUARDED_BY(upload_lock) = UploadState::ACTIVE;
	idx_t active_upload_calls DUCKDB_GUARDED_BY(upload_lock) = 0;
};

class S3FileSystem : public HTTPFileSystem {
public:
	explicit S3FileSystem(BufferManager &buffer_manager);

public:
	//! FileSystem overrides.
	string GetName() const override;
	bool CanHandleFile(const string &fpath) override;
	bool OnDiskFile(FileHandle &handle) override;
	void RemoveFile(const string &filename, optional_ptr<FileOpener> opener = nullptr) override;
	void RemoveFiles(const vector<string> &filenames, optional_ptr<FileOpener> opener = nullptr) override;
	void RemoveDirectory(const string &directory, optional_ptr<FileOpener> opener = nullptr) override;
	void FileSync(FileHandle &handle) override;
	void AbortFileWrite(FileHandle &handle) override;
	FileWriteMode GetWriteMode(FileHandle &) override;
	void Write(FileHandle &handle, void *buffer, int64_t nr_bytes, idx_t location) override;

	//! S3 is object storage so directories effectively always exist
	bool DirectoryExists(const string &directory, optional_ptr<FileOpener> opener = nullptr) override;

	//! HTTP request overrides.
	unique_ptr<HTTPResponse> HeadRequest(FileHandle &handle, const string &s3_url, HTTPHeaders header_map) override;
	unique_ptr<HTTPResponse> GetRequest(FileHandle &handle, string url, HTTPHeaders header_map,
	                                    const HTTPReadConfig &read_config, CachedFileDownload &download) override;
	unique_ptr<HTTPResponse> GetRangeRequest(FileHandle &handle, string s3_url, HTTPHeaders header_map,
	                                         const HTTPReadConfig &read_config, idx_t file_offset,
	                                         data_ptr_t buffer_out, idx_t buffer_out_len) override;
	S3RequestResult PostRequest(HTTPRequestSession &session, S3RequestOperation operation, const string &s3_url,
	                            string &buffer_out, const_data_ptr_t buffer_in, idx_t buffer_in_len,
	                            const S3RequestQuery &query = S3RequestQuery());
	S3RequestResult PutRequest(HTTPRequestSession &session, S3RequestOperation operation, const string &s3_url,
	                           const_data_ptr_t buffer_in, idx_t buffer_in_len,
	                           const S3RequestQuery &query = S3RequestQuery());
	S3RequestResult DeleteRequest(HTTPRequestSession &session, S3RequestOperation operation, const string &s3_url,
	                              const S3RequestQuery &query);
	unique_ptr<HTTPResponse> DeleteRequest(FileHandle &handle, const string &s3_url, HTTPHeaders header_map) override;
	HTTPException GetHTTPError(FileHandle &, const HTTPResponse &response, RequestType request_type,
	                           const string &url) override;

	//! Database services used by S3 requests and uploads.
	EncryptionUtil &GetEncryptionUtil();
	BufferManager &GetBufferManager();

protected:
	//! FileSystem extension points for S3 open/list/glob.
	bool ListFilesExtended(const string &directory, const std::function<void(OpenFileInfo &info)> &callback,
	                       optional_ptr<FileOpener> opener) override;
	bool SupportsListFilesExtended() const override;
	unique_ptr<MultiFileList> GlobFilesExtended(const string &path, const FileGlobInput &input,
	                                            optional_ptr<FileOpener> opener) override;
	bool SupportsGlobExtended() const override;
	unique_ptr<HTTPFileHandle> CreateHandle(const OpenFileInfo &file, FileOpenFlags flags,
	                                        optional_ptr<FileOpener> opener) override;

private:
	S3RequestResult RunS3BulkDeleteRequest(HTTPRequestSession &session, const string &secret_lookup_url,
	                                       const string &body, idx_t key_count, string &result);

	//! Database-owned buffer manager.
	BufferManager &buffer_manager;
};
} // namespace duckdb
