#pragma once

#include "duckdb/common/atomic.hpp"
#include "duckdb/common/chrono.hpp"
#include "duckdb/common/file_opener.hpp"
#include "duckdb/common/mutex.hpp"
#include "duckdb/common/serializer/deserializer.hpp"
#include "duckdb/main/config.hpp"
#include "duckdb/main/secret/secret.hpp"
#include "duckdb/main/secret/secret_manager.hpp"
#include "duckdb/storage/buffer_manager.hpp"
#include "duckdb/common/case_insensitive_map.hpp"
#include "httpfs.hpp"

#include <condition_variable>
#include <exception>
#include <iostream>

#undef RemoveDirectory

namespace duckdb {

class S3KeyValueReader {
public:
	S3KeyValueReader(FileOpener &opener_p, optional_ptr<FileOpenerInfo> info, const char **secret_types,
	                 idx_t secret_types_len);

	template <class TYPE>
	SettingLookupResult TryGetSecretKeyOrSetting(const string &secret_key, const string &setting_name, TYPE &result) {
		Value temp_result;
		auto setting_scope = reader.TryGetSecretKeyOrSetting(secret_key, setting_name, temp_result);
		if (temp_result.IsNull() || setting_scope.GetScope() == SettingScope::GLOBAL) {
			// if setting is global, do not use it for s3 key value reader. User must call
			// inherit_aws_config_from_environment to load env vars into extension config.
			return setting_scope;
		}
		result = temp_result.GetValue<TYPE>();
		return setting_scope;
	}

	template <class TYPE>
	SettingLookupResult TryGetSecretKey(const string &secret_key, TYPE &value_out) {
		// TryGetSecretKey never returns anything from global scope, so we don't need to check
		return reader.TryGetSecretKey(secret_key, value_out);
	}

private:
	KeyValueSecretReader reader;
};

struct S3AuthParams {
	string region;
	string access_key_id;
	string secret_access_key;
	string session_token;
	string endpoint;
	string kms_key_id;
	string url_style;
	bool use_ssl = true;
	bool s3_url_compatibility_mode = false;
	bool requester_pays = false;
	string oauth2_bearer_token; // OAuth2 bearer token for GCS

	static S3AuthParams ReadFrom(optional_ptr<FileOpener> opener, FileOpenerInfo &info);
	static S3AuthParams ReadFrom(S3KeyValueReader &secret_reader, const std::string &file_path);
};

struct AWSEnvVarToConfigHelper {
	AWSEnvVarToConfigHelper(string env_var_name, string config_name, string value)
	    : env_var_name(env_var_name), config_name(config_name), value(value) {
	}
	string env_var_name;
	string config_name;
	string value;
};

struct AWSEnvironmentCredentialsProvider {
	static constexpr const char *REGION_ENV_VAR = "AWS_REGION";
	static constexpr const char *DEFAULT_REGION_ENV_VAR = "AWS_DEFAULT_REGION";
	static constexpr const char *ACCESS_KEY_ENV_VAR = "AWS_ACCESS_KEY_ID";
	static constexpr const char *SECRET_KEY_ENV_VAR = "AWS_SECRET_ACCESS_KEY";
	static constexpr const char *SESSION_TOKEN_ENV_VAR = "AWS_SESSION_TOKEN";
	static constexpr const char *DUCKDB_ENDPOINT_ENV_VAR = "DUCKDB_S3_ENDPOINT";
	static constexpr const char *DUCKDB_USE_SSL_ENV_VAR = "DUCKDB_S3_USE_SSL";
	static constexpr const char *DUCKDB_KMS_KEY_ID_ENV_VAR = "DUCKDB_S3_KMS_KEY_ID";
	static constexpr const char *DUCKDB_REQUESTER_PAYS_ENV_VAR = "DUCKDB_S3_REQUESTER_PAYS";

	explicit AWSEnvironmentCredentialsProvider(DBConfig &config) : config(config) {};

	DBConfig &config;

	void SetExtensionOptionValue(string key, const char *env_var, vector<AWSEnvVarToConfigHelper> &ret);
	vector<AWSEnvVarToConfigHelper> SetAll();
	vector<AWSEnvVarToConfigHelper> SetDuckDBSettings();
	S3AuthParams CreateParams();
};

struct ParsedS3Url {
	const string http_proto;
	const string prefix;
	const string host;
	const string bucket;
	const string key;
	const string path;
	const string query_param;
	const string trimmed_s3_url;

	string GetHTTPUrl(S3AuthParams &auth_params, const string &http_query_string = "");
};

struct S3ConfigParams {
	static constexpr uint64_t DEFAULT_MAX_FILESIZE = 800000000000; // 800GB
	static constexpr uint64_t DEFAULT_MAX_PARTS_PER_FILE = 10000;  // AWS DEFAULT
	static constexpr uint64_t DEFAULT_MAX_UPLOAD_THREADS = 50;

	uint64_t max_file_size;
	uint64_t max_parts_per_file;
	uint64_t max_upload_threads;

	static S3ConfigParams ReadFrom(optional_ptr<FileOpener> opener);
};

class S3FileSystem;

// Holds the buffered data for 1 part of an S3 Multipart upload
class S3WriteBuffer {
public:
	explicit S3WriteBuffer(idx_t buffer_start, size_t buffer_size, BufferHandle buffer_p)
	    : idx(0), buffer_start(buffer_start), buffer(std::move(buffer_p)) {
		buffer_end = buffer_start + buffer_size;
		part_no = buffer_start / buffer_size;
		uploading = false;
	}

	void *Ptr() {
		return buffer.Ptr();
	}

	// The S3 multipart part number. Note that internally we start at 0 but AWS S3 starts at 1
	idx_t part_no;

	idx_t idx;
	idx_t buffer_start;
	idx_t buffer_end;
	BufferHandle buffer;
	atomic<bool> uploading;
};

class S3FileHandle : public HTTPFileHandle {
	friend class S3FileSystem;

public:
	S3FileHandle(FileSystem &fs, const OpenFileInfo &file, FileOpenFlags flags, unique_ptr<HTTPParams> http_params_p,
	             const S3AuthParams &auth_params_p, const S3ConfigParams &config_params_p)
	    : HTTPFileHandle(fs, file, flags, std::move(http_params_p)), auth_params(auth_params_p),
	      config_params(config_params_p), uploads_in_progress(0), parts_uploaded(0), upload_finalized(false),
	      uploader_has_error(false), upload_exception(nullptr) {
		auto_fallback_to_full_file_download = false;
		if (flags.OpenForReading() && flags.OpenForWriting()) {
			throw NotImplementedException("Cannot open an HTTP file for both reading and writing");
		} else if (flags.OpenForAppending()) {
			throw NotImplementedException("Cannot open an HTTP file for appending");
		}
	}
	~S3FileHandle() override;

	S3AuthParams auth_params;
	const S3ConfigParams config_params;
	bool initialized_multipart_upload {false};

public:
	void Close() override;
	void Initialize(optional_ptr<FileOpener> opener) override;

	shared_ptr<S3WriteBuffer> GetBuffer(uint16_t write_buffer_idx);

protected:
	string multipart_upload_id;
	size_t part_size;

	//! Write buffers for this file
	mutex write_buffers_lock;
	unordered_map<uint16_t, shared_ptr<S3WriteBuffer>> write_buffers;

	//! Synchronization for upload threads
	mutex uploads_in_progress_lock;
	std::condition_variable uploads_in_progress_cv;
	std::condition_variable final_flush_cv;
	uint16_t uploads_in_progress;

	//! Etags are stored for each part
	mutex part_etags_lock;
	unordered_map<uint16_t, string> part_etags;

	//! Info for upload
	atomic<uint16_t> parts_uploaded;
	bool upload_finalized = true;

	//! Error handling in upload threads
	atomic<bool> uploader_has_error {false};
	std::exception_ptr upload_exception;

	unique_ptr<HTTPClient> CreateClient() override;

	//! Rethrow IO Exception originating from an upload thread
	void RethrowIOError() {
		if (uploader_has_error) {
			std::rethrow_exception(upload_exception);
		}
	}
};

class S3FileSystem : public HTTPFileSystem {
public:
	explicit S3FileSystem(BufferManager &buffer_manager) : buffer_manager(buffer_manager) {
	}

	BufferManager &buffer_manager;
	string GetName() const override;

public:
	duckdb::unique_ptr<HTTPResponse> HeadRequest(FileHandle &handle, string s3_url, HTTPHeaders header_map) override;
	duckdb::unique_ptr<HTTPResponse> GetRequest(FileHandle &handle, string url, HTTPHeaders header_map) override;
	duckdb::unique_ptr<HTTPResponse> GetRangeRequest(FileHandle &handle, string s3_url, HTTPHeaders header_map,
	                                                 idx_t file_offset, char *buffer_out,
	                                                 idx_t buffer_out_len) override;
	duckdb::unique_ptr<HTTPResponse> PostRequest(FileHandle &handle, string s3_url, HTTPHeaders header_map,
	                                             string &buffer_out, char *buffer_in, idx_t buffer_in_len,
	                                             string http_params = "") override;
	duckdb::unique_ptr<HTTPResponse> PutRequest(FileHandle &handle, string s3_url, HTTPHeaders header_map,
	                                            char *buffer_in, idx_t buffer_in_len, string http_params = "") override;
	duckdb::unique_ptr<HTTPResponse> DeleteRequest(FileHandle &handle, string s3_url, HTTPHeaders header_map) override;

	bool CanHandleFile(const string &fpath) override;
	bool OnDiskFile(FileHandle &handle) override {
		return false;
	}
	void RemoveFile(const string &filename, optional_ptr<FileOpener> opener = nullptr) override;
	void RemoveDirectory(const string &directory, optional_ptr<FileOpener> opener = nullptr) override;
	void FileSync(FileHandle &handle) override;
	void Write(FileHandle &handle, void *buffer, int64_t nr_bytes, idx_t location) override;

	string InitializeMultipartUpload(S3FileHandle &file_handle);
	void FinalizeMultipartUpload(S3FileHandle &file_handle);

	void FlushAllBuffers(S3FileHandle &handle);

	void ReadQueryParams(const string &url_query_param, S3AuthParams &params);
	static ParsedS3Url S3UrlParse(string url, S3AuthParams &params);

	static string UrlEncode(const string &input, bool encode_slash = false);
	static string UrlDecode(string input);

	static string TryGetPrefix(const string &url);

	// Uploads the contents of write_buffer to S3.
	// Note: caller is responsible to not call this method twice on the same buffer
	static void UploadBuffer(S3FileHandle &file_handle, shared_ptr<S3WriteBuffer> write_buffer);
	static void UploadSingleBuffer(S3FileHandle &file_handle, shared_ptr<S3WriteBuffer> write_buffer);
	static void UploadBufferImplementation(S3FileHandle &file_handle, shared_ptr<S3WriteBuffer> write_buffer,
	                                       string query_param, bool direct_throw);

	vector<OpenFileInfo> Glob(const string &glob_pattern, FileOpener *opener = nullptr) override;
	bool ListFiles(const string &directory, const std::function<void(const string &, bool)> &callback,
	               FileOpener *opener = nullptr) override;

	//! Wrapper around BufferManager::Allocate to limit the number of buffers
	BufferHandle Allocate(idx_t part_size, uint16_t max_threads);

	//! S3 is object storage so directories effectively always exist
	bool DirectoryExists(const string &directory, optional_ptr<FileOpener> opener = nullptr) override {
		return true;
	}

	static string GetS3BadRequestError(S3AuthParams &s3_auth_params, string correct_region = "");
	static string GetS3AuthError(S3AuthParams &s3_auth_params);
	static string GetGCSAuthError(S3AuthParams &s3_auth_params);
	static HTTPException GetS3Error(S3AuthParams &s3_auth_params, const HTTPResponse &response, const string &url);

protected:
	static void NotifyUploadsInProgress(S3FileHandle &file_handle);
	static string GetPrefix(const string &url);
	duckdb::unique_ptr<HTTPFileHandle> CreateHandle(const OpenFileInfo &file, FileOpenFlags flags,
	                                                optional_ptr<FileOpener> opener) override;

	void FlushBuffer(S3FileHandle &handle, shared_ptr<S3WriteBuffer> write_buffer);
	string GetPayloadHash(char *buffer, idx_t buffer_len);

	HTTPException GetHTTPError(FileHandle &, const HTTPResponse &response, const string &url) override;
};

// Helper class to do s3 ListObjectV2 api call https://docs.aws.amazon.com/AmazonS3/latest/API/API_ListObjectsV2.html
struct AWSListObjectV2 {
	static string Request(string &path, HTTPParams &http_params, S3AuthParams &s3_auth_params,
	                      string &continuation_token, optional_ptr<HTTPState> state, bool use_delimiter = false);
	static void ParseFileList(string &aws_response, vector<OpenFileInfo> &result);
	static vector<string> ParseCommonPrefix(string &aws_response);
	static string ParseContinuationToken(string &aws_response);
};

HTTPHeaders CreateS3Header(string url, string query, string host, string service, string method,
                           const S3AuthParams &auth_params, string date_now = "", string datetime_now = "",
                           string payload_hash = "", string content_type = "");
} // namespace duckdb
