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
	explicit S3KeyValueReader(const KeyValueSecretReader &reader);

	template <class TYPE>
	SettingLookupResult TryGetSecretKeyOrSetting(const string &secret_key, const string &setting_name, TYPE &result) {
		Value temp_result;
		auto setting_scope = reader.TryGetSecretKeyOrSetting(secret_key, setting_name, temp_result);
		if (!temp_result.IsNull() &&
		    !(setting_scope.GetScope() == SettingScope::GLOBAL && !use_env_variables_for_secret_settings)) {
			result = temp_result.GetValue<TYPE>();
		}
		return setting_scope;
	}

	template <class TYPE>
	SettingLookupResult TryGetSecretKey(const string &secret_key, TYPE &value_out) {
		// TryGetSecretKey never returns anything from global scope, so we don't need to check
		return reader.TryGetSecretKey(secret_key, value_out);
	}

private:
	bool use_env_variables_for_secret_settings;
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
	void SetRegion(string region_p);

private:
	void InitializeEndpoint();
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

	void SetExtensionOptionValue(string key, const char *env_var);
	void SetAll();
};

struct ParsedS3Url {
	string http_proto;
	string prefix;
	string host;
	string bucket;
	string key;
	string path;
	string query_param;
	string trimmed_s3_url;

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

class S3HTTPInput : public HTTPInput {
public:
	S3HTTPInput(unique_ptr<HTTPParams> params, const S3AuthParams &auth_params_p,
	            const S3ConfigParams &config_params_p);
	~S3HTTPInput() override;

	S3AuthParams auth_params;
	S3ConfigParams config_params;
};

class S3FileSystem;
class S3MultiPartUpload;
class S3WriteBuffer;

class S3FileHandle : public HTTPFileHandle {
	friend class S3FileSystem;

public:
	S3FileHandle(FileSystem &fs, const OpenFileInfo &file, FileOpenFlags flags, unique_ptr<HTTPParams> http_params_p,
	             const S3AuthParams &auth_params_p, const S3ConfigParams &config_params_p);
	~S3FileHandle() override;

	S3AuthParams &auth_params;
	const S3ConfigParams &config_params;
	shared_ptr<S3MultiPartUpload> multi_part_upload;

public:
	void Close() override;
	void Initialize(optional_ptr<FileOpener> opener) override;
	void FinalizeUpload();

protected:
	void InitializeFromCacheEntry(const HTTPMetadataCacheEntry &cache_entry) override;
	HTTPMetadataCacheEntry GetCacheEntry() const override;
	void SetRegion(string region_p);

protected:
	unique_ptr<HTTPClient> CreateClient() override;
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
	duckdb::unique_ptr<HTTPResponse> PostRequest(HTTPInput &input, string s3_url, HTTPHeaders header_map,
	                                             string &buffer_out, char *buffer_in, idx_t buffer_in_len,
	                                             string http_params = "") override;
	duckdb::unique_ptr<HTTPResponse> PutRequest(HTTPInput &input, string s3_url, HTTPHeaders header_map,
	                                            char *buffer_in, idx_t buffer_in_len, string http_params = "") override;
	duckdb::unique_ptr<HTTPResponse> DeleteRequest(FileHandle &handle, string s3_url, HTTPHeaders header_map) override;

	bool CanHandleFile(const string &fpath) override;
	bool OnDiskFile(FileHandle &handle) override {
		return false;
	}
	void RemoveFile(const string &filename, optional_ptr<FileOpener> opener = nullptr) override;
	void RemoveFiles(const vector<string> &filenames, optional_ptr<FileOpener> opener = nullptr) override;
	void RemoveDirectory(const string &directory, optional_ptr<FileOpener> opener = nullptr) override;
	void FileSync(FileHandle &handle) override;
	void Write(FileHandle &handle, void *buffer, int64_t nr_bytes, idx_t location) override;

	void ReadQueryParams(const string &url_query_param, S3AuthParams &params);
	static ParsedS3Url S3UrlParse(string url, const S3AuthParams &params);

	static string UrlEncode(const string &input, bool encode_slash = false);
	static string UrlDecode(string input);

	static string TryGetPrefix(const string &url);

	//! Wrapper around BufferManager::Allocate to limit the number of buffers
	BufferHandle Allocate(idx_t part_size, uint16_t max_threads);

	//! S3 is object storage so directories effectively always exist
	bool DirectoryExists(const string &directory, optional_ptr<FileOpener> opener = nullptr) override {
		return true;
	}

	static string GetS3BadRequestError(const S3AuthParams &s3_auth_params, string correct_region = "");
	static string ParseS3Error(const string &error);
	static string GetS3AuthError(const S3AuthParams &s3_auth_params);
	static string GetGCSAuthError(const S3AuthParams &s3_auth_params);
	static HTTPException GetS3Error(const S3AuthParams &s3_auth_params, const HTTPResponse &response,
	                                const string &url);
	HTTPException GetHTTPError(FileHandle &, const HTTPResponse &response, const string &url) override;

protected:
	bool ListFilesExtended(const string &directory, const std::function<void(OpenFileInfo &info)> &callback,
	                       optional_ptr<FileOpener> opener) override;
	bool SupportsListFilesExtended() const override {
		return true;
	}
	unique_ptr<MultiFileList> GlobFilesExtended(const string &path, const FileGlobInput &input,
	                                            optional_ptr<FileOpener> opener) override;
	bool SupportsGlobExtended() const override {
		return true;
	}

protected:
	static string GetPrefix(const string &url);
	duckdb::unique_ptr<HTTPFileHandle> CreateHandle(const OpenFileInfo &file, FileOpenFlags flags,
	                                                optional_ptr<FileOpener> opener) override;
	string GetPayloadHash(char *buffer, idx_t buffer_len);
};

// Helper class to do s3 ListObjectV2 api call https://docs.aws.amazon.com/AmazonS3/latest/API/API_ListObjectsV2.html
struct AWSListObjectV2 {
	static string Request(const string &path, HTTPParams &http_params, S3AuthParams &s3_auth_params,
	                      string &continuation_token, bool use_delimiter = false,
	                      optional_idx max_keys = optional_idx());
	static void ParseFileList(string &aws_response, vector<OpenFileInfo> &result);
	static vector<string> ParseCommonPrefix(string &aws_response);
	static string ParseContinuationToken(string &aws_response);
};

HTTPHeaders CreateS3Header(string url, string query, string host, string service, string method,
                           const S3AuthParams &auth_params, string date_now = "", string datetime_now = "",
                           string payload_hash = "", string content_type = "", string content_md5 = "");
} // namespace duckdb
