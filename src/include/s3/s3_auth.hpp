#pragma once

#include "s3/s3_provider.hpp"

#include "duckdb/common/file_opener.hpp"
#include "duckdb/main/config.hpp"
#include "duckdb/main/secret/secret_manager.hpp"

namespace duckdb {

enum class S3EndpointMode : uint8_t { AUTOMATIC, EXPLICIT };

class S3KeyValueReader {
public:
	S3KeyValueReader(FileOpener &opener_p, optional_ptr<FileOpenerInfo> info, const char **secret_types,
	                 idx_t secret_types_len);
	explicit S3KeyValueReader(const KeyValueSecretReader &reader);

public:
	template <class TYPE>
	SettingLookupResult TryGetSecretKeyOrSetting(const Identifier &secret_key, const Identifier &setting_name,
	                                             TYPE &result) {
		Value temp_result;
		auto setting_scope = reader.TryGetSecretKeyOrSetting(secret_key, setting_name, temp_result);
		if (!temp_result.IsNull() && !(setting_scope && setting_scope.GetScope() == SettingScope::GLOBAL &&
		                               !use_env_variables_for_secret_settings)) {
			result = temp_result.GetValue<TYPE>();
		}
		return setting_scope;
	}

	template <class TYPE>
	SettingLookupResult TryGetSecretKey(const Identifier &secret_key, TYPE &value_out) {
		return reader.TryGetSecretKey(secret_key, value_out);
	}

	template <class TYPE>
	SettingLookupResult TryGetSecretKeysOrSetting(const Identifier &secret_key, const Identifier &legacy_secret_key,
	                                              const Identifier &setting_name, TYPE &result) {
		Value temp_result;
		auto setting_scope = reader.TryGetSecretKey(secret_key, temp_result);
		if (!setting_scope) {
			setting_scope = reader.TryGetSecretKey(legacy_secret_key, temp_result);
		}
		if (!setting_scope) {
			setting_scope = reader.TryGetSecretKeyOrSetting(secret_key, setting_name, temp_result);
		}
		if (!temp_result.IsNull() && !(setting_scope && setting_scope.GetScope() == SettingScope::GLOBAL &&
		                               !use_env_variables_for_secret_settings)) {
			result = temp_result.GetValue<TYPE>();
		}
		return setting_scope;
	}

private:
	bool use_env_variables_for_secret_settings;
	KeyValueSecretReader reader;
};

struct S3AuthParams {
public:
	static S3AuthParams ReadFrom(optional_ptr<FileOpener> opener, FileOpenerInfo &info);
	static S3AuthParams ReadFrom(S3KeyValueReader &secret_reader, const string &file_path);
	void SetEndpoint(string endpoint_p);
	void SetRegion(string region_p);
	bool operator==(const S3AuthParams &other) const;

public:
	//! Provider and URL routing
	S3ProviderType provider_type = S3ProviderType::S3;
	bool scheme_is_alias = false;

	//! Authentication
	string region;
	string access_key_id;
	string secret_access_key;
	string session_token;
	string oauth2_bearer_token;

	//! Endpoint and URL behavior
	string endpoint;
	S3EndpointMode endpoint_mode = S3EndpointMode::AUTOMATIC;
	string url_style;
	bool use_ssl = true;
	bool s3_url_compatibility_mode = false;

	//! Request headers
	string kms_key_id;
	bool requester_pays = false;
	string user_project;
};

struct AWSEnvironmentCredentialsProvider {
public:
	explicit AWSEnvironmentCredentialsProvider(DBConfig &config) : config(config) {
	}

public:
	void SetExtensionOptionValue(const Identifier &key, const char *env_var);
	void SetAll();

public:
	static constexpr const char *REGION_ENV_VAR = "AWS_REGION";
	static constexpr const char *DEFAULT_REGION_ENV_VAR = "AWS_DEFAULT_REGION";
	static constexpr const char *ACCESS_KEY_ENV_VAR = "AWS_ACCESS_KEY_ID";
	static constexpr const char *SECRET_KEY_ENV_VAR = "AWS_SECRET_ACCESS_KEY";
	static constexpr const char *SESSION_TOKEN_ENV_VAR = "AWS_SESSION_TOKEN";
	static constexpr const char *DUCKDB_ENDPOINT_ENV_VAR = "DUCKDB_S3_ENDPOINT";
	static constexpr const char *DUCKDB_USE_SSL_ENV_VAR = "DUCKDB_S3_USE_SSL";
	static constexpr const char *DUCKDB_KMS_KEY_ID_ENV_VAR = "DUCKDB_S3_KMS_KEY_ID";
	static constexpr const char *DUCKDB_REQUESTER_PAYS_ENV_VAR = "DUCKDB_S3_REQUESTER_PAYS";

	DBConfig &config;
};

} // namespace duckdb
