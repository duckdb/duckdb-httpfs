#pragma once

#include "s3/s3_endpoint.hpp"
#include "s3/s3_provider.hpp"

#include "duckdb/common/file_opener.hpp"
#include "duckdb/main/config.hpp"
#include "duckdb/main/secret/secret_manager.hpp"

namespace duckdb {

enum class S3EndpointMode : uint8_t { AUTOMATIC, EXPLICIT };

struct S3AuthCredentials {
	string region;
	string access_key_id;
	string secret_access_key;
	string session_token;
	string oauth2_bearer_token;

	bool operator==(const S3AuthCredentials &other) const;
};

struct S3AuthURLParams {
	static S3URLStyle ParseStyle(const string &url_style);

	NormalizedS3Endpoint endpoint;
	S3EndpointMode endpoint_mode = S3EndpointMode::AUTOMATIC;
	S3URLStyle style = S3URLStyle::VIRTUAL_HOSTED;
	bool compatibility_mode = false;

	bool operator==(const S3AuthURLParams &other) const;
};

struct S3AuthRequestOptions {
	string kms_key_id;
	bool requester_pays = false;
	string user_project;

	bool operator==(const S3AuthRequestOptions &other) const;
};

struct S3AuthRefreshIdentity {
	bool use_ssl = true;

	bool operator==(const S3AuthRefreshIdentity &other) const {
		return use_ssl == other.use_ssl;
	}
};

struct S3AuthConfig {
	//! Provider and URL routing
	S3ProviderMatch route {S3ProviderType::S3, "s3://"};

	//! Authentication
	S3AuthCredentials credentials;

	//! Endpoint and URL behavior
	string endpoint;
	S3EndpointMode endpoint_mode = S3EndpointMode::AUTOMATIC;
	string url_style;
	bool use_ssl = true;
	bool compatibility_mode = false;

	//! Request headers
	S3AuthRequestOptions request_options;
};

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

class S3AuthParams {
public:
	const S3Provider &GetProvider() const {
		return provider;
	}
	const S3AuthCredentials &GetCredentials() const {
		return credentials;
	}
	const S3AuthURLParams &GetURLParams() const {
		return url;
	}
	const S3AuthRequestOptions &GetRequestOptions() const {
		return request_options;
	}
	const S3AuthRefreshIdentity &GetRefreshIdentity() const {
		return refresh_identity;
	}
	S3AuthParams WithRegion(string region) const;
	bool operator==(const S3AuthParams &other) const;

private:
	friend struct S3AuthResolver;
	S3AuthParams();

	S3Provider provider;
	S3AuthCredentials credentials;
	S3AuthURLParams url;
	S3AuthRequestOptions request_options;
	S3AuthRefreshIdentity refresh_identity;
};

struct S3AuthResolver {
	static S3AuthParams Resolve(optional_ptr<FileOpener> opener, FileOpenerInfo &info);
	static S3AuthParams Resolve(S3KeyValueReader &secret_reader, const string &file_path);
	static S3AuthParams Resolve(S3AuthConfig config, const string &file_path);

private:
	static S3AuthConfig ReadConfig(S3KeyValueReader &secret_reader, const string &file_path);
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
