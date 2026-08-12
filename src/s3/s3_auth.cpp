#include "s3/s3_auth.hpp"

#include <cstdlib>

namespace duckdb {

void AWSEnvironmentCredentialsProvider::SetExtensionOptionValue(const Identifier &key, const char *env_var_name) {
	const auto env_value = std::getenv(env_var_name);
	if (env_value) {
		if (StringUtil::Lower(env_value) == "false") {
			this->config.SetOption(key, Value(false));
		} else if (StringUtil::Lower(env_value) == "true") {
			this->config.SetOption(key, Value(true));
		} else {
			this->config.SetOption(key, Value(env_value));
		}
	}
}

void AWSEnvironmentCredentialsProvider::SetAll() {
	this->SetExtensionOptionValue("s3_region", DEFAULT_REGION_ENV_VAR);
	this->SetExtensionOptionValue("s3_region", REGION_ENV_VAR);
	this->SetExtensionOptionValue("s3_access_key_id", ACCESS_KEY_ENV_VAR);
	this->SetExtensionOptionValue("s3_secret_access_key", SECRET_KEY_ENV_VAR);
	this->SetExtensionOptionValue("s3_session_token", SESSION_TOKEN_ENV_VAR);
	this->SetExtensionOptionValue("s3_endpoint", DUCKDB_ENDPOINT_ENV_VAR);
	this->SetExtensionOptionValue("s3_use_ssl", DUCKDB_USE_SSL_ENV_VAR);
	this->SetExtensionOptionValue("s3_kms_key_id", DUCKDB_KMS_KEY_ID_ENV_VAR);
	this->SetExtensionOptionValue("s3_requester_pays", DUCKDB_REQUESTER_PAYS_ENV_VAR);
}

S3AuthParams S3AuthParams::ReadFrom(optional_ptr<FileOpener> opener, FileOpenerInfo &info) {
	// Without a FileOpener we can not access settings nor secrets: return empty auth params
	if (!opener) {
		auto result = S3AuthParams();
		result.provider_type = S3Provider::MatchUrl(info.file_path).type;
		return result;
	}

	auto secret_types = S3Provider::SecretTypes();
	S3KeyValueReader secret_reader(*opener, info, secret_types.data(), secret_types.size());

	return ReadFrom(secret_reader, info.file_path);
}

S3AuthParams S3AuthParams::ReadFrom(S3KeyValueReader &secret_reader, const string &file_path) {
	auto result = S3AuthParams();
	S3Provider::ReadAuthParams(secret_reader, file_path, result);
	return result;
}

void S3AuthParams::SetRegion(string new_region) {
	region = std::move(new_region);
	S3Provider::InitializeAuthParams(*this);
}

bool S3AuthParams::operator==(const S3AuthParams &other) const {
	return provider_type == other.provider_type && region == other.region && access_key_id == other.access_key_id &&
	       secret_access_key == other.secret_access_key && session_token == other.session_token &&
	       endpoint == other.endpoint && kms_key_id == other.kms_key_id && url_style == other.url_style &&
	       use_ssl == other.use_ssl && s3_url_compatibility_mode == other.s3_url_compatibility_mode &&
	       requester_pays == other.requester_pays && oauth2_bearer_token == other.oauth2_bearer_token;
}

S3KeyValueReader::S3KeyValueReader(FileOpener &opener_p, optional_ptr<FileOpenerInfo> info, const char **secret_types,
                                   const idx_t secret_types_len)
    : S3KeyValueReader(KeyValueSecretReader {opener_p, info, secret_types, secret_types_len}) {
}

S3KeyValueReader::S3KeyValueReader(const KeyValueSecretReader &_reader) : reader(_reader) {
	Value use_env_vars_for_secret_info_setting;
	reader.TryGetSecretKeyOrSetting("enable_global_s3_configuration", "enable_global_s3_configuration",
	                                use_env_vars_for_secret_info_setting);
	use_env_variables_for_secret_settings = use_env_vars_for_secret_info_setting.GetValue<bool>();
}

} // namespace duckdb
