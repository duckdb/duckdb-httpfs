#include "s3/s3_auth.hpp"

#include "s3/s3_url.hpp"

#include "duckdb/common/string_util.hpp"

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

S3AuthParams::S3AuthParams() = default;

bool S3AuthCredentials::operator==(const S3AuthCredentials &other) const {
	return region == other.region && access_key_id == other.access_key_id &&
	       secret_access_key == other.secret_access_key && session_token == other.session_token &&
	       oauth2_bearer_token == other.oauth2_bearer_token;
}

bool S3AuthURLParams::operator==(const S3AuthURLParams &other) const {
	return endpoint == other.endpoint && endpoint_mode == other.endpoint_mode && style == other.style &&
	       compatibility_mode == other.compatibility_mode;
}

bool S3AuthRequestOptions::operator==(const S3AuthRequestOptions &other) const {
	return kms_key_id == other.kms_key_id && requester_pays == other.requester_pays &&
	       user_project == other.user_project;
}

S3AuthParams S3AuthResolver::Resolve(optional_ptr<FileOpener> opener, FileOpenerInfo &info) {
	// Without a FileOpener we cannot access settings or secrets.
	if (!opener) {
		S3AuthConfig config;
		config.route = S3UrlScheme::MatchRoutedUrl(info.file_path);
		return Resolve(std::move(config), info.file_path);
	}

	auto secret_types = S3SecretConfig::SecretTypes();
	S3KeyValueReader secret_reader(*opener, info, secret_types.data(), secret_types.size());
	return Resolve(secret_reader, info.file_path);
}

S3AuthParams S3AuthResolver::Resolve(S3KeyValueReader &secret_reader, const string &file_path) {
	return Resolve(ReadConfig(secret_reader, file_path), file_path);
}

static void SetEndpoint(S3AuthConfig &config, string endpoint) {
	config.endpoint = std::move(endpoint);
	auto trimmed_endpoint = config.endpoint;
	StringUtil::Trim(trimmed_endpoint);
	config.endpoint_mode = trimmed_endpoint.empty() ? S3EndpointMode::AUTOMATIC : S3EndpointMode::EXPLICIT;
}

S3AuthConfig S3AuthResolver::ReadConfig(S3KeyValueReader &secret_reader, const string &file_path) {
	S3AuthConfig config;
	config.route = S3UrlScheme::MatchRoutedUrl(file_path);
	auto &credentials = config.credentials;
	auto &request_options = config.request_options;
	secret_reader.TryGetSecretKeyOrSetting("region", "s3_region", credentials.region);
	secret_reader.TryGetSecretKeyOrSetting("key_id", "s3_access_key_id", credentials.access_key_id);
	secret_reader.TryGetSecretKeyOrSetting("secret", "s3_secret_access_key", credentials.secret_access_key);
	secret_reader.TryGetSecretKeyOrSetting("session_token", "s3_session_token", credentials.session_token);
	secret_reader.TryGetSecretKeyOrSetting("use_ssl", "s3_use_ssl", config.use_ssl);
	secret_reader.TryGetSecretKeyOrSetting("kms_key_id", "s3_kms_key_id", request_options.kms_key_id);
	secret_reader.TryGetSecretKeysOrSetting("url_compatibility_mode", "s3_url_compatibility_mode",
	                                        "s3_url_compatibility_mode", config.compatibility_mode);
	secret_reader.TryGetSecretKeyOrSetting("requester_pays", "s3_requester_pays", request_options.requester_pays);

	string endpoint;
	auto endpoint_result = secret_reader.TryGetSecretKeyOrSetting("endpoint", "s3_endpoint", endpoint);
	auto url_style_result = secret_reader.TryGetSecretKeyOrSetting("url_style", "s3_url_style", config.url_style);
	if (config.route.type == S3ProviderType::GCS) {
		if (endpoint_result && endpoint_result.GetScope() == SettingScope::SECRET) {
			SetEndpoint(config, std::move(endpoint));
		}
		if (config.url_style.empty() || !url_style_result || url_style_result.GetScope() != SettingScope::SECRET) {
			config.url_style = "path";
		}
		secret_reader.TryGetSecretKeyOrSetting("user_project", "gcs_user_project", request_options.user_project);
		secret_reader.TryGetSecretKey("bearer_token", credentials.oauth2_bearer_token);
	} else {
		SetEndpoint(config, std::move(endpoint));
	}
	return config;
}

static bool EndpointIsAWS(const NormalizedS3Endpoint &endpoint) {
	if (endpoint.IsEmpty()) {
		return true;
	}
	return StringUtil::StartsWith(endpoint.GetHost(), "s3.") &&
	       StringUtil::EndsWith(endpoint.GetHost(), ".amazonaws.com");
}

static bool EndpointIsUnresolved(const string &endpoint) {
	auto trimmed_endpoint = endpoint;
	StringUtil::Trim(trimmed_endpoint);
	return trimmed_endpoint.empty();
}

S3URLStyle S3AuthURLParams::ParseStyle(const string &url_style) {
	if (url_style.empty() || url_style == "vhost" || url_style == "virtual") {
		return S3URLStyle::VIRTUAL_HOSTED;
	}
	if (url_style == "path") {
		return S3URLStyle::PATH;
	}
	throw InvalidInputException("Invalid S3 URL style '%s': expected 'vhost', 'virtual', 'path', or an empty string",
	                            url_style);
}

S3AuthParams S3AuthResolver::Resolve(S3AuthConfig config, const string &file_path) {
	S3Url::ApplyAuthQueryParameters(file_path, config);
	auto &credentials = config.credentials;
	auto &request_options = config.request_options;

	if (config.route.type == S3ProviderType::GCS) {
		if (EndpointIsUnresolved(config.endpoint)) {
			config.endpoint = "storage.googleapis.com";
			config.endpoint_mode = S3EndpointMode::AUTOMATIC;
		}
		if (config.url_style.empty()) {
			config.url_style = "path";
		}
		if (credentials.region.empty() && credentials.oauth2_bearer_token.empty() &&
		    (!credentials.secret_access_key.empty() || !credentials.access_key_id.empty())) {
			credentials.region = "auto";
		}
	}

	auto style = S3AuthURLParams::ParseStyle(config.url_style);
	if (config.route.type == S3ProviderType::GCS && request_options.requester_pays &&
	    request_options.user_project.empty()) {
		throw InvalidInputException(
		    "GCS Requester Pays requires a billing project; set USER_PROJECT in the GCS secret, "
		    "set gcs_user_project, or pass gcs_user_project in the URL.");
	}
	if ((config.route.IsAlias() || config.route.type == S3ProviderType::R2) && EndpointIsUnresolved(config.endpoint)) {
		if (config.route.type == S3ProviderType::R2) {
			throw IOException("R2 requires an endpoint; provide account_id in the secret or s3_endpoint in the URL");
		}
		throw IOException("An aliased URL scheme requires an endpoint; provide ENDPOINT in the secret, set "
		                  "s3_endpoint, or pass s3_endpoint in the URL");
	}

	auto endpoint = NormalizedS3Endpoint::Parse(config.endpoint, config.use_ssl);
	if (config.route.type == S3ProviderType::S3 && !config.route.IsAlias() &&
	    endpoint.GetHost() == "s3.amazonaws.com" && endpoint.GetBasePath().empty() && endpoint.IsDefaultPort()) {
		config.endpoint_mode = S3EndpointMode::AUTOMATIC;
	}
	if (config.route.type == S3ProviderType::S3 &&
	    (config.endpoint_mode == S3EndpointMode::AUTOMATIC || EndpointIsAWS(endpoint))) {
		if (credentials.region.empty()) {
			if (credentials.access_key_id.empty()) {
				if (config.endpoint_mode == S3EndpointMode::AUTOMATIC) {
					endpoint.SetHost("s3.amazonaws.com");
				}
			} else {
				credentials.region = "us-east-1";
			}
		}
		if (config.endpoint_mode == S3EndpointMode::AUTOMATIC && !credentials.region.empty()) {
			endpoint.SetHost(StringUtil::Format("s3.%s.amazonaws.com", credentials.region));
		}
	}

	S3AuthParams result;
	result.provider = S3Provider::Resolve(std::move(config.route), endpoint);
	result.credentials = std::move(credentials);
	result.url = {std::move(endpoint), config.endpoint_mode, style, config.compatibility_mode};
	result.request_options = std::move(request_options);
	result.refresh_identity = {config.use_ssl};
	return result;
}

S3AuthParams S3AuthParams::WithRegion(string region) const {
	auto result = *this;
	result.credentials.region = std::move(region);
	if (result.provider.GetType() == S3ProviderType::S3 && result.url.endpoint_mode == S3EndpointMode::AUTOMATIC) {
		result.url.endpoint.SetHost(StringUtil::Format("s3.%s.amazonaws.com", result.credentials.region));
	}
	result.provider = S3Provider::Resolve(result.provider.GetRoute(), result.url.endpoint);
	return result;
}

bool S3AuthParams::operator==(const S3AuthParams &other) const {
	return provider == other.provider && credentials == other.credentials && url == other.url &&
	       request_options == other.request_options;
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
