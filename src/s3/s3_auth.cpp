#include "s3/s3_auth.hpp"

#include "s3/s3_url.hpp"

#include "duckdb/common/crypto/md5.hpp"
#include "duckdb/common/error_data.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/common/types/blob.hpp"

#include <cstdlib>

namespace duckdb {

S3SSECustomerKey::S3SSECustomerKey(string key_p, string key_md5_p)
    : key(std::move(key_p)), key_md5(std::move(key_md5_p)) {
}

S3SSECustomerKey S3SSECustomerKey::Create(const string &key) {
	string decoded_key;
	try {
		decoded_key = Blob::FromBase64(key);
	} catch (std::exception &) {
		throw InvalidInputException("SSE_C_KEY must be a valid base64-encoded 256-bit key");
	}
	if (decoded_key.size() != 32 || Blob::ToBase64(decoded_key) != key) {
		throw InvalidInputException("SSE_C_KEY must be a valid base64-encoded 256-bit key");
	}

	MD5Context md5_context;
	md5_context.Add(decoded_key);
	data_t md5_hash[MD5Context::MD5_HASH_LENGTH_BINARY];
	md5_context.Finish(md5_hash);
	string_t md5_blob(const_char_ptr_cast(md5_hash), MD5Context::MD5_HASH_LENGTH_BINARY);
	return S3SSECustomerKey(key, Blob::ToBase64(md5_blob));
}

bool S3SSECustomerKey::operator==(const S3SSECustomerKey &other) const {
	return key == other.key && key_md5 == other.key_md5;
}

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

bool S3AuthCredentials::HasAuthentication() const {
	return !HasSameAuthentication(S3AuthCredentials());
}

bool S3AuthCredentials::HasSameAuthentication(const S3AuthCredentials &other) const {
	return access_key_id == other.access_key_id && secret_access_key == other.secret_access_key &&
	       session_token == other.session_token && oauth2_bearer_token == other.oauth2_bearer_token;
}

bool S3AuthCredentials::operator==(const S3AuthCredentials &other) const {
	return region == other.region && HasSameAuthentication(other);
}

bool S3AuthURLParams::operator==(const S3AuthURLParams &other) const {
	return endpoint == other.endpoint && endpoint_mode == other.endpoint_mode && style == other.style &&
	       query_mode == other.query_mode;
}

bool S3AuthRequestOptions::operator==(const S3AuthRequestOptions &other) const {
	return kms_key_id == other.kms_key_id && sse_customer_key == other.sse_customer_key &&
	       requester_pays == other.requester_pays && user_project == other.user_project;
}

template <class T>
static void ApplyQueryParam(const optional<T> &option, T &value) {
	if (option) {
		value = *option;
	}
}

void S3AuthQueryParameters::ApplyCredentials(S3AuthCredentials &credentials) const {
	ApplyQueryParam(region, credentials.region);
	ApplyQueryParam(access_key_id, credentials.access_key_id);
	ApplyQueryParam(secret_access_key, credentials.secret_access_key);
	ApplyQueryParam(session_token, credentials.session_token);
}

S3AuthCredentials S3AuthQueryParameters::GetExplicitCredentials() const {
	S3AuthCredentials result;
	ApplyCredentials(result);
	return result;
}

bool S3AuthQueryParameters::OverridesSSECustomerKey() const {
	return sse_c_key.has_value();
}

void S3AuthQueryParameters::ApplyTo(S3AuthConfig &config) const {
	ApplyCredentials(config.credentials);
	ApplyQueryParam(use_ssl, config.use_ssl);
	ApplyQueryParam(url_style, config.url_style);
	ApplyQueryParam(requester_pays, config.request_options.requester_pays);
	ApplyQueryParam(user_project, config.request_options.user_project);
	if (endpoint) {
		config.endpoint = *endpoint;
		auto trimmed_endpoint = *endpoint;
		StringUtil::Trim(trimmed_endpoint);
		config.endpoint_mode = trimmed_endpoint.empty() ? S3EndpointMode::AUTOMATIC : S3EndpointMode::EXPLICIT;
	}
	if (sse_c_key) {
		if (sse_c_key->empty()) {
			config.request_options.sse_customer_key.reset();
		} else {
			// Restore unescaped '+' in base64 keys after URL decoding.
			auto key = StringUtil::Replace(*sse_c_key, " ", "+");
			try {
				config.request_options.sse_customer_key = S3SSECustomerKey::Create(key);
			} catch (InvalidInputException &) {
				throw IOException("Incorrect setting found for s3_sse_c_key, expected a base64-encoded 256-bit key "
				                  "(percent-encode '+' as %2B, '/' as %2F and '=' as %3D)");
			}
		}
	}
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
	string sse_c_key;
	if (secret_reader.TryGetSecretKey("sse_c_key", sse_c_key)) {
		request_options.sse_customer_key = S3SSECustomerKey::Create(sse_c_key);
	}
	bool compatibility_mode = false;
	secret_reader.TryGetSecretKeysOrSetting("url_compatibility_mode", "s3_url_compatibility_mode",
	                                        "s3_url_compatibility_mode", compatibility_mode);
	config.query_mode = compatibility_mode ? S3URLQueryMode::LITERAL_KEY : S3URLQueryMode::PARSE_OPTIONS;
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
	auto components = S3Url::Split(file_path, config.query_mode);
	if (components.query.empty()) {
		return ResolveConfig(std::move(config));
	}
	auto configured = config;
	auto url_options = S3Url::ParseAuthQueryParameters(components.query, config.route.type);
	url_options.ApplyTo(config);
	auto result = ResolveConfig(std::move(config));
	result.routing = ResolveRoutingPolicy(configured, result, url_options, file_path);
	result.ValidateInheritedMaterial(false);
	return result;
}

S3AuthRoutingPolicy S3AuthResolver::ResolveRoutingPolicy(const S3AuthConfig &configured, const S3AuthParams &resolved,
                                                         const S3AuthQueryParameters &url_options,
                                                         const string &file_path) {
	S3AuthRoutingPolicy result;
	result.inheritance = S3AuthRoutingPolicy::Inheritance::REQUIRE_EXPLICIT;
	result.has_inherited_credentials =
	    !resolved.credentials.HasSameAuthentication(url_options.GetExplicitCredentials());
	result.has_inherited_sse_key = resolved.request_options.sse_customer_key && !url_options.OverridesSSECustomerKey();
	S3AuthURLParams url;
	try {
		auto endpoint = S3Provider::ResolveEndpoint(configured);
		url = {std::move(endpoint.endpoint), endpoint.mode, endpoint.style, configured.query_mode};
	} catch (const InvalidInputException &ex) {
		result.configured_destination_error = ErrorData(ex).RawMessage();
		return result;
	} catch (const IOException &ex) {
		result.configured_destination_error = ErrorData(ex).RawMessage();
		return result;
	}
	// Failed URL comparisons cannot authorize inherited material, but are not
	// necessarily errors in the saved configuration (the URL supplies the bucket).
	try {
		if (url == resolved.GetURLParams() ||
		    S3Url::Parse(file_path, configured.route, url).GetBucketHTTPUrl() ==
		        S3Url::Parse(file_path, resolved).GetBucketHTTPUrl() ||
		    resolved.GetProvider().AllowsAutomaticEndpointChange(url, resolved.GetURLParams())) {
			result.inheritance = S3AuthRoutingPolicy::Inheritance::ALLOW_CONFIGURED;
		}
	} catch (const InvalidInputException &) {
	} catch (const IOException &) {
	}
	return result;
}

void S3AuthRoutingPolicy::ValidateInheritedMaterial(bool has_configured_headers) const {
	if (inheritance == Inheritance::ALLOW_CONFIGURED) {
		return;
	}
	vector<string> inherited_material;
	if (has_inherited_credentials) {
		inherited_material.emplace_back("credentials");
	}
	if (has_inherited_sse_key) {
		inherited_material.emplace_back("SSE-C encryption key (SSE_C_KEY)");
	}
	if (has_configured_headers) {
		inherited_material.emplace_back("HTTP headers");
	}
	if (inherited_material.empty()) {
		return;
	}
	auto material = StringUtil::Join(inherited_material, " and ");
	if (!configured_destination_error.empty()) {
		throw InvalidInputException(
		    "Cannot reuse configured %s because the configured S3 destination could not be resolved: %s. "
		    "Fix the destination configuration in the secret or settings.",
		    material, configured_destination_error);
	}
	throw InvalidInputException(
	    "URL options change the S3 destination, but the request uses %s from a secret or setting. "
	    "Configure the intended ENDPOINT, URL_STYLE and USE_SSL together with the %s.",
	    material, material);
}

bool S3AuthRoutingPolicy::operator==(const S3AuthRoutingPolicy &other) const {
	return inheritance == other.inheritance && has_inherited_credentials == other.has_inherited_credentials &&
	       has_inherited_sse_key == other.has_inherited_sse_key &&
	       configured_destination_error == other.configured_destination_error;
}

bool S3AuthParams::HasAuthenticationMaterial() const {
	return credentials.HasAuthentication() || request_options.sse_customer_key.has_value();
}

void S3AuthParams::ValidateInheritedMaterial(bool has_configured_headers) const {
	routing.ValidateInheritedMaterial(has_configured_headers);
}

S3AuthParams S3AuthResolver::ResolveConfig(S3AuthConfig config) {
	auto endpoint = S3Provider::ResolveEndpoint(config);
	auto &request_options = config.request_options;
	if (config.route.type == S3ProviderType::GCS && request_options.requester_pays &&
	    request_options.user_project.empty()) {
		throw InvalidInputException(
		    "GCS Requester Pays requires a billing project; set USER_PROJECT in the GCS secret, "
		    "set gcs_user_project, or pass gcs_user_project in the URL.");
	}
	S3AuthParams result;
	result.provider = S3Provider::Resolve(std::move(config.route), endpoint.endpoint);
	result.credentials = std::move(config.credentials);
	result.credentials.region = std::move(endpoint.region);
	result.url = {std::move(endpoint.endpoint), endpoint.mode, endpoint.style, config.query_mode};
	result.request_options = std::move(request_options);
	result.refresh_identity = {config.use_ssl};
	result.routing.has_inherited_credentials = result.credentials.HasAuthentication();
	result.routing.has_inherited_sse_key = result.request_options.sse_customer_key.has_value();
	if (result.request_options.sse_customer_key) {
		if (!result.request_options.kms_key_id.empty()) {
			throw InvalidInputException("SSE_C_KEY and KMS_KEY_ID cannot be configured together");
		}
		if (!result.provider.SupportsSSECustomerKey()) {
			throw InvalidInputException("SSE_C_KEY is only supported for S3-compatible endpoints");
		}
		if (!result.url.endpoint.UsesSSL()) {
			throw InvalidInputException("SSE_C_KEY requires an HTTPS endpoint");
		}
		if (result.credentials.access_key_id.empty() || result.credentials.secret_access_key.empty()) {
			throw InvalidInputException("SSE_C_KEY requires both KEY_ID and SECRET for signed S3 requests");
		}
	}
	return result;
}

S3AuthParams S3AuthParams::WithRegion(string region) const {
	auto result = *this;
	result.credentials.region = std::move(region);
	result.url.endpoint = result.provider.GetEndpointForRegion(result.url, result.credentials.region);
	result.provider = S3Provider::Resolve(result.provider.GetRoute(), result.url.endpoint);
	return result;
}

bool S3AuthParams::operator==(const S3AuthParams &other) const {
	return provider == other.provider && credentials == other.credentials && url == other.url &&
	       request_options == other.request_options && routing == other.routing;
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
