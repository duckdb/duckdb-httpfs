#include "s3/s3_provider.hpp"

#include "s3/s3_auth.hpp"

#include "duckdb/common/string_util.hpp"
#include "duckdb/common/types/value.hpp"
#include "duckdb/main/config.hpp"
#include "duckdb/main/extension_entries.hpp"
#include "duckdb/main/secret/secret.hpp"

#include <algorithm>

namespace duckdb {

bool S3MultipartUploadPolicy::operator==(const S3MultipartUploadPolicy &other) const {
	return part_size_strategy == other.part_size_strategy && minimum_part_size == other.minimum_part_size &&
	       maximum_part_size == other.maximum_part_size && maximum_part_count == other.maximum_part_count &&
	       maximum_object_size == other.maximum_object_size;
}

static const array<S3ProviderMatch, 6> &ProviderMatches() {
	static const array<S3ProviderMatch, 6> provider_matches = {
	    S3ProviderMatch {S3ProviderType::S3, "s3://"},  S3ProviderMatch {S3ProviderType::S3, "s3a://"},
	    S3ProviderMatch {S3ProviderType::S3, "s3n://"}, S3ProviderMatch {S3ProviderType::GCS, "gcs://"},
	    S3ProviderMatch {S3ProviderType::GCS, "gs://"}, S3ProviderMatch {S3ProviderType::R2, "r2://"}};
	return provider_matches;
}

static bool SchemeIsReserved(const string &scheme) {
	auto prefix = scheme + "://";
	for (const auto &provider_match : ProviderMatches()) {
		if (prefix == provider_match.prefix) {
			return true;
		}
	}
	// Schemes core maps to an extension, so an alias cannot keep that extension from being autoloaded
	for (const auto &entry : EXTENSION_FILE_PREFIXES) {
		if (prefix == entry.name) {
			return true;
		}
	}
	// Schemes that table misses: 'file' is the VFS fallback the core registry does not list, and the
	// azure extension serves 'abfs' alongside the 'abfss' the table does list
	return scheme == "file" || scheme == "abfs";
}

static bool SchemeSyntaxIsValid(const string &scheme) {
	if (scheme.empty() || !StringUtil::CharacterIsAlpha(scheme[0])) {
		return false;
	}
	for (idx_t i = 1; i < scheme.size(); i++) {
		if (!StringUtil::CharacterIsAlphaNumeric(scheme[i]) && scheme[i] != '+' && scheme[i] != '-' &&
		    scheme[i] != '.') {
			return false;
		}
	}
	return true;
}

Value S3Provider::NormalizeSchemeAliases(const Value &aliases) {
	vector<Value> normalized;
	vector<string> seen;
	if (aliases.IsNull()) {
		return Value::LIST(LogicalType::VARCHAR, std::move(normalized));
	}
	for (auto &element : ListValue::GetChildren(aliases)) {
		if (element.IsNull()) {
			throw InvalidInputException("s3_url_scheme_aliases does not accept NULL elements");
		}
		auto alias = StringUtil::Lower(element.ToString());
		StringUtil::Trim(alias);
		if (!SchemeSyntaxIsValid(alias)) {
			throw InvalidInputException("Invalid URL scheme alias '%s': provide bare scheme names such as 'oss'",
			                            element.ToString());
		}
		if (SchemeIsReserved(alias)) {
			throw InvalidInputException(
			    "Scheme '%s' is already handled by a built-in filesystem and cannot be added to "
			    "'s3_url_scheme_aliases'",
			    alias);
		}
		if (std::find(seen.begin(), seen.end(), alias) != seen.end()) {
			continue;
		}
		seen.push_back(alias);
		normalized.emplace_back(std::move(alias));
	}
	return Value::LIST(LogicalType::VARCHAR, std::move(normalized));
}

vector<string> S3Provider::GetSchemeAliasPrefixes(const DBConfig &config) {
	Value value;
	if (!config.TryGetCurrentSetting("s3_url_scheme_aliases", value) || value.IsNull() ||
	    value.type().id() != LogicalTypeId::LIST) {
		return {};
	}
	vector<string> result;
	for (auto &element : ListValue::GetChildren(value)) {
		if (element.IsNull()) {
			continue;
		}
		// Values that were stored without going through the setting callback are filtered here rather
		// than trusted: a reserved scheme would otherwise hijack the filesystem that owns it
		auto alias = StringUtil::Lower(element.ToString());
		if (!SchemeSyntaxIsValid(alias) || SchemeIsReserved(alias)) {
			continue;
		}
		result.push_back(alias + "://");
	}
	return result;
}

const array<const char *, 4> &S3Provider::SecretTypes() {
	static constexpr array<const char *, 4> SECRET_TYPES = {S3_SECRET_TYPE, R2_SECRET_TYPE, GCS_SECRET_TYPE,
	                                                        AWS_SECRET_TYPE};
	return SECRET_TYPES;
}

const array<const char *, 13> &S3Provider::CredentialMaterialKeys() {
	static constexpr array<const char *, 13> CREDENTIAL_MATERIAL_KEYS = {
	    "key_id",    "secret",  "session_token",          "region",         "endpoint",     "kms_key_id",
	    "url_style", "use_ssl", "url_compatibility_mode", "requester_pays", "bearer_token", "user_project",
	    "account_id"};
	return CREDENTIAL_MATERIAL_KEYS;
}

optional<S3ProviderMatch> S3Provider::TryMatchUrl(const string &url) {
	auto lower_url = StringUtil::Lower(url);
	for (const auto &provider_match : ProviderMatches()) {
		if (StringUtil::StartsWith(lower_url, provider_match.prefix)) {
			return provider_match;
		}
	}
	return {};
}

optional<S3ProviderMatch> S3Provider::TryMatchUrl(const string &url, const vector<string> &scheme_alias_prefixes) {
	auto provider_match = TryMatchUrl(url);
	if (provider_match) {
		return provider_match;
	}
	// Aliased schemes are served by the plain S3 provider
	auto lower_url = StringUtil::Lower(url);
	for (auto &prefix : scheme_alias_prefixes) {
		if (StringUtil::StartsWith(lower_url, prefix)) {
			return S3ProviderMatch {S3ProviderType::S3, prefix};
		}
	}
	return {};
}

S3ProviderMatch S3Provider::MatchUrl(const string &url) {
	auto provider_match = TryMatchUrl(url);
	if (!provider_match) {
		vector<string> prefixes;
		for (const auto &entry : ProviderMatches()) {
			prefixes.push_back(entry.prefix);
		}
		throw IOException("URL needs to start with %s (or a scheme listed in the 's3_url_scheme_aliases' setting)",
		                  StringUtil::Join(prefixes, ", "));
	}
	return *provider_match;
}

vector<string> S3Provider::DefaultSecretScope(const string &secret_type) {
	if (secret_type == S3_SECRET_TYPE) {
		return {"s3://", "s3n://", "s3a://"};
	}
	if (secret_type == R2_SECRET_TYPE) {
		return {"r2://"};
	}
	if (secret_type == GCS_SECRET_TYPE) {
		return {"gcs://", "gs://"};
	}
	if (secret_type == AWS_SECRET_TYPE) {
		return {""};
	}
	throw InternalException("Unknown secret type found in httpfs extension: '%s'", secret_type);
}

void S3Provider::SetSecretNamedParameters(const string &secret_type, CreateSecretFunction &function) {
	if (secret_type == R2_SECRET_TYPE) {
		function.named_parameters["account_id"] = LogicalType::VARCHAR;
	} else if (secret_type == GCS_SECRET_TYPE) {
		function.named_parameters["bearer_token"] = LogicalType::VARCHAR;
		function.named_parameters["user_project"] = LogicalType::VARCHAR;
	}
}

void S3Provider::ApplySecretDefaults(const CreateSecretInput &input, KeyValueSecret &secret) {
	if (input.type != R2_SECRET_TYPE) {
		return;
	}
	auto account_id = input.options.find("account_id");
	if (account_id == input.options.end()) {
		return;
	}
	secret.secret_map["endpoint"] = account_id->second.ToString() + ".r2.cloudflarestorage.com";
	secret.secret_map["url_style"] = "path";
}

bool S3Provider::TryApplySecretOption(const CreateSecretInput &input, const string &name, const Value &value,
                                      KeyValueSecret &secret) {
	if (name == "account_id" && input.type == R2_SECRET_TYPE) {
		return true;
	}
	if (name == "bearer_token" && input.type == GCS_SECRET_TYPE) {
		secret.secret_map["bearer_token"] = value.ToString();
		secret.redact_keys.insert("bearer_token");
		return true;
	}
	if (name == "user_project" && input.type == GCS_SECRET_TYPE) {
		secret.secret_map["user_project"] = value.ToString();
		return true;
	}
	return false;
}

void S3Provider::ReadAuthParams(S3KeyValueReader &secret_reader, const string &file_path, S3AuthParams &result) {
	// Routing already accepted the path, so a non-built-in scheme is an alias served by plain S3
	auto provider_match = TryMatchUrl(file_path);
	result.provider_type = provider_match ? provider_match->type : S3ProviderType::S3;
	result.scheme_is_alias = !provider_match;
	secret_reader.TryGetSecretKeyOrSetting("region", "s3_region", result.region);
	secret_reader.TryGetSecretKeyOrSetting("key_id", "s3_access_key_id", result.access_key_id);
	secret_reader.TryGetSecretKeyOrSetting("secret", "s3_secret_access_key", result.secret_access_key);
	secret_reader.TryGetSecretKeyOrSetting("session_token", "s3_session_token", result.session_token);
	secret_reader.TryGetSecretKeyOrSetting("use_ssl", "s3_use_ssl", result.use_ssl);
	secret_reader.TryGetSecretKeyOrSetting("kms_key_id", "s3_kms_key_id", result.kms_key_id);
	secret_reader.TryGetSecretKeysOrSetting("url_compatibility_mode", "s3_url_compatibility_mode",
	                                        "s3_url_compatibility_mode", result.s3_url_compatibility_mode);
	secret_reader.TryGetSecretKeyOrSetting("requester_pays", "s3_requester_pays", result.requester_pays);

	string endpoint;
	auto endpoint_result = secret_reader.TryGetSecretKeyOrSetting("endpoint", "s3_endpoint", endpoint);
	auto url_style_result = secret_reader.TryGetSecretKeyOrSetting("url_style", "s3_url_style", result.url_style);
	if (result.provider_type == S3ProviderType::GCS) {
		if (endpoint_result && endpoint_result.GetScope() == SettingScope::SECRET) {
			result.SetEndpoint(std::move(endpoint));
		}
		if (result.url_style.empty() || !url_style_result || url_style_result.GetScope() != SettingScope::SECRET) {
			result.url_style = "path";
		}
		secret_reader.TryGetSecretKeyOrSetting("user_project", "gcs_user_project", result.user_project);
		secret_reader.TryGetSecretKey("bearer_token", result.oauth2_bearer_token);
	} else {
		result.SetEndpoint(std::move(endpoint));
	}
	InitializeAuthParams(result);
}

static bool EndpointIsAWS(const string &endpoint) {
	if (endpoint.empty()) {
		return true;
	}
	return StringUtil::StartsWith(endpoint, "s3.") && StringUtil::EndsWith(endpoint, ".amazonaws.com");
}

//! Not AWS, so deriving an AWS endpoint would sign a request to the wrong host
static bool RequiresExplicitEndpoint(const S3AuthParams &auth_params) {
	return auth_params.scheme_is_alias || auth_params.provider_type == S3ProviderType::R2;
}

static bool EndpointIsUnresolved(const S3AuthParams &auth_params) {
	auto endpoint = auth_params.endpoint;
	StringUtil::Trim(endpoint);
	return endpoint.empty();
}

//! Re-applied in both phases: url query parameters can clear these between them
static void ApplyProviderDefaults(S3AuthParams &auth_params) {
	if (auth_params.provider_type != S3ProviderType::GCS) {
		return;
	}
	if (EndpointIsUnresolved(auth_params)) {
		auth_params.endpoint = "storage.googleapis.com";
		auth_params.endpoint_mode = S3EndpointMode::AUTOMATIC;
	}
	if (auth_params.url_style.empty()) {
		auth_params.url_style = "path";
	}
}

static void ApplyDerivedDefaults(S3AuthParams &auth_params) {
	if (auth_params.provider_type == S3ProviderType::GCS) {
		if (auth_params.region.empty() && S3Provider::GetAuthType(auth_params) == S3AuthType::SIGV4) {
			auth_params.region = "auto";
		}
		return;
	}
	if (auth_params.provider_type != S3ProviderType::S3 ||
	    (auth_params.endpoint_mode == S3EndpointMode::EXPLICIT && !EndpointIsAWS(auth_params.endpoint))) {
		return;
	}
	if (auth_params.region.empty()) {
		if (auth_params.access_key_id.empty()) {
			if (auth_params.endpoint_mode == S3EndpointMode::AUTOMATIC) {
				auth_params.endpoint = "s3.amazonaws.com";
			}
			return;
		}
		auth_params.region = "us-east-1";
	}
	if (auth_params.endpoint_mode == S3EndpointMode::AUTOMATIC) {
		auth_params.endpoint = StringUtil::Format("s3.%s.amazonaws.com", auth_params.region);
	}
}

void S3Provider::InitializeAuthParams(S3AuthParams &auth_params) {
	ApplyProviderDefaults(auth_params);
	ParseURLStyle(auth_params.url_style);
	if (RequiresExplicitEndpoint(auth_params) && EndpointIsUnresolved(auth_params)) {
		// Url query parameters still get to supply one; FinalizeAuthParams rejects it if none did
		return;
	}
	ApplyDerivedDefaults(auth_params);
}

void S3Provider::FinalizeAuthParams(S3AuthParams &auth_params) {
	ApplyProviderDefaults(auth_params);
	ParseURLStyle(auth_params.url_style);
	if (auth_params.provider_type == S3ProviderType::GCS && auth_params.requester_pays &&
	    auth_params.user_project.empty()) {
		throw InvalidInputException(
		    "GCS Requester Pays requires a billing project; set USER_PROJECT in the GCS secret, "
		    "set gcs_user_project, or pass gcs_user_project in the URL.");
	}
	if (RequiresExplicitEndpoint(auth_params) && EndpointIsUnresolved(auth_params)) {
		if (auth_params.provider_type == S3ProviderType::R2) {
			throw IOException("R2 requires an endpoint; provide account_id in the secret or s3_endpoint in the URL");
		}
		throw IOException("An aliased URL scheme requires an endpoint; provide ENDPOINT in the secret, set "
		                  "s3_endpoint, or pass s3_endpoint in the URL");
	}
	ApplyDerivedDefaults(auth_params);
}

S3URLStyle S3Provider::ParseURLStyle(const string &url_style) {
	if (url_style.empty() || url_style == "vhost" || url_style == "virtual") {
		return S3URLStyle::VIRTUAL_HOSTED;
	}
	if (url_style == "path") {
		return S3URLStyle::PATH;
	}
	throw InvalidInputException("Invalid S3 URL style '%s': expected 'vhost', 'virtual', 'path', or an empty string",
	                            url_style);
}

S3AuthType S3Provider::GetAuthType(const S3AuthParams &auth_params) {
	if (auth_params.provider_type == S3ProviderType::GCS && !auth_params.oauth2_bearer_token.empty()) {
		return S3AuthType::BEARER;
	}
	if (auth_params.secret_access_key.empty() && auth_params.access_key_id.empty()) {
		return S3AuthType::ANONYMOUS;
	}
	return S3AuthType::SIGV4;
}

static bool EndpointIsR2(const string &endpoint) {
	static const string R2_ENDPOINT_SUFFIX = ".r2.cloudflarestorage.com";
	auto host = endpoint.substr(0, endpoint.find('/'));
	host = host.substr(0, host.find(':'));
	host = StringUtil::Lower(host);
	if (!StringUtil::EndsWith(host, R2_ENDPOINT_SUFFIX)) {
		return false;
	}
	auto prefix = host.substr(0, host.size() - R2_ENDPOINT_SUFFIX.size());
	auto separator = prefix.find('.');
	if (prefix.empty() || separator == 0) {
		return false;
	}
	if (separator == string::npos) {
		return true;
	}
	auto jurisdiction = prefix.substr(separator + 1);
	return jurisdiction == "eu" || jurisdiction == "us" || jurisdiction == "fedramp";
}

static bool UsesR2CompatibilityProfile(const S3AuthParams &auth_params) {
	return auth_params.provider_type == S3ProviderType::R2 ||
	       (auth_params.provider_type == S3ProviderType::S3 && EndpointIsR2(auth_params.endpoint));
}

static S3MultipartUploadPolicy DefaultMultipartUploadPolicy() {
	static constexpr idx_t MIB = 1024ULL * 1024ULL;
	static constexpr idx_t GIB = 1024ULL * MIB;
	return {S3MultipartPartSizeStrategy::ADAPTIVE, 5ULL * MIB, 5ULL * GIB, 10000, optional_idx()};
}

static S3MultipartUploadPolicy R2MultipartUploadPolicy() {
	static constexpr idx_t MIB = 1024ULL * 1024ULL;
	static constexpr idx_t GIB = 1024ULL * MIB;
	static constexpr idx_t MAXIMUM_PART_SIZE = 5ULL * GIB - 5ULL * MIB;
	static constexpr idx_t MAXIMUM_OBJECT_SIZE = 5ULL * 1024ULL * GIB - 5ULL * GIB;
	return {S3MultipartPartSizeStrategy::FIXED, 8ULL * MIB, MAXIMUM_PART_SIZE, 10000, MAXIMUM_OBJECT_SIZE};
}

S3MultipartUploadPolicy S3Provider::GetMultipartUploadPolicy(const S3AuthParams &auth_params) {
	if (UsesR2CompatibilityProfile(auth_params)) {
		return R2MultipartUploadPolicy();
	}
	return DefaultMultipartUploadPolicy();
}

idx_t S3Provider::GetBulkDeleteMaxBatchSize(const S3AuthParams &auth_params) {
	return UsesR2CompatibilityProfile(auth_params) ? 700 : 1000;
}

string S3Provider::GetBadRequestError(const S3AuthParams &auth_params, const string &correct_region) {
	if (auth_params.provider_type != S3ProviderType::S3) {
		return {};
	}
	string extra_text = "\n\nBad Request - this can be caused by the S3 region being set incorrectly.";
	if (auth_params.region.empty()) {
		extra_text += "\n* No region is provided.";
	} else {
		extra_text += "\n* Provided region is: \"" + auth_params.region + "\"";
	}
	if (!correct_region.empty()) {
		extra_text += "\n* Correct region is: \"" + correct_region + "\"";
	}
	return extra_text;
}

string S3Provider::GetAuthError(const S3AuthParams &auth_params) {
	if (auth_params.provider_type == S3ProviderType::GCS) {
		string extra_text = "\n\nAuthentication Failure - GCS authentication failed.";
		if (auth_params.oauth2_bearer_token.empty() && auth_params.secret_access_key.empty() &&
		    auth_params.access_key_id.empty()) {
			extra_text += "\n* No credentials provided.";
			extra_text += "\n* For OAuth2: CREATE SECRET (TYPE GCS, bearer_token 'your-token')";
			extra_text += "\n* For HMAC: CREATE SECRET (TYPE GCS, key_id 'key', secret 'secret')";
		} else if (!auth_params.oauth2_bearer_token.empty()) {
			extra_text += "\n* Bearer token was provided but authentication failed.";
			extra_text += "\n* Ensure your OAuth2 token is valid and not expired.";
		} else {
			extra_text += "\n* HMAC credentials were provided but authentication failed.";
			extra_text += "\n* Ensure your HMAC key_id and secret are correct.";
		}
		return extra_text;
	}
	if (auth_params.provider_type == S3ProviderType::R2) {
		string extra_text = "\n\nAuthentication Failure - R2 authentication failed.";
		if (auth_params.secret_access_key.empty() && auth_params.access_key_id.empty()) {
			extra_text += "\n* No credentials are provided.";
			extra_text += "\n* Create an R2 secret with account_id, key_id, and secret.";
		} else {
			extra_text += "\n* Credentials were provided, but they did not work.";
		}
		return extra_text;
	}

	string extra_text = "\n\nAuthentication Failure - this is usually caused by invalid or missing credentials.";
	if (auth_params.secret_access_key.empty() && auth_params.access_key_id.empty()) {
		extra_text += "\n* No credentials are provided.";
	} else {
		extra_text += "\n* Credentials are provided, but they did not work.";
	}
	extra_text += "\n* See https://duckdb.org/docs/stable/extensions/httpfs/s3api.html";
	return extra_text;
}

} // namespace duckdb
