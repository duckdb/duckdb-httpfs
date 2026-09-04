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

Value S3UrlScheme::NormalizeAliases(const Value &aliases) {
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

vector<string> S3UrlScheme::GetAliasPrefixes(const DBConfig &config) {
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

const array<const char *, 4> &S3SecretConfig::SecretTypes() {
	static constexpr array<const char *, 4> SECRET_TYPES = {S3_SECRET_TYPE, R2_SECRET_TYPE, GCS_SECRET_TYPE,
	                                                        AWS_SECRET_TYPE};
	return SECRET_TYPES;
}

const array<const char *, 13> &S3SecretConfig::CredentialMaterialKeys() {
	static constexpr array<const char *, 13> CREDENTIAL_MATERIAL_KEYS = {
	    "key_id",    "secret",  "session_token",          "region",         "endpoint",     "kms_key_id",
	    "url_style", "use_ssl", "url_compatibility_mode", "requester_pays", "bearer_token", "user_project",
	    "account_id"};
	return CREDENTIAL_MATERIAL_KEYS;
}

optional<S3ProviderMatch> S3UrlScheme::TryMatch(const string &url) {
	auto lower_url = StringUtil::Lower(url);
	for (const auto &provider_match : ProviderMatches()) {
		if (StringUtil::StartsWith(lower_url, provider_match.prefix)) {
			return provider_match;
		}
	}
	return {};
}

optional<S3ProviderMatch> S3UrlScheme::TryMatch(const string &url, const vector<string> &scheme_alias_prefixes) {
	auto provider_match = TryMatch(url);
	if (provider_match) {
		return provider_match;
	}
	// Aliased schemes are served by the plain S3 provider
	auto lower_url = StringUtil::Lower(url);
	for (auto &prefix : scheme_alias_prefixes) {
		if (StringUtil::StartsWith(lower_url, prefix)) {
			return S3ProviderMatch {S3ProviderType::S3, prefix, S3UrlSchemeOrigin::ALIAS};
		}
	}
	return {};
}

S3ProviderMatch S3UrlScheme::Match(const string &url) {
	auto provider_match = TryMatch(url);
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

S3ProviderMatch S3UrlScheme::MatchRoutedUrl(const string &url) {
	auto provider_match = TryMatch(url);
	if (provider_match) {
		return *provider_match;
	}
	auto scheme_end = url.find("://");
	if (scheme_end == string::npos) {
		return Match(url);
	}
	return {S3ProviderType::S3, StringUtil::Lower(url.substr(0, scheme_end + 3)), S3UrlSchemeOrigin::ALIAS};
}

vector<string> S3SecretConfig::DefaultSecretScope(const string &secret_type) {
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

void S3SecretConfig::SetSecretNamedParameters(const string &secret_type, CreateSecretFunction &function) {
	if (secret_type == R2_SECRET_TYPE) {
		function.named_parameters["account_id"] = LogicalType::VARCHAR;
	} else if (secret_type == GCS_SECRET_TYPE) {
		function.named_parameters["bearer_token"] = LogicalType::VARCHAR;
		function.named_parameters["user_project"] = LogicalType::VARCHAR;
	}
}

void S3SecretConfig::ApplySecretDefaults(const CreateSecretInput &input, KeyValueSecret &secret) {
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

bool S3SecretConfig::TryApplySecretOption(const CreateSecretInput &input, const string &name, const Value &value,
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

S3Provider::S3Provider() : S3Provider(S3ProviderMatch {S3ProviderType::S3, "s3://"}, S3CompatibilityProfile::S3) {
}

S3Provider::S3Provider(S3ProviderMatch route_p, S3CompatibilityProfile profile_p)
    : route(std::move(route_p)), profile(profile_p) {
}

S3AuthType S3Provider::GetAuthType(const S3AuthParams &auth_params) const {
	auto &credentials = auth_params.GetCredentials();
	if (GetType() == S3ProviderType::GCS && !credentials.oauth2_bearer_token.empty()) {
		return S3AuthType::BEARER;
	}
	if (credentials.secret_access_key.empty() && credentials.access_key_id.empty()) {
		return S3AuthType::ANONYMOUS;
	}
	return S3AuthType::SIGV4;
}

static bool EndpointIsR2(const NormalizedS3Endpoint &endpoint) {
	static const string R2_ENDPOINT_SUFFIX = ".r2.cloudflarestorage.com";
	auto &host = endpoint.GetHost();
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

S3Provider S3Provider::Resolve(S3ProviderMatch route, const NormalizedS3Endpoint &endpoint) {
	auto profile = S3CompatibilityProfile::S3;
	if (route.type == S3ProviderType::GCS) {
		profile = S3CompatibilityProfile::GCS;
	} else if (route.type == S3ProviderType::R2 || EndpointIsR2(endpoint)) {
		profile = S3CompatibilityProfile::R2;
	}
	return S3Provider(std::move(route), profile);
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

S3MultipartUploadPolicy S3Provider::GetMultipartUploadPolicy() const {
	if (profile == S3CompatibilityProfile::R2) {
		return R2MultipartUploadPolicy();
	}
	return DefaultMultipartUploadPolicy();
}

idx_t S3Provider::GetBulkDeleteMaxBatchSize() const {
	return profile == S3CompatibilityProfile::R2 ? 700 : 1000;
}

string S3Provider::GetBadRequestError(const S3AuthParams &auth_params, const string &correct_region) const {
	if (GetType() != S3ProviderType::S3) {
		return {};
	}
	auto &credentials = auth_params.GetCredentials();
	string extra_text = "\n\nBad Request - this can be caused by the S3 region being set incorrectly.";
	if (credentials.region.empty()) {
		extra_text += "\n* No region is provided.";
	} else {
		extra_text += "\n* Provided region is: \"" + credentials.region + "\"";
	}
	if (!correct_region.empty()) {
		extra_text += "\n* Correct region is: \"" + correct_region + "\"";
	}
	return extra_text;
}

string S3Provider::GetAuthError(const S3AuthParams &auth_params) const {
	auto &credentials = auth_params.GetCredentials();
	if (GetType() == S3ProviderType::GCS) {
		string extra_text = "\n\nAuthentication Failure - GCS authentication failed.";
		if (credentials.oauth2_bearer_token.empty() && credentials.secret_access_key.empty() &&
		    credentials.access_key_id.empty()) {
			extra_text += "\n* No credentials provided.";
			extra_text += "\n* For OAuth2: CREATE SECRET (TYPE GCS, bearer_token 'your-token')";
			extra_text += "\n* For HMAC: CREATE SECRET (TYPE GCS, key_id 'key', secret 'secret')";
		} else if (!credentials.oauth2_bearer_token.empty()) {
			extra_text += "\n* Bearer token was provided but authentication failed.";
			extra_text += "\n* Ensure your OAuth2 token is valid and not expired.";
		} else {
			extra_text += "\n* HMAC credentials were provided but authentication failed.";
			extra_text += "\n* Ensure your HMAC key_id and secret are correct.";
		}
		return extra_text;
	}
	if (GetType() == S3ProviderType::R2) {
		string extra_text = "\n\nAuthentication Failure - R2 authentication failed.";
		if (credentials.secret_access_key.empty() && credentials.access_key_id.empty()) {
			extra_text += "\n* No credentials are provided.";
			extra_text += "\n* Create an R2 secret with account_id, key_id, and secret.";
		} else {
			extra_text += "\n* Credentials were provided, but they did not work.";
		}
		return extra_text;
	}

	string extra_text = "\n\nAuthentication Failure - this is usually caused by invalid or missing credentials.";
	if (credentials.secret_access_key.empty() && credentials.access_key_id.empty()) {
		extra_text += "\n* No credentials are provided.";
	} else {
		extra_text += "\n* Credentials are provided, but they did not work.";
	}
	extra_text += "\n* See https://duckdb.org/docs/stable/extensions/httpfs/s3api.html";
	return extra_text;
}

bool S3Provider::operator==(const S3Provider &other) const {
	return route.type == other.route.type && route.prefix == other.route.prefix && route.origin == other.route.origin &&
	       profile == other.profile;
}

} // namespace duckdb
