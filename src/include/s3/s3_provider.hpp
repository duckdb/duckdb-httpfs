#pragma once

#include "duckdb/common/array.hpp"
#include "duckdb/common/common.hpp"
#include "duckdb/common/optional.hpp"
#include "duckdb/common/optional_idx.hpp"

namespace duckdb {

class CreateSecretFunction;
struct DBConfig;
class KeyValueSecret;
class NormalizedS3Endpoint;
class Value;
struct CreateSecretInput;
class S3AuthParams;
class S3KeyValueReader;

enum class S3ProviderType : uint8_t { S3, GCS, R2 };

enum class S3CompatibilityProfile : uint8_t { S3, GCS, R2 };

enum class S3UrlSchemeOrigin : uint8_t { BUILTIN, ALIAS };

enum class S3AuthType : uint8_t { ANONYMOUS, SIGV4, BEARER };

enum class S3URLStyle : uint8_t { VIRTUAL_HOSTED, PATH };

enum class S3MultipartPartSizeStrategy : uint8_t { ADAPTIVE, FIXED };

struct S3MultipartUploadPolicy {
	bool operator==(const S3MultipartUploadPolicy &other) const;

	S3MultipartPartSizeStrategy part_size_strategy;
	idx_t minimum_part_size;
	idx_t maximum_part_size;
	idx_t maximum_part_count;
	optional_idx maximum_object_size;
};

struct S3ProviderMatch {
	S3ProviderType type;
	string prefix;
	S3UrlSchemeOrigin origin = S3UrlSchemeOrigin::BUILTIN;

	bool IsAlias() const {
		return origin == S3UrlSchemeOrigin::ALIAS;
	}
};

struct S3UrlScheme {
	static optional<S3ProviderMatch> TryMatch(const string &url);
	static optional<S3ProviderMatch> TryMatch(const string &url, const vector<string> &scheme_alias_prefixes);
	static S3ProviderMatch Match(const string &url);
	static S3ProviderMatch MatchRoutedUrl(const string &url);

	//! Validate and normalize bare URL scheme aliases
	static Value NormalizeAliases(const Value &aliases);
	//! The configured aliases as '<scheme>://' prefixes
	static vector<string> GetAliasPrefixes(const DBConfig &config);
};

struct S3SecretConfig {
	static constexpr const char *S3_SECRET_TYPE = "s3";
	static constexpr const char *R2_SECRET_TYPE = "r2";
	static constexpr const char *GCS_SECRET_TYPE = "gcs";
	static constexpr const char *AWS_SECRET_TYPE = "aws";

	static const array<const char *, 4> &SecretTypes();
	static const array<const char *, 13> &CredentialMaterialKeys();

	static vector<string> DefaultSecretScope(const string &secret_type);
	static void SetSecretNamedParameters(const string &secret_type, CreateSecretFunction &function);
	static void ApplySecretDefaults(const CreateSecretInput &input, KeyValueSecret &secret);
	static bool TryApplySecretOption(const CreateSecretInput &input, const string &name, const Value &value,
	                                 KeyValueSecret &secret);
};

class S3Provider {
public:
	static S3Provider Resolve(S3ProviderMatch route, const NormalizedS3Endpoint &endpoint);

	const S3ProviderMatch &GetRoute() const {
		return route;
	}
	S3ProviderType GetType() const {
		return route.type;
	}
	S3CompatibilityProfile GetCompatibilityProfile() const {
		return profile;
	}

	S3AuthType GetAuthType(const S3AuthParams &auth_params) const;
	S3MultipartUploadPolicy GetMultipartUploadPolicy() const;
	idx_t GetBulkDeleteMaxBatchSize() const;
	string GetBadRequestError(const S3AuthParams &auth_params, const string &correct_region = "") const;
	string GetAuthError(const S3AuthParams &auth_params) const;

	bool operator==(const S3Provider &other) const;

private:
	friend class S3AuthParams;
	S3Provider();
	S3Provider(S3ProviderMatch route_p, S3CompatibilityProfile profile_p);

	//! Finalized route and compatibility policy
	S3ProviderMatch route;
	S3CompatibilityProfile profile;
};

} // namespace duckdb
