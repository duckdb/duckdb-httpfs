#pragma once

#include "duckdb/common/array.hpp"
#include "duckdb/common/common.hpp"
#include "duckdb/common/optional.hpp"
#include "duckdb/common/optional_idx.hpp"

namespace duckdb {

class CreateSecretFunction;
struct DBConfig;
class KeyValueSecret;
class Value;
struct CreateSecretInput;
struct S3AuthParams;
class S3KeyValueReader;

enum class S3ProviderType : uint8_t { S3, GCS, R2 };

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
};

struct S3Provider {
	static constexpr const char *S3_SECRET_TYPE = "s3";
	static constexpr const char *R2_SECRET_TYPE = "r2";
	static constexpr const char *GCS_SECRET_TYPE = "gcs";
	static constexpr const char *AWS_SECRET_TYPE = "aws";

	static const array<const char *, 4> &SecretTypes();
	static const array<const char *, 13> &CredentialMaterialKeys();

	static optional<S3ProviderMatch> TryMatchUrl(const string &url);
	static optional<S3ProviderMatch> TryMatchUrl(const string &url, const vector<string> &scheme_alias_prefixes);
	static S3ProviderMatch MatchUrl(const string &url);

	//! Validate and normalize the 's3_url_scheme_aliases' value (bare scheme names, lowercased, deduplicated)
	static Value NormalizeSchemeAliases(const Value &aliases);
	//! The database's configured scheme aliases as '<scheme>://' prefixes
	static vector<string> GetSchemeAliasPrefixes(const DBConfig &config);

	static vector<string> DefaultSecretScope(const string &secret_type);
	static void SetSecretNamedParameters(const string &secret_type, CreateSecretFunction &function);
	static void ApplySecretDefaults(const CreateSecretInput &input, KeyValueSecret &secret);
	static bool TryApplySecretOption(const CreateSecretInput &input, const string &name, const Value &value,
	                                 KeyValueSecret &secret);

	static void ReadAuthParams(S3KeyValueReader &secret_reader, const string &file_path, S3AuthParams &result);
	//! Apply provider defaults; a required endpoint no secret or setting supplied stays unresolved
	static void InitializeAuthParams(S3AuthParams &auth_params);
	//! Validate that endpoint once every source has been read, then derive the remaining defaults
	static void FinalizeAuthParams(S3AuthParams &auth_params);
	static S3URLStyle ParseURLStyle(const string &url_style);
	static S3AuthType GetAuthType(const S3AuthParams &auth_params);
	static S3MultipartUploadPolicy GetMultipartUploadPolicy(const S3AuthParams &auth_params);
	static string GetBadRequestError(const S3AuthParams &auth_params, const string &correct_region = "");
	static string GetAuthError(const S3AuthParams &auth_params);
};

} // namespace duckdb
