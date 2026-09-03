#include "s3/s3_settings.hpp"

#include "s3/s3_auth.hpp"
#include "duckdb/common/exception.hpp"
#include "duckdb/main/config.hpp"
#include "duckdb/storage/storage_info.hpp"

namespace duckdb {

namespace {

struct S3UploadSizing {
	static bool ScheduleCovers(uint64_t initial_part_size, uint64_t max_file_size, idx_t max_parts,
	                           idx_t growth_interval, idx_t maximum_part_size) {
		uint64_t capacity = 0;
		idx_t completed_parts = 0;
		while (completed_parts < max_parts) {
			auto part_size = PartSize(initial_part_size, growth_interval, completed_parts, maximum_part_size);
			auto parts_at_size = MinValue<idx_t>(growth_interval, max_parts - completed_parts);
			if (part_size > (max_file_size - MinValue<uint64_t>(capacity, max_file_size)) / parts_at_size) {
				return true;
			}
			capacity += part_size * parts_at_size;
			if (capacity >= max_file_size) {
				return true;
			}
			completed_parts += parts_at_size;
		}
		return false;
	}

	static idx_t PartSize(uint64_t initial_part_size, idx_t growth_interval, idx_t completed_parts,
	                      idx_t maximum_part_size) {
		auto result = initial_part_size;
		auto doubling_count = completed_parts / growth_interval;
		while (doubling_count > 0 && result < maximum_part_size) {
			result = result > maximum_part_size / 2 ? maximum_part_size : result * 2;
			doubling_count--;
		}
		return NumericCast<idx_t>(result);
	}

	static idx_t InitialPartSize(uint64_t max_file_size, idx_t max_parts, idx_t growth_interval,
	                             const S3MultipartUploadPolicy &policy) {
		const auto block_size = NumericCast<uint64_t>(Storage::DEFAULT_BLOCK_SIZE + Storage::DEFAULT_BLOCK_HEADER_SIZE);
		D_ASSERT(policy.minimum_part_size % block_size == 0);
		D_ASSERT(policy.maximum_part_size % block_size == 0);
		auto lower = NumericCast<uint64_t>(policy.minimum_part_size) / block_size;
		auto upper = NumericCast<uint64_t>(policy.maximum_part_size) / block_size;
		while (lower < upper) {
			auto middle = lower + (upper - lower) / 2;
			if (ScheduleCovers(middle * block_size, max_file_size, max_parts, growth_interval,
			                   policy.maximum_part_size)) {
				upper = middle;
			} else {
				lower = middle + 1;
			}
		}
		return NumericCast<idx_t>(lower * block_size);
	}

	static idx_t FixedPartSize(uint64_t required_part_size, const S3MultipartUploadPolicy &policy) {
		auto part_size = NumericCast<uint64_t>(policy.minimum_part_size);
		while (part_size < required_part_size && part_size <= policy.maximum_part_size / 2) {
			part_size *= 2;
		}
		if (part_size >= required_part_size) {
			return NumericCast<idx_t>(part_size);
		}
		D_ASSERT(required_part_size <= policy.maximum_part_size);
		return policy.maximum_part_size;
	}
};

static void ValidateMultipartUploadPolicy(const S3MultipartUploadPolicy &policy) {
	if (policy.minimum_part_size == 0) {
		throw InvalidConfigurationException("S3 multipart upload policy requires a nonzero minimum part size");
	}
	if (policy.maximum_part_size < policy.minimum_part_size) {
		throw InvalidConfigurationException(
		    "S3 multipart upload policy maximum part size is smaller than its minimum part size");
	}
	if (policy.maximum_part_count == 0) {
		throw InvalidConfigurationException("S3 multipart upload policy requires a nonzero maximum part count");
	}
	if (policy.maximum_object_size.IsValid() && policy.maximum_object_size.GetIndex() == 0) {
		throw InvalidConfigurationException("S3 multipart upload policy maximum object size must be nonzero");
	}
	switch (policy.part_size_strategy) {
	case S3MultipartPartSizeStrategy::ADAPTIVE: {
		const auto block_size = Storage::DEFAULT_BLOCK_SIZE + Storage::DEFAULT_BLOCK_HEADER_SIZE;
		if (policy.minimum_part_size % block_size != 0 || policy.maximum_part_size % block_size != 0) {
			throw InvalidConfigurationException("Adaptive S3 multipart upload policy part sizes must be block aligned");
		}
		break;
	}
	case S3MultipartPartSizeStrategy::FIXED:
		break;
	default:
		throw InvalidConfigurationException("S3 multipart upload policy has an unknown part-size strategy");
	}
}

} // namespace

static void SetS3URLStyle(ClientContext &, SetScope, Value &parameter) {
	S3Provider::ParseURLStyle(StringValue::Get(parameter));
}

S3UploadConfig S3UploadConfig::Create(uint64_t max_file_size, uint64_t max_parts,
                                      const S3MultipartUploadPolicy &policy) {
	ValidateMultipartUploadPolicy(policy);
	if (max_file_size == 0) {
		throw InvalidInputException("s3_uploader_max_filesize must be greater than zero");
	}
	if (max_parts == 0 || max_parts > policy.maximum_part_count) {
		throw InvalidInputException("s3_uploader_max_parts_per_file must be between 1 and %llu",
		                            policy.maximum_part_count);
	}
	const auto required_part_size = max_file_size / max_parts + (max_file_size % max_parts != 0);
	if (required_part_size > policy.maximum_part_size) {
		throw InvalidInputException(
		    "s3_uploader_max_filesize exceeds the size supported by s3_uploader_max_parts_per_file");
	}
	if (policy.maximum_object_size.IsValid() && max_file_size > policy.maximum_object_size.GetIndex()) {
		throw InvalidInputException("s3_uploader_max_filesize exceeds the provider's maximum object size");
	}

	S3UploadConfig result;
	result.max_file_size = max_file_size;
	result.max_parts = NumericCast<idx_t>(max_parts);
	result.maximum_part_size = policy.maximum_part_size;
	result.part_size_strategy = policy.part_size_strategy;
	if (policy.part_size_strategy == S3MultipartPartSizeStrategy::FIXED) {
		result.initial_part_size = S3UploadSizing::FixedPartSize(required_part_size, policy);
		return result;
	}
	result.growth_interval = result.max_parts / PART_SIZE_TIERS + (result.max_parts % PART_SIZE_TIERS != 0);
	result.initial_part_size =
	    S3UploadSizing::InitialPartSize(max_file_size, result.max_parts, result.growth_interval, policy);
	return result;
}

S3UploadConfig S3UploadConfig::ReadFrom(optional_ptr<FileOpener> opener, const S3MultipartUploadPolicy &policy) {
	uint64_t uploader_max_filesize;
	uint64_t max_parts_per_file;
	Value value;

	if (FileOpener::TryGetCurrentSetting(opener, "s3_uploader_max_filesize", value)) {
		uploader_max_filesize = DBConfig::ParseMemoryLimit(value.GetValue<string>());
	} else {
		uploader_max_filesize = S3UploadConfig::DEFAULT_MAX_FILESIZE;
	}
	if (FileOpener::TryGetCurrentSetting(opener, "s3_uploader_max_parts_per_file", value)) {
		max_parts_per_file = value.GetValue<uint64_t>();
	} else {
		max_parts_per_file = S3UploadConfig::DEFAULT_MAX_PARTS_PER_FILE;
	}
	return Create(uploader_max_filesize, max_parts_per_file, policy);
}

idx_t S3UploadConfig::TargetPartSize(idx_t reserved_parts) const {
	if (part_size_strategy == S3MultipartPartSizeStrategy::FIXED) {
		D_ASSERT(initial_part_size <= maximum_part_size);
		return initial_part_size;
	}
	D_ASSERT(initial_part_size <= maximum_part_size);
	D_ASSERT(growth_interval > 0);
	return S3UploadSizing::PartSize(initial_part_size, growth_interval, reserved_parts, maximum_part_size);
}

idx_t S3UploadConfig::DirectPartSize(idx_t reserved_parts, idx_t remaining) const {
	auto target_part_size = TargetPartSize(reserved_parts);
	D_ASSERT(remaining >= target_part_size);
	if (part_size_strategy == S3MultipartPartSizeStrategy::FIXED) {
		return target_part_size;
	}
	return MinValue<idx_t>(remaining, maximum_part_size);
}

bool S3UploadConfig::HasPartCapacity(idx_t reserved_parts) const {
	return reserved_parts < max_parts;
}

void S3Settings::Register(DBConfig &config) {
	config.AddExtensionOption("s3_region", "S3 Region", LogicalType::VARCHAR);
	config.AddExtensionOption("s3_access_key_id", "S3 Access Key ID", LogicalType::VARCHAR);
	config.AddExtensionOption("s3_secret_access_key", "S3 Access Key", LogicalType::VARCHAR);
	config.AddExtensionOption("s3_session_token", "S3 Session Token", LogicalType::VARCHAR);
	config.AddExtensionOption("s3_endpoint", "S3 Endpoint", LogicalType::VARCHAR);
	config.AddExtensionOption("s3_url_style", "S3 URL style", LogicalType::VARCHAR, Value("vhost"), SetS3URLStyle);
	config.AddExtensionOption("s3_use_ssl", "S3 use SSL", LogicalType::BOOLEAN, Value(true));
	config.AddExtensionOption("s3_kms_key_id", "S3 KMS Key ID", LogicalType::VARCHAR);
	config.AddExtensionOption("s3_url_compatibility_mode", "Disable Globs and Query Parameters on S3 URLs",
	                          LogicalType::BOOLEAN, Value(false));
	config.AddExtensionOption("s3_requester_pays", "S3 use requester pays mode", LogicalType::BOOLEAN, Value(false));
	config.AddExtensionOption("gcs_user_project", "GCS billing project for Requester Pays", LogicalType::VARCHAR);
	config.AddExtensionOption(
	    "s3_url_scheme_aliases",
	    "Additional URL schemes routed to the S3-compatible filesystem (e.g. ['oss', 'cos']). "
	    "Can only be set globally; secrets for aliased schemes need an explicit SCOPE.",
	    LogicalType::LIST(LogicalType::VARCHAR), Value::LIST(LogicalType::VARCHAR, vector<Value>()),
	    [](ClientContext &context, SetScope scope, Value &parameter) {
		    if (scope == SetScope::SESSION || scope == SetScope::LOCAL) {
			    throw InvalidInputException("s3_url_scheme_aliases can only be set globally");
		    }
		    // Validate only: routing reads the stored value from DBConfig
		    parameter = S3Provider::NormalizeSchemeAliases(parameter);
	    },
	    SetScope::GLOBAL);
	config.AddExtensionOption(
	    "s3_allow_recursive_globbing",
	    "Whether globs on S3-like storage are optimized with recursive strategy (alternative is listing)",
	    LogicalType::BOOLEAN, Value(true));
	config.AddExtensionOption("s3_uploader_max_filesize", "Maximum size of an S3 upload", LogicalType::VARCHAR, "80GB");
	config.AddExtensionOption("s3_uploader_max_parts_per_file", "Maximum number of parts in an S3 multipart upload",
	                          LogicalType::UBIGINT, Value::UBIGINT(10000));
	config.AddExtensionOption("s3_version_id_pinning", "Pin S3 reads to a specific object version for consistency",
	                          LogicalType::BOOLEAN, Value(false));
	config.AddExtensionOption("merge_http_secret_into_s3_request", "Merges HTTP secret parameters into S3 requests",
	                          LogicalType::BOOLEAN, Value(true));
	config.AddExtensionOption("httpfs_enable_credential_refresh", "Enable credential refresh for HTTPFS S3 secrets",
	                          LogicalType::BOOLEAN, Value(true));
	config.AddExtensionOption("enable_global_s3_configuration",
	                          "Automatically fetch AWS credentials from environment variables.", LogicalType::BOOLEAN,
	                          Value::BOOLEAN(true));
}

void S3Settings::Initialize(DBConfig &config) {
	auto provider = make_uniq<AWSEnvironmentCredentialsProvider>(config);
	provider->SetAll();
}

} // namespace duckdb
