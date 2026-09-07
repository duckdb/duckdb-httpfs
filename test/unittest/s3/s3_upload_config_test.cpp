#include "catch.hpp"

#include "s3/s3_auth.hpp"
#include "s3/s3_settings.hpp"

#include "duckdb/common/array.hpp"
#include "duckdb/common/limits.hpp"
#include "duckdb/storage/storage_info.hpp"

namespace duckdb {

namespace {

static constexpr idx_t MIB = 1024ULL * 1024ULL;
static constexpr idx_t GIB = 1024ULL * MIB;

static S3MultipartUploadPolicy GetUploadPolicy(S3ProviderType provider_type) {
	const char *scheme = provider_type == S3ProviderType::R2 ? "r2://" : "s3://";
	S3AuthConfig config;
	config.route = S3UrlScheme::Match(scheme);
	if (provider_type == S3ProviderType::R2) {
		config.endpoint = "account.r2.cloudflarestorage.com";
	}
	auto auth_params = S3AuthResolver::Resolve(std::move(config), scheme);
	return auth_params.GetProvider().GetMultipartUploadPolicy();
}

} // namespace

TEST_CASE("S3 upload config uses adaptive part sizes", "[httpfs][s3][upload]") {
	auto policy = GetUploadPolicy(S3ProviderType::S3);

	SECTION("default schedule") {
		auto config = S3UploadConfig::Create(S3UploadConfig::DEFAULT_MAX_FILESIZE,
		                                     S3UploadConfig::DEFAULT_MAX_PARTS_PER_FILE, policy);
		REQUIRE(config.max_file_size == S3UploadConfig::DEFAULT_MAX_FILESIZE);
		REQUIRE(config.max_parts == S3UploadConfig::DEFAULT_MAX_PARTS_PER_FILE);
		REQUIRE(config.initial_part_size == policy.minimum_part_size);
		REQUIRE(config.maximum_part_size == policy.maximum_part_size);
		REQUIRE(config.growth_interval == 910);
		REQUIRE(config.TargetPartSize(0) == policy.minimum_part_size);
		REQUIRE(config.TargetPartSize(909) == policy.minimum_part_size);
		REQUIRE(config.TargetPartSize(910) == 2 * policy.minimum_part_size);
		REQUIRE(config.TargetPartSize(1819) == 2 * policy.minimum_part_size);
		REQUIRE(config.TargetPartSize(1820) == 4 * policy.minimum_part_size);
		REQUIRE(config.TargetPartSize(9100) == policy.maximum_part_size);
		REQUIRE(config.TargetPartSize(9999) == policy.maximum_part_size);
	}

	SECTION("small part budget") {
		auto config = S3UploadConfig::Create(16ULL * MIB, 11, policy);
		REQUIRE(config.initial_part_size == policy.minimum_part_size);
		REQUIRE(config.growth_interval == 1);
		REQUIRE(config.TargetPartSize(0) == 5ULL * MIB);
		REQUIRE(config.TargetPartSize(1) == 10ULL * MIB);
		REQUIRE(config.TargetPartSize(10) == policy.maximum_part_size);
		REQUIRE(config.HasPartCapacity(10));
		REQUIRE_FALSE(config.HasPartCapacity(11));
	}

	SECTION("initial size is block aligned") {
		auto minimum_config = S3UploadConfig::Create(16ULL * MIB, 11, policy);
		uint64_t minimum_capacity = 0;
		for (idx_t part_index = 0; part_index < minimum_config.max_parts; part_index++) {
			minimum_capacity += minimum_config.TargetPartSize(part_index);
		}
		auto config = S3UploadConfig::Create(minimum_capacity + 1, 11, policy);
		REQUIRE(config.initial_part_size ==
		        policy.minimum_part_size + Storage::DEFAULT_BLOCK_SIZE + Storage::DEFAULT_BLOCK_HEADER_SIZE);
	}

	SECTION("maximum supported schedule") {
		const auto maximum_file_size = NumericCast<uint64_t>(policy.maximum_part_size) * policy.maximum_part_count;
		auto config = S3UploadConfig::Create(maximum_file_size, policy.maximum_part_count, policy);
		REQUIRE(config.initial_part_size == policy.maximum_part_size);
		REQUIRE(config.TargetPartSize(0) == policy.maximum_part_size);

		auto single_part = S3UploadConfig::Create(policy.maximum_part_size, 1, policy);
		REQUIRE(single_part.initial_part_size == policy.maximum_part_size);
		REQUIRE(single_part.HasPartCapacity(0));
		REQUIRE_FALSE(single_part.HasPartCapacity(1));
	}

	SECTION("direct parts retain the adaptive maximum") {
		auto config = S3UploadConfig::Create(16ULL * MIB, 11, policy);
		REQUIRE(config.TargetPartSize(0) == 5ULL * MIB);
		REQUIRE(config.DirectPartSize(0, 7ULL * MIB) == 7ULL * MIB);
		REQUIRE(config.DirectPartSize(0, policy.maximum_part_size + MIB) == policy.maximum_part_size);
	}

	SECTION("maximum policy part count") {
		policy.maximum_part_count = NumericLimits<idx_t>::Maximum();
		auto config = S3UploadConfig::Create(1, policy.maximum_part_count, policy);
		auto expected_interval = policy.maximum_part_count / S3UploadConfig::PART_SIZE_TIERS +
		                         (policy.maximum_part_count % S3UploadConfig::PART_SIZE_TIERS != 0);
		REQUIRE(config.growth_interval == expected_interval);
		REQUIRE(config.TargetPartSize(0) == policy.minimum_part_size);
	}

	SECTION("invalid limits") {
		const auto maximum_file_size = NumericCast<uint64_t>(policy.maximum_part_size) * policy.maximum_part_count;
		REQUIRE_THROWS(S3UploadConfig::Create(0, 1, policy));
		REQUIRE_THROWS(S3UploadConfig::Create(1, 0, policy));
		REQUIRE_THROWS(S3UploadConfig::Create(1, policy.maximum_part_count + 1, policy));
		REQUIRE_THROWS(S3UploadConfig::Create(maximum_file_size + 1, policy.maximum_part_count, policy));
		REQUIRE_THROWS(S3UploadConfig::Create(NumericLimits<uint64_t>::Maximum(), policy.maximum_part_count, policy));
	}
}

TEST_CASE("S3 upload config validates multipart policies", "[httpfs][s3][upload]") {
	auto policy = GetUploadPolicy(S3ProviderType::S3);

	SECTION("minimum part size") {
		policy.minimum_part_size = 0;
		REQUIRE_THROWS(S3UploadConfig::Create(1, 1, policy));
	}
	SECTION("ordered part sizes") {
		policy.maximum_part_size = policy.minimum_part_size - 1;
		REQUIRE_THROWS(S3UploadConfig::Create(1, 1, policy));
	}
	SECTION("maximum part count") {
		policy.maximum_part_count = 0;
		REQUIRE_THROWS(S3UploadConfig::Create(1, 1, policy));
	}
	SECTION("maximum object size") {
		policy.maximum_object_size = 0;
		REQUIRE_THROWS(S3UploadConfig::Create(1, 1, policy));
	}
	SECTION("adaptive part alignment") {
		policy.minimum_part_size++;
		REQUIRE_THROWS(S3UploadConfig::Create(1, 1, policy));
	}
	SECTION("part-size strategy") {
		policy.part_size_strategy = static_cast<S3MultipartPartSizeStrategy>(99);
		REQUIRE_THROWS(S3UploadConfig::Create(1, 1, policy));
	}
}

TEST_CASE("Fixed multipart upload policies use their own limits", "[httpfs][s3][upload]") {
	S3MultipartUploadPolicy policy {S3MultipartPartSizeStrategy::FIXED, 3ULL * MIB, 25ULL * MIB, 10, optional_idx()};
	auto config = S3UploadConfig::Create(12ULL * MIB, 1, policy);
	REQUIRE(config.initial_part_size == 12ULL * MIB);
	REQUIRE(config.TargetPartSize(0) == 12ULL * MIB);
	REQUIRE(config.TargetPartSize(9) == 12ULL * MIB);
	REQUIRE(config.DirectPartSize(0, 20ULL * MIB) == 12ULL * MIB);

	SECTION("terminal tier") {
		auto terminal = S3UploadConfig::Create(25ULL * MIB, 1, policy);
		REQUIRE(terminal.initial_part_size == 25ULL * MIB);
	}

	SECTION("doubling does not overflow") {
		policy.minimum_part_size = NumericLimits<idx_t>::Maximum() / 2 + 1;
		policy.maximum_part_size = NumericLimits<idx_t>::Maximum();
		auto maximum = S3UploadConfig::Create(NumericLimits<uint64_t>::Maximum(), 1, policy);
		REQUIRE(maximum.initial_part_size == NumericLimits<idx_t>::Maximum());
	}
}

TEST_CASE("R2 upload config uses fixed part sizes", "[httpfs][s3][upload]") {
	auto policy = GetUploadPolicy(S3ProviderType::R2);

	SECTION("default schedule") {
		auto config = S3UploadConfig::Create(S3UploadConfig::DEFAULT_MAX_FILESIZE,
		                                     S3UploadConfig::DEFAULT_MAX_PARTS_PER_FILE, policy);
		REQUIRE(config.part_size_strategy == S3MultipartPartSizeStrategy::FIXED);
		REQUIRE(config.initial_part_size == 8 * MIB);
		REQUIRE(config.TargetPartSize(0) == 8 * MIB);
		REQUIRE(config.TargetPartSize(config.max_parts - 1) == 8 * MIB);
		REQUIRE(config.DirectPartSize(0, 16 * MIB) == 8 * MIB);
	}

	SECTION("part size tiers") {
		static constexpr array<idx_t, 11> PART_SIZES = {8 * MIB,    16 * MIB,   32 * MIB,  64 * MIB,
		                                                128 * MIB,  256 * MIB,  512 * MIB, 1024 * MIB,
		                                                2048 * MIB, 4096 * MIB, 5115 * MIB};
		uint64_t lower_bound = 1;
		for (auto part_size : PART_SIZES) {
			auto lower_config = S3UploadConfig::Create(lower_bound, 1, policy);
			auto upper_config = S3UploadConfig::Create(part_size, 1, policy);
			INFO(part_size);
			REQUIRE(lower_config.initial_part_size == part_size);
			REQUIRE(upper_config.initial_part_size == part_size);
			REQUIRE(lower_config.TargetPartSize(0) == part_size);
			REQUIRE(lower_config.TargetPartSize(1) == part_size);
			lower_bound = NumericCast<uint64_t>(part_size) + 1;
		}
	}

	SECTION("exact limits") {
		REQUIRE(policy.maximum_part_size == 5115 * MIB);
		REQUIRE(policy.maximum_object_size == 5115ULL * GIB);

		auto maximum = S3UploadConfig::Create(policy.maximum_object_size.GetIndex(), 1024, policy);
		REQUIRE(maximum.initial_part_size == policy.maximum_part_size);
		REQUIRE_THROWS(
		    S3UploadConfig::Create(policy.maximum_object_size.GetIndex() + 1, policy.maximum_part_count, policy));
		REQUIRE_THROWS(S3UploadConfig::Create(policy.maximum_object_size.GetIndex(), 1023, policy));
	}
}

} // namespace duckdb
