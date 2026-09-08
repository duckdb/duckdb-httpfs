#pragma once

#include "duckdb/common/common.hpp"

namespace duckdb {

enum class HTTPObjectVersionType : uint8_t { NONE, S3_VERSION_ID, GCS_GENERATION };

class HTTPObjectVersion {
public:
	HTTPObjectVersion() = default;
	HTTPObjectVersion(HTTPObjectVersionType type_p, string value_p) : type(type_p), value(std::move(value_p)) {
		D_ASSERT(type != HTTPObjectVersionType::NONE && !value.empty());
	}

public:
	bool IsSet() const {
		return type != HTTPObjectVersionType::NONE;
	}
	HTTPObjectVersionType GetType() const {
		return type;
	}
	const string &GetValue() const {
		return value;
	}

private:
	HTTPObjectVersionType type = HTTPObjectVersionType::NONE;
	string value;
};

} // namespace duckdb
