#pragma once

#include "duckdb/common/common.hpp"
#include "duckdb/common/optional_idx.hpp"

namespace duckdb {

class S3AuthParams;
struct S3AuthResolver;

class NormalizedS3Endpoint {
	friend class S3AuthParams;
	friend struct S3AuthResolver;

public:
	NormalizedS3Endpoint() = default;

public:
	//! Construction and comparison
	static NormalizedS3Endpoint Parse(const string &endpoint, bool fallback_use_ssl);
	bool operator==(const NormalizedS3Endpoint &other) const;

	//! Endpoint properties
	bool IsEmpty() const;
	bool IsIPv6() const;
	bool UsesSSL() const;
	const string &GetHost() const;
	const string &GetBasePath() const;
	string GetAuthority() const;
	string GetProtocol() const;
	string GetCanonicalValue() const;

private:
	enum class Scheme : uint8_t { HTTP, HTTPS };

private:
	//! Provider finalization helpers
	bool IsDefaultPort() const;
	void SetHost(string host_p);

private:
	//! Endpoint authority and scheme
	string host;
	optional_idx port;
	Scheme scheme = Scheme::HTTPS;
	bool is_ipv6 = false;

	//! Request path prefix
	string base_path;
};

} // namespace duckdb
