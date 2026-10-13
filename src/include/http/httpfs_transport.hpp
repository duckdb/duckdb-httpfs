#pragma once

#include "duckdb/common/optional_idx.hpp"
#include "duckdb/main/http/http_transport_config.hpp"

namespace duckdb {

struct HTTPFSParams;

struct HTTPFSConnectionConfig {
public:
	static HTTPFSConnectionConfig Create(const HTTPFSParams &params);
	bool Matches(const HTTPFSParams &params) const;
	bool operator==(const HTTPFSConnectionConfig &other) const;

public:
	//! Domain identity, unset until the configuration is captured.
	optional_idx reuse_domain;
	//! Common proxy and TLS-override settings, also enforced by the core pool.
	HTTPTransportConfig transport_config;
	string ca_cert_file;
	//! Effective server certificate verification setting.
	bool verify_ssl = true;
};

} // namespace duckdb
