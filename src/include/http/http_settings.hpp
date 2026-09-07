#pragma once

namespace duckdb {

struct DBConfig;

struct HTTPSettings {
	static void Register(DBConfig &config);
	static void Initialize(DBConfig &config);
};

} // namespace duckdb
