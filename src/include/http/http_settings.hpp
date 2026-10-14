#pragma once

namespace duckdb {
class DatabaseInstance;

struct DBConfig;

struct HTTPSettings {
	static void Register(DBConfig &config);
	static void Initialize(DatabaseInstance &db);
};

} // namespace duckdb
