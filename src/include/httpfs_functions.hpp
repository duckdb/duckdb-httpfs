//===----------------------------------------------------------------------===//
//                         DuckDB
//
// httpfs_functions.hpp
//
//
//===----------------------------------------------------------------------===//

#pragma once

#include "duckdb/parser/parsed_data/create_copy_function_info.hpp"
#include "duckdb/parser/parsed_data/create_scalar_function_info.hpp"
#include "duckdb/parser/parsed_data/create_table_function_info.hpp"

namespace duckdb {
class ExtensionLoader;

class HttpfsFunctions {
public:
	static vector<TableFunctionSet> GetTableFunctions(ExtensionLoader &loader);
};
} // namespace duckdb
