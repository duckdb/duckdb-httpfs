# This file is included by DuckDB's build system. It specifies which extension to load

################# HTTPFS
duckdb_extension_load(json)
duckdb_extension_load(parquet)

duckdb_extension_load(httpfs
	SOURCE_DIR ${CMAKE_CURRENT_LIST_DIR}
	INCLUDE_DIR ${CMAKE_CURRENT_LIST_DIR}/extension/httpfs/include
)
