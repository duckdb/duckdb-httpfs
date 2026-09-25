# This file is included by DuckDB's build system. It specifies which extension to load

################# HTTPFS
duckdb_extension_load(json)
duckdb_extension_load(parquet)

# The unit tests create secrets with MAP literals, which live in core_functions since DuckDB v2.0. Load it
# ahead of httpfs so it exists when the httpfs unit-test target links every built extension.
duckdb_extension_load(core_functions)
duckdb_extension_load(httpfs
	SOURCE_DIR ${CMAKE_CURRENT_LIST_DIR}
	INCLUDE_DIR ${CMAKE_CURRENT_LIST_DIR}/src/include
)
