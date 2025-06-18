# This file is included by DuckDB's build system. It specifies which extension to load

################# HTTPFS
# Windows MinGW tests for httpfs currently not working
if (NOT MINGW)
    set(LOAD_HTTPFS_TESTS "LOAD_TESTS")
else ()
    set(LOAD_HTTPFS_TESTS "")
endif()

duckdb_extension_load(json)
duckdb_extension_load(parquet)

duckdb_extension_load(httpfs
	SOURCE_DIR ${CMAKE_CURRENT_LIST_DIR}
	INCLUDE_DIR ${CMAKE_CURRENT_LIST_DIR}/extension/httpfs/include
	${LOAD_HTTPFS_TESTS}
	LINKED_LIBS "../../third_party/mbedtls/libduckdb_mbedtls.a"
)
