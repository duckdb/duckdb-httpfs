#!/usr/bin/env bash
#Note: DONT run as root

DUCKDB_PATH=duckdb
if command -v duckdb; then
  DUCKDB_PATH=duckdb
elif test -f build/release/duckdb; then
  DUCKDB_PATH=build/release/duckdb
elif test -f build/reldebug/duckdb; then
  DUCKDB_PATH=build/reldebug/duckdb
elif test -f build/debug/duckdb; then
  DUCKDB_PATH=build/debug/duckdb
fi

rm -rf test/test_data
mkdir -p test/test_data

generate_large_parquet_query=$(cat <<EOF

CALL DBGEN(sf=1);
COPY lineitem TO 'test/test_data/presigned-url-lineitem.parquet' (FORMAT 'parquet');

EOF
)
$DUCKDB_PATH -c "$generate_large_parquet_query"

# Generate Storage Version
$DUCKDB_PATH  test/test_data/attach.db < duckdb/test/sql/storage_version/generate_storage_version.sql
$DUCKDB_PATH  test/test_data/lineitem_sf1.db -c "CALL dbgen(sf=1)"
