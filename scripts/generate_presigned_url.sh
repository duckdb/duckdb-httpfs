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

mkdir -p data/parquet-testing/presigned

generate_large_parquet_query=$(cat <<EOF

CALL DBGEN(sf=1);
COPY lineitem TO 'data/parquet-testing/presigned/presigned-url-lineitem.parquet' (FORMAT 'parquet');

EOF
)
$DUCKDB_PATH -c "$generate_large_parquet_query"

mkdir -p data/attach_test/

# Generate Storage Version
rm -f data/attach_test/attach.db
rm -f data/attach_test/lineitem_sf1.db
$DUCKDB_PATH  data/attach_test/attach.db < duckdb/test/sql/storage_version/generate_storage_version.sql
$DUCKDB_PATH  data/attach_test/lineitem_sf1.db -c "CALL dbgen(sf=1)"
