#!/usr/bin/env bash
# Regression test for PR #165 -- ExecuteWithRefresh on S3FileSystem::GetRangeRequest.
#
# The existing refresh hook lives in S3FileHandle::Initialize and only fires
# on HEAD failures. Callers that skip HEAD (DuckLake, Iceberg, anything using
# prefilled OpenFileInfo.extended_info) silently opt out of auto-refresh.
# We trigger the same HEAD-skip via enable_http_metadata_cache, then revoke
# the service-account token mid-session so phase B's first range GET hits a
# real minio 403. REFRESH_INFO swaps the secret to a second token on refresh.
#
# Usage:
#   source ./scripts/run_s3_test_server.sh
#   source scripts/set_s3_test_server_variables.sh
#   make release
#   ./scripts/test_refresh_get_range.sh
#
# Service accounts are minio's revocable per-key tokens, distinct from
# disabling the parent user. Mirrors STS revocation semantically -- parent
# stays enabled, only the cached token is invalidated.

set -euo pipefail

DUCKDB=${DUCKDB:-./build/release/duckdb}
KEY_A=svcacct_phase_a
SEC_A=svcacct_phase_a_secret
KEY_B=svcacct_phase_b
SEC_B=svcacct_phase_b_secret
URL=s3://test-bucket/refresh-range-test.parquet

MC_RUN="docker exec duckdb-minio-minio-1 /usr/bin/mc"
mc() { $MC_RUN "$@"; }

cleanup() {
    mc admin user svcacct rm local "$KEY_A" >/dev/null 2>&1 || true
    mc admin user svcacct rm local "$KEY_B" >/dev/null 2>&1 || true
    mc rm local/test-bucket/refresh-range-test.parquet >/dev/null 2>&1 || true
}
trap cleanup EXIT

mc alias set local http://localhost:9000 duckdb_minio_admin duckdb_minio_admin_password >/dev/null
mc admin info local >/dev/null

mc admin user svcacct rm local "$KEY_A" >/dev/null 2>&1 || true
mc admin user svcacct rm local "$KEY_B" >/dev/null 2>&1 || true
mc admin user svcacct add local minio_duckdb_user --access-key "$KEY_A" --secret-key "$SEC_A" >/dev/null
mc admin user svcacct add local minio_duckdb_user --access-key "$KEY_B" --secret-key "$SEC_B" >/dev/null

"$DUCKDB" -bail -list -noheader <<SQL
.output stdout
LOAD httpfs;
SET enable_http_metadata_cache=true; -- to provoke skipping the HEAD request
SET enable_external_file_cache=false;
SET s3_endpoint='localhost:9000'; SET s3_url_style='path';
SET s3_use_ssl=false;        SET s3_region='eu-west-1';

CREATE SECRET seed (TYPE S3,
    KEY_ID 'duckdb_minio_admin', SECRET 'duckdb_minio_admin_password');
COPY (SELECT range FROM range(1000)) TO '$URL' (FORMAT PARQUET);
DROP SECRET seed;

CREATE SECRET refresh_test (TYPE S3,
    KEY_ID '$KEY_A', SECRET '$SEC_A',
    REFRESH_INFO MAP {'KEY_ID': '$KEY_B', 'SECRET': '$SEC_B'});

-- Phase A: populates http_metadata_cache. Assert read returns 1000.
CREATE TEMP TABLE _a AS SELECT count(*)::BIGINT AS rcount FROM read_parquet('$URL');
SELECT CASE WHEN (SELECT rcount FROM _a) = 1000 THEN NULL
       ELSE error('phase A read != 1000, got ' || (SELECT rcount FROM _a)::VARCHAR) END;

.shell $MC_RUN admin user svcacct rm local $KEY_A

-- Phase B: cache hit -> no HEAD; first range GET hits 403 from revoked
-- token. PR #165 wrapper catches, refreshes via REFRESH_INFO, retries.
-- Force the read into its own statement so the refresh side effects land
-- before the duckdb_logs / duckdb_secrets checks below.
CREATE TEMP TABLE _b AS SELECT count(*)::BIGINT AS rcount FROM read_parquet('$URL');

.output stdout
SELECT CASE
    WHEN (SELECT rcount FROM _b) != 1000
        THEN error('phase B read != 1000, got ' || (SELECT rcount FROM _b)::VARCHAR)
    WHEN (SELECT regexp_extract(secret_string, 'key_id=(\w+)', 1)
          FROM duckdb_secrets() WHERE name='refresh_test') != '$KEY_B'
        THEN error('key_id did not advance')
    ELSE 'PASS: range-GET refresh recovered; key_id $KEY_A -> $KEY_B'
END;
SQL
