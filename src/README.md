# Source layout

The root of `src` contains extension composition and functionality shared across
backends. Backend-specific implementation is grouped in shallow directories:

- `http/` contains the generic HTTP filesystem, request sessions, state, and
  transport clients.
- `s3/` contains S3 authentication, URL handling, request execution, listing,
  deletion, and multipart upload.
- `include/http/` and `include/s3/` mirror those implementation directories.

Keep cross-cutting extension registration and secret creation at the root. New
backend-specific code should live in its backend directory, and a reusable
header helper should be exposed as a struct or class with static methods rather
than as free functions.

The unit tests use the same `http/` and `s3/` split under `test/unittest`. The
S3 mock server and shared test helpers live with the S3 tests. Documentation on
the external S3 test setup can be found
[in the DuckDB repository](https://github.com/duckdb/duckdb/blob/main/test/sql/copy/s3/README.md).
