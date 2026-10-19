# DuckDB HTTPFS extension

The httpfs extension is an autoloadable extension implementing a file system that allows reading remote/writing remote files. For plain HTTP(S), only file reading is supported. For object storage using the S3 API, the httpfs extension supports reading/writing/globbing files.

## Building & Loading the Extension

The DuckDB submodule must be initialized prior to building.
```bash
git submodule init
git pull --recurse-submodules
```

To build, type:
```
make setup-vcpkg
VCPKG_TOOLCHAIN_PATH=$pwd/vcpkg/scripts/buildsystems/vcpkg.cmake GEN=ninja make
```
Consider adding `GEN=ninja` and having `ccache` installed to speed up recompilations.

### VCPKG
`vcpkg`, a package manager for C++, it's highly reccomended to generate reproducible and stable builds, in particular here it serves to build the `openssl` and `curl` dependencies.
Without the `VCPKG_TOOLCHAIN_PATH` option, locally available libraries will be used from default search paths.

## Running
The resulting binary, that will also statically link and load the `httfps`, it's available like:
```
./build/release/duckdb
```
```sql
FROM read_blob('https://duckdb.org/');
```

## Deprecated S3 URL parameters

S3-family URLs treat `?` and the following text as literal object-key bytes by default.
Configure credentials, endpoints and request options in secrets. Existing workflows that
use URL parameters, including `s3_version_id` and `gcs_generation`, can opt in temporarily:

```sql
LOAD httpfs;
SET s3_enable_deprecated_url_parameters = true;
```

This restores the legacy URL parameter behavior, including credential inheritance and
authenticated HTTP redirects. Without opt-in, authenticated requests do not follow ordinary
HTTP redirects; S3 region correction still works.
Literal `?` is supported in object names, but directory operations reject paths containing
`?` because DuckDB's path joining treats it as a query suffix.

The setting is global to the database instance. Its default `NULL` means disabled but
undecided. Explicit `false` permanently disables it, including for other connections:

```sql
SET s3_enable_deprecated_url_parameters = false;
```

`RESET` or `SET ... = NULL` returns to the default and permits a later opt-in.
After explicit `false`, the setting cannot be reset or enabled; enabling requires a new
database instance. Already-running operations keep their starting policy.
After `RESET`, use `duckdb_settings()` to inspect the default: the current core version's
`current_setting()` cannot read an unset NULL extension default.
Set the URL policy before reading S3 data. DuckDB's core byte cache uses the raw path and
does not distinguish literal and legacy interpretations. Changing the policy while readers
or cached data exist can reuse bytes from the other interpretation.
Avoid concurrent setters: explicit opt-out always takes effect, but `current_setting()`
can report a stale value after concurrent changes.

## Testing
Some tests querying remote resources can be run already without further setup:
```
./build/release/test/unittest
```
Further integration testing uses a local MinIO setup using Docker. See the [testing documentation for more information on how to set this up locally](test).
