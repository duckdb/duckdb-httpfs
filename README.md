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

### Preloading CA certificates

HTTPFS normally loads its CA certificate bundle on the first HTTP(S) request.
To initialize the cache without a network request before restricting local file access, run:

```sql
LOAD httpfs;
-- Optionally set ca_cert_file to a custom PEM bundle first.
CALL httpfs_preload_ca_certificates();
SET disabled_filesystems = 'LocalFileSystem';
SET lock_configuration = true;
```

The command uses the current `ca_cert_file` setting, or the default bundle lookup when it is empty.
It preserves filesystem permission checks and TLS verification. Connections with the same
`ca_cert_file` setting and HTTP client provider reuse the cached bundle; changing `httpfs_client_implementation` or
`httpfs_connection_caching` replaces that provider, so preload after configuring those settings.
Platforms without a bundle file retain the existing native trust-store fallback.

## Testing
Some tests querying remote resources can be run already without further setup:
```
./build/release/test/unittest
```
Further integration testing uses a local MinIO setup using Docker. See the [testing documentation for more information on how to set this up locally](test).
