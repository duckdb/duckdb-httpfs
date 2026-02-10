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
make vcpkg-setup
VCPKG_TOOLCHAIN_PATH=$pwd/vcpkg/scripts/buildsystems/vcpkg.cmake GEN=ninja make
```

Consider `GEN=ninja` and having `ccache` or equivalent software installed.

To try out the resulting binary that will have a statically linked (and already loaded `httfps` extension), try:
```
./build/release/duckdb
```
```sql
FROM read_blob('https://duckdb.org/');
```

## Testing

Some tests querying remote resources can be run already without further setup:
```
./build/release/test/unittest
```
Further integration testing uses a local MinIO setup using Docker. See the [testing documentation for more information on how to set this up locally](test).
