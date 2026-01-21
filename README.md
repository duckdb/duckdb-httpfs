# DuckDB HTTPFS extension

The httpfs extension is an autoloadable extension implementing a file system that allows reading remote/writing remote files. For plain HTTP(S), only file reading is supported. For object storage using the S3 API, the httpfs extension supports reading/writing/globbing files.

## Building & Loading the Extension

The DuckDB submodule must be initialized prior to building.

```bash
git submodule init
git pull --recurse-submodules
```

To build, type
```
make
```

## Testing

Testing uses a local MinIO setup using Docker. See the [testing documentation for more information on how to set this up locally](test).
