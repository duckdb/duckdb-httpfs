# WebDAV Tests

This directory contains tests for the WebDAV filesystem implementation in the DuckDB httpfs extension.

## Test Files

- `webdav_docker_test.test` - Comprehensive WebDAV functionality test using a Docker test server

## Running the Tests

### Prerequisites

- Docker and Docker Compose installed
- DuckDB httpfs extension built

### Setup

1. **Start the WebDAV test server:**
   ```bash
   ./scripts/run_webdav_test_server.sh
   ```

   This script will:
   - Start a bytemark/webdav Docker container
   - Create test directory structure with sample CSV files
   - Set up test data for reading and globbing tests
   - Configure authentication (username: `duckdb_webdav_user`, password: `duckdb_webdav_password`)

2. **Set environment variables:**
   ```bash
   source ./scripts/set_webdav_test_server_variables.sh
   ```

   This sets:
   - `WEBDAV_TEST_SERVER_AVAILABLE=1`
   - `WEBDAV_TEST_USERNAME=duckdb_webdav_user`
   - `WEBDAV_TEST_PASSWORD=duckdb_webdav_password`
   - `WEBDAV_TEST_ENDPOINT=http://localhost:9100`
   - `WEBDAV_TEST_BASE_URL=webdav://localhost:9100`

3. **Run the tests:**
   ```bash
   # Run all WebDAV tests with environment variables
   WEBDAV_TEST_SERVER_AVAILABLE=1 \
   WEBDAV_TEST_USERNAME=duckdb_webdav_user \
   WEBDAV_TEST_PASSWORD=duckdb_webdav_password \
   WEBDAV_TEST_BASE_URL=webdav://localhost:9100 \
     build/debug/test/unittest test/sql/webdav/*.test

   # Or run a specific test
   WEBDAV_TEST_SERVER_AVAILABLE=1 \
   WEBDAV_TEST_USERNAME=duckdb_webdav_user \
   WEBDAV_TEST_PASSWORD=duckdb_webdav_password \
   WEBDAV_TEST_BASE_URL=webdav://localhost:9100 \
     build/debug/test/unittest test/sql/webdav/webdav_docker_test.test
   ```

4. **Stop the test server (when done):**
   ```bash
   ./scripts/stop_webdav_test_server.sh
   ```

## What the Tests Cover

The `webdav_docker_test.test` file tests the following functionality:

### Authentication
- Creating WebDAV secrets with username/password
- Verifying secret creation in `duckdb_secrets()`

### Reading Operations
- Reading simple text files from WebDAV
- Reading CSV files from WebDAV
- Reading CSV files from subdirectories

### Globbing and Pattern Matching
- Non-recursive globbing with `*.csv` patterns
- Recursive globbing with `**/*.csv` patterns
- Hive-style partitioning with glob patterns
- Filtering data from hive-partitioned directories
- Complex glob patterns like `subdir*/*.csv`

### Writing Operations
- Writing CSV files to WebDAV
- Writing to subdirectories
- Writing multiple files and reading them back with glob patterns

### Integration Tests
- Reading all files after write operations
- Verifying file counts with glob patterns
- End-to-end workflow: create table → write to WebDAV → read back

## Test Data Structure

The test server creates the following directory structure:

```
/data/
├── hello.txt                    # Simple text file
├── test-dir/
│   ├── test1.csv               # Sample CSV with 2 rows
│   ├── subdir1/
│   │   └── test2.csv           # Sample CSV with 2 rows
│   └── subdir2/
│       └── test3.csv           # Sample CSV with 2 rows
└── glob-test/
    ├── year=2023/
    │   └── data.csv            # Hive-partitioned data
    └── year=2024/
        └── data.csv            # Hive-partitioned data
```

Additional files are created during the test execution to verify write operations.

## Docker Container Details

- **Image**: `bytemark/webdav`
- **Port**: 9100 (maps to container port 80)
- **Authentication**: Basic HTTP authentication
- **Data Storage**: Ephemeral (inside container only, automatically cleaned on restart)
- **Note**: Port 9100 is used to avoid conflicts with other services

## Troubleshooting

### Container won't start
```bash
# Check if port 9100 is already in use
lsof -i :9100

# Check Docker logs
docker logs duckdb-webdav-webdav-1
```

### Tests fail with authentication errors
Ensure the environment variables are set correctly:
```bash
source ./scripts/set_webdav_test_server_variables.sh
env | grep WEBDAV
```

### Tests fail with connection errors
Verify the WebDAV server is running:
```bash
curl -u duckdb_webdav_user:duckdb_webdav_password http://localhost:9100/
```

### Clean slate restart
```bash
./scripts/stop_webdav_test_server.sh
./scripts/run_webdav_test_server.sh
source ./scripts/set_webdav_test_server_variables.sh
```

## Notes

- The test server runs on `localhost:9100`, ensure this port is available
- Test data is stored ephemerally inside the container and is automatically cleaned up when the container is stopped
- The tests use the `webdav://` protocol scheme, which is handled by the WebDAV filesystem implementation
- All write operations during tests create actual files on the WebDAV server that can be inspected during the test run
- **Configuration**: The base URL is configurable via the `WEBDAV_TEST_BASE_URL` environment variable, allowing you to test against different WebDAV servers or ports
- **Colima users**: Port 9100 is used because Colima (Lima) requires specific port forwarding configuration. If using Docker Desktop, you can change the port in `scripts/webdav.yml` if needed
- **No cleanup needed**: Since no volumes are used, test data is automatically cleaned when the container restarts
