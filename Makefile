PROJ_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

# Configuration of extension
EXT_NAME=httpfs
EXT_CONFIG=${PROJ_DIR}extension_config.cmake

# Stabilize all tests in CI
ifdef CI
TEST_FLAGS:=--stabilize-tests
endif
T ?= $(TEST_FLAGS) "test/*"

# Include the Makefile from extension-ci-tools
include extension-ci-tools/makefiles/duckdb_extension.Makefile
include extension-ci-tools/makefiles/vcpkg.Makefile
 
unittest_relassert:
	build/relassert/test/run $(T)

MINIO_TEST_CONFIGS := \
	test/configs/httpfs_dynamic.json \
	test/configs/httpfs_autoloading.json \
	test/configs/httpfs_curl.json \
	test/configs/httpfs_httplib.json \
	test/configs/httpfs_connection_caching.json

TEST_MINIO_FLAGS ?= --track-runtime=30 --batch-timeout=60

.PHONY: test_minio
test_minio:
	@set -e; for config in $(MINIO_TEST_CONFIGS); do \
		scripts/with_s3_test_server.sh build/release/test/run "*" $(TEST_MINIO_FLAGS) --test-config "$(PROJ_DIR)$$config"; \
	done
