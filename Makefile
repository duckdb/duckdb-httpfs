PROJ_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

# Configuration of extension
EXT_NAME=httpfs
EXT_CONFIG=${PROJ_DIR}extension_config.cmake

CORE_EXTENSIONS=''

# Include the Makefile from extension-ci-tools
include extension-ci-tools/makefiles/duckdb_extension.Makefile


## Add some more extra tests
test_release_internal:
	./build/release/$(TEST_PATH) "$(PROJ_DIR)test/*"
	./build/release/$(TEST_PATH) --test-dir duckdb --test-config test/configs/duckdb-tests.json

test_debug_internal:
	./build/debug/$(TEST_PATH) "$(PROJ_DIR)test/*"
	./build/debug/$(TEST_PATH) --test-dir duckdb --test-config test/configs/duckdb-tests.json

test_reldebug_internal:
	./build/reldebug/$(TEST_PATH) "$(PROJ_DIR)test/*"
	./build/reldebug/$(TEST_PATH) --test-dir duckdb --test-config test/configs/duckdb-tests.json
