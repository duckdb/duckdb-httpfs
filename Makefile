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
