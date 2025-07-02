PROJ_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

# Configuration of extension
EXT_NAME=httpfs
EXT_CONFIG=${PROJ_DIR}extension_config.cmake

CORE_EXTENSIONS=''

# Include the Makefile from extension-ci-tools
include extension-ci-tools/makefiles/duckdb_extension.Makefile

#### Misc
format-check:
	python3 duckdb/scripts/format.py --all --check --directories extension/httpfs test

format:
	python3 duckdb/scripts/format.py --all --fix --noconfirm --directories extension/httpfs test

format-fix:
	python3 duckdb/scripts/format.py --all --fix --noconfirm --directories extension/httpfs test

format-main:
	python3 duckdb/scripts/format.py main --fix --noconfirm --directories extension/httpfs test

tidy-check:
	mkdir -p ./build/tidy
	cmake $(GENERATOR) $(BUILD_FLAGS) $(EXT_DEBUG_FLAGS) -DDISABLE_UNITY=1 -DCLANG_TIDY=1 -S $(DUCKDB_SRCDIR) -B build/tidy
	cp duckdb/.clang-tidy build/tidy/.clang-tidy
	cd build/tidy && python3 ../../duckdb/scripts/run-clang-tidy.py '$(PROJ_DIR)extension/httpfs/' -header-filter '$(PROJ_DIR)extension/httpfs/' -quiet ${TIDY_THREAD_PARAMETER} ${TIDY_BINARY_PARAMETER} ${TIDY_PERFORM_CHECKS}

