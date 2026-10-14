if(NOT _DUCKDB_HTTPFS_VCPKG_CLANGCL_TOOLCHAIN)
	set(_DUCKDB_HTTPFS_VCPKG_CLANGCL_TOOLCHAIN ON)

	find_program(CMAKE_C_COMPILER NAMES clang-cl.exe clang-cl REQUIRED)
	find_program(CMAKE_CXX_COMPILER NAMES clang-cl.exe clang-cl REQUIRED)
	find_program(CMAKE_RC_COMPILER NAMES llvm-rc.exe llvm-rc rc.exe rc REQUIRED)

	string(APPEND VCPKG_C_FLAGS " --target=arm64-pc-windows-msvc")
	string(APPEND VCPKG_CXX_FLAGS " --target=arm64-pc-windows-msvc")

	if(DEFINED Z_VCPKG_ROOT_DIR)
		set(_duckdb_httpfs_vcpkg_root "${Z_VCPKG_ROOT_DIR}")
	elseif(DEFINED _VCPKG_ROOT_DIR)
		set(_duckdb_httpfs_vcpkg_root "${_VCPKG_ROOT_DIR}")
	elseif(DEFINED ENV{VCPKG_ROOT})
		set(_duckdb_httpfs_vcpkg_root "$ENV{VCPKG_ROOT}")
	else()
		message(FATAL_ERROR "Unable to determine the vcpkg root")
	endif()

	include("${_duckdb_httpfs_vcpkg_root}/scripts/toolchains/windows.cmake")
endif()
