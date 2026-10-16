set(VCPKG_TARGET_ARCHITECTURE arm64)
set(VCPKG_CRT_LINKAGE static)
set(VCPKG_LIBRARY_LINKAGE static)
set(VCPKG_BUILD_TYPE release)

set(VCPKG_LOAD_VCVARS_ENV ON)

# Work around https://github.com/openssl/openssl/issues/26239 for OpenSSL only.
if(PORT STREQUAL "openssl")
	set(VCPKG_CHAINLOAD_TOOLCHAIN_FILE "${CMAKE_CURRENT_LIST_DIR}/scripts/clangcl.cmake")

	if(DEFINED VCPKG_PLATFORM_TOOLSET)
		set(VCPKG_PLATFORM_TOOLSET ClangCL)
	endif()
endif()
