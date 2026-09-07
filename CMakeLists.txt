cmake_minimum_required(VERSION 2.8.12...3.29)

project(HTTPFsExtension)

add_extension_definitions()

if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
  add_compile_options(-Wpessimizing-move)
endif()

if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
  add_compile_options(-Werror=thread-safety)
  add_compile_options(-Werror=mismatched-tags)
endif()

if (NOT EMSCRIPTEN)
  add_definitions(-DOVERRIDE_ENCRYPTION_UTILS=1)
else()
  set(DUCKDB_EXTENSION_HTTPFS_LINKED_LIBS "../../third_party/mbedtls/libduckdb_mbedtls.a")
endif()

if(MINGW)
  set(OPENSSL_USE_STATIC_LIBS TRUE)
endif()

find_package(OpenSSL REQUIRED)
find_package(CURL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})
include_directories(${CURL_INCLUDE_DIRS})

include_directories(src/include
                    ${DUCKDB_MODULE_BASE_DIR}/third_party/httplib)
add_subdirectory(src)
set(EXTENSION_SOURCES ${ALL_OBJECT_FILES})

build_static_extension(httpfs ${EXTENSION_SOURCES})

set(PARAMETERS "-warnings")
build_loadable_extension(httpfs ${PARAMETERS} ${EXTENSION_SOURCES})

if(EMSCRIPTEN)
  target_link_libraries(httpfs_loadable_extension duckdb_mbedtls)
else()
  # Link dependencies into extension
  target_link_libraries(httpfs_loadable_extension ${CURL_LIBRARIES})
  target_link_libraries(httpfs_extension ${CURL_LIBRARIES})

  target_link_libraries(httpfs_loadable_extension duckdb_mbedtls
                        ${OPENSSL_LIBRARIES})
  target_link_libraries(httpfs_extension duckdb_mbedtls ${OPENSSL_LIBRARIES})

  if(APPLE)
    find_library(COREFOUNDATION_FRAMEWORK CoreFoundation)
    find_library(SECURITY_FRAMEWORK Security)
    target_link_libraries(httpfs_loadable_extension
                          ${COREFOUNDATION_FRAMEWORK}
                          ${SECURITY_FRAMEWORK})
    target_link_libraries(httpfs_extension ${COREFOUNDATION_FRAMEWORK}
                          ${SECURITY_FRAMEWORK})
  endif()

  if(MINGW)
    find_package(ZLIB)
    target_link_libraries(httpfs_loadable_extension ZLIB::ZLIB -lcrypt32)
    target_link_libraries(httpfs_extension ZLIB::ZLIB -lcrypt32)
  endif()
endif()


install(
  TARGETS httpfs_extension
  EXPORT "${DUCKDB_EXPORT_SET}"
  LIBRARY DESTINATION "${INSTALL_LIB_DIR}"
  ARCHIVE DESTINATION "${INSTALL_LIB_DIR}")

if(BUILD_UNITTESTS AND NOT EMSCRIPTEN)
  add_subdirectory(test/unittest)
endif()
