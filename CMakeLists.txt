cmake_minimum_required(VERSION 2.8.12...3.29)

set(HTTPFS_BASE_FOLDER "extension/httpfs")

project(HTTPFsExtension)

add_extension_definitions()

include_directories(extension/httpfs/include
                    ${DUCKDB_MODULE_BASE_DIR}/third_party/httplib)

build_static_extension(
  httpfs
  extension/httpfs/hffs.cpp
  extension/httpfs/s3fs.cpp
  extension/httpfs/httpfs.cpp
  extension/httpfs/httpfs_client.cpp
  extension/httpfs/http_state.cpp
  extension/httpfs/crypto.cpp
  extension/httpfs/hash_functions.cpp
  extension/httpfs/create_secret_functions.cpp
  extension/httpfs/httpfs_extension.cpp)

set(PARAMETERS "-warnings")
build_loadable_extension(
  httpfs
  ${PARAMETERS}
  extension/httpfs/hffs.cpp
  extension/httpfs/s3fs.cpp
  extension/httpfs/httpfs.cpp
  extension/httpfs/httpfs_client.cpp
  extension/httpfs/http_state.cpp
  extension/httpfs/crypto.cpp
  extension/httpfs/hash_functions.cpp
  extension/httpfs/create_secret_functions.cpp
  extension/httpfs/httpfs_extension.cpp)

if(MINGW)
  set(OPENSSL_USE_STATIC_LIBS TRUE)
endif()

find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})
if(EMSCRIPTEN)

else()
  target_link_libraries(httpfs_loadable_extension duckdb_mbedtls
                        ${OPENSSL_LIBRARIES})
  target_link_libraries(httpfs_extension duckdb_mbedtls ${OPENSSL_LIBRARIES})

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
