set(HTTPFS_SOURCES
    hffs.cpp
    s3fs.cpp
    httpfs.cpp
    http_state.cpp
    crypto.cpp
    hash_functions.cpp
    create_secret_functions.cpp
    httpfs_extension.cpp
    httpfs_functions.cpp)
if(NOT EMSCRIPTEN)
  set(HTTPFS_SOURCES ${HTTPFS_SOURCES} crypto.cpp httpfs_httplib_client.cpp
                     httpfs_curl_client.cpp)
else()
  set(HTTPFS_SOURCES ${HTTPFS_SOURCES} httpfs_client_wasm.cpp)
endif()

add_library(httpfs_library OBJECT ${HTTPFS_SOURCES})
set(ALL_OBJECT_FILES
    ${ALL_OBJECT_FILES} $<TARGET_OBJECTS:httpfs_library>
    PARENT_SCOPE)
