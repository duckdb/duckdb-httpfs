target_sources(
  httpfs_library PRIVATE httpfs.cpp http_request.cpp http_settings.cpp
                         http_request_session.cpp http_state.cpp)

if(NOT EMSCRIPTEN)
  target_sources(
    httpfs_library PRIVATE httpfs_httplib_client.cpp
                           httpfs_connection_caching.cpp httpfs_curl_client.cpp)
else()
  target_sources(httpfs_library PRIVATE httpfs_client_wasm.cpp)
endif()
