target_sources(
  httpfs_library
  PRIVATE httpfs.cpp httpfs_transport.cpp http_request.cpp http_settings.cpp
          http_request_session.cpp http_state.cpp)

if(NOT EMSCRIPTEN)
  target_sources(httpfs_library PRIVATE httpfs_httplib_client.cpp
                                        httpfs_curl_client.cpp)
else()
  target_sources(httpfs_library PRIVATE httpfs_client_wasm.cpp)
endif()
