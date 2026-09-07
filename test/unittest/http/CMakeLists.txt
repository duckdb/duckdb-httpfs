target_sources(
  unittest_httpfs
  PRIVATE connection_reuse_test.cpp
          hffs_test.cpp
          http_request_session_test.cpp
          http_test_helper.cpp
          positional_read_test.cpp
          range_read_test.cpp
          sequential_read_test.cpp)
