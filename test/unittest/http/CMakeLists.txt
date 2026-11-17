target_sources(
  unittest_httpfs
  PRIVATE browser_adapter_test.cpp
          cancellation_test.cpp
          connection_reuse_test.cpp
          fd_exhaustion_test.cpp
          http_cache_policy_test.cpp
          hffs_test.cpp
          http_request_session_test.cpp
          http_test_helper.cpp
          openssl_test.cpp
          positional_read_test.cpp
          range_read_test.cpp
          sequential_read_test.cpp
          tls_version_test.cpp)
