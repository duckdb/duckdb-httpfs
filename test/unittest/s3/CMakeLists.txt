target_sources(
  unittest_httpfs
  PRIVATE mock_s3_server.cpp
          s3_refresh_storage_test.cpp
          s3_refresh_test.cpp
          s3_request_test.cpp
          s3_retry_test.cpp
          s3_sse_test.cpp
          s3_test_helper.cpp
          scheme_alias_isolation_test.cpp
          s3_upload_config_test.cpp
          s3_upload_lifecycle_test.cpp
          s3_upload_test.cpp
          s3_xml_response_test.cpp)
