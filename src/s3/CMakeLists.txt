target_sources(
  httpfs_library
  PRIVATE s3_auth.cpp
          s3_delete.cpp
          s3_endpoint.cpp
          s3_list.cpp
          s3_provider.cpp
          s3_request.cpp
          s3_settings.cpp
          s3_upload_session.cpp
          s3_url.cpp
          s3_xml_response.cpp
          s3fs.cpp)
