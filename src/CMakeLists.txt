set(HTTPFS_SOURCES hffs.cpp create_secret_functions.cpp httpfs_extension.cpp)
if(NOT EMSCRIPTEN)
  list(APPEND HTTPFS_SOURCES crypto.cpp)
endif()

add_library(httpfs_library OBJECT ${HTTPFS_SOURCES})
add_subdirectory(http)
add_subdirectory(s3)

set(ALL_OBJECT_FILES
    ${ALL_OBJECT_FILES} $<TARGET_OBJECTS:httpfs_library>
    PARENT_SCOPE)
