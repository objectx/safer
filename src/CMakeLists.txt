
cmake_minimum_required (VERSION 3.3)

set (SOURCE_FILES safer.cpp table.cpp)

set (TARGET_NAME "safer")
add_library (${TARGET_NAME} ${SOURCE_FILES})
    target_include_directories (${TARGET_NAME}
        PUBLIC ${SAFER_SOURCE_DIR}/include
        PRIVATE ${CMAKE_CURRENT_BINARY_DIR}/include)
