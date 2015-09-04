
cmake_minimum_required (VERSION 3.3)

set (SOURCE_FILES main.cpp)

set (TARGET_NAME test-safer)
add_executable (${TARGET_NAME} ${SOURCE_FILES})
    target_include_directories (${TARGET_NAME}
        PRIVATE ${CMAKE_CURRENT_BINARY_DIR}/include
                ${SAFER_SOURCE_DIR}/include
                ${CMAKE_BINARY_DIR}/include)
    target_link_libraries (${TARGET_NAME} PRIVATE safer cppformat)
