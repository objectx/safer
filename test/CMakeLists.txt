
cmake_minimum_required (VERSION 3.3)

set (SOURCE_FILES main.cpp)

add_executable (test-safer ${SOURCE_FILES})
target_include_directories (test-safer PRIVATE ${CMAKE_SOURCE_DIR}/include)
target_link_libraries (test-safer PRIVATE safer cppformat)
