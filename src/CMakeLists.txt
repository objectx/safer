
cmake_minimum_required (VERSION 3.3)

set (SOURCE_FILES safer.cpp)

add_library (safer ${SOURCE_FILES})
target_include_directories (safer PUBLIC ${CMAKE_SOURCE_DIR}/include)
