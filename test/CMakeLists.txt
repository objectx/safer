
cmake_minimum_required (VERSION 3.14)

find_package (Catch2 3 REQUIRED)

add_executable (test-${PROJECT_NAME} main.cpp)

target_link_libraries (test-${PROJECT_NAME} PRIVATE safer Catch2::Catch2WithMain)
