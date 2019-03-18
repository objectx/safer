
cmake_minimum_required (VERSION 3.14)

if (NOT CMAKE_CROSSCOMPILING)
    include (TestBigEndian)
    include (CheckCXXSourceRuns)
    include (CheckCXXCompilerFlag)
    TEST_BIG_ENDIAN (IS_BIG_ENDIAN)
    if (NOT IS_BIG_ENDIAN)
        set (TARGET_LITTLE_ENDIAN 1)
    endif ()
    CHECK_CXX_SOURCE_RUNS ([=[
        #include <cstdint>
        int main () {
            const uint8_t tmp [] = { 0, 4, 3, 2, 1 } ;
            uint32_t v = *((const uint32_t *)(&tmp [1])) ;
            if (v == 0x01020304u) {
                return 0 ;
            }
            return 1 ;
        }
    ]=] TARGET_ALLOWS_UNALIGNED_ACCESS)
    if (${WIN32})
        CHECK_CXX_COMPILER_FLAG ("/arch:AVX" HAVE_SSE3)
    else ()
        CHECK_CXX_COMPILER_FLAG ("-msse3" HAVE_SSE3)
    endif ()
    target_compile_definitions (${PROJECT_NAME} PRIVATE HAVE_CONFIG_H=1)
endif ()

configure_file (${CMAKE_CURRENT_SOURCE_DIR}/config.h.in
                ${CMAKE_CURRENT_BINARY_DIR}/include/config.h @ONLY)

target_sources (${PROJECT_NAME} PRIVATE safer.cpp table.cpp)

target_include_directories (${PROJECT_NAME}
                            PRIVATE ${CMAKE_CURRENT_BINARY_DIR}/include)
target_compile_features (${PROJECT_NAME} PUBLIC cxx_std_14)
