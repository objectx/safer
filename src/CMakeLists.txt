
cmake_minimum_required (VERSION 3.3)

if (NOT ${CMAKE_CROSSCOMPILING})
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
    add_definitions ("-DHAVE_CONFIG_H")
endif ()

configure_file (${CMAKE_CURRENT_SOURCE_DIR}/config.h.in ${CMAKE_CURRENT_BINARY_DIR}/include/config.h @ONLY)

set (SOURCE_FILES safer.cpp table.cpp)

set (TARGET_NAME "safer")
add_library (${TARGET_NAME} ${SOURCE_FILES})
    target_include_directories (${TARGET_NAME}
        PUBLIC ${SAFER_SOURCE_DIR}/include
        PRIVATE ${CMAKE_CURRENT_BINARY_DIR}/include)
    target_compile_features (${TARGET_NAME} PRIVATE cxx_auto_type cxx_delegating_constructors)
