
cmake_minimum_required (VERSION 3.3)

project (SAFER
    LANGUAGES C CXX
    VERSION 1.0.0.0)

list (INSERT CMAKE_MODULE_PATH 0 ${SAFER_SOURCE_DIR}/CMake)

function (setvar_default var_)
    if (NOT DEFINED ${var_})
        set (${var_} ${ARGN} PARENT_SCOPE)
    endif ()
endfunction ()

setvar_default (CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
setvar_default (CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
setvar_default (CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

include (EnableCppFormat)
include (EnableCatch)

add_subdirectory (src)
add_subdirectory (test)
