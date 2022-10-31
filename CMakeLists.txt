
cmake_minimum_required (VERSION 3.14)

project (safer
         LANGUAGES C CXX
         VERSION 1.0.0.0)

function (setvar_default var_)
    if (NOT DEFINED ${var_})
        set (${var_} ${ARGN} PARENT_SCOPE)
    endif ()
endfunction ()

setvar_default (CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
setvar_default (CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
setvar_default (CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

set (sanitizers_ ${PROJECT_NAME}-sanitizers_)
add_library (${sanitizers_} INTERFACE)
target_compile_options (${sanitizers_} INTERFACE "-fsanitize=address,undefined")
target_link_options (${sanitizers_} INTERFACE "-fsanitize=address,undefined")

add_library (${PROJECT_NAME} STATIC)
target_include_directories (${PROJECT_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries (${PROJECT_NAME} PUBLIC ${sanitizers_})

add_subdirectory (src)
add_subdirectory (test)
