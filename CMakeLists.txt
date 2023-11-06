cmake_minimum_required (VERSION 3.16...3.19)

project (libgit2_example
    LANGUAGES CXX C
)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_EXTENSIONS OFF)

# Add install to VS; set install dir to build_xxx/out
set(CMAKE_VS_INCLUDE_INSTALL_TO_DEFAULT_BUILD OFF)
set(CMAKE_INSTALL_PREFIX ${CMAKE_BINARY_DIR}/out)
set(CMAKE_SKIP_INSTALL_ALL_DEPENDENCY TRUE)

# Set temp directory for all runtime output, this is needed for the unit tests
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_DEBUG ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_RELEASE ${CMAKE_BINARY_DIR}/bin)

# Don't include imported header files (i.e. from conan) as system files. VS 2019 intellisense seems to be buggy with this feature and is not able to locate those header files!
set(CMAKE_NO_SYSTEM_FROM_IMPORTED ON)

add_subdirectory(libgit2)
add_subdirectory(example) 