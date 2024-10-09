cmake_minimum_required(VERSION 3.9)

project(nito-tidy VERSION 1.0.0 DESCRIPTION "clang-tidy checks for Nito Core")

include(GNUInstallDirs)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)
set(CMAKE_CXX_EXTENSIONS False)

# TODO: Figure out how to avoid the terminfo check
find_package(LLVM REQUIRED CONFIG)
find_program(CLANG_TIDY_EXE NAMES "clang-tidy-${LLVM_VERSION_MAJOR}" "clang-tidy" HINTS ${LLVM_TOOLS_BINARY_DIR})
message(STATUS "Found LLVM ${LLVM_PACKAGE_VERSION}")
message(STATUS "Found clang-tidy: ${CLANG_TIDY_EXE}")

add_library(nito-tidy MODULE nito-tidy.cpp logprintf.cpp)
target_include_directories(nito-tidy SYSTEM PRIVATE ${LLVM_INCLUDE_DIRS})

# Disable RTTI and exceptions as necessary
if (MSVC)
    target_compile_options(nito-tidy PRIVATE /GR-)
else()
    target_compile_options(nito-tidy PRIVATE -fno-rtti)
    target_compile_options(nito-tidy PRIVATE -fno-exceptions)
endif()

if(CMAKE_HOST_APPLE)
    # ld64 expects no undefined symbols by default
    target_link_options(nito-tidy PRIVATE -Wl,-flat_namespace)
    target_link_options(nito-tidy PRIVATE -Wl,-undefined -Wl,suppress)
endif()

# Add warnings
if (MSVC)
    target_compile_options(nito-tidy PRIVATE /W4)
else()
    target_compile_options(nito-tidy PRIVATE -Wall)
    target_compile_options(nito-tidy PRIVATE -Wextra)
endif()

if(CMAKE_VERSION VERSION_LESS 3.27)
    set(CLANG_TIDY_COMMAND "${CLANG_TIDY_EXE}" "--load=${CMAKE_BINARY_DIR}/${CMAKE_SHARED_MODULE_PREFIX}nito-tidy${CMAKE_SHARED_MODULE_SUFFIX}" "-checks=-*,nito-*")
else()
    # CLANG_TIDY_COMMAND supports generator expressions as of 3.27
    set(CLANG_TIDY_COMMAND "${CLANG_TIDY_EXE}" "--load=$<TARGET_FILE:nito-tidy>" "-checks=-*,nito-*")
endif()

# Create a dummy library that runs clang-tidy tests as a side-effect of building
add_library(nito-tidy-tests OBJECT EXCLUDE_FROM_ALL example_logprintf.cpp)
add_dependencies(nito-tidy-tests nito-tidy)

set_target_properties(nito-tidy-tests PROPERTIES CXX_CLANG_TIDY "${CLANG_TIDY_COMMAND}")


install(TARGETS nito-tidy LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR})
