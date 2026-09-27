cmake_minimum_required(VERSION 3.14)
project(PQC_HBS_Benchmark)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

option(PQC_ENABLE_CUSTOM_SPHINCS "Build the custom hash-based signature library (libhbs)" ON)
option(PQC_REQUIRE_OQS "Fail configure if liboqs is missing" OFF)

if(UNIX)
    find_package(OpenSSL QUIET)
    if(OpenSSL_FOUND)
        message(STATUS "Found OpenSSL: ${OPENSSL_INCLUDE_DIR}")
    endif()
endif()

find_path(OQS_INCLUDE_DIR
    NAMES oqs/oqs.h
    HINTS
        "/usr/local/include"
        "/usr/include"
        "C:/Program Files/liboqs/include"
        "C:/Program Files (x86)/liboqs/include"
        $ENV{liboqs_DIR}/include
)

find_library(OQS_LIBRARY
    NAMES oqs liboqs
    HINTS
        "/usr/local/lib"
        "/usr/lib"
        "C:/Program Files/liboqs/lib"
        "C:/Program Files (x86)/liboqs/lib"
        $ENV{liboqs_DIR}/lib
        $ENV{liboqs_DIR}/build/lib/Release
)

set(PQC_HAS_OQS FALSE)
if(OQS_INCLUDE_DIR AND OQS_LIBRARY)
    set(PQC_HAS_OQS TRUE)
    message(STATUS "Found OQS Header: ${OQS_INCLUDE_DIR}")
    message(STATUS "Found OQS Library: ${OQS_LIBRARY}")
elseif(PQC_REQUIRE_OQS)
    message(FATAL_ERROR "Could NOT find liboqs.")
else()
    message(WARNING "liboqs not found; OQS schemes will be skipped at runtime. Pass -DPQC_REQUIRE_OQS=ON to make this a hard error.")
endif()

set(PQC_HAS_CUSTOM_SPHINCS FALSE)
if(PQC_ENABLE_CUSTOM_SPHINCS AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/libs/hbs/CMakeLists.txt")
    add_subdirectory(libs/hbs)
    set(PQC_HAS_CUSTOM_SPHINCS TRUE)
    message(STATUS "Custom HBS library (libhbs) enabled")
else()
    message(STATUS "Custom HBS library disabled; MY_SPHINCS-* schemes will be skipped")
endif()

add_executable(benchmark src/benchmark.cpp)
add_executable(tester src/tester.cpp)

if(PQC_HAS_OQS)
    target_include_directories(benchmark PRIVATE ${OQS_INCLUDE_DIR})
    target_link_libraries(benchmark PRIVATE ${OQS_LIBRARY})
    target_compile_definitions(benchmark PRIVATE PQC_HAS_OQS=1)
    if(UNIX AND OpenSSL_FOUND)
        target_link_libraries(benchmark PRIVATE OpenSSL::SSL OpenSSL::Crypto)
    endif()
else()
    target_compile_definitions(benchmark PRIVATE PQC_HAS_OQS=0)
endif()

if(PQC_HAS_CUSTOM_SPHINCS)
    target_link_libraries(benchmark PRIVATE hbs)
    target_compile_definitions(benchmark PRIVATE PQC_HAS_CUSTOM_SPHINCS=1)
    add_executable(hbs_selftest tests/test_hbs.cpp)
    target_link_libraries(hbs_selftest PRIVATE hbs)
else()
    target_compile_definitions(benchmark PRIVATE PQC_HAS_CUSTOM_SPHINCS=0)
endif()

if(MSVC)
    set_target_properties(benchmark PROPERTIES LINK_FLAGS "/STACK:10000000")
    set_property(TARGET benchmark PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreadedDLL")
endif()