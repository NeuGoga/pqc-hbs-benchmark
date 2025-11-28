cmake_minimum_required(VERSION 3.14)
project(PQC_HBS_Benchmark)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(UNIX)
    find_package(OpenSSL REQUIRED)
    message(STATUS "Found OpenSSL: " ${OPENSSL_INCLUDE_DIR})
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

if (OQS_INCLUDE_DIR AND OQS_LIBRARY)
    message(STATUS "Found OQS Header: ${OQS_INCLUDE_DIR}")
    message(STATUS "Found OQS Library: ${OQS_LIBRARY}")
else()
    message(FATAL_ERROR "Could NOT find liboqs. \n")
endif()

add_executable(benchmark src/benchmark.cpp)

target_include_directories(benchmark PRIVATE ${OQS_INCLUDE_DIR})

target_link_libraries(benchmark PRIVATE ${OQS_LIBRARY})

if(UNIX)
    target_link_libraries(benchmark PRIVATE OpenSSL::SSL OpenSSL::Crypto)
endif()

if(MSVC)
    set_target_properties(benchmark PROPERTIES LINK_FLAGS "/STACK:10000000")
    set_property(TARGET benchmark PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreadedDLL")
endif()

add_executable(tester src/tester.cpp)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)