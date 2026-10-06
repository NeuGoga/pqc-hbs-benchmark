cmake_minimum_required(VERSION 3.14)

add_library(hbs
    src/crypto/keccak.cpp
    src/crypto/shake.cpp
    src/crypto/rng.cpp
    src/crypto/utils.cpp
    src/sphincs/address.cpp
    src/sphincs/params.cpp
    src/sphincs/hash.cpp
    src/sphincs/wots.cpp
    src/sphincs/fors.cpp
    src/sphincs/sphincs.cpp
    src/merkle/merkle.cpp
    src/registry.cpp
)

target_include_directories(hbs
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)

if(MSVC)
    target_compile_options(hbs PRIVATE /O2 /Oi /Ob2)
    include(CheckCXXCompilerFlag)
    check_cxx_compiler_flag("/arch:AVX2" PQC_HAS_AVX2)
    if(PQC_HAS_AVX2)
        target_compile_options(hbs PRIVATE /arch:AVX2)
    endif()
else()
    target_compile_options(hbs PRIVATE -O3)
    option(PQC_NATIVE_CPU "Optimize libhbs for this CPU (-march=native)" ON)
    if(PQC_NATIVE_CPU)
        target_compile_options(hbs PRIVATE -march=native)
    endif()
endif()

if(WIN32)
    target_link_libraries(hbs PUBLIC bcrypt)
endif()

# Optional OpenSSL SHAKE256 (Windows: OpenSSL-Win64 or vcpkg; Linux: libssl-dev)
if(WIN32 AND NOT OPENSSL_ROOT_DIR)
    if(EXISTS "C:/Program Files/OpenSSL-Win64")
        set(OPENSSL_ROOT_DIR "C:/Program Files/OpenSSL-Win64")
    elseif(EXISTS "C:/Program Files/OpenSSL")
        set(OPENSSL_ROOT_DIR "C:/Program Files/OpenSSL")
    endif()
endif()
find_package(OpenSSL QUIET COMPONENTS Crypto)
if(OpenSSL_FOUND)
    target_link_libraries(hbs PUBLIC OpenSSL::Crypto)
    target_compile_definitions(hbs PRIVATE PQC_HAS_OPENSSL=1)
    message(STATUS "libhbs: SHAKE256 via OpenSSL ${OPENSSL_VERSION}")
else()
    message(STATUS "libhbs: SHAKE256 via scalar Keccak (install OpenSSL for a large speedup)")
endif()

find_package(OpenMP)
if(OpenMP_CXX_FOUND)
    target_link_libraries(hbs PUBLIC OpenMP::OpenMP_CXX)
    message(STATUS "libhbs: OpenMP enabled")
else()
    message(STATUS "libhbs: OpenMP not found — single-thread hashes")
endif()
