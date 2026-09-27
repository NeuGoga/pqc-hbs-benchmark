cmake_minimum_required(VERSION 3.14)
project(libhbs)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_library(hbs
    src/crypto/keccak.cpp
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
else()
    target_compile_options(hbs PRIVATE -O3 -march=native)
endif()

if(WIN32)
    target_compile_definitions(hbs PRIVATE _WIN32)
    target_link_libraries(hbs PRIVATE bcrypt)
endif()
