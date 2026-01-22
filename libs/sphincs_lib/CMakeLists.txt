cmake_minimum_required(VERSION 3.14)
project(SphincsPlusLib)

set(CMAKE_CXX_STANDARD 17)

add_library(sphincs_lib SHARED sphincs.cpp)

target_include_directories(sphincs_lib PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

if(WIN32)
    target_compile_definitions(sphincs_lib PRIVATE _WIN32)
    target_link_libraries(sphincs_lib PRIVATE bcrypt)
endif()