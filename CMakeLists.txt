cmake_minimum_required(VERSION 3.16)
project(PQC_HBS_Benchmark LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

option(PQC_ENABLE_CUSTOM_SPHINCS "Build libhbs (custom SPHINCS+)" ON)
option(PQC_REQUIRE_OQS "Fail if liboqs is missing" OFF)
option(PQC_BUILD_GUI "Build the desktop window" ON)

# aqt default: C:\Qt\6.8.3\msvc2022_64
if(WIN32)
    file(GLOB _PQC_QT_HINTS
        "C:/Qt/6.*/msvc2022_64"
        "C:/Qt/6.*/msvc2019_64"
        "C:/Qt/5.*/msvc2019_64"
        "C:/Qt/5.*/msvc2022_64"
    )
    if(_PQC_QT_HINTS)
        list(APPEND CMAKE_PREFIX_PATH ${_PQC_QT_HINTS})
        message(STATUS "Qt search paths: ${_PQC_QT_HINTS}")
    endif()
endif()

find_path(OQS_INCLUDE_DIR NAMES oqs/oqs.h
    HINTS /usr/local/include /usr/include
          "C:/Program Files/liboqs/include"
          $ENV{liboqs_DIR}/include)
find_library(OQS_LIBRARY NAMES oqs liboqs
    HINTS /usr/local/lib /usr/lib
          "C:/Program Files/liboqs/lib"
          $ENV{liboqs_DIR}/lib
          $ENV{liboqs_DIR}/build/lib/Release)

set(PQC_HAS_OQS FALSE)
if(OQS_INCLUDE_DIR AND OQS_LIBRARY)
    set(PQC_HAS_OQS TRUE)
    message(STATUS "liboqs: ${OQS_LIBRARY}")
elseif(PQC_REQUIRE_OQS)
    message(FATAL_ERROR "liboqs not found")
else()
    message(WARNING "liboqs not found — OQS schemes will be skipped at runtime")
endif()

set(PQC_HAS_CUSTOM_SPHINCS FALSE)
if(PQC_ENABLE_CUSTOM_SPHINCS AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/libs/hbs/CMakeLists.txt")
    add_subdirectory(libs/hbs)
    set(PQC_HAS_CUSTOM_SPHINCS TRUE)
endif()

add_executable(benchmark src/benchmark.cpp)
add_executable(tester src/tester.cpp)

if(PQC_HAS_OQS)
    target_include_directories(benchmark PRIVATE ${OQS_INCLUDE_DIR})
    target_link_libraries(benchmark PRIVATE ${OQS_LIBRARY})
    target_compile_definitions(benchmark PRIVATE PQC_HAS_OQS=1)
endif()

if(PQC_HAS_CUSTOM_SPHINCS)
    target_link_libraries(benchmark PRIVATE hbs)
    target_compile_definitions(benchmark PRIVATE PQC_HAS_CUSTOM_SPHINCS=1)
    if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_hbs.cpp")
        add_executable(test_hbs tests/test_hbs.cpp)
        target_link_libraries(test_hbs PRIVATE hbs)
    endif()
endif()

if(WIN32)
    target_link_libraries(benchmark PRIVATE psapi)
endif()

function(pqc_add_qt_gui)
    add_executable(hbs-bench WIN32
        src/gui/main.cpp
        src/gui/main_window.cpp
        src/gui/main_window.h
    )
    set_target_properties(hbs-bench PROPERTIES AUTOMOC ON AUTORCC ON AUTOUIC ON)
    target_link_libraries(hbs-bench PRIVATE Qt${QT_VERSION_MAJOR}::Widgets)
    add_dependencies(hbs-bench benchmark)

    if(WIN32)
        get_target_property(QT_QMAKE_EXECUTABLE Qt${QT_VERSION_MAJOR}::qmake IMPORTED_LOCATION)
        get_filename_component(QT_BIN_DIR "${QT_QMAKE_EXECUTABLE}" DIRECTORY)
        find_program(WINDEPLOYQT_EXECUTABLE windeployqt HINTS "${QT_BIN_DIR}")
        if(WINDEPLOYQT_EXECUTABLE)
            add_custom_command(TARGET hbs-bench POST_BUILD
                COMMAND "${WINDEPLOYQT_EXECUTABLE}"
                        --no-translations
                        --no-compiler-runtime
                        "$<TARGET_FILE:hbs-bench>"
                COMMENT "Deploying Qt DLLs next to hbs-bench.exe"
            )
        else()
            message(WARNING "windeployqt not found. You may need to copy Qt DLLs next to hbs-bench.exe.")
        endif()
    endif()
endfunction()

if(PQC_BUILD_GUI)
    find_package(QT NAMES Qt6 Qt5 COMPONENTS Widgets QUIET)
    if(QT_FOUND)
        find_package(Qt${QT_VERSION_MAJOR} COMPONENTS Widgets REQUIRED)
        pqc_add_qt_gui()
        message(STATUS "GUI: Qt ${QT_VERSION_MAJOR} Widgets")
    elseif(WIN32)
        add_executable(hbs-bench WIN32 src/gui/win32_main.cpp)
        target_compile_definitions(hbs-bench PRIVATE UNICODE _UNICODE)
        target_link_libraries(hbs-bench PRIVATE comctl32 comdlg32)
        add_dependencies(hbs-bench benchmark)
        message(STATUS "GUI: Win32 (Qt not found — this is fine)")
    else()
        message(WARNING "Qt Widgets not found — Linux GUI not built. Install qt6-base-dev.")
    endif()
endif()

if(TARGET hbs-bench)
    message(STATUS "GUI target: hbs-bench")
else()
    message(STATUS "GUI target: (not built)")
endif()
