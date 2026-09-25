cmake_minimum_required(VERSION 3.20)

project(xxemul
    VERSION 0.1.0
    DESCRIPTION "Pure C x86 and ARM instruction emulator"
    LANGUAGES C
)

include(GNUInstallDirs)
include(CTest)

option(BUILD_SHARED_LIBS "Build xxemul as a shared library" OFF)
option(XXEMUL_BUILD_CLI "Build the flat-region command-line runner" ON)
option(XXEMUL_BUILD_VIEWER "Build the DOS display viewer" ON)
option(XXEMUL_BUILD_TESTS "Build xxemul tests" ${PROJECT_IS_TOP_LEVEL})
option(XXEMUL_USE_SYSTEM_CDISASM "Use an installed cdisasm package" OFF)
option(XXEMUL_CDISASM_EXTRA_OPCODES "Enable cdisasm's generated extra opcode catalog" ON)
set(XXEMUL_VIEWER_BACKEND "auto" CACHE STRING "Viewer backend: auto, win32, or sdl2")
set_property(CACHE XXEMUL_VIEWER_BACKEND PROPERTY STRINGS auto win32 sdl2)

set(XXEMUL_CDISASM_SOURCE_DIR
    "${CMAKE_CURRENT_SOURCE_DIR}/../cdisasm"
    CACHE PATH "Path to the cdisasm source tree")
set(XXEMUL_XXFCLIB_SOURCE_DIR
    "${CMAKE_CURRENT_SOURCE_DIR}/../xxfclib"
    CACHE PATH "Path to the xxfclib source tree")
set(XXEMUL_UPX_FIXTURE_DIR
    "${CMAKE_CURRENT_SOURCE_DIR}/build-upx-fixtures"
    CACHE PATH "Optional UPX executable fixtures for integration tests")

if(NOT TARGET cdisasm::cdisasm)
    if(XXEMUL_USE_SYSTEM_CDISASM)
        find_package(cdisasm CONFIG REQUIRED)
    else()
        if(NOT EXISTS "${XXEMUL_CDISASM_SOURCE_DIR}/CMakeLists.txt")
            message(FATAL_ERROR "cdisasm was not found at ${XXEMUL_CDISASM_SOURCE_DIR}")
        endif()
        set(CDISASM_BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)
        set(CDISASM_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
        set(CDISASM_BUILD_FUZZERS OFF CACHE BOOL "" FORCE)
        set(CDISASM_BUILD_PACKAGE_TESTS OFF CACHE BOOL "" FORCE)
        set(CDISASM_VERIFY_GENERATED OFF CACHE BOOL "" FORCE)
        set(USE_ARCH_X86 ON CACHE BOOL "" FORCE)
        set(USE_ARCH_ARM ON CACHE BOOL "" FORCE)
        set(USE_DISASM_FORMAT ON CACHE BOOL "" FORCE)
        set(USE_EXTRA_OPCODES ${XXEMUL_CDISASM_EXTRA_OPCODES} CACHE BOOL "" FORCE)
        set(_xxemul_build_testing "${BUILD_TESTING}")
        set(BUILD_TESTING OFF)
        add_subdirectory(
            "${XXEMUL_CDISASM_SOURCE_DIR}"
            "${CMAKE_CURRENT_BINARY_DIR}/_deps/cdisasm"
            EXCLUDE_FROM_ALL)
        set(BUILD_TESTING "${_xxemul_build_testing}")
        unset(_xxemul_build_testing)
    endif()
endif()

if(NOT TARGET xxfclib::xxfclib)
    if(NOT EXISTS "${XXEMUL_XXFCLIB_SOURCE_DIR}/CMakeLists.txt")
        message(FATAL_ERROR "xxfclib was not found at ${XXEMUL_XXFCLIB_SOURCE_DIR}")
    endif()
    set(XXFC_BUILD_TESTS OFF CACHE BOOL "" FORCE)
    set(XXFC_BUILD_SAMPLES OFF CACHE BOOL "" FORCE)
    add_subdirectory(
        "${XXEMUL_XXFCLIB_SOURCE_DIR}"
        "${CMAKE_CURRENT_BINARY_DIR}/_deps/xxfclib"
        EXCLUDE_FROM_ALL)
endif()

add_library(xxemul
    include/xxemul/xxemul.h
    src/xxemul_internal.h
    src/xxemul.c
    src/xxemul_x86.c
    src/xxemul_arm.c
    src/xxemul_display.c
    src/xxemul_image.c
    src/formats/xxemul_pe.c
    src/formats/xxemul_elf.c
    src/formats/xxemul_macho.c
    src/formats/xxemul_com.c
    src/formats/xxemul_msdos_exe.c
    src/platforms/xxemul_dos_loader.c
    src/platforms/xxemul_msdos.c
    src/platforms/xxemul_dos_files.c
    src/platforms/xxemul_bios.c
    src/platforms/xxemul_dpmi.c
    src/platforms/xxemul_windows.c
    src/platforms/xxemul_linux.c
)
add_library(xxemul::xxemul ALIAS xxemul)

target_compile_features(xxemul PUBLIC c_std_11)
set_target_properties(xxemul PROPERTIES
    C_STANDARD 11
    C_STANDARD_REQUIRED YES
    C_EXTENSIONS NO
    VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR}
)
target_compile_definitions(xxemul PRIVATE XXEMUL_BUILDING_LIBRARY)
target_include_directories(xxemul
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)
target_link_libraries(xxemul
    PRIVATE
        cdisasm::cdisasm
        xxfclib::xxfclib
)

if(NOT BUILD_SHARED_LIBS)
    target_compile_definitions(xxemul PUBLIC XXEMUL_STATIC)
endif()

if(MSVC)
    target_compile_options(xxemul PRIVATE /W4 /permissive-)
else()
    target_compile_options(xxemul PRIVATE -Wall -Wextra -Wpedantic)
endif()

if(XXEMUL_BUILD_CLI)
    add_executable(xxemul_cli tools/xxemul_cli.c)
    target_compile_features(xxemul_cli PRIVATE c_std_11)
    target_link_libraries(xxemul_cli PRIVATE xxemul::xxemul)
endif()

if(XXEMUL_BUILD_VIEWER)
    string(TOLOWER "${XXEMUL_VIEWER_BACKEND}" _xxemul_viewer_backend)
    if(_xxemul_viewer_backend STREQUAL "auto")
        if(WIN32)
            set(_xxemul_viewer_backend "win32")
        else()
            set(_xxemul_viewer_backend "sdl2")
        endif()
    endif()
    if(_xxemul_viewer_backend STREQUAL "win32")
        if(NOT WIN32)
            message(FATAL_ERROR "The win32 viewer backend requires Windows")
        endif()
        set(_xxemul_viewer_source tools/xxemul_viewer.c)
    elseif(_xxemul_viewer_backend STREQUAL "sdl2")
        set(_xxemul_viewer_source tools/xxemul_viewer_sdl.c)
        find_package(SDL2 CONFIG QUIET)
        if(TARGET SDL2::SDL2)
            set(_xxemul_sdl_target SDL2::SDL2)
        else()
            find_package(PkgConfig QUIET)
            if(PkgConfig_FOUND)
                pkg_check_modules(XXEMUL_SDL2 QUIET IMPORTED_TARGET sdl2)
            endif()
            if(TARGET PkgConfig::XXEMUL_SDL2)
                set(_xxemul_sdl_target PkgConfig::XXEMUL_SDL2)
            else()
                message(FATAL_ERROR
                    "SDL2 development files are required for the viewer. "
                    "Install SDL2, or set -DXXEMUL_BUILD_VIEWER=OFF.")
            endif()
        endif()
    else()
        message(FATAL_ERROR
            "XXEMUL_VIEWER_BACKEND must be auto, win32, or sdl2")
    endif()
    add_executable(xxemul_viewer
        ${_xxemul_viewer_source}
        tools/xxemul_viewer_app.c
        tools/xxemul_viewer_app.h)
    target_compile_features(xxemul_viewer PRIVATE c_std_11)
    target_link_libraries(xxemul_viewer PRIVATE xxemul::xxemul)
    if(_xxemul_viewer_backend STREQUAL "win32")
        target_compile_definitions(xxemul_viewer PRIVATE WIN32_LEAN_AND_MEAN)
        target_link_libraries(xxemul_viewer PRIVATE user32 gdi32)
    else()
        target_link_libraries(xxemul_viewer PRIVATE ${_xxemul_sdl_target})
    endif()
endif()

if(XXEMUL_BUILD_TESTS AND BUILD_TESTING)
    if(XXEMUL_CDISASM_EXTRA_OPCODES)
        add_executable(xxemul_cdisasm_x87_tests tests/test_cdisasm_x87.c)
        target_link_libraries(xxemul_cdisasm_x87_tests PRIVATE cdisasm::cdisasm)
        add_test(NAME xxemul_cdisasm_x87_tests COMMAND xxemul_cdisasm_x87_tests)
        add_executable(xxemul_x87_tests tests/test_xxemul_x87.c)
        target_link_libraries(xxemul_x87_tests PRIVATE xxemul::xxemul)
        add_test(NAME xxemul_x87_tests COMMAND xxemul_x87_tests)
    endif()
    add_executable(xxemul_tests tests/test_xxemul.c)
    target_compile_features(xxemul_tests PRIVATE c_std_11)
    target_link_libraries(xxemul_tests PRIVATE
        xxemul::xxemul cdisasm::cdisasm xxfclib::xxfclib)
    add_test(NAME xxemul_tests COMMAND xxemul_tests)
    add_executable(xxemul_format_tests tests/test_formats.c)
    target_compile_features(xxemul_format_tests PRIVATE c_std_11)
    target_link_libraries(xxemul_format_tests PRIVATE xxemul::xxemul)
    add_test(NAME xxemul_format_tests COMMAND xxemul_format_tests)
    add_executable(xxemul_upx_dos_tests tests/test_upx_dos.c)
    target_link_libraries(xxemul_upx_dos_tests PRIVATE
        xxemul::xxemul cdisasm::cdisasm xxfclib::xxfclib)
    if(EXISTS "${XXEMUL_UPX_FIXTURE_DIR}/upx-5.2.1-dos/upx.exe")
        add_test(NAME xxemul_upx_dos_tests COMMAND xxemul_upx_dos_tests
            "${XXEMUL_UPX_FIXTURE_DIR}/upx-5.2.1-dos/upx.exe")
    else()
    add_test(NAME xxemul_upx_dos_tests COMMAND xxemul_upx_dos_tests)
    endif()
    set(XXEMUL_FASM_DOS_DIR
        "${CMAKE_CURRENT_SOURCE_DIR}/../XEmulator/FASM_DOS"
        CACHE PATH "Optional DOS FASM distribution for integration tests")
    if(EXISTS "${XXEMUL_FASM_DOS_DIR}/FASM.EXE"
        AND EXISTS "${XXEMUL_FASM_DOS_DIR}/EXAMPLES/COMDEMO/COMDEMO.ASM"
        AND EXISTS "${XXEMUL_FASM_DOS_DIR}/EXAMPLES/EXEDEMO/EXEDEMO.ASM")
        file(MAKE_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/fasm-dos-test")
        configure_file(
            "${XXEMUL_FASM_DOS_DIR}/EXAMPLES/COMDEMO/COMDEMO.ASM"
            "${CMAKE_CURRENT_BINARY_DIR}/fasm-dos-test/COMDEMO.ASM" COPYONLY)
        configure_file(
            "${XXEMUL_FASM_DOS_DIR}/EXAMPLES/EXEDEMO/EXEDEMO.ASM"
            "${CMAKE_CURRENT_BINARY_DIR}/fasm-dos-test/EXEDEMO.ASM" COPYONLY)
        add_executable(xxemul_fasm_dos_tests tests/test_fasm_dos.c)
        target_link_libraries(xxemul_fasm_dos_tests PRIVATE xxemul::xxemul)
        add_test(NAME xxemul_fasm_dos_tests COMMAND xxemul_fasm_dos_tests
            "${XXEMUL_FASM_DOS_DIR}/FASM.EXE"
            "${CMAKE_CURRENT_BINARY_DIR}/fasm-dos-test")
    endif()
    if(EXISTS "${XXEMUL_UPX_FIXTURE_DIR}/upx-5.2.1-win32/upx.exe"
        AND EXISTS "${XXEMUL_UPX_FIXTURE_DIR}/upx-5.2.1-win64/upx.exe")
        add_executable(xxemul_upx_windows_tests tests/test_upx_windows.c)
        target_include_directories(xxemul_upx_windows_tests PRIVATE src/platforms)
        target_link_libraries(xxemul_upx_windows_tests PRIVATE xxemul::xxemul)
        add_test(NAME xxemul_upx_windows_tests COMMAND xxemul_upx_windows_tests
            "${XXEMUL_UPX_FIXTURE_DIR}/upx-5.2.1-win32/upx.exe"
            "${XXEMUL_UPX_FIXTURE_DIR}/upx-5.2.1-win64/upx.exe"
            "${XXEMUL_UPX_FIXTURE_DIR}")
    endif()
    if(EXISTS "${XXEMUL_UPX_FIXTURE_DIR}/upx-5.2.1-i386_linux/upx"
        AND EXISTS "${XXEMUL_UPX_FIXTURE_DIR}/upx-5.2.1-amd64_linux/upx")
        add_executable(xxemul_upx_linux_tests tests/test_upx_linux.c)
        target_include_directories(xxemul_upx_linux_tests PRIVATE src)
        target_link_libraries(xxemul_upx_linux_tests PRIVATE
            xxemul::xxemul cdisasm::cdisasm xxfclib::xxfclib)
        add_test(NAME xxemul_upx_linux_tests COMMAND xxemul_upx_linux_tests
            "${XXEMUL_UPX_FIXTURE_DIR}/upx-5.2.1-i386_linux/upx"
            "${XXEMUL_UPX_FIXTURE_DIR}/upx-5.2.1-amd64_linux/upx")
    endif()
    if(XXEMUL_BUILD_VIEWER)
        add_executable(xxemul_viewer_app_tests
            tests/test_viewer_app.c
            tools/xxemul_viewer_app.c)
        target_compile_features(xxemul_viewer_app_tests PRIVATE c_std_11)
        target_include_directories(xxemul_viewer_app_tests PRIVATE tools)
        target_link_libraries(xxemul_viewer_app_tests PRIVATE xxemul::xxemul)
        add_test(NAME xxemul_viewer_app_tests COMMAND xxemul_viewer_app_tests)
    endif()
endif()

install(TARGETS xxemul
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
)
if(XXEMUL_BUILD_VIEWER)
    install(TARGETS xxemul_viewer RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()
install(DIRECTORY include/xxemul DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
