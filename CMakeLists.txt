cmake_minimum_required(VERSION 3.20)

project(xxemul
    VERSION 0.1.0
    DESCRIPTION "Pure C x86, ARM, Dalvik and .NET CIL instruction emulator"
    LANGUAGES C
)

include(GNUInstallDirs)

# Tests and command-line applications are development support trees. Release
# exports may contain only the library headers and sources.
set(_xxemul_has_tests OFF)
if(IS_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/tests")
    set(_xxemul_has_tests ON)
    include(CTest)
endif()

set(_xxemul_has_tools OFF)
if(IS_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/tools")
    set(_xxemul_has_tools ON)
endif()

option(BUILD_SHARED_LIBS "Build xxemul as a shared library" OFF)
if(_xxemul_has_tools)
    option(XXEMUL_BUILD_CLI "Build the flat-region command-line runner" ON)
    option(XXEMUL_BUILD_VIEWER "Build the DOS display viewer" ON)
else()
    set(XXEMUL_BUILD_CLI OFF)
    set(XXEMUL_BUILD_VIEWER OFF)
endif()
if(_xxemul_has_tests)
    option(XXEMUL_BUILD_TESTS "Build xxemul tests" ${PROJECT_IS_TOP_LEVEL})
else()
    set(XXEMUL_BUILD_TESTS OFF)
endif()
option(XXEMUL_USE_SYSTEM_CDISASM "Use an installed cdisasm package" OFF)
option(XXEMUL_ENABLE_DEX "Build the APK loader and Dalvik interpreter" ON)
option(XXEMUL_ENABLE_DOTNET "Build the managed PE loader and CIL interpreter" OFF)
option(XXEMUL_CDISASM_EXTRA_OPCODES "Enable cdisasm's generated extra opcode catalog" ON)
set(XXEMUL_VIEWER_BACKEND "auto" CACHE STRING "Viewer backend: auto, win32, or sdl2")
set_property(CACHE XXEMUL_VIEWER_BACKEND PROPERTY STRINGS auto win32 sdl2)

set(XXEMUL_CDISASM_SOURCE_DIR
    "${CMAKE_CURRENT_SOURCE_DIR}/../cdisasm"
    CACHE PATH "Path to the cdisasm source tree")
set(XXEMUL_XXFCLIB_SOURCE_DIR
    "${CMAKE_CURRENT_SOURCE_DIR}/../xxfclib"
    CACHE PATH "Path to the xxfclib source tree")
set(XXEMUL_XXBYTE_SOURCE_DIR
    "${CMAKE_CURRENT_SOURCE_DIR}/../xxbyte"
    CACHE PATH "Path to the xxbyte source tree")
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
        set(USE_ARCH_MIPS ON CACHE BOOL "" FORCE)
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

if((XXEMUL_ENABLE_DEX OR XXEMUL_ENABLE_DOTNET) AND NOT TARGET xxbyte::xxbyte)
    if(NOT EXISTS "${XXEMUL_XXBYTE_SOURCE_DIR}/CMakeLists.txt")
        message(FATAL_ERROR "xxbyte was not found at ${XXEMUL_XXBYTE_SOURCE_DIR}")
    endif()
    set(XXBYTE_BUILD_CLI OFF CACHE BOOL "" FORCE)
    set(XXBYTE_BUILD_TESTS OFF CACHE BOOL "" FORCE)
    set(XXBYTE_INSTALL OFF CACHE BOOL "" FORCE)
    set(XXBYTE_FAMILIES "")
    if(XXEMUL_ENABLE_DEX)
        list(APPEND XXBYTE_FAMILIES DEX)
    endif()
    if(XXEMUL_ENABLE_DOTNET)
        list(APPEND XXBYTE_FAMILIES DOTNET)
    endif()
    add_subdirectory("${XXEMUL_XXBYTE_SOURCE_DIR}"
        "${CMAKE_CURRENT_BINARY_DIR}/_deps/xxbyte" EXCLUDE_FROM_ALL)
endif()

add_library(xxemul
    include/xxemul/xxemul.h
    src/xxemul_internal.h
    src/xxemul.c
    src/xxemul_status.c
    src/xxemul_x86.c
    src/xxemul_arm.c
    src/xxemul_mips.c
    src/xxemul_arm_simd.h
    src/xxemul_arm_auth.h
    src/xxemul_arm_auth_exec.h
    src/xxemul_display.c
    src/xxemul_image.c
    src/formats/xxemul_pe.c
    src/formats/xxemul_elf.c
    src/formats/xxemul_macho.c
    src/formats/xxemul_macho_fixups.h
    src/formats/xxemul_com.c
    src/formats/xxemul_msdos_exe.c
    src/platforms/xxemul_dos_loader.c
    src/platforms/xxemul_msdos.c
    src/platforms/xxemul_dos_files.c
    src/platforms/xxemul_bios.c
    src/platforms/xxemul_dpmi.c
    src/platforms/xxemul_windows.c
    src/platforms/xxemul_linux.c
    src/platforms/xxemul_darwin.c
    src/platforms/xxemul_darwin.h
    src/platforms/xxemul_darwin_posix.c
    src/platforms/xxemul_darwin_posix.h
    src/platforms/xxemul_darwin_archive.c
    src/platforms/xxemul_darwin_archive.h
    src/platforms/xxemul_darwin_zlib.c
    src/platforms/xxemul_darwin_zlib.h
    src/platforms/xxemul_darwin_bzip2.c
    src/platforms/xxemul_darwin_bzip2.h
)
add_library(xxemul::xxemul ALIAS xxemul)

if(XXEMUL_ENABLE_DEX)
    target_sources(xxemul PRIVATE
        include/xxemul/xxemul_dex.h
        include/xxemul/xxemul_dex_runtime.h
        src/xxemul_dex_internal.h
        src/formats/xxemul_dex.c
        src/formats/xxemul_apk.c
        src/xxemul_dex_runtime.c)
    target_link_libraries(xxemul PRIVATE xxbyte::xxbyte)
    if(UNIX)
        target_link_libraries(xxemul PRIVATE m)
    endif()
    target_compile_definitions(xxemul PUBLIC XXEMUL_ENABLE_DEX=1)
else()
    target_compile_definitions(xxemul PUBLIC XXEMUL_ENABLE_DEX=0)
endif()

if(XXEMUL_ENABLE_DOTNET)
    target_sources(xxemul PRIVATE
        include/xxemul/xxemul_dotnet.h
        include/xxemul/xxemul_dotnet_runtime.h
        src/xxemul_dotnet_internal.h
        src/formats/xxemul_dotnet.c
        src/xxemul_dotnet_runtime.c)
    target_link_libraries(xxemul PRIVATE xxbyte::xxbyte)
    if(UNIX)
        target_link_libraries(xxemul PRIVATE m)
    endif()
    target_compile_definitions(xxemul PUBLIC XXEMUL_ENABLE_DOTNET=1)
else()
    target_compile_definitions(xxemul PUBLIC XXEMUL_ENABLE_DOTNET=0)
endif()

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
        ${CMAKE_DL_LIBS}
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

if(XXEMUL_BUILD_TESTS AND BUILD_TESTING AND _xxemul_has_tests)
    add_executable(xxemul_dos_cpu_faults_tests tests/test_dos_cpu_faults.c)
    target_link_libraries(xxemul_dos_cpu_faults_tests PRIVATE xxemul::xxemul)
    add_test(NAME xxemul_dos_cpu_faults_tests COMMAND xxemul_dos_cpu_faults_tests)
    set_tests_properties(xxemul_dos_cpu_faults_tests PROPERTIES TIMEOUT 30)
    add_executable(xxemul_dos_exec_tests tests/test_dos_exec.c)
    target_link_libraries(xxemul_dos_exec_tests PRIVATE xxemul::xxemul xxfclib::xxfclib cdisasm::cdisasm)
    file(MAKE_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/dos-exec-run")
    add_test(NAME xxemul_dos_exec_tests COMMAND xxemul_dos_exec_tests "${CMAKE_CURRENT_BINARY_DIR}/dos-exec-run")
    set_tests_properties(xxemul_dos_exec_tests PROPERTIES TIMEOUT 30
        WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/dos-exec-run")
    add_executable(xxemul_dos_irq0_tests tests/test_dos_irq0.c)
    target_link_libraries(xxemul_dos_irq0_tests PRIVATE xxemul::xxemul)
    add_test(NAME xxemul_dos_irq0_tests COMMAND xxemul_dos_irq0_tests)
    set_tests_properties(xxemul_dos_irq0_tests PROPERTIES TIMEOUT 30)
    add_executable(xxemul_dpmi_installation_tests tests/test_dpmi_installation.c)
    target_link_libraries(xxemul_dpmi_installation_tests PRIVATE xxemul::xxemul)
    add_test(NAME xxemul_dpmi_installation_tests COMMAND xxemul_dpmi_installation_tests)
    set_tests_properties(xxemul_dpmi_installation_tests PROPERTIES TIMEOUT 30)
    add_executable(xxemul_dos_string_segments_tests tests/test_dos_string_segments.c)
    target_link_libraries(xxemul_dos_string_segments_tests PRIVATE xxemul::xxemul)
    add_test(NAME xxemul_dos_string_segments_tests COMMAND xxemul_dos_string_segments_tests)
    set_tests_properties(xxemul_dos_string_segments_tests PROPERTIES TIMEOUT 30)
    add_executable(xxemul_dos_mz_compat_tests tests/test_dos_mz_compat.c)
    target_link_libraries(xxemul_dos_mz_compat_tests PRIVATE xxemul::xxemul)
    add_test(NAME xxemul_dos_mz_compat_tests COMMAND xxemul_dos_mz_compat_tests)
    set_tests_properties(xxemul_dos_mz_compat_tests PROPERTIES TIMEOUT 30)
    add_executable(xxemul_dos_bios_clock_tests tests/test_dos_bios_clock.c)
    target_link_libraries(xxemul_dos_bios_clock_tests PRIVATE xxemul::xxemul)
    add_test(NAME xxemul_dos_bios_clock_tests COMMAND xxemul_dos_bios_clock_tests)
    set_tests_properties(xxemul_dos_bios_clock_tests PROPERTIES TIMEOUT 30)
    add_executable(xxemul_dos_file_services_tests tests/test_dos_file_services.c)
    target_link_libraries(xxemul_dos_file_services_tests PRIVATE xxemul::xxemul)
    file(MAKE_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/dos-file-services-run")
    add_test(NAME xxemul_dos_file_services_tests COMMAND xxemul_dos_file_services_tests)
    set_tests_properties(xxemul_dos_file_services_tests PROPERTIES TIMEOUT 30
        WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/dos-file-services-run")
    add_executable(xxemul_windows_modules_tests tests/test_windows_modules.c)
    target_link_libraries(xxemul_windows_modules_tests PRIVATE xxemul::xxemul)
    add_test(NAME xxemul_windows_modules_tests COMMAND xxemul_windows_modules_tests)
    set_tests_properties(xxemul_windows_modules_tests PROPERTIES TIMEOUT 30)
    add_executable(xxemul_windows_runtime_tests tests/test_windows_runtime_edges.c)
    target_link_libraries(xxemul_windows_runtime_tests PRIVATE xxemul::xxemul)
    add_test(NAME xxemul_windows_runtime_tests COMMAND xxemul_windows_runtime_tests)
    set_tests_properties(xxemul_windows_runtime_tests PROPERTIES TIMEOUT 30)
    foreach(component format heap crt_startup mapping memory_status locale startup_abi)
        add_executable(xxemul_windows_${component}_tests tests/test_windows_${component}.c)
        target_link_libraries(xxemul_windows_${component}_tests PRIVATE xxemul::xxemul)
        add_test(NAME xxemul_windows_${component}_tests COMMAND xxemul_windows_${component}_tests)
        set_tests_properties(xxemul_windows_${component}_tests PROPERTIES TIMEOUT 30)
    endforeach()
    add_executable(xxemul_x87_integer_tests tests/test_x87_integer.c)
    target_link_libraries(xxemul_x87_integer_tests PRIVATE xxemul::xxemul)
    add_test(NAME xxemul_x87_integer_tests COMMAND xxemul_x87_integer_tests)
    set_tests_properties(xxemul_x87_integer_tests PROPERTIES TIMEOUT 30)
    if(UNIX)
        foreach(component crt_extensions profile find legacy_file legacy_write)
            add_executable(xxemul_windows_${component}_tests tests/test_windows_${component}.c)
            target_link_libraries(xxemul_windows_${component}_tests PRIVATE xxemul::xxemul)
            add_test(NAME xxemul_windows_${component}_tests COMMAND xxemul_windows_${component}_tests)
            set_tests_properties(xxemul_windows_${component}_tests PROPERTIES TIMEOUT 30)
        endforeach()
        find_package(Python3 COMPONENTS Interpreter QUIET)
        if(Python3_Interpreter_FOUND)
            foreach(component environment_cwd children resources move startup_info child_review dll dll_resources dll_edges resource_generations tls main_dll)
                add_executable(xxemul_windows_${component}_tests tests/test_windows_${component}.c)
                target_link_libraries(xxemul_windows_${component}_tests PRIVATE xxemul::xxemul)
                target_compile_features(xxemul_windows_${component}_tests PRIVATE c_std_11)
                add_test(NAME xxemul_windows_${component}_tests
                    COMMAND "${Python3_EXECUTABLE}" -B "${CMAKE_CURRENT_SOURCE_DIR}/tests/run_windows_guest_tests.py"
                        --test $<TARGET_FILE:xxemul_windows_${component}_tests>
                        --work "${CMAKE_CURRENT_BINARY_DIR}/windows-${component}-tests" --mode ${component})
                set_tests_properties(xxemul_windows_${component}_tests PROPERTIES TIMEOUT 180)
            endforeach()
            add_executable(xxemul_windows_registry_temp_tests tests/test_windows_registry_temp.c)
            target_link_libraries(xxemul_windows_registry_temp_tests PRIVATE xxemul::xxemul)
            add_test(NAME xxemul_windows_registry_temp_tests
                COMMAND "${Python3_EXECUTABLE}" -B "${CMAKE_CURRENT_SOURCE_DIR}/tests/run_windows_registry_temp.py"
                    --test $<TARGET_FILE:xxemul_windows_registry_temp_tests>
                    --work "${CMAKE_CURRENT_BINARY_DIR}/windows-registry-tests")
            set_tests_properties(xxemul_windows_registry_temp_tests PROPERTIES TIMEOUT 60)
            add_executable(xxemul_windows_threads_tests tests/test_windows_threads.c)
            target_link_libraries(xxemul_windows_threads_tests PRIVATE xxemul::xxemul)
            add_test(NAME xxemul_windows_threads_tests
                COMMAND "${Python3_EXECUTABLE}" -B "${CMAKE_CURRENT_SOURCE_DIR}/tests/run_windows_registry_temp.py"
                    --test $<TARGET_FILE:xxemul_windows_threads_tests>
                    --work "${CMAKE_CURRENT_BINARY_DIR}/windows-thread-tests")
            set_tests_properties(xxemul_windows_threads_tests PROPERTIES TIMEOUT 60)
            add_executable(xxemul_windows_dialog_tests tests/test_windows_dialog.c)
            target_link_libraries(xxemul_windows_dialog_tests PRIVATE xxemul::xxemul)
            add_test(NAME xxemul_windows_dialog_tests
                COMMAND "${Python3_EXECUTABLE}" -B "${CMAKE_CURRENT_SOURCE_DIR}/tests/run_windows_registry_temp.py"
                    --test $<TARGET_FILE:xxemul_windows_dialog_tests>
                    --work "${CMAKE_CURRENT_BINARY_DIR}/windows-dialog-tests" --dialogs)
            set_tests_properties(xxemul_windows_dialog_tests PROPERTIES TIMEOUT 60)
            add_executable(xxemul_windows_gui_abi_tests tests/test_windows_gui_abi.c)
            target_link_libraries(xxemul_windows_gui_abi_tests PRIVATE xxemul::xxemul)
            add_test(NAME xxemul_windows_gui_abi_tests
                COMMAND "${Python3_EXECUTABLE}" -B "${CMAKE_CURRENT_SOURCE_DIR}/tests/run_windows_registry_temp.py"
                    --test $<TARGET_FILE:xxemul_windows_gui_abi_tests>
                    --work "${CMAKE_CURRENT_BINARY_DIR}/windows-gui-abi-tests")
            set_tests_properties(xxemul_windows_gui_abi_tests PROPERTIES TIMEOUT 60)
            add_executable(xxemul_windows_file_commit_tests tests/test_windows_file_commit.c)
            target_link_libraries(xxemul_windows_file_commit_tests PRIVATE xxemul::xxemul)
            add_test(NAME xxemul_windows_file_commit_tests
                COMMAND "${Python3_EXECUTABLE}" -B "${CMAKE_CURRENT_SOURCE_DIR}/tests/run_windows_registry_temp.py"
                    --test $<TARGET_FILE:xxemul_windows_file_commit_tests>
                    --work "${CMAKE_CURRENT_BINARY_DIR}/windows-file-commit-tests")
            set_tests_properties(xxemul_windows_file_commit_tests PROPERTIES TIMEOUT 60
                ENVIRONMENT "TEST_FILE_ATTRIBUTES=1;TEST_HANDLE_COUNT=1")
        endif()
    endif()
    add_executable(xxemul_dos_load_base_tests tests/test_dos_load_base.c)
    target_link_libraries(xxemul_dos_load_base_tests PRIVATE xxemul::xxemul)
    add_test(NAME xxemul_dos_load_base_tests COMMAND xxemul_dos_load_base_tests)
    set_tests_properties(xxemul_dos_load_base_tests PROPERTIES TIMEOUT 30)
    add_executable(xxemul_mips_tests tests/test_mips.c)
    target_link_libraries(xxemul_mips_tests PRIVATE xxemul::xxemul)
    add_test(NAME xxemul_mips_tests COMMAND xxemul_mips_tests)
    add_executable(xxemul_arm_memory_hook_tests tests/test_arm_memory_hooks.c)
    target_link_libraries(xxemul_arm_memory_hook_tests PRIVATE xxemul::xxemul)
    add_test(NAME xxemul_arm_memory_hook_tests COMMAND xxemul_arm_memory_hook_tests)
    add_executable(xxemul_linux_abi_tests tests/test_linux_abis.c)
    target_include_directories(xxemul_linux_abi_tests PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/src")
    target_link_libraries(xxemul_linux_abi_tests PRIVATE xxemul::xxemul cdisasm::cdisasm xxfclib::xxfclib)
    add_test(NAME xxemul_linux_abi_tests COMMAND xxemul_linux_abi_tests)
    add_executable(xxemul_freebsd_abi_tests tests/test_freebsd_abi.c)
    target_include_directories(xxemul_freebsd_abi_tests PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/src")
    target_link_libraries(xxemul_freebsd_abi_tests PRIVATE xxemul::xxemul cdisasm::cdisasm xxfclib::xxfclib)
    add_test(NAME xxemul_freebsd_abi_tests COMMAND xxemul_freebsd_abi_tests)
    if(XXEMUL_CDISASM_EXTRA_OPCODES)
        add_executable(xxemul_cdisasm_x87_tests tests/test_cdisasm_x87.c)
        target_link_libraries(xxemul_cdisasm_x87_tests PRIVATE cdisasm::cdisasm)
        add_test(NAME xxemul_cdisasm_x87_tests COMMAND xxemul_cdisasm_x87_tests)
        add_executable(xxemul_x87_tests tests/test_xxemul_x87.c)
        target_link_libraries(xxemul_x87_tests PRIVATE xxemul::xxemul)
        add_test(NAME xxemul_x87_tests COMMAND xxemul_x87_tests)
        add_executable(xxemul_arm_cache_tests tests/test_arm_cache.c)
        target_link_libraries(xxemul_arm_cache_tests PRIVATE xxemul::xxemul cdisasm::cdisasm)
        add_test(NAME xxemul_arm_cache_tests COMMAND xxemul_arm_cache_tests)
        add_executable(xxemul_arm_crc_tests tests/test_arm_crc.c)
        target_link_libraries(xxemul_arm_crc_tests PRIVATE xxemul::xxemul cdisasm::cdisasm)
        add_test(NAME xxemul_arm_crc_tests COMMAND xxemul_arm_crc_tests)
        add_executable(xxemul_arm_literal_tests tests/test_arm_literal.c)
        target_link_libraries(xxemul_arm_literal_tests PRIVATE xxemul::xxemul cdisasm::cdisasm)
        add_test(NAME xxemul_arm_literal_tests COMMAND xxemul_arm_literal_tests)
        add_executable(xxemul_arm_bitops_tests tests/test_arm_bitops.c)
        target_link_libraries(xxemul_arm_bitops_tests PRIVATE xxemul::xxemul cdisasm::cdisasm)
        add_test(NAME xxemul_arm_bitops_tests COMMAND xxemul_arm_bitops_tests)
    endif()
    add_executable(xxemul_tests tests/test_xxemul.c)
    target_compile_features(xxemul_tests PRIVATE c_std_11)
    target_link_libraries(xxemul_tests PRIVATE
        xxemul::xxemul cdisasm::cdisasm xxfclib::xxfclib)
    add_test(NAME xxemul_tests COMMAND xxemul_tests)
    add_executable(xxemul_elf_shared_tests tests/test_elf_shared.c)
    target_compile_features(xxemul_elf_shared_tests PRIVATE c_std_11)
    target_link_libraries(xxemul_elf_shared_tests PRIVATE xxemul::xxemul)
    add_test(NAME xxemul_elf_shared_tests COMMAND xxemul_elf_shared_tests)
    if(CMAKE_SYSTEM_NAME STREQUAL "Linux" AND Python3_Interpreter_FOUND AND CMAKE_SYSTEM_PROCESSOR MATCHES "^(x86_64|amd64|AMD64|i[3-6]86)$" AND CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
        add_executable(xxemul_elf_primary_tests tests/test_elf_primary.c)
        target_compile_features(xxemul_elf_primary_tests PRIVATE c_std_11)
        target_link_libraries(xxemul_elf_primary_tests PRIVATE xxemul::xxemul)
        add_executable(xxemul_linux_auxv_tests tests/test_linux_auxv.c)
        target_compile_features(xxemul_linux_auxv_tests PRIVATE c_std_11)
        target_link_libraries(xxemul_linux_auxv_tests PRIVATE xxemul::xxemul)
        add_test(NAME xxemul_elf_primary_tests
            COMMAND "${Python3_EXECUTABLE}" -B "${CMAKE_CURRENT_SOURCE_DIR}/tests/run_elf_primary_tests.py"
                --test $<TARGET_FILE:xxemul_elf_primary_tests>
                --auxv-test $<TARGET_FILE:xxemul_linux_auxv_tests>
                --work "${CMAKE_CURRENT_BINARY_DIR}/elf-primary"
                --compiler "${CMAKE_C_COMPILER}")
        set_tests_properties(xxemul_elf_primary_tests PROPERTIES TIMEOUT 120)
    endif()
    add_executable(xxemul_format_tests tests/test_formats.c)
    target_compile_features(xxemul_format_tests PRIVATE c_std_11)
    target_link_libraries(xxemul_format_tests PRIVATE xxemul::xxemul)
    add_test(NAME xxemul_format_tests COMMAND xxemul_format_tests)
    if(NOT WIN32)
        add_executable(xxemul_darwin_libc_tests tests/test_darwin_libc.c)
        target_compile_features(xxemul_darwin_libc_tests PRIVATE c_std_11)
        target_link_libraries(xxemul_darwin_libc_tests PRIVATE xxemul::xxemul cdisasm::cdisasm xxfclib::xxfclib)
        add_test(NAME xxemul_darwin_libc_tests COMMAND xxemul_darwin_libc_tests)

        add_executable(xxemul_darwin_memory_tests tests/test_darwin_memory.c)
        target_compile_features(xxemul_darwin_memory_tests PRIVATE c_std_11)
        target_link_libraries(xxemul_darwin_memory_tests PRIVATE xxemul::xxemul cdisasm::cdisasm xxfclib::xxfclib)
        add_test(NAME xxemul_darwin_memory_tests COMMAND xxemul_darwin_memory_tests)

        if(APPLE)
            add_executable(xxemul_darwin_bzip2_tests tests/test_darwin_bzip2.c)
            target_compile_features(xxemul_darwin_bzip2_tests PRIVATE c_std_11)
            target_link_libraries(xxemul_darwin_bzip2_tests PRIVATE xxemul::xxemul cdisasm::cdisasm xxfclib::xxfclib)
            add_test(NAME xxemul_darwin_bzip2_tests COMMAND xxemul_darwin_bzip2_tests)
            set_tests_properties(xxemul_darwin_bzip2_tests PROPERTIES SKIP_RETURN_CODE 77)

            add_executable(xxemul_darwin_zlib_tests tests/test_darwin_zlib.c)
            target_compile_features(xxemul_darwin_zlib_tests PRIVATE c_std_11)
            target_link_libraries(xxemul_darwin_zlib_tests PRIVATE xxemul::xxemul cdisasm::cdisasm xxfclib::xxfclib)
            add_test(NAME xxemul_darwin_zlib_tests COMMAND xxemul_darwin_zlib_tests)
            set_tests_properties(xxemul_darwin_zlib_tests PROPERTIES SKIP_RETURN_CODE 77)

            add_executable(xxemul_darwin_archive_tests tests/test_darwin_archive.c)
            target_compile_features(xxemul_darwin_archive_tests PRIVATE c_std_11)
            target_link_libraries(xxemul_darwin_archive_tests PRIVATE xxemul::xxemul cdisasm::cdisasm xxfclib::xxfclib)
            add_test(NAME xxemul_darwin_archive_tests COMMAND xxemul_darwin_archive_tests)
            set_tests_properties(xxemul_darwin_archive_tests PROPERTIES SKIP_RETURN_CODE 77)
        endif()

        add_executable(xxemul_darwin_services_tests tests/test_darwin_services.c)
        target_compile_features(xxemul_darwin_services_tests PRIVATE c_std_11)
        target_link_libraries(xxemul_darwin_services_tests PRIVATE xxemul::xxemul cdisasm::cdisasm xxfclib::xxfclib)
        add_test(NAME xxemul_darwin_services_tests COMMAND xxemul_darwin_services_tests)

        add_executable(xxemul_darwin_cli_tests tests/test_darwin_cli.c)
        target_compile_features(xxemul_darwin_cli_tests PRIVATE c_std_11)
        target_link_libraries(xxemul_darwin_cli_tests PRIVATE xxemul::xxemul cdisasm::cdisasm xxfclib::xxfclib)
        add_test(NAME xxemul_darwin_cli_tests COMMAND xxemul_darwin_cli_tests)

        add_executable(xxemul_darwin_vm_tests tests/test_darwin_vm.c)
        target_compile_features(xxemul_darwin_vm_tests PRIVATE c_std_11)
        target_link_libraries(xxemul_darwin_vm_tests PRIVATE xxemul::xxemul cdisasm::cdisasm xxfclib::xxfclib)
        add_test(NAME xxemul_darwin_vm_tests COMMAND xxemul_darwin_vm_tests)
    endif()
    add_executable(xxemul_upx_macos_tests tests/test_upx_macos.c)
    target_compile_features(xxemul_upx_macos_tests PRIVATE c_std_11)
    target_link_libraries(xxemul_upx_macos_tests PRIVATE xxemul::xxemul)
    if(EXISTS "${XXEMUL_UPX_FIXTURE_DIR}/hello-macos-arm64.upx"
       AND EXISTS "${XXEMUL_UPX_FIXTURE_DIR}/hello-macos-arm64")
        add_test(NAME xxemul_upx_macos_tests COMMAND xxemul_upx_macos_tests
            "${XXEMUL_UPX_FIXTURE_DIR}/hello-macos-arm64.upx"
            "${XXEMUL_UPX_FIXTURE_DIR}/hello-macos-arm64"
            "${XXEMUL_UPX_FIXTURE_DIR}")
    endif()
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

# Local-only Radare2 corpus. Release source packages may omit private_tests,
# and embedded consumers should opt in explicitly from their integration tree.
if(PROJECT_IS_TOP_LEVEL AND BUILD_TESTING AND
   IS_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/private_tests")
    add_subdirectory(private_tests)
endif()

install(TARGETS xxemul
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
)
if(TARGET xxemul_viewer)
    install(TARGETS xxemul_viewer RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()
install(DIRECTORY include/xxemul DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
