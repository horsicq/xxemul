#include "xxemul/xxemul.h"
#include "xxemul_windows.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int check(int condition, const char *message)
{
    if (!condition) fprintf(stderr, "%s\n", message);
    return condition;
}

static xxemul_status read_integer(xxemul *emulator,
    uint64_t address, uint8_t size, uint64_t *value)
{
    uint8_t bytes[8];
    uint8_t i;
    xxemul_status status = xxemul_read_memory(
        emulator, address, bytes, size);
    if (status != XXEMUL_STATUS_OK) return status;
    *value = 0;
    for (i = 0; i < size; ++i)
        *value |= (uint64_t)bytes[i] << (i * 8u);
    return XXEMUL_STATUS_OK;
}

static xxemul_status write_integer(xxemul *emulator,
    uint64_t address, uint8_t size, uint64_t value)
{
    uint8_t bytes[8];
    uint8_t i;
    for (i = 0; i < size; ++i)
        bytes[i] = (uint8_t)(value >> (i * 8u));
    return xxemul_write_memory(emulator, address, bytes, size);
}

static int invoke_thunk(xxemul *emulator, xxemul_windows *process,
    int is_64, uint64_t target, uint64_t stack, uint64_t return_address,
    const uint64_t *arguments, size_t argument_count,
    xxemul_x86_state *state, xxemul_status *status)
{
    xxemul_step_info info;
    size_t i;
    uint8_t word_size = (uint8_t)(is_64 ? 8u : 4u);
    if (xxemul_get_x86_state(emulator, state) != XXEMUL_STATUS_OK
        || write_integer(emulator, stack,
            word_size, return_address) != XXEMUL_STATUS_OK) return 0;
    for (i = 0; i < argument_count; ++i) {
        if (is_64 && i < 4u) {
            static const uint8_t registers[] = {
                XXEMUL_X86_RCX, XXEMUL_X86_RDX,
                XXEMUL_X86_R8, XXEMUL_X86_R9
            };
            state->gpr[registers[i]] = arguments[i];
        } else {
            uint64_t slot = stack + (is_64
                ? 40u + (i - 4u) * 8u : 4u + i * 4u);
            if (write_integer(emulator, slot,
                    word_size, arguments[i]) != XXEMUL_STATUS_OK) return 0;
        }
    }
    state->ip = target;
    state->gpr[XXEMUL_X86_RSP] = stack;
    return xxemul_set_x86_state(emulator, state) == XXEMUL_STATUS_OK
        && xxemul_windows_try_step(process, &info, status)
        && xxemul_get_x86_state(emulator, state) == XXEMUL_STATUS_OK;
}

static int lookup_api(xxemul *emulator, xxemul_windows *process,
    int is_64, uint64_t get_proc, uint64_t stack,
    uint64_t return_address, uint64_t scratch, const char *name,
    xxemul_x86_state *state, uint64_t *address)
{
    xxemul_status status;
    uint64_t arguments[2] = {0x76000000u, scratch};
    if (xxemul_write_memory(emulator, scratch,
            name, strlen(name) + 1u) != XXEMUL_STATUS_OK
        || !invoke_thunk(emulator, process, is_64,
            get_proc, stack, return_address, arguments, 2u,
            state, &status)
        || status != XXEMUL_STATUS_OK) return 0;
    *address = state->gpr[XXEMUL_X86_RAX];
    return *address != 0;
}

static int lookup_crt_api(xxemul *emulator, xxemul_windows *process,
    int is_64, uint64_t get_proc, uint64_t stack,
    uint64_t return_address, uint64_t scratch, const char *name,
    xxemul_x86_state *state, uint64_t *address)
{
    xxemul_status status;
    uint64_t arguments[2] = {0x77000000u, scratch};
    if (xxemul_write_memory(emulator, scratch,
            name, strlen(name) + 1u) != XXEMUL_STATUS_OK
        || !invoke_thunk(emulator, process, is_64,
            get_proc, stack, return_address, arguments, 2u,
            state, &status)
        || status != XXEMUL_STATUS_OK) return 0;
    *address = state->gpr[XXEMUL_X86_RAX];
    return *address != 0u;
}

static int equal_ascii_ci(const char *left, const char *right)
{
    while (*left != '\0' && *right != '\0') {
        if (tolower((unsigned char)*left)
            != tolower((unsigned char)*right)) return 0;
        ++left;
        ++right;
    }
    return *left == *right;
}

static int read_ascii(xxemul *emulator, uint64_t address,
    char *buffer, size_t capacity)
{
    size_t index;
    for (index = 0; index + 1u < capacity; ++index) {
        uint8_t character;
        if (xxemul_read_memory(emulator, address + index,
                &character, 1u) != XXEMUL_STATUS_OK) return 0;
        buffer[index] = (char)character;
        if (character == 0u) return 1;
        if (character < 32u || character > 126u) return 0;
    }
    return 0;
}

static int discover_imports(const char *unpacked_path,
    xxemul *packed, xxemul_windows *process, int is_64,
    uint64_t get_proc, uint64_t stack, uint64_t return_address,
    uint64_t scratch)
{
    xxemul *unpacked;
    xxemul_x86_state state;
    xxemul_status status;
    uint64_t base, pe_offset, optional, magic, import_rva;
    uint64_t import_size, descriptor_index, total = 0u, missing = 0u;
    uint8_t pointer_size = (uint8_t)(is_64 ? 8u : 4u);
    int verbose;
#if defined(_WIN32)
    size_t verbose_length = 0u;
    (void)getenv_s(&verbose_length, NULL, 0u,
        "XXEMUL_IMPORT_VERBOSE");
    verbose = verbose_length != 0u;
#else
    verbose = getenv("XXEMUL_IMPORT_VERBOSE") != NULL;
#endif
    unpacked = xxemul_create_image_file(
        is_64 ? XXEMUL_IMAGE_PE64 : XXEMUL_IMAGE_PE32,
        unpacked_path, &status);
    if (unpacked == NULL) return 0;
    base = xxemul_get_region_address(unpacked);
    if (read_integer(unpacked, base + 0x3cu, 4u, &pe_offset)
            != XXEMUL_STATUS_OK) goto failed;
    optional = base + pe_offset + 24u;
    if (read_integer(unpacked, optional, 2u, &magic)
            != XXEMUL_STATUS_OK
        || magic != (is_64 ? 0x20bu : 0x10bu)) goto failed;
    if (read_integer(unpacked, optional + (is_64 ? 120u : 104u),
            4u, &import_rva) != XXEMUL_STATUS_OK
        || read_integer(unpacked, optional + (is_64 ? 124u : 108u),
            4u, &import_size) != XXEMUL_STATUS_OK
        || import_size < 20u || import_size > 0x100000u) goto failed;
    for (descriptor_index = 0; descriptor_index + 20u <= import_size;
         descriptor_index += 20u) {
        uint64_t descriptor = base + import_rva + descriptor_index;
        uint64_t lookup_rva, module_rva, iat_rva, module_handle;
        char module[80];
        size_t symbol_index;
        if (read_integer(unpacked, descriptor, 4u, &lookup_rva)
                != XXEMUL_STATUS_OK
            || read_integer(unpacked, descriptor + 12u, 4u,
                &module_rva) != XXEMUL_STATUS_OK
            || read_integer(unpacked, descriptor + 16u, 4u,
                &iat_rva) != XXEMUL_STATUS_OK) goto failed;
        if (lookup_rva == 0u && module_rva == 0u
            && iat_rva == 0u) break;
        if (module_rva == 0u
            || !read_ascii(unpacked, base + module_rva,
                module, sizeof(module))) goto failed;
        module_handle = equal_ascii_ci(module, "KERNEL32.DLL")
            ? 0x76000000u : equal_ascii_ci(module, "msvcrt.dll")
                ? 0x77000000u : 0u;
        if (lookup_rva == 0u) lookup_rva = iat_rva;
        for (symbol_index = 0; symbol_index < 4096u; ++symbol_index) {
            uint64_t raw, arguments[2], result;
            char name[96];
            if (read_integer(unpacked,
                    base + lookup_rva + symbol_index * pointer_size,
                    pointer_size, &raw) != XXEMUL_STATUS_OK) goto failed;
            if (raw == 0u) break;
            if (raw & (is_64 ? UINT64_C(0x8000000000000000)
                             : UINT64_C(0x80000000))) continue;
            if (!read_ascii(unpacked, base + raw + 2u,
                    name, sizeof(name))) goto failed;
            ++total;
            result = 0u;
            if (module_handle != 0u) {
                arguments[0] = module_handle;
                arguments[1] = scratch;
                if (xxemul_write_memory(packed, scratch,
                        name, strlen(name) + 1u) != XXEMUL_STATUS_OK
                    || !invoke_thunk(packed, process, is_64,
                        get_proc, stack, return_address, arguments,
                        2u, &state, &status)
                    || status != XXEMUL_STATUS_OK) goto failed;
                result = state.gpr[XXEMUL_X86_RAX];
            }
            if (result == 0u) {
                if (missing < 40u || verbose)
                    printf("  unresolved %s!%s\n", module, name);
                ++missing;
            }
        }
        if (symbol_index == 4096u) goto failed;
    }
    printf("%s imports: %llu total, %llu unresolved\n",
        is_64 ? "PE64" : "PE32",
        (unsigned long long)total, (unsigned long long)missing);
    xxemul_destroy(unpacked);
    return 1;
failed:
    xxemul_destroy(unpacked);
    return 0;
}

static int test_console(xxemul *emulator, xxemul_windows *process,
    int is_64, uint64_t get_proc, uint64_t stack,
    uint64_t return_address, uint64_t scratch)
{
    static const char *const names[] = {
        "GetConsoleCursorInfo", "GetConsoleScreenBufferInfo",
        "SetConsoleCursorInfo", "SetConsoleCursorPosition",
        "SetConsoleTextAttribute", "GetConsoleMode", "SetConsoleMode"
    };
    uint64_t api[sizeof(names) / sizeof(names[0])];
    uint64_t args[2] = {0x11u, scratch + 0x100u};
    uint64_t value;
    xxemul_x86_state state;
    xxemul_status status;
    size_t index;
    for (index = 0; index < sizeof(names) / sizeof(names[0]); ++index) {
        if (!check(lookup_api(emulator, process, is_64, get_proc,
                stack, return_address, scratch, names[index],
                &state, &api[index]), "console API lookup failed")) return 0;
    }
    if (!check(invoke_thunk(emulator, process, is_64,
            api[1], stack, return_address, args, 2u, &state, &status)
            && status == XXEMUL_STATUS_OK
            && state.gpr[XXEMUL_X86_RAX] == 1u
            && state.gpr[XXEMUL_X86_RSP]
                == stack + (is_64 ? 8u : 12u)
            && read_integer(emulator, args[1], 2u, &value)
                == XXEMUL_STATUS_OK && value == 80u
            && read_integer(emulator, args[1] + 2u, 2u, &value)
                == XXEMUL_STATUS_OK && value == 25u
            && read_integer(emulator, args[1] + 14u, 2u, &value)
                == XXEMUL_STATUS_OK && value == 79u,
            "initial console buffer info is wrong")) return 0;
    args[1] = (5u << 16) | 12u;
    if (!check(invoke_thunk(emulator, process, is_64,
            api[3], stack, return_address, args, 2u, &state, &status)
            && status == XXEMUL_STATUS_OK
            && state.gpr[XXEMUL_X86_RAX] == 1u,
            "SetConsoleCursorPosition failed")) return 0;
    args[1] = 0x1eu;
    if (!check(invoke_thunk(emulator, process, is_64,
            api[4], stack, return_address, args, 2u, &state, &status)
            && status == XXEMUL_STATUS_OK
            && state.gpr[XXEMUL_X86_RAX] == 1u,
            "SetConsoleTextAttribute failed")) return 0;
    args[1] = scratch + 0x100u;
    if (!check(invoke_thunk(emulator, process, is_64,
            api[1], stack, return_address, args, 2u, &state, &status)
            && status == XXEMUL_STATUS_OK
            && read_integer(emulator, args[1] + 4u, 2u, &value)
                == XXEMUL_STATUS_OK && value == 12u
            && read_integer(emulator, args[1] + 6u, 2u, &value)
                == XXEMUL_STATUS_OK && value == 5u
            && read_integer(emulator, args[1] + 8u, 2u, &value)
                == XXEMUL_STATUS_OK && value == 0x1eu,
            "console cursor/attributes did not persist")) return 0;
    if (!check(write_integer(emulator, args[1], 4u, 50u)
                == XXEMUL_STATUS_OK
            && write_integer(emulator, args[1] + 4u, 4u, 0u)
                == XXEMUL_STATUS_OK
            && invoke_thunk(emulator, process, is_64,
                api[2], stack, return_address, args, 2u, &state, &status)
            && status == XXEMUL_STATUS_OK
            && state.gpr[XXEMUL_X86_RAX] == 1u
            && invoke_thunk(emulator, process, is_64,
                api[0], stack, return_address, args, 2u, &state, &status)
            && status == XXEMUL_STATUS_OK
            && read_integer(emulator, args[1], 4u, &value)
                == XXEMUL_STATUS_OK && value == 50u
            && read_integer(emulator, args[1] + 4u, 4u, &value)
                == XXEMUL_STATUS_OK && value == 0u,
            "console cursor visibility/size did not persist")) return 0;
    if (!check(invoke_thunk(emulator, process, is_64,
            api[5], stack, return_address, args, 2u, &state, &status)
            && status == XXEMUL_STATUS_OK
            && read_integer(emulator, args[1], 4u, &value)
                == XXEMUL_STATUS_OK && value == 3u,
            "default output console mode is wrong")) return 0;
    args[1] = 5u;
    if (!check(invoke_thunk(emulator, process, is_64,
            api[6], stack, return_address, args, 2u, &state, &status)
            && status == XXEMUL_STATUS_OK
            && state.gpr[XXEMUL_X86_RAX] == 1u,
            "SetConsoleMode failed")) return 0;
    args[1] = scratch + 0x100u;
    if (!check(invoke_thunk(emulator, process, is_64,
            api[5], stack, return_address, args, 2u, &state, &status)
            && status == XXEMUL_STATUS_OK
            && read_integer(emulator, args[1], 4u, &value)
                == XXEMUL_STATUS_OK && value == 5u,
            "output console mode did not persist")) return 0;
    args[0] = 0xdeadu;
    if (!check(invoke_thunk(emulator, process, is_64,
            api[1], stack, return_address, args, 2u, &state, &status)
            && status == XXEMUL_STATUS_OK
            && state.gpr[XXEMUL_X86_RAX] == 0u,
            "invalid console handle unexpectedly succeeded")) return 0;
    return 1;
}

static int test_console_output(xxemul *emulator,
    xxemul_windows *process, int is_64, uint64_t get_proc,
    uint64_t stack, uint64_t return_address, uint64_t scratch)
{
    uint64_t write_output = 0u, read_output = 0u, scroll = 0u;
    uint64_t args[5] = {0};
    uint64_t source_rect = UINT64_C(3) | (UINT64_C(4) << 16u)
        | (UINT64_C(3) << 32u) | (UINT64_C(4) << 48u);
    uint64_t destination_rect = UINT64_C(5) | (UINT64_C(6) << 16u)
        | (UINT64_C(5) << 32u) | (UINT64_C(6) << 48u);
    uint64_t value;
    xxemul_x86_state state;
    xxemul_status status;
    if (!check(lookup_api(emulator, process, is_64, get_proc,
            stack, return_address, scratch, "WriteConsoleOutputA",
            &state, &write_output)
        && lookup_api(emulator, process, is_64, get_proc,
            stack, return_address, scratch, "ReadConsoleOutputA",
            &state, &read_output)
        && lookup_api(emulator, process, is_64, get_proc,
            stack, return_address, scratch, "ScrollConsoleScreenBufferA",
            &state, &scroll),
        "console block API lookup failed")) return 0;
    args[0] = 0x11u;
    args[1] = scratch + 0x100u;
    args[2] = 1u | (1u << 16u);
    args[3] = 0u;
    args[4] = scratch + 0x120u;
    if (!check(write_integer(emulator, args[1], 4u,
            (0x1eu << 16u) | 'X') == XXEMUL_STATUS_OK
        && write_integer(emulator, args[4], 8u, source_rect)
            == XXEMUL_STATUS_OK
        && invoke_thunk(emulator, process, is_64,
            write_output, stack, return_address, args, 5u,
            &state, &status)
        && status == XXEMUL_STATUS_OK
        && state.gpr[XXEMUL_X86_RAX] == 1u
        && state.gpr[XXEMUL_X86_RSP]
            == stack + (is_64 ? 8u : 24u),
        "WriteConsoleOutputA failed")) return 0;
    args[1] = scratch + 0x140u;
    if (!check(write_integer(emulator, args[4], 8u, source_rect)
            == XXEMUL_STATUS_OK
        && invoke_thunk(emulator, process, is_64,
            read_output, stack, return_address, args, 5u,
            &state, &status)
        && status == XXEMUL_STATUS_OK
        && state.gpr[XXEMUL_X86_RAX] == 1u
        && read_integer(emulator, args[1], 4u, &value)
            == XXEMUL_STATUS_OK
        && value == ((0x1eu << 16u) | 'X'),
        "console cell did not round-trip")) return 0;
    args[1] = scratch + 0x160u;
    args[2] = 0u;
    args[3] = 5u | (6u << 16u);
    args[4] = scratch + 0x170u;
    if (!check(write_integer(emulator, args[1], 8u, source_rect)
            == XXEMUL_STATUS_OK
        && write_integer(emulator, args[4], 4u,
            (0x1fu << 16u) | '.') == XXEMUL_STATUS_OK
        && invoke_thunk(emulator, process, is_64,
            scroll, stack, return_address, args, 5u,
            &state, &status)
        && status == XXEMUL_STATUS_OK
        && state.gpr[XXEMUL_X86_RAX] == 1u,
        "ScrollConsoleScreenBufferA failed")) return 0;
    args[1] = scratch + 0x180u;
    args[2] = 1u | (1u << 16u);
    args[3] = 0u;
    args[4] = scratch + 0x190u;
    if (!check(write_integer(emulator, args[4], 8u,
            destination_rect) == XXEMUL_STATUS_OK
        && invoke_thunk(emulator, process, is_64,
            read_output, stack, return_address, args, 5u,
            &state, &status)
        && status == XXEMUL_STATUS_OK
        && read_integer(emulator, args[1], 4u, &value)
            == XXEMUL_STATUS_OK
        && value == ((0x1eu << 16u) | 'X'),
        "scrolled console cell was not moved")) return 0;
    return check(write_integer(emulator, args[4], 8u,
            source_rect) == XXEMUL_STATUS_OK
        && invoke_thunk(emulator, process, is_64,
            read_output, stack, return_address, args, 5u,
            &state, &status)
        && status == XXEMUL_STATUS_OK
        && read_integer(emulator, args[1], 4u, &value)
            == XXEMUL_STATUS_OK
        && value == ((0x1fu << 16u) | '.'),
        "scroll did not fill vacated console cell");
}

static int test_process_state(xxemul *emulator, xxemul_windows *process,
    int is_64, uint64_t get_proc, uint64_t stack,
    uint64_t return_address, uint64_t scratch)
{
    static const char *const names[] = {
        "GetProcessAffinityMask", "SetProcessAffinityMask",
        "GetSystemTimeAsFileTime", "IsDebuggerPresent",
        "TlsAlloc", "TlsGetValue", "TlsSetValue",
        "GetLastError", "OutputDebugStringA",
        "QueryPerformanceCounter", "DebugBreak",
        "GetCurrentThread", "GetThreadPriority",
        "SetThreadPriority", "SetUnhandledExceptionFilter",
        "GetThreadContext", "IsDBCSLeadByteEx"
    };
    uint64_t api[sizeof(names) / sizeof(names[0])];
    uint64_t args[3] = {is_64 ? UINT64_MAX : UINT32_MAX,
        scratch + 0x100u, scratch + 0x108u};
    uint64_t module_args[2] = {0x77000000u, scratch};
    uint64_t value, slot, current_thread;
    xxemul_x86_state state;
    xxemul_status status;
    size_t index;
    for (index = 0; index < sizeof(names) / sizeof(names[0]); ++index) {
        if (!check(lookup_api(emulator, process, is_64, get_proc,
                stack, return_address, scratch, names[index],
                &state, &api[index]), "process API lookup failed")) return 0;
    }
    if (!check(xxemul_write_memory(emulator, scratch,
            "DebugBreak", sizeof("DebugBreak")) == XXEMUL_STATUS_OK
            && invoke_thunk(emulator, process, is_64,
                get_proc, stack, return_address, module_args,
                2u, &state, &status)
            && status == XXEMUL_STATUS_OK
            && state.gpr[XXEMUL_X86_RAX] == 0u,
            "DebugBreak incorrectly resolved from MSVCRT")) return 0;
    if (!check(invoke_thunk(emulator, process, is_64,
            api[0], stack, return_address, args, 3u, &state, &status)
            && status == XXEMUL_STATUS_OK
            && state.gpr[XXEMUL_X86_RAX] == 1u
            && read_integer(emulator, args[1],
                (uint8_t)(is_64 ? 8u : 4u), &value) == XXEMUL_STATUS_OK
            && value == 1u
            && read_integer(emulator, args[2],
                (uint8_t)(is_64 ? 8u : 4u), &value) == XXEMUL_STATUS_OK
            && value == 1u,
            "single-CPU process affinity is wrong")) return 0;
    args[1] = 2u;
    if (!check(invoke_thunk(emulator, process, is_64,
            api[1], stack, return_address, args, 2u, &state, &status)
            && status == XXEMUL_STATUS_OK
            && state.gpr[XXEMUL_X86_RAX] == 0u
            && invoke_thunk(emulator, process, is_64,
                api[7], stack, return_address, args, 0u, &state, &status)
            && status == XXEMUL_STATUS_OK
            && state.gpr[XXEMUL_X86_RAX] == 87u,
            "invalid affinity mask did not fail")) return 0;
    args[0] = scratch + 0x100u;
    if (!check(invoke_thunk(emulator, process, is_64,
            api[2], stack, return_address, args, 1u, &state, &status)
            && status == XXEMUL_STATUS_OK
            && read_integer(emulator, args[0], 8u, &value)
                == XXEMUL_STATUS_OK
            && value > UINT64_C(132000000000000000),
            "GetSystemTimeAsFileTime is not a current FILETIME"))
        return 0;
    if (!check(invoke_thunk(emulator, process, is_64,
            api[3], stack, return_address, args, 0u, &state, &status)
            && status == XXEMUL_STATUS_OK
            && state.gpr[XXEMUL_X86_RAX] == 0u,
            "IsDebuggerPresent should report no debugger")) return 0;
    if (!check(invoke_thunk(emulator, process, is_64,
            api[4], stack, return_address, args, 0u, &state, &status)
            && status == XXEMUL_STATUS_OK
            && state.gpr[XXEMUL_X86_RSP] == stack + (is_64 ? 8u : 4u)
            && state.gpr[XXEMUL_X86_RAX] != UINT32_MAX,
            "TlsAlloc failed")) return 0;
    slot = state.gpr[XXEMUL_X86_RAX];
    args[0] = slot;
    if (!check(invoke_thunk(emulator, process, is_64,
            api[5], stack, return_address, args, 1u, &state, &status)
            && status == XXEMUL_STATUS_OK
            && state.gpr[XXEMUL_X86_RAX] == 0u
            && invoke_thunk(emulator, process, is_64,
                api[7], stack, return_address, args, 0u, &state, &status)
            && status == XXEMUL_STATUS_OK
            && state.gpr[XXEMUL_X86_RAX] == 0u,
            "fresh TLS slot should be null with no error")) return 0;
    args[1] = scratch + 0x140u;
    if (!check(invoke_thunk(emulator, process, is_64,
            api[6], stack, return_address, args, 2u, &state, &status)
            && status == XXEMUL_STATUS_OK
            && state.gpr[XXEMUL_X86_RAX] == 1u
            && invoke_thunk(emulator, process, is_64,
                api[5], stack, return_address, args, 1u, &state, &status)
            && status == XXEMUL_STATUS_OK
            && state.gpr[XXEMUL_X86_RAX] == args[1],
            "TlsSetValue/TlsGetValue round trip failed")) return 0;
    args[0] = 999u;
    if (!check(invoke_thunk(emulator, process, is_64,
            api[5], stack, return_address, args, 1u, &state, &status)
            && status == XXEMUL_STATUS_OK
            && state.gpr[XXEMUL_X86_RAX] == 0u
            && invoke_thunk(emulator, process, is_64,
                api[7], stack, return_address, args, 0u, &state, &status)
            && status == XXEMUL_STATUS_OK
            && state.gpr[XXEMUL_X86_RAX] == 87u,
            "invalid TLS slot did not set last error")) return 0;
    if (!check(xxemul_write_memory(emulator, scratch + 0x180u,
            "UPX test", sizeof("UPX test")) == XXEMUL_STATUS_OK,
            "unable to write debug string")) return 0;
    args[0] = scratch + 0x180u;
    if (!check(invoke_thunk(emulator, process, is_64,
            api[8], stack, return_address, args, 1u, &state, &status)
            && status == XXEMUL_STATUS_OK,
            "OutputDebugStringA rejected a valid string")) return 0;
    args[0] = scratch + 0x100u;
    if (!check(invoke_thunk(emulator, process, is_64,
            api[9], stack, return_address, args, 1u, &state, &status)
            && status == XXEMUL_STATUS_OK
            && state.gpr[XXEMUL_X86_RSP] == stack + (is_64 ? 8u : 8u)
            && read_integer(emulator, args[0], 8u, &value)
                == XXEMUL_STATUS_OK && value != 0u,
            "QueryPerformanceCounter ABI failed")) return 0;
    if (!check(invoke_thunk(emulator, process, is_64,
            api[10], stack, return_address, args, 0u, &state, &status)
            && status == XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION
            && state.ip == api[10],
            "DebugBreak did not resolve to an explicit breakpoint stub"))
        return 0;
    if (!check(invoke_thunk(emulator, process, is_64,
            api[11], stack, return_address, args, 0u, &state, &status)
            && status == XXEMUL_STATUS_OK
            && state.gpr[XXEMUL_X86_RAX]
                == (is_64 ? UINT64_MAX - 1u : UINT32_MAX - 1u)
            && state.gpr[XXEMUL_X86_RSP]
                == stack + (is_64 ? 8u : 4u),
            "GetCurrentThread pseudo-handle ABI failed")) return 0;
    current_thread = state.gpr[XXEMUL_X86_RAX];
    args[0] = current_thread;
    if (!check(invoke_thunk(emulator, process, is_64,
            api[12], stack, return_address, args, 1u, &state, &status)
            && status == XXEMUL_STATUS_OK
            && state.gpr[XXEMUL_X86_RAX] == 0u,
            "initial thread priority is not normal")) return 0;
    args[1] = 1u;
    if (!check(invoke_thunk(emulator, process, is_64,
            api[13], stack, return_address, args, 2u, &state, &status)
            && status == XXEMUL_STATUS_OK
            && state.gpr[XXEMUL_X86_RAX] == 1u
            && invoke_thunk(emulator, process, is_64,
                api[12], stack, return_address, args, 1u, &state, &status)
            && status == XXEMUL_STATUS_OK
            && state.gpr[XXEMUL_X86_RAX] == 1u,
            "thread priority did not persist")) return 0;
    args[0] = 0xdeadu;
    if (!check(invoke_thunk(emulator, process, is_64,
            api[12], stack, return_address, args, 1u, &state, &status)
            && status == XXEMUL_STATUS_OK
            && state.gpr[XXEMUL_X86_RAX] == INT32_MAX,
            "invalid thread handle did not return error priority"))
        return 0;
    args[0] = scratch + 0x200u;
    if (!check(invoke_thunk(emulator, process, is_64,
            api[14], stack, return_address, args, 1u, &state, &status)
            && status == XXEMUL_STATUS_OK
            && state.gpr[XXEMUL_X86_RAX] == 0u,
            "first exception filter registration did not return null"))
        return 0;
    args[0] = 0u;
    if (!check(invoke_thunk(emulator, process, is_64,
            api[14], stack, return_address, args, 1u, &state, &status)
            && status == XXEMUL_STATUS_OK
            && state.gpr[XXEMUL_X86_RAX] == scratch + 0x200u,
            "exception filter replacement did not return prior filter"))
        return 0;
    args[0] = current_thread;
    args[1] = scratch + 0x300u;
    if (!check(write_integer(emulator,
            args[1] + (is_64 ? 48u : 0u), 4u,
            is_64 ? 0x100007u : 0x10007u) == XXEMUL_STATUS_OK
            && invoke_thunk(emulator, process, is_64,
                api[15], stack, return_address, args, 2u,
                &state, &status)
            && status == XXEMUL_STATUS_OK
            && state.gpr[XXEMUL_X86_RAX] == 1u
            && read_integer(emulator,
                args[1] + (is_64 ? 248u : 184u),
                (uint8_t)(is_64 ? 8u : 4u), &value)
                == XXEMUL_STATUS_OK
            && value == return_address
            && read_integer(emulator,
                args[1] + (is_64 ? 152u : 196u),
                (uint8_t)(is_64 ? 8u : 4u), &value)
                == XXEMUL_STATUS_OK
            && value == state.gpr[XXEMUL_X86_RSP]
            && read_integer(emulator,
                args[1] + (is_64 ? 120u : 176u),
                (uint8_t)(is_64 ? 8u : 4u), &value)
                == XXEMUL_STATUS_OK && value == 1u,
            "GetThreadContext did not capture main-thread registers"))
        return 0;
    args[0] = 0xdeadu;
    if (!check(invoke_thunk(emulator, process, is_64,
            api[15], stack, return_address, args, 2u,
            &state, &status)
            && status == XXEMUL_STATUS_OK
            && state.gpr[XXEMUL_X86_RAX] == 0u,
            "GetThreadContext accepted an invalid handle")) return 0;
    args[0] = current_thread;
    if (!check(write_integer(emulator,
            args[1] + (is_64 ? 48u : 0u), 4u,
            is_64 ? 0x10000fu : 0x1000fu) == XXEMUL_STATUS_OK
            && invoke_thunk(emulator, process, is_64,
                api[15], stack, return_address, args, 2u,
                &state, &status)
            && status == XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION,
            "GetThreadContext silently accepted unsupported FP state"))
        return 0;
    args[0] = 0u;
    args[1] = 0x82u;
    if (!check(invoke_thunk(emulator, process, is_64,
            api[16], stack, return_address, args, 2u,
            &state, &status)
            && status == XXEMUL_STATUS_OK
            && state.gpr[XXEMUL_X86_RAX] == 0u,
            "ACP 1252 incorrectly has a DBCS lead byte")) return 0;
    args[0] = 932u;
    if (!check(invoke_thunk(emulator, process, is_64,
            api[16], stack, return_address, args, 2u,
            &state, &status)
            && status == XXEMUL_STATUS_OK
            && state.gpr[XXEMUL_X86_RAX] == 1u,
            "CP932 lead byte was not recognized")) return 0;
    return 1;
}

static int test_text_conversion(xxemul *emulator,
    xxemul_windows *process, int is_64, uint64_t get_proc,
    uint64_t stack, uint64_t return_address, uint64_t scratch)
{
    static const uint8_t utf8_smile[] = {0xf0u, 0x9fu, 0x98u, 0x80u, 0u};
    static const uint8_t cp1252_euro[] = {0x80u, 0u};
    static const uint8_t invalid_utf8[] = {0xc0u, 0x80u};
    uint64_t mb_to_wide = 0u, wide_to_mb = 0u;
    uint64_t get_last_error = 0u, value;
    uint64_t args[8] = {0};
    xxemul_x86_state state;
    xxemul_status status;
    uint8_t output[5];
    uint64_t source = scratch + 0x100u;
    uint64_t wide = scratch + 0x200u;
    uint64_t bytes = scratch + 0x300u;
    uint64_t used_default = scratch + 0x400u;
    if (!check(lookup_api(emulator, process, is_64, get_proc,
            stack, return_address, scratch, "MultiByteToWideChar",
            &state, &mb_to_wide)
        && lookup_api(emulator, process, is_64, get_proc,
            stack, return_address, scratch, "WideCharToMultiByte",
            &state, &wide_to_mb)
        && lookup_api(emulator, process, is_64, get_proc,
            stack, return_address, scratch, "GetLastError",
            &state, &get_last_error),
        "text conversion API lookup failed")) return 0;
    args[0] = 65001u;
    args[2] = source;
    args[3] = UINT32_MAX;
    if (!check(xxemul_write_memory(emulator, source,
            utf8_smile, sizeof(utf8_smile)) == XXEMUL_STATUS_OK
        && invoke_thunk(emulator, process, is_64,
            mb_to_wide, stack, return_address, args, 6u,
            &state, &status)
        && status == XXEMUL_STATUS_OK
        && state.gpr[XXEMUL_X86_RAX] == 3u,
        "UTF-8 length query failed")) return 0;
    args[4] = wide;
    args[5] = 3u;
    if (!check(invoke_thunk(emulator, process, is_64,
            mb_to_wide, stack, return_address, args, 6u,
            &state, &status)
        && status == XXEMUL_STATUS_OK
        && state.gpr[XXEMUL_X86_RAX] == 3u
        && state.gpr[XXEMUL_X86_RSP]
            == stack + (is_64 ? 8u : 28u)
        && read_integer(emulator, wide, 2u, &value)
            == XXEMUL_STATUS_OK && value == 0xd83du
        && read_integer(emulator, wide + 2u, 2u, &value)
            == XXEMUL_STATUS_OK && value == 0xde00u,
        "UTF-8 surrogate conversion or six-argument ABI failed"))
        return 0;
    args[2] = wide;
    args[4] = bytes;
    args[5] = 5u;
    if (!check(invoke_thunk(emulator, process, is_64,
            wide_to_mb, stack, return_address, args, 8u,
            &state, &status)
        && status == XXEMUL_STATUS_OK
        && state.gpr[XXEMUL_X86_RAX] == 5u
        && state.gpr[XXEMUL_X86_RSP]
            == stack + (is_64 ? 8u : 36u)
        && xxemul_read_memory(emulator, bytes,
            output, sizeof(output)) == XXEMUL_STATUS_OK
        && memcmp(output, utf8_smile, sizeof(output)) == 0,
        "UTF-16 surrogate round trip or eight-argument ABI failed"))
        return 0;
    args[0] = 1252u;
    args[2] = source;
    args[4] = wide;
    args[5] = 2u;
    if (!check(xxemul_write_memory(emulator, source,
            cp1252_euro, sizeof(cp1252_euro)) == XXEMUL_STATUS_OK
        && invoke_thunk(emulator, process, is_64,
            mb_to_wide, stack, return_address, args, 6u,
            &state, &status)
        && status == XXEMUL_STATUS_OK
        && state.gpr[XXEMUL_X86_RAX] == 2u
        && read_integer(emulator, wide, 2u, &value)
            == XXEMUL_STATUS_OK && value == 0x20acu,
        "CP1252 euro conversion failed")) return 0;
    args[2] = wide;
    args[4] = bytes;
    args[6] = 0u;
    args[7] = used_default;
    if (!check(invoke_thunk(emulator, process, is_64,
            wide_to_mb, stack, return_address, args, 8u,
            &state, &status)
        && status == XXEMUL_STATUS_OK
        && state.gpr[XXEMUL_X86_RAX] == 2u
        && read_integer(emulator, bytes, 2u, &value)
            == XXEMUL_STATUS_OK && value == 0x80u
        && read_integer(emulator, used_default, 4u, &value)
            == XXEMUL_STATUS_OK && value == 0u,
        "CP1252 round trip or default-character tracking failed"))
        return 0;
    args[0] = 65001u;
    args[2] = source;
    args[4] = wide;
    args[5] = 3u;
    args[6] = 0u;
    args[7] = 0u;
    args[1] = 8u;
    if (!check(xxemul_write_memory(emulator, source,
            invalid_utf8, sizeof(invalid_utf8)) == XXEMUL_STATUS_OK,
        "unable to write invalid UTF-8 sample")) return 0;
    args[3] = sizeof(invalid_utf8);
    if (!check(invoke_thunk(emulator, process, is_64,
            mb_to_wide, stack, return_address, args, 6u,
            &state, &status)
        && status == XXEMUL_STATUS_OK
        && state.gpr[XXEMUL_X86_RAX] == 0u
        && invoke_thunk(emulator, process, is_64,
            get_last_error, stack, return_address, args, 0u,
            &state, &status)
        && status == XXEMUL_STATUS_OK
        && state.gpr[XXEMUL_X86_RAX] == 1113u,
        "invalid UTF-8 did not set translation error")) return 0;
    args[1] = 0u;
    args[3] = UINT32_MAX;
    args[5] = 1u;
    if (!check(xxemul_write_memory(emulator, source,
            utf8_smile, sizeof(utf8_smile)) == XXEMUL_STATUS_OK
        && invoke_thunk(emulator, process, is_64,
            mb_to_wide, stack, return_address, args, 6u,
            &state, &status)
        && status == XXEMUL_STATUS_OK
        && state.gpr[XXEMUL_X86_RAX] == 0u
        && invoke_thunk(emulator, process, is_64,
            get_last_error, stack, return_address, args, 0u,
            &state, &status)
        && status == XXEMUL_STATUS_OK
        && state.gpr[XXEMUL_X86_RAX] == 122u,
        "short UTF-16 output buffer did not report its error"))
        return 0;
    return 1;
}

static int test_open_process(xxemul *emulator,
    xxemul_windows *process, int is_64, uint64_t get_proc,
    uint64_t stack, uint64_t return_address, uint64_t scratch)
{
    uint64_t open_process = 0u, close_handle = 0u;
    uint64_t affinity = 0u, duplicate = 0u, get_last_error = 0u;
    uint64_t args[7] = {0};
    uint64_t handle, copied = 0u, value;
    xxemul_x86_state state;
    xxemul_status status;
    uint8_t word_size = (uint8_t)(is_64 ? 8u : 4u);
    if (!check(lookup_api(emulator, process, is_64, get_proc,
            stack, return_address, scratch, "OpenProcess",
            &state, &open_process)
        && lookup_api(emulator, process, is_64, get_proc,
            stack, return_address, scratch, "CloseHandle",
            &state, &close_handle)
        && lookup_api(emulator, process, is_64, get_proc,
            stack, return_address, scratch, "DuplicateHandle",
            &state, &duplicate)
        && lookup_api(emulator, process, is_64, get_proc,
            stack, return_address, scratch, "GetProcessAffinityMask",
            &state, &affinity)
        && lookup_api(emulator, process, is_64, get_proc,
            stack, return_address, scratch, "GetLastError",
            &state, &get_last_error),
        "OpenProcess API lookup failed")) return 0;
    args[0] = 0x400u;
    args[1] = 1u;
    args[2] = 1u;
    if (!check(invoke_thunk(emulator, process, is_64,
            open_process, stack, return_address, args, 3u,
            &state, &status)
        && status == XXEMUL_STATUS_OK
        && state.gpr[XXEMUL_X86_RAX] >= 0x100u
        && state.gpr[XXEMUL_X86_RSP]
            == stack + (is_64 ? 8u : 16u),
        "OpenProcess did not return a real guest handle")) return 0;
    handle = state.gpr[XXEMUL_X86_RAX];
    args[0] = handle;
    args[1] = scratch + 0x100u;
    args[2] = scratch + 0x108u;
    if (!check(invoke_thunk(emulator, process, is_64,
            affinity, stack, return_address, args, 3u,
            &state, &status)
        && status == XXEMUL_STATUS_OK
        && state.gpr[XXEMUL_X86_RAX] == 1u
        && read_integer(emulator, args[1], word_size, &value)
            == XXEMUL_STATUS_OK && value == 1u,
        "affinity query rejected opened process")) return 0;
    args[0] = handle;
    args[1] = handle;
    args[2] = handle;
    args[3] = scratch + 0x120u;
    args[4] = 0u;
    args[5] = 0u;
    args[6] = 0u;
    if (!check(invoke_thunk(emulator, process, is_64,
            duplicate, stack, return_address, args, 7u,
            &state, &status)
        && status == XXEMUL_STATUS_OK
        && state.gpr[XXEMUL_X86_RAX] == 1u
        && read_integer(emulator, args[3], word_size, &copied)
            == XXEMUL_STATUS_OK
        && copied != handle && copied >= 0x100u,
        "opened process handle was not duplicable")) return 0;
    args[0] = handle;
    if (!check(invoke_thunk(emulator, process, is_64,
            close_handle, stack, return_address, args, 1u,
            &state, &status)
        && status == XXEMUL_STATUS_OK
        && state.gpr[XXEMUL_X86_RAX] == 1u,
        "opened process handle did not close")) return 0;
    args[0] = copied;
    args[1] = scratch + 0x100u;
    args[2] = scratch + 0x108u;
    if (!check(invoke_thunk(emulator, process, is_64,
            affinity, stack, return_address, args, 3u,
            &state, &status)
        && status == XXEMUL_STATUS_OK
        && state.gpr[XXEMUL_X86_RAX] == 1u,
        "duplicate process handle did not outlive original"))
        return 0;
    args[0] = copied;
    if (!check(invoke_thunk(emulator, process, is_64,
            close_handle, stack, return_address, args, 1u,
            &state, &status)
        && status == XXEMUL_STATUS_OK
        && state.gpr[XXEMUL_X86_RAX] == 1u,
        "duplicate process handle did not close")) return 0;
    args[0] = 0x400u;
    args[1] = 0u;
    args[2] = 999u;
    if (!check(invoke_thunk(emulator, process, is_64,
            open_process, stack, return_address, args, 3u,
            &state, &status)
        && status == XXEMUL_STATUS_OK
        && state.gpr[XXEMUL_X86_RAX] == 0u
        && invoke_thunk(emulator, process, is_64,
            get_last_error, stack, return_address, args, 0u,
            &state, &status)
        && status == XXEMUL_STATUS_OK
        && state.gpr[XXEMUL_X86_RAX] == 87u,
        "unknown process ID did not fail")) return 0;
    return 1;
}

static int test_memory_and_exception_imports(xxemul *emulator,
    xxemul_windows *process, int is_64, uint64_t get_proc,
    uint64_t stack, uint64_t return_address, uint64_t scratch)
{
    uint64_t virtual_query = 0u, raise_exception = 0u;
    uint64_t get_last_error = 0u, value;
    uint64_t args[4] = {0};
    uint64_t base = xxemul_get_region_address(emulator);
    uint32_t structure_size = is_64 ? 48u : 28u;
    uint8_t word_size = (uint8_t)(is_64 ? 8u : 4u);
    xxemul_x86_state state;
    xxemul_status status;
    if (!check(lookup_api(emulator, process, is_64, get_proc,
            stack, return_address, scratch, "VirtualQuery",
            &state, &virtual_query)
        && lookup_api(emulator, process, is_64, get_proc,
            stack, return_address, scratch, "RaiseException",
            &state, &raise_exception)
        && lookup_api(emulator, process, is_64, get_proc,
            stack, return_address, scratch, "GetLastError",
            &state, &get_last_error),
        "memory or exception import lookup failed")) return 0;
    args[0] = base + 0x1000u;
    args[1] = scratch + 0x100u;
    args[2] = structure_size;
    if (!check(invoke_thunk(emulator, process, is_64,
            virtual_query, stack, return_address, args, 3u,
            &state, &status)
        && status == XXEMUL_STATUS_OK
        && state.gpr[XXEMUL_X86_RAX] == structure_size
        && read_integer(emulator, args[1], word_size, &value)
            == XXEMUL_STATUS_OK && value == base
        && read_integer(emulator, args[1] + (is_64 ? 32u : 16u),
            4u, &value) == XXEMUL_STATUS_OK && value == 0x1000u
        && read_integer(emulator, args[1] + (is_64 ? 40u : 24u),
            4u, &value) == XXEMUL_STATUS_OK && value == 0x1000000u,
        "VirtualQuery image mapping is malformed")) return 0;
    args[2] = structure_size - 1u;
    if (!check(invoke_thunk(emulator, process, is_64,
            virtual_query, stack, return_address, args, 3u,
            &state, &status)
        && status == XXEMUL_STATUS_OK
        && state.gpr[XXEMUL_X86_RAX] == 0u
        && invoke_thunk(emulator, process, is_64,
            get_last_error, stack, return_address, args, 0u,
            &state, &status)
        && status == XXEMUL_STATUS_OK
        && state.gpr[XXEMUL_X86_RAX] == 87u,
        "VirtualQuery accepted a short information buffer")) return 0;
    args[0] = 0xe0000001u;
    args[1] = 0u;
    args[2] = 0u;
    args[3] = 0u;
    return check(invoke_thunk(emulator, process, is_64,
            raise_exception, stack, return_address, args, 4u,
            &state, &status)
            && status == XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION
            && state.ip == raise_exception,
        "RaiseException was silently discarded");
}

static int test_thread_control(xxemul *emulator,
    xxemul_windows *process, int is_64, uint64_t get_proc,
    uint64_t stack, uint64_t return_address, uint64_t scratch)
{
    uint64_t get_thread = 0u, resume = 0u, suspend = 0u;
    uint64_t set_context = 0u, sleep_api = 0u;
    uint64_t tick = 0u, get_last_error = 0u;
    uint64_t args[2] = {0};
    uint64_t current, before;
    xxemul_x86_state state;
    xxemul_status status;
    if (!check(lookup_api(emulator, process, is_64, get_proc,
            stack, return_address, scratch, "GetCurrentThread",
            &state, &get_thread)
        && lookup_api(emulator, process, is_64, get_proc,
            stack, return_address, scratch, "ResumeThread",
            &state, &resume)
        && lookup_api(emulator, process, is_64, get_proc,
            stack, return_address, scratch, "SuspendThread",
            &state, &suspend)
        && lookup_api(emulator, process, is_64, get_proc,
            stack, return_address, scratch, "SetThreadContext",
            &state, &set_context)
        && lookup_api(emulator, process, is_64, get_proc,
            stack, return_address, scratch, "Sleep",
            &state, &sleep_api)
        && lookup_api(emulator, process, is_64, get_proc,
            stack, return_address, scratch, "GetTickCount",
            &state, &tick)
        && lookup_api(emulator, process, is_64, get_proc,
            stack, return_address, scratch, "GetLastError",
            &state, &get_last_error),
        "thread-control API lookup failed")) return 0;
    if (!check(invoke_thunk(emulator, process, is_64,
            get_thread, stack, return_address, args, 0u,
            &state, &status)
        && status == XXEMUL_STATUS_OK,
        "GetCurrentThread failed")) return 0;
    current = state.gpr[XXEMUL_X86_RAX];
    args[0] = current;
    if (!check(invoke_thunk(emulator, process, is_64,
            resume, stack, return_address, args, 1u,
            &state, &status)
        && status == XXEMUL_STATUS_OK
        && state.gpr[XXEMUL_X86_RAX] == 0u,
        "resuming a running current thread should return zero"))
        return 0;
    args[0] = 0xdeadu;
    if (!check(invoke_thunk(emulator, process, is_64,
            resume, stack, return_address, args, 1u,
            &state, &status)
        && status == XXEMUL_STATUS_OK
        && state.gpr[XXEMUL_X86_RAX] == UINT32_MAX
        && invoke_thunk(emulator, process, is_64,
            get_last_error, stack, return_address, args, 0u,
            &state, &status)
        && status == XXEMUL_STATUS_OK
        && state.gpr[XXEMUL_X86_RAX] == 6u,
        "ResumeThread accepted an invalid thread handle")) return 0;
    if (!check(invoke_thunk(emulator, process, is_64,
            tick, stack, return_address, args, 0u,
            &state, &status)
        && status == XXEMUL_STATUS_OK,
        "GetTickCount failed")) return 0;
    before = state.gpr[XXEMUL_X86_RAX];
    args[0] = 37u;
    if (!check(invoke_thunk(emulator, process, is_64,
            sleep_api, stack, return_address, args, 1u,
            &state, &status)
        && status == XXEMUL_STATUS_OK
        && state.gpr[XXEMUL_X86_RSP]
            == stack + (is_64 ? 8u : 8u)
        && invoke_thunk(emulator, process, is_64,
            tick, stack, return_address, args, 0u,
            &state, &status)
        && status == XXEMUL_STATUS_OK
        && state.gpr[XXEMUL_X86_RAX] == before + 37u,
        "Sleep failed to advance guest time")) return 0;
    args[0] = current;
    args[1] = scratch + 0x100u;
    if (!check(invoke_thunk(emulator, process, is_64,
            suspend, stack, return_address, args, 1u,
            &state, &status)
        && status == XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION
        && invoke_thunk(emulator, process, is_64,
            set_context, stack, return_address, args, 2u,
            &state, &status)
        && status == XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION,
        "unsupported current-thread suspension/context change was hidden"))
        return 0;
    return 1;
}

static int test_file_time(xxemul *emulator, xxemul_windows *process,
    const char *path, int is_64, uint64_t get_proc, uint64_t stack,
    uint64_t return_address, uint64_t scratch)
{
    uint64_t create_file = 0, get_file_time = 0;
    uint64_t set_file_time = 0u;
    uint64_t close_handle = 0, get_last_error = 0;
    uint64_t args[7] = {0};
    uint64_t handle, value;
    xxemul_x86_state state;
    xxemul_status status;
    if (!check(lookup_api(emulator, process, is_64, get_proc,
            stack, return_address, scratch, "CreateFileA",
            &state, &create_file)
        && lookup_api(emulator, process, is_64, get_proc,
            stack, return_address, scratch, "GetFileTime",
            &state, &get_file_time)
        && lookup_api(emulator, process, is_64, get_proc,
            stack, return_address, scratch, "SetFileTime",
            &state, &set_file_time)
        && lookup_api(emulator, process, is_64, get_proc,
            stack, return_address, scratch, "CloseHandle",
            &state, &close_handle)
        && lookup_api(emulator, process, is_64, get_proc,
            stack, return_address, scratch, "GetLastError",
            &state, &get_last_error),
        "file-time API lookup failed")) return 0;
    if (!check(xxemul_write_memory(emulator, scratch,
            path, strlen(path) + 1u) == XXEMUL_STATUS_OK,
            "unable to write input file path")) return 0;
    args[0] = scratch;
    args[1] = UINT32_C(0x80000000);
    args[4] = 3u;
    if (!check(invoke_thunk(emulator, process, is_64,
            create_file, stack, return_address, args, 7u,
            &state, &status)
            && status == XXEMUL_STATUS_OK
            && state.gpr[XXEMUL_X86_RAX]
                != (is_64 ? UINT64_MAX : UINT32_MAX),
            "CreateFileA could not open UPX fixture")) return 0;
    handle = state.gpr[XXEMUL_X86_RAX];
    args[0] = handle;
    args[1] = scratch + 0x500u;
    args[2] = scratch + 0x510u;
    args[3] = scratch + 0x520u;
    if (!check(invoke_thunk(emulator, process, is_64,
            get_file_time, stack, return_address, args, 4u,
            &state, &status)
            && status == XXEMUL_STATUS_OK
            && state.gpr[XXEMUL_X86_RAX] == 1u
            && state.gpr[XXEMUL_X86_RSP]
                == stack + (is_64 ? 8u : 20u)
            && read_integer(emulator, args[1], 8u, &value)
                == XXEMUL_STATUS_OK
            && value > UINT64_C(120000000000000000)
            && read_integer(emulator, args[3], 8u, &value)
                == XXEMUL_STATUS_OK
            && value > UINT64_C(120000000000000000),
            "GetFileTime did not return file metadata")) return 0;
    args[1] = args[2] = args[3] = 0u;
    if (!check(invoke_thunk(emulator, process, is_64,
            get_file_time, stack, return_address, args, 4u,
            &state, &status)
            && status == XXEMUL_STATUS_OK
            && state.gpr[XXEMUL_X86_RAX] == 1u,
            "GetFileTime rejected optional null outputs")) return 0;
    args[0] = 0xdeadu;
    if (!check(invoke_thunk(emulator, process, is_64,
            get_file_time, stack, return_address, args, 4u,
            &state, &status)
            && status == XXEMUL_STATUS_OK
            && state.gpr[XXEMUL_X86_RAX] == 0u
            && invoke_thunk(emulator, process, is_64,
                get_last_error, stack, return_address, args, 0u,
                &state, &status)
            && status == XXEMUL_STATUS_OK
            && state.gpr[XXEMUL_X86_RAX] == 6u,
            "invalid GetFileTime handle did not fail")) return 0;
    args[0] = handle;
    if (!check(invoke_thunk(emulator, process, is_64,
            close_handle, stack, return_address, args, 1u,
            &state, &status)
            && status == XXEMUL_STATUS_OK
            && state.gpr[XXEMUL_X86_RAX] == 1u,
        "CloseHandle(file) failed")) return 0;
    if (!check(xxemul_write_memory(emulator, scratch,
            is_64 ? "AGENT_TIME_64.bin" : "AGENT_TIME_32.bin",
            sizeof("AGENT_TIME_64.bin")) == XXEMUL_STATUS_OK,
        "unable to write agent-owned file name")) return 0;
    memset(args, 0, sizeof(args));
    args[0] = scratch;
    args[1] = UINT32_C(0xc0000000);
    args[4] = 2u;
    if (!check(invoke_thunk(emulator, process, is_64,
            create_file, stack, return_address, args, 7u,
            &state, &status)
        && status == XXEMUL_STATUS_OK
        && state.gpr[XXEMUL_X86_RAX]
            != (is_64 ? UINT64_MAX : UINT32_MAX),
        "CreateFileA could not create agent-owned file")) return 0;
    handle = state.gpr[XXEMUL_X86_RAX];
    args[0] = handle;
    args[1] = 0u;
    args[2] = 0u;
    args[3] = scratch + 0x540u;
    if (!check(write_integer(emulator, args[3], 8u,
            UINT64_C(133500000000000000)) == XXEMUL_STATUS_OK
        && invoke_thunk(emulator, process, is_64,
            set_file_time, stack, return_address, args, 4u,
            &state, &status)
        && status == XXEMUL_STATUS_OK
        && state.gpr[XXEMUL_X86_RAX] == 1u,
        "SetFileTime did not update agent-owned file")) return 0;
    args[3] = scratch + 0x550u;
    if (!check(invoke_thunk(emulator, process, is_64,
            get_file_time, stack, return_address, args, 4u,
            &state, &status)
        && status == XXEMUL_STATUS_OK
        && state.gpr[XXEMUL_X86_RAX] == 1u
        && read_integer(emulator, args[3], 8u, &value)
            == XXEMUL_STATUS_OK
        && value == UINT64_C(133500000000000000),
        "SetFileTime/GetFileTime write timestamp did not round-trip"))
        return 0;
    args[0] = handle;
    return check(invoke_thunk(emulator, process, is_64,
            close_handle, stack, return_address, args, 1u,
            &state, &status)
        && status == XXEMUL_STATUS_OK
        && state.gpr[XXEMUL_X86_RAX] == 1u,
        "agent-owned file handle did not close");
}

static int test_crt_startup(xxemul *emulator,
    xxemul_windows *process, int is_64, uint64_t get_proc,
    uint64_t stack, uint64_t return_address, uint64_t scratch,
    const char *program_path)
{
    uint64_t getmainargs = 0u, init_env = 0u;
    uint64_t mb_cur_max = 0u, p_acmdln = 0u;
    uint64_t set_app_type = 0u, lconv_init = 0u;
    uint64_t locale_conv = 0u, set_matherr = 0u;
    uint64_t onexit = 0u;
    uint64_t time64 = 0u;
    uint64_t clock_api = 0u;
    uint64_t srand_api = 0u, rand_api = 0u;
    uint64_t osfhandle_api = 0u;
    uint64_t isatty_api = 0u;
    uint64_t iob_api = 0u, fileno_api = 0u;
    uint64_t fflush_api = 0u;
    uint64_t stat_api = 0u, stat64_api = 0u;
    uint64_t fstat_api = 0u, unlink_api = 0u;
    uint64_t chmod_api = 0u;
    uint64_t getenv_api = 0u;
    uint64_t sopen_api = 0u, read_api = 0u, write_api = 0u;
    uint64_t close_api = 0u, seek_api = 0u, opened_fd = 0u;
    uint64_t unimplemented_printf = 0u;
    uint64_t args[5] = {0};
    uint64_t value, argv = 0u, envp = 0u, command_line;
    uint64_t iob_address;
    uint8_t word_size = (uint8_t)(is_64 ? 8u : 4u);
    char text[256];
    xxemul_x86_state state;
    xxemul_status status;
    if (!check(lookup_crt_api(emulator, process, is_64, get_proc,
            stack, return_address, scratch, "__getmainargs",
            &state, &getmainargs)
        && lookup_crt_api(emulator, process, is_64, get_proc,
            stack, return_address, scratch, "__initenv",
            &state, &init_env)
        && lookup_crt_api(emulator, process, is_64, get_proc,
            stack, return_address, scratch, "__mb_cur_max",
            &state, &mb_cur_max)
        && lookup_crt_api(emulator, process, is_64, get_proc,
            stack, return_address, scratch, "__p__acmdln",
            &state, &p_acmdln)
        && lookup_crt_api(emulator, process, is_64, get_proc,
            stack, return_address, scratch, "__set_app_type",
            &state, &set_app_type)
        && lookup_crt_api(emulator, process, is_64, get_proc,
            stack, return_address, scratch, "__lconv_init",
            &state, &lconv_init)
        && lookup_crt_api(emulator, process, is_64, get_proc,
            stack, return_address, scratch, "localeconv",
            &state, &locale_conv)
        && lookup_crt_api(emulator, process, is_64, get_proc,
            stack, return_address, scratch, "__setusermatherr",
            &state, &set_matherr)
        && lookup_crt_api(emulator, process, is_64, get_proc,
            stack, return_address, scratch, "_onexit",
            &state, &onexit)
        && lookup_crt_api(emulator, process, is_64, get_proc,
            stack, return_address, scratch, "_time64",
            &state, &time64)
        && lookup_crt_api(emulator, process, is_64, get_proc,
            stack, return_address, scratch, "clock",
            &state, &clock_api)
        && lookup_crt_api(emulator, process, is_64, get_proc,
            stack, return_address, scratch, "srand",
            &state, &srand_api)
        && lookup_crt_api(emulator, process, is_64, get_proc,
            stack, return_address, scratch, "rand",
            &state, &rand_api)
        && lookup_crt_api(emulator, process, is_64, get_proc,
            stack, return_address, scratch, "_get_osfhandle",
            &state, &osfhandle_api)
        && lookup_crt_api(emulator, process, is_64, get_proc,
            stack, return_address, scratch, "_isatty",
            &state, &isatty_api)
        && lookup_crt_api(emulator, process, is_64, get_proc,
            stack, return_address, scratch, "__iob_func",
            &state, &iob_api)
        && lookup_crt_api(emulator, process, is_64, get_proc,
            stack, return_address, scratch, "_fileno",
            &state, &fileno_api)
        && lookup_crt_api(emulator, process, is_64, get_proc,
            stack, return_address, scratch, "fflush",
            &state, &fflush_api)
        && lookup_crt_api(emulator, process, is_64, get_proc,
            stack, return_address, scratch, "_stati64",
            &state, &stat_api)
        && lookup_crt_api(emulator, process, is_64, get_proc,
            stack, return_address, scratch, "_stat64",
            &state, &stat64_api)
        && lookup_crt_api(emulator, process, is_64, get_proc,
            stack, return_address, scratch, "_fstati64",
            &state, &fstat_api)
        && lookup_crt_api(emulator, process, is_64, get_proc,
            stack, return_address, scratch, "_unlink",
            &state, &unlink_api)
        && lookup_crt_api(emulator, process, is_64, get_proc,
            stack, return_address, scratch, "_chmod",
            &state, &chmod_api)
        && lookup_crt_api(emulator, process, is_64, get_proc,
            stack, return_address, scratch, "getenv",
            &state, &getenv_api)
        && lookup_crt_api(emulator, process, is_64, get_proc,
            stack, return_address, scratch, "_sopen",
            &state, &sopen_api)
        && lookup_crt_api(emulator, process, is_64, get_proc,
            stack, return_address, scratch, "_read",
            &state, &read_api)
        && lookup_crt_api(emulator, process, is_64, get_proc,
            stack, return_address, scratch, "_write",
            &state, &write_api)
        && lookup_crt_api(emulator, process, is_64, get_proc,
            stack, return_address, scratch, "_close",
            &state, &close_api)
        && lookup_crt_api(emulator, process, is_64, get_proc,
            stack, return_address, scratch, "_lseeki64",
            &state, &seek_api)
        && lookup_crt_api(emulator, process, is_64, get_proc,
            stack, return_address, scratch, "printf",
            &state, &unimplemented_printf),
        "MSVCRT startup symbol lookup failed")) return 0;
    args[0] = scratch + 0x100u;
    args[1] = scratch + 0x108u;
    args[2] = scratch + 0x118u;
    args[3] = 0u;
    args[4] = scratch + 0x128u;
    if (!check(invoke_thunk(emulator, process, is_64,
            getmainargs, stack, return_address, args, 5u,
            &state, &status)
        && status == XXEMUL_STATUS_OK
        && state.gpr[XXEMUL_X86_RAX] == 0u
        && state.gpr[XXEMUL_X86_RSP]
            == stack + (is_64 ? 8u : 4u)
        && read_integer(emulator, args[0], 4u, &value)
            == XXEMUL_STATUS_OK && value == 4u
        && read_integer(emulator, args[1], word_size, &argv)
            == XXEMUL_STATUS_OK
        && read_integer(emulator, args[2], word_size, &envp)
            == XXEMUL_STATUS_OK,
        "__getmainargs did not build argc/argv/envp")) return 0;
    if (!check(read_integer(emulator, argv + word_size,
            word_size, &value) == XXEMUL_STATUS_OK
        && read_ascii(emulator, value, text, sizeof(text))
        && strcmp(text, "-o") == 0
        && read_integer(emulator, argv + 2u * word_size,
            word_size, &value) == XXEMUL_STATUS_OK
        && read_ascii(emulator, value, text, sizeof(text))
        && strcmp(text, "PACKED.EXE") == 0
        && read_integer(emulator, argv + 3u * word_size,
            word_size, &value) == XXEMUL_STATUS_OK
        && read_ascii(emulator, value, text, sizeof(text))
        && strcmp(text, "FASM.EXE") == 0
        && read_integer(emulator, argv + 4u * word_size,
            word_size, &value) == XXEMUL_STATUS_OK
        && value == 0u,
        "MSVCRT argv contents or terminator are wrong")) return 0;
    if (!check(read_integer(emulator, init_env,
            word_size, &value) == XXEMUL_STATUS_OK
        && value == envp
        && read_integer(emulator, envp,
            word_size, &value) == XXEMUL_STATUS_OK
        && read_ascii(emulator, value, text, sizeof(text))
        && strcmp(text, "PATH=.") == 0
        && read_integer(emulator, mb_cur_max, 4u, &value)
            == XXEMUL_STATUS_OK && value == 1u,
        "MSVCRT imported data symbols are malformed")) return 0;
    args[0] = scratch + 0x800u;
    status = xxemul_windows_set_environment(process,
        "UPX_DEBUG_DOCTEST_DISABLE", "1");
    if (status != XXEMUL_STATUS_OK) {
        fprintf(stderr, "setting guest environment: %s\n",
            xxemul_status_string(status));
        return 0;
    }
    if (!check(xxemul_write_memory(emulator, args[0],
            "UPX_DEBUG_DOCTEST_DISABLE",
            sizeof("UPX_DEBUG_DOCTEST_DISABLE")) == XXEMUL_STATUS_OK,
        "writing getenv key failed")) return 0;
    if (!check(invoke_thunk(emulator, process, is_64,
            getenv_api, stack, return_address, args, 1u,
            &state, &status)
        && status == XXEMUL_STATUS_OK
        && state.gpr[XXEMUL_X86_RAX] != 0u,
        "getenv did not find explicit guest variable")) return 0;
    if (!check(read_ascii(emulator, state.gpr[XXEMUL_X86_RAX],
            text, sizeof(text))
        && strcmp(text, "1") == 0,
        "getenv returned the wrong guest value")) return 0;
    if (!check(read_integer(emulator, envp + word_size,
            word_size, &value) == XXEMUL_STATUS_OK
        && read_ascii(emulator, value, text, sizeof(text))
        && strcmp(text, "UPX_DEBUG_DOCTEST_DISABLE=1") == 0,
        "explicit guest environment did not reach envp")) return 0;
    if (!check(xxemul_windows_set_environment(process,
            "UPX_DEBUG_DOCTEST_DISABLE", "0") == XXEMUL_STATUS_OK
        && invoke_thunk(emulator, process, is_64,
            getenv_api, stack, return_address, args, 1u,
            &state, &status)
        && status == XXEMUL_STATUS_OK
        && read_ascii(emulator, state.gpr[XXEMUL_X86_RAX],
            text, sizeof(text))
        && strcmp(text, "0") == 0,
        "guest environment replacement failed")) return 0;
    if (!check(invoke_thunk(emulator, process, is_64,
            p_acmdln, stack, return_address, args, 0u,
            &state, &status)
        && status == XXEMUL_STATUS_OK
        && read_integer(emulator, state.gpr[XXEMUL_X86_RAX],
            word_size, &command_line) == XXEMUL_STATUS_OK
        && read_ascii(emulator, command_line, text, sizeof(text))
        && strstr(text, "FASM.EXE") != NULL,
        "__p__acmdln did not expose guest command line")) return 0;
    args[0] = 1u;
    if (!check(invoke_thunk(emulator, process, is_64,
            set_app_type, stack, return_address, args, 1u,
            &state, &status)
        && status == XXEMUL_STATUS_OK
        && state.gpr[XXEMUL_X86_RSP]
            == stack + (is_64 ? 8u : 4u),
        "__set_app_type cdecl cleanup failed")) return 0;
    if (!check(invoke_thunk(emulator, process, is_64,
            lconv_init, stack, return_address, args, 0u,
            &state, &status)
        && status == XXEMUL_STATUS_OK
        && state.gpr[XXEMUL_X86_RAX] == 0u
        && invoke_thunk(emulator, process, is_64,
            locale_conv, stack, return_address, args, 0u,
            &state, &status)
        && status == XXEMUL_STATUS_OK
        && read_integer(emulator, state.gpr[XXEMUL_X86_RAX],
            word_size, &value) == XXEMUL_STATUS_OK
        && read_ascii(emulator, value, text, sizeof(text))
        && strcmp(text, ".") == 0,
        "C locale initialization is malformed")) return 0;
    args[0] = scratch + 0x200u;
    if (!check(invoke_thunk(emulator, process, is_64,
            set_matherr, stack, return_address, args, 1u,
            &state, &status)
        && status == XXEMUL_STATUS_OK
        && state.gpr[XXEMUL_X86_RSP]
            == stack + (is_64 ? 8u : 4u),
        "__setusermatherr cdecl cleanup failed")) return 0;
    args[0] = scratch + 0x220u;
    if (!check(invoke_thunk(emulator, process, is_64,
            onexit, stack, return_address, args, 1u,
            &state, &status)
        && status == XXEMUL_STATUS_OK
        && state.gpr[XXEMUL_X86_RAX] == args[0]
        && state.gpr[XXEMUL_X86_RSP] == stack + word_size,
        "_onexit callback registration failed")) return 0;
    args[0] = 0u;
    if (!check(invoke_thunk(emulator, process, is_64,
            onexit, stack, return_address, args, 1u,
            &state, &status)
        && status == XXEMUL_STATUS_OK
        && state.gpr[XXEMUL_X86_RAX] == 0u,
        "_onexit accepted a null callback")) return 0;
    args[0] = scratch + 0x240u;
    if (!check(invoke_thunk(emulator, process, is_64,
            time64, stack, return_address, args, 1u,
            &state, &status)
        && status == XXEMUL_STATUS_OK
        && read_integer(emulator, args[0], 8u, &value)
            == XXEMUL_STATUS_OK
        && value > UINT64_C(1000000000)
        && (is_64 ? state.gpr[XXEMUL_X86_RAX] == value
            : (uint32_t)state.gpr[XXEMUL_X86_RAX] == (uint32_t)value
                && (uint32_t)state.gpr[XXEMUL_X86_RDX]
                    == (uint32_t)(value >> 32u)),
        "_time64 return or writeback failed")) return 0;
    if (!check(invoke_thunk(emulator, process, is_64,
            clock_api, stack, return_address, args, 0u,
            &state, &status)
        && status == XXEMUL_STATUS_OK
        && state.gpr[XXEMUL_X86_RAX] != UINT32_MAX
        && state.gpr[XXEMUL_X86_RSP] == stack + word_size,
        "clock return or cdecl cleanup failed")) return 0;
    args[0] = 1u;
    if (!check(invoke_thunk(emulator, process, is_64,
            srand_api, stack, return_address, args, 1u,
            &state, &status)
        && status == XXEMUL_STATUS_OK
        && invoke_thunk(emulator, process, is_64,
            rand_api, stack, return_address, args, 0u,
            &state, &status)
        && status == XXEMUL_STATUS_OK
        && state.gpr[XXEMUL_X86_RAX] == 41u,
        "MSVCRT srand/rand sequence failed")) return 0;
    args[0] = 1u;
    if (!check(invoke_thunk(emulator, process, is_64,
            osfhandle_api, stack, return_address, args, 1u,
            &state, &status)
        && status == XXEMUL_STATUS_OK
        && state.gpr[XXEMUL_X86_RAX] == 0x11u,
        "_get_osfhandle did not map stdout")) return 0;
    args[0] = 9u;
    if (!check(invoke_thunk(emulator, process, is_64,
            osfhandle_api, stack, return_address, args, 1u,
            &state, &status)
        && status == XXEMUL_STATUS_OK
        && state.gpr[XXEMUL_X86_RAX]
            == (is_64 ? UINT64_MAX : UINT32_MAX),
        "_get_osfhandle accepted an unknown descriptor")) return 0;
    args[0] = 0u;
    if (!check(invoke_thunk(emulator, process, is_64,
            isatty_api, stack, return_address, args, 1u,
            &state, &status)
        && status == XXEMUL_STATUS_OK
        && state.gpr[XXEMUL_X86_RAX] != 0u,
        "_isatty did not recognize stdin")) return 0;
    if (!check(invoke_thunk(emulator, process, is_64,
            iob_api, stack, return_address, args, 0u,
            &state, &status)
        && status == XXEMUL_STATUS_OK,
        "__iob_func did not expose standard streams")) return 0;
    iob_address = state.gpr[XXEMUL_X86_RAX];
    args[0] = iob_address + (is_64 ? 48u : 32u);
    if (!check(invoke_thunk(emulator, process, is_64,
            fflush_api, stack, return_address, args, 1u,
            &state, &status)
        && status == XXEMUL_STATUS_OK
        && state.gpr[XXEMUL_X86_RAX] == 0u,
        "fflush did not flush guest stdout")) return 0;
    args[0] = 0u;
    if (!check(invoke_thunk(emulator, process, is_64,
            fflush_api, stack, return_address, args, 1u,
            &state, &status)
        && status == XXEMUL_STATUS_OK
        && state.gpr[XXEMUL_X86_RAX] == 0u,
        "fflush(NULL) did not flush guest streams")) return 0;
    args[0] = scratch + 0x120u;
    if (!check(invoke_thunk(emulator, process, is_64,
            fflush_api, stack, return_address, args, 1u,
            &state, &status)
        && status == XXEMUL_STATUS_OK
        && (uint32_t)state.gpr[XXEMUL_X86_RAX] == UINT32_MAX,
        "fflush accepted an unknown stream")) return 0;
    args[0] = iob_address + (is_64 ? 48u : 32u);
    if (!check(invoke_thunk(emulator, process, is_64,
            fileno_api, stack, return_address, args, 1u,
            &state, &status)
        && status == XXEMUL_STATUS_OK
        && state.gpr[XXEMUL_X86_RAX] == 1u,
        "_fileno did not map stdout")) return 0;
    args[0] = scratch + 0x300u;
    args[1] = scratch + 0x500u;
    if (!check(xxemul_write_memory(emulator, args[0],
            program_path, strlen(program_path) + 1u) == XXEMUL_STATUS_OK
        && invoke_thunk(emulator, process, is_64,
            stat_api, stack, return_address, args, 2u,
            &state, &status)
        && status == XXEMUL_STATUS_OK
        && state.gpr[XXEMUL_X86_RAX] == 0u
        && read_integer(emulator, args[1] + 6u, 2u, &value)
            == XXEMUL_STATUS_OK
        && (value & 0xf000u) == 0x8000u
        && read_integer(emulator, args[1] + 24u, 8u, &value)
            == XXEMUL_STATUS_OK
        && value > 10000u,
        "_stati64 did not report the UPX executable")) return 0;
    args[1] = scratch + 0x580u;
    if (!check(invoke_thunk(emulator, process, is_64,
            stat64_api, stack, return_address, args, 2u,
            &state, &status)
        && status == XXEMUL_STATUS_OK
        && state.gpr[XXEMUL_X86_RAX] == 0u
        && read_integer(emulator, args[1] + 24u, 8u, &value)
            == XXEMUL_STATUS_OK
        && value > 10000u,
        "_stat64 did not report the UPX executable")) return 0;
    args[0] = scratch + 0x300u;
    args[1] = 0x8000u;
    args[2] = 0x40u;
    args[3] = 0u;
    if (!check(invoke_thunk(emulator, process, is_64,
            sopen_api, stack, return_address, args, 4u,
            &state, &status)
        && status == XXEMUL_STATUS_OK
        && state.gpr[XXEMUL_X86_RAX] >= 3u
        && state.gpr[XXEMUL_X86_RAX] < 128u,
        "_sopen did not create a CRT descriptor")) return 0;
    opened_fd = state.gpr[XXEMUL_X86_RAX];
    args[0] = opened_fd;
    args[1] = scratch + 0x700u;
    if (!check(invoke_thunk(emulator, process, is_64,
            fstat_api, stack, return_address, args, 2u,
            &state, &status)
        && status == XXEMUL_STATUS_OK
        && state.gpr[XXEMUL_X86_RAX] == 0u
        && read_integer(emulator, args[1] + 24u, 8u, &value)
            == XXEMUL_STATUS_OK
        && value > 10000u,
        "_fstati64 did not report the open executable")) return 0;
    if (!check(invoke_thunk(emulator, process, is_64,
            osfhandle_api, stack, return_address, args, 1u,
            &state, &status)
        && status == XXEMUL_STATUS_OK
        && state.gpr[XXEMUL_X86_RAX] >= 0x100u,
        "_get_osfhandle lost the opened descriptor")) return 0;
    args[1] = scratch + 0x620u;
    args[2] = 2u;
    if (!check(invoke_thunk(emulator, process, is_64,
            read_api, stack, return_address, args, 3u,
            &state, &status)
        && status == XXEMUL_STATUS_OK
        && state.gpr[XXEMUL_X86_RAX] == 2u
        && read_integer(emulator, args[1], 2u, &value)
            == XXEMUL_STATUS_OK && value == 0x5a4du,
        "_read did not return the executable header")) return 0;
    args[0] = opened_fd;
    args[1] = 0u;
    args[2] = 0u;
    args[3] = 0u;
    if (!check(invoke_thunk(emulator, process, is_64,
            seek_api, stack, return_address, args,
            is_64 ? 3u : 4u, &state, &status)
        && status == XXEMUL_STATUS_OK
        && state.gpr[XXEMUL_X86_RAX] == 0u,
        "_lseeki64 did not rewind the descriptor")) return 0;
    args[0] = 1u;
    args[1] = scratch + 0x620u;
    args[2] = 0u;
    if (!check(invoke_thunk(emulator, process, is_64,
            write_api, stack, return_address, args, 3u,
            &state, &status)
        && status == XXEMUL_STATUS_OK
        && state.gpr[XXEMUL_X86_RAX] == 0u,
        "_write rejected an empty stdout write")) return 0;
    args[0] = opened_fd;
    if (!check(invoke_thunk(emulator, process, is_64,
            close_api, stack, return_address, args, 1u,
            &state, &status)
        && status == XXEMUL_STATUS_OK
        && state.gpr[XXEMUL_X86_RAX] == 0u,
        "_close did not release the CRT descriptor")) return 0;
    args[0] = scratch + 0x300u;
    if (!check(invoke_thunk(emulator, process, is_64,
            unlink_api, stack, return_address, args, 1u,
            &state, &status)
        && status == XXEMUL_STATUS_OK
        && (uint32_t)state.gpr[XXEMUL_X86_RAX] == UINT32_MAX,
        "_unlink accepted deletion of the loaded executable")) return 0;
    args[0] = scratch + 0x900u;
    if (!check(xxemul_write_memory(emulator, args[0],
            "XXEMUL_UNLINK_TEST.tmp",
            sizeof("XXEMUL_UNLINK_TEST.tmp")) == XXEMUL_STATUS_OK,
        "unable to prepare guest deletion path")) return 0;
    args[1] = 2u | 0x100u | 0x400u;
    args[2] = 0x40u;
    args[3] = 0u;
    if (!check(invoke_thunk(emulator, process, is_64,
            sopen_api, stack, return_address, args, 4u,
            &state, &status)
        && status == XXEMUL_STATUS_OK
        && state.gpr[XXEMUL_X86_RAX] >= 3u
        && state.gpr[XXEMUL_X86_RAX] < 128u,
        "_sopen did not create a disposable guest file")) return 0;
    args[0] = state.gpr[XXEMUL_X86_RAX];
    if (!check(invoke_thunk(emulator, process, is_64,
            close_api, stack, return_address, args, 1u,
            &state, &status)
        && status == XXEMUL_STATUS_OK,
        "_close failed for disposable guest file")) return 0;
    args[0] = scratch + 0x900u;
    args[1] = 0x180u;
    if (!check(invoke_thunk(emulator, process, is_64,
            chmod_api, stack, return_address, args, 2u,
            &state, &status)
        && status == XXEMUL_STATUS_OK
        && state.gpr[XXEMUL_X86_RAX] == 0u,
        "_chmod did not update the disposable guest file")) return 0;
    if (!check(invoke_thunk(emulator, process, is_64,
            unlink_api, stack, return_address, args, 1u,
            &state, &status)
        && status == XXEMUL_STATUS_OK
        && state.gpr[XXEMUL_X86_RAX] == 0u,
        "_unlink did not delete the disposable guest file")) return 0;
    return check(invoke_thunk(emulator, process, is_64,
            unimplemented_printf, stack, return_address, args, 0u,
            &state, &status)
        && status == XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION
        && state.ip == unimplemented_printf,
        "known unimplemented CRT call was silently accepted");
}

static int test_crt_initterm(xxemul *emulator,
    xxemul_windows *process, int is_64, uint64_t get_proc,
    uint64_t stack, uint64_t return_address, uint64_t scratch)
{
    uint64_t initterm = 0u;
    uint64_t arguments[2];
    uint64_t callbacks = scratch + 0x200u;
    uint64_t first = scratch + 0x300u;
    uint64_t second = scratch + 0x310u;
    uint8_t word_size = (uint8_t)(is_64 ? 8u : 4u);
    const uint8_t ret_instruction = 0xc3u;
    xxemul_x86_state state;
    xxemul_step_info info;
    xxemul_status status;
    if (!check(lookup_crt_api(emulator, process, is_64, get_proc,
            stack, return_address, scratch, "_initterm",
            &state, &initterm),
        "_initterm lookup failed")) return 0;
    arguments[0] = callbacks;
    arguments[1] = callbacks + 3u * word_size;
    if (!check(write_integer(emulator, callbacks,
            word_size, first) == XXEMUL_STATUS_OK
        && write_integer(emulator, callbacks + word_size,
            word_size, 0u) == XXEMUL_STATUS_OK
        && write_integer(emulator, callbacks + 2u * word_size,
            word_size, second) == XXEMUL_STATUS_OK
        && xxemul_write_memory(emulator, first,
            &ret_instruction, 1u) == XXEMUL_STATUS_OK
        && xxemul_write_memory(emulator, second,
            &ret_instruction, 1u) == XXEMUL_STATUS_OK
        && invoke_thunk(emulator, process, is_64,
            initterm, stack, return_address, arguments, 2u,
            &state, &status)
        && status == XXEMUL_STATUS_OK
        && state.ip == first
        && state.gpr[XXEMUL_X86_RSP]
            == stack - (is_64 ? 48u : 16u),
        "_initterm did not enter first callback")) return 0;
    if (!check(xxemul_step(emulator, &info) == XXEMUL_STATUS_OK
        && xxemul_windows_try_step(process, &info, &status)
        && status == XXEMUL_STATUS_OK
        && xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK
        && state.ip == second,
        "_initterm did not skip null slot and enter second callback"))
        return 0;
    return check(xxemul_step(emulator, &info) == XXEMUL_STATUS_OK
        && xxemul_windows_try_step(process, &info, &status)
        && status == XXEMUL_STATUS_OK
        && xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK
        && state.ip == return_address
        && state.gpr[XXEMUL_X86_RSP] == stack + word_size,
        "_initterm did not return to its caller with cdecl ABI");
}

static int test_crt_qsort(xxemul *emulator,
    xxemul_windows *process, int is_64, uint64_t get_proc,
    uint64_t stack, uint64_t return_address, uint64_t scratch)
{
    static const uint8_t comparator32[] = {
        0x8b, 0x44, 0x24, 0x04, 0x8b, 0x00,
        0x8b, 0x54, 0x24, 0x08, 0x2b, 0x02, 0xc3
    };
    static const uint8_t comparator64[] = {
        0x8b, 0x01, 0x2b, 0x02, 0xc3
    };
    static const uint32_t keys[] = {4u, 1u, 7u, 3u, 1u, 6u, 2u};
    uint64_t qsort_api = 0u;
    uint64_t args[4] = {scratch + 0x200u, 7u, 8u,
        scratch + 0x100u};
    uint64_t key = 0u, payload = 0u, left = 0u, right = 0u;
    uint32_t previous = 0u, seen = 0u;
    size_t index, steps, comparisons = 0u;
    uint8_t word_size = (uint8_t)(is_64 ? 8u : 4u);
    xxemul_x86_state state;
    xxemul_step_info info;
    xxemul_status status;
    if (!check(lookup_crt_api(emulator, process, is_64,
            get_proc, stack, return_address, scratch,
            "qsort", &state, &qsort_api)
        && xxemul_write_memory(emulator, args[3],
            is_64 ? comparator64 : comparator32,
            is_64 ? sizeof(comparator64) : sizeof(comparator32))
            == XXEMUL_STATUS_OK,
        "qsort comparator setup failed")) return 0;
    for (index = 0u; index < sizeof(keys) / sizeof(keys[0]);
         ++index) {
        if (!check(write_integer(emulator,
                args[0] + index * 8u, 4u, keys[index])
                == XXEMUL_STATUS_OK
            && write_integer(emulator,
                args[0] + index * 8u + 4u, 4u, index)
                == XXEMUL_STATUS_OK,
            "qsort input setup failed")) return 0;
    }
    if (!check(invoke_thunk(emulator, process, is_64,
            qsort_api, stack, return_address, args, 4u,
            &state, &status)
        && status == XXEMUL_STATUS_OK
        && state.ip == args[3]
        && state.gpr[XXEMUL_X86_RSP]
            == stack - (is_64 ? 48u : 16u)
        && (!is_64 || (state.gpr[XXEMUL_X86_RSP] & 15u) == 8u),
        "qsort did not enter comparator with the expected stack"))
        return 0;
    for (steps = 0u; steps < 2048u && state.ip != return_address;
         ++steps) {
        if (state.ip == args[3]) {
            ++comparisons;
            if (is_64) {
                left = state.gpr[XXEMUL_X86_RCX];
                right = state.gpr[XXEMUL_X86_RDX];
            } else if (!check(read_integer(emulator,
                    state.gpr[XXEMUL_X86_RSP] + 4u, 4u, &left)
                    == XXEMUL_STATUS_OK
                && read_integer(emulator,
                    state.gpr[XXEMUL_X86_RSP] + 8u, 4u, &right)
                    == XXEMUL_STATUS_OK,
                "qsort comparator stack arguments are missing"))
                return 0;
            if (!check(left >= args[0] && right >= args[0]
                && left < args[0] + args[1] * args[2]
                && right < args[0] + args[1] * args[2]
                && (left - args[0]) % args[2] == 0u
                && (right - args[0]) % args[2] == 0u,
                "qsort comparator received invalid element pointers"))
                return 0;
        }
        if (!xxemul_windows_try_step(process, &info, &status))
            status = xxemul_step(emulator, &info);
        if (!check(status == XXEMUL_STATUS_OK
            && xxemul_get_x86_state(emulator, &state)
                == XXEMUL_STATUS_OK,
            "qsort comparator execution failed")) return 0;
    }
    if (!check(state.ip == return_address
        && state.gpr[XXEMUL_X86_RSP] == stack + word_size
        && comparisons > 0u,
        "qsort did not finish with the cdecl return ABI")) return 0;
    for (index = 0u; index < sizeof(keys) / sizeof(keys[0]);
         ++index) {
        if (!check(read_integer(emulator,
                args[0] + index * 8u, 4u, &key) == XXEMUL_STATUS_OK
            && read_integer(emulator,
                args[0] + index * 8u + 4u, 4u, &payload)
                == XXEMUL_STATUS_OK
            && payload < sizeof(keys) / sizeof(keys[0])
            && key == keys[payload]
            && (seen & (1u << payload)) == 0u
            && (index == 0u || key >= previous),
            "qsort did not preserve and order guest records")) return 0;
        seen |= 1u << payload;
        previous = (uint32_t)key;
    }
    args[0] = 0u;
    args[1] = 0u;
    args[2] = 0u;
    args[3] = 0u;
    if (!check(invoke_thunk(emulator, process, is_64,
            qsort_api, stack, return_address, args, 4u,
            &state, &status)
        && status == XXEMUL_STATUS_OK
        && state.ip == return_address
        && state.gpr[XXEMUL_X86_RSP] == stack + word_size,
        "qsort empty input failed")) return 0;
    args[0] = scratch + 0x200u;
    args[1] = 65537u;
    args[2] = 4u;
    args[3] = scratch + 0x100u;
    return check(invoke_thunk(emulator, process, is_64,
            qsort_api, stack, return_address, args, 4u,
            &state, &status)
        && status == XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION
        && state.ip == qsort_api,
        "qsort did not reject excessive element count");
}

static int test_crt_memory(xxemul *emulator,
    xxemul_windows *process, int is_64, uint64_t get_proc,
    uint64_t stack, uint64_t return_address, uint64_t scratch)
{
    static const char *const names[] = {
        "malloc", "calloc", "free", "realloc", "memset",
        "memcpy", "memmove", "memcmp", "memchr", "strlen"
    };
    uint64_t api[sizeof(names) / sizeof(names[0])] = {0};
    uint64_t args[3] = {0};
    uint64_t original, grown, zeroed, value;
    char bytes[8];
    size_t index;
    xxemul_x86_state state;
    xxemul_status status;
    for (index = 0u; index < sizeof(names) / sizeof(names[0]);
         ++index) {
        if (!check(lookup_crt_api(emulator, process, is_64,
                get_proc, stack, return_address, scratch,
                names[index], &state, &api[index]),
            "CRT memory API lookup failed")) return 0;
    }
    args[0] = 8u;
    if (!check(invoke_thunk(emulator, process, is_64,
            api[0], stack, return_address, args, 1u,
            &state, &status)
        && status == XXEMUL_STATUS_OK
        && state.gpr[XXEMUL_X86_RAX] != 0u
        && state.gpr[XXEMUL_X86_RSP]
            == stack + (is_64 ? 8u : 4u),
        "malloc or cdecl cleanup failed")) return 0;
    original = state.gpr[XXEMUL_X86_RAX];
    if (!check(xxemul_write_memory(emulator, original,
            "ABCDEFG", 8u) == XXEMUL_STATUS_OK,
        "unable to write allocated bytes")) return 0;
    args[0] = original;
    args[1] = 16u;
    if (!check(invoke_thunk(emulator, process, is_64,
            api[3], stack, return_address, args, 2u,
            &state, &status)
        && status == XXEMUL_STATUS_OK
        && state.gpr[XXEMUL_X86_RAX] != 0u
        && state.gpr[XXEMUL_X86_RAX] != original,
        "realloc did not grow allocation")) return 0;
    grown = state.gpr[XXEMUL_X86_RAX];
    if (!check(xxemul_read_memory(emulator, grown,
            bytes, sizeof(bytes)) == XXEMUL_STATUS_OK
        && memcmp(bytes, "ABCDEFG", 8u) == 0,
        "realloc did not preserve old bytes")) return 0;
    args[0] = grown;
    if (!check(invoke_thunk(emulator, process, is_64,
            api[9], stack, return_address, args, 1u,
            &state, &status)
        && status == XXEMUL_STATUS_OK
        && state.gpr[XXEMUL_X86_RAX] == 7u,
        "strlen of allocated string failed")) return 0;
    args[0] = 4u;
    args[1] = 4u;
    if (!check(invoke_thunk(emulator, process, is_64,
            api[1], stack, return_address, args, 2u,
            &state, &status)
        && status == XXEMUL_STATUS_OK
        && state.gpr[XXEMUL_X86_RAX] != 0u,
        "calloc failed")) return 0;
    zeroed = state.gpr[XXEMUL_X86_RAX];
    if (!check(read_integer(emulator, zeroed, 8u, &value)
            == XXEMUL_STATUS_OK && value == 0u,
        "calloc did not clear guest memory")) return 0;
    args[0] = zeroed;
    args[1] = 'X';
    args[2] = 4u;
    if (!check(invoke_thunk(emulator, process, is_64,
            api[4], stack, return_address, args, 3u,
            &state, &status)
        && status == XXEMUL_STATUS_OK
        && state.gpr[XXEMUL_X86_RAX] == zeroed
        && xxemul_read_memory(emulator, zeroed,
            bytes, 4u) == XXEMUL_STATUS_OK
        && memcmp(bytes, "XXXX", 4u) == 0,
        "memset failed")) return 0;
    args[0] = scratch + 0x500u;
    args[1] = grown;
    args[2] = 8u;
    if (!check(invoke_thunk(emulator, process, is_64,
            api[5], stack, return_address, args, 3u,
            &state, &status)
        && status == XXEMUL_STATUS_OK
        && xxemul_read_memory(emulator, args[0],
            bytes, 8u) == XXEMUL_STATUS_OK
        && memcmp(bytes, "ABCDEFG", 8u) == 0,
        "memcpy failed")) return 0;
    args[0] = scratch + 0x501u;
    args[1] = scratch + 0x500u;
    args[2] = 4u;
    if (!check(invoke_thunk(emulator, process, is_64,
            api[6], stack, return_address, args, 3u,
            &state, &status)
        && status == XXEMUL_STATUS_OK
        && xxemul_read_memory(emulator, scratch + 0x500u,
            bytes, 5u) == XXEMUL_STATUS_OK
        && memcmp(bytes, "AABCD", 5u) == 0,
        "overlapping memmove failed")) return 0;
    args[0] = scratch + 0x500u;
    args[1] = scratch + 0x520u;
    args[2] = 5u;
    if (!check(xxemul_write_memory(emulator, args[1],
            "AABCD", 5u) == XXEMUL_STATUS_OK
        && invoke_thunk(emulator, process, is_64,
            api[7], stack, return_address, args, 3u,
            &state, &status)
        && status == XXEMUL_STATUS_OK
        && state.gpr[XXEMUL_X86_RAX] == 0u,
        "memcmp equality failed")) return 0;
    args[0] = grown;
    args[1] = 'C';
    args[2] = 8u;
    if (!check(invoke_thunk(emulator, process, is_64,
            api[8], stack, return_address, args, 3u,
            &state, &status)
        && status == XXEMUL_STATUS_OK
        && state.gpr[XXEMUL_X86_RAX] == grown + 2u,
        "memchr did not return guest pointer")) return 0;
    args[0] = grown;
    if (!check(invoke_thunk(emulator, process, is_64,
            api[2], stack, return_address, args, 1u,
            &state, &status)
        && status == XXEMUL_STATUS_OK,
        "free failed")) return 0;
    args[0] = zeroed;
    if (!check(invoke_thunk(emulator, process, is_64,
            api[2], stack, return_address, args, 1u,
            &state, &status)
        && status == XXEMUL_STATUS_OK,
        "free(calloc result) failed")) return 0;
    args[0] = 2u * 1024u * 1024u;
    if (!check(invoke_thunk(emulator, process, is_64,
            api[0], stack, return_address, args, 1u,
            &state, &status)
        && status == XXEMUL_STATUS_OK
        && state.gpr[XXEMUL_X86_RAX] != 0u,
        "PE heap rejected a multi-megabyte allocation")) return 0;
    original = state.gpr[XXEMUL_X86_RAX];
    args[0] = original;
    if (!check(invoke_thunk(emulator, process, is_64,
            api[2], stack, return_address, args, 1u,
            &state, &status)
        && status == XXEMUL_STATUS_OK,
        "free of large allocation failed")) return 0;
    args[0] = 2u * 1024u * 1024u;
    if (!check(invoke_thunk(emulator, process, is_64,
            api[0], stack, return_address, args, 1u,
            &state, &status)
        && status == XXEMUL_STATUS_OK
        && state.gpr[XXEMUL_X86_RAX] == original,
        "PE heap did not reuse a freed allocation")) return 0;
    args[0] = original;
    return check(invoke_thunk(emulator, process, is_64,
            api[2], stack, return_address, args, 1u,
            &state, &status)
        && status == XXEMUL_STATUS_OK,
        "second free of large allocation failed");
}

static int test_crt_strings(xxemul *emulator,
    xxemul_windows *process, int is_64, uint64_t get_proc,
    uint64_t stack, uint64_t return_address, uint64_t scratch)
{
    static const char *const names[] = {
        "strcpy", "strcmp", "_stricmp", "strchr", "strrchr",
        "strstr", "strcspn", "strncpy", "wcslen", "getenv",
        "tolower", "isspace", "_strdup", "free"
    };
    uint64_t api[sizeof(names) / sizeof(names[0])] = {0};
    uint64_t args[3] = {0};
    uint64_t source = scratch + 0x100u;
    uint64_t destination = scratch + 0x200u;
    uint64_t value, duplicate;
    char bytes[16];
    size_t index;
    xxemul_x86_state state;
    xxemul_status status;
    for (index = 0u; index < sizeof(names) / sizeof(names[0]);
         ++index) {
        if (!check(lookup_crt_api(emulator, process, is_64,
                get_proc, stack, return_address, scratch,
                names[index], &state, &api[index]),
            "CRT string API lookup failed")) return 0;
    }
    if (!check(xxemul_write_memory(emulator, source,
            "AlphaBeta", sizeof("AlphaBeta")) == XXEMUL_STATUS_OK
        && xxemul_write_memory(emulator, scratch + 0x300u,
            "alphabeta", sizeof("alphabeta")) == XXEMUL_STATUS_OK
        && xxemul_write_memory(emulator, scratch + 0x320u,
            "Beta", sizeof("Beta")) == XXEMUL_STATUS_OK
        && xxemul_write_memory(emulator, scratch + 0x330u,
            "B", sizeof("B")) == XXEMUL_STATUS_OK,
        "unable to prepare CRT string inputs")) return 0;
    args[0] = destination;
    args[1] = source;
    if (!check(invoke_thunk(emulator, process, is_64,
            api[0], stack, return_address, args, 2u,
            &state, &status)
        && status == XXEMUL_STATUS_OK
        && state.gpr[XXEMUL_X86_RAX] == destination
        && xxemul_read_memory(emulator, destination,
            bytes, sizeof("AlphaBeta")) == XXEMUL_STATUS_OK
        && strcmp(bytes, "AlphaBeta") == 0,
        "strcpy failed")) return 0;
    args[0] = source;
    args[1] = destination;
    if (!check(invoke_thunk(emulator, process, is_64,
            api[1], stack, return_address, args, 2u,
            &state, &status)
        && status == XXEMUL_STATUS_OK
        && state.gpr[XXEMUL_X86_RAX] == 0u,
        "strcmp equality failed")) return 0;
    args[1] = scratch + 0x300u;
    if (!check(invoke_thunk(emulator, process, is_64,
            api[2], stack, return_address, args, 2u,
            &state, &status)
        && status == XXEMUL_STATUS_OK
        && state.gpr[XXEMUL_X86_RAX] == 0u,
        "_stricmp case-folded equality failed")) return 0;
    args[1] = 'B';
    if (!check(invoke_thunk(emulator, process, is_64,
            api[3], stack, return_address, args, 2u,
            &state, &status)
        && status == XXEMUL_STATUS_OK
        && state.gpr[XXEMUL_X86_RAX] == source + 5u,
        "strchr failed")) return 0;
    args[1] = 'a';
    if (!check(invoke_thunk(emulator, process, is_64,
            api[4], stack, return_address, args, 2u,
            &state, &status)
        && status == XXEMUL_STATUS_OK
        && state.gpr[XXEMUL_X86_RAX] == source + 8u,
        "strrchr failed")) return 0;
    args[1] = scratch + 0x320u;
    if (!check(invoke_thunk(emulator, process, is_64,
            api[5], stack, return_address, args, 2u,
            &state, &status)
        && status == XXEMUL_STATUS_OK
        && state.gpr[XXEMUL_X86_RAX] == source + 5u,
        "strstr failed")) return 0;
    args[1] = scratch + 0x330u;
    if (!check(invoke_thunk(emulator, process, is_64,
            api[6], stack, return_address, args, 2u,
            &state, &status)
        && status == XXEMUL_STATUS_OK
        && state.gpr[XXEMUL_X86_RAX] == 5u,
        "strcspn failed")) return 0;
    args[0] = destination;
    args[1] = source;
    args[2] = 3u;
    if (!check(invoke_thunk(emulator, process, is_64,
            api[7], stack, return_address, args, 3u,
            &state, &status)
        && status == XXEMUL_STATUS_OK
        && xxemul_read_memory(emulator, destination,
            bytes, 3u) == XXEMUL_STATUS_OK
        && memcmp(bytes, "Alp", 3u) == 0,
        "strncpy prefix failed")) return 0;
    args[0] = scratch + 0x350u;
    if (!check(write_integer(emulator, args[0], 2u, 'A')
            == XXEMUL_STATUS_OK
        && write_integer(emulator, args[0] + 2u, 2u, 'B')
            == XXEMUL_STATUS_OK
        && write_integer(emulator, args[0] + 4u, 2u, 0u)
            == XXEMUL_STATUS_OK
        && invoke_thunk(emulator, process, is_64,
            api[8], stack, return_address, args, 1u,
            &state, &status)
        && status == XXEMUL_STATUS_OK
        && state.gpr[XXEMUL_X86_RAX] == 2u,
        "wcslen failed")) return 0;
    args[0] = scratch + 0x360u;
    if (!check(xxemul_write_memory(emulator, args[0],
            "PATH", sizeof("PATH")) == XXEMUL_STATUS_OK
        && invoke_thunk(emulator, process, is_64,
            api[9], stack, return_address, args, 1u,
            &state, &status)
        && status == XXEMUL_STATUS_OK
        && read_integer(emulator, state.gpr[XXEMUL_X86_RAX],
            1u, &value) == XXEMUL_STATUS_OK && value == '.',
        "getenv(PATH) did not return guest environment value"))
        return 0;
    args[0] = 'Q';
    if (!check(invoke_thunk(emulator, process, is_64,
            api[10], stack, return_address, args, 1u,
            &state, &status)
        && status == XXEMUL_STATUS_OK
        && state.gpr[XXEMUL_X86_RAX] == 'q',
        "tolower failed")) return 0;
    args[0] = ' ';
    if (!check(invoke_thunk(emulator, process, is_64,
            api[11], stack, return_address, args, 1u,
            &state, &status)
        && status == XXEMUL_STATUS_OK
        && state.gpr[XXEMUL_X86_RAX] == 1u,
        "isspace failed")) return 0;
    args[0] = source;
    if (!check(invoke_thunk(emulator, process, is_64,
            api[12], stack, return_address, args, 1u,
            &state, &status)
        && status == XXEMUL_STATUS_OK
        && state.gpr[XXEMUL_X86_RAX] != 0u,
        "_strdup failed")) return 0;
    duplicate = state.gpr[XXEMUL_X86_RAX];
    if (!check(xxemul_read_memory(emulator, duplicate,
            bytes, sizeof("AlphaBeta")) == XXEMUL_STATUS_OK
        && strcmp(bytes, "AlphaBeta") == 0,
        "_strdup did not copy bytes")) return 0;
    args[0] = duplicate;
    return check(invoke_thunk(emulator, process, is_64,
            api[13], stack, return_address, args, 1u,
            &state, &status)
        && status == XXEMUL_STATUS_OK,
        "free(_strdup result) failed");
}

static int test_crt_numbers(xxemul *emulator,
    xxemul_windows *process, int is_64, uint64_t get_proc,
    uint64_t stack, uint64_t return_address, uint64_t scratch)
{
    static const struct {
        const char *input;
        uint32_t base;
        uint32_t expected;
        uint32_t expected_errno;
        uint32_t expected_end;
        int is_unsigned;
    } cases[] = {
        {"  -0x80000000tail", 0u, 0x80000000u, 0u, 13u, 0},
        {"2147483648!", 10u, INT32_MAX, 34u, 10u, 0},
        {"4294967295x", 10u, UINT32_MAX, 0u, 10u, 1},
        {"-1", 10u, UINT32_MAX, 0u, 2u, 1},
        {"4294967296", 10u, UINT32_MAX, 34u, 10u, 1},
        {"zzz", 10u, 0u, 0u, 0u, 0},
        {"25", 1u, 0u, 22u, 0u, 0}
    };
    uint64_t strtol_api = 0u, strtoul_api = 0u;
    uint64_t errno_api = 0u, errno_address;
    uint64_t args[3] = {scratch + 0x100u, scratch + 0x200u, 0u};
    uint64_t end_pointer, guest_errno;
    xxemul_x86_state state;
    xxemul_status status;
    size_t index;
    if (!check(lookup_crt_api(emulator, process, is_64,
            get_proc, stack, return_address, scratch,
            "strtol", &state, &strtol_api)
        && lookup_crt_api(emulator, process, is_64,
            get_proc, stack, return_address, scratch,
            "strtoul", &state, &strtoul_api)
        && lookup_crt_api(emulator, process, is_64,
            get_proc, stack, return_address, scratch,
            "_errno", &state, &errno_api)
        && invoke_thunk(emulator, process, is_64, errno_api,
            stack, return_address, args, 0u, &state, &status)
        && status == XXEMUL_STATUS_OK,
        "CRT number API lookup failed")) return 0;
    errno_address = state.gpr[XXEMUL_X86_RAX];
    for (index = 0u; index < sizeof(cases) / sizeof(cases[0]);
         ++index) {
        args[2] = cases[index].base;
        if (!check(xxemul_write_memory(emulator, args[0],
                cases[index].input, strlen(cases[index].input) + 1u)
                == XXEMUL_STATUS_OK
            && write_integer(emulator, errno_address, 4u, 0u)
                == XXEMUL_STATUS_OK
            && invoke_thunk(emulator, process, is_64,
                cases[index].is_unsigned ? strtoul_api : strtol_api,
                stack, return_address, args, 3u, &state, &status)
            && status == XXEMUL_STATUS_OK
            && (uint32_t)state.gpr[XXEMUL_X86_RAX]
                == cases[index].expected
            && state.gpr[XXEMUL_X86_RSP]
                == stack + (is_64 ? 8u : 4u)
            && read_integer(emulator, args[1],
                (uint8_t)(is_64 ? 8u : 4u), &end_pointer)
                == XXEMUL_STATUS_OK
            && end_pointer == args[0] + cases[index].expected_end
            && read_integer(emulator, errno_address, 4u, &guest_errno)
                == XXEMUL_STATUS_OK
            && guest_errno == cases[index].expected_errno,
            "CRT numeric conversion failed")) return 0;
    }
    return 1;
}

static int test_image(const char *path, const char *workdir,
    const char *unpacked_path, int is_64)
{
    xxemul *emulator;
    xxemul_windows *process;
    xxemul_x86_state state;
    xxemul_step_info info;
    xxemul_status status;
    const char *const arguments[] = {"-o", "PACKED.EXE", "FASM.EXE"};
    uint64_t base, teb, iat, target, peb, sp, ret, value, proc;
    uint64_t get_proc, add_handler, remove_handler, first_handle, last_handle;
    uint64_t arguments_for_call[4];
    uint64_t create_event = 0, set_event = 0, reset_event = 0;
    uint64_t wait_single = 0, wait_multiple = 0, close_handle = 0;
    uint64_t create_semaphore = 0, release_semaphore = 0;
    uint64_t initialize_critical = 0, delete_critical = 0;
    uint64_t enter_critical = 0, leave_critical = 0;
    uint64_t try_enter_critical = 0, critical_address;
    uint64_t get_current_process = 0, duplicate_handle = 0;
    uint64_t get_current_thread = 0, get_thread_priority = 0;
    uint64_t get_handle_information = 0;
    uint64_t get_last_error = 0;
    uint64_t crt_exit = 0;
    uint64_t current_process, duplicated_thread = 0;
    uint64_t duplicated_event = 0, reopened_event = 0;
    uint64_t duplicate_args[7];
    uint64_t event_handle, semaphore_handle;
    uint8_t breakpoint;
    int ok = 0;

    emulator = xxemul_create_image_file(
        is_64 ? XXEMUL_IMAGE_PE64 : XXEMUL_IMAGE_PE32,
        path, &status);
    if (!check(emulator != NULL, "UPX PE image did not load")) return 0;
    process = xxemul_windows_create(emulator, path, workdir,
        arguments, 3u, &status);
    if (!check(process != NULL, "Windows process initialization failed"))
        goto done_emulator;
    base = xxemul_get_region_address(emulator);
    teb = xxemul_windows_segment_base(process,
        is_64 ? XXEMUL_X86_GS : XXEMUL_X86_FS);
    if (!check(teb != 0, "TEB base missing")
        || !check(read_integer(emulator,
            teb + (is_64 ? 0x60u : 0x30u),
            (uint8_t)(is_64 ? 8u : 4u), &peb) == XXEMUL_STATUS_OK
            && peb != 0, "PEB pointer missing")) goto done_process;
    iat = base + (is_64 ? 0x273614u : 0x284610u);
    if (!check(read_integer(emulator, iat,
            (uint8_t)(is_64 ? 8u : 4u), &target) == XXEMUL_STATUS_OK
            && target != 0, "LoadLibraryA IAT entry missing")
        || !check(xxemul_read_memory(emulator, target,
            &breakpoint, 1u) == XXEMUL_STATUS_OK
            && breakpoint == 0xccu, "IAT target is not an API thunk"))
        goto done_process;
    if (!check(xxemul_get_x86_state(emulator, &state)
            == XXEMUL_STATUS_OK, "unable to read x86 state"))
        goto done_process;
    sp = state.gpr[XXEMUL_X86_RSP] - 64u;
    ret = base + 0x1000u;
    value = teb + 0x1000u;
    if (!check(xxemul_write_memory(emulator, value,
            "kernel32.dll", 13u) == XXEMUL_STATUS_OK
        && write_integer(emulator, sp,
            (uint8_t)(is_64 ? 8u : 4u), ret) == XXEMUL_STATUS_OK,
        "unable to prepare API call")) goto done_process;
    if (is_64) state.gpr[XXEMUL_X86_RCX] = value;
    else if (!check(write_integer(emulator,
            sp + 4u, 4u, value) == XXEMUL_STATUS_OK,
            "unable to write stdcall argument")) goto done_process;
    state.gpr[XXEMUL_X86_RSP] = sp;
    state.ip = target;
    if (!check(xxemul_set_x86_state(emulator, &state) == XXEMUL_STATUS_OK,
            "unable to set x86 state")) goto done_process;
    if (!check(xxemul_windows_try_step(process, &info, &status)
            && status == XXEMUL_STATUS_OK,
            "LoadLibraryA thunk did not execute")) goto done_process;
    if (!check(xxemul_get_x86_state(emulator, &state)
            == XXEMUL_STATUS_OK
            && state.ip == ret
            && state.gpr[XXEMUL_X86_RAX] == 0x76000000u
            && state.gpr[XXEMUL_X86_RSP]
                == sp + (is_64 ? 8u : 8u),
            "LoadLibraryA return ABI is wrong")) goto done_process;

    if (!check(read_integer(emulator,
            iat + (is_64 ? 16u : 8u),
            (uint8_t)(is_64 ? 8u : 4u), &target)
            == XXEMUL_STATUS_OK && target != 0,
            "GetProcAddress IAT entry missing")) goto done_process;
    value = teb + 0x1100u;
    if (!check(xxemul_write_memory(emulator, value,
            "VirtualProtect", 15u) == XXEMUL_STATUS_OK
            && write_integer(emulator, sp,
                (uint8_t)(is_64 ? 8u : 4u), ret) == XXEMUL_STATUS_OK,
            "unable to prepare GetProcAddress")) goto done_process;
    if (is_64) {
        state.gpr[XXEMUL_X86_RCX] = 0x76000000u;
        state.gpr[XXEMUL_X86_RDX] = value;
    } else if (!check(write_integer(emulator, sp + 4u,
            4u, 0x76000000u) == XXEMUL_STATUS_OK
            && write_integer(emulator, sp + 8u, 4u, value)
                == XXEMUL_STATUS_OK,
            "unable to write GetProcAddress arguments"))
        goto done_process;
    state.gpr[XXEMUL_X86_RSP] = sp;
    state.ip = target;
    if (!check(xxemul_set_x86_state(emulator, &state) == XXEMUL_STATUS_OK
            && xxemul_windows_try_step(process, &info, &status)
            && status == XXEMUL_STATUS_OK,
            "GetProcAddress thunk did not execute")) goto done_process;
    if (!check(xxemul_get_x86_state(emulator, &state)
            == XXEMUL_STATUS_OK && state.gpr[XXEMUL_X86_RAX] != 0,
            "GetProcAddress failed to resolve VirtualProtect"))
        goto done_process;
    proc = state.gpr[XXEMUL_X86_RAX];
    value = teb + 0x1200u;
    if (!check(write_integer(emulator, sp,
            (uint8_t)(is_64 ? 8u : 4u), ret) == XXEMUL_STATUS_OK,
            "unable to prepare VirtualProtect")) goto done_process;
    if (is_64) {
        state.gpr[XXEMUL_X86_RCX] = base + 0x1000u;
        state.gpr[XXEMUL_X86_RDX] = 0x1000u;
        state.gpr[XXEMUL_X86_R8] = 0x40u;
        state.gpr[XXEMUL_X86_R9] = value;
    } else if (!check(write_integer(emulator, sp + 4u,
            4u, base + 0x1000u) == XXEMUL_STATUS_OK
            && write_integer(emulator, sp + 8u, 4u, 0x1000u)
                == XXEMUL_STATUS_OK
            && write_integer(emulator, sp + 12u, 4u, 0x40u)
                == XXEMUL_STATUS_OK
            && write_integer(emulator, sp + 16u, 4u, value)
                == XXEMUL_STATUS_OK,
            "unable to write VirtualProtect arguments"))
        goto done_process;
    state.gpr[XXEMUL_X86_RSP] = sp;
    state.ip = proc;
    if (!check(xxemul_set_x86_state(emulator, &state) == XXEMUL_STATUS_OK
            && xxemul_windows_try_step(process, &info, &status)
            && status == XXEMUL_STATUS_OK
            && xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK
            && state.gpr[XXEMUL_X86_RAX] == 1u
            && read_integer(emulator, value, 4u, &value)
                == XXEMUL_STATUS_OK
            && value == 0x40u,
            "VirtualProtect thunk did not execute")) goto done_process;

    if (!check(read_integer(emulator, iat + (is_64 ? 16u : 8u),
            (uint8_t)(is_64 ? 8u : 4u), &get_proc)
            == XXEMUL_STATUS_OK,
            "GetProcAddress IAT entry missing")) goto done_process;
    value = teb + 0x1300u;
    if (!check(xxemul_write_memory(emulator, value,
            "AddVectoredExceptionHandler",
            sizeof("AddVectoredExceptionHandler")) == XXEMUL_STATUS_OK,
            "unable to write handler API name")) goto done_process;
    arguments_for_call[0] = 0x76000000u;
    arguments_for_call[1] = value;
    if (!check(invoke_thunk(emulator, process, is_64,
            get_proc, sp, ret, arguments_for_call, 2u, &state, &status)
            && status == XXEMUL_STATUS_OK
            && state.gpr[XXEMUL_X86_RAX] != 0
            && state.ip == ret
            && state.gpr[XXEMUL_X86_RSP] == sp + (is_64 ? 8u : 12u),
            "AddVectoredExceptionHandler lookup failed"))
        goto done_process;
    add_handler = state.gpr[XXEMUL_X86_RAX];
    arguments_for_call[0] = 1u;
    arguments_for_call[1] = base + 0x1234u;
    if (!check(invoke_thunk(emulator, process, is_64,
            add_handler, sp, ret, arguments_for_call, 2u, &state, &status)
            && status == XXEMUL_STATUS_OK
            && state.gpr[XXEMUL_X86_RAX] != 0
            && state.gpr[XXEMUL_X86_RSP] == sp + (is_64 ? 8u : 12u),
            "first vectored handler registration failed"))
        goto done_process;
    first_handle = state.gpr[XXEMUL_X86_RAX];
    arguments_for_call[0] = 0u;
    if (!check(invoke_thunk(emulator, process, is_64,
            add_handler, sp, ret, arguments_for_call, 2u, &state, &status)
            && status == XXEMUL_STATUS_OK
            && state.gpr[XXEMUL_X86_RAX] != 0
            && state.gpr[XXEMUL_X86_RAX] != first_handle,
            "duplicate callback did not get a distinct handle"))
        goto done_process;
    last_handle = state.gpr[XXEMUL_X86_RAX];
    value = teb + 0x1400u;
    if (!check(xxemul_write_memory(emulator, value,
            "RemoveVectoredExceptionHandler",
            sizeof("RemoveVectoredExceptionHandler")) == XXEMUL_STATUS_OK,
            "unable to write removal API name")) goto done_process;
    arguments_for_call[0] = 0x76000000u;
    arguments_for_call[1] = value;
    if (!check(invoke_thunk(emulator, process, is_64,
            get_proc, sp, ret, arguments_for_call, 2u, &state, &status)
            && status == XXEMUL_STATUS_OK
            && state.gpr[XXEMUL_X86_RAX] != 0,
            "RemoveVectoredExceptionHandler lookup failed"))
        goto done_process;
    remove_handler = state.gpr[XXEMUL_X86_RAX];
    arguments_for_call[0] = first_handle;
    if (!check(invoke_thunk(emulator, process, is_64,
            remove_handler, sp, ret, arguments_for_call, 1u, &state, &status)
            && status == XXEMUL_STATUS_OK
            && state.gpr[XXEMUL_X86_RAX] != 0
            && state.gpr[XXEMUL_X86_RSP] == sp + (is_64 ? 8u : 8u),
            "registered handler removal failed")) goto done_process;
    if (!check(invoke_thunk(emulator, process, is_64,
            remove_handler, sp, ret, arguments_for_call, 1u, &state, &status)
            && status == XXEMUL_STATUS_OK
            && state.gpr[XXEMUL_X86_RAX] == 0,
            "stale handler removal unexpectedly succeeded"))
        goto done_process;
    arguments_for_call[0] = last_handle;
    if (!check(invoke_thunk(emulator, process, is_64,
            remove_handler, sp, ret, arguments_for_call, 1u, &state, &status)
            && status == XXEMUL_STATUS_OK
            && state.gpr[XXEMUL_X86_RAX] != 0,
            "second handler removal failed")) goto done_process;
    arguments_for_call[0] = 1u;
    arguments_for_call[1] = 0u;
    if (!check(invoke_thunk(emulator, process, is_64,
            add_handler, sp, ret, arguments_for_call, 2u, &state, &status)
            && status == XXEMUL_STATUS_OK
            && state.gpr[XXEMUL_X86_RAX] == 0,
            "null callback registration unexpectedly succeeded"))
        goto done_process;

    if (!check(lookup_api(emulator, process, is_64, get_proc,
            sp, ret, teb + 0x1500u, "CreateEventA", &state, &create_event)
            && lookup_api(emulator, process, is_64, get_proc,
                sp, ret, teb + 0x1500u, "SetEvent", &state, &set_event)
            && lookup_api(emulator, process, is_64, get_proc,
                sp, ret, teb + 0x1500u, "ResetEvent", &state, &reset_event)
            && lookup_api(emulator, process, is_64, get_proc,
                sp, ret, teb + 0x1500u, "WaitForSingleObject",
                &state, &wait_single)
            && lookup_api(emulator, process, is_64, get_proc,
                sp, ret, teb + 0x1500u, "WaitForMultipleObjects",
                &state, &wait_multiple)
            && lookup_api(emulator, process, is_64, get_proc,
                sp, ret, teb + 0x1500u, "CreateSemaphoreA",
                &state, &create_semaphore)
            && lookup_api(emulator, process, is_64, get_proc,
                sp, ret, teb + 0x1500u, "ReleaseSemaphore",
                &state, &release_semaphore)
            && lookup_api(emulator, process, is_64, get_proc,
                sp, ret, teb + 0x1500u, "CloseHandle",
                &state, &close_handle),
            "synchronization API lookup failed")) goto done_process;
    arguments_for_call[0] = 0u;
    arguments_for_call[1] = 0u;
    arguments_for_call[2] = 0u;
    arguments_for_call[3] = 0u;
    if (!check(invoke_thunk(emulator, process, is_64,
            create_event, sp, ret, arguments_for_call, 4u, &state, &status)
            && status == XXEMUL_STATUS_OK
            && state.gpr[XXEMUL_X86_RAX] != 0
            && state.gpr[XXEMUL_X86_RSP] == sp + (is_64 ? 8u : 20u),
            "CreateEventA failed")) goto done_process;
    event_handle = state.gpr[XXEMUL_X86_RAX];
    arguments_for_call[0] = event_handle;
    arguments_for_call[1] = 0u;
    if (!check(invoke_thunk(emulator, process, is_64,
            wait_single, sp, ret, arguments_for_call, 2u, &state, &status)
            && status == XXEMUL_STATUS_OK
            && state.gpr[XXEMUL_X86_RAX] == 0x102u,
            "unsignaled event did not time out")) goto done_process;
    if (!check(invoke_thunk(emulator, process, is_64,
            set_event, sp, ret, arguments_for_call, 1u, &state, &status)
            && status == XXEMUL_STATUS_OK
            && state.gpr[XXEMUL_X86_RAX] == 1u,
            "SetEvent failed")) goto done_process;
    if (!check(invoke_thunk(emulator, process, is_64,
            wait_single, sp, ret, arguments_for_call, 2u, &state, &status)
            && status == XXEMUL_STATUS_OK
            && state.gpr[XXEMUL_X86_RAX] == 0u,
            "signaled event did not wake")) goto done_process;
    if (!check(invoke_thunk(emulator, process, is_64,
            wait_single, sp, ret, arguments_for_call, 2u, &state, &status)
            && status == XXEMUL_STATUS_OK
            && state.gpr[XXEMUL_X86_RAX] == 0x102u,
            "auto-reset event remained signaled")) goto done_process;
    if (!check(invoke_thunk(emulator, process, is_64,
            set_event, sp, ret, arguments_for_call, 1u, &state, &status)
            && invoke_thunk(emulator, process, is_64,
                reset_event, sp, ret, arguments_for_call, 1u,
                &state, &status)
            && status == XXEMUL_STATUS_OK
            && state.gpr[XXEMUL_X86_RAX] == 1u,
            "ResetEvent failed")) goto done_process;
    if (!check(invoke_thunk(emulator, process, is_64,
            close_handle, sp, ret, arguments_for_call, 1u, &state, &status)
            && status == XXEMUL_STATUS_OK
            && state.gpr[XXEMUL_X86_RAX] == 1u,
            "CloseHandle(event) failed")) goto done_process;
    if (!check(invoke_thunk(emulator, process, is_64,
            close_handle, sp, ret, arguments_for_call, 1u, &state, &status)
            && status == XXEMUL_STATUS_OK
            && state.gpr[XXEMUL_X86_RAX] == 0u,
            "closed event handle was reused")) goto done_process;

    arguments_for_call[0] = 0u;
    arguments_for_call[1] = 0u;
    arguments_for_call[2] = 2u;
    arguments_for_call[3] = 0u;
    if (!check(invoke_thunk(emulator, process, is_64,
            create_semaphore, sp, ret, arguments_for_call,
            4u, &state, &status)
            && status == XXEMUL_STATUS_OK
            && state.gpr[XXEMUL_X86_RAX] != 0,
            "CreateSemaphoreA failed")) goto done_process;
    semaphore_handle = state.gpr[XXEMUL_X86_RAX];
    arguments_for_call[0] = semaphore_handle;
    arguments_for_call[1] = 1u;
    arguments_for_call[2] = teb + 0x1600u;
    if (!check(invoke_thunk(emulator, process, is_64,
            release_semaphore, sp, ret, arguments_for_call,
            3u, &state, &status)
            && status == XXEMUL_STATUS_OK
            && state.gpr[XXEMUL_X86_RAX] == 1u
            && read_integer(emulator, teb + 0x1600u,
                4u, &value) == XXEMUL_STATUS_OK
            && value == 0u,
            "ReleaseSemaphore failed")) goto done_process;
    if (!check(write_integer(emulator, teb + 0x1610u,
            (uint8_t)(is_64 ? 8u : 4u), semaphore_handle)
                == XXEMUL_STATUS_OK,
            "unable to write wait handle array")) goto done_process;
    arguments_for_call[0] = 1u;
    arguments_for_call[1] = teb + 0x1610u;
    arguments_for_call[2] = 0u;
    arguments_for_call[3] = 0u;
    if (!check(invoke_thunk(emulator, process, is_64,
            wait_multiple, sp, ret, arguments_for_call,
            4u, &state, &status)
            && status == XXEMUL_STATUS_OK
            && state.gpr[XXEMUL_X86_RAX] == 0u,
            "WaitForMultipleObjects did not consume semaphore"))
        goto done_process;
    if (!check(invoke_thunk(emulator, process, is_64,
            wait_multiple, sp, ret, arguments_for_call,
            4u, &state, &status)
            && status == XXEMUL_STATUS_OK
            && state.gpr[XXEMUL_X86_RAX] == 0x102u,
            "consumed semaphore did not time out")) goto done_process;
    arguments_for_call[0] = semaphore_handle;
    if (!check(invoke_thunk(emulator, process, is_64,
            close_handle, sp, ret, arguments_for_call,
            1u, &state, &status)
            && status == XXEMUL_STATUS_OK
            && state.gpr[XXEMUL_X86_RAX] == 1u,
            "CloseHandle(semaphore) failed")) goto done_process;

    if (!check(lookup_api(emulator, process, is_64, get_proc,
            sp, ret, teb + 0x1500u, "InitializeCriticalSection",
            &state, &initialize_critical)
            && lookup_api(emulator, process, is_64, get_proc,
                sp, ret, teb + 0x1500u, "DeleteCriticalSection",
                &state, &delete_critical)
            && lookup_api(emulator, process, is_64, get_proc,
                sp, ret, teb + 0x1500u, "EnterCriticalSection",
                &state, &enter_critical)
            && lookup_api(emulator, process, is_64, get_proc,
                sp, ret, teb + 0x1500u, "LeaveCriticalSection",
                &state, &leave_critical)
            && lookup_api(emulator, process, is_64, get_proc,
                sp, ret, teb + 0x1500u, "TryEnterCriticalSection",
                &state, &try_enter_critical),
            "critical-section API lookup failed")) goto done_process;
    critical_address = teb + 0x1800u;
    arguments_for_call[0] = critical_address;
    if (!check(invoke_thunk(emulator, process, is_64,
            initialize_critical, sp, ret, arguments_for_call,
            1u, &state, &status)
            && status == XXEMUL_STATUS_OK
            && read_integer(emulator, critical_address
                + (is_64 ? 8u : 4u), 4u, &value)
                == XXEMUL_STATUS_OK
            && value == UINT32_MAX,
            "InitializeCriticalSection did not initialize guest object"))
        goto done_process;
    if (!check(invoke_thunk(emulator, process, is_64,
            enter_critical, sp, ret, arguments_for_call,
            1u, &state, &status)
            && status == XXEMUL_STATUS_OK
            && invoke_thunk(emulator, process, is_64,
                try_enter_critical, sp, ret, arguments_for_call,
                1u, &state, &status)
            && status == XXEMUL_STATUS_OK
            && state.gpr[XXEMUL_X86_RAX] == 1u
            && read_integer(emulator, critical_address
                + (is_64 ? 12u : 8u), 4u, &value)
                == XXEMUL_STATUS_OK
            && value == 2u,
            "recursive critical-section entry failed"))
        goto done_process;
    if (!check(invoke_thunk(emulator, process, is_64,
            leave_critical, sp, ret, arguments_for_call,
            1u, &state, &status)
            && status == XXEMUL_STATUS_OK
            && invoke_thunk(emulator, process, is_64,
                leave_critical, sp, ret, arguments_for_call,
                1u, &state, &status)
            && status == XXEMUL_STATUS_OK
            && read_integer(emulator, critical_address
                + (is_64 ? 12u : 8u), 4u, &value)
                == XXEMUL_STATUS_OK
            && value == 0u,
            "critical-section leave count is wrong"))
        goto done_process;
    if (!check(invoke_thunk(emulator, process, is_64,
            delete_critical, sp, ret, arguments_for_call,
            1u, &state, &status)
            && status == XXEMUL_STATUS_OK
            && invoke_thunk(emulator, process, is_64,
                initialize_critical, sp, ret, arguments_for_call,
                1u, &state, &status)
            && status == XXEMUL_STATUS_OK,
            "critical-section deletion/reinitialization failed"))
        goto done_process;

    if (!check(lookup_api(emulator, process, is_64, get_proc,
            sp, ret, teb + 0x1500u, "GetCurrentProcess",
            &state, &get_current_process)
            && lookup_api(emulator, process, is_64, get_proc,
                sp, ret, teb + 0x1500u, "DuplicateHandle",
                &state, &duplicate_handle)
            && lookup_api(emulator, process, is_64, get_proc,
                sp, ret, teb + 0x1500u, "GetCurrentThread",
                &state, &get_current_thread)
            && lookup_api(emulator, process, is_64, get_proc,
                sp, ret, teb + 0x1500u, "GetThreadPriority",
                &state, &get_thread_priority)
            && lookup_api(emulator, process, is_64, get_proc,
                sp, ret, teb + 0x1500u, "GetHandleInformation",
                &state, &get_handle_information)
            && lookup_api(emulator, process, is_64, get_proc,
                sp, ret, teb + 0x1500u, "GetLastError",
                &state, &get_last_error),
            "DuplicateHandle support lookup failed")) goto done_process;
    if (!check(invoke_thunk(emulator, process, is_64,
            get_current_process, sp, ret, arguments_for_call,
            0u, &state, &status)
            && status == XXEMUL_STATUS_OK
            && state.gpr[XXEMUL_X86_RAX]
                == (is_64 ? UINT64_MAX : UINT32_MAX)
            && state.gpr[XXEMUL_X86_RSP] == sp + (is_64 ? 8u : 4u),
            "GetCurrentProcess pseudo-handle is wrong"))
        goto done_process;
    current_process = state.gpr[XXEMUL_X86_RAX];
    if (!check(invoke_thunk(emulator, process, is_64,
            get_current_thread, sp, ret, arguments_for_call,
            0u, &state, &status)
            && status == XXEMUL_STATUS_OK,
            "current thread pseudo-handle missing")) goto done_process;
    duplicate_args[0] = current_process;
    duplicate_args[1] = state.gpr[XXEMUL_X86_RAX];
    duplicate_args[2] = current_process;
    duplicate_args[3] = teb + 0x1900u;
    duplicate_args[4] = 0u;
    duplicate_args[5] = 0u;
    duplicate_args[6] = 2u;
    if (!check(invoke_thunk(emulator, process, is_64,
            duplicate_handle, sp, ret, duplicate_args,
            7u, &state, &status)
            && status == XXEMUL_STATUS_OK
            && state.gpr[XXEMUL_X86_RAX] == 1u
            && read_integer(emulator, duplicate_args[3],
                (uint8_t)(is_64 ? 8u : 4u), &duplicated_thread)
                == XXEMUL_STATUS_OK
            && duplicated_thread >= 0x100u,
            "current-thread pseudo-handle duplication failed"))
        goto done_process;
    arguments_for_call[0] = duplicated_thread;
    if (!check(invoke_thunk(emulator, process, is_64,
            get_thread_priority, sp, ret, arguments_for_call,
            1u, &state, &status)
            && status == XXEMUL_STATUS_OK
            && state.gpr[XXEMUL_X86_RAX] == 0u
            && invoke_thunk(emulator, process, is_64,
                close_handle, sp, ret, arguments_for_call,
                1u, &state, &status)
            && status == XXEMUL_STATUS_OK
            && state.gpr[XXEMUL_X86_RAX] == 1u,
            "duplicated current-thread handle was not usable"))
        goto done_process;
    if (!check(xxemul_write_memory(emulator, teb + 0x1920u,
            "xxemul-event", sizeof("xxemul-event")) == XXEMUL_STATUS_OK,
            "unable to write named event")) goto done_process;
    arguments_for_call[0] = 0u;
    arguments_for_call[1] = 1u;
    arguments_for_call[2] = 1u;
    arguments_for_call[3] = teb + 0x1920u;
    if (!check(invoke_thunk(emulator, process, is_64,
            create_event, sp, ret, arguments_for_call,
            4u, &state, &status)
            && status == XXEMUL_STATUS_OK
            && state.gpr[XXEMUL_X86_RAX] != 0,
            "event for duplication failed")) goto done_process;
    event_handle = state.gpr[XXEMUL_X86_RAX];
    duplicate_args[0] = current_process;
    duplicate_args[1] = event_handle;
    duplicate_args[2] = current_process;
    duplicate_args[3] = teb + 0x1900u;
    duplicate_args[4] = 0u;
    duplicate_args[5] = 1u;
    duplicate_args[6] = 2u;
    if (!check(invoke_thunk(emulator, process, is_64,
            duplicate_handle, sp, ret, duplicate_args,
            7u, &state, &status)
            && status == XXEMUL_STATUS_OK
            && state.gpr[XXEMUL_X86_RAX] == 1u
            && state.gpr[XXEMUL_X86_RSP]
                == sp + (is_64 ? 8u : 32u)
            && read_integer(emulator, teb + 0x1900u,
                (uint8_t)(is_64 ? 8u : 4u), &duplicated_event)
                == XXEMUL_STATUS_OK
            && duplicated_event != event_handle,
            "DuplicateHandle did not create a distinct handle"))
        goto done_process;
    arguments_for_call[0] = duplicated_event;
    arguments_for_call[1] = teb + 0x1910u;
    if (!check(invoke_thunk(emulator, process, is_64,
            get_handle_information, sp, ret, arguments_for_call,
            2u, &state, &status)
            && status == XXEMUL_STATUS_OK
            && state.gpr[XXEMUL_X86_RAX] == 1u
            && read_integer(emulator, teb + 0x1910u, 4u, &value)
                == XXEMUL_STATUS_OK && value == 1u,
            "duplicated handle did not retain inherit flag"))
        goto done_process;
    arguments_for_call[0] = event_handle;
    if (!check(invoke_thunk(emulator, process, is_64,
            close_handle, sp, ret, arguments_for_call,
            1u, &state, &status)
            && status == XXEMUL_STATUS_OK
            && state.gpr[XXEMUL_X86_RAX] == 1u,
            "closing original event handle failed")) goto done_process;
    arguments_for_call[0] = 0u;
    arguments_for_call[1] = 1u;
    arguments_for_call[2] = 0u;
    arguments_for_call[3] = teb + 0x1920u;
    if (!check(invoke_thunk(emulator, process, is_64,
            create_event, sp, ret, arguments_for_call,
            4u, &state, &status)
            && status == XXEMUL_STATUS_OK
            && state.gpr[XXEMUL_X86_RAX] != 0u
            && state.gpr[XXEMUL_X86_RAX] != duplicated_event,
            "named event did not reopen through live duplicate"))
        goto done_process;
    reopened_event = state.gpr[XXEMUL_X86_RAX];
    if (!check(invoke_thunk(emulator, process, is_64,
            get_last_error, sp, ret, arguments_for_call,
            0u, &state, &status)
            && status == XXEMUL_STATUS_OK
            && state.gpr[XXEMUL_X86_RAX] == 183u,
            "reopened named event did not report already exists"))
        goto done_process;
    arguments_for_call[0] = duplicated_event;
    arguments_for_call[1] = 0u;
    if (!check(invoke_thunk(emulator, process, is_64,
            wait_single, sp, ret, arguments_for_call,
            2u, &state, &status)
            && status == XXEMUL_STATUS_OK
            && state.gpr[XXEMUL_X86_RAX] == 0u,
            "duplicate handle lost its event")) goto done_process;
    if (!check(invoke_thunk(emulator, process, is_64,
            close_handle, sp, ret, arguments_for_call,
            1u, &state, &status)
            && status == XXEMUL_STATUS_OK
            && state.gpr[XXEMUL_X86_RAX] == 1u,
            "closing duplicate event handle failed")) goto done_process;
    arguments_for_call[0] = reopened_event;
    if (!check(invoke_thunk(emulator, process, is_64,
            close_handle, sp, ret, arguments_for_call,
            1u, &state, &status)
            && status == XXEMUL_STATUS_OK
            && state.gpr[XXEMUL_X86_RAX] == 1u,
            "closing reopened event handle failed")) goto done_process;

    if (!test_console(emulator, process, is_64, get_proc,
            sp, ret, teb + 0x1a00u)) goto done_process;
    if (!test_console_output(emulator, process, is_64, get_proc,
            sp, ret, teb + 0x1a00u)) goto done_process;
    if (!test_process_state(emulator, process, is_64, get_proc,
            sp, ret, teb + 0x1b00u)) goto done_process;
    if (!test_text_conversion(emulator, process, is_64, get_proc,
            sp, ret, teb + 0x1400u)) goto done_process;
    if (!test_open_process(emulator, process, is_64, get_proc,
            sp, ret, teb + 0x1400u)) goto done_process;
    if (!test_memory_and_exception_imports(emulator, process,
            is_64, get_proc, sp, ret, teb + 0x1400u)) goto done_process;
    if (!test_thread_control(emulator, process, is_64, get_proc,
            sp, ret, teb + 0x1400u)) goto done_process;
    if (!test_file_time(emulator, process, path, is_64, get_proc,
            sp, ret, teb + 0x1200u)) goto done_process;
    if (!test_crt_startup(emulator, process, is_64, get_proc,
            sp, ret, teb + 0x1400u, path)) goto done_process;
    if (!test_crt_initterm(emulator, process, is_64, get_proc,
            sp, ret, teb + 0x1400u)) goto done_process;
    if (!test_crt_qsort(emulator, process, is_64, get_proc,
            sp, ret, teb + 0x1400u)) goto done_process;
    if (!test_crt_memory(emulator, process, is_64, get_proc,
            sp, ret, teb + 0x1400u)) goto done_process;
    if (!test_crt_strings(emulator, process, is_64, get_proc,
            sp, ret, teb + 0x1400u)) goto done_process;
    if (!test_crt_numbers(emulator, process, is_64, get_proc,
            sp, ret, teb + 0x1400u)) goto done_process;

    if (unpacked_path != NULL
        && !check(discover_imports(unpacked_path, emulator, process,
                is_64, get_proc, sp, ret, teb + 0x1700u),
            "unpacked PE import discovery failed")) goto done_process;

    arguments_for_call[0] = 9u;
    if (!check(lookup_crt_api(emulator, process, is_64, get_proc,
            sp, ret, teb + 0x1500u, "exit", &state, &crt_exit)
        && invoke_thunk(emulator, process, is_64,
            crt_exit, sp, ret, arguments_for_call,
            1u, &state, &status)
        && status == XXEMUL_STATUS_HALTED
        && xxemul_windows_exit_code(process) == 9u,
        "CRT exit status or exit code is wrong")) goto done_process;

    if (!check(read_integer(emulator, iat + (is_64 ? 8u : 4u),
            (uint8_t)(is_64 ? 8u : 4u), &target)
            == XXEMUL_STATUS_OK && target != 0
            && write_integer(emulator, sp,
                (uint8_t)(is_64 ? 8u : 4u), ret) == XXEMUL_STATUS_OK,
            "ExitProcess IAT entry missing")) goto done_process;
    if (is_64) state.gpr[XXEMUL_X86_RCX] = 7u;
    else if (!check(write_integer(emulator, sp + 4u,
            4u, 7u) == XXEMUL_STATUS_OK,
            "unable to write ExitProcess argument")) goto done_process;
    state.ip = target;
    state.gpr[XXEMUL_X86_RSP] = sp;
    if (!check(xxemul_set_x86_state(emulator, &state) == XXEMUL_STATUS_OK
            && xxemul_windows_try_step(process, &info, &status)
            && status == XXEMUL_STATUS_HALTED
            && xxemul_windows_exit_code(process) == 7u,
            "ExitProcess status or exit code is wrong"))
        goto done_process;
    ok = 1;
done_process:
    xxemul_windows_destroy(process);
done_emulator:
    xxemul_destroy(emulator);
    return ok;
}

static int probe_guest(const char *format_name, const char *path,
    const char *workdir, const char *output_name)
{
    xxemul_image_format format;
    xxemul *emulator;
    xxemul_x86_state state;
    xxemul_status status;
    uint64_t executed = 0u;
    const char *name;
    const char *const arguments[] = {
        path, "-o", output_name, "FASM.EXE"
    };
    if (strcmp(format_name, "pe32") == 0)
        format = XXEMUL_IMAGE_PE32;
    else if (strcmp(format_name, "pe64") == 0)
        format = XXEMUL_IMAGE_PE64;
    else return 2;
    emulator = xxemul_create_image_file(format, path, &status);
    if (emulator == NULL) return 2;
    status = xxemul_start_process(emulator, format, path, workdir,
        4, arguments);
    if (status == XXEMUL_STATUS_OK)
        status = xxemul_run(emulator, 35000000u, &executed);
    if (xxemul_get_x86_state(emulator, &state) != XXEMUL_STATUS_OK)
        state.ip = 0u;
    name = xxemul_windows_thunk_name(emulator, state.ip);
    printf("probe %s: %s after %llu instructions at 0x%llx",
        format_name, xxemul_status_string(status),
        (unsigned long long)executed,
        (unsigned long long)state.ip);
    if (name != NULL) printf(" API=%s", name);
    putchar('\n');
    xxemul_destroy(emulator);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc == 6 && strcmp(argv[1], "--probe") == 0)
        return probe_guest(argv[2], argv[3], argv[4], argv[5]);
    if (argc != 4 && argc != 6) {
        fprintf(stderr,
            "usage: %s UPX32.EXE UPX64.EXE WORKDIR "
            "[UNPACKED32.EXE UNPACKED64.EXE]\n", argv[0]);
        return 2;
    }
    if (!test_image(argv[1], argv[3], argc == 6 ? argv[4] : NULL, 0)
        || !test_image(argv[2], argv[3], argc == 6 ? argv[5] : NULL, 1))
        return 1;
    puts("Windows UPX PE bootstrap tests passed");
    return 0;
}
