#include "xxemul_windows.h"
#include "xxemul_internal.h"

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <io.h>
#include <windows.h>
#else
#include <utime.h>
#endif

#define WIN_RUNTIME_SIZE UINT64_C(0x20000)
#define WIN_THUNK_OFFSET UINT64_C(0x9000)
#define WIN_THUNK_STRIDE UINT64_C(16)
#define WIN_MAX_APIS 512u
#define WIN_MAX_HANDLES 64u
#define WIN_MAX_ALLOCATIONS 4096u
#define WIN_MAX_VECTORED_HANDLERS 64u
#define WIN_VECTORED_HANDLE_OFFSET UINT64_C(0x8200)
#define WIN_SHELL_MALLOC_OFFSET UINT64_C(0x8500)
#define WIN_TLS_ARRAY_OFFSET UINT64_C(0x8600)
#define WIN_TLS_DEFAULT_DATA_OFFSET UINT64_C(0x8680)
#define WIN_MAX_CRITICAL_SECTIONS 128u
#define WIN_MAX_TLS_SLOTS 128u
#define WIN_MAX_ONEXIT 256u
#define WIN_MAX_CRT_FDS 128u
#define WIN_ENV_MAX_BYTES 512u
#define WIN_ENV_MAX_ENTRIES 24u
#define WIN_MAX_IO (16u * 1024u * 1024u)
#define WIN_INVALID_HANDLE UINT64_MAX
#define WIN_CONSOLE_WIDTH 80
#define WIN_CONSOLE_HEIGHT 25
#define WIN_CRT_ARGV_OFFSET UINT64_C(0xb000)
#define WIN_CRT_ENVP_OFFSET UINT64_C(0xb800)
#define WIN_CRT_DATA_OFFSET UINT64_C(0xb900)
#define WIN_CRT_LOCALE_OFFSET UINT64_C(0xba00)
#define WIN_CRT_STRINGS_OFFSET UINT64_C(0xc000)
#define WIN_QSORT_RETURN_OFFSET UINT64_C(0x8fe0)
#define WIN_INITTERM_RETURN_OFFSET UINT64_C(0x8ff0)
#define WIN_MAX_INITTERM_DEPTH 8u
#define WIN_MAX_QSORT_DEPTH 8u
#define WIN_MAX_QSORT_ELEMENTS 65536u

typedef struct win_api {
    char module[48];
    char name[96];
    uint8_t argument_count;
    uint8_t caller_cleans;
} win_api;

typedef struct win_handle {
    xx_io_device *io;
    char name[128];
    char file_path[2048];
    uint32_t semaphore_count;
    uint32_t semaphore_max;
    uint32_t references;
    uint32_t flags;
    uint32_t file_access;
    uint16_t root_slot;
    uint8_t kind;
    uint8_t manual_reset;
    uint8_t signaled;
    uint8_t closed;
    uint8_t in_use;
} win_handle;

enum {
    WIN_HANDLE_FILE = 1,
    WIN_HANDLE_EVENT = 2,
    WIN_HANDLE_SEMAPHORE = 3,
    WIN_HANDLE_ALIAS = 4,
    WIN_HANDLE_PROCESS = 5,
    WIN_HANDLE_THREAD = 6
};

typedef struct win_allocation {
    uint64_t address;
    uint64_t size;
    uint64_t capacity;
    uint8_t active;
} win_allocation;

typedef struct win_vectored_handler {
    uint64_t callback;
    uint64_t handle;
    uint8_t first;
    uint8_t active;
} win_vectored_handler;

typedef struct win_critical_section {
    uint64_t address;
    uint32_t recursion;
    uint8_t active;
} win_critical_section;

typedef struct win_console_cell {
    uint8_t character;
    uint16_t attributes;
} win_console_cell;

typedef struct win_console_rect {
    int16_t left, top, right, bottom;
} win_console_rect;

typedef struct win_initterm_frame {
    uint64_t cursor;
    uint64_t end;
    uint64_t call_sp;
    uint64_t return_address;
} win_initterm_frame;

enum {
    WIN_QSORT_NEXT,
    WIN_QSORT_SIFT,
    WIN_QSORT_AFTER_LEFT,
    WIN_QSORT_AFTER_RIGHT,
    WIN_QSORT_CHECK
};

typedef struct win_qsort_frame {
    uint64_t base;
    uint64_t count;
    uint64_t size;
    uint64_t comparator;
    uint64_t call_sp;
    uint64_t return_address;
    uint64_t build_start;
    uint64_t heap_end;
    uint64_t root;
    uint64_t child;
    uint64_t candidate;
    uint8_t phase;
    uint8_t building;
} win_qsort_frame;

struct xxemul_windows {
    xxemul *emulator;
    uint64_t image_base;
    uint64_t image_size;
    uint64_t runtime_base;
    uint64_t heap_cursor;
    uint64_t heap_limit;
    uint64_t command_line_a;
    uint64_t command_line_w;
    uint64_t environment_a;
    char environment_data[WIN_ENV_MAX_BYTES];
    size_t environment_size;
    uint64_t iob_address;
    uint64_t argv_address;
    uint64_t envp_address;
    uint32_t argc;
    uint32_t app_type;
    uint64_t matherr_handler;
    uint32_t last_error;
    uint32_t exit_code;
    uint32_t virtual_tick;
    uint32_t random_state;
    int32_t thread_priority;
    uint64_t process_affinity;
    uint64_t unhandled_filter;
    uint64_t tls_values[WIN_MAX_TLS_SLOTS];
    uint32_t tls_count;
    uint64_t onexit_callbacks[WIN_MAX_ONEXIT];
    size_t onexit_count;
    uint64_t crt_fd_handles[WIN_MAX_CRT_FDS];
    uint16_t console_cursor_x;
    uint16_t console_cursor_y;
    uint16_t console_attributes;
    uint32_t console_input_mode;
    uint32_t console_output_mode;
    uint8_t console_cursor_size;
    uint8_t console_cursor_visible;
    win_console_cell console_cells[
        WIN_CONSOLE_WIDTH * WIN_CONSOLE_HEIGHT];
    char program_path[1024];
    char working_directory[1024];
    win_api apis[WIN_MAX_APIS];
    size_t api_count;
    win_handle handles[WIN_MAX_HANDLES];
    win_allocation allocations[WIN_MAX_ALLOCATIONS];
    size_t allocation_count;
    win_vectored_handler vectored_handlers[WIN_MAX_VECTORED_HANDLERS];
    size_t vectored_handler_count;
    win_critical_section critical_sections[WIN_MAX_CRITICAL_SECTIONS];
    win_initterm_frame initterm_frames[WIN_MAX_INITTERM_DEPTH];
    size_t initterm_depth;
    win_qsort_frame qsort_frames[WIN_MAX_QSORT_DEPTH];
    size_t qsort_depth;
    uint32_t resource_rva;
    uint32_t resource_size;
};

static uint16_t win_le16(const uint8_t *data)
{
    return (uint16_t)((uint16_t)data[0] | ((uint16_t)data[1] << 8));
}

static uint32_t win_le32(const uint8_t *data)
{
    return (uint32_t)data[0] | ((uint32_t)data[1] << 8)
        | ((uint32_t)data[2] << 16) | ((uint32_t)data[3] << 24);
}

static uint64_t win_le64(const uint8_t *data)
{
    return (uint64_t)win_le32(data) | ((uint64_t)win_le32(data + 4) << 32);
}

static void win_put32(uint8_t *data, uint32_t value)
{
    data[0] = (uint8_t)value;
    data[1] = (uint8_t)(value >> 8u);
    data[2] = (uint8_t)(value >> 16u);
    data[3] = (uint8_t)(value >> 24u);
}

static void win_put16(uint8_t *data, uint16_t value)
{
    data[0] = (uint8_t)value;
    data[1] = (uint8_t)(value >> 8u);
}

static void win_put64(uint8_t *data, uint64_t value)
{
    win_put32(data, (uint32_t)value);
    win_put32(data + 4u, (uint32_t)(value >> 32u));
}

static int win_copy(char *target, size_t capacity, const char *source)
{
    size_t length;
    if (source == NULL) return 0;
    length = strlen(source);
    if (length >= capacity) return 0;
    memcpy(target, source, length + 1);
    return 1;
}

static int win_equal(const char *left, const char *right)
{
    while (*left != '\0' && *right != '\0') {
        if (tolower((unsigned char)*left) != tolower((unsigned char)*right))
            return 0;
        ++left;
        ++right;
    }
    return *left == *right;
}

static int win_suffix(const char *text, const char *suffix)
{
    size_t a = strlen(text), b = strlen(suffix);
    return a >= b && win_equal(text + a - b, suffix);
}

static int win_prefix(const char *text, const char *prefix)
{
    while (*prefix != '\0') {
        if (*text == '\0' || tolower((unsigned char)*text) != tolower((unsigned char)*prefix))
            return 0;
        ++text;
        ++prefix;
    }
    return 1;
}

static int win_write(xxemul_windows *process, uint64_t address,
    const void *bytes, size_t count)
{
    return xxemul_write_memory(process->emulator, address, bytes, count)
        == XXEMUL_STATUS_OK;
}

static int win_read(xxemul_windows *process, uint64_t address,
    void *bytes, size_t count)
{
    return xxemul_read_memory(process->emulator, address, bytes, count)
        == XXEMUL_STATUS_OK;
}

static int win_store(xxemul_windows *process, uint64_t address,
    uint8_t size, uint64_t value)
{
    return xxemul_store_integer(process->emulator, address, size, value)
        == XXEMUL_STATUS_OK;
}

static int win_load(xxemul_windows *process, uint64_t address,
    uint8_t size, uint64_t *value)
{
    return xxemul_load_integer(process->emulator, address, size, value)
        == XXEMUL_STATUS_OK;
}

static int win_guest_string(xxemul_windows *process, uint64_t address,
    char *buffer, size_t capacity, int wide)
{
    size_t i;
    for (i = 0; i + 1 < capacity; ++i) {
        uint64_t ch;
        if (!win_load(process, address + i * (wide ? 2u : 1u),
                (uint8_t)(wide ? 2u : 1u), &ch)) return 0;
        if (ch == 0) {
            buffer[i] = '\0';
            return 1;
        }
        if (ch > 0x7f) return 0;
        buffer[i] = (char)ch;
    }
    return 0;
}

static int win_console_read_rect(xxemul_windows *process,
    uint64_t address, win_console_rect *rect)
{
    uint8_t bytes[8];
    if (!win_read(process, address, bytes, sizeof(bytes))) return 0;
    rect->left = (int16_t)win_le16(bytes);
    rect->top = (int16_t)win_le16(bytes + 2u);
    rect->right = (int16_t)win_le16(bytes + 4u);
    rect->bottom = (int16_t)win_le16(bytes + 6u);
    return 1;
}

static int win_console_write_rect(xxemul_windows *process,
    uint64_t address, const win_console_rect *rect)
{
    uint8_t bytes[8];
    win_put16(bytes, (uint16_t)rect->left);
    win_put16(bytes + 2u, (uint16_t)rect->top);
    win_put16(bytes + 4u, (uint16_t)rect->right);
    win_put16(bytes + 6u, (uint16_t)rect->bottom);
    return win_write(process, address, bytes, sizeof(bytes));
}

static int win_console_in_bounds(int x, int y)
{
    return x >= 0 && x < WIN_CONSOLE_WIDTH
        && y >= 0 && y < WIN_CONSOLE_HEIGHT;
}

static size_t win_console_index(int x, int y)
{
    return (size_t)y * WIN_CONSOLE_WIDTH + (size_t)x;
}

static int win_write_wide(xxemul_windows *process, uint64_t address,
    const char *text, size_t capacity)
{
    size_t i, count = strlen(text);
    if (count + 1 > capacity) return 0;
    for (i = 0; i <= count; ++i) {
        if (!win_store(process, address + i * 2u, 2u,
                (unsigned char)text[i])) return 0;
    }
    return 1;
}

static int win_environment_match(const char *entry, const char *name)
{
    const char *separator = strchr(entry, '=');
    size_t i, length;
    if (separator == NULL) return 0;
    length = (size_t)(separator - entry);
    if (length != strlen(name)) return 0;
    for (i = 0u; i < length; ++i) {
        if (tolower((unsigned char)entry[i])
            != tolower((unsigned char)name[i])) return 0;
    }
    return 1;
}

static int win_sync_environment(xxemul_windows *process)
{
    uint8_t word_size = process->emulator->mode == XXEMUL_MODE_X86_64
        ? 8u : 4u;
    size_t offset = 0u, index = 0u, i;
    if (!win_write(process, process->environment_a,
            process->environment_data, process->environment_size))
        return 0;
    for (i = 0u; i < process->environment_size; ++i) {
        if (!win_store(process, process->runtime_base + 0x7c00u
                + i * 2u, 2u,
                (uint8_t)process->environment_data[i])) return 0;
    }
    while (offset + 1u < process->environment_size
        && process->environment_data[offset] != '\0') {
        if (index >= WIN_ENV_MAX_ENTRIES
            || !win_store(process, process->envp_address
                + index * word_size, word_size,
                process->environment_a + offset)) return 0;
        ++index;
        offset += strlen(process->environment_data + offset) + 1u;
    }
    return win_store(process, process->envp_address
        + index * word_size, word_size, 0u);
}

static int win_append_quoted(char *buffer, size_t capacity,
    size_t *length, const char *arg)
{
    size_t i;
    int quoted = strchr(arg, ' ') != NULL || strchr(arg, '\t') != NULL;
    if (*length + 3 >= capacity) return 0;
    if (*length != 0) buffer[(*length)++] = ' ';
    if (quoted) buffer[(*length)++] = '"';
    for (i = 0; arg[i] != '\0'; ++i) {
        if (*length + 3 >= capacity) return 0;
        if (arg[i] == '"') buffer[(*length)++] = '\\';
        buffer[(*length)++] = arg[i];
    }
    if (quoted) buffer[(*length)++] = '"';
    buffer[*length] = '\0';
    return 1;
}

static uint64_t win_heap_alloc(xxemul_windows *process, uint64_t size)
{
    uint64_t result, rounded;
    win_allocation *free_slot = NULL;
    win_allocation *best = NULL;
    size_t index;
    if (size == 0) size = 1;
    if (size > UINT64_MAX - 15u) return 0;
    rounded = (size + 15u) & ~UINT64_C(15);
    for (index = 0u; index < process->allocation_count; ++index) {
        win_allocation *entry = &process->allocations[index];
        if (entry->active) continue;
        if (free_slot == NULL) free_slot = entry;
        if (entry->capacity >= rounded
            && (best == NULL || entry->capacity < best->capacity))
            best = entry;
    }
    if (best != NULL) {
        best->active = 1u;
        best->size = size;
        return best->address;
    }
    if (rounded > process->heap_limit - process->heap_cursor)
        return 0;
    if (free_slot == NULL) {
        if (process->allocation_count >= WIN_MAX_ALLOCATIONS) return 0;
        free_slot = &process->allocations[process->allocation_count++];
    }
    result = process->heap_cursor;
    process->heap_cursor += rounded;
    free_slot->address = result;
    free_slot->size = size;
    free_slot->capacity = rounded;
    free_slot->active = 1u;
    return result;
}

static win_allocation *win_find_allocation(xxemul_windows *process,
    uint64_t address)
{
    size_t i;
    for (i = process->allocation_count; i != 0; --i) {
        win_allocation *allocation = &process->allocations[i - 1u];
        if (allocation->active && allocation->address == address)
            return allocation;
    }
    return NULL;
}

static int win_image_rva(xxemul_windows *process, uint64_t rva,
    size_t size, const uint8_t **bytes)
{
    if (rva > process->image_size
        || size > process->image_size - rva) return 0;
    *bytes = process->emulator->region_data + (size_t)rva;
    return 1;
}

static int win_image_string(xxemul_windows *process, uint64_t rva,
    char *output, size_t capacity)
{
    const uint8_t *bytes;
    size_t i;
    if (!win_image_rva(process, rva, 1, &bytes)) return 0;
    for (i = 0; i + 1 < capacity && rva + i < process->image_size; ++i) {
        output[i] = (char)bytes[i];
        if (bytes[i] == 0) return 1;
    }
    return 0;
}

static int win_known_api(const char *name)
{
    static const char *const names[] = {
        "LoadLibraryA", "LoadLibraryW", "LoadLibraryExA", "GetProcAddress",
        "ExitProcess", "VirtualProtect", "VirtualAlloc", "VirtualFree",
        "GetLastError", "SetLastError", "GetCommandLineA", "GetCommandLineW",
        "GetModuleHandleA", "GetModuleHandleW", "GetModuleFileNameA",
        "GetModuleFileNameW", "GetStdHandle", "WriteFile", "ReadFile",
        "CreateFileA", "CreateFileW", "CloseHandle", "SetFilePointer",
        "SetFilePointerEx", "GetFileSize", "GetFileSizeEx", "GetFileType",
        "FlushFileBuffers", "GetProcessHeap", "HeapAlloc", "HeapFree",
        "HeapReAlloc", "HeapSize", "GetCurrentDirectoryA",
        "GetCurrentDirectoryW", "GetEnvironmentStringsA",
        "GetEnvironmentStringsW", "FreeEnvironmentStringsA",
        "FreeEnvironmentStringsW", "GetTickCount", "GetCurrentProcessId",
        "GetCurrentThreadId", "GetVersion", "GetACP", "GetOEMCP",
        "GetConsoleOutputCP", "SetConsoleMode", "GetConsoleMode",
        "GetStartupInfoA", "GetSystemInfo", "GetActiveProcessorGroupCount",
        "GetActiveProcessorCount", "QueryPerformanceCounter",
        "QueryPerformanceFrequency", "AddVectoredExceptionHandler",
        "RemoveVectoredExceptionHandler", "CreateEventA", "SetEvent",
        "ResetEvent", "WaitForSingleObject", "WaitForMultipleObjects",
        "CreateSemaphoreA", "ReleaseSemaphore",
        "DuplicateHandle", "GetCurrentProcess", "GetCurrentThread",
        "GetConsoleCursorInfo", "GetConsoleScreenBufferInfo",
        "SetConsoleCursorInfo", "SetConsoleCursorPosition",
        "SetConsoleTextAttribute", "WriteConsoleOutputA",
        "ReadConsoleOutputA", "ScrollConsoleScreenBufferA",
        "GetHandleInformation", "GetProcessAffinityMask",
        "SetProcessAffinityMask", "GetSystemTimeAsFileTime",
        "IsDebuggerPresent", "TlsAlloc", "TlsGetValue",
        "TlsSetValue", "OutputDebugStringA", "DebugBreak",
        "GetFileTime", "SetFileTime", "GetThreadPriority",
        "SetThreadPriority",
        "SetUnhandledExceptionFilter", "GetThreadContext",
        "IsDBCSLeadByte", "IsDBCSLeadByteEx", "MultiByteToWideChar",
        "SetDllDirectoryW", "SetDllDirectoryA",
        "AreFileApisANSI", "GetCPInfo",
        "WideCharToMultiByte", "OpenProcess", "RaiseException",
        "VirtualQuery", "ResumeThread", "SuspendThread",
        "SetThreadContext", "Sleep",
        "RtlCaptureContext", "RtlLookupFunctionEntry",
        "RtlUnwindEx", "RtlVirtualUnwind", "__C_specific_handler",
        "InitializeCriticalSection", "DeleteCriticalSection",
        "EnterCriticalSection", "LeaveCriticalSection",
        "TryEnterCriticalSection", "atoi", "_iob",
        "LoadLibraryExW", "GetModuleHandleExW", "GetModuleHandleExA",
        "GetStartupInfoW", "GetVersionExW",
        "InitializeCriticalSectionAndSpinCount", "InitializeCriticalSectionEx",
        "FlsAlloc", "FlsFree", "FlsGetValue", "FlsGetValue2", "FlsSetValue",
        "AcquireSRWLockExclusive", "ReleaseSRWLockExclusive",
        "AcquireSRWLockShared", "ReleaseSRWLockShared",
        "SleepConditionVariableSRW", "WakeAllConditionVariable", "WakeConditionVariable",
        "InitializeSListHead", "EncodePointer", "DecodePointer",
        "SetErrorMode", "SetPriorityClass", "SetThreadExecutionState",
        "GetDiskFreeSpaceExW", "GetDriveTypeW", "GetVolumeInformationW",
        "LCMapStringW", "GetStringTypeW", "IsValidCodePage",
        "CompareStringW", "FoldStringW", "FormatMessageW",
        "ExpandEnvironmentStringsW", "WriteConsoleW", "ReadConsoleW",
        "RtlPcToFileHeader", "FindFirstFileExW", "CreateHardLinkW",
        "BackupRead", "BackupSeek", "DeviceIoControl",
        "OpenProcessToken", "GetTokenInformation", "LookupPrivilegeValueW",
        "AdjustTokenPrivileges", "CheckTokenMembership",
        "AllocateAndInitializeSid", "FreeSid", "RegOpenKeyExW",
        "RegQueryValueExW", "RegCloseKey", "ConvertStringSidToSidW",
        "ConvertSidToStringSidW", "LsaOpenPolicy", "LsaClose",
        "LsaAddAccountRights", "CharLowerW", "ExitWindowsEx",
        "LoadStringW", "OemToCharBuffW", "CharToOemBuffW",
        "CharToOemBuffA", "CharToOemA", "OemToCharA",
        "SetSuspendState", "SHGetPathFromIDListW", "SHGetMalloc",
        "ShellExecuteExW", "SHFileOperationW", "SHGetSpecialFolderLocation",
        "CreateThread", "CreateSemaphoreW", "CreateEventW",
        "FileTimeToSystemTime", "SystemTimeToFileTime",
        "SystemTimeToTzSpecificLocalTime", "TzSpecificLocalTimeToSystemTime",
        "GetSystemTime", "GetLongPathNameW", "GetShortPathNameW"
    };
    size_t i;
    for (i = 0; i < sizeof(names) / sizeof(names[0]); ++i) {
        if (strcmp(name, names[i]) == 0) return 1;
    }
    return 0;
}

static int win_crt_api(const char *name)
{
    static const char *const names[] = {
        "atoi", "_iob", "__getmainargs", "__initenv",
        "__lconv_init", "__mb_cur_max", "__p__acmdln",
        "__p__commode", "__p__fmode", "__set_app_type",
        "_acmdln", "_commode", "_fmode", "__setusermatherr",
        "___lc_codepage_func", "___mb_cur_max_func", "__iob_func",
        "_amsg_exit", "_beginthreadex", "_cexit", "_endthreadex",
        "_errno", "_fstati64", "_fstat64", "_get_osfhandle",
        "_gmtime64", "_initterm", "_kbhit", "_localtime64",
        "_lock", "_lseeki64", "_onexit", "_setjmp3", "_setjmp",
        "_stat64", "_stati64", "_time64", "_ultoa", "_unlock",
        "_wopen", "abort", "calloc", "clock", "exit", "fflush",
        "fprintf", "fputc", "fputs", "free", "fwrite", "getc",
        "getenv", "islower", "isspace", "isupper", "isxdigit",
        "localeconv", "malloc", "memchr", "memcmp", "memcpy",
        "memmove", "memset", "localtime", "gmtime", "printf",
        "qsort", "rand", "realloc", "rename", "setlocale",
        "signal", "srand", "strchr", "strcmp", "strcpy",
        "strcspn", "strerror", "strlen", "strncmp", "strncpy",
        "strrchr", "strstr", "strtol", "strtoul", "tolower",
        "ungetc", "vfprintf", "time", "wcslen", "wcstombs",
        "longjmp", "_write", "_unlink", "_stricmp", "_strdup",
        "_sopen", "_setmode", "_rmdir", "_read", "_open",
        "_isatty", "_fileno", "_dup", "_close", "_chmod"
    };
    size_t index;
    for (index = 0u; index < sizeof(names) / sizeof(names[0]);
         ++index) {
        if (strcmp(name, names[index]) == 0) return 1;
    }
    return 0;
}

static uint8_t win_argument_count(const char *name)
{
    if (win_equal(name, "AllocateAndInitializeSid")) return 11u;
    if (win_equal(name, "CreateProcessA") || win_equal(name, "CreateProcessW")) return 10u;
    if (win_equal(name, "DeviceIoControl") || win_equal(name, "WideCharToMultiByte")
        || win_equal(name, "GetVolumeInformationW") || win_equal(name, "RtlVirtualUnwind")) return 8u;
    if (win_equal(name, "CreateFileA") || win_equal(name, "CreateFileW")
        || win_equal(name, "DuplicateHandle") || win_equal(name, "BackupRead")
        || win_equal(name, "FormatMessageW")) return 7u;
    if (win_equal(name, "MultiByteToWideChar")
        || win_equal(name, "CompareStringA") || win_equal(name, "CompareStringW")
        || win_equal(name, "CreateThread") || win_equal(name, "FindFirstFileExW")
        || win_equal(name, "GetDateFormatA") || win_equal(name, "GetDateFormatW")
        || win_equal(name, "PeekNamedPipe") || win_equal(name, "RegQueryValueExA")
        || win_equal(name, "RegQueryValueExW") || win_equal(name, "LCMapStringW")
        || win_equal(name, "BackupSeek") || win_equal(name, "AdjustTokenPrivileges")) return 6u;
    if (win_equal(name, "ReadFile") || win_equal(name, "WriteFile")
        || win_equal(name, "WriteConsoleOutputA") || win_equal(name, "ReadConsoleOutputA")
        || win_equal(name, "ScrollConsoleScreenBufferA") || win_equal(name, "__getmainargs")
        || win_equal(name, "CreateConsoleScreenBuffer") || win_equal(name, "EnumResourceLanguagesA")
        || win_equal(name, "ReadProcessMemory") || win_equal(name, "WriteConsoleOutputW")
        || win_equal(name, "VariantChangeTypeEx") || win_equal(name, "RegOpenKeyExA")
        || win_equal(name, "RegOpenKeyExW") || win_equal(name, "WriteConsoleW")
        || win_equal(name, "ReadConsoleW") || win_equal(name, "FoldStringW")
        || win_equal(name, "GetTokenInformation")) return 5u;
    if (win_equal(name, "VirtualProtect") || win_equal(name, "VirtualAlloc")
        || win_equal(name, "qsort") || win_equal(name, "CreateEventA")
        || win_equal(name, "CreateSemaphoreA") || win_equal(name, "RaiseException")
        || win_equal(name, "WaitForMultipleObjects") || win_equal(name, "GetFileTime")
        || win_equal(name, "SetFileTime") || win_equal(name, "HeapReAlloc")
        || win_equal(name, "SetFilePointer") || win_equal(name, "SetFilePointerEx")
        || win_equal(name, "_sopen") || win_equal(name, "_lseeki64")
        || win_equal(name, "CreatePipe") || win_equal(name, "EnumCalendarInfoA")
        || win_equal(name, "EnumResourceNamesA") || win_equal(name, "FindResourceExA")
        || win_equal(name, "GetFullPathNameW") || win_equal(name, "GetLocaleInfoA")
        || win_equal(name, "GetLocaleInfoW") || win_equal(name, "ReadConsoleInputA")
        || win_equal(name, "WriteConsoleInputA") || win_equal(name, "RtlUnwind")
        || win_equal(name, "MessageBoxA") || win_equal(name, "GetFileVersionInfoA")
        || win_equal(name, "SleepConditionVariableSRW") || win_equal(name, "GetDiskFreeSpaceExW")
        || win_equal(name, "GetStringTypeW") || win_equal(name, "LoadStringW")
        || win_equal(name, "LsaOpenPolicy") || win_equal(name, "CreateSemaphoreW")
        || win_equal(name, "CreateEventW") || win_equal(name, "RtlUnwindEx")
        || win_equal(name, "VerQueryValueA")) return 4u;
    if (win_equal(name, "GetModuleFileNameA") || win_equal(name, "GetModuleFileNameW")
        || win_equal(name, "VirtualFree") || win_equal(name, "HeapAlloc")
        || win_equal(name, "HeapFree") || win_equal(name, "HeapSize")
        || win_equal(name, "LoadLibraryExA") || win_equal(name, "LoadLibraryExW")
        || win_equal(name, "GetProcessAffinityMask")
        || win_equal(name, "GetModuleHandleExW") || win_equal(name, "GetModuleHandleExA")
        || win_equal(name, "InitializeCriticalSectionEx") || win_equal(name, "ExpandEnvironmentStringsW")
        || win_equal(name, "OpenProcessToken") || win_equal(name, "LookupPrivilegeValueW")
        || win_equal(name, "LookupPrivilegeValueA") || win_equal(name, "CheckTokenMembership")
        || win_equal(name, "OemToCharBuffW") || win_equal(name, "CharToOemBuffW")
        || win_equal(name, "CharToOemBuffA") || win_equal(name, "SetSuspendState")
        || win_equal(name, "SHGetSpecialFolderLocation") || win_equal(name, "LsaAddAccountRights")
        || win_equal(name, "CreateHardLinkW") || win_equal(name, "SystemTimeToTzSpecificLocalTime")
        || win_equal(name, "TzSpecificLocalTimeToSystemTime") || win_equal(name, "GetLongPathNameW")
        || win_equal(name, "VirtualQuery") || win_equal(name, "OpenProcess")
        || win_equal(name, "_open") || win_equal(name, "_read") || win_equal(name, "_write")
        || win_equal(name, "memchr") || win_equal(name, "memcmp")
        || win_equal(name, "memcpy") || win_equal(name, "memmove") || win_equal(name, "memset")
        || win_equal(name, "strtol") || win_equal(name, "strtoul")
        || win_equal(name, "strncmp") || win_equal(name, "strncpy")
        || win_equal(name, "ReleaseSemaphore")
        || win_equal(name, "SysReAllocStringLen") || win_equal(name, "SetConsoleWindowInfo")
        || win_equal(name, "EnumResourceTypesA") || win_equal(name, "FindResourceA")
        || win_equal(name, "FileTimeToDosDateTime") || win_equal(name, "DosDateTimeToFileTime")
        || win_equal(name, "GetShortPathNameA") || win_equal(name, "OpenThread")
        || win_equal(name, "SafeArrayCreate") || win_equal(name, "SafeArrayGetElement")
        || win_equal(name, "SafeArrayGetLBound") || win_equal(name, "SafeArrayGetUBound")
        || win_equal(name, "SafeArrayPtrOfIndex") || win_equal(name, "SafeArrayPutElement")
        || win_equal(name, "GetWindowTextA") || win_equal(name, "OemToCharBuffA")) return 3u;
    if (win_equal(name, "GetProcAddress") || win_equal(name, "AddVectoredExceptionHandler")
        || win_equal(name, "WaitForSingleObject") || win_equal(name, "GetCurrentDirectoryA")
        || win_equal(name, "GetCurrentDirectoryW") || win_equal(name, "GetFileSize")
        || win_equal(name, "GetFileSizeEx") || win_equal(name, "GetConsoleMode")
        || win_equal(name, "SetConsoleMode") || win_equal(name, "GetConsoleCursorInfo")
        || win_equal(name, "GetConsoleScreenBufferInfo") || win_equal(name, "SetConsoleCursorInfo")
        || win_equal(name, "SetConsoleCursorPosition") || win_equal(name, "SetConsoleTextAttribute")
        || win_equal(name, "GetHandleInformation") || win_equal(name, "SetProcessAffinityMask")
        || win_equal(name, "SetThreadPriority") || win_equal(name, "GetThreadContext")
        || win_equal(name, "SetThreadContext") || win_equal(name, "IsDBCSLeadByteEx")
        || win_equal(name, "_initterm") || win_equal(name, "setlocale")
        || win_equal(name, "calloc") || win_equal(name, "realloc")
        || win_equal(name, "strchr") || win_equal(name, "strrchr")
        || win_equal(name, "strstr") || win_equal(name, "strcspn")
        || win_equal(name, "strcmp") || win_equal(name, "_stricmp")
        || win_equal(name, "strcpy") || win_equal(name, "_stati64")
        || win_equal(name, "_stat64") || win_equal(name, "_fstati64")
        || win_equal(name, "_fstat64") || win_equal(name, "_chmod")
        || win_equal(name, "LocalAlloc") || win_equal(name, "GlobalAlloc")
        || win_equal(name, "SetConsoleCtrlHandler") || win_equal(name, "FindFirstFileA")
        || win_equal(name, "FindFirstFileW") || win_equal(name, "FindNextFileA")
        || win_equal(name, "FindNextFileW") || win_equal(name, "GetFileInformationByHandle")
        || win_equal(name, "SysAllocStringLen") || win_equal(name, "SetConsoleScreenBufferSize")
        || win_equal(name, "TlsSetValue") || win_equal(name, "FlsSetValue")
        || win_equal(name, "InitializeCriticalSectionAndSpinCount")
        || win_equal(name, "RtlPcToFileHeader") || win_equal(name, "SetPriorityClass")
        || win_equal(name, "SetFileAttributesW") || win_equal(name, "ConvertStringSidToSidW")
        || win_equal(name, "ConvertSidToStringSidW") || win_equal(name, "CharToOemA")
        || win_equal(name, "OemToCharA") || win_equal(name, "ExitWindowsEx")
        || win_equal(name, "SHGetPathFromIDListW") || win_equal(name, "FileTimeToSystemTime")
        || win_equal(name, "SystemTimeToFileTime")
        || win_equal(name, "CreateDirectoryW") || win_equal(name, "MoveFileW")
        || win_equal(name, "SetEnvironmentVariableW") || win_equal(name, "GetCPInfo")
        || win_equal(name, "GetExitCodeProcess") || win_equal(name, "GetWindowsDirectoryA")
        || win_equal(name, "GetSystemDirectoryW") || win_equal(name, "LocalFileTimeToFileTime")
        || win_equal(name, "FileTimeToLocalFileTime") || win_equal(name, "LoadResource")
        || win_equal(name, "SizeofResource") || win_equal(name, "SetStdHandle")
        || win_equal(name, "SleepEx") || win_equal(name, "TerminateProcess")
        || win_equal(name, "TerminateThread") || win_equal(name, "SafeArrayAccessData")
        || win_equal(name, "SafeArrayRedim") || win_equal(name, "VariantCopy")
        || win_equal(name, "CharLowerBuffA") || win_equal(name, "CharLowerBuffW")
        || win_equal(name, "CharUpperBuffA") || win_equal(name, "CharUpperBuffW")
        || win_equal(name, "EnumWindows") || win_equal(name, "GetWindowThreadProcessId")
        || win_equal(name, "SetClipboardData") || win_equal(name, "SetWindowTextA")
        || win_equal(name, "VkKeyScanExA") || win_equal(name, "GetFileVersionInfoSizeA")) return 2u;
    if (win_equal(name, "QueryPerformanceCounter") || win_equal(name, "QueryPerformanceFrequency")
        || win_equal(name, "LoadLibraryA") || win_equal(name, "LoadLibraryW")
        || win_equal(name, "ExitProcess") || win_equal(name, "exit")
        || win_equal(name, "GetModuleHandleA") || win_equal(name, "GetModuleHandleW")
        || win_equal(name, "GetStdHandle") || win_equal(name, "GetFileType")
        || win_equal(name, "FlushFileBuffers") || win_equal(name, "CloseHandle")
        || win_equal(name, "RemoveVectoredExceptionHandler") || win_equal(name, "InitializeCriticalSection")
        || win_equal(name, "DeleteCriticalSection") || win_equal(name, "EnterCriticalSection")
        || win_equal(name, "LeaveCriticalSection") || win_equal(name, "TryEnterCriticalSection")
        || win_equal(name, "GetSystemTimeAsFileTime") || win_equal(name, "GetThreadPriority")
        || win_equal(name, "SetUnhandledExceptionFilter") || win_equal(name, "TlsGetValue")
        || win_equal(name, "FlsGetValue") || win_equal(name, "FlsGetValue2") || win_equal(name, "FlsAlloc") || win_equal(name, "FlsFree")
        || win_equal(name, "AcquireSRWLockExclusive") || win_equal(name, "ReleaseSRWLockExclusive")
        || win_equal(name, "AcquireSRWLockShared") || win_equal(name, "ReleaseSRWLockShared")
        || win_equal(name, "WakeAllConditionVariable") || win_equal(name, "WakeConditionVariable")
        || win_equal(name, "InitializeSListHead") || win_equal(name, "EncodePointer")
        || win_equal(name, "DecodePointer") || win_equal(name, "SetErrorMode")
        || win_equal(name, "SetThreadExecutionState") || win_equal(name, "GetDriveTypeW")
        || win_equal(name, "GetDriveTypeA") || win_equal(name, "IsValidCodePage")
        || win_equal(name, "FreeSid") || win_equal(name, "CharLowerW")
        || win_equal(name, "SHGetMalloc") || win_equal(name, "ShellExecuteExW")
        || win_equal(name, "SHFileOperationW") || win_equal(name, "LsaClose")
        || win_equal(name, "GetStartupInfoW") || win_equal(name, "GetVersionExW")
        || win_equal(name, "GetSystemTime") || win_equal(name, "GetShortPathNameW")
        || win_equal(name, "IsDBCSLeadByte") || win_equal(name, "SetDllDirectoryW")
        || win_equal(name, "SetDllDirectoryA")
        || win_equal(name, "AreFileApisANSI") || win_equal(name, "GetCPInfo")
        || win_equal(name, "OutputDebugStringA") || win_equal(name, "SetEvent")
        || win_equal(name, "ResetEvent") || win_equal(name, "SetLastError")
        || win_equal(name, "GetStartupInfoA") || win_equal(name, "GetSystemInfo")
        || win_equal(name, "GetActiveProcessorGroupCount") || win_equal(name, "GetActiveProcessorCount")
        || win_equal(name, "ResumeThread") || win_equal(name, "SuspendThread")
        || win_equal(name, "Sleep") || win_equal(name, "__set_app_type")
        || win_equal(name, "__setusermatherr") || win_equal(name, "malloc")
        || win_equal(name, "free") || win_equal(name, "strlen")
        || win_equal(name, "wcslen") || win_equal(name, "_strdup")
        || win_equal(name, "_onexit") || win_equal(name, "_time64")
        || win_equal(name, "time") || win_equal(name, "srand")
        || win_equal(name, "_get_osfhandle") || win_equal(name, "_isatty")
        || win_equal(name, "_fileno") || win_equal(name, "_close")
        || win_equal(name, "_unlink") || win_equal(name, "fflush")
        || win_equal(name, "getenv") || win_equal(name, "tolower")
        || win_equal(name, "islower") || win_equal(name, "isspace")
        || win_equal(name, "isupper") || win_equal(name, "isxdigit")
        || win_equal(name, "LocalFree") || win_equal(name, "GlobalFree")
        || win_equal(name, "GlobalLock") || win_equal(name, "GlobalUnlock")
        || win_equal(name, "TlsFree") || win_equal(name, "IsProcessorFeaturePresent")
        || win_equal(name, "CharUpperW") || win_equal(name, "GetFileAttributesA")
        || win_equal(name, "GetFileAttributesW") || win_equal(name, "FindClose")
        || win_equal(name, "SetEndOfFile") || win_equal(name, "SysFreeString")
        || win_equal(name, "GetVersionExA") || win_equal(name, "SetThreadLocale")
        || win_equal(name, "SetConsoleCP") || win_equal(name, "SetConsoleActiveScreenBuffer")
        || win_equal(name, "FlushConsoleInputBuffer") || win_equal(name, "GetNumberOfConsoleMouseButtons")
        || win_equal(name, "GetLocalTime") || win_equal(name, "FreeLibrary")
        || win_equal(name, "DeleteFileW") || win_equal(name, "ExitThread")
        || win_equal(name, "FreeEnvironmentStringsA") || win_equal(name, "FreeResource")
        || win_equal(name, "LockResource") || win_equal(name, "RemoveDirectoryW")
        || win_equal(name, "SetCurrentDirectoryW") || win_equal(name, "RegCloseKey")
        || win_equal(name, "CoTaskMemFree") || win_equal(name, "SafeArrayUnaccessData")
        || win_equal(name, "VariantClear") || win_equal(name, "VariantInit")
        || win_equal(name, "CharLowerA") || win_equal(name, "CharUpperA")
        || win_equal(name, "GetClipboardData") || win_equal(name, "GetKeyboardLayout")
        || win_equal(name, "GetSystemMetrics") || win_equal(name, "MessageBeep")
        || win_equal(name, "OpenClipboard")
        || win_equal(name, "GetActiveProcessorCount")
        || win_equal(name, "atoi")) return 1u;
    return 0u;
}

static uint64_t win_resolve(xxemul_windows *process,
    const char *module, const char *name)
{
    size_t i;
    win_api *api;
    uint64_t address;
    int is_crt = win_crt_api(name) || win_suffix(module, "msvcrt.dll")
        || win_suffix(module, "ucrtbase.dll");
    if (win_equal(name, "_iob")) return process->iob_address;
    if (win_equal(name, "__initenv"))
        return process->runtime_base + WIN_CRT_DATA_OFFSET;
    if (win_equal(name, "__mb_cur_max"))
        return process->runtime_base + WIN_CRT_DATA_OFFSET + 8u;
    if (win_equal(name, "_acmdln"))
        return process->runtime_base + WIN_CRT_DATA_OFFSET + 16u;
    if (win_equal(name, "_commode"))
        return process->runtime_base + WIN_CRT_DATA_OFFSET + 24u;
    if (win_equal(name, "_fmode"))
        return process->runtime_base + WIN_CRT_DATA_OFFSET + 28u;
    for (i = 0; i < process->api_count; ++i) {
        if (win_equal(process->apis[i].module, module)
            && strcmp(process->apis[i].name, name) == 0)
            return process->runtime_base + WIN_THUNK_OFFSET
                + i * WIN_THUNK_STRIDE;
    }
    if (process->api_count >= WIN_MAX_APIS) return 0;
    api = &process->apis[process->api_count];
    if (!win_copy(api->module, sizeof(api->module), module)
        || !win_copy(api->name, sizeof(api->name), name)) return 0;
    api->argument_count = win_argument_count(name);
    if (process->emulator->mode == XXEMUL_MODE_X86_32
        && strcmp(name, "SetFilePointerEx") == 0)
        api->argument_count = 5u;
    if (process->emulator->mode == XXEMUL_MODE_X86_64
        && strcmp(name, "_lseeki64") == 0)
        api->argument_count = 3u;
    api->caller_cleans = (uint8_t)is_crt;
    address = process->runtime_base + WIN_THUNK_OFFSET
        + process->api_count * WIN_THUNK_STRIDE;
    if (!win_store(process, address, 1u, 0xccu)) return 0;
    ++process->api_count;
    return address;
}

static const char *win_oleaut32_ordinal_name(uint16_t ordinal)
{
    switch (ordinal) {
    case 2: return "SysAllocString";
    case 4: return "SysAllocStringLen";
    case 6: return "SysFreeString";
    case 7: return "SysStringLen";
    case 8: return "VariantInit";
    case 9: return "VariantClear";
    case 10: return "VariantCopy";
    case 149: return "SysStringByteLen";
    default: return NULL;
    }
}

static int win_bind_imports(xxemul_windows *process, const uint8_t *optional,
    size_t optional_size, int is_64)
{
    uint32_t import_rva, import_size;
    size_t directory_offset = is_64 ? 112u : 96u;
    uint8_t pointer_size = (uint8_t)(is_64 ? 8u : 4u);
    size_t descriptor_index;
    const uint8_t *descriptor;

    if (optional_size < directory_offset + 16u) return 0;
    import_rva = win_le32(optional + directory_offset + 8u);
    import_size = win_le32(optional + directory_offset + 12u);
    if (import_rva == 0u) return 1;
    if (import_size < 20u || import_size > process->image_size
        || !win_image_rva(process, import_rva, import_size, &descriptor)) return 0;
    for (descriptor_index = 0; descriptor_index + 20u <= import_size;
         descriptor_index += 20u) {
        const uint8_t *entry = descriptor + descriptor_index;
        uint32_t lookup_rva = win_le32(entry);
        uint32_t module_rva = win_le32(entry + 12u);
        uint32_t iat_rva = win_le32(entry + 16u);
        char module[48];
        size_t symbol_index;
        if (lookup_rva == 0 && module_rva == 0 && iat_rva == 0) return 1;
        if (module_rva == 0 || iat_rva == 0
            || !win_image_string(process, module_rva,
                module, sizeof(module))) return 0;
        if (lookup_rva == 0) lookup_rva = iat_rva;
        for (symbol_index = 0; symbol_index < 4096u; ++symbol_index) {
            uint64_t raw, slot_rva, source_rva, address;
            const uint8_t *slot;
            char name[96];
            source_rva = (uint64_t)lookup_rva + symbol_index * pointer_size;
            slot_rva = (uint64_t)iat_rva + symbol_index * pointer_size;
            if (!win_image_rva(process, source_rva, pointer_size, &slot)
                || !win_image_rva(process, slot_rva, pointer_size, &slot)) return 0;
            slot = process->emulator->region_data + (size_t)source_rva;
            raw = is_64 ? win_le64(slot) : win_le32(slot);
            if (raw == 0) break;
            if (raw & (is_64 ? UINT64_C(0x8000000000000000)
                             : UINT64_C(0x80000000))) {
                uint16_t ordinal = (uint16_t)(raw & 0xffffu);
                const char *ord_name = NULL;
                if (win_suffix(module, "oleaut32.dll")) {
                    ord_name = win_oleaut32_ordinal_name(ordinal);
                }
                if (ord_name != NULL) {
                    snprintf(name, sizeof(name), "%s", ord_name);
                } else {
                    snprintf(name, sizeof(name), "#%u", ordinal);
                }
            } else {
                if (raw > UINT32_MAX || !win_image_string(process,
                        raw + 2u, name, sizeof(name))) return 0;
            }
            address = win_resolve(process, module, name);
            if (address == 0 || !win_store(process,
                    process->image_base + slot_rva,
                    pointer_size, address)) return 0;
        }
        if (symbol_index == 4096u) return 0;
    }
    return 1;
}

static int win_bind_tls(xxemul_windows *process, const uint8_t *optional,
    size_t optional_size, int is_64)
{
    size_t directory_offset = is_64 ? 112u : 96u;
    uint8_t pointer_size = (uint8_t)(is_64 ? 8u : 4u);
    uint32_t tls_rva = 0, tls_size = 0;
    uint64_t tls_array = process->runtime_base + WIN_TLS_ARRAY_OFFSET;
    uint64_t default_data = process->runtime_base + WIN_TLS_DEFAULT_DATA_OFFSET;
    uint64_t target_tls_data = default_data;

    win_store(process, default_data, pointer_size, 0);
    win_store(process, tls_array, pointer_size, default_data);

    if (is_64) {
        win_store(process, process->runtime_base + 0x58u, 8u, tls_array);
    } else {
        win_store(process, process->runtime_base + 0x2cu, 4u, tls_array);
    }

    if (optional_size >= directory_offset + 80u) {
        tls_rva = win_le32(optional + directory_offset + 72u);
        tls_size = win_le32(optional + directory_offset + 76u);
    }

    if (tls_rva != 0 && tls_size >= (is_64 ? 40u : 24u)) {
        const uint8_t *dir;
        if (win_image_rva(process, tls_rva, tls_size, &dir)) {
            uint64_t start_raw = is_64 ? win_le64(dir) : win_le32(dir);
            uint64_t end_raw = is_64 ? win_le64(dir + 8u) : win_le32(dir + 4u);
            uint64_t addr_index = is_64 ? win_le64(dir + 16u) : win_le32(dir + 8u);
            uint32_t zero_fill = win_le32(dir + (is_64 ? 32u : 16u));
            uint64_t raw_size = (end_raw > start_raw) ? (end_raw - start_raw) : 0u;
            uint64_t total_size = raw_size + zero_fill;

            if (addr_index != 0) {
                win_store(process, addr_index, 4u, 0);
            }

            if (total_size > 0) {
                target_tls_data = win_heap_alloc(process, total_size > 16u ? total_size : 16u);
                if (target_tls_data != 0) {
                    if (raw_size > 0) {
                        uint8_t temp[1024];
                        uint64_t copied = 0;
                        while (copied < raw_size) {
                            size_t chunk = (size_t)(raw_size - copied);
                            if (chunk > sizeof(temp)) chunk = sizeof(temp);
                            if (win_read(process, start_raw + copied, temp, chunk)) {
                                win_write(process, target_tls_data + copied, temp, chunk);
                            }
                            copied += chunk;
                        }
                    }
                    win_store(process, tls_array, pointer_size, target_tls_data);
                }
            } else if (start_raw != 0) {
                win_store(process, tls_array, pointer_size, start_raw);
            }
        }
    }
    return 1;
}

static int win_prepare_runtime(xxemul_windows *process,
    const char *const *arguments, size_t argument_count)
{
    xxemul *emulator = process->emulator;
    uint64_t peb = process->runtime_base + 0x2000u;
    uint64_t params = process->runtime_base + 0x4000u;
    uint64_t stack_top = process->runtime_base
        - (emulator->mode == XXEMUL_MODE_X86_64 ? 8u : 4u);
    uint8_t word_size = (uint8_t)(emulator->mode == XXEMUL_MODE_X86_64 ? 8u : 4u);
    char command_line[2048];
    uint64_t string_cursor;
    size_t i, length = 0;

    command_line[0] = '\0';
    if (!win_append_quoted(command_line, sizeof(command_line),
            &length, process->program_path)) return 0;
    for (i = 0; i < argument_count; ++i) {
        if (arguments == NULL || arguments[i] == NULL
            || !win_append_quoted(command_line, sizeof(command_line),
                &length, arguments[i])) return 0;
    }
    process->command_line_a = process->runtime_base + 0x6000u;
    process->command_line_w = process->runtime_base + 0x6800u;
    process->environment_a = process->runtime_base + 0x7800u;
    process->iob_address = process->runtime_base + 0x8000u;
    process->argv_address = process->runtime_base + WIN_CRT_ARGV_OFFSET;
    process->envp_address = process->runtime_base + WIN_CRT_ENVP_OFFSET;
    memcpy(process->environment_data, "PATH=.\0", 8u);
    process->environment_size = 8u;
    if (argument_count >= 0x800u / word_size - 1u) return 0;
    process->argc = (uint32_t)(argument_count + 1u);
    if (!win_write(process, process->command_line_a, command_line, length + 1u)
        || !win_write_wide(process, process->command_line_w,
            command_line, 2048u)
        || !win_sync_environment(process)
        || !win_store(process, stack_top, word_size, 0)) return 0;
    string_cursor = process->runtime_base + WIN_CRT_STRINGS_OFFSET;
    for (i = 0u; i < process->argc; ++i) {
        const char *argument = i == 0u
            ? process->program_path : arguments[i - 1u];
        size_t bytes = strlen(argument) + 1u;
        if (bytes > process->runtime_base + 0x1f000u - string_cursor
            || !win_write(process, string_cursor, argument, bytes)
            || !win_store(process, process->argv_address
                + i * word_size, word_size, string_cursor)) return 0;
        string_cursor += bytes;
    }
    if (!win_store(process, process->argv_address
            + process->argc * word_size, word_size, 0u)
        || !win_store(process, process->runtime_base
            + WIN_CRT_DATA_OFFSET, word_size, process->envp_address)
        || !win_store(process, process->runtime_base
            + WIN_CRT_DATA_OFFSET + 8u, 4u, 1u)
        || !win_store(process, process->runtime_base
            + WIN_CRT_DATA_OFFSET + 16u, word_size,
            process->command_line_a)
        || !win_store(process, process->runtime_base
            + WIN_CRT_DATA_OFFSET + 28u, 4u, 0x4000u)
        || !win_write(process, process->runtime_base + 0xbb00u,
            ".\0\0C\0", 5u)) return 0;
    for (i = 0u; i < 10u; ++i) {
        if (!win_store(process, process->runtime_base
                + WIN_CRT_LOCALE_OFFSET + i * word_size, word_size,
                process->runtime_base + (i == 0u
                    ? 0xbb00u : 0xbb02u))) return 0;
    }
    for (i = 0u; i < 8u; ++i) {
        if (!win_store(process, process->runtime_base
                + WIN_CRT_LOCALE_OFFSET + 10u * word_size + i,
                1u, 0xffu)) return 0;
    }

    win_store(process, process->runtime_base + WIN_TLS_DEFAULT_DATA_OFFSET, word_size, 0);
    win_store(process, process->runtime_base + WIN_TLS_ARRAY_OFFSET, word_size,
        process->runtime_base + WIN_TLS_DEFAULT_DATA_OFFSET);

    if (word_size == 4u) {
        if (!win_store(process, process->runtime_base + 0x04u, 4u,
                process->runtime_base)
            || !win_store(process, process->runtime_base + 0x08u, 4u,
                process->runtime_base - 0x40000u)
            || !win_store(process, process->runtime_base + 0x18u, 4u,
                process->runtime_base)
            || !win_store(process, process->runtime_base + 0x2cu, 4u,
                process->runtime_base + WIN_TLS_ARRAY_OFFSET)
            || !win_store(process, process->runtime_base + 0x30u, 4u, peb)
            || !win_store(process, peb + 0x08u, 4u, process->image_base)
            || !win_store(process, peb + 0x10u, 4u, params)
            || !win_store(process, params + 0x40u, 2u, length * 2u)
            || !win_store(process, params + 0x42u, 2u,
                (length + 1u) * 2u)
            || !win_store(process, params + 0x44u, 4u,
                process->command_line_w)) return 0;
        emulator->x86.segment[XXEMUL_X86_FS] = 0x53u;
    } else {
        if (!win_store(process, process->runtime_base + 0x08u, 8u,
                process->runtime_base)
            || !win_store(process, process->runtime_base + 0x10u, 8u,
                process->runtime_base - 0x40000u)
            || !win_store(process, process->runtime_base + 0x30u, 8u,
                process->runtime_base)
            || !win_store(process, process->runtime_base + 0x58u, 8u,
                process->runtime_base + WIN_TLS_ARRAY_OFFSET)
            || !win_store(process, process->runtime_base + 0x60u, 8u, peb)
            || !win_store(process, peb + 0x10u, 8u, process->image_base)
            || !win_store(process, peb + 0x20u, 8u, params)
            || !win_store(process, params + 0x70u, 2u, length * 2u)
            || !win_store(process, params + 0x72u, 2u,
                (length + 1u) * 2u)
            || !win_store(process, params + 0x78u, 8u,
                process->command_line_w)) return 0;
        emulator->x86.segment[XXEMUL_X86_GS] = 0x2bu;
    }
    emulator->x86.gpr[XXEMUL_X86_RSP] = stack_top;
    return 1;
}

xxemul_windows *xxemul_windows_create(
    xxemul *emulator, const char *program_path,
    const char *working_directory, const char *const *arguments,
    size_t argument_count, xxemul_status *status)
{
    xxemul_windows *process;
    const uint8_t *bytes, *optional;
    size_t pe_offset, optional_offset, optional_size;
    uint16_t magic;
    uint32_t image_size;
    int is_64;

    if (status != NULL) *status = XXEMUL_STATUS_INVALID_ARGUMENT;
    if (emulator == NULL || program_path == NULL
        || working_directory == NULL || emulator->arch != XXEMUL_ARCH_X86
        || (emulator->mode != XXEMUL_MODE_X86_32
            && emulator->mode != XXEMUL_MODE_X86_64)
        || emulator->region_size < WIN_RUNTIME_SIZE + 0x80000u
        || (argument_count != 0u && arguments == NULL)) return NULL;
    bytes = emulator->region_data;
    if (bytes[0] != 'M' || bytes[1] != 'Z') return NULL;
    pe_offset = win_le32(bytes + 0x3cu);
    if (pe_offset > emulator->region_size
        || 24u > emulator->region_size - pe_offset
        || memcmp(bytes + pe_offset, "PE\0\0", 4) != 0) return NULL;
    optional_offset = pe_offset + 24u;
    optional_size = win_le16(bytes + pe_offset + 20u);
    if (optional_size < 64u || optional_size > emulator->region_size
        || optional_offset > emulator->region_size - optional_size) return NULL;
    optional = bytes + optional_offset;
    magic = win_le16(optional);
    is_64 = emulator->mode == XXEMUL_MODE_X86_64;
    if (magic != (is_64 ? 0x20bu : 0x10bu)) return NULL;
    image_size = win_le32(optional + 56u);
    if (image_size == 0u || image_size > emulator->region_size
        || image_size + WIN_RUNTIME_SIZE + 0x80000u > emulator->region_size)
        return NULL;

    process = (xxemul_windows *)calloc(1, sizeof(*process));
    if (process == NULL) {
        if (status != NULL) *status = XXEMUL_STATUS_OUT_OF_MEMORY;
        return NULL;
    }
    process->emulator = emulator;
    process->image_base = emulator->region_address;
    process->virtual_tick = 1000u;
    process->random_state = 1u;
    process->image_size = image_size;
    {
        size_t dir_off = is_64 ? 112u : 96u;
        if (optional_size >= dir_off + 24u) {
            process->resource_rva = win_le32(optional + dir_off + 16u);
            process->resource_size = win_le32(optional + dir_off + 20u);
        }
    }
    process->runtime_base = emulator->region_address
        + emulator->region_size - WIN_RUNTIME_SIZE;
    process->heap_cursor = (emulator->region_address + image_size + 15u)
        & ~UINT64_C(15);
    process->heap_limit = process->runtime_base - 0x40000u;
    process->console_attributes = 7u;
    process->process_affinity = 1u;
    process->console_input_mode = 7u;
    process->console_output_mode = 3u;
    process->console_cursor_size = 25u;
    process->console_cursor_visible = 1u;
    {
        size_t index;
        for (index = 0u; index < WIN_CONSOLE_WIDTH * WIN_CONSOLE_HEIGHT;
             ++index) {
            process->console_cells[index].character = ' ';
            process->console_cells[index].attributes = 7u;
        }
    }
    if (!win_copy(process->program_path, sizeof(process->program_path),
            program_path)
        || !win_copy(process->working_directory,
            sizeof(process->working_directory), working_directory)
        || process->heap_cursor >= process->heap_limit
        || !win_prepare_runtime(process, arguments, argument_count)
        || !win_bind_imports(process, optional, optional_size, is_64)
        || !win_bind_tls(process, optional, optional_size, is_64)) {
        free(process);
        if (status != NULL) *status = XXEMUL_STATUS_INVALID_IMAGE;
        return NULL;
    }
    if (status != NULL) *status = XXEMUL_STATUS_OK;
    return process;
}

xxemul_status xxemul_windows_set_environment(
    xxemul_windows *process, const char *name, const char *value)
{
    char updated[WIN_ENV_MAX_BYTES];
    size_t name_length, value_length, assignment_size;
    size_t offset = 0u, used = 0u, count = 0u;
    int replaced = 0;

    if (process == NULL || name == NULL || name[0] == '\0'
        || strchr(name, '=') != NULL || value == NULL)
        return XXEMUL_STATUS_INVALID_ARGUMENT;
    name_length = strlen(name);
    value_length = strlen(value);
    if (name_length >= WIN_ENV_MAX_BYTES
        || value_length >= WIN_ENV_MAX_BYTES
        || name_length + value_length + 3u > WIN_ENV_MAX_BYTES)
        return XXEMUL_STATUS_OUT_OF_MEMORY;
    assignment_size = name_length + value_length + 2u;
    while (offset + 1u < process->environment_size
        && process->environment_data[offset] != '\0') {
        const char *entry = process->environment_data + offset;
        int replace = win_environment_match(entry, name);
        size_t entry_size = strlen(entry) + 1u;
        size_t copy_size = replace ? assignment_size : entry_size;
        if (used + copy_size + 1u > sizeof(updated)
            || count >= WIN_ENV_MAX_ENTRIES)
            return XXEMUL_STATUS_OUT_OF_MEMORY;
        if (replace) {
            memcpy(updated + used, name, name_length);
            updated[used + name_length] = '=';
            memcpy(updated + used + name_length + 1u,
                value, value_length + 1u);
            replaced = 1;
        } else {
            memcpy(updated + used, entry, entry_size);
        }
        used += copy_size;
        offset += entry_size;
        ++count;
    }
    if (!replaced) {
        if (used + assignment_size + 1u > sizeof(updated)
            || count >= WIN_ENV_MAX_ENTRIES)
            return XXEMUL_STATUS_OUT_OF_MEMORY;
        memcpy(updated + used, name, name_length);
        updated[used + name_length] = '=';
        memcpy(updated + used + name_length + 1u,
            value, value_length + 1u);
        used += assignment_size;
    }
    updated[used++] = '\0';
    memcpy(process->environment_data, updated, used);
    process->environment_size = used;
    return win_sync_environment(process) ? XXEMUL_STATUS_OK
        : XXEMUL_STATUS_ADDRESS_FAULT;
}

void xxemul_windows_destroy(xxemul_windows *process)
{
    size_t i;
    if (process == NULL) return;
    for (i = 0; i < WIN_MAX_HANDLES; ++i) {
        if (process->handles[i].in_use
            && process->handles[i].io != NULL)
            xx_io_close(process->handles[i].io);
    }
    free(process);
}

uint64_t xxemul_windows_segment_base(
    const xxemul_windows *process, uint8_t segment_index)
{
    if (process == NULL) return 0;
    if ((process->emulator->mode == XXEMUL_MODE_X86_32
            && segment_index == XXEMUL_X86_FS)
        || (process->emulator->mode == XXEMUL_MODE_X86_64
            && segment_index == XXEMUL_X86_GS)) return process->runtime_base;
    return 0;
}

uint32_t xxemul_windows_exit_code(const xxemul_windows *process)
{
    return process == NULL ? 0u : process->exit_code;
}

const char *xxemul_windows_thunk_name(
    const xxemul *emulator, uint64_t address)
{
    const xxemul_windows *process;
    uint64_t offset, index;
    if (emulator == NULL || emulator->windows == NULL) return NULL;
    process = emulator->windows;
    if (address < process->runtime_base + WIN_THUNK_OFFSET) return NULL;
    offset = address - process->runtime_base - WIN_THUNK_OFFSET;
    if (offset % WIN_THUNK_STRIDE != 0u) return NULL;
    index = offset / WIN_THUNK_STRIDE;
    return index < process->api_count ? process->apis[index].name : NULL;
}

static uint64_t win_module_handle(xxemul_windows *process, const char *name)
{
    char base[260];
    const char *dot;
    if (name == NULL || *name == '\0') return process->image_base;
    if (win_copy(base, sizeof(base), name)) {
        dot = strrchr(base, '.');
        if (dot == NULL && strlen(base) + 4 < sizeof(base)) {
            memcpy(base + strlen(base), ".dll", 5);
        }
    } else {
        win_copy(base, sizeof(base), name);
    }
    if (win_suffix(base, "kernel32.dll")
        || win_suffix(base, "kernelbase.dll")
        || win_prefix(base, "api-ms-win-core-")) return 0x76000000u;
    if (win_suffix(base, "msvcrt.dll")
        || win_suffix(base, "ucrtbase.dll")
        || win_prefix(base, "api-ms-win-crt-")) return 0x77000000u;
    if (win_suffix(base, "ntdll.dll")) return 0x78000000u;
    if (win_suffix(base, "user32.dll")) return 0x79000000u;
    if (win_suffix(base, "advapi32.dll")) return 0x7a000000u;
    if (win_suffix(base, "shell32.dll")) return 0x7b000000u;
    if (win_suffix(base, "powrprof.dll")) return 0x7c000000u;
    return 0;
}

static const char *win_module_name(uint64_t handle)
{
    switch (handle) {
    case 0x76000000u: return "kernel32.dll";
    case 0x77000000u: return "msvcrt.dll";
    case 0x78000000u: return "ntdll.dll";
    case 0x79000000u: return "user32.dll";
    case 0x7a000000u: return "advapi32.dll";
    case 0x7b000000u: return "shell32.dll";
    case 0x7c000000u: return "powrprof.dll";
    default: return NULL;
    }
}

static int win_guest_path(xxemul_windows *process, const char *guest,
    char *host, size_t capacity)
{
    char relative[1024];
    char program[1024];
    size_t i, j = 0, base_length;
    if (guest == NULL || *guest == '\0') return 0;
    if (!win_copy(program, sizeof(program), process->program_path)) return 0;
    for (i = 0; program[i] != '\0'; ++i) {
        if (program[i] == '\\') program[i] = '/';
    }
    for (i = 0; guest[i] != '\0'; ++i) {
        char ch = guest[i] == '\\' ? '/' : guest[i];
        if (j + 1 >= sizeof(relative)) return 0;
        relative[j++] = ch;
    }
    relative[j] = '\0';
    if (win_equal(relative, program))
        return win_copy(host, capacity, process->program_path);
    if (relative[0] == '/' || strchr(relative, ':') != NULL) return 0;
    i = 0;
    while (i < j) {
        size_t component_start = i;
        while (i < j && relative[i] != '/') ++i;
        if (i - component_start == 2
            && relative[component_start] == '.'
            && relative[component_start + 1] == '.') return 0;
        if (i < j) ++i;
    }
    base_length = strlen(process->working_directory);
    if (base_length == 0 || base_length + 1u + j >= capacity) return 0;
    memcpy(host, process->working_directory, base_length);
    host[base_length++] = '/';
    memcpy(host + base_length, relative, j + 1u);
    return 1;
}

static uint64_t win_file_open(xxemul_windows *process,
    const char *guest_path, uint32_t access, uint32_t disposition)
{
    char host_path[2048];
    const char *mode;
    xx_io_device *io;
    size_t i;
    int exists;
    int writable = (access & 0x40000000u) != 0u;
    if (!win_guest_path(process, guest_path,
            host_path, sizeof(host_path))) {
        process->last_error = 3u;
        return WIN_INVALID_HANDLE;
    }
    exists = xx_io_file_exists_a(host_path);
    switch (disposition) {
    case 1u: /* CREATE_NEW */
        if (exists || !writable) goto fail;
        mode = "w+b";
        break;
    case 2u: /* CREATE_ALWAYS */
        if (!writable) goto fail;
        mode = "w+b";
        break;
    case 3u: /* OPEN_EXISTING */
        if (!exists) goto fail;
        mode = writable ? "r+b" : "rb";
        break;
    case 4u: /* OPEN_ALWAYS */
        if (!exists && !writable) goto fail;
        mode = exists ? (writable ? "r+b" : "rb") : "w+b";
        break;
    case 5u: /* TRUNCATE_EXISTING */
        if (!exists || !writable) goto fail;
        mode = "w+b";
        break;
    default:
        process->last_error = 87u;
        return WIN_INVALID_HANDLE;
    }
    if (!writable && win_equal(host_path, process->program_path)) {
        mode = "rb";
    } else if (win_equal(host_path, process->program_path)) {
        process->last_error = 5u;
        return WIN_INVALID_HANDLE;
    }
    for (i = 0; i < WIN_MAX_HANDLES; ++i) {
        if (!process->handles[i].in_use) break;
    }
    if (i == WIN_MAX_HANDLES) {
        process->last_error = 4u;
        return WIN_INVALID_HANDLE;
    }
    io = xx_io_file_open(host_path, mode);
    if (io == NULL) goto fail;
    memset(&process->handles[i], 0, sizeof(process->handles[i]));
    process->handles[i].io = io;
    (void)win_copy(process->handles[i].file_path,
        sizeof(process->handles[i].file_path), host_path);
    process->handles[i].kind = WIN_HANDLE_FILE;
    process->handles[i].file_access = access;
    process->handles[i].references = 1u;
    process->handles[i].root_slot = (uint16_t)i;
    process->handles[i].in_use = 1u;
    process->last_error = 0u;
    return 0x100u + i;
fail:
    process->last_error = exists ? 5u : 2u;
    return WIN_INVALID_HANDLE;
}

static win_handle *win_handle_at(xxemul_windows *process, uint64_t handle)
{
    size_t slot;
    win_handle *entry;
    if (handle < 0x100u) return NULL;
    slot = (size_t)(handle - 0x100u);
    if (slot >= WIN_MAX_HANDLES) return NULL;
    entry = &process->handles[slot];
    if (!entry->in_use || entry->closed) return NULL;
    if (entry->kind == WIN_HANDLE_ALIAS) {
        entry = &process->handles[entry->root_slot];
        if (!entry->in_use) return NULL;
    }
    return entry;
}

static int win_is_current_process_handle(xxemul_windows *process,
    uint64_t handle, uint8_t word_size)
{
    win_handle *entry;
    if (handle == (word_size == 8u ? UINT64_MAX : UINT32_MAX))
        return 1;
    entry = win_handle_at(process, handle);
    return entry != NULL && entry->kind == WIN_HANDLE_PROCESS;
}

static int win_is_current_thread_handle(xxemul_windows *process,
    uint64_t handle, uint8_t word_size)
{
    uint64_t pseudo = word_size == 8u ? UINT64_MAX - 1u
        : UINT32_MAX - 1u;
    win_handle *entry;
    if (handle == pseudo) return 1;
    entry = win_handle_at(process, handle);
    return entry != NULL && entry->kind == WIN_HANDLE_THREAD;
}

static uint64_t win_open_current_process(xxemul_windows *process,
    uint32_t process_id, uint32_t inherit)
{
    size_t slot;
    win_handle *entry;
    if (process_id != 1u) {
        process->last_error = 87u;
        return 0u;
    }
    for (slot = 0u; slot < WIN_MAX_HANDLES; ++slot) {
        if (!process->handles[slot].in_use) break;
    }
    if (slot == WIN_MAX_HANDLES) {
        process->last_error = 4u;
        return 0u;
    }
    entry = &process->handles[slot];
    memset(entry, 0, sizeof(*entry));
    entry->kind = WIN_HANDLE_PROCESS;
    entry->references = 1u;
    entry->root_slot = (uint16_t)slot;
    entry->flags = inherit ? 1u : 0u;
    entry->in_use = 1u;
    process->last_error = 0u;
    return 0x100u + slot;
}

static xx_io_device *win_handle_io(xxemul_windows *process,
    uint64_t handle)
{
    win_handle *entry = win_handle_at(process, handle);
    return entry != NULL && entry->kind == WIN_HANDLE_FILE
        ? entry->io : NULL;
}

static uint64_t win_crt_handle(xxemul_windows *process, uint64_t fd)
{
    if (fd < 3u) return 0x10u + fd;
    if (fd >= WIN_MAX_CRT_FDS) return 0u;
    return process->crt_fd_handles[fd];
}

static int win_file_times(const char *path, uint64_t *creation,
    uint64_t *access, uint64_t *write_time)
{
#if defined(_WIN32)
    WIN32_FILE_ATTRIBUTE_DATA attributes;
    if (!GetFileAttributesExA(path, GetFileExInfoStandard,
            &attributes)) return 0;
    *creation = (uint64_t)attributes.ftCreationTime.dwLowDateTime
        | ((uint64_t)attributes.ftCreationTime.dwHighDateTime << 32);
    *access = (uint64_t)attributes.ftLastAccessTime.dwLowDateTime
        | ((uint64_t)attributes.ftLastAccessTime.dwHighDateTime << 32);
    *write_time = (uint64_t)attributes.ftLastWriteTime.dwLowDateTime
        | ((uint64_t)attributes.ftLastWriteTime.dwHighDateTime << 32);
#else
    struct stat attributes;
    if (stat(path, &attributes) != 0) return 0;
    /* POSIX stat has no portable creation timestamp. */
    *creation = ((uint64_t)attributes.st_mtime
        + UINT64_C(11644473600)) * UINT64_C(10000000);
    *access = ((uint64_t)attributes.st_atime
        + UINT64_C(11644473600)) * UINT64_C(10000000);
    *write_time = *creation;
#endif
    return 1;
}

static xxemul_status win_set_file_times(xxemul_windows *process,
    win_handle *entry, const uint64_t *arg, uint64_t *result)
{
    uint64_t values[3] = {0u, 0u, 0u};
    size_t index;
    if (entry == NULL || entry->kind != WIN_HANDLE_FILE) {
        process->last_error = 6u;
        return XXEMUL_STATUS_OK;
    }
    if ((entry->file_access & (0x40000000u | 0x100u)) == 0u) {
        process->last_error = 5u;
        return XXEMUL_STATUS_OK;
    }
    for (index = 0u; index < 3u; ++index) {
        if (arg[index + 1u] != 0u
            && !win_load(process, arg[index + 1u], 8u,
                &values[index]))
            return XXEMUL_STATUS_ADDRESS_FAULT;
    }
#if defined(_WIN32)
    {
        HANDLE host;
        FILETIME times[3];
        const FILETIME *selected[3] = {NULL, NULL, NULL};
        for (index = 0u; index < 3u; ++index) {
            if (arg[index + 1u] != 0u) {
                times[index].dwLowDateTime = (DWORD)values[index];
                times[index].dwHighDateTime = (DWORD)(values[index] >> 32u);
                selected[index] = &times[index];
            }
        }
        host = CreateFileA(entry->file_path, FILE_WRITE_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (host == INVALID_HANDLE_VALUE) {
            process->last_error = GetLastError();
            return XXEMUL_STATUS_OK;
        }
        if (!SetFileTime(host, selected[0], selected[1], selected[2]))
            process->last_error = GetLastError();
        else *result = 1u;
        CloseHandle(host);
    }
#else
    {
        struct stat attributes;
        struct utimbuf times;
        if (arg[1] != 0u) {
            process->last_error = 50u;
            return XXEMUL_STATUS_OK;
        }
        if (stat(entry->file_path, &attributes) != 0) {
            process->last_error = 5u;
            return XXEMUL_STATUS_OK;
        }
        times.actime = attributes.st_atime;
        times.modtime = attributes.st_mtime;
        for (index = 1u; index < 3u; ++index) {
            uint64_t seconds;
            if (arg[index + 1u] == 0u) continue;
            seconds = values[index] / UINT64_C(10000000);
            if (seconds < UINT64_C(11644473600)) {
                process->last_error = 87u;
                return XXEMUL_STATUS_OK;
            }
            if (index == 1u)
                times.actime = (time_t)(seconds - UINT64_C(11644473600));
            else times.modtime = (time_t)(seconds
                - UINT64_C(11644473600));
        }
        if (utime(entry->file_path, &times) != 0)
            process->last_error = 5u;
        else *result = 1u;
    }
#endif
    return XXEMUL_STATUS_OK;
}

static uint64_t win_duplicate_handle(xxemul_windows *process,
    uint64_t source, int inherit)
{
    win_handle *root;
    win_handle *entry;
    uint64_t pseudo_process = process->emulator->mode == XXEMUL_MODE_X86_64
        ? UINT64_MAX : UINT32_MAX;
    size_t slot;
    if (source == 0x10u || source == 0x11u || source == 0x12u)
        return source;
    if (source == pseudo_process || source == pseudo_process - 1u) {
        for (slot = 0u; slot < WIN_MAX_HANDLES; ++slot) {
            if (!process->handles[slot].in_use) break;
        }
        if (slot == WIN_MAX_HANDLES) return 0u;
        entry = &process->handles[slot];
        memset(entry, 0, sizeof(*entry));
        entry->kind = source == pseudo_process
            ? WIN_HANDLE_PROCESS : WIN_HANDLE_THREAD;
        entry->references = 1u;
        entry->root_slot = (uint16_t)slot;
        entry->flags = inherit ? 1u : 0u;
        entry->in_use = 1u;
        return 0x100u + slot;
    }
    root = win_handle_at(process, source);
    if (root == NULL || root->references == UINT32_MAX) return 0;
    for (slot = 0; slot < WIN_MAX_HANDLES; ++slot) {
        if (!process->handles[slot].in_use) break;
    }
    if (slot == WIN_MAX_HANDLES) return 0;
    memset(&process->handles[slot], 0, sizeof(process->handles[slot]));
    process->handles[slot].kind = WIN_HANDLE_ALIAS;
    process->handles[slot].root_slot = (uint16_t)(root - process->handles);
    process->handles[slot].flags = inherit ? 1u : 0u;
    process->handles[slot].in_use = 1u;
    ++root->references;
    return 0x100u + slot;
}

static int win_close_handle(xxemul_windows *process, uint64_t handle)
{
    win_handle *entry, *root;
    size_t slot;
    if (handle == 0x10u || handle == 0x11u || handle == 0x12u)
        return 1;
    root = win_handle_at(process, handle);
    if (root == NULL) return 0;
    slot = (size_t)(handle - 0x100u);
    entry = &process->handles[slot];
    if (entry != root) memset(entry, 0, sizeof(*entry));
    else entry->closed = 1u;
    if (--root->references == 0u) {
        if (root->io != NULL) xx_io_close(root->io);
        memset(root, 0, sizeof(*root));
    }
    return 1;
}

static uint64_t win_create_sync(xxemul_windows *process, uint8_t kind,
    uint64_t first, uint64_t second, uint64_t name_pointer)
{
    char name[128] = {0};
    size_t index;
    win_handle *entry;
    if (kind == WIN_HANDLE_SEMAPHORE
        && ((int32_t)first < 0 || (int32_t)second <= 0
            || first > second)) {
        process->last_error = 87u;
        return 0;
    }
    if (name_pointer != 0
        && !win_guest_string(process, name_pointer,
            name, sizeof(name), 0)) {
        process->last_error = 87u;
        return 0;
    }
    if (name[0] != '\0') {
        for (index = 0; index < WIN_MAX_HANDLES; ++index) {
            uint64_t live_handle;
            size_t alias_index;
            entry = &process->handles[index];
            if (entry->in_use && entry->kind != WIN_HANDLE_ALIAS
                && entry->name[0] != '\0'
                && win_equal(entry->name, name)) {
                if (entry->kind != kind || entry->references == UINT32_MAX) {
                    process->last_error = 6u;
                    return 0;
                }
                live_handle = entry->closed ? 0u : 0x100u + index;
                for (alias_index = 0; live_handle == 0u
                    && alias_index < WIN_MAX_HANDLES; ++alias_index) {
                    win_handle *alias = &process->handles[alias_index];
                    if (alias->in_use && !alias->closed
                        && alias->kind == WIN_HANDLE_ALIAS
                        && alias->root_slot == index)
                        live_handle = 0x100u + alias_index;
                }
                if (live_handle == 0u) {
                    process->last_error = 6u;
                    return 0;
                }
                process->last_error = 183u;
                return win_duplicate_handle(process, live_handle, 0);
            }
        }
    }
    for (index = 0; index < WIN_MAX_HANDLES; ++index) {
        if (!process->handles[index].in_use) break;
    }
    if (index == WIN_MAX_HANDLES) {
        process->last_error = 4u;
        return 0;
    }
    entry = &process->handles[index];
    memset(entry, 0, sizeof(*entry));
    entry->kind = kind;
    entry->references = 1u;
    entry->root_slot = (uint16_t)index;
    entry->in_use = 1u;
    if (name[0] != '\0') (void)win_copy(entry->name,
        sizeof(entry->name), name);
    if (kind == WIN_HANDLE_EVENT) {
        entry->manual_reset = (uint8_t)(first != 0);
        entry->signaled = (uint8_t)(second != 0);
    } else {
        entry->semaphore_count = (uint32_t)first;
        entry->semaphore_max = (uint32_t)second;
    }
    process->last_error = 0u;
    return 0x100u + index;
}

static int win_sync_ready(const win_handle *entry)
{
    if (entry->kind == WIN_HANDLE_PROCESS || entry->kind == WIN_HANDLE_THREAD)
        return 1;
    return entry->kind == WIN_HANDLE_EVENT ? entry->signaled != 0
        : entry->kind == WIN_HANDLE_SEMAPHORE
            && entry->semaphore_count != 0u;
}

static void win_sync_consume(win_handle *entry)
{
    if (entry->kind == WIN_HANDLE_EVENT && !entry->manual_reset)
        entry->signaled = 0u;
    else if (entry->kind == WIN_HANDLE_SEMAPHORE)
        --entry->semaphore_count;
}

static win_critical_section *win_critical_at(
    xxemul_windows *process, uint64_t address)
{
    size_t index;
    for (index = 0; index < WIN_MAX_CRITICAL_SECTIONS; ++index) {
        win_critical_section *entry = &process->critical_sections[index];
        if (entry->active && entry->address == address) return entry;
    }
    return NULL;
}

static xxemul_status win_critical_write(
    xxemul_windows *process, const win_critical_section *entry)
{
    uint8_t word_size = process->emulator->mode == XXEMUL_MODE_X86_64
        ? 8u : 4u;
    uint64_t address = entry->address;
    uint32_t lock_count = entry->recursion == 0u
        ? UINT32_MAX : entry->recursion - 1u;
    if (!win_store(process, address + word_size, 4u, lock_count)
        || !win_store(process, address + word_size + 4u,
            4u, entry->recursion)
        || !win_store(process, address + (word_size == 8u ? 16u : 12u),
            word_size, entry->recursion == 0u ? 0u : 1u))
        return XXEMUL_STATUS_ADDRESS_FAULT;
    return XXEMUL_STATUS_OK;
}

static xxemul_status win_critical_initialize(
    xxemul_windows *process, uint64_t address)
{
    uint8_t zero[40] = {0};
    win_critical_section *entry = NULL;
    size_t index;
    if (address == 0u)
        return XXEMUL_STATUS_INVALID_ARGUMENT;
    entry = win_critical_at(process, address);
    if (entry == NULL) {
        for (index = 0; index < WIN_MAX_CRITICAL_SECTIONS; ++index) {
            if (!process->critical_sections[index].active) {
                entry = &process->critical_sections[index];
                break;
            }
        }
    }
    if (entry == NULL) return XXEMUL_STATUS_OUT_OF_MEMORY;
    if (!win_write(process, address, zero,
            process->emulator->mode == XXEMUL_MODE_X86_64
                ? 40u : 24u)) return XXEMUL_STATUS_ADDRESS_FAULT;
    entry->address = address;
    entry->recursion = 0u;
    entry->active = 1u;
    return win_critical_write(process, entry);
}

static uint64_t win_file_read(xxemul_windows *process,
    uint64_t handle, uint64_t buffer, uint64_t count,
    uint64_t bytes_read)
{
    xx_io_device *io = win_handle_io(process, handle);
    uint8_t *bytes;
    ssize_t result;
    if (bytes_read != 0 && !win_store(process, bytes_read, 4u, 0)) return 0;
    if (io == NULL || count > WIN_MAX_IO) {
        process->last_error = 6u;
        return 0;
    }
    bytes = (uint8_t *)malloc((size_t)(count != 0 ? count : 1u));
    if (bytes == NULL) {
        process->last_error = 8u;
        return 0;
    }
    result = xx_io_read(io, bytes, (size_t)count);
    if (result >= 0 && (!win_write(process, buffer, bytes, (size_t)result)
        || (bytes_read != 0
            && !win_store(process, bytes_read, 4u, (uint32_t)result))))
        result = -1;
    free(bytes);
    if (result == 0 && count > 0) {
        win_handle *entry = win_handle_at(process, handle);
        if (entry != NULL && entry->file_path[0] == '\0') {
            process->last_error = 109u; /* ERROR_BROKEN_PIPE */
            return 0u;
        }
    }
    process->last_error = result < 0 ? 6u : 0u;
    return result < 0 ? 0u : 1u;
}

static uint64_t win_file_write(xxemul_windows *process,
    uint64_t handle, uint64_t buffer, uint64_t count,
    uint64_t bytes_written)
{
    xx_io_device *io = win_handle_io(process, handle);
    uint8_t *bytes;
    ssize_t result;
    size_t i;
    if (bytes_written != 0 && !win_store(process,
            bytes_written, 4u, 0)) return 0;
    if (count > WIN_MAX_IO) {
        process->last_error = 8u;
        return 0;
    }
    bytes = (uint8_t *)malloc((size_t)(count != 0 ? count : 1u));
    if (bytes == NULL) {
        process->last_error = 8u;
        return 0;
    }
    if (!win_read(process, buffer, bytes, (size_t)count)) {
        free(bytes);
        process->last_error = 487u;
        return 0;
    }
    if (handle == 0x11u || handle == 0x12u) {
        if (process->emulator->output_callback != NULL) {
            for (i = 0; i < (size_t)count; ++i) {
                process->emulator->output_callback(
                    process->emulator->output_context, bytes[i]);
            }
            result = (ssize_t)count;
        } else {
            FILE *stream = handle == 0x11u ? stdout : stderr;
            result = (ssize_t)fwrite(bytes, 1, (size_t)count, stream);
            fflush(stream);
        }
    } else {
        result = io == NULL ? -1 : xx_io_write(io, bytes, (size_t)count);
    }
    free(bytes);
    if (result >= 0 && bytes_written != 0
        && !win_store(process, bytes_written, 4u, (uint32_t)result))
        result = -1;
    process->last_error = result < 0 ? 6u : 0u;
    return result < 0 ? 0u : 1u;
}

static uint64_t win_console_write_w(xxemul_windows *process,
    uint64_t handle, uint64_t buffer, uint64_t count,
    uint64_t chars_written)
{
    uint16_t *chars;
    size_t i;
    if (chars_written != 0 && !win_store(process, chars_written, 4u, 0)) return 0;
    if (count == 0) return 1;
    if (count > WIN_MAX_IO) {
        process->last_error = 8u;
        return 0;
    }
    chars = (uint16_t *)malloc((size_t)(count * 2u));
    if (chars == NULL) {
        process->last_error = 8u;
        return 0;
    }
    if (!win_read(process, buffer, chars, (size_t)count * 2u)) {
        free(chars);
        process->last_error = 487u;
        return 0;
    }
    for (i = 0; i < (size_t)count; ++i) {
        uint16_t ch = chars[i];
        if (process->emulator->output_callback != NULL) {
            if (ch < 0x80) {
                process->emulator->output_callback(
                    process->emulator->output_context, (uint8_t)ch);
            } else {
                char utf8[4];
                int len = WideCharToMultiByte(CP_UTF8, 0, (LPCWCH)&ch, 1,
                    utf8, sizeof(utf8), NULL, NULL);
                int k;
                for (k = 0; k < len; ++k) {
                    process->emulator->output_callback(
                        process->emulator->output_context, (uint8_t)utf8[k]);
                }
            }
        } else {
            FILE *stream = handle == 0x12u ? stderr : stdout;
            if (ch < 0x80) {
                fputc((int)ch, stream);
            } else {
#if defined(_WIN32)
                char utf8[8];
                int len = WideCharToMultiByte(CP_UTF8, 0, (LPCWCH)&ch, 1,
                    utf8, sizeof(utf8), NULL, NULL);
                if (len > 0) {
                    fwrite(utf8, 1, (size_t)len, stream);
                } else {
                    fputc('?', stream);
                }
#else
                fputc('?', stream);
#endif
            }
        }
    }
    if (process->emulator->output_callback == NULL) {
        fflush(handle == 0x12u ? stderr : stdout);
    }
    free(chars);
    if (chars_written != 0)
        win_store(process, chars_written, 4u, (uint32_t)count);
    return 1;
}

static int win_get_arg(xxemul_windows *process,
    uint8_t index, uint64_t *argument)
{
    xxemul *emulator = process->emulator;
    uint64_t sp = emulator->x86.gpr[XXEMUL_X86_RSP];
    if (emulator->mode == XXEMUL_MODE_X86_32)
        return win_load(process, sp + 4u + (uint64_t)index * 4u,
            4u, argument);
    if (index == 0u) {
        *argument = emulator->x86.gpr[XXEMUL_X86_RCX];
        return 1;
    }
    if (index == 1u) {
        *argument = emulator->x86.gpr[XXEMUL_X86_RDX];
        return 1;
    }
    if (index == 2u) {
        *argument = emulator->x86.gpr[XXEMUL_X86_R8];
        return 1;
    }
    if (index == 3u) {
        *argument = emulator->x86.gpr[XXEMUL_X86_R9];
        return 1;
    }
    return win_load(process, sp + 40u + (uint64_t)(index - 4u) * 8u,
        8u, argument);
}

static xxemul_status win_capture_thread_context(
    xxemul_windows *process, uint64_t address, uint8_t word_size,
    uint64_t *result)
{
    const xxemul_x86_state *state = &process->emulator->x86;
    uint32_t architecture_flag = word_size == 8u ? 0x100000u : 0x10000u;
    uint64_t flags, return_address, next_sp;
    size_t index;
    if (!win_load(process, address + (word_size == 8u ? 48u : 0u),
            4u, &flags)
        || !win_load(process, state->gpr[XXEMUL_X86_RSP],
            word_size, &return_address))
        return XXEMUL_STATUS_ADDRESS_FAULT;
    if ((flags & architecture_flag) == 0u || (flags & 7u) == 0u) {
        process->last_error = 87u;
        return XXEMUL_STATUS_OK;
    }
    if ((flags & ~(uint64_t)(architecture_flag | 7u)) != 0u)
        return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    next_sp = state->gpr[XXEMUL_X86_RSP]
        + (word_size == 8u ? 8u : 12u);
    if (word_size == 8u) {
        if ((flags & 1u) != 0u
            && (!win_store(process, address + 56u, 2u,
                    state->segment[XXEMUL_X86_CS])
                || !win_store(process, address + 66u, 2u,
                    state->segment[XXEMUL_X86_SS])
                || !win_store(process, address + 68u, 4u, state->flags)
                || !win_store(process, address + 152u, 8u, next_sp)
                || !win_store(process, address + 248u, 8u,
                    return_address)))
            return XXEMUL_STATUS_ADDRESS_FAULT;
        if ((flags & 2u) != 0u) {
            for (index = 0; index < XXEMUL_X86_GPR_COUNT; ++index) {
                uint64_t value = index == XXEMUL_X86_RAX
                    ? 1u : state->gpr[index];
                if (index != XXEMUL_X86_RSP
                    && !win_store(process, address + 120u + index * 8u,
                        8u, value)) return XXEMUL_STATUS_ADDRESS_FAULT;
            }
        }
        if ((flags & 4u) != 0u
            && (!win_store(process, address + 58u, 2u,
                    state->segment[XXEMUL_X86_DS])
                || !win_store(process, address + 60u, 2u,
                    state->segment[XXEMUL_X86_ES])
                || !win_store(process, address + 62u, 2u,
                    state->segment[XXEMUL_X86_FS])
                || !win_store(process, address + 64u, 2u,
                    state->segment[XXEMUL_X86_GS])))
            return XXEMUL_STATUS_ADDRESS_FAULT;
    } else {
        static const uint8_t integer_gpr[] = {
            XXEMUL_X86_RDI, XXEMUL_X86_RSI, XXEMUL_X86_RBX,
            XXEMUL_X86_RDX, XXEMUL_X86_RCX, XXEMUL_X86_RAX
        };
        if ((flags & 1u) != 0u
            && (!win_store(process, address + 180u, 4u,
                    state->gpr[XXEMUL_X86_RBP])
                || !win_store(process, address + 184u, 4u,
                    return_address)
                || !win_store(process, address + 188u, 4u,
                    state->segment[XXEMUL_X86_CS])
                || !win_store(process, address + 192u, 4u,
                    state->flags)
                || !win_store(process, address + 196u, 4u,
                    next_sp)
                || !win_store(process, address + 200u, 4u,
                    state->segment[XXEMUL_X86_SS])))
            return XXEMUL_STATUS_ADDRESS_FAULT;
        if ((flags & 2u) != 0u) {
            for (index = 0; index < sizeof(integer_gpr); ++index) {
                uint64_t value = integer_gpr[index] == XXEMUL_X86_RAX
                    ? 1u : state->gpr[integer_gpr[index]];
                if (!win_store(process, address + 156u + index * 4u,
                        4u, value)) return XXEMUL_STATUS_ADDRESS_FAULT;
            }
        }
        if ((flags & 4u) != 0u
            && (!win_store(process, address + 140u, 4u,
                    state->segment[XXEMUL_X86_GS])
                || !win_store(process, address + 144u, 4u,
                    state->segment[XXEMUL_X86_FS])
                || !win_store(process, address + 148u, 4u,
                    state->segment[XXEMUL_X86_ES])
                || !win_store(process, address + 152u, 4u,
                    state->segment[XXEMUL_X86_DS])))
            return XXEMUL_STATUS_ADDRESS_FAULT;
    }
    *result = 1u;
    return XXEMUL_STATUS_OK;
}

static const uint16_t win_cp1252_upper[32] = {
    0x20acu, 0x0081u, 0x201au, 0x0192u, 0x201eu, 0x2026u,
    0x2020u, 0x2021u, 0x02c6u, 0x2030u, 0x0160u, 0x2039u,
    0x0152u, 0x008du, 0x017du, 0x008fu, 0x0090u, 0x2018u,
    0x2019u, 0x201cu, 0x201du, 0x2022u, 0x2013u, 0x2014u,
    0x02dcu, 0x2122u, 0x0161u, 0x203au, 0x0153u, 0x009du,
    0x017eu, 0x0178u
};

static uint32_t win_code_page(uint32_t code_page)
{
    return code_page == 0u || code_page == 1u || code_page == 3u
        ? 1252u : code_page;
}

static xxemul_status win_conversion_input(xxemul_windows *process,
    uint64_t address, int32_t length, size_t unit_size,
    uint8_t **bytes, size_t *units)
{
    size_t count = 0u;
    uint8_t *buffer;
    if (address == 0u || length == 0 || length < -1
        || length > (int32_t)(WIN_MAX_IO / 4u)) {
        process->last_error = 87u;
        return XXEMUL_STATUS_OK;
    }
    if (length == -1) {
        uint64_t ch;
        do {
            if (count >= WIN_MAX_IO / 4u) {
                process->last_error = 87u;
                return XXEMUL_STATUS_OK;
            }
            if (!win_load(process, address + count * unit_size,
                    (uint8_t)unit_size, &ch))
                return XXEMUL_STATUS_ADDRESS_FAULT;
            ++count;
        } while (ch != 0u);
    } else count = (size_t)length;
    buffer = (uint8_t *)malloc(count * unit_size);
    if (buffer == NULL) {
        process->last_error = 8u;
        return XXEMUL_STATUS_OK;
    }
    if (!win_read(process, address, buffer, count * unit_size)) {
        free(buffer);
        return XXEMUL_STATUS_ADDRESS_FAULT;
    }
    *bytes = buffer;
    *units = count;
    return XXEMUL_STATUS_OK;
}

static int win_utf8_scalar(const uint8_t *bytes, size_t available,
    uint32_t *scalar, size_t *length)
{
    uint8_t first = bytes[0];
    uint32_t value;
    size_t count, index;
    if (first < 0x80u) {
        *scalar = first;
        *length = 1u;
        return 1;
    }
    if (first >= 0xc2u && first <= 0xdfu) {
        value = first & 0x1fu;
        count = 2u;
    } else if (first >= 0xe0u && first <= 0xefu) {
        value = first & 0x0fu;
        count = 3u;
    } else if (first >= 0xf0u && first <= 0xf4u) {
        value = first & 0x07u;
        count = 4u;
    } else return 0;
    if (available < count) return 0;
    for (index = 1u; index < count; ++index) {
        if ((bytes[index] & 0xc0u) != 0x80u) return 0;
        value = (value << 6u) | (bytes[index] & 0x3fu);
    }
    if ((count == 2u && value < 0x80u)
        || (count == 3u && value < 0x800u)
        || (count == 4u && value < 0x10000u)
        || (value >= 0xd800u && value <= 0xdfffu)
        || value > 0x10ffffu) return 0;
    *scalar = value;
    *length = count;
    return 1;
}

static xxemul_status win_multi_byte_to_wide(xxemul_windows *process,
    const uint64_t *arg, uint64_t *result)
{
    uint32_t code_page = win_code_page((uint32_t)arg[0]);
    uint32_t flags = (uint32_t)arg[1];
    uint8_t *input = NULL, *output;
    size_t units = 0u, used = 0u, index;
    xxemul_status status;
    if (code_page != 1252u && code_page != 65001u)
        return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    if ((flags & ~(code_page == 65001u ? 8u : 11u)) != 0u
        || (int32_t)arg[5] < 0
        || ((int32_t)arg[5] != 0 && arg[4] == 0u)) {
        process->last_error = 1004u;
        return XXEMUL_STATUS_OK;
    }
    status = win_conversion_input(process, arg[2], (int32_t)arg[3],
        1u, &input, &units);
    if (status != XXEMUL_STATUS_OK || input == NULL) return status;
    output = (uint8_t *)malloc(units * 4u);
    if (output == NULL) {
        free(input);
        process->last_error = 8u;
        return XXEMUL_STATUS_OK;
    }
    for (index = 0u; index < units;) {
        uint32_t scalar;
        size_t consumed = 1u;
        if (code_page == 1252u) {
            uint8_t ch = input[index];
            scalar = ch >= 0x80u && ch < 0xa0u
                ? win_cp1252_upper[ch - 0x80u] : ch;
        } else if (!win_utf8_scalar(input + index, units - index,
                &scalar, &consumed)) {
            if ((flags & 8u) != 0u) {
                process->last_error = 1113u;
                break;
            }
            scalar = 0xfffdu;
        }
        index += consumed;
        if (scalar > 0xffffu) {
            uint32_t pair = scalar - 0x10000u;
            uint16_t high = (uint16_t)(0xd800u + (pair >> 10u));
            uint16_t low = (uint16_t)(0xdc00u + (pair & 0x3ffu));
            output[used++] = (uint8_t)high;
            output[used++] = (uint8_t)(high >> 8u);
            output[used++] = (uint8_t)low;
            output[used++] = (uint8_t)(low >> 8u);
        } else {
            output[used++] = (uint8_t)scalar;
            output[used++] = (uint8_t)(scalar >> 8u);
        }
    }
    if (index == units) {
        if (arg[5] == 0u) *result = used / 2u;
        else if (used / 2u > (size_t)(int32_t)arg[5])
            process->last_error = 122u;
        else if (!win_write(process, arg[4], output, used))
            status = XXEMUL_STATUS_ADDRESS_FAULT;
        else *result = used / 2u;
    }
    free(output);
    free(input);
    return status;
}

static size_t win_encode_utf8(uint32_t scalar, uint8_t *output)
{
    if (scalar < 0x80u) {
        output[0] = (uint8_t)scalar;
        return 1u;
    }
    if (scalar < 0x800u) {
        output[0] = (uint8_t)(0xc0u | (scalar >> 6u));
        output[1] = (uint8_t)(0x80u | (scalar & 0x3fu));
        return 2u;
    }
    if (scalar < 0x10000u) {
        output[0] = (uint8_t)(0xe0u | (scalar >> 12u));
        output[1] = (uint8_t)(0x80u | ((scalar >> 6u) & 0x3fu));
        output[2] = (uint8_t)(0x80u | (scalar & 0x3fu));
        return 3u;
    }
    output[0] = (uint8_t)(0xf0u | (scalar >> 18u));
    output[1] = (uint8_t)(0x80u | ((scalar >> 12u) & 0x3fu));
    output[2] = (uint8_t)(0x80u | ((scalar >> 6u) & 0x3fu));
    output[3] = (uint8_t)(0x80u | (scalar & 0x3fu));
    return 4u;
}

static xxemul_status win_wide_to_multi_byte(xxemul_windows *process,
    const uint64_t *arg, uint64_t *result)
{
    uint32_t code_page = win_code_page((uint32_t)arg[0]);
    uint32_t flags = (uint32_t)arg[1];
    uint8_t *input = NULL, *output, fallback = '?';
    size_t units = 0u, used = 0u, index;
    uint64_t default_character;
    int substituted = 0;
    xxemul_status status;
    if (code_page != 1252u && code_page != 65001u)
        return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    if ((flags & ~(code_page == 65001u ? 0x80u : 0x400u)) != 0u
        || (int32_t)arg[5] < 0
        || ((int32_t)arg[5] != 0 && arg[4] == 0u)
        || (code_page == 65001u && (arg[6] != 0u || arg[7] != 0u))) {
        process->last_error = 1004u;
        return XXEMUL_STATUS_OK;
    }
    status = win_conversion_input(process, arg[2], (int32_t)arg[3],
        2u, &input, &units);
    if (status != XXEMUL_STATUS_OK || input == NULL) return status;
    if (arg[6] != 0u) {
        if (!win_load(process, arg[6], 1u, &default_character)) {
            free(input);
            return XXEMUL_STATUS_ADDRESS_FAULT;
        }
        fallback = (uint8_t)default_character;
    }
    output = (uint8_t *)malloc(units * 4u);
    if (output == NULL) {
        free(input);
        process->last_error = 8u;
        return XXEMUL_STATUS_OK;
    }
    for (index = 0u; index < units; ++index) {
        uint32_t scalar = win_le16(input + index * 2u);
        if (scalar >= 0xd800u && scalar <= 0xdbffu
            && index + 1u < units) {
            uint32_t low = win_le16(input + (index + 1u) * 2u);
            if (low >= 0xdc00u && low <= 0xdfffu) {
                scalar = 0x10000u + ((scalar - 0xd800u) << 10u)
                    + low - 0xdc00u;
                ++index;
            }
        }
        if (scalar >= 0xd800u && scalar <= 0xdfffu) {
            if ((flags & 0x80u) != 0u) {
                process->last_error = 1113u;
                break;
            }
            scalar = 0xfffdu;
        }
        if (code_page == 65001u)
            used += win_encode_utf8(scalar, output + used);
        else {
            size_t cp_index;
            if (scalar < 0x80u || (scalar >= 0xa0u && scalar <= 0xffu))
                output[used++] = (uint8_t)scalar;
            else {
                for (cp_index = 0u; cp_index < 32u; ++cp_index) {
                    if (win_cp1252_upper[cp_index] == scalar) break;
                }
                if (cp_index == 32u) {
                    output[used++] = fallback;
                    substituted = 1;
                } else output[used++] = (uint8_t)(0x80u + cp_index);
            }
        }
    }
    if (index == units) {
        if (arg[5] == 0u) *result = used;
        else if (used > (size_t)(int32_t)arg[5])
            process->last_error = 122u;
        else if (!win_write(process, arg[4], output, used))
            status = XXEMUL_STATUS_ADDRESS_FAULT;
        else *result = used;
        if (*result != 0u && arg[7] != 0u
            && !win_store(process, arg[7], 4u, (uint32_t)substituted))
            status = XXEMUL_STATUS_ADDRESS_FAULT;
    }
    free(output);
    free(input);
    return status;
}

static xxemul_status win_console_transfer(xxemul_windows *process,
    const uint64_t *arg, uint64_t *result, int read_output)
{
    win_console_rect requested, written;
    int width = (int16_t)arg[2];
    int height = (int16_t)(arg[2] >> 16u);
    int source_x = (int16_t)arg[3];
    int source_y = (int16_t)(arg[3] >> 16u);
    int x, y, found = 0;
    if (arg[0] != 0x11u && arg[0] != 0x12u) {
        process->last_error = 6u;
        return XXEMUL_STATUS_OK;
    }
    if (width <= 0 || height <= 0 || source_x < 0 || source_y < 0
        || source_x >= width || source_y >= height) {
        process->last_error = 87u;
        return XXEMUL_STATUS_OK;
    }
    if (!win_console_read_rect(process, arg[4], &requested))
        return XXEMUL_STATUS_ADDRESS_FAULT;
    if (requested.left > requested.right
        || requested.top > requested.bottom) {
        process->last_error = 87u;
        return XXEMUL_STATUS_OK;
    }
    written.left = 0;
    written.top = 0;
    written.right = -1;
    written.bottom = -1;
    for (y = 0; y < WIN_CONSOLE_HEIGHT; ++y) {
        if (y < requested.top || y > requested.bottom) continue;
        for (x = 0; x < WIN_CONSOLE_WIDTH; ++x) {
            int sx = source_x + x - requested.left;
            int sy = source_y + y - requested.top;
            uint64_t guest_cell, cell_value;
            win_console_cell *cell;
            if (x < requested.left || x > requested.right
                || sx < 0 || sx >= width || sy < 0 || sy >= height)
                continue;
            guest_cell = arg[1] + ((uint64_t)sy * (uint64_t)width
                + (uint64_t)sx) * 4u;
            cell = &process->console_cells[win_console_index(x, y)];
            if (read_output) {
                cell_value = (uint64_t)cell->character
                    | ((uint64_t)cell->attributes << 16u);
                if (!win_store(process, guest_cell, 4u, cell_value))
                    return XXEMUL_STATUS_ADDRESS_FAULT;
            } else {
                if (!win_load(process, guest_cell, 4u, &cell_value))
                    return XXEMUL_STATUS_ADDRESS_FAULT;
                cell->character = (uint8_t)cell_value;
                cell->attributes = (uint16_t)(cell_value >> 16u);
            }
            if (!found) {
                written.left = written.right = (int16_t)x;
                written.top = written.bottom = (int16_t)y;
                found = 1;
            } else {
                if (x < written.left) written.left = (int16_t)x;
                if (x > written.right) written.right = (int16_t)x;
                if (y < written.top) written.top = (int16_t)y;
                if (y > written.bottom) written.bottom = (int16_t)y;
            }
        }
    }
    if (!win_console_write_rect(process, arg[4], &written))
        return XXEMUL_STATUS_ADDRESS_FAULT;
    *result = 1u;
    return XXEMUL_STATUS_OK;
}

static xxemul_status win_console_scroll(xxemul_windows *process,
    const uint64_t *arg, uint64_t *result)
{
    win_console_rect source = {0};
    win_console_rect clip = {0, 0,
        WIN_CONSOLE_WIDTH - 1, WIN_CONSOLE_HEIGHT - 1};
    win_console_cell old[WIN_CONSOLE_WIDTH * WIN_CONSOLE_HEIGHT];
    uint64_t fill_value;
    int dest_x = (int16_t)arg[3];
    int dest_y = (int16_t)(arg[3] >> 16u);
    int x, y, left, right, top, bottom;
    if (arg[0] != 0x11u && arg[0] != 0x12u) {
        process->last_error = 6u;
        return XXEMUL_STATUS_OK;
    }
    if (!win_console_read_rect(process, arg[1], &source)
        || (arg[2] != 0u
            && !win_console_read_rect(process, arg[2], &clip))
        || !win_load(process, arg[4], 4u, &fill_value))
        return XXEMUL_STATUS_ADDRESS_FAULT;
    if (source.left > source.right || source.top > source.bottom
        || clip.left > clip.right || clip.top > clip.bottom) {
        process->last_error = 87u;
        return XXEMUL_STATUS_OK;
    }
    left = source.left > clip.left ? source.left : clip.left;
    right = source.right < clip.right ? source.right : clip.right;
    top = source.top > clip.top ? source.top : clip.top;
    bottom = source.bottom < clip.bottom ? source.bottom : clip.bottom;
    if (left < 0) left = 0;
    if (top < 0) top = 0;
    if (right >= WIN_CONSOLE_WIDTH) right = WIN_CONSOLE_WIDTH - 1;
    if (bottom >= WIN_CONSOLE_HEIGHT) bottom = WIN_CONSOLE_HEIGHT - 1;
    memcpy(old, process->console_cells, sizeof(old));
    for (y = top; y <= bottom; ++y) {
        for (x = left; x <= right; ++x) {
            win_console_cell *cell;
            cell = &process->console_cells[win_console_index(x, y)];
            cell->character = (uint8_t)fill_value;
            cell->attributes = (uint16_t)(fill_value >> 16u);
        }
    }
    for (y = top; y <= bottom; ++y) {
        for (x = left; x <= right; ++x) {
            int to_x = dest_x + x - source.left;
            int to_y = dest_y + y - source.top;
            if (!win_console_in_bounds(to_x, to_y)
                || to_x < clip.left || to_x > clip.right
                || to_y < clip.top || to_y > clip.bottom) continue;
            process->console_cells[win_console_index(to_x, to_y)]
                = old[win_console_index(x, y)];
        }
    }
    *result = 1u;
    return XXEMUL_STATUS_OK;
}

static xxemul_status win_crt_errno(xxemul_windows *process, uint32_t value)
{
    return win_store(process, process->runtime_base
        + WIN_CRT_DATA_OFFSET + 32u, 4u, value)
        ? XXEMUL_STATUS_OK : XXEMUL_STATUS_ADDRESS_FAULT;
}

static xxemul_status win_crt_store_stat(xxemul_windows *process,
    const char *host_path, uint64_t output, uint8_t time_size,
    uint64_t *result)
{
    uint8_t zero[56] = {0};
#if defined(_WIN32)
    struct _stat64 attributes;
#else
    struct stat attributes;
#endif
#if defined(_WIN32)
    if (_stat64(host_path, &attributes) != 0) {
#else
    if (stat(host_path, &attributes) != 0) {
#endif
        *result = UINT32_MAX;
        return win_crt_errno(process, errno == EACCES ? 13u : 2u);
    }
    if (!win_write(process, output, zero, time_size == 8u ? 56u : 48u)
        || !win_store(process, output + 6u, 2u,
            (uint16_t)attributes.st_mode)
        || !win_store(process, output + 8u, 2u,
            (uint16_t)attributes.st_nlink)
        || !win_store(process, output + 24u, 8u,
            (uint64_t)attributes.st_size)
        || !win_store(process, output + 32u, time_size,
            (uint64_t)attributes.st_atime)
        || !win_store(process, output + 32u + time_size, time_size,
            (uint64_t)attributes.st_mtime)
        || !win_store(process, output + 32u + 2u * time_size,
            time_size, (uint64_t)attributes.st_ctime))
        return XXEMUL_STATUS_ADDRESS_FAULT;
    return XXEMUL_STATUS_OK;
}

static xxemul_status win_crt_copy(xxemul_windows *process,
    uint64_t destination, uint64_t source, uint64_t count)
{
    uint8_t bytes[4096];
    int reverse;
    uint64_t offset;
    if (count > WIN_MAX_IO || source > UINT64_MAX - count
        || destination > UINT64_MAX - count)
        return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    reverse = destination > source && destination - source < count;
    for (offset = 0u; offset < count;) {
        size_t chunk = (size_t)(count - offset > sizeof(bytes)
            ? sizeof(bytes) : count - offset);
        uint64_t at = reverse ? count - offset - chunk : offset;
        if (!win_read(process, source + at, bytes, chunk)
            || !win_write(process, destination + at, bytes, chunk))
            return XXEMUL_STATUS_ADDRESS_FAULT;
        offset += chunk;
    }
    return XXEMUL_STATUS_OK;
}

static xxemul_status win_crt_fill(xxemul_windows *process,
    uint64_t destination, uint8_t character, uint64_t count)
{
    uint8_t bytes[4096];
    uint64_t offset;
    if (count > WIN_MAX_IO || destination > UINT64_MAX - count)
        return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    memset(bytes, character, sizeof(bytes));
    for (offset = 0u; offset < count;) {
        size_t chunk = (size_t)(count - offset > sizeof(bytes)
            ? sizeof(bytes) : count - offset);
        if (!win_write(process, destination + offset, bytes, chunk))
            return XXEMUL_STATUS_ADDRESS_FAULT;
        offset += chunk;
    }
    return XXEMUL_STATUS_OK;
}

static xxemul_status win_crt_string_length(xxemul_windows *process,
    uint64_t address, uint8_t unit_size, uint64_t *length)
{
    uint64_t ch;
    for (*length = 0u; *length < WIN_MAX_IO / unit_size;
         ++*length) {
        if (!win_load(process, address + *length * unit_size,
                unit_size, &ch)) return XXEMUL_STATUS_ADDRESS_FAULT;
        if (ch == 0u) return XXEMUL_STATUS_OK;
    }
    return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
}

static xxemul_status win_crt_compare_strings(xxemul_windows *process,
    uint64_t left, uint64_t right, uint64_t limit, int folded,
    uint64_t *result)
{
    uint64_t index;
    int bounded = limit <= WIN_MAX_IO;
    if (limit > WIN_MAX_IO) limit = WIN_MAX_IO;
    for (index = 0u; index < limit; ++index) {
        uint64_t a, b;
        int difference;
        if (!win_load(process, left + index, 1u, &a)
            || !win_load(process, right + index, 1u, &b))
            return XXEMUL_STATUS_ADDRESS_FAULT;
        if (folded) {
            a = (uint8_t)tolower((unsigned char)a);
            b = (uint8_t)tolower((unsigned char)b);
        }
        difference = (int)a - (int)b;
        if (difference != 0) {
            *result = (uint32_t)difference;
            return XXEMUL_STATUS_OK;
        }
        if (a == 0u) return XXEMUL_STATUS_OK;
    }
    return bounded ? XXEMUL_STATUS_OK
        : XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
}

static xxemul_status win_crt_read_string(xxemul_windows *process,
    uint64_t address, char **buffer, size_t *length)
{
    xxemul_status status;
    uint64_t count;
    status = win_crt_string_length(process, address, 1u, &count);
    if (status != XXEMUL_STATUS_OK) return status;
    *buffer = (char *)malloc((size_t)count + 1u);
    if (*buffer == NULL) return win_crt_errno(process, 12u);
    if (!win_read(process, address, *buffer, (size_t)count + 1u)) {
        free(*buffer);
        *buffer = NULL;
        return XXEMUL_STATUS_ADDRESS_FAULT;
    }
    *length = (size_t)count;
    return XXEMUL_STATUS_OK;
}

static xxemul_status win_crt_parse_number(xxemul_windows *process,
    const uint64_t *arg, uint8_t word_size, int unsigned_value,
    uint64_t *result)
{
    char *text = NULL, *end = NULL;
    size_t length = 0u;
    int base = (int32_t)arg[2];
    uint32_t guest_error = 0u;
    xxemul_status status;
    if (base != 0 && (base < 2 || base > 36)) {
        guest_error = 22u;
        if (arg[1] != 0u && !win_store(process, arg[1],
                word_size, arg[0])) return XXEMUL_STATUS_ADDRESS_FAULT;
        return win_crt_errno(process, guest_error);
    }
    status = win_crt_read_string(process, arg[0], &text, &length);
    if (status != XXEMUL_STATUS_OK || text == NULL) return status;
    if (unsigned_value) {
        const char *digits = text;
        unsigned long long parsed;
        int negative;
        while (isspace((unsigned char)*digits)) ++digits;
        negative = *digits == '-';
        if (*digits == '-' || *digits == '+') ++digits;
        errno = 0;
        parsed = strtoull(digits, &end, base);
        if (end == digits) end = text;
        else if (errno == ERANGE || parsed > UINT32_MAX) {
            *result = UINT32_MAX;
            guest_error = 34u;
        } else {
            uint32_t narrowed = (uint32_t)parsed;
            *result = negative ? (uint32_t)(0u - narrowed) : narrowed;
        }
    } else {
        long long parsed;
        errno = 0;
        parsed = strtoll(text, &end, base);
        if (errno == ERANGE || parsed > INT32_MAX) {
            *result = INT32_MAX;
            guest_error = 34u;
        } else if (parsed < INT32_MIN) {
            *result = (uint32_t)INT32_MIN;
            guest_error = 34u;
        } else *result = (uint32_t)(int32_t)parsed;
    }
    if (arg[1] != 0u && !win_store(process, arg[1],
            word_size, arg[0] + (size_t)(end - text)))
        status = XXEMUL_STATUS_ADDRESS_FAULT;
    if (status == XXEMUL_STATUS_OK && guest_error != 0u)
        status = win_crt_errno(process, guest_error);
    free(text);
    (void)length;
    return status;
}

static int win_load_string(xxemul_windows *process, uint32_t uid,
    uint64_t buffer, uint32_t max_chars, uint64_t *result)
{
    uint32_t block_id = (uid / 16u) + 1u;
    uint32_t str_idx = uid % 16u;
    uint64_t rsrc_base;
    uint64_t named_entries = 0, id_entries = 0;
    uint32_t i, j, k;
    uint64_t block_dir_offset = 0, lang_dir_offset = 0, data_entry_offset = 0;
    uint64_t offset_to_data = 0, data_size = 0;

    if (process->resource_rva == 0 || process->resource_size == 0) return 0;
    rsrc_base = process->image_base + process->resource_rva;

    /* Level 1: Find Type 6 (RT_STRING) */
    if (!win_load(process, rsrc_base + 12u, 2u, &named_entries)
        || !win_load(process, rsrc_base + 14u, 2u, &id_entries)) return 0;
    for (i = 0; i < (uint32_t)named_entries + (uint32_t)id_entries; ++i) {
        uint64_t entry_addr = rsrc_base + 16u + (uint64_t)i * 8u;
        uint64_t type_id = 0, offset = 0;
        win_load(process, entry_addr, 4u, &type_id);
        win_load(process, entry_addr + 4u, 4u, &offset);
        if (type_id == 6u && (offset & 0x80000000u)) {
            block_dir_offset = rsrc_base + (offset & 0x7fffffffu);
            break;
        }
    }
    if (block_dir_offset == 0) return 0;

    /* Level 2: Find block_id */
    if (!win_load(process, block_dir_offset + 12u, 2u, &named_entries)
        || !win_load(process, block_dir_offset + 14u, 2u, &id_entries)) return 0;
    for (j = 0; j < (uint32_t)named_entries + (uint32_t)id_entries; ++j) {
        uint64_t entry_addr = block_dir_offset + 16u + (uint64_t)j * 8u;
        uint64_t cur_id = 0, offset = 0;
        win_load(process, entry_addr, 4u, &cur_id);
        win_load(process, entry_addr + 4u, 4u, &offset);
        if (cur_id == block_id && (offset & 0x80000000u)) {
            lang_dir_offset = rsrc_base + (offset & 0x7fffffffu);
            break;
        }
    }
    if (lang_dir_offset == 0) return 0;

    /* Level 3: First language entry */
    if (!win_load(process, lang_dir_offset + 12u, 2u, &named_entries)
        || !win_load(process, lang_dir_offset + 14u, 2u, &id_entries)) return 0;
    if ((uint32_t)named_entries + (uint32_t)id_entries == 0) return 0;
    {
        uint64_t offset = 0;
        win_load(process, lang_dir_offset + 16u + 4u, 4u, &offset);
        data_entry_offset = rsrc_base + (offset & 0x7fffffffu);
    }

    /* Read IMAGE_RESOURCE_DATA_ENTRY */
    win_load(process, data_entry_offset, 4u, &offset_to_data);
    win_load(process, data_entry_offset + 4u, 4u, &data_size);
    if (offset_to_data == 0 || data_size == 0) return 0;

    /* Read the 16 counted UTF-16 strings */
    {
        uint64_t curr = process->image_base + offset_to_data;
        uint64_t end = curr + data_size;
        for (k = 0; k < 16u && curr + 2u <= end; ++k) {
            uint64_t str_len = 0;
            win_load(process, curr, 2u, &str_len);
            curr += 2u;
            if (k == str_idx) {
                if (max_chars == 0) {
                    if (buffer != 0) {
                        win_store(process, buffer, process->emulator->mode == XXEMUL_MODE_X86_64 ? 8u : 4u, curr);
                    }
                    *result = str_len;
                    return 1;
                }
                uint32_t to_copy = (uint32_t)str_len < max_chars - 1u ? (uint32_t)str_len : max_chars - 1u;
                if (buffer != 0) {
                    uint8_t temp[2048];
                    uint32_t bytes_to_copy = to_copy * 2u;
                    if (bytes_to_copy > sizeof(temp)) bytes_to_copy = sizeof(temp);
                    win_read(process, curr, temp, bytes_to_copy);
                    win_write(process, buffer, temp, bytes_to_copy);
                    win_store(process, buffer + (uint64_t)to_copy * 2u, 2u, 0);
                }
                *result = to_copy;
                return 1;
            }
            curr += (uint64_t)str_len * 2u;
        }
    }
    return 0;
}

static xxemul_status win_call(xxemul_windows *process,
    const win_api *api, const uint64_t *arg, uint64_t *result)
{
    const char *name = api->name;
    uint8_t word_size = process->emulator->mode == XXEMUL_MODE_X86_64
        ? 8u : 4u;
    char text[1024];
    xx_io_device *io;
    uint64_t value, address;
    int wide;

    *result = 0;
    if (strcmp(name, "LoadLibraryA") == 0
        || strcmp(name, "LoadLibraryW") == 0
        || strcmp(name, "LoadLibraryExA") == 0
        || strcmp(name, "LoadLibraryExW") == 0
        || strcmp(name, "GetModuleHandleA") == 0
        || strcmp(name, "GetModuleHandleW") == 0) {
        if (arg[0] == 0 && name[0] == 'G') {
            *result = process->image_base;
            return XXEMUL_STATUS_OK;
        }
        wide = win_suffix(name, "W");
        if (!win_guest_string(process, arg[0], text,
                sizeof(text), wide)) return XXEMUL_STATUS_ADDRESS_FAULT;
        *result = win_module_handle(process, text);
        if (*result == 0) process->last_error = 126u;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "GetModuleHandleExW") == 0
        || strcmp(name, "GetModuleHandleExA") == 0) {
        uint64_t mod = 0;
        if (arg[1] == 0) {
            mod = process->image_base;
        } else {
            wide = win_suffix(name, "W");
            if (win_guest_string(process, arg[1], text, sizeof(text), wide))
                mod = win_module_handle(process, text);
        }
        if (mod == 0) mod = process->image_base;
        if (arg[2] != 0) win_store(process, arg[2], word_size, mod);
        *result = 1u;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "GetProcAddress") == 0) {
        const char *module = win_module_name(arg[0]);
        if (module != NULL && arg[1] >= 0x10000u) {
            if (!win_guest_string(process, arg[1], text,
                    sizeof(text), 0)) return XXEMUL_STATUS_ADDRESS_FAULT;
            *result = win_resolve(process, module, text);
        }
        if (*result == 0) process->last_error = 127u;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "__getmainargs") == 0) {
        if (arg[0] == 0u || arg[1] == 0u || arg[2] == 0u) {
            process->last_error = 87u;
            *result = UINT32_MAX;
            return XXEMUL_STATUS_OK;
        }
        if (!win_store(process, arg[0], 4u, process->argc)
            || !win_store(process, arg[1], word_size,
                process->argv_address)
            || !win_store(process, arg[2], word_size,
                process->envp_address))
            return XXEMUL_STATUS_ADDRESS_FAULT;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "__p__acmdln") == 0)
        *result = process->runtime_base + WIN_CRT_DATA_OFFSET + 16u;
    else if (strcmp(name, "__p__commode") == 0)
        *result = process->runtime_base + WIN_CRT_DATA_OFFSET + 24u;
    else if (strcmp(name, "__p__fmode") == 0)
        *result = process->runtime_base + WIN_CRT_DATA_OFFSET + 28u;
    if (strcmp(name, "__p__acmdln") == 0
        || strcmp(name, "__p__commode") == 0
        || strcmp(name, "__p__fmode") == 0)
        return XXEMUL_STATUS_OK;
    if (strcmp(name, "__set_app_type") == 0) {
        process->app_type = (uint32_t)arg[0];
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "__setusermatherr") == 0) {
        process->matherr_handler = arg[0];
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "_onexit") == 0) {
        if (arg[0] != 0u && process->onexit_count < WIN_MAX_ONEXIT) {
            process->onexit_callbacks[process->onexit_count++] = arg[0];
            *result = arg[0];
        }
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "_time64") == 0
        || strcmp(name, "time") == 0) {
        time_t now = time(NULL);
        uint8_t result_size = strcmp(name, "_time64") == 0 ? 8u : 4u;
        *result = now == (time_t)-1 ? UINT64_MAX : (uint64_t)now;
        if (arg[0] != 0u
            && !win_store(process, arg[0], result_size, *result))
            return XXEMUL_STATUS_ADDRESS_FAULT;
        if (word_size == 4u && result_size == 8u)
            process->emulator->x86.gpr[XXEMUL_X86_RDX]
                = (uint32_t)(*result >> 32u);
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "clock") == 0) {
        clock_t ticks = clock();
        if (ticks == (clock_t)-1)
            *result = UINT32_MAX;
        else
            *result = (uint32_t)((uint64_t)ticks * 1000u
                / (uint64_t)CLOCKS_PER_SEC);
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "srand") == 0) {
        process->random_state = (uint32_t)arg[0];
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "rand") == 0) {
        process->random_state = process->random_state
            * UINT32_C(214013) + UINT32_C(2531011);
        *result = (process->random_state >> 16u) & UINT32_C(0x7fff);
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "_get_osfhandle") == 0) {
        uint64_t handle = win_crt_handle(process, arg[0]);
        if (handle != 0u) {
            *result = handle;
            return XXEMUL_STATUS_OK;
        }
        *result = UINT64_MAX;
        return win_crt_errno(process, 9u);
    }
    if (strcmp(name, "_isatty") == 0) {
        if (arg[0] < 3u) {
            *result = 1u;
            return XXEMUL_STATUS_OK;
        }
        *result = 0u;
        return win_crt_errno(process, 9u);
    }
    if (strcmp(name, "_fileno") == 0) {
        uint64_t stride = word_size == 8u ? 48u : 32u;
        uint64_t offset;
        if (arg[0] >= process->iob_address) {
            offset = arg[0] - process->iob_address;
            if (offset < 3u * stride && offset % stride == 0u) {
                *result = offset / stride;
                return XXEMUL_STATUS_OK;
            }
        }
        *result = UINT32_MAX;
        return win_crt_errno(process, 9u);
    }
    if (strcmp(name, "fflush") == 0) {
        uint64_t stride = word_size == 8u ? 48u : 32u;
        uint64_t stream = arg[0];
        if (stream == 0u) {
            if (process->emulator->output_callback == NULL
                && (fflush(stdout) != 0 || fflush(stderr) != 0)) {
                *result = UINT32_MAX;
                return win_crt_errno(process, 9u);
            }
            return XXEMUL_STATUS_OK;
        }
        if (stream >= process->iob_address
            && stream - process->iob_address < 3u * stride
            && (stream - process->iob_address) % stride == 0u) {
            uint64_t index = (stream - process->iob_address) / stride;
            if (index != 0u && process->emulator->output_callback == NULL
                && fflush(index == 1u ? stdout : stderr) != 0) {
                *result = UINT32_MAX;
                return win_crt_errno(process, 9u);
            }
            return XXEMUL_STATUS_OK;
        }
        *result = UINT32_MAX;
        return win_crt_errno(process, 9u);
    }
    if (strcmp(name, "_open") == 0
        || strcmp(name, "_sopen") == 0) {
        uint32_t flags = (uint32_t)arg[1];
        uint32_t access = (flags & 3u) == 2u ? 0xc0000000u
            : (flags & 3u) == 1u ? 0x40000000u : 0x80000000u;
        uint32_t disposition = (flags & 0x100u) != 0u
            ? (flags & 0x400u) != 0u ? 1u
                : (flags & 0x200u) != 0u ? 2u : 4u
            : (flags & 0x200u) != 0u ? 5u : 3u;
        uint64_t handle;
        size_t fd;
        if (!win_guest_string(process, arg[0], text,
                sizeof(text), 0)) return XXEMUL_STATUS_ADDRESS_FAULT;
        handle = win_file_open(process, text, access, disposition);
        if (handle == WIN_INVALID_HANDLE) {
            *result = UINT32_MAX;
            return win_crt_errno(process,
                process->last_error == 2u ? 2u
                    : process->last_error == 4u ? 24u : 13u);
        }
        for (fd = 3u; fd < WIN_MAX_CRT_FDS; ++fd) {
            if (process->crt_fd_handles[fd] == 0u) break;
        }
        if (fd == WIN_MAX_CRT_FDS) {
            (void)win_close_handle(process, handle);
            *result = UINT32_MAX;
            return win_crt_errno(process, 24u);
        }
        process->crt_fd_handles[fd] = handle;
        if ((flags & 8u) != 0u) {
            xx_io_device *opened = win_handle_io(process, handle);
            if (opened == NULL || xx_io_seek64(opened, 0, SEEK_END) != 0) {
                process->crt_fd_handles[fd] = 0u;
                (void)win_close_handle(process, handle);
                *result = UINT32_MAX;
                return win_crt_errno(process, 9u);
            }
        }
        *result = fd;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "_read") == 0) {
        uint64_t handle = win_crt_handle(process, arg[0]);
        xx_io_device *opened = win_handle_io(process, handle);
        uint8_t *bytes;
        ssize_t count;
        if (handle == 0u || (arg[0] != 0u && opened == NULL)) {
            *result = UINT32_MAX;
            return win_crt_errno(process, 9u);
        }
        if (arg[2] > WIN_MAX_IO) {
            *result = UINT32_MAX;
            return win_crt_errno(process, 22u);
        }
        if (arg[0] == 0u) return XXEMUL_STATUS_OK;
        bytes = (uint8_t *)malloc((size_t)(arg[2] == 0u ? 1u : arg[2]));
        if (bytes == NULL) {
            *result = UINT32_MAX;
            return win_crt_errno(process, 12u);
        }
        count = xx_io_read(opened, bytes, (size_t)arg[2]);
        if (count >= 0 && !win_write(process, arg[1], bytes, (size_t)count))
            count = -1;
        free(bytes);
        if (count < 0) {
            *result = UINT32_MAX;
            return win_crt_errno(process, 9u);
        }
        *result = (uint32_t)count;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "_write") == 0) {
        uint64_t handle = win_crt_handle(process, arg[0]);
        xx_io_device *opened = win_handle_io(process, handle);
        uint8_t *bytes;
        ssize_t count;
        size_t index;
        if (handle == 0u || (arg[0] != 1u && arg[0] != 2u
                && opened == NULL)) {
            *result = UINT32_MAX;
            return win_crt_errno(process, 9u);
        }
        if (arg[2] > WIN_MAX_IO) {
            *result = UINT32_MAX;
            return win_crt_errno(process, 22u);
        }
        bytes = (uint8_t *)malloc((size_t)(arg[2] == 0u ? 1u : arg[2]));
        if (bytes == NULL) {
            *result = UINT32_MAX;
            return win_crt_errno(process, 12u);
        }
        if (!win_read(process, arg[1], bytes, (size_t)arg[2])) {
            free(bytes);
            return XXEMUL_STATUS_ADDRESS_FAULT;
        }
        if (arg[0] == 1u || arg[0] == 2u) {
            if (process->emulator->output_callback != NULL) {
                for (index = 0u; index < (size_t)arg[2]; ++index)
                    process->emulator->output_callback(
                        process->emulator->output_context, bytes[index]);
                count = (ssize_t)arg[2];
            } else {
                count = (ssize_t)fwrite(bytes, 1u, (size_t)arg[2],
                    arg[0] == 1u ? stdout : stderr);
            }
        } else {
            count = xx_io_write(opened, bytes, (size_t)arg[2]);
        }
        free(bytes);
        if (count < 0) {
            *result = UINT32_MAX;
            return win_crt_errno(process, 9u);
        }
        *result = (uint32_t)count;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "_close") == 0) {
        uint64_t handle = win_crt_handle(process, arg[0]);
        if (handle == 0u || (arg[0] >= 3u
                && !win_close_handle(process, handle))) {
            *result = UINT32_MAX;
            return win_crt_errno(process, 9u);
        }
        if (arg[0] >= 3u) process->crt_fd_handles[arg[0]] = 0u;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "fputs") == 0) {
        char *str = NULL;
        size_t len = 0u;
        xxemul_status s = win_crt_read_string(process, arg[0], &str, &len);
        if (s != XXEMUL_STATUS_OK || str == NULL) return s;
        if (process->emulator->output_callback != NULL) {
            size_t k;
            for (k = 0; k < len; ++k)
                process->emulator->output_callback(process->emulator->output_context, (uint8_t)str[k]);
        } else {
            fputs(str, stdout);
            fflush(stdout);
        }
        free(str);
        *result = 0u;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "fputc") == 0) {
        uint8_t ch = (uint8_t)arg[0];
        if (process->emulator->output_callback != NULL) {
            process->emulator->output_callback(process->emulator->output_context, ch);
        } else {
            fputc(ch, stdout);
            fflush(stdout);
        }
        *result = ch;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "_lseeki64") == 0) {
        uint64_t handle = win_crt_handle(process, arg[0]);
        xx_io_device *opened = win_handle_io(process, handle);
        int64_t offset = word_size == 8u ? (int64_t)arg[1]
            : (int64_t)((uint64_t)(uint32_t)arg[1]
                | ((uint64_t)(uint32_t)arg[2] << 32u));
        uint64_t origin = word_size == 8u ? arg[2] : arg[3];
        int64_t position;
        int whence = origin == 0u ? SEEK_SET
            : origin == 1u ? SEEK_CUR : SEEK_END;
        if (opened == NULL || origin > 2u
            || xx_io_seek64(opened, offset, whence) != 0
            || (position = xx_io_tell(opened)) < 0) {
            *result = UINT64_MAX;
            return win_crt_errno(process, opened == NULL ? 9u : 22u);
        }
        *result = (uint64_t)position;
        if (word_size == 4u)
            process->emulator->x86.gpr[XXEMUL_X86_RDX]
                = (uint32_t)(*result >> 32u);
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "_stati64") == 0
        || strcmp(name, "_stat64") == 0) {
        char host_path[2048];
        if (!win_guest_string(process, arg[0], text,
                sizeof(text), 0)) return XXEMUL_STATUS_ADDRESS_FAULT;
        if (!win_guest_path(process, text, host_path,
                sizeof(host_path))) {
            *result = UINT32_MAX;
            return win_crt_errno(process, 2u);
        }
        return win_crt_store_stat(process, host_path, arg[1],
            strcmp(name, "_stat64") == 0 ? 8u : word_size, result);
    }
    if (strcmp(name, "_unlink") == 0) {
        char host_path[2048];
        if (!win_guest_string(process, arg[0], text,
                sizeof(text), 0)) return XXEMUL_STATUS_ADDRESS_FAULT;
        if (!win_guest_path(process, text, host_path,
                sizeof(host_path))
            || win_equal(host_path, process->program_path)) {
            *result = UINT32_MAX;
            return win_crt_errno(process, 13u);
        }
        if (!xx_io_file_exists_a(host_path)) {
            *result = UINT32_MAX;
            return win_crt_errno(process, 2u);
        }
        if (!xx_io_file_remove_a(host_path)) {
            *result = UINT32_MAX;
            return win_crt_errno(process, 13u);
        }
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "_chmod") == 0) {
        char host_path[2048];
        int success;
        if (!win_guest_string(process, arg[0], text,
                sizeof(text), 0)) return XXEMUL_STATUS_ADDRESS_FAULT;
        if (!win_guest_path(process, text, host_path,
                sizeof(host_path))
            || win_equal(host_path, process->program_path)) {
            *result = UINT32_MAX;
            return win_crt_errno(process, 13u);
        }
#if defined(_WIN32)
        success = _chmod(host_path, (int)(uint32_t)arg[1]) == 0;
#else
        struct stat attributes;
        success = stat(host_path, &attributes) == 0
            && chmod(host_path, (attributes.st_mode & ~S_IWUSR)
                | (((uint32_t)arg[1] & 0x80u) != 0u ? S_IWUSR : 0u)) == 0;
#endif
        if (!success) {
            *result = UINT32_MAX;
            return win_crt_errno(process,
                errno == ENOENT ? 2u : errno == EACCES ? 13u : 22u);
        }
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "_fstati64") == 0
        || strcmp(name, "_fstat64") == 0) {
        uint64_t handle = win_crt_handle(process, arg[0]);
        win_handle *entry = win_handle_at(process, handle);
        if (entry == NULL || entry->kind != WIN_HANDLE_FILE) {
            *result = UINT32_MAX;
            return win_crt_errno(process, 9u);
        }
        return win_crt_store_stat(process, entry->file_path, arg[1],
            strcmp(name, "_fstat64") == 0 ? 8u : word_size,
            result);
    }
    if (strcmp(name, "__lconv_init") == 0)
        return XXEMUL_STATUS_OK;
    if (strcmp(name, "___lc_codepage_func") == 0) {
        *result = 1252u;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "___mb_cur_max_func") == 0) {
        *result = 1u;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "__iob_func") == 0) {
        *result = process->iob_address;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "_errno") == 0) {
        *result = process->runtime_base + WIN_CRT_DATA_OFFSET + 32u;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "localeconv") == 0) {
        *result = process->runtime_base + WIN_CRT_LOCALE_OFFSET;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "setlocale") == 0) {
        if (arg[1] != 0u) {
            if (!win_guest_string(process, arg[1], text,
                    sizeof(text), 0)) return XXEMUL_STATUS_ADDRESS_FAULT;
            if (strcmp(text, "C") != 0)
                return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
        }
        *result = process->runtime_base + 0xbb03u;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "AddVectoredExceptionHandler") == 0) {
        win_vectored_handler *entry;
        if (arg[1] == 0) {
            process->last_error = 87u;
            return XXEMUL_STATUS_OK;
        }
        if (process->vectored_handler_count >= WIN_MAX_VECTORED_HANDLERS) {
            process->last_error = 8u;
            return XXEMUL_STATUS_OK;
        }
        entry = &process->vectored_handlers[process->vectored_handler_count];
        entry->callback = arg[1];
        entry->first = (uint8_t)(arg[0] != 0);
        entry->active = 1u;
        entry->handle = process->runtime_base + WIN_VECTORED_HANDLE_OFFSET
            + process->vectored_handler_count * 16u;
        ++process->vectored_handler_count;
        *result = entry->handle;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "RemoveVectoredExceptionHandler") == 0) {
        size_t index;
        for (index = 0; index < process->vectored_handler_count; ++index) {
            win_vectored_handler *entry = &process->vectored_handlers[index];
            if (entry->active && entry->handle == arg[0]) {
                entry->active = 0u;
                *result = 1u;
                return XXEMUL_STATUS_OK;
            }
        }
        process->last_error = 6u;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "ExitProcess") == 0
        || strcmp(name, "exit") == 0) {
        process->exit_code = (uint32_t)arg[0];
        process->emulator->exit_code = (uint8_t)arg[0];
        process->emulator->halted = 1;
        return XXEMUL_STATUS_HALTED;
    }
    if (strcmp(name, "RaiseException") == 0) {
        if (arg[0] == 0xe06d7363u) {
            uint64_t exit_code = 0;
            if (arg[3] != 0 && arg[2] >= 2) {
                uint64_t p_obj = 0;
                if (win_load(process, arg[3] + 8u, 8u, &p_obj) && p_obj != 0) {
                    win_load(process, p_obj, 4u, &exit_code);
                }
            }
            process->exit_code = (int32_t)exit_code;
            *result = 0u;
            return XXEMUL_STATUS_HALTED;
        }
        return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    }
    if (strcmp(name, "VirtualProtect") == 0) {
        uint64_t base = process->emulator->region_address;
        uint64_t span = process->emulator->region_size;
        if (arg[0] >= base && arg[1] <= span
            && arg[0] - base <= span - arg[1]
            && win_store(process, arg[3], 4u, 0x40u)) *result = 1u;
        else process->last_error = 487u;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "VirtualAlloc") == 0) {
        if (arg[0] != 0) {
            uint64_t base = process->emulator->region_address;
            uint64_t span = process->emulator->region_size;
            if (arg[0] >= base && arg[1] <= span
                && arg[0] - base <= span - arg[1]) *result = arg[0];
        } else {
            *result = win_heap_alloc(process, arg[1]);
        }
        if (*result == 0) process->last_error = 8u;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "VirtualFree") == 0) {
        uint64_t base = process->emulator->region_address;
        *result = arg[0] >= base
            && arg[0] < base + process->emulator->region_size;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "VirtualQuery") == 0) {
        uint64_t base = process->emulator->region_address;
        uint64_t size = process->emulator->region_size;
        uint64_t query = arg[0];
        uint64_t block_base, block_size;
        uint32_t type;
        uint32_t structure_size = word_size == 8u ? 48u : 28u;
        uint8_t data[48] = {0};
        if (query < base || query - base >= size
            || arg[2] < structure_size) {
            process->last_error = 87u;
            return XXEMUL_STATUS_OK;
        }
        if (query < process->image_base + process->image_size) {
            block_base = process->image_base;
            block_size = process->image_size;
            type = 0x1000000u; /* MEM_IMAGE */
        } else {
            block_base = process->image_base + process->image_size;
            block_size = size - process->image_size;
            type = 0x20000u; /* MEM_PRIVATE */
        }
        if (word_size == 8u) {
            win_put64(data, block_base);
            win_put64(data + 8u, block_base);
            win_put32(data + 16u, 0x40u);
            win_put64(data + 24u, block_size);
            win_put32(data + 32u, 0x1000u);
            win_put32(data + 36u, 0x40u);
            win_put32(data + 40u, type);
        } else {
            win_put32(data, (uint32_t)block_base);
            win_put32(data + 4u, (uint32_t)block_base);
            win_put32(data + 8u, 0x40u);
            win_put32(data + 12u, (uint32_t)block_size);
            win_put32(data + 16u, 0x1000u);
            win_put32(data + 20u, 0x40u);
            win_put32(data + 24u, type);
        }
        if (!win_write(process, arg[1], data, structure_size))
            return XXEMUL_STATUS_ADDRESS_FAULT;
        *result = structure_size;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "GetLastError") == 0) {
        *result = process->last_error;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "SetLastError") == 0) {
        process->last_error = (uint32_t)arg[0];
        address = process->runtime_base + (word_size == 8u ? 0x68u : 0x34u);
        if (!win_store(process, address, 4u, arg[0]))
            return XXEMUL_STATUS_ADDRESS_FAULT;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "GetCommandLineA") == 0) {
        *result = process->command_line_a;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "GetCommandLineW") == 0) {
        *result = process->command_line_w;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "GetModuleFileNameA") == 0
        || strcmp(name, "GetModuleFileNameW") == 0) {
        size_t length = strlen(process->program_path);
        wide = win_suffix(name, "W");
        if (arg[2] == 0) return XXEMUL_STATUS_OK;
        if (length >= arg[2]) length = (size_t)arg[2] - 1u;
        if (wide) {
            char temporary[1024];
            memcpy(temporary, process->program_path, length);
            temporary[length] = '\0';
            if (!win_write_wide(process, arg[1], temporary,
                    (size_t)arg[2])) return XXEMUL_STATUS_ADDRESS_FAULT;
        } else {
            if (!win_write(process, arg[1],
                    process->program_path, length)
                || !win_store(process, arg[1] + length, 1u, 0))
                return XXEMUL_STATUS_ADDRESS_FAULT;
        }
        *result = length;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "GetStdHandle") == 0) {
        uint32_t which = (uint32_t)arg[0];
        *result = which == 0xfffffff6u ? 0x10u
            : which == 0xfffffff5u ? 0x11u
            : which == 0xfffffff4u ? 0x12u : WIN_INVALID_HANDLE;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "GetCurrentProcess") == 0) {
        *result = WIN_INVALID_HANDLE;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "OpenProcess") == 0) {
        *result = win_open_current_process(process,
            (uint32_t)arg[2], (uint32_t)arg[1]);
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "GetCurrentThread") == 0) {
        *result = WIN_INVALID_HANDLE - 1u;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "DuplicateHandle") == 0) {
        uint64_t duplicate;
        if (!win_is_current_process_handle(process, arg[0], word_size)
            || !win_is_current_process_handle(process, arg[2], word_size)
            || arg[3] == 0u) {
            process->last_error = 6u;
            return XXEMUL_STATUS_OK;
        }
        duplicate = win_duplicate_handle(process, arg[1], arg[5] != 0u);
        if (duplicate == 0u) {
            process->last_error = 6u;
            return XXEMUL_STATUS_OK;
        }
        if (!win_store(process, arg[3], word_size, duplicate)) {
            (void)win_close_handle(process, duplicate);
            return XXEMUL_STATUS_ADDRESS_FAULT;
        }
        if ((arg[6] & 1u) != 0u)
            (void)win_close_handle(process, arg[1]);
        *result = 1u;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "GetHandleInformation") == 0) {
        uint32_t flags = 0u;
        if (arg[0] >= 0x100u
            && arg[0] < 0x100u + WIN_MAX_HANDLES
            && win_handle_at(process, arg[0]) != NULL) {
            flags = process->handles[(size_t)(arg[0] - 0x100u)].flags;
        } else if (arg[0] != 0x10u && arg[0] != 0x11u
            && arg[0] != 0x12u) {
            process->last_error = 6u;
            return XXEMUL_STATUS_OK;
        }
        if (!win_store(process, arg[1], 4u, flags))
            return XXEMUL_STATUS_ADDRESS_FAULT;
        *result = 1u;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "GetFileTime") == 0) {
        win_handle *entry = win_handle_at(process, arg[0]);
        uint64_t creation, access, write_time;
        if (entry == NULL || entry->kind != WIN_HANDLE_FILE
            || !win_file_times(entry->file_path,
                &creation, &access, &write_time)) {
            process->last_error = 6u;
            return XXEMUL_STATUS_OK;
        }
        if ((arg[1] != 0u && !win_store(process, arg[1], 8u, creation))
            || (arg[2] != 0u && !win_store(process, arg[2], 8u, access))
            || (arg[3] != 0u && !win_store(process, arg[3],
                8u, write_time)))
            return XXEMUL_STATUS_ADDRESS_FAULT;
        *result = 1u;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "SetFileTime") == 0)
        return win_set_file_times(process,
            win_handle_at(process, arg[0]), arg, result);
    if (strcmp(name, "GetProcessAffinityMask") == 0) {
        if (!win_is_current_process_handle(process, arg[0], word_size)) {
            process->last_error = 6u;
            return XXEMUL_STATUS_OK;
        }
        if (!win_store(process, arg[1], word_size,
                process->process_affinity)
            || !win_store(process, arg[2], word_size, 1u))
            return XXEMUL_STATUS_ADDRESS_FAULT;
        *result = 1u;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "GetThreadPriority") == 0) {
        if (!win_is_current_thread_handle(process, arg[0], word_size)) {
            process->last_error = 6u;
            *result = INT32_MAX;
        } else *result = (uint32_t)process->thread_priority;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "GetThreadContext") == 0) {
        if (!win_is_current_thread_handle(process, arg[0], word_size)) {
            process->last_error = 6u;
            return XXEMUL_STATUS_OK;
        }
        return win_capture_thread_context(process, arg[1],
            word_size, result);
    }
    if (strcmp(name, "ResumeThread") == 0
        || strcmp(name, "SuspendThread") == 0
        || strcmp(name, "SetThreadContext") == 0) {
        if (!win_is_current_thread_handle(process, arg[0], word_size)) {
            process->last_error = 6u;
            *result = strcmp(name, "SetThreadContext") == 0
                ? 0u : UINT32_MAX;
            return XXEMUL_STATUS_OK;
        }
        if (strcmp(name, "ResumeThread") == 0) {
            *result = 0u;
            return XXEMUL_STATUS_OK;
        }
        return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    }
    if (strcmp(name, "IsDBCSLeadByte") == 0) {
        uint8_t character = (uint8_t)arg[0];
#if defined(_WIN32)
        *result = IsDBCSLeadByte(character) != 0;
#else
        *result = 0u;
#endif
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "SetDllDirectoryW") == 0
        || strcmp(name, "SetDllDirectoryA") == 0) {
        *result = 1u;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "AreFileApisANSI") == 0) {
        *result = 1u;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "GetCPInfo") == 0) {
        uint32_t code_page = (uint32_t)arg[0];
        uint8_t buffer[20] = {0};
#if defined(_WIN32)
        CPINFO cp;
        memset(&cp, 0, sizeof(cp));
        if (GetCPInfo(code_page, &cp)) {
            memcpy(buffer, &cp, sizeof(cp));
            *result = 1u;
        } else {
            *result = 0u;
        }
#else
        buffer[0] = 1; /* MaxCharSize = 1 */
        buffer[4] = '?'; /* DefaultChar = '?' */
        *result = 1u;
#endif
        if (*result != 0u && arg[1] != 0u) {
            if (!win_write(process, arg[1], buffer, sizeof(buffer)))
                return XXEMUL_STATUS_ADDRESS_FAULT;
        }
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "IsDBCSLeadByteEx") == 0) {
        uint32_t code_page = (uint32_t)arg[0];
        uint8_t character = (uint8_t)arg[1];
#if defined(_WIN32)
        *result = IsDBCSLeadByteEx(code_page, character) != 0;
#else
        if (code_page <= 3u) code_page = 1252u;
        if (code_page == 932u)
            *result = (character >= 0x81u && character <= 0x9fu)
                || (character >= 0xe0u && character <= 0xfcu);
        else if (code_page == 936u || code_page == 949u
            || code_page == 950u)
            *result = character >= 0x81u && character <= 0xfeu;
        else if (code_page == 1252u || code_page == 65001u)
            *result = 0u;
        else return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
#endif
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "MultiByteToWideChar") == 0)
        return win_multi_byte_to_wide(process, arg, result);
    if (strcmp(name, "WideCharToMultiByte") == 0)
        return win_wide_to_multi_byte(process, arg, result);
    if (strcmp(name, "SetThreadPriority") == 0) {
        int32_t priority = (int32_t)arg[1];
        if (!win_is_current_thread_handle(process, arg[0], word_size))
            process->last_error = 6u;
        else if (priority != -15 && priority != -2
            && priority != -1 && priority != 0 && priority != 1
            && priority != 2 && priority != 15)
            process->last_error = 87u;
        else {
            process->thread_priority = priority;
            *result = 1u;
        }
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "SetUnhandledExceptionFilter") == 0) {
        *result = process->unhandled_filter;
        process->unhandled_filter = arg[0];
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "SetProcessAffinityMask") == 0) {
        if (!win_is_current_process_handle(process, arg[0], word_size))
            process->last_error = 6u;
        else if (arg[1] != 1u) process->last_error = 87u;
        else {
            process->process_affinity = arg[1];
            *result = 1u;
        }
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "TlsAlloc") == 0 || strcmp(name, "FlsAlloc") == 0) {
        if (process->tls_count >= WIN_MAX_TLS_SLOTS) {
            process->last_error = 8u;
            *result = UINT32_MAX;
        } else {
            *result = process->tls_count++;
            process->tls_values[*result] = 0u;
        }
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "TlsGetValue") == 0 || strcmp(name, "FlsGetValue") == 0
        || strcmp(name, "FlsGetValue2") == 0) {
        if (arg[0] >= process->tls_count) {
            process->last_error = 87u;
        } else {
            process->last_error = 0u;
            *result = process->tls_values[arg[0]];
        }
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "TlsSetValue") == 0 || strcmp(name, "FlsSetValue") == 0) {
        if (arg[0] >= process->tls_count) {
            process->last_error = 87u;
        } else {
            process->tls_values[arg[0]] = arg[1];
            *result = 1u;
        }
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "TlsFree") == 0 || strcmp(name, "FlsFree") == 0) {
        *result = 1u;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "GetSystemTimeAsFileTime") == 0) {
        time_t now = time(NULL);
        uint64_t file_time;
        if (now == (time_t)-1) return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
        file_time = (uint64_t)now * UINT64_C(10000000)
            + UINT64_C(116444736000000000);
        if (!win_store(process, arg[0], 8u, file_time))
            return XXEMUL_STATUS_ADDRESS_FAULT;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "IsDebuggerPresent") == 0)
        return XXEMUL_STATUS_OK;
    if (strcmp(name, "DebugBreak") == 0)
        return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    if (strcmp(name, "OutputDebugStringA") == 0) {
        if (!win_guest_string(process, arg[0], text,
                sizeof(text), 0)) return XXEMUL_STATUS_ADDRESS_FAULT;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "InitializeCriticalSection") == 0
        || strcmp(name, "InitializeCriticalSectionAndSpinCount") == 0
        || strcmp(name, "InitializeCriticalSectionEx") == 0) {
        *result = 1u;
        return win_critical_initialize(process, arg[0]);
    }
    if (strcmp(name, "DeleteCriticalSection") == 0
        || strcmp(name, "EnterCriticalSection") == 0
        || strcmp(name, "LeaveCriticalSection") == 0
        || strcmp(name, "TryEnterCriticalSection") == 0) {
        win_critical_section *entry = win_critical_at(process, arg[0]);
        if (entry == NULL) {
            if (strcmp(name, "TryEnterCriticalSection") == 0) *result = 1u;
            return XXEMUL_STATUS_OK;
        }
        if (strcmp(name, "DeleteCriticalSection") == 0) {
            entry->active = 0u;
            return XXEMUL_STATUS_OK;
        }
        if (strcmp(name, "LeaveCriticalSection") == 0) {
            if (entry->recursion > 0u) --entry->recursion;
        } else {
            if (entry->recursion < UINT32_MAX) ++entry->recursion;
            if (strcmp(name, "TryEnterCriticalSection") == 0)
                *result = 1u;
        }
        return win_critical_write(process, entry);
    }
    if (strcmp(name, "AcquireSRWLockExclusive") == 0
        || strcmp(name, "ReleaseSRWLockExclusive") == 0
        || strcmp(name, "AcquireSRWLockShared") == 0
        || strcmp(name, "ReleaseSRWLockShared") == 0
        || strcmp(name, "WakeAllConditionVariable") == 0
        || strcmp(name, "WakeConditionVariable") == 0) {
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "SleepConditionVariableSRW") == 0) {
        *result = 1u;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "InitializeSListHead") == 0) {
        uint8_t zero16[16] = {0};
        if (arg[0] != 0) win_write(process, arg[0], zero16, word_size == 8u ? 16u : 8u);
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "EncodePointer") == 0 || strcmp(name, "DecodePointer") == 0) {
        *result = arg[0];
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "SetErrorMode") == 0) {
        *result = 0u;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "SetPriorityClass") == 0
        || strcmp(name, "SetThreadExecutionState") == 0) {
        *result = 1u;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "CreateEventA") == 0 || strcmp(name, "CreateEventW") == 0) {
        *result = win_create_sync(process, WIN_HANDLE_EVENT,
            arg[1], arg[2], arg[3]);
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "CreateSemaphoreA") == 0 || strcmp(name, "CreateSemaphoreW") == 0) {
        *result = win_create_sync(process, WIN_HANDLE_SEMAPHORE,
            arg[1], arg[2], arg[3]);
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "SetEvent") == 0
        || strcmp(name, "ResetEvent") == 0) {
        win_handle *entry = win_handle_at(process, arg[0]);
        if (entry != NULL && entry->kind == WIN_HANDLE_EVENT) {
            entry->signaled = (uint8_t)(strcmp(name, "SetEvent") == 0);
            *result = 1u;
        } else process->last_error = 6u;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "ReleaseSemaphore") == 0) {
        win_handle *entry = win_handle_at(process, arg[0]);
        if (entry == NULL || entry->kind != WIN_HANDLE_SEMAPHORE) {
            process->last_error = 6u;
        } else if ((int32_t)arg[1] <= 0
            || arg[1] > entry->semaphore_max - entry->semaphore_count) {
            process->last_error = 298u;
        } else if (arg[2] != 0
            && !win_store(process, arg[2], 4u,
                entry->semaphore_count)) {
            return XXEMUL_STATUS_ADDRESS_FAULT;
        } else {
            entry->semaphore_count += (uint32_t)arg[1];
            *result = 1u;
        }
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "WaitForSingleObject") == 0) {
        win_handle *entry = win_handle_at(process, arg[0]);
        if (entry == NULL || entry->kind == WIN_HANDLE_FILE) {
            *result = UINT32_MAX;
            process->last_error = 6u;
        } else if (win_sync_ready(entry)) {
            win_sync_consume(entry);
            *result = 0u;
        } else if ((uint32_t)arg[1] == UINT32_MAX) {
            return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
        } else {
            *result = 0x102u;
        }
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "WaitForMultipleObjects") == 0) {
        win_handle *entries[WIN_MAX_HANDLES];
        uint64_t handle;
        uint32_t count = (uint32_t)arg[0];
        uint32_t index, earlier;
        int all_ready = 1;
        if (count == 0u || count > WIN_MAX_HANDLES || arg[1] == 0u) {
            *result = UINT32_MAX;
            process->last_error = 87u;
            return XXEMUL_STATUS_OK;
        }
        for (index = 0; index < count; ++index) {
            if (!win_load(process, arg[1] + (uint64_t)index * word_size,
                    word_size, &handle))
                return XXEMUL_STATUS_ADDRESS_FAULT;
            entries[index] = win_handle_at(process, handle);
            if (entries[index] == NULL
                || entries[index]->kind == WIN_HANDLE_FILE) {
                *result = UINT32_MAX;
                process->last_error = 6u;
                return XXEMUL_STATUS_OK;
            }
            for (earlier = 0; earlier < index; ++earlier) {
                if (entries[earlier] == entries[index]) {
                    *result = UINT32_MAX;
                    process->last_error = 87u;
                    return XXEMUL_STATUS_OK;
                }
            }
            if (!win_sync_ready(entries[index])) all_ready = 0;
        }
        if (arg[2] != 0u) {
            if (all_ready) {
                for (index = 0; index < count; ++index)
                    win_sync_consume(entries[index]);
                *result = 0u;
            } else if ((uint32_t)arg[3] == UINT32_MAX) {
                return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
            } else *result = 0x102u;
        } else {
            for (index = 0; index < count; ++index) {
                if (win_sync_ready(entries[index])) {
                    win_sync_consume(entries[index]);
                    *result = index;
                    return XXEMUL_STATUS_OK;
                }
            }
            if ((uint32_t)arg[3] == UINT32_MAX)
                return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
            *result = 0x102u;
        }
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "CreateFileA") == 0
        || strcmp(name, "CreateFileW") == 0) {
        if (!win_guest_string(process, arg[0], text,
                sizeof(text), win_suffix(name, "W")))
            return XXEMUL_STATUS_ADDRESS_FAULT;
        *result = win_file_open(process, text,
            (uint32_t)arg[1], (uint32_t)arg[4]);
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "ReadFile") == 0) {
        *result = win_file_read(process,
            arg[0], arg[1], arg[2], arg[3]);
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "WriteFile") == 0) {
        *result = win_file_write(process,
            arg[0], arg[1], arg[2], arg[3]);
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "CloseHandle") == 0) {
        *result = (uint64_t)win_close_handle(process, arg[0]);
        if (*result == 0) process->last_error = 6u;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "SetFilePointer") == 0) {
        io = win_handle_io(process, arg[0]);
        if (io != NULL) {
            int64_t offset = (int32_t)arg[1];
            int whence = arg[3] == 0 ? SEEK_SET
                : arg[3] == 1 ? SEEK_CUR : SEEK_END;
            int64_t position;
            if (arg[2] != 0) {
                if (!win_load(process, arg[2], 4u, &value))
                    return XXEMUL_STATUS_ADDRESS_FAULT;
                offset = (int64_t)((uint64_t)(uint32_t)offset
                    | ((uint64_t)(uint32_t)value << 32));
            }
            if (xx_io_seek64(io, offset, whence) == 0
                && (position = xx_io_tell(io)) >= 0
                && (arg[2] == 0
                    || win_store(process, arg[2], 4u,
                        (uint32_t)((uint64_t)position >> 32)))) {
                *result = (uint32_t)position;
                return XXEMUL_STATUS_OK;
            }
        }
        *result = WIN_INVALID_HANDLE;
        process->last_error = 6u;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "SetFilePointerEx") == 0) {
        uint64_t output = word_size == 8u ? arg[2] : arg[3];
        uint64_t method = word_size == 8u ? arg[3] : arg[4];
        int64_t distance = word_size == 8u
            ? (int64_t)arg[1]
            : (int64_t)((uint64_t)(uint32_t)arg[1]
                | ((uint64_t)(uint32_t)arg[2] << 32));
        int whence = method == 0 ? SEEK_SET
            : method == 1 ? SEEK_CUR : SEEK_END;
        int64_t position;
        io = win_handle_io(process, arg[0]);
        if (io != NULL && method <= 2u
            && xx_io_seek64(io, distance, whence) == 0
            && (position = xx_io_tell(io)) >= 0
            && (output == 0
                || win_store(process, output, 8u, (uint64_t)position)))
            *result = 1u;
        else process->last_error = 6u;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "GetFileSize") == 0
        || strcmp(name, "GetFileSizeEx") == 0) {
        io = win_handle_io(process, arg[0]);
        if (io == NULL || (value = (uint64_t)xx_io_total_size(io))
            == UINT64_MAX) {
            process->last_error = 6u;
            *result = WIN_INVALID_HANDLE;
        } else if (strcmp(name, "GetFileSizeEx") == 0) {
            if (!win_store(process, arg[1], 8u, value))
                return XXEMUL_STATUS_ADDRESS_FAULT;
            *result = 1u;
        } else {
            if (arg[1] != 0 && !win_store(process,
                    arg[1], 4u, value >> 32))
                return XXEMUL_STATUS_ADDRESS_FAULT;
            *result = (uint32_t)value;
        }
        return XXEMUL_STATUS_OK;
    }
#if defined(_WIN32)
    if (strcmp(name, "GetFileAttributesW") == 0
        || strcmp(name, "GetFileAttributesA") == 0) {
        wide = win_suffix(name, "W");
        if (!win_guest_string(process, arg[0], text, sizeof(text), wide))
            return XXEMUL_STATUS_ADDRESS_FAULT;
        *result = (uint64_t)GetFileAttributesA(text);
        if (*result == (uint64_t)INVALID_FILE_ATTRIBUTES) {
            *result = (uint32_t)INVALID_FILE_ATTRIBUTES;
            process->last_error = GetLastError();
        }
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "FindFirstFileW") == 0
        || strcmp(name, "FindFirstFileExW") == 0) {
        wchar_t wpath[MAX_PATH];
        WIN32_FIND_DATAW fd;
        HANDLE h;
        uint64_t data_addr = strcmp(name, "FindFirstFileExW") == 0 ? arg[2] : arg[1];
        if (!win_guest_string(process, arg[0], text, sizeof(text), 1))
            return XXEMUL_STATUS_ADDRESS_FAULT;
        MultiByteToWideChar(CP_UTF8, 0, text, -1, wpath, MAX_PATH);
        h = FindFirstFileW(wpath, &fd);
        if (h == INVALID_HANDLE_VALUE) {
            process->last_error = GetLastError();
            *result = (uint64_t)INVALID_HANDLE_VALUE;
            return XXEMUL_STATUS_OK;
        }
        if (!win_write(process, data_addr, (const uint8_t *)&fd, sizeof(fd))) {
            FindClose(h);
            return XXEMUL_STATUS_ADDRESS_FAULT;
        }
        *result = (uint64_t)(uintptr_t)h;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "FindNextFileW") == 0) {
        WIN32_FIND_DATAW fd;
        BOOL ok = FindNextFileW((HANDLE)(uintptr_t)arg[0], &fd);
        if (!ok) {
            process->last_error = GetLastError();
            *result = 0;
            return XXEMUL_STATUS_OK;
        }
        if (!win_write(process, arg[1], (const uint8_t *)&fd, sizeof(fd)))
            return XXEMUL_STATUS_ADDRESS_FAULT;
        *result = 1;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "FindFirstFileA") == 0) {
        WIN32_FIND_DATAA fd;
        HANDLE h;
        if (!win_guest_string(process, arg[0], text, sizeof(text), 0))
            return XXEMUL_STATUS_ADDRESS_FAULT;
        h = FindFirstFileA(text, &fd);
        if (h == INVALID_HANDLE_VALUE) {
            process->last_error = GetLastError();
            *result = (uint64_t)INVALID_HANDLE_VALUE;
            return XXEMUL_STATUS_OK;
        }
        if (!win_write(process, arg[1], (const uint8_t *)&fd, sizeof(fd))) {
            FindClose(h);
            return XXEMUL_STATUS_ADDRESS_FAULT;
        }
        *result = (uint64_t)(uintptr_t)h;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "FindNextFileA") == 0) {
        WIN32_FIND_DATAA fd;
        BOOL ok = FindNextFileA((HANDLE)(uintptr_t)arg[0], &fd);
        if (!ok) {
            process->last_error = GetLastError();
            *result = 0;
            return XXEMUL_STATUS_OK;
        }
        if (!win_write(process, arg[1], (const uint8_t *)&fd, sizeof(fd)))
            return XXEMUL_STATUS_ADDRESS_FAULT;
        *result = 1;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "FileTimeToLocalFileTime") == 0) {
        FILETIME ft_in, ft_out;
        if (!win_read(process, arg[0], (uint8_t *)&ft_in, sizeof(ft_in)))
            return XXEMUL_STATUS_ADDRESS_FAULT;
        FileTimeToLocalFileTime(&ft_in, &ft_out);
        if (!win_write(process, arg[1], (const uint8_t *)&ft_out, sizeof(ft_out)))
            return XXEMUL_STATUS_ADDRESS_FAULT;
        *result = 1;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "FileTimeToDosDateTime") == 0) {
        FILETIME ft;
        WORD fat_date = 0, fat_time = 0;
        if (!win_read(process, arg[0], (uint8_t *)&ft, sizeof(ft)))
            return XXEMUL_STATUS_ADDRESS_FAULT;
        FileTimeToDosDateTime(&ft, &fat_date, &fat_time);
        if (arg[1] != 0) win_store(process, arg[1], 2u, fat_date);
        if (arg[2] != 0) win_store(process, arg[2], 2u, fat_time);
        *result = 1;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "FindClose") == 0) {
        if (arg[0] != 0 && arg[0] != (uint64_t)INVALID_HANDLE_VALUE)
            FindClose((HANDLE)(uintptr_t)arg[0]);
        *result = 1;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "GetFileInformationByHandle") == 0) {
        BY_HANDLE_FILE_INFORMATION info;
        memset(&info, 0, sizeof(info));
        io = win_handle_io(process, arg[0]);
        if (io != NULL) {
            int64_t sz = xx_io_size(io);
            if (sz >= 0) {
                info.nFileSizeLow = (DWORD)sz;
                info.nFileSizeHigh = (DWORD)((uint64_t)sz >> 32);
            }
            info.dwFileAttributes = FILE_ATTRIBUTE_NORMAL;
            info.nNumberOfLinks = 1;
            if (!win_write(process, arg[1], (const uint8_t *)&info, sizeof(info)))
                return XXEMUL_STATUS_ADDRESS_FAULT;
            *result = 1;
            return XXEMUL_STATUS_OK;
        }
        process->last_error = 6u;
        *result = 0;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "SetEndOfFile") == 0) {
        *result = 1;
        return XXEMUL_STATUS_OK;
    }
#endif
    if (strcmp(name, "GetFileType") == 0) {
        *result = arg[0] == 0x10u || arg[0] == 0x11u
            || arg[0] == 0x12u ? 2u
            : win_handle_io(process, arg[0]) != NULL ? 1u : 0u;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "FlushFileBuffers") == 0) {
        *result = arg[0] == 0x11u || arg[0] == 0x12u
            || win_handle_io(process, arg[0]) != NULL;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "GetProcessHeap") == 0) {
        *result = 0x400u;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "HeapAlloc") == 0) {
        *result = win_heap_alloc(process, arg[2]);
        if (*result == 0) process->last_error = 8u;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "HeapReAlloc") == 0) {
        win_allocation *allocation = win_find_allocation(process, arg[2]);
        if (allocation != NULL) {
            if (arg[3] <= allocation->size) {
                allocation->size = arg[3];
                *result = arg[2];
            } else {
                uint64_t old_size = allocation->size;
                *result = win_heap_alloc(process, arg[3]);
                if (*result != 0) {
                    uint64_t base = process->emulator->region_address;
                    memcpy(process->emulator->region_data
                            + (size_t)(*result - base),
                        process->emulator->region_data
                            + (size_t)(arg[2] - base), (size_t)old_size);
                    allocation->active = 0u;
                }
            }
        }
        if (*result == 0) process->last_error = 8u;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "HeapFree") == 0) {
        win_allocation *allocation = win_find_allocation(process, arg[2]);
        if (allocation != NULL) {
            allocation->active = 0u;
            *result = 1u;
        }
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "HeapSize") == 0) {
        win_allocation *allocation = win_find_allocation(process, arg[2]);
        *result = allocation == NULL ? WIN_INVALID_HANDLE
            : allocation->size;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "LocalAlloc") == 0
        || strcmp(name, "GlobalAlloc") == 0) {
        *result = win_heap_alloc(process, arg[1]);
        if (*result == 0) process->last_error = 8u;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "LocalFree") == 0
        || strcmp(name, "GlobalFree") == 0) {
        win_allocation *allocation = win_find_allocation(process, arg[0]);
        if (allocation != NULL) allocation->active = 0u;
        *result = 0;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "GlobalLock") == 0) {
        *result = arg[0];
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "GlobalUnlock") == 0) {
        *result = 0;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "GetCurrentDirectoryA") == 0
        || strcmp(name, "GetCurrentDirectoryW") == 0) {
        size_t length = strlen(process->working_directory);
        wide = win_suffix(name, "W");
        *result = length + 1u > arg[0] ? length + 1u : length;
        if (length + 1u > arg[0] || arg[1] == 0) return XXEMUL_STATUS_OK;
        if ((wide && !win_write_wide(process, arg[1],
                process->working_directory, (size_t)arg[0]))
            || (!wide && !win_write(process, arg[1],
                process->working_directory, length + 1u)))
            return XXEMUL_STATUS_ADDRESS_FAULT;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "GetEnvironmentStringsA") == 0) {
        *result = process->environment_a;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "GetEnvironmentStringsW") == 0) {
        *result = process->runtime_base + 0x7c00u;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "FreeEnvironmentStringsA") == 0
        || strcmp(name, "FreeEnvironmentStringsW") == 0) {
        *result = 1u;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "GetTickCount") == 0) {
#if defined(_WIN32)
        *result = (uint32_t)GetTickCount();
#else
        process->virtual_tick += 10u;
        *result = process->virtual_tick;
#endif
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "Sleep") == 0) {
        if ((uint32_t)arg[0] == UINT32_MAX)
            return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
        process->virtual_tick += (uint32_t)arg[0];
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "GetCurrentProcessId") == 0
        || strcmp(name, "GetCurrentThreadId") == 0) {
        *result = 1u;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "GetVersion") == 0) {
        *result = 0x0a000006u;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "GetFileVersionInfoSizeA") == 0
        || strcmp(name, "GetFileVersionInfoA") == 0) {
        process->last_error = 1813u;
        *result = 0u;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "CreateProcessA") == 0
        || strcmp(name, "CreateProcessW") == 0) {
        char cmd[512] = {0};
        size_t i;
        win_guest_string(process, arg[1] ? arg[1] : arg[0], cmd, sizeof(cmd), strcmp(name, "CreateProcessW") == 0);
        fprintf(stderr, "[CreateProcess] cmd='%s'\n", cmd);

        /* Find pipe read handle to provide mock output to */
        for (i = 0; i < WIN_MAX_HANDLES; ++i) {
            if (process->handles[i].in_use && process->handles[i].kind == WIN_HANDLE_FILE
                && process->handles[i].file_path[0] == '\0' && process->handles[i].io == NULL) {
                if (strstr(cmd, "gdb") != NULL) {
                    static const char gdb_banner[] = "GNU gdb (GDB) 7.2\r\n(gdb) \r\n";
                    process->handles[i].io = xx_io_mem_open_ro(gdb_banner, strlen(gdb_banner));
                    break;
                } else if (strstr(cmd, "fpc") != NULL) {
                    static const char fpc_banner[] = "Free Pascal Compiler version 3.2.2 [2021/05/15] for i386\r\n";
                    process->handles[i].io = xx_io_mem_open_ro(fpc_banner, strlen(fpc_banner));
                    break;
                }
            }
        }

        /* Fill PROCESS_INFORMATION */
        if (arg[9] != 0) {
            size_t proc_slot = WIN_MAX_HANDLES, thread_slot = WIN_MAX_HANDLES, s;
            for (s = 0; s < WIN_MAX_HANDLES; ++s) {
                if (!process->handles[s].in_use) {
                    if (proc_slot == WIN_MAX_HANDLES) proc_slot = s;
                    else if (thread_slot == WIN_MAX_HANDLES) { thread_slot = s; break; }
                }
            }
            if (proc_slot < WIN_MAX_HANDLES) {
                memset(&process->handles[proc_slot], 0, sizeof(process->handles[proc_slot]));
                process->handles[proc_slot].kind = WIN_HANDLE_PROCESS;
                process->handles[proc_slot].references = 1u;
                process->handles[proc_slot].root_slot = (uint16_t)proc_slot;
                process->handles[proc_slot].in_use = 1u;
            }
            if (thread_slot < WIN_MAX_HANDLES) {
                memset(&process->handles[thread_slot], 0, sizeof(process->handles[thread_slot]));
                process->handles[thread_slot].kind = WIN_HANDLE_THREAD;
                process->handles[thread_slot].references = 1u;
                process->handles[thread_slot].root_slot = (uint16_t)thread_slot;
                process->handles[thread_slot].in_use = 1u;
            }
            win_store(process, arg[9], word_size, 0x100u + (proc_slot < WIN_MAX_HANDLES ? proc_slot : 0));
            win_store(process, arg[9] + word_size, word_size, 0x100u + (thread_slot < WIN_MAX_HANDLES ? thread_slot : 0));
            win_store(process, arg[9] + word_size * 2, 4u, 1234u);
            win_store(process, arg[9] + word_size * 2 + 4u, 4u, 5678u);
        }
        *result = 1u;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "CreatePipe") == 0) {
        size_t r = WIN_MAX_HANDLES, w = WIN_MAX_HANDLES, i;
        for (i = 0; i < WIN_MAX_HANDLES; ++i) {
            if (!process->handles[i].in_use) {
                if (r == WIN_MAX_HANDLES) r = i;
                else if (w == WIN_MAX_HANDLES) { w = i; break; }
            }
        }
        if (r == WIN_MAX_HANDLES || w == WIN_MAX_HANDLES) {
            process->last_error = 4u;
            *result = 0u;
            return XXEMUL_STATUS_OK;
        }
        memset(&process->handles[r], 0, sizeof(process->handles[r]));
        process->handles[r].kind = WIN_HANDLE_FILE;
        process->handles[r].references = 1u;
        process->handles[r].root_slot = (uint16_t)w;
        process->handles[r].in_use = 1u;

        memset(&process->handles[w], 0, sizeof(process->handles[w]));
        process->handles[w].kind = WIN_HANDLE_FILE;
        process->handles[w].references = 1u;
        process->handles[w].root_slot = (uint16_t)r;
        process->handles[w].in_use = 1u;

        if (arg[0] != 0) win_store(process, arg[0], word_size, 0x100u + r);
        if (arg[1] != 0) win_store(process, arg[1], word_size, 0x100u + w);
        *result = 1u;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "PeekNamedPipe") == 0) {
        uint32_t avail = 0;
        io = win_handle_io(process, arg[0]);
        if (io != NULL) {
            int64_t total = xx_io_size(io);
            int64_t cur = xx_io_tell(io);
            if (total > cur) avail = (uint32_t)(total - cur);
        }
        if (arg[1] != 0 && avail > 0 && (uint32_t)arg[2] > 0) {
            uint32_t to_read = (uint32_t)arg[2] < avail ? (uint32_t)arg[2] : avail;
            uint8_t *tmp = (uint8_t *)malloc(to_read);
            if (tmp != NULL) {
                int64_t pos = xx_io_tell(io);
                xx_io_read(io, tmp, to_read);
                xx_io_seek64(io, pos, SEEK_SET);
                win_write(process, arg[1], tmp, to_read);
                free(tmp);
            }
        }
        if (arg[3] != 0) win_store(process, arg[3], 4u, 0u);
        if (arg[4] != 0) win_store(process, arg[4], 4u, avail);
        if (arg[5] != 0) win_store(process, arg[5], 4u, avail);
        *result = 1u;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "GetExitCodeProcess") == 0) {
        if (arg[1] != 0) win_store(process, arg[1], 4u, 0u);
        *result = 1u;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "DuplicateHandle") == 0) {
        if (arg[3] != 0) win_store(process, arg[3], word_size, arg[1]);
        *result = 1u;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "GetVersionExA") == 0
        || strcmp(name, "GetVersionExW") == 0) {
        if (arg[0] == 0) return XXEMUL_STATUS_ADDRESS_FAULT;
        win_store(process, arg[0] + 4u, 4u, 10u);
        win_store(process, arg[0] + 8u, 4u, 0u);
        win_store(process, arg[0] + 12u, 4u, 19045u);
        win_store(process, arg[0] + 16u, 4u, 2u);
        uint8_t zero256[256] = {0};
        win_write(process, arg[0] + 20u, zero256,
            strcmp(name, "GetVersionExW") == 0 ? 256u : 128u);
        *result = 1u;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "SysAllocStringLen") == 0) {
        uint64_t psz = arg[0];
        uint32_t len = (uint32_t)arg[1];
        uint32_t byte_len = len * 2u;
        uint64_t alloc = win_heap_alloc(process, (uint64_t)byte_len + 6u);
        if (alloc == 0) {
            *result = 0;
            return XXEMUL_STATUS_OK;
        }
        win_store(process, alloc, 4u, byte_len);
        uint64_t bstr = alloc + 4u;
        if (psz != 0) {
            uint8_t buf[512];
            uint32_t copied = 0;
            while (copied < byte_len) {
                uint32_t chunk = byte_len - copied;
                if (chunk > (uint32_t)sizeof(buf)) chunk = (uint32_t)sizeof(buf);
                if (!win_read(process, psz + copied, buf, chunk)) break;
                win_write(process, bstr + copied, buf, chunk);
                copied += chunk;
            }
        }
        win_store(process, bstr + byte_len, 2u, 0u);
        *result = bstr;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "SysFreeString") == 0) {
        uint64_t bstr = arg[0];
        if (bstr >= 4u) {
            win_allocation *allocation = win_find_allocation(process, bstr - 4u);
            if (allocation != NULL) allocation->active = 0u;
        }
        *result = 0;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "SysReAllocStringLen") == 0) {
        uint64_t pbstr = arg[0];
        uint64_t psz = arg[1];
        uint32_t len = (uint32_t)arg[2];
        if (pbstr == 0) {
            *result = 0;
            return XXEMUL_STATUS_OK;
        }
        uint32_t byte_len = len * 2u;
        uint64_t alloc = win_heap_alloc(process, (uint64_t)byte_len + 6u);
        if (alloc == 0) {
            *result = 0;
            return XXEMUL_STATUS_OK;
        }
        win_store(process, alloc, 4u, byte_len);
        uint64_t bstr = alloc + 4u;
        if (psz != 0) {
            uint8_t buf[512];
            uint32_t copied = 0;
            while (copied < byte_len) {
                uint32_t chunk = byte_len - copied;
                if (chunk > (uint32_t)sizeof(buf)) chunk = (uint32_t)sizeof(buf);
                if (!win_read(process, psz + copied, buf, chunk)) break;
                win_write(process, bstr + copied, buf, chunk);
                copied += chunk;
            }
        }
        win_store(process, bstr + byte_len, 2u, 0u);
        uint64_t old_bstr = 0;
        win_load(process, pbstr, word_size, &old_bstr);
        if (old_bstr >= 4u) {
            win_allocation *allocation = win_find_allocation(process, old_bstr - 4u);
            if (allocation != NULL) allocation->active = 0u;
        }
        win_store(process, pbstr, word_size, bstr);
        *result = 1u;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "GetProcessHeap") == 0) {
        *result = 0x10000u;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "GetCurrentProcess") == 0) {
        *result = (uint64_t)(int64_t)-1;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "GetCurrentThread") == 0) {
        *result = (uint64_t)(int64_t)-2;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "GetConsoleCP") == 0) {
        *result = 1252u;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "IsDebuggerPresent") == 0) {
        *result = 0u;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "GetUserDefaultLCID") == 0 || strcmp(name, "GetThreadLocale") == 0) {
        *result = 0x0409u;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "SetThreadLocale") == 0
        || strcmp(name, "SetConsoleCP") == 0
        || strcmp(name, "SetConsoleActiveScreenBuffer") == 0
        || strcmp(name, "FlushConsoleInputBuffer") == 0
        || strcmp(name, "SetConsoleScreenBufferSize") == 0
        || strcmp(name, "SetConsoleWindowInfo") == 0
        || strcmp(name, "AllocConsole") == 0
        || strcmp(name, "FreeConsole") == 0
        || strcmp(name, "FreeLibrary") == 0) {
        *result = 1u;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "GetNumberOfConsoleMouseButtons") == 0) {
        if (arg[0] != 0) win_store(process, arg[0], 4u, 3u);
        *result = 1u;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "GetLocalTime") == 0) {
#if defined(_WIN32)
        SYSTEMTIME st;
        GetLocalTime(&st);
        win_write(process, arg[0], (const uint8_t *)&st, sizeof(st));
#else
        uint8_t zero16[16] = {0};
        win_write(process, arg[0], zero16, 16u);
#endif
        *result = 0;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "GetACP") == 0
        || strcmp(name, "GetOEMCP") == 0
        || strcmp(name, "GetConsoleOutputCP") == 0) {
        *result = 1252u;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "GetConsoleCursorInfo") == 0) {
        if (arg[0] != 0x11u && arg[0] != 0x12u) {
            process->last_error = 6u;
            return XXEMUL_STATUS_OK;
        }
        if (!win_store(process, arg[1], 4u, process->console_cursor_size)
            || !win_store(process, arg[1] + 4u, 4u,
                process->console_cursor_visible))
            return XXEMUL_STATUS_ADDRESS_FAULT;
        *result = 1u;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "WriteConsoleOutputA") == 0)
        return win_console_transfer(process, arg, result, 0);
    if (strcmp(name, "ReadConsoleOutputA") == 0)
        return win_console_transfer(process, arg, result, 1);
    if (strcmp(name, "ScrollConsoleScreenBufferA") == 0)
        return win_console_scroll(process, arg, result);
    if (strcmp(name, "GetConsoleScreenBufferInfo") == 0) {
        uint8_t info[22] = {0};
        uint16_t fields[] = {
            80u, 25u, process->console_cursor_x,
            process->console_cursor_y, process->console_attributes,
            0u, 0u, 79u, 24u, 80u, 25u
        };
        size_t index;
        if (arg[0] != 0x11u && arg[0] != 0x12u) {
            process->last_error = 6u;
            return XXEMUL_STATUS_OK;
        }
        for (index = 0; index < 11u; ++index) {
            info[index * 2u] = (uint8_t)fields[index];
            info[index * 2u + 1u] = (uint8_t)(fields[index] >> 8);
        }
        if (!win_write(process, arg[1], info, sizeof(info)))
            return XXEMUL_STATUS_ADDRESS_FAULT;
        *result = 1u;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "SetConsoleCursorInfo") == 0) {
        uint64_t size, visible;
        if (arg[0] != 0x11u && arg[0] != 0x12u) {
            process->last_error = 6u;
            return XXEMUL_STATUS_OK;
        }
        if (!win_load(process, arg[1], 4u, &size)
            || !win_load(process, arg[1] + 4u, 4u, &visible))
            return XXEMUL_STATUS_ADDRESS_FAULT;
        if (size == 0u || size > 100u) {
            process->last_error = 87u;
            return XXEMUL_STATUS_OK;
        }
        process->console_cursor_size = (uint8_t)size;
        process->console_cursor_visible = (uint8_t)(visible != 0u);
        *result = 1u;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "SetConsoleCursorPosition") == 0) {
        uint16_t x = (uint16_t)arg[1];
        uint16_t y = (uint16_t)(arg[1] >> 16);
        if (arg[0] != 0x11u && arg[0] != 0x12u) {
            process->last_error = 6u;
            return XXEMUL_STATUS_OK;
        }
        if (x >= 80u || y >= 25u) {
            process->last_error = 87u;
            return XXEMUL_STATUS_OK;
        }
        process->console_cursor_x = x;
        process->console_cursor_y = y;
        *result = 1u;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "SetConsoleTextAttribute") == 0) {
        if (arg[0] != 0x11u && arg[0] != 0x12u) {
            process->last_error = 6u;
            return XXEMUL_STATUS_OK;
        }
        process->console_attributes = (uint16_t)arg[1];
        *result = 1u;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "GetConsoleMode") == 0) {
        if (arg[0] < 0x10u || arg[0] > 0x12u) {
            process->last_error = 6u;
            return XXEMUL_STATUS_OK;
        }
        if (!win_store(process, arg[1], 4u, arg[0] == 0x10u
                ? process->console_input_mode
                : process->console_output_mode))
            return XXEMUL_STATUS_ADDRESS_FAULT;
        *result = 1u;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "SetConsoleMode") == 0) {
        if (arg[0] < 0x10u || arg[0] > 0x12u) {
            process->last_error = 6u;
            return XXEMUL_STATUS_OK;
        }
        if (arg[0] == 0x10u)
            process->console_input_mode = (uint32_t)arg[1];
        else process->console_output_mode = (uint32_t)arg[1];
        *result = 1u;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "GetStartupInfoA") == 0
        || strcmp(name, "GetStartupInfoW") == 0) {
        if (!win_store(process, arg[0], 4u, word_size == 8u ? 104u : 68u))
            return XXEMUL_STATUS_ADDRESS_FAULT;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "GetSystemInfo") == 0) {
        if (process->emulator->mode == XXEMUL_MODE_X86_64) {
            win_store(process, arg[0], 2u, 9u);
            win_store(process, arg[0] + 4u, 4u, 4096u);
            win_store(process, arg[0] + 8u, 8u, 0x10000u);
            win_store(process, arg[0] + 16u, 8u, UINT64_C(0x7ffffffeffff));
            win_store(process, arg[0] + 24u, 8u, 0x0fu);
            win_store(process, arg[0] + 32u, 4u, 4u);
            win_store(process, arg[0] + 36u, 4u, 8664u);
            win_store(process, arg[0] + 40u, 4u, 65536u);
            win_store(process, arg[0] + 44u, 2u, 6u);
        } else {
            win_store(process, arg[0], 2u, 0u);
            win_store(process, arg[0] + 4u, 4u, 4096u);
            win_store(process, arg[0] + 8u, 4u, 0x10000u);
            win_store(process, arg[0] + 12u, 4u, 0x0fu);
            win_store(process, arg[0] + 16u, 4u, 4u);
            win_store(process, arg[0] + 20u, 4u, 586u);
            win_store(process, arg[0] + 24u, 4u, 65536u);
            win_store(process, arg[0] + 28u, 2u, 6u);
        }
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "GetActiveProcessorGroupCount") == 0) {
        *result = 1u;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "GetActiveProcessorCount") == 0) {
        *result = 4u;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "QueryPerformanceFrequency") == 0) {
        if (!win_store(process, arg[0], 8u, 1000000u))
            return XXEMUL_STATUS_ADDRESS_FAULT;
        *result = 1u;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "QueryPerformanceCounter") == 0) {
        process->virtual_tick += 500u;
        if (!win_store(process, arg[0], 8u, (uint64_t)process->virtual_tick * 1000u))
            return XXEMUL_STATUS_ADDRESS_FAULT;
        *result = 1u;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "malloc") == 0
        || strcmp(name, "calloc") == 0) {
        uint64_t bytes = arg[0];
        xxemul_status fill_status;
        if (strcmp(name, "calloc") == 0) {
            if (arg[1] != 0u && bytes > UINT64_MAX / arg[1]) {
                return win_crt_errno(process, 12u);
            }
            bytes *= arg[1];
        }
        *result = win_heap_alloc(process, bytes);
        if (*result == 0u) return win_crt_errno(process, 12u);
        if (strcmp(name, "calloc") == 0) {
            fill_status = win_crt_fill(process, *result, 0u, bytes);
            if (fill_status != XXEMUL_STATUS_OK) return fill_status;
        }
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "free") == 0) {
        win_allocation *allocation;
        if (arg[0] == 0u) return XXEMUL_STATUS_OK;
        allocation = win_find_allocation(process, arg[0]);
        if (allocation == NULL)
            return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
        allocation->active = 0u;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "realloc") == 0) {
        win_allocation *allocation;
        xxemul_status copy_status;
        uint64_t old_size;
        if (arg[0] == 0u) {
            *result = win_heap_alloc(process, arg[1]);
            return *result != 0u ? XXEMUL_STATUS_OK
                : win_crt_errno(process, 12u);
        }
        allocation = win_find_allocation(process, arg[0]);
        if (allocation == NULL)
            return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
        if (arg[1] == 0u) {
            allocation->active = 0u;
            return XXEMUL_STATUS_OK;
        }
        if (arg[1] <= allocation->size) {
            allocation->size = arg[1];
            *result = arg[0];
            return XXEMUL_STATUS_OK;
        }
        old_size = allocation->size;
        *result = win_heap_alloc(process, arg[1]);
        if (*result == 0u) return win_crt_errno(process, 12u);
        copy_status = win_crt_copy(process, *result, arg[0], old_size);
        if (copy_status != XXEMUL_STATUS_OK) return copy_status;
        allocation->active = 0u;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "memcpy") == 0
        || strcmp(name, "memmove") == 0) {
        xxemul_status copy_status = win_crt_copy(process,
            arg[0], arg[1], arg[2]);
        if (copy_status == XXEMUL_STATUS_OK) *result = arg[0];
        return copy_status;
    }
    if (strcmp(name, "memset") == 0) {
        xxemul_status fill_status = win_crt_fill(process,
            arg[0], (uint8_t)arg[1], arg[2]);
        if (fill_status == XXEMUL_STATUS_OK) *result = arg[0];
        return fill_status;
    }
    if (strcmp(name, "memcmp") == 0
        || strcmp(name, "memchr") == 0) {
        uint8_t first[4096], second[4096];
        uint64_t offset;
        if (arg[2] > WIN_MAX_IO)
            return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
        for (offset = 0u; offset < arg[2];) {
            size_t chunk = (size_t)(arg[2] - offset > sizeof(first)
                ? sizeof(first) : arg[2] - offset);
            if (!win_read(process, arg[0] + offset, first, chunk))
                return XXEMUL_STATUS_ADDRESS_FAULT;
            if (strcmp(name, "memchr") == 0) {
                const uint8_t *found = (const uint8_t *)memchr(first,
                    (uint8_t)arg[1], chunk);
                if (found != NULL) {
                    *result = arg[0] + offset + (size_t)(found - first);
                    return XXEMUL_STATUS_OK;
                }
            } else {
                int difference;
                if (!win_read(process, arg[1] + offset,
                        second, chunk))
                    return XXEMUL_STATUS_ADDRESS_FAULT;
                difference = memcmp(first, second, chunk);
                if (difference != 0) {
                    *result = (uint32_t)difference;
                    return XXEMUL_STATUS_OK;
                }
            }
            offset += chunk;
        }
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "strlen") == 0) {
        uint64_t character;
        for (*result = 0u; *result < WIN_MAX_IO; ++*result) {
            if (!win_load(process, arg[0] + *result,
                    1u, &character)) return XXEMUL_STATUS_ADDRESS_FAULT;
            if (character == 0u) return XXEMUL_STATUS_OK;
        }
        return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    }
    if (strcmp(name, "wcslen") == 0)
        return win_crt_string_length(process, arg[0], 2u, result);
    if (strcmp(name, "strcmp") == 0
        || strcmp(name, "strncmp") == 0
        || strcmp(name, "_stricmp") == 0)
        return win_crt_compare_strings(process, arg[0], arg[1],
            strcmp(name, "strncmp") == 0 ? arg[2] : UINT64_MAX,
            strcmp(name, "_stricmp") == 0, result);
    if (strcmp(name, "strcpy") == 0
        || strcmp(name, "_strdup") == 0) {
        uint64_t length;
        xxemul_status string_status = win_crt_string_length(process,
            arg[strcmp(name, "_strdup") == 0 ? 0u : 1u],
            1u, &length);
        if (string_status != XXEMUL_STATUS_OK) return string_status;
        if (strcmp(name, "_strdup") == 0) {
            *result = win_heap_alloc(process, length + 1u);
            if (*result == 0u) return win_crt_errno(process, 12u);
            return win_crt_copy(process, *result, arg[0], length + 1u);
        }
        *result = arg[0];
        return win_crt_copy(process, arg[0], arg[1], length + 1u);
    }
    if (strcmp(name, "strncpy") == 0) {
        uint64_t index, character;
        if (arg[2] > WIN_MAX_IO)
            return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
        for (index = 0u; index < arg[2]; ++index) {
            if (!win_load(process, arg[1] + index,
                    1u, &character)
                || !win_store(process, arg[0] + index,
                    1u, character))
                return XXEMUL_STATUS_ADDRESS_FAULT;
            if (character == 0u) {
                xxemul_status fill_status = win_crt_fill(process,
                    arg[0] + index + 1u, 0u, arg[2] - index - 1u);
                if (fill_status != XXEMUL_STATUS_OK) return fill_status;
                break;
            }
        }
        *result = arg[0];
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "strchr") == 0
        || strcmp(name, "strrchr") == 0) {
        uint64_t index, ch;
        for (index = 0u; index < WIN_MAX_IO; ++index) {
            if (!win_load(process, arg[0] + index, 1u, &ch))
                return XXEMUL_STATUS_ADDRESS_FAULT;
            if (ch == (uint8_t)arg[1]) {
                *result = arg[0] + index;
                if (strcmp(name, "strchr") == 0)
                    return XXEMUL_STATUS_OK;
            }
            if (ch == 0u) return XXEMUL_STATUS_OK;
        }
        return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    }
    if (strcmp(name, "strstr") == 0
        || strcmp(name, "strcspn") == 0) {
        char *left = NULL, *right = NULL;
        size_t left_length = 0u, right_length = 0u;
        xxemul_status string_status = win_crt_read_string(process,
            arg[0], &left, &left_length);
        if (string_status != XXEMUL_STATUS_OK || left == NULL)
            return string_status;
        string_status = win_crt_read_string(process, arg[1],
            &right, &right_length);
        if (string_status == XXEMUL_STATUS_OK && right != NULL) {
            if (strcmp(name, "strstr") == 0) {
                const char *found = strstr(left, right);
                if (found != NULL)
                    *result = arg[0] + (size_t)(found - left);
            } else *result = strcspn(left, right);
        }
        free(left);
        free(right);
        (void)left_length;
        (void)right_length;
        return string_status;
    }
    if (strcmp(name, "getenv") == 0) {
        char *key = NULL;
        size_t length = 0u;
        size_t offset = 0u;
        xxemul_status string_status = win_crt_read_string(process,
            arg[0], &key, &length);
        if (string_status != XXEMUL_STATUS_OK || key == NULL)
            return string_status;
        while (offset + 1u < process->environment_size
            && process->environment_data[offset] != '\0') {
            const char *entry = process->environment_data + offset;
            if (win_environment_match(entry, key)) {
                *result = process->environment_a + offset
                    + strlen(key) + 1u;
                break;
            }
            offset += strlen(entry) + 1u;
        }
        free(key);
        (void)length;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "tolower") == 0
        || strcmp(name, "islower") == 0
        || strcmp(name, "isspace") == 0
        || strcmp(name, "isupper") == 0
        || strcmp(name, "isxdigit") == 0) {
        int character = (int32_t)arg[0];
        if (character != -1 && (character < 0 || character > 255))
            return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
        if (strcmp(name, "tolower") == 0)
            *result = (uint32_t)tolower(character);
        else if (strcmp(name, "islower") == 0)
            *result = islower(character) != 0;
        else if (strcmp(name, "isspace") == 0)
            *result = isspace(character) != 0;
        else if (strcmp(name, "isupper") == 0)
            *result = isupper(character) != 0;
        else *result = isxdigit(character) != 0;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "atoi") == 0) {
        char *end;
        long parsed;
        if (!win_guest_string(process, arg[0], text,
                sizeof(text), 0)) return XXEMUL_STATUS_ADDRESS_FAULT;
        parsed = strtol(text, &end, 10);
        *result = end == text ? 0u : (uint32_t)parsed;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "strtol") == 0
        || strcmp(name, "strtoul") == 0)
        return win_crt_parse_number(process, arg, word_size,
            strcmp(name, "strtoul") == 0, result);
    if (strcmp(name, "_c_exit") == 0
        || strcmp(name, "_cexit") == 0) {
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "_exit") == 0) {
        process->exit_code = (uint32_t)arg[0];
        return XXEMUL_STATUS_HALTED;
    }
    if (strcmp(name, "_XcptFilter") == 0) {
        *result = 0u;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "__dllonexit") == 0) {
        *result = arg[0];
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "SetFileApisToOEM") == 0
        || strcmp(name, "SetConsoleCtrlHandler") == 0) {
        *result = 1u;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "GetLargePageMinimum") == 0) {
        *result = 0u;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "IsProcessorFeaturePresent") == 0) {
        uint32_t feat = (uint32_t)arg[0];
        if (feat == 2u || feat == 3u || feat == 6u || feat == 8u
            || feat == 10u || feat == 12u || feat == 13u || feat == 17u) {
            *result = 1u;
        } else if (feat == 14u) {
            *result = process->emulator->mode == XXEMUL_MODE_X86_64 ? 1u : 0u;
        } else {
            *result = 0u;
        }
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "wcscmp") == 0) {
        uint64_t idx = 0;
        *result = 0;
        for (;; idx += 2u) {
            uint64_t c1 = 0, c2 = 0;
            if (!win_load(process, arg[0] + idx, 2u, &c1)
                || !win_load(process, arg[1] + idx, 2u, &c2))
                return XXEMUL_STATUS_ADDRESS_FAULT;
            if (c1 != c2) {
                *result = (uint64_t)(c1 < c2 ? -1 : 1);
                return XXEMUL_STATUS_OK;
            }
            if (c1 == 0) return XXEMUL_STATUS_OK;
        }
    }
    if (strcmp(name, "CharUpperW") == 0) {
        if (arg[0] < 0x10000u) {
            uint16_t c = (uint16_t)arg[0];
            if (c >= 'a' && c <= 'z') c -= 32;
            *result = c;
        } else {
            uint64_t ptr = arg[0];
            for (;; ptr += 2u) {
                uint64_t w = 0;
                if (!win_load(process, ptr, 2u, &w) || w == 0) break;
                if (w >= 'a' && w <= 'z') win_store(process, ptr, 2u, w - 32);
            }
            *result = arg[0];
        }
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "GetDriveTypeW") == 0
        || strcmp(name, "GetDriveTypeA") == 0) {
        *result = 3u;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "GetDiskFreeSpaceExW") == 0
        || strcmp(name, "GetDiskFreeSpaceExA") == 0) {
        uint64_t bytes = 100ULL * 1024ULL * 1024ULL * 1024ULL;
        if (arg[1] != 0) win_store(process, arg[1], 8u, bytes);
        if (arg[2] != 0) win_store(process, arg[2], 8u, bytes * 2u);
        if (arg[3] != 0) win_store(process, arg[3], 8u, bytes);
        *result = 1u;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "GetVolumeInformationW") == 0) {
        static const uint16_t fs_name[] = {'N','T','F','S', 0};
        if (arg[3] != 0) win_store(process, arg[3], 4u, 0x12345678u);
        if (arg[4] != 0) win_store(process, arg[4], 4u, 255u);
        if (arg[5] != 0) win_store(process, arg[5], 4u, 0x00000003u);
        if (arg[6] != 0 && arg[7] >= sizeof(fs_name)/2)
            win_write(process, arg[6], fs_name, sizeof(fs_name));
        *result = 1u;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "GetFullPathNameW") == 0) {
        uint64_t len = 0;
        uint64_t last_slash = 0;
        for (;; ++len) {
            uint64_t w = 0;
            if (!win_load(process, arg[0] + len * 2u, 2u, &w)) break;
            if (w == '\\' || w == '/') last_slash = len + 1u;
            if (arg[2] != 0 && len < arg[1]) win_store(process, arg[2] + len * 2u, 2u, w);
            if (w == 0) break;
        }
        if (arg[3] != 0 && arg[2] != 0 && last_slash > 0) {
            win_store(process, arg[3], word_size, arg[2] + last_slash * 2u);
        }
        *result = (uint32_t)len;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "GetLongPathNameW") == 0
        || strcmp(name, "GetShortPathNameW") == 0
        || strcmp(name, "ExpandEnvironmentStringsW") == 0) {
        uint64_t len = 0;
        for (;; ++len) {
            uint64_t w = 0;
            if (!win_load(process, arg[0] + len * 2u, 2u, &w)) break;
            if (arg[1] != 0 && len < arg[2]) win_store(process, arg[1] + len * 2u, 2u, w);
            if (w == 0) break;
        }
        *result = (uint32_t)len;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "LCMapStringW") == 0) {
        int cch_src = (int)arg[3];
        int cch_dest = (int)arg[5];
        if (cch_src <= 0) {
            uint64_t len = 0;
            for (;; ++len) {
                uint64_t w = 0;
                if (!win_load(process, arg[2] + len * 2u, 2u, &w)) break;
                if (w == 0) { ++len; break; }
            }
            cch_src = (int)len;
        }
        if (cch_dest == 0 || arg[4] == 0) {
            *result = (uint32_t)cch_src;
            return XXEMUL_STATUS_OK;
        }
        int count = cch_src < cch_dest ? cch_src : cch_dest;
        int i;
        for (i = 0; i < count; ++i) {
            uint64_t w = 0;
            if (!win_load(process, arg[2] + (uint64_t)i * 2u, 2u, &w)) break;
            if ((arg[1] & 0x00000100u) != 0 && w >= 'A' && w <= 'Z') w += 32;
            else if ((arg[1] & 0x00000200u) != 0 && w >= 'a' && w <= 'z') w -= 32;
            win_store(process, arg[4] + (uint64_t)i * 2u, 2u, w);
        }
        *result = (uint32_t)count;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "GetStringTypeW") == 0) {
        int count = (int)arg[2];
        if (count < 0) {
            uint64_t len = 0;
            for (;; ++len) {
                uint64_t w = 0;
                if (!win_load(process, arg[1] + len * 2u, 2u, &w) || w == 0) break;
            }
            count = (int)len;
        }
        if (arg[3] != 0 && count > 0) {
            int i;
            for (i = 0; i < count; ++i) {
                uint64_t w = 0;
                uint16_t type = 0;
                win_load(process, arg[1] + (uint64_t)i * 2u, 2u, &w);
                if ((w >= 'a' && w <= 'z') || (w >= 'A' && w <= 'Z')) type |= 0x0001u | 0x0004u;
                if (w >= '0' && w <= '9') type |= 0x0004u;
                if (w == ' ' || w == '\t' || w == '\r' || w == '\n') type |= 0x0008u;
                win_store(process, arg[3] + (uint64_t)i * 2u, 2u, type);
            }
        }
        *result = 1u;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "IsValidCodePage") == 0) {
        *result = 1u;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "CompareStringW") == 0 || strcmp(name, "CompareStringA") == 0) {
        int is_wide = strcmp(name, "CompareStringW") == 0;
        int step = is_wide ? 2 : 1;
        uint64_t i = 0;
        int cmp = 0;
        for (;; ++i) {
            uint64_t c1 = 0, c2 = 0;
            int has1 = (arg[3] == (uint64_t)(int64_t)-1) || (i < arg[3]);
            int has2 = (arg[5] == (uint64_t)(int64_t)-1) || (i < arg[5]);
            if (!has1 && !has2) { cmp = 0; break; }
            if (has1) win_load(process, arg[2] + i * (uint64_t)step, (uint8_t)step, &c1);
            if (has2) win_load(process, arg[4] + i * (uint64_t)step, (uint8_t)step, &c2);
            if (arg[1] & 1u) {
                if (c1 >= 'A' && c1 <= 'Z') c1 += 32;
                if (c2 >= 'A' && c2 <= 'Z') c2 += 32;
            }
            if (c1 != c2) { cmp = c1 < c2 ? -1 : 1; break; }
            if (c1 == 0) { cmp = 0; break; }
        }
        *result = cmp < 0 ? 1u : cmp == 0 ? 2u : 3u;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "FoldStringW") == 0) {
        int count = (int)arg[2];
        if (count < 0) {
            uint64_t len = 0;
            for (;; ++len) {
                uint64_t w = 0;
                if (!win_load(process, arg[1] + len * 2u, 2u, &w) || w == 0) { ++len; break; }
            }
            count = (int)len;
        }
        if (arg[3] != 0 && arg[4] > 0) {
            int n = count < (int)arg[4] ? count : (int)arg[4];
            int i;
            for (i = 0; i < n; ++i) {
                uint64_t w = 0;
                win_load(process, arg[1] + (uint64_t)i * 2u, 2u, &w);
                win_store(process, arg[3] + (uint64_t)i * 2u, 2u, w);
            }
        }
        *result = (uint32_t)count;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "FormatMessageW") == 0) {
        *result = 0u;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "WriteConsoleW") == 0) {
        *result = win_console_write_w(process, arg[0], arg[1], arg[2], arg[3]);
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "ReadConsoleW") == 0) {
        if (arg[3] != 0) win_store(process, arg[3], 4u, 0u);
        *result = 1u;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "CharLowerW") == 0) {
        if (arg[0] < 0x10000u) {
            uint16_t c = (uint16_t)arg[0];
            if (c >= 'A' && c <= 'Z') c += 32;
            *result = c;
        } else {
            uint64_t ptr = arg[0];
            for (;; ptr += 2u) {
                uint64_t w = 0;
                if (!win_load(process, ptr, 2u, &w) || w == 0) break;
                if (w >= 'A' && w <= 'Z') win_store(process, ptr, 2u, w + 32);
            }
            *result = arg[0];
        }
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "OemToCharBuffW") == 0
        || strcmp(name, "CharToOemBuffW") == 0
        || strcmp(name, "CharToOemBuffA") == 0
        || strcmp(name, "OemToCharBuffA") == 0) {
        int is_w = win_suffix(name, "W");
        size_t bytes = (size_t)arg[2] * (is_w ? 2u : 1u);
        if (arg[0] != arg[1] && bytes > 0 && bytes < WIN_MAX_IO) {
            uint8_t *tmp = (uint8_t *)malloc(bytes);
            if (tmp != NULL) {
                if (win_read(process, arg[0], tmp, bytes))
                    win_write(process, arg[1], tmp, bytes);
                free(tmp);
            }
        }
        *result = 1u;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "CharToOemA") == 0 || strcmp(name, "OemToCharA") == 0) {
        if (arg[0] != arg[1]) {
            char buf[1024];
            if (win_guest_string(process, arg[0], buf, sizeof(buf), 0))
                win_write(process, arg[1], buf, strlen(buf) + 1);
        }
        *result = 1u;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "RtlPcToFileHeader") == 0) {
        if (arg[1] != 0) win_store(process, arg[1], word_size, process->image_base);
        *result = process->image_base;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "RtlUnwindEx") == 0 || strcmp(name, "RtlVirtualUnwind") == 0) {
        *result = 0u;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "DeviceIoControl") == 0) {
        if (arg[6] != 0) win_store(process, arg[6], 4u, 0u);
        process->last_error = 1u;
        *result = 0u;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "BackupRead") == 0 || strcmp(name, "BackupSeek") == 0) {
        process->last_error = 50u;
        *result = 0u;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "OpenProcessToken") == 0) {
        if (arg[2] != 0) win_store(process, arg[2], word_size, 0x100u);
        *result = 1u;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "GetTokenInformation") == 0) {
        if (arg[4] != 0) win_store(process, arg[4], 4u, 4u);
        *result = 1u;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "LookupPrivilegeValueW") == 0
        || strcmp(name, "LookupPrivilegeValueA") == 0) {
        if (arg[2] != 0) win_store(process, arg[2], 8u, 0x1234u);
        *result = 1u;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "AdjustTokenPrivileges") == 0
        || strcmp(name, "LsaAddAccountRights") == 0) {
        *result = 1u;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "CheckTokenMembership") == 0) {
        if (arg[2] != 0) win_store(process, arg[2], 4u, 1u);
        *result = 1u;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "AllocateAndInitializeSid") == 0) {
        if (arg[10] != 0) win_store(process, arg[10], word_size, 0x500u);
        *result = 1u;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "FreeSid") == 0 || strcmp(name, "LsaClose") == 0) {
        *result = 0u;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "LsaOpenPolicy") == 0) {
        if (arg[3] != 0) win_store(process, arg[3], word_size, 0x600u);
        *result = 0u;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "RegOpenKeyExW") == 0 || strcmp(name, "RegOpenKeyExA") == 0) {
        if (arg[4] != 0) win_store(process, arg[4], word_size, 0x200u);
        *result = 0u;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "RegQueryValueExW") == 0 || strcmp(name, "RegQueryValueExA") == 0) {
        *result = 2u;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "ConvertStringSidToSidW") == 0
        || strcmp(name, "ConvertSidToStringSidW") == 0) {
        *result = 1u;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "CreateThread") == 0) {
        if (arg[5] != 0) win_store(process, arg[5], 4u, 0x42u);
        *result = 0x300u;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "GetSystemTime") == 0) {
        uint16_t st[8] = {2026, 9, 5, 25, 12, 0, 0, 0};
        win_write(process, arg[0], st, sizeof(st));
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "FileTimeToSystemTime") == 0) {
        uint16_t st[8] = {2026, 9, 5, 25, 12, 0, 0, 0};
        win_write(process, arg[1], st, sizeof(st));
        *result = 1u;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "SystemTimeToFileTime") == 0) {
        uint64_t ft = 133000000000000000ULL;
        win_store(process, arg[1], 8u, ft);
        *result = 1u;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "SystemTimeToTzSpecificLocalTime") == 0
        || strcmp(name, "TzSpecificLocalTimeToSystemTime") == 0) {
        uint8_t st[16];
        if (win_read(process, arg[1], st, 16u)) win_write(process, arg[2], st, 16u);
        *result = 1u;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "SetFileAttributesW") == 0
        || strcmp(name, "CreateHardLinkW") == 0
        || strcmp(name, "ExitWindowsEx") == 0
        || strcmp(name, "SetSuspendState") == 0) {
        *result = 1u;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "SHGetMalloc") == 0) {
        uint64_t obj = process->runtime_base + WIN_SHELL_MALLOC_OFFSET;
        uint64_t vtbl = process->runtime_base + WIN_SHELL_MALLOC_OFFSET + 8u;
        uint64_t stub = process->runtime_base + WIN_SHELL_MALLOC_OFFSET + 0x80u;
        size_t i;
        word_size = (uint8_t)(process->emulator->mode == XXEMUL_MODE_X86_64 ? 8u : 4u);
        if (word_size == 8u) {
            uint8_t ret_code[3] = { 0x31, 0xc0, 0xc3 }; /* xor eax, eax; ret */
            win_write(process, stub, ret_code, sizeof(ret_code));
        } else {
            uint8_t ret_code[4] = { 0x31, 0xc0, 0xc2, 0x08 }; /* xor eax, eax; ret 8 */
            win_write(process, stub, ret_code, sizeof(ret_code));
        }
        for (i = 0; i < 10; ++i) {
            win_store(process, vtbl + i * word_size, word_size, stub);
        }
        win_store(process, obj, word_size, vtbl);
        if (arg[0] != 0u) {
            if (!win_store(process, arg[0], word_size, obj))
                return XXEMUL_STATUS_ADDRESS_FAULT;
        }
        *result = 0u; /* S_OK */
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "SHGetSpecialFolderLocation") == 0) {
        if (arg[2] != 0u) {
            uint64_t dummy_pidl = process->runtime_base + WIN_SHELL_MALLOC_OFFSET + 0x90u;
            if (!win_store(process, arg[2], process->emulator->mode == XXEMUL_MODE_X86_64 ? 8u : 4u, dummy_pidl))
                return XXEMUL_STATUS_ADDRESS_FAULT;
        }
        *result = 0u; /* S_OK */
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "SHGetPathFromIDListW") == 0) {
        const char *appdata = getenv("APPDATA");
        if (appdata == NULL || appdata[0] == '\0') {
            appdata = "C:\\Users\\Default\\AppData\\Roaming";
        }
        if (arg[1] != 0u) {
            if (!win_write_wide(process, arg[1], appdata, 260u))
                return XXEMUL_STATUS_ADDRESS_FAULT;
        }
        *result = 1u; /* TRUE */
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "LoadStringW") == 0) {
        uint32_t uid = (uint32_t)arg[1];
        uint64_t buffer = arg[2];
        uint32_t max_chars = (uint32_t)arg[3];
        if (!win_load_string(process, uid, buffer, max_chars, result)) {
            if (max_chars > 0 && buffer != 0) {
                win_store(process, buffer, 2u, 0);
            }
            *result = 0u;
        }
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "ShellExecuteExW") == 0
        || strcmp(name, "SHFileOperationW") == 0) {
        *result = 0u;
        return XXEMUL_STATUS_OK;
    }
    fprintf(stderr, "[xxemul API stub] %s::%s\n", api->module, name);
    *result = 0u;
    return XXEMUL_STATUS_OK;
}

static xxemul_status win_initterm_continue(xxemul_windows *process,
    uint64_t current_ip, xxemul_step_info *info)
{
    win_initterm_frame *frame;
    uint8_t word_size = (uint8_t)(process->emulator->mode
        == XXEMUL_MODE_X86_64 ? 8u : 4u);
    uint64_t next_ip;
    if (process->initterm_depth == 0u)
        return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    frame = &process->initterm_frames[process->initterm_depth - 1u];
    for (;;) {
        uint64_t callback;
        uint64_t callback_sp;
        if (frame->cursor == frame->end) {
            next_ip = frame->return_address;
            process->emulator->x86.ip = next_ip;
            process->emulator->x86.gpr[XXEMUL_X86_RSP]
                = frame->call_sp + word_size;
            process->emulator->x86.gpr[XXEMUL_X86_RAX] = 0u;
            --process->initterm_depth;
            break;
        }
        if (!win_load(process, frame->cursor, word_size, &callback))
            return XXEMUL_STATUS_ADDRESS_FAULT;
        frame->cursor += word_size;
        if (callback == 0u) continue;
        callback_sp = frame->call_sp - (word_size == 8u ? 48u : 16u);
        if (!win_store(process, callback_sp, word_size,
                process->runtime_base + WIN_INITTERM_RETURN_OFFSET))
            return XXEMUL_STATUS_ADDRESS_FAULT;
        next_ip = callback;
        process->emulator->x86.ip = callback;
        process->emulator->x86.gpr[XXEMUL_X86_RSP] = callback_sp;
        break;
    }
    if (info != NULL) {
        info->address = current_ip;
        info->next_address = next_ip;
        info->size = 1u;
        info->instruction_id = 0u;
    }
    return XXEMUL_STATUS_OK;
}

static xxemul_status win_qsort_swap(xxemul_windows *process,
    const win_qsort_frame *frame, uint64_t left, uint64_t right)
{
    uint8_t first[4096], second[4096];
    uint64_t offset;
    uint64_t left_address = frame->base + left * frame->size;
    uint64_t right_address = frame->base + right * frame->size;
    for (offset = 0u; offset < frame->size;) {
        size_t chunk = (size_t)(frame->size - offset > sizeof(first)
            ? sizeof(first) : frame->size - offset);
        if (!win_read(process, left_address + offset, first, chunk)
            || !win_read(process, right_address + offset, second, chunk)
            || !win_write(process, left_address + offset, second, chunk)
            || !win_write(process, right_address + offset, first, chunk))
            return XXEMUL_STATUS_ADDRESS_FAULT;
        offset += chunk;
    }
    return XXEMUL_STATUS_OK;
}

static xxemul_status win_qsort_compare(xxemul_windows *process,
    const win_qsort_frame *frame, uint64_t left, uint64_t right)
{
    uint8_t word_size = (uint8_t)(process->emulator->mode
        == XXEMUL_MODE_X86_64 ? 8u : 4u);
    uint64_t reserved = word_size == 8u ? 48u : 16u;
    uint64_t callback_sp;
    if (frame->call_sp < reserved)
        return XXEMUL_STATUS_ADDRESS_FAULT;
    callback_sp = frame->call_sp - reserved;
    if (!win_store(process, callback_sp, word_size,
            process->runtime_base + WIN_QSORT_RETURN_OFFSET))
        return XXEMUL_STATUS_ADDRESS_FAULT;
    if (word_size == 8u) {
        process->emulator->x86.gpr[XXEMUL_X86_RCX]
            = frame->base + left * frame->size;
        process->emulator->x86.gpr[XXEMUL_X86_RDX]
            = frame->base + right * frame->size;
    } else if (!win_store(process, callback_sp + 4u, 4u,
            frame->base + left * frame->size)
        || !win_store(process, callback_sp + 8u, 4u,
            frame->base + right * frame->size))
        return XXEMUL_STATUS_ADDRESS_FAULT;
    process->emulator->x86.ip = frame->comparator;
    process->emulator->x86.gpr[XXEMUL_X86_RSP] = callback_sp;
    return XXEMUL_STATUS_OK;
}

static xxemul_status win_qsort_continue(xxemul_windows *process,
    uint64_t current_ip, xxemul_step_info *info)
{
    win_qsort_frame *frame;
    uint8_t word_size = (uint8_t)(process->emulator->mode
        == XXEMUL_MODE_X86_64 ? 8u : 4u);
    xxemul_status status;
    uint64_t next_ip;
    if (process->qsort_depth == 0u)
        return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    frame = &process->qsort_frames[process->qsort_depth - 1u];
    for (;;) {
        if (frame->phase == WIN_QSORT_NEXT) {
            if (frame->building && frame->build_start != 0u) {
                frame->root = --frame->build_start;
                frame->phase = WIN_QSORT_SIFT;
            } else {
                frame->building = 0u;
                if (frame->heap_end <= 1u) {
                    next_ip = frame->return_address;
                    process->emulator->x86.ip = next_ip;
                    process->emulator->x86.gpr[XXEMUL_X86_RSP]
                        = frame->call_sp + word_size;
                    process->emulator->x86.gpr[XXEMUL_X86_RAX] = 0u;
                    --process->qsort_depth;
                    break;
                }
                --frame->heap_end;
                status = win_qsort_swap(process, frame, 0u,
                    frame->heap_end);
                if (status != XXEMUL_STATUS_OK) return status;
                frame->root = 0u;
                frame->phase = WIN_QSORT_SIFT;
            }
        } else if (frame->phase == WIN_QSORT_SIFT) {
            if (frame->heap_end < 2u
                || frame->root > (frame->heap_end - 2u) / 2u) {
                frame->phase = WIN_QSORT_NEXT;
                continue;
            }
            frame->child = frame->root * 2u + 1u;
            frame->candidate = frame->root;
            frame->phase = WIN_QSORT_AFTER_LEFT;
            status = win_qsort_compare(process, frame,
                frame->candidate, frame->child);
            if (status != XXEMUL_STATUS_OK) return status;
            next_ip = frame->comparator;
            break;
        } else if (frame->phase == WIN_QSORT_AFTER_LEFT) {
            if ((int32_t)process->emulator->x86.gpr[XXEMUL_X86_RAX] < 0)
                frame->candidate = frame->child;
            if (frame->child + 1u < frame->heap_end) {
                frame->phase = WIN_QSORT_AFTER_RIGHT;
                status = win_qsort_compare(process, frame,
                    frame->candidate, frame->child + 1u);
                if (status != XXEMUL_STATUS_OK) return status;
                next_ip = frame->comparator;
                break;
            }
            frame->phase = WIN_QSORT_CHECK;
        } else if (frame->phase == WIN_QSORT_AFTER_RIGHT) {
            if ((int32_t)process->emulator->x86.gpr[XXEMUL_X86_RAX] < 0)
                frame->candidate = frame->child + 1u;
            frame->phase = WIN_QSORT_CHECK;
        } else if (frame->phase == WIN_QSORT_CHECK) {
            if (frame->candidate == frame->root) {
                frame->phase = WIN_QSORT_NEXT;
            } else {
                status = win_qsort_swap(process, frame,
                    frame->root, frame->candidate);
                if (status != XXEMUL_STATUS_OK) return status;
                frame->root = frame->candidate;
                frame->phase = WIN_QSORT_SIFT;
            }
        } else return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    }
    if (info != NULL) {
        info->address = current_ip;
        info->next_address = next_ip;
        info->size = 1u;
        info->instruction_id = 0u;
    }
    return XXEMUL_STATUS_OK;
}

int xxemul_windows_try_step(
    xxemul_windows *process, xxemul_step_info *info,
    xxemul_status *status)
{
    uint64_t ip, index, return_address, value = 0;
    uint64_t arguments[16] = {0};
    uint8_t word_size, i;
    win_api *api;
    xxemul_status call_status;

    if (process == NULL || status == NULL) return 0;
    ip = process->emulator->x86.ip;
    if (ip == process->runtime_base + WIN_INITTERM_RETURN_OFFSET) {
        *status = win_initterm_continue(process, ip, info);
        return 1;
    }
    if (ip == process->runtime_base + WIN_QSORT_RETURN_OFFSET) {
        *status = win_qsort_continue(process, ip, info);
        return 1;
    }
    if (ip < process->runtime_base + WIN_THUNK_OFFSET) return 0;
    index = (ip - process->runtime_base - WIN_THUNK_OFFSET)
        / WIN_THUNK_STRIDE;
    if (index >= process->api_count
        || ip != process->runtime_base + WIN_THUNK_OFFSET
            + index * WIN_THUNK_STRIDE) return 0;
    api = &process->apis[index];
    word_size = (uint8_t)(process->emulator->mode == XXEMUL_MODE_X86_64
        ? 8u : 4u);
    if (!win_load(process, process->emulator->x86.gpr[XXEMUL_X86_RSP],
            word_size, &return_address)) {
        *status = XXEMUL_STATUS_ADDRESS_FAULT;
        return 1;
    }
    if (process->emulator->mode == XXEMUL_MODE_X86_64) {
        arguments[0] = process->emulator->x86.gpr[XXEMUL_X86_RCX];
        arguments[1] = process->emulator->x86.gpr[XXEMUL_X86_RDX];
        arguments[2] = process->emulator->x86.gpr[XXEMUL_X86_R8];
        arguments[3] = process->emulator->x86.gpr[XXEMUL_X86_R9];
        for (i = 4; i < api->argument_count && i < 16; ++i) {
            if (!win_get_arg(process, i, &arguments[i])) {
                *status = XXEMUL_STATUS_ADDRESS_FAULT;
                return 1;
            }
        }
    } else {
        for (i = 0; i < api->argument_count && i < 16; ++i) {
            if (!win_get_arg(process, i, &arguments[i])) {
                *status = XXEMUL_STATUS_ADDRESS_FAULT;
                return 1;
            }
        }
    }
    if (strcmp(api->name, "_initterm") == 0) {
        win_initterm_frame *frame;
        if (process->initterm_depth >= WIN_MAX_INITTERM_DEPTH
            || arguments[1] < arguments[0]
            || arguments[1] - arguments[0]
                > (uint64_t)word_size * 4096u
            || (arguments[1] - arguments[0]) % word_size != 0u) {
            *status = XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
            return 1;
        }
        frame = &process->initterm_frames[process->initterm_depth++];
        frame->cursor = arguments[0];
        frame->end = arguments[1];
        frame->call_sp = process->emulator->x86.gpr[XXEMUL_X86_RSP];
        frame->return_address = return_address;
        *status = win_initterm_continue(process, ip, info);
        return 1;
    }
    if (strcmp(api->name, "qsort") == 0) {
        win_qsort_frame *frame;
        if (process->qsort_depth >= WIN_MAX_QSORT_DEPTH
            || arguments[1] > WIN_MAX_QSORT_ELEMENTS
            || (arguments[1] > 1u
                && (arguments[0] == 0u || arguments[2] == 0u
                    || arguments[3] == 0u
                    || arguments[2] > WIN_MAX_IO / arguments[1]
                    || arguments[0] > UINT64_MAX
                        - arguments[1] * arguments[2]))) {
            *status = XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
            return 1;
        }
        frame = &process->qsort_frames[process->qsort_depth++];
        memset(frame, 0, sizeof(*frame));
        frame->base = arguments[0];
        frame->count = arguments[1];
        frame->size = arguments[2];
        frame->comparator = arguments[3];
        frame->call_sp = process->emulator->x86.gpr[XXEMUL_X86_RSP];
        frame->return_address = return_address;
        frame->build_start = arguments[1] / 2u;
        frame->heap_end = arguments[1];
        frame->building = 1u;
        *status = win_qsort_continue(process, ip, info);
        return 1;
    }
    call_status = win_call(process, api, arguments, &value);
    if (call_status != XXEMUL_STATUS_OK
        && call_status != XXEMUL_STATUS_HALTED) {
        *status = call_status;
        return 1;
    }
    if (info != NULL) {
        info->address = ip;
        info->next_address = return_address;
        info->size = 1u;
        info->instruction_id = 0u;
    }
    if (call_status == XXEMUL_STATUS_OK) {
        process->emulator->x86.ip = return_address;
        process->emulator->x86.gpr[XXEMUL_X86_RSP]
            += word_size == 8u ? 8u
                : 4u + (api->caller_cleans ? 0u
                    : (uint64_t)api->argument_count * 4u);
        process->emulator->x86.gpr[XXEMUL_X86_RAX]
            = word_size == 8u ? value : (uint32_t)value;
    }
    *status = call_status;
    return 1;
}
