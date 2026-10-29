#if defined(__linux__) && !defined(_GNU_SOURCE)
#define _GNU_SOURCE
#endif
#if !defined(_WIN32) && !defined(_POSIX_C_SOURCE)
#define _POSIX_C_SOURCE 200809L
#endif
#if !defined(_WIN32) && !defined(_XOPEN_SOURCE)
/* glibc declares realpath() only for X/Open, not plain POSIX. */
#define _XOPEN_SOURCE 700
#endif
#if defined(__APPLE__) && !defined(_DARWIN_C_SOURCE)
#define _DARWIN_C_SOURCE
#endif

#include "xxemul_windows.h"
#include "xxemul_internal.h"
#include <xxfclib/formats/executable/pe/xx_pe_make.h>

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
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
#include <unistd.h>
#include <dirent.h>
#include <utime.h>
#if defined(__linux__)
#include <sys/syscall.h>
#endif
#endif

#define WIN_RUNTIME_SIZE UINT64_C(0x100000)
#define WIN_THUNK_OFFSET UINT64_C(0xe0000)
#define WIN_THUNK_STRIDE UINT64_C(16)
#define WIN_MAX_APIS 2048u
#define WIN_MAX_THREADS 8u
#define WIN_MAX_MODULES 24u
#define WIN_STATIC_TLS_SLOTS (WIN_MAX_MODULES + 1u)
#define WIN_MAX_TLS_CALLBACKS 64u
#define WIN_MODULE_OFFSET UINT64_C(0x20000)
#define WIN_MODULE_STRIDE UINT64_C(0x8000)
#define WIN_MAX_HANDLES 64u
#define WIN_MAX_ALLOCATIONS 4096u
#define WIN_MAX_VECTORED_HANDLERS 64u
#define WIN_VECTORED_HANDLE_OFFSET UINT64_C(0x8200)
#define WIN_SHELL_MALLOC_OFFSET UINT64_C(0x8500)
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
#define WIN_CRT_ARGV_OFFSET UINT64_C(0xf2000)
#define WIN_CRT_ENVP_OFFSET UINT64_C(0xf2800)
#define WIN_CRT_DATA_OFFSET UINT64_C(0xf1000)
#define WIN_CRT_LOCALE_OFFSET UINT64_C(0xf3000)
#define WIN_CRT_STRINGS_OFFSET UINT64_C(0xf4000)
#define WIN_QSORT_RETURN_OFFSET UINT64_C(0x8fe0)
#define WIN_PROCESS_RETURN_OFFSET UINT64_C(0x8fd0)
#define WIN_SEH_RETURN_OFFSET UINT64_C(0x8fc0)
#define WIN_THREAD_RETURN_OFFSET UINT64_C(0x8fa0)
#define WIN_DLL_RETURN_OFFSET UINT64_C(0x8f70)
#define WIN_LOADER_START_OFFSET UINT64_C(0x8f50)
#define WIN_THREAD_START_OFFSET UINT64_C(0x8f40)
#define WIN_DLL_DEPTH 8u
#define WIN_INITTERM_RETURN_OFFSET UINT64_C(0x8ff0)
#define WIN_MAX_INITTERM_DEPTH 8u
#define WIN_MAX_QSORT_DEPTH 8u
#define WIN_MAX_QSORT_ELEMENTS 65536u

#define WIN_REG_KEYS 128u
#define WIN_REG_VALUES 256u
#define WIN_REG_HANDLES 128u
#define WIN_REG_NAME 256u
#define WIN_REG_PATH 1024u
#define WIN_REG_DATA (1024u * 1024u)
#define WIN_REG_TOTAL (16u * 1024u * 1024u)
typedef struct win_reg_key { uint32_t parent; uint16_t name[WIN_REG_NAME]; } win_reg_key;
typedef struct win_reg_handle { uint32_t id, key, access; } win_reg_handle;
typedef struct win_reg_value {
    uint32_t key, type;
    uint16_t name[WIN_REG_NAME];
    uint8_t *data;
    size_t size;
} win_reg_value;

typedef struct win_api {
    char module[48];
    char name[96];
    char qualified[145];
    uint8_t argument_count;
    uint8_t caller_cleans;
} win_api;

typedef struct win_tls_image {
    uint64_t base, image_size, callbacks;
    uint8_t *template_data;
    size_t data_size, alignment;
    uint32_t index;
    uint8_t present;
} win_tls_image;

typedef struct win_module {
    char name[48];
    uint64_t base;
    uint8_t building;
    uint64_t image_size, allocation, init_order;
    uint32_t generation, references, entry_rva, export_rva, export_size, resource_rva, resource_size, dependencies;
    uint8_t real, live, initialized, initializing, data_only, thread_callbacks_disabled, primary;
    win_tls_image tls;
    char file_path[2048];
} win_module;
typedef struct win_dll_frame {
    xxemul_x86_state caller;
    uint32_t owner_id, unload_mask, notify_mask, exit_code, current_generation;
    uint32_t notify_generations[WIN_MAX_MODULES];
    uint16_t root_slot, current_slot;
    unsigned callback_index;
    uint8_t reason, failed, unloading, startup, exiting;
    uint8_t mode, main_pending, notifying, phase, invoking_tls;
} win_dll_frame;

#define WIN_RESOURCE_RECORDS 256u
typedef struct win_resource_record {
    uint64_t module,address;
    uint32_t generation,entry,size;
    uint8_t used,loaded;
} win_resource_record;

typedef struct win_find_state {
    uint8_t *records;
    size_t count, capacity, index;
} win_find_state;
static void win_find_destroy(win_find_state *state);

#define WIN_FILE_ATTRIBUTE_SLOTS 128u
typedef struct win_file_attribute {
    char path[2048];
    uint64_t device, inode;
    uint32_t logical, write_bits;
    uint8_t used;
} win_file_attribute;

typedef struct win_handle {
    uint16_t child_slot;
    uint32_t object_id;
    uint64_t thread_start, thread_parameter;
    uint32_t thread_exit;
    uint8_t thread_finished;
    uint16_t thread_slot;
    xx_io_device *io;
    win_find_state *find;
    uint8_t *mapping_data;
    uint64_t mapping_size, view_address, view_allocation, view_size, view_offset, view_reference;
    uint32_t mapping_protect, view_access;
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
    WIN_HANDLE_THREAD = 6,
    WIN_HANDLE_HEAP = 7,
    WIN_HANDLE_MAPPING = 8,
    WIN_HANDLE_FIND = 9
};

typedef struct win_allocation {
    uint64_t address;
    uint64_t size;
    uint64_t capacity;
    uint64_t heap_owner;
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

typedef struct win_seh_frame {
    xxemul_x86_state saved;
    uint64_t context, record, call_sp, registration;
    unsigned searched, vectored_cursor;
    int vectored;
    xxemul_status original_status;
    uint64_t dispatcher, original_registration;
} win_seh_frame;

#define WIN_GUI_OBJECTS 256u
#define WIN_GUI_DIALOGS 8u
#define WIN_DIALOG_RETURN_OFFSET UINT64_C(0x8f90)
#define WIN_DIALOG_WAIT_OFFSET UINT64_C(0x8f80)
enum { WIN_GUI_DIALOG=1, WIN_GUI_CONTROL=2, WIN_GUI_FONT=3, WIN_GUI_ICON=4 };
typedef struct win_gui_object {
    uint64_t parent, font, icon[2], resource;
    uint32_t id, style, resource_size;
    int32_t position, minimum, maximum, increment;
    uint16_t text[256], class_name[64], class_ordinal;
    uint8_t logfont[92], kind, active;
} win_gui_object;
typedef struct win_dialog_frame {
    xxemul_x86_state caller;
    uint64_t handle, procedure, parameter, event, result, sequence;
    uint32_t owner_id;
    uint8_t active, ended, phase, wide;
} win_dialog_frame;

typedef struct win_thread_context {
    xxemul_x86_state cpu;
    double x87_stack[8];
    uint64_t x87_int_val[8], tls_values[WIN_MAX_TLS_SLOTS];
    uint8_t x87_is_int[8], x87_depth, x87_top;
    uint16_t x87_control, x87_status, handle_slot;
    uint32_t last_error, id, suspended, exit_code;
    uint64_t stack_base, stack_limit, seh_head, tls_array, stack_allocation, tls_allocation, start_address;
    uint64_t static_tls_allocations[WIN_STATIC_TLS_SLOTS];
    win_seh_frame seh_frames[8]; size_t seh_depth;
    win_qsort_frame qsort_frames[WIN_MAX_QSORT_DEPTH]; size_t qsort_depth;
    win_initterm_frame initterm_frames[WIN_MAX_INITTERM_DEPTH]; size_t initterm_depth;
    uint64_t deadline, wait_handles[WIN_MAX_HANDLES];
    size_t wait_count;
    uint8_t active, blocked, wait_all, handle_bound, notify_started, detaching;
} win_thread_context;

#define WIN_MAX_CHILDREN 8u
#define WIN_CHILD_WAIT_OFFSET UINT64_C(0x8f60)
typedef struct win_process_tree { uint32_t next_id, processes; uint64_t memory; } win_process_tree;
typedef struct win_child_process {
    xxemul *emulator;
    uint32_t process_id, thread_id, exit_code, suspended;
    uint64_t steps;
    xxemul_status failure;
    uint8_t active, finished;
} win_child_process;

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
    uint32_t process_id;
    uint32_t startup_flags;
    uint16_t startup_show;
    win_process_tree *process_tree;
    win_child_process children[WIN_MAX_CHILDREN];
    uint32_t child_tick;
    uint8_t tree_owner, process_depth, process_terminated, child_waiting;
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
    uint8_t crt_fd_eof[WIN_MAX_CRT_FDS];
    uint16_t console_cursor_x;
    uint16_t console_cursor_y;
    uint16_t console_attributes;
    uint32_t console_input_mode;
    uint32_t console_output_mode;
    uint8_t console_cursor_size;
    uint8_t console_cursor_visible;
    win_console_cell console_cells[WIN_CONSOLE_WIDTH * WIN_CONSOLE_HEIGHT];
    win_reg_key registry_keys[WIN_REG_KEYS];
    win_reg_value registry_values[WIN_REG_VALUES];
    win_reg_handle registry_handles[WIN_REG_HANDLES];
    size_t registry_key_count, registry_value_count, registry_bytes;
    uint32_t registry_next_handle, temp_counter;
    char program_path[1024];
    char working_directory[1024];
    char guest_directory[1024];
    win_api apis[WIN_MAX_APIS];
    size_t api_count;
    char data_qualified[7][145];
    win_module modules[WIN_MAX_MODULES];
    size_t module_count;
    uint8_t loader_ready;
    win_handle handles[WIN_MAX_HANDLES];
    win_file_attribute file_attributes[WIN_FILE_ATTRIBUTE_SLOTS];
    win_allocation allocations[WIN_MAX_ALLOCATIONS];
    size_t allocation_count;
    win_vectored_handler vectored_handlers[WIN_MAX_VECTORED_HANDLERS];
    size_t vectored_handler_count;
    win_critical_section critical_sections[WIN_MAX_CRITICAL_SECTIONS];
    win_initterm_frame initterm_frames[WIN_MAX_INITTERM_DEPTH];
    size_t initterm_depth;
    win_qsort_frame qsort_frames[WIN_MAX_QSORT_DEPTH];
    size_t qsort_depth;
    win_seh_frame seh_frames[8];
    size_t seh_depth;
    int tls_started;
    uint64_t loader_entry;
    uint8_t startup_pending;
    uint8_t main_dll_slot, main_dll_complete;
    win_tls_image main_tls;
    win_thread_context threads[WIN_MAX_THREADS];
    unsigned thread_current;
    uint32_t next_thread_id;
    uint64_t scheduler_tick;
    win_gui_object gui_objects[WIN_GUI_OBJECTS];
    win_dialog_frame dialogs[WIN_GUI_DIALOGS];
    uint64_t dialog_sequence;
    unsigned dialog_pending;
    uint32_t gui_common_controls;
    win_resource_record resource_records[WIN_RESOURCE_RECORDS];
    uint32_t resource_rva;
    uint32_t resource_size;
    win_dll_frame dll_frames[WIN_DLL_DEPTH];
    size_t dll_depth, dll_pending;
    uint8_t dll_pending_unload, dll_exiting;
    uint64_t dll_sequence;
    uint32_t dll_generation;
};

static void win_children_destroy(xxemul_windows *process);
static xxemul_status win_children_pump(xxemul_windows *process, unsigned quantum);
static int win_children_runnable(const xxemul_windows *process);
static win_child_process *win_child_at(xxemul_windows *process, const win_handle *handle);
static int win_set_guest_directory(xxemul_windows *process, const char *guest);
static xxemul_status win_thread_yield(xxemul_windows *process, xxemul_step_info *info);
static xxemul_status win_thread_finish_raw(xxemul_windows *process, uint32_t code, xxemul_step_info *info);
static void win_thread_end(xxemul_windows *process, size_t slot, uint32_t code);
static int win_dll_last_thread(xxemul_windows *process);

static uint8_t win_word_size(const xxemul *emulator)
{
    return emulator->mode == XXEMUL_MODE_X86_64 || emulator->mode == XXEMUL_MODE_ARM_A64 ? 8u : 4u;
}

static uint16_t win_le16(const uint8_t *data)
{
    return (uint16_t)((uint16_t)data[0] | ((uint16_t)data[1] << 8));
}

static uint32_t win_le32(const uint8_t *data)
{
    return (uint32_t)data[0] | ((uint32_t)data[1] << 8) | ((uint32_t)data[2] << 16) | ((uint32_t)data[3] << 24);
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
        if (tolower((unsigned char)*left) != tolower((unsigned char)*right)) return 0;
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
        if (*text == '\0' || tolower((unsigned char)*text) != tolower((unsigned char)*prefix)) return 0;
        ++text;
        ++prefix;
    }
    return 1;
}

static int win_write(xxemul_windows *process, uint64_t address, const void *bytes, size_t count)
{
    return xxemul_write_memory(process->emulator, address, bytes, count) == XXEMUL_STATUS_OK;
}

static int win_read(xxemul_windows *process, uint64_t address, void *bytes, size_t count)
{
    return xxemul_read_memory(process->emulator, address, bytes, count) == XXEMUL_STATUS_OK;
}

static int win_store(xxemul_windows *process, uint64_t address, uint8_t size, uint64_t value)
{
    return xxemul_store_integer(process->emulator, address, size, value) == XXEMUL_STATUS_OK;
}

static int win_load(xxemul_windows *process, uint64_t address, uint8_t size, uint64_t *value)
{
    return xxemul_load_integer(process->emulator, address, size, value) == XXEMUL_STATUS_OK;
}

static int win_guest_string(xxemul_windows *process, uint64_t address, char *buffer, size_t capacity, int wide)
{
    size_t i;
    for (i = 0; i + 1 < capacity; ++i) {
        uint64_t ch;
        if (!win_load(process, address + i * (wide ? 2u : 1u), (uint8_t)(wide ? 2u : 1u), &ch)) return 0;
        if (ch == 0) {
            buffer[i] = '\0';
            return 1;
        }
        if (ch > 0x7f) return 0;
        buffer[i] = (char)ch;
    }
    return 0;
}

static int win_console_read_rect(xxemul_windows *process, uint64_t address, win_console_rect *rect)
{
    uint8_t bytes[8];
    if (!win_read(process, address, bytes, sizeof(bytes))) return 0;
    rect->left = (int16_t)win_le16(bytes);
    rect->top = (int16_t)win_le16(bytes + 2u);
    rect->right = (int16_t)win_le16(bytes + 4u);
    rect->bottom = (int16_t)win_le16(bytes + 6u);
    return 1;
}

static int win_console_write_rect(xxemul_windows *process, uint64_t address, const win_console_rect *rect)
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
    return x >= 0 && x < WIN_CONSOLE_WIDTH && y >= 0 && y < WIN_CONSOLE_HEIGHT;
}

static size_t win_console_index(int x, int y)
{
    return (size_t)y * WIN_CONSOLE_WIDTH + (size_t)x;
}

static int win_write_wide(xxemul_windows *process, uint64_t address, const char *text, size_t capacity)
{
    size_t i, count = strlen(text);
    if (count + 1 > capacity) return 0;
    for (i = 0; i <= count; ++i) {
        if (!win_store(process, address + i * 2u, 2u, (unsigned char)text[i])) return 0;
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
        if (tolower((unsigned char)entry[i]) != tolower((unsigned char)name[i])) return 0;
    }
    return 1;
}

static uint16_t win_reg_ansi(uint8_t c);

static int win_sync_environment(xxemul_windows *process)
{
    uint8_t word_size = win_word_size(process->emulator);
    size_t offset = 0u, index = 0u, i;
    if (!win_write(process, process->environment_a, process->environment_data, process->environment_size)) return 0;
    for (i = 0u; i < process->environment_size; ++i) {
        if (!win_store(process, process->runtime_base + 0x7c00u + i * 2u, 2u, win_reg_ansi((uint8_t)process->environment_data[i]))) return 0;
    }
    while (offset + 1u < process->environment_size && process->environment_data[offset] != '\0') {
        if (index >= WIN_ENV_MAX_ENTRIES || !win_store(process, process->envp_address + index * word_size, word_size, process->environment_a + offset)) return 0;
        ++index;
        offset += strlen(process->environment_data + offset) + 1u;
    }
    return win_store(process, process->envp_address + index * word_size, word_size, 0u);
}

static int win_append_quoted(char *buffer, size_t capacity, size_t *length, const char *arg)
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
        if (entry->capacity >= rounded && (best == NULL || entry->capacity < best->capacity)) best = entry;
    }
    if (best != NULL) {
        best->active = 1u;
        best->size = size;
        best->heap_owner = 0x400u;
        return best->address;
    }
    if (rounded > process->heap_limit - process->heap_cursor) return 0;
    if (free_slot == NULL) {
        if (process->allocation_count >= WIN_MAX_ALLOCATIONS) return 0;
        free_slot = &process->allocations[process->allocation_count++];
    }
    result = process->heap_cursor;
    process->heap_cursor += rounded;
    free_slot->address = result;
    free_slot->size = size;
    free_slot->capacity = rounded;
    free_slot->heap_owner = 0x400u;
    free_slot->active = 1u;
    return result;
}

static win_allocation *win_find_allocation(xxemul_windows *process, uint64_t address)
{
    size_t i;
    for (i = process->allocation_count; i != 0; --i) {
        win_allocation *allocation = &process->allocations[i - 1u];
        if (allocation->active && allocation->address == address) return allocation;
    }
    return NULL;
}

static int win_image_rva(xxemul_windows *process, uint64_t rva, size_t size, const uint8_t **bytes)
{
    if (rva > process->image_size || size > process->image_size - rva) return 0;
    *bytes = process->emulator->region_data + (size_t)rva;
    return 1;
}

static int win_image_string(xxemul_windows *process, uint64_t rva, char *output, size_t capacity)
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

static const char *const win_export_names[] = {"LoadLibraryA",
                                        "LoadLibraryW",
                                        "LoadLibraryExA",
                                        "GetProcAddress",
                                        "ExitProcess",
                                        "VirtualProtect",
                                        "VirtualAlloc",
                                        "VirtualFree",
                                        "GetLastError",
                                        "SetLastError",
                                        "GetCommandLineA",
                                        "GetCommandLineW",
                                        "GetModuleHandleA",
                                        "GetModuleHandleW",
                                        "GetModuleFileNameA",
                                        "GetModuleFileNameW",
                                        "GetStdHandle",
                                        "WriteFile",
                                        "ReadFile",
                                        "CreateFileA",
                                        "CreateFileW",
                                        "CloseHandle",
                                        "SetFilePointer",
                                        "SetFilePointerEx",
                                        "GetFileSize",
                                        "GetFileSizeEx",
                                        "GetFileType",
                                        "FlushFileBuffers",
                                        "GetProcessHeap",
                                        "HeapCreate",
                                        "HeapDestroy",
                                        "InterlockedIncrement",
                                        "InterlockedDecrement",
                                        "HeapAlloc",
                                        "HeapFree",
                                        "HeapReAlloc",
                                        "HeapSize",
                                        "GetCurrentDirectoryA",
                                        "GetCurrentDirectoryW",
                                        "GetEnvironmentStringsA",
                                        "GetEnvironmentStringsW",
                                        "FreeEnvironmentStringsA",
                                        "FreeEnvironmentStringsW",
                                        "GetTickCount",
                                        "GetCurrentProcessId",
                                        "GetCurrentThreadId",
                                        "GetVersion",
                                        "GetACP",
                                        "GetOEMCP",
                                        "GetConsoleOutputCP",
                                        "SetConsoleMode",
                                        "GetConsoleMode",
                                        "GetStartupInfoA",
                                        "GetSystemInfo",
                                        "GetActiveProcessorGroupCount",
                                        "GetActiveProcessorCount",
                                        "QueryPerformanceCounter",
                                        "QueryPerformanceFrequency",
                                        "AddVectoredExceptionHandler",
                                        "RemoveVectoredExceptionHandler",
                                        "CreateEventA",
                                        "SetEvent",
                                        "ResetEvent",
                                        "WaitForSingleObject",
                                        "WaitForMultipleObjects",
                                        "CreateSemaphoreA",
                                        "ReleaseSemaphore",
                                        "DuplicateHandle",
                                        "GetCurrentProcess",
                                        "GetCurrentThread",
                                        "GetConsoleCursorInfo",
                                        "GetConsoleScreenBufferInfo",
                                        "SetConsoleCursorInfo",
                                        "SetConsoleCursorPosition",
                                        "SetConsoleTextAttribute",
                                        "WriteConsoleOutputA",
                                        "ReadConsoleOutputA",
                                        "ScrollConsoleScreenBufferA",
                                        "GetHandleInformation",
                                        "GetProcessAffinityMask",
                                        "SetProcessAffinityMask",
                                        "GetSystemTimeAsFileTime",
                                        "IsDebuggerPresent",
                                        "TlsAlloc",
                                        "TlsGetValue",
                                        "TlsSetValue",
                                        "OutputDebugStringA",
                                        "DebugBreak",
                                        "GetFileTime",
                                        "SetFileTime",
                                        "GetThreadPriority",
                                        "SetThreadPriority",
                                        "SetUnhandledExceptionFilter",
                                        "GetThreadContext",
                                        "IsDBCSLeadByte",
                                        "IsDBCSLeadByteEx",
                                        "MultiByteToWideChar",
                                        "SetDllDirectoryW",
                                        "SetDllDirectoryA",
                                        "AreFileApisANSI",
                                        "GetCPInfo",
                                        "WideCharToMultiByte",
                                        "OpenProcess",
                                        "RaiseException",
                                        "VirtualQuery",
                                        "ResumeThread",
                                        "SuspendThread",
                                        "SetThreadContext",
                                        "Sleep",
                                        "RtlCaptureContext",
                                        "RtlLookupFunctionEntry",
                                        "RtlUnwindEx",
                                        "RtlVirtualUnwind",
                                        "__C_specific_handler",
                                        "InitializeCriticalSection",
                                        "DeleteCriticalSection",
                                        "EnterCriticalSection",
                                        "LeaveCriticalSection",
                                        "TryEnterCriticalSection",
                                        "atoi",
                                        "_iob",
                                        "LoadLibraryExW",
                                        "GetModuleHandleExW",
                                        "GetModuleHandleExA",
                                        "GetStartupInfoW",
                                        "GetVersionExW",
                                        "InitializeCriticalSectionAndSpinCount",
                                        "InitializeCriticalSectionEx",
                                        "FlsAlloc",
                                        "FlsFree",
                                        "FlsGetValue",
                                        "FlsGetValue2",
                                        "FlsSetValue",
                                        "AcquireSRWLockExclusive",
                                        "ReleaseSRWLockExclusive",
                                        "AcquireSRWLockShared",
                                        "ReleaseSRWLockShared",
                                        "SleepConditionVariableSRW",
                                        "WakeAllConditionVariable",
                                        "WakeConditionVariable",
                                        "InitializeSListHead",
                                        "EncodePointer",
                                        "DecodePointer",
                                        "SetErrorMode",
                                        "SetPriorityClass",
                                        "SetThreadExecutionState",
                                        "GetDiskFreeSpaceExW",
                                        "GetDriveTypeW",
                                        "GetVolumeInformationW",
                                        "LCMapStringW",
                                        "GetStringTypeW",
                                        "IsValidCodePage",
                                        "CompareStringW",
                                        "FoldStringW",
                                        "FormatMessageW",
                                        "ExpandEnvironmentStringsW",
                                        "WriteConsoleW",
                                        "ReadConsoleW",
                                        "RtlPcToFileHeader",
                                        "FindFirstFileExW",
                                        "CreateHardLinkW",
                                        "BackupRead",
                                        "BackupSeek",
                                        "DeviceIoControl",
                                        "OpenProcessToken",
                                        "GetTokenInformation",
                                        "LookupPrivilegeValueW",
                                        "AdjustTokenPrivileges",
                                        "CheckTokenMembership",
                                        "AllocateAndInitializeSid",
                                        "FreeSid",
                                        "RegOpenKeyExW",
                                        "RegQueryValueExW",
                                        "RegCloseKey",
                                        "ConvertStringSidToSidW",
                                        "ConvertSidToStringSidW",
                                        "LsaOpenPolicy",
                                        "LsaClose",
                                        "LsaAddAccountRights",
                                        "CharLowerW",
                                        "ExitWindowsEx",
                                        "LoadStringW",
                                        "OemToCharBuffW",
                                        "CharToOemBuffW",
                                        "CharToOemBuffA",
                                        "CharToOemA",
                                        "OemToCharA",
                                        "SetSuspendState",
                                        "SHGetPathFromIDListW",
                                        "SHGetMalloc",
                                        "ShellExecuteExW",
                                        "SHFileOperationW",
                                        "SHGetSpecialFolderLocation",
                                        "CreateThread",
                                        "CreateSemaphoreW",
                                        "CreateEventW",
                                        "FileTimeToSystemTime",
                                        "SystemTimeToFileTime",
                                        "SystemTimeToTzSpecificLocalTime",
                                        "TzSpecificLocalTimeToSystemTime",
                                        "GetSystemTime",
                                        "GetLongPathNameW",
                                        "GetShortPathNameW"};

static const char *const win_extra_export_names[] = {
    "DisableThreadLibraryCalls", "lstrcmpiA", "lstrcmpiW", "CheckSumMappedFile",
    "MoveFileA",
    "FindResourceW", "FindResourceExW",
    "GetEnvironmentVariableA", "GetEnvironmentVariableW", "SetEnvironmentVariableA", "SetCurrentDirectoryA",
    "GetProcessId", "GetThreadId",
    "SetTimer",
    "MoveWindow",
    "DialogBoxParamA", "DialogBoxParamW", "EndDialog", "GetDlgItem", "SetWindowTextA", "SetWindowTextW", "SetDlgItemTextA", "SetDlgItemTextW", "GetWindowTextA", "GetWindowTextW", "GetDlgItemTextA", "GetDlgItemTextW", "SendMessageA", "SendMessageW", "SendDlgItemMessageA", "SendDlgItemMessageW", "LoadIconA", "LoadIconW", "GetObjectA", "GetObjectW", "CreateFontIndirectA", "CreateFontIndirectW", "DeleteObject", "InitCommonControlsEx",
    "SetFileAttributesA",
    "CopyFileA", "CopyFileW",
    "SwitchToThread", "GetTickCount64",
    "_lcreat", "_lwrite",
    "_lopen", "_lread", "_lclose", "_llseek",
    "GlobalMemoryStatus", "GlobalMemoryStatusEx",
    "GetPrivateProfileIntA", "GetPrivateProfileStringA", "LoadBitmapA", "DialogBoxParamA",
    "CreateFileMappingA", "CreateFileMappingW", "MapViewOfFile", "MapViewOfFileEx", "FlushViewOfFile", "UnmapViewOfFile",
    "RegCreateKeyExA", "RegCreateKeyExW", "RegOpenKeyExA", "RegSetValueExA", "RegSetValueExW",
    "GetTempPathA", "GetTempPathW", "GetTempFileNameA", "GetTempFileNameW",
    "DeleteFileA",
    "lstrlenA", "lstrlenW", "HeapValidate",
    "VirtualFreeEx", "VirtualProtectEx", "GetExitCodeThread", "GetKeyboardType", "KillTimer", "ShellExecuteA", "wsprintfA", "wsprintfW", "wvsprintfA", "wvsprintfW",
    "NtSetInformationThread", "ZwSetInformationThread", "atexit", "atoi", "_iob",
    "AllocConsole", "CacheSync", "CharLowerA", "CharLowerBuffA",
    "CharLowerBuffW", "CharNextA", "CharNextW", "CharUpperA",
    "CharUpperBuffA", "CharUpperBuffW", "CharUpperW", "CoTaskMemFree",
    "CompareStringA", "CreateConsoleScreenBuffer", "CreateDirectoryW", "CreatePipe",
    "CreateProcessA", "CreateProcessW", "DeleteFileW", "DosDateTimeToFileTime",
    "EnumCalendarInfoA", "EnumResourceLanguagesA", "EnumResourceNamesA", "EnumResourceTypesA",
    "EnumWindows", "ExitThread", "FileTimeToDosDateTime", "FileTimeToLocalFileTime",
    "FindClose", "FindFirstFileA", "FindFirstFileW", "FindNextFileA",
    "FindNextFileW", "FindResourceA", "FindResourceExA", "FlushConsoleInputBuffer",
    "FlushInstructionCache", "FreeConsole", "FreeLibrary", "FreeResource",
    "GetClipboardData", "GetConsoleCP", "GetDateFormatA", "GetDateFormatW",
    "GetDiskFreeSpaceExA", "GetDriveTypeA", "GetExitCodeProcess", "GetFileAttributesA",
    "GetFileAttributesW", "GetFileInformationByHandle", "GetFileVersionInfoA", "GetFileVersionInfoSizeA",
    "GetFullPathNameW", "GetKeyboardLayout", "GetLargePageMinimum", "GetLocalTime",
    "GetLocaleInfoA", "GetLocaleInfoW", "GetLongPathNameA", "GetNumberOfConsoleMouseButtons",
    "GetProcAddressA", "GetShortPathNameA", "GetSystemDirectoryW", "GetSystemMetrics",
    "GetThreadLocale", "GetUserDefaultLCID", "GetVersionExA", "GetWindowTextA",
    "GetWindowThreadProcessId", "GetWindowsDirectoryA", "GlobalAlloc", "GlobalFree",
    "GlobalLock", "GlobalUnlock", "GlobalHandle", "GlobalReAlloc", "LocalReAlloc", "IsProcessorFeaturePresent", "LoadResource",
    "LocalAlloc", "LocalFileTimeToFileTime", "LocalFree", "LockResource",
    "LookupPrivilegeValueA", "MessageBeep", "MessageBoxA", "MessageBoxW",
    "MoveFileW", "OemToCharBuffA", "OpenClipboard", "OpenThread",
    "PeekNamedPipe", "ReadConsoleInputA", "ReadProcessMemory", "RegOpenKeyExA",
    "RegQueryValueExA", "RemoveDirectoryW", "RtlUnwind", "SafeArrayAccessData",
    "SafeArrayCreate", "SafeArrayGetElement", "SafeArrayGetLBound", "SafeArrayGetUBound",
    "SafeArrayPtrOfIndex", "SafeArrayPutElement", "SafeArrayRedim", "SafeArrayUnaccessData",
    "SetClipboardData", "SetConsoleActiveScreenBuffer", "SetConsoleCP", "SetConsoleCtrlHandler",
    "SetConsoleScreenBufferSize", "SetConsoleWindowInfo", "SetCurrentDirectoryW", "SetEndOfFile",
    "SetEnvironmentVariableW", "SetFileApisToOEM", "SetFileAttributesW", "SetStdHandle",
    "SetThreadLocale", "SetWindowTextA", "SizeofResource", "SleepEx",
    "SysAllocStringLen", "SysFreeString", "SysReAllocStringLen", "TerminateProcess",
    "TerminateThread", "TlsFree", "VariantChangeTypeEx", "VariantClear",
    "VariantCopy", "VariantInit", "VerQueryValueA", "VkKeyScanExA",
    "WriteConsoleInputA", "WriteConsoleOutputW", "_XcptFilter", "___lc_codepage_func",
    "___mb_cur_max_func", "__acrt_iob_func", "__dllonexit", "__getmainargs",
    "__initenv", "__iob_func", "__lconv_init", "__mb_cur_max",
    "__p___argc", "__p___argv", "__p__acmdln", "__p__commode",
    "__p__environ", "__p__fmode", "__set_app_type", "__setusermatherr",
    "__stdio_common_vfprintf", "_acmdln", "_c_exit", "_cexit",
    "_chmod", "_chsize_s", "_close", "_commode",
    "_configthreadlocale", "_configure_narrow_argv", "_crt_atexit", "_errno",
    "_exit", "_fileno", "_fmode", "_fseeki64",
    "_fstat64", "_fstati64", "_ftelli64", "_fullpath",
    "_get_osfhandle", "_gmtime64", "_initialize_narrow_environment", "_initterm",
    "_isatty", "_localtime64", "_lock_file", "_lseeki64",
    "_onexit", "_open", "_read", "_set_app_type",
    "_set_invalid_parameter_handler", "_set_new_mode", "_setmode", "_sopen",
    "_stat64", "_stati64", "_strdup", "_stricmp",
    "_strnicmp", "_time64", "_unlink", "_unlock_file",
    "_waccess", "_wfopen", "_write", "_wstat64",
    "calloc", "clearerr", "clock", "exit",
    "fclose", "feof", "ferror", "fflush",
    "fgetc", "fgets", "fopen", "fputc",
    "fputs", "fread", "free", "fseek",
    "ftell", "fwrite", "getc", "getenv",
    "gmtime", "isalpha", "iscntrl", "isdigit",
    "islower", "ispunct", "isspace", "isupper",
    "isxdigit", "localeconv", "localtime", "lstrcpynA",
    "lstrcpynW", "malloc", "mbrlen", "mbrtowc",
    "memchr", "memcmp", "memcpy", "memmove",
    "memset", "perror", "putc", "qsort",
    "rand", "realloc", "remove", "setlocale",
    "setvbuf", "srand", "strcat", "strchr",
    "strcmp", "strcpy", "strcspn", "strerror",
    "strftime", "strlen", "strncmp", "strncpy",
    "strnlen", "strpbrk", "strrchr", "strspn",
    "strstr", "strtol", "strtoll", "strtoul",
    "strtoull", "time", "tolower", "toupper",
    "ungetc", "vfprintf", "wcrtomb", "wcscmp",
    "wcslen", "wcsnlen",
};

static const char *const win_crt_names[] = {"_controlfp", "_except_handler3", "_filelength", "_filelengthi64", "_chsize", "_access", "__p___initenv", "_adjust_fdiv", "atexit", "atoi",
                                        "_iob",
                                        "__getmainargs",
                                        "__initenv",
                                        "__lconv_init",
                                        "__mb_cur_max",
                                        "__p__acmdln",
                                        "__p__commode",
                                        "__p__fmode",
                                        "__set_app_type",
                                        "_acmdln",
                                        "_commode",
                                        "_fmode",
                                        "__setusermatherr",
                                        "___lc_codepage_func",
                                        "___mb_cur_max_func",
                                        "__iob_func",
                                        "_amsg_exit",
                                        "_beginthreadex",
                                        "_cexit",
                                        "_endthreadex",
                                        "_errno",
                                        "_fstati64",
                                        "_fstat64",
                                        "_get_osfhandle",
                                        "_gmtime64",
                                        "_initterm",
                                        "_kbhit",
                                        "_localtime64",
                                        "_lock",
                                        "_lseeki64",
                                        "_onexit",
                                        "_setjmp3",
                                        "_setjmp",
                                        "_stat64",
                                        "_stati64",
                                        "_time64",
                                        "_ultoa",
                                        "_unlock",
                                        "_wopen",
                                        "abort",
                                        "calloc",
                                        "clock",
                                        "exit",
                                        "fflush",
                                        "fprintf",
                                        "fputc",
                                        "fputs",
                                        "free",
                                        "fwrite",
                                        "getc",
                                        "getchar",
                                        "getenv",
                                        "islower",
                                        "isspace",
                                        "isupper",
                                        "isxdigit",
                                        "localeconv",
                                        "malloc",
                                        "memchr",
                                        "memcmp",
                                        "memcpy",
                                        "memmove",
                                        "memset",
                                        "localtime",
                                        "gmtime",
                                        "printf",
                                        "sprintf",
                                        "vsprintf",
                                        "qsort",
                                        "rand",
                                        "realloc",
                                        "rename",
                                        "setlocale",
                                        "signal",
                                        "srand",
                                        "strchr",
                                        "strcmp",
                                        "strcpy",
                                        "strcspn",
                                        "strerror",
                                        "strlen",
                                        "strncmp",
                                        "strncpy",
                                        "strrchr",
                                        "strstr",
                                        "strtol",
                                        "strtoul",
                                        "tolower",
                                        "ungetc",
                                        "vfprintf",
                                        "time",
                                        "wcslen",
                                        "wcstombs",
                                        "longjmp",
                                        "_write",
                                        "_unlink",
                                        "_stricmp",
                                        "_strdup",
                                        "_sopen",
                                        "_setmode",
                                        "_rmdir",
                                        "_read",
                                        "_open",
                                        "_isatty",
                                        "_fileno",
                                        "_dup",
                                        "_close",
                                        "_chmod"};
static int win_crt_api(const char *name)
{
    size_t index;
    for (index = 0u; index < sizeof(win_crt_names) / sizeof(win_crt_names[0]); ++index) {
        if (strcmp(name, win_crt_names[index]) == 0) return 1;
    }
    return 0;
}

static uint8_t win_argument_count(const char *name)
{
    if(win_equal(name,"DisableThreadLibraryCalls"))return 1u;
    if(win_equal(name,"lstrcmpiA") || win_equal(name,"lstrcmpiW"))return 2u;
    if(win_equal(name,"CheckSumMappedFile"))return 4u;
    if (win_equal(name,"MoveFileA") || win_equal(name,"MoveFileW")) return 2u;
    if (win_equal(name,"FindResourceA") || win_equal(name,"FindResourceW")) return 3u;
    if (win_equal(name,"FindResourceExA") || win_equal(name,"FindResourceExW")) return 4u;
    if (win_equal(name,"LoadResource") || win_equal(name,"SizeofResource")) return 2u;
    if (win_equal(name,"LockResource") || win_equal(name,"FreeResource")) return 1u;
    if (win_equal(name, "GetEnvironmentVariableA") || win_equal(name, "GetEnvironmentVariableW")) return 3u;
    if (win_equal(name, "SetEnvironmentVariableA")) return 2u;
    if (win_equal(name, "SetCurrentDirectoryA")) return 1u;
    if(win_equal(name,"GetProcessId")||win_equal(name,"GetThreadId"))return 1u;
    if (win_equal(name, "SetTimer")) return 4u;
    if (win_equal(name, "MoveWindow")) return 6u;
    if (win_equal(name,"DialogBoxParamA") || win_equal(name,"DialogBoxParamW") || win_equal(name,"SendDlgItemMessageA") || win_equal(name,"SendDlgItemMessageW")) return 5u;
    if (win_equal(name,"SendMessageA") || win_equal(name,"SendMessageW") || win_equal(name,"GetDlgItemTextA") || win_equal(name,"GetDlgItemTextW")) return 4u;
    if (win_equal(name,"GetObjectA") || win_equal(name,"GetObjectW") || win_equal(name,"SetDlgItemTextA") || win_equal(name,"SetDlgItemTextW") || win_equal(name,"GetWindowTextA") || win_equal(name,"GetWindowTextW")) return 3u;
    if (win_equal(name,"EndDialog") || win_equal(name,"GetDlgItem") || win_equal(name,"LoadIconA") || win_equal(name,"LoadIconW") || win_equal(name,"SetWindowTextA") || win_equal(name,"SetWindowTextW")) return 2u;
    if (win_equal(name,"CreateFontIndirectA") || win_equal(name,"CreateFontIndirectW") || win_equal(name,"DeleteObject") || win_equal(name,"InitCommonControlsEx")) return 1u;
    if (win_equal(name, "SetFileAttributesA") || win_equal(name, "SetFileAttributesW")) return 2u;
    if (win_equal(name, "SetHandleCount")) return 1u;
    if (win_equal(name, "CopyFileA") || win_equal(name, "CopyFileW")) return 3u;
    if (win_equal(name, "SleepEx")) return 2u;
    if (win_equal(name, "_lcreat")) return 2u;
    if (win_equal(name, "_lwrite")) return 3u;
    if (win_equal(name, "_lopen")) return 2u;
    if (win_equal(name, "_lread") || win_equal(name, "_llseek")) return 3u;
    if (win_equal(name, "_lclose")) return 1u;
    if (win_equal(name, "FindFirstFileA") || win_equal(name, "FindFirstFileW") ||
        win_equal(name, "FindNextFileA") || win_equal(name, "FindNextFileW")) return 2u;
    if (win_equal(name, "FindFirstFileExW")) return 6u;
    if (win_equal(name, "FindClose")) return 1u;
    if (win_equal(name, "GlobalMemoryStatus") || win_equal(name, "GlobalMemoryStatusEx")) return 1u;
    if (win_equal(name, "GetPrivateProfileIntA")) return 4u;
    if (win_equal(name, "GetPrivateProfileStringA")) return 6u;
    if (win_equal(name, "LoadBitmapA")) return 2u;
    if (win_equal(name, "DialogBoxParamA")) return 5u;
    if (win_equal(name, "_controlfp")) return 2u;
    if (win_equal(name, "_except_handler3")) return 4u;
    if (win_equal(name, "_filelength") || win_equal(name, "_filelengthi64")) return 1u;
    if (win_equal(name, "_chsize") || win_equal(name, "_access")) return 2u;
    if (win_equal(name, "fopen") || win_equal(name, "_wfopen") || win_equal(name, "_waccess")) return 2u;
    if (win_equal(name, "fclose") || win_equal(name, "fgetc") || win_equal(name, "getc") || win_equal(name, "remove")) return 1u;
    if (win_equal(name, "fread") || win_equal(name, "fwrite")) return 4u;
    if (win_equal(name, "_chsize_s")) return 3u;
    if (win_equal(name, "CreateFileMappingA") || win_equal(name, "CreateFileMappingW") || win_equal(name, "MapViewOfFileEx")) return 6u;
    if (win_equal(name, "MapViewOfFile")) return 5u;
    if (win_equal(name, "FlushViewOfFile")) return 2u;
    if (win_equal(name, "UnmapViewOfFile")) return 1u;
    if (win_equal(name, "RegCreateKeyExA") || win_equal(name, "RegCreateKeyExW")) return 9u;
    if (win_equal(name, "RegSetValueExA") || win_equal(name, "RegSetValueExW")) return 6u;
    if (win_equal(name, "GetTempPathA") || win_equal(name, "GetTempPathW")) return 2u;
    if (win_equal(name, "GetTempFileNameA") || win_equal(name, "GetTempFileNameW")) return 4u;
    if (win_equal(name, "DeleteFileA") || win_equal(name, "DeleteFileW")) return 1u;
    if (win_equal(name, "lstrlenA") || win_equal(name, "lstrlenW")) return 1u;
    if (win_equal(name, "HeapValidate")) return 3u;
    if (win_equal(name, "wvsprintfA") || win_equal(name, "wvsprintfW") || win_equal(name, "vsprintf") || win_equal(name, "vfprintf")) return 3u;
    if (win_equal(name, "sprintf") || win_equal(name, "fprintf")) return 2u;
    if (win_equal(name, "printf")) return 1u;
    if (win_equal(name, "NtSetInformationThread") || win_equal(name, "ZwSetInformationThread") || win_equal(name, "VirtualFreeEx")) return 4u;
    if (win_equal(name, "VirtualProtectEx") || win_equal(name, "VirtualAllocEx")) return 5u;
    if (win_equal(name, "GetExitCodeThread") || win_equal(name, "KillTimer") || win_equal(name, "wsprintfA") || win_equal(name, "wsprintfW")) return 2u;
    if (win_equal(name, "ShellExecuteA")) return 6u;
    if (win_equal(name, "GetKeyboardType") || win_equal(name, "atexit") || win_equal(name, "ResumeThread") || win_equal(name, "ExitThread")) return 1u;
    if (win_equal(name, "GetLongPathNameA") || win_equal(name, "GetLongPathNameW") ||
        win_equal(name, "lstrcpynA") || win_equal(name, "lstrcpynW")) return 3u;
    if (win_equal(name, "CharNextA") || win_equal(name, "CharNextW")) return 1u;
    if (win_equal(name, "MessageBoxA") || win_equal(name, "MessageBoxW")) return 4u;
    if (win_equal(name, "AllocateAndInitializeSid")) return 11u;
    if (win_equal(name, "CreateProcessA") || win_equal(name, "CreateProcessW")) return 10u;
    if (win_equal(name, "DeviceIoControl") || win_equal(name, "WideCharToMultiByte") || win_equal(name, "GetVolumeInformationW") || win_equal(name, "RtlVirtualUnwind"))
        return 8u;
    if (win_equal(name, "CreateFileA") || win_equal(name, "CreateFileW") || win_equal(name, "DuplicateHandle") || win_equal(name, "BackupRead") ||
        win_equal(name, "FormatMessageW"))
        return 7u;
    if (win_equal(name, "MultiByteToWideChar") || win_equal(name, "CompareStringA") || win_equal(name, "CompareStringW") || win_equal(name, "CreateThread") ||
        win_equal(name, "FindFirstFileExW") || win_equal(name, "GetDateFormatA") || win_equal(name, "GetDateFormatW") || win_equal(name, "PeekNamedPipe") ||
        win_equal(name, "RegQueryValueExA") || win_equal(name, "RegQueryValueExW") || win_equal(name, "LCMapStringW") || win_equal(name, "BackupSeek") ||
        win_equal(name, "AdjustTokenPrivileges"))
        return 6u;
    if (win_equal(name, "ReadFile") || win_equal(name, "WriteFile") || win_equal(name, "WriteConsoleOutputA") || win_equal(name, "ReadConsoleOutputA") ||
        win_equal(name, "ScrollConsoleScreenBufferA") || win_equal(name, "__getmainargs") || win_equal(name, "CreateConsoleScreenBuffer") ||
        win_equal(name, "EnumResourceLanguagesA") || win_equal(name, "ReadProcessMemory") || win_equal(name, "WriteConsoleOutputW") ||
        win_equal(name, "VariantChangeTypeEx") || win_equal(name, "RegOpenKeyExA") || win_equal(name, "RegOpenKeyExW") || win_equal(name, "WriteConsoleW") ||
        win_equal(name, "ReadConsoleW") || win_equal(name, "FoldStringW") || win_equal(name, "GetTokenInformation") || win_equal(name, "__stdio_common_vfprintf"))
        return 5u;
    if (win_equal(name, "VirtualProtect") || win_equal(name, "VirtualAlloc") || win_equal(name, "qsort") || win_equal(name, "CreateEventA") ||
        win_equal(name, "CreateSemaphoreA") || win_equal(name, "RaiseException") || win_equal(name, "WaitForMultipleObjects") || win_equal(name, "GetFileTime") ||
        win_equal(name, "SetFileTime") || win_equal(name, "HeapReAlloc") || win_equal(name, "SetFilePointer") || win_equal(name, "SetFilePointerEx") ||
        win_equal(name, "_sopen") || win_equal(name, "_lseeki64") || win_equal(name, "CreatePipe") || win_equal(name, "EnumCalendarInfoA") ||
        win_equal(name, "EnumResourceNamesA") || win_equal(name, "FindResourceExA") || win_equal(name, "GetFullPathNameW") || win_equal(name, "GetLocaleInfoA") ||
        win_equal(name, "GetLocaleInfoW") || win_equal(name, "ReadConsoleInputA") || win_equal(name, "WriteConsoleInputA") || win_equal(name, "RtlUnwind") ||
        win_equal(name, "MessageBoxA") || win_equal(name, "GetFileVersionInfoA") || win_equal(name, "SleepConditionVariableSRW") ||
        win_equal(name, "GetDiskFreeSpaceExW") || win_equal(name, "GetStringTypeW") || win_equal(name, "LoadStringW") || win_equal(name, "LoadStringA") || win_equal(name, "LsaOpenPolicy") ||
        win_equal(name, "CreateSemaphoreW") || win_equal(name, "CreateEventW") || win_equal(name, "RtlUnwindEx") || win_equal(name, "VerQueryValueA"))
        return 4u;
    if (win_equal(name, "FlushInstructionCache") || win_equal(name, "GetModuleFileNameA") || win_equal(name, "GetModuleFileNameW") || win_equal(name, "VirtualFree") || win_equal(name, "HeapAlloc") ||
        win_equal(name, "HeapFree") || win_equal(name, "HeapSize") || win_equal(name, "HeapCreate") || win_equal(name, "GlobalReAlloc") || win_equal(name, "LocalReAlloc") || win_equal(name, "LoadLibraryExA") || win_equal(name, "LoadLibraryExW") ||
        win_equal(name, "GetProcessAffinityMask") || win_equal(name, "GetModuleHandleExW") || win_equal(name, "GetModuleHandleExA") ||
        win_equal(name, "InitializeCriticalSectionEx") || win_equal(name, "ExpandEnvironmentStringsW") || win_equal(name, "OpenProcessToken") ||
        win_equal(name, "LookupPrivilegeValueW") || win_equal(name, "LookupPrivilegeValueA") || win_equal(name, "CheckTokenMembership") ||
        win_equal(name, "OemToCharBuffW") || win_equal(name, "CharToOemBuffW") || win_equal(name, "CharToOemBuffA") || win_equal(name, "SetSuspendState") ||
        win_equal(name, "SHGetSpecialFolderLocation") || win_equal(name, "LsaAddAccountRights") || win_equal(name, "CreateHardLinkW") ||
        win_equal(name, "SystemTimeToTzSpecificLocalTime") || win_equal(name, "TzSpecificLocalTimeToSystemTime") || win_equal(name, "GetLongPathNameW") ||
        win_equal(name, "VirtualQuery") || win_equal(name, "OpenProcess") || win_equal(name, "_open") || win_equal(name, "_read") || win_equal(name, "_write") ||
        win_equal(name, "memchr") || win_equal(name, "memcmp") || win_equal(name, "memcpy") || win_equal(name, "memmove") || win_equal(name, "memset") ||
        win_equal(name, "strtol") || win_equal(name, "strtoul") || win_equal(name, "strncmp") || win_equal(name, "strncpy") || win_equal(name, "ReleaseSemaphore") ||
        win_equal(name, "SysReAllocStringLen") || win_equal(name, "SetConsoleWindowInfo") || win_equal(name, "EnumResourceTypesA") || win_equal(name, "FindResourceA") ||
        win_equal(name, "FileTimeToDosDateTime") || win_equal(name, "DosDateTimeToFileTime") || win_equal(name, "GetShortPathNameA") || win_equal(name, "OpenThread") ||
        win_equal(name, "SafeArrayCreate") || win_equal(name, "SafeArrayGetElement") || win_equal(name, "SafeArrayGetLBound") || win_equal(name, "SafeArrayGetUBound") ||
        win_equal(name, "SafeArrayPtrOfIndex") || win_equal(name, "SafeArrayPutElement") || win_equal(name, "GetWindowTextA") || win_equal(name, "OemToCharBuffA") ||
        win_equal(name, "fseek"))
        return 3u;
    if (win_equal(name, "GetProcAddress") || win_equal(name, "AddVectoredExceptionHandler") || win_equal(name, "WaitForSingleObject") ||
        win_equal(name, "GetCurrentDirectoryA") || win_equal(name, "GetCurrentDirectoryW") || win_equal(name, "GetFileSize") || win_equal(name, "GetFileSizeEx") ||
        win_equal(name, "GetConsoleMode") || win_equal(name, "SetConsoleMode") || win_equal(name, "GetConsoleCursorInfo") ||
        win_equal(name, "GetConsoleScreenBufferInfo") || win_equal(name, "SetConsoleCursorInfo") || win_equal(name, "SetConsoleCursorPosition") ||
        win_equal(name, "SetConsoleTextAttribute") || win_equal(name, "GetHandleInformation") || win_equal(name, "SetProcessAffinityMask") ||
        win_equal(name, "SetThreadPriority") || win_equal(name, "GetThreadContext") || win_equal(name, "SetThreadContext") || win_equal(name, "IsDBCSLeadByteEx") ||
        win_equal(name, "_initterm") || win_equal(name, "setlocale") || win_equal(name, "calloc") || win_equal(name, "realloc") || win_equal(name, "strchr") ||
        win_equal(name, "strrchr") || win_equal(name, "strstr") || win_equal(name, "strcspn") || win_equal(name, "strcmp") || win_equal(name, "_stricmp") ||
        win_equal(name, "strcpy") || win_equal(name, "_stati64") || win_equal(name, "_stat64") || win_equal(name, "_fstati64") || win_equal(name, "_fstat64") ||
        win_equal(name, "_chmod") || win_equal(name, "LocalAlloc") || win_equal(name, "GlobalAlloc") || win_equal(name, "SetConsoleCtrlHandler") ||
        win_equal(name, "FindFirstFileA") || win_equal(name, "FindFirstFileW") || win_equal(name, "FindNextFileA") || win_equal(name, "FindNextFileW") ||
        win_equal(name, "GetFileInformationByHandle") || win_equal(name, "SysAllocStringLen") || win_equal(name, "SetConsoleScreenBufferSize") ||
        win_equal(name, "TlsSetValue") || win_equal(name, "FlsSetValue") || win_equal(name, "InitializeCriticalSectionAndSpinCount") ||
        win_equal(name, "RtlPcToFileHeader") || win_equal(name, "SetPriorityClass") || win_equal(name, "SetFileAttributesW") ||
        win_equal(name, "ConvertStringSidToSidW") || win_equal(name, "ConvertSidToStringSidW") || win_equal(name, "CharToOemA") || win_equal(name, "OemToCharA") ||
        win_equal(name, "ExitWindowsEx") || win_equal(name, "SHGetPathFromIDListW") || win_equal(name, "FileTimeToSystemTime") ||
        win_equal(name, "SystemTimeToFileTime") || win_equal(name, "CreateDirectoryW") || win_equal(name, "MoveFileW") || win_equal(name, "SetEnvironmentVariableW") ||
        win_equal(name, "GetCPInfo") || win_equal(name, "GetExitCodeProcess") || win_equal(name, "GetWindowsDirectoryA") || win_equal(name, "GetSystemDirectoryW") ||
        win_equal(name, "LocalFileTimeToFileTime") || win_equal(name, "FileTimeToLocalFileTime") || win_equal(name, "LoadResource") ||
        win_equal(name, "SizeofResource") || win_equal(name, "SetStdHandle") || win_equal(name, "SleepEx") || win_equal(name, "TerminateProcess") ||
        win_equal(name, "TerminateThread") || win_equal(name, "SafeArrayAccessData") || win_equal(name, "SafeArrayRedim") || win_equal(name, "VariantCopy") ||
        win_equal(name, "CharLowerBuffA") || win_equal(name, "CharLowerBuffW") || win_equal(name, "CharUpperBuffA") || win_equal(name, "CharUpperBuffW") ||
        win_equal(name, "EnumWindows") || win_equal(name, "GetWindowThreadProcessId") || win_equal(name, "SetClipboardData") || win_equal(name, "SetWindowTextA") ||
        win_equal(name, "VkKeyScanExA") || win_equal(name, "GetFileVersionInfoSizeA") || win_equal(name, "fputc") || win_equal(name, "putc") ||
        win_equal(name, "ungetc") || win_equal(name, "fputs") || win_equal(name, "_setmode"))
        return 2u;
    if (win_equal(name, "CacheSync") || win_equal(name, "QueryPerformanceCounter") || win_equal(name, "QueryPerformanceFrequency") || win_equal(name, "LoadLibraryA") ||
        win_equal(name, "LoadLibraryW") || win_equal(name, "ExitProcess") || win_equal(name, "exit") || win_equal(name, "GetModuleHandleA") ||
        win_equal(name, "GetModuleHandleW") || win_equal(name, "GetStdHandle") || win_equal(name, "GetFileType") || win_equal(name, "FlushFileBuffers") ||
        win_equal(name, "CloseHandle") || win_equal(name, "HeapDestroy") || win_equal(name, "InterlockedIncrement") || win_equal(name, "InterlockedDecrement") ||
        win_equal(name, "RegCloseKey") || win_equal(name, "UnhandledExceptionFilter") || win_equal(name, "RemoveVectoredExceptionHandler") || win_equal(name, "InitializeCriticalSection") ||
        win_equal(name, "DeleteCriticalSection") || win_equal(name, "EnterCriticalSection") || win_equal(name, "LeaveCriticalSection") ||
        win_equal(name, "TryEnterCriticalSection") || win_equal(name, "GetSystemTimeAsFileTime") || win_equal(name, "GetThreadPriority") ||
        win_equal(name, "SetUnhandledExceptionFilter") || win_equal(name, "TlsGetValue") || win_equal(name, "FlsGetValue") || win_equal(name, "FlsGetValue2") ||
        win_equal(name, "FlsAlloc") || win_equal(name, "FlsFree") || win_equal(name, "AcquireSRWLockExclusive") || win_equal(name, "ReleaseSRWLockExclusive") ||
        win_equal(name, "AcquireSRWLockShared") || win_equal(name, "ReleaseSRWLockShared") || win_equal(name, "WakeAllConditionVariable") ||
        win_equal(name, "WakeConditionVariable") || win_equal(name, "InitializeSListHead") || win_equal(name, "EncodePointer") || win_equal(name, "DecodePointer") ||
        win_equal(name, "SetErrorMode") || win_equal(name, "SetThreadExecutionState") || win_equal(name, "GetDriveTypeW") || win_equal(name, "GetDriveTypeA") ||
        win_equal(name, "IsValidCodePage") || win_equal(name, "FreeSid") || win_equal(name, "CharLowerW") || win_equal(name, "SHGetMalloc") ||
        win_equal(name, "ShellExecuteExW") || win_equal(name, "SHFileOperationW") || win_equal(name, "LsaClose") || win_equal(name, "GetStartupInfoW") ||
        win_equal(name, "GetVersionExW") || win_equal(name, "GetSystemTime") || win_equal(name, "GetShortPathNameW") || win_equal(name, "IsDBCSLeadByte") ||
        win_equal(name, "SetDllDirectoryW") || win_equal(name, "SetDllDirectoryA") || win_equal(name, "AreFileApisANSI") || win_equal(name, "GetCPInfo") ||
        win_equal(name, "OutputDebugStringA") || win_equal(name, "SetEvent") || win_equal(name, "ResetEvent") || win_equal(name, "SetLastError") ||
        win_equal(name, "GetStartupInfoA") || win_equal(name, "GetSystemInfo") || win_equal(name, "GetActiveProcessorGroupCount") ||
        win_equal(name, "GetActiveProcessorCount") || win_equal(name, "ResumeThread") || win_equal(name, "SuspendThread") || win_equal(name, "Sleep") ||
        win_equal(name, "__set_app_type") || win_equal(name, "__setusermatherr") || win_equal(name, "malloc") || win_equal(name, "free") || win_equal(name, "strlen") ||
        win_equal(name, "wcslen") || win_equal(name, "_strdup") || win_equal(name, "_onexit") || win_equal(name, "_time64") || win_equal(name, "time") ||
        win_equal(name, "srand") || win_equal(name, "_get_osfhandle") || win_equal(name, "_isatty") || win_equal(name, "_fileno") || win_equal(name, "_close") ||
        win_equal(name, "_unlink") || win_equal(name, "fflush") || win_equal(name, "ftell") || win_equal(name, "_ftelli64") || win_equal(name, "feof") ||
        win_equal(name, "clearerr") || win_equal(name, "ferror") || win_equal(name, "getenv") || win_equal(name, "tolower") || win_equal(name, "islower") ||
        win_equal(name, "isspace") || win_equal(name, "isupper") || win_equal(name, "isxdigit") || win_equal(name, "LocalFree") || win_equal(name, "GlobalFree") ||
        win_equal(name, "GlobalLock") || win_equal(name, "GlobalUnlock") || win_equal(name, "GlobalHandle") || win_equal(name, "TlsFree") || win_equal(name, "IsProcessorFeaturePresent") ||
        win_equal(name, "CharUpperW") || win_equal(name, "GetFileAttributesA") || win_equal(name, "GetFileAttributesW") || win_equal(name, "FindClose") ||
        win_equal(name, "SetEndOfFile") || win_equal(name, "SysFreeString") || win_equal(name, "GetVersionExA") || win_equal(name, "SetThreadLocale") ||
        win_equal(name, "SetConsoleCP") || win_equal(name, "SetConsoleActiveScreenBuffer") || win_equal(name, "FlushConsoleInputBuffer") ||
        win_equal(name, "GetNumberOfConsoleMouseButtons") || win_equal(name, "GetLocalTime") || win_equal(name, "FreeLibrary") || win_equal(name, "DeleteFileW") ||
        win_equal(name, "ExitThread") || win_equal(name, "FreeEnvironmentStringsA") || win_equal(name, "FreeEnvironmentStringsW") || win_equal(name, "FreeResource") || win_equal(name, "LockResource") ||
        win_equal(name, "RemoveDirectoryW") || win_equal(name, "SetCurrentDirectoryW") || win_equal(name, "RegCloseKey") || win_equal(name, "CoTaskMemFree") ||
        win_equal(name, "SafeArrayUnaccessData") || win_equal(name, "VariantClear") || win_equal(name, "VariantInit") || win_equal(name, "CharLowerA") ||
        win_equal(name, "CharUpperA") || win_equal(name, "GetClipboardData") || win_equal(name, "GetKeyboardLayout") || win_equal(name, "GetSystemMetrics") ||
        win_equal(name, "MessageBeep") || win_equal(name, "OpenClipboard") || win_equal(name, "GetActiveProcessorCount") || win_equal(name, "atoi"))
        return 1u;
    return 0u;
}

static win_module *win_find_module(xxemul_windows *process, const char *name, int create);
static int win_loadable_module(xxemul_windows *process, const char *name);
static win_module *win_dll_at(xxemul_windows *process, uint64_t handle);
static uint64_t win_dll_load(xxemul_windows *process,const char *name,uint32_t flags);
static uint64_t win_dll_export(xxemul_windows *process,win_module *module,const char *name,unsigned depth,int by_ordinal);
static int win_guest_module_span(xxemul_windows *process,uint64_t handle,uint64_t *base,uint64_t *size,uint32_t *generation);
static int win_set_guest_directory(xxemul_windows *process, const char *guest);
static int win_module_exports(xxemul_windows *process, win_module *module);
static int win_loader_lists(xxemul_windows *process);

static uint64_t win_data_address(const xxemul_windows *process, unsigned index)
{
    static const unsigned offsets[7] = {0, WIN_CRT_DATA_OFFSET, WIN_CRT_DATA_OFFSET + 8u, WIN_CRT_DATA_OFFSET + 16u, WIN_CRT_DATA_OFFSET + 24u, WIN_CRT_DATA_OFFSET + 28u, WIN_CRT_DATA_OFFSET + 36u};
    return index ? process->runtime_base + offsets[index] : process->iob_address;
}

static const char *win_data_symbol(const xxemul_windows *process, uint64_t address, int qualified)
{
    unsigned index;
    for (index = 0; index < 7; ++index) {
        const char *name = process->data_qualified[index];
        if (*name && address == win_data_address(process, index)) return qualified ? name : strchr(name, '!') + 1;
    }
    return NULL;
}

static uint64_t win_resolve(xxemul_windows *process, const char *module, const char *name)
{
    size_t i;
    win_api *api;
    uint64_t address;
    int is_crt;
    win_module *mapped = win_find_module(process, module, 0);
    if(mapped==NULL){
        if(win_loadable_module(process,module))mapped=win_find_module(process,module,1);
        else mapped=win_dll_at(process,win_dll_load(process,module,0u));
    }
    if (mapped == NULL) return 0;
    if (mapped->real) return win_dll_export(process,mapped,name,0u,0);
    module = mapped->name;
    if (strcmp(name, "GetProcAddressA") == 0) name = "GetProcAddress";
    is_crt = win_crt_api(name) || win_suffix(module, "msvcrt.dll") || win_suffix(module, "ucrtbase.dll") || strstr(module, "api-ms-win-crt-") != NULL;
    {
        static const char *const data_names[7] = {"_iob", "__initenv", "__mb_cur_max", "_acmdln", "_commode", "_fmode", "_adjust_fdiv"};
        unsigned data_index;
        for (data_index = 0; data_index < 7; ++data_index) if (win_equal(name, data_names[data_index])) {
            snprintf(process->data_qualified[data_index], sizeof(process->data_qualified[data_index]), "%s!%s", module, data_names[data_index]);
            return win_data_address(process, data_index);
        }
    }
    for (i = 0; i < process->api_count; ++i) {
        if (win_equal(process->apis[i].module, module) && strcmp(process->apis[i].name, name) == 0)
            return process->runtime_base + WIN_THUNK_OFFSET + i * WIN_THUNK_STRIDE;
    }
    if (process->api_count >= WIN_MAX_APIS) return 0;
    api = &process->apis[process->api_count];
    if (!win_copy(api->module, sizeof(api->module), module) || !win_copy(api->name, sizeof(api->name), name)) return 0;
    snprintf(api->qualified, sizeof(api->qualified), "%s!%s", api->module, api->name);
    api->argument_count = win_argument_count(name);
    if (process->emulator->mode == XXEMUL_MODE_X86_32 && strcmp(name, "SetFilePointerEx") == 0) api->argument_count = 5u;
    if (process->emulator->mode == XXEMUL_MODE_X86_64 && strcmp(name, "_lseeki64") == 0) api->argument_count = 3u;
    if (process->emulator->mode == XXEMUL_MODE_X86_64 && strcmp(name, "_chsize_s") == 0) api->argument_count = 2u;
    api->caller_cleans = (uint8_t)(is_crt || win_equal(name, "wsprintfA") || win_equal(name, "wsprintfW"));
    address = process->runtime_base + WIN_THUNK_OFFSET + process->api_count * WIN_THUNK_STRIDE;
    /* Dispatch is address based; an INT3 byte would falsely trip guest
     * anti-debug checks that inspect the imported function's prologue. */
    if (!win_store(process, address, 1u, 0x90u) || !win_store(process, address + 1u, 1u, 0xc3u)) return 0;
    ++process->api_count;
    if (!mapped->building && !win_module_exports(process, mapped)) return 0;
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

static int win_bind_imports(xxemul_windows *process, const uint8_t *optional, size_t optional_size, int is_64)
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
    if (import_rva >= process->image_size) return 0;
    /* The Windows loader follows a terminated descriptor array even when a
     * packer omits the optional directory byte count. Keep the image bound. */
    if (import_size < 20u) import_size = process->image_size - import_rva;
    if (import_size < 20u || import_size > process->image_size || !win_image_rva(process, import_rva, import_size, &descriptor)) return 0;
    for (descriptor_index = 0; descriptor_index + 20u <= import_size; descriptor_index += 20u) {
        const uint8_t *entry = descriptor + descriptor_index;
        uint32_t lookup_rva = win_le32(entry);
        uint32_t module_rva = win_le32(entry + 12u);
        uint32_t iat_rva = win_le32(entry + 16u);
        char module[48];
        size_t symbol_index;
        if (module_rva == 0 || iat_rva == 0) return 1;
        if (module_rva == 0 || iat_rva == 0 || !win_image_string(process, module_rva, module, sizeof(module))) return 0;
        if (lookup_rva == 0) lookup_rva = iat_rva;
        for (symbol_index = 0; symbol_index < 4096u; ++symbol_index) {
            uint64_t raw, slot_rva, source_rva, address;
            const uint8_t *slot;
            char name[96];
            source_rva = (uint64_t)lookup_rva + symbol_index * pointer_size;
            slot_rva = (uint64_t)iat_rva + symbol_index * pointer_size;
            if (!win_image_rva(process, source_rva, pointer_size, &slot) || !win_image_rva(process, slot_rva, pointer_size, &slot)) return 0;
            slot = process->emulator->region_data + (size_t)source_rva;
            raw = is_64 ? win_le64(slot) : win_le32(slot);
            if (raw == 0) break;
            if (raw & (is_64 ? UINT64_C(0x8000000000000000) : UINT64_C(0x80000000))) {
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
                if (raw > UINT32_MAX || !win_image_string(process, raw + 2u, name, sizeof(name))) return 0;
            }
            if(raw & (is_64 ? UINT64_C(0x8000000000000000) : UINT64_C(0x80000000))){
                win_module *real_module=win_find_module(process,module,0);
                if(!real_module && !win_loadable_module(process,module)) {
                    real_module=win_dll_at(process,win_dll_load(process,module,0u));
                    if(!real_module)return 0;
                }
                if(real_module&&real_module->real){
                    char ordinal_name[16];snprintf(ordinal_name,sizeof(ordinal_name),"#%u",(unsigned)(raw&0xffffu));
                    address=win_dll_export(process,real_module,ordinal_name,0u,1);
                } else address=win_resolve(process,module,name);
            } else address=win_resolve(process,module,name);
            if (address == 0 || !win_store(process, process->image_base + slot_rva, pointer_size, address)) return 0;
        }
        if (symbol_index == 4096u) return 0;
        if (process->main_dll_slot) {
            win_module *dependency = win_find_module(process, module, 0);
            if (dependency && dependency->real && !dependency->primary)
                process->modules[process->main_dll_slot - 1u].dependencies |= UINT32_C(1) << (size_t)(dependency - process->modules);
        }
    }
    return 1;
}

#include "xxemul_windows_tls.inc"

static int win_bind_tls(xxemul_windows *process, const uint8_t *optional, size_t optional_size, int is_64)
{
    size_t directory = is_64 ? 112u : 96u;
    uint32_t rva = 0u, size = 0u;
    if (optional_size >= directory + 80u && win_le32(optional + directory - 4u) > 9u) {
        rva = win_le32(optional + directory + 72u);
        size = win_le32(optional + directory + 76u);
    }
    return win_tls_bind_image(process, process->main_dll_slot ? &process->modules[process->main_dll_slot - 1u].tls : &process->main_tls,
                              process->image_base, process->image_size, rva, size, 0u, 1);
}

static int win_primary_dll_register(xxemul_windows *process, const uint8_t *optional, size_t optional_size, int is_64)
{
    uint32_t nt = win_le32(process->emulator->region_data + 0x3cu);
    size_t directory = is_64 ? 112u : 96u, slot = process->module_count, i;
    const char *leaf = process->program_path, *at;
    win_module *module;
    if (!(win_le16(process->emulator->region_data + nt + 22u) & 0x2000u)) return 1;
    if (process->emulator->arch != XXEMUL_ARCH_X86 || slot >= WIN_MAX_MODULES || optional_size < directory + 16u ||
        win_le32(optional + 16u) >= process->image_size || process->dll_generation == UINT32_MAX) return 0;
    module = &process->modules[slot];
    memset(module, 0, sizeof(*module));
    for (at = leaf; *at; ++at) if (*at == '/' || *at == '\\') leaf = at + 1;
    if (!win_copy(module->name, sizeof(module->name), leaf) ||
        !win_copy(module->file_path, sizeof(module->file_path), process->program_path)) return 0;
    for (i = 0u; module->name[i]; ++i) module->name[i] = (char)tolower((unsigned char)module->name[i]);
#if defined(_WIN32)
    { char absolute[2048]; DWORD length = GetFullPathNameA(process->program_path, sizeof(absolute), absolute, NULL);
      if (length && length < sizeof(absolute)) (void)win_copy(module->file_path, sizeof(module->file_path), absolute); }
#else
    { char *absolute = realpath(process->program_path, NULL);
      if (absolute) { int copied = win_copy(module->file_path, sizeof(module->file_path), absolute); free(absolute); if (!copied) return 0; } }
#endif
    module->base = process->image_base;
    module->image_size = process->image_size;
    module->generation = ++process->dll_generation;
    module->references = 1u;
    module->entry_rva = win_le32(optional + 16u);
    module->export_rva = win_le32(optional + directory);
    module->export_size = win_le32(optional + directory + 4u);
    module->resource_rva = process->resource_rva;
    module->resource_size = process->resource_size;
    module->real = module->live = module->primary = 1u;
    ++process->module_count;
    process->main_dll_slot = (uint8_t)(slot + 1u);
    return win_loader_lists(process);
}

static int win_guest_program_path(const xxemul_windows *process, char *path, size_t capacity)
{
    const char *base = process->program_path, *at;
    size_t length;
    for (at = base; *at; ++at) if (*at == '/' || *at == '\\') base = at + 1u;
    length = strlen(base);
    if (!length || length + 4u > capacity || strpbrk(base, ":\"<>|?*")) return 0;
    memcpy(path, "C:\\", 3u);
    memcpy(path + 3u, base, length + 1u);
    return 1;
}

static int win_main_program_name(const xxemul_windows *process, const char *name)
{
    char program[1024], normalized[1024];
    size_t i;
    if (!win_guest_program_path(process, program, sizeof(program)) || !win_copy(normalized, sizeof(normalized), name)) return 0;
    for (i = 0u; normalized[i]; ++i) if (normalized[i] == '/') normalized[i] = '\\';
    return win_equal(normalized, program) || win_equal(normalized, program + 3u) || win_equal(name, process->program_path);
}

static int win_prepare_runtime(xxemul_windows *process, const char *const *arguments, size_t argument_count)
{
    xxemul *emulator = process->emulator;
    uint64_t peb = process->runtime_base + 0x2000u;
    uint64_t params = process->runtime_base + 0x4000u;
    uint64_t stack_top = (process->runtime_base - 0x100u) & ~UINT64_C(15);
    uint8_t word_size = (uint8_t)(win_word_size(emulator));
    char command_line[2048], guest_program[1024];
    uint64_t string_cursor;
    size_t i, length = 0;

    command_line[0] = '\0';
    if (!win_guest_program_path(process, guest_program, sizeof(guest_program)) ||
        !win_append_quoted(command_line, sizeof(command_line), &length, guest_program)) return 0;
    for (i = 0; i < argument_count; ++i) {
        if (arguments == NULL || arguments[i] == NULL || !win_append_quoted(command_line, sizeof(command_line), &length, arguments[i])) return 0;
    }
    process->command_line_a = process->runtime_base + 0x6000u;
    process->command_line_w = process->runtime_base + 0x6800u;
    process->environment_a = process->runtime_base + 0x7800u;
    process->iob_address = process->runtime_base + 0xf0000u;
    process->argv_address = process->runtime_base + WIN_CRT_ARGV_OFFSET;
    process->envp_address = process->runtime_base + WIN_CRT_ENVP_OFFSET;
    memcpy(process->environment_data, "PATH=.\0", 8u);
    process->environment_size = 8u;
    if (argument_count >= 0x800u / word_size - 1u) return 0;
    process->argc = (uint32_t)(argument_count + 1u);
    if (!win_write(process, process->command_line_a, command_line, length + 1u) || !win_write_wide(process, process->command_line_w, command_line, 2048u) ||
        !win_sync_environment(process) || !win_store(process, stack_top, word_size, 0))
        return 0;
    string_cursor = process->runtime_base + WIN_CRT_STRINGS_OFFSET;
    for (i = 0u; i < process->argc; ++i) {
        const char *argument = i == 0u ? guest_program : arguments[i - 1u];
        size_t bytes = strlen(argument) + 1u;
        if (bytes > process->runtime_base + WIN_RUNTIME_SIZE - string_cursor || !win_write(process, string_cursor, argument, bytes) ||
            !win_store(process, process->argv_address + i * word_size, word_size, string_cursor))
            return 0;
        string_cursor += bytes;
    }
    if (!win_store(process, process->argv_address + process->argc * word_size, word_size, 0u) ||
        !win_store(process, process->runtime_base + WIN_CRT_DATA_OFFSET, word_size, process->envp_address) ||
        !win_store(process, process->runtime_base + WIN_CRT_DATA_OFFSET + 8u, 4u, 1u) ||
        !win_store(process, process->runtime_base + WIN_CRT_DATA_OFFSET + 16u, word_size, process->command_line_a) ||
        !win_store(process, process->runtime_base + WIN_CRT_DATA_OFFSET + 28u, 4u, 0x4000u) ||
        !win_store(process, process->runtime_base + WIN_CRT_DATA_OFFSET + 36u, 4u, 0u) ||
        !win_store(process, process->runtime_base + WIN_CRT_DATA_OFFSET + 40u, 4u, process->argc) ||
        !win_store(process, process->runtime_base + WIN_CRT_DATA_OFFSET + 48u, word_size, process->argv_address) ||
        !win_store(process, process->runtime_base + WIN_CRT_DATA_OFFSET + 56u, word_size, process->envp_address) ||
        !win_write(process, process->runtime_base + 0xbb00u, ".\0\0C\0", 5u))
        return 0;
    for (i = 0u; i < 10u; ++i) {
        if (!win_store(process, process->runtime_base + WIN_CRT_LOCALE_OFFSET + i * word_size, word_size, process->runtime_base + (i == 0u ? 0xbb00u : 0xbb02u)))
            return 0;
    }
    for (i = 0u; i < 8u; ++i) {
        if (!win_store(process, process->runtime_base + WIN_CRT_LOCALE_OFFSET + 10u * word_size + i, 1u, 0xffu)) return 0;
    }

    if (!win_tls_thread_create(process, &process->threads[0])) return 0;

    /* The loader lists are circular LIST_ENTRYs with genuine-sized Unicode
     * descriptors, allowing guest PEB walks and PE export-name resolution. */
    if (win_find_module(process, "ntdll.dll", 1) == NULL || win_find_module(process, "kernel32.dll", 1) == NULL ||
        win_find_module(process, "kernelbase.dll", 1) == NULL) return 0;
    process->loader_ready = 1u;
    if (!win_loader_lists(process)) return 0;

    if (word_size == 4u) {
        if (!win_store(process, process->runtime_base, 4u, UINT32_MAX) ||
            !win_store(process, process->runtime_base + 0x04u, 4u, process->runtime_base) ||
            !win_store(process, process->runtime_base + 0x08u, 4u, process->runtime_base - 0x40000u) ||
            !win_store(process, process->runtime_base + 0x18u, 4u, process->runtime_base) ||
            !win_store(process, process->runtime_base + 0x2cu, 4u, process->threads[0].tls_array) ||
            !win_store(process, process->runtime_base + 0x30u, 4u, peb) || !win_store(process, peb + 0x08u, 4u, process->image_base) ||
            !win_store(process, peb + 0x10u, 4u, params) || !win_store(process, params + 0x40u, 2u, length * 2u) ||
            !win_store(process, params + 0x42u, 2u, (length + 1u) * 2u) || !win_store(process, params + 0x44u, 4u, process->command_line_w))
            return 0;
        if (emulator->arch == XXEMUL_ARCH_X86) emulator->x86.segment[XXEMUL_X86_FS] = 0x53u;
    } else {
        if (!win_store(process, process->runtime_base + 0x08u, 8u, process->runtime_base) ||
            !win_store(process, process->runtime_base + 0x10u, 8u, process->runtime_base - 0x40000u) ||
            !win_store(process, process->runtime_base + 0x30u, 8u, process->runtime_base) ||
            !win_store(process, process->runtime_base + 0x58u, 8u, process->threads[0].tls_array) ||
            !win_store(process, process->runtime_base + 0x60u, 8u, peb) || !win_store(process, peb + 0x10u, 8u, process->image_base) ||
            !win_store(process, peb + 0x20u, 8u, params) || !win_store(process, params + 0x70u, 2u, length * 2u) ||
            !win_store(process, params + 0x72u, 2u, (length + 1u) * 2u) || !win_store(process, params + 0x78u, 8u, process->command_line_w))
            return 0;
        if (emulator->arch == XXEMUL_ARCH_X86) emulator->x86.segment[XXEMUL_X86_GS] = 0x2bu;
    }
    {
        uint64_t image_string = process->runtime_base + 0x18000u, cwd_string = process->runtime_base + 0x18c00u;
        uint64_t image_descriptor = params + (word_size == 8u ? 0x60u : 0x38u);
        uint64_t cwd_descriptor = params + (word_size == 8u ? 0x38u : 0x24u);
        size_t image_length = strlen(guest_program);
        if (!win_write_wide(process, image_string, guest_program, 1024u) || !win_write_wide(process, cwd_string, "C:\\", 4u) ||
            !win_store(process, image_descriptor, 2u, image_length * 2u) ||
            !win_store(process, image_descriptor + 2u, 2u, (image_length + 1u) * 2u) ||
            !win_store(process, image_descriptor + (word_size == 8u ? 8u : 4u), word_size, image_string) ||
            !win_store(process, cwd_descriptor, 2u, 6u) || !win_store(process, cwd_descriptor + 2u, 2u, 8u) ||
            !win_store(process, cwd_descriptor + (word_size == 8u ? 8u : 4u), word_size, cwd_string)) return 0;
    }
    if (emulator->arch == XXEMUL_ARCH_ARM) {
        /* AAPCS stack alignment and an explicit return-to-ExitProcess thunk.
         * Windows ARM64 reserves X18 for its TEB; ARM32 has no x86 segment. */
        emulator->arm.sp = stack_top & ~(uint64_t)(word_size == 8u ? 15u : 7u);
        emulator->arm.gpr[word_size == 8u ? 30u : 14u] = win_resolve(process, word_size == 8u ? "kernel32.dll" : "coredll.dll", "ExitProcess");
        if (word_size == 8u) emulator->arm.gpr[18] = process->runtime_base;
    } else {
        uint64_t initial_sp = stack_top - (word_size == 8u ? 40u : 4u);
        int is_dll = (win_le16(emulator->region_data + win_le32(emulator->region_data + 0x3cu) + 22u) & 0x2000u) != 0;
        if (is_dll && word_size == 4u) initial_sp = stack_top - 16u;
        if (!win_store(process, initial_sp, (uint8_t)word_size, process->runtime_base + WIN_PROCESS_RETURN_OFFSET)) return 0;
        if (is_dll) {
            if (word_size == 8u) {
                emulator->x86.gpr[XXEMUL_X86_RCX] = process->image_base;
                emulator->x86.gpr[XXEMUL_X86_RDX] = 1u; /* DLL_PROCESS_ATTACH */
                emulator->x86.gpr[XXEMUL_X86_R8] = 0u;
            } else if (!win_store(process, initial_sp + 4u, 4u, process->image_base) ||
                       !win_store(process, initial_sp + 8u, 4u, 1u) || !win_store(process, initial_sp + 12u, 4u, 0u)) return 0;
        }
        emulator->x86.gpr[XXEMUL_X86_RSP] = initial_sp;
    }
    return 1;
}

xxemul_windows *xxemul_windows_create(xxemul *emulator, const char *program_path, const char *working_directory, const char *const *arguments, size_t argument_count,
                                      xxemul_status *status)
{
    xxemul_windows *process;
    const uint8_t *bytes, *optional;
    size_t pe_offset, optional_offset, optional_size;
    uint16_t magic;
    uint32_t image_size;
    int is_64;

    if (status != NULL) *status = XXEMUL_STATUS_INVALID_ARGUMENT;
    if (emulator == NULL || program_path == NULL || working_directory == NULL ||
        !((emulator->arch == XXEMUL_ARCH_X86 && (emulator->mode == XXEMUL_MODE_X86_32 || emulator->mode == XXEMUL_MODE_X86_64)) ||
          (emulator->arch == XXEMUL_ARCH_ARM && (emulator->mode == XXEMUL_MODE_ARM_A32 || emulator->mode == XXEMUL_MODE_ARM_T32 || emulator->mode == XXEMUL_MODE_ARM_A64))) ||
        emulator->region_size < WIN_RUNTIME_SIZE + 0x80000u ||
        (argument_count != 0u && arguments == NULL))
        return NULL;
    bytes = emulator->region_data;
    if (bytes[0] != 'M' || bytes[1] != 'Z') return NULL;
    pe_offset = win_le32(bytes + 0x3cu);
    if (pe_offset > emulator->region_size || 24u > emulator->region_size - pe_offset || memcmp(bytes + pe_offset, "PE\0\0", 4) != 0) return NULL;
    optional_offset = pe_offset + 24u;
    optional_size = win_le16(bytes + pe_offset + 20u);
    if (optional_size < 64u || optional_size > emulator->region_size || optional_offset > emulator->region_size - optional_size) return NULL;
    optional = bytes + optional_offset;
    magic = win_le16(optional);
    is_64 = win_word_size(emulator) == 8u;
    if (magic != (is_64 ? 0x20bu : 0x10bu)) return NULL;
    image_size = win_le32(optional + 56u);
    if (image_size == 0u || image_size > emulator->region_size || image_size + WIN_RUNTIME_SIZE + 0x80000u > emulator->region_size) return NULL;

    process = (xxemul_windows *)calloc(1, sizeof(*process));
    if (process == NULL) {
        if (status != NULL) *status = XXEMUL_STATUS_OUT_OF_MEMORY;
        return NULL;
    }
    process->emulator = emulator;
    process->process_id = 1u;
    process->image_base = emulator->region_address;
    process->virtual_tick = 1000u;
    process->scheduler_tick = 1000u;
    process->registry_key_count = 7u;
    process->registry_next_handle = 0x10000u;
    process->random_state = 1u;
    process->image_size = image_size;
    {
        size_t dir_off = is_64 ? 112u : 96u;
        if (optional_size >= dir_off + 24u) {
            process->resource_rva = win_le32(optional + dir_off + 16u);
            process->resource_size = win_le32(optional + dir_off + 20u);
        }
    }
    process->runtime_base = emulator->region_address + emulator->region_size - WIN_RUNTIME_SIZE;
    process->threads[0].active = 1u;
    process->threads[0].id = 1u;
    process->threads[0].notify_started = 1u;
    process->next_thread_id = 1u;
    (void)win_store(process, process->runtime_base + (win_word_size(emulator) == 8u ? 0x40u : 0x20u), win_word_size(emulator), 1u);
    (void)win_store(process, process->runtime_base + (win_word_size(emulator) == 8u ? 0x48u : 0x24u), win_word_size(emulator), 1u);
    process->heap_cursor = (emulator->region_address + image_size + 15u) & ~UINT64_C(15);
    process->heap_limit = process->runtime_base - 0x40000u;
    process->console_attributes = 7u;
    process->process_affinity = 1u;
    process->console_input_mode = 7u;
    process->console_output_mode = 3u;
    process->console_cursor_size = 25u;
    process->console_cursor_visible = 1u;
    {
        size_t index;
        for (index = 0u; index < WIN_CONSOLE_WIDTH * WIN_CONSOLE_HEIGHT; ++index) {
            process->console_cells[index].character = ' ';
            process->console_cells[index].attributes = 7u;
        }
    }
    if (!win_copy(process->program_path, sizeof(process->program_path), program_path) ||
        !win_copy(process->working_directory, sizeof(process->working_directory), working_directory) ||
        !win_copy(process->guest_directory, sizeof(process->guest_directory), "C:\\") || process->heap_cursor >= process->heap_limit ||
        !win_prepare_runtime(process, arguments, argument_count) || !win_primary_dll_register(process, optional, optional_size, is_64) ||
        !win_bind_imports(process, optional, optional_size, is_64) ||
        !win_bind_tls(process, optional, optional_size, is_64)) {
        size_t tls_slot;
        for (tls_slot = 0u; tls_slot < process->module_count; ++tls_slot) win_tls_release_image(process, &process->modules[tls_slot].tls);
        win_tls_release_image(process, &process->main_tls);
        for (tls_slot = 0u; tls_slot < WIN_MAX_THREADS; ++tls_slot) win_tls_thread_release(process, &process->threads[tls_slot]);
        free(process);
        if (status != NULL) *status = XXEMUL_STATUS_INVALID_IMAGE;
        return NULL;
    }
    if (emulator->arch == XXEMUL_ARCH_X86) {
        size_t slot;
        if (process->main_dll_slot) process->modules[process->main_dll_slot - 1u].init_order = ++process->dll_sequence;
        process->startup_pending = (uint8_t)(process->main_tls.callbacks != 0u);
        for (slot = 0u; slot < process->module_count; ++slot)
            if (process->modules[slot].real && process->modules[slot].live && !process->modules[slot].initialized)
                process->startup_pending = 1u;
        if (process->startup_pending) {
            process->loader_entry = emulator->x86.ip;
            emulator->x86.ip = process->runtime_base + WIN_LOADER_START_OFFSET;
        }
    }
    if (status != NULL) *status = XXEMUL_STATUS_OK;
    return process;
}

xxemul_status xxemul_windows_set_environment(xxemul_windows *process, const char *name, const char *value)
{
    char updated[WIN_ENV_MAX_BYTES];
    size_t name_length, value_length = value ? strlen(value) : 0u;
    size_t offset = 0u, used = 0u, count = 0u;
    int replaced = 0;
    if (!process || !name || !*name || strchr(name, '=')) return XXEMUL_STATUS_INVALID_ARGUMENT;
    name_length = strlen(name);
    if (name_length >= WIN_ENV_MAX_BYTES || value_length >= WIN_ENV_MAX_BYTES ||
        name_length + value_length + 3u > WIN_ENV_MAX_BYTES) return XXEMUL_STATUS_OUT_OF_MEMORY;
    while (offset + 1u < process->environment_size && process->environment_data[offset]) {
        const char *entry = process->environment_data + offset;
        size_t size = strlen(entry) + 1u;
        int replace = win_environment_match(entry, name);
        offset += size;
        if (replace) {
            replaced = 1;
            if (!value) continue;
            size = name_length + value_length + 2u;
        }
        if (used + size + 1u > sizeof(updated) || count >= WIN_ENV_MAX_ENTRIES) return XXEMUL_STATUS_OUT_OF_MEMORY;
        if (replace) {
            memcpy(updated + used, name, name_length);
            updated[used + name_length] = '=';
            memcpy(updated + used + name_length + 1u, value, value_length + 1u);
        } else memcpy(updated + used, entry, size);
        used += size; ++count;
    }
    if (!replaced && value) {
        size_t size = name_length + value_length + 2u;
        if (used + size + 1u > sizeof(updated) || count >= WIN_ENV_MAX_ENTRIES) return XXEMUL_STATUS_OUT_OF_MEMORY;
        memcpy(updated + used, name, name_length); updated[used + name_length] = '=';
        memcpy(updated + used + name_length + 1u, value, value_length + 1u); used += size;
    }
    updated[used++] = '\0';
    if (used == 1u) updated[used++] = '\0';
    memcpy(process->environment_data, updated, used); process->environment_size = used;
    return win_sync_environment(process) ? XXEMUL_STATUS_OK : XXEMUL_STATUS_ADDRESS_FAULT;
}

static int win_mapping_flush(xxemul_windows *process, win_handle *mapping, uint64_t address, uint64_t length);

void xxemul_windows_destroy(xxemul_windows *process)
{
    size_t i;
    if (process == NULL) return;
    win_children_destroy(process);
    for (i = 0; i < WIN_MAX_HANDLES; ++i) {
        if (process->handles[i].kind == WIN_HANDLE_MAPPING && process->handles[i].view_address)
            (void)win_mapping_flush(process, &process->handles[i], process->handles[i].view_address, 0u);
        if (process->handles[i].in_use && process->handles[i].io != NULL) xx_io_close(process->handles[i].io);
        win_find_destroy(process->handles[i].find);
        free(process->handles[i].mapping_data);
    }
    for (i = 0u; i < process->registry_value_count; ++i) free(process->registry_values[i].data);
    for (i = 0u; i < process->module_count; ++i) win_tls_release_image(process, &process->modules[i].tls);
    win_tls_release_image(process, &process->main_tls);
    for (i = 0u; i < WIN_MAX_THREADS; ++i) win_tls_thread_release(process, &process->threads[i]);
    memset(process->registry_handles, 0, sizeof(process->registry_handles));
    free(process);
}

uint64_t xxemul_windows_segment_base(const xxemul_windows *process, uint8_t segment_index)
{
    if (process == NULL) return 0;
    if ((process->emulator->mode == XXEMUL_MODE_X86_32 && segment_index == XXEMUL_X86_FS) ||
        (process->emulator->mode == XXEMUL_MODE_X86_64 && segment_index == XXEMUL_X86_GS))
        return process->runtime_base;
    return 0;
}

uint32_t xxemul_windows_exit_code(const xxemul_windows *process)
{
    return process == NULL ? 0u : process->exit_code;
}

const char *xxemul_windows_thunk_name(const xxemul *emulator, uint64_t address)
{
    const xxemul_windows *process;
    uint64_t offset, index;
    if (emulator == NULL || emulator->windows == NULL) return NULL;
    process = emulator->windows;
    {
        const char *data_name = win_data_symbol(process, address, 0);
        if (data_name) return data_name;
    }
    if (address < process->runtime_base + WIN_THUNK_OFFSET) return NULL;
    offset = address - process->runtime_base - WIN_THUNK_OFFSET;
    if (offset % WIN_THUNK_STRIDE != 0u) return NULL;
    index = offset / WIN_THUNK_STRIDE;
    return index < process->api_count ? process->apis[index].name : NULL;
}

const char *xxemul_windows_thunk_qualified_name(const xxemul *emulator, uint64_t address)
{
    const xxemul_windows *process;
    uint64_t offset, index;
    if (emulator == NULL || emulator->windows == NULL) return NULL;
    process = emulator->windows;
    {
        const char *data_name = win_data_symbol(process, address, 1);
        if (data_name) return data_name;
    }
    if (address < process->runtime_base + WIN_THUNK_OFFSET) return NULL;
    offset = address - process->runtime_base - WIN_THUNK_OFFSET;
    if (offset % WIN_THUNK_STRIDE != 0u) return NULL;
    index = offset / WIN_THUNK_STRIDE;
    return index < process->api_count ? process->apis[index].qualified : NULL;
}

/* These are readable modeled modules, not copies of host DLLs. Their export
 * RVAs point into the same runtime's address-dispatched API thunk pool. */
static const char *win_export_owner(const char *name)
{
    if(win_equal(name,"CheckSumMappedFile"))return "imagehlp.dll";
    if (win_equal(name, "SetTimer") || win_equal(name, "MoveWindow")) return "user32.dll";
    if (win_prefix(name,"DialogBox") || win_prefix(name,"EndDialog") || win_prefix(name,"GetDlgItem") || win_prefix(name,"SetDlgItem") || win_prefix(name,"SendDlgItem") || win_prefix(name,"SendMessage") || win_prefix(name,"LoadIcon")) return "user32.dll";
    if (win_prefix(name,"CreateFontIndirect") || win_equal(name,"GetObjectA") || win_equal(name,"GetObjectW") || win_equal(name,"DeleteObject")) return "gdi32.dll";
    if (win_equal(name,"InitCommonControlsEx")) return "comctl32.dll";
    if (win_equal(name, "_lcreat") || win_equal(name, "_lwrite")) return "kernel32.dll";
    if (win_equal(name, "_lopen") || win_equal(name, "_lread") || win_equal(name, "_lclose") || win_equal(name, "_llseek")) return "kernel32.dll";
    if (win_equal(name, "LoadBitmapA") || win_equal(name, "DialogBoxParamA")) return "user32.dll";
    if (win_equal(name, "KillTimer") || win_equal(name, "wsprintfA") || win_equal(name, "wsprintfW") ||
        win_equal(name, "wvsprintfA") || win_equal(name, "wvsprintfW")) return "user32.dll";
    if (win_crt_api(name) || name[0] == '_' ||
        (islower((unsigned char)name[0]) && !win_prefix(name, "lstr"))) return "msvcrt.dll";
    if (win_prefix(name, "Rtl") || win_prefix(name, "Nt") || win_prefix(name, "Zw")) return "ntdll.dll";
    if (win_prefix(name, "Reg") || win_prefix(name, "Lsa") || win_prefix(name, "LookupPrivilege") ||
        win_prefix(name, "ConvertSid") || win_prefix(name, "ConvertStringSid") ||
        strcmp(name, "OpenProcessToken") == 0 || strcmp(name, "GetTokenInformation") == 0 ||
        strcmp(name, "AdjustTokenPrivileges") == 0 || strcmp(name, "CheckTokenMembership") == 0 ||
        strcmp(name, "AllocateAndInitializeSid") == 0 || strcmp(name, "FreeSid") == 0) return "advapi32.dll";
    if (win_prefix(name, "SH") || win_prefix(name, "Shell")) return "shell32.dll";
    if (strcmp(name, "SetSuspendState") == 0) return "powrprof.dll";
    if (win_prefix(name, "Sys") && !win_prefix(name, "System")) return "oleaut32.dll";
    if (win_prefix(name, "SafeArray") || win_prefix(name, "Variant")) return "oleaut32.dll";
    if (strcmp(name, "CoTaskMemFree") == 0) return "ole32.dll";
    if (win_prefix(name, "GetFileVersion") || win_prefix(name, "VerQuery")) return "version.dll";
    if (win_prefix(name, "Message") || win_prefix(name, "Char") || win_prefix(name, "OemToChar") ||
        win_prefix(name, "EnumWindows") || win_prefix(name, "GetWindow") || win_prefix(name, "SetWindow") ||
        win_prefix(name, "GetKeyboard") || win_prefix(name, "GetSystemMetrics") || win_prefix(name, "VkKeyScan") ||
        strstr(name, "Clipboard") != NULL || strcmp(name, "LoadStringW") == 0 || strcmp(name, "ExitWindowsEx") == 0) return "user32.dll";
    return "kernel32.dll";
}

static int win_export_for_module(const char *module, const char *name)
{
    const char *owner = win_export_owner(name);
    if (win_equal(module, "coredll.dll")) return !win_equal(owner, "msvcrt.dll");
    if (win_equal(module, "kernelbase.dll") || win_prefix(module, "api-ms-win-core-")) return win_equal(owner, "kernel32.dll");
    if (win_equal(module, "ucrtbase.dll") || win_prefix(module, "api-ms-win-crt-")) return win_equal(owner, "msvcrt.dll");
    return win_equal(module, owner);
}

static int win_module_exports(xxemul_windows *process, win_module *module)
{
    static const char *const data_names[] = {"_iob", "__initenv", "__mb_cur_max", "_acmdln", "_commode", "_fmode", "_adjust_fdiv"};
    struct { const char *name; uint64_t address; } entries[WIN_MAX_APIS + 7u];
    uint8_t *image = (uint8_t *)calloc(1u, (size_t)WIN_MODULE_STRIDE);
    size_t order[WIN_MAX_APIS + 7u], count = 0u, i, j, cursor;
    uint32_t optional, directories, section, thunk_rva;
    int wide = win_word_size(process->emulator) == 8u;
    if (image == NULL) return 0;
    for (i = 0u; i < process->api_count; ++i) {
        if (!win_equal(process->apis[i].module, module->name)) continue;
        entries[count].name = process->apis[i].name;
        entries[count].address = process->runtime_base + WIN_THUNK_OFFSET + i * WIN_THUNK_STRIDE;
        ++count;
    }
    for (i = 0u; i < sizeof(data_names) / sizeof(data_names[0]); ++i) {
        if (!win_export_for_module(module->name, data_names[i])) continue;
        entries[count].name = data_names[i]; entries[count].address = win_resolve(process, module->name, data_names[i]);
        ++count;
    }
    for (i = 0u; i < count; ++i) {
        j = i;
        while (j > 0u && strcmp(entries[order[j - 1u]].name, entries[i].name) > 0) {
            order[j] = order[j - 1u]; --j;
        }
        order[j] = i;
    }
    /* A module slot has room for 512 exports including all names. */
    if (count > 512u) { free(image); return 0; }
    image[0] = 'M'; image[1] = 'Z'; win_put32(image + 0x3cu, 0x80u);
    memcpy(image + 0x80u, "PE\0\0", 4u);
    win_put16(image + 0x84u, process->emulator->arch == XXEMUL_ARCH_ARM ? (wide ? 0xaa64u : 0x1c0u) : (wide ? 0x8664u : 0x14cu));
    win_put16(image + 0x86u, 2u);
    win_put16(image + 0x94u, (uint16_t)(wide ? 0xf0u : 0xe0u));
    win_put16(image + 0x96u, 0x2022u);
    optional = 0x98u; directories = optional + (wide ? 112u : 96u);
    win_put16(image + optional, (uint16_t)(wide ? 0x20bu : 0x10bu));
    if (wide) win_put64(image + optional + 24u, module->base);
    else win_put32(image + optional + 28u, (uint32_t)module->base);
    win_put32(image + optional + 32u, 0x1000u); win_put32(image + optional + 36u, 0x200u);
    win_put16(image + optional + 40u, 6u); win_put16(image + optional + 48u, 6u);
    thunk_rva = (uint32_t)(process->runtime_base + WIN_THUNK_OFFSET - module->base);
    win_put32(image + optional + 56u, (uint32_t)(process->runtime_base + WIN_RUNTIME_SIZE - module->base));
    win_put32(image + optional + 60u, 0x400u); win_put16(image + optional + 68u, 3u);
    win_put32(image + directories - 4u, 16u);
    win_put32(image + directories, 0x1000u); win_put32(image + directories + 4u, 0x100u);
    section = optional + (wide ? 0xf0u : 0xe0u);
    memcpy(image + section, ".edata", 6u); win_put32(image + section + 8u, 0x7000u);
    win_put32(image + section + 12u, 0x1000u); win_put32(image + section + 36u, 0x40000040u);
    memcpy(image + section + 40u, ".text", 5u); win_put32(image + section + 48u, WIN_MAX_APIS * 16u);
    win_put32(image + section + 52u, thunk_rva); win_put32(image + section + 76u, 0x60000020u);
    win_put32(image + 0x100cu, 0x1040u); win_put32(image + 0x1010u, 1u);
    win_put32(image + 0x1014u, (uint32_t)count); win_put32(image + 0x1018u, (uint32_t)count);
    win_put32(image + 0x101cu, 0x1100u); win_put32(image + 0x1020u, 0x1900u); win_put32(image + 0x1024u, 0x2100u);
    memcpy(image + 0x1040u, module->name, strlen(module->name) + 1u);
    cursor = 0x2500u;
    for (i = 0u; i < count; ++i) {
        const char *name = entries[order[i]].name;
        size_t bytes = strlen(name) + 1u;
        if (bytes > (size_t)WIN_MODULE_STRIDE - cursor) { free(image); return 0; }
        win_put32(image + 0x1100u + i * 4u, (uint32_t)(entries[order[i]].address - module->base));
        win_put32(image + 0x1900u + i * 4u, (uint32_t)cursor);
        win_put16(image + 0x2100u + i * 2u, (uint16_t)i);
        memcpy(image + cursor, name, bytes); cursor += bytes;
    }
    i = (size_t)win_write(process, module->base, image, (size_t)WIN_MODULE_STRIDE);
    free(image); return i != 0u;
}

static int win_loader_lists(xxemul_windows *process)
{
    uint8_t word = win_word_size(process->emulator);
    uint64_t peb = process->runtime_base + 0x2000u, ldr = process->runtime_base + 0x3000u;
    size_t i, list, count = 1u, order[WIN_MAX_MODULES];
    char guest_program[1024];
    if (!win_guest_program_path(process, guest_program, sizeof(guest_program))) return 0;
    for(i=0u;i<process->module_count;++i)if(process->modules[i].live && !process->modules[i].primary)order[count++-1u]=i;
    if (!win_store(process, peb + (word == 8u ? 0x18u : 0x0cu), word, ldr) ||
        !win_store(process, ldr, 4u, word == 8u ? 0x58u : 0x30u) || !win_store(process, ldr + 4u, 1u, 1u)) return 0;
    for (i = 0u; i < count; ++i) {
        uint64_t entry = process->runtime_base + 0x10000u + i * 0x100u;
        uint64_t text = process->runtime_base + 0x15000u + i * 0x100u;
        uint64_t base = i == 0u ? process->image_base : process->modules[order[i - 1u]].base;
        const char *name = i == 0u ? guest_program : process->modules[order[i - 1u]].name;
        uint64_t name_offset = word == 8u ? 0x48u : 0x24u;
        size_t length = strlen(name);
        if (!win_store(process, entry + (word == 8u ? 0x30u : 0x18u), word, base) ||
            !win_store(process, entry + (word == 8u ? 0x40u : 0x20u), 4u,
                       i == 0u ? process->image_size : (process->modules[order[i - 1u]].real ? process->modules[order[i - 1u]].image_size : process->runtime_base + WIN_RUNTIME_SIZE - base)) ||
            !win_write_wide(process, i == 0u ? process->runtime_base + 0x17000u : text, name, i == 0u ? 1024u : 128u)) return 0;
        for (list = 0u; list < 2u; ++list) {
            uint64_t descriptor = entry + name_offset + list * (word == 8u ? 16u : 8u);
            uint64_t string_address = i == 0u ? process->runtime_base + (list == 0u ? 0x17000u : 0x17800u) : text;
            size_t string_length = length;
            if (i == 0u && list == 1u) {
                string_length -= 3u;
                if (!win_write_wide(process, string_address, name + 3u, 1024u)) return 0;
            }
            if (!win_store(process, descriptor, 2u, string_length * 2u) || !win_store(process, descriptor + 2u, 2u, (string_length + 1u) * 2u) ||
                !win_store(process, descriptor + (word == 8u ? 8u : 4u), word, string_address)) return 0;
        }
    }
    for (list = 0u; list < 3u; ++list) {
        uint64_t head = ldr + (word == 8u ? 0x10u : 0x0cu) + list * word * 2u;
        uint64_t links = list * word * 2u;
        if (list == 2u && process->main_dll_slot) {
            size_t member;
            uint64_t first = process->runtime_base + 0x10000u + links + (count > 1u ? 0x100u : 0u);
            uint64_t last = process->runtime_base + 0x10000u + links;
            if (!win_store(process, head, word, first) || !win_store(process, head + word, word, last)) return 0;
            for (member = 0u; member < count; ++member) {
                size_t node_index = member + 1u < count ? member + 1u : 0u;
                uint64_t node = process->runtime_base + 0x10000u + node_index * 0x100u + links;
                uint64_t previous = member ? process->runtime_base + 0x10000u + member * 0x100u + links : head;
                uint64_t next = member + 1u < count ? process->runtime_base + 0x10000u + (member + 2u < count ? member + 2u : 0u) * 0x100u + links : head;
                if (!win_store(process, node, word, next) || !win_store(process, node + word, word, previous)) return 0;
            }
            continue;
        }
        /* The executable participates in load/memory order, but not in the
         * DLL initialization-order chain exposed by PEB_LDR_DATA. */
        size_t members = count - (list == 2u ? 1u : 0u);
        uint64_t first = process->runtime_base + 0x10000u + links + (list == 2u ? 0x100u : 0u);
        uint64_t last = members ? first + (members - 1u) * 0x100u : head;
        if(!members)first=head;
        if (!win_store(process, head, word, first) || !win_store(process, head + word, word, last)) return 0;
        for (i = 0u; i < members; ++i) {
            uint64_t node = first + i * 0x100u;
            if (!win_store(process, node, word, i + 1u == members ? head : node + 0x100u) ||
                !win_store(process, node + word, word, i == 0u ? head : node - 0x100u)) return 0;
        }
    }
    return 1;
}

static win_module *win_find_module(xxemul_windows *process, const char *name, int create)
{
    char normalized[48];
    const char *base = name, *at;
    size_t i, checkpoint;
    win_module *module;
    if (name == NULL || *name == '\0') return NULL;
    for (at = name; *at != '\0'; ++at) if (*at == '/' || *at == '\\') base = at + 1;
    if (!win_copy(normalized, sizeof(normalized), base)) return NULL;
    for (i = 0u; normalized[i] != '\0'; ++i) normalized[i] = (char)tolower((unsigned char)normalized[i]);
    if (strchr(normalized, '.') == NULL) {
        i = strlen(normalized); if (i + 5u > sizeof(normalized)) return NULL;
        memcpy(normalized + i, ".dll", 5u);
    }
    for (i = 0u; i < process->module_count; ++i) if (process->modules[i].live && win_equal(process->modules[i].name, normalized)) return &process->modules[i];
    if (!create || process->module_count == WIN_MAX_MODULES) return NULL;
    module = &process->modules[process->module_count];
    memcpy(module->name, normalized, strlen(normalized) + 1u);
    module->base = process->runtime_base + WIN_MODULE_OFFSET + process->module_count * WIN_MODULE_STRIDE;
    module->building = 1u; module->live = 1u; ++process->module_count; checkpoint = process->api_count;
    for (i = 0u; i < sizeof(win_export_names) / sizeof(win_export_names[0]); ++i)
        if (win_export_for_module(module->name, win_export_names[i]) && !win_resolve(process, module->name, win_export_names[i])) goto failed;
    for (i = 0u; i < sizeof(win_extra_export_names) / sizeof(win_extra_export_names[0]); ++i)
        if (win_export_for_module(module->name, win_extra_export_names[i]) && !win_resolve(process, module->name, win_extra_export_names[i])) goto failed;
    for (i = 0u; i < sizeof(win_crt_names) / sizeof(win_crt_names[0]); ++i)
        if (win_export_for_module(module->name, win_crt_names[i]) && !win_resolve(process, module->name, win_crt_names[i])) goto failed;
    module->building = 0u;
    if (!win_module_exports(process, module) || (process->loader_ready && !win_loader_lists(process))) goto failed;
    return module;
failed:
    process->api_count = checkpoint; --process->module_count; memset(module, 0, sizeof(*module)); return NULL;
}

static uint64_t win_module_handle(xxemul_windows *process, const char *name)
{
    win_module *module;
    if (name == NULL || *name == '\0') return process->image_base;
    module = win_find_module(process, name, 1);
    return module != NULL ? module->base : 0u;
}

static int win_loadable_module(xxemul_windows *process, const char *name)
{
    static const char *const modules[] = {
        "kernel32.dll", "kernelbase.dll", "ntdll.dll", "coredll.dll",
        "user32.dll", "gdi32.dll", "advapi32.dll", "shell32.dll", "shlwapi.dll",
        "ole32.dll", "oleaut32.dll", "comdlg32.dll", "comctl32.dll", "winmm.dll",
        "msvcrt.dll", "ucrtbase.dll", "ws2_32.dll", "wsock32.dll", "version.dll",
        "rpcrt4.dll", "secur32.dll", "crypt32.dll", "bcrypt.dll", "wininet.dll",
        "winhttp.dll", "iphlpapi.dll", "psapi.dll", "imagehlp.dll", "dbghelp.dll",
        "setupapi.dll", "netapi32.dll", "userenv.dll", "imm32.dll", "powrprof.dll",
        "mpr.dll", "lz32.dll", "wintrust.dll", "dwmapi.dll", "winspool.drv"
    };
    const char *base = name, *at;
    char normalized[48];
    size_t length, index;
    if (!name || !*name) return 0;
    if (win_find_module(process, name, 0)) return 1;
    for (at = name; *at; ++at) if (*at == '/' || *at == '\\') base = at + 1;
    if (!win_copy(normalized, sizeof(normalized), base)) return 0;
    if (!strchr(normalized, '.')) {
        length = strlen(normalized);
        if (length + 5u > sizeof(normalized)) return 0;
        memcpy(normalized + length, ".dll", 5u);
    }
    for (index = 0; index < sizeof(modules) / sizeof(modules[0]); ++index)
        if (win_equal(normalized, modules[index])) return 1;
    return win_suffix(normalized, ".dll") &&
        (win_prefix(normalized, "api-ms-win-") || win_prefix(normalized, "ext-ms-win-") ||
         win_prefix(normalized, "msvcr") || win_prefix(normalized, "msvcp") || win_prefix(normalized, "vcruntime"));
}

static const char *win_module_name(xxemul_windows *process, uint64_t handle)
{
    size_t i;
    for (i = 0u; i < process->module_count; ++i) if (process->modules[i].live && process->modules[i].base == handle) return process->modules[i].name;
    /* Accept handles issued by older versions to existing API-only clients;
     * guest module discovery always returns the mapped addresses above. */
    switch (handle) {
        case 0x75000000u: return "coredll.dll";
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

static int win_working_root(xxemul_windows *process, char *root, size_t capacity)
{
#if defined(_WIN32)
    DWORD length = GetFullPathNameA(process->working_directory, (DWORD)capacity, root, NULL);
    size_t i;
    if (!length || length >= capacity) return 0;
    for (i = 0u; root[i]; ++i) if (root[i] == '\\') root[i] = '/';
    return 1;
#else
    char *resolved = realpath(process->working_directory, NULL);
    int copied;
    if (!resolved) return 0;
    copied = win_copy(root, capacity, resolved);
    free(resolved);
    return copied;
#endif
}

static int win_guest_path(xxemul_windows *process, const char *guest, char *host, size_t capacity)
{
    char relative[1024], combined[2048], program[1024], working[1024], root[2048];
    const char *suffix;
    size_t i, j = 0u, length, root_length, working_length;
    if (!guest || !*guest || !win_copy(program, sizeof(program), process->program_path) ||
        !win_copy(working, sizeof(working), process->working_directory) ||
        !win_working_root(process, root, sizeof(root))) return 0;
    for (i = 0u; program[i]; ++i) if (program[i] == '\\') program[i] = '/';
    for (i = 0u; working[i]; ++i) if (working[i] == '\\') working[i] = '/';
    for (i = 0u; guest[i]; ++i) {
        if (i + 1u >= sizeof(relative)) return 0;
        relative[i] = guest[i] == '\\' ? '/' : guest[i];
    }
    relative[i] = 0;
    if (win_equal(relative, program) || (win_main_program_name(process, guest) &&
        (strlen(process->guest_directory) <= 3u || relative[0] == '/' || relative[1] == ':')))
        return win_copy(host, capacity, process->program_path);
    root_length = strlen(root);
    while (root_length > 1u && root[root_length - 1u] == '/') root[--root_length] = 0;
    working_length = strlen(working);
    while (working_length > 1u && working[working_length - 1u] == '/') working[--working_length] = 0;
    suffix = relative;
    /* Accept paths previously returned by GetCurrentDirectory, but never
     * pass a drive-qualified guest string straight to the host filesystem. */
    if (!strncmp(relative, root, root_length) && (!relative[root_length] || relative[root_length] == '/')) suffix += root_length;
    else if (!strncmp(relative, working, working_length) && (!relative[working_length] || relative[working_length] == '/')) suffix += working_length;
    else if (relative[0] && relative[1] == ':') {
        if (tolower((unsigned char)relative[0]) != 'c' || relative[2] != '/') return 0;
        suffix += 2u;
    } else if (relative[0] == '/' && relative[1] == '/') return 0;
    else if (relative[0] != '/' && strlen(process->guest_directory) > 3u) {
        size_t cwd_length = strlen(process->guest_directory + 3u);
        if (cwd_length + strlen(relative) + 2u > sizeof(combined)) return 0;
        memcpy(combined, process->guest_directory + 3u, cwd_length);
        combined[cwd_length] = '/';
        memcpy(combined + cwd_length + 1u, relative, strlen(relative) + 1u);
        for (i = 0u; combined[i]; ++i) if (combined[i] == '\\') combined[i] = '/';
        suffix = combined;
    }
    while (*suffix == '/') ++suffix;
    length = strlen(suffix);
    if (strchr(suffix, ':')) return 0;
    for (i = 0u; i <= length;) {
        size_t start = i, count;
        while (i < length && suffix[i] != '/') ++i;
        count = i - start;
        if (count == 2u && suffix[start] == '.' && suffix[start + 1u] == '.') {
            if (!j) return 0;
            while (j && relative[j - 1u] != '/') --j;
            if (j) --j;
        } else if (count && !(count == 1u && suffix[start] == '.')) {
            if (j && j + 1u < sizeof(relative)) relative[j++] = '/';
            if (count >= sizeof(relative) - j) return 0;
            memmove(relative + j, suffix + start, count); j += count;
        }
        if (i == length) break;
        ++i;
    }
    relative[j] = 0;
    if (root_length + (j ? 1u : 0u) + j >= capacity) return 0;
    memcpy(host, root, root_length + 1u);
    if (j) {
        host[root_length] = '/';
        memcpy(host + root_length + 1u, relative, j + 1u);
    }
    /* Every existing component is checked, including a final file symlink.
     * Temporary creation additionally uses descriptor-relative O_NOFOLLOW. */
    for (i = root_length + 1u; j && i <= strlen(host); ++i) {
        if (!host[i] || host[i] == '/') {
            char saved = host[i];
            host[i] = 0;
#if defined(_WIN32)
            {
                DWORD attributes = GetFileAttributesA(host);
                if (attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_REPARSE_POINT)) { host[i] = saved; return 0; }
                if (attributes == INVALID_FILE_ATTRIBUTES && GetLastError() != ERROR_FILE_NOT_FOUND && GetLastError() != ERROR_PATH_NOT_FOUND) {
                    host[i] = saved; return 0;
                }
            }
#else
            {
                struct stat attributes;
                if (lstat(host, &attributes) == 0) {
                    if (S_ISLNK(attributes.st_mode)) { host[i] = saved; return 0; }
                } else if (errno != ENOENT && errno != ENOTDIR) { host[i] = saved; return 0; }
            }
#endif
            host[i] = saved;
            if (!saved) break;
        }
    }
    return 1;
}

#include "xxemul_windows_dll.inc"

/* Process-local registry: no host registry, preloaded license data, or persistence. */
static int win_memory_span(const xxemul_windows *process, uint64_t address, uint64_t count)
{
    uint64_t base = process->emulator->region_address, size = process->emulator->region_size;
    return address >= base && count <= size && address - base <= size - count;
}

static uint16_t win_reg_fold(uint16_t c)
{
    if ((c >= 'A' && c <= 'Z') || (c >= 0xc0u && c <= 0xdeu && c != 0xd7u) ||
        (c >= 0x410u && c <= 0x42fu)) return (uint16_t)(c + 32u);
    return c;
}

static uint16_t win_reg_ansi(uint8_t c)
{
    static const uint16_t cp1252[32] = {
        0x20ac,0x81,0x201a,0x192,0x201e,0x2026,0x2020,0x2021,
        0x2c6,0x2030,0x160,0x2039,0x152,0x8d,0x17d,0x8f,
        0x90,0x2018,0x2019,0x201c,0x201d,0x2022,0x2013,0x2014,
        0x2dc,0x2122,0x161,0x203a,0x153,0x9d,0x17e,0x178
    };
    return c >= 0x80u && c < 0xa0u ? cp1252[c - 0x80u] : c;
}

static uint8_t win_reg_unansi(uint16_t c)
{
    unsigned i;
    if (c < 0x80u || (c >= 0xa0u && c <= 0xffu)) return (uint8_t)c;
    for (i = 0x80u; i < 0xa0u; ++i) if (win_reg_ansi((uint8_t)i) == c) return (uint8_t)i;
    return '?';
}

#include "xxemul_windows_environment.inc"

static uint32_t win_reg_name(xxemul_windows *process, uint64_t address, int wide, uint16_t *name, size_t capacity, int optional)
{
    size_t i;
    if (address == 0u) { name[0] = 0u; return optional ? 0u : 87u; }
    for (i = 0u; i < capacity; ++i) {
        uint64_t c;
        if (address > UINT64_MAX - i * (wide ? 2u : 1u) ||
            !win_load(process, address + i * (wide ? 2u : 1u), (uint8_t)(wide ? 2u : 1u), &c)) return 998u;
        name[i] = wide ? (uint16_t)c : win_reg_ansi((uint8_t)c);
        if (c == 0u) return 0u;
    }
    return 206u;
}

static int win_reg_name_equal(const uint16_t *a, const uint16_t *b)
{
    while (*a && *b) {
        if (win_reg_fold(*a++) != win_reg_fold(*b++)) return 0;
    }
    return *a == *b;
}

static int win_reg_root(uint64_t h)
{
    uint32_t low = (uint32_t)h;
    if ((h >> 32u) != 0u && (h >> 32u) != UINT32_MAX) return -1;
    if (low >= 0x80000000u && low <= 0x80000006u && low != 0x80000004u && low != 0x80000006u) return (int)(low - 0x80000000u);
    return -1;
}

static int win_reg_key_for_handle(xxemul_windows *process, uint64_t h, uint32_t access)
{
    size_t i;
    int root = win_reg_root(h);
    if (root >= 0) return root;
    for (i = 0u; i < WIN_REG_HANDLES; ++i) {
        win_reg_handle *entry = &process->registry_handles[i];
        if (entry->id == h && h != 0u) return (entry->access & access) == access ? (int)entry->key : -2;
    }
    return -1;
}

static uint32_t win_registry_call(xxemul_windows *process, const char *name, const uint64_t *arg)
{
    int wide = win_suffix(name, "W"), key;
    uint16_t value_name[WIN_REG_NAME] = {0}, path[WIN_REG_PATH];
    size_t i, slot;
    uint32_t error;
    if (strcmp(name, "RegCloseKey") == 0) {
        if (win_reg_root(arg[0]) >= 0) return 0u;
        for (i = 0u; i < WIN_REG_HANDLES; ++i) if (process->registry_handles[i].id == arg[0] && arg[0] != 0u) {
            memset(&process->registry_handles[i], 0, sizeof(process->registry_handles[i]));
            return 0u;
        }
        return 6u;
    }
    if (win_prefix(name, "RegCreateKeyEx") || win_prefix(name, "RegOpenKeyEx")) {
        int create = win_prefix(name, "RegCreateKeyEx"), existed = 1;
        uint64_t output = arg[create ? 7u : 4u], disposition = create ? arg[8] : 0u;
        uint32_t access = (uint32_t)arg[create ? 5u : 3u];
        size_t at = 0u, depth = 0u;
        key = win_reg_key_for_handle(process, arg[0], 0u);
        if (key < 0) return 6u;
        if (arg[2] != 0u || (create && (arg[4] & ~UINT64_C(1)) != 0u)) return 87u;
        if (output == 0u) return 87u;
        if (!win_memory_span(process, output, win_word_size(process->emulator)) ||
            (disposition && !win_memory_span(process, disposition, 4u))) return 998u;
        error = win_reg_name(process, arg[1], wide, path, WIN_REG_PATH, !create);
        if (error) return error;
        for (slot = 0u; slot < WIN_REG_HANDLES && process->registry_handles[slot].id; ++slot) {}
        if (slot == WIN_REG_HANDLES || process->registry_next_handle == UINT32_MAX) return 8u;
        while (path[at]) {
            uint16_t component[WIN_REG_NAME];
            size_t length = 0u, next;
            if (++depth > 32u) return 206u;
            while (path[at] && path[at] != '\\') {
                if (length + 1u >= WIN_REG_NAME) return 206u;
                component[length++] = path[at++];
            }
            if (!length) return 87u;
            component[length] = 0u;
            if (path[at] == '\\') { ++at; if (!path[at]) return 87u; }
            for (next = 7u; next < process->registry_key_count; ++next) {
                win_reg_key *candidate = &process->registry_keys[next];
                if (candidate->parent == (uint32_t)key && win_reg_name_equal(candidate->name, component)) break;
            }
            if (next == process->registry_key_count) {
                win_reg_key *added;
                if (!create) return 2u;
                if (next == WIN_REG_KEYS) return 8u;
                added = &process->registry_keys[next];
                added->parent = (uint32_t)key;
                memcpy(added->name, component, (length + 1u) * sizeof(uint16_t));
                ++process->registry_key_count;
                existed = 0;
            } else if (!path[at]) existed = 1;
            key = (int)next;
        }
        process->registry_handles[slot].id = ++process->registry_next_handle;
        process->registry_handles[slot].key = (uint32_t)key;
        process->registry_handles[slot].access = access;
        (void)win_store(process, output, win_word_size(process->emulator), process->registry_handles[slot].id);
        if (disposition) (void)win_store(process, disposition, 4u, existed ? 2u : 1u);
        return 0u;
    }
    key = win_reg_key_for_handle(process, arg[0], win_prefix(name, "RegSetValueEx") ? 2u : 1u);
    if (key < 0) return key == -2 ? 5u : 6u;
    if (arg[2] != 0u) return 87u;
    error = win_reg_name(process, arg[1], wide, value_name, WIN_REG_NAME, 1);
    if (error) return error;
    for (slot = 0u; slot < process->registry_value_count; ++slot) {
        win_reg_value *value = &process->registry_values[slot];
        if (value->key == (uint32_t)key && win_reg_name_equal(value->name, value_name)) break;
    }
    if (win_prefix(name, "RegSetValueEx")) {
        uint32_t type = (uint32_t)arg[3], size = (uint32_t)arg[5];
        size_t stored_size = size, old_size = slot < process->registry_value_count ? process->registry_values[slot].size : 0u;
        int string = type == 1u || type == 2u || type == 7u;
        uint8_t *data;
        win_reg_value *value;
        if (size > WIN_REG_DATA || (size && !arg[4])) return 87u;
        if (size && !win_memory_span(process, arg[4], size)) return 998u;
        if (string && wide && (size & 1u)) return 87u;
        if (string && !wide) stored_size *= 2u;
        if (slot == WIN_REG_VALUES || stored_size > WIN_REG_DATA ||
            process->registry_bytes - old_size > WIN_REG_TOTAL - stored_size) return 8u;
        data = (uint8_t *)malloc(stored_size ? stored_size : 1u);
        if (!data) return 8u;
        if (string && !wide) {
            for (i = 0u; i < size; ++i) {
                uint64_t c;
                if (!win_load(process, arg[4] + i, 1u, &c)) { free(data); return 998u; }
                win_put16(data + i * 2u, win_reg_ansi((uint8_t)c));
            }
        } else if (size && !win_read(process, arg[4], data, size)) { free(data); return 998u; }
        value = &process->registry_values[slot];
        if (slot == process->registry_value_count) {
            ++process->registry_value_count;
            value->key = (uint32_t)key;
            memcpy(value->name, value_name, sizeof(value_name));
        } else free(value->data);
        value->data = data; value->size = stored_size; value->type = type;
        process->registry_bytes = process->registry_bytes - old_size + stored_size;
        return 0u;
    }
    if (slot == process->registry_value_count) return 2u;
    {
        win_reg_value *value = &process->registry_values[slot];
        size_t required = value->size;
        int convert = !wide && (value->type == 1u || value->type == 2u || value->type == 7u);
        uint64_t capacity = 0u;
        if (convert) required /= 2u;
        if (arg[4] && !arg[5]) return 87u;
        if ((arg[3] && !win_memory_span(process, arg[3], 4u)) ||
            (arg[5] && !win_memory_span(process, arg[5], 4u))) return 998u;
        if (arg[5] && !win_load(process, arg[5], 4u, &capacity)) return 998u;
        if (arg[4] && capacity >= required && !win_memory_span(process, arg[4], required)) return 998u;
        if (arg[3]) (void)win_store(process, arg[3], 4u, value->type);
        if (arg[5]) (void)win_store(process, arg[5], 4u, required);
        if (!arg[4]) return 0u;
        if (capacity < required) return 234u;
        if (convert) {
            for (i = 0u; i < required; ++i) (void)win_store(process, arg[4] + i, 1u, win_reg_unansi(win_le16(value->data + i * 2u)));
        } else if (required) (void)win_write(process, arg[4], value->data, required);
        return 0u;
    }
}

static uint32_t win_temp_error(int error)
{
    if (error == EEXIST) return 80u;
    if (error == ENOENT || error == ENOTDIR) return 3u;
    if (error == EACCES || error == EPERM || error == ELOOP) return 5u;
    return 31u;
}

static uint32_t win_temp_create(xxemul_windows *process, const char *guest)
{
    char host[2048];
    if (!win_guest_path(process, guest, host, sizeof(host))) return 3u;
#if defined(_WIN32)
    {
        HANDLE file = CreateFileA(host, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
        if (file == INVALID_HANDLE_VALUE) return (uint32_t)GetLastError();
        CloseHandle(file);
        return 0u;
    }
#else
    {
        char root[2048], relative[2048], *part, *next;
        size_t length;
        int directory, file, saved;
        if (!win_working_root(process, root, sizeof(root))) return 3u;
        length = strlen(root);
        if (strncmp(host, root, length) || host[length] != '/' || !win_copy(relative, sizeof(relative), host + length + 1u)) return 3u;
        directory = open(root, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
        if (directory < 0) return win_temp_error(errno);
        part = relative;
        while ((next = strchr(part, '/')) != NULL) {
            int child;
            *next = 0;
            child = openat(directory, part, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
            saved = errno; close(directory);
            if (child < 0) return win_temp_error(saved);
            directory = child; part = next + 1;
        }
        file = openat(directory, part, O_CREAT | O_EXCL | O_WRONLY | O_NOFOLLOW, 0600);
        saved = errno; close(directory);
        if (file < 0) return win_temp_error(saved);
        if (close(file)) return win_temp_error(errno);
        return 0u;
    }
#endif
}

static xxemul_status win_temp_call(xxemul_windows *process, const char *name, const uint64_t *arg, uint64_t *result)
{
    int wide = win_suffix(name, "W");
    char path[1024], prefix[1024], output[260];
    size_t length, i;
    *result = 0u;
    if (win_prefix(name, "GetTempPath")) {
        static const char *const variables[] = {"TMP", "TEMP", "USERPROFILE"};
        const char *found = NULL;
        size_t variable, offset;
        for (variable = 0u; variable < 3u && !found; ++variable) {
            for (offset = 0u; offset + 1u < process->environment_size && process->environment_data[offset];) {
                const char *entry = process->environment_data + offset;
                if (win_environment_match(entry, variables[variable])) {
                    const char *value = strchr(entry, '=') + 1;
                    if (*value) found = value;
                    break;
                }
                offset += strlen(entry) + 1u;
            }
        }
        if (!found) found = "C:\\";
        if (strlen(found) + 5u >= sizeof(path)) { process->last_error = 206u; return XXEMUL_STATUS_OK; }
        if (found[0] != '/' && found[0] != '\\' && !(found[0] && found[1] == ':')) {
            memcpy(path, "C:\\", 3u); memcpy(path + 3u, found, strlen(found) + 1u);
        } else memcpy(path, found, strlen(found) + 1u);
        length = strlen(path);
        for (i = 0u; i < length; ++i) if (path[i] == '/') path[i] = '\\';
        if (length && path[length - 1u] != '\\') path[length++] = '\\';
        path[length] = 0;
        if (length >= 260u) { process->last_error = 206u; return XXEMUL_STATUS_OK; }
        if ((uint32_t)arg[0] <= length) { *result = length + 1u; return XXEMUL_STATUS_OK; }
        if (!arg[1] || !win_memory_span(process, arg[1], (length + 1u) * (wide ? 2u : 1u))) {
            process->last_error = 998u; return XXEMUL_STATUS_OK;
        }
        if (wide) (void)win_write_wide(process, arg[1], path, length + 1u);
        else (void)win_write(process, arg[1], path, length + 1u);
        *result = length;
        return XXEMUL_STATUS_OK;
    }
    if (!arg[0] || !arg[1] || !arg[3]) { process->last_error = 87u; return XXEMUL_STATUS_OK; }
    if (!win_guest_string(process, arg[0], path, sizeof(path), wide) ||
        !win_guest_string(process, arg[1], prefix, sizeof(prefix), wide)) { process->last_error = 998u; return XXEMUL_STATUS_OK; }
    length = strlen(path);
    if (!length || length > 246u) { process->last_error = length ? 111u : 3u; return XXEMUL_STATUS_OK; }
    prefix[3] = 0;
    for (i = 0u; prefix[i]; ++i) if ((unsigned char)prefix[i] < 32u || strchr("\\/:*?\"<>|", prefix[i])) {
        process->last_error = 123u; return XXEMUL_STATUS_OK;
    }
    {
        uint32_t unique = (uint32_t)arg[2];
        unsigned attempt;
        for (attempt = 0u; attempt < (unique ? 1u : 65535u); ++attempt) {
            uint32_t number = unique ? unique & 0xffffu : (++process->temp_counter & 0xffffu);
            uint32_t error;
            if (!unique && !number) number = ++process->temp_counter & 0xffffu;
            if (snprintf(output, sizeof(output), "%s%s%s%04X.TMP", path,
                         path[length - 1u] == '/' || path[length - 1u] == '\\' ? "" : "\\", prefix, number) >= (int)sizeof(output)) {
                process->last_error = 111u; return XXEMUL_STATUS_OK;
            }
            /* Validate the exact write span before creating anything. */
            if (!win_memory_span(process, arg[3], (strlen(output) + 1u) * (wide ? 2u : 1u))) {
                process->last_error = 998u; return XXEMUL_STATUS_OK;
            }
            if (unique) {
                char host[2048];
                if (!win_guest_path(process, output, host, sizeof(host))) { process->last_error = 3u; return XXEMUL_STATUS_OK; }
                error = 0u;
            } else error = win_temp_create(process, output);
            if (!error) {
                if (wide) (void)win_write_wide(process, arg[3], output, 260u);
                else (void)win_write(process, arg[3], output, strlen(output) + 1u);
                *result = unique ? unique : number;
                return XXEMUL_STATUS_OK;
            }
            if (error != 80u && error != 183u) { process->last_error = error; return XXEMUL_STATUS_OK; }
        }
        process->last_error = 80u;
    }
    return XXEMUL_STATUS_OK;
}

static uint32_t win_commit_error(int error)
{
    if (error == ENOENT) return 2u;
    if (error == ENOTDIR) return 3u;
    if (error == EEXIST) return 80u;
    if (error == EACCES || error == EPERM || error == ELOOP || error == EISDIR) return 5u;
    if (error == EBADF) return 6u;
    if (error == ENOMEM) return 8u;
    if (error == ENOSPC) return 112u;
    if (error == EINVAL) return 87u;
    return 31u;
}

#if !defined(_WIN32)
static int win_commit_open(xxemul_windows *process, const char *host, int flags, mode_t mode)
{
    char root[2048], relative[2048], *part, *next;
    size_t length;
    int directory, file, saved;
    if (!win_working_root(process, root, sizeof(root))) { errno = ENOENT; return -1; }
    length = strlen(root);
    if (strncmp(host, root, length) || host[length] != '/') {
        if ((flags & O_ACCMODE) == O_RDONLY && win_equal(host, process->program_path))
            return open(host, flags | O_NOFOLLOW | O_NONBLOCK, mode);
        errno = EACCES; return -1;
    }
    if (!win_copy(relative, sizeof(relative), host + length + 1u)) { errno = ENAMETOOLONG; return -1; }
    directory = open(root, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
    if (directory < 0) return -1;
    part = relative;
    while ((next = strchr(part, '/')) != NULL) {
        int child;
        *next = 0;
        child = openat(directory, part, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
        saved = errno; close(directory);
        if (child < 0) { errno = saved == ENOENT ? ENOTDIR : saved; return -1; }
        directory = child; part = next + 1;
    }
    file = openat(directory, part, flags | O_NOFOLLOW | O_NONBLOCK, mode);
    saved = errno; close(directory); errno = saved;
    return file;
}
#endif

#if !defined(_WIN32)
static win_file_attribute *win_file_attribute_at(xxemul_windows *process, const char *path, const struct stat *info, int create)
{
    size_t i, empty = WIN_FILE_ATTRIBUTE_SLOTS;
    for (i = 0u; i < WIN_FILE_ATTRIBUTE_SLOTS; ++i) {
        win_file_attribute *entry = &process->file_attributes[i];
        if (entry->used && !strcmp(entry->path, path)) {
            if (entry->device == (uint64_t)info->st_dev && entry->inode == (uint64_t)info->st_ino) return entry;
            entry->used = 0u;
        }
        if (!entry->used && empty == WIN_FILE_ATTRIBUTE_SLOTS) empty = i;
    }
    if (create && empty < WIN_FILE_ATTRIBUTE_SLOTS) {
        win_file_attribute *entry = &process->file_attributes[empty];
        memset(entry, 0, sizeof(*entry));
        if (!win_copy(entry->path, sizeof(entry->path), path)) return NULL;
        entry->used = 1u; entry->device = (uint64_t)info->st_dev; entry->inode = (uint64_t)info->st_ino;
        return entry;
    }
    return NULL;
}

static int win_copy_file_attributes(xxemul_windows *process, const char *from, const char *to, const struct stat *source, const struct stat *destination)
{
    win_file_attribute *original = win_file_attribute_at(process, from, source, 0);
    win_file_attribute *target = win_file_attribute_at(process, to, destination, original != NULL);
    if (original && !target) return 0;
    if (target) {
        if (original) { target->logical = original->logical; target->write_bits = original->write_bits; }
        else target->used = 0u;
    }
    return 1;
}
#endif

static void win_forget_file_attributes(xxemul_windows *process, const char *path)
{
    size_t i;
    for (i = 0u; i < WIN_FILE_ATTRIBUTE_SLOTS; ++i)
        if (process->file_attributes[i].used && !strcmp(process->file_attributes[i].path, path)) process->file_attributes[i].used = 0u;
}

static uint32_t win_set_file_attributes(xxemul_windows *process, const char *guest, uint32_t flags)
{
    char host[2048];
    if (!win_guest_path(process, guest, host, sizeof(host))) return 5u;
#if defined(_WIN32)
    return SetFileAttributesA(host, flags) ? 0u : (uint32_t)GetLastError();
#else
    {
        struct stat info;
        win_file_attribute *entry;
        mode_t mode, writes;
        int fd = -1, saved;
        if ((flags & ~UINT32_C(0xa1)) != 0u) return 50u;
        if ((flags & 0x80u) && flags != 0x80u) return 87u;
        fd = win_commit_open(process, host, O_RDONLY, 0);
        if (fd < 0 && errno == EACCES) fd = win_commit_open(process, host, O_WRONLY, 0);
        if (fd < 0) return win_commit_error(errno);
        if (fstat(fd, &info) || !S_ISREG(info.st_mode)) { close(fd); return 50u; }
        entry = win_file_attribute_at(process, host, &info, 1);
        if (!entry) { close(fd); return 8u; }
        writes = info.st_mode & (S_IWUSR | S_IWGRP | S_IWOTH);
        mode = info.st_mode;
        if (flags & 1u) {
            if (writes) entry->write_bits = (uint32_t)writes;
            mode &= (mode_t)~(S_IWUSR | S_IWGRP | S_IWOTH);
        } else if (!writes) mode |= entry->write_bits ? (mode_t)entry->write_bits : S_IWUSR;
        if (fchmod(fd, mode)) { saved = errno; close(fd); return win_commit_error(saved); }
        if (close(fd)) return win_commit_error(errno);
        entry->logical = flags & 0x20u;
        return 0u;
    }
#endif
}

static uint32_t win_copy_file(xxemul_windows *process, const char *source, const char *destination, int fail_if_exists)
{
    char from[2048], to[2048];
    if (!win_guest_path(process, source, from, sizeof(from)) || !win_guest_path(process, destination, to, sizeof(to))) return 5u;
    if (win_equal(to, process->program_path)) return 5u;
#if defined(_WIN32)
    return CopyFileA(from, to, fail_if_exists) ? 0u : (uint32_t)GetLastError();
#else
    {
        int input = -1, output = -1;
        uint32_t error = 0u;
        struct stat original, target;
        uint8_t buffer[0x8000];
        input = win_commit_open(process, from, O_RDONLY, 0);
        if (input < 0) return win_commit_error(errno);
        if (fstat(input, &original) || !S_ISREG(original.st_mode)) { error = 5u; goto done; }
        output = win_commit_open(process, to, O_WRONLY | O_CREAT | (fail_if_exists ? O_EXCL : 0), 0600);
        if (output < 0) { error = win_commit_error(errno); goto done; }
        if (fstat(output, &target) || !S_ISREG(target.st_mode)) { error = 5u; goto done; }
        if (original.st_dev == target.st_dev && original.st_ino == target.st_ino) { error = 32u; goto done; }
        if (!(target.st_mode & (S_IWUSR | S_IWGRP | S_IWOTH))) { error = 5u; goto done; }
        if (ftruncate(output, 0)) { error = win_commit_error(errno); goto done; }
        for (;;) {
            ssize_t count = read(input, buffer, sizeof(buffer));
            size_t offset = 0u;
            if (count < 0) { if (errno == EINTR) continue; error = win_commit_error(errno); break; }
            if (!count) break;
            while (offset < (size_t)count) {
                ssize_t written = write(output, buffer + offset, (size_t)count - offset);
                if (written < 0 && errno == EINTR) continue;
                if (written <= 0) { error = written < 0 ? win_commit_error(errno) : 112u; goto done; }
                offset += (size_t)written;
            }
        }
        if (!error && fchmod(output, original.st_mode & 0777u)) error = win_commit_error(errno);
        if (!error && !win_copy_file_attributes(process, from, to, &original, &target)) error = 8u;
done:
        if (output >= 0 && close(output) && !error) error = win_commit_error(errno);
        if (input >= 0 && close(input) && !error) error = win_commit_error(errno);
        return error;
    }
#endif
}

#include "xxemul_windows_move.inc"

static uint64_t win_file_open(xxemul_windows *process, const char *guest_path, uint32_t access, uint32_t disposition)
{
    char host_path[2048];
    const char *mode;
    xx_io_device *io;
    size_t i;
    int exists;
    int writable = (access & 0x40000000u) != 0u;
    if (!win_guest_path(process, guest_path, host_path, sizeof(host_path))) {
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
        default: process->last_error = 87u; return WIN_INVALID_HANDLE;
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
    (void)win_copy(process->handles[i].file_path, sizeof(process->handles[i].file_path), host_path);
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

static int win_is_current_process_handle(xxemul_windows *process, uint64_t handle, uint8_t word_size)
{
    win_handle *entry;
    if (handle == (word_size == 8u ? UINT64_MAX : UINT32_MAX)) return 1;
    entry = win_handle_at(process, handle);
    return entry != NULL && entry->kind == WIN_HANDLE_PROCESS && !entry->child_slot;
}

static int win_is_current_thread_handle(xxemul_windows *process, uint64_t handle, uint8_t word_size)
{
    uint64_t pseudo = word_size == 8u ? UINT64_MAX - 1u : UINT32_MAX - 1u;
    win_handle *entry;
    if (handle == pseudo) return 1;
    entry = win_handle_at(process, handle);
    return entry != NULL && entry->kind == WIN_HANDLE_THREAD && !entry->child_slot;
}

static uint64_t win_open_current_process(xxemul_windows *process, uint32_t process_id, uint32_t inherit)
{
    size_t slot;
    size_t child_slot=0u;
    win_handle *entry;
    if (process_id != process->process_id) {
        size_t index;
        for(index=0u;index<WIN_MAX_CHILDREN;++index)
            if(process->children[index].active && process->children[index].process_id==process_id) {child_slot=index+1u;break;}
        if(!child_slot) {process->last_error=87u;return 0u;}
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
    entry->child_slot=(uint16_t)child_slot;
    entry->references = 1u;
    entry->root_slot = (uint16_t)slot;
    entry->flags = inherit ? 1u : 0u;
    entry->in_use = 1u;
    process->last_error = 0u;
    return 0x100u + slot;
}

static xx_io_device *win_handle_io(xxemul_windows *process, uint64_t handle)
{
    win_handle *entry = win_handle_at(process, handle);
    return entry != NULL && entry->kind == WIN_HANDLE_FILE ? entry->io : NULL;
}

static uint64_t win_crt_handle(xxemul_windows *process, uint64_t fd)
{
    if (fd < 3u) return 0x10u + fd;
    if (fd >= WIN_MAX_CRT_FDS) return 0u;
    return process->crt_fd_handles[fd];
}

static int win_file_times(const char *path, uint64_t *creation, uint64_t *access, uint64_t *write_time)
{
#if defined(_WIN32)
    WIN32_FILE_ATTRIBUTE_DATA attributes;
    if (!GetFileAttributesExA(path, GetFileExInfoStandard, &attributes)) return 0;
    *creation = (uint64_t)attributes.ftCreationTime.dwLowDateTime | ((uint64_t)attributes.ftCreationTime.dwHighDateTime << 32);
    *access = (uint64_t)attributes.ftLastAccessTime.dwLowDateTime | ((uint64_t)attributes.ftLastAccessTime.dwHighDateTime << 32);
    *write_time = (uint64_t)attributes.ftLastWriteTime.dwLowDateTime | ((uint64_t)attributes.ftLastWriteTime.dwHighDateTime << 32);
#else
    struct stat attributes;
    if (stat(path, &attributes) != 0) return 0;
    /* POSIX stat has no portable creation timestamp. */
    *creation = ((uint64_t)attributes.st_mtime + UINT64_C(11644473600)) * UINT64_C(10000000);
    *access = ((uint64_t)attributes.st_atime + UINT64_C(11644473600)) * UINT64_C(10000000);
    *write_time = *creation;
#endif
    return 1;
}

static xxemul_status win_set_file_times(xxemul_windows *process, win_handle *entry, const uint64_t *arg, uint64_t *result)
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
        if (arg[index + 1u] != 0u && !win_load(process, arg[index + 1u], 8u, &values[index])) return XXEMUL_STATUS_ADDRESS_FAULT;
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
        host = CreateFileA(entry->file_path, FILE_WRITE_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL,
                           NULL);
        if (host == INVALID_HANDLE_VALUE) {
            process->last_error = GetLastError();
            return XXEMUL_STATUS_OK;
        }
        if (!SetFileTime(host, selected[0], selected[1], selected[2])) process->last_error = GetLastError();
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
            if (index == 1u) times.actime = (time_t)(seconds - UINT64_C(11644473600));
            else times.modtime = (time_t)(seconds - UINT64_C(11644473600));
        }
        if (utime(entry->file_path, &times) != 0) process->last_error = 5u;
        else *result = 1u;
    }
#endif
    return XXEMUL_STATUS_OK;
}

static uint64_t win_duplicate_handle(xxemul_windows *process, uint64_t source, int inherit)
{
    win_handle *root;
    win_handle *entry;
    uint64_t pseudo_process = process->emulator->mode == XXEMUL_MODE_X86_64 ? UINT64_MAX : UINT32_MAX;
    size_t slot;
    if (source == 0x10u || source == 0x11u || source == 0x12u) return source;
    if (source == pseudo_process - 1u) {
        win_thread_context *thread = &process->threads[process->thread_current];
        if (!thread->active) return 0u;
        if (!thread->handle_bound) {
            for (slot = 0u; slot < WIN_MAX_HANDLES && process->handles[slot].in_use; ++slot) {}
            if (slot == WIN_MAX_HANDLES) return 0u;
            entry = &process->handles[slot]; memset(entry, 0, sizeof(*entry));
            entry->kind = WIN_HANDLE_THREAD; entry->in_use = 1u; entry->closed = 1u;
            entry->references = 1u; entry->root_slot = (uint16_t)slot;
            entry->thread_slot = (uint16_t)process->thread_current;
            entry->thread_start = process->emulator->x86.ip;
            entry->object_id=thread->id;
            thread->handle_slot = (uint16_t)slot; thread->handle_bound = 1u;
        }
        root = &process->handles[thread->handle_slot];
        goto duplicate_root;
    }
    if (source == pseudo_process) {
        for (slot = 0u; slot < WIN_MAX_HANDLES; ++slot) {
            if (!process->handles[slot].in_use) break;
        }
        if (slot == WIN_MAX_HANDLES) return 0u;
        entry = &process->handles[slot];
        memset(entry, 0, sizeof(*entry));
        entry->kind = WIN_HANDLE_PROCESS;
        entry->references = 1u;
        entry->root_slot = (uint16_t)slot;
        entry->flags = inherit ? 1u : 0u;
        entry->in_use = 1u;
        return 0x100u + slot;
    }
    root = win_handle_at(process, source);
duplicate_root:
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
    if (handle == 0x10u || handle == 0x11u || handle == 0x12u) return 1;
    root = win_handle_at(process, handle);
    if (root == NULL) return 0;
    slot = (size_t)(handle - 0x100u);
    entry = &process->handles[slot];
    if (entry != root) memset(entry, 0, sizeof(*entry));
    else entry->closed = 1u;
    if (--root->references == 0u) {
        if (root->io != NULL) xx_io_close(root->io);
        win_find_destroy(root->find);
        free(root->mapping_data);
        memset(root, 0, sizeof(*root));
    }
    return 1;
}

#include "xxemul_windows_mapping.inc"
#include "xxemul_windows_process.inc"

static uint64_t win_create_sync(xxemul_windows *process, uint8_t kind, uint64_t first, uint64_t second, uint64_t name_pointer)
{
    char name[128] = {0};
    size_t index;
    win_handle *entry;
    if (kind == WIN_HANDLE_SEMAPHORE && ((int32_t)first < 0 || (int32_t)second <= 0 || first > second)) {
        process->last_error = 87u;
        return 0;
    }
    if (name_pointer != 0 && !win_guest_string(process, name_pointer, name, sizeof(name), 0)) {
        process->last_error = 87u;
        return 0;
    }
    if (name[0] != '\0') {
        for (index = 0; index < WIN_MAX_HANDLES; ++index) {
            uint64_t live_handle;
            size_t alias_index;
            entry = &process->handles[index];
            if (entry->in_use && entry->kind != WIN_HANDLE_ALIAS && entry->name[0] != '\0' && win_equal(entry->name, name)) {
                if (entry->kind != kind || entry->references == UINT32_MAX) {
                    process->last_error = 6u;
                    return 0;
                }
                live_handle = entry->closed ? 0u : 0x100u + index;
                for (alias_index = 0; live_handle == 0u && alias_index < WIN_MAX_HANDLES; ++alias_index) {
                    win_handle *alias = &process->handles[alias_index];
                    if (alias->in_use && !alias->closed && alias->kind == WIN_HANDLE_ALIAS && alias->root_slot == index) live_handle = 0x100u + alias_index;
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
    if (name[0] != '\0') (void)win_copy(entry->name, sizeof(entry->name), name);
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

static int win_sync_ready(xxemul_windows *process, const win_handle *entry)
{
    win_child_process *child=win_child_at(process,entry);
    if(child) return entry->kind==WIN_HANDLE_THREAD?!child->emulator->windows->threads[0].active:child->finished!=0u;
    if (entry->kind == WIN_HANDLE_THREAD) return entry->thread_finished != 0u;
    if (entry->kind == WIN_HANDLE_PROCESS) return process->process_terminated!=0u;
    return entry->kind == WIN_HANDLE_EVENT ? entry->signaled != 0 : entry->kind == WIN_HANDLE_SEMAPHORE && entry->semaphore_count != 0u;
}

static void win_sync_consume(win_handle *entry)
{
    if (entry->kind == WIN_HANDLE_EVENT && !entry->manual_reset) entry->signaled = 0u;
    else if (entry->kind == WIN_HANDLE_SEMAPHORE) --entry->semaphore_count;
}

static win_critical_section *win_critical_at(xxemul_windows *process, uint64_t address)
{
    size_t index;
    for (index = 0; index < WIN_MAX_CRITICAL_SECTIONS; ++index) {
        win_critical_section *entry = &process->critical_sections[index];
        if (entry->active && entry->address == address) return entry;
    }
    return NULL;
}

static xxemul_status win_critical_write(xxemul_windows *process, const win_critical_section *entry)
{
    uint8_t word_size = win_word_size(process->emulator);
    uint64_t address = entry->address;
    uint32_t lock_count = entry->recursion == 0u ? UINT32_MAX : entry->recursion - 1u;
    if (!win_store(process, address + word_size, 4u, lock_count) || !win_store(process, address + word_size + 4u, 4u, entry->recursion) ||
        !win_store(process, address + (word_size == 8u ? 16u : 12u), word_size, entry->recursion == 0u ? 0u : 1u))
        return XXEMUL_STATUS_ADDRESS_FAULT;
    return XXEMUL_STATUS_OK;
}

static xxemul_status win_critical_initialize(xxemul_windows *process, uint64_t address)
{
    uint8_t zero[40] = {0};
    win_critical_section *entry = NULL;
    size_t index;
    if (address == 0u) return XXEMUL_STATUS_INVALID_ARGUMENT;
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
    if (!win_write(process, address, zero, process->emulator->mode == XXEMUL_MODE_X86_64 ? 40u : 24u)) return XXEMUL_STATUS_ADDRESS_FAULT;
    entry->address = address;
    entry->recursion = 0u;
    entry->active = 1u;
    return win_critical_write(process, entry);
}

static uint64_t win_file_read(xxemul_windows *process, uint64_t handle, uint64_t buffer, uint64_t count, uint64_t bytes_read)
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
    if (result >= 0 && (!win_write(process, buffer, bytes, (size_t)result) || (bytes_read != 0 && !win_store(process, bytes_read, 4u, (uint32_t)result)))) result = -1;
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

static uint64_t win_file_write(xxemul_windows *process, uint64_t handle, uint64_t buffer, uint64_t count, uint64_t bytes_written)
{
    xx_io_device *io = win_handle_io(process, handle);
    uint8_t *bytes;
    ssize_t result;
    size_t i;
    if (bytes_written != 0 && !win_store(process, bytes_written, 4u, 0)) return 0;
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
        if (xxemul_emit_output(process->emulator, handle == 0x11u ? 1 : 2, bytes, (size_t)count)) {
            result = (ssize_t)count;
        } else if (process->emulator->output_callback != NULL) {
            for (i = 0; i < (size_t)count; ++i) {
                process->emulator->output_callback(process->emulator->output_context, bytes[i]);
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
    if (result >= 0 && bytes_written != 0 && !win_store(process, bytes_written, 4u, (uint32_t)result)) result = -1;
    process->last_error = result < 0 ? 6u : 0u;
    return result < 0 ? 0u : 1u;
}

#if !defined(_WIN32)
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
#endif

static uint64_t win_console_write_w(xxemul_windows *process, uint64_t handle, uint64_t buffer, uint64_t count, uint64_t chars_written)
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
                process->emulator->output_callback(process->emulator->output_context, (uint8_t)ch);
            } else {
#if defined(_WIN32)
                char utf8[4];
                int len = WideCharToMultiByte(CP_UTF8, 0, (LPCWCH)&ch, 1, utf8, sizeof(utf8), NULL, NULL);
#else
                /* Same as CP_UTF8: a lone surrogate becomes U+FFFD. */
                uint8_t utf8[4];
                int len = (int)win_encode_utf8(ch >= 0xd800u && ch <= 0xdfffu ? 0xfffdu : ch, utf8);
#endif
                int k;
                for (k = 0; k < len; ++k) {
                    process->emulator->output_callback(process->emulator->output_context, (uint8_t)utf8[k]);
                }
            }
        } else {
            FILE *stream = handle == 0x12u ? stderr : stdout;
            if (ch < 0x80) {
                fputc((int)ch, stream);
            } else {
#if defined(_WIN32)
                char utf8[8];
                int len = WideCharToMultiByte(CP_UTF8, 0, (LPCWCH)&ch, 1, utf8, sizeof(utf8), NULL, NULL);
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
    if (chars_written != 0) win_store(process, chars_written, 4u, (uint32_t)count);
    return 1;
}

static int win_get_arg(xxemul_windows *process, uint8_t index, uint64_t *argument)
{
    xxemul *emulator = process->emulator;
    uint64_t sp = emulator->x86.gpr[XXEMUL_X86_RSP];
    if (emulator->mode == XXEMUL_MODE_X86_32) return win_load(process, sp + 4u + (uint64_t)index * 4u, 4u, argument);
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
    return win_load(process, sp + 40u + (uint64_t)(index - 4u) * 8u, 8u, argument);
}

static xxemul_status win_capture_thread_context(xxemul_windows *process, uint64_t address, uint8_t word_size, uint64_t *result)
{
    const xxemul_x86_state *state = &process->emulator->x86;
    uint32_t architecture_flag = word_size == 8u ? 0x100000u : 0x10000u;
    uint64_t flags, return_address, next_sp;
    size_t index;
    if (!win_load(process, address + (word_size == 8u ? 48u : 0u), 4u, &flags) || !win_load(process, state->gpr[XXEMUL_X86_RSP], word_size, &return_address))
        return XXEMUL_STATUS_ADDRESS_FAULT;
    if ((flags & architecture_flag) == 0u || (flags & 7u) == 0u) {
        process->last_error = 87u;
        return XXEMUL_STATUS_OK;
    }
    if ((flags & ~(uint64_t)(architecture_flag | 7u)) != 0u) return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    next_sp = state->gpr[XXEMUL_X86_RSP] + (word_size == 8u ? 8u : 12u);
    if (word_size == 8u) {
        if ((flags & 1u) != 0u && (!win_store(process, address + 56u, 2u, state->segment[XXEMUL_X86_CS]) ||
                                   !win_store(process, address + 66u, 2u, state->segment[XXEMUL_X86_SS]) || !win_store(process, address + 68u, 4u, state->flags) ||
                                   !win_store(process, address + 152u, 8u, next_sp) || !win_store(process, address + 248u, 8u, return_address)))
            return XXEMUL_STATUS_ADDRESS_FAULT;
        if ((flags & 2u) != 0u) {
            for (index = 0; index < XXEMUL_X86_GPR_COUNT; ++index) {
                uint64_t value = index == XXEMUL_X86_RAX ? 1u : state->gpr[index];
                if (index != XXEMUL_X86_RSP && !win_store(process, address + 120u + index * 8u, 8u, value)) return XXEMUL_STATUS_ADDRESS_FAULT;
            }
        }
        if ((flags & 4u) != 0u &&
            (!win_store(process, address + 58u, 2u, state->segment[XXEMUL_X86_DS]) || !win_store(process, address + 60u, 2u, state->segment[XXEMUL_X86_ES]) ||
             !win_store(process, address + 62u, 2u, state->segment[XXEMUL_X86_FS]) || !win_store(process, address + 64u, 2u, state->segment[XXEMUL_X86_GS])))
            return XXEMUL_STATUS_ADDRESS_FAULT;
    } else {
        static const uint8_t integer_gpr[] = {XXEMUL_X86_RDI, XXEMUL_X86_RSI, XXEMUL_X86_RBX, XXEMUL_X86_RDX, XXEMUL_X86_RCX, XXEMUL_X86_RAX};
        if ((flags & 1u) != 0u && (!win_store(process, address + 180u, 4u, state->gpr[XXEMUL_X86_RBP]) || !win_store(process, address + 184u, 4u, return_address) ||
                                   !win_store(process, address + 188u, 4u, state->segment[XXEMUL_X86_CS]) || !win_store(process, address + 192u, 4u, state->flags) ||
                                   !win_store(process, address + 196u, 4u, next_sp) || !win_store(process, address + 200u, 4u, state->segment[XXEMUL_X86_SS])))
            return XXEMUL_STATUS_ADDRESS_FAULT;
        if ((flags & 2u) != 0u) {
            for (index = 0; index < sizeof(integer_gpr); ++index) {
                uint64_t value = integer_gpr[index] == XXEMUL_X86_RAX ? 1u : state->gpr[integer_gpr[index]];
                if (!win_store(process, address + 156u + index * 4u, 4u, value)) return XXEMUL_STATUS_ADDRESS_FAULT;
            }
        }
        if ((flags & 4u) != 0u &&
            (!win_store(process, address + 140u, 4u, state->segment[XXEMUL_X86_GS]) || !win_store(process, address + 144u, 4u, state->segment[XXEMUL_X86_FS]) ||
             !win_store(process, address + 148u, 4u, state->segment[XXEMUL_X86_ES]) || !win_store(process, address + 152u, 4u, state->segment[XXEMUL_X86_DS])))
            return XXEMUL_STATUS_ADDRESS_FAULT;
    }
    *result = 1u;
    return XXEMUL_STATUS_OK;
}

static const uint16_t win_cp1252_upper[32] = {0x20acu, 0x0081u, 0x201au, 0x0192u, 0x201eu, 0x2026u, 0x2020u, 0x2021u, 0x02c6u, 0x2030u, 0x0160u,
                                              0x2039u, 0x0152u, 0x008du, 0x017du, 0x008fu, 0x0090u, 0x2018u, 0x2019u, 0x201cu, 0x201du, 0x2022u,
                                              0x2013u, 0x2014u, 0x02dcu, 0x2122u, 0x0161u, 0x203au, 0x0153u, 0x009du, 0x017eu, 0x0178u};

static uint32_t win_code_page(uint32_t code_page)
{
    return code_page == 0u || code_page == 1u || code_page == 3u ? 1252u : code_page;
}

static xxemul_status win_conversion_input(xxemul_windows *process, uint64_t address, int32_t length, size_t unit_size, uint8_t **bytes, size_t *units)
{
    size_t count = 0u;
    uint8_t *buffer;
    if (address == 0u || length == 0 || length < -1 || length > (int32_t)(WIN_MAX_IO / 4u)) {
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
            if (!win_load(process, address + count * unit_size, (uint8_t)unit_size, &ch)) return XXEMUL_STATUS_ADDRESS_FAULT;
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

static int win_utf8_scalar(const uint8_t *bytes, size_t available, uint32_t *scalar, size_t *length)
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
    if ((count == 2u && value < 0x80u) || (count == 3u && value < 0x800u) || (count == 4u && value < 0x10000u) || (value >= 0xd800u && value <= 0xdfffu) ||
        value > 0x10ffffu)
        return 0;
    *scalar = value;
    *length = count;
    return 1;
}

#if defined(_WIN32)
static xxemul_status win_multi_byte_to_wide(xxemul_windows *process, const uint64_t *arg, uint64_t *result)
{
    UINT code_page = (UINT)arg[0];
    DWORD flags = (DWORD)arg[1];
    int cb_multi = (int)(int32_t)arg[3];
    int cch_wide = (int)(int32_t)arg[5];
    uint8_t *input = NULL;
    size_t units = 0u;
    xxemul_status status;

    if (cch_wide < 0 || (cch_wide != 0 && arg[4] == 0u)) {
        process->last_error = 1004u;
        *result = 0u;
        return XXEMUL_STATUS_OK;
    }
    status = win_conversion_input(process, arg[2], cb_multi, 1u, &input, &units);
    if (status != XXEMUL_STATUS_OK || input == NULL) return status;

    if (cch_wide == 0) {
        int needed = MultiByteToWideChar(code_page, flags, (const char *)input, (int)units, NULL, 0);
        if (needed <= 0) {
            process->last_error = GetLastError();
            *result = 0u;
        } else {
            *result = (uint64_t)needed;
        }
    } else {
        wchar_t *wbuf = (wchar_t *)malloc((size_t)cch_wide * sizeof(wchar_t));
        if (wbuf == NULL) {
            free(input);
            process->last_error = 8u;
            *result = 0u;
            return XXEMUL_STATUS_OK;
        }
        int converted = MultiByteToWideChar(code_page, flags, (const char *)input, (int)units, wbuf, cch_wide);
        if (converted <= 0) {
            process->last_error = GetLastError();
            *result = 0u;
        } else {
            if (!win_write(process, arg[4], (const uint8_t *)wbuf, (size_t)converted * sizeof(wchar_t))) {
                status = XXEMUL_STATUS_ADDRESS_FAULT;
            } else {
                *result = (uint64_t)converted;
            }
        }
        free(wbuf);
    }
    free(input);
    return status;
}

static xxemul_status win_wide_to_multi_byte(xxemul_windows *process, const uint64_t *arg, uint64_t *result)
{
    UINT code_page = (UINT)arg[0];
    DWORD flags = (DWORD)arg[1];
    int cch_wide = (int)(int32_t)arg[3];
    int cb_multi = (int)(int32_t)arg[5];
    uint8_t *input = NULL;
    size_t units = 0u;
    xxemul_status status;

    if (cb_multi < 0 || (cb_multi != 0 && arg[4] == 0u)) {
        process->last_error = 1004u;
        *result = 0u;
        return XXEMUL_STATUS_OK;
    }
    status = win_conversion_input(process, arg[2], cch_wide, 2u, &input, &units);
    if (status != XXEMUL_STATUS_OK || input == NULL) return status;

    if (cb_multi == 0) {
        int needed = WideCharToMultiByte(code_page, flags, (const wchar_t *)input, (int)units, NULL, 0, NULL, NULL);
        if (needed <= 0) {
            process->last_error = GetLastError();
            *result = 0u;
        } else {
            *result = (uint64_t)needed;
        }
    } else {
        char *mb_buf = (char *)malloc((size_t)cb_multi);
        if (mb_buf == NULL) {
            free(input);
            process->last_error = 8u;
            *result = 0u;
            return XXEMUL_STATUS_OK;
        }
        BOOL used_default = FALSE;
        int converted = WideCharToMultiByte(code_page, flags, (const wchar_t *)input, (int)units, mb_buf, cb_multi, NULL, arg[7] != 0 ? &used_default : NULL);
        if (converted <= 0) {
            process->last_error = GetLastError();
            *result = 0u;
        } else {
            if (!win_write(process, arg[4], (const uint8_t *)mb_buf, (size_t)converted)) {
                status = XXEMUL_STATUS_ADDRESS_FAULT;
            } else {
                *result = (uint64_t)converted;
                if (arg[7] != 0) win_store(process, arg[7], 4u, (uint32_t)used_default);
            }
        }
        free(mb_buf);
    }
    free(input);
    return status;
}
#else
static xxemul_status win_multi_byte_to_wide(xxemul_windows *process, const uint64_t *arg, uint64_t *result)
{
    uint32_t code_page = win_code_page((uint32_t)arg[0]);
    uint32_t flags = (uint32_t)arg[1];
    uint8_t *input = NULL, *output;
    size_t units = 0u, used = 0u, index;
    xxemul_status status = XXEMUL_STATUS_OK;
    if (code_page != 1252u && code_page != 65001u) return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    if ((flags & ~(code_page == 65001u ? 8u : 11u)) != 0u || (int32_t)arg[5] < 0 || ((int32_t)arg[5] != 0 && arg[4] == 0u)) {
        process->last_error = 1004u;
        return XXEMUL_STATUS_OK;
    }
    status = win_conversion_input(process, arg[2], (int32_t)arg[3], 1u, &input, &units);
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
            scalar = ch >= 0x80u && ch < 0xa0u ? win_cp1252_upper[ch - 0x80u] : ch;
        } else if (!win_utf8_scalar(input + index, units - index, &scalar, &consumed)) {
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
        if ((int32_t)arg[5] == 0) *result = used / 2u;
        else if (used / 2u > (size_t)(int32_t)arg[5]) process->last_error = 122u;
        else if (!win_write(process, arg[4], output, used)) status = XXEMUL_STATUS_ADDRESS_FAULT;
        else *result = used / 2u;
    }
    free(output);
    free(input);
    return status;
}

static xxemul_status win_wide_to_multi_byte(xxemul_windows *process, const uint64_t *arg, uint64_t *result)
{
    uint32_t code_page = win_code_page((uint32_t)arg[0]);
    uint32_t flags = (uint32_t)arg[1];
    uint8_t *input = NULL, *output, fallback = '?';
    size_t units = 0u, used = 0u, index;
    uint64_t default_character;
    int substituted = 0;
    xxemul_status status = XXEMUL_STATUS_OK;
    if (code_page != 1252u && code_page != 65001u) return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    if ((flags & ~(code_page == 65001u ? 0x80u : 0x400u)) != 0u || (int32_t)arg[5] < 0 || ((int32_t)arg[5] != 0 && arg[4] == 0u) ||
        (code_page == 65001u && (arg[6] != 0u || arg[7] != 0u))) {
        process->last_error = 1004u;
        return XXEMUL_STATUS_OK;
    }
    status = win_conversion_input(process, arg[2], (int32_t)arg[3], 2u, &input, &units);
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
        if (scalar >= 0xd800u && scalar <= 0xdbffu && index + 1u < units) {
            uint32_t low = win_le16(input + (index + 1u) * 2u);
            if (low >= 0xdc00u && low <= 0xdfffu) {
                scalar = 0x10000u + ((scalar - 0xd800u) << 10u) + low - 0xdc00u;
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
        if (code_page == 65001u) used += win_encode_utf8(scalar, output + used);
        else {
            size_t cp_index;
            if (scalar < 0x80u || (scalar >= 0xa0u && scalar <= 0xffu)) output[used++] = (uint8_t)scalar;
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
        if ((int32_t)arg[5] == 0) *result = used;
        else if (used > (size_t)(int32_t)arg[5]) process->last_error = 122u;
        else if (!win_write(process, arg[4], output, used)) status = XXEMUL_STATUS_ADDRESS_FAULT;
        else *result = used;
        if (*result != 0u && arg[7] != 0u && !win_store(process, arg[7], 4u, (uint32_t)substituted)) status = XXEMUL_STATUS_ADDRESS_FAULT;
    }
    free(output);
    free(input);
    return status;
}
#endif

static xxemul_status win_console_transfer(xxemul_windows *process, const uint64_t *arg, uint64_t *result, int read_output)
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
    if (width <= 0 || height <= 0 || source_x < 0 || source_y < 0 || source_x >= width || source_y >= height) {
        process->last_error = 87u;
        return XXEMUL_STATUS_OK;
    }
    if (!win_console_read_rect(process, arg[4], &requested)) return XXEMUL_STATUS_ADDRESS_FAULT;
    if (requested.left > requested.right || requested.top > requested.bottom) {
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
            if (x < requested.left || x > requested.right || sx < 0 || sx >= width || sy < 0 || sy >= height) continue;
            guest_cell = arg[1] + ((uint64_t)sy * (uint64_t)width + (uint64_t)sx) * 4u;
            cell = &process->console_cells[win_console_index(x, y)];
            if (read_output) {
                cell_value = (uint64_t)cell->character | ((uint64_t)cell->attributes << 16u);
                if (!win_store(process, guest_cell, 4u, cell_value)) return XXEMUL_STATUS_ADDRESS_FAULT;
            } else {
                if (!win_load(process, guest_cell, 4u, &cell_value)) return XXEMUL_STATUS_ADDRESS_FAULT;
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
    if (!win_console_write_rect(process, arg[4], &written)) return XXEMUL_STATUS_ADDRESS_FAULT;
    *result = 1u;
    return XXEMUL_STATUS_OK;
}

static xxemul_status win_console_scroll(xxemul_windows *process, const uint64_t *arg, uint64_t *result)
{
    win_console_rect source = {0};
    win_console_rect clip = {0, 0, WIN_CONSOLE_WIDTH - 1, WIN_CONSOLE_HEIGHT - 1};
    win_console_cell old[WIN_CONSOLE_WIDTH * WIN_CONSOLE_HEIGHT];
    uint64_t fill_value;
    int dest_x = (int16_t)arg[3];
    int dest_y = (int16_t)(arg[3] >> 16u);
    int x, y, left, right, top, bottom;
    if (arg[0] != 0x11u && arg[0] != 0x12u) {
        process->last_error = 6u;
        return XXEMUL_STATUS_OK;
    }
    if (!win_console_read_rect(process, arg[1], &source) || (arg[2] != 0u && !win_console_read_rect(process, arg[2], &clip)) ||
        !win_load(process, arg[4], 4u, &fill_value))
        return XXEMUL_STATUS_ADDRESS_FAULT;
    if (source.left > source.right || source.top > source.bottom || clip.left > clip.right || clip.top > clip.bottom) {
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
            if (!win_console_in_bounds(to_x, to_y) || to_x < clip.left || to_x > clip.right || to_y < clip.top || to_y > clip.bottom) continue;
            process->console_cells[win_console_index(to_x, to_y)] = old[win_console_index(x, y)];
        }
    }
    *result = 1u;
    return XXEMUL_STATUS_OK;
}

static uint64_t win_errno_address(const xxemul_windows *process)
{
    return process->runtime_base + (process->thread_current ? 0x19000u + process->thread_current * 8u : WIN_CRT_DATA_OFFSET + 32u);
}

static xxemul_status win_crt_errno(xxemul_windows *process, uint32_t value)
{
    return win_store(process, win_errno_address(process), 4u, value) ? XXEMUL_STATUS_OK : XXEMUL_STATUS_ADDRESS_FAULT;
}

static xxemul_status win_crt_store_stat(xxemul_windows *process, const char *host_path, uint64_t output, uint8_t time_size, uint64_t *result)
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
    if (!win_write(process, output, zero, time_size == 8u ? 56u : 48u) || !win_store(process, output + 6u, 2u, (uint16_t)attributes.st_mode) ||
        !win_store(process, output + 8u, 2u, (uint16_t)attributes.st_nlink) || !win_store(process, output + 24u, 8u, (uint64_t)attributes.st_size) ||
        !win_store(process, output + 32u, time_size, (uint64_t)attributes.st_atime) ||
        !win_store(process, output + 32u + time_size, time_size, (uint64_t)attributes.st_mtime) ||
        !win_store(process, output + 32u + 2u * time_size, time_size, (uint64_t)attributes.st_ctime))
        return XXEMUL_STATUS_ADDRESS_FAULT;
    return XXEMUL_STATUS_OK;
}

static xxemul_status win_crt_copy(xxemul_windows *process, uint64_t destination, uint64_t source, uint64_t count)
{
    uint8_t bytes[4096];
    int reverse;
    uint64_t offset;
    if (count > WIN_MAX_IO || source > UINT64_MAX - count || destination > UINT64_MAX - count) return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    reverse = destination > source && destination - source < count;
    for (offset = 0u; offset < count;) {
        size_t chunk = (size_t)(count - offset > sizeof(bytes) ? sizeof(bytes) : count - offset);
        uint64_t at = reverse ? count - offset - chunk : offset;
        if (!win_read(process, source + at, bytes, chunk) || !win_write(process, destination + at, bytes, chunk)) return XXEMUL_STATUS_ADDRESS_FAULT;
        offset += chunk;
    }
    return XXEMUL_STATUS_OK;
}

static xxemul_status win_crt_fill(xxemul_windows *process, uint64_t destination, uint8_t character, uint64_t count)
{
    uint8_t bytes[4096];
    uint64_t offset;
    if (count > WIN_MAX_IO || destination > UINT64_MAX - count) return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    memset(bytes, character, sizeof(bytes));
    for (offset = 0u; offset < count;) {
        size_t chunk = (size_t)(count - offset > sizeof(bytes) ? sizeof(bytes) : count - offset);
        if (!win_write(process, destination + offset, bytes, chunk)) return XXEMUL_STATUS_ADDRESS_FAULT;
        offset += chunk;
    }
    return XXEMUL_STATUS_OK;
}

static xxemul_status win_crt_string_length(xxemul_windows *process, uint64_t address, uint8_t unit_size, uint64_t *length)
{
    uint64_t ch;
    for (*length = 0u; *length < WIN_MAX_IO / unit_size; ++*length) {
        if (!win_load(process, address + *length * unit_size, unit_size, &ch)) return XXEMUL_STATUS_ADDRESS_FAULT;
        if (ch == 0u) return XXEMUL_STATUS_OK;
    }
    return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
}

static xxemul_status win_crt_compare_strings(xxemul_windows *process, uint64_t left, uint64_t right, uint64_t limit, int folded, uint64_t *result)
{
    uint64_t index;
    int bounded = limit <= WIN_MAX_IO;
    if (limit > WIN_MAX_IO) limit = WIN_MAX_IO;
    for (index = 0u; index < limit; ++index) {
        uint64_t a, b;
        int difference;
        if (!win_load(process, left + index, 1u, &a) || !win_load(process, right + index, 1u, &b)) return XXEMUL_STATUS_ADDRESS_FAULT;
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
    return bounded ? XXEMUL_STATUS_OK : XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
}

static xxemul_status win_crt_read_string(xxemul_windows *process, uint64_t address, char **buffer, size_t *length)
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

static xxemul_status win_crt_parse_number(xxemul_windows *process, const uint64_t *arg, uint8_t word_size, int unsigned_value, uint64_t *result)
{
    char *text = NULL, *end = NULL;
    size_t length = 0u;
    int base = (int32_t)arg[2];
    uint32_t guest_error = 0u;
    xxemul_status status;
    if (base != 0 && (base < 2 || base > 36)) {
        guest_error = 22u;
        if (arg[1] != 0u && !win_store(process, arg[1], word_size, arg[0])) return XXEMUL_STATUS_ADDRESS_FAULT;
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
    if (arg[1] != 0u && !win_store(process, arg[1], word_size, arg[0] + (size_t)(end - text))) status = XXEMUL_STATUS_ADDRESS_FAULT;
    if (status == XXEMUL_STATUS_OK && guest_error != 0u) status = win_crt_errno(process, guest_error);
    free(text);
    (void)length;
    return status;
}

static int win_load_string(xxemul_windows *process, uint32_t uid, uint64_t buffer, uint32_t max_chars, int wide, uint64_t *result)
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
    if (!win_load(process, rsrc_base + 12u, 2u, &named_entries) || !win_load(process, rsrc_base + 14u, 2u, &id_entries)) return 0;
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
    if (!win_load(process, block_dir_offset + 12u, 2u, &named_entries) || !win_load(process, block_dir_offset + 14u, 2u, &id_entries)) return 0;
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
    if (!win_load(process, lang_dir_offset + 12u, 2u, &named_entries) || !win_load(process, lang_dir_offset + 14u, 2u, &id_entries)) return 0;
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
            if (str_len > (end - curr) / 2u) return 0;
            if (k == str_idx) {
                if (max_chars == 0) {
                    if (!wide) { *result = 0; return 1; }
                    if (buffer != 0) {
                        win_store(process, buffer, win_word_size(process->emulator), curr);
                    }
                    *result = str_len;
                    return 1;
                }
                uint32_t to_copy = (uint32_t)str_len < max_chars - 1u ? (uint32_t)str_len : max_chars - 1u;
                if (buffer != 0) {
                    uint32_t character;
                    for (character = 0; character < to_copy; ++character) {
                        uint64_t value;
                        if (!win_load(process, curr + character * 2u, 2u, &value)) return 0;
                        if (!wide && value >= 0x80u) {
                            unsigned cp;
                            for (cp = 0; cp < 32u; ++cp) if (win_cp1252_upper[cp] == value) break;
                            value = cp < 32u ? cp + 0x80u : value >= 0xa0u && value <= 0xffu ? value : '?';
                        }
                        if (!win_store(process, buffer + (uint64_t)character * (wide ? 2u : 1u), wide ? 2u : 1u, value)) return 0;
                    }
                    if (!win_store(process, buffer + (uint64_t)to_copy * (wide ? 2u : 1u), wide ? 2u : 1u, 0)) return 0;
                }
                *result = to_copy;
                return 1;
            }
            curr += (uint64_t)str_len * 2u;
        }
    }
    return 0;
}

/* Guest Windows printf core: all guest reads and final writes are checked.
 * Windows int/long remain 32-bit even on an LP64 host.  IEEE double arguments
 * are copied as bits, never forwarded through a mismatched host vararg. */
typedef struct win_format_args {
    uint64_t cursor;
    unsigned index;
    int direct;
} win_format_args;

typedef struct win_format_buffer {
    uint8_t *bytes;
    size_t length, capacity, limit;
    int wide;
} win_format_buffer;

static xxemul_status win_format_reserve(win_format_buffer *out, size_t count)
{
    size_t capacity, unit = out->wide ? 2u : 1u;
    uint8_t *bytes;
    if (count > out->limit - out->length) return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    count += out->length;
    if (count <= out->capacity) return XXEMUL_STATUS_OK;
    capacity = out->capacity ? out->capacity : 128u;
    while (capacity < count) {
        if (capacity > out->limit / 2u) { capacity = out->limit; break; }
        capacity *= 2u;
    }
    if (capacity > out->limit) capacity = out->limit;
    bytes = (uint8_t *)realloc(out->bytes, capacity * unit);
    if (bytes == NULL) return XXEMUL_STATUS_OUT_OF_MEMORY;
    out->bytes = bytes;
    out->capacity = capacity;
    return XXEMUL_STATUS_OK;
}

static xxemul_status win_format_append(win_format_buffer *out, uint16_t character)
{
    xxemul_status status = win_format_reserve(out, 1u);
    if (status != XXEMUL_STATUS_OK) return status;
    if (out->wide) win_put16(out->bytes + out->length * 2u, character);
    else out->bytes[out->length] = (uint8_t)character;
    ++out->length;
    return XXEMUL_STATUS_OK;
}

static xxemul_status win_format_repeat(win_format_buffer *out, uint16_t character, size_t count)
{
    xxemul_status status = win_format_reserve(out, count);
    if (status != XXEMUL_STATUS_OK) return status;
    while (count--) {
        if (out->wide) win_put16(out->bytes + out->length * 2u, character);
        else out->bytes[out->length] = (uint8_t)character;
        ++out->length;
    }
    return XXEMUL_STATUS_OK;
}

static xxemul_status win_format_next(xxemul_windows *process, win_format_args *args, unsigned bits, uint64_t *value)
{
    uint8_t word = (uint8_t)win_word_size(process->emulator);
    uint8_t size = bits == 64u ? 8u : 4u;
    if (args->direct) {
        if (args->index > UINT8_MAX) return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
        if (word == 4u && size == 8u) {
            uint64_t sp = process->emulator->x86.gpr[XXEMUL_X86_RSP];
            if (!win_load(process, sp + 4u + (uint64_t)args->index * 4u, 8u, value)) return XXEMUL_STATUS_ADDRESS_FAULT;
            args->index += 2u;
        } else {
            if (!win_get_arg(process, (uint8_t)args->index++, value)) return XXEMUL_STATUS_ADDRESS_FAULT;
        }
    } else {
        if (args->cursor > UINT64_MAX - (size > word ? size : word)) return XXEMUL_STATUS_ADDRESS_FAULT;
        if (!win_load(process, args->cursor, size, value)) return XXEMUL_STATUS_ADDRESS_FAULT;
        args->cursor += size > word ? size : word;
    }
    return XXEMUL_STATUS_OK;
}

static uint16_t win_format_character(uint16_t ch, int source_wide, int output_wide)
{
    unsigned i;
    if (source_wide == output_wide) return ch;
    if (output_wide) return ch >= 0x80u && ch < 0xa0u ? win_cp1252_upper[ch - 0x80u] : ch;
    if (ch < 0x80u || (ch >= 0xa0u && ch <= 0xffu)) return ch;
    for (i = 0u; i < 32u; ++i) if (win_cp1252_upper[i] == ch) return (uint16_t)(i + 0x80u);
    return '?';
}

static xxemul_status win_format_string(xxemul_windows *process, win_format_buffer *out, uint64_t address, int source_wide,
                                      int precision, unsigned width, int left)
{
    win_format_buffer text = {NULL, 0u, 0u, out->limit, out->wide};
    uint64_t ch;
    size_t index, limit = precision < 0 ? out->limit : (size_t)precision;
    xxemul_status status = XXEMUL_STATUS_OK;
    if (address == 0u) {
        const char *null_text = "(null)";
        for (index = 0u; null_text[index] && index < limit; ++index) {
            status = win_format_append(&text, (uint16_t)null_text[index]);
            if (status != XXEMUL_STATUS_OK) goto done;
        }
    } else {
        for (index = 0u; index < limit; ++index) {
            size_t unit = source_wide ? 2u : 1u;
            if (address > UINT64_MAX - index * unit || !win_load(process, address + index * unit, (uint8_t)unit, &ch)) {
                status = XXEMUL_STATUS_ADDRESS_FAULT; goto done;
            }
            if (ch == 0u) break;
            status = win_format_append(&text, win_format_character((uint16_t)ch, source_wide, out->wide));
            if (status != XXEMUL_STATUS_OK) goto done;
        }
        if (precision < 0 && index == limit) { status = XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION; goto done; }
    }
    if (!left && width > text.length) {
        status = win_format_repeat(out, ' ', width - text.length);
        if (status != XXEMUL_STATUS_OK) goto done;
    }
    status = win_format_reserve(out, text.length);
    if (status != XXEMUL_STATUS_OK) goto done;
    if (text.length) memcpy(out->bytes + out->length * (out->wide ? 2u : 1u), text.bytes, text.length * (out->wide ? 2u : 1u));
    out->length += text.length;
    if (left && width > text.length) status = win_format_repeat(out, ' ', width - text.length);
done:
    free(text.bytes);
    return status;
}

static xxemul_status win_format_guest(xxemul_windows *process, uint64_t format, int format_wide, win_format_args *args,
                                     win_format_buffer *out)
{
    uint64_t cursor = format, character, value;
    size_t format_count = 0u;
    uint8_t word = (uint8_t)win_word_size(process->emulator), format_unit = format_wide ? 2u : 1u;
    xxemul_status status;
    /* One lookahead unit; do not read past the terminating NUL. */
#define FORMAT_READ() do { \
    if (format_count++ >= WIN_MAX_IO / format_unit || cursor > UINT64_MAX - format_unit || \
        !win_load(process, cursor, format_unit, &character)) return XXEMUL_STATUS_ADDRESS_FAULT; \
    cursor += format_unit; \
} while (0)
#define FORMAT_NEXT(bits) do { status = win_format_next(process, args, (bits), &value); if (status != XXEMUL_STATUS_OK) return status; } while (0)
#define FORMAT_APPEND(ch) do { status = win_format_append(out, (uint16_t)(ch)); if (status != XXEMUL_STATUS_OK) return status; } while (0)
    FORMAT_READ();
    while (character != 0u) {
        char flags[6] = {0}, spec[80], type, length = 0;
        unsigned flag_count = 0u, width = 0u, bits = 32u;
        int precision = -1, left = 0, alternate = 0, is_signed;
        if (character != '%') { FORMAT_APPEND(character); FORMAT_READ(); continue; }
        FORMAT_READ();
        if (character == '%') { FORMAT_APPEND('%'); FORMAT_READ(); continue; }
        while (character && character < 0x80u && strchr("-+ #0", (int)character) != NULL) {
            if (character == '-') left = 1;
            if (character == '#') alternate = 1;
            if (strchr(flags, (int)character) == NULL && flag_count < sizeof(flags) - 1u) {
                flags[flag_count++] = (char)character;
                flags[flag_count] = '\0';
            }
            FORMAT_READ();
        }
        flags[flag_count] = '\0';
        if (character == '*') {
            FORMAT_NEXT(32u);
            if ((int32_t)value < 0) {
                uint64_t magnitude = (uint64_t)(-(int64_t)(int32_t)value);
                if (magnitude > out->limit) return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
                width = (unsigned)magnitude;
                if (!left) { flags[flag_count++] = '-'; flags[flag_count] = '\0'; }
                left = 1;
            } else width = (uint32_t)value;
            FORMAT_READ();
        } else while (character >= '0' && character <= '9') {
            if (width > out->limit / 10u) return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
            width = width * 10u + (unsigned)(character - '0');
            if (width > out->limit) return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
            FORMAT_READ();
        }
        if (width > out->limit) return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
        if (character == '.') {
            precision = 0;
            FORMAT_READ();
            if (character == '*') {
                FORMAT_NEXT(32u);
                precision = (int32_t)value;
                if (precision < 0) precision = -1;
                FORMAT_READ();
            } else while (character >= '0' && character <= '9') {
                if ((unsigned)precision > out->limit / 10u) return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
                precision = precision * 10 + (int)(character - '0');
                if ((unsigned)precision > out->limit) return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
                FORMAT_READ();
            }
            if (precision >= 0 && (unsigned)precision > out->limit) return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
        }
        if (character == 'h') {
            length = 'h'; bits = 16u; FORMAT_READ();
            if (character == 'h') { bits = 8u; FORMAT_READ(); }
        } else if (character == 'l') {
            length = 'l'; FORMAT_READ();
            if (character == 'l') { length = 'q'; bits = 64u; FORMAT_READ(); }
        } else if (character == 'z' || character == 't' || character == 'j') {
            length = (char)character; bits = character == 'j' ? 64u : word * 8u; FORMAT_READ();
        } else if (character == 'w' || character == 'L') { length = (char)character; FORMAT_READ(); }
        else if (character == 'I') {
            length = 'I'; bits = word * 8u; FORMAT_READ();
            if (character == '3' || character == '6') {
                unsigned first = (unsigned)character; FORMAT_READ();
                if (first == '3' && character == '2') bits = 32u;
                else if (first == '6' && character == '4') bits = 64u;
                else return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
                FORMAT_READ();
            }
        }
        if (character == 0u || character > 0x7fu) return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
        type = (char)character;
        if (type == 's' || type == 'S' || type == 'c' || type == 'C') {
            int source_wide = (type == 's' || type == 'c') ? format_wide : !format_wide;
            if (length == 'h') source_wide = 0;
            else if (length == 'l' || length == 'w') source_wide = 1;
            else if (length != 0) return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
            FORMAT_NEXT(type == 's' || type == 'S' ? word * 8u : 32u);
            if (type == 's' || type == 'S') {
                status = win_format_string(process, out, value, source_wide, precision, width, left);
                if (status != XXEMUL_STATUS_OK) return status;
            } else {
                if (!left && width > 1u) { status = win_format_repeat(out, ' ', width - 1u); if (status != XXEMUL_STATUS_OK) return status; }
                FORMAT_APPEND(win_format_character(source_wide ? (uint16_t)value : (uint8_t)value, source_wide, out->wide));
                if (left && width > 1u) { status = win_format_repeat(out, ' ', width - 1u); if (status != XXEMUL_STATUS_OK) return status; }
            }
        } else if (strchr("diuoxXpaAeEfFgG", type) != NULL) {
            char *piece;
            int count, written;
            int floating = strchr("aAeEfFgG", type) != NULL;
            double real = 0.0;
            size_t index;
            if (length == 'w') return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
            is_signed = type == 'd' || type == 'i';
            if (floating) {
                if (length != 0 && length != 'l' && length != 'L') return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
                bits = 64u;
            } else if (length == 'L') return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
            if (type == 'p') { bits = word * 8u; type = 'X'; precision = (int)word * 2; alternate = 0; }
            FORMAT_NEXT(bits > 32u ? 64u : 32u);
            if (floating) memcpy(&real, &value, sizeof(real));
            if (bits == 8u) value = is_signed ? (uint64_t)(int64_t)(int8_t)value : (uint8_t)value;
            else if (bits == 16u) value = is_signed ? (uint64_t)(int64_t)(int16_t)value : (uint16_t)value;
            else if (bits == 32u) value = is_signed ? (uint64_t)(int64_t)(int32_t)value : (uint32_t)value;
            /* Normalise the host specifier and argument type; never forward
             * a guest %l or x64 %d to a mismatched host vararg. */
            if (!alternate) {
                char *hash = strchr(flags, '#');
                if (hash != NULL) memmove(hash, hash + 1, strlen(hash));
            }
            if (precision >= 0) written = snprintf(spec, sizeof(spec), "%%%s%u.%d%s%c", flags, width, precision, floating ? "" : "ll", type);
            else written = snprintf(spec, sizeof(spec), "%%%s%u%s%c", flags, width, floating ? "" : "ll", type);
            if (written < 0 || (size_t)written >= sizeof(spec)) return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
            count = floating ? snprintf(NULL, 0u, spec, real) : is_signed ? snprintf(NULL, 0u, spec, (long long)(int64_t)value) : snprintf(NULL, 0u, spec, (unsigned long long)value);
            if (count < 0 || (size_t)count > out->limit - out->length) return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
            piece = (char *)malloc((size_t)count + 1u);
            if (piece == NULL) return XXEMUL_STATUS_OUT_OF_MEMORY;
            if (floating) snprintf(piece, (size_t)count + 1u, spec, real);
            else if (is_signed) snprintf(piece, (size_t)count + 1u, spec, (long long)(int64_t)value);
            else snprintf(piece, (size_t)count + 1u, spec, (unsigned long long)value);
            status = win_format_reserve(out, (size_t)count);
            if (status == XXEMUL_STATUS_OK) for (index = 0u; index < (size_t)count; ++index) {
                if (out->wide) win_put16(out->bytes + out->length * 2u, (uint16_t)(uint8_t)piece[index]);
                else out->bytes[out->length] = (uint8_t)piece[index];
                ++out->length;
            }
            free(piece);
            if (status != XXEMUL_STATUS_OK) return status;
        } else return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
        FORMAT_READ();
    }
    return XXEMUL_STATUS_OK;
#undef FORMAT_READ
#undef FORMAT_NEXT
#undef FORMAT_APPEND
}

static xxemul_status win_format_result(xxemul_windows *process, uint64_t destination, uint64_t format, int wide,
                                      win_format_args *args, size_t limit, uint64_t *result)
{
    win_format_buffer out = {NULL, 0u, 0u, limit, wide};
    xxemul_status status = win_format_guest(process, format, wide, args, &out);
    size_t count = out.length;
    if (status == XXEMUL_STATUS_OK) status = win_format_append(&out, 0u);
    if (status == XXEMUL_STATUS_OK && !win_write(process, destination, out.bytes, out.length * (wide ? 2u : 1u))) status = XXEMUL_STATUS_ADDRESS_FAULT;
    if (status == XXEMUL_STATUS_OK) *result = count;
    free(out.bytes);
    return status;
}

static xxemul_status win_stdio_format(xxemul_windows *process, uint64_t stream, uint64_t format, win_format_args *args, uint64_t *result)
{
    win_format_buffer out = {NULL, 0u, 0u, WIN_MAX_IO, 0};
    uint64_t stride = win_word_size(process->emulator) == 8u ? 48u : 32u;
    uint64_t offset = stream >= process->iob_address ? stream - process->iob_address : UINT64_MAX;
    xxemul_status status = win_format_guest(process, format, 0, args, &out);
    if (status == XXEMUL_STATUS_OK) {
        if (offset == stride || offset == stride * 2u) {
            int channel = offset == stride ? 1 : 2;
            if (!xxemul_emit_output(process->emulator, channel, out.bytes, out.length)) {
                if (process->emulator->output_callback != NULL) {
                    size_t index;
                    for (index = 0u; index < out.length; ++index) process->emulator->output_callback(process->emulator->output_context, out.bytes[index]);
                } else if (fwrite(out.bytes, 1u, out.length, channel == 1 ? stdout : stderr) != out.length) {
                    *result = UINT32_MAX; status = win_crt_errno(process, 5u);
                }
            }
        } else if (offset < WIN_MAX_CRT_FDS * stride && offset % stride == 0u) {
            xx_io_device *opened = win_handle_io(process, win_crt_handle(process, offset / stride));
            if (opened == NULL || xx_io_write(opened, out.bytes, out.length) != (int64_t)out.length) {
                *result = UINT32_MAX; status = win_crt_errno(process, 9u);
            }
        } else { *result = UINT32_MAX; status = win_crt_errno(process, 9u); }
        if (status == XXEMUL_STATUS_OK && *result != UINT32_MAX) *result = out.length;
    }
    free(out.bytes);
    return status;
}

static xxemul_status win_stdio_vfprintf(xxemul_windows *process, uint64_t stream, uint64_t format, uint64_t valist, uint64_t *result)
{
    win_format_args args = {valist, 0u, 0};
    return win_stdio_format(process, stream, format, &args, result);
}

static uint64_t win_crt_fopen(xxemul_windows *process, const char *filename, const char *mode)
{
    uint32_t access = 0x80000000u;
    uint32_t disposition = 3u;
    uint64_t handle;
    size_t fd;
    uint8_t word_size = (uint8_t)(win_word_size(process->emulator));
    uint64_t stride = word_size == 8u ? 48u : 32u;

    if (filename == NULL || mode == NULL) return 0;
    if (strchr(mode, 'w') != NULL) {
        access = 0x40000000u;
        disposition = 2u;
    } else if (strchr(mode, 'a') != NULL) {
        access = 0x40000000u;
        disposition = 4u;
    }
    if (strchr(mode, '+') != NULL) {
        access |= 0xc0000000u;
    }
    handle = win_file_open(process, filename, access, disposition);
    if (handle == WIN_INVALID_HANDLE) return 0;
    for (fd = 3u; fd < WIN_MAX_CRT_FDS; ++fd) {
        if (process->crt_fd_handles[fd] == 0u) break;
    }
    if (fd == WIN_MAX_CRT_FDS) {
        win_close_handle(process, handle);
        return 0;
    }
    process->crt_fd_handles[fd] = handle;
    process->crt_fd_eof[fd] = 0;
    if (strchr(mode, 'a') != NULL) {
        xx_io_device *opened = win_handle_io(process, handle);
        if (opened != NULL) xx_io_seek64(opened, 0, SEEK_END);
    }
    return process->iob_address + (uint64_t)fd * stride;
}

static xxemul_status win_crt_fputc(xxemul_windows *process, uint8_t ch, uint64_t stream, uint64_t *result)
{
    uint8_t word_size = (uint8_t)(win_word_size(process->emulator));
    uint64_t stride = word_size == 8u ? 48u : 32u;
    if (stream == process->iob_address || stream == process->iob_address + stride || stream == process->iob_address + 2u * stride) {
        FILE *target_file = (stream == process->iob_address + 2u * stride) ? stderr : stdout;
        if (process->emulator->output_callback != NULL) {
            process->emulator->output_callback(process->emulator->output_context, ch);
        } else {
            fputc(ch, target_file);
            fflush(target_file);
        }
        *result = ch;
        return XXEMUL_STATUS_OK;
    }
    uint64_t offset = stream >= process->iob_address ? (stream - process->iob_address) : UINT64_MAX;
    if (offset < (uint64_t)WIN_MAX_CRT_FDS * stride && offset % stride == 0u) {
        size_t fd = (size_t)(offset / stride);
        uint64_t handle = win_crt_handle(process, fd);
        xx_io_device *opened = win_handle_io(process, handle);
        if (opened != NULL) {
            if (xx_io_write(opened, &ch, 1) == 1) {
                *result = ch;
                return XXEMUL_STATUS_OK;
            }
        }
    }
    *result = UINT32_MAX;
    return win_crt_errno(process, 9u);
}

/* A heap handle is either the process heap or a live modeled heap.  Alias
 * handles identify the same owner; allocation validation uses exact starts. */
static uint64_t win_heap_owner(xxemul_windows *process, uint64_t handle)
{
    win_handle *entry;
    if (handle == 0x400u) return handle;
    entry = win_handle_at(process, handle);
    if (entry == NULL || entry->kind != WIN_HANDLE_HEAP) return 0u;
    return 0x100u + (uint64_t)(entry - process->handles);
}

#define WIN_PROFILE_MAX (1024u * 1024u)

static char *win_profile_trim(char *text)
{
    size_t length;
    while (*text == ' ' || *text == '\t' || *text == '\r') ++text;
    length = strlen(text);
    while (length && (text[length - 1u] == ' ' || text[length - 1u] == '\t' || text[length - 1u] == '\r')) text[--length] = '\0';
    return text;
}

static xxemul_status win_profile_load(xxemul_windows *process, uint64_t filename, char **contents)
{
    char guest[1024], host[2048];
    FILE *file;
    long size;
    *contents = NULL;
    if (filename == 0u) return XXEMUL_STATUS_OK;
    if (!win_guest_string(process, filename, guest, sizeof(guest), 0)) return XXEMUL_STATUS_ADDRESS_FAULT;
    if (!win_guest_path(process, guest, host, sizeof(host))) { process->last_error = 5u; return XXEMUL_STATUS_OK; }
#if !defined(_WIN32)
    {
        char *resolved = realpath(host, NULL), *root = realpath(process->working_directory, NULL);
        size_t root_length = root ? strlen(root) : 0u;
        int inside = resolved && root && strncmp(resolved, root, root_length) == 0 &&
                     (resolved[root_length] == '/' || resolved[root_length] == '\0');
        free(root);
        if (!inside || !win_copy(host, sizeof(host), resolved)) {
            free(resolved); process->last_error = 2u; return XXEMUL_STATUS_OK;
        }
        free(resolved);
    }
#endif
    file = fopen(host, "rb");
    if (file == NULL) { process->last_error = 2u; return XXEMUL_STATUS_OK; }
    if (fseek(file, 0, SEEK_END) != 0 || (size = ftell(file)) < 0 || fseek(file, 0, SEEK_SET) != 0) {
        fclose(file); process->last_error = 5u; return XXEMUL_STATUS_OK;
    }
    if ((unsigned long)size > WIN_PROFILE_MAX) { fclose(file); return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION; }
    *contents = (char *)malloc((size_t)size + 1u);
    if (*contents == NULL) { fclose(file); return XXEMUL_STATUS_OUT_OF_MEMORY; }
    if (fread(*contents, 1u, (size_t)size, file) != (size_t)size) {
        free(*contents); *contents = NULL; fclose(file); process->last_error = 5u; return XXEMUL_STATUS_OK;
    }
    fclose(file);
    (*contents)[size] = '\0';
    if (size >= 2 && (((uint8_t)(*contents)[0] == 0xffu && (uint8_t)(*contents)[1] == 0xfeu) ||
                     ((uint8_t)(*contents)[0] == 0xfeu && (uint8_t)(*contents)[1] == 0xffu))) {
        free(*contents); *contents = NULL; return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    }
    return XXEMUL_STATUS_OK;
}

/* The returned bytes include NUL-separated names for enumeration.  The final
 * extra NUL is supplied by the output writer.  A single-value result has no
 * NUL in its byte count.  Input storage is private to the current call. */
static xxemul_status win_profile_select(char *contents, const char *section, const char *key, char **value, size_t *length, int *found)
{
    char *line = contents, *out;
    size_t used = 0u;
    int active = 0, enumeration = section == NULL || key == NULL;
    *found = 0; *length = 0u;
    out = (char *)calloc(WIN_PROFILE_MAX + 2u, 1u);
    if (out == NULL) return XXEMUL_STATUS_OUT_OF_MEMORY;
    *value = out;
    if (line && (uint8_t)line[0] == 0xefu && (uint8_t)line[1] == 0xbbu && (uint8_t)line[2] == 0xbfu) line += 3;
    while (line && *line) {
        char *next = strchr(line, '\n'), *text;
        if (next) *next++ = '\0';
        text = win_profile_trim(line);
        if (*text == '[') {
            char *end = strchr(text + 1, ']');
            if (end) {
                size_t size;
                *end = '\0'; text = win_profile_trim(text + 1);
                active = section && win_equal(section, text);
                if (section == NULL && *text) {
                    size = strlen(text) + 1u;
                    if (size > WIN_PROFILE_MAX - used) { free(out); *value = NULL; return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION; }
                    memcpy(out + used, text, size); used += size; *found = 1;
                }
            } else active = 0;
        } else if (active && *text != ';' && *text != '#' && *text != '\0') {
            char *equals = strchr(text, '=');
            if (equals) {
                char *name, *selected;
                size_t size;
                *equals = '\0'; name = win_profile_trim(text);
                if (key == NULL && *name) {
                    size = strlen(name) + 1u;
                    if (size > WIN_PROFILE_MAX - used) { free(out); *value = NULL; return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION; }
                    memcpy(out + used, name, size); used += size; *found = 1;
                } else if (key && win_equal(key, name)) {
                    selected = win_profile_trim(equals + 1); size = strlen(selected);
                    if (size >= 2u && ((*selected == '"' && selected[size - 1u] == '"') || (*selected == '\'' && selected[size - 1u] == '\''))) {
                        ++selected; size -= 2u;
                    }
                    memcpy(out, selected, size); used = size; *found = 1; break;
                }
            }
        }
        line = next;
    }
    *length = used;
    if (!enumeration) out[used] = '\0';
    return XXEMUL_STATUS_OK;
}

static xxemul_status win_private_profile(xxemul_windows *process, const uint64_t *arg, int integer, uint64_t *result)
{
    char *section = NULL, *key = NULL, *contents = NULL, *value = NULL, *fallback = NULL;
    size_t section_length, key_length, length = 0u, fallback_length = 0u;
    int found = 0, enumeration = !integer && (arg[0] == 0u || arg[1] == 0u);
    xxemul_status status = XXEMUL_STATUS_OK;
    if (integer && (arg[0] == 0u || arg[1] == 0u)) { *result = (uint32_t)arg[2]; return XXEMUL_STATUS_OK; }
    if (!integer && arg[4] == 0u) return XXEMUL_STATUS_OK;
    if (!integer && arg[4] > WIN_PROFILE_MAX) return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    if (arg[0]) { status = win_crt_read_string(process, arg[0], &section, &section_length); if (status != XXEMUL_STATUS_OK) goto done; }
    if (arg[1]) { status = win_crt_read_string(process, arg[1], &key, &key_length); if (status != XXEMUL_STATUS_OK) goto done; }
    status = win_profile_load(process, arg[integer ? 3u : 5u], &contents);
    if (status != XXEMUL_STATUS_OK) goto done;
    status = win_profile_select(contents, section, key, &value, &length, &found);
    if (status != XXEMUL_STATUS_OK) goto done;
    if (integer) {
        *result = found ? (uint32_t)strtoull(value, NULL, 0) : (uint32_t)arg[2];
    } else if (enumeration) {
        size_t capacity = (size_t)arg[4], copied = length, bytes;
        uint8_t *output = (uint8_t *)calloc(capacity, 1u);
        if (output == NULL) { status = XXEMUL_STATUS_OUT_OF_MEMORY; goto done; }
        if (capacity < 2u) { copied = 0u; bytes = capacity; }
        else if (length + 1u > capacity) { copied = capacity - 2u; bytes = copied + 2u; }
        else bytes = length ? length + 1u : 2u;
        if (copied) memcpy(output, value, copied);
        if (!win_write(process, arg[3], output, bytes)) status = XXEMUL_STATUS_ADDRESS_FAULT;
        else *result = copied;
        free(output);
    } else {
        size_t copied;
        if (!found && arg[2]) {
            status = win_crt_read_string(process, arg[2], &fallback, &fallback_length);
            if (status != XXEMUL_STATUS_OK) goto done;
            if (fallback_length > WIN_PROFILE_MAX) { status = XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION; goto done; }
            while (fallback_length && fallback[fallback_length - 1u] == ' ') fallback[--fallback_length] = '\0';
        }
        if (!found) { free(value); value = fallback; fallback = NULL; length = fallback_length; }
        copied = length < arg[4] - 1u ? length : (size_t)arg[4] - 1u;
        if (value) value[copied] = '\0';
        if (!win_write(process, arg[3], value ? value : "", copied + 1u)) status = XXEMUL_STATUS_ADDRESS_FAULT;
        else *result = copied;
    }
done:
    free(section); free(key); free(contents); free(value); free(fallback);
    return status;
}

#define WIN_FIND_MAX 4096u

static void win_find_destroy(win_find_state *state)
{
    if (state) { free(state->records); free(state); }
}

static int win_find_match(const char *pattern, const char *name)
{
    const char *star = NULL, *retry = NULL;
    if (!strcmp(pattern, "*.*")) pattern = "*";
    while (*name) {
        if (*pattern == '?' || tolower((unsigned char)*pattern) == tolower((unsigned char)*name)) { ++pattern; ++name; }
        else if (*pattern == '*') { star = pattern++; retry = name; }
        else if (star) { pattern = star + 1; name = ++retry; }
        else return 0;
    }
    while (*pattern == '*') ++pattern;
    return !*pattern || !strcmp(pattern, ".*");
}

static int win_find_order(const void *left, const void *right)
{
    const uint8_t *a = (const uint8_t *)left + 44u, *b = (const uint8_t *)right + 44u;
    while (*a && tolower(*a) == tolower(*b)) { ++a; ++b; }
    return tolower(*a) - tolower(*b);
}

static uint64_t win_find_time(time_t time)
{
    int64_t seconds = (int64_t)time;
    if (seconds < -INT64_C(11644473600)) return 0u;
    if (seconds > (int64_t)(UINT64_MAX / UINT64_C(10000000)) - INT64_C(11644473600)) return UINT64_MAX;
    return (uint64_t)(seconds + INT64_C(11644473600)) * UINT64_C(10000000);
}

static int win_find_add(xxemul_windows *process, win_find_state *state, const uint8_t *record)
{
    if (state->count >= WIN_FIND_MAX) { process->last_error = 8u; return 0; }
    if (state->count == state->capacity) {
        size_t capacity = state->capacity ? state->capacity * 2u : 16u;
        uint8_t *records = (uint8_t *)realloc(state->records, capacity * 320u);
        if (!records) { process->last_error = 8u; return 0; }
        state->records = records; state->capacity = capacity;
    }
    memcpy(state->records + state->count++ * 320u, record, 320u);
    return 1;
}

static int win_find_collect(xxemul_windows *process, const char *host, const char *pattern, win_find_state *state)
{
#if defined(_WIN32)
    WIN32_FIND_DATAA found;
    HANDLE search;
    char path[2048];
    if (strlen(host) + 3u > sizeof(path)) { process->last_error = 206u; return 0; }
    memcpy(path, host, strlen(host)); memcpy(path + strlen(host), "/*", 3u);
    search = FindFirstFileA(path, &found);
    if (search == INVALID_HANDLE_VALUE) { process->last_error = GetLastError(); return 0; }
    do {
        uint8_t record[320] = {0};
        size_t length = strlen(found.cFileName);
        if (!strcmp(found.cFileName, ".") || !strcmp(found.cFileName, "..") || !win_find_match(pattern, found.cFileName) ||
            (found.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) || length >= 260u) continue;
        win_put32(record, found.dwFileAttributes);
        win_put64(record + 4u, (uint64_t)found.ftCreationTime.dwLowDateTime | (uint64_t)found.ftCreationTime.dwHighDateTime << 32u);
        win_put64(record + 12u, (uint64_t)found.ftLastAccessTime.dwLowDateTime | (uint64_t)found.ftLastAccessTime.dwHighDateTime << 32u);
        win_put64(record + 20u, (uint64_t)found.ftLastWriteTime.dwLowDateTime | (uint64_t)found.ftLastWriteTime.dwHighDateTime << 32u);
        win_put32(record + 28u, found.nFileSizeHigh); win_put32(record + 32u, found.nFileSizeLow);
        memcpy(record + 44u, found.cFileName, length + 1u);
        memcpy(record + 304u, found.cAlternateFileName, sizeof(found.cAlternateFileName));
        if (!win_find_add(process, state, record)) { FindClose(search); return 0; }
    } while (FindNextFileA(search, &found));
    FindClose(search);
#else
    DIR *directory = opendir(host);
    struct dirent *entry;
    if (!directory) { process->last_error = errno == ENOENT || errno == ENOTDIR ? 3u : 5u; return 0; }
    while ((entry = readdir(directory)) != NULL) {
        uint8_t record[320] = {0};
        struct stat attributes;
        char path[2048];
        size_t length = strlen(entry->d_name), host_length = strlen(host);
        uint32_t flags;
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..") || !win_find_match(pattern, entry->d_name) || length >= 260u) continue;
        if (host_length + length + 2u > sizeof(path)) { closedir(directory); process->last_error = 206u; return 0; }
        memcpy(path, host, host_length); path[host_length] = '/'; memcpy(path + host_length + 1u, entry->d_name, length + 1u);
        if (lstat(path, &attributes) != 0 || S_ISLNK(attributes.st_mode)) continue;
        flags = S_ISDIR(attributes.st_mode) ? 0x10u : 0x20u;
        if (!(attributes.st_mode & 0222)) flags |= 1u;
        if (entry->d_name[0] == '.') flags |= 2u;
        win_put32(record, flags);
        win_put64(record + 4u, win_find_time(attributes.st_ctime));
        win_put64(record + 12u, win_find_time(attributes.st_atime));
        win_put64(record + 20u, win_find_time(attributes.st_mtime));
        win_put32(record + 28u, (uint32_t)((uint64_t)attributes.st_size >> 32u));
        win_put32(record + 32u, (uint32_t)attributes.st_size);
        memcpy(record + 44u, entry->d_name, length + 1u);
        if (!win_find_add(process, state, record)) { closedir(directory); return 0; }
    }
    closedir(directory);
#endif
    if (!state->count) { process->last_error = 2u; return 0; }
    qsort(state->records, state->count, 320u, win_find_order);
    return 1;
}

static xxemul_status win_find_write(xxemul_windows *process, const uint8_t *record, uint64_t address, int wide)
{
    uint8_t buffer[592] = {0};
    size_t i;
    if (!wide) return win_write(process, address, record, 320u) ? XXEMUL_STATUS_OK : XXEMUL_STATUS_ADDRESS_FAULT;
    memcpy(buffer, record, 44u);
    for (i = 0u; i < 260u && record[44u + i]; ++i) {
        uint16_t ch = record[44u + i];
        if (ch >= 0x80u && ch < 0xa0u) ch = win_cp1252_upper[ch - 0x80u];
        win_put16(buffer + 44u + i * 2u, ch);
    }
    for (i = 0u; i < 14u && record[304u + i]; ++i) win_put16(buffer + 564u + i * 2u, record[304u + i]);
    return win_write(process, address, buffer, sizeof(buffer)) ? XXEMUL_STATUS_OK : XXEMUL_STATUS_ADDRESS_FAULT;
}

static xxemul_status win_find_first(xxemul_windows *process, const uint64_t *arg, int wide, int extended, uint64_t *result)
{
    char guest[1024], host[2048], directory[1024], *separator, *pattern;
    win_find_state *state;
    size_t slot, length;
    xxemul_status status;
    *result = WIN_INVALID_HANDLE;
    if (extended && (arg[1] > 1u || arg[3] != 0u || arg[4] != 0u)) { process->last_error = 87u; return XXEMUL_STATUS_OK; }
    if (!win_guest_string(process, arg[0], guest, sizeof(guest), wide)) return XXEMUL_STATUS_ADDRESS_FAULT;
    for (length = 0u; guest[length]; ++length) if (guest[length] == '\\') guest[length] = '/';
    separator = strrchr(guest, '/');
    if (separator) {
        pattern = separator + 1;
        if (separator == guest) strcpy(directory, "/");
        else { size_t count = (size_t)(separator - guest); memcpy(directory, guest, count); directory[count] = 0; if (count == 2u && directory[1] == ':') strcat(directory, "/"); }
    } else { strcpy(directory, "."); pattern = guest; }
    if (!*pattern || strchr(directory, '*') || strchr(directory, '?') || !win_guest_path(process, directory, host, sizeof(host))) {
        process->last_error = 3u; return XXEMUL_STATUS_OK;
    }
    for (slot = 0u; slot < WIN_MAX_HANDLES; ++slot) if (!process->handles[slot].in_use) break;
    if (slot == WIN_MAX_HANDLES) { process->last_error = 4u; return XXEMUL_STATUS_OK; }
    state = (win_find_state *)calloc(1u, sizeof(*state));
    if (!state) { process->last_error = 8u; return XXEMUL_STATUS_OK; }
    if (!win_find_collect(process, host, pattern, state)) { win_find_destroy(state); return XXEMUL_STATUS_OK; }
    status = win_find_write(process, state->records, arg[extended ? 2u : 1u], wide);
    if (status != XXEMUL_STATUS_OK) { win_find_destroy(state); return status; }
    state->index = 1u;
    memset(&process->handles[slot], 0, sizeof(process->handles[slot]));
    process->handles[slot].kind = WIN_HANDLE_FIND;
    process->handles[slot].in_use = 1u;
    process->handles[slot].references = 1u;
    process->handles[slot].root_slot = (uint16_t)slot;
    process->handles[slot].find = state;
    *result = 0x100u + slot;
    return XXEMUL_STATUS_OK;
}

static xxemul_status win_find_next(xxemul_windows *process, const uint64_t *arg, int wide, uint64_t *result)
{
    win_handle *handle = win_handle_at(process, arg[0]);
    win_find_state *state;
    xxemul_status status;
    if (!handle || handle->kind != WIN_HANDLE_FIND || !handle->find) { process->last_error = 6u; return XXEMUL_STATUS_OK; }
    state = handle->find;
    if (state->index == state->count) { process->last_error = 18u; return XXEMUL_STATUS_OK; }
    status = win_find_write(process, state->records + state->index * 320u, arg[1], wide);
    if (status == XXEMUL_STATUS_OK) { ++state->index; *result = 1u; }
    return status;
}

static xxemul_status win_legacy_open(xxemul_windows *process, const uint64_t *arg, uint64_t *result)
{
    char filename[1024];
    uint32_t mode = (uint32_t)arg[1] & 3u;
    uint64_t handle;
    *result = UINT32_MAX;
    if (mode == 3u || ((uint32_t)arg[1] & ~0x73u)) { process->last_error = 87u; return XXEMUL_STATUS_OK; }
    if (!win_guest_string(process, arg[0], filename, sizeof(filename), 0)) return XXEMUL_STATUS_ADDRESS_FAULT;
    handle = win_file_open(process, filename, mode == 0u ? 0x80000000u : mode == 1u ? 0x40000000u : 0xc0000000u, 3u);
    if (handle != WIN_INVALID_HANDLE) *result = handle;
    return XXEMUL_STATUS_OK;
}

static xxemul_status win_legacy_read(xxemul_windows *process, const uint64_t *arg, uint64_t *result)
{
    win_handle *handle = win_handle_at(process, arg[0]);
    uint32_t count = (uint32_t)arg[2];
    uint8_t *buffer;
    ssize_t read_count;
    *result = UINT32_MAX;
    if (!handle || handle->kind != WIN_HANDLE_FILE || !handle->io) { process->last_error = 6u; return XXEMUL_STATUS_OK; }
    if (!(handle->file_access & 0x80000000u)) { process->last_error = 5u; return XXEMUL_STATUS_OK; }
    if (count > WIN_MAX_IO) { process->last_error = 8u; return XXEMUL_STATUS_OK; }
    if (!count) { *result = 0u; return XXEMUL_STATUS_OK; }
    buffer = (uint8_t *)malloc(count);
    if (!buffer) { process->last_error = 8u; return XXEMUL_STATUS_OK; }
    /* Validate the destination before consuming the file position.  This
     * public read checks the complete contiguous Windows guest range. */
    if (!win_read(process, arg[1], buffer, count)) { free(buffer); return XXEMUL_STATUS_ADDRESS_FAULT; }
    read_count = xx_io_read(handle->io, buffer, count);
    if (read_count < 0) { free(buffer); process->last_error = 5u; return XXEMUL_STATUS_OK; }
    if (!win_write(process, arg[1], buffer, (size_t)read_count)) { free(buffer); return XXEMUL_STATUS_ADDRESS_FAULT; }
    free(buffer); *result = (uint64_t)read_count;
    return XXEMUL_STATUS_OK;
}

static xxemul_status win_legacy_create(xxemul_windows *process, const uint64_t *arg, uint64_t *result)
{
    char filename[1024];
    uint64_t handle;
    *result = UINT32_MAX;
    /* Only normal file attributes are currently representable by the portable
     * file model.  Report unsupported attributes instead of ignoring them. */
    if (arg[1] != 0u) { process->last_error = 50u; return XXEMUL_STATUS_OK; }
    if (!win_guest_string(process, arg[0], filename, sizeof(filename), 0)) return XXEMUL_STATUS_ADDRESS_FAULT;
    handle = win_file_open(process, filename, 0xc0000000u, 2u);
    if (handle != WIN_INVALID_HANDLE) *result = handle;
    return XXEMUL_STATUS_OK;
}

static xxemul_status win_legacy_write(xxemul_windows *process, const uint64_t *arg, uint64_t *result)
{
    win_handle *handle = win_handle_at(process, arg[0]);
    uint32_t count = (uint32_t)arg[2];
    uint8_t *buffer;
    ssize_t written;
    *result = UINT32_MAX;
    if (!handle || handle->kind != WIN_HANDLE_FILE || !handle->io) { process->last_error = 6u; return XXEMUL_STATUS_OK; }
    if (!(handle->file_access & 0x40000000u)) { process->last_error = 5u; return XXEMUL_STATUS_OK; }
    if (count > WIN_MAX_IO) { process->last_error = 8u; return XXEMUL_STATUS_OK; }
    if (count == 0u) {
        int64_t position = xx_io_tell(handle->io);
        if (position < 0 || xx_io_resize(handle->io, position) != 0) process->last_error = 5u;
        else *result = 0u;
        return XXEMUL_STATUS_OK;
    }
    buffer = (uint8_t *)malloc(count);
    if (!buffer) { process->last_error = 8u; return XXEMUL_STATUS_OK; }
    if (!win_read(process, arg[1], buffer, count)) { free(buffer); return XXEMUL_STATUS_ADDRESS_FAULT; }
    written = xx_io_write(handle->io, buffer, count);
    free(buffer);
    if (written < 0) process->last_error = 5u;
    else *result = (uint64_t)written;
    return XXEMUL_STATUS_OK;
}

/* Explicit process locale model: en-US, ACP 1252, OEM 437.  These are guest
 * defaults, independent of the host user's locale and custom settings. */
typedef struct win_locale_value { uint16_t type; const char *text; uint32_t number; uint8_t numeric; } win_locale_value;
static const win_locale_value win_en_us[] = {
    {0x0001,"0409",0x409,1},{0x0002,"English (United States)",0,0},{0x0003,"ENU",0,0},{0x0004,"English",0,0},
    {0x0005,"1",1,1},{0x0006,"United States",0,0},{0x0007,"USA",0,0},{0x0008,"United States",0,0},
    {0x0009,"0409",0x409,1},{0x000a,"1",1,1},{0x000b,"437",437,1},{0x000c,",",0,0},
    {0x000d,"1",1,1},{0x000e,".",0,0},{0x000f,",",0,0},{0x0010,"3;0",0,0},
    {0x0011,"2",2,1},{0x0012,"1",1,1},{0x0013,"0123456789",0,0},{0x0014,"$",0,0},
    {0x0015,"USD",0,0},{0x0016,".",0,0},{0x0017,",",0,0},{0x0018,"3;0",0,0},
    {0x0019,"2",2,1},{0x001a,"2",2,1},{0x001b,"0",0,1},{0x001c,"0",0,1},
    {0x001d,"/",0,0},{0x001e,":",0,0},{0x001f,"M/d/yyyy",0,0},{0x0020,"dddd, MMMM d, yyyy",0,0},
    {0x0021,"0",0,1},{0x0022,"0",0,1},{0x0023,"0",0,1},{0x0024,"1",1,1},
    {0x0025,"0",0,1},{0x0026,"0",0,1},{0x0027,"0",0,1},{0x0028,"AM",0,0},{0x0029,"PM",0,0},
    {0x002a,"Monday",0,0},{0x002b,"Tuesday",0,0},{0x002c,"Wednesday",0,0},{0x002d,"Thursday",0,0},
    {0x002e,"Friday",0,0},{0x002f,"Saturday",0,0},{0x0030,"Sunday",0,0},
    {0x0031,"Mon",0,0},{0x0032,"Tue",0,0},{0x0033,"Wed",0,0},{0x0034,"Thu",0,0},{0x0035,"Fri",0,0},{0x0036,"Sat",0,0},{0x0037,"Sun",0,0},
    {0x0038,"January",0,0},{0x0039,"February",0,0},{0x003a,"March",0,0},{0x003b,"April",0,0},
    {0x003c,"May",0,0},{0x003d,"June",0,0},{0x003e,"July",0,0},{0x003f,"August",0,0},
    {0x0040,"September",0,0},{0x0041,"October",0,0},{0x0042,"November",0,0},{0x0043,"December",0,0},
    {0x0044,"Jan",0,0},{0x0045,"Feb",0,0},{0x0046,"Mar",0,0},{0x0047,"Apr",0,0},
    {0x0048,"May",0,0},{0x0049,"Jun",0,0},{0x004a,"Jul",0,0},{0x004b,"Aug",0,0},
    {0x004c,"Sep",0,0},{0x004d,"Oct",0,0},{0x004e,"Nov",0,0},{0x004f,"Dec",0,0},
    {0x0050,"",0,0},{0x0051,"-",0,0},{0x0052,"3",3,1},{0x0053,"0",0,1},
    {0x0054,"1",1,1},{0x0055,"0",0,1},{0x0056,"1",1,1},{0x0057,"0",0,1},
    {0x0059,"en",0,0},{0x005a,"US",0,0},{0x005b,"244",244,1},{0x005c,"en-US",0,0},
    {0x1001,"English",0,0},{0x1002,"United States",0,0},{0x1003,"h:mm:ss tt",0,0},
    {0x1004,"1252",1252,1},{0x1005,"0",0,1},{0x1006,"MMMM yyyy",0,0},
    {0x1007,"US Dollar",0,0},{0x1008,"US Dollar",0,0},{0x1009,"1",1,1},
    {0x100a,"1",1,1},{0x100b,"0",0,1},{0x100c,"6",6,1},{0x100d,"0",0,1},
    {0x100e,"",0,0},{0x100f,"",0,0},{0x1011,"10000",10000,1},{0x1012,"37",37,1},{0x1013,"Default",0,0}
};

static xxemul_status win_locale_info(xxemul_windows *process, const uint64_t *arg, int wide, uint64_t *result)
{
    uint32_t locale = (uint32_t)arg[0], type = (uint32_t)arg[1];
    int32_t capacity = (int32_t)arg[3];
    uint32_t selector = type & 0xffffu;
    int number = (type & 0x20000000u) != 0u;
    const win_locale_value *value = NULL;
    size_t index, length, required, unit = wide ? 2u : 1u;
    uint8_t output[128];
    if (locale != 0x0409u && locale != 0x0400u && locale != 0x0800u && locale != 0u && locale != 9u) {
        process->last_error = 87u; return XXEMUL_STATUS_OK;
    }
    if ((type & ~UINT32_C(0xe000ffff)) != 0u) { process->last_error = 1004u; return XXEMUL_STATUS_OK; }
    if (capacity < 0 || capacity > (int32_t)(WIN_MAX_IO / unit)) { process->last_error = 87u; return XXEMUL_STATUS_OK; }
    for (index = 0u; index < sizeof(win_en_us) / sizeof(win_en_us[0]); ++index)
        if (win_en_us[index].type == selector) { value = &win_en_us[index]; break; }
    if (!value || (number && !value->numeric)) { process->last_error = 1004u; return XXEMUL_STATUS_OK; }
    length = strlen(value->text);
    required = number ? 4u / unit : length + 1u;
    if (!capacity) { *result = required; return XXEMUL_STATUS_OK; }
    if (!arg[2] || (size_t)capacity < required) { process->last_error = 122u; return XXEMUL_STATUS_OK; }
    if (number) win_put32(output, value->number);
    else {
        if ((length + 1u) * unit > sizeof(output)) return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
        for (index = 0u; index <= length; ++index)
            if (wide) win_put16(output + index * 2u, (uint8_t)value->text[index]); else output[index] = (uint8_t)value->text[index];
    }
    if (!win_write(process, arg[2], output, required * unit)) return XXEMUL_STATUS_ADDRESS_FAULT;
    *result = required;
    return XXEMUL_STATUS_OK;
}

#include "xxemul_windows_resource.inc"

static win_gui_object *win_gui_at(xxemul_windows *process, uint64_t handle)
{
    uint64_t slot = handle - UINT64_C(0x10000);
    return handle >= UINT64_C(0x10000) && slot < WIN_GUI_OBJECTS && process->gui_objects[slot].active ?
        &process->gui_objects[slot] : NULL;
}
static uint64_t win_gui_new(xxemul_windows *process, uint8_t kind, uint64_t parent)
{
    size_t i;
    for (i=0u;i<WIN_GUI_OBJECTS;++i) if (!process->gui_objects[i].active) {
        win_gui_object *object=&process->gui_objects[i];
        memset(object,0,sizeof(*object));object->active=1u;object->kind=kind;object->parent=parent;
        object->maximum=100;object->increment=10;
        return UINT64_C(0x10000)+i;
    }
    return 0u;
}
static int win_gui_resource(xxemul_windows *process,unsigned type,unsigned name,uint64_t *address,uint32_t *size)
{
    win_resource_key type_key,name_key;win_resource_image image;uint32_t entry;
    memset(&type_key,0,sizeof(type_key));memset(&name_key,0,sizeof(name_key));
    type_key.id=(uint16_t)type;name_key.id=(uint16_t)name;
    return type<=UINT16_MAX&&name<=UINT16_MAX&&
        win_resource_lookup(process,0u,&type_key,&name_key,0,0u,&image,&entry,address,size)&&*size&&*size<=0x10000u;
}
typedef struct win_dialog_reader{xxemul_windows *process;uint64_t at,end;}win_dialog_reader;
static int win_dialog_value(win_dialog_reader *reader,unsigned width,uint64_t *value)
{
    if(reader->at>reader->end || width>reader->end-reader->at || !win_load(reader->process,reader->at,(uint8_t)width,value))return 0;
    reader->at+=width;return 1;
}
static int win_dialog_string(win_dialog_reader *reader,uint16_t *text,size_t capacity,uint16_t *ordinal)
{
    uint64_t value;size_t used=0u;
    if(ordinal)*ordinal=0u;
    if(text&&capacity)text[0]=0u;
    if(!win_dialog_value(reader,2u,&value))return 0;
    if(value==0xffffu){if(!win_dialog_value(reader,2u,&value))return 0;if(ordinal)*ordinal=(uint16_t)value;return 1;}
    for(;;){
        if(text&&used+1u<capacity){text[used]=(uint16_t)value;text[used+1u]=0u;}
        if(!value)return 1;
        if(++used>=256u || !win_dialog_value(reader,2u,&value))return 0;
    }
}
static void win_gui_discard(xxemul_windows *process,uint64_t dialog)
{
    size_t i;
    for(i=0u;i<WIN_GUI_OBJECTS;++i){
        win_gui_object *object=&process->gui_objects[i];
        if(object->active && (UINT64_C(0x10000)+i==dialog || object->parent==dialog))memset(object,0,sizeof(*object));
    }
}
static uint64_t win_gui_template(xxemul_windows *process,uint64_t address,uint32_t size)
{
    win_dialog_reader r={process,address,address+size};
    uint64_t version,signature,style,count,ignored,dialog=0u,font=0u,control,value;
    unsigned extended,i;uint16_t face[256],menu[256],dialog_class[256],ordinal=0u;win_gui_object *object,*font_object;
    if(!win_dialog_value(&r,2u,&version)||!win_dialog_value(&r,2u,&signature))return 0u;
    extended=version==1u&&signature==0xffffu;
    r.at=address;
    if(extended){
        if(!win_dialog_value(&r,4u,&ignored)||!win_dialog_value(&r,4u,&ignored)||
           !win_dialog_value(&r,4u,&ignored)||!win_dialog_value(&r,4u,&style)||!win_dialog_value(&r,2u,&count))return 0u;
    }else if(!win_dialog_value(&r,4u,&style)||!win_dialog_value(&r,4u,&ignored)||!win_dialog_value(&r,2u,&count))return 0u;
    if(count>64u || !win_dialog_value(&r,8u,&ignored) || !win_dialog_string(&r,menu,256u,&ordinal) ||menu[0]||ordinal||
       !win_dialog_string(&r,dialog_class,256u,&ordinal)||dialog_class[0]||ordinal)return 0u;
    dialog=win_gui_new(process,WIN_GUI_DIALOG,0u);if(!dialog)return 0u;
    object=win_gui_at(process,dialog);object->style=(uint32_t)style;
    if(!win_dialog_string(&r,object->text,256u,NULL))goto bad;
    if(style&0x40u){
        uint64_t points,weight=400u,italic=0u,charset=1u;
        if(!win_dialog_value(&r,2u,&points))goto bad;
        if(extended && (!win_dialog_value(&r,2u,&weight)||!win_dialog_value(&r,1u,&italic)||!win_dialog_value(&r,1u,&charset)))goto bad;
        if(!win_dialog_string(&r,face,256u,NULL))goto bad;
        font=win_gui_new(process,WIN_GUI_FONT,dialog);if(!font)goto bad;
        font_object=win_gui_at(process,font);
        /* Headless logical fonts retain the template's point size/family.
         * The GUI model has a fixed logical 96-DPI coordinate system. */
        win_put32(font_object->logfont,(uint32_t)(-(int32_t)((points*4u+1u)/3u)));
        win_put32(font_object->logfont+16u,(uint32_t)weight);font_object->logfont[20u]=(uint8_t)italic;font_object->logfont[23u]=(uint8_t)charset;
        for(i=0u;i<31u&&face[i];++i){font_object->logfont[28u+i]=win_reg_unansi(face[i]);font_object->text[i]=face[i];}
        object->font=font;
    }
    for(i=0u;i<count;++i){
        r.at=(r.at+3u)&~UINT64_C(3);
        control=win_gui_new(process,WIN_GUI_CONTROL,dialog);if(!control)goto bad;
        object=win_gui_at(process,control);object->font=font;
        if(extended && !win_dialog_value(&r,4u,&ignored))goto bad;
        if(extended){if(!win_dialog_value(&r,4u,&ignored)||!win_dialog_value(&r,4u,&style))goto bad;}
        else if(!win_dialog_value(&r,4u,&style)||!win_dialog_value(&r,4u,&ignored))goto bad;
        object->style=(uint32_t)style;
        if(!win_dialog_value(&r,8u,&ignored)||!win_dialog_value(&r,extended?4u:2u,&value))goto bad;
        object->id=(uint32_t)value;
        if(!win_dialog_string(&r,object->class_name,64u,&object->class_ordinal)||
           !win_dialog_string(&r,object->text,256u,NULL)||!win_dialog_value(&r,2u,&value))goto bad;
        /* Standard creation-data size includes its WORD; extended extraCount
         * counts only the following bytes. Zero means no creation data. */
        if(!extended&&value){if(value<2u)goto bad;value-=2u;}
        if(value>r.end-r.at)goto bad;
        if(object->class_ordinal && (object->class_ordinal<0x80u||object->class_ordinal>0x85u))goto bad;
        if(!object->class_ordinal){
            char class_name[64];unsigned k;
            for(k=0u;k<63u&&object->class_name[k];++k){if(object->class_name[k]>127u)goto bad;class_name[k]=(char)object->class_name[k];}class_name[k]=0;
            if(!win_equal(class_name,"msctls_progress32") && !win_equal(class_name,"static") && !win_equal(class_name,"button") &&
               !win_equal(class_name,"edit") && !win_equal(class_name,"listbox") && !win_equal(class_name,"scrollbar") && !win_equal(class_name,"combobox"))goto bad;
        }
        r.at+=value;
    }
    return dialog;
bad:win_gui_discard(process,dialog);return 0u;
}
static uint64_t win_gui_child(xxemul_windows *process,uint64_t parent,uint32_t id)
{
    size_t i;
    for(i=0u;i<WIN_GUI_OBJECTS;++i)if(process->gui_objects[i].active&&process->gui_objects[i].kind==WIN_GUI_CONTROL&&
        process->gui_objects[i].parent==parent&&process->gui_objects[i].id==id)return UINT64_C(0x10000)+i;
    return 0u;
}
static uint64_t win_gui_initial_focus(xxemul_windows *process,uint64_t parent)
{
    size_t i;
    for(i=0u;i<WIN_GUI_OBJECTS;++i){win_gui_object *object=&process->gui_objects[i];
        if(object->active&&object->kind==WIN_GUI_CONTROL&&object->parent==parent&&
           (object->style&0x10000u)&&!(object->style&0x08000000u))return UINT64_C(0x10000)+i;
    }
    return 0u;
}
static int win_gui_text(xxemul_windows *process,uint64_t address,int wide,uint16_t *output)
{
    size_t i;uint64_t value;
    memset(output,0,256u*sizeof(*output));
    if(!address)return 1;
    for(i=0u;i<256u;++i){
        if(!win_load(process,address+i*(wide?2u:1u),(uint8_t)(wide?2u:1u),&value))return 0;
        output[i]=wide?(uint16_t)value:win_reg_ansi((uint8_t)value);if(!value)return 1;
    }
    return 0;
}
static xxemul_status win_dialog_invoke(xxemul_windows *process,win_dialog_frame *frame,xxemul_step_info *info);
static xxemul_status win_dialog_return(xxemul_windows *process,int waited,xxemul_step_info *info);
static xxemul_status win_gui_read_text(xxemul_windows *process,const win_gui_object *object,uint64_t output,uint64_t capacity,int wide,uint64_t *result)
{
    uint8_t bytes[512];size_t count=0u,i;
    if(!capacity)return XXEMUL_STATUS_OK;
    while(count+1u<capacity && count<255u && object->text[count])++count;
    for(i=0u;i<=count;++i){
        uint16_t value=i==count?0u:object->text[i];
        if(wide){bytes[i*2u]=(uint8_t)value;bytes[i*2u+1u]=(uint8_t)(value>>8u);}
        else bytes[i]=win_reg_unansi(value);
    }
    if(!win_write(process,output,bytes,(count+1u)*(wide?2u:1u)))return XXEMUL_STATUS_ADDRESS_FAULT;
    *result=count;return XXEMUL_STATUS_OK;
}
static xxemul_status win_gui_message(xxemul_windows *process,uint64_t handle,uint32_t message,uint64_t wparam,uint64_t lparam,int wide,uint64_t *result)
{
    win_gui_object *object=win_gui_at(process,handle),*other;uint16_t temporary[256];size_t i;
    if(!object || (object->kind!=WIN_GUI_DIALOG && object->kind!=WIN_GUI_CONTROL)){process->last_error=1400u;return XXEMUL_STATUS_OK;}
    if(message==0x30u){
        other=win_gui_at(process,wparam);if(wparam && (!other||other->kind!=WIN_GUI_FONT)){process->last_error=6u;return XXEMUL_STATUS_OK;}
        object->font=wparam;return XXEMUL_STATUS_OK;
    }
    if(message==0x31u){*result=object->font;return XXEMUL_STATUS_OK;}
    if(message==0x80u){
        other=win_gui_at(process,lparam);if(wparam>1u ||(lparam&&(!other||other->kind!=WIN_GUI_ICON))){process->last_error=87u;return XXEMUL_STATUS_OK;}
        *result=object->icon[wparam];object->icon[wparam]=lparam;return XXEMUL_STATUS_OK;
    }
    if(message==0xcu){
        if(!win_gui_text(process,lparam,wide,temporary))return XXEMUL_STATUS_ADDRESS_FAULT;
        memcpy(object->text,temporary,sizeof(temporary));*result=1u;return XXEMUL_STATUS_OK;
    }
    if(message==0xdu)return win_gui_read_text(process,object,lparam,wparam,wide,result);
    if(message==0xeu){for(i=0u;i<256u&&object->text[i];++i){}*result=i;return XXEMUL_STATUS_OK;}
    if(object->kind==WIN_GUI_CONTROL && message>=0x401u && message<=0x406u){
        if(object->class_name[0]!='m' || object->class_name[1]!='s')return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
        if(message==0x401u || message==0x406u){
            *result=((uint32_t)object->minimum&0xffffu)|(((uint32_t)object->maximum&0xffffu)<<16u);
            object->minimum=message==0x401u?(int16_t)lparam:(int32_t)wparam;
            object->maximum=message==0x401u?(int16_t)(lparam>>16u):(int32_t)lparam;
        }else if(message==0x404u){*result=(uint32_t)object->increment;object->increment=(int32_t)wparam;}
        else{
            int64_t next=message==0x402u?(int32_t)wparam:(int64_t)object->position+(message==0x403u?(int32_t)wparam:object->increment);
            *result=(uint32_t)object->position;
            if(next<object->minimum)next=object->minimum;
            if(next>object->maximum)next=object->maximum;
            object->position=(int32_t)next;
        }
        return XXEMUL_STATUS_OK;
    }
    return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
}

static xxemul_status win_thread_create(xxemul_windows *process, const uint64_t *arg, uint64_t *result);

static xxemul_status win_call(xxemul_windows *process, const win_api *api, const uint64_t *arg, uint64_t *result)
{
    const char *name = api->name;
    uint8_t word_size = win_word_size(process->emulator);
    char text[1024];
    xx_io_device *io;
    uint64_t value, address;
    int wide;

    *result = 0;
    if(win_equal(name,"CheckSumMappedFile")){
        uint64_t nt,signature,magic,header;uint32_t sum;const uint8_t *raw;
        uint32_t length=(uint32_t)arg[1];
        if(!arg[2]||!arg[3]||!win_memory_span(process,arg[2],4u)||!win_memory_span(process,arg[3],4u)){process->last_error=998u;return XXEMUL_STATUS_OK;}
        if(length<64u || length>WIN_MAX_IO || !win_memory_span(process,arg[0],length) ||
           !win_load(process,arg[0],2u,&magic) || magic!=0x5a4du || !win_load(process,arg[0]+0x3cu,4u,&nt) ||
           nt>length-24u || length-(nt+24u)<68u || (nt&1u) || !win_load(process,arg[0]+nt,4u,&signature) || signature!=0x4550u ||
           !win_load(process,arg[0]+nt+24u,2u,&magic) || (magic!=0x10bu && magic!=0x20bu)){
            (void)win_store(process,arg[2],4u,0u);process->last_error=193u;return XXEMUL_STATUS_OK;}
        raw=process->emulator->region_data+(size_t)(arg[0]-process->image_base);
        if(!win_load(process,arg[0]+nt+24u+64u,4u,&header))return XXEMUL_STATUS_ADDRESS_FAULT;
        sum=xx_pe_checksum(raw,length,(size_t)nt+24u+64u);
        (void)win_store(process,arg[2],4u,header);(void)win_store(process,arg[3],4u,sum);
        *result=arg[0]+nt;return XXEMUL_STATUS_OK;
    }
    if(win_equal(name,"lstrcmpiA") || win_equal(name,"lstrcmpiW")){
        size_t position;uint8_t width=win_suffix(name,"W")?2u:1u;
        /* The process locale is en-US. The observed codec export identifiers
         * use ASCII letters/digits/underscore, whose case-insensitive ordering
         * is modeled explicitly. Other linguistic data remains unsupported. */
        for(position=0u;position<4096u;++position){uint64_t left,right;unsigned a,b;
            if(!win_load(process,arg[0]+position*width,width,&left)||!win_load(process,arg[1]+position*width,width,&right))return XXEMUL_STATUS_ADDRESS_FAULT;
            if((left && !((left>='a'&&left<='z')||(left>='A'&&left<='Z')||(left>='0'&&left<='9')||left=='_')) ||
               (right && !((right>='a'&&right<='z')||(right>='A'&&right<='Z')||(right>='0'&&right<='9')||right=='_')))return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
            a=left>='A'&&left<='Z'?(unsigned)left+32u:(unsigned)left;b=right>='A'&&right<='Z'?(unsigned)right+32u:(unsigned)right;
            if(a=='_')a=1u;
            if(b=='_')b=1u;
            if(a!=b){*result=a<b?UINT32_MAX:1u;return XXEMUL_STATUS_OK;}
            if(!a)return XXEMUL_STATUS_OK;
        }
        return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    }
    if(strcmp(name,"DisableThreadLibraryCalls")==0){
        win_module *module=win_dll_at(process,arg[0]);
        if(!module||!module->real){process->last_error=87u;return XXEMUL_STATUS_OK;}
        if(module->tls.callbacks || (module->tls.present && module->tls.data_size)){
            process->last_error=87u;return XXEMUL_STATUS_OK;
        }
        module->thread_callbacks_disabled=1u;*result=1u;return XXEMUL_STATUS_OK;
    }
    if (win_resource_call(process,name,arg,result)) return XXEMUL_STATUS_OK;
    if (win_equal(name, "SetTimer") || win_equal(name, "MoveWindow")) {
        /* Correct observed GUI ABIs without claiming unimplemented timer,
         * layout, painting, or window-message effects. */
        process->last_error = 120u;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name,"DialogBoxParamA")==0 || strcmp(name,"DialogBoxParamW")==0) {
        uint64_t resource,dialog,event;uint32_t size;size_t index;
        win_dialog_frame *frame;
        *result=word_size==8u?UINT64_MAX:UINT32_MAX;
        if(arg[2]){win_gui_object *parent=win_gui_at(process,arg[2]);
            if(!parent||(parent->kind!=WIN_GUI_DIALOG&&parent->kind!=WIN_GUI_CONTROL)){process->last_error=1400u;*result=0u;return XXEMUL_STATUS_OK;}}
        if(process->emulator->arch!=XXEMUL_ARCH_X86)return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
        if(arg[0]&&arg[0]!=process->image_base){process->last_error=1812u;return XXEMUL_STATUS_OK;}
        if(arg[1]>0xffffu)return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
        if(!arg[3]||!win_memory_span(process,arg[3],1u)){process->last_error=87u;return XXEMUL_STATUS_OK;}
        if(!win_gui_resource(process,5u,(unsigned)arg[1],&resource,&size)){process->last_error=1814u;return XXEMUL_STATUS_OK;}
        for(index=0u;index<WIN_GUI_DIALOGS&&process->dialogs[index].active;++index){}
        if(index==WIN_GUI_DIALOGS){process->last_error=8u;return XXEMUL_STATUS_OK;}
        dialog=win_gui_template(process,resource,size);
        if(!dialog){process->last_error=1813u;return XXEMUL_STATUS_OK;}
        event=win_create_sync(process,WIN_HANDLE_EVENT,1u,0u,0u);
        if(!event){win_gui_discard(process,dialog);process->last_error=8u;return XXEMUL_STATUS_OK;}
        frame=&process->dialogs[index];memset(frame,0,sizeof(*frame));
        frame->active=1u;frame->handle=dialog;frame->event=event;frame->procedure=arg[3];frame->parameter=arg[4];
        frame->owner_id=process->threads[process->thread_current].id;frame->wide=(uint8_t)win_suffix(name,"W");
        frame->sequence=++process->dialog_sequence;process->dialog_pending=(unsigned)index+1u;
        return XXEMUL_STATUS_OK;
    }
    if(strcmp(name,"EndDialog")==0){
        size_t i;
        for(i=0u;i<WIN_GUI_DIALOGS;++i){win_dialog_frame *frame=&process->dialogs[i];
            if(frame->active&&frame->handle==arg[0]){win_handle *event=win_handle_at(process,frame->event);
                if(!frame->ended){frame->ended=1u;frame->result=arg[1];if(event)event->signaled=1u;}
                *result=1u;return XXEMUL_STATUS_OK;
            }
        }
        process->last_error=1400u;return XXEMUL_STATUS_OK;
    }
    if(strcmp(name,"GetDlgItem")==0){
        win_gui_object *parent=win_gui_at(process,arg[0]);
        if(!parent||(parent->kind!=WIN_GUI_DIALOG&&parent->kind!=WIN_GUI_CONTROL)){process->last_error=1400u;return XXEMUL_STATUS_OK;}
        *result=win_gui_child(process,arg[0],(uint32_t)arg[1]);return XXEMUL_STATUS_OK;
    }
    if(strcmp(name,"SetWindowTextA")==0||strcmp(name,"SetWindowTextW")==0 ||
       strcmp(name,"SetDlgItemTextA")==0||strcmp(name,"SetDlgItemTextW")==0){
        uint64_t handle=win_prefix(name,"SetDlg")?win_gui_child(process,arg[0],(uint32_t)arg[1]):arg[0];
        uint64_t source=win_prefix(name,"SetDlg")?arg[2]:arg[1];
        return win_gui_message(process,handle,0xcu,0u,source,win_suffix(name,"W"),result);
    }
    if(strcmp(name,"GetWindowTextA")==0||strcmp(name,"GetWindowTextW")==0 ||
       strcmp(name,"GetDlgItemTextA")==0||strcmp(name,"GetDlgItemTextW")==0){
        int child=win_prefix(name,"GetDlg");uint64_t handle=child?win_gui_child(process,arg[0],(uint32_t)arg[1]):arg[0];
        return win_gui_message(process,handle,0xdu,child?arg[3]:arg[2],child?arg[2]:arg[1],win_suffix(name,"W"),result);
    }
    if(strcmp(name,"SendMessageA")==0||strcmp(name,"SendMessageW")==0)
        return win_gui_message(process,arg[0],(uint32_t)arg[1],arg[2],arg[3],win_suffix(name,"W"),result);
    if(strcmp(name,"SendDlgItemMessageA")==0||strcmp(name,"SendDlgItemMessageW")==0)
        return win_gui_message(process,win_gui_child(process,arg[0],(uint32_t)arg[1]),(uint32_t)arg[2],arg[3],arg[4],win_suffix(name,"W"),result);
    if(strcmp(name,"CreateFontIndirectA")==0||strcmp(name,"CreateFontIndirectW")==0){
        uint8_t bytes[92];unsigned i;uint64_t font;win_gui_object *object;
        int wide=win_suffix(name,"W");unsigned amount=wide?92u:60u;
        if(!win_read(process,arg[0],bytes,amount))return XXEMUL_STATUS_ADDRESS_FAULT;
        font=win_gui_new(process,WIN_GUI_FONT,0u);if(!font){process->last_error=8u;return XXEMUL_STATUS_OK;}
        object=win_gui_at(process,font);memcpy(object->logfont,bytes,28u);
        for(i=0u;i<32u;++i){uint16_t ch=wide?(uint16_t)(bytes[28u+i*2u]|((uint16_t)bytes[29u+i*2u]<<8u)):win_reg_ansi(bytes[28u+i]);
            object->text[i]=ch;object->logfont[28u+i]=win_reg_unansi(ch);}
        *result=font;return XXEMUL_STATUS_OK;
    }
    if(strcmp(name,"GetObjectA")==0||strcmp(name,"GetObjectW")==0){
        win_gui_object *object=win_gui_at(process,arg[0]);uint8_t bytes[92];unsigned i;int wide=win_suffix(name,"W");unsigned amount=wide?92u:60u;
        if(!object||object->kind!=WIN_GUI_FONT){process->last_error=6u;return XXEMUL_STATUS_OK;}
        if(!arg[2]){*result=amount;return XXEMUL_STATUS_OK;}
        if(arg[1]<amount){process->last_error=87u;return XXEMUL_STATUS_OK;}
        memcpy(bytes,object->logfont,28u);
        for(i=0u;i<32u;++i){uint16_t ch=object->text[i]?object->text[i]:win_reg_ansi(object->logfont[28u+i]);
            if(wide){bytes[28u+i*2u]=(uint8_t)ch;bytes[29u+i*2u]=(uint8_t)(ch>>8u);}else bytes[28u+i]=win_reg_unansi(ch);}
        if(!win_write(process,arg[2],bytes,amount))return XXEMUL_STATUS_ADDRESS_FAULT;
        *result=amount;return XXEMUL_STATUS_OK;
    }
    if(strcmp(name,"DeleteObject")==0){win_gui_object *object=win_gui_at(process,arg[0]);
        if(object&&object->kind==WIN_GUI_FONT){memset(object,0,sizeof(*object));*result=1u;}else process->last_error=6u;
        return XXEMUL_STATUS_OK;
    }
    if(strcmp(name,"InitCommonControlsEx")==0){
        uint64_t amount,classes;
        if(!win_load(process,arg[0],4u,&amount)||!win_load(process,arg[0]+4u,4u,&classes))return XXEMUL_STATUS_ADDRESS_FAULT;
        if(amount!=8u || classes&~UINT64_C(0xffff)){process->last_error=87u;return XXEMUL_STATUS_OK;}
        process->gui_common_controls|=(uint32_t)classes;*result=1u;return XXEMUL_STATUS_OK;
    }
    if(strcmp(name,"LoadIconA")==0||strcmp(name,"LoadIconW")==0){
        uint64_t group,kind,count,id,image,handle;uint32_t group_size,image_size;win_gui_object *object;
        if(!arg[0])return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
        if(arg[0]!=process->image_base){process->last_error=1812u;return XXEMUL_STATUS_OK;}
        if(arg[1]>0xffffu)return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
        if(!win_gui_resource(process,14u,(unsigned)arg[1],&group,&group_size)||group_size<20u||
            !win_load(process,group+2u,2u,&kind)||kind!=1u||!win_load(process,group+4u,2u,&count)||!count||count>32u||
            group_size<6u+count*14u||!win_load(process,group+18u,2u,&id)||
            !win_gui_resource(process,3u,(unsigned)id,&image,&image_size)){process->last_error=1814u;return XXEMUL_STATUS_OK;}
        handle=win_gui_new(process,WIN_GUI_ICON,0u);if(!handle){process->last_error=8u;return XXEMUL_STATUS_OK;}
        object=win_gui_at(process,handle);object->resource=image;object->resource_size=image_size;*result=handle;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "VirtualFreeEx") == 0 || strcmp(name, "VirtualProtectEx") == 0 || strcmp(name, "VirtualAllocEx") == 0) {
        win_api alias = *api;
        const char *plain = strcmp(name, "VirtualFreeEx") == 0 ? "VirtualFree" : strcmp(name, "VirtualProtectEx") == 0 ? "VirtualProtect" : "VirtualAlloc";
        if (!win_is_current_process_handle(process, arg[0], word_size)) {
            process->last_error = 6u;
            return XXEMUL_STATUS_OK;
        }
        snprintf(alias.name, sizeof(alias.name), "%s", plain);
        return win_call(process, &alias, arg + 1u, result);
    }
    if (strcmp(name, "NtSetInformationThread") == 0 || strcmp(name, "ZwSetInformationThread") == 0) return XXEMUL_STATUS_OK;
    if (strcmp(name, "GetKeyboardType") == 0) {
        *result = arg[0] == 0u ? 4u : arg[0] == 2u ? 12u : 0u;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "GetExitCodeThread") == 0) {
        win_handle *thread = win_handle_at(process, arg[0]);
        win_child_process *child=win_child_at(process,thread);
        uint32_t code = child?(!child->emulator->windows->threads[0].active?child->emulator->windows->threads[0].exit_code:259u):(thread && thread->kind == WIN_HANDLE_THREAD && thread->thread_finished ? thread->thread_exit : 259u);
        if(child && thread->kind==WIN_HANDLE_THREAD) {
            if(!arg[1] || !win_memory_span(process,arg[1],4u)){process->last_error=998u;return XXEMUL_STATUS_OK;}
            (void)win_store(process,arg[1],4u,code);*result=1u;return XXEMUL_STATUS_OK;
        }
        if (!win_is_current_thread_handle(process, arg[0], word_size) || !arg[1]) {
            process->last_error = 6u;
            return XXEMUL_STATUS_OK;
        }
        if (!win_store(process, arg[1], 4u, code)) return XXEMUL_STATUS_ADDRESS_FAULT;
        *result = 1u;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "ResumeThread") == 0 || strcmp(name, "SuspendThread") == 0) {
        win_handle *handle = win_handle_at(process, arg[0]);
        win_thread_context *thread;
        win_child_process *child=win_child_at(process,handle);
        *result = UINT32_MAX;
        if(child && handle->kind==WIN_HANDLE_THREAD) {
            win_thread_context *primary=&child->emulator->windows->threads[0];
            *result=primary->active?primary->suspended:0u;
            if(primary->active) {
                if(win_equal(name,"ResumeThread")){if(primary->suspended)--primary->suspended;}
                else if(primary->suspended<0x7fffffffu)++primary->suspended;
                else{*result=UINT32_MAX;process->last_error=87u;}
            }
            child->suspended=primary->suspended;
            return XXEMUL_STATUS_OK;
        }
        if (!handle || handle->kind != WIN_HANDLE_THREAD || !handle->thread_start) { process->last_error = 6u; return XXEMUL_STATUS_OK; }
        if (handle->thread_finished) { *result = 0u; return XXEMUL_STATUS_OK; }
        thread = &process->threads[handle->thread_slot];
        *result = thread->suspended;
        if (strcmp(name, "ResumeThread") == 0) { if (thread->suspended) --thread->suspended; }
        else if (thread->suspended < 0x7fffffffu) ++thread->suspended;
        else { *result = UINT32_MAX; process->last_error = 87u; }
        return XXEMUL_STATUS_OK;
    }

    if (strcmp(name, "ShellExecuteA") == 0) {
        *result = 33u; /* bounded headless shell model; no host process */
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "LoadLibraryA") == 0 || strcmp(name, "LoadLibraryW") == 0 || strcmp(name, "LoadLibraryExA") == 0 || strcmp(name, "LoadLibraryExW") == 0 ||
        strcmp(name, "GetModuleHandleA") == 0 || strcmp(name, "GetModuleHandleW") == 0) {
        win_module *module;int loading=name[0]=='L';uint32_t flags=0u;
        if(!arg[0]&&!loading){*result=process->image_base;return XXEMUL_STATUS_OK;}
        if(!win_guest_string(process,arg[0],text,sizeof(text),win_suffix(name,"W")))return XXEMUL_STATUS_ADDRESS_FAULT;
        if(!loading&&win_main_program_name(process,text)){*result=process->image_base;return XXEMUL_STATUS_OK;}
        module=win_find_module(process,text,0);
        if(!loading){if(module)*result=module->base;else process->last_error=126u;return XXEMUL_STATUS_OK;}
        if(win_prefix(name,"LoadLibraryEx")){if(arg[1]){process->last_error=87u;return XXEMUL_STATUS_OK;}flags=(uint32_t)arg[2];}
        if(module&&!module->real){if(flags){process->last_error=120u;return XXEMUL_STATUS_OK;}*result=module->base;return XXEMUL_STATUS_OK;}
        if(module && module->primary && !strpbrk(text,"/\\")){
            if(flags){process->last_error=120u;return XXEMUL_STATUS_OK;}
            *result=module->base;return XXEMUL_STATUS_OK;
        }
        *result=win_dll_load(process,text,flags);
        if(!*result && process->last_error==126u && win_loadable_module(process,text)) *result=win_module_handle(process,text);
        if(*result){module=win_dll_at(process,*result);if(module&&module->real&&!module->initialized){process->dll_pending=(size_t)(module-process->modules)+1u;process->dll_pending_unload=0u;}}
        return XXEMUL_STATUS_OK;
    }
    if(strcmp(name,"FreeLibrary")==0){
        win_module *module=win_dll_at(process,arg[0]);
        if(!module||(!module->references&&module->real)){process->last_error=6u;return XXEMUL_STATUS_OK;}
        if(!module->real){*result=1u;return XXEMUL_STATUS_OK;}
        if(module->initializing || win_dll_module_notifying(process,(size_t)(module-process->modules))){process->last_error=170u;return XXEMUL_STATUS_OK;}
        if(module->references==1u){process->dll_pending=(size_t)(module-process->modules)+1u;process->dll_pending_unload=1u;}
        else if(module->references!=UINT32_MAX)--module->references;
        *result=1u;return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "GetModuleHandleExW") == 0 || strcmp(name, "GetModuleHandleExA") == 0) {
        uint32_t flags=(uint32_t)arg[0];uint64_t handle=0u;win_module *module=NULL;size_t index;
        if(!arg[2]||!win_memory_span(process,arg[2],word_size)){process->last_error=998u;return XXEMUL_STATUS_OK;}
        (void)win_store(process,arg[2],word_size,0u);
        if((flags&~7u)||((flags&3u)==3u)){process->last_error=87u;return XXEMUL_STATUS_OK;}
        if(flags&4u){
            uint64_t address=arg[1];
            if(address>=process->image_base && address-process->image_base<process->image_size)handle=process->image_base;
            else{
                for(index=0u;index<process->module_count;++index){win_module *candidate=&process->modules[index];
                    uint64_t size=candidate->real?candidate->image_size:WIN_MODULE_STRIDE;
                    if(candidate->live&&address>=candidate->base&&address-candidate->base<size){module=candidate;break;}}
                if(!module&&address>=process->runtime_base+WIN_THUNK_OFFSET&&
                   address-process->runtime_base-WIN_THUNK_OFFSET<process->api_count*WIN_THUNK_STRIDE){
                    size_t api_index=(size_t)((address-process->runtime_base-WIN_THUNK_OFFSET)/WIN_THUNK_STRIDE);
                    module=win_find_module(process,process->apis[api_index].module,0);
                }
            }
        }else if(!arg[1])handle=process->image_base;
        else{
            if(!win_guest_string(process,arg[1],text,sizeof(text),win_suffix(name,"W"))){process->last_error=998u;return XXEMUL_STATUS_OK;}
            if(win_main_program_name(process,text))handle=process->image_base;
            else if(!strchr(text,'/')&&!strchr(text,'\\'))module=win_find_module(process,text,0);
            else{char host[2048];
                if(win_guest_path(process,text,host,sizeof(host)))for(index=0u;index<process->module_count;++index){win_module *candidate=&process->modules[index];
                    if(candidate->live&&candidate->real&&win_equal(candidate->file_path,host)){module=candidate;break;}}
                if(!module&&(win_prefix(text,"C:\\Windows\\System32\\")||win_prefix(text,"C:/Windows/System32/"))){
                    win_module *candidate=win_find_module(process,text,0);if(candidate&&!candidate->real)module=candidate;
                }
            }
        }
        if(module){
            if(module->real && !(flags&2u)){
                if(!module->references){process->last_error=1115u;return XXEMUL_STATUS_OK;}
                if(flags&1u)module->references=UINT32_MAX;
                else if(module->references!=UINT32_MAX){
                    if(module->references==UINT32_MAX-1u){process->last_error=8u;return XXEMUL_STATUS_OK;}
                    ++module->references;
                }
            }
            handle=module->base;
        }
        if(!handle){process->last_error=126u;return XXEMUL_STATUS_OK;}
        (void)win_store(process,arg[2],word_size,handle);*result=1u;return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "GetProcAddress") == 0) {
        win_module *real_module=win_dll_at(process,arg[0]);
        const char *module = win_module_name(process, arg[0]);
        if(real_module&&real_module->real){
            if(arg[1]<0x10000u)snprintf(text,sizeof(text),"#%u",(unsigned)arg[1]);
            else if(!win_guest_string(process,arg[1],text,sizeof(text),0))return XXEMUL_STATUS_ADDRESS_FAULT;
            *result=win_dll_export(process,real_module,text,0u,arg[1]<0x10000u);
            if(!*result)process->last_error=127u;
            return XXEMUL_STATUS_OK;
        }
        if (module != NULL && arg[1] >= 0x10000u) {
            size_t export_index;
            int available;
            if (!win_guest_string(process, arg[1], text, sizeof(text), 0)) return XXEMUL_STATUS_ADDRESS_FAULT;
            if (text[0] == '\0' || win_suffix(text, ".dll") || win_suffix(text, ".exe")) {
                process->last_error = 127u;
                return XXEMUL_STATUS_OK;
            }
            /* Lazy thunks permit importing APIs that the guest never calls.
             * An executed unsupported API is reported by the dispatcher.
             * CRT modules must still reject Windows-only function names. */
            available = !win_equal(module, "msvcrt.dll") && !win_equal(module, "ucrtbase.dll") && !win_prefix(module, "api-ms-win-crt-");
            if (win_find_module(process, module, 1) != NULL) {
                for (export_index = 0u; export_index < process->api_count; ++export_index)
                    if (win_equal(process->apis[export_index].module, module) && strcmp(process->apis[export_index].name, text) == 0) available = 1;
                if (win_crt_api(text) && win_export_for_module(module, text)) available = 1;
                if (available) *result = win_resolve(process, module, text);
            }
        }
        if (module != NULL && arg[1] < 0x10000u && win_equal(module, "oleaut32.dll")) {
            const char *ordinal_name = win_oleaut32_ordinal_name((uint16_t)arg[1]);
            if (ordinal_name != NULL) *result = win_resolve(process, module, ordinal_name);
        }
        if (*result == 0) process->last_error = 127u;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "GetPrivateProfileIntA") == 0 || strcmp(name, "GetPrivateProfileStringA") == 0)
        return win_private_profile(process, arg, strcmp(name, "GetPrivateProfileIntA") == 0, result);
    if (strcmp(name, "_except_handler3") == 0) {
        /* Its export is required during genuine producer import bootstrap.
         * The CRT scope-table interpreter is not yet modeled. An actual
         * exception call must remain explicit, never a fabricated disposition. */
        return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    }
    if (strcmp(name, "_controlfp") == 0) {
        uint16_t raw = process->emulator->x87_control;
        uint32_t current = ((raw & 1u) ? 0x10u : 0u) | ((raw & 2u) ? 0x80000u : 0u) |
            ((raw & 4u) ? 8u : 0u) | ((raw & 8u) ? 4u : 0u) |
            ((raw & 16u) ? 2u : 0u) | ((raw & 32u) ? 1u : 0u) |
            ((uint32_t)(raw & 0xc00u) >> 2u) | ((raw & 0x1000u) ? 0x40000u : 0u);
        uint32_t precision = (raw >> 8u) & 3u;
        uint32_t mask = (uint32_t)arg[1] & 0x7031fu;
        uint32_t updated;
        /* x64 _controlfp controls MXCSR. There is no MXCSR model here. */
        if (word_size != 4u) return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
        current |= precision == 0u ? 0x20000u : precision == 2u ? 0x10000u : 0u;
        updated = (current & ~mask) | ((uint32_t)arg[0] & mask);
        precision = updated & 0x30000u;
        if (precision == 0x30000u) return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
        raw = (uint16_t)((raw & ~UINT16_C(0x1f3d)) |
            ((updated & 0x10u) ? 1u : 0u) | ((updated & 8u) ? 4u : 0u) |
            ((updated & 4u) ? 8u : 0u) | ((updated & 2u) ? 16u : 0u) |
            ((updated & 1u) ? 32u : 0u) | ((updated & 0x300u) << 2u) |
            ((updated & 0x40000u) ? 0x1000u : 0u) |
            (precision == 0u ? 0x300u : precision == 0x10000u ? 0x200u : 0u));
        process->emulator->x87_control = raw;
        *result = updated;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "FindFirstFileA") == 0 || strcmp(name, "FindFirstFileW") == 0 || strcmp(name, "FindFirstFileExW") == 0)
        return win_find_first(process, arg, win_suffix(name, "W"), strcmp(name, "FindFirstFileExW") == 0, result);
    if (strcmp(name, "FindNextFileA") == 0 || strcmp(name, "FindNextFileW") == 0)
        return win_find_next(process, arg, win_suffix(name, "W"), result);
    if (strcmp(name, "FindClose") == 0) {
        win_handle *handle = win_handle_at(process, arg[0]);
        if (!handle || handle->kind != WIN_HANDLE_FIND) process->last_error = 6u;
        else *result = win_close_handle(process, arg[0]);
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "_lopen") == 0) return win_legacy_open(process, arg, result);
    if (strcmp(name, "_lread") == 0) return win_legacy_read(process, arg, result);
    if (strcmp(name, "_llseek") == 0) {
        win_handle *handle = win_handle_at(process, arg[0]);
        int64_t position;
        *result = UINT32_MAX;
        if (!handle || handle->kind != WIN_HANDLE_FILE || !handle->io) { process->last_error = 6u; return XXEMUL_STATUS_OK; }
        if (arg[2] > 2u) { process->last_error = 87u; return XXEMUL_STATUS_OK; }
        position = xx_io_seek64(handle->io, (int32_t)arg[1], (int)arg[2]) == 0 ? xx_io_tell(handle->io) : -1;
        if (position < 0 || position > INT32_MAX) process->last_error = 87u;
        else *result = (uint32_t)position;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "_lclose") == 0) {
        win_handle *handle = win_handle_at(process, arg[0]);
        *result = UINT32_MAX;
        if (!handle || handle->kind != WIN_HANDLE_FILE || !handle->io) process->last_error = 6u;
        else if (win_close_handle(process, arg[0])) *result = 0u;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "_lcreat") == 0) return win_legacy_create(process, arg, result);
    if (strcmp(name, "_lwrite") == 0) return win_legacy_write(process, arg, result);
    if (strcmp(name, "GetLocaleInfoA") == 0 || strcmp(name, "GetLocaleInfoW") == 0)
        return win_locale_info(process, arg, win_suffix(name, "W"), result);
    if (strcmp(name, "__getmainargs") == 0) {
        if (arg[0] == 0u || arg[1] == 0u || arg[2] == 0u) {
            process->last_error = 87u;
            *result = UINT32_MAX;
            return XXEMUL_STATUS_OK;
        }
        if (!win_store(process, arg[0], 4u, process->argc) || !win_store(process, arg[1], word_size, process->argv_address) ||
            !win_store(process, arg[2], word_size, process->envp_address))
            return XXEMUL_STATUS_ADDRESS_FAULT;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "__p___initenv") == 0) *result = win_data_address(process, 1u);
    else if (strcmp(name, "__p__acmdln") == 0) *result = process->runtime_base + WIN_CRT_DATA_OFFSET + 16u;
    else if (strcmp(name, "__p__commode") == 0) *result = process->runtime_base + WIN_CRT_DATA_OFFSET + 24u;
    else if (strcmp(name, "__p__fmode") == 0) *result = process->runtime_base + WIN_CRT_DATA_OFFSET + 28u;
    else if (strcmp(name, "__p___argc") == 0) *result = process->runtime_base + WIN_CRT_DATA_OFFSET + 40u;
    else if (strcmp(name, "__p___argv") == 0) *result = process->runtime_base + WIN_CRT_DATA_OFFSET + 48u;
    else if (strcmp(name, "__p__environ") == 0) *result = process->runtime_base + WIN_CRT_DATA_OFFSET;
    if (strcmp(name, "__p___initenv") == 0 || strcmp(name, "__p__acmdln") == 0 || strcmp(name, "__p__commode") == 0 || strcmp(name, "__p__fmode") == 0 || strcmp(name, "__p___argc") == 0 ||
        strcmp(name, "__p___argv") == 0 || strcmp(name, "__p__environ") == 0)
        return XXEMUL_STATUS_OK;
    if (strcmp(name, "__set_app_type") == 0 || strcmp(name, "_set_app_type") == 0) {
        process->app_type = (uint32_t)arg[0];
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "_set_invalid_parameter_handler") == 0) {
        *result = 0u;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "_initialize_narrow_environment") == 0) {
        *result = 0u;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "_configure_narrow_argv") == 0) {
        *result = 0u;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "_crt_atexit") == 0 || strcmp(name, "atexit") == 0) {
        if (arg[0] != 0u && process->onexit_count < WIN_MAX_ONEXIT) {
            process->onexit_callbacks[process->onexit_count++] = arg[0];
        }
        *result = 0u;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "_configthreadlocale") == 0) {
        *result = 0u;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "_set_new_mode") == 0) {
        *result = 0u;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "_lock_file") == 0 || strcmp(name, "_unlock_file") == 0) {
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "__acrt_iob_func") == 0) {
        uint64_t stride = word_size == 8u ? 48u : 32u;
        *result = process->iob_address + arg[0] * stride;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "sprintf") == 0 || strcmp(name, "vsprintf") == 0 ||
        strcmp(name, "wsprintfA") == 0 || strcmp(name, "wsprintfW") == 0 ||
        strcmp(name, "wvsprintfA") == 0 || strcmp(name, "wvsprintfW") == 0) {
        int wide = win_suffix(name, "W");
        int valist = strcmp(name, "vsprintf") == 0 || win_prefix(name, "wvsprintf");
        win_format_args arguments = {valist ? arg[2] : 0u, 2u, !valist};
        size_t limit = win_prefix(name, "w") ? 1024u / (wide ? 2u : 1u) : WIN_MAX_IO;
        return win_format_result(process, arg[0], arg[1], wide, &arguments, limit, result);
    }
    if (strcmp(name, "printf") == 0 || strcmp(name, "fprintf") == 0) {
        int explicit_stream = strcmp(name, "fprintf") == 0;
        win_format_args arguments = {0u, explicit_stream ? 2u : 1u, 1};
        uint64_t stride = word_size == 8u ? 48u : 32u;
        return win_stdio_format(process, explicit_stream ? arg[0] : process->iob_address + stride,
                                arg[explicit_stream ? 1u : 0u], &arguments, result);
    }
    if (strcmp(name, "__stdio_common_vfprintf") == 0) {
        return win_stdio_vfprintf(process, arg[1], arg[2], arg[4], result);
    }
    if (strcmp(name, "vfprintf") == 0) {
        return win_stdio_vfprintf(process, arg[0], arg[1], arg[2], result);
    }
    if (strcmp(name, "putc") == 0 || strcmp(name, "fputc") == 0) {
        return win_crt_fputc(process, (uint8_t)arg[0], arg[1], result);
    }
    if (strcmp(name, "perror") == 0) {
        char *msg = NULL;
        size_t mlen = 0;
        if (arg[0] != 0 && win_crt_read_string(process, arg[0], &msg, &mlen) == XXEMUL_STATUS_OK && msg != NULL) {
            fprintf(stderr, "%s: error\n", msg);
            free(msg);
        }
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "strerror") == 0) {
        char *err_msg = strerror((int)arg[0]);
        if (err_msg == NULL) err_msg = "Unknown error";
        size_t elen = strlen(err_msg);
        uint64_t err_buf = process->runtime_base + WIN_CRT_DATA_OFFSET + 128u;
        win_write(process, err_buf, err_msg, elen + 1);
        *result = err_buf;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "fopen") == 0 || strcmp(name, "_wfopen") == 0) {
        char fn[1024];
        char md[64];
        int w = strcmp(name, "_wfopen") == 0;
        int s1 = win_guest_string(process, arg[0], fn, sizeof(fn), w);
        int s2 = win_guest_string(process, arg[1], md, sizeof(md), w);
        if (!s1 || !s2) {
            *result = 0;
            return XXEMUL_STATUS_OK;
        }
        *result = win_crt_fopen(process, fn, md);
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "fclose") == 0) {
        uint64_t stride = word_size == 8u ? 48u : 32u;
        uint64_t stream = arg[0];
        uint64_t offset = stream >= process->iob_address ? (stream - process->iob_address) : UINT64_MAX;
        if (offset < (uint64_t)WIN_MAX_CRT_FDS * stride && offset % stride == 0u) {
            size_t fd = (size_t)(offset / stride);
            if (fd >= 3u && process->crt_fd_handles[fd] != 0u) {
                win_close_handle(process, process->crt_fd_handles[fd]);
                process->crt_fd_handles[fd] = 0u;
                process->crt_fd_eof[fd] = 0;
            }
        }
        *result = 0;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "fwrite") == 0) {
        uint64_t stride = word_size == 8u ? 48u : 32u;
        uint64_t stream = arg[3];
        uint64_t total = arg[1] * arg[2];
        if (total == 0) {
            *result = 0;
            return XXEMUL_STATUS_OK;
        }
        if (stream == process->iob_address || stream == process->iob_address + stride || stream == process->iob_address + 2u * stride) {
            FILE *tgt = (stream == process->iob_address + 2u * stride) ? stderr : stdout;
            uint8_t buf[2048];
            uint64_t done = 0;
            while (done < total) {
                size_t chunk = (size_t)(total - done);
                if (chunk > sizeof(buf)) chunk = sizeof(buf);
                if (!win_read(process, arg[0] + done, buf, chunk)) break;
                if (process->emulator->output_callback != NULL) {
                    size_t k;
                    for (k = 0; k < chunk; ++k) process->emulator->output_callback(process->emulator->output_context, buf[k]);
                } else {
                    fwrite(buf, 1, chunk, tgt);
                }
                done += chunk;
            }
            if (process->emulator->output_callback == NULL) fflush(tgt);
            *result = arg[1] > 0 ? (done / arg[1]) : 0;
            return XXEMUL_STATUS_OK;
        } else {
            uint64_t offset = stream >= process->iob_address ? (stream - process->iob_address) : UINT64_MAX;
            if (offset < (uint64_t)WIN_MAX_CRT_FDS * stride && offset % stride == 0u) {
                size_t fd = (size_t)(offset / stride);
                process->crt_fd_eof[fd] = 0;
                uint64_t handle = win_crt_handle(process, fd);
                xx_io_device *opened = win_handle_io(process, handle);
                if (opened != NULL) {
                    uint8_t buf[4096];
                    uint64_t done = 0;
                    while (done < total) {
                        size_t chunk = (size_t)(total - done);
                        if (chunk > sizeof(buf)) chunk = sizeof(buf);
                        if (!win_read(process, arg[0] + done, buf, chunk)) break;
                        xx_io_write(opened, buf, chunk);
                        done += chunk;
                    }
                    *result = arg[1] > 0 ? (done / arg[1]) : 0;
                    return XXEMUL_STATUS_OK;
                }
            }
        }
        *result = 0;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "fread") == 0) {
        uint64_t stride = word_size == 8u ? 48u : 32u;
        uint64_t stream = arg[3];
        uint64_t total = arg[1] * arg[2];
        if (total == 0) {
            *result = 0;
            return XXEMUL_STATUS_OK;
        }
        uint64_t offset = stream >= process->iob_address ? (stream - process->iob_address) : UINT64_MAX;
        if (offset < (uint64_t)WIN_MAX_CRT_FDS * stride && offset % stride == 0u) {
            size_t fd = (size_t)(offset / stride);
            uint64_t handle = win_crt_handle(process, fd);
            xx_io_device *opened = win_handle_io(process, handle);
            if (opened != NULL) {
                uint8_t buf[4096];
                uint64_t done = 0;
                while (done < total) {
                    size_t chunk = (size_t)(total - done);
                    if (chunk > sizeof(buf)) chunk = sizeof(buf);
                    int64_t r = xx_io_read(opened, buf, chunk);
                    if (r <= 0) {
                        process->crt_fd_eof[fd] = 1;
                        break;
                    }
                    if (!win_write(process, arg[0] + done, buf, (size_t)r)) break;
                    done += (size_t)r;
                    if ((size_t)r < chunk) {
                        process->crt_fd_eof[fd] = 1;
                        break;
                    }
                }
                *result = arg[1] > 0 ? (done / arg[1]) : 0;
                return XXEMUL_STATUS_OK;
            }
        }
        *result = 0;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "fgetc") == 0 || strcmp(name, "getc") == 0 || strcmp(name, "getchar") == 0) {
        uint64_t stride = word_size == 8u ? 48u : 32u;
        uint64_t stream = strcmp(name, "getchar") == 0 ? process->iob_address : arg[0];
        uint64_t offset = stream >= process->iob_address ? (stream - process->iob_address) : UINT64_MAX;
        if (offset < (uint64_t)WIN_MAX_CRT_FDS * stride && offset % stride == 0u) {
            size_t fd = (size_t)(offset / stride);
            uint64_t handle = win_crt_handle(process, fd);
            xx_io_device *opened = win_handle_io(process, handle);
            if (opened != NULL) {
                uint8_t b = 0;
                if (xx_io_read(opened, &b, 1) == 1) {
                    *result = (uint64_t)b;
                    return XXEMUL_STATUS_OK;
                }
                process->crt_fd_eof[fd] = 1;
            }
        }
        *result = UINT64_MAX;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "fgets") == 0) {
        uint64_t stride = word_size == 8u ? 48u : 32u;
        uint64_t stream = arg[2];
        int count = (int)arg[1];
        if (count <= 1 || arg[0] == 0) {
            *result = 0;
            return XXEMUL_STATUS_OK;
        }
        uint64_t offset = stream >= process->iob_address ? (stream - process->iob_address) : UINT64_MAX;
        if (offset < (uint64_t)WIN_MAX_CRT_FDS * stride && offset % stride == 0u) {
            size_t fd = (size_t)(offset / stride);
            uint64_t handle = win_crt_handle(process, fd);
            xx_io_device *opened = win_handle_io(process, handle);
            if (opened != NULL) {
                int i;
                for (i = 0; i < count - 1; ++i) {
                    uint8_t b = 0;
                    if (xx_io_read(opened, &b, 1) != 1) {
                        process->crt_fd_eof[fd] = 1;
                        if (i == 0) {
                            *result = 0;
                            return XXEMUL_STATUS_OK;
                        }
                        break;
                    }
                    win_store(process, arg[0] + (uint64_t)i, 1u, b);
                    if (b == '\n') {
                        i++;
                        break;
                    }
                }
                win_store(process, arg[0] + (uint64_t)i, 1u, 0);
                *result = arg[0];
                return XXEMUL_STATUS_OK;
            }
        }
        *result = 0;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "feof") == 0) {
        uint64_t stride = word_size == 8u ? 48u : 32u;
        uint64_t stream = arg[0];
        uint64_t offset = stream >= process->iob_address ? (stream - process->iob_address) : UINT64_MAX;
        if (offset < (uint64_t)WIN_MAX_CRT_FDS * stride && offset % stride == 0u) {
            size_t fd = (size_t)(offset / stride);
            *result = (uint64_t)process->crt_fd_eof[fd];
            return XXEMUL_STATUS_OK;
        }
        *result = 0;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "clearerr") == 0) {
        uint64_t stride = word_size == 8u ? 48u : 32u;
        uint64_t stream = arg[0];
        uint64_t offset = stream >= process->iob_address ? (stream - process->iob_address) : UINT64_MAX;
        if (offset < (uint64_t)WIN_MAX_CRT_FDS * stride && offset % stride == 0u) {
            size_t fd = (size_t)(offset / stride);
            process->crt_fd_eof[fd] = 0;
        }
        *result = 0;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "ferror") == 0 || strcmp(name, "setvbuf") == 0) {
        *result = 0;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "ungetc") == 0) {
        uint64_t stride = word_size == 8u ? 48u : 32u;
        uint64_t stream = arg[1];
        if ((int32_t)arg[0] == -1) {
            *result = UINT32_MAX;
            return XXEMUL_STATUS_OK;
        }
        uint64_t offset = stream >= process->iob_address ? (stream - process->iob_address) : UINT64_MAX;
        if (offset < (uint64_t)WIN_MAX_CRT_FDS * stride && offset % stride == 0u) {
            size_t fd = (size_t)(offset / stride);
            uint64_t handle = win_crt_handle(process, fd);
            xx_io_device *opened = win_handle_io(process, handle);
            if (opened != NULL) {
                if (xx_io_seek64(opened, -1, SEEK_CUR) == 0) {
                    process->crt_fd_eof[fd] = 0;
                    *result = (uint8_t)arg[0];
                    return XXEMUL_STATUS_OK;
                }
            }
        }
        *result = UINT32_MAX;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "_setmode") == 0) {
        *result = 0x8000; /* _O_BINARY */
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "_fseeki64") == 0 || strcmp(name, "fseek") == 0) {
        uint64_t stride = word_size == 8u ? 48u : 32u;
        uint64_t stream = arg[0];
        uint64_t offset = stream >= process->iob_address ? (stream - process->iob_address) : UINT64_MAX;
        if (offset < (uint64_t)WIN_MAX_CRT_FDS * stride && offset % stride == 0u) {
            size_t fd = (size_t)(offset / stride);
            uint64_t handle = win_crt_handle(process, fd);
            xx_io_device *opened = win_handle_io(process, handle);
            if (opened != NULL) {
                int whence = arg[2] == 0 ? SEEK_SET : arg[2] == 1 ? SEEK_CUR : SEEK_END;
                int64_t seek_off = (strcmp(name, "fseek") == 0) ? (int64_t)(int32_t)arg[1] : (int64_t)arg[1];
                process->crt_fd_eof[fd] = 0;
                *result = (uint64_t)xx_io_seek64(opened, seek_off, whence);
                return XXEMUL_STATUS_OK;
            }
        }
        *result = UINT64_MAX;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "_ftelli64") == 0 || strcmp(name, "ftell") == 0) {
        uint64_t stride = word_size == 8u ? 48u : 32u;
        uint64_t stream = arg[0];
        uint64_t offset = stream >= process->iob_address ? (stream - process->iob_address) : UINT64_MAX;
        if (offset < (uint64_t)WIN_MAX_CRT_FDS * stride && offset % stride == 0u) {
            size_t fd = (size_t)(offset / stride);
            uint64_t handle = win_crt_handle(process, fd);
            xx_io_device *opened = win_handle_io(process, handle);
            if (opened != NULL) {
                int64_t pos = xx_io_tell(opened);
                if (strcmp(name, "ftell") == 0) {
                    *result = (pos < 0) ? UINT32_MAX : (uint32_t)pos;
                } else {
                    *result = (pos < 0) ? UINT64_MAX : (uint64_t)pos;
                }
                return XXEMUL_STATUS_OK;
            }
        }
        *result = UINT64_MAX;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "_fullpath") == 0) {
        char rel[1024];
        char abs_path[2048];
        size_t maxlen = (size_t)arg[2];
        if (!win_guest_string(process, arg[1], rel, sizeof(rel), 0)) return XXEMUL_STATUS_ADDRESS_FAULT;
        char host_rel[2048];
        win_guest_path(process, rel, host_rel, sizeof(host_rel));
#if defined(_WIN32)
        if (_fullpath(abs_path, host_rel, sizeof(abs_path)) == NULL) {
            *result = 0;
            return win_crt_errno(process, 2u);
        }
#else
        if (realpath(host_rel, abs_path) == NULL) {
            *result = 0;
            return win_crt_errno(process, 2u);
        }
#endif
        size_t alen = strlen(abs_path);
        uint64_t out_addr = arg[0];
        if (out_addr == 0) {
            out_addr = win_heap_alloc(process, alen + 1);
            if (out_addr == 0) return win_crt_errno(process, 12u);
        } else if (alen >= maxlen) {
            *result = 0;
            return win_crt_errno(process, 34u);
        }
        win_write(process, out_addr, abs_path, alen + 1);
        *result = out_addr;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "_wstat64") == 0) {
        char host_path[2048];
        if (!win_guest_string(process, arg[0], text, sizeof(text), 1)) return XXEMUL_STATUS_ADDRESS_FAULT;
        if (!win_guest_path(process, text, host_path, sizeof(host_path))) {
            *result = UINT32_MAX;
            return win_crt_errno(process, 2u);
        }
        return win_crt_store_stat(process, host_path, arg[1], 8u, result);
    }
    if (strcmp(name, "_waccess") == 0) {
        char host_path[2048];
        if (!win_guest_string(process, arg[0], text, sizeof(text), 1)) return XXEMUL_STATUS_ADDRESS_FAULT;
        if (!win_guest_path(process, text, host_path, sizeof(host_path))) {
            *result = UINT32_MAX;
            return win_crt_errno(process, 2u);
        }
#if defined(_WIN32)
        int acc = _access(host_path, (int)arg[1]);
#else
        int acc = access(host_path, (int)arg[1]);
#endif
        if (acc != 0) {
            *result = UINT32_MAX;
            return win_crt_errno(process, 2u);
        }
        *result = 0;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "remove") == 0) {
        char host_path[2048];
        if (!win_guest_string(process, arg[0], text, sizeof(text), 0)) return XXEMUL_STATUS_ADDRESS_FAULT;
        if (!win_guest_path(process, text, host_path, sizeof(host_path))) {
            *result = UINT32_MAX;
            return win_crt_errno(process, 2u);
        }
        if (remove(host_path) != 0) {
            *result = UINT32_MAX;
            return win_crt_errno(process, 2u);
        }
        *result = 0;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "_filelength") == 0 || strcmp(name, "_filelengthi64") == 0) {
        uint64_t handle = win_crt_handle(process, (uint32_t)arg[0]);
        xx_io_device *opened = win_handle_io(process, handle);
        int64_t length = opened != NULL ? xx_io_total_size(opened) : -1;
        int extended = strcmp(name, "_filelengthi64") == 0;
        uint32_t error = opened == NULL ? 9u : length < 0 ? 5u :
                         (!extended && length > INT32_MAX) ? 132u : 0u;
        *result = error ? (extended ? UINT64_MAX : UINT32_MAX) : (uint64_t)length;
        if (extended && word_size == 4u)
            process->emulator->x86.gpr[XXEMUL_X86_RDX] = (uint32_t)(*result >> 32u);
        return error ? win_crt_errno(process, error) : XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "_chsize") == 0 || strcmp(name, "_chsize_s") == 0) {
        int secure = strcmp(name, "_chsize_s") == 0;
        int64_t length = secure ? (word_size == 8u ? (int64_t)arg[1] :
            (int64_t)((uint64_t)(uint32_t)arg[1] | ((uint64_t)(uint32_t)arg[2] << 32u))) : (int32_t)arg[1];
        uint64_t handle = win_crt_handle(process, (uint32_t)arg[0]);
        win_handle *entry = win_handle_at(process, handle);
        uint32_t error = length < 0 ? 22u :
            entry == NULL || entry->kind != WIN_HANDLE_FILE ? 9u :
            !(entry->file_access & (UINT32_C(0x40000000) | UINT32_C(0x10000000))) ? (secure ? 9u : 13u) : 0u;
        if (error == 0u && xx_io_resize(entry->io, length) != 0)
            error = errno == ENOSPC ? 28u : errno == EACCES || errno == EPERM ? 13u : 5u;
        *result = error ? (secure ? error : UINT32_MAX) : 0u;
        return error ? win_crt_errno(process, error) : XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "_access") == 0) {
        char host_path[2048];
        uint32_t mode = (uint32_t)arg[1];
        uint32_t error = 0u;
        if ((mode & ~6u) != 0u) error = 22u;
        else if (arg[0] == 0u) error = 22u;
        else {
            if (!win_guest_string(process, arg[0], text, sizeof(text), 0)) return XXEMUL_STATUS_ADDRESS_FAULT;
            if (!win_guest_path(process, text, host_path, sizeof(host_path))) error = 2u;
            else {
#if defined(_WIN32)
                int checked = _access(host_path, (int)mode);
                if (checked != 0) error = errno == EACCES || errno == EPERM ? 13u : 2u;
#else
                struct stat attributes;
                if (stat(host_path, &attributes) != 0) error = errno == EACCES || errno == EPERM ? 13u : 2u;
                /* Windows _access checks the read-only attribute, not ACLs.
                 * The mapped file's write mode bits model that attribute. */
                else if (!S_ISDIR(attributes.st_mode) && (mode & 2u) &&
                    !(attributes.st_mode & (S_IWUSR | S_IWGRP | S_IWOTH))) error = 13u;
#endif
            }
        }
        *result = error ? UINT32_MAX : 0u;
        return error ? win_crt_errno(process, error) : XXEMUL_STATUS_OK;
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
    if (strcmp(name, "_time64") == 0 || strcmp(name, "time") == 0) {
        time_t now = time(NULL);
        uint8_t result_size = strcmp(name, "_time64") == 0 ? 8u : 4u;
        *result = now == (time_t)-1 ? UINT64_MAX : (uint64_t)now;
        if (arg[0] != 0u && !win_store(process, arg[0], result_size, *result)) return XXEMUL_STATUS_ADDRESS_FAULT;
        if (word_size == 4u && result_size == 8u) process->emulator->x86.gpr[XXEMUL_X86_RDX] = (uint32_t)(*result >> 32u);
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "_localtime64") == 0 || strcmp(name, "localtime") == 0 || strcmp(name, "_gmtime64") == 0 || strcmp(name, "gmtime") == 0) {
        uint64_t tval = 0;
        time_t tt;
        struct tm t_res_buf;
        struct tm *t_res = NULL;
        uint64_t tm_buf = process->runtime_base + WIN_CRT_DATA_OFFSET + 64u;
        uint8_t t_size = (strcmp(name, "_localtime64") == 0 || strcmp(name, "_gmtime64") == 0) ? 8u : 4u;
        if (arg[0] == 0 || !win_load(process, arg[0], t_size, &tval)) {
            *result = 0;
            return XXEMUL_STATUS_OK;
        }
        tt = (time_t)tval;
        memset(&t_res_buf, 0, sizeof(t_res_buf));
#if defined(_MSC_VER)
        if (strcmp(name, "_gmtime64") == 0 || strcmp(name, "gmtime") == 0) {
            if (_gmtime64_s(&t_res_buf, &tt) != 0) {
                *result = 0;
                return XXEMUL_STATUS_OK;
            }
        } else {
            if (_localtime64_s(&t_res_buf, &tt) != 0) {
                *result = 0;
                return XXEMUL_STATUS_OK;
            }
        }
        t_res = &t_res_buf;
#else
        if (strcmp(name, "_gmtime64") == 0 || strcmp(name, "gmtime") == 0) {
            t_res = gmtime_r(&tt, &t_res_buf);
        } else {
            t_res = localtime_r(&tt, &t_res_buf);
        }
        if (t_res == NULL) {
            *result = 0;
            return XXEMUL_STATUS_OK;
        }
#endif
        win_store(process, tm_buf + 0u, 4u, (uint32_t)t_res->tm_sec);
        win_store(process, tm_buf + 4u, 4u, (uint32_t)t_res->tm_min);
        win_store(process, tm_buf + 8u, 4u, (uint32_t)t_res->tm_hour);
        win_store(process, tm_buf + 12u, 4u, (uint32_t)t_res->tm_mday);
        win_store(process, tm_buf + 16u, 4u, (uint32_t)t_res->tm_mon);
        win_store(process, tm_buf + 20u, 4u, (uint32_t)t_res->tm_year);
        win_store(process, tm_buf + 24u, 4u, (uint32_t)t_res->tm_wday);
        win_store(process, tm_buf + 28u, 4u, (uint32_t)t_res->tm_yday);
        win_store(process, tm_buf + 32u, 4u, (uint32_t)t_res->tm_isdst);
        *result = tm_buf;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "strftime") == 0) {
        char *fmt = NULL;
        size_t flen = 0;
        uint64_t tm_addr = arg[3];
        struct tm t_val;
        char s_buf[1024];
        size_t written = 0;
        uint64_t fld;
        memset(&t_val, 0, sizeof(t_val));
        if (tm_addr != 0) {
            win_load(process, tm_addr + 0u, 4u, &fld);
            t_val.tm_sec = (int)fld;
            win_load(process, tm_addr + 4u, 4u, &fld);
            t_val.tm_min = (int)fld;
            win_load(process, tm_addr + 8u, 4u, &fld);
            t_val.tm_hour = (int)fld;
            win_load(process, tm_addr + 12u, 4u, &fld);
            t_val.tm_mday = (int)fld;
            win_load(process, tm_addr + 16u, 4u, &fld);
            t_val.tm_mon = (int)fld;
            win_load(process, tm_addr + 20u, 4u, &fld);
            t_val.tm_year = (int)fld;
            win_load(process, tm_addr + 24u, 4u, &fld);
            t_val.tm_wday = (int)fld;
            win_load(process, tm_addr + 28u, 4u, &fld);
            t_val.tm_yday = (int)fld;
            win_load(process, tm_addr + 32u, 4u, &fld);
            t_val.tm_isdst = (int)fld;
        }
        if (win_crt_read_string(process, arg[2], &fmt, &flen) == XXEMUL_STATUS_OK && fmt != NULL) {
            written = strftime(s_buf, sizeof(s_buf), fmt, &t_val);
            if (written > 0 && arg[0] != 0 && arg[1] > 0) {
                if (written >= arg[1]) written = arg[1] - 1;
                win_write(process, arg[0], s_buf, written + 1);
            }
            free(fmt);
        }
        *result = (uint64_t)written;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "clock") == 0) {
        clock_t ticks = clock();
        if (ticks == (clock_t)-1) *result = UINT32_MAX;
        else *result = (uint32_t)((uint64_t)ticks * 1000u / (uint64_t)CLOCKS_PER_SEC);
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "srand") == 0) {
        process->random_state = (uint32_t)arg[0];
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "rand") == 0) {
        process->random_state = process->random_state * UINT32_C(214013) + UINT32_C(2531011);
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
        if (arg[0] < WIN_MAX_CRT_FDS && process->crt_fd_handles[arg[0]] != 0u) {
            *result = 0u;
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
            if (offset < (uint64_t)WIN_MAX_CRT_FDS * stride && offset % stride == 0u) {
                size_t fd = (size_t)(offset / stride);
                if (fd < 3u || process->crt_fd_handles[fd] != 0u) {
                    *result = (uint32_t)fd;
                    return XXEMUL_STATUS_OK;
                }
            }
        }
        *result = UINT32_MAX;
        return win_crt_errno(process, 9u);
    }
    if (strcmp(name, "fflush") == 0) {
        uint64_t stride = word_size == 8u ? 48u : 32u;
        uint64_t stream = arg[0];
        if (stream == 0u) {
            if (process->emulator->output_callback == NULL && (fflush(stdout) != 0 || fflush(stderr) != 0)) {
                *result = UINT32_MAX;
                return win_crt_errno(process, 9u);
            }
            return XXEMUL_STATUS_OK;
        }
        if (stream >= process->iob_address && stream - process->iob_address < (uint64_t)WIN_MAX_CRT_FDS * stride && (stream - process->iob_address) % stride == 0u) {
            uint64_t index = (stream - process->iob_address) / stride;
            if (index < 3u) {
                if (index != 0u && process->emulator->output_callback == NULL && fflush(index == 1u ? stdout : stderr) != 0) {
                    *result = UINT32_MAX;
                    return win_crt_errno(process, 9u);
                }
                return XXEMUL_STATUS_OK;
            }
            if (process->crt_fd_handles[index] != 0u) {
                *result = 0u;
                return XXEMUL_STATUS_OK;
            }
        }
        *result = UINT32_MAX;
        return win_crt_errno(process, 9u);
    }
    if (strcmp(name, "_open") == 0 || strcmp(name, "_sopen") == 0) {
        uint32_t flags = (uint32_t)arg[1];
        uint32_t access = (flags & 3u) == 2u ? 0xc0000000u : (flags & 3u) == 1u ? 0x40000000u : 0x80000000u;
        uint32_t disposition = (flags & 0x100u) != 0u ? (flags & 0x400u) != 0u ? 1u : (flags & 0x200u) != 0u ? 2u : 4u : (flags & 0x200u) != 0u ? 5u : 3u;
        uint64_t handle;
        size_t fd;
        if (!win_guest_string(process, arg[0], text, sizeof(text), 0)) return XXEMUL_STATUS_ADDRESS_FAULT;
        handle = win_file_open(process, text, access, disposition);
        if (handle == WIN_INVALID_HANDLE) {
            *result = UINT32_MAX;
            return win_crt_errno(process, process->last_error == 2u ? 2u : process->last_error == 4u ? 24u : 13u);
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
        if (count >= 0 && !win_write(process, arg[1], bytes, (size_t)count)) count = -1;
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
        if (handle == 0u || (arg[0] != 1u && arg[0] != 2u && opened == NULL)) {
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
            if (xxemul_emit_output(process->emulator, (int)arg[0], bytes, (size_t)arg[2])) {
                count = (ssize_t)arg[2];
            } else if (process->emulator->output_callback != NULL) {
                for (index = 0u; index < (size_t)arg[2]; ++index) process->emulator->output_callback(process->emulator->output_context, bytes[index]);
                count = (ssize_t)arg[2];
            } else {
                count = (ssize_t)fwrite(bytes, 1u, (size_t)arg[2], arg[0] == 1u ? stdout : stderr);
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
        if (handle == 0u || (arg[0] >= 3u && !win_close_handle(process, handle))) {
            *result = UINT32_MAX;
            return win_crt_errno(process, 9u);
        }
        if (arg[0] >= 3u) {
            process->crt_fd_handles[arg[0]] = 0u;
            process->crt_fd_eof[arg[0]] = 0;
        }
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "fputs") == 0) {
        char *str = NULL;
        size_t len = 0u;
        xxemul_status s = win_crt_read_string(process, arg[0], &str, &len);
        if (s != XXEMUL_STATUS_OK || str == NULL) return s;
        uint64_t stream = arg[1];
        uint64_t stride = word_size == 8u ? 48u : 32u;
        if (stream == process->iob_address || stream == process->iob_address + stride || stream == process->iob_address + 2u * stride) {
            FILE *target_file = (stream == process->iob_address + 2u * stride) ? stderr : stdout;
            if (process->emulator->output_callback != NULL) {
                size_t k;
                for (k = 0; k < len; ++k) process->emulator->output_callback(process->emulator->output_context, (uint8_t)str[k]);
            } else {
                fputs(str, target_file);
                fflush(target_file);
            }
        } else {
            uint64_t offset = stream >= process->iob_address ? (stream - process->iob_address) : UINT64_MAX;
            if (offset < (uint64_t)WIN_MAX_CRT_FDS * stride && offset % stride == 0u) {
                size_t fd = (size_t)(offset / stride);
                uint64_t handle = win_crt_handle(process, fd);
                xx_io_device *opened = win_handle_io(process, handle);
                if (opened != NULL) {
                    xx_io_write(opened, str, len);
                }
            }
        }
        free(str);
        *result = 0u;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "_lseeki64") == 0) {
        uint64_t handle = win_crt_handle(process, arg[0]);
        xx_io_device *opened = win_handle_io(process, handle);
        int64_t offset = word_size == 8u ? (int64_t)arg[1] : (int64_t)((uint64_t)(uint32_t)arg[1] | ((uint64_t)(uint32_t)arg[2] << 32u));
        uint64_t origin = word_size == 8u ? arg[2] : arg[3];
        int64_t position;
        int whence = origin == 0u ? SEEK_SET : origin == 1u ? SEEK_CUR : SEEK_END;
        if (opened == NULL || origin > 2u || xx_io_seek64(opened, offset, whence) != 0 || (position = xx_io_tell(opened)) < 0) {
            *result = UINT64_MAX;
            return win_crt_errno(process, opened == NULL ? 9u : 22u);
        }
        *result = (uint64_t)position;
        if (word_size == 4u) process->emulator->x86.gpr[XXEMUL_X86_RDX] = (uint32_t)(*result >> 32u);
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "_stati64") == 0 || strcmp(name, "_stat64") == 0) {
        char host_path[2048];
        if (!win_guest_string(process, arg[0], text, sizeof(text), 0)) return XXEMUL_STATUS_ADDRESS_FAULT;
        if (!win_guest_path(process, text, host_path, sizeof(host_path))) {
            *result = UINT32_MAX;
            return win_crt_errno(process, 2u);
        }
        return win_crt_store_stat(process, host_path, arg[1], strcmp(name, "_stat64") == 0 ? 8u : word_size, result);
    }
    if (strcmp(name, "_unlink") == 0) {
        char host_path[2048];
        if (!win_guest_string(process, arg[0], text, sizeof(text), 0)) return XXEMUL_STATUS_ADDRESS_FAULT;
        if (!win_guest_path(process, text, host_path, sizeof(host_path)) || win_equal(host_path, process->program_path)) {
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
        if (!win_guest_string(process, arg[0], text, sizeof(text), 0)) return XXEMUL_STATUS_ADDRESS_FAULT;
        if (!win_guest_path(process, text, host_path, sizeof(host_path)) || win_equal(host_path, process->program_path)) {
            *result = UINT32_MAX;
            return win_crt_errno(process, 13u);
        }
#if defined(_WIN32)
        success = _chmod(host_path, (int)(uint32_t)arg[1]) == 0;
#else
        struct stat attributes;
        success = stat(host_path, &attributes) == 0 && chmod(host_path, (attributes.st_mode & ~S_IWUSR) | (((uint32_t)arg[1] & 0x80u) != 0u ? S_IWUSR : 0u)) == 0;
#endif
        if (!success) {
            *result = UINT32_MAX;
            return win_crt_errno(process, errno == ENOENT ? 2u : errno == EACCES ? 13u : 22u);
        }
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "_fstati64") == 0 || strcmp(name, "_fstat64") == 0) {
        uint64_t handle = win_crt_handle(process, arg[0]);
        win_handle *entry = win_handle_at(process, handle);
        if (entry == NULL || entry->kind != WIN_HANDLE_FILE) {
            *result = UINT32_MAX;
            return win_crt_errno(process, 9u);
        }
        return win_crt_store_stat(process, entry->file_path, arg[1], strcmp(name, "_fstat64") == 0 ? 8u : word_size, result);
    }
    if (strcmp(name, "__lconv_init") == 0) return XXEMUL_STATUS_OK;
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
        *result = win_errno_address(process);
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "localeconv") == 0) {
        *result = process->runtime_base + WIN_CRT_LOCALE_OFFSET;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "setlocale") == 0) {
        if (arg[1] != 0u) {
            if (!win_guest_string(process, arg[1], text, sizeof(text), 0)) return XXEMUL_STATUS_ADDRESS_FAULT;
            if (strcmp(text, "C") != 0) return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
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
        entry->handle = process->runtime_base + WIN_VECTORED_HANDLE_OFFSET + process->vectored_handler_count * 16u;
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
    if (strcmp(name, "ExitProcess") == 0 || strcmp(name, "exit") == 0) {
        process->exit_code = (uint32_t)arg[0];
        process->emulator->exit_code = (uint8_t)arg[0];
        process->emulator->halted = 1;
        process->process_terminated = 1u;
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
        if (arg[0] >= base && arg[1] <= span && arg[0] - base <= span - arg[1] && win_store(process, arg[3], 4u, 0x40u)) *result = 1u;
        else process->last_error = 487u;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "CacheSync") == 0) {
        /* WinCE exposes this as a void API. ARM instructions are decoded
         * from current guest memory, so no instruction-cache work is needed. */
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "FlushInstructionCache") == 0) {
        uint64_t base = process->emulator->region_address;
        uint64_t span = process->emulator->region_size;
        if ((arg[1] == 0 && arg[2] == 0) || (arg[1] >= base && arg[2] <= span && arg[1] - base <= span - arg[2])) *result = 1;
        else process->last_error = 487u;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "VirtualAlloc") == 0) {
        if (arg[0] != 0) {
            uint64_t base = process->emulator->region_address;
            uint64_t span = process->emulator->region_size;
            if (arg[0] >= base && arg[1] <= span && arg[0] - base <= span - arg[1]) *result = arg[0];
        } else {
            *result = win_heap_alloc(process, arg[1]);
        }
        if (*result == 0) process->last_error = 8u;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "VirtualFree") == 0) {
        uint64_t base = process->emulator->region_address;
        *result = arg[0] >= base && arg[0] < base + process->emulator->region_size;
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
        if (query < base || query - base >= size || arg[2] < structure_size) {
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
        if (!win_write(process, arg[1], data, structure_size)) return XXEMUL_STATUS_ADDRESS_FAULT;
        *result = structure_size;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "CharNextA") == 0 || strcmp(name, "CharNextW") == 0) {
        uint64_t value;
        unsigned width = win_suffix(name, "W") ? 2u : 1u;
        if (!arg[0] || !win_load(process, arg[0], (uint8_t)width, &value)) return XXEMUL_STATUS_ADDRESS_FAULT;
        *result = arg[0] + (value ? width : 0u);
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "lstrlenA") == 0 || strcmp(name, "lstrlenW") == 0) {
        if (arg[0] == 0u) return XXEMUL_STATUS_OK;
        return win_crt_string_length(process, arg[0], win_suffix(name, "W") ? 2u : 1u, result);
    }
    if (strcmp(name, "lstrcpynA") == 0 || strcmp(name, "lstrcpynW") == 0) {
        int32_t count = (int32_t)arg[2];
        unsigned width = win_suffix(name, "W") ? 2u : 1u;
        uint64_t value = 0, index;
        if (count > (int32_t)(WIN_MAX_IO / width)) return XXEMUL_STATUS_INVALID_ARGUMENT;
        for (index = 0; count > 0 && index + 1u < (uint32_t)count; ++index) {
            if (!win_load(process, arg[1] + index * width, (uint8_t)width, &value) ||
                !win_store(process, arg[0] + index * width, (uint8_t)width, value)) return XXEMUL_STATUS_ADDRESS_FAULT;
            if (!value) break;
        }
        if (count > 0 && !win_store(process, arg[0] + index * width, (uint8_t)width, 0)) return XXEMUL_STATUS_ADDRESS_FAULT;
        *result = arg[0];
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "GetLongPathNameA") == 0 || strcmp(name, "GetLongPathNameW") == 0) {
        unsigned width = win_suffix(name, "W") ? 2u : 1u;
        uint64_t value, length = 0, index;
        do {
            if (length >= 4096u || !win_load(process, arg[0] + length * width, (uint8_t)width, &value)) return XXEMUL_STATUS_ADDRESS_FAULT;
            if (value) ++length;
        } while (value);
        *result = length + 1u;
        if (arg[2] <= length) return XXEMUL_STATUS_OK;
        for (index = 0; index <= length; ++index) {
            if (!win_load(process, arg[0] + index * width, (uint8_t)width, &value) ||
                !win_store(process, arg[1] + index * width, (uint8_t)width, value)) return XXEMUL_STATUS_ADDRESS_FAULT;
        }
        *result = length;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "LoadBitmapA") == 0 || strcmp(name, "DialogBoxParamA") == 0) {
        process->last_error = 120u; /* ERROR_CALL_NOT_IMPLEMENTED: no GDI/dialog model. */
        if (strcmp(name, "DialogBoxParamA") == 0) *result = UINT64_MAX;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "MessageBoxA") == 0 || strcmp(name, "MessageBoxW") == 0) {
        char message[1024], caption[256], line[1320];
        size_t index, length;
        int wide = win_suffix(name, "W");
        if (!win_guest_string(process, arg[1], message, sizeof(message), wide) ||
            !win_guest_string(process, arg[2], caption, sizeof(caption), wide)) return XXEMUL_STATUS_ADDRESS_FAULT;
        snprintf(line, sizeof(line), "[MessageBox] %s: %s\n", caption, message);
        length = strlen(line);
        if (xxemul_emit_output(process->emulator, 1, line, length)) {
            /* The public stream callback owns this output. */
        } else if (process->emulator->output_callback) {
            for (index = 0; index < length; ++index) process->emulator->output_callback(process->emulator->output_context, (uint8_t)line[index]);
        } else fputs(line, stdout);
        *result = (arg[3] & 15u) == 2u ? 3u : (arg[3] & 15u) == 3u || (arg[3] & 15u) == 4u ? 6u : (arg[3] & 15u) == 5u ? 4u : (arg[3] & 15u) == 6u ? 10u : 1u;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "GetLastError") == 0) {
        *result = process->last_error;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "SetLastError") == 0) {
        process->last_error = (uint32_t)arg[0];
        address = process->runtime_base + (word_size == 8u ? 0x68u : 0x34u);
        if (!win_store(process, address, 4u, arg[0])) return XXEMUL_STATUS_ADDRESS_FAULT;
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
    if (strcmp(name, "GetModuleFileNameA") == 0 || strcmp(name, "GetModuleFileNameW") == 0) {
        char path[1024];
        size_t length, copied;
        uint32_t capacity = (uint32_t)arg[2];
        wide = win_suffix(name, "W");
        if (!arg[0] || arg[0] == process->image_base) {
            if (!win_guest_program_path(process, path, sizeof(path))) { process->last_error = 206u; return XXEMUL_STATUS_OK; }
        } else {
            const char *module = win_module_name(process, arg[0]);
            if (!module) { process->last_error = 126u; return XXEMUL_STATUS_OK; }
            win_module *real_module=win_dll_at(process,arg[0]);
            if(real_module&&real_module->real){
                char root[2048];const char *relative;size_t path_index,root_length;
                if(!win_working_root(process,root,sizeof(root))){process->last_error=3u;return XXEMUL_STATUS_OK;}
                root_length=strlen(root);while(root_length>1u&&root[root_length-1u]=='/')--root_length;
                if(strncmp(real_module->file_path,root,root_length) ||
                   (real_module->file_path[root_length] && real_module->file_path[root_length]!='/')){process->last_error=5u;return XXEMUL_STATUS_OK;}
                relative=real_module->file_path+root_length;
                while(*relative=='/'||*relative=='\\')++relative;
                if(snprintf(path,sizeof(path),"C:\\%s",relative)>=(int)sizeof(path)){process->last_error=206u;return XXEMUL_STATUS_OK;}
                for(path_index=0u;path[path_index];++path_index)if(path[path_index]=='/')path[path_index]='\\';
            } else if (snprintf(path, sizeof(path), "C:\\Windows\\System32\\%s", module) >= (int)sizeof(path)) {
                process->last_error = 206u; return XXEMUL_STATUS_OK;
            }
        }
        length = strlen(path);
        if (!capacity) { process->last_error = 122u; return XXEMUL_STATUS_OK; }
        copied = length < capacity ? length : capacity - 1u;
        if (!arg[1] || !win_memory_span(process, arg[1], (copied + 1u) * (wide ? 2u : 1u))) {
            process->last_error = 998u; return XXEMUL_STATUS_OK;
        }
        path[copied] = 0;
        if (wide) (void)win_write_wide(process, arg[1], path, copied + 1u);
        else (void)win_write(process, arg[1], path, copied + 1u);
        *result = length < capacity ? length : capacity;
        if (length >= capacity) process->last_error = 122u;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "GetStdHandle") == 0) {
        uint32_t which = (uint32_t)arg[0];
        *result = which == 0xfffffff6u ? 0x10u : which == 0xfffffff5u ? 0x11u : which == 0xfffffff4u ? 0x12u : WIN_INVALID_HANDLE;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "GetCurrentProcess") == 0) {
        *result = WIN_INVALID_HANDLE;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "OpenProcess") == 0) {
        *result = win_open_current_process(process, (uint32_t)arg[2], (uint32_t)arg[1]);
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "GetCurrentThread") == 0) {
        *result = WIN_INVALID_HANDLE - 1u;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "DuplicateHandle") == 0) {
        uint64_t duplicate;
        if (!win_is_current_process_handle(process, arg[0], word_size) || !win_is_current_process_handle(process, arg[2], word_size) || arg[3] == 0u) {
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
        if ((arg[6] & 1u) != 0u) (void)win_close_handle(process, arg[1]);
        *result = 1u;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "GetHandleInformation") == 0) {
        uint32_t flags = 0u;
        if (arg[0] >= 0x100u && arg[0] < 0x100u + WIN_MAX_HANDLES && win_handle_at(process, arg[0]) != NULL) {
            flags = process->handles[(size_t)(arg[0] - 0x100u)].flags;
        } else if (arg[0] != 0x10u && arg[0] != 0x11u && arg[0] != 0x12u) {
            process->last_error = 6u;
            return XXEMUL_STATUS_OK;
        }
        if (!win_store(process, arg[1], 4u, flags)) return XXEMUL_STATUS_ADDRESS_FAULT;
        *result = 1u;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "GetFileTime") == 0) {
        win_handle *entry = win_handle_at(process, arg[0]);
        uint64_t creation, access, write_time;
        if (entry == NULL || entry->kind != WIN_HANDLE_FILE || !win_file_times(entry->file_path, &creation, &access, &write_time)) {
            process->last_error = 6u;
            return XXEMUL_STATUS_OK;
        }
        if ((arg[1] != 0u && !win_store(process, arg[1], 8u, creation)) || (arg[2] != 0u && !win_store(process, arg[2], 8u, access)) ||
            (arg[3] != 0u && !win_store(process, arg[3], 8u, write_time)))
            return XXEMUL_STATUS_ADDRESS_FAULT;
        *result = 1u;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "SetFileTime") == 0) return win_set_file_times(process, win_handle_at(process, arg[0]), arg, result);
    if (strcmp(name, "GetProcessAffinityMask") == 0) {
        if (!win_is_current_process_handle(process, arg[0], word_size)) {
            process->last_error = 6u;
            return XXEMUL_STATUS_OK;
        }
        if (!win_store(process, arg[1], word_size, process->process_affinity) || !win_store(process, arg[2], word_size, 1u)) return XXEMUL_STATUS_ADDRESS_FAULT;
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
        return win_capture_thread_context(process, arg[1], word_size, result);
    }
    if (strcmp(name, "ResumeThread") == 0 || strcmp(name, "SuspendThread") == 0 || strcmp(name, "SetThreadContext") == 0) {
        if (!win_is_current_thread_handle(process, arg[0], word_size)) {
            process->last_error = 6u;
            *result = strcmp(name, "SetThreadContext") == 0 ? 0u : UINT32_MAX;
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
    if (strcmp(name, "SetDllDirectoryW") == 0 || strcmp(name, "SetDllDirectoryA") == 0) {
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
        buffer[0] = 1;   /* MaxCharSize = 1 */
        buffer[4] = '?'; /* DefaultChar = '?' */
        *result = 1u;
#endif
        if (*result != 0u && arg[1] != 0u) {
            if (!win_write(process, arg[1], buffer, sizeof(buffer))) return XXEMUL_STATUS_ADDRESS_FAULT;
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
        if (code_page == 932u) *result = (character >= 0x81u && character <= 0x9fu) || (character >= 0xe0u && character <= 0xfcu);
        else if (code_page == 936u || code_page == 949u || code_page == 950u) *result = character >= 0x81u && character <= 0xfeu;
        else if (code_page == 1252u || code_page == 65001u) *result = 0u;
        else return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
#endif
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "MultiByteToWideChar") == 0) return win_multi_byte_to_wide(process, arg, result);
    if (strcmp(name, "WideCharToMultiByte") == 0) return win_wide_to_multi_byte(process, arg, result);
    if (strcmp(name, "SetThreadPriority") == 0) {
        int32_t priority = (int32_t)arg[1];
        if (!win_is_current_thread_handle(process, arg[0], word_size)) process->last_error = 6u;
        else if (priority != -15 && priority != -2 && priority != -1 && priority != 0 && priority != 1 && priority != 2 && priority != 15) process->last_error = 87u;
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
        if (!win_is_current_process_handle(process, arg[0], word_size)) process->last_error = 6u;
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
    if (strcmp(name, "TlsGetValue") == 0 || strcmp(name, "FlsGetValue") == 0 || strcmp(name, "FlsGetValue2") == 0) {
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
        file_time = (uint64_t)now * UINT64_C(10000000) + UINT64_C(116444736000000000);
        if (!win_store(process, arg[0], 8u, file_time)) return XXEMUL_STATUS_ADDRESS_FAULT;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "IsDebuggerPresent") == 0) return XXEMUL_STATUS_OK;
    if (strcmp(name, "DebugBreak") == 0) return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    if (strcmp(name, "OutputDebugStringA") == 0) {
        if (!win_guest_string(process, arg[0], text, sizeof(text), 0)) return XXEMUL_STATUS_ADDRESS_FAULT;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "InitializeCriticalSection") == 0 || strcmp(name, "InitializeCriticalSectionAndSpinCount") == 0 ||
        strcmp(name, "InitializeCriticalSectionEx") == 0) {
        *result = 1u;
        return win_critical_initialize(process, arg[0]);
    }
    if (strcmp(name, "DeleteCriticalSection") == 0 || strcmp(name, "EnterCriticalSection") == 0 || strcmp(name, "LeaveCriticalSection") == 0 ||
        strcmp(name, "TryEnterCriticalSection") == 0) {
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
            if (strcmp(name, "TryEnterCriticalSection") == 0) *result = 1u;
        }
        return win_critical_write(process, entry);
    }
    if (strcmp(name, "AcquireSRWLockExclusive") == 0 || strcmp(name, "ReleaseSRWLockExclusive") == 0 || strcmp(name, "AcquireSRWLockShared") == 0 ||
        strcmp(name, "ReleaseSRWLockShared") == 0 || strcmp(name, "WakeAllConditionVariable") == 0 || strcmp(name, "WakeConditionVariable") == 0) {
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
    if (strcmp(name, "SetPriorityClass") == 0 || strcmp(name, "SetThreadExecutionState") == 0) {
        *result = 1u;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "CreateEventA") == 0 || strcmp(name, "CreateEventW") == 0) {
        *result = win_create_sync(process, WIN_HANDLE_EVENT, arg[1], arg[2], arg[3]);
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "CreateSemaphoreA") == 0 || strcmp(name, "CreateSemaphoreW") == 0) {
        *result = win_create_sync(process, WIN_HANDLE_SEMAPHORE, arg[1], arg[2], arg[3]);
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "SetEvent") == 0 || strcmp(name, "ResetEvent") == 0) {
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
        } else if ((int32_t)arg[1] <= 0 || arg[1] > entry->semaphore_max - entry->semaphore_count) {
            process->last_error = 298u;
        } else if (arg[2] != 0 && !win_store(process, arg[2], 4u, entry->semaphore_count)) {
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
        } else if (win_sync_ready(process,entry)) {
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
            if (!win_load(process, arg[1] + (uint64_t)index * word_size, word_size, &handle)) return XXEMUL_STATUS_ADDRESS_FAULT;
            entries[index] = win_handle_at(process, handle);
            if (entries[index] == NULL || entries[index]->kind == WIN_HANDLE_FILE) {
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
            if (!win_sync_ready(process,entries[index])) all_ready = 0;
        }
        if (arg[2] != 0u) {
            if (all_ready) {
                for (index = 0; index < count; ++index) win_sync_consume(entries[index]);
                *result = 0u;
            } else if ((uint32_t)arg[3] == UINT32_MAX) {
                return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
            } else *result = 0x102u;
        } else {
            for (index = 0; index < count; ++index) {
                if (win_sync_ready(process,entries[index])) {
                    win_sync_consume(entries[index]);
                    *result = index;
                    return XXEMUL_STATUS_OK;
                }
            }
            if ((uint32_t)arg[3] == UINT32_MAX) return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
            *result = 0x102u;
        }
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "RegCreateKeyExA") == 0 || strcmp(name, "RegCreateKeyExW") == 0 ||
        strcmp(name, "RegOpenKeyExA") == 0 || strcmp(name, "RegOpenKeyExW") == 0 ||
        strcmp(name, "RegQueryValueExA") == 0 || strcmp(name, "RegQueryValueExW") == 0 ||
        strcmp(name, "RegSetValueExA") == 0 || strcmp(name, "RegSetValueExW") == 0 || strcmp(name, "RegCloseKey") == 0) {
        *result = win_registry_call(process, name, arg);
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "GetTempPathA") == 0 || strcmp(name, "GetTempPathW") == 0 ||
        strcmp(name, "GetTempFileNameA") == 0 || strcmp(name, "GetTempFileNameW") == 0)
        return win_temp_call(process, name, arg, result);
    if (strcmp(name, "DeleteFileA") == 0 || strcmp(name, "DeleteFileW") == 0) {
        char host[2048];
        if (!arg[0] || !win_guest_string(process, arg[0], text, sizeof(text), win_suffix(name, "W"))) {
            process->last_error = 998u;
        } else if (!win_guest_path(process, text, host, sizeof(host)) || win_equal(host, process->program_path)) {
            process->last_error = 5u;
        } else if (!xx_io_file_exists_a(host)) {
            process->last_error = 2u;
        } else if (xx_io_file_remove_a(host)) {
            win_forget_file_attributes(process, host);
            *result = 1u;
        } else process->last_error = 5u;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "SetFileAttributesA") == 0 || strcmp(name, "SetFileAttributesW") == 0) {
        uint32_t error;
        if (!arg[0] || !win_guest_string(process, arg[0], text, sizeof(text), win_suffix(name, "W"))) {
            process->last_error = 998u; return XXEMUL_STATUS_OK;
        }
        error = win_set_file_attributes(process, text, (uint32_t)arg[1]);
        if (error) process->last_error = error;
        else *result = 1u;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "GetFileAttributesA") == 0 || strcmp(name, "GetFileAttributesW") == 0) {
        char host[2048];
        *result = UINT32_MAX;
        if (!arg[0] || !win_guest_string(process, arg[0], text, sizeof(text), win_suffix(name, "W"))) {
            process->last_error = 998u;
        } else if (!win_guest_path(process, text, host, sizeof(host))) {
            process->last_error = 5u;
        } else {
#if defined(_WIN32)
            DWORD attributes = GetFileAttributesA(host);
            *result = attributes;
            if (attributes == INVALID_FILE_ATTRIBUTES) process->last_error = GetLastError();
#else
            struct stat attributes;
            if (stat(host, &attributes) == 0) {
                uint32_t flags = S_ISDIR(attributes.st_mode) ? 0x10u : 0u;
                if (!(attributes.st_mode & (S_IWUSR | S_IWGRP | S_IWOTH))) flags |= 1u;
                win_file_attribute *explicit_attributes = win_file_attribute_at(process, host, &attributes, 0);
                if (explicit_attributes) flags |= explicit_attributes->logical;
                *result = flags ? flags : 0x80u;
            } else if (errno == ENOENT || errno == ENOTDIR) {
                char *slash = strrchr(host, '/');
                if (slash) *slash = 0;
                process->last_error = slash && stat(host, &attributes) == 0 && S_ISDIR(attributes.st_mode) ? 2u : 3u;
            } else process->last_error = errno == EACCES ? 5u : 31u;
#endif
        }
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "CreateFileMappingA") == 0 || strcmp(name, "CreateFileMappingW") == 0) {
        *result = win_mapping_create(process, name, arg);
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "MapViewOfFile") == 0 || strcmp(name, "MapViewOfFileEx") == 0) {
        *result = win_mapping_view(process, name, arg);
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "FlushViewOfFile") == 0 || strcmp(name, "UnmapViewOfFile") == 0) {
        *result = win_mapping_release(process, arg[0], strcmp(name, "FlushViewOfFile") == 0 ? arg[1] : 0u,
                                      strcmp(name, "UnmapViewOfFile") == 0);
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "SetHandleCount") == 0) { *result = (uint32_t)arg[0]; return XXEMUL_STATUS_OK; }
    if (strcmp(name, "SetEndOfFile") == 0) {
        win_handle *file = win_handle_at(process, arg[0]);
        int64_t position;
        size_t index;
        if (!file || file->kind != WIN_HANDLE_FILE || !file->io) { process->last_error = 6u; return XXEMUL_STATUS_OK; }
        if (!(file->file_access & 0x40000000u)) { process->last_error = 5u; return XXEMUL_STATUS_OK; }
        for (index = 0u; index < WIN_MAX_HANDLES; ++index) {
            win_handle *mapping = &process->handles[index];
            if (mapping->in_use && mapping->kind == WIN_HANDLE_MAPPING && mapping->file_path[0] && win_equal(mapping->file_path, file->file_path)) {
                process->last_error = 1224u; return XXEMUL_STATUS_OK;
            }
        }
        position = xx_io_tell(file->io);
        if (position < 0) process->last_error = 87u;
        else if (xx_io_resize(file->io, position)) process->last_error = win_commit_error(errno);
        else *result = 1u;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name,"MoveFileA")==0 || strcmp(name,"MoveFileW")==0) {
        char destination[1024];uint32_t error;
        wide=win_suffix(name,"W");
        if(!arg[0]||!arg[1]||!win_guest_string(process,arg[0],text,sizeof(text),wide)||
           !win_guest_string(process,arg[1],destination,sizeof(destination),wide)){
            process->last_error=998u;return XXEMUL_STATUS_OK;
        }
        error=win_move_file(process,text,destination);
        if(error)process->last_error=error;else *result=1u;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "CopyFileA") == 0 || strcmp(name, "CopyFileW") == 0) {
        char destination[1024];
        uint32_t error;
        wide = win_suffix(name, "W");
        if (!arg[0] || !arg[1] || !win_guest_string(process, arg[0], text, sizeof(text), wide) ||
            !win_guest_string(process, arg[1], destination, sizeof(destination), wide)) {
            process->last_error = 998u; return XXEMUL_STATUS_OK;
        }
        error = win_copy_file(process, text, destination, arg[2] != 0u);
        if (error) process->last_error = error;
        else *result = 1u;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "CreateFileA") == 0 || strcmp(name, "CreateFileW") == 0) {
        if (!win_guest_string(process, arg[0], text, sizeof(text), win_suffix(name, "W"))) return XXEMUL_STATUS_ADDRESS_FAULT;
        *result = win_file_open(process, text, (uint32_t)arg[1], (uint32_t)arg[4]);
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "ReadFile") == 0) {
        *result = win_file_read(process, arg[0], arg[1], arg[2], arg[3]);
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "WriteFile") == 0) {
        *result = win_file_write(process, arg[0], arg[1], arg[2], arg[3]);
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
            int whence = arg[3] == 0 ? SEEK_SET : arg[3] == 1 ? SEEK_CUR : SEEK_END;
            int64_t position;
            if (arg[2] != 0) {
                if (!win_load(process, arg[2], 4u, &value)) return XXEMUL_STATUS_ADDRESS_FAULT;
                offset = (int64_t)((uint64_t)(uint32_t)offset | ((uint64_t)(uint32_t)value << 32));
            }
            if (xx_io_seek64(io, offset, whence) == 0 && (position = xx_io_tell(io)) >= 0 &&
                (arg[2] == 0 || win_store(process, arg[2], 4u, (uint32_t)((uint64_t)position >> 32)))) {
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
        int64_t distance = word_size == 8u ? (int64_t)arg[1] : (int64_t)((uint64_t)(uint32_t)arg[1] | ((uint64_t)(uint32_t)arg[2] << 32));
        int whence = method == 0 ? SEEK_SET : method == 1 ? SEEK_CUR : SEEK_END;
        int64_t position;
        io = win_handle_io(process, arg[0]);
        if (io != NULL && method <= 2u && xx_io_seek64(io, distance, whence) == 0 && (position = xx_io_tell(io)) >= 0 &&
            (output == 0 || win_store(process, output, 8u, (uint64_t)position)))
            *result = 1u;
        else process->last_error = 6u;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "GetFileSize") == 0 || strcmp(name, "GetFileSizeEx") == 0) {
        io = win_handle_io(process, arg[0]);
        if (io == NULL || (value = (uint64_t)xx_io_total_size(io)) == UINT64_MAX) {
            process->last_error = 6u;
            *result = WIN_INVALID_HANDLE;
        } else if (strcmp(name, "GetFileSizeEx") == 0) {
            if (!win_store(process, arg[1], 8u, value)) return XXEMUL_STATUS_ADDRESS_FAULT;
            *result = 1u;
        } else {
            if (arg[1] != 0 && !win_store(process, arg[1], 4u, value >> 32)) return XXEMUL_STATUS_ADDRESS_FAULT;
            *result = (uint32_t)value;
        }
        return XXEMUL_STATUS_OK;
    }
#if defined(_WIN32)
    if (strcmp(name, "FileTimeToLocalFileTime") == 0) {
        FILETIME ft_in, ft_out;
        if (!win_read(process, arg[0], (uint8_t *)&ft_in, sizeof(ft_in))) return XXEMUL_STATUS_ADDRESS_FAULT;
        FileTimeToLocalFileTime(&ft_in, &ft_out);
        if (!win_write(process, arg[1], (const uint8_t *)&ft_out, sizeof(ft_out))) return XXEMUL_STATUS_ADDRESS_FAULT;
        *result = 1;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "FileTimeToDosDateTime") == 0) {
        FILETIME ft;
        WORD fat_date = 0, fat_time = 0;
        if (!win_read(process, arg[0], (uint8_t *)&ft, sizeof(ft))) return XXEMUL_STATUS_ADDRESS_FAULT;
        FileTimeToDosDateTime(&ft, &fat_date, &fat_time);
        if (arg[1] != 0) win_store(process, arg[1], 2u, fat_date);
        if (arg[2] != 0) win_store(process, arg[2], 2u, fat_time);
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
            if (!win_write(process, arg[1], (const uint8_t *)&info, sizeof(info))) return XXEMUL_STATUS_ADDRESS_FAULT;
            *result = 1;
            return XXEMUL_STATUS_OK;
        }
        process->last_error = 6u;
        *result = 0;
        return XXEMUL_STATUS_OK;
    }
#endif
    if (strcmp(name, "GetFileType") == 0) {
        *result = arg[0] == 0x10u || arg[0] == 0x11u || arg[0] == 0x12u ? 2u : win_handle_io(process, arg[0]) != NULL ? 1u : 0u;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "FlushFileBuffers") == 0) {
        *result = arg[0] == 0x11u || arg[0] == 0x12u || win_handle_io(process, arg[0]) != NULL;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "InterlockedIncrement") == 0 || strcmp(name, "InterlockedDecrement") == 0) {
        uint64_t value;
        if (!win_load(process, arg[0], 4u, &value)) return XXEMUL_STATUS_ADDRESS_FAULT;
        value = (uint32_t)((uint32_t)value + (strcmp(name, "InterlockedIncrement") == 0 ? 1u : UINT32_MAX));
        if (!win_store(process, arg[0], 4u, value)) return XXEMUL_STATUS_ADDRESS_FAULT;
        *result = value;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "GetProcessHeap") == 0) {
        *result = 0x400u;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "HeapCreate") == 0) {
        size_t slot;
        for (slot = 0; slot < WIN_MAX_HANDLES; ++slot) if (!process->handles[slot].in_use) break;
        if (slot == WIN_MAX_HANDLES) { process->last_error = 8u; return XXEMUL_STATUS_OK; }
        memset(&process->handles[slot], 0, sizeof(process->handles[slot]));
        process->handles[slot].kind = WIN_HANDLE_HEAP;
        process->handles[slot].in_use = 1u;
        process->handles[slot].references = 1u;
        process->handles[slot].root_slot = (uint16_t)slot;
        *result = 0x100u + slot;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "HeapDestroy") == 0) {
        uint64_t owner = win_heap_owner(process, arg[0]);
        size_t index;
        if (owner == 0u || owner == 0x400u) { process->last_error = 6u; return XXEMUL_STATUS_OK; }
        for (index = 0u; index < process->allocation_count; ++index)
            if (process->allocations[index].heap_owner == owner) process->allocations[index].active = 0u;
        /* Destroying the heap invalidates every alias as well as its blocks. */
        for (index = 0u; index < WIN_MAX_HANDLES; ++index) {
            win_handle *entry = &process->handles[index];
            if ((0x100u + index == owner) || (entry->kind == WIN_HANDLE_ALIAS && 0x100u + entry->root_slot == owner))
                memset(entry, 0, sizeof(*entry));
        }
        *result = 1u;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "HeapAlloc") == 0) {
        uint64_t owner = win_heap_owner(process, arg[0]);
        win_allocation *allocation;
        if (owner == 0u) { process->last_error = 6u; return XXEMUL_STATUS_OK; }
        *result = win_heap_alloc(process, arg[2]);
        allocation = win_find_allocation(process, *result);
        if (allocation == NULL) process->last_error = 8u;
        else {
            allocation->heap_owner = owner;
            if ((arg[1] & 8u) != 0u) memset(process->emulator->region_data + (size_t)(*result - process->emulator->region_address), 0, (size_t)allocation->size);
        }
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "HeapReAlloc") == 0) {
        uint64_t owner = win_heap_owner(process, arg[0]);
        win_allocation *allocation = win_find_allocation(process, arg[2]);
        uint64_t old_size, new_size = arg[3] ? arg[3] : 1u;
        if (owner == 0u) { process->last_error = 6u; return XXEMUL_STATUS_OK; }
        if (allocation == NULL || allocation->heap_owner != owner) { process->last_error = 87u; return XXEMUL_STATUS_OK; }
        old_size = allocation->size;
        if (new_size <= allocation->capacity) {
            allocation->size = new_size;
            *result = arg[2];
        } else if ((arg[1] & 0x10u) == 0u) {
            win_allocation *replacement;
            *result = win_heap_alloc(process, new_size);
            replacement = win_find_allocation(process, *result);
            if (replacement != NULL) {
                uint64_t base = process->emulator->region_address;
                replacement->heap_owner = owner;
                memcpy(process->emulator->region_data + (size_t)(*result - base), process->emulator->region_data + (size_t)(arg[2] - base), (size_t)old_size);
                allocation->active = 0u;
            }
        }
        if (*result == 0u) process->last_error = 8u;
        else if ((arg[1] & 8u) != 0u && new_size > old_size)
            memset(process->emulator->region_data + (size_t)(*result - process->emulator->region_address + old_size), 0, (size_t)(new_size - old_size));
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "HeapFree") == 0 || strcmp(name, "HeapSize") == 0 || strcmp(name, "HeapValidate") == 0) {
        uint64_t owner = win_heap_owner(process, arg[0]);
        win_allocation *allocation = win_find_allocation(process, arg[2]);
        int size_query = strcmp(name, "HeapSize") == 0;
        if (size_query) *result = WIN_INVALID_HANDLE;
        if (owner == 0u) { process->last_error = 6u; return XXEMUL_STATUS_OK; }
        if (strcmp(name, "HeapValidate") == 0 && arg[2] == 0u) {
            size_t index;
            uint64_t begin = process->emulator->region_address + process->image_size;
            for (index = 0u; index < process->allocation_count; ++index) {
                win_allocation *item = &process->allocations[index];
                if (!item->active || item->heap_owner != owner) continue;
                if (item->address < begin || item->address > process->heap_cursor || item->size > item->capacity ||
                    item->capacity > process->heap_cursor - item->address || item->capacity % 16u != 0u) {
                    process->last_error = 87u; return XXEMUL_STATUS_OK;
                }
            }
            *result = 1u;
            return XXEMUL_STATUS_OK;
        }
        if (allocation == NULL || allocation->heap_owner != owner) { process->last_error = 87u; return XXEMUL_STATUS_OK; }
        if (size_query) *result = allocation->size;
        else {
            if (strcmp(name, "HeapFree") == 0) allocation->active = 0u;
            *result = 1u;
        }
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "LocalAlloc") == 0 || strcmp(name, "GlobalAlloc") == 0) {
        *result = win_heap_alloc(process, arg[1]);
        if (*result == 0) process->last_error = 8u;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "LocalFree") == 0 || strcmp(name, "GlobalFree") == 0) {
        win_allocation *allocation = win_find_allocation(process, arg[0]);
        if (allocation != NULL) allocation->active = 0u;
        *result = 0;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "GlobalHandle") == 0) {
        win_allocation *allocation = win_find_allocation(process, arg[0]);
        if (allocation) *result = allocation->address;
        else process->last_error = 6u;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "GlobalReAlloc") == 0 || strcmp(name, "LocalReAlloc") == 0) {
        win_allocation *allocation = win_find_allocation(process, arg[0]);
        if (allocation) {
            if ((arg[2] & 0x80u) || arg[1] <= allocation->size) {
                if (!(arg[2] & 0x80u)) allocation->size = arg[1];
                *result = allocation->address;
            } else {
                uint64_t old_size = allocation->size;
                *result = win_heap_alloc(process, arg[1]);
                if (*result) {
                    uint64_t region_base = process->emulator->region_address;
                    memcpy(process->emulator->region_data + (size_t)(*result - region_base),
                        process->emulator->region_data + (size_t)(arg[0] - region_base), (size_t)old_size);
                    allocation->active = 0u;
                }
            }
        }
        if (!*result) process->last_error = allocation ? 8u : 6u;
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
    if (strcmp(name, "GetCurrentDirectoryA") == 0 || strcmp(name, "GetCurrentDirectoryW") == 0 ||
        strcmp(name, "SetCurrentDirectoryA") == 0 || strcmp(name, "SetCurrentDirectoryW") == 0)
        return win_current_directory_call(process, name, arg, result);
    if (strcmp(name, "GetEnvironmentVariableA") == 0 || strcmp(name, "GetEnvironmentVariableW") == 0 ||
        strcmp(name, "SetEnvironmentVariableA") == 0 || strcmp(name, "SetEnvironmentVariableW") == 0)
        return win_environment_call(process, name, arg, result);
    if (strcmp(name, "GetEnvironmentStringsA") == 0) {
        *result = process->environment_a;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "GetEnvironmentStringsW") == 0) {
        *result = process->runtime_base + 0x7c00u;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "FreeEnvironmentStringsA") == 0 || strcmp(name, "FreeEnvironmentStringsW") == 0) {
        *result = 1u;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "GetTickCount") == 0 || strcmp(name, "GetTickCount64") == 0) {
        process->scheduler_tick += 10u;
        process->virtual_tick = (uint32_t)process->scheduler_tick;
        *result = strcmp(name, "GetTickCount64") == 0 ? process->scheduler_tick : process->virtual_tick;
        if (word_size == 4u && strcmp(name, "GetTickCount64") == 0) process->emulator->x86.gpr[XXEMUL_X86_RDX] = (uint32_t)(process->scheduler_tick >> 32u);
        return XXEMUL_STATUS_OK;
    }

    if (strcmp(name, "Sleep") == 0 || strcmp(name, "SleepEx") == 0) {
        if (strcmp(name, "SleepEx") == 0 && arg[1]) return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "SwitchToThread") == 0) {
        size_t index;
        for (index = 0u; index < WIN_MAX_THREADS; ++index) if (index != process->thread_current &&
            process->threads[index].active && !process->threads[index].blocked && !process->threads[index].suspended) { *result = 1u; break; }
        return XXEMUL_STATUS_OK;
    }

    if (strcmp(name, "GetCurrentProcessId") == 0 || strcmp(name, "GetCurrentThreadId") == 0) {
        *result = strcmp(name, "GetCurrentThreadId") == 0 ? process->threads[process->thread_current].id : process->process_id;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "GetVersion") == 0) {
        *result = 0x0a000006u;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "GetFileVersionInfoSizeA") == 0 || strcmp(name, "GetFileVersionInfoA") == 0) {
        process->last_error = 1813u;
        *result = 0u;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "CreateProcessA") == 0 || strcmp(name, "CreateProcessW") == 0)
        return win_create_process(process,arg,win_suffix(name,"W"),result);
    if (strcmp(name, "CreatePipe") == 0) {
        size_t r = WIN_MAX_HANDLES, w = WIN_MAX_HANDLES, i;
        for (i = 0; i < WIN_MAX_HANDLES; ++i) {
            if (!process->handles[i].in_use) {
                if (r == WIN_MAX_HANDLES) r = i;
                else if (w == WIN_MAX_HANDLES) {
                    w = i;
                    break;
                }
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
        win_handle *entry=win_handle_at(process,arg[0]);
        win_child_process *child=win_child_at(process,entry);
        uint32_t code=child?(child->finished?child->exit_code:259u):(process->process_terminated?process->exit_code:259u);
        if((!child && !win_is_current_process_handle(process,arg[0],word_size)) || (entry && entry->kind!=WIN_HANDLE_PROCESS)) {
            process->last_error=6u;return XXEMUL_STATUS_OK;
        }
        if(!arg[1] || !win_memory_span(process,arg[1],4u)) {process->last_error=998u;return XXEMUL_STATUS_OK;}
        (void)win_store(process,arg[1],4u,code);*result=1u;return XXEMUL_STATUS_OK;
    }
    if (strcmp(name,"GetProcessId")==0 || strcmp(name,"GetThreadId")==0) {
        win_handle *entry=win_handle_at(process,arg[0]);
        win_child_process *child=win_child_at(process,entry);
        int thread=win_equal(name,"GetThreadId");
        if(child && entry->kind==(thread?WIN_HANDLE_THREAD:WIN_HANDLE_PROCESS)) *result=thread?child->thread_id:child->process_id;
        else if(thread && win_is_current_thread_handle(process,arg[0],word_size)) *result=entry?entry->object_id:process->threads[process->thread_current].id;
        else if(!thread && win_is_current_process_handle(process,arg[0],word_size)) *result=process->process_id;
        else process->last_error=6u;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name,"TerminateProcess")==0) {
        win_handle *entry=win_handle_at(process,arg[0]);
        win_child_process *child=win_child_at(process,entry);
        if(child && entry->kind==WIN_HANDLE_PROCESS) {
            win_child_finish(child,(uint32_t)arg[1]);*result=1u;return XXEMUL_STATUS_OK;
        }
        if(win_is_current_process_handle(process,arg[0],word_size)) {
            process->process_terminated=1u;process->exit_code=(uint32_t)arg[1];process->emulator->halted=1u;
            return XXEMUL_STATUS_HALTED;
        }
        process->last_error=6u;return XXEMUL_STATUS_OK;
    }
    if (strcmp(name,"TerminateThread")==0) {
        win_handle *entry=win_handle_at(process,arg[0]);
        size_t slot, frame;
        if(!entry || entry->kind!=WIN_HANDLE_THREAD){process->last_error=6u;return XXEMUL_STATUS_OK;}
        if(entry->child_slot){process->last_error=50u;return XXEMUL_STATUS_OK;}
        if(entry->thread_finished){*result=1u;return XXEMUL_STATUS_OK;}
        slot=entry->thread_slot;
        if(slot>=WIN_MAX_THREADS || !process->threads[slot].active || process->threads[slot].id!=entry->object_id){
            process->last_error=6u;return XXEMUL_STATUS_OK;
        }
        for(frame=0u;frame<process->dll_depth;++frame)
            if(process->dll_frames[frame].owner_id==process->threads[slot].id){process->last_error=170u;return XXEMUL_STATUS_OK;}
        if(slot==process->thread_current) return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION; /* handled before API dispatch */
        win_thread_end(process,slot,(uint32_t)arg[1]);*result=1u;return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "DuplicateHandle") == 0) {
        if (arg[3] != 0) win_store(process, arg[3], word_size, arg[1]);
        *result = 1u;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "GetVersionExA") == 0 || strcmp(name, "GetVersionExW") == 0) {
        if (arg[0] == 0) return XXEMUL_STATUS_ADDRESS_FAULT;
        win_store(process, arg[0] + 4u, 4u, 10u);
        win_store(process, arg[0] + 8u, 4u, 0u);
        win_store(process, arg[0] + 12u, 4u, 19045u);
        win_store(process, arg[0] + 16u, 4u, 2u);
        uint8_t zero256[256] = {0};
        win_write(process, arg[0] + 20u, zero256, strcmp(name, "GetVersionExW") == 0 ? 256u : 128u);
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
    if (strcmp(name, "SetThreadLocale") == 0 || strcmp(name, "SetConsoleCP") == 0 || strcmp(name, "SetConsoleActiveScreenBuffer") == 0 ||
        strcmp(name, "FlushConsoleInputBuffer") == 0 || strcmp(name, "SetConsoleScreenBufferSize") == 0 || strcmp(name, "SetConsoleWindowInfo") == 0 ||
        strcmp(name, "AllocConsole") == 0 || strcmp(name, "FreeConsole") == 0 || strcmp(name, "FreeLibrary") == 0) {
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
    if (strcmp(name, "GetACP") == 0 || strcmp(name, "GetOEMCP") == 0 || strcmp(name, "GetConsoleOutputCP") == 0) {
        *result = 1252u;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "GetConsoleCursorInfo") == 0) {
        if (arg[0] != 0x11u && arg[0] != 0x12u) {
            process->last_error = 6u;
            return XXEMUL_STATUS_OK;
        }
        if (!win_store(process, arg[1], 4u, process->console_cursor_size) || !win_store(process, arg[1] + 4u, 4u, process->console_cursor_visible))
            return XXEMUL_STATUS_ADDRESS_FAULT;
        *result = 1u;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "WriteConsoleOutputA") == 0) return win_console_transfer(process, arg, result, 0);
    if (strcmp(name, "ReadConsoleOutputA") == 0) return win_console_transfer(process, arg, result, 1);
    if (strcmp(name, "ScrollConsoleScreenBufferA") == 0) return win_console_scroll(process, arg, result);
    if (strcmp(name, "GetConsoleScreenBufferInfo") == 0) {
        uint8_t info[22] = {0};
        uint16_t fields[] = {80u, 25u, process->console_cursor_x, process->console_cursor_y, process->console_attributes, 0u, 0u, 79u, 24u, 80u, 25u};
        size_t index;
        if (arg[0] != 0x11u && arg[0] != 0x12u) {
            process->last_error = 6u;
            return XXEMUL_STATUS_OK;
        }
        for (index = 0; index < 11u; ++index) {
            info[index * 2u] = (uint8_t)fields[index];
            info[index * 2u + 1u] = (uint8_t)(fields[index] >> 8);
        }
        if (!win_write(process, arg[1], info, sizeof(info))) return XXEMUL_STATUS_ADDRESS_FAULT;
        *result = 1u;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "SetConsoleCursorInfo") == 0) {
        uint64_t size, visible;
        if (arg[0] != 0x11u && arg[0] != 0x12u) {
            process->last_error = 6u;
            return XXEMUL_STATUS_OK;
        }
        if (!win_load(process, arg[1], 4u, &size) || !win_load(process, arg[1] + 4u, 4u, &visible)) return XXEMUL_STATUS_ADDRESS_FAULT;
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
        if (!win_store(process, arg[1], 4u, arg[0] == 0x10u ? process->console_input_mode : process->console_output_mode)) return XXEMUL_STATUS_ADDRESS_FAULT;
        *result = 1u;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "SetConsoleMode") == 0) {
        if (arg[0] < 0x10u || arg[0] > 0x12u) {
            process->last_error = 6u;
            return XXEMUL_STATUS_OK;
        }
        if (arg[0] == 0x10u) process->console_input_mode = (uint32_t)arg[1];
        else process->console_output_mode = (uint32_t)arg[1];
        *result = 1u;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "GetStartupInfoA") == 0 || strcmp(name, "GetStartupInfoW") == 0) {
        uint8_t startup[104]={0};size_t count=word_size==8u?104u:68u,j,k;
        if(!arg[0] || !win_memory_span(process,arg[0],count))return XXEMUL_STATUS_ADDRESS_FAULT;
        win_put32(startup,(uint32_t)count);
        win_put32(startup+(word_size==8u?60u:44u),process->startup_flags);
        startup[word_size==8u?64u:48u]=(uint8_t)process->startup_show;
        startup[word_size==8u?65u:49u]=(uint8_t)(process->startup_show>>8u);
        for(j=0u;j<3u;++j)for(k=0u;k<word_size;++k)
            startup[(word_size==8u?80u:56u)+j*word_size+k]=(uint8_t)((UINT64_C(0x10)+j)>>(k*8u));
        if(!win_write(process,arg[0],startup,count))return XXEMUL_STATUS_ADDRESS_FAULT;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "GlobalMemoryStatus") == 0 || strcmp(name, "GlobalMemoryStatusEx") == 0) {
        uint8_t bytes[64] = {0};
        int extended = strcmp(name, "GlobalMemoryStatusEx") == 0;
        unsigned field_width = extended ? 8u : word_size;
        unsigned length = extended ? 64u : 8u + 6u * field_width;
        uint64_t total = process->emulator->region_size;
        uint64_t available = process->heap_cursor < process->heap_limit ? process->heap_limit - process->heap_cursor : 0u;
        uint64_t values[7];
        size_t index;
        unsigned byte;
        uint32_t load;
        if (extended) {
            uint64_t requested;
            if (!win_load(process, arg[0], 4u, &requested)) return XXEMUL_STATUS_ADDRESS_FAULT;
            if (requested != length) { process->last_error = 87u; return XXEMUL_STATUS_OK; }
        }
        /* The guest has one bounded mapped-memory budget, no modeled swap.
         * Only unused heap space and tracked reusable blocks are available;
         * image, stack and runtime reservations stay charged. No host RAM is
         * reported as capacity that the guest allocator cannot supply. */
        for (index = 0u; index < process->allocation_count; ++index) {
            const win_allocation *allocation = &process->allocations[index];
            if (!allocation->active && allocation->capacity <= total - available)
                available += allocation->capacity;
        }
        if (available > total) available = total;
        load = total ? (uint32_t)((long double)(total - available) * 100.0L / (long double)total) : 100u;
        win_put32(bytes, length); win_put32(bytes + 4u, load);
        values[0] = total; values[1] = available;
        values[2] = total; values[3] = available;
        values[4] = total; values[5] = available; values[6] = 0u;
        for (index = 0u; index < (extended ? 7u : 6u); ++index) {
            uint64_t value = values[index];
            if (field_width == 4u && value > UINT32_MAX) value = UINT32_MAX;
            for (byte = 0u; byte < field_width; ++byte)
                bytes[8u + index * field_width + byte] = (uint8_t)(value >> (byte * 8u));
        }
        if (!win_write(process, arg[0], bytes, length)) return XXEMUL_STATUS_ADDRESS_FAULT;
        if (extended) *result = 1u;
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
        if (!win_store(process, arg[0], 8u, 1000000u)) return XXEMUL_STATUS_ADDRESS_FAULT;
        *result = 1u;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "QueryPerformanceCounter") == 0) {
        process->scheduler_tick += 500u;
        process->virtual_tick = (uint32_t)process->scheduler_tick;
        if (!win_store(process, arg[0], 8u, process->scheduler_tick * 1000u)) return XXEMUL_STATUS_ADDRESS_FAULT;
        *result = 1u;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "malloc") == 0 || strcmp(name, "calloc") == 0) {
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
        if (allocation == NULL) return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
        allocation->active = 0u;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "realloc") == 0) {
        win_allocation *allocation;
        xxemul_status copy_status;
        uint64_t old_size;
        if (arg[0] == 0u) {
            *result = win_heap_alloc(process, arg[1]);
            return *result != 0u ? XXEMUL_STATUS_OK : win_crt_errno(process, 12u);
        }
        allocation = win_find_allocation(process, arg[0]);
        if (allocation == NULL) return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
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
    if (strcmp(name, "memcpy") == 0 || strcmp(name, "memmove") == 0) {
        xxemul_status copy_status = win_crt_copy(process, arg[0], arg[1], arg[2]);
        if (copy_status == XXEMUL_STATUS_OK) *result = arg[0];
        return copy_status;
    }
    if (strcmp(name, "memset") == 0) {
        xxemul_status fill_status = win_crt_fill(process, arg[0], (uint8_t)arg[1], arg[2]);
        if (fill_status == XXEMUL_STATUS_OK) *result = arg[0];
        return fill_status;
    }
    if (strcmp(name, "memcmp") == 0 || strcmp(name, "memchr") == 0) {
        uint8_t first[4096], second[4096];
        uint64_t offset;
        if (arg[2] > WIN_MAX_IO) return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
        for (offset = 0u; offset < arg[2];) {
            size_t chunk = (size_t)(arg[2] - offset > sizeof(first) ? sizeof(first) : arg[2] - offset);
            if (!win_read(process, arg[0] + offset, first, chunk)) return XXEMUL_STATUS_ADDRESS_FAULT;
            if (strcmp(name, "memchr") == 0) {
                const uint8_t *found = (const uint8_t *)memchr(first, (uint8_t)arg[1], chunk);
                if (found != NULL) {
                    *result = arg[0] + offset + (size_t)(found - first);
                    return XXEMUL_STATUS_OK;
                }
            } else {
                int difference;
                if (!win_read(process, arg[1] + offset, second, chunk)) return XXEMUL_STATUS_ADDRESS_FAULT;
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
            if (!win_load(process, arg[0] + *result, 1u, &character)) return XXEMUL_STATUS_ADDRESS_FAULT;
            if (character == 0u) return XXEMUL_STATUS_OK;
        }
        return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    }
    if (strcmp(name, "wcslen") == 0) return win_crt_string_length(process, arg[0], 2u, result);
    if (strcmp(name, "strcmp") == 0 || strcmp(name, "strncmp") == 0 || strcmp(name, "_stricmp") == 0 || strcmp(name, "_strnicmp") == 0)
        return win_crt_compare_strings(process, arg[0], arg[1], (strcmp(name, "strncmp") == 0 || strcmp(name, "_strnicmp") == 0) ? arg[2] : UINT64_MAX,
                                       (strcmp(name, "_stricmp") == 0 || strcmp(name, "_strnicmp") == 0), result);
    if (strcmp(name, "strcat") == 0) {
        uint64_t dest_len = 0, src_len = 0;
        win_crt_string_length(process, arg[0], 1u, &dest_len);
        win_crt_string_length(process, arg[1], 1u, &src_len);
        win_crt_copy(process, arg[0] + dest_len, arg[1], src_len + 1u);
        *result = arg[0];
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "strnlen") == 0) {
        uint64_t maxlen = arg[1];
        uint64_t i, ch;
        for (i = 0; i < maxlen; ++i) {
            if (!win_load(process, arg[0] + i, 1u, &ch) || ch == 0) break;
        }
        *result = i;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "wcsnlen") == 0) {
        uint64_t maxlen = arg[1];
        uint64_t i, ch;
        for (i = 0; i < maxlen; ++i) {
            if (!win_load(process, arg[0] + i * 2u, 2u, &ch) || ch == 0) break;
        }
        *result = i;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "isalpha") == 0) {
        *result = isalpha((int)(unsigned char)arg[0]) != 0;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "isdigit") == 0) {
        *result = isdigit((int)(unsigned char)arg[0]) != 0;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "isspace") == 0) {
        *result = isspace((int)(unsigned char)arg[0]) != 0;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "isxdigit") == 0) {
        *result = isxdigit((int)(unsigned char)arg[0]) != 0;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "iscntrl") == 0) {
        *result = iscntrl((int)(unsigned char)arg[0]) != 0;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "ispunct") == 0) {
        *result = ispunct((int)(unsigned char)arg[0]) != 0;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "tolower") == 0) {
        *result = (uint32_t)tolower((int)(unsigned char)arg[0]);
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "toupper") == 0) {
        *result = (uint32_t)toupper((int)(unsigned char)arg[0]);
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "strspn") == 0 || strcmp(name, "strpbrk") == 0) {
        char *left = NULL, *right = NULL;
        size_t left_length = 0u, right_length = 0u;
        xxemul_status s = win_crt_read_string(process, arg[0], &left, &left_length);
        if (s != XXEMUL_STATUS_OK || left == NULL) return s;
        s = win_crt_read_string(process, arg[1], &right, &right_length);
        if (s == XXEMUL_STATUS_OK && right != NULL) {
            if (strcmp(name, "strspn") == 0) {
                *result = strspn(left, right);
            } else {
                char *f = strpbrk(left, right);
                *result = f != NULL ? arg[0] + (size_t)(f - left) : 0u;
            }
        }
        free(left);
        free(right);
        return s;
    }
    if (strcmp(name, "strtoll") == 0 || strcmp(name, "strtoull") == 0) {
        char *str = NULL;
        size_t len = 0;
        char *endp = NULL;
        xxemul_status s = win_crt_read_string(process, arg[0], &str, &len);
        if (s != XXEMUL_STATUS_OK || str == NULL) return s;
        if (strcmp(name, "strtoll") == 0) {
            *result = (uint64_t)strtoll(str, &endp, (int)arg[2]);
        } else {
            *result = (uint64_t)strtoull(str, &endp, (int)arg[2]);
        }
        if (arg[1] != 0u && endp != NULL) {
            win_store(process, arg[1], word_size, arg[0] + (size_t)(endp - str));
        }
        free(str);
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "mbrlen") == 0) {
        *result = arg[0] != 0 ? 1u : 0u;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "mbrtowc") == 0) {
        uint64_t ch = 0;
        if (arg[1] != 0) {
            win_load(process, arg[1], 1u, &ch);
            if (arg[0] != 0) win_store(process, arg[0], 2u, (uint16_t)ch);
            *result = ch == 0 ? 0u : 1u;
        } else {
            *result = 0u;
        }
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "wcrtomb") == 0) {
        if (arg[0] != 0) {
            win_store(process, arg[0], 1u, (uint8_t)arg[1]);
            *result = 1u;
        } else {
            *result = 1u;
        }
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "strcpy") == 0 || strcmp(name, "_strdup") == 0) {
        uint64_t length;
        xxemul_status string_status = win_crt_string_length(process, arg[strcmp(name, "_strdup") == 0 ? 0u : 1u], 1u, &length);
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
        if (arg[2] > WIN_MAX_IO) return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
        for (index = 0u; index < arg[2]; ++index) {
            if (!win_load(process, arg[1] + index, 1u, &character) || !win_store(process, arg[0] + index, 1u, character)) return XXEMUL_STATUS_ADDRESS_FAULT;
            if (character == 0u) {
                xxemul_status fill_status = win_crt_fill(process, arg[0] + index + 1u, 0u, arg[2] - index - 1u);
                if (fill_status != XXEMUL_STATUS_OK) return fill_status;
                break;
            }
        }
        *result = arg[0];
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "strchr") == 0 || strcmp(name, "strrchr") == 0) {
        uint64_t index, ch;
        for (index = 0u; index < WIN_MAX_IO; ++index) {
            if (!win_load(process, arg[0] + index, 1u, &ch)) return XXEMUL_STATUS_ADDRESS_FAULT;
            if (ch == (uint8_t)arg[1]) {
                *result = arg[0] + index;
                if (strcmp(name, "strchr") == 0) return XXEMUL_STATUS_OK;
            }
            if (ch == 0u) return XXEMUL_STATUS_OK;
        }
        return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    }
    if (strcmp(name, "strstr") == 0 || strcmp(name, "strcspn") == 0) {
        char *left = NULL, *right = NULL;
        size_t left_length = 0u, right_length = 0u;
        xxemul_status string_status = win_crt_read_string(process, arg[0], &left, &left_length);
        if (string_status != XXEMUL_STATUS_OK || left == NULL) return string_status;
        string_status = win_crt_read_string(process, arg[1], &right, &right_length);
        if (string_status == XXEMUL_STATUS_OK && right != NULL) {
            if (strcmp(name, "strstr") == 0) {
                const char *found = strstr(left, right);
                if (found != NULL) *result = arg[0] + (size_t)(found - left);
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
        xxemul_status string_status = win_crt_read_string(process, arg[0], &key, &length);
        if (string_status != XXEMUL_STATUS_OK || key == NULL) return string_status;
        while (offset + 1u < process->environment_size && process->environment_data[offset] != '\0') {
            const char *entry = process->environment_data + offset;
            if (win_environment_match(entry, key)) {
                *result = process->environment_a + offset + strlen(key) + 1u;
                break;
            }
            offset += strlen(entry) + 1u;
        }
        free(key);
        (void)length;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "tolower") == 0 || strcmp(name, "islower") == 0 || strcmp(name, "isspace") == 0 || strcmp(name, "isupper") == 0 || strcmp(name, "isxdigit") == 0) {
        int character = (int32_t)arg[0];
        if (character != -1 && (character < 0 || character > 255)) return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
        if (strcmp(name, "tolower") == 0) *result = (uint32_t)tolower(character);
        else if (strcmp(name, "islower") == 0) *result = islower(character) != 0;
        else if (strcmp(name, "isspace") == 0) *result = isspace(character) != 0;
        else if (strcmp(name, "isupper") == 0) *result = isupper(character) != 0;
        else *result = isxdigit(character) != 0;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "atoi") == 0) {
        char *end;
        long parsed;
        if (!win_guest_string(process, arg[0], text, sizeof(text), 0)) return XXEMUL_STATUS_ADDRESS_FAULT;
        parsed = strtol(text, &end, 10);
        *result = end == text ? 0u : (uint32_t)parsed;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "strtol") == 0 || strcmp(name, "strtoul") == 0) return win_crt_parse_number(process, arg, word_size, strcmp(name, "strtoul") == 0, result);
    if (strcmp(name, "_c_exit") == 0 || strcmp(name, "_cexit") == 0) {
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "_exit") == 0) {
        process->process_terminated=1u;
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
    if (strcmp(name, "SetFileApisToOEM") == 0 || strcmp(name, "SetConsoleCtrlHandler") == 0) {
        *result = 1u;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "GetLargePageMinimum") == 0) {
        *result = 0u;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "IsProcessorFeaturePresent") == 0) {
        uint32_t feat = (uint32_t)arg[0];
        if (feat == 2u || feat == 3u || feat == 6u || feat == 8u || feat == 10u || feat == 12u || feat == 13u || feat == 17u) {
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
            if (!win_load(process, arg[0] + idx, 2u, &c1) || !win_load(process, arg[1] + idx, 2u, &c2)) return XXEMUL_STATUS_ADDRESS_FAULT;
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
    if (strcmp(name, "GetDriveTypeW") == 0 || strcmp(name, "GetDriveTypeA") == 0) {
        *result = 3u;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "GetDiskFreeSpaceExW") == 0 || strcmp(name, "GetDiskFreeSpaceExA") == 0) {
        uint64_t bytes = 100ULL * 1024ULL * 1024ULL * 1024ULL;
        if (arg[1] != 0) win_store(process, arg[1], 8u, bytes);
        if (arg[2] != 0) win_store(process, arg[2], 8u, bytes * 2u);
        if (arg[3] != 0) win_store(process, arg[3], 8u, bytes);
        *result = 1u;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "GetVolumeInformationW") == 0) {
        static const uint16_t fs_name[] = {'N', 'T', 'F', 'S', 0};
        if (arg[3] != 0) win_store(process, arg[3], 4u, 0x12345678u);
        if (arg[4] != 0) win_store(process, arg[4], 4u, 255u);
        if (arg[5] != 0) win_store(process, arg[5], 4u, 0x00000003u);
        if (arg[6] != 0 && arg[7] >= sizeof(fs_name) / 2) win_write(process, arg[6], fs_name, sizeof(fs_name));
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
    if (strcmp(name, "GetLongPathNameW") == 0 || strcmp(name, "GetShortPathNameW") == 0 || strcmp(name, "ExpandEnvironmentStringsW") == 0) {
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
                if (w == 0) {
                    ++len;
                    break;
                }
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
            if (!has1 && !has2) {
                cmp = 0;
                break;
            }
            if (has1) win_load(process, arg[2] + i * (uint64_t)step, (uint8_t)step, &c1);
            if (has2) win_load(process, arg[4] + i * (uint64_t)step, (uint8_t)step, &c2);
            if (arg[1] & 1u) {
                if (c1 >= 'A' && c1 <= 'Z') c1 += 32;
                if (c2 >= 'A' && c2 <= 'Z') c2 += 32;
            }
            if (c1 != c2) {
                cmp = c1 < c2 ? -1 : 1;
                break;
            }
            if (c1 == 0) {
                cmp = 0;
                break;
            }
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
                if (!win_load(process, arg[1] + len * 2u, 2u, &w) || w == 0) {
                    ++len;
                    break;
                }
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
    if (strcmp(name, "OemToCharBuffW") == 0 || strcmp(name, "CharToOemBuffW") == 0 || strcmp(name, "CharToOemBuffA") == 0 || strcmp(name, "OemToCharBuffA") == 0) {
        int is_w = win_suffix(name, "W");
        size_t bytes = (size_t)arg[2] * (is_w ? 2u : 1u);
        if (arg[0] != arg[1] && bytes > 0 && bytes < WIN_MAX_IO) {
            uint8_t *tmp = (uint8_t *)malloc(bytes);
            if (tmp != NULL) {
                if (win_read(process, arg[0], tmp, bytes)) win_write(process, arg[1], tmp, bytes);
                free(tmp);
            }
        }
        *result = 1u;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "CharToOemA") == 0 || strcmp(name, "OemToCharA") == 0) {
        if (arg[0] != arg[1]) {
            char buf[1024];
            if (win_guest_string(process, arg[0], buf, sizeof(buf), 0)) win_write(process, arg[1], buf, strlen(buf) + 1);
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
    if (strcmp(name, "LookupPrivilegeValueW") == 0 || strcmp(name, "LookupPrivilegeValueA") == 0) {
        if (arg[2] != 0) win_store(process, arg[2], 8u, 0x1234u);
        *result = 1u;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "AdjustTokenPrivileges") == 0 || strcmp(name, "LsaAddAccountRights") == 0) {
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
    if (strcmp(name, "ConvertStringSidToSidW") == 0 || strcmp(name, "ConvertSidToStringSidW") == 0) {
        *result = 1u;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "CreateThread") == 0) return win_thread_create(process, arg, result);

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
    if (strcmp(name, "SystemTimeToTzSpecificLocalTime") == 0 || strcmp(name, "TzSpecificLocalTimeToSystemTime") == 0) {
        uint8_t st[16];
        if (win_read(process, arg[1], st, 16u)) win_write(process, arg[2], st, 16u);
        *result = 1u;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "CreateHardLinkW") == 0 || strcmp(name, "ExitWindowsEx") == 0 || strcmp(name, "SetSuspendState") == 0) {
        *result = 1u;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "SHGetMalloc") == 0) {
        uint64_t obj = process->runtime_base + WIN_SHELL_MALLOC_OFFSET;
        uint64_t vtbl = process->runtime_base + WIN_SHELL_MALLOC_OFFSET + 8u;
        uint64_t stub = process->runtime_base + WIN_SHELL_MALLOC_OFFSET + 0x80u;
        size_t i;
        word_size = (uint8_t)(win_word_size(process->emulator));
        if (word_size == 8u) {
            uint8_t ret_code[3] = {0x31, 0xc0, 0xc3}; /* xor eax, eax; ret */
            win_write(process, stub, ret_code, sizeof(ret_code));
        } else {
            uint8_t ret_code[4] = {0x31, 0xc0, 0xc2, 0x08}; /* xor eax, eax; ret 8 */
            win_write(process, stub, ret_code, sizeof(ret_code));
        }
        for (i = 0; i < 10; ++i) {
            win_store(process, vtbl + i * word_size, word_size, stub);
        }
        win_store(process, obj, word_size, vtbl);
        if (arg[0] != 0u) {
            if (!win_store(process, arg[0], word_size, obj)) return XXEMUL_STATUS_ADDRESS_FAULT;
        }
        *result = 0u; /* S_OK */
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "SHGetSpecialFolderLocation") == 0) {
        if (arg[2] != 0u) {
            uint64_t dummy_pidl = process->runtime_base + WIN_SHELL_MALLOC_OFFSET + 0x90u;
            if (!win_store(process, arg[2], win_word_size(process->emulator), dummy_pidl)) return XXEMUL_STATUS_ADDRESS_FAULT;
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
            if (!win_write_wide(process, arg[1], appdata, 260u)) return XXEMUL_STATUS_ADDRESS_FAULT;
        }
        *result = 1u; /* TRUE */
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "LoadStringW") == 0 || strcmp(name, "LoadStringA") == 0) {
        int wide = strcmp(name, "LoadStringW") == 0;
        uint32_t uid = (uint32_t)arg[1];
        uint64_t buffer = arg[2];
        uint32_t max_chars = (uint32_t)arg[3];
        if (!win_load_string(process, uid, buffer, max_chars, wide, result)) {
            if (max_chars > 0 && buffer != 0) {
                win_store(process, buffer, wide ? 2u : 1u, 0);
            }
            *result = 0u;
        }
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "ShellExecuteExW") == 0 || strcmp(name, "SHFileOperationW") == 0) {
        *result = 0u;
        return XXEMUL_STATUS_OK;
    }
    fprintf(stderr, "[xxemul API stub] %s::%s\n", api->module, name);
    *result = 0u;
    return XXEMUL_STATUS_OK;
}

static xxemul_status win_initterm_continue(xxemul_windows *process, uint64_t current_ip, xxemul_step_info *info)
{
    win_initterm_frame *frame;
    uint8_t word_size = (uint8_t)(win_word_size(process->emulator));
    uint64_t next_ip;
    if (process->initterm_depth == 0u) return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    frame = &process->initterm_frames[process->initterm_depth - 1u];
    for (;;) {
        uint64_t callback;
        uint64_t callback_sp;
        if (frame->cursor == frame->end) {
            next_ip = frame->return_address;
            process->emulator->x86.ip = next_ip;
            process->emulator->x86.gpr[XXEMUL_X86_RSP] = frame->call_sp + word_size;
            process->emulator->x86.gpr[XXEMUL_X86_RAX] = 0u;
            --process->initterm_depth;
            break;
        }
        if (!win_load(process, frame->cursor, word_size, &callback)) return XXEMUL_STATUS_ADDRESS_FAULT;
        frame->cursor += word_size;
        if (callback == 0u) continue;
        callback_sp = frame->call_sp - (word_size == 8u ? 48u : 16u);
        if (!win_store(process, callback_sp, word_size, process->runtime_base + WIN_INITTERM_RETURN_OFFSET)) return XXEMUL_STATUS_ADDRESS_FAULT;
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

static xxemul_status win_qsort_swap(xxemul_windows *process, const win_qsort_frame *frame, uint64_t left, uint64_t right)
{
    uint8_t first[4096], second[4096];
    uint64_t offset;
    uint64_t left_address = frame->base + left * frame->size;
    uint64_t right_address = frame->base + right * frame->size;
    for (offset = 0u; offset < frame->size;) {
        size_t chunk = (size_t)(frame->size - offset > sizeof(first) ? sizeof(first) : frame->size - offset);
        if (!win_read(process, left_address + offset, first, chunk) || !win_read(process, right_address + offset, second, chunk) ||
            !win_write(process, left_address + offset, second, chunk) || !win_write(process, right_address + offset, first, chunk))
            return XXEMUL_STATUS_ADDRESS_FAULT;
        offset += chunk;
    }
    return XXEMUL_STATUS_OK;
}

static xxemul_status win_qsort_compare(xxemul_windows *process, const win_qsort_frame *frame, uint64_t left, uint64_t right)
{
    uint8_t word_size = (uint8_t)(win_word_size(process->emulator));
    uint64_t reserved = word_size == 8u ? 48u : 16u;
    uint64_t callback_sp;
    if (frame->call_sp < reserved) return XXEMUL_STATUS_ADDRESS_FAULT;
    callback_sp = frame->call_sp - reserved;
    if (!win_store(process, callback_sp, word_size, process->runtime_base + WIN_QSORT_RETURN_OFFSET)) return XXEMUL_STATUS_ADDRESS_FAULT;
    if (word_size == 8u) {
        process->emulator->x86.gpr[XXEMUL_X86_RCX] = frame->base + left * frame->size;
        process->emulator->x86.gpr[XXEMUL_X86_RDX] = frame->base + right * frame->size;
    } else if (!win_store(process, callback_sp + 4u, 4u, frame->base + left * frame->size) ||
               !win_store(process, callback_sp + 8u, 4u, frame->base + right * frame->size))
        return XXEMUL_STATUS_ADDRESS_FAULT;
    process->emulator->x86.ip = frame->comparator;
    process->emulator->x86.gpr[XXEMUL_X86_RSP] = callback_sp;
    return XXEMUL_STATUS_OK;
}

static xxemul_status win_qsort_continue(xxemul_windows *process, uint64_t current_ip, xxemul_step_info *info)
{
    win_qsort_frame *frame;
    uint8_t word_size = (uint8_t)(win_word_size(process->emulator));
    xxemul_status status;
    uint64_t next_ip;
    if (process->qsort_depth == 0u) return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
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
                    process->emulator->x86.gpr[XXEMUL_X86_RSP] = frame->call_sp + word_size;
                    process->emulator->x86.gpr[XXEMUL_X86_RAX] = 0u;
                    --process->qsort_depth;
                    break;
                }
                --frame->heap_end;
                status = win_qsort_swap(process, frame, 0u, frame->heap_end);
                if (status != XXEMUL_STATUS_OK) return status;
                frame->root = 0u;
                frame->phase = WIN_QSORT_SIFT;
            }
        } else if (frame->phase == WIN_QSORT_SIFT) {
            if (frame->heap_end < 2u || frame->root > (frame->heap_end - 2u) / 2u) {
                frame->phase = WIN_QSORT_NEXT;
                continue;
            }
            frame->child = frame->root * 2u + 1u;
            frame->candidate = frame->root;
            frame->phase = WIN_QSORT_AFTER_LEFT;
            status = win_qsort_compare(process, frame, frame->candidate, frame->child);
            if (status != XXEMUL_STATUS_OK) return status;
            next_ip = frame->comparator;
            break;
        } else if (frame->phase == WIN_QSORT_AFTER_LEFT) {
            if ((int32_t)process->emulator->x86.gpr[XXEMUL_X86_RAX] < 0) frame->candidate = frame->child;
            if (frame->child + 1u < frame->heap_end) {
                frame->phase = WIN_QSORT_AFTER_RIGHT;
                status = win_qsort_compare(process, frame, frame->candidate, frame->child + 1u);
                if (status != XXEMUL_STATUS_OK) return status;
                next_ip = frame->comparator;
                break;
            }
            frame->phase = WIN_QSORT_CHECK;
        } else if (frame->phase == WIN_QSORT_AFTER_RIGHT) {
            if ((int32_t)process->emulator->x86.gpr[XXEMUL_X86_RAX] < 0) frame->candidate = frame->child + 1u;
            frame->phase = WIN_QSORT_CHECK;
        } else if (frame->phase == WIN_QSORT_CHECK) {
            if (frame->candidate == frame->root) {
                frame->phase = WIN_QSORT_NEXT;
            } else {
                status = win_qsort_swap(process, frame, frame->root, frame->candidate);
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

static int win_arm_try_step(xxemul_windows *process, xxemul_step_info *info, xxemul_status *status)
{
    xxemul *emulator = process->emulator;
    uint64_t ip = emulator->arm.pc, index, result = 0, return_address;
    uint64_t arguments[16] = {0};
    uint8_t word_size = win_word_size(emulator), register_count = word_size == 8u ? 8u : 4u;
    unsigned i;
    win_api *api;
    xxemul_status call_status;
    if (ip < process->runtime_base + WIN_THUNK_OFFSET) return 0;
    index = (ip - process->runtime_base - WIN_THUNK_OFFSET) / WIN_THUNK_STRIDE;
    if (index >= process->api_count || ip != process->runtime_base + WIN_THUNK_OFFSET + index * WIN_THUNK_STRIDE) return 0;
    api = &process->apis[index];
    /* The shared implementations below use guest-memory addresses and
     * scalar arguments. Register-context and guest-callback APIs require
     * architecture-specific implementations and are deliberately rejected. */
    if (strcmp(api->name, "LoadLibraryA") && strcmp(api->name, "LoadLibraryW") && strcmp(api->name, "LoadLibraryExA") &&
        strcmp(api->name, "LoadLibraryExW") && strcmp(api->name, "GetProcAddress") && strcmp(api->name, "VirtualProtect") &&
        strcmp(api->name, "FlushInstructionCache") && strcmp(api->name, "CacheSync") && strcmp(api->name, "ExitProcess") &&
        strcmp(api->name, "GetStdHandle") && strcmp(api->name, "WriteFile") && strcmp(api->name, "GetCurrentProcess") &&
        strcmp(api->name, "GetModuleHandleA") && strcmp(api->name, "GetModuleHandleW")) {
        *status = XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
        return 1;
    }
    for (i = 0; i < api->argument_count && i < 16; ++i) {
        if (i < register_count) arguments[i] = emulator->arm.gpr[i] & (word_size == 8u ? UINT64_MAX : UINT32_MAX);
        else if (!win_load(process, emulator->arm.sp + (uint64_t)(i - register_count) * word_size, word_size, &arguments[i])) {
            *status = XXEMUL_STATUS_ADDRESS_FAULT;
            return 1;
        }
    }
    return_address = emulator->arm.gpr[word_size == 8u ? 30u : 14u];
    if ((word_size == 8u && (return_address & 3u) != 0u) ||
        (word_size == 4u && (return_address & 3u) == 2u)) {
        *status = XXEMUL_STATUS_ADDRESS_FAULT;
        return 1;
    }
    call_status = win_call(process, api, arguments, &result);
    if (info != NULL) {
        info->address = ip;
        info->next_address = return_address & (word_size == 8u ? UINT64_MAX : ~UINT64_C(1));
        info->size = 4u;
        info->instruction_id = 0;
    }
    if (call_status == XXEMUL_STATUS_OK) {
        emulator->arm.gpr[0] = result & (word_size == 8u ? UINT64_MAX : UINT32_MAX);
        if (word_size == 4u) {
            emulator->mode = (return_address & 1u) != 0u ? XXEMUL_MODE_ARM_T32 : XXEMUL_MODE_ARM_A32;
            emulator->arm.pstate = (emulator->arm.pstate & ~UINT32_C(0x20)) | ((return_address & 1u) != 0u ? 0x20u : 0u);
            emulator->arm.pc = return_address & UINT32_C(0xfffffffe);
        } else emulator->arm.pc = return_address;
    }
    *status = call_status;
    return 1;
}

static int win_seh_context(xxemul_windows *process, win_seh_frame *frame, int restore)
{
    static const unsigned registers[7] = {7, 6, 3, 2, 1, 0, 5};
    static const unsigned segment_offsets[6] = {0x94, 0xbc, 0xc8, 0x98, 0x90, 0x8c};
    xxemul_x86_state state = frame->saved;
    uint64_t value;
    unsigned index;
    uint8_t zeros[0x2cc] = {0};
    if (!restore && (!win_write(process, frame->context, zeros, sizeof(zeros)) ||
                    !win_store(process, frame->context, 4u, 0x1003fu))) return 0;
    for (index = 0; index < 7; ++index) {
        if (restore) {
            if (!win_load(process, frame->context + 0x9cu + index * 4u, 4u, &value)) return 0;
            state.gpr[registers[index]] = value;
        } else if (!win_store(process, frame->context + 0x9cu + index * 4u, 4u, state.gpr[registers[index]])) return 0;
    }
    for (index = 0; index < 6; ++index) {
        if (restore) {
            if (!win_load(process, frame->context + segment_offsets[index], 4u, &value)) return 0;
            state.segment[index] = (uint16_t)value;
        } else if (!win_store(process, frame->context + segment_offsets[index], 4u, state.segment[index])) return 0;
    }
    if (restore) {
        if (!win_load(process, frame->context + 0xb8u, 4u, &state.ip) ||
            !win_load(process, frame->context + 0xc0u, 4u, &state.flags) ||
            !win_load(process, frame->context + 0xc4u, 4u, &state.gpr[XXEMUL_X86_RSP]) ||
            !win_read(process, frame->context + 0x16cu, state.xmm, 8u * 16u)) return 0;
        state.flags |= 2u;
        process->emulator->x86 = state;
    } else if (!win_store(process, frame->context + 0xb8u, 4u, state.ip) ||
               !win_store(process, frame->context + 0xc0u, 4u, state.flags) ||
               !win_store(process, frame->context + 0xc4u, 4u, state.gpr[XXEMUL_X86_RSP]) ||
               !win_write(process, frame->context + 0x16cu, state.xmm, 8u * 16u)) return 0;
    return 1;
}

static int win_seh_next(xxemul_windows *process, win_seh_frame *frame)
{
    uint64_t handler = 0, ignored;
    size_t count = process->vectored_handler_count;
    while (frame->vectored_cursor < count * 2u) {
        size_t ordinal = frame->vectored_cursor++;
        size_t index = ordinal < count ? count - ordinal - 1u : ordinal - count;
        win_vectored_handler *entry = &process->vectored_handlers[index];
        if (entry->active && (ordinal < count ? entry->first : !entry->first)) {
            handler = entry->callback;
            frame->vectored = 1;
            break;
        }
    }
    if (!handler) {
        frame->vectored = 0;
        if (!frame->registration || frame->registration == UINT32_MAX || ++frame->searched > 64u ||
            !win_load(process, frame->registration + 4u, 4u, &handler)) return 0;
    }
    if (!handler || !win_load(process, handler, 1u, &ignored) ||
        !win_store(process, frame->call_sp, 4u, process->runtime_base + WIN_SEH_RETURN_OFFSET) ||
        !win_store(process, frame->call_sp + 4u, 4u, frame->vectored ? frame->record + 0x60u : frame->record) ||
        !win_store(process, frame->call_sp + 8u, 4u, frame->registration) ||
        !win_store(process, frame->call_sp + 12u, 4u, frame->context) ||
        !win_store(process, frame->call_sp + 16u, 4u, 0u)) return 0;
    if (!frame->vectored && (!win_store(process, frame->dispatcher, 4u, frame->registration) ||
        !win_store(process, frame->dispatcher + 4u, 4u, 0u) || !win_store(process, process->runtime_base, 4u, frame->dispatcher))) return 0;
    process->emulator->x86 = frame->saved;
    process->emulator->x86.ip = handler;
    process->emulator->x86.gpr[XXEMUL_X86_RSP] = frame->call_sp;
    process->emulator->x86.flags &= ~UINT64_C(0x100);
    process->emulator->halted = 0;
    return 1;
}

int xxemul_windows_try_exception(xxemul_windows *process, const xxemul_x86_state *before, xxemul_status status, xxemul_step_info *info)
{
    win_seh_frame *frame;
    uint64_t registration, frame_base, fault_address;
    uint32_t code;
    unsigned fault_access;
    int has_vectored = 0;
    size_t index;
    if (!process || !before || process->emulator->mode != XXEMUL_MODE_X86_32 || process->seh_depth >= 8u ||
        (status != XXEMUL_STATUS_BREAKPOINT && status != XXEMUL_WINDOWS_SINGLE_STEP_FAULT && status != XXEMUL_STATUS_ADDRESS_FAULT &&
         status != XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION && status != XXEMUL_STATUS_DECODE_ERROR)) return 0;
    fault_address = process->emulator->fault_address;
    fault_access = process->emulator->fault_access;
    for (index = 0; index < process->vectored_handler_count; ++index)
        if (process->vectored_handlers[index].active) has_vectored = 1;
    if (!win_load(process, process->runtime_base, 4u, &registration) ||
        ((!registration || registration == UINT32_MAX) && !has_vectored) || before->gpr[XXEMUL_X86_RSP] < 0x500u) return 0;
    frame_base = (before->gpr[XXEMUL_X86_RSP] - 0x400u) & ~UINT64_C(15);
    frame = &process->seh_frames[process->seh_depth];
    memset(frame, 0, sizeof(*frame));
    frame->saved = *before;
    if (status == XXEMUL_STATUS_BREAKPOINT) frame->saved.ip = process->emulator->x86.ip;
    frame->call_sp = frame_base;
    frame->record = frame_base + 0x20u;
    frame->context = frame_base + 0x100u;
    frame->registration = registration;
    frame->original_registration = registration;
    frame->dispatcher = frame_base + 0x90u;
    frame->original_status = status;
    code = status == XXEMUL_STATUS_BREAKPOINT ? 0x80000003u : status == XXEMUL_WINDOWS_SINGLE_STEP_FAULT ? 0x80000004u : status == XXEMUL_STATUS_ADDRESS_FAULT ? 0xc0000005u : 0xc000001du;
    if (!win_seh_context(process, frame, 0) ||
        !win_store(process, frame->record, 4u, code) || !win_store(process, frame->record + 4u, 4u, 0u) ||
        !win_store(process, frame->record + 8u, 4u, 0u) || !win_store(process, frame->record + 12u, 4u, before->ip) ||
        !win_store(process, frame->record + 16u, 4u, status == XXEMUL_STATUS_ADDRESS_FAULT ? 2u : 0u) ||
        !win_store(process, frame->record + 20u, 4u, fault_access) ||
        !win_store(process, frame->record + 24u, 4u, process->emulator->fault_address_valid ? fault_address : 0u) ||
        !win_store(process, frame->record + 0x60u, 4u, frame->record) ||
        !win_store(process, frame->record + 0x64u, 4u, frame->context) || !win_seh_next(process, frame)) return 0;
    ++process->seh_depth;
    if (info) {
        memset(info, 0, sizeof(*info));
        info->address = before->ip;
        info->next_address = process->emulator->x86.ip;
    }
    return 1;
}

static xxemul_status win_seh_return(xxemul_windows *process, xxemul_step_info *info)
{
    win_seh_frame *frame;
    uint32_t result;
    int resume;
    if (!process->seh_depth) return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    frame = &process->seh_frames[process->seh_depth - 1u];
    result = (uint32_t)process->emulator->x86.gpr[XXEMUL_X86_RAX];
    resume = frame->vectored ? result == UINT32_MAX : result == 0u;
    if (resume) {
        if (!win_store(process, process->runtime_base, 4u, frame->original_registration)) return XXEMUL_STATUS_ADDRESS_FAULT;
        if (!win_seh_context(process, frame, 1)) return XXEMUL_STATUS_ADDRESS_FAULT;
        --process->seh_depth;
    } else {
        if (!frame->vectored && (result != 1u || !win_load(process, frame->registration, 4u, &frame->registration))) return frame->original_status;
        if (!win_seh_next(process, frame)) {
            win_store(process, process->runtime_base, 4u, frame->original_registration);
            process->emulator->x86 = frame->saved;
            --process->seh_depth;
            return frame->original_status;
        }
    }
    if (info) {
        memset(info, 0, sizeof(*info));
        info->address = process->runtime_base + WIN_SEH_RETURN_OFFSET;
        info->next_address = process->emulator->x86.ip;
    }
    return XXEMUL_STATUS_OK;
}

static void win_thread_save(xxemul_windows *process, win_thread_context *thread)
{
    xxemul *e = process->emulator;
    uint8_t width = win_word_size(e);
    thread->cpu = e->x86;
    memcpy(thread->x87_stack, e->x87_stack, sizeof(thread->x87_stack));
    memcpy(thread->x87_int_val, e->x87_int_val, sizeof(thread->x87_int_val));
    memcpy(thread->x87_is_int, e->x87_is_int, sizeof(thread->x87_is_int));
    thread->x87_depth = e->x87_depth; thread->x87_top = e->x87_top;
    thread->x87_control = e->x87_control; thread->x87_status = e->x87_status;
    memcpy(thread->tls_values, process->tls_values, sizeof(thread->tls_values));
    thread->last_error = process->last_error;
    (void)win_load(process, process->runtime_base, width, &thread->seh_head);
    (void)win_load(process, process->runtime_base + width, width, &thread->stack_base);
    (void)win_load(process, process->runtime_base + width * 2u, width, &thread->stack_limit);
    memcpy(thread->seh_frames, process->seh_frames, sizeof(thread->seh_frames)); thread->seh_depth = process->seh_depth;
    memcpy(thread->qsort_frames, process->qsort_frames, sizeof(thread->qsort_frames)); thread->qsort_depth = process->qsort_depth;
    memcpy(thread->initterm_frames, process->initterm_frames, sizeof(thread->initterm_frames)); thread->initterm_depth = process->initterm_depth;
}

static void win_thread_restore(xxemul_windows *process, const win_thread_context *thread)
{
    xxemul *e = process->emulator;
    uint8_t width = win_word_size(e);
    e->x86 = thread->cpu;
    memcpy(e->x87_stack, thread->x87_stack, sizeof(thread->x87_stack));
    memcpy(e->x87_int_val, thread->x87_int_val, sizeof(thread->x87_int_val));
    memcpy(e->x87_is_int, thread->x87_is_int, sizeof(thread->x87_is_int));
    e->x87_depth = thread->x87_depth; e->x87_top = thread->x87_top;
    e->x87_control = thread->x87_control; e->x87_status = thread->x87_status;
    memcpy(process->tls_values, thread->tls_values, sizeof(thread->tls_values));
    process->last_error = thread->last_error;
    (void)win_store(process, process->runtime_base + (width == 8u ? 0x68u : 0x34u), 4u, thread->last_error);
    (void)win_store(process, process->runtime_base, width, thread->seh_head);
    (void)win_store(process, process->runtime_base + width, width, thread->stack_base);
    (void)win_store(process, process->runtime_base + width * 2u, width, thread->stack_limit);
    (void)win_store(process, process->runtime_base + (width == 8u ? 0x58u : 0x2cu), width, thread->tls_array);
    (void)win_store(process, process->runtime_base + (width == 8u ? 0x40u : 0x20u), width, process->process_id);
    (void)win_store(process, process->runtime_base + (width == 8u ? 0x48u : 0x24u), width, thread->id);
    memcpy(process->seh_frames, thread->seh_frames, sizeof(thread->seh_frames)); process->seh_depth = thread->seh_depth;
    memcpy(process->qsort_frames, thread->qsort_frames, sizeof(thread->qsort_frames)); process->qsort_depth = thread->qsort_depth;
    memcpy(process->initterm_frames, thread->initterm_frames, sizeof(thread->initterm_frames)); process->initterm_depth = thread->initterm_depth;
}

static void win_thread_release_guest(xxemul_windows *process, win_thread_context *thread)
{
    win_allocation *allocation;
    allocation = win_find_allocation(process, thread->stack_allocation);
    if (allocation) allocation->active = 0u;
    win_tls_thread_release(process, thread);
    thread->stack_allocation = 0u;
}

static xxemul_status win_thread_create(xxemul_windows *process, const uint64_t *arg, uint64_t *result)
{
    size_t slot, handle_slot;
    uint64_t ignored, stack_size, stack, sp;
    uint8_t width = win_word_size(process->emulator);
    win_thread_context *thread;
    win_handle *handle;
    *result = 0u;
    if (process->emulator->arch != XXEMUL_ARCH_X86 || process->dll_exiting) {
        process->last_error = 120u; return XXEMUL_STATUS_OK;
    }
    if ((arg[4] & ~UINT64_C(0x10004)) || !arg[2] || !win_load(process, arg[2], 1u, &ignored) ||
        (arg[5] && !win_memory_span(process, arg[5], 4u))) { process->last_error = 87u; return XXEMUL_STATUS_OK; }
    for (slot = 1u; slot < WIN_MAX_THREADS && process->threads[slot].active; ++slot) {}
    for (handle_slot = 0u; handle_slot < WIN_MAX_HANDLES && process->handles[handle_slot].in_use; ++handle_slot) {}
    if (slot == WIN_MAX_THREADS || handle_slot == WIN_MAX_HANDLES || process->next_thread_id == UINT32_MAX ||
        (process->process_tree && process->process_tree->next_id==UINT32_MAX)) {
        process->last_error = 8u; return XXEMUL_STATUS_OK;
    }
    stack_size = arg[1] ? arg[1] : 0x100000u;
    if (stack_size < 0x10000u) stack_size = 0x10000u;
    if (stack_size > WIN_MAX_IO) { process->last_error = 8u; return XXEMUL_STATUS_OK; }
    stack = win_heap_alloc(process, stack_size);
    if (!stack) { process->last_error = 8u; return XXEMUL_STATUS_OK; }
    thread = &process->threads[slot]; memset(thread, 0, sizeof(*thread));
    thread->stack_allocation = stack;
    if (!win_tls_thread_create(process, thread)) {
        win_thread_release_guest(process, thread);
        process->last_error = 8u; return XXEMUL_STATUS_OK;
    }
    thread->stack_base = stack + stack_size; thread->stack_limit = stack;
    thread->seh_head = width == 4u ? UINT32_MAX : UINT64_MAX;
    thread->x87_control = 0x37fu;
    thread->cpu.flags = 0x202u;
    memcpy(thread->cpu.segment, process->emulator->x86.segment, sizeof(thread->cpu.segment));
    sp = (thread->stack_base & ~UINT64_C(15)) - (width == 8u ? 40u : 8u);
    thread->cpu.gpr[XXEMUL_X86_RSP] = sp;
    thread->start_address = arg[2];
    thread->cpu.ip = process->runtime_base + WIN_THREAD_START_OFFSET;
    if (width == 8u) thread->cpu.gpr[XXEMUL_X86_RCX] = arg[3];
    if (!win_store(process, sp, width, process->runtime_base + WIN_THREAD_RETURN_OFFSET) ||
        (width == 4u && !win_store(process, sp + 4u, width, arg[3]))) {
        win_thread_release_guest(process, thread); process->last_error = 998u; return XXEMUL_STATUS_OK;
    }
    thread->active = 1u; thread->handle_bound = 1u; thread->handle_slot = (uint16_t)handle_slot;
    (void)win_store(process, process->runtime_base + 0x19000u + slot * 8u, 4u, 0u);
    thread->suspended = (arg[4] & 4u) ? 1u : 0u;
    thread->id = process->process_tree?++process->process_tree->next_id:++process->next_thread_id;
    handle = &process->handles[handle_slot]; memset(handle, 0, sizeof(*handle));
    handle->kind = WIN_HANDLE_THREAD; handle->in_use = 1u;
    handle->references = 2u; /* public reference plus scheduler lifetime */
    handle->root_slot = (uint16_t)handle_slot; handle->thread_slot = (uint16_t)slot;
    handle->thread_start = arg[2]; handle->thread_parameter = arg[3];
    handle->object_id=thread->id;
    if (arg[5]) (void)win_store(process, arg[5], 4u, thread->id);
    *result = 0x100u + handle_slot;
    return XXEMUL_STATUS_OK;
}

static int win_thread_wait_ready(xxemul_windows *process, win_thread_context *thread, uint64_t *value)
{
    win_handle *entries[WIN_MAX_HANDLES];
    size_t i;
    int all = 1;
    for (i = 0u; i < thread->wait_count; ++i) {
        entries[i] = win_handle_at(process, thread->wait_handles[i]);
        if (!entries[i] || entries[i]->kind == WIN_HANDLE_FILE) { *value = UINT32_MAX; return 1; }
        if (!win_sync_ready(process,entries[i])) all = 0;
    }
    if (thread->wait_all && all) {
        for (i = 0u; i < thread->wait_count; ++i) win_sync_consume(entries[i]);
        *value = 0u; return 1;
    }
    if (!thread->wait_all) for (i = 0u; i < thread->wait_count; ++i) if (win_sync_ready(process,entries[i])) {
        win_sync_consume(entries[i]); *value = i; return 1;
    }
    return 0;
}

static xxemul_status win_thread_yield(xxemul_windows *process, xxemul_step_info *info)
{
    if(win_dll_thread_active(process))return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    size_t i, turn;
    win_thread_context *current = &process->threads[process->thread_current];
    /* SEH records/CONTEXT bytes use a shared runtime arena. Do not switch
     * a live exception handler until that arena is made thread-local. */
    if (process->seh_depth && current->active) return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    if (current->active && !process->child_waiting) win_thread_save(process, current);
    process->child_waiting=0u;
    {
        xxemul_status child_status=win_children_pump(process,0x1000u);
        if(child_status!=XXEMUL_STATUS_OK)return child_status;
    }
    ++process->scheduler_tick; process->virtual_tick = (uint32_t)process->scheduler_tick;
    for (;;) {
        uint64_t earliest = UINT64_MAX;
        int active = 0;
        for (i = 0u; i < WIN_MAX_THREADS; ++i) {
            win_thread_context *thread = &process->threads[i];
            uint64_t value = 0u;
            if (!thread->active) continue;
            active = 1;
            if (thread->blocked == 2u && win_thread_wait_ready(process, thread, &value)) {
                thread->cpu.gpr[XXEMUL_X86_RAX] = value; thread->blocked = 0u;
                if (value == UINT32_MAX) thread->last_error = 6u;
            } else if (thread->blocked && thread->deadline <= process->scheduler_tick) {
                if (thread->blocked == 2u) thread->cpu.gpr[XXEMUL_X86_RAX] = 0x102u;
                thread->blocked = 0u;
            }
            if (thread->blocked && !thread->suspended && thread->deadline < earliest) earliest = thread->deadline;
        }
        if (!active) {
            process->process_terminated=1u;
            process->emulator->halted = 1; process->emulator->exit_code = (uint8_t)process->exit_code;
            return XXEMUL_STATUS_HALTED;
        }
        for (turn = 1u; turn <= WIN_MAX_THREADS; ++turn) {
            size_t next = (process->thread_current + turn) % WIN_MAX_THREADS;
            win_thread_context *thread = &process->threads[next];
            if (thread->active && !thread->blocked && !thread->suspended) {
                process->thread_current = (unsigned)next;
                win_thread_restore(process, thread);
                if (info) info->next_address = thread->cpu.ip;
                return XXEMUL_STATUS_OK;
            }
        }
        if (win_children_runnable(process)) {
            process->child_waiting=1u;
            process->emulator->x86.ip=process->runtime_base+WIN_CHILD_WAIT_OFFSET;
            if(info)info->next_address=process->emulator->x86.ip;
            return XXEMUL_STATUS_OK;
        }
        if (earliest == UINT64_MAX) return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
        process->scheduler_tick = earliest;
        process->virtual_tick = (uint32_t)earliest;
    }
}

static win_dialog_frame *win_dialog_current(xxemul_windows *process)
{
    win_dialog_frame *result=NULL;size_t i;uint32_t owner=process->threads[process->thread_current].id;
    for(i=0u;i<WIN_GUI_DIALOGS;++i){win_dialog_frame *frame=&process->dialogs[i];
        if(frame->active&&frame->owner_id==owner&&(!result||frame->sequence>result->sequence))result=frame;
    }
    return result;
}
static xxemul_status win_dialog_invoke(xxemul_windows *process,win_dialog_frame *frame,xxemul_step_info *info)
{
    xxemul *emulator=process->emulator;uint8_t width=win_word_size(emulator);
    uint64_t sp=(frame->caller.gpr[XXEMUL_X86_RSP]&~UINT64_C(15))-(width==8u?40u:32u);
    uint64_t message=frame->phase==1u?0x30u:0x110u;
    uint64_t wparam=frame->phase==1u?win_gui_at(process,frame->handle)->font:win_gui_initial_focus(process,frame->handle);
    uint64_t lparam=frame->phase==1u?0u:frame->parameter;
    if(!win_store(process,sp,width,process->runtime_base+WIN_DIALOG_RETURN_OFFSET))return XXEMUL_STATUS_ADDRESS_FAULT;
    emulator->x86=frame->caller;
    if(width==8u){
        emulator->x86.gpr[XXEMUL_X86_RCX]=frame->handle;emulator->x86.gpr[XXEMUL_X86_RDX]=message;
        emulator->x86.gpr[XXEMUL_X86_R8]=wparam;emulator->x86.gpr[XXEMUL_X86_R9]=lparam;
    }else if(!win_store(process,sp+4u,4u,frame->handle)||!win_store(process,sp+8u,4u,message)||
             !win_store(process,sp+12u,4u,wparam)||!win_store(process,sp+16u,4u,lparam))return XXEMUL_STATUS_ADDRESS_FAULT;
    emulator->x86.gpr[XXEMUL_X86_RSP]=sp;emulator->x86.ip=frame->procedure;
    if(info)info->next_address=frame->procedure;
    return XXEMUL_STATUS_OK;
}
static xxemul_status win_dialog_finish(xxemul_windows *process,win_dialog_frame *frame,xxemul_step_info *info)
{
    xxemul_x86_state caller=frame->caller;uint64_t result=frame->result;
    (void)win_close_handle(process,frame->event);win_gui_discard(process,frame->handle);memset(frame,0,sizeof(*frame));
    process->emulator->x86=caller;process->emulator->x86.gpr[XXEMUL_X86_RAX]=win_word_size(process->emulator)==8u?result:(uint32_t)result;
    if(info)info->next_address=caller.ip;
    return XXEMUL_STATUS_OK;
}
static xxemul_status win_dialog_return(xxemul_windows *process,int waited,xxemul_step_info *info)
{
    win_dialog_frame *frame=win_dialog_current(process);win_thread_context *thread;
    size_t i;int others=0;
    if(!frame)return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    if(frame->ended)return win_dialog_finish(process,frame,info);
    if(!waited&&frame->phase==1u){frame->phase=2u;return win_dialog_invoke(process,frame,info);}
    frame->phase=3u;process->emulator->x86=frame->caller;
    process->emulator->x86.ip=process->runtime_base+WIN_DIALOG_WAIT_OFFSET;
    thread=&process->threads[process->thread_current];thread->blocked=2u;thread->deadline=UINT64_MAX;
    thread->wait_count=1u;thread->wait_handles[0]=frame->event;thread->wait_all=0u;
    for(i=0u;i<WIN_MAX_THREADS;++i)if(i!=process->thread_current&&process->threads[i].active&&!process->threads[i].suspended)others=1;
    if(!others)return XXEMUL_STATUS_INPUT_REQUIRED;
    return win_thread_yield(process,info);
}

static void win_thread_end(xxemul_windows *process, size_t slot, uint32_t code)
{
    win_thread_context *thread = &process->threads[slot];
    if (!thread->active) return;
    {
        size_t index;
        for (index=0u;index<WIN_GUI_DIALOGS;++index) {
            win_dialog_frame *dialog=&process->dialogs[index];
            if (!dialog->active || dialog->owner_id!=thread->id) continue;
            (void)win_close_handle(process,dialog->event);
            win_gui_discard(process,dialog->handle);
            memset(dialog,0,sizeof(*dialog));
        }
    }
    if (thread->handle_bound) {
        win_handle *handle = &process->handles[thread->handle_slot];
        handle->thread_exit = code; handle->thread_finished = 1u;
        if (--handle->references == 0u) memset(handle, 0, sizeof(*handle));
    }
    win_thread_release_guest(process, thread);
    thread->active = 0u;thread->exit_code=code;process->exit_code = code;

}

static xxemul_status win_thread_finish_raw(xxemul_windows *process, uint32_t code, xxemul_step_info *info)
{
    if (!process->threads[process->thread_current].active) return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    win_thread_end(process, process->thread_current, code);
    return win_thread_yield(process, info);
}

static xxemul_status win_thread_finish(xxemul_windows *process, uint32_t code, xxemul_step_info *info)
{
    win_thread_context *thread = &process->threads[process->thread_current];
    if (!thread->active || win_dll_thread_active(process)) return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    if (win_dll_last_thread(process)) {
        if (win_dll_exit_needed(process)) return win_dll_exit(process, code, info);
        return win_thread_finish_raw(process, code, info);
    }
    thread->detaching = 1u;
    return win_dll_thread_begin(process, 3u, code, info);
}

int xxemul_windows_try_step(xxemul_windows *process, xxemul_step_info *info, xxemul_status *status)
{
    uint64_t ip, index, return_address, value = 0;
    uint64_t arguments[16] = {0};
    uint8_t word_size, i;
    win_api *api;
    xxemul_status call_status;
    uint32_t wait_timeout = 0u;
    int wait_single = 0, wait_multiple = 0;

    if (process == NULL || status == NULL) return 0;
    if (process->emulator->arch == XXEMUL_ARCH_ARM) return win_arm_try_step(process, info, status);
    ip = process->emulator->x86.ip;
    if (process->startup_pending) {
        process->startup_pending = 0u;
        process->tls_started = 1;
        if (ip == process->runtime_base + WIN_LOADER_START_OFFSET) process->emulator->x86.ip = process->loader_entry;
        *status = win_dll_startup_begin(process, info);
        return 1;
    }
    if(ip==process->runtime_base+WIN_DLL_RETURN_OFFSET){*status=win_dll_continue(process,1,info);return 1;}
    if(!process->dll_depth){size_t dll_slot;if(win_dll_uninitialized(process,&dll_slot)){
        *status=win_dll_begin(process,dll_slot,0,1,info);return 1;}}
    if(ip==process->runtime_base+WIN_CHILD_WAIT_OFFSET && process->child_waiting) {
        *status=win_thread_yield(process,info);return 1;
    }
    if((++process->child_tick&63u)==0u) {
        xxemul_status child_status=win_children_pump(process,8u);
        if(child_status!=XXEMUL_STATUS_OK){*status=child_status;return 1;}
    }
    if (ip == process->runtime_base + WIN_DIALOG_RETURN_OFFSET || ip == process->runtime_base + WIN_DIALOG_WAIT_OFFSET) {
        *status = win_dialog_return(process, ip == process->runtime_base + WIN_DIALOG_WAIT_OFFSET, info); return 1;
    }
    if (ip == process->runtime_base + WIN_THREAD_RETURN_OFFSET) {
        if(win_dll_last_thread(process)&&win_dll_exit_needed(process)){*status=win_dll_exit(process,(uint32_t)process->emulator->x86.gpr[XXEMUL_X86_RAX],info);return 1;}
        *status = win_thread_finish(process, (uint32_t)process->emulator->x86.gpr[XXEMUL_X86_RAX], info);
        return 1;
    }
    while (process->seh_depth && ip != process->runtime_base + WIN_SEH_RETURN_OFFSET) {
        win_seh_frame *frame = &process->seh_frames[process->seh_depth - 1u];
        uint64_t head;
        if (process->emulator->x86.gpr[XXEMUL_X86_RSP] < frame->saved.gpr[XXEMUL_X86_RSP] ||
            !win_load(process, process->runtime_base, 4u, &head) || head == frame->dispatcher) break;
        /* Some native handlers unwind their registration and resume with a
         * direct RET instead of returning an EXCEPTION_DISPOSITION. */
        --process->seh_depth;
    }
    if (!process->tls_started && !process->dll_depth) {
        process->tls_started = 1;
        if (process->main_tls.callbacks) { *status = win_dll_main_begin(process, info); return 1; }
    }
    if (!process->dll_depth && !process->threads[process->thread_current].notify_started) {
        win_thread_context *thread = &process->threads[process->thread_current];
        thread->notify_started = 1u;
        if (ip == process->runtime_base + WIN_THREAD_START_OFFSET) process->emulator->x86.ip = thread->start_address;
        *status = win_dll_thread_begin(process, 2u, 0u, info);
        return 1;
    }
    if (ip == process->runtime_base + WIN_SEH_RETURN_OFFSET) {
        *status = win_seh_return(process, info);
        return 1;
    }
    if (ip == process->runtime_base + WIN_PROCESS_RETURN_OFFSET) {
        if (process->main_dll_slot && process->main_dll_complete) {
            process->emulator->halted = 1u;
            process->emulator->exit_code = (uint8_t)process->exit_code;
            *status = XXEMUL_STATUS_HALTED;
            return 1;
        }
        if(win_dll_exit_needed(process)){*status=win_dll_exit(process,(uint32_t)process->emulator->x86.gpr[XXEMUL_X86_RAX],info);return 1;}
        process->process_terminated=1u;
        process->exit_code = (uint32_t)process->emulator->x86.gpr[XXEMUL_X86_RAX];
        process->emulator->exit_code = (uint8_t)process->exit_code;
        process->emulator->halted = 1;
        *status = XXEMUL_STATUS_HALTED;
        if (info != NULL) {
            memset(info, 0, sizeof(*info));
            info->address = ip;
            info->next_address = ip;
        }
        return 1;
    }
    if (ip == process->runtime_base + WIN_INITTERM_RETURN_OFFSET) {
        *status = win_initterm_continue(process, ip, info);
        return 1;
    }
    if (ip == process->runtime_base + WIN_QSORT_RETURN_OFFSET) {
        *status = win_qsort_continue(process, ip, info);
        return 1;
    }
    if (ip < process->runtime_base + WIN_THUNK_OFFSET) return 0;
    index = (ip - process->runtime_base - WIN_THUNK_OFFSET) / WIN_THUNK_STRIDE;
    if (index >= process->api_count || ip != process->runtime_base + WIN_THUNK_OFFSET + index * WIN_THUNK_STRIDE) return 0;
    api = &process->apis[index];
    word_size = (uint8_t)(win_word_size(process->emulator));
    if (!win_load(process, process->emulator->x86.gpr[XXEMUL_X86_RSP], word_size, &return_address)) {
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
    if (strcmp(api->name, "_initterm") == 0 || strcmp(api->name, "_initterm_e") == 0) {
        win_initterm_frame *frame;
        if (process->initterm_depth >= WIN_MAX_INITTERM_DEPTH || arguments[1] < arguments[0] || arguments[1] - arguments[0] > (uint64_t)word_size * 4096u ||
            (arguments[1] - arguments[0]) % word_size != 0u) {
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
        if (process->qsort_depth >= WIN_MAX_QSORT_DEPTH || arguments[1] > WIN_MAX_QSORT_ELEMENTS ||
            (arguments[1] > 1u && (arguments[0] == 0u || arguments[2] == 0u || arguments[3] == 0u || arguments[2] > WIN_MAX_IO / arguments[1] ||
                                   arguments[0] > UINT64_MAX - arguments[1] * arguments[2]))) {
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
    if (strcmp(api->name, "TerminateThread") == 0) {
        win_handle *entry = win_handle_at(process, arguments[0]);
        uint64_t pseudo = word_size == 8u ? UINT64_MAX - 1u : UINT32_MAX - 1u;
        if (arguments[0] == pseudo || (entry && entry->kind == WIN_HANDLE_THREAD && !entry->child_slot &&
            !entry->thread_finished && entry->thread_slot == process->thread_current &&
            entry->object_id == process->threads[process->thread_current].id)) {
            if (win_dll_thread_active(process)) { *status = XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION; return 1; }
            *status = win_thread_finish_raw(process, (uint32_t)arguments[1], info);
            return 1;
        }
    }
    if (strcmp(api->name, "ExitThread") == 0 && process->threads[process->thread_current].active) {
        if(win_dll_last_thread(process)&&win_dll_exit_needed(process)){*status=win_dll_exit(process,(uint32_t)arguments[0],info);return 1;}
        if(win_dll_thread_active(process)){*status=XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;return 1;}
        *status = win_thread_finish(process, (uint32_t)arguments[0], info);
        return 1;
    }
    wait_single = strcmp(api->name, "WaitForSingleObject") == 0;
    wait_multiple = strcmp(api->name, "WaitForMultipleObjects") == 0;
    if (wait_single || wait_multiple) {
        unsigned timeout_index = wait_single ? 1u : 3u;
        wait_timeout = (uint32_t)arguments[timeout_index];
        arguments[timeout_index] = 0u;
    }
    {
        uint64_t teb_error;
        if (win_load(process, process->runtime_base + (word_size == 8u ? 0x68u : 0x34u), 4u, &teb_error))
            process->last_error = (uint32_t)teb_error;
    }
    if((win_equal(api->name,"ExitProcess")||win_equal(api->name,"exit")||win_equal(api->name,"_exit"))&&win_dll_exit_needed(process)){*status=win_dll_exit(process,(uint32_t)arguments[0],info);return 1;}
    call_status = win_call(process, api, arguments, &value);
    (void)win_store(process, process->runtime_base + (word_size == 8u ? 0x68u : 0x34u), 4u, process->last_error);
    if (call_status != XXEMUL_STATUS_OK && call_status != XXEMUL_STATUS_HALTED) {
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
        process->emulator->x86.gpr[XXEMUL_X86_RSP] += word_size == 8u ? 8u : 4u + (api->caller_cleans ? 0u : (uint64_t)api->argument_count * 4u);
        process->emulator->x86.gpr[XXEMUL_X86_RAX] = word_size == 8u ? value : (uint32_t)value;
        if(process->dll_pending){size_t dll_slot=process->dll_pending-1u;int unloading=process->dll_pending_unload;
            process->dll_pending=0u;process->dll_pending_unload=0u;
            *status=win_dll_begin(process,dll_slot,unloading,0,info);return 1;}
        {size_t dll_slot;if(win_dll_uninitialized(process,&dll_slot)){
            *status=win_dll_begin(process,dll_slot,0,0,info);return 1;}}
        if (process->dialog_pending && (win_equal(api->name,"DialogBoxParamA") || win_equal(api->name,"DialogBoxParamW"))) {
            win_dialog_frame *frame=&process->dialogs[process->dialog_pending-1u];
            process->dialog_pending=0u;frame->caller=process->emulator->x86;
            frame->phase=win_gui_at(process,frame->handle)->font?1u:2u;
            *status=win_dialog_invoke(process,frame,info);return 1;
        }
        {
            win_thread_context *thread = &process->threads[process->thread_current];
            int yield = win_equal(api->name,"EndDialog") && value;
            if ((wait_single || wait_multiple) && value == 0x102u && wait_timeout) {
                size_t index;
                thread->blocked = 2u;
                thread->deadline = wait_timeout == UINT32_MAX ? UINT64_MAX : process->scheduler_tick + wait_timeout;
                thread->wait_count = wait_single ? 1u : (size_t)arguments[0];
                thread->wait_all = (uint8_t)(!wait_single && arguments[2]);
                for (index = 0u; index < thread->wait_count; ++index) {
                    if (wait_single) thread->wait_handles[index] = arguments[0];
                    else (void)win_load(process, arguments[1] + index * word_size, word_size, &thread->wait_handles[index]);
                }
                yield = 1;
            }
            if (strcmp(api->name, "Sleep") == 0 || strcmp(api->name, "SleepEx") == 0) {
                uint32_t delay = (uint32_t)arguments[0];
                if (delay) {
                    thread->blocked = 1u;
                    thread->deadline = delay == UINT32_MAX ? UINT64_MAX : process->scheduler_tick + delay;
                }
                yield = 1;
            }
            if ((strcmp(api->name, "CreateThread") == 0 && value) ||
                ((strcmp(api->name, "ResumeThread") == 0 || strcmp(api->name, "SuspendThread") == 0) && value != UINT32_MAX) ||
                strcmp(api->name, "SwitchToThread") == 0) yield = 1;
            if (yield && win_dll_thread_active(process) &&
                (win_equal(api->name, "CreateThread") || win_equal(api->name, "ResumeThread"))) yield = 0;
            if (yield) { *status = win_thread_yield(process, info); return 1; }
        }
    }
    *status = call_status;
    return 1;
}
