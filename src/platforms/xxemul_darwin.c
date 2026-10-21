#include "xxemul_darwin.h"
#include "../xxemul_internal.h"
#include "../xxemul_arm_auth.h"
#include "xxemul_darwin_posix.h"
#include "xxemul_darwin_archive.h"
#include "xxemul_darwin_zlib.h"
#include "xxemul_darwin_bzip2.h"

#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DARWIN_ARENA_SIZE ((uint64_t)XXEMUL_DARWIN_ARENA_SIZE)
#define DARWIN_MAX_THUNKS 256u
#define DARWIN_MAX_STRING UINT64_C(1048576)
#define DARWIN_COUT_OFFSET UINT64_C(0x100)
#define DARWIN_CERR_OFFSET UINT64_C(0x200)
#define DARWIN_COUT_BUFFER_OFFSET UINT64_C(0x400)
#define DARWIN_CERR_BUFFER_OFFSET UINT64_C(0x480)
#define DARWIN_FACET_OFFSET UINT64_C(0x500)
#define DARWIN_LOCALE_OFFSET UINT64_C(0x600)
#define DARWIN_CTYPE_ID_OFFSET UINT64_C(0x680)
#define DARWIN_OSTREAM_VTABLE_OFFSET UINT64_C(0x800)
#define DARWIN_STREAMBUF_VTABLE_OFFSET UINT64_C(0x900)
#define DARWIN_FACET_VTABLE_OFFSET UINT64_C(0xa00)
#define DARWIN_C_LOCALE_NAME_OFFSET UINT64_C(0x1420)
#define DARWIN_OPTARG_OFFSET UINT64_C(0x1430)
#define DARWIN_OPTIND_OFFSET UINT64_C(0x1438)
#define DARWIN_OPTERR_OFFSET UINT64_C(0x143c)
#define DARWIN_OPTOPT_OFFSET UINT64_C(0x1440)
#define DARWIN_OPTRESET_OFFSET UINT64_C(0x1444)
#define DARWIN_BASENAME_OFFSET UINT64_C(0x6000)
#define DARWIN_DIRNAME_OFFSET UINT64_C(0x7000)
#define DARWIN_THUNK_OFFSET UINT64_C(0x2000)
#define DARWIN_HEAP_OFFSET UINT64_C(0x10000)

enum darwin_call {
    CALL_RETURN, CALL_STRLEN, CALL_SENTRY_CTOR, CALL_SENTRY_DTOR,
    CALL_GETLOC, CALL_USE_FACET, CALL_LOCALE_DTOR, CALL_WIDEN,
    CALL_XSPUTN, CALL_OVERFLOW, CALL_SYNC, CALL_STRING_INIT,
    CALL_STRING_DTOR, CALL_IOS_CLEAR, CALL_WRITE, CALL_EXIT,
    CALL_LIBC, CALL_POSIX, CALL_QSORT_RETURN, CALL_ARCHIVE, CALL_ARCHIVE_RETURN, CALL_ZLIB, CALL_BZIP2, CALL_UNSUPPORTED
};

struct darwin_thunk {
    char name[192];
    enum darwin_call call;
};

struct xxemul_darwin {
    xxemul *emulator;
    uint64_t base;
    uint64_t heap;
    uint64_t return_address;
    unsigned thunk_count;
    struct darwin_thunk thunks[DARWIN_MAX_THUNKS];
    int started;
    int exited;
    int exit_code;
    xxemul_darwin_posix *posix;
    xxemul_darwin_archive *archive;
    xxemul_darwin_zlib *zlib;
    xxemul_darwin_bzip2 *bzip2;
    uint64_t archive_lr, archive_sp;
    int archive_callback_active;
    struct { uint64_t address, size; int free; } allocations[4096];
    unsigned allocation_count;
    struct { uint64_t base, count, size, compare, i, j, lr; } sorts[8];
    unsigned sort_depth;
    int redirect;
    uint32_t random_state;
    int kernel_entry, packed_entry, dyld_bound;
    uint8_t *kernel_image;
    size_t kernel_image_size;
    uint64_t kernel_sp, main_argc, main_argv, main_envp, main_apple;
    uint64_t getopt_next, getopt_argv;
    unsigned getopt_first, getopt_last, getopt_index, getopt_argc;
    int getopt_finished;
    char error[256];
};

static xxemul_status darwin_error(xxemul_darwin *process, xxemul_status status, const char *message)
{
    if (process != NULL) snprintf(process->error, sizeof(process->error), "%s", message);
    return status;
}

static int guest_range(const xxemul_darwin *process, uint64_t address, uint64_t count)
{
    const xxemul *emulator = process->emulator;
    uint64_t relative;
    if (address < emulator->region_address) return 0;
    relative = address - emulator->region_address;
    return relative <= emulator->region_size && count <= emulator->region_size - relative;
}

static int store(xxemul_darwin *process, uint64_t address, unsigned bytes, uint64_t value)
{
    return xxemul_store_integer(process->emulator, address, (uint8_t)bytes, value) == XXEMUL_STATUS_OK;
}

static int load(xxemul_darwin *process, uint64_t address, unsigned bytes, uint64_t *value)
{
    return xxemul_load_integer(process->emulator, address, (uint8_t)bytes, value) == XXEMUL_STATUS_OK;
}

static uint64_t allocate_guest(xxemul_darwin *process, uint64_t count)
{
    uint64_t address = process->heap;
    uint64_t aligned;
    if (count > DARWIN_ARENA_SIZE || count > UINT64_MAX - 15u) return 0;
    aligned = (count + 15u) & ~UINT64_C(15);
    if (address > process->base + DARWIN_ARENA_SIZE || aligned > process->base + DARWIN_ARENA_SIZE - address) return 0;
    process->heap += aligned;
    return address;
}

static uint64_t heap_malloc(xxemul_darwin *process, uint64_t count);

static uint64_t bridge_allocate(void *context, uint64_t count)
{
    /* POSIX may return caller-owned storage, such as realpath(path, NULL).
     * Use the same allocation records as the guest malloc/free imports. */
    return heap_malloc((xxemul_darwin *)context, count);
}

static uint32_t rune_type(unsigned c)
{
    uint32_t value = 0;
    int upper = c >= 'A' && c <= 'Z';
    int lower = c >= 'a' && c <= 'z';
    int digit = c >= '0' && c <= '9';
    int graph = c >= 33u && c <= 126u;
    if (c >= 128u) return 0;
    if (upper || lower) value |= 0x100u;
    if (c < 32u || c == 127u) value |= 0x200u;
    if (digit) value |= 0x400u | (c - '0');
    if (graph) value |= 0x800u;
    if (lower) value |= 0x1000u;
    if (graph && !upper && !lower && !digit) value |= 0x2000u;
    if (c == ' ' || (c >= '\t' && c <= '\r')) value |= 0x4000u;
    if (upper) value |= 0x8000u;
    if (digit || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f')) value |= 0x10000u;
    if (c == ' ' || c == '\t') value |= 0x20000u;
    if (c >= 32u && c <= 126u) value |= 0x40000u | 0x40000000u;
    return value;
}

static uint64_t add_thunk(xxemul_darwin *process, const char *name, enum darwin_call call)
{
    uint64_t address;
    unsigned i;
    for (i = 0; i < process->thunk_count; ++i) {
        if (strcmp(process->thunks[i].name, name) == 0) return process->base + DARWIN_THUNK_OFFSET + i * 16u;
    }
    if (process->thunk_count == DARWIN_MAX_THUNKS || strlen(name) >= sizeof(process->thunks[0].name)) return 0;
    i = process->thunk_count++;
    snprintf(process->thunks[i].name, sizeof(process->thunks[i].name), "%s", name);
    process->thunks[i].call = call;
    address = process->base + DARWIN_THUNK_OFFSET + i * 16u;
    /* BRK prevents accidentally treating a thunk as a native guest function
     * before start_process installs the runtime dispatch. */
    if (!store(process, address, 4, UINT32_C(0xd4200000))) return 0;
    return address;
}

static int initialize_ostream(xxemul_darwin *process, uint64_t object, uint64_t buffer)
{
    uint64_t ios = object + 8u;
    return store(process, object, 8, process->base + DARWIN_OSTREAM_VTABLE_OFFSET + 24u) &&
           store(process, ios, 8, process->base + DARWIN_OSTREAM_VTABLE_OFFSET + 24u) &&
           store(process, ios + 8u, 4, UINT32_C(0x1002)) && /* skipws | dec */
           store(process, ios + 16u, 8, 6u) &&
           store(process, ios + 40u, 8, buffer) &&
           store(process, ios + 48u, 8, process->base + DARWIN_LOCALE_OFFSET) &&
           store(process, ios + 144u, 4, UINT32_MAX) &&
           store(process, buffer, 8, process->base + DARWIN_STREAMBUF_VTABLE_OFFSET) &&
           store(process, buffer + 8u, 8, process->base + DARWIN_LOCALE_OFFSET);
}

xxemul_darwin *xxemul_darwin_create(xxemul *emulator, uint64_t runtime_base, xxemul_status *status)
{
    xxemul_darwin *process;
    uint64_t unsupported, xsputn, overflow, sync, widen;
    unsigned i;
    if (status != NULL) *status = XXEMUL_STATUS_INVALID_ARGUMENT;
    if (emulator == NULL || emulator->arch != XXEMUL_ARCH_ARM || emulator->mode != XXEMUL_MODE_ARM_A64 ||
        runtime_base < emulator->region_address || (runtime_base & 15u) != 0u ||
        runtime_base - emulator->region_address > emulator->region_size ||
        DARWIN_ARENA_SIZE > emulator->region_size - (runtime_base - emulator->region_address)) return NULL;
    process = (xxemul_darwin *)calloc(1, sizeof(*process));
    if (process == NULL) { if (status != NULL) *status = XXEMUL_STATUS_OUT_OF_MEMORY; return NULL; }
    process->emulator = emulator;
    process->base = runtime_base;
    process->heap = runtime_base + DARWIN_HEAP_OFFSET;
    process->exit_code = -1;
    process->random_state = 1;
    memset(emulator->region_data + (size_t)(runtime_base - emulator->region_address), 0, (size_t)DARWIN_ARENA_SIZE);
    process->return_address = add_thunk(process, "<Darwin main return>", CALL_RETURN);
    unsupported = add_thunk(process, "<unsupported libc++ virtual method>", CALL_UNSUPPORTED);
    xsputn = add_thunk(process, "std::__1::streambuf::xsputn", CALL_XSPUTN);
    overflow = add_thunk(process, "std::__1::streambuf::overflow", CALL_OVERFLOW);
    sync = add_thunk(process, "std::__1::streambuf::sync", CALL_SYNC);
    widen = add_thunk(process, "std::__1::ctype<char>::do_widen", CALL_WIDEN);
    add_thunk(process, "<Darwin qsort compare return>", CALL_QSORT_RETURN);
    store(process, runtime_base + 0x1410u, 8, UINT64_C(0x71535a4b01931f00));
    store(process, runtime_base + DARWIN_C_LOCALE_NAME_OFFSET, 2, 'C');
    store(process, runtime_base + DARWIN_OPTIND_OFFSET, 4, 1);
    store(process, runtime_base + DARWIN_OPTERR_OFFSET, 4, 1);
    xxemul_write_memory(emulator, runtime_base + 0x5000u, "RuneMagA", 8);
    xxemul_write_memory(emulator, runtime_base + 0x5008u, "NONE", 5);
    for (i = 0; i < 256u; ++i) {
        store(process, runtime_base + 0x5000u + 60u + i * 4u, 4, rune_type(i));
        store(process, runtime_base + 0x5000u + 1084u + i * 4u, 4, i >= 'A' && i <= 'Z' ? i - 'A' + 'a' : i);
        store(process, runtime_base + 0x5000u + 2108u + i * 4u, 4, i >= 'a' && i <= 'z' ? i - 'a' + 'A' : i);
    }
    for (i = 0; i < 16u; ++i) {
        store(process, runtime_base + DARWIN_STREAMBUF_VTABLE_OFFSET + i * 8u, 8, unsupported);
        store(process, runtime_base + DARWIN_FACET_VTABLE_OFFSET + i * 8u, 8, unsupported);
    }
    /* Itanium ABI vptr[-3] holds the ostream-to-ios virtual-base offset. */
    store(process, runtime_base + DARWIN_OSTREAM_VTABLE_OFFSET, 8, 8u);
    store(process, runtime_base + DARWIN_STREAMBUF_VTABLE_OFFSET + 6u * 8u, 8, sync);
    store(process, runtime_base + DARWIN_STREAMBUF_VTABLE_OFFSET + 12u * 8u, 8, xsputn);
    store(process, runtime_base + DARWIN_STREAMBUF_VTABLE_OFFSET + 13u * 8u, 8, overflow);
    store(process, runtime_base + DARWIN_FACET_VTABLE_OFFSET + 7u * 8u, 8, widen);
    store(process, runtime_base + DARWIN_FACET_OFFSET, 8, runtime_base + DARWIN_FACET_VTABLE_OFFSET);
    store(process, runtime_base + DARWIN_LOCALE_OFFSET, 8, runtime_base + DARWIN_FACET_OFFSET);
    if (process->return_address == 0 || unsupported == 0 || xsputn == 0 || overflow == 0 || sync == 0 || widen == 0 ||
        !initialize_ostream(process, runtime_base + DARWIN_COUT_OFFSET, runtime_base + DARWIN_COUT_BUFFER_OFFSET) ||
        !initialize_ostream(process, runtime_base + DARWIN_CERR_OFFSET, runtime_base + DARWIN_CERR_BUFFER_OFFSET)) {
        free(process);
        if (status != NULL) *status = XXEMUL_STATUS_ADDRESS_FAULT;
        return NULL;
    }
    if (status != NULL) *status = XXEMUL_STATUS_OK;
    return process;
}

void xxemul_darwin_destroy(xxemul_darwin *process)
{
    if (process != NULL) {
        xxemul_darwin_bzip2_destroy(process->bzip2);
        xxemul_darwin_zlib_destroy(process->zlib);
        xxemul_darwin_archive_destroy(process->archive);
        xxemul_darwin_posix_destroy(process->posix);
        free(process->kernel_image);
    }
    free(process);
}

static uint32_t darwin_u32(const uint8_t *p)
{
    return (uint32_t)p[0] | (uint32_t)p[1] << 8u | (uint32_t)p[2] << 16u | (uint32_t)p[3] << 24u;
}

xxemul_status xxemul_darwin_kernel_entry(xxemul_darwin *process, const void *bytes, size_t size)
{
    const uint8_t *image = bytes;
    uint64_t entry, info;
    uint32_t backwards;
    if (!process || !image || size < 32u || process->started || process->kernel_entry) return XXEMUL_STATUS_INVALID_ARGUMENT;
    process->kernel_entry = 1;
    /* UPX stores two backwards offsets just before its LC_UNIXTHREAD entry:
     * one reaches the Mach header, the other its l_info with the UPX! tag.
     * The compatibility svc #0/x8 ABI is enabled only for this structure. */
    if (darwin_u32(image) != UINT32_C(0xfeedfacf) || darwin_u32(image + 4u) != UINT32_C(0x0100000c) ||
        darwin_u32(image + 12u) != 2u || process->emulator->arm.pc < process->emulator->region_address) return XXEMUL_STATUS_OK;
    entry = process->emulator->arm.pc - process->emulator->region_address;
    if (entry < 8u || entry > size - 4u || darwin_u32(image + (size_t)entry - 8u) != entry - 8u) return XXEMUL_STATUS_OK;
    backwards = darwin_u32(image + (size_t)entry - 4u);
    if (backwards > entry - 4u) return XXEMUL_STATUS_OK;
    info = entry - 4u - backwards;
    if (info > size - 24u || memcmp(image + (size_t)info + 4u, "UPX!", 4u) ||
        image[(size_t)info + 11u] != 0x25u || size > 32u * 1024u * 1024u) return XXEMUL_STATUS_OK;
    process->kernel_image = malloc(size);
    if (!process->kernel_image) return XXEMUL_STATUS_OUT_OF_MEMORY;
    memcpy(process->kernel_image, image, size);
    process->kernel_image_size = size;
    process->packed_entry = 1;
    return XXEMUL_STATUS_OK;
}

static void dyld_word(uint8_t *image, size_t offset, uint64_t value, unsigned size)
{
    unsigned i;
    for (i = 0; i < size; ++i) image[offset + i] = (uint8_t)(value >> (i * 8u));
}

static int install_packed_files(xxemul_darwin *process, const char *path)
{
    uint8_t image[16384] = {0};
    const size_t segment = 32u, thread = 104u;
    /* A deliberately modeled dyld image. The guest UPX mapper reads and maps
     * this image itself; only its final loader entry is a runtime service. */
    dyld_word(image, 0u, UINT32_C(0xfeedfacf), 4);
    dyld_word(image, 4u, UINT32_C(0x0100000c), 4);
    dyld_word(image, 12u, 7u, 4); /* MH_DYLINKER */
    dyld_word(image, 16u, 2u, 4);
    dyld_word(image, 20u, 72u + 288u, 4);
    dyld_word(image, segment, 0x19u, 4);
    dyld_word(image, segment + 4u, 72u, 4);
    memcpy(image + segment + 8u, "__TEXT", 6u);
    dyld_word(image, segment + 32u, sizeof(image), 8);
    dyld_word(image, segment + 48u, sizeof(image), 8);
    dyld_word(image, segment + 56u, 7u, 4);
    dyld_word(image, segment + 60u, 5u, 4);
    dyld_word(image, thread, 5u, 4);
    dyld_word(image, thread + 4u, 288u, 4);
    dyld_word(image, thread + 8u, 6u, 4);
    dyld_word(image, thread + 12u, 68u, 4);
    dyld_word(image, thread + 272u, 0x1000u, 8);
    dyld_word(image, 0x1000u, UINT32_C(0xd4200000), 4); /* explicit service trap */
    return xxemul_darwin_posix_configure_vm(process->posix, process->emulator->region_address, process->base,
                process->base + DARWIN_ARENA_SIZE, XXEMUL_DARWIN_VM_ARENA_SIZE) &&
           xxemul_darwin_posix_set_virtual_file(process->posix, path, process->kernel_image, process->kernel_image_size) &&
           xxemul_darwin_posix_set_virtual_file(process->posix, "/usr/lib/dyld", image, sizeof(image));
}

xxemul_status xxemul_darwin_resolve_import(xxemul_darwin *process, const char *name, uint64_t *address)
{
    static const struct { const char *name; enum darwin_call call; } functions[] = {
        {"_strlen", CALL_STRLEN}, {"_write", CALL_WRITE}, {"_exit", CALL_EXIT}, {"__exit", CALL_EXIT},
        {"__ZNSt3__113basic_ostreamIcNS_11char_traitsIcEEE6sentryC1ERS3_", CALL_SENTRY_CTOR},
        {"__ZNSt3__113basic_ostreamIcNS_11char_traitsIcEEE6sentryC2ERS3_", CALL_SENTRY_CTOR},
        {"__ZNSt3__113basic_ostreamIcNS_11char_traitsIcEEE6sentryD1Ev", CALL_SENTRY_DTOR},
        {"__ZNSt3__113basic_ostreamIcNS_11char_traitsIcEEE6sentryD2Ev", CALL_SENTRY_DTOR},
        {"__ZNKSt3__18ios_base6getlocEv", CALL_GETLOC},
        {"__ZNKSt3__16locale9use_facetERNS0_2idE", CALL_USE_FACET},
        {"__ZNSt3__16localeD1Ev", CALL_LOCALE_DTOR}, {"__ZNSt3__16localeD2Ev", CALL_LOCALE_DTOR},
        {"__ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE6__initEmc", CALL_STRING_INIT},
        {"__ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEED1Ev", CALL_STRING_DTOR},
        {"__ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEED2Ev", CALL_STRING_DTOR},
        {"__ZNSt3__18ios_base5clearEj", CALL_IOS_CLEAR},
        {"__ZNSt3__18ios_base33__set_badbit_and_consider_rethrowEv", CALL_UNSUPPORTED},
        {"__Unwind_Resume", CALL_UNSUPPORTED}, {"___cxa_begin_catch", CALL_UNSUPPORTED},
        {"___cxa_end_catch", CALL_UNSUPPORTED}, {"___gxx_personality_v0", CALL_UNSUPPORTED},
        {"___cxa_throw", CALL_UNSUPPORTED}, {"__ZSt9terminatev", CALL_UNSUPPORTED},
        {"_abort", CALL_UNSUPPORTED}
    };
    size_t i;
    if (process == NULL || name == NULL || address == NULL) return XXEMUL_STATUS_INVALID_ARGUMENT;
    if (strcmp(name, "__DefaultRuneLocale") == 0) { *address = process->base + 0x5000u; return XXEMUL_STATUS_OK; }
    if (strcmp(name, "___stack_chk_guard") == 0) { *address = process->base + 0x1410u; return XXEMUL_STATUS_OK; }
    if (strcmp(name, "___stdinp") == 0) { *address = process->base + 0x1000u; return XXEMUL_STATUS_OK; }
    if (strcmp(name, "___stdoutp") == 0) { *address = process->base + 0x1008u; return XXEMUL_STATUS_OK; }
    if (strcmp(name, "___stderrp") == 0) { *address = process->base + 0x1010u; return XXEMUL_STATUS_OK; }
    if (strcmp(name, "_optarg") == 0) { *address = process->base + DARWIN_OPTARG_OFFSET; return XXEMUL_STATUS_OK; }
    if (strcmp(name, "_optind") == 0) { *address = process->base + DARWIN_OPTIND_OFFSET; return XXEMUL_STATUS_OK; }
    if (strcmp(name, "_opterr") == 0) { *address = process->base + DARWIN_OPTERR_OFFSET; return XXEMUL_STATUS_OK; }
    if (strcmp(name, "_optopt") == 0) { *address = process->base + DARWIN_OPTOPT_OFFSET; return XXEMUL_STATUS_OK; }
    if (strcmp(name, "_optreset") == 0) { *address = process->base + DARWIN_OPTRESET_OFFSET; return XXEMUL_STATUS_OK; }
    if (strcmp(name, "__ZNSt3__14coutE") == 0) { *address = process->base + DARWIN_COUT_OFFSET; return XXEMUL_STATUS_OK; }
    if (strcmp(name, "__ZNSt3__14cerrE") == 0 || strcmp(name, "__ZNSt3__14clogE") == 0) {
        *address = process->base + DARWIN_CERR_OFFSET;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "__ZNSt3__15ctypeIcE2idE") == 0) { *address = process->base + DARWIN_CTYPE_ID_OFFSET; return XXEMUL_STATUS_OK; }
    for (i = 0; i < sizeof(functions) / sizeof(functions[0]); ++i) {
        if (strcmp(name, functions[i].name) == 0) {
            *address = add_thunk(process, name, functions[i].call);
            return *address != 0 ? XXEMUL_STATUS_OK : XXEMUL_STATUS_OUT_OF_MEMORY;
        }
    }
    {
        static const char *const libc[] = {
            "_malloc_type_malloc", "_malloc_type_calloc", "_malloc_type_realloc", "_malloc", "_realloc", "_free", "_calloc",
            "_memcpy", "_memmove", "_memset", "_memset_pattern16", "_bzero", "_memcmp", "_memchr", "_strcpy", "_strncpy", "_strcat", "_strncat",
            "___memcpy_chk", "___memmove_chk", "___memset_chk",
            "___strcpy_chk", "___strcat_chk", "___strncat_chk", "_strcmp", "_strncmp", "_strchr", "_strrchr", "_strstr",
            "_getenv", "_setlocale", "_atoi", "___error", "___maskrune", "___toupper", "___tolower", "___chkstk_darwin", "_rand", "_srand", "_qsort",
            "_printf", "_fprintf", "_sprintf", "_snprintf", "_vprintf", "_vfprintf", "_vsprintf", "_vsnprintf", "_vasprintf",
            "___sprintf_chk", "___snprintf_chk", "___vsprintf_chk", "___vsnprintf_chk", "_sscanf",
            "_getopt_long", "_getopt", "_getprogname", "_basename", "_dirname", "_strlcpy", "___strlcpy_chk", "_strlcat", "___strlcat_chk", "_strndup", "_compat_mode"
        };
        enum darwin_call call = CALL_UNSUPPORTED;
        for (i = 0; i < sizeof(libc) / sizeof(libc[0]); ++i) if (strcmp(name, libc[i]) == 0) { call = CALL_LIBC; break; }
        if (call == CALL_UNSUPPORTED && xxemul_darwin_posix_supports(name)) call = CALL_POSIX;
        if (call == CALL_UNSUPPORTED && xxemul_darwin_archive_supports(name)) call = CALL_ARCHIVE;
        if (call == CALL_UNSUPPORTED && xxemul_darwin_zlib_supports(name)) call = CALL_ZLIB;
        if (call == CALL_UNSUPPORTED && xxemul_darwin_bzip2_supports(name)) call = CALL_BZIP2;
        *address = add_thunk(process, name, call);
        return *address != 0 ? XXEMUL_STATUS_OK : XXEMUL_STATUS_OUT_OF_MEMORY;
    }
}

xxemul_status xxemul_darwin_start(xxemul_darwin *process, const char *path, const char *workdir, int argc, const char *const *argv)
{
    uint64_t guest_argv, guest_envp;
    uint64_t saved_heap;
    unsigned saved_allocation_count;
    xxemul_status status = XXEMUL_STATUS_OUT_OF_MEMORY;
    const char *failure_reason = "Cannot initialize Darwin guest arguments";
    int count = argc == 0 ? 1 : argc;
    int i;
    if (process == NULL || path == NULL || workdir == NULL || argc < 0 || (argc > 0 && argv == NULL) || process->started) return XXEMUL_STATUS_INVALID_ARGUMENT;
    if (count > 1024) return darwin_error(process, XXEMUL_STATUS_INVALID_ARGUMENT, "Too many Darwin guest arguments");
    saved_heap = process->heap;
    saved_allocation_count = process->allocation_count;
    process->posix = xxemul_darwin_posix_create(process->emulator, process->base, workdir, process->base + 0x1400u, bridge_allocate, process);
    if (process->posix == NULL) {
        status = XXEMUL_STATUS_IO_ERROR;
        failure_reason = "Cannot initialize Darwin guest working directory";
        goto failed;
    }
    if (process->packed_entry && !install_packed_files(process, path)) {
        failure_reason = "Cannot initialize bounded Darwin packed-image mappings";
        goto failed;
    }
    guest_argv = allocate_guest(process, ((uint64_t)count + 3u) * 8u);
    if (guest_argv == 0) goto failed;
    for (i = 0; i < count; ++i) {
        const char *argument = argc == 0 ? path : argv[i];
        size_t length;
        uint64_t destination;
        if (argument == NULL) { status = XXEMUL_STATUS_INVALID_ARGUMENT; goto failed; }
        length = strlen(argument);
        if (length >= DARWIN_ARENA_SIZE) goto failed;
        destination = allocate_guest(process, (uint64_t)length + 1u);
        if (destination == 0) goto failed;
        if (!store(process, guest_argv + (uint64_t)i * 8u, 8, destination) ||
            xxemul_write_memory(process->emulator, destination, argument, length + 1u) != XXEMUL_STATUS_OK) {
            status = XXEMUL_STATUS_ADDRESS_FAULT;
            goto failed;
        }
    }
    guest_envp = guest_argv + ((uint64_t)count + 1u) * 8u;
    if (!store(process, guest_argv + (uint64_t)count * 8u, 8, 0) ||
        !store(process, guest_envp, 8, 0) || !store(process, guest_envp + 8u, 8, 0)) {
        status = XXEMUL_STATUS_ADDRESS_FAULT;
        goto failed;
    }
    process->main_argc = (uint64_t)count;
    process->main_argv = guest_argv;
    process->main_envp = guest_envp;
    process->main_apple = guest_envp + 8u;
    if (process->kernel_entry) {
        size_t path_length = strlen(path);
        uint64_t apple_string, stack, pointer;
        uint64_t words = (uint64_t)count + 5u;
        if (path_length > DARWIN_MAX_STRING - 17u || process->emulator->arm.sp < words * 8u) goto failed;
        apple_string = allocate_guest(process, 16u + path_length + 1u);
        stack = (process->emulator->arm.sp - words * 8u) & ~UINT64_C(15);
        if (!apple_string || !guest_range(process, stack, words * 8u) ||
            xxemul_write_memory(process->emulator, apple_string, "executable_path=", 16u) != XXEMUL_STATUS_OK ||
            xxemul_write_memory(process->emulator, apple_string + 16u, path, path_length + 1u) != XXEMUL_STATUS_OK ||
            !store(process, stack, 8, (uint64_t)count)) goto failed;
        for (i = 0; i < count; ++i) {
            if (!load(process, guest_argv + (uint64_t)i * 8u, 8, &pointer) || !store(process, stack + ((uint64_t)i + 1u) * 8u, 8, pointer)) goto failed;
        }
        if (!store(process, stack + ((uint64_t)count + 1u) * 8u, 8, 0) ||
            !store(process, stack + ((uint64_t)count + 2u) * 8u, 8, 0) ||
            !store(process, stack + ((uint64_t)count + 3u) * 8u, 8, apple_string) ||
            !store(process, stack + ((uint64_t)count + 4u) * 8u, 8, 0)) goto failed;
        process->kernel_sp = stack;
        process->main_argv = stack + 8u;
        process->main_envp = stack + ((uint64_t)count + 2u) * 8u;
        process->main_apple = process->main_envp + 8u;
        process->emulator->arm.sp = stack;
    } else {
        process->emulator->arm.gpr[0] = process->main_argc;
        process->emulator->arm.gpr[1] = process->main_argv;
        process->emulator->arm.gpr[2] = process->main_envp;
        process->emulator->arm.gpr[3] = process->main_apple;
        process->emulator->arm.gpr[30] = process->return_address;
    }
    process->emulator->arm.sp &= ~UINT64_C(15);
    process->started = 1;
    process->error[0] = '\0';
    return XXEMUL_STATUS_OK;
failed:
    /* Before a process has started, all tracked allocations belong to this
     * bridge initialization. Roll them back with the arena for a safe retry. */
    xxemul_darwin_posix_destroy(process->posix);
    process->posix = NULL;
    memset(process->emulator->region_data + (size_t)(saved_heap - process->emulator->region_address),
           0, (size_t)(process->heap - saved_heap));
    memset(process->allocations + saved_allocation_count, 0,
           (process->allocation_count - saved_allocation_count) * sizeof(process->allocations[0]));
    process->allocation_count = saved_allocation_count;
    process->heap = saved_heap;
    return darwin_error(process, status, failure_reason);
}

static xxemul_status write_guest(xxemul_darwin *process, int descriptor, uint64_t address, uint64_t size)
{
    xxemul *emulator = process->emulator;
    unsigned char buffer[4096];
    if (descriptor != 1 && descriptor != 2) return darwin_error(process, XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION, "Darwin write supports stdout/stderr only");
    if (!guest_range(process, address, size)) return darwin_error(process, XXEMUL_STATUS_ADDRESS_FAULT, "Darwin output buffer is outside guest memory");
    while (size != 0) {
        size_t count = size > sizeof(buffer) ? sizeof(buffer) : (size_t)size;
        if (xxemul_read_memory(emulator, address, buffer, count) != XXEMUL_STATUS_OK) return XXEMUL_STATUS_ADDRESS_FAULT;
        if (!xxemul_emit_output(emulator, descriptor, buffer, count)) {
            FILE *stream = descriptor == 2 ? stderr : stdout;
            if (fwrite(buffer, 1, count, stream) != count || fflush(stream) != 0) return XXEMUL_STATUS_IO_ERROR;
        }
        address += count;
        size -= count;
    }
    return XXEMUL_STATUS_OK;
}

static int ostream_address(const xxemul_darwin *process, uint64_t address)
{
    return address == process->base + DARWIN_COUT_OFFSET || address == process->base + DARWIN_CERR_OFFSET;
}

static unsigned char *guest_pointer(xxemul_darwin *process, uint64_t address, uint64_t count)
{
    if (!guest_range(process, address, count)) return NULL;
    return process->emulator->region_data + (size_t)(address - process->emulator->region_address);
}

static const char *guest_string(xxemul_darwin *process, uint64_t address)
{
    unsigned char *p = guest_pointer(process, address, 1);
    uint64_t available;
    if (p == NULL) return NULL;
    available = process->emulator->region_size - (address - process->emulator->region_address);
    if (available > DARWIN_MAX_STRING) available = DARWIN_MAX_STRING;
    return memchr(p, 0, (size_t)available) != NULL ? (const char *)p : NULL;
}

static uint64_t heap_malloc(xxemul_darwin *process, uint64_t count)
{
    unsigned i;
    uint64_t address;
    if (count == 0) count = 1;
    if (count > DARWIN_ARENA_SIZE) return 0;
    for (i = 0; i < process->allocation_count; ++i) {
        if (process->allocations[i].free && process->allocations[i].size >= count) {
            process->allocations[i].free = 0;
            return process->allocations[i].address;
        }
    }
    if (process->allocation_count == 4096u || (address = allocate_guest(process, count)) == 0) return 0;
    i = process->allocation_count++;
    process->allocations[i].address = address;
    process->allocations[i].size = count;
    process->allocations[i].free = 0;
    return address;
}

static int heap_index(xxemul_darwin *process, uint64_t address)
{
    unsigned i;
    for (i = 0; i < process->allocation_count; ++i) if (process->allocations[i].address == address && !process->allocations[i].free) return (int)i;
    return -1;
}

static const char *option_argument(xxemul_darwin *process, uint64_t argv, unsigned index, uint64_t *address)
{
    if (!load(process, argv + (uint64_t)index * 8u, 8, address)) return NULL;
    return guest_string(process, *address);
}

/* Move consumed options before skipped operands, preserving order in both
 * groups. The caller has validated the whole bounded argv pointer array. */
static void option_exchange(xxemul_darwin *process, uint64_t argv, unsigned end)
{
    uint64_t values[1024];
    unsigned first = process->getopt_first, middle = process->getopt_last, i;
    for (i = first; i < end; ++i) (void)load(process, argv + (uint64_t)i * 8u, 8, &values[i - first]);
    for (i = middle; i < end; ++i) (void)store(process, argv + (uint64_t)(first + i - middle) * 8u, 8, values[i - first]);
    for (i = first; i < middle; ++i) (void)store(process, argv + (uint64_t)(end - middle + i) * 8u, 8, values[i - first]);
    process->getopt_first += end - middle;
    process->getopt_last = end;
}

static int option_error(xxemul_darwin *process, int value, int option, const char *argument, const char *reason)
{
    uint64_t enabled;
    (void)store(process, process->base + DARWIN_OPTOPT_OFFSET, 4, (uint32_t)option);
    if (value != ':' && load(process, process->base + DARWIN_OPTERR_OFFSET, 4, &enabled) && enabled) {
        char message[256];
        int count = snprintf(message, sizeof(message), "getopt: %s: %.160s\n", reason, argument);
        if (count > 0 && process->posix != NULL)
            (void)xxemul_darwin_posix_write_stream(process->posix, process->base + 0x1300u,
                                                  message, (size_t)count < sizeof(message) ? (size_t)count : sizeof(message) - 1u);
    }
    return value;
}

/* Darwin ARM64 struct option: name@0, has_arg@8, flag@16, val@24,
 * sizeof=32. Parsing state and exported getopt globals belong to the guest. */
static xxemul_status parse_options(xxemul_darwin *process, int long_options)
{
    xxemul_arm_state *state = &process->emulator->arm;
    uint64_t argv = state->gpr[1], table = long_options ? state->gpr[3] : 0;
    uint64_t long_index = long_options ? state->gpr[4] : 0, exported_index, reset, address = 0;
    const char *options = guest_string(process, state->gpr[2]), *argument;
    unsigned argc = (uint32_t)state->gpr[0], index;
    int ordering = long_options ? 0 : 1, result = -1, missing;
    if (options == NULL || argc > 1024u || (argc && !guest_range(process, argv, (uint64_t)argc * 8u)) ||
        !load(process, process->base + DARWIN_OPTIND_OFFSET, 4, &exported_index) ||
        !load(process, process->base + DARWIN_OPTRESET_OFFSET, 4, &reset)) return XXEMUL_STATUS_ADDRESS_FAULT;
    if (*options == '+' || *options == '-') { ordering = *options == '+' ? 1 : 2; ++options; }
    missing = *options == ':' ? ':' : '?';
    if (*options == ':') ++options;
    index = exported_index == 0 ? 1u : (unsigned)exported_index;
    if (index > argc && !(argc == 0 && index == 1u)) return XXEMUL_STATUS_ADDRESS_FAULT;
    if (reset || exported_index == 0 || argv != process->getopt_argv || argc != process->getopt_argc || index != process->getopt_index) {
        process->getopt_next = 0;
        process->getopt_first = process->getopt_last = index;
        process->getopt_finished = 0;
        process->getopt_argv = argv;
        process->getopt_argc = argc;
        (void)store(process, process->base + DARWIN_OPTRESET_OFFSET, 4, 0);
    }
    (void)store(process, process->base + DARWIN_OPTARG_OFFSET, 8, 0);
    if (process->getopt_finished || argc == 0) goto done;
    if (!process->getopt_next) {
        if (ordering == 0) {
            if (process->getopt_first != process->getopt_last && process->getopt_last != index) option_exchange(process, argv, index);
            else if (process->getopt_last != index) process->getopt_first = index;
            while (index < argc) {
                argument = option_argument(process, argv, index, &address);
                if (argument == NULL) return XXEMUL_STATUS_ADDRESS_FAULT;
                if (argument[0] == '-' && argument[1] != '\0') break;
                ++index;
            }
            process->getopt_last = index;
        }
        if (index >= argc) {
            if (ordering == 0 && process->getopt_first != process->getopt_last) index = process->getopt_first;
            process->getopt_finished = 1;
            goto done;
        }
        argument = option_argument(process, argv, index, &address);
        if (argument == NULL) return XXEMUL_STATUS_ADDRESS_FAULT;
        if (strcmp(argument, "--") == 0) {
            ++index;
            if (ordering == 0) {
                if (process->getopt_first != process->getopt_last && process->getopt_last != index) option_exchange(process, argv, index);
                else if (process->getopt_first == process->getopt_last) process->getopt_first = index;
                process->getopt_last = argc;
                if (process->getopt_first != process->getopt_last) index = process->getopt_first;
            }
            process->getopt_finished = 1;
            goto done;
        }
        if (argument[0] != '-' || argument[1] == '\0') {
            if (ordering == 2) { (void)store(process, process->base + DARWIN_OPTARG_OFFSET, 8, address); ++index; result = 1; }
            else process->getopt_finished = 1;
            goto done;
        }
        if (table && argument[1] == '-') {
            const char *equal = strchr(argument + 2, '=');
            size_t length = equal ? (size_t)(equal - argument - 2) : strlen(argument + 2);
            uint64_t selected_flag = 0, selected_value = 0, selected_kind = 0;
            int selected = -1, ambiguous = 0;
            unsigned n;
            ++index;
            for (n = 0; n < 256u; ++n) {
                uint64_t entry, name_address, kind, flag, value;
                const char *name;
                if (table > UINT64_MAX - (uint64_t)n * 32u) return XXEMUL_STATUS_ADDRESS_FAULT;
                entry = table + (uint64_t)n * 32u;
                if (!guest_range(process, entry, 32u) || !load(process, entry, 8, &name_address)) return XXEMUL_STATUS_ADDRESS_FAULT;
                if (!name_address) break;
                name = guest_string(process, name_address);
                if (name == NULL || !load(process, entry + 8u, 4, &kind) || kind > 2u ||
                    !load(process, entry + 16u, 8, &flag) || !load(process, entry + 24u, 4, &value)) return XXEMUL_STATUS_ADDRESS_FAULT;
                if (strncmp(name, argument + 2, length) == 0) {
                    if (strlen(name) == length) { selected = (int)n; selected_kind = kind; selected_flag = flag; selected_value = value; ambiguous = 0; break; }
                    if (selected >= 0) ambiguous = 1;
                    else { selected = (int)n; selected_kind = kind; selected_flag = flag; selected_value = value; }
                }
            }
            if (n == 256u) return darwin_error(process, XXEMUL_STATUS_ADDRESS_FAULT, "Unterminated or oversized getopt long-option table");
            if (selected < 0 || ambiguous) result = option_error(process, '?', 0, argument, ambiguous ? "ambiguous option" : "unknown option");
            else if (equal && selected_kind == 0) result = option_error(process, '?', (int)selected_value, argument, "option takes no argument");
            else {
                uint64_t value = 0;
                if (equal) value = address + (uint64_t)(equal + 1 - argument);
                else if (selected_kind == 1) {
                    if (index == argc) { result = option_error(process, missing, (int)selected_value, argument, "missing argument"); goto done; }
                    if (option_argument(process, argv, index++, &value) == NULL) return XXEMUL_STATUS_ADDRESS_FAULT;
                }
                if ((selected_flag && !guest_range(process, selected_flag, 4)) || (long_index && !guest_range(process, long_index, 4))) return XXEMUL_STATUS_ADDRESS_FAULT;
                (void)store(process, process->base + DARWIN_OPTARG_OFFSET, 8, value);
                if (long_index) (void)store(process, long_index, 4, (uint32_t)selected);
                if (selected_flag) { (void)store(process, selected_flag, 4, selected_value); result = 0; }
                else result = (int32_t)selected_value;
            }
            goto done;
        }
        process->getopt_next = address + 1u;
    }
    {
        const char *cursor = guest_string(process, process->getopt_next), *found;
        unsigned char option;
        if (cursor == NULL || *cursor == '\0') return XXEMUL_STATUS_ADDRESS_FAULT;
        option = (unsigned char)*cursor++;
        ++process->getopt_next;
        found = option == ':' ? NULL : strchr(options, option);
        result = option;
        if (found == NULL) result = option_error(process, '?', option, cursor - 1, "unknown option");
        else if (found[1] == ':') {
            if (*cursor) { (void)store(process, process->base + DARWIN_OPTARG_OFFSET, 8, process->getopt_next); ++index; }
            else if (found[2] != ':' && ++index < argc) {
                if (option_argument(process, argv, index++, &address) == NULL) return XXEMUL_STATUS_ADDRESS_FAULT;
                (void)store(process, process->base + DARWIN_OPTARG_OFFSET, 8, address);
            } else if (found[2] != ':') result = option_error(process, missing, option, cursor - 1, "missing argument");
            else ++index;
            process->getopt_next = 0;
            goto done;
        }
        if (*cursor == '\0') { ++index; process->getopt_next = 0; }
    }
done:
    process->getopt_index = index;
    (void)store(process, process->base + DARWIN_OPTIND_OFFSET, 4, index);
    state->gpr[0] = (uint32_t)result;
    return XXEMUL_STATUS_OK;
}

static xxemul_status qsort_next(xxemul_darwin *process, int returned)
{
    xxemul_arm_state *state = &process->emulator->arm;
    unsigned n;
    uint64_t callback;
    if (process->sort_depth == 0) return XXEMUL_STATUS_INVALID_ARGUMENT;
    n = process->sort_depth - 1;
    if (returned) {
        if ((int32_t)state->gpr[0] > 0) {
            uint64_t left = process->sorts[n].base + (process->sorts[n].j - 1) * process->sorts[n].size;
            uint64_t right = left + process->sorts[n].size;
            uint64_t offset = 0;
            unsigned char temp[256];
            while (offset < process->sorts[n].size) {
                size_t part = process->sorts[n].size - offset > sizeof(temp) ? sizeof(temp) : (size_t)(process->sorts[n].size - offset);
                unsigned char *a = guest_pointer(process, left + offset, part), *b = guest_pointer(process, right + offset, part);
                if (a == NULL || b == NULL) return XXEMUL_STATUS_ADDRESS_FAULT;
                memcpy(temp, a, part); memcpy(a, b, part); memcpy(b, temp, part);
                offset += part;
            }
            --process->sorts[n].j;
        } else process->sorts[n].j = 0;
        if (process->sorts[n].j == 0) { ++process->sorts[n].i; process->sorts[n].j = process->sorts[n].i; }
    }
    process->redirect = 1;
    if (process->sorts[n].i >= process->sorts[n].count) {
        state->pc = process->sorts[n].lr;
        state->gpr[30] = process->sorts[n].lr;
        --process->sort_depth;
        return XXEMUL_STATUS_OK;
    }
    callback = add_thunk(process, "<Darwin qsort compare return>", CALL_QSORT_RETURN);
    state->gpr[0] = process->sorts[n].base + (process->sorts[n].j - 1u) * process->sorts[n].size;
    state->gpr[1] = state->gpr[0] + process->sorts[n].size;
    state->gpr[30] = callback;
    state->pc = process->sorts[n].compare;
    return XXEMUL_STATUS_OK;
}

/* Darwin ARM64 passes unnamed varargs in 8-byte stack slots. */
static int next_vararg(xxemul_darwin *process, uint64_t *cursor, uint64_t *value)
{
    if (*cursor > UINT64_MAX - 8u || !load(process, *cursor, 8, value)) return 0;
    *cursor += 8u;
    return 1;
}

static xxemul_status format_output(xxemul_darwin *process, const char *name)
{
    xxemul_arm_state *state = &process->emulator->arm;
    int allocated = strcmp(name, "_vasprintf") == 0;
    int to_file = strcmp(name, "_fprintf") == 0 || strcmp(name, "_vfprintf") == 0;
    int bounded = strcmp(name, "_snprintf") == 0 || strcmp(name, "_vsnprintf") == 0 ||
                  strcmp(name, "___snprintf_chk") == 0 || strcmp(name, "___vsnprintf_chk") == 0;
    int checked = strcmp(name, "___sprintf_chk") == 0 || strcmp(name, "___snprintf_chk") == 0 ||
                  strcmp(name, "___vsprintf_chk") == 0 || strcmp(name, "___vsnprintf_chk") == 0;
    int uses_va_list = allocated || strcmp(name, "_vprintf") == 0 || strcmp(name, "_vfprintf") == 0 ||
                  strcmp(name, "_vsprintf") == 0 || strcmp(name, "_vsnprintf") == 0 ||
                  strcmp(name, "___vsprintf_chk") == 0 || strcmp(name, "___vsnprintf_chk") == 0;
    int to_memory = allocated || bounded || checked || strcmp(name, "_sprintf") == 0 || strcmp(name, "_vsprintf") == 0;
    uint64_t destination = state->gpr[0];
    uint64_t capacity = bounded ? state->gpr[1] : checked ? state->gpr[2] : UINT64_MAX;
    unsigned format_index = checked ? (bounded ? 4u : 3u) : bounded ? 2u : (to_file || to_memory ? 1u : 0u);
    const char *format;
    uint64_t cursor = uses_va_list ? state->gpr[format_index + 1u] : state->sp;
    size_t used = 0;
    char *result;
    xxemul_status status = XXEMUL_STATUS_OK;
    if (allocated && !guest_range(process, destination, 8u)) return XXEMUL_STATUS_ADDRESS_FAULT;
    if (bounded && checked && capacity > state->gpr[3])
        return darwin_error(process, XXEMUL_STATUS_ADDRESS_FAULT, "Checked snprintf limit exceeds destination size");
    format = guest_string(process, state->gpr[format_index]);
    result = (char *)malloc((size_t)DARWIN_MAX_STRING + 1u);
    if (format == NULL) { free(result); return XXEMUL_STATUS_ADDRESS_FAULT; }
    if (result == NULL) { status = XXEMUL_STATUS_OUT_OF_MEMORY; goto finished; }
    while (*format != '\0' && status == XXEMUL_STATUS_OK) {
        char spec[96], temporary[8192], flags[8];
        int width = 0, precision = -1, long_value = 0, count;
        size_t nf = 0;
        uint64_t value = 0;
        char conversion;
        if (*format != '%') {
            if (used == DARWIN_MAX_STRING) { status = XXEMUL_STATUS_OUT_OF_MEMORY; break; }
            result[used++] = *format++;
            continue;
        }
        ++format;
        if (*format == '%') { if (used == DARWIN_MAX_STRING) { status = XXEMUL_STATUS_OUT_OF_MEMORY; break; } result[used++] = *format++; continue; }
        while (*format && strchr("-+ #0'", *format) != NULL) {
            if (nf + 1 >= sizeof(flags)) { status = XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION; break; }
            if (*format != '\'') flags[nf++] = *format;
            ++format;
        }
        flags[nf] = '\0';
        if (*format == '*') {
            if (!next_vararg(process, &cursor, &value)) { status = XXEMUL_STATUS_ADDRESS_FAULT; break; }
            width = (int32_t)value; ++format;
        } else while (isdigit((unsigned char)*format)) { if (width > 100000) { status = XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION; break; } width = width * 10 + (*format++ - '0'); }
        if (*format == '.') {
            ++format; precision = 0;
            if (*format == '*') { if (!next_vararg(process, &cursor, &value)) { status = XXEMUL_STATUS_ADDRESS_FAULT; break; } precision = (int32_t)value; ++format; }
            else while (isdigit((unsigned char)*format)) { if (precision > 100000) { status = XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION; break; } precision = precision * 10 + (*format++ - '0'); }
        }
        if (*format == 'l' || *format == 'z' || *format == 'j' || *format == 't') { long_value = 1; if (*format++ == 'l' && *format == 'l') ++format; }
        else if (*format == 'h') { ++format; if (*format == 'h') ++format; }
        conversion = *format;
        if (conversion == '\0') { status = XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION; break; }
        ++format;
        if (width < -4096 || width > 4096 || precision > 4096) { status = XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION; break; }
        if (!next_vararg(process, &cursor, &value)) { status = XXEMUL_STATUS_ADDRESS_FAULT; break; }
        if (conversion == 'n') { if (!store(process, value, long_value ? 8 : 4, used)) status = XXEMUL_STATUS_ADDRESS_FAULT; continue; }
        snprintf(spec, sizeof(spec), "%%%s*.*%s%c", flags, strchr("diuoxX", conversion) != NULL ? "ll" : "", conversion);
        if (conversion == 's') {
            const char *string = value == 0 ? "(null)" : guest_string(process, value);
            if (string == NULL) { status = XXEMUL_STATUS_ADDRESS_FAULT; break; }
            count = snprintf(temporary, sizeof(temporary), spec, width, precision, string);
        } else if (conversion == 'd' || conversion == 'i') count = snprintf(temporary, sizeof(temporary), spec, width, precision, (long long)(long_value ? (int64_t)value : (int32_t)value));
        else if (strchr("uoxX", conversion) != NULL) count = snprintf(temporary, sizeof(temporary), spec, width, precision, (unsigned long long)(long_value ? value : (uint32_t)value));
        else if (conversion == 'c') count = snprintf(temporary, sizeof(temporary), spec, width, precision, (int)(unsigned char)value);
        else if (conversion == 'p') count = snprintf(temporary, sizeof(temporary), "0x%llx", (unsigned long long)value);
        else if (strchr("fFeEgGaA", conversion) != NULL) { double number; memcpy(&number, &value, sizeof(number)); count = snprintf(temporary, sizeof(temporary), spec, width, precision, number); }
        else { status = XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION; break; }
        if (count < 0 || (size_t)count >= sizeof(temporary) || (size_t)count > DARWIN_MAX_STRING - used) { status = XXEMUL_STATUS_OUT_OF_MEMORY; break; }
        memcpy(result + used, temporary, (size_t)count); used += (size_t)count;
    }
    if (status == XXEMUL_STATUS_OK) {
        result[used] = '\0';
        if (allocated) {
            uint64_t pointer = heap_malloc(process, used + 1u);
            if (!pointer) status = XXEMUL_STATUS_OUT_OF_MEMORY;
            else {
                status = xxemul_write_memory(process->emulator, pointer, result, used + 1u);
                if (status == XXEMUL_STATUS_OK && !store(process, destination, 8u, pointer)) status = XXEMUL_STATUS_ADDRESS_FAULT;
                if (status != XXEMUL_STATUS_OK) {
                    int index = heap_index(process, pointer);
                    if (index >= 0) process->allocations[index].free = 1;
                }
            }
        } else if (to_memory) {
            if (bounded) {
                if (capacity != 0u) {
                    size_t written = used;
                    if ((uint64_t)written >= capacity) written = (size_t)(capacity - 1u);
                    if (!guest_range(process, destination, (uint64_t)written + 1u)) status = XXEMUL_STATUS_ADDRESS_FAULT;
                    else {
                        result[written] = '\0';
                        status = xxemul_write_memory(process->emulator, destination, result, written + 1u);
                    }
                }
            } else if (used >= capacity || !guest_range(process, destination, used + 1u)) status = XXEMUL_STATUS_ADDRESS_FAULT;
            else status = xxemul_write_memory(process->emulator, destination, result, used + 1u);
        } else if (to_file) {
            if (xxemul_darwin_posix_write_stream(process->posix, destination, result, used) != (int64_t)used) { state->gpr[0] = UINT64_MAX; free(result); return XXEMUL_STATUS_OK; }
        } else if (!xxemul_emit_output(process->emulator, 1, result, used)) {
            if (fwrite(result, 1, used, stdout) != used) status = XXEMUL_STATUS_IO_ERROR;
        }
        state->gpr[0] = used;
    }
finished:
    if (allocated && status == XXEMUL_STATUS_OUT_OF_MEMORY) {
        (void)store(process, destination, 8u, 0);
        (void)store(process, process->base + 0x1400u, 4u, 12); /* ENOMEM */
        state->gpr[0] = UINT64_MAX;
        status = XXEMUL_STATUS_OK;
    }
    free(result);
    return status;
}

static xxemul_status scan_input(xxemul_darwin *process)
{
    xxemul_arm_state *state = &process->emulator->arm;
    const char *input = guest_string(process, state->gpr[0]), *format = guest_string(process, state->gpr[1]);
    const char *begin = input;
    uint64_t cursor = state->sp;
    int assigned = 0;
    if (input == NULL || format == NULL) return XXEMUL_STATUS_ADDRESS_FAULT;
    while (*format) {
        int suppress = 0, width = 0, long_value = 0;
        uint64_t target = 0;
        char conversion;
        if (isspace((unsigned char)*format)) { while (isspace((unsigned char)*input)) ++input; ++format; continue; }
        if (*format != '%') { if (*input != *format) break; ++input; ++format; continue; }
        ++format;
        if (*format == '%') { if (*input != '%') break; ++input; ++format; continue; }
        if (*format == '*') { suppress = 1; ++format; }
        while (isdigit((unsigned char)*format)) { if (width > 100000) return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION; width = width * 10 + (*format++ - '0'); }
        if (*format == 'l') { long_value = 1; ++format; if (*format == 'l') ++format; }
        conversion = *format++;
        if (!suppress && !next_vararg(process, &cursor, &target)) return XXEMUL_STATUS_ADDRESS_FAULT;
        if (strchr("diuoxX", conversion) != NULL && conversion != 0) {
            char text[128], *end;
            size_t count = 0;
            long long value;
            while (isspace((unsigned char)*input)) ++input;
            while (input[count] && count + 1u < sizeof(text) && (width == 0 || count < (size_t)width)) { text[count] = input[count]; ++count; }
            text[count] = '\0';
            value = strtoll(text, &end, conversion == 'i' ? 0 : conversion == 'o' ? 8 : (conversion == 'x' || conversion == 'X') ? 16 : 10);
            if (end == text) break;
            input += end - text;
            if (!suppress) { if (!store(process, target, long_value ? 8 : 4, (uint64_t)value)) return XXEMUL_STATUS_ADDRESS_FAULT; ++assigned; }
        } else if (conversion == 's' || conversion == 'c') {
            size_t count = 0;
            if (conversion == 's') while (isspace((unsigned char)*input)) ++input;
            if (width == 0) width = conversion == 'c' ? 1 : (int)DARWIN_MAX_STRING;
            while (input[count] && count < (size_t)width && (conversion == 'c' || !isspace((unsigned char)input[count]))) ++count;
            if (count == 0) break;
            if (!suppress) {
                if (!guest_range(process, target, count + (conversion == 's'))) return XXEMUL_STATUS_ADDRESS_FAULT;
                xxemul_write_memory(process->emulator, target, input, count);
                if (conversion == 's') store(process, target + count, 1, 0);
                ++assigned;
            }
            input += count;
        } else if (conversion == 'n') { if (!suppress && !store(process, target, long_value ? 8 : 4, (uint64_t)(input - begin))) return XXEMUL_STATUS_ADDRESS_FAULT; }
        else return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    }
    state->gpr[0] = (uint32_t)assigned;
    return XXEMUL_STATUS_OK;
}

static xxemul_status call_libc(xxemul_darwin *process, const char *name)
{
    xxemul_arm_state *state = &process->emulator->arm;
    uint64_t a = state->gpr[0], b = state->gpr[1], c = state->gpr[2], d = state->gpr[3];
    const char *s, *t;
    unsigned char *dest;
    uint64_t pointer;
    int index;
    if (strcmp(name, "___error") == 0) { state->gpr[0] = process->base + 0x1400u; return XXEMUL_STATUS_OK; }
    if (strcmp(name, "___chkstk_darwin") == 0) return XXEMUL_STATUS_OK;
    if (strcmp(name, "_getenv") == 0) { state->gpr[0] = 0; return XXEMUL_STATUS_OK; }
    if (strcmp(name, "_getopt_long") == 0 || strcmp(name, "_getopt") == 0)
        return parse_options(process, strcmp(name, "_getopt_long") == 0);
    if (strcmp(name, "_getprogname") == 0) {
        if (!load(process, process->main_argv, 8, &pointer) || (s = guest_string(process, pointer)) == NULL)
            return XXEMUL_STATUS_ADDRESS_FAULT;
        t = strrchr(s, '/');
        state->gpr[0] = t ? pointer + (uint64_t)(t + 1 - s) : pointer;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "_compat_mode") == 0) {
        s = guest_string(process, a); t = guest_string(process, b);
        if (s == NULL || t == NULL) return XXEMUL_STATUS_ADDRESS_FAULT;
        /* The empty guest environment uses modern Darwin's Unix2003 mode.
         * Other private compatibility modes have no modeled semantics. */
        if (strcmp(t, "Unix2003") != 0) return darwin_error(process, XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION, "Unsupported Darwin compatibility mode");
        state->gpr[0] = 1;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "_dirname") == 0) {
        const char *begin, *end;
        size_t length;
        s = a == 0 ? "" : guest_string(process, a);
        if (s == NULL) return XXEMUL_STATUS_ADDRESS_FAULT;
        begin = s; end = s + strlen(s);
        while (end > s && end[-1] == '/') --end;
        while (end > s && end[-1] != '/') --end;
        while (end > s && end[-1] == '/') --end;
        if (end == s) { begin = *s == '/' ? "/" : "."; length = 1u; }
        else length = (size_t)(end - s);
        if (length >= 4096u) { (void)store(process, process->base + 0x1400u, 4, 63); state->gpr[0] = 0; return XXEMUL_STATUS_OK; }
        pointer = process->base + DARWIN_DIRNAME_OFFSET;
        if (xxemul_write_memory(process->emulator, pointer, begin, length) != XXEMUL_STATUS_OK ||
            !store(process, pointer + length, 1, 0)) return XXEMUL_STATUS_ADDRESS_FAULT;
        state->gpr[0] = pointer;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "_basename") == 0) {
        const char *begin, *end;
        size_t length;
        s = a == 0 ? "" : guest_string(process, a);
        if (s == NULL) return XXEMUL_STATUS_ADDRESS_FAULT;
        end = s + strlen(s);
        while (end > s && end[-1] == '/') --end;
        begin = end;
        while (begin > s && begin[-1] != '/') --begin;
        if (end == s) { begin = *s == '/' ? "/" : "."; length = 1; }
        else length = (size_t)(end - begin);
        if (length >= 4096u) { (void)store(process, process->base + 0x1400u, 4, 63); state->gpr[0] = 0; return XXEMUL_STATUS_OK; }
        pointer = process->base + DARWIN_BASENAME_OFFSET;
        if (xxemul_write_memory(process->emulator, pointer, begin, length) != XXEMUL_STATUS_OK || !store(process, pointer + length, 1, 0)) return XXEMUL_STATUS_ADDRESS_FAULT;
        state->gpr[0] = pointer;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "_strndup") == 0) {
        size_t length = 0;
        if (b) {
            uint64_t available, limit;
            const void *end;
            s = (const char *)guest_pointer(process, a, 1);
            if (s == NULL) return XXEMUL_STATUS_ADDRESS_FAULT;
            available = process->emulator->region_size - (a - process->emulator->region_address);
            limit = b < DARWIN_MAX_STRING ? b : DARWIN_MAX_STRING;
            if (limit > available) limit = available;
            end = memchr(s, 0, (size_t)limit);
            if (end) length = (size_t)((const char *)end - s);
            else if (limit == b) length = (size_t)b;
            else return darwin_error(process, XXEMUL_STATUS_ADDRESS_FAULT, "Unterminated or oversized strndup input");
        }
        pointer = heap_malloc(process, (uint64_t)length + 1u);
        if (!pointer) { (void)store(process, process->base + 0x1400u, 4, 12); state->gpr[0] = 0; return XXEMUL_STATUS_OK; }
        if (length) memmove(guest_pointer(process, pointer, length), guest_pointer(process, a, length), length);
        (void)store(process, pointer + length, 1, 0);
        state->gpr[0] = pointer;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "_strlcat") == 0 || strcmp(name, "___strlcat_chk") == 0) {
        uint64_t destination_length = 0;
        size_t source_length;
        if (strcmp(name, "___strlcat_chk") == 0 && c > d)
            return darwin_error(process, XXEMUL_STATUS_ADDRESS_FAULT, "Checked strlcat limit exceeds destination size");
        s = guest_string(process, b);
        if (s == NULL) return XXEMUL_STATUS_ADDRESS_FAULT;
        source_length = strlen(s);
        if (c) {
            uint64_t available, limit;
            unsigned char *end;
            dest = guest_pointer(process, a, 1);
            if (dest == NULL) return XXEMUL_STATUS_ADDRESS_FAULT;
            available = process->emulator->region_size - (a - process->emulator->region_address);
            limit = c < available ? c : available;
            end = memchr(dest, 0, (size_t)limit);
            if (end == NULL) {
                if (limit != c) return XXEMUL_STATUS_ADDRESS_FAULT;
                destination_length = c;
            } else {
                size_t written;
                destination_length = (uint64_t)(end - dest);
                written = (uint64_t)source_length < c - destination_length ? source_length : (size_t)(c - destination_length - 1u);
                if (!guest_range(process, a + destination_length, (uint64_t)written + 1u)) return XXEMUL_STATUS_ADDRESS_FAULT;
                memmove(end, s, written);
                end[written] = 0;
            }
        }
        state->gpr[0] = destination_length + source_length;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "_strlcpy") == 0 || strcmp(name, "___strlcpy_chk") == 0) {
        size_t length, written;
        if (strcmp(name, "___strlcpy_chk") == 0 && c > d)
            return darwin_error(process, XXEMUL_STATUS_ADDRESS_FAULT, "Checked strlcpy limit exceeds destination size");
        s = guest_string(process, b);
        if (s == NULL) return XXEMUL_STATUS_ADDRESS_FAULT;
        length = strlen(s);
        if (c) {
            written = (uint64_t)length < c ? length : (size_t)(c - 1u);
            dest = guest_pointer(process, a, (uint64_t)written + 1u);
            if (dest == NULL) return XXEMUL_STATUS_ADDRESS_FAULT;
            memmove(dest, s, written);
            dest[written] = 0;
        }
        state->gpr[0] = (uint64_t)length;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "_setlocale") == 0) {
        /* Darwin categories are LC_ALL=0 through LC_MESSAGES=6. The guest
         * environment is empty, so its default locale is C. Every supported
         * category stays C; a rejected name leaves that state unchanged. */
        if ((uint32_t)a > 6u) { state->gpr[0] = 0; return XXEMUL_STATUS_OK; }
        if (b != 0) {
            s = guest_string(process, b);
            if (s == NULL) return XXEMUL_STATUS_ADDRESS_FAULT;
            if (s[0] != '\0' && strcmp(s, "C") != 0 && strcmp(s, "POSIX") != 0) {
                state->gpr[0] = 0;
                return XXEMUL_STATUS_OK;
            }
        }
        state->gpr[0] = process->base + DARWIN_C_LOCALE_NAME_OFFSET;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "___maskrune") == 0) { state->gpr[0] = a < 256u ? rune_type((unsigned)a) & b : 0; return XXEMUL_STATUS_OK; }
    if (strcmp(name, "___toupper") == 0) { state->gpr[0] = a >= 'a' && a <= 'z' ? a - 'a' + 'A' : a; return XXEMUL_STATUS_OK; }
    if (strcmp(name, "___tolower") == 0) { state->gpr[0] = a >= 'A' && a <= 'Z' ? a - 'A' + 'a' : a; return XXEMUL_STATUS_OK; }
    if (strcmp(name, "_srand") == 0) { process->random_state = (uint32_t)a; return XXEMUL_STATUS_OK; }
    if (strcmp(name, "_rand") == 0) { process->random_state = process->random_state * 1103515245u + 12345u; state->gpr[0] = process->random_state & 0x7fffffffu; return XXEMUL_STATUS_OK; }
    if (strcmp(name, "_malloc_type_malloc") == 0 || strcmp(name, "_malloc") == 0 ||
        strcmp(name, "_calloc") == 0 || strcmp(name, "_malloc_type_calloc") == 0) {
        int clear = strcmp(name, "_calloc") == 0 || strcmp(name, "_malloc_type_calloc") == 0;
        uint64_t count = a;
        /* The allocation type identifier is an extra argument, never a size. */
        if (clear) { if (b && a > UINT64_MAX / b) count = UINT64_MAX; else count = a * b; }
        pointer = heap_malloc(process, count);
        if (pointer == 0) store(process, process->base + 0x1400u, 4, 12);
        else if (clear) memset(guest_pointer(process, pointer, count), 0, (size_t)count);
        state->gpr[0] = pointer; return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "_free") == 0) { if (a == 0) return XXEMUL_STATUS_OK; index = heap_index(process, a); if (index < 0) return XXEMUL_STATUS_ADDRESS_FAULT; process->allocations[index].free = 1; return XXEMUL_STATUS_OK; }
    if (strcmp(name, "_malloc_type_realloc") == 0 || strcmp(name, "_realloc") == 0) {
        index = a == 0 ? -1 : heap_index(process, a);
        if (a && index < 0) return XXEMUL_STATUS_ADDRESS_FAULT;
        if (index >= 0 && b <= process->allocations[index].size && b != 0) return XXEMUL_STATUS_OK;
        pointer = b == 0 ? 0 : heap_malloc(process, b);
        if (index >= 0 && (pointer || b == 0)) {
            if (pointer) memcpy(guest_pointer(process, pointer, b), guest_pointer(process, a, process->allocations[index].size), (size_t)process->allocations[index].size);
            process->allocations[index].free = 1;
        }
        if (pointer == 0 && b) store(process, process->base + 0x1400u, 4, 12);
        state->gpr[0] = pointer; return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "_memchr") == 0) {
        const unsigned char *found;
        if (!c) { state->gpr[0] = 0; return XXEMUL_STATUS_OK; }
        dest = guest_pointer(process, a, c);
        if (dest == NULL) return XXEMUL_STATUS_ADDRESS_FAULT;
        found = memchr(dest, (unsigned char)b, (size_t)c);
        state->gpr[0] = found ? a + (uint64_t)(found - dest) : 0;
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "_memcpy") == 0 || strcmp(name, "_memmove") == 0 || strcmp(name, "_memcmp") == 0 ||
        strcmp(name, "___memcpy_chk") == 0 || strcmp(name, "___memmove_chk") == 0) {
        if ((strcmp(name, "___memcpy_chk") == 0 || strcmp(name, "___memmove_chk") == 0) && c > d)
            return darwin_error(process, XXEMUL_STATUS_ADDRESS_FAULT, "Checked memory copy exceeds destination size");
        unsigned char *source = guest_pointer(process, b, c); dest = guest_pointer(process, a, c);
        if (source == NULL || dest == NULL) return XXEMUL_STATUS_ADDRESS_FAULT;
        if (strcmp(name, "_memcmp") == 0) state->gpr[0] = (uint32_t)memcmp(dest, source, (size_t)c);
        else memmove(dest, source, (size_t)c);
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "_memset") == 0 || strcmp(name, "_bzero") == 0 || strcmp(name, "___memset_chk") == 0) {
        if (strcmp(name, "___memset_chk") == 0 && c > d)
            return darwin_error(process, XXEMUL_STATUS_ADDRESS_FAULT, "Checked memset exceeds destination size");
        if (strcmp(name, "_bzero") == 0) { c = b; b = 0; }
        dest = guest_pointer(process, a, c); if (dest == NULL) return XXEMUL_STATUS_ADDRESS_FAULT;
        memset(dest, (int)(unsigned char)b, (size_t)c); return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "_memset_pattern16") == 0) {
        unsigned char pattern[16];
        const unsigned char *source;
        uint64_t offset = 0;
        if (c == 0) return XXEMUL_STATUS_OK;
        source = guest_pointer(process, b, sizeof(pattern));
        dest = guest_pointer(process, a, c);
        if (source == NULL || dest == NULL) return XXEMUL_STATUS_ADDRESS_FAULT;
        memcpy(pattern, source, sizeof(pattern));
        while (offset < c) {
            size_t part = c - offset < sizeof(pattern) ? (size_t)(c - offset) : sizeof(pattern);
            memcpy(dest + (size_t)offset, pattern, part);
            offset += part;
        }
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "_qsort") == 0) {
        unsigned n;
        uint64_t comparator = d;
        if (b < 2u || c == 0) return XXEMUL_STATUS_OK;
        if (process->sort_depth == 8u || b > UINT64_MAX / c || !guest_range(process, a, b * c)) return XXEMUL_STATUS_ADDRESS_FAULT;
        if (!guest_range(process, comparator, 4) && xxemul_arm_auth_check(process->emulator, d, 0, 0, &comparator) != XXEMUL_STATUS_OK) return XXEMUL_STATUS_ADDRESS_FAULT;
        n = process->sort_depth++;
        process->sorts[n].base = a; process->sorts[n].count = b; process->sorts[n].size = c;
        process->sorts[n].compare = comparator; process->sorts[n].lr = state->gpr[30];
        process->sorts[n].i = 1; process->sorts[n].j = 1;
        return qsort_next(process, 0);
    }
    if (strcmp(name, "_printf") == 0 || strcmp(name, "_fprintf") == 0 || strcmp(name, "_sprintf") == 0 ||
        strcmp(name, "_snprintf") == 0 || strcmp(name, "_vprintf") == 0 || strcmp(name, "_vfprintf") == 0 ||
        strcmp(name, "_vsprintf") == 0 || strcmp(name, "_vsnprintf") == 0 || strcmp(name, "___sprintf_chk") == 0 ||
        strcmp(name, "___snprintf_chk") == 0 || strcmp(name, "___vsprintf_chk") == 0 || strcmp(name, "___vsnprintf_chk") == 0 ||
        strcmp(name, "_vasprintf") == 0)
        return format_output(process, name);
    if (strcmp(name, "_sscanf") == 0) return scan_input(process);
    s = guest_string(process, a);
    if (strcmp(name, "_atoi") == 0) { if (s == NULL) return XXEMUL_STATUS_ADDRESS_FAULT; state->gpr[0] = (uint32_t)strtol(s, NULL, 10); return XXEMUL_STATUS_OK; }
    if (strcmp(name, "_strchr") == 0 || strcmp(name, "_strrchr") == 0) {
        const char *found;
        if (s == NULL) return XXEMUL_STATUS_ADDRESS_FAULT;
        found = strcmp(name, "_strchr") == 0 ? strchr(s, (int)(unsigned char)b) : strrchr(s, (int)(unsigned char)b);
        state->gpr[0] = found != NULL ? a + (uint64_t)(found - s) : 0; return XXEMUL_STATUS_OK;
    }
    t = guest_string(process, b);
    if (strcmp(name, "_strcmp") == 0 || strcmp(name, "_strncmp") == 0 || strcmp(name, "_strstr") == 0) {
        if (s == NULL || t == NULL) return XXEMUL_STATUS_ADDRESS_FAULT;
        if (strcmp(name, "_strstr") == 0) { const char *found = strstr(s, t); state->gpr[0] = found ? a + (uint64_t)(found - s) : 0; }
        else state->gpr[0] = (uint32_t)(strcmp(name, "_strcmp") == 0 ? strcmp(s, t) : strncmp(s, t, c > SIZE_MAX ? SIZE_MAX : (size_t)c));
        return XXEMUL_STATUS_OK;
    }
    if (strcmp(name, "_strcpy") == 0 || strcmp(name, "___strcpy_chk") == 0 || strcmp(name, "_strncpy") == 0 ||
        strcmp(name, "_strcat") == 0 || strcmp(name, "___strcat_chk") == 0 || strcmp(name, "_strncat") == 0 || strcmp(name, "___strncat_chk") == 0) {
        size_t length, offset = 0;
        int bounded = strcmp(name, "_strncpy") == 0 || strcmp(name, "_strncat") == 0 || strcmp(name, "___strncat_chk") == 0;
        int cat = strstr(name, "cat") != NULL;
        uint64_t cap = strstr(name, "_chk") != NULL ? (bounded ? d : c) : UINT64_MAX;
        if (t == NULL || (cat && s == NULL)) return XXEMUL_STATUS_ADDRESS_FAULT;
        length = strlen(t); if (bounded && c < length) length = (size_t)c;
        if (cat) offset = strlen(s);
        if (strcmp(name, "_strncpy") == 0) {
            dest = guest_pointer(process, a, c); if (dest == NULL) return XXEMUL_STATUS_ADDRESS_FAULT;
            memcpy(dest, t, length); if (c > length) memset(dest + length, 0, (size_t)c - length);
        } else {
            if (offset >= cap || length >= cap - offset || !guest_range(process, a, offset + length + 1u)) return XXEMUL_STATUS_ADDRESS_FAULT;
            dest = guest_pointer(process, a, offset + length + 1u); memmove(dest + offset, t, length); dest[offset + length] = 0;
        }
        return XXEMUL_STATUS_OK;
    }
    return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
}

static xxemul_status archive_callback(xxemul_darwin *process, int returned)
{
    xxemul_arm_state *state = &process->emulator->arm;
    uint64_t target, arguments[3], callback;
    unsigned count, i;
    xxemul_status status;
    if (returned) {
        if (!process->archive_callback_active || state->sp != process->archive_sp)
            return darwin_error(process, XXEMUL_STATUS_INVALID_ARGUMENT, "Invalid archive callback return");
        status = xxemul_darwin_archive_complete_callback(process->archive, state->gpr[0]);
        if (status != XXEMUL_STATUS_OK) return status;
    }
    if (xxemul_darwin_archive_take_callback(process->archive, &target, arguments, &count)) {
        if (count > 3u || (!returned && process->archive_callback_active))
            return darwin_error(process, XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION, "Nested archive callbacks are unsupported");
        if (!guest_range(process, target, 4u) &&
            xxemul_arm_auth_check(process->emulator, target, 0, 0, &target) != XXEMUL_STATUS_OK)
            return XXEMUL_STATUS_ADDRESS_FAULT;
        if ((target & 3u) || !guest_range(process, target, 4u)) return XXEMUL_STATUS_ADDRESS_FAULT;
        callback = add_thunk(process, "<Darwin archive callback return>", CALL_ARCHIVE_RETURN);
        if (!callback) return XXEMUL_STATUS_OUT_OF_MEMORY;
        if (!returned) {
            process->archive_lr = state->gpr[30];
            process->archive_sp = state->sp;
            process->archive_callback_active = 1;
        }
        for (i = 0; i < count; ++i) state->gpr[i] = arguments[i];
        state->gpr[30] = callback;
        state->pc = target;
        process->redirect = 1;
    } else if (returned) {
        state->gpr[30] = process->archive_lr;
        state->pc = process->archive_lr;
        process->archive_callback_active = 0;
        process->redirect = 1;
    }
    return XXEMUL_STATUS_OK;
}

static xxemul_status call_import(xxemul_darwin *process, const struct darwin_thunk *thunk)
{
    xxemul_arm_state *state = &process->emulator->arm;
    uint64_t a = state->gpr[0], b = state->gpr[1], c = state->gpr[2];
    uint64_t value;
    xxemul_status status = XXEMUL_STATUS_OK;
    switch (thunk->call) {
        case CALL_LIBC: return call_libc(process, thunk->name);
        case CALL_POSIX:
            if (xxemul_darwin_posix_dispatch(process->posix, thunk->name, &status)) return status;
            return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
        case CALL_QSORT_RETURN: return qsort_next(process, 1);
        case CALL_ARCHIVE:
            if (!process->archive)
                process->archive = xxemul_darwin_archive_create(process->emulator, bridge_allocate, process, process->posix);
            if (!process->archive)
                return darwin_error(process, XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION, "The libarchive runtime adapter is unavailable on this host");
            if (!xxemul_darwin_archive_dispatch(process->archive, thunk->name, &status)) return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
            return status == XXEMUL_STATUS_OK ? archive_callback(process, 0) : status;
        case CALL_ARCHIVE_RETURN: return archive_callback(process, 1);
        case CALL_ZLIB:
            if (!process->zlib)
                process->zlib = xxemul_darwin_zlib_create(process->emulator, bridge_allocate, process);
            if (!process->zlib)
                return darwin_error(process, XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION, "The zlib runtime adapter is unavailable on this host");
            if (!xxemul_darwin_zlib_dispatch(process->zlib, thunk->name, &status)) return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
            return status;
        case CALL_BZIP2:
            if (!process->bzip2)
                process->bzip2 = xxemul_darwin_bzip2_create(process->emulator, bridge_allocate, process, process->posix);
            if (!process->bzip2)
                return darwin_error(process, XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION, "The bzip2 runtime adapter is unavailable on this host");
            if (!xxemul_darwin_bzip2_dispatch(process->bzip2, thunk->name, &status)) return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
            return status;
        case CALL_RETURN:
        case CALL_EXIT:
            process->exit_code = (int)(uint32_t)a;
            process->exited = 1;
            process->emulator->halted = 1;
            return XXEMUL_STATUS_HALTED;
        case CALL_STRLEN:
            for (value = 0; value < DARWIN_MAX_STRING; ++value) {
                uint64_t ch;
                if (a > UINT64_MAX - value || !load(process, a + value, 1, &ch)) return XXEMUL_STATUS_ADDRESS_FAULT;
                if (ch == 0) { state->gpr[0] = value; return XXEMUL_STATUS_OK; }
            }
            return darwin_error(process, XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION, "Darwin strlen input exceeds 1 MiB");
        case CALL_SENTRY_CTOR:
            if (!ostream_address(process, b)) return darwin_error(process, XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION, "Unsupported libc++ ostream object");
            if (!load(process, b + 8u + 32u, 4, &value) || !store(process, a, 1, value == 0) || !store(process, a + 8u, 8, b)) return XXEMUL_STATUS_ADDRESS_FAULT;
            return XXEMUL_STATUS_OK;
        case CALL_SENTRY_DTOR:
        case CALL_LOCALE_DTOR:
        case CALL_STRING_DTOR:
            /* Writes are immediate; arena allocations live until process exit. */
            return XXEMUL_STATUS_OK;
        case CALL_GETLOC:
            if (!store(process, state->gpr[8], 8, process->base + DARWIN_LOCALE_OFFSET)) return XXEMUL_STATUS_ADDRESS_FAULT;
            return XXEMUL_STATUS_OK;
        case CALL_USE_FACET:
            if (b != process->base + DARWIN_CTYPE_ID_OFFSET) return darwin_error(process, XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION, "Only the default char ctype facet is supported");
            state->gpr[0] = process->base + DARWIN_FACET_OFFSET;
            return XXEMUL_STATUS_OK;
        case CALL_WIDEN:
            state->gpr[0] = (uint32_t)(int32_t)(int8_t)b;
            return XXEMUL_STATUS_OK;
        case CALL_XSPUTN:
            if (a != process->base + DARWIN_COUT_BUFFER_OFFSET && a != process->base + DARWIN_CERR_BUFFER_OFFSET) return darwin_error(process, XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION, "Unsupported libc++ stream buffer");
            status = write_guest(process, a == process->base + DARWIN_COUT_BUFFER_OFFSET ? 1 : 2, b, c);
            if (status == XXEMUL_STATUS_OK) state->gpr[0] = c;
            return status;
        case CALL_OVERFLOW:
            if ((uint32_t)b == UINT32_MAX) { state->gpr[0] = 0; return XXEMUL_STATUS_OK; }
            if (a != process->base + DARWIN_COUT_BUFFER_OFFSET && a != process->base + DARWIN_CERR_BUFFER_OFFSET) return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
            if (!store(process, process->base + 0x700u, 1, b)) return XXEMUL_STATUS_ADDRESS_FAULT;
            status = write_guest(process, a == process->base + DARWIN_COUT_BUFFER_OFFSET ? 1 : 2, process->base + 0x700u, 1);
            state->gpr[0] = (uint8_t)b;
            return status;
        case CALL_SYNC:
            state->gpr[0] = 0;
            return XXEMUL_STATUS_OK;
        case CALL_STRING_INIT: {
            unsigned char object[24] = {0};
            uint64_t data = a;
            unsigned char block[256];
            uint64_t remaining = b, offset = 0;
            if (!guest_range(process, a, sizeof(object)) || b >= DARWIN_ARENA_SIZE) return XXEMUL_STATUS_ADDRESS_FAULT;
            if (b <= 22u) {
                memset(object, (int)(unsigned char)c, (size_t)b);
                object[23] = (unsigned char)b;
                return xxemul_write_memory(process->emulator, a, object, sizeof(object));
            }
            data = allocate_guest(process, b + 1u);
            if (data == 0) return XXEMUL_STATUS_OUT_OF_MEMORY;
            memset(block, (int)(unsigned char)c, sizeof(block));
            while (remaining != 0) {
                size_t amount = remaining > sizeof(block) ? sizeof(block) : (size_t)remaining;
                if (xxemul_write_memory(process->emulator, data + offset, block, amount) != XXEMUL_STATUS_OK) return XXEMUL_STATUS_ADDRESS_FAULT;
                remaining -= amount;
                offset += amount;
            }
            if (!store(process, data + b, 1, 0) || !store(process, a, 8, data) || !store(process, a + 8u, 8, b) ||
                !store(process, a + 16u, 8, (b + 1u) | (UINT64_C(1) << 63))) return XXEMUL_STATUS_ADDRESS_FAULT;
            return XXEMUL_STATUS_OK;
        }
        case CALL_IOS_CLEAR:
            if (!load(process, a + 36u, 4, &value)) return XXEMUL_STATUS_ADDRESS_FAULT;
            if ((value & b) != 0) return darwin_error(process, XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION, "C++ stream exceptions are unsupported");
            return store(process, a + 32u, 4, b) ? XXEMUL_STATUS_OK : XXEMUL_STATUS_ADDRESS_FAULT;
        case CALL_WRITE:
            if (process->posix != NULL && xxemul_darwin_posix_dispatch(process->posix, "_write", &status)) return status;
            status = write_guest(process, (int)a, b, c);
            if (status == XXEMUL_STATUS_OK) state->gpr[0] = c;
            return status;
        default:
            snprintf(process->error, sizeof(process->error), "Unsupported Darwin runtime call: %.180s", thunk->name);
            return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    }
}

int xxemul_darwin_try_step(xxemul_darwin *process, xxemul_step_info *info, xxemul_status *status)
{
    uint64_t pc;
    unsigned index;
    xxemul_arm_state *state;
    if (process == NULL || !process->started || status == NULL) return 0;
    state = &process->emulator->arm;
    pc = state->pc;
    process->redirect = 0;
    if (pc != 0 && process->packed_entry && process->posix != NULL && pc == xxemul_darwin_posix_dyld_entry(process->posix)) {
        uint64_t header, entry;
        process->error[0] = '\0';
        if (process->dyld_bound || state->sp != process->kernel_sp - 16u || !load(process, state->sp, 8, &header)) {
            *status = darwin_error(process, XXEMUL_STATUS_INVALID_IMAGE, "Invalid or repeated modeled dyld handoff");
        } else {
            *status = xxemul_macho_bind_restored(process->emulator, header, &entry);
            if (*status == XXEMUL_STATUS_OK) {
                process->dyld_bound = 1;
                process->redirect = 1;
                state->gpr[0] = process->main_argc;
                state->gpr[1] = process->main_argv;
                state->gpr[2] = process->main_envp;
                state->gpr[3] = process->main_apple;
                state->gpr[30] = process->return_address;
                state->sp = process->kernel_sp;
                state->pc = entry;
            } else {
                snprintf(process->error, sizeof(process->error), "Modeled dyld rejected guest-restored Mach-O: %s", xxemul_status_string(*status));
            }
        }
    } else if (pc >= process->base + DARWIN_THUNK_OFFSET &&
        pc - (process->base + DARWIN_THUNK_OFFSET) < process->thunk_count * 16u &&
        ((pc - process->base - DARWIN_THUNK_OFFSET) & 15u) == 0) {
        index = (unsigned)((pc - process->base - DARWIN_THUNK_OFFSET) / 16u);
        process->error[0] = '\0';
        *status = call_import(process, &process->thunks[index]);
        if (*status != XXEMUL_STATUS_OK && *status != XXEMUL_STATUS_HALTED && process->error[0] == '\0') {
            snprintf(process->error, sizeof(process->error), "Darwin runtime %s: %.160s", xxemul_status_string(*status), process->thunks[index].name);
        }
    } else return 0;
    if (*status == XXEMUL_STATUS_OK && !process->redirect) state->pc = state->gpr[30];
    if (info != NULL) {
        memset(info, 0, sizeof(*info));
        info->address = pc;
        info->next_address = state->pc;
        if (*status == XXEMUL_STATUS_OK || *status == XXEMUL_STATUS_HALTED) info->size = 4;
    }
    return 1;
}

xxemul_status xxemul_darwin_handle_svc(xxemul_darwin *process, uint64_t immediate)
{
    xxemul_arm_state *state;
    xxemul_status status;
    uint64_t number;
    if (process == NULL || !process->started || (immediate != UINT64_C(0x80) && !(immediate == 0 && process->packed_entry)))
        return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    state = &process->emulator->arm;
    process->error[0] = '\0';
    /* Native Darwin uses x16/svc #0x80. The recognized UPX stub instead
     * emits x8/svc #0; keep that compatibility convention local to it. */
    number = immediate == 0 ? state->gpr[8] : state->gpr[16];
    if ((number & UINT64_C(0xff000000)) == UINT64_C(0x02000000)) number &= UINT64_C(0x00ffffff);
    if (number == 1u) {
        process->exit_code = (int)(uint32_t)state->gpr[0];
        process->exited = 1;
        process->emulator->halted = 1;
        return XXEMUL_STATUS_HALTED;
    }
    if (process->posix != NULL && xxemul_darwin_posix_syscall(process->posix, number, &status)) return status;
    if (number == 4u) {
        uint64_t count = state->gpr[2];
        status = write_guest(process, (int)state->gpr[0], state->gpr[1], count);
        if (status == XXEMUL_STATUS_OK) {
            state->gpr[0] = count;
            state->pstate &= ~UINT32_C(0x20000000); /* clear carry */
        }
        return status;
    }
    snprintf(process->error, sizeof(process->error), "Unsupported Darwin syscall: %" PRIu64, number);
    return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
}

int xxemul_darwin_exit_code(const xxemul_darwin *process)
{
    return process != NULL && process->exited ? process->exit_code : -1;
}

const char *xxemul_darwin_symbol(const xxemul_darwin *process, uint64_t address)
{
    uint64_t offset;
    if (address != 0 && process != NULL && process->packed_entry && process->posix != NULL &&
        address == xxemul_darwin_posix_dyld_entry(process->posix)) return "<Darwin modeled dyld entry>";
    if (process == NULL || address < process->base + DARWIN_THUNK_OFFSET) return NULL;
    offset = address - process->base - DARWIN_THUNK_OFFSET;
    if ((offset & 15u) != 0u || offset / 16u >= process->thunk_count) return NULL;
    return process->thunks[(size_t)(offset / 16u)].name;
}

const char *xxemul_darwin_last_error(const xxemul_darwin *process)
{
    return process != NULL ? process->error : "No Darwin process";
}
