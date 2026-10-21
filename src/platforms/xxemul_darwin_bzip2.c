#include "xxemul_internal.h"
#include "xxemul_darwin_bzip2.h"

#include <string.h>

int xxemul_darwin_bzip2_supports(const char *name)
{
    static const char *const names[] = {
        "_BZ2_bzRead", "_BZ2_bzReadClose", "_BZ2_bzReadGetUnused", "_BZ2_bzReadOpen",
        "_BZ2_bzWrite", "_BZ2_bzWriteClose64", "_BZ2_bzWriteOpen", "_BZ2_bzlibVersion"
    };
    size_t i;
    if (!name) return 0;
    for (i = 0; i < sizeof(names) / sizeof(names[0]); ++i) if (!strcmp(name, names[i])) return 1;
    return 0;
}

#if defined(__APPLE__)

#include <bzlib.h>
#include <dlfcn.h>
#include <stddef.h>
#include <stdlib.h>

#define HANDLE_LIMIT 32u
#define IO_SIZE 5000u
#define CALL_LIMIT (32u * 1024u * 1024u)
#define STORAGE_LIMIT (64u * 1024u * 1024u)

struct native_api {
    int (*compress_init)(bz_stream *, int, int, int);
    int (*compress)(bz_stream *, int);
    int (*compress_end)(bz_stream *);
    int (*decompress_init)(bz_stream *, int, int);
    int (*decompress)(bz_stream *);
    int (*decompress_end)(bz_stream *);
    const char *(*version)(void);
};

struct native_allocation {
    struct native_allocation *next, *previous;
    size_t size;
    max_align_t alignment;
};

struct bz_handle {
    int active, writing, ended, eof, error;
    uint64_t token, file, unused;
    bz_stream native;
    unsigned char input[IO_SIZE], output[IO_SIZE];
};

struct xxemul_darwin_bzip2 {
    xxemul *emulator;
    xxemul_darwin_posix *posix;
    xxemul_darwin_posix_allocate allocate;
    void *context, *library;
    struct native_api api;
    struct bz_handle handles[HANDLE_LIMIT];
    struct native_allocation *allocations;
    size_t allocated;
    uint64_t version;
};

static int guest_range(const xxemul_darwin_bzip2 *p, uint64_t address, uint64_t size)
{
    return address >= p->emulator->region_address &&
        address - p->emulator->region_address <= p->emulator->region_size &&
        size <= p->emulator->region_size - (address - p->emulator->region_address);
}

static int store(xxemul_darwin_bzip2 *p, uint64_t address, unsigned size, uint64_t value)
{
    return xxemul_store_integer(p->emulator, address, (uint8_t)size, value) == XXEMUL_STATUS_OK;
}

static void *bounded_allocate(void *opaque, int items, int item_size)
{
    xxemul_darwin_bzip2 *p = opaque;
    struct native_allocation *allocation;
    size_t size;
    if (items < 0 || item_size < 0 || (item_size && (unsigned)items > SIZE_MAX / (unsigned)item_size)) return NULL;
    size = (size_t)items * (size_t)item_size;
    if (size > STORAGE_LIMIT || size > STORAGE_LIMIT - p->allocated || size > SIZE_MAX - sizeof(*allocation)) return NULL;
    allocation = calloc(1, sizeof(*allocation) + size);
    if (!allocation) return NULL;
    allocation->size = size; allocation->next = p->allocations;
    if (p->allocations) p->allocations->previous = allocation;
    p->allocations = allocation; p->allocated += size;
    return allocation + 1;
}

static void bounded_free(void *opaque, void *pointer)
{
    xxemul_darwin_bzip2 *p = opaque;
    struct native_allocation *allocation;
    if (!pointer) return;
    allocation = (struct native_allocation *)pointer - 1;
    if (allocation->previous) allocation->previous->next = allocation->next;
    else p->allocations = allocation->next;
    if (allocation->next) allocation->next->previous = allocation->previous;
    p->allocated -= allocation->size;
    free(allocation);
}

xxemul_darwin_bzip2 *xxemul_darwin_bzip2_create(xxemul *emulator,
    xxemul_darwin_posix_allocate allocate, void *context, xxemul_darwin_posix *posix)
{
    xxemul_darwin_bzip2 *p;
    const char *version;
    size_t length;
    if (!emulator || !allocate || !posix) return NULL;
    p = calloc(1, sizeof(*p));
    if (!p) return NULL;
    p->emulator = emulator; p->allocate = allocate; p->context = context; p->posix = posix;
    p->library = dlopen("/usr/lib/libbz2.1.0.dylib", RTLD_LOCAL | RTLD_LAZY);
    if (!p->library) { free(p); return NULL; }
#define LOAD(member, name) do { \
    void *symbol = dlsym(p->library, name); \
    if (!symbol || sizeof(symbol) != sizeof(p->api.member)) goto failed; \
    memcpy(&p->api.member, &symbol, sizeof(symbol)); \
} while (0)
    LOAD(compress_init, "BZ2_bzCompressInit"); LOAD(compress, "BZ2_bzCompress"); LOAD(compress_end, "BZ2_bzCompressEnd");
    LOAD(decompress_init, "BZ2_bzDecompressInit"); LOAD(decompress, "BZ2_bzDecompress"); LOAD(decompress_end, "BZ2_bzDecompressEnd");
    LOAD(version, "BZ2_bzlibVersion");
#undef LOAD
    version = p->api.version(); length = strlen(version) + 1u;
    if (length > 256u) goto failed;
    p->version = allocate(context, length);
    if (!p->version || xxemul_write_memory(emulator, p->version, version, length) != XXEMUL_STATUS_OK) goto failed;
    return p;
failed:
    dlclose(p->library); free(p); return NULL;
}

static void release_handle(xxemul_darwin_bzip2 *p, struct bz_handle *h)
{
    if (!h || !h->active) return;
    if (h->writing) p->api.compress_end(&h->native);
    else p->api.decompress_end(&h->native);
    memset(h, 0, sizeof(*h));
}

void xxemul_darwin_bzip2_destroy(xxemul_darwin_bzip2 *p)
{
    unsigned i;
    if (!p) return;
    /* Destroy abandons unfinished output, without touching any FILE lifetime. */
    for (i = 0; i < HANDLE_LIMIT; ++i) release_handle(p, &p->handles[i]);
    while (p->allocations) bounded_free(p, p->allocations + 1);
    dlclose(p->library); free(p);
}

static struct bz_handle *find_handle(xxemul_darwin_bzip2 *p, uint64_t token)
{
    unsigned i;
    for (i = 0; i < HANDLE_LIMIT; ++i)
        if (p->handles[i].active && p->handles[i].token == token) return &p->handles[i];
    return NULL;
}

static struct bz_handle *new_handle(xxemul_darwin_bzip2 *p, uint64_t file, int writing,
    int parameter, int work_factor, int *error)
{
    struct bz_handle *h;
    unsigned i;
    if (!xxemul_darwin_posix_validate_stream(p->posix, file, writing)) { *error = BZ_IO_ERROR; return NULL; }
    for (i = 0; i < HANDLE_LIMIT && p->handles[i].active; ++i) {}
    if (i == HANDLE_LIMIT) { *error = BZ_MEM_ERROR; return NULL; }
    h = &p->handles[i]; memset(h, 0, sizeof(*h));
    h->token = p->allocate(p->context, 16u + IO_SIZE);
    if (!h->token || !guest_range(p, h->token, 16u + IO_SIZE)) { *error = BZ_MEM_ERROR; return NULL; }
    h->unused = h->token + 16u; h->file = file; h->writing = writing;
    h->native.bzalloc = bounded_allocate; h->native.bzfree = bounded_free; h->native.opaque = p;
    *error = writing ? p->api.compress_init(&h->native, parameter, 0, work_factor) : p->api.decompress_init(&h->native, 0, parameter);
    h->active = *error == BZ_OK;
    return h->active ? h : NULL;
}

static int write_output(xxemul_darwin_bzip2 *p, struct bz_handle *h, size_t size)
{
    size_t position = 0;
    while (position < size) {
        int64_t wrote = xxemul_darwin_posix_write_stream(p->posix, h->file, h->output + position, size - position);
        if (wrote <= 0 || (uint64_t)wrote > size - position) return BZ_IO_ERROR;
        position += (size_t)wrote;
    }
    return BZ_OK;
}

static int write_data(xxemul_darwin_bzip2 *p, struct bz_handle *h, void *data, unsigned length)
{
    if (!xxemul_darwin_posix_validate_stream(p->posix, h->file, 1)) return BZ_IO_ERROR;
    if (h->error != BZ_OK) return h->error;
    h->native.next_in = data; h->native.avail_in = length;
    while (h->native.avail_in) {
        unsigned before = h->native.avail_in;
        size_t produced;
        int result;
        h->native.next_out = (char *)h->output; h->native.avail_out = IO_SIZE;
        result = p->api.compress(&h->native, BZ_RUN);
        if (result != BZ_RUN_OK) return result;
        produced = IO_SIZE - h->native.avail_out;
        if (write_output(p, h, produced) != BZ_OK) return BZ_IO_ERROR;
        if (!produced && before == h->native.avail_in) return BZ_SEQUENCE_ERROR;
    }
    return BZ_OK;
}

static int finish_write(xxemul_darwin_bzip2 *p, struct bz_handle *h)
{
    if (!xxemul_darwin_posix_validate_stream(p->posix, h->file, 1)) return BZ_IO_ERROR;
    if (h->error != BZ_OK) return h->error;
    for (;;) {
        int result;
        size_t produced;
        h->native.next_out = (char *)h->output; h->native.avail_out = IO_SIZE;
        result = p->api.compress(&h->native, BZ_FINISH);
        if (result != BZ_FINISH_OK && result != BZ_STREAM_END) return result;
        produced = IO_SIZE - h->native.avail_out;
        if (write_output(p, h, produced) != BZ_OK) return BZ_IO_ERROR;
        if (result == BZ_STREAM_END) return xxemul_darwin_posix_flush_stream(p->posix, h->file) ? BZ_IO_ERROR : BZ_OK;
        if (!produced) return BZ_SEQUENCE_ERROR;
    }
}

static unsigned read_data(xxemul_darwin_bzip2 *p, struct bz_handle *h, void *data, unsigned length, int *error)
{
    size_t read_this_call = 0;
    if (!xxemul_darwin_posix_validate_stream(p->posix, h->file, 0)) { *error = BZ_IO_ERROR; return 0; }
    if (h->ended) { *error = BZ_SEQUENCE_ERROR; return 0; }
    if (h->error != BZ_OK) { *error = h->error; return 0; }
    if (!length) { *error = BZ_OK; return 0; }
    h->native.next_out = data; h->native.avail_out = length;
    while (h->native.avail_out) {
        unsigned before_in, before_out;
        int result;
        if (!h->native.avail_in && !h->eof) {
            int64_t got;
            size_t amount;
            if (read_this_call >= CALL_LIMIT) { *error = BZ_DATA_ERROR; return 0; }
            amount = CALL_LIMIT - read_this_call;
            if (amount > IO_SIZE) amount = IO_SIZE;
            got = xxemul_darwin_posix_read_stream(p->posix, h->file, h->input, amount);
            if (got < 0 || (uint64_t)got > amount) { *error = BZ_IO_ERROR; return 0; }
            if (!got) h->eof = 1;
            read_this_call += (size_t)got;
            h->native.next_in = (char *)h->input; h->native.avail_in = (unsigned)got;
        }
        before_in = h->native.avail_in; before_out = h->native.avail_out;
        result = p->api.decompress(&h->native);
        if (result == BZ_STREAM_END) { h->ended = 1; *error = result; return length - h->native.avail_out; }
        if (result != BZ_OK) { *error = result; return 0; }
        if (!h->native.avail_out) { *error = BZ_OK; return length; }
        if (h->eof && !h->native.avail_in) { *error = BZ_UNEXPECTED_EOF; return 0; }
        if (before_in == h->native.avail_in && before_out == h->native.avail_out) { *error = BZ_DATA_ERROR; return 0; }
    }
    *error = BZ_OK;
    return length;
}

int xxemul_darwin_bzip2_dispatch(xxemul_darwin_bzip2 *p, const char *name, xxemul_status *status)
{
    uint64_t arguments[8], error_pointer, result = 0;
    struct bz_handle *h;
    int error = BZ_OK;
    unsigned i;
    if (!p || !status || !xxemul_darwin_bzip2_supports(name)) return 0;
    *status = XXEMUL_STATUS_OK;
    memcpy(arguments, p->emulator->arm.gpr, sizeof(arguments));
    if (!strcmp(name, "_BZ2_bzlibVersion")) { p->emulator->arm.gpr[0] = p->version; return 1; }
    error_pointer = arguments[0];
    if (error_pointer && !guest_range(p, error_pointer, 4u)) goto bad_pointer;
    h = find_handle(p, arguments[1]);
    if (!strcmp(name, "_BZ2_bzReadOpen")) {
        int verbosity = (int32_t)arguments[2], small = (int32_t)arguments[3], unused = (int32_t)arguments[5];
        if (verbosity != 0 || small < 0 || small > 1 || unused < 0 || unused > (int)IO_SIZE || (!arguments[4] && unused)) {
            error = BZ_PARAM_ERROR; goto done;
        }
        if (unused && !guest_range(p, arguments[4], (unsigned)unused)) goto bad_pointer;
        h = new_handle(p, arguments[1], 0, small, 0, &error);
        if (h) {
            if (unused) memcpy(h->input, p->emulator->region_data + (size_t)(arguments[4] - p->emulator->region_address), (size_t)unused);
            h->native.next_in = (char *)h->input; h->native.avail_in = (unsigned)unused;
            result = h->token;
        }
        goto done;
    }
    if (!strcmp(name, "_BZ2_bzWriteOpen")) {
        int block = (int32_t)arguments[2], verbosity = (int32_t)arguments[3], factor = (int32_t)arguments[4];
        if (block < 1 || block > 9 || verbosity != 0 || factor < 0 || factor > 250) { error = BZ_PARAM_ERROR; goto done; }
        h = new_handle(p, arguments[1], 1, block, factor, &error);
        if (h) result = h->token;
        goto done;
    }
    if (!strcmp(name, "_BZ2_bzReadClose")) {
        if (!arguments[1]) goto done;
        if (!h) { error = BZ_PARAM_ERROR; goto done; }
        if (h->writing) { error = BZ_SEQUENCE_ERROR; goto done; }
        release_handle(p, h); goto done;
    }
    if (!strcmp(name, "_BZ2_bzWriteClose64")) {
        for (i = 3; i < 7u; ++i) if (arguments[i] && !guest_range(p, arguments[i], 4u)) goto bad_pointer;
        if (!arguments[1]) {
            for (i = 3; i < 7u; ++i) if (arguments[i] && !store(p, arguments[i], 4u, 0)) goto bad_pointer;
            goto done;
        }
        if (!h) { error = BZ_PARAM_ERROR; goto done; }
        if (!h->writing) { error = BZ_SEQUENCE_ERROR; goto done; }
        if (!(int32_t)arguments[2]) {
            error = finish_write(p, h);
            if (error != BZ_OK) { h->error = error; goto done; }
        }
        {
            const unsigned counters[4] = {h->native.total_in_lo32, h->native.total_in_hi32,
                h->native.total_out_lo32, h->native.total_out_hi32};
            for (i = 0; i < 4u; ++i) if (arguments[i + 3u] && !store(p, arguments[i + 3u], 4u, counters[i])) goto bad_pointer;
        }
        release_handle(p, h); goto done;
    }
    if (!h) { error = BZ_PARAM_ERROR; goto done; }
    if (!strcmp(name, "_BZ2_bzReadGetUnused")) {
        if (h->writing || !h->ended) { error = BZ_SEQUENCE_ERROR; goto done; }
        if (!arguments[2] || !arguments[3]) { error = BZ_PARAM_ERROR; goto done; }
        if (!guest_range(p, arguments[2], 8u) || !guest_range(p, arguments[3], 4u)) goto bad_pointer;
        if (h->native.avail_in > IO_SIZE) { error = BZ_DATA_ERROR; goto done; }
        if (xxemul_write_memory(p->emulator, h->unused, h->native.next_in, h->native.avail_in) != XXEMUL_STATUS_OK ||
            !store(p, arguments[2], 8u, h->unused) || !store(p, arguments[3], 4u, h->native.avail_in)) goto bad_pointer;
        goto done;
    }
    if (!strcmp(name, "_BZ2_bzWrite") || !strcmp(name, "_BZ2_bzRead")) {
        int writing = !strcmp(name, "_BZ2_bzWrite");
        int length = (int32_t)arguments[3];
        void *buffer = NULL;
        if (writing != h->writing) { error = BZ_SEQUENCE_ERROR; goto done; }
        if (length < 0 || (unsigned)length > CALL_LIMIT || (!arguments[2] && length)) { error = BZ_PARAM_ERROR; goto done; }
        if (length && !guest_range(p, arguments[2], (unsigned)length)) goto bad_pointer;
        if (length) buffer = p->emulator->region_data + (size_t)(arguments[2] - p->emulator->region_address);
        if (writing) { error = write_data(p, h, buffer, (unsigned)length); h->error = error; }
        else {
            result = read_data(p, h, buffer, (unsigned)length, &error);
            if (error < BZ_OK) h->error = error;
        }
        goto done;
    }
    error = BZ_PARAM_ERROR;
done:
    if (error_pointer && !store(p, error_pointer, 4u, (uint32_t)error)) goto bad_pointer;
    p->emulator->arm.gpr[0] = result;
    return 1;
bad_pointer:
    *status = XXEMUL_STATUS_ADDRESS_FAULT;
    p->emulator->arm.gpr[0] = 0;
    return 1;
}

#else

xxemul_darwin_bzip2 *xxemul_darwin_bzip2_create(xxemul *e,
    xxemul_darwin_posix_allocate a, void *c, xxemul_darwin_posix *p)
{ (void)e; (void)a; (void)c; (void)p; return NULL; }
void xxemul_darwin_bzip2_destroy(xxemul_darwin_bzip2 *p) { (void)p; }
int xxemul_darwin_bzip2_dispatch(xxemul_darwin_bzip2 *p, const char *n, xxemul_status *s)
{ (void)p; (void)n; if (s) *s = XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION; return 0; }

#endif
