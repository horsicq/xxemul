#include "xxemul_internal.h"
#include "xxemul_darwin_zlib.h"

#include <string.h>

int xxemul_darwin_zlib_supports(const char *name)
{
    static const char *const names[] = {
        "_crc32", "_deflateInit2_", "_deflate", "_deflateEnd",
        "_inflateInit2_", "_inflate", "_inflateEnd"
    };
    size_t i;
    if (!name) return 0;
    for (i = 0; i < sizeof(names) / sizeof(names[0]); ++i) if (!strcmp(name, names[i])) return 1;
    return 0;
}

#if defined(__APPLE__)

#include <dlfcn.h>
#include <stddef.h>
#include <stdlib.h>
#include <zlib.h>

#define GUEST_STREAM_SIZE 112u
#define STREAM_LIMIT 32u
#define BUFFER_LIMIT (32u * 1024u * 1024u)
#define STORAGE_LIMIT (64u * 1024u * 1024u)
#define MESSAGE_SIZE 256u

struct native_api {
    uLong (*crc32)(uLong, const Bytef *, uInt);
    int (*deflate_init)(z_streamp, int, int, int, int, int, const char *, int);
    int (*deflate_run)(z_streamp, int);
    int (*deflate_end)(z_streamp);
    int (*inflate_init)(z_streamp, int, const char *, int);
    int (*inflate_run)(z_streamp, int);
    int (*inflate_end)(z_streamp);
};

struct native_allocation {
    struct native_allocation *next, *previous;
    size_t size;
    max_align_t alignment;
};

struct modeled_stream {
    int active, inflate;
    uint64_t address, token, message;
    z_stream native;
};

struct xxemul_darwin_zlib {
    xxemul *emulator;
    xxemul_darwin_zlib_allocate allocate;
    void *context, *library;
    struct native_api api;
    struct modeled_stream streams[STREAM_LIMIT];
    struct native_allocation *allocations;
    size_t allocated;
    uint64_t error_message;
};

static int guest_range(const xxemul_darwin_zlib *p, uint64_t address, uint64_t size)
{
    return address >= p->emulator->region_address &&
        address - p->emulator->region_address <= p->emulator->region_size &&
        size <= p->emulator->region_size - (address - p->emulator->region_address);
}

static int load(xxemul_darwin_zlib *p, uint64_t address, unsigned size, uint64_t *value)
{
    return xxemul_load_integer(p->emulator, address, (uint8_t)size, value) == XXEMUL_STATUS_OK;
}

static int store(xxemul_darwin_zlib *p, uint64_t address, unsigned size, uint64_t value)
{
    return xxemul_store_integer(p->emulator, address, (uint8_t)size, value) == XXEMUL_STATUS_OK;
}

static const char *version_string(xxemul_darwin_zlib *p, uint64_t address)
{
    size_t available;
    const char *text;
    if (!guest_range(p, address, 1u)) return NULL;
    available = p->emulator->region_size - (size_t)(address - p->emulator->region_address);
    if (available > 64u) available = 64u;
    text = (const char *)p->emulator->region_data + (size_t)(address - p->emulator->region_address);
    return memchr(text, 0, available) ? text : NULL;
}

static int message(xxemul_darwin_zlib *p, uint64_t stream, uint64_t destination, const char *text)
{
    size_t size = 0;
    if (!text) return store(p, stream + 48u, 8, 0);
    while (size < MESSAGE_SIZE - 1u && text[size]) ++size;
    if (xxemul_write_memory(p->emulator, destination, text, size) != XXEMUL_STATUS_OK ||
        !store(p, destination + size, 1, 0)) return 0;
    return store(p, stream + 48u, 8, destination);
}

static voidpf bounded_allocate(voidpf opaque, uInt items, uInt item_size)
{
    xxemul_darwin_zlib *p = opaque;
    struct native_allocation *allocation;
    size_t size;
    if (item_size && items > SIZE_MAX / item_size) return NULL;
    size = (size_t)items * item_size;
    if (size > STORAGE_LIMIT || size > STORAGE_LIMIT - p->allocated || size > SIZE_MAX - sizeof(*allocation)) return NULL;
    allocation = calloc(1, sizeof(*allocation) + size);
    if (!allocation) return NULL;
    allocation->size = size;
    allocation->next = p->allocations;
    if (p->allocations) p->allocations->previous = allocation;
    p->allocations = allocation;
    p->allocated += size;
    return allocation + 1;
}

static void bounded_free(voidpf opaque, voidpf pointer)
{
    xxemul_darwin_zlib *p = opaque;
    struct native_allocation *allocation;
    if (!pointer) return;
    allocation = (struct native_allocation *)pointer - 1;
    if (allocation->previous) allocation->previous->next = allocation->next;
    else p->allocations = allocation->next;
    if (allocation->next) allocation->next->previous = allocation->previous;
    p->allocated -= allocation->size;
    free(allocation);
}

xxemul_darwin_zlib *xxemul_darwin_zlib_create(xxemul *emulator,
    xxemul_darwin_zlib_allocate allocate, void *context)
{
    xxemul_darwin_zlib *p;
    if (!emulator || !allocate) return NULL;
    p = calloc(1, sizeof(*p));
    if (!p) return NULL;
    p->emulator = emulator; p->allocate = allocate; p->context = context;
    p->library = dlopen("/usr/lib/libz.1.dylib", RTLD_LOCAL | RTLD_LAZY);
    if (!p->library) { free(p); return NULL; }
#define LOAD(member, name) do { \
    void *symbol = dlsym(p->library, name); \
    if (!symbol || sizeof(symbol) != sizeof(p->api.member)) goto failed; \
    memcpy(&p->api.member, &symbol, sizeof(symbol)); \
} while (0)
    LOAD(crc32, "crc32");
    LOAD(deflate_init, "deflateInit2_"); LOAD(deflate_run, "deflate"); LOAD(deflate_end, "deflateEnd");
    LOAD(inflate_init, "inflateInit2_"); LOAD(inflate_run, "inflate"); LOAD(inflate_end, "inflateEnd");
#undef LOAD
    p->error_message = allocate(context, MESSAGE_SIZE);
    if (!p->error_message || !guest_range(p, p->error_message, MESSAGE_SIZE)) goto failed;
    return p;
failed:
    dlclose(p->library); free(p); return NULL;
}

void xxemul_darwin_zlib_destroy(xxemul_darwin_zlib *p)
{
    unsigned i;
    if (!p) return;
    for (i = 0; i < STREAM_LIMIT; ++i) if (p->streams[i].active) {
        if (p->streams[i].inflate) p->api.inflate_end(&p->streams[i].native);
        else p->api.deflate_end(&p->streams[i].native);
    }
    while (p->allocations) bounded_free(p, p->allocations + 1);
    dlclose(p->library); free(p);
}

static struct modeled_stream *find_stream(xxemul_darwin_zlib *p, uint64_t address)
{
    unsigned i;
    for (i = 0; i < STREAM_LIMIT; ++i)
        if (p->streams[i].active && p->streams[i].address == address) return &p->streams[i];
    return NULL;
}

static int publish(xxemul_darwin_zlib *p, struct modeled_stream *s, int ended)
{
    return store(p, s->address + 16u, 8, s->native.total_in) &&
        store(p, s->address + 40u, 8, s->native.total_out) &&
        message(p, s->address, s->message, s->native.msg) &&
        store(p, s->address + 56u, 8, ended ? 0 : s->token) &&
        store(p, s->address + 88u, 4, (uint32_t)s->native.data_type) &&
        store(p, s->address + 96u, 8, s->native.adler) &&
        store(p, s->address + 104u, 8, s->native.reserved);
}

static int overlaps(uint64_t first, uint64_t first_size, uint64_t second, uint64_t second_size)
{
    if (!first_size || !second_size) return 0;
    return first <= second ? second - first < first_size : first - second < second_size;
}

int xxemul_darwin_zlib_dispatch(xxemul_darwin_zlib *p, const char *name, xxemul_status *status)
{
    xxemul_arm_state *registers;
    uint64_t address, allocation, release, token;
    struct modeled_stream *s;
    int result = Z_STREAM_ERROR, inflate;
    if (!p || !status || !xxemul_darwin_zlib_supports(name)) return 0;
    *status = XXEMUL_STATUS_OK;
    registers = &p->emulator->arm;
    if (!strcmp(name, "_crc32")) {
        uint64_t buffer = registers->gpr[1];
        uint32_t size = (uint32_t)registers->gpr[2];
        if (!buffer) { registers->gpr[0] = p->api.crc32(0, Z_NULL, 0); return 1; }
        if (size > BUFFER_LIMIT || !guest_range(p, buffer, size)) goto bad_pointer;
        registers->gpr[0] = p->api.crc32((uLong)registers->gpr[0],
            p->emulator->region_data + (size_t)(buffer - p->emulator->region_address), size) & UINT32_MAX;
        return 1;
    }
    address = registers->gpr[0];
    inflate = !strncmp(name, "_inflate", 8u);
    if (!address) goto done;
    if (!guest_range(p, address, GUEST_STREAM_SIZE)) goto bad_pointer;
    if (!load(p, address + 64u, 8, &allocation) || !load(p, address + 72u, 8, &release) || !load(p, address + 56u, 8, &token)) goto bad_pointer;
    s = find_stream(p, address);
    if (!strcmp(name, "_deflateInit2_") || !strcmp(name, "_inflateInit2_")) {
        const char *version;
        uint64_t version_address = registers->gpr[inflate ? 2u : 6u];
        int stream_size = (int32_t)registers->gpr[inflate ? 3u : 7u];
        unsigned i;
        if (stream_size != GUEST_STREAM_SIZE) { result = Z_VERSION_ERROR; goto done; }
        if (s || token) goto done;
        if (allocation || release) {
            if (!message(p, address, p->error_message, "Guest zlib allocation callbacks are unsupported")) goto bad_pointer;
            goto done;
        }
        version = version_string(p, version_address);
        if (!version) goto bad_pointer;
        for (i = 0; i < STREAM_LIMIT && p->streams[i].active; ++i) {}
        if (i == STREAM_LIMIT) { result = Z_MEM_ERROR; goto done; }
        s = &p->streams[i]; memset(s, 0, sizeof(*s));
        s->address = address; s->inflate = inflate;
        s->token = p->allocate(p->context, 16u + MESSAGE_SIZE);
        if (!s->token || !guest_range(p, s->token, 16u + MESSAGE_SIZE)) { result = Z_MEM_ERROR; goto done; }
        s->message = s->token + 16u;
        s->native.zalloc = bounded_allocate; s->native.zfree = bounded_free; s->native.opaque = p;
        if (inflate) result = p->api.inflate_init(&s->native, (int32_t)registers->gpr[1], version, (int)sizeof(s->native));
        else result = p->api.deflate_init(&s->native, (int32_t)registers->gpr[1], (int32_t)registers->gpr[2],
            (int32_t)registers->gpr[3], (int32_t)registers->gpr[4], (int32_t)registers->gpr[5], version, (int)sizeof(s->native));
        s->active = result == Z_OK;
        if (!publish(p, s, !s->active)) goto bad_pointer;
        goto done;
    }
    if (!s || s->inflate != inflate || token != s->token || allocation || release) goto done;
    if (!strcmp(name, "_deflateEnd") || !strcmp(name, "_inflateEnd")) {
        result = inflate ? p->api.inflate_end(&s->native) : p->api.deflate_end(&s->native);
        /* Both End APIs destroy valid internal state even when unfinished
         * deflate reports Z_DATA_ERROR. Never retain a freed native state. */
        if (!publish(p, s, s->native.state == Z_NULL)) goto bad_pointer;
        if (s->native.state == Z_NULL) s->active = 0;
        goto done;
    }
    {
        uint64_t next_in, next_out, available_in, available_out;
        uint32_t consumed, produced;
        int flush = (int32_t)registers->gpr[1];
        if (flush < Z_NO_FLUSH || flush > Z_TREES || (!inflate && flush > Z_BLOCK)) goto done;
        if (!load(p, address, 8, &next_in) || !load(p, address + 8u, 4, &available_in) ||
            !load(p, address + 24u, 8, &next_out) || !load(p, address + 32u, 4, &available_out)) goto bad_pointer;
        if (available_in > BUFFER_LIMIT || available_out > BUFFER_LIMIT ||
            (available_in && !guest_range(p, next_in, available_in)) ||
            (available_out && !guest_range(p, next_out, available_out))) goto bad_pointer;
        if (overlaps(next_in, available_in, address, GUEST_STREAM_SIZE) ||
            overlaps(next_out, available_out, address, GUEST_STREAM_SIZE) ||
            overlaps(next_in, available_in, next_out, available_out)) goto done;
        s->native.next_in = next_in && guest_range(p, next_in, available_in) ?
            p->emulator->region_data + (size_t)(next_in - p->emulator->region_address) : Z_NULL;
        s->native.next_out = next_out && guest_range(p, next_out, available_out) ?
            p->emulator->region_data + (size_t)(next_out - p->emulator->region_address) : Z_NULL;
        s->native.avail_in = (uInt)available_in; s->native.avail_out = (uInt)available_out;
        result = inflate ? p->api.inflate_run(&s->native, flush) : p->api.deflate_run(&s->native, flush);
        consumed = (uint32_t)available_in - s->native.avail_in;
        produced = (uint32_t)available_out - s->native.avail_out;
        if (!store(p, address, 8, next_in + consumed) || !store(p, address + 8u, 4, s->native.avail_in) ||
            !store(p, address + 24u, 8, next_out + produced) || !store(p, address + 32u, 4, s->native.avail_out) ||
            !publish(p, s, 0)) goto bad_pointer;
    }
done:
    registers->gpr[0] = (uint64_t)(int64_t)result;
    return 1;
bad_pointer:
    *status = XXEMUL_STATUS_ADDRESS_FAULT;
    registers->gpr[0] = (uint64_t)(int64_t)Z_STREAM_ERROR;
    return 1;
}

#else

xxemul_darwin_zlib *xxemul_darwin_zlib_create(xxemul *e, xxemul_darwin_zlib_allocate a, void *c)
{ (void)e; (void)a; (void)c; return NULL; }
void xxemul_darwin_zlib_destroy(xxemul_darwin_zlib *p) { (void)p; }
int xxemul_darwin_zlib_dispatch(xxemul_darwin_zlib *p, const char *n, xxemul_status *s)
{ (void)p; (void)n; if (s) *s = XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION; return 0; }

#endif
