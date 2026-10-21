#include "xxemul_internal.h"
#include "xxemul_darwin_archive.h"

#if defined(__APPLE__)

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define ARC_LIMIT (32u * 1024u * 1024u)
#define ARC_HANDLES 128u
#define ARC_PATH 4096u
#define ARC_OK 0
#define ARC_EOF 1
#define ARC_FAILED (-25)
#define ARC_FATAL (-30)

struct archive;
struct archive_entry;
struct archive_entry_linkresolver;

/* Private declarations deliberately use only public, stable libarchive ABI.
 * No host archive open_filename/read_disk/write_disk operation is imported. */
#define NATIVE_FUNCTIONS(F) \
 F(struct archive *, archive_write_new, (void)) \
 F(int, archive_write_set_format_pax_restricted, (struct archive *)) \
 F(int, archive_write_set_format_by_name, (struct archive *, const char *)) \
 F(int, archive_write_set_format, (struct archive *, int)) \
 F(int, archive_write_set_options, (struct archive *, const char *)) \
 F(int, archive_write_set_bytes_per_block, (struct archive *, int)) \
 F(int, archive_write_set_bytes_in_last_block, (struct archive *, int)) \
 F(int, archive_write_open_memory, (struct archive *, void *, size_t, size_t *)) \
 F(int, archive_write_header, (struct archive *, struct archive_entry *)) \
 F(ssize_t, archive_write_data, (struct archive *, const void *, size_t)) \
 F(int, archive_write_close, (struct archive *)) \
 F(int, archive_write_free, (struct archive *)) \
 F(struct archive *, archive_read_new, (void)) \
 F(int, archive_read_support_filter_none, (struct archive *)) \
 F(int, archive_read_support_format_tar, (struct archive *)) \
 F(int, archive_read_support_format_empty, (struct archive *)) \
 F(int, archive_read_set_options, (struct archive *, const char *)) \
 F(int, archive_read_open_memory, (struct archive *, const void *, size_t)) \
 F(int, archive_read_next_header, (struct archive *, struct archive_entry **)) \
 F(int, archive_read_data_block, (struct archive *, const void **, size_t *, int64_t *)) \
 F(int, archive_read_data_skip, (struct archive *)) \
 F(int, archive_read_close, (struct archive *)) \
 F(int, archive_read_free, (struct archive *)) \
 F(int64_t, archive_read_header_position, (struct archive *)) \
 F(struct archive_entry *, archive_entry_new, (void)) \
 F(struct archive_entry *, archive_entry_clone, (struct archive_entry *)) \
 F(struct archive_entry *, archive_entry_clear, (struct archive_entry *)) \
 F(void, archive_entry_free, (struct archive_entry *)) \
 F(void, archive_entry_copy_stat, (struct archive_entry *, const struct stat *)) \
 F(void, archive_entry_copy_pathname, (struct archive_entry *, const char *)) \
 F(void, archive_entry_copy_sourcepath, (struct archive_entry *, const char *)) \
 F(void, archive_entry_copy_hardlink, (struct archive_entry *, const char *)) \
 F(void, archive_entry_copy_symlink, (struct archive_entry *, const char *)) \
 F(const char *, archive_entry_pathname, (struct archive_entry *)) \
 F(const char *, archive_entry_sourcepath, (struct archive_entry *)) \
 F(const char *, archive_entry_hardlink, (struct archive_entry *)) \
 F(const char *, archive_entry_symlink, (struct archive_entry *)) \
 F(const char *, archive_entry_uname, (struct archive_entry *)) \
 F(const char *, archive_entry_gname, (struct archive_entry *)) \
 F(const char *, archive_entry_strmode, (struct archive_entry *)) \
 F(mode_t, archive_entry_filetype, (struct archive_entry *)) \
 F(mode_t, archive_entry_perm, (struct archive_entry *)) \
 F(unsigned int, archive_entry_nlink, (struct archive_entry *)) \
 F(int64_t, archive_entry_size, (struct archive_entry *)) \
 F(int64_t, archive_entry_uid, (struct archive_entry *)) \
 F(int64_t, archive_entry_gid, (struct archive_entry *)) \
 F(time_t, archive_entry_mtime, (struct archive_entry *)) \
 F(dev_t, archive_entry_rdevmajor, (struct archive_entry *)) \
 F(dev_t, archive_entry_rdevminor, (struct archive_entry *)) \
 F(void, archive_entry_set_uid, (struct archive_entry *, int64_t)) \
 F(void, archive_entry_set_gid, (struct archive_entry *, int64_t)) \
 F(void, archive_entry_set_size, (struct archive_entry *, int64_t)) \
 F(void, archive_entry_set_uname, (struct archive_entry *, const char *)) \
 F(void, archive_entry_set_gname, (struct archive_entry *, const char *)) \
 F(struct archive *, archive_match_new, (void)) \
 F(int, archive_match_free, (struct archive *)) \
 F(int, archive_match_excluded, (struct archive *, struct archive_entry *)) \
 F(int, archive_match_exclude_pattern, (struct archive *, const char *)) \
 F(int, archive_match_include_pattern, (struct archive *, const char *)) \
 F(int, archive_match_path_unmatched_inclusions, (struct archive *)) \
 F(int, archive_match_path_unmatched_inclusions_next, (struct archive *, const char **)) \
 F(int, archive_match_set_inclusion_recursion, (struct archive *, int)) \
 F(struct archive_entry_linkresolver *, archive_entry_linkresolver_new, (void)) \
 F(void, archive_entry_linkresolver_free, (struct archive_entry_linkresolver *)) \
 F(void, archive_entry_linkresolver_set_strategy, (struct archive_entry_linkresolver *, int)) \
 F(void, archive_entry_linkify, (struct archive_entry_linkresolver *, struct archive_entry **, struct archive_entry **)) \
 F(int, archive_errno, (struct archive *)) \
 F(const char *, archive_error_string, (struct archive *)) \
 F(void, archive_clear_error, (struct archive *)) \
 F(int, archive_format, (struct archive *)) \
 F(const char *, archive_format_name, (struct archive *)) \
 F(int, archive_file_count, (struct archive *)) \
 F(int64_t, archive_filter_bytes, (struct archive *, int)) \
 F(int, archive_filter_code, (struct archive *, int)) \
 F(const char *, archive_filter_name, (struct archive *, int)) \
 F(const char *, archive_version_details, (void))

struct native_api {
#define DECLARE(result, name, arguments) result (*name) arguments;
    NATIVE_FUNCTIONS(DECLARE)
#undef DECLARE
};

enum object_kind { A_FREE, A_WRITER, A_READER, A_DISK, A_EXTRACT, A_ENTRY, A_MATCH, A_LINK };
struct archive_object {
    enum object_kind kind;
    uint64_t token;
    void *native;
    int fd, opened, closed, delivered, eof;
    unsigned char *memory;
    size_t size, used, position, capacity;
    uint64_t data_buffer, returned_entry;
    char path[ARC_PATH], error[256];
    int error_number;
    unsigned entries, options;
    uint64_t matching, metadata, metadata_data, excluded, excluded_data;
    uint64_t progress, progress_data, passphrase, passphrase_data;
};

struct xxemul_darwin_archive {
    xxemul *emulator;
    xxemul_darwin_posix *posix;
    xxemul_darwin_posix_allocate allocate;
    void *context, *library;
    struct native_api api;
    struct archive_object objects[ARC_HANDLES];
    size_t host_bytes;
    int pending, inflight, operation;
    uint64_t callback, arguments[3];
    unsigned argument_count;
    struct archive_object *active, *active_entry, *extract_destination;
    int extract_fd;
    uint64_t extract_size;
};

static int memory_range(xxemul_darwin_archive *p, uint64_t address, uint64_t size)
{
    return address >= p->emulator->region_address &&
        address - p->emulator->region_address <= p->emulator->region_size &&
        size <= p->emulator->region_size - (address - p->emulator->region_address);
}

static const char *guest_string(xxemul_darwin_archive *p, uint64_t address)
{
    size_t available;
    const char *text;
    if (!memory_range(p, address, 1u)) return NULL;
    available = p->emulator->region_size - (size_t)(address - p->emulator->region_address);
    if (available > ARC_PATH) available = ARC_PATH;
    text = (const char *)p->emulator->region_data + (size_t)(address - p->emulator->region_address);
    return memchr(text, 0, available) ? text : NULL;
}

static uint64_t copy_string(xxemul_darwin_archive *p, const char *text)
{
    size_t size;
    uint64_t address;
    if (!text) return 0;
    size = strlen(text) + 1u;
    if (size > ARC_PATH) return 0;
    address = p->allocate(p->context, size);
    return address && xxemul_write_memory(p->emulator, address, text, size) == XXEMUL_STATUS_OK ? address : 0;
}

static struct archive_object *object(xxemul_darwin_archive *p, uint64_t token)
{
    unsigned i;
    for (i = 0; i < ARC_HANDLES; ++i)
        if (p->objects[i].kind != A_FREE && p->objects[i].token == token) return &p->objects[i];
    return NULL;
}

static struct archive_object *new_object(xxemul_darwin_archive *p, enum object_kind kind, void *native)
{
    unsigned i;
    for (i = 0; i < ARC_HANDLES; ++i) if (p->objects[i].kind == A_FREE) {
        struct archive_object *o = &p->objects[i];
        uint64_t token = p->allocate(p->context, 16u);
        if (!token) return NULL;
        memset(o, 0, sizeof(*o));
        o->token = token; o->kind = kind; o->native = native; o->fd = -1;
        return o;
    }
    return NULL;
}

static int archive_error(struct archive_object *o, int error, const char *text)
{
    if (o) { o->error_number = error; snprintf(o->error, sizeof(o->error), "%s", text); }
    return ARC_FAILED;
}

static int allocate_buffer(xxemul_darwin_archive *p, struct archive_object *o)
{
    if (p->host_bytes > 2u * ARC_LIMIT - ARC_LIMIT) return 0;
    o->memory = malloc(ARC_LIMIT);
    if (!o->memory) return 0;
    o->capacity = ARC_LIMIT; p->host_bytes += ARC_LIMIT;
    return 1;
}

static void free_buffer(xxemul_darwin_archive *p, struct archive_object *o)
{
    free(o->memory); o->memory = NULL;
    p->host_bytes -= o->capacity; o->capacity = 0;
}

static int write_all(int fd, const void *data, size_t size)
{
    const unsigned char *bytes = data;
    while (size) {
        ssize_t wrote = write(fd, bytes, size);
        if (wrote < 0 && errno == EINTR) continue;
        if (wrote <= 0) return 0;
        bytes += (size_t)wrote; size -= (size_t)wrote;
    }
    return 1;
}

static int close_object(xxemul_darwin_archive *p, struct archive_object *o)
{
    int result = ARC_OK;
    if (o->closed) return ARC_OK;
    if (o->kind == A_WRITER && o->opened) {
        result = p->api.archive_write_close(o->native);
        if (result == ARC_OK && (o->fd < 0 || o->used > ARC_LIMIT || !write_all(o->fd, o->memory, o->used)))
            result = archive_error(o, errno ? errno : EIO, "Cannot write confined archive file");
    } else if (o->kind == A_READER && o->opened) result = p->api.archive_read_close(o->native);
    if (o->fd >= 0) { if (close(o->fd) && result == ARC_OK) result = archive_error(o, errno, "Cannot close archive file"); o->fd = -1; }
    o->closed = 1;
    return result;
}

static void free_object(xxemul_darwin_archive *p, struct archive_object *o)
{
    struct archive_object *borrowed;
    if (!o) return;
    borrowed = object(p, o->returned_entry);
    if (borrowed && borrowed != o) free_object(p, borrowed);
    (void)close_object(p, o);
    if (o->native) switch (o->kind) {
        case A_WRITER: p->api.archive_write_free(o->native); break;
        case A_READER: p->api.archive_read_free(o->native); break;
        case A_ENTRY: p->api.archive_entry_free(o->native); break;
        case A_MATCH: p->api.archive_match_free(o->native); break;
        case A_LINK: p->api.archive_entry_linkresolver_free(o->native); break;
        default: break;
    }
    free_buffer(p, o); memset(o, 0, sizeof(*o)); o->fd = -1;
}

xxemul_darwin_archive *xxemul_darwin_archive_create(xxemul *emulator,
    xxemul_darwin_posix_allocate allocate, void *context, xxemul_darwin_posix *posix)
{
    xxemul_darwin_archive *p;
    if (!emulator || !allocate || !posix) return NULL;
    p = calloc(1, sizeof(*p));
    if (!p) return NULL;
    p->emulator = emulator; p->allocate = allocate; p->context = context; p->posix = posix; p->extract_fd = -1;
    p->library = dlopen("/usr/lib/libarchive.2.dylib", RTLD_LOCAL | RTLD_LAZY);
    if (!p->library) { free(p); return NULL; }
#define LOAD(result, name, arguments) do { \
    void *symbol = dlsym(p->library, #name); \
    if (!symbol || sizeof(symbol) != sizeof(p->api.name)) goto failed; \
    memcpy(&p->api.name, &symbol, sizeof(symbol)); \
} while (0);
    NATIVE_FUNCTIONS(LOAD)
#undef LOAD
    return p;
failed:
    dlclose(p->library); free(p); return NULL;
}

void xxemul_darwin_archive_destroy(xxemul_darwin_archive *p)
{
    unsigned i;
    if (!p) return;
    if (p->extract_fd >= 0) close(p->extract_fd);
    for (i = 0; i < ARC_HANDLES; ++i) if (p->objects[i].kind != A_FREE) free_object(p, &p->objects[i]);
    dlclose(p->library); free(p);
}

int xxemul_darwin_archive_supports(const char *name)
{
    return name && !strncmp(name, "_archive_", 9u);
}

static int load_fd(xxemul_darwin_archive *p, struct archive_object *o)
{
    struct stat st;
    size_t used = 0;
    if (fstat(o->fd, &st) || (S_ISREG(st.st_mode) && (st.st_size < 0 || (uint64_t)st.st_size > ARC_LIMIT)))
        return archive_error(o, errno ? errno : EFBIG, "Archive input exceeds memory limit");
    if (!allocate_buffer(p, o)) return archive_error(o, ENOMEM, "Archive buffers exceed the 64 MiB process limit");
    while (used < ARC_LIMIT) {
        ssize_t got = read(o->fd, o->memory + used, ARC_LIMIT - used);
        if (got < 0 && errno == EINTR) continue;
        if (got < 0) return archive_error(o, errno, "Cannot read confined archive input");
        if (!got) { o->size = used; return ARC_OK; }
        used += (size_t)got;
    }
    { unsigned char extra; if (read(o->fd, &extra, 1u) != 0) return archive_error(o, EFBIG, "Archive input exceeds memory limit"); }
    o->size = used;
    return ARC_OK;
}

static int open_archive(xxemul_darwin_archive *p, struct archive_object *o, uint64_t argument, int by_fd)
{
    const char *path;
    int result;
    if (o->opened || o->closed || (o->kind != A_READER && o->kind != A_WRITER))
        return archive_error(o, EINVAL, "Invalid archive open state");
    if (by_fd) o->fd = xxemul_darwin_posix_dup_host(p->posix, argument);
    else {
        path = guest_string(p, argument);
        if (!path) return archive_error(o, EFAULT, "Invalid archive pathname");
        o->fd = xxemul_darwin_posix_open_host(p->posix, path,
            o->kind == A_READER ? O_RDONLY : O_WRONLY | O_CREAT | O_TRUNC, 0666u);
    }
    if (o->fd < 0) return archive_error(o, errno, "Cannot open confined archive file");
    if (o->kind == A_READER) {
        result = load_fd(p, o);
        if (result == ARC_OK) result = p->api.archive_read_open_memory(o->native, o->memory, o->size);
    } else {
        result = allocate_buffer(p, o) ? p->api.archive_write_open_memory(o->native, o->memory, ARC_LIMIT, &o->used) :
            archive_error(o, ENOMEM, "Cannot allocate archive output");
    }
    if (result == ARC_OK) o->opened = 1;
    else { close(o->fd); o->fd = -1; free_buffer(p, o); }
    return result;
}

static void queue_callback(xxemul_darwin_archive *p, int operation, struct archive_object *o,
    struct archive_object *entry, uint64_t target, unsigned count, uint64_t a, uint64_t b, uint64_t c)
{
    p->operation = operation; p->active = o; p->active_entry = entry;
    p->callback = target; p->argument_count = count;
    p->arguments[0] = a; p->arguments[1] = b; p->arguments[2] = c; p->pending = 1;
}

static int next_disk_header(xxemul_darwin_archive *p, struct archive_object *o, struct archive_object *entry)
{
    struct stat st;
    struct archive_object *matching;
    if (o->delivered) return ARC_EOF;
    if (!o->opened || o->fd < 0 || fstat(o->fd, &st)) return archive_error(o, errno, "Cannot stat confined input file");
    if (!S_ISREG(st.st_mode) || st.st_size < 0 || (uint64_t)st.st_size > ARC_LIMIT)
        return archive_error(o, ENOTSUP, "Archive disk model supports bounded regular files");
    p->api.archive_entry_clear(entry->native);
    p->api.archive_entry_copy_stat(entry->native, &st);
    p->api.archive_entry_copy_pathname(entry->native, o->path);
    p->api.archive_entry_copy_sourcepath(entry->native, o->path);
    o->size = (size_t)st.st_size; o->position = 0; o->delivered = 1;
    matching = object(p, o->matching);
    if (matching && p->api.archive_match_excluded(matching->native, entry->native)) {
        if (o->excluded) queue_callback(p, 2, o, entry, o->excluded, 3, o->token, o->excluded_data, entry->token);
        return ARC_EOF;
    }
    if (o->metadata) queue_callback(p, 1, o, entry, o->metadata, 3, o->token, o->metadata_data, entry->token);
    ++o->entries;
    return ARC_OK;
}

static int data_block(xxemul_darwin_archive *p, struct archive_object *o, uint64_t pointer,
    uint64_t size_pointer, uint64_t offset_pointer)
{
    const void *bytes;
    size_t size;
    int64_t offset;
    unsigned char buffer[65536];
    int result;
    if (!memory_range(p, pointer, 8u) || !memory_range(p, size_pointer, 8u) || !memory_range(p, offset_pointer, 8u)) return ARC_FATAL;
    if (o->kind == A_DISK) {
        ssize_t got;
        if (o->position >= o->size) return ARC_EOF;
        size = o->size - o->position;
        if (size > sizeof(buffer)) size = sizeof(buffer);
        do { got = pread(o->fd, buffer, size, (off_t)o->position); } while (got < 0 && errno == EINTR);
        if (got <= 0) return archive_error(o, errno ? errno : EIO, "Cannot read archive source data");
        bytes = buffer; size = (size_t)got; offset = (int64_t)o->position; o->position += size;
    } else {
        result = p->api.archive_read_data_block(o->native, &bytes, &size, &offset);
        if (result != ARC_OK) return result;
    }
    if (size > ARC_LIMIT) return archive_error(o, EFBIG, "Archive data block exceeds limit");
    /* libarchive may expose a block larger than a disk traversal block. */
    if (!o->data_buffer || size > o->used) {
        o->data_buffer = p->allocate(p->context, size ? size : 1u); o->used = size;
    }
    if (!o->data_buffer || xxemul_write_memory(p->emulator, o->data_buffer, bytes, size) != XXEMUL_STATUS_OK ||
        xxemul_store_integer(p->emulator, pointer, 8u, o->data_buffer) != XXEMUL_STATUS_OK ||
        xxemul_store_integer(p->emulator, size_pointer, 8u, size) != XXEMUL_STATUS_OK ||
        xxemul_store_integer(p->emulator, offset_pointer, 8u, (uint64_t)offset) != XXEMUL_STATUS_OK) return ARC_FATAL;
    return ARC_OK;
}

static int relative_path(const char *path)
{
    const char *p;
    if (!path || !*path || *path == '/') return 0;
    for (p = path; *p;) {
        const char *begin;
        while (*p == '/') ++p;
        begin = p; while (*p && *p != '/') ++p;
        if (p - begin == 2 && begin[0] == '.' && begin[1] == '.') return 0;
    }
    return 1;
}

static int extract_next(xxemul_darwin_archive *p)
{
    struct archive_object *o = p->active;
    for (;;) {
        const void *buffer;
        size_t size;
        int64_t offset;
        int result = p->api.archive_read_data_block(o->native, &buffer, &size, &offset);
        if (result == ARC_EOF) {
            int failed = ftruncate(p->extract_fd, (off_t)p->extract_size);
            unsigned options = p->extract_destination->options;
            if ((options & 2u) && fchmod(p->extract_fd, p->api.archive_entry_perm(p->active_entry->native) & 0777u)) failed = 1;
            if (options & 4u) {
                struct timespec times[2];
                times[0].tv_sec = 0; times[0].tv_nsec = UTIME_OMIT;
                times[1].tv_sec = p->api.archive_entry_mtime(p->active_entry->native); times[1].tv_nsec = 0;
                if (futimens(p->extract_fd, times)) failed = 1;
            }
            if (close(p->extract_fd)) failed = 1;
            p->extract_fd = -1;
            return failed ? archive_error(o, errno, "Cannot finish confined extraction") : ARC_OK;
        }
        if (result != ARC_OK || offset < 0 || (uint64_t)offset > p->extract_size || size > p->extract_size - (uint64_t)offset ||
            lseek(p->extract_fd, (off_t)offset, SEEK_SET) < 0 || !write_all(p->extract_fd, buffer, size)) {
            close(p->extract_fd); p->extract_fd = -1;
            return result != ARC_OK ? result : archive_error(o, errno ? errno : EINVAL, "Invalid or unwritable archive data block");
        }
        if (o->progress) {
            queue_callback(p, 3, o, p->active_entry, o->progress, 1, o->progress_data, 0, 0);
            return ARC_OK;
        }
    }
}

int xxemul_darwin_archive_take_callback(xxemul_darwin_archive *p, uint64_t *target,
    uint64_t arguments[3], unsigned *count)
{
    if (!p || !target || !arguments || !count || !p->pending || p->inflight) return 0;
    *target = p->callback; memcpy(arguments, p->arguments, sizeof(p->arguments)); *count = p->argument_count;
    p->pending = 0; p->inflight = 1;
    return 1;
}

xxemul_status xxemul_darwin_archive_complete_callback(xxemul_darwin_archive *p, uint64_t result)
{
    int value;
    if (!p || !p->inflight) return XXEMUL_STATUS_INVALID_ARGUMENT;
    p->inflight = 0;
    if (p->operation == 1) value = (int32_t)result ? ARC_OK : ARC_EOF;
    else if (p->operation == 2) value = ARC_EOF;
    else if (p->operation == 3) value = extract_next(p);
    else return XXEMUL_STATUS_INVALID_ARGUMENT;
    p->emulator->arm.gpr[0] = (uint64_t)(int64_t)value;
    return XXEMUL_STATUS_OK;
}

int xxemul_darwin_archive_dispatch(xxemul_darwin_archive *p, const char *name, xxemul_status *status)
{
    uint64_t a, b, c, d, value = 0;
    struct archive_object *o, *entry;
    const char *text = NULL;
    int result = ARC_OK;
    if (!p || !status || !xxemul_darwin_archive_supports(name)) return 0;
    a = p->emulator->arm.gpr[0]; b = p->emulator->arm.gpr[1]; c = p->emulator->arm.gpr[2]; d = p->emulator->arm.gpr[3];
    o = object(p, a); entry = object(p, b); *status = XXEMUL_STATUS_OK;
#define IS(s) (!strcmp(name, "_" s))
#define RETURN(v) do { value = (uint64_t)(v); goto done; } while (0)
#define REQUIRE(k) do { if (!o || o->kind != (k)) goto bad_handle; } while (0)
    if (IS("archive_write_new") || IS("archive_read_new") || IS("archive_read_disk_new") ||
        IS("archive_write_disk_new") || IS("archive_entry_new") || IS("archive_match_new") || IS("archive_entry_linkresolver_new")) {
        enum object_kind kind = IS("archive_write_new") ? A_WRITER : IS("archive_read_new") ? A_READER :
            IS("archive_read_disk_new") ? A_DISK : IS("archive_write_disk_new") ? A_EXTRACT :
            IS("archive_entry_new") ? A_ENTRY : IS("archive_match_new") ? A_MATCH : A_LINK;
        void *native = kind == A_WRITER ? (void *)p->api.archive_write_new() : kind == A_READER ? (void *)p->api.archive_read_new() :
            kind == A_ENTRY ? (void *)p->api.archive_entry_new() : kind == A_MATCH ? (void *)p->api.archive_match_new() :
            kind == A_LINK ? (void *)p->api.archive_entry_linkresolver_new() : NULL;
        if (!native && kind != A_DISK && kind != A_EXTRACT) RETURN(0);
        o = new_object(p, kind, native);
        if (!o && native) { struct archive_object temporary = {0}; temporary.kind = kind; temporary.native = native; temporary.fd = -1; free_object(p, &temporary); }
        RETURN(o ? o->token : 0);
    }
    if (IS("archive_version_details")) RETURN(copy_string(p, "xxemul bounded libarchive memory service (regular files, tar/PAX, no compression)"));
    if (!a && (IS("archive_entry_free") || IS("archive_match_free") || IS("archive_entry_linkresolver_free") ||
        IS("archive_read_free") || IS("archive_write_free"))) RETURN(0);
    if (!o) goto bad_handle;
    /* Validate the API's object type before any generic cleanup. In
     * particular, a callback must not free its suspended reader by passing
     * that handle to a different object's free function. */
    if (IS("archive_entry_free") && o->kind != A_ENTRY) goto bad_handle;
    if (IS("archive_match_free") && o->kind != A_MATCH) goto bad_handle;
    if (IS("archive_entry_linkresolver_free") && o->kind != A_LINK) goto bad_handle;
    if ((IS("archive_read_free") || IS("archive_read_close")) && o->kind != A_READER && o->kind != A_DISK) goto bad_handle;
    if ((IS("archive_write_free") || IS("archive_write_close")) && o->kind != A_WRITER && o->kind != A_EXTRACT) goto bad_handle;
    if ((p->pending || p->inflight) && (o == p->active || o == p->active_entry || o == p->extract_destination ||
        (o->returned_entry && object(p, o->returned_entry) == p->active_entry)) &&
        (IS("archive_entry_free") || IS("archive_match_free") || IS("archive_entry_linkresolver_free") ||
         IS("archive_read_free") || IS("archive_write_free") || IS("archive_read_close") || IS("archive_write_close"))) goto unsupported;
    if (IS("archive_entry_free") || IS("archive_match_free") || IS("archive_entry_linkresolver_free") ||
        IS("archive_read_free") || IS("archive_write_free")) { free_object(p, o); RETURN(0); }
    if (IS("archive_read_close") || IS("archive_write_close")) RETURN((int64_t)close_object(p, o));
    if (IS("archive_errno")) RETURN(o->error_number ? o->error_number : o->native && o->kind != A_ENTRY && o->kind != A_LINK ? p->api.archive_errno(o->native) : 0);
    if (IS("archive_error_string")) RETURN(copy_string(p, o->error[0] ? o->error : o->native && o->kind != A_ENTRY && o->kind != A_LINK ? p->api.archive_error_string(o->native) : NULL));
    if (IS("archive_clear_error")) { o->error[0] = 0; o->error_number = 0; if (o->native && o->kind != A_ENTRY && o->kind != A_LINK) p->api.archive_clear_error(o->native); RETURN(0); }
    if (IS("archive_file_count")) RETURN(o->kind == A_DISK ? o->entries : o->native && o->kind != A_ENTRY && o->kind != A_LINK ? p->api.archive_file_count(o->native) : 0);
    if (IS("archive_format")) RETURN(o->kind == A_WRITER || o->kind == A_READER ? p->api.archive_format(o->native) : 0);
    if (IS("archive_format_name")) RETURN(copy_string(p, o->kind == A_WRITER || o->kind == A_READER ? p->api.archive_format_name(o->native) : "disk"));
    if (IS("archive_filter_bytes")) RETURN(o->kind == A_WRITER || o->kind == A_READER ? (uint64_t)p->api.archive_filter_bytes(o->native, (int)b) : o->position);
    if (IS("archive_filter_code")) RETURN(0);
    if (IS("archive_filter_name")) RETURN(copy_string(p, "none"));
    if (!strncmp(name, "_archive_entry_", 15u) && o->kind == A_ENTRY) {
        if (IS("archive_entry_pathname")) text = p->api.archive_entry_pathname(o->native);
        else if (IS("archive_entry_sourcepath")) text = p->api.archive_entry_sourcepath(o->native);
        else if (IS("archive_entry_hardlink")) text = p->api.archive_entry_hardlink(o->native);
        else if (IS("archive_entry_symlink")) text = p->api.archive_entry_symlink(o->native);
        else if (IS("archive_entry_uname")) text = p->api.archive_entry_uname(o->native);
        else if (IS("archive_entry_gname")) text = p->api.archive_entry_gname(o->native);
        else if (IS("archive_entry_strmode")) text = p->api.archive_entry_strmode(o->native);
        else if (IS("archive_entry_filetype")) RETURN(p->api.archive_entry_filetype(o->native));
        else if (IS("archive_entry_nlink")) RETURN(p->api.archive_entry_nlink(o->native));
        else if (IS("archive_entry_size")) RETURN((uint64_t)p->api.archive_entry_size(o->native));
        else if (IS("archive_entry_uid")) RETURN((uint64_t)p->api.archive_entry_uid(o->native));
        else if (IS("archive_entry_gid")) RETURN((uint64_t)p->api.archive_entry_gid(o->native));
        else if (IS("archive_entry_mtime")) RETURN((uint64_t)p->api.archive_entry_mtime(o->native));
        else if (IS("archive_entry_rdevmajor")) RETURN(p->api.archive_entry_rdevmajor(o->native));
        else if (IS("archive_entry_rdevminor")) RETURN(p->api.archive_entry_rdevminor(o->native));
        else if (IS("archive_entry_set_size")) { p->api.archive_entry_set_size(o->native, (int64_t)b); RETURN(0); }
        else if (IS("archive_entry_set_uid")) { p->api.archive_entry_set_uid(o->native, (int64_t)b); RETURN(0); }
        else if (IS("archive_entry_set_gid")) { p->api.archive_entry_set_gid(o->native, (int64_t)b); RETURN(0); }
        else {
            text = b ? guest_string(p, b) : NULL;
            if (b && !text) goto bad_pointer;
            if (IS("archive_entry_copy_pathname")) p->api.archive_entry_copy_pathname(o->native, text);
            else if (IS("archive_entry_copy_hardlink")) p->api.archive_entry_copy_hardlink(o->native, text);
            else if (IS("archive_entry_copy_symlink")) p->api.archive_entry_copy_symlink(o->native, text);
            else if (IS("archive_entry_set_uname")) p->api.archive_entry_set_uname(o->native, text);
            else if (IS("archive_entry_set_gname")) p->api.archive_entry_set_gname(o->native, text);
            else goto unsupported;
            RETURN(0);
        }
        RETURN(copy_string(p, text));
    }
    if (IS("archive_match_excluded")) { REQUIRE(A_MATCH); if (!entry || entry->kind != A_ENTRY) goto bad_handle; RETURN((int64_t)p->api.archive_match_excluded(o->native, entry->native)); }
    if (IS("archive_match_path_unmatched_inclusions")) { REQUIRE(A_MATCH); RETURN(p->api.archive_match_path_unmatched_inclusions(o->native)); }
    if (IS("archive_match_path_unmatched_inclusions_next")) {
        REQUIRE(A_MATCH); if (!memory_range(p, b, 8u)) goto bad_pointer;
        result = p->api.archive_match_path_unmatched_inclusions_next(o->native, &text);
        if (xxemul_store_integer(p->emulator, b, 8u, copy_string(p, text)) != XXEMUL_STATUS_OK) goto bad_pointer;
        RETURN((int64_t)result);
    }
    if (IS("archive_match_set_inclusion_recursion")) { REQUIRE(A_MATCH); RETURN((int64_t)p->api.archive_match_set_inclusion_recursion(o->native, (int)b)); }
    if (IS("archive_match_exclude_pattern") || IS("archive_match_include_pattern")) {
        REQUIRE(A_MATCH); text = guest_string(p, b); if (!text) goto bad_pointer;
        RETURN((int64_t)(IS("archive_match_exclude_pattern") ? p->api.archive_match_exclude_pattern(o->native, text) : p->api.archive_match_include_pattern(o->native, text)));
    }
    if (IS("archive_entry_linkresolver_set_strategy")) { REQUIRE(A_LINK); p->api.archive_entry_linkresolver_set_strategy(o->native, (int)b); RETURN(0); }
    if (IS("archive_entry_linkify")) {
        uint64_t token;
        REQUIRE(A_LINK);
        if (xxemul_load_integer(p->emulator, b, 8u, &token) != XXEMUL_STATUS_OK || !memory_range(p, c, 8u)) goto bad_pointer;
        if (!token) {
            if (xxemul_store_integer(p->emulator, c, 8u, 0) != XXEMUL_STATUS_OK) goto bad_pointer;
            RETURN(0);
        }
        entry = object(p, token);
        if (!entry || entry->kind != A_ENTRY) goto bad_handle;
        /* Regular files with one link need no deferred link resolution. */
        if (p->api.archive_entry_nlink(entry->native) > 1u) goto unsupported;
        if (xxemul_store_integer(p->emulator, c, 8u, 0) != XXEMUL_STATUS_OK) goto bad_pointer;
        RETURN(0);
    }
    if (IS("archive_write_open_filename") || IS("archive_write_open_fd") || IS("archive_read_open_filename") || IS("archive_read_open_fd"))
        RETURN((int64_t)open_archive(p, o, b, IS("archive_write_open_fd") || IS("archive_read_open_fd")));
    if (IS("archive_write_set_format_pax_restricted")) { REQUIRE(A_WRITER); RETURN((int64_t)p->api.archive_write_set_format_pax_restricted(o->native)); }
    if (IS("archive_write_set_format")) { REQUIRE(A_WRITER); if ((b & 0xff0000u) != 0x30000u) goto unsupported; RETURN((int64_t)p->api.archive_write_set_format(o->native, (int)b)); }
    if (IS("archive_write_set_format_by_name")) {
        REQUIRE(A_WRITER); text = guest_string(p, b); if (!text) goto bad_pointer;
        if (strcmp(text, "ustar") && strcmp(text, "pax") && strcmp(text, "paxr") && strcmp(text, "gnutar")) goto unsupported;
        RETURN((int64_t)p->api.archive_write_set_format_by_name(o->native, text));
    }
    if (IS("archive_write_set_bytes_per_block")) { REQUIRE(A_WRITER); RETURN((int64_t)p->api.archive_write_set_bytes_per_block(o->native, (int)b)); }
    if (IS("archive_write_set_bytes_in_last_block")) { REQUIRE(A_WRITER); RETURN((int64_t)p->api.archive_write_set_bytes_in_last_block(o->native, (int)b)); }
    if (IS("archive_write_set_options") || IS("archive_read_set_options")) {
        text = b ? guest_string(p, b) : NULL; if (b && !text) goto bad_pointer;
        if (o->kind == A_WRITER) result = p->api.archive_write_set_options(o->native, text);
        else if (o->kind == A_READER) result = p->api.archive_read_set_options(o->native, text);
        else goto bad_handle;
        RETURN((int64_t)result);
    }
    if (IS("archive_write_add_filter_by_name")) { REQUIRE(A_WRITER); text = guest_string(p, b); if (!text) goto bad_pointer; if (strcmp(text, "none")) goto unsupported; RETURN(0); }
    if (IS("archive_read_support_filter_all")) { REQUIRE(A_READER); RETURN((int64_t)p->api.archive_read_support_filter_none(o->native)); }
    if (IS("archive_read_support_format_all") || IS("archive_read_support_format_tar") || IS("archive_read_support_format_gnutar")) {
        REQUIRE(A_READER); RETURN((int64_t)p->api.archive_read_support_format_tar(o->native));
    }
    if (IS("archive_read_support_format_empty")) { REQUIRE(A_READER); RETURN((int64_t)p->api.archive_read_support_format_empty(o->native)); }
    if (IS("archive_write_set_passphrase_callback") || IS("archive_read_set_passphrase_callback")) { o->passphrase_data = b; o->passphrase = c; RETURN(0); }
    if (IS("archive_read_add_passphrase") || IS("archive_write_set_passphrase")) { text = guest_string(p, b); if (!text) goto bad_pointer; RETURN(0); }
    if (IS("archive_write_header")) { REQUIRE(A_WRITER); if (!entry || entry->kind != A_ENTRY) goto bad_handle; RETURN((int64_t)p->api.archive_write_header(o->native, entry->native)); }
    if (IS("archive_write_data")) {
        REQUIRE(A_WRITER); if (c > ARC_LIMIT || !memory_range(p, b, c)) goto bad_pointer;
        RETURN((int64_t)p->api.archive_write_data(o->native, p->emulator->region_data + (size_t)(b - p->emulator->region_address), (size_t)c));
    }
    if (IS("archive_read_disk_open")) {
        REQUIRE(A_DISK); text = guest_string(p, b); if (!text) goto bad_pointer;
        if (o->fd >= 0) close(o->fd);
        o->fd = xxemul_darwin_posix_open_host(p->posix, text, O_RDONLY, 0);
        if (o->fd < 0) RETURN((int64_t)archive_error(o, errno, "Cannot open confined archive source"));
        snprintf(o->path, sizeof(o->path), "%s", text); o->opened = 1; o->closed = 0; o->delivered = 0; RETURN(0);
    }
    if (IS("archive_read_disk_set_matching")) { REQUIRE(A_DISK); if (b && (!entry || entry->kind != A_MATCH)) goto bad_handle; o->matching = b; o->excluded = c; o->excluded_data = d; RETURN(0); }
    if (IS("archive_read_disk_set_metadata_filter_callback")) { REQUIRE(A_DISK); o->metadata = b; o->metadata_data = c; RETURN(0); }
    if (IS("archive_read_disk_can_descend")) { REQUIRE(A_DISK); RETURN(0); }
    if (IS("archive_read_disk_descend")) { REQUIRE(A_DISK); RETURN((int64_t)archive_error(o, ENOTSUP, "Directory traversal is not available")); }
    if (IS("archive_read_disk_set_symlink_physical") || IS("archive_read_disk_set_standard_lookup") || IS("archive_read_disk_set_behavior")) { REQUIRE(A_DISK); RETURN(0); }
    if (IS("archive_read_disk_uname") || IS("archive_read_disk_gname")) { REQUIRE(A_DISK); RETURN(0); }
    if (IS("archive_read_next_header2") || IS("archive_read_next_header")) {
        if (p->pending || p->inflight) goto unsupported;
        if (IS("archive_read_next_header")) {
            if (!memory_range(p, b, 8u)) goto bad_pointer;
            entry = object(p, o->returned_entry);
            if (!entry) {
                struct archive_entry *native = p->api.archive_entry_new();
                if (!native) RETURN((int64_t)ARC_FATAL);
                entry = new_object(p, A_ENTRY, native);
                if (!entry) { p->api.archive_entry_free(native); RETURN((int64_t)ARC_FATAL); }
                o->returned_entry = entry->token;
            }
        } else if (!entry || entry->kind != A_ENTRY) goto bad_handle;
        if (o->kind == A_DISK) result = next_disk_header(p, o, entry);
        else if (o->kind == A_READER) {
            struct archive_entry *borrowed = NULL;
            result = o->eof ? ARC_EOF : p->api.archive_read_next_header(o->native, &borrowed);
            if (result == ARC_EOF) o->eof = 1;
            if (result == ARC_OK) {
                struct archive_entry *copy = p->api.archive_entry_clone(borrowed);
                if (!copy) result = ARC_FATAL;
                else { p->api.archive_entry_free(entry->native); entry->native = copy; }
            }
        } else goto bad_handle;
        if (IS("archive_read_next_header") && xxemul_store_integer(p->emulator, b, 8u, result == ARC_OK ? entry->token : 0) != XXEMUL_STATUS_OK) goto bad_pointer;
        RETURN((int64_t)result);
    }
    if (IS("archive_read_data_block")) { if (o->kind != A_DISK && o->kind != A_READER) goto bad_handle; RETURN((int64_t)data_block(p, o, b, c, d)); }
    if (IS("archive_read_data_skip")) { if (o->kind == A_DISK) { o->position = o->size; RETURN(0); } REQUIRE(A_READER); RETURN((int64_t)p->api.archive_read_data_skip(o->native)); }
    if (IS("archive_read_header_position")) { REQUIRE(A_READER); RETURN((uint64_t)p->api.archive_read_header_position(o->native)); }
    if (IS("archive_read_extract_set_progress_callback")) { REQUIRE(A_READER); o->progress = b; o->progress_data = c; RETURN(0); }
    if (IS("archive_write_disk_set_options")) { REQUIRE(A_EXTRACT); o->options = (unsigned)b; RETURN(0); }
    if (IS("archive_write_disk_set_standard_lookup")) { REQUIRE(A_EXTRACT); RETURN(0); }
    if (IS("archive_write_disk_set_quarantine")) { REQUIRE(A_EXTRACT); if (b) goto unsupported; RETURN(0); }
    if (IS("archive_read_extract2")) {
        struct archive_object *destination = object(p, c);
        int64_t size;
        REQUIRE(A_READER);
        if (!entry || entry->kind != A_ENTRY || !destination || destination->kind != A_EXTRACT) goto bad_handle;
        if (p->pending || p->inflight || p->extract_fd >= 0) goto unsupported;
        text = p->api.archive_entry_pathname(entry->native); size = p->api.archive_entry_size(entry->native);
        if (!relative_path(text) || p->api.archive_entry_filetype(entry->native) != 0100000u ||
            p->api.archive_entry_hardlink(entry->native) || p->api.archive_entry_symlink(entry->native) || size < 0 || (uint64_t)size > ARC_LIMIT)
            RETURN((int64_t)archive_error(o, ENOTSUP, "Extraction requires a bounded regular file with a confined relative path"));
        p->extract_fd = xxemul_darwin_posix_open_host(p->posix, text,
            O_WRONLY | O_CREAT | (destination->options & 8u ? O_EXCL : O_TRUNC),
            p->api.archive_entry_perm(entry->native) & 0777u);
        if (p->extract_fd < 0) RETURN((int64_t)archive_error(o, errno, "Cannot open confined extraction file"));
        p->active = o; p->active_entry = entry; p->extract_destination = destination; p->extract_size = (uint64_t)size;
        RETURN((int64_t)extract_next(p));
    }
unsupported:
    RETURN((int64_t)archive_error(o, ENOTSUP, "Operation is outside the bounded archive service model"));
bad_pointer:
    *status = XXEMUL_STATUS_ADDRESS_FAULT;
    RETURN((int64_t)ARC_FATAL);
bad_handle:
    *status = XXEMUL_STATUS_INVALID_ARGUMENT;
    value = (uint64_t)(int64_t)ARC_FATAL;
done:
    p->emulator->arm.gpr[0] = value;
    return 1;
#undef REQUIRE
#undef RETURN
#undef IS
}

#else

#include <string.h>
xxemul_darwin_archive *xxemul_darwin_archive_create(xxemul *e,
    xxemul_darwin_posix_allocate a, void *c, xxemul_darwin_posix *p)
{ (void)e; (void)a; (void)c; (void)p; return NULL; }
void xxemul_darwin_archive_destroy(xxemul_darwin_archive *p) { (void)p; }
int xxemul_darwin_archive_supports(const char *n) { return n && !strncmp(n, "_archive_", 9u); }
int xxemul_darwin_archive_dispatch(xxemul_darwin_archive *p, const char *n, xxemul_status *s)
{ (void)p; (void)n; if (s) *s = XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION; return 0; }
int xxemul_darwin_archive_take_callback(xxemul_darwin_archive *p, uint64_t *t, uint64_t a[3], unsigned *c)
{ (void)p; (void)t; (void)a; (void)c; return 0; }
xxemul_status xxemul_darwin_archive_complete_callback(xxemul_darwin_archive *p, uint64_t r)
{ (void)p; (void)r; return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION; }

#endif
