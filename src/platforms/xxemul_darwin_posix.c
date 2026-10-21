/* Darwin ARM64 file/stdio/time services. Guest code is never executed by the host. */
#ifndef _DARWIN_C_SOURCE
#define _DARWIN_C_SOURCE 1
#endif
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE 1
#endif
#include "xxemul_darwin_posix.h"
#include "xxemul_darwin.h"
#include "../xxemul_internal.h"
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifndef _WIN32
#include <dirent.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <utime.h>
#if defined(__APPLE__)
#include <copyfile.h>
#include <sys/attr.h>
#include <sys/xattr.h>
#endif

#define POSIX_FILES 128
#define POSIX_DIRS 32
#define GUEST_PATH_MAX 4096
#define GUEST_STRING_MAX (1024u * 1024u)
#define GUEST_AT_FDCWD (-2)
#define POSIX_VIRTUAL_FILES 4
#define POSIX_VIRTUAL_HANDLES 16
#define POSIX_VIRTUAL_FD_BASE 0x40000000u
#define GUEST_VM_PAGE 4096u
#define GUEST_VM_MAX (64u * 1024u * 1024u)

struct guest_file {
    int fd;
    FILE *file;
    uint64_t guest;
    unsigned flags;
    unsigned logical_flags, descriptor_flags;
    int owned;
};
struct guest_directory { DIR *directory; uint64_t guest, entry; };
struct guest_quarantine { uint64_t guest; size_t size; unsigned char data[4096]; };
struct guest_virtual_file { char path[GUEST_PATH_MAX]; unsigned char *data; size_t size; };
struct guest_virtual_handle { int file; uint64_t offset; int active; };
struct xxemul_darwin_posix {
    xxemul *emulator;
    uint64_t base, errno_address, tm_address, zone_address, text_address;
    xxemul_darwin_posix_allocate allocate;
    void *allocate_context;
    int root;
    char root_path[GUEST_PATH_MAX];
    struct guest_file files[POSIX_FILES];
    struct guest_directory directories[POSIX_DIRS];
    struct guest_quarantine quarantine[POSIX_DIRS];
    unsigned temp_counter;
    unsigned creation_mask;
    uint32_t signal_mask;
    unsigned char signal_actions[32][16];
    struct guest_virtual_file virtual_files[POSIX_VIRTUAL_FILES];
    struct guest_virtual_handle virtual_handles[POSIX_VIRTUAL_HANDLES];
    uint64_t image_base, image_limit, map_base, map_size, map_next, sparse_limit, dyld_entry;
    unsigned char *image_pages, *map_pages;
};

static int guest_range(xxemul_darwin_posix *p, uint64_t address, uint64_t size)
{
    uint64_t relative;
    if (address < p->emulator->region_address) return 0;
    relative = address - p->emulator->region_address;
    return relative <= p->emulator->region_size && size <= p->emulator->region_size - relative;
}
static int put(xxemul_darwin_posix *p, uint64_t a, unsigned n, uint64_t value)
{ return xxemul_store_integer(p->emulator, a, (uint8_t)n, value) == XXEMUL_STATUS_OK; }
static int get(xxemul_darwin_posix *p, uint64_t a, unsigned n, uint64_t *value)
{ return xxemul_load_integer(p->emulator, a, (uint8_t)n, value) == XXEMUL_STATUS_OK; }

static int guest_errno_value(int value)
{
    switch (value) {
        case EAGAIN: return 35;
        case ENAMETOOLONG: return 63;
        case ENOTEMPTY: return 66;
        case ELOOP: return 62;
        case ENOSYS: return 78;
        case EOVERFLOW: return 84;
        case ENOTSUP: return 45;
        default: return value;
    }
}
static void set_error(xxemul_darwin_posix *p, int error)
{ (void)put(p, p->errno_address, 4, (unsigned)guest_errno_value(error)); }
static uint64_t failure(xxemul_darwin_posix *p, int error, uint64_t result)
{ set_error(p, error); return result; }

static int guest_string(xxemul_darwin_posix *p, uint64_t address, char *out, size_t capacity)
{
    size_t i;
    if (!address || !capacity) { errno = EFAULT; return 0; }
    for (i = 0; i < capacity; ++i) {
        uint64_t ch;
        if (address > UINT64_MAX - i || !get(p, address + i, 1, &ch)) { errno = EFAULT; return 0; }
        out[i] = (char)ch;
        if (!ch) return 1;
    }
    errno = ENAMETOOLONG;
    return 0;
}

/* Return an opened parent directory and one basename. No component follows
 * a symlink; absolute paths must name this same confined root. */
static int parent_directory_at(xxemul_darwin_posix *p, int guest_directory, const char *path, char leaf[GUEST_PATH_MAX])
{
    char copy[GUEST_PATH_MAX], *cursor, *part, *next;
    int directory;
    size_t root_length = strlen(p->root_path);
    if (!path || !*path) { errno = ENOENT; return -1; }
    if (path[0] == '/') {
        if (strncmp(path, p->root_path, root_length) ||
            (path[root_length] != '/' && path[root_length] != '\0')) { errno = EACCES; return -1; }
        path += root_length;
        while (*path == '/') ++path;
        guest_directory = GUEST_AT_FDCWD;
    }
    if (strlen(path) >= sizeof(copy)) { errno = ENAMETOOLONG; return -1; }
    strcpy(copy, *path ? path : ".");
    if (guest_directory == GUEST_AT_FDCWD) directory = dup(p->root);
    else {
        struct stat st;
        if (guest_directory < 3 || guest_directory >= POSIX_FILES || p->files[guest_directory].fd < 0) { errno = EBADF; return -1; }
        if (fstat(p->files[guest_directory].fd, &st) < 0) return -1;
        if (!S_ISDIR(st.st_mode)) { errno = ENOTDIR; return -1; }
        directory = dup(p->files[guest_directory].fd);
    }
    if (directory < 0) return -1;
    cursor = copy;
    for (;;) {
        while (*cursor == '/') ++cursor;
        part = cursor;
        next = strchr(part, '/');
        if (next) *next++ = '\0';
        if (!strcmp(part, "..")) { close(directory); errno = EACCES; return -1; }
        if (!next || !*next) { strcpy(leaf, *part ? part : "."); return directory; }
        if (*part && strcmp(part, ".")) {
            int opened = openat(directory, part, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
            int error = errno;
            close(directory);
            if (opened < 0) { errno = error; return -1; }
            directory = opened;
        }
        cursor = next;
    }
}

static int parent_directory(xxemul_darwin_posix *p, const char *path, char leaf[GUEST_PATH_MAX])
{ return parent_directory_at(p, GUEST_AT_FDCWD, path, leaf); }

static int open_guest_path_at(xxemul_darwin_posix *p, int guest_directory, const char *path, int flags, mode_t mode)
{
    char leaf[GUEST_PATH_MAX];
    int parent = parent_directory_at(p, guest_directory, path, leaf), fd, error;
    if (parent < 0) return -1;
    fd = openat(parent, leaf, flags | O_NOFOLLOW | O_CLOEXEC, mode & (mode_t)~p->creation_mask);
    error = errno;
    close(parent);
    errno = error;
    return fd;
}

static int open_guest_path(xxemul_darwin_posix *p, const char *path, int flags, mode_t mode)
{
    return open_guest_path_at(p, GUEST_AT_FDCWD, path, flags, mode);
}

int xxemul_darwin_posix_open_host(xxemul_darwin_posix *p, const char *path, int flags, unsigned mode)
{
    if (!p) { errno = EINVAL; return -1; }
    return open_guest_path(p, path, flags, (mode_t)mode);
}

int xxemul_darwin_posix_dup_host(xxemul_darwin_posix *p, uint64_t guest_fd)
{
    if (!p || guest_fd < 3u || guest_fd >= POSIX_FILES || p->files[guest_fd].fd < 0) {
        errno = EBADF;
        return -1;
    }
    return dup(p->files[guest_fd].fd);
}

static int file_index(xxemul_darwin_posix *p, uint64_t guest)
{
    int i;
    for (i = 0; i < POSIX_FILES; ++i)
        if (p->files[i].fd >= 0 && p->files[i].guest == guest && guest) return i;
    return -1;
}
static int descriptor_valid(xxemul_darwin_posix *p, uint64_t descriptor)
{ return descriptor < POSIX_FILES && p->files[descriptor].fd >= 0; }

static unsigned darwin_open_flags(int flags)
{
    unsigned result=(unsigned)(flags&O_ACCMODE);
    if(flags&O_NONBLOCK) result|=4u;
    if(flags&O_APPEND) result|=8u;
    return result;
}
static uint64_t pread_guest(xxemul_darwin_posix *p, uint64_t fd, uint64_t address, uint64_t count, uint64_t offset);
static int adopt_descriptor(xxemul_darwin_posix *p, int fd)
{
    int i;
    for (i = 3; i < POSIX_FILES; ++i) {
        if (p->files[i].fd < 0) {
            memset(&p->files[i], 0, sizeof(p->files[i]));
            p->files[i].fd = fd;
            p->files[i].owned = 1;
            { int flags=fcntl(fd,F_GETFL); p->files[i].logical_flags=flags<0?0:darwin_open_flags(flags); }
            return i;
        }
    }
    close(fd);
    errno = EMFILE;
    return -1;
}
static void sync_file(xxemul_darwin_posix *p, int index)
{
    struct guest_file *f = &p->files[index];
    unsigned flags = f->flags;
    if (!f->guest) return;
    if (f->file && feof(f->file)) flags |= 0x20u;
    if (f->file && ferror(f->file)) flags |= 0x40u;
    (void)put(p, f->guest, 8, 0); /* _p: buffering remains in the host stdio object. */
    (void)put(p, f->guest + 8, 4, 0);
    (void)put(p, f->guest + 12, 4, 0);
    (void)put(p, f->guest + 16, 2, flags);
    (void)put(p, f->guest + 18, 2, (unsigned)index);
}
static int close_descriptor(xxemul_darwin_posix *p, int index)
{
    struct guest_file *f = &p->files[index];
    int result = 0;
    if (f->owned) result = f->file ? fclose(f->file) : close(f->fd);
    else if (f->file && index != 0) result = fflush(f->file);
    f->file = NULL; f->fd = -1; f->guest = 0;
    return result;
}

static int mode_flags(const char *mode, int *flags, unsigned *file_flags)
{
    int update;
    if (!mode || !*mode) { errno = EINVAL; return 0; }
    update = strchr(mode, '+') != NULL;
    if (*mode == 'r') *flags = update ? O_RDWR : O_RDONLY;
    else if (*mode == 'w') *flags = (update ? O_RDWR : O_WRONLY) | O_CREAT | O_TRUNC;
    else if (*mode == 'a') *flags = (update ? O_RDWR : O_WRONLY) | O_CREAT | O_APPEND;
    else { errno = EINVAL; return 0; }
    *file_flags = update ? 0x10u : *mode == 'r' ? 4u : 8u;
    return 1;
}

static uint64_t attach_stream(xxemul_darwin_posix *p, int index, const char *mode, unsigned flags)
{
    struct guest_file *f = &p->files[index];
    unsigned char object[160] = {0};
    uint64_t guest;
    FILE *stream;
    if (f->file) { errno = EINVAL; return 0; }
    guest = p->allocate(p->allocate_context, 160);
    if (!guest) { errno = ENOMEM; return 0; }
    if (xxemul_write_memory(p->emulator, guest, object, sizeof(object)) != XXEMUL_STATUS_OK) { errno = EFAULT; return 0; }
    stream = fdopen(f->fd, mode);
    if (!stream) return 0;
    f->file = stream; f->guest = guest; f->flags = flags;
    sync_file(p, index);
    return guest;
}

xxemul_darwin_posix *xxemul_darwin_posix_create(xxemul *emulator, uint64_t runtime_base,
    const char *workdir, uint64_t errno_address, xxemul_darwin_posix_allocate allocate, void *allocate_context)
{
    xxemul_darwin_posix *p;
    int i;
    if (!emulator || !workdir || !allocate) return NULL;
    p = calloc(1, sizeof(*p));
    if (!p) return NULL;
    p->root = -1;
    for (i = 0; i < POSIX_FILES; ++i) p->files[i].fd = -1;
    p->emulator = emulator; p->base = runtime_base; p->errno_address = errno_address;
    p->creation_mask = 022u;
    p->allocate = allocate; p->allocate_context = allocate_context;
    if (!realpath(workdir, p->root_path)) { free(p); return NULL; }
    p->root = open(p->root_path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (p->root < 0) { free(p); return NULL; }
    for (i = 0; i < 3; ++i) {
        p->files[i].fd = i;
        { int flags=fcntl(i,F_GETFL); p->files[i].logical_flags=flags<0?(i==0?0u:1u):darwin_open_flags(flags); }
        p->files[i].file = i == 0 ? stdin : i == 1 ? stdout : stderr;
        p->files[i].guest = runtime_base + UINT64_C(0x1100) + (unsigned)i * 0x100u;
        p->files[i].flags = i == 0 ? 4u : 8u;
        sync_file(p, i);
    }
    /* Shared imported globals: stdinp, stdoutp, stderrp. */
    (void)put(p, runtime_base + 0x1000, 8, p->files[0].guest);
    (void)put(p, runtime_base + 0x1008, 8, p->files[1].guest);
    (void)put(p, runtime_base + 0x1010, 8, p->files[2].guest);
    p->tm_address = allocate(allocate_context, 56);
    p->zone_address = allocate(allocate_context, 64);
    p->text_address = allocate(allocate_context, 1024);
    if (!p->tm_address || !p->zone_address || !p->text_address) { xxemul_darwin_posix_destroy(p); return NULL; }
    return p;
}

void xxemul_darwin_posix_destroy(xxemul_darwin_posix *p)
{
    int i;
    if (!p) return;
    for (i = 0; i < POSIX_FILES; ++i) if (p->files[i].fd >= 0 && p->files[i].owned) (void)close_descriptor(p, i);
    for (i = 0; i < POSIX_DIRS; ++i) if (p->directories[i].directory) closedir(p->directories[i].directory);
    for (i = 0; i < POSIX_VIRTUAL_FILES; ++i) free(p->virtual_files[i].data);
    free(p->image_pages);
    free(p->map_pages);
    if (p->root >= 0) close(p->root);
    free(p);
}

int xxemul_darwin_posix_configure_vm(xxemul_darwin_posix *p, uint64_t image_base, uint64_t image_limit,
                                       uint64_t map_base, uint64_t map_size)
{
    size_t image_count, map_count;
    unsigned char *image_pages, *map_pages;
    if (!p || p->image_pages || image_limit <= image_base || image_limit - image_base > GUEST_VM_MAX ||
        map_size == 0u || map_size > GUEST_VM_MAX || ((image_base | image_limit | map_base | map_size) & (GUEST_VM_PAGE - 1u)) ||
        map_base < image_limit || !guest_range(p, image_base, image_limit - image_base) || !guest_range(p, map_base, map_size)) return 0;
    image_count = (size_t)((image_limit - image_base) / GUEST_VM_PAGE);
    map_count = (size_t)(map_size / GUEST_VM_PAGE);
    image_pages = malloc(image_count);
    map_pages = calloc(map_count, 1);
    if (!image_pages || !map_pages) { free(image_pages); free(map_pages); return 0; }
    memset(image_pages, 0x87, image_count);
    p->image_base=image_base; p->image_limit=image_limit; p->map_base=map_base; p->map_size=map_size; p->map_next=map_base;
    p->image_pages=image_pages; p->map_pages=map_pages;
    return 1;
}

int xxemul_darwin_posix_set_virtual_file(xxemul_darwin_posix *p, const char *path, const void *bytes, size_t length)
{
    unsigned index;
    unsigned char *copy;
    if (!p || !path || !*path || strlen(path) >= GUEST_PATH_MAX || !bytes || !length || length > GUEST_VM_MAX) return 0;
    for (index=0; index<POSIX_VIRTUAL_FILES && p->virtual_files[index].data; ++index)
        if (!strcmp(p->virtual_files[index].path,path)) return 0;
    if (index==POSIX_VIRTUAL_FILES || !(copy=malloc(length))) return 0;
    memcpy(copy,bytes,length);
    strcpy(p->virtual_files[index].path,path);
    p->virtual_files[index].data=copy; p->virtual_files[index].size=length;
    return 1;
}

uint64_t xxemul_darwin_posix_dyld_entry(const xxemul_darwin_posix *p)
{ return p ? p->dyld_entry : 0; }

int xxemul_darwin_posix_validate_stream(xxemul_darwin_posix *p, uint64_t stream, int writing)
{
    int index = p ? file_index(p, stream) : -1;
    if (index < 0 || !p->files[index].file || !(p->files[index].flags & (0x10u | (writing ? 8u : 4u)))) {
        errno = EBADF;
        if (p) set_error(p, EBADF);
        return 0;
    }
    return 1;
}

int64_t xxemul_darwin_posix_read_stream(xxemul_darwin_posix *p, uint64_t stream, void *bytes, size_t size)
{
    int index;
    size_t result;
    if (!xxemul_darwin_posix_validate_stream(p, stream, 0)) return -1;
    if ((!bytes && size) || size > INT64_MAX) { set_error(p, size > INT64_MAX ? EOVERFLOW : EFAULT); return -1; }
    if (!size) return 0;
    index = file_index(p, stream);
    errno = 0;
    result = fread(bytes, 1, size, p->files[index].file);
    if (ferror(p->files[index].file)) {
        set_error(p, errno ? errno : EIO);
        sync_file(p, index);
        return result ? (int64_t)result : -1;
    }
    sync_file(p, index);
    return (int64_t)result;
}

int xxemul_darwin_posix_flush_stream(xxemul_darwin_posix *p, uint64_t stream)
{
    int index, result;
    if (!xxemul_darwin_posix_validate_stream(p, stream, 1)) return -1;
    index = file_index(p, stream);
    errno = 0;
    result = fflush(p->files[index].file);
    if (result) set_error(p, errno ? errno : EIO);
    sync_file(p, index);
    return result ? -1 : 0;
}

int64_t xxemul_darwin_posix_write_stream(xxemul_darwin_posix *p, uint64_t stream, const void *bytes, size_t size)
{
    int index;
    size_t result;
    if (!xxemul_darwin_posix_validate_stream(p, stream, 1)) return -1;
    if ((!bytes && size) || size > INT64_MAX) { set_error(p, size > INT64_MAX ? EOVERFLOW : EFAULT); return -1; }
    if (!size) return 0;
    index = file_index(p, stream);
    if ((index == 1 || index == 2) && xxemul_emit_output(p->emulator, index, bytes, size)) return (int64_t)size;
    errno = 0;
    result = fwrite(bytes, 1, size, p->files[index].file);
    if (result != size) set_error(p, errno ? errno : EIO);
    sync_file(p, index);
    return (int64_t)result;
}

static uint64_t transfer(xxemul_darwin_posix *p, int index, uint64_t address, uint64_t size, int writing, int buffered)
{
    unsigned char block[16384];
    uint64_t done = 0;
    if (!guest_range(p, address, size)) return failure(p, EFAULT, UINT64_MAX);
    while (done < size) {
        size_t amount = size - done > sizeof(block) ? sizeof(block) : (size_t)(size - done);
        ssize_t transferred;
        if (writing) {
            if (xxemul_read_memory(p->emulator, address + done, block, amount) != XXEMUL_STATUS_OK) return failure(p, EFAULT, UINT64_MAX);
            if (buffered) transferred = (ssize_t)xxemul_darwin_posix_write_stream(p, p->files[index].guest, block, amount);
            else if ((index == 1 || index == 2) && xxemul_emit_output(p->emulator, index, block, amount)) transferred = (ssize_t)amount;
            else transferred = write(p->files[index].fd, block, amount);
        } else {
            if (buffered) {
                transferred = (ssize_t)fread(block, 1, amount, p->files[index].file);
                if (!transferred && ferror(p->files[index].file)) transferred = -1;
            } else transferred = read(p->files[index].fd, block, amount);
            if (transferred > 0 && xxemul_write_memory(p->emulator, address + done, block, (size_t)transferred) != XXEMUL_STATUS_OK) return failure(p, EFAULT, UINT64_MAX);
        }
        if (transferred < 0) { set_error(p, errno ? errno : EIO); return done ? done : UINT64_MAX; }
        done += (uint64_t)transferred;
        if ((size_t)transferred < amount || !buffered) break;
    }
    if (buffered) sync_file(p, index);
    return done;
}

static int write_stat(xxemul_darwin_posix *p, uint64_t address, const struct stat *s)
{
    unsigned char zero[144] = {0};
    if (xxemul_write_memory(p->emulator, address, zero, sizeof(zero)) != XXEMUL_STATUS_OK) return 0;
    if (!put(p,address,4,(uint32_t)s->st_dev) || !put(p,address+4,2,s->st_mode) ||
        !put(p,address+6,2,s->st_nlink) || !put(p,address+8,8,s->st_ino) ||
        !put(p,address+16,4,s->st_uid) || !put(p,address+20,4,s->st_gid) || !put(p,address+24,4,s->st_rdev)) return 0;
#ifdef __APPLE__
    if (!put(p,address+32,8,(uint64_t)s->st_atimespec.tv_sec) || !put(p,address+40,8,(uint64_t)s->st_atimespec.tv_nsec) ||
        !put(p,address+48,8,(uint64_t)s->st_mtimespec.tv_sec) || !put(p,address+56,8,(uint64_t)s->st_mtimespec.tv_nsec) ||
        !put(p,address+64,8,(uint64_t)s->st_ctimespec.tv_sec) || !put(p,address+72,8,(uint64_t)s->st_ctimespec.tv_nsec) ||
        !put(p,address+80,8,(uint64_t)s->st_birthtimespec.tv_sec) || !put(p,address+88,8,(uint64_t)s->st_birthtimespec.tv_nsec) ||
        !put(p,address+116,4,s->st_flags) || !put(p,address+120,4,s->st_gen)) return 0;
#else
    if (!put(p,address+32,8,(uint64_t)s->st_atim.tv_sec) || !put(p,address+40,8,(uint64_t)s->st_atim.tv_nsec) ||
        !put(p,address+48,8,(uint64_t)s->st_mtim.tv_sec) || !put(p,address+56,8,(uint64_t)s->st_mtim.tv_nsec) ||
        !put(p,address+64,8,(uint64_t)s->st_ctim.tv_sec) || !put(p,address+72,8,(uint64_t)s->st_ctim.tv_nsec)) return 0;
#endif
    return put(p,address+96,8,(uint64_t)s->st_size) && put(p,address+104,8,(uint64_t)s->st_blocks) && put(p,address+112,4,(uint32_t)s->st_blksize);
}

static int write_tm(xxemul_darwin_posix *p, uint64_t address, const struct tm *value)
{
    int values[9] = {value->tm_sec,value->tm_min,value->tm_hour,value->tm_mday,value->tm_mon,value->tm_year,value->tm_wday,value->tm_yday,value->tm_isdst};
    unsigned i;
    if (!guest_range(p,address,56)) return 0;
    for (i=0;i<9;++i) if (!put(p,address+i*4u,4,(uint32_t)values[i])) return 0;
#if defined(__APPLE__) || defined(__linux__)
    {
        char zone[64];
        snprintf(zone,sizeof(zone),"%s",value->tm_zone ? value->tm_zone : "");
        if (xxemul_write_memory(p->emulator,p->zone_address,zone,strlen(zone)+1) != XXEMUL_STATUS_OK) return 0;
        return put(p,address+40,8,(uint64_t)value->tm_gmtoff) && put(p,address+48,8,p->zone_address);
    }
#else
    return put(p,address+40,8,0) && put(p,address+48,8,0);
#endif
}
static int read_tm(xxemul_darwin_posix *p, uint64_t address, struct tm *value)
{
    uint64_t v[9]; unsigned i;
    memset(value,0,sizeof(*value));
    if (!guest_range(p,address,56)) return 0;
    for (i=0;i<9;++i) if (!get(p,address+i*4u,4,&v[i])) return 0;
    value->tm_sec=(int32_t)v[0]; value->tm_min=(int32_t)v[1]; value->tm_hour=(int32_t)v[2];
    value->tm_mday=(int32_t)v[3]; value->tm_mon=(int32_t)v[4]; value->tm_year=(int32_t)v[5];
    value->tm_wday=(int32_t)v[6]; value->tm_yday=(int32_t)v[7]; value->tm_isdst=(int32_t)v[8];
    return 1;
}

int xxemul_darwin_posix_supports(const char *name)
{
    static const char *const names[] = {
        "_fopen","_fdopen","_fclose","_fread","_fwrite","_fseeko","_fseek","_ftello","_ftell",
        "_rewind","_fflush","_clearerr","_feof","_ferror","_fileno","_setvbuf","_fgets",
        "_getc","_fgetc","_putc","_fputc","_ungetc","_fputs","_puts","_putchar",
        "_open","_openat","_close","_read","_write","_lseek","_stat","_lstat","_fstat","_fstatat",
        "_chmod","_fchmod","_lchmod","_chown","_fchown","_lchown","_mkdir","_mkdirat","_umask",
        "_rename","_renameat","_unlink","_unlinkat","_symlinkat","_rmdir","_realpath$DARWIN_EXTSN","_ioctl",
        "_mkstemp","_utime","_readlink","_opendir","_readdir","_closedir","_time","_localtime","_gmtime",
        "_mktime","_asctime","_tzset","_getpid","_isatty","_signal","_tcgetattr","_tcsetattr","_strerror","_perror",
        "_popen","_pclose","_posix_spawnp","_waitpid",
        "_access","_geteuid","_getuid","_getgid","_getegid","_sigaction","_localtime_r","_strftime",
        "_isprint","_isspace","_iswprint","_mbtowc","_nl_langinfo","_strdup","_strcspn","_strtol",
        "_dup","_pread","_gettimeofday","_futimes","_ctime","_fchflags","_fcopyfile","_fgetattrlist","_fsetattrlist",
        "_pipe","_fcntl","_poll","_sigprocmask","_clock_gettime","_futimens","_fsync","_sysconf","_getrlimit",
        "_fopen$DARWIN_EXTSN","_mbrtowc","_mbsinit","_wcwidth","_alarm",
        "__qtn_file_alloc","__qtn_file_free","__qtn_file_init_with_fd","__qtn_file_apply_to_fd","__qtn_file_apply_to_path"
    };
    size_t i;
    if (!name) return 0;
    for(i=0;i<sizeof(names)/sizeof(*names);++i) if (!strcmp(name,names[i])) return 1;
    return 0;
}

int xxemul_darwin_posix_dispatch(xxemul_darwin_posix *p, const char *name, xxemul_status *status)
{
    uint64_t a,b,c,d,result=0;
    char path[GUEST_PATH_MAX], second[GUEST_PATH_MAX], leaf[GUEST_PATH_MAX];
    int index, operation=-1;
    if (!p || !name || !status || !xxemul_darwin_posix_supports(name)) return 0;
    if(!strcmp(name,"_fopen$DARWIN_EXTSN")) name="_fopen";
    a=p->emulator->arm.gpr[0]; b=p->emulator->arm.gpr[1]; c=p->emulator->arm.gpr[2]; d=p->emulator->arm.gpr[3];
    (void)d;
    *status=XXEMUL_STATUS_OK;
#define IS(s) (!strcmp(name,s))
#define BAD(e,r) do { result=failure(p,e,r); goto done; } while(0)
    if (IS("_popen") || IS("_pclose") || IS("_posix_spawnp") || IS("_waitpid")) { *status=XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION; return 1; }
    if (IS("_pipe")) {
#ifdef F_SETNOSIGPIPE
        int descriptors[2], first, last;
        if(!guest_range(p,a,8u)) BAD(EFAULT,UINT64_MAX);
        if(pipe(descriptors)<0) BAD(errno,UINT64_MAX);
        /* A closed guest reader must produce guest EPIPE, never terminate
         * the host interpreter or install a host-global signal handler. */
        if(fcntl(descriptors[1],F_SETNOSIGPIPE,1)<0) {
            int error=errno; close(descriptors[0]); close(descriptors[1]); BAD(error,UINT64_MAX);
        }
        (void)fcntl(descriptors[0],F_SETFD,FD_CLOEXEC);
        (void)fcntl(descriptors[1],F_SETFD,FD_CLOEXEC);
        first=adopt_descriptor(p,descriptors[0]);
        if(first<0) { int error=errno; close(descriptors[1]); BAD(error,UINT64_MAX); }
        last=adopt_descriptor(p,descriptors[1]);
        if(last<0) { int error=errno; close_descriptor(p,first); BAD(error,UINT64_MAX); }
        (void)put(p,a,4,(unsigned)first); (void)put(p,a+4u,4,(unsigned)last);
#else
        /* No safe per-descriptor suppression is available on this host. */
        BAD(ENOTSUP,UINT64_MAX);
#endif
    } else if (IS("_fcntl")) {
        uint64_t value=0;
        struct guest_file *file;
        if(!descriptor_valid(p,a)) BAD(EBADF,UINT64_MAX);
        file=&p->files[a];
        if((b==2u||b==4u)&&!get(p,p->emulator->arm.sp,4,&value)) BAD(EFAULT,UINT64_MAX);
        if(b==1u) result=file->descriptor_flags; /* F_GETFD */
        else if(b==2u) file->descriptor_flags=(unsigned)value&1u; /* F_SETFD: host CLOEXEC remains enforced */
        else if(b==3u) { /* F_GETFL */
            if(file->owned) { int flags=fcntl(file->fd,F_GETFL); if(flags<0) BAD(errno,UINT64_MAX); file->logical_flags=darwin_open_flags(flags); }
            result=file->logical_flags;
        } else if(b==4u) { /* F_SETFL; Darwin's unnamed int argument is on SP. */
            int flags;
            if(value&~UINT64_C(15)) BAD(ENOTSUP,UINT64_MAX);
            if(!file->owned&&(((unsigned)value^file->logical_flags)&12u)) BAD(ENOTSUP,UINT64_MAX);
            if(file->owned) {
                flags=fcntl(file->fd,F_GETFL); if(flags<0) BAD(errno,UINT64_MAX);
                flags=(flags&~(O_NONBLOCK|O_APPEND))|((value&4u)?O_NONBLOCK:0)|((value&8u)?O_APPEND:0);
                if(fcntl(file->fd,F_SETFL,flags)<0) BAD(errno,UINT64_MAX);
            }
            /* Inherited host standard descriptors belong to the application;
             * changes to their shared status flags are unsupported. */
            file->logical_flags=(file->logical_flags&3u)|((unsigned)value&12u);
        } else BAD(ENOTSUP,UINT64_MAX);
    } else if (IS("_poll")) {
        struct pollfd descriptors[POSIX_FILES];
        uint16_t invalid[POSIX_FILES];
        unsigned i, ready=0;
        int timeout=(int32_t)c, polled;
        if(b>POSIX_FILES) BAD(EINVAL,UINT64_MAX);
        if(b&&!guest_range(p,a,b*8u)) BAD(EFAULT,UINT64_MAX);
        if(timeout < -1) BAD(EINVAL,UINT64_MAX);
        for(i=0;i<(unsigned)b;++i) {
            uint64_t descriptor,events;
            (void)get(p,a+i*8u,4,&descriptor); (void)get(p,a+i*8u+4u,2,&events);
            invalid[i]=0; memset(&descriptors[i],0,sizeof(descriptors[i]));
            if((int32_t)descriptor<0) descriptors[i].fd=-1;
            else if(!descriptor_valid(p,descriptor)) { descriptors[i].fd=-1; invalid[i]=0x20u; ++ready; }
            else descriptors[i].fd=p->files[descriptor].fd;
            if(events&1u) descriptors[i].events|=POLLIN;
            if(events&2u) descriptors[i].events|=POLLPRI;
            if(events&4u) descriptors[i].events|=POLLOUT;
            if(events&0x40u) descriptors[i].events|=POLLRDNORM;
            if(events&0x80u) descriptors[i].events|=POLLRDBAND;
            if(events&0x100u) descriptors[i].events|=POLLWRBAND;
        }
        polled=poll(descriptors,(nfds_t)b,ready?0:timeout);
        if(polled<0) BAD(errno,UINT64_MAX);
        for(i=0;i<(unsigned)b;++i) {
            unsigned returned=invalid[i];
            if(descriptors[i].revents&POLLIN) returned|=1u;
            if(descriptors[i].revents&POLLPRI) returned|=2u;
            if(descriptors[i].revents&POLLOUT) returned|=4u;
            if(descriptors[i].revents&POLLERR) returned|=8u;
            if(descriptors[i].revents&POLLHUP) returned|=0x10u;
            if(descriptors[i].revents&POLLNVAL) returned|=0x20u;
            if(descriptors[i].revents&POLLRDNORM) returned|=0x40u;
            if(descriptors[i].revents&POLLRDBAND) returned|=0x80u;
            if(descriptors[i].revents&POLLWRBAND) returned|=0x100u;
            (void)put(p,a+i*8u+6u,2,returned);
        }
        result=ready+(unsigned)polled;
    } else if (IS("_sigprocmask")) {
        uint64_t mask=0;
        if((b&&!guest_range(p,b,4u))||(c&&!guest_range(p,c,4u))) BAD(EFAULT,UINT64_MAX);
        if(b&&(a<1u||a>3u)) BAD(EINVAL,UINT64_MAX);
        if(b) (void)get(p,b,4,&mask);
        if(c) (void)put(p,c,4,p->signal_mask);
        if(b) {
            if(a==1u) p->signal_mask|=(uint32_t)mask;
            else if(a==2u) p->signal_mask&=~(uint32_t)mask;
            else p->signal_mask=(uint32_t)mask;
            p->signal_mask&=~((UINT32_C(1)<<8)|(UINT32_C(1)<<16)); /* SIGKILL/SIGSTOP */
        }
    } else if (IS("_clock_gettime")) {
        struct timespec value;
        clockid_t clock;
        if(!guest_range(p,b,16u)) BAD(EFAULT,UINT64_MAX);
        if(a==0u) clock=CLOCK_REALTIME;
        else if(a==6u) clock=CLOCK_MONOTONIC;
        else if(a==12u) clock=CLOCK_PROCESS_CPUTIME_ID;
        else if(a==16u) clock=CLOCK_THREAD_CPUTIME_ID;
        else BAD(EINVAL,UINT64_MAX);
        if(clock_gettime(clock,&value)<0) BAD(errno,UINT64_MAX);
        (void)put(p,b,8,(uint64_t)value.tv_sec); (void)put(p,b+8u,8,(uint64_t)value.tv_nsec);
    } else if (IS("_sysconf")) {
        /* Configuration describes this bounded, single-thread guest. */
        if(a==29u) result=4096u;
        else if(a==200u) result=XXEMUL_DARWIN_ARENA_SIZE/4096u;
        else if(a==57u||a==58u) result=1;
        else if(a==5u) result=POSIX_FILES;
        else if(a==3u) result=100;
        else BAD(EINVAL,UINT64_MAX);
    } else if (IS("_getrlimit")) {
        uint64_t limit;
        if(a>8u) BAD(EINVAL,UINT64_MAX);
        if(!guest_range(p,b,16u)) BAD(EFAULT,UINT64_MAX);
        if(a==2u) limit=XXEMUL_DARWIN_ARENA_SIZE;
        else if(a==5u) limit=p->emulator->region_size;
        else if(a==8u) limit=POSIX_FILES;
        else if(a==7u) limit=1;
        else if(a==4u||a==6u) limit=0;
        else limit=INT64_MAX;
        (void)put(p,b,8,limit); (void)put(p,b+8u,8,limit);
    } else if (IS("_futimens")) {
        struct timespec times[2]; unsigned i;
        if(a<3u||!descriptor_valid(p,a)) BAD(EBADF,UINT64_MAX);
        if(b&&!guest_range(p,b,32u)) BAD(EFAULT,UINT64_MAX);
        for(i=0;b&&i<2u;++i) {
            uint64_t seconds,nanoseconds;
            (void)get(p,b+i*16u,8,&seconds); (void)get(p,b+i*16u+8u,8,&nanoseconds);
            if((int64_t)nanoseconds==-1) times[i].tv_nsec=UTIME_NOW;
            else if((int64_t)nanoseconds==-2) times[i].tv_nsec=UTIME_OMIT;
            else if(nanoseconds>999999999u) BAD(EINVAL,UINT64_MAX);
            else times[i].tv_nsec=(long)nanoseconds;
            times[i].tv_sec=(time_t)(int64_t)seconds;
        }
        if(futimens(p->files[a].fd,b?times:NULL)<0) BAD(errno,UINT64_MAX);
    } else if (IS("_fsync")) {
        if(!descriptor_valid(p,a)) BAD(EBADF,UINT64_MAX);
        if(fsync(p->files[a].fd)<0) BAD(errno,UINT64_MAX);
    } else if (IS("_alarm")) {
        /* Timed asynchronous guest signal delivery is not implemented. */
        if(a) { *status=XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION; return 1; }
    } else if (IS("_mbrtowc") || IS("_mbsinit")) {
        uint64_t state=IS("_mbsinit")?a:d, ch=0;
        unsigned i;
        if(state&&!guest_range(p,state,128u)) BAD(EFAULT,IS("_mbsinit")?0:UINT64_MAX);
        for(i=0;state&&i<128u;++i) {
            (void)get(p,state+i,1,&ch);
            if(ch) { if(IS("_mbsinit")) goto done; BAD(92,UINT64_MAX); }
        }
        if(IS("_mbsinit")) result=1;
        else if(!b) result=0;
        else if(!c) result=UINT64_MAX-1u;
        else {
            if(!get(p,b,1,&ch)) BAD(EFAULT,UINT64_MAX);
            if(ch>127u) BAD(92,UINT64_MAX);
            if(a&&!put(p,a,4,ch)) BAD(EFAULT,UINT64_MAX);
            result=ch?1u:0u;
        }
    } else if (IS("_wcwidth")) {
        result=a==0?0:a>=32u&&a<=126u?1:UINT64_MAX;
    } else if (IS("_dup")) {
        int fd;
        if(!descriptor_valid(p,a)) BAD(EBADF,UINT64_MAX);
        fd=dup(p->files[a].fd); if(fd<0) BAD(errno,UINT64_MAX);
        index=adopt_descriptor(p,fd); if(index<0) BAD(errno,UINT64_MAX);
        result=(uint64_t)index;
    } else if (IS("_pread")) {
        result=pread_guest(p,a,b,c,d);
        if(result==UINT64_MAX) set_error(p,errno);
    } else if (IS("_gettimeofday")) {
        struct timeval tv; struct timezone tz;
        if((a&&!guest_range(p,a,16u))||(b&&!guest_range(p,b,8u))) BAD(EFAULT,UINT64_MAX);
        if(gettimeofday(&tv,b?&tz:NULL)<0) BAD(errno,UINT64_MAX);
        if(a&&(!put(p,a,8,(uint64_t)tv.tv_sec)||!put(p,a+8u,4,(uint32_t)tv.tv_usec)||!put(p,a+12u,4,0))) BAD(EFAULT,UINT64_MAX);
        if(b&&(!put(p,b,4,(uint32_t)tz.tz_minuteswest)||!put(p,b+4u,4,(uint32_t)tz.tz_dsttime))) BAD(EFAULT,UINT64_MAX);
    } else if (IS("_futimes")) {
        struct timeval times[2]; unsigned i;
        if(a<3u||!descriptor_valid(p,a)) BAD(EBADF,UINT64_MAX);
        if(b&&!guest_range(p,b,32u)) BAD(EFAULT,UINT64_MAX);
        for(i=0;b&&i<2u;++i) {
            uint64_t seconds,useconds;
            if(!get(p,b+i*16u,8,&seconds)||!get(p,b+i*16u+8u,4,&useconds)) BAD(EFAULT,UINT64_MAX);
            if(useconds>999999u) BAD(EINVAL,UINT64_MAX);
            times[i].tv_sec=(time_t)(int64_t)seconds; times[i].tv_usec=(suseconds_t)useconds;
        }
        if(futimes(p->files[a].fd,b?times:NULL)<0) BAD(errno,UINT64_MAX);
    } else if (IS("_fchflags") || IS("_fcopyfile") || IS("_fgetattrlist") || IS("_fsetattrlist")) {
        if(a<3u||!descriptor_valid(p,a)) BAD(EBADF,UINT64_MAX);
#if defined(__APPLE__)
        if(IS("_fchflags")) {
            if(b>UINT32_MAX) BAD(EINVAL,UINT64_MAX);
            operation=fchflags(p->files[a].fd,(uint32_t)b);
        } else if(IS("_fcopyfile")) {
            if(b<3u||!descriptor_valid(p,b)) BAD(EBADF,UINT64_MAX);
            /* Only metadata copying is modeled. No guest copyfile state or
             * callback is ever passed to a native library. */
            if(c || (d&~(uint64_t)(COPYFILE_ACL|COPYFILE_XATTR|COPYFILE_STAT))) BAD(ENOTSUP,UINT64_MAX);
            operation=fcopyfile(p->files[a].fd,p->files[b].fd,NULL,(copyfile_flags_t)d);
        } else {
            struct attrlist attributes;
            unsigned char buffer[36];
            uint64_t value; unsigned i;
            uint32_t masks[5];
            if(!guest_range(p,b,24u)||!get(p,b,2,&value)) BAD(EFAULT,UINT64_MAX);
            if(value!=5u) BAD(EINVAL,UINT64_MAX);
            if(!get(p,b+2u,2,&value)) BAD(EFAULT,UINT64_MAX);
            if(value) BAD(EINVAL,UINT64_MAX);
            for(i=0;i<5u;++i) { if(!get(p,b+4u+i*4u,4,&value)) BAD(EFAULT,UINT64_MAX); masks[i]=(uint32_t)value; }
            /* gzip preserves FinderInfo but clears type/creator codes. Other
             * attribute operations, notably pathname changes, are unsupported. */
            if(masks[0]!=ATTR_CMN_FNDRINFO||masks[1]||masks[2]||masks[3]||masks[4]||p->emulator->arm.gpr[4]) BAD(ENOTSUP,UINT64_MAX);
            memset(&attributes,0,sizeof(attributes)); attributes.bitmapcount=5; attributes.commonattr=ATTR_CMN_FNDRINFO;
            if(IS("_fgetattrlist")) {
                if(d<sizeof(buffer)) BAD(ERANGE,UINT64_MAX);
                if(!guest_range(p,c,sizeof(buffer))) BAD(EFAULT,UINT64_MAX);
                memset(buffer,0,sizeof(buffer));
                operation=fgetattrlist(p->files[a].fd,&attributes,buffer,sizeof(buffer),0);
                if(!operation&&xxemul_write_memory(p->emulator,c,buffer,sizeof(buffer))!=XXEMUL_STATUS_OK) BAD(EFAULT,UINT64_MAX);
            } else {
                if(d!=32u) BAD(EINVAL,UINT64_MAX);
                if(xxemul_read_memory(p->emulator,c,buffer,32u)!=XXEMUL_STATUS_OK) BAD(EFAULT,UINT64_MAX);
                operation=fsetattrlist(p->files[a].fd,&attributes,buffer,32u,0);
            }
        }
        if(operation<0) BAD(errno,UINT64_MAX);
#else
        BAD(ENOTSUP,UINT64_MAX);
#endif
    } else if (IS("_isprint") || IS("_iswprint") || IS("_isspace")) {
        result=IS("_isspace")?(a==32u||(a>=9u&&a<=13u)):(a>=32u&&a<=126u);
    } else if (IS("_mbtowc")) {
        uint64_t ch;
        if(!b) goto done; /* C locale has no conversion state. */
        if(!c) BAD(92,UINT64_MAX); /* incomplete C-locale character */
        if(!get(p,b,1,&ch)) BAD(EFAULT,UINT64_MAX);
        if(ch>127u) BAD(92,UINT64_MAX); /* Darwin EILSEQ */
        if(a&&!put(p,a,4,ch)) BAD(EFAULT,UINT64_MAX);
        result=ch?1u:0u;
    } else if (IS("_nl_langinfo")) {
        static const char *const values[]={
            "US-ASCII","%a %b %e %H:%M:%S %Y","%m/%d/%y","%H:%M:%S","%I:%M:%S %p","AM","PM",
            "Sunday","Monday","Tuesday","Wednesday","Thursday","Friday","Saturday",
            "Sun","Mon","Tue","Wed","Thu","Fri","Sat",
            "January","February","March","April","May","June","July","August","September","October","November","December",
            "Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec",
            "","","","","",".","","^[yY]","^[nN]"
        };
        const char *value=a<sizeof(values)/sizeof(*values)?values[a]:"";
        if(xxemul_write_memory(p->emulator,p->text_address,value,strlen(value)+1u)!=XXEMUL_STATUS_OK) BAD(EFAULT,0);
        result=p->text_address;
    } else if (IS("_strdup") || IS("_strcspn") || IS("_strtol")) {
        char *text=malloc(GUEST_STRING_MAX);
        if(!text) BAD(ENOMEM,IS("_strdup")?0:UINT64_MAX);
        if(!guest_string(p,a,text,GUEST_STRING_MAX)) { int error=errno; free(text); BAD(error,0); }
        if(IS("_strdup")) {
            size_t size=strlen(text)+1u;
            result=p->allocate(p->allocate_context,size);
            if(!result) { free(text); BAD(ENOMEM,0); }
            if(xxemul_write_memory(p->emulator,result,text,size)!=XXEMUL_STATUS_OK) { free(text); BAD(EFAULT,0); }
        } else if(IS("_strcspn")) {
            if(!guest_string(p,b,second,sizeof(second))) { int error=errno; free(text); BAD(error,0); }
            result=strcspn(text,second);
        } else {
            char *end;
            if((int)c!=0&&((int)c<2||(int)c>36)) { free(text); BAD(EINVAL,0); }
            errno=0;
            result=(uint64_t)(int64_t)strtoll(text,&end,(int)c);
            if(errno) set_error(p,errno);
            if(b&&!put(p,b,8,a+(size_t)(end-text))) { free(text); BAD(EFAULT,0); }
        }
        free(text);
    } else if (IS("_access")) {
        int parent; struct stat sb;
        if(b&~UINT64_C(7)) BAD(EINVAL,UINT64_MAX);
        if(!guest_string(p,a,path,sizeof(path))) BAD(errno,UINT64_MAX);
        parent=parent_directory(p,path,leaf); if(parent<0) BAD(errno,UINT64_MAX);
        operation=fstatat(parent,leaf,&sb,AT_SYMLINK_NOFOLLOW);
        if(!operation && S_ISLNK(sb.st_mode)) { operation=-1; errno=ELOOP; }
        if(!operation) operation=faccessat(parent,leaf,(int)b,AT_SYMLINK_NOFOLLOW);
        { int error=errno; close(parent); if(operation<0) BAD(error,UINT64_MAX); }
    } else if (IS("_geteuid") || IS("_getuid") || IS("_getgid") || IS("_getegid")) {
        result=IS("_geteuid")?geteuid():IS("_getuid")?getuid():IS("_getgid")?getgid():getegid();
    } else if (IS("_sigaction")) {
        unsigned char action[16];
        if(a==0u||a>=32u||a==9u||a==17u) BAD(EINVAL,UINT64_MAX);
        if((b&&!guest_range(p,b,16u))||(c&&!guest_range(p,c,16u))) BAD(EFAULT,UINT64_MAX);
        if(b&&xxemul_read_memory(p->emulator,b,action,16u)!=XXEMUL_STATUS_OK) BAD(EFAULT,UINT64_MAX);
        if(c&&xxemul_write_memory(p->emulator,c,p->signal_actions[a],16u)!=XXEMUL_STATUS_OK) BAD(EFAULT,UINT64_MAX);
        if(b) memcpy(p->signal_actions[a],action,16u);
        /* Stored guest dispositions never install handlers in the host process.
         * Asynchronous signal delivery is outside this single-thread runtime. */
    } else if (IS("_fopen") || IS("_fdopen")) {
        int flags; unsigned file_flags;
        if (!guest_string(p,b,second,sizeof(second)) || !mode_flags(second,&flags,&file_flags)) BAD(errno,0);
        if (IS("_fdopen")) { if (!descriptor_valid(p,a)) BAD(EBADF,0); index=(int)a; }
        else {
            int fd;
            if (!guest_string(p,a,path,sizeof(path))) BAD(errno,0);
            fd=open_guest_path(p,path,flags,0666);
            if (fd<0) BAD(errno,0);
            index=adopt_descriptor(p,fd);
            if(index<0) BAD(errno,0);
        }
        result=attach_stream(p,index,second,file_flags);
        if(!result) { int error=errno; if(IS("_fopen")) (void)close_descriptor(p,index); BAD(error,0); }
    } else if (IS("_open") || IS("_openat")) {
        int flags=0,fd, directory=IS("_openat")?(int32_t)a:GUEST_AT_FDCWD;
        uint64_t requested=IS("_openat")?c:b;
        uint64_t mode=0666;
        if(!guest_string(p,IS("_openat")?b:a,path,sizeof(path))) BAD(errno,UINT64_MAX);
        if((requested&3u)==3u) BAD(EINVAL,UINT64_MAX);
        flags=(requested&3u)==2u?O_RDWR:(requested&3u)==1u?O_WRONLY:O_RDONLY;
        if(requested&4u) flags|=O_NONBLOCK;
        if(requested&0x8u) flags|=O_APPEND;
        if(requested&0x200u) { flags|=O_CREAT; if(!get(p,p->emulator->arm.sp,4,&mode)) BAD(EFAULT,UINT64_MAX); }
        if(requested&0x400u) flags|=O_TRUNC;
        if(requested&0x800u) flags|=O_EXCL;
        if(requested&0x100000u) flags|=O_DIRECTORY;
        if(requested&0x200000u) {
#ifdef O_SYMLINK
            flags|=O_SYMLINK;
#else
            BAD(ENOTSUP,UINT64_MAX);
#endif
        }
        /* The bridge always enforces no-follow traversal, including Darwin's
         * private no-follow flags used by the system unzip utility. */
        fd=open_guest_path_at(p,directory,path,flags,(mode_t)mode);
        if(fd<0) BAD(errno,UINT64_MAX);
        index=adopt_descriptor(p,fd); if(index<0) BAD(errno,UINT64_MAX);
        p->files[index].descriptor_flags=(requested&0x1000000u)?1u:0u;
        result=(uint64_t)index;
    } else if (IS("_close")) {
        if(!descriptor_valid(p,a)) BAD(EBADF,UINT64_MAX);
        operation=close_descriptor(p,(int)a); if(operation<0) BAD(errno,UINT64_MAX);
    } else if (IS("_read") || IS("_write")) {
        if(!descriptor_valid(p,a)) BAD(EBADF,UINT64_MAX);
        result=transfer(p,(int)a,b,c,IS("_write"),0);
    } else if (IS("_lseek")) {
        off_t offset;
        if(!descriptor_valid(p,a)) BAD(EBADF,UINT64_MAX);
        if(c>2u) BAD(EINVAL,UINT64_MAX);
        offset=lseek(p->files[a].fd,(off_t)(int64_t)b,(int)c);
        if(offset==(off_t)-1) BAD(errno,UINT64_MAX);
        result=(uint64_t)offset;
    } else if (IS("_fread") || IS("_fwrite")) {
        uint64_t total,transferred;
        index=file_index(p,d); if(index<0 || !p->files[index].file) BAD(EBADF,0);
        if(!b || !c) { result=0; goto done; }
        if(c>UINT64_MAX/b) BAD(EOVERFLOW,0);
        total=b*c; transferred=transfer(p,index,a,total,IS("_fwrite"),1);
        result=transferred==UINT64_MAX?0:transferred/b;
    } else if(IS("_fclose") || IS("_fseeko") || IS("_fseek") || IS("_ftello") || IS("_ftell") || IS("_rewind") ||
              IS("_clearerr") || IS("_feof") || IS("_ferror") || IS("_fileno") || IS("_setvbuf") || IS("_fflush")) {
        if(IS("_fflush") && !a) {
            for(index=0;index<POSIX_FILES;++index) if(p->files[index].file && fflush(p->files[index].file)) BAD(errno,UINT64_MAX);
            result=0; goto done;
        }
        index=file_index(p,a); if(index<0 || !p->files[index].file) BAD(EBADF,UINT64_MAX);
        if(IS("_fclose")) { if(close_descriptor(p,index)) BAD(errno,UINT64_MAX); }
        else if(IS("_fseeko") || IS("_fseek")) { if(fseeko(p->files[index].file,(off_t)(int64_t)b,(int)c)) BAD(errno,UINT64_MAX); sync_file(p,index); }
        else if(IS("_ftello") || IS("_ftell")) { off_t offset=ftello(p->files[index].file); if(offset<0) BAD(errno,UINT64_MAX); result=(uint64_t)offset; }
        else if(IS("_rewind")) { rewind(p->files[index].file); sync_file(p,index); }
        else if(IS("_clearerr")) { clearerr(p->files[index].file); sync_file(p,index); }
        else if(IS("_feof")) result=(uint64_t)!!feof(p->files[index].file);
        else if(IS("_ferror")) result=(uint64_t)!!ferror(p->files[index].file);
        else if(IS("_fileno")) result=(uint64_t)index;
        else if(IS("_setvbuf")) result=0; /* retain host-owned buffers */
        else if(fflush(p->files[index].file)) BAD(errno,UINT64_MAX);
    } else if(IS("_getc") || IS("_fgetc") || IS("_putc") || IS("_fputc") || IS("_ungetc") || IS("_putchar")) {
        int input=IS("_getc")||IS("_fgetc"), value;
        index=IS("_putchar")?1:file_index(p,input?a:b);
        if(index<0 || !p->files[index].file) BAD(EBADF,UINT64_MAX);
        if(input) value=fgetc(p->files[index].file);
        else if(IS("_ungetc")) value=ungetc((int)a,p->files[index].file);
        else { unsigned char byte=(unsigned char)a; value=xxemul_darwin_posix_write_stream(p,p->files[index].guest,&byte,1)==1?byte:EOF; }
        sync_file(p,index); result=(uint64_t)(int64_t)value;
    } else if(IS("_fgets")) {
        char *buffer;
        index=file_index(p,c); if(index<0 || !p->files[index].file) BAD(EBADF,0);
        if((int32_t)b<=0 || b>GUEST_STRING_MAX || !guest_range(p,a,b)) BAD(EINVAL,0);
        buffer=malloc((size_t)b); if(!buffer) BAD(ENOMEM,0);
        if(fgets(buffer,(int)b,p->files[index].file)) {
            if(xxemul_write_memory(p->emulator,a,buffer,strlen(buffer)+1)!=XXEMUL_STATUS_OK) { free(buffer); BAD(EFAULT,0); }
            result=a;
        }
        free(buffer); sync_file(p,index);
    } else if(IS("_fputs") || IS("_puts")) {
        char *text=malloc(GUEST_STRING_MAX); uint64_t stream;
        if(!text) BAD(ENOMEM,UINT64_MAX);
        if(!guest_string(p,a,text,GUEST_STRING_MAX)) { int error=errno; free(text); BAD(error,UINT64_MAX); }
        stream=IS("_puts")?p->files[1].guest:b;
        if(xxemul_darwin_posix_write_stream(p,stream,text,strlen(text))!=(int64_t)strlen(text)) { free(text); result=UINT64_MAX; goto done; }
        free(text);
        if(IS("_puts") && xxemul_darwin_posix_write_stream(p,stream,"\n",1)!=1) result=UINT64_MAX;
    } else if(IS("_stat") || IS("_lstat") || IS("_fstat") || IS("_fstatat")) {
        struct stat sb;
        uint64_t output=IS("_fstatat")?c:b;
        if(IS("_fstat")) { if(!descriptor_valid(p,a)) BAD(EBADF,UINT64_MAX); operation=fstat(p->files[a].fd,&sb); }
        else {
            int parent;
            if(IS("_fstatat") && (d&~UINT64_C(0x820))) BAD(EINVAL,UINT64_MAX);
            if(!guest_string(p,IS("_fstatat")?b:a,path,sizeof(path))) BAD(errno,UINT64_MAX);
            parent=parent_directory_at(p,IS("_fstatat")?(int32_t)a:GUEST_AT_FDCWD,path,leaf); if(parent<0) BAD(errno,UINT64_MAX);
            operation=fstatat(parent,leaf,&sb,AT_SYMLINK_NOFOLLOW);
            { int error=errno; close(parent); errno=error; }
            if(!operation && (IS("_stat") || (IS("_fstatat") && (!(d&0x20u) || (d&0x800u)))) && S_ISLNK(sb.st_mode)) BAD(ELOOP,UINT64_MAX);
        }
        if(operation<0) BAD(errno,UINT64_MAX);
        if(!write_stat(p,output,&sb)) BAD(EFAULT,UINT64_MAX);
    } else if(IS("_fchmod") || IS("_fchown")) {
        if(a<3u || !descriptor_valid(p,a)) BAD(EBADF,UINT64_MAX);
        operation=IS("_fchmod")?fchmod(p->files[a].fd,(mode_t)b):fchown(p->files[a].fd,(uid_t)b,(gid_t)c);
        if(operation<0) BAD(errno,UINT64_MAX);
    } else if(IS("_chown") || IS("_lchown") || IS("_lchmod")) {
        int parent;
        if(!guest_string(p,a,path,sizeof(path))) BAD(errno,UINT64_MAX);
        parent=parent_directory(p,path,leaf); if(parent<0) BAD(errno,UINT64_MAX);
        if(IS("_lchmod")) operation=fchmodat(parent,leaf,(mode_t)b,AT_SYMLINK_NOFOLLOW);
        else if(IS("_lchown")) operation=fchownat(parent,leaf,(uid_t)b,(gid_t)c,AT_SYMLINK_NOFOLLOW);
        else {
            int fd=openat(parent,leaf,O_RDONLY|O_NOFOLLOW|O_CLOEXEC);
            if(fd>=0) { operation=fchown(fd,(uid_t)b,(gid_t)c); { int error=errno; close(fd); errno=error; } }
        }
        { int error=errno; close(parent); if(operation<0) BAD(error,UINT64_MAX); }
    } else if(IS("_mkdir") || IS("_mkdirat")) {
        int parent;
        if(!guest_string(p,IS("_mkdirat")?b:a,path,sizeof(path))) BAD(errno,UINT64_MAX);
        parent=parent_directory_at(p,IS("_mkdirat")?(int32_t)a:GUEST_AT_FDCWD,path,leaf); if(parent<0) BAD(errno,UINT64_MAX);
        operation=mkdirat(parent,leaf,(mode_t)(IS("_mkdirat")?c:b)&(mode_t)~p->creation_mask);
        { int error=errno; close(parent); if(operation<0) BAD(error,UINT64_MAX); }
    } else if(IS("_umask")) {
        result=p->creation_mask; p->creation_mask=(unsigned)a&0777u;
    } else if(IS("_chmod") || IS("_utime")) {
        int fd;
        if(!guest_string(p,a,path,sizeof(path))) BAD(errno,UINT64_MAX);
        fd=open_guest_path(p,path,O_RDONLY,0); if(fd<0) BAD(errno,UINT64_MAX);
        if(IS("_chmod")) operation=fchmod(fd,(mode_t)b);
        else {
            struct timespec times[2]; uint64_t first,last;
            if(b && (!get(p,b,8,&first)||!get(p,b+8,8,&last))) { close(fd); BAD(EFAULT,UINT64_MAX); }
            if(b) { times[0].tv_sec=(time_t)first; times[0].tv_nsec=0; times[1].tv_sec=(time_t)last; times[1].tv_nsec=0; }
            operation=futimens(fd,b?times:NULL);
        }
        { int error=errno; close(fd); if(operation<0) BAD(error,UINT64_MAX); }
    } else if(IS("_rename") || IS("_renameat") || IS("_unlink") || IS("_unlinkat") || IS("_rmdir") || IS("_readlink") || IS("_symlinkat")) {
        int parent;
        uint64_t path_address=IS("_renameat")||IS("_unlinkat")?b:IS("_symlinkat")?c:a;
        int directory=IS("_renameat")||IS("_unlinkat")?(int32_t)a:IS("_symlinkat")?(int32_t)b:GUEST_AT_FDCWD;
        if(!guest_string(p,path_address,path,sizeof(path))) BAD(errno,UINT64_MAX);
        parent=parent_directory_at(p,directory,path,leaf); if(parent<0) BAD(errno,UINT64_MAX);
        if(IS("_rename") || IS("_renameat")) {
            char destination[GUEST_PATH_MAX]; int other;
            if(!guest_string(p,IS("_renameat")?d:b,second,sizeof(second))) { int error=errno; close(parent); BAD(error,UINT64_MAX); }
            other=parent_directory_at(p,IS("_renameat")?(int32_t)c:GUEST_AT_FDCWD,second,destination); if(other<0) { int error=errno; close(parent); BAD(error,UINT64_MAX); }
            operation=renameat(parent,leaf,other,destination);
            { int error=errno; close(other); errno=error; }
        } else if(IS("_symlinkat")) {
            const char *component;
            if(!guest_string(p,a,second,sizeof(second))) { int error=errno; close(parent); BAD(error,UINT64_MAX); }
            /* Confined extraction permits only relative targets without an
             * upward path component. The bridge never follows these links. */
            if(second[0]=='/') { close(parent); BAD(EACCES,UINT64_MAX); }
            for(component=second;*component;) {
                size_t length=strcspn(component,"/");
                if(length==2 && component[0]=='.' && component[1]=='.') { close(parent); BAD(EACCES,UINT64_MAX); }
                component+=length; while(*component=='/') ++component;
            }
            operation=symlinkat(second,parent,leaf);
        } else if(IS("_readlink")) {
            ssize_t length;
            if(c>sizeof(second)||!guest_range(p,b,c)) { close(parent); BAD(EINVAL,UINT64_MAX); }
            length=readlinkat(parent,leaf,second,(size_t)c);
            if(length>=0) { result=(uint64_t)length; operation=xxemul_write_memory(p->emulator,b,second,(size_t)length)==XXEMUL_STATUS_OK?0:-1; }
        } else {
            if(IS("_unlinkat") && (c&~UINT64_C(0x28a0))) { close(parent); BAD(EINVAL,UINT64_MAX); }
            operation=unlinkat(parent,leaf,IS("_rmdir")||(IS("_unlinkat")&&(c&0x80u))?AT_REMOVEDIR:0);
        }
        { int error=errno; close(parent); if(operation<0) BAD(error,UINT64_MAX); }
    } else if(IS("_realpath$DARWIN_EXTSN")) {
        const char *component;
        size_t used;
        int fd;
        if(!guest_string(p,a,path,sizeof(path))) BAD(errno,0);
        fd=open_guest_path(p,path,O_RDONLY,0); if(fd<0) BAD(errno,0);
        close(fd);
        used=strlen(p->root_path);
        if(used>=1024u) BAD(ENAMETOOLONG,0);
        memcpy(second,p->root_path,used+1);
        component=path;
        if(*component=='/') component+=used; /* already checked against root */
        while(*component) {
            size_t length;
            while(*component=='/') ++component;
            length=strcspn(component,"/");
            if(length && !(length==1u && *component=='.')) {
                if(used+length+2u>1024u) BAD(ENAMETOOLONG,0);
                if(used==0u || second[used-1]!='/') second[used++]='/';
                memcpy(second+used,component,length); used+=length; second[used]='\0';
            }
            component+=length;
        }
        result=b?b:p->allocate(p->allocate_context,used+1u);
        if(!result) BAD(ENOMEM,0);
        if(xxemul_write_memory(p->emulator,result,second,used+1u)!=XXEMUL_STATUS_OK) BAD(EFAULT,0);
    } else if(IS("__qtn_file_alloc")) {
        for(index=0;index<POSIX_DIRS && p->quarantine[index].guest;++index) {}
        if(index==POSIX_DIRS) BAD(ENOMEM,0);
        result=p->allocate(p->allocate_context,16);
        if(!result) BAD(ENOMEM,0);
        p->quarantine[index].guest=result; p->quarantine[index].size=0;
    } else if(IS("__qtn_file_free") || IS("__qtn_file_init_with_fd") || IS("__qtn_file_apply_to_fd") || IS("__qtn_file_apply_to_path")) {
        struct guest_quarantine *q;
        if(IS("__qtn_file_free") && !a) goto done;
        for(index=0;index<POSIX_DIRS && p->quarantine[index].guest!=a;++index) {}
        if(index==POSIX_DIRS || !a) BAD(EINVAL,(uint32_t)EINVAL);
        q=&p->quarantine[index];
        if(IS("__qtn_file_free")) { memset(q,0,sizeof(*q)); goto done; }
#if defined(__APPLE__)
        {
            int fd, owned=0;
            if(IS("__qtn_file_apply_to_path")) {
                if(!guest_string(p,b,path,sizeof(path))) BAD(errno,(uint32_t)errno);
                fd=open_guest_path(p,path,O_RDONLY,0); owned=1;
                if(fd<0) BAD(errno,(uint32_t)errno);
            } else {
                if(b<3u || !descriptor_valid(p,b)) BAD(EBADF,(uint32_t)EBADF);
                fd=p->files[b].fd;
            }
            if(IS("__qtn_file_init_with_fd")) {
                ssize_t length=fgetxattr(fd,"com.apple.quarantine",q->data,sizeof(q->data),0,0);
                if(length>=0) { q->size=(size_t)length; operation=0; }
                else operation=-1; /* Missing metadata remains a real error. */
            } else operation=q->size?fsetxattr(fd,"com.apple.quarantine",q->data,q->size,0,0):0;
            { int error=errno; if(owned) close(fd); if(operation<0) BAD(error,(uint32_t)error); }
        }
#else
        BAD(ENOTSUP,(uint32_t)ENOTSUP);
#endif
    } else if(IS("_mkstemp")) {
        size_t length; unsigned attempt; int parent,fd=-1;
        if(!guest_string(p,a,path,sizeof(path))) BAD(errno,UINT64_MAX);
        length=strlen(path); if(length<6||strcmp(path+length-6,"XXXXXX")) BAD(EINVAL,UINT64_MAX);
        parent=parent_directory(p,path,leaf); if(parent<0) BAD(errno,UINT64_MAX);
        for(attempt=0;attempt<256;++attempt) {
            static const char alphabet[]="abcdefghijklmnopqrstuvwxyz0123456789";
            unsigned value=++p->temp_counter*2654435761u^(unsigned)getpid(); size_t j;
            for(j=0;j<6;++j) { path[length-6+j]=alphabet[value%36]; value=value/36u+17u; }
            memcpy(leaf+strlen(leaf)-6,path+length-6,6);
            fd=openat(parent,leaf,O_RDWR|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);
            if(fd>=0||errno!=EEXIST) break;
        }
        { int error=errno; close(parent); if(fd<0) BAD(error,UINT64_MAX); }
        if(xxemul_write_memory(p->emulator,a,path,length+1)!=XXEMUL_STATUS_OK) { close(fd); BAD(EFAULT,UINT64_MAX); }
        index=adopt_descriptor(p,fd); if(index<0) BAD(errno,UINT64_MAX); result=(uint64_t)index;
    } else if(IS("_opendir")) {
        int fd;
        if(!guest_string(p,a,path,sizeof(path))) BAD(errno,0);
        for(index=0;index<POSIX_DIRS&&p->directories[index].directory;++index) {}
        if(index==POSIX_DIRS) BAD(EMFILE,0);
        fd=open_guest_path(p,path,O_RDONLY|O_DIRECTORY,0); if(fd<0) BAD(errno,0);
        p->directories[index].directory=fdopendir(fd);
        if(!p->directories[index].directory) { int error=errno; close(fd); BAD(error,0); }
        p->directories[index].guest=p->allocate(p->allocate_context,16);
        p->directories[index].entry=p->allocate(p->allocate_context,1048);
        if(!p->directories[index].guest||!p->directories[index].entry) { closedir(p->directories[index].directory); p->directories[index].directory=NULL; BAD(ENOMEM,0); }
        result=p->directories[index].guest;
    } else if(IS("_readdir") || IS("_closedir")) {
        for(index=0;index<POSIX_DIRS;++index) if(p->directories[index].directory&&p->directories[index].guest==a) break;
        if(index==POSIX_DIRS) BAD(EBADF,IS("_readdir")?0:UINT64_MAX);
        if(IS("_closedir")) { operation=closedir(p->directories[index].directory); p->directories[index].directory=NULL; if(operation) BAD(errno,UINT64_MAX); }
        else {
            struct dirent *entry; size_t length;
            errno=0; entry=readdir(p->directories[index].directory);
            if(!entry) { if(errno) set_error(p,errno); result=0; goto done; }
            result=p->directories[index].entry; length=strlen(entry->d_name);
            if(length>1023) BAD(ENAMETOOLONG,0);
            if(!put(p,result,8,entry->d_ino)||!put(p,result+8,8,0)||!put(p,result+16,2,1048)||
               !put(p,result+18,2,length)||!put(p,result+20,1,entry->d_type)||
               xxemul_write_memory(p->emulator,result+21,entry->d_name,length+1)!=XXEMUL_STATUS_OK) BAD(EFAULT,0);
        }
    } else if(IS("_time")) {
        time_t now=time(NULL); result=(uint64_t)now; if(a&&!put(p,a,8,result)) BAD(EFAULT,UINT64_MAX);
    } else if(IS("_ctime")) {
        uint64_t seconds; time_t when; struct tm value; char text[80];
        if(!get(p,a,8,&seconds)) BAD(EFAULT,0);
        when=(time_t)(int64_t)seconds;
        if(!localtime_r(&when,&value)||!asctime_r(&value,text)) BAD(errno,0);
        if(xxemul_write_memory(p->emulator,p->text_address,text,strlen(text)+1u)!=XXEMUL_STATUS_OK) BAD(EFAULT,0);
        result=p->text_address;
    } else if(IS("_localtime") || IS("_localtime_r") || IS("_gmtime")) {
        uint64_t seconds; time_t when; struct tm value;
        if(!get(p,a,8,&seconds)) BAD(EFAULT,0); when=(time_t)(int64_t)seconds;
        if(!(IS("_gmtime")?gmtime_r(&when,&value):localtime_r(&when,&value))) BAD(errno,0);
        result=IS("_localtime_r")?b:p->tm_address;
        if(!write_tm(p,result,&value)) BAD(EFAULT,0);
    } else if(IS("_strftime")) {
        struct tm value;
        char *text;
        if(b>GUEST_STRING_MAX||!guest_range(p,a,b)||!guest_string(p,c,path,sizeof(path))||!read_tm(p,d,&value)) BAD(EFAULT,0);
#if defined(__APPLE__) || defined(__linux__)
        {
            uint64_t offset, zone;
            if(!get(p,d+40u,8,&offset)||!get(p,d+48u,8,&zone)) BAD(EFAULT,0);
            if(zone&&!guest_string(p,zone,second,sizeof(second))) BAD(EFAULT,0);
            value.tm_gmtoff=(long)(int64_t)offset;
            value.tm_zone=zone?second:NULL;
        }
#endif
        if(!b) goto done;
        text=malloc((size_t)b); if(!text) BAD(ENOMEM,0);
        result=strftime(text,(size_t)b,path,&value);
        if(result&&xxemul_write_memory(p->emulator,a,text,(size_t)result+1u)!=XXEMUL_STATUS_OK) { free(text); BAD(EFAULT,0); }
        free(text);
    } else if(IS("_mktime") || IS("_asctime")) {
        struct tm value;
        if(!read_tm(p,a,&value)) BAD(EFAULT,IS("_asctime")?0:UINT64_MAX);
        if(IS("_mktime")) { time_t converted=mktime(&value); result=(uint64_t)converted; if(!write_tm(p,a,&value)) BAD(EFAULT,UINT64_MAX); }
        else {
            char text[80];
            if(!asctime_r(&value,text)) BAD(errno,0);
            if(xxemul_write_memory(p->emulator,p->text_address,text,strlen(text)+1)!=XXEMUL_STATUS_OK) BAD(EFAULT,0);
            result=p->text_address;
        }
    } else if(IS("_tzset")) tzset();
    else if(IS("_getpid")) result=(uint64_t)getpid();
    else if(IS("_isatty")) { result=0; set_error(p,ENOTTY); }
    else if(IS("_signal")) result=0; /* guest handlers are not host signal handlers */
    else if(IS("_tcgetattr") || IS("_tcsetattr") || IS("_ioctl")) BAD(ENOTTY,UINT64_MAX);
    else if(IS("_strerror")) {
        const char *message=strerror((int)a); size_t length=strlen(message);
        if(length>1023) length=1023;
        if(xxemul_write_memory(p->emulator,p->text_address,message,length)!=XXEMUL_STATUS_OK||!put(p,p->text_address+length,1,0)) BAD(EFAULT,0);
        result=p->text_address;
    } else if(IS("_perror")) {
        uint64_t error; const char *message;
        if(!get(p,p->errno_address,4,&error)) BAD(EFAULT,0);
        if(a&&!guest_string(p,a,path,sizeof(path))) BAD(errno,0);
        if(a&&*path) { (void)xxemul_darwin_posix_write_stream(p,p->files[2].guest,path,strlen(path)); (void)xxemul_darwin_posix_write_stream(p,p->files[2].guest,": ",2); }
        message=strerror((int)error); (void)xxemul_darwin_posix_write_stream(p,p->files[2].guest,message,strlen(message));
        (void)xxemul_darwin_posix_write_stream(p,p->files[2].guest,"\n",1);
    }
done:
    p->emulator->arm.gpr[0]=result;
#undef IS
#undef BAD
    return 1;
}

static struct guest_virtual_handle *virtual_handle(xxemul_darwin_posix *p, uint64_t fd)
{
    if (fd < POSIX_VIRTUAL_FD_BASE || fd - POSIX_VIRTUAL_FD_BASE >= POSIX_VIRTUAL_HANDLES) return NULL;
    return p->virtual_handles[fd - POSIX_VIRTUAL_FD_BASE].active ? &p->virtual_handles[fd - POSIX_VIRTUAL_FD_BASE] : NULL;
}

static uint64_t pread_guest(xxemul_darwin_posix *p, uint64_t fd, uint64_t address, uint64_t count, uint64_t offset)
{
    struct guest_virtual_handle *handle=virtual_handle(p,fd);
    unsigned char buffer[16384];
    uint64_t total=0;
    if (!guest_range(p,address,count)) { errno=EFAULT; return UINT64_MAX; }
    if (offset > INT64_MAX || count > INT64_MAX - offset) { errno=EINVAL; return UINT64_MAX; }
    if (handle) {
        struct guest_virtual_file *file=&p->virtual_files[handle->file];
        uint64_t amount=offset>=file->size?0:file->size-offset;
        if (amount>count) amount=count;
        if (amount && xxemul_write_memory(p->emulator,address,file->data+(size_t)offset,(size_t)amount)!=XXEMUL_STATUS_OK) {
            errno=EFAULT; return UINT64_MAX;
        }
        return amount;
    }
    if (!descriptor_valid(p,fd)) { errno=EBADF; return UINT64_MAX; }
    while (total<count) {
        size_t amount=count-total>sizeof(buffer)?sizeof(buffer):(size_t)(count-total);
        ssize_t read_count=pread(p->files[fd].fd,buffer,amount,(off_t)(offset+total));
        if (read_count<0) return total?total:UINT64_MAX;
        if (!read_count) break;
        if (xxemul_write_memory(p->emulator,address+total,buffer,(size_t)read_count)!=XXEMUL_STATUS_OK) { errno=EFAULT; return UINT64_MAX; }
        total+=(uint64_t)read_count;
        if ((size_t)read_count<amount) break;
    }
    return total;
}

static unsigned char *vm_pages(xxemul_darwin_posix *p, uint64_t address, uint64_t length)
{
    if (!p->image_pages || (address & (GUEST_VM_PAGE-1u))) return NULL;
    if (address>=p->image_base && address<=p->image_limit && length<=p->image_limit-address)
        return p->image_pages+(size_t)((address-p->image_base)/GUEST_VM_PAGE);
    if (address>=p->map_base && address-p->map_base<=p->map_size && length<=p->map_size-(address-p->map_base))
        return p->map_pages+(size_t)((address-p->map_base)/GUEST_VM_PAGE);
    return NULL;
}

int xxemul_darwin_posix_syscall(xxemul_darwin_posix *p, uint64_t number, xxemul_status *status)
{
    uint64_t *registers, a,b,c,d,e,f,result=0;
    int error=0;
    struct guest_virtual_handle *handle;
    if (!p || !status) return 0;
    registers=p->emulator->arm.gpr;
    a=registers[0]; b=registers[1]; c=registers[2]; d=registers[3]; e=registers[4]; f=registers[5];
    *status=XXEMUL_STATUS_OK;
    if (number==5u) {
        char path[GUEST_PATH_MAX];
        unsigned file, slot;
        int fd, flags;
        if (!guest_string(p,a,path,sizeof(path))) { error=errno; goto finished; }
        for (file=0;file<POSIX_VIRTUAL_FILES;++file)
            if (p->virtual_files[file].data && !strcmp(p->virtual_files[file].path,path)) break;
        if (file<POSIX_VIRTUAL_FILES) {
            if ((b&3u)!=0u || (b&(0x200u|0x400u|0x800u))) { error=EACCES; goto finished; }
            for (slot=0;slot<POSIX_VIRTUAL_HANDLES && p->virtual_handles[slot].active;++slot) {}
            if (slot==POSIX_VIRTUAL_HANDLES) { error=EMFILE; goto finished; }
            p->virtual_handles[slot].active=1; p->virtual_handles[slot].file=(int)file; p->virtual_handles[slot].offset=0;
            result=POSIX_VIRTUAL_FD_BASE+slot;
        } else {
            flags=(b&3u)==2u?O_RDWR:(b&3u)==1u?O_WRONLY:O_RDONLY;
            if (b&8u) flags|=O_APPEND;
            if (b&0x200u) flags|=O_CREAT;
            if (b&0x400u) flags|=O_TRUNC;
            if (b&0x800u) flags|=O_EXCL;
            if (b&0x100000u) flags|=O_DIRECTORY;
            fd=open_guest_path(p,path,flags,(mode_t)c);
            if (fd<0) { error=errno; goto finished; }
            fd=adopt_descriptor(p,fd);
            if (fd<0) { error=errno; goto finished; }
            result=(uint64_t)fd;
        }
    } else if (number==3u || number==4u || number==6u) {
        handle=virtual_handle(p,a);
        if (handle) {
            if (number==6u) handle->active=0;
            else if (number==4u) error=EBADF;
            else {
                result=pread_guest(p,a,b,c,handle->offset);
                if (result==UINT64_MAX) error=errno;
                else handle->offset+=result;
            }
        } else {
            const char *name=number==3u?"_read":number==4u?"_write":"_close";
            if (!xxemul_darwin_posix_dispatch(p,name,status)) return 0;
            if (*status!=XXEMUL_STATUS_OK) return 1;
            result=registers[0];
            if (result==UINT64_MAX) {
                uint64_t guest_error;
                if (!get(p,p->errno_address,4,&guest_error)) { *status=XXEMUL_STATUS_ADDRESS_FAULT; return 1; }
                registers[0]=guest_error; p->emulator->arm.pstate|=UINT32_C(0x20000000);
                return 1;
            }
        }
    } else if (number==153u) {
        result=pread_guest(p,a,b,c,d);
        if (result==UINT64_MAX) error=errno;
    } else if (number==197u || number==74u || number==73u) {
        uint64_t length, address=a;
        unsigned char *pages;
        size_t page_count, i;
        if (!b || b>UINT64_MAX-(GUEST_VM_PAGE-1u)) { error=EINVAL; goto finished; }
        length=(b+GUEST_VM_PAGE-1u)&~UINT64_C(4095);
        if (!p->image_pages) { error=ENOTSUP; goto finished; }
        if (number==197u) {
            int anonymous=(d&(UINT64_C(0x20)|UINT64_C(0x1000)))!=0u;
            int fixed=(d&UINT64_C(0x10))!=0u;
            if ((c&~UINT64_C(7)) || !(d&2u) || (f&(GUEST_VM_PAGE-1u))) { error=EINVAL; goto finished; }
            /* UPX reserves __PAGEZERO plus the image as one PROT_NONE span.
             * Only the populated image tail has backing RAM. */
            if (anonymous && !fixed && c==0u && length>p->map_size &&
                (a==0u || a==p->image_base) && length>p->image_base && length<=p->image_limit) {
                p->sparse_limit=length; result=0; goto finished;
            }
            if (!fixed) address=p->map_next;
            pages=vm_pages(p,address,length);
            if (!pages) { error=ENOMEM; goto finished; }
            if (!anonymous && !virtual_handle(p,e) && !descriptor_valid(p,e)) { error=EBADF; goto finished; }
            memset(p->emulator->region_data+(size_t)(address-p->emulator->region_address),0,(size_t)length);
            if (!anonymous) {
                uint64_t copied=pread_guest(p,e,address,b,f);
                if (copied==UINT64_MAX) { error=errno; goto finished; }
                handle=virtual_handle(p,e);
                if (handle && !strcmp(p->virtual_files[handle->file].path,"/usr/lib/dyld") && f==0u && b>0x1000u)
                    p->dyld_entry=address+UINT64_C(0x1000);
            }
            page_count=(size_t)(length/GUEST_VM_PAGE);
            memset(pages,0x80u|(unsigned)c,page_count);
            if (!fixed) p->map_next=address+length;
            result=address;
        } else {
            pages=vm_pages(p,address,length);
            if (!pages) { error=EINVAL; goto finished; }
            page_count=(size_t)(length/GUEST_VM_PAGE);
            if (number==74u) {
                if (c&~UINT64_C(7)) { error=EINVAL; goto finished; }
                for (i=0;i<page_count;++i) if (!(pages[i]&0x80u)) { error=ENOMEM; goto finished; }
                /* Protections describe interpreted guest pages. No host page
                 * is made executable and guest memory stays within the region. */
                memset(pages,0x80u|(unsigned)c,page_count);
            } else {
                memset(pages,0,page_count);
                memset(p->emulator->region_data+(size_t)(address-p->emulator->region_address),0,(size_t)length);
                if (p->dyld_entry>=address && p->dyld_entry-address<length) p->dyld_entry=0;
            }
        }
    } else return 0;
finished:
    if (error) {
        set_error(p,error); registers[0]=(uint64_t)guest_errno_value(error);
        p->emulator->arm.pstate|=UINT32_C(0x20000000);
    } else {
        registers[0]=result;
        p->emulator->arm.pstate&=~UINT32_C(0x20000000);
    }
    return 1;
}

#else
struct xxemul_darwin_posix { int unavailable; };
int xxemul_darwin_posix_open_host(xxemul_darwin_posix *p,const char *s,int f,unsigned m)
{ (void)p;(void)s;(void)f;(void)m;return -1; }
int xxemul_darwin_posix_dup_host(xxemul_darwin_posix *p,uint64_t f)
{ (void)p;(void)f;return -1; }
xxemul_darwin_posix *xxemul_darwin_posix_create(xxemul *e,uint64_t b,const char *w,uint64_t n,xxemul_darwin_posix_allocate a,void *c)
{ (void)e;(void)b;(void)w;(void)n;(void)a;(void)c;return NULL; }
void xxemul_darwin_posix_destroy(xxemul_darwin_posix *p) { free(p); }
int xxemul_darwin_posix_configure_vm(xxemul_darwin_posix *p,uint64_t b,uint64_t e,uint64_t m,uint64_t n) { (void)p;(void)b;(void)e;(void)m;(void)n;return 0; }
int xxemul_darwin_posix_set_virtual_file(xxemul_darwin_posix *p,const char *n,const void *b,size_t s) { (void)p;(void)n;(void)b;(void)s;return 0; }
uint64_t xxemul_darwin_posix_dyld_entry(const xxemul_darwin_posix *p) { (void)p;return 0; }
int xxemul_darwin_posix_syscall(xxemul_darwin_posix *p,uint64_t n,xxemul_status *s) { (void)p;(void)n;(void)s;return 0; }
int xxemul_darwin_posix_supports(const char *n) { (void)n;return 0; }
int xxemul_darwin_posix_dispatch(xxemul_darwin_posix *p,const char *n,xxemul_status *s) { (void)p;(void)n;(void)s;return 0; }
int xxemul_darwin_posix_validate_stream(xxemul_darwin_posix *p,uint64_t f,int w) { (void)p;(void)f;(void)w;return 0; }
int xxemul_darwin_posix_flush_stream(xxemul_darwin_posix *p,uint64_t f) { (void)p;(void)f;return -1; }
int64_t xxemul_darwin_posix_read_stream(xxemul_darwin_posix *p,uint64_t f,void *b,size_t n) { (void)p;(void)f;(void)b;(void)n;return -1; }
int64_t xxemul_darwin_posix_write_stream(xxemul_darwin_posix *p,uint64_t f,const void *b,size_t n) { (void)p;(void)f;(void)b;(void)n;return -1; }
#endif
