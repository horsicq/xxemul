#ifndef XXEMUL_DARWIN_POSIX_H
#define XXEMUL_DARWIN_POSIX_H

#include "xxemul/xxemul.h"
#include <stddef.h>
#include <stdint.h>

typedef struct xxemul_darwin_posix xxemul_darwin_posix;
typedef uint64_t (*xxemul_darwin_posix_allocate)(void *context, uint64_t size);

xxemul_darwin_posix *xxemul_darwin_posix_create(xxemul *emulator, uint64_t runtime_base,
    const char *workdir, uint64_t errno_address, xxemul_darwin_posix_allocate allocate, void *allocate_context);
void xxemul_darwin_posix_destroy(xxemul_darwin_posix *process);
/* Runtime-library adapters use owned host descriptors opened through the same
 * no-traversal/no-symlink policy as guest POSIX calls. Flags are host flags;
 * callers must close returned descriptors and must never expose them to guests. */
int xxemul_darwin_posix_open_host(xxemul_darwin_posix *process, const char *path,
    int flags, unsigned mode);
int xxemul_darwin_posix_dup_host(xxemul_darwin_posix *process, uint64_t guest_fd);
/* Packed-image support uses existing guest RAM, never host executable maps. */
int xxemul_darwin_posix_configure_vm(xxemul_darwin_posix *process, uint64_t image_base,
    uint64_t image_limit, uint64_t map_base, uint64_t map_size);
int xxemul_darwin_posix_set_virtual_file(xxemul_darwin_posix *process, const char *path,
    const void *bytes, size_t length);
uint64_t xxemul_darwin_posix_dyld_entry(const xxemul_darwin_posix *process);
/* Reads x0..x5; on a handled call writes x0 and the Darwin carry error flag. */
int xxemul_darwin_posix_syscall(xxemul_darwin_posix *process, uint64_t number, xxemul_status *status);
int xxemul_darwin_posix_supports(const char *name);
int xxemul_darwin_posix_dispatch(xxemul_darwin_posix *process, const char *name, xxemul_status *status);
/* Validate the live FILE token and its mode (0=read, nonzero=write). Closed
 * tokens fail even if their descriptor slot has been used by a later fopen.
 * Helpers set guest errno on failure; reads return 0 at EOF, -1 on error. */
int xxemul_darwin_posix_validate_stream(xxemul_darwin_posix *process, uint64_t stream, int writing);
/* Flush a live writable stream without closing it. */
int xxemul_darwin_posix_flush_stream(xxemul_darwin_posix *process, uint64_t stream);
int64_t xxemul_darwin_posix_read_stream(xxemul_darwin_posix *process, uint64_t stream,
    void *bytes, size_t size);
int64_t xxemul_darwin_posix_write_stream(xxemul_darwin_posix *process, uint64_t stream,
    const void *bytes, size_t size);

#endif
