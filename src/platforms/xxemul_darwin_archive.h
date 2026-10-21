#ifndef XXEMUL_DARWIN_ARCHIVE_H
#define XXEMUL_DARWIN_ARCHIVE_H

#include "xxemul/xxemul.h"
#include "xxemul_darwin_posix.h"

typedef struct xxemul_darwin_archive xxemul_darwin_archive;

/* Explicit libarchive service model. Native libarchive only parses/serializes
 * bounded memory buffers. All files use the confined POSIX bridge; guest
 * callbacks are returned to the interpreter, never called as host code.
 * Opaque handles validate their type and protect callback-owned lifetimes. */
xxemul_darwin_archive *xxemul_darwin_archive_create(xxemul *emulator,
    xxemul_darwin_posix_allocate allocate, void *context, xxemul_darwin_posix *posix);
void xxemul_darwin_archive_destroy(xxemul_darwin_archive *process);
int xxemul_darwin_archive_supports(const char *name);
int xxemul_darwin_archive_dispatch(xxemul_darwin_archive *process, const char *name,
    xxemul_status *status);
/* A dispatched API can suspend for one guest callback. take_callback consumes
 * that request; after the interpreter returns, complete_callback resumes it.
 * Completion can queue another callback. Preserve the suspended API's LR. */
int xxemul_darwin_archive_take_callback(xxemul_darwin_archive *process,
    uint64_t *target, uint64_t arguments[3], unsigned *count);
xxemul_status xxemul_darwin_archive_complete_callback(xxemul_darwin_archive *process,
    uint64_t result);

#endif
