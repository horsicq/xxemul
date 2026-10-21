#ifndef XXEMUL_DARWIN_BZIP2_H
#define XXEMUL_DARWIN_BZIP2_H

#include "xxemul/xxemul.h"
#include "xxemul_darwin_posix.h"

typedef struct xxemul_darwin_bzip2 xxemul_darwin_bzip2;

/* Explicit libbz2 service model. Guest BZFILE values are opaque handles;
 * native low-level streams use confined read_stream/write_stream operations,
 * never native FILE pointers or guest callbacks. There are at most 32 open
 * handles, 5000-byte streaming buffers, 32 MiB per guest read/write call,
 * and 64 MiB of native payload storage plus bookkeeping. Library verbosity
 * must be zero; native diagnostic output is not part of the guest streams.
 * ReadGetUnused returns a guest copy valid until that BZ handle is closed.
 * WriteClose64 writes four 32-bit counters through optional guest pointers. */
xxemul_darwin_bzip2 *xxemul_darwin_bzip2_create(xxemul *emulator,
    xxemul_darwin_posix_allocate allocate, void *context, xxemul_darwin_posix *posix);
void xxemul_darwin_bzip2_destroy(xxemul_darwin_bzip2 *process);
int xxemul_darwin_bzip2_supports(const char *name);
int xxemul_darwin_bzip2_dispatch(xxemul_darwin_bzip2 *process, const char *name,
    xxemul_status *status);

#endif
