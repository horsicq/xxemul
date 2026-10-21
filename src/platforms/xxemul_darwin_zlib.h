#ifndef XXEMUL_DARWIN_ZLIB_H
#define XXEMUL_DARWIN_ZLIB_H

#include "xxemul/xxemul.h"

typedef struct xxemul_darwin_zlib xxemul_darwin_zlib;
typedef uint64_t (*xxemul_darwin_zlib_allocate)(void *context, uint64_t size);

/* Explicit zlib service model, with no native guest code. The Darwin ARM64
 * z_stream is 112 bytes: next_in0, avail_in8, total_in16, next_out24,
 * avail_out32, total_out40, msg48, state56, zalloc64, zfree72, opaque80,
 * data_type88, adler96, reserved104. Pointer/ulong fields are 64-bit;
 * avail_* and data_type are 32-bit. Guest alloc/free callbacks are rejected.
 * At most 32 streams, 32 MiB per buffer/call, 64 MiB native payload storage
 * plus allocation bookkeeping. */
xxemul_darwin_zlib *xxemul_darwin_zlib_create(xxemul *emulator,
    xxemul_darwin_zlib_allocate allocate, void *context);
void xxemul_darwin_zlib_destroy(xxemul_darwin_zlib *process);
int xxemul_darwin_zlib_supports(const char *name);
int xxemul_darwin_zlib_dispatch(xxemul_darwin_zlib *process, const char *name,
    xxemul_status *status);

#endif
