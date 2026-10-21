#ifndef XXEMUL_DARWIN_H
#define XXEMUL_DARWIN_H

#include "xxemul/xxemul.h"

typedef struct xxemul_darwin xxemul_darwin;
/* Shared by the loader, guest allocator and reported physical-memory limit.
 * 128 MiB accommodates a single-threaded XZ preset-6 encoder (~94 MiB)
 * while keeping all guest allocations inside a fixed, checked region. */
#define XXEMUL_DARWIN_ARENA_SIZE (128u * 1024u * 1024u)
#define XXEMUL_DARWIN_IMAGE_WINDOW_SIZE (16u * 1024u * 1024u)
#define XXEMUL_DARWIN_VM_ARENA_SIZE (32u * 1024u * 1024u)

/* Darwin ARM64/arm64e process adapter, not dyld or a complete macOS runtime.
 * The loader reserves a 128 MiB arena at runtime_base for runtime objects,
 * guest argv, bounded malloc/realloc storage and stdio bridge buffers.
 * Known libSystem and libc++ imports use bounded guest-memory operations;
 * executable-local functions must resolve to their actual guest addresses.
 * The libc++ object model follows the arm64 libc++ v15006 layout used by the
 * local Xcode SDK: ostream virtual ios base at +8, 160-byte ostream object.
 * A bounded libc/stdio bridge confines host files to the requested workdir;
 * qsort comparator callbacks execute as guest instructions; signed function
 * pointers use the same software PAC validation as the ARM64 interpreter.
 * setlocale supports querying or selecting C/POSIX (including an empty
 * name with the empty guest environment), with ASCII case conversion.
 * Other locale names return NULL without changing the host process locale.
 * Exceptions, arbitrary dylibs, threads and general locale behavior remain
 * unsupported.
 * Unknown functions and exception entry points bind named failure thunks.
 * On macOS, selected libarchive imports use bounded native in-memory TAR
 * services. Their file operations remain confined and callbacks execute in
 * the interpreter; this is a library service model, not guest dylib execution.
 * Selected zlib imports similarly translate Darwin streams to bounded native
 * DEFLATE/inflate/CRC services; guest allocation callbacks are unsupported.
 * Selected bzip2 file APIs use bounded native compression/decompression
 * streams with opaque guest handles and confined guest stdio operations.
 * No guest code executes natively and no host subprocess is launched.
 */
xxemul_darwin *xxemul_darwin_create(xxemul *emulator, uint64_t runtime_base, xxemul_status *status);
/* LC_UNIXTHREAD starts at the guest kernel entry, with no dyld work skipped.
 * Original bytes supply only the packed executable's read-only virtual fd. */
xxemul_status xxemul_darwin_kernel_entry(xxemul_darwin *process, const void *image, size_t size);
/* Validate and bind an image restored by guest code, using its live segments. */
xxemul_status xxemul_macho_bind_restored(xxemul *emulator, uint64_t header_address, uint64_t *main_address);
void xxemul_darwin_destroy(xxemul_darwin *process);
xxemul_status xxemul_darwin_resolve_import(xxemul_darwin *process, const char *name, uint64_t *address);
xxemul_status xxemul_darwin_start(xxemul_darwin *process, const char *path, const char *workdir, int argc, const char *const *argv);
int xxemul_darwin_try_step(xxemul_darwin *process, xxemul_step_info *info, xxemul_status *status);
/* Called only after cdisasm decodes an A64 SVC instruction. */
xxemul_status xxemul_darwin_handle_svc(xxemul_darwin *process, uint64_t immediate);
int xxemul_darwin_exit_code(const xxemul_darwin *process);
const char *xxemul_darwin_symbol(const xxemul_darwin *process, uint64_t address);
const char *xxemul_darwin_last_error(const xxemul_darwin *process);

#endif
