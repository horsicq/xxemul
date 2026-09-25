#ifndef XXEMUL_LINUX_H
#define XXEMUL_LINUX_H

#include "xxemul/xxemul.h"

#include <stddef.h>
#include <stdint.h>

typedef struct xxemul_linux_process xxemul_linux_process;
typedef void (*xxemul_linux_output_callback)(
    void *context, int descriptor, const void *bytes, size_t size);

/* The caller owns the emulator. argv includes argv[0]; when empty, the
 * executable path is used. The working directory confines host file I/O. */
xxemul_linux_process *xxemul_linux_create(
    xxemul *emulator, const char *executable_path,
    const char *working_directory, int argc, const char *const *argv);
/* Start a replacement ELF already held in guest memory (such as a memfd).
 * The image and argument strings are copied; the caller retains ownership. */
xxemul_linux_process *xxemul_linux_create_image(
    xxemul *emulator, const uint8_t *image, size_t image_size,
    const char *guest_executable_path, const char *working_directory,
    int argc, const char *const *argv,
    int envc, const char *const *envp);
void xxemul_linux_destroy(xxemul_linux_process *process);
void xxemul_linux_set_output(
    xxemul_linux_process *process,
    xxemul_linux_output_callback callback, void *context);

/* Called for int 0x80 (i386) or syscall (amd64), after instruction decode.
 * The CPU still owns advancement of IP and the final HALTED step result. */
xxemul_status xxemul_linux_dispatch(xxemul_linux_process *process);
int xxemul_linux_has_exited(const xxemul_linux_process *process);
int xxemul_linux_exit_code(const xxemul_linux_process *process);

/* A self-unpacking ELF may execve an in-memory image. The returned bytes are
 * borrowed until the process is destroyed; the caller creates the successor. */
const uint8_t *xxemul_linux_exec_image(
    const xxemul_linux_process *process, size_t *size);
const char *xxemul_linux_working_directory(
    const xxemul_linux_process *process);
/* The pathname is exactly the guest argument; it is empty for
 * execveat(fd, "", ..., AT_EMPTY_PATH). dirfd/flags preserve that target. */
const char *xxemul_linux_exec_path(const xxemul_linux_process *process);
int xxemul_linux_exec_is_at(const xxemul_linux_process *process);
int xxemul_linux_exec_dirfd(const xxemul_linux_process *process);
uint64_t xxemul_linux_exec_flags(const xxemul_linux_process *process);
size_t xxemul_linux_exec_argc(const xxemul_linux_process *process);
const char *xxemul_linux_exec_argument(
    const xxemul_linux_process *process, size_t index);
size_t xxemul_linux_exec_envc(const xxemul_linux_process *process);
const char *xxemul_linux_exec_environment(
    const xxemul_linux_process *process, size_t index);

/* Call these before the original flat-region memory access. A return value
 * of 0 means the address is not in a Linux mmap; 1 means success; -1 means
 * a partial/invalid mapping. MAP_FIXED can intentionally cover the image. */
int xxemul_linux_mapping_read(
    xxemul_linux_process *process, uint64_t address,
    void *buffer, size_t size);
int xxemul_linux_mapping_write(
    xxemul_linux_process *process, uint64_t address,
    const void *buffer, size_t size);

/* The x86 effective-address path adds this for FS/GS references. */
uint64_t xxemul_linux_segment_base(
    const xxemul_linux_process *process, unsigned segment_index,
    uint16_t selector);

#endif
