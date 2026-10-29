#ifndef XXEMUL_WINDOWS_H
#define XXEMUL_WINDOWS_H

#include "xxemul/xxemul.h"

#include <stddef.h>
#include <stdint.h>

typedef struct xxemul_windows xxemul_windows;
#define XXEMUL_WINDOWS_SINGLE_STEP_FAULT UINT32_C(0x80000004)

/* Arguments exclude the executable name. The working directory confines
 * guest file I/O; both paths must remain valid until this call returns. */
xxemul_windows *xxemul_windows_create(xxemul *emulator, const char *program_path, const char *working_directory, const char *const *arguments, size_t argument_count,
                                      xxemul_status *status);
/* Names and values are borrowed for this call; the process owns any stored
 * guest environment data. */
xxemul_status xxemul_windows_set_environment(xxemul_windows *process, const char *name, const char *value);
void xxemul_windows_destroy(xxemul_windows *process);

/* Call before normal x86/ARM instruction decoding. A nonzero return means
 * the guest PC was a synthetic Windows API thunk and status is authoritative. */
int xxemul_windows_try_step(xxemul_windows *process, xxemul_step_info *info, xxemul_status *status);
/* Dispatch guest x86 SEH/VEH faults; debugger-owned breakpoints are stopped
 * by the adapters before instruction execution and never enter this path. */
int xxemul_windows_try_exception(xxemul_windows *process, const xxemul_x86_state *before, xxemul_status status, xxemul_step_info *info);

/* FS (x86) and GS (x86-64) base for TEB-relative memory operands. */
uint64_t xxemul_windows_segment_base(const xxemul_windows *process, uint8_t segment_index);
uint32_t xxemul_windows_exit_code(const xxemul_windows *process);
/* Returns a borrowed import name when address is a synthetic API thunk. */
const char *xxemul_windows_thunk_name(const xxemul *emulator, uint64_t address);
const char *xxemul_windows_thunk_qualified_name(const xxemul *emulator, uint64_t address);

#endif
