/* Copyright (c) 2026 hors<horsicq@gmail.com> */

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
int xxemul_windows_try_arm_exception(xxemul_windows *process, const xxemul_arm_state *before, xxemul_status status, xxemul_step_info *info);

/* FS (x86) and GS (x86-64) base for TEB-relative memory operands. */
uint64_t xxemul_windows_segment_base(const xxemul_windows *process, uint8_t segment_index);
uint64_t xxemul_windows_teb_address(const xxemul_windows *process);
uint32_t xxemul_windows_exit_code(const xxemul_windows *process);
/* Guest access policy; debugger/loader reads remain privileged. access is
 * Windows AV parameter 0(read),1(write),8(execute). */
int xxemul_windows_memory_access(xxemul_windows *, uint64_t, uint64_t, unsigned, int);

/* Bounded scalar calls into the same guest Windows process. Widths describe
 * argument values, not host C types: x86 lays out 4/8-byte stack values;
 * Windows x64 uses 8-byte ABI slots. All pointers must already be guest VAs. */
#define XXEMUL_WINDOWS_NATIVE_STDCALL UINT32_C(1)
#define XXEMUL_WINDOWS_NATIVE_CDECL UINT32_C(2)
#define XXEMUL_WINDOWS_NATIVE_WIN64 UINT32_C(3)
#define XXEMUL_WINDOWS_NATIVE_VALIDATE UINT32_C(0)
#define XXEMUL_WINDOWS_NATIVE_LOAD UINT32_C(1)
#define XXEMUL_WINDOWS_NATIVE_INITIALIZE UINT32_C(2)
#define XXEMUL_WINDOWS_NATIVE_RESOLVE UINT32_C(3)
#define XXEMUL_WINDOWS_NATIVE_CALL UINT32_C(4)
#define XXEMUL_WINDOWS_NATIVE_COMPLETE UINT32_C(5)
typedef struct xxemul_windows_native_call {
    const char *module;
    const char *entry; /* Exact export name, or #decimal ordinal. */
    const uint64_t *arguments;
    const uint8_t *argument_widths; /* 4 or 8 for every argument. */
    size_t argument_count;          /* At most 16. */
    uint32_t convention;
    uint8_t return_width;       /* 0=void, 4=EAX, 8=RAX or x86 EDX:EAX. */
    uint64_t instruction_limit; /* Shared by loading, initialization and call. */
} xxemul_windows_native_call;
typedef struct xxemul_windows_native_result {
    xxemul_status status;
    uint32_t phase, last_error, stopped_thread_id;
    uint64_t value, instructions, module_base, entry_address;
    xxemul_x86_state stopped_state;
    char diagnostic[192];
} xxemul_windows_native_result;
/* Return bits are meaningful only for OK. Caller CPU/x87 state is restored;
 * guest memory, TLS, output and LastError effects remain. Incomplete native
 * execution makes subsequent calls fail closed. Loader/bridge reentry fails.
 * Native callbacks execute guest instructions; reverse managed callbacks and
 * non-scalar marshalling are not provided by this service. */
xxemul_status xxemul_windows_invoke_native(xxemul_windows *process, const xxemul_windows_native_call *call, xxemul_windows_native_result *result);
xxemul_status xxemul_windows_post_input(xxemul_windows *process, uint64_t window, uint32_t message, uint64_t wparam, uint64_t lparam);
/* Returns a borrowed import name when address is a synthetic API thunk. */
const char *xxemul_windows_thunk_name(const xxemul *emulator, uint64_t address);
const char *xxemul_windows_thunk_qualified_name(const xxemul *emulator, uint64_t address);

#endif
