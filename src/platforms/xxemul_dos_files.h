#ifndef XXEMUL_DOS_FILES_H
#define XXEMUL_DOS_FILES_H

#include "xxemul/xxemul.h"

#include <stddef.h>
#include <stdint.h>

/* Call after creating a DOS image and before stepping it. argv excludes argv[0].
 * The DOS drive is rooted at workdir; the executable must also be staged there.
 * A failed start preserves the current session. Destroying the emulator stops it. */
xxemul_status xxemul_dos_files_start(xxemul *emulator, const char *workdir, const char *guest_exe_name, size_t argc, const char *const *argv);
void xxemul_dos_files_stop(xxemul *emulator);

/* Internal INT 21h handle-service entry point. */
xxemul_status xxemul_dos_files_interrupt(xxemul *emulator, uint8_t function);
/* AH=0Ah line input: retain a partial line when the CPU retries the interrupt
 * after XXEMUL_STATUS_INPUT_REQUIRED. A CR completes the bounded guest buffer. */
xxemul_status xxemul_dos_buffered_input(xxemul *emulator);
/* AH=0Ch flushes before its first input attempt, retaining that fact while
 * the same interrupt waits so newly supplied keys survive a CPU retry. */
xxemul_status xxemul_dos_flush_input_begin(xxemul *emulator, uint8_t function);
void xxemul_dos_flush_input_end(xxemul *emulator, xxemul_status status);
void xxemul_dos_files_initialize_kernel(xxemul *emulator);
int xxemul_dos_files_list_of_lists(xxemul *emulator, uint16_t *segment, uint16_t *offset);

/* Memory allocation strategy belongs to the DOS process session.
 * The default before process startup is first-fit (0). */
uint16_t xxemul_dos_files_allocation_strategy(xxemul *emulator);
int xxemul_dos_files_set_allocation_strategy(xxemul *emulator, uint16_t strategy);

/* Returns 4 KiB cluster counts for the current workdir-backed C: drive. */
int xxemul_dos_files_drive_space(xxemul *emulator, uint16_t *available, uint16_t *total);

/* Same-emulator real-mode EXEC/termination. A successful transfer is consumed
 * by the x86 instruction step, so debugger hooks observe every child step. */
xxemul_status xxemul_dos_files_exec(xxemul *emulator);
int xxemul_dos_files_return_to_parent(xxemul *emulator, uint8_t code, xxemul_status *status);
uint16_t xxemul_dos_files_child_status(xxemul *emulator);
uint16_t xxemul_dos_files_mcb_head(const xxemul *emulator);
int xxemul_dos_files_child_active(xxemul *emulator);

#endif
