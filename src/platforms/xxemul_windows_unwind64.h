/* Copyright (c) 2026 hors<horsicq@gmail.com> */

#ifndef XXEMUL_WINDOWS_UNWIND64_H
#define XXEMUL_WINDOWS_UNWIND64_H

#include <xxemul/xxemul.h>
#include <stddef.h>
#include <stdint.h>

/* Internal x64 Windows metadata walker. It never executes guest handlers or
 * writes guest memory. All target bytes are obtained through this reader. */
typedef int (*xxemul_windows_unwind64_read)(void *context, uint64_t address, void *destination, size_t size);

typedef struct xxemul_windows_runtime_function64 {
    uint64_t address; /* Guest address of the twelve-byte RUNTIME_FUNCTION. */
    uint32_t begin_address, end_address, unwind_data;
} xxemul_windows_runtime_function64;

typedef struct xxemul_windows_unwind64_result {
    uint64_t establisher_frame;
    uint64_t handler, handler_data;
    uint64_t integer_save[16], xmm_save[16];
    unsigned in_prologue, in_epilogue, machine_frame, chained_records;
} xxemul_windows_unwind64_result;

/* A successful lookup with address==0 means no matching function (leaf).
 * Tables must be DWORD aligned, sorted and nonoverlapping; at most 0x10000
 * entries are read. Outputs are unchanged on error. */
xxemul_status xxemul_windows_unwind64_lookup_table(xxemul_windows_unwind64_read read, void *context, uint64_t table, uint32_t count, uint64_t image_base,
                                                   uint64_t control_pc, xxemul_windows_runtime_function64 *function);
xxemul_status xxemul_windows_unwind64_lookup_image(xxemul_windows_unwind64_read read, void *context, uint64_t image_base, uint64_t image_size, uint64_t control_pc,
                                                   xxemul_windows_runtime_function64 *function);

/* function==NULL or function->address==0 performs the Windows leaf unwind.
 * handler_type uses UNW_FLAG_EHANDLER=1 / UNW_FLAG_UHANDLER=2 (or zero).
 * Native GPR/XMM/context updates commit only after a complete successful
 * unwind. Version 1/2, chained records and normal x64 epilogues are supported;
 * unknown/new unwind versions return UNSUPPORTED_IMAGE. */
xxemul_status xxemul_windows_unwind64_virtual_unwind(xxemul_windows_unwind64_read read, void *context, uint64_t image_base, uint64_t control_pc,
                                                     const xxemul_windows_runtime_function64 *function, unsigned handler_type, xxemul_x86_state *cpu,
                                                     xxemul_windows_unwind64_result *result);

#define XXEMUL_WINDOWS_UNWIND64_MAX_TABLES 64u
typedef struct xxemul_windows_unwind64_table {
    uint64_t address, image_base, begin_address, end_address;
    uint32_t count;
    unsigned active;
} xxemul_windows_unwind64_table;
typedef struct xxemul_windows_unwind64_registry {
    xxemul_windows_unwind64_table tables[XXEMUL_WINDOWS_UNWIND64_MAX_TABLES];
} xxemul_windows_unwind64_registry;

xxemul_status xxemul_windows_unwind64_add_table(xxemul_windows_unwind64_read read, void *context, xxemul_windows_unwind64_registry *registry, uint64_t table,
                                                uint32_t count, uint64_t image_base);
int xxemul_windows_unwind64_delete_table(xxemul_windows_unwind64_registry *registry, uint64_t table);
xxemul_status xxemul_windows_unwind64_lookup_dynamic(xxemul_windows_unwind64_read read, void *context, const xxemul_windows_unwind64_registry *registry,
                                                     uint64_t control_pc, uint64_t *image_base, xxemul_windows_runtime_function64 *function);

#endif
