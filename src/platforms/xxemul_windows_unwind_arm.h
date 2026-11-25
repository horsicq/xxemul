#ifndef XXEMUL_WINDOWS_UNWIND_ARM_H
#define XXEMUL_WINDOWS_UNWIND_ARM_H

#include "xxemul_windows_unwind64.h"

typedef struct xxemul_windows_runtime_function_arm {
    uint64_t address;
    uint32_t begin_address, end_address, unwind_data;
} xxemul_windows_runtime_function_arm;

typedef struct xxemul_windows_unwind_arm_result {
    uint64_t establisher_frame, handler, handler_data;
    uint64_t integer_save[31], vfp_save[32];
    unsigned in_prologue, in_epilogue, chained_records;
} xxemul_windows_unwind_arm_result;

/* Authentication uses the existing guest CPU key/profile, never a host key.
 * Return zero on authentication failure. Windows Arm64 uses the IB key and
 * the completely unwound caller SP for PACIBSP return-address signing. */
typedef int (*xxemul_windows_unwind_arm_authenticate)(void *context, uint64_t signed_lr, uint64_t caller_sp, uint64_t *unsigned_lr);

xxemul_status xxemul_windows_unwind_arm_lookup_table(xxemul_windows_unwind64_read read, void *context, int is64, uint64_t table, uint32_t count, uint64_t image_base,
                                                     uint64_t control_pc, xxemul_windows_runtime_function_arm *function);
xxemul_status xxemul_windows_unwind_arm_lookup_image(xxemul_windows_unwind64_read read, void *context, int is64, uint64_t image_base, uint64_t image_size,
                                                     uint64_t control_pc, xxemul_windows_runtime_function_arm *function);

xxemul_status xxemul_windows_unwind_arm_virtual_unwind_ex(xxemul_windows_unwind64_read read, void *context, int is64, uint64_t image_base, uint64_t control_pc,
                                                          const xxemul_windows_runtime_function_arm *function, unsigned handler_type, xxemul_arm_state *cpu,
                                                          xxemul_windows_unwind_arm_result *result, xxemul_windows_unwind_arm_authenticate authenticate);
xxemul_status xxemul_windows_unwind_arm_virtual_unwind(xxemul_windows_unwind64_read read, void *context, int is64, uint64_t image_base, uint64_t control_pc,
                                                       const xxemul_windows_runtime_function_arm *function, unsigned handler_type, xxemul_arm_state *cpu,
                                                       xxemul_windows_unwind_arm_result *result);

/* Ordinary dynamic tables; callback-based tables are dispatched by the guest
 * runtime. All metadata/state/output updates are bounded and atomic on error. */
typedef struct xxemul_windows_unwind_arm_table {
    uint64_t address, image_base, begin_address, end_address;
    uint32_t count;
    unsigned active, is64;
} xxemul_windows_unwind_arm_table;
typedef struct xxemul_windows_unwind_arm_registry {
    xxemul_windows_unwind_arm_table tables[64];
} xxemul_windows_unwind_arm_registry;
xxemul_status xxemul_windows_unwind_arm_add_table(xxemul_windows_unwind64_read read, void *context, int is64, xxemul_windows_unwind_arm_registry *registry,
                                                  uint64_t table, uint32_t count, uint64_t image_base);
int xxemul_windows_unwind_arm_delete_table(xxemul_windows_unwind_arm_registry *registry, uint64_t table);
xxemul_status xxemul_windows_unwind_arm_lookup_dynamic(xxemul_windows_unwind64_read read, void *context, int is64, const xxemul_windows_unwind_arm_registry *registry,
                                                       uint64_t control_pc, uint64_t *image_base, xxemul_windows_runtime_function_arm *function);

#endif
