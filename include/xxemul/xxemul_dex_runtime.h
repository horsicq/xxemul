#ifndef XXEMUL_XXEMUL_DEX_RUNTIME_H
#define XXEMUL_XXEMUL_DEX_RUNTIME_H

#include "xxemul_dex.h"
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct xxemul_dex_vm xxemul_dex_vm;

typedef enum xxemul_dex_value_kind {
    XXEMUL_DEX_VALUE_VOID = 0,
    XXEMUL_DEX_VALUE_WORD = 1,
    XXEMUL_DEX_VALUE_WIDE = 2,
    XXEMUL_DEX_VALUE_OBJECT = 3
} xxemul_dex_value_kind;

typedef struct xxemul_dex_value {
    uint64_t value;
    xxemul_dex_value_kind kind;
} xxemul_dex_value;

/** Arguments contain Dalvik 32-bit register words, including the receiver
 * for non-static methods and low/high words for wide parameters. A callback
 * must explicitly handle an external method or return a failure status. */
typedef xxemul_status (*xxemul_dex_external_callback)(void *context, xxemul_dex_vm *vm, const xxemul_dex_method_info *method, const uint32_t *argument_words,
                                                      size_t argument_word_count, xxemul_dex_value *result);

/** Optionally model a resolved method, including one with a DEX body. Runs
 * after argument/receiver checks and class initialization. Set handled=true
 * only when the method was implemented; handled=false and OK continues normal
 * execution and ignores result. Failures always stop the invocation. Handled
 * return values undergo the same kind/reference checks as external calls. */
typedef xxemul_status (*xxemul_dex_intercept_callback)(void *context, xxemul_dex_vm *vm, const xxemul_dex_method_info *method, const uint32_t *argument_words,
                                                       size_t argument_word_count, xxemul_dex_value *result, bool *handled);

typedef void (*xxemul_dex_trace_callback)(void *context, const xxemul_dex_method_info *method, uint32_t pc, const char *mnemonic);

/** Supply an explicit relationship for external classes whose hierarchy is
 * absent from the DEX files. Return positive for assignable, zero for
 * incompatible, or negative when unknown. DEX-defined hierarchy is always
 * checked first. */
typedef int (*xxemul_dex_assignability_callback)(void *context, const char *source_descriptor, const char *destination_descriptor);

typedef struct xxemul_dex_vm_config {
    /** Zero selects 100000 instructions per invocation. Includes callees
     * and class initializers. */
    uint64_t max_instructions;
    /** Zero selects 128 frames; values above 128 are rejected. The bounded
     * recursive interpreter reserves headroom for ordinary host stacks. */
    uint32_t max_call_depth;
    /** Zero selects 16 MiB of tracked heap allocations. */
    size_t max_heap_bytes;
    xxemul_dex_external_callback external_callback;
    void *external_context;
    xxemul_dex_trace_callback trace_callback;
    void *trace_context;
    xxemul_dex_assignability_callback assignability_callback;
    void *assignability_context;
    xxemul_dex_intercept_callback intercept_callback;
    void *intercept_context;
} xxemul_dex_vm_config;

typedef struct xxemul_dex_result {
    xxemul_status status;
    uint64_t value;
    xxemul_dex_value_kind value_kind;
    uint64_t instructions;
    size_t method_index;
    /** Byte offset from the method's first instruction. */
    uint32_t pc;
    char diagnostic[256];
} xxemul_dex_result;

/** The program must outlive the VM. Heap and static fields persist across
 * invokes; each invocation receives a fresh instruction budget. */
XXEMUL_API xxemul_dex_vm *xxemul_dex_vm_create(const xxemul_dex_program *program, const xxemul_dex_vm_config *config, xxemul_status *status);
XXEMUL_API void xxemul_dex_vm_destroy(xxemul_dex_vm *vm);
XXEMUL_API xxemul_status xxemul_dex_vm_invoke(xxemul_dex_vm *vm, size_t method_index, const uint32_t *argument_words, size_t argument_word_count,
                                              xxemul_dex_result *result);

/** Allocate a zero-initialized instance for an explicit host service or
 * entry receiver. Does not run its constructor. References are opaque
 * nonzero 32-bit handles; zero denotes null. */
XXEMUL_API xxemul_status xxemul_dex_vm_new_object(xxemul_dex_vm *vm, const char *class_descriptor, uint32_t *reference);
/** Copy bytes into a VM-owned [B array, charged to the VM heap budget. NULL
 * data is valid only for an empty array. Clears reference on failure. */
XXEMUL_API xxemul_status xxemul_dex_vm_new_byte_array(xxemul_dex_vm *vm, const uint8_t *data, size_t size, uint32_t *reference);
/** Byte-array access copies bytes without exposing VM storage. Null/invalid
 * handles and out-of-bounds ranges return ADDRESS_FAULT; other object types
 * return INVALID_ARGUMENT. Empty transfers permit NULL data. */
XXEMUL_API xxemul_status xxemul_dex_vm_byte_array_length(const xxemul_dex_vm *vm, uint32_t reference, size_t *length);
XXEMUL_API xxemul_status xxemul_dex_vm_read_byte_array(const xxemul_dex_vm *vm, uint32_t reference, size_t offset, uint8_t *data, size_t size);
XXEMUL_API xxemul_status xxemul_dex_vm_write_byte_array(xxemul_dex_vm *vm, uint32_t reference, size_t offset, const uint8_t *data, size_t size);
/** Check a class/array descriptor using the DEX hierarchy and optional host
 * assignability callback. Null matches nothing. An unknown external type
 * relationship returns UNSUPPORTED_INSTRUCTION; matches is cleared on error. */
XXEMUL_API xxemul_status xxemul_dex_vm_is_instance(xxemul_dex_vm *vm, uint32_t reference, const char *descriptor, int *matches);
/** Returns a borrowed NUL-terminated DEX MUTF-8 string, or NULL when the
 * reference is not a string. */
XXEMUL_API const char *xxemul_dex_vm_get_string(const xxemul_dex_vm *vm, uint32_t reference);
XXEMUL_API const char *xxemul_dex_vm_object_type(const xxemul_dex_vm *vm, uint32_t reference);

#ifdef __cplusplus
}
#endif

#endif
