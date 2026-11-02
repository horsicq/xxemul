#ifndef XXEMUL_XXEMUL_DOTNET_RUNTIME_H
#define XXEMUL_XXEMUL_DOTNET_RUNTIME_H

#include "xxemul_dotnet.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct xxemul_dotnet_vm xxemul_dotnet_vm;
typedef enum xxemul_dotnet_value_kind {
    XXEMUL_DOTNET_VALUE_VOID = 0,
    XXEMUL_DOTNET_VALUE_I4 = 1,
    XXEMUL_DOTNET_VALUE_I8 = 2,
    /** IEEE-754 binary64 bits in the CIL internal floating stack type. */
    XXEMUL_DOTNET_VALUE_F = 3,
    /** Opaque 32-bit handle; zero denotes null. */
    XXEMUL_DOTNET_VALUE_OBJECT = 4,
    XXEMUL_DOTNET_VALUE_NATIVE = 5
} xxemul_dotnet_value_kind;

typedef struct xxemul_dotnet_value {
    uint64_t bits;
    xxemul_dotnet_value_kind kind;
} xxemul_dotnet_value;

/** Arguments contain one typed value per parameter, preceded by the
 * receiver for instance methods. Explicitly handle the method or return
 * a failure status; unknown BCL/PInvoke calls never succeed implicitly. */
typedef xxemul_status (*xxemul_dotnet_external_callback)(void *context, xxemul_dotnet_vm *vm, const xxemul_dotnet_method_info *method,
                                                         const xxemul_dotnet_value *arguments, size_t argument_count, xxemul_dotnet_value *result);

/** Optional explicit intrinsic dispatch, including locally defined compatibility
 * methods. Set *handled to one only when this callback implements the method.
 * Unhandled calls execute their CIL or use external_callback normally. A handled
 * failure is never converted into success or retried as CIL. */
typedef xxemul_status (*xxemul_dotnet_intrinsic_callback)(void *context, xxemul_dotnet_vm *vm, const xxemul_dotnet_method_info *method,
    const xxemul_dotnet_value *arguments, size_t argument_count, xxemul_dotnet_value *result, int *handled);
/** Static MemberRef fields use an explicit host implementation. Unknown fields
 * fail; they never read as an implicit zero or accept an ignored write. */
typedef xxemul_status (*xxemul_dotnet_field_callback)(void *context, xxemul_dotnet_vm *vm,
    const xxemul_dotnet_field_info *field, int store, xxemul_dotnet_value *value, int *handled);

typedef void (*xxemul_dotnet_trace_callback)(void *context, const xxemul_dotnet_method_info *method, uint32_t pc, const char *mnemonic);

/** Positive means assignable, zero incompatible, negative unknown. Invoked
 * only when the loaded assembly's hierarchy cannot determine the answer. */
typedef int (*xxemul_dotnet_assignability_callback)(void *context, const char *source_type, const char *destination_type);

typedef struct xxemul_dotnet_vm_config {
    uint64_t max_instructions; /* Zero selects 100000 per invocation. */
    uint32_t max_call_depth;   /* Zero selects 128; values above 128 rejected. */
    size_t max_stack_values;   /* Zero selects 65536 reserved slots across frames. */
    size_t max_frame_bytes;    /* Zero selects 8 MiB of active frame storage. */
    size_t max_heap_bytes;     /* Zero selects 16 MiB; includes code boundary maps. */
    xxemul_dotnet_external_callback external_callback;
    void *external_context;
    xxemul_dotnet_trace_callback trace_callback;
    void *trace_context;
    xxemul_dotnet_assignability_callback assignability_callback;
    void *assignability_context;
    xxemul_dotnet_intrinsic_callback intrinsic_callback;
    void *intrinsic_context;
    xxemul_dotnet_field_callback field_callback;
    void *field_context;
    /** Optional borrowed remaining-instruction counter shared by a host's
     * assembly VMs. Initialize it before execution; VM APIs never reset it.
     * Each real CIL instruction decrements once. Access must be serialized. */
    uint64_t *shared_instruction_budget;
} xxemul_dotnet_vm_config;

typedef struct xxemul_dotnet_result {
    xxemul_status status;
    xxemul_dotnet_value value;
    uint64_t instructions;
    size_t method_index;
    uint32_t pc;
    char diagnostic[256];
} xxemul_dotnet_result;

XXEMUL_API xxemul_dotnet_vm *xxemul_dotnet_vm_create(const xxemul_dotnet_program *program, const xxemul_dotnet_vm_config *config, xxemul_status *status);
XXEMUL_API void xxemul_dotnet_vm_destroy(xxemul_dotnet_vm *vm);
/** Program must outlive VM. Objects/statics persist; each invoke receives a
 * fresh instruction budget. Reentrant invokes on the same VM are rejected. */
XXEMUL_API xxemul_status xxemul_dotnet_vm_invoke(xxemul_dotnet_vm *vm, size_t method_index, const xxemul_dotnet_value *arguments, size_t argument_count,
                                                 xxemul_dotnet_result *result);
/** Explicit host callback reentry, e.g. a registered AssemblyResolve delegate.
 * Shares the active VM's heap, statics, call-depth and root instruction budget.
 * result.instructions is the increment consumed by this nested call. A failed
 * call leaves its diagnostic/pending exception active for the host to propagate. */
XXEMUL_API xxemul_status xxemul_dotnet_vm_invoke_nested(xxemul_dotnet_vm *vm, size_t method_index,
    const xxemul_dotnet_value *arguments, size_t argument_count, xxemul_dotnet_result *result);

XXEMUL_API xxemul_status xxemul_dotnet_vm_new_object(xxemul_dotnet_vm *vm, const char *type_name, uint32_t *reference);
XXEMUL_API xxemul_status xxemul_dotnet_vm_new_string(xxemul_dotnet_vm *vm, const char *utf8, size_t byte_count, uint32_t *reference);
XXEMUL_API const char *xxemul_dotnet_vm_get_string(const xxemul_dotnet_vm *vm, uint32_t reference, size_t *byte_count);
XXEMUL_API const char *xxemul_dotnet_vm_object_type(const xxemul_dotnet_vm *vm, uint32_t reference);
/** Allocate a zero-initialized vector. Supports primitive CIL types and
 * object references; value types and multidimensional arrays are unsupported. */
XXEMUL_API xxemul_status xxemul_dotnet_vm_new_array(xxemul_dotnet_vm *vm, const char *element_type_name, size_t length, uint32_t *reference);
XXEMUL_API xxemul_status xxemul_dotnet_vm_array_set(xxemul_dotnet_vm *vm, uint32_t reference, size_t index, xxemul_dotnet_value value);
XXEMUL_API const xxemul_dotnet_program *xxemul_dotnet_vm_get_program(const xxemul_dotnet_vm *vm);
/** Borrowed immediate managed caller during a host callback; NULL at root. */
XXEMUL_API const xxemul_dotnet_method_info *xxemul_dotnet_vm_caller(const xxemul_dotnet_vm *vm);
XXEMUL_API xxemul_status xxemul_dotnet_vm_array_length(const xxemul_dotnet_vm *vm, uint32_t reference, size_t *length);
XXEMUL_API xxemul_status xxemul_dotnet_vm_array_get(const xxemul_dotnet_vm *vm, uint32_t reference, size_t index, xxemul_dotnet_value *value);
XXEMUL_API xxemul_status xxemul_dotnet_vm_box(xxemul_dotnet_vm *vm, const char *type_name, xxemul_dotnet_value value, uint32_t *reference);
XXEMUL_API xxemul_status xxemul_dotnet_vm_unbox(const xxemul_dotnet_vm *vm, uint32_t reference, xxemul_dotnet_value *value);
/** Raise a real managed exception during a running invocation. The returned
 * ADDRESS_FAULT is dispatched through CIL catch/finally regions. Other host
 * errors remain hard failures unless the host explicitly raises an exception. */
XXEMUL_API xxemul_status xxemul_dotnet_vm_raise(xxemul_dotnet_vm *vm, uint32_t exception_reference);
XXEMUL_API xxemul_status xxemul_dotnet_vm_raise_type(xxemul_dotnet_vm *vm, const char *type_name);
/** Pending exception handle after failed execution; zero after success/catch.
 * Objects remain valid until VM destruction; a new invoke clears pending state. */
XXEMUL_API uint32_t xxemul_dotnet_vm_exception(const xxemul_dotnet_vm *vm);
/** Charge already executed child instructions to the active parent's result
 * count/local limit. A shared budget was already decremented by the child and
 * is not decremented again here. Same-VM invoke_nested is already counted. */
XXEMUL_API uint64_t xxemul_dotnet_vm_instruction_count(const xxemul_dotnet_vm *vm);
XXEMUL_API xxemul_status xxemul_dotnet_vm_consume_instructions(xxemul_dotnet_vm *vm, uint64_t count);

#ifdef __cplusplus
}
#endif
#endif
