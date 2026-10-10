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

XXEMUL_API xxemul_status xxemul_dotnet_vm_new_object(xxemul_dotnet_vm *vm, const char *type_name, uint32_t *reference);
XXEMUL_API xxemul_status xxemul_dotnet_vm_new_string(xxemul_dotnet_vm *vm, const char *utf8, size_t byte_count, uint32_t *reference);
XXEMUL_API const char *xxemul_dotnet_vm_get_string(const xxemul_dotnet_vm *vm, uint32_t reference, size_t *byte_count);
XXEMUL_API const char *xxemul_dotnet_vm_object_type(const xxemul_dotnet_vm *vm, uint32_t reference);
/** Allocate a zero-initialized vector. Supports primitive CIL types and
 * object references; value types and multidimensional arrays are unsupported. */
XXEMUL_API xxemul_status xxemul_dotnet_vm_new_array(xxemul_dotnet_vm *vm, const char *element_type_name, size_t length, uint32_t *reference);
XXEMUL_API xxemul_status xxemul_dotnet_vm_array_set(xxemul_dotnet_vm *vm, uint32_t reference, size_t index, xxemul_dotnet_value value);

#ifdef __cplusplus
}
#endif
#endif
