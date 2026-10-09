#ifndef XXEMUL_XXEMUL_DOTNET_H
#define XXEMUL_XXEMUL_DOTNET_H

#include "xxemul.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct xxemul_dotnet_program xxemul_dotnet_program;

typedef struct xxemul_dotnet_method_info {
    uint32_t token, flags, impl_flags, rva, code_size;
    uint16_t max_stack;
    int is_defined, has_this, init_locals, has_exception_handlers, is_executable;
    const char *type_name;
    const char *name;
    const char *signature; /* (System.Int32,System.String)System.Void */
    const char *selector;  /* Namespace.Type::Method(Arguments)Return */
} xxemul_dotnet_method_info;

/* The program owns a bounded copy of the PE and all exposed metadata. No CLR
 * or native entry point is invoked. Malformed mappings/heaps/signatures fail
 * creation; valid unsupported signatures remain available for inspection. */
XXEMUL_API xxemul_dotnet_program *xxemul_dotnet_create(
    const void *data, size_t size, xxemul_status *status);
XXEMUL_API xxemul_dotnet_program *xxemul_dotnet_create_file(
    const char *path, xxemul_status *status);
XXEMUL_API void xxemul_dotnet_destroy(xxemul_dotnet_program *program);
/* Borrowed strings and method information remain valid until destruction. */
XXEMUL_API const char *xxemul_dotnet_assembly_name(const xxemul_dotnet_program *program);
XXEMUL_API uint32_t xxemul_dotnet_entry_point_token(const xxemul_dotnet_program *program);
XXEMUL_API size_t xxemul_dotnet_entry_point(const xxemul_dotnet_program *program);
XXEMUL_API size_t xxemul_dotnet_method_count(const xxemul_dotnet_program *program);
XXEMUL_API const xxemul_dotnet_method_info *xxemul_dotnet_method_info_at(
    const xxemul_dotnet_program *program, size_t index);
XXEMUL_API size_t xxemul_dotnet_find_method(const xxemul_dotnet_program *program, const char *selector);
/* MethodDef and method-shaped MemberRef tokens. Local definitions are
 * preferred for references with the same complete selector. SIZE_MAX misses. */
XXEMUL_API size_t xxemul_dotnet_resolve_token(const xxemul_dotnet_program *program, uint32_t token);
XXEMUL_API const char *xxemul_dotnet_type_name(const xxemul_dotnet_program *program, uint32_t token);
/* #US token 0x70xxxxxx. UTF-8 bytes may contain embedded NULs; unpaired UTF-16
 * surrogates are preserved with the UTF-8 surrogate extension. Size excludes
 * the extra terminating NUL. NULL means an invalid token. Decoding happens
 * during creation, so getters never allocate. */
XXEMUL_API const char *xxemul_dotnet_user_string(const xxemul_dotnet_program *program,
    uint32_t token, size_t *size);
XXEMUL_API xxemul_status xxemul_dotnet_disassemble(const xxemul_dotnet_program *program,
    size_t method_index, uint32_t byte_offset, char *text, size_t text_size,
    uint32_t *instruction_size);

#ifdef __cplusplus
}
#endif
#endif
