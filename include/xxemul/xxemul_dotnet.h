#ifndef XXEMUL_XXEMUL_DOTNET_H
#define XXEMUL_XXEMUL_DOTNET_H

#include "xxemul.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct xxemul_dotnet_program xxemul_dotnet_program;

/* All offsets are relative to the first CIL instruction. Metadata is validated
 * during program creation; execution policy (including filter support) belongs
 * to the VM. flags: 0 catch, 1 filter, 2 finally, 4 fault. */
typedef struct xxemul_dotnet_exception_clause {
    uint32_t flags, try_offset, try_length, handler_offset, handler_length;
    uint32_t class_token_or_filter_offset;
} xxemul_dotnet_exception_clause;

typedef struct xxemul_dotnet_resource_info {
    uint32_t token, flags, implementation;
    const char *name;
    /* Borrowed embedded bytes, excluding the four-byte resource length.
     * Linked resources have nonzero implementation and NULL data/zero size. */
    const uint8_t *data;
    size_t size;
} xxemul_dotnet_resource_info;

typedef struct xxemul_dotnet_assembly_info {
    uint32_t token, flags, hash_algorithm;
    uint16_t major, minor, build, revision;
    const char *name, *culture;
    /* Assembly public key or AssemblyRef key/token, as encoded by flags. */
    const uint8_t *public_key_or_token;
    size_t public_key_size;
} xxemul_dotnet_assembly_info;

typedef struct xxemul_dotnet_field_info {
    uint32_t token, owner_token, flags;
    int is_defined;
    const char *type_name, *name, *signature, *assembly_name;
} xxemul_dotnet_field_info;

typedef struct xxemul_dotnet_method_info {
    uint32_t token, flags, impl_flags, rva, code_size;
    uint16_t max_stack;
    int is_defined, has_this, init_locals, has_exception_handlers, is_executable;
    const char *type_name;
    const char *name;
    const char *signature; /* (System.Int32,System.String)System.Void */
    const char *selector;  /* Namespace.Type::Method(Arguments)Return */
    /* Defining assembly for MethodDefs, resolution-scope assembly for
     * MemberRefs. NULL when a module/unsupported scope has no assembly. */
    const char *assembly_name;
} xxemul_dotnet_method_info;

/* The program owns a bounded copy of the PE and all exposed metadata. No CLR
 * or native entry point is invoked. Malformed mappings/heaps/signatures fail
 * creation; valid unsupported signatures remain available for inspection. */
XXEMUL_API xxemul_dotnet_program *xxemul_dotnet_create(const void *data, size_t size, xxemul_status *status);
XXEMUL_API xxemul_dotnet_program *xxemul_dotnet_create_file(const char *path, xxemul_status *status);
XXEMUL_API void xxemul_dotnet_destroy(xxemul_dotnet_program *program);
/* Borrowed strings and method information remain valid until destruction. */
XXEMUL_API const char *xxemul_dotnet_assembly_name(const xxemul_dotnet_program *program);
XXEMUL_API const char *xxemul_dotnet_module_name(const xxemul_dotnet_program *program);
/* NULL identity denotes a valid netmodule with no Assembly row. All returned
 * metadata/data pointers are borrowed until program destruction. */
XXEMUL_API const xxemul_dotnet_assembly_info *xxemul_dotnet_assembly_identity(const xxemul_dotnet_program *program);
XXEMUL_API size_t xxemul_dotnet_assembly_ref_count(const xxemul_dotnet_program *program);
XXEMUL_API const xxemul_dotnet_assembly_info *xxemul_dotnet_assembly_ref_at(const xxemul_dotnet_program *program, size_t index);
XXEMUL_API const uint8_t *xxemul_dotnet_data(const xxemul_dotnet_program *program, size_t *size);
XXEMUL_API size_t xxemul_dotnet_resource_count(const xxemul_dotnet_program *program);
XXEMUL_API const xxemul_dotnet_resource_info *xxemul_dotnet_resource_at(const xxemul_dotnet_program *program, size_t index);
XXEMUL_API const xxemul_dotnet_resource_info *xxemul_dotnet_resource_find(const xxemul_dotnet_program *program, const char *name);
/* Exact raw initializer extent for primitive or explicitly sized ClassLayout
 * FieldRVA data. NULL denotes absent/unsupported layout or invalid token. */
XXEMUL_API const uint8_t *xxemul_dotnet_field_data(const xxemul_dotnet_program *program, uint32_t field_token, size_t *size);
/* FieldDef or field-shaped MemberRef. signature is the field's complete type
 * name. MemberRef has no declaration flags; is_defined distinguishes it. */
XXEMUL_API const xxemul_dotnet_field_info *xxemul_dotnet_field_info_token(const xxemul_dotnet_program *program, uint32_t field_token);
XXEMUL_API uint32_t xxemul_dotnet_entry_point_token(const xxemul_dotnet_program *program);
XXEMUL_API size_t xxemul_dotnet_entry_point(const xxemul_dotnet_program *program);
XXEMUL_API size_t xxemul_dotnet_method_count(const xxemul_dotnet_program *program);
XXEMUL_API const xxemul_dotnet_method_info *xxemul_dotnet_method_info_at(const xxemul_dotnet_program *program, size_t index);
XXEMUL_API size_t xxemul_dotnet_exception_clause_count(const xxemul_dotnet_program *program, size_t method_index);
XXEMUL_API const xxemul_dotnet_exception_clause *xxemul_dotnet_exception_clause_at(const xxemul_dotnet_program *program, size_t method_index, size_t index);
XXEMUL_API size_t xxemul_dotnet_find_method(const xxemul_dotnet_program *program, const char *selector);
/* MethodDef and method-shaped MemberRef tokens. Local definitions are
 * preferred for references with the same complete selector. SIZE_MAX misses. */
XXEMUL_API size_t xxemul_dotnet_resolve_token(const xxemul_dotnet_program *program, uint32_t token);
XXEMUL_API const char *xxemul_dotnet_type_name(const xxemul_dotnet_program *program, uint32_t token);
/* #US token 0x70xxxxxx. UTF-8 bytes may contain embedded NULs; unpaired UTF-16
 * surrogates are preserved with the UTF-8 surrogate extension. Size excludes
 * the extra terminating NUL. NULL means an invalid token. Decoding happens
 * during creation, so getters never allocate. */
XXEMUL_API const char *xxemul_dotnet_user_string(const xxemul_dotnet_program *program, uint32_t token, size_t *size);
XXEMUL_API xxemul_status xxemul_dotnet_disassemble(const xxemul_dotnet_program *program, size_t method_index, uint32_t byte_offset, char *text, size_t text_size,
                                                   uint32_t *instruction_size);

#ifdef __cplusplus
}
#endif
#endif
