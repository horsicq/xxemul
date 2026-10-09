#ifndef XXEMUL_XXEMUL_DEX_H
#define XXEMUL_XXEMUL_DEX_H

#include "xxemul.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct xxemul_dex_program xxemul_dex_program;

typedef struct xxemul_dex_file_info {
    const char *name;
    uint32_t version;
    size_t file_size;
    uint32_t class_count;
    uint32_t string_count;
    uint32_t type_count;
    uint32_t method_count;
} xxemul_dex_file_info;

typedef struct xxemul_dex_method_info {
    size_t dex_index;
    uint32_t method_id;
    uint32_t access_flags;
    const char *class_descriptor;
    const char *name;
    const char *prototype;
    const char *selector; /* Lpackage/Class;->method(Arguments)Return */
    uint16_t registers_size;
    uint16_t ins_size;
    uint16_t outs_size;
    uint32_t code_units;
    int is_defined; /* Includes abstract/native definitions with no code. */
} xxemul_dex_method_info;

/* Inputs are borrowed only during creation. All DEX bytes and metadata are
 * owned by the resulting program. Standard little-endian DEX 035 and 037-040 are
 * supported; DEX containers and optimized ODEX are rejected explicitly. */
XXEMUL_API xxemul_dex_program *xxemul_dex_create_dex(
    const void *data, size_t size, xxemul_status *status);
XXEMUL_API xxemul_dex_program *xxemul_dex_create_apk(
    const void *data, size_t size, xxemul_status *status);
XXEMUL_API xxemul_dex_program *xxemul_dex_create_file(
    const char *path, xxemul_status *status);
XXEMUL_API void xxemul_dex_destroy(xxemul_dex_program *program);
XXEMUL_API size_t xxemul_dex_dex_count(const xxemul_dex_program *program);
XXEMUL_API const xxemul_dex_file_info *xxemul_dex_dex_info(
    const xxemul_dex_program *program, size_t index);
/* Includes both definitions and external method references from each DEX. */
XXEMUL_API size_t xxemul_dex_method_count(const xxemul_dex_program *program);
XXEMUL_API const xxemul_dex_method_info *xxemul_dex_method_info_at(
    const xxemul_dex_program *program, size_t index);
/* Returns SIZE_MAX if absent. With duplicate references, a definition with
 * code is preferred. Selectors use the full, unambiguous spelling above. */
XXEMUL_API size_t xxemul_dex_find_method(
    const xxemul_dex_program *program, const char *selector);
XXEMUL_API int xxemul_dex_is_apk(const xxemul_dex_program *program);
/* Borrowed decoded AndroidManifest.xml text, or NULL for a standalone DEX
 * or a manifest whose binary XML cannot be decoded. */
XXEMUL_API const char *xxemul_dex_manifest(const xxemul_dex_program *program);
XXEMUL_API const char *xxemul_dex_package_name(const xxemul_dex_program *program);
/* First activity with a MAIN/LAUNCHER intent filter. Relative activity names
 * are expanded against the package. An activity-alias resolves to its target. */
XXEMUL_API const char *xxemul_dex_launcher_activity(const xxemul_dex_program *program);
/* Decode one instruction. Byte offsets are relative to the method's code.
 * instruction_size is set to zero on failure. */
XXEMUL_API xxemul_status xxemul_dex_disassemble(
    const xxemul_dex_program *program, size_t method_index,
    uint32_t byte_offset, char *text, size_t text_size,
    uint32_t *instruction_size);

#ifdef __cplusplus
}
#endif
#endif
