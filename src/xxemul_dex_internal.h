#ifndef XXEMUL_DEX_INTERNAL_H
#define XXEMUL_DEX_INTERNAL_H

#include "xxemul/xxemul_dex.h"
#include <xxfclib/formats/dex/xx_dex.h>

typedef struct xxemul_dex_file {
    xxemul_dex_file_info info;
    uint8_t *data;
    size_t size;
    char *name;
    uint32_t version;
    xx_dex_header header;
    char **strings;
    char **types; /* Borrowed pointers into strings. */
    char **prototypes;
    size_t *method_map; /* DEX method_id -> program method index. */
} xxemul_dex_file;

typedef struct xxemul_dex_method {
    xxemul_dex_method_info info;
    uint32_t code_offset;
    const uint8_t *code; /* First instruction byte, not code_item header. */
} xxemul_dex_method;

struct xxemul_dex_program {
    xxemul_dex_file *dex_files;
    size_t dex_count;
    xxemul_dex_method *methods;
    size_t method_count;
    int is_apk;
    char *manifest;
    char *package_name;
    char *launcher_activity;
};

/* Internal append copies input bytes; on failure the program remains safe
 * to destroy (partially appended metadata must not be used). */
xxemul_status xxemul_dex_append(xxemul_dex_program *program,
    const void *data, size_t size, const char *name);

static inline uint16_t xxemul_dex_u16(const uint8_t *p) {
    return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}
static inline uint32_t xxemul_dex_u32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
        ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

#endif
