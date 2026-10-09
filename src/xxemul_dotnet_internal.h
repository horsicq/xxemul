#ifndef XXEMUL_DOTNET_INTERNAL_H
#define XXEMUL_DOTNET_INTERNAL_H

#include "xxemul/xxemul_dotnet.h"

/* element_type uses the ECMA-335 ELEMENT_TYPE_* byte values. */
typedef struct xxemul_dotnet_type {
    uint8_t element_type, array_element_type;
    uint32_t token;
    char *name;
    int supported;
} xxemul_dotnet_type;

typedef struct xxemul_dotnet_signature {
    xxemul_dotnet_type return_type;
    xxemul_dotnet_type *parameters;
    size_t parameter_count;
    int has_this, explicit_this, generic, vararg, supported;
} xxemul_dotnet_signature;

typedef struct xxemul_dotnet_method {
    xxemul_dotnet_method_info info;
    const uint8_t *code;
    xxemul_dotnet_signature signature;
    xxemul_dotnet_type *locals;
    size_t local_count;
    uint32_t owner_token;
    int local_reference;
} xxemul_dotnet_method;

typedef struct xxemul_dotnet_class {
    uint32_t token, flags, extends_token;
    uint32_t resolution_scope;
    int is_generic, has_method_impl;
    char *name;
    uint32_t field_begin, field_end, method_begin, method_end; /* 1-based RIDs */
} xxemul_dotnet_class;

typedef struct xxemul_dotnet_field {
    uint32_t token, owner_token, flags;
    char *name;
    xxemul_dotnet_type type;
} xxemul_dotnet_field;

typedef struct xxemul_dotnet_string {
    uint32_t offset;
    char *text;
    size_t size;
} xxemul_dotnet_string;

struct xxemul_dotnet_program {
    uint8_t *data;
    size_t size;
    unsigned pointer_size;
    char *assembly_name;
    uint32_t entry_point_token;
    xxemul_dotnet_method *methods;
    size_t method_count, method_def_count;
    size_t *memberref_map;
    size_t memberref_count;
    xxemul_dotnet_class *types; /* TypeDef rows, followed by TypeRef rows. */
    size_t type_count, type_def_count;
    size_t type_ref_count, type_spec_count;
    xxemul_dotnet_field *fields;
    size_t field_count;
    xxemul_dotnet_string *user_strings;
    size_t user_string_count;
};

static inline uint16_t xxemul_dotnet_u16(const uint8_t *p) {
    return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}
static inline uint32_t xxemul_dotnet_u32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
#endif
