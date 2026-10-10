/* Copyright (c) 2026 hors<horsicq@gmail.com>
 * SPDX-License-Identifier: MIT */
#include "xxemul_dex_internal.h"
#include "xxemul/xxemul_dex_runtime.h"
#include <xxbyte/xxbyte_dex.h>

#include <limits.h>
#include <math.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DEX_ACC_STATIC 8u
#define DEX_NO_INDEX UINT32_MAX

typedef struct dex_field {
    const char *owner, *name, *type;
    size_t canonical;
    uint64_t value;
    uint32_t flags;
    unsigned declared : 1;
    unsigned unsupported_initial : 1;
} dex_field;

typedef struct dex_class {
    const char *descriptor, *superclass;
    size_t dex_index;
    const uint8_t *interfaces;
    uint32_t interface_count, visit;
    unsigned initialized, hierarchy_state;
} dex_class;

typedef struct dex_property {
    size_t field;
    uint64_t value;
    struct dex_property *next;
} dex_property;

typedef struct dex_object {
    char *descriptor;
    const char *string;
    uint64_t *elements;
    size_t length;
    unsigned kind; /* 0 instance, 1 array, 2 string, 3 class */
    dex_property *properties;
} dex_object;

typedef struct dex_code_cache {
    uint8_t *boundaries; /* 1 instruction, 2 payload, indexed in code units */
    xxemul_status status;
} dex_code_cache;

struct xxemul_dex_vm {
    const xxemul_dex_program *program;
    xxemul_dex_vm_config config;
    dex_object **objects;
    size_t object_count, object_capacity, heap_bytes;
    size_t *field_bases;
    dex_field *fields;
    size_t field_count;
    dex_class *classes;
    dex_class **type_worklist;
    size_t class_count;
    uint32_t type_visit;
    dex_code_cache *code_cache;
    xxemul_dex_result *result;
    xxemul_status allocation_status;
    uint32_t depth;
    uint32_t initialization_depth;
    unsigned running;
};

static int32_t signed32(uint32_t bits)
{
    int32_t value;
    memcpy(&value, &bits, sizeof(value));
    return value;
}

static int64_t signed64(uint64_t bits)
{
    int64_t value;
    memcpy(&value, &bits, sizeof(value));
    return value;
}

static uint64_t wide_read(const uint32_t *registers, uint32_t reg)
{
    return (uint64_t)registers[reg] | ((uint64_t)registers[reg + 1] << 32);
}

static void wide_write(uint32_t *registers, uint32_t reg, uint64_t value)
{
    registers[reg] = (uint32_t)value;
    registers[reg + 1] = (uint32_t)(value >> 32);
}

static xxemul_status vm_fail(xxemul_dex_vm *vm, xxemul_status status, const char *format, ...)
{
    if (vm->result && vm->result->status == XXEMUL_STATUS_OK) {
        va_list arguments;
        vm->result->status = status;
        va_start(arguments, format);
        (void)vsnprintf(vm->result->diagnostic, sizeof(vm->result->diagnostic), format, arguments);
        va_end(arguments);
    }
    return status;
}

static void *heap_alloc(xxemul_dex_vm *vm, size_t size)
{
    void *memory;
    if (size > vm->config.max_heap_bytes - vm->heap_bytes) {
        vm->allocation_status = XXEMUL_STATUS_LIMIT_REACHED;
        return NULL;
    }
    memory = calloc(size ? size : 1, 1);
    if (!memory) {
        vm->allocation_status = XXEMUL_STATUS_OUT_OF_MEMORY;
        return NULL;
    }
    vm->heap_bytes += size;
    return memory;
}

static dex_object *get_object(const xxemul_dex_vm *vm, uint32_t reference)
{
    return reference && reference <= vm->object_count ? vm->objects[reference - 1] : NULL;
}

static xxemul_status allocate_object(xxemul_dex_vm *vm, const char *descriptor, unsigned kind, size_t length, uint32_t *reference)
{
    dex_object *object;
    size_t descriptor_size;
    if (!descriptor || !*descriptor || !reference) return XXEMUL_STATUS_INVALID_ARGUMENT;
    if (vm->object_count >= UINT32_MAX) return XXEMUL_STATUS_LIMIT_REACHED;
    if (vm->object_count == vm->object_capacity) {
        size_t capacity = vm->object_capacity ? vm->object_capacity * 2 : 32;
        size_t extra;
        dex_object **objects;
        if (capacity < vm->object_capacity || capacity > SIZE_MAX / sizeof(*objects)) return XXEMUL_STATUS_LIMIT_REACHED;
        extra = (capacity - vm->object_capacity) * sizeof(*objects);
        if (extra > vm->config.max_heap_bytes - vm->heap_bytes) return XXEMUL_STATUS_LIMIT_REACHED;
        objects = (dex_object **)realloc(vm->objects, capacity * sizeof(*objects));
        if (!objects) return XXEMUL_STATUS_OUT_OF_MEMORY;
        vm->objects = objects;
        vm->object_capacity = capacity;
        vm->heap_bytes += extra;
    }
    descriptor_size = strlen(descriptor) + 1;
    if (length > SIZE_MAX / sizeof(uint64_t)) return XXEMUL_STATUS_LIMIT_REACHED;
    object = (dex_object *)heap_alloc(vm, sizeof(*object));
    if (!object) return vm->allocation_status;
    object->descriptor = (char *)heap_alloc(vm, descriptor_size);
    if (!object->descriptor) {
        free(object);
        vm->heap_bytes -= sizeof(*object);
        return vm->allocation_status;
    }
    memcpy(object->descriptor, descriptor, descriptor_size);
    if (length) {
        object->elements = (uint64_t *)heap_alloc(vm, length * sizeof(uint64_t));
        if (!object->elements) {
            free(object->descriptor);
            free(object);
            vm->heap_bytes -= descriptor_size + sizeof(*object);
            return vm->allocation_status;
        }
    }
    object->kind = kind;
    object->length = length;
    vm->objects[vm->object_count++] = object;
    *reference = (uint32_t)vm->object_count;
    return XXEMUL_STATUS_OK;
}

xxemul_status xxemul_dex_vm_new_object(xxemul_dex_vm *vm, const char *class_descriptor, uint32_t *reference)
{
    if (!vm || !class_descriptor || class_descriptor[0] != 'L' || class_descriptor[strlen(class_descriptor) - 1] != ';' || !reference)
        return XXEMUL_STATUS_INVALID_ARGUMENT;
    return allocate_object(vm, class_descriptor, 0, 0, reference);
}

const char *xxemul_dex_vm_get_string(const xxemul_dex_vm *vm, uint32_t reference)
{
    dex_object *object = vm ? get_object(vm, reference) : NULL;
    return object && object->kind == 2 ? object->string : NULL;
}

const char *xxemul_dex_vm_object_type(const xxemul_dex_vm *vm, uint32_t reference)
{
    dex_object *object = vm ? get_object(vm, reference) : NULL;
    return object ? object->descriptor : NULL;
}

xxemul_status xxemul_dex_vm_new_byte_array(xxemul_dex_vm *vm, const uint8_t *data, size_t size, uint32_t *reference)
{
    xxemul_status status;
    size_t i;
    if (reference) *reference = 0;
    if (!vm || !reference || (size && !data)) return XXEMUL_STATUS_INVALID_ARGUMENT;
    /* Dalvik array lengths are signed 32-bit integers. */
    if (size > INT32_MAX || size > SIZE_MAX / sizeof(uint64_t)) return XXEMUL_STATUS_LIMIT_REACHED;
    status = allocate_object(vm, "[B", 1, size, reference);
    if (status != XXEMUL_STATUS_OK) return status;
    for (i = 0; i < size; ++i) vm->objects[*reference - 1]->elements[i] = data[i];
    return XXEMUL_STATUS_OK;
}

static xxemul_status get_byte_array(const xxemul_dex_vm *vm, uint32_t reference, dex_object **array)
{
    dex_object *object;
    if (!vm) return XXEMUL_STATUS_INVALID_ARGUMENT;
    object = get_object(vm, reference);
    if (!object) return XXEMUL_STATUS_ADDRESS_FAULT;
    if (object->kind != 1 || strcmp(object->descriptor, "[B")) return XXEMUL_STATUS_INVALID_ARGUMENT;
    *array = object;
    return XXEMUL_STATUS_OK;
}

xxemul_status xxemul_dex_vm_byte_array_length(const xxemul_dex_vm *vm, uint32_t reference, size_t *length)
{
    dex_object *array;
    xxemul_status status;
    if (!length) return XXEMUL_STATUS_INVALID_ARGUMENT;
    *length = 0;
    status = get_byte_array(vm, reference, &array);
    if (status == XXEMUL_STATUS_OK) *length = array->length;
    return status;
}

xxemul_status xxemul_dex_vm_read_byte_array(const xxemul_dex_vm *vm, uint32_t reference, size_t offset, uint8_t *data, size_t size)
{
    dex_object *array;
    xxemul_status status;
    size_t i;
    if (size && !data) return XXEMUL_STATUS_INVALID_ARGUMENT;
    status = get_byte_array(vm, reference, &array);
    if (status != XXEMUL_STATUS_OK) return status;
    if (offset > array->length || size > array->length - offset) return XXEMUL_STATUS_ADDRESS_FAULT;
    for (i = 0; i < size; ++i) data[i] = (uint8_t)array->elements[offset + i];
    return XXEMUL_STATUS_OK;
}

xxemul_status xxemul_dex_vm_write_byte_array(xxemul_dex_vm *vm, uint32_t reference, size_t offset, const uint8_t *data, size_t size)
{
    dex_object *array;
    xxemul_status status;
    size_t i;
    if (size && !data) return XXEMUL_STATUS_INVALID_ARGUMENT;
    status = get_byte_array(vm, reference, &array);
    if (status != XXEMUL_STATUS_OK) return status;
    if (offset > array->length || size > array->length - offset) return XXEMUL_STATUS_ADDRESS_FAULT;
    for (i = 0; i < size; ++i) array->elements[offset + i] = data[i];
    return XXEMUL_STATUS_OK;
}

static xxemul_status intern_string(xxemul_dex_vm *vm, const char *string, uint32_t *reference)
{
    size_t i;
    xxemul_status status;
    for (i = 0; i < vm->object_count; ++i) {
        dex_object *object = vm->objects[i];
        if (object->kind == 2 && !strcmp(object->string, string)) {
            *reference = (uint32_t)(i + 1);
            return XXEMUL_STATUS_OK;
        }
    }
    status = allocate_object(vm, "Ljava/lang/String;", 2, 0, reference);
    if (status == XXEMUL_STATUS_OK) vm->objects[*reference - 1]->string = string;
    return status;
}

static int read_uleb(const xxemul_dex_file *file, size_t *offset, uint32_t *value)
{
    unsigned i;
    *value = 0;
    for (i = 0; i < 5; ++i) {
        uint8_t byte;
        if (*offset >= file->size) return 0;
        byte = file->data[(*offset)++];
        if (i == 4 && (byte & 0xf0u)) return 0;
        *value |= (uint32_t)(byte & 0x7fu) << (i * 7);
        if (!(byte & 0x80u)) return 1;
    }
    return 0;
}

static dex_class *find_class(xxemul_dex_vm *vm, const char *descriptor)
{
    size_t i;
    for (i = 0; i < vm->class_count; ++i)
        if (!strcmp(vm->classes[i].descriptor, descriptor)) return &vm->classes[i];
    return NULL;
}

static int external_relationship(xxemul_dex_vm *vm, const char *source, const char *destination)
{
    if (!strcmp(source, "Ljava/lang/Object;")) return 0;
    if (vm->config.assignability_callback) {
        int answer = vm->config.assignability_callback(vm->config.assignability_context, source, destination);
        if (answer >= 0) return answer > 0 ? 1 : 0;
    }
    /* Bootstrap/platform classes cannot inherit an application-defined
     * class; its own ancestors are available in this program. */
    return find_class(vm, destination) ? 0 : -1;
}

static int is_assignable(xxemul_dex_vm *vm, const char *source, const char *destination)
{
    size_t read_index = 0, write_index = 0;
    int unknown = 0;
    dex_class *class_info;
    if (!source || !destination) return 0;
    /* Java arrays are covariant only for reference element types. */
    while (*source == '[' && *destination == '[') {
        ++source;
        ++destination;
        if (!strcmp(source, destination)) return 1;
        if ((*source != '[' && *source != 'L') || (*destination != '[' && *destination != 'L')) return 0;
    }
    if (!strcmp(source, destination)) return 1;
    if (!strcmp(destination, "Ljava/lang/Object;")) return 1;
    if (*source == '[') return !strcmp(destination, "Ljava/lang/Cloneable;") || !strcmp(destination, "Ljava/io/Serializable;");
    if (++vm->type_visit == 0) {
        size_t i;
        for (i = 0; i < vm->class_count; ++i) vm->classes[i].visit = 0;
        ++vm->type_visit;
    }
    class_info = find_class(vm, source);
    if (class_info) {
        class_info->visit = vm->type_visit;
        vm->type_worklist[write_index++] = class_info;
    } else return external_relationship(vm, source, destination);
    while (read_index < write_index) {
        uint32_t i;
        const xxemul_dex_file *file;
        class_info = vm->type_worklist[read_index++];
        file = &vm->program->dex_files[class_info->dex_index];
        for (i = 0; i <= class_info->interface_count; ++i) {
            const char *ancestor = i == class_info->interface_count ? class_info->superclass : file->types[xxemul_dex_u16(class_info->interfaces + (size_t)i * 2)];
            dex_class *parent;
            if (!ancestor) continue;
            if (!strcmp(ancestor, destination)) return 1;
            parent = find_class(vm, ancestor);
            if (parent && parent->visit != vm->type_visit) {
                parent->visit = vm->type_visit;
                vm->type_worklist[write_index++] = parent;
            } else if (!parent) {
                int answer = external_relationship(vm, ancestor, destination);
                if (answer > 0) return 1;
                if (answer < 0) unknown = 1;
            }
        }
    }
    return unknown ? -1 : 0;
}

static int valid_reference_descriptor(const char *descriptor)
{
    const char *p;
    unsigned dimensions = 0;
    if (!descriptor || (*descriptor != '[' && *descriptor != 'L')) return 0;
    p = descriptor;
    while (*p == '[') {
        if (++dimensions > 255) return 0;
        ++p;
    }
    if (*p != 'L') return dimensions && *p && strchr("ZBSCIJFD", *p) && !p[1];
    ++p;
    if (!*p || *p == '/' || *p == ';') return 0;
    for (; *p && *p != ';'; ++p) {
        unsigned char c = (unsigned char)*p;
        if (c <= 0x20 || c == '.' || c == '[' || c == '(' || c == ')' || (c == '/' && (!p[1] || p[1] == '/' || p[1] == ';'))) return 0;
    }
    return *p == ';' && !p[1];
}

xxemul_status xxemul_dex_vm_is_instance(xxemul_dex_vm *vm, uint32_t reference, const char *descriptor, int *matches)
{
    dex_object *object;
    int answer;
    if (matches) *matches = 0;
    if (!vm || !matches || !valid_reference_descriptor(descriptor)) return XXEMUL_STATUS_INVALID_ARGUMENT;
    if (!reference) return XXEMUL_STATUS_OK;
    object = get_object(vm, reference);
    if (!object) return XXEMUL_STATUS_ADDRESS_FAULT;
    answer = is_assignable(vm, object->descriptor, descriptor);
    if (answer < 0) return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    *matches = answer;
    return XXEMUL_STATUS_OK;
}

static xxemul_status require_assignable(xxemul_dex_vm *vm, const char *source, const char *destination, const char *operation)
{
    int answer = is_assignable(vm, source, destination);
    if (answer > 0) return XXEMUL_STATUS_OK;
    if (answer < 0) return vm_fail(vm, XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION, "unknown external type relationship: %s -> %s (%s)", source, destination, operation);
    return vm_fail(vm, XXEMUL_STATUS_ADDRESS_FAULT, "%s type mismatch: %s -> %s", operation, source, destination);
}

static xxemul_status parse_static_value(xxemul_dex_vm *vm, const xxemul_dex_file *file, size_t *offset, uint64_t *value, unsigned *unsupported, unsigned depth)
{
    uint8_t header, type, argument;
    uint64_t bits = 0;
    unsigned i, count;
    if (*offset >= file->size || depth > 64) return XXEMUL_STATUS_INVALID_IMAGE;
    header = file->data[(*offset)++];
    type = header & 0x1fu;
    argument = header >> 5;
    *unsupported = 0;
    *value = 0;
    if (type == 0x1e) return argument ? XXEMUL_STATUS_INVALID_IMAGE : XXEMUL_STATUS_OK;
    if (type == 0x1f) {
        if (argument > 1) return XXEMUL_STATUS_INVALID_IMAGE;
        *value = argument;
        return XXEMUL_STATUS_OK;
    }
    if (type == 0x1c || type == 0x1d) {
        uint32_t entries, ignored;
        if (argument || (type == 0x1d && !read_uleb(file, offset, &ignored)) || !read_uleb(file, offset, &entries)) return XXEMUL_STATUS_INVALID_IMAGE;
        for (i = 0; i < entries; ++i) {
            unsigned nested;
            xxemul_status status;
            if (type == 0x1d && !read_uleb(file, offset, &ignored)) return XXEMUL_STATUS_INVALID_IMAGE;
            status = parse_static_value(vm, file, offset, value, &nested, depth + 1);
            if (status != XXEMUL_STATUS_OK) return status;
        }
        *unsupported = 1;
        return XXEMUL_STATUS_OK;
    }
    count = (unsigned)argument + 1;
    if (!count || count > 8) return XXEMUL_STATUS_INVALID_IMAGE;
    if (count > file->size - *offset) return XXEMUL_STATUS_INVALID_IMAGE;
    for (i = 0; i < count; ++i) bits |= (uint64_t)file->data[(*offset)++] << (i * 8);
    switch (type) {
        case 0x00:
            if (argument) return XXEMUL_STATUS_INVALID_IMAGE; /* byte */
            *value = (uint64_t)(int64_t)(int8_t)bits;
            break;
        case 0x02:
        case 0x04:
        case 0x06: /* short, int, long */
            if (count > (type == 0x02 ? 2u : type == 0x04 ? 4u : 8u)) return XXEMUL_STATUS_INVALID_IMAGE;
            if (count < 8 && (bits & (UINT64_C(1) << (count * 8 - 1)))) bits |= UINT64_MAX << (count * 8);
            *value = bits;
            break;
        case 0x03:
            if (count > 2) return XXEMUL_STATUS_INVALID_IMAGE;
            *value = bits;
            break;
        case 0x10:
            if (count > 4) return XXEMUL_STATUS_INVALID_IMAGE;
            *value = bits << ((4 - count) * 8);
            break;
        case 0x11: *value = bits << ((8 - count) * 8); break;
        case 0x17: {
            uint32_t reference;
            xxemul_status status;
            if (count > 4 || bits >= file->header.string_ids_size) return XXEMUL_STATUS_INVALID_IMAGE;
            status = intern_string(vm, file->strings[(uint32_t)bits], &reference);
            if (status != XXEMUL_STATUS_OK) return status;
            *value = reference;
            break;
        }
        case 0x15:
        case 0x16:
        case 0x18:
        case 0x19:
        case 0x1a:
        case 0x1b:
            if (count > 4) return XXEMUL_STATUS_INVALID_IMAGE;
            *unsupported = 1;
            break;
        default: return XXEMUL_STATUS_INVALID_IMAGE;
    }
    return XXEMUL_STATUS_OK;
}

static xxemul_status prepare_metadata(xxemul_dex_vm *vm)
{
    size_t dex_index, field_index = 0, class_index = 0;
    const xxemul_dex_program *program = vm->program;
    vm->field_bases = (size_t *)calloc(program->dex_count + 1, sizeof(size_t));
    vm->code_cache = (dex_code_cache *)calloc(program->method_count ? program->method_count : 1, sizeof(dex_code_cache));
    if (!vm->field_bases || !vm->code_cache) return XXEMUL_STATUS_OUT_OF_MEMORY;
    for (dex_index = 0; dex_index < program->dex_count; ++dex_index) {
        const xxemul_dex_file *file = &program->dex_files[dex_index];
        vm->field_bases[dex_index] = vm->field_count;
        if (file->header.field_ids_size > SIZE_MAX - vm->field_count || file->header.class_defs_size > SIZE_MAX - vm->class_count) return XXEMUL_STATUS_INVALID_IMAGE;
        vm->field_count += file->header.field_ids_size;
        vm->class_count += file->header.class_defs_size;
    }
    vm->field_bases[program->dex_count] = vm->field_count;
    vm->fields = (dex_field *)calloc(vm->field_count ? vm->field_count : 1, sizeof(dex_field));
    vm->classes = (dex_class *)calloc(vm->class_count ? vm->class_count : 1, sizeof(dex_class));
    vm->type_worklist = (dex_class **)calloc(vm->class_count ? vm->class_count : 1, sizeof(dex_class *));
    if (!vm->fields || !vm->classes || !vm->type_worklist) return XXEMUL_STATUS_OUT_OF_MEMORY;
    for (dex_index = 0; dex_index < program->dex_count; ++dex_index) {
        const xxemul_dex_file *file = &program->dex_files[dex_index];
        uint32_t i;
        for (i = 0; i < file->header.field_ids_size; ++i, ++field_index) {
            const uint8_t *raw = file->data + file->header.field_ids_off + (size_t)i * 8;
            uint16_t owner = xxemul_dex_u16(raw), type = xxemul_dex_u16(raw + 2);
            uint32_t name = xxemul_dex_u32(raw + 4);
            dex_field *field = &vm->fields[field_index];
            size_t previous;
            if (owner >= file->header.type_ids_size || type >= file->header.type_ids_size || name >= file->header.string_ids_size) return XXEMUL_STATUS_INVALID_IMAGE;
            field->owner = file->types[owner];
            field->type = file->types[type];
            field->name = file->strings[name];
            field->canonical = field_index;
            for (previous = 0; previous < field_index; ++previous) {
                dex_field *other = &vm->fields[previous];
                if (!strcmp(field->owner, other->owner) && !strcmp(field->type, other->type) && !strcmp(field->name, other->name)) {
                    field->canonical = other->canonical;
                    break;
                }
            }
        }
        for (i = 0; i < file->header.class_defs_size; ++i, ++class_index) {
            const uint8_t *raw = file->data + file->header.class_defs_off + (size_t)i * 32;
            uint32_t type = xxemul_dex_u32(raw), super = xxemul_dex_u32(raw + 8);
            uint32_t interfaces = xxemul_dex_u32(raw + 12);
            dex_class *class_info = &vm->classes[class_index];
            if (type >= file->header.type_ids_size || (super != DEX_NO_INDEX && super >= file->header.type_ids_size)) return XXEMUL_STATUS_INVALID_IMAGE;
            class_info->descriptor = file->types[type];
            class_info->superclass = super == DEX_NO_INDEX ? NULL : file->types[super];
            class_info->dex_index = dex_index;
            {
                size_t previous;
                for (previous = 0; previous < class_index; ++previous)
                    if (!strcmp(vm->classes[previous].descriptor, class_info->descriptor)) return XXEMUL_STATUS_INVALID_IMAGE;
            }
            if (interfaces) {
                uint32_t j;
                if ((interfaces & 3u) || interfaces > file->size || file->size - interfaces < 4) return XXEMUL_STATUS_INVALID_IMAGE;
                class_info->interface_count = xxemul_dex_u32(file->data + interfaces);
                if (class_info->interface_count > (file->size - interfaces - 4) / 2) return XXEMUL_STATUS_INVALID_IMAGE;
                class_info->interfaces = file->data + interfaces + 4;
                for (j = 0; j < class_info->interface_count; ++j)
                    if (xxemul_dex_u16(class_info->interfaces + (size_t)j * 2) >= file->header.type_ids_size) return XXEMUL_STATUS_INVALID_IMAGE;
            }
        }
    }
    {
        size_t i;
        for (i = 0; i < vm->class_count; ++i) {
            size_t path_count = 0, j;
            dex_class *current = &vm->classes[i];
            while (current && current->hierarchy_state != 2) {
                if (current->hierarchy_state == 1) return XXEMUL_STATUS_INVALID_IMAGE;
                current->hierarchy_state = 1;
                vm->type_worklist[path_count++] = current;
                current = current->superclass ? find_class(vm, current->superclass) : NULL;
            }
            for (j = 0; j < path_count; ++j) vm->type_worklist[j]->hierarchy_state = 2;
        }
    }
    for (dex_index = 0; dex_index < program->dex_count; ++dex_index) {
        const xxemul_dex_file *file = &program->dex_files[dex_index];
        uint32_t i;
        for (i = 0; i < file->header.class_defs_size; ++i) {
            const uint8_t *raw = file->data + file->header.class_defs_off + (size_t)i * 32;
            size_t offset = xxemul_dex_u32(raw + 24), values = xxemul_dex_u32(raw + 28);
            uint32_t counts[4], static_values = 0, group;
            if (!offset) {
                if (values) return XXEMUL_STATUS_INVALID_IMAGE;
                continue;
            }
            for (group = 0; group < 4; ++group)
                if (!read_uleb(file, &offset, &counts[group])) return XXEMUL_STATUS_INVALID_IMAGE;
            if (values && !read_uleb(file, &values, &static_values)) return XXEMUL_STATUS_INVALID_IMAGE;
            if (static_values > counts[0]) return XXEMUL_STATUS_INVALID_IMAGE;
            for (group = 0; group < 2; ++group) {
                uint32_t j, index = 0;
                for (j = 0; j < counts[group]; ++j) {
                    uint32_t delta, flags;
                    dex_field *field;
                    if (!read_uleb(file, &offset, &delta) || !read_uleb(file, &offset, &flags) || delta > UINT32_MAX - index) return XXEMUL_STATUS_INVALID_IMAGE;
                    index += delta;
                    if (index >= file->header.field_ids_size) return XXEMUL_STATUS_INVALID_IMAGE;
                    field = &vm->fields[vm->field_bases[dex_index] + index];
                    field = &vm->fields[field->canonical];
                    field->declared = 1;
                    field->flags = flags;
                    if ((group == 0) != ((flags & DEX_ACC_STATIC) != 0)) return XXEMUL_STATUS_INVALID_IMAGE;
                    if (!group && j < static_values) {
                        unsigned unsupported;
                        xxemul_status status = parse_static_value(vm, file, &values, &field->value, &unsupported, 0);
                        if (status != XXEMUL_STATUS_OK) return status;
                        field->unsupported_initial = unsupported != 0;
                    }
                }
            }
        }
    }
    return XXEMUL_STATUS_OK;
}

xxemul_dex_vm *xxemul_dex_vm_create(const xxemul_dex_program *program, const xxemul_dex_vm_config *config, xxemul_status *status)
{
    xxemul_dex_vm *vm;
    xxemul_status current;
    if (status) *status = XXEMUL_STATUS_INVALID_ARGUMENT;
    if (!program || !program->dex_count || (config && config->max_call_depth > 128)) return NULL;
    vm = (xxemul_dex_vm *)calloc(1, sizeof(*vm));
    if (!vm) {
        if (status) *status = XXEMUL_STATUS_OUT_OF_MEMORY;
        return NULL;
    }
    vm->program = program;
    if (config) vm->config = *config;
    if (!vm->config.max_instructions) vm->config.max_instructions = 100000;
    if (!vm->config.max_call_depth) vm->config.max_call_depth = 128;
    if (!vm->config.max_heap_bytes) vm->config.max_heap_bytes = 16u * 1024u * 1024u;
    current = prepare_metadata(vm);
    if (current != XXEMUL_STATUS_OK) {
        xxemul_dex_vm_destroy(vm);
        if (status) *status = current;
        return NULL;
    }
    if (status) *status = XXEMUL_STATUS_OK;
    return vm;
}

void xxemul_dex_vm_destroy(xxemul_dex_vm *vm)
{
    size_t i;
    if (!vm) return;
    for (i = 0; i < vm->object_count; ++i) {
        dex_object *object = vm->objects[i];
        dex_property *property = object->properties;
        while (property) {
            dex_property *next = property->next;
            free(property);
            property = next;
        }
        free(object->descriptor);
        free(object->elements);
        free(object);
    }
    if (vm->code_cache)
        for (i = 0; i < vm->program->method_count; ++i) free(vm->code_cache[i].boundaries);
    free(vm->code_cache);
    free(vm->objects);
    free(vm->field_bases);
    free(vm->fields);
    free(vm->classes);
    free(vm->type_worklist);
    free(vm);
}

static xxemul_dex_value_kind prototype_kind(const char *prototype);

static xxemul_status validate_host_return(xxemul_dex_vm *vm, const xxemul_dex_method *method, xxemul_dex_value *value, const char *callback_name)
{
    if (value->kind != prototype_kind(method->info.prototype))
        return vm_fail(vm, XXEMUL_STATUS_INVALID_ARGUMENT, "%s returned wrong value kind for %s", callback_name, method->info.selector);
    if (value->kind == XXEMUL_DEX_VALUE_OBJECT && value->value) {
        dex_object *object;
        const char *return_type;
        if (value->value > UINT32_MAX || !(object = get_object(vm, (uint32_t)value->value)))
            return vm_fail(vm, XXEMUL_STATUS_ADDRESS_FAULT, "%s returned invalid object reference", callback_name);
        return_type = strchr(method->info.prototype, ')') + 1;
        return require_assignable(vm, object->descriptor, return_type, "host return value");
    }
    if (value->kind == XXEMUL_DEX_VALUE_WORD) value->value = (uint32_t)value->value;
    else if (value->kind == XXEMUL_DEX_VALUE_VOID) value->value = 0;
    return XXEMUL_STATUS_OK;
}

static xxemul_status execute_method(xxemul_dex_vm *vm, size_t method_index, const uint32_t *arguments, size_t argument_count, int static_call,
                                    xxemul_dex_value *return_value);

static size_t find_implementation(xxemul_dex_vm *vm, const char *owner, const char *name, const char *prototype, int search_superclasses)
{
    size_t depth;
    for (depth = 0; owner && depth <= vm->class_count; ++depth) {
        size_t i;
        dex_class *class_info;
        for (i = 0; i < vm->program->method_count; ++i) {
            const xxemul_dex_method_info *method = &vm->program->methods[i].info;
            if (method->is_defined && !strcmp(method->class_descriptor, owner) && !strcmp(method->name, name) && !strcmp(method->prototype, prototype)) return i;
        }
        if (!search_superclasses) break;
        class_info = find_class(vm, owner);
        owner = class_info ? class_info->superclass : NULL;
    }
    return SIZE_MAX;
}

static xxemul_status initialize_class(xxemul_dex_vm *vm, const char *descriptor)
{
    dex_class *class_info = find_class(vm, descriptor);
    size_t method_index, saved_method;
    uint32_t saved_pc;
    xxemul_status status;
    xxemul_dex_value ignored;
    if (!class_info || class_info->initialized == 2 || class_info->initialized == 1) return XXEMUL_STATUS_OK;
    if (class_info->initialized == 3) return vm_fail(vm, XXEMUL_STATUS_ADDRESS_FAULT, "class initialization previously failed: %s", descriptor);
    if (vm->initialization_depth >= vm->config.max_call_depth) return vm_fail(vm, XXEMUL_STATUS_LIMIT_REACHED, "class initialization depth limit reached");
    ++vm->initialization_depth;
    class_info->initialized = 1;
    saved_method = vm->result->method_index;
    saved_pc = vm->result->pc;
    status = class_info->superclass ? initialize_class(vm, class_info->superclass) : XXEMUL_STATUS_OK;
    if (status == XXEMUL_STATUS_OK) {
        method_index = find_implementation(vm, descriptor, "<clinit>", "()V", 0);
        if (method_index != SIZE_MAX) status = execute_method(vm, method_index, NULL, 0, 1, &ignored);
    }
    class_info->initialized = status == XXEMUL_STATUS_OK ? 2u : 3u;
    --vm->initialization_depth;
    if (status == XXEMUL_STATUS_OK) {
        vm->result->method_index = saved_method;
        vm->result->pc = saved_pc;
    }
    return status;
}

static xxemul_dex_value_kind prototype_kind(const char *prototype)
{
    const char *return_type = strchr(prototype, ')');
    if (!return_type) return XXEMUL_DEX_VALUE_VOID;
    switch (return_type[1]) {
        case 'V': return XXEMUL_DEX_VALUE_VOID;
        case 'J':
        case 'D': return XXEMUL_DEX_VALUE_WIDE;
        case 'L':
        case '[': return XXEMUL_DEX_VALUE_OBJECT;
        default: return XXEMUL_DEX_VALUE_WORD;
    }
}

static int prototype_words(const char *prototype, int static_call, size_t *words)
{
    const char *cursor = prototype;
    *words = static_call ? 0 : 1;
    if (*cursor++ != '(') return 0;
    while (*cursor && *cursor != ')') {
        unsigned array = 0;
        while (*cursor == '[') {
            ++cursor;
            array = 1;
        }
        if (*cursor == 'L') {
            cursor = strchr(cursor, ';');
            if (!cursor) return 0;
            ++cursor;
            ++*words;
        } else if (strchr("ZBCSIFJD", *cursor) && *cursor) {
            *words += !array && (*cursor == 'J' || *cursor == 'D') ? 2 : 1;
            ++cursor;
        } else return 0;
    }
    return *cursor == ')' && cursor[1] != '\0';
}

static xxemul_status prepare_code(xxemul_dex_vm *vm, size_t method_index)
{
    const xxemul_dex_method *method = &vm->program->methods[method_index];
    const xxemul_dex_file *file = &vm->program->dex_files[method->info.dex_index];
    dex_code_cache *cache = &vm->code_cache[method_index];
    size_t pc = 0, size = (size_t)method->info.code_units * 2;
    if (cache->boundaries) return cache->status == XXEMUL_STATUS_OK ? cache->status : vm_fail(vm, cache->status, "method contains an invalid DEX instruction");
    if (!size) return vm_fail(vm, XXEMUL_STATUS_DECODE_ERROR, "empty method body");
    cache->boundaries = (uint8_t *)heap_alloc(vm, method->info.code_units);
    if (!cache->boundaries) return vm_fail(vm, vm->allocation_status, "method boundary map exceeds heap limit");
    while (pc < size) {
        xxbyte_instruction instruction;
        xxbyte_status status = xxbyte_decode(XXBYTE_FAMILY_DEX, file->version, method->code + pc, size - pc, pc, &instruction);
        if (status != XXBYTE_STATUS_OK || !instruction.size || instruction.size > size - pc) {
            cache->status = XXEMUL_STATUS_DECODE_ERROR;
            vm->result->pc = (uint32_t)pc;
            return vm_fail(vm, cache->status, "invalid DEX instruction at byte 0x%zx: %s", pc, xxbyte_status_string(status));
        }
        cache->boundaries[pc / 2] = (instruction.group & XXBYTE_GROUP_PAYLOAD) ? 2 : 1;
        pc += instruction.size;
    }
    cache->status = XXEMUL_STATUS_OK;
    return XXEMUL_STATUS_OK;
}

static xxemul_status branch_to(xxemul_dex_vm *vm, size_t method_index, int64_t target, uint32_t *pc)
{
    const xxemul_dex_method *method = &vm->program->methods[method_index];
    if (target < 0 || (uint64_t)target >= (uint64_t)method->info.code_units * 2 || (target & 1) || vm->code_cache[method_index].boundaries[(size_t)target / 2] != 1)
        return vm_fail(vm, XXEMUL_STATUS_DECODE_ERROR, "branch target 0x%llx is not an instruction boundary", (unsigned long long)(uint64_t)target);
    *pc = (uint32_t)target;
    return XXEMUL_STATUS_OK;
}

static xxemul_status validate_operands(xxemul_dex_vm *vm, const xxemul_dex_method *method, const xxbyte_instruction *instruction)
{
    uint32_t i;
    for (i = 0; i < instruction->operand_count; ++i) {
        const xxbyte_operand *operand = &instruction->operands[i];
        if (operand->type == XXBYTE_OPERAND_REGISTER || operand->type == XXBYTE_OPERAND_REGISTER_RANGE) {
            uint64_t count = operand->type == XXBYTE_OPERAND_REGISTER_RANGE ? operand->extra : (operand->flags & XXBYTE_OPERAND_FLAG_WIDE) ? 2u : 1u;
            if (operand->value < 0 || (uint64_t)operand->value > method->info.registers_size || count > method->info.registers_size - (uint64_t)operand->value)
                return vm_fail(vm, XXEMUL_STATUS_DECODE_ERROR, "%s references invalid register v%lld (register count %u)", instruction->mnemonic,
                               (long long)operand->value, (unsigned)method->info.registers_size);
        }
    }
    return XXEMUL_STATUS_OK;
}

static xxemul_status allocation_failure(xxemul_dex_vm *vm, xxemul_status status)
{
    return vm_fail(vm, status, status == XXEMUL_STATUS_LIMIT_REACHED ? "DEX heap limit reached" : "DEX heap allocation failed");
}

static xxemul_status require_object(xxemul_dex_vm *vm, uint32_t reference, dex_object **object)
{
    *object = get_object(vm, reference);
    if (!*object) return vm_fail(vm, XXEMUL_STATUS_ADDRESS_FAULT, reference ? "invalid object reference 0x%x" : "null object reference", reference);
    return XXEMUL_STATUS_OK;
}

static uint64_t narrow_value(uint64_t value, unsigned kind)
{
    switch (kind) {
        case 3: return (uint32_t)(value != 0); /* boolean */
        case 4: return (uint32_t)(int32_t)(int8_t)value;
        case 5: return (uint16_t)value;
        case 6: return (uint32_t)(int32_t)(int16_t)value;
        default: return value;
    }
}

static unsigned array_width(const char *descriptor)
{
    if (!descriptor || descriptor[0] != '[') return 0;
    switch (descriptor[1]) {
        case 'Z':
        case 'B': return 1;
        case 'C':
        case 'S': return 2;
        case 'I':
        case 'F': return 4;
        case 'J':
        case 'D': return 8;
        case '[':
        case 'L': return 4;
        default: return 0;
    }
}

static int array_access_matches(const char *descriptor, unsigned kind)
{
    if (!descriptor || descriptor[0] != '[') return 0;
    switch (kind) {
        case 0: return descriptor[1] == 'I' || descriptor[1] == 'F';
        case 1: return descriptor[1] == 'J' || descriptor[1] == 'D';
        case 2: return descriptor[1] == '[' || descriptor[1] == 'L';
        case 3: return descriptor[1] == 'Z';
        case 4: return descriptor[1] == 'B';
        case 5: return descriptor[1] == 'C';
        case 6: return descriptor[1] == 'S';
        default: return 0;
    }
}

static int field_access_matches(const char *type, unsigned kind)
{
    char descriptor[3] = {'[', 0, 0};
    descriptor[1] = type[0];
    return array_access_matches(descriptor, kind);
}

static xxemul_status access_field(xxemul_dex_vm *vm, const xxemul_dex_method *method, uint32_t field_id, uint32_t reference, unsigned is_static, unsigned write,
                                  unsigned kind, uint64_t *value)
{
    const xxemul_dex_file *file = &vm->program->dex_files[method->info.dex_index];
    dex_field *field;
    xxemul_status status;
    if (field_id >= file->header.field_ids_size) return vm_fail(vm, XXEMUL_STATUS_DECODE_ERROR, "invalid field index %u", field_id);
    field = &vm->fields[vm->field_bases[method->info.dex_index] + field_id];
    field = &vm->fields[field->canonical];
    if (!field->declared)
        return vm_fail(vm, XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION, "external field is not implemented: %s->%s:%s", field->owner, field->name, field->type);
    if ((is_static != 0) != ((field->flags & DEX_ACC_STATIC) != 0) || !field_access_matches(field->type, kind))
        return vm_fail(vm, XXEMUL_STATUS_DECODE_ERROR, "field access type mismatch: %s->%s:%s", field->owner, field->name, field->type);
    if (write && kind == 2 && *value) {
        dex_object *object;
        if (*value > UINT32_MAX) return vm_fail(vm, XXEMUL_STATUS_ADDRESS_FAULT, "invalid field object reference");
        status = require_object(vm, (uint32_t)*value, &object);
        if (status != XXEMUL_STATUS_OK) return status;
        status = require_assignable(vm, object->descriptor, field->type, "field store");
        if (status != XXEMUL_STATUS_OK) return status;
    }
    if (is_static) {
        status = initialize_class(vm, field->owner);
        if (status != XXEMUL_STATUS_OK) return status;
        if (write) {
            field->value = narrow_value(*value, kind);
            field->unsupported_initial = 0;
        } else {
            if (field->unsupported_initial)
                return vm_fail(vm, XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION, "unsupported encoded initial value: %s->%s:%s", field->owner, field->name, field->type);
            *value = narrow_value(field->value, kind);
        }
    } else {
        dex_object *object;
        dex_property *property;
        status = require_object(vm, reference, &object);
        if (status != XXEMUL_STATUS_OK) return status;
        status = require_assignable(vm, object->descriptor, field->owner, "field receiver");
        if (status != XXEMUL_STATUS_OK) return status;
        for (property = object->properties; property; property = property->next)
            if (property->field == field->canonical) break;
        if (write && !property) {
            property = (dex_property *)heap_alloc(vm, sizeof(*property));
            if (!property) return allocation_failure(vm, vm->allocation_status);
            property->field = field->canonical;
            property->next = object->properties;
            object->properties = property;
        }
        if (write) property->value = narrow_value(*value, kind);
        else *value = property ? narrow_value(property->value, kind) : 0;
    }
    return XXEMUL_STATUS_OK;
}

static xxemul_status int_operation(xxemul_dex_vm *vm, unsigned operation, uint32_t left, uint32_t right, uint32_t *value)
{
    int32_t a = signed32(left), b = signed32(right);
    unsigned shift = right & 31u;
    switch (operation) {
        case 0: *value = left + right; break;
        case 1: *value = left - right; break;
        case 2: *value = left * right; break;
        case 3:
        case 4:
            if (!right) return vm_fail(vm, XXEMUL_STATUS_ADDRESS_FAULT, "integer division by zero");
            if (a == INT32_MIN && b == -1) *value = operation == 3 ? left : 0;
            else *value = (uint32_t)(operation == 3 ? a / b : a % b);
            break;
        case 5: *value = left & right; break;
        case 6: *value = left | right; break;
        case 7: *value = left ^ right; break;
        case 8: *value = left << shift; break;
        case 9:
            *value = left >> shift;
            if (shift && (left & UINT32_C(0x80000000))) *value |= UINT32_MAX << (32u - shift);
            break;
        case 10: *value = left >> shift; break;
        default: return vm_fail(vm, XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION, "unsupported int operation");
    }
    return XXEMUL_STATUS_OK;
}

static xxemul_status long_operation(xxemul_dex_vm *vm, unsigned operation, uint64_t left, uint64_t right, uint64_t *value)
{
    int64_t a = signed64(left), b = signed64(right);
    unsigned shift = (unsigned)right & 63u;
    switch (operation) {
        case 0: *value = left + right; break;
        case 1: *value = left - right; break;
        case 2: *value = left * right; break;
        case 3:
        case 4:
            if (!right) return vm_fail(vm, XXEMUL_STATUS_ADDRESS_FAULT, "long division by zero");
            if (a == INT64_MIN && b == -1) *value = operation == 3 ? left : 0;
            else *value = (uint64_t)(operation == 3 ? a / b : a % b);
            break;
        case 5: *value = left & right; break;
        case 6: *value = left | right; break;
        case 7: *value = left ^ right; break;
        case 8: *value = left << shift; break;
        case 9:
            *value = left >> shift;
            if (shift && (left & UINT64_C(0x8000000000000000))) *value |= UINT64_MAX << (64u - shift);
            break;
        case 10: *value = left >> shift; break;
        default: return vm_fail(vm, XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION, "unsupported long operation");
    }
    return XXEMUL_STATUS_OK;
}

static float float_read(uint32_t bits)
{
    float value;
    memcpy(&value, &bits, sizeof(value));
    return value;
}

static uint32_t float_bits(float value)
{
    uint32_t bits;
    memcpy(&bits, &value, sizeof(bits));
    return bits;
}

static double double_read(uint64_t bits)
{
    double value;
    memcpy(&value, &bits, sizeof(value));
    return value;
}

static uint64_t double_bits(double value)
{
    uint64_t bits;
    memcpy(&bits, &value, sizeof(bits));
    return bits;
}

static uint64_t floating_to_integer(double value, int wide)
{
    if (isnan(value)) return 0;
    if (wide) {
        if (value >= 9223372036854775808.0) return (uint64_t)INT64_MAX;
        if (value <= -9223372036854775808.0) return (uint64_t)INT64_MIN;
        return (uint64_t)(int64_t)value;
    }
    if (value >= 2147483647.0) return (uint32_t)INT32_MAX;
    if (value <= -2147483648.0) return (uint32_t)INT32_MIN;
    return (uint32_t)(int32_t)value;
}

static xxemul_status collect_arguments(xxemul_dex_vm *vm, const xxbyte_instruction *instruction, const uint32_t *registers, uint32_t *arguments, size_t *argument_count,
                                       uint32_t *index)
{
    uint32_t i;
    unsigned found = 0;
    *argument_count = 0;
    for (i = 0; i < instruction->operand_count; ++i) {
        const xxbyte_operand *operand = &instruction->operands[i];
        if (operand->type == XXBYTE_OPERAND_REGISTER_RANGE) {
            size_t j;
            if (operand->extra > 255) return vm_fail(vm, XXEMUL_STATUS_DECODE_ERROR, "invalid invoke register count");
            for (j = 0; j < operand->extra; ++j) arguments[(*argument_count)++] = registers[(size_t)operand->value + j];
        } else if (operand->type == XXBYTE_OPERAND_REGISTER && (operand->flags & XXBYTE_OPERAND_FLAG_LIST)) {
            if (*argument_count >= 255) return vm_fail(vm, XXEMUL_STATUS_DECODE_ERROR, "invalid invoke register list");
            arguments[(*argument_count)++] = registers[(size_t)operand->value];
        } else if (operand->type == XXBYTE_OPERAND_INDEX) {
            *index = (uint32_t)operand->value;
            found = 1;
        }
    }
    return found ? XXEMUL_STATUS_OK : vm_fail(vm, XXEMUL_STATUS_DECODE_ERROR, "missing invoke index");
}

static xxemul_status perform_invoke(xxemul_dex_vm *vm, const xxemul_dex_method *caller, const xxbyte_instruction *instruction, const uint32_t *registers,
                                    xxemul_dex_value *return_value)
{
    const xxemul_dex_file *file = &vm->program->dex_files[caller->info.dex_index];
    uint32_t arguments[255], method_id = 0;
    size_t argument_count, method_index, resolved;
    unsigned opcode = instruction->opcode;
    unsigned base = opcode >= 0x74 ? opcode - 0x74 : opcode - 0x6e;
    int static_call = base == 3;
    const xxemul_dex_method_info *target;
    xxemul_status status = collect_arguments(vm, instruction, registers, arguments, &argument_count, &method_id);
    if (status != XXEMUL_STATUS_OK) return status;
    if (method_id >= file->header.method_ids_size) return vm_fail(vm, XXEMUL_STATUS_DECODE_ERROR, "invalid method index %u", method_id);
    if (argument_count > caller->info.outs_size) return vm_fail(vm, XXEMUL_STATUS_DECODE_ERROR, "invoke arguments exceed code_item outs_size");
    method_index = file->method_map[method_id];
    if (method_index >= vm->program->method_count) return vm_fail(vm, XXEMUL_STATUS_DECODE_ERROR, "unmapped method index %u", method_id);
    target = &vm->program->methods[method_index].info;
    resolved = SIZE_MAX;
    if (!static_call) {
        dex_object *object;
        if (!argument_count) return vm_fail(vm, XXEMUL_STATUS_DECODE_ERROR, "instance invoke has no receiver");
        status = require_object(vm, arguments[0], &object);
        if (status != XXEMUL_STATUS_OK) return status;
        status = require_assignable(vm, object->descriptor, target->class_descriptor, "invoke receiver");
        if (status != XXEMUL_STATUS_OK) return status;
        if (base == 0 || base == 4) resolved = find_implementation(vm, object->descriptor, target->name, target->prototype, 1);
        else if (base == 1) {
            dex_class *class_info = find_class(vm, caller->info.class_descriptor);
            resolved = find_implementation(vm, class_info ? class_info->superclass : NULL, target->name, target->prototype, 1);
        }
    }
    if (resolved == SIZE_MAX) resolved = find_implementation(vm, target->class_descriptor, target->name, target->prototype, base != 2);
    if (resolved != SIZE_MAX) method_index = resolved;
    status = execute_method(vm, method_index, arguments, argument_count, static_call, return_value);
    if (status != XXEMUL_STATUS_OK && !vm->program->methods[method_index].code && vm->result->method_index == method_index) {
        vm->result->method_index = file->method_map[caller->info.method_id];
        vm->result->pc = (uint32_t)instruction->address;
    }
    return status;
}

static xxemul_status execute_body(xxemul_dex_vm *vm, size_t method_index, uint32_t *registers, xxemul_dex_value *return_value)
{
    const xxemul_dex_method *method = &vm->program->methods[method_index];
    const xxemul_dex_file *file = &vm->program->dex_files[method->info.dex_index];
    size_t code_size = (size_t)method->info.code_units * 2;
    uint32_t pc = 0;
    xxemul_dex_value pending = {0, XXEMUL_DEX_VALUE_VOID};
    unsigned pending_valid = 0;
    xxemul_status status = prepare_code(vm, method_index);
    if (status != XXEMUL_STATUS_OK) return status;
    while (pc < code_size) {
        xxbyte_instruction instruction;
        uint32_t next_pc, a = 0, b = 0, c = 0, opcode;
        uint64_t value = 0;
        vm->result->method_index = method_index;
        vm->result->pc = pc;
        if (vm->result->instructions >= vm->config.max_instructions) return vm_fail(vm, XXEMUL_STATUS_LIMIT_REACHED, "instruction limit reached");
        if (vm->code_cache[method_index].boundaries[pc / 2] != 1) return vm_fail(vm, XXEMUL_STATUS_DECODE_ERROR, "attempted to execute a DEX payload");
        if (xxbyte_decode(XXBYTE_FAMILY_DEX, file->version, method->code + pc, code_size - pc, pc, &instruction) != XXBYTE_STATUS_OK)
            return vm_fail(vm, XXEMUL_STATUS_DECODE_ERROR, "DEX instruction decode failed");
        status = validate_operands(vm, method, &instruction);
        if (status != XXEMUL_STATUS_OK) return status;
        ++vm->result->instructions;
        if (vm->config.trace_callback) vm->config.trace_callback(vm->config.trace_context, &method->info, pc, instruction.mnemonic);
        opcode = instruction.opcode;
        next_pc = pc + instruction.size;
        if (instruction.operand_count) a = (uint32_t)instruction.operands[0].value;
        if (instruction.operand_count > 1) b = (uint32_t)instruction.operands[1].value;
        if (instruction.operand_count > 2) c = (uint32_t)instruction.operands[2].value;
        if (opcode < 0x0a || opcode > 0x0c) pending_valid = 0;
        if ((opcode >= 0x90 && opcode <= 0xaf) || (opcode >= 0xb0 && opcode <= 0xcf)) {
            unsigned operation = opcode >= 0xb0 ? opcode - 0xb0 : opcode - 0x90;
            uint32_t left_register = opcode >= 0xb0 ? a : b;
            uint32_t right_register = opcode >= 0xb0 ? b : c;
            if (operation < 11) {
                uint32_t word = 0;
                status = int_operation(vm, operation, registers[left_register], registers[right_register], &word);
                if (status != XXEMUL_STATUS_OK) return status;
                registers[a] = word;
            } else if (operation < 22) {
                uint64_t right = operation >= 19 ? registers[right_register] : wide_read(registers, right_register);
                status = long_operation(vm, operation - 11, wide_read(registers, left_register), right, &value);
                if (status != XXEMUL_STATUS_OK) return status;
                wide_write(registers, a, value);
            } else if (operation < 27) {
                float left = float_read(registers[left_register]);
                float right = float_read(registers[right_register]);
                float result;
                switch (operation - 22) {
                    case 0: result = left + right; break;
                    case 1: result = left - right; break;
                    case 2: result = left * right; break;
                    case 3: result = left / right; break;
                    default: result = fmodf(left, right); break;
                }
                registers[a] = float_bits(result);
            } else {
                double left = double_read(wide_read(registers, left_register));
                double right = double_read(wide_read(registers, right_register));
                double result;
                switch (operation - 27) {
                    case 0: result = left + right; break;
                    case 1: result = left - right; break;
                    case 2: result = left * right; break;
                    case 3: result = left / right; break;
                    default: result = fmod(left, right); break;
                }
                wide_write(registers, a, double_bits(result));
            }
        } else if (opcode >= 0xd0 && opcode <= 0xe2) {
            unsigned operation = opcode <= 0xd7 ? opcode - 0xd0 : opcode - 0xd8;
            uint32_t left = registers[b], right = c, word = 0;
            if (operation == 1) {
                uint32_t swap = left;
                left = right;
                right = swap;
            }
            status = int_operation(vm, operation, left, right, &word);
            if (status != XXEMUL_STATUS_OK) return status;
            registers[a] = word;
        } else if (opcode >= 0x44 && opcode <= 0x51) {
            unsigned write = opcode >= 0x4b, kind = opcode - (write ? 0x4b : 0x44);
            dex_object *array;
            status = require_object(vm, registers[b], &array);
            if (status != XXEMUL_STATUS_OK) return status;
            if (array->kind != 1 || !array_access_matches(array->descriptor, kind)) return vm_fail(vm, XXEMUL_STATUS_ADDRESS_FAULT, "array access type mismatch");
            if (registers[c] >= array->length)
                return vm_fail(vm, XXEMUL_STATUS_ADDRESS_FAULT, "array index %d outside length %zu", signed32(registers[c]), array->length);
            if (write) {
                value = kind == 1 ? wide_read(registers, a) : registers[a];
                if (kind == 2 && value) {
                    dex_object *element;
                    status = require_object(vm, (uint32_t)value, &element);
                    if (status != XXEMUL_STATUS_OK) return status;
                    status = require_assignable(vm, element->descriptor, array->descriptor + 1, "array store");
                    if (status != XXEMUL_STATUS_OK) return status;
                }
                array->elements[registers[c]] = narrow_value(value, kind);
            } else {
                value = narrow_value(array->elements[registers[c]], kind);
                if (kind == 1) wide_write(registers, a, value);
                else registers[a] = (uint32_t)value;
            }
        } else if (opcode >= 0x52 && opcode <= 0x6d) {
            unsigned group = (opcode - 0x52) / 7, kind = (opcode - 0x52) % 7;
            unsigned write = group & 1u, is_static = group >= 2;
            uint32_t field_id = is_static ? b : c;
            value = kind == 1 ? wide_read(registers, a) : registers[a];
            status = access_field(vm, method, field_id, is_static ? 0 : registers[b], is_static, write, kind, &value);
            if (status != XXEMUL_STATUS_OK) return status;
            if (!write) {
                if (kind == 1) wide_write(registers, a, value);
                else registers[a] = (uint32_t)value;
            }
        } else if ((opcode >= 0x6e && opcode <= 0x72) || (opcode >= 0x74 && opcode <= 0x78)) {
            status = perform_invoke(vm, method, &instruction, registers, &pending);
            if (status != XXEMUL_STATUS_OK) return status;
            pending_valid = 1;
        } else if (opcode >= 0x32 && opcode <= 0x3d) {
            unsigned condition = opcode >= 0x38 ? opcode - 0x38 : opcode - 0x32;
            int32_t left = signed32(registers[a]);
            int32_t right = opcode >= 0x38 ? 0 : signed32(registers[b]);
            int taken = condition == 0   ? left == right
                        : condition == 1 ? left != right
                        : condition == 2 ? left < right
                        : condition == 3 ? left >= right
                        : condition == 4 ? left > right
                                         : left <= right;
            if (taken) {
                int64_t target = instruction.operands[opcode >= 0x38 ? 1 : 2].value;
                status = branch_to(vm, method_index, target, &next_pc);
                if (status != XXEMUL_STATUS_OK) return status;
            }
        } else switch (opcode) {
                case 0x00: break;
                case 0x01:
                case 0x02:
                case 0x03:
                case 0x07:
                case 0x08:
                case 0x09: registers[a] = registers[b]; break;
                case 0x04:
                case 0x05:
                case 0x06: wide_write(registers, a, wide_read(registers, b)); break;
                case 0x0a:
                case 0x0b:
                case 0x0c: {
                    xxemul_dex_value_kind expected = opcode == 0x0a ? XXEMUL_DEX_VALUE_WORD : opcode == 0x0b ? XXEMUL_DEX_VALUE_WIDE : XXEMUL_DEX_VALUE_OBJECT;
                    if (!pending_valid || pending.kind != expected)
                        return vm_fail(vm, XXEMUL_STATUS_DECODE_ERROR, "%s does not follow a compatible invoke or filled-new-array", instruction.mnemonic);
                    if (opcode == 0x0b) wide_write(registers, a, pending.value);
                    else registers[a] = (uint32_t)pending.value;
                    pending_valid = 0;
                    break;
                }
                case 0x0e:
                case 0x0f:
                case 0x10:
                case 0x11:
                    return_value->kind = opcode == 0x0e   ? XXEMUL_DEX_VALUE_VOID
                                         : opcode == 0x0f ? XXEMUL_DEX_VALUE_WORD
                                         : opcode == 0x10 ? XXEMUL_DEX_VALUE_WIDE
                                                          : XXEMUL_DEX_VALUE_OBJECT;
                    return_value->value = opcode == 0x0e ? 0 : opcode == 0x10 ? wide_read(registers, a) : registers[a];
                    if (return_value->kind != prototype_kind(method->info.prototype))
                        return vm_fail(vm, XXEMUL_STATUS_DECODE_ERROR, "return instruction does not match method prototype");
                    if (return_value->kind == XXEMUL_DEX_VALUE_OBJECT && return_value->value) {
                        dex_object *object;
                        const char *return_type = strchr(method->info.prototype, ')') + 1;
                        status = require_object(vm, (uint32_t)return_value->value, &object);
                        if (status != XXEMUL_STATUS_OK) return status;
                        status = require_assignable(vm, object->descriptor, return_type, "return value");
                        if (status != XXEMUL_STATUS_OK) return status;
                    }
                    return XXEMUL_STATUS_OK;
                case 0x12:
                case 0x13:
                case 0x14:
                case 0x15: registers[a] = b; break;
                case 0x16:
                case 0x17:
                case 0x18:
                case 0x19: wide_write(registers, a, (uint64_t)instruction.operands[1].value); break;
                case 0x1a:
                case 0x1b: {
                    uint32_t reference;
                    if (b >= file->header.string_ids_size) return vm_fail(vm, XXEMUL_STATUS_DECODE_ERROR, "invalid string index %u", b);
                    status = intern_string(vm, file->strings[b], &reference);
                    if (status != XXEMUL_STATUS_OK) return allocation_failure(vm, status);
                    registers[a] = reference;
                    break;
                }
                case 0x1c: {
                    size_t i;
                    uint32_t reference = 0;
                    if (b >= file->header.type_ids_size) return vm_fail(vm, XXEMUL_STATUS_DECODE_ERROR, "invalid type index %u", b);
                    for (i = 0; i < vm->object_count; ++i)
                        if (vm->objects[i]->kind == 3 && !strcmp(vm->objects[i]->string, file->types[b])) {
                            reference = (uint32_t)(i + 1);
                            break;
                        }
                    if (!reference) {
                        status = allocate_object(vm, "Ljava/lang/Class;", 3, 0, &reference);
                        if (status != XXEMUL_STATUS_OK) return allocation_failure(vm, status);
                        vm->objects[reference - 1]->string = file->types[b];
                    }
                    registers[a] = reference;
                    break;
                }
                case 0x1f:
                case 0x20: {
                    uint32_t reference = registers[opcode == 0x1f ? a : b];
                    uint32_t type = opcode == 0x1f ? b : c;
                    dex_object *object = NULL;
                    int matches;
                    if (type >= file->header.type_ids_size) return vm_fail(vm, XXEMUL_STATUS_DECODE_ERROR, "invalid cast type index %u", type);
                    if (reference) {
                        status = require_object(vm, reference, &object);
                        if (status != XXEMUL_STATUS_OK) return status;
                    }
                    matches = object ? is_assignable(vm, object->descriptor, file->types[type]) : 0;
                    if (matches < 0)
                        return vm_fail(vm, XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION, "unknown external type relationship: %s -> %s (%s)", object->descriptor,
                                       file->types[type], instruction.mnemonic);
                    if (opcode == 0x1f) {
                        if (reference && !matches) return vm_fail(vm, XXEMUL_STATUS_ADDRESS_FAULT, "check-cast failed for %s", file->types[type]);
                    } else registers[a] = (uint32_t)matches;
                    break;
                }
                case 0x21: {
                    dex_object *array;
                    status = require_object(vm, registers[b], &array);
                    if (status != XXEMUL_STATUS_OK) return status;
                    if (array->kind != 1) return vm_fail(vm, XXEMUL_STATUS_ADDRESS_FAULT, "array-length receiver is not an array");
                    registers[a] = (uint32_t)array->length;
                    break;
                }
                case 0x22: {
                    uint32_t reference;
                    if (b >= file->header.type_ids_size || file->types[b][0] != 'L')
                        return vm_fail(vm, XXEMUL_STATUS_DECODE_ERROR, "invalid new-instance type index %u", b);
                    status = initialize_class(vm, file->types[b]);
                    if (status != XXEMUL_STATUS_OK) return status;
                    status = xxemul_dex_vm_new_object(vm, file->types[b], &reference);
                    if (status != XXEMUL_STATUS_OK) return allocation_failure(vm, status);
                    registers[a] = reference;
                    break;
                }
                case 0x23: {
                    uint32_t reference;
                    if (c >= file->header.type_ids_size || !array_width(file->types[c]))
                        return vm_fail(vm, XXEMUL_STATUS_DECODE_ERROR, "invalid new-array type index %u", c);
                    if (signed32(registers[b]) < 0) return vm_fail(vm, XXEMUL_STATUS_ADDRESS_FAULT, "negative array length");
                    status = allocate_object(vm, file->types[c], 1, registers[b], &reference);
                    if (status != XXEMUL_STATUS_OK) return allocation_failure(vm, status);
                    registers[a] = reference;
                    break;
                }
                case 0x24:
                case 0x25: {
                    uint32_t words[255], type = 0, reference;
                    size_t count, i;
                    status = collect_arguments(vm, &instruction, registers, words, &count, &type);
                    if (status != XXEMUL_STATUS_OK) return status;
                    if (type >= file->header.type_ids_size || !array_width(file->types[type]) || array_width(file->types[type]) == 8)
                        return vm_fail(vm, XXEMUL_STATUS_DECODE_ERROR, "invalid filled-new-array element type");
                    status = allocate_object(vm, file->types[type], 1, count, &reference);
                    if (status != XXEMUL_STATUS_OK) return allocation_failure(vm, status);
                    for (i = 0; i < count; ++i) {
                        const char *element_type = file->types[type] + 1;
                        if ((*element_type == '[' || *element_type == 'L') && words[i]) {
                            dex_object *element;
                            status = require_object(vm, words[i], &element);
                            if (status != XXEMUL_STATUS_OK) return status;
                            status = require_assignable(vm, element->descriptor, element_type, "filled-new-array store");
                            if (status != XXEMUL_STATUS_OK) return status;
                        }
                        vm->objects[reference - 1]->elements[i] = words[i];
                    }
                    pending.value = reference;
                    pending.kind = XXEMUL_DEX_VALUE_OBJECT;
                    pending_valid = 1;
                    break;
                }
                case 0x26: {
                    dex_object *array;
                    xxbyte_instruction payload;
                    int64_t target = instruction.operands[1].value;
                    size_t i, count;
                    unsigned width;
                    status = require_object(vm, registers[a], &array);
                    if (status != XXEMUL_STATUS_OK) return status;
                    if (array->kind != 1 || array->descriptor[1] == '[' || array->descriptor[1] == 'L')
                        return vm_fail(vm, XXEMUL_STATUS_ADDRESS_FAULT, "fill-array-data receiver is not a primitive array");
                    if (target < 0 || (uint64_t)target >= code_size || (target & 3) || vm->code_cache[method_index].boundaries[(size_t)target / 2] != 2 ||
                        xxbyte_decode(XXBYTE_FAMILY_DEX, file->version, method->code + (size_t)target, code_size - (size_t)target, (uint64_t)target, &payload) !=
                            XXBYTE_STATUS_OK ||
                        payload.opcode != XXBYTE_DEX_FILL_ARRAY_DATA_PAYLOAD)
                        return vm_fail(vm, XXEMUL_STATUS_DECODE_ERROR, "invalid fill-array-data payload");
                    width = (unsigned)payload.operands[0].value;
                    count = (size_t)payload.operands[1].value;
                    if (width != array_width(array->descriptor) || count > array->length)
                        return vm_fail(vm, XXEMUL_STATUS_ADDRESS_FAULT, "fill-array-data width or length mismatch");
                    for (i = 0; i < count; ++i) {
                        unsigned j;
                        value = 0;
                        for (j = 0; j < width; ++j) value |= (uint64_t)payload.code[8 + i * width + j] << (j * 8);
                        array->elements[i] = value;
                    }
                    break;
                }
                case 0x27: return vm_fail(vm, XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION, "throw/DEX exception handlers are not implemented (reference 0x%x)", registers[a]);
                case 0x28:
                case 0x29:
                case 0x2a:
                    status = branch_to(vm, method_index, instruction.operands[0].value, &next_pc);
                    if (status != XXEMUL_STATUS_OK) return status;
                    break;
                case 0x2b:
                case 0x2c: {
                    xxbyte_instruction payload;
                    int64_t target = instruction.operands[1].value;
                    uint32_t i;
                    if (target < 0 || (uint64_t)target >= code_size || (target & 3) || vm->code_cache[method_index].boundaries[(size_t)target / 2] != 2 ||
                        xxbyte_decode(XXBYTE_FAMILY_DEX, file->version, method->code + (size_t)target, code_size - (size_t)target, (uint64_t)target, &payload) !=
                            XXBYTE_STATUS_OK ||
                        payload.opcode != (opcode == 0x2b ? XXBYTE_DEX_PACKED_SWITCH_PAYLOAD : XXBYTE_DEX_SPARSE_SWITCH_PAYLOAD))
                        return vm_fail(vm, XXEMUL_STATUS_DECODE_ERROR, "invalid switch payload");
                    for (i = 0; i < payload.table_count; ++i) {
                        int64_t key, displacement;
                        if (xxbyte_switch_entry(&payload, i, &key, &displacement) != XXBYTE_STATUS_OK)
                            return vm_fail(vm, XXEMUL_STATUS_DECODE_ERROR, "invalid switch entry");
                        if (key == signed32(registers[a])) {
                            status = branch_to(vm, method_index, (int64_t)pc + displacement, &next_pc);
                            if (status != XXEMUL_STATUS_OK) return status;
                            break;
                        }
                    }
                    break;
                }
                case 0x2d:
                case 0x2e:
                case 0x2f:
                case 0x30:
                case 0x31: {
                    int comparison;
                    if (opcode == 0x31) {
                        int64_t left = signed64(wide_read(registers, b)), right = signed64(wide_read(registers, c));
                        comparison = left < right ? -1 : left > right ? 1 : 0;
                    } else {
                        double left = opcode < 0x2f ? float_read(registers[b]) : double_read(wide_read(registers, b));
                        double right = opcode < 0x2f ? float_read(registers[c]) : double_read(wide_read(registers, c));
                        comparison = isnan(left) || isnan(right) ? (opcode == 0x2d || opcode == 0x2f ? -1 : 1) : left < right ? -1 : left > right ? 1 : 0;
                    }
                    registers[a] = (uint32_t)comparison;
                    break;
                }
                case 0x7b: registers[a] = 0u - registers[b]; break;
                case 0x7c: registers[a] = ~registers[b]; break;
                case 0x7d: wide_write(registers, a, UINT64_C(0) - wide_read(registers, b)); break;
                case 0x7e: wide_write(registers, a, ~wide_read(registers, b)); break;
                case 0x7f: registers[a] = registers[b] ^ UINT32_C(0x80000000); break;
                case 0x80: wide_write(registers, a, wide_read(registers, b) ^ UINT64_C(0x8000000000000000)); break;
                case 0x81: wide_write(registers, a, (uint64_t)(int64_t)signed32(registers[b])); break;
                case 0x82: registers[a] = float_bits((float)signed32(registers[b])); break;
                case 0x83: wide_write(registers, a, double_bits((double)signed32(registers[b]))); break;
                case 0x84: registers[a] = registers[b]; break;
                case 0x85: registers[a] = float_bits((float)signed64(wide_read(registers, b))); break;
                case 0x86: wide_write(registers, a, double_bits((double)signed64(wide_read(registers, b)))); break;
                case 0x87: registers[a] = (uint32_t)floating_to_integer(float_read(registers[b]), 0); break;
                case 0x88: wide_write(registers, a, floating_to_integer(float_read(registers[b]), 1)); break;
                case 0x89: wide_write(registers, a, double_bits((double)float_read(registers[b]))); break;
                case 0x8a: registers[a] = (uint32_t)floating_to_integer(double_read(wide_read(registers, b)), 0); break;
                case 0x8b: wide_write(registers, a, floating_to_integer(double_read(wide_read(registers, b)), 1)); break;
                case 0x8c: registers[a] = float_bits((float)double_read(wide_read(registers, b))); break;
                case 0x8d: registers[a] = (uint32_t)(int32_t)(int8_t)registers[b]; break;
                case 0x8e: registers[a] = (uint16_t)registers[b]; break;
                case 0x8f: registers[a] = (uint32_t)(int32_t)(int16_t)registers[b]; break;
                default: return vm_fail(vm, XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION, "unsupported DEX instruction %s (opcode 0x%02x)", instruction.mnemonic, opcode);
            }
        pc = next_pc;
    }
    return vm_fail(vm, XXEMUL_STATUS_DECODE_ERROR, "method falls off its instruction array without return");
}

static xxemul_status execute_method(xxemul_dex_vm *vm, size_t method_index, const uint32_t *arguments, size_t argument_count, int static_call,
                                    xxemul_dex_value *return_value)
{
    const xxemul_dex_method *method;
    xxemul_status status;
    size_t expected_count;
    uint32_t *registers = NULL;
    if (method_index >= vm->program->method_count) return vm_fail(vm, XXEMUL_STATUS_INVALID_ARGUMENT, "invalid method index");
    method = &vm->program->methods[method_index];
    vm->result->method_index = method_index;
    vm->result->pc = 0;
    if (!prototype_words(method->info.prototype, static_call, &expected_count) || argument_count != expected_count || (argument_count && !arguments))
        return vm_fail(vm, XXEMUL_STATUS_INVALID_ARGUMENT, "argument word count %zu does not match %s (%zu expected)", argument_count, method->info.selector,
                       expected_count);
    if (method->info.is_defined && static_call != ((method->info.access_flags & DEX_ACC_STATIC) != 0))
        return vm_fail(vm, XXEMUL_STATUS_DECODE_ERROR, "static/instance invoke mismatch for %s", method->info.selector);
    if (!static_call) {
        dex_object *receiver;
        status = require_object(vm, arguments[0], &receiver);
        if (status != XXEMUL_STATUS_OK) return status;
        status = require_assignable(vm, receiver->descriptor, method->info.class_descriptor, "method receiver");
        if (status != XXEMUL_STATUS_OK) return status;
    }
    if (vm->depth >= vm->config.max_call_depth) return vm_fail(vm, XXEMUL_STATUS_LIMIT_REACHED, "DEX call depth limit reached");
    ++vm->depth;
    return_value->value = 0;
    return_value->kind = XXEMUL_DEX_VALUE_VOID;
    status = strcmp(method->info.name, "<clinit>") ? initialize_class(vm, method->info.class_descriptor) : XXEMUL_STATUS_OK;
    if (status != XXEMUL_STATUS_OK) goto finished;
    vm->result->method_index = method_index;
    vm->result->pc = 0;
    if (vm->config.intercept_callback) {
        bool handled = false;
        status = vm->config.intercept_callback(vm->config.intercept_context, vm, &method->info, arguments, argument_count, return_value, &handled);
        if (status != XXEMUL_STATUS_OK) {
            status = vm_fail(vm, status, "intercept callback rejected %s (status %u)", method->info.selector, (unsigned)status);
            goto finished;
        }
        if (handled) {
            status = validate_host_return(vm, method, return_value, "intercept callback");
            goto finished;
        }
        return_value->value = 0;
        return_value->kind = XXEMUL_DEX_VALUE_VOID;
    }
    if (!method->code) {
        if (!vm->config.external_callback)
            status = vm_fail(vm, XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION, "external/native method is not implemented: %s", method->info.selector);
        else {
            status = vm->config.external_callback(vm->config.external_context, vm, &method->info, arguments, argument_count, return_value);
            if (status != XXEMUL_STATUS_OK) status = vm_fail(vm, status, "external callback rejected %s (status %u)", method->info.selector, (unsigned)status);
            else status = validate_host_return(vm, method, return_value, "external callback");
        }
        goto finished;
    }
    if (method->info.ins_size != argument_count || method->info.ins_size > method->info.registers_size) {
        status = vm_fail(vm, XXEMUL_STATUS_DECODE_ERROR, "code_item incoming register count does not match prototype");
        goto finished;
    }
    registers = (uint32_t *)calloc(method->info.registers_size ? method->info.registers_size : 1, sizeof(*registers));
    if (!registers) {
        status = vm_fail(vm, XXEMUL_STATUS_OUT_OF_MEMORY, "DEX register frame allocation failed");
        goto finished;
    }
    if (argument_count) memcpy(registers + method->info.registers_size - argument_count, arguments, argument_count * sizeof(*registers));
    status = execute_body(vm, method_index, registers, return_value);
finished:
    free(registers);
    --vm->depth;
    return status;
}

xxemul_status xxemul_dex_vm_invoke(xxemul_dex_vm *vm, size_t method_index, const uint32_t *argument_words, size_t argument_word_count, xxemul_dex_result *result)
{
    xxemul_dex_value value = {0, XXEMUL_DEX_VALUE_VOID};
    xxemul_status status;
    if (!result) return XXEMUL_STATUS_INVALID_ARGUMENT;
    memset(result, 0, sizeof(*result));
    result->method_index = method_index;
    if (!vm || vm->running || method_index >= (vm ? vm->program->method_count : 0) || (argument_word_count && !argument_words)) {
        result->status = XXEMUL_STATUS_INVALID_ARGUMENT;
        (void)snprintf(result->diagnostic, sizeof(result->diagnostic), "invalid or reentrant DEX invocation");
        return result->status;
    }
    vm->running = 1;
    vm->result = result;
    vm->depth = 0;
    status = execute_method(vm, method_index, argument_words, argument_word_count, (vm->program->methods[method_index].info.access_flags & DEX_ACC_STATIC) != 0, &value);
    result->status = status;
    if (status == XXEMUL_STATUS_OK) {
        result->value = value.value;
        result->value_kind = value.kind;
        (void)snprintf(result->diagnostic, sizeof(result->diagnostic), "method returned normally");
    }
    vm->result = NULL;
    vm->running = 0;
    return status;
}
