/* Copyright (c) 2026 hors<horsicq@gmail.com>
 * SPDX-License-Identifier: MIT */
#include "xxemul_dotnet_internal.h"
#include "xxemul/xxemul_dotnet_runtime.h"
#include <xxbyte/xxbyte_dotnet.h>
#include <float.h>
#include <limits.h>
#include <math.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct net_property {
    size_t field;
    xxemul_dotnet_value value;
    struct net_property *next;
} net_property;
typedef struct net_object {
    char *type_name;
    unsigned kind; /* instance=0, string=1, vector=2, boxed=3 */
    char *string;
    size_t length;
    xxemul_dotnet_type element_type;
    xxemul_dotnet_value *elements;
    xxemul_dotnet_value boxed;
    net_property *properties;
} net_object;
typedef struct net_code_cache { uint8_t *boundaries; xxemul_status status; } net_code_cache;
typedef struct net_frame {
    xxemul_dotnet_value *stack, *locals, *arguments;
    size_t count, capacity;
    size_t allocation_bytes;
} net_frame;
struct xxemul_dotnet_vm {
    const xxemul_dotnet_program *program;
    xxemul_dotnet_vm_config config;
    net_object **objects;
    size_t object_count, object_capacity, heap_bytes, frame_bytes, stack_values;
    xxemul_dotnet_value *static_fields;
    uint8_t *static_written, *class_states;
    net_code_cache *code_cache;
    xxemul_dotnet_result *result;
    xxemul_status allocation_status;
    uint32_t depth, initialization_depth;
    unsigned running;
};

static int32_t net_s32(uint32_t bits) { int32_t v; memcpy(&v, &bits, 4); return v; }
static int64_t net_s64(uint64_t bits) { int64_t v; memcpy(&v, &bits, 8); return v; }
static double net_double(uint64_t bits) { double v; memcpy(&v, &bits, 8); return v; }
static uint64_t net_double_bits(double v) { uint64_t bits; memcpy(&bits, &v, 8); return bits; }
static xxemul_dotnet_value net_value(xxemul_dotnet_value_kind kind, uint64_t bits) {
    xxemul_dotnet_value value; value.kind = kind; value.bits = bits; return value;
}
static uint64_t net_native_mask(const xxemul_dotnet_vm *vm, uint64_t bits) {
    return vm->program->pointer_size == 4 ? (uint32_t)bits : bits;
}
static xxemul_status net_fail(xxemul_dotnet_vm *vm, xxemul_status status, const char *format, ...) {
    if (vm->result && vm->result->status == XXEMUL_STATUS_OK) {
        va_list args; vm->result->status = status;
        va_start(args, format);
        (void)vsnprintf(vm->result->diagnostic, sizeof(vm->result->diagnostic), format, args);
        va_end(args);
    }
    return status;
}
static void *net_alloc(xxemul_dotnet_vm *vm, size_t size) {
    void *memory;
    if (size > vm->config.max_heap_bytes - vm->heap_bytes) {
        vm->allocation_status = XXEMUL_STATUS_LIMIT_REACHED; return NULL;
    }
    memory = calloc(size ? size : 1, 1);
    if (!memory) { vm->allocation_status = XXEMUL_STATUS_OUT_OF_MEMORY; return NULL; }
    vm->heap_bytes += size; return memory;
}
static xxemul_status net_allocation_failure(xxemul_dotnet_vm *vm, xxemul_status status) {
    return net_fail(vm, status, status == XXEMUL_STATUS_LIMIT_REACHED
        ? "CIL heap budget reached" : "CIL allocation failed");
}
static net_object *net_object_at(const xxemul_dotnet_vm *vm, uint64_t reference) {
    return reference && reference <= vm->object_count ? vm->objects[(size_t)reference - 1] : NULL;
}
static xxemul_status net_require_object(xxemul_dotnet_vm *vm, xxemul_dotnet_value value, net_object **out) {
    if (value.kind != XXEMUL_DOTNET_VALUE_OBJECT)
        return net_fail(vm, XXEMUL_STATUS_DECODE_ERROR, "object reference required on evaluation stack");
    *out = net_object_at(vm, value.bits);
    return *out ? XXEMUL_STATUS_OK : net_fail(vm, XXEMUL_STATUS_ADDRESS_FAULT,
        value.bits ? "invalid object handle 0x%llx" : "null object reference", (unsigned long long)value.bits);
}
static const xxemul_dotnet_class *net_class_named(const xxemul_dotnet_vm *vm, const char *name) {
    size_t i;
    for (i = 0; i < vm->program->type_count; ++i)
        if (!strcmp(vm->program->types[i].name, name)) return &vm->program->types[i];
    return NULL;
}
static int net_assignable(xxemul_dotnet_vm *vm, const char *source, const char *destination) {
    size_t depth;
    if (!strcmp(source, destination) || !strcmp(destination, "System.Object")) return 1;
    for (depth = 0; depth <= vm->program->type_count; ++depth) {
        const xxemul_dotnet_class *type = net_class_named(vm, source);
        const char *parent = type && type->extends_token
            ? xxemul_dotnet_type_name(vm->program, type->extends_token) : NULL;
        if (parent) {
            if (!strcmp(parent, destination)) return 1;
            source = parent;
        } else {
            int answer = vm->config.assignability_callback
                ? vm->config.assignability_callback(vm->config.assignability_context, source, destination) : -1;
            if (answer >= 0) return answer > 0;
            if (!strcmp(source, "System.Object")) return 0;
            type = net_class_named(vm, destination);
            return type && (type->token >> 24) == 2 ? 0 : -1;
        }
    }
    return -1;
}
static xxemul_status net_require_assignable(xxemul_dotnet_vm *vm, const char *source, const char *destination) {
    int answer = net_assignable(vm, source, destination);
    if (answer > 0) return XXEMUL_STATUS_OK;
    return net_fail(vm, answer < 0 ? XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION : XXEMUL_STATUS_ADDRESS_FAULT,
        answer < 0 ? "unknown external type relationship: %s -> %s" : "incompatible object types: %s -> %s", source, destination);
}
static xxemul_dotnet_value_kind net_type_kind(const xxemul_dotnet_type *type) {
    if (!type->supported) return XXEMUL_DOTNET_VALUE_VOID;
    switch (type->element_type) {
    case 1: return XXEMUL_DOTNET_VALUE_VOID;
    case 2: case 3: case 4: case 5: case 6: case 7: case 8: case 9: return XXEMUL_DOTNET_VALUE_I4;
    case 10: case 11: return XXEMUL_DOTNET_VALUE_I8;
    case 12: case 13: return XXEMUL_DOTNET_VALUE_F;
    case 24: case 25: return XXEMUL_DOTNET_VALUE_NATIVE;
    case 14: case 18: case 28: case 29: return XXEMUL_DOTNET_VALUE_OBJECT;
    default: return XXEMUL_DOTNET_VALUE_VOID;
    }
}
static xxemul_dotnet_type net_named_type(const char *name) {
    static const char *const names[] = {"System.Void", "System.Boolean", "System.Char", "System.SByte", "System.Byte",
        "System.Int16", "System.UInt16", "System.Int32", "System.UInt32", "System.Int64", "System.UInt64", "System.Single", "System.Double"};
    xxemul_dotnet_type type; size_t i;
    memset(&type, 0, sizeof(type)); type.name = (char *)name; type.supported = 1; type.element_type = 18;
    for (i = 0; i < sizeof(names) / sizeof(names[0]); ++i)
        if (!strcmp(name, names[i])) { type.element_type = (uint8_t)(i + 1); return type; }
    if (!strcmp(name, "System.String")) type.element_type = 14;
    if (!strcmp(name, "System.Object")) type.element_type = 28;
    if (!strcmp(name, "System.IntPtr")) type.element_type = 24;
    if (!strcmp(name, "System.UIntPtr")) type.element_type = 25;
    return type;
}
static xxemul_status net_coerce(xxemul_dotnet_vm *vm, const xxemul_dotnet_type *type,
    xxemul_dotnet_value input, xxemul_dotnet_value *output) {
    xxemul_dotnet_value_kind expected = net_type_kind(type);
    if (!type->supported || (!expected && type->element_type != 1))
        return net_fail(vm, XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION, "unsupported signature type %s", type->name);
    if (input.kind != expected)
        return net_fail(vm, XXEMUL_STATUS_DECODE_ERROR, "value kind %u does not match %s", (unsigned)input.kind, type->name);
    *output = input;
    if (expected == XXEMUL_DOTNET_VALUE_I4) {
        uint32_t bits = (uint32_t)input.bits;
        switch (type->element_type) {
        case 2: bits = bits != 0; break;
        case 3: case 7: bits = (uint16_t)bits; break;
        case 4: bits = (uint32_t)(int32_t)(int8_t)bits; break;
        case 5: bits = (uint8_t)bits; break;
        case 6: bits = (uint32_t)(int32_t)(int16_t)bits; break;
        default: break;
        }
        output->bits = bits;
    } else if (expected == XXEMUL_DOTNET_VALUE_NATIVE) output->bits = net_native_mask(vm, input.bits);
    else if (expected == XXEMUL_DOTNET_VALUE_F && type->element_type == 12) {
        double value = net_double(input.bits);
        float narrow = value > FLT_MAX ? INFINITY : value < -FLT_MAX ? -INFINITY : (float)value;
        output->bits = net_double_bits(narrow);
    } else if (expected == XXEMUL_DOTNET_VALUE_OBJECT && input.bits) {
        net_object *object;
        xxemul_status status = net_require_object(vm, input, &object);
        if (status != XXEMUL_STATUS_OK) return status;
        return net_require_assignable(vm, object->type_name, type->name);
    }
    return XXEMUL_STATUS_OK;
}
static xxemul_status net_add_object(xxemul_dotnet_vm *vm, const char *name, unsigned kind, uint32_t *reference) {
    net_object *object; size_t bytes;
    if (!vm || !name || !*name || !reference) return XXEMUL_STATUS_INVALID_ARGUMENT;
    if (vm->object_count >= UINT32_MAX) return XXEMUL_STATUS_LIMIT_REACHED;
    if (vm->object_count == vm->object_capacity) {
        size_t capacity = vm->object_capacity ? vm->object_capacity * 2 : 32;
        size_t extra; net_object **objects;
        if (capacity < vm->object_capacity || capacity > SIZE_MAX / sizeof(*objects)) return XXEMUL_STATUS_LIMIT_REACHED;
        extra = (capacity - vm->object_capacity) * sizeof(*objects);
        if (extra > vm->config.max_heap_bytes - vm->heap_bytes) return XXEMUL_STATUS_LIMIT_REACHED;
        objects = (net_object **)realloc(vm->objects, capacity * sizeof(*objects));
        if (!objects) return XXEMUL_STATUS_OUT_OF_MEMORY;
        vm->objects = objects; vm->object_capacity = capacity; vm->heap_bytes += extra;
    }
    object = (net_object *)net_alloc(vm, sizeof(*object));
    if (!object) return vm->allocation_status;
    bytes = strlen(name) + 1;
    object->type_name = (char *)net_alloc(vm, bytes);
    if (!object->type_name) { free(object); vm->heap_bytes -= sizeof(*object); return vm->allocation_status; }
    memcpy(object->type_name, name, bytes); object->kind = kind;
    vm->objects[vm->object_count++] = object; *reference = (uint32_t)vm->object_count;
    return XXEMUL_STATUS_OK;
}
xxemul_status xxemul_dotnet_vm_new_object(xxemul_dotnet_vm *vm, const char *type_name, uint32_t *reference) {
    return net_add_object(vm, type_name, 0, reference);
}
static void net_discard_last_object(xxemul_dotnet_vm *vm, uint32_t *reference) {
    net_object *object = vm->objects[--vm->object_count];
    vm->heap_bytes -= sizeof(*object) + strlen(object->type_name) + 1;
    if (object->string) vm->heap_bytes -= object->length + 1;
    if (object->elements) vm->heap_bytes -= object->length * sizeof(*object->elements);
    if (object->kind == 2 && object->element_type.name) {
        vm->heap_bytes -= strlen(object->element_type.name) + 1; free(object->element_type.name);
    }
    free(object->type_name); free(object->string); free(object->elements); free(object); *reference = 0;
}
xxemul_status xxemul_dotnet_vm_new_string(xxemul_dotnet_vm *vm, const char *utf8, size_t byte_count, uint32_t *reference) {
    xxemul_status status; net_object *object;
    if (!vm || (!utf8 && byte_count) || !reference || byte_count == SIZE_MAX) return XXEMUL_STATUS_INVALID_ARGUMENT;
    status = net_add_object(vm, "System.String", 1, reference); if (status != XXEMUL_STATUS_OK) return status;
    object = vm->objects[*reference - 1]; object->string = (char *)net_alloc(vm, byte_count + 1);
    if (!object->string) { net_discard_last_object(vm, reference); return vm->allocation_status; }
    if (byte_count) memcpy(object->string, utf8, byte_count);
    object->length = byte_count; return XXEMUL_STATUS_OK;
}
const char *xxemul_dotnet_vm_get_string(const xxemul_dotnet_vm *vm, uint32_t reference, size_t *byte_count) {
    net_object *object = vm ? net_object_at(vm, reference) : NULL;
    if (byte_count) *byte_count = 0;
    if (!object || object->kind != 1) return NULL;
    if (byte_count) *byte_count = object->length; return object->string;
}
const char *xxemul_dotnet_vm_object_type(const xxemul_dotnet_vm *vm, uint32_t reference) {
    net_object *object = vm ? net_object_at(vm, reference) : NULL;
    return object ? object->type_name : NULL;
}
xxemul_status xxemul_dotnet_vm_new_array(xxemul_dotnet_vm *vm, const char *element_type_name,
    size_t length, uint32_t *reference) {
    char *name; size_t bytes, i; net_object *object; xxemul_status status;
    xxemul_dotnet_type element;
    if (!vm || !element_type_name || !*element_type_name || !reference) return XXEMUL_STATUS_INVALID_ARGUMENT;
    element = net_named_type(element_type_name);
    { const xxemul_dotnet_class *type = net_class_named(vm, element_type_name);
      const char *parent = type && type->extends_token ? xxemul_dotnet_type_name(vm->program, type->extends_token) : NULL;
      if ((type && type->is_generic) || (parent && (!strcmp(parent, "System.ValueType") || !strcmp(parent, "System.Enum"))))
          return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION; }
    if (element.element_type == 1 || length > INT32_MAX || length > SIZE_MAX / sizeof(xxemul_dotnet_value))
        return XXEMUL_STATUS_LIMIT_REACHED;
    bytes = strlen(element_type_name);
    if (bytes > SIZE_MAX - 3) return XXEMUL_STATUS_LIMIT_REACHED;
    name = (char *)malloc(bytes + 3); if (!name) return XXEMUL_STATUS_OUT_OF_MEMORY;
    memcpy(name, element_type_name, bytes); memcpy(name + bytes, "[]", 3);
    status = net_add_object(vm, name, 2, reference); free(name);
    if (status != XXEMUL_STATUS_OK) return status;
    object = vm->objects[*reference - 1]; object->length = length;
    object->element_type = element; object->element_type.name = NULL;
    /* Keep a separately terminated element name for storage checks. */
    object->element_type.name = (char *)net_alloc(vm, bytes + 1);
    if (!object->element_type.name) { net_discard_last_object(vm, reference); return vm->allocation_status; }
    memcpy(object->element_type.name, element_type_name, bytes + 1);
    if (length) {
        object->elements = (xxemul_dotnet_value *)net_alloc(vm, length * sizeof(*object->elements));
        if (!object->elements) { net_discard_last_object(vm, reference); return vm->allocation_status; }
        for (i = 0; i < length; ++i) object->elements[i].kind = net_type_kind(&element);
    }
    return XXEMUL_STATUS_OK;
}
xxemul_status xxemul_dotnet_vm_array_set(xxemul_dotnet_vm *vm, uint32_t reference,
    size_t index, xxemul_dotnet_value value) {
    net_object *array = vm ? net_object_at(vm, reference) : NULL;
    if (!array || array->kind != 2 || index >= array->length) return XXEMUL_STATUS_ADDRESS_FAULT;
    return net_coerce(vm, &array->element_type, value, &array->elements[index]);
}

xxemul_dotnet_vm *xxemul_dotnet_vm_create(const xxemul_dotnet_program *program,
    const xxemul_dotnet_vm_config *config, xxemul_status *status) {
    xxemul_dotnet_vm *vm; size_t i;
    if (status) *status = XXEMUL_STATUS_INVALID_ARGUMENT;
    if (!program || (config && config->max_call_depth > 128)) return NULL;
    vm = (xxemul_dotnet_vm *)calloc(1, sizeof(*vm));
    if (!vm) { if (status) *status = XXEMUL_STATUS_OUT_OF_MEMORY; return NULL; }
    vm->program = program; if (config) vm->config = *config;
    if (!vm->config.max_instructions) vm->config.max_instructions = 100000;
    if (!vm->config.max_call_depth) vm->config.max_call_depth = 128;
    if (!vm->config.max_stack_values) vm->config.max_stack_values = 65536;
    if (!vm->config.max_frame_bytes) vm->config.max_frame_bytes = 8u * 1024u * 1024u;
    if (!vm->config.max_heap_bytes) vm->config.max_heap_bytes = 16u * 1024u * 1024u;
    vm->static_fields = (xxemul_dotnet_value *)calloc(program->field_count ? program->field_count : 1, sizeof(*vm->static_fields));
    vm->static_written = (uint8_t *)calloc(program->field_count ? program->field_count : 1, 1);
    vm->class_states = (uint8_t *)calloc(program->type_count ? program->type_count : 1, 1);
    vm->code_cache = (net_code_cache *)calloc(program->method_count ? program->method_count : 1, sizeof(*vm->code_cache));
    if (!vm->static_fields || !vm->static_written || !vm->class_states || !vm->code_cache) {
        xxemul_dotnet_vm_destroy(vm); if (status) *status = XXEMUL_STATUS_OUT_OF_MEMORY; return NULL;
    }
    for (i = 0; i < program->field_count; ++i) vm->static_fields[i].kind = net_type_kind(&program->fields[i].type);
    if (status) *status = XXEMUL_STATUS_OK; return vm;
}
void xxemul_dotnet_vm_destroy(xxemul_dotnet_vm *vm) {
    size_t i; if (!vm) return;
    for (i = 0; i < vm->object_count; ++i) {
        net_object *object = vm->objects[i]; net_property *property = object->properties;
        while (property) { net_property *next = property->next; free(property); property = next; }
        free(object->type_name); free(object->string); free(object->elements);
        if (object->kind == 2) free(object->element_type.name);
        free(object);
    }
    if (vm->code_cache) for (i = 0; i < vm->program->method_count; ++i) free(vm->code_cache[i].boundaries);
    free(vm->objects); free(vm->static_fields); free(vm->static_written); free(vm->class_states); free(vm->code_cache); free(vm);
}

static xxemul_status net_execute(xxemul_dotnet_vm *, size_t, const xxemul_dotnet_value *, size_t, xxemul_dotnet_value *);
static xxemul_status net_initialize(xxemul_dotnet_vm *vm, uint32_t token) {
    size_t i, owner = SIZE_MAX; xxemul_status status = XXEMUL_STATUS_OK;
    size_t caller_method = vm->result->method_index; uint32_t caller_pc = vm->result->pc;
    for (i = 0; i < vm->program->type_def_count; ++i)
        if (vm->program->types[i].token == token) { owner = i; break; }
    if (owner == SIZE_MAX) return XXEMUL_STATUS_OK;
    if (vm->class_states[owner] == 2 || vm->class_states[owner] == 1) return XXEMUL_STATUS_OK;
    if (vm->class_states[owner] == 3) return net_fail(vm, XXEMUL_STATUS_ADDRESS_FAULT, "type initializer previously failed: %s", vm->program->types[owner].name);
    if (vm->initialization_depth >= vm->config.max_call_depth)
        return net_fail(vm, XXEMUL_STATUS_LIMIT_REACHED, "type initialization depth limit reached");
    ++vm->initialization_depth; vm->class_states[owner] = 1;
    /* Only local parent initializers can be executed without a CLR host. */
    if (vm->program->types[owner].extends_token)
        status = net_initialize(vm, vm->program->types[owner].extends_token);
    if (status == XXEMUL_STATUS_OK) for (i = 0; i < vm->program->method_def_count; ++i) {
        const xxemul_dotnet_method *method = &vm->program->methods[i];
        if (method->owner_token == token && !strcmp(method->info.name, ".cctor")) {
            xxemul_dotnet_value ignored;
            if (method->signature.has_this || method->signature.parameter_count || method->signature.return_type.element_type != 1)
                status = net_fail(vm, XXEMUL_STATUS_INVALID_IMAGE, "invalid type initializer signature");
            else status = net_execute(vm, i, NULL, 0, &ignored);
            break;
        }
    }
    vm->class_states[owner] = status == XXEMUL_STATUS_OK ? 2 : 3;
    --vm->initialization_depth;
    if (status == XXEMUL_STATUS_OK) { vm->result->method_index = caller_method; vm->result->pc = caller_pc; }
    return status;
}
static xxemul_status net_push(xxemul_dotnet_vm *vm, net_frame *frame, xxemul_dotnet_value value) {
    if (frame->count >= frame->capacity)
        return net_fail(vm, XXEMUL_STATUS_DECODE_ERROR, "evaluation stack exceeds declared max_stack");
    frame->stack[frame->count++] = value; return XXEMUL_STATUS_OK;
}
static xxemul_status net_pop(xxemul_dotnet_vm *vm, net_frame *frame, xxemul_dotnet_value *value) {
    if (!frame->count) return net_fail(vm, XXEMUL_STATUS_DECODE_ERROR, "evaluation stack underflow");
    *value = frame->stack[--frame->count]; return XXEMUL_STATUS_OK;
}
static xxemul_status net_prepare_code(xxemul_dotnet_vm *vm, size_t index) {
    const xxemul_dotnet_method *method = &vm->program->methods[index];
    net_code_cache *cache = &vm->code_cache[index]; uint32_t pc = 0;
    if (cache->boundaries) return cache->status == XXEMUL_STATUS_OK ? cache->status
        : net_fail(vm, cache->status, "method contains invalid CIL encoding");
    cache->boundaries = (uint8_t *)net_alloc(vm, method->info.code_size);
    if (!cache->boundaries) return net_allocation_failure(vm, vm->allocation_status);
    while (pc < method->info.code_size) {
        xxbyte_instruction instruction;
        if (xxbyte_decode(XXBYTE_FAMILY_DOTNET, 0, method->code + pc, method->info.code_size - pc, pc, &instruction) != XXBYTE_STATUS_OK || !instruction.size) {
            cache->status = XXEMUL_STATUS_DECODE_ERROR;
            return net_fail(vm, cache->status, "invalid CIL encoding at IL_%04x", pc);
        }
        cache->boundaries[pc] = 1; pc += instruction.size;
    }
    cache->status = XXEMUL_STATUS_OK; return XXEMUL_STATUS_OK;
}
static xxemul_status net_branch(xxemul_dotnet_vm *vm, size_t method, int64_t target, uint32_t *pc) {
    if (target < 0 || (uint64_t)target >= vm->program->methods[method].info.code_size ||
        !vm->code_cache[method].boundaries[(size_t)target])
        return net_fail(vm, XXEMUL_STATUS_DECODE_ERROR, "branch target is not an instruction boundary: %lld", (long long)target);
    *pc = (uint32_t)target; return XXEMUL_STATUS_OK;
}
static unsigned net_width(const xxemul_dotnet_vm *vm, xxemul_dotnet_value value) {
    return value.kind == XXEMUL_DOTNET_VALUE_I4 || (value.kind == XXEMUL_DOTNET_VALUE_NATIVE && vm->program->pointer_size == 4) ? 32 : 64;
}
static int net_integer(xxemul_dotnet_value value) {
    return value.kind == XXEMUL_DOTNET_VALUE_I4 || value.kind == XXEMUL_DOTNET_VALUE_I8 || value.kind == XXEMUL_DOTNET_VALUE_NATIVE;
}
static uint64_t net_mask(unsigned width) { return width == 32 ? UINT32_MAX : UINT64_MAX; }
static int64_t net_signed(unsigned width, uint64_t bits) { return width == 32 ? net_s32((uint32_t)bits) : net_s64(bits); }
static xxemul_status net_binary(xxemul_dotnet_vm *vm, uint32_t opcode, xxemul_dotnet_value a, xxemul_dotnet_value b, xxemul_dotnet_value *out) {
    unsigned width; uint64_t x, y, z = 0, mask; int64_t sx, sy; int checked = 0, unsign = 0;
    if (a.kind == XXEMUL_DOTNET_VALUE_F && b.kind == a.kind) {
        double xfloat = net_double(a.bits), yfloat = net_double(b.bits), result;
        switch (opcode) {
        case 0x58: result = xfloat + yfloat; break; case 0x59: result = xfloat - yfloat; break;
        case 0x5a: result = xfloat * yfloat; break; case 0x5b: result = xfloat / yfloat; break;
        case 0x5d: result = fmod(xfloat, yfloat); break;
        default: return net_fail(vm, XXEMUL_STATUS_DECODE_ERROR, "integer operands required");
        }
        *out = net_value(a.kind, net_double_bits(result)); return XXEMUL_STATUS_OK;
    }
    if (!net_integer(a) || !net_integer(b)) return net_fail(vm, XXEMUL_STATUS_DECODE_ERROR, "numeric operands required");
    if (opcode >= 0x62 && opcode <= 0x64) {
        if (b.kind != XXEMUL_DOTNET_VALUE_I4 && b.kind != XXEMUL_DOTNET_VALUE_NATIVE)
            return net_fail(vm, XXEMUL_STATUS_DECODE_ERROR, "shift count must be int32 or native int");
    } else if (a.kind != b.kind) return net_fail(vm, XXEMUL_STATUS_DECODE_ERROR, "binary operand types differ");
    width = net_width(vm, a); mask = net_mask(width); x = a.bits & mask; y = b.bits & mask;
    sx = net_signed(width, x); sy = net_signed(width, y);
    if (opcode >= 0xd6 && opcode <= 0xdb) {
        checked = 1; unsign = opcode & 1; opcode = opcode <= 0xd7 ? 0x58 : opcode <= 0xd9 ? 0x5a : 0x59;
    }
    switch (opcode) {
    case 0x58: z = x + y; break; case 0x59: z = x - y; break; case 0x5a: z = x * y; break;
    case 0x5b: case 0x5d:
        if (!y) return net_fail(vm, XXEMUL_STATUS_ADDRESS_FAULT, "integer division by zero");
        if (sx == (width == 32 ? INT32_MIN : INT64_MIN) && sy == -1)
            return net_fail(vm, XXEMUL_STATUS_ADDRESS_FAULT, "signed division overflow");
        z = (uint64_t)(opcode == 0x5b ? sx / sy : sx % sy); break;
    case 0x5c: case 0x5e:
        if (!y) return net_fail(vm, XXEMUL_STATUS_ADDRESS_FAULT, "integer division by zero");
        z = opcode == 0x5c ? x / y : x % y; break;
    case 0x5f: z = x & y; break; case 0x60: z = x | y; break; case 0x61: z = x ^ y; break;
    case 0x62: z = x << (y & (width - 1)); break;
    case 0x63: { unsigned shift = (unsigned)y & (width - 1); z = x >> shift;
        if (shift && (x & (UINT64_C(1) << (width - 1)))) z |= mask << (width - shift); break; }
    case 0x64: z = x >> (y & (width - 1)); break;
    default: return net_fail(vm, XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION, "unsupported arithmetic opcode");
    }
    if (checked) {
        int overflow = 0;
        if (unsign) overflow = opcode == 0x58 ? x > mask - y : opcode == 0x59 ? x < y : y && x > mask / y;
        else {
            int64_t minimum = width == 32 ? INT32_MIN : INT64_MIN, maximum = width == 32 ? INT32_MAX : INT64_MAX;
            if (opcode == 0x58) overflow = (sy > 0 && sx > maximum - sy) || (sy < 0 && sx < minimum - sy);
            else if (opcode == 0x59) overflow = (sy < 0 && sx > maximum + sy) || (sy > 0 && sx < minimum + sy);
            else if (sx && sy) overflow = sx > 0 ? (sy > 0 ? sx > maximum / sy : sy < minimum / sx)
                : (sy > 0 ? sx < minimum / sy : sx < maximum / sy);
        }
        if (overflow) return net_fail(vm, XXEMUL_STATUS_ADDRESS_FAULT, "checked arithmetic overflow");
    }
    *out = net_value(a.kind, z & mask); return XXEMUL_STATUS_OK;
}
/* Relation: 0 equal, 1 greater, 2 less; unsigned floating comparisons include unordered. */
static xxemul_status net_compare(xxemul_dotnet_vm *vm, xxemul_dotnet_value a, xxemul_dotnet_value b, unsigned relation, int unsign, int *answer) {
    if (a.kind != b.kind) return net_fail(vm, XXEMUL_STATUS_DECODE_ERROR, "comparison operand types differ");
    if (a.kind == XXEMUL_DOTNET_VALUE_F) {
        double x = net_double(a.bits), y = net_double(b.bits);
        *answer = (unsign && (isnan(x) || isnan(y))) || (relation == 0 ? x == y : relation == 1 ? x > y : x < y);
    } else if (a.kind == XXEMUL_DOTNET_VALUE_OBJECT) {
        if (relation && !(unsign && relation == 1 && b.bits == 0))
            return net_fail(vm, XXEMUL_STATUS_DECODE_ERROR, "invalid object relational comparison");
        if ((a.bits && !net_object_at(vm, a.bits)) || (b.bits && !net_object_at(vm, b.bits)))
            return net_fail(vm, XXEMUL_STATUS_ADDRESS_FAULT, "invalid object comparison handle");
        *answer = relation ? a.bits != 0 : a.bits == b.bits;
    } else if (net_integer(a)) {
        unsigned width = net_width(vm, a); uint64_t x = a.bits & net_mask(width), y = b.bits & net_mask(width);
        *answer = relation == 0 ? x == y : unsign ? (relation == 1 ? x > y : x < y)
            : (relation == 1 ? net_signed(width, x) > net_signed(width, y) : net_signed(width, x) < net_signed(width, y));
    } else return net_fail(vm, XXEMUL_STATUS_DECODE_ERROR, "invalid comparison operands");
    return XXEMUL_STATUS_OK;
}
static xxemul_status net_convert(xxemul_dotnet_vm *vm, uint32_t opcode, xxemul_dotnet_value input, xxemul_dotnet_value *out) {
    unsigned width = 0; int sign = 1, checked = 0, source_unsigned = 0, floating = 0;
    xxemul_dotnet_value_kind kind = XXEMUL_DOTNET_VALUE_I4; uint64_t bits; long double numeric;
    if (!net_integer(input) && input.kind != XXEMUL_DOTNET_VALUE_F)
        return net_fail(vm, XXEMUL_STATUS_DECODE_ERROR, "conversion requires a numeric operand");
    switch (opcode) {
    case 0x67: width = 8; break; case 0x68: width = 16; break; case 0x69: width = 32; break;
    case 0x6a: width = 64; kind = XXEMUL_DOTNET_VALUE_I8; break;
    case 0x6b: floating = 4; break; case 0x6c: floating = 8; break; case 0x76: floating = 8; source_unsigned = 1; break;
    case 0x6d: width = 32; sign = 0; break; case 0x6e: width = 64; sign = 0; kind = XXEMUL_DOTNET_VALUE_I8; break;
    case 0xd1: width = 16; sign = 0; break; case 0xd2: width = 8; sign = 0; break;
    case 0xd3: case 0xe0: width = vm->program->pointer_size * 8; sign = opcode == 0xd3; kind = XXEMUL_DOTNET_VALUE_NATIVE; break;
    case 0xd4: case 0xd5: width = vm->program->pointer_size * 8; sign = opcode == 0xd4; kind = XXEMUL_DOTNET_VALUE_NATIVE; checked = 1; break;
    default:
        checked = 1;
        if (opcode >= 0x82 && opcode <= 0x8b) {
            static const unsigned widths[] = {8,16,32,64,8,16,32,64,0,0};
            unsigned index = opcode - 0x82; width = widths[index]; sign = index < 4 || index == 8; source_unsigned = 1;
            if (index == 3 || index == 7) kind = XXEMUL_DOTNET_VALUE_I8;
            if (index >= 8) { kind = XXEMUL_DOTNET_VALUE_NATIVE; width = vm->program->pointer_size * 8; }
        } else if (opcode >= 0xb3 && opcode <= 0xba) {
            unsigned index = opcode - 0xb3; width = 8u << (index / 2); sign = !(index & 1);
            if (index >= 6) kind = XXEMUL_DOTNET_VALUE_I8;
        } else return net_fail(vm, XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION, "unsupported conversion");
    }
    if (input.kind == XXEMUL_DOTNET_VALUE_F) numeric = (long double)net_double(input.bits);
    else {
        unsigned source_width = net_width(vm, input); uint64_t source = input.bits & net_mask(source_width);
        numeric = source_unsigned ? (long double)source : (long double)net_signed(source_width, source);
    }
    if (floating) {
        double number = (double)numeric;
        if (floating == 4) number = number > FLT_MAX ? INFINITY : number < -FLT_MAX ? -INFINITY : (float)number;
        *out = net_value(XXEMUL_DOTNET_VALUE_F, net_double_bits(number)); return XXEMUL_STATUS_OK;
    }
    if (checked && net_integer(input)) {
        unsigned source_width = net_width(vm, input); uint64_t source = input.bits & net_mask(source_width);
        int64_t signed_source = net_signed(source_width, source);
        uint64_t maximum = sign ? (width == 64 ? (uint64_t)INT64_MAX : (UINT64_C(1) << (width - 1)) - 1) : net_mask(width);
        int overflow;
        if (source_unsigned) { overflow = source > maximum; bits = source; }
        else if (signed_source < 0) {
            int64_t minimum = width == 64 ? INT64_MIN : -(INT64_C(1) << (width - 1));
            overflow = !sign || signed_source < minimum; bits = (uint64_t)signed_source;
        } else { overflow = (uint64_t)signed_source > maximum; bits = (uint64_t)signed_source; }
        if (overflow) return net_fail(vm, XXEMUL_STATUS_ADDRESS_FAULT, "numeric conversion overflow");
    } else if (input.kind == XXEMUL_DOTNET_VALUE_F) {
        long double lower = sign ? -ldexpl(1.0L, (int)width - 1) : 0;
        long double upper = ldexpl(1.0L, (int)width - (sign ? 1 : 0));
        numeric = truncl(numeric);
        if (!isfinite(numeric) || numeric < lower || numeric >= upper)
            return net_fail(vm, XXEMUL_STATUS_ADDRESS_FAULT, "numeric conversion overflow");
        bits = numeric < 0 ? (uint64_t)(int64_t)numeric : (uint64_t)numeric;
    } else {
        unsigned source_width = net_width(vm, input);
        bits = (uint64_t)net_signed(source_width, input.bits);
    }
    if (width < 64) {
        uint64_t mask = (UINT64_C(1) << width) - 1; bits &= mask;
        if (sign && (bits & (UINT64_C(1) << (width - 1)))) bits |= ~mask;
    }
    if (kind == XXEMUL_DOTNET_VALUE_I4) bits = (uint32_t)bits;
    *out = net_value(kind, bits); return XXEMUL_STATUS_OK;
}

static xxemul_status net_field(xxemul_dotnet_vm *vm, net_frame *frame, uint32_t opcode, uint32_t token) {
    size_t index; const xxemul_dotnet_field *field; xxemul_dotnet_value value = {0, XXEMUL_DOTNET_VALUE_VOID}, receiver; net_object *object; net_property *property;
    xxemul_status status; int store = opcode == 0x7d || opcode == 0x80, is_static = opcode == 0x7e || opcode == 0x80;
    if ((token >> 24) != 4 || !(token & 0xffffff) || (token & 0xffffff) > vm->program->field_count)
        return net_fail(vm, XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION, "field token 0x%08x is not a local FieldDef", token);
    index = (token & 0xffffff) - 1; field = &vm->program->fields[index];
    if (!!(field->flags & 0x10) != is_static) return net_fail(vm, XXEMUL_STATUS_DECODE_ERROR, "field static/instance opcode mismatch");
    if (!field->type.supported) return net_fail(vm, XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION, "unsupported field type %s", field->type.name);
    if (store && (status = net_pop(vm, frame, &value)) != XXEMUL_STATUS_OK) return status;
    if (is_static) {
        if ((status = net_initialize(vm, field->owner_token)) != XXEMUL_STATUS_OK) return status;
        if (store) {
            if ((status = net_coerce(vm, &field->type, value, &vm->static_fields[index])) == XXEMUL_STATUS_OK) vm->static_written[index] = 1;
            return status;
        }
        if ((field->flags & (0x8000 | 0x100)) && !vm->static_written[index])
            return net_fail(vm, XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION, "constant/RVA field initialization unsupported: %s", field->name);
        return net_push(vm, frame, vm->static_fields[index]);
    }
    if ((status = net_pop(vm, frame, &receiver)) != XXEMUL_STATUS_OK ||
        (status = net_require_object(vm, receiver, &object)) != XXEMUL_STATUS_OK) return status;
    if ((status = net_require_assignable(vm, object->type_name, xxemul_dotnet_type_name(vm->program, field->owner_token))) != XXEMUL_STATUS_OK) return status;
    for (property = object->properties; property; property = property->next) if (property->field == index) break;
    if (store) {
        xxemul_dotnet_value coerced;
        if ((status = net_coerce(vm, &field->type, value, &coerced)) != XXEMUL_STATUS_OK) return status;
        if (!property) {
            property = (net_property *)net_alloc(vm, sizeof(*property));
            if (!property) return net_allocation_failure(vm, vm->allocation_status);
            property->field = index; property->next = object->properties; object->properties = property;
        }
        property->value = coerced; return XXEMUL_STATUS_OK;
    }
    if (!property && (field->flags & (0x8000 | 0x100)))
        return net_fail(vm, XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION, "constant/RVA field initialization unsupported: %s", field->name);
    return net_push(vm, frame, property ? property->value : net_value(net_type_kind(&field->type), 0));
}
static xxemul_status net_array(xxemul_dotnet_vm *vm, net_frame *frame, uint32_t opcode, uint32_t token) {
    xxemul_dotnet_value value = {0, XXEMUL_DOTNET_VALUE_VOID}, index, receiver, normalized; net_object *array; xxemul_status status;
    int store = (opcode >= 0x9b && opcode <= 0xa2) || opcode == 0xa4; unsigned element = 0;
    xxemul_dotnet_type requested;
    if (store && (status = net_pop(vm, frame, &value)) != XXEMUL_STATUS_OK) return status;
    if ((status = net_pop(vm, frame, &index)) != XXEMUL_STATUS_OK || (status = net_pop(vm, frame, &receiver)) != XXEMUL_STATUS_OK ||
        (status = net_require_object(vm, receiver, &array)) != XXEMUL_STATUS_OK) return status;
    if (!net_integer(index) || index.kind == XXEMUL_DOTNET_VALUE_I8)
        return net_fail(vm, XXEMUL_STATUS_DECODE_ERROR, "array index must be int32 or native int");
    if (array->kind != 2 || index.bits >= array->length)
        return net_fail(vm, XXEMUL_STATUS_ADDRESS_FAULT, "array index outside vector bounds");
    if (opcode == 0xa3 || opcode == 0xa4) {
        const char *name = xxemul_dotnet_type_name(vm->program, token);
        if (!name) return net_fail(vm, XXEMUL_STATUS_INVALID_IMAGE, "invalid array element type token");
        requested = net_named_type(name);
        if (strcmp(name, array->element_type.name)) return net_fail(vm, XXEMUL_STATUS_DECODE_ERROR, "array element token/type mismatch");
    } else {
        static const uint8_t load_types[] = {4,5,6,7,8,9,10,24,12,13,28};
        static const uint8_t store_types[] = {24,4,6,8,10,12,13,28};
        element = store ? store_types[opcode - 0x9b] : load_types[opcode - 0x90];
        requested = array->element_type; requested.element_type = (uint8_t)element;
        if (element == 28) {
            if (net_type_kind(&array->element_type) != XXEMUL_DOTNET_VALUE_OBJECT)
                return net_fail(vm, XXEMUL_STATUS_DECODE_ERROR, "reference array required");
        } else {
            unsigned actual = array->element_type.element_type;
            unsigned actual_width = actual == 2 || actual == 4 || actual == 5 ? 1 : actual == 3 || actual == 6 || actual == 7 ? 2
                : actual == 8 || actual == 9 || actual == 12 ? 4 : actual == 10 || actual == 11 || actual == 13 ? 8 : vm->program->pointer_size;
            unsigned expected_width = element == 4 || element == 5 ? 1 : element == 6 || element == 7 ? 2
                : element == 8 || element == 9 || element == 12 ? 4 : element == 10 || element == 13 ? 8 : vm->program->pointer_size;
            if (actual_width != expected_width || net_type_kind(&requested) != net_type_kind(&array->element_type))
                return net_fail(vm, XXEMUL_STATUS_DECODE_ERROR, "array opcode/type mismatch");
        }
    }
    if (store) {
        if ((status = net_coerce(vm, &array->element_type, value, &normalized)) != XXEMUL_STATUS_OK) return status;
        array->elements[(size_t)index.bits] = normalized; return XXEMUL_STATUS_OK;
    }
    if ((status = net_coerce(vm, &requested, array->elements[(size_t)index.bits], &normalized)) != XXEMUL_STATUS_OK) return status;
    return net_push(vm, frame, normalized);
}
static size_t net_virtual_target(xxemul_dotnet_vm *vm, size_t target, const net_object *object) {
    const xxemul_dotnet_method *requested = &vm->program->methods[target]; const char *name = object->type_name; size_t depth, i, selected = target;
    /* External metadata does not expose its virtual slots; its callback owns
       the external dispatch. Local methods have enough flags for slot checks. */
    if (!(requested->info.flags & 0x40) || (requested->info.flags & 0x20)) return target;
    for (depth = 0; depth <= vm->program->type_count; ++depth) {
        const xxemul_dotnet_class *type = net_class_named(vm, name);
        for (i = 0; i < vm->program->method_def_count; ++i) {
            const xxemul_dotnet_method *candidate = &vm->program->methods[i];
            if (candidate->signature.has_this && (candidate->info.flags & 0x40) && !strcmp(candidate->info.type_name, name) &&
                !strcmp(candidate->info.name, requested->info.name) && !strcmp(candidate->info.signature, requested->info.signature)) {
                if (candidate->owner_token != requested->owner_token && (candidate->info.flags & 0x100))
                    selected = target; /* Overrides below this newslot belong to another slot. */
                else if (selected == target) selected = i;
                break;
            }
        }
        if (type && type->token == requested->owner_token) return selected;
        name = type && type->extends_token ? xxemul_dotnet_type_name(vm->program, type->extends_token) : NULL;
        if (!name) break;
    }
    return target; /* Missing external ancestry cannot prove local slot dispatch. */
}
static xxemul_status net_call(xxemul_dotnet_vm *vm, net_frame *frame, uint32_t opcode, uint32_t token) {
    size_t target = xxemul_dotnet_resolve_token(vm->program, token), count, begin; const xxemul_dotnet_method *method;
    xxemul_dotnet_value result; xxemul_status status;
    size_t caller_method = vm->result->method_index; uint32_t caller_pc = vm->result->pc;
    if (target == SIZE_MAX) return net_fail(vm, XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION, "unresolved method token 0x%08x", token);
    method = &vm->program->methods[target]; count = method->signature.parameter_count + (method->signature.has_this ? 1u : 0u);
    if (opcode == 0x73) {
        xxemul_dotnet_value *arguments; uint32_t reference; size_t bytes;
        if (strcmp(method->info.name, ".ctor") || !method->signature.has_this || method->signature.return_type.element_type != 1)
            return net_fail(vm, XXEMUL_STATUS_DECODE_ERROR, "newobj requires an instance constructor");
        if (!count || frame->count < count - 1) return net_fail(vm, XXEMUL_STATUS_DECODE_ERROR, "constructor argument stack underflow");
        if (count > SIZE_MAX / sizeof(*arguments)) return net_fail(vm, XXEMUL_STATUS_LIMIT_REACHED, "constructor arguments exceed frame budget");
        bytes = count * sizeof(*arguments);
        if (bytes > vm->config.max_frame_bytes - vm->frame_bytes) return net_fail(vm, XXEMUL_STATUS_LIMIT_REACHED, "constructor arguments exceed frame budget");
        if ((status = net_initialize(vm, method->owner_token)) != XXEMUL_STATUS_OK) return status;
        { const xxemul_dotnet_class *type = net_class_named(vm, method->info.type_name);
          const char *parent = type && type->extends_token ? xxemul_dotnet_type_name(vm->program, type->extends_token) : NULL;
          if ((type && (type->is_generic || (type->flags & (0x20 | 0x80)))) || (parent && (!strcmp(parent, "System.ValueType") || !strcmp(parent, "System.Enum"))))
              return net_fail(vm, XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION, "abstract/interface/generic/value-type construction unsupported"); }
        status = xxemul_dotnet_vm_new_object(vm, method->info.type_name, &reference);
        if (status != XXEMUL_STATUS_OK) return net_allocation_failure(vm, status);
        arguments = (xxemul_dotnet_value *)malloc(bytes); if (!arguments) return net_allocation_failure(vm, XXEMUL_STATUS_OUT_OF_MEMORY);
        vm->frame_bytes += bytes; arguments[0] = net_value(XXEMUL_DOTNET_VALUE_OBJECT, reference);
        begin = frame->count - (count - 1); if (count > 1) memcpy(arguments + 1, frame->stack + begin, (count - 1) * sizeof(*arguments));
        frame->count = begin; status = net_execute(vm, target, arguments, count, &result);
        vm->frame_bytes -= bytes; free(arguments);
        if (status == XXEMUL_STATUS_OK) { vm->result->method_index = caller_method; vm->result->pc = caller_pc; }
        return status == XXEMUL_STATUS_OK ? net_push(vm, frame, net_value(XXEMUL_DOTNET_VALUE_OBJECT, reference)) : status;
    }
    if (frame->count < count) return net_fail(vm, XXEMUL_STATUS_DECODE_ERROR, "call argument stack underflow");
    begin = frame->count - count;
    if (opcode == 0x6f) {
        net_object *object; const char *class_name; size_t depth;
        if (!method->signature.has_this) return net_fail(vm, XXEMUL_STATUS_DECODE_ERROR, "callvirt requires instance method");
        if ((status = net_require_object(vm, frame->stack[begin], &object)) != XXEMUL_STATUS_OK) return status;
        if ((status = net_require_assignable(vm, object->type_name, method->info.type_name)) != XXEMUL_STATUS_OK) return status;
        class_name = object->type_name;
        for (depth = 0; class_name && depth <= vm->program->type_count; ++depth) {
            const xxemul_dotnet_class *type = net_class_named(vm, class_name);
            if (type && type->has_method_impl)
                return net_fail(vm, XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION, "explicit MethodImpl virtual slots unsupported: %s", class_name);
            class_name = type && type->extends_token ? xxemul_dotnet_type_name(vm->program, type->extends_token) : NULL;
        }
        target = net_virtual_target(vm, target, object);
    }
    status = net_execute(vm, target, frame->stack + begin, count, &result); frame->count = begin;
    if (status != XXEMUL_STATUS_OK) return status;
    vm->result->method_index = caller_method; vm->result->pc = caller_pc;
    return result.kind == XXEMUL_DOTNET_VALUE_VOID ? XXEMUL_STATUS_OK : net_push(vm, frame, result);
}

static xxemul_status net_body(xxemul_dotnet_vm *vm, size_t method_index, net_frame *frame, xxemul_dotnet_value *result) {
    const xxemul_dotnet_method *method = &vm->program->methods[method_index]; uint32_t pc = 0;
    while (pc < method->info.code_size) {
        xxbyte_instruction instruction; uint32_t opcode, next, token; uint64_t operand; xxemul_status status = XXEMUL_STATUS_OK;
        xxemul_dotnet_value a, b, value; size_t index; int answer;
        vm->result->method_index = method_index; vm->result->pc = pc;
        if (vm->result->instructions >= vm->config.max_instructions)
            return net_fail(vm, XXEMUL_STATUS_LIMIT_REACHED, "CIL instruction limit reached");
        if (xxbyte_decode(XXBYTE_FAMILY_DOTNET, 0, method->code + pc, method->info.code_size - pc, pc, &instruction) != XXBYTE_STATUS_OK)
            return net_fail(vm, XXEMUL_STATUS_DECODE_ERROR, "invalid CIL encoding at IL_%04x", pc);
        ++vm->result->instructions;
        if (vm->config.trace_callback) vm->config.trace_callback(vm->config.trace_context, &method->info, pc, instruction.mnemonic);
        opcode = instruction.opcode; operand = instruction.operand_count ? (uint64_t)instruction.operands[0].value : 0;
        token = (uint32_t)operand; next = pc + instruction.size;
        if (opcode == 0x00) { pc = next; continue; }
        if ((opcode >= 0x02 && opcode <= 0x05) || opcode == 0x0e || opcode == 0xfe09) {
            index = (size_t)operand;
            if (index >= method->signature.parameter_count + (method->signature.has_this ? 1u : 0u))
                return net_fail(vm, XXEMUL_STATUS_DECODE_ERROR, "argument index out of bounds");
            status = net_push(vm, frame, frame->arguments[index]);
        } else if (opcode == 0x10 || opcode == 0xfe0b) {
            index = (size_t)operand;
            if (index >= method->signature.parameter_count + (method->signature.has_this ? 1u : 0u))
                return net_fail(vm, XXEMUL_STATUS_DECODE_ERROR, "argument index out of bounds");
            if ((status = net_pop(vm, frame, &value)) == XXEMUL_STATUS_OK) {
                if (method->signature.has_this && !index) {
                    xxemul_dotnet_type receiver = net_named_type(method->info.type_name);
                    status = net_coerce(vm, &receiver, value, &frame->arguments[index]);
                } else status = net_coerce(vm, &method->signature.parameters[index - (method->signature.has_this ? 1u : 0u)], value, &frame->arguments[index]);
            }
        } else if ((opcode >= 0x06 && opcode <= 0x09) || opcode == 0x11 || opcode == 0xfe0c) {
            index = (size_t)operand;
            if (index >= method->local_count) return net_fail(vm, XXEMUL_STATUS_DECODE_ERROR, "local index out of bounds");
            if (frame->locals[index].kind == XXEMUL_DOTNET_VALUE_VOID)
                return net_fail(vm, XXEMUL_STATUS_DECODE_ERROR, "read of uninitialized local");
            status = net_push(vm, frame, frame->locals[index]);
        } else if ((opcode >= 0x0a && opcode <= 0x0d) || opcode == 0x13 || opcode == 0xfe0e) {
            index = (size_t)operand;
            if (index >= method->local_count) return net_fail(vm, XXEMUL_STATUS_DECODE_ERROR, "local index out of bounds");
            if ((status = net_pop(vm, frame, &value)) == XXEMUL_STATUS_OK)
                status = net_coerce(vm, &method->locals[index], value, &frame->locals[index]);
        } else if (opcode == 0x14) status = net_push(vm, frame, net_value(XXEMUL_DOTNET_VALUE_OBJECT, 0));
        else if (opcode >= 0x15 && opcode <= 0x20) status = net_push(vm, frame, net_value(XXEMUL_DOTNET_VALUE_I4, (uint32_t)operand));
        else if (opcode == 0x21) status = net_push(vm, frame, net_value(XXEMUL_DOTNET_VALUE_I8, operand));
        else if (opcode == 0x22 || opcode == 0x23) {
            if (opcode == 0x22) { uint32_t bits = (uint32_t)operand; float narrow; memcpy(&narrow, &bits, 4); operand = net_double_bits(narrow); }
            status = net_push(vm, frame, net_value(XXEMUL_DOTNET_VALUE_F, operand));
        } else if (opcode == 0x25) {
            if (!frame->count) return net_fail(vm, XXEMUL_STATUS_DECODE_ERROR, "dup on empty evaluation stack");
            status = net_push(vm, frame, frame->stack[frame->count - 1]);
        } else if (opcode == 0x26) status = net_pop(vm, frame, &value);
        else if (opcode == 0x28 || opcode == 0x6f || opcode == 0x73) status = net_call(vm, frame, opcode, token);
        else if (opcode == 0x2a) {
            size_t expected = method->signature.return_type.element_type == 1 ? 0 : 1;
            if (frame->count != expected) return net_fail(vm, XXEMUL_STATUS_DECODE_ERROR, "ret requires exactly %u evaluation stack values", (unsigned)expected);
            if (!expected) { *result = net_value(XXEMUL_DOTNET_VALUE_VOID, 0); return XXEMUL_STATUS_OK; }
            return net_coerce(vm, &method->signature.return_type, frame->stack[0], result);
        } else if ((opcode >= 0x2b && opcode <= 0x44)) {
            unsigned branch = opcode >= 0x38 ? opcode - 0x38 : opcode - 0x2b;
            answer = 1;
            if (branch == 1 || branch == 2) {
                if ((status = net_pop(vm, frame, &value)) != XXEMUL_STATUS_OK) return status;
                if (!net_integer(value) && value.kind != XXEMUL_DOTNET_VALUE_OBJECT)
                    return net_fail(vm, XXEMUL_STATUS_DECODE_ERROR, "conditional branch requires integer or reference");
                if (value.kind == XXEMUL_DOTNET_VALUE_OBJECT && value.bits && !net_object_at(vm, value.bits))
                    return net_fail(vm, XXEMUL_STATUS_ADDRESS_FAULT, "invalid branch object handle");
                answer = branch == 1 ? !value.bits : !!value.bits;
            } else if (branch >= 3) {
                unsigned relation = 0; int unsign = branch >= 8, invert = 0;
                if ((status = net_pop(vm, frame, &b)) != XXEMUL_STATUS_OK || (status = net_pop(vm, frame, &a)) != XXEMUL_STATUS_OK) return status;
                switch (branch) {
                case 3: relation = 0; break; case 4: relation = 2; invert = 1; break;
                case 5: relation = 1; break; case 6: relation = 1; invert = 1; break; case 7: relation = 2; break;
                case 8: relation = 0; invert = 1; unsign = 0; break;
                case 9: relation = 2; invert = 1; break; case 10: relation = 1; break;
                case 11: relation = 1; invert = 1; break; case 12: relation = 2; break;
                default: return net_fail(vm, XXEMUL_STATUS_DECODE_ERROR, "invalid conditional branch");
                }
                /* >= and <= invert the complementary comparison. For floating
                   operands invert unordered as well to preserve ordered branches. */
                if (invert && branch != 8 && a.kind == XXEMUL_DOTNET_VALUE_F) unsign = !unsign;
                if ((status = net_compare(vm, a, b, relation, unsign, &answer)) != XXEMUL_STATUS_OK) return status;
                if (invert) answer = !answer;
            }
            if (answer) status = net_branch(vm, method_index, (int64_t)operand, &next);
        } else if (opcode == 0x45) {
            if ((status = net_pop(vm, frame, &value)) != XXEMUL_STATUS_OK) return status;
            if (value.kind != XXEMUL_DOTNET_VALUE_I4) return net_fail(vm, XXEMUL_STATUS_DECODE_ERROR, "switch requires int32");
            if ((uint32_t)value.bits < instruction.table_count) {
                int64_t key, target;
                if (xxbyte_switch_entry(&instruction, (uint32_t)value.bits, &key, &target) != XXBYTE_STATUS_OK)
                    return net_fail(vm, XXEMUL_STATUS_DECODE_ERROR, "invalid switch table");
                status = net_branch(vm, method_index, target, &next);
            }
        } else if ((opcode >= 0x58 && opcode <= 0x64) || (opcode >= 0xd6 && opcode <= 0xdb)) {
            if ((status = net_pop(vm, frame, &b)) == XXEMUL_STATUS_OK && (status = net_pop(vm, frame, &a)) == XXEMUL_STATUS_OK &&
                (status = net_binary(vm, opcode, a, b, &value)) == XXEMUL_STATUS_OK) status = net_push(vm, frame, value);
        } else if (opcode == 0x65 || opcode == 0x66) {
            if ((status = net_pop(vm, frame, &value)) != XXEMUL_STATUS_OK) return status;
            if (value.kind == XXEMUL_DOTNET_VALUE_F && opcode == 0x65) value.bits = net_double_bits(-net_double(value.bits));
            else if (net_integer(value)) value.bits = (opcode == 0x65 ? UINT64_C(0) - value.bits : ~value.bits) & net_mask(net_width(vm, value));
            else return net_fail(vm, XXEMUL_STATUS_DECODE_ERROR, "invalid unary numeric operand");
            status = net_push(vm, frame, value);
        } else if ((opcode >= 0x67 && opcode <= 0x6e) || opcode == 0x76 || (opcode >= 0x82 && opcode <= 0x8b) ||
            (opcode >= 0xb3 && opcode <= 0xba) || (opcode >= 0xd1 && opcode <= 0xd5) || opcode == 0xe0) {
            if ((status = net_pop(vm, frame, &a)) == XXEMUL_STATUS_OK && (status = net_convert(vm, opcode, a, &value)) == XXEMUL_STATUS_OK)
                status = net_push(vm, frame, value);
        } else if (opcode >= 0xfe01 && opcode <= 0xfe05) {
            if ((status = net_pop(vm, frame, &b)) == XXEMUL_STATUS_OK && (status = net_pop(vm, frame, &a)) == XXEMUL_STATUS_OK &&
                (status = net_compare(vm, a, b, opcode == 0xfe01 ? 0 : opcode <= 0xfe03 ? 1 : 2, opcode == 0xfe03 || opcode == 0xfe05, &answer)) == XXEMUL_STATUS_OK)
                status = net_push(vm, frame, net_value(XXEMUL_DOTNET_VALUE_I4, (unsigned)answer));
        } else if (opcode == 0x72) {
            size_t bytes, i; const char *text = xxemul_dotnet_user_string(vm->program, token, &bytes); uint32_t reference = 0;
            if (!text) return net_fail(vm, XXEMUL_STATUS_INVALID_IMAGE, "invalid user string token 0x%08x", token);
            for (i = 0; i < vm->object_count; ++i) {
                net_object *object = vm->objects[i];
                if (object->kind == 1 && object->length == bytes && !memcmp(object->string, text, bytes)) { reference = (uint32_t)i + 1; break; }
            }
            if (!reference && (status = xxemul_dotnet_vm_new_string(vm, text, bytes, &reference)) != XXEMUL_STATUS_OK) return net_allocation_failure(vm, status);
            status = net_push(vm, frame, net_value(XXEMUL_DOTNET_VALUE_OBJECT, reference));
        } else if (opcode == 0x74 || opcode == 0x75) {
            const char *name = xxemul_dotnet_type_name(vm->program, token); net_object *object;
            if (!name) return net_fail(vm, XXEMUL_STATUS_INVALID_IMAGE, "invalid cast type token");
            if ((status = net_pop(vm, frame, &value)) != XXEMUL_STATUS_OK) return status;
            if (value.kind != XXEMUL_DOTNET_VALUE_OBJECT) return net_fail(vm, XXEMUL_STATUS_DECODE_ERROR, "cast requires reference");
            if (value.bits) {
                if ((status = net_require_object(vm, value, &object)) != XXEMUL_STATUS_OK) return status;
                answer = net_assignable(vm, object->type_name, name);
                if (answer < 0) return net_fail(vm, XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION, "unknown cast relationship: %s -> %s", object->type_name, name);
                if (!answer) { if (opcode == 0x74) return net_fail(vm, XXEMUL_STATUS_ADDRESS_FAULT, "invalid object cast"); value.bits = 0; }
            }
            status = net_push(vm, frame, value);
        } else if (opcode == 0x7b || opcode == 0x7d || opcode == 0x7e || opcode == 0x80) status = net_field(vm, frame, opcode, token);
        else if (opcode == 0x8d) {
            const char *name = xxemul_dotnet_type_name(vm->program, token); uint32_t reference;
            if (!name) return net_fail(vm, XXEMUL_STATUS_INVALID_IMAGE, "invalid newarr type token");
            if ((status = net_pop(vm, frame, &value)) != XXEMUL_STATUS_OK) return status;
            if ((value.kind != XXEMUL_DOTNET_VALUE_I4 && value.kind != XXEMUL_DOTNET_VALUE_NATIVE) || value.bits > INT32_MAX)
                return net_fail(vm, XXEMUL_STATUS_ADDRESS_FAULT, "invalid vector length");
            status = xxemul_dotnet_vm_new_array(vm, name, (size_t)value.bits, &reference);
            if (status != XXEMUL_STATUS_OK) return net_allocation_failure(vm, status);
            status = net_push(vm, frame, net_value(XXEMUL_DOTNET_VALUE_OBJECT, reference));
        } else if (opcode == 0x8e) {
            net_object *array;
            if ((status = net_pop(vm, frame, &value)) != XXEMUL_STATUS_OK || (status = net_require_object(vm, value, &array)) != XXEMUL_STATUS_OK) return status;
            if (array->kind != 2) return net_fail(vm, XXEMUL_STATUS_DECODE_ERROR, "ldlen requires vector");
            status = net_push(vm, frame, net_value(XXEMUL_DOTNET_VALUE_NATIVE, array->length));
        } else if ((opcode >= 0x90 && opcode <= 0xa4)) status = net_array(vm, frame, opcode, token);
        else if (opcode == 0x8c || opcode == 0xa5) {
            const char *name = xxemul_dotnet_type_name(vm->program, token); xxemul_dotnet_type type; net_object *object;
            if (!name) return net_fail(vm, XXEMUL_STATUS_INVALID_IMAGE, "invalid boxing type token");
            type = net_named_type(name);
            if ((status = net_pop(vm, frame, &value)) != XXEMUL_STATUS_OK) return status;
            if (net_type_kind(&type) == XXEMUL_DOTNET_VALUE_OBJECT) {
                status = net_coerce(vm, &type, value, &a); if (status == XXEMUL_STATUS_OK) status = net_push(vm, frame, a);
            } else if (opcode == 0x8c) {
                uint32_t reference;
                if ((status = net_coerce(vm, &type, value, &a)) != XXEMUL_STATUS_OK) return status;
                if ((status = net_add_object(vm, name, 3, &reference)) != XXEMUL_STATUS_OK) return net_allocation_failure(vm, status);
                vm->objects[reference - 1]->boxed = a; status = net_push(vm, frame, net_value(XXEMUL_DOTNET_VALUE_OBJECT, reference));
            } else {
                if ((status = net_require_object(vm, value, &object)) != XXEMUL_STATUS_OK) return status;
                if (object->kind != 3 || strcmp(object->type_name, name)) return net_fail(vm, XXEMUL_STATUS_ADDRESS_FAULT, "unbox.any type mismatch");
                status = net_push(vm, frame, object->boxed);
            }
        } else if (opcode == 0xc3) {
            if ((status = net_pop(vm, frame, &value)) != XXEMUL_STATUS_OK) return status;
            if (value.kind != XXEMUL_DOTNET_VALUE_F) return net_fail(vm, XXEMUL_STATUS_DECODE_ERROR, "ckfinite requires floating operand");
            if (!isfinite(net_double(value.bits))) return net_fail(vm, XXEMUL_STATUS_ADDRESS_FAULT, "non-finite floating operand");
            status = net_push(vm, frame, value);
        } else return net_fail(vm, XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION, "unsupported CIL %s (0x%x) at IL_%04x", instruction.mnemonic, opcode, pc);
        if (status != XXEMUL_STATUS_OK) return status;
        pc = next;
    }
    return net_fail(vm, XXEMUL_STATUS_DECODE_ERROR, "method falls off the end without ret");
}

static xxemul_status net_execute(xxemul_dotnet_vm *vm, size_t index, const xxemul_dotnet_value *arguments,
    size_t argument_count, xxemul_dotnet_value *result) {
    const xxemul_dotnet_method *method = &vm->program->methods[index]; net_frame frame; size_t count, bytes, i;
    xxemul_status status;
    vm->result->method_index = index; vm->result->pc = 0;
    if (vm->depth >= vm->config.max_call_depth) return net_fail(vm, XXEMUL_STATUS_LIMIT_REACHED, "CIL call depth limit reached");
    if (!method->signature.supported || method->signature.generic || method->signature.vararg || method->signature.explicit_this)
        return net_fail(vm, XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION, "unsupported method signature: %s", method->info.selector);
    { const xxemul_dotnet_class *owner = net_class_named(vm, method->info.type_name);
      if (owner && owner->is_generic) return net_fail(vm, XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION, "generic declaring type unsupported: %s", owner->name); }
    count = method->signature.parameter_count + (method->signature.has_this ? 1u : 0u);
    if (argument_count != count) return net_fail(vm, XXEMUL_STATUS_INVALID_ARGUMENT, "method expects %u arguments, received %u", (unsigned)count, (unsigned)argument_count);
    if (method->signature.has_this) {
        net_object *object;
        if ((status = net_require_object(vm, arguments[0], &object)) != XXEMUL_STATUS_OK) return status;
        if ((status = net_require_assignable(vm, object->type_name, method->info.type_name)) != XXEMUL_STATUS_OK) return status;
    }
    if (method->info.has_exception_handlers) return net_fail(vm, XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION, "exception handlers are unsupported: %s", method->info.selector);
    if (count > SIZE_MAX - method->local_count || count + method->local_count > SIZE_MAX - method->info.max_stack ||
        count + method->local_count + method->info.max_stack > SIZE_MAX / sizeof(xxemul_dotnet_value))
        return net_fail(vm, XXEMUL_STATUS_LIMIT_REACHED, "CIL frame size overflow");
    bytes = (count + method->local_count + method->info.max_stack) * sizeof(xxemul_dotnet_value);
    if (bytes > vm->config.max_frame_bytes - vm->frame_bytes) return net_fail(vm, XXEMUL_STATUS_LIMIT_REACHED, "CIL frame byte limit reached");
    if (method->info.max_stack > vm->config.max_stack_values - vm->stack_values) return net_fail(vm, XXEMUL_STATUS_LIMIT_REACHED, "CIL stack slot limit reached");
    memset(&frame, 0, sizeof(frame)); frame.arguments = (xxemul_dotnet_value *)calloc(bytes ? bytes : 1, 1);
    if (!frame.arguments) return net_allocation_failure(vm, XXEMUL_STATUS_OUT_OF_MEMORY);
    frame.locals = frame.arguments + count; frame.stack = frame.locals + method->local_count; frame.capacity = method->info.max_stack;
    frame.allocation_bytes = bytes; vm->frame_bytes += bytes; vm->stack_values += frame.capacity; ++vm->depth;
    if (method->signature.has_this) frame.arguments[0] = arguments[0];
    status = XXEMUL_STATUS_OK;
    for (i = 0; i < method->signature.parameter_count; ++i) {
        size_t offset = i + (method->signature.has_this ? 1u : 0u);
        status = net_coerce(vm, &method->signature.parameters[i], arguments[offset], &frame.arguments[offset]);
        if (status != XXEMUL_STATUS_OK) break;
    }
    if (status == XXEMUL_STATUS_OK) for (i = 0; i < method->local_count; ++i) {
        if (!method->locals[i].supported) { status = net_fail(vm, XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION, "unsupported local type %s", method->locals[i].name); break; }
        if (method->info.init_locals) frame.locals[i].kind = net_type_kind(&method->locals[i]);
    }
    if (status == XXEMUL_STATUS_OK && !method->signature.has_this && strcmp(method->info.name, ".cctor")) status = net_initialize(vm, method->owner_token);
    if (status == XXEMUL_STATUS_OK) {
        if (method->local_reference && !method->info.is_defined) {
            status = net_fail(vm, XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION, "unresolved local method reference: %s", method->info.selector);
        } else if (!method->info.is_executable || !method->code) {
            if (!vm->config.external_callback) status = net_fail(vm, XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION, "external method requires callback: %s", method->info.selector);
            else {
                *result = net_value(XXEMUL_DOTNET_VALUE_VOID, 0);
                status = vm->config.external_callback(vm->config.external_context, vm, &method->info, frame.arguments, count, result);
                if (status != XXEMUL_STATUS_OK) status = net_fail(vm, status, "external callback failed: %s", method->info.selector);
                else { xxemul_dotnet_value returned = *result; status = net_coerce(vm, &method->signature.return_type, returned, result); }
            }
        } else if ((status = net_prepare_code(vm, index)) == XXEMUL_STATUS_OK) status = net_body(vm, index, &frame, result);
    }
    --vm->depth; vm->frame_bytes -= bytes; vm->stack_values -= frame.capacity; free(frame.arguments); return status;
}
xxemul_status xxemul_dotnet_vm_invoke(xxemul_dotnet_vm *vm, size_t method_index,
    const xxemul_dotnet_value *arguments, size_t argument_count, xxemul_dotnet_result *result) {
    xxemul_status status;
    if (!result) return XXEMUL_STATUS_INVALID_ARGUMENT;
    memset(result, 0, sizeof(*result)); result->method_index = method_index;
    if (!vm || method_index >= vm->program->method_count || (!arguments && argument_count) || vm->running) {
        result->status = XXEMUL_STATUS_INVALID_ARGUMENT;
        (void)snprintf(result->diagnostic, sizeof(result->diagnostic), "invalid VM invocation arguments or reentrant invocation");
        return result->status;
    }
    vm->running = 1; vm->result = result;
    status = net_execute(vm, method_index, arguments, argument_count, &result->value);
    result->status = status; vm->result = NULL; vm->running = 0; return status;
}
