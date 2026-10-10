#include "../xxemul_dex_internal.h"

#include <xxbyte/xxbyte.h>
#include <xxfclib/io/xx_io.h>

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DEX_MAX_SIZE ((size_t)256 * 1024 * 1024)
#define DEX_METADATA_LIMIT ((size_t)256 * 1024 * 1024)

static int dex_range(const xxemul_dex_file *dex, size_t off, size_t size)
{
    return off <= dex->size && size <= dex->size - off;
}

static size_t dex_data_end(const xxemul_dex_file *dex)
{
    return (size_t)dex->header.data_off + dex->header.data_size;
}

static int dex_data_range(const xxemul_dex_file *dex, size_t off, size_t size)
{
    size_t end = dex_data_end(dex);
    return off >= dex->header.data_off && off <= end && size <= end - off;
}

static int dex_map_valid(const xxemul_dex_file *dex)
{
    uint32_t off = dex->header.map_off, count, i, previous = 0;
    unsigned char *seen;
    int valid = 1;
    if (!off) return 1;
    if ((off & 3U) || !dex_data_range(dex, off, 4)) return 0;
    count = xxemul_dex_u32(dex->data + off);
    if (!count || count > 65536 || count > (dex_data_end(dex) - off - 4) / 12) return 0;
    seen = (unsigned char *)calloc(8192, 1);
    if (!seen) return 0;
    for (i = 0; i < count; ++i) {
        const uint8_t *item = dex->data + off + 4 + (size_t)i * 12;
        uint16_t type = xxemul_dex_u16(item);
        uint32_t n = xxemul_dex_u32(item + 4), at = xxemul_dex_u32(item + 8);
        size_t width = 1;
        if (!n || (seen[type / 8] & (1U << (type % 8))) || (i && at <= previous) || at >= dex->size) {
            valid = 0;
            break;
        }
        seen[type / 8] |= (unsigned char)(1U << (type % 8));
        previous = at;
        switch (type) {
            case 0:
                width = XX_DEX_HEADER_SIZE;
                if (n != 1 || at != 0) valid = 0;
                break;
            case 1:
            case 2:
            case 7: width = 4; break;
            case 3: width = 12; break;
            case 4:
            case 5:
            case 8: width = 8; break;
            case 6: width = 32; break;
            case 0x1000:
                if (n != 1 || at != off) valid = 0;
                width = 4;
                break;
            default:
                if (at < dex->header.data_off) valid = 0;
                break;
        }
        if (!valid || n > SIZE_MAX / width || !dex_range(dex, at, n * width)) {
            valid = 0;
            break;
        }
    }
    free(seen);
    return valid;
}

static int dex_uleb(const xxemul_dex_file *dex, size_t *cursor, uint32_t *out)
{
    uint32_t value = 0;
    unsigned i;
    for (i = 0; i != 5; ++i) {
        uint8_t byte;
        if (!dex_data_range(dex, *cursor, 1)) return 0;
        byte = dex->data[(*cursor)++];
        if (i == 4 && (byte & 0xf0U)) return 0;
        value |= (uint32_t)(byte & 0x7fU) << (i * 7);
        if (!(byte & 0x80U)) {
            *out = value;
            return 1;
        }
    }
    return 0;
}

static int dex_sleb(const xxemul_dex_file *dex, size_t *cursor, int32_t *out)
{
    uint32_t value = 0;
    unsigned i;
    for (i = 0; i != 5; ++i) {
        uint8_t byte;
        unsigned bits;
        if (!dex_data_range(dex, *cursor, 1)) return 0;
        byte = dex->data[(*cursor)++];
        if (i == 4 && ((byte & 0xf0U) != 0 && (byte & 0xf0U) != 0x70U)) return 0;
        value |= (uint32_t)(byte & 0x7fU) << (i * 7);
        if (byte & 0x80U) continue;
        bits = (i + 1) * 7;
        if (bits < 32 && (byte & 0x40U)) value |= UINT32_MAX << bits;
        memcpy(out, &value, sizeof(value));
        return 1;
    }
    return 0;
}

static char *dex_copy_string(const char *text)
{
    size_t size = strlen(text) + 1;
    char *copy = (char *)malloc(size);
    if (copy) memcpy(copy, text, size);
    return copy;
}

static xxemul_status dex_strings(xxemul_dex_file *dex, const xx_dex *reader)
{
    uint32_t i;
    size_t budget = 0;
    dex->strings = (char **)calloc(dex->header.string_ids_size, sizeof(char *));
    if (dex->header.string_ids_size && !dex->strings) return XXEMUL_STATUS_OUT_OF_MEMORY;
    for (i = 0; i < dex->header.string_ids_size; ++i) {
        xx_dex_string_info info;
        size_t bytes;
        if (!xx_dex_read_string_info(reader, i, DEX_METADATA_LIMIT - budget, &info, NULL)) return XXEMUL_STATUS_INVALID_IMAGE;
        bytes = info.byte_size + 1;
        budget += bytes;
        dex->strings[i] = (char *)malloc(bytes);
        if (!dex->strings[i]) return XXEMUL_STATUS_OUT_OF_MEMORY;
        memcpy(dex->strings[i], dex->data + info.data_off, bytes);
    }
    return XXEMUL_STATUS_OK;
}

static int dex_descriptor(const char *text, int allow_void)
{
    const char *p = text;
    size_t arrays = 0;
    while (*p == '[') {
        ++p;
        if (++arrays > 255) return 0;
    }
    if (*p == 'L') {
        const char *start = ++p;
        while (*p && *p != ';') ++p;
        return p != start && *p == ';' && p[1] == 0;
    }
    if (strchr("ZBSCIJFD", *p) && *p && p[1] == 0) return 1;
    return allow_void && !arrays && *p == 'V' && p[1] == 0;
}

static xxemul_status dex_types_and_prototypes(xxemul_dex_file *dex, const xx_dex *reader)
{
    uint32_t i;
    size_t budget = 0;
    dex->types = (char **)calloc(dex->header.type_ids_size, sizeof(char *));
    dex->prototypes = (char **)calloc(dex->header.proto_ids_size, sizeof(char *));
    if ((dex->header.type_ids_size && !dex->types) || (dex->header.proto_ids_size && !dex->prototypes)) return XXEMUL_STATUS_OUT_OF_MEMORY;
    for (i = 0; i < dex->header.type_ids_size; ++i) {
        xx_dex_type_id item;
        uint32_t id;
        if (!xx_dex_read_type_id(reader, i, &item)) return XXEMUL_STATUS_INVALID_IMAGE;
        id = item.descriptor_idx;
        if (!dex_descriptor(dex->strings[id], 1)) return XXEMUL_STATUS_INVALID_IMAGE;
        dex->types[i] = dex->strings[id];
    }
    for (i = 0; i < dex->header.proto_ids_size; ++i) {
        xx_dex_proto_id item;
        uint32_t ret, off, count, j;
        size_t length, cursor;
        char *prototype;
        if (!xx_dex_read_proto_id(reader, i, &item)) return XXEMUL_STATUS_INVALID_IMAGE;
        ret = item.return_type_idx;
        off = item.parameters_off;
        if (!xx_dex_read_type_list_count(reader, off, &count)) return XXEMUL_STATUS_INVALID_IMAGE;
        length = strlen(dex->types[ret]) + 3;
        for (j = 0; j < count; ++j) {
            uint16_t type;
            size_t n;
            if (!xx_dex_read_type_list_item(reader, off, j, &type) || dex->types[type][0] == 'V') return XXEMUL_STATUS_INVALID_IMAGE;
            n = strlen(dex->types[type]);
            if (n > DEX_METADATA_LIMIT - length) return XXEMUL_STATUS_INVALID_IMAGE;
            length += n;
        }
        if (length > DEX_METADATA_LIMIT - budget) return XXEMUL_STATUS_INVALID_IMAGE;
        budget += length;
        prototype = (char *)malloc(length);
        if (!prototype) return XXEMUL_STATUS_OUT_OF_MEMORY;
        dex->prototypes[i] = prototype;
        prototype[0] = '(';
        cursor = 1;
        for (j = 0; j < count; ++j) {
            uint16_t type;
            size_t n;
            if (!xx_dex_read_type_list_item(reader, off, j, &type)) return XXEMUL_STATUS_INVALID_IMAGE;
            n = strlen(dex->types[type]);
            memcpy(prototype + cursor, dex->types[type], n);
            cursor += n;
        }
        prototype[cursor++] = ')';
        memcpy(prototype + cursor, dex->types[ret], strlen(dex->types[ret]) + 1);
    }
    return XXEMUL_STATUS_OK;
}

static xxemul_status dex_methods(xxemul_dex_program *program, size_t dex_index, const xx_dex *reader)
{
    xxemul_dex_file *dex = &program->dex_files[dex_index];
    xxemul_dex_method *methods;
    size_t first = program->method_count, total, budget = 0;
    uint32_t i;
    if (dex->header.method_ids_size > SIZE_MAX - first) return XXEMUL_STATUS_OUT_OF_MEMORY;
    total = first + dex->header.method_ids_size;
    if (total > SIZE_MAX / sizeof(*methods)) return XXEMUL_STATUS_OUT_OF_MEMORY;
    methods = (xxemul_dex_method *)realloc(program->methods, total * sizeof(*methods));
    if (total && !methods) return XXEMUL_STATUS_OUT_OF_MEMORY;
    program->methods = methods;
    if (total > first) memset(methods + first, 0, (total - first) * sizeof(*methods));
    program->method_count = total;
    dex->method_map = (size_t *)calloc(dex->header.method_ids_size, sizeof(size_t));
    if (dex->header.method_ids_size && !dex->method_map) return XXEMUL_STATUS_OUT_OF_MEMORY;
    for (i = 0; i < dex->header.method_ids_size; ++i) {
        xx_dex_method_id item;
        uint16_t klass, proto;
        uint32_t name;
        xxemul_dex_method_info *info = &methods[first + i].info;
        size_t length;
        char *selector;
        if (!xx_dex_read_method_id(reader, i, &item)) return XXEMUL_STATUS_INVALID_IMAGE;
        klass = item.class_idx;
        proto = item.proto_idx;
        name = item.name_idx;
        /* Array classes can own method references such as int[].clone().
         * Class definitions themselves remain restricted to L descriptors. */
        if ((dex->types[klass][0] != 'L' && dex->types[klass][0] != '[') || !dex->strings[name][0]) return XXEMUL_STATUS_INVALID_IMAGE;
        info->dex_index = dex_index;
        info->method_id = i;
        info->class_descriptor = dex->types[klass];
        info->name = dex->strings[name];
        info->prototype = dex->prototypes[proto];
        length = strlen(info->class_descriptor) + strlen(info->name) + strlen(info->prototype) + 3;
        if (length > DEX_METADATA_LIMIT - budget) return XXEMUL_STATUS_INVALID_IMAGE;
        budget += length;
        selector = (char *)malloc(length);
        if (!selector) return XXEMUL_STATUS_OUT_OF_MEMORY;
        (void)snprintf(selector, length, "%s->%s%s", info->class_descriptor, info->name, info->prototype);
        info->selector = selector;
        dex->method_map[i] = first + i;
    }
    return XXEMUL_STATUS_OK;
}

static xxemul_status dex_code(xxemul_dex_file *dex, xxemul_dex_method *method, uint32_t off, const xx_dex *reader)
{
    xx_dex_code_item code;
    uint32_t units;
    uint16_t tries;
    size_t cursor, tries_off;
    if (!off) {
        return (method->info.access_flags & (0x100U | 0x400U)) ? XXEMUL_STATUS_OK : XXEMUL_STATUS_INVALID_IMAGE;
    }
    if (!xx_dex_read_code_item(reader, off, &code) || (method->info.access_flags & (0x100U | 0x400U))) return XXEMUL_STATUS_INVALID_IMAGE;
    method->info.registers_size = code.registers_size;
    method->info.ins_size = code.ins_size;
    method->info.outs_size = code.outs_size;
    tries = code.tries_size;
    units = code.insns_size;
    if (!units) return XXEMUL_STATUS_INVALID_IMAGE;
    method->info.code_units = units;
    method->code_offset = off;
    method->code = dex->data + code.insns_off;
    cursor = (size_t)code.insns_off + (size_t)units * 2;
    if (tries) {
        uint32_t handlers, h;
        size_t handler_base;
        uint32_t *starts;
        uint16_t t;
        if (units & 1U) cursor += 2;
        tries_off = cursor;
        if (!dex_data_range(dex, cursor, (size_t)tries * 8)) return XXEMUL_STATUS_INVALID_IMAGE;
        cursor += (size_t)tries * 8;
        handler_base = cursor;
        if (!dex_uleb(dex, &cursor, &handlers) || !handlers || handlers > dex->size - cursor) return XXEMUL_STATUS_INVALID_IMAGE;
        starts = (uint32_t *)calloc(handlers, sizeof(uint32_t));
        if (!starts) return XXEMUL_STATUS_OUT_OF_MEMORY;
        for (h = 0; h < handlers; ++h) {
            int32_t count;
            uint32_t n, j, value, address;
            starts[h] = (uint32_t)(cursor - handler_base);
            if (!dex_sleb(dex, &cursor, &count) || count == INT32_MIN) {
                free(starts);
                return XXEMUL_STATUS_INVALID_IMAGE;
            }
            n = count < 0 ? (uint32_t)-count : (uint32_t)count;
            if (n > (dex->size - cursor) / 2) {
                free(starts);
                return XXEMUL_STATUS_INVALID_IMAGE;
            }
            for (j = 0; j < n; ++j) {
                if (!dex_uleb(dex, &cursor, &value) || value >= dex->header.type_ids_size || !dex_uleb(dex, &cursor, &address) || address >= units) {
                    free(starts);
                    return XXEMUL_STATUS_INVALID_IMAGE;
                }
            }
            if (count <= 0 && (!dex_uleb(dex, &cursor, &address) || address >= units)) {
                free(starts);
                return XXEMUL_STATUS_INVALID_IMAGE;
            }
        }
        for (t = 0; t < tries; ++t) {
            const uint8_t *item = dex->data + tries_off + (size_t)t * 8;
            uint32_t start = xxemul_dex_u32(item);
            uint16_t count = xxemul_dex_u16(item + 4), handler = xxemul_dex_u16(item + 6);
            size_t lo = 0, hi = handlers;
            while (lo < hi) {
                size_t mid = lo + (hi - lo) / 2;
                if (starts[mid] < handler) lo = mid + 1;
                else hi = mid;
            }
            if (!count || start >= units || count > units - start || lo == handlers || starts[lo] != handler) {
                free(starts);
                return XXEMUL_STATUS_INVALID_IMAGE;
            }
        }
        free(starts);
    }
    return XXEMUL_STATUS_OK;
}

static xxemul_status dex_classes(xxemul_dex_program *program, size_t dex_index, const xx_dex *reader)
{
    xxemul_dex_file *dex = &program->dex_files[dex_index];
    uint32_t c;
    uint8_t *seen = (uint8_t *)calloc(dex->header.type_ids_size, 1);
    if (dex->header.type_ids_size && !seen) return XXEMUL_STATUS_OUT_OF_MEMORY;
    for (c = 0; c < dex->header.class_defs_size; ++c) {
        xx_dex_class_def def;
        uint32_t klass, super, interfaces, source, data_off;
        uint32_t counts[4], group;
        size_t cursor;
        if (!xx_dex_read_class_def(reader, c, &def)) goto invalid;
        klass = def.class_idx;
        super = def.superclass_idx;
        interfaces = def.interfaces_off;
        source = def.source_file_idx;
        data_off = def.class_data_off;
        cursor = data_off;
        if (klass >= dex->header.type_ids_size || seen[klass] || dex->types[klass][0] != 'L' ||
            (super != UINT32_MAX && (super >= dex->header.type_ids_size || dex->types[super][0] != 'L')) ||
            (source != UINT32_MAX && source >= dex->header.string_ids_size))
            goto invalid;
        seen[klass] = 1;
        if (interfaces) {
            uint32_t n, j;
            if (!xx_dex_read_type_list_count(reader, interfaces, &n)) goto invalid;
            for (j = 0; j < n; ++j) {
                uint16_t type;
                if (!xx_dex_read_type_list_item(reader, interfaces, j, &type) || dex->types[type][0] != 'L') goto invalid;
            }
        }
        if (!data_off) continue;
        if (data_off < dex->header.data_off) goto invalid;
        for (group = 0; group < 4; ++group)
            if (!dex_uleb(dex, &cursor, &counts[group])) goto invalid;
        for (group = 0; group < 4; ++group) {
            uint32_t member = 0, j;
            if (counts[group] > (dex->size - cursor) / (group < 2 ? 2 : 3)) goto invalid;
            for (j = 0; j < counts[group]; ++j) {
                uint32_t diff, access, off;
                if (!dex_uleb(dex, &cursor, &diff) || (j && !diff) || diff > UINT32_MAX - member || !dex_uleb(dex, &cursor, &access)) goto invalid;
                member += diff;
                if (group < 2) {
                    xx_dex_field_id field;
                    if (!xx_dex_read_field_id(reader, member, &field) || field.class_idx != klass) goto invalid;
                } else {
                    xxemul_dex_method *method;
                    xxemul_status result;
                    if (member >= dex->header.method_ids_size || !dex_uleb(dex, &cursor, &off)) goto invalid;
                    method = &program->methods[dex->method_map[member]];
                    if (method->info.is_defined || strcmp(method->info.class_descriptor, dex->types[klass])) goto invalid;
                    method->info.is_defined = 1;
                    method->info.access_flags = access;
                    result = dex_code(dex, method, off, reader);
                    if (result != XXEMUL_STATUS_OK) {
                        free(seen);
                        return result;
                    }
                }
            }
        }
    }
    free(seen);
    return XXEMUL_STATUS_OK;
invalid:
    free(seen);
    return XXEMUL_STATUS_INVALID_IMAGE;
}

xxemul_status xxemul_dex_append(xxemul_dex_program *program, const void *data, size_t size, const char *name)
{
    xxemul_dex_file *dex, *files;
    xx_io_device *device;
    xx_dex reader;
    xxemul_status result;
    uint32_t i;
    size_t index;
    if (!program || !data || !name || size < XX_DEX_HEADER_SIZE || size > DEX_MAX_SIZE) return XXEMUL_STATUS_INVALID_IMAGE;
    if (memcmp(data, "dex\n", 4)) return XXEMUL_STATUS_UNSUPPORTED_IMAGE;
    if (memcmp((const uint8_t *)data + 4, "041", 3) == 0 || xxemul_dex_u32((const uint8_t *)data + 40) == XX_DEX_REVERSE_ENDIAN_CONSTANT)
        return XXEMUL_STATUS_UNSUPPORTED_IMAGE;
    device = xx_io_mem_open_ro(data, size);
    if (!device) return XXEMUL_STATUS_OUT_OF_MEMORY;
    xx_dex_init(&reader, device, 0);
    if (!xx_dex_handle_base_info(&reader.format, NULL)) {
        xx_dex_destroy(&reader);
        xx_io_close(device);
        return XXEMUL_STATUS_INVALID_IMAGE;
    }
    if (program->dex_count >= 128 || program->dex_count == SIZE_MAX / sizeof(*files)) {
        xx_dex_destroy(&reader);
        xx_io_close(device);
        return XXEMUL_STATUS_INVALID_IMAGE;
    }
    index = program->dex_count;
    files = (xxemul_dex_file *)realloc(program->dex_files, (index + 1) * sizeof(*files));
    if (!files) {
        xx_dex_destroy(&reader);
        xx_io_close(device);
        return XXEMUL_STATUS_OUT_OF_MEMORY;
    }
    program->dex_files = files;
    dex = &files[index];
    memset(dex, 0, sizeof(*dex));
    ++program->dex_count;
    dex->header = reader.header;
    dex->version = reader.version_number;
    dex->size = reader.header.file_size;
    xx_dex_destroy(&reader);
    xx_io_close(device);
    dex->data = (uint8_t *)malloc(dex->size);
    dex->name = dex_copy_string(name);
    if (!dex->data || !dex->name) return XXEMUL_STATUS_OUT_OF_MEMORY;
    memcpy(dex->data, data, dex->size);
    dex->info.name = dex->name;
    dex->info.version = dex->version;
    dex->info.file_size = dex->size;
    dex->info.class_count = dex->header.class_defs_size;
    dex->info.string_count = dex->header.string_ids_size;
    dex->info.type_count = dex->header.type_ids_size;
    dex->info.method_count = dex->header.method_ids_size;
    device = xx_io_mem_open_ro(dex->data, dex->size);
    if (!device) return XXEMUL_STATUS_OUT_OF_MEMORY;
    xx_dex_init(&reader, device, 0);
    result = XXEMUL_STATUS_INVALID_IMAGE;
    if (!xx_dex_handle_base_info(&reader.format, NULL) || !xx_dex_validate_tables(&reader) || dex->header.type_ids_size > 65536 || dex->header.proto_ids_size > 65536 ||
        dex->header.field_ids_size > 65536 || dex->header.method_ids_size > 65536 || dex->header.class_defs_size > dex->header.type_ids_size || !dex_map_valid(dex))
        goto reader_done;
    result = dex_strings(dex, &reader);
    if (result != XXEMUL_STATUS_OK) goto reader_done;
    result = dex_types_and_prototypes(dex, &reader);
    if (result != XXEMUL_STATUS_OK) goto reader_done;
    for (i = 0; i < dex->header.field_ids_size; ++i) {
        xx_dex_field_id field;
        if (!xx_dex_read_field_id(&reader, i, &field) || dex->types[field.class_idx][0] != 'L' || dex->types[field.type_idx][0] == 'V' ||
            !dex->strings[field.name_idx][0]) {
            result = XXEMUL_STATUS_INVALID_IMAGE;
            goto reader_done;
        }
    }
    result = dex_methods(program, index, &reader);
    if (result != XXEMUL_STATUS_OK) goto reader_done;
    result = dex_classes(program, index, &reader);
reader_done:
    xx_dex_destroy(&reader);
    xx_io_close(device);
    return result;
}

xxemul_dex_program *xxemul_dex_create_dex(const void *data, size_t size, xxemul_status *status)
{
    xxemul_dex_program *program;
    xxemul_status result;
    if (status) *status = XXEMUL_STATUS_INVALID_ARGUMENT;
    if (!data || !size) return NULL;
    program = (xxemul_dex_program *)calloc(1, sizeof(*program));
    if (!program) {
        if (status) *status = XXEMUL_STATUS_OUT_OF_MEMORY;
        return NULL;
    }
    result = xxemul_dex_append(program, data, size, "classes.dex");
    if (status) *status = result;
    if (result != XXEMUL_STATUS_OK) {
        xxemul_dex_destroy(program);
        return NULL;
    }
    return program;
}

xxemul_dex_program *xxemul_dex_create_file(const char *path, xxemul_status *status)
{
    xx_io_device *device;
    int64_t file_size;
    uint8_t *data;
    size_t done = 0;
    xxemul_dex_program *program;
    if (status) *status = XXEMUL_STATUS_INVALID_ARGUMENT;
    if (!path || !path[0]) return NULL;
    device = xx_io_file_open(path, "rb");
    if (!device) {
        if (status) *status = XXEMUL_STATUS_IO_ERROR;
        return NULL;
    }
    file_size = xx_io_total_size(device);
    if (file_size <= 0 || (uint64_t)file_size > (uint64_t)DEX_MAX_SIZE * 4 || (uint64_t)file_size > SIZE_MAX) {
        xx_io_close(device);
        if (status) *status = XXEMUL_STATUS_INVALID_IMAGE;
        return NULL;
    }
    data = (uint8_t *)malloc((size_t)file_size);
    if (!data) {
        xx_io_close(device);
        if (status) *status = XXEMUL_STATUS_OUT_OF_MEMORY;
        return NULL;
    }
    while (done < (size_t)file_size) {
        ssize_t n = xx_io_read(device, data + done, (size_t)file_size - done);
        if (n <= 0 || (size_t)n > (size_t)file_size - done) break;
        done += (size_t)n;
    }
    xx_io_close(device);
    if (done != (size_t)file_size) {
        free(data);
        if (status) *status = XXEMUL_STATUS_IO_ERROR;
        return NULL;
    }
    if (done >= 4 && !memcmp(data, "dex\n", 4)) program = xxemul_dex_create_dex(data, done, status);
    else if (done >= 4 && !memcmp(data, "PK\003\004", 4)) program = xxemul_dex_create_apk(data, done, status);
    else {
        program = NULL;
        if (status) *status = XXEMUL_STATUS_UNSUPPORTED_IMAGE;
    }
    free(data);
    return program;
}

void xxemul_dex_destroy(xxemul_dex_program *program)
{
    size_t i;
    if (!program) return;
    for (i = 0; i < program->method_count; ++i) free((void *)program->methods[i].info.selector);
    free(program->methods);
    for (i = 0; i < program->dex_count; ++i) {
        xxemul_dex_file *dex = &program->dex_files[i];
        uint32_t j;
        if (dex->strings)
            for (j = 0; j < dex->header.string_ids_size; ++j) free(dex->strings[j]);
        if (dex->prototypes)
            for (j = 0; j < dex->header.proto_ids_size; ++j) free(dex->prototypes[j]);
        free(dex->strings);
        free(dex->types);
        free(dex->prototypes);
        free(dex->method_map);
        free(dex->data);
        free(dex->name);
    }
    free(program->dex_files);
    free(program->manifest);
    free(program->package_name);
    free(program->launcher_activity);
    free(program);
}

size_t xxemul_dex_dex_count(const xxemul_dex_program *program)
{
    return program ? program->dex_count : 0;
}
const xxemul_dex_file_info *xxemul_dex_dex_info(const xxemul_dex_program *program, size_t index)
{
    return program && index < program->dex_count ? &program->dex_files[index].info : NULL;
}
size_t xxemul_dex_method_count(const xxemul_dex_program *program)
{
    return program ? program->method_count : 0;
}
const xxemul_dex_method_info *xxemul_dex_method_info_at(const xxemul_dex_program *program, size_t index)
{
    return program && index < program->method_count ? &program->methods[index].info : NULL;
}
size_t xxemul_dex_find_method(const xxemul_dex_program *program, const char *selector)
{
    size_t i, best = SIZE_MAX;
    if (!program || !selector) return SIZE_MAX;
    for (i = 0; i < program->method_count; ++i)
        if (!strcmp(program->methods[i].info.selector, selector)) {
            if (program->methods[i].code) return i;
            if (best == SIZE_MAX || program->methods[i].info.is_defined) best = i;
        }
    return best;
}
int xxemul_dex_is_apk(const xxemul_dex_program *program)
{
    return program ? program->is_apk : 0;
}
const char *xxemul_dex_manifest(const xxemul_dex_program *program)
{
    return program ? program->manifest : NULL;
}
const char *xxemul_dex_package_name(const xxemul_dex_program *program)
{
    return program ? program->package_name : NULL;
}
const char *xxemul_dex_launcher_activity(const xxemul_dex_program *program)
{
    return program ? program->launcher_activity : NULL;
}

typedef struct dex_resolver_context {
    const xxemul_dex_program *program;
    const xxemul_dex_file *dex;
} dex_resolver_context;

static size_t dex_resolve(void *context, const xxbyte_instruction *instruction, uint32_t operand_index, char *buffer, size_t size)
{
    const dex_resolver_context *ctx = (const dex_resolver_context *)context;
    const xxbyte_operand *operand = &instruction->operands[operand_index];
    const xxemul_dex_file *dex = ctx->dex;
    uint64_t id = (uint64_t)operand->value;
    const char *text = NULL;
    int n;
    if (operand->type != XXBYTE_OPERAND_INDEX) return 0;
    if (operand->kind == XXBYTE_INDEX_STRING && id < dex->header.string_ids_size) {
        n = snprintf(buffer, size, "\"%s\"", dex->strings[id]);
        return n < 0 ? 0 : (size_t)n;
    }
    if (operand->kind == XXBYTE_INDEX_TYPE && id < dex->header.type_ids_size) text = dex->types[id];
    if (operand->kind == XXBYTE_INDEX_METHOD && id < dex->header.method_ids_size) text = ctx->program->methods[dex->method_map[id]].info.selector;
    if (operand->kind == XXBYTE_INDEX_PROTO && id < dex->header.proto_ids_size) text = dex->prototypes[id];
    if (operand->kind == XXBYTE_INDEX_FIELD && id < dex->header.field_ids_size) {
        const uint8_t *field = dex->data + dex->header.field_ids_off + (size_t)id * 8;
        n = snprintf(buffer, size, "%s->%s:%s", dex->types[xxemul_dex_u16(field)], dex->strings[xxemul_dex_u32(field + 4)], dex->types[xxemul_dex_u16(field + 2)]);
        return n < 0 ? 0 : (size_t)n;
    }
    if (!text) return 0;
    n = snprintf(buffer, size, "%s", text);
    return n < 0 ? 0 : (size_t)n;
}

xxemul_status xxemul_dex_disassemble(const xxemul_dex_program *program, size_t method_index, uint32_t byte_offset, char *text, size_t text_size,
                                     uint32_t *instruction_size)
{
    const xxemul_dex_method *method;
    const xxemul_dex_file *dex;
    size_t bytes;
    xxbyte_instruction instruction;
    dex_resolver_context context;
    if (instruction_size) *instruction_size = 0;
    if (text && text_size) text[0] = 0;
    if (!program || method_index >= program->method_count || !text || !text_size || !instruction_size) return XXEMUL_STATUS_INVALID_ARGUMENT;
    method = &program->methods[method_index];
    dex = &program->dex_files[method->info.dex_index];
    bytes = (size_t)method->info.code_units * 2;
    if (!method->code || byte_offset >= bytes || (byte_offset & 1U)) return XXEMUL_STATUS_ADDRESS_FAULT;
    if (xxbyte_decode(XXBYTE_FAMILY_DEX, XXBYTE_DEX_MODE(dex->version), method->code + byte_offset, bytes - byte_offset, byte_offset, &instruction) != XXBYTE_STATUS_OK)
        return XXEMUL_STATUS_DECODE_ERROR;
    context.program = program;
    context.dex = dex;
    if (!xxbyte_format_ex(&instruction, XXBYTE_FORMAT_DEFAULT, dex_resolve, &context, text, text_size)) return XXEMUL_STATUS_DECODE_ERROR;
    *instruction_size = instruction.size;
    return XXEMUL_STATUS_OK;
}
