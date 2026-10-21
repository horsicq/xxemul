/* Private, portable decoding of dyld chained fixups. No host Mach-O ABI. */
#ifndef XXEMUL_MACHO_FIXUPS_H
#define XXEMUL_MACHO_FIXUPS_H

typedef struct xxemul_macho_linkedit {
    uint32_t fixups_offset, fixups_size;
    uint32_t symbols_offset, symbols_count, strings_offset, strings_size;
    uint32_t dylib_count;
    int has_fixups, has_symbols, has_old_fixups, has_initializers;
} xxemul_macho_linkedit;

static uint16_t macho_u16(const uint8_t *p)
{
    return (uint16_t)((uint16_t)p[0] | (uint16_t)p[1] << 8);
}

static uint32_t macho_u32(const uint8_t *p)
{
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

static uint64_t macho_u64(const uint8_t *p)
{
    return (uint64_t)macho_u32(p) | (uint64_t)macho_u32(p + 4) << 32;
}

static int macho_range(size_t size, uint64_t offset, uint64_t length)
{
    return offset <= size && length <= size - offset;
}

static xxemul_status macho_linkedit(const uint8_t *image, size_t size, int is64, xxemul_macho_linkedit *result)
{
    size_t offset = is64 ? 32u : 28u, commands_end;
    uint32_t i, count;
    memset(result, 0, sizeof(*result));
    if (size < offset || !macho_range(size, offset, macho_u32(image + 20))) return XXEMUL_STATUS_INVALID_IMAGE;
    commands_end = offset + macho_u32(image + 20);
    count = macho_u32(image + 16);
    if (count > (commands_end - offset) / 8u) return XXEMUL_STATUS_INVALID_IMAGE;
    for (i = 0; i < count; ++i) {
        uint32_t command, length;
        if (!macho_range(commands_end, offset, 8)) return XXEMUL_STATUS_INVALID_IMAGE;
        command = macho_u32(image + offset);
        length = macho_u32(image + offset + 4);
        if (length < 8 || (length & 3u) || !macho_range(commands_end, offset, length)) return XXEMUL_STATUS_INVALID_IMAGE;
        if (command == UINT32_C(0x80000034)) { /* LC_DYLD_CHAINED_FIXUPS */
            if (length < 16 || result->has_fixups) return XXEMUL_STATUS_INVALID_IMAGE;
            result->has_fixups = 1;
            result->fixups_offset = macho_u32(image + offset + 8);
            result->fixups_size = macho_u32(image + offset + 12);
            if (!macho_range(size, result->fixups_offset, result->fixups_size)) return XXEMUL_STATUS_INVALID_IMAGE;
        } else if (command == 2u) { /* LC_SYMTAB */
            if (length < 24 || result->has_symbols) return XXEMUL_STATUS_INVALID_IMAGE;
            result->has_symbols = 1;
            result->symbols_offset = macho_u32(image + offset + 8);
            result->symbols_count = macho_u32(image + offset + 12);
            result->strings_offset = macho_u32(image + offset + 16);
            result->strings_size = macho_u32(image + offset + 20);
            if (!macho_range(size, result->symbols_offset, (uint64_t)result->symbols_count * (is64 ? 16u : 12u)) ||
                !macho_range(size, result->strings_offset, result->strings_size)) return XXEMUL_STATUS_INVALID_IMAGE;
        } else if (command == 0x22u || command == UINT32_C(0x80000022)) { /* LC_DYLD_INFO[_ONLY] */
            if (length < 48) return XXEMUL_STATUS_INVALID_IMAGE;
            if (macho_u32(image + offset + 12) || macho_u32(image + offset + 20) ||
                macho_u32(image + offset + 28) || macho_u32(image + offset + 36)) result->has_old_fixups = 1;
        } else if (command == 0xcu || command == UINT32_C(0x80000018) ||
                   command == UINT32_C(0x8000001f) || command == UINT32_C(0x80000023)) {
            ++result->dylib_count;
        } else if (command == 0x19u && is64) { /* LC_SEGMENT_64 */
            uint32_t section_count, section;
            if (length < 72u) return XXEMUL_STATUS_INVALID_IMAGE;
            section_count = macho_u32(image + offset + 64u);
            if ((uint64_t)section_count * 80u > length - 72u) return XXEMUL_STATUS_INVALID_IMAGE;
            for (section = 0; section < section_count; ++section) {
                const uint8_t *record = image + offset + 72u + (size_t)section * 80u;
                uint32_t kind = macho_u32(record + 64u) & 0xffu;
                /* Constructors, TLS constructors, compact constructor offsets. */
                if (macho_u64(record + 40u) && (kind == 9u || kind == 0x15u || kind == 0x16u))
                    result->has_initializers = 1;
            }
        } else if (command == 0x1au) { /* LC_ROUTINES_64 */
            if (length < 72u) return XXEMUL_STATUS_INVALID_IMAGE;
            if (macho_u64(image + offset + 8u)) result->has_initializers = 1;
        }
        offset += length;
    }
    return offset == commands_end ? XXEMUL_STATUS_OK : XXEMUL_STATUS_INVALID_IMAGE;
}

/* Dyld's weak/flat/self lookup must retain definitions in the executable.
 * In particular, libc++ inline templates in the guest are not host shims. */
static xxemul_status macho_defined_symbol(const uint8_t *image, const xxemul_macho_linkedit *linkedit,
                                         const xx_macho *macho, const char *name, uint64_t *value, int *found)
{
    uint32_t i;
    *found = 0;
    for (i = 0; i < linkedit->symbols_count; ++i) {
        const uint8_t *symbol = image + linkedit->symbols_offset + (size_t)i * 16u;
        uint32_t string_index = macho_u32(symbol);
        const char *symbol_name;
        uint32_t segment_index;
        if ((symbol[4] & 0xe0u) || (symbol[4] & 0x0eu) != 0x0eu) continue; /* N_STAB, N_SECT */
        if (string_index >= linkedit->strings_size) return XXEMUL_STATUS_INVALID_IMAGE;
        symbol_name = (const char *)image + linkedit->strings_offset + string_index;
        if (!memchr(symbol_name, 0, linkedit->strings_size - string_index)) return XXEMUL_STATUS_INVALID_IMAGE;
        if (strcmp(symbol_name, name)) continue;
        *value = macho_u64(symbol + 8);
        for (segment_index = 0; segment_index < xx_macho_get_number_of_segments(macho); ++segment_index) {
            const xx_macho_segment *segment = xx_macho_get_segment(macho, segment_index);
            if (segment && !xxemul_macho_is_pagezero(segment) && *value >= segment->virtual_address &&
                *value - segment->virtual_address < segment->virtual_size) {
                *found = 1;
                return XXEMUL_STATUS_OK;
            }
        }
        return XXEMUL_STATUS_INVALID_IMAGE;
    }
    return XXEMUL_STATUS_OK;
}

static xxemul_status macho_add_signed(uint64_t address, int64_t addend, uint64_t *result)
{
    if (addend < 0) {
        uint64_t magnitude = (uint64_t)(-(addend + 1)) + 1u;
        if (magnitude > address) return XXEMUL_STATUS_INVALID_IMAGE;
        *result = address - magnitude;
    } else {
        if ((uint64_t)addend > UINT64_MAX - address) return XXEMUL_STATUS_INVALID_IMAGE;
        *result = address + (uint64_t)addend;
    }
    return XXEMUL_STATUS_OK;
}

static int macho_rebase_target(const xx_macho *macho, uint64_t value, int64_t slide)
{
    uint32_t index;
    /* Top-byte tags are independent of the address carried by a rebase. */
    value &= UINT64_C(0x00ffffffffffffff);
    for (index = 0; index < xx_macho_get_number_of_segments(macho); ++index) {
        const xx_macho_segment *segment = xx_macho_get_segment(macho, index);
        uint64_t begin;
        if (!segment || xxemul_macho_is_pagezero(segment) || !segment->virtual_size ||
            macho_add_signed(segment->virtual_address, slide, &begin) != XXEMUL_STATUS_OK) continue;
        if (value >= begin && value - begin <= segment->virtual_size) return 1;
    }
    return 0;
}

static xxemul_status macho_chained_imports(xxemul *emulator, const uint8_t *image,
                                         const xxemul_macho_linkedit *linkedit, const xx_macho *macho,
                                         const uint8_t *data, size_t size, int64_t slide, uint64_t **out_values, uint32_t *out_count)
{
    uint32_t imports_offset = macho_u32(data + 8), names_offset = macho_u32(data + 12);
    uint32_t count = macho_u32(data + 16), format = macho_u32(data + 20);
    size_t item_size;
    uint64_t *values;
    uint32_t i;
    xxemul_status status = XXEMUL_STATUS_OK;
    *out_values = NULL;
    *out_count = 0;
    if (format < 1u || format > 3u) return XXEMUL_STATUS_UNSUPPORTED_IMAGE;
    item_size = format == 1u ? 4u : format == 2u ? 8u : 16u;
    if (names_offset > size || imports_offset < 28u || !macho_range(size, imports_offset, (uint64_t)count * item_size))
        return XXEMUL_STATUS_INVALID_IMAGE;
    if (count == 0) return XXEMUL_STATUS_OK;
    if ((uint64_t)count * sizeof(*values) > SIZE_MAX) return XXEMUL_STATUS_INVALID_IMAGE;
    values = (uint64_t *)xx_mem_calloc(count, sizeof(*values));
    if (!values) return XXEMUL_STATUS_OUT_OF_MEMORY;
    for (i = 0; i < count; ++i) {
        const uint8_t *record = data + imports_offset + (size_t)i * item_size;
        uint64_t name_offset, raw = macho_u32(record);
        int ordinal, found = 0;
        int64_t addend = 0;
        const char *name;
        if (format == 3u) {
            raw = macho_u64(record);
            if ((raw >> 17u) & 0x7fffu) { status = XXEMUL_STATUS_INVALID_IMAGE; break; }
            ordinal = (int)(raw & 0xffffu);
            if (ordinal > 0xfff0) ordinal -= 0x10000;
            name_offset = raw >> 32u;
            raw = macho_u64(record + 8);
            addend = raw <= INT64_MAX ? (int64_t)raw : -1 - (int64_t)(UINT64_MAX - raw);
        } else {
            ordinal = (int)(raw & 0xffu);
            if (ordinal > 0xf0) ordinal -= 0x100;
            name_offset = raw >> 9u;
            if (format == 2u) {
                uint32_t encoded = macho_u32(record + 4);
                addend = encoded <= INT32_MAX ? (int64_t)encoded : (int64_t)encoded - INT64_C(0x100000000);
            }
        }
        if (ordinal < -3 || (ordinal > 0 && (uint32_t)ordinal > linkedit->dylib_count)) {
            status = XXEMUL_STATUS_INVALID_IMAGE; break;
        }
        if (name_offset >= size - names_offset) { status = XXEMUL_STATUS_INVALID_IMAGE; break; }
        name = (const char *)data + names_offset + (size_t)name_offset;
        if (!*name || !memchr(name, 0, size - names_offset - (size_t)name_offset)) {
            status = XXEMUL_STATUS_INVALID_IMAGE; break;
        }
        if (ordinal <= 0) status = macho_defined_symbol(image, linkedit, macho, name, &values[i], &found);
        if (status != XXEMUL_STATUS_OK) break;
        if (found) {
            status = macho_add_signed(values[i], slide, &values[i]);
            if (status != XXEMUL_STATUS_OK) break;
        }
        if (!found) {
            if (ordinal == 0 || ordinal == -1) { status = XXEMUL_STATUS_UNSUPPORTED_IMAGE; break; }
            status = xxemul_darwin_resolve_import(emulator->darwin, name, &values[i]);
            if (status != XXEMUL_STATUS_OK) break;
        }
        status = macho_add_signed(values[i], addend, &values[i]);
        if (status != XXEMUL_STATUS_OK) break;
    }
    if (status != XXEMUL_STATUS_OK) { xx_mem_free(values); return status; }
    *out_values = values;
    *out_count = count;
    return XXEMUL_STATUS_OK;
}

static xxemul_status macho_chained_fixups(xxemul *emulator, const uint8_t *image,
                                        const xxemul_macho_linkedit *linkedit, const xx_macho *macho,
                                        uint64_t preferred_base, int64_t slide)
{
    const uint8_t *data = image + linkedit->fixups_offset;
    size_t size = linkedit->fixups_size;
    uint32_t starts_offset, segment_count, import_count, index;
    uint64_t *imports = NULL;
    uint64_t loaded_base;
    xxemul_status status;
    if (macho_add_signed(preferred_base, slide, &loaded_base) != XXEMUL_STATUS_OK) return XXEMUL_STATUS_INVALID_IMAGE;
    if (size < 28u) return XXEMUL_STATUS_INVALID_IMAGE;
    if (macho_u32(data) != 0u || macho_u32(data + 24) != 0u) return XXEMUL_STATUS_UNSUPPORTED_IMAGE;
    starts_offset = macho_u32(data + 4);
    if (starts_offset < 28u || !macho_range(size, starts_offset, 4u)) return XXEMUL_STATUS_INVALID_IMAGE;
    segment_count = macho_u32(data + starts_offset);
    if (segment_count > xx_macho_get_number_of_segments(macho) ||
        !macho_range(size, starts_offset + 4u, (uint64_t)segment_count * 4u)) return XXEMUL_STATUS_INVALID_IMAGE;
    status = macho_chained_imports(emulator, image, linkedit, macho, data, size, slide, &imports, &import_count);
    if (status != XXEMUL_STATUS_OK) return status;
    for (index = 0; index < segment_count; ++index) {
        const xx_macho_segment *segment = xx_macho_get_segment(macho, index);
        uint32_t relative = macho_u32(data + starts_offset + 4u + (size_t)index * 4u);
        uint64_t offset = (uint64_t)starts_offset + relative;
        uint32_t record_size;
        uint16_t page_size, pointer_format, page_count, page;
        if (!relative) continue;
        status = XXEMUL_STATUS_INVALID_IMAGE;
        if (!segment || relative < 4u + (uint64_t)segment_count * 4u || !macho_range(size, offset, 22u)) goto done;
        record_size = macho_u32(data + (size_t)offset);
        page_size = macho_u16(data + (size_t)offset + 4u);
        pointer_format = macho_u16(data + (size_t)offset + 6u);
        page_count = macho_u16(data + (size_t)offset + 20u);
        if (pointer_format != 1u && pointer_format != 2u && pointer_format != 6u &&
            pointer_format != 9u && pointer_format != 12u) { status = XXEMUL_STATUS_UNSUPPORTED_IMAGE; goto done; }
        if (record_size < 22u + (uint32_t)page_count * 2u || !macho_range(size, offset, record_size) ||
            (page_size != 4096u && page_size != 16384u) || xxemul_macho_is_pagezero(segment) ||
            segment->virtual_address < preferred_base ||
            macho_u64(data + (size_t)offset + 8u) != segment->virtual_address - preferred_base ||
            macho_u32(data + (size_t)offset + 16u) != 0u ||
            (page_count && (uint64_t)(page_count - 1u) * page_size >= segment->virtual_size)) goto done;
        for (page = 0; page < page_count; ++page) {
            uint16_t start = macho_u16(data + (size_t)offset + 22u + (size_t)page * 2u);
            uint64_t page_offset = (uint64_t)page * page_size, within = start;
            if (start == 0xffffu) continue;
            if (start & 0x8000u) { status = XXEMUL_STATUS_UNSUPPORTED_IMAGE; goto done; }
            for (;;) {
                uint64_t raw, value, next;
                uint64_t in_segment = page_offset + within;
                uint64_t location;
                int arm64e = pointer_format == 1u || pointer_format == 9u || pointer_format == 12u;
                unsigned stride = arm64e ? 8u : 4u;
                if (within > page_size - 8u || (within & (stride - 1u)) ||
                    in_segment > segment->file_size || 8u > segment->file_size - in_segment) goto done;
                if (segment->virtual_address > UINT64_MAX - in_segment ||
                    macho_add_signed(segment->virtual_address + in_segment, slide, &location) != XXEMUL_STATUS_OK) goto done;
                raw = macho_u64(image + (size_t)(segment->file_offset + in_segment));
                next = (raw >> 51u) & (arm64e ? 0x7ffu : 0xfffu);
                if (arm64e) {
                    int authenticated = (raw >> 63u) != 0;
                    int bound = ((raw >> 62u) & 1u) != 0;
                    if (bound) {
                        uint32_t ordinal_mask = pointer_format == 12u ? 0xffffffu : 0xffffu;
                        uint32_t ordinal = (uint32_t)raw & ordinal_mask;
                        if (((uint32_t)raw & ~ordinal_mask) || ordinal >= import_count) goto done;
                        value = imports[ordinal];
                        if (!authenticated) {
                            int64_t addend = (int64_t)((raw >> 32u) & 0x7ffffu);
                            if (addend & 0x40000) addend -= 0x80000;
                            if (macho_add_signed(value, addend, &value) != XXEMUL_STATUS_OK) goto done;
                        }
                    } else if (authenticated) {
                        uint64_t target = raw & UINT64_C(0xffffffff);
                        if (target > UINT64_MAX - loaded_base) goto done;
                        value = loaded_base + target;
                    } else {
                        uint64_t target = raw & UINT64_C(0x7ffffffffff);
                        if (pointer_format != 1u) {
                            if (target > UINT64_MAX - loaded_base) goto done;
                            target += loaded_base;
                        }
                        value = target | (((raw >> 43u) & 0xffu) << 56u);
                        if (pointer_format == 1u && macho_add_signed(value, slide, &value) != XXEMUL_STATUS_OK) goto done;
                    }
                    if (!bound && !macho_rebase_target(macho, value, slide)) goto done;
                    if (authenticated) {
                        uint64_t modifier = xxemul_arm_auth_modifier(location,
                                                                    (uint16_t)(raw >> 32u), (int)((raw >> 48u) & 1u));
                        unsigned key = (unsigned)((raw >> 49u) & 3u);
                        if (xxemul_arm_auth_sign(emulator, value, modifier, key, &value) != XXEMUL_STATUS_OK) {
                            status = XXEMUL_STATUS_UNSUPPORTED_IMAGE;
                            goto done;
                        }
                    }
                } else if (raw >> 63u) {
                    uint32_t ordinal = (uint32_t)(raw & 0xffffffu);
                    uint64_t addend = (raw >> 24u) & 0xffu;
                    if (((raw >> 32u) & 0x7ffffu) || ordinal >= import_count || imports[ordinal] > UINT64_MAX - addend) goto done;
                    value = imports[ordinal] + addend;
                } else {
                    uint64_t target = raw & UINT64_C(0xfffffffff);
                    if ((raw >> 44u) & 0x7fu) goto done;
                    if (pointer_format == 6u) {
                        if (target > UINT64_MAX - loaded_base) goto done;
                        target += loaded_base;
                    }
                    value = target | (((raw >> 36u) & 0xffu) << 56u);
                    if (pointer_format == 2u && macho_add_signed(value, slide, &value) != XXEMUL_STATUS_OK) goto done;
                    if (!macho_rebase_target(macho, value, slide)) goto done;
                }
                if (xxemul_store_integer(emulator, location, 8u, value) != XXEMUL_STATUS_OK) goto done;
                if (!next) break;
                if (next * stride < 8u || next * stride > page_size - within) goto done;
                within += next * stride;
            }
        }
    }
    status = XXEMUL_STATUS_OK;
done:
    xx_mem_free(imports);
    return status;
}

#endif
