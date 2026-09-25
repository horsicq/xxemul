#include "xxemul_internal.h"

#include <xxfclib/formats/macho/xx_macho.h>

#include <string.h>

static int xxemul_macho_machine_mode(
    uint32_t cpu_type, xxemul_image_format format,
    uint64_t *entry, xxemul_arch *arch, xxemul_mode *mode)
{
    switch (cpu_type) {
    case 7u:
        if (format != XXEMUL_IMAGE_MACHO32) return 0;
        *arch = XXEMUL_ARCH_X86;
        *mode = XXEMUL_MODE_X86_32;
        return 1;
    case 0x01000007u:
        if (format != XXEMUL_IMAGE_MACHO64) return 0;
        *arch = XXEMUL_ARCH_X86;
        *mode = XXEMUL_MODE_X86_64;
        return 1;
    case 12u:
        if (format != XXEMUL_IMAGE_MACHO32) return 0;
        *arch = XXEMUL_ARCH_ARM;
        *mode = (*entry & 1u) != 0u
            ? XXEMUL_MODE_ARM_T32 : XXEMUL_MODE_ARM_A32;
        *entry &= ~UINT64_C(1);
        return 1;
    case 0x0100000cu:
        if (format != XXEMUL_IMAGE_MACHO64) return 0;
        *arch = XXEMUL_ARCH_ARM;
        *mode = XXEMUL_MODE_ARM_A64;
        return 1;
    default:
        return 0;
    }
}

static int xxemul_macho_is_pagezero(const xx_macho_segment *segment)
{
    return strcmp(segment->name, "__PAGEZERO") == 0
        && segment->file_size == 0u
        && segment->initial_protection == 0u;
}

xxemul *xxemul_load_macho(
    xxemul_image_format format, const uint8_t *image,
    size_t image_size, xx_io_device *io, xxemul_status *status)
{
    xx_macho macho;
    xxemul *emulator = NULL;
    xxemul_arch arch;
    xxemul_mode mode;
    uint64_t base = UINT64_MAX;
    uint64_t end = 0u;
    uint64_t entry = 0u;
    uint32_t index;
    int entry_mapped = 0;

    xx_macho_init(&macho, io, 0);
    *status = XXEMUL_STATUS_INVALID_IMAGE;
    if (!xx_macho_handle_base_info(&macho.format, NULL)
        || xx_macho_is_64(&macho) != (format == XXEMUL_IMAGE_MACHO64)) {
        goto done;
    }
    if (xx_macho_get_file_type(&macho) != XX_MACHO_FILE_EXECUTE
        || (macho.magic != XX_MACHO_MAGIC_32
            && macho.magic != XX_MACHO_MAGIC_64)
        || !macho.has_main_entry) {
        *status = XXEMUL_STATUS_UNSUPPORTED_IMAGE;
        goto done;
    }
    for (index = 0u; index < xx_macho_get_number_of_segments(&macho);
         ++index) {
        const xx_macho_segment *segment = xx_macho_get_segment(&macho, index);
        uint64_t segment_end;

        if (segment == NULL) {
            goto done;
        }
        if (xxemul_macho_is_pagezero(segment)
            || segment->virtual_size == 0u) {
            continue;
        }
        if (segment->file_size > segment->virtual_size
            || segment->file_offset > image_size
            || segment->file_size > image_size - segment->file_offset
            || segment->virtual_address
                > UINT64_MAX - segment->virtual_size) {
            goto done;
        }
        segment_end = segment->virtual_address + segment->virtual_size;
        if (segment->virtual_address < base) {
            base = segment->virtual_address;
        }
        if (segment_end > end) {
            end = segment_end;
        }
        if (segment->file_size != 0u
            && macho.main_entry_offset >= segment->file_offset
            && macho.main_entry_offset
                - segment->file_offset < segment->file_size
            && (segment->initial_protection & 4u) != 0u) {
            entry = segment->virtual_address
                + macho.main_entry_offset - segment->file_offset;
            entry_mapped = 1;
        }
    }
    if (base == UINT64_MAX || !entry_mapped) {
        goto done;
    }
    if (!xxemul_macho_machine_mode(
            xx_macho_get_cpu_type(&macho), format,
            &entry, &arch, &mode)) {
        *status = XXEMUL_STATUS_UNSUPPORTED_IMAGE;
        goto done;
    }
    base &= ~UINT64_C(0xfff);
    emulator = xxemul_image_allocate(
        arch, mode, base, end - base, entry, 1, status);
    if (emulator == NULL) {
        goto done;
    }
    for (index = 0u; index < xx_macho_get_number_of_segments(&macho);
         ++index) {
        const xx_macho_segment *segment = xx_macho_get_segment(&macho, index);

        if (!xxemul_macho_is_pagezero(segment)
            && segment->file_size != 0u) {
            xx_mem_copy(emulator->region_data
                    + (size_t)(segment->virtual_address - base),
                image + (size_t)segment->file_offset,
                (size_t)segment->file_size);
        }
    }
done:
    xx_macho_destroy(&macho);
    return emulator;
}
