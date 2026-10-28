#include "xxemul_internal.h"

#include <xxfclib/formats/executable/pe/xx_pe.h>

static uint16_t xxemul_pe_u16(const uint8_t *bytes)
{
    return (uint16_t)(bytes[0] | ((uint16_t)bytes[1] << 8));
}

static uint32_t xxemul_pe_u32(const uint8_t *bytes)
{
    return (uint32_t)bytes[0] | ((uint32_t)bytes[1] << 8) | ((uint32_t)bytes[2] << 16) | ((uint32_t)bytes[3] << 24);
}

/* Validate the entire directory before modifying any mapped image bytes.
 * A private copy keeps relocation targets from changing the table while it
 * is being walked, including unusual relocations into the table itself. */
static xxemul_status xxemul_pe_relocate(xxemul *emulator, const xx_pe *pe, xxemul_image_format format)
{
    uint32_t rva, size;
    size_t offset;
    uint64_t delta = emulator->region_address - pe->image_base;
    uint8_t *table;
    unsigned expected_type = format == XXEMUL_IMAGE_PE64 ? 10u : 3u;

    if (emulator->region_address == pe->image_base) return XXEMUL_STATUS_OK;
    if ((pe->characteristics & 1u) != 0u || pe->number_of_data_directories <= 5u) return XXEMUL_STATUS_INVALID_IMAGE;
    rva = pe->data_directory_rva[5];
    size = pe->data_directory_size[5];
    /* Position-independent images, including UPX's PE64 loader stub, can
     * have no loader fixups. A fully absent directory is valid when the PE
     * does not declare relocations stripped; a partial directory is not. */
    if (rva == 0u && size == 0u) return XXEMUL_STATUS_OK;
    if (rva == 0u || size < 8u || rva > pe->size_of_image || size > pe->size_of_image - rva) return XXEMUL_STATUS_INVALID_IMAGE;
    table = (uint8_t *)xx_mem_alloc(size);
    if (table == NULL) return XXEMUL_STATUS_OUT_OF_MEMORY;
    xx_mem_copy(table, emulator->region_data + rva, size);

    offset = 0;
    while (offset < size) {
        uint32_t page, block;
        size_t item;
        if ((size_t)size - offset < 8u) goto invalid;
        page = xxemul_pe_u32(table + offset);
        block = xxemul_pe_u32(table + offset + 4u);
        if ((page & 0xfffu) != 0u || page >= pe->size_of_image || block < 8u || (block & 3u) != 0u || block > (size_t)size - offset) goto invalid;
        for (item = 8u; item < block; item += 2u) {
            uint16_t entry = xxemul_pe_u16(table + offset + item);
            unsigned type = entry >> 12;
            uint64_t target;
            size_t width;
            if (type == 0u) continue; /* IMAGE_REL_BASED_ABSOLUTE padding */
            if (type != 1u && type != 2u && type != expected_type) {
                xx_mem_free(table);
                return XXEMUL_STATUS_UNSUPPORTED_IMAGE;
            }
            width = type == 1u || type == 2u ? 2u : (format == XXEMUL_IMAGE_PE64 ? 8u : 4u);
            target = (uint64_t)page + (entry & 0xfffu);
            if (target >= pe->size_of_image || width > pe->size_of_image - target) goto invalid;
        }
        offset += block;
    }

    offset = 0;
    while (offset < size) {
        uint32_t page = xxemul_pe_u32(table + offset);
        uint32_t block = xxemul_pe_u32(table + offset + 4u);
        size_t item;
        for (item = 8u; item < block; item += 2u) {
            uint16_t entry = xxemul_pe_u16(table + offset + item);
            unsigned type = entry >> 12;
            uint8_t *target;
            uint64_t value;
            size_t width;
            size_t byte;
            if (type == 0u) continue;
            target = emulator->region_data + page + (entry & 0xfffu);
            width = type == 1u || type == 2u ? 2u : (format == XXEMUL_IMAGE_PE64 ? 8u : 4u);
            value = width == 2u ? xxemul_pe_u16(target) : xxemul_pe_u32(target);
            if (width == 8u) value |= (uint64_t)xxemul_pe_u32(target + 4u) << 32;
            /* Unsigned arithmetic also handles negative deltas. HIGH adds
             * the upper half of the PE32 relocation delta; LOW its low half. */
            value += type == 1u ? delta >> 16 : delta;
            for (byte = 0; byte < width; ++byte) target[byte] = (uint8_t)(value >> (8u * byte));
        }
        offset += block;
    }
    xx_mem_free(table);
    return XXEMUL_STATUS_OK;

invalid:
    xx_mem_free(table);
    return XXEMUL_STATUS_INVALID_IMAGE;
}

static int xxemul_pe_machine_mode(uint16_t machine, xxemul_image_format format, uint64_t *entry, xxemul_arch *arch, xxemul_mode *mode)
{
    switch (machine) {
        case 0x014cu:
            if (format != XXEMUL_IMAGE_PE32) return 0;
            *arch = XXEMUL_ARCH_X86;
            *mode = XXEMUL_MODE_X86_32;
            return 1;
        case 0x8664u:
            if (format != XXEMUL_IMAGE_PE64) return 0;
            *arch = XXEMUL_ARCH_X86;
            *mode = XXEMUL_MODE_X86_64;
            return 1;
        case 0x01c0u:
        case 0x01c2u:
        case 0x01c4u:
            if (format != XXEMUL_IMAGE_PE32) return 0;
            *arch = XXEMUL_ARCH_ARM;
            *mode = (machine != 0x01c0u || (*entry & 1u) != 0u) ? XXEMUL_MODE_ARM_T32 : XXEMUL_MODE_ARM_A32;
            *entry &= ~UINT64_C(1);
            return 1;
        case 0xaa64u:
            if (format != XXEMUL_IMAGE_PE64) return 0;
            *arch = XXEMUL_ARCH_ARM;
            *mode = XXEMUL_MODE_ARM_A64;
            return 1;
        default: return 0;
    }
}

xxemul *xxemul_load_pe(xxemul_image_format format, const uint8_t *image, size_t image_size, xx_io_device *io, uint64_t image_base, xxemul_status *status)
{
    xx_pe pe;
    xxemul *emulator = NULL;
    xxemul_arch arch;
    xxemul_mode mode;
    uint64_t entry;
    uint64_t base;
    uint16_t index;

    xx_pe_init(&pe, io, 0);
    *status = XXEMUL_STATUS_INVALID_IMAGE;
    if (!xx_pe_handle_base_info(&pe.format, NULL) || xx_pe_is_64(&pe) != (format == XXEMUL_IMAGE_PE64) || pe.size_of_image == 0u ||
        pe.size_of_headers > pe.size_of_image || pe.size_of_headers > image_size || pe.entry_point_rva >= pe.size_of_image ||
        pe.image_base > UINT64_MAX - pe.entry_point_rva) {
        goto done;
    }
    base = image_base != 0 ? image_base : pe.image_base;
    if (base > UINT64_MAX - pe.entry_point_rva) goto done;
    entry = base + pe.entry_point_rva;
    if (!xxemul_pe_machine_mode(xx_pe_get_machine(&pe), format, &entry, &arch, &mode)) {
        *status = XXEMUL_STATUS_UNSUPPORTED_IMAGE;
        goto done;
    }
    for (index = 0u; index < xx_pe_get_number_of_sections(&pe); ++index) {
        const xx_pe_section *section = xx_pe_get_section(&pe, index);
        uint64_t section_size;

        if (section == NULL) {
            goto done;
        }
        section_size = section->virtual_size > section->raw_size ? section->virtual_size : section->raw_size;
        if (section->virtual_address > pe.size_of_image || section_size > pe.size_of_image - section->virtual_address || section->raw_offset > image_size ||
            section->raw_size > image_size - section->raw_offset) {
            goto done;
        }
    }
    emulator = xxemul_image_allocate(arch, mode, base, pe.size_of_image, entry, 0, status);
    if (emulator == NULL) {
        goto done;
    }
    xx_mem_copy(emulator->region_data, image, pe.size_of_headers);
    for (index = 0u; index < xx_pe_get_number_of_sections(&pe); ++index) {
        const xx_pe_section *section = xx_pe_get_section(&pe, index);

        if (section->raw_size != 0u) {
            xx_mem_copy(emulator->region_data + section->virtual_address, image + section->raw_offset, section->raw_size);
        }
    }
    *status = xxemul_pe_relocate(emulator, &pe, format);
    if (*status != XXEMUL_STATUS_OK) {
        xxemul_destroy(emulator);
        emulator = NULL;
    }
done:
    xx_pe_destroy(&pe);
    return emulator;
}
