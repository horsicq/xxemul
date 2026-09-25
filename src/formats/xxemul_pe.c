#include "xxemul_internal.h"

#include <xxfclib/formats/pe/xx_pe.h>

static int xxemul_pe_machine_mode(
    uint16_t machine, xxemul_image_format format,
    uint64_t *entry, xxemul_arch *arch, xxemul_mode *mode)
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
        *mode = (machine != 0x01c0u || (*entry & 1u) != 0u)
            ? XXEMUL_MODE_ARM_T32 : XXEMUL_MODE_ARM_A32;
        *entry &= ~UINT64_C(1);
        return 1;
    case 0xaa64u:
        if (format != XXEMUL_IMAGE_PE64) return 0;
        *arch = XXEMUL_ARCH_ARM;
        *mode = XXEMUL_MODE_ARM_A64;
        return 1;
    default:
        return 0;
    }
}

xxemul *xxemul_load_pe(
    xxemul_image_format format, const uint8_t *image,
    size_t image_size, xx_io_device *io, xxemul_status *status)
{
    xx_pe pe;
    xxemul *emulator = NULL;
    xxemul_arch arch;
    xxemul_mode mode;
    uint64_t entry;
    uint16_t index;

    xx_pe_init(&pe, io, 0);
    *status = XXEMUL_STATUS_INVALID_IMAGE;
    if (!xx_pe_handle_base_info(&pe.format, NULL)
        || xx_pe_is_64(&pe) != (format == XXEMUL_IMAGE_PE64)
        || pe.size_of_image == 0u
        || pe.size_of_headers > pe.size_of_image
        || pe.size_of_headers > image_size
        || pe.entry_point_rva >= pe.size_of_image
        || pe.image_base > UINT64_MAX - pe.entry_point_rva) {
        goto done;
    }
    entry = pe.image_base + pe.entry_point_rva;
    if (!xxemul_pe_machine_mode(
            xx_pe_get_machine(&pe), format, &entry, &arch, &mode)) {
        *status = XXEMUL_STATUS_UNSUPPORTED_IMAGE;
        goto done;
    }
    for (index = 0u; index < xx_pe_get_number_of_sections(&pe); ++index) {
        const xx_pe_section *section = xx_pe_get_section(&pe, index);
        uint64_t section_size;

        if (section == NULL) {
            goto done;
        }
        section_size = section->virtual_size > section->raw_size
            ? section->virtual_size : section->raw_size;
        if (section->virtual_address > pe.size_of_image
            || section_size > pe.size_of_image - section->virtual_address
            || section->raw_offset > image_size
            || section->raw_size > image_size - section->raw_offset) {
            goto done;
        }
    }
    emulator = xxemul_image_allocate(
        arch, mode, pe.image_base, pe.size_of_image, entry, 0, status);
    if (emulator == NULL) {
        goto done;
    }
    xx_mem_copy(emulator->region_data, image, pe.size_of_headers);
    for (index = 0u; index < xx_pe_get_number_of_sections(&pe); ++index) {
        const xx_pe_section *section = xx_pe_get_section(&pe, index);

        if (section->raw_size != 0u) {
            xx_mem_copy(emulator->region_data + section->virtual_address,
                image + section->raw_offset, section->raw_size);
        }
    }
done:
    xx_pe_destroy(&pe);
    return emulator;
}
