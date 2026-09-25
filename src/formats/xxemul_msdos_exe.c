#include "xxemul_internal.h"

#include <xxfclib/formats/msdos/xx_msdos.h>

#define XXEMUL_DOS_CONVENTIONAL_END 0xa0000u
#define XXEMUL_DOS_CONVENTIONAL_END_SEGMENT 0xa000u

static uint16_t xxemul_dos_word(const uint8_t *data)
{
    return (uint16_t)((uint16_t)data[0] | ((uint16_t)data[1] << 8));
}

int xxemul_load_msdos_exe(
    xxemul *emulator, const uint8_t *image,
    size_t image_size, xx_io_device *io)
{
    xx_msdos msdos;
    size_t header_size;
    size_t declared_size;
    size_t body_size;
    size_t relocation_count;
    size_t relocation_offset;
    size_t index;
    size_t file_declared_size;
    size_t body_paragraphs;
    uint32_t block_end;
    uint32_t available_extra;
    uint32_t allocated_extra;
    uint16_t load_segment = (uint16_t)(emulator->psp_segment + 0x10u);
    uint32_t load_address = (uint32_t)load_segment << 4;
    int valid = 0;

    xx_msdos_init(&msdos, io, 0);
    if (!xx_msdos_check_is_valid(&msdos.format, NULL)
        || !xx_msdos_handle_base_info(&msdos.format, NULL)
        || xx_msdos_has_pe_header(&msdos)
        || msdos.format.format_size <= 0) {
        goto done;
    }
    header_size = (size_t)xx_msdos_get_header_size(&msdos) * 16u;
    declared_size = (size_t)msdos.format.format_size;
    if (xx_msdos_get_pages_in_file(&msdos) == 0u
        || xx_msdos_get_bytes_on_last_page(&msdos) > 511u) {
        goto done;
    }
    file_declared_size =
        ((size_t)xx_msdos_get_pages_in_file(&msdos) - 1u) * 512u
        + (xx_msdos_get_bytes_on_last_page(&msdos) == 0u
            ? 512u : xx_msdos_get_bytes_on_last_page(&msdos));
    relocation_count = xx_msdos_get_relocations(&msdos);
    relocation_offset = xx_msdos_get_reloc_offset(&msdos);
    if (file_declared_size > image_size
        || header_size < 28u || header_size > declared_size
        || declared_size > image_size
        || relocation_offset > header_size
        || relocation_count > (header_size - relocation_offset) / 4u) {
        goto done;
    }
    body_size = declared_size - header_size;
    if (body_size == 0u
        || load_address + body_size > XXEMUL_DOS_CONVENTIONAL_END
        || ((uint32_t)xx_msdos_get_minalloc(&msdos) << 4)
            > XXEMUL_DOS_CONVENTIONAL_END - load_address - body_size) {
        goto done;
    }
    body_paragraphs = (body_size + 15u) / 16u;
    block_end = (uint32_t)load_segment + (uint32_t)body_paragraphs;
    if (block_end >= XXEMUL_DOS_CONVENTIONAL_END_SEGMENT) {
        goto done;
    }
    available_extra = XXEMUL_DOS_CONVENTIONAL_END_SEGMENT - block_end;
    if (xx_msdos_get_minalloc(&msdos) > available_extra) {
        goto done;
    }
    allocated_extra = xx_msdos_get_maxalloc(&msdos);
    if (allocated_extra > available_extra) {
        allocated_extra = available_extra;
    }
    if (allocated_extra < xx_msdos_get_minalloc(&msdos)) {
        allocated_extra = xx_msdos_get_minalloc(&msdos);
    }
    block_end += allocated_extra;
    for (index = 0u; index < relocation_count; ++index) {
        const uint8_t *entry = image + relocation_offset + index * 4u;
        size_t position = (size_t)xxemul_dos_word(entry + 2u) * 16u
            + xxemul_dos_word(entry);
        if (position > body_size || body_size - position < 2u) {
            goto done;
        }
    }
    xx_mem_copy(emulator->region_data + load_address,
        image + header_size, body_size);
    for (index = 0u; index < relocation_count; ++index) {
        const uint8_t *entry = image + relocation_offset + index * 4u;
        uint8_t *target = emulator->region_data + load_address
            + (size_t)xxemul_dos_word(entry + 2u) * 16u
            + xxemul_dos_word(entry);
        uint16_t adjusted = (uint16_t)(xxemul_dos_word(target) + load_segment);
        target[0] = (uint8_t)adjusted;
        target[1] = (uint8_t)(adjusted >> 8);
    }
    emulator->x86.segment[XXEMUL_X86_CS] =
        (uint16_t)(load_segment + xx_msdos_get_cs(&msdos));
    emulator->x86.segment[XXEMUL_X86_SS] =
        (uint16_t)(load_segment + xx_msdos_get_ss(&msdos));
    emulator->x86.segment[XXEMUL_X86_DS] = emulator->psp_segment;
    emulator->x86.segment[XXEMUL_X86_ES] = emulator->psp_segment;
    emulator->x86.ip = xx_msdos_get_ip(&msdos);
    emulator->x86.gpr[XXEMUL_X86_RSP] = xx_msdos_get_sp(&msdos);
    if (xxemul_dos_linear(
            emulator->x86.segment[XXEMUL_X86_CS],
            (uint16_t)emulator->x86.ip) >= XXEMUL_DOS_CONVENTIONAL_END
        || xxemul_dos_linear(
            emulator->x86.segment[XXEMUL_X86_SS],
            (uint16_t)emulator->x86.gpr[XXEMUL_X86_RSP])
            >= XXEMUL_DOS_CONVENTIONAL_END) {
        goto done;
    }
    {
        uint8_t *psp = emulator->region_data
            + ((uint32_t)emulator->psp_segment << 4);
        uint8_t *mcb = emulator->region_data
            + (((uint32_t)emulator->psp_segment - 1u) << 4);
        uint16_t block_size = (uint16_t)(block_end - emulator->psp_segment);

        psp[2] = (uint8_t)block_end;
        psp[3] = (uint8_t)(block_end >> 8);
        mcb[0] = block_end == XXEMUL_DOS_CONVENTIONAL_END_SEGMENT
            ? 'Z' : 'M';
        mcb[3] = (uint8_t)block_size;
        mcb[4] = (uint8_t)(block_size >> 8);
        if (block_end < XXEMUL_DOS_CONVENTIONAL_END_SEGMENT) {
            uint8_t *free_mcb = emulator->region_data + (block_end << 4);
            uint16_t free_size = (uint16_t)(
                XXEMUL_DOS_CONVENTIONAL_END_SEGMENT - block_end - 1u);

            free_mcb[0] = 'Z';
            free_mcb[1] = 0u;
            free_mcb[2] = 0u;
            free_mcb[3] = (uint8_t)free_size;
            free_mcb[4] = (uint8_t)(free_size >> 8);
        }
    }
    valid = 1;
done:
    xx_msdos_destroy(&msdos);
    return valid;
}
