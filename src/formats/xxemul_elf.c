#include "xxemul_internal.h"

#include <xxfclib/formats/elf/xx_elf.h>

static int xxemul_elf_machine_mode(
    uint16_t machine, xxemul_image_format format,
    uint64_t *entry, xxemul_arch *arch, xxemul_mode *mode)
{
    switch (machine) {
    case 3u:
        if (format != XXEMUL_IMAGE_ELF32) return 0;
        *arch = XXEMUL_ARCH_X86;
        *mode = XXEMUL_MODE_X86_32;
        return 1;
    case 62u:
        if (format != XXEMUL_IMAGE_ELF64) return 0;
        *arch = XXEMUL_ARCH_X86;
        *mode = XXEMUL_MODE_X86_64;
        return 1;
    case 40u:
        if (format != XXEMUL_IMAGE_ELF32) return 0;
        *arch = XXEMUL_ARCH_ARM;
        *mode = (*entry & 1u) != 0u
            ? XXEMUL_MODE_ARM_T32 : XXEMUL_MODE_ARM_A32;
        *entry &= ~UINT64_C(1);
        return 1;
    case 183u:
        if (format != XXEMUL_IMAGE_ELF64) return 0;
        *arch = XXEMUL_ARCH_ARM;
        *mode = XXEMUL_MODE_ARM_A64;
        return 1;
    default:
        return 0;
    }
}

xxemul *xxemul_load_elf(
    xxemul_image_format format, const uint8_t *image,
    size_t image_size, xx_io_device *io, xxemul_status *status)
{
    xx_elf elf;
    xxemul *emulator = NULL;
    xxemul_arch arch;
    xxemul_mode mode;
    uint64_t entry;
    uint64_t base = UINT64_MAX;
    uint64_t end = 0u;
    uint64_t index;
    int entry_mapped = 0;

    xx_elf_init(&elf, io, 0);
    *status = XXEMUL_STATUS_INVALID_IMAGE;
    if (!xx_elf_handle_base_info(&elf.format, NULL)
        || xx_elf_is_64(&elf) != (format == XXEMUL_IMAGE_ELF64)) {
        goto done;
    }
    if (xx_elf_get_type(&elf) != XX_ELF_TYPE_EXEC
        || elf.data_encoding != XX_ELF_DATA_LSB) {
        *status = XXEMUL_STATUS_UNSUPPORTED_IMAGE;
        goto done;
    }
    entry = xx_elf_get_entry_point(&elf);
    if (!xxemul_elf_machine_mode(
            xx_elf_get_machine(&elf), format, &entry, &arch, &mode)) {
        *status = XXEMUL_STATUS_UNSUPPORTED_IMAGE;
        goto done;
    }
    for (index = 0u; index < xx_elf_get_number_of_program_headers(&elf);
         ++index) {
        const xx_elf_program_header *program =
            xx_elf_get_program_header(&elf, index);
        uint64_t program_end;

        if (program == NULL) {
            goto done;
        }
        if (program->type != XX_ELF_PROGRAM_LOAD
            || program->memory_size == 0u) {
            continue;
        }
        if (program->file_size > program->memory_size
            || program->offset > image_size
            || program->virtual_address > UINT64_MAX - program->memory_size) {
            goto done;
        }
        /* UPX-packed ELFs give the first PT_LOAD a file_size rounded up to a
         * page, which can run a few bytes past the physical end of the file;
         * the kernel simply zero-fills the tail. Tolerate that here rather
         * than rejecting the image - the copy below clamps to what exists. */
        program_end = program->virtual_address + program->memory_size;
        if (program->virtual_address < base) {
            base = program->virtual_address;
        }
        if (program_end > end) {
            end = program_end;
        }
        if (entry >= program->virtual_address && entry < program_end
            && (program->flags & 1u) != 0u) {
            entry_mapped = 1;
        }
    }
    if (base == UINT64_MAX || !entry_mapped) {
        goto done;
    }
    base &= ~UINT64_C(0xfff);
    emulator = xxemul_image_allocate(
        arch, mode, base, end - base, entry, 1, status);
    if (emulator == NULL) {
        goto done;
    }
    for (index = 0u; index < xx_elf_get_number_of_program_headers(&elf);
         ++index) {
        const xx_elf_program_header *program =
            xx_elf_get_program_header(&elf, index);

        if (program->type == XX_ELF_PROGRAM_LOAD
            && program->file_size != 0u) {
            uint64_t copy = program->file_size;
            if (copy > image_size - program->offset)
                copy = image_size - program->offset;   /* clamp to the file */
            xx_mem_copy(emulator->region_data
                    + (size_t)(program->virtual_address - base),
                image + (size_t)program->offset,
                (size_t)copy);
        }
    }
done:
    xx_elf_destroy(&elf);
    return emulator;
}
