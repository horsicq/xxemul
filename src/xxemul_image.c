#include "xxemul_internal.h"

#include <limits.h>

#define XXEMUL_IMAGE_STACK_SIZE (1024u * 1024u)
#define XXEMUL_PE_ARENA_SIZE (32u * 1024u * 1024u)
#define XXEMUL_IMAGE_MAX_REGION_SIZE (128u * 1024u * 1024u)
#define XXEMUL_IMAGE_MAX_FILE_SIZE (128u * 1024u * 1024u)

xxemul *xxemul_image_allocate(
    xxemul_arch arch, xxemul_mode mode, uint64_t base,
    uint64_t image_span, uint64_t entry, int unix_stack,
    xxemul_status *status)
{
    uint64_t total;
    uint64_t extra = XXEMUL_IMAGE_STACK_SIZE;
    uint64_t stack_top;
    xxemul *emulator;

    if (!unix_stack && image_span <= XXEMUL_IMAGE_MAX_REGION_SIZE
            - XXEMUL_PE_ARENA_SIZE)
        extra = XXEMUL_PE_ARENA_SIZE;
    if (image_span == 0u
        || image_span > XXEMUL_IMAGE_MAX_REGION_SIZE
            - extra
        || base > UINT64_MAX - image_span
            - extra) {
        *status = XXEMUL_STATUS_UNSUPPORTED_IMAGE;
        return NULL;
    }
    total = image_span + extra;
    if (entry < base || entry >= base + image_span
        || ((mode == XXEMUL_MODE_X86_32
             || mode == XXEMUL_MODE_ARM_A32
             || mode == XXEMUL_MODE_ARM_T32)
            && base + total > UINT32_MAX)) {
        *status = XXEMUL_STATUS_INVALID_IMAGE;
        return NULL;
    }
    if (((mode == XXEMUL_MODE_ARM_A32
           || mode == XXEMUL_MODE_ARM_A64) && (entry & 3u) != 0u)
        || (mode == XXEMUL_MODE_ARM_T32 && (entry & 1u) != 0u)) {
        *status = XXEMUL_STATUS_INVALID_IMAGE;
        return NULL;
    }
    emulator = xxemul_create_empty(
        arch, mode, base, (size_t)total, status);
    if (emulator == NULL) {
        return NULL;
    }
    stack_top = (base + total) & ~UINT64_C(15);
    if (unix_stack) {
        size_t word_size = (mode == XXEMUL_MODE_X86_64
            || mode == XXEMUL_MODE_ARM_A64) ? 8u : 4u;
        stack_top = (stack_top - 5u * word_size) & ~UINT64_C(15);
    }
    if (arch == XXEMUL_ARCH_X86) {
        emulator->x86.ip = entry;
        emulator->x86.flags = 2u;
        emulator->x86.gpr[XXEMUL_X86_RSP] = stack_top;
    } else {
        emulator->arm.pc = entry;
        emulator->arm.sp = stack_top;
    }
    *status = XXEMUL_STATUS_OK;
    return emulator;
}

xxemul *xxemul_create_image(
    xxemul_image_format format, const void *image,
    size_t image_size, xxemul_status *status)
{
    xx_io_device *io;
    xxemul *emulator;
    xxemul_status local_status;

    if (status == NULL) {
        status = &local_status;
    }
    *status = XXEMUL_STATUS_INVALID_ARGUMENT;
    if (format < XXEMUL_IMAGE_COM || format > XXEMUL_IMAGE_MACHO64
        || image == NULL || image_size == 0u
        || image_size > (size_t)LONG_MAX) {
        return NULL;
    }
    if (format == XXEMUL_IMAGE_COM || format == XXEMUL_IMAGE_MZ) {
        return xxemul_create_dos((xxemul_dos_format)format,
            image, image_size, status);
    }
    io = xx_io_mem_open_ro(image, image_size);
    if (io == NULL) {
        *status = XXEMUL_STATUS_OUT_OF_MEMORY;
        return NULL;
    }
    switch (format) {
    case XXEMUL_IMAGE_PE32:
    case XXEMUL_IMAGE_PE64:
        emulator = xxemul_load_pe(format, (const uint8_t *)image,
            image_size, io, status);
        break;
    case XXEMUL_IMAGE_ELF32:
    case XXEMUL_IMAGE_ELF64:
        emulator = xxemul_load_elf(format, (const uint8_t *)image,
            image_size, io, status);
        break;
    default:
        emulator = xxemul_load_macho(format, (const uint8_t *)image,
            image_size, io, status);
        break;
    }
    xx_io_close(io);
    return emulator;
}

xxemul *xxemul_create_image_file(
    xxemul_image_format format, const char *path, xxemul_status *status)
{
    xx_io_device *io;
    xxemul *emulator;
    uint8_t *image;
    int64_t size;
    xxemul_status local_status;

    if (status == NULL) {
        status = &local_status;
    }
    *status = XXEMUL_STATUS_INVALID_ARGUMENT;
    if (path == NULL || format < XXEMUL_IMAGE_COM
        || format > XXEMUL_IMAGE_MACHO64) {
        return NULL;
    }
    io = xx_io_file_open(path, "rb");
    if (io == NULL) {
        *status = XXEMUL_STATUS_IO_ERROR;
        return NULL;
    }
    size = xx_io_total_size(io);
    if (size <= 0 || size > XXEMUL_IMAGE_MAX_FILE_SIZE) {
        xx_io_close(io);
        *status = XXEMUL_STATUS_UNSUPPORTED_IMAGE;
        return NULL;
    }
    image = (uint8_t *)xx_mem_alloc((size_t)size);
    if (image == NULL) {
        xx_io_close(io);
        *status = XXEMUL_STATUS_OUT_OF_MEMORY;
        return NULL;
    }
    if (xx_io_read(io, image, (size_t)size) != (ssize_t)size) {
        xx_mem_free(image);
        xx_io_close(io);
        *status = XXEMUL_STATUS_IO_ERROR;
        return NULL;
    }
    xx_io_close(io);
    emulator = xxemul_create_image(format, image, (size_t)size, status);
    xx_mem_free(image);
    return emulator;
}
