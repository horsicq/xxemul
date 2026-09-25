#include "xxemul_internal.h"
#include "xxemul_dos_files.h"

#include <limits.h>

#define XXEMUL_DOS_MEMORY_SIZE 0x2200000u
#define XXEMUL_DOS_PSP_SEGMENT 0x0814u
#define XXEMUL_DOS_CONVENTIONAL_END 0xa000u
#define XXEMUL_DOS_INT21_THUNK_PHYSICAL 0xf0100u
#define XXEMUL_DOS_INT10_THUNK_PHYSICAL 0xf0110u

uint32_t xxemul_dos_linear(uint16_t segment, uint16_t offset)
{
    return (((uint32_t)segment << 4) + offset) & 0xfffffu;
}

uint32_t xxemul_dos_physical(const xxemul *emulator,
    uint16_t segment, uint16_t offset)
{
    uint32_t address = ((uint32_t)segment << 4) + offset;
    return (emulator->dos_port_92 & 2u) != 0u
        ? address : address & 0xfffffu;
}

static void xxemul_dos_make_psp(xxemul *emulator)
{
    uint8_t *psp = emulator->region_data
        + xxemul_dos_linear(emulator->psp_segment, 0u);
    uint8_t *mcb = emulator->region_data
        + xxemul_dos_linear((uint16_t)(emulator->psp_segment - 1u), 0u);
    uint16_t block_size = (uint16_t)(
        XXEMUL_DOS_CONVENTIONAL_END - emulator->psp_segment);

    mcb[0] = 'Z';
    mcb[1] = (uint8_t)emulator->psp_segment;
    mcb[2] = (uint8_t)(emulator->psp_segment >> 8);
    mcb[3] = (uint8_t)block_size;
    mcb[4] = (uint8_t)(block_size >> 8);
    psp[0] = 0xcdu;
    psp[1] = 0x20u;
    psp[2] = 0u;
    psp[3] = (uint8_t)(XXEMUL_DOS_CONVENTIONAL_END >> 8);
    psp[0x16] = (uint8_t)emulator->psp_segment;
    psp[0x17] = (uint8_t)(emulator->psp_segment >> 8);
    psp[0x50] = 0xcdu;
    psp[0x51] = 0x21u;
    psp[0x52] = 0xcbu;
    psp[0x81] = 0x0du;
}

xxemul *xxemul_create_dos(
    xxemul_dos_format format, const void *image,
    size_t image_size, xxemul_status *status)
{
    xx_io_device *io;
    xxemul *emulator;
    int loaded;

    if (status != NULL) {
        *status = XXEMUL_STATUS_INVALID_ARGUMENT;
    }
    if ((format != XXEMUL_DOS_COM && format != XXEMUL_DOS_MZ)
        || image == NULL || image_size == 0u
        || image_size > (size_t)LONG_MAX) {
        return NULL;
    }
    io = xx_io_mem_open_ro(image, image_size);
    if (io == NULL) {
        if (status != NULL) {
            *status = XXEMUL_STATUS_OUT_OF_MEMORY;
        }
        return NULL;
    }
    emulator = xxemul_create_empty(
        XXEMUL_ARCH_X86, XXEMUL_MODE_X86_16,
        0u, XXEMUL_DOS_MEMORY_SIZE, status);
    if (emulator == NULL) {
        xx_io_close(io);
        return NULL;
    }
    emulator->dos_mode = 1;
    emulator->psp_segment = XXEMUL_DOS_PSP_SEGMENT;
    emulator->dos_dta_segment = emulator->psp_segment;
    emulator->dos_dta_offset = 0x80u;
    emulator->dos_port_92 = 2u;
    emulator->dos_kbc_output = 3u;
    emulator->x86.flags = 0x202u;
    xxemul_dos_make_psp(emulator);
    xxemul_dos_files_initialize_kernel(emulator);
    /* Real-mode DPMI interrupt simulation reads the IVT directly. */
    emulator->region_data[0x21u * 4u] = 0x00u;
    emulator->region_data[0x21u * 4u + 1u] = 0x01u;
    emulator->region_data[0x21u * 4u + 2u] = 0x00u;
    emulator->region_data[0x21u * 4u + 3u] = 0xf0u;
    emulator->region_data[XXEMUL_DOS_INT21_THUNK_PHYSICAL] = 0xcfu;
    emulator->region_data[0x10u * 4u] = 0x10u;
    emulator->region_data[0x10u * 4u + 1u] = 0x01u;
    emulator->region_data[0x10u * 4u + 2u] = 0x00u;
    emulator->region_data[0x10u * 4u + 3u] = 0xf0u;
    emulator->region_data[XXEMUL_DOS_INT10_THUNK_PHYSICAL] = 0xcfu;
    emulator->region_data[0x449u] = 3u;
    emulator->region_data[0x44au] = 80u;
    loaded = format == XXEMUL_DOS_COM
        ? xxemul_load_com(emulator, image, image_size, io)
        : xxemul_load_msdos_exe(emulator, image, image_size, io);
    xx_io_close(io);
    if (!loaded) {
        xxemul_destroy(emulator);
        if (status != NULL) {
            *status = XXEMUL_STATUS_INVALID_IMAGE;
        }
        return NULL;
    }
    xxemul_video_clear(emulator);
    if (status != NULL) {
        *status = XXEMUL_STATUS_OK;
    }
    return emulator;
}

xxemul_status xxemul_dos_get_exit_code(
    const xxemul *emulator, uint8_t *exit_code)
{
    if (emulator == NULL || !emulator->dos_mode || exit_code == NULL) {
        return XXEMUL_STATUS_INVALID_ARGUMENT;
    }
    *exit_code = emulator->exit_code;
    return XXEMUL_STATUS_OK;
}

xxemul_status xxemul_dos_push_key(
    xxemul *emulator, uint8_t ascii, uint8_t scan_code)
{
    uint8_t tail;

    if (emulator == NULL || !emulator->dos_mode) {
        return XXEMUL_STATUS_INVALID_ARGUMENT;
    }
    if (emulator->key_count == 32u) {
        return XXEMUL_STATUS_LIMIT_REACHED;
    }
    tail = (uint8_t)((emulator->key_head + emulator->key_count) % 32u);
    emulator->key_queue[tail] = (uint16_t)(ascii | ((uint16_t)scan_code << 8));
    ++emulator->key_count;
    return XXEMUL_STATUS_OK;
}

xxemul_status xxemul_dos_set_output_callback(
    xxemul *emulator, xxemul_dos_output_callback callback, void *context)
{
    if (emulator == NULL || !emulator->dos_mode) {
        return XXEMUL_STATUS_INVALID_ARGUMENT;
    }
    emulator->output_callback = callback;
    emulator->output_context = context;
    return XXEMUL_STATUS_OK;
}

xxemul *xxemul_create_dos_file(
    xxemul_dos_format format, const char *path, xxemul_status *status)
{
    if (status != NULL) {
        *status = XXEMUL_STATUS_INVALID_ARGUMENT;
    }
    if (path == NULL || (format != XXEMUL_DOS_COM
        && format != XXEMUL_DOS_MZ)) {
        return NULL;
    }
    return xxemul_create_image_file(
        format == XXEMUL_DOS_COM ? XXEMUL_IMAGE_COM : XXEMUL_IMAGE_MZ,
        path, status);
}
