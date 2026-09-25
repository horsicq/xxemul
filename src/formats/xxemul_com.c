#include "xxemul_internal.h"

#include <xxfclib/formats/com/xx_com.h>

int xxemul_load_com(
    xxemul *emulator, const uint8_t *image,
    size_t image_size, xx_io_device *io)
{
    xx_com com;
    uint16_t psp = emulator->psp_segment;
    uint32_t load_address = xxemul_dos_linear(psp, XX_COM_ADDRESS_BEGIN);

    xx_com_init(&com, io, 0);
    if (!xx_com_check_is_valid(&com.format, NULL)
        || !xx_com_handle_base_info(&com.format, NULL)
        || xx_com_get_code_size(&com) != (int64_t)image_size) {
        xx_com_destroy(&com);
        return 0;
    }
    xx_mem_copy(emulator->region_data + load_address, image, image_size);
    emulator->x86.segment[XXEMUL_X86_CS] = psp;
    emulator->x86.segment[XXEMUL_X86_SS] = psp;
    emulator->x86.segment[XXEMUL_X86_DS] = psp;
    emulator->x86.segment[XXEMUL_X86_ES] = psp;
    emulator->x86.ip = xx_com_get_address_begin(&com);
    emulator->x86.gpr[XXEMUL_X86_RSP] = 0xfffeu;
    xx_com_destroy(&com);
    return 1;
}
