#include "xxemul_internal.h"

#define XXEMUL_VGA_TEXT_BASE 0xb8000u
#define XXEMUL_VGA_GRAPHICS_BASE 0xa0000u

static uint8_t xxemul_bios_ah(const xxemul *emulator)
{
    return (uint8_t)(emulator->x86.gpr[XXEMUL_X86_RAX] >> 8);
}

static void xxemul_bios_set_ax(xxemul *emulator, uint16_t value)
{
    emulator->x86.gpr[XXEMUL_X86_RAX] = value;
}

static xxemul_status xxemul_bios_video(xxemul *emulator)
{
    uint8_t function = xxemul_bios_ah(emulator);
    uint16_t count;
    uint16_t index;
    uint16_t x;
    uint16_t y;
    size_t cell;
    uint8_t character;

    switch (function) {
    case 0x00u:
        if ((uint8_t)emulator->x86.gpr[XXEMUL_X86_RAX] != 0x03u
            && (uint8_t)emulator->x86.gpr[XXEMUL_X86_RAX] != 0x13u) {
            return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
        }
        emulator->video_mode = (uint8_t)emulator->x86.gpr[XXEMUL_X86_RAX];
        emulator->cursor_row = 0u;
        emulator->cursor_column = 0u;
        xxemul_video_clear(emulator);
        emulator->region_data[0x449u] = emulator->video_mode;
        emulator->region_data[0x44au] =
            emulator->video_mode == 0x03u ? 80u : 40u;
        emulator->region_data[0x44bu] = 0u;
        return XXEMUL_STATUS_OK;
    case 0x02u:
        emulator->cursor_row =
            (uint8_t)(emulator->x86.gpr[XXEMUL_X86_RDX] >> 8);
        emulator->cursor_column =
            (uint8_t)emulator->x86.gpr[XXEMUL_X86_RDX];
        if (emulator->cursor_row >= 25u) {
            emulator->cursor_row = 24u;
        }
        if (emulator->cursor_column >= 80u) {
            emulator->cursor_column = 79u;
        }
        return XXEMUL_STATUS_OK;
    case 0x03u:
        emulator->x86.gpr[XXEMUL_X86_RDX] =
            (uint16_t)(((uint16_t)emulator->cursor_row << 8)
                | emulator->cursor_column);
        emulator->x86.gpr[XXEMUL_X86_RCX] = 0x0607u;
        return XXEMUL_STATUS_OK;
    case 0x09u:
    case 0x0au:
        if (emulator->video_mode != 0x03u) {
            return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
        }
        character = (uint8_t)emulator->x86.gpr[XXEMUL_X86_RAX];
        count = (uint16_t)emulator->x86.gpr[XXEMUL_X86_RCX];
        cell = (size_t)emulator->cursor_row * 80u
            + emulator->cursor_column;
        for (index = 0u; index < count && cell < 80u * 25u;
             ++index, ++cell) {
            emulator->region_data[XXEMUL_VGA_TEXT_BASE + cell * 2u] =
                character;
            if (function == 0x09u) {
                emulator->region_data[
                    XXEMUL_VGA_TEXT_BASE + cell * 2u + 1u] =
                    (uint8_t)emulator->x86.gpr[XXEMUL_X86_RBX];
            }
        }
        return XXEMUL_STATUS_OK;
    case 0x0cu:
    case 0x0du:
        if (emulator->video_mode != 0x13u) {
            return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
        }
        x = (uint16_t)emulator->x86.gpr[XXEMUL_X86_RCX];
        y = (uint16_t)emulator->x86.gpr[XXEMUL_X86_RDX];
        if (x >= 320u || y >= 200u) {
            return XXEMUL_STATUS_ADDRESS_FAULT;
        }
        if (function == 0x0cu) {
            emulator->region_data[
                XXEMUL_VGA_GRAPHICS_BASE + (size_t)y * 320u + x] =
                (uint8_t)emulator->x86.gpr[XXEMUL_X86_RAX];
        } else {
            emulator->x86.gpr[XXEMUL_X86_RAX] =
                (emulator->x86.gpr[XXEMUL_X86_RAX] & 0xff00u)
                | emulator->region_data[
                    XXEMUL_VGA_GRAPHICS_BASE + (size_t)y * 320u + x];
        }
        return XXEMUL_STATUS_OK;
    case 0x0eu:
        xxemul_video_putc(emulator,
            (uint8_t)emulator->x86.gpr[XXEMUL_X86_RAX]);
        return XXEMUL_STATUS_OK;
    case 0x0fu:
        xxemul_bios_set_ax(emulator,
            (uint16_t)((emulator->video_mode == 0x03u ? 80u : 40u) << 8)
                | emulator->video_mode);
        emulator->x86.gpr[XXEMUL_X86_RBX] &= 0x00ffu;
        return XXEMUL_STATUS_OK;
    default:
        return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    }
}

static xxemul_status xxemul_bios_keyboard(xxemul *emulator)
{
    uint8_t function = xxemul_bios_ah(emulator);
    uint16_t key;

    switch (function) {
    case 0x00u:
        if (emulator->key_count == 0u) {
            return XXEMUL_STATUS_INPUT_REQUIRED;
        }
        key = emulator->key_queue[emulator->key_head];
        emulator->key_head = (uint8_t)((emulator->key_head + 1u) % 32u);
        --emulator->key_count;
        xxemul_bios_set_ax(emulator, key);
        return XXEMUL_STATUS_OK;
    case 0x01u:
        if (emulator->key_count == 0u) {
            emulator->x86.flags |= UINT64_C(0x40);
        } else {
            emulator->x86.flags &= ~UINT64_C(0x40);
            xxemul_bios_set_ax(emulator,
                emulator->key_queue[emulator->key_head]);
        }
        return XXEMUL_STATUS_OK;
    case 0x02u:
        xxemul_bios_set_ax(emulator, 0u);
        return XXEMUL_STATUS_OK;
    default:
        return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    }
}

static xxemul_status xxemul_bios_multiplex(xxemul *emulator)
{
    uint16_t function = (uint16_t)emulator->x86.gpr[XXEMUL_X86_RAX];

    if (function == 0x1687u) {
        if (!xxemul_dpmi_prepare(emulator)) {
            xxemul_bios_set_ax(emulator, 1u);
            return XXEMUL_STATUS_OK;
        }
        xxemul_bios_set_ax(emulator, 0u);
        emulator->x86.gpr[XXEMUL_X86_RBX] = 1u;
        emulator->x86.gpr[XXEMUL_X86_RCX] = 0x0100u;
        emulator->x86.gpr[XXEMUL_X86_RSI] = 1u;
        emulator->x86.gpr[XXEMUL_X86_RDI] = 0x0200u;
        emulator->x86.segment[XXEMUL_X86_ES] = 0xf000u;
        return XXEMUL_STATUS_OK;
    }
    if (function == 0x4300u) {
        /* XMS installation check: AL=0 means no XMS driver. */
        emulator->x86.gpr[XXEMUL_X86_RAX] &= ~UINT64_C(0xff);
        return XXEMUL_STATUS_OK;
    }
    return XXEMUL_STATUS_OK;
}

static xxemul_status xxemul_bios_dpmi(xxemul *emulator)
{
    /* DPMI errors must be explicit; reporting success would corrupt clients. */
    xxemul_bios_set_ax(emulator, 0x8001u);
    emulator->x86.flags |= UINT64_C(1);
    return XXEMUL_STATUS_OK;
}

xxemul_status xxemul_bios_interrupt(xxemul *emulator, uint8_t vector)
{
    switch (vector) {
    case 0x10u:
        return xxemul_bios_video(emulator);
    case 0x11u:
        xxemul_bios_set_ax(emulator, 0x0021u);
        return XXEMUL_STATUS_OK;
    case 0x12u:
        xxemul_bios_set_ax(emulator, 640u);
        return XXEMUL_STATUS_OK;
    case 0x16u:
        return xxemul_bios_keyboard(emulator);
    case 0x15u:
        if (xxemul_bios_ah(emulator) == 0x88u) {
            xxemul_bios_set_ax(emulator, 0u);
            emulator->x86.flags &= ~UINT64_C(1);
            return XXEMUL_STATUS_OK;
        }
        xxemul_bios_set_ax(emulator, 0x8600u);
        emulator->x86.flags |= UINT64_C(1);
        return XXEMUL_STATUS_OK;
    case 0x1au:
        if (xxemul_bios_ah(emulator) == 0u) {
            emulator->x86.gpr[XXEMUL_X86_RCX] = 0u;
            emulator->x86.gpr[XXEMUL_X86_RDX] = 0u;
            emulator->x86.gpr[XXEMUL_X86_RAX] &= ~UINT64_C(0xff);
            return XXEMUL_STATUS_OK;
        }
        return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    case 0x2fu:
        return xxemul_bios_multiplex(emulator);
    case 0x31u:
        return xxemul_bios_dpmi(emulator);
    case 0x67u:
        xxemul_bios_set_ax(emulator, 0x8f00u);
        return XXEMUL_STATUS_OK;
    case 0x33u:
        if ((uint16_t)emulator->x86.gpr[XXEMUL_X86_RAX] == 0u) {
            xxemul_bios_set_ax(emulator, 0u);
            emulator->x86.gpr[XXEMUL_X86_RBX] = 0u;
            return XXEMUL_STATUS_OK;
        }
        return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    default:
        return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    }
}
