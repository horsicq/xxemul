#include "xxemul_internal.h"
#include "xxemul_dos_files.h"

#include <string.h>

#define XXEMUL_VGA_TEXT_BASE 0xb8000u
#define XXEMUL_VGA_GRAPHICS_BASE 0xa0000u

/* One deterministic PIT period per4096 completed guest instructions. The
 * hardware request is distinct from the BDA counter maintained by BIOS INT8.
 * Reserved F000:0A00/0A80 do not overlap the DOS/DPMI host/callback thunks. */
#define XXEMUL_BIOS_TIMER_PHYSICAL 0xf0a00u
#define XXEMUL_BIOS_USER_TIMER_PHYSICAL 0xf0a80u
static const uint8_t bios_timer_code[] = {
    /* STI; save AX/DS; DS=40h; increment 32-bit BDA tick; midnight latch;
     * INT1C; PIC EOI; restore DS/AX; IRET. All real-mode execution is guest
     * code, including a handler's saved-vector far-JMP or PUSHF/CALL FAR. */
    0xfbu,0x50u,0x1eu,0xb8u,0x40u,0x00u,0x8eu,0xd8u,
    0x83u,0x06u,0x6cu,0x00u,0x01u,0x83u,0x16u,0x6eu,0x00u,0x00u,
    0x83u,0x3eu,0x6eu,0x00u,0x18u,0x72u,0x1bu,0x77u,0x08u,
    0x81u,0x3eu,0x6cu,0x00u,0xb0u,0x00u,0x72u,0x11u,
    0xc7u,0x06u,0x6cu,0x00u,0x00u,0x00u,0xc7u,0x06u,0x6eu,0x00u,0x00u,0x00u,
    0xc6u,0x06u,0x70u,0x00u,0x01u,0xcdu,0x1cu,0xb0u,0x20u,0xe6u,0x20u,0x1fu,0x58u,0xcfu
};

void xxemul_bios_initialize_timer(xxemul *emulator)
{
    uint8_t *memory = emulator->region_data;
    memcpy(memory + XXEMUL_BIOS_TIMER_PHYSICAL, bios_timer_code, sizeof(bios_timer_code));
    memory[XXEMUL_BIOS_USER_TIMER_PHYSICAL] = 0xcfu;
    memory[8u * 4u] = 0x00u; memory[8u * 4u + 1u] = 0x0au;
    memory[8u * 4u + 2u] = 0x00u; memory[8u * 4u + 3u] = 0xf0u;
    memory[0x1cu * 4u] = 0x80u; memory[0x1cu * 4u + 1u] = 0x0au;
    memory[0x1cu * 4u + 2u] = 0x00u; memory[0x1cu * 4u + 3u] = 0xf0u;
}

int xxemul_bios_timer_is_default(const xxemul *emulator)
{
    static const uint8_t vector[] = {0x00u,0x0au,0x00u,0xf0u};
    static const uint8_t user_vector[] = {0x80u,0x0au,0x00u,0xf0u};
    return emulator && emulator->dos_mode && emulator->region_address == 0u &&
        emulator->region_size > XXEMUL_BIOS_USER_TIMER_PHYSICAL && emulator->dos_pic_master_offset == 8u &&
        memcmp(emulator->region_data + 8u * 4u, vector, sizeof(vector)) == 0 &&
        memcmp(emulator->region_data + XXEMUL_BIOS_TIMER_PHYSICAL, bios_timer_code, sizeof(bios_timer_code)) == 0 &&
        /* A virtual default-BIOS service cannot silently skip a guest INT1C
         * callback. Such requests remain pending until real-mode delivery. */
        memcmp(emulator->region_data + 0x1cu * 4u, user_vector, sizeof(user_vector)) == 0 &&
        emulator->region_data[XXEMUL_BIOS_USER_TIMER_PHYSICAL] == 0xcfu;
}

static uint32_t bios_ticks(const xxemul *emulator)
{
    const uint8_t *p = emulator->region_data + 0x46cu;
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8u) |
        ((uint32_t)p[2] << 16u) | ((uint32_t)p[3] << 24u);
}

static void bios_store_ticks(xxemul *emulator, uint32_t ticks)
{
    uint8_t *p = emulator->region_data + 0x46cu;
    unsigned i;
    for (i = 0; i < 4u; ++i) p[i] = (uint8_t)(ticks >> (i * 8u));
}

void xxemul_bios_service_timer(xxemul *emulator)
{
    uint32_t ticks = bios_ticks(emulator) + 1u;
    /* Bounded DPMI default-BIOS host service. The dispatcher has checked
     * ownership/IF/PIC/shadow/in-service and consumes this pending period;
     * this does not manufacture a protected interrupt frame or a second IRQ. */
    if (ticks >= 0x1800b0u) {
        ticks = 0;
        emulator->region_data[0x470u] = 1u;
    }
    bios_store_ticks(emulator, ticks);
}

void xxemul_bios_advance_clock(xxemul *emulator)
{
    if (!emulator->dos_mode || emulator->region_address != 0u || emulator->region_size <= 0x470u) return;
    if (++emulator->dos_timer_instructions < 0x1000u) return;
    emulator->dos_timer_instructions = 0;
    /* The8259 coalesces requests while masked, IF-clear or in service.
     * Only the real BIOS ISR or eligible default DPMI host service updates BDA. */
    emulator->dos_irq0_pending = 1u;
}

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
            if ((uint8_t)emulator->x86.gpr[XXEMUL_X86_RAX] != 0x03u && (uint8_t)emulator->x86.gpr[XXEMUL_X86_RAX] != 0x13u) {
                return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
            }
            emulator->video_mode = (uint8_t)emulator->x86.gpr[XXEMUL_X86_RAX];
            emulator->cursor_row = 0u;
            emulator->cursor_column = 0u;
            xxemul_video_clear(emulator);
            emulator->region_data[0x449u] = emulator->video_mode;
            emulator->region_data[0x44au] = emulator->video_mode == 0x03u ? 80u : 40u;
            emulator->region_data[0x44bu] = 0u;
            return XXEMUL_STATUS_OK;
        case 0x02u:
            emulator->cursor_row = (uint8_t)(emulator->x86.gpr[XXEMUL_X86_RDX] >> 8);
            emulator->cursor_column = (uint8_t)emulator->x86.gpr[XXEMUL_X86_RDX];
            if (emulator->cursor_row >= 25u) {
                emulator->cursor_row = 24u;
            }
            if (emulator->cursor_column >= 80u) {
                emulator->cursor_column = 79u;
            }
            return XXEMUL_STATUS_OK;
        case 0x03u:
            emulator->x86.gpr[XXEMUL_X86_RDX] = (uint16_t)(((uint16_t)emulator->cursor_row << 8) | emulator->cursor_column);
            emulator->x86.gpr[XXEMUL_X86_RCX] = 0x0607u;
            return XXEMUL_STATUS_OK;
        case 0x09u:
        case 0x0au:
            if (emulator->video_mode != 0x03u) {
                return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
            }
            character = (uint8_t)emulator->x86.gpr[XXEMUL_X86_RAX];
            count = (uint16_t)emulator->x86.gpr[XXEMUL_X86_RCX];
            cell = (size_t)emulator->cursor_row * 80u + emulator->cursor_column;
            for (index = 0u; index < count && cell < 80u * 25u; ++index, ++cell) {
                emulator->region_data[XXEMUL_VGA_TEXT_BASE + cell * 2u] = character;
                if (function == 0x09u) {
                    emulator->region_data[XXEMUL_VGA_TEXT_BASE + cell * 2u + 1u] = (uint8_t)emulator->x86.gpr[XXEMUL_X86_RBX];
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
                emulator->region_data[XXEMUL_VGA_GRAPHICS_BASE + (size_t)y * 320u + x] = (uint8_t)emulator->x86.gpr[XXEMUL_X86_RAX];
            } else {
                emulator->x86.gpr[XXEMUL_X86_RAX] =
                    (emulator->x86.gpr[XXEMUL_X86_RAX] & 0xff00u) | emulator->region_data[XXEMUL_VGA_GRAPHICS_BASE + (size_t)y * 320u + x];
            }
            return XXEMUL_STATUS_OK;
        case 0x0eu: xxemul_video_putc(emulator, (uint8_t)emulator->x86.gpr[XXEMUL_X86_RAX]); return XXEMUL_STATUS_OK;
        case 0x0fu:
            xxemul_bios_set_ax(emulator, (uint16_t)((emulator->video_mode == 0x03u ? 80u : 40u) << 8) | emulator->video_mode);
            emulator->x86.gpr[XXEMUL_X86_RBX] &= 0x00ffu;
            return XXEMUL_STATUS_OK;
        default:
            /* Unknown video sub-function: ignore silently. */
            return XXEMUL_STATUS_OK;
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
                xxemul_bios_set_ax(emulator, emulator->key_queue[emulator->key_head]);
            }
            return XXEMUL_STATUS_OK;
        case 0x02u: xxemul_bios_set_ax(emulator, 0u); return XXEMUL_STATUS_OK;
        default:
            /* Unknown keyboard sub-function: ignore. */
            return XXEMUL_STATUS_OK;
    }
}

static xxemul_status xxemul_bios_multiplex(xxemul *emulator)
{
    uint16_t function = (uint16_t)emulator->x86.gpr[XXEMUL_X86_RAX];

    if (function == 0x1687u) {
        /* EXEC currently hosts real-mode children only. Do not let their
         * installation probe mutate the parent's DPMI host/client state. */
        if (xxemul_dos_files_child_active(emulator) || !xxemul_dpmi_prepare(emulator)) {
            xxemul_bios_set_ax(emulator, 1u);
            return XXEMUL_STATUS_OK;
        }
        xxemul_bios_set_ax(emulator, 0u);
        emulator->x86.gpr[XXEMUL_X86_RBX] = 1u;
        /* DPMI 0.9, 386 CPU, no caller-allocated private paragraphs. */
        emulator->x86.gpr[XXEMUL_X86_RCX] = 3u;
        emulator->x86.gpr[XXEMUL_X86_RDX] = 0x005au;
        emulator->x86.gpr[XXEMUL_X86_RSI] = 0u;
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
        case 0x10u: return xxemul_bios_video(emulator);
        case 0x11u: xxemul_bios_set_ax(emulator, 0x0021u); return XXEMUL_STATUS_OK;
        case 0x12u: xxemul_bios_set_ax(emulator, 640u); return XXEMUL_STATUS_OK;
        case 0x16u: return xxemul_bios_keyboard(emulator);
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
                uint32_t ticks = bios_ticks(emulator);
                emulator->x86.gpr[XXEMUL_X86_RCX] = ticks >> 16u;
                emulator->x86.gpr[XXEMUL_X86_RDX] = ticks & 0xffffu;
                emulator->x86.gpr[XXEMUL_X86_RAX] = (emulator->x86.gpr[XXEMUL_X86_RAX] & ~UINT64_C(0xff)) |
                    emulator->region_data[0x470u];
                emulator->region_data[0x470u] = 0;
                emulator->x86.flags &= ~UINT64_C(1);
                return XXEMUL_STATUS_OK;
            }
            if (xxemul_bios_ah(emulator) == 1u) {
                uint32_t ticks = ((uint32_t)(uint16_t)emulator->x86.gpr[XXEMUL_X86_RCX] << 16u) |
                    (uint16_t)emulator->x86.gpr[XXEMUL_X86_RDX];
                bios_store_ticks(emulator, ticks % 0x1800b0u);
                emulator->region_data[0x470u] = 0;
                emulator->dos_timer_instructions = 0;
                emulator->x86.flags &= ~UINT64_C(1);
                return XXEMUL_STATUS_OK;
            }
            return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
        case 0x2fu: return xxemul_bios_multiplex(emulator);
        case 0x31u: return xxemul_bios_dpmi(emulator);
        case 0x67u: xxemul_bios_set_ax(emulator, 0x8f00u); return XXEMUL_STATUS_OK;
        case 0x33u:
            if ((uint16_t)emulator->x86.gpr[XXEMUL_X86_RAX] == 0u) {
                xxemul_bios_set_ax(emulator, 0u);
                emulator->x86.gpr[XXEMUL_X86_RBX] = 0u;
                return XXEMUL_STATUS_OK;
            }
            if ((uint16_t)emulator->x86.gpr[XXEMUL_X86_RAX] == 3u) {
                /* No pointing device supplies movement or button events. */
                emulator->x86.gpr[XXEMUL_X86_RBX] = 0u;
                emulator->x86.gpr[XXEMUL_X86_RCX] = 0u;
                emulator->x86.gpr[XXEMUL_X86_RDX] = 0u;
                return XXEMUL_STATUS_OK;
            }
            if ((uint16_t)emulator->x86.gpr[XXEMUL_X86_RAX] == 0x1du &&
                (uint16_t)emulator->x86.gpr[XXEMUL_X86_RBX] == 0u) {
                /* The absent cursor has only the default display page. */
                return XXEMUL_STATUS_OK;
            }
            if ((uint16_t)emulator->x86.gpr[XXEMUL_X86_RAX] == 0x1eu) {
                emulator->x86.gpr[XXEMUL_X86_RBX] = 0u;
                return XXEMUL_STATUS_OK;
            }
            if ((uint16_t)emulator->x86.gpr[XXEMUL_X86_RAX] == 1u ||
                (uint16_t)emulator->x86.gpr[XXEMUL_X86_RAX] == 2u ||
                (uint16_t)emulator->x86.gpr[XXEMUL_X86_RAX] == 4u ||
                (uint16_t)emulator->x86.gpr[XXEMUL_X86_RAX] == 7u ||
                (uint16_t)emulator->x86.gpr[XXEMUL_X86_RAX] == 8u) {
                /* Visibility/range setters have no return values. This
                 * host exposes an absent mouse, so there is no cursor. */
                return XXEMUL_STATUS_OK;
            }
            return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
        case 0x04u:
            /* INT 4: overflow (triggered by INTO). Treat as NOP. */
            return XXEMUL_STATUS_OK;
        default:
            /* Unknown BIOS interrupt vector: silently ignore in DOS real mode. */
            return XXEMUL_STATUS_OK;
    }
}
