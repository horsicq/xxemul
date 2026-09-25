#include "xxemul_internal.h"

#include <string.h>

#define DPMI_GDT_BASE 0x100000u
#define DPMI_HEAP_BASE 0x200000u
#define DPMI_HEAP_LIMIT 0x1200000u
#define DPMI_CF UINT64_C(1)

static uint16_t dpmi_u16(const uint8_t *bytes)
{
    return (uint16_t)(bytes[0] | ((uint16_t)bytes[1] << 8u));
}

static uint32_t dpmi_u32(const uint8_t *bytes)
{
    return (uint32_t)bytes[0] | ((uint32_t)bytes[1] << 8u)
        | ((uint32_t)bytes[2] << 16u) | ((uint32_t)bytes[3] << 24u);
}

static void dpmi_put_u16(uint8_t *bytes, uint16_t value)
{
    bytes[0] = (uint8_t)value;
    bytes[1] = (uint8_t)(value >> 8u);
}

static void dpmi_put_u32(uint8_t *bytes, uint32_t value)
{
    bytes[0] = (uint8_t)value;
    bytes[1] = (uint8_t)(value >> 8u);
    bytes[2] = (uint8_t)(value >> 16u);
    bytes[3] = (uint8_t)(value >> 24u);
}

static void dpmi_descriptor(xxemul *emulator, uint16_t selector,
    uint32_t base, uint32_t limit, uint8_t access, uint8_t flags)
{
    uint8_t *bytes = emulator->region_data + DPMI_GDT_BASE + selector;
    uint32_t encoded_limit = limit;

    if (limit > 0xfffffu) {
        encoded_limit = limit >> 12u;
        flags |= 8u;
    }
    dpmi_put_u16(bytes, (uint16_t)encoded_limit);
    dpmi_put_u16(bytes + 2u, (uint16_t)base);
    bytes[4] = (uint8_t)(base >> 16u);
    bytes[5] = access;
    bytes[6] = (uint8_t)((flags << 4u) | ((encoded_limit >> 16u) & 15u));
    bytes[7] = (uint8_t)(base >> 24u);
}

static void dpmi_cache(xxemul *emulator, unsigned index,
    uint16_t selector, uint32_t base, uint32_t limit,
    uint8_t access, uint8_t flags)
{
    emulator->x86.segment[index] = selector;
    emulator->dos_segments[index].base = base;
    emulator->dos_segments[index].limit = limit;
    emulator->dos_segments[index].access = access;
    emulator->dos_segments[index].flags = flags;
    emulator->dos_segments[index].valid = 1u;
}

int xxemul_dpmi_prepare(xxemul *emulator)
{
    uint32_t mcb_segment = (uint32_t)emulator->psp_segment - 1u;
    uint8_t *mcb = emulator->region_data + (mcb_segment << 4u);
    uint32_t end;
    uint32_t free_segment;
    uint8_t *free_mcb;
    uint8_t *psp;

    if (emulator->dos_dpmi_prepared) return 1;
    if (mcb[0] != 'Z' || dpmi_u16(mcb + 1u) != emulator->psp_segment)
        return 0;
    end = mcb_segment + 1u + dpmi_u16(mcb + 3u);
    if (end > 0xa000u || end - emulator->psp_segment < 0x120u)
        return 0;
    free_segment = end - 0x11u;
    free_mcb = emulator->region_data + (free_segment << 4u);
    free_mcb[0] = 'Z';
    dpmi_put_u16(free_mcb + 1u, 0u);
    dpmi_put_u16(free_mcb + 3u, 0x10u);
    mcb[0] = 'M';
    dpmi_put_u16(mcb + 3u,
        (uint16_t)(free_segment - mcb_segment - 1u));
    psp = emulator->region_data + ((uint32_t)emulator->psp_segment << 4u);
    dpmi_put_u16(psp + 2u, (uint16_t)free_segment);
    emulator->dos_dpmi_prepared = 1u;
    return 1;
}

xxemul_status xxemul_dpmi_enter(xxemul *emulator)
{
    uint16_t stack_segment = emulator->x86.segment[XXEMUL_X86_SS];
    uint16_t stack_offset = (uint16_t)emulator->x86.gpr[XXEMUL_X86_RSP];
    uint32_t frame = ((uint32_t)stack_segment << 4u) + stack_offset;
    uint16_t return_ip;
    uint16_t return_segment;
    uint16_t data_segment;

    if (emulator->region_size < DPMI_HEAP_LIMIT
        || frame > emulator->region_size
        || emulator->region_size - frame < 4u)
        return XXEMUL_STATUS_ADDRESS_FAULT;
    return_ip = dpmi_u16(emulator->region_data + frame);
    return_segment = dpmi_u16(emulator->region_data + frame + 2u);
    data_segment = emulator->x86.segment[XXEMUL_X86_DS];
    emulator->dos_gdtr_base = DPMI_GDT_BASE;
    emulator->dos_gdtr_limit = 0xfffu;
    emulator->dos_dpmi_next_selector = 0x28u;
    emulator->dos_dpmi_heap_next = DPMI_HEAP_BASE;

    dpmi_descriptor(emulator, 0x08u,
        (uint32_t)return_segment << 4u, 0xffffu, 0x9bu, 0u);
    dpmi_descriptor(emulator, 0x10u,
        (uint32_t)stack_segment << 4u, 0xffffu, 0x93u, 0u);
    dpmi_descriptor(emulator, 0x18u,
        (uint32_t)data_segment << 4u, 0xffffu, 0x93u, 0u);
    dpmi_descriptor(emulator, 0x20u,
        (uint32_t)emulator->psp_segment << 4u, 0xffffu, 0x93u, 0u);
    emulator->dos_cr0 |= 1u;
    dpmi_cache(emulator, XXEMUL_X86_CS, 0x08u,
        (uint32_t)return_segment << 4u, 0xffffu, 0x9bu, 0u);
    dpmi_cache(emulator, XXEMUL_X86_SS, 0x10u,
        (uint32_t)stack_segment << 4u, 0xffffu, 0x93u, 0u);
    dpmi_cache(emulator, XXEMUL_X86_DS, 0x18u,
        (uint32_t)data_segment << 4u, 0xffffu, 0x93u, 0u);
    dpmi_cache(emulator, XXEMUL_X86_ES, 0x20u,
        (uint32_t)emulator->psp_segment << 4u, 0xffffu, 0x93u, 0u);
    emulator->x86.gpr[XXEMUL_X86_RSP] = (uint16_t)(stack_offset + 4u);
    emulator->x86.ip = return_ip;
    emulator->x86.flags &= ~DPMI_CF;
    return XXEMUL_STATUS_OK;
}

static xxemul_status dpmi_simulate_dos(xxemul *emulator)
{
    uint32_t offset = (uint32_t)emulator->x86.gpr[XXEMUL_X86_RDI];
    uint32_t base = emulator->dos_segments[XXEMUL_X86_ES].base;
    uint32_t address = base + offset;
    uint8_t *frame;
    xxemul_x86_state saved;
    xxemul_status status;

    if ((uint16_t)emulator->x86.gpr[XXEMUL_X86_RBX] != 0x21u
        || address < base || address > emulator->region_size
        || emulator->region_size - address < 0x32u)
        return XXEMUL_STATUS_ADDRESS_FAULT;
    frame = emulator->region_data + address;
    saved = emulator->x86;
    emulator->x86.gpr[XXEMUL_X86_RDI] = dpmi_u32(frame);
    emulator->x86.gpr[XXEMUL_X86_RSI] = dpmi_u32(frame + 4u);
    emulator->x86.gpr[XXEMUL_X86_RBP] = dpmi_u32(frame + 8u);
    emulator->x86.gpr[XXEMUL_X86_RBX] = dpmi_u32(frame + 0x10u);
    emulator->x86.gpr[XXEMUL_X86_RDX] = dpmi_u32(frame + 0x14u);
    emulator->x86.gpr[XXEMUL_X86_RCX] = dpmi_u32(frame + 0x18u);
    emulator->x86.gpr[XXEMUL_X86_RAX] = dpmi_u32(frame + 0x1cu);
    emulator->x86.segment[XXEMUL_X86_ES] = dpmi_u16(frame + 0x22u);
    emulator->x86.segment[XXEMUL_X86_DS] = dpmi_u16(frame + 0x24u);
    emulator->x86.flags = dpmi_u16(frame + 0x20u) | 2u;
    status = xxemul_msdos_interrupt(emulator, 0x21u);
    if (status == XXEMUL_STATUS_OK) {
        dpmi_put_u32(frame, (uint32_t)emulator->x86.gpr[XXEMUL_X86_RDI]);
        dpmi_put_u32(frame + 4u,
            (uint32_t)emulator->x86.gpr[XXEMUL_X86_RSI]);
        dpmi_put_u32(frame + 8u,
            (uint32_t)emulator->x86.gpr[XXEMUL_X86_RBP]);
        dpmi_put_u32(frame + 0x10u,
            (uint32_t)emulator->x86.gpr[XXEMUL_X86_RBX]);
        dpmi_put_u32(frame + 0x14u,
            (uint32_t)emulator->x86.gpr[XXEMUL_X86_RDX]);
        dpmi_put_u32(frame + 0x18u,
            (uint32_t)emulator->x86.gpr[XXEMUL_X86_RCX]);
        dpmi_put_u32(frame + 0x1cu,
            (uint32_t)emulator->x86.gpr[XXEMUL_X86_RAX]);
        dpmi_put_u16(frame + 0x20u, (uint16_t)emulator->x86.flags);
        dpmi_put_u16(frame + 0x22u,
            emulator->x86.segment[XXEMUL_X86_ES]);
        dpmi_put_u16(frame + 0x24u,
            emulator->x86.segment[XXEMUL_X86_DS]);
    }
    emulator->x86 = saved;
    if (status == XXEMUL_STATUS_OK)
        emulator->x86.flags &= ~DPMI_CF;
    return status;
}

xxemul_status xxemul_dpmi_interrupt(xxemul *emulator)
{
    uint16_t function = (uint16_t)emulator->x86.gpr[XXEMUL_X86_RAX];
    uint16_t selector = (uint16_t)emulator->x86.gpr[XXEMUL_X86_RBX];
    uint8_t *descriptor;
    uint32_t address;
    uint32_t bytes;

    emulator->x86.flags &= ~DPMI_CF;
    switch (function) {
    case 0x0000u:
        if ((uint16_t)emulator->x86.gpr[XXEMUL_X86_RCX] != 1u
            || emulator->dos_dpmi_next_selector > 0xff0u)
            break;
        selector = emulator->dos_dpmi_next_selector;
        emulator->dos_dpmi_next_selector += 8u;
        dpmi_descriptor(emulator, selector, 0u, 0xffffu, 0x93u, 0u);
        emulator->x86.gpr[XXEMUL_X86_RAX] = selector;
        return XXEMUL_STATUS_OK;
    case 0x0007u:
    case 0x0008u:
    case 0x0009u:
        if (selector < 8u || selector >= emulator->dos_dpmi_next_selector
            || (selector & 7u) != 0u)
            break;
        descriptor = emulator->region_data + DPMI_GDT_BASE + selector;
        if (function == 0x0007u) {
            uint32_t base = ((uint32_t)(uint16_t)
                emulator->x86.gpr[XXEMUL_X86_RCX] << 16u)
                | (uint16_t)emulator->x86.gpr[XXEMUL_X86_RDX];
            dpmi_put_u16(descriptor + 2u, (uint16_t)base);
            descriptor[4] = (uint8_t)(base >> 16u);
            descriptor[7] = (uint8_t)(base >> 24u);
        } else if (function == 0x0008u) {
            uint32_t limit = ((uint32_t)(uint16_t)
                emulator->x86.gpr[XXEMUL_X86_RCX] << 16u)
                | (uint16_t)emulator->x86.gpr[XXEMUL_X86_RDX];
            uint32_t encoded = limit > 0xfffffu ? limit >> 12u : limit;
            dpmi_put_u16(descriptor, (uint16_t)encoded);
            descriptor[6] = (uint8_t)((descriptor[6] & 0x70u)
                | (limit > 0xfffffu ? 0x80u : 0u)
                | ((encoded >> 16u) & 15u));
        } else {
            uint16_t rights = (uint16_t)emulator->x86.gpr[XXEMUL_X86_RCX];
            descriptor[5] = (uint8_t)rights;
            descriptor[6] = (uint8_t)((descriptor[6] & 15u)
                | ((rights >> 8u) & 0xf0u));
        }
        return XXEMUL_STATUS_OK;
    case 0x0500u:
        address = emulator->dos_segments[XXEMUL_X86_ES].base
            + (uint32_t)emulator->x86.gpr[XXEMUL_X86_RDI];
        if (address > emulator->region_size
            || emulator->region_size - address < 0x30u)
            return XXEMUL_STATUS_ADDRESS_FAULT;
        memset(emulator->region_data + address, 0, 0x30u);
        dpmi_put_u32(emulator->region_data + address,
            DPMI_HEAP_LIMIT - emulator->dos_dpmi_heap_next);
        return XXEMUL_STATUS_OK;
    case 0x0501u:
        bytes = ((uint32_t)selector << 16u)
            | (uint16_t)emulator->x86.gpr[XXEMUL_X86_RCX];
        bytes = (bytes + 15u) & ~15u;
        if (bytes == 0u || bytes > DPMI_HEAP_LIMIT
                - emulator->dos_dpmi_heap_next)
            break;
        address = emulator->dos_dpmi_heap_next;
        emulator->dos_dpmi_heap_next += bytes;
        emulator->x86.gpr[XXEMUL_X86_RBX] = address >> 16u;
        emulator->x86.gpr[XXEMUL_X86_RCX] = address & 0xffffu;
        emulator->x86.gpr[XXEMUL_X86_RSI] = 0u;
        emulator->x86.gpr[XXEMUL_X86_RDI] = 1u;
        return XXEMUL_STATUS_OK;
    case 0x0100u:
        emulator->x86.gpr[XXEMUL_X86_RBX] = 0u;
        emulator->x86.gpr[XXEMUL_X86_RAX] = 0x0008u;
        emulator->x86.flags |= DPMI_CF;
        return XXEMUL_STATUS_OK;
    case 0x0300u:
        return dpmi_simulate_dos(emulator);
    default:
        break;
    }
    emulator->x86.gpr[XXEMUL_X86_RAX] = 0x8001u;
    emulator->x86.flags |= DPMI_CF;
    return XXEMUL_STATUS_OK;
}
