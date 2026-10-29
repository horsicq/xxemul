#include "xxemul_internal.h"
#include "xxemul_dos_files.h"

#include <string.h>

#define DPMI_GDT_BASE 0x100000u
#define DPMI_HEAP_BASE 0x200000u
#define DPMI_HEAP_LIMIT 0x1200000u
#define DPMI_CF UINT64_C(1)
#define DPMI_CALLBACK_FIRST 0x1000u
#define DPMI_CALLBACK_RETURN 0x0800u
#define DPMI_REAL_RETURN 0x0900u
#define DPMI_CALLBACK_STACK_BASE 0x102000u
#define DPMI_REAL_STACK_BASE 0xe0000u
#define DPMI_TRANSITION_SIMULATE 1u
#define DPMI_TRANSITION_CALLBACK 2u
#define DPMI_TRANSITION_REFLECT 3u
#define DPMI_REFLECTION_PACKET_BASE 0x112000u

static xxemul_status dpmi_begin_reflection(xxemul *emulator, uint8_t vector);

static uint16_t dpmi_u16(const uint8_t *bytes)
{
    return (uint16_t)(bytes[0] | ((uint16_t)bytes[1] << 8u));
}

static uint32_t dpmi_u32(const uint8_t *bytes)
{
    return (uint32_t)bytes[0] | ((uint32_t)bytes[1] << 8u) | ((uint32_t)bytes[2] << 16u) | ((uint32_t)bytes[3] << 24u);
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

static void dpmi_descriptor(xxemul *emulator, uint16_t selector, uint32_t base, uint32_t limit, uint8_t access, uint8_t flags)
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

static void dpmi_cache(xxemul *emulator, unsigned index, uint16_t selector, uint32_t base, uint32_t limit, uint8_t access, uint8_t flags)
{
    emulator->x86.segment[index] = selector;
    emulator->dos_segments[index].base = base;
    emulator->dos_segments[index].limit = limit;
    emulator->dos_segments[index].access = access;
    emulator->dos_segments[index].flags = flags;
    emulator->dos_segments[index].valid = 1u;
}

static int dpmi_callback_owns_selector(const xxemul *emulator, uint16_t selector)
{
    unsigned slot;
    for (slot = 0u; slot < XXEMUL_DPMI_CALLBACK_SLOTS; ++slot)
        if (emulator->dos_dpmi_callbacks[slot].procedure_selector && emulator->dos_dpmi_callbacks[slot].stack_alias == selector)
            return 1;
    return 0;
}

static uint16_t dpmi_find_descriptors(xxemul *emulator, uint16_t count)
{
    uint16_t first, i;

    if (count == 0u || count > (0x1000u - 0x28u) / 8u) return 0u;
    for (first = 0x28u; first <= 0x1000u - count * 8u; first += 8u) {
        for (i = 0u; i < count; ++i)
            if (emulator->region_data[DPMI_GDT_BASE + first + i * 8u + 5u] != 0u ||
                dpmi_callback_owns_selector(emulator, (uint16_t)(first + i * 8u))) break;
        if (i == count) return first;
    }
    return 0u;
}

static void dpmi_descriptors_used(xxemul *emulator, uint16_t first, uint16_t count)
{
    uint16_t after = (uint16_t)(first + count * 8u);
    if (after > emulator->dos_dpmi_next_selector) emulator->dos_dpmi_next_selector = after;
}

static uint8_t *dpmi_client_descriptor(xxemul *emulator, uint16_t selector)
{
    uint8_t *descriptor;
    if (selector < 8u || selector == XXEMUL_DPMI_HOST_SELECTOR || selector == XXEMUL_DPMI_STACK_SELECTOR ||
        selector >= emulator->dos_dpmi_next_selector || (selector & 7u) != 0u) return NULL;
    descriptor = emulator->region_data + DPMI_GDT_BASE + selector;
    return descriptor[5] ? descriptor : NULL;
}

static uint32_t dpmi_descriptor_base(const uint8_t *descriptor)
{
    return dpmi_u16(descriptor + 2u) | ((uint32_t)descriptor[4] << 16u) | ((uint32_t)descriptor[7] << 24u);
}

static uint32_t dpmi_descriptor_limit(const uint8_t *descriptor)
{
    uint32_t limit = dpmi_u16(descriptor) | ((uint32_t)(descriptor[6] & 15u) << 16u);
    return (descriptor[6] & 0x80u) ? (limit << 12u) | 0xfffu : limit;
}

static void dpmi_refresh_descriptor(xxemul *emulator, uint16_t selector, const uint8_t *descriptor)
{
    unsigned i;
    for (i = 0u; i < XXEMUL_X86_SEGMENT_COUNT; ++i)
        if (emulator->x86.segment[i] == selector)
            dpmi_cache(emulator, i, selector, dpmi_descriptor_base(descriptor),
                       dpmi_descriptor_limit(descriptor), descriptor[5], descriptor[6] >> 4u);
}

static void dpmi_initialize_vectors(xxemul *emulator)
{
    unsigned vector;
    dpmi_descriptor(emulator, XXEMUL_DPMI_HOST_SELECTOR, XXEMUL_DPMI_HOST_CODE_BASE, 0xfffu, 0x9bu, 0u);
    dpmi_descriptor(emulator, XXEMUL_DPMI_STACK_SELECTOR, DPMI_CALLBACK_STACK_BASE, 0xffffu, 0x93u,
                    emulator->dos_dpmi_client32 ? 4u : 0u);
    emulator->dos_idtr_base = XXEMUL_DPMI_IDT_BASE;
    emulator->dos_idtr_limit = 256u * 8u - 1u;
    for (vector = 0u; vector < 256u; ++vector) {
        uint16_t offset = (uint16_t)(XXEMUL_DPMI_HOST_VECTOR_BASE + vector * 4u);
        uint8_t *gate = emulator->region_data + XXEMUL_DPMI_IDT_BASE + vector * 8u;
        uint8_t *code = emulator->region_data + XXEMUL_DPMI_HOST_CODE_BASE + offset;
        memset(gate, 0, 8u);
        dpmi_put_u16(gate, offset);
        dpmi_put_u16(gate + 2u, XXEMUL_DPMI_HOST_SELECTOR);
        gate[5] = emulator->dos_dpmi_client32 ? 0x8eu : 0x86u;
        /* An old vector is a callable protected entry, including when a
         * handler chains with PUSHF[D]/CALL FAR rather than another INT. */
        memset(code, 0xcc, 4u);
        code[0] = emulator->dos_dpmi_client32 ? 0x66u : 0xcfu;
        if (emulator->dos_dpmi_client32) code[1] = 0xcfu;
    }
    memset(emulator->dos_dpmi_callbacks, 0, sizeof(emulator->dos_dpmi_callbacks));
    memset(emulator->dos_dpmi_transitions, 0, sizeof(emulator->dos_dpmi_transitions));
    emulator->dos_dpmi_transition_depth = 0u;
    emulator->dos_dpmi_resume_host = 0u;
}

static xxemul_status dpmi_protected_vector(xxemul *emulator, int setting)
{
    uint8_t vector = (uint8_t)emulator->x86.gpr[XXEMUL_X86_RBX];
    uint32_t at = (uint32_t)vector * 8u;
    uint8_t *gate, *descriptor;
    uint16_t selector;
    uint32_t offset;
    uint64_t address;
    if (at + 7u > emulator->dos_idtr_limit || emulator->dos_idtr_base > emulator->region_size ||
        emulator->region_size - emulator->dos_idtr_base < at + 8u) goto invalid;
    gate = emulator->region_data + emulator->dos_idtr_base + at;
    if (!setting) {
        if ((gate[5] & 0x9fu) != (emulator->dos_dpmi_client32 ? 0x8eu : 0x86u) || gate[4]) goto invalid;
        emulator->x86.gpr[XXEMUL_X86_RCX] = dpmi_u16(gate + 2u);
        offset = dpmi_u16(gate) | ((uint32_t)dpmi_u16(gate + 6u) << 16u);
        emulator->x86.gpr[XXEMUL_X86_RDX] = emulator->dos_dpmi_client32 ? offset : (uint16_t)offset;
        return XXEMUL_STATUS_OK;
    }
    selector = (uint16_t)emulator->x86.gpr[XXEMUL_X86_RCX];
    offset = emulator->dos_dpmi_client32 ? (uint32_t)emulator->x86.gpr[XXEMUL_X86_RDX]
                                        : (uint16_t)emulator->x86.gpr[XXEMUL_X86_RDX];
    descriptor = selector == XXEMUL_DPMI_HOST_SELECTOR ? emulator->region_data + DPMI_GDT_BASE + selector
                                                     : dpmi_client_descriptor(emulator, selector);
    if (!descriptor || (descriptor[5] & 0x98u) != 0x98u || (descriptor[6] & 0x20u) ||
        ((descriptor[5] >> 5u) & 3u) != (emulator->x86.segment[XXEMUL_X86_CS] & 3u) ||
        (selector & 3u) != (emulator->x86.segment[XXEMUL_X86_CS] & 3u) ||
        offset > dpmi_descriptor_limit(descriptor)) goto invalid;
    address = (uint64_t)dpmi_descriptor_base(descriptor) + offset;
    if (address >= emulator->region_size || address > UINT32_MAX) goto invalid;
    /* Validate first: failures leave the actual dispatch gate untouched. */
    dpmi_put_u16(gate, (uint16_t)offset);
    dpmi_put_u16(gate + 2u, selector);
    gate[4] = 0u;
    gate[5] = emulator->dos_dpmi_client32 ? 0x8eu : 0x86u;
    dpmi_put_u16(gate + 6u, emulator->dos_dpmi_client32 ? (uint16_t)(offset >> 16u) : 0u);
    return XXEMUL_STATUS_OK;
invalid:
    emulator->x86.gpr[XXEMUL_X86_RAX] = 0x8022u;
    emulator->x86.flags |= DPMI_CF;
    return XXEMUL_STATUS_OK;
}

xxemul_status xxemul_dpmi_reflect_interrupt(xxemul *emulator, uint8_t vector)
{
    if (emulator->dos_dpmi_resume_host == vector) {
        emulator->dos_dpmi_resume_host = 0u;
        return XXEMUL_STATUS_OK;
    }
    if (vector == 0x21u || vector == 0x10u || vector == 0x1au || vector == 0x33u) {
        uint16_t ip = dpmi_u16(emulator->region_data + vector * 4u), cs = dpmi_u16(emulator->region_data + vector * 4u + 2u);
        int original = vector == 0x21u ? cs == 0xf000u && ip == 0x100u :
                       vector == 0x10u ? cs == 0xf000u && ip == 0x110u : !cs && !ip;
        if (!original) return dpmi_begin_reflection(emulator, vector);
    }
    switch (vector) {
        case 0x10u:
        case 0x1au:
        case 0x33u: return xxemul_bios_interrupt(emulator, vector);
        case 0x21u: return xxemul_msdos_interrupt(emulator, vector);
        case 0x31u: return xxemul_dpmi_interrupt(emulator);
        default: return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    }
}

static uint8_t *dpmi_descriptor_buffer(xxemul *emulator, int writing, size_t size)
{
    const xxemul_x86_segment_cache *es = emulator->dos_segments + XXEMUL_X86_ES;
    uint32_t offset = emulator->dos_dpmi_client32 ? (uint32_t)emulator->x86.gpr[XXEMUL_X86_RDI]
                                                : (uint16_t)emulator->x86.gpr[XXEMUL_X86_RDI];
    uint64_t address = (uint64_t)es->base + offset;
    uint32_t upper = (es->flags & 4u) ? UINT32_MAX : 0xffffu;
    int expand_down = (es->access & 0x0cu) == 4u;
    if (!es->valid || (es->access & 0x90u) != 0x90u ||
        ((es->access & 8u) ? (!(es->access & 2u) || writing) : (writing && !(es->access & 2u))) ||
        (expand_down ? (offset <= es->limit || offset > upper || upper - offset < size - 1u)
                     : (offset > es->limit || es->limit - offset < size - 1u)) ||
        address > emulator->region_size || emulator->region_size - address < size) return NULL;
    return emulator->region_data + (size_t)address;
}

static uint8_t *dpmi_pointer(xxemul *emulator, uint16_t selector, uint32_t offset, size_t size, int code)
{
    uint8_t *d = selector == XXEMUL_DPMI_HOST_SELECTOR || selector == XXEMUL_DPMI_STACK_SELECTOR
                     ? emulator->region_data + DPMI_GDT_BASE + selector : dpmi_client_descriptor(emulator, selector);
    uint32_t limit, upper;
    uint64_t address;
    if (!d || !size || (d[5] & 0x90u) != 0x90u || (d[6] & 0x20u) ||
        ((d[5] >> 5u) & 3u) != 0u || (selector & 3u)) return NULL;
    if (code ? !(d[5] & 8u) : ((d[5] & 0x0au) != 2u)) return NULL;
    limit = dpmi_descriptor_limit(d); upper = (d[6] & 0x40u) ? UINT32_MAX : UINT16_MAX;
    if (!code && (d[5] & 4u)) {
        if (offset <= limit || offset > upper || size - 1u > upper - offset) return NULL;
    } else if (offset > limit || size - 1u > limit - offset) return NULL;
    address = (uint64_t)dpmi_descriptor_base(d) + offset;
    if (address > emulator->region_size || size > emulator->region_size - address) return NULL;
    return emulator->region_data + (size_t)address;
}

static void dpmi_load_selector(xxemul *emulator, unsigned index, uint16_t selector)
{
    const uint8_t *d = emulator->region_data + DPMI_GDT_BASE + selector;
    dpmi_cache(emulator, index, selector, dpmi_descriptor_base(d), dpmi_descriptor_limit(d), d[5], d[6] >> 4u);
}

static void dpmi_packet_save(const xxemul *emulator, uint8_t *p)
{
    static const unsigned registers[8] = {XXEMUL_X86_RDI, XXEMUL_X86_RSI, XXEMUL_X86_RBP, XXEMUL_X86_RSP,
                                          XXEMUL_X86_RBX, XXEMUL_X86_RDX, XXEMUL_X86_RCX, XXEMUL_X86_RAX};
    unsigned i;
    memset(p, 0, 0x32u);
    for (i = 0u; i < 8u; ++i) if (i != 3u) dpmi_put_u32(p + i * 4u, (uint32_t)emulator->x86.gpr[registers[i]]);
    dpmi_put_u16(p + 0x20u, (uint16_t)emulator->x86.flags);
    dpmi_put_u16(p + 0x22u, emulator->x86.segment[XXEMUL_X86_ES]);
    dpmi_put_u16(p + 0x24u, emulator->x86.segment[XXEMUL_X86_DS]);
    dpmi_put_u16(p + 0x26u, emulator->x86.segment[XXEMUL_X86_FS]);
    dpmi_put_u16(p + 0x28u, emulator->x86.segment[XXEMUL_X86_GS]);
    dpmi_put_u16(p + 0x2au, (uint16_t)emulator->x86.ip);
    dpmi_put_u16(p + 0x2cu, emulator->x86.segment[XXEMUL_X86_CS]);
    dpmi_put_u16(p + 0x2eu, (uint16_t)emulator->x86.gpr[XXEMUL_X86_RSP]);
    dpmi_put_u16(p + 0x30u, emulator->x86.segment[XXEMUL_X86_SS]);
}

static void dpmi_packet_load(xxemul *emulator, const uint8_t *p)
{
    static const unsigned registers[8] = {XXEMUL_X86_RDI, XXEMUL_X86_RSI, XXEMUL_X86_RBP, XXEMUL_X86_RSP,
                                          XXEMUL_X86_RBX, XXEMUL_X86_RDX, XXEMUL_X86_RCX, XXEMUL_X86_RAX};
    static const unsigned segments[6] = {XXEMUL_X86_ES, XXEMUL_X86_DS, XXEMUL_X86_FS, XXEMUL_X86_GS, XXEMUL_X86_CS, XXEMUL_X86_SS};
    unsigned i;
    for (i = 0u; i < 8u; ++i) if (i != 3u) emulator->x86.gpr[registers[i]] = dpmi_u32(p + i * 4u);
    for (i = 0u; i < 6u; ++i) {
        uint16_t segment = dpmi_u16(p + (i < 4u ? 0x22u + i * 2u : i == 4u ? 0x2cu : 0x30u));
        dpmi_cache(emulator, segments[i], segment, (uint32_t)segment << 4u, 0xffffu,
                    segments[i] == XXEMUL_X86_CS ? 0x9bu : 0x93u, 0u);
    }
    emulator->x86.flags = dpmi_u16(p + 0x20u) | 2u;
    emulator->x86.ip = dpmi_u16(p + 0x2au);
    emulator->x86.gpr[XXEMUL_X86_RSP] = dpmi_u16(p + 0x2eu);
    emulator->mode = XXEMUL_MODE_X86_16;
    emulator->dos_cr0 &= ~UINT32_C(1);
}

static void dpmi_real_write(xxemul *emulator, uint16_t segment, uint16_t offset, const uint8_t *p, size_t size)
{
    size_t i;
    for (i = 0u; i < size; ++i)
        emulator->region_data[xxemul_dos_physical(emulator, segment, (uint16_t)(offset + i))] = p[i];
}

static xxemul_status dpmi_callback_allocate(xxemul *emulator)
{
    uint16_t procedure = emulator->x86.segment[XXEMUL_X86_DS], packet = emulator->x86.segment[XXEMUL_X86_ES], alias;
    uint32_t offset = emulator->dos_dpmi_client32 ? (uint32_t)emulator->x86.gpr[XXEMUL_X86_RSI] : (uint16_t)emulator->x86.gpr[XXEMUL_X86_RSI];
    uint32_t packet_offset = emulator->dos_dpmi_client32 ? (uint32_t)emulator->x86.gpr[XXEMUL_X86_RDI] : (uint16_t)emulator->x86.gpr[XXEMUL_X86_RDI];
    unsigned slot;
    for (slot = 0u; slot < XXEMUL_DPMI_CALLBACK_SLOTS; ++slot) if (!emulator->dos_dpmi_callbacks[slot].procedure_selector) break;
    alias = dpmi_find_descriptors(emulator, 1u);
    if (slot == XXEMUL_DPMI_CALLBACK_SLOTS || !alias || !dpmi_pointer(emulator, procedure, offset, 1u, 1) ||
        !dpmi_pointer(emulator, packet, packet_offset, 0x32u, 0)) {
        emulator->x86.gpr[XXEMUL_X86_RAX] = 0x8015u; emulator->x86.flags |= DPMI_CF; return XXEMUL_STATUS_OK;
    }
    dpmi_descriptor(emulator, alias, 0u, 0xffffu, 0x93u, 0u);
    dpmi_descriptors_used(emulator, alias, 1u);
    emulator->dos_dpmi_callbacks[slot].procedure_selector = procedure;
    emulator->dos_dpmi_callbacks[slot].procedure_offset = offset;
    emulator->dos_dpmi_callbacks[slot].packet_selector = packet;
    emulator->dos_dpmi_callbacks[slot].packet_offset = packet_offset;
    emulator->dos_dpmi_callbacks[slot].stack_alias = alias;
    emulator->x86.gpr[XXEMUL_X86_RCX] = 0xf000u;
    emulator->x86.gpr[XXEMUL_X86_RDX] = DPMI_CALLBACK_FIRST + slot * 16u;
    return XXEMUL_STATUS_OK;
}

static xxemul_status dpmi_callback_free(xxemul *emulator)
{
    uint16_t segment = (uint16_t)emulator->x86.gpr[XXEMUL_X86_RCX], offset = (uint16_t)emulator->x86.gpr[XXEMUL_X86_RDX];
    unsigned slot = (offset - DPMI_CALLBACK_FIRST) / 16u;
    if (segment == 0xf000u && offset >= DPMI_CALLBACK_FIRST && (offset - DPMI_CALLBACK_FIRST) % 16u == 0u &&
        slot < XXEMUL_DPMI_CALLBACK_SLOTS && emulator->dos_dpmi_callbacks[slot].procedure_selector && !emulator->dos_dpmi_callbacks[slot].active) {
        uint16_t alias = emulator->dos_dpmi_callbacks[slot].stack_alias;
        memset(emulator->region_data + DPMI_GDT_BASE + alias, 0, 8u);
        memset(emulator->dos_dpmi_callbacks + slot, 0, sizeof(emulator->dos_dpmi_callbacks[slot]));
        return XXEMUL_STATUS_OK;
    }
    emulator->x86.gpr[XXEMUL_X86_RAX] = 0x8024u; emulator->x86.flags |= DPMI_CF; return XXEMUL_STATUS_OK;
}

static xxemul_status dpmi_allocate_dos(xxemul *emulator)
{
    xxemul_x86_state saved = emulator->x86;
    uint16_t paragraphs = (uint16_t)saved.gpr[XXEMUL_X86_RBX];
    uint16_t count = emulator->dos_dpmi_client32 ? 1u : (uint16_t)((paragraphs + 0xfffu) / 0x1000u);
    uint16_t selector = dpmi_find_descriptors(emulator, count ? count : 1u);
    uint16_t segment, largest, error;
    unsigned i;
    xxemul_status status;

    if (selector == 0u) {
        emulator->x86.gpr[XXEMUL_X86_RAX] = 0x8011u;
        emulator->x86.gpr[XXEMUL_X86_RBX] = 0u;
        emulator->x86.flags |= DPMI_CF;
        return XXEMUL_STATUS_OK;
    }
    emulator->x86.gpr[XXEMUL_X86_RAX] = 0x4800u;
    status = xxemul_msdos_interrupt(emulator, 0x21u);
    segment = (uint16_t)emulator->x86.gpr[XXEMUL_X86_RAX];
    largest = (uint16_t)emulator->x86.gpr[XXEMUL_X86_RBX];
    error = (emulator->x86.flags & DPMI_CF) ? segment : 0u;
    emulator->x86 = saved;
    if (status != XXEMUL_STATUS_OK) return status;
    if (error != 0u) {
        emulator->x86.gpr[XXEMUL_X86_RAX] = error;
        emulator->x86.gpr[XXEMUL_X86_RBX] = largest;
        emulator->x86.flags |= DPMI_CF;
        return XXEMUL_STATUS_OK;
    }
    for (i = 0u; i < count; ++i) {
        uint32_t remaining = (uint32_t)paragraphs * 16u - i * 0x10000u;
        uint32_t limit = (i == 0u || remaining < 0x10000u) ? remaining - 1u : 0xffffu;
        dpmi_descriptor(emulator, (uint16_t)(selector + i * 8u),
                        ((uint32_t)segment << 4u) + i * 0x10000u, limit, 0x93u,
                        emulator->dos_dpmi_client32 ? 4u : 0u);
    }
    dpmi_descriptors_used(emulator, selector, count);
    emulator->dos_dpmi_dos_segment[selector / 8u] = segment;
    emulator->dos_dpmi_dos_descriptors[selector / 8u] = (uint8_t)count;
    emulator->x86.gpr[XXEMUL_X86_RAX] = segment;
    emulator->x86.gpr[XXEMUL_X86_RDX] = selector;
    emulator->x86.flags &= ~DPMI_CF;
    return XXEMUL_STATUS_OK;
}

static xxemul_status dpmi_free_dos(xxemul *emulator)
{
    xxemul_x86_state saved = emulator->x86;
    uint16_t selector = (uint16_t)saved.gpr[XXEMUL_X86_RDX];
    uint16_t segment, count, error;
    unsigned i;
    xxemul_status status;

    if ((selector & 7u) != 0u || selector >= 0x1000u ||
        (segment = emulator->dos_dpmi_dos_segment[selector / 8u]) == 0u) {
        emulator->x86.gpr[XXEMUL_X86_RAX] = 0x8022u;
        emulator->x86.flags |= DPMI_CF;
        return XXEMUL_STATUS_OK;
    }
    count = emulator->dos_dpmi_dos_descriptors[selector / 8u];
    emulator->x86.gpr[XXEMUL_X86_RAX] = 0x4900u;
    emulator->x86.segment[XXEMUL_X86_ES] = segment;
    status = xxemul_msdos_interrupt(emulator, 0x21u);
    error = (emulator->x86.flags & DPMI_CF) ? (uint16_t)emulator->x86.gpr[XXEMUL_X86_RAX] : 0u;
    emulator->x86 = saved;
    if (status != XXEMUL_STATUS_OK) return status;
    if (error != 0u) {
        emulator->x86.gpr[XXEMUL_X86_RAX] = error;
        emulator->x86.flags |= DPMI_CF;
        return XXEMUL_STATUS_OK;
    }
    memset(emulator->region_data + DPMI_GDT_BASE + selector, 0, count * 8u);
    emulator->dos_dpmi_dos_segment[selector / 8u] = 0u;
    emulator->dos_dpmi_dos_descriptors[selector / 8u] = 0u;
    for (i = 0u; i < XXEMUL_X86_SEGMENT_COUNT; ++i) {
        uint16_t current = emulator->x86.segment[i];
        if (current >= selector && current < selector + count * 8u) {
            emulator->x86.segment[i] = 0u;
            emulator->dos_segments[i].valid = 0u;
        }
    }
    emulator->x86.flags &= ~DPMI_CF;
    return XXEMUL_STATUS_OK;
}

static uint32_t dpmi_find_memory(xxemul *emulator, uint32_t size, const xxemul_dpmi_memory_block *ignore)
{
    uint32_t base = DPMI_HEAP_BASE, next;
    unsigned i;
    if (size > DPMI_HEAP_LIMIT - DPMI_HEAP_BASE) return 0u;
    while (base <= DPMI_HEAP_LIMIT - size) {
        next = base;
        for (i = 0u; i < 128u; ++i) {
            const xxemul_dpmi_memory_block *block = emulator->dos_dpmi_memory + i;
            if (block != ignore && block->handle && base < block->base + block->size && block->base < base + size &&
                block->base + block->size > next) next = block->base + block->size;
        }
        if (next == base) return base;
        base = next;
    }
    return 0u;
}

static uint32_t dpmi_largest_free_memory(xxemul *emulator)
{
    uint32_t at = DPMI_HEAP_BASE, largest = 0u;
    unsigned i, active = 0u;
    for (i = 0u; i < 128u; ++i) if (emulator->dos_dpmi_memory[i].handle) ++active;
    if (active == 128u) return 0u; /* no handle remains for another allocation */
    while (at < DPMI_HEAP_LIMIT) {
        uint32_t next = DPMI_HEAP_LIMIT, after = DPMI_HEAP_LIMIT;
        for (i = 0u; i < 128u; ++i) {
            const xxemul_dpmi_memory_block *block = emulator->dos_dpmi_memory + i;
            if (block->handle && block->base >= at && block->base < next) {
                next = block->base;
                after = block->base + block->size;
            }
        }
        if (next - at > largest) largest = next - at;
        at = after;
    }
    return largest;
}

static uint32_t dpmi_new_memory_handle(xxemul *emulator)
{
    uint32_t handle;
    unsigned i;
    for (;;) {
        handle = emulator->dos_dpmi_next_memory_handle++;
        if (!handle) continue;
        for (i = 0u; i < 128u; ++i) if (emulator->dos_dpmi_memory[i].handle == handle) break;
        if (i == 128u) return handle;
    }
}

static void dpmi_update_heap_end(xxemul *emulator)
{
    unsigned i;
    emulator->dos_dpmi_heap_next = DPMI_HEAP_BASE;
    for (i = 0u; i < 128u; ++i) {
        const xxemul_dpmi_memory_block *block = emulator->dos_dpmi_memory + i;
        if (block->handle && block->base + block->size > emulator->dos_dpmi_heap_next)
            emulator->dos_dpmi_heap_next = block->base + block->size;
    }
}

static xxemul_status dpmi_memory(xxemul *emulator, uint16_t function)
{
    uint32_t handle = ((uint32_t)(uint16_t)emulator->x86.gpr[XXEMUL_X86_RSI] << 16u) |
                      (uint16_t)emulator->x86.gpr[XXEMUL_X86_RDI];
    uint32_t size = ((uint32_t)(uint16_t)emulator->x86.gpr[XXEMUL_X86_RBX] << 16u) |
                    (uint16_t)emulator->x86.gpr[XXEMUL_X86_RCX];
    xxemul_dpmi_memory_block *block = NULL;
    uint32_t base, error = 0u;
    unsigned i;

    if (function != 0x0501u) {
        for (i = 0u; i < 128u; ++i)
            if (handle && emulator->dos_dpmi_memory[i].handle == handle) { block = emulator->dos_dpmi_memory + i; break; }
        if (block == NULL) { error = 0x8023u; goto failed; }
        if (function == 0x0502u) {
            memset(block, 0, sizeof(*block));
            dpmi_update_heap_end(emulator);
            return XXEMUL_STATUS_OK;
        }
    }
    if (size == 0u) { error = 0x8021u; goto failed; }
    if (size > DPMI_HEAP_LIMIT - DPMI_HEAP_BASE) { error = 0x8012u; goto failed; }
    size = (size + 15u) & ~15u;
    if (function == 0x0501u) {
        for (i = 0u; i < 128u; ++i)
            if (!emulator->dos_dpmi_memory[i].handle) { block = emulator->dos_dpmi_memory + i; break; }
        if (block == NULL) { error = 0x8016u; goto failed; }
    }
    /* Preserve the old address for a shrink or an unfragmented in-place grow. */
    base = 0u;
    if (block->handle && block->base <= DPMI_HEAP_LIMIT - size) {
        base = block->base;
        for (i = 0u; i < 128u; ++i) {
            const xxemul_dpmi_memory_block *other = emulator->dos_dpmi_memory + i;
            if (other != block && other->handle && base < other->base + other->size && other->base < base + size) {
                base = 0u; break;
            }
        }
    }
    if (!base) base = dpmi_find_memory(emulator, size, block);
    if (!base) { error = 0x8012u; goto failed; }
    if (block->handle) {
        uint32_t preserved = block->size < size ? block->size : size;
        memmove(emulator->region_data + base, emulator->region_data + block->base, preserved);
        if (size > preserved) memset(emulator->region_data + base + preserved, 0, size - preserved);
    } else memset(emulator->region_data + base, 0, size);
    block->base = base;
    block->size = size;
    block->handle = dpmi_new_memory_handle(emulator);
    dpmi_update_heap_end(emulator);
    emulator->x86.gpr[XXEMUL_X86_RBX] = base >> 16u;
    emulator->x86.gpr[XXEMUL_X86_RCX] = base & 0xffffu;
    emulator->x86.gpr[XXEMUL_X86_RSI] = block->handle >> 16u;
    emulator->x86.gpr[XXEMUL_X86_RDI] = block->handle & 0xffffu;
    return XXEMUL_STATUS_OK;
failed:
    emulator->x86.gpr[XXEMUL_X86_RAX] = error;
    emulator->x86.flags |= DPMI_CF;
    return XXEMUL_STATUS_OK;
}

static xxemul_status dpmi_resident_region(xxemul *emulator)
{
    uint32_t address = ((uint32_t)(uint16_t)emulator->x86.gpr[XXEMUL_X86_RBX] << 16u) |
                       (uint16_t)emulator->x86.gpr[XXEMUL_X86_RCX];
    uint32_t size = ((uint32_t)(uint16_t)emulator->x86.gpr[XXEMUL_X86_RSI] << 16u) |
                    (uint16_t)emulator->x86.gpr[XXEMUL_X86_RDI];
    uint64_t end = (uint64_t)address + size, at = address;
    unsigned i;

    if (end > emulator->region_size) goto invalid;
    while (at < end) {
        uint64_t after = at;
        /* Conventional DOS/BIOS memory is permanently resident. The high
           arena is client-mapped only where a live linear block covers it. */
        if (at < 0x100000u) after = 0x100000u;
        else for (i = 0u; i < 128u; ++i) {
            const xxemul_dpmi_memory_block *block = emulator->dos_dpmi_memory + i;
            if (block->handle && at >= block->base && at < (uint64_t)block->base + block->size) {
                after = (uint64_t)block->base + block->size;
                break;
            }
        }
        if (after == at) goto invalid;
        at = after;
    }
    /* DPMI 0.9 explicitly permits ignoring lock/unlock on a host without
       virtual memory. Every valid byte here already has resident backing. */
    return XXEMUL_STATUS_OK;
invalid:
    emulator->x86.gpr[XXEMUL_X86_RAX] = 0x8025u;
    emulator->x86.flags |= DPMI_CF;
    return XXEMUL_STATUS_OK;
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
    if ((mcb[0] != 'M' && mcb[0] != 'Z') || dpmi_u16(mcb + 1u) != emulator->psp_segment) return 0;
    end = mcb_segment + 1u + dpmi_u16(mcb + 3u);
    if (end > 0xa000u) return 0;
    if (mcb[0] == 'M') {
        uint32_t segment = end;

        /* A normal DOS program shrinks its PSP block before probing DPMI.
           In that case the following MCB chain already contains memory for
           the one-paragraph host-private block advertised by INT 2F/1687. */
        while (segment < 0xa000u) {
            uint8_t *candidate = emulator->region_data + (segment << 4u);
            uint16_t size = dpmi_u16(candidate + 3u);
            uint32_t next = segment + 1u + size;

            if ((candidate[0] != 'M' && candidate[0] != 'Z') || next > 0xa000u || next <= segment) return 0;
            if (dpmi_u16(candidate + 1u) == 0u && size >= 1u) {
                emulator->dos_dpmi_prepared = 1u;
                return 1;
            }
            if (candidate[0] == 'Z') return 0;
            segment = next;
        }
        return 0;
    }
    if (end - emulator->psp_segment < 0x120u) return 0;
    free_segment = end - 0x11u;
    free_mcb = emulator->region_data + (free_segment << 4u);
    free_mcb[0] = 'Z';
    dpmi_put_u16(free_mcb + 1u, 0u);
    dpmi_put_u16(free_mcb + 3u, 0x10u);
    mcb[0] = 'M';
    dpmi_put_u16(mcb + 3u, (uint16_t)(free_segment - mcb_segment - 1u));
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
    uint16_t environment;
    uint8_t *psp;

    if (xxemul_dos_files_child_active(emulator)) return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    if (emulator->region_size < DPMI_HEAP_LIMIT || frame > emulator->region_size || emulator->region_size - frame < 4u) return XXEMUL_STATUS_ADDRESS_FAULT;
    return_ip = dpmi_u16(emulator->region_data + frame);
    return_segment = dpmi_u16(emulator->region_data + frame + 2u);
    data_segment = emulator->x86.segment[XXEMUL_X86_DS];
    psp = emulator->region_data + ((uint32_t)emulator->psp_segment << 4u);
    environment = dpmi_u16(psp + 0x2cu);
    emulator->dos_dpmi_client32 = (uint8_t)(emulator->x86.gpr[XXEMUL_X86_RAX] & 1u);
    emulator->dos_gdtr_base = DPMI_GDT_BASE;
    emulator->dos_gdtr_limit = 0xfffu;
    emulator->dos_dpmi_next_selector = 0x28u;
    emulator->dos_dpmi_heap_next = DPMI_HEAP_BASE;
    emulator->dos_dpmi_next_memory_handle = 1u;
    memset(emulator->dos_dpmi_memory, 0, sizeof(emulator->dos_dpmi_memory));
    dpmi_initialize_vectors(emulator);

    dpmi_descriptor(emulator, 0x08u, (uint32_t)return_segment << 4u, 0xffffu, 0x9bu, 0u);
    dpmi_descriptor(emulator, 0x10u, (uint32_t)stack_segment << 4u, 0xffffu, 0x93u, emulator->dos_dpmi_client32 ? 4u : 0u);
    dpmi_descriptor(emulator, 0x18u, (uint32_t)data_segment << 4u, 0xffffu, 0x93u, emulator->dos_dpmi_client32 ? 4u : 0u);
    dpmi_descriptor(emulator, 0x20u, (uint32_t)emulator->psp_segment << 4u, 0xffu, 0x93u, 0u);
    if (environment) {
        /* PSP:2C is a selector after the initial DPMI mode switch. */
        dpmi_descriptor(emulator, 0x28u, (uint32_t)environment << 4u, 0xffffu, 0x93u,
                        emulator->dos_dpmi_client32 ? 4u : 0u);
        dpmi_put_u16(psp + 0x2cu, 0x28u);
        emulator->dos_dpmi_next_selector = 0x30u;
    }
    /* The DPMI host owns the transition to extended-memory addressing. */
    emulator->dos_port_92 |= 2u;
    emulator->dos_kbc_output |= 2u;
    emulator->dos_cr0 |= 1u;
    dpmi_cache(emulator, XXEMUL_X86_CS, 0x08u, (uint32_t)return_segment << 4u, 0xffffu, 0x9bu, 0u);
    dpmi_cache(emulator, XXEMUL_X86_SS, 0x10u, (uint32_t)stack_segment << 4u, 0xffffu, 0x93u, emulator->dos_dpmi_client32 ? 4u : 0u);
    dpmi_cache(emulator, XXEMUL_X86_DS, 0x18u, (uint32_t)data_segment << 4u, 0xffffu, 0x93u, emulator->dos_dpmi_client32 ? 4u : 0u);
    dpmi_cache(emulator, XXEMUL_X86_ES, 0x20u, (uint32_t)emulator->psp_segment << 4u, 0xffu, 0x93u, 0u);
    emulator->x86.segment[XXEMUL_X86_FS] = 0u;
    emulator->x86.segment[XXEMUL_X86_GS] = 0u;
    memset(emulator->dos_segments + XXEMUL_X86_FS, 0, sizeof(emulator->dos_segments[XXEMUL_X86_FS]));
    memset(emulator->dos_segments + XXEMUL_X86_GS, 0, sizeof(emulator->dos_segments[XXEMUL_X86_GS]));
    emulator->x86.gpr[XXEMUL_X86_RSP] = (uint16_t)(stack_offset + 4u);
    emulator->x86.ip = return_ip;
    emulator->x86.flags &= ~DPMI_CF;
    return XXEMUL_STATUS_OK;
}

static xxemul_status dpmi_begin_real_interrupt(xxemul *emulator, uint8_t vector, uint8_t *packet, uint8_t kind)
{
    uint16_t words = kind == DPMI_TRANSITION_SIMULATE ? (uint16_t)emulator->x86.gpr[XXEMUL_X86_RCX] : 0u;
    uint16_t real_ss = dpmi_u16(packet + 0x30u), real_sp = dpmi_u16(packet + 0x2eu);
    uint16_t ip = dpmi_u16(emulator->region_data + vector * 4u), cs = dpmi_u16(emulator->region_data + vector * 4u + 2u);
    xxemul_dpmi_transition *t;
    uint8_t parameters[256], frame[6];
    uint32_t protected_sp, protected_mask;
    const xxemul_x86_segment_cache *ss = emulator->dos_segments + XXEMUL_X86_SS;
    int resume_host = emulator->x86.segment[XXEMUL_X86_CS] == XXEMUL_DPMI_HOST_SELECTOR &&
                      emulator->x86.ip == XXEMUL_DPMI_HOST_VECTOR_BASE + (kind == DPMI_TRANSITION_SIMULATE ? 0x31u : (uint32_t)vector) * 4u;
    if (!cs && !ip) return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    if ((emulator->dos_cr0 & UINT32_C(0x80000000)) || emulator->dos_dpmi_transition_depth >= XXEMUL_DPMI_TRANSITIONS) {
        emulator->x86.gpr[XXEMUL_X86_RAX] = 0x8012u; emulator->x86.flags |= DPMI_CF; return XXEMUL_STATUS_OK;
    }
    if (words > 128u || (kind == DPMI_TRANSITION_SIMULATE && (emulator->x86.gpr[XXEMUL_X86_RBX] & 0xff00u))) {
        emulator->x86.gpr[XXEMUL_X86_RAX] = 0x8021u; emulator->x86.flags |= DPMI_CF; return XXEMUL_STATUS_OK;
    }
    protected_mask = (ss->flags & 4u) ? UINT32_MAX : UINT16_MAX;
    protected_sp = ((uint32_t)emulator->x86.gpr[XXEMUL_X86_RSP] + (resume_host ? (emulator->dos_dpmi_client32 ? 12u : 6u) : 0u)) & protected_mask;
    if (words) {
        uint64_t address = (uint64_t)ss->base + protected_sp;
        if (!ss->valid || (ss->access & 0x92u) != 0x92u || protected_sp > ss->limit || words * 2u - 1u > ss->limit - protected_sp ||
            address > emulator->region_size || words * 2u > emulator->region_size - address) return XXEMUL_STATUS_ADDRESS_FAULT;
        memcpy(parameters, emulator->region_data + (size_t)address, words * 2u);
    }
    t = emulator->dos_dpmi_transitions + emulator->dos_dpmi_transition_depth;
    memset(t, 0, sizeof(*t));
    t->kind = kind; t->resume_host = (uint8_t)resume_host; t->vector = kind == DPMI_TRANSITION_SIMULATE ? 0x31u : vector;
    t->state = emulator->x86; t->state.ip = resume_host ? emulator->x86.ip : emulator->dos_call_next_ip;
    memcpy(t->segments, emulator->dos_segments, sizeof(t->segments)); t->mode = emulator->mode; t->cr0 = emulator->dos_cr0;
    t->packet_selector = kind == DPMI_TRANSITION_REFLECT ? 0u : emulator->x86.segment[XXEMUL_X86_ES];
    t->packet_offset = kind == DPMI_TRANSITION_REFLECT ? (uint32_t)(packet - emulator->region_data) :
                       emulator->dos_dpmi_client32 ? (uint32_t)emulator->x86.gpr[XXEMUL_X86_RDI] : (uint16_t)emulator->x86.gpr[XXEMUL_X86_RDI];
    if (!real_ss && !real_sp) { real_ss = (uint16_t)((DPMI_REAL_STACK_BASE + emulator->dos_dpmi_transition_depth * 0x1000u) >> 4u); real_sp = 0x1000u; }
    real_sp = (uint16_t)(real_sp - words * 2u); t->real_ss = real_ss; t->real_sp = real_sp;
    if (words) dpmi_real_write(emulator, real_ss, real_sp, parameters, words * 2u);
    dpmi_put_u16(frame, DPMI_REAL_RETURN); dpmi_put_u16(frame + 2u, 0xf000u); dpmi_put_u16(frame + 4u, dpmi_u16(packet + 0x20u) | 2u);
    dpmi_packet_load(emulator, packet);
    real_sp = (uint16_t)(real_sp - 6u); dpmi_real_write(emulator, real_ss, real_sp, frame, sizeof(frame));
    dpmi_cache(emulator, XXEMUL_X86_SS, real_ss, (uint32_t)real_ss << 4u, 0xffffu, 0x93u, 0u);
    dpmi_cache(emulator, XXEMUL_X86_CS, cs, (uint32_t)cs << 4u, 0xffffu, 0x9bu, 0u);
    emulator->x86.gpr[XXEMUL_X86_RSP] = real_sp; emulator->x86.ip = ip; emulator->x86.flags &= ~UINT64_C(0x300);
    ++emulator->dos_dpmi_transition_depth; emulator->dos_context_transfer = 1u;
    return XXEMUL_STATUS_OK;
}

static xxemul_status dpmi_begin_reflection(xxemul *emulator, uint8_t vector)
{
    static const unsigned segments[4] = {XXEMUL_X86_ES, XXEMUL_X86_DS, XXEMUL_X86_FS, XXEMUL_X86_GS};
    uint8_t packet[0x32u], *destination;
    unsigned i;
    if (emulator->dos_dpmi_transition_depth >= XXEMUL_DPMI_TRANSITIONS) return XXEMUL_STATUS_LIMIT_REACHED;
    dpmi_packet_save(emulator, packet);
    for (i = 0u; i < 4u; ++i) {
        const xxemul_x86_segment_cache *cache = emulator->dos_segments + segments[i];
        uint32_t base = emulator->x86.segment[segments[i]] ? cache->base : 0u;
        if ((base & 15u) || base > 0xffff0u || (emulator->x86.segment[segments[i]] && !cache->valid))
            return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
        dpmi_put_u16(packet + 0x22u + i * 2u, (uint16_t)(base >> 4u));
    }
    dpmi_put_u16(packet + 0x2eu, 0u); dpmi_put_u16(packet + 0x30u, 0u);
    destination = emulator->region_data + DPMI_REFLECTION_PACKET_BASE + emulator->dos_dpmi_transition_depth * 0x40u;
    memcpy(destination, packet, sizeof(packet));
    return dpmi_begin_real_interrupt(emulator, vector, destination, DPMI_TRANSITION_REFLECT);
}

static xxemul_status dpmi_finish_reflection(xxemul *emulator, const xxemul_dpmi_transition *t)
{
    static const unsigned segments[4] = {XXEMUL_X86_ES, XXEMUL_X86_DS, XXEMUL_X86_FS, XXEMUL_X86_GS};
    xxemul_x86_state result = emulator->x86;
    uint16_t selectors[4], allocated[4], old_next = emulator->dos_dpmi_next_selector;
    unsigned i, count = 0u;
    for (i = 0u; i < 4u; ++i) {
        uint16_t real = result.segment[segments[i]], selector;
        uint32_t base = (uint32_t)real << 4u;
        if ((!t->state.segment[segments[i]] && !real) ||
            (t->state.segment[segments[i]] && t->segments[segments[i]].valid && t->segments[segments[i]].base == base)) {
            selectors[i] = t->state.segment[segments[i]]; continue;
        }
        if (!real) { selectors[i] = 0u; continue; }
        for (selector = 8u; selector < emulator->dos_dpmi_next_selector; selector += 8u) {
            const uint8_t *d = emulator->region_data + DPMI_GDT_BASE + selector;
            if (!dpmi_callback_owns_selector(emulator, selector) && (d[5] & 0xfeu) == 0x92u &&
                dpmi_descriptor_base(d) == base && dpmi_descriptor_limit(d) >= 0xffffu) break;
        }
        if (selector == emulator->dos_dpmi_next_selector) {
            selector = dpmi_find_descriptors(emulator, 1u);
            if (!selector) {
                while (count) memset(emulator->region_data + DPMI_GDT_BASE + allocated[--count], 0, 8u);
                emulator->dos_dpmi_next_selector = old_next; return XXEMUL_STATUS_OUT_OF_MEMORY;
            }
            dpmi_descriptor(emulator, selector, base, 0xffffu, 0x93u, emulator->dos_dpmi_client32 ? 4u : 0u);
            dpmi_descriptors_used(emulator, selector, 1u); allocated[count++] = selector;
        }
        selectors[i] = selector;
    }
    emulator->x86 = t->state; memcpy(emulator->dos_segments, t->segments, sizeof(t->segments));
    emulator->mode = t->mode; emulator->dos_cr0 = t->cr0;
    for (i = 0u; i < 8u; ++i) if (i != XXEMUL_X86_RSP) emulator->x86.gpr[i] = (uint32_t)result.gpr[i];
    emulator->x86.flags = (t->state.flags & ~UINT64_C(0xffff)) | (result.flags & 0xffffu) | 2u;
    for (i = 0u; i < 4u; ++i) {
        if (selectors[i]) dpmi_load_selector(emulator, segments[i], selectors[i]);
        else { emulator->x86.segment[segments[i]] = 0u; memset(emulator->dos_segments + segments[i], 0, sizeof(emulator->dos_segments[0])); }
    }
    return XXEMUL_STATUS_OK;
}

static xxemul_status dpmi_callback_enter(xxemul *emulator, unsigned slot)
{
    xxemul_dpmi_callback *c = emulator->dos_dpmi_callbacks + slot;
    xxemul_dpmi_transition *t;
    uint8_t *packet, *stack;
    uint32_t frame_sp, width = emulator->dos_dpmi_client32 ? 4u : 2u;
    uint16_t real_ss = emulator->x86.segment[XXEMUL_X86_SS], real_sp = (uint16_t)emulator->x86.gpr[XXEMUL_X86_RSP];
    if (!c->procedure_selector) return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    if (emulator->dos_dpmi_transition_depth >= XXEMUL_DPMI_TRANSITIONS) return XXEMUL_STATUS_LIMIT_REACHED;
    /* A wrap across the A20 boundary cannot be represented by one linear
     * real-stack alias. Reject that unusual stack before touching the client. */
    if (!(emulator->dos_port_92 & 2u) && ((uint32_t)real_ss << 4u) + 0xffffu > 0xfffffu)
        return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    packet = dpmi_pointer(emulator, c->packet_selector, c->packet_offset, 0x32u, 0);
    if (!packet || !dpmi_pointer(emulator, c->procedure_selector, c->procedure_offset, 1u, 1)) return XXEMUL_STATUS_ADDRESS_FAULT;
    frame_sp = (emulator->dos_dpmi_transition_depth + 1u) * 0x2000u - width * 3u;
    stack = emulator->region_data + DPMI_CALLBACK_STACK_BASE + frame_sp;
    t = emulator->dos_dpmi_transitions + emulator->dos_dpmi_transition_depth;
    memset(t, 0, sizeof(*t)); t->kind = DPMI_TRANSITION_CALLBACK; t->callback = (uint8_t)slot; t->cr0 = emulator->dos_cr0;
    t->real_port92 = emulator->dos_port_92; t->real_kbc = emulator->dos_kbc_output;
    dpmi_packet_save(emulator, packet);
    dpmi_descriptor(emulator, c->stack_alias, (uint32_t)real_ss << 4u, 0xffffu, 0x93u, 0u);
    if (width == 4u) { dpmi_put_u32(stack, DPMI_CALLBACK_RETURN); dpmi_put_u32(stack + 4u, XXEMUL_DPMI_HOST_SELECTOR); dpmi_put_u32(stack + 8u, 2u); }
    else { dpmi_put_u16(stack, DPMI_CALLBACK_RETURN); dpmi_put_u16(stack + 2u, XXEMUL_DPMI_HOST_SELECTOR); dpmi_put_u16(stack + 4u, 2u); }
    dpmi_load_selector(emulator, XXEMUL_X86_CS, c->procedure_selector);
    dpmi_load_selector(emulator, XXEMUL_X86_SS, XXEMUL_DPMI_STACK_SELECTOR);
    dpmi_load_selector(emulator, XXEMUL_X86_DS, c->stack_alias);
    dpmi_load_selector(emulator, XXEMUL_X86_ES, c->packet_selector);
    emulator->x86.gpr[XXEMUL_X86_RSI] = real_sp; emulator->x86.gpr[XXEMUL_X86_RDI] = c->packet_offset;
    emulator->x86.gpr[XXEMUL_X86_RSP] = frame_sp; emulator->x86.ip = c->procedure_offset;
    emulator->x86.segment[XXEMUL_X86_FS] = emulator->x86.segment[XXEMUL_X86_GS] = 0u;
    memset(emulator->dos_segments + XXEMUL_X86_FS, 0, sizeof(emulator->dos_segments[XXEMUL_X86_FS]));
    memset(emulator->dos_segments + XXEMUL_X86_GS, 0, sizeof(emulator->dos_segments[XXEMUL_X86_GS]));
    emulator->dos_port_92 |= 2u; emulator->dos_kbc_output |= 2u;
    emulator->dos_cr0 |= 1u; emulator->x86.flags = 2u;
    emulator->mode = (emulator->dos_segments[XXEMUL_X86_CS].flags & 4u) ? XXEMUL_MODE_X86_32 : XXEMUL_MODE_X86_16;
    ++c->active; ++emulator->dos_dpmi_transition_depth;
    return XXEMUL_STATUS_OK;
}

int xxemul_dpmi_try_transition(xxemul *emulator, xxemul_step_info *info, xxemul_status *status)
{
    uint64_t address;
    uint32_t ip = (uint32_t)emulator->x86.ip;
    xxemul_dpmi_transition *t;
    uint8_t *packet;
    if (!emulator->dos_mode || !emulator->dos_dpmi_next_selector) return 0;
    address = (uint64_t)emulator->dos_segments[XXEMUL_X86_CS].base + ip;
    if (!(emulator->dos_cr0 & 1u) && emulator->x86.segment[XXEMUL_X86_CS] == 0xf000u &&
        ip >= DPMI_CALLBACK_FIRST && ip < DPMI_CALLBACK_FIRST + XXEMUL_DPMI_CALLBACK_SLOTS * 16u &&
        (ip - DPMI_CALLBACK_FIRST) % 16u == 0u) {
        *status = dpmi_callback_enter(emulator, (ip - DPMI_CALLBACK_FIRST) / 16u);
    } else if ((emulator->dos_cr0 & 1u) && emulator->x86.segment[XXEMUL_X86_CS] == XXEMUL_DPMI_HOST_SELECTOR && ip == DPMI_CALLBACK_RETURN) {
        if (!emulator->dos_dpmi_transition_depth || (t = emulator->dos_dpmi_transitions + emulator->dos_dpmi_transition_depth - 1u)->kind != DPMI_TRANSITION_CALLBACK) {
            *status = XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION; return 1;
        }
        packet = dpmi_pointer(emulator, emulator->x86.segment[XXEMUL_X86_ES], emulator->dos_dpmi_client32 ? (uint32_t)emulator->x86.gpr[XXEMUL_X86_RDI] : (uint16_t)emulator->x86.gpr[XXEMUL_X86_RDI], 0x32u, 0);
        if (!packet) { *status = XXEMUL_STATUS_ADDRESS_FAULT; return 1; }
        emulator->dos_cr0 = t->cr0; dpmi_packet_load(emulator, packet);
        emulator->dos_port_92 = t->real_port92; emulator->dos_kbc_output = t->real_kbc;
        --emulator->dos_dpmi_callbacks[t->callback].active; --emulator->dos_dpmi_transition_depth;
        *status = XXEMUL_STATUS_OK;
    } else if (!(emulator->dos_cr0 & 1u) && emulator->x86.segment[XXEMUL_X86_CS] == 0xf000u && ip == DPMI_REAL_RETURN) {
        if (!emulator->dos_dpmi_transition_depth || ((t = emulator->dos_dpmi_transitions + emulator->dos_dpmi_transition_depth - 1u)->kind != DPMI_TRANSITION_SIMULATE && t->kind != DPMI_TRANSITION_REFLECT)) {
            *status = XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION; return 1;
        }
        packet = t->kind == DPMI_TRANSITION_REFLECT ? emulator->region_data + t->packet_offset : dpmi_pointer(emulator, t->packet_selector, t->packet_offset, 0x32u, 0);
        if (!packet || emulator->x86.segment[XXEMUL_X86_SS] != t->real_ss || (uint16_t)emulator->x86.gpr[XXEMUL_X86_RSP] != t->real_sp) {
            *status = XXEMUL_STATUS_ADDRESS_FAULT; return 1;
        }
        dpmi_packet_save(emulator, packet);
        if (t->kind == DPMI_TRANSITION_REFLECT) {
            *status = dpmi_finish_reflection(emulator, t);
            if (*status != XXEMUL_STATUS_OK) return 1;
        } else {
            emulator->x86 = t->state; memcpy(emulator->dos_segments, t->segments, sizeof(t->segments));
            emulator->mode = t->mode; emulator->dos_cr0 = t->cr0; emulator->x86.flags &= ~DPMI_CF;
        }
        emulator->dos_dpmi_resume_host = t->resume_host ? t->vector : 0u;
        emulator->dos_port_92 |= 2u; emulator->dos_kbc_output |= 2u;
        --emulator->dos_dpmi_transition_depth; *status = XXEMUL_STATUS_OK;
    } else return 0;
    if (*status == XXEMUL_STATUS_OK && info) {
        info->address = address; info->next_address = (uint64_t)emulator->dos_segments[XXEMUL_X86_CS].base + emulator->x86.ip;
        info->size = 0u; info->instruction_id = 0u;
    }
    return 1;
}

static xxemul_status dpmi_simulate_interrupt(xxemul *emulator)
{
    uint16_t vector = (uint16_t)emulator->x86.gpr[XXEMUL_X86_RBX];
    uint8_t *frame;
    xxemul_x86_state saved;
    xxemul_status status;

    frame = dpmi_descriptor_buffer(emulator, 1, 0x32u);
    if (!frame) return XXEMUL_STATUS_ADDRESS_FAULT;
    if (vector > 0xffu || (uint16_t)emulator->x86.gpr[XXEMUL_X86_RCX] > 128u) {
        emulator->x86.gpr[XXEMUL_X86_RAX] = 0x8021u; emulator->x86.flags |= DPMI_CF; return XXEMUL_STATUS_OK;
    }
    {
        uint16_t ip = dpmi_u16(emulator->region_data + vector * 4u), cs = dpmi_u16(emulator->region_data + vector * 4u + 2u);
        if ((uint16_t)emulator->x86.gpr[XXEMUL_X86_RCX] ||
            !((vector == 0x21u && cs == 0xf000u && ip == 0x100u) || (vector == 0x10u && cs == 0xf000u && ip == 0x110u)))
            return dpmi_begin_real_interrupt(emulator, (uint8_t)vector, frame, DPMI_TRANSITION_SIMULATE);
    }
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
    status = vector == 0x21u ? xxemul_msdos_interrupt(emulator, 0x21u) : xxemul_bios_interrupt(emulator, 0x10u);
    if (status == XXEMUL_STATUS_OK) {
        dpmi_put_u32(frame, (uint32_t)emulator->x86.gpr[XXEMUL_X86_RDI]);
        dpmi_put_u32(frame + 4u, (uint32_t)emulator->x86.gpr[XXEMUL_X86_RSI]);
        dpmi_put_u32(frame + 8u, (uint32_t)emulator->x86.gpr[XXEMUL_X86_RBP]);
        dpmi_put_u32(frame + 0x10u, (uint32_t)emulator->x86.gpr[XXEMUL_X86_RBX]);
        dpmi_put_u32(frame + 0x14u, (uint32_t)emulator->x86.gpr[XXEMUL_X86_RDX]);
        dpmi_put_u32(frame + 0x18u, (uint32_t)emulator->x86.gpr[XXEMUL_X86_RCX]);
        dpmi_put_u32(frame + 0x1cu, (uint32_t)emulator->x86.gpr[XXEMUL_X86_RAX]);
        dpmi_put_u16(frame + 0x20u, (uint16_t)emulator->x86.flags);
        dpmi_put_u16(frame + 0x22u, emulator->x86.segment[XXEMUL_X86_ES]);
        dpmi_put_u16(frame + 0x24u, emulator->x86.segment[XXEMUL_X86_DS]);
    }
    emulator->x86 = saved;
    if (status == XXEMUL_STATUS_OK) emulator->x86.flags &= ~DPMI_CF;
    return status;
}

xxemul_status xxemul_dpmi_interrupt(xxemul *emulator)
{
    uint16_t function = (uint16_t)emulator->x86.gpr[XXEMUL_X86_RAX];
    uint16_t selector = (uint16_t)emulator->x86.gpr[XXEMUL_X86_RBX];
    uint8_t *descriptor;
    uint32_t address;

    emulator->x86.flags &= ~DPMI_CF;
    switch (function) {
        case 0x0000u:
            {
            uint16_t count = (uint16_t)emulator->x86.gpr[XXEMUL_X86_RCX], i;
            selector = dpmi_find_descriptors(emulator, count);
            if (selector == 0u) break;
            for (i = 0u; i < count; ++i) dpmi_descriptor(emulator, (uint16_t)(selector + i * 8u), 0u, 0xffffu, 0x93u, 0u);
            dpmi_descriptors_used(emulator, selector, count);
            emulator->x86.gpr[XXEMUL_X86_RAX] = selector;
            return XXEMUL_STATUS_OK;
            }
        case 0x0006u:
            descriptor = dpmi_client_descriptor(emulator, selector);
            if (descriptor == NULL) {
                emulator->x86.gpr[XXEMUL_X86_RAX] = 0x8022u;
                emulator->x86.flags |= DPMI_CF;
                return XXEMUL_STATUS_OK;
            }
            address = dpmi_descriptor_base(descriptor);
            emulator->x86.gpr[XXEMUL_X86_RCX] = address >> 16u;
            emulator->x86.gpr[XXEMUL_X86_RDX] = address & 0xffffu;
            return XXEMUL_STATUS_OK;
        case 0x0007u:
        case 0x0008u:
        case 0x0009u:
            if (dpmi_callback_owns_selector(emulator, selector)) {
                emulator->x86.gpr[XXEMUL_X86_RAX] = 0x8022u; emulator->x86.flags |= DPMI_CF;
                return XXEMUL_STATUS_OK;
            }
            if (selector < 8u || selector == XXEMUL_DPMI_HOST_SELECTOR || selector == XXEMUL_DPMI_STACK_SELECTOR || selector >= emulator->dos_dpmi_next_selector || (selector & 7u) != 0u ||
                emulator->region_data[DPMI_GDT_BASE + selector + 5u] == 0u) break;
            descriptor = emulator->region_data + DPMI_GDT_BASE + selector;
            if (function == 0x0007u) {
                uint32_t base = ((uint32_t)(uint16_t)emulator->x86.gpr[XXEMUL_X86_RCX] << 16u) | (uint16_t)emulator->x86.gpr[XXEMUL_X86_RDX];
                dpmi_put_u16(descriptor + 2u, (uint16_t)base);
                descriptor[4] = (uint8_t)(base >> 16u);
                descriptor[7] = (uint8_t)(base >> 24u);
            } else if (function == 0x0008u) {
                uint32_t limit = ((uint32_t)(uint16_t)emulator->x86.gpr[XXEMUL_X86_RCX] << 16u) | (uint16_t)emulator->x86.gpr[XXEMUL_X86_RDX];
                uint32_t encoded = limit > 0xfffffu ? limit >> 12u : limit;
                dpmi_put_u16(descriptor, (uint16_t)encoded);
                descriptor[6] = (uint8_t)((descriptor[6] & 0x70u) | (limit > 0xfffffu ? 0x80u : 0u) | ((encoded >> 16u) & 15u));
            } else {
                uint16_t rights = (uint16_t)emulator->x86.gpr[XXEMUL_X86_RCX];
                descriptor[5] = (uint8_t)rights;
                descriptor[6] = (uint8_t)((descriptor[6] & 15u) | ((rights >> 8u) & 0xf0u));
            }
            dpmi_refresh_descriptor(emulator, selector, descriptor);
            return XXEMUL_STATUS_OK;
        case 0x000au:
            {
            uint16_t alias;
            if (selector < 8u || selector == XXEMUL_DPMI_HOST_SELECTOR || selector == XXEMUL_DPMI_STACK_SELECTOR || selector >= emulator->dos_dpmi_next_selector || (selector & 7u) != 0u ||
                (emulator->region_data[DPMI_GDT_BASE + selector + 5u] & 0x90u) != 0x90u) {
                emulator->x86.gpr[XXEMUL_X86_RAX] = 0x8022u;
                emulator->x86.flags |= DPMI_CF;
                return XXEMUL_STATUS_OK;
            }
            alias = dpmi_find_descriptors(emulator, 1u);
            if (alias == 0u) {
                emulator->x86.gpr[XXEMUL_X86_RAX] = 0x8011u;
                emulator->x86.flags |= DPMI_CF;
                return XXEMUL_STATUS_OK;
            }
            descriptor = emulator->region_data + DPMI_GDT_BASE + alias;
            memcpy(descriptor, emulator->region_data + DPMI_GDT_BASE + selector, 8u);
            descriptor[5] = (uint8_t)((descriptor[5] & 0xf0u) | 3u); /* writable data alias */
            dpmi_descriptors_used(emulator, alias, 1u);
            emulator->x86.gpr[XXEMUL_X86_RAX] = alias;
            return XXEMUL_STATUS_OK;
            }
        case 0x000bu:
        case 0x000cu:
            {
            uint8_t *buffer, replacement[8];
            if (function == 0x000cu && dpmi_callback_owns_selector(emulator, selector)) {
                emulator->x86.gpr[XXEMUL_X86_RAX] = 0x8022u; emulator->x86.flags |= DPMI_CF;
                return XXEMUL_STATUS_OK;
            }
            descriptor = dpmi_client_descriptor(emulator, selector);
            if (descriptor == NULL) {
                emulator->x86.gpr[XXEMUL_X86_RAX] = 0x8022u;
                emulator->x86.flags |= DPMI_CF;
                return XXEMUL_STATUS_OK;
            }
            buffer = dpmi_descriptor_buffer(emulator, function == 0x000bu, 8u);
            if (buffer == NULL) {
                emulator->x86.gpr[XXEMUL_X86_RAX] = 0x8025u;
                emulator->x86.flags |= DPMI_CF;
                return XXEMUL_STATUS_OK;
            }
            if (function == 0x000bu) {
                memcpy(buffer, descriptor, 8u);
                return XXEMUL_STATUS_OK;
            }
            memcpy(replacement, buffer, 8u);
            if (!(replacement[5] & 0x10u) ||
                ((replacement[5] >> 5u) & 3u) != (emulator->x86.segment[XXEMUL_X86_CS] & 3u) ||
                ((replacement[5] & 0x80u) && (replacement[6] & 0x20u))) {
                emulator->x86.gpr[XXEMUL_X86_RAX] = 0x8021u;
                emulator->x86.flags |= DPMI_CF;
                return XXEMUL_STATUS_OK;
            }
            if ((replacement[5] & 0x80u) &&
                (uint64_t)dpmi_descriptor_base(replacement) + dpmi_descriptor_limit(replacement) > UINT32_MAX) {
                emulator->x86.gpr[XXEMUL_X86_RAX] = 0x8025u;
                emulator->x86.flags |= DPMI_CF;
                return XXEMUL_STATUS_OK;
            }
            memcpy(descriptor, replacement, 8u);
            dpmi_refresh_descriptor(emulator, selector, descriptor);
            return XXEMUL_STATUS_OK;
            }
        case 0x0500u:
            {
            uint8_t *buffer = dpmi_descriptor_buffer(emulator, 1, 0x30u);
            if (!buffer) {
                emulator->x86.gpr[XXEMUL_X86_RAX] = 0x8025u;
                emulator->x86.flags |= DPMI_CF;
                return XXEMUL_STATUS_OK;
            }
            memset(buffer, 0xff, 0x30u);
            dpmi_put_u32(buffer, dpmi_largest_free_memory(emulator));
            return XXEMUL_STATUS_OK;
            }
        case 0x0501u:
        case 0x0502u:
        case 0x0503u: return dpmi_memory(emulator, function);
        case 0x0600u:
        case 0x0601u: return dpmi_resident_region(emulator);
        case 0x0100u: return dpmi_allocate_dos(emulator);
        case 0x0101u: return dpmi_free_dos(emulator);
        case 0x0204u: return dpmi_protected_vector(emulator, 0);
        case 0x0205u: return dpmi_protected_vector(emulator, 1);
        case 0x0200u:
        case 0x0201u:
            {
            uint8_t *entry = emulator->region_data + (uint8_t)selector * 4u;
            if (function == 0x0200u) {
                emulator->x86.gpr[XXEMUL_X86_RCX] = dpmi_u16(entry + 2u);
                emulator->x86.gpr[XXEMUL_X86_RDX] = dpmi_u16(entry);
            } else {
                dpmi_put_u16(entry, (uint16_t)emulator->x86.gpr[XXEMUL_X86_RDX]);
                dpmi_put_u16(entry + 2u, (uint16_t)emulator->x86.gpr[XXEMUL_X86_RCX]);
            }
            return XXEMUL_STATUS_OK;
            }
        case 0x0300u: return dpmi_simulate_interrupt(emulator);
        case 0x0303u: return dpmi_callback_allocate(emulator);
        case 0x0304u: return dpmi_callback_free(emulator);
        case 0x0400u:
            emulator->x86.gpr[XXEMUL_X86_RAX] = 0x005au;
            emulator->x86.gpr[XXEMUL_X86_RBX] = 3u; /* 386 host, real reflection, resident/no virtual memory */
            emulator->x86.gpr[XXEMUL_X86_RCX] = 3u;
            emulator->x86.gpr[XXEMUL_X86_RDX] = ((uint32_t)emulator->dos_pic_master_offset << 8u) | emulator->dos_pic_slave_offset;
            return XXEMUL_STATUS_OK;
        default: break;
    }
    emulator->x86.gpr[XXEMUL_X86_RAX] = 0x8001u;
    emulator->x86.flags |= DPMI_CF;
    return XXEMUL_STATUS_OK;
}
