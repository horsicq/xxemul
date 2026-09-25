#include "xxemul_internal.h"
#include "platforms/xxemul_windows.h"
#include "platforms/xxemul_linux.h"

#include <math.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define XXEMUL_X86_FLAG_CF (UINT64_C(1) << 0)
#define XXEMUL_X86_FLAG_PF (UINT64_C(1) << 2)
#define XXEMUL_X86_FLAG_AF (UINT64_C(1) << 4)
#define XXEMUL_X86_FLAG_ZF (UINT64_C(1) << 6)
#define XXEMUL_X86_FLAG_SF (UINT64_C(1) << 7)
#define XXEMUL_X86_FLAG_TF (UINT64_C(1) << 8)
#define XXEMUL_X86_FLAG_OF (UINT64_C(1) << 11)
#define XXEMUL_X86_FLAG_IF (UINT64_C(1) << 9)
#define XXEMUL_X86_FLAG_DF (UINT64_C(1) << 10)
#define XXEMUL_X86_FLAG_NT (UINT64_C(1) << 14)
#define XXEMUL_X86_FLAG_RF (UINT64_C(1) << 16)
#define XXEMUL_X86_FLAG_VM (UINT64_C(1) << 17)

#define XXEMUL_DOS_INT21_THUNK_SEGMENT 0xf000u
#define XXEMUL_DOS_INT21_THUNK_OFFSET 0x0100u
#define XXEMUL_DOS_INT10_THUNK_OFFSET 0x0110u

#define XXEMUL_X86_DECODE_CACHE_SIZE 4096u

struct xxemul_x86_decode_cache_entry {
    uint64_t ip;
    uint64_t fetch_address;
    uint8_t code[15];
    uint8_t available;
    uint8_t valid;
    cdisasm_x86_instruction instruction;
};

typedef struct xxemul_x86_register_view {
    uint8_t index;
    uint8_t size;
    uint8_t shift;
    uint8_t is_ip;
    uint8_t is_segment;
} xxemul_x86_register_view;

static uint8_t xxemul_x86_mode_size(const xxemul *emulator)
{
    if (emulator->mode == XXEMUL_MODE_X86_16) {
        return 2u;
    }
    if (emulator->mode == XXEMUL_MODE_X86_32) {
        return 4u;
    }
    return 8u;
}

static uint64_t xxemul_x86_address_mask(const xxemul *emulator)
{
    return xxemul_mask_for_size(xxemul_x86_mode_size(emulator));
}

static uint64_t xxemul_x86_operand_address_mask(
    const xxemul *emulator, const cdisasm_x86_instruction *instruction)
{
    uint8_t size = xxemul_x86_mode_size(emulator);
    if ((instruction->opcode_flags & CDISASM_PREFIX_ADDRESS_SIZE) != 0u)
        size = size == 2u ? 4u : size == 4u ? 2u : 4u;
    return xxemul_mask_for_size(size);
}

static cdisasm_x86_mode xxemul_x86_cdisasm_mode(const xxemul *emulator)
{
    if (emulator->mode == XXEMUL_MODE_X86_16) {
        return CDISASM_X86_MODE_16;
    }
    if (emulator->mode == XXEMUL_MODE_X86_32) {
        return CDISASM_X86_MODE_32;
    }
    return CDISASM_X86_MODE_64;
}

static uint64_t xxemul_x86_stack_mask(const xxemul *emulator)
{
    if (emulator->dos_mode && emulator->dos_segments[XXEMUL_X86_SS].valid) {
        return (emulator->dos_segments[XXEMUL_X86_SS].flags & 4u) != 0u
            ? UINT32_MAX : UINT16_MAX;
    }
    return xxemul_x86_address_mask(emulator);
}

static xxemul_status xxemul_x86_dos_address(
    const xxemul *emulator, uint8_t segment_index,
    uint64_t offset, uint8_t size, uint64_t *address)
{
    const xxemul_x86_segment_cache *segment =
        &emulator->dos_segments[segment_index];
    uint64_t limit = segment->valid ? segment->limit : UINT16_MAX;
    uint64_t base = segment->valid ? segment->base
        : (uint32_t)emulator->x86.segment[segment_index] << 4u;
    uint64_t linear;

    if (size == 0u || offset > limit || size - 1u > limit - offset
        || (segment->valid && segment->access == 0u)) {
        return XXEMUL_STATUS_ADDRESS_FAULT;
    }
    linear = base + offset;
    *address = (uint32_t)linear;
    return XXEMUL_STATUS_OK;
}

static uint32_t xxemul_x86_dos_a20(
    const xxemul *emulator, uint32_t physical)
{
    return (emulator->dos_port_92 & 2u) != 0u
        ? physical : physical & ~UINT32_C(0x100000);
}

static xxemul_status xxemul_x86_dos_translate(
    xxemul *emulator, uint32_t linear, int writing,
    uint32_t *physical, uint32_t *page_fault_error)
{
    uint64_t pde_address;
    uint64_t pte_address;
    uint64_t entry;
    uint32_t pde;
    uint32_t pte;
    xxemul_status status;

    if ((emulator->dos_cr0 & UINT32_C(0x80000000)) == 0u) {
        *physical = xxemul_x86_dos_a20(emulator, linear);
        return XXEMUL_STATUS_OK;
    }
    pde_address = xxemul_x86_dos_a20(emulator,
        (emulator->dos_cr3 & UINT32_C(0xfffff000))
            + ((linear >> 22u) * 4u));
    status = xxemul_load_integer(emulator, pde_address, 4u, &entry);
    if (status != XXEMUL_STATUS_OK) goto fault;
    pde = (uint32_t)entry;
    if ((pde & 1u) == 0u) goto not_present;
    if ((pde & 0x80u) != 0u)
        return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    pte_address = xxemul_x86_dos_a20(emulator,
        (pde & UINT32_C(0xfffff000))
            + (((linear >> 12u) & 0x3ffu) * 4u));
    status = xxemul_load_integer(emulator, pte_address, 4u, &entry);
    if (status != XXEMUL_STATUS_OK) goto fault;
    pte = (uint32_t)entry;
    if ((pte & 1u) == 0u) goto not_present;
    if (writing && (emulator->dos_cr0 & UINT32_C(0x10000)) != 0u
        && ((pde & pte & 2u) == 0u)) goto protection;

    if ((pde & 0x20u) == 0u) {
        status = xxemul_store_integer(emulator, pde_address,
            4u, pde | 0x20u);
        if (status != XXEMUL_STATUS_OK) goto fault;
    }
    if ((pte & (writing ? 0x60u : 0x20u))
        != (writing ? 0x60u : 0x20u)) {
        status = xxemul_store_integer(emulator, pte_address,
            4u, pte | (writing ? 0x60u : 0x20u));
        if (status != XXEMUL_STATUS_OK) goto fault;
    }
    *physical = xxemul_x86_dos_a20(emulator,
        (pte & UINT32_C(0xfffff000)) | (linear & 0xfffu));
    return XXEMUL_STATUS_OK;

not_present:
    emulator->dos_pending_page_fault_error = (writing ? 2u : 0u)
        | ((emulator->x86.segment[XXEMUL_X86_CS] & 3u) != 0u
            ? 4u : 0u);
    if (page_fault_error != NULL)
        *page_fault_error = emulator->dos_pending_page_fault_error;
    goto fault;
protection:
    emulator->dos_pending_page_fault_error = 1u | (writing ? 2u : 0u)
        | ((emulator->x86.segment[XXEMUL_X86_CS] & 3u) != 0u
            ? 4u : 0u);
    if (page_fault_error != NULL)
        *page_fault_error = emulator->dos_pending_page_fault_error;
fault:
    emulator->dos_cr2 = linear;
    return XXEMUL_STATUS_ADDRESS_FAULT;
}

static xxemul_status xxemul_x86_guest_memory_tracked(
    xxemul *emulator, uint64_t address,
    void *buffer, size_t size, int writing,
    uint32_t *page_fault_error)
{
    size_t done = 0u;

    if (page_fault_error != NULL) *page_fault_error = UINT32_MAX;
    if (emulator->memory_hook != NULL && emulator->in_step
        && !emulator->x86_fetching && size != 0u) {
        emulator->memory_hook(emulator->memory_hook_context,
            address, size, writing);
    }
    if (!emulator->dos_mode) {
        return writing
            ? xxemul_write_memory(emulator, address, buffer, size)
            : xxemul_read_memory(emulator, address, buffer, size);
    }
    if (writing && size != 0u
        && ((uint32_t)address >> 12u)
            != ((uint32_t)(address + size - 1u) >> 12u)) {
        size_t checked = 0u;

        while (checked < size) {
            uint32_t linear = (uint32_t)(address + checked);
            uint32_t physical;
            uint8_t probe;
            size_t chunk = 0x1000u - (linear & 0xfffu);
            xxemul_status status;

            if (chunk > size - checked) chunk = size - checked;
            status = xxemul_x86_dos_translate(emulator, linear, 1,
                &physical, page_fault_error);
            if (status != XXEMUL_STATUS_OK) return status;
            status = xxemul_read_memory(emulator, physical, &probe, 1u);
            if (status == XXEMUL_STATUS_OK)
                status = xxemul_read_memory(emulator,
                    (uint64_t)physical + chunk - 1u, &probe, 1u);
            if (status != XXEMUL_STATUS_OK) {
                emulator->dos_cr2 = linear;
                return status;
            }
            checked += chunk;
        }
    }
    while (done < size) {
        uint32_t linear = (uint32_t)(address + done);
        uint32_t physical;
        size_t chunk = 0x1000u - (linear & 0xfffu);
        xxemul_status status;

        if (chunk > size - done) chunk = size - done;
        status = xxemul_x86_dos_translate(
            emulator, linear, writing, &physical, page_fault_error);
        if (status != XXEMUL_STATUS_OK) return status;
        status = writing
            ? xxemul_write_memory(emulator, physical,
                (const uint8_t *)buffer + done, chunk)
            : xxemul_read_memory(emulator, physical,
                (uint8_t *)buffer + done, chunk);
        if (status != XXEMUL_STATUS_OK) {
            emulator->dos_cr2 = linear;
            return status;
        }
        done += chunk;
    }
    return XXEMUL_STATUS_OK;
}

static xxemul_status xxemul_x86_guest_memory(
    xxemul *emulator, uint64_t address,
    void *buffer, size_t size, int writing)
{
    return xxemul_x86_guest_memory_tracked(
        emulator, address, buffer, size, writing, NULL);
}

static xxemul_status xxemul_x86_guest_load_integer_tracked(
    xxemul *emulator, uint64_t address, uint8_t size, uint64_t *value,
    uint32_t *page_fault_error)
{
    uint8_t bytes[8];
    uint64_t result = 0u;
    uint8_t index;
    xxemul_status status;

    if (size == 0u || size > sizeof(bytes) || value == NULL)
        return XXEMUL_STATUS_INVALID_ARGUMENT;
    status = xxemul_x86_guest_memory_tracked(
        emulator, address, bytes, size, 0, page_fault_error);
    if (status != XXEMUL_STATUS_OK) return status;
    for (index = 0u; index < size; ++index)
        result |= (uint64_t)bytes[index] << (index * 8u);
    *value = result;
    return XXEMUL_STATUS_OK;
}

static xxemul_status xxemul_x86_guest_load_integer(
    xxemul *emulator, uint64_t address, uint8_t size, uint64_t *value)
{
    return xxemul_x86_guest_load_integer_tracked(
        emulator, address, size, value, NULL);
}

static xxemul_status xxemul_x86_guest_store_integer_tracked(
    xxemul *emulator, uint64_t address, uint8_t size, uint64_t value,
    uint32_t *page_fault_error)
{
    uint8_t bytes[8];
    uint8_t index;

    if (size == 0u || size > sizeof(bytes))
        return XXEMUL_STATUS_INVALID_ARGUMENT;
    for (index = 0u; index < size; ++index)
        bytes[index] = (uint8_t)(value >> (index * 8u));
    return xxemul_x86_guest_memory_tracked(
        emulator, address, bytes, size, 1, page_fault_error);
}

static xxemul_status xxemul_x86_guest_store_integer(
    xxemul *emulator, uint64_t address, uint8_t size, uint64_t value)
{
    return xxemul_x86_guest_store_integer_tracked(
        emulator, address, size, value, NULL);
}

static uint16_t xxemul_x86_dos_u16(const uint8_t *bytes)
{
    return (uint16_t)((uint16_t)bytes[0]
        | ((uint16_t)bytes[1] << 8u));
}

static uint32_t xxemul_x86_dos_u32(const uint8_t *bytes)
{
    return (uint32_t)bytes[0] | ((uint32_t)bytes[1] << 8u)
        | ((uint32_t)bytes[2] << 16u) | ((uint32_t)bytes[3] << 24u);
}

static void xxemul_x86_dos_put_u16(uint8_t *bytes, uint16_t value)
{
    bytes[0] = (uint8_t)value;
    bytes[1] = (uint8_t)(value >> 8u);
}

static void xxemul_x86_dos_put_u32(uint8_t *bytes, uint32_t value)
{
    bytes[0] = (uint8_t)value;
    bytes[1] = (uint8_t)(value >> 8u);
    bytes[2] = (uint8_t)(value >> 16u);
    bytes[3] = (uint8_t)(value >> 24u);
}

static uint32_t xxemul_x86_dos_descriptor_base(const uint8_t *descriptor)
{
    return (uint32_t)descriptor[2] | ((uint32_t)descriptor[3] << 8u)
        | ((uint32_t)descriptor[4] << 16u)
        | ((uint32_t)descriptor[7] << 24u);
}

static uint32_t xxemul_x86_dos_descriptor_limit(const uint8_t *descriptor)
{
    uint32_t limit = xxemul_x86_dos_u16(descriptor)
        | (((uint32_t)descriptor[6] & 15u) << 16u);

    return (descriptor[6] & 0x80u) != 0u
        ? (limit << 12u) | 0xfffu : limit;
}

static xxemul_status xxemul_x86_dos_read_descriptor_tracked(
    xxemul *emulator, uint16_t selector,
    uint16_t ldt_selector, uint32_t ldt_base, uint32_t ldt_limit,
    uint8_t descriptor[8], uint32_t *address,
    uint32_t *page_fault_error)
{
    uint32_t index = selector & ~7u;
    uint32_t base = emulator->dos_gdtr_base;
    uint32_t limit = emulator->dos_gdtr_limit;

    if ((selector & 4u) != 0u) {
        if (ldt_selector == 0u) return XXEMUL_STATUS_ADDRESS_FAULT;
        base = ldt_base;
        limit = ldt_limit;
    }
    if (index > limit || limit - index < 7u
        || (selector & ~3u) == 0u)
        return XXEMUL_STATUS_ADDRESS_FAULT;
    *address = base + index;
    return xxemul_x86_guest_memory_tracked(emulator,
        *address, descriptor, 8u, 0, page_fault_error);
}

static xxemul_status xxemul_x86_dos_read_descriptor(
    xxemul *emulator, uint16_t selector,
    uint16_t ldt_selector, uint32_t ldt_base, uint32_t ldt_limit,
    uint8_t descriptor[8], uint32_t *address)
{
    return xxemul_x86_dos_read_descriptor_tracked(emulator, selector,
        ldt_selector, ldt_base, ldt_limit, descriptor, address, NULL);
}

static xxemul_status xxemul_x86_decode_dos_segment(
    xxemul *emulator, uint8_t segment_index, uint16_t selector,
    uint16_t ldt_selector, uint32_t ldt_base, uint32_t ldt_limit,
    xxemul_x86_segment_cache *cache)
{
    uint8_t descriptor[8];
    uint32_t address;
    xxemul_status status;

    if ((emulator->dos_cr0 & 1u) == 0u) {
        cache->base = (uint32_t)selector << 4u;
        cache->limit = UINT16_MAX;
        cache->access = segment_index == XXEMUL_X86_CS ? 0x9bu : 0x93u;
        cache->flags = 0u;
        cache->valid = 1u;
    } else if ((selector & ~3u) == 0u && segment_index != XXEMUL_X86_CS
        && segment_index != XXEMUL_X86_SS) {
        memset(cache, 0, sizeof(*cache));
        cache->valid = 1u;
    } else {
        status = xxemul_x86_dos_read_descriptor(emulator, selector,
            ldt_selector, ldt_base, ldt_limit, descriptor, &address);
        if (status != XXEMUL_STATUS_OK) return status;
        cache->access = descriptor[5];
        cache->flags = descriptor[6] >> 4u;
        if ((cache->access & 0x90u) != 0x90u
            || (segment_index == XXEMUL_X86_CS
                && (cache->access & 8u) == 0u)
            || (segment_index == XXEMUL_X86_SS
                && (cache->access & 0x0au) != 2u)
            || (segment_index != XXEMUL_X86_CS
                && segment_index != XXEMUL_X86_SS
                && (cache->access & 8u) != 0u
                && (cache->access & 2u) == 0u)) {
            return XXEMUL_STATUS_ADDRESS_FAULT;
        }
        cache->limit = xxemul_x86_dos_descriptor_limit(descriptor);
        cache->base = xxemul_x86_dos_descriptor_base(descriptor);
        cache->valid = 1u;
    }
    return XXEMUL_STATUS_OK;
}

static xxemul_status xxemul_x86_load_dos_segment(
    xxemul *emulator, uint8_t segment_index, uint16_t selector)
{
    xxemul_x86_segment_cache cache;
    xxemul_status status = xxemul_x86_decode_dos_segment(emulator,
        segment_index, selector, emulator->dos_ldtr_selector,
        emulator->dos_ldtr_base, emulator->dos_ldtr_limit, &cache);

    if (status != XXEMUL_STATUS_OK) return status;
    emulator->x86.segment[segment_index] = selector;
    emulator->dos_segments[segment_index] = cache;
    if (segment_index == XXEMUL_X86_CS) {
        emulator->mode = (cache.flags & 4u) != 0u
            ? XXEMUL_MODE_X86_32 : XXEMUL_MODE_X86_16;
    }
    return XXEMUL_STATUS_OK;
}

static xxemul_status xxemul_x86_dos_preflight_write(
    xxemul *emulator, uint32_t address, size_t size)
{
    size_t done = 0u;

    while (done < size) {
        uint32_t linear = address + (uint32_t)done;
        uint32_t physical;
        uint8_t probe;
        size_t chunk = 0x1000u - (linear & 0xfffu);
        xxemul_status status;

        if (chunk > size - done) chunk = size - done;
        status = xxemul_x86_dos_translate(
            emulator, linear, 1, &physical, NULL);
        if (status != XXEMUL_STATUS_OK) return status;
        status = xxemul_read_memory(
            emulator, (uint64_t)physical + chunk - 1u, &probe, 1u);
        if (status != XXEMUL_STATUS_OK) return status;
        done += chunk;
    }
    return XXEMUL_STATUS_OK;
}

static int xxemul_x86_dos_task_segment_valid(
    uint8_t segment_index, uint16_t selector,
    const xxemul_x86_segment_cache *cache, uint8_t cpl)
{
    uint8_t dpl;
    uint8_t rpl = selector & 3u;
    uint8_t code;
    uint8_t conforming;

    if (cache->access == 0u)
        return segment_index != XXEMUL_X86_CS
            && segment_index != XXEMUL_X86_SS;
    dpl = (cache->access >> 5u) & 3u;
    code = cache->access & 8u;
    conforming = cache->access & 4u;
    if (segment_index == XXEMUL_X86_CS)
        return rpl == cpl && (conforming != 0u
            ? dpl <= cpl : dpl == cpl);
    if (segment_index == XXEMUL_X86_SS)
        return code == 0u && (cache->access & 2u) != 0u
            && dpl == cpl && rpl == cpl;
    return (code != 0u && conforming != 0u)
        || (dpl >= cpl && dpl >= rpl);
}

static xxemul_status xxemul_x86_dos_task_jump(
    xxemul *emulator, uint16_t target_selector,
    uint32_t resume_ip, uint64_t *target_ip)
{
    uint8_t old_descriptor[8];
    uint8_t new_descriptor[8];
    uint8_t ldt_descriptor[8];
    uint8_t old_tss[0x68];
    uint8_t saved_tss[0x68];
    uint8_t new_tss[0x68];
    xxemul_x86_segment_cache new_cache[XXEMUL_X86_SEGMENT_COUNT];
    uint16_t new_selector[XXEMUL_X86_SEGMENT_COUNT];
    uint16_t ldt_selector;
    uint32_t old_descriptor_address;
    uint32_t new_descriptor_address;
    uint32_t ldt_descriptor_address;
    uint32_t new_tss_base;
    uint32_t new_tss_limit;
    uint32_t new_ldt_base = 0u;
    uint32_t new_ldt_limit = 0u;
    uint32_t new_cr3;
    uint32_t old_cr3 = emulator->dos_cr3;
    uint32_t entry_ip;
    uint8_t cpl;
    uint8_t byte;
    uint8_t old_access;
    uint8_t new_access;
    uint8_t index;
    xxemul_status status;

    if ((emulator->dos_cr0 & 1u) == 0u
        || (target_selector & 4u) != 0u
        || (target_selector & ~7u) == 0u
        || (emulator->dos_tr_selector & 4u) != 0u
        || (emulator->dos_tr_selector & ~7u) == 0u
        || emulator->dos_tr_limit < 0x67u)
        return XXEMUL_STATUS_ADDRESS_FAULT;
    status = xxemul_x86_dos_read_descriptor(emulator,
        emulator->dos_tr_selector, 0u, 0u, 0u,
        old_descriptor, &old_descriptor_address);
    if (status != XXEMUL_STATUS_OK) return status;
    status = xxemul_x86_dos_read_descriptor(emulator,
        target_selector, 0u, 0u, 0u,
        new_descriptor, &new_descriptor_address);
    if (status != XXEMUL_STATUS_OK) return status;
    old_access = old_descriptor[5];
    new_access = new_descriptor[5];
    if ((old_access & 0x9fu) != 0x8bu
        || (new_access & 0x9fu) != 0x89u
        || (emulator->x86.segment[XXEMUL_X86_CS] & 3u)
            > ((new_access >> 5u) & 3u)
        || (target_selector & 3u) > ((new_access >> 5u) & 3u))
        return XXEMUL_STATUS_ADDRESS_FAULT;
    new_tss_base = xxemul_x86_dos_descriptor_base(new_descriptor);
    new_tss_limit = xxemul_x86_dos_descriptor_limit(new_descriptor);
    if (new_tss_limit < 0x67u) return XXEMUL_STATUS_ADDRESS_FAULT;

    status = xxemul_x86_guest_memory(emulator,
        emulator->dos_tr_base, old_tss, sizeof(old_tss), 0);
    if (status != XXEMUL_STATUS_OK) return status;
    status = xxemul_x86_guest_memory(emulator,
        new_tss_base, new_tss, sizeof(new_tss), 0);
    if (status != XXEMUL_STATUS_OK) return status;
    memcpy(saved_tss, old_tss, sizeof(saved_tss));
    new_cr3 = xxemul_x86_dos_u32(new_tss + 0x1cu);
    entry_ip = xxemul_x86_dos_u32(new_tss + 0x20u);
    if ((xxemul_x86_dos_u32(new_tss + 0x24u) & 0x20000u) != 0u)
        return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    ldt_selector = xxemul_x86_dos_u16(new_tss + 0x60u);

    /* Validate incoming descriptors under the new task's page tables. */
    if ((emulator->dos_cr0 & UINT32_C(0x80000000)) != 0u)
        emulator->dos_cr3 = new_cr3;
    if (ldt_selector != 0u) {
        if ((ldt_selector & 4u) != 0u) {
            status = XXEMUL_STATUS_ADDRESS_FAULT;
            goto restore_cr3;
        }
        status = xxemul_x86_dos_read_descriptor(emulator,
            ldt_selector, 0u, 0u, 0u,
            ldt_descriptor, &ldt_descriptor_address);
        if (status != XXEMUL_STATUS_OK) goto restore_cr3;
        if ((ldt_descriptor[5] & 0x9fu) != 0x82u) {
            status = XXEMUL_STATUS_ADDRESS_FAULT;
            goto restore_cr3;
        }
        new_ldt_base = xxemul_x86_dos_descriptor_base(ldt_descriptor);
        new_ldt_limit = xxemul_x86_dos_descriptor_limit(ldt_descriptor);
    }
    new_selector[XXEMUL_X86_ES] = xxemul_x86_dos_u16(new_tss + 0x48u);
    new_selector[XXEMUL_X86_CS] = xxemul_x86_dos_u16(new_tss + 0x4cu);
    new_selector[XXEMUL_X86_SS] = xxemul_x86_dos_u16(new_tss + 0x50u);
    new_selector[XXEMUL_X86_DS] = xxemul_x86_dos_u16(new_tss + 0x54u);
    new_selector[XXEMUL_X86_FS] = xxemul_x86_dos_u16(new_tss + 0x58u);
    new_selector[XXEMUL_X86_GS] = xxemul_x86_dos_u16(new_tss + 0x5cu);
    cpl = new_selector[XXEMUL_X86_CS] & 3u;
    for (index = 0u; index < XXEMUL_X86_SEGMENT_COUNT; ++index) {
        status = xxemul_x86_decode_dos_segment(emulator, index,
            new_selector[index], ldt_selector, new_ldt_base,
            new_ldt_limit, &new_cache[index]);
        if (status != XXEMUL_STATUS_OK) goto restore_cr3;
        if (!xxemul_x86_dos_task_segment_valid(index,
                new_selector[index], &new_cache[index], cpl)) {
            status = XXEMUL_STATUS_ADDRESS_FAULT;
            goto restore_cr3;
        }
    }
    if (entry_ip > new_cache[XXEMUL_X86_CS].limit) {
        status = XXEMUL_STATUS_ADDRESS_FAULT;
        goto restore_cr3;
    }
    /* Fetch after committing the new task so its paging faults use its TSS. */
    status = XXEMUL_STATUS_OK;
restore_cr3:
    emulator->dos_cr3 = old_cr3;
    if (status != XXEMUL_STATUS_OK) return status;

    status = xxemul_x86_dos_preflight_write(
        emulator, emulator->dos_tr_base, sizeof(old_tss));
    if (status != XXEMUL_STATUS_OK) return status;
    status = xxemul_x86_dos_preflight_write(
        emulator, old_descriptor_address + 5u, 1u);
    if (status != XXEMUL_STATUS_OK) return status;
    status = xxemul_x86_dos_preflight_write(
        emulator, new_descriptor_address + 5u, 1u);
    if (status != XXEMUL_STATUS_OK) return status;

    xxemul_x86_dos_put_u32(saved_tss + 0x20u, resume_ip);
    xxemul_x86_dos_put_u32(saved_tss + 0x24u,
        (uint32_t)emulator->x86.flags);
    for (index = 0u; index < 8u; ++index)
        xxemul_x86_dos_put_u32(saved_tss + 0x28u + 4u * index,
            (uint32_t)emulator->x86.gpr[index]);
    for (index = 0u; index < XXEMUL_X86_SEGMENT_COUNT; ++index)
        xxemul_x86_dos_put_u16(saved_tss + 0x48u + 4u * index,
            emulator->x86.segment[index]);
    status = xxemul_x86_guest_memory(emulator,
        emulator->dos_tr_base, saved_tss, sizeof(saved_tss), 1);
    if (status != XXEMUL_STATUS_OK) return status;
    byte = (uint8_t)(old_access & 0xfdu);
    status = xxemul_x86_guest_memory(emulator,
        old_descriptor_address + 5u, &byte, 1u, 1);
    if (status != XXEMUL_STATUS_OK) {
        xxemul_x86_guest_memory(emulator,
            emulator->dos_tr_base, old_tss, sizeof(old_tss), 1);
        return status;
    }
    byte = new_access | 2u;
    status = xxemul_x86_guest_memory(emulator,
        new_descriptor_address + 5u, &byte, 1u, 1);
    if (status != XXEMUL_STATUS_OK) {
        xxemul_x86_guest_memory(emulator,
            old_descriptor_address + 5u, &old_access, 1u, 1);
        xxemul_x86_guest_memory(emulator,
            emulator->dos_tr_base, old_tss, sizeof(old_tss), 1);
        return status;
    }

    if ((emulator->dos_cr0 & UINT32_C(0x80000000)) != 0u)
        emulator->dos_cr3 = new_cr3;
    emulator->dos_cr0 |= 8u;
    emulator->dos_tr_selector = target_selector;
    emulator->dos_tr_base = new_tss_base;
    emulator->dos_tr_limit = new_tss_limit;
    emulator->dos_ldtr_selector = ldt_selector;
    emulator->dos_ldtr_base = new_ldt_base;
    emulator->dos_ldtr_limit = new_ldt_limit;
    emulator->x86.flags = xxemul_x86_dos_u32(new_tss + 0x24u) | 2u;
    for (index = 0u; index < 8u; ++index)
        emulator->x86.gpr[index] = xxemul_x86_dos_u32(
            new_tss + 0x28u + 4u * index);
    for (index = 0u; index < XXEMUL_X86_SEGMENT_COUNT; ++index) {
        emulator->x86.segment[index] = new_selector[index];
        emulator->dos_segments[index] = new_cache[index];
    }
    emulator->mode = (new_cache[XXEMUL_X86_CS].flags & 4u) != 0u
        ? XXEMUL_MODE_X86_32 : XXEMUL_MODE_X86_16;
    *target_ip = entry_ip;
    return XXEMUL_STATUS_OK;
}

static xxemul_status xxemul_x86_dos_stack_address(
    const xxemul_x86_segment_cache *cache,
    uint32_t offset, size_t size, uint32_t *linear)
{
    if (!cache->valid || cache->access == 0u || size == 0u
        || offset > cache->limit || size - 1u > cache->limit - offset)
        return XXEMUL_STATUS_ADDRESS_FAULT;
    *linear = cache->base + offset;
    return XXEMUL_STATUS_OK;
}

static xxemul_status xxemul_x86_dos_host_thunk(
    xxemul *emulator, uint8_t vector)
{
    uint64_t flags_address;
    uint64_t saved_flags;
    uint64_t status_mask = XXEMUL_X86_FLAG_CF;
    uint16_t ax = (uint16_t)emulator->x86.gpr[XXEMUL_X86_RAX];
    uint16_t dx = (uint16_t)emulator->x86.gpr[XXEMUL_X86_RDX];
    uint16_t flags_offset = (uint16_t)(
        emulator->x86.gpr[XXEMUL_X86_RSP] + 4u);
    xxemul_status status;

    status = xxemul_x86_dos_address(emulator, XXEMUL_X86_SS,
        flags_offset, 2u, &flags_address);
    if (status != XXEMUL_STATUS_OK) return status;
    status = xxemul_x86_guest_load_integer(
        emulator, flags_address, 2u, &saved_flags);
    if (status != XXEMUL_STATUS_OK) return status;
    status = xxemul_x86_dos_preflight_write(
        emulator, (uint32_t)flags_address, 2u);
    if (status != XXEMUL_STATUS_OK) return status;

    status = vector == 0x21u
        ? xxemul_msdos_interrupt(emulator, vector)
        : xxemul_bios_interrupt(emulator, vector);
    if (status != XXEMUL_STATUS_OK) return status;
    /* The following IRET restores status from the saved return frame. */
    if (vector == 0x21u && (ax >> 8u) == 0x06u
        && (uint8_t)dx == 0xffu)
        status_mask |= XXEMUL_X86_FLAG_ZF;
    saved_flags = (saved_flags & ~status_mask)
        | (emulator->x86.flags & status_mask);
    return xxemul_x86_guest_store_integer(
        emulator, flags_address, 2u, saved_flags);
}

static xxemul_status xxemul_x86_dos_interrupt_gate(
    xxemul *emulator, uint8_t vector,
    uint32_t resume_ip, int hardware_fault,
    uint32_t error_code, uint64_t *target_ip)
{
    uint8_t gate[8];
    uint8_t stack_pointer[6];
    uint8_t frame[24];
    uint8_t *return_frame = frame + (hardware_fault ? 4u : 0u);
    uint8_t fetch_byte;
    uint16_t code_selector;
    uint16_t stack_selector = emulator->x86.segment[XXEMUL_X86_SS];
    xxemul_x86_segment_cache code_cache;
    xxemul_x86_segment_cache stack_cache =
        emulator->dos_segments[XXEMUL_X86_SS];
    uint32_t code_offset;
    uint32_t stack_offset = (uint32_t)emulator->x86.gpr[XXEMUL_X86_RSP];
    uint32_t frame_offset;
    uint32_t frame_address;
    uint32_t stack_mask;
    uint32_t tss_offset;
    size_t frame_size;
    uint8_t old_cpl = emulator->x86.segment[XXEMUL_X86_CS] & 3u;
    uint8_t new_cpl;
    uint8_t dpl;
    int stack_switch;
    xxemul_status status;

    if ((uint32_t)vector * 8u + 7u > emulator->dos_idtr_limit)
        return XXEMUL_STATUS_ADDRESS_FAULT;
    if ((emulator->x86.flags & XXEMUL_X86_FLAG_VM) != 0u)
        return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    status = xxemul_x86_guest_memory(emulator,
        emulator->dos_idtr_base + (uint32_t)vector * 8u,
        gate, sizeof(gate), 0);
    if (status != XXEMUL_STATUS_OK) return status;
    if ((gate[5] & 0x9fu) != 0x8eu || gate[4] != 0u
        || (!hardware_fault && old_cpl > ((gate[5] >> 5u) & 3u)))
        return XXEMUL_STATUS_ADDRESS_FAULT;
    code_selector = xxemul_x86_dos_u16(gate + 2u);
    code_offset = xxemul_x86_dos_u16(gate)
        | ((uint32_t)xxemul_x86_dos_u16(gate + 6u) << 16u);
    status = xxemul_x86_decode_dos_segment(emulator, XXEMUL_X86_CS,
        code_selector, emulator->dos_ldtr_selector,
        emulator->dos_ldtr_base, emulator->dos_ldtr_limit, &code_cache);
    if (status != XXEMUL_STATUS_OK) return status;
    dpl = (code_cache.access >> 5u) & 3u;
    if (dpl > old_cpl || code_offset > code_cache.limit)
        return XXEMUL_STATUS_ADDRESS_FAULT;
    new_cpl = (code_cache.access & 4u) != 0u ? old_cpl : dpl;
    status = xxemul_x86_guest_memory(emulator,
        code_cache.base + code_offset, &fetch_byte, 1u, 0);
    if (status != XXEMUL_STATUS_OK) return status;

    stack_switch = new_cpl < old_cpl;
    if (stack_switch) {
        if (emulator->dos_tr_selector == 0u
            || emulator->dos_tr_limit < 9u + 8u * new_cpl)
            return XXEMUL_STATUS_ADDRESS_FAULT;
        tss_offset = 4u + 8u * new_cpl;
        status = xxemul_x86_guest_memory(emulator,
            emulator->dos_tr_base + tss_offset,
            stack_pointer, sizeof(stack_pointer), 0);
        if (status != XXEMUL_STATUS_OK) return status;
        stack_offset = xxemul_x86_dos_u32(stack_pointer);
        stack_selector = xxemul_x86_dos_u16(stack_pointer + 4u);
        status = xxemul_x86_decode_dos_segment(emulator,
            XXEMUL_X86_SS, stack_selector, emulator->dos_ldtr_selector,
            emulator->dos_ldtr_base, emulator->dos_ldtr_limit,
            &stack_cache);
        if (status != XXEMUL_STATUS_OK) return status;
        if ((stack_selector & 3u) != new_cpl
            || ((stack_cache.access >> 5u) & 3u) != new_cpl)
            return XXEMUL_STATUS_ADDRESS_FAULT;
    }
    stack_mask = (stack_cache.flags & 4u) != 0u
        ? UINT32_MAX : UINT16_MAX;
    frame_size = (stack_switch ? 20u : 12u)
        + (hardware_fault ? 4u : 0u);
    frame_offset = (stack_offset - (uint32_t)frame_size) & stack_mask;
    status = xxemul_x86_dos_stack_address(
        &stack_cache, frame_offset, frame_size, &frame_address);
    if (status != XXEMUL_STATUS_OK) return status;
    if (hardware_fault) xxemul_x86_dos_put_u32(frame, error_code);
    xxemul_x86_dos_put_u32(return_frame, resume_ip);
    xxemul_x86_dos_put_u32(return_frame + 4u,
        emulator->x86.segment[XXEMUL_X86_CS]);
    xxemul_x86_dos_put_u32(return_frame + 8u,
        (uint32_t)emulator->x86.flags);
    if (stack_switch) {
        xxemul_x86_dos_put_u32(return_frame + 12u,
            (uint32_t)emulator->x86.gpr[XXEMUL_X86_RSP]);
        xxemul_x86_dos_put_u32(return_frame + 16u,
            emulator->x86.segment[XXEMUL_X86_SS]);
    }
    status = xxemul_x86_dos_preflight_write(
        emulator, frame_address, frame_size);
    if (status != XXEMUL_STATUS_OK) return status;
    status = xxemul_x86_guest_memory(emulator,
        frame_address, frame, frame_size, 1);
    if (status != XXEMUL_STATUS_OK) return status;

    if (stack_switch) {
        emulator->x86.segment[XXEMUL_X86_SS] = stack_selector;
        emulator->dos_segments[XXEMUL_X86_SS] = stack_cache;
    }
    emulator->x86.gpr[XXEMUL_X86_RSP] = frame_offset;
    emulator->x86.segment[XXEMUL_X86_CS] =
        (uint16_t)((code_selector & ~3u) | new_cpl);
    emulator->dos_segments[XXEMUL_X86_CS] = code_cache;
    emulator->mode = (code_cache.flags & 4u) != 0u
        ? XXEMUL_MODE_X86_32 : XXEMUL_MODE_X86_16;
    emulator->x86.flags &= ~(XXEMUL_X86_FLAG_IF | XXEMUL_X86_FLAG_TF
        | XXEMUL_X86_FLAG_NT | XXEMUL_X86_FLAG_RF);
    *target_ip = code_offset;
    return XXEMUL_STATUS_OK;
}

static xxemul_status xxemul_x86_dos_protected_iret(
    xxemul *emulator, uint8_t width, uint64_t *target_ip)
{
    uint8_t frame[20];
    uint8_t fetch_byte;
    uint32_t stack_mask = (emulator->dos_segments[XXEMUL_X86_SS].flags & 4u)
        != 0u ? UINT32_MAX : UINT16_MAX;
    uint32_t stack_offset =
        (uint32_t)emulator->x86.gpr[XXEMUL_X86_RSP] & stack_mask;
    uint32_t stack_address;
    uint32_t return_offset;
    uint32_t return_stack_offset = 0u;
    uint32_t return_flags;
    uint16_t return_cs;
    uint16_t return_ss = 0u;
    uint8_t old_cpl = emulator->x86.segment[XXEMUL_X86_CS] & 3u;
    uint8_t new_cpl;
    uint8_t dpl;
    size_t frame_size = (size_t)width * 3u;
    xxemul_x86_segment_cache code_cache;
    xxemul_x86_segment_cache stack_cache = {0};
    xxemul_status status;

    if ((emulator->x86.flags & (XXEMUL_X86_FLAG_NT
            | XXEMUL_X86_FLAG_VM)) != 0u)
        return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    status = xxemul_x86_dos_stack_address(
        &emulator->dos_segments[XXEMUL_X86_SS],
        stack_offset, frame_size, &stack_address);
    if (status != XXEMUL_STATUS_OK) return status;
    status = xxemul_x86_guest_memory(emulator,
        stack_address, frame, frame_size, 0);
    if (status != XXEMUL_STATUS_OK) return status;
    return_offset = width == 4u
        ? xxemul_x86_dos_u32(frame) : xxemul_x86_dos_u16(frame);
    return_cs = width == 4u
        ? (uint16_t)xxemul_x86_dos_u32(frame + width)
        : xxemul_x86_dos_u16(frame + width);
    return_flags = width == 4u
        ? xxemul_x86_dos_u32(frame + width * 2u)
        : xxemul_x86_dos_u16(frame + width * 2u);
    new_cpl = return_cs & 3u;
    if (new_cpl < old_cpl) return XXEMUL_STATUS_ADDRESS_FAULT;
    if (new_cpl > old_cpl) {
        frame_size = (size_t)width * 5u;
        status = xxemul_x86_dos_stack_address(
            &emulator->dos_segments[XXEMUL_X86_SS],
            stack_offset, frame_size, &stack_address);
        if (status != XXEMUL_STATUS_OK) return status;
        status = xxemul_x86_guest_memory(emulator,
            stack_address, frame, frame_size, 0);
        if (status != XXEMUL_STATUS_OK) return status;
        return_stack_offset = width == 4u
            ? xxemul_x86_dos_u32(frame + width * 3u)
            : xxemul_x86_dos_u16(frame + width * 3u);
        return_ss = width == 4u
            ? (uint16_t)xxemul_x86_dos_u32(frame + width * 4u)
            : xxemul_x86_dos_u16(frame + width * 4u);
        status = xxemul_x86_decode_dos_segment(emulator,
            XXEMUL_X86_SS, return_ss, emulator->dos_ldtr_selector,
            emulator->dos_ldtr_base, emulator->dos_ldtr_limit,
            &stack_cache);
        if (status != XXEMUL_STATUS_OK) return status;
        if ((return_ss & 3u) != new_cpl
            || ((stack_cache.access >> 5u) & 3u) != new_cpl)
            return XXEMUL_STATUS_ADDRESS_FAULT;
    }
    status = xxemul_x86_decode_dos_segment(emulator,
        XXEMUL_X86_CS, return_cs, emulator->dos_ldtr_selector,
        emulator->dos_ldtr_base, emulator->dos_ldtr_limit, &code_cache);
    if (status != XXEMUL_STATUS_OK) return status;
    dpl = (code_cache.access >> 5u) & 3u;
    if (((code_cache.access & 4u) != 0u
            ? dpl > new_cpl : dpl != new_cpl)
        || return_offset > code_cache.limit)
        return XXEMUL_STATUS_ADDRESS_FAULT;
    status = xxemul_x86_guest_memory(emulator,
        code_cache.base + return_offset, &fetch_byte, 1u, 0);
    if (status != XXEMUL_STATUS_OK) return status;
    if (width == 2u)
        return_flags |= (uint32_t)emulator->x86.flags & 0xffff0000u;
    if ((return_flags & XXEMUL_X86_FLAG_VM) != 0u)
        return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    if (old_cpl != 0u)
        return_flags = (return_flags & ~UINT32_C(0x3000))
            | ((uint32_t)emulator->x86.flags & 0x3000u);
    if (old_cpl > ((emulator->x86.flags >> 12u) & 3u))
        return_flags = (return_flags & ~(uint32_t)XXEMUL_X86_FLAG_IF)
            | ((uint32_t)emulator->x86.flags & XXEMUL_X86_FLAG_IF);

    if (new_cpl > old_cpl) {
        emulator->x86.segment[XXEMUL_X86_SS] = return_ss;
        emulator->dos_segments[XXEMUL_X86_SS] = stack_cache;
        emulator->x86.gpr[XXEMUL_X86_RSP] = return_stack_offset;
    } else {
        emulator->x86.gpr[XXEMUL_X86_RSP] =
            (stack_offset + (uint32_t)frame_size) & stack_mask;
    }
    emulator->x86.segment[XXEMUL_X86_CS] = return_cs;
    emulator->dos_segments[XXEMUL_X86_CS] = code_cache;
    emulator->mode = (code_cache.flags & 4u) != 0u
        ? XXEMUL_MODE_X86_32 : XXEMUL_MODE_X86_16;
    emulator->x86.flags = return_flags | 2u;
    *target_ip = return_offset;
    return XXEMUL_STATUS_OK;
}

static int xxemul_x86_register_view_get(
    cdisasm_x86_reg_id register_id,
    xxemul_x86_register_view *view)
{
    if (view == NULL) {
        return 0;
    }
    view->shift = 0u;
    view->is_ip = 0u;
    view->is_segment = 0u;

    if (register_id >= CDISASM_X86_REG_ES
        && register_id <= CDISASM_X86_REG_GS) {
        view->index = (uint8_t)(register_id - CDISASM_X86_REG_ES);
        view->size = 2u;
        view->is_segment = 1u;
        return 1;
    }

    if (register_id >= CDISASM_X86_REG_AL
        && register_id <= CDISASM_X86_REG_BL) {
        view->index = (uint8_t)(register_id - CDISASM_X86_REG_AL);
        view->size = 1u;
        return 1;
    }
    if (register_id >= CDISASM_X86_REG_AH
        && register_id <= CDISASM_X86_REG_BH) {
        view->index = (uint8_t)(register_id - CDISASM_X86_REG_AH);
        view->size = 1u;
        view->shift = 8u;
        return 1;
    }
    if (register_id >= CDISASM_X86_REG_SPL
        && register_id <= CDISASM_X86_REG_DIL) {
        view->index = (uint8_t)(XXEMUL_X86_RSP
            + register_id - CDISASM_X86_REG_SPL);
        view->size = 1u;
        return 1;
    }
    if (register_id >= CDISASM_X86_REG_R8B
        && register_id <= CDISASM_X86_REG_R15B) {
        view->index = (uint8_t)(XXEMUL_X86_R8
            + register_id - CDISASM_X86_REG_R8B);
        view->size = 1u;
        return 1;
    }
    if (register_id >= CDISASM_X86_REG_AX
        && register_id <= CDISASM_X86_REG_R15W) {
        view->index = (uint8_t)(register_id - CDISASM_X86_REG_AX);
        view->size = 2u;
        return 1;
    }
    if (register_id >= CDISASM_X86_REG_EAX
        && register_id <= CDISASM_X86_REG_R15D) {
        view->index = (uint8_t)(register_id - CDISASM_X86_REG_EAX);
        view->size = 4u;
        return 1;
    }
    if (register_id >= CDISASM_X86_REG_RAX
        && register_id <= CDISASM_X86_REG_R15) {
        view->index = (uint8_t)(register_id - CDISASM_X86_REG_RAX);
        view->size = 8u;
        return 1;
    }
    if (register_id >= CDISASM_X86_REG_IP
        && register_id <= CDISASM_X86_REG_RIP) {
        view->index = 0u;
        view->size = (uint8_t)(2u << (register_id - CDISASM_X86_REG_IP));
        view->is_ip = 1u;
        return 1;
    }
    return 0;
}

static xxemul_status xxemul_x86_read_register(
    const xxemul *emulator,
    cdisasm_x86_reg_id register_id,
    uint64_t next_ip,
    uint64_t *value)
{
    xxemul_x86_register_view view;
    uint64_t raw;

    if (value == NULL) return XXEMUL_STATUS_INVALID_ARGUMENT;
    if (emulator->dos_mode && register_id == CDISASM_X86_REG_CR0) {
        *value = emulator->dos_cr0 | 0x10u;
        return XXEMUL_STATUS_OK;
    }
    if (emulator->dos_mode && register_id == CDISASM_X86_REG_CR2) {
        *value = emulator->dos_cr2;
        return XXEMUL_STATUS_OK;
    }
    if (emulator->dos_mode && register_id == CDISASM_X86_REG_CR3) {
        *value = emulator->dos_cr3;
        return XXEMUL_STATUS_OK;
    }
    if (emulator->dos_mode && register_id >= CDISASM_X86_REG_DR0
        && register_id <= CDISASM_X86_REG_DR7) {
        *value = emulator->dos_dr[register_id - CDISASM_X86_REG_DR0];
        return XXEMUL_STATUS_OK;
    }
    if (!xxemul_x86_register_view_get(register_id, &view)) {
        return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    }
    raw = view.is_ip ? next_ip : (view.is_segment
        ? emulator->x86.segment[view.index] : emulator->x86.gpr[view.index]);
    *value = (raw >> view.shift) & xxemul_mask_for_size(view.size);
    return XXEMUL_STATUS_OK;
}

static xxemul_status xxemul_x86_write_register(
    xxemul *emulator,
    cdisasm_x86_reg_id register_id,
    uint64_t value)
{
    xxemul_x86_register_view view;
    uint64_t mask;
    uint64_t raw;
    uint8_t index;

    if (emulator->dos_mode && register_id == CDISASM_X86_REG_CR0) {
        if ((value & UINT32_C(0x80000001)) == UINT32_C(0x80000000))
            return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
        if ((emulator->dos_cr0 & 1u) == 0u && (value & 1u) != 0u) {
            for (index = 0u; index < 6u; ++index) {
                if (!emulator->dos_segments[index].valid) {
                    xxemul_status status = xxemul_x86_load_dos_segment(
                        emulator, index, emulator->x86.segment[index]);
                    if (status != XXEMUL_STATUS_OK) return status;
                }
            }
        }
        emulator->dos_cr0 = (uint32_t)value | 0x10u;
        return XXEMUL_STATUS_OK;
    }
    if (emulator->dos_mode && register_id == CDISASM_X86_REG_CR3) {
        emulator->dos_cr3 = (uint32_t)value;
        return XXEMUL_STATUS_OK;
    }
    if (emulator->dos_mode && register_id == CDISASM_X86_REG_CR2) {
        emulator->dos_cr2 = (uint32_t)value;
        return XXEMUL_STATUS_OK;
    }
    if (emulator->dos_mode && register_id >= CDISASM_X86_REG_DR0
        && register_id <= CDISASM_X86_REG_DR7) {
        emulator->dos_dr[register_id - CDISASM_X86_REG_DR0]
            = (uint32_t)value;
        return XXEMUL_STATUS_OK;
    }
    if (!xxemul_x86_register_view_get(register_id, &view) || view.is_ip) {
        return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    }
    if (view.is_segment) {
        if (view.index == XXEMUL_X86_CS) {
            return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
        }
        return emulator->dos_mode
            ? xxemul_x86_load_dos_segment(emulator,
                view.index, (uint16_t)value)
            : (emulator->x86.segment[view.index] = (uint16_t)value,
                XXEMUL_STATUS_OK);
    }
    mask = xxemul_mask_for_size(view.size);
    raw = emulator->x86.gpr[view.index];
    if (view.size == 4u && emulator->mode == XXEMUL_MODE_X86_64) {
        emulator->x86.gpr[view.index] = value & mask;
    } else {
        mask <<= view.shift;
        emulator->x86.gpr[view.index] = (raw & ~mask)
            | ((value << view.shift) & mask);
    }
    if (emulator->mode != XXEMUL_MODE_X86_64) {
        emulator->x86.gpr[view.index] &= UINT32_MAX;
    }
    return XXEMUL_STATUS_OK;
}

static int xxemul_x86_parity_even(uint8_t value)
{
    unsigned ones = 0u;
    unsigned bit;

    for (bit = 0u; bit < 8u; ++bit) {
        ones += (value >> bit) & 1u;
    }
    return (ones & 1u) == 0u;
}

static void xxemul_x86_set_szp_flags(
    xxemul *emulator,
    uint64_t result,
    uint8_t size)
{
    uint64_t mask = xxemul_mask_for_size(size);
    uint64_t sign = UINT64_C(1) << (size * 8u - 1u);

    emulator->x86.flags &= ~(XXEMUL_X86_FLAG_SF
        | XXEMUL_X86_FLAG_ZF | XXEMUL_X86_FLAG_PF);
    result &= mask;
    if (result == 0u) {
        emulator->x86.flags |= XXEMUL_X86_FLAG_ZF;
    }
    if ((result & sign) != 0u) {
        emulator->x86.flags |= XXEMUL_X86_FLAG_SF;
    }
    if (xxemul_x86_parity_even((uint8_t)result)) {
        emulator->x86.flags |= XXEMUL_X86_FLAG_PF;
    }
}

static void xxemul_x86_set_logic_flags(
    xxemul *emulator,
    uint64_t result,
    uint8_t size)
{
    emulator->x86.flags &= ~(XXEMUL_X86_FLAG_CF
        | XXEMUL_X86_FLAG_OF | XXEMUL_X86_FLAG_AF);
    xxemul_x86_set_szp_flags(emulator, result, size);
}

static void xxemul_x86_set_add_flags(
    xxemul *emulator,
    uint64_t left,
    uint64_t right,
    uint64_t result,
    uint8_t size)
{
    uint64_t mask = xxemul_mask_for_size(size);
    uint64_t sign = UINT64_C(1) << (size * 8u - 1u);
    uint64_t truncated_left = left & mask;
    uint64_t truncated_right = right & mask;
    uint64_t truncated_result = result & mask;

    emulator->x86.flags &= ~(XXEMUL_X86_FLAG_CF
        | XXEMUL_X86_FLAG_OF | XXEMUL_X86_FLAG_AF);
    if (truncated_result < truncated_left) {
        emulator->x86.flags |= XXEMUL_X86_FLAG_CF;
    }
    if (((~(truncated_left ^ truncated_right)
          & (truncated_left ^ truncated_result)) & sign) != 0u) {
        emulator->x86.flags |= XXEMUL_X86_FLAG_OF;
    }
    if (((truncated_left ^ truncated_right ^ truncated_result)
         & UINT64_C(0x10)) != 0u) {
        emulator->x86.flags |= XXEMUL_X86_FLAG_AF;
    }
    xxemul_x86_set_szp_flags(emulator, truncated_result, size);
}

static void xxemul_x86_set_sub_flags(
    xxemul *emulator,
    uint64_t left,
    uint64_t right,
    uint64_t result,
    uint8_t size)
{
    uint64_t mask = xxemul_mask_for_size(size);
    uint64_t sign = UINT64_C(1) << (size * 8u - 1u);
    uint64_t truncated_left = left & mask;
    uint64_t truncated_right = right & mask;
    uint64_t truncated_result = result & mask;

    emulator->x86.flags &= ~(XXEMUL_X86_FLAG_CF
        | XXEMUL_X86_FLAG_OF | XXEMUL_X86_FLAG_AF);
    if (truncated_left < truncated_right) {
        emulator->x86.flags |= XXEMUL_X86_FLAG_CF;
    }
    if ((((truncated_left ^ truncated_right)
          & (truncated_left ^ truncated_result)) & sign) != 0u) {
        emulator->x86.flags |= XXEMUL_X86_FLAG_OF;
    }
    if (((truncated_left ^ truncated_right ^ truncated_result)
         & UINT64_C(0x10)) != 0u) {
        emulator->x86.flags |= XXEMUL_X86_FLAG_AF;
    }
    xxemul_x86_set_szp_flags(emulator, truncated_result, size);
}

static xxemul_status xxemul_x86_effective_offset(
    xxemul *emulator,
    const cdisasm_x86_instruction *instruction,
    const cdisasm_x86_operand *operand,
    uint64_t next_ip,
    uint64_t *address)
{
    uint64_t result = UINT64_C(0);
    uint64_t value;
    uint64_t displacement = UINT64_C(0);
    uint8_t displacement_size;
    xxemul_status status;

    if (address == NULL || operand->type != CDISASM_OPERAND_MEMORY) {
        return XXEMUL_STATUS_INVALID_ARGUMENT;
    }
    if ((operand->flags & CDISASM_OPERAND_FLAG_HAS_ADDRESS) != 0u) {
        *address = operand->address
            & xxemul_x86_operand_address_mask(emulator, instruction);
        return XXEMUL_STATUS_OK;
    }
    if (operand->base_reg != CDISASM_X86_REG_NONE) {
        status = xxemul_x86_read_register(
            emulator, operand->base_reg, next_ip, &value);
        if (status != XXEMUL_STATUS_OK) {
            return status;
        }
        result += value;
    }
    if (operand->index_reg != CDISASM_X86_REG_NONE) {
        status = xxemul_x86_read_register(
            emulator, operand->index_reg, next_ip, &value);
        if (status != XXEMUL_STATUS_OK) {
            return status;
        }
        result += value * (operand->scale == 0u ? 1u : operand->scale);
    }
    if ((operand->flags & CDISASM_OPERAND_FLAG_HAS_DISPLACEMENT) != 0u) {
        displacement_size = instruction->encoding.displacement_size;
        displacement = displacement_size == 0u ? operand->imm
            : xxemul_sign_extend(operand->imm, displacement_size);
    }
    *address = (result + displacement)
        & xxemul_x86_operand_address_mask(emulator, instruction);
    return XXEMUL_STATUS_OK;
}

static xxemul_status xxemul_x86_effective_address(
    xxemul *emulator,
    const cdisasm_x86_instruction *instruction,
    const cdisasm_x86_operand *operand,
    uint64_t next_ip,
    uint64_t *address)
{
    uint64_t offset;
    uint8_t segment_index = XXEMUL_X86_DS;
    xxemul_status status = xxemul_x86_effective_offset(
        emulator, instruction, operand, next_ip, &offset);

    if (status != XXEMUL_STATUS_OK || !emulator->dos_mode) {
        if (status == XXEMUL_STATUS_OK) {
            *address = offset;
            if (operand->segment_reg == CDISASM_X86_REG_FS
                || operand->segment_reg == CDISASM_X86_REG_GS) {
                segment_index = (uint8_t)(operand->segment_reg
                    - CDISASM_X86_REG_ES);
                if (emulator->windows != NULL) {
                    *address += xxemul_windows_segment_base(
                        emulator->windows, segment_index);
                } else if (emulator->linux_process != NULL) {
                    *address += xxemul_linux_segment_base(
                        emulator->linux_process, segment_index,
                        emulator->x86.segment[segment_index]);
                }
            }
        }
        return status;
    }
    if (operand->segment_reg >= CDISASM_X86_REG_ES
        && operand->segment_reg <= CDISASM_X86_REG_GS) {
        segment_index = (uint8_t)(operand->segment_reg - CDISASM_X86_REG_ES);
    } else if (operand->base_reg == CDISASM_X86_REG_BP
        || operand->base_reg == CDISASM_X86_REG_SP
        || operand->base_reg == CDISASM_X86_REG_EBP
        || operand->base_reg == CDISASM_X86_REG_ESP
        || operand->base_reg == CDISASM_X86_REG_RBP
        || operand->base_reg == CDISASM_X86_REG_RSP) {
        segment_index = XXEMUL_X86_SS;
    }
    return xxemul_x86_dos_address(emulator,
        segment_index, offset, operand->size, address);
}

static xxemul_status xxemul_x86_read_operand_tracked(
    xxemul *emulator,
    const cdisasm_x86_instruction *instruction,
    const cdisasm_x86_operand *operand,
    uint64_t next_ip,
    uint64_t *value,
    uint32_t *page_fault_error)
{
    uint64_t address;
    xxemul_status status;

    if (operand == NULL || value == NULL) {
        return XXEMUL_STATUS_INVALID_ARGUMENT;
    }
    switch (operand->type) {
    case CDISASM_OPERAND_REGISTER:
        return xxemul_x86_read_register(
            emulator, operand->reg, next_ip, value);
    case CDISASM_OPERAND_IMMEDIATE:
        if ((operand->flags & CDISASM_OPERAND_FLAG_PC_RELATIVE) != 0u) {
            *value = operand->imm;
            return XXEMUL_STATUS_OK;
        }
        *value = (operand->flags & CDISASM_OPERAND_FLAG_SIGNED) != 0u
            ? xxemul_sign_extend(operand->imm, operand->size)
            : operand->imm;
        return XXEMUL_STATUS_OK;
    case CDISASM_OPERAND_MEMORY:
        if (operand->size == 0u || operand->size > 8u) {
            return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
        }
        status = xxemul_x86_effective_address(
            emulator, instruction, operand, next_ip, &address);
        return status == XXEMUL_STATUS_OK
            ? xxemul_x86_guest_load_integer_tracked(
                emulator, address, operand->size, value,
                page_fault_error)
            : status;
    default:
        return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    }
}

static xxemul_status xxemul_x86_read_operand(
    xxemul *emulator,
    const cdisasm_x86_instruction *instruction,
    const cdisasm_x86_operand *operand,
    uint64_t next_ip,
    uint64_t *value)
{
    return xxemul_x86_read_operand_tracked(emulator, instruction,
        operand, next_ip, value, NULL);
}

static xxemul_status xxemul_x86_write_operand_tracked(
    xxemul *emulator,
    const cdisasm_x86_instruction *instruction,
    const cdisasm_x86_operand *operand,
    uint64_t next_ip,
    uint64_t value,
    uint32_t *page_fault_error)
{
    uint64_t address;
    xxemul_status status;

    if (operand == NULL) {
        return XXEMUL_STATUS_INVALID_ARGUMENT;
    }
    if (operand->type == CDISASM_OPERAND_REGISTER) {
        return xxemul_x86_write_register(emulator, operand->reg, value);
    }
    if (operand->type != CDISASM_OPERAND_MEMORY
        || operand->size == 0u || operand->size > 8u) {
        return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    }
    status = xxemul_x86_effective_address(
        emulator, instruction, operand, next_ip, &address);
    return status == XXEMUL_STATUS_OK
        ? xxemul_x86_guest_store_integer_tracked(
            emulator, address, operand->size, value,
            page_fault_error)
        : status;
}

static xxemul_status xxemul_x86_write_operand(
    xxemul *emulator,
    const cdisasm_x86_instruction *instruction,
    const cdisasm_x86_operand *operand,
    uint64_t next_ip,
    uint64_t value)
{
    return xxemul_x86_write_operand_tracked(emulator, instruction,
        operand, next_ip, value, NULL);
}

static xxemul_status xxemul_x86_decode_current_tracked(
    xxemul *emulator,
    cdisasm_x86_instruction *instruction,
    uint32_t *page_fault_error)
{
    uint8_t code[15];
    uint64_t fetch_address;
    size_t available;
    uint32_t decoded_size;
    xxemul_x86_decode_cache_entry *cache_entry = NULL;
    xxemul_status status;

    if (emulator->dos_mode) {
        status = xxemul_x86_dos_address(emulator,
            XXEMUL_X86_CS, emulator->x86.ip, 1u, &fetch_address);
        if (status != XXEMUL_STATUS_OK) return status;
    } else {
        fetch_address = emulator->x86.ip;
    }
    emulator->x86_fetching = 1;
    for (available = sizeof(code); available != 0u; --available) {
        status = xxemul_x86_guest_memory_tracked(
            emulator, fetch_address, code, available, 0,
            page_fault_error);
        if (status == XXEMUL_STATUS_OK) break;
    }
    emulator->x86_fetching = 0;
    if (available == 0u) return XXEMUL_STATUS_ADDRESS_FAULT;
    if (emulator->x86_decode_cache == NULL) {
        emulator->x86_decode_cache = (xxemul_x86_decode_cache_entry *)
            xx_mem_calloc(XXEMUL_X86_DECODE_CACHE_SIZE,
                sizeof(*emulator->x86_decode_cache));
    }
    if (emulator->x86_decode_cache != NULL) {
        size_t slot = (size_t)((emulator->x86.ip ^ fetch_address
            ^ (emulator->x86.ip >> 12u))
            & (XXEMUL_X86_DECODE_CACHE_SIZE - 1u));
        cache_entry = &emulator->x86_decode_cache[slot];
        if (cache_entry->valid
            && cache_entry->ip == emulator->x86.ip
            && cache_entry->fetch_address == fetch_address
            && cache_entry->available == available
            && memcmp(cache_entry->code, code, available) == 0) {
            *instruction = cache_entry->instruction;
            return XXEMUL_STATUS_OK;
        }
    }
    decoded_size = cdisasm_x86_decode(
        CDISASM_CPU_X86,
        xxemul_x86_cdisasm_mode(emulator),
        code,
        available,
        emulator->x86.ip,
        &emulator->x86_decode_flags,
        instruction);
    if (decoded_size == 0u && available >= 4u
        && code[0] == 0xf3u && code[1] == 0x0fu
        && code[2] == 0x1eu && (code[3] == 0xfau || code[3] == 0xfbu)) {
        xx_mem_zero(instruction, sizeof(*instruction));
        instruction->address = emulator->x86.ip;
        instruction->opcode_size = 4u;
        instruction->name_id = code[3] == 0xfau
            ? CDISASM_X86_NAME_ENDBR64 : CDISASM_X86_NAME_ENDBR32;
        decoded_size = 4u;
    }
    if (decoded_size == 0u && emulator->mode == XXEMUL_MODE_X86_64
        && available >= 2u && code[0] == 0x0fu && code[1] == 0x05u) {
        xx_mem_zero(instruction, sizeof(*instruction));
        instruction->address = emulator->x86.ip;
        instruction->opcode_size = 2u;
        instruction->name_id = CDISASM_X86_NAME_SYSCALL;
        decoded_size = 2u;
    }
    if (decoded_size == 0u) {
        if (emulator->dos_mode && page_fault_error != NULL
            && available < sizeof(code)) {
            uint32_t missing_page_error = UINT32_MAX;
            status = xxemul_x86_guest_memory_tracked(emulator,
                fetch_address, code, available + 1u, 0,
                &missing_page_error);
            if (status == XXEMUL_STATUS_ADDRESS_FAULT
                && missing_page_error != UINT32_MAX) {
                *page_fault_error = missing_page_error;
                return status;
            }
        }
        return XXEMUL_STATUS_DECODE_ERROR;
    }
    if (cache_entry != NULL) {
        cache_entry->ip = emulator->x86.ip;
        cache_entry->fetch_address = fetch_address;
        cache_entry->available = (uint8_t)available;
        memcpy(cache_entry->code, code, available);
        cache_entry->instruction = *instruction;
        cache_entry->valid = 1u;
    }
    return XXEMUL_STATUS_OK;
}

static xxemul_status xxemul_x86_decode_current(
    xxemul *emulator, cdisasm_x86_instruction *instruction)
{
    return xxemul_x86_decode_current_tracked(emulator, instruction, NULL);
}

static xxemul_status xxemul_x86_push_width_tracked(
    xxemul *emulator, uint64_t value, uint8_t size,
    uint32_t *page_fault_error)
{
    uint64_t mask = xxemul_x86_stack_mask(emulator);
    uint64_t stack_pointer = (emulator->x86.gpr[XXEMUL_X86_RSP] - size) & mask;
    uint64_t address = stack_pointer;
    xxemul_status status;

    if (emulator->dos_mode) {
        status = xxemul_x86_dos_address(emulator,
            XXEMUL_X86_SS, stack_pointer, size, &address);
        if (status != XXEMUL_STATUS_OK) return status;
    }
    status = xxemul_x86_guest_store_integer_tracked(
        emulator, address, size, value, page_fault_error);

    if (status == XXEMUL_STATUS_OK) {
        emulator->x86.gpr[XXEMUL_X86_RSP] = stack_pointer;
    }
    return status;
}

static xxemul_status xxemul_x86_push_width(
    xxemul *emulator, uint64_t value, uint8_t size)
{
    return xxemul_x86_push_width_tracked(emulator, value, size, NULL);
}

static xxemul_status xxemul_x86_pop_width_tracked(
    xxemul *emulator, uint64_t *value, uint8_t size,
    uint32_t *page_fault_error)
{
    uint64_t mask = xxemul_x86_stack_mask(emulator);
    uint64_t stack_pointer = emulator->x86.gpr[XXEMUL_X86_RSP] & mask;
    uint64_t address = stack_pointer;
    xxemul_status status;

    if (emulator->dos_mode) {
        status = xxemul_x86_dos_address(emulator,
            XXEMUL_X86_SS, stack_pointer, size, &address);
        if (status != XXEMUL_STATUS_OK) return status;
    }
    status = xxemul_x86_guest_load_integer_tracked(
        emulator, address, size, value, page_fault_error);

    if (status == XXEMUL_STATUS_OK) {
        emulator->x86.gpr[XXEMUL_X86_RSP] = (stack_pointer + size) & mask;
    }
    return status;
}

static xxemul_status xxemul_x86_pop_width(
    xxemul *emulator, uint64_t *value, uint8_t size)
{
    return xxemul_x86_pop_width_tracked(emulator, value, size, NULL);
}

static xxemul_status xxemul_x86_push(xxemul *emulator, uint64_t value)
{
    return xxemul_x86_push_width(
        emulator, value, xxemul_x86_mode_size(emulator));
}

static xxemul_status xxemul_x86_pop(xxemul *emulator, uint64_t *value)
{
    return xxemul_x86_pop_width(
        emulator, value, xxemul_x86_mode_size(emulator));
}

static void xxemul_x86_multiply_u64(
    uint64_t left, uint64_t right, uint64_t *low, uint64_t *high)
{
    uint64_t lo_lo = (uint32_t)left * (uint64_t)(uint32_t)right;
    uint64_t lo_hi = (uint32_t)left * (right >> 32u);
    uint64_t hi_lo = (left >> 32u) * (uint32_t)right;
    uint64_t hi_hi = (left >> 32u) * (right >> 32u);
    uint64_t middle = (lo_lo >> 32u)
        + (uint32_t)lo_hi + (uint32_t)hi_lo;
    *low = (lo_lo & UINT32_MAX) | (middle << 32u);
    *high = hi_hi + (lo_hi >> 32u) + (hi_lo >> 32u)
        + (middle >> 32u);
}

static int xxemul_x86_divide_u128(uint64_t high, uint64_t low,
    uint64_t divisor, uint64_t *quotient, uint64_t *remainder)
{
    unsigned bit;
    if (divisor == 0u || high >= divisor) return 0;
    *quotient = 0u;
    *remainder = high;
    for (bit = 64u; bit != 0u; --bit) {
        uint64_t carry = *remainder >> 63u;
        *remainder = (*remainder << 1u)
            | ((low >> (bit - 1u)) & 1u);
        if (carry != 0u || *remainder >= divisor) {
            *remainder -= divisor;
            *quotient |= UINT64_C(1) << (bit - 1u);
        }
    }
    return 1;
}

static int xxemul_x86_branch_condition(
    const xxemul *emulator,
    cdisasm_x86_name_id name_id)
{
    int cf = (emulator->x86.flags & XXEMUL_X86_FLAG_CF) != 0u;
    int pf = (emulator->x86.flags & XXEMUL_X86_FLAG_PF) != 0u;
    int zf = (emulator->x86.flags & XXEMUL_X86_FLAG_ZF) != 0u;
    int sf = (emulator->x86.flags & XXEMUL_X86_FLAG_SF) != 0u;
    int of = (emulator->x86.flags & XXEMUL_X86_FLAG_OF) != 0u;

    switch (name_id) {
    case CDISASM_X86_NAME_JO:
    case CDISASM_X86_NAME_CMOVO:
    case CDISASM_X86_NAME_SETO: return of;
    case CDISASM_X86_NAME_JNO:
    case CDISASM_X86_NAME_CMOVNO:
    case CDISASM_X86_NAME_SETNO: return !of;
    case CDISASM_X86_NAME_JB:
    case CDISASM_X86_NAME_CMOVB:
    case CDISASM_X86_NAME_SETB: return cf;
    case CDISASM_X86_NAME_JAE:
    case CDISASM_X86_NAME_CMOVAE:
    case CDISASM_X86_NAME_SETAE: return !cf;
    case CDISASM_X86_NAME_JE:
    case CDISASM_X86_NAME_CMOVE:
    case CDISASM_X86_NAME_SETE: return zf;
    case CDISASM_X86_NAME_JNE:
    case CDISASM_X86_NAME_CMOVNE:
    case CDISASM_X86_NAME_SETNE: return !zf;
    case CDISASM_X86_NAME_JBE:
    case CDISASM_X86_NAME_CMOVBE:
    case CDISASM_X86_NAME_SETBE: return cf || zf;
    case CDISASM_X86_NAME_JA:
    case CDISASM_X86_NAME_CMOVA:
    case CDISASM_X86_NAME_SETA: return !cf && !zf;
    case CDISASM_X86_NAME_JS:
    case CDISASM_X86_NAME_CMOVS:
    case CDISASM_X86_NAME_SETS: return sf;
    case CDISASM_X86_NAME_JNS:
    case CDISASM_X86_NAME_CMOVNS:
    case CDISASM_X86_NAME_SETNS: return !sf;
    case CDISASM_X86_NAME_JP:
    case CDISASM_X86_NAME_CMOVP:
    case CDISASM_X86_NAME_SETP: return pf;
    case CDISASM_X86_NAME_JNP:
    case CDISASM_X86_NAME_CMOVNP:
    case CDISASM_X86_NAME_SETNP: return !pf;
    case CDISASM_X86_NAME_JL:
    case CDISASM_X86_NAME_CMOVL:
    case CDISASM_X86_NAME_SETL: return sf != of;
    case CDISASM_X86_NAME_JGE:
    case CDISASM_X86_NAME_CMOVGE:
    case CDISASM_X86_NAME_SETGE: return sf == of;
    case CDISASM_X86_NAME_JLE:
    case CDISASM_X86_NAME_CMOVLE:
    case CDISASM_X86_NAME_SETLE: return zf || sf != of;
    case CDISASM_X86_NAME_JG:
    case CDISASM_X86_NAME_CMOVG:
    case CDISASM_X86_NAME_SETG: return !zf && sf == of;
    case CDISASM_X86_NAME_JCXZ:
        return (emulator->x86.gpr[XXEMUL_X86_RCX] & UINT16_MAX) == 0u;
    case CDISASM_X86_NAME_JECXZ:
        return (emulator->x86.gpr[XXEMUL_X86_RCX] & UINT32_MAX) == 0u;
    case CDISASM_X86_NAME_JRCXZ:
        return emulator->x86.gpr[XXEMUL_X86_RCX] == 0u;
    default:
        return -1;
    }
}

static xxemul_status xxemul_x86_branch_target_tracked(
    xxemul *emulator,
    const cdisasm_x86_instruction *instruction,
    uint64_t next_ip,
    uint64_t *target,
    uint32_t *page_fault_error)
{
    if (target == NULL) {
        return XXEMUL_STATUS_INVALID_ARGUMENT;
    }
    if (instruction->operand_count == 0u) {
        *target = instruction->branch_target;
        return XXEMUL_STATUS_OK;
    }
    return xxemul_x86_read_operand_tracked(emulator, instruction,
        &instruction->opcode[0], next_ip, target, page_fault_error);
}

static xxemul_status xxemul_x86_branch_target(
    xxemul *emulator,
    const cdisasm_x86_instruction *instruction,
    uint64_t next_ip,
    uint64_t *target)
{
    return xxemul_x86_branch_target_tracked(emulator, instruction,
        next_ip, target, NULL);
}

static xxemul_status xxemul_x86_binary(
    xxemul *emulator,
    const cdisasm_x86_instruction *instruction,
    uint64_t next_ip,
    cdisasm_x86_name_id operation,
    uint32_t *page_fault_error)
{
    const cdisasm_x86_operand *destination;
    uint64_t left;
    uint64_t right;
    uint64_t result;
    uint64_t mask;
    uint8_t size;
    xxemul_status status;

    if (instruction->operand_count < 2u) {
        return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    }
    destination = &instruction->opcode[0];
    size = destination->size;
    if (size == 0u || size > 8u) {
        return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    }
    status = xxemul_x86_read_operand_tracked(emulator, instruction,
        destination, next_ip, &left, page_fault_error);
    if (status != XXEMUL_STATUS_OK) {
        return status;
    }
    status = xxemul_x86_read_operand_tracked(emulator, instruction,
        &instruction->opcode[1], next_ip, &right, page_fault_error);
    if (status != XXEMUL_STATUS_OK) {
        return status;
    }
    mask = xxemul_mask_for_size(size);

    switch (operation) {
    case CDISASM_X86_NAME_ADC:
    case CDISASM_X86_NAME_SBB:
        {
            uint64_t sign = UINT64_C(1) << (size * 8u - 1u);
            uint64_t carry_in = (emulator->x86.flags & XXEMUL_X86_FLAG_CF)
                != 0u ? 1u : 0u;
            int carry_out;
            int overflow;
            left &= mask;
            right &= mask;
            if (operation == CDISASM_X86_NAME_ADC) {
                result = (left + right + carry_in) & mask;
                carry_out = result < left
                    || (carry_in != 0u && result == left);
                overflow = ((~(left ^ right) & (left ^ result))
                    & (UINT64_C(1) << (size * 8u - 1u))) != 0u;
            } else {
                result = (left - right - carry_in) & mask;
                carry_out = left < right
                    || (carry_in != 0u && left == right);
                overflow = (((left ^ right) & (left ^ result))
                    & sign) != 0u;
            }
            status = xxemul_x86_write_operand(emulator, instruction,
                destination, next_ip, result);
            if (status != XXEMUL_STATUS_OK) return status;
            emulator->x86.flags &= ~(XXEMUL_X86_FLAG_CF
                | XXEMUL_X86_FLAG_OF | XXEMUL_X86_FLAG_AF);
            if (carry_out) emulator->x86.flags |= XXEMUL_X86_FLAG_CF;
            if (overflow) emulator->x86.flags |= XXEMUL_X86_FLAG_OF;
            if (((left ^ right ^ result) & UINT64_C(0x10)) != 0u) {
                emulator->x86.flags |= XXEMUL_X86_FLAG_AF;
            }
            xxemul_x86_set_szp_flags(emulator, result, size);
            return XXEMUL_STATUS_OK;
        }
    case CDISASM_X86_NAME_ADD:
        result = (left + right) & mask;
        status = xxemul_x86_write_operand(
            emulator, instruction, destination, next_ip, result);
        if (status == XXEMUL_STATUS_OK) {
            xxemul_x86_set_add_flags(emulator, left, right, result, size);
        }
        return status;
    case CDISASM_X86_NAME_SUB:
    case CDISASM_X86_NAME_CMP:
        result = (left - right) & mask;
        if (operation == CDISASM_X86_NAME_SUB) {
            status = xxemul_x86_write_operand(
                emulator, instruction, destination, next_ip, result);
            if (status != XXEMUL_STATUS_OK) {
                return status;
            }
        }
        xxemul_x86_set_sub_flags(emulator, left, right, result, size);
        return XXEMUL_STATUS_OK;
    case CDISASM_X86_NAME_AND:
    case CDISASM_X86_NAME_TEST:
        result = (left & right) & mask;
        if (operation == CDISASM_X86_NAME_AND) {
            status = xxemul_x86_write_operand(
                emulator, instruction, destination, next_ip, result);
            if (status != XXEMUL_STATUS_OK) {
                return status;
            }
        }
        xxemul_x86_set_logic_flags(emulator, result, size);
        return XXEMUL_STATUS_OK;
    case CDISASM_X86_NAME_OR:
        result = (left | right) & mask;
        status = xxemul_x86_write_operand(
            emulator, instruction, destination, next_ip, result);
        if (status == XXEMUL_STATUS_OK) {
            xxemul_x86_set_logic_flags(emulator, result, size);
        }
        return status;
    case CDISASM_X86_NAME_XOR:
        result = (left ^ right) & mask;
        status = xxemul_x86_write_operand(
            emulator, instruction, destination, next_ip, result);
        if (status == XXEMUL_STATUS_OK) {
            xxemul_x86_set_logic_flags(emulator, result, size);
        }
        return status;
    default:
        return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    }
}

static xxemul_status xxemul_x86_shift(
    xxemul *emulator,
    const cdisasm_x86_instruction *instruction,
    uint64_t next_ip)
{
    uint64_t value;
    uint64_t count_value;
    uint64_t mask;
    uint64_t sign;
    unsigned bits;
    unsigned count;
    unsigned index;
    int carry = 0;
    int original_sign;
    xxemul_status status;

    if (instruction->operand_count < 2u) {
        return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    }
    bits = (unsigned)instruction->opcode[0].size * 8u;
    if (bits < 8u || bits > 64u) {
        return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    }
    status = xxemul_x86_read_operand(emulator, instruction,
        &instruction->opcode[0], next_ip, &value);
    if (status != XXEMUL_STATUS_OK) return status;
    status = xxemul_x86_read_operand(emulator, instruction,
        &instruction->opcode[1], next_ip, &count_value);
    if (status != XXEMUL_STATUS_OK) return status;
    count = (unsigned)count_value & (bits == 64u ? 63u : 31u);
    if (instruction->name_id == CDISASM_X86_NAME_ROL
        || instruction->name_id == CDISASM_X86_NAME_ROR) {
        count %= bits;
    }
    if (count == 0u) return XXEMUL_STATUS_OK;

    mask = xxemul_mask_for_size(instruction->opcode[0].size);
    sign = UINT64_C(1) << (bits - 1u);
    value &= mask;
    original_sign = (value & sign) != 0u;
    for (index = 0u; index < count; ++index) {
        switch (instruction->name_id) {
        case CDISASM_X86_NAME_SHL:
        case CDISASM_X86_NAME_ROL:
            carry = (value & sign) != 0u;
            value = ((value << 1u)
                | (instruction->name_id == CDISASM_X86_NAME_ROL
                    ? (uint64_t)carry : UINT64_C(0))) & mask;
            break;
        case CDISASM_X86_NAME_SHR:
        case CDISASM_X86_NAME_ROR:
            carry = (value & 1u) != 0u;
            value = (value >> 1u)
                | (instruction->name_id == CDISASM_X86_NAME_ROR
                    ? ((uint64_t)carry << (bits - 1u)) : UINT64_C(0));
            break;
        case CDISASM_X86_NAME_SAR:
            carry = (value & 1u) != 0u;
            value = (value >> 1u) | (value & sign);
            break;
        default:
            return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
        }
    }
    status = xxemul_x86_write_operand(emulator, instruction,
        &instruction->opcode[0], next_ip, value);
    if (status != XXEMUL_STATUS_OK) return status;
    emulator->x86.flags = (emulator->x86.flags & ~XXEMUL_X86_FLAG_CF)
        | (carry ? XXEMUL_X86_FLAG_CF : 0u);
    if (instruction->name_id != CDISASM_X86_NAME_ROL
        && instruction->name_id != CDISASM_X86_NAME_ROR) {
        xxemul_x86_set_szp_flags(emulator, value,
            instruction->opcode[0].size);
    }
    if (count == 1u) {
        int overflow = 0;
        if (instruction->name_id == CDISASM_X86_NAME_SHL
            || instruction->name_id == CDISASM_X86_NAME_ROL) {
            overflow = ((value & sign) != 0u) != carry;
        } else if (instruction->name_id == CDISASM_X86_NAME_SHR) {
            overflow = original_sign;
        } else if (instruction->name_id == CDISASM_X86_NAME_ROR) {
            overflow = ((value & sign) != 0u)
                != ((value & (sign >> 1u)) != 0u);
        }
        emulator->x86.flags = (emulator->x86.flags & ~XXEMUL_X86_FLAG_OF)
            | (overflow ? XXEMUL_X86_FLAG_OF : 0u);
    }
    return XXEMUL_STATUS_OK;
}

static xxemul_status xxemul_x86_dos_page_fault(
    xxemul *emulator, xxemul_status status, uint32_t page_fault_error,
    uint64_t current_ip, uint64_t *next_ip)
{
    if (status == XXEMUL_STATUS_ADDRESS_FAULT
        && page_fault_error != UINT32_MAX
        && emulator->dos_mode && (emulator->dos_cr0 & 1u) != 0u) {
        emulator->dos_pending_page_fault_error = UINT32_MAX;
        return xxemul_x86_dos_interrupt_gate(emulator, 14u,
            (uint32_t)current_ip, 1, page_fault_error, next_ip);
    }
    return status;
}

xxemul_status xxemul_x86_dispatch_pending_page_fault(
    xxemul *emulator, xxemul_step_info *info, uint64_t fault_ip)
{
    uint64_t fault_address;
    uint64_t next_ip;
    uint32_t error;
    xxemul_status status;

    if (emulator == NULL || !emulator->dos_mode
        || (emulator->dos_cr0 & 1u) == 0u
        || emulator->dos_pending_page_fault_error == UINT32_MAX) {
        return XXEMUL_STATUS_ADDRESS_FAULT;
    }
    error = emulator->dos_pending_page_fault_error;
    emulator->dos_pending_page_fault_error = UINT32_MAX;
    fault_address = (uint64_t)emulator->dos_segments[XXEMUL_X86_CS].base
        + fault_ip;
    status = xxemul_x86_dos_interrupt_gate(emulator, 14u,
        (uint32_t)fault_ip, 1, error, &next_ip);
    if (status != XXEMUL_STATUS_OK) {
        return status;
    }
    emulator->x86.ip = next_ip;
    emulator->x86.flags |= UINT64_C(2);
    if (info != NULL) {
        info->address = fault_address;
        info->next_address =
            (uint64_t)emulator->dos_segments[XXEMUL_X86_CS].base
                + next_ip;
    }
    return XXEMUL_STATUS_OK;
}

static xxemul_status xxemul_x86_dos_stack_fault(
    xxemul *emulator, xxemul_status status, uint32_t page_fault_error,
    uint64_t original_sp, uint64_t current_ip, uint64_t *next_ip)
{
    if (status != XXEMUL_STATUS_OK)
        emulator->x86.gpr[XXEMUL_X86_RSP] = original_sp;
    return xxemul_x86_dos_page_fault(emulator, status,
        page_fault_error, current_ip, next_ip);
}

static xxemul_status xxemul_x86_string(
    xxemul *emulator,
    const cdisasm_x86_instruction *instruction,
    uint64_t current_ip,
    uint64_t *next_ip)
{
    uint8_t element_size;
    uint8_t address_size = xxemul_x86_mode_size(emulator);
    uint64_t address_mask;
    uint64_t count;
    uint64_t iterations;
    uint64_t index;
    uint32_t repeat = instruction->opcode_flags
        & (CDISASM_PREFIX_REP | CDISASM_PREFIX_REPNE);
    int operation;

    switch (instruction->name_id) {
    case CDISASM_X86_NAME_MOVSB: element_size = 1u; operation = 0; break;
    case CDISASM_X86_NAME_MOVSW: element_size = 2u; operation = 0; break;
    case CDISASM_X86_NAME_MOVSD: element_size = 4u; operation = 0; break;
    case CDISASM_X86_NAME_MOVSQ: element_size = 8u; operation = 0; break;
    case CDISASM_X86_NAME_STOSB: element_size = 1u; operation = 1; break;
    case CDISASM_X86_NAME_STOSW: element_size = 2u; operation = 1; break;
    case CDISASM_X86_NAME_STOSD: element_size = 4u; operation = 1; break;
    case CDISASM_X86_NAME_STOSQ: element_size = 8u; operation = 1; break;
    case CDISASM_X86_NAME_LODSB: element_size = 1u; operation = 2; break;
    case CDISASM_X86_NAME_LODSW: element_size = 2u; operation = 2; break;
    case CDISASM_X86_NAME_LODSD: element_size = 4u; operation = 2; break;
    case CDISASM_X86_NAME_LODSQ: element_size = 8u; operation = 2; break;
    case CDISASM_X86_NAME_CMPSB: element_size = 1u; operation = 3; break;
    case CDISASM_X86_NAME_CMPSW: element_size = 2u; operation = 3; break;
    case CDISASM_X86_NAME_CMPSD: element_size = 4u; operation = 3; break;
    case CDISASM_X86_NAME_CMPSQ: element_size = 8u; operation = 3; break;
    case CDISASM_X86_NAME_SCASB: element_size = 1u; operation = 4; break;
    case CDISASM_X86_NAME_SCASW: element_size = 2u; operation = 4; break;
    case CDISASM_X86_NAME_SCASD: element_size = 4u; operation = 4; break;
    case CDISASM_X86_NAME_SCASQ: element_size = 8u; operation = 4; break;
    default: return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    }
    if (instruction->operand_count == 0u
        || (operation <= 1 && instruction->opcode[0].type
            != CDISASM_OPERAND_MEMORY)) {
        return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    }
    if ((instruction->opcode_flags & CDISASM_PREFIX_ADDRESS_SIZE) != 0u) {
        address_size = emulator->mode == XXEMUL_MODE_X86_16 ? 4u
            : emulator->mode == XXEMUL_MODE_X86_32 ? 2u : 4u;
    }
    address_mask = xxemul_mask_for_size(address_size);
    count = repeat != 0u
        ? emulator->x86.gpr[XXEMUL_X86_RCX] & address_mask : 1u;
    iterations = count > UINT64_C(65536) ? UINT64_C(65536) : count;

    for (index = 0u; index < iterations; ++index) {
        uint64_t source_offset = emulator->x86.gpr[XXEMUL_X86_RSI]
            & address_mask;
        uint64_t destination_offset = emulator->x86.gpr[XXEMUL_X86_RDI]
            & address_mask;
        uint64_t source_address = source_offset;
        uint64_t destination_address = destination_offset;
        uint64_t source = 0u;
        uint64_t destination = 0u;
        uint64_t accumulator = emulator->x86.gpr[XXEMUL_X86_RAX]
            & xxemul_mask_for_size(element_size);
        uint32_t page_fault_error = UINT32_MAX;
        xxemul_status status;

        if (emulator->dos_mode) {
            uint8_t source_segment = XXEMUL_X86_DS;
            const cdisasm_x86_operand *source_operand =
                operation == 2 ? &instruction->opcode[0]
                : &instruction->opcode[1];
            if (source_operand->segment_reg >= CDISASM_X86_REG_ES
                && source_operand->segment_reg <= CDISASM_X86_REG_GS) {
                source_segment = (uint8_t)(
                    source_operand->segment_reg - CDISASM_X86_REG_ES);
            }
            if (operation == 0 || operation == 2 || operation == 3) {
                status = xxemul_x86_dos_address(emulator, source_segment,
                    source_offset, element_size, &source_address);
                if (status != XXEMUL_STATUS_OK) return status;
            }
            if (operation != 2) {
                status = xxemul_x86_dos_address(emulator, XXEMUL_X86_ES,
                    destination_offset, element_size, &destination_address);
                if (status != XXEMUL_STATUS_OK) return status;
            }
        }
        if (operation == 0 || operation == 2 || operation == 3) {
            status = xxemul_x86_guest_load_integer_tracked(emulator,
                source_address, element_size, &source, &page_fault_error);
            if (status != XXEMUL_STATUS_OK)
                return xxemul_x86_dos_page_fault(emulator, status,
                    page_fault_error, current_ip, next_ip);
        }
        if (operation == 3 || operation == 4) {
            status = xxemul_x86_guest_load_integer_tracked(emulator,
                destination_address, element_size, &destination,
                &page_fault_error);
            if (status != XXEMUL_STATUS_OK)
                return xxemul_x86_dos_page_fault(emulator, status,
                    page_fault_error, current_ip, next_ip);
        }
        if (operation == 0 || operation == 1) {
            status = xxemul_x86_guest_store_integer_tracked(emulator,
                destination_address, element_size,
                operation == 0 ? source : accumulator, &page_fault_error);
            if (status != XXEMUL_STATUS_OK)
                return xxemul_x86_dos_page_fault(emulator, status,
                    page_fault_error, current_ip, next_ip);
        } else if (operation == 2) {
            uint64_t mask = xxemul_mask_for_size(element_size);
            emulator->x86.gpr[XXEMUL_X86_RAX] =
                (emulator->x86.gpr[XXEMUL_X86_RAX] & ~mask) | source;
            if (element_size == 4u
                && emulator->mode == XXEMUL_MODE_X86_64) {
                emulator->x86.gpr[XXEMUL_X86_RAX] &= UINT32_MAX;
            }
        } else {
            uint64_t left = operation == 3 ? source : accumulator;
            uint64_t right = destination;
            uint64_t result = (left - right)
                & xxemul_mask_for_size(element_size);
            xxemul_x86_set_sub_flags(emulator, left, right,
                result, element_size);
        }
        if (operation == 0 || operation == 2 || operation == 3) {
            uint64_t original = emulator->x86.gpr[XXEMUL_X86_RSI];
            uint64_t updated = (source_offset
                + ((emulator->x86.flags & XXEMUL_X86_FLAG_DF) != 0u
                    ? UINT64_C(0) - element_size : (uint64_t)element_size))
                & address_mask;
            emulator->x86.gpr[XXEMUL_X86_RSI] =
                (address_size == 4u && emulator->mode == XXEMUL_MODE_X86_64)
                    ? updated : (original & ~address_mask) | updated;
        }
        if (operation == 0 || operation == 1 || operation == 3
            || operation == 4) {
            uint64_t original = emulator->x86.gpr[XXEMUL_X86_RDI];
            uint64_t updated = (destination_offset
                + ((emulator->x86.flags & XXEMUL_X86_FLAG_DF) != 0u
                    ? UINT64_C(0) - element_size : (uint64_t)element_size))
                & address_mask;
            emulator->x86.gpr[XXEMUL_X86_RDI] =
                (address_size == 4u && emulator->mode == XXEMUL_MODE_X86_64)
                    ? updated : (original & ~address_mask) | updated;
        }
        if (repeat != 0u) {
            --count;
            emulator->x86.gpr[XXEMUL_X86_RCX] =
                (emulator->x86.gpr[XXEMUL_X86_RCX] & ~address_mask)
                | (count & address_mask);
            if ((operation == 3 || operation == 4) && count != 0u) {
                int zero = (emulator->x86.flags & XXEMUL_X86_FLAG_ZF) != 0u;
                if (((repeat & CDISASM_PREFIX_REP) != 0u && !zero)
                    || ((repeat & CDISASM_PREFIX_REPNE) != 0u && zero)) {
                    break;
                }
            }
        }
    }
    if (repeat != 0u && count != 0u
        && index == iterations) {
        *next_ip = current_ip;
    }
    return XXEMUL_STATUS_OK;
}

static xxemul_status xxemul_x87_push(xxemul *emulator, double value)
{
    size_t index;
    if (emulator->x87_depth == 8u)
        return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    for (index = emulator->x87_depth; index != 0u; --index) {
        emulator->x87_stack[index] = emulator->x87_stack[index - 1u];
        emulator->x87_int_val[index] = emulator->x87_int_val[index - 1u];
        emulator->x87_is_int[index] = emulator->x87_is_int[index - 1u];
    }
    emulator->x87_stack[0] = value;
    emulator->x87_int_val[0] = 0;
    emulator->x87_is_int[0] = 0;
    ++emulator->x87_depth;
    emulator->x87_top = (uint8_t)((emulator->x87_top - 1u) & 7u);
    return XXEMUL_STATUS_OK;
}

static xxemul_status xxemul_x87_push_int(xxemul *emulator, uint64_t int_val, uint8_t size)
{
    size_t index;
    uint64_t sign_ext = xxemul_sign_extend(int_val, size);
    if (emulator->x87_depth == 8u)
        return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    for (index = emulator->x87_depth; index != 0u; --index) {
        emulator->x87_stack[index] = emulator->x87_stack[index - 1u];
        emulator->x87_int_val[index] = emulator->x87_int_val[index - 1u];
        emulator->x87_is_int[index] = emulator->x87_is_int[index - 1u];
    }
    emulator->x87_stack[0] = (double)(int64_t)sign_ext;
    emulator->x87_int_val[0] = sign_ext;
    emulator->x87_is_int[0] = 1;
    ++emulator->x87_depth;
    emulator->x87_top = (uint8_t)((emulator->x87_top - 1u) & 7u);
    return XXEMUL_STATUS_OK;
}

static xxemul_status xxemul_x87_pop(xxemul *emulator)
{
    size_t index;
    if (emulator->x87_depth == 0u)
        return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    for (index = 1u; index < emulator->x87_depth; ++index) {
        emulator->x87_stack[index - 1u] = emulator->x87_stack[index];
        emulator->x87_int_val[index - 1u] = emulator->x87_int_val[index];
        emulator->x87_is_int[index - 1u] = emulator->x87_is_int[index];
    }
    --emulator->x87_depth;
    emulator->x87_top = (uint8_t)((emulator->x87_top + 1u) & 7u);
    return XXEMUL_STATUS_OK;
}

static xxemul_status xxemul_x87_read(
    xxemul *emulator, const cdisasm_x86_instruction *instruction,
    const cdisasm_opcode *operand, uint64_t next_ip, double *value,
    uint32_t *page_fault_error)
{
    uint64_t bits;
    xxemul_status status;
    if (operand->type == CDISASM_OPERAND_REGISTER
        && operand->reg >= CDISASM_X86_REG_ST0
        && operand->reg <= CDISASM_X86_REG_ST7) {
        size_t index = (size_t)(operand->reg - CDISASM_X86_REG_ST0);
        if (index >= emulator->x87_depth)
            return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
        *value = emulator->x87_stack[index];
        return XXEMUL_STATUS_OK;
    }
    if (operand->type != CDISASM_OPERAND_MEMORY
        || (operand->size != 4u && operand->size != 8u))
        return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    status = xxemul_x86_read_operand_tracked(
        emulator, instruction, operand, next_ip, &bits,
        page_fault_error);
    if (status != XXEMUL_STATUS_OK) return status;
    if (operand->size == 4u) {
        uint32_t bits32 = (uint32_t)bits;
        float value32;
        memcpy(&value32, &bits32, sizeof(value32));
        *value = value32;
    } else {
        memcpy(value, &bits, sizeof(*value));
    }
    return XXEMUL_STATUS_OK;
}

static uint64_t xxemul_x87_convert_to_integer(
    xxemul *emulator, double val, size_t size, int truncate_mode)
{
    double rounded;
    if (isnan(val) || isinf(val)) {
        emulator->x87_status |= 0x0001u; /* IE */
        if (size == 2u) return UINT64_C(0x8000);
        if (size == 4u) return UINT64_C(0x80000000);
        return UINT64_C(0x8000000000000000);
    }

    if (truncate_mode) {
        rounded = trunc(val);
    } else {
        switch ((emulator->x87_control >> 10) & 3u) {
        case 0: /* Round to nearest (even) */
            rounded = nearbyint(val);
            break;
        case 1: /* Round down (-inf) */
            rounded = floor(val);
            break;
        case 2: /* Round up (+inf) */
            rounded = ceil(val);
            break;
        case 3: /* Truncate */
        default:
            rounded = trunc(val);
            break;
        }
    }

    if (size == 2u) {
        if (rounded < -32768.0 || rounded > 32767.0) {
            emulator->x87_status |= 0x0001u; /* IE */
            return UINT64_C(0x8000);
        }
        return (uint16_t)(int16_t)rounded;
    } else if (size == 4u) {
        if (rounded < -2147483648.0 || rounded > 2147483647.0) {
            emulator->x87_status |= 0x0001u; /* IE */
            return UINT64_C(0x80000000);
        }
        return (uint32_t)(int32_t)rounded;
    } else {
        if (rounded < -9223372036854775808.0 || rounded >= 9223372036854775808.0) {
            emulator->x87_status |= 0x0001u; /* IE */
            return UINT64_C(0x8000000000000000);
        }
        return (uint64_t)(int64_t)rounded;
    }
}

static xxemul_status xxemul_x86_read_xmm_operand(
    xxemul *emulator, const cdisasm_x86_instruction *instruction,
    const cdisasm_x86_operand *operand, uint64_t next_ip,
    uint8_t bytes[16])
{
    uint64_t address;
    xxemul_status status;
    if (operand->size != 16u)
        return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    if (operand->type == CDISASM_OPERAND_REGISTER
        && operand->reg >= CDISASM_X86_REG_XMM0
        && operand->reg <= CDISASM_X86_REG_XMM15) {
        memcpy(bytes,
            emulator->x86.xmm[operand->reg - CDISASM_X86_REG_XMM0], 16u);
        return XXEMUL_STATUS_OK;
    }
    if (operand->type != CDISASM_OPERAND_MEMORY)
        return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    status = xxemul_x86_effective_address(
        emulator, instruction, operand, next_ip, &address);
    return status == XXEMUL_STATUS_OK
        ? xxemul_x86_guest_memory(emulator, address, bytes, 16u, 0)
        : status;
}

static xxemul_status xxemul_x86_write_xmm_operand(
    xxemul *emulator, const cdisasm_x86_instruction *instruction,
    const cdisasm_x86_operand *operand, uint64_t next_ip,
    const uint8_t bytes[16])
{
    uint64_t address;
    xxemul_status status;
    if (operand->size != 16u)
        return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    if (operand->type == CDISASM_OPERAND_REGISTER
        && operand->reg >= CDISASM_X86_REG_XMM0
        && operand->reg <= CDISASM_X86_REG_XMM15) {
        memcpy(emulator->x86.xmm[operand->reg - CDISASM_X86_REG_XMM0],
            bytes, 16u);
        return XXEMUL_STATUS_OK;
    }
    if (operand->type != CDISASM_OPERAND_MEMORY)
        return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    status = xxemul_x86_effective_address(
        emulator, instruction, operand, next_ip, &address);
    return status == XXEMUL_STATUS_OK
        ? xxemul_x86_guest_memory(emulator, address,
            (void *)bytes, 16u, 1) : status;
}

static xxemul_status xxemul_x86_simd_binary(
    xxemul *emulator, const cdisasm_x86_instruction *instruction,
    uint64_t next_ip)
{
    uint8_t op1[16];
    uint8_t op2[16];
    uint8_t res[16];
    const cdisasm_x86_operand *dest_op;
    size_t i;
    xxemul_status status;

    if (instruction->operand_count == 2u) {
        dest_op = &instruction->opcode[0];
        status = xxemul_x86_read_xmm_operand(emulator, instruction, &instruction->opcode[0], next_ip, op1);
        if (status != XXEMUL_STATUS_OK) return status;
        status = xxemul_x86_read_xmm_operand(emulator, instruction, &instruction->opcode[1], next_ip, op2);
        if (status != XXEMUL_STATUS_OK) return status;
    } else if (instruction->operand_count == 3u) {
        dest_op = &instruction->opcode[0];
        status = xxemul_x86_read_xmm_operand(emulator, instruction, &instruction->opcode[1], next_ip, op1);
        if (status != XXEMUL_STATUS_OK) return status;
        status = xxemul_x86_read_xmm_operand(emulator, instruction, &instruction->opcode[2], next_ip, op2);
        if (status != XXEMUL_STATUS_OK) return status;
    } else {
        return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    }

    switch (instruction->name_id) {
    case CDISASM_X86_NAME_PXOR:
    case CDISASM_X86_NAME_VPXOR:
    case CDISASM_X86_NAME_XORPS:
    case CDISASM_X86_NAME_VXORPS:
    case CDISASM_X86_NAME_XORPD:
    case CDISASM_X86_NAME_VXORPD:
        for (i = 0; i < 16; ++i) res[i] = op1[i] ^ op2[i];
        break;
    case CDISASM_X86_NAME_POR:
    case CDISASM_X86_NAME_VPOR:
    case CDISASM_X86_NAME_ORPS:
    case CDISASM_X86_NAME_VORPS:
    case CDISASM_X86_NAME_ORPD:
    case CDISASM_X86_NAME_VORPD:
        for (i = 0; i < 16; ++i) res[i] = op1[i] | op2[i];
        break;
    case CDISASM_X86_NAME_PAND:
    case CDISASM_X86_NAME_VPAND:
    case CDISASM_X86_NAME_ANDPS:
    case CDISASM_X86_NAME_VANDPS:
    case CDISASM_X86_NAME_ANDPD:
    case CDISASM_X86_NAME_VANDPD:
        for (i = 0; i < 16; ++i) res[i] = op1[i] & op2[i];
        break;
    case CDISASM_X86_NAME_PANDN:
    case CDISASM_X86_NAME_VPANDN:
    case CDISASM_X86_NAME_ANDNPS:
    case CDISASM_X86_NAME_VANDNPS:
    case CDISASM_X86_NAME_ANDNPD:
    case CDISASM_X86_NAME_VANDNPD:
        for (i = 0; i < 16; ++i) res[i] = (uint8_t)((~op1[i]) & op2[i]);
        break;
    case CDISASM_X86_NAME_PADDB:
    case CDISASM_X86_NAME_VPADDB:
        for (i = 0; i < 16; ++i) res[i] = (uint8_t)(op1[i] + op2[i]);
        break;
    case CDISASM_X86_NAME_PADDW:
    case CDISASM_X86_NAME_VPADDW:
        for (i = 0; i < 8; ++i) {
            uint16_t a, b;
            memcpy(&a, op1 + i * 2, 2);
            memcpy(&b, op2 + i * 2, 2);
            a += b;
            memcpy(res + i * 2, &a, 2);
        }
        break;
    case CDISASM_X86_NAME_PADDD:
    case CDISASM_X86_NAME_VPADDD:
        for (i = 0; i < 4; ++i) {
            uint32_t a, b;
            memcpy(&a, op1 + i * 4, 4);
            memcpy(&b, op2 + i * 4, 4);
            a += b;
            memcpy(res + i * 4, &a, 4);
        }
        break;
    case CDISASM_X86_NAME_PADDQ:
    case CDISASM_X86_NAME_VPADDQ:
        for (i = 0; i < 2; ++i) {
            uint64_t a, b;
            memcpy(&a, op1 + i * 8, 8);
            memcpy(&b, op2 + i * 8, 8);
            a += b;
            memcpy(res + i * 8, &a, 8);
        }
        break;
    case CDISASM_X86_NAME_PSUBB:
    case CDISASM_X86_NAME_VPSUBB:
        for (i = 0; i < 16; ++i) res[i] = (uint8_t)(op1[i] - op2[i]);
        break;
    case CDISASM_X86_NAME_PSUBW:
    case CDISASM_X86_NAME_VPSUBW:
        for (i = 0; i < 8; ++i) {
            uint16_t a, b;
            memcpy(&a, op1 + i * 2, 2);
            memcpy(&b, op2 + i * 2, 2);
            a -= b;
            memcpy(res + i * 2, &a, 2);
        }
        break;
    case CDISASM_X86_NAME_PSUBD:
    case CDISASM_X86_NAME_VPSUBD:
        for (i = 0; i < 4; ++i) {
            uint32_t a, b;
            memcpy(&a, op1 + i * 4, 4);
            memcpy(&b, op2 + i * 4, 4);
            a -= b;
            memcpy(res + i * 4, &a, 4);
        }
        break;
    case CDISASM_X86_NAME_PSUBQ:
    case CDISASM_X86_NAME_VPSUBQ:
        for (i = 0; i < 2; ++i) {
            uint64_t a, b;
            memcpy(&a, op1 + i * 8, 8);
            memcpy(&b, op2 + i * 8, 8);
            a -= b;
            memcpy(res + i * 8, &a, 8);
        }
        break;
    case CDISASM_X86_NAME_PCMPEQB:
    case CDISASM_X86_NAME_VPCMPEQB:
        for (i = 0; i < 16; ++i) res[i] = (op1[i] == op2[i]) ? 0xff : 0x00;
        break;
    case CDISASM_X86_NAME_PCMPEQW:
    case CDISASM_X86_NAME_VPCMPEQW:
        for (i = 0; i < 8; ++i) {
            uint16_t a, b, r;
            memcpy(&a, op1 + i * 2, 2);
            memcpy(&b, op2 + i * 2, 2);
            r = (a == b) ? 0xffff : 0x0000;
            memcpy(res + i * 2, &r, 2);
        }
        break;
    case CDISASM_X86_NAME_PCMPEQD:
    case CDISASM_X86_NAME_VPCMPEQD:
        for (i = 0; i < 4; ++i) {
            uint32_t a, b, r;
            memcpy(&a, op1 + i * 4, 4);
            memcpy(&b, op2 + i * 4, 4);
            r = (a == b) ? 0xffffffffu : 0x00000000u;
            memcpy(res + i * 4, &r, 4);
        }
        break;
    case CDISASM_X86_NAME_PCMPEQQ:
    case CDISASM_X86_NAME_VPCMPEQQ:
        for (i = 0; i < 2; ++i) {
            uint64_t a, b, r;
            memcpy(&a, op1 + i * 8, 8);
            memcpy(&b, op2 + i * 8, 8);
            r = (a == b) ? UINT64_MAX : 0;
            memcpy(res + i * 8, &r, 8);
        }
        break;
    case CDISASM_X86_NAME_PCMPGTB:
    case CDISASM_X86_NAME_VPCMPGTB:
        for (i = 0; i < 16; ++i) res[i] = ((int8_t)op1[i] > (int8_t)op2[i]) ? 0xff : 0x00;
        break;
    case CDISASM_X86_NAME_PCMPGTW:
    case CDISASM_X86_NAME_VPCMPGTW:
        for (i = 0; i < 8; ++i) {
            int16_t a, b;
            uint16_t r;
            memcpy(&a, op1 + i * 2, 2);
            memcpy(&b, op2 + i * 2, 2);
            r = (a > b) ? 0xffff : 0x0000;
            memcpy(res + i * 2, &r, 2);
        }
        break;
    case CDISASM_X86_NAME_PCMPGTD:
    case CDISASM_X86_NAME_VPCMPGTD:
        for (i = 0; i < 4; ++i) {
            int32_t a, b;
            uint32_t r;
            memcpy(&a, op1 + i * 4, 4);
            memcpy(&b, op2 + i * 4, 4);
            r = (a > b) ? 0xffffffffu : 0x00000000u;
            memcpy(res + i * 4, &r, 4);
        }
        break;
    case CDISASM_X86_NAME_PCMPGTQ:
    case CDISASM_X86_NAME_VPCMPGTQ:
        for (i = 0; i < 2; ++i) {
            int64_t a, b;
            uint64_t r;
            memcpy(&a, op1 + i * 8, 8);
            memcpy(&b, op2 + i * 8, 8);
            r = (a > b) ? UINT64_MAX : 0;
            memcpy(res + i * 8, &r, 8);
        }
        break;
    case CDISASM_X86_NAME_PUNPCKLBW:
    case CDISASM_X86_NAME_VPUNPCKLBW:
        for (i = 0; i < 8; ++i) {
            res[i * 2] = op1[i];
            res[i * 2 + 1] = op2[i];
        }
        break;
    case CDISASM_X86_NAME_PUNPCKHBW:
    case CDISASM_X86_NAME_VPUNPCKHBW:
        for (i = 0; i < 8; ++i) {
            res[i * 2] = op1[8 + i];
            res[i * 2 + 1] = op2[8 + i];
        }
        break;
    case CDISASM_X86_NAME_PUNPCKLWD:
    case CDISASM_X86_NAME_VPUNPCKLWD:
        for (i = 0; i < 4; ++i) {
            memcpy(res + i * 4, op1 + i * 2, 2);
            memcpy(res + i * 4 + 2, op2 + i * 2, 2);
        }
        break;
    case CDISASM_X86_NAME_PUNPCKHWD:
    case CDISASM_X86_NAME_VPUNPCKHWD:
        for (i = 0; i < 4; ++i) {
            memcpy(res + i * 4, op1 + 8 + i * 2, 2);
            memcpy(res + i * 4 + 2, op2 + 8 + i * 2, 2);
        }
        break;
    case CDISASM_X86_NAME_PUNPCKLDQ:
    case CDISASM_X86_NAME_VPUNPCKLDQ:
        memcpy(res, op1, 4);
        memcpy(res + 4, op2, 4);
        memcpy(res + 8, op1 + 4, 4);
        memcpy(res + 12, op2 + 4, 4);
        break;
    case CDISASM_X86_NAME_PUNPCKHDQ:
    case CDISASM_X86_NAME_VPUNPCKHDQ:
        memcpy(res, op1 + 8, 4);
        memcpy(res + 4, op2 + 8, 4);
        memcpy(res + 8, op1 + 12, 4);
        memcpy(res + 12, op2 + 12, 4);
        break;
    case CDISASM_X86_NAME_PUNPCKLQDQ:
    case CDISASM_X86_NAME_VPUNPCKLQDQ:
        memcpy(res, op1, 8);
        memcpy(res + 8, op2, 8);
        break;
    case CDISASM_X86_NAME_PUNPCKHQDQ:
    case CDISASM_X86_NAME_VPUNPCKHQDQ:
        memcpy(res, op1 + 8, 8);
        memcpy(res + 8, op2 + 8, 8);
        break;
    default:
        return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    }

    return xxemul_x86_write_xmm_operand(emulator, instruction, dest_op, next_ip, res);
}


xxemul_status xxemul_x86_step(xxemul *emulator, xxemul_step_info *info)
{
    cdisasm_x86_instruction instruction;
    uint64_t current_ip = emulator->x86.ip;
    uint64_t next_ip;
    uint64_t left;
    uint64_t right = 0u;
    uint64_t target;
    uint64_t saved_cf;
    uint64_t original_sp;
    uint8_t size;
    uint32_t page_fault_error = UINT32_MAX;
    int condition;
    xxemul_status status;

    emulator->dos_pending_page_fault_error = UINT32_MAX;
    if (emulator->dos_mode && emulator->dos_dpmi_prepared
        && (emulator->dos_cr0 & 1u) == 0u
        && emulator->x86.segment[XXEMUL_X86_CS] == 0xf000u
        && current_ip == 0x0200u) {
        status = xxemul_dpmi_enter(emulator);
        if (status == XXEMUL_STATUS_OK && info != NULL) {
            info->address = 0xf0200u;
            info->next_address =
                (uint64_t)emulator->dos_segments[XXEMUL_X86_CS].base
                    + emulator->x86.ip;
            info->size = 0u;
            info->instruction_id = 0u;
        }
        return status;
    }
    status = xxemul_x86_decode_current_tracked(emulator, &instruction,
        &page_fault_error);
    if (status != XXEMUL_STATUS_OK) {
        if (status == XXEMUL_STATUS_ADDRESS_FAULT
            && page_fault_error != UINT32_MAX
            && emulator->dos_mode && (emulator->dos_cr0 & 1u) != 0u) {
            uint64_t fault_address =
                (uint64_t)emulator->dos_segments[XXEMUL_X86_CS].base
                    + current_ip;

            emulator->dos_pending_page_fault_error = UINT32_MAX;
            status = xxemul_x86_dos_interrupt_gate(emulator, 14u,
                (uint32_t)current_ip, 1, page_fault_error, &next_ip);
            if (status != XXEMUL_STATUS_OK) return status;
            emulator->x86.ip = next_ip;
            emulator->x86.flags |= UINT64_C(2);
            if (info != NULL) {
                info->address = fault_address;
                info->next_address =
                    (uint64_t)emulator->dos_segments[XXEMUL_X86_CS].base
                        + next_ip;
            }
            return XXEMUL_STATUS_OK;
        }
        return status;
    }
    emulator->dos_pending_page_fault_error = UINT32_MAX;
    next_ip = (current_ip + instruction.opcode_size)
        & xxemul_x86_address_mask(emulator);
    if (info != NULL) {
        info->address = emulator->dos_mode
            ? emulator->dos_segments[XXEMUL_X86_CS].valid
                ? (uint64_t)emulator->dos_segments[XXEMUL_X86_CS].base
                    + current_ip
                : xxemul_dos_physical(emulator,
                    emulator->x86.segment[XXEMUL_X86_CS],
                    (uint16_t)current_ip)
            : current_ip;
        info->next_address = info->address;
        info->size = instruction.opcode_size;
        info->instruction_id = instruction.name_id;
    }

    switch (instruction.name_id) {
    case CDISASM_X86_NAME_IN:
    case CDISASM_X86_NAME_OUT:
        {
        uint16_t port;
        uint8_t value;
        if (!emulator->dos_mode || instruction.operand_count != 2u)
            return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
        status = xxemul_x86_read_operand(emulator, &instruction,
            &instruction.opcode[instruction.name_id == CDISASM_X86_NAME_IN
                ? 1u : 0u], next_ip, &right);
        if (status != XXEMUL_STATUS_OK) return status;
        port = (uint16_t)right;
        if (instruction.name_id == CDISASM_X86_NAME_IN) {
            if (instruction.opcode[0].size != 1u)
                return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
            if (port == 0x92u)
                value = emulator->dos_port_92;
            else if (port == 0x20u || port == 0xa0u)
                value = 0u;
            else if (port == 0x21u)
                value = emulator->dos_pic_master_mask;
            else if (port == 0xa1u)
                value = emulator->dos_pic_slave_mask;
            else if (port == 0x64u)
                value = emulator->dos_kbc_data_ready ? 1u : 0u;
            else if (port == 0x60u) {
                value = emulator->dos_kbc_data_ready
                    ? emulator->dos_kbc_data : 0u;
                emulator->dos_kbc_data_ready = 0u;
            } else {
                return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
            }
            status = xxemul_x86_write_operand(emulator, &instruction,
                &instruction.opcode[0], next_ip, value);
        } else {
            if (instruction.opcode[1].size != 1u)
                return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
            status = xxemul_x86_read_operand(emulator, &instruction,
                &instruction.opcode[1], next_ip, &right);
            if (status != XXEMUL_STATUS_OK) return status;
            value = (uint8_t)right;
            if (port == 0x92u) {
                emulator->dos_port_92 = (uint8_t)right;
                emulator->dos_kbc_output = (uint8_t)(
                    (emulator->dos_kbc_output & ~2u) | (value & 2u));
            } else if (port == 0x21u) {
                if (emulator->dos_pic_master_stage == 1u) {
                    emulator->dos_pic_master_offset = value & 0xf8u;
                    emulator->dos_pic_master_stage = 2u;
                } else if (emulator->dos_pic_master_stage == 2u) {
                    emulator->dos_pic_master_stage =
                        emulator->dos_pic_master_icw4 ? 3u : 0u;
                } else if (emulator->dos_pic_master_stage == 3u) {
                    emulator->dos_pic_master_stage = 0u;
                } else {
                    emulator->dos_pic_master_mask = value;
                }
            } else if (port == 0xa1u) {
                if (emulator->dos_pic_slave_stage == 1u) {
                    emulator->dos_pic_slave_offset = value & 0xf8u;
                    emulator->dos_pic_slave_stage = 2u;
                } else if (emulator->dos_pic_slave_stage == 2u) {
                    emulator->dos_pic_slave_stage =
                        emulator->dos_pic_slave_icw4 ? 3u : 0u;
                } else if (emulator->dos_pic_slave_stage == 3u) {
                    emulator->dos_pic_slave_stage = 0u;
                } else {
                    emulator->dos_pic_slave_mask = value;
                }
            } else if (port == 0x20u || port == 0xa0u) {
                if ((value & 0x10u) != 0u) {
                    uint8_t *stage = port == 0x20u
                        ? &emulator->dos_pic_master_stage
                        : &emulator->dos_pic_slave_stage;
                    uint8_t *icw4 = port == 0x20u
                        ? &emulator->dos_pic_master_icw4
                        : &emulator->dos_pic_slave_icw4;
                    *stage = 1u;
                    *icw4 = value & 1u;
                }
            } else if (port == 0x64u) {
                if (value == 0xd0u) {
                    emulator->dos_kbc_data = emulator->dos_kbc_output;
                    emulator->dos_kbc_data_ready = 1u;
                } else if (value == 0xaau) {
                    emulator->dos_kbc_data = 0x55u;
                    emulator->dos_kbc_data_ready = 1u;
                } else if (value != 0xd1u && value != 0xaeu
                    && value != 0xadu) {
                    return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
                }
                emulator->dos_kbc_command = value;
            } else if (port == 0x60u) {
                if (emulator->dos_kbc_command == 0xd1u) {
                    emulator->dos_kbc_output = value;
                    emulator->dos_port_92 = (uint8_t)(
                        (emulator->dos_port_92 & ~2u) | (value & 2u));
                    emulator->dos_kbc_command = 0u;
                }
            } else {
                return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
            }
        }
        break;
        }
    case CDISASM_X86_NAME_CPUID:
        {
            uint32_t leaf = (uint32_t)emulator->x86.gpr[XXEMUL_X86_RAX];
            uint32_t eax = 0u, ebx = 0u, ecx = 0u, edx = 0u;
            if (leaf == 0u) {
                eax = 1u;
                ebx = UINT32_C(0x756e6547);
                edx = UINT32_C(0x49656e69);
                ecx = UINT32_C(0x6c65746e);
            } else if (leaf == 1u) {
                eax = UINT32_C(0x00000400);
                edx = 1u;
            } else if (leaf == UINT32_C(0x80000000)) {
                eax = UINT32_C(0x80000000);
            }
            status = xxemul_x86_write_register(emulator,
                CDISASM_X86_REG_EAX, eax);
            if (status == XXEMUL_STATUS_OK)
                status = xxemul_x86_write_register(emulator,
                    CDISASM_X86_REG_EBX, ebx);
            if (status == XXEMUL_STATUS_OK)
                status = xxemul_x86_write_register(emulator,
                    CDISASM_X86_REG_ECX, ecx);
            if (status == XXEMUL_STATUS_OK)
                status = xxemul_x86_write_register(emulator,
                    CDISASM_X86_REG_EDX, edx);
        }
        break;
    case CDISASM_X86_NAME_MOVHPS:
    case CDISASM_X86_NAME_MOVLPS:
    case CDISASM_X86_NAME_MOVHPD:
    case CDISASM_X86_NAME_MOVLPD:
        if (instruction.operand_count != 2u)
            return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
        {
            size_t half = instruction.name_id == CDISASM_X86_NAME_MOVHPS
                || instruction.name_id == CDISASM_X86_NAME_MOVHPD
                ? 8u : 0u;
            const cdisasm_x86_operand *destination = &instruction.opcode[0];
            const cdisasm_x86_operand *source = &instruction.opcode[1];
            if (destination->type == CDISASM_OPERAND_REGISTER
                && destination->reg >= CDISASM_X86_REG_XMM0
                && destination->reg <= CDISASM_X86_REG_XMM15
                && source->type == CDISASM_OPERAND_MEMORY
                && source->size == 8u) {
                status = xxemul_x86_read_operand(emulator, &instruction,
                    source, next_ip, &right);
                if (status == XXEMUL_STATUS_OK)
                    memcpy(emulator->x86.xmm[
                        destination->reg - CDISASM_X86_REG_XMM0] + half,
                        &right, sizeof(right));
            } else if (destination->type == CDISASM_OPERAND_MEMORY
                && destination->size == 8u
                && source->type == CDISASM_OPERAND_REGISTER
                && source->reg >= CDISASM_X86_REG_XMM0
                && source->reg <= CDISASM_X86_REG_XMM15) {
                memcpy(&right, emulator->x86.xmm[
                    source->reg - CDISASM_X86_REG_XMM0] + half,
                    sizeof(right));
                status = xxemul_x86_write_operand(emulator, &instruction,
                    destination, next_ip, right);
            } else {
                return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
            }
        }
        break;
    case CDISASM_X86_NAME_MOVHLPS:
    case CDISASM_X86_NAME_MOVLHPS:
    case CDISASM_X86_NAME_VMOVHLPS:
    case CDISASM_X86_NAME_VMOVLHPS:
        if (instruction.operand_count == 2u) {
            if (instruction.opcode[0].type != CDISASM_OPERAND_REGISTER
                || instruction.opcode[0].reg < CDISASM_X86_REG_XMM0
                || instruction.opcode[0].reg > CDISASM_X86_REG_XMM15
                || instruction.opcode[1].type != CDISASM_OPERAND_REGISTER
                || instruction.opcode[1].reg < CDISASM_X86_REG_XMM0
                || instruction.opcode[1].reg > CDISASM_X86_REG_XMM15)
                return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
            uint8_t *dest = emulator->x86.xmm[instruction.opcode[0].reg - CDISASM_X86_REG_XMM0];
            const uint8_t *src = emulator->x86.xmm[instruction.opcode[1].reg - CDISASM_X86_REG_XMM0];
            if (instruction.name_id == CDISASM_X86_NAME_MOVHLPS) {
                memcpy(dest, src + 8, 8);
            } else {
                memcpy(dest + 8, src, 8);
            }
            status = XXEMUL_STATUS_OK;
        } else if (instruction.operand_count == 3u) {
            if (instruction.opcode[0].type != CDISASM_OPERAND_REGISTER
                || instruction.opcode[0].reg < CDISASM_X86_REG_XMM0
                || instruction.opcode[0].reg > CDISASM_X86_REG_XMM15
                || instruction.opcode[1].type != CDISASM_OPERAND_REGISTER
                || instruction.opcode[1].reg < CDISASM_X86_REG_XMM0
                || instruction.opcode[1].reg > CDISASM_X86_REG_XMM15
                || instruction.opcode[2].type != CDISASM_OPERAND_REGISTER
                || instruction.opcode[2].reg < CDISASM_X86_REG_XMM0
                || instruction.opcode[2].reg > CDISASM_X86_REG_XMM15)
                return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
            uint8_t *dest = emulator->x86.xmm[instruction.opcode[0].reg - CDISASM_X86_REG_XMM0];
            const uint8_t *s1 = emulator->x86.xmm[instruction.opcode[1].reg - CDISASM_X86_REG_XMM0];
            const uint8_t *s2 = emulator->x86.xmm[instruction.opcode[2].reg - CDISASM_X86_REG_XMM0];
            uint8_t tmp[16];
            if (instruction.name_id == CDISASM_X86_NAME_VMOVHLPS) {
                memcpy(tmp, s2 + 8, 8);
                memcpy(tmp + 8, s1 + 8, 8);
            } else {
                memcpy(tmp, s1, 8);
                memcpy(tmp + 8, s2, 8);
            }
            memcpy(dest, tmp, 16);
            status = XXEMUL_STATUS_OK;
        } else {
            return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
        }
        break;
    case CDISASM_X86_NAME_BSF:
    case CDISASM_X86_NAME_TZCNT:
    case CDISASM_X86_NAME_BSR:
        if (instruction.operand_count != 2u
            || instruction.opcode[0].type != CDISASM_OPERAND_REGISTER
            || instruction.opcode[0].size == 0u
            || instruction.opcode[0].size > 8u)
            return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
        status = xxemul_x86_read_operand(emulator, &instruction,
            &instruction.opcode[1], next_ip, &right);
        if (status != XXEMUL_STATUS_OK) return status;
        right &= xxemul_mask_for_size(instruction.opcode[0].size);
        if (right == 0u) {
            emulator->x86.flags |= XXEMUL_X86_FLAG_ZF;
            status = XXEMUL_STATUS_OK;
        } else {
            uint8_t bit;
            emulator->x86.flags &= ~XXEMUL_X86_FLAG_ZF;
            if (instruction.name_id == CDISASM_X86_NAME_BSF) {
                for (bit = 0u; (right & (UINT64_C(1) << bit)) == 0u;
                     ++bit) {}
            } else {
                for (bit = (uint8_t)(instruction.opcode[0].size * 8u - 1u);
                     (right & (UINT64_C(1) << bit)) == 0u; --bit) {}
            }
            status = xxemul_x86_write_operand(emulator, &instruction,
                &instruction.opcode[0], next_ip, bit);
        }
        break;
    case CDISASM_X86_NAME_MOVD:
    case CDISASM_X86_NAME_MOVQ:
        if (instruction.operand_count != 2u)
            return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
        {
            size_t op_size = (instruction.name_id == CDISASM_X86_NAME_MOVD) ? 4u : 8u;
            if (instruction.opcode[0].size == 4u || instruction.opcode[0].size == 8u) {
                if (instruction.opcode[0].type != CDISASM_OPERAND_REGISTER ||
                    instruction.opcode[0].reg < CDISASM_X86_REG_XMM0 || instruction.opcode[0].reg > CDISASM_X86_REG_XMM15)
                    op_size = (size_t)instruction.opcode[0].size;
            }
            if (instruction.opcode[1].size == 4u || instruction.opcode[1].size == 8u) {
                if (instruction.opcode[1].type != CDISASM_OPERAND_REGISTER ||
                    instruction.opcode[1].reg < CDISASM_X86_REG_XMM0 || instruction.opcode[1].reg > CDISASM_X86_REG_XMM15)
                    op_size = (size_t)instruction.opcode[1].size;
            }
            if (instruction.opcode[1].type == CDISASM_OPERAND_REGISTER
                && instruction.opcode[1].reg >= CDISASM_X86_REG_XMM0
                && instruction.opcode[1].reg <= CDISASM_X86_REG_XMM15) {
                right = 0;
                memcpy(&right, emulator->x86.xmm[
                    instruction.opcode[1].reg - CDISASM_X86_REG_XMM0],
                    op_size);
                status = XXEMUL_STATUS_OK;
            } else if (instruction.opcode[1].size == op_size) {
                status = xxemul_x86_read_operand(emulator, &instruction,
                    &instruction.opcode[1], next_ip, &right);
            } else {
                return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
            }
            if (status != XXEMUL_STATUS_OK) return status;
            if (instruction.opcode[0].type == CDISASM_OPERAND_REGISTER
                && instruction.opcode[0].reg >= CDISASM_X86_REG_XMM0
                && instruction.opcode[0].reg <= CDISASM_X86_REG_XMM15) {
                uint8_t *destination = emulator->x86.xmm[
                    instruction.opcode[0].reg - CDISASM_X86_REG_XMM0];
                memset(destination, 0, 16u);
                memcpy(destination, &right, op_size);
                status = XXEMUL_STATUS_OK;
            } else if (instruction.opcode[0].size == op_size) {
                status = xxemul_x86_write_operand(emulator, &instruction,
                    &instruction.opcode[0], next_ip, right);
            } else {
                return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
            }
        }
        break;
    case CDISASM_X86_NAME_MOVUPS:
    case CDISASM_X86_NAME_MOVAPS:
    case CDISASM_X86_NAME_MOVUPD:
    case CDISASM_X86_NAME_MOVAPD:
    case CDISASM_X86_NAME_MOVDQU:
    case CDISASM_X86_NAME_MOVDQA:
    case CDISASM_X86_NAME_VMOVUPS:
    case CDISASM_X86_NAME_VMOVAPS:
    case CDISASM_X86_NAME_VMOVUPD:
    case CDISASM_X86_NAME_VMOVAPD:
        if (instruction.operand_count != 2u)
            return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
        {
            uint8_t bytes[16];
            status = xxemul_x86_read_xmm_operand(emulator, &instruction,
                &instruction.opcode[1], next_ip, bytes);
            if (status == XXEMUL_STATUS_OK)
                status = xxemul_x86_write_xmm_operand(emulator, &instruction,
                    &instruction.opcode[0], next_ip, bytes);
        }
        break;
    case CDISASM_X86_NAME_PXOR:
    case CDISASM_X86_NAME_VPXOR:
    case CDISASM_X86_NAME_XORPS:
    case CDISASM_X86_NAME_VXORPS:
    case CDISASM_X86_NAME_XORPD:
    case CDISASM_X86_NAME_VXORPD:
    case CDISASM_X86_NAME_POR:
    case CDISASM_X86_NAME_VPOR:
    case CDISASM_X86_NAME_ORPS:
    case CDISASM_X86_NAME_VORPS:
    case CDISASM_X86_NAME_ORPD:
    case CDISASM_X86_NAME_VORPD:
    case CDISASM_X86_NAME_PAND:
    case CDISASM_X86_NAME_VPAND:
    case CDISASM_X86_NAME_ANDPS:
    case CDISASM_X86_NAME_VANDPS:
    case CDISASM_X86_NAME_ANDPD:
    case CDISASM_X86_NAME_VANDPD:
    case CDISASM_X86_NAME_PANDN:
    case CDISASM_X86_NAME_VPANDN:
    case CDISASM_X86_NAME_ANDNPS:
    case CDISASM_X86_NAME_VANDNPS:
    case CDISASM_X86_NAME_ANDNPD:
    case CDISASM_X86_NAME_VANDNPD:
    case CDISASM_X86_NAME_PADDB:
    case CDISASM_X86_NAME_VPADDB:
    case CDISASM_X86_NAME_PADDW:
    case CDISASM_X86_NAME_VPADDW:
    case CDISASM_X86_NAME_PADDD:
    case CDISASM_X86_NAME_VPADDD:
    case CDISASM_X86_NAME_PADDQ:
    case CDISASM_X86_NAME_VPADDQ:
    case CDISASM_X86_NAME_PSUBB:
    case CDISASM_X86_NAME_VPSUBB:
    case CDISASM_X86_NAME_PSUBW:
    case CDISASM_X86_NAME_VPSUBW:
    case CDISASM_X86_NAME_PSUBD:
    case CDISASM_X86_NAME_VPSUBD:
    case CDISASM_X86_NAME_PSUBQ:
    case CDISASM_X86_NAME_VPSUBQ:
    case CDISASM_X86_NAME_PCMPEQB:
    case CDISASM_X86_NAME_VPCMPEQB:
    case CDISASM_X86_NAME_PCMPEQW:
    case CDISASM_X86_NAME_VPCMPEQW:
    case CDISASM_X86_NAME_PCMPEQD:
    case CDISASM_X86_NAME_VPCMPEQD:
    case CDISASM_X86_NAME_PCMPEQQ:
    case CDISASM_X86_NAME_VPCMPEQQ:
    case CDISASM_X86_NAME_PCMPGTB:
    case CDISASM_X86_NAME_VPCMPGTB:
    case CDISASM_X86_NAME_PCMPGTW:
    case CDISASM_X86_NAME_VPCMPGTW:
    case CDISASM_X86_NAME_PCMPGTD:
    case CDISASM_X86_NAME_VPCMPGTD:
    case CDISASM_X86_NAME_PCMPGTQ:
    case CDISASM_X86_NAME_VPCMPGTQ:
    case CDISASM_X86_NAME_PUNPCKLBW:
    case CDISASM_X86_NAME_VPUNPCKLBW:
    case CDISASM_X86_NAME_PUNPCKHBW:
    case CDISASM_X86_NAME_VPUNPCKHBW:
    case CDISASM_X86_NAME_PUNPCKLWD:
    case CDISASM_X86_NAME_VPUNPCKLWD:
    case CDISASM_X86_NAME_PUNPCKHWD:
    case CDISASM_X86_NAME_VPUNPCKHWD:
    case CDISASM_X86_NAME_PUNPCKLDQ:
    case CDISASM_X86_NAME_VPUNPCKLDQ:
    case CDISASM_X86_NAME_PUNPCKHDQ:
    case CDISASM_X86_NAME_VPUNPCKHDQ:
    case CDISASM_X86_NAME_PUNPCKLQDQ:
    case CDISASM_X86_NAME_VPUNPCKLQDQ:
    case CDISASM_X86_NAME_PUNPCKHQDQ:
    case CDISASM_X86_NAME_VPUNPCKHQDQ:
        status = xxemul_x86_simd_binary(emulator, &instruction, next_ip);
        break;
    case CDISASM_X86_NAME_PTEST:
    case CDISASM_X86_NAME_VPTEST:
        {
            uint8_t op1[16], op2[16];
            int zf = 1, cf = 1;
            size_t idx;
            status = xxemul_x86_read_xmm_operand(emulator, &instruction, &instruction.opcode[0], next_ip, op1);
            if (status != XXEMUL_STATUS_OK) return status;
            status = xxemul_x86_read_xmm_operand(emulator, &instruction, &instruction.opcode[1], next_ip, op2);
            if (status != XXEMUL_STATUS_OK) return status;
            for (idx = 0; idx < 16; ++idx) {
                if ((op1[idx] & op2[idx]) != 0) zf = 0;
                if (((~op1[idx]) & op2[idx]) != 0) cf = 0;
            }
            emulator->x86.flags &= ~(XXEMUL_X86_FLAG_OF | XXEMUL_X86_FLAG_SF | XXEMUL_X86_FLAG_AF | XXEMUL_X86_FLAG_PF | XXEMUL_X86_FLAG_CF | XXEMUL_X86_FLAG_ZF);
            if (zf) emulator->x86.flags |= XXEMUL_X86_FLAG_ZF;
            if (cf) emulator->x86.flags |= XXEMUL_X86_FLAG_CF;
        }
        break;
    case CDISASM_X86_NAME_PMOVMSKB:
    case CDISASM_X86_NAME_MOVMSKPS:
    case CDISASM_X86_NAME_MOVMSKPD:
    case CDISASM_X86_NAME_VMOVMSKPS:
    case CDISASM_X86_NAME_VMOVMSKPD:
        if (instruction.operand_count != 2u
            || instruction.opcode[1].type != CDISASM_OPERAND_REGISTER
            || instruction.opcode[1].reg < CDISASM_X86_REG_XMM0
            || instruction.opcode[1].reg > CDISASM_X86_REG_XMM15)
            return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
        {
            const uint8_t *source = emulator->x86.xmm[
                instruction.opcode[1].reg - CDISASM_X86_REG_XMM0];
            uint32_t mask = 0;
            size_t i;
            if (instruction.name_id == CDISASM_X86_NAME_PMOVMSKB) {
                for (i = 0u; i < 16u; ++i) {
                    if (source[i] & 0x80u) mask |= (1u << i);
                }
            } else if (instruction.name_id == CDISASM_X86_NAME_MOVMSKPS
                || instruction.name_id == CDISASM_X86_NAME_VMOVMSKPS) {
                for (i = 0u; i < 4u; ++i) {
                    if (source[i * 4u + 3u] & 0x80u) mask |= (1u << i);
                }
            } else {
                for (i = 0u; i < 2u; ++i) {
                    if (source[i * 8u + 7u] & 0x80u) mask |= (1u << i);
                }
            }
            status = xxemul_x86_write_operand(emulator, &instruction,
                &instruction.opcode[0], next_ip, (uint64_t)mask);
        }
        break;
    case CDISASM_X86_NAME_PSHUFD:
    case CDISASM_X86_NAME_VPSHUFD:
    case CDISASM_X86_NAME_PSHUFHW:
    case CDISASM_X86_NAME_VPSHUFHW:
    case CDISASM_X86_NAME_PSHUFLW:
    case CDISASM_X86_NAME_VPSHUFLW:
        if (instruction.operand_count != 3u)
            return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
        {
            uint8_t src[16];
            uint8_t dest[16];
            uint64_t imm_val = 0;
            status = xxemul_x86_read_xmm_operand(emulator, &instruction,
                &instruction.opcode[1], next_ip, src);
            if (status != XXEMUL_STATUS_OK) return status;
            status = xxemul_x86_read_operand(emulator, &instruction,
                &instruction.opcode[2], next_ip, &imm_val);
            if (status != XXEMUL_STATUS_OK) return status;
            uint8_t imm = (uint8_t)imm_val;

            if (instruction.name_id == CDISASM_X86_NAME_PSHUFD
                || instruction.name_id == CDISASM_X86_NAME_VPSHUFD) {
                uint32_t s[4], d[4];
                memcpy(s, src, 16u);
                d[0] = s[(imm >> 0) & 3u];
                d[1] = s[(imm >> 2) & 3u];
                d[2] = s[(imm >> 4) & 3u];
                d[3] = s[(imm >> 6) & 3u];
                memcpy(dest, d, 16u);
            } else if (instruction.name_id == CDISASM_X86_NAME_PSHUFLW
                || instruction.name_id == CDISASM_X86_NAME_VPSHUFLW) {
                uint16_t s[8], d[8];
                memcpy(s, src, 16u);
                d[0] = s[(imm >> 0) & 3u];
                d[1] = s[(imm >> 2) & 3u];
                d[2] = s[(imm >> 4) & 3u];
                d[3] = s[(imm >> 6) & 3u];
                d[4] = s[4];
                d[5] = s[5];
                d[6] = s[6];
                d[7] = s[7];
                memcpy(dest, d, 16u);
            } else {
                uint16_t s[8], d[8];
                memcpy(s, src, 16u);
                d[0] = s[0];
                d[1] = s[1];
                d[2] = s[2];
                d[3] = s[3];
                d[4] = s[4u + ((imm >> 0) & 3u)];
                d[5] = s[4u + ((imm >> 2) & 3u)];
                d[6] = s[4u + ((imm >> 4) & 3u)];
                d[7] = s[4u + ((imm >> 6) & 3u)];
                memcpy(dest, d, 16u);
            }
            status = xxemul_x86_write_xmm_operand(emulator, &instruction,
                &instruction.opcode[0], next_ip, dest);
        }
        break;
    case CDISASM_X86_NAME_SHUFPS:
    case CDISASM_X86_NAME_SHUFPD:
        if (instruction.operand_count != 3u)
            return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
        {
            uint8_t d_orig[16];
            uint8_t src[16];
            uint8_t dest[16];
            uint64_t imm_val = 0;
            status = xxemul_x86_read_xmm_operand(emulator, &instruction,
                &instruction.opcode[0], next_ip, d_orig);
            if (status != XXEMUL_STATUS_OK) return status;
            status = xxemul_x86_read_xmm_operand(emulator, &instruction,
                &instruction.opcode[1], next_ip, src);
            if (status != XXEMUL_STATUS_OK) return status;
            status = xxemul_x86_read_operand(emulator, &instruction,
                &instruction.opcode[2], next_ip, &imm_val);
            if (status != XXEMUL_STATUS_OK) return status;
            uint8_t imm = (uint8_t)imm_val;

            if (instruction.name_id == CDISASM_X86_NAME_SHUFPS) {
                uint32_t d_in[4], s[4], d[4];
                memcpy(d_in, d_orig, 16u);
                memcpy(s, src, 16u);
                d[0] = d_in[(imm >> 0) & 3u];
                d[1] = d_in[(imm >> 2) & 3u];
                d[2] = s[(imm >> 4) & 3u];
                d[3] = s[(imm >> 6) & 3u];
                memcpy(dest, d, 16u);
            } else {
                uint64_t d_in[2], s[2], d[2];
                memcpy(d_in, d_orig, 16u);
                memcpy(s, src, 16u);
                d[0] = d_in[(imm >> 0) & 1u];
                d[1] = s[(imm >> 1) & 1u];
                memcpy(dest, d, 16u);
            }
            status = xxemul_x86_write_xmm_operand(emulator, &instruction,
                &instruction.opcode[0], next_ip, dest);
        }
        break;
    case CDISASM_X86_NAME_PSHUFB:
        if (instruction.operand_count != 2u)
            return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
        {
            uint8_t d_orig[16];
            uint8_t mask[16];
            uint8_t dest[16];
            size_t i;
            status = xxemul_x86_read_xmm_operand(emulator, &instruction,
                &instruction.opcode[0], next_ip, d_orig);
            if (status != XXEMUL_STATUS_OK) return status;
            status = xxemul_x86_read_xmm_operand(emulator, &instruction,
                &instruction.opcode[1], next_ip, mask);
            if (status != XXEMUL_STATUS_OK) return status;
            for (i = 0u; i < 16u; ++i) {
                if (mask[i] & 0x80u) {
                    dest[i] = 0u;
                } else {
                    dest[i] = d_orig[mask[i] & 0x0fu];
                }
            }
            status = xxemul_x86_write_xmm_operand(emulator, &instruction,
                &instruction.opcode[0], next_ip, dest);
        }
        break;
    case CDISASM_X86_NAME_CVTSI2SS:
    case CDISASM_X86_NAME_CVTSI2SD:
        if (instruction.operand_count != 2u
            || instruction.opcode[0].type != CDISASM_OPERAND_REGISTER
            || instruction.opcode[0].reg < CDISASM_X86_REG_XMM0
            || instruction.opcode[0].reg > CDISASM_X86_REG_XMM15
            || (instruction.opcode[1].size != 4u
                && instruction.opcode[1].size != 8u))
            return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
        status = xxemul_x86_read_operand(emulator, &instruction,
            &instruction.opcode[1], next_ip, &right);
        if (status != XXEMUL_STATUS_OK) return status;
        {
            uint8_t *destination = emulator->x86.xmm[
                instruction.opcode[0].reg - CDISASM_X86_REG_XMM0];
            int64_t integer = (int64_t)xxemul_sign_extend(right,
                instruction.opcode[1].size);
            if (instruction.name_id == CDISASM_X86_NAME_CVTSI2SS) {
                float scalar = (float)integer;
                memcpy(destination, &scalar, sizeof(scalar));
            } else {
                double scalar = (double)integer;
                memcpy(destination, &scalar, sizeof(scalar));
            }
        }
        break;
    case CDISASM_X86_NAME_MOVSS:
    case CDISASM_X86_NAME_MOVSD:
        if (instruction.name_id == CDISASM_X86_NAME_MOVSD
            && instruction.operand_count == 2u
            && instruction.opcode[0].type == CDISASM_OPERAND_MEMORY
            && instruction.opcode[1].type == CDISASM_OPERAND_MEMORY) {
            status = xxemul_x86_string(emulator, &instruction,
                current_ip, &next_ip);
            break;
        }
        if (instruction.operand_count != 2u)
            return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
        {
            size_t scalar_size = instruction.name_id == CDISASM_X86_NAME_MOVSS
                ? sizeof(float) : sizeof(double);
            const cdisasm_x86_operand *destination = &instruction.opcode[0];
            const cdisasm_x86_operand *source = &instruction.opcode[1];
            if (destination->type == CDISASM_OPERAND_REGISTER
                && destination->reg >= CDISASM_X86_REG_XMM0
                && destination->reg <= CDISASM_X86_REG_XMM15) {
                uint8_t *xmm_destination = emulator->x86.xmm[
                    destination->reg - CDISASM_X86_REG_XMM0];
                if (source->type == CDISASM_OPERAND_REGISTER
                    && source->reg >= CDISASM_X86_REG_XMM0
                    && source->reg <= CDISASM_X86_REG_XMM15) {
                    memmove(xmm_destination, emulator->x86.xmm[
                        source->reg - CDISASM_X86_REG_XMM0], scalar_size);
                    status = XXEMUL_STATUS_OK;
                } else if (source->type == CDISASM_OPERAND_MEMORY
                    && source->size == scalar_size) {
                    status = xxemul_x86_read_operand(emulator, &instruction,
                        source, next_ip, &right);
                    if (status == XXEMUL_STATUS_OK) {
                        memset(xmm_destination, 0, 16u);
                        memcpy(xmm_destination, &right, scalar_size);
                    }
                } else {
                    return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
                }
            } else if (destination->type == CDISASM_OPERAND_MEMORY
                && destination->size == scalar_size
                && source->type == CDISASM_OPERAND_REGISTER
                && source->reg >= CDISASM_X86_REG_XMM0
                && source->reg <= CDISASM_X86_REG_XMM15) {
                right = 0u;
                memcpy(&right, emulator->x86.xmm[
                    source->reg - CDISASM_X86_REG_XMM0], scalar_size);
                status = xxemul_x86_write_operand(emulator, &instruction,
                    destination, next_ip, right);
            } else {
                return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
            }
        }
        break;
    case CDISASM_X86_NAME_FNINIT:
    case CDISASM_X86_NAME_FINIT:
        memset(emulator->x87_stack, 0, sizeof(emulator->x87_stack));
        memset(emulator->x87_int_val, 0, sizeof(emulator->x87_int_val));
        memset(emulator->x87_is_int, 0, sizeof(emulator->x87_is_int));
        emulator->x87_depth = 0u;
        emulator->x87_top = 0u;
        emulator->x87_control = 0x037fu;
        emulator->x87_status = 0u;
        status = XXEMUL_STATUS_OK;
        break;
    case CDISASM_X86_NAME_FNCLEX:
    case CDISASM_X86_NAME_FCLEX:
        emulator->x87_status &= UINT16_C(0x7f00);
        status = XXEMUL_STATUS_OK;
        break;
    case CDISASM_X86_NAME_WAIT:
        status = XXEMUL_STATUS_OK;
        break;
    case CDISASM_X86_NAME_ADDSS:
    case CDISASM_X86_NAME_SUBSS:
    case CDISASM_X86_NAME_MULSS:
    case CDISASM_X86_NAME_DIVSS:
    case CDISASM_X86_NAME_ADDSD:
    case CDISASM_X86_NAME_SUBSD:
    case CDISASM_X86_NAME_MULSD:
    case CDISASM_X86_NAME_DIVSD:
        if (instruction.operand_count != 2u
            || instruction.opcode[0].type != CDISASM_OPERAND_REGISTER
            || instruction.opcode[0].reg < CDISASM_X86_REG_XMM0
            || instruction.opcode[0].reg > CDISASM_X86_REG_XMM15)
            return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
        {
            int single = instruction.name_id == CDISASM_X86_NAME_ADDSS
                || instruction.name_id == CDISASM_X86_NAME_SUBSS
                || instruction.name_id == CDISASM_X86_NAME_MULSS
                || instruction.name_id == CDISASM_X86_NAME_DIVSS;
            size_t scalar_size = single ? sizeof(float) : sizeof(double);
            uint8_t *destination = emulator->x86.xmm[
                instruction.opcode[0].reg - CDISASM_X86_REG_XMM0];
            uint64_t source_bits = 0u;
            if (instruction.opcode[1].type == CDISASM_OPERAND_REGISTER
                && instruction.opcode[1].reg >= CDISASM_X86_REG_XMM0
                && instruction.opcode[1].reg <= CDISASM_X86_REG_XMM15) {
                memcpy(&source_bits, emulator->x86.xmm[
                    instruction.opcode[1].reg - CDISASM_X86_REG_XMM0],
                    scalar_size);
            } else if (instruction.opcode[1].type == CDISASM_OPERAND_MEMORY
                && instruction.opcode[1].size == scalar_size) {
                status = xxemul_x86_read_operand(emulator, &instruction,
                    &instruction.opcode[1], next_ip, &source_bits);
                if (status != XXEMUL_STATUS_OK) return status;
            } else {
                return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
            }
            if (single) {
                float lhs, rhs;
                memcpy(&lhs, destination, sizeof(lhs));
                memcpy(&rhs, &source_bits, sizeof(rhs));
                if (instruction.name_id == CDISASM_X86_NAME_ADDSS)
                    lhs += rhs;
                else if (instruction.name_id == CDISASM_X86_NAME_SUBSS)
                    lhs -= rhs;
                else if (instruction.name_id == CDISASM_X86_NAME_MULSS)
                    lhs *= rhs;
                else
                    lhs /= rhs;
                memcpy(destination, &lhs, sizeof(lhs));
            } else {
                double lhs, rhs;
                memcpy(&lhs, destination, sizeof(lhs));
                memcpy(&rhs, &source_bits, sizeof(rhs));
                if (instruction.name_id == CDISASM_X86_NAME_ADDSD)
                    lhs += rhs;
                else if (instruction.name_id == CDISASM_X86_NAME_SUBSD)
                    lhs -= rhs;
                else if (instruction.name_id == CDISASM_X86_NAME_MULSD)
                    lhs *= rhs;
                else
                    lhs /= rhs;
                memcpy(destination, &lhs, sizeof(lhs));
            }
        }
        break;
    case CDISASM_X86_NAME_UCOMISS:
    case CDISASM_X86_NAME_COMISS:
    case CDISASM_X86_NAME_UCOMISD:
    case CDISASM_X86_NAME_COMISD:
        if (instruction.operand_count != 2u
            || instruction.opcode[0].type != CDISASM_OPERAND_REGISTER
            || instruction.opcode[0].reg < CDISASM_X86_REG_XMM0
            || instruction.opcode[0].reg > CDISASM_X86_REG_XMM15)
            return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
        {
            int single = instruction.name_id == CDISASM_X86_NAME_UCOMISS
                || instruction.name_id == CDISASM_X86_NAME_COMISS;
            size_t scalar_size = single ? sizeof(float) : sizeof(double);
            const uint8_t *lhs_bits = emulator->x86.xmm[
                instruction.opcode[0].reg - CDISASM_X86_REG_XMM0];
            uint64_t rhs_bits = 0u;
            int unordered, less, equal;
            if (instruction.opcode[1].type == CDISASM_OPERAND_REGISTER
                && instruction.opcode[1].reg >= CDISASM_X86_REG_XMM0
                && instruction.opcode[1].reg <= CDISASM_X86_REG_XMM15) {
                memcpy(&rhs_bits, emulator->x86.xmm[
                    instruction.opcode[1].reg - CDISASM_X86_REG_XMM0],
                    scalar_size);
            } else if (instruction.opcode[1].type == CDISASM_OPERAND_MEMORY
                && instruction.opcode[1].size == scalar_size) {
                status = xxemul_x86_read_operand(emulator, &instruction,
                    &instruction.opcode[1], next_ip, &rhs_bits);
                if (status != XXEMUL_STATUS_OK) return status;
            } else {
                return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
            }
            if (single) {
                float lhs, rhs;
                memcpy(&lhs, lhs_bits, sizeof(lhs));
                memcpy(&rhs, &rhs_bits, sizeof(rhs));
                unordered = lhs != lhs || rhs != rhs;
                less = lhs < rhs;
                equal = lhs == rhs;
            } else {
                double lhs, rhs;
                memcpy(&lhs, lhs_bits, sizeof(lhs));
                memcpy(&rhs, &rhs_bits, sizeof(rhs));
                unordered = lhs != lhs || rhs != rhs;
                less = lhs < rhs;
                equal = lhs == rhs;
            }
            emulator->x86.flags &= ~(XXEMUL_X86_FLAG_OF
                | XXEMUL_X86_FLAG_SF | XXEMUL_X86_FLAG_AF
                | XXEMUL_X86_FLAG_CF | XXEMUL_X86_FLAG_PF
                | XXEMUL_X86_FLAG_ZF);
            if (unordered)
                emulator->x86.flags |= XXEMUL_X86_FLAG_CF
                    | XXEMUL_X86_FLAG_PF | XXEMUL_X86_FLAG_ZF;
            else if (less)
                emulator->x86.flags |= XXEMUL_X86_FLAG_CF;
            else if (equal)
                emulator->x86.flags |= XXEMUL_X86_FLAG_ZF;
        }
        break;
    case CDISASM_X86_NAME_FUCOMPP:
    case CDISASM_X86_NAME_FCOMPP:
        if (emulator->x87_depth < 2u)
            return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
        emulator->x87_status &= UINT16_C(0xb8ff);
        if (emulator->x87_stack[0] != emulator->x87_stack[0]
            || emulator->x87_stack[1] != emulator->x87_stack[1]) {
            emulator->x87_status |= 0x4500u;
            if (instruction.name_id == CDISASM_X86_NAME_FCOMPP)
                emulator->x87_status |= 0x0001u;
        } else if (emulator->x87_stack[0] < emulator->x87_stack[1])
            emulator->x87_status |= 0x0100u;
        else if (emulator->x87_stack[0] == emulator->x87_stack[1])
            emulator->x87_status |= 0x4000u;
        status = xxemul_x87_pop(emulator);
        if (status == XXEMUL_STATUS_OK)
            status = xxemul_x87_pop(emulator);
        break;
    case CDISASM_X86_NAME_FNSTSW:
    case CDISASM_X86_NAME_FSTSW:
        if (instruction.operand_count != 1u
            || instruction.opcode[0].size != 2u)
            return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
        status = xxemul_x86_write_operand(emulator, &instruction,
            &instruction.opcode[0], next_ip,
            (emulator->x87_status & UINT16_C(0xc7ff))
                | ((uint16_t)emulator->x87_top << 11u));
        break;
    case CDISASM_X86_NAME_FNSTCW:
    case CDISASM_X86_NAME_FSTCW:
        if (instruction.operand_count != 1u
            || instruction.opcode[0].type != CDISASM_OPERAND_MEMORY
            || instruction.opcode[0].size != 2u)
            return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
        page_fault_error = UINT32_MAX;
        status = xxemul_x86_write_operand_tracked(emulator, &instruction,
            &instruction.opcode[0], next_ip, emulator->x87_control,
            &page_fault_error);
        status = xxemul_x86_dos_page_fault(emulator, status,
            page_fault_error, current_ip, &next_ip);
        break;
    case CDISASM_X86_NAME_FLDCW:
        if (instruction.operand_count != 1u
            || instruction.opcode[0].type != CDISASM_OPERAND_MEMORY
            || instruction.opcode[0].size != 2u)
            return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
        page_fault_error = UINT32_MAX;
        status = xxemul_x86_read_operand_tracked(emulator, &instruction,
            &instruction.opcode[0], next_ip, &right, &page_fault_error);
        if (status == XXEMUL_STATUS_OK)
            emulator->x87_control = (uint16_t)right;
        status = xxemul_x86_dos_page_fault(emulator, status,
            page_fault_error, current_ip, &next_ip);
        break;
    case CDISASM_X86_NAME_LAHF:
        emulator->x86.gpr[XXEMUL_X86_RAX] =
            (emulator->x86.gpr[XXEMUL_X86_RAX] & ~UINT64_C(0xff00))
            | (((emulator->x86.flags
                & (XXEMUL_X86_FLAG_SF | XXEMUL_X86_FLAG_ZF
                    | XXEMUL_X86_FLAG_AF | XXEMUL_X86_FLAG_PF
                    | XXEMUL_X86_FLAG_CF)) | UINT64_C(2)) << 8u);
        status = XXEMUL_STATUS_OK;
        break;
    case CDISASM_X86_NAME_SAHF:
        emulator->x86.flags = (emulator->x86.flags
            & ~(XXEMUL_X86_FLAG_SF | XXEMUL_X86_FLAG_ZF
                | XXEMUL_X86_FLAG_AF | XXEMUL_X86_FLAG_PF
                | XXEMUL_X86_FLAG_CF))
            | ((emulator->x86.gpr[XXEMUL_X86_RAX] >> 8u)
                & (XXEMUL_X86_FLAG_SF | XXEMUL_X86_FLAG_ZF
                    | XXEMUL_X86_FLAG_AF | XXEMUL_X86_FLAG_PF
                    | XXEMUL_X86_FLAG_CF)) | UINT64_C(2);
        status = XXEMUL_STATUS_OK;
        break;

    case CDISASM_X86_NAME_FXCH:
        if (instruction.operand_count != 1u
            || instruction.opcode[0].type != CDISASM_OPERAND_REGISTER
            || instruction.opcode[0].reg < CDISASM_X86_REG_ST0
            || instruction.opcode[0].reg > CDISASM_X86_REG_ST7)
            return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
        {
            size_t index = (size_t)(instruction.opcode[0].reg
                - CDISASM_X86_REG_ST0);
            double value;
            if (index >= emulator->x87_depth)
                return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
            value = emulator->x87_stack[0];
            emulator->x87_stack[0] = emulator->x87_stack[index];
            emulator->x87_stack[index] = value;
            {
                uint64_t int_tmp = emulator->x87_int_val[0];
                emulator->x87_int_val[0] = emulator->x87_int_val[index];
                emulator->x87_int_val[index] = int_tmp;
                uint8_t is_int_tmp = emulator->x87_is_int[0];
                emulator->x87_is_int[0] = emulator->x87_is_int[index];
                emulator->x87_is_int[index] = is_int_tmp;
            }
        }
        status = XXEMUL_STATUS_OK;
        break;
    case CDISASM_X86_NAME_FADD:
    case CDISASM_X86_NAME_FADDP:
    case CDISASM_X86_NAME_FMUL:
    case CDISASM_X86_NAME_FMULP:
    case CDISASM_X86_NAME_FSUB:
    case CDISASM_X86_NAME_FSUBP:
    case CDISASM_X86_NAME_FSUBR:
    case CDISASM_X86_NAME_FSUBRP:
    case CDISASM_X86_NAME_FDIV:
    case CDISASM_X86_NAME_FDIVP:
    case CDISASM_X86_NAME_FDIVR:
    case CDISASM_X86_NAME_FDIVRP:
        if (instruction.operand_count == 0u
            || emulator->x87_depth == 0u)
            return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
        {
            double operand_value;
            size_t destination = 0u;
            const cdisasm_opcode *source = &instruction.opcode[0];
            int pop = instruction.name_id == CDISASM_X86_NAME_FADDP
                || instruction.name_id == CDISASM_X86_NAME_FMULP
                || instruction.name_id == CDISASM_X86_NAME_FSUBP
                || instruction.name_id == CDISASM_X86_NAME_FSUBRP
                || instruction.name_id == CDISASM_X86_NAME_FDIVP
                || instruction.name_id == CDISASM_X86_NAME_FDIVRP;
            if (instruction.operand_count == 2u) {
                if (instruction.opcode[0].type != CDISASM_OPERAND_REGISTER
                    || instruction.opcode[0].reg < CDISASM_X86_REG_ST0
                    || instruction.opcode[0].reg > CDISASM_X86_REG_ST7)
                    return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
                destination = (size_t)(instruction.opcode[0].reg
                    - CDISASM_X86_REG_ST0);
                source = &instruction.opcode[1];
            }
            if (destination >= emulator->x87_depth)
                return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
            page_fault_error = UINT32_MAX;
            status = xxemul_x87_read(emulator, &instruction,
                source, next_ip, &operand_value, &page_fault_error);
            if (status != XXEMUL_STATUS_OK) {
                status = xxemul_x86_dos_page_fault(emulator, status,
                    page_fault_error, current_ip, &next_ip);
                break;
            }
            switch (instruction.name_id) {
            case CDISASM_X86_NAME_FADD:
            case CDISASM_X86_NAME_FADDP:
                emulator->x87_stack[destination] += operand_value;
                break;
            case CDISASM_X86_NAME_FMUL:
            case CDISASM_X86_NAME_FMULP:
                emulator->x87_stack[destination] *= operand_value;
                break;
            case CDISASM_X86_NAME_FSUB:
            case CDISASM_X86_NAME_FSUBP:
                emulator->x87_stack[destination] -= operand_value;
                break;
            case CDISASM_X86_NAME_FSUBR:
            case CDISASM_X86_NAME_FSUBRP:
                emulator->x87_stack[destination] = operand_value
                    - emulator->x87_stack[destination];
                break;
            case CDISASM_X86_NAME_FDIV:
            case CDISASM_X86_NAME_FDIVP:
                emulator->x87_stack[destination] /= operand_value;
                break;
            default:
                emulator->x87_stack[destination] = operand_value
                    / emulator->x87_stack[destination];
                break;
            }
            emulator->x87_is_int[destination] = 0;
            if (pop) {
                status = xxemul_x87_pop(emulator);
            } else {
                status = XXEMUL_STATUS_OK;
            }
        }
        break;
    case CDISASM_X86_NAME_FLD:
        if (instruction.operand_count != 1u)
            return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
        {
            double value;
            page_fault_error = UINT32_MAX;
            status = xxemul_x87_read(emulator, &instruction,
                &instruction.opcode[0], next_ip, &value,
                &page_fault_error);
            if (status == XXEMUL_STATUS_OK)
                status = xxemul_x87_push(emulator, value);
            else
                status = xxemul_x86_dos_page_fault(emulator, status,
                    page_fault_error, current_ip, &next_ip);
        }
        break;
    case CDISASM_X86_NAME_FLD1:
    case CDISASM_X86_NAME_FLDZ:
    case CDISASM_X86_NAME_FLDPI:
    case CDISASM_X86_NAME_FLDL2E:
    case CDISASM_X86_NAME_FLDL2T:
    case CDISASM_X86_NAME_FLDLG2:
    case CDISASM_X86_NAME_FLDLN2:
        if (instruction.operand_count != 0u)
            return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
        {
            double value;
            switch (instruction.name_id) {
            case CDISASM_X86_NAME_FLD1: value = 1.0; break;
            case CDISASM_X86_NAME_FLDZ: value = 0.0; break;
            case CDISASM_X86_NAME_FLDPI:
                value = 3.14159265358979323846; break;
            case CDISASM_X86_NAME_FLDL2E:
                value = 1.44269504088896340736; break;
            case CDISASM_X86_NAME_FLDL2T:
                value = 3.32192809488736234787; break;
            case CDISASM_X86_NAME_FLDLG2:
                value = 0.30102999566398119521; break;
            default:
                value = 0.69314718055994530942; break;
            }
            status = xxemul_x87_push(emulator, value);
        }
        break;
    case CDISASM_X86_NAME_FCHS:
    case CDISASM_X86_NAME_FABS:
        if (instruction.operand_count != 0u || emulator->x87_depth == 0u)
            return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
        if (instruction.name_id == CDISASM_X86_NAME_FCHS) {
            emulator->x87_stack[0] = -emulator->x87_stack[0];
        } else {
            uint64_t bits;
            memcpy(&bits, &emulator->x87_stack[0], sizeof(bits));
            bits &= ~(UINT64_C(1) << 63u);
            memcpy(&emulator->x87_stack[0], &bits, sizeof(bits));
        }
        status = XXEMUL_STATUS_OK;
        break;
    case CDISASM_X86_NAME_FILD:
        if (instruction.operand_count != 1u
            || instruction.opcode[0].type != CDISASM_OPERAND_MEMORY
            || (instruction.opcode[0].size != 2u
                && instruction.opcode[0].size != 4u
                && instruction.opcode[0].size != 8u)
            || emulator->x87_depth == 8u)
            return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
        status = xxemul_x86_read_operand(emulator, &instruction,
            &instruction.opcode[0], next_ip, &right);
        if (status != XXEMUL_STATUS_OK) return status;
        status = xxemul_x87_push_int(emulator,
            right, instruction.opcode[0].size);
        break;
    case CDISASM_X86_NAME_FST:
    case CDISASM_X86_NAME_FSTP:
        if (instruction.operand_count != 1u || emulator->x87_depth == 0u)
            return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
        if (instruction.opcode[0].type == CDISASM_OPERAND_REGISTER
            && instruction.opcode[0].reg >= CDISASM_X86_REG_ST0
            && instruction.opcode[0].reg <= CDISASM_X86_REG_ST7) {
            size_t reg_index = (size_t)(instruction.opcode[0].reg - CDISASM_X86_REG_ST0);
            if (reg_index >= emulator->x87_depth)
                return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
            emulator->x87_stack[reg_index] = emulator->x87_stack[0];
            emulator->x87_int_val[reg_index] = emulator->x87_int_val[0];
            emulator->x87_is_int[reg_index] = emulator->x87_is_int[0];
            if (instruction.name_id == CDISASM_X86_NAME_FSTP)
                status = xxemul_x87_pop(emulator);
            else
                status = XXEMUL_STATUS_OK;
            break;
        }
        if (instruction.opcode[0].type != CDISASM_OPERAND_MEMORY
            || (instruction.opcode[0].size != 4u
                && instruction.opcode[0].size != 8u))
            return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
        if (instruction.opcode[0].size == 4u) {
            float value = (float)emulator->x87_stack[0];
            uint32_t bits;
            memcpy(&bits, &value, sizeof(bits));
            right = bits;
        } else {
            memcpy(&right, &emulator->x87_stack[0], sizeof(right));
        }
        page_fault_error = UINT32_MAX;
        status = xxemul_x86_write_operand_tracked(emulator, &instruction,
            &instruction.opcode[0], next_ip, right, &page_fault_error);
        if (status == XXEMUL_STATUS_OK
            && instruction.name_id == CDISASM_X86_NAME_FSTP)
            status = xxemul_x87_pop(emulator);
        else if (status != XXEMUL_STATUS_OK)
            status = xxemul_x86_dos_page_fault(emulator, status,
                page_fault_error, current_ip, &next_ip);
        break;
    case CDISASM_X86_NAME_FIST:
    case CDISASM_X86_NAME_FISTP:
    case CDISASM_X86_NAME_FISTTP:
        if (instruction.operand_count != 1u
            || instruction.opcode[0].type != CDISASM_OPERAND_MEMORY
            || (instruction.opcode[0].size != 2u
                && instruction.opcode[0].size != 4u
                && instruction.opcode[0].size != 8u)
            || emulator->x87_depth == 0u)
            return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
        if (emulator->x87_is_int[0]) {
            if (instruction.opcode[0].size == 8u) right = emulator->x87_int_val[0];
            else if (instruction.opcode[0].size == 4u) right = (uint32_t)emulator->x87_int_val[0];
            else right = (uint16_t)emulator->x87_int_val[0];
        } else {
            right = xxemul_x87_convert_to_integer(
                emulator, emulator->x87_stack[0],
                instruction.opcode[0].size,
                instruction.name_id == CDISASM_X86_NAME_FISTTP);
        }
        page_fault_error = UINT32_MAX;
        status = xxemul_x86_write_operand_tracked(emulator, &instruction,
            &instruction.opcode[0], next_ip, right, &page_fault_error);
        if (status == XXEMUL_STATUS_OK
            && instruction.name_id != CDISASM_X86_NAME_FIST)
            status = xxemul_x87_pop(emulator);
        else if (status != XXEMUL_STATUS_OK)
            status = xxemul_x86_dos_page_fault(emulator, status,
                page_fault_error, current_ip, &next_ip);
        break;
    case CDISASM_X86_NAME_NOP:
    case CDISASM_X86_NAME_ENDBR32:
    case CDISASM_X86_NAME_ENDBR64:
    case CDISASM_X86_NAME_PAUSE:
    case CDISASM_X86_NAME_LFENCE:
    case CDISASM_X86_NAME_SFENCE:
    case CDISASM_X86_NAME_MFENCE:
    case CDISASM_X86_NAME_PREFETCH:
    case CDISASM_X86_NAME_PREFETCHW:
    case CDISASM_X86_NAME_PREFETCHNTA:
    case CDISASM_X86_NAME_PREFETCHT0:
    case CDISASM_X86_NAME_PREFETCHT1:
    case CDISASM_X86_NAME_PREFETCHT2:
    case CDISASM_X86_NAME_PREFETCHRST2:
    case CDISASM_X86_NAME_PREFETCHWT1:
    case CDISASM_X86_NAME_PREFETCHIT0:
    case CDISASM_X86_NAME_PREFETCHIT1:
    case CDISASM_X86_NAME_CLFLUSH:
    case CDISASM_X86_NAME_CLFLUSHOPT:
    case CDISASM_X86_NAME_CLWB:
        status = XXEMUL_STATUS_OK;
        break;
    case CDISASM_X86_NAME_XCHG:
        if (instruction.operand_count < 2u) {
            return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
        }
        status = xxemul_x86_read_operand(emulator, &instruction,
            &instruction.opcode[0], next_ip, &left);
        if (status != XXEMUL_STATUS_OK) return status;
        status = xxemul_x86_read_operand(emulator, &instruction,
            &instruction.opcode[1], next_ip, &right);
        if (status != XXEMUL_STATUS_OK) return status;
        status = xxemul_x86_write_operand(emulator, &instruction,
            &instruction.opcode[0], next_ip, right);
        if (status != XXEMUL_STATUS_OK) return status;
        status = xxemul_x86_write_operand(emulator, &instruction,
            &instruction.opcode[1], next_ip, left);
        break;
    case CDISASM_X86_NAME_CMPXCHG:
        if (instruction.operand_count < 2u
            || instruction.opcode[0].size == 0u
            || instruction.opcode[0].size > 8u)
            return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
        size = instruction.opcode[0].size;
        status = xxemul_x86_read_operand(emulator, &instruction,
            &instruction.opcode[0], next_ip, &left);
        if (status != XXEMUL_STATUS_OK) return status;
        status = xxemul_x86_read_operand(emulator, &instruction,
            &instruction.opcode[1], next_ip, &right);
        if (status != XXEMUL_STATUS_OK) return status;
        target = emulator->x86.gpr[XXEMUL_X86_RAX]
            & xxemul_mask_for_size(size);
        xxemul_x86_set_sub_flags(emulator, target, left,
            target - left, size);
        if (target == left) {
            status = xxemul_x86_write_operand(emulator, &instruction,
                &instruction.opcode[0], next_ip, right);
        } else {
            cdisasm_x86_reg_id accumulator = size == 1u
                ? CDISASM_X86_REG_AL : size == 2u
                ? CDISASM_X86_REG_AX : size == 4u
                ? CDISASM_X86_REG_EAX : CDISASM_X86_REG_RAX;
            status = xxemul_x86_write_register(
                emulator, accumulator, left);
        }
        break;
    case CDISASM_X86_NAME_XADD:
        if (instruction.operand_count < 2u
            || instruction.opcode[0].size == 0u
            || instruction.opcode[0].size > 8u)
            return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
        size = instruction.opcode[0].size;
        page_fault_error = UINT32_MAX;
        status = xxemul_x86_read_operand_tracked(emulator, &instruction,
            &instruction.opcode[0], next_ip, &left, &page_fault_error);
        if (status != XXEMUL_STATUS_OK) {
            status = xxemul_x86_dos_page_fault(emulator, status,
                page_fault_error, current_ip, &next_ip);
            break;
        }
        status = xxemul_x86_read_operand(emulator, &instruction,
            &instruction.opcode[1], next_ip, &right);
        if (status != XXEMUL_STATUS_OK) return status;
        target = (left + right) & xxemul_mask_for_size(size);
        xxemul_x86_set_add_flags(emulator, left, right, target, size);
        status = xxemul_x86_write_operand(emulator, &instruction,
            &instruction.opcode[1], next_ip, left);
        if (status != XXEMUL_STATUS_OK) return status;
        page_fault_error = UINT32_MAX;
        status = xxemul_x86_write_operand_tracked(emulator, &instruction,
            &instruction.opcode[0], next_ip, target, &page_fault_error);
        if (status != XXEMUL_STATUS_OK)
            status = xxemul_x86_dos_page_fault(emulator, status,
                page_fault_error, current_ip, &next_ip);
        break;
    case CDISASM_X86_NAME_IMUL:
        if (instruction.operand_count == 1u) {
            int overflow;
            if (instruction.opcode[0].size != 1u
                && instruction.opcode[0].size != 2u
                && instruction.opcode[0].size != 4u
                && instruction.opcode[0].size != 8u)
                return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
            size = instruction.opcode[0].size;
            status = xxemul_x86_read_operand(emulator, &instruction,
                &instruction.opcode[0], next_ip, &right);
            if (status != XXEMUL_STATUS_OK) return status;
            left = emulator->x86.gpr[XXEMUL_X86_RAX]
                & xxemul_mask_for_size(size);
            right &= xxemul_mask_for_size(size);
            if (size == 8u) {
                xxemul_x86_multiply_u64(left, right, &target, &saved_cf);
                if ((int64_t)left < 0) saved_cf -= right;
                if ((int64_t)right < 0) saved_cf -= left;
                overflow = saved_cf != ((int64_t)target < 0
                    ? UINT64_MAX : 0u);
            } else {
                int64_t product =
                    (int64_t)xxemul_sign_extend(left, size)
                    * (int64_t)xxemul_sign_extend(right, size);
                uint64_t full = (uint64_t)product;
                target = full & xxemul_mask_for_size(size);
                saved_cf = (full >> (size * 8u))
                    & xxemul_mask_for_size(size);
                overflow = product !=
                    (int64_t)xxemul_sign_extend(target, size);
            }
            if (size == 1u) {
                status = xxemul_x86_write_register(emulator,
                    CDISASM_X86_REG_AX, target | (saved_cf << 8u));
            } else {
                status = xxemul_x86_write_register(emulator,
                    size == 2u ? CDISASM_X86_REG_AX
                        : size == 4u ? CDISASM_X86_REG_EAX
                        : CDISASM_X86_REG_RAX, target);
                if (status == XXEMUL_STATUS_OK)
                    status = xxemul_x86_write_register(emulator,
                        size == 2u ? CDISASM_X86_REG_DX
                            : size == 4u ? CDISASM_X86_REG_EDX
                            : CDISASM_X86_REG_RDX, saved_cf);
            }
            emulator->x86.flags &= ~(XXEMUL_X86_FLAG_CF | XXEMUL_X86_FLAG_OF);
            if (overflow)
                emulator->x86.flags |= XXEMUL_X86_FLAG_CF | XXEMUL_X86_FLAG_OF;
            break;
        }
        if (instruction.operand_count < 2u
            || instruction.operand_count > 3u
            || instruction.opcode[0].size < 2u
            || instruction.opcode[0].size > 8u)
            return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
        size = instruction.opcode[0].size;
        status = xxemul_x86_read_operand(emulator, &instruction,
            &instruction.opcode[instruction.operand_count == 2u ? 0u : 1u],
            next_ip, &left);
        if (status != XXEMUL_STATUS_OK) return status;
        status = xxemul_x86_read_operand(emulator, &instruction,
            &instruction.opcode[instruction.operand_count == 2u ? 1u : 2u],
            next_ip, &right);
        if (status != XXEMUL_STATUS_OK) return status;
        {
            int overflow;
            uint64_t result;
            if (size < 8u) {
                int64_t product = (int64_t)xxemul_sign_extend(left, size)
                    * (int64_t)xxemul_sign_extend(right, size);
                int64_t limit = INT64_C(1) << (size * 8u - 1u);
                overflow = product < -limit || product >= limit;
                result = (uint64_t)product & xxemul_mask_for_size(size);
            } else {
                int64_t signed_left = (int64_t)left;
                int64_t signed_right = (int64_t)right;
                uint64_t abs_left = signed_left < 0
                    ? UINT64_C(0) - left : left;
                uint64_t abs_right = signed_right < 0
                    ? UINT64_C(0) - right : right;
                uint64_t limit = (signed_left < 0) != (signed_right < 0)
                    ? UINT64_C(0x8000000000000000)
                    : UINT64_C(0x7fffffffffffffff);
                overflow = abs_left != 0u && abs_right > limit / abs_left;
                result = left * right;
            }
            emulator->x86.flags &= ~(XXEMUL_X86_FLAG_CF | XXEMUL_X86_FLAG_OF);
            if (overflow)
                emulator->x86.flags |= XXEMUL_X86_FLAG_CF | XXEMUL_X86_FLAG_OF;
            status = xxemul_x86_write_operand(emulator, &instruction,
                &instruction.opcode[0], next_ip, result);
        }
        break;
    case CDISASM_X86_NAME_MUL:
        if (instruction.operand_count != 1u
            || (instruction.opcode[0].size != 1u
                && instruction.opcode[0].size != 2u
                && instruction.opcode[0].size != 4u
                && instruction.opcode[0].size != 8u))
            return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
        size = instruction.opcode[0].size;
        status = xxemul_x86_read_operand(emulator, &instruction,
            &instruction.opcode[0], next_ip, &right);
        if (status != XXEMUL_STATUS_OK) return status;
        left = emulator->x86.gpr[XXEMUL_X86_RAX]
            & xxemul_mask_for_size(size);
        right &= xxemul_mask_for_size(size);
        if (size == 8u) {
            xxemul_x86_multiply_u64(left, right, &target, &saved_cf);
        } else {
            uint64_t product = left * right;
            target = product & xxemul_mask_for_size(size);
            saved_cf = product >> (size * 8u);
        }
        if (size == 1u) {
            status = xxemul_x86_write_register(emulator,
                CDISASM_X86_REG_AX, target | (saved_cf << 8u));
        } else {
            status = xxemul_x86_write_register(emulator,
                size == 2u ? CDISASM_X86_REG_AX
                    : size == 4u ? CDISASM_X86_REG_EAX
                    : CDISASM_X86_REG_RAX, target);
            if (status == XXEMUL_STATUS_OK)
                status = xxemul_x86_write_register(emulator,
                    size == 2u ? CDISASM_X86_REG_DX
                        : size == 4u ? CDISASM_X86_REG_EDX
                        : CDISASM_X86_REG_RDX, saved_cf);
        }
        emulator->x86.flags &= ~(XXEMUL_X86_FLAG_CF | XXEMUL_X86_FLAG_OF);
        if (saved_cf != 0u)
            emulator->x86.flags |= XXEMUL_X86_FLAG_CF | XXEMUL_X86_FLAG_OF;
        break;
    case CDISASM_X86_NAME_DIV:
    case CDISASM_X86_NAME_IDIV:
        if (instruction.operand_count != 1u
            || (instruction.opcode[0].size != 1u
                && instruction.opcode[0].size != 2u
                && instruction.opcode[0].size != 4u
                && instruction.opcode[0].size != 8u))
            return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
        size = instruction.opcode[0].size;
        status = xxemul_x86_read_operand(emulator, &instruction,
            &instruction.opcode[0], next_ip, &right);
        if (status != XXEMUL_STATUS_OK) return status;
        if ((right & xxemul_mask_for_size(size)) == 0u)
            return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
        if (size == 8u) {
            uint64_t low = emulator->x86.gpr[XXEMUL_X86_RAX];
            uint64_t high = emulator->x86.gpr[XXEMUL_X86_RDX];
            uint64_t divisor = right, quotient, remainder;
            int negative_dividend = (int)(high >> 63u);
            int negative_divisor = (int)(right >> 63u);
            if (instruction.name_id == CDISASM_X86_NAME_IDIV) {
                if (negative_dividend) {
                    low = ~low + 1u;
                    high = ~high + (low == 0u ? 1u : 0u);
                }
                if (negative_divisor) divisor = ~divisor + 1u;
            }
            if (!xxemul_x86_divide_u128(high, low, divisor,
                    &quotient, &remainder))
                return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
            if (instruction.name_id == CDISASM_X86_NAME_IDIV) {
                uint64_t limit = negative_dividend != negative_divisor
                    ? UINT64_C(0x8000000000000000)
                    : UINT64_C(0x7fffffffffffffff);
                if (quotient > limit)
                    return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
                if (negative_dividend != negative_divisor)
                    quotient = ~quotient + 1u;
                if (negative_dividend)
                    remainder = ~remainder + 1u;
            }
            status = xxemul_x86_write_register(emulator,
                CDISASM_X86_REG_RAX, quotient);
            if (status == XXEMUL_STATUS_OK)
                status = xxemul_x86_write_register(emulator,
                    CDISASM_X86_REG_RDX, remainder);
            break;
        }
        {
            uint64_t quotient;
            uint64_t remainder;
            uint64_t dividend = size == 1u
                ? emulator->x86.gpr[XXEMUL_X86_RAX] & UINT16_MAX
                : size == 2u
                    ? ((emulator->x86.gpr[XXEMUL_X86_RDX] & UINT16_MAX) << 16u)
                        | (emulator->x86.gpr[XXEMUL_X86_RAX] & UINT16_MAX)
                    : ((emulator->x86.gpr[XXEMUL_X86_RDX] & UINT32_MAX) << 32u)
                        | (emulator->x86.gpr[XXEMUL_X86_RAX] & UINT32_MAX);
            if (instruction.name_id == CDISASM_X86_NAME_IDIV) {
                int64_t signed_dividend = size == 1u
                    ? (int16_t)dividend
                    : size == 2u ? (int32_t)dividend
                    : (int64_t)(int32_t)(dividend >> 32u)
                        * INT64_C(4294967296)
                        + (int64_t)(uint32_t)dividend;
                int64_t divisor = (int64_t)xxemul_sign_extend(right, size);
                int64_t signed_quotient;
                int64_t limit = INT64_C(1) << (size * 8u - 1u);
                if (signed_dividend == INT64_MIN && divisor == -1)
                    return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
                signed_quotient = signed_dividend / divisor;
                if (signed_quotient < -limit || signed_quotient >= limit)
                    return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
                quotient = (uint64_t)signed_quotient
                    & xxemul_mask_for_size(size);
                remainder = (uint64_t)(signed_dividend % divisor)
                    & xxemul_mask_for_size(size);
            } else {
                uint64_t divisor = right & xxemul_mask_for_size(size);
                quotient = dividend / divisor;
                remainder = dividend % divisor;
                if (quotient > xxemul_mask_for_size(size))
                    return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
            }
            if (size == 1u) {
                status = xxemul_x86_write_register(emulator,
                    CDISASM_X86_REG_AX,
                    quotient | (remainder << 8u));
            } else {
                status = xxemul_x86_write_register(emulator,
                    size == 2u ? CDISASM_X86_REG_AX
                        : CDISASM_X86_REG_EAX, quotient);
                if (status == XXEMUL_STATUS_OK)
                    status = xxemul_x86_write_register(emulator,
                        size == 2u ? CDISASM_X86_REG_DX
                            : CDISASM_X86_REG_EDX, remainder);
            }
        }
        break;
    case CDISASM_X86_NAME_BSWAP:
        if (instruction.operand_count < 1u
            || instruction.opcode[0].type != CDISASM_OPERAND_REGISTER
            || (instruction.opcode[0].size != 4u
                && instruction.opcode[0].size != 8u)) {
            return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
        }
        status = xxemul_x86_read_operand(emulator, &instruction,
            &instruction.opcode[0], next_ip, &left);
        if (status != XXEMUL_STATUS_OK) return status;
        right = 0u;
        for (size = 0u; size < instruction.opcode[0].size; ++size) {
            right = (right << 8u) | ((left >> (size * 8u)) & 0xffu);
        }
        status = xxemul_x86_write_operand(emulator, &instruction,
            &instruction.opcode[0], next_ip, right);
        break;
    case CDISASM_X86_NAME_SHL:
    case CDISASM_X86_NAME_SHR:
    case CDISASM_X86_NAME_SAR:
    case CDISASM_X86_NAME_ROL:
    case CDISASM_X86_NAME_ROR:
        status = xxemul_x86_shift(emulator, &instruction, next_ip);
        break;
    case CDISASM_X86_NAME_SHLD:
    case CDISASM_X86_NAME_SHRD:
        if (instruction.operand_count < 3u
            || instruction.opcode[0].size < 2u
            || instruction.opcode[0].size > 8u)
            return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
        size = instruction.opcode[0].size;
        status = xxemul_x86_read_operand(emulator, &instruction,
            &instruction.opcode[0], next_ip, &left);
        if (status != XXEMUL_STATUS_OK) return status;
        status = xxemul_x86_read_operand(emulator, &instruction,
            &instruction.opcode[1], next_ip, &right);
        if (status != XXEMUL_STATUS_OK) return status;
        status = xxemul_x86_read_operand(emulator, &instruction,
            &instruction.opcode[2], next_ip, &target);
        if (status != XXEMUL_STATUS_OK) return status;
        target &= size == 8u ? 63u : 31u;
        if (target == 0u) {
            status = XXEMUL_STATUS_OK;
            break;
        }
        if (target > (uint64_t)size * 8u)
            return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
        {
            uint64_t bits = (uint64_t)size * 8u;
            uint64_t sign = UINT64_C(1) << (bits - 1u);
            uint64_t result;
            uint64_t carry;
            left &= xxemul_mask_for_size(size);
            right &= xxemul_mask_for_size(size);
            if (instruction.name_id == CDISASM_X86_NAME_SHLD) {
                result = target == bits ? right
                    : (left << target) | (right >> (bits - target));
                carry = (left >> (bits - target)) & 1u;
            } else {
                result = target == bits ? right
                    : (left >> target) | (right << (bits - target));
                carry = (left >> (target - 1u)) & 1u;
            }
            result &= xxemul_mask_for_size(size);
            emulator->x86.flags &= ~(XXEMUL_X86_FLAG_CF | XXEMUL_X86_FLAG_OF);
            if (carry != 0u) emulator->x86.flags |= XXEMUL_X86_FLAG_CF;
            if (target == 1u && ((left ^ result) & sign) != 0u)
                emulator->x86.flags |= XXEMUL_X86_FLAG_OF;
            xxemul_x86_set_szp_flags(emulator, result, size);
            status = xxemul_x86_write_operand(emulator, &instruction,
                &instruction.opcode[0], next_ip, result);
        }
        break;
    case CDISASM_X86_NAME_NEG:
    case CDISASM_X86_NAME_NOT:
        if (instruction.operand_count < 1u
            || instruction.opcode[0].size == 0u
            || instruction.opcode[0].size > 8u) {
            return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
        }
        size = instruction.opcode[0].size;
        status = xxemul_x86_read_operand(emulator, &instruction,
            &instruction.opcode[0], next_ip, &left);
        if (status != XXEMUL_STATUS_OK) return status;
        right = instruction.name_id == CDISASM_X86_NAME_NEG
            ? (UINT64_C(0) - left) & xxemul_mask_for_size(size)
            : (~left) & xxemul_mask_for_size(size);
        if (instruction.name_id == CDISASM_X86_NAME_NEG)
            xxemul_x86_set_sub_flags(emulator, 0u, left, right, size);
        status = xxemul_x86_write_operand(emulator, &instruction,
            &instruction.opcode[0], next_ip, right);
        break;
    case CDISASM_X86_NAME_BT:
    case CDISASM_X86_NAME_BTC:
    case CDISASM_X86_NAME_BTR:
    case CDISASM_X86_NAME_BTS:
        if (instruction.operand_count < 2u
            || (instruction.opcode[0].type != CDISASM_OPERAND_REGISTER
                && instruction.opcode[0].type != CDISASM_OPERAND_MEMORY)
            || instruction.opcode[0].size == 0u
            || instruction.opcode[0].size > 8u) {
            return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
        }
        status = xxemul_x86_read_operand(emulator, &instruction,
            &instruction.opcode[1], next_ip, &right);
        if (status != XXEMUL_STATUS_OK) return status;
        {
            uint64_t memory_address = 0u;
            uint8_t operand_size = instruction.opcode[0].size;
            uint8_t width = (uint8_t)(operand_size * 8u);
            if (instruction.opcode[0].type == CDISASM_OPERAND_MEMORY) {
                status = xxemul_x86_effective_address(emulator,
                    &instruction, &instruction.opcode[0],
                    next_ip, &memory_address);
                if (status != XXEMUL_STATUS_OK) return status;
                if (instruction.opcode[1].type == CDISASM_OPERAND_REGISTER) {
                    int64_t index = (int64_t)xxemul_sign_extend(
                        right, instruction.opcode[1].size);
                    int64_t word = index / width;
                    if (index < 0 && index % width != 0) --word;
                    size = (uint8_t)(index - word * width);
                    memory_address += (uint64_t)(word * operand_size);
                    if (!emulator->dos_mode)
                        memory_address &= xxemul_x86_address_mask(emulator);
                } else {
                    size = (uint8_t)(right & (width - 1u));
                }
                status = xxemul_x86_guest_load_integer(emulator,
                    memory_address, operand_size, &left);
            } else {
                size = (uint8_t)(right & (width - 1u));
                status = xxemul_x86_read_operand(emulator,
                    &instruction, &instruction.opcode[0], next_ip, &left);
            }
            if (status != XXEMUL_STATUS_OK) return status;
            if ((left & (UINT64_C(1) << size)) != 0u)
                emulator->x86.flags |= XXEMUL_X86_FLAG_CF;
            else
                emulator->x86.flags &= ~XXEMUL_X86_FLAG_CF;
            if (instruction.name_id == CDISASM_X86_NAME_BT) {
                status = XXEMUL_STATUS_OK;
            } else {
                if (instruction.name_id == CDISASM_X86_NAME_BTC)
                    left ^= UINT64_C(1) << size;
                else if (instruction.name_id == CDISASM_X86_NAME_BTR)
                    left &= ~(UINT64_C(1) << size);
                else
                    left |= UINT64_C(1) << size;
                status = instruction.opcode[0].type == CDISASM_OPERAND_MEMORY
                    ? xxemul_x86_guest_store_integer(emulator,
                        memory_address, operand_size, left)
                    : xxemul_x86_write_operand(emulator, &instruction,
                        &instruction.opcode[0], next_ip, left);
            }
        }
        break;
    case CDISASM_X86_NAME_MOVSB:
    case CDISASM_X86_NAME_MOVSW:
    case CDISASM_X86_NAME_MOVSQ:
    case CDISASM_X86_NAME_STOSB:
    case CDISASM_X86_NAME_STOSW:
    case CDISASM_X86_NAME_STOSD:
    case CDISASM_X86_NAME_STOSQ:
    case CDISASM_X86_NAME_LODSB:
    case CDISASM_X86_NAME_LODSW:
    case CDISASM_X86_NAME_LODSD:
    case CDISASM_X86_NAME_LODSQ:
    case CDISASM_X86_NAME_CMPSB:
    case CDISASM_X86_NAME_CMPSW:
    case CDISASM_X86_NAME_CMPSD:
    case CDISASM_X86_NAME_CMPSQ:
    case CDISASM_X86_NAME_SCASB:
    case CDISASM_X86_NAME_SCASW:
    case CDISASM_X86_NAME_SCASD:
    case CDISASM_X86_NAME_SCASQ:
        status = xxemul_x86_string(emulator, &instruction,
            current_ip, &next_ip);
        break;
    case CDISASM_X86_NAME_PUSHA:
    case CDISASM_X86_NAME_PUSHAD:
        if ((instruction.name_id == CDISASM_X86_NAME_PUSHA
                && emulator->mode != XXEMUL_MODE_X86_16)
            || (instruction.name_id == CDISASM_X86_NAME_PUSHAD
                && emulator->mode != XXEMUL_MODE_X86_32)) {
            return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
        }
        {
            static const uint8_t order[8] = {
                XXEMUL_X86_RAX, XXEMUL_X86_RCX, XXEMUL_X86_RDX,
                XXEMUL_X86_RBX, XXEMUL_X86_RSP, XXEMUL_X86_RBP,
                XXEMUL_X86_RSI, XXEMUL_X86_RDI
            };
            uint64_t pusha_original_sp = emulator->x86.gpr[XXEMUL_X86_RSP];
            unsigned i;
            status = XXEMUL_STATUS_OK;
            for (i = 0u; i < 8u && status == XXEMUL_STATUS_OK; ++i) {
                status = xxemul_x86_push(emulator,
                    order[i] == XXEMUL_X86_RSP
                        ? pusha_original_sp : emulator->x86.gpr[order[i]]);
            }
        }
        break;
    case CDISASM_X86_NAME_POPA:
    case CDISASM_X86_NAME_POPAD:
        if ((instruction.name_id == CDISASM_X86_NAME_POPA
                && emulator->mode != XXEMUL_MODE_X86_16)
            || (instruction.name_id == CDISASM_X86_NAME_POPAD
                && emulator->mode != XXEMUL_MODE_X86_32)) {
            return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
        }
        {
            static const uint8_t order[8] = {
                XXEMUL_X86_RDI, XXEMUL_X86_RSI, XXEMUL_X86_RBP,
                XXEMUL_X86_RSP, XXEMUL_X86_RBX, XXEMUL_X86_RDX,
                XXEMUL_X86_RCX, XXEMUL_X86_RAX
            };
            unsigned i;
            status = XXEMUL_STATUS_OK;
            for (i = 0u; i < 8u && status == XXEMUL_STATUS_OK; ++i) {
                status = xxemul_x86_pop(emulator, &right);
                if (status == XXEMUL_STATUS_OK
                    && order[i] != XXEMUL_X86_RSP) {
                    emulator->x86.gpr[order[i]] = right;
                }
            }
        }
        break;
    case CDISASM_X86_NAME_CLC:
        emulator->x86.flags &= ~XXEMUL_X86_FLAG_CF;
        status = XXEMUL_STATUS_OK;
        break;
    case CDISASM_X86_NAME_STC:
        emulator->x86.flags |= XXEMUL_X86_FLAG_CF;
        status = XXEMUL_STATUS_OK;
        break;
    case CDISASM_X86_NAME_CLI:
        emulator->x86.flags &= ~XXEMUL_X86_FLAG_IF;
        status = XXEMUL_STATUS_OK;
        break;
    case CDISASM_X86_NAME_STI:
        emulator->x86.flags |= XXEMUL_X86_FLAG_IF;
        status = XXEMUL_STATUS_OK;
        break;
    case CDISASM_X86_NAME_CLD:
        emulator->x86.flags &= ~XXEMUL_X86_FLAG_DF;
        status = XXEMUL_STATUS_OK;
        break;
    case CDISASM_X86_NAME_STD:
        emulator->x86.flags |= XXEMUL_X86_FLAG_DF;
        status = XXEMUL_STATUS_OK;
        break;
    case CDISASM_X86_NAME_PUSHF:
    case CDISASM_X86_NAME_PUSHFD:
    case CDISASM_X86_NAME_PUSHFQ:
        size = instruction.name_id == CDISASM_X86_NAME_PUSHFD ? 4u
            : instruction.name_id == CDISASM_X86_NAME_PUSHFQ ? 8u : 2u;
        page_fault_error = UINT32_MAX;
        status = xxemul_x86_push_width_tracked(emulator,
            emulator->x86.flags, size, &page_fault_error);
        status = xxemul_x86_dos_page_fault(emulator, status,
            page_fault_error, current_ip, &next_ip);
        break;
    case CDISASM_X86_NAME_POPF:
    case CDISASM_X86_NAME_POPFD:
    case CDISASM_X86_NAME_POPFQ:
        size = instruction.name_id == CDISASM_X86_NAME_POPFD ? 4u
            : instruction.name_id == CDISASM_X86_NAME_POPFQ ? 8u : 2u;
        page_fault_error = UINT32_MAX;
        status = xxemul_x86_pop_width_tracked(emulator,
            &right, size, &page_fault_error);
        if (status == XXEMUL_STATUS_OK) {
            emulator->x86.flags = (right & xxemul_mask_for_size(size))
                | UINT64_C(2);
        } else {
            status = xxemul_x86_dos_page_fault(emulator, status,
                page_fault_error, current_ip, &next_ip);
        }
        break;
    case CDISASM_X86_NAME_LEAVE:
        original_sp = emulator->x86.gpr[XXEMUL_X86_RSP];
        size = xxemul_x86_mode_size(emulator);
        emulator->x86.gpr[XXEMUL_X86_RSP] =
            emulator->x86.gpr[XXEMUL_X86_RBP]
            & xxemul_x86_stack_mask(emulator);
        page_fault_error = UINT32_MAX;
        status = xxemul_x86_pop_width_tracked(emulator,
            &right, size, &page_fault_error);
        if (status == XXEMUL_STATUS_OK)
            emulator->x86.gpr[XXEMUL_X86_RBP] = right;
        else
            status = xxemul_x86_dos_stack_fault(emulator, status,
                page_fault_error, original_sp, current_ip, &next_ip);
        break;
    case CDISASM_X86_NAME_ENTER:
        if (instruction.operand_count != 2u)
            return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
        {
            uint64_t allocation;
            uint64_t nesting;
            uint64_t frame_pointer;
            uint64_t frame_sp;
            uint64_t mask = xxemul_x86_stack_mask(emulator);
            unsigned index;
            size = xxemul_x86_mode_size(emulator);
            status = xxemul_x86_read_operand(emulator, &instruction,
                &instruction.opcode[0], next_ip, &allocation);
            if (status != XXEMUL_STATUS_OK) return status;
            status = xxemul_x86_read_operand(emulator, &instruction,
                &instruction.opcode[1], next_ip, &nesting);
            if (status != XXEMUL_STATUS_OK) return status;
            nesting &= 31u;
            frame_pointer = emulator->x86.gpr[XXEMUL_X86_RBP] & mask;
            status = xxemul_x86_push_width(emulator, frame_pointer, size);
            if (status != XXEMUL_STATUS_OK) return status;
            frame_sp = emulator->x86.gpr[XXEMUL_X86_RSP] & mask;
            for (index = 1u; index < nesting; ++index) {
                uint64_t address;
                uint64_t value;
                frame_pointer = (frame_pointer - size) & mask;
                address = frame_pointer;
                if (emulator->dos_mode) {
                    status = xxemul_x86_dos_address(emulator,
                        XXEMUL_X86_SS, frame_pointer, size, &address);
                    if (status != XXEMUL_STATUS_OK) return status;
                }
                status = xxemul_x86_guest_load_integer(
                    emulator, address, size, &value);
                if (status != XXEMUL_STATUS_OK) return status;
                status = xxemul_x86_push_width(emulator, value, size);
                if (status != XXEMUL_STATUS_OK) return status;
            }
            if (nesting != 0u) {
                status = xxemul_x86_push_width(emulator, frame_sp, size);
                if (status != XXEMUL_STATUS_OK) return status;
            }
            emulator->x86.gpr[XXEMUL_X86_RBP] =
                (emulator->x86.gpr[XXEMUL_X86_RBP] & ~mask) | frame_sp;
            emulator->x86.gpr[XXEMUL_X86_RSP] =
                (emulator->x86.gpr[XXEMUL_X86_RSP] - (uint16_t)allocation)
                & mask;
        }
        break;
    case CDISASM_X86_NAME_INT:
        if (instruction.operand_count < 1u) {
            return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
        }
        status = xxemul_x86_read_operand(
            emulator, &instruction, &instruction.opcode[0], next_ip, &right);
        if (status != XXEMUL_STATUS_OK) {
            return status;
        }
        if (right == 3u && emulator->debug_traps && !emulator->dos_mode) {
            status = XXEMUL_STATUS_BREAKPOINT;
            break;
        }
        if (emulator->dos_mode && (emulator->dos_cr0 & 1u) != 0u) {
            if (right > 0xffu)
                return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
            if (emulator->dos_dpmi_next_selector != 0u
                && right == 0x31u) {
                status = xxemul_dpmi_interrupt(emulator);
                break;
            }
            if (emulator->dos_dpmi_next_selector != 0u
                && right == 0x21u) {
                status = xxemul_msdos_interrupt(emulator, 0x21u);
                break;
            }
            if (emulator->dos_dpmi_next_selector != 0u
                && right == 0x1au) {
                status = xxemul_bios_interrupt(emulator, 0x1au);
                break;
            }
            status = xxemul_x86_dos_interrupt_gate(emulator,
                (uint8_t)right, (uint32_t)next_ip, 0, 0u, &next_ip);
            break;
        }
        if (emulator->dos_mode && right <= 0xffu) {
            uint64_t vector_offset;
            uint64_t vector_segment;
            status = xxemul_load_integer(emulator, right * 4u,
                2u, &vector_offset);
            if (status != XXEMUL_STATUS_OK) return status;
            status = xxemul_load_integer(emulator, right * 4u + 2u,
                2u, &vector_segment);
            if (status != XXEMUL_STATUS_OK) return status;
            if (right == 0x21u
                && vector_offset == XXEMUL_DOS_INT21_THUNK_OFFSET
                && vector_segment == XXEMUL_DOS_INT21_THUNK_SEGMENT) {
                status = xxemul_msdos_interrupt(emulator, 0x21u);
                break;
            }
            if (vector_offset != 0u || vector_segment != 0u
                || right == 0x21u) {
                status = xxemul_x86_push_width(emulator,
                    emulator->x86.flags, 2u);
                if (status != XXEMUL_STATUS_OK) return status;
                status = xxemul_x86_push_width(emulator,
                    emulator->x86.segment[XXEMUL_X86_CS], 2u);
                if (status != XXEMUL_STATUS_OK) return status;
                status = xxemul_x86_push_width(emulator, next_ip, 2u);
                if (status != XXEMUL_STATUS_OK) return status;
                status = xxemul_x86_load_dos_segment(emulator,
                    XXEMUL_X86_CS, (uint16_t)vector_segment);
                if (status != XXEMUL_STATUS_OK) return status;
                emulator->x86.flags &= ~(XXEMUL_X86_FLAG_IF
                    | XXEMUL_X86_FLAG_TF);
                next_ip = (uint16_t)vector_offset;
                break;
            }
        }
        if (emulator->linux_process != NULL && right == 0x80u) {
            status = xxemul_linux_dispatch(emulator->linux_process);
            if (status == XXEMUL_STATUS_HALTED) emulator->halted = 1;
        } else if (emulator->windows != NULL && right == 0x29u) {
            fprintf(stderr, "[xxemul] Windows __fastfail (code 0x%llx)\n",
                (unsigned long long)emulator->x86.gpr[XXEMUL_X86_RCX]);
            status = XXEMUL_STATUS_HALTED;
            emulator->halted = 1;
        } else if (emulator->dos_mode) {
            status = (right == 0x20u || right == 0x21u || right == 0x29u)
                ? xxemul_msdos_interrupt(emulator, (uint8_t)right)
                : xxemul_bios_interrupt(emulator, (uint8_t)right);
        } else {
            status = XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
        }
        break;
    case CDISASM_X86_NAME_IRET:
    case CDISASM_X86_NAME_IRETD:
        if (!emulator->dos_mode)
            return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
        if ((emulator->dos_cr0 & 1u) != 0u) {
            size = instruction.name_id == CDISASM_X86_NAME_IRETD
                ? 4u : 2u;
            if (size != 2u && size != 4u)
                return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
            status = xxemul_x86_dos_protected_iret(
                emulator, size, &next_ip);
            break;
        }
        if (instruction.name_id == CDISASM_X86_NAME_IRETD)
            return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
        if (emulator->x86.segment[XXEMUL_X86_CS]
                == XXEMUL_DOS_INT21_THUNK_SEGMENT
            && (current_ip == XXEMUL_DOS_INT21_THUNK_OFFSET
                || current_ip == XXEMUL_DOS_INT10_THUNK_OFFSET)) {
            status = xxemul_x86_dos_host_thunk(emulator,
                current_ip == XXEMUL_DOS_INT21_THUNK_OFFSET
                    ? 0x21u : 0x10u);
            if (status != XXEMUL_STATUS_OK) break;
        }
        status = xxemul_x86_pop_width(emulator, &target, 2u);
        if (status != XXEMUL_STATUS_OK) return status;
        status = xxemul_x86_pop_width(emulator, &right, 2u);
        if (status != XXEMUL_STATUS_OK) return status;
        status = xxemul_x86_load_dos_segment(emulator,
            XXEMUL_X86_CS, (uint16_t)right);
        if (status != XXEMUL_STATUS_OK) return status;
        status = xxemul_x86_pop_width(emulator, &right, 2u);
        if (status != XXEMUL_STATUS_OK) return status;
        emulator->x86.flags = (uint16_t)right | UINT64_C(2);
        next_ip = (uint16_t)target;
        break;
    case CDISASM_X86_NAME_SYSCALL:
        if (emulator->linux_process == NULL
            || emulator->mode != XXEMUL_MODE_X86_64) {
            return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
        }
        emulator->x86.gpr[XXEMUL_X86_RCX] = next_ip;
        emulator->x86.gpr[XXEMUL_X86_R11] = emulator->x86.flags;
        status = xxemul_linux_dispatch(emulator->linux_process);
        if (status == XXEMUL_STATUS_HALTED) emulator->halted = 1;
        break;
    case CDISASM_X86_NAME_SMSW:
        if (!emulator->dos_mode || instruction.operand_count < 1u)
            return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
        status = xxemul_x86_write_operand(emulator, &instruction,
            &instruction.opcode[0], next_ip, emulator->dos_cr0 | 0x10u);
        break;
    case CDISASM_X86_NAME_XLATB:
        {
            uint8_t address_size = xxemul_x86_mode_size(emulator);
            uint64_t address;
            uint64_t value;

            if ((instruction.opcode_flags & CDISASM_PREFIX_ADDRESS_SIZE) != 0u)
                address_size = emulator->mode == XXEMUL_MODE_X86_16
                    ? 4u : 2u;
            address = (emulator->x86.gpr[XXEMUL_X86_RBX]
                + (uint8_t)emulator->x86.gpr[XXEMUL_X86_RAX])
                & xxemul_mask_for_size(address_size);
            if (emulator->dos_mode) {
                status = xxemul_x86_dos_address(emulator, XXEMUL_X86_DS,
                    address, 1u, &address);
                if (status != XXEMUL_STATUS_OK) break;
            }
            page_fault_error = UINT32_MAX;
            status = xxemul_x86_guest_load_integer_tracked(emulator,
                address, 1u, &value, &page_fault_error);
            if (status == XXEMUL_STATUS_OK) {
                emulator->x86.gpr[XXEMUL_X86_RAX] =
                    (emulator->x86.gpr[XXEMUL_X86_RAX] & ~UINT64_C(0xff))
                        | value;
            } else {
                status = xxemul_x86_dos_page_fault(emulator, status,
                    page_fault_error, current_ip, &next_ip);
            }
        }
        break;
    case CDISASM_X86_NAME_SALC:
        emulator->x86.gpr[XXEMUL_X86_RAX] =
            (emulator->x86.gpr[XXEMUL_X86_RAX] & ~UINT64_C(0xff))
                | ((emulator->x86.flags & XXEMUL_X86_FLAG_CF) != 0u
                    ? 0xffu : 0u);
        status = XXEMUL_STATUS_OK;
        break;
    case CDISASM_X86_NAME_LAR:
    case CDISASM_X86_NAME_LSL:
        if (!emulator->dos_mode || (emulator->dos_cr0 & 1u) == 0u
            || (emulator->x86.flags & XXEMUL_X86_FLAG_VM) != 0u
            || instruction.operand_count != 2u
            || instruction.opcode[0].type != CDISASM_OPERAND_REGISTER
            || (instruction.opcode[0].size != 2u
                && instruction.opcode[0].size != 4u)
            || (instruction.opcode[1].type != CDISASM_OPERAND_REGISTER
                && instruction.opcode[1].type != CDISASM_OPERAND_MEMORY))
            return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
        page_fault_error = UINT32_MAX;
        status = xxemul_x86_read_operand_tracked(emulator, &instruction,
            &instruction.opcode[1], next_ip, &right, &page_fault_error);
        if (status != XXEMUL_STATUS_OK) {
            status = xxemul_x86_dos_page_fault(emulator, status,
                page_fault_error, current_ip, &next_ip);
            break;
        }
        {
            uint16_t selector = (uint16_t)right;
            uint32_t index = selector & ~7u;
            uint32_t table_limit = (selector & 4u) != 0u
                ? emulator->dos_ldtr_limit : emulator->dos_gdtr_limit;
            uint8_t descriptor[8];
            uint8_t access;
            uint8_t type;
            uint8_t dpl;
            uint8_t cpl = emulator->x86.segment[XXEMUL_X86_CS] & 3u;
            uint32_t descriptor_address;
            int valid = 0;

            if ((selector & ~3u) != 0u
                && ((selector & 4u) == 0u
                    || emulator->dos_ldtr_selector != 0u)
                && index <= table_limit && table_limit - index >= 7u) {
                status = xxemul_x86_dos_read_descriptor_tracked(emulator,
                    selector, emulator->dos_ldtr_selector,
                    emulator->dos_ldtr_base, emulator->dos_ldtr_limit,
                    descriptor, &descriptor_address, &page_fault_error);
                if (status != XXEMUL_STATUS_OK) {
                    status = xxemul_x86_dos_page_fault(emulator, status,
                        page_fault_error, current_ip, &next_ip);
                    break;
                }
                access = descriptor[5];
                type = access & 0x0fu;
                dpl = (access >> 5u) & 3u;
                valid = (access & 0x10u) != 0u
                    || type == 1u || type == 2u || type == 3u
                    || type == 9u || type == 11u;
                if ((access & 0x1cu) != 0x1cu
                    && (cpl > dpl || (selector & 3u) > dpl))
                    valid = 0;
                if (valid) {
                    status = xxemul_x86_write_operand(emulator,
                        &instruction, &instruction.opcode[0], next_ip,
                        instruction.name_id == CDISASM_X86_NAME_LAR
                            ? ((uint32_t)descriptor[5] << 8u)
                                | ((uint32_t)descriptor[6] & 0xf0u) << 16u
                            : xxemul_x86_dos_descriptor_limit(descriptor));
                    if (status != XXEMUL_STATUS_OK) break;
                }
            }
            emulator->x86.flags = (emulator->x86.flags
                & ~XXEMUL_X86_FLAG_ZF)
                | (valid ? XXEMUL_X86_FLAG_ZF : 0u);
            status = XXEMUL_STATUS_OK;
        }
        break;
    case CDISASM_X86_NAME_LGDT:
    case CDISASM_X86_NAME_LIDT:
    case CDISASM_X86_NAME_SGDT:
    case CDISASM_X86_NAME_SIDT:
        if (!emulator->dos_mode || instruction.operand_count != 1u
            || instruction.opcode[0].type != CDISASM_OPERAND_MEMORY
            || instruction.opcode[0].size != 6u)
            return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
        if (instruction.name_id == CDISASM_X86_NAME_LGDT
            || instruction.name_id == CDISASM_X86_NAME_LIDT) {
            status = xxemul_x86_read_operand(emulator, &instruction,
                &instruction.opcode[0], next_ip, &right);
            if (status != XXEMUL_STATUS_OK) return status;
            if ((instruction.opcode_flags & CDISASM_PREFIX_OPERAND_SIZE) == 0u
                && emulator->mode == XXEMUL_MODE_X86_16)
                right &= UINT64_C(0xffffffffff);
            if (instruction.name_id == CDISASM_X86_NAME_LGDT) {
                emulator->dos_gdtr_limit = (uint16_t)right;
                emulator->dos_gdtr_base = (uint32_t)(right >> 16u);
            } else {
                emulator->dos_idtr_limit = (uint16_t)right;
                emulator->dos_idtr_base = (uint32_t)(right >> 16u);
            }
        } else {
            right = instruction.name_id == CDISASM_X86_NAME_SGDT
                ? ((uint64_t)emulator->dos_gdtr_base << 16u)
                    | emulator->dos_gdtr_limit
                : ((uint64_t)emulator->dos_idtr_base << 16u)
                    | emulator->dos_idtr_limit;
            status = xxemul_x86_write_operand(emulator, &instruction,
                &instruction.opcode[0], next_ip, right);
        }
        break;
    case CDISASM_X86_NAME_LMSW:
        if (!emulator->dos_mode || instruction.operand_count != 1u)
            return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
        status = xxemul_x86_read_operand(emulator, &instruction,
            &instruction.opcode[0], next_ip, &right);
        if (status != XXEMUL_STATUS_OK) return status;
        right = (emulator->dos_cr0 & ~UINT32_C(0x0f))
            | (right & 0x0eu) | (emulator->dos_cr0 & 1u) | (right & 1u);
        status = xxemul_x86_write_register(emulator,
            CDISASM_X86_REG_CR0, right);
        break;
    case CDISASM_X86_NAME_CLTS:
        if (!emulator->dos_mode) return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
        emulator->dos_cr0 &= ~UINT32_C(8);
        status = XXEMUL_STATUS_OK;
        break;
    case CDISASM_X86_NAME_LTR:
        if (!emulator->dos_mode || (emulator->dos_cr0 & 1u) == 0u
            || (emulator->x86.segment[XXEMUL_X86_CS] & 3u) != 0u
            || instruction.operand_count != 1u)
            return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
        status = xxemul_x86_read_operand(emulator, &instruction,
            &instruction.opcode[0], next_ip, &right);
        if (status != XXEMUL_STATUS_OK) return status;
        {
            uint16_t selector = (uint16_t)right;
            uint32_t index = selector & ~7u;
            uint8_t descriptor[8];
            uint8_t access;
            uint32_t limit;

            if ((selector & 4u) != 0u || index == 0u
                || index > emulator->dos_gdtr_limit
                || emulator->dos_gdtr_limit - index < 7u)
                return XXEMUL_STATUS_ADDRESS_FAULT;
            status = xxemul_x86_guest_memory(emulator,
                (uint64_t)emulator->dos_gdtr_base + index,
                descriptor, sizeof(descriptor), 0);
            if (status != XXEMUL_STATUS_OK) return status;
            access = descriptor[5];
            if ((access & 0x9fu) != 0x89u
                && (access & 0x9fu) != 0x81u)
                return XXEMUL_STATUS_ADDRESS_FAULT;
            limit = (uint32_t)descriptor[0]
                | ((uint32_t)descriptor[1] << 8u)
                | (((uint32_t)descriptor[6] & 15u) << 16u);
            if ((descriptor[6] & 0x80u) != 0u)
                limit = (limit << 12u) | 0xfffu;
            if (limit < ((access & 8u) != 0u ? 0x67u : 0x2bu))
                return XXEMUL_STATUS_ADDRESS_FAULT;
            access |= 2u;
            status = xxemul_x86_guest_memory(emulator,
                (uint64_t)emulator->dos_gdtr_base + index + 5u,
                &access, 1u, 1);
            if (status != XXEMUL_STATUS_OK) return status;
            emulator->dos_tr_selector = selector;
            emulator->dos_tr_limit = limit;
            emulator->dos_tr_base = (uint32_t)descriptor[2]
                | ((uint32_t)descriptor[3] << 8u)
                | ((uint32_t)descriptor[4] << 16u)
                | ((uint32_t)descriptor[7] << 24u);
        }
        break;
    case CDISASM_X86_NAME_STR:
        if (!emulator->dos_mode || instruction.operand_count != 1u)
            return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
        status = xxemul_x86_write_operand(emulator, &instruction,
            &instruction.opcode[0], next_ip, emulator->dos_tr_selector);
        break;
    case CDISASM_X86_NAME_CBW:
        status = xxemul_x86_write_register(emulator, CDISASM_X86_REG_AX,
            xxemul_sign_extend(emulator->x86.gpr[XXEMUL_X86_RAX], 1u));
        break;
    case CDISASM_X86_NAME_CWDE:
        status = xxemul_x86_write_register(emulator, CDISASM_X86_REG_EAX,
            xxemul_sign_extend(emulator->x86.gpr[XXEMUL_X86_RAX], 2u));
        break;
    case CDISASM_X86_NAME_CDQE:
        status = xxemul_x86_write_register(emulator, CDISASM_X86_REG_RAX,
            xxemul_sign_extend(emulator->x86.gpr[XXEMUL_X86_RAX], 4u));
        break;
    case CDISASM_X86_NAME_CWD:
    case CDISASM_X86_NAME_CDQ:
    case CDISASM_X86_NAME_CQO:
        size = instruction.name_id == CDISASM_X86_NAME_CWD ? 2u
            : instruction.name_id == CDISASM_X86_NAME_CDQ ? 4u : 8u;
        right = (emulator->x86.gpr[XXEMUL_X86_RAX]
            & (UINT64_C(1) << (size * 8u - 1u))) != 0u
            ? xxemul_mask_for_size(size) : 0u;
        status = xxemul_x86_write_register(emulator,
            size == 2u ? CDISASM_X86_REG_DX
            : size == 4u ? CDISASM_X86_REG_EDX
            : CDISASM_X86_REG_RDX, right);
        break;
    case CDISASM_X86_NAME_INT3:
        if (emulator->debug_traps) {
            status = XXEMUL_STATUS_BREAKPOINT;
            break;
        }
        /* fall through */
    case CDISASM_X86_NAME_HLT:
        emulator->halted = 1;
        status = XXEMUL_STATUS_HALTED;
        break;
    case CDISASM_X86_NAME_MOV:
    case CDISASM_X86_NAME_MOVABS:
        if (instruction.operand_count < 2u) {
            return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
        }
        page_fault_error = UINT32_MAX;
        status = xxemul_x86_read_operand_tracked(emulator, &instruction,
            &instruction.opcode[1], next_ip, &right, &page_fault_error);
        if (status == XXEMUL_STATUS_OK) {
            status = xxemul_x86_write_operand_tracked(emulator, &instruction,
                &instruction.opcode[0], next_ip, right, &page_fault_error);
        }
        status = xxemul_x86_dos_page_fault(emulator, status,
            page_fault_error, current_ip, &next_ip);
        break;
    case CDISASM_X86_NAME_MOVSX:
    case CDISASM_X86_NAME_MOVSXD:
    case CDISASM_X86_NAME_MOVZX:
        if (instruction.operand_count < 2u) {
            return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
        }
        status = xxemul_x86_read_operand(
            emulator, &instruction, &instruction.opcode[1], next_ip, &right);
        if (status == XXEMUL_STATUS_OK
            && instruction.name_id != CDISASM_X86_NAME_MOVZX) {
            right = xxemul_sign_extend(right, instruction.opcode[1].size);
        }
        if (status == XXEMUL_STATUS_OK) {
            status = xxemul_x86_write_operand(
                emulator, &instruction, &instruction.opcode[0], next_ip, right);
        }
        break;
    case CDISASM_X86_NAME_LEA:
        if (instruction.operand_count < 2u
            || instruction.opcode[1].type != CDISASM_OPERAND_MEMORY) {
            return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
        }
        status = xxemul_x86_effective_offset(
            emulator, &instruction, &instruction.opcode[1], next_ip, &right);
        if (status == XXEMUL_STATUS_OK) {
            status = xxemul_x86_write_operand(
                emulator, &instruction, &instruction.opcode[0], next_ip, right);
        }
        break;
    case CDISASM_X86_NAME_LDS:
    case CDISASM_X86_NAME_LES:
    case CDISASM_X86_NAME_LFS:
    case CDISASM_X86_NAME_LGS:
    case CDISASM_X86_NAME_LSS:
        if (instruction.operand_count < 2u
            || instruction.opcode[0].type != CDISASM_OPERAND_REGISTER
            || instruction.opcode[1].type != CDISASM_OPERAND_MEMORY
            || (instruction.opcode[0].size != 2u
                && instruction.opcode[0].size != 4u)
            || instruction.opcode[1].size
                != instruction.opcode[0].size + 2u)
            return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
        status = xxemul_x86_read_operand(emulator, &instruction,
            &instruction.opcode[1], next_ip, &right);
        if (status != XXEMUL_STATUS_OK) return status;
        size = instruction.opcode[0].size;
        status = xxemul_x86_write_operand(emulator, &instruction,
            &instruction.opcode[0], next_ip,
            right & xxemul_mask_for_size(size));
        if (status != XXEMUL_STATUS_OK) return status;
        {
            uint8_t segment_index = instruction.name_id == CDISASM_X86_NAME_LDS
                ? XXEMUL_X86_DS
                : instruction.name_id == CDISASM_X86_NAME_LES
                    ? XXEMUL_X86_ES
                : instruction.name_id == CDISASM_X86_NAME_LFS
                    ? XXEMUL_X86_FS
                : instruction.name_id == CDISASM_X86_NAME_LGS
                    ? XXEMUL_X86_GS : XXEMUL_X86_SS;
            if (emulator->dos_mode) {
                status = xxemul_x86_load_dos_segment(emulator,
                    segment_index, (uint16_t)(right >> (size * 8u)));
            } else {
                emulator->x86.segment[segment_index] =
                    (uint16_t)(right >> (size * 8u));
            }
        }
        break;
    case CDISASM_X86_NAME_ADD:
    case CDISASM_X86_NAME_ADC:
    case CDISASM_X86_NAME_SUB:
    case CDISASM_X86_NAME_SBB:
    case CDISASM_X86_NAME_AND:
    case CDISASM_X86_NAME_OR:
    case CDISASM_X86_NAME_XOR:
    case CDISASM_X86_NAME_CMP:
    case CDISASM_X86_NAME_TEST:
        page_fault_error = UINT32_MAX;
        status = xxemul_x86_binary(emulator, &instruction, next_ip,
            instruction.name_id, &page_fault_error);
        status = xxemul_x86_dos_page_fault(emulator, status,
            page_fault_error, current_ip, &next_ip);
        break;
    case CDISASM_X86_NAME_INC:
    case CDISASM_X86_NAME_DEC:
        if (instruction.operand_count < 1u) {
            return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
        }
        size = instruction.opcode[0].size;
        if (size == 0u || size > 8u) {
            return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
        }
        page_fault_error = UINT32_MAX;
        status = xxemul_x86_read_operand_tracked(emulator, &instruction,
            &instruction.opcode[0], next_ip, &left, &page_fault_error);
        if (status != XXEMUL_STATUS_OK) {
            status = xxemul_x86_dos_page_fault(emulator, status,
                page_fault_error, current_ip, &next_ip);
            break;
        }
        saved_cf = emulator->x86.flags & XXEMUL_X86_FLAG_CF;
        page_fault_error = UINT32_MAX;
        if (instruction.name_id == CDISASM_X86_NAME_INC) {
            right = (left + UINT64_C(1)) & xxemul_mask_for_size(size);
            status = xxemul_x86_write_operand_tracked(emulator,
                &instruction, &instruction.opcode[0], next_ip, right,
                &page_fault_error);
            if (status == XXEMUL_STATUS_OK) {
                xxemul_x86_set_add_flags(emulator, left, 1u, right, size);
            }
        } else {
            right = (left - UINT64_C(1)) & xxemul_mask_for_size(size);
            status = xxemul_x86_write_operand_tracked(emulator,
                &instruction, &instruction.opcode[0], next_ip, right,
                &page_fault_error);
            if (status == XXEMUL_STATUS_OK) {
                xxemul_x86_set_sub_flags(emulator, left, 1u, right, size);
            }
        }
        if (status == XXEMUL_STATUS_OK) {
            emulator->x86.flags = (emulator->x86.flags
                & ~XXEMUL_X86_FLAG_CF) | saved_cf;
        }
        status = xxemul_x86_dos_page_fault(emulator, status,
            page_fault_error, current_ip, &next_ip);
        break;
    case CDISASM_X86_NAME_PUSH:
        if (instruction.operand_count < 1u) {
            return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
        }
        size = xxemul_x86_mode_size(emulator);
        if ((instruction.opcode_flags & CDISASM_PREFIX_OPERAND_SIZE) != 0u)
            size = size == 2u ? 4u : 2u;
        page_fault_error = UINT32_MAX;
        status = xxemul_x86_read_operand_tracked(emulator, &instruction,
            &instruction.opcode[0], next_ip, &right, &page_fault_error);
        if (status == XXEMUL_STATUS_OK) {
            status = xxemul_x86_push_width_tracked(emulator, right, size,
                &page_fault_error);
        }
        status = xxemul_x86_dos_page_fault(emulator, status,
            page_fault_error, current_ip, &next_ip);
        break;
    case CDISASM_X86_NAME_POP:
        if (instruction.operand_count < 1u) {
            return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
        }
        size = xxemul_x86_mode_size(emulator);
        if ((instruction.opcode_flags & CDISASM_PREFIX_OPERAND_SIZE) != 0u)
            size = size == 2u ? 4u : 2u;
        original_sp = emulator->x86.gpr[XXEMUL_X86_RSP];
        page_fault_error = UINT32_MAX;
        status = xxemul_x86_pop_width_tracked(emulator,
            &right, size, &page_fault_error);
        if (status == XXEMUL_STATUS_OK) {
            status = xxemul_x86_write_operand_tracked(emulator, &instruction,
                &instruction.opcode[0], next_ip, right, &page_fault_error);
        }
        status = xxemul_x86_dos_stack_fault(emulator, status,
            page_fault_error, original_sp, current_ip, &next_ip);
        break;
    case CDISASM_X86_NAME_CALL:
    case CDISASM_X86_NAME_CALL_NEAR:
        page_fault_error = UINT32_MAX;
        status = xxemul_x86_branch_target_tracked(emulator,
            &instruction, next_ip, &target, &page_fault_error);
        if (status == XXEMUL_STATUS_OK) {
            status = xxemul_x86_push_width_tracked(emulator, next_ip,
                xxemul_x86_mode_size(emulator), &page_fault_error);
        }
        if (status == XXEMUL_STATUS_OK) {
            next_ip = target & xxemul_x86_address_mask(emulator);
        }
        status = xxemul_x86_dos_page_fault(emulator, status,
            page_fault_error, current_ip, &next_ip);
        break;
    case CDISASM_X86_NAME_CALL_FAR:
    case CDISASM_X86_NAME_JMP_FAR:
        if (instruction.operand_count == 1u
            && instruction.opcode[0].type == CDISASM_OPERAND_MEMORY
            && (instruction.opcode[0].size == 4u
                || instruction.opcode[0].size == 6u)) {
            size = (uint8_t)(instruction.opcode[0].size - 2u);
            status = xxemul_x86_read_operand(emulator, &instruction,
                &instruction.opcode[0], next_ip, &right);
        } else if (emulator->dos_mode) {
            uint64_t pointer_address;
            size = xxemul_x86_mode_size(emulator);
            if ((instruction.opcode_flags & CDISASM_PREFIX_OPERAND_SIZE) != 0u)
                size = size == 2u ? 4u : 2u;
            if ((size != 2u && size != 4u)
                || instruction.opcode_size < (uint32_t)size + 3u)
                return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
            status = xxemul_x86_dos_address(emulator, XXEMUL_X86_CS,
                current_ip + instruction.opcode_size - size - 2u,
                (uint8_t)(size + 2u), &pointer_address);
            if (status == XXEMUL_STATUS_OK)
                status = xxemul_x86_guest_load_integer(emulator, pointer_address,
                    (uint8_t)(size + 2u), &right);
        } else {
            return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
        }
        if (status != XXEMUL_STATUS_OK) return status;
        target = right & xxemul_mask_for_size(size);
        right >>= size * 8u;
        if (emulator->dos_mode && (emulator->dos_cr0 & 1u) != 0u) {
            uint8_t descriptor[8];
            uint32_t descriptor_address;
            uint8_t type;

            status = xxemul_x86_dos_read_descriptor(emulator,
                (uint16_t)right, emulator->dos_ldtr_selector,
                emulator->dos_ldtr_base, emulator->dos_ldtr_limit,
                descriptor, &descriptor_address);
            if (status != XXEMUL_STATUS_OK) return status;
            type = descriptor[5] & 0x1fu;
            if (type == 9u || type == 11u) {
                if (instruction.name_id != CDISASM_X86_NAME_JMP_FAR)
                    return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
                status = xxemul_x86_dos_task_jump(emulator,
                    (uint16_t)right, (uint32_t)next_ip, &next_ip);
                break;
            }
        }
        if (instruction.name_id == CDISASM_X86_NAME_CALL_FAR) {
            status = xxemul_x86_push_width(emulator,
                emulator->x86.segment[XXEMUL_X86_CS], size);
            if (status == XXEMUL_STATUS_OK)
                status = xxemul_x86_push_width(emulator, next_ip, size);
        }
        if (status == XXEMUL_STATUS_OK) {
            if (emulator->dos_mode) {
                status = xxemul_x86_load_dos_segment(emulator,
                    XXEMUL_X86_CS, (uint16_t)right);
            } else {
                emulator->x86.segment[XXEMUL_X86_CS] = (uint16_t)right;
            }
            if (status == XXEMUL_STATUS_OK) next_ip = target;
        }
        break;
    case CDISASM_X86_NAME_RET:
    case CDISASM_X86_NAME_RET_NEAR:
    case CDISASM_X86_NAME_RETF:
        original_sp = emulator->x86.gpr[XXEMUL_X86_RSP];
        size = xxemul_x86_mode_size(emulator);
        if ((instruction.opcode_flags & CDISASM_PREFIX_OPERAND_SIZE) != 0u
            && emulator->mode != XXEMUL_MODE_X86_64)
            size = size == 2u ? 4u : 2u;
        page_fault_error = UINT32_MAX;
        status = xxemul_x86_pop_width_tracked(emulator,
            &target, size, &page_fault_error);
        if (status == XXEMUL_STATUS_OK
            && instruction.name_id == CDISASM_X86_NAME_RETF) {
            status = xxemul_x86_pop_width_tracked(emulator,
                &right, size, &page_fault_error);
            if (status == XXEMUL_STATUS_OK) {
                if (emulator->dos_mode) {
                    status = xxemul_x86_load_dos_segment(emulator,
                        XXEMUL_X86_CS, (uint16_t)right);
                } else {
                    emulator->x86.segment[XXEMUL_X86_CS] = (uint16_t)right;
                }
            }
        }
        if (status == XXEMUL_STATUS_OK && instruction.operand_count != 0u) {
            status = xxemul_x86_read_operand(emulator, &instruction,
                &instruction.opcode[0], next_ip, &right);
            if (status == XXEMUL_STATUS_OK)
                emulator->x86.gpr[XXEMUL_X86_RSP] =
                    (emulator->x86.gpr[XXEMUL_X86_RSP] + (uint16_t)right)
                    & xxemul_x86_stack_mask(emulator);
        }
        if (status == XXEMUL_STATUS_OK) {
            next_ip = target & xxemul_x86_address_mask(emulator);
        }
        status = xxemul_x86_dos_stack_fault(emulator, status,
            page_fault_error, original_sp, current_ip, &next_ip);
        break;
    case CDISASM_X86_NAME_JMP:
        page_fault_error = UINT32_MAX;
        status = xxemul_x86_branch_target_tracked(emulator,
            &instruction, next_ip, &target, &page_fault_error);
        if (status == XXEMUL_STATUS_OK) {
            next_ip = target & xxemul_x86_address_mask(emulator);
        }
        status = xxemul_x86_dos_page_fault(emulator, status,
            page_fault_error, current_ip, &next_ip);
        break;
    case CDISASM_X86_NAME_LOOP:
    case CDISASM_X86_NAME_LOOPE:
    case CDISASM_X86_NAME_LOOPNE:
        {
            uint8_t count_size = xxemul_x86_mode_size(emulator);
            uint64_t count_mask;
            uint64_t count;
            int take;
            if ((instruction.opcode_flags & CDISASM_PREFIX_ADDRESS_SIZE) != 0u)
                count_size = count_size == 2u ? 4u
                    : count_size == 4u ? 2u : 4u;
            count_mask = xxemul_mask_for_size(count_size);
            count = (emulator->x86.gpr[XXEMUL_X86_RCX] - 1u) & count_mask;
            if (emulator->mode == XXEMUL_MODE_X86_64 && count_size == 4u)
                emulator->x86.gpr[XXEMUL_X86_RCX] = count;
            else
                emulator->x86.gpr[XXEMUL_X86_RCX] =
                    (emulator->x86.gpr[XXEMUL_X86_RCX] & ~count_mask)
                    | count;
            take = count != 0u;
            if (instruction.name_id == CDISASM_X86_NAME_LOOPE)
                take = take && (emulator->x86.flags & XXEMUL_X86_FLAG_ZF) != 0u;
            if (instruction.name_id == CDISASM_X86_NAME_LOOPNE)
                take = take && (emulator->x86.flags & XXEMUL_X86_FLAG_ZF) == 0u;
            status = XXEMUL_STATUS_OK;
            if (take) {
                status = xxemul_x86_branch_target(
                    emulator, &instruction, next_ip, &target);
                if (status == XXEMUL_STATUS_OK)
                    next_ip = target & xxemul_x86_address_mask(emulator);
            }
        }
        break;
    case CDISASM_X86_NAME_SETA:
    case CDISASM_X86_NAME_SETAE:
    case CDISASM_X86_NAME_SETB:
    case CDISASM_X86_NAME_SETBE:
    case CDISASM_X86_NAME_SETE:
    case CDISASM_X86_NAME_SETG:
    case CDISASM_X86_NAME_SETGE:
    case CDISASM_X86_NAME_SETL:
    case CDISASM_X86_NAME_SETLE:
    case CDISASM_X86_NAME_SETNE:
    case CDISASM_X86_NAME_SETNO:
    case CDISASM_X86_NAME_SETNP:
    case CDISASM_X86_NAME_SETNS:
    case CDISASM_X86_NAME_SETO:
    case CDISASM_X86_NAME_SETP:
    case CDISASM_X86_NAME_SETS:
        if (instruction.operand_count < 1u
            || instruction.opcode[0].size != 1u)
            return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
        condition = xxemul_x86_branch_condition(
            emulator, instruction.name_id);
        if (condition < 0) return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
        status = xxemul_x86_write_operand(emulator, &instruction,
            &instruction.opcode[0], next_ip, condition != 0 ? 1u : 0u);
        break;
    case CDISASM_X86_NAME_CMOVA:
    case CDISASM_X86_NAME_CMOVAE:
    case CDISASM_X86_NAME_CMOVB:
    case CDISASM_X86_NAME_CMOVBE:
    case CDISASM_X86_NAME_CMOVE:
    case CDISASM_X86_NAME_CMOVG:
    case CDISASM_X86_NAME_CMOVGE:
    case CDISASM_X86_NAME_CMOVL:
    case CDISASM_X86_NAME_CMOVLE:
    case CDISASM_X86_NAME_CMOVNE:
    case CDISASM_X86_NAME_CMOVNO:
    case CDISASM_X86_NAME_CMOVNP:
    case CDISASM_X86_NAME_CMOVNS:
    case CDISASM_X86_NAME_CMOVO:
    case CDISASM_X86_NAME_CMOVP:
    case CDISASM_X86_NAME_CMOVS:
        if (instruction.operand_count < 2u
            || instruction.opcode[0].type != CDISASM_OPERAND_REGISTER)
            return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
        status = xxemul_x86_read_operand(emulator, &instruction,
            &instruction.opcode[1], next_ip, &right);
        if (status != XXEMUL_STATUS_OK) return status;
        condition = xxemul_x86_branch_condition(
            emulator, instruction.name_id);
        if (condition < 0) return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
        status = condition != 0
            ? xxemul_x86_write_operand(emulator, &instruction,
                &instruction.opcode[0], next_ip, right)
            : XXEMUL_STATUS_OK;
        break;
    case CDISASM_X86_NAME_JCXZ:
    case CDISASM_X86_NAME_JECXZ:
    case CDISASM_X86_NAME_JRCXZ:
        size = instruction.name_id == CDISASM_X86_NAME_JCXZ ? 2u
            : instruction.name_id == CDISASM_X86_NAME_JECXZ ? 4u : 8u;
        status = XXEMUL_STATUS_OK;
        if ((emulator->x86.gpr[XXEMUL_X86_RCX]
             & xxemul_mask_for_size(size)) == 0u) {
            status = xxemul_x86_branch_target(
                emulator, &instruction, next_ip, &target);
            if (status == XXEMUL_STATUS_OK)
                next_ip = target & xxemul_x86_address_mask(emulator);
        }
        break;
    default:
        condition = xxemul_x86_branch_condition(emulator, instruction.name_id);
        if (condition < 0) {
            return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
        }
        status = XXEMUL_STATUS_OK;
        if (condition != 0) {
            status = xxemul_x86_branch_target(
                emulator, &instruction, next_ip, &target);
            if (status == XXEMUL_STATUS_OK) {
                next_ip = target & xxemul_x86_address_mask(emulator);
            }
        }
        break;
    }

    if (status == XXEMUL_STATUS_OK || status == XXEMUL_STATUS_HALTED
        || status == XXEMUL_STATUS_BREAKPOINT) {
        emulator->x86.ip = next_ip;
        emulator->x86.flags |= UINT64_C(2);
        if (info != NULL) {
            info->next_address = emulator->dos_mode
                ? emulator->dos_segments[XXEMUL_X86_CS].valid
                    ? (uint64_t)emulator->dos_segments[XXEMUL_X86_CS].base
                        + next_ip
                    : xxemul_dos_physical(emulator,
                        emulator->x86.segment[XXEMUL_X86_CS],
                        (uint16_t)next_ip)
                : next_ip;
        }
    }
    return status;
}

size_t xxemul_x86_format_current(
    xxemul *emulator,
    char *buffer,
    size_t buffer_size)
{
    cdisasm_x86_instruction instruction;
    const char *literal = NULL;

    if (xxemul_x86_decode_current(emulator, &instruction) != XXEMUL_STATUS_OK) {
        if (buffer != NULL && buffer_size > 0u) {
            buffer[0] = '\0';
        }
        return 0u;
    }
    if (instruction.name_id == CDISASM_X86_NAME_ENDBR32)
        literal = "endbr32";
    else if (instruction.name_id == CDISASM_X86_NAME_ENDBR64)
        literal = "endbr64";
    else if (instruction.name_id == CDISASM_X86_NAME_SYSCALL)
        literal = "syscall";
    if (literal != NULL) {
        size_t length = strlen(literal);
        if (buffer != NULL && buffer_size != 0u) {
            size_t copied = length < buffer_size - 1u
                ? length : buffer_size - 1u;
            memcpy(buffer, literal, copied);
            buffer[copied] = '\0';
        }
        return length;
    }
    return cdisasm_x86_format_mode(
        &instruction,
        xxemul_x86_cdisasm_mode(emulator),
        CDISASM_FORMAT_SYNTAX_X86_INTEL,
        buffer,
        buffer_size);
}
