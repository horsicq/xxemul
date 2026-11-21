#include "xxemul_windows_unwind64.h"
#include <string.h>

#define U64_MAX_ENTRIES 0x10000u
#define U64_MAX_CHAIN 32u
#define U64_MAX_EPILOGUE 64u

static int u64_add(uint64_t a, uint64_t b, uint64_t *out)
{
    if (a > UINT64_MAX - b) return 0;
    *out = a + b;
    return 1;
}

static uint16_t u64_le16(const uint8_t *p)
{
    return (uint16_t)((uint16_t)p[0] | (uint16_t)p[1] << 8u);
}

static uint32_t u64_le32(const uint8_t *p)
{
    return (uint32_t)p[0] | (uint32_t)p[1] << 8u |
           (uint32_t)p[2] << 16u | (uint32_t)p[3] << 24u;
}

static uint64_t u64_le64(const uint8_t *p)
{
    return (uint64_t)u64_le32(p) | (uint64_t)u64_le32(p + 4u) << 32u;
}

static int u64_read(xxemul_windows_unwind64_read read, void *context,
                    uint64_t address, void *bytes, size_t size)
{
    return read && size && address <= UINT64_MAX - (size - 1u) &&
           read(context, address, bytes, size);
}

static int u64_load(xxemul_windows_unwind64_read read, void *context,
                    uint64_t address, uint64_t *value)
{
    uint8_t bytes[8];
    if (!u64_read(read, context, address, bytes, sizeof(bytes))) return 0;
    *value = u64_le64(bytes);
    return 1;
}

static int u64_nonvolatile(unsigned reg)
{
    return reg == 3u || reg == 5u || reg == 6u || reg == 7u || reg >= 12u;
}

static xxemul_status u64_function(xxemul_windows_unwind64_read read, void *context,
                                 uint64_t address, uint64_t base,
                                 xxemul_windows_runtime_function64 *function)
{
    uint8_t bytes[12];
    uint64_t ignored;
    if ((address & 3u) || !u64_read(read, context, address, bytes, sizeof(bytes)))
        return XXEMUL_STATUS_ADDRESS_FAULT;
    function->address = address;
    function->begin_address = u64_le32(bytes);
    function->end_address = u64_le32(bytes + 4u);
    function->unwind_data = u64_le32(bytes + 8u);
    if (function->begin_address >= function->end_address ||
        !function->unwind_data || !u64_add(base, function->end_address, &ignored) ||
        !u64_add(base, function->unwind_data & ~1u, &ignored))
        return XXEMUL_STATUS_INVALID_IMAGE;
    return XXEMUL_STATUS_OK;
}

/* Validate the ordering too: a malformed table must not silently become a
 * leaf because a binary search happened to miss its misplaced entries. */
static xxemul_status u64_table(xxemul_windows_unwind64_read read, void *context,
                              uint64_t table, uint32_t count, uint64_t base,
                              uint64_t pc, xxemul_windows_runtime_function64 *found,
                              uint64_t *minimum, uint64_t *maximum)
{
    xxemul_windows_runtime_function64 result = {0}, item;
    uint32_t index, previous_end = 0;
    uint64_t end, address;
    xxemul_status status;
    if (!read || !table || (table & 3u) || count > U64_MAX_ENTRIES ||
        !u64_add(table, (uint64_t)count * 12u, &end))
        return XXEMUL_STATUS_INVALID_ARGUMENT;
    (void)end;
    if (minimum) *minimum = 0u;
    if (maximum) *maximum = 0u;
    for (index = 0u; index < count; ++index) {
        address = table + (uint64_t)index * 12u;
        status = u64_function(read, context, address, base, &item);
        if (status != XXEMUL_STATUS_OK) return status;
        if (index && item.begin_address < previous_end) return XXEMUL_STATUS_INVALID_IMAGE;
        previous_end = item.end_address;
        if (!index && minimum) *minimum = base + item.begin_address;
        if (maximum) *maximum = base + item.end_address;
        if (pc >= base + item.begin_address && pc < base + item.end_address) result = item;
    }
    if (found) *found = result;
    return XXEMUL_STATUS_OK;
}

xxemul_status xxemul_windows_unwind64_lookup_table(
    xxemul_windows_unwind64_read read, void *context, uint64_t table,
    uint32_t count, uint64_t image_base, uint64_t control_pc,
    xxemul_windows_runtime_function64 *function)
{
    if (!function) return XXEMUL_STATUS_INVALID_ARGUMENT;
    return u64_table(read, context, table, count, image_base, control_pc, function, NULL, NULL);
}

xxemul_status xxemul_windows_unwind64_lookup_image(
    xxemul_windows_unwind64_read read, void *context, uint64_t base,
    uint64_t size, uint64_t pc, xxemul_windows_runtime_function64 *function)
{
    uint8_t dos[64], nt[24], optional[144];
    uint32_t pe, rva, bytes;
    uint64_t address, end;
    uint16_t optional_size;
    xxemul_windows_runtime_function64 found, entry;
    uint32_t index;
    xxemul_status status;
    if (!function || !read || size < sizeof(dos) || !u64_add(base, size, &end))
        return XXEMUL_STATUS_INVALID_ARGUMENT;
    if (pc < base || pc >= end) { memset(function, 0, sizeof(*function)); return XXEMUL_STATUS_OK; }
    if (!u64_read(read, context, base, dos, sizeof(dos))) return XXEMUL_STATUS_ADDRESS_FAULT;
    pe = u64_le32(dos + 0x3cu);
    if (u64_le16(dos) != 0x5a4du || pe > size || sizeof(nt) > size - pe)
        return XXEMUL_STATUS_INVALID_IMAGE;
    address = base + pe;
    if (!u64_read(read, context, address, nt, sizeof(nt))) return XXEMUL_STATUS_ADDRESS_FAULT;
    optional_size = u64_le16(nt + 20u);
    if (u64_le32(nt) != 0x4550u || u64_le16(nt + 4u) != 0x8664u ||
        optional_size < 112u || (uint64_t)pe + 24u + optional_size > size)
        return XXEMUL_STATUS_INVALID_IMAGE;
    if (!u64_read(read, context, address + 24u, optional, 112u)) return XXEMUL_STATUS_ADDRESS_FAULT;
    if (u64_le16(optional) != 0x20bu) return XXEMUL_STATUS_INVALID_IMAGE;
    if (u64_le32(optional + 108u) <= 3u) { memset(function, 0, sizeof(*function)); return XXEMUL_STATUS_OK; }
    if (optional_size < sizeof(optional)) return XXEMUL_STATUS_INVALID_IMAGE;
    if (!u64_read(read, context, address + 24u + 112u, optional + 112u, 32u))
        return XXEMUL_STATUS_ADDRESS_FAULT;
    rva = u64_le32(optional + 136u);
    bytes = u64_le32(optional + 140u);
    if (!rva && !bytes) { memset(function, 0, sizeof(*function)); return XXEMUL_STATUS_OK; }
    if (!rva || !bytes || (rva & 3u) || bytes % 12u || rva > size || bytes > size - rva)
        return XXEMUL_STATUS_INVALID_IMAGE;
    if (bytes / 12u > U64_MAX_ENTRIES) return XXEMUL_STATUS_INVALID_IMAGE;
    for (index = 0u; index < bytes / 12u; ++index) {
        status = u64_function(read, context, base + rva + (uint64_t)index * 12u, base, &entry);
        if (status != XXEMUL_STATUS_OK) return status;
        if (entry.end_address > size || (entry.unwind_data & ~1u) >= size)
            return XXEMUL_STATUS_INVALID_IMAGE;
    }
    status = u64_table(read, context, base + rva, bytes / 12u, base, pc, &found, NULL, NULL);
    if (status != XXEMUL_STATUS_OK) return status;
    if (found.address && (found.end_address > size || (found.unwind_data & ~1u) >= size))
        return XXEMUL_STATUS_INVALID_IMAGE;
    *function = found;
    return XXEMUL_STATUS_OK;
}

static int u64_code(xxemul_windows_unwind64_read read, void *context,
                    uint64_t pc, uint64_t end, unsigned offset, uint8_t *byte)
{
    uint64_t address;
    return u64_add(pc, offset, &address) && address < end &&
           u64_read(read, context, address, byte, 1u);
}

/* Return 1 for a complete legal epilogue, zero for ordinary body code, and
 * -1 for an inaccessible stack in an otherwise complete epilogue. Work is
 * speculative and all register changes remain local until recognition. */
static int u64_epilogue(xxemul_windows_unwind64_read read, void *context,
                        uint64_t pc, uint64_t begin, uint64_t end,
                        unsigned frame_reg, xxemul_x86_state *cpu,
                        xxemul_windows_unwind64_result *result)
{
    xxemul_x86_state state = *cpu;
    xxemul_windows_unwind64_result saved = *result;
    unsigned at = 0u, steps, reg, rex, modrm, i, n, displacement_offset;
    uint8_t byte, next, bytes[4];
    uint64_t value, address, target;
    int64_t displacement;
    int stack_fault = 0;
    if (!u64_code(read, context, pc, end, 0u, &byte)) return 0;
    /* ADD RSP, imm or LEA RSP, disp[FP] may appear only first. A current
     * instruction after this point starts at a POP or terminal jump/RET. */
    if (byte == 0x48u && u64_code(read, context, pc, end, 1u, &next) &&
        (next == 0x83u || next == 0x81u)) {
        if (!u64_code(read, context, pc, end, 2u, &byte) || byte != 0xc4u) return 0;
        n = next == 0x83u ? 1u : 4u;
        for (i = 0u; i < n; ++i) if (!u64_code(read, context, pc, end, 3u + i, &bytes[i])) return 0;
        displacement = n == 1u ? (int8_t)bytes[0] : (int32_t)u64_le32(bytes);
        if (displacement < 0 || !u64_add(state.gpr[4], (uint64_t)displacement, &state.gpr[4])) return 0;
        at = 3u + n;
    } else if ((byte == 0x48u || byte == 0x49u) &&
               u64_code(read, context, pc, end, 1u, &next) && next == 0x8du) {
        rex = byte;
        if (!u64_code(read, context, pc, end, 2u, &byte)) return 0;
        modrm = byte;
        reg = (modrm & 7u) | ((rex & 1u) ? 8u : 0u);
        displacement_offset = 3u;
        if ((modrm & 7u) == 4u) {
            if (!u64_code(read, context, pc, end, 3u, &byte) || byte != 0x24u) return 0;
            displacement_offset = 4u;
        }
        if (((modrm >> 3u) & 7u) != 4u ||
            (modrm >> 6u) == 0u || (modrm >> 6u) == 3u || !frame_reg || reg != frame_reg)
            return 0;
        n = (modrm >> 6u) == 1u ? 1u : 4u;
        for (i = 0u; i < n; ++i) if (!u64_code(read, context, pc, end, displacement_offset + i, &bytes[i])) return 0;
        displacement = n == 1u ? (int8_t)bytes[0] : (int32_t)u64_le32(bytes);
        if (displacement < 0) {
            if (state.gpr[reg] < (uint64_t)-displacement) return 0;
            state.gpr[4] = state.gpr[reg] - (uint64_t)-displacement;
        } else if (!u64_add(state.gpr[reg], (uint64_t)displacement, &state.gpr[4])) return 0;
        at = displacement_offset + n;
    }
    for (steps = 0u; steps < U64_MAX_EPILOGUE; ++steps) {
        if (!u64_code(read, context, pc, end, at, &byte)) return 0;
        rex = 0u;
        if (byte >= 0x40u && byte <= 0x4fu) {
            rex = byte;
            if (!u64_code(read, context, pc, end, at + 1u, &byte)) return 0;
        }
        if (byte >= 0x58u && byte <= 0x5fu && !(rex & 6u)) {
            reg = byte - 0x58u + ((rex & 1u) ? 8u : 0u);
            if (!u64_nonvolatile(reg)) return 0;
            address = state.gpr[4];
            if (!u64_load(read, context, address, &value)) stack_fault = 1;
            else state.gpr[reg] = value;
            saved.integer_save[reg] = address;
            if (!u64_add(address, 8u, &state.gpr[4])) return 0;
            at += rex ? 2u : 1u;
            continue;
        }
        if (!rex && byte == 0xf3u) {
            if (!u64_code(read, context, pc, end, at + 1u, &byte) || byte != 0xc3u) return 0;
            ++at;
        }
        if (!rex && (byte == 0xc3u || byte == 0xc2u)) {
            uint64_t cleanup = 8u;
            if (byte == 0xc2u) {
                if (!u64_code(read, context, pc, end, at + 1u, &bytes[0]) ||
                    !u64_code(read, context, pc, end, at + 2u, &bytes[1])) return 0;
                cleanup += u64_le16(bytes);
            }
            if (!u64_load(read, context, state.gpr[4], &state.ip)) stack_fault = 1;
            if (!u64_add(state.gpr[4], cleanup, &state.gpr[4])) return 0;
            if (stack_fault) return -1;
            *cpu = state; *result = saved;
            return 1;
        }
        if (!rex && (byte == 0xe9u || byte == 0xebu)) {
            n = byte == 0xebu ? 1u : 4u;
            for (i = 0u; i < n; ++i) if (!u64_code(read, context, pc, end, at + 1u + i, &bytes[i])) return 0;
            displacement = n == 1u ? (int8_t)bytes[0] : (int32_t)u64_le32(bytes);
            if (!u64_add(pc, (uint64_t)at + 1u + n, &target)) return 0;
            if (displacement < 0) {
                if (target < (uint64_t)-displacement) return 0;
                target -= (uint64_t)-displacement;
            } else if (!u64_add(target, (uint64_t)displacement, &target)) return 0;
            if (target >= begin && target < end) return 0;
        } else if (byte == 0xffu) {
            if (!u64_code(read, context, pc, end, at + (rex ? 2u : 1u), &next)) return 0;
            if (((next >> 3u) & 7u) != 4u ||
                !(((next >> 6u) == 3u && (rex & 8u)) ||
                  (next == 0x25u && !rex))) return 0;
            if (next == 0x25u) for (i = 0u; i < 4u; ++i)
                if (!u64_code(read, context, pc, end, at + 2u + i, &bytes[i])) return 0;
        } else return 0;
        /* A legal epilogue tail jump transfers the caller's existing return
         * address, so virtual unwinding obtains that same caller context. */
        if (!u64_load(read, context, state.gpr[4], &state.ip)) stack_fault = 1;
        if (!u64_add(state.gpr[4], 8u, &state.gpr[4])) return 0;
        if (stack_fault) return -1;
        *cpu = state; *result = saved;
        return 1;
    }
    return 0;
}

static unsigned u64_slots(unsigned opcode, unsigned info, unsigned version)
{
    switch (opcode) {
    case 0u: case 2u: case 3u: case 10u: return 1u;
    case 1u: return info == 0u ? 2u : info == 1u ? 3u : 0u;
    case 4u: case 8u: return 2u;
    case 5u: case 9u: return 3u;
    case 6u: return version == 2u ? 1u : 0u;
    default: return 0u;
    }
}

xxemul_status xxemul_windows_unwind64_virtual_unwind(
    xxemul_windows_unwind64_read read, void *context, uint64_t base,
    uint64_t pc, const xxemul_windows_runtime_function64 *function,
    unsigned handler_type, xxemul_x86_state *cpu,
    xxemul_windows_unwind64_result *result)
{
    xxemul_x86_state state;
    xxemul_windows_unwind64_result output = {0};
    xxemul_windows_runtime_function64 current;
    uint64_t address, offset, value, frame, seen[U64_MAX_CHAIN], tail;
    uint8_t head[4], codes[510], bytes[12];
    unsigned depth = 0u, index, slot_count, version, flags, count, frame_reg, frame_offset;
    unsigned opcode, info, code_offset, previous, frame_seen, first = 1u;
    unsigned root_frame_reg = 0u, root_frame_offset = 0u;
    int in_prologue, epilogue;
    xxemul_status status;
    if (!read || !cpu || !result || (handler_type & ~3u)) return XXEMUL_STATUS_INVALID_ARGUMENT;
    state = *cpu;
    output.establisher_frame = state.gpr[4];
    if (!function || !function->address) {
        if (!u64_load(read, context, state.gpr[4], &state.ip)) return XXEMUL_STATUS_ADDRESS_FAULT;
        if (!u64_add(state.gpr[4], 8u, &state.gpr[4])) return XXEMUL_STATUS_INVALID_IMAGE;
        *cpu = state; *result = output;
        return XXEMUL_STATUS_OK;
    }
    current = *function;
    if (current.begin_address >= current.end_address || pc < base ||
        pc - base < current.begin_address || pc - base >= current.end_address)
        return XXEMUL_STATUS_INVALID_ARGUMENT;
    for (;;) {
        if (depth >= U64_MAX_CHAIN || !u64_add(base, current.unwind_data & ~1u, &address))
            return XXEMUL_STATUS_INVALID_IMAGE;
        for (index = 0u; index < depth; ++index) if (seen[index] == address)
            return XXEMUL_STATUS_INVALID_IMAGE;
        seen[depth++] = address;
        if (current.unwind_data & 1u) {
            status = u64_function(read, context, address, base, &current);
            if (status != XXEMUL_STATUS_OK) return status;
            ++output.chained_records;
            continue;
        }
        if (address & 3u) return XXEMUL_STATUS_INVALID_IMAGE;
        if (!u64_read(read, context, address, head, sizeof(head))) return XXEMUL_STATUS_ADDRESS_FAULT;
        version = head[0] & 7u; flags = head[0] >> 3u;
        count = head[2]; frame_reg = head[3] & 15u; frame_offset = head[3] >> 4u;
        if (version != 1u && version != 2u) return XXEMUL_STATUS_UNSUPPORTED_IMAGE;
        if ((flags & ~7u) || ((flags & 4u) && (flags & 3u)) ||
            (!frame_reg && frame_offset) || (frame_reg && !u64_nonvolatile(frame_reg)))
            return XXEMUL_STATUS_INVALID_IMAGE;
        if (!u64_add(address, 4u + (uint64_t)count * 2u, &tail)) return XXEMUL_STATUS_INVALID_IMAGE;
        if (count && !u64_read(read, context, address + 4u, codes, count * 2u))
            return XXEMUL_STATUS_ADDRESS_FAULT;
        offset = pc >= base + current.begin_address ? pc - base - current.begin_address : UINT64_MAX;
        in_prologue = first && offset < head[1];
        if (first) {
            root_frame_reg = frame_reg; root_frame_offset = frame_offset;
            output.in_prologue = (unsigned)in_prologue;
        } else if (root_frame_reg != frame_reg || root_frame_offset != frame_offset)
            return XXEMUL_STATUS_INVALID_IMAGE;
        frame = state.gpr[4];
        frame_seen = !frame_reg || !in_prologue || (flags & 4u);
        previous = 256u;
        /* Validate every entry, even a not-yet-executed prologue operation. */
        for (index = 0u; index < count; index += slot_count) {
            opcode = codes[index * 2u + 1u] & 15u;
            info = codes[index * 2u + 1u] >> 4u;
            code_offset = codes[index * 2u];
            slot_count = u64_slots(opcode, info, version);
            if (!slot_count || slot_count > count - index) return XXEMUL_STATUS_INVALID_IMAGE;
            if (opcode == 6u) continue; /* Version-2 epilogue descriptors. */
            if (code_offset > head[1] || code_offset > previous) return XXEMUL_STATUS_INVALID_IMAGE;
            previous = code_offset;
            if (((opcode == 0u || opcode == 4u || opcode == 5u) && !u64_nonvolatile(info)) ||
                ((opcode == 8u || opcode == 9u) && info < 6u) ||
                (opcode == 3u && (!frame_reg || info)) || (opcode == 10u && info > 1u))
                return XXEMUL_STATUS_INVALID_IMAGE;
            if (opcode == 3u && (!in_prologue || offset >= code_offset)) frame_seen = 1u;
        }
        if (frame_reg && frame_seen) {
            if (state.gpr[frame_reg] < frame_offset * 16u) return XXEMUL_STATUS_INVALID_IMAGE;
            frame = state.gpr[frame_reg] - frame_offset * 16u;
        }
        if (first) {
            output.establisher_frame = frame;
            if (!in_prologue) {
                uint64_t begin, end;
                if (!u64_add(base, current.begin_address, &begin) || !u64_add(base, current.end_address, &end))
                    return XXEMUL_STATUS_INVALID_IMAGE;
                epilogue = u64_epilogue(read, context, pc, begin, end, frame_reg, &state, &output);
                if (epilogue < 0) return XXEMUL_STATUS_ADDRESS_FAULT;
                if (epilogue) {
                    output.in_epilogue = 1u;
                    *cpu = state; *result = output;
                    return XXEMUL_STATUS_OK;
                }
            }
        }
        for (index = 0u; index < count; index += slot_count) {
            opcode = codes[index * 2u + 1u] & 15u;
            info = codes[index * 2u + 1u] >> 4u;
            code_offset = codes[index * 2u];
            slot_count = u64_slots(opcode, info, version);
            if (opcode == 6u || (in_prologue && offset < code_offset)) continue;
            switch (opcode) {
            case 0u:
                tail = state.gpr[4];
                if (!u64_load(read, context, tail, &value)) return XXEMUL_STATUS_ADDRESS_FAULT;
                state.gpr[info] = value; output.integer_save[info] = tail;
                if (!u64_add(tail, 8u, &state.gpr[4])) return XXEMUL_STATUS_INVALID_IMAGE;
                break;
            case 1u:
                value = info == 0u ? (uint64_t)u64_le16(codes + (index + 1u) * 2u) * 8u :
                                    u64_le32(codes + (index + 1u) * 2u);
                if (!value || (value & 7u) || !u64_add(state.gpr[4], value, &state.gpr[4]))
                    return XXEMUL_STATUS_INVALID_IMAGE;
                break;
            case 2u:
                if (!u64_add(state.gpr[4], info * 8u + 8u, &state.gpr[4])) return XXEMUL_STATUS_INVALID_IMAGE;
                break;
            case 3u: state.gpr[4] = frame; break;
            case 4u: case 5u:
                value = opcode == 4u ? (uint64_t)u64_le16(codes + (index + 1u) * 2u) * 8u :
                                      u64_le32(codes + (index + 1u) * 2u);
                if ((value & 7u) || !u64_add(frame, value, &tail)) return XXEMUL_STATUS_INVALID_IMAGE;
                if (!u64_load(read, context, tail, &state.gpr[info])) return XXEMUL_STATUS_ADDRESS_FAULT;
                output.integer_save[info] = tail;
                break;
            case 8u: case 9u:
                value = opcode == 8u ? (uint64_t)u64_le16(codes + (index + 1u) * 2u) * 16u :
                                      u64_le32(codes + (index + 1u) * 2u);
                if ((value & 15u) || !u64_add(frame, value, &tail)) return XXEMUL_STATUS_INVALID_IMAGE;
                if (!u64_read(read, context, tail, state.xmm[info], 16u)) return XXEMUL_STATUS_ADDRESS_FAULT;
                output.xmm_save[info] = tail;
                break;
            case 10u:
                if (output.machine_frame || index + slot_count != count || (flags & 4u) ||
                    !u64_add(state.gpr[4], info * 8u, &tail) || tail > UINT64_MAX - 39u)
                    return XXEMUL_STATUS_INVALID_IMAGE;
                if (!u64_read(read, context, tail, bytes, 8u)) return XXEMUL_STATUS_ADDRESS_FAULT;
                state.ip = u64_le64(bytes);
                if (!u64_load(read, context, tail + 8u, &value)) return XXEMUL_STATUS_ADDRESS_FAULT;
                state.segment[XXEMUL_X86_CS] = (uint16_t)value;
                if (!u64_load(read, context, tail + 16u, &state.flags) ||
                    !u64_load(read, context, tail + 24u, &state.gpr[4]) ||
                    !u64_load(read, context, tail + 32u, &value)) return XXEMUL_STATUS_ADDRESS_FAULT;
                state.segment[XXEMUL_X86_SS] = (uint16_t)value;
                output.machine_frame = 1u;
                break;
            default: return XXEMUL_STATUS_INVALID_IMAGE;
            }
        }
        if (!u64_add(address, 4u + ((count + 1u) & ~1u) * 2u, &tail))
            return XXEMUL_STATUS_INVALID_IMAGE;
        if (flags & 4u) {
            status = u64_function(read, context, tail, base, &current);
            if (status != XXEMUL_STATUS_OK) return status;
            ++output.chained_records; first = 0u;
            continue;
        }
        if (!output.in_prologue && (flags & handler_type)) {
            if (!u64_read(read, context, tail, bytes, 4u)) return XXEMUL_STATUS_ADDRESS_FAULT;
            value = u64_le32(bytes);
            if (!value || !u64_add(base, value, &output.handler) || !u64_add(tail, 4u, &output.handler_data))
                return XXEMUL_STATUS_INVALID_IMAGE;
        }
        if (!output.machine_frame) {
            if (!u64_load(read, context, state.gpr[4], &state.ip)) return XXEMUL_STATUS_ADDRESS_FAULT;
            if (!u64_add(state.gpr[4], 8u, &state.gpr[4])) return XXEMUL_STATUS_INVALID_IMAGE;
        }
        *cpu = state; *result = output;
        return XXEMUL_STATUS_OK;
    }
}

xxemul_status xxemul_windows_unwind64_add_table(
    xxemul_windows_unwind64_read read, void *context,
    xxemul_windows_unwind64_registry *registry, uint64_t table,
    uint32_t count, uint64_t base)
{
    xxemul_windows_unwind64_table entry = {0};
    size_t index, available = XXEMUL_WINDOWS_UNWIND64_MAX_TABLES;
    xxemul_status status;
    if (!registry || !count) return XXEMUL_STATUS_INVALID_ARGUMENT;
    for (index = 0u; index < XXEMUL_WINDOWS_UNWIND64_MAX_TABLES; ++index) {
        if (registry->tables[index].active && registry->tables[index].address == table)
            return XXEMUL_STATUS_INVALID_ARGUMENT;
        if (!registry->tables[index].active && available == XXEMUL_WINDOWS_UNWIND64_MAX_TABLES) available = index;
    }
    if (available == XXEMUL_WINDOWS_UNWIND64_MAX_TABLES) return XXEMUL_STATUS_OUT_OF_MEMORY;
    status = u64_table(read, context, table, count, base, 0u, NULL, &entry.begin_address, &entry.end_address);
    if (status != XXEMUL_STATUS_OK) return status;
    entry.address = table; entry.image_base = base; entry.count = count; entry.active = 1u;
    registry->tables[available] = entry;
    return XXEMUL_STATUS_OK;
}

int xxemul_windows_unwind64_delete_table(xxemul_windows_unwind64_registry *registry, uint64_t table)
{
    size_t index;
    if (!registry) return 0;
    for (index = 0u; index < XXEMUL_WINDOWS_UNWIND64_MAX_TABLES; ++index)
        if (registry->tables[index].active && registry->tables[index].address == table) {
            memset(&registry->tables[index], 0, sizeof(registry->tables[index])); return 1;
        }
    return 0;
}

xxemul_status xxemul_windows_unwind64_lookup_dynamic(
    xxemul_windows_unwind64_read read, void *context,
    const xxemul_windows_unwind64_registry *registry, uint64_t pc,
    uint64_t *base, xxemul_windows_runtime_function64 *function)
{
    size_t index;
    xxemul_windows_runtime_function64 found;
    xxemul_status status;
    if (!registry || !base || !function) return XXEMUL_STATUS_INVALID_ARGUMENT;
    for (index = 0u; index < XXEMUL_WINDOWS_UNWIND64_MAX_TABLES; ++index) {
        const xxemul_windows_unwind64_table *table = &registry->tables[index];
        if (!table->active || pc < table->begin_address || pc >= table->end_address) continue;
        status = u64_table(read, context, table->address, table->count, table->image_base, pc, &found, NULL, NULL);
        if (status != XXEMUL_STATUS_OK) return status;
        if (found.address) { *base = table->image_base; *function = found; return XXEMUL_STATUS_OK; }
    }
    *base = 0u; memset(function, 0, sizeof(*function));
    return XXEMUL_STATUS_OK;
}
