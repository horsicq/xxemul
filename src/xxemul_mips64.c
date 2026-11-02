#include "xxemul_internal.h"
#include "platforms/xxemul_linux.h"

#include <limits.h>
#include <string.h>

/* Standard fixed-width MIPS64r2 integer execution. This has an independent
 * register/branch state; MIPS32's public layout and execution stay intact. */
static xxemul_status m64_decode(xxemul *e, cdisasm_mips_instruction *instruction)
{
    uint8_t code[4];
    cdisasm_mips_decode_flags flags = CDISASM_DECODE_FLAGS_INITIALIZER(CDISASM_MIPS_DECODE_FLAG_ISA_64R2);
    xxemul_status status;
    if (e->mips64.pc & 3u) return XXEMUL_STATUS_ADDRESS_FAULT;
    status = xxemul_read_memory(e, e->mips64.pc, code, sizeof(code));
    if (status != XXEMUL_STATUS_OK) return status;
    if (e->mode == XXEMUL_MODE_MIPS64_BE) flags.bitmap[0] |= CDISASM_MIPS_DECODE_FLAG_BIG_ENDIAN;
    return cdisasm_mips_decode(CDISASM_MIPS_CPU_ANY, CDISASM_MIPS_MODE_64, code, sizeof(code),
                              e->mips64.pc, &flags, instruction) == 4u
        ? XXEMUL_STATUS_OK : XXEMUL_STATUS_DECODE_ERROR;
}

static xxemul_status m64_load(xxemul *e, uint64_t address, unsigned size, uint64_t *value)
{
    uint8_t bytes[8]; unsigned i; xxemul_status status;
    if (!size || size > 8u || address > UINT64_MAX - (size - 1u)) return XXEMUL_STATUS_ADDRESS_FAULT;
    status = xxemul_read_memory(e, address, bytes, size);
    if (status != XXEMUL_STATUS_OK) return status;
    if (e->memory_hook && e->in_step) e->memory_hook(e->memory_hook_context, address, size, 0);
    *value = 0;
    for (i = 0; i < size; ++i)
        *value |= (uint64_t)bytes[i] << ((e->mode == XXEMUL_MODE_MIPS64_BE ? size - 1u - i : i) * 8u);
    return XXEMUL_STATUS_OK;
}

static xxemul_status m64_store(xxemul *e, uint64_t address, unsigned size, uint64_t value)
{
    uint8_t bytes[8]; unsigned i; xxemul_status status;
    if (!size || size > 8u || address > UINT64_MAX - (size - 1u)) return XXEMUL_STATUS_ADDRESS_FAULT;
    for (i = 0; i < size; ++i)
        bytes[i] = (uint8_t)(value >> ((e->mode == XXEMUL_MODE_MIPS64_BE ? size - 1u - i : i) * 8u));
    e->mips64_reservation_valid = 0;
    status = xxemul_write_memory(e, address, bytes, size);
    if (status == XXEMUL_STATUS_OK && e->memory_hook && e->in_step)
        e->memory_hook(e->memory_hook_context, address, size, 1);
    return status;
}

static uint64_t m64_word(uint32_t value) { return (uint64_t)(int64_t)(int32_t)value; }
static uint64_t m64_mask(unsigned bits) { return bits >= 64u ? UINT64_MAX : (UINT64_C(1) << bits) - 1u; }
static uint64_t m64_sar(uint64_t value, unsigned shift)
{
    shift &= 63u;
    return shift && (value >> 63u) ? (value >> shift) | (UINT64_MAX << (64u - shift)) : value >> shift;
}
static uint64_t m64_ror(uint64_t value, unsigned shift)
{
    shift &= 63u;
    return shift ? (value >> shift) | (value << (64u - shift)) : value;
}
static uint32_t m64_ror_word(uint32_t value, unsigned shift)
{
    shift &= 31u;
    return shift ? (value >> shift) | (value << (32u - shift)) : value;
}
static uint64_t m64_multiply_high(uint64_t a, uint64_t b)
{
    uint64_t low = (uint64_t)(uint32_t)a * (uint32_t)b;
    uint64_t middle = (low >> 32u) + (a >> 32u) * (uint32_t)b;
    uint64_t carry = (uint32_t)middle + (uint64_t)(uint32_t)a * (b >> 32u);
    return (a >> 32u) * (b >> 32u) + (middle >> 32u) + (carry >> 32u);
}

xxemul_status xxemul_mips64_step(xxemul *e, xxemul_step_info *info)
{
    cdisasm_mips_instruction decoded; xxemul_mips64_state r; xxemul_status status;
    uint64_t pc, next, target = 0, a, b, value = 0, address;
    uint32_t instruction, op, rs, rt, rd, sa, fn, imm;
    int delayed, branch = 0, taken = 0, likely = 0; unsigned size;
    status = m64_decode(e, &decoded);
    if (status != XXEMUL_STATUS_OK) return status;
    instruction = decoded.raw_instruction; pc = e->mips64.pc;
    delayed = e->mips64_delay_pending;
    next = delayed ? e->mips64_branch_target : pc + 4u;
    r = e->mips64; r.gpr[0] = 0;
    op = instruction >> 26u; rs = (instruction >> 21u) & 31u; rt = (instruction >> 16u) & 31u;
    rd = (instruction >> 11u) & 31u; sa = (instruction >> 6u) & 31u; fn = instruction & 63u; imm = instruction & 0xffffu;
    a = r.gpr[rs]; b = r.gpr[rt]; address = a + (uint64_t)(int64_t)(int16_t)imm;
    if (info) { info->address = pc; info->size = 4u; info->instruction_id = decoded.name_id; }
#define M64_MEMORY(call) do { status = (call); if (status != XXEMUL_STATUS_OK) return status; } while (0)
#define M64_BRANCH(condition) do { branch = 1; taken = (condition); \
    target = taken ? pc + 4u + (uint64_t)((int64_t)(int16_t)imm * 4) : pc + 8u; } while (0)
    switch (op) {
        case 0:
            switch (fn) {
                case 0: r.gpr[rd] = m64_word((uint32_t)b << sa); break;
                case 2: r.gpr[rd] = m64_word(rs == 1u ? m64_ror_word((uint32_t)b, sa) : (uint32_t)b >> sa); break;
                case 3: r.gpr[rd] = m64_word((uint32_t)m64_sar(m64_word((uint32_t)b), sa)); break;
                case 4: r.gpr[rd] = m64_word((uint32_t)b << (a & 31u)); break;
                case 6: r.gpr[rd] = m64_word(sa == 1u ? m64_ror_word((uint32_t)b, (unsigned)a) : (uint32_t)b >> (a & 31u)); break;
                case 7: r.gpr[rd] = m64_word((uint32_t)m64_sar(m64_word((uint32_t)b), (unsigned)(a & 31u))); break;
                case 8: branch = 1; target = a; break;
                case 9: branch = 1; target = a; r.gpr[rd] = pc + 8u; break;
                case 10: if (!b) r.gpr[rd] = a; break;
                case 11: if (b) r.gpr[rd] = a; break;
                case 12:
                    if (!e->linux_process) return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
                    r.pc = next; e->mips64 = r; e->mips64_delay_pending = 0;
                    status = xxemul_linux_dispatch(e->linux_process);
                    if (xxemul_linux_has_exited(e->linux_process)) { e->halted = 1; status = XXEMUL_STATUS_HALTED; }
                    e->mips64.gpr[0] = 0;
                    if (info) info->next_address = e->mips64.pc;
                    return status;
                case 13:
                    r.pc = next; e->mips64 = r; e->mips64_delay_pending = 0;
                    if (info) info->next_address = next;
                    if (e->debug_traps) return XXEMUL_STATUS_BREAKPOINT;
                    e->halted = 1; return XXEMUL_STATUS_HALTED;
                case 15: break; /* Coherent modeled memory. */
                case 16: r.gpr[rd] = r.hi; break;
                case 17: r.hi = a; break;
                case 18: r.gpr[rd] = r.lo; break;
                case 19: r.lo = a; break;
                case 20: r.gpr[rd] = b << (a & 63u); break;
                case 22: r.gpr[rd] = sa == 1u ? m64_ror(b, (unsigned)a) : b >> (a & 63u); break;
                case 23: r.gpr[rd] = m64_sar(b, (unsigned)a); break;
                case 24: case 25: {
                    uint64_t product = fn == 24u ? (uint64_t)((int64_t)(int32_t)a * (int32_t)b) : (uint64_t)(uint32_t)a * (uint32_t)b;
                    r.hi = m64_word((uint32_t)(product >> 32u)); r.lo = m64_word((uint32_t)product); break;
                }
                case 26:
                    if (!(uint32_t)b) { r.hi = m64_word((uint32_t)a); r.lo = (int32_t)a < 0 ? 1u : UINT64_MAX; }
                    else if ((uint32_t)a == 0x80000000u && (uint32_t)b == UINT32_MAX) { r.hi = 0; r.lo = m64_word((uint32_t)a); }
                    else { r.lo = m64_word((uint32_t)((int32_t)a / (int32_t)b)); r.hi = m64_word((uint32_t)((int32_t)a % (int32_t)b)); }
                    break;
                case 27:
                    r.hi = m64_word((uint32_t)b ? (uint32_t)a % (uint32_t)b : (uint32_t)a);
                    r.lo = (uint32_t)b ? m64_word((uint32_t)a / (uint32_t)b) : UINT64_MAX; break;
                case 28: case 29:
                    r.lo = a * b; r.hi = m64_multiply_high(a, b);
                    if (fn == 28u) { if (a >> 63u) r.hi -= b; if (b >> 63u) r.hi -= a; }
                    break;
                case 30:
                    if (!b) { r.hi = a; r.lo = (a >> 63u) ? 1u : UINT64_MAX; }
                    else if (a == (UINT64_C(1) << 63u) && b == UINT64_MAX) { r.hi = 0; r.lo = a; }
                    else { r.lo = (uint64_t)((int64_t)a / (int64_t)b); r.hi = (uint64_t)((int64_t)a % (int64_t)b); }
                    break;
                case 31: r.hi = b ? a % b : a; r.lo = b ? a / b : UINT64_MAX; break;
                case 32: case 34: {
                    int64_t result = (int64_t)(int32_t)a + (fn == 32u ? (int64_t)(int32_t)b : -(int64_t)(int32_t)b);
                    if (result < INT32_MIN || result > INT32_MAX) return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
                    r.gpr[rd] = m64_word((uint32_t)result); break;
                }
                case 33: r.gpr[rd] = m64_word((uint32_t)a + (uint32_t)b); break;
                case 35: r.gpr[rd] = m64_word((uint32_t)a - (uint32_t)b); break;
                case 36: r.gpr[rd] = a & b; break;
                case 37: r.gpr[rd] = a | b; break;
                case 38: r.gpr[rd] = a ^ b; break;
                case 39: r.gpr[rd] = ~(a | b); break;
                case 42: r.gpr[rd] = (int64_t)a < (int64_t)b; break;
                case 43: r.gpr[rd] = a < b; break;
                case 44: case 45: case 46: case 47:
                    value = fn <= 45u ? a + b : a - b;
                    if ((fn == 44u && (~(a ^ b) & (a ^ value) & (UINT64_C(1) << 63u))) ||
                        (fn == 46u && ((a ^ b) & (a ^ value) & (UINT64_C(1) << 63u)))) return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
                    r.gpr[rd] = value; break;
                case 56: r.gpr[rd] = b << sa; break;
                case 58: r.gpr[rd] = rs == 1u ? m64_ror(b, sa) : b >> sa; break;
                case 59: r.gpr[rd] = m64_sar(b, sa); break;
                case 60: r.gpr[rd] = b << (sa + 32u); break;
                case 62: r.gpr[rd] = rs == 1u ? m64_ror(b, sa + 32u) : b >> (sa + 32u); break;
                case 63: r.gpr[rd] = m64_sar(b, sa + 32u); break;
                default: return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
            }
            break;
        case 1:
            if (rt == 31u) break; /* SYNCI */
            if (rt != 0u && rt != 1u && rt != 2u && rt != 3u && rt != 16u && rt != 17u && rt != 18u && rt != 19u)
                return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
            likely = (rt & 2u) != 0u;
            if (rt & 16u) r.gpr[31] = pc + 8u;
            M64_BRANCH((rt & 1u) ? (int64_t)a >= 0 : (int64_t)a < 0); break;
        case 2: case 3:
            branch = 1; target = ((pc + 4u) & ~UINT64_C(0x0fffffff)) | ((uint64_t)(instruction & 0x03ffffffu) << 2u);
            if (op == 3u) r.gpr[31] = pc + 8u;
            break;
        case 4: case 20: M64_BRANCH(a == b); likely = op == 20u; break;
        case 5: case 21: M64_BRANCH(a != b); likely = op == 21u; break;
        case 6: case 22: M64_BRANCH((int64_t)a <= 0); likely = op == 22u; break;
        case 7: case 23: M64_BRANCH((int64_t)a > 0); likely = op == 23u; break;
        case 8: {
            int64_t result = (int64_t)(int32_t)a + (int16_t)imm;
            if (result < INT32_MIN || result > INT32_MAX) return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
            r.gpr[rt] = m64_word((uint32_t)result); break;
        }
        case 9: r.gpr[rt] = m64_word((uint32_t)a + (uint32_t)(int32_t)(int16_t)imm); break;
        case 10: r.gpr[rt] = (int64_t)a < (int16_t)imm; break;
        case 11: r.gpr[rt] = a < (uint64_t)(int64_t)(int16_t)imm; break;
        case 12: r.gpr[rt] = a & imm; break;
        case 13: r.gpr[rt] = a | imm; break;
        case 14: r.gpr[rt] = a ^ imm; break;
        case 15: r.gpr[rt] = m64_word(imm << 16u); break;
        case 24: case 25:
            if (op == 24u && (~(a ^ (uint64_t)(int64_t)(int16_t)imm) & (a ^ address) & (UINT64_C(1) << 63u)))
                return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
            r.gpr[rt] = address; break;
        case 28:
            if (fn == 0u || fn == 1u || fn == 4u || fn == 5u) {
                uint64_t accumulator = ((uint64_t)(uint32_t)r.hi << 32u) | (uint32_t)r.lo;
                uint64_t product = (fn & 1u) ? (uint64_t)(uint32_t)a * (uint32_t)b : (uint64_t)((int64_t)(int32_t)a * (int32_t)b);
                accumulator = (fn & 4u) ? accumulator - product : accumulator + product;
                r.hi = m64_word((uint32_t)(accumulator >> 32u)); r.lo = m64_word((uint32_t)accumulator);
            } else if (fn == 2u) r.gpr[rd] = m64_word((uint32_t)(a * b));
            else if (fn == 32u || fn == 33u || fn == 36u || fn == 37u) {
                unsigned bits = fn >= 36u ? 64u : 32u, count = 0;
                value = (fn & 1u) ? ~a : a;
                if (bits == 32u) value = (uint32_t)value;
                while (count < bits && !(value & (UINT64_C(1) << (bits - 1u)))) { ++count; value <<= 1u; }
                r.gpr[rd] = count;
            } else return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
            break;
        case 31:
            if (fn <= 3u) { /* EXT / DEXTM / DEXTU / DEXT */
                unsigned position = sa + (fn == 2u ? 32u : 0u);
                unsigned bits = rd + (fn == 1u ? 33u : 1u), limit = fn == 0u ? 32u : 64u;
                if (position + bits > limit) return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
                r.gpr[rt] = (a >> position) & m64_mask(bits);
            } else if (fn >= 4u && fn <= 7u) { /* INS / DINSM / DINSU / DINS */
                unsigned position = sa + (fn == 6u ? 32u : 0u), top = rd + ((fn == 5u || fn == 6u) ? 32u : 0u);
                uint64_t field;
                if (top < position || top >= (fn == 4u ? 32u : 64u)) return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
                field = m64_mask(top - position + 1u) << position;
                value = (b & ~field) | ((a << position) & field);
                r.gpr[rt] = fn == 4u ? m64_word((uint32_t)value) : value;
            } else if (fn == 32u && sa == 2u)
                r.gpr[rd] = m64_word((((uint32_t)b & 0x00ff00ffu) << 8u) | (((uint32_t)b & 0xff00ff00u) >> 8u));
            else if (fn == 32u && sa == 16u) r.gpr[rd] = (uint64_t)(int64_t)(int8_t)b;
            else if (fn == 32u && sa == 24u) r.gpr[rd] = (uint64_t)(int64_t)(int16_t)b;
            else if (fn == 36u && sa == 2u)
                r.gpr[rd] = ((b & UINT64_C(0x00ff00ff00ff00ff)) << 8u) | ((b & UINT64_C(0xff00ff00ff00ff00)) >> 8u);
            else if (fn == 36u && sa == 5u)
                r.gpr[rd] = ((b & UINT64_C(0xffff)) << 48u) | ((b & UINT64_C(0xffff0000)) << 16u) |
                            ((b >> 16u) & UINT64_C(0xffff0000)) | (b >> 48u);
            else return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
            break;
        case 32: case 33: case 35: case 36: case 37: case 39: case 48: case 52: case 55:
            size = (op == 32u || op == 36u) ? 1u : (op == 33u || op == 37u) ? 2u : (op == 52u || op == 55u) ? 8u : 4u;
            if (address & (size - 1u)) return XXEMUL_STATUS_ADDRESS_FAULT;
            M64_MEMORY(m64_load(e, address, size, &value));
            if (op == 32u) value = (uint64_t)(int64_t)(int8_t)value;
            if (op == 33u) value = (uint64_t)(int64_t)(int16_t)value;
            if (op == 35u || op == 48u) value = m64_word((uint32_t)value);
            r.gpr[rt] = value;
            if (op == 48u || op == 52u) {
                e->mips64_reservation = address; e->mips64_reservation_size = size; e->mips64_reservation_valid = 1;
            }
            break;
        case 26: case 27: case 34: case 38: case 42: case 44: case 45: case 46: {
            unsigned bytes = op == 26u || op == 27u || op == 44u || op == 45u ? 8u : 4u;
            unsigned offset = (unsigned)(address & (bytes - 1u)), shift;
            int left = op == 26u || op == 34u || op == 42u || op == 44u;
            int big = e->mode == XXEMUL_MODE_MIPS64_BE, load = op == 26u || op == 27u || op == 34u || op == 38u;
            uint64_t field;
            size = left ? (big ? bytes - offset : offset + 1u) : (big ? offset + 1u : bytes - offset);
            if ((left && !big) || (!left && big)) address &= ~(uint64_t)(bytes - 1u);
            shift = left ? (bytes - size) * 8u : 0u; field = m64_mask(size * 8u) << shift;
            if (load) {
                M64_MEMORY(m64_load(e, address, size, &value));
                value = (b & ~field) | (value << shift);
                r.gpr[rt] = bytes == 4u ? m64_word((uint32_t)value) : value;
            } else M64_MEMORY(m64_store(e, address, size, b >> shift));
            break;
        }
        case 40: case 41: case 43: case 56: case 60: case 63:
            size = op == 40u ? 1u : op == 41u ? 2u : (op == 60u || op == 63u) ? 8u : 4u;
            if (address & (size - 1u)) return XXEMUL_STATUS_ADDRESS_FAULT;
            if (op == 56u || op == 60u) {
                int reserved = e->mips64_reservation_valid && e->mips64_reservation == address && e->mips64_reservation_size == size;
                e->mips64_reservation_valid = 0;
                if (reserved) M64_MEMORY(m64_store(e, address, size, b));
                r.gpr[rt] = reserved != 0;
            } else M64_MEMORY(m64_store(e, address, size, b));
            break;
        case 47: case 51: break; /* CACHE / PREF */
        default: return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    }
    if (branch) {
        if (delayed) return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
        if (likely && !taken) { branch = 0; next = pc + 8u; }
        else next = pc + 4u;
    }
    r.gpr[0] = 0; r.pc = next; e->mips64 = r;
    e->mips64_delay_pending = branch;
    if (branch) e->mips64_branch_target = target;
    if (info) info->next_address = next;
#undef M64_MEMORY
#undef M64_BRANCH
    return XXEMUL_STATUS_OK;
}

size_t xxemul_mips64_format_current(xxemul *e, char *buffer, size_t size)
{
    cdisasm_mips_instruction instruction;
    if (m64_decode(e, &instruction) != XXEMUL_STATUS_OK) return 0;
    return cdisasm_mips_format(&instruction, 0, buffer, size);
}
