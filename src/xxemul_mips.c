#include "xxemul_internal.h"
#include "platforms/xxemul_linux.h"

#include <limits.h>
#include <string.h>

/* Standard fixed-width MIPS I/II/MIPS32r2 integer execution. Instruction
 * recognition and presentation share cdisasm's real MIPS decoder. */
static xxemul_status mips_decode(xxemul *e, cdisasm_mips_instruction *instruction)
{
    uint8_t code[4];
    cdisasm_mips_decode_flags flags = CDISASM_DECODE_FLAGS_INITIALIZER(CDISASM_MIPS_DECODE_FLAG_ISA_32R2);
    xxemul_status status;
    if (e->mips.pc & 3u) return XXEMUL_STATUS_ADDRESS_FAULT;
    status = xxemul_read_memory(e, e->mips.pc, code, sizeof(code));
    if (status != XXEMUL_STATUS_OK) return status;
    if (e->mode == XXEMUL_MODE_MIPS32_BE) flags.bitmap[0] |= CDISASM_MIPS_DECODE_FLAG_BIG_ENDIAN;
    return cdisasm_mips_decode(CDISASM_MIPS_CPU_ANY, CDISASM_MIPS_MODE_32, code, sizeof(code),
                               e->mips.pc, &flags, instruction) == 4u
        ? XXEMUL_STATUS_OK : XXEMUL_STATUS_DECODE_ERROR;
}

static xxemul_status mips_load(xxemul *e, uint32_t address, unsigned size, uint32_t *value)
{
    uint8_t bytes[4];
    unsigned i;
    xxemul_status status;
    if (!size || size > 4 || (uint64_t)address + size > UINT64_C(0x100000000)) return XXEMUL_STATUS_ADDRESS_FAULT;
    status = xxemul_read_memory(e, address, bytes, size);
    if (status != XXEMUL_STATUS_OK) return status;
    if (e->memory_hook && e->in_step) e->memory_hook(e->memory_hook_context, address, size, 0);
    *value = 0;
    for (i = 0; i < size; ++i) {
        unsigned shift = e->mode == XXEMUL_MODE_MIPS32_BE ? (size - 1u - i) * 8u : i * 8u;
        *value |= (uint32_t)bytes[i] << shift;
    }
    return XXEMUL_STATUS_OK;
}

static xxemul_status mips_store(xxemul *e, uint32_t address, unsigned size, uint32_t value)
{
    uint8_t bytes[4];
    unsigned i;
    xxemul_status status;
    if (!size || size > 4 || (uint64_t)address + size > UINT64_C(0x100000000)) return XXEMUL_STATUS_ADDRESS_FAULT;
    for (i = 0; i < size; ++i) {
        unsigned shift = e->mode == XXEMUL_MODE_MIPS32_BE ? (size - 1u - i) * 8u : i * 8u;
        bytes[i] = (uint8_t)(value >> shift);
    }
    e->mips_reservation_valid = 0;
    status = xxemul_write_memory(e, address, bytes, size);
    if (status == XXEMUL_STATUS_OK && e->memory_hook && e->in_step)
        e->memory_hook(e->memory_hook_context, address, size, 1);
    return status;
}

static uint32_t mips_ror(uint32_t value, unsigned shift)
{
    shift &= 31u;
    return shift ? (value >> shift) | (value << (32u - shift)) : value;
}

static uint32_t mips_sar(uint32_t value, unsigned shift)
{
    shift &= 31u;
    return shift && (value & 0x80000000u) ? (value >> shift) | (UINT32_MAX << (32u - shift)) : value >> shift;
}

static uint32_t mips_low_mask(unsigned bits)
{
    return bits >= 32u ? UINT32_MAX : ((UINT32_C(1) << bits) - 1u);
}

xxemul_status xxemul_mips_step(xxemul *e, xxemul_step_info *info)
{
    cdisasm_mips_instruction decoded;
    xxemul_mips_state r;
    xxemul_status status;
    uint32_t instruction, pc, next, target = 0, a, b, value = 0, address;
    uint32_t op, rs, rt, rd, sa, fn, imm;
    int delayed, branch = 0, taken, likely = 0;
    unsigned size;
    status = mips_decode(e, &decoded);
    if (status != XXEMUL_STATUS_OK) return status;
    instruction = decoded.raw_instruction;
    pc = e->mips.pc;
    delayed = e->mips_delay_pending;
    next = delayed ? e->mips_branch_target : pc + 4u;
    r = e->mips;
    r.gpr[0] = 0;
    op = instruction >> 26;
    rs = (instruction >> 21) & 31u;
    rt = (instruction >> 16) & 31u;
    rd = (instruction >> 11) & 31u;
    sa = (instruction >> 6) & 31u;
    fn = instruction & 63u;
    imm = instruction & 0xffffu;
    a = r.gpr[rs];
    b = r.gpr[rt];
    address = a + (uint32_t)(int32_t)(int16_t)imm;
    if (info) {
        info->address = pc;
        info->size = 4;
        info->instruction_id = decoded.name_id;
    }
#define MIPS_MEMORY(call) do { status = (call); if (status != XXEMUL_STATUS_OK) return status; } while (0)
#define MIPS_BRANCH(condition) do { branch = 1; taken = (condition); \
    target = taken ? pc + 4u + (uint32_t)((int32_t)(int16_t)imm * 4) : pc + 8u; } while (0)
    switch (op) {
        case 0:
            switch (fn) {
                case 0: r.gpr[rd] = b << sa; break; /* sll/nop */
                case 2: r.gpr[rd] = rs == 1u ? mips_ror(b, sa) : b >> sa; break;
                case 3: r.gpr[rd] = mips_sar(b, sa); break;
                case 4: r.gpr[rd] = b << (a & 31u); break;
                case 6: r.gpr[rd] = sa == 1u ? mips_ror(b, a) : b >> (a & 31u); break;
                case 7: r.gpr[rd] = mips_sar(b, a); break;
                case 8: branch = 1; target = a; break; /* jr */
                case 9: branch = 1; target = a; r.gpr[rd] = pc + 8u; break;
                case 10: if (!b) r.gpr[rd] = a; break;
                case 11: if (b) r.gpr[rd] = a; break;
                case 12:
                    if (!e->linux_process) return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
                    r.pc = next;
                    e->mips = r;
                    e->mips_delay_pending = 0;
                    status = xxemul_linux_dispatch(e->linux_process);
                    if (xxemul_linux_has_exited(e->linux_process)) {
                        e->halted = 1;
                        status = XXEMUL_STATUS_HALTED;
                    }
                    e->mips.gpr[0] = 0;
                    if (info) info->next_address = e->mips.pc;
                    return status;
                case 13:
                    r.pc = next;
                    e->mips = r;
                    e->mips_delay_pending = 0;
                    if (info) info->next_address = next;
                    if (e->debug_traps) return XXEMUL_STATUS_BREAKPOINT;
                    e->halted = 1;
                    return XXEMUL_STATUS_HALTED;
                case 15: break; /* sync: memory is coherent */
                case 16: r.gpr[rd] = r.hi; break;
                case 17: r.hi = a; break;
                case 18: r.gpr[rd] = r.lo; break;
                case 19: r.lo = a; break;
                case 24: case 25: {
                    uint64_t product = fn == 24u ? (uint64_t)((int64_t)(int32_t)a * (int32_t)b) : (uint64_t)a * b;
                    r.hi = (uint32_t)(product >> 32); r.lo = (uint32_t)product;
                    break;
                }
                case 26:
                    if (!b) { r.hi = a; r.lo = (int32_t)a < 0 ? 1u : UINT32_MAX; }
                    else if (a == 0x80000000u && b == UINT32_MAX) { r.hi = 0; r.lo = a; }
                    else { r.lo = (uint32_t)((int32_t)a / (int32_t)b); r.hi = (uint32_t)((int32_t)a % (int32_t)b); }
                    break;
                case 27: r.hi = b ? a % b : a; r.lo = b ? a / b : UINT32_MAX; break;
                case 32: case 34: {
                    int64_t result = (int64_t)(int32_t)a + (fn == 32u ? (int64_t)(int32_t)b : -(int64_t)(int32_t)b);
                    if (result < INT32_MIN || result > INT32_MAX) return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
                    r.gpr[rd] = (uint32_t)result; break;
                }
                case 33: r.gpr[rd] = a + b; break;
                case 35: r.gpr[rd] = a - b; break;
                case 36: r.gpr[rd] = a & b; break;
                case 37: r.gpr[rd] = a | b; break;
                case 38: r.gpr[rd] = a ^ b; break;
                case 39: r.gpr[rd] = ~(a | b); break;
                case 42: r.gpr[rd] = (int32_t)a < (int32_t)b; break;
                case 43: r.gpr[rd] = a < b; break;
                default: return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
            }
            break;
        case 1:
            if (rt == 31u) break; /* synci */
            if (rt != 0u && rt != 1u && rt != 2u && rt != 3u && rt != 16u && rt != 17u && rt != 18u && rt != 19u)
                return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
            likely = (rt & 2u) != 0u;
            if (rt & 16u) r.gpr[31] = pc + 8u;
            MIPS_BRANCH((rt & 1u) ? (int32_t)a >= 0 : (int32_t)a < 0);
            break;
        case 2: case 3:
            branch = 1;
            target = ((pc + 4u) & 0xf0000000u) | ((instruction & 0x03ffffffu) << 2);
            if (op == 3u) r.gpr[31] = pc + 8u;
            break;
        case 4: case 20: MIPS_BRANCH(a == b); likely = op == 20u; break;
        case 5: case 21: MIPS_BRANCH(a != b); likely = op == 21u; break;
        case 6: case 22: MIPS_BRANCH((int32_t)a <= 0); likely = op == 22u; break;
        case 7: case 23: MIPS_BRANCH((int32_t)a > 0); likely = op == 23u; break;
        case 8: {
            int64_t result = (int64_t)(int32_t)a + (int16_t)imm;
            if (result < INT32_MIN || result > INT32_MAX) return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
            r.gpr[rt] = (uint32_t)result; break;
        }
        case 9: r.gpr[rt] = address; break;
        case 10: r.gpr[rt] = (int32_t)a < (int32_t)(int16_t)imm; break;
        case 11: r.gpr[rt] = a < (uint32_t)(int32_t)(int16_t)imm; break;
        case 12: r.gpr[rt] = a & imm; break;
        case 13: r.gpr[rt] = a | imm; break;
        case 14: r.gpr[rt] = a ^ imm; break;
        case 15: r.gpr[rt] = imm << 16; break;
        case 28:
            if (fn == 0u || fn == 1u || fn == 4u || fn == 5u) {
                uint64_t accumulator = ((uint64_t)r.hi << 32) | r.lo;
                uint64_t product = (fn & 1u) ? (uint64_t)a * b : (uint64_t)((int64_t)(int32_t)a * (int32_t)b);
                accumulator = (fn & 4u) ? accumulator - product : accumulator + product;
                r.hi = (uint32_t)(accumulator >> 32); r.lo = (uint32_t)accumulator;
            } else if (fn == 2u) r.gpr[rd] = (uint32_t)((uint64_t)a * b);
            else if (fn == 32u || fn == 33u) {
                unsigned count = 0;
                value = fn == 33u ? ~a : a;
                while (count < 32u && !(value & 0x80000000u)) { ++count; value <<= 1; }
                r.gpr[rd] = count;
            } else return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
            break;
        case 31:
            if (fn == 0u) { /* ext */
                size = rd + 1u;
                if (sa + size > 32u) return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
                r.gpr[rt] = (a >> sa) & mips_low_mask(size);
            } else if (fn == 4u) { /* ins */
                uint32_t mask;
                if (rd < sa) return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
                mask = mips_low_mask(rd - sa + 1u) << sa;
                r.gpr[rt] = (b & ~mask) | ((a << sa) & mask);
            } else if (fn == 32u && sa == 2u) r.gpr[rd] = ((b & 0x00ff00ffu) << 8) | ((b & 0xff00ff00u) >> 8);
            else if (fn == 32u && sa == 16u) r.gpr[rd] = (uint32_t)(int32_t)(int8_t)b;
            else if (fn == 32u && sa == 24u) r.gpr[rd] = (uint32_t)(int32_t)(int16_t)b;
            else return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
            break;
        case 32: case 33: case 35: case 36: case 37: case 48:
            size = (op == 32u || op == 36u) ? 1u : (op == 33u || op == 37u) ? 2u : 4u;
            if (address & (size - 1u)) return XXEMUL_STATUS_ADDRESS_FAULT;
            MIPS_MEMORY(mips_load(e, address, size, &value));
            if (op == 32u) value = (uint32_t)(int32_t)(int8_t)value;
            if (op == 33u) value = (uint32_t)(int32_t)(int16_t)value;
            r.gpr[rt] = value;
            if (op == 48u) { e->mips_reservation = address; e->mips_reservation_valid = 1; }
            break;
        case 34: case 38: case 42: case 46: {
            unsigned offset = address & 3u, shift;
            int left = op == 34u || op == 42u;
            int big = e->mode == XXEMUL_MODE_MIPS32_BE;
            uint32_t mask;
            size = left ? (big ? 4u - offset : offset + 1u) : (big ? offset + 1u : 4u - offset);
            if ((left && !big) || (!left && big)) address &= ~3u;
            shift = left ? (4u - size) * 8u : 0u;
            mask = mips_low_mask(size * 8u) << shift;
            if (op == 34u || op == 38u) {
                MIPS_MEMORY(mips_load(e, address, size, &value));
                r.gpr[rt] = (b & ~mask) | (value << shift);
            } else MIPS_MEMORY(mips_store(e, address, size, b >> shift));
            break;
        }
        case 40: case 41: case 43: case 56:
            size = op == 40u ? 1u : op == 41u ? 2u : 4u;
            if (address & (size - 1u)) return XXEMUL_STATUS_ADDRESS_FAULT;
            if (op == 56u) {
                int reserved = e->mips_reservation_valid && e->mips_reservation == address;
                e->mips_reservation_valid = 0;
                if (reserved) MIPS_MEMORY(mips_store(e, address, size, b));
                r.gpr[rt] = reserved != 0;
            } else MIPS_MEMORY(mips_store(e, address, size, b));
            break;
        case 47: case 51: break; /* cache/pref: no separate data cache */
        default: return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    }
    if (branch) {
        /* Branches in a branch delay slot are architecturally unpredictable. */
        if (delayed) return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
        if (likely && target == pc + 8u && !taken) { branch = 0; next = pc + 8u; }
        else next = pc + 4u;
    }
    r.gpr[0] = 0;
    r.pc = next;
    e->mips = r;
    e->mips_delay_pending = branch;
    if (branch) e->mips_branch_target = target;
    if (info) info->next_address = next;
#undef MIPS_MEMORY
#undef MIPS_BRANCH
    return XXEMUL_STATUS_OK;
}

size_t xxemul_mips_format_current(xxemul *e, char *buffer, size_t size)
{
    cdisasm_mips_instruction instruction;
    if (mips_decode(e, &instruction) != XXEMUL_STATUS_OK) return 0;
    return cdisasm_mips_format(&instruction, 0, buffer, size);
}
