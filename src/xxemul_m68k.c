#include "xxemul_internal.h"

#include <limits.h>
#include <string.h>

/* MC68000 architectural interpreter. cdisasm owns instruction recognition,
 * extension words and legality; this file owns execution and bus accesses.
 * Undefined CCR bits (BCD N/V, DIV overflow N/Z, CHK Z/V/C) are preserved.
 * No bus timing, prefetch queue, external devices or interrupt source is
 * modeled. RESET is consequently a privileged no-op. */
#define C XXEMUL_M68K_SR_C
#define V XXEMUL_M68K_SR_V
#define Z XXEMUL_M68K_SR_Z
#define N XXEMUL_M68K_SR_N
#define X XXEMUL_M68K_SR_X
#define S XXEMUL_M68K_SR_S
#define T XXEMUL_M68K_SR_T
#define SR_MASK UINT16_C(0xa71f)

static void sync_sp(xxemul_m68k_state *r)
{
    if (r->sr & S) r->ssp = r->a[7];
    else r->usp = r->a[7];
}

static void set_sr(xxemul_m68k_state *r, uint16_t sr)
{
    sync_sp(r);
    if ((r->sr ^ sr) & S) r->a[7] = (sr & S) ? r->ssp : r->usp;
    r->sr = sr & SR_MASK;
}

xxemul_m68k_state *xxemul_m68k_regs(xxemul *e)
{
    return e && e->arch == XXEMUL_ARCH_M68K ? &e->m68k : NULL;
}

xxemul_status xxemul_get_m68k_state(const xxemul *e, xxemul_m68k_state *state)
{
    if (!e || !state || e->arch != XXEMUL_ARCH_M68K) return XXEMUL_STATUS_INVALID_ARGUMENT;
    *state = e->m68k;
    sync_sp(state);
    return XXEMUL_STATUS_OK;
}

xxemul_status xxemul_set_m68k_state(xxemul *e, const xxemul_m68k_state *state)
{
    if (!e || !state || e->arch != XXEMUL_ARCH_M68K || (state->pc & 1u)) return XXEMUL_STATUS_INVALID_ARGUMENT;
    e->m68k = *state;
    e->m68k.sr &= SR_MASK;
    e->m68k.reserved = 0;
    sync_sp(&e->m68k);
    e->halted = 0;
    return XXEMUL_STATUS_OK;
}

static uint32_t mask_for(unsigned size)
{
    return size == 1 ? UINT32_C(0xff) : size == 2 ? UINT32_C(0xffff) : UINT32_MAX;
}

static uint32_t sext(uint32_t value, unsigned size)
{
    uint32_t sign = UINT32_C(1) << (size * 8u - 1u);
    return ((value & mask_for(size)) ^ sign) - sign;
}

static xxemul_status fault(xxemul *e, uint32_t address, unsigned access)
{
    e->fault_address = address;
    e->fault_access = access; /* 1 read, 2 write, 8 instruction */
    e->fault_address_valid = 1;
    return XXEMUL_STATUS_ADDRESS_FAULT;
}

static xxemul_status load(xxemul *e, uint32_t address, unsigned size, uint32_t *value)
{
    uint8_t bytes[4];
    unsigned i;
    if ((size > 1 && (address & 1u)) || (uint64_t)address + size > UINT64_C(0x100000000) || xxemul_read_memory(e, address, bytes, size) != XXEMUL_STATUS_OK)
        return fault(e, address, 1);
    *value = 0;
    for (i = 0; i < size; ++i) *value = (*value << 8) | bytes[i];
    if (e->memory_hook && e->in_step) e->memory_hook(e->memory_hook_context, address, size, 0);
    return XXEMUL_STATUS_OK;
}

static xxemul_status store_value(xxemul *e, uint32_t address, unsigned size, uint32_t value)
{
    uint8_t bytes[4];
    unsigned i;
    if ((size > 1 && (address & 1u)) || (uint64_t)address + size > UINT64_C(0x100000000)) return fault(e, address, 2);
    for (i = 0; i < size; ++i) bytes[i] = (uint8_t)(value >> ((size - 1u - i) * 8u));
    if (xxemul_write_memory(e, address, bytes, size) != XXEMUL_STATUS_OK) return fault(e, address, 2);
    if (e->memory_hook && e->in_step) e->memory_hook(e->memory_hook_context, address, size, 1);
    return XXEMUL_STATUS_OK;
}

static xxemul_status decode(xxemul *e, cdisasm_m68k_instruction *ins)
{
    uint8_t bytes[CDISASM_M68K_MAX_LENGTH] = {0};
    uint32_t pc = e->m68k.pc;
    size_t available;
    if ((pc & 1u) || pc < e->region_address || (uint64_t)pc - e->region_address >= e->region_size) return fault(e, pc, 8);
    available = e->region_size - (size_t)((uint64_t)pc - e->region_address);
    if (available > sizeof(bytes)) available = sizeof(bytes);
    if (available < 2 || xxemul_read_memory(e, pc, bytes, available) != XXEMUL_STATUS_OK) return fault(e, pc, 8);
    memset(ins, 0, sizeof(*ins));
    if (cdisasm_m68k_decode(CDISASM_M68K_CPU_68000, 0, bytes, available, pc, NULL, ins)) return XXEMUL_STATUS_OK;
    /* Distinguish a valid instruction with missing extension words from an
     * illegal encoding. Padding is used only for this length probe. */
    if (available < sizeof(bytes) && cdisasm_m68k_decode(CDISASM_M68K_CPU_68000, 0, bytes, sizeof(bytes), pc, NULL, ins))
        return fault(e, pc + (uint32_t)(available & ~(size_t)1), 8);
    memset(ins, 0, sizeof(*ins));
    ins->opcode = (uint16_t)((bytes[0] << 8) | bytes[1]);
    ins->address = pc;
    ins->length = 2;
    return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
}

/* Resolve an operand once, so read/modify/write never increments An twice.
 * Source operands are resolved/read before destination operands, including
 * when both operands use the same postincrement/predecrement register. */
typedef struct operand_ref {
    unsigned kind; /* 0 immediate, 1 Dn, 2 An, 3 memory, 4 CCR, 5 SR, 6 USP */
    unsigned reg, size;
    uint32_t address, value;
} operand_ref;

static operand_ref resolve(xxemul_m68k_state *r, const cdisasm_m68k_operand *op, unsigned size, int update)
{
    operand_ref ref = {0, op->reg, size, 0, (uint32_t)op->imm};
    unsigned mode = op->ea_mode, step = size == 1 && op->reg == 7 ? 2 : size;
    uint32_t index;
    switch (op->type) {
        case CDISASM_M68K_OP_DREG: ref.kind = 1; return ref;
        case CDISASM_M68K_OP_AREG: ref.kind = 2; return ref;
        case CDISASM_M68K_OP_RREG:
            ref.kind = op->reg < 8 ? 1 : 2;
            ref.reg &= 7;
            return ref;
        case CDISASM_M68K_OP_CCR: ref.kind = 4; return ref;
        case CDISASM_M68K_OP_SR: ref.kind = 5; return ref;
        case CDISASM_M68K_OP_USP: ref.kind = 6; return ref;
        case CDISASM_M68K_OP_PREDEC: mode = CDISASM_M68K_EA_PREDEC; break;
        case CDISASM_M68K_OP_POSTINC: mode = CDISASM_M68K_EA_POSTINC; break;
        case CDISASM_M68K_OP_DISP: mode = CDISASM_M68K_EA_DISP; break;
        case CDISASM_M68K_OP_IND: mode = CDISASM_M68K_EA_IND; break;
        case CDISASM_M68K_OP_EA: break;
        default: return ref;
    }
    ref.kind = 3;
    switch (mode) {
        case CDISASM_M68K_EA_DN: ref.kind = 1; break;
        case CDISASM_M68K_EA_AN: ref.kind = 2; break;
        case CDISASM_M68K_EA_IND: ref.address = r->a[op->reg]; break;
        case CDISASM_M68K_EA_POSTINC:
            ref.address = r->a[op->reg];
            if (update) r->a[op->reg] += step;
            break;
        case CDISASM_M68K_EA_PREDEC:
            if (update) r->a[op->reg] -= step;
            ref.address = r->a[op->reg];
            break;
        case CDISASM_M68K_EA_DISP: ref.address = r->a[op->reg] + (uint32_t)op->disp; break;
        case CDISASM_M68K_EA_INDEX:
        case CDISASM_M68K_EA_PC_INDEX:
            index = op->reg2 < 8 ? r->d[op->reg2] : r->a[op->reg2 - 8];
            if (op->index_size == 2) index = sext(index, 2);
            ref.address = (mode == CDISASM_M68K_EA_INDEX ? r->a[op->reg] : op->ext_address) + (uint32_t)op->disp + index;
            break;
        case CDISASM_M68K_EA_ABS_W: ref.address = sext((uint32_t)op->imm, 2); break;
        case CDISASM_M68K_EA_ABS_L:
        case CDISASM_M68K_EA_PC_DISP: ref.address = (uint32_t)op->imm; break;
        default: ref.kind = 0; break;
    }
    return ref;
}

static xxemul_status read_ref(xxemul *e, operand_ref ref, uint32_t *value)
{
    xxemul_m68k_state *r = &e->m68k;
    switch (ref.kind) {
        case 1: *value = r->d[ref.reg]; break;
        case 2: *value = r->a[ref.reg]; break;
        case 3: return load(e, ref.address, ref.size, value);
        case 4: *value = r->sr & 31u; break;
        case 5: *value = r->sr; break;
        case 6: *value = r->usp; break;
        default: *value = ref.value; break;
    }
    *value &= mask_for(ref.size);
    return XXEMUL_STATUS_OK;
}

static xxemul_status write_ref(xxemul *e, operand_ref ref, uint32_t value)
{
    xxemul_m68k_state *r = &e->m68k;
    uint32_t mask = mask_for(ref.size);
    switch (ref.kind) {
        case 1: r->d[ref.reg] = (r->d[ref.reg] & ~mask) | (value & mask); break;
        case 2: r->a[ref.reg] = ref.size == 2 ? sext(value, 2) : value; break;
        case 3: return store_value(e, ref.address, ref.size, value);
        case 4: r->sr = (uint16_t)((r->sr & ~31u) | (value & 31u)); break;
        case 5: set_sr(r, (uint16_t)value); break;
        case 6: r->usp = value; break;
        default: return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    }
    return XXEMUL_STATUS_OK;
}

static void logic_flags(xxemul_m68k_state *r, uint32_t value, unsigned size)
{
    value &= mask_for(size);
    r->sr &= (uint16_t)~(N | Z | V | C);
    if (!value) r->sr |= Z;
    if (value & (UINT32_C(1) << (size * 8u - 1u))) r->sr |= N;
}

static uint32_t arithmetic(xxemul_m68k_state *r, uint32_t dst, uint32_t src, unsigned size, int sub, int extend, int compare)
{
    uint32_t mask = mask_for(size), sign = UINT32_C(1) << (size * 8u - 1u);
    unsigned carry_in = extend && (r->sr & X) ? 1u : 0u;
    uint16_t old = r->sr;
    uint64_t wide;
    uint32_t result;
    int carry, overflow;
    dst &= mask;
    src &= mask;
    wide = sub ? (uint64_t)dst - src - carry_in : (uint64_t)dst + src + carry_in;
    result = (uint32_t)wide & mask;
    carry = sub ? (uint64_t)src + carry_in > dst : wide > mask;
    overflow = sub ? ((dst ^ src) & (dst ^ result) & sign) != 0 : ((~(dst ^ src)) & (dst ^ result) & sign) != 0;
    logic_flags(r, result, size);
    if (extend && !(old & Z)) r->sr &= (uint16_t)~Z;
    if (overflow) r->sr |= V;
    if (carry) r->sr |= C;
    if (!compare) r->sr = (uint16_t)((r->sr & ~X) | (carry ? X : 0));
    return result;
}

static int condition(uint16_t sr, unsigned cc)
{
    int c = !!(sr & C), z = !!(sr & Z), n = !!(sr & N), v = !!(sr & V);
    switch (cc) {
        case 0: return 1;
        case 1: return 0;
        case 2: return !c && !z;
        case 3: return c || z;
        case 4: return !c;
        case 5: return c;
        case 6: return !z;
        case 7: return z;
        case 8: return !v;
        case 9: return v;
        case 10: return !n;
        case 11: return n;
        case 12: return n == v;
        case 13: return n != v;
        case 14: return !z && n == v;
        default: return z || n != v;
    }
}

static xxemul_status push(xxemul *e, unsigned size, uint32_t value)
{
    e->m68k.a[7] -= size;
    return store_value(e, e->m68k.a[7], size, value);
}

static xxemul_status pop(xxemul *e, unsigned size, uint32_t *value)
{
    xxemul_status status = load(e, e->m68k.a[7], size, value);
    if (status == XXEMUL_STATUS_OK) e->m68k.a[7] += size;
    return status;
}

static xxemul_status exception(xxemul *e, unsigned vector, uint16_t opcode, uint32_t saved_pc)
{
    xxemul_m68k_state *r = &e->m68k;
    uint32_t target, sp;
    uint16_t old_sr = r->sr;
    uint32_t access_address = (uint32_t)e->fault_address;
    unsigned access = e->fault_access;
    uint8_t bytes[4];
    xxemul_status fallback = vector == 4 ? XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION : vector == 3 ? XXEMUL_STATUS_ADDRESS_FAULT : XXEMUL_STATUS_HALTED;
    e->m68k_exception_vector = vector;
    e->m68k_exception_opcode = opcode;
    /* An absent table/zero vector is a host-visible stop, not a recursive
     * fault while trying to read an unmapped vector table. */
    if (e->region_address != 0 || xxemul_read_memory(e, vector * 4u, bytes, 4) != XXEMUL_STATUS_OK) goto unhandled;
    target = ((uint32_t)bytes[0] << 24) | ((uint32_t)bytes[1] << 16) | ((uint32_t)bytes[2] << 8) | bytes[3];
    if (!target) goto unhandled;
    if (e->memory_hook && e->in_step) e->memory_hook(e->memory_hook_context, vector * 4u, 4, 0);
    set_sr(r, (uint16_t)((old_sr | S) & ~T));
    sp = r->a[7] - (vector == 3 ? 14u : 6u);
    if (vector == 3) {
        /* PRM B-2: SSW, access address, IR, SR, PC (seven words). */
        /* I/N is zero while processing an instruction (including its
         * data cycles); function code distinguishes data from program. */
        uint16_t ssw = (uint16_t)((access == 2 ? 0 : 16) | (old_sr & S ? 4 : 0) | (access == 8 ? 2 : 1));
        if (store_value(e, sp, 2, ssw) != XXEMUL_STATUS_OK || store_value(e, sp + 2, 4, access_address) != XXEMUL_STATUS_OK ||
            store_value(e, sp + 6, 2, opcode) != XXEMUL_STATUS_OK)
            goto double_fault;
    }
    if (store_value(e, sp + (vector == 3 ? 8u : 0u), 2, old_sr) != XXEMUL_STATUS_OK || store_value(e, sp + (vector == 3 ? 10u : 2u), 4, saved_pc) != XXEMUL_STATUS_OK)
        goto double_fault;
    r->a[7] = sp;
    r->pc = target;
    sync_sp(r);
    return XXEMUL_STATUS_OK;
double_fault:
    e->halted = 1;
    return XXEMUL_STATUS_ADDRESS_FAULT;
unhandled:
    if (fallback == XXEMUL_STATUS_HALTED) e->halted = 1;
    return fallback;
}

static uint32_t shift_value(xxemul_m68k_state *r, uint32_t value, unsigned size, unsigned count, unsigned type, int left)
{
    uint32_t mask = mask_for(size), sign = UINT32_C(1) << (size * 8u - 1u);
    unsigned i, carry = type == 2 && (r->sr & X) ? 1 : 0, extend = !!(r->sr & X), overflow = 0;
    value &= mask;
    for (i = 0; i < count; ++i) {
        uint32_t old = value;
        carry = left ? !!(value & sign) : value & 1u;
        value = left ? (value << 1) & mask : value >> 1;
        if (type == 0 && !left) value |= old & sign;
        if (type == 0 && left && ((old ^ value) & sign)) overflow = 1;
        if (type == 2) value |= left ? extend : (extend ? sign : 0);
        if (type == 3) value |= left ? carry : (carry ? sign : 0);
        if (type != 3) extend = carry;
    }
    logic_flags(r, value, size);
    if (carry) r->sr |= C;
    if (overflow) r->sr |= V;
    if (type != 3 && count) r->sr = (uint16_t)((r->sr & ~X) | (extend ? X : 0));
    return value;
}

static uint32_t decimal(xxemul_m68k_state *r, uint32_t dst, uint32_t src, int sub)
{
    int x = !!(r->sr & X), carry, result;
    dst &= 255u;
    src &= 255u;
    if (sub) {
        result = (int)dst - (int)src - x;
        if ((int)(dst & 15u) - (int)(src & 15u) - x < 0) result -= 6;
        carry = (int)dst - (int)src - x < 0;
        if (carry) result -= 0x60;
    } else {
        result = (int)dst + (int)src + x;
        if ((dst & 15u) + (src & 15u) + (unsigned)x > 9) result += 6;
        carry = result > 0x99;
        if (carry) result += 0x60;
    }
    r->sr = (uint16_t)((r->sr & ~(X | C)) | (carry ? X | C : 0));
    if (result & 255) r->sr &= (uint16_t)~Z;
    return (uint32_t)result & 255u;
}

static xxemul_status execute(xxemul *e, const cdisasm_m68k_instruction *ins, uint32_t *next)
{
    xxemul_m68k_state *r = &e->m68k;
    const cdisasm_m68k_operand *ops = ins->operand;
    const char *name = cdisasm_m68k_name(ins->name_id);
    unsigned size = ins->size == 'b' ? 1u : ins->size == 'w' ? 2u : 4u;
    unsigned count = ins->operand_count, opcode = ins->opcode;
    operand_ref src, dst;
    uint32_t a = 0, b = 0, result = 0;
    xxemul_status status;
#define IS(s) (!strcmp(name, (s)))
#define TRY(call)                                      \
    do {                                               \
        status = (call);                               \
        if (status != XXEMUL_STATUS_OK) return status; \
    } while (0)
#define SOURCE(i, n)                       \
    do {                                   \
        src = resolve(r, &ops[i], (n), 1); \
        TRY(read_ref(e, src, &a));         \
    } while (0)
#define DEST(i, n)                         \
    do {                                   \
        dst = resolve(r, &ops[i], (n), 1); \
        TRY(read_ref(e, dst, &b));         \
    } while (0)
#define WRITE(v) TRY(write_ref(e, dst, (v)))
    if ((ins->flags & CDISASM_M68K_FLAG_PRIVILEGED) && !(r->sr & S)) return exception(e, 8, ins->opcode, r->pc);
    if (IS("nop") || IS("reset")) return XXEMUL_STATUS_OK;
    if (IS("illegal")) {
        if (e->debug_traps) {
            r->pc = *next;
            return XXEMUL_STATUS_BREAKPOINT;
        }
        return exception(e, 4, ins->opcode, r->pc);
    }
    if (IS("trap")) return exception(e, 32u + (opcode & 15u), ins->opcode, *next);
    if (IS("trapv")) return r->sr & V ? exception(e, 7, ins->opcode, *next) : XXEMUL_STATUS_OK;
    if (IS("stop")) {
        set_sr(r, (uint16_t)ops[0].imm);
        r->pc = *next;
        e->halted = 1;
        return XXEMUL_STATUS_HALTED;
    }
    if (IS("rts") || IS("rtr") || IS("rte")) {
        if (!IS("rts")) TRY(pop(e, 2, &a));
        TRY(pop(e, 4, next));
        if (IS("rtr")) r->sr = (uint16_t)((r->sr & ~31u) | (a & 31u));
        if (IS("rte")) set_sr(r, (uint16_t)a);
        return XXEMUL_STATUS_OK;
    }
    if (IS("link")) {
        unsigned reg = ops[0].reg;
        a = r->a[reg];
        TRY(push(e, 4, a));
        r->a[reg] = r->a[7];
        r->a[7] += (uint32_t)ops[1].imm;
        return XXEMUL_STATUS_OK;
    }
    if (IS("unlk")) {
        r->a[7] = r->a[ops[0].reg];
        TRY(pop(e, 4, &a));
        r->a[ops[0].reg] = a;
        return XXEMUL_STATUS_OK;
    }
    if (IS("lea") || IS("pea") || IS("jmp") || IS("jsr")) {
        src = resolve(r, &ops[0], 4, 0);
        if (IS("lea")) r->a[ops[1].reg] = src.address;
        else if (IS("pea")) TRY(push(e, 4, src.address));
        else {
            if (IS("jsr")) TRY(push(e, 4, *next));
            *next = src.address;
        }
        return XXEMUL_STATUS_OK;
    }
    if ((opcode & 0xf000u) == 0x6000u) {
        unsigned cc = (opcode >> 8) & 15u;
        if (cc == 1) TRY(push(e, 4, *next));
        if (cc <= 1 || condition(r->sr, cc)) *next = (uint32_t)ins->branch_target;
        return XXEMUL_STATUS_OK;
    }
    if ((opcode & 0xf0f8u) == 0x50c8u) { /* DBcc never changes CCR. */
        if (!condition(r->sr, (opcode >> 8) & 15u)) {
            unsigned reg = opcode & 7u;
            uint32_t low = (r->d[reg] - 1u) & 0xffffu;
            r->d[reg] = (r->d[reg] & 0xffff0000u) | low;
            if (low != 0xffffu) *next = (uint32_t)ins->branch_target;
        }
        return XXEMUL_STATUS_OK;
    }
    if ((opcode & 0xf0c0u) == 0x50c0u) {
        dst = resolve(r, &ops[0], 1, 1);
        WRITE(condition(r->sr, (opcode >> 8) & 15u) ? 255u : 0u);
        return XXEMUL_STATUS_OK;
    }
    if (IS("movem")) {
        int from_memory = ops[0].type == CDISASM_M68K_OP_EA;
        const cdisasm_m68k_operand *mem = &ops[from_memory ? 0 : 1];
        uint32_t list = ops[from_memory ? 1 : 0].value;
        uint32_t original[16];
        int i, predec = mem->ea_mode == CDISASM_M68K_EA_PREDEC;
        src = resolve(r, mem, size, 0);
        a = src.address;
        for (i = 0; i < 16; ++i) original[i] = i < 8 ? r->d[i] : r->a[i - 8];
        for (i = 0; i < 16; ++i) {
            unsigned reg = predec ? 15u - (unsigned)i : (unsigned)i;
            if (!(list & (1u << reg))) continue;
            if (predec) a -= size;
            if (from_memory) {
                TRY(load(e, a, size, &b));
                if (size == 2) b = sext(b, 2);
                if (reg < 8) r->d[reg] = b;
                else r->a[reg - 8] = b;
            } else TRY(store_value(e, a, size, original[reg]));
            if (!predec) a += size;
        }
        if (predec || mem->ea_mode == CDISASM_M68K_EA_POSTINC) r->a[mem->reg] = a;
        return XXEMUL_STATUS_OK;
    }
    if (IS("movep")) {
        int from_memory = ops[0].type == CDISASM_M68K_OP_DISP;
        const cdisasm_m68k_operand *mem = &ops[from_memory ? 0 : 1];
        unsigned reg = ops[from_memory ? 1 : 0].reg, i;
        a = r->a[mem->reg] + (uint32_t)mem->disp;
        for (i = 0; i < size; ++i) {
            if (from_memory) {
                TRY(load(e, a + i * 2u, 1, &b));
                result = (result << 8) | b;
            } else TRY(store_value(e, a + i * 2u, 1, r->d[reg] >> ((size - 1u - i) * 8u)));
        }
        if (from_memory) r->d[reg] = (r->d[reg] & ~mask_for(size)) | result;
        return XXEMUL_STATUS_OK;
    }
    if (IS("move") || IS("movea") || IS("moveq")) {
        SOURCE(0, size);
        dst = resolve(r, &ops[1], size, 1);
        WRITE(a);
        if (IS("moveq") || (IS("move") && src.kind != 4 && src.kind != 5 && src.kind != 6 && dst.kind < 4)) logic_flags(r, a, size);
        return XXEMUL_STATUS_OK;
    }
    if (IS("exg")) {
        SOURCE(0, 4);
        DEST(1, 4);
        WRITE(a);
        TRY(write_ref(e, src, b));
        return XXEMUL_STATUS_OK;
    }
    if (IS("swap") || IS("ext")) {
        DEST(0, IS("swap") ? 4 : size);
        result = IS("swap") ? (b << 16) | (b >> 16) : sext(b, size == 2 ? 1 : 2);
        WRITE(result);
        logic_flags(r, result, dst.size);
        return XXEMUL_STATUS_OK;
    }
    if (IS("btst") || IS("bchg") || IS("bclr") || IS("bset")) {
        SOURCE(0, 4);
        DEST(1, size);
        a = UINT32_C(1) << (a % (size == 4 ? 32u : 8u));
        r->sr = (uint16_t)((r->sr & ~Z) | (b & a ? 0 : Z));
        if (IS("bchg")) WRITE(b ^ a);
        if (IS("bclr")) WRITE(b & ~a);
        if (IS("bset")) WRITE(b | a);
        return XXEMUL_STATUS_OK;
    }
    if ((opcode & 0xf000u) == 0xe000u) {
        unsigned type, shifts;
        int left = !!(opcode & 0x100u);
        if (count == 1) {
            DEST(0, 2);
            type = (opcode >> 9) & 3u;
            shifts = 1;
        } else {
            SOURCE(0, 4);
            shifts = a & 63u;
            DEST(1, size);
            type = (opcode >> 3) & 3u;
        }
        result = shift_value(r, b, dst.size, shifts, type, left);
        WRITE(result);
        return XXEMUL_STATUS_OK;
    }
    if (IS("mulu") || IS("muls") || IS("divu") || IS("divs")) {
        SOURCE(0, 2);
        DEST(1, 4);
        if (IS("mulu") || IS("muls")) {
            result = IS("mulu") ? a * (b & 0xffffu) : (uint32_t)((int32_t)(int16_t)a * (int32_t)(int16_t)b);
            WRITE(result);
            logic_flags(r, result, 4);
        } else {
            int64_t dividend = IS("divs") ? (int32_t)b : (int64_t)b;
            int64_t divisor = IS("divs") ? (int16_t)a : (int64_t)a;
            int64_t quotient, remainder;
            if (!divisor) return exception(e, 5, ins->opcode, *next);
            quotient = dividend / divisor;
            remainder = dividend % divisor;
            r->sr &= (uint16_t)~C;
            if (IS("divs") ? quotient < -32768 || quotient > 32767 : quotient > 65535) r->sr |= V;
            else {
                result = ((uint32_t)remainder << 16) | ((uint32_t)quotient & 0xffffu);
                WRITE(result);
                logic_flags(r, (uint32_t)quotient, 2);
            }
        }
        return XXEMUL_STATUS_OK;
    }
    if (IS("chk")) {
        SOURCE(0, 2);
        DEST(1, 2);
        if ((int16_t)b < 0 || (int16_t)b > (int16_t)a) {
            r->sr = (uint16_t)((r->sr & ~N) | ((int16_t)b < 0 ? N : 0));
            return exception(e, 6, ins->opcode, *next);
        }
        return XXEMUL_STATUS_OK;
    }
    if (IS("abcd") || IS("sbcd") || IS("nbcd")) {
        if (count == 2) {
            SOURCE(0, 1);
            DEST(1, 1);
        } else {
            DEST(0, 1);
            a = b;
            b = 0;
        }
        result = decimal(r, b, a, !IS("abcd"));
        WRITE(result);
        return XXEMUL_STATUS_OK;
    }
    if (IS("clr") || IS("tst") || IS("tas") || IS("not") || IS("neg") || IS("negx")) {
        /* MC68000 CLR performs a read bus cycle even though it discards data. */
        DEST(0, size);
        if (IS("neg") || IS("negx")) result = arithmetic(r, 0, b, size, 1, IS("negx"), 0);
        else {
            result = IS("clr") ? 0 : IS("not") ? ~b : b;
            logic_flags(r, result, size);
        }
        if (IS("tas")) result |= 128u;
        if (!IS("tst")) WRITE(result);
        return XXEMUL_STATUS_OK;
    }
    if (IS("adda") || IS("suba") || IS("cmpa")) {
        SOURCE(0, size);
        DEST(1, 4);
        if (size == 2) a = sext(a, 2);
        if (IS("cmpa")) (void)arithmetic(r, b, a, 4, 1, 0, 1);
        else WRITE(IS("adda") ? b + a : b - a);
        return XXEMUL_STATUS_OK;
    }
    if (IS("add") || IS("addi") || IS("addq") || IS("addx") || IS("sub") || IS("subi") || IS("subq") || IS("subx") || IS("cmp") || IS("cmpi") || IS("cmpm")) {
        int compare = name[0] == 'c', sub = name[0] != 'a', extended = IS("addx") || IS("subx");
        SOURCE(0, size);
        dst = resolve(r, &ops[1], size, 1);
        if (dst.kind == 2) dst.size = 4; /* ADDQ/SUBQ An is always long. */
        TRY(read_ref(e, dst, &b));
        result = dst.kind == 2 ? (sub ? b - a : b + a) : arithmetic(r, b, a, size, sub, extended, compare);
        if (!compare) WRITE(result);
        return XXEMUL_STATUS_OK;
    }
    if (IS("and") || IS("andi") || IS("or") || IS("ori") || IS("eor") || IS("eori")) {
        SOURCE(0, size);
        DEST(1, size);
        result = name[0] == 'a' ? b & a : name[0] == 'o' ? b | a : b ^ a;
        WRITE(result);
        if (dst.kind < 4) logic_flags(r, result, size);
        return XXEMUL_STATUS_OK;
    }
    return exception(e, 4, ins->opcode, r->pc);
#undef IS
#undef TRY
#undef SOURCE
#undef DEST
#undef WRITE
}

xxemul_status xxemul_m68k_step(xxemul *e, xxemul_step_info *info)
{
    cdisasm_m68k_instruction ins;
    uint32_t pc = e->m68k.pc, next, fault_pc = pc;
    uint16_t initial_sr = e->m68k.sr;
    xxemul_status status;
    unsigned trap_vector = 0;
    e->m68k_exception_vector = 0;
    e->fault_address_valid = 0;
    memset(&ins, 0, sizeof(ins));
    status = decode(e, &ins);
    next = pc + ins.length;
    if (info) {
        info->address = pc;
        info->size = ins.length;
        info->instruction_id = ins.name_id;
    }
    if (status == XXEMUL_STATUS_ADDRESS_FAULT) {
        fault_pc = (uint32_t)e->fault_address;
        goto address_error;
    }
    fault_pc = next;
    if ((ins.opcode & 0xf000u) == 0xa000u) trap_vector = 10;
    else if ((ins.opcode & 0xf000u) == 0xf000u) trap_vector = 11;
    else if ((ins.opcode & 0xfff0u) == 0x4e40u) trap_vector = 32u + (ins.opcode & 15u);
    if (trap_vector && e->m68k_trap_hook && e->m68k_trap_hook(e, trap_vector, ins.opcode, e->m68k_trap_context) == XXEMUL_STATUS_OK) {
        if (e->m68k.pc == pc) e->m68k.pc = next;
        status = XXEMUL_STATUS_OK;
        goto completed;
    }
    if (trap_vector == 10 || trap_vector == 11) status = exception(e, trap_vector, ins.opcode, pc);
    else if (status != XXEMUL_STATUS_OK) status = exception(e, 4, ins.opcode, pc);
    else status = execute(e, &ins, &next);
    if (status == XXEMUL_STATUS_ADDRESS_FAULT && !e->m68k_exception_vector) goto address_error;
    if (status == XXEMUL_STATUS_OK && !e->m68k_exception_vector) e->m68k.pc = next;
completed:
    if (status == XXEMUL_STATUS_OK && !e->m68k_exception_vector && (e->m68k.pc & 1u)) {
        fault(e, e->m68k.pc, 8);
        goto address_error;
    }
    /* Trace follows a completed STOP or group-2 instruction trap, but not
     * an illegal instruction, privilege violation or aborted bus access.
     * A TRAP with T set therefore creates two ordinary exception frames. */
    if ((initial_sr & T) && (status == XXEMUL_STATUS_OK || (status == XXEMUL_STATUS_HALTED && ins.opcode == 0x4e72 && !e->m68k_exception_vector)) &&
        (!e->m68k_exception_vector || e->m68k_exception_vector == 5 || e->m68k_exception_vector == 6 || e->m68k_exception_vector == 7 ||
         e->m68k_exception_vector >= 32)) {
        e->halted = 0;
        status = exception(e, 9, ins.opcode, e->m68k.pc);
    }
    goto finish;
address_error:
    /* Without a prefetch queue the fault-frame PC is the decode cursor:
     * after consumed instruction words, or the failing fetch address. */
    status = exception(e, 3, ins.opcode, fault_pc);
finish:
    sync_sp(&e->m68k);
    if (info) info->next_address = e->m68k.pc;
    return status;
}

size_t xxemul_m68k_format_current(xxemul *e, char *buffer, size_t capacity)
{
    cdisasm_m68k_instruction ins;
    if (decode(e, &ins) != XXEMUL_STATUS_OK) return 0;
    return cdisasm_m68k_format(&ins, 0, buffer, capacity);
}
