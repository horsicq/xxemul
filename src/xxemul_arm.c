#include "xxemul_internal.h"

#include <stddef.h>
#include <stdint.h>

#define XXEMUL_ARM_FLAG_N (UINT32_C(1) << 31)
#define XXEMUL_ARM_FLAG_Z (UINT32_C(1) << 30)
#define XXEMUL_ARM_FLAG_C (UINT32_C(1) << 29)
#define XXEMUL_ARM_FLAG_V (UINT32_C(1) << 28)

static cdisasm_arm_mode xxemul_arm_cdisasm_mode(const xxemul *emulator)
{
    if (emulator->mode == XXEMUL_MODE_ARM_A32) {
        return CDISASM_ARM_MODE_A32;
    }
    if (emulator->mode == XXEMUL_MODE_ARM_T32) {
        return CDISASM_ARM_MODE_T32;
    }
    return CDISASM_ARM_MODE_A64;
}

static uint64_t xxemul_arm_address_mask(const xxemul *emulator)
{
    return emulator->mode == XXEMUL_MODE_ARM_A64
        ? UINT64_MAX : UINT64_C(0xffffffff);
}

static uint64_t xxemul_arm_next_sequential(
    const xxemul *emulator,
    uint64_t pc,
    uint32_t instruction_size)
{
    return (pc + instruction_size) & xxemul_arm_address_mask(emulator);
}

static uint64_t xxemul_arm_align_pc(const xxemul *emulator, uint64_t value)
{
    if (emulator->mode == XXEMUL_MODE_ARM_T32) {
        return value & ~UINT64_C(1);
    }
    return value & ~UINT64_C(3);
}

static xxemul_status xxemul_arm_read_register(
    const xxemul *emulator,
    cdisasm_arm_reg_id register_id,
    uint64_t current_pc,
    uint64_t *value,
    uint8_t *size)
{
    if (value == NULL) {
        return XXEMUL_STATUS_INVALID_ARGUMENT;
    }
    if (register_id >= CDISASM_ARM_REG_R0
        && register_id <= CDISASM_ARM_REG_R15) {
        uint8_t index = (uint8_t)(register_id - CDISASM_ARM_REG_R0);
        if (size != NULL) {
            *size = 4u;
        }
        if (index == 13u) {
            *value = emulator->arm.sp & UINT32_MAX;
        } else if (index == 15u) {
            *value = (current_pc
                + (emulator->mode == XXEMUL_MODE_ARM_A32 ? 8u : 4u))
                & UINT32_MAX;
        } else {
            *value = emulator->arm.gpr[index] & UINT32_MAX;
        }
        return XXEMUL_STATUS_OK;
    }
    if (register_id >= CDISASM_ARM_REG_W0
        && register_id <= CDISASM_ARM_REG_W30) {
        if (size != NULL) {
            *size = 4u;
        }
        *value = emulator->arm.gpr[
            register_id - CDISASM_ARM_REG_W0] & UINT32_MAX;
        return XXEMUL_STATUS_OK;
    }
    if (register_id == CDISASM_ARM_REG_WSP) {
        if (size != NULL) {
            *size = 4u;
        }
        *value = emulator->arm.sp & UINT32_MAX;
        return XXEMUL_STATUS_OK;
    }
    if (register_id == CDISASM_ARM_REG_WZR) {
        if (size != NULL) {
            *size = 4u;
        }
        *value = UINT64_C(0);
        return XXEMUL_STATUS_OK;
    }
    if (register_id >= CDISASM_ARM_REG_X0
        && register_id <= CDISASM_ARM_REG_X30) {
        if (size != NULL) {
            *size = 8u;
        }
        *value = emulator->arm.gpr[
            register_id - CDISASM_ARM_REG_X0];
        return XXEMUL_STATUS_OK;
    }
    if (register_id == CDISASM_ARM_REG_SP) {
        if (size != NULL) {
            *size = 8u;
        }
        *value = emulator->arm.sp;
        return XXEMUL_STATUS_OK;
    }
    if (register_id == CDISASM_ARM_REG_XZR) {
        if (size != NULL) {
            *size = 8u;
        }
        *value = UINT64_C(0);
        return XXEMUL_STATUS_OK;
    }
    return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
}

static xxemul_status xxemul_arm_write_register(
    xxemul *emulator,
    cdisasm_arm_reg_id register_id,
    uint64_t value)
{
    if (register_id >= CDISASM_ARM_REG_R0
        && register_id <= CDISASM_ARM_REG_R15) {
        uint8_t index = (uint8_t)(register_id - CDISASM_ARM_REG_R0);
        value &= UINT32_MAX;
        if (index == 13u) {
            emulator->arm.sp = value;
        } else if (index == 15u) {
            emulator->arm.pc = xxemul_arm_align_pc(emulator, value);
        } else {
            emulator->arm.gpr[index] = value;
        }
        return XXEMUL_STATUS_OK;
    }
    if (register_id >= CDISASM_ARM_REG_W0
        && register_id <= CDISASM_ARM_REG_W30) {
        emulator->arm.gpr[register_id - CDISASM_ARM_REG_W0]
            = value & UINT32_MAX;
        return XXEMUL_STATUS_OK;
    }
    if (register_id == CDISASM_ARM_REG_WSP) {
        emulator->arm.sp = value & UINT32_MAX;
        return XXEMUL_STATUS_OK;
    }
    if (register_id == CDISASM_ARM_REG_WZR
        || register_id == CDISASM_ARM_REG_XZR) {
        return XXEMUL_STATUS_OK;
    }
    if (register_id >= CDISASM_ARM_REG_X0
        && register_id <= CDISASM_ARM_REG_X30) {
        emulator->arm.gpr[register_id - CDISASM_ARM_REG_X0] = value;
        return XXEMUL_STATUS_OK;
    }
    if (register_id == CDISASM_ARM_REG_SP) {
        emulator->arm.sp = value;
        return XXEMUL_STATUS_OK;
    }
    return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
}

static uint64_t xxemul_arm_apply_extend(
    uint64_t value,
    cdisasm_arm_extend_type extend_type)
{
    switch (extend_type) {
    case CDISASM_ARM_EXTEND_UXTB: return value & UINT8_MAX;
    case CDISASM_ARM_EXTEND_UXTH: return value & UINT16_MAX;
    case CDISASM_ARM_EXTEND_UXTW: return value & UINT32_MAX;
    case CDISASM_ARM_EXTEND_UXTX: return value;
    case CDISASM_ARM_EXTEND_SXTB: return xxemul_sign_extend(value, 1u);
    case CDISASM_ARM_EXTEND_SXTH: return xxemul_sign_extend(value, 2u);
    case CDISASM_ARM_EXTEND_SXTW: return xxemul_sign_extend(value, 4u);
    case CDISASM_ARM_EXTEND_SXTX: return value;
    default: return value;
    }
}

static uint64_t xxemul_arm_apply_shift(
    const xxemul *emulator,
    uint64_t value,
    uint8_t size,
    cdisasm_arm_shift_type shift_type,
    uint8_t amount)
{
    uint8_t bits = (uint8_t)(size * 8u);
    uint64_t mask = xxemul_mask_for_size(size);

    if (shift_type == CDISASM_ARM_SHIFT_NONE || amount == 0u) {
        return value & mask;
    }
    value &= mask;
    switch (shift_type) {
    case CDISASM_ARM_SHIFT_LSL:
        return amount >= bits ? UINT64_C(0) : (value << amount) & mask;
    case CDISASM_ARM_SHIFT_LSR:
        return amount >= bits ? UINT64_C(0) : value >> amount;
    case CDISASM_ARM_SHIFT_ASR:
        if (amount >= bits) {
            amount = (uint8_t)(bits - 1u);
        }
        return ((uint64_t)((int64_t)xxemul_sign_extend(value, size) >> amount))
            & mask;
    case CDISASM_ARM_SHIFT_ROR:
        amount %= bits;
        return amount == 0u ? value
            : ((value >> amount) | (value << (bits - amount))) & mask;
    case CDISASM_ARM_SHIFT_RRX:
        return (value >> 1u)
            | ((emulator->arm.pstate & XXEMUL_ARM_FLAG_C) != 0u
               ? (UINT64_C(1) << (bits - 1u)) : UINT64_C(0));
    default:
        return value;
    }
}

static xxemul_status xxemul_arm_read_operand(
    xxemul *emulator,
    const cdisasm_arm_operand *operand,
    uint64_t current_pc,
    uint64_t *value)
{
    uint8_t register_size = 0u;
    xxemul_status status;

    if (operand == NULL || value == NULL) {
        return XXEMUL_STATUS_INVALID_ARGUMENT;
    }
    if (operand->type == CDISASM_OPERAND_IMMEDIATE) {
        if ((operand->flags & CDISASM_OPERAND_FLAG_PC_RELATIVE) != 0u) {
            *value = operand->imm;
            return XXEMUL_STATUS_OK;
        }
        *value = (operand->flags & CDISASM_OPERAND_FLAG_SIGNED) != 0u
            ? xxemul_sign_extend(operand->imm, operand->size)
            : operand->imm;
        if (operand->shift_type != CDISASM_ARM_SHIFT_NONE) {
            uint8_t size = operand->size == 0u
                ? (emulator->mode == XXEMUL_MODE_ARM_A64 ? 8u : 4u)
                : operand->size;
            *value = xxemul_arm_apply_shift(
                emulator, *value, size, operand->shift_type,
                operand->shift_amount);
        }
        return XXEMUL_STATUS_OK;
    }
    if (operand->type != CDISASM_OPERAND_REGISTER) {
        return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    }
    status = xxemul_arm_read_register(
        emulator, operand->reg, current_pc, value, &register_size);
    if (status != XXEMUL_STATUS_OK) {
        return status;
    }
    *value = xxemul_arm_apply_extend(*value, operand->extend_type);
    *value = xxemul_arm_apply_shift(
        emulator,
        *value,
        operand->size == 0u ? register_size : operand->size,
        operand->shift_type,
        operand->shift_amount);
    return XXEMUL_STATUS_OK;
}

static xxemul_status xxemul_arm_memory_address(
    xxemul *emulator,
    const cdisasm_arm_instruction *instruction,
    const cdisasm_arm_operand *operand,
    uint64_t current_pc,
    uint64_t *address,
    uint64_t *writeback,
    int *has_writeback)
{
    uint64_t base = UINT64_C(0);
    uint64_t offset = UINT64_C(0);
    uint64_t index;
    uint8_t index_size = 0u;
    xxemul_status status;

    if (operand == NULL || address == NULL
        || operand->type != CDISASM_OPERAND_MEMORY) {
        return XXEMUL_STATUS_INVALID_ARGUMENT;
    }
    if (has_writeback != NULL) {
        *has_writeback = 0;
    }
    if ((operand->flags & CDISASM_OPERAND_FLAG_HAS_ADDRESS) != 0u) {
        *address = operand->address & xxemul_arm_address_mask(emulator);
        return XXEMUL_STATUS_OK;
    }
    if (operand->base_reg != CDISASM_ARM_REG_NONE) {
        status = xxemul_arm_read_register(
            emulator, operand->base_reg, current_pc, &base, NULL);
        if (status != XXEMUL_STATUS_OK) {
            return status;
        }
    }
    if (operand->index_reg != CDISASM_ARM_REG_NONE) {
        status = xxemul_arm_read_register(
            emulator, operand->index_reg, current_pc, &index, &index_size);
        if (status != XXEMUL_STATUS_OK) {
            return status;
        }
        index = xxemul_arm_apply_extend(index, operand->extend_type);
        index = xxemul_arm_apply_shift(
            emulator, index, index_size, operand->shift_type,
            operand->shift_amount);
        offset += index * (operand->scale == 0u ? 1u : operand->scale);
    }
    if ((operand->flags & CDISASM_OPERAND_FLAG_HAS_DISPLACEMENT) != 0u) {
        offset += (operand->flags & CDISASM_OPERAND_FLAG_SIGNED) != 0u
            ? (uint64_t)(int64_t)operand->imm : operand->imm;
    }
    offset &= xxemul_arm_address_mask(emulator);

    if ((instruction->instruction_flags
         & CDISASM_ARM_INSTRUCTION_FLAG_POST_INDEX) != 0u) {
        *address = base & xxemul_arm_address_mask(emulator);
        if (writeback != NULL) {
            *writeback = (base + offset) & xxemul_arm_address_mask(emulator);
        }
    } else {
        *address = (base + offset) & xxemul_arm_address_mask(emulator);
        if (writeback != NULL) {
            *writeback = *address;
        }
    }
    if (has_writeback != NULL
        && ((operand->flags & CDISASM_ARM_OPERAND_FLAG_WRITEBACK) != 0u
            || (instruction->instruction_flags
                & CDISASM_ARM_INSTRUCTION_FLAG_WRITEBACK) != 0u)) {
        *has_writeback = 1;
    }
    return XXEMUL_STATUS_OK;
}

static int xxemul_arm_condition_passed(
    const xxemul *emulator,
    cdisasm_arm_condition condition)
{
    int n = (emulator->arm.pstate & XXEMUL_ARM_FLAG_N) != 0u;
    int z = (emulator->arm.pstate & XXEMUL_ARM_FLAG_Z) != 0u;
    int c = (emulator->arm.pstate & XXEMUL_ARM_FLAG_C) != 0u;
    int v = (emulator->arm.pstate & XXEMUL_ARM_FLAG_V) != 0u;

    switch (condition) {
    case CDISASM_ARM_CONDITION_EQ: return z;
    case CDISASM_ARM_CONDITION_NE: return !z;
    case CDISASM_ARM_CONDITION_CS: return c;
    case CDISASM_ARM_CONDITION_CC: return !c;
    case CDISASM_ARM_CONDITION_MI: return n;
    case CDISASM_ARM_CONDITION_PL: return !n;
    case CDISASM_ARM_CONDITION_VS: return v;
    case CDISASM_ARM_CONDITION_VC: return !v;
    case CDISASM_ARM_CONDITION_HI: return c && !z;
    case CDISASM_ARM_CONDITION_LS: return !c || z;
    case CDISASM_ARM_CONDITION_GE: return n == v;
    case CDISASM_ARM_CONDITION_LT: return n != v;
    case CDISASM_ARM_CONDITION_GT: return !z && n == v;
    case CDISASM_ARM_CONDITION_LE: return z || n != v;
    case CDISASM_ARM_CONDITION_AL: return 1;
    default: return 0;
    }
}

static void xxemul_arm_set_nz(xxemul *emulator, uint64_t value, uint8_t size)
{
    uint64_t mask = xxemul_mask_for_size(size);
    uint64_t sign = UINT64_C(1) << (size * 8u - 1u);

    value &= mask;
    emulator->arm.pstate &= ~(XXEMUL_ARM_FLAG_N | XXEMUL_ARM_FLAG_Z);
    if (value == 0u) {
        emulator->arm.pstate |= XXEMUL_ARM_FLAG_Z;
    }
    if ((value & sign) != 0u) {
        emulator->arm.pstate |= XXEMUL_ARM_FLAG_N;
    }
}

static void xxemul_arm_set_add_flags(
    xxemul *emulator,
    uint64_t left,
    uint64_t right,
    uint64_t result,
    uint8_t size)
{
    uint64_t mask = xxemul_mask_for_size(size);
    uint64_t sign = UINT64_C(1) << (size * 8u - 1u);
    uint64_t a = left & mask;
    uint64_t b = right & mask;
    uint64_t r = result & mask;

    emulator->arm.pstate &= ~(XXEMUL_ARM_FLAG_C | XXEMUL_ARM_FLAG_V);
    if (r < a) {
        emulator->arm.pstate |= XXEMUL_ARM_FLAG_C;
    }
    if (((~(a ^ b) & (a ^ r)) & sign) != 0u) {
        emulator->arm.pstate |= XXEMUL_ARM_FLAG_V;
    }
    xxemul_arm_set_nz(emulator, r, size);
}

static void xxemul_arm_set_sub_flags(
    xxemul *emulator,
    uint64_t left,
    uint64_t right,
    uint64_t result,
    uint8_t size)
{
    uint64_t mask = xxemul_mask_for_size(size);
    uint64_t sign = UINT64_C(1) << (size * 8u - 1u);
    uint64_t a = left & mask;
    uint64_t b = right & mask;
    uint64_t r = result & mask;

    emulator->arm.pstate &= ~(XXEMUL_ARM_FLAG_C | XXEMUL_ARM_FLAG_V);
    if (a >= b) {
        emulator->arm.pstate |= XXEMUL_ARM_FLAG_C;
    }
    if ((((a ^ b) & (a ^ r)) & sign) != 0u) {
        emulator->arm.pstate |= XXEMUL_ARM_FLAG_V;
    }
    xxemul_arm_set_nz(emulator, r, size);
}

static xxemul_status xxemul_arm_decode_current(
    xxemul *emulator,
    cdisasm_arm_instruction *instruction)
{
    uint8_t code[4];
    uint64_t relative;
    size_t available;
    uint32_t decoded_size;
    xxemul_status status;

    if (emulator->arm.pc < emulator->region_address) {
        return XXEMUL_STATUS_ADDRESS_FAULT;
    }
    relative = emulator->arm.pc - emulator->region_address;
    if (relative >= emulator->region_size) {
        return XXEMUL_STATUS_ADDRESS_FAULT;
    }
    available = emulator->region_size - (size_t)relative;
    if (available > sizeof(code)) {
        available = sizeof(code);
    }
    status = xxemul_read_memory(emulator, emulator->arm.pc, code, available);
    if (status != XXEMUL_STATUS_OK) {
        return status;
    }
    decoded_size = cdisasm_arm_decode(
        CDISASM_ARM_CPU_ANY,
        xxemul_arm_cdisasm_mode(emulator),
        code,
        available,
        emulator->arm.pc,
        NULL,
        instruction);
    return decoded_size == 0u ? XXEMUL_STATUS_DECODE_ERROR : XXEMUL_STATUS_OK;
}

static xxemul_status xxemul_arm_binary(
    xxemul *emulator,
    const cdisasm_arm_instruction *instruction,
    uint64_t current_pc)
{
    const cdisasm_arm_operand *destination;
    uint64_t left;
    uint64_t right;
    uint64_t result;
    uint64_t mask;
    uint8_t size;
    uint8_t source_index;
    int set_flags;
    xxemul_status status;

    if (instruction->operand_count < 2u) {
        return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    }
    destination = &instruction->operand[0];
    size = destination->size;
    if (size == 0u) {
        size = emulator->mode == XXEMUL_MODE_ARM_A64 ? 8u : 4u;
    }
    if (size > 8u) {
        return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    }
    source_index = instruction->operand_count >= 3u ? 1u : 0u;
    status = xxemul_arm_read_operand(
        emulator, &instruction->operand[source_index], current_pc, &left);
    if (status != XXEMUL_STATUS_OK) {
        return status;
    }
    status = xxemul_arm_read_operand(
        emulator, &instruction->operand[source_index + 1u], current_pc, &right);
    if (status != XXEMUL_STATUS_OK) {
        return status;
    }
    mask = xxemul_mask_for_size(size);
    set_flags = (instruction->instruction_flags
        & CDISASM_ARM_INSTRUCTION_FLAG_SETS_FLAGS) != 0u;

    switch (instruction->name_id) {
    case CDISASM_ARM_NAME_ADD:
    case CDISASM_ARM_NAME_ADDS:
        result = (left + right) & mask;
        status = xxemul_arm_write_register(emulator, destination->reg, result);
        if (status == XXEMUL_STATUS_OK
            && (set_flags || instruction->name_id == CDISASM_ARM_NAME_ADDS)) {
            xxemul_arm_set_add_flags(emulator, left, right, result, size);
        }
        return status;
    case CDISASM_ARM_NAME_SUB:
    case CDISASM_ARM_NAME_SUBS:
        result = (left - right) & mask;
        status = xxemul_arm_write_register(emulator, destination->reg, result);
        if (status == XXEMUL_STATUS_OK
            && (set_flags || instruction->name_id == CDISASM_ARM_NAME_SUBS)) {
            xxemul_arm_set_sub_flags(emulator, left, right, result, size);
        }
        return status;
    case CDISASM_ARM_NAME_AND:
    case CDISASM_ARM_NAME_ANDS:
        result = (left & right) & mask;
        status = xxemul_arm_write_register(emulator, destination->reg, result);
        if (status == XXEMUL_STATUS_OK
            && (set_flags || instruction->name_id == CDISASM_ARM_NAME_ANDS)) {
            emulator->arm.pstate &= ~(XXEMUL_ARM_FLAG_C | XXEMUL_ARM_FLAG_V);
            xxemul_arm_set_nz(emulator, result, size);
        }
        return status;
    case CDISASM_ARM_NAME_ORR:
        result = (left | right) & mask;
        return xxemul_arm_write_register(emulator, destination->reg, result);
    case CDISASM_ARM_NAME_EOR:
        result = (left ^ right) & mask;
        return xxemul_arm_write_register(emulator, destination->reg, result);
    default:
        return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    }
}

static xxemul_status xxemul_arm_compare(
    xxemul *emulator,
    const cdisasm_arm_instruction *instruction,
    uint64_t current_pc)
{
    uint64_t left;
    uint64_t right;
    uint64_t result;
    uint8_t size;
    xxemul_status status;

    if (instruction->operand_count < 2u) {
        return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    }
    status = xxemul_arm_read_operand(
        emulator, &instruction->operand[0], current_pc, &left);
    if (status != XXEMUL_STATUS_OK) {
        return status;
    }
    status = xxemul_arm_read_operand(
        emulator, &instruction->operand[1], current_pc, &right);
    if (status != XXEMUL_STATUS_OK) {
        return status;
    }
    size = instruction->operand[0].size;
    if (size == 0u) {
        size = emulator->mode == XXEMUL_MODE_ARM_A64 ? 8u : 4u;
    }
    if (instruction->name_id == CDISASM_ARM_NAME_CMP) {
        result = (left - right) & xxemul_mask_for_size(size);
        xxemul_arm_set_sub_flags(emulator, left, right, result, size);
    } else {
        result = (left & right) & xxemul_mask_for_size(size);
        emulator->arm.pstate &= ~(XXEMUL_ARM_FLAG_C | XXEMUL_ARM_FLAG_V);
        xxemul_arm_set_nz(emulator, result, size);
    }
    return XXEMUL_STATUS_OK;
}

static xxemul_status xxemul_arm_load_store(
    xxemul *emulator,
    const cdisasm_arm_instruction *instruction,
    uint64_t current_pc,
    int is_load)
{
    const cdisasm_arm_operand *register_operand;
    const cdisasm_arm_operand *memory_operand;
    uint64_t address;
    uint64_t writeback;
    uint64_t value;
    uint8_t size;
    int has_writeback;
    xxemul_status status;

    if (instruction->operand_count < 2u) {
        return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    }
    register_operand = &instruction->operand[0];
    memory_operand = &instruction->operand[1];
    if (register_operand->type != CDISASM_OPERAND_REGISTER
        || memory_operand->type != CDISASM_OPERAND_MEMORY) {
        return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    }
    size = memory_operand->size;
    if (size == 0u) {
        size = register_operand->size;
    }
    if (size == 0u || size > 8u) {
        return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    }
    status = xxemul_arm_memory_address(
        emulator, instruction, memory_operand, current_pc,
        &address, &writeback, &has_writeback);
    if (status != XXEMUL_STATUS_OK) {
        return status;
    }
    if (is_load) {
        status = xxemul_load_integer(emulator, address, size, &value);
        if (status == XXEMUL_STATUS_OK
            && (instruction->name_id == CDISASM_ARM_NAME_LDRSB
                || instruction->name_id == CDISASM_ARM_NAME_LDRSH
                || instruction->name_id == CDISASM_ARM_NAME_LDRSW)) {
            value = xxemul_sign_extend(value, size);
        }
        if (status == XXEMUL_STATUS_OK) {
            status = xxemul_arm_write_register(
                emulator, register_operand->reg, value);
        }
    } else {
        status = xxemul_arm_read_operand(
            emulator, register_operand, current_pc, &value);
        if (status == XXEMUL_STATUS_OK) {
            status = xxemul_store_integer(emulator, address, size, value);
        }
    }
    if (status == XXEMUL_STATUS_OK && has_writeback) {
        status = xxemul_arm_write_register(
            emulator, memory_operand->base_reg, writeback);
    }
    return status;
}

static xxemul_status xxemul_arm_branch_target(
    xxemul *emulator,
    const cdisasm_arm_instruction *instruction,
    uint64_t current_pc,
    uint64_t *target)
{
    if (target == NULL) {
        return XXEMUL_STATUS_INVALID_ARGUMENT;
    }
    if (instruction->operand_count == 0u) {
        *target = instruction->branch_target;
        return XXEMUL_STATUS_OK;
    }
    return xxemul_arm_read_operand(
        emulator, &instruction->operand[0], current_pc, target);
}

xxemul_status xxemul_arm_step(xxemul *emulator, xxemul_step_info *info)
{
    cdisasm_arm_instruction instruction;
    uint64_t current_pc = emulator->arm.pc;
    uint64_t next_pc;
    uint64_t value;
    uint64_t target;
    uint64_t old_value;
    uint64_t mask;
    uint8_t size;
    xxemul_status status;

    status = xxemul_arm_decode_current(emulator, &instruction);
    if (status != XXEMUL_STATUS_OK) {
        return status;
    }
    if ((instruction.instruction_flags
         & (CDISASM_ARM_INSTRUCTION_FLAG_ILLEGAL
            | CDISASM_ARM_INSTRUCTION_FLAG_UNPREDICTABLE)) != 0u) {
        return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    }
    next_pc = xxemul_arm_next_sequential(
        emulator, current_pc, instruction.opcode_size);
    if (info != NULL) {
        info->address = current_pc;
        info->next_address = current_pc;
        info->size = instruction.opcode_size;
        info->instruction_id = instruction.name_id;
    }

    if (!xxemul_arm_condition_passed(emulator, instruction.condition)) {
        emulator->arm.pc = next_pc;
        if (info != NULL) {
            info->next_address = next_pc;
        }
        return XXEMUL_STATUS_OK;
    }

    emulator->arm.pc = next_pc;
    switch (instruction.name_id) {
    case CDISASM_ARM_NAME_NOP:
        status = XXEMUL_STATUS_OK;
        break;
    case CDISASM_ARM_NAME_BKPT:
    case CDISASM_ARM_NAME_BRK:
        emulator->halted = 1;
        status = XXEMUL_STATUS_HALTED;
        break;
    case CDISASM_ARM_NAME_MOV:
    case CDISASM_ARM_NAME_MOVZ:
        if (instruction.operand_count < 2u) {
            status = XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
            break;
        }
        status = xxemul_arm_read_operand(
            emulator, &instruction.operand[1], current_pc, &value);
        if (status == XXEMUL_STATUS_OK) {
            status = xxemul_arm_write_register(
                emulator, instruction.operand[0].reg, value);
        }
        break;
    case CDISASM_ARM_NAME_MOVN:
        if (instruction.operand_count < 2u) {
            status = XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
            break;
        }
        size = instruction.operand[0].size == 0u ? 8u
            : instruction.operand[0].size;
        status = xxemul_arm_read_operand(
            emulator, &instruction.operand[1], current_pc, &value);
        if (status == XXEMUL_STATUS_OK) {
            status = xxemul_arm_write_register(
                emulator, instruction.operand[0].reg,
                (~value) & xxemul_mask_for_size(size));
        }
        break;
    case CDISASM_ARM_NAME_MOVK:
        if (instruction.operand_count < 2u) {
            status = XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
            break;
        }
        status = xxemul_arm_read_register(
            emulator, instruction.operand[0].reg, current_pc,
            &old_value, &size);
        if (status == XXEMUL_STATUS_OK) {
            uint8_t shift = instruction.operand[1].shift_amount;
            value = (instruction.operand[1].imm & UINT64_C(0xffff)) << shift;
            mask = UINT64_C(0xffff) << shift;
            status = xxemul_arm_write_register(
                emulator, instruction.operand[0].reg,
                (old_value & ~mask) | value);
        }
        break;
    case CDISASM_ARM_NAME_MOVW:
    case CDISASM_ARM_NAME_MOVT:
        if (instruction.operand_count < 2u) {
            status = XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
            break;
        }
        status = xxemul_arm_read_register(
            emulator, instruction.operand[0].reg, current_pc,
            &old_value, NULL);
        if (status == XXEMUL_STATUS_OK) {
            value = instruction.operand[1].imm & UINT16_MAX;
            value = instruction.name_id == CDISASM_ARM_NAME_MOVT
                ? ((old_value & UINT16_MAX) | (value << 16u)) : value;
            status = xxemul_arm_write_register(
                emulator, instruction.operand[0].reg, value);
        }
        break;
    case CDISASM_ARM_NAME_ADD:
    case CDISASM_ARM_NAME_ADDS:
    case CDISASM_ARM_NAME_SUB:
    case CDISASM_ARM_NAME_SUBS:
    case CDISASM_ARM_NAME_AND:
    case CDISASM_ARM_NAME_ANDS:
    case CDISASM_ARM_NAME_ORR:
    case CDISASM_ARM_NAME_EOR:
        status = xxemul_arm_binary(emulator, &instruction, current_pc);
        break;
    case CDISASM_ARM_NAME_CMP:
    case CDISASM_ARM_NAME_TST:
        status = xxemul_arm_compare(emulator, &instruction, current_pc);
        break;
    case CDISASM_ARM_NAME_LDR:
    case CDISASM_ARM_NAME_LDRB:
    case CDISASM_ARM_NAME_LDRH:
    case CDISASM_ARM_NAME_LDRSB:
    case CDISASM_ARM_NAME_LDRSH:
    case CDISASM_ARM_NAME_LDRSW:
        status = xxemul_arm_load_store(
            emulator, &instruction, current_pc, 1);
        break;
    case CDISASM_ARM_NAME_STR:
    case CDISASM_ARM_NAME_STRB:
    case CDISASM_ARM_NAME_STRH:
        status = xxemul_arm_load_store(
            emulator, &instruction, current_pc, 0);
        break;
    case CDISASM_ARM_NAME_B:
        status = xxemul_arm_branch_target(
            emulator, &instruction, current_pc, &target);
        if (status == XXEMUL_STATUS_OK) {
            emulator->arm.pc = xxemul_arm_align_pc(emulator, target);
        }
        break;
    case CDISASM_ARM_NAME_BL:
        status = xxemul_arm_branch_target(
            emulator, &instruction, current_pc, &target);
        if (status == XXEMUL_STATUS_OK) {
            emulator->arm.gpr[emulator->mode == XXEMUL_MODE_ARM_A64 ? 30u : 14u]
                = next_pc;
            emulator->arm.pc = xxemul_arm_align_pc(emulator, target);
        }
        break;
    case CDISASM_ARM_NAME_BR:
    case CDISASM_ARM_NAME_BX:
        status = xxemul_arm_branch_target(
            emulator, &instruction, current_pc, &target);
        if (status == XXEMUL_STATUS_OK) {
            emulator->arm.pc = xxemul_arm_align_pc(emulator, target);
        }
        break;
    case CDISASM_ARM_NAME_BLR:
        status = xxemul_arm_branch_target(
            emulator, &instruction, current_pc, &target);
        if (status == XXEMUL_STATUS_OK) {
            emulator->arm.gpr[30] = next_pc;
            emulator->arm.pc = xxemul_arm_align_pc(emulator, target);
        }
        break;
    case CDISASM_ARM_NAME_RET:
        if (instruction.operand_count > 0u) {
            status = xxemul_arm_branch_target(
                emulator, &instruction, current_pc, &target);
        } else {
            target = emulator->arm.gpr[30];
            status = XXEMUL_STATUS_OK;
        }
        if (status == XXEMUL_STATUS_OK) {
            emulator->arm.pc = xxemul_arm_align_pc(emulator, target);
        }
        break;
    default:
        status = XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
        break;
    }

    if (status != XXEMUL_STATUS_OK && status != XXEMUL_STATUS_HALTED) {
        emulator->arm.pc = current_pc;
    } else if (info != NULL) {
        info->next_address = emulator->arm.pc;
    }
    return status;
}

size_t xxemul_arm_format_current(
    xxemul *emulator,
    char *buffer,
    size_t buffer_size)
{
    cdisasm_arm_instruction instruction;

    if (xxemul_arm_decode_current(emulator, &instruction) != XXEMUL_STATUS_OK) {
        if (buffer != NULL && buffer_size > 0u) {
            buffer[0] = '\0';
        }
        return 0u;
    }
    return cdisasm_arm_format(
        &instruction,
        CDISASM_FORMAT_SYNTAX_ARM_CANONICAL,
        buffer,
        buffer_size);
}
