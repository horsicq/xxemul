#include "xxemul_internal.h"
#include "xxemul_arm_auth.h"
#include "platforms/xxemul_darwin.h"
#include "platforms/xxemul_linux.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define XXEMUL_ARM_FLAG_N (UINT32_C(1) << 31)
#define XXEMUL_ARM_FLAG_Z (UINT32_C(1) << 30)
#define XXEMUL_ARM_FLAG_C (UINT32_C(1) << 29)
#define XXEMUL_ARM_FLAG_V (UINT32_C(1) << 28)
#define XXEMUL_ARM_FLAG_T (UINT32_C(1) << 5)

/* Report successful instruction-originated data accesses only. Public
 * memory functions also serve debugger reads/writes and instruction fetch,
 * so hook delivery belongs in these CPU data paths. */
static void xxemul_arm_data_access(xxemul *emulator, uint64_t address, size_t size, int is_write, xxemul_status status)
{
    if (status == XXEMUL_STATUS_OK && size && emulator->in_step && emulator->memory_hook)
        emulator->memory_hook(emulator->memory_hook_context, address, size, is_write);
}

static xxemul_status xxemul_arm_guest_load_integer(xxemul *emulator, uint64_t address, uint8_t size, uint64_t *value)
{
    xxemul_status status = xxemul_load_integer(emulator, address, size, value);
    xxemul_arm_data_access(emulator, address, size, 0, status);
    return status;
}

static xxemul_status xxemul_arm_guest_store_integer(xxemul *emulator, uint64_t address, uint8_t size, uint64_t value)
{
    xxemul_status status = xxemul_store_integer(emulator, address, size, value);
    xxemul_arm_data_access(emulator, address, size, 1, status);
    return status;
}

static xxemul_status xxemul_arm_guest_read_memory(xxemul *emulator, uint64_t address, void *buffer, size_t size)
{
    xxemul_status status = xxemul_read_memory(emulator, address, buffer, size);
    xxemul_arm_data_access(emulator, address, size, 0, status);
    return status;
}

static xxemul_status xxemul_arm_guest_write_memory(xxemul *emulator, uint64_t address, const void *buffer, size_t size)
{
    xxemul_status status = xxemul_write_memory(emulator, address, buffer, size);
    xxemul_arm_data_access(emulator, address, size, 1, status);
    return status;
}

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
    return emulator->mode == XXEMUL_MODE_ARM_A64 ? UINT64_MAX : UINT64_C(0xffffffff);
}

static uint64_t xxemul_arm_next_sequential(const xxemul *emulator, uint64_t pc, uint32_t instruction_size)
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

static xxemul_status xxemul_arm_branch_exchange(xxemul *emulator, uint64_t target)
{
    target &= UINT32_MAX;
    /* An ARM destination must be word aligned. Thumb uses bit zero solely
     * to select its instruction set and permits halfword alignment. */
    if ((target & UINT64_C(3)) == UINT64_C(2)) {
        return XXEMUL_STATUS_ADDRESS_FAULT;
    }
    if ((target & UINT64_C(1)) != 0u) {
        emulator->mode = XXEMUL_MODE_ARM_T32;
        emulator->arm.pstate |= XXEMUL_ARM_FLAG_T;
        emulator->arm.pc = target & ~UINT64_C(1);
    } else {
        emulator->mode = XXEMUL_MODE_ARM_A32;
        emulator->arm.pstate &= ~XXEMUL_ARM_FLAG_T;
        emulator->arm.pc = target;
    }
    return XXEMUL_STATUS_OK;
}

static xxemul_status xxemul_arm_read_register(const xxemul *emulator, cdisasm_arm_reg_id register_id, uint64_t current_pc, uint64_t *value, uint8_t *size)
{
    if (value == NULL) {
        return XXEMUL_STATUS_INVALID_ARGUMENT;
    }
    if (register_id >= CDISASM_ARM_REG_R0 && register_id <= CDISASM_ARM_REG_R15) {
        uint8_t index = (uint8_t)(register_id - CDISASM_ARM_REG_R0);
        if (size != NULL) {
            *size = 4u;
        }
        if (index == 13u) {
            *value = emulator->arm.sp & UINT32_MAX;
        } else if (index == 15u) {
            *value = (current_pc + (emulator->mode == XXEMUL_MODE_ARM_A32 ? 8u : 4u)) & UINT32_MAX;
        } else {
            *value = emulator->arm.gpr[index] & UINT32_MAX;
        }
        return XXEMUL_STATUS_OK;
    }
    if (register_id >= CDISASM_ARM_REG_W0 && register_id <= CDISASM_ARM_REG_W30) {
        if (size != NULL) {
            *size = 4u;
        }
        *value = emulator->arm.gpr[register_id - CDISASM_ARM_REG_W0] & UINT32_MAX;
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
    if (register_id >= CDISASM_ARM_REG_X0 && register_id <= CDISASM_ARM_REG_X30) {
        if (size != NULL) {
            *size = 8u;
        }
        *value = emulator->arm.gpr[register_id - CDISASM_ARM_REG_X0];
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

static xxemul_status xxemul_arm_write_register(xxemul *emulator, cdisasm_arm_reg_id register_id, uint64_t value)
{
    if (register_id >= CDISASM_ARM_REG_R0 && register_id <= CDISASM_ARM_REG_R15) {
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
    if (register_id >= CDISASM_ARM_REG_W0 && register_id <= CDISASM_ARM_REG_W30) {
        emulator->arm.gpr[register_id - CDISASM_ARM_REG_W0] = value & UINT32_MAX;
        return XXEMUL_STATUS_OK;
    }
    if (register_id == CDISASM_ARM_REG_WSP) {
        emulator->arm.sp = value & UINT32_MAX;
        return XXEMUL_STATUS_OK;
    }
    if (register_id == CDISASM_ARM_REG_WZR || register_id == CDISASM_ARM_REG_XZR) {
        return XXEMUL_STATUS_OK;
    }
    if (register_id >= CDISASM_ARM_REG_X0 && register_id <= CDISASM_ARM_REG_X30) {
        emulator->arm.gpr[register_id - CDISASM_ARM_REG_X0] = value;
        return XXEMUL_STATUS_OK;
    }
    if (register_id == CDISASM_ARM_REG_SP) {
        emulator->arm.sp = value;
        return XXEMUL_STATUS_OK;
    }
    return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
}

static uint64_t xxemul_arm_apply_extend(uint64_t value, cdisasm_arm_extend_type extend_type)
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

static uint64_t xxemul_arm_apply_shift(const xxemul *emulator, uint64_t value, uint8_t size, cdisasm_arm_shift_type shift_type, uint8_t amount)
{
    uint8_t bits = (uint8_t)(size * 8u);
    uint64_t mask = xxemul_mask_for_size(size);

    if (shift_type == CDISASM_ARM_SHIFT_NONE || amount == 0u) {
        return value & mask;
    }
    value &= mask;
    switch (shift_type) {
        case CDISASM_ARM_SHIFT_LSL: return amount >= bits ? UINT64_C(0) : (value << amount) & mask;
        case CDISASM_ARM_SHIFT_LSR: return amount >= bits ? UINT64_C(0) : value >> amount;
        case CDISASM_ARM_SHIFT_ASR:
            if (amount >= bits) {
                amount = (uint8_t)(bits - 1u);
            }
            return ((uint64_t)((int64_t)xxemul_sign_extend(value, size) >> amount)) & mask;
        case CDISASM_ARM_SHIFT_ROR: amount %= bits; return amount == 0u ? value : ((value >> amount) | (value << (bits - amount))) & mask;
        case CDISASM_ARM_SHIFT_RRX: return (value >> 1u) | ((emulator->arm.pstate & XXEMUL_ARM_FLAG_C) != 0u ? (UINT64_C(1) << (bits - 1u)) : UINT64_C(0));
        default: return value;
    }
}

static uint64_t xxemul_arm_apply_shift_with_carry(const xxemul *emulator, uint64_t value, uint8_t size,
                                                  cdisasm_arm_shift_type shift_type, uint8_t amount,
                                                  int *carry_valid, int *carry)
{
    uint8_t bits = (uint8_t)(size * 8u);
    uint64_t mask = xxemul_mask_for_size(size);
    uint64_t result;

    if (carry_valid != NULL) *carry_valid = 0;
    if (carry != NULL) *carry = 0;
    value &= mask;
    if (shift_type == CDISASM_ARM_SHIFT_NONE || amount == 0u) {
        return value;
    }
    result = xxemul_arm_apply_shift(emulator, value, size, shift_type, amount);
    if (carry_valid != NULL) *carry_valid = 1;
    switch (shift_type) {
        case CDISASM_ARM_SHIFT_LSL:
            if (carry != NULL) *carry = amount <= bits ? (int)((value >> (bits - amount)) & UINT64_C(1)) : 0;
            break;
        case CDISASM_ARM_SHIFT_LSR:
            if (carry != NULL) *carry = amount <= bits ? (int)((value >> (amount - 1u)) & UINT64_C(1)) : 0;
            break;
        case CDISASM_ARM_SHIFT_ASR:
            if (carry != NULL) *carry = amount < bits ? (int)((value >> (amount - 1u)) & UINT64_C(1)) : (int)((value >> (bits - 1u)) & UINT64_C(1));
            break;
        case CDISASM_ARM_SHIFT_ROR: {
            uint8_t rotation = (uint8_t)(amount % bits);
            if (carry != NULL) *carry = rotation == 0u ? (int)((value >> (bits - 1u)) & UINT64_C(1)) : (int)((result >> (bits - 1u)) & UINT64_C(1));
            break;
        }
        case CDISASM_ARM_SHIFT_RRX:
            if (carry != NULL) *carry = (int)(value & UINT64_C(1));
            break;
        default:
            if (carry_valid != NULL) *carry_valid = 0;
            break;
    }
    return result;
}

static xxemul_status xxemul_arm_read_operand(xxemul *emulator, const cdisasm_arm_operand *operand, uint64_t current_pc, uint64_t *value)
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
        *value = (operand->flags & CDISASM_OPERAND_FLAG_SIGNED) != 0u ? xxemul_sign_extend(operand->imm, operand->size) : operand->imm;
        /* cdisasm exposes the semantic immediate.  shift_type/shift_amount
         * retain how that value was encoded and must not be applied again. */
        return XXEMUL_STATUS_OK;
    }
    if (operand->type != CDISASM_OPERAND_REGISTER) {
        return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    }
    status = xxemul_arm_read_register(emulator, operand->reg, current_pc, value, &register_size);
    if (status != XXEMUL_STATUS_OK) {
        return status;
    }
    *value = xxemul_arm_apply_extend(*value, operand->extend_type);
    if (operand->extend_type != CDISASM_ARM_EXTEND_NONE) {
        if (operand->scale != 0u) *value = operand->scale >= 64u ? UINT64_C(0) : *value << operand->scale;
    } else {
        *value = xxemul_arm_apply_shift(emulator, *value, operand->size == 0u ? register_size : operand->size, operand->shift_type, operand->shift_amount);
    }
    return XXEMUL_STATUS_OK;
}

static xxemul_status xxemul_arm_read_data_operand(xxemul *emulator, const cdisasm_arm_instruction *instruction,
                                                   unsigned index, uint64_t current_pc, uint64_t *value,
                                                   int *carry_valid, int *carry)
{
    const cdisasm_arm_operand *operand;
    cdisasm_arm_shift_type shift_type;
    uint8_t amount;
    uint8_t size;
    xxemul_status status;

    if (carry_valid != NULL) *carry_valid = 0;
    if (carry != NULL) *carry = 0;
    if (index >= instruction->operand_count) return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    operand = &instruction->operand[index];
    if (operand->type != CDISASM_OPERAND_REGISTER || operand->extend_type != CDISASM_ARM_EXTEND_NONE) {
        status = xxemul_arm_read_operand(emulator, operand, current_pc, value);
        if (status == XXEMUL_STATUS_OK && emulator->mode == XXEMUL_MODE_ARM_A32 &&
            operand->type == CDISASM_OPERAND_IMMEDIATE && operand->shift_type == CDISASM_ARM_SHIFT_ROR &&
            operand->shift_amount != 0u) {
            /* The immediate is already rotated by the decoder. */
            if (carry_valid != NULL) *carry_valid = 1;
            if (carry != NULL) *carry = (int)((*value >> 31u) & UINT64_C(1));
        }
        return status;
    }
    status = xxemul_arm_read_register(emulator, operand->reg, current_pc, value, &size);
    if (status != XXEMUL_STATUS_OK) return status;
    if (operand->size != 0u) size = operand->size;
    if (size == 0u || size > 8u) return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    shift_type = operand->shift_type;
    amount = operand->shift_amount;
    if (emulator->mode == XXEMUL_MODE_ARM_A32 && index + 2u == instruction->operand_count) {
        const cdisasm_arm_operand *shift = &instruction->operand[index + 1u];
        if (shift->type == CDISASM_OPERAND_REGISTER && shift->shift_type >= CDISASM_ARM_SHIFT_LSL &&
            shift->shift_type <= CDISASM_ARM_SHIFT_ROR) {
            uint64_t count;
            status = xxemul_arm_read_register(emulator, shift->reg, current_pc, &count, NULL);
            if (status != XXEMUL_STATUS_OK) return status;
            shift_type = shift->shift_type;
            amount = (uint8_t)count;
        }
    }
    *value = xxemul_arm_apply_shift_with_carry(emulator, *value, size, shift_type, amount, carry_valid, carry);
    return XXEMUL_STATUS_OK;
}

static int xxemul_arm_literal_operand(const xxemul *emulator, const cdisasm_arm_instruction *instruction,
                                      const cdisasm_arm_operand *operand)
{
    return emulator->mode == XXEMUL_MODE_ARM_A64 && instruction->operand_count == 2u &&
        operand == &instruction->operand[1] && operand->type == CDISASM_OPERAND_IMMEDIATE &&
        (operand->flags & CDISASM_OPERAND_FLAG_PC_RELATIVE) != 0u &&
        (instruction->name_id == CDISASM_ARM_NAME_LDR || instruction->name_id == CDISASM_ARM_NAME_LDRSW);
}

static xxemul_status xxemul_arm_memory_address(xxemul *emulator, const cdisasm_arm_instruction *instruction, const cdisasm_arm_operand *operand, uint64_t current_pc,
                                               uint64_t *address, uint64_t *writeback, int *has_writeback)
{
    uint64_t base = UINT64_C(0);
    uint64_t offset = UINT64_C(0);
    uint64_t index;
    uint8_t index_size = 0u;
    xxemul_status status;

    if (operand == NULL || address == NULL) {
        return XXEMUL_STATUS_INVALID_ARGUMENT;
    }
    if (has_writeback != NULL) {
        *has_writeback = 0;
    }
    if (xxemul_arm_literal_operand(emulator, instruction, operand)) {
        /* The decoder's semantic immediate is already the absolute target;
         * its address field preserves the encoded signed displacement. */
        *address = operand->imm;
        return XXEMUL_STATUS_OK;
    }
    if (operand->type != CDISASM_OPERAND_MEMORY) return XXEMUL_STATUS_INVALID_ARGUMENT;
    if ((operand->flags & CDISASM_OPERAND_FLAG_HAS_ADDRESS) != 0u) {
        *address = operand->address & xxemul_arm_address_mask(emulator);
        return XXEMUL_STATUS_OK;
    }
    if (operand->base_reg != CDISASM_ARM_REG_NONE) {
        status = xxemul_arm_read_register(emulator, operand->base_reg, current_pc, &base, NULL);
        if (status != XXEMUL_STATUS_OK) {
            return status;
        }
    }
    if (operand->index_reg != CDISASM_ARM_REG_NONE) {
        status = xxemul_arm_read_register(emulator, operand->index_reg, current_pc, &index, &index_size);
        if (status != XXEMUL_STATUS_OK) {
            return status;
        }
        index = xxemul_arm_apply_extend(index, operand->extend_type);
        if (operand->extend_type == CDISASM_ARM_EXTEND_NONE) {
            index = xxemul_arm_apply_shift(emulator, index, index_size, operand->shift_type, operand->shift_amount);
        }
        /* For ARM scalar memory operands scale is the encoded left-shift
         * amount (for example UXTW #2), rather than a multiplier. */
        index = operand->scale >= 64u ? UINT64_C(0) : index << operand->scale;
        if ((operand->flags & CDISASM_OPERAND_FLAG_SIGNED) != 0u) {
            offset -= index;
        } else {
            offset += index;
        }
    }
    if ((operand->flags & CDISASM_OPERAND_FLAG_HAS_DISPLACEMENT) != 0u) {
        offset += (operand->flags & CDISASM_OPERAND_FLAG_SIGNED) != 0u ? (uint64_t)(int64_t)operand->imm : operand->imm;
    }
    offset &= xxemul_arm_address_mask(emulator);

    if ((instruction->instruction_flags & CDISASM_ARM_INSTRUCTION_FLAG_POST_INDEX) != 0u) {
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
    if (has_writeback != NULL &&
        ((operand->flags & CDISASM_ARM_OPERAND_FLAG_WRITEBACK) != 0u || (instruction->instruction_flags & CDISASM_ARM_INSTRUCTION_FLAG_WRITEBACK) != 0u)) {
        *has_writeback = 1;
    }
    return XXEMUL_STATUS_OK;
}

static int xxemul_arm_condition_passed(const xxemul *emulator, cdisasm_arm_condition condition)
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

static void xxemul_arm_set_add_flags(xxemul *emulator, uint64_t left, uint64_t right, uint64_t result, uint8_t size)
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

static void xxemul_arm_set_sub_flags(xxemul *emulator, uint64_t left, uint64_t right, uint64_t result, uint8_t size)
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

static xxemul_status xxemul_arm_decode_current(xxemul *emulator, cdisasm_arm_instruction *instruction)
{
    uint8_t code[4];
    size_t available = sizeof(code);
    uint32_t decoded_size;
    xxemul_status status;

    /* Linux loaders execute their folded code in mmap regions outside the
     * original image. Fetch through the same guest memory path as data. */
    status = xxemul_read_memory(emulator, emulator->arm.pc, code, available);
    if (status != XXEMUL_STATUS_OK && emulator->mode == XXEMUL_MODE_ARM_T32) {
        available = 2u;
        status = xxemul_read_memory(emulator, emulator->arm.pc, code, available);
    }
    if (status != XXEMUL_STATUS_OK) {
        return status;
    }
    decoded_size = cdisasm_arm_decode(CDISASM_ARM_CPU_ANY, xxemul_arm_cdisasm_mode(emulator), code, available, emulator->arm.pc, NULL, instruction);
    return decoded_size == 0u ? XXEMUL_STATUS_DECODE_ERROR : XXEMUL_STATUS_OK;
}

static void xxemul_arm_set_logic_flags(xxemul *emulator, uint64_t value, uint8_t size, int carry_valid, int carry)
{
    if (emulator->mode == XXEMUL_MODE_ARM_A64) {
        emulator->arm.pstate &= ~(XXEMUL_ARM_FLAG_C | XXEMUL_ARM_FLAG_V);
    } else if (carry_valid) {
        emulator->arm.pstate &= ~XXEMUL_ARM_FLAG_C;
        if (carry) emulator->arm.pstate |= XXEMUL_ARM_FLAG_C;
    }
    xxemul_arm_set_nz(emulator, value, size);
}

static xxemul_status xxemul_arm_binary(xxemul *emulator, const cdisasm_arm_instruction *instruction, uint64_t current_pc)
{
    const cdisasm_arm_operand *destination;
    uint64_t left;
    uint64_t right;
    uint64_t result;
    uint64_t mask;
    uint8_t size;
    uint8_t source_index;
    int set_flags;
    int shift_carry_valid;
    int shift_carry;
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
    status = xxemul_arm_read_operand(emulator, &instruction->operand[source_index], current_pc, &left);
    if (status != XXEMUL_STATUS_OK) {
        return status;
    }
    status = xxemul_arm_read_data_operand(emulator, instruction, source_index + 1u, current_pc, &right, &shift_carry_valid, &shift_carry);
    if (status != XXEMUL_STATUS_OK) {
        return status;
    }
    mask = xxemul_mask_for_size(size);
    set_flags = (instruction->instruction_flags & CDISASM_ARM_INSTRUCTION_FLAG_SETS_FLAGS) != 0u;

    switch (instruction->name_id) {
        case CDISASM_ARM_NAME_ADD:
        case CDISASM_ARM_NAME_ADDS:
        case CDISASM_ARM_NAME_ADDPT:
            result = (left + right) & mask;
            status = xxemul_arm_write_register(emulator, destination->reg, result);
            if (status == XXEMUL_STATUS_OK && (set_flags || instruction->name_id == CDISASM_ARM_NAME_ADDS)) {
                xxemul_arm_set_add_flags(emulator, left, right, result, size);
            }
            return status;
        case CDISASM_ARM_NAME_SUB:
        case CDISASM_ARM_NAME_SUBS:
        case CDISASM_ARM_NAME_SUBPT:
            result = (left - right) & mask;
            status = xxemul_arm_write_register(emulator, destination->reg, result);
            if (status == XXEMUL_STATUS_OK && (set_flags || instruction->name_id == CDISASM_ARM_NAME_SUBS)) {
                xxemul_arm_set_sub_flags(emulator, left, right, result, size);
            }
            return status;
        case CDISASM_ARM_NAME_RSB:
        case CDISASM_ARM_NAME_RSBS:
            result = (right - left) & mask;
            status = xxemul_arm_write_register(emulator, destination->reg, result);
            if (status == XXEMUL_STATUS_OK && (set_flags || instruction->name_id == CDISASM_ARM_NAME_RSBS)) {
                xxemul_arm_set_sub_flags(emulator, right, left, result, size);
            }
            return status;
        case CDISASM_ARM_NAME_AND:
        case CDISASM_ARM_NAME_ANDS:
            result = (left & right) & mask;
            status = xxemul_arm_write_register(emulator, destination->reg, result);
            if (status == XXEMUL_STATUS_OK && (set_flags || instruction->name_id == CDISASM_ARM_NAME_ANDS)) {
                xxemul_arm_set_logic_flags(emulator, result, size, shift_carry_valid, shift_carry);
            }
            return status;
        case CDISASM_ARM_NAME_ORR:
        case CDISASM_ARM_NAME_ORRS:
            result = (left | right) & mask;
            status = xxemul_arm_write_register(emulator, destination->reg, result);
            if (status == XXEMUL_STATUS_OK && (set_flags || instruction->name_id == CDISASM_ARM_NAME_ORRS)) {
                xxemul_arm_set_logic_flags(emulator, result, size, shift_carry_valid, shift_carry);
            }
            return status;
        case CDISASM_ARM_NAME_EOR:
        case CDISASM_ARM_NAME_EORS:
            result = (left ^ right) & mask;
            status = xxemul_arm_write_register(emulator, destination->reg, result);
            if (status == XXEMUL_STATUS_OK && (set_flags || instruction->name_id == CDISASM_ARM_NAME_EORS)) {
                xxemul_arm_set_logic_flags(emulator, result, size, shift_carry_valid, shift_carry);
            }
            return status;
        case CDISASM_ARM_NAME_EON:
            result = (left ^ (~right & mask)) & mask;
            return xxemul_arm_write_register(emulator, destination->reg, result);
        case CDISASM_ARM_NAME_BIC:
        case CDISASM_ARM_NAME_BICS:
            result = (left & (~right & mask)) & mask;
            status = xxemul_arm_write_register(emulator, destination->reg, result);
            if (status == XXEMUL_STATUS_OK && (set_flags || instruction->name_id == CDISASM_ARM_NAME_BICS)) {
                xxemul_arm_set_logic_flags(emulator, result, size, shift_carry_valid, shift_carry);
            }
            return status;
        case CDISASM_ARM_NAME_ORN:
        case CDISASM_ARM_NAME_ORNS:
            result = (left | (~right & mask)) & mask;
            status = xxemul_arm_write_register(emulator, destination->reg, result);
            if (status == XXEMUL_STATUS_OK && (set_flags || instruction->name_id == CDISASM_ARM_NAME_ORNS)) {
                xxemul_arm_set_logic_flags(emulator, result, size, shift_carry_valid, shift_carry);
            }
            return status;
        default: return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    }
}

static xxemul_status xxemul_arm_compare(xxemul *emulator, const cdisasm_arm_instruction *instruction, uint64_t current_pc)
{
    uint64_t left;
    uint64_t right;
    uint64_t result;
    uint8_t size;
    int shift_carry_valid;
    int shift_carry;
    xxemul_status status;

    if (instruction->operand_count < 2u) {
        return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    }
    status = xxemul_arm_read_operand(emulator, &instruction->operand[0], current_pc, &left);
    if (status != XXEMUL_STATUS_OK) {
        return status;
    }
    status = xxemul_arm_read_data_operand(emulator, instruction, 1u, current_pc, &right, &shift_carry_valid, &shift_carry);
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
    } else if (instruction->name_id == CDISASM_ARM_NAME_CMN) {
        result = (left + right) & xxemul_mask_for_size(size);
        xxemul_arm_set_add_flags(emulator, left, right, result, size);
    } else {
        result = (left & right) & xxemul_mask_for_size(size);
        xxemul_arm_set_logic_flags(emulator, result, size, shift_carry_valid, shift_carry);
    }
    return XXEMUL_STATUS_OK;
}

static xxemul_status xxemul_arm_add_with_carry(xxemul *emulator, const cdisasm_arm_instruction *instruction, uint64_t current_pc,
                                               int subtract, int reverse_subtract)
{
    uint64_t left;
    uint64_t right;
    uint64_t intermediate;
    uint64_t result;
    uint64_t mask;
    uint64_t borrow_or_carry;
    uint64_t sign;
    uint8_t size;
    int set_flags;
    int overflow;
    int carry;
    xxemul_status status;

    if (instruction->operand_count < 2u) {
        return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    }
    size = instruction->operand[0].size == 0u ? (emulator->mode == XXEMUL_MODE_ARM_A64 ? 8u : 4u) : instruction->operand[0].size;
    if (size > 8u) {
        return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    }
    if (instruction->name_id == CDISASM_ARM_NAME_NGC || instruction->name_id == CDISASM_ARM_NAME_NGCS) {
        left = UINT64_C(0);
        status = xxemul_arm_read_data_operand(emulator, instruction, 1u, current_pc, &right, NULL, NULL);
        if (status != XXEMUL_STATUS_OK) return status;
    } else if (instruction->operand_count == 2u) {
        status = xxemul_arm_read_operand(emulator, &instruction->operand[0], current_pc, &left);
        if (status != XXEMUL_STATUS_OK) return status;
        status = xxemul_arm_read_data_operand(emulator, instruction, 1u, current_pc, &right, NULL, NULL);
        if (status != XXEMUL_STATUS_OK) return status;
    } else {
        status = xxemul_arm_read_operand(emulator, &instruction->operand[1], current_pc, &left);
        if (status != XXEMUL_STATUS_OK) return status;
        status = xxemul_arm_read_data_operand(emulator, instruction, 2u, current_pc, &right, NULL, NULL);
        if (status != XXEMUL_STATUS_OK) return status;
    }
    if (reverse_subtract) {
        uint64_t temporary = left;
        left = right;
        right = temporary;
    }

    mask = xxemul_mask_for_size(size);
    left &= mask;
    right &= mask;
    borrow_or_carry = (emulator->arm.pstate & XXEMUL_ARM_FLAG_C) != 0u ? 1u : 0u;
    if (subtract) {
        uint64_t borrow = borrow_or_carry ^ 1u;
        intermediate = (left - right) & mask;
        result = (intermediate - borrow) & mask;
        carry = borrow == 0u ? left >= right : (right != mask && left > right);
        sign = UINT64_C(1) << (size * 8u - 1u);
        overflow = ((((left ^ right) & (left ^ result)) & sign) != 0u);
    } else {
        intermediate = (left + right) & mask;
        result = (intermediate + borrow_or_carry) & mask;
        carry = intermediate < left || result < intermediate;
        sign = UINT64_C(1) << (size * 8u - 1u);
        overflow = (((~(left ^ right) & (left ^ result)) & sign) != 0u);
    }
    status = xxemul_arm_write_register(emulator, instruction->operand[0].reg, result);
    set_flags = (instruction->instruction_flags & CDISASM_ARM_INSTRUCTION_FLAG_SETS_FLAGS) != 0u ||
                instruction->name_id == CDISASM_ARM_NAME_ADCS || instruction->name_id == CDISASM_ARM_NAME_SBCS ||
                instruction->name_id == CDISASM_ARM_NAME_RSCS || instruction->name_id == CDISASM_ARM_NAME_NGCS;
    if (status == XXEMUL_STATUS_OK && set_flags) {
        emulator->arm.pstate &= ~(XXEMUL_ARM_FLAG_C | XXEMUL_ARM_FLAG_V);
        if (carry) emulator->arm.pstate |= XXEMUL_ARM_FLAG_C;
        if (overflow) emulator->arm.pstate |= XXEMUL_ARM_FLAG_V;
        xxemul_arm_set_nz(emulator, result, size);
    }
    return status;
}

static xxemul_status xxemul_arm_multiply(xxemul *emulator, const cdisasm_arm_instruction *instruction, uint64_t current_pc)
{
    uint64_t left;
    uint64_t right;
    uint64_t addend = UINT64_C(0);
    uint64_t result;
    uint64_t mask;
    uint8_t size;
    int set_flags;
    xxemul_status status;

    if (instruction->operand_count < 3u) return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    size = instruction->operand[0].size == 0u ? (emulator->mode == XXEMUL_MODE_ARM_A64 ? 8u : 4u) : instruction->operand[0].size;
    if (size > 8u) return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    status = xxemul_arm_read_operand(emulator, &instruction->operand[1], current_pc, &left);
    if (status != XXEMUL_STATUS_OK) return status;
    status = xxemul_arm_read_operand(emulator, &instruction->operand[2], current_pc, &right);
    if (status != XXEMUL_STATUS_OK) return status;
    if (instruction->name_id == CDISASM_ARM_NAME_MADD || instruction->name_id == CDISASM_ARM_NAME_MSUB ||
        instruction->name_id == CDISASM_ARM_NAME_MADDPT || instruction->name_id == CDISASM_ARM_NAME_MSUBPT ||
        instruction->name_id == CDISASM_ARM_NAME_MLA || instruction->name_id == CDISASM_ARM_NAME_MLS) {
        if (instruction->operand_count < 4u) return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
        status = xxemul_arm_read_operand(emulator, &instruction->operand[3], current_pc, &addend);
        if (status != XXEMUL_STATUS_OK) return status;
    }
    mask = xxemul_mask_for_size(size);
    result = (left * right) & mask;
    if (instruction->name_id == CDISASM_ARM_NAME_MADD || instruction->name_id == CDISASM_ARM_NAME_MADDPT || instruction->name_id == CDISASM_ARM_NAME_MLA)
        result = (addend + result) & mask;
    if (instruction->name_id == CDISASM_ARM_NAME_MSUB || instruction->name_id == CDISASM_ARM_NAME_MSUBPT || instruction->name_id == CDISASM_ARM_NAME_MLS)
        result = (addend - result) & mask;
    if (instruction->name_id == CDISASM_ARM_NAME_MNEG) result = (UINT64_C(0) - result) & mask;
    status = xxemul_arm_write_register(emulator, instruction->operand[0].reg, result);
    set_flags = (instruction->instruction_flags & CDISASM_ARM_INSTRUCTION_FLAG_SETS_FLAGS) != 0u;
    if (status == XXEMUL_STATUS_OK && set_flags) xxemul_arm_set_nz(emulator, result, size);
    return status;
}

static xxemul_status xxemul_arm_multiply_long(xxemul *emulator, const cdisasm_arm_instruction *instruction, uint64_t current_pc, int is_signed)
{
    uint64_t left;
    uint64_t right;
    uint64_t result;
    xxemul_status status;

    if (instruction->operand_count < 4u) return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    status = xxemul_arm_read_operand(emulator, &instruction->operand[2], current_pc, &left);
    if (status != XXEMUL_STATUS_OK) return status;
    status = xxemul_arm_read_operand(emulator, &instruction->operand[3], current_pc, &right);
    if (status != XXEMUL_STATUS_OK) return status;
    if (is_signed) {
        result = (uint64_t)((int64_t)(int32_t)(uint32_t)left * (int64_t)(int32_t)(uint32_t)right);
    } else {
        result = (uint64_t)(uint32_t)left * (uint64_t)(uint32_t)right;
    }
    status = xxemul_arm_write_register(emulator, instruction->operand[0].reg, (uint32_t)result);
    if (status == XXEMUL_STATUS_OK) {
        status = xxemul_arm_write_register(emulator, instruction->operand[1].reg, result >> 32u);
    }
    return status;
}

static xxemul_status xxemul_arm_signed_most_significant_multiply(xxemul *emulator, const cdisasm_arm_instruction *instruction, uint64_t current_pc)
{
    uint64_t left;
    uint64_t right;
    uint64_t addend;
    uint64_t result;
    xxemul_status status;

    if (instruction->operand_count < 4u) return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    status = xxemul_arm_read_operand(emulator, &instruction->operand[1], current_pc, &left);
    if (status != XXEMUL_STATUS_OK) return status;
    status = xxemul_arm_read_operand(emulator, &instruction->operand[2], current_pc, &right);
    if (status != XXEMUL_STATUS_OK) return status;
    status = xxemul_arm_read_operand(emulator, &instruction->operand[3], current_pc, &addend);
    if (status != XXEMUL_STATUS_OK) return status;
    result = (uint64_t)((int64_t)(int32_t)(uint32_t)left * (int64_t)(int32_t)(uint32_t)right);
    result += (uint64_t)(uint32_t)addend << 32u;
    if (instruction->name_id == CDISASM_ARM_NAME_SMMLAR) result += UINT64_C(0x80000000);
    return xxemul_arm_write_register(emulator, instruction->operand[0].reg, result >> 32u);
}

static xxemul_status xxemul_arm_bitfield(xxemul *emulator, const cdisasm_arm_instruction *instruction, uint64_t current_pc)
{
    uint64_t destination = UINT64_C(0);
    uint64_t source = UINT64_C(0);
    uint64_t field_mask;
    uint64_t result;
    uint64_t lsb;
    uint64_t width;
    uint8_t size;
    unsigned bits;
    xxemul_status status;

    if (instruction->operand_count < 3u || instruction->operand[0].type != CDISASM_OPERAND_REGISTER) {
        return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    }
    size = instruction->operand[0].size == 0u ? (emulator->mode == XXEMUL_MODE_ARM_A64 ? 8u : 4u) : instruction->operand[0].size;
    if (size == 0u || size > 8u) return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    bits = (unsigned)size * 8u;

    if (instruction->name_id == CDISASM_ARM_NAME_BFC) {
        if (instruction->operand_count != 3u || instruction->operand[1].type != CDISASM_OPERAND_IMMEDIATE ||
            instruction->operand[2].type != CDISASM_OPERAND_IMMEDIATE) return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
        status = xxemul_arm_read_operand(emulator, &instruction->operand[0], current_pc, &destination);
        lsb = instruction->operand[1].imm;
        width = instruction->operand[2].imm;
    } else {
        if (instruction->operand_count != 4u || instruction->operand[1].type != CDISASM_OPERAND_REGISTER ||
            instruction->operand[2].type != CDISASM_OPERAND_IMMEDIATE || instruction->operand[3].type != CDISASM_OPERAND_IMMEDIATE)
            return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
        status = xxemul_arm_read_operand(emulator, &instruction->operand[1], current_pc, &source);
        lsb = instruction->operand[2].imm;
        width = instruction->operand[3].imm;
    }
    if (status != XXEMUL_STATUS_OK) return status;
    if (instruction->name_id == CDISASM_ARM_NAME_BFM || instruction->name_id == CDISASM_ARM_NAME_UBFM ||
        instruction->name_id == CDISASM_ARM_NAME_SBFM) {
        uint64_t immr = lsb;
        uint64_t imms = width;
        uint64_t result_width;

        /* Canonical A64 bitfields expose immr/imms. Aliases below expose
         * lsb/width instead; the two schemas must not be interchanged. */
        if (emulator->mode != XXEMUL_MODE_ARM_A64 || (size != 4u && size != 8u) || immr >= bits || imms >= bits)
            return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
        if (imms >= immr) {
            width = imms - immr + UINT64_C(1);
            field_mask = width == 64u ? UINT64_MAX : (UINT64_C(1) << width) - UINT64_C(1);
            result = (source >> immr) & field_mask;
            result_width = width;
        } else {
            width = imms + UINT64_C(1);
            lsb = bits - immr;
            field_mask = ((UINT64_C(1) << width) - UINT64_C(1)) << lsb;
            result = (source << lsb) & field_mask;
            result_width = lsb + width;
        }
        if (instruction->name_id == CDISASM_ARM_NAME_BFM) {
            status = xxemul_arm_read_operand(emulator, &instruction->operand[0], current_pc, &destination);
            if (status != XXEMUL_STATUS_OK) return status;
            result |= destination & ~field_mask;
        } else if (instruction->name_id == CDISASM_ARM_NAME_SBFM && result_width < 64u &&
                   (source & (UINT64_C(1) << imms)) != 0u) {
            result |= UINT64_MAX << result_width;
        }
        return xxemul_arm_write_register(emulator, instruction->operand[0].reg, result & xxemul_mask_for_size(size));
    }
    if (lsb >= bits || width == 0u || width > bits - lsb) {
        return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    }
    field_mask = width == 64u ? UINT64_MAX : (UINT64_C(1) << width) - UINT64_C(1);
    if (instruction->name_id == CDISASM_ARM_NAME_UBFX || instruction->name_id == CDISASM_ARM_NAME_SBFX) {
        result = (source >> lsb) & field_mask;
        if (instruction->name_id == CDISASM_ARM_NAME_SBFX && width < 64u && (result & (UINT64_C(1) << (width - 1u))) != 0u) {
            result |= ~field_mask;
        }
    } else if (instruction->name_id == CDISASM_ARM_NAME_UBFIZ || instruction->name_id == CDISASM_ARM_NAME_SBFIZ) {
        result = (source & field_mask) << lsb;
        if (instruction->name_id == CDISASM_ARM_NAME_SBFIZ && lsb + width < 64u &&
            (source & (UINT64_C(1) << (width - 1u))) != 0u) {
            result |= UINT64_MAX << (lsb + width);
        }
    } else {
        if (instruction->name_id != CDISASM_ARM_NAME_BFC) {
            status = xxemul_arm_read_operand(emulator, &instruction->operand[0], current_pc, &destination);
            if (status != XXEMUL_STATUS_OK) return status;
        }
        if (instruction->name_id == CDISASM_ARM_NAME_BFXIL) {
            result = (destination & ~field_mask) | ((source >> lsb) & field_mask);
        } else if (instruction->name_id == CDISASM_ARM_NAME_BFC || instruction->name_id == CDISASM_ARM_NAME_BFI) {
            field_mask <<= lsb;
            result = instruction->name_id == CDISASM_ARM_NAME_BFC
                         ? destination & ~field_mask
                         : (destination & ~field_mask) | ((source << lsb) & field_mask);
        } else {
            return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
        }
    }
    return xxemul_arm_write_register(emulator, instruction->operand[0].reg, result & xxemul_mask_for_size(size));
}

static uint64_t xxemul_arm_reverse_bytes(uint64_t value, uint8_t size)
{
    uint64_t result = UINT64_C(0);
    uint8_t index;
    for (index = 0u; index < size; ++index) {
        result = (result << 8u) | ((value >> (index * 8u)) & UINT8_MAX);
    }
    return result;
}

static xxemul_status xxemul_arm_reverse(xxemul *emulator, const cdisasm_arm_instruction *instruction, uint64_t current_pc)
{
    uint64_t value;
    uint64_t result = UINT64_C(0);
    uint8_t size;
    uint8_t index;
    xxemul_status status;

    if (instruction->operand_count < 2u) return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    size = instruction->operand[0].size == 0u ? (emulator->mode == XXEMUL_MODE_ARM_A64 ? 8u : 4u) : instruction->operand[0].size;
    status = xxemul_arm_read_operand(emulator, &instruction->operand[1], current_pc, &value);
    if (status != XXEMUL_STATUS_OK) return status;
    if (instruction->name_id == CDISASM_ARM_NAME_RBIT) {
        if ((size != 4u && size != 8u) || instruction->operand_count != 2u ||
            instruction->operand[0].type != CDISASM_OPERAND_REGISTER ||
            instruction->operand[1].type != CDISASM_OPERAND_REGISTER ||
            instruction->operand[1].size != size) return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
        for (index = 0u; index < (unsigned)size * 8u; ++index) {
            result = (result << 1u) | (value & UINT64_C(1));
            value >>= 1u;
        }
    } else if (instruction->name_id == CDISASM_ARM_NAME_REV) {
        result = xxemul_arm_reverse_bytes(value, size);
    } else if (instruction->name_id == CDISASM_ARM_NAME_REV16) {
        for (index = 0u; index < size; index += 2u) {
            uint64_t half = (value >> (index * 8u)) & UINT16_MAX;
            result |= ((half >> 8u) | ((half & UINT8_MAX) << 8u)) << (index * 8u);
        }
    } else if (instruction->name_id == CDISASM_ARM_NAME_REVSH) {
        uint64_t half = ((value & UINT8_MAX) << 8u) | ((value >> 8u) & UINT8_MAX);
        result = xxemul_sign_extend(half, 2u);
    } else {
        return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    }
    return xxemul_arm_write_register(emulator, instruction->operand[0].reg, result);
}

static xxemul_status xxemul_arm_conditional_select(xxemul *emulator, const cdisasm_arm_instruction *instruction, uint64_t current_pc)
{
    uint64_t value;
    uint64_t mask;
    int passed;
    uint8_t size;
    xxemul_status status;

    size = instruction->operand[0].size == 0u ? 8u : instruction->operand[0].size;
    mask = xxemul_mask_for_size(size);
    if (instruction->name_id == CDISASM_ARM_NAME_CSET || instruction->name_id == CDISASM_ARM_NAME_CSETM) {
        if (instruction->operand_count < 2u) return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
        passed = xxemul_arm_condition_passed(emulator, (cdisasm_arm_condition)instruction->operand[1].imm);
        value = passed ? (instruction->name_id == CDISASM_ARM_NAME_CSET ? UINT64_C(1) : mask) : UINT64_C(0);
    } else if (instruction->name_id == CDISASM_ARM_NAME_CINC || instruction->name_id == CDISASM_ARM_NAME_CINV ||
               instruction->name_id == CDISASM_ARM_NAME_CNEG) {
        if (instruction->operand_count < 3u) return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
        passed = xxemul_arm_condition_passed(emulator, (cdisasm_arm_condition)instruction->operand[2].imm);
        status = xxemul_arm_read_operand(emulator, &instruction->operand[1], current_pc, &value);
        if (status != XXEMUL_STATUS_OK) return status;
        if (passed) {
            if (instruction->name_id == CDISASM_ARM_NAME_CINC) value = (value + UINT64_C(1)) & mask;
            else if (instruction->name_id == CDISASM_ARM_NAME_CINV) value = (~value) & mask;
            else value = (UINT64_C(0) - value) & mask;
        }
    } else {
        if (instruction->operand_count < 4u) return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
        passed = xxemul_arm_condition_passed(emulator, (cdisasm_arm_condition)instruction->operand[3].imm);
        status = xxemul_arm_read_operand(emulator, &instruction->operand[passed ? 1u : 2u], current_pc, &value);
        if (status != XXEMUL_STATUS_OK) return status;
        if (!passed) {
            if (instruction->name_id == CDISASM_ARM_NAME_CSINC) value = (value + UINT64_C(1)) & mask;
            else if (instruction->name_id == CDISASM_ARM_NAME_CSINV) value = (~value) & mask;
            else if (instruction->name_id == CDISASM_ARM_NAME_CSNEG) value = (UINT64_C(0) - value) & mask;
        }
    }
    return xxemul_arm_write_register(emulator, instruction->operand[0].reg, value);
}

static xxemul_status xxemul_arm_negate(xxemul *emulator, const cdisasm_arm_instruction *instruction, uint64_t current_pc)
{
    uint64_t value;
    uint64_t result;
    uint8_t size;
    xxemul_status status;

    if (instruction->operand_count < 2u) return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    size = instruction->operand[0].size == 0u ? (emulator->mode == XXEMUL_MODE_ARM_A64 ? 8u : 4u) : instruction->operand[0].size;
    status = xxemul_arm_read_operand(emulator, &instruction->operand[1], current_pc, &value);
    if (status != XXEMUL_STATUS_OK) return status;
    result = (UINT64_C(0) - value) & xxemul_mask_for_size(size);
    status = xxemul_arm_write_register(emulator, instruction->operand[0].reg, result);
    if (status == XXEMUL_STATUS_OK && (instruction->name_id == CDISASM_ARM_NAME_NEGS ||
                                       (instruction->instruction_flags & CDISASM_ARM_INSTRUCTION_FLAG_SETS_FLAGS) != 0u)) {
        xxemul_arm_set_sub_flags(emulator, UINT64_C(0), value, result, size);
    }
    return status;
}

static xxemul_status xxemul_arm_shift_instruction(xxemul *emulator, const cdisasm_arm_instruction *instruction, uint64_t current_pc)
{
    uint64_t value;
    uint64_t amount;
    uint64_t result;
    uint8_t size;
    unsigned source_index;
    unsigned amount_index;
    int carry_valid;
    int carry;
    cdisasm_arm_shift_type type;
    xxemul_status status;

    if (instruction->operand_count < 2u) return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    size = instruction->operand[0].size == 0u ? (emulator->mode == XXEMUL_MODE_ARM_A64 ? 8u : 4u) : instruction->operand[0].size;
    source_index = instruction->operand_count >= 3u ? 1u : 0u;
    amount_index = instruction->operand_count >= 3u ? 2u : 1u;
    status = xxemul_arm_read_operand(emulator, &instruction->operand[source_index], current_pc, &value);
    if (status != XXEMUL_STATUS_OK) return status;
    status = xxemul_arm_read_operand(emulator, &instruction->operand[amount_index], current_pc, &amount);
    if (status != XXEMUL_STATUS_OK) return status;
    if (emulator->mode == XXEMUL_MODE_ARM_A64 && instruction->operand[amount_index].type == CDISASM_OPERAND_REGISTER) {
        amount &= (uint64_t)size * 8u - 1u;
    }
    switch (instruction->name_id) {
        case CDISASM_ARM_NAME_LSL:
        case CDISASM_ARM_NAME_LSLS: type = CDISASM_ARM_SHIFT_LSL; break;
        case CDISASM_ARM_NAME_LSR:
        case CDISASM_ARM_NAME_LSRS: type = CDISASM_ARM_SHIFT_LSR; break;
        case CDISASM_ARM_NAME_ASR:
        case CDISASM_ARM_NAME_ASRS: type = CDISASM_ARM_SHIFT_ASR; break;
        default: type = CDISASM_ARM_SHIFT_ROR; break;
    }
    result = xxemul_arm_apply_shift_with_carry(emulator, value, size, type, (uint8_t)amount, &carry_valid, &carry);
    status = xxemul_arm_write_register(emulator, instruction->operand[0].reg, result);
    if (status == XXEMUL_STATUS_OK && (instruction->instruction_flags & CDISASM_ARM_INSTRUCTION_FLAG_SETS_FLAGS) != 0u) {
        xxemul_arm_set_nz(emulator, result, size);
        if (carry_valid) {
            emulator->arm.pstate &= ~XXEMUL_ARM_FLAG_C;
            if (carry) emulator->arm.pstate |= XXEMUL_ARM_FLAG_C;
        }
    }
    return status;
}

static xxemul_status xxemul_arm_count_leading_zeros(xxemul *emulator, const cdisasm_arm_instruction *instruction, uint64_t current_pc)
{
    uint64_t value;
    uint8_t size;
    unsigned count = 0u;
    unsigned bits;
    xxemul_status status;

    if (instruction->operand_count < 2u) return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    size = instruction->operand[0].size == 0u ? (emulator->mode == XXEMUL_MODE_ARM_A64 ? 8u : 4u) : instruction->operand[0].size;
    if (size == 0u || size > 8u) return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    status = xxemul_arm_read_operand(emulator, &instruction->operand[1], current_pc, &value);
    if (status != XXEMUL_STATUS_OK) return status;
    bits = (unsigned)size * 8u;
    value &= xxemul_mask_for_size(size);
    while (count < bits && (value & (UINT64_C(1) << (bits - count - 1u))) == 0u) ++count;
    return xxemul_arm_write_register(emulator, instruction->operand[0].reg, count);
}

static xxemul_status xxemul_arm_crc32(xxemul *emulator, const cdisasm_arm_instruction *instruction, uint64_t current_pc)
{
    uint64_t accumulator, data;
    uint32_t crc, polynomial = UINT32_C(0xedb88320);
    unsigned width, byte, bit;
    xxemul_status status;

    /* cdisasm carries the consumed byte width independently of the W/X
     * register width. CRC32B/H use only the low byte/halfword of Wm. */
    switch (instruction->name_id) {
        case CDISASM_ARM_NAME_CRC32B: width = 1u; break;
        case CDISASM_ARM_NAME_CRC32H: width = 2u; break;
        case CDISASM_ARM_NAME_CRC32W: width = 4u; break;
        case CDISASM_ARM_NAME_CRC32X: width = 8u; break;
        case CDISASM_ARM_NAME_CRC32CB: width = 1u; polynomial = UINT32_C(0x82f63b78); break;
        case CDISASM_ARM_NAME_CRC32CH: width = 2u; polynomial = UINT32_C(0x82f63b78); break;
        case CDISASM_ARM_NAME_CRC32CW: width = 4u; polynomial = UINT32_C(0x82f63b78); break;
        case CDISASM_ARM_NAME_CRC32CX: width = 8u; polynomial = UINT32_C(0x82f63b78); break;
        default: return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    }
    if (instruction->operand_count != 3u ||
        instruction->operand[0].type != CDISASM_OPERAND_REGISTER || instruction->operand[0].size != 4u ||
        instruction->operand[1].type != CDISASM_OPERAND_REGISTER || instruction->operand[1].size != 4u ||
        instruction->operand[2].type != CDISASM_OPERAND_REGISTER || instruction->operand[2].size != width ||
        (width == 8u && emulator->mode != XXEMUL_MODE_ARM_A64)) return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    status = xxemul_arm_read_operand(emulator, &instruction->operand[1], current_pc, &accumulator);
    if (status != XXEMUL_STATUS_OK) return status;
    status = xxemul_arm_read_operand(emulator, &instruction->operand[2], current_pc, &data);
    if (status != XXEMUL_STATUS_OK) return status;
    crc = (uint32_t)accumulator;
    /* Architectural instructions consume least-significant data bits first,
     * without the initial/final complement used by a whole-file CRC API. */
    for (byte = 0u; byte < width; ++byte) {
        crc ^= (uint8_t)data;
        data >>= 8u;
        for (bit = 0u; bit < 8u; ++bit)
            crc = (crc >> 1u) ^ ((crc & 1u) != 0u ? polynomial : 0u);
    }
    return xxemul_arm_write_register(emulator, instruction->operand[0].reg, crc);
}

static xxemul_status xxemul_arm_extend_instruction(xxemul *emulator, const cdisasm_arm_instruction *instruction, uint64_t current_pc)
{
    uint64_t value;
    uint8_t source_size;
    xxemul_status status;

    if (instruction->operand_count < 2u) return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    status = xxemul_arm_read_operand(emulator, &instruction->operand[1], current_pc, &value);
    if (status != XXEMUL_STATUS_OK) return status;
    switch (instruction->name_id) {
        case CDISASM_ARM_NAME_SXTB: source_size = 1u; value = xxemul_sign_extend(value, source_size); break;
        case CDISASM_ARM_NAME_SXTH: source_size = 2u; value = xxemul_sign_extend(value, source_size); break;
        case CDISASM_ARM_NAME_SXTW: source_size = 4u; value = xxemul_sign_extend(value, source_size); break;
        case CDISASM_ARM_NAME_UXTB: value &= UINT8_MAX; break;
        case CDISASM_ARM_NAME_UXTH: value &= UINT16_MAX; break;
        case CDISASM_ARM_NAME_UXTW: value &= UINT32_MAX; break;
        default: return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    }
    return xxemul_arm_write_register(emulator, instruction->operand[0].reg, value);
}

static xxemul_status xxemul_arm_extract_registers(xxemul *emulator, const cdisasm_arm_instruction *instruction, uint64_t current_pc)
{
    uint64_t high;
    uint64_t low;
    uint64_t amount;
    uint64_t result;
    uint8_t size;
    unsigned bits;
    xxemul_status status;

    if (instruction->operand_count < 4u) return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    size = instruction->operand[0].size == 0u ? 8u : instruction->operand[0].size;
    if (size == 0u || size > 8u) return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    status = xxemul_arm_read_operand(emulator, &instruction->operand[1], current_pc, &high);
    if (status != XXEMUL_STATUS_OK) return status;
    status = xxemul_arm_read_operand(emulator, &instruction->operand[2], current_pc, &low);
    if (status != XXEMUL_STATUS_OK) return status;
    status = xxemul_arm_read_operand(emulator, &instruction->operand[3], current_pc, &amount);
    if (status != XXEMUL_STATUS_OK) return status;
    bits = (unsigned)size * 8u;
    if (amount >= bits) return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    high &= xxemul_mask_for_size(size);
    low &= xxemul_mask_for_size(size);
    result = amount == 0u ? low : (low >> amount) | (high << (bits - (unsigned)amount));
    return xxemul_arm_write_register(emulator, instruction->operand[0].reg, result & xxemul_mask_for_size(size));
}

static uint64_t xxemul_arm_unsigned_multiply_high(uint64_t left, uint64_t right)
{
    uint64_t left_low = (uint32_t)left;
    uint64_t left_high = left >> 32u;
    uint64_t right_low = (uint32_t)right;
    uint64_t right_high = right >> 32u;
    uint64_t low_product = left_low * right_low;
    uint64_t middle = (low_product >> 32u) + left_high * right_low;
    uint64_t middle_low = (uint32_t)middle + left_low * right_high;

    return left_high * right_high + (middle >> 32u) + (middle_low >> 32u);
}

static xxemul_status xxemul_arm_special_multiply(xxemul *emulator, const cdisasm_arm_instruction *instruction, uint64_t current_pc)
{
    uint64_t left;
    uint64_t right;
    uint64_t addend;
    uint64_t result;
    xxemul_status status;

    if (instruction->name_id == CDISASM_ARM_NAME_SMULH) {
        if (instruction->operand_count < 3u) return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
        status = xxemul_arm_read_operand(emulator, &instruction->operand[1], current_pc, &left);
        if (status != XXEMUL_STATUS_OK) return status;
        status = xxemul_arm_read_operand(emulator, &instruction->operand[2], current_pc, &right);
        if (status != XXEMUL_STATUS_OK) return status;
        result = xxemul_arm_unsigned_multiply_high(left, right);
        if ((int64_t)left < 0) result -= right;
        if ((int64_t)right < 0) result -= left;
    } else {
        if (instruction->operand_count < 4u) return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
        status = xxemul_arm_read_operand(emulator, &instruction->operand[1], current_pc, &left);
        if (status != XXEMUL_STATUS_OK) return status;
        status = xxemul_arm_read_operand(emulator, &instruction->operand[2], current_pc, &right);
        if (status != XXEMUL_STATUS_OK) return status;
        status = xxemul_arm_read_operand(emulator, &instruction->operand[3], current_pc, &addend);
        if (status != XXEMUL_STATUS_OK) return status;
        result = addend - (uint64_t)((int64_t)(int32_t)(uint32_t)left * (int64_t)(int32_t)(uint32_t)right);
    }
    return xxemul_arm_write_register(emulator, instruction->operand[0].reg, result);
}

static xxemul_status xxemul_arm_divide(xxemul *emulator, const cdisasm_arm_instruction *instruction, uint64_t current_pc, int is_signed)
{
    uint64_t dividend;
    uint64_t divisor;
    uint64_t result;
    uint8_t size;
    xxemul_status status;

    if (instruction->operand_count < 3u) return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    size = instruction->operand[0].size == 0u ? (emulator->mode == XXEMUL_MODE_ARM_A64 ? 8u : 4u) : instruction->operand[0].size;
    status = xxemul_arm_read_operand(emulator, &instruction->operand[1], current_pc, &dividend);
    if (status != XXEMUL_STATUS_OK) return status;
    status = xxemul_arm_read_operand(emulator, &instruction->operand[2], current_pc, &divisor);
    if (status != XXEMUL_STATUS_OK) return status;
    dividend &= xxemul_mask_for_size(size);
    divisor &= xxemul_mask_for_size(size);
    if (divisor == 0u) {
        result = 0u;
    } else if (is_signed && size == 8u) {
        int64_t signed_dividend = (int64_t)dividend;
        int64_t signed_divisor = (int64_t)divisor;
        result = signed_dividend == INT64_MIN && signed_divisor == -1 ? dividend : (uint64_t)(signed_dividend / signed_divisor);
    } else if (is_signed) {
        int32_t signed_dividend = (int32_t)(uint32_t)dividend;
        int32_t signed_divisor = (int32_t)(uint32_t)divisor;
        result = signed_dividend == INT32_MIN && signed_divisor == -1 ? (uint32_t)dividend : (uint32_t)(signed_dividend / signed_divisor);
    } else {
        result = dividend / divisor;
    }
    return xxemul_arm_write_register(emulator, instruction->operand[0].reg, result & xxemul_mask_for_size(size));
}

static uint64_t xxemul_arm_untag_pointer(uint64_t value)
{
    return xxemul_sign_extend(value & UINT64_C(0x00ffffffffffffff), 7u);
}

static xxemul_status xxemul_arm_pointer_subtract(xxemul *emulator, const cdisasm_arm_instruction *instruction, uint64_t current_pc)
{
    uint64_t left;
    uint64_t right;
    uint64_t result;
    size_t source_index;
    xxemul_status status;

    source_index = instruction->name_id == CDISASM_ARM_NAME_CMPP ? 0u : 1u;
    if (instruction->operand_count < source_index + 2u) return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    status = xxemul_arm_read_operand(emulator, &instruction->operand[source_index], current_pc, &left);
    if (status != XXEMUL_STATUS_OK) return status;
    status = xxemul_arm_read_operand(emulator, &instruction->operand[source_index + 1u], current_pc, &right);
    if (status != XXEMUL_STATUS_OK) return status;
    left = xxemul_arm_untag_pointer(left);
    right = xxemul_arm_untag_pointer(right);
    result = left - right;
    if (instruction->name_id == CDISASM_ARM_NAME_CMPP) {
        xxemul_arm_set_sub_flags(emulator, left, right, result, 8u);
        return XXEMUL_STATUS_OK;
    }
    status = xxemul_arm_write_register(emulator, instruction->operand[0].reg, result);
    if (status == XXEMUL_STATUS_OK && instruction->name_id == CDISASM_ARM_NAME_SUBPS) {
        xxemul_arm_set_sub_flags(emulator, left, right, result, 8u);
    }
    return status;
}

static xxemul_status xxemul_arm_subtract_tagged_offset(xxemul *emulator, const cdisasm_arm_instruction *instruction, uint64_t current_pc)
{
    uint64_t base;
    uint64_t offset;
    xxemul_status status;

    if (instruction->operand_count < 3u) return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    status = xxemul_arm_read_operand(emulator, &instruction->operand[1], current_pc, &base);
    if (status != XXEMUL_STATUS_OK) return status;
    status = xxemul_arm_read_operand(emulator, &instruction->operand[2], current_pc, &offset);
    if (status != XXEMUL_STATUS_OK) return status;
    return xxemul_arm_write_register(emulator, instruction->operand[0].reg, base - offset);
}

static xxemul_status xxemul_arm_uadd8(xxemul *emulator, const cdisasm_arm_instruction *instruction, uint64_t current_pc)
{
    uint64_t left;
    uint64_t right;
    uint64_t result = UINT64_C(0);
    unsigned index;
    xxemul_status status;

    if (instruction->operand_count < 3u) return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    status = xxemul_arm_read_operand(emulator, &instruction->operand[1], current_pc, &left);
    if (status != XXEMUL_STATUS_OK) return status;
    status = xxemul_arm_read_operand(emulator, &instruction->operand[2], current_pc, &right);
    if (status != XXEMUL_STATUS_OK) return status;
    for (index = 0u; index < 4u; ++index) {
        uint64_t sum = ((left >> (index * 8u)) & UINT8_MAX) + ((right >> (index * 8u)) & UINT8_MAX);
        result |= (sum & UINT8_MAX) << (index * 8u);
    }
    return xxemul_arm_write_register(emulator, instruction->operand[0].reg, result);
}

static xxemul_status xxemul_arm_multiple_transfer(xxemul *emulator, const cdisasm_arm_instruction *instruction, uint64_t current_pc, int is_load)
{
    const cdisasm_arm_operand *base_operand;
    const cdisasm_arm_operand *list_operand;
    uint64_t base;
    uint64_t address;
    uint64_t value;
    uint64_t delta;
    uint16_t list;
    unsigned count = 0u;
    unsigned index;
    int increment;
    int pre;
    xxemul_status status;

    if (instruction->name_id == CDISASM_ARM_NAME_PUSH || instruction->name_id == CDISASM_ARM_NAME_POP) {
        if (instruction->operand_count < 1u) return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
        base_operand = NULL;
        list_operand = &instruction->operand[0];
        base = emulator->arm.sp & UINT32_MAX;
    } else {
        if (instruction->operand_count < 2u) return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
        base_operand = &instruction->operand[0];
        list_operand = &instruction->operand[1];
        status = xxemul_arm_read_operand(emulator, base_operand, current_pc, &base);
        if (status != XXEMUL_STATUS_OK) return status;
    }
    if (list_operand->type != CDISASM_ARM_OPERAND_REGISTER_LIST) return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    list = list_operand->register_list;
    for (index = 0u; index < 16u; ++index) if ((list & (UINT16_C(1) << index)) != 0u) ++count;
    if (count == 0u) return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    delta = (uint64_t)count * UINT64_C(4);
    increment = (instruction->instruction_flags & CDISASM_ARM_INSTRUCTION_FLAG_ADDRESS_INCREMENT) != 0u;
    pre = (instruction->instruction_flags & CDISASM_ARM_INSTRUCTION_FLAG_PRE_INDEX) != 0u;
    if (increment) {
        address = base + (pre ? UINT64_C(4) : UINT64_C(0));
    } else {
        address = base - delta + (pre ? UINT64_C(0) : UINT64_C(4));
    }
    address &= xxemul_arm_address_mask(emulator);
    for (index = 0u; index < 16u; ++index) {
        if ((list & (UINT16_C(1) << index)) == 0u) continue;
        if (is_load) {
            status = xxemul_arm_guest_load_integer(emulator, address, 4u, &value);
            if (status == XXEMUL_STATUS_OK) status = xxemul_arm_write_register(emulator, (cdisasm_arm_reg_id)(CDISASM_ARM_REG_R0 + index), value);
        } else {
            status = xxemul_arm_read_register(emulator, (cdisasm_arm_reg_id)(CDISASM_ARM_REG_R0 + index), current_pc, &value, NULL);
            if (status == XXEMUL_STATUS_OK) status = xxemul_arm_guest_store_integer(emulator, address, 4u, value);
        }
        if (status != XXEMUL_STATUS_OK) return status;
        address = (address + UINT64_C(4)) & xxemul_arm_address_mask(emulator);
    }
    if ((instruction->instruction_flags & CDISASM_ARM_INSTRUCTION_FLAG_WRITEBACK) != 0u) {
        uint64_t updated = increment ? base + delta : base - delta;
        if (base_operand != NULL) return xxemul_arm_write_register(emulator, base_operand->reg, updated);
        emulator->arm.sp = updated & UINT32_MAX;
    }
    return XXEMUL_STATUS_OK;
}

static xxemul_status xxemul_arm_pair_transfer(xxemul *emulator, const cdisasm_arm_instruction *instruction, uint64_t current_pc, int is_load)
{
    const cdisasm_arm_operand *memory_operand;
    uint64_t address;
    uint64_t writeback;
    uint64_t first;
    uint64_t second;
    uint8_t size;
    int has_writeback;
    xxemul_status status;

    if (instruction->operand_count < 3u) return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    memory_operand = &instruction->operand[2];
    if (instruction->operand[0].type != CDISASM_OPERAND_REGISTER || instruction->operand[1].type != CDISASM_OPERAND_REGISTER ||
        memory_operand->type != CDISASM_OPERAND_MEMORY) return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    size = (instruction->name_id == CDISASM_ARM_NAME_LDRD || instruction->name_id == CDISASM_ARM_NAME_STRD)
               ? 4u
               : (memory_operand->size == 0u ? instruction->operand[0].size : memory_operand->size);
    if (size == 0u || size > 8u) return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    status = xxemul_arm_memory_address(emulator, instruction, memory_operand, current_pc, &address, &writeback, &has_writeback);
    if (status != XXEMUL_STATUS_OK) return status;
    if (is_load) {
        status = xxemul_arm_guest_load_integer(emulator, address, size, &first);
        if (status == XXEMUL_STATUS_OK) status = xxemul_arm_guest_load_integer(emulator, address + size, size, &second);
        if (status == XXEMUL_STATUS_OK) status = xxemul_arm_write_register(emulator, instruction->operand[0].reg, first);
        if (status == XXEMUL_STATUS_OK) status = xxemul_arm_write_register(emulator, instruction->operand[1].reg, second);
    } else {
        status = xxemul_arm_read_operand(emulator, &instruction->operand[0], current_pc, &first);
        if (status == XXEMUL_STATUS_OK) status = xxemul_arm_read_operand(emulator, &instruction->operand[1], current_pc, &second);
        if (status == XXEMUL_STATUS_OK) status = xxemul_arm_guest_store_integer(emulator, address, size, first);
        if (status == XXEMUL_STATUS_OK) status = xxemul_arm_guest_store_integer(emulator, address + size, size, second);
    }
    if (status == XXEMUL_STATUS_OK && has_writeback) status = xxemul_arm_write_register(emulator, memory_operand->base_reg, writeback);
    return status;
}

static xxemul_status xxemul_arm_conditional_compare(xxemul *emulator, const cdisasm_arm_instruction *instruction, uint64_t current_pc)
{
    uint64_t left;
    uint64_t right;
    uint64_t result;
    uint64_t nzcv;
    uint8_t size;
    cdisasm_arm_condition condition;
    xxemul_status status;

    if (instruction->operand_count < 4u) return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    condition = (cdisasm_arm_condition)instruction->operand[3].imm;
    if (!xxemul_arm_condition_passed(emulator, condition)) {
        nzcv = instruction->operand[2].imm & UINT64_C(0xf);
        emulator->arm.pstate &= ~(XXEMUL_ARM_FLAG_N | XXEMUL_ARM_FLAG_Z | XXEMUL_ARM_FLAG_C | XXEMUL_ARM_FLAG_V);
        if ((nzcv & UINT64_C(8)) != 0u) emulator->arm.pstate |= XXEMUL_ARM_FLAG_N;
        if ((nzcv & UINT64_C(4)) != 0u) emulator->arm.pstate |= XXEMUL_ARM_FLAG_Z;
        if ((nzcv & UINT64_C(2)) != 0u) emulator->arm.pstate |= XXEMUL_ARM_FLAG_C;
        if ((nzcv & UINT64_C(1)) != 0u) emulator->arm.pstate |= XXEMUL_ARM_FLAG_V;
        return XXEMUL_STATUS_OK;
    }
    status = xxemul_arm_read_operand(emulator, &instruction->operand[0], current_pc, &left);
    if (status != XXEMUL_STATUS_OK) return status;
    status = xxemul_arm_read_operand(emulator, &instruction->operand[1], current_pc, &right);
    if (status != XXEMUL_STATUS_OK) return status;
    size = instruction->operand[0].size == 0u ? 8u : instruction->operand[0].size;
    if (instruction->name_id == CDISASM_ARM_NAME_CCMP) {
        result = (left - right) & xxemul_mask_for_size(size);
        xxemul_arm_set_sub_flags(emulator, left, right, result, size);
    } else {
        result = (left + right) & xxemul_mask_for_size(size);
        xxemul_arm_set_add_flags(emulator, left, right, result, size);
    }
    return XXEMUL_STATUS_OK;
}

static xxemul_status xxemul_arm_load_store(xxemul *emulator, const cdisasm_arm_instruction *instruction, uint64_t current_pc, int is_load)
{
    const cdisasm_arm_operand *register_operand;
    const cdisasm_arm_operand *memory_operand;
    uint64_t address;
    uint64_t writeback;
    uint64_t value;
    uint8_t size;
    int has_writeback, literal;
    xxemul_status status;

    if (instruction->operand_count < 2u) {
        return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    }
    register_operand = &instruction->operand[0];
    memory_operand = &instruction->operand[1];
    literal = is_load && xxemul_arm_literal_operand(emulator, instruction, memory_operand);
    if (register_operand->type != CDISASM_OPERAND_REGISTER ||
        (memory_operand->type != CDISASM_OPERAND_MEMORY && !literal)) {
        return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    }
    size = literal ? (instruction->name_id == CDISASM_ARM_NAME_LDRSW ? 4u : register_operand->size) : memory_operand->size;
    if (size == 0u) {
        size = register_operand->size;
    }
    if (size == 0u || size > 8u) {
        return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    }
    status = xxemul_arm_memory_address(emulator, instruction, memory_operand, current_pc, &address, &writeback, &has_writeback);
    if (status != XXEMUL_STATUS_OK) {
        return status;
    }
    if (is_load) {
        status = xxemul_arm_guest_load_integer(emulator, address, size, &value);
        if (status == XXEMUL_STATUS_OK &&
            (instruction->name_id == CDISASM_ARM_NAME_LDRSB || instruction->name_id == CDISASM_ARM_NAME_LDRSH ||
             instruction->name_id == CDISASM_ARM_NAME_LDRSW || instruction->name_id == CDISASM_ARM_NAME_LDURSB ||
             instruction->name_id == CDISASM_ARM_NAME_LDURSH || instruction->name_id == CDISASM_ARM_NAME_LDURSW ||
             instruction->name_id == CDISASM_ARM_NAME_LDRSBT || instruction->name_id == CDISASM_ARM_NAME_LDRSHT)) {
            value = xxemul_sign_extend(value, size);
        }
        if (status == XXEMUL_STATUS_OK) {
            status = xxemul_arm_write_register(emulator, register_operand->reg, value);
        }
    } else {
        status = xxemul_arm_read_operand(emulator, register_operand, current_pc, &value);
        if (status == XXEMUL_STATUS_OK) {
            status = xxemul_arm_guest_store_integer(emulator, address, size, value);
        }
    }
    if (status == XXEMUL_STATUS_OK && has_writeback) {
        status = xxemul_arm_write_register(emulator, memory_operand->base_reg, writeback);
    }
    return status;
}

static xxemul_status xxemul_arm_branch_target(xxemul *emulator, const cdisasm_arm_instruction *instruction, uint64_t current_pc, uint64_t *target)
{
    if (target == NULL) {
        return XXEMUL_STATUS_INVALID_ARGUMENT;
    }
    if (instruction->operand_count == 0u) {
        *target = instruction->branch_target;
        return XXEMUL_STATUS_OK;
    }
    return xxemul_arm_read_operand(emulator, &instruction->operand[0], current_pc, target);
}

#include "xxemul_arm_auth_exec.h"
#include "xxemul_arm_simd.h"

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
    int shift_carry_valid;
    int shift_carry;
    xxemul_status status;

    status = xxemul_arm_decode_current(emulator, &instruction);
    if (status != XXEMUL_STATUS_OK) {
        return status;
    }
    if ((instruction.instruction_flags & (CDISASM_ARM_INSTRUCTION_FLAG_ILLEGAL | CDISASM_ARM_INSTRUCTION_FLAG_UNPREDICTABLE)) != 0u) {
        return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    }
    next_pc = xxemul_arm_next_sequential(emulator, current_pc, instruction.opcode_size);
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
    if (emulator->mode == XXEMUL_MODE_ARM_A64 && xxemul_arm_auth_execute(emulator, &instruction, current_pc, &status)) {
        /* Pointer authentication uses the same decoded instruction as tracing. */
    } else if (emulator->mode == XXEMUL_MODE_ARM_A64 && xxemul_arm_simd(emulator, &instruction, current_pc, &status)) {
        /* Vector and floating-point instructions share the normal step accounting. */
    } else switch (instruction.name_id) {
        case CDISASM_ARM_NAME_NOP: status = XXEMUL_STATUS_OK; break;
        case CDISASM_ARM_NAME_SVC:
            if (emulator->linux_process != NULL && instruction.operand_count == 1u &&
                instruction.operand[0].type == CDISASM_OPERAND_IMMEDIATE && instruction.operand[0].imm == 0) {
                /* ARM EABI uses r7, AArch64 uses x8; both return in r0/x0. */
                status = xxemul_linux_dispatch(emulator->linux_process);
                if (status == XXEMUL_STATUS_HALTED) emulator->halted = 1;
            } else {
                status = emulator->mode == XXEMUL_MODE_ARM_A64 && emulator->darwin != NULL &&
                         instruction.operand_count == 1u && instruction.operand[0].type == CDISASM_OPERAND_IMMEDIATE
                             ? xxemul_darwin_handle_svc(emulator->darwin, instruction.operand[0].imm)
                             : XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
            }
            break;
        case CDISASM_ARM_NAME_BKPT:
        case CDISASM_ARM_NAME_BRK:
            emulator->halted = 1;
            status = XXEMUL_STATUS_HALTED;
            break;
        case CDISASM_ARM_NAME_MOV:
        case CDISASM_ARM_NAME_MOVS:
        case CDISASM_ARM_NAME_MOVZ:
            if (instruction.operand_count < 2u) {
                status = XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
                break;
            }
            /* PC is an architectural operand: A32 reads current_pc + 8,
             * including MOV LR,PC used before an indirect BX call. */
            status = xxemul_arm_read_data_operand(emulator, &instruction, 1u, current_pc, &value, &shift_carry_valid, &shift_carry);
            if (status == XXEMUL_STATUS_OK) {
                status = xxemul_arm_write_register(emulator, instruction.operand[0].reg, value);
            }
            if (status == XXEMUL_STATUS_OK && instruction.name_id == CDISASM_ARM_NAME_MOVS) {
                size = instruction.operand[0].size == 0u ? 4u : instruction.operand[0].size;
                xxemul_arm_set_nz(emulator, value, size);
                if (shift_carry_valid) {
                    emulator->arm.pstate &= ~XXEMUL_ARM_FLAG_C;
                    if (shift_carry) emulator->arm.pstate |= XXEMUL_ARM_FLAG_C;
                }
            }
            break;
        case CDISASM_ARM_NAME_MVN:
        case CDISASM_ARM_NAME_MVNS:
            if (instruction.operand_count < 2u) {
                status = XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
                break;
            }
            size = instruction.operand[0].size == 0u ? (emulator->mode == XXEMUL_MODE_ARM_A64 ? 8u : 4u) : instruction.operand[0].size;
            status = xxemul_arm_read_data_operand(emulator, &instruction, 1u, current_pc, &value, &shift_carry_valid, &shift_carry);
            if (status == XXEMUL_STATUS_OK) {
                value = (~value) & xxemul_mask_for_size(size);
                status = xxemul_arm_write_register(emulator, instruction.operand[0].reg, value);
                if (status == XXEMUL_STATUS_OK && (instruction.instruction_flags & CDISASM_ARM_INSTRUCTION_FLAG_SETS_FLAGS) != 0u) {
                    xxemul_arm_set_logic_flags(emulator, value, size, shift_carry_valid, shift_carry);
                }
            }
            break;
        case CDISASM_ARM_NAME_MOVN:
            if (instruction.operand_count < 2u) {
                status = XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
                break;
            }
            size = instruction.operand[0].size == 0u ? 8u : instruction.operand[0].size;
            status = xxemul_arm_read_operand(emulator, &instruction.operand[1], current_pc, &value);
            if (status == XXEMUL_STATUS_OK) {
                status = xxemul_arm_write_register(emulator, instruction.operand[0].reg, (~value) & xxemul_mask_for_size(size));
            }
            break;
        case CDISASM_ARM_NAME_MOVK:
            if (instruction.operand_count < 2u) {
                status = XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
                break;
            }
            status = xxemul_arm_read_register(emulator, instruction.operand[0].reg, current_pc, &old_value, &size);
            if (status == XXEMUL_STATUS_OK) {
                uint8_t shift = instruction.operand[1].shift_amount;
                value = instruction.operand[1].imm & (UINT64_C(0xffff) << shift);
                mask = UINT64_C(0xffff) << shift;
                status = xxemul_arm_write_register(emulator, instruction.operand[0].reg, (old_value & ~mask) | value);
            }
            break;
        case CDISASM_ARM_NAME_MOVW:
        case CDISASM_ARM_NAME_MOVT:
            if (instruction.operand_count < 2u) {
                status = XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
                break;
            }
            status = xxemul_arm_read_register(emulator, instruction.operand[0].reg, current_pc, &old_value, NULL);
            if (status == XXEMUL_STATUS_OK) {
                value = instruction.operand[1].imm & UINT16_MAX;
                value = instruction.name_id == CDISASM_ARM_NAME_MOVT ? ((old_value & UINT16_MAX) | (value << 16u)) : value;
                status = xxemul_arm_write_register(emulator, instruction.operand[0].reg, value);
            }
            break;
        case CDISASM_ARM_NAME_ADR:
        case CDISASM_ARM_NAME_ADRP:
            if (instruction.operand_count < 2u) {
                status = XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
                break;
            }
            status = xxemul_arm_read_operand(emulator, &instruction.operand[1], current_pc, &value);
            if (status == XXEMUL_STATUS_OK) status = xxemul_arm_write_register(emulator, instruction.operand[0].reg, value);
            break;
        case CDISASM_ARM_NAME_ADD:
        case CDISASM_ARM_NAME_ADDS:
        case CDISASM_ARM_NAME_ADDPT:
        case CDISASM_ARM_NAME_SUB:
        case CDISASM_ARM_NAME_SUBS:
        case CDISASM_ARM_NAME_SUBPT:
        case CDISASM_ARM_NAME_RSB:
        case CDISASM_ARM_NAME_RSBS:
        case CDISASM_ARM_NAME_AND:
        case CDISASM_ARM_NAME_ANDS:
        case CDISASM_ARM_NAME_ORR:
        case CDISASM_ARM_NAME_ORRS:
        case CDISASM_ARM_NAME_ORN:
        case CDISASM_ARM_NAME_ORNS:
        case CDISASM_ARM_NAME_EOR:
        case CDISASM_ARM_NAME_EORS:
        case CDISASM_ARM_NAME_EON:
        case CDISASM_ARM_NAME_BIC:
        case CDISASM_ARM_NAME_BICS: status = xxemul_arm_binary(emulator, &instruction, current_pc); break;
        case CDISASM_ARM_NAME_ADC:
        case CDISASM_ARM_NAME_ADCS: status = xxemul_arm_add_with_carry(emulator, &instruction, current_pc, 0, 0); break;
        case CDISASM_ARM_NAME_SBC:
        case CDISASM_ARM_NAME_SBCS:
        case CDISASM_ARM_NAME_NGC:
        case CDISASM_ARM_NAME_NGCS: status = xxemul_arm_add_with_carry(emulator, &instruction, current_pc, 1, 0); break;
        case CDISASM_ARM_NAME_RSC:
        case CDISASM_ARM_NAME_RSCS: status = xxemul_arm_add_with_carry(emulator, &instruction, current_pc, 1, 1); break;
        case CDISASM_ARM_NAME_MUL:
        case CDISASM_ARM_NAME_MADD:
        case CDISASM_ARM_NAME_MADDPT:
        case CDISASM_ARM_NAME_MSUB:
        case CDISASM_ARM_NAME_MSUBPT:
        case CDISASM_ARM_NAME_MLA:
        case CDISASM_ARM_NAME_MLS:
        case CDISASM_ARM_NAME_MNEG: status = xxemul_arm_multiply(emulator, &instruction, current_pc); break;
        case CDISASM_ARM_NAME_UMULL: status = xxemul_arm_multiply_long(emulator, &instruction, current_pc, 0); break;
        case CDISASM_ARM_NAME_SMULL: status = xxemul_arm_multiply_long(emulator, &instruction, current_pc, 1); break;
        case CDISASM_ARM_NAME_SMMLA:
        case CDISASM_ARM_NAME_SMMLAR: status = xxemul_arm_signed_most_significant_multiply(emulator, &instruction, current_pc); break;
        case CDISASM_ARM_NAME_SMULH:
        case CDISASM_ARM_NAME_SMSUBL: status = xxemul_arm_special_multiply(emulator, &instruction, current_pc); break;
        case CDISASM_ARM_NAME_SDIV: status = xxemul_arm_divide(emulator, &instruction, current_pc, 1); break;
        case CDISASM_ARM_NAME_UDIV: status = xxemul_arm_divide(emulator, &instruction, current_pc, 0); break;
        case CDISASM_ARM_NAME_NEG:
        case CDISASM_ARM_NAME_NEGS: status = xxemul_arm_negate(emulator, &instruction, current_pc); break;
        case CDISASM_ARM_NAME_LSL:
        case CDISASM_ARM_NAME_LSLS:
        case CDISASM_ARM_NAME_LSR:
        case CDISASM_ARM_NAME_LSRS:
        case CDISASM_ARM_NAME_ASR:
        case CDISASM_ARM_NAME_ASRS:
        case CDISASM_ARM_NAME_ROR:
        case CDISASM_ARM_NAME_RORS: status = xxemul_arm_shift_instruction(emulator, &instruction, current_pc); break;
        case CDISASM_ARM_NAME_CLZ: status = xxemul_arm_count_leading_zeros(emulator, &instruction, current_pc); break;
        case CDISASM_ARM_NAME_CRC32B:
        case CDISASM_ARM_NAME_CRC32H:
        case CDISASM_ARM_NAME_CRC32W:
        case CDISASM_ARM_NAME_CRC32X:
        case CDISASM_ARM_NAME_CRC32CB:
        case CDISASM_ARM_NAME_CRC32CH:
        case CDISASM_ARM_NAME_CRC32CW:
        case CDISASM_ARM_NAME_CRC32CX: status = xxemul_arm_crc32(emulator, &instruction, current_pc); break;
        case CDISASM_ARM_NAME_SXTB:
        case CDISASM_ARM_NAME_SXTH:
        case CDISASM_ARM_NAME_SXTW:
        case CDISASM_ARM_NAME_UXTB:
        case CDISASM_ARM_NAME_UXTH:
        case CDISASM_ARM_NAME_UXTW: status = xxemul_arm_extend_instruction(emulator, &instruction, current_pc); break;
        case CDISASM_ARM_NAME_UADD8: status = xxemul_arm_uadd8(emulator, &instruction, current_pc); break;
        case CDISASM_ARM_NAME_UBFX:
        case CDISASM_ARM_NAME_SBFX:
        case CDISASM_ARM_NAME_UBFIZ:
        case CDISASM_ARM_NAME_SBFIZ:
        case CDISASM_ARM_NAME_UBFM:
        case CDISASM_ARM_NAME_SBFM:
        case CDISASM_ARM_NAME_BFM:
        case CDISASM_ARM_NAME_BFC:
        case CDISASM_ARM_NAME_BFI:
        case CDISASM_ARM_NAME_BFXIL: status = xxemul_arm_bitfield(emulator, &instruction, current_pc); break;
        case CDISASM_ARM_NAME_EXTR: status = xxemul_arm_extract_registers(emulator, &instruction, current_pc); break;
        case CDISASM_ARM_NAME_RBIT:
        case CDISASM_ARM_NAME_REV:
        case CDISASM_ARM_NAME_REV16:
        case CDISASM_ARM_NAME_REVSH: status = xxemul_arm_reverse(emulator, &instruction, current_pc); break;
        case CDISASM_ARM_NAME_CSEL:
        case CDISASM_ARM_NAME_CSINC:
        case CDISASM_ARM_NAME_CSINV:
        case CDISASM_ARM_NAME_CSNEG:
        case CDISASM_ARM_NAME_CSET:
        case CDISASM_ARM_NAME_CSETM:
        case CDISASM_ARM_NAME_CINC:
        case CDISASM_ARM_NAME_CINV:
        case CDISASM_ARM_NAME_CNEG: status = xxemul_arm_conditional_select(emulator, &instruction, current_pc); break;
        case CDISASM_ARM_NAME_CMP:
        case CDISASM_ARM_NAME_CMN:
        case CDISASM_ARM_NAME_TST: status = xxemul_arm_compare(emulator, &instruction, current_pc); break;
        case CDISASM_ARM_NAME_SUBP:
        case CDISASM_ARM_NAME_SUBPS:
        case CDISASM_ARM_NAME_CMPP: status = xxemul_arm_pointer_subtract(emulator, &instruction, current_pc); break;
        case CDISASM_ARM_NAME_SUBG: status = xxemul_arm_subtract_tagged_offset(emulator, &instruction, current_pc); break;
        case CDISASM_ARM_NAME_CCMP:
        case CDISASM_ARM_NAME_CCMN: status = xxemul_arm_conditional_compare(emulator, &instruction, current_pc); break;
        case CDISASM_ARM_NAME_LDR:
        case CDISASM_ARM_NAME_LDRB:
        case CDISASM_ARM_NAME_LDRH:
        case CDISASM_ARM_NAME_LDRSB:
        case CDISASM_ARM_NAME_LDRSH:
        case CDISASM_ARM_NAME_LDRSW:
        case CDISASM_ARM_NAME_LDRT:
        case CDISASM_ARM_NAME_LDRBT:
        case CDISASM_ARM_NAME_LDRHT:
        case CDISASM_ARM_NAME_LDRSBT:
        case CDISASM_ARM_NAME_LDRSHT:
        case CDISASM_ARM_NAME_LDUR:
        case CDISASM_ARM_NAME_LDURB:
        case CDISASM_ARM_NAME_LDURH:
        case CDISASM_ARM_NAME_LDURSB:
        case CDISASM_ARM_NAME_LDURSH:
        case CDISASM_ARM_NAME_LDURSW: status = xxemul_arm_load_store(emulator, &instruction, current_pc, 1); break;
        case CDISASM_ARM_NAME_STR:
        case CDISASM_ARM_NAME_STRB:
        case CDISASM_ARM_NAME_STRH:
        case CDISASM_ARM_NAME_STRT:
        case CDISASM_ARM_NAME_STRBT:
        case CDISASM_ARM_NAME_STRHT:
        case CDISASM_ARM_NAME_STUR:
        case CDISASM_ARM_NAME_STURB:
        case CDISASM_ARM_NAME_STURH: status = xxemul_arm_load_store(emulator, &instruction, current_pc, 0); break;
        case CDISASM_ARM_NAME_LDM:
        case CDISASM_ARM_NAME_LDMIB:
        case CDISASM_ARM_NAME_LDMDA:
        case CDISASM_ARM_NAME_LDMDB:
        case CDISASM_ARM_NAME_POP: status = xxemul_arm_multiple_transfer(emulator, &instruction, current_pc, 1); break;
        case CDISASM_ARM_NAME_STM:
        case CDISASM_ARM_NAME_STMIB:
        case CDISASM_ARM_NAME_STMDA:
        case CDISASM_ARM_NAME_STMDB:
        case CDISASM_ARM_NAME_PUSH: status = xxemul_arm_multiple_transfer(emulator, &instruction, current_pc, 0); break;
        case CDISASM_ARM_NAME_LDP: status = xxemul_arm_pair_transfer(emulator, &instruction, current_pc, 1); break;
        case CDISASM_ARM_NAME_STP: status = xxemul_arm_pair_transfer(emulator, &instruction, current_pc, 0); break;
        case CDISASM_ARM_NAME_LDRD: status = xxemul_arm_pair_transfer(emulator, &instruction, current_pc, 1); break;
        case CDISASM_ARM_NAME_STRD: status = xxemul_arm_pair_transfer(emulator, &instruction, current_pc, 0); break;
        case CDISASM_ARM_NAME_CBZ:
        case CDISASM_ARM_NAME_CBNZ:
        case CDISASM_ARM_NAME_TBZ:
        case CDISASM_ARM_NAME_TBNZ:
        {
            int bit_test = instruction.name_id == CDISASM_ARM_NAME_TBZ || instruction.name_id == CDISASM_ARM_NAME_TBNZ;
            int branch_nonzero = instruction.name_id == CDISASM_ARM_NAME_CBNZ || instruction.name_id == CDISASM_ARM_NAME_TBNZ;
            unsigned target_index = bit_test ? 2u : 1u;
            if (instruction.operand_count <= target_index) {
                status = XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
                break;
            }
            status = xxemul_arm_read_operand(emulator, &instruction.operand[0], current_pc, &value);
            if (status != XXEMUL_STATUS_OK) break;
            if (bit_test) {
                uint64_t bit;
                status = xxemul_arm_read_operand(emulator, &instruction.operand[1], current_pc, &bit);
                if (status != XXEMUL_STATUS_OK) break;
                if (bit >= 64u) {
                    status = XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
                    break;
                }
                value &= UINT64_C(1) << bit;
            }
            if ((value != 0u) == branch_nonzero) {
                status = xxemul_arm_read_operand(emulator, &instruction.operand[target_index], current_pc, &target);
                if (status == XXEMUL_STATUS_OK) {
                    emulator->arm.pc = xxemul_arm_align_pc(emulator, target & xxemul_arm_address_mask(emulator));
                }
            }
            break;
        }
        case CDISASM_ARM_NAME_B:
            status = xxemul_arm_branch_target(emulator, &instruction, current_pc, &target);
            if (status == XXEMUL_STATUS_OK) {
                emulator->arm.pc = xxemul_arm_align_pc(emulator, target);
            }
            break;
        case CDISASM_ARM_NAME_BL:
            status = xxemul_arm_branch_target(emulator, &instruction, current_pc, &target);
            if (status == XXEMUL_STATUS_OK) {
                emulator->arm.gpr[emulator->mode == XXEMUL_MODE_ARM_A64 ? 30u : 14u] = next_pc;
                emulator->arm.pc = xxemul_arm_align_pc(emulator, target);
            }
            break;
        case CDISASM_ARM_NAME_BR:
            status = xxemul_arm_branch_target(emulator, &instruction, current_pc, &target);
            if (status == XXEMUL_STATUS_OK) {
                emulator->arm.pc = xxemul_arm_align_pc(emulator, target);
            }
            break;
        case CDISASM_ARM_NAME_BX:
        case CDISASM_ARM_NAME_BLX:
            if (emulator->mode == XXEMUL_MODE_ARM_A64) {
                status = XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
                break;
            }
            status = xxemul_arm_branch_target(emulator, &instruction, current_pc, &target);
            if (status == XXEMUL_STATUS_OK) {
                uint64_t return_address = next_pc | (emulator->mode == XXEMUL_MODE_ARM_T32 ? 1u : 0u);
                if (instruction.name_id == CDISASM_ARM_NAME_BLX && (instruction.operand_count == 0u || instruction.operand[0].type != CDISASM_OPERAND_REGISTER)) {
                    /* Immediate BLX always enters the opposite instruction set. */
                    target = emulator->mode == XXEMUL_MODE_ARM_A32 ? target | UINT64_C(1) : target & ~UINT64_C(1);
                }
                status = xxemul_arm_branch_exchange(emulator, target);
                if (status == XXEMUL_STATUS_OK && instruction.name_id == CDISASM_ARM_NAME_BLX) {
                    emulator->arm.gpr[14] = return_address;
                }
            }
            break;
        case CDISASM_ARM_NAME_BLR:
            status = xxemul_arm_branch_target(emulator, &instruction, current_pc, &target);
            if (status == XXEMUL_STATUS_OK) {
                emulator->arm.gpr[30] = next_pc;
                emulator->arm.pc = xxemul_arm_align_pc(emulator, target);
            }
            break;
        case CDISASM_ARM_NAME_RET:
            if (instruction.operand_count > 0u) {
                status = xxemul_arm_branch_target(emulator, &instruction, current_pc, &target);
            } else {
                target = emulator->arm.gpr[30];
                status = XXEMUL_STATUS_OK;
            }
            if (status == XXEMUL_STATUS_OK) {
                emulator->arm.pc = xxemul_arm_align_pc(emulator, target);
            }
            break;
        default: status = XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION; break;
    }

    if (status != XXEMUL_STATUS_OK && status != XXEMUL_STATUS_HALTED) {
        emulator->arm.pc = current_pc;
    } else if (info != NULL) {
        info->next_address = emulator->arm.pc;
    }
    return status;
}

size_t xxemul_arm_format_current(xxemul *emulator, char *buffer, size_t buffer_size)
{
    cdisasm_arm_instruction instruction;

    if (xxemul_arm_decode_current(emulator, &instruction) != XXEMUL_STATUS_OK) {
        if (buffer != NULL && buffer_size > 0u) {
            buffer[0] = '\0';
        }
        return 0u;
    }
    return cdisasm_arm_format(&instruction, CDISASM_FORMAT_SYNTAX_ARM_CANONICAL, buffer, buffer_size);
}
