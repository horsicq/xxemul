#ifndef XXEMUL_ARM_AUTH_EXEC_H
#define XXEMUL_ARM_AUTH_EXEC_H

/* Included by xxemul_arm.c after its register helpers. cdisasm supplies the
 * mnemonic and explicit operands; only architecturally implicit registers
 * are selected here. No instruction bytes are decoded by this executor. */
static int xxemul_arm_auth_register_operand(const cdisasm_arm_operand *operand,
                                           cdisasm_arm_reg_id register_31)
{
    return operand->type == CDISASM_OPERAND_REGISTER && operand->size == 8u &&
           operand->shift_type == CDISASM_ARM_SHIFT_NONE &&
           operand->extend_type == CDISASM_ARM_EXTEND_NONE &&
           ((operand->reg >= CDISASM_ARM_REG_X0 && operand->reg <= CDISASM_ARM_REG_X30) ||
            operand->reg == register_31);
}

static int xxemul_arm_auth_execute(xxemul *emulator, const cdisasm_arm_instruction *instruction,
                                   uint64_t current_pc, xxemul_status *status)
{
    cdisasm_arm_reg_id destination = CDISASM_ARM_REG_X30;
    cdisasm_arm_reg_id modifier_register = CDISASM_ARM_REG_NONE;
    uint64_t pointer, modifier = 0u, value;
    unsigned key = 0u, operand_count = 0u;
    int authenticate = 0, strip = 0, branch = 0, link = 0;

    /* Software keys: 0 = IA, 1 = IB, 2 = DA, 3 = DB. Keep the distinct
     * zero-modifier mnemonics so step metadata agrees with disassembly. */
    switch (instruction->name_id) {
        case CDISASM_ARM_NAME_PACIA: operand_count = 2u; break;
        case CDISASM_ARM_NAME_PACIB: operand_count = 2u; key = 1u; break;
        case CDISASM_ARM_NAME_PACDA: operand_count = 2u; key = 2u; break;
        case CDISASM_ARM_NAME_PACDB: operand_count = 2u; key = 3u; break;
        case CDISASM_ARM_NAME_AUTIA: operand_count = 2u; authenticate = 1; break;
        case CDISASM_ARM_NAME_AUTIB: operand_count = 2u; authenticate = 1; key = 1u; break;
        case CDISASM_ARM_NAME_AUTDA: operand_count = 2u; authenticate = 1; key = 2u; break;
        case CDISASM_ARM_NAME_AUTDB: operand_count = 2u; authenticate = 1; key = 3u; break;
        case CDISASM_ARM_NAME_PACIZA: operand_count = 1u; break;
        case CDISASM_ARM_NAME_PACIZB: operand_count = 1u; key = 1u; break;
        case CDISASM_ARM_NAME_PACDZA: operand_count = 1u; key = 2u; break;
        case CDISASM_ARM_NAME_PACDZB: operand_count = 1u; key = 3u; break;
        case CDISASM_ARM_NAME_AUTIZA: operand_count = 1u; authenticate = 1; break;
        case CDISASM_ARM_NAME_AUTIZB: operand_count = 1u; authenticate = 1; key = 1u; break;
        case CDISASM_ARM_NAME_AUTDZA: operand_count = 1u; authenticate = 1; key = 2u; break;
        case CDISASM_ARM_NAME_AUTDZB: operand_count = 1u; authenticate = 1; key = 3u; break;
        case CDISASM_ARM_NAME_XPACI:
        case CDISASM_ARM_NAME_XPACD: operand_count = 1u; strip = 1; break;
        case CDISASM_ARM_NAME_XPACLRI: strip = 1; break;
        case CDISASM_ARM_NAME_PACIA1716:
            destination = CDISASM_ARM_REG_X17; modifier_register = CDISASM_ARM_REG_X16; break;
        case CDISASM_ARM_NAME_PACIB1716:
            destination = CDISASM_ARM_REG_X17; modifier_register = CDISASM_ARM_REG_X16; key = 1u; break;
        case CDISASM_ARM_NAME_AUTIA1716:
            destination = CDISASM_ARM_REG_X17; modifier_register = CDISASM_ARM_REG_X16; authenticate = 1; break;
        case CDISASM_ARM_NAME_AUTIB1716:
            destination = CDISASM_ARM_REG_X17; modifier_register = CDISASM_ARM_REG_X16; authenticate = 1; key = 1u; break;
        case CDISASM_ARM_NAME_PACIAZ: break;
        case CDISASM_ARM_NAME_PACIBZ: key = 1u; break;
        case CDISASM_ARM_NAME_AUTIAZ: authenticate = 1; break;
        case CDISASM_ARM_NAME_AUTIBZ: authenticate = 1; key = 1u; break;
        case CDISASM_ARM_NAME_PACIASP: modifier_register = CDISASM_ARM_REG_SP; break;
        case CDISASM_ARM_NAME_PACIBSP: modifier_register = CDISASM_ARM_REG_SP; key = 1u; break;
        case CDISASM_ARM_NAME_AUTIASP: modifier_register = CDISASM_ARM_REG_SP; authenticate = 1; break;
        case CDISASM_ARM_NAME_AUTIBSP: modifier_register = CDISASM_ARM_REG_SP; authenticate = 1; key = 1u; break;
        case CDISASM_ARM_NAME_RETAA:
            modifier_register = CDISASM_ARM_REG_SP; authenticate = 1; branch = 1; break;
        case CDISASM_ARM_NAME_RETAB:
            modifier_register = CDISASM_ARM_REG_SP; authenticate = 1; branch = 1; key = 1u; break;
        case CDISASM_ARM_NAME_BRAA: operand_count = 2u; authenticate = 1; branch = 1; break;
        case CDISASM_ARM_NAME_BRAB: operand_count = 2u; authenticate = 1; branch = 1; key = 1u; break;
        case CDISASM_ARM_NAME_BLRAA: operand_count = 2u; authenticate = 1; branch = 1; link = 1; break;
        case CDISASM_ARM_NAME_BLRAB: operand_count = 2u; authenticate = 1; branch = 1; link = 1; key = 1u; break;
        case CDISASM_ARM_NAME_BRAAZ: operand_count = 1u; authenticate = 1; branch = 1; break;
        case CDISASM_ARM_NAME_BRABZ: operand_count = 1u; authenticate = 1; branch = 1; key = 1u; break;
        case CDISASM_ARM_NAME_BLRAAZ: operand_count = 1u; authenticate = 1; branch = 1; link = 1; break;
        case CDISASM_ARM_NAME_BLRABZ: operand_count = 1u; authenticate = 1; branch = 1; link = 1; key = 1u; break;
        default:
            /* Decoding a PAuth instruction does not imply execution support
             * for PACGA, authenticated loads, exception returns or PAuth_LR. */
            if (!(instruction->instruction_flags & CDISASM_ARM_INSTRUCTION_FLAG_POINTER_AUTH)) return 0;
            *status = XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
            return 1;
    }

    *status = XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    if (instruction->opcode_size != 4u || instruction->operand_count != operand_count ||
        (instruction->instruction_flags & CDISASM_ARM_INSTRUCTION_FLAG_OPERANDS_OPAQUE)) return 1;
    if (current_pc & 3u) {
        *status = XXEMUL_STATUS_ADDRESS_FAULT;
        return 1;
    }
    if (operand_count > 0u) {
        if (!xxemul_arm_auth_register_operand(&instruction->operand[0], CDISASM_ARM_REG_XZR)) return 1;
        destination = instruction->operand[0].reg;
    }
    if (operand_count == 2u) {
        if (!xxemul_arm_auth_register_operand(&instruction->operand[1], CDISASM_ARM_REG_SP)) return 1;
        modifier_register = instruction->operand[1].reg;
    }
    *status = xxemul_arm_read_register(emulator, destination, current_pc, &pointer, NULL);
    if (*status != XXEMUL_STATUS_OK) return 1;
    if (modifier_register != CDISASM_ARM_REG_NONE) {
        *status = xxemul_arm_read_register(emulator, modifier_register, current_pc, &modifier, NULL);
        if (*status != XXEMUL_STATUS_OK) return 1;
    }
    if (strip) value = xxemul_arm_auth_strip(pointer);
    else if (authenticate) *status = xxemul_arm_auth_check(emulator, pointer, modifier, key, &value);
    else *status = xxemul_arm_auth_sign(emulator, pointer, modifier, key, &value);
    if (*status == XXEMUL_STATUS_OK && branch && (value & 3u)) *status = XXEMUL_STATUS_ADDRESS_FAULT;
    if (*status != XXEMUL_STATUS_OK) return 1;

    /* Commit only after authentication and alignment succeed. The caller
     * handles sequential PC, fault rollback and cdisasm step metadata. */
    if (branch) {
        if (link) emulator->arm.gpr[30] = current_pc + instruction->opcode_size;
        emulator->arm.pc = value;
    } else {
        *status = xxemul_arm_write_register(emulator, destination, value);
    }
    return 1;
}

#endif
