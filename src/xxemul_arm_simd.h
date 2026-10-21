/* A64 vector register and instruction helpers. Included after scalar helpers. */
#ifndef XXEMUL_ARM_SIMD_H
#define XXEMUL_ARM_SIMD_H

static int arm_vector_index(cdisasm_arm_reg_id reg)
{
    if (reg >= CDISASM_ARM_REG_V0 && reg <= CDISASM_ARM_REG_V31) return reg - CDISASM_ARM_REG_V0;
    if (reg >= CDISASM_ARM_REG_D0 && reg <= CDISASM_ARM_REG_D31) return reg - CDISASM_ARM_REG_D0;
    if (reg >= CDISASM_ARM_REG_Q0 && reg <= CDISASM_ARM_REG_Q15) return reg - CDISASM_ARM_REG_Q0;
    if (reg >= CDISASM_ARM_REG_Q16 && reg <= CDISASM_ARM_REG_Q31) return reg - CDISASM_ARM_REG_Q16 + 16;
    if (reg >= CDISASM_ARM_REG_S0 && reg <= CDISASM_ARM_REG_S31) return reg - CDISASM_ARM_REG_S0;
    if (reg >= CDISASM_ARM_REG_H0 && reg <= CDISASM_ARM_REG_H31) return reg - CDISASM_ARM_REG_H0;
    if (reg >= CDISASM_ARM_REG_B0 && reg <= CDISASM_ARM_REG_B31) return reg - CDISASM_ARM_REG_B0;
    return -1;
}

static uint64_t arm_vector_lane(const uint8_t *bytes, unsigned offset, unsigned size)
{
    uint64_t value = 0;
    unsigned i;
    for (i = 0; i < size; ++i) value |= (uint64_t)bytes[offset + i] << (i * 8u);
    return value;
}

static void arm_vector_put(uint8_t *bytes, unsigned offset, unsigned size, uint64_t value)
{
    unsigned i;
    for (i = 0; i < size; ++i) bytes[offset + i] = (uint8_t)(value >> (i * 8u));
}

static int arm_vector_operand(xxemul *e, const cdisasm_arm_operand *o, uint64_t pc, uint64_t *value)
{
    int index = arm_vector_index(o->reg);
    unsigned size = CDISASM_ARM_VECTOR_ELEMENT_SIZE(o);
    unsigned offset = 0;
    if (o->type != CDISASM_OPERAND_REGISTER || index < 0)
        return xxemul_arm_read_operand(e, o, pc, value) == XXEMUL_STATUS_OK;
    if (size == 0 || size > 8) size = o->size;
    if (o->flags & CDISASM_ARM_OPERAND_FLAG_HAS_LANE) {
        if (size == 0 || size > 8 || o->imm >= 16u / size) return 0;
        offset = (unsigned)o->imm * size;
    }
    if (size == 0 || size > 8 || offset + size > 16) return 0;
    *value = arm_vector_lane(e->arm.v[index], offset, size);
    return 1;
}

static xxemul_status arm_vector_memory(xxemul *e, const cdisasm_arm_instruction *in, uint64_t pc)
{
    int pair = in->name_id == CDISASM_ARM_NAME_LDP || in->name_id == CDISASM_ARM_NAME_STP;
    int load = in->name_id == CDISASM_ARM_NAME_LDP || in->name_id == CDISASM_ARM_NAME_LDR || in->name_id == CDISASM_ARM_NAME_LDUR;
    const cdisasm_arm_operand *memory = &in->operand[pair ? 2 : 1];
    uint64_t address, writeback;
    int has_writeback, index = arm_vector_index(in->operand[0].reg);
    unsigned size = in->operand[0].size, count = pair ? 2 : 1, n;
    uint8_t bytes[32];
    xxemul_status status;
    if (index < 0 || size == 0 || size > 16 || (memory->type != CDISASM_OPERAND_MEMORY &&
        !(load && !pair && xxemul_arm_literal_operand(e, in, memory)))) return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    status = xxemul_arm_memory_address(e, in, memory, pc, &address, &writeback, &has_writeback);
    if (status != XXEMUL_STATUS_OK) return status;
    if (load) {
        status = xxemul_read_memory(e, address, bytes, size * count);
        if (status != XXEMUL_STATUS_OK) return status;
    }
    for (n = 0; n < count; ++n) {
        index = arm_vector_index(in->operand[n].reg);
        if (index < 0) return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
        if (load) {
            memset(e->arm.v[index], 0, 16);
            memcpy(e->arm.v[index], bytes + n * size, size);
        } else memcpy(bytes + n * size, e->arm.v[index], size);
    }
    if (!load) status = xxemul_write_memory(e, address, bytes, size * count);
    if (status == XXEMUL_STATUS_OK && has_writeback) status = xxemul_arm_write_register(e, memory->base_reg, writeback);
    return status;
}

static int xxemul_arm_simd(xxemul *e, const cdisasm_arm_instruction *in, uint64_t pc, xxemul_status *status)
{
    unsigned name = in->name_id, count = in->operand_count, i, size, total;
    int dest = count ? arm_vector_index(in->operand[0].reg) : -1;
    int left = count > 1 ? arm_vector_index(in->operand[1].reg) : -1;
    int right = count > 2 ? arm_vector_index(in->operand[2].reg) : -1;
    uint8_t result[16] = {0};
    uint64_t value, a, b;
    *status = XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    if (dest < 0 && (name == CDISASM_ARM_NAME_UMULH || name == CDISASM_ARM_NAME_SMULL || name == CDISASM_ARM_NAME_UMULL ||
        name == CDISASM_ARM_NAME_SMADDL || name == CDISASM_ARM_NAME_UMADDL)) {
        uint64_t addend = 0;
        if (count < 3 || !arm_vector_operand(e,&in->operand[1],pc,&a) || !arm_vector_operand(e,&in->operand[2],pc,&b)) return 1;
        if (name == CDISASM_ARM_NAME_UMULH) value = xxemul_arm_unsigned_multiply_high(a,b);
        else {
            if (count > 3 && !arm_vector_operand(e,&in->operand[3],pc,&addend)) return 1;
            value = (name == CDISASM_ARM_NAME_SMULL || name == CDISASM_ARM_NAME_SMADDL)
                ? (uint64_t)((int64_t)(int32_t)(uint32_t)a * (int64_t)(int32_t)(uint32_t)b)
                : (uint64_t)(uint32_t)a * (uint64_t)(uint32_t)b;
            value += addend;
        }
        *status=xxemul_arm_write_register(e,in->operand[0].reg,value); return 1;
    }
    if (name == CDISASM_ARM_NAME_LDPSW) {
        uint64_t address, writeback; int has_writeback;
        *status=xxemul_arm_memory_address(e,in,&in->operand[2],pc,&address,&writeback,&has_writeback);
        if(*status!=XXEMUL_STATUS_OK)return 1;
        *status=xxemul_load_integer(e,address,4,&a);if(*status!=XXEMUL_STATUS_OK)return 1;
        *status=xxemul_load_integer(e,address+4,4,&b);if(*status!=XXEMUL_STATUS_OK)return 1;
        *status=xxemul_arm_write_register(e,in->operand[0].reg,xxemul_sign_extend(a,4));
        if(*status==XXEMUL_STATUS_OK)*status=xxemul_arm_write_register(e,in->operand[1].reg,xxemul_sign_extend(b,4));
        if(*status==XXEMUL_STATUS_OK && has_writeback)*status=xxemul_arm_write_register(e,in->operand[2].base_reg,writeback);
        return 1;
    }
    if (name == CDISASM_ARM_NAME_MRS || name == CDISASM_ARM_NAME_MSR) {
        unsigned register_index = name == CDISASM_ARM_NAME_MRS ? 0u : 1u;
        unsigned system_index = 1u - register_index;
        const cdisasm_arm_operand *reg = &in->operand[register_index];
        const cdisasm_arm_operand *system = &in->operand[system_index];
        if (count != 2u || system->type != CDISASM_ARM_OPERAND_SYSTEM_REGISTER ||
            reg->type != CDISASM_OPERAND_REGISTER || reg->size != 8u ||
            !((reg->reg >= CDISASM_ARM_REG_X0 && reg->reg <= CDISASM_ARM_REG_X30) || reg->reg == CDISASM_ARM_REG_XZR)) return 1;
        /* CTR_EL0 (S3_3_C0_C0_1): model 64-byte instruction/data cache lines.
         * The interpreter has coherent memory, but reports IDC/DIC clear so
         * guest cache-maintenance loops still execute their normal path. */
        if (system->imm == UINT64_C(0xd801) && name == CDISASM_ARM_NAME_MRS) {
            *status = xxemul_arm_write_register(e, reg->reg, UINT64_C(0x8004c004));
            return 1;
        }
        /* cdisasm's packed system-register operand for NZCV (S3_3_C4_C2_0). */
        if (system->imm != UINT64_C(0xda10)) return 1;
        if (name == CDISASM_ARM_NAME_MRS) {
            *status = xxemul_arm_write_register(e, reg->reg, e->arm.pstate & UINT32_C(0xf0000000));
        } else {
            *status = xxemul_arm_read_register(e, reg->reg, pc, &value, NULL);
            if (*status == XXEMUL_STATUS_OK)
                e->arm.pstate = (e->arm.pstate & ~UINT32_C(0xf0000000)) | ((uint32_t)value & UINT32_C(0xf0000000));
        }
        return 1;
    }
    if (name == CDISASM_ARM_NAME_SYS) {
        const cdisasm_arm_operand *operation = &in->operand[0];
        uint8_t byte;
        /* SYS #3,C7,C11,#1 = DC CVAU; SYS #3,C7,C5,#1 = IC IVAU.
         * Only these user cache operations are modeled. ARM instructions are
         * decoded from current memory on each step, so stores are already
         * visible to instruction fetch. Still validate the target address. */
        if ((count != 1u && count != 2u) || operation->type != CDISASM_ARM_OPERAND_SYSTEM_OPERATION ||
            (operation->imm != UINT64_C(0x1bd9) && operation->imm != UINT64_C(0x1ba9))) return 1;
        value = 0; /* The decoder omits the optional XZR operand. */
        if (count == 2u) {
            if (in->operand[1].type != CDISASM_OPERAND_REGISTER || in->operand[1].size != 8u ||
                !((in->operand[1].reg >= CDISASM_ARM_REG_X0 && in->operand[1].reg <= CDISASM_ARM_REG_X30) ||
                  in->operand[1].reg == CDISASM_ARM_REG_XZR)) return 1;
            *status = xxemul_arm_read_register(e, in->operand[1].reg, pc, &value, NULL);
            if (*status != XXEMUL_STATUS_OK) return 1;
        }
        *status = xxemul_read_memory(e, value, &byte, 1u);
        return 1;
    }
    if (name == CDISASM_ARM_NAME_DMB || name == CDISASM_ARM_NAME_DSB || name == CDISASM_ARM_NAME_ISB) {
        /* A single interpreter executes memory accesses in order and retains
         * no ARM instruction cache, so completion is immediate. */
        if (count > 1u || (count == 1u &&
            (in->operand[0].type != CDISASM_OPERAND_IMMEDIATE || in->operand[0].imm > 15u))) return 1;
        *status = XXEMUL_STATUS_OK;
        return 1;
    }
    if (dest < 0 && left < 0 && right < 0) return 0;
    if (name == CDISASM_ARM_NAME_LDR || name == CDISASM_ARM_NAME_STR || name == CDISASM_ARM_NAME_LDUR || name == CDISASM_ARM_NAME_STUR ||
        name == CDISASM_ARM_NAME_LDP || name == CDISASM_ARM_NAME_STP) {
        *status = arm_vector_memory(e, in, pc); return 1;
    }
    if (name == CDISASM_ARM_NAME_FCMP) {
        double x, y;
        if (left < 0 || dest < 0) return 1;
        if (in->operand[0].size == 4) { float f, g; memcpy(&f,e->arm.v[dest],4); memcpy(&g,e->arm.v[left],4); x=f; y=g; }
        else { memcpy(&x,e->arm.v[dest],8); memcpy(&y,e->arm.v[left],8); }
        e->arm.pstate = (e->arm.pstate & UINT32_C(0x0fffffff)) |
            (x != x || y != y ? UINT32_C(0x30000000) : x == y ? UINT32_C(0x60000000) : x < y ? UINT32_C(0x80000000) : UINT32_C(0x20000000));
        *status=XXEMUL_STATUS_OK; return 1;
    }
    if (name == CDISASM_ARM_NAME_FCVT && dest >= 0 && left >= 0) {
        if (in->operand[0].size == 8 && in->operand[1].size == 4) { float f; double d; memcpy(&f,e->arm.v[left],4); d=f; memcpy(result,&d,8); }
        else if (in->operand[0].size == 4 && in->operand[1].size == 8) { double d; float f; memcpy(&d,e->arm.v[left],8); f=(float)d; memcpy(result,&f,4); }
        else return 1;
        memcpy(e->arm.v[dest],result,16); *status=XXEMUL_STATUS_OK; return 1;
    }
    if (dest < 0) {
        if ((name == CDISASM_ARM_NAME_FMOV || name == CDISASM_ARM_NAME_UMOV || name == CDISASM_ARM_NAME_SMOV) &&
            arm_vector_operand(e,&in->operand[1],pc,&value)) {
            if (name == CDISASM_ARM_NAME_SMOV) value=xxemul_sign_extend(value,CDISASM_ARM_VECTOR_ELEMENT_SIZE(&in->operand[1]));
            *status=xxemul_arm_write_register(e,in->operand[0].reg,value);
        }
        return 1;
    }
    total=in->operand[0].size;
    size=CDISASM_ARM_VECTOR_ELEMENT_SIZE(&in->operand[0]);
    if (!(in->instruction_flags & CDISASM_ARM_INSTRUCTION_FLAG_SIMD) || size==0) size=total;
    if (total==0 || total>16 || size==0 || size>8 || total%size) return 1;
    if (name == CDISASM_ARM_NAME_INS || ((name == CDISASM_ARM_NAME_FMOV || name == CDISASM_ARM_NAME_MOV) &&
        (in->operand[0].flags & CDISASM_ARM_OPERAND_FLAG_HAS_LANE))) {
        unsigned offset=(unsigned)in->operand[0].imm*size;
        if (in->operand[0].imm>=16u/size || !arm_vector_operand(e,&in->operand[1],pc,&value)) return 1;
        arm_vector_put(e->arm.v[dest],offset,size,value); *status=XXEMUL_STATUS_OK; return 1;
    }
    if (name == CDISASM_ARM_NAME_MOVI || name == CDISASM_ARM_NAME_MVNI || name == CDISASM_ARM_NAME_DUP || name == CDISASM_ARM_NAME_FMOV) {
        if (!arm_vector_operand(e,&in->operand[1],pc,&value)) return 1;
        if (name == CDISASM_ARM_NAME_MVNI) value=~value;
        for (i=0;i<total;i+=size) arm_vector_put(result,i,size,value);
    } else if (name == CDISASM_ARM_NAME_EXT && left>=0 && right>=0 && count>=4) {
        uint8_t both[32]; unsigned offset=(unsigned)in->operand[3].imm;
        if (offset>=total) return 1;
        memcpy(both,e->arm.v[left],total); memcpy(both+total,e->arm.v[right],total); memcpy(result,both+offset,total);
    } else if ((name == CDISASM_ARM_NAME_USHLL || name == CDISASM_ARM_NAME_SSHLL ||
                name == CDISASM_ARM_NAME_UXTL || name == CDISASM_ARM_NAME_SXTL) && left>=0 && count>=2) {
        unsigned source_size=size/2, source_total=in->operand[1].size, offset;
        unsigned shift=count>=3?(unsigned)in->operand[2].imm:0u;
        if (!source_size || total!=16u || (source_total!=8u && source_total!=16u) ||
            CDISASM_ARM_VECTOR_ELEMENT_SIZE(&in->operand[1])!=source_size || shift>=size*8) return 1;
        /* The decoded source arrangement selects the low or high 64 bits. */
        offset=source_total-8u;
        for(i=0;i<total;i+=size) {
            value=arm_vector_lane(e->arm.v[left],offset+i/2,source_size);
            if(name==CDISASM_ARM_NAME_SSHLL || name==CDISASM_ARM_NAME_SXTL) value=xxemul_sign_extend(value,(uint8_t)source_size);
            arm_vector_put(result,i,size,value<<shift);
        }
    } else if (name==CDISASM_ARM_NAME_ADDP && left>=0) {
        unsigned source_total=in->operand[1].size;
        if(count==2 && source_total==2*size) arm_vector_put(result,0,size,arm_vector_lane(e->arm.v[left],0,size)+arm_vector_lane(e->arm.v[left],size,size));
        else if(right>=0) for(i=0;i<total;i+=size) {
            const uint8_t *source=i<total/2?e->arm.v[left]:e->arm.v[right];
            unsigned offset=(i%(total/2))*2;
            arm_vector_put(result,i,size,arm_vector_lane(source,offset,size)+arm_vector_lane(source,offset+size,size));
        } else return 1;
    } else if (left>=0 && (right>=0 || count==2 || in->operand[2].type==CDISASM_OPERAND_IMMEDIATE)) {
        for(i=0;i<total;i+=size) {
            a=arm_vector_lane(e->arm.v[left],i,size);
            b=right>=0?arm_vector_lane(e->arm.v[right],i,size):count>2?in->operand[2].imm:0;
            switch(name) {
                case CDISASM_ARM_NAME_MOV:value=a;break;
                case CDISASM_ARM_NAME_ADD:value=a+b;break;
                case CDISASM_ARM_NAME_SUB:value=a-b;break;
                case CDISASM_ARM_NAME_AND:value=a&b;break;
                case CDISASM_ARM_NAME_ORR:value=a|b;break;
                case CDISASM_ARM_NAME_EOR:value=a^b;break;
                case CDISASM_ARM_NAME_BIC:value=a&~b;break;
                case CDISASM_ARM_NAME_CMHI:value=a>b?UINT64_MAX:0;break;
                case CDISASM_ARM_NAME_CMHS:value=a>=b?UINT64_MAX:0;break;
                case CDISASM_ARM_NAME_CMEQ:value=a==b?UINT64_MAX:0;break;
                case CDISASM_ARM_NAME_CMLT:value=(int64_t)xxemul_sign_extend(a,(uint8_t)size)<(int64_t)xxemul_sign_extend(b,(uint8_t)size)?UINT64_MAX:0;break;
                case CDISASM_ARM_NAME_CMLE:value=(int64_t)xxemul_sign_extend(a,(uint8_t)size)<=(int64_t)xxemul_sign_extend(b,(uint8_t)size)?UINT64_MAX:0;break;
                case CDISASM_ARM_NAME_CMGT:value=(int64_t)xxemul_sign_extend(a,(uint8_t)size)>(int64_t)xxemul_sign_extend(b,(uint8_t)size)?UINT64_MAX:0;break;
                case CDISASM_ARM_NAME_CMGE:value=(int64_t)xxemul_sign_extend(a,(uint8_t)size)>=(int64_t)xxemul_sign_extend(b,(uint8_t)size)?UINT64_MAX:0;break;
                case CDISASM_ARM_NAME_BSL:value=arm_vector_lane(e->arm.v[dest],i,size);value=(value&a)|(~value&b);break;
                case CDISASM_ARM_NAME_BIF:value=arm_vector_lane(e->arm.v[dest],i,size);value=(value&b)|(a&~b);break;
                case CDISASM_ARM_NAME_BIT:value=arm_vector_lane(e->arm.v[dest],i,size);value=(value&~b)|(a&b);break;
                case CDISASM_ARM_NAME_UQSUB:value=a>=b?a-b:0;if(a<b)e->arm.fpsr|=UINT32_C(1)<<27;break;
                case CDISASM_ARM_NAME_SHL:
                    value=b>=size*8u?0:a<<b;
                    break;
                case CDISASM_ARM_NAME_USHR:
                    value=b>=size*8u?0:a>>b;
                    break;
                case CDISASM_ARM_NAME_SSHR: {
                    int64_t signed_a=(int64_t)xxemul_sign_extend(a,(uint8_t)size);
                    value=b>=size*8u?(signed_a<0?UINT64_MAX:0):(uint64_t)(signed_a>>b);
                    break;
                }
                case CDISASM_ARM_NAME_USHL:case CDISASM_ARM_NAME_SSHL: {
                    int shift=(int8_t)b; unsigned bits=size*8;
                    if(shift>=0) value=(unsigned)shift>=bits?0:a<<shift;
                    else if(name==CDISASM_ARM_NAME_SSHL) { int64_t signed_a=(int64_t)xxemul_sign_extend(a,(uint8_t)size);value=(unsigned)-shift>=bits?(signed_a<0?UINT64_MAX:0):(uint64_t)(signed_a>>-shift); }
                    else value=(unsigned)-shift>=bits?0:a>>-shift;
                    break;
                }
                default:return 1;
            }
            arm_vector_put(result,i,size,value);
        }
    } else return 1;
    memcpy(e->arm.v[dest],result,16); *status=XXEMUL_STATUS_OK; return 1;
}
#endif
