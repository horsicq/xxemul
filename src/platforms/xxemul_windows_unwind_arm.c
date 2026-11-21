#include "xxemul_windows_unwind_arm.h"
#include <string.h>

#define ARM_MAX_ENTRIES 0x10000u
#define ARM_MAX_CODES 1020u
#define ARM_MAX_OPS 1024u
#define ARM_MAX_SCOPES 0x10000u

enum arm_unwind_action { A_ALLOC, A_GPR, A_VECTOR, A_SETSP, A_NOP, A_CHAIN, A_PAC, A_END };
typedef struct arm_unwind_op {
    unsigned action, reg, reg2, width, instruction_size, terminal_size, code_index;
    uint64_t offset, adjust;
    uint32_t mask;
} arm_unwind_op;
typedef struct arm_unwind_sequence {
    arm_unwind_op ops[ARM_MAX_OPS];
    unsigned count, prologue_size, epilogue_size;
} arm_unwind_sequence;

static uint16_t a16(const uint8_t *p) { return (uint16_t)((unsigned)p[0] | (unsigned)p[1] << 8u); }
static uint32_t a32(const uint8_t *p) { return (uint32_t)p[0] | (uint32_t)p[1] << 8u | (uint32_t)p[2] << 16u | (uint32_t)p[3] << 24u; }
static uint64_t a64(const uint8_t *p) { return (uint64_t)a32(p) | (uint64_t)a32(p + 4u) << 32u; }
static int aadd(uint64_t a, uint64_t b, uint64_t *out) { if (a > UINT64_MAX - b) return 0; *out = a + b; return 1; }
static int aread(xxemul_windows_unwind64_read read, void *context, uint64_t at, void *data, size_t size)
{ return size && at <= UINT64_MAX - (size - 1u) && read(context, at, data, size); }
static int aload32(xxemul_windows_unwind64_read read, void *context, uint64_t at, uint32_t *value)
{ uint8_t b[4]; if (!aread(read, context, at, b, 4u)) return 0; *value = a32(b); return 1; }
static int aload(xxemul_windows_unwind64_read read, void *context, uint64_t at, unsigned width, uint64_t *value)
{ uint8_t b[8]; if (!aread(read, context, at, b, width)) return 0; *value = width == 8u ? a64(b) : a32(b); return 1; }

static int append(arm_unwind_sequence *s, arm_unwind_op op)
{
    if (s->count >= ARM_MAX_OPS) return 0;
    s->ops[s->count++] = op;
    return 1;
}
static arm_unwind_op operation(unsigned action, unsigned reg, unsigned reg2,
                                unsigned width, uint64_t offset, uint64_t adjust,
                                unsigned instruction_size)
{
    arm_unwind_op op;
    memset(&op, 0, sizeof(op)); op.action = action; op.reg = reg; op.reg2 = reg2;
    op.width = width; op.offset = offset; op.adjust = adjust; op.instruction_size = instruction_size;
    return op;
}
static void lengths(arm_unwind_sequence *s)
{
    unsigned i, phantom = 0u;
    s->prologue_size = s->epilogue_size = 0u;
    for (i = 0u; i < s->count; ++i) {
        arm_unwind_op *op = &s->ops[i];
        if (op->action == A_CHAIN) phantom = 1u;
        if (!phantom) s->prologue_size += op->instruction_size;
        s->epilogue_size += op->instruction_size + op->terminal_size;
    }
}
static void reverse(arm_unwind_sequence *s)
{
    unsigned i;
    for (i = 0u; i < s->count / 2u; ++i) {
        arm_unwind_op tmp = s->ops[i]; s->ops[i] = s->ops[s->count - i - 1u]; s->ops[s->count - i - 1u] = tmp;
    }
}

/* Decode a stream independently from its selected start index. save_next
 * precedes the base pair in unwind order, so expand its higher pairs before
 * the base restore and keep each instruction's own metadata byte index. */
static xxemul_status decode64(const uint8_t *codes, unsigned bytes, unsigned start,
                              arm_unwind_sequence *s)
{
    unsigned at = start, begin, byte, value, n, pending = 0u, pending_index[32], i, kind, pair, pre;
    arm_unwind_op op;
    memset(s, 0, sizeof(*s));
    while (at < bytes) {
        begin = at; byte = codes[at++];
        op = operation(A_NOP, 0u, 31u, 0u, 0u, 0u, 4u);
        if (byte == 0xe6u) {
            if (pending >= 31u) return XXEMUL_STATUS_INVALID_IMAGE;
            pending_index[pending++] = begin; continue;
        }
        n = byte < 0xc0u || byte == 0xe1u || (byte >= 0xe3u && byte <= 0xe6u) || byte == 0xfcu ? 0u :
            byte < 0xe0u || byte == 0xe2u ? 1u : byte == 0xe0u ? 3u : byte == 0xe7u ? 2u : 0u;
        if (n > bytes - at) return XXEMUL_STATUS_INVALID_IMAGE;
        value = 0u; for (i = 0u; i < n; ++i) value = (value << 8u) | codes[at++];
        if (byte < 0x20u) op = operation(A_ALLOC, 0u, 31u, 0u, 0u, (byte & 31u) * 16u, 4u);
        else if (byte < 0x40u) op = operation(A_GPR, 19u, 20u, 8u, 0u, (byte & 31u) * 8u, 4u);
        else if (byte < 0x80u) op = operation(A_GPR, 29u, 30u, 8u, (byte & 63u) * 8u, 0u, 4u);
        else if (byte < 0xc0u) op = operation(A_GPR, 29u, 30u, 8u, 0u, ((byte & 63u) + 1u) * 8u, 4u);
        else if (byte < 0xc8u) op = operation(A_ALLOC, 0u, 31u, 0u, 0u, (((byte & 7u) << 8u) | value) * 16u, 4u);
        else if (byte < 0xccu) op = operation(A_GPR, 19u + (((byte & 3u) << 2u) | (value >> 6u)), 0u, 8u, (value & 63u) * 8u, 0u, 4u);
        else if (byte < 0xd0u) op = operation(A_GPR, 19u + (((byte & 3u) << 2u) | (value >> 6u)), 0u, 8u, 0u, ((value & 63u) + 1u) * 8u, 4u);
        else if (byte < 0xd4u) op = operation(A_GPR, 19u + (((byte & 3u) << 2u) | (value >> 6u)), 31u, 8u, (value & 63u) * 8u, 0u, 4u);
        else if (byte < 0xd6u) op = operation(A_GPR, 19u + (((byte & 1u) << 3u) | (value >> 5u)), 31u, 8u, 0u, ((value & 31u) + 1u) * 8u, 4u);
        else if (byte < 0xd8u) op = operation(A_GPR, 19u + ((((byte & 1u) << 2u) | (value >> 6u)) * 2u), 30u, 8u, (value & 63u) * 8u, 0u, 4u);
        else if (byte < 0xdau) op = operation(A_VECTOR, 8u + (((byte & 1u) << 2u) | (value >> 6u)), 0u, 8u, (value & 63u) * 8u, 0u, 4u);
        else if (byte < 0xdcu) op = operation(A_VECTOR, 8u + (((byte & 1u) << 2u) | (value >> 6u)), 0u, 8u, 0u, ((value & 63u) + 1u) * 8u, 4u);
        else if (byte < 0xdeu) op = operation(A_VECTOR, 8u + (((byte & 1u) << 2u) | (value >> 6u)), 32u, 8u, (value & 63u) * 8u, 0u, 4u);
        else if (byte == 0xdeu) op = operation(A_VECTOR, 8u + (value >> 5u), 32u, 8u, 0u, ((value & 31u) + 1u) * 8u, 4u);
        else if (byte == 0xe0u) op = operation(A_ALLOC, 0u, 31u, 0u, 0u, (uint64_t)value * 16u, 4u);
        else if (byte == 0xe1u) op = operation(A_SETSP, 29u, 31u, 0u, 0u, 0u, 4u);
        else if (byte == 0xe2u) op = operation(A_SETSP, 29u, 31u, 0u, (uint64_t)value * 8u, 0u, 4u);
        else if (byte == 0xe3u) { /* nop */ }
        else if (byte == 0xe4u) { op.action = A_END; op.instruction_size = 0u; op.terminal_size = 4u; }
        else if (byte == 0xe5u) { op.action = A_CHAIN; op.instruction_size = 0u; }
        else if (byte == 0xe7u) {
            unsigned hi = value >> 8u, lo = value & 255u;
            if (hi & 0x80u) return XXEMUL_STATUS_INVALID_IMAGE;
            kind = lo >> 6u; pair = (hi >> 6u) & 1u; pre = (hi >> 5u) & 1u;
            if (kind == 3u) return XXEMUL_STATUS_UNSUPPORTED_IMAGE; /* SVE state is not modeled. */
            op = operation(kind ? A_VECTOR : A_GPR, hi & 31u,
                pair ? 0u : kind ? 32u : 31u, kind == 2u ? 16u : 8u,
                pre ? 0u : (uint64_t)(lo & 63u) * ((pre || pair || kind == 2u) ? 16u : 8u),
                pre ? (uint64_t)((lo & 63u) + 1u) * 16u : 0u, 4u);
        } else if (byte == 0xfcu) op.action = A_PAC;
        else return XXEMUL_STATUS_UNSUPPORTED_IMAGE;
        if ((op.action == A_GPR || op.action == A_VECTOR) && op.reg2 == 0u) op.reg2 = op.reg + 1u;
        if ((op.action == A_GPR && (op.reg > 30u || (op.reg2 != 31u && op.reg2 > 30u))) ||
            (op.action == A_VECTOR && (op.reg > 31u || (op.reg2 != 32u && op.reg2 > 31u))))
            return XXEMUL_STATUS_INVALID_IMAGE;
        if (pending) {
            if ((op.action != A_GPR && op.action != A_VECTOR) || op.reg2 != op.reg + 1u)
                return XXEMUL_STATUS_INVALID_IMAGE;
            for (i = 0u; i < pending; ++i) {
                arm_unwind_op higher = op;
                unsigned step = pending - i;
                higher.reg += step * 2u; higher.reg2 += step * 2u;
                higher.offset += (uint64_t)step * op.width * 2u; higher.adjust = 0u;
                higher.code_index = pending_index[i];
                if ((higher.action == A_GPR && higher.reg2 > 30u) || (higher.action == A_VECTOR && higher.reg2 > 31u) ||
                    !append(s, higher)) return XXEMUL_STATUS_INVALID_IMAGE;
            }
            pending = 0u;
        }
        op.code_index = begin;
        if (!append(s, op)) return XXEMUL_STATUS_INVALID_IMAGE;
        if (op.action == A_END) { lengths(s); return XXEMUL_STATUS_OK; }
    }
    return XXEMUL_STATUS_INVALID_IMAGE;
}

static unsigned popcount(uint32_t mask)
{ unsigned count = 0u; while (mask) { count += mask & 1u; mask >>= 1u; } return count; }
static arm_unwind_op mask32(uint32_t mask, unsigned size)
{ arm_unwind_op op = operation(A_GPR, 0u, 31u, 4u, 0u, popcount(mask) * 4u, size); op.mask = mask; return op; }

static xxemul_status decode32(const uint8_t *codes, unsigned bytes, unsigned start,
                              arm_unwind_sequence *s)
{
    unsigned at = start, begin, byte, n, value, i, top, first;
    arm_unwind_op op;
    memset(s, 0, sizeof(*s));
    while (at < bytes) {
        begin = at; byte = codes[at++];
        n = byte < 0x80u || (byte >= 0xc0u && byte < 0xe8u) || (byte >= 0xf0u && byte <= 0xf4u) || byte >= 0xfbu ? 0u :
            byte < 0xc0u || byte <= 0xefu || byte == 0xf5u || byte == 0xf6u ? 1u :
            byte == 0xf7u || byte == 0xf9u ? 2u : 3u;
        if (n > bytes - at) return XXEMUL_STATUS_INVALID_IMAGE;
        value = 0u; for (i = 0u; i < n; ++i) value = (value << 8u) | codes[at++];
        op = operation(A_NOP, 0u, 31u, 0u, 0u, 0u, 2u);
        if (byte < 0x80u) op = operation(A_ALLOC, 0u, 31u, 0u, 0u, (byte & 0x7fu) * 4u, 2u);
        else if (byte < 0xc0u) op = mask32((((byte & 0x3fu) << 8u) | value) & 0x1fffu, 4u);
        else if (byte < 0xd0u) op = operation(A_SETSP, byte & 15u, 31u, 0u, 0u, 0u, 2u);
        else if (byte < 0xe0u) {
            top = (byte & 3u) + (byte < 0xd8u ? 4u : 8u);
            op = mask32(((UINT32_C(1) << (top + 1u)) - 1u) & ~15u, byte < 0xd8u ? 2u : 4u);
        } else if (byte < 0xe8u) op = operation(A_VECTOR, 8u, 8u + (byte & 7u), 8u, 0u, (uint64_t)((byte & 7u) + 1u) * 8u, 4u);
        else if (byte < 0xecu) op = operation(A_ALLOC, 0u, 31u, 0u, 0u, (((byte & 3u) << 8u) | value) * 4u, 4u);
        else if (byte <= 0xedu) op = mask32(value, 2u);
        else if (byte == 0xefu && value < 16u) op = operation(A_GPR, 14u, 31u, 4u, 0u, value * 4u, 4u);
        else if (byte == 0xf5u || byte == 0xf6u) {
            first = (value >> 4u) + (byte == 0xf6u ? 16u : 0u);
            top = (value & 15u) + (byte == 0xf6u ? 16u : 0u);
            if (top < first) return XXEMUL_STATUS_INVALID_IMAGE;
            op = operation(A_VECTOR, first, top, 8u, 0u, (uint64_t)(top - first + 1u) * 8u, 4u);
        } else if (byte >= 0xf7u && byte <= 0xfau)
            op = operation(A_ALLOC, 0u, 31u, 0u, 0u, (uint64_t)value * 4u, byte < 0xf9u ? 2u : 4u);
        else if (byte == 0xfbu || byte == 0xfcu) op.instruction_size = byte == 0xfbu ? 2u : 4u;
        else if (byte >= 0xfdu) {
            op.action = A_END; op.instruction_size = 0u; op.terminal_size = byte == 0xfdu ? 2u : byte == 0xfeu ? 4u : 0u;
        } else return XXEMUL_STATUS_UNSUPPORTED_IMAGE;
        if ((byte >= 0x80u && byte < 0xc0u && (byte & 0x20u)) ||
            (byte >= 0xd0u && byte < 0xe0u && (byte & 4u)) || byte == 0xedu) {
            op.mask |= UINT32_C(1) << 14u; op.adjust += 4u;
        }
        if (op.action == A_GPR && op.mask == 0u && byte != 0xefu) return XXEMUL_STATUS_INVALID_IMAGE;
        op.code_index = begin;
        if (!append(s, op)) return XXEMUL_STATUS_INVALID_IMAGE;
        if (op.action == A_END) { lengths(s); return XXEMUL_STATUS_OK; }
    }
    return XXEMUL_STATUS_INVALID_IMAGE;
}

static xxemul_status packed32(uint32_t data, int epilogue, arm_unwind_sequence *s)
{
    unsigned flag = data & 3u, ret = (data >> 13u) & 3u, home = (data >> 15u) & 1u;
    unsigned reg = (data >> 16u) & 7u, fp = (data >> 19u) & 1u, lr = (data >> 20u) & 1u, chain = (data >> 21u) & 1u;
    unsigned adjust = data >> 22u, fold = adjust >= 0x3f4u && (adjust & (epilogue ? 8u : 4u));
    unsigned first = fold ? (~adjust) & 3u : 4u, last = fp ? 3u : reg + 4u;
    unsigned amount = adjust >= 0x3f4u ? ((adjust & 3u) + 1u) * 4u : adjust * 4u;
    uint32_t mask = 0u;
    arm_unwind_op op;
    memset(s, 0, sizeof(*s));
    if (!flag || flag == 3u || (chain && (!lr || (!fp && reg == 7u))) || (!ret && !lr)) return XXEMUL_STATUS_INVALID_IMAGE;
    if (first <= last) mask = ((UINT32_C(1) << (last + 1u)) - 1u) & ~((UINT32_C(1) << first) - 1u);
    if (chain) mask |= UINT32_C(1) << 11u;
    if (lr && (!epilogue || !home || ret)) mask |= UINT32_C(1) << 14u;
    if (epilogue) {
        if (amount && !fold) append(s, operation(A_ALLOC, 0u,31u,0u,0u,amount,amount <= 508u ? 2u : 4u));
        if (fp && reg != 7u) append(s, operation(A_VECTOR,8u,8u+reg,8u,0u,(reg+1u)*8u,4u));
        if (mask) append(s, mask32(mask, mask & 0x1f00u ? 4u : 2u));
        if (home) {
            if (lr && !ret) append(s, operation(A_GPR,14u,31u,4u,0u,20u,4u));
            else append(s, operation(A_ALLOC,0u,31u,0u,0u,16u,2u));
        }
        op = operation(A_END,0u,31u,0u,0u,0u,0u); op.terminal_size = ret == 1u ? 2u : ret == 2u ? 4u : 0u; append(s,op);
    } else {
        if (home) append(s, operation(A_ALLOC,0u,31u,0u,0u,16u,2u));
        if (mask) append(s, mask32(mask, mask & 0x1f00u ? 4u : 2u));
        if (chain) append(s, operation(A_NOP,0u,31u,0u,0u,0u,fp && !fold ? 2u : 4u));
        if (fp && reg != 7u) append(s, operation(A_VECTOR,8u,8u+reg,8u,0u,(reg+1u)*8u,4u));
        if (amount && !fold) append(s, operation(A_ALLOC,0u,31u,0u,0u,amount,amount <= 508u ? 2u : 4u));
        reverse(s); append(s, operation(A_END,0u,31u,0u,0u,0u,0u));
    }
    lengths(s); return XXEMUL_STATUS_OK;
}

static xxemul_status packed64(uint32_t data, arm_unwind_sequence *s)
{
    unsigned ints = (data >> 16u) & 15u, floats = (data >> 13u) & 7u, home = (data >> 20u) & 1u;
    unsigned cr = (data >> 21u) & 3u, frame = (data >> 23u) * 16u;
    unsigned intsize = ints * 8u + (cr == 1u ? 8u : 0u), fcount = floats ? floats + 1u : 0u;
    unsigned save = (intsize + fcount * 8u + home * 64u + 15u) & ~15u, local, index, saved = 0u;
    arm_unwind_op op;
    memset(s,0,sizeof(*s));
    if (ints > 10u || frame < save || ((cr == 2u || cr == 3u) && frame - save < 16u)) return XXEMUL_STATUS_INVALID_IMAGE;
    local = frame - save;
    if (cr == 2u) append(s, operation(A_PAC,0u,31u,0u,0u,0u,4u));
    if (ints == 1u && cr == 1u) {
        append(s,operation(A_ALLOC,0u,31u,0u,0u,save,4u));
        append(s,operation(A_GPR,19u,30u,8u,0u,0u,4u)); saved = 1u;
    } else {
        for (index=0u;index<ints;index+=2u) {
            unsigned second = index+1u<ints ? 20u+index : cr==1u ? 30u : 31u;
            op=operation(A_GPR,19u+index,second,8u,saved ? index*8u : 0u,saved ? 0u : save,4u);
            append(s,op); saved=1u;
        }
        if (cr==1u && !(ints&1u)) {
            append(s,operation(A_GPR,30u,31u,8u,saved ? ints*8u : 0u,saved ? 0u : save,4u)); saved=1u;
        }
    }
    for(index=0u;index<fcount;index+=2u) {
        append(s,operation(A_VECTOR,8u+index,index+1u<fcount ? 9u+index : 32u,8u,
            saved ? intsize+index*8u : 0u,saved ? 0u : save,4u)); saved=1u;
    }
    if(home) for(index=0u;index<4u;++index) {
        append(s,operation(saved ? A_NOP : A_ALLOC,0u,31u,0u,0u,saved ? 0u : save,4u)); saved=1u;
    }
    if(cr==2u||cr==3u) {
        if(local<=512u) append(s,operation(A_GPR,29u,30u,8u,0u,local,4u));
        else {
            if(local>4080u) append(s,operation(A_ALLOC,0u,31u,0u,0u,4080u,4u));
            append(s,operation(A_ALLOC,0u,31u,0u,0u,local>4080u ? local-4080u : local,4u));
            append(s,operation(A_GPR,29u,30u,8u,0u,0u,4u));
        }
        append(s,operation(A_NOP,0u,31u,0u,0u,0u,4u)); /* canonical SET_FP has no unwind effect */
    } else if(local) {
        if(local>4080u) append(s,operation(A_ALLOC,0u,31u,0u,0u,4080u,4u));
        append(s,operation(A_ALLOC,0u,31u,0u,0u,local>4080u ? local-4080u : local,4u));
    }
    reverse(s); op=operation(A_END,0u,31u,0u,0u,0u,0u);op.terminal_size=4u;append(s,op);
    lengths(s);return XXEMUL_STATUS_OK;
}

static xxemul_status arm_function(xxemul_windows_unwind64_read read, void *context, int is64,
                                  uint64_t at, uint64_t base,
                                  xxemul_windows_runtime_function_arm *f)
{
    uint8_t bytes[8]; uint32_t header, length, begin, flag; uint64_t end, xdata;
    if ((at&3u)||!aread(read,context,at,bytes,8u)) return XXEMUL_STATUS_ADDRESS_FAULT;
    begin=a32(bytes);f->address=at;f->begin_address=begin;f->unwind_data=a32(bytes+4u);flag=f->unwind_data&3u;
    if ((is64 && (begin&3u)) || (!is64 && ((begin&~1u)&1u))) return XXEMUL_STATUS_INVALID_IMAGE;
    if (flag==3u) return XXEMUL_STATUS_UNSUPPORTED_IMAGE;
    if(flag) length=((f->unwind_data>>2u)&0x7ffu)*(is64 ? 4u : 2u);
    else {
        if(!f->unwind_data||!aadd(base,f->unwind_data,&xdata))return XXEMUL_STATUS_INVALID_IMAGE;
        if(!aload32(read,context,xdata,&header))return XXEMUL_STATUS_ADDRESS_FAULT;
        if((header>>18u)&3u)return XXEMUL_STATUS_UNSUPPORTED_IMAGE;
        length=(header&0x3ffffu)*(is64 ? 4u : 2u);
    }
    begin&=~1u;
    if(!length||length>UINT32_MAX-begin||!aadd(base,(uint64_t)begin+length,&end))return XXEMUL_STATUS_INVALID_IMAGE;
    f->end_address=begin+length;return XXEMUL_STATUS_OK;
}

static xxemul_status arm_table(xxemul_windows_unwind64_read read,void*context,int is64,
 uint64_t table,uint32_t count,uint64_t base,uint64_t pc,xxemul_windows_runtime_function_arm*out,
 uint64_t*minimum,uint64_t*maximum)
{
    xxemul_windows_runtime_function_arm found={0},f;uint32_t i,previous=0u;uint64_t end;xxemul_status status;
    if(!read||!table||(table&3u)||count>ARM_MAX_ENTRIES||!aadd(table,(uint64_t)count*8u,&end))return XXEMUL_STATUS_INVALID_ARGUMENT;
    if(minimum)*minimum=0u;
    if(maximum)*maximum=0u;
    pc&=is64 ? UINT64_MAX : ~UINT64_C(1);
    for(i=0u;i<count;++i){
        status=arm_function(read,context,is64,table+(uint64_t)i*8u,base,&f);if(status!=XXEMUL_STATUS_OK)return status;
        if(i&&(f.begin_address&~1u)<previous)return XXEMUL_STATUS_INVALID_IMAGE;
        previous=f.end_address;
        if(!i&&minimum)*minimum=base+(f.begin_address&~1u);
        if(maximum)*maximum=base+f.end_address;
        if(pc>=base+(f.begin_address&~1u)&&pc<base+f.end_address)found=f;
    }
    if(out)*out=found;
    return XXEMUL_STATUS_OK;
}

xxemul_status xxemul_windows_unwind_arm_lookup_table(xxemul_windows_unwind64_read read,void*context,int is64,
 uint64_t table,uint32_t count,uint64_t base,uint64_t pc,xxemul_windows_runtime_function_arm*out)
{if(!out)return XXEMUL_STATUS_INVALID_ARGUMENT;return arm_table(read,context,is64,table,count,base,pc,out,NULL,NULL);}

xxemul_status xxemul_windows_unwind_arm_lookup_image(xxemul_windows_unwind64_read read,void*context,int is64,
 uint64_t base,uint64_t size,uint64_t pc,xxemul_windows_runtime_function_arm*out)
{
    uint8_t dos[64],nt[24],optional[144];uint32_t pe,rva,bytes,number,i;unsigned opt_size,offset;uint64_t end;
    xxemul_status status;xxemul_windows_runtime_function_arm found,f;
    if(!read||!out||size<64u||!aadd(base,size,&end))return XXEMUL_STATUS_INVALID_ARGUMENT;
    pc&=is64 ? UINT64_MAX : ~UINT64_C(1);if(pc<base||pc>=end){memset(out,0,sizeof(*out));return XXEMUL_STATUS_OK;}
    if(!aread(read,context,base,dos,64u))return XXEMUL_STATUS_ADDRESS_FAULT;
    pe=a32(dos+0x3cu);
    if(a16(dos)!=0x5a4du||pe>size||24u>size-pe)return XXEMUL_STATUS_INVALID_IMAGE;
    if(!aread(read,context,base+pe,nt,24u))return XXEMUL_STATUS_ADDRESS_FAULT;
    opt_size=a16(nt+20u);offset=is64?112u:96u;
    if(a32(nt)!=0x4550u||(is64?a16(nt+4u)!=0xaa64u:(a16(nt+4u)!=0x1c4u&&a16(nt+4u)!=0x1c2u))||
        opt_size<offset|| (uint64_t)pe+24u+opt_size>size)return XXEMUL_STATUS_INVALID_IMAGE;
    if(!aread(read,context,base+pe+24u,optional,offset))return XXEMUL_STATUS_ADDRESS_FAULT;
    if(a16(optional)!=(is64?0x20bu:0x10bu))return XXEMUL_STATUS_INVALID_IMAGE;
    number=a32(optional+offset-4u);if(number<=3u){memset(out,0,sizeof(*out));return XXEMUL_STATUS_OK;}
    if(opt_size<offset+32u)return XXEMUL_STATUS_INVALID_IMAGE;
    if(!aread(read,context,base+pe+24u+offset,optional+offset,32u))return XXEMUL_STATUS_ADDRESS_FAULT;
    rva=a32(optional+offset+24u);bytes=a32(optional+offset+28u);
    if(!rva&&!bytes){memset(out,0,sizeof(*out));return XXEMUL_STATUS_OK;}
    if(!rva||!bytes||(rva&3u)||bytes%8u||rva>size||bytes>size-rva||bytes/8u>ARM_MAX_ENTRIES)return XXEMUL_STATUS_INVALID_IMAGE;
    for(i=0u;i<bytes/8u;++i){status=arm_function(read,context,is64,base+rva+(uint64_t)i*8u,base,&f);if(status!=XXEMUL_STATUS_OK)return status;
        if(f.end_address>size||(!(f.unwind_data&3u)&&f.unwind_data>=size))return XXEMUL_STATUS_INVALID_IMAGE;}
    status=arm_table(read,context,is64,base+rva,bytes/8u,base,pc,&found,NULL,NULL);if(status==XXEMUL_STATUS_OK)*out=found;return status;
}

static int condition(unsigned code,uint32_t flags)
{
    unsigned n=(flags>>31u)&1u,z=(flags>>30u)&1u,c=(flags>>29u)&1u,v=(flags>>28u)&1u;
    switch(code){case 0:return z;case 1:return !z;case 2:return c;case 3:return !c;case 4:return n;case 5:return !n;
    case 6:return v;case 7:return !v;case 8:return c&&!z;case 9:return !c||z;case 10:return n==v;case 11:return n!=v;
    case 12:return !z&&n==v;case 13:return z||n!=v;case 14:return 1;default:return 0;}
}

static xxemul_status execute(xxemul_windows_unwind64_read read,void*context,int is64,
 const arm_unwind_sequence*s,unsigned skip,int prologue,xxemul_arm_state*state,
 xxemul_windows_unwind_arm_result*out,xxemul_windows_unwind_arm_authenticate authenticate)
{
    unsigned i,reg,phantom=0u,skipped=0u,pac=0u;uint64_t at,value;const arm_unwind_op*op;
    for(i=0u;i<s->count;++i){op=&s->ops[i];if(op->action==A_CHAIN){phantom=1u;++out->chained_records;continue;}
        if(op->action==A_END)break;
        if(skipped<skip&&(!prologue||!phantom)){
            skipped+=op->instruction_size;
            /* A Thumb caller walk uses returnPC-2, including the second
             * halfword of a 32-bit BL inside a prologue. That call is a
             * 32-bit NOP in unwind metadata; skip its complete annotation. */
            if(skipped>skip&&!(prologue&&!is64&&op->action==A_NOP&&op->instruction_size==4u))
                return XXEMUL_STATUS_INVALID_IMAGE;
            continue;
        }
        if(op->action==A_ALLOC){if(!aadd(state->sp,op->adjust,&state->sp))return XXEMUL_STATUS_INVALID_IMAGE;}
        else if(op->action==A_SETSP){value=op->reg==13u&&!is64?state->sp:op->reg==15u&&!is64?state->pc:state->gpr[op->reg];
            if(value<op->offset)return XXEMUL_STATUS_INVALID_IMAGE;
            state->sp=value-op->offset;out->establisher_frame=state->sp;}
        else if(op->action==A_GPR||op->action==A_VECTOR){
            if(!aadd(state->sp,op->offset,&at))return XXEMUL_STATUS_INVALID_IMAGE;
            if(op->mask){for(reg=0u;reg<=14u;++reg)if(op->mask&(1u<<reg)){
                if(!aload(read,context,at,4u,&state->gpr[reg]))return XXEMUL_STATUS_ADDRESS_FAULT;
                out->integer_save[reg]=at;
                if(!aadd(at,4u,&at))return XXEMUL_STATUS_INVALID_IMAGE;}}
            else if(op->action==A_GPR){
                if(!aload(read,context,at,op->width,&state->gpr[op->reg]))return XXEMUL_STATUS_ADDRESS_FAULT;
                out->integer_save[op->reg]=at;
                if(op->reg2!=31u){if(!aadd(at,op->width,&at)||!aload(read,context,at,op->width,&state->gpr[op->reg2]))return XXEMUL_STATUS_ADDRESS_FAULT;
                    out->integer_save[op->reg2]=at;}}
            else {unsigned last=op->reg2==32u?op->reg:op->reg2;
                for(reg=op->reg;reg<=last;++reg){if(!aread(read,context,at,state->v[reg],op->width))return XXEMUL_STATUS_ADDRESS_FAULT;
                    out->vfp_save[reg]=at;if(reg!=last&&!aadd(at,op->width,&at))return XXEMUL_STATUS_INVALID_IMAGE;}}
            if(!aadd(state->sp,op->adjust,&state->sp))return XXEMUL_STATUS_INVALID_IMAGE;
        }else if(op->action==A_PAC)pac=1u;
        if(!is64&&state->sp>UINT32_MAX)return XXEMUL_STATUS_INVALID_IMAGE;
    }
    if(pac){if(!authenticate)return XXEMUL_STATUS_UNSUPPORTED_IMAGE;
        if(!authenticate(context,state->gpr[30],state->sp,&value))return XXEMUL_STATUS_INVALID_IMAGE;
        state->gpr[30]=value;}
    if(is64)state->pc=state->gpr[30];else{state->pc=(uint32_t)state->gpr[14]&~UINT32_C(1);
        state->pstate=(state->pstate&~0x20u)|((state->gpr[14]&1u)?0x20u:0u);}
    return XXEMUL_STATUS_OK;
}

xxemul_status xxemul_windows_unwind_arm_virtual_unwind_ex(xxemul_windows_unwind64_read read,void*context,int is64,
 uint64_t base,uint64_t pc,const xxemul_windows_runtime_function_arm*function,unsigned handler_type,
 xxemul_arm_state*cpu,xxemul_windows_unwind_arm_result*result,xxemul_windows_unwind_arm_authenticate authenticate)
{
    xxemul_arm_state state;xxemul_windows_unwind_arm_result out={0};arm_unwind_sequence sequence,epilogue;
    xxemul_status status;uint32_t header,extended,scope,handler;uint64_t address,codes_address,tail,offset,begin;
    uint8_t codes[ARM_MAX_CODES];unsigned words,count,single,has_handler,fragment,skip=0u,start=0u,i,selected=0u,previous=0u;
    uint64_t previous_end=0u, function_size;
    if(!read||!cpu||!result||(handler_type&~3u))return XXEMUL_STATUS_INVALID_ARGUMENT;
    state=*cpu;out.establisher_frame=state.sp;pc&=is64?UINT64_MAX:~UINT64_C(1);
    if(!function||!function->address){if(is64)state.pc=state.gpr[30];else{state.pc=(uint32_t)state.gpr[14]&~UINT32_C(1);state.pstate=(state.pstate&~0x20u)|((state.gpr[14]&1u)?0x20u:0u);}
        *cpu=state;*result=out;return XXEMUL_STATUS_OK;}
    begin=function->begin_address&~1u;
    if(pc<base||pc-base<begin||pc-base>=function->end_address)return XXEMUL_STATUS_INVALID_ARGUMENT;
    function_size=(uint64_t)function->end_address-begin;
    offset=pc-base-begin;
    if(function->unwind_data&3u){
        if((function->unwind_data&3u)==3u)return XXEMUL_STATUS_UNSUPPORTED_IMAGE;
        status=is64?packed64(function->unwind_data,&sequence):packed32(function->unwind_data,0,&sequence);
        if(status!=XXEMUL_STATUS_OK)return status;
        if(sequence.prologue_size>function_size)return XXEMUL_STATUS_INVALID_IMAGE;
        if((function->unwind_data&3u)==1u&&offset<sequence.prologue_size){out.in_prologue=1u;skip=sequence.prologue_size-(unsigned)offset;}
        else if((function->unwind_data&3u)==1u&&(is64||((function->unwind_data>>13u)&3u)!=3u)){
            if(is64){epilogue=sequence;/* canonical frame setup is omitted in epilogue */
                if(((function->unwind_data>>21u)&3u)>=2u&&epilogue.count&&epilogue.ops[0].action==A_NOP){
                    memmove(epilogue.ops,epilogue.ops+1u,(epilogue.count-1u)*sizeof(epilogue.ops[0]));--epilogue.count;lengths(&epilogue);}}
            else{status=packed32(function->unwind_data,1,&epilogue);if(status!=XXEMUL_STATUS_OK)return status;}
            if(epilogue.epilogue_size>function->end_address-begin)return XXEMUL_STATUS_INVALID_IMAGE;
            address=(uint64_t)function->end_address-begin-epilogue.epilogue_size;
            if(offset>=address){out.in_epilogue=1u;skip=(unsigned)(offset-address);sequence=epilogue;}
        }
    }else{
        if(!aadd(base,function->unwind_data,&address)||!aload32(read,context,address,&header))return XXEMUL_STATUS_ADDRESS_FAULT;
        if((header>>18u)&3u)return XXEMUL_STATUS_UNSUPPORTED_IMAGE;
        has_handler=(header>>20u)&1u;single=(header>>21u)&1u;fragment=is64?0u:(header>>22u)&1u;
        count=(header>>(is64?22u:23u))&31u;words=header>>(is64?27u:28u);
        if(!aadd(address,4u,&tail))return XXEMUL_STATUS_INVALID_IMAGE;
        if(!count&&!words){if(!aload32(read,context,tail,&extended))return XXEMUL_STATUS_ADDRESS_FAULT;
            if(extended&0xff000000u)return XXEMUL_STATUS_INVALID_IMAGE;
            count=extended&0xffffu;words=(extended>>16u)&255u;
            if(!aadd(tail,4u,&tail))return XXEMUL_STATUS_INVALID_IMAGE;}
        if(!words||words>255u||count>ARM_MAX_SCOPES||(!single&&!aadd(tail,(uint64_t)count*4u,&codes_address)))return XXEMUL_STATUS_INVALID_IMAGE;
        if(single)codes_address=tail;
        if(codes_address>UINT64_MAX-(uint64_t)words*4u)return XXEMUL_STATUS_INVALID_IMAGE;
        if(!aread(read,context,codes_address,codes,words*4u))return XXEMUL_STATUS_ADDRESS_FAULT;
        status=is64?decode64(codes,words*4u,0u,&sequence):decode32(codes,words*4u,0u,&sequence);
        if(status!=XXEMUL_STATUS_OK)return status;
        if(sequence.prologue_size>function_size)return XXEMUL_STATUS_INVALID_IMAGE;
        if(single){start=count;status=is64?decode64(codes,words*4u,start,&epilogue):decode32(codes,words*4u,start,&epilogue);
            if(status!=XXEMUL_STATUS_OK)return status;
            if(epilogue.epilogue_size>function->end_address-begin)return XXEMUL_STATUS_INVALID_IMAGE;
            address=(uint64_t)function->end_address-begin-epilogue.epilogue_size;
            if(offset>=address){out.in_epilogue=1u;skip=(unsigned)(offset-address);sequence=epilogue;selected=1u;}}
        else for(i=0u;i<count;++i){
            if(!aload32(read,context,tail+(uint64_t)i*4u,&scope))return XXEMUL_STATUS_ADDRESS_FAULT;
            if((is64?(scope&0x003c0000u):(scope&0x000c0000u))|| (i&&(scope&0x3ffffu)<=previous))return XXEMUL_STATUS_INVALID_IMAGE;
            if(!is64&&((scope>>20u)&15u)==15u)return XXEMUL_STATUS_INVALID_IMAGE;
            previous=scope&0x3ffffu;start=is64?scope>>22u:scope>>24u;
            status=is64?decode64(codes,words*4u,start,&epilogue):decode32(codes,words*4u,start,&epilogue);if(status!=XXEMUL_STATUS_OK)return status;
            address=(uint64_t)(scope&0x3ffffu)*(is64?4u:2u);
            if(address>=function->end_address-begin||epilogue.epilogue_size>function->end_address-begin-address)return XXEMUL_STATUS_INVALID_IMAGE;
            if(i&&address<previous_end)return XXEMUL_STATUS_INVALID_IMAGE;
            previous_end=address+epilogue.epilogue_size;
            if(offset>=address&&offset<address+epilogue.epilogue_size&&(is64||condition((scope>>20u)&15u,state.pstate))){
                out.in_epilogue=1u;skip=(unsigned)(offset-address);sequence=epilogue;selected=1u;}
        }
        if(!selected&&!fragment&&offset<sequence.prologue_size){out.in_prologue=1u;skip=sequence.prologue_size-(unsigned)offset;}
        if(has_handler&&handler_type&&!out.in_prologue&&!out.in_epilogue){
            if(!aadd(codes_address,(uint64_t)words*4u,&address)||!aload32(read,context,address,&handler))return XXEMUL_STATUS_ADDRESS_FAULT;
            if(!handler||!aadd(base,handler,&out.handler)||!aadd(address,4u,&out.handler_data))return XXEMUL_STATUS_INVALID_IMAGE;
        }
    }
    status=execute(read,context,is64,&sequence,skip,out.in_prologue,&state,&out,authenticate);
    if(status!=XXEMUL_STATUS_OK)return status;
    *cpu=state;*result=out;return XXEMUL_STATUS_OK;
}

xxemul_status xxemul_windows_unwind_arm_virtual_unwind(xxemul_windows_unwind64_read read,void*context,int is64,
 uint64_t base,uint64_t pc,const xxemul_windows_runtime_function_arm*function,unsigned handler_type,
 xxemul_arm_state*cpu,xxemul_windows_unwind_arm_result*result)
{return xxemul_windows_unwind_arm_virtual_unwind_ex(read,context,is64,base,pc,function,handler_type,cpu,result,NULL);}

xxemul_status xxemul_windows_unwind_arm_add_table(xxemul_windows_unwind64_read read,void*context,int is64,
 xxemul_windows_unwind_arm_registry*registry,uint64_t table,uint32_t count,uint64_t base)
{
    size_t i,available=64u;xxemul_windows_unwind_arm_table item={0};xxemul_status status;
    if(!registry||!count)return XXEMUL_STATUS_INVALID_ARGUMENT;
    for(i=0u;i<64u;++i){if(registry->tables[i].active&&registry->tables[i].address==table)return XXEMUL_STATUS_INVALID_ARGUMENT;
        if(!registry->tables[i].active&&available==64u)available=i;}
    if(available==64u)return XXEMUL_STATUS_OUT_OF_MEMORY;
    status=arm_table(read,context,is64,table,count,base,0u,NULL,&item.begin_address,&item.end_address);if(status!=XXEMUL_STATUS_OK)return status;
    item.address=table;item.image_base=base;item.count=count;item.active=1u;item.is64=(unsigned)!!is64;registry->tables[available]=item;return XXEMUL_STATUS_OK;
}
int xxemul_windows_unwind_arm_delete_table(xxemul_windows_unwind_arm_registry*registry,uint64_t table)
{size_t i;if(!registry)return 0;for(i=0u;i<64u;++i)if(registry->tables[i].active&&registry->tables[i].address==table){memset(&registry->tables[i],0,sizeof(registry->tables[i]));return 1;}return 0;}
xxemul_status xxemul_windows_unwind_arm_lookup_dynamic(xxemul_windows_unwind64_read read,void*context,int is64,
 const xxemul_windows_unwind_arm_registry*registry,uint64_t pc,uint64_t*base,xxemul_windows_runtime_function_arm*function)
{
    size_t i;xxemul_windows_runtime_function_arm found;xxemul_status status;if(!registry||!base||!function)return XXEMUL_STATUS_INVALID_ARGUMENT;
    pc&=is64?UINT64_MAX:~UINT64_C(1);for(i=0u;i<64u;++i){const xxemul_windows_unwind_arm_table*t=&registry->tables[i];
        if(!t->active||t->is64!=(unsigned)!!is64||pc<t->begin_address||pc>=t->end_address)continue;
        status=arm_table(read,context,is64,t->address,t->count,t->image_base,pc,&found,NULL,NULL);if(status!=XXEMUL_STATUS_OK)return status;
        if(found.address){*base=t->image_base;*function=found;return XXEMUL_STATUS_OK;}}
    *base=0u;memset(function,0,sizeof(*function));return XXEMUL_STATUS_OK;
}
