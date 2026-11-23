#include "xxemul_windows_context.h"
#include "../xxemul_internal.h"

#include <math.h>
#include <string.h>

typedef struct win_fp_context {
    uint8_t raw[8][10];
    uint16_t tags;
    double stack[8];
    uint64_t integer[8];
    uint8_t is_integer[8], depth, top;
    uint16_t control, status;
    uint32_t mxcsr;
    uint8_t xmm[16][16];
} win_fp_context;

static uint64_t get(const uint8_t *p, unsigned n)
{
    uint64_t value = 0;
    unsigned i;
    for (i = 0; i < n; ++i) value |= (uint64_t)p[i] << (i * 8u);
    return value;
}

static void put(uint8_t *p, unsigned n, uint64_t value)
{
    unsigned i;
    for (i = 0; i < n; ++i) p[i] = (uint8_t)(value >> (i * 8u));
}

size_t xxemul_windows_context_size(const xxemul *e)
{
    if (!e) return 0;
    if (e->arch == XXEMUL_ARCH_ARM)
        return e->mode == XXEMUL_MODE_ARM_A64 ? XXEMUL_WINDOWS_CONTEXT_ARM64_SIZE : XXEMUL_WINDOWS_CONTEXT_ARM32_SIZE;
    if (e->arch != XXEMUL_ARCH_X86) return 0;
    return e->mode == XXEMUL_MODE_X86_32 ? XXEMUL_WINDOWS_CONTEXT32_SIZE
        : e->mode == XXEMUL_MODE_X86_64 ? XXEMUL_WINDOWS_CONTEXT64_SIZE : 0;
}

uint32_t xxemul_windows_context_all(const xxemul *e)
{
    size_t n = xxemul_windows_context_size(e);
    return n == XXEMUL_WINDOWS_CONTEXT32_SIZE ? XXEMUL_WINDOWS_CONTEXT32_ALL
        : n == XXEMUL_WINDOWS_CONTEXT64_SIZE ? XXEMUL_WINDOWS_CONTEXT64_ALL
        : n == XXEMUL_WINDOWS_CONTEXT_ARM32_SIZE ? XXEMUL_WINDOWS_CONTEXT_ARM32_ALL
        : n == XXEMUL_WINDOWS_CONTEXT_ARM64_SIZE ? XXEMUL_WINDOWS_CONTEXT_ARM64_ALL : 0;
}

static xxemul_status flags_valid(const xxemul *e, uint32_t flags)
{
    uint32_t all = xxemul_windows_context_all(e);
    uint32_t architecture = all & UINT32_C(0xffff0000);
    if (!all || (flags & UINT32_C(0x00ff0000)) != architecture || !(flags & (all & 0xffu)))
        return XXEMUL_STATUS_INVALID_ARGUMENT;
    /* Exception/service annotations do not request additional CPU registers. */
    if (flags & ~(all | UINT32_C(0xd8000000))) return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    return XXEMUL_STATUS_OK;
}

static void fp_load(const xxemul *e, win_fp_context *fp)
{
    memcpy(fp->raw, e->x87_raw, sizeof(fp->raw)); fp->tags = e->x87_tags;
    memcpy(fp->stack, e->x87_stack, sizeof(fp->stack));
    memcpy(fp->integer, e->x87_int_val, sizeof(fp->integer));
    memcpy(fp->is_integer, e->x87_is_int, sizeof(fp->is_integer));
    fp->depth = e->x87_depth; fp->top = e->x87_top;
    fp->control = e->x87_control; fp->status = e->x87_status;
    fp->mxcsr = e->x86_mxcsr;
    memcpy(fp->xmm, e->x86.xmm, sizeof(fp->xmm));
}

static void fp_store(xxemul *e, const win_fp_context *fp)
{
    memcpy(e->x87_raw, fp->raw, sizeof(fp->raw)); e->x87_tags = fp->tags;
    memcpy(e->x87_stack, fp->stack, sizeof(fp->stack));
    memcpy(e->x87_int_val, fp->integer, sizeof(fp->integer));
    memcpy(e->x87_is_int, fp->is_integer, sizeof(fp->is_integer));
    e->x87_depth = fp->depth; e->x87_top = fp->top;
    e->x87_control = fp->control; e->x87_status = fp->status;
    e->x86_mxcsr = fp->mxcsr;
    memcpy(e->x86.xmm, fp->xmm, sizeof(fp->xmm));
}

static unsigned high_bit(uint64_t value)
{
    unsigned bit = 0;
    while (value >>= 1u) ++bit;
    return bit;
}

/* Convert the core's represented binary64/exact signed integers to the
 * architectural little-endian 80-bit register format without host ABI casts. */
static void encode80(const win_fp_context *fp, unsigned index, uint8_t *out)
{
    uint64_t mantissa = 0, bits;
    uint16_t exponent = 0;
    unsigned sign, bit, exp;
    if (fp->is_integer[index]) {
        bits = fp->integer[index]; sign = (unsigned)(bits >> 63u);
        if (sign) bits = ~bits + 1u;
        if (bits) { bit = high_bit(bits); mantissa = bits << (63u - bit); exponent = (uint16_t)(16383u + bit); }
    } else {
        memcpy(&bits, &fp->stack[index], sizeof(bits));
        sign = (unsigned)(bits >> 63u); exp = (unsigned)((bits >> 52u) & 0x7ffu);
        bits &= UINT64_C(0x000fffffffffffff);
        if (exp == 0x7ffu) {
            exponent = 0x7fffu; mantissa = UINT64_C(0x8000000000000000) | (bits << 11u);
        } else if (exp) {
            exponent = (uint16_t)(exp + 16383u - 1023u);
            mantissa = (UINT64_C(0x0010000000000000) | bits) << 11u;
        } else if (bits) {
            bit = high_bit(bits); exponent = (uint16_t)(16383 + (int)bit - 1074);
            mantissa = bits << (63u - bit);
        }
    }
    put(out, 8u, mantissa); put(out + 8u, 2u, exponent | (sign << 15u));
}

static void decode80(win_fp_context *fp, unsigned index, const uint8_t *in)
{
    uint64_t mantissa = get(in, 8u), magnitude = 0;
    uint16_t se = (uint16_t)get(in + 8u, 2u);
    unsigned exp = se & 0x7fffu, sign = se >> 15u;
    int power = (int)exp - 16383;
    double value;
    fp->is_integer[index] = 0; fp->integer[index] = 0;
    if (exp == 0x7fffu) value = (mantissa & UINT64_C(0x7fffffffffffffff)) ? NAN : INFINITY;
    else value = ldexp((double)mantissa, (exp ? power : 1 - 16383) - 63);
    if (sign) value = -value;
    fp->stack[index] = value;
    if (exp && exp != 0x7fffu && power >= 0 && power <= 63) {
        unsigned shift = 63u - (unsigned)power;
        uint64_t fraction = shift ? mantissa & ((UINT64_C(1) << shift) - 1u) : 0;
        if (!fraction) {
            magnitude = mantissa >> shift;
            if ((!sign && magnitude <= INT64_MAX) || (sign && magnitude <= UINT64_C(0x8000000000000000))) {
                fp->integer[index] = sign ? ~magnitude + 1u : magnitude;
                fp->is_integer[index] = 1;
            }
        }
    }
}

static unsigned fp_tag(const win_fp_context *fp, unsigned logical)
{
    if (logical >= fp->depth) return 3u;
    if (fp->is_integer[logical]) return fp->integer[logical] ? 0u : 1u;
    return fp->stack[logical] == 0.0 ? 1u : isfinite(fp->stack[logical]) ? 0u : 2u;
}

static unsigned raw_tag(const uint8_t raw[10])
{
    uint64_t significand = get(raw, 8u);
    unsigned exponent = (unsigned)get(raw + 8u, 2u) & 0x7fffu;
    if (!exponent && !significand) return 1u;
    if (!exponent || exponent == 0x7fffu || !(significand >> 63u)) return 2u;
    return 0u;
}

/* Legacy saves reconstruct the class of every nonempty physical register.
 * MMX sets internal tags to valid, but FNSTENV/FSAVE classify its raw bits
 * (usually special), unlike the one-bit-per-register FX abridged tag. */
static uint16_t full_tag(const win_fp_context *fp)
{
    uint16_t tags = 0;
    unsigned i;
    for (i = 0; i < 8u; ++i) {
        unsigned tag = ((fp->tags >> (i * 2u)) & 3u) == 3u ? 3u : raw_tag(fp->raw[i]);
        tags |= (uint16_t)(tag << (i * 2u));
    }
    return tags;
}

uint16_t xxemul_x87_saved_tags(const xxemul *e)
{
    win_fp_context fp;
    fp_load(e, &fp);
    return full_tag(&fp);
}

/* The wire data slots are logical ST(i); the tag fields are physical. */
static xxemul_status decode_stack(win_fp_context *fp, const uint8_t *registers,
                                  unsigned stride, uint16_t tag)
{
    unsigned i;
    fp->tags = tag;
    for (i = 0; i < 8u; ++i) memcpy(fp->raw[(fp->top + i) & 7u], registers + i * stride, 10u);
    return XXEMUL_STATUS_OK;
}

/* Bridge only the previously supported numeric subset. Raw state is never
 * rounded or canonicalized merely by a save, restore, MMX op or context copy.
 * Holes, inconsistent full tags and unrepresented extended precision fail
 * before an arithmetic instruction can mutate guest registers or memory. */
xxemul_status xxemul_x87_prepare_numeric(xxemul *e)
{
    win_fp_context fp;
    unsigned i;
    int empty = 0;
    uint8_t encoded[10];
    fp_load(e, &fp);
    /* Every physical tag empty means there is no raw register state to bridge.
     * Keep the numeric cache untouched so a faulting arithmetic instruction
     * (e.g. FDIV m32fp that raises #PF on its operand read) leaves the register
     * file, and therefore a restart, exactly as it found it. */
    if (fp.tags == UINT16_C(0xffff) && e->x87_depth != 0u) return XXEMUL_STATUS_OK;
    fp.depth = 0;
    memset(fp.stack, 0, sizeof(fp.stack)); memset(fp.integer, 0, sizeof(fp.integer));
    memset(fp.is_integer, 0, sizeof(fp.is_integer));
    for (i = 0; i < 8u; ++i) {
        unsigned physical = (fp.top + i) & 7u;
        unsigned tag = (fp.tags >> (physical * 2u)) & 3u;
        if (tag == 3u) { empty = 1; continue; }
        if (empty) return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
        decode80(&fp, i, fp.raw[physical]); ++fp.depth;
        encode80(&fp, i, encoded);
        if (fp_tag(&fp, i) != tag || memcmp(encoded, fp.raw[physical], 10u))
            return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    }
    memcpy(e->x87_stack, fp.stack, sizeof(fp.stack));
    memcpy(e->x87_int_val, fp.integer, sizeof(fp.integer));
    memcpy(e->x87_is_int, fp.is_integer, sizeof(fp.is_integer)); e->x87_depth = fp.depth;
    return XXEMUL_STATUS_OK;
}

/* Called only after a completed numeric x87 instruction. Empty physical
 * payloads retain their previous bits, including a just-popped register. */
void xxemul_x87_commit_numeric(xxemul *e)
{
    win_fp_context fp;
    unsigned i;
    fp_load(e, &fp); fp.tags = UINT16_C(0xffff);
    for (i = 0; i < fp.depth; ++i) {
        unsigned physical = (fp.top + i) & 7u;
        encode80(&fp, i, fp.raw[physical]);
        fp.tags = (uint16_t)((fp.tags & ~(3u << (physical * 2u))) | (fp_tag(&fp, i) << (physical * 2u)));
    }
    memcpy(e->x87_raw, fp.raw, sizeof(fp.raw)); e->x87_tags = fp.tags;
}

static void encode_fx(const win_fp_context *fp, uint8_t *out, unsigned xmm_count)
{
    unsigned i;
    memset(out, 0, 512u);
    put(out, 2u, fp->control);
    put(out + 2u, 2u, (fp->status & 0xc7ffu) | ((unsigned)fp->top << 11u));
    for (i = 0; i < 8u; ++i) if (((fp->tags >> (i * 2u)) & 3u) != 3u) out[4] |= (uint8_t)(1u << i);
    put(out + 24u, 4u, fp->mxcsr); put(out + 28u, 4u, 0xffffu);
    for (i = 0; i < 8u; ++i) memcpy(out + 32u + i * 16u, fp->raw[(fp->top + i) & 7u], 10u);
    memcpy(out + 160u, fp->xmm, xmm_count * 16u);
}

static xxemul_status decode_fx(win_fp_context *fp, const uint8_t *in, unsigned xmm_count)
{
    uint16_t tags = 0;
    unsigned i;
    if (get(in + 24u, 4u) & UINT32_C(0xffff0000)) return XXEMUL_STATUS_INVALID_ARGUMENT;
    fp->control = (uint16_t)get(in, 2u); fp->status = (uint16_t)get(in + 2u, 2u);
    fp->top = (uint8_t)((fp->status >> 11u) & 7u);
    fp->mxcsr = (uint32_t)get(in + 24u, 4u);
    for (i = 0; i < 8u; ++i) {
        unsigned physical = (fp->top + i) & 7u;
        unsigned tag = in[4] & (1u << physical) ? raw_tag(in + 32u + i * 16u) : 3u;
        tags |= (uint16_t)(tag << (physical * 2u));
    }
    memcpy(fp->xmm, in + 160u, xmm_count * 16u);
    return decode_stack(fp, in + 32u, 16u, tags);
}

xxemul_status xxemul_windows_fxsave(const xxemul *e, uint8_t bytes[512])
{
    win_fp_context fp;
    if (!e || !bytes || e->arch != XXEMUL_ARCH_X86 || !xxemul_windows_context_size(e)) return XXEMUL_STATUS_INVALID_ARGUMENT;
    fp_load(e, &fp); encode_fx(&fp, bytes, e->mode == XXEMUL_MODE_X86_64 ? 16u : 8u);
    return XXEMUL_STATUS_OK;
}

xxemul_status xxemul_windows_fxrstor(xxemul *e, const uint8_t bytes[512])
{
    win_fp_context fp;
    xxemul_status status;
    if (!e || !bytes || e->arch != XXEMUL_ARCH_X86 || !xxemul_windows_context_size(e)) return XXEMUL_STATUS_INVALID_ARGUMENT;
    fp_load(e, &fp); status = decode_fx(&fp, bytes, e->mode == XXEMUL_MODE_X86_64 ? 16u : 8u);
    if (status == XXEMUL_STATUS_OK) fp_store(e, &fp);
    return status;
}

xxemul_status xxemul_x87_legacy_save(const xxemul *e, uint8_t *bytes, size_t size)
{
    win_fp_context fp;
    unsigned stride, environment, i;
    if (!e || !bytes || e->arch != XXEMUL_ARCH_X86 || (size != 94u && size != 108u)) return XXEMUL_STATUS_INVALID_ARGUMENT;
    fp_load(e, &fp);
    stride = size == 94u ? 2u : 4u; environment = size == 94u ? 14u : 28u;
    memset(bytes, 0, size);
    put(bytes, 2u, fp.control);
    put(bytes + stride, 2u, (fp.status & 0xc7ffu) | ((unsigned)fp.top << 11u));
    put(bytes + stride * 2u, 2u, full_tag(&fp));
    for (i = 0u; i < 8u; ++i) memcpy(bytes + environment + i * 10u, fp.raw[(fp.top + i) & 7u], 10u);
    return XXEMUL_STATUS_OK;
}

xxemul_status xxemul_x87_legacy_restore(xxemul *e, const uint8_t *bytes, size_t size)
{
    win_fp_context fp;
    uint16_t tag;
    unsigned stride, environment, i;
    xxemul_status status;
    if (!e || !bytes || e->arch != XXEMUL_ARCH_X86 || (size != 94u && size != 108u)) return XXEMUL_STATUS_INVALID_ARGUMENT;
    stride = size == 94u ? 2u : 4u; environment = size == 94u ? 14u : 28u;
    /* The current core does not retain x87 instruction/data pointers or the
     * last opcode. Refuse a nonzero image instead of silently discarding it. */
    for (i = stride * 3u; i < environment; ++i) if (bytes[i]) return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    fp_load(e, &fp);
    fp.control = (uint16_t)get(bytes, 2u); fp.status = (uint16_t)get(bytes + stride, 2u);
    fp.top = (uint8_t)((fp.status >> 11u) & 7u); tag = (uint16_t)get(bytes + stride * 2u, 2u);
    status = decode_stack(&fp, bytes + environment, 10u, tag);
    if (status != XXEMUL_STATUS_OK) return status;
    fp_store(e, &fp);
    return XXEMUL_STATUS_OK;
}

xxemul_status xxemul_windows_context_capture(const xxemul *e,
                                            const xxemul_x86_state *override_cpu,
                                            uint8_t *bytes, size_t size, uint32_t flags)
{
    static const uint8_t integer32[6] = {7, 6, 3, 2, 1, 0};
    static const unsigned segment32[6] = {0x94u, 0xbcu, 0xc8u, 0x98u, 0x90u, 0x8cu};
    static const unsigned segment64[6] = {0x3cu, 0x38u, 0x42u, 0x3au, 0x3eu, 0x40u};
    const xxemul_x86_state *cpu;
    win_fp_context fp;
    unsigned i;
    size_t needed = xxemul_windows_context_size(e);
    xxemul_status status = flags_valid(e, flags);
    if (e && e->arch == XXEMUL_ARCH_ARM) {
        if (override_cpu) return XXEMUL_STATUS_INVALID_ARGUMENT;
        return xxemul_windows_context_capture_arm(e, NULL, bytes, size, flags);
    }
    if (!bytes || !needed || size < needed) return XXEMUL_STATUS_INVALID_ARGUMENT;
    if (status != XXEMUL_STATUS_OK) return status;
    cpu = override_cpu ? override_cpu : &e->x86;
    fp_load(e, &fp); memcpy(fp.xmm, cpu->xmm, sizeof(fp.xmm));
    if (e->mode == XXEMUL_MODE_X86_32) {
        put(bytes, 4u, flags);
        if (flags & 1u) {
            put(bytes + 0xb4u, 4u, cpu->gpr[5]); put(bytes + 0xb8u, 4u, cpu->ip);
            put(bytes + 0xc0u, 4u, cpu->flags); put(bytes + 0xc4u, 4u, cpu->gpr[4]);
            put(bytes + 0xbcu, 4u, cpu->segment[1]); put(bytes + 0xc8u, 4u, cpu->segment[2]);
        }
        if (flags & 2u) for (i = 0; i < 6u; ++i) put(bytes + 0x9cu + i * 4u, 4u, cpu->gpr[integer32[i]]);
        if (flags & 4u) for (i = 0; i < 6u; ++i) if (i != 1u && i != 2u) put(bytes + segment32[i], 4u, cpu->segment[i]);
        if (flags & 8u) {
            memset(bytes + 0x1cu, 0, 0x70u);
            put(bytes + 0x1cu, 4u, fp.control);
            put(bytes + 0x20u, 4u, (fp.status & 0xc7ffu) | ((unsigned)fp.top << 11u));
            put(bytes + 0x24u, 4u, full_tag(&fp));
            for (i = 0; i < 8u; ++i) memcpy(bytes + 0x38u + i * 10u, fp.raw[(fp.top + i) & 7u], 10u);
        }
        if (flags & 0x10u) for (i = 0; i < 6u; ++i) put(bytes + 4u + i * 4u, 4u, e->x86_debug[i]);
        if (flags & 0x20u) encode_fx(&fp, bytes + 0xccu, 8u);
    } else {
        put(bytes + 0x30u, 4u, flags);
        if (flags & 1u) {
            put(bytes + 0x38u, 2u, cpu->segment[1]); put(bytes + 0x42u, 2u, cpu->segment[2]);
            put(bytes + 0x44u, 4u, cpu->flags); put(bytes + 0x98u, 8u, cpu->gpr[4]);
            put(bytes + 0xf8u, 8u, cpu->ip);
        }
        if (flags & 2u) for (i = 0; i < 16u; ++i) if (i != 4u) put(bytes + 0x78u + i * 8u, 8u, cpu->gpr[i]);
        if (flags & 4u) for (i = 0; i < 6u; ++i) if (i != 1u && i != 2u) put(bytes + segment64[i], 2u, cpu->segment[i]);
        if (flags & 8u) { encode_fx(&fp, bytes + 0x100u, 16u); put(bytes + 0x34u, 4u, fp.mxcsr); }
        if (flags & 0x10u) for (i = 0; i < 6u; ++i) put(bytes + 0x48u + i * 8u, 8u, e->x86_debug[i]);
    }
    return XXEMUL_STATUS_OK;
}

xxemul_status xxemul_windows_context_capture_arm(const xxemul *e,
                                                const xxemul_arm_state *override_cpu,
                                                uint8_t *bytes, size_t size, uint32_t flags)
{
    const xxemul_arm_state *cpu;
    size_t needed = xxemul_windows_context_size(e);
    unsigned i;
    xxemul_status status = flags_valid(e, flags);
    if (!e || e->arch != XXEMUL_ARCH_ARM || !bytes || size < needed || !needed) return XXEMUL_STATUS_INVALID_ARGUMENT;
    if (status != XXEMUL_STATUS_OK) return status;
    cpu = override_cpu ? override_cpu : &e->arm;
    put(bytes, 4u, flags);
    if (e->mode == XXEMUL_MODE_ARM_A64) {
        if (flags & 1u) {
            put(bytes + 4u, 4u, cpu->pstate); put(bytes + 0xf0u, 8u, cpu->gpr[29]);
            put(bytes + 0xf8u, 8u, cpu->gpr[30]); put(bytes + 0x100u, 8u, cpu->sp);
            put(bytes + 0x108u, 8u, cpu->pc);
        }
        if (flags & 2u) for (i = 0; i < 29u; ++i) put(bytes + 8u + i * 8u, 8u, cpu->gpr[i]);
        if (flags & 4u) {
            memcpy(bytes + 0x110u, cpu->v, sizeof(cpu->v));
            put(bytes + 0x310u, 4u, cpu->fpcr); put(bytes + 0x314u, 4u, cpu->fpsr);
        }
        if (flags & 8u) {
            for (i = 0; i < 8u; ++i) { put(bytes + 0x318u + i * 4u, 4u, e->arm_break_control[i]); put(bytes + 0x338u + i * 8u, 8u, e->arm_break_value[i]); }
            for (i = 0; i < 2u; ++i) { put(bytes + 0x378u + i * 4u, 4u, e->arm_watch_control[i]); put(bytes + 0x380u + i * 8u, 8u, e->arm_watch_value[i]); }
        }
    } else {
        if (flags & 1u) {
            put(bytes + 0x38u, 4u, cpu->sp); put(bytes + 0x3cu, 4u, cpu->gpr[14]);
            put(bytes + 0x40u, 4u, cpu->pc); put(bytes + 0x44u, 4u, cpu->pstate);
        }
        if (flags & 2u) for (i = 0; i < 13u; ++i) put(bytes + 4u + i * 4u, 4u, cpu->gpr[i]);
        if (flags & 4u) {
            put(bytes + 0x48u, 4u, cpu->fpcr | cpu->fpsr);
            for (i = 0; i < 32u; ++i) memcpy(bytes + 0x50u + i * 8u, cpu->v[i], 8u);
        }
        if (flags & 8u) {
            for (i = 0; i < 8u; ++i) { put(bytes + 0x150u + i * 4u, 4u, e->arm_break_value[i]); put(bytes + 0x170u + i * 4u, 4u, e->arm_break_control[i]); }
            put(bytes + 0x190u, 4u, e->arm_watch_value[0]); put(bytes + 0x194u, 4u, e->arm_watch_control[0]);
        }
    }
    return XXEMUL_STATUS_OK;
}

static xxemul_status decode_arm_context(const xxemul *e, const uint8_t *bytes, size_t size,
                                        xxemul_arm_state *cpu)
{
    uint32_t flags, fpscr;
    unsigned i;
    size_t needed = xxemul_windows_context_size(e);
    xxemul_status status;
    if (!e || e->arch != XXEMUL_ARCH_ARM || !bytes || !needed || size < needed) return XXEMUL_STATUS_INVALID_ARGUMENT;
    flags = (uint32_t)get(bytes, 4u); status = flags_valid(e, flags);
    if (status != XXEMUL_STATUS_OK) return status;
    *cpu = e->arm;
    if (e->mode == XXEMUL_MODE_ARM_A64) {
        if (flags & 1u) {
            cpu->pstate = (uint32_t)get(bytes + 4u, 4u) & UINT32_C(0xf3201c00);
            cpu->gpr[29] = get(bytes + 0xf0u, 8u); cpu->gpr[30] = get(bytes + 0xf8u, 8u);
            cpu->sp = get(bytes + 0x100u, 8u); cpu->pc = get(bytes + 0x108u, 8u);
            if ((cpu->pc & 3u) || (cpu->sp & 15u)) return XXEMUL_STATUS_INVALID_ARGUMENT;
        }
        if (flags & 2u) for (i = 0; i < 29u; ++i) cpu->gpr[i] = get(bytes + 8u + i * 8u, 8u);
        if (flags & 4u) {
            memcpy(cpu->v, bytes + 0x110u, sizeof(cpu->v));
            cpu->fpcr = (uint32_t)get(bytes + 0x310u, 4u); cpu->fpsr = (uint32_t)get(bytes + 0x314u, 4u);
        }
    } else {
        if (flags & 1u) {
            cpu->pstate = ((uint32_t)get(bytes + 0x44u, 4u) & UINT32_C(0xfe0ffc20)) | 0x10u;
            cpu->sp = get(bytes + 0x38u, 4u); cpu->gpr[14] = get(bytes + 0x3cu, 4u);
            cpu->pc = get(bytes + 0x40u, 4u) & ~UINT64_C(1);
            if ((cpu->sp & 3u) || (!(cpu->pstate & 0x20u) && (cpu->pc & 3u))) return XXEMUL_STATUS_INVALID_ARGUMENT;
        }
        if (flags & 2u) for (i = 0; i < 13u; ++i) cpu->gpr[i] = get(bytes + 4u + i * 4u, 4u);
        if (flags & 4u) {
            fpscr = (uint32_t)get(bytes + 0x48u, 4u);
            cpu->fpcr = fpscr & UINT32_C(0x07c09f00); cpu->fpsr = fpscr & UINT32_C(0xf80000ff);
            for (i = 0; i < 32u; ++i) memcpy(cpu->v[i], bytes + 0x50u + i * 8u, 8u);
        }
    }
    return XXEMUL_STATUS_OK;
}

static void restore_arm_debug(xxemul *e, const uint8_t *bytes)
{
    unsigned i;
    if (!(get(bytes, 4u) & 8u)) return;
    if (e->mode == XXEMUL_MODE_ARM_A64) {
        for (i = 0; i < 8u; ++i) { e->arm_break_control[i] = (uint32_t)get(bytes + 0x318u + i * 4u, 4u); e->arm_break_value[i] = get(bytes + 0x338u + i * 8u, 8u); }
        for (i = 0; i < 2u; ++i) { e->arm_watch_control[i] = (uint32_t)get(bytes + 0x378u + i * 4u, 4u); e->arm_watch_value[i] = get(bytes + 0x380u + i * 8u, 8u); }
    } else {
        for (i = 0; i < 8u; ++i) { e->arm_break_value[i] = get(bytes + 0x150u + i * 4u, 4u); e->arm_break_control[i] = (uint32_t)get(bytes + 0x170u + i * 4u, 4u); }
        e->arm_watch_value[0] = get(bytes + 0x190u, 4u); e->arm_watch_control[0] = (uint32_t)get(bytes + 0x194u, 4u);
    }
}

static xxemul_status decode_context(const xxemul *e, const uint8_t *bytes, size_t size,
                                    xxemul_x86_state *cpu, win_fp_context *fp,
                                    uint64_t debug[6])
{
    static const uint8_t integer32[6] = {7, 6, 3, 2, 1, 0};
    static const unsigned segment32[6] = {0x94u, 0xbcu, 0xc8u, 0x98u, 0x90u, 0x8cu};
    static const unsigned segment64[6] = {0x3cu, 0x38u, 0x42u, 0x3au, 0x3eu, 0x40u};
    size_t needed = xxemul_windows_context_size(e);
    uint32_t flags;
    unsigned i;
    xxemul_status status;
    if (!bytes || !needed || size < needed) return XXEMUL_STATUS_INVALID_ARGUMENT;
    flags = (uint32_t)get(bytes + (e->mode == XXEMUL_MODE_X86_64 ? 0x30u : 0u), 4u);
    status = flags_valid(e, flags);
    if (status != XXEMUL_STATUS_OK) return status;
    *cpu = e->x86; fp_load(e, fp); memcpy(debug, e->x86_debug, 6u * sizeof(uint64_t));
    if (e->mode == XXEMUL_MODE_X86_32) {
        if (flags & 1u) {
            cpu->gpr[5] = get(bytes + 0xb4u, 4u); cpu->ip = get(bytes + 0xb8u, 4u);
            cpu->flags = get(bytes + 0xc0u, 4u); cpu->gpr[4] = get(bytes + 0xc4u, 4u);
            cpu->segment[1] = (uint16_t)get(bytes + 0xbcu, 4u); cpu->segment[2] = (uint16_t)get(bytes + 0xc8u, 4u);
        }
        if (flags & 2u) for (i = 0; i < 6u; ++i) cpu->gpr[integer32[i]] = get(bytes + 0x9cu + i * 4u, 4u);
        if (flags & 4u) for (i = 0; i < 6u; ++i) if (i != 1u && i != 2u) cpu->segment[i] = (uint16_t)get(bytes + segment32[i], 4u);
        if (flags & 8u) {
            fp->control = (uint16_t)get(bytes + 0x1cu, 4u); fp->status = (uint16_t)get(bytes + 0x20u, 4u);
            fp->top = (uint8_t)((fp->status >> 11u) & 7u);
            status = decode_stack(fp, bytes + 0x38u, 10u, (uint16_t)get(bytes + 0x24u, 4u));
            if (status != XXEMUL_STATUS_OK && !(flags & 0x20u)) return status;
        }
        if (flags & 0x10u) for (i = 0; i < 6u; ++i) debug[i] = get(bytes + 4u + i * 4u, 4u);
        if (flags & 0x20u) { status = decode_fx(fp, bytes + 0xccu, 8u); if (status != XXEMUL_STATUS_OK) return status; }
    } else {
        if (flags & 1u) {
            cpu->segment[1] = (uint16_t)get(bytes + 0x38u, 2u); cpu->segment[2] = (uint16_t)get(bytes + 0x42u, 2u);
            cpu->flags = get(bytes + 0x44u, 4u); cpu->gpr[4] = get(bytes + 0x98u, 8u); cpu->ip = get(bytes + 0xf8u, 8u);
            if ((cpu->ip >> 47u) != 0u && (cpu->ip >> 47u) != 0x1ffffu) return XXEMUL_STATUS_INVALID_ARGUMENT;
            if ((cpu->gpr[4] >> 47u) != 0u && (cpu->gpr[4] >> 47u) != 0x1ffffu) return XXEMUL_STATUS_INVALID_ARGUMENT;
        }
        if (flags & 2u) for (i = 0; i < 16u; ++i) if (i != 4u) cpu->gpr[i] = get(bytes + 0x78u + i * 8u, 8u);
        if (flags & 4u) for (i = 0; i < 6u; ++i) if (i != 1u && i != 2u) cpu->segment[i] = (uint16_t)get(bytes + segment64[i], 2u);
        if (flags & 8u) {
            status = decode_fx(fp, bytes + 0x100u, 16u);
            if (status != XXEMUL_STATUS_OK) return status;
            fp->mxcsr = (uint32_t)get(bytes + 0x34u, 4u);
            if (fp->mxcsr & UINT32_C(0xffff0000)) return XXEMUL_STATUS_INVALID_ARGUMENT;
        }
        if (flags & 0x10u) for (i = 0; i < 6u; ++i) debug[i] = get(bytes + 0x48u + i * 8u, 8u);
    }
    if (flags & 1u) cpu->flags = (cpu->flags & UINT64_C(0x00250dd5)) | UINT64_C(0x202);
    memcpy(cpu->xmm, fp->xmm, sizeof(cpu->xmm));
    return XXEMUL_STATUS_OK;
}

xxemul_status xxemul_windows_context_validate(const xxemul *e, const uint8_t *bytes, size_t size)
{
    xxemul_x86_state cpu;
    win_fp_context fp;
    uint64_t debug[6];
    if (e && e->arch == XXEMUL_ARCH_ARM) { xxemul_arm_state arm; return decode_arm_context(e, bytes, size, &arm); }
    return decode_context(e, bytes, size, &cpu, &fp, debug);
}

xxemul_status xxemul_windows_context_restore(xxemul *e, const uint8_t *bytes, size_t size)
{
    xxemul_x86_state cpu;
    win_fp_context fp;
    uint64_t debug[6];
    if (e && e->arch == XXEMUL_ARCH_ARM) {
        xxemul_arm_state arm;
        xxemul_status arm_status = decode_arm_context(e, bytes, size, &arm);
        if (arm_status == XXEMUL_STATUS_OK) {
            e->arm = arm; restore_arm_debug(e, bytes); e->halted = 0;
            if (e->mode != XXEMUL_MODE_ARM_A64) e->mode = arm.pstate & 0x20u ? XXEMUL_MODE_ARM_T32 : XXEMUL_MODE_ARM_A32;
        }
        return arm_status;
    }
    xxemul_status status = decode_context(e, bytes, size, &cpu, &fp, debug);
    if (status == XXEMUL_STATUS_OK) {
        e->x86 = cpu; fp_store(e, &fp); memcpy(e->x86_debug, debug, sizeof(debug));
        e->halted = 0;
    }
    return status;
}
