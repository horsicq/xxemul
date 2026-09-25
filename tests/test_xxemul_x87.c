#include "xxemul/xxemul.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int test_compare_flags(void)
{
    static const uint8_t code[] = {
        0xb8, 0x00, 0x11, 0x00, 0x00, /* mov eax, 0x1100 */
        0xd9, 0x00,                   /* fld dword ptr [eax] */
        0xd9, 0x40, 0x04,             /* fld dword ptr [eax+4] */
        0xda, 0xe9,                   /* fucompp */
        0xdf, 0xe0,                   /* fnstsw ax */
        0x9e,                         /* sahf */
        0xcc
    };
    xxemul_config config = {0};
    xxemul_x86_state state;
    xxemul_status status;
    xxemul *emulator;
    float first = 3.0f;
    float second = 2.0f;

    config.arch = XXEMUL_ARCH_X86;
    config.mode = XXEMUL_MODE_X86_32;
    config.region_address = 0x1000u;
    config.entry_address = 0x1000u;
    config.code = code;
    config.code_size = sizeof(code);
    config.region_size = 4096u;
    emulator = xxemul_create(&config, &status);
    if (emulator == NULL) return 0;
    if (xxemul_write_memory(emulator, 0x1100u,
            &first, sizeof(first)) != XXEMUL_STATUS_OK
        || xxemul_write_memory(emulator, 0x1104u,
            &second, sizeof(second)) != XXEMUL_STATUS_OK
        || xxemul_run(emulator, 12u, NULL) != XXEMUL_STATUS_HALTED
        || xxemul_get_x86_state(emulator, &state) != XXEMUL_STATUS_OK
        || (state.flags & 1u) == 0u) {
        xxemul_destroy(emulator);
        return 0;
    }
    xxemul_destroy(emulator);
    return 1;
}

static int test_initialize(void)
{
    static const uint8_t code[] = {
        0xb8, 0x00, 0x11, 0x00, 0x00, /* mov eax, 1100h */
        0xdf, 0x28,                   /* fild qword ptr [eax] */
        0xdb, 0xe3,                   /* fninit */
        0xdf, 0xe0,                   /* fnstsw ax */
        0xcc
    };
    xxemul_config config = {0};
    xxemul_status status;
    xxemul_x86_state state;
    xxemul *emulator;
    int64_t value = 7;
    int ok;

    config.arch = XXEMUL_ARCH_X86;
    config.mode = XXEMUL_MODE_X86_32;
    config.region_address = 0x1000u;
    config.entry_address = 0x1000u;
    config.code = code;
    config.code_size = sizeof(code);
    config.region_size = 4096u;
    emulator = xxemul_create(&config, &status);
    if (emulator == NULL) return 0;
    ok = xxemul_write_memory(emulator, 0x1100u,
            &value, sizeof(value)) == XXEMUL_STATUS_OK
        && xxemul_run(emulator, 8u, NULL) == XXEMUL_STATUS_HALTED
        && xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK
        && (state.gpr[XXEMUL_X86_RAX] & 0xffffu) == 0u;
    xxemul_destroy(emulator);
    return ok;
}

static int test_clear_exceptions_case(const uint8_t *clear_code,
    size_t clear_size)
{
    static const uint8_t prefix[] = {
        0xbb, 0x00, 0x11, 0x00, 0x00, /* mov ebx, 1100h */
        0xd9, 0x6b, 0x0a,             /* fldcw word ptr [ebx+10] */
        0xd9, 0x03,                   /* fld dword ptr [ebx] */
        0xd9, 0xe8,                   /* fld1 */
        0xde, 0xd9,                   /* fcompp */
        0xd9, 0xe8,                   /* fld1 */
        0xdf, 0xe0,                   /* fnstsw ax */
        0x66, 0x89, 0x43, 0x04        /* mov word ptr [ebx+4], ax */
    };
    static const uint8_t suffix[] = {
        0xdf, 0xe0,                   /* fnstsw ax */
        0x66, 0x89, 0x43, 0x06,       /* mov word ptr [ebx+6], ax */
        0xd9, 0x7b, 0x08,             /* fnstcw word ptr [ebx+8] */
        0xdd, 0x5b, 0x0c,             /* fstp qword ptr [ebx+12] */
        0xcc
    };
    uint8_t code[sizeof(prefix) + 3u + sizeof(suffix)];
    xxemul_config config = {0};
    xxemul_status status;
    xxemul *emulator;
    uint32_t nan_bits = UINT32_C(0x7fc00000);
    uint16_t loaded_control = 0x027fu;
    uint16_t before = 0u;
    uint16_t after = 0u;
    uint16_t stored_control = 0u;
    double stack_value = 0.0;
    int ok;

    memcpy(code, prefix, sizeof(prefix));
    memcpy(code + sizeof(prefix), clear_code, clear_size);
    memcpy(code + sizeof(prefix) + clear_size, suffix, sizeof(suffix));
    config.arch = XXEMUL_ARCH_X86;
    config.mode = XXEMUL_MODE_X86_32;
    config.region_address = 0x1000u;
    config.entry_address = 0x1000u;
    config.code = code;
    config.code_size = sizeof(prefix) + clear_size + sizeof(suffix);
    config.region_size = 4096u;
    emulator = xxemul_create(&config, &status);
    if (emulator == NULL) return 0;
    ok = xxemul_write_memory(emulator, 0x1100u,
            &nan_bits, sizeof(nan_bits)) == XXEMUL_STATUS_OK
        && xxemul_write_memory(emulator, 0x110au,
            &loaded_control, sizeof(loaded_control)) == XXEMUL_STATUS_OK
        && xxemul_run(emulator, 20u, NULL) == XXEMUL_STATUS_HALTED
        && xxemul_read_memory(emulator, 0x1104u,
            &before, sizeof(before)) == XXEMUL_STATUS_OK
        && xxemul_read_memory(emulator, 0x1106u,
            &after, sizeof(after)) == XXEMUL_STATUS_OK
        && xxemul_read_memory(emulator, 0x1108u,
            &stored_control, sizeof(stored_control)) == XXEMUL_STATUS_OK
        && xxemul_read_memory(emulator, 0x110cu,
            &stack_value, sizeof(stack_value)) == XXEMUL_STATUS_OK
        && before == 0x7d01u && after == 0x7d00u
        && stored_control == loaded_control && stack_value == 1.0;
    xxemul_destroy(emulator);
    return ok;
}

static int test_clear_exceptions(void)
{
    static const uint8_t fnclex[] = {0xdb, 0xe2};
    static const uint8_t fclex[] = {0x9b, 0xdb, 0xe2};
    return test_clear_exceptions_case(fnclex, sizeof(fnclex))
        && test_clear_exceptions_case(fclex, sizeof(fclex));
}

static int test_control_word(void)
{
    static const uint8_t code[] = {
        0xb8, 0x00, 0x11, 0x00, 0x00, /* mov eax, 1100h */
        0xd9, 0x38,                   /* fnstcw word ptr [eax] */
        0xd9, 0x68, 0x04,             /* fldcw word ptr [eax+4] */
        0xd9, 0x78, 0x02,             /* fnstcw word ptr [eax+2] */
        0xcc
    };
    xxemul_config config = {0};
    xxemul_status status;
    xxemul *emulator;
    uint16_t loaded = 0x027fu;
    uint16_t initial = 0u;
    uint16_t stored = 0u;
    int ok;

    config.arch = XXEMUL_ARCH_X86;
    config.mode = XXEMUL_MODE_X86_32;
    config.region_address = 0x1000u;
    config.entry_address = 0x1000u;
    config.code = code;
    config.code_size = sizeof(code);
    config.region_size = 4096u;
    emulator = xxemul_create(&config, &status);
    if (emulator == NULL) return 0;
    ok = xxemul_write_memory(emulator, 0x1104u,
            &loaded, sizeof(loaded)) == XXEMUL_STATUS_OK
        && xxemul_run(emulator, 8u, NULL) == XXEMUL_STATUS_HALTED
        && xxemul_read_memory(emulator, 0x1100u,
            &initial, sizeof(initial)) == XXEMUL_STATUS_OK
        && xxemul_read_memory(emulator, 0x1102u,
            &stored, sizeof(stored)) == XXEMUL_STATUS_OK
        && initial == 0x037fu && stored == loaded;
    xxemul_destroy(emulator);
    return ok;
}

static int test_constants(void)
{
    static const uint8_t code[] = {
        0xb8, 0x00, 0x11, 0x00, 0x00, /* mov eax, 1100h */
        0xd9, 0xe8,                   /* fld1 */
        0xdd, 0x18,                   /* fstp qword ptr [eax] */
        0xd9, 0xee,                   /* fldz */
        0xdd, 0x58, 0x08,             /* fstp qword ptr [eax+8] */
        0xcc
    };
    xxemul_config config = {0};
    xxemul_status status;
    xxemul *emulator;
    double one = -1.0;
    double zero = -1.0;
    int ok;

    config.arch = XXEMUL_ARCH_X86;
    config.mode = XXEMUL_MODE_X86_32;
    config.region_address = 0x1000u;
    config.entry_address = 0x1000u;
    config.code = code;
    config.code_size = sizeof(code);
    config.region_size = 4096u;
    emulator = xxemul_create(&config, &status);
    if (emulator == NULL) return 0;
    ok = xxemul_run(emulator, 8u, NULL) == XXEMUL_STATUS_HALTED
        && xxemul_read_memory(emulator, 0x1100u,
            &one, sizeof(one)) == XXEMUL_STATUS_OK
        && xxemul_read_memory(emulator, 0x1108u,
            &zero, sizeof(zero)) == XXEMUL_STATUS_OK
        && one == 1.0 && zero == 0.0;
    xxemul_destroy(emulator);
    return ok;
}

static int test_sign_operations(void)
{
    static const uint8_t code[] = {
        0xb8, 0x00, 0x11, 0x00, 0x00, /* mov eax, 1100h */
        0xd9, 0xe8,                   /* fld1 */
        0xd9, 0xe0,                   /* fchs */
        0xdd, 0x18,                   /* fstp qword ptr [eax] */
        0xd9, 0xe8,                   /* fld1 */
        0xd9, 0xe0,                   /* fchs */
        0xd9, 0xe1,                   /* fabs */
        0xdd, 0x58, 0x08,             /* fstp qword ptr [eax+8] */
        0x9b,                         /* wait */
        0xcc
    };
    xxemul_config config = {0};
    xxemul_status status;
    xxemul *emulator;
    double negative = 0.0;
    double positive = 0.0;
    int ok;

    config.arch = XXEMUL_ARCH_X86;
    config.mode = XXEMUL_MODE_X86_32;
    config.region_address = 0x1000u;
    config.entry_address = 0x1000u;
    config.code = code;
    config.code_size = sizeof(code);
    config.region_size = 4096u;
    emulator = xxemul_create(&config, &status);
    if (emulator == NULL) return 0;
    ok = xxemul_run(emulator, 10u, NULL) == XXEMUL_STATUS_HALTED
        && xxemul_read_memory(emulator, 0x1100u,
            &negative, sizeof(negative)) == XXEMUL_STATUS_OK
        && xxemul_read_memory(emulator, 0x1108u,
            &positive, sizeof(positive)) == XXEMUL_STATUS_OK
        && negative == -1.0 && positive == 1.0;
    xxemul_destroy(emulator);
    return ok;
}

int main(void)
{
    static const uint8_t code[] = {
        0xb8, 0x00, 0x11, 0x00, 0x00, /* mov eax, 0x1100 */
        0xdf, 0x28,                   /* fild qword ptr [eax] */
        0xd8, 0x70, 0x10,             /* fdiv dword ptr [eax+16] */
        0xd9, 0x40, 0x14,             /* fld dword ptr [eax+20] */
        0xd9, 0xc9,                   /* fxch st(1) */
        0xde, 0xc1,                   /* faddp st(1), st(0) */
        0xdd, 0x58, 0x08,             /* fstp qword ptr [eax+8] */
        0xcc                          /* int3 */
    };
    xxemul_config config = {0};
    xxemul_status status;
    xxemul *emulator;
    int64_t source = -42;
    float divisor = 2.0f;
    float addend = 2.0f;
    uint64_t stored;
    double result;

    config.arch = XXEMUL_ARCH_X86;
    config.mode = XXEMUL_MODE_X86_32;
    config.region_address = 0x1000u;
    config.entry_address = 0x1000u;
    config.code = code;
    config.code_size = sizeof(code);
    config.region_size = 4096u;
    emulator = xxemul_create(&config, &status);
    if (emulator == NULL) return 1;
    if (xxemul_write_memory(emulator, 0x1100u,
            &source, sizeof(source)) != XXEMUL_STATUS_OK
        || xxemul_write_memory(emulator, 0x1110u,
            &divisor, sizeof(divisor)) != XXEMUL_STATUS_OK
        || xxemul_write_memory(emulator, 0x1114u,
            &addend, sizeof(addend)) != XXEMUL_STATUS_OK
        || xxemul_run(emulator, 8u, NULL) != XXEMUL_STATUS_HALTED
        || xxemul_read_memory(emulator, 0x1108u,
            &stored, sizeof(stored)) != XXEMUL_STATUS_OK) {
        fprintf(stderr, "x87 execution failed\n");
        xxemul_destroy(emulator);
        return 1;
    }
    memcpy(&result, &stored, sizeof(result));
    xxemul_destroy(emulator);
    if (result != -19.0) {
        fprintf(stderr, "x87 result: %g\n", result);
        return 1;
    }
    return !test_compare_flags() || !test_initialize()
        || !test_clear_exceptions()
        || !test_control_word() || !test_constants()
        || !test_sign_operations();
}
