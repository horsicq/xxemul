#include "xxemul/xxemul.h"
#include "../src/xxemul_internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(expression)                                                     \
    do {                                                                      \
        if (!(expression)) {                                                  \
            fprintf(stderr, "%s:%d: check failed: %s\n",                    \
                __FILE__, __LINE__, #expression);                             \
            return 0;                                                         \
        }                                                                     \
    } while (0)

typedef struct output_capture {
    uint8_t bytes[16];
    size_t size;
} output_capture;

static void capture_output(void *context, uint8_t byte)
{
    output_capture *capture = (output_capture *)context;
    if (capture->size < sizeof(capture->bytes)) {
        capture->bytes[capture->size++] = byte;
    }
}

static xxemul *create_emulator(
    xxemul_arch arch,
    xxemul_mode mode,
    uint64_t address,
    const uint8_t *code,
    size_t code_size)
{
    xxemul_config config;
    xxemul_status status;
    xxemul *emulator;

    memset(&config, 0, sizeof(config));
    config.arch = arch;
    config.mode = mode;
    config.region_address = address;
    config.entry_address = address;
    config.code = code;
    config.code_size = code_size;
    config.region_size = 4096u;
    emulator = xxemul_create(&config, &status);
    if (emulator == NULL) {
        fprintf(stderr, "create failed: %s\n", xxemul_status_string(status));
    }
    return emulator;
}

static int test_x86_64(void)
{
    static const uint8_t code[] = {
        0xb8, 0x05, 0x00, 0x00, 0x00, /* mov eax, 5 */
        0x83, 0xc0, 0x03,             /* add eax, 3 */
        0x83, 0xf8, 0x08,             /* cmp eax, 8 */
        0x75, 0x05,                   /* jne +5 */
        0xbb, 0x09, 0x00, 0x00, 0x00, /* mov ebx, 9 */
        0xcc                          /* int3 */
    };
    xxemul_x86_state state;
    xxemul_status status;
    xxemul *emulator = create_emulator(
        XXEMUL_ARCH_X86, XXEMUL_MODE_X86_64,
        UINT64_C(0x1000), code, sizeof(code));
    uint64_t executed = 0;
    char text[64];

    CHECK(emulator != NULL);
    CHECK(xxemul_format_current(emulator, text, sizeof(text)) > 0u);
    CHECK(strstr(text, "mov") != NULL);
    status = xxemul_run(emulator, 16u, &executed);
    CHECK(status == XXEMUL_STATUS_HALTED);
    CHECK(executed == 6u);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK(state.gpr[XXEMUL_X86_RAX] == 8u);
    CHECK(state.gpr[XXEMUL_X86_RBX] == 9u);
    CHECK((state.flags & (UINT64_C(1) << 6)) != 0u);
    executed = UINT64_MAX;
    status = xxemul_run(emulator, 1u, &executed);
    CHECK(status == XXEMUL_STATUS_HALTED);
    CHECK(executed == 0u);
    xxemul_destroy(emulator);
    return 1;
}

static int test_x86_pxor(void)
{
    static const uint8_t code[] = {0x66, 0x0f, 0xef, 0xc1, 0xcc};
    xxemul *emulator = create_emulator(
        XXEMUL_ARCH_X86, XXEMUL_MODE_X86_64,
        UINT64_C(0x1000), code, sizeof(code));
    xxemul_x86_state state;
    size_t index;

    CHECK(emulator != NULL);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    for (index = 0u; index < 16u; ++index) {
        state.xmm[0][index] = 0xffu;
        state.xmm[1][index] = (uint8_t)index;
    }
    CHECK(xxemul_set_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    for (index = 0u; index < 16u; ++index)
        CHECK(state.xmm[0][index] == (uint8_t)(0xffu ^ index));
    xxemul_destroy(emulator);
    return 1;
}

static int test_x86_packed_equal(void)
{
    static const uint8_t code[] = {
        0x66, 0x0f, 0x76, 0xc0,
        0x66, 0x0f, 0x74, 0x08,
        0xcc
    };
    xxemul *emulator = create_emulator(XXEMUL_ARCH_X86,
        XXEMUL_MODE_X86_64, 0x1000u, code, sizeof(code));
    xxemul_x86_state state;
    uint8_t source[16];
    size_t index;

    CHECK(emulator != NULL);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    state.gpr[XXEMUL_X86_RAX] = 0x1100u;
    for (index = 0u; index < sizeof(source); ++index) {
        state.xmm[1][index] = (uint8_t)index;
        source[index] = (uint8_t)(index + (index % 3u == 0u));
    }
    CHECK(xxemul_set_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK(xxemul_write_memory(emulator, 0x1100u,
        source, sizeof(source)) == XXEMUL_STATUS_OK);
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    for (index = 0u; index < 16u; ++index)
        CHECK(state.xmm[0][index] == 0xffu);
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    for (index = 0u; index < 16u; ++index)
        CHECK(state.xmm[1][index] == (index % 3u == 0u ? 0u : 0xffu));
    xxemul_destroy(emulator);
    return 1;
}

static int test_x86_unpack_quadwords(void)
{
    static const uint8_t code[] = {
        0x66, 0x0f, 0x6c, 0xc1,
        0x66, 0x0f, 0x6d, 0x08,
        0xcc
    };
    xxemul *emulator = create_emulator(XXEMUL_ARCH_X86,
        XXEMUL_MODE_X86_64, 0x1000u, code, sizeof(code));
    xxemul_x86_state state;
    uint8_t source[16];
    size_t index;

    CHECK(emulator != NULL);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    state.gpr[XXEMUL_X86_RAX] = 0x1100u;
    for (index = 0u; index < sizeof(source); ++index) {
        state.xmm[0][index] = (uint8_t)(0x10u + index);
        state.xmm[1][index] = (uint8_t)(0x30u + index);
        source[index] = (uint8_t)(0x50u + index);
    }
    CHECK(xxemul_set_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK(xxemul_write_memory(emulator, 0x1100u,
        source, sizeof(source)) == XXEMUL_STATUS_OK);
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    for (index = 0u; index < 8u; ++index) {
        CHECK(state.xmm[0][index] == (uint8_t)(0x10u + index));
        CHECK(state.xmm[0][index + 8u]
            == (uint8_t)(0x30u + index));
    }
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    for (index = 0u; index < 8u; ++index) {
        CHECK(state.xmm[1][index] == (uint8_t)(0x38u + index));
        CHECK(state.xmm[1][index + 8u]
            == (uint8_t)(0x58u + index));
    }
    xxemul_destroy(emulator);
    return 1;
}

static int test_x86_movups(void)
{
    static const uint8_t code[] = {
        0x0f, 0x11, 0x0d, 0xf9, 0x00, 0x00, 0x00,
        0x0f, 0x10, 0x05, 0xf2, 0x00, 0x00, 0x00,
        0xcc
    };
    xxemul *emulator = create_emulator(
        XXEMUL_ARCH_X86, XXEMUL_MODE_X86_64,
        UINT64_C(0x1000), code, sizeof(code));
    xxemul_x86_state state;
    uint8_t memory[16];
    size_t index;

    CHECK(emulator != NULL);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    for (index = 0u; index < 16u; ++index)
        state.xmm[1][index] = (uint8_t)(index + 1u);
    CHECK(xxemul_set_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_read_memory(emulator, 0x1100u,
        memory, sizeof(memory)) == XXEMUL_STATUS_OK);
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    for (index = 0u; index < 16u; ++index) {
        CHECK(memory[index] == (uint8_t)(index + 1u));
        CHECK(state.xmm[0][index] == memory[index]);
    }
    xxemul_destroy(emulator);
    return 1;
}

static int test_x86_movapd_movupd(void)
{
    static const uint8_t code[] = {
        0x66, 0x0f, 0x28, 0xc7,
        0x66, 0x0f, 0x10, 0x08,
        0x66, 0x0f, 0x11, 0x48, 0x10,
        0xcc
    };
    xxemul *emulator = create_emulator(XXEMUL_ARCH_X86,
        XXEMUL_MODE_X86_64, 0x1000u, code, sizeof(code));
    xxemul_x86_state state;
    uint8_t source[16], stored[16];
    size_t index;

    CHECK(emulator != NULL);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    state.gpr[XXEMUL_X86_RAX] = 0x1100u;
    for (index = 0u; index < sizeof(source); ++index) {
        state.xmm[7][index] = (uint8_t)(index + 1u);
        source[index] = (uint8_t)(0xf0u - index);
    }
    CHECK(xxemul_set_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK(xxemul_write_memory(emulator, 0x1100u,
        source, sizeof(source)) == XXEMUL_STATUS_OK);
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    for (index = 0u; index < sizeof(source); ++index)
        CHECK(state.xmm[0][index] == (uint8_t)(index + 1u));
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK(memcmp(state.xmm[1], source, sizeof(source)) == 0);
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_read_memory(emulator, 0x1110u,
        stored, sizeof(stored)) == XXEMUL_STATUS_OK);
    CHECK(memcmp(stored, source, sizeof(stored)) == 0);
    xxemul_destroy(emulator);
    return 1;
}

static int test_x86_movq_xmm(void)
{
    static const uint8_t code[] = {
        0x66, 0x48, 0x0f, 0x6e, 0xc0, /* movq xmm0, rax */
        0x66, 0x48, 0x0f, 0x7e, 0xc1, /* movq rcx, xmm0 */
        0xcc
    };
    xxemul *emulator = create_emulator(
        XXEMUL_ARCH_X86, XXEMUL_MODE_X86_64,
        UINT64_C(0x1000), code, sizeof(code));
    xxemul_x86_state state;
    uint64_t low;
    size_t index;

    CHECK(emulator != NULL);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    state.gpr[XXEMUL_X86_RAX] = UINT64_C(0x8877665544332211);
    memset(state.xmm[0], 0xff, sizeof(state.xmm[0]));
    CHECK(xxemul_set_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    memcpy(&low, state.xmm[0], sizeof(low));
    CHECK(low == UINT64_C(0x8877665544332211));
    CHECK(state.gpr[XXEMUL_X86_RCX] == low);
    for (index = 8u; index < 16u; ++index)
        CHECK(state.xmm[0][index] == 0u);
    xxemul_destroy(emulator);
    return 1;
}

static int test_x86_bit_scan(void)
{
    static const uint8_t code[] = {
        0xb8, 0x80, 0x00, 0x00, 0x00, /* mov eax, 0x80 */
        0x0f, 0xbc, 0xc8,             /* bsf ecx, eax */
        0x0f, 0xbd, 0xd0,             /* bsr edx, eax */
        0x31, 0xc0,                   /* xor eax, eax */
        0x0f, 0xbc, 0xc8,             /* bsf ecx, eax */
        0xcc
    };
    xxemul *emulator = create_emulator(
        XXEMUL_ARCH_X86, XXEMUL_MODE_X86_32,
        UINT64_C(0x1000), code, sizeof(code));
    xxemul_x86_state state;

    CHECK(emulator != NULL);
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK(state.gpr[XXEMUL_X86_RCX] == 7u);
    CHECK(state.gpr[XXEMUL_X86_RDX] == 7u);
    CHECK((state.flags & (UINT64_C(1) << 6u)) == 0u);
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK(state.gpr[XXEMUL_X86_RCX] == 7u);
    CHECK((state.flags & (UINT64_C(1) << 6u)) != 0u);
    xxemul_destroy(emulator);
    return 1;
}

static int test_x86_decode_cache_mutation(void)
{
    static const uint8_t code[] = {
        0xb8, 0x01, 0x00, 0x00, 0x00, /* mov eax, 1 */
        0xcc
    };
    xxemul *emulator = create_emulator(
        XXEMUL_ARCH_X86, XXEMUL_MODE_X86_32,
        UINT64_C(0x1000), code, sizeof(code));
    xxemul_x86_state state;
    uint8_t replacement = 2u;

    CHECK(emulator != NULL);
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK(state.gpr[XXEMUL_X86_RAX] == 1u);
    state.ip = 0x1000u;
    CHECK(xxemul_set_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK(xxemul_write_memory(emulator, 0x1001u,
        &replacement, 1u) == XXEMUL_STATUS_OK);
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK(state.gpr[XXEMUL_X86_RAX] == 2u);
    xxemul_destroy(emulator);
    return 1;
}

static int test_x86_bt_memory(void)
{
    static const uint8_t code[] = {
        0xb8, 0x00, 0x11, 0x00, 0x00, /* mov eax, 0x1100 */
        0x0f, 0xba, 0x60, 0x08, 0x0d, /* bt dword ptr [eax+8], 13 */
        0x0f, 0xba, 0x70, 0x08, 0x0d, /* btr dword ptr [eax+8], 13 */
        0xcc
    };
    xxemul *emulator = create_emulator(
        XXEMUL_ARCH_X86, XXEMUL_MODE_X86_32,
        UINT64_C(0x1000), code, sizeof(code));
    xxemul_x86_state state;
    uint32_t word = UINT32_C(1) << 13u;

    CHECK(emulator != NULL);
    CHECK(xxemul_write_memory(emulator, 0x1108u,
        &word, sizeof(word)) == XXEMUL_STATUS_OK);
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK((state.flags & 1u) != 0u);
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_read_memory(emulator, 0x1108u,
        &word, sizeof(word)) == XXEMUL_STATUS_OK);
    CHECK(word == 0u);
    xxemul_destroy(emulator);
    return 1;
}

static int test_x86_cpuid(void)
{
    static const uint8_t code[] = {
        0x31, 0xc0, /* xor eax, eax */
        0x0f, 0xa2, /* cpuid */
        0xcc
    };
    xxemul *emulator = create_emulator(
        XXEMUL_ARCH_X86, XXEMUL_MODE_X86_16,
        UINT64_C(0x1000), code, sizeof(code));
    xxemul_x86_state state;

    CHECK(emulator != NULL);
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK(state.gpr[XXEMUL_X86_RAX] == 1u);
    CHECK(state.gpr[XXEMUL_X86_RBX] == UINT32_C(0x756e6547));
    CHECK(state.gpr[XXEMUL_X86_RDX] == UINT32_C(0x49656e69));
    CHECK(state.gpr[XXEMUL_X86_RCX] == UINT32_C(0x6c65746e));
    xxemul_destroy(emulator);
    return 1;
}

static int test_x86_mul(void)
{
    static const uint8_t code32[] = {
        0xb8, 0x00, 0x00, 0x01, 0x00, /* mov eax, 65536 */
        0xb9, 0x00, 0x00, 0x01, 0x00, /* mov ecx, 65536 */
        0xf7, 0xe1,                   /* mul ecx */
        0xcc
    };
    static const uint8_t code64[] = {0x48, 0xf7, 0xe3, 0xcc};
    xxemul *emulator;
    xxemul_x86_state state;

    emulator = create_emulator(XXEMUL_ARCH_X86, XXEMUL_MODE_X86_32,
        UINT64_C(0x1000), code32, sizeof(code32));
    CHECK(emulator != NULL);
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK(state.gpr[XXEMUL_X86_RAX] == 0u);
    CHECK(state.gpr[XXEMUL_X86_RDX] == 1u);
    CHECK((state.flags & (UINT64_C(1) | (UINT64_C(1) << 11u))) != 0u);
    xxemul_destroy(emulator);

    emulator = create_emulator(XXEMUL_ARCH_X86, XXEMUL_MODE_X86_64,
        UINT64_C(0x1000), code64, sizeof(code64));
    CHECK(emulator != NULL);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    state.gpr[XXEMUL_X86_RAX] = UINT64_MAX;
    state.gpr[XXEMUL_X86_RBX] = 2u;
    CHECK(xxemul_set_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK(state.gpr[XXEMUL_X86_RAX] == UINT64_MAX - 1u);
    CHECK(state.gpr[XXEMUL_X86_RDX] == 1u);
    xxemul_destroy(emulator);
    return 1;
}

static int test_x86_imul_accumulator(void)
{
    static const uint8_t code16[] = {0xf7, 0xe9, 0xcc}; /* imul cx */
    static const uint8_t code32[] = {0xf7, 0xe9, 0xcc}; /* imul ecx */
    xxemul *emulator;
    xxemul_x86_state state;

    emulator = create_emulator(XXEMUL_ARCH_X86, XXEMUL_MODE_X86_16,
        UINT64_C(0x1000), code16, sizeof(code16));
    CHECK(emulator != NULL);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    state.gpr[XXEMUL_X86_RAX] = 0xfffdu;
    state.gpr[XXEMUL_X86_RCX] = 2u;
    CHECK(xxemul_set_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK(state.gpr[XXEMUL_X86_RAX] == 0xfffau);
    CHECK(state.gpr[XXEMUL_X86_RDX] == 0xffffu);
    CHECK((state.flags & (UINT64_C(1) | (UINT64_C(1) << 11u))) == 0u);
    xxemul_destroy(emulator);

    emulator = create_emulator(XXEMUL_ARCH_X86, XXEMUL_MODE_X86_32,
        UINT64_C(0x1000), code32, sizeof(code32));
    CHECK(emulator != NULL);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    state.gpr[XXEMUL_X86_RAX] = UINT32_C(0x40000000);
    state.gpr[XXEMUL_X86_RCX] = 2u;
    CHECK(xxemul_set_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK(state.gpr[XXEMUL_X86_RAX] == UINT32_C(0x80000000));
    CHECK(state.gpr[XXEMUL_X86_RDX] == 0u);
    CHECK((state.flags & (UINT64_C(1) | (UINT64_C(1) << 11u)))
        == (UINT64_C(1) | (UINT64_C(1) << 11u)));
    xxemul_destroy(emulator);
    return 1;
}

static int test_x86_movhps(void)
{
    static const uint8_t code[] = {
        0x0f, 0x16, 0x05, 0xf9, 0x00, 0x00, 0x00,
        0x0f, 0x17, 0x05, 0x02, 0x01, 0x00, 0x00,
        0xcc
    };
    static const uint8_t source[8] = {
        0x10, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87
    };
    xxemul *emulator = create_emulator(
        XXEMUL_ARCH_X86, XXEMUL_MODE_X86_64,
        UINT64_C(0x1000), code, sizeof(code));
    xxemul_x86_state state;
    uint8_t stored[8];
    size_t index;

    CHECK(emulator != NULL);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    memset(state.xmm[0], 0xaau, sizeof(state.xmm[0]));
    CHECK(xxemul_set_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK(xxemul_write_memory(emulator, 0x1100u,
        source, sizeof(source)) == XXEMUL_STATUS_OK);
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK(xxemul_read_memory(emulator, 0x1110u,
        stored, sizeof(stored)) == XXEMUL_STATUS_OK);
    for (index = 0u; index < 8u; ++index) {
        CHECK(state.xmm[0][index] == 0xaau);
        CHECK(state.xmm[0][index + 8u] == source[index]);
        CHECK(stored[index] == source[index]);
    }
    xxemul_destroy(emulator);
    return 1;
}

static int test_x86_cvtsi2s_scalar(void)
{
    static const uint8_t code[] = {
        0xf3, 0x48, 0x0f, 0x2a, 0xc7, /* cvtsi2ss xmm0, rdi */
        0xf2, 0x48, 0x0f, 0x2a, 0xc7, /* cvtsi2sd xmm0, rdi */
        0xcc
    };
    xxemul *emulator = create_emulator(
        XXEMUL_ARCH_X86, XXEMUL_MODE_X86_64,
        UINT64_C(0x1000), code, sizeof(code));
    xxemul_x86_state state;
    float single;
    double number;
    unsigned index;

    CHECK(emulator != NULL);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    state.gpr[XXEMUL_X86_RDI] = 42u;
    memset(state.xmm[0], 0xaau, sizeof(state.xmm[0]));
    CHECK(xxemul_set_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    memcpy(&single, state.xmm[0], sizeof(single));
    CHECK(single == 42.0f);
    for (index = 4u; index < 16u; ++index)
        CHECK(state.xmm[0][index] == 0xaau);
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    memcpy(&number, state.xmm[0], sizeof(number));
    CHECK(number == 42.0);
    for (index = 8u; index < 16u; ++index)
        CHECK(state.xmm[0][index] == 0xaau);
    xxemul_destroy(emulator);
    return 1;
}

static int test_x86_scalar_sse_arithmetic(void)
{
    static const uint8_t code_single[] = {
        0xf3, 0x0f, 0x5e, 0x05, 0xf8, 0x00, 0x00, 0x00,
        0xf3, 0x0f, 0x58, 0xc1,
        0xcc
    };
    static const uint8_t code_double[] = {
        0xf2, 0x0f, 0x59, 0xc1,
        0xcc
    };
    xxemul *emulator;
    xxemul_x86_state state;
    float single = 100.0f;
    float divisor = 4.0f;
    float addend = 2.5f;
    double number = 4.0;
    double factor = 2.5;
    unsigned index;

    emulator = create_emulator(XXEMUL_ARCH_X86, XXEMUL_MODE_X86_64,
        UINT64_C(0x1000), code_single, sizeof(code_single));
    CHECK(emulator != NULL);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    memset(state.xmm[0], 0xaau, sizeof(state.xmm[0]));
    memcpy(state.xmm[0], &single, sizeof(single));
    memcpy(state.xmm[1], &addend, sizeof(addend));
    CHECK(xxemul_set_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK(xxemul_write_memory(emulator, 0x1100u,
        &divisor, sizeof(divisor)) == XXEMUL_STATUS_OK);
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    memcpy(&single, state.xmm[0], sizeof(single));
    CHECK(single == 25.0f);
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    memcpy(&single, state.xmm[0], sizeof(single));
    CHECK(single == 27.5f);
    for (index = 4u; index < 16u; ++index)
        CHECK(state.xmm[0][index] == 0xaau);
    xxemul_destroy(emulator);

    emulator = create_emulator(XXEMUL_ARCH_X86, XXEMUL_MODE_X86_64,
        UINT64_C(0x1000), code_double, sizeof(code_double));
    CHECK(emulator != NULL);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    memset(state.xmm[0], 0xaau, sizeof(state.xmm[0]));
    memcpy(state.xmm[0], &number, sizeof(number));
    memcpy(state.xmm[1], &factor, sizeof(factor));
    CHECK(xxemul_set_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    memcpy(&number, state.xmm[0], sizeof(number));
    CHECK(number == 10.0);
    for (index = 8u; index < 16u; ++index)
        CHECK(state.xmm[0][index] == 0xaau);
    xxemul_destroy(emulator);
    return 1;
}

static int test_x86_scalar_sse_compare(void)
{
    static const uint8_t code[] = {
        0x0f, 0x2e, 0x05, 0xf9, 0x00, 0x00, 0x00,
        0x0f, 0x2f, 0xc1,
        0x66, 0x0f, 0x2e, 0xc1,
        0x66, 0x0f, 0x2f, 0xc1,
        0xcc
    };
    xxemul *emulator = create_emulator(XXEMUL_ARCH_X86,
        XXEMUL_MODE_X86_64, 0x1000u, code, sizeof(code));
    xxemul_x86_state state;
    float lhs_single = 1.0f, rhs_single = 2.0f;
    double lhs_double = 3.0, rhs_double = 2.0;
    uint64_t nan_bits = UINT64_C(0x7ff8000000000000);

    CHECK(emulator != NULL);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    memcpy(state.xmm[0], &lhs_single, sizeof(lhs_single));
    CHECK(xxemul_set_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK(xxemul_write_memory(emulator, 0x1100u, &rhs_single,
        sizeof(rhs_single)) == XXEMUL_STATUS_OK);
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK((state.flags & 0x8d5u) == 1u);

    memcpy(state.xmm[1], &lhs_single, sizeof(lhs_single));
    CHECK(xxemul_set_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK((state.flags & 0x8d5u) == 0x40u);

    memcpy(state.xmm[0], &lhs_double, sizeof(lhs_double));
    memcpy(state.xmm[1], &rhs_double, sizeof(rhs_double));
    CHECK(xxemul_set_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK((state.flags & 0x8d5u) == 0u);

    memcpy(state.xmm[1], &nan_bits, sizeof(nan_bits));
    CHECK(xxemul_set_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK((state.flags & 0x8d5u) == 0x45u);
    xxemul_destroy(emulator);
    return 1;
}

static int test_x86_scalar_sse_move(void)
{
    static const uint8_t single_code[] = {
        0xf3, 0x0f, 0x10, 0x00,
        0xf3, 0x0f, 0x10, 0xc1,
        0xf3, 0x0f, 0x11, 0x40, 0x10,
        0xcc
    };
    static const uint8_t double_code[] = {
        0xf2, 0x0f, 0x10, 0x00,
        0xf2, 0x0f, 0x10, 0xc1,
        0xf2, 0x0f, 0x11, 0x40, 0x10,
        0xcc
    };
    const uint8_t *codes[] = {single_code, double_code};
    size_t lengths[] = {sizeof(single_code), sizeof(double_code)};
    float single_values[] = {4.5f, 7.25f};
    double double_values[] = {4.5, 7.25};
    size_t variant;

    for (variant = 0u; variant < 2u; ++variant) {
        xxemul *emulator = create_emulator(XXEMUL_ARCH_X86,
            XXEMUL_MODE_X86_64, 0x1000u, codes[variant], lengths[variant]);
        xxemul_x86_state state;
        uint8_t source[8] = {0};
        uint8_t reg_source[8] = {0};
        uint8_t stored[8];
        uint8_t sentinel[8];
        size_t size = variant == 0u ? 4u : 8u;
        size_t index;

        CHECK(emulator != NULL);
        if (variant == 0u) {
            memcpy(source, &single_values[0], size);
            memcpy(reg_source, &single_values[1], size);
        } else {
            memcpy(source, &double_values[0], size);
            memcpy(reg_source, &double_values[1], size);
        }
        CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
        state.gpr[XXEMUL_X86_RAX] = 0x1100u;
        memset(state.xmm[0], 0xaau, sizeof(state.xmm[0]));
        memcpy(state.xmm[1], reg_source, size);
        CHECK(xxemul_set_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
        CHECK(xxemul_write_memory(emulator, 0x1100u,
            source, size) == XXEMUL_STATUS_OK);
        memset(sentinel, 0xccu, sizeof(sentinel));
        CHECK(xxemul_write_memory(emulator, 0x1110u,
            sentinel, sizeof(sentinel)) == XXEMUL_STATUS_OK);
        CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
        CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
        CHECK(memcmp(state.xmm[0], source, size) == 0);
        for (index = size; index < 16u; ++index)
            CHECK(state.xmm[0][index] == 0u);

        memset(state.xmm[0] + size, 0xaau, 16u - size);
        CHECK(xxemul_set_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
        CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
        CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
        CHECK(memcmp(state.xmm[0], reg_source, size) == 0);
        for (index = size; index < 16u; ++index)
            CHECK(state.xmm[0][index] == 0xaau);

        CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
        CHECK(xxemul_read_memory(emulator, 0x1110u,
            stored, sizeof(stored)) == XXEMUL_STATUS_OK);
        CHECK(memcmp(stored, reg_source, size) == 0);
        for (index = size; index < sizeof(stored); ++index)
            CHECK(stored[index] == 0xccu);
        xxemul_destroy(emulator);
    }
    return 1;
}

static int test_x86_endbr_and_flags_stack(void)
{
    static const uint8_t code32[] = {0xf3, 0x0f, 0x1e, 0xfb, 0xcc};
    static const uint8_t code64[] = {0xf3, 0x0f, 0x1e, 0xfa, 0xcc};
    static const uint8_t flags_code[] = {0x66, 0x9c, 0x66, 0x9d, 0xcc};
    const uint8_t *codes[] = {code32, code64};
    xxemul_mode modes[] = {XXEMUL_MODE_X86_32, XXEMUL_MODE_X86_64};
    xxemul *emulator;
    xxemul_x86_state state;
    xxemul_step_info info;
    size_t index;

    for (index = 0u; index < 2u; ++index) {
        emulator = create_emulator(XXEMUL_ARCH_X86, modes[index],
            UINT64_C(0x1000), codes[index], sizeof(code32));
        CHECK(emulator != NULL);
        CHECK(xxemul_step(emulator, &info) == XXEMUL_STATUS_OK);
        CHECK(info.size == 4u);
        CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
        CHECK(state.ip == 0x1004u);
        xxemul_destroy(emulator);
    }
    emulator = create_emulator(XXEMUL_ARCH_X86, XXEMUL_MODE_X86_16,
        UINT64_C(0x1000), flags_code, sizeof(flags_code));
    CHECK(emulator != NULL);
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK(state.gpr[XXEMUL_X86_RSP] == 0x1ffcu);
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK(state.gpr[XXEMUL_X86_RSP] == 0x2000u);
    CHECK(state.flags == 2u);
    xxemul_destroy(emulator);
    return 1;
}

static int test_x86_lahf_sahf(void)
{
    static const uint8_t code[] = {0x9f, 0x9e, 0xcc};
    static const xxemul_mode modes[] = {
        XXEMUL_MODE_X86_16, XXEMUL_MODE_X86_32, XXEMUL_MODE_X86_64
    };
    static const uint8_t initial_status[] = {0x00u, 0xd5u, 0x95u};
    static const uint8_t sahf_ah[] = {0xffu, 0x08u, 0x4au};
    const uint64_t status_mask = UINT64_C(0xd5);
    const uint64_t initial_rax = UINT64_C(0x112233445566ab7d);
    xxemul_x86_state state;
    xxemul *emulator;
    uint64_t initial_flags;
    uint64_t expected_rax;
    uint64_t expected_flags;
    size_t mode_index;
    size_t sample_index;

    for (mode_index = 0u; mode_index < sizeof(modes) / sizeof(modes[0]);
        ++mode_index) {
        for (sample_index = 0u;
            sample_index < sizeof(initial_status) / sizeof(initial_status[0]);
            ++sample_index) {
            emulator = create_emulator(XXEMUL_ARCH_X86, modes[mode_index],
                UINT64_C(0x1000), code, sizeof(code));
            CHECK(emulator != NULL);
            CHECK(xxemul_get_x86_state(emulator, &state)
                == XXEMUL_STATUS_OK);
            initial_flags = UINT64_C(0x10a02) | initial_status[sample_index];
            state.gpr[XXEMUL_X86_RAX] = initial_rax;
            state.flags = initial_flags;
            CHECK(xxemul_set_x86_state(emulator, &state)
                == XXEMUL_STATUS_OK);

            CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
            CHECK(xxemul_get_x86_state(emulator, &state)
                == XXEMUL_STATUS_OK);
            expected_rax = (initial_rax & ~UINT64_C(0xff00))
                | (((initial_flags & status_mask) | UINT64_C(2)) << 8u);
            CHECK(state.gpr[XXEMUL_X86_RAX] == expected_rax);
            CHECK(state.flags == initial_flags);
            CHECK(state.ip == UINT64_C(0x1001));

            expected_rax = (state.gpr[XXEMUL_X86_RAX]
                & ~UINT64_C(0xff00))
                | ((uint64_t)sahf_ah[sample_index] << 8u);
            state.gpr[XXEMUL_X86_RAX] = expected_rax;
            CHECK(xxemul_set_x86_state(emulator, &state)
                == XXEMUL_STATUS_OK);
            CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
            CHECK(xxemul_get_x86_state(emulator, &state)
                == XXEMUL_STATUS_OK);
            expected_flags = (initial_flags & ~status_mask)
                | (sahf_ah[sample_index] & status_mask) | UINT64_C(2);
            CHECK(state.flags == expected_flags);
            CHECK(state.gpr[XXEMUL_X86_RAX] == expected_rax);
            CHECK(state.ip == UINT64_C(0x1002));
            xxemul_destroy(emulator);
        }
    }
    return 1;
}

static int test_x86_upx_scalar_controls(void)
{
    static const uint8_t arithmetic[] = {
        0xb9, 0x03, 0x00, 0x00, 0x00, /* mov ecx, 3 */
        0xb8, 0x01, 0x00, 0x00, 0x00, /* mov eax, 1 */
        0xf7, 0xd8,                   /* neg eax */
        0xf7, 0xd0,                   /* not eax */
        0x0f, 0xbb, 0xc8,             /* btc eax, ecx */
        0xe2, 0xfe,                   /* loop to itself */
        0xcc
    };
    static const uint8_t leave_code[] = {0xc9, 0xcc};
    static const uint8_t syscall_code[] = {0x0f, 0x05, 0xcc};
    xxemul_x86_state state;
    xxemul_status status;
    xxemul *emulator;
    uint64_t executed;
    uint8_t frame[4] = {0x78, 0x56, 0x34, 0x12};
    char text[64];

    emulator = create_emulator(XXEMUL_ARCH_X86, XXEMUL_MODE_X86_32,
        UINT64_C(0x1000), arithmetic, sizeof(arithmetic));
    CHECK(emulator != NULL);
    status = xxemul_run(emulator, 16u, &executed);
    CHECK(status == XXEMUL_STATUS_HALTED);
    CHECK(executed == 9u);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK(state.gpr[XXEMUL_X86_RAX] == 8u);
    CHECK(state.gpr[XXEMUL_X86_RCX] == 0u);
    CHECK((state.flags & 1u) == 0u);
    xxemul_destroy(emulator);

    emulator = create_emulator(XXEMUL_ARCH_X86, XXEMUL_MODE_X86_32,
        UINT64_C(0x1000), leave_code, sizeof(leave_code));
    CHECK(emulator != NULL);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    state.gpr[XXEMUL_X86_RBP] = 0x1ff0u;
    CHECK(xxemul_set_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK(xxemul_write_memory(emulator, 0x1ff0u, frame,
        sizeof(frame)) == XXEMUL_STATUS_OK);
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK(state.gpr[XXEMUL_X86_RSP] == 0x1ff4u);
    CHECK(state.gpr[XXEMUL_X86_RBP] == 0x12345678u);
    xxemul_destroy(emulator);

    emulator = create_emulator(XXEMUL_ARCH_X86, XXEMUL_MODE_X86_64,
        UINT64_C(0x1000), syscall_code, sizeof(syscall_code));
    CHECK(emulator != NULL);
    CHECK(xxemul_format_current(emulator, text, sizeof(text)) > 0u);
    CHECK(strstr(text, "syscall") != NULL);
    CHECK(xxemul_step(emulator, NULL)
        == XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION);
    xxemul_destroy(emulator);
    return 1;
}

static int test_x86_cmpxchg(void)
{
    static const uint8_t code[] = {
        0xf0, 0x0f, 0xb1, 0x0b, /* lock cmpxchg [ebx], ecx */
        0xcc
    };
    xxemul_x86_state state;
    xxemul *emulator = create_emulator(
        XXEMUL_ARCH_X86, XXEMUL_MODE_X86_32,
        UINT64_C(0x1000), code, sizeof(code));
    uint8_t bytes[4] = {1u, 0u, 0u, 0u};

    CHECK(emulator != NULL);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    state.gpr[XXEMUL_X86_RAX] = 1u;
    state.gpr[XXEMUL_X86_RBX] = 0x1100u;
    state.gpr[XXEMUL_X86_RCX] = 7u;
    CHECK(xxemul_set_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK(xxemul_write_memory(emulator, 0x1100u, bytes,
        sizeof(bytes)) == XXEMUL_STATUS_OK);
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK(state.gpr[XXEMUL_X86_RAX] == 1u);
    CHECK((state.flags & 0x40u) != 0u);
    CHECK(xxemul_read_memory(emulator, 0x1100u, bytes,
        sizeof(bytes)) == XXEMUL_STATUS_OK);
    CHECK(bytes[0] == 7u);
    xxemul_destroy(emulator);
    return 1;
}

static int test_x86_imul_three_operands(void)
{
    static const uint8_t code[] = {
        0xb8, 0xff, 0xff, 0xff, 0x7f, /* mov eax, INT32_MAX */
        0x6b, 0xd0, 0x03,             /* imul edx, eax, 3 */
        0xcc
    };
    xxemul *emulator = create_emulator(
        XXEMUL_ARCH_X86, XXEMUL_MODE_X86_32,
        UINT64_C(0x1000), code, sizeof(code));
    xxemul_x86_state state;

    CHECK(emulator != NULL);
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK(state.gpr[XXEMUL_X86_RDX] == 0x7ffffffdu);
    CHECK((state.flags & 0x801u) == 0x801u);
    xxemul_destroy(emulator);
    return 1;
}

static int test_x86_cdq(void)
{
    static const uint8_t code[] = {
        0xb8, 0x00, 0x00, 0x00, 0x80, /* mov eax, 0x80000000 */
        0x99,                         /* cdq */
        0xcc
    };
    xxemul *emulator = create_emulator(
        XXEMUL_ARCH_X86, XXEMUL_MODE_X86_32,
        UINT64_C(0x1000), code, sizeof(code));
    xxemul_x86_state state;

    CHECK(emulator != NULL);
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK(state.gpr[XXEMUL_X86_RDX] == 0xffffffffu);
    xxemul_destroy(emulator);
    return 1;
}

static int test_x86_idiv(void)
{
    static const uint8_t code[] = {
        0xb8, 0xe8, 0x03, 0x00, 0x00, /* mov eax, 1000 */
        0x99,                         /* cdq */
        0xb9, 0x03, 0x00, 0x00, 0x00, /* mov ecx, 3 */
        0xf7, 0xf9,                   /* idiv ecx */
        0xcc
    };
    xxemul *emulator = create_emulator(
        XXEMUL_ARCH_X86, XXEMUL_MODE_X86_32,
        UINT64_C(0x1000), code, sizeof(code));
    xxemul_x86_state state;

    CHECK(emulator != NULL);
    CHECK(xxemul_run(emulator, 8u, NULL) == XXEMUL_STATUS_HALTED);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK(state.gpr[XXEMUL_X86_RAX] == 333u);
    CHECK(state.gpr[XXEMUL_X86_RDX] == 1u);
    xxemul_destroy(emulator);
    return 1;
}

static int test_x86_divide_64(void)
{
    static const uint8_t unsigned_code[] = {0x48, 0xf7, 0xf1, 0xcc};
    static const uint8_t signed_code[] = {0x48, 0xf7, 0xf9, 0xcc};
    xxemul *emulator = create_emulator(XXEMUL_ARCH_X86,
        XXEMUL_MODE_X86_64, 0x1000u,
        unsigned_code, sizeof(unsigned_code));
    xxemul_x86_state state;

    CHECK(emulator != NULL);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    state.gpr[XXEMUL_X86_RAX] = 100u;
    state.gpr[XXEMUL_X86_RDX] = 0u;
    state.gpr[XXEMUL_X86_RCX] = 9u;
    CHECK(xxemul_set_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK(state.gpr[XXEMUL_X86_RAX] == 11u);
    CHECK(state.gpr[XXEMUL_X86_RDX] == 1u);

    state.ip = 0x1000u;
    state.gpr[XXEMUL_X86_RAX] = 0u;
    state.gpr[XXEMUL_X86_RDX] = 1u;
    state.gpr[XXEMUL_X86_RCX] = 3u;
    CHECK(xxemul_set_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK(state.gpr[XXEMUL_X86_RAX] == UINT64_C(0x5555555555555555));
    CHECK(state.gpr[XXEMUL_X86_RDX] == 1u);

    state.ip = 0x1000u;
    state.gpr[XXEMUL_X86_RAX] = 0u;
    state.gpr[XXEMUL_X86_RDX] = 3u;
    CHECK(xxemul_set_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK(xxemul_step(emulator, NULL)
        == XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION);
    xxemul_destroy(emulator);

    emulator = create_emulator(XXEMUL_ARCH_X86,
        XXEMUL_MODE_X86_64, 0x1000u,
        signed_code, sizeof(signed_code));
    CHECK(emulator != NULL);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    state.gpr[XXEMUL_X86_RAX] = (uint64_t)(int64_t)-100;
    state.gpr[XXEMUL_X86_RDX] = UINT64_MAX;
    state.gpr[XXEMUL_X86_RCX] = 9u;
    CHECK(xxemul_set_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK(state.gpr[XXEMUL_X86_RAX] == (uint64_t)(int64_t)-11);
    CHECK(state.gpr[XXEMUL_X86_RDX] == UINT64_MAX);
    xxemul_destroy(emulator);
    return 1;
}

static int test_x86_cmovne(void)
{
    static const uint8_t code[] = {
        0xb8, 0x00, 0x00, 0x00, 0x00, /* mov eax, 0 */
        0xbe, 0x34, 0x12, 0x00, 0x00, /* mov esi, 0x1234 */
        0x83, 0xf8, 0x01,             /* cmp eax, 1 */
        0x0f, 0x45, 0xc6,             /* cmovne eax, esi */
        0xcc
    };
    xxemul *emulator = create_emulator(
        XXEMUL_ARCH_X86, XXEMUL_MODE_X86_32,
        UINT64_C(0x1000), code, sizeof(code));
    xxemul_x86_state state;

    CHECK(emulator != NULL);
    CHECK(xxemul_run(emulator, 8u, NULL) == XXEMUL_STATUS_HALTED);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK(state.gpr[XXEMUL_X86_RAX] == 0x1234u);
    xxemul_destroy(emulator);
    return 1;
}

static int test_x86_shifts_and_pushad(void)
{
    static const uint8_t shift_code[] = {
        0xbf, 0x01, 0x80, /* mov di, 0x8001 */
        0xb1, 0x04,       /* mov cl, 4 */
        0xd3, 0xef,       /* shr di, cl */
        0xb0, 0x80,       /* mov al, 0x80 */
        0xd0, 0xe8,       /* shr al, 1 */
        0xcc
    };
    static const uint8_t pushad_code[] = {
        0x60,             /* pushad */
        0x31, 0xc0,       /* xor eax, eax */
        0x61,             /* popad */
        0xcc
    };
    xxemul *emulator = create_emulator(XXEMUL_ARCH_X86,
        XXEMUL_MODE_X86_16, 0x1000u, shift_code, sizeof(shift_code));
    xxemul_x86_state state;
    uint64_t original_sp;

    CHECK(emulator != NULL);
    CHECK(xxemul_run(emulator, 8u, NULL) == XXEMUL_STATUS_HALTED);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK((state.gpr[XXEMUL_X86_RDI] & 0xffffu) == 0x0800u);
    CHECK((state.gpr[XXEMUL_X86_RAX] & 0xffu) == 0x40u);
    CHECK((state.flags & (UINT64_C(1) << 11)) != 0u);
    xxemul_destroy(emulator);

    emulator = create_emulator(XXEMUL_ARCH_X86,
        XXEMUL_MODE_X86_32, 0x1000u, pushad_code, sizeof(pushad_code));
    CHECK(emulator != NULL);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    original_sp = state.gpr[XXEMUL_X86_RSP];
    state.gpr[XXEMUL_X86_RAX] = 0x12345678u;
    state.gpr[XXEMUL_X86_RBX] = 0x87654321u;
    CHECK(xxemul_set_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK(xxemul_run(emulator, 8u, NULL) == XXEMUL_STATUS_HALTED);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK(state.gpr[XXEMUL_X86_RAX] == 0x12345678u);
    CHECK(state.gpr[XXEMUL_X86_RBX] == 0x87654321u);
    CHECK(state.gpr[XXEMUL_X86_RSP] == original_sp);
    xxemul_destroy(emulator);
    return 1;
}

static int test_x86_adc_and_strings(void)
{
    static const uint8_t adc_code[] = {
        0xb8, 0xff, 0xff, 0xff, 0xff, /* mov eax, -1 */
        0xf9,                         /* stc */
        0x83, 0xd0, 0x00,             /* adc eax, 0 */
        0xcc
    };
    static const uint8_t stos_code[] = {
        0xbf, 0x00, 0x12, /* mov di, 0x1200 */
        0xb9, 0x03, 0x00, /* mov cx, 3 */
        0xb0, 0x5a,       /* mov al, 'Z' */
        0xf3, 0xaa,       /* rep stosb */
        0xcc
    };
    xxemul *emulator = create_emulator(XXEMUL_ARCH_X86,
        XXEMUL_MODE_X86_32, 0x1000u, adc_code, sizeof(adc_code));
    xxemul_x86_state state;
    uint8_t bytes[3];

    CHECK(emulator != NULL);
    CHECK(xxemul_run(emulator, 8u, NULL) == XXEMUL_STATUS_HALTED);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK(state.gpr[XXEMUL_X86_RAX] == 0u);
    CHECK((state.flags & UINT64_C(1)) != 0u);
    CHECK((state.flags & (UINT64_C(1) << 6)) != 0u);
    xxemul_destroy(emulator);

    emulator = create_emulator(XXEMUL_ARCH_X86,
        XXEMUL_MODE_X86_16, 0x1000u, stos_code, sizeof(stos_code));
    CHECK(emulator != NULL);
    CHECK(xxemul_run(emulator, 8u, NULL) == XXEMUL_STATUS_HALTED);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK((state.gpr[XXEMUL_X86_RCX] & 0xffffu) == 0u);
    CHECK((state.gpr[XXEMUL_X86_RDI] & 0xffffu) == 0x1203u);
    CHECK(xxemul_read_memory(emulator, 0x1200u, bytes, sizeof(bytes))
        == XXEMUL_STATUS_OK);
    CHECK(bytes[0] == 'Z' && bytes[1] == 'Z' && bytes[2] == 'Z');
    xxemul_destroy(emulator);
    return 1;
}

static int test_x86_xchg_bswap(void)
{
    static const uint8_t code[] = {
        0xb8, 0x78, 0x56, 0x34, 0x12, /* mov eax, 0x12345678 */
        0x86, 0xc4,                   /* xchg ah, al */
        0x0f, 0xc8,                   /* bswap eax */
        0xcc
    };
    xxemul *emulator = create_emulator(XXEMUL_ARCH_X86,
        XXEMUL_MODE_X86_32, 0x1000u, code, sizeof(code));
    xxemul_x86_state state;

    CHECK(emulator != NULL);
    CHECK(xxemul_run(emulator, 8u, NULL) == XXEMUL_STATUS_HALTED);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK(state.gpr[XXEMUL_X86_RAX] == UINT64_C(0x56783412));
    xxemul_destroy(emulator);
    return 1;
}

static int test_arm_a64(void)
{
    static const uint8_t code[] = {
        0xa0, 0x00, 0x80, 0xd2, /* mov x0, #5 */
        0x01, 0x0c, 0x00, 0x91, /* add x1, x0, #3 */
        0x22, 0x04, 0x00, 0xd1, /* sub x2, x1, #1 */
        0x00, 0x00, 0x20, 0xd4  /* brk #0 */
    };
    xxemul_arm_state state;
    xxemul_status status;
    xxemul *emulator = create_emulator(
        XXEMUL_ARCH_ARM, XXEMUL_MODE_ARM_A64,
        UINT64_C(0x4000), code, sizeof(code));
    uint64_t executed = 0;

    CHECK(emulator != NULL);
    status = xxemul_run(emulator, 8u, &executed);
    CHECK(status == XXEMUL_STATUS_HALTED);
    CHECK(executed == 4u);
    CHECK(xxemul_get_arm_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK(state.gpr[0] == 5u);
    CHECK(state.gpr[1] == 8u);
    CHECK(state.gpr[2] == 7u);
    xxemul_destroy(emulator);
    return 1;
}

static int test_arm_a32(void)
{
    static const uint8_t code[] = {
        0x05, 0x00, 0xa0, 0xe3, /* mov r0, #5 */
        0x03, 0x10, 0x80, 0xe2, /* add r1, r0, #3 */
        0x70, 0x00, 0x20, 0xe1  /* bkpt #0 */
    };
    xxemul_arm_state state;
    xxemul_status status;
    xxemul *emulator = create_emulator(
        XXEMUL_ARCH_ARM, XXEMUL_MODE_ARM_A32,
        UINT64_C(0x8000), code, sizeof(code));
    uint64_t executed = 0;

    CHECK(emulator != NULL);
    status = xxemul_run(emulator, 8u, &executed);
    CHECK(status == XXEMUL_STATUS_HALTED);
    CHECK(executed == 3u);
    CHECK(xxemul_get_arm_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK(state.gpr[0] == 5u);
    CHECK(state.gpr[1] == 8u);
    xxemul_destroy(emulator);
    return 1;
}

static int test_arm_t32(void)
{
    static const uint8_t code[] = {
        0x05, 0x20, /* movs r0, #5 */
        0x03, 0x30, /* adds r0, #3 */
        0x00, 0xbe  /* bkpt #0 */
    };
    xxemul_arm_state state;
    xxemul_status status;
    xxemul *emulator = create_emulator(
        XXEMUL_ARCH_ARM, XXEMUL_MODE_ARM_T32,
        UINT64_C(0xa000), code, sizeof(code));
    uint64_t executed = 0;

    CHECK(emulator != NULL);
    status = xxemul_run(emulator, 8u, &executed);
    CHECK(status == XXEMUL_STATUS_HALTED);
    CHECK(executed == 3u);
    CHECK(xxemul_get_arm_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK(state.gpr[0] == 8u);
    xxemul_destroy(emulator);
    return 1;
}

static int test_region_bounds(void)
{
    static const uint8_t code[] = {0x90, 0xcc};
    uint8_t value = 0xaa;
    xxemul *emulator = create_emulator(
        XXEMUL_ARCH_X86, XXEMUL_MODE_X86_64,
        UINT64_C(0x100000), code, sizeof(code));

    CHECK(emulator != NULL);
    CHECK(xxemul_write_memory(emulator, UINT64_C(0x100100), &value, 1u)
        == XXEMUL_STATUS_OK);
    CHECK(xxemul_read_memory(emulator, UINT64_C(0x0fffff), &value, 1u)
        == XXEMUL_STATUS_ADDRESS_FAULT);
    CHECK(xxemul_read_memory(emulator, UINT64_C(0x101000), &value, 1u)
        == XXEMUL_STATUS_ADDRESS_FAULT);
    xxemul_destroy(emulator);
    return 1;
}

static int test_dos_com_text(void)
{
    static const uint8_t image[] = {
        0xba, 0x0c, 0x01, /* mov dx, 010ch */
        0xb4, 0x09,       /* mov ah, 09h */
        0xcd, 0x21,       /* int 21h */
        0xb8, 0x07, 0x4c, /* mov ax, 4c07h */
        0xcd, 0x21,       /* int 21h */
        'H', 'i', '$'
    };
    xxemul_status status;
    xxemul_x86_state state;
    xxemul *emulator = xxemul_create_dos(
        XXEMUL_DOS_COM, image, sizeof(image), &status);
    uint8_t psp[2];
    uint8_t video[4];
    uint8_t last_cell[2] = {'H', 7u};
    uint8_t exit_code = 0u;
    uint64_t executed = 0u;
    output_capture capture = {{0}, 0u};
    uint32_t *pixels;

    CHECK(emulator != NULL);
    CHECK(status == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK(state.segment[XXEMUL_X86_CS] == 0x0814u);
    CHECK(state.segment[XXEMUL_X86_DS] == 0x0814u);
    CHECK(state.segment[XXEMUL_X86_SS] == 0x0814u);
    CHECK(state.ip == 0x100u);
    CHECK(state.gpr[XXEMUL_X86_RSP] == 0xfffeu);
    CHECK(xxemul_read_memory(emulator, 0x8140u, psp, sizeof(psp))
        == XXEMUL_STATUS_OK);
    CHECK(psp[0] == 0xcdu && psp[1] == 0x20u);
    CHECK(xxemul_dos_set_output_callback(emulator,
        capture_output, &capture) == XXEMUL_STATUS_OK);
    CHECK(xxemul_run(emulator, 16u, &executed) == XXEMUL_STATUS_HALTED);
    CHECK(executed == 5u);
    CHECK(capture.size == 2u);
    CHECK(capture.bytes[0] == 'H' && capture.bytes[1] == 'i');
    CHECK(xxemul_dos_get_exit_code(emulator, &exit_code)
        == XXEMUL_STATUS_OK);
    CHECK(exit_code == 7u);
    CHECK(xxemul_read_memory(emulator, 0xb8000u, video, sizeof(video))
        == XXEMUL_STATUS_OK);
    CHECK(video[0] == 'H' && video[1] == 7u);
    CHECK(video[2] == 'i' && video[3] == 7u);
    CHECK(xxemul_write_memory(emulator,
        0xb8000u + 24u * 80u * 2u, last_cell, sizeof(last_cell))
        == XXEMUL_STATUS_OK);
    pixels = (uint32_t *)malloc(XXEMUL_DISPLAY_WIDTH
        * XXEMUL_DISPLAY_HEIGHT * sizeof(*pixels));
    CHECK(pixels != NULL);
    CHECK(xxemul_display_render(emulator, pixels, XXEMUL_DISPLAY_WIDTH)
        == XXEMUL_STATUS_OK);
    CHECK(XXEMUL_DISPLAY_WIDTH == 640u);
    CHECK(XXEMUL_DISPLAY_HEIGHT == 480u);
    CHECK(pixels[4u * XXEMUL_DISPLAY_WIDTH + 1u] == 0xffaaaaaau);
    CHECK(pixels[460u * XXEMUL_DISPLAY_WIDTH + 1u] == 0xffaaaaaau);
    CHECK(pixels[0] == 0xff000000u);
    free(pixels);
    xxemul_destroy(emulator);
    return 1;
}

static int test_dos_far_return(void)
{
    static const uint8_t image[] = {
        0xca, 0x04, 0x00, /* retf 4 */
        0xb8, 0x00, 0x4c, /* mov ax, 4c00h */
        0xcd, 0x21
    };
    xxemul_status status;
    xxemul_x86_state state;
    xxemul *emulator = xxemul_create_dos(
        XXEMUL_DOS_COM, image, sizeof(image), &status);
    uint8_t stack[4];

    CHECK(emulator != NULL);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    state.gpr[XXEMUL_X86_RSP] = 0xfff6u;
    stack[0] = 0x03u;
    stack[1] = 0x01u;
    stack[2] = (uint8_t)state.segment[XXEMUL_X86_CS];
    stack[3] = (uint8_t)(state.segment[XXEMUL_X86_CS] >> 8u);
    CHECK(xxemul_write_memory(emulator,
        xxemul_dos_linear(state.segment[XXEMUL_X86_SS], 0xfff6u),
        stack, sizeof(stack)) == XXEMUL_STATUS_OK);
    CHECK(xxemul_set_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK(state.ip == 0x103u);
    CHECK(state.gpr[XXEMUL_X86_RSP] == 0xfffeu);
    CHECK(xxemul_run(emulator, 4u, NULL) == XXEMUL_STATUS_HALTED);
    xxemul_destroy(emulator);
    return 1;
}

static int test_dos_far_call(void)
{
    static const uint8_t image[] = {
        0xff, 0x1e, 0x10, 0x01, /* call far dword ptr [0110h] */
        0xb8, 0x00, 0x4c,       /* mov ax, 4c00h */
        0xcd, 0x21,             /* int 21h */
        0xcb                    /* retf */
    };
    xxemul_status status;
    xxemul_x86_state state;
    xxemul *emulator = xxemul_create_dos(
        XXEMUL_DOS_COM, image, sizeof(image), &status);
    uint8_t pointer[4];

    CHECK(emulator != NULL);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    pointer[0] = 0x09u;
    pointer[1] = 0x01u;
    pointer[2] = (uint8_t)state.segment[XXEMUL_X86_CS];
    pointer[3] = (uint8_t)(state.segment[XXEMUL_X86_CS] >> 8u);
    CHECK(xxemul_write_memory(emulator,
        xxemul_dos_linear(state.segment[XXEMUL_X86_DS], 0x110u),
        pointer, sizeof(pointer)) == XXEMUL_STATUS_OK);
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK(state.ip == 0x109u);
    CHECK(state.gpr[XXEMUL_X86_RSP] == 0xfffau);
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK(state.ip == 0x104u);
    CHECK(state.gpr[XXEMUL_X86_RSP] == 0xfffeu);
    CHECK(xxemul_run(emulator, 4u, NULL) == XXEMUL_STATUS_HALTED);
    xxemul_destroy(emulator);
    return 1;
}

static int test_dos_enter_leave(void)
{
    static const uint8_t image[] = {
        0xc8, 0x04, 0x00, 0x00, /* enter 4, 0 */
        0xc9,                   /* leave */
        0xb8, 0x00, 0x4c,
        0xcd, 0x21
    };
    xxemul_status status;
    xxemul_x86_state state;
    xxemul *emulator = xxemul_create_dos(
        XXEMUL_DOS_COM, image, sizeof(image), &status);

    CHECK(emulator != NULL);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    state.gpr[XXEMUL_X86_RBP] = 0x1234u;
    CHECK(xxemul_set_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK(state.gpr[XXEMUL_X86_RBP] == 0xfffcu);
    CHECK(state.gpr[XXEMUL_X86_RSP] == 0xfff8u);
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK(state.gpr[XXEMUL_X86_RBP] == 0x1234u);
    CHECK(state.gpr[XXEMUL_X86_RSP] == 0xfffeu);
    CHECK(xxemul_run(emulator, 4u, NULL) == XXEMUL_STATUS_HALTED);
    xxemul_destroy(emulator);
    return 1;
}

static int test_dos_port_92(void)
{
    static const uint8_t image[] = {
        0xe4, 0x92,       /* in al, 92h */
        0xb0, 0x00,       /* mov al, 0 */
        0xe6, 0x92,       /* out 92h, al */
        0xe4, 0x92,       /* in al, 92h */
        0xb8, 0x00, 0x4c,
        0xcd, 0x21
    };
    xxemul_status status;
    xxemul_x86_state state;
    xxemul *emulator = xxemul_create_dos(
        XXEMUL_DOS_COM, image, sizeof(image), &status);

    CHECK(emulator != NULL);
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK((state.gpr[XXEMUL_X86_RAX] & 0xffu) == 2u);
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK((state.gpr[XXEMUL_X86_RAX] & 0xffu) == 0u);
    CHECK(xxemul_run(emulator, 4u, NULL) == XXEMUL_STATUS_HALTED);
    xxemul_destroy(emulator);
    return 1;
}

static int test_dos_kbc_a20(void)
{
    static const uint8_t image[] = {
        0xb0, 0xd0,       /* read controller output port */
        0xe6, 0x64,
        0xe4, 0x64,       /* status: output data available */
        0xe4, 0x60,       /* initial output port */
        0xb0, 0xd1,       /* write controller output port */
        0xe6, 0x64,
        0xb0, 0x00,
        0xe6, 0x60,
        0xe4, 0x92,       /* A20 bit now clear */
        0xb8, 0x00, 0x4c,
        0xcd, 0x21
    };
    xxemul_status status;
    xxemul_x86_state state;
    xxemul *emulator = xxemul_create_dos(
        XXEMUL_DOS_COM, image, sizeof(image), &status);
    unsigned index;

    CHECK(emulator != NULL);
    for (index = 0u; index < 3u; ++index)
        CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK((state.gpr[XXEMUL_X86_RAX] & 0xffu) == 1u);
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK((state.gpr[XXEMUL_X86_RAX] & 0xffu) == 3u);
    for (index = 0u; index < 5u; ++index)
        CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK((state.gpr[XXEMUL_X86_RAX] & 0xffu) == 0u);
    CHECK(xxemul_run(emulator, 4u, NULL) == XXEMUL_STATUS_HALTED);
    xxemul_destroy(emulator);
    return 1;
}

static int test_dos_a20_memory(void)
{
    static const uint8_t image[] = {
        0xb8, 0xff, 0xff,             /* mov ax, 0ffffh */
        0x8e, 0xc0,                   /* mov es, ax */
        0x26, 0xc7, 0x06, 0x10, 0x00,
        0x34, 0x12,                   /* mov word es:[10h], 1234h */
        0xb0, 0x00,
        0xe6, 0x92,                   /* disable A20 */
        0x26, 0xc7, 0x06, 0x10, 0x00,
        0x78, 0x56,                   /* same address now wraps to zero */
        0xb8, 0x00, 0x4c,
        0xcd, 0x21
    };
    xxemul_status status;
    xxemul *emulator = xxemul_create_dos(
        XXEMUL_DOS_COM, image, sizeof(image), &status);
    uint8_t low[2];
    uint8_t high[2];
    unsigned index;

    CHECK(emulator != NULL);
    for (index = 0u; index < 3u; ++index)
        CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_read_memory(emulator, 0u, low, sizeof(low))
        == XXEMUL_STATUS_OK);
    CHECK(xxemul_read_memory(emulator, 0x100000u, high, sizeof(high))
        == XXEMUL_STATUS_OK);
    CHECK(low[0] == 0u && low[1] == 0u);
    CHECK(high[0] == 0x34u && high[1] == 0x12u);
    for (index = 0u; index < 3u; ++index)
        CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_read_memory(emulator, 0u, low, sizeof(low))
        == XXEMUL_STATUS_OK);
    CHECK(xxemul_read_memory(emulator, 0x100000u, high, sizeof(high))
        == XXEMUL_STATUS_OK);
    CHECK(low[0] == 0x78u && low[1] == 0x56u);
    CHECK(high[0] == 0x34u && high[1] == 0x12u);
    CHECK(xxemul_run(emulator, 4u, NULL) == XXEMUL_STATUS_HALTED);
    xxemul_destroy(emulator);
    return 1;
}

static xxemul *create_dos_protected_fixture(void)
{
    static const uint8_t image[] = {
        0x0f, 0x01, 0x16, 0x80, 0x01, /* lgdt [180h] */
        0x0f, 0x01, 0x1e, 0x86, 0x01, /* lidt [186h] */
        0x0f, 0x01, 0x06, 0xc0, 0x01, /* sgdt [1c0h] */
        0x0f, 0x20, 0xc0,             /* mov eax, cr0 */
        0x0c, 0x01,                   /* or al, 1 */
        0x0f, 0x22, 0xc0,             /* mov cr0, eax */
        0xea, 0x00, 0x02, 0x08, 0x00  /* jmp 0008h:0200h */
    };
    static const uint8_t gdtr[] = {
        0x1f, 0x00, 0xd0, 0x82, 0x00, 0x00
    };
    static const uint8_t gdt[] = {
        0, 0, 0, 0, 0, 0, 0, 0,
        0xff, 0xff, 0x40, 0x81, 0x00, 0x9a, 0x40, 0x00,
        0xff, 0x0f, 0x00, 0x00, 0x09, 0x92, 0x40, 0x00,
        0xff, 0x0f, 0x00, 0x10, 0x09, 0x92, 0x40, 0x00
    };
    static const uint8_t code32[] = {
        0x66, 0xb8, 0x10, 0x00,       /* mov ax, 10h */
        0x8e, 0xd8,                   /* mov ds, ax */
        0x66, 0xb8, 0x18, 0x00,       /* mov ax, 18h */
        0x8e, 0xd0,                   /* mov ss, ax */
        0xc7, 0x05, 0x20, 0x00, 0x00, 0x00,
        0x78, 0x56, 0x34, 0x12,       /* mov dword [20h], 12345678h */
        0x0f, 0x23, 0xc0,             /* mov dr0, eax */
        0x31, 0xc0,                   /* xor eax, eax */
        0x0f, 0x21, 0xc0,             /* mov eax, dr0 */
        0x89, 0x05, 0x24, 0x00, 0x00, 0x00,
        0x0f, 0x22, 0xd0,             /* mov cr2, eax */
        0x31, 0xc0,
        0x0f, 0x20, 0xd0,             /* mov eax, cr2 */
        0x89, 0x05, 0x28, 0x00, 0x00, 0x00,
        0xbd, 0x50, 0x00, 0x00, 0x00, /* mov ebp, 50h */
        0xc7, 0x45, 0x00, 0x44, 0x33, 0x22, 0x11,
        0xbc, 0x00, 0x01, 0x00, 0x00, /* mov esp, 100h */
        0x68, 0xef, 0xcd, 0xab, 0x89, /* push 89abcdefh */
        0x58,                         /* pop eax */
        0xf4                          /* hlt */
    };
    xxemul_status status;
    xxemul *emulator = xxemul_create_dos(
        XXEMUL_DOS_COM, image, sizeof(image), &status);

    if (emulator == NULL) return NULL;
    if (xxemul_write_memory(emulator, 0x82c0u, gdtr, sizeof(gdtr))
            != XXEMUL_STATUS_OK
        || xxemul_write_memory(emulator, 0x82d0u, gdt, sizeof(gdt))
            != XXEMUL_STATUS_OK
        || xxemul_write_memory(emulator, 0x8340u, code32,
            sizeof(code32)) != XXEMUL_STATUS_OK) {
        xxemul_destroy(emulator);
        return NULL;
    }
    return emulator;
}

static int test_dos_protected_transition(void)
{
    xxemul *emulator = create_dos_protected_fixture();
    xxemul_x86_state state;
    uint8_t bytes[6];
    unsigned index;

    CHECK(emulator != NULL);
    for (index = 0u; index < 7u; ++index)
        CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK(state.segment[XXEMUL_X86_CS] == 8u && state.ip == 0x200u);
    CHECK(xxemul_read_memory(emulator, 0x8300u, bytes, sizeof(bytes))
        == XXEMUL_STATUS_OK);
    CHECK(bytes[0] == 0x1fu && bytes[1] == 0u);
    CHECK(bytes[2] == 0xd0u && bytes[3] == 0x82u);
    CHECK(xxemul_run(emulator, 32u, NULL) == XXEMUL_STATUS_HALTED);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK(state.segment[XXEMUL_X86_DS] == 0x10u);
    CHECK(state.segment[XXEMUL_X86_SS] == 0x18u);
    CHECK(state.gpr[XXEMUL_X86_RAX] == 0x89abcdefu);
    CHECK(state.gpr[XXEMUL_X86_RSP] == 0x100u);
    CHECK(xxemul_read_memory(emulator, 0x90020u, bytes, 4u)
        == XXEMUL_STATUS_OK);
    CHECK(bytes[0] == 0x78u && bytes[1] == 0x56u
        && bytes[2] == 0x34u && bytes[3] == 0x12u);
    CHECK(xxemul_read_memory(emulator, 0x90024u, bytes, 4u)
        == XXEMUL_STATUS_OK);
    CHECK(bytes[0] == 0x18u && bytes[1] == 0u);
    CHECK(xxemul_read_memory(emulator, 0x90028u, bytes, 4u)
        == XXEMUL_STATUS_OK);
    CHECK(bytes[0] == 0x18u && bytes[1] == 0u);
    CHECK(xxemul_read_memory(emulator, 0x91050u, bytes, 4u)
        == XXEMUL_STATUS_OK);
    CHECK(bytes[0] == 0x44u && bytes[1] == 0x33u
        && bytes[2] == 0x22u && bytes[3] == 0x11u);
    CHECK(xxemul_read_memory(emulator, 0x90050u, bytes, 4u)
        == XXEMUL_STATUS_OK);
    CHECK(bytes[0] == 0u && bytes[1] == 0u);
    CHECK(xxemul_read_memory(emulator, 0x910fcu, bytes, 4u)
        == XXEMUL_STATUS_OK);
    CHECK(bytes[0] == 0xefu && bytes[1] == 0xcdu
        && bytes[2] == 0xabu && bytes[3] == 0x89u);
    xxemul_destroy(emulator);
    return 1;
}

static int test_dos_protected_bad_selector(void)
{
    xxemul *emulator = create_dos_protected_fixture();
    xxemul_x86_state state;
    static const uint8_t short_limit[] = {7u, 0u};
    unsigned index;

    CHECK(emulator != NULL);
    CHECK(xxemul_write_memory(emulator, 0x82c0u,
        short_limit, sizeof(short_limit)) == XXEMUL_STATUS_OK);
    for (index = 0u; index < 6u; ++index)
        CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_ADDRESS_FAULT);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK(state.segment[XXEMUL_X86_CS] == 0x814u);
    CHECK(state.ip == 0x117u);
    xxemul_destroy(emulator);
    return 1;
}

static int test_dos_protected_segment_limit(void)
{
    static const uint8_t code32[] = {
        0x66, 0xb8, 0x10, 0x00,
        0x8e, 0xd8,
        0xc7, 0x05, 0x00, 0x10, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00
    };
    xxemul *emulator = create_dos_protected_fixture();
    xxemul_x86_state state;
    unsigned index;

    CHECK(emulator != NULL);
    CHECK(xxemul_write_memory(emulator, 0x8340u,
        code32, sizeof(code32)) == XXEMUL_STATUS_OK);
    for (index = 0u; index < 9u; ++index)
        CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_ADDRESS_FAULT);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK(state.ip == 0x206u);
    xxemul_destroy(emulator);
    return 1;
}

static int test_dos_ltr(void)
{
    static const uint8_t code32[] = {
        0x66, 0xb8, 0x20, 0x00, /* mov ax, 20h */
        0x0f, 0x00, 0xd8,       /* ltr ax */
        0x31, 0xc0,             /* xor eax, eax */
        0x0f, 0x00, 0xc8,       /* str ax */
        0xf4
    };
    static const uint8_t gdtr_limit[] = {0x27u, 0u};
    static const uint8_t tss_descriptor[] = {
        0x67u, 0u, 0u, 0xa0u, 0u, 0x89u, 0u, 0u
    };
    xxemul *emulator = create_dos_protected_fixture();
    xxemul_x86_state state;
    uint8_t access = 0u;
    unsigned index;

    CHECK(emulator != NULL);
    CHECK(xxemul_write_memory(emulator, 0x82c0u,
        gdtr_limit, sizeof(gdtr_limit)) == XXEMUL_STATUS_OK);
    CHECK(xxemul_write_memory(emulator, 0x82f0u,
        tss_descriptor, sizeof(tss_descriptor)) == XXEMUL_STATUS_OK);
    CHECK(xxemul_write_memory(emulator, 0x8340u,
        code32, sizeof(code32)) == XXEMUL_STATUS_OK);
    for (index = 0u; index < 7u; ++index)
        CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_run(emulator, 8u, NULL) == XXEMUL_STATUS_HALTED);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK(state.gpr[XXEMUL_X86_RAX] == 0x20u);
    CHECK(emulator->dos_tr_selector == 0x20u);
    CHECK(emulator->dos_tr_base == 0xa000u);
    CHECK(emulator->dos_tr_limit == 0x67u);
    CHECK(xxemul_read_memory(emulator, 0x82f5u,
        &access, 1u) == XXEMUL_STATUS_OK);
    CHECK(access == 0x8bu);
    xxemul_destroy(emulator);
    return 1;
}

static int test_dos_paging_boundary(void)
{
    static const uint8_t code32[] = {
        0x0f, 0x20, 0xc0,             /* mov eax, cr0 */
        0x0d, 0x00, 0x00, 0x00, 0x80, /* or eax, 80000000h */
        0x0f, 0x22, 0xc0              /* mov cr0, eax */
    };
    xxemul *emulator = create_dos_protected_fixture();
    xxemul_x86_state state;
    unsigned index;

    CHECK(emulator != NULL);
    CHECK(xxemul_write_memory(emulator, 0x8340u,
        code32, sizeof(code32)) == XXEMUL_STATUS_OK);
    for (index = 0u; index < 9u; ++index)
        CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_ADDRESS_FAULT);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK(state.ip == 0x20bu);
    xxemul_destroy(emulator);
    return 1;
}

static int dos_write_u32(xxemul *emulator, uint32_t address, uint32_t value)
{
    uint8_t bytes[4];
    unsigned index;

    for (index = 0u; index < 4u; ++index)
        bytes[index] = (uint8_t)(value >> (index * 8u));
    return xxemul_write_memory(emulator, address, bytes, sizeof(bytes))
        == XXEMUL_STATUS_OK;
}

static uint32_t dos_test_u32(const uint8_t *bytes)
{
    return (uint32_t)bytes[0] | ((uint32_t)bytes[1] << 8u)
        | ((uint32_t)bytes[2] << 16u) | ((uint32_t)bytes[3] << 24u);
}

static int dos_install_page_tables(
    xxemul *emulator, uint32_t data_page0, uint32_t data_page1)
{
    static const uint8_t two_page_limit = 0x1fu;

    return xxemul_write_memory(emulator, 0x82e1u,
            &two_page_limit, 1u) == XXEMUL_STATUS_OK
        && dos_write_u32(emulator, 0x4000u, 0x5003u)
        && dos_write_u32(emulator, 0x5020u, 0x8003u)
        && dos_write_u32(emulator, 0x5240u, data_page0 | 3u)
        && (data_page1 == 0u
            || dos_write_u32(emulator, 0x5244u, data_page1 | 3u));
}

static xxemul *create_dos_task_jump_fixture(int paging)
{
    static const uint8_t gdtr_limit[] = {0x3fu, 0u};
    static const uint8_t descriptors[] = {
        0x67, 0, 0, 0xa0, 0, 0x89, 0, 0, /* old TSS, selector 20h */
        0x67, 0, 0, 0xa1, 0, 0x89, 0, 0, /* new TSS, selector 28h */
        0, 0, 0, 0, 0, 0, 0, 0,       /* SGDT writes over selector 30h */
        0x3f, 0, 0, 0xa2, 0, 0x82, 0, 0  /* LDT, selector 38h */
    };
    static const uint8_t ldt_descriptors[] = {
        0xff, 0x0f, 0, 0xb0, 0, 0xfa, 0, 0,    /* 16-bit code */
        0xff, 0x0f, 0, 0xc0, 0, 0xf2, 0x40, 0, /* 32-bit data */
        0xff, 0x0f, 0, 0xd0, 0, 0xf2, 0x40, 0  /* 32-bit stack */
    };
    static const uint8_t code32[] = {
        0x66, 0xb8, 0x20, 0x00,             /* mov ax, 20h */
        0x0f, 0x00, 0xd8,                   /* ltr ax */
        0xea, 0, 0, 0, 0, 0x28, 0x00        /* jmp far 28h:0 */
    };
    static const uint8_t code16[] = {
        0xb8, 0x17, 0x00, /* mov ax, 17h */
        0x8e, 0xd8,       /* mov ds, ax */
        0xf4
    };
    xxemul *emulator = create_dos_protected_fixture();
    unsigned index;

    if (emulator == NULL) return NULL;
    if (xxemul_write_memory(emulator, 0x82c0u,
            gdtr_limit, sizeof(gdtr_limit)) != XXEMUL_STATUS_OK
        || xxemul_write_memory(emulator, 0x82f0u,
            descriptors, sizeof(descriptors)) != XXEMUL_STATUS_OK
        || xxemul_write_memory(emulator, 0xa208u,
            ldt_descriptors, sizeof(ldt_descriptors)) != XXEMUL_STATUS_OK
        || xxemul_write_memory(emulator, 0x8340u,
            code32, sizeof(code32)) != XXEMUL_STATUS_OK
        || xxemul_write_memory(emulator, 0xb020u,
            code16, sizeof(code16)) != XXEMUL_STATUS_OK
        || !dos_write_u32(emulator, 0xa020u, 0xdeadbeefu)
        || !dos_write_u32(emulator, 0xa01cu, 0x4000u)
        || !dos_write_u32(emulator, 0xa11cu, 0x6000u)
        || !dos_write_u32(emulator, 0xa120u, 0x20u)
        || !dos_write_u32(emulator, 0xa124u, 0x202u)
        || !dos_write_u32(emulator, 0xa128u, 0x12345678u)
        || !dos_write_u32(emulator, 0xa138u, 0x100u)
        || !dos_write_u32(emulator, 0xa148u, 0x17u)
        || !dos_write_u32(emulator, 0xa14cu, 0x0fu)
        || !dos_write_u32(emulator, 0xa150u, 0x1fu)
        || !dos_write_u32(emulator, 0xa154u, 0x17u)
        || !dos_write_u32(emulator, 0xa160u, 0x38u))
        goto fail;
    for (index = 0u; index < 9u; ++index)
        if (xxemul_step(emulator, NULL) != XXEMUL_STATUS_OK) goto fail;
    emulator->x86.gpr[XXEMUL_X86_RSP] = 0x300u;
    emulator->x86.gpr[XXEMUL_X86_RBX] = 0xfeedbeefu;
    emulator->x86.flags = 0x202u;
    if (paging) {
        if (!dos_write_u32(emulator, 0x4000u, 0x5007u)
            || !dos_write_u32(emulator, 0x6000u, 0x7007u))
            goto fail;
        for (index = 0u; index < 0x20u; ++index)
            if (!dos_write_u32(emulator, 0x5000u + 4u * index,
                    (index << 12u) | 7u)
                || !dos_write_u32(emulator, 0x7000u + 4u * index,
                    (index << 12u) | 7u))
                goto fail;
        emulator->dos_cr3 = 0x4000u;
        emulator->dos_cr0 |= UINT32_C(0x80000000);
    }
    return emulator;
fail:
    xxemul_destroy(emulator);
    return NULL;
}

static int test_dos_lsl_selector_limit(void)
{
    static const uint8_t code[] = {
        0x66, 0x0f, 0x03, 0xdb,       /* lsl ebx, ebx */
        0x0f, 0x03, 0xdb,             /* lsl bx, bx */
        0x66, 0x0f, 0x03, 0x1e, 0x00, 0x01, /* lsl ebx, [100h] */
        0xf4
    };
    static const uint8_t paged_data[] = {
        0x45, 0x23, 0, 0, 0, 0xf2, 0xc1, 0
    };
    static const uint8_t call_gate[] = {
        0xff, 0x00, 0, 0, 0, 0xec, 0, 0
    };
    static const uint8_t ring0_data[] = {
        0x56, 0x34, 0, 0, 0, 0x92, 0x42, 0
    };
    static const uint8_t conforming_code[] = {
        0x56, 0x34, 0, 0, 0, 0x9e, 0x42, 0
    };
    static const uint8_t absent_data[] = {
        0x56, 0x34, 0, 0, 0, 0x72, 0x42, 0
    };
    static const uint8_t ldt_descriptor[] = {
        0xff, 0x03, 0, 0, 0, 0xe2, 0, 0
    };
    xxemul *emulator = create_dos_task_jump_fixture(0);
    xxemul_x86_state state;
    uint8_t selector[] = {0x27, 0x00};

    CHECK(emulator != NULL);
    CHECK(xxemul_write_memory(emulator, 0xb020u,
        code, sizeof(code)) == XXEMUL_STATUS_OK);
    CHECK(xxemul_write_memory(emulator, 0xa220u,
        paged_data, sizeof(paged_data)) == XXEMUL_STATUS_OK);
    CHECK(xxemul_write_memory(emulator, 0xc100u,
        selector, sizeof(selector)) == XXEMUL_STATUS_OK);
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(emulator->x86.segment[XXEMUL_X86_CS] == 0x0fu);
    emulator->x86.gpr[XXEMUL_X86_RBX] = 0xfeed0027u;
    emulator->x86.flags = 0xa07u;
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK(state.gpr[XXEMUL_X86_RBX] == 0x12345fffu);
    CHECK(state.flags == 0xa47u);

    emulator->x86.gpr[XXEMUL_X86_RBX] = 0xabcd0027u;
    emulator->x86.flags = 0xa07u;
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK(state.gpr[XXEMUL_X86_RBX] == 0xabcd5fffu);
    CHECK(state.flags == 0xa47u);

    emulator->x86.gpr[XXEMUL_X86_RBX] = 0xdeadbeefu;
    emulator->x86.flags = 0xa07u;
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK(state.gpr[XXEMUL_X86_RBX] == 0x12345fffu);
    CHECK(state.flags == 0xa47u);

    emulator->x86.ip = 0x20u;
    emulator->x86.gpr[XXEMUL_X86_RBX] = 0xabcd0000u;
    emulator->x86.flags = 0xa47u;
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(emulator->x86.gpr[XXEMUL_X86_RBX] == 0xabcd0000u);
    CHECK(emulator->x86.flags == 0xa07u);

    emulator->x86.ip = 0x20u;
    emulator->x86.gpr[XXEMUL_X86_RBX] = 0xabcd0047u;
    emulator->x86.flags = 0xa47u;
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(emulator->x86.gpr[XXEMUL_X86_RBX] == 0xabcd0047u);
    CHECK(emulator->x86.flags == 0xa07u);

    CHECK(xxemul_write_memory(emulator, 0xa220u,
        call_gate, sizeof(call_gate)) == XXEMUL_STATUS_OK);
    emulator->x86.ip = 0x20u;
    emulator->x86.gpr[XXEMUL_X86_RBX] = 0xabcd0027u;
    emulator->x86.flags = 0xa47u;
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(emulator->x86.gpr[XXEMUL_X86_RBX] == 0xabcd0027u);
    CHECK(emulator->x86.flags == 0xa07u);

    CHECK(xxemul_write_memory(emulator, 0xa220u,
        ring0_data, sizeof(ring0_data)) == XXEMUL_STATUS_OK);
    emulator->x86.ip = 0x20u;
    emulator->x86.flags = 0xa47u;
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(emulator->x86.gpr[XXEMUL_X86_RBX] == 0xabcd0027u);
    CHECK(emulator->x86.flags == 0xa07u);

    CHECK(xxemul_write_memory(emulator, 0xa220u,
        conforming_code, sizeof(conforming_code)) == XXEMUL_STATUS_OK);
    emulator->x86.ip = 0x20u;
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(emulator->x86.gpr[XXEMUL_X86_RBX] == 0x23456u);
    CHECK(emulator->x86.flags == 0xa47u);

    CHECK(xxemul_write_memory(emulator, 0xa220u,
        absent_data, sizeof(absent_data)) == XXEMUL_STATUS_OK);
    emulator->x86.ip = 0x20u;
    emulator->x86.gpr[XXEMUL_X86_RBX] = 0x27u;
    emulator->x86.flags = 0xa07u;
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(emulator->x86.gpr[XXEMUL_X86_RBX] == 0x23456u);
    CHECK(emulator->x86.flags == 0xa47u);

    CHECK(xxemul_write_memory(emulator, 0x8310u,
        ldt_descriptor, sizeof(ldt_descriptor)) == XXEMUL_STATUS_OK);
    emulator->dos_gdtr_limit = 0x47u;
    emulator->x86.ip = 0x20u;
    emulator->x86.gpr[XXEMUL_X86_RBX] = 0x43u;
    emulator->x86.flags = 0xa07u;
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(emulator->x86.gpr[XXEMUL_X86_RBX] == 0x3ffu);
    CHECK(emulator->x86.flags == 0xa47u);
    xxemul_destroy(emulator);
    return 1;
}

static int test_dos_lsl_rpl_visibility(void)
{
    static const uint8_t code[] = {0x0f, 0x03, 0xdb};
    static const uint8_t data[] = {
        0x56, 0x34, 0, 0, 0, 0x92, 0x42, 0
    };
    xxemul *emulator = create_dos_protected_fixture();
    unsigned index;

    CHECK(emulator != NULL);
    CHECK(xxemul_write_memory(emulator, 0x8340u,
        code, sizeof(code)) == XXEMUL_STATUS_OK);
    CHECK(xxemul_write_memory(emulator, 0x82f0u,
        data, sizeof(data)) == XXEMUL_STATUS_OK);
    for (index = 0u; index < 7u; ++index)
        CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    emulator->dos_gdtr_limit = 0x27u;
    emulator->x86.gpr[XXEMUL_X86_RBX] = 0x23u;
    emulator->x86.flags = 0xa47u;
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(emulator->x86.gpr[XXEMUL_X86_RBX] == 0x23u);
    CHECK(emulator->x86.flags == 0xa07u);
    emulator->x86.ip = 0x200u;
    emulator->x86.gpr[XXEMUL_X86_RBX] = 0x20u;
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(emulator->x86.gpr[XXEMUL_X86_RBX] == 0x23456u);
    CHECK(emulator->x86.flags == 0xa47u);
    xxemul_destroy(emulator);
    return 1;
}

static int test_dos_task_jump_and_ldt(void)
{
    xxemul *emulator = create_dos_task_jump_fixture(1);
    xxemul_x86_state state;
    xxemul_status status;
    char instruction[96];
    uint8_t bytes[4];

    CHECK(emulator != NULL);
    xxemul_format_current(emulator, instruction, sizeof(instruction));
    status = xxemul_step(emulator, NULL);
    if (status != XXEMUL_STATUS_OK)
        fprintf(stderr, "task jump: %s at %s CR2=%08x\n",
            xxemul_status_string(status), instruction, emulator->dos_cr2);
    CHECK(status == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK(state.segment[XXEMUL_X86_CS] == 0x0fu && state.ip == 0x20u);
    CHECK(state.segment[XXEMUL_X86_SS] == 0x1fu);
    CHECK(state.segment[XXEMUL_X86_DS] == 0x17u);
    CHECK(state.gpr[XXEMUL_X86_RAX] == 0x12345678u);
    CHECK(state.gpr[XXEMUL_X86_RSP] == 0x100u);
    CHECK(state.flags == 0x202u);
    CHECK(emulator->mode == XXEMUL_MODE_X86_16);
    CHECK(emulator->dos_tr_selector == 0x28u);
    CHECK(emulator->dos_tr_base == 0xa100u);
    CHECK(emulator->dos_ldtr_selector == 0x38u);
    CHECK(emulator->dos_ldtr_base == 0xa200u);
    CHECK(emulator->dos_segments[XXEMUL_X86_CS].base == 0xb000u);
    CHECK(emulator->dos_segments[XXEMUL_X86_SS].base == 0xd000u);
    CHECK((emulator->dos_segments[XXEMUL_X86_SS].flags & 4u) != 0u);
    CHECK(emulator->dos_cr0 == UINT32_C(0x80000019));
    CHECK(emulator->dos_cr3 == 0x6000u);
    CHECK(xxemul_read_memory(emulator, 0x82f5u, bytes, 1u)
        == XXEMUL_STATUS_OK && bytes[0] == 0x89u);
    CHECK(xxemul_read_memory(emulator, 0x82fdu, bytes, 1u)
        == XXEMUL_STATUS_OK && bytes[0] == 0x8bu);
    CHECK(xxemul_read_memory(emulator, 0xa020u, bytes, 4u)
        == XXEMUL_STATUS_OK);
    CHECK(dos_test_u32(bytes) == 0x20eu);
    CHECK(xxemul_read_memory(emulator, 0xa024u, bytes, 4u)
        == XXEMUL_STATUS_OK);
    CHECK(dos_test_u32(bytes) == 0x202u);
    CHECK(xxemul_read_memory(emulator, 0xa034u, bytes, 4u)
        == XXEMUL_STATUS_OK);
    CHECK(dos_test_u32(bytes) == 0xfeedbeefu);
    CHECK(xxemul_read_memory(emulator, 0xa038u, bytes, 4u)
        == XXEMUL_STATUS_OK);
    CHECK(dos_test_u32(bytes) == 0x300u);
    CHECK(xxemul_read_memory(emulator, 0xa01cu, bytes, 4u)
        == XXEMUL_STATUS_OK);
    CHECK(dos_test_u32(bytes) == 0x4000u);
    CHECK(xxemul_read_memory(emulator, 0xa100u, bytes, 2u)
        == XXEMUL_STATUS_OK && bytes[0] == 0u && bytes[1] == 0u);
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(emulator->dos_segments[XXEMUL_X86_DS].base == 0xc000u);
    xxemul_destroy(emulator);
    return 1;
}

static int test_dos_task_jump_bad_ldt(void)
{
    xxemul *emulator = create_dos_task_jump_fixture(0);
    xxemul_x86_state state;
    uint8_t bytes[4];

    CHECK(emulator != NULL);
    CHECK(dos_write_u32(emulator, 0xa154u, 0x27u));
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_ADDRESS_FAULT);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK(state.segment[XXEMUL_X86_CS] == 8u && state.ip == 0x207u);
    CHECK(state.gpr[XXEMUL_X86_RSP] == 0x300u);
    CHECK(emulator->dos_tr_selector == 0x20u);
    CHECK(emulator->dos_ldtr_selector == 0u);
    CHECK(emulator->dos_cr0 == 0x11u);
    CHECK(xxemul_read_memory(emulator, 0x82f5u, bytes, 1u)
        == XXEMUL_STATUS_OK && bytes[0] == 0x8bu);
    CHECK(xxemul_read_memory(emulator, 0x82fdu, bytes, 1u)
        == XXEMUL_STATUS_OK && bytes[0] == 0x89u);
    CHECK(xxemul_read_memory(emulator, 0xa020u, bytes, 4u)
        == XXEMUL_STATUS_OK);
    CHECK(dos_test_u32(bytes) == 0xdeadbeefu);
    xxemul_destroy(emulator);
    return 1;
}

static int test_dos_task_jump_busy_target(void)
{
    xxemul *emulator = create_dos_task_jump_fixture(0);
    xxemul_x86_state state;
    uint8_t access = 0x8bu;
    uint8_t bytes[4];

    CHECK(emulator != NULL);
    CHECK(xxemul_write_memory(emulator, 0x82fdu, &access, 1u)
        == XXEMUL_STATUS_OK);
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_ADDRESS_FAULT);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK(state.segment[XXEMUL_X86_CS] == 8u && state.ip == 0x207u);
    CHECK(emulator->dos_tr_selector == 0x20u);
    CHECK(emulator->dos_cr0 == 0x11u);
    CHECK(xxemul_read_memory(emulator, 0x82f5u, &access, 1u)
        == XXEMUL_STATUS_OK && access == 0x8bu);
    CHECK(xxemul_read_memory(emulator, 0x82fdu, &access, 1u)
        == XXEMUL_STATUS_OK && access == 0x8bu);
    CHECK(xxemul_read_memory(emulator, 0xa020u, bytes, 4u)
        == XXEMUL_STATUS_OK);
    CHECK(dos_test_u32(bytes) == 0xdeadbeefu);
    xxemul_destroy(emulator);
    return 1;
}

static xxemul *create_dos_interrupt_fixture(int ring_zero, int allowed)
{
    static const uint8_t ring3_code[] = {
        0xff, 0x0f, 0, 0xe0, 0, 0xfa, 0, 0
    };
    static const uint8_t ring0_code[] = {
        0xff, 0x0f, 0, 0xe0, 0, 0x9a, 0, 0
    };
    static const uint8_t ring0_stack[] = {
        0xff, 0x0f, 0, 0xf0, 0, 0x92, 0x40, 0
    };
    static const uint8_t caller[] = {0xcd, 0x31, 0xf4};
    static const uint8_t handler[] = {0x66, 0xcf};
    uint8_t gate[] = {0, 1, 0x43, 0, 0, 0xee, 0, 0};
    xxemul *emulator = create_dos_task_jump_fixture(1);

    if (emulator == NULL) return NULL;
    if (xxemul_step(emulator, NULL) != XXEMUL_STATUS_OK)
        goto fail;
    if (ring_zero) gate[2] = 0x40u;
    if (!allowed) gate[5] = 0x8eu;
    if (xxemul_write_memory(emulator, 0x8310u,
            ring_zero ? ring0_code : ring3_code,
            sizeof(ring3_code)) != XXEMUL_STATUS_OK
        || xxemul_write_memory(emulator, 0x8318u,
            ring0_stack, sizeof(ring0_stack)) != XXEMUL_STATUS_OK
        || xxemul_write_memory(emulator, 0x10188u,
            gate, sizeof(gate)) != XXEMUL_STATUS_OK
        || xxemul_write_memory(emulator, 0xb020u,
            caller, sizeof(caller)) != XXEMUL_STATUS_OK
        || xxemul_write_memory(emulator, 0xe100u,
            handler, sizeof(handler)) != XXEMUL_STATUS_OK
        || !dos_write_u32(emulator, 0xa104u, 0x200u)
        || !dos_write_u32(emulator, 0xa108u, 0x48u))
        goto fail;
    emulator->dos_gdtr_limit = 0x4fu;
    emulator->dos_idtr_base = 0x10000u;
    emulator->dos_idtr_limit = 0x1ffu;
    emulator->x86.flags = 0x3202u;
    return emulator;
fail:
    xxemul_destroy(emulator);
    return NULL;
}

static int test_dos_protected_interrupt_same_ring(void)
{
    xxemul *emulator = create_dos_interrupt_fixture(0, 1);
    xxemul_x86_state state;
    uint8_t frame[12];

    CHECK(emulator != NULL);
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK(state.segment[XXEMUL_X86_CS] == 0x43u && state.ip == 0x100u);
    CHECK(state.segment[XXEMUL_X86_SS] == 0x1fu);
    CHECK(state.gpr[XXEMUL_X86_RSP] == 0xf4u);
    CHECK((state.flags & 0x200u) == 0u);
    CHECK(xxemul_read_memory(emulator, 0xd0f4u, frame, sizeof(frame))
        == XXEMUL_STATUS_OK);
    CHECK(dos_test_u32(frame) == 0x22u);
    CHECK(dos_test_u32(frame + 4u) == 0x0fu);
    CHECK(dos_test_u32(frame + 8u) == 0x3202u);
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK(state.segment[XXEMUL_X86_CS] == 0x0fu && state.ip == 0x22u);
    CHECK(state.segment[XXEMUL_X86_SS] == 0x1fu);
    CHECK(state.gpr[XXEMUL_X86_RSP] == 0x100u);
    CHECK(state.flags == 0x3202u);
    xxemul_destroy(emulator);
    return 1;
}

static int test_dos_protected_interrupt_ring_switch(void)
{
    xxemul *emulator = create_dos_interrupt_fixture(1, 1);
    xxemul_x86_state state;
    uint8_t frame[20];

    CHECK(emulator != NULL);
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK(state.segment[XXEMUL_X86_CS] == 0x40u && state.ip == 0x100u);
    CHECK(state.segment[XXEMUL_X86_SS] == 0x48u);
    CHECK(state.gpr[XXEMUL_X86_RSP] == 0x1ecu);
    CHECK(xxemul_read_memory(emulator, 0xf1ecu, frame, sizeof(frame))
        == XXEMUL_STATUS_OK);
    CHECK(dos_test_u32(frame) == 0x22u);
    CHECK(dos_test_u32(frame + 4u) == 0x0fu);
    CHECK(dos_test_u32(frame + 8u) == 0x3202u);
    CHECK(dos_test_u32(frame + 12u) == 0x100u);
    CHECK(dos_test_u32(frame + 16u) == 0x1fu);
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK(state.segment[XXEMUL_X86_CS] == 0x0fu && state.ip == 0x22u);
    CHECK(state.segment[XXEMUL_X86_SS] == 0x1fu);
    CHECK(state.gpr[XXEMUL_X86_RSP] == 0x100u);
    CHECK(state.flags == 0x3202u);
    xxemul_destroy(emulator);
    return 1;
}

static int test_dos_protected_interrupt_gate_privilege(void)
{
    xxemul *emulator = create_dos_interrupt_fixture(0, 0);
    xxemul_x86_state state;
    uint8_t frame[12];
    unsigned index;

    CHECK(emulator != NULL);
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_ADDRESS_FAULT);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK(state.segment[XXEMUL_X86_CS] == 0x0fu && state.ip == 0x20u);
    CHECK(state.segment[XXEMUL_X86_SS] == 0x1fu);
    CHECK(state.gpr[XXEMUL_X86_RSP] == 0x100u);
    CHECK(xxemul_read_memory(emulator, 0xd0f4u, frame, sizeof(frame))
        == XXEMUL_STATUS_OK);
    for (index = 0u; index < sizeof(frame); ++index)
        CHECK(frame[index] == 0u);
    xxemul_destroy(emulator);
    return 1;
}

static int test_dos_protected_iret_bad_return(void)
{
    xxemul *emulator = create_dos_interrupt_fixture(1, 1);
    xxemul_x86_state before;
    xxemul_x86_state after;
    uint8_t frame[20];
    uint8_t original[20];

    CHECK(emulator != NULL);
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(dos_write_u32(emulator, 0xf1f0u, 0x3u));
    CHECK(xxemul_read_memory(emulator, 0xf1ecu,
        original, sizeof(original)) == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_x86_state(emulator, &before) == XXEMUL_STATUS_OK);
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_ADDRESS_FAULT);
    CHECK(xxemul_get_x86_state(emulator, &after) == XXEMUL_STATUS_OK);
    CHECK(after.ip == before.ip && after.flags == before.flags);
    CHECK(after.segment[XXEMUL_X86_CS] == before.segment[XXEMUL_X86_CS]);
    CHECK(after.segment[XXEMUL_X86_SS] == before.segment[XXEMUL_X86_SS]);
    CHECK(after.gpr[XXEMUL_X86_RSP] == before.gpr[XXEMUL_X86_RSP]);
    CHECK(xxemul_read_memory(emulator, 0xf1ecu,
        frame, sizeof(frame)) == XXEMUL_STATUS_OK);
    CHECK(memcmp(frame, original, sizeof(frame)) == 0);
    xxemul_destroy(emulator);
    return 1;
}

static int test_dos_page_fault_string_restart(void)
{
    static const uint8_t gate[] = {
        0x00, 0x01, 0x40, 0x00, 0x00, 0x8e, 0x00, 0x00
    };
    static const uint8_t flat_data[] = {
        0xff, 0xff, 0x00, 0x00, 0x00, 0x92, 0x40, 0x00
    };
    static const uint8_t destination[] = {
        0xff, 0x0f, 0x00, 0x00, 0x40, 0xf2, 0x40, 0x00
    };
    static const uint8_t caller[] = {
        0xb8, 0x27, 0x00,       /* mov ax, 27h */
        0x8e, 0xc0,             /* mov es, ax */
        0x66, 0x67, 0xf3, 0xa5, /* rep movsd */
        0xf4
    };
    static const uint8_t handler[] = {
        0x1e,                   /* push ds */
        0xb8, 0x50, 0x00,       /* mov ax, flat data selector */
        0x8e, 0xd8,             /* mov ds, ax */
        0x66, 0xc7, 0x06, 0x04, 0x60,
        0x07, 0x90, 0x00, 0x00, /* map the missing PDE */
        0x1f,                   /* pop ds */
        0x66, 0x58,             /* discard page-fault error code */
        0x66, 0xcf              /* iretd */
    };
    static const uint8_t source[] = {0xde, 0xad, 0xbe, 0xef};
    xxemul *emulator = create_dos_interrupt_fixture(1, 1);
    xxemul_x86_state state;
    uint8_t frame[24];
    uint8_t copied[4];
    unsigned index;

    CHECK(emulator != NULL);
    CHECK(xxemul_write_memory(emulator, 0x10070u,
        gate, sizeof(gate)) == XXEMUL_STATUS_OK);
    CHECK(xxemul_write_memory(emulator, 0x8320u,
        flat_data, sizeof(flat_data)) == XXEMUL_STATUS_OK);
    CHECK(xxemul_write_memory(emulator, 0xa220u,
        destination, sizeof(destination)) == XXEMUL_STATUS_OK);
    CHECK(xxemul_write_memory(emulator, 0xb020u,
        caller, sizeof(caller)) == XXEMUL_STATUS_OK);
    CHECK(xxemul_write_memory(emulator, 0xe100u,
        handler, sizeof(handler)) == XXEMUL_STATUS_OK);
    CHECK(xxemul_write_memory(emulator, 0xc000u,
        source, sizeof(source)) == XXEMUL_STATUS_OK);
    CHECK(dos_write_u32(emulator, 0x9000u, 0x8007u));
    emulator->dos_gdtr_limit = 0x57u;
    emulator->x86.gpr[XXEMUL_X86_RCX] = 1u;
    emulator->x86.gpr[XXEMUL_X86_RSI] = 0u;
    emulator->x86.gpr[XXEMUL_X86_RDI] = 0u;

    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK(state.segment[XXEMUL_X86_CS] == 0x40u && state.ip == 0x100u);
    CHECK(state.segment[XXEMUL_X86_SS] == 0x48u);
    CHECK(state.gpr[XXEMUL_X86_RSP] == 0x1e8u);
    CHECK(state.gpr[XXEMUL_X86_RCX] == 1u);
    CHECK(state.gpr[XXEMUL_X86_RSI] == 0u);
    CHECK(state.gpr[XXEMUL_X86_RDI] == 0u);
    CHECK(emulator->dos_cr2 == 0x400000u);
    CHECK(xxemul_read_memory(emulator, 0xf1e8u,
        frame, sizeof(frame)) == XXEMUL_STATUS_OK);
    CHECK(dos_test_u32(frame) == 6u);
    CHECK(dos_test_u32(frame + 4u) == 0x25u);
    CHECK(dos_test_u32(frame + 8u) == 0x0fu);
    CHECK(dos_test_u32(frame + 12u) == 0x3202u);
    CHECK(dos_test_u32(frame + 16u) == 0x100u);
    CHECK(dos_test_u32(frame + 20u) == 0x1fu);
    CHECK(xxemul_read_memory(emulator, 0x6004u,
        copied, sizeof(copied)) == XXEMUL_STATUS_OK);
    CHECK((dos_test_u32(copied) & 1u) == 0u);

    for (index = 0u; index < 7u; ++index)
        CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK(state.segment[XXEMUL_X86_CS] == 0x0fu && state.ip == 0x25u);
    CHECK(state.segment[XXEMUL_X86_SS] == 0x1fu);
    CHECK(state.gpr[XXEMUL_X86_RSP] == 0x100u);
    CHECK(state.segment[XXEMUL_X86_DS] == 0x17u);
    CHECK(xxemul_read_memory(emulator, 0x6004u,
        copied, sizeof(copied)) == XXEMUL_STATUS_OK);
    CHECK(dos_test_u32(copied) == 0x9007u);
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK(state.ip == 0x29u && state.gpr[XXEMUL_X86_RCX] == 0u);
    CHECK(state.gpr[XXEMUL_X86_RSI] == 4u);
    CHECK(state.gpr[XXEMUL_X86_RDI] == 4u);
    CHECK(xxemul_read_memory(emulator, 0x8000u,
        copied, sizeof(copied)) == XXEMUL_STATUS_OK);
    CHECK(memcmp(copied, source, sizeof(source)) == 0);
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_HALTED);
    xxemul_destroy(emulator);
    return 1;
}

static int test_dos_page_fault_fetch_restart(void)
{
    static const uint8_t gate[] = {
        0x00, 0x01, 0x40, 0x00, 0x00, 0x8e, 0x00, 0x00
    };
    static const uint8_t flat_data[] = {
        0xff, 0xff, 0x00, 0x00, 0x00, 0x92, 0x40, 0x00
    };
    static const uint8_t code32[] = {
        0xff, 0x0f, 0x00, 0x00, 0x40, 0xfa, 0x40, 0x00
    };
    static const uint8_t jump[] = {
        0x66, 0xea, 0x00, 0x01, 0x00, 0x00, 0x2f, 0x00
    };
    static const uint8_t handler[] = {
        0x1e, 0xb8, 0x50, 0x00, 0x8e, 0xd8,
        0x66, 0xc7, 0x06, 0x04, 0x60, 0x07, 0x90, 0x00, 0x00,
        0x1f, 0x66, 0x58, 0x66, 0xcf
    };
    static const uint8_t halt[] = {0xf4};
    xxemul *emulator = create_dos_interrupt_fixture(1, 1);
    xxemul_x86_state state;
    uint8_t frame[24];
    unsigned index;

    CHECK(emulator != NULL);
    CHECK(xxemul_write_memory(emulator, 0x10070u,
        gate, sizeof(gate)) == XXEMUL_STATUS_OK);
    CHECK(xxemul_write_memory(emulator, 0x8320u,
        flat_data, sizeof(flat_data)) == XXEMUL_STATUS_OK);
    CHECK(xxemul_write_memory(emulator, 0xa228u,
        code32, sizeof(code32)) == XXEMUL_STATUS_OK);
    CHECK(xxemul_write_memory(emulator, 0xb020u,
        jump, sizeof(jump)) == XXEMUL_STATUS_OK);
    CHECK(xxemul_write_memory(emulator, 0xe100u,
        handler, sizeof(handler)) == XXEMUL_STATUS_OK);
    CHECK(xxemul_write_memory(emulator, 0x8100u,
        halt, sizeof(halt)) == XXEMUL_STATUS_OK);
    CHECK(dos_write_u32(emulator, 0x9000u, 0x8007u));
    emulator->dos_gdtr_limit = 0x57u;

    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK(state.segment[XXEMUL_X86_CS] == 0x2fu && state.ip == 0x100u);
    CHECK(emulator->mode == XXEMUL_MODE_X86_32);
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK(state.segment[XXEMUL_X86_CS] == 0x40u && state.ip == 0x100u);
    CHECK(state.segment[XXEMUL_X86_SS] == 0x48u);
    CHECK(state.gpr[XXEMUL_X86_RSP] == 0x1e8u);
    CHECK(emulator->dos_cr2 == 0x400100u);
    CHECK(xxemul_read_memory(emulator, 0xf1e8u,
        frame, sizeof(frame)) == XXEMUL_STATUS_OK);
    CHECK(dos_test_u32(frame) == 4u);
    CHECK(dos_test_u32(frame + 4u) == 0x100u);
    CHECK(dos_test_u32(frame + 8u) == 0x2fu);
    CHECK(dos_test_u32(frame + 12u) == 0x3202u);
    CHECK(dos_test_u32(frame + 16u) == 0x100u);
    CHECK(dos_test_u32(frame + 20u) == 0x1fu);

    for (index = 0u; index < 7u; ++index)
        CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK(state.segment[XXEMUL_X86_CS] == 0x2fu && state.ip == 0x100u);
    CHECK(state.gpr[XXEMUL_X86_RSP] == 0x100u);
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_HALTED);
    xxemul_destroy(emulator);
    return 1;
}

static int test_dos_page_fault_cross_page_fetch_restart(void)
{
    static const uint8_t gate[] = {
        0x00, 0x01, 0x40, 0x00, 0x00, 0x8e, 0x00, 0x00
    };
    static const uint8_t flat_data[] = {
        0xff, 0xff, 0x00, 0x00, 0x00, 0x92, 0x40, 0x00
    };
    static const uint8_t code32[] = {
        0xff, 0x1f, 0x00, 0x00, 0x00, 0xfa, 0x40, 0x00
    };
    static const uint8_t jump[] = {
        0x66, 0xea, 0xff, 0x0f, 0x00, 0x00, 0x2f, 0x00
    };
    static const uint8_t handler[] = {
        0x1e, 0xb8, 0x50, 0x00, 0x8e, 0xd8,
        0x66, 0xc7, 0x06, 0x04, 0x70, 0x07, 0x10, 0x00, 0x00,
        0x1f, 0x66, 0x58, 0x66, 0xcf
    };
    static const uint8_t opcode = 0xb8; /* mov eax, 12345678h */
    static const uint8_t next_page[] = {0x78, 0x56, 0x34, 0x12, 0xf4};
    xxemul *emulator = create_dos_interrupt_fixture(1, 1);
    xxemul_x86_state state;
    uint8_t frame[24];
    uint8_t pte[4];
    unsigned index;

    CHECK(emulator != NULL);
    CHECK(xxemul_write_memory(emulator, 0x10070u,
        gate, sizeof(gate)) == XXEMUL_STATUS_OK);
    CHECK(xxemul_write_memory(emulator, 0x8320u,
        flat_data, sizeof(flat_data)) == XXEMUL_STATUS_OK);
    CHECK(xxemul_write_memory(emulator, 0xa228u,
        code32, sizeof(code32)) == XXEMUL_STATUS_OK);
    CHECK(xxemul_write_memory(emulator, 0xb020u,
        jump, sizeof(jump)) == XXEMUL_STATUS_OK);
    CHECK(xxemul_write_memory(emulator, 0xe100u,
        handler, sizeof(handler)) == XXEMUL_STATUS_OK);
    CHECK(xxemul_write_memory(emulator, 0xfffu,
        &opcode, sizeof(opcode)) == XXEMUL_STATUS_OK);
    CHECK(xxemul_write_memory(emulator, 0x1000u,
        next_page, sizeof(next_page)) == XXEMUL_STATUS_OK);
    CHECK(dos_write_u32(emulator, 0x7004u, 0x1006u));
    CHECK(xxemul_read_memory(emulator, 0x7004u,
        pte, sizeof(pte)) == XXEMUL_STATUS_OK);
    CHECK(dos_test_u32(pte) == 0x1006u);
    CHECK((emulator->dos_cr0 & UINT32_C(0x80000000)) != 0u);
    emulator->dos_gdtr_limit = 0x57u;

    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK(state.segment[XXEMUL_X86_CS] == 0x2fu && state.ip == 0xfffu);
    CHECK(emulator->mode == XXEMUL_MODE_X86_32);
    emulator->x86.gpr[XXEMUL_X86_RAX] = 0xa5a5a5a5u;
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    if (state.segment[XXEMUL_X86_CS] != 0x40u || state.ip != 0x100u)
        fprintf(stderr, "cross-page fetch: %04x:%08llx CR2=%08x\n",
            state.segment[XXEMUL_X86_CS],
            (unsigned long long)state.ip, emulator->dos_cr2);
    CHECK(state.segment[XXEMUL_X86_CS] == 0x40u && state.ip == 0x100u);
    CHECK(state.segment[XXEMUL_X86_SS] == 0x48u);
    CHECK(state.gpr[XXEMUL_X86_RSP] == 0x1e8u);
    CHECK(state.gpr[XXEMUL_X86_RAX] == 0xa5a5a5a5u);
    CHECK(emulator->dos_cr2 == 0x1000u);
    CHECK(xxemul_read_memory(emulator, 0xf1e8u,
        frame, sizeof(frame)) == XXEMUL_STATUS_OK);
    CHECK(dos_test_u32(frame) == 4u);
    CHECK(dos_test_u32(frame + 4u) == 0xfffu);
    CHECK(dos_test_u32(frame + 8u) == 0x2fu);
    CHECK(dos_test_u32(frame + 12u) == 0x3202u);
    CHECK(dos_test_u32(frame + 16u) == 0x100u);
    CHECK(dos_test_u32(frame + 20u) == 0x1fu);

    for (index = 0u; index < 7u; ++index)
        CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK(state.segment[XXEMUL_X86_CS] == 0x2fu && state.ip == 0xfffu);
    CHECK(state.gpr[XXEMUL_X86_RSP] == 0x100u);
    CHECK(xxemul_read_memory(emulator, 0x7004u,
        pte, sizeof(pte)) == XXEMUL_STATUS_OK);
    CHECK(dos_test_u32(pte) == 0x1007u);
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK(state.segment[XXEMUL_X86_CS] == 0x2fu && state.ip == 0x1004u);
    CHECK(state.gpr[XXEMUL_X86_RAX] == 0x12345678u);
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_HALTED);
    xxemul_destroy(emulator);
    return 1;
}

static int test_dos_task_jump_page_fault_fetch(void)
{
    static const uint8_t gate[] = {
        0x00, 0x01, 0x40, 0x00, 0x00, 0x8e, 0x00, 0x00
    };
    static const uint8_t ring0_code[] = {
        0xff, 0x0f, 0x00, 0xe0, 0x00, 0x9a, 0x00, 0x00
    };
    static const uint8_t ring0_stack[] = {
        0xff, 0x0f, 0x00, 0xf0, 0x00, 0x92, 0x40, 0x00
    };
    static const uint8_t flat_data[] = {
        0xff, 0xff, 0x00, 0x00, 0x00, 0x92, 0x40, 0x00
    };
    static const uint8_t code32[] = {
        0xff, 0x0f, 0x00, 0x00, 0x40, 0xfa, 0x40, 0x00
    };
    static const uint8_t handler[] = {
        0x1e, 0xb8, 0x50, 0x00, 0x8e, 0xd8,
        0x66, 0xc7, 0x06, 0x04, 0x60, 0x07, 0x90, 0x00, 0x00,
        0x1f, 0x66, 0x58, 0x66, 0xcf
    };
    static const uint8_t halt[] = {0xf4};
    xxemul *emulator = create_dos_task_jump_fixture(1);
    xxemul_x86_state state;
    uint8_t frame[24];
    unsigned index;

    CHECK(emulator != NULL);
    CHECK(xxemul_write_memory(emulator, 0x10070u,
        gate, sizeof(gate)) == XXEMUL_STATUS_OK);
    CHECK(xxemul_write_memory(emulator, 0x8310u,
        ring0_code, sizeof(ring0_code)) == XXEMUL_STATUS_OK);
    CHECK(xxemul_write_memory(emulator, 0x8318u,
        ring0_stack, sizeof(ring0_stack)) == XXEMUL_STATUS_OK);
    CHECK(xxemul_write_memory(emulator, 0x8320u,
        flat_data, sizeof(flat_data)) == XXEMUL_STATUS_OK);
    CHECK(xxemul_write_memory(emulator, 0xa208u,
        code32, sizeof(code32)) == XXEMUL_STATUS_OK);
    CHECK(xxemul_write_memory(emulator, 0xe100u,
        handler, sizeof(handler)) == XXEMUL_STATUS_OK);
    CHECK(xxemul_write_memory(emulator, 0x8020u,
        halt, sizeof(halt)) == XXEMUL_STATUS_OK);
    CHECK(dos_write_u32(emulator, 0x9000u, 0x8007u));
    CHECK(dos_write_u32(emulator, 0xa104u, 0x200u));
    CHECK(dos_write_u32(emulator, 0xa108u, 0x48u));
    emulator->dos_gdtr_limit = 0x57u;
    emulator->dos_idtr_base = 0x10000u;
    emulator->dos_idtr_limit = 0x1ffu;

    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK(state.segment[XXEMUL_X86_CS] == 0x0fu && state.ip == 0x20u);
    CHECK(emulator->dos_tr_selector == 0x28u);
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK(state.segment[XXEMUL_X86_CS] == 0x40u && state.ip == 0x100u);
    CHECK(state.segment[XXEMUL_X86_SS] == 0x48u);
    CHECK(state.gpr[XXEMUL_X86_RSP] == 0x1e8u);
    CHECK(emulator->dos_cr2 == 0x400020u);
    CHECK(xxemul_read_memory(emulator, 0xf1e8u,
        frame, sizeof(frame)) == XXEMUL_STATUS_OK);
    CHECK(dos_test_u32(frame) == 4u);
    CHECK(dos_test_u32(frame + 4u) == 0x20u);
    CHECK(dos_test_u32(frame + 8u) == 0x0fu);
    CHECK(dos_test_u32(frame + 12u) == 0x202u);
    CHECK(dos_test_u32(frame + 16u) == 0x100u);
    CHECK(dos_test_u32(frame + 20u) == 0x1fu);
    for (index = 0u; index < 7u; ++index)
        CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK(state.segment[XXEMUL_X86_CS] == 0x0fu && state.ip == 0x20u);
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_HALTED);
    xxemul_destroy(emulator);
    return 1;
}

static int test_dos_page_fault_mov_restart(void)
{
    static const uint8_t gate[] = {
        0x00, 0x01, 0x40, 0x00, 0x00, 0x8e, 0x00, 0x00
    };
    static const uint8_t flat_data[] = {
        0xff, 0xff, 0x00, 0x00, 0x00, 0x92, 0x40, 0x00
    };
    static const uint8_t source_segment[] = {
        0xff, 0x0f, 0x00, 0x00, 0x40, 0xf2, 0x40, 0x00
    };
    static const uint8_t caller[] = {
        0xb8, 0x27, 0x00, 0x8e, 0xd8,
        0x66, 0x67, 0x8b, 0x06,
        0x67, 0x80, 0x3e, 0x1d,
        0xf4
    };
    static const uint8_t handler[] = {
        0x1e, 0xb8, 0x50, 0x00, 0x8e, 0xd8,
        0x66, 0xc7, 0x06, 0x04, 0x60, 0x07, 0x90, 0x00, 0x00,
        0x1f, 0x66, 0x58, 0x66, 0xcf
    };
    xxemul *emulator = create_dos_interrupt_fixture(1, 1);
    xxemul_x86_state state;
    uint8_t frame[24];
    unsigned index;

    CHECK(emulator != NULL);
    CHECK(xxemul_write_memory(emulator, 0x10070u,
        gate, sizeof(gate)) == XXEMUL_STATUS_OK);
    CHECK(xxemul_write_memory(emulator, 0x8320u,
        flat_data, sizeof(flat_data)) == XXEMUL_STATUS_OK);
    CHECK(xxemul_write_memory(emulator, 0xa220u,
        source_segment, sizeof(source_segment)) == XXEMUL_STATUS_OK);
    CHECK(xxemul_write_memory(emulator, 0xb020u,
        caller, sizeof(caller)) == XXEMUL_STATUS_OK);
    CHECK(xxemul_write_memory(emulator, 0xe100u,
        handler, sizeof(handler)) == XXEMUL_STATUS_OK);
    CHECK(dos_write_u32(emulator, 0x8000u, 0x12345678u));
    CHECK(dos_write_u32(emulator, 0x9000u, 0x8007u));
    emulator->dos_gdtr_limit = 0x57u;
    emulator->x86.gpr[XXEMUL_X86_RSI] = 0u;
    emulator->x86.gpr[XXEMUL_X86_RAX] = 0u;

    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK(state.segment[XXEMUL_X86_CS] == 0x40u && state.ip == 0x100u);
    CHECK(state.gpr[XXEMUL_X86_RSP] == 0x1e8u);
    CHECK(emulator->dos_cr2 == 0x400000u);
    CHECK(xxemul_read_memory(emulator, 0xf1e8u,
        frame, sizeof(frame)) == XXEMUL_STATUS_OK);
    CHECK(dos_test_u32(frame) == 4u);
    CHECK(dos_test_u32(frame + 4u) == 0x25u);
    CHECK(dos_test_u32(frame + 8u) == 0x0fu);
    CHECK(dos_test_u32(frame + 12u) == 0x3202u);
    CHECK(dos_test_u32(frame + 16u) == 0x100u);
    CHECK(dos_test_u32(frame + 20u) == 0x1fu);
    CHECK(state.gpr[XXEMUL_X86_RAX] == 0x27u);

    for (index = 0u; index < 7u; ++index)
        CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK(state.segment[XXEMUL_X86_CS] == 0x0fu && state.ip == 0x25u);
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK(state.gpr[XXEMUL_X86_RAX] == 0x12345678u);
    CHECK(dos_write_u32(emulator, 0x6004u, 0u));
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK(state.segment[XXEMUL_X86_CS] == 0x40u && state.ip == 0x100u);
    CHECK(emulator->dos_cr2 == 0x400000u);
    CHECK(xxemul_read_memory(emulator, 0xf1e8u,
        frame, sizeof(frame)) == XXEMUL_STATUS_OK);
    CHECK(dos_test_u32(frame) == 4u);
    CHECK(dos_test_u32(frame + 4u) == 0x29u);
    for (index = 0u; index < 7u; ++index)
        CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK(state.ip == 0x2du && (state.flags & 0x40u) == 0u);
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_HALTED);
    xxemul_destroy(emulator);
    return 1;
}

static int test_dos_page_fault_movzx_restart(void)
{
    static const uint8_t gate[] = {
        0x00, 0x01, 0x40, 0x00, 0x00, 0x8e, 0x00, 0x00
    };
    static const uint8_t flat_data[] = {
        0xff, 0xff, 0x00, 0x00, 0x00, 0xf2, 0x40, 0x00
    };
    static const uint8_t code32[] = {
        0xff, 0x0f, 0x00, 0x00, 0x40, 0xfa, 0x40, 0x00
    };
    static const uint8_t jump[] = {
        0x66, 0xea, 0x00, 0x01, 0x00, 0x00, 0x2f, 0x00
    };
    static const uint8_t caller[] = {
        0x66, 0xb8, 0x53, 0x00,       /* mov ax, flat data selector */
        0x8e, 0xd8,                   /* mov ds, ax */
        0x0f, 0xb6, 0x05, 0x00, 0x10, 0x00, 0x00, /* movzx eax, byte [1000h] */
        0xf4
    };
    static const uint8_t handler[] = {
        0x1e, 0x50, 0xb8, 0x50, 0x00, 0x8e, 0xd8,
        0x66, 0xc7, 0x06, 0x04, 0x70, 0x07, 0x10, 0x00, 0x00,
        0x58, 0x1f, 0x66, 0x83, 0xc4, 0x04, 0x66, 0xcf
    };
    static const uint8_t source = 0xe5u;
    xxemul *emulator = create_dos_interrupt_fixture(1, 1);
    xxemul_x86_state state;
    uint8_t frame[24];
    uint8_t pte[4];
    unsigned index;

    CHECK(emulator != NULL);
    CHECK(xxemul_write_memory(emulator, 0x10070u,
        gate, sizeof(gate)) == XXEMUL_STATUS_OK);
    CHECK(xxemul_write_memory(emulator, 0x8320u,
        flat_data, sizeof(flat_data)) == XXEMUL_STATUS_OK);
    CHECK(xxemul_write_memory(emulator, 0xa228u,
        code32, sizeof(code32)) == XXEMUL_STATUS_OK);
    CHECK(xxemul_write_memory(emulator, 0xb020u,
        jump, sizeof(jump)) == XXEMUL_STATUS_OK);
    CHECK(xxemul_write_memory(emulator, 0x8100u,
        caller, sizeof(caller)) == XXEMUL_STATUS_OK);
    CHECK(xxemul_write_memory(emulator, 0xe100u,
        handler, sizeof(handler)) == XXEMUL_STATUS_OK);
    CHECK(xxemul_write_memory(emulator, 0x1000u,
        &source, sizeof(source)) == XXEMUL_STATUS_OK);
    CHECK(dos_write_u32(emulator, 0x6004u, 0x9007u));
    CHECK(dos_write_u32(emulator, 0x9000u, 0x8007u));
    CHECK(dos_write_u32(emulator, 0x7004u, 0x1006u));
    emulator->dos_gdtr_limit = 0x57u;

    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK(state.segment[XXEMUL_X86_CS] == 0x2fu && state.ip == 0x100u);
    CHECK(emulator->mode == XXEMUL_MODE_X86_32);
    emulator->x86.gpr[XXEMUL_X86_RAX] = 0xa5a5a5a5u;
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK(state.segment[XXEMUL_X86_DS] == 0x53u && state.ip == 0x106u);
    CHECK(state.gpr[XXEMUL_X86_RAX] == 0xa5a50053u);

    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK(state.segment[XXEMUL_X86_CS] == 0x40u && state.ip == 0x100u);
    CHECK(state.segment[XXEMUL_X86_SS] == 0x48u);
    CHECK(state.gpr[XXEMUL_X86_RSP] == 0x1e8u);
    CHECK(state.gpr[XXEMUL_X86_RAX] == 0xa5a50053u);
    CHECK(emulator->dos_cr2 == 0x1000u);
    CHECK(xxemul_read_memory(emulator, 0xf1e8u,
        frame, sizeof(frame)) == XXEMUL_STATUS_OK);
    CHECK(dos_test_u32(frame) == 4u);
    CHECK(dos_test_u32(frame + 4u) == 0x106u);
    CHECK(dos_test_u32(frame + 8u) == 0x2fu);
    CHECK(dos_test_u32(frame + 12u) == 0x3202u);
    CHECK(dos_test_u32(frame + 16u) == 0x100u);
    CHECK(dos_test_u32(frame + 20u) == 0x1fu);
    CHECK(xxemul_read_memory(emulator, 0x7004u,
        pte, sizeof(pte)) == XXEMUL_STATUS_OK);
    CHECK(dos_test_u32(pte) == 0x1006u);

    for (index = 0u; index < 9u; ++index)
        CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK(state.segment[XXEMUL_X86_CS] == 0x2fu && state.ip == 0x106u);
    CHECK(state.segment[XXEMUL_X86_DS] == 0x53u);
    CHECK(state.gpr[XXEMUL_X86_RSP] == 0x100u);
    CHECK(state.gpr[XXEMUL_X86_RAX] == 0xa5a50053u);
    CHECK(xxemul_read_memory(emulator, 0x7004u,
        pte, sizeof(pte)) == XXEMUL_STATUS_OK);
    CHECK(dos_test_u32(pte) == 0x1007u);

    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK(state.segment[XXEMUL_X86_CS] == 0x2fu && state.ip == 0x10du);
    CHECK(state.gpr[XXEMUL_X86_RAX] == source);
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_HALTED);
    xxemul_destroy(emulator);
    return 1;
}

static int test_dos_page_fault_inc_byte_restart(void)
{
    static const uint8_t gate[] = {
        0x00, 0x01, 0x40, 0x00, 0x00, 0x8e, 0x00, 0x00
    };
    static const uint8_t flat_data[] = {
        0xff, 0xff, 0x00, 0x00, 0x00, 0x92, 0x40, 0x00
    };
    static const uint8_t target_segment[] = {
        0xff, 0x0f, 0x00, 0x00, 0x40, 0xf2, 0x40, 0x00
    };
    static const uint8_t caller[] = {
        0xb8, 0x27, 0x00,       /* mov ax, 27h */
        0x8e, 0xd8,             /* mov ds, ax */
        0xfe, 0x06, 0x00, 0x00, /* inc byte ptr [0] */
        0xf4
    };
    static const uint8_t handler[] = {
        0x1e, 0xb8, 0x50, 0x00, 0x8e, 0xd8,
        0x66, 0xc7, 0x06, 0x00, 0x90, 0x07, 0x80, 0x00, 0x00,
        0x1f, 0x66, 0x58, 0x66, 0xcf
    };
    static const uint8_t initial_byte = 0x7fu;
    const uint32_t initial_flags = 0x3243u;
    xxemul *emulator = create_dos_interrupt_fixture(1, 1);
    xxemul_x86_state state;
    uint8_t frame[24];
    uint8_t value;
    uint8_t pte[4];
    uint64_t initial_rax;
    unsigned index;

    CHECK(emulator != NULL);
    CHECK(xxemul_write_memory(emulator, 0x10070u,
        gate, sizeof(gate)) == XXEMUL_STATUS_OK);
    CHECK(xxemul_write_memory(emulator, 0x8320u,
        flat_data, sizeof(flat_data)) == XXEMUL_STATUS_OK);
    CHECK(xxemul_write_memory(emulator, 0xa220u,
        target_segment, sizeof(target_segment)) == XXEMUL_STATUS_OK);
    CHECK(xxemul_write_memory(emulator, 0xb020u,
        caller, sizeof(caller)) == XXEMUL_STATUS_OK);
    CHECK(xxemul_write_memory(emulator, 0xe100u,
        handler, sizeof(handler)) == XXEMUL_STATUS_OK);
    CHECK(xxemul_write_memory(emulator, 0x8000u,
        &initial_byte, sizeof(initial_byte)) == XXEMUL_STATUS_OK);
    CHECK(dos_write_u32(emulator, 0x6004u, 0x9007u));
    CHECK(dos_write_u32(emulator, 0x9000u, 0x8006u));
    emulator->dos_gdtr_limit = 0x57u;

    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    emulator->x86.flags = initial_flags;
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK(state.segment[XXEMUL_X86_CS] == 0x0fu && state.ip == 0x25u);
    CHECK(state.segment[XXEMUL_X86_DS] == 0x27u);
    CHECK(state.flags == initial_flags);
    initial_rax = state.gpr[XXEMUL_X86_RAX];
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK(state.segment[XXEMUL_X86_CS] == 0x40u && state.ip == 0x100u);
    CHECK(state.segment[XXEMUL_X86_SS] == 0x48u);
    CHECK(state.gpr[XXEMUL_X86_RSP] == 0x1e8u);
    CHECK(state.gpr[XXEMUL_X86_RAX] == initial_rax);
    CHECK(emulator->dos_cr2 == 0x400000u);
    CHECK(xxemul_read_memory(emulator, 0xf1e8u,
        frame, sizeof(frame)) == XXEMUL_STATUS_OK);
    CHECK((dos_test_u32(frame) & 5u) == 4u);
    CHECK(dos_test_u32(frame + 4u) == 0x25u);
    CHECK(dos_test_u32(frame + 8u) == 0x0fu);
    CHECK(dos_test_u32(frame + 12u) == initial_flags);
    CHECK(dos_test_u32(frame + 16u) == 0x100u);
    CHECK(dos_test_u32(frame + 20u) == 0x1fu);
    CHECK((state.flags & 0x8d5u) == (initial_flags & 0x8d5u));
    CHECK(xxemul_read_memory(emulator, 0x8000u,
        &value, sizeof(value)) == XXEMUL_STATUS_OK && value == initial_byte);
    CHECK(xxemul_read_memory(emulator, 0x9000u,
        pte, sizeof(pte)) == XXEMUL_STATUS_OK);
    CHECK(dos_test_u32(pte) == 0x8006u);

    for (index = 0u; index < 7u; ++index)
        CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK(state.segment[XXEMUL_X86_CS] == 0x0fu && state.ip == 0x25u);
    CHECK(state.segment[XXEMUL_X86_DS] == 0x27u);
    CHECK(state.gpr[XXEMUL_X86_RSP] == 0x100u);
    CHECK(state.flags == initial_flags);
    CHECK(xxemul_read_memory(emulator, 0x9000u,
        pte, sizeof(pte)) == XXEMUL_STATUS_OK);
    CHECK(dos_test_u32(pte) == 0x8007u);
    CHECK(xxemul_read_memory(emulator, 0x8000u,
        &value, sizeof(value)) == XXEMUL_STATUS_OK && value == initial_byte);

    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK(state.segment[XXEMUL_X86_CS] == 0x0fu && state.ip == 0x29u);
    CHECK((state.flags & 0x8d5u) == 0x891u);
    CHECK(xxemul_read_memory(emulator, 0x8000u,
        &value, sizeof(value)) == XXEMUL_STATUS_OK && value == 0x80u);
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_HALTED);
    CHECK(xxemul_read_memory(emulator, 0x8000u,
        &value, sizeof(value)) == XXEMUL_STATUS_OK && value == 0x80u);
    xxemul_destroy(emulator);
    return 1;
}

static int test_dos_page_fault_fdiv_restart(void)
{
    static const uint8_t gate[] = {
        0x00, 0x01, 0x40, 0x00, 0x00, 0x8e, 0x00, 0x00
    };
    static const uint8_t flat_data[] = {
        0xff, 0xff, 0x00, 0x00, 0x00, 0x92, 0x40, 0x00
    };
    static const uint8_t source_segment[] = {
        0xff, 0x0f, 0x00, 0x00, 0x40, 0xf2, 0x40, 0x00
    };
    static const uint8_t caller[] = {
        0xb8, 0x27, 0x00,       /* mov ax, 27h */
        0x8e, 0xd8,             /* mov ds, ax */
        0xd8, 0x36, 0x00, 0x00, /* fdiv dword ptr [0] */
        0xf4
    };
    static const uint8_t handler[] = {
        0x1e, 0xb8, 0x50, 0x00, 0x8e, 0xd8,
        0x66, 0xc7, 0x06, 0x04, 0x60, 0x07, 0x90, 0x00, 0x00,
        0x1f, 0x66, 0x58, 0x66, 0xcf
    };
    static const uint8_t divisor[] = {0x00, 0x00, 0x00, 0x40};
    xxemul *emulator = create_dos_interrupt_fixture(1, 1);
    xxemul_x86_state state;
    double initial_stack[8];
    uint8_t frame[24];
    unsigned index;

    CHECK(emulator != NULL);
    CHECK(xxemul_write_memory(emulator, 0x10070u,
        gate, sizeof(gate)) == XXEMUL_STATUS_OK);
    CHECK(xxemul_write_memory(emulator, 0x8320u,
        flat_data, sizeof(flat_data)) == XXEMUL_STATUS_OK);
    CHECK(xxemul_write_memory(emulator, 0xa220u,
        source_segment, sizeof(source_segment)) == XXEMUL_STATUS_OK);
    CHECK(xxemul_write_memory(emulator, 0xb020u,
        caller, sizeof(caller)) == XXEMUL_STATUS_OK);
    CHECK(xxemul_write_memory(emulator, 0xe100u,
        handler, sizeof(handler)) == XXEMUL_STATUS_OK);
    CHECK(xxemul_write_memory(emulator, 0x8000u,
        divisor, sizeof(divisor)) == XXEMUL_STATUS_OK);
    CHECK(dos_write_u32(emulator, 0x9000u, 0x8007u));
    emulator->dos_gdtr_limit = 0x57u;
    emulator->x87_stack[0] = 84.0;
    emulator->x87_depth = 1u;
    emulator->x87_top = 7u;
    memcpy(initial_stack, emulator->x87_stack, sizeof(initial_stack));

    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK(state.segment[XXEMUL_X86_CS] == 0x40u && state.ip == 0x100u);
    CHECK(emulator->dos_cr2 == 0x400000u);
    CHECK(xxemul_read_memory(emulator, 0xf1e8u,
        frame, sizeof(frame)) == XXEMUL_STATUS_OK);
    CHECK(dos_test_u32(frame) == 4u);
    CHECK(dos_test_u32(frame + 4u) == 0x25u);
    CHECK(dos_test_u32(frame + 16u) == 0x100u);
    CHECK(dos_test_u32(frame + 20u) == 0x1fu);
    CHECK(emulator->x87_depth == 1u && emulator->x87_top == 7u);
    CHECK(emulator->x87_status == 0u && emulator->x87_control == 0x037fu);
    CHECK(memcmp(emulator->x87_stack, initial_stack,
        sizeof(initial_stack)) == 0);

    for (index = 0u; index < 7u; ++index)
        CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK(state.segment[XXEMUL_X86_CS] == 0x0fu && state.ip == 0x25u);
    CHECK(state.segment[XXEMUL_X86_DS] == 0x27u);
    CHECK(state.gpr[XXEMUL_X86_RSP] == 0x100u);
    CHECK(emulator->x87_depth == 1u && emulator->x87_top == 7u);
    CHECK(emulator->x87_status == 0u && emulator->x87_control == 0x037fu);
    CHECK(memcmp(emulator->x87_stack, initial_stack,
        sizeof(initial_stack)) == 0);

    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK(state.ip == 0x29u);
    CHECK(emulator->x87_depth == 1u && emulator->x87_top == 7u);
    CHECK(emulator->x87_stack[0] == 42.0);
    CHECK(emulator->x87_status == 0u && emulator->x87_control == 0x037fu);
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_HALTED);
    xxemul_destroy(emulator);
    return 1;
}

static int test_dos_page_fault_indirect_jmp_restart(void)
{
    static const uint8_t gate[] = {
        0x00, 0x01, 0x40, 0x00, 0x00, 0x8e, 0x00, 0x00
    };
    static const uint8_t flat_data[] = {
        0xff, 0xff, 0x00, 0x00, 0x00, 0x92, 0x40, 0x00
    };
    static const uint8_t source_segment[] = {
        0xff, 0x0f, 0x00, 0x00, 0x40, 0xf2, 0x40, 0x00
    };
    static const uint8_t caller[] = {
        0xb8, 0x27, 0x00,             /* mov ax, 27h */
        0x8e, 0xd8,                   /* mov ds, ax */
        0x66, 0x67, 0xff, 0x25,
        0x00, 0x00, 0x00, 0x00,       /* jmp dword ptr [0] */
        0xf4
    };
    static const uint8_t handler[] = {
        0x1e, 0xb8, 0x50, 0x00, 0x8e, 0xd8,
        0x66, 0xc7, 0x06, 0x04, 0x60, 0x07, 0x90, 0x00, 0x00,
        0x1f, 0x66, 0x58, 0x66, 0xcf
    };
    static const uint8_t halt[] = {0xf4};
    xxemul *emulator = create_dos_interrupt_fixture(1, 1);
    xxemul_x86_state state;
    uint8_t frame[24];
    unsigned index;

    CHECK(emulator != NULL);
    CHECK(xxemul_write_memory(emulator, 0x10070u,
        gate, sizeof(gate)) == XXEMUL_STATUS_OK);
    CHECK(xxemul_write_memory(emulator, 0x8320u,
        flat_data, sizeof(flat_data)) == XXEMUL_STATUS_OK);
    CHECK(xxemul_write_memory(emulator, 0xa220u,
        source_segment, sizeof(source_segment)) == XXEMUL_STATUS_OK);
    CHECK(xxemul_write_memory(emulator, 0xb020u,
        caller, sizeof(caller)) == XXEMUL_STATUS_OK);
    CHECK(xxemul_write_memory(emulator, 0xb040u,
        halt, sizeof(halt)) == XXEMUL_STATUS_OK);
    CHECK(xxemul_write_memory(emulator, 0xe100u,
        handler, sizeof(handler)) == XXEMUL_STATUS_OK);
    CHECK(dos_write_u32(emulator, 0x8000u, 0x40u));
    CHECK(dos_write_u32(emulator, 0x9000u, 0x8007u));
    emulator->dos_gdtr_limit = 0x57u;

    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK(state.segment[XXEMUL_X86_CS] == 0x40u && state.ip == 0x100u);
    CHECK(state.segment[XXEMUL_X86_SS] == 0x48u);
    CHECK(state.gpr[XXEMUL_X86_RSP] == 0x1e8u);
    CHECK(emulator->dos_cr2 == 0x400000u);
    CHECK(xxemul_read_memory(emulator, 0xf1e8u,
        frame, sizeof(frame)) == XXEMUL_STATUS_OK);
    CHECK(dos_test_u32(frame) == 4u);
    CHECK(dos_test_u32(frame + 4u) == 0x25u);
    CHECK(dos_test_u32(frame + 8u) == 0x0fu);
    CHECK(dos_test_u32(frame + 12u) == 0x3202u);
    CHECK(dos_test_u32(frame + 16u) == 0x100u);
    CHECK(dos_test_u32(frame + 20u) == 0x1fu);

    for (index = 0u; index < 7u; ++index)
        CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK(state.segment[XXEMUL_X86_CS] == 0x0fu && state.ip == 0x25u);
    CHECK(state.segment[XXEMUL_X86_DS] == 0x27u);
    CHECK(state.gpr[XXEMUL_X86_RSP] == 0x100u);
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK(state.segment[XXEMUL_X86_CS] == 0x0fu && state.ip == 0x40u);
    CHECK(state.gpr[XXEMUL_X86_RSP] == 0x100u);
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_HALTED);
    xxemul_destroy(emulator);
    return 1;
}

static int test_dos_page_fault_push_restart(void)
{
    static const uint8_t gate[] = {
        0x00, 0x01, 0x40, 0x00, 0x00, 0x8e, 0x00, 0x00
    };
    static const uint8_t flat_data[] = {
        0xff, 0xff, 0x00, 0x00, 0x00, 0x92, 0x40, 0x00
    };
    static const uint8_t stack[] = {
        0xff, 0x0f, 0x00, 0x00, 0x40, 0xf2, 0x40, 0x00
    };
    static const uint8_t caller[] = {
        0xb8, 0x1f, 0x00,       /* mov ax, 1fh */
        0x8e, 0xd0,             /* mov ss, ax */
        0x66, 0x68, 0x78, 0x56, 0x34, 0x12, /* push 12345678h */
        0xf4
    };
    static const uint8_t handler[] = {
        0x1e, 0xb8, 0x50, 0x00, 0x8e, 0xd8,
        0x66, 0xc7, 0x06, 0x04, 0x60, 0x07, 0x90, 0x00, 0x00,
        0x1f, 0x66, 0x58, 0x66, 0xcf
    };
    xxemul *emulator = create_dos_interrupt_fixture(1, 1);
    xxemul_x86_state state;
    uint8_t frame[24];
    uint8_t pushed[4];
    unsigned index;

    CHECK(emulator != NULL);
    CHECK(xxemul_write_memory(emulator, 0x10070u,
        gate, sizeof(gate)) == XXEMUL_STATUS_OK);
    CHECK(xxemul_write_memory(emulator, 0x8320u,
        flat_data, sizeof(flat_data)) == XXEMUL_STATUS_OK);
    CHECK(xxemul_write_memory(emulator, 0xa218u,
        stack, sizeof(stack)) == XXEMUL_STATUS_OK);
    CHECK(xxemul_write_memory(emulator, 0xb020u,
        caller, sizeof(caller)) == XXEMUL_STATUS_OK);
    CHECK(xxemul_write_memory(emulator, 0xe100u,
        handler, sizeof(handler)) == XXEMUL_STATUS_OK);
    CHECK(dos_write_u32(emulator, 0x9000u, 0x8007u));
    emulator->dos_gdtr_limit = 0x57u;

    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK(state.segment[XXEMUL_X86_CS] == 0x40u && state.ip == 0x100u);
    CHECK(state.segment[XXEMUL_X86_SS] == 0x48u);
    CHECK(state.gpr[XXEMUL_X86_RSP] == 0x1e8u);
    CHECK(emulator->dos_cr2 == 0x4000fcu);
    CHECK(xxemul_read_memory(emulator, 0xf1e8u,
        frame, sizeof(frame)) == XXEMUL_STATUS_OK);
    CHECK(dos_test_u32(frame) == 6u);
    CHECK(dos_test_u32(frame + 4u) == 0x25u);
    CHECK(dos_test_u32(frame + 8u) == 0x0fu);
    CHECK(dos_test_u32(frame + 12u) == 0x3202u);
    CHECK(dos_test_u32(frame + 16u) == 0x100u);
    CHECK(dos_test_u32(frame + 20u) == 0x1fu);
    CHECK(xxemul_read_memory(emulator, 0x80fcu,
        pushed, sizeof(pushed)) == XXEMUL_STATUS_OK);
    CHECK(dos_test_u32(pushed) == 0u);

    for (index = 0u; index < 7u; ++index)
        CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK(state.segment[XXEMUL_X86_CS] == 0x0fu && state.ip == 0x25u);
    CHECK(state.segment[XXEMUL_X86_SS] == 0x1fu);
    CHECK(state.gpr[XXEMUL_X86_RSP] == 0x100u);
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK(state.gpr[XXEMUL_X86_RSP] == 0xfcu && state.ip == 0x2bu);
    CHECK(xxemul_read_memory(emulator, 0x80fcu,
        pushed, sizeof(pushed)) == XXEMUL_STATUS_OK);
    CHECK(dos_test_u32(pushed) == 0x12345678u);
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_HALTED);
    xxemul_destroy(emulator);
    return 1;
}

static int test_dos_page_fault_pop_store_rollback(void)
{
    static const uint8_t gate[] = {
        0x00, 0x01, 0x40, 0x00, 0x00, 0x8e, 0x00, 0x00
    };
    static const uint8_t flat_data[] = {
        0xff, 0xff, 0x00, 0x00, 0x00, 0x92, 0x40, 0x00
    };
    static const uint8_t destination[] = {
        0xff, 0x0f, 0x00, 0x00, 0x40, 0xf2, 0x40, 0x00
    };
    static const uint8_t caller[] = {
        0xb8, 0x27, 0x00,       /* mov ax, 27h */
        0x8e, 0xd8,             /* mov ds, ax */
        0x66, 0x67, 0x8f, 0x06, /* pop dword ptr [esi] */
        0xf4
    };
    static const uint8_t handler[] = {
        0x1e, 0xb8, 0x50, 0x00, 0x8e, 0xd8,
        0x66, 0xc7, 0x06, 0x04, 0x60, 0x07, 0x90, 0x00, 0x00,
        0x1f, 0x66, 0x58, 0x66, 0xcf
    };
    xxemul *emulator = create_dos_interrupt_fixture(1, 1);
    xxemul_x86_state state;
    uint8_t frame[24];
    uint8_t stored[4];
    unsigned index;

    CHECK(emulator != NULL);
    CHECK(xxemul_write_memory(emulator, 0x10070u,
        gate, sizeof(gate)) == XXEMUL_STATUS_OK);
    CHECK(xxemul_write_memory(emulator, 0x8320u,
        flat_data, sizeof(flat_data)) == XXEMUL_STATUS_OK);
    CHECK(xxemul_write_memory(emulator, 0xa220u,
        destination, sizeof(destination)) == XXEMUL_STATUS_OK);
    CHECK(xxemul_write_memory(emulator, 0xb020u,
        caller, sizeof(caller)) == XXEMUL_STATUS_OK);
    CHECK(xxemul_write_memory(emulator, 0xe100u,
        handler, sizeof(handler)) == XXEMUL_STATUS_OK);
    CHECK(dos_write_u32(emulator, 0xd100u, 0x12345678u));
    CHECK(dos_write_u32(emulator, 0x9000u, 0x8007u));
    emulator->dos_gdtr_limit = 0x57u;
    emulator->x86.gpr[XXEMUL_X86_RSI] = 0u;

    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK(state.segment[XXEMUL_X86_CS] == 0x40u && state.ip == 0x100u);
    CHECK(emulator->dos_cr2 == 0x400000u);
    CHECK(xxemul_read_memory(emulator, 0xf1e8u,
        frame, sizeof(frame)) == XXEMUL_STATUS_OK);
    CHECK(dos_test_u32(frame) == 6u);
    CHECK(dos_test_u32(frame + 4u) == 0x25u);
    CHECK(dos_test_u32(frame + 16u) == 0x100u);
    CHECK(dos_test_u32(frame + 20u) == 0x1fu);
    CHECK(xxemul_read_memory(emulator, 0x8000u,
        stored, sizeof(stored)) == XXEMUL_STATUS_OK);
    CHECK(dos_test_u32(stored) == 0u);

    for (index = 0u; index < 7u; ++index)
        CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK(state.segment[XXEMUL_X86_CS] == 0x0fu && state.ip == 0x25u);
    CHECK(state.gpr[XXEMUL_X86_RSP] == 0x100u);
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK(state.gpr[XXEMUL_X86_RSP] == 0x104u && state.ip == 0x29u);
    CHECK(xxemul_read_memory(emulator, 0x8000u,
        stored, sizeof(stored)) == XXEMUL_STATUS_OK);
    CHECK(dos_test_u32(stored) == 0x12345678u);
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_HALTED);
    xxemul_destroy(emulator);
    return 1;
}

static int test_dos_paging_cross_page(void)
{
    static const uint8_t code32[] = {
        0xb8, 0x00, 0x40, 0x00, 0x00, /* mov eax, 4000h */
        0x0f, 0x22, 0xd8,             /* mov cr3, eax */
        0x0f, 0x20, 0xc0,             /* mov eax, cr0 */
        0x0d, 0x00, 0x00, 0x00, 0x80, /* or eax, 80000000h */
        0x0f, 0x22, 0xc0,             /* mov cr0, eax */
        0x66, 0xb8, 0x10, 0x00,       /* mov ax, 10h */
        0x8e, 0xd8,                   /* mov ds, ax */
        0xc7, 0x05, 0xfe, 0x0f, 0x00, 0x00,
        0x44, 0x33, 0x22, 0x11,       /* mov dword [0ffe], 11223344h */
        0xa1, 0xfe, 0x0f, 0x00, 0x00, /* mov eax, [0ffe] */
        0xf4
    };
    xxemul *emulator = create_dos_protected_fixture();
    xxemul_x86_state state;
    uint8_t bytes[4];
    unsigned index;
    xxemul_status run_status;

    CHECK(emulator != NULL);
    CHECK(dos_install_page_tables(emulator, 0xa0000u, 0xb0000u));
    CHECK(xxemul_write_memory(emulator, 0x8340u,
        code32, sizeof(code32)) == XXEMUL_STATUS_OK);
    for (index = 0u; index < 7u; ++index)
        CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    run_status = xxemul_run(emulator, 20u, NULL);
    if (run_status != XXEMUL_STATUS_HALTED) {
        xxemul_get_x86_state(emulator, &state);
        fprintf(stderr, "paging cross-page: %s at %04x:%08llx CR2=%08x\n",
            xxemul_status_string(run_status),
            state.segment[XXEMUL_X86_CS],
            (unsigned long long)state.ip, emulator->dos_cr2);
    }
    CHECK(run_status == XXEMUL_STATUS_HALTED);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK(state.gpr[XXEMUL_X86_RAX] == 0x11223344u);
    CHECK(emulator->dos_cr0 == UINT32_C(0x80000011));
    CHECK(emulator->dos_cr3 == 0x4000u);
    CHECK(xxemul_read_memory(emulator, 0xa0ffeu, bytes, 2u)
        == XXEMUL_STATUS_OK);
    CHECK(bytes[0] == 0x44u && bytes[1] == 0x33u);
    CHECK(xxemul_read_memory(emulator, 0xb0000u, bytes, 2u)
        == XXEMUL_STATUS_OK);
    CHECK(bytes[0] == 0x22u && bytes[1] == 0x11u);
    CHECK(xxemul_read_memory(emulator, 0x4000u, bytes, 4u)
        == XXEMUL_STATUS_OK);
    CHECK((bytes[0] & 0x20u) != 0u);
    CHECK(xxemul_read_memory(emulator, 0x5240u, bytes, 4u)
        == XXEMUL_STATUS_OK);
    CHECK((bytes[0] & 0x60u) == 0x60u);
    CHECK(xxemul_read_memory(emulator, 0x5244u, bytes, 4u)
        == XXEMUL_STATUS_OK);
    CHECK((bytes[0] & 0x60u) == 0x60u);
    xxemul_destroy(emulator);
    return 1;
}

static int test_dos_paging_not_present(void)
{
    static const uint8_t code32[] = {
        0xb8, 0x00, 0x40, 0x00, 0x00,
        0x0f, 0x22, 0xd8,
        0x0f, 0x20, 0xc0,
        0x0d, 0x00, 0x00, 0x00, 0x80,
        0x0f, 0x22, 0xc0,
        0x66, 0xb8, 0x10, 0x00,
        0x8e, 0xd8,
        0xc7, 0x05, 0xfe, 0x0f, 0x00, 0x00,
        0x44, 0x33, 0x22, 0x11
    };
    xxemul *emulator = create_dos_protected_fixture();
    xxemul_x86_state state;
    unsigned index;
    xxemul_status run_status;

    CHECK(emulator != NULL);
    CHECK(dos_install_page_tables(emulator, 0xa0000u, 0u));
    CHECK(xxemul_write_memory(emulator, 0x8340u,
        code32, sizeof(code32)) == XXEMUL_STATUS_OK);
    for (index = 0u; index < 7u; ++index)
        CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    run_status = xxemul_run(emulator, 20u, NULL);
    CHECK(run_status == XXEMUL_STATUS_ADDRESS_FAULT);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    if (emulator->dos_cr2 != 0x91000u)
        fprintf(stderr, "paging not-present: %04x:%08llx CR2=%08x\n",
            state.segment[XXEMUL_X86_CS],
            (unsigned long long)state.ip, emulator->dos_cr2);
    CHECK(state.ip == 0x219u);
    CHECK(emulator->dos_cr2 == 0x91000u);
    xxemul_destroy(emulator);
    return 1;
}

static int test_dos_paging_write_protect(void)
{
    static const uint8_t code32[] = {
        0xb8, 0x00, 0x40, 0x00, 0x00,
        0x0f, 0x22, 0xd8,
        0x0f, 0x20, 0xc0,
        0x0d, 0x00, 0x00, 0x01, 0x80, /* enable PG and WP */
        0x0f, 0x22, 0xc0,
        0x66, 0xb8, 0x10, 0x00,
        0x8e, 0xd8,
        0xc7, 0x05, 0x20, 0x00, 0x00, 0x00,
        0x44, 0x33, 0x22, 0x11
    };
    xxemul *emulator = create_dos_protected_fixture();
    uint8_t before[4];
    uint8_t after[4];
    unsigned index;

    CHECK(emulator != NULL);
    CHECK(dos_install_page_tables(emulator, 0xa0000u, 0u));
    CHECK(dos_write_u32(emulator, 0x5240u, 0xa0001u));
    CHECK(xxemul_read_memory(emulator, 0xa0020u,
        before, sizeof(before)) == XXEMUL_STATUS_OK);
    CHECK(xxemul_write_memory(emulator, 0x8340u,
        code32, sizeof(code32)) == XXEMUL_STATUS_OK);
    for (index = 0u; index < 7u; ++index)
        CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_run(emulator, 20u, NULL)
        == XXEMUL_STATUS_ADDRESS_FAULT);
    CHECK(emulator->dos_cr2 == 0x90020u);
    CHECK(xxemul_read_memory(emulator, 0xa0020u,
        after, sizeof(after)) == XXEMUL_STATUS_OK);
    CHECK(memcmp(before, after, sizeof(before)) == 0);
    xxemul_destroy(emulator);
    return 1;
}

static int test_dos_paging_a20(void)
{
    static const uint8_t code32[] = {
        0xb8, 0x00, 0x40, 0x00, 0x00,
        0x0f, 0x22, 0xd8,
        0x0f, 0x20, 0xc0,
        0x0d, 0x00, 0x00, 0x00, 0x80,
        0x0f, 0x22, 0xc0,
        0x66, 0xb8, 0x10, 0x00,
        0x8e, 0xd8,
        0xc7, 0x05, 0x20, 0x00, 0x00, 0x00,
        0xdd, 0xcc, 0xbb, 0xaa,
        0xb0, 0x00, 0xe6, 0x92,       /* disable A20 */
        0xc7, 0x05, 0x20, 0x00, 0x00, 0x00,
        0x44, 0x33, 0x22, 0x11,
        0xf4
    };
    xxemul *emulator = create_dos_protected_fixture();
    uint8_t low[4];
    uint8_t high[4];
    unsigned index;

    CHECK(emulator != NULL);
    CHECK(dos_install_page_tables(emulator, 0x100000u, 0u));
    CHECK(xxemul_write_memory(emulator, 0x8340u,
        code32, sizeof(code32)) == XXEMUL_STATUS_OK);
    for (index = 0u; index < 7u; ++index)
        CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_run(emulator, 20u, NULL) == XXEMUL_STATUS_HALTED);
    CHECK(xxemul_read_memory(emulator, 0x100020u, high, sizeof(high))
        == XXEMUL_STATUS_OK);
    CHECK(high[0] == 0xddu && high[1] == 0xccu
        && high[2] == 0xbbu && high[3] == 0xaau);
    CHECK(xxemul_read_memory(emulator, 0x20u, low, sizeof(low))
        == XXEMUL_STATUS_OK);
    CHECK(low[0] == 0x44u && low[1] == 0x33u
        && low[2] == 0x22u && low[3] == 0x11u);
    xxemul_destroy(emulator);
    return 1;
}

static int test_dos_pic_mask(void)
{
    static const uint8_t image[] = {
        0xba, 0x21, 0x00, /* mov dx, 21h */
        0xec,             /* in al, dx */
        0xb0, 0x5a,       /* mov al, 5ah */
        0xee,             /* out dx, al */
        0xec,             /* in al, dx */
        0xb8, 0x00, 0x4c,
        0xcd, 0x21
    };
    xxemul_status status;
    xxemul_x86_state state;
    xxemul *emulator = xxemul_create_dos(
        XXEMUL_DOS_COM, image, sizeof(image), &status);
    unsigned index;

    CHECK(emulator != NULL);
    for (index = 0u; index < 4u; ++index)
        CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK((state.gpr[XXEMUL_X86_RAX] & 0xffu) == 0x5au);
    CHECK(xxemul_run(emulator, 4u, NULL) == XXEMUL_STATUS_HALTED);
    xxemul_destroy(emulator);
    return 1;
}

static int test_dos_pic_initialization(void)
{
    static const uint8_t image[] = {
        0xba, 0x20, 0x00, /* command port */
        0xb0, 0x11,
        0xee,             /* ICW1 */
        0x42,             /* data port */
        0xb0, 0x08,
        0xee,             /* ICW2 */
        0xec,             /* still reads the mask */
        0xb0, 0x04,
        0xee,             /* ICW3 */
        0xb0, 0x01,
        0xee,             /* ICW4 */
        0xb0, 0x5a,
        0xee,             /* interrupt mask */
        0xec,
        0xb8, 0x00, 0x4c,
        0xcd, 0x21
    };
    xxemul_status status;
    xxemul_x86_state state;
    xxemul *emulator = xxemul_create_dos(
        XXEMUL_DOS_COM, image, sizeof(image), &status);
    unsigned index;

    CHECK(emulator != NULL);
    for (index = 0u; index < 7u; ++index)
        CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK((state.gpr[XXEMUL_X86_RAX] & 0xffu) == 0u);
    for (index = 0u; index < 7u; ++index)
        CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK((state.gpr[XXEMUL_X86_RAX] & 0xffu) == 0x5au);
    CHECK(xxemul_run(emulator, 4u, NULL) == XXEMUL_STATUS_HALTED);
    xxemul_destroy(emulator);
    return 1;
}

static int test_dos_mz_relocation(void)
{
    static const uint8_t image[] = {
        'M', 'Z', 0x30, 0x00, 0x01, 0x00, 0x01, 0x00,
        0x02, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00,
        0xfe, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x1c, 0x00, 0x00, 0x00,
        0x08, 0x00, 0x00, 0x00, /* relocation at image + 8 */
        0xb8, 0x05, 0x00, 0xb4, 0x4c, 0xcd, 0x21, 0x90,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    xxemul_status status;
    xxemul_x86_state state;
    uint8_t relocated[2];
    uint8_t invalid[sizeof(image)];
    uint8_t exit_code = 0u;
    xxemul *emulator = xxemul_create_dos(
        XXEMUL_DOS_MZ, image, sizeof(image), &status);

    CHECK(emulator != NULL);
    CHECK(status == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK(state.segment[XXEMUL_X86_CS] == 0x0824u);
    CHECK(state.segment[XXEMUL_X86_DS] == 0x0814u);
    CHECK(xxemul_read_memory(emulator, 0x8248u, relocated,
        sizeof(relocated)) == XXEMUL_STATUS_OK);
    CHECK(relocated[0] == 0x24u && relocated[1] == 0x08u);
    CHECK(xxemul_run(emulator, 16u, NULL) == XXEMUL_STATUS_HALTED);
    CHECK(xxemul_dos_get_exit_code(emulator, &exit_code)
        == XXEMUL_STATUS_OK);
    CHECK(exit_code == 5u);
    xxemul_destroy(emulator);
    memcpy(invalid, image, sizeof(invalid));
    invalid[28] = 0xffu;
    CHECK(xxemul_create_dos(XXEMUL_DOS_MZ, invalid,
        sizeof(invalid), &status) == NULL);
    CHECK(status == XXEMUL_STATUS_INVALID_IMAGE);
    return 1;
}

static int test_dos_segment_override(void)
{
    static const uint8_t image[] = {
        0xb8, 0x00, 0xb8,             /* mov ax, b800h */
        0x8e, 0xc0,                   /* mov es, ax */
        0x26, 0xc7, 0x06, 0x00, 0x00,
        0x5a, 0x1f,                   /* mov word es:[0], 1f5ah */
        0xb8, 0x00, 0x4c,
        0xcd, 0x21
    };
    xxemul_status status;
    uint8_t video[2];
    xxemul *emulator = xxemul_create_dos(
        XXEMUL_DOS_COM, image, sizeof(image), &status);

    CHECK(emulator != NULL);
    CHECK(xxemul_run(emulator, 16u, NULL) == XXEMUL_STATUS_HALTED);
    CHECK(xxemul_read_memory(emulator, 0xb8000u, video, sizeof(video))
        == XXEMUL_STATUS_OK);
    CHECK(video[0] == 'Z' && video[1] == 0x1fu);
    xxemul_destroy(emulator);
    return 1;
}

static int test_dos_bios_graphics(void)
{
    static const uint8_t image[] = {
        0xb8, 0x13, 0x00, /* mov ax, 13h */
        0xcd, 0x10,       /* int 10h */
        0xb8, 0x04, 0x0c, /* mov ax, 0c04h */
        0xb9, 0x00, 0x00, /* mov cx, 0 */
        0xba, 0x00, 0x00, /* mov dx, 0 */
        0xcd, 0x10,       /* int 10h */
        0xb8, 0x00, 0x4c, /* mov ax, 4c00h */
        0xcd, 0x21
    };
    xxemul_status status;
    xxemul *emulator = xxemul_create_dos(
        XXEMUL_DOS_COM, image, sizeof(image), &status);
    uint32_t *pixels;
    uint8_t vram = 0u;
    uint8_t bottom_pixel = 1u;

    CHECK(emulator != NULL);
    CHECK(xxemul_run(emulator, 16u, NULL) == XXEMUL_STATUS_HALTED);
    CHECK(xxemul_display_get_mode(emulator) == 0x13u);
    CHECK(xxemul_read_memory(emulator, 0xa0000u, &vram, 1u)
        == XXEMUL_STATUS_OK);
    CHECK(vram == 4u);
    CHECK(xxemul_write_memory(emulator,
        0xa0000u + 199u * 320u, &bottom_pixel, 1u)
        == XXEMUL_STATUS_OK);
    pixels = (uint32_t *)malloc(XXEMUL_DISPLAY_WIDTH
        * XXEMUL_DISPLAY_HEIGHT * sizeof(*pixels));
    CHECK(pixels != NULL);
    CHECK(xxemul_display_render(emulator, pixels, XXEMUL_DISPLAY_WIDTH)
        == XXEMUL_STATUS_OK);
    CHECK(pixels[0] == 0xffaa0000u);
    CHECK(pixels[1] == 0xffaa0000u);
    CHECK(pixels[2] == 0xff000000u);
    CHECK(pixels[(XXEMUL_DISPLAY_HEIGHT - 1u)
        * XXEMUL_DISPLAY_WIDTH] == 0xff0000aau);
    free(pixels);
    xxemul_destroy(emulator);
    return 1;
}

static int test_dos_keyboard(void)
{
    static const uint8_t image[] = {
        0xb4, 0x00, 0xcd, 0x16, /* BIOS read key */
        0xb4, 0x4c, 0xcd, 0x21
    };
    xxemul_status status;
    xxemul_x86_state state;
    xxemul *emulator = xxemul_create_dos(
        XXEMUL_DOS_COM, image, sizeof(image), &status);

    CHECK(emulator != NULL);
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_INPUT_REQUIRED);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK(state.ip == 0x102u);
    CHECK(xxemul_dos_push_key(emulator, 'A', 0x1eu)
        == XXEMUL_STATUS_OK);
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK(state.gpr[XXEMUL_X86_RAX] == 0x1e41u);
    xxemul_destroy(emulator);
    return 1;
}

static int test_dos_file_loader(void)
{
    static const uint8_t image[] = {
        0xb8, 0x00, 0x4c, 0xcd, 0x21
    };
    const char *path = "xxemul_test_file.com";
    FILE *file = fopen(path, "wb");
    xxemul_status status;
    xxemul *emulator;

    CHECK(file != NULL);
    CHECK(fwrite(image, 1u, sizeof(image), file) == sizeof(image));
    CHECK(fclose(file) == 0);
    emulator = xxemul_create_dos_file(XXEMUL_DOS_COM, path, &status);
    CHECK(emulator != NULL);
    CHECK(status == XXEMUL_STATUS_OK);
    CHECK(xxemul_run(emulator, 8u, NULL) == XXEMUL_STATUS_HALTED);
    xxemul_destroy(emulator);
    CHECK(remove(path) == 0);
    return 1;
}

int main(void)
{
    int passed = 1;

    passed &= test_x86_64();
    passed &= test_x86_pxor();
    passed &= test_x86_packed_equal();
    passed &= test_x86_unpack_quadwords();
    passed &= test_x86_movups();
    passed &= test_x86_movapd_movupd();
    passed &= test_x86_movq_xmm();
    passed &= test_x86_bit_scan();
    passed &= test_x86_decode_cache_mutation();
    passed &= test_x86_bt_memory();
    passed &= test_x86_cpuid();
    passed &= test_x86_mul();
    passed &= test_x86_imul_accumulator();
    passed &= test_x86_movhps();
    passed &= test_x86_cvtsi2s_scalar();
    passed &= test_x86_scalar_sse_arithmetic();
    passed &= test_x86_scalar_sse_compare();
    passed &= test_x86_scalar_sse_move();
    passed &= test_x86_endbr_and_flags_stack();
    passed &= test_x86_lahf_sahf();
    passed &= test_x86_upx_scalar_controls();
    passed &= test_x86_cmpxchg();
    passed &= test_x86_imul_three_operands();
    passed &= test_x86_cdq();
    passed &= test_x86_idiv();
    passed &= test_x86_divide_64();
    passed &= test_x86_cmovne();
    passed &= test_x86_shifts_and_pushad();
    passed &= test_x86_adc_and_strings();
    passed &= test_x86_xchg_bswap();
    passed &= test_arm_a64();
    passed &= test_arm_a32();
    passed &= test_arm_t32();
    passed &= test_region_bounds();
    passed &= test_dos_com_text();
    passed &= test_dos_far_return();
    passed &= test_dos_far_call();
    passed &= test_dos_enter_leave();
    passed &= test_dos_port_92();
    passed &= test_dos_kbc_a20();
    passed &= test_dos_a20_memory();
    passed &= test_dos_protected_transition();
    passed &= test_dos_protected_bad_selector();
    passed &= test_dos_protected_segment_limit();
    passed &= test_dos_ltr();
    passed &= test_dos_lsl_selector_limit();
    passed &= test_dos_lsl_rpl_visibility();
    passed &= test_dos_task_jump_and_ldt();
    passed &= test_dos_task_jump_bad_ldt();
    passed &= test_dos_task_jump_busy_target();
    passed &= test_dos_protected_interrupt_same_ring();
    passed &= test_dos_protected_interrupt_ring_switch();
    passed &= test_dos_protected_interrupt_gate_privilege();
    passed &= test_dos_protected_iret_bad_return();
    passed &= test_dos_page_fault_string_restart();
    passed &= test_dos_page_fault_fetch_restart();
    passed &= test_dos_page_fault_cross_page_fetch_restart();
    passed &= test_dos_task_jump_page_fault_fetch();
    passed &= test_dos_page_fault_mov_restart();
    passed &= test_dos_page_fault_movzx_restart();
    passed &= test_dos_page_fault_inc_byte_restart();
    passed &= test_dos_page_fault_fdiv_restart();
    passed &= test_dos_page_fault_indirect_jmp_restart();
    passed &= test_dos_page_fault_push_restart();
    passed &= test_dos_page_fault_pop_store_rollback();
    passed &= test_dos_paging_boundary();
    passed &= test_dos_paging_cross_page();
    passed &= test_dos_paging_not_present();
    passed &= test_dos_paging_write_protect();
    passed &= test_dos_paging_a20();
    passed &= test_dos_pic_mask();
    passed &= test_dos_pic_initialization();
    passed &= test_dos_mz_relocation();
    passed &= test_dos_segment_override();
    passed &= test_dos_bios_graphics();
    passed &= test_dos_keyboard();
    passed &= test_dos_file_loader();
    if (!passed) {
        return 1;
    }
    puts("xxemul tests passed");
    return 0;
}
