#include "xxemul/xxemul.h"
#include "../src/xxemul_internal.h"
#include "../src/platforms/xxemul_dos_files.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if defined(_WIN32)
#include <direct.h>
#else
#include <sys/stat.h>
#include <unistd.h>
#endif

#define CHECK(expression) do { \
    if (!(expression)) { \
        fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #expression); \
        return 0; \
    } \
} while (0)

static int test_memory_blocks(void)
{
    static const uint8_t image[] = {
        0xcd, 0x21, 0xcd, 0x21, 0xcd, 0x21, 0xcd, 0x21,
        0xb8, 0x00, 0x4c, 0xcd, 0x21
    };
    xxemul_status status;
    xxemul_x86_state state;
    xxemul *emulator = xxemul_create_dos(
        XXEMUL_DOS_COM, image, sizeof(image), &status);
    uint16_t allocated;
    uint8_t psp_end[2];

    CHECK(emulator != NULL && status == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    state.segment[XXEMUL_X86_ES] = state.segment[XXEMUL_X86_CS];
    state.gpr[XXEMUL_X86_RAX] = 0x4a00u;
    state.gpr[XXEMUL_X86_RBX] = 0x100u;
    CHECK(xxemul_set_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    status = xxemul_step(emulator, NULL);
    if (status != XXEMUL_STATUS_OK) {
        fprintf(stderr, "first DOS step: %s\n", xxemul_status_string(status));
    }
    CHECK(status == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK((state.flags & 1u) == 0u);
    CHECK(xxemul_read_memory(emulator, 0x8142u, psp_end, 2u)
        == XXEMUL_STATUS_OK);
    CHECK(psp_end[0] == 0x14u && psp_end[1] == 0x09u);

    state.gpr[XXEMUL_X86_RAX] = 0x4800u;
    state.gpr[XXEMUL_X86_RBX] = 0x20u;
    CHECK(xxemul_set_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK((state.flags & 1u) == 0u);
    allocated = (uint16_t)state.gpr[XXEMUL_X86_RAX];
    CHECK(allocated == 0x915u);

    state.segment[XXEMUL_X86_ES] = allocated;
    state.gpr[XXEMUL_X86_RAX] = 0x4900u;
    CHECK(xxemul_set_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK((state.flags & 1u) == 0u);

    state.gpr[XXEMUL_X86_RAX] = 0x4800u;
    state.gpr[XXEMUL_X86_RBX] = 0x20u;
    CHECK(xxemul_set_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK((state.flags & 1u) == 0u);
    CHECK((uint16_t)state.gpr[XXEMUL_X86_RAX] == allocated);
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_HALTED);
    xxemul_destroy(emulator);
    return 1;
}

static int test_resize_failure(void)
{
    static const uint8_t image[] = {0xcd, 0x21, 0xcd, 0x21};
    xxemul_status status;
    xxemul_x86_state state;
    uint8_t mcb_size[2];
    xxemul *emulator = xxemul_create_dos(
        XXEMUL_DOS_COM, image, sizeof(image), &status);

    CHECK(emulator != NULL && status == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    state.segment[XXEMUL_X86_ES] = state.segment[XXEMUL_X86_CS];
    state.gpr[XXEMUL_X86_RAX] = 0x4a00u;
    state.gpr[XXEMUL_X86_RBX] = 0x100u;
    CHECK(xxemul_set_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    state.gpr[XXEMUL_X86_RAX] = 0x4a00u;
    state.gpr[XXEMUL_X86_RBX] = 0xffffu;
    CHECK(xxemul_set_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK((state.flags & 1u) != 0u);
    CHECK((uint16_t)state.gpr[XXEMUL_X86_RAX] == 8u);
    CHECK((uint16_t)state.gpr[XXEMUL_X86_RBX] == 0x97ecu);
    CHECK(xxemul_read_memory(emulator, 0x8133u, mcb_size, 2u)
        == XXEMUL_STATUS_OK);
    CHECK(mcb_size[0] == 0x00u && mcb_size[1] == 0x01u);
    xxemul_destroy(emulator);
    return 1;
}

static int test_dpmi_probe(void)
{
    static const uint8_t image[] = {
        0xcd, 0x2f, 0xcd, 0x31, 0xcd, 0x15
    };
    xxemul_status status;
    xxemul_x86_state state;
    xxemul *emulator = xxemul_create_dos(
        XXEMUL_DOS_COM, image, sizeof(image), &status);

    CHECK(emulator != NULL && status == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    state.gpr[XXEMUL_X86_RAX] = 0x1687u;
    CHECK(xxemul_set_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK((uint16_t)state.gpr[XXEMUL_X86_RAX] == 0u);
    CHECK((uint16_t)state.gpr[XXEMUL_X86_RBX] == 1u);
    CHECK(state.segment[XXEMUL_X86_ES] == 0xf000u);
    CHECK((uint16_t)state.gpr[XXEMUL_X86_RDI] == 0x0200u);
    state.gpr[XXEMUL_X86_RAX] = 0x0400u;
    CHECK(xxemul_set_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK((uint16_t)state.gpr[XXEMUL_X86_RAX] == 0x8001u);
    CHECK((state.flags & 1u) != 0u);
    state.gpr[XXEMUL_X86_RAX] = 0xe801u;
    CHECK(xxemul_set_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK((uint16_t)state.gpr[XXEMUL_X86_RAX] == 0x8600u);
    CHECK((state.flags & 1u) != 0u);
    xxemul_destroy(emulator);
    return 1;
}

static int test_dos_interrupt_vector(void)
{
    static const uint8_t image[] = {
        0xcd, 0x21, 0xcd, 0x21,
        0xb8, 0x00, 0x4c, 0xcd, 0x21
    };
    xxemul_status status;
    xxemul_x86_state state;
    uint8_t entry[4];
    xxemul *emulator = xxemul_create_dos(
        XXEMUL_DOS_COM, image, sizeof(image), &status);

    CHECK(emulator != NULL && status == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    state.gpr[XXEMUL_X86_RAX] = 0x252fu;
    state.gpr[XXEMUL_X86_RDX] = 0x1234u;
    CHECK(xxemul_set_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_read_memory(emulator, 0x2fu * 4u,
        entry, sizeof(entry)) == XXEMUL_STATUS_OK);
    CHECK(entry[0] == 0x34u && entry[1] == 0x12u);
    CHECK(entry[2] == 0x14u && entry[3] == 0x08u);

    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    state.gpr[XXEMUL_X86_RAX] = 0x352fu;
    CHECK(xxemul_set_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK(state.segment[XXEMUL_X86_ES] == 0x0814u);
    CHECK((uint16_t)state.gpr[XXEMUL_X86_RBX] == 0x1234u);
    CHECK((state.flags & 1u) == 0u);
    xxemul_destroy(emulator);
    return 1;
}

static int test_dos_current_psp(void)
{
    static const uint8_t image[] = {
        0xcd, 0x21, 0xcd, 0x21, 0xcd, 0x21
    };
    xxemul_status status;
    xxemul_x86_state state;
    xxemul *emulator = xxemul_create_dos(
        XXEMUL_DOS_COM, image, sizeof(image), &status);

    CHECK(emulator != NULL && status == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    state.gpr[XXEMUL_X86_RAX] = 0x5000u;
    state.gpr[XXEMUL_X86_RBX] = 0x1234u;
    CHECK(xxemul_set_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK((state.flags & 1u) == 0u);

    state.gpr[XXEMUL_X86_RAX] = 0x5100u;
    state.gpr[XXEMUL_X86_RBX] = 0u;
    CHECK(xxemul_set_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK((uint16_t)state.gpr[XXEMUL_X86_RBX] == 0x1234u);

    state.gpr[XXEMUL_X86_RAX] = 0x6200u;
    state.gpr[XXEMUL_X86_RBX] = 0u;
    CHECK(xxemul_set_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK((uint16_t)state.gpr[XXEMUL_X86_RBX] == 0x1234u);
    xxemul_destroy(emulator);
    return 1;
}

static int test_dos_list_of_lists(void)
{
    static const uint8_t image[] = {0xcd, 0x21, 0xcd, 0x21};
    xxemul_status status;
    xxemul_x86_state before;
    xxemul_x86_state after;
    xxemul *emulator = xxemul_create_dos(
        XXEMUL_DOS_COM, image, sizeof(image), &status);
    uint16_t list_segment;
    uint16_t list_offset;
    uint8_t list[0x22u];
    uint8_t mcb_pointer[2];
    uint8_t mcb_type;
    uint8_t sft_header[6];
    uint16_t mcb_segment;
    uint16_t sft_segment;
    uint16_t sft_offset;
    size_t index;

    CHECK(emulator != NULL && status == XXEMUL_STATUS_OK);
    CHECK(xxemul_start_process(emulator, XXEMUL_IMAGE_COM,
        "LIST.COM", ".", 0u, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_x86_state(emulator, &before) == XXEMUL_STATUS_OK);
    before.gpr[XXEMUL_X86_RAX] = 0x52a7u;
    before.gpr[XXEMUL_X86_RBX] = 0x1357u;
    before.gpr[XXEMUL_X86_RCX] = 0x2468u;
    before.gpr[XXEMUL_X86_RDX] = 0x3579u;
    before.gpr[XXEMUL_X86_RSI] = 0x468au;
    before.gpr[XXEMUL_X86_RDI] = 0x579bu;
    before.gpr[XXEMUL_X86_RBP] = 0x68acu;
    before.segment[XXEMUL_X86_ES] = 0x1111u;
    before.flags |= 1u;
    CHECK(xxemul_set_x86_state(emulator, &before) == XXEMUL_STATUS_OK);
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_x86_state(emulator, &after) == XXEMUL_STATUS_OK);
    CHECK(after.ip == 0x102u);
    CHECK((after.flags & 1u) == 0u);
    CHECK((after.flags & ~UINT64_C(1)) == (before.flags & ~UINT64_C(1)));
    for (index = 0u; index < XXEMUL_X86_GPR_COUNT; ++index) {
        if (index != XXEMUL_X86_RBX)
            CHECK(after.gpr[index] == before.gpr[index]);
    }
    for (index = 0u; index < XXEMUL_X86_SEGMENT_COUNT; ++index) {
        if (index != XXEMUL_X86_ES)
            CHECK(after.segment[index] == before.segment[index]);
    }
    list_segment = after.segment[XXEMUL_X86_ES];
    list_offset = (uint16_t)after.gpr[XXEMUL_X86_RBX];
    CHECK(xxemul_read_memory(emulator,
        xxemul_dos_linear(list_segment, list_offset),
        list, sizeof(list)) == XXEMUL_STATUS_OK);
    CHECK(xxemul_read_memory(emulator,
        xxemul_dos_linear(list_segment,
            (uint16_t)(list_offset - 2u)),
        mcb_pointer, sizeof(mcb_pointer)) == XXEMUL_STATUS_OK);
    mcb_segment = (uint16_t)mcb_pointer[0]
        | (uint16_t)((uint16_t)mcb_pointer[1] << 8u);
    CHECK(mcb_segment == (uint16_t)(before.segment[XXEMUL_X86_CS] - 1u));
    CHECK(xxemul_read_memory(emulator,
        xxemul_dos_linear(mcb_segment, 0u),
        &mcb_type, sizeof(mcb_type)) == XXEMUL_STATUS_OK);
    CHECK(mcb_type == 'M' || mcb_type == 'Z');
    sft_offset = (uint16_t)list[4u]
        | (uint16_t)((uint16_t)list[5u] << 8u);
    sft_segment = (uint16_t)list[6u]
        | (uint16_t)((uint16_t)list[7u] << 8u);
    CHECK(xxemul_read_memory(emulator,
        xxemul_dos_linear(sft_segment, sft_offset),
        sft_header, sizeof(sft_header)) == XXEMUL_STATUS_OK);
    CHECK(((uint16_t)sft_header[4u]
        | (uint16_t)((uint16_t)sft_header[5u] << 8u)) == 16u);
    CHECK(list[0x20u] == 1u);
    CHECK(list[0x21u] == 26u);

    after.gpr[XXEMUL_X86_RAX] = 0x5200u;
    after.gpr[XXEMUL_X86_RBX] = 0xabcdu;
    after.segment[XXEMUL_X86_ES] = 0x2222u;
    after.flags |= 1u;
    CHECK(xxemul_set_x86_state(emulator, &after) == XXEMUL_STATUS_OK);
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_x86_state(emulator, &after) == XXEMUL_STATUS_OK);
    CHECK(after.ip == 0x104u);
    CHECK((after.flags & 1u) == 0u);
    CHECK(after.segment[XXEMUL_X86_ES] == list_segment);
    CHECK((uint16_t)after.gpr[XXEMUL_X86_RBX] == list_offset);
    xxemul_dos_files_stop(emulator);
    xxemul_destroy(emulator);
    return 1;
}

static int test_dos_unsupported_lfn(void)
{
    static const uint8_t image[] = {0xcd, 0x21};
    xxemul_status status;
    xxemul_x86_state state;
    xxemul *emulator = xxemul_create_dos(
        XXEMUL_DOS_COM, image, sizeof(image), &status);

    CHECK(emulator != NULL && status == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    state.gpr[XXEMUL_X86_RAX] = 0x71a0u;
    CHECK(xxemul_set_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK((uint16_t)state.gpr[XXEMUL_X86_RAX] == 0x7100u);
    CHECK((state.flags & 1u) != 0u);
    xxemul_destroy(emulator);
    return 1;
}

static int test_dos_clock(void)
{
    static const uint8_t image[] = {0xcd, 0x21, 0xcd, 0x21};
    xxemul_status status;
    xxemul_x86_state state;
    xxemul *emulator = xxemul_create_dos(
        XXEMUL_DOS_COM, image, sizeof(image), &status);
    uint16_t date;
    uint16_t clock;

    CHECK(emulator != NULL && status == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    state.gpr[XXEMUL_X86_RAX] = 0x2a00u;
    CHECK(xxemul_set_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    date = (uint16_t)state.gpr[XXEMUL_X86_RDX];
    CHECK((state.flags & 1u) == 0u);
    CHECK((uint16_t)state.gpr[XXEMUL_X86_RCX] >= 1980u);
    CHECK((uint8_t)state.gpr[XXEMUL_X86_RAX] <= 6u);
    CHECK((date >> 8u) >= 1u && (date >> 8u) <= 12u);
    CHECK((date & 0xffu) >= 1u && (date & 0xffu) <= 31u);

    state.gpr[XXEMUL_X86_RAX] = 0x2c00u;
    CHECK(xxemul_set_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    clock = (uint16_t)state.gpr[XXEMUL_X86_RCX];
    CHECK((state.flags & 1u) == 0u);
    CHECK((clock >> 8u) < 24u && (clock & 0xffu) < 60u);
    clock = (uint16_t)state.gpr[XXEMUL_X86_RDX];
    CHECK((clock >> 8u) < 60u && (clock & 0xffu) < 100u);
    xxemul_destroy(emulator);
    return 1;
}

static int test_dos_dta(void)
{
    static const uint8_t image[] = {
        0xcd, 0x21, 0xcd, 0x21, 0xcd, 0x21
    };
    xxemul_status status;
    xxemul_x86_state state;
    xxemul *emulator = xxemul_create_dos(
        XXEMUL_DOS_COM, image, sizeof(image), &status);

    CHECK(emulator != NULL && status == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    state.gpr[XXEMUL_X86_RAX] = 0x2f00u;
    CHECK(xxemul_set_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK(state.segment[XXEMUL_X86_ES] == state.segment[XXEMUL_X86_CS]);
    CHECK((uint16_t)state.gpr[XXEMUL_X86_RBX] == 0x80u);

    state.gpr[XXEMUL_X86_RAX] = 0x1a00u;
    state.gpr[XXEMUL_X86_RDX] = 0x0234u;
    CHECK(xxemul_set_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK((state.flags & 1u) == 0u);

    state.gpr[XXEMUL_X86_RAX] = 0x2f00u;
    CHECK(xxemul_set_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK(state.segment[XXEMUL_X86_ES] == state.segment[XXEMUL_X86_DS]);
    CHECK((uint16_t)state.gpr[XXEMUL_X86_RBX] == 0x0234u);
    xxemul_destroy(emulator);
    return 1;
}

static int test_dos_current_directory(void)
{
    static const uint8_t image[] = {0xcd, 0x21};
    xxemul_status status;
    xxemul_x86_state state;
    xxemul *emulator = xxemul_create_dos(
        XXEMUL_DOS_COM, image, sizeof(image), &status);
    uint8_t current = 0xffu;

    CHECK(emulator != NULL && status == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    state.gpr[XXEMUL_X86_RAX] = 0x4700u;
    state.gpr[XXEMUL_X86_RDX] = 3u;
    state.gpr[XXEMUL_X86_RSI] = 0x0200u;
    CHECK(xxemul_set_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK(xxemul_write_memory(emulator, 0x8140u + 0x200u,
        &current, 1u) == XXEMUL_STATUS_OK);
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK((state.flags & 1u) == 0u);
    CHECK(xxemul_read_memory(emulator, 0x8140u + 0x200u,
        &current, 1u) == XXEMUL_STATUS_OK);
    CHECK(current == 0u);
    xxemul_destroy(emulator);
    return 1;
}

static int test_dos_operand_size_stack(void)
{
    static const uint8_t image[] = {
        0x66, 0xb8, 0x78, 0x56, 0x34, 0x12, /* mov eax, 12345678h */
        0x66, 0x50,                         /* push eax */
        0x66, 0x5b,                         /* pop ebx */
        0x66, 0x68, 0xef, 0xcd, 0xab, 0x89, /* push 89ABCDEFh */
        0x66, 0x59,                         /* pop ecx */
        0x66, 0x6a, 0xff,                   /* push dword -1 */
        0x66, 0x5a,                         /* pop edx */
        0xb8, 0x00, 0x4c, 0xcd, 0x21        /* exit 0 */
    };
    xxemul_status status;
    xxemul_x86_state state;
    xxemul *emulator = xxemul_create_dos(
        XXEMUL_DOS_COM, image, sizeof(image), &status);
    uint16_t initial_sp;

    CHECK(emulator != NULL && status == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    initial_sp = (uint16_t)state.gpr[XXEMUL_X86_RSP];
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK((uint16_t)state.gpr[XXEMUL_X86_RSP]
        == (uint16_t)(initial_sp - 4u));
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK((uint16_t)state.gpr[XXEMUL_X86_RSP] == initial_sp);
    CHECK((uint32_t)state.gpr[XXEMUL_X86_RBX] == UINT32_C(0x12345678));
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK((uint16_t)state.gpr[XXEMUL_X86_RSP]
        == (uint16_t)(initial_sp - 4u));
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK((uint16_t)state.gpr[XXEMUL_X86_RSP] == initial_sp);
    CHECK((uint32_t)state.gpr[XXEMUL_X86_RCX] == UINT32_C(0x89abcdef));
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK((uint16_t)state.gpr[XXEMUL_X86_RSP]
        == (uint16_t)(initial_sp - 4u));
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK((uint16_t)state.gpr[XXEMUL_X86_RSP] == initial_sp);
    CHECK((uint32_t)state.gpr[XXEMUL_X86_RDX] == UINT32_MAX);
    CHECK(xxemul_run(emulator, 4u, NULL) == XXEMUL_STATUS_HALTED);
    xxemul_destroy(emulator);
    return 1;
}

static int test_dos_guest_interrupt_return(void)
{
    static const uint8_t image[] = {
        0xba, 0x12, 0x01,       /* mov dx, handler at PSP:0112h */
        0xb8, 0x2f, 0x25,       /* mov ax, 252Fh */
        0xcd, 0x21,             /* install INT 2Fh vector */
        0xb8, 0x87, 0x16,       /* mov ax, 1687h */
        0xcd, 0x2f,             /* enter guest handler */
        0xb8, 0x00, 0x4c,       /* terminate after IRET */
        0xcd, 0x21,
        0xb8, 0x00, 0x00, 0xcf  /* handler: mov ax, 0; iret */
    };
    xxemul_status status;
    xxemul_x86_state state;
    uint16_t initial_sp;
    xxemul *emulator = xxemul_create_dos(
        XXEMUL_DOS_COM, image, sizeof(image), &status);

    CHECK(emulator != NULL && status == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    initial_sp = (uint16_t)state.gpr[XXEMUL_X86_RSP];
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK(state.segment[XXEMUL_X86_CS] == 0x0814u);
    CHECK((uint16_t)state.ip == 0x0112u);
    CHECK((uint16_t)state.gpr[XXEMUL_X86_RSP]
        == (uint16_t)(initial_sp - 6u));
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK((uint16_t)state.ip == 0x010du);
    CHECK((uint16_t)state.gpr[XXEMUL_X86_RSP] == initial_sp);
    CHECK((uint16_t)state.gpr[XXEMUL_X86_RAX] == 0u);
    CHECK(xxemul_run(emulator, 4u, NULL) == XXEMUL_STATUS_HALTED);
    xxemul_destroy(emulator);
    return 1;
}

static int test_dos_int21_host_thunk(void)
{
    static const uint8_t image[] = {
        0xcd, 0x21, 0xcf, 0xf4 /* direct INT 21h, IRET entry, HLT */
    };
    static const uint8_t frame[] = {
        0x00, 0x01, 0x00, 0xf0, 0x02, 0x30, /* host vector and flags */
        0x03, 0x01, 0x14, 0x08, 0x02, 0x32  /* continuation and flags */
    };
    xxemul_status status;
    xxemul_x86_state state;
    xxemul *emulator = xxemul_create_dos(
        XXEMUL_DOS_COM, image, sizeof(image), &status);
    uint8_t entry[4];
    uint8_t saved_flags[2];
    uint8_t thunk;
    uint64_t initial_sp;

    CHECK(emulator != NULL && status == XXEMUL_STATUS_OK);
    CHECK(xxemul_read_memory(emulator, 0x84u,
        entry, sizeof(entry)) == XXEMUL_STATUS_OK);
    CHECK(entry[0] == 0x00u && entry[1] == 0x01u
        && entry[2] == 0x00u && entry[3] == 0xf0u);
    CHECK(xxemul_read_memory(emulator, 0xf0100u, &thunk, 1u)
        == XXEMUL_STATUS_OK && thunk == 0xcfu);

    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    initial_sp = state.gpr[XXEMUL_X86_RSP];
    state.gpr[XXEMUL_X86_RAX] = 0x3000u;
    CHECK(xxemul_set_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK(state.ip == 0x102u && state.gpr[XXEMUL_X86_RSP] == initial_sp);
    CHECK((uint16_t)state.gpr[XXEMUL_X86_RAX] == 0x0005u);

    state.gpr[XXEMUL_X86_RSP] = 0xffe0u;
    state.gpr[XXEMUL_X86_RAX] = 0x33ffu;
    state.flags = 0x3202u;
    CHECK(xxemul_set_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK(xxemul_write_memory(emulator,
        xxemul_dos_linear(state.segment[XXEMUL_X86_SS], 0xffe0u),
        frame, sizeof(frame)) == XXEMUL_STATUS_OK);
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK(state.segment[XXEMUL_X86_CS] == 0xf000u && state.ip == 0x100u);
    CHECK((uint16_t)state.gpr[XXEMUL_X86_RSP] == 0xffe6u);
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK(state.segment[XXEMUL_X86_CS] == 0x0814u && state.ip == 0x103u);
    CHECK((uint16_t)state.gpr[XXEMUL_X86_RSP] == 0xffecu);
    CHECK((uint16_t)state.gpr[XXEMUL_X86_RAX] == 1u);
    CHECK((state.flags & 1u) != 0u);
    CHECK(xxemul_read_memory(emulator,
        xxemul_dos_linear(state.segment[XXEMUL_X86_SS], 0xffeau),
        saved_flags, sizeof(saved_flags)) == XXEMUL_STATUS_OK);
    CHECK(saved_flags[0] == 0x03u && saved_flags[1] == 0x32u);

    state.ip = 0x102u;
    state.gpr[XXEMUL_X86_RSP] = 0xffe0u;
    state.gpr[XXEMUL_X86_RAX] = 0x3000u;
    CHECK(xxemul_set_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK(state.segment[XXEMUL_X86_CS] == 0x0814u && state.ip == 0x103u);
    CHECK((uint16_t)state.gpr[XXEMUL_X86_RAX] == 0x0005u);
    CHECK((state.flags & 1u) == 0u);
    CHECK(xxemul_read_memory(emulator,
        xxemul_dos_linear(state.segment[XXEMUL_X86_SS], 0xffeau),
        saved_flags, sizeof(saved_flags)) == XXEMUL_STATUS_OK);
    CHECK(saved_flags[0] == 0x02u && saved_flags[1] == 0x32u);
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_HALTED);
    xxemul_destroy(emulator);
    return 1;
}

static int test_dos_int10_host_thunk(void)
{
    static const uint8_t image[] = {
        0xb8, 0x00, 0x0f, /* mov ax, 0F00h */
        0xcd, 0x10,       /* int 10h */
        0xf4              /* hlt */
    };
    static const uint8_t int10_vector[] = {0x10, 0x01, 0x00, 0xf0};
    static const uint8_t int21_vector[] = {0x00, 0x01, 0x00, 0xf0};
    xxemul_status status;
    xxemul_x86_state initial;
    xxemul_x86_state state;
    xxemul *emulator = xxemul_create_dos(
        XXEMUL_DOS_COM, image, sizeof(image), &status);
    uint8_t entry[4];
    uint8_t frame[6];
    uint8_t returned_frame[6];
    uint8_t thunk;
    uint16_t initial_sp;
    size_t index;

    CHECK(emulator != NULL && status == XXEMUL_STATUS_OK);
    CHECK(xxemul_read_memory(emulator, 0x10u * 4u,
        entry, sizeof(entry)) == XXEMUL_STATUS_OK);
    CHECK(memcmp(entry, int10_vector, sizeof(entry)) == 0);
    CHECK(xxemul_read_memory(emulator, 0xf0110u, &thunk, 1u)
        == XXEMUL_STATUS_OK && thunk == 0xcfu);
    CHECK(xxemul_read_memory(emulator, 0x21u * 4u,
        entry, sizeof(entry)) == XXEMUL_STATUS_OK);
    CHECK(memcmp(entry, int21_vector, sizeof(entry)) == 0);
    CHECK(xxemul_read_memory(emulator, 0xf0100u, &thunk, 1u)
        == XXEMUL_STATUS_OK && thunk == 0xcfu);

    CHECK(xxemul_get_x86_state(emulator, &initial) == XXEMUL_STATUS_OK);
    initial_sp = (uint16_t)initial.gpr[XXEMUL_X86_RSP];
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK(state.segment[XXEMUL_X86_CS] == 0xf000u);
    CHECK((uint16_t)state.ip == 0x0110u);
    CHECK((uint16_t)state.gpr[XXEMUL_X86_RSP]
        == (uint16_t)(initial_sp - 6u));
    for (index = 0u; index < XXEMUL_X86_SEGMENT_COUNT; ++index) {
        if (index != XXEMUL_X86_CS) {
            CHECK(state.segment[index] == initial.segment[index]);
        }
    }
    CHECK(xxemul_read_memory(emulator,
        xxemul_dos_linear(state.segment[XXEMUL_X86_SS],
            (uint16_t)state.gpr[XXEMUL_X86_RSP]),
        frame, sizeof(frame)) == XXEMUL_STATUS_OK);
    CHECK(frame[0] == 0x05u && frame[1] == 0x01u);
    CHECK(frame[2] == (uint8_t)initial.segment[XXEMUL_X86_CS]);
    CHECK(frame[3] == (uint8_t)(initial.segment[XXEMUL_X86_CS] >> 8u));
    CHECK(frame[4] == (uint8_t)initial.flags);
    CHECK(frame[5] == (uint8_t)(initial.flags >> 8u));

    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK((uint16_t)state.gpr[XXEMUL_X86_RAX] == 0x5003u);
    CHECK((uint16_t)state.ip == 0x0105u);
    CHECK((uint16_t)state.gpr[XXEMUL_X86_RSP] == initial_sp);
    CHECK((uint16_t)state.flags == (uint16_t)initial.flags);
    for (index = 0u; index < XXEMUL_X86_SEGMENT_COUNT; ++index) {
        CHECK(state.segment[index] == initial.segment[index]);
    }
    CHECK(xxemul_read_memory(emulator,
        xxemul_dos_linear(state.segment[XXEMUL_X86_SS],
            (uint16_t)(initial_sp - 6u)),
        returned_frame, sizeof(returned_frame)) == XXEMUL_STATUS_OK);
    CHECK(memcmp(returned_frame, frame, sizeof(frame)) == 0);
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_HALTED);
    CHECK(xxemul_read_memory(emulator, 0x10u * 4u,
        entry, sizeof(entry)) == XXEMUL_STATUS_OK);
    CHECK(memcmp(entry, int10_vector, sizeof(entry)) == 0);
    CHECK(xxemul_read_memory(emulator, 0x21u * 4u,
        entry, sizeof(entry)) == XXEMUL_STATUS_OK);
    CHECK(memcmp(entry, int21_vector, sizeof(entry)) == 0);
    xxemul_destroy(emulator);
    return 1;
}

static int test_dos_int21_guest_override(void)
{
    static const uint8_t image[] = {
        0xba, 0x10, 0x01,       /* mov dx, handler */
        0xb8, 0x21, 0x25,       /* mov ax, 2521h */
        0xcd, 0x21,             /* install INT 21h handler */
        0xb8, 0x00, 0x30,       /* mov ax, 3000h */
        0xcd, 0x21,             /* enter guest handler */
        0xf4, 0x90, 0x90,       /* continuation and padding */
        0xb8, 0x34, 0x12, 0xcf  /* handler: mov ax, 1234h; iret */
    };
    xxemul_status status;
    xxemul_x86_state state;
    xxemul *emulator = xxemul_create_dos(
        XXEMUL_DOS_COM, image, sizeof(image), &status);
    uint8_t entry[4];
    uint64_t initial_sp;

    CHECK(emulator != NULL && status == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    initial_sp = state.gpr[XXEMUL_X86_RSP];
    CHECK(xxemul_run(emulator, 4u, NULL) == XXEMUL_STATUS_LIMIT_REACHED);
    CHECK(xxemul_read_memory(emulator, 0x84u,
        entry, sizeof(entry)) == XXEMUL_STATUS_OK);
    CHECK(entry[0] == 0x10u && entry[1] == 0x01u
        && entry[2] == 0x14u && entry[3] == 0x08u);
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK(state.segment[XXEMUL_X86_CS] == 0x0814u && state.ip == 0x110u);
    CHECK(state.gpr[XXEMUL_X86_RSP] == initial_sp - 6u);
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK(state.ip == 0x10du && state.gpr[XXEMUL_X86_RSP] == initial_sp);
    CHECK((uint16_t)state.gpr[XXEMUL_X86_RAX] == 0x1234u);

    memset(entry, 0, sizeof(entry));
    CHECK(xxemul_write_memory(emulator, 0x84u,
        entry, sizeof(entry)) == XXEMUL_STATUS_OK);
    state.ip = 0x10bu;
    state.gpr[XXEMUL_X86_RAX] = 0x3000u;
    CHECK(xxemul_set_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK(state.segment[XXEMUL_X86_CS] == 0u && state.ip == 0u);
    CHECK(state.gpr[XXEMUL_X86_RSP] == initial_sp - 6u);
    xxemul_destroy(emulator);
    return 1;
}

static int test_mz_overlay(void)
{
    static const uint8_t image[] = {
        'M', 'Z', 0x30, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x02, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00,
        0xfe, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x1c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xb8, 0x00, 0x4c, 0xcd, 0x21, 0x90, 0x90, 0x90,
        0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
        'O', 'V', 'E', 'R', 'L', 'A', 'Y'
    };
    xxemul_status status;
    uint8_t memory[17];
    xxemul *emulator = xxemul_create_dos(
        XXEMUL_DOS_MZ, image, sizeof(image), &status);

    CHECK(emulator != NULL && status == XXEMUL_STATUS_OK);
    CHECK(xxemul_read_memory(emulator, 0x8240u, memory, sizeof(memory))
        == XXEMUL_STATUS_OK);
    CHECK(memcmp(memory, image + 32u, 16u) == 0);
    CHECK(memory[16] == 0u);
    CHECK(xxemul_run(emulator, 8u, NULL) == XXEMUL_STATUS_HALTED);
    xxemul_destroy(emulator);
    return 1;
}

static int dos_call(
    xxemul *emulator, uint16_t ax, uint16_t bx,
    uint16_t cx, uint16_t dx, xxemul_x86_state *state)
{
    CHECK(xxemul_get_x86_state(emulator, state) == XXEMUL_STATUS_OK);
    state->gpr[XXEMUL_X86_RAX] = ax;
    state->gpr[XXEMUL_X86_RBX] = bx;
    state->gpr[XXEMUL_X86_RCX] = cx;
    state->gpr[XXEMUL_X86_RDX] = dx;
    CHECK(xxemul_set_x86_state(emulator, state) == XXEMUL_STATUS_OK);
    CHECK(xxemul_step(emulator, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_x86_state(emulator, state) == XXEMUL_STATUS_OK);
    return 1;
}

static uint16_t dos_test_word(const uint8_t *data)
{
    return (uint16_t)data[0]
        | (uint16_t)((uint16_t)data[1] << 8u);
}

static int test_dos_list_of_lists_file(void)
{
    static const uint8_t image[] = {
        0xcd, 0x21, 0xcd, 0x21, 0xcd, 0x21, 0xcd, 0x21
    };
    static const char name[] = "XXSFT57.BIN";
    static const char payload[] = "SFT metadata";
    static const char dos_name[] = "XXSFT57 BIN";
    xxemul_status status;
    xxemul_x86_state state;
    xxemul *emulator;
    FILE *file;
    uint8_t psp_jft[6];
    uint8_t jft_entry;
    uint8_t sft_pointer[4];
    uint8_t sft_header[6];
    uint8_t sft_entry[0x3bu];
    uint16_t handle;
    uint16_t table_segment;
    uint16_t table_offset;
    uint16_t sft_index;
    uint16_t dos_time;
    uint16_t dos_date;
    size_t table;
    uint64_t entry_address;

    file = fopen(name, "rb");
    CHECK(file == NULL);
    file = fopen(name, "wb");
    CHECK(file != NULL);
    CHECK(fwrite(payload, 1u, sizeof(payload) - 1u, file)
        == sizeof(payload) - 1u);
    CHECK(fclose(file) == 0);

    emulator = xxemul_create_dos(
        XXEMUL_DOS_COM, image, sizeof(image), &status);
    CHECK(emulator != NULL && status == XXEMUL_STATUS_OK);
    CHECK(xxemul_start_process(emulator, XXEMUL_IMAGE_COM,
        "SFT.COM", ".", 0u, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK(xxemul_write_memory(emulator,
        xxemul_dos_linear(state.segment[XXEMUL_X86_DS], 0x200u),
        name, sizeof(name)) == XXEMUL_STATUS_OK);

    CHECK(dos_call(emulator, 0x3d00u, 0u, 0u, 0x200u, &state));
    CHECK((state.flags & 1u) == 0u);
    handle = (uint16_t)state.gpr[XXEMUL_X86_RAX];
    CHECK(handle >= 5u && handle < 64u);
    CHECK(xxemul_read_memory(emulator,
        xxemul_dos_linear(state.segment[XXEMUL_X86_CS], 0x32u),
        psp_jft, sizeof(psp_jft)) == XXEMUL_STATUS_OK);
    CHECK(dos_test_word(psp_jft) == 64u);
    CHECK(xxemul_read_memory(emulator,
        xxemul_dos_linear(dos_test_word(psp_jft + 4u),
            (uint16_t)(dos_test_word(psp_jft + 2u) + handle)),
        &jft_entry, sizeof(jft_entry)) == XXEMUL_STATUS_OK);
    CHECK(jft_entry != 0xffu && jft_entry < 64u);

    CHECK(dos_call(emulator, 0x5200u, 0u, 0u, 0u, &state));
    CHECK((state.flags & 1u) == 0u);
    CHECK(xxemul_read_memory(emulator,
        xxemul_dos_linear(state.segment[XXEMUL_X86_ES],
            (uint16_t)(state.gpr[XXEMUL_X86_RBX] + 4u)),
        sft_pointer, sizeof(sft_pointer)) == XXEMUL_STATUS_OK);
    table_offset = dos_test_word(sft_pointer);
    table_segment = dos_test_word(sft_pointer + 2u);
    sft_index = jft_entry;
    for (table = 0u; table < 4u; ++table) {
        CHECK(xxemul_read_memory(emulator,
            xxemul_dos_linear(table_segment, table_offset),
            sft_header, sizeof(sft_header)) == XXEMUL_STATUS_OK);
        CHECK(dos_test_word(sft_header + 4u) == 16u);
        if (sft_index < 16u) break;
        sft_index = (uint16_t)(sft_index - 16u);
        CHECK(dos_test_word(sft_header) != 0xffffu
            || dos_test_word(sft_header + 2u) != 0xffffu);
        table_offset = dos_test_word(sft_header);
        table_segment = dos_test_word(sft_header + 2u);
    }
    CHECK(table < 4u);
    entry_address = xxemul_dos_linear(table_segment,
        (uint16_t)(table_offset + 6u + sft_index * sizeof(sft_entry)));
    CHECK(xxemul_read_memory(emulator, entry_address,
        sft_entry, sizeof(sft_entry)) == XXEMUL_STATUS_OK);
    CHECK(dos_test_word(sft_entry) == 1u);
    CHECK(dos_test_word(sft_entry + 2u) == 0u);
    CHECK(((uint32_t)dos_test_word(sft_entry + 0x11u)
        | ((uint32_t)dos_test_word(sft_entry + 0x13u) << 16u))
        == sizeof(payload) - 1u);
    CHECK(memcmp(sft_entry + 0x20u, dos_name, 11u) == 0);
    dos_time = dos_test_word(sft_entry + 0x0du);
    dos_date = dos_test_word(sft_entry + 0x0fu);
    CHECK((dos_date & 31u) >= 1u && (dos_date & 31u) <= 31u);
    CHECK(((dos_date >> 5u) & 15u) >= 1u
        && ((dos_date >> 5u) & 15u) <= 12u);
    CHECK(((dos_time >> 11u) & 31u) < 24u);
    CHECK(((dos_time >> 5u) & 63u) < 60u);
    CHECK((dos_time & 31u) < 30u);

    CHECK(dos_call(emulator, 0x5700u, handle, 0u, 0u, &state));
    CHECK((state.flags & 1u) == 0u);
    CHECK((uint16_t)state.gpr[XXEMUL_X86_RCX] == dos_time);
    CHECK((uint16_t)state.gpr[XXEMUL_X86_RDX] == dos_date);
    CHECK(dos_call(emulator, 0x3e00u, handle, 0u, 0u, &state));
    CHECK((state.flags & 1u) == 0u);
    CHECK(xxemul_read_memory(emulator,
        xxemul_dos_linear(dos_test_word(psp_jft + 4u),
            (uint16_t)(dos_test_word(psp_jft + 2u) + handle)),
        &jft_entry, sizeof(jft_entry)) == XXEMUL_STATUS_OK);
    CHECK(jft_entry == 0xffu);
    CHECK(xxemul_read_memory(emulator, entry_address,
        sft_entry, sizeof(sft_entry)) == XXEMUL_STATUS_OK);
    CHECK(dos_test_word(sft_entry) == 0u);
    xxemul_destroy(emulator);
    CHECK(remove(name) == 0);
    return 1;
}

static int test_dos_truename(void)
{
    static const uint8_t image[] = {
        0xcd, 0x21, 0xcd, 0x21, 0xcd, 0x21, 0xcd, 0x21,
        0xcd, 0x21, 0xcd, 0x21, 0xcd, 0x21, 0xcd, 0x21,
        0xcd, 0x21, 0xcd, 0x21, 0xcd, 0x21
    };
    static const struct {
        const char *input;
        const char *output;
        uint16_t error;
    } cases[] = {
        {"fasm.exe", "C:\\FASM.EXE", 0u},
        {"c:/src//./../fasm.exe", "C:\\FASM.EXE", 0u},
        {"dir\\sub/../file.bin", "C:\\DIR\\FILE.BIN", 0u},
        {"\\tools/uPx.exe", "C:\\TOOLS\\UPX.EXE", 0u},
        {"c:abc", "C:\\ABC", 0u},
        {"C:\\", "C:\\", 0u},
        {"..\\escape.bin", NULL, 3u},
        {"D:\\FASM.EXE", NULL, 3u},
        {"\\\\server\\share", NULL, 3u},
        {"C:", NULL, 2u},
        {"", NULL, 2u}
    };
    xxemul_status status;
    xxemul_x86_state state;
    xxemul *emulator = xxemul_create_dos(
        XXEMUL_DOS_COM, image, sizeof(image), &status);
    uint8_t output[128];
    uint8_t sentinel[128];
    uint8_t overlong[128];
    size_t original_region_size;
    size_t index;

    CHECK(emulator != NULL && status == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    state.segment[XXEMUL_X86_DS] = 0x2000u;
    state.segment[XXEMUL_X86_ES] = 0x3000u;
    state.gpr[XXEMUL_X86_RSI] = 0u;
    state.gpr[XXEMUL_X86_RDI] = 0x0104u;
    state.flags |= 1u;
    CHECK(xxemul_set_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    memset(sentinel, 0xa5, sizeof(sentinel));
    for (index = 0u; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        CHECK(xxemul_write_memory(emulator, 0x20000u,
            cases[index].input, strlen(cases[index].input) + 1u)
            == XXEMUL_STATUS_OK);
        CHECK(xxemul_write_memory(emulator, 0x30104u,
            sentinel, sizeof(sentinel)) == XXEMUL_STATUS_OK);
        CHECK(dos_call(emulator, 0x6000u, 0u, 0u, 0u, &state));
        CHECK((uint16_t)state.gpr[XXEMUL_X86_RAX] == cases[index].error);
        CHECK((state.flags & 1u) == (cases[index].error != 0u));
        CHECK((uint16_t)state.gpr[XXEMUL_X86_RSI] == 0u);
        CHECK((uint16_t)state.gpr[XXEMUL_X86_RDI] == 0x0104u);
        CHECK(xxemul_read_memory(emulator, 0x30104u,
            output, sizeof(output)) == XXEMUL_STATUS_OK);
        if (cases[index].error == 0u) {
            CHECK(memcmp(output, cases[index].output,
                strlen(cases[index].output) + 1u) == 0);
        } else {
            CHECK(memcmp(output, sentinel, sizeof(output)) == 0);
        }
    }

    memset(overlong, 'A', sizeof(overlong));
    CHECK(xxemul_write_memory(emulator, 0x20000u,
        overlong, sizeof(overlong)) == XXEMUL_STATUS_OK);
    emulator->x86.gpr[XXEMUL_X86_RAX] = 0x6000u;
    CHECK(xxemul_msdos_interrupt(emulator, 0x21u) == XXEMUL_STATUS_OK);
    CHECK((uint16_t)emulator->x86.gpr[XXEMUL_X86_RAX] == 3u);
    CHECK((emulator->x86.flags & 1u) != 0u);
    CHECK(xxemul_read_memory(emulator, 0x30104u,
        output, sizeof(output)) == XXEMUL_STATUS_OK);
    CHECK(memcmp(output, sentinel, sizeof(output)) == 0);

    CHECK(xxemul_write_memory(emulator, 0x20000u,
        "FASM.EXE", sizeof("FASM.EXE")) == XXEMUL_STATUS_OK);
    original_region_size = emulator->region_size;
    emulator->x86.gpr[XXEMUL_X86_RAX] = 0x6000u;
    emulator->region_size = 0x30105u;
    CHECK(xxemul_msdos_interrupt(emulator, 0x21u) == XXEMUL_STATUS_OK);
    emulator->region_size = original_region_size;
    CHECK((uint16_t)emulator->x86.gpr[XXEMUL_X86_RAX] == 3u);
    CHECK((emulator->x86.flags & 1u) != 0u);
    CHECK(xxemul_read_memory(emulator, 0x30104u,
        output, sizeof(output)) == XXEMUL_STATUS_OK);
    CHECK(memcmp(output, sentinel, sizeof(output)) == 0);

    emulator->x86.segment[XXEMUL_X86_DS] = 0x5000u;
    emulator->x86.gpr[XXEMUL_X86_RAX] = 0x6000u;
    emulator->region_size = 0x40000u;
    CHECK(xxemul_msdos_interrupt(emulator, 0x21u) == XXEMUL_STATUS_OK);
    emulator->region_size = original_region_size;
    CHECK((uint16_t)emulator->x86.gpr[XXEMUL_X86_RAX] == 3u);
    CHECK((emulator->x86.flags & 1u) != 0u);
    CHECK(xxemul_read_memory(emulator, 0x30104u,
        output, sizeof(output)) == XXEMUL_STATUS_OK);
    CHECK(memcmp(output, sentinel, sizeof(output)) == 0);
    xxemul_destroy(emulator);
    return 1;
}

static int test_dos_allocation_strategy(void)
{
    static const uint8_t image[] = {
        0xcd, 0x21, 0xcd, 0x21, 0xcd, 0x21, 0xcd, 0x21,
        0xcd, 0x21, 0xcd, 0x21, 0xcd, 0x21, 0xcd, 0x21,
        0xcd, 0x21, 0xcd, 0x21, 0xcd, 0x21, 0xcd, 0x21,
        0xcd, 0x21, 0xcd, 0x21, 0xcd, 0x21, 0xcd, 0x21,
        0xcd, 0x21, 0xcd, 0x21, 0xcd, 0x21, 0xcd, 0x21
    };
    xxemul_status status;
    xxemul_x86_state state;
    xxemul *emulator = xxemul_create_dos(
        XXEMUL_DOS_COM, image, sizeof(image), &status);
    uint16_t first_block;
    uint16_t middle_block;
    uint16_t high_block;

    CHECK(emulator != NULL && status == XXEMUL_STATUS_OK);
    CHECK(xxemul_start_process(emulator, XXEMUL_IMAGE_COM,
        "MEM.COM", ".", 0, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    state.segment[XXEMUL_X86_ES] = state.segment[XXEMUL_X86_CS];
    CHECK(xxemul_set_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK(dos_call(emulator, 0x4a00u, 0x100u, 0u, 0u, &state));
    CHECK((state.flags & 1u) == 0u);
    CHECK(dos_call(emulator, 0x5800u, 0u, 0u, 0u, &state));
    CHECK((state.flags & 1u) == 0u);
    CHECK((uint16_t)state.gpr[XXEMUL_X86_RAX] == 0u);

    CHECK(dos_call(emulator, 0x5801u, 2u, 0u, 0u, &state));
    CHECK((state.flags & 1u) == 0u);
    CHECK(dos_call(emulator, 0x5800u, 0u, 0u, 0u, &state));
    CHECK((uint16_t)state.gpr[XXEMUL_X86_RAX] == 2u);
    CHECK(dos_call(emulator, 0x4800u, 0x20u, 0u, 0u, &state));
    CHECK((state.flags & 1u) == 0u);
    high_block = (uint16_t)state.gpr[XXEMUL_X86_RAX];
    CHECK(high_block == 0x9fe0u);

    CHECK(dos_call(emulator, 0x5801u, 0u, 0u, 0u, &state));
    CHECK((state.flags & 1u) == 0u);
    CHECK(dos_call(emulator, 0x4800u, 0x20u, 0u, 0u, &state));
    CHECK((state.flags & 1u) == 0u);
    first_block = (uint16_t)state.gpr[XXEMUL_X86_RAX];
    CHECK(first_block == 0x915u);
    CHECK(dos_call(emulator, 0x4800u, 0x80u, 0u, 0u, &state));
    CHECK((state.flags & 1u) == 0u);
    middle_block = (uint16_t)state.gpr[XXEMUL_X86_RAX];
    CHECK(middle_block == 0x936u);

    state.segment[XXEMUL_X86_ES] = middle_block;
    CHECK(xxemul_set_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK(dos_call(emulator, 0x4900u, 0u, 0u, 0u, &state));
    CHECK((state.flags & 1u) == 0u);
    CHECK(dos_call(emulator, 0x5801u, 1u, 0u, 0u, &state));
    CHECK((state.flags & 1u) == 0u);
    CHECK(dos_call(emulator, 0x4800u, 0x30u, 0u, 0u, &state));
    CHECK((state.flags & 1u) == 0u);
    CHECK((uint16_t)state.gpr[XXEMUL_X86_RAX] == middle_block);

    CHECK(dos_call(emulator, 0x5801u, 3u, 0u, 0u, &state));
    CHECK((state.flags & 1u) != 0u);
    CHECK((uint16_t)state.gpr[XXEMUL_X86_RAX] == 1u);
    CHECK(dos_call(emulator, 0x5800u, 0u, 0u, 0u, &state));
    CHECK((uint16_t)state.gpr[XXEMUL_X86_RAX] == 1u);
    CHECK(dos_call(emulator, 0x5801u, 0x80u, 0u, 0u, &state));
    CHECK((state.flags & 1u) == 0u);
    CHECK(dos_call(emulator, 0x5800u, 0u, 0u, 0u, &state));
    CHECK((uint16_t)state.gpr[XXEMUL_X86_RAX] == 0x80u);
    CHECK(dos_call(emulator, 0x4800u, 0x10u, 0u, 0u, &state));
    CHECK((state.flags & 1u) == 0u);
    CHECK((uint16_t)state.gpr[XXEMUL_X86_RAX] < high_block);
    CHECK(dos_call(emulator, 0x5801u, 0x40u, 0u, 0u, &state));
    CHECK((state.flags & 1u) == 0u);
    CHECK(dos_call(emulator, 0x4800u, 0x10u, 0u, 0u, &state));
    CHECK((state.flags & 1u) != 0u);
    CHECK((uint16_t)state.gpr[XXEMUL_X86_RAX] == 8u);
    CHECK((uint16_t)state.gpr[XXEMUL_X86_RBX] == 0u);
    CHECK(dos_call(emulator, 0x5802u, 0u, 0u, 0u, &state));
    CHECK((state.flags & 1u) == 0u);
    CHECK((uint16_t)state.gpr[XXEMUL_X86_RAX] == 0x5800u);
    CHECK(dos_call(emulator, 0x5803u, 1u, 0u, 0u, &state));
    CHECK((state.flags & 1u) != 0u);
    CHECK((uint16_t)state.gpr[XXEMUL_X86_RAX] == 1u);
    xxemul_destroy(emulator);
    return 1;
}

static int test_dos_drive_space(void)
{
    static const uint8_t image[] = {
        0xcd, 0x21, 0xcd, 0x21, 0xcd, 0x21
    };
    xxemul_status status;
    xxemul_x86_state state;
    xxemul *emulator = xxemul_create_dos(
        XXEMUL_DOS_COM, image, sizeof(image), &status);

    CHECK(emulator != NULL && status == XXEMUL_STATUS_OK);
    CHECK(xxemul_start_process(emulator, XXEMUL_IMAGE_COM,
        "SPACE.COM", ".", 0, NULL) == XXEMUL_STATUS_OK);
    CHECK(dos_call(emulator, 0x3600u, 0u, 0u, 3u, &state));
    CHECK((state.flags & 1u) == 0u);
    CHECK((uint16_t)state.gpr[XXEMUL_X86_RAX] == 8u);
    CHECK((uint16_t)state.gpr[XXEMUL_X86_RCX] == 512u);
    CHECK((uint16_t)state.gpr[XXEMUL_X86_RDX] > 0u);
    CHECK((uint16_t)state.gpr[XXEMUL_X86_RBX]
        <= (uint16_t)state.gpr[XXEMUL_X86_RDX]);
    CHECK(dos_call(emulator, 0x3600u, 0u, 0u, 0u, &state));
    CHECK((state.flags & 1u) == 0u);
    CHECK((uint16_t)state.gpr[XXEMUL_X86_RAX] == 8u);
    CHECK((uint16_t)state.gpr[XXEMUL_X86_RCX] == 512u);
    CHECK(dos_call(emulator, 0x3600u, 0u, 0u, 2u, &state));
    CHECK((state.flags & 1u) == 0u);
    CHECK((uint16_t)state.gpr[XXEMUL_X86_RAX] == UINT16_MAX);
    xxemul_destroy(emulator);
    return 1;
}

static int test_dos_files(void)
{
    static const uint8_t image[] = {
        0xcd, 0x21, 0xcd, 0x21, 0xcd, 0x21, 0xcd, 0x21,
        0xcd, 0x21, 0xcd, 0x21, 0xcd, 0x21, 0xcd, 0x21,
        0xcd, 0x21, 0xcd, 0x21, 0xcd, 0x21, 0xcd, 0x21,
        0xcd, 0x21, 0xcd, 0x21, 0xcd, 0x21, 0xcd, 0x21
    };
    static const char name[] = "XXDOSIO.BIN";
    static const char lower_name[] = "xxdosio.bin";
    static const char escape[] = "..\\ESCAPE.BIN";
    static const char payload[] = "DOS-UPX";
    static const char *const args[] = {
        "UPX.EXE", "-o", "PACKED.EXE"
    };
    xxemul_status status;
    xxemul_x86_state state;
    uint8_t tail[18];
    uint8_t saved_tail[18];
    char too_long[128];
    const char *bad_args[] = {too_long};
    char received[sizeof(payload)];
    uint8_t dta_record[43];
    uint16_t handle;
    uint16_t standard_handle;
    FILE *file;
    xxemul *emulator = xxemul_create_dos(
        XXEMUL_DOS_COM, image, sizeof(image), &status);

    CHECK(emulator != NULL && status == XXEMUL_STATUS_OK);
    file = fopen(name, "rb");
    CHECK(file == NULL);
    CHECK(xxemul_start_process(emulator, XXEMUL_IMAGE_COM,
        "UPX.EXE", ".", 3, args)
        == XXEMUL_STATUS_OK);
    CHECK(xxemul_read_memory(emulator, 0x8140u + 0x80u,
        tail, sizeof(tail)) == XXEMUL_STATUS_OK);
    CHECK(tail[0] == 14u);
    CHECK(memcmp(tail + 1u, " -o PACKED.EXE", 14u) == 0);
    CHECK(tail[15] == 0x0du);
    memcpy(saved_tail, tail, sizeof(tail));
    memset(too_long, 'X', sizeof(too_long) - 1u);
    too_long[sizeof(too_long) - 1u] = '\0';
    CHECK(xxemul_dos_files_start(emulator, ".", "UPX.EXE", 1u, bad_args)
        == XXEMUL_STATUS_INVALID_ARGUMENT);
    CHECK(xxemul_read_memory(emulator, 0x8140u + 0x80u,
        tail, sizeof(tail)) == XXEMUL_STATUS_OK);
    CHECK(memcmp(tail, saved_tail, sizeof(tail)) == 0);
    CHECK(xxemul_write_memory(emulator, 0x8140u + 0x200u,
        name, sizeof(name)) == XXEMUL_STATUS_OK);
    CHECK(xxemul_write_memory(emulator, 0x8140u + 0x300u,
        payload, sizeof(payload) - 1u) == XXEMUL_STATUS_OK);

    CHECK(dos_call(emulator, 0x3c00u, 0u, 0u, 0x200u, &state));
    CHECK((state.flags & 1u) == 0u);
    handle = (uint16_t)state.gpr[XXEMUL_X86_RAX];
    CHECK(handle == 5u);
    CHECK(dos_call(emulator, 0x4000u, handle,
        (uint16_t)(sizeof(payload) - 1u), 0x300u, &state));
    CHECK((state.flags & 1u) == 0u);
    CHECK((uint16_t)state.gpr[XXEMUL_X86_RAX] == sizeof(payload) - 1u);
    CHECK(dos_call(emulator, 0x4200u, handle, 0u, 0u, &state));
    CHECK((state.flags & 1u) == 0u);
    CHECK(state.gpr[XXEMUL_X86_RAX] == 0u);
    CHECK(dos_call(emulator, 0x3f00u, handle,
        (uint16_t)(sizeof(payload) - 1u), 0x400u, &state));
    CHECK((state.flags & 1u) == 0u);
    CHECK(xxemul_read_memory(emulator, 0x8140u + 0x400u,
        received, sizeof(payload) - 1u) == XXEMUL_STATUS_OK);
    CHECK(memcmp(received, payload, sizeof(payload) - 1u) == 0);
    CHECK(dos_call(emulator, 0x3e00u, handle, 0u, 0u, &state));
    CHECK((state.flags & 1u) == 0u);

    CHECK(dos_call(emulator, 0x4300u, 0u, 0u, 0x200u, &state));
    CHECK((state.flags & 1u) == 0u);
    CHECK(((uint16_t)state.gpr[XXEMUL_X86_RCX] & 0x10u) == 0u);
    CHECK(dos_call(emulator, 0x4e00u, 0u, 0u, 0x200u, &state));
    CHECK((state.flags & 1u) == 0u);
    CHECK(xxemul_read_memory(emulator, 0x8140u + 0x80u,
        dta_record, sizeof(dta_record)) == XXEMUL_STATUS_OK);
    CHECK(dta_record[0x1au] == sizeof(payload) - 1u);
    CHECK(strcmp((const char *)dta_record + 0x1eu, name) == 0);

    CHECK(xxemul_write_memory(emulator, 0x8140u + 0x200u,
        lower_name, sizeof(lower_name)) == XXEMUL_STATUS_OK);
    CHECK(dos_call(emulator, 0x3d00u, 0u, 0u, 0x200u, &state));
    CHECK((state.flags & 1u) == 0u);
    CHECK((uint16_t)state.gpr[XXEMUL_X86_RAX] == handle);
    for (standard_handle = 0u; standard_handle <= 2u; ++standard_handle) {
        CHECK(dos_call(emulator, 0x4400u, standard_handle,
            0u, 0u, &state));
        CHECK((state.flags & 1u) == 0u);
        CHECK((uint16_t)state.gpr[XXEMUL_X86_RDX] == 0x80d3u);
    }
    CHECK(dos_call(emulator, 0x4400u, handle, 0u, 0u, &state));
    CHECK((state.flags & 1u) == 0u);
    CHECK(((uint16_t)state.gpr[XXEMUL_X86_RDX] & 0x8080u) == 0u);
    CHECK(((uint16_t)state.gpr[XXEMUL_X86_RDX] & 0x1fu) == 2u);
    CHECK(dos_call(emulator, 0x4400u, 0xffffu, 0u, 0u, &state));
    CHECK((state.flags & 1u) != 0u);
    CHECK((uint16_t)state.gpr[XXEMUL_X86_RAX] == 6u);
    CHECK(dos_call(emulator, 0x4000u, handle, 1u, 0x300u, &state));
    CHECK((state.flags & 1u) != 0u);
    CHECK((uint16_t)state.gpr[XXEMUL_X86_RAX] == 5u);
    CHECK(dos_call(emulator, 0x3e00u, handle, 0u, 0u, &state));
    CHECK((state.flags & 1u) == 0u);
    CHECK(xxemul_write_memory(emulator, 0x8140u + 0x200u,
        escape, sizeof(escape)) == XXEMUL_STATUS_OK);
    CHECK(dos_call(emulator, 0x3c00u, 0u, 0u, 0x200u, &state));
    CHECK((state.flags & 1u) != 0u);
    CHECK((uint16_t)state.gpr[XXEMUL_X86_RAX] == 3u);

    xxemul_dos_files_stop(emulator);
    xxemul_destroy(emulator);
    file = fopen(name, "rb");
    CHECK(file != NULL);
    CHECK(fread(received, 1u, sizeof(payload) - 1u, file)
        == sizeof(payload) - 1u);
    CHECK(fclose(file) == 0);
    CHECK(memcmp(received, payload, sizeof(payload) - 1u) == 0);
    CHECK(remove(name) == 0);
    return 1;
}

static int test_dos_delete_file(void)
{
    static const uint8_t image[] = {
        0xcd, 0x21, 0xcd, 0x21, 0xcd, 0x21,
        0xcd, 0x21, 0xcd, 0x21, 0xcd, 0x21
    };
    static const char workdir[] = "XX41WORK";
    static const char host_name[] = "XX41WORK/XX41DEL.BIN";
    static const char guest_name[] = "XX41DEL.BIN";
    static const char outside_name[] = "XX41OUT.BIN";
    static const char escape_name[] = "..\\XX41OUT.BIN";
    static const char payload[] = "delete through DOS";
    static const char outside_payload[] = "keep outside file";
    xxemul_status status;
    xxemul_x86_state state;
    xxemul *emulator;
    uint16_t handle;
    char received[sizeof(payload) > sizeof(outside_payload)
        ? sizeof(payload) : sizeof(outside_payload)];
    FILE *file;

#if defined(_WIN32)
    CHECK(_mkdir(workdir) == 0 || errno == EEXIST);
#else
    CHECK(mkdir(workdir, 0700) == 0 || errno == EEXIST);
#endif
    file = fopen(host_name, "rb");
    CHECK(file == NULL);
    file = fopen(outside_name, "rb");
    CHECK(file == NULL);
    file = fopen(outside_name, "wb");
    CHECK(file != NULL);
    CHECK(fwrite(outside_payload, 1u, sizeof(outside_payload) - 1u, file)
        == sizeof(outside_payload) - 1u);
    CHECK(fclose(file) == 0);

    emulator = xxemul_create_dos(
        XXEMUL_DOS_COM, image, sizeof(image), &status);
    CHECK(emulator != NULL && status == XXEMUL_STATUS_OK);
    CHECK(xxemul_start_process(emulator, XXEMUL_IMAGE_COM,
        "DELETE.COM", workdir, 0u, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK(xxemul_write_memory(emulator,
        xxemul_dos_linear(state.segment[XXEMUL_X86_DS], 0x200u),
        guest_name, sizeof(guest_name)) == XXEMUL_STATUS_OK);
    CHECK(xxemul_write_memory(emulator,
        xxemul_dos_linear(state.segment[XXEMUL_X86_DS], 0x220u),
        escape_name, sizeof(escape_name)) == XXEMUL_STATUS_OK);
    CHECK(xxemul_write_memory(emulator,
        xxemul_dos_linear(state.segment[XXEMUL_X86_DS], 0x300u),
        payload, sizeof(payload) - 1u) == XXEMUL_STATUS_OK);

    CHECK(dos_call(emulator, 0x3c00u, 0u, 0u, 0x200u, &state));
    CHECK((state.flags & 1u) == 0u);
    handle = (uint16_t)state.gpr[XXEMUL_X86_RAX];
    CHECK(handle >= 5u && handle < 64u);
    CHECK(dos_call(emulator, 0x4000u, handle,
        (uint16_t)(sizeof(payload) - 1u), 0x300u, &state));
    CHECK((state.flags & 1u) == 0u);
    CHECK((uint16_t)state.gpr[XXEMUL_X86_RAX] == sizeof(payload) - 1u);
    CHECK(dos_call(emulator, 0x3e00u, handle, 0u, 0u, &state));
    CHECK((state.flags & 1u) == 0u);
    file = fopen(host_name, "rb");
    CHECK(file != NULL);
    CHECK(fread(received, 1u, sizeof(payload) - 1u, file)
        == sizeof(payload) - 1u);
    CHECK(memcmp(received, payload, sizeof(payload) - 1u) == 0);
    CHECK(fclose(file) == 0);

    CHECK(dos_call(emulator, 0x4100u, 0u, 0u, 0x200u, &state));
    CHECK((state.flags & 1u) == 0u);
    file = fopen(host_name, "rb");
    CHECK(file == NULL);
    CHECK(dos_call(emulator, 0x4100u, 0u, 0u, 0x200u, &state));
    CHECK((state.flags & 1u) != 0u);
    CHECK((uint16_t)state.gpr[XXEMUL_X86_RAX] == 2u);

    CHECK(dos_call(emulator, 0x4100u, 0u, 0u, 0x220u, &state));
    CHECK((state.flags & 1u) != 0u);
    CHECK((uint16_t)state.gpr[XXEMUL_X86_RAX] == 3u);
    file = fopen(outside_name, "rb");
    CHECK(file != NULL);
    CHECK(fread(received, 1u, sizeof(outside_payload) - 1u, file)
        == sizeof(outside_payload) - 1u);
    CHECK(memcmp(received, outside_payload,
        sizeof(outside_payload) - 1u) == 0);
    CHECK(fgetc(file) == EOF);
    CHECK(fclose(file) == 0);

    xxemul_dos_files_stop(emulator);
    xxemul_destroy(emulator);
    CHECK(remove(outside_name) == 0);
#if defined(_WIN32)
    CHECK(_rmdir(workdir) == 0);
#else
    CHECK(rmdir(workdir) == 0);
#endif
    return 1;
}

static int test_dos_extended_open_create(void)
{
    static const uint8_t image[] = {
        0xcd, 0x21, 0xcd, 0x21, 0xcd, 0x21, 0xcd, 0x21,
        0xcd, 0x21, 0xcd, 0x21, 0xcd, 0x21, 0xcd, 0x21,
        0xcd, 0x21, 0xcd, 0x21, 0xcd, 0x21
    };
    static const char name[] = "XX6COPEN.BIN";
    static const char payload[] = "extended DOS open";
    xxemul_status status;
    xxemul_x86_state state;
    xxemul *emulator;
    FILE *file = fopen(name, "rb");
    char received[sizeof(payload)];
    uint16_t handle;

    CHECK(file == NULL);
    emulator = xxemul_create_dos(
        XXEMUL_DOS_COM, image, sizeof(image), &status);
    CHECK(emulator != NULL && status == XXEMUL_STATUS_OK);
    CHECK(xxemul_start_process(emulator, XXEMUL_IMAGE_COM,
        "OPEN6C.COM", ".", 0u, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK(xxemul_write_memory(emulator,
        xxemul_dos_linear(state.segment[XXEMUL_X86_DS], 0x200u),
        name, sizeof(name)) == XXEMUL_STATUS_OK);
    CHECK(xxemul_write_memory(emulator,
        xxemul_dos_linear(state.segment[XXEMUL_X86_DS], 0x300u),
        payload, sizeof(payload) - 1u) == XXEMUL_STATUS_OK);
    state.gpr[XXEMUL_X86_RSI] = 0x200u;
    CHECK(xxemul_set_x86_state(emulator, &state) == XXEMUL_STATUS_OK);

    CHECK(dos_call(emulator, 0x6c00u, 2u, 0u, 0x0010u, &state));
    CHECK((state.flags & 1u) == 0u);
    handle = (uint16_t)state.gpr[XXEMUL_X86_RAX];
    CHECK(handle >= 5u && handle < 64u);
    CHECK((uint16_t)state.gpr[XXEMUL_X86_RCX] == 2u);
    CHECK(dos_call(emulator, 0x4000u, handle,
        (uint16_t)(sizeof(payload) - 1u), 0x300u, &state));
    CHECK((state.flags & 1u) == 0u);
    CHECK((uint16_t)state.gpr[XXEMUL_X86_RAX] == sizeof(payload) - 1u);
    CHECK(dos_call(emulator, 0x3e00u, handle, 0u, 0u, &state));
    CHECK((state.flags & 1u) == 0u);

    CHECK(dos_call(emulator, 0x6c00u, 2u, 0u, 0x0010u, &state));
    CHECK((state.flags & 1u) != 0u);
    CHECK((uint16_t)state.gpr[XXEMUL_X86_RAX] == 80u);
    CHECK(dos_call(emulator, 0x6c00u, 0u, 0u, 0x0001u, &state));
    CHECK((state.flags & 1u) == 0u);
    handle = (uint16_t)state.gpr[XXEMUL_X86_RAX];
    CHECK(handle >= 5u && handle < 64u);
    CHECK((uint16_t)state.gpr[XXEMUL_X86_RCX] == 1u);
    CHECK(dos_call(emulator, 0x4202u, handle, 0u, 0u, &state));
    CHECK((state.flags & 1u) == 0u);
    CHECK((uint16_t)state.gpr[XXEMUL_X86_RAX] == sizeof(payload) - 1u);
    CHECK((uint16_t)state.gpr[XXEMUL_X86_RDX] == 0u);
    CHECK(dos_call(emulator, 0x4200u, handle, 0u, 0u, &state));
    CHECK((state.flags & 1u) == 0u);
    CHECK((uint16_t)state.gpr[XXEMUL_X86_RAX] == 0u);
    CHECK(dos_call(emulator, 0x3f00u, handle,
        (uint16_t)(sizeof(payload) - 1u), 0x400u, &state));
    CHECK((state.flags & 1u) == 0u);
    CHECK((uint16_t)state.gpr[XXEMUL_X86_RAX] == sizeof(payload) - 1u);
    CHECK(xxemul_read_memory(emulator,
        xxemul_dos_linear(state.segment[XXEMUL_X86_DS], 0x400u),
        received, sizeof(payload) - 1u) == XXEMUL_STATUS_OK);
    CHECK(memcmp(received, payload, sizeof(payload) - 1u) == 0);
    CHECK(dos_call(emulator, 0x3e00u, handle, 0u, 0u, &state));
    CHECK((state.flags & 1u) == 0u);

    CHECK(dos_call(emulator, 0x6c00u, 0u, 0u, 0x0030u, &state));
    CHECK((state.flags & 1u) != 0u);
    CHECK((uint16_t)state.gpr[XXEMUL_X86_RAX] == 1u);
    CHECK(dos_call(emulator, 0x6c01u, 0u, 0u, 0x0001u, &state));
    CHECK((state.flags & 1u) != 0u);
    CHECK((uint16_t)state.gpr[XXEMUL_X86_RAX] == 1u);

    xxemul_dos_files_stop(emulator);
    xxemul_destroy(emulator);
    CHECK(remove(name) == 0);
    return 1;
}

static int test_dos_timestamp_live_sft(void)
{
    static const uint8_t image[] = {
        0xcd, 0x21, 0xcd, 0x21, 0xcd, 0x21, 0xcd, 0x21,
        0xcd, 0x21, 0xcd, 0x21, 0xcd, 0x21, 0xcd, 0x21,
        0xcd, 0x21, 0xcd, 0x21, 0xcd, 0x21, 0xcd, 0x21,
        0xcd, 0x21, 0xcd, 0x21, 0xcd, 0x21, 0xcd, 0x21
    };
    static const char name[] = "XX57TIME.BIN";
    static const char payload[] = "DOS time";
    static const char dos_name[] = "XX57TIMEBIN";
    const uint16_t date = (uint16_t)((41u << 9u) | (6u << 5u) | 7u);
    const uint16_t clock = (uint16_t)((12u << 11u) | (34u << 5u) | 5u);
    xxemul_status status;
    xxemul_x86_state state;
    xxemul *emulator;
    uint8_t psp_jft[6];
    uint8_t jft_index;
    uint8_t sft_pointer[4];
    uint8_t sft_header[6];
    uint8_t sft_entry[0x3bu];
    uint16_t handle;
    uint16_t sft_index;
    uint16_t sft_segment;
    uint16_t sft_offset;
    uint64_t entry_address;
    unsigned table;
    FILE *file = fopen(name, "rb");

    CHECK(file == NULL);
    emulator = xxemul_create_dos(
        XXEMUL_DOS_COM, image, sizeof(image), &status);
    CHECK(emulator != NULL && status == XXEMUL_STATUS_OK);
    CHECK(xxemul_start_process(emulator, XXEMUL_IMAGE_COM,
        "TIME.COM", ".", 0u, NULL) == XXEMUL_STATUS_OK);
    CHECK(xxemul_write_memory(emulator, 0x8140u + 0x200u,
        name, sizeof(name)) == XXEMUL_STATUS_OK);
    CHECK(xxemul_write_memory(emulator, 0x8140u + 0x300u,
        payload, sizeof(payload) - 1u) == XXEMUL_STATUS_OK);
    CHECK(dos_call(emulator, 0x3c00u, 0u, 0u, 0x200u, &state));
    CHECK((state.flags & 1u) == 0u);
    handle = (uint16_t)state.gpr[XXEMUL_X86_RAX];
    CHECK(handle >= 5u);
    CHECK(dos_call(emulator, 0x4000u, handle,
        (uint16_t)(sizeof(payload) - 1u), 0x300u, &state));
    CHECK((state.flags & 1u) == 0u);
    CHECK(dos_call(emulator, 0x5700u, handle, 0u, 0u, &state));
    CHECK((state.flags & 1u) == 0u);
    CHECK((uint16_t)state.gpr[XXEMUL_X86_RDX] != 0u);
    CHECK(dos_call(emulator, 0x5701u, handle, clock, date, &state));
    CHECK((state.flags & 1u) == 0u);
    CHECK(dos_call(emulator, 0x5700u, handle, 0u, 0u, &state));
    CHECK((state.flags & 1u) == 0u);
    CHECK((uint16_t)state.gpr[XXEMUL_X86_RCX] == clock);
    CHECK((uint16_t)state.gpr[XXEMUL_X86_RDX] == date);

    CHECK(dos_call(emulator, 0x6200u, 0u, 0u, 0u, &state));
    CHECK((state.flags & 1u) == 0u);
    CHECK(xxemul_read_memory(emulator,
        xxemul_dos_linear((uint16_t)state.gpr[XXEMUL_X86_RBX], 0x32u),
        psp_jft, sizeof(psp_jft)) == XXEMUL_STATUS_OK);
    CHECK(handle < dos_test_word(psp_jft));
    CHECK(xxemul_read_memory(emulator,
        xxemul_dos_linear(dos_test_word(psp_jft + 4u),
            (uint16_t)(dos_test_word(psp_jft + 2u) + handle)),
        &jft_index, sizeof(jft_index)) == XXEMUL_STATUS_OK);
    CHECK(jft_index != 0xffu);
    CHECK(dos_call(emulator, 0x5200u, 0u, 0u, 0u, &state));
    CHECK((state.flags & 1u) == 0u);
    CHECK(xxemul_read_memory(emulator,
        xxemul_dos_linear(state.segment[XXEMUL_X86_ES],
            (uint16_t)(state.gpr[XXEMUL_X86_RBX] + 4u)),
        sft_pointer, sizeof(sft_pointer)) == XXEMUL_STATUS_OK);
    sft_offset = dos_test_word(sft_pointer);
    sft_segment = dos_test_word(sft_pointer + 2u);
    sft_index = jft_index;
    for (table = 0u; table < 4u; ++table) {
        CHECK(xxemul_read_memory(emulator,
            xxemul_dos_linear(sft_segment, sft_offset),
            sft_header, sizeof(sft_header)) == XXEMUL_STATUS_OK);
        CHECK(dos_test_word(sft_header + 4u) != 0u);
        if (sft_index < dos_test_word(sft_header + 4u)) break;
        sft_index = (uint16_t)(sft_index
            - dos_test_word(sft_header + 4u));
        CHECK(dos_test_word(sft_header) != 0xffffu);
        sft_offset = dos_test_word(sft_header);
        sft_segment = dos_test_word(sft_header + 2u);
    }
    CHECK(table < 4u);
    entry_address = xxemul_dos_linear(sft_segment,
        (uint16_t)(sft_offset + 6u + sft_index * sizeof(sft_entry)));
    CHECK(xxemul_read_memory(emulator, entry_address,
        sft_entry, sizeof(sft_entry)) == XXEMUL_STATUS_OK);
    CHECK(dos_test_word(sft_entry) == 1u);
    CHECK(((uint32_t)dos_test_word(sft_entry + 0x11u)
        | ((uint32_t)dos_test_word(sft_entry + 0x13u) << 16u))
        == sizeof(payload) - 1u);
    CHECK(((uint32_t)dos_test_word(sft_entry + 0x15u)
        | ((uint32_t)dos_test_word(sft_entry + 0x17u) << 16u))
        == sizeof(payload) - 1u);
    CHECK(memcmp(sft_entry + 0x20u, dos_name, 11u) == 0);
    CHECK(dos_test_word(sft_entry + 0x0du) == clock);
    CHECK(dos_test_word(sft_entry + 0x0fu) == date);

    CHECK(dos_call(emulator, 0x4200u, handle, 0u, 0u, &state));
    CHECK((state.flags & 1u) == 0u);
    CHECK(xxemul_read_memory(emulator, entry_address,
        sft_entry, sizeof(sft_entry)) == XXEMUL_STATUS_OK);
    CHECK(dos_test_word(sft_entry + 0x15u) == 0u);
    CHECK(dos_call(emulator, 0x5700u, 0xffffu, 0u, 0u, &state));
    CHECK((state.flags & 1u) != 0u);
    CHECK((uint16_t)state.gpr[XXEMUL_X86_RAX] == 6u);
    CHECK(dos_call(emulator, 0x5702u, handle, 0u, 0u, &state));
    CHECK((state.flags & 1u) != 0u);
    CHECK((uint16_t)state.gpr[XXEMUL_X86_RAX] == 1u);
    CHECK(dos_call(emulator, 0x3e00u, handle, 0u, 0u, &state));
    CHECK((state.flags & 1u) == 0u);
    CHECK(xxemul_read_memory(emulator,
        xxemul_dos_linear(dos_test_word(psp_jft + 4u),
            (uint16_t)(dos_test_word(psp_jft + 2u) + handle)),
        &jft_index, sizeof(jft_index)) == XXEMUL_STATUS_OK);
    CHECK(jft_index == 0xffu);
    CHECK(xxemul_read_memory(emulator, entry_address,
        sft_entry, sizeof(sft_entry)) == XXEMUL_STATUS_OK);
    CHECK(dos_test_word(sft_entry) == 0u);

    CHECK(dos_call(emulator, 0x3d00u, 0u, 0u, 0x200u, &state));
    CHECK((state.flags & 1u) == 0u);
    handle = (uint16_t)state.gpr[XXEMUL_X86_RAX];
    CHECK(dos_call(emulator, 0x5700u, handle, 0u, 0u, &state));
    CHECK((state.flags & 1u) == 0u);
    CHECK((uint16_t)state.gpr[XXEMUL_X86_RCX] == clock);
    CHECK((uint16_t)state.gpr[XXEMUL_X86_RDX] == date);
    CHECK(dos_call(emulator, 0x3e00u, handle, 0u, 0u, &state));
    CHECK((state.flags & 1u) == 0u);
    xxemul_dos_files_stop(emulator);
    xxemul_destroy(emulator);
    CHECK(remove(name) == 0);
    return 1;
}

static int test_upx_mz_header(const char *path)
{
    FILE *file = fopen(path, "rb");
    xxemul *emulator;
    xxemul_status status;
    xxemul_x86_state state;
    uint8_t *image;
    uint8_t psp_end[2];
    uint8_t entry_opcode;
    long size;

    CHECK(file != NULL);
    CHECK(fseek(file, 0, SEEK_END) == 0);
    size = ftell(file);
    CHECK(size == 740112L);
    CHECK(fseek(file, 0, SEEK_SET) == 0);
    image = (uint8_t *)malloc((size_t)size);
    CHECK(image != NULL);
    CHECK(fread(image, 1u, (size_t)size, file) == (size_t)size);
    CHECK(fclose(file) == 0);
    emulator = xxemul_create_dos(XXEMUL_DOS_MZ,
        image, (size_t)size, &status);
    free(image);
    CHECK(emulator != NULL && status == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK(state.segment[XXEMUL_X86_CS] == 0x824u);
    CHECK(state.segment[XXEMUL_X86_SS] == 0x1124u);
    CHECK(state.segment[XXEMUL_X86_DS] == 0x814u);
    CHECK(state.segment[XXEMUL_X86_ES] == 0x814u);
    CHECK(state.ip == 0x54u);
    CHECK((uint16_t)state.gpr[XXEMUL_X86_RSP] == 0x0100u);
    CHECK(xxemul_read_memory(emulator,
        xxemul_dos_linear(state.segment[XXEMUL_X86_CS],
            (uint16_t)state.ip), &entry_opcode, 1u) == XXEMUL_STATUS_OK);
    CHECK(entry_opcode == 0xe8u);
    CHECK(xxemul_read_memory(emulator, 0x8142u, psp_end, 2u)
        == XXEMUL_STATUS_OK);
    CHECK(psp_end[0] == 0x48u && psp_end[1] == 0x13u);
    xxemul_destroy(emulator);
    return 1;
}

static int probe_upx_packing(const char *upx_path, const char *fasm_path)
{
    static const char *const args[] = {
        "UPX.EXE", "-1", "-o", "FASM_PACKED.EXE", "FASM.EXE"
    };
    FILE *file = fopen(fasm_path, "rb");
    FILE *packed;
    xxemul_status status;
    xxemul_x86_state state;
    xxemul *emulator;
    char instruction[128];
    char opened_name[260];
    uint8_t signature[2];
    uint8_t exit_code = 0xffu;
    struct {
        uint16_t cs;
        uint16_t ip;
        uint16_t sp;
        uint16_t stack0;
        char disassembly[128];
    } history[64];
    uint64_t executed = 0u;
    unsigned interrupt_count = 0u;
    uint16_t previous_ip = 0u;
    long size;

    CHECK(file != NULL);
    CHECK(fseek(file, 0, SEEK_END) == 0);
    size = ftell(file);
    CHECK(fclose(file) == 0);
    CHECK(size == 118272L);
    packed = fopen("FASM_PACKED.EXE", "rb");
    CHECK(packed == NULL);
    emulator = xxemul_create_dos_file(
        XXEMUL_DOS_MZ, upx_path, &status);
    CHECK(emulator != NULL && status == XXEMUL_STATUS_OK);
    CHECK(xxemul_start_process(emulator, XXEMUL_IMAGE_MZ,
        upx_path, ".", 5, args)
        == XXEMUL_STATUS_OK);
    for (executed = 0u; executed < 1000000u; ++executed) {
        uint8_t opcode[2];
        int opening = 0;
        uint8_t interrupt = 0u;
        uint16_t call_ax = 0u;
        size_t index;

        CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
        history[executed % 64u].cs = state.segment[XXEMUL_X86_CS];
        history[executed % 64u].ip = (uint16_t)state.ip;
        history[executed % 64u].sp =
            (uint16_t)state.gpr[XXEMUL_X86_RSP];
        CHECK(xxemul_read_memory(emulator,
            xxemul_dos_linear(state.segment[XXEMUL_X86_SS],
                history[executed % 64u].sp),
            &history[executed % 64u].stack0,
            sizeof(history[0].stack0)) == XXEMUL_STATUS_OK);
        if (getenv("XXEMUL_DOS_TRACE") != NULL
            && (executed < 12u || ((uint16_t)state.ip >= 0x0c00u
            && (uint16_t)state.ip < 0x0d00u
            && (previous_ip < 0x0c00u || previous_ip >= 0x0d00u)))) {
            fprintf(stderr, "entry %llu %04x:%04x from %04x SP=%04x [SP]=%04x\n",
                (unsigned long long)executed,
                state.segment[XXEMUL_X86_CS], (unsigned)(uint16_t)state.ip,
                previous_ip, history[executed % 64u].sp,
                history[executed % 64u].stack0);
        }
        previous_ip = (uint16_t)state.ip;
        xxemul_format_current(emulator,
            history[executed % 64u].disassembly,
            sizeof(history[0].disassembly));
        if (getenv("XXEMUL_DOS_TRACE") != NULL) {
            fprintf(stderr,
                "%llu %04x:%04x SS=%04x SP=%04x [SP]=%04x %s\n",
                (unsigned long long)executed,
                history[executed % 64u].cs,
                history[executed % 64u].ip,
                state.segment[XXEMUL_X86_SS],
                history[executed % 64u].sp,
                history[executed % 64u].stack0,
                history[executed % 64u].disassembly);
        }
        if (xxemul_read_memory(emulator,
                xxemul_dos_linear(state.segment[XXEMUL_X86_CS],
                    (uint16_t)state.ip), opcode, sizeof(opcode))
                == XXEMUL_STATUS_OK
            && opcode[0] == 0xcdu
            && (opcode[1] == 0x21u || opcode[1] == 0x2fu
                || opcode[1] == 0x31u)) {
            interrupt = opcode[1];
            call_ax = (uint16_t)state.gpr[XXEMUL_X86_RAX];
        }
        if (interrupt == 0x21u && (call_ax >> 8) == 0x3du) {
            opening = 1;
            for (index = 0u; index + 1u < sizeof(opened_name); ++index) {
                uint8_t byte;
                CHECK(xxemul_read_memory(emulator,
                    xxemul_dos_linear(state.segment[XXEMUL_X86_DS],
                        (uint16_t)(state.gpr[XXEMUL_X86_RDX] + index)),
                    &byte, 1u) == XXEMUL_STATUS_OK);
                opened_name[index] = (char)byte;
                if (byte == 0u) {
                    break;
                }
            }
            opened_name[sizeof(opened_name) - 1u] = '\0';
        }
        status = xxemul_step(emulator, NULL);
        if (interrupt != 0u && interrupt_count++ < 96u) {
            CHECK(xxemul_get_x86_state(emulator, &state)
                == XXEMUL_STATUS_OK);
            fprintf(stderr,
                "INT %02x AX=%04x -> AX=%04x BX=%04x CF=%u (%s)%s%s\n",
                interrupt, call_ax,
                (unsigned)(uint16_t)state.gpr[XXEMUL_X86_RAX],
                (unsigned)(uint16_t)state.gpr[XXEMUL_X86_RBX],
                (unsigned)(state.flags & 1u), xxemul_status_string(status),
                opening ? " path=" : "", opening ? opened_name : "");
        }
        if (status != XXEMUL_STATUS_OK) {
            break;
        }
    }
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    xxemul_format_current(emulator, instruction, sizeof(instruction));
    if (status != XXEMUL_STATUS_HALTED) {
        uint64_t start = executed > 63u ? executed - 63u : 0u;
        uint64_t index;

        for (index = start; index <= executed; ++index) {
            fprintf(stderr, "  %04x:%04x SP=%04x [SP]=%04x %s\n",
                history[index % 64u].cs, history[index % 64u].ip,
                history[index % 64u].sp, history[index % 64u].stack0,
                history[index % 64u].disassembly);
        }
    }
    fprintf(stderr,
        "UPX DOS pack attempt: %s after %llu instructions at %04x:%04x"
        " (%s, AX=%04x BX=%04x CX=%04x DX=%04x DS=%04x)\n",
        xxemul_status_string(status), (unsigned long long)executed,
        state.segment[XXEMUL_X86_CS], (unsigned)(uint16_t)state.ip,
        instruction,
        (unsigned)(uint16_t)state.gpr[XXEMUL_X86_RAX],
        (unsigned)(uint16_t)state.gpr[XXEMUL_X86_RBX],
        (unsigned)(uint16_t)state.gpr[XXEMUL_X86_RCX],
        (unsigned)(uint16_t)state.gpr[XXEMUL_X86_RDX],
        state.segment[XXEMUL_X86_DS]);
    if (status != XXEMUL_STATUS_HALTED) {
        uint8_t tss_descriptor[16];
        size_t descriptor_index;
        fprintf(stderr, "DOS control state: CR0=%08x CR2=%08x CR3=%08x"
            " GDTR=%08x:%04x CS.base=%08x DS.base=%08x\n",
            emulator->dos_cr0, emulator->dos_cr2, emulator->dos_cr3,
            emulator->dos_gdtr_base, emulator->dos_gdtr_limit,
            emulator->dos_segments[XXEMUL_X86_CS].base,
            emulator->dos_segments[XXEMUL_X86_DS].base);
        if (xxemul_read_memory(emulator,
                (uint64_t)emulator->dos_gdtr_base + 0x60u,
                tss_descriptor, sizeof(tss_descriptor))
                == XXEMUL_STATUS_OK) {
            fprintf(stderr, "GDT[0060..006f]:");
            for (descriptor_index = 0u;
                descriptor_index < sizeof(tss_descriptor);
                ++descriptor_index)
                fprintf(stderr, " %02x", tss_descriptor[descriptor_index]);
            fputc('\n', stderr);
        }
    }
    CHECK(xxemul_dos_get_exit_code(emulator, &exit_code)
        == XXEMUL_STATUS_OK);
    xxemul_dos_files_stop(emulator);
    xxemul_destroy(emulator);
    if (status != XXEMUL_STATUS_HALTED || exit_code != 0u) {
        return 0;
    }
    packed = fopen("FASM_PACKED.EXE", "rb");
    CHECK(packed != NULL);
    CHECK(fseek(packed, 0, SEEK_END) == 0);
    size = ftell(packed);
    CHECK(size > 2L && size < 118272L);
    CHECK(fseek(packed, 0, SEEK_SET) == 0);
    CHECK(fread(signature, 1u, sizeof(signature), packed)
        == sizeof(signature));
    CHECK(fclose(packed) == 0);
    CHECK(signature[0] == 'M' && signature[1] == 'Z');
    return 1;
}

int main(int argc, char **argv)
{
    if (!test_memory_blocks()) {
        return 1;
    }
    if (!test_resize_failure() || !test_dpmi_probe()
        || !test_dos_interrupt_vector()
        || !test_dos_current_psp()
        || !test_dos_list_of_lists()
        || !test_dos_unsupported_lfn()
        || !test_dos_clock()
        || !test_dos_dta()
        || !test_dos_current_directory()
        || !test_dos_truename()
        || !test_mz_overlay() || !test_dos_allocation_strategy()
        || !test_dos_drive_space() || !test_dos_list_of_lists_file()
        || !test_dos_files() || !test_dos_delete_file()
        || !test_dos_extended_open_create()
        || !test_dos_timestamp_live_sft()) {
        return 1;
    }
    if (argc > 1 && !test_upx_mz_header(argv[1])) {
        return 1;
    }
    if (!test_dos_operand_size_stack()) {
        return 1;
    }
    if (!test_dos_guest_interrupt_return()) {
        return 1;
    }
    if (!test_dos_int10_host_thunk()
        || !test_dos_int21_host_thunk()
        || !test_dos_int21_guest_override()) {
        return 1;
    }
    if (argc > 2 && !probe_upx_packing(argv[1], argv[2])) {
        return 2;
    }
    puts("DOS UPX loader tests passed");
    return 0;
}
