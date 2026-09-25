#include "xxemul/xxemul.h"

#include <stdio.h>
#include <string.h>

#define CHECK(expression)                                                     \
    do {                                                                      \
        if (!(expression)) {                                                  \
            fprintf(stderr, "%s:%d: check failed: %s\n",                    \
                __FILE__, __LINE__, #expression);                             \
            return 0;                                                         \
        }                                                                     \
    } while (0)

static void put16(uint8_t *bytes, size_t offset, uint16_t value)
{
    bytes[offset] = (uint8_t)value;
    bytes[offset + 1u] = (uint8_t)(value >> 8);
}

static void put32(uint8_t *bytes, size_t offset, uint32_t value)
{
    put16(bytes, offset, (uint16_t)value);
    put16(bytes, offset + 2u, (uint16_t)(value >> 16));
}

static void put64(uint8_t *bytes, size_t offset, uint64_t value)
{
    put32(bytes, offset, (uint32_t)value);
    put32(bytes, offset + 4u, (uint32_t)(value >> 32));
}

static void make_pe(
    uint8_t image[0x400], int is_64,
    uint16_t machine, const uint8_t *code, size_t code_size)
{
    size_t optional = 0x98u;
    size_t section = optional + (is_64 ? 0xf0u : 0xe0u);

    memset(image, 0, 0x400u);
    image[0] = 'M';
    image[1] = 'Z';
    put32(image, 0x3cu, 0x80u);
    image[0x80] = 'P';
    image[0x81] = 'E';
    put16(image, 0x84u, machine);
    put16(image, 0x86u, 1u);
    put16(image, 0x94u, (uint16_t)(is_64 ? 0xf0u : 0xe0u));
    put16(image, 0x96u, 2u);
    put16(image, optional, (uint16_t)(is_64 ? 0x20bu : 0x10bu));
    put32(image, optional + 16u, 0x1000u);
    if (is_64) {
        put64(image, optional + 24u, UINT64_C(0x140000000));
    } else {
        put32(image, optional + 28u, 0x400000u);
    }
    put32(image, optional + 32u, 0x1000u);
    put32(image, optional + 36u, 0x200u);
    put32(image, optional + 56u, 0x2000u);
    put32(image, optional + 60u, 0x200u);
    put16(image, optional + 68u, 3u);
    memcpy(image + section, ".text", 5u);
    put32(image, section + 8u, 0x300u);
    put32(image, section + 12u, 0x1000u);
    put32(image, section + 16u, 0x200u);
    put32(image, section + 20u, 0x200u);
    put32(image, section + 36u, 0x60000020u);
    memcpy(image + 0x200u, code, code_size);
}

static void make_elf(
    uint8_t image[0x200], int is_64,
    uint16_t machine, const uint8_t *code, size_t code_size)
{
    uint64_t base = is_64 ? UINT64_C(0x400000) : UINT64_C(0x8048000);
    size_t program = is_64 ? 64u : 52u;

    memset(image, 0, 0x200u);
    image[0] = 0x7fu;
    image[1] = 'E';
    image[2] = 'L';
    image[3] = 'F';
    image[4] = (uint8_t)(is_64 ? 2u : 1u);
    image[5] = 1u;
    image[6] = 1u;
    put16(image, 16u, 2u);
    put16(image, 18u, machine);
    put32(image, 20u, 1u);
    if (is_64) {
        put64(image, 24u, base + 0x100u);
        put64(image, 32u, program);
        put16(image, 52u, 64u);
        put16(image, 54u, 56u);
        put16(image, 56u, 1u);
        put32(image, program, 1u);
        put32(image, program + 4u, 5u);
        put64(image, program + 16u, base);
        put64(image, program + 24u, base);
        put64(image, program + 32u, 0x100u + code_size);
        put64(image, program + 40u, 0x200u);
        put64(image, program + 48u, 0x1000u);
    } else {
        put32(image, 24u, (uint32_t)base + 0x100u);
        put32(image, 28u, (uint32_t)program);
        put16(image, 40u, 52u);
        put16(image, 42u, 32u);
        put16(image, 44u, 1u);
        put32(image, program, 1u);
        put32(image, program + 8u, (uint32_t)base);
        put32(image, program + 12u, (uint32_t)base);
        put32(image, program + 16u, (uint32_t)(0x100u + code_size));
        put32(image, program + 20u, 0x200u);
        put32(image, program + 24u, 5u);
        put32(image, program + 28u, 0x1000u);
    }
    memcpy(image + 0x100u, code, code_size);
}

static void make_macho(
    uint8_t image[0x400], int is_64,
    uint32_t cpu_type, const uint8_t *code, size_t code_size)
{
    size_t header_size = is_64 ? 32u : 28u;
    size_t segment_size = is_64 ? 72u : 56u;
    size_t pagezero = header_size;
    size_t text = pagezero + segment_size;
    size_t main_command = text + segment_size;
    uint64_t text_address = is_64
        ? UINT64_C(0x100000000) : UINT64_C(0x1000);

    memset(image, 0, 0x400u);
    put32(image, 0u, is_64 ? 0xfeedfacfu : 0xfeedfaceu);
    put32(image, 4u, cpu_type);
    put32(image, 12u, 2u);
    put32(image, 16u, 3u);
    put32(image, 20u, (uint32_t)(2u * segment_size + 24u));
    put32(image, pagezero, is_64 ? 0x19u : 1u);
    put32(image, pagezero + 4u, (uint32_t)segment_size);
    memcpy(image + pagezero + 8u, "__PAGEZERO", 10u);
    put32(image, text, is_64 ? 0x19u : 1u);
    put32(image, text + 4u, (uint32_t)segment_size);
    memcpy(image + text + 8u, "__TEXT", 6u);
    if (is_64) {
        put64(image, pagezero + 32u, text_address);
        put64(image, text + 24u, text_address);
        put64(image, text + 32u, 0x300u);
        put64(image, text + 48u, 0x200u);
        put32(image, text + 56u, 7u);
        put32(image, text + 60u, 5u);
    } else {
        put32(image, pagezero + 28u, (uint32_t)text_address);
        put32(image, text + 24u, (uint32_t)text_address);
        put32(image, text + 28u, 0x300u);
        put32(image, text + 36u, 0x200u);
        put32(image, text + 40u, 7u);
        put32(image, text + 44u, 5u);
    }
    put32(image, main_command, 0x80000028u);
    put32(image, main_command + 4u, 24u);
    put64(image, main_command + 8u, 0x100u);
    memcpy(image + 0x100u, code, code_size);
}

static int test_pe_formats(void)
{
    static const uint8_t x86_code[] = {0xccu};
    static const uint8_t t32_code[] = {0x00u, 0xbeu};
    static const uint8_t a64_code[] = {0x00u, 0x00u, 0x20u, 0xd4u};
    uint8_t image[0x400];
    uint8_t zero = 0xffu;
    xxemul_status status;
    xxemul_x86_state state;
    xxemul *emulator;
    FILE *file;

    make_pe(image, 0, 0x014cu, x86_code, sizeof(x86_code));
    emulator = xxemul_create_image(XXEMUL_IMAGE_PE32,
        image, sizeof(image), &status);
    CHECK(emulator != NULL && status == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_mode(emulator) == XXEMUL_MODE_X86_32);
    CHECK(xxemul_get_region_address(emulator) == 0x400000u);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK(state.ip == 0x401000u);
    CHECK(xxemul_read_memory(emulator, 0x401250u, &zero, 1u)
        == XXEMUL_STATUS_OK && zero == 0u);
    CHECK(xxemul_run(emulator, 2u, NULL) == XXEMUL_STATUS_HALTED);
    xxemul_destroy(emulator);
    file = fopen("xxemul_test_pe32.bin", "wb");
    CHECK(file != NULL);
    CHECK(fwrite(image, 1u, sizeof(image), file) == sizeof(image));
    CHECK(fclose(file) == 0);
    emulator = xxemul_create_image_file(
        XXEMUL_IMAGE_PE32, "xxemul_test_pe32.bin", &status);
    CHECK(emulator != NULL && status == XXEMUL_STATUS_OK);
    CHECK(xxemul_run(emulator, 2u, NULL) == XXEMUL_STATUS_HALTED);
    xxemul_destroy(emulator);
    CHECK(remove("xxemul_test_pe32.bin") == 0);
    CHECK(xxemul_create_image(XXEMUL_IMAGE_PE64,
        image, sizeof(image), &status) == NULL);
    CHECK(status == XXEMUL_STATUS_INVALID_IMAGE);

    make_pe(image, 1, 0x8664u, x86_code, sizeof(x86_code));
    emulator = xxemul_create_image(XXEMUL_IMAGE_PE64,
        image, sizeof(image), &status);
    CHECK(emulator != NULL && status == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_mode(emulator) == XXEMUL_MODE_X86_64);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK(state.ip == UINT64_C(0x140001000));
    CHECK(xxemul_run(emulator, 2u, NULL) == XXEMUL_STATUS_HALTED);
    xxemul_destroy(emulator);

    make_pe(image, 0, 0x01c2u, t32_code, sizeof(t32_code));
    emulator = xxemul_create_image(XXEMUL_IMAGE_PE32,
        image, sizeof(image), &status);
    CHECK(emulator != NULL && status == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_mode(emulator) == XXEMUL_MODE_ARM_T32);
    CHECK(xxemul_run(emulator, 2u, NULL) == XXEMUL_STATUS_HALTED);
    xxemul_destroy(emulator);

    make_pe(image, 0, 0x01c4u, t32_code, sizeof(t32_code));
    emulator = xxemul_create_image(XXEMUL_IMAGE_PE32,
        image, sizeof(image), &status);
    CHECK(emulator != NULL && status == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_mode(emulator) == XXEMUL_MODE_ARM_T32);
    CHECK(xxemul_run(emulator, 2u, NULL) == XXEMUL_STATUS_HALTED);
    xxemul_destroy(emulator);

    make_pe(image, 1, 0xaa64u, a64_code, sizeof(a64_code));
    emulator = xxemul_create_image(XXEMUL_IMAGE_PE64,
        image, sizeof(image), &status);
    CHECK(emulator != NULL && status == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_mode(emulator) == XXEMUL_MODE_ARM_A64);
    CHECK(xxemul_run(emulator, 2u, NULL) == XXEMUL_STATUS_HALTED);
    xxemul_destroy(emulator);

    make_pe(image, 0, 0x014cu, x86_code, sizeof(x86_code));
    put32(image, 0x178u + 20u, 0x400u);
    CHECK(xxemul_create_image(XXEMUL_IMAGE_PE32,
        image, sizeof(image), &status) == NULL);
    CHECK(status == XXEMUL_STATUS_INVALID_IMAGE);
    return 1;
}

static int test_elf_formats(void)
{
    static const uint8_t x86_code[] = {0xccu};
    static const uint8_t a32_code[] = {0x70u, 0x00u, 0x20u, 0xe1u};
    static const uint8_t a64_code[] = {0x00u, 0x00u, 0x20u, 0xd4u};
    uint8_t image[0x200];
    uint8_t zero = 0xffu;
    xxemul_status status;
    xxemul *emulator;

    make_elf(image, 0, 3u, x86_code, sizeof(x86_code));
    emulator = xxemul_create_image(XXEMUL_IMAGE_ELF32,
        image, sizeof(image), &status);
    CHECK(emulator != NULL && status == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_mode(emulator) == XXEMUL_MODE_X86_32);
    CHECK(xxemul_get_region_address(emulator) == 0x8048000u);
    CHECK(xxemul_read_memory(emulator, 0x8048180u, &zero, 1u)
        == XXEMUL_STATUS_OK && zero == 0u);
    CHECK(xxemul_run(emulator, 2u, NULL) == XXEMUL_STATUS_HALTED);
    xxemul_destroy(emulator);

    make_elf(image, 1, 62u, x86_code, sizeof(x86_code));
    emulator = xxemul_create_image(XXEMUL_IMAGE_ELF64,
        image, sizeof(image), &status);
    CHECK(emulator != NULL && status == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_mode(emulator) == XXEMUL_MODE_X86_64);
    CHECK(xxemul_run(emulator, 2u, NULL) == XXEMUL_STATUS_HALTED);
    xxemul_destroy(emulator);

    make_elf(image, 0, 40u, a32_code, sizeof(a32_code));
    emulator = xxemul_create_image(XXEMUL_IMAGE_ELF32,
        image, sizeof(image), &status);
    CHECK(emulator != NULL && status == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_mode(emulator) == XXEMUL_MODE_ARM_A32);
    CHECK(xxemul_run(emulator, 2u, NULL) == XXEMUL_STATUS_HALTED);
    xxemul_destroy(emulator);

    make_elf(image, 1, 183u, a64_code, sizeof(a64_code));
    emulator = xxemul_create_image(XXEMUL_IMAGE_ELF64,
        image, sizeof(image), &status);
    CHECK(emulator != NULL && status == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_mode(emulator) == XXEMUL_MODE_ARM_A64);
    CHECK(xxemul_run(emulator, 2u, NULL) == XXEMUL_STATUS_HALTED);
    xxemul_destroy(emulator);

    make_elf(image, 0, 3u, x86_code, sizeof(x86_code));
    put16(image, 16u, 3u);
    CHECK(xxemul_create_image(XXEMUL_IMAGE_ELF32,
        image, sizeof(image), &status) == NULL);
    CHECK(status == XXEMUL_STATUS_UNSUPPORTED_IMAGE);
    return 1;
}

static int test_macho_formats(void)
{
    static const uint8_t x86_code[] = {0xccu};
    static const uint8_t a32_code[] = {0x70u, 0x00u, 0x20u, 0xe1u};
    static const uint8_t a64_code[] = {0x00u, 0x00u, 0x20u, 0xd4u};
    uint8_t image[0x400];
    uint8_t zero = 0xffu;
    xxemul_status status;
    xxemul_x86_state state;
    xxemul *emulator;

    make_macho(image, 0, 7u, x86_code, sizeof(x86_code));
    emulator = xxemul_create_image(XXEMUL_IMAGE_MACHO32,
        image, sizeof(image), &status);
    CHECK(emulator != NULL && status == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_mode(emulator) == XXEMUL_MODE_X86_32);
    CHECK(xxemul_get_region_address(emulator) == 0x1000u);
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK(state.ip == 0x1100u);
    CHECK(xxemul_read_memory(emulator, 0x1250u, &zero, 1u)
        == XXEMUL_STATUS_OK && zero == 0u);
    CHECK(xxemul_run(emulator, 2u, NULL) == XXEMUL_STATUS_HALTED);
    xxemul_destroy(emulator);
    CHECK(xxemul_create_image(XXEMUL_IMAGE_MACHO64,
        image, sizeof(image), &status) == NULL);
    CHECK(status == XXEMUL_STATUS_INVALID_IMAGE);

    make_macho(image, 1, 0x01000007u, x86_code, sizeof(x86_code));
    emulator = xxemul_create_image(XXEMUL_IMAGE_MACHO64,
        image, sizeof(image), &status);
    CHECK(emulator != NULL && status == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_mode(emulator) == XXEMUL_MODE_X86_64);
    CHECK(xxemul_get_region_address(emulator) == UINT64_C(0x100000000));
    CHECK(xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK);
    CHECK(state.ip == UINT64_C(0x100000100));
    CHECK(xxemul_run(emulator, 2u, NULL) == XXEMUL_STATUS_HALTED);
    xxemul_destroy(emulator);

    make_macho(image, 0, 12u, a32_code, sizeof(a32_code));
    emulator = xxemul_create_image(XXEMUL_IMAGE_MACHO32,
        image, sizeof(image), &status);
    CHECK(emulator != NULL && status == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_mode(emulator) == XXEMUL_MODE_ARM_A32);
    CHECK(xxemul_run(emulator, 2u, NULL) == XXEMUL_STATUS_HALTED);
    xxemul_destroy(emulator);

    make_macho(image, 1, 0x0100000cu, a64_code, sizeof(a64_code));
    emulator = xxemul_create_image(XXEMUL_IMAGE_MACHO64,
        image, sizeof(image), &status);
    CHECK(emulator != NULL && status == XXEMUL_STATUS_OK);
    CHECK(xxemul_get_mode(emulator) == XXEMUL_MODE_ARM_A64);
    CHECK(xxemul_run(emulator, 2u, NULL) == XXEMUL_STATUS_HALTED);
    xxemul_destroy(emulator);

    make_macho(image, 0, 7u, x86_code, sizeof(x86_code));
    put32(image, 28u + 2u * 56u, 0x1bu);
    CHECK(xxemul_create_image(XXEMUL_IMAGE_MACHO32,
        image, sizeof(image), &status) == NULL);
    CHECK(status == XXEMUL_STATUS_UNSUPPORTED_IMAGE);

    make_macho(image, 0, 7u, x86_code, sizeof(x86_code));
    put64(image, 28u + 2u * 56u + 8u, 0x300u);
    CHECK(xxemul_create_image(XXEMUL_IMAGE_MACHO32,
        image, sizeof(image), &status) == NULL);
    CHECK(status == XXEMUL_STATUS_INVALID_IMAGE);
    return 1;
}

int main(void)
{
    if (!test_pe_formats() || !test_elf_formats()
        || !test_macho_formats()) {
        return 1;
    }
    puts("format tests passed");
    return 0;
}
