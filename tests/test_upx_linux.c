#include "xxemul/xxemul.h"
#include "platforms/xxemul_linux.h"
#include "xxemul_internal.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uint64_t read_word(xxemul *emulator, uint64_t address, unsigned width)
{
    uint8_t bytes[8] = {0};
    uint64_t value = 0;
    unsigned index;
    if (xxemul_read_memory(emulator, address, bytes, width)
        != XXEMUL_STATUS_OK) return UINT64_MAX;
    for (index = 0; index < width; ++index)
        value |= (uint64_t)bytes[index] << (index * 8u);
    return value;
}

static int write_word(
    xxemul *emulator, uint64_t address, unsigned width, uint64_t value)
{
    uint8_t bytes[8];
    unsigned index;
    for (index = 0; index < width; ++index)
        bytes[index] = (uint8_t)(value >> (index * 8u));
    return xxemul_write_memory(emulator, address, bytes, width)
        == XXEMUL_STATUS_OK;
}

static uint8_t *read_image(const char *path, size_t *size)
{
    FILE *file = fopen(path, "rb");
    long length;
    uint8_t *image;
    if (file == NULL) return NULL;
    if (fseek(file, 0, SEEK_END) != 0 || (length = ftell(file)) <= 0
        || fseek(file, 0, SEEK_SET) != 0) {
        fclose(file);
        return NULL;
    }
    image = (uint8_t *)malloc((size_t)length);
    if (image == NULL || fread(image, 1u, (size_t)length, file)
            != (size_t)length) {
        free(image);
        fclose(file);
        return NULL;
    }
    fclose(file);
    *size = (size_t)length;
    return image;
}

static int check_image(const char *path, int is_64)
{
    static const uint8_t endbr32[] = {0xf3, 0x0f, 0x1e, 0xfb};
    static const uint8_t endbr64[] = {0xf3, 0x0f, 0x1e, 0xfa};
    const char *guest_argv[] = {path, "-o", "FASM_GUEST.EXE", "FASM.EXE"};
    xxemul_status status;
    xxemul_x86_state state = {0};
    xxemul_linux_process *process;
    xxemul *emulator;
    uint8_t actual[4] = {0};
    char argument[1024];
    uint64_t stack;
    uint64_t arg0;
    uint64_t address;
    uint64_t scratch;
    uint64_t fd;
    uint8_t mapped[4];
    unsigned width = is_64 ? 8u : 4u;
    int index;
    int ok = 0;

    emulator = xxemul_create_image_file(is_64
        ? XXEMUL_IMAGE_ELF64 : XXEMUL_IMAGE_ELF32, path, &status);
    if (emulator == NULL) {
        fprintf(stderr, "ELF load failed: %s\n", xxemul_status_string(status));
        return 0;
    }
    if (xxemul_get_x86_state(emulator, &state) != XXEMUL_STATUS_OK
        || xxemul_read_memory(emulator, state.ip, actual, sizeof(actual))
            != XXEMUL_STATUS_OK
        || memcmp(actual, is_64 ? endbr64 : endbr32, sizeof(actual)) != 0) {
        fprintf(stderr, "ELF entry mapping differs from file: %s at 0x%llx"
            " (%02x %02x %02x %02x)\n", path,
            (unsigned long long)state.ip, actual[0], actual[1],
            actual[2], actual[3]);
        goto done;
    }
    process = xxemul_linux_create(emulator, path, ".", 4, guest_argv);
    if (process == NULL) {
        fprintf(stderr, "Linux stack setup failed: %s\n", path);
        goto done;
    }
    if (xxemul_get_x86_state(emulator, &state) != XXEMUL_STATUS_OK)
        goto done_process;
    stack = state.gpr[XXEMUL_X86_RSP];
    arg0 = read_word(emulator, stack + width, width);
    if ((stack & 15u) != 0u || read_word(emulator, stack, width) != 4u
        || arg0 == UINT64_MAX || arg0 == 0u) {
        fprintf(stderr, "Linux argc/argv setup failed: %s\n", path);
        goto done_process;
    }
    for (index = 0; index < 4; ++index) {
        size_t length = strlen(guest_argv[index]) + 1u;
        uint64_t pointer = read_word(emulator,
            stack + (uint64_t)(index + 1) * width, width);
        if (pointer == UINT64_MAX || pointer == 0u
            || length > sizeof(argument)
            || xxemul_read_memory(emulator, pointer, argument, length)
                != XXEMUL_STATUS_OK
            || strcmp(argument, guest_argv[index]) != 0) {
            fprintf(stderr, "Linux argv[%d] string failed: %s\n",
                index, path);
            goto done_process;
        }
    }
    if (read_word(emulator, stack + 5u * width, width) != 0u
        || read_word(emulator, stack + 6u * width, width) != 0u) {
        fprintf(stderr, "Linux argv/env terminator failed: %s\n", path);
        goto done_process;
    }
    scratch = stack - 64u;
    if (xxemul_write_memory(emulator, scratch, "UPX!", 4u)
        != XXEMUL_STATUS_OK) goto done_process;
    state.gpr[XXEMUL_X86_RAX] = is_64 ? 319u : 356u;
    if (xxemul_set_x86_state(emulator, &state) != XXEMUL_STATUS_OK
        || xxemul_linux_dispatch(process) != XXEMUL_STATUS_OK
        || xxemul_get_x86_state(emulator, &state) != XXEMUL_STATUS_OK)
        goto done_process;
    fd = state.gpr[XXEMUL_X86_RAX];
    if (fd < 3u || fd >= 64u) goto done_process;
    state.gpr[XXEMUL_X86_RAX] = is_64 ? 1u : 4u;
    state.gpr[is_64 ? XXEMUL_X86_RDI : XXEMUL_X86_RBX] = fd;
    state.gpr[is_64 ? XXEMUL_X86_RSI : XXEMUL_X86_RCX] = scratch;
    state.gpr[XXEMUL_X86_RDX] = 4u;
    if (xxemul_set_x86_state(emulator, &state) != XXEMUL_STATUS_OK
        || xxemul_linux_dispatch(process) != XXEMUL_STATUS_OK
        || xxemul_get_x86_state(emulator, &state) != XXEMUL_STATUS_OK
        || state.gpr[XXEMUL_X86_RAX] != 4u) goto done_process;
    state.gpr[XXEMUL_X86_RAX] = is_64 ? 9u : 192u;
    state.gpr[is_64 ? XXEMUL_X86_RDI : XXEMUL_X86_RBX] = 0u;
    state.gpr[is_64 ? XXEMUL_X86_RSI : XXEMUL_X86_RCX] = 4096u;
    state.gpr[XXEMUL_X86_RDX] = 3u;
    state.gpr[is_64 ? XXEMUL_X86_R10 : XXEMUL_X86_RSI] = 1u;
    state.gpr[is_64 ? XXEMUL_X86_R8 : XXEMUL_X86_RDI] = fd;
    state.gpr[is_64 ? XXEMUL_X86_R9 : XXEMUL_X86_RBP] = 0u;
    if (xxemul_set_x86_state(emulator, &state) != XXEMUL_STATUS_OK
        || xxemul_linux_dispatch(process) != XXEMUL_STATUS_OK
        || xxemul_get_x86_state(emulator, &state) != XXEMUL_STATUS_OK)
        goto done_process;
    address = state.gpr[XXEMUL_X86_RAX];
    if (address == 0 || (int64_t)address < 0
        || xxemul_linux_mapping_read(process, address, mapped,
            sizeof(mapped)) != 1
        || memcmp(mapped, "UPX!", sizeof(mapped)) != 0) {
        fprintf(stderr, "Linux mmap failed: %s\n", path);
        goto done_process;
    }
    memcpy(mapped, "MAP!", sizeof(mapped));
    if (xxemul_linux_mapping_write(process, address, mapped,
            sizeof(mapped)) != 1) goto done_process;
    memset(mapped, 0, sizeof(mapped));
    if (xxemul_linux_mapping_read(process, address, mapped,
            sizeof(mapped)) != 1
        || memcmp(mapped, "MAP!", sizeof(mapped)) != 0) {
        fprintf(stderr, "Linux mmap failed: %s\n", path);
        goto done_process;
    }
    state.gpr[XXEMUL_X86_RAX] = is_64 ? 8u : 19u;
    state.gpr[is_64 ? XXEMUL_X86_RDI : XXEMUL_X86_RBX] = fd;
    state.gpr[is_64 ? XXEMUL_X86_RSI : XXEMUL_X86_RCX] = 0u;
    state.gpr[XXEMUL_X86_RDX] = 0u;
    if (xxemul_set_x86_state(emulator, &state) != XXEMUL_STATUS_OK
        || xxemul_linux_dispatch(process) != XXEMUL_STATUS_OK
        || xxemul_get_x86_state(emulator, &state) != XXEMUL_STATUS_OK
        || state.gpr[XXEMUL_X86_RAX] != 0u) goto done_process;
    state.gpr[XXEMUL_X86_RAX] = is_64 ? 0u : 3u;
    state.gpr[is_64 ? XXEMUL_X86_RDI : XXEMUL_X86_RBX] = fd;
    state.gpr[is_64 ? XXEMUL_X86_RSI : XXEMUL_X86_RCX] = scratch;
    state.gpr[XXEMUL_X86_RDX] = 4u;
    if (xxemul_set_x86_state(emulator, &state) != XXEMUL_STATUS_OK
        || xxemul_linux_dispatch(process) != XXEMUL_STATUS_OK
        || xxemul_get_x86_state(emulator, &state) != XXEMUL_STATUS_OK
        || state.gpr[XXEMUL_X86_RAX] != 4u
        || xxemul_read_memory(emulator, scratch, mapped, sizeof(mapped))
            != XXEMUL_STATUS_OK
        || memcmp(mapped, "MAP!", sizeof(mapped)) != 0) {
        fprintf(stderr, "Linux shared mapping alias failed: %s\n", path);
        goto done_process;
    }
    state.gpr[XXEMUL_X86_RAX] = is_64 ? 60u : 1u;
    state.gpr[is_64 ? XXEMUL_X86_RDI : XXEMUL_X86_RBX] = 7u;
    if (xxemul_set_x86_state(emulator, &state) != XXEMUL_STATUS_OK
        || xxemul_linux_dispatch(process) != XXEMUL_STATUS_HALTED
        || !xxemul_linux_has_exited(process)
        || xxemul_linux_exit_code(process) != 7) {
        fprintf(stderr, "Linux exit failed: %s\n", path);
        goto done_process;
    }
    ok = 1;
done_process:
    xxemul_linux_destroy(process);
done:
    xxemul_destroy(emulator);
    return ok;
}

static int check_exec_handoff_image(
    const char *path, int is_64,
    const uint8_t *image, size_t image_size, int from_file)
{
    static const char *const arguments[] = {
        "upx", "-o", "PACKED.EXE", "FASM.EXE"
    };
    xxemul_image_format format = is_64
        ? XXEMUL_IMAGE_ELF64 : XXEMUL_IMAGE_ELF32;
    xxemul_status status;
    xxemul_x86_state state;
    xxemul *emulator = NULL;
    xxemul *successor = NULL;
    xxemul_linux_process *process = NULL;
    const uint8_t *replacement;
    size_t replacement_size = 0;
    uint64_t stack, scratch, fd, mapped, next_stack, pointer;
    unsigned width = is_64 ? 8u : 4u;
    char fd_path[64];
    char value[32];
    int index;
    int ok = 0;

    if (image == NULL || image_size == 0u) goto done;
    emulator = xxemul_create_image(format, image, image_size, &status);
    if (emulator == NULL) goto done;
    if (from_file) {
        if (xxemul_start_process(emulator, format, path, ".", 1, &path)
                != XXEMUL_STATUS_OK) goto done;
    } else {
        emulator->linux_process = xxemul_linux_create_image(emulator,
            image, image_size, path, ".", 1, &path, 0, NULL);
        if (emulator->linux_process == NULL) goto done;
    }
    process = emulator->linux_process;
    if (process == NULL || xxemul_get_x86_state(emulator, &state)
            != XXEMUL_STATUS_OK) goto done;
    stack = state.gpr[XXEMUL_X86_RSP];
    scratch = stack - 4096u;

    state.gpr[XXEMUL_X86_RAX] = is_64 ? 319u : 356u;
    if (xxemul_set_x86_state(emulator, &state) != XXEMUL_STATUS_OK
        || xxemul_linux_dispatch(process) != XXEMUL_STATUS_OK
        || xxemul_get_x86_state(emulator, &state) != XXEMUL_STATUS_OK)
        goto done;
    fd = state.gpr[XXEMUL_X86_RAX];
    if (fd < 3u || fd >= 64u) goto done;

    state.gpr[XXEMUL_X86_RAX] = is_64 ? 77u : 93u;
    state.gpr[is_64 ? XXEMUL_X86_RDI : XXEMUL_X86_RBX] = fd;
    state.gpr[is_64 ? XXEMUL_X86_RSI : XXEMUL_X86_RCX] = image_size;
    if (xxemul_set_x86_state(emulator, &state) != XXEMUL_STATUS_OK
        || xxemul_linux_dispatch(process) != XXEMUL_STATUS_OK
        || xxemul_get_x86_state(emulator, &state) != XXEMUL_STATUS_OK
        || state.gpr[XXEMUL_X86_RAX] != 0u) goto done;

    state.gpr[XXEMUL_X86_RAX] = is_64 ? 9u : 192u;
    state.gpr[is_64 ? XXEMUL_X86_RDI : XXEMUL_X86_RBX] = 0u;
    state.gpr[is_64 ? XXEMUL_X86_RSI : XXEMUL_X86_RCX] = image_size;
    state.gpr[XXEMUL_X86_RDX] = 3u;
    state.gpr[is_64 ? XXEMUL_X86_R10 : XXEMUL_X86_RSI] = 1u;
    state.gpr[is_64 ? XXEMUL_X86_R8 : XXEMUL_X86_RDI] = fd;
    state.gpr[is_64 ? XXEMUL_X86_R9 : XXEMUL_X86_RBP] = 0u;
    if (xxemul_set_x86_state(emulator, &state) != XXEMUL_STATUS_OK
        || xxemul_linux_dispatch(process) != XXEMUL_STATUS_OK
        || xxemul_get_x86_state(emulator, &state) != XXEMUL_STATUS_OK)
        goto done;
    mapped = state.gpr[XXEMUL_X86_RAX];
    if (mapped == 0u || (int64_t)mapped < 0
        || xxemul_linux_mapping_write(process, mapped, image,
            image_size) != 1) goto done;

    snprintf(fd_path, sizeof(fd_path), "/proc/self/fd/%llu",
        (unsigned long long)fd);
    if (xxemul_write_memory(emulator, scratch,
            is_64 ? "" : fd_path,
            is_64 ? 1u : strlen(fd_path) + 1u) != XXEMUL_STATUS_OK)
        goto done;
    for (index = 0; index < 4; ++index) {
        uint64_t string_address = scratch + 128u + (uint64_t)index * 32u;
        if (xxemul_write_memory(emulator, string_address,
                arguments[index], strlen(arguments[index]) + 1u)
                != XXEMUL_STATUS_OK
            || !write_word(emulator, scratch + 512u + (uint64_t)index * width,
                width, string_address)) goto done;
    }
    if (xxemul_write_memory(emulator, scratch + 320u,
            "UPX_TEST=1", 11u) != XXEMUL_STATUS_OK
        || !write_word(emulator, scratch + 512u + 4u * width, width, 0u)
        || !write_word(emulator, scratch + 640u, width, scratch + 320u)
        || !write_word(emulator, scratch + 640u + width, width, 0u))
        goto done;

    state.gpr[XXEMUL_X86_RAX] = is_64 ? 322u : 11u;
    state.gpr[is_64 ? XXEMUL_X86_RDI : XXEMUL_X86_RBX] = is_64
        ? fd : scratch;
    state.gpr[is_64 ? XXEMUL_X86_RSI : XXEMUL_X86_RCX] = is_64
        ? scratch : UINT32_MAX;
    state.gpr[XXEMUL_X86_RDX] = is_64 ? UINT64_MAX : scratch + 640u;
    state.gpr[XXEMUL_X86_R10] = scratch + 640u;
    state.gpr[XXEMUL_X86_R8] = 0x1000u;
    if (xxemul_set_x86_state(emulator, &state) != XXEMUL_STATUS_OK
        || xxemul_linux_dispatch(process) != XXEMUL_STATUS_OK
        || xxemul_get_x86_state(emulator, &state) != XXEMUL_STATUS_OK
        || (int32_t)state.gpr[XXEMUL_X86_RAX] != -14
        || xxemul_linux_has_exited(process)) {
        fprintf(stderr, "invalid exec arguments were accepted: %s\n", path);
        goto done;
    }
    {
        xxemul_status rejected_status;
        xxemul *unexpected = xxemul_create_exec_successor(
            emulator, &rejected_status);
        if (unexpected != NULL
            || rejected_status != XXEMUL_STATUS_INVALID_ARGUMENT) {
            xxemul_destroy(unexpected);
            fprintf(stderr, "failed exec left a successor: %s\n", path);
            goto done;
        }
    }

    state.gpr[XXEMUL_X86_RAX] = is_64 ? 322u : 11u;
    state.gpr[is_64 ? XXEMUL_X86_RSI : XXEMUL_X86_RCX] = is_64
        ? scratch : scratch + 512u;
    state.gpr[XXEMUL_X86_RDX] = is_64
        ? scratch + 512u : scratch + 640u;
    if (xxemul_set_x86_state(emulator, &state) != XXEMUL_STATUS_OK
        || xxemul_linux_dispatch(process) != XXEMUL_STATUS_HALTED)
        goto done;
    replacement = xxemul_linux_exec_image(process, &replacement_size);
    if (replacement == NULL || replacement_size != image_size
        || memcmp(replacement, image, image_size) != 0
        || strcmp(xxemul_linux_exec_path(process),
            is_64 ? "" : fd_path) != 0
        || xxemul_linux_exec_is_at(process) != is_64
        || xxemul_linux_exec_dirfd(process) != (is_64 ? (int)fd : -1)
        || xxemul_linux_exec_flags(process) != (is_64 ? 0x1000u : 0u)
        || xxemul_linux_exec_argc(process) != 4u
        || xxemul_linux_exec_envc(process) != 1u
        || strcmp(xxemul_linux_working_directory(process), ".") != 0
        || strcmp(xxemul_linux_exec_environment(process, 0),
            "UPX_TEST=1") != 0) {
        fprintf(stderr, "exec handoff record failed: %s\n", path);
        goto done;
    }
    for (index = 0; index < 4; ++index) {
        const char *argument = xxemul_linux_exec_argument(process,
            (size_t)index);
        if (argument == NULL || strcmp(argument, arguments[index]) != 0)
            goto done;
    }
    successor = xxemul_create_exec_successor(emulator, &status);
    if (successor == NULL || status != XXEMUL_STATUS_OK
        || successor->linux_process == NULL
        || strcmp(xxemul_linux_working_directory(
            successor->linux_process), ".") != 0
        || xxemul_get_x86_state(successor, &state) != XXEMUL_STATUS_OK)
        goto done;
    next_stack = state.gpr[XXEMUL_X86_RSP];
    pointer = read_word(successor, next_stack + width, width);
    if (read_word(successor, next_stack, width) != 4u
        || pointer == UINT64_MAX
        || xxemul_read_memory(successor, pointer, value, 4u)
            != XXEMUL_STATUS_OK || strcmp(value, "upx") != 0)
        goto done;
    pointer = read_word(successor, next_stack + 6u * width, width);
    if (pointer == UINT64_MAX
        || xxemul_read_memory(successor, pointer, value, 11u)
            != XXEMUL_STATUS_OK
        || strcmp(value, "UPX_TEST=1") != 0) goto done;
    for (index = 0; index < 17; ++index) {
        uint64_t entry = next_stack + (8u + (uint64_t)index * 2u) * width;
        if (read_word(successor, entry, width) == 31u) {
            const char *expected = is_64 ? "upx" : fd_path;
            pointer = read_word(successor, entry + width, width);
            if (pointer == UINT64_MAX
                || xxemul_read_memory(successor, pointer, value,
                    strlen(expected) + 1u) != XXEMUL_STATUS_OK
                || strcmp(value, expected) != 0) goto done;
            break;
        }
    }
    if (index == 17) goto done;
    ok = 1;
done:
    if (!ok) fprintf(stderr, "Linux successor test failed: %s\n", path);
    xxemul_destroy(successor);
    xxemul_destroy(emulator);
    return ok;
}

static int check_exec_handoff(const char *path, int is_64)
{
    size_t size = 0;
    uint8_t *image = read_image(path, &size);
    int ok = check_exec_handoff_image(path, is_64, image, size, 1);
    free(image);
    return ok;
}

static void put_le(uint8_t *data, size_t offset,
    uint64_t value, unsigned width)
{
    unsigned index;
    for (index = 0; index < width; ++index)
        data[offset + index] = (uint8_t)(value >> (8u * index));
}

static int check_synthetic_handoff(int is_64)
{
    uint8_t image[256] = {0};
    uint64_t base = is_64 ? UINT64_C(0x400000) : UINT64_C(0x8048000);
    size_t ph = is_64 ? 64u : 52u;
    memcpy(image, "\177ELF", 4u);
    image[4] = is_64 ? 2u : 1u;
    image[5] = 1u;
    image[6] = 1u;
    put_le(image, 16u, 2u, 2u);
    put_le(image, 18u, is_64 ? 62u : 3u, 2u);
    put_le(image, 20u, 1u, 4u);
    put_le(image, 24u, base + 128u, is_64 ? 8u : 4u);
    put_le(image, is_64 ? 32u : 28u, ph, is_64 ? 8u : 4u);
    put_le(image, is_64 ? 52u : 40u, ph, 2u);
    put_le(image, is_64 ? 54u : 42u, is_64 ? 56u : 32u, 2u);
    put_le(image, is_64 ? 56u : 44u, 1u, 2u);
    put_le(image, ph, 1u, 4u);
    if (is_64) {
        put_le(image, ph + 4u, 5u, 4u);
        put_le(image, ph + 16u, base, 8u);
        put_le(image, ph + 32u, sizeof(image), 8u);
        put_le(image, ph + 40u, 4096u, 8u);
        put_le(image, ph + 48u, 4096u, 8u);
    } else {
        put_le(image, ph + 8u, base, 4u);
        put_le(image, ph + 16u, sizeof(image), 4u);
        put_le(image, ph + 20u, 4096u, 4u);
        put_le(image, ph + 24u, 5u, 4u);
        put_le(image, ph + 28u, 4096u, 4u);
    }
    image[128] = 0x90u;
    return check_exec_handoff_image("synthetic-upx", is_64,
        image, sizeof(image), 0);
}

int main(int argc, char **argv)
{
    if (argc == 1) {
        if (!check_synthetic_handoff(0)
            || !check_synthetic_handoff(1)) return 1;
        puts("Linux synthetic exec handoff tests passed");
        return 0;
    }
    if (argc != 3) {
        fprintf(stderr, "usage: test_upx_linux <i386-upx> <amd64-upx>\n");
        return 2;
    }
    if (!check_image(argv[1], 0) || !check_image(argv[2], 1)
        || !check_exec_handoff(argv[1], 0)
        || !check_exec_handoff(argv[2], 1)) return 1;
    puts("UPX ELF mapping and Linux process handoff tests passed");
    return 0;
}
