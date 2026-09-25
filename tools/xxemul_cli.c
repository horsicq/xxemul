#include "xxemul/xxemul.h"
#include "../src/platforms/xxemul_windows.h"

#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int parse_mode(
    const char *text,
    xxemul_arch *arch,
    xxemul_mode *mode)
{
    if (strcmp(text, "x86-16") == 0) {
        *arch = XXEMUL_ARCH_X86;
        *mode = XXEMUL_MODE_X86_16;
    } else if (strcmp(text, "x86-32") == 0) {
        *arch = XXEMUL_ARCH_X86;
        *mode = XXEMUL_MODE_X86_32;
    } else if (strcmp(text, "x86-64") == 0) {
        *arch = XXEMUL_ARCH_X86;
        *mode = XXEMUL_MODE_X86_64;
    } else if (strcmp(text, "arm-a32") == 0) {
        *arch = XXEMUL_ARCH_ARM;
        *mode = XXEMUL_MODE_ARM_A32;
    } else if (strcmp(text, "arm-t32") == 0) {
        *arch = XXEMUL_ARCH_ARM;
        *mode = XXEMUL_MODE_ARM_T32;
    } else if (strcmp(text, "arm-a64") == 0) {
        *arch = XXEMUL_ARCH_ARM;
        *mode = XXEMUL_MODE_ARM_A64;
    } else {
        return 0;
    }
    return 1;
}

static uint64_t current_pc(xxemul *emulator, xxemul_arch arch)
{
    if (arch == XXEMUL_ARCH_X86) {
        xxemul_x86_state state;
        if (xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK) {
            return state.ip;
        }
    } else {
        xxemul_arm_state state;
        if (xxemul_get_arm_state(emulator, &state) == XXEMUL_STATUS_OK) {
            return state.pc;
        }
    }
    return UINT64_C(0);
}

static int parse_image_format(
    const char *text, xxemul_image_format *format)
{
    static const struct {
        const char *name;
        xxemul_image_format format;
    } formats[] = {
        {"com", XXEMUL_IMAGE_COM},
        {"mz", XXEMUL_IMAGE_MZ},
        {"pe32", XXEMUL_IMAGE_PE32},
        {"pe64", XXEMUL_IMAGE_PE64},
        {"elf32", XXEMUL_IMAGE_ELF32},
        {"elf64", XXEMUL_IMAGE_ELF64},
        {"macho32", XXEMUL_IMAGE_MACHO32},
        {"macho64", XXEMUL_IMAGE_MACHO64}
    };
    size_t index;

    for (index = 0u; index < sizeof(formats) / sizeof(formats[0]); ++index) {
        if (strcmp(text, formats[index].name) == 0) {
            *format = formats[index].format;
            return 1;
        }
    }
    return 0;
}

static void dos_output(void *context, uint8_t byte)
{
    fputc(byte, (FILE *)context);
}

static xxemul_status set_guest_environment_assignment(
    xxemul *emulator, const char *assignment)
{
    const char *separator = strchr(assignment, '=');
    size_t name_length;
    char *name;
    xxemul_status status;

    if (separator == NULL || separator == assignment)
        return XXEMUL_STATUS_INVALID_ARGUMENT;
    name_length = (size_t)(separator - assignment);
    name = (char *)malloc(name_length + 1u);
    if (name == NULL) return XXEMUL_STATUS_OUT_OF_MEMORY;
    memcpy(name, assignment, name_length);
    name[name_length] = '\0';
    status = xxemul_set_guest_environment(emulator, name, separator + 1);
    free(name);
    return status;
}

static int run_dos(int argc, char **argv)
{
    xxemul_image_format format;
    xxemul_status status;
    xxemul_x86_state state;
    xxemul *emulator;
    uint64_t limit = UINT64_C(1000000);
    uint64_t executed = 0u;
    uint8_t exit_code = 0u;
    char *end;

    if ((argc != 4 && argc != 5)
        || !parse_image_format(argc >= 3 ? argv[2] : "", &format)
        || (format != XXEMUL_IMAGE_COM && format != XXEMUL_IMAGE_MZ)) {
        fprintf(stderr,
            "usage: %s --dos <com|mz> <file> [instruction-limit]\n",
            argv[0]);
        return 1;
    }
    if (argc == 5) {
        errno = 0;
        limit = strtoull(argv[4], &end, 0);
        if (errno != 0 || argv[4][0] == '\0' || argv[4][0] == '-'
            || *end != '\0' || limit == 0u) {
            fprintf(stderr, "invalid instruction limit: %s\n", argv[4]);
            return 1;
        }
    }
    emulator = xxemul_create_image_file(format, argv[3], &status);
    if (emulator == NULL) {
        fprintf(stderr, "load failed: %s\n", xxemul_status_string(status));
        return 1;
    }
    xxemul_dos_set_output_callback(emulator, dos_output, stdout);
    status = xxemul_run(emulator, limit, &executed);
    fflush(stdout);
    if (status == XXEMUL_STATUS_HALTED) {
        xxemul_dos_get_exit_code(emulator, &exit_code);
        xxemul_destroy(emulator);
        return exit_code;
    }
    if (xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK) {
        fprintf(stderr,
            "xxemul stopped: %s after %" PRIu64
            " instructions at %04x:%04x\n",
            xxemul_status_string(status), executed,
            state.segment[XXEMUL_X86_CS], (unsigned)(uint16_t)state.ip);
    } else {
        fprintf(stderr, "xxemul stopped: %s after %" PRIu64
            " instructions\n", xxemul_status_string(status), executed);
    }
    xxemul_destroy(emulator);
    return 2;
}

static int run_image(int argc, char **argv)
{
    xxemul_image_format format;
    xxemul_status status;
    xxemul_step_info info;
    xxemul *emulator;
    char text[256];
    char *end;
    uint64_t limit = 100u;
    uint64_t index;

    if ((argc != 4 && argc != 5)
        || !parse_image_format(argc >= 3 ? argv[2] : "", &format)) {
        fprintf(stderr,
            "usage: %s --image <com|mz|pe32|pe64|elf32|elf64|macho32|macho64> "
            "<file> [instruction-limit]\n", argv[0]);
        return 1;
    }
    if (argc == 5) {
        errno = 0;
        limit = strtoull(argv[4], &end, 0);
        if (errno != 0 || argv[4][0] == '\0' || *end != '\0'
            || limit == 0u) {
            fprintf(stderr, "invalid instruction limit: %s\n", argv[4]);
            return 1;
        }
    }
    emulator = xxemul_create_image_file(format, argv[3], &status);
    if (emulator == NULL) {
        fprintf(stderr, "load failed: %s\n", xxemul_status_string(status));
        return 1;
    }
    for (index = 0u; index < limit; ++index) {
        uint64_t pc = current_pc(emulator, xxemul_get_arch(emulator));
        size_t length = xxemul_format_current(emulator, text, sizeof(text));

        if ((format == XXEMUL_IMAGE_COM || format == XXEMUL_IMAGE_MZ)
            && xxemul_get_mode(emulator) == XXEMUL_MODE_X86_16) {
            xxemul_x86_state state;
            if (xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK) {
                pc = xxemul_dos_linear(
                    state.segment[XXEMUL_X86_CS], (uint16_t)state.ip);
            }
        }
        printf("%016" PRIx64 "  %s\n", pc,
            length == 0u ? "<decode error>" : text);
        status = xxemul_step(emulator, &info);
        if (status != XXEMUL_STATUS_OK) {
            printf("stop: %s at 0x%016" PRIx64 "\n",
                xxemul_status_string(status), info.address);
            xxemul_destroy(emulator);
            return status == XXEMUL_STATUS_HALTED ? 0 : 2;
        }
    }
    printf("stop: instruction limit reached\n");
    xxemul_destroy(emulator);
    return 0;
}

static int run_image_quiet(int argc, char **argv)
{
    xxemul_image_format format;
    xxemul_status status;
    xxemul *emulator;
    uint64_t limit = UINT64_C(1000000);
    uint64_t executed = 0u;
    uint64_t trace_after = UINT64_MAX;
    uint64_t dump_address = 0u;
    size_t dump_length = 0u;
    unsigned exec_transitions = 0u;
    uint64_t pc;
    char text[256];
    char *end;
    const char *workdir = ".";
    const char **guest_argv = NULL;
    int guest_count = 1;
    int option_index = 4;
    int first_option_index;
    int last_option_index;
    int guest_index;
    int env_index;

    if (argc < 4
        || !parse_image_format(argc >= 3 ? argv[2] : "", &format)) {
        fprintf(stderr, "usage: %s --run <format> <file> [instruction-limit] [--workdir <directory>] [--env NAME=VALUE]... [-- guest-args...]\n", argv[0]);
        return 1;
    }
    if (option_index < argc && argv[option_index][0] != '-') {
        errno = 0;
        limit = strtoull(argv[option_index], &end, 0);
        if (errno != 0 || argv[option_index][0] == '\0'
            || *end != '\0' || limit == 0u) {
            fprintf(stderr, "invalid instruction limit: %s\n", argv[option_index]);
            return 1;
        }
        ++option_index;
    }
    first_option_index = option_index;
    while (option_index < argc) {
        if (option_index + 1 < argc
            && strcmp(argv[option_index], "--workdir") == 0) {
            workdir = argv[option_index + 1];
            option_index += 2;
        } else if (option_index + 1 < argc
            && strcmp(argv[option_index], "--trace-after") == 0) {
            errno = 0;
            trace_after = strtoull(argv[option_index + 1], &end, 0);
            if (errno != 0 || argv[option_index + 1][0] == '\0'
                || argv[option_index + 1][0] == '-'
                || *end != '\0') {
                fprintf(stderr, "invalid trace start: %s\n",
                    argv[option_index + 1]);
                return 1;
            }
            option_index += 2;
        } else if (option_index + 2 < argc
            && strcmp(argv[option_index], "--dump-strings") == 0) {
            unsigned long long parsed_length;
            errno = 0;
            dump_address = strtoull(argv[option_index + 1], &end, 0);
            if (errno != 0 || argv[option_index + 1][0] == '\0'
                || *end != '\0') {
                fprintf(stderr, "invalid dump address\n");
                return 1;
            }
            errno = 0;
            parsed_length = strtoull(argv[option_index + 2], &end, 0);
            if (errno != 0 || argv[option_index + 2][0] == '\0'
                || *end != '\0' || parsed_length == 0u
                || parsed_length > 65536u) {
                fprintf(stderr, "invalid dump length\n");
                return 1;
            }
            dump_length = (size_t)parsed_length;
            option_index += 3;
        } else if (strcmp(argv[option_index], "--env") == 0) {
            const char *assignment;
            const char *separator;
            if (option_index + 1 >= argc) {
                fprintf(stderr, "missing NAME=VALUE after --env\n");
                return 1;
            }
            assignment = argv[option_index + 1];
            separator = strchr(assignment, '=');
            if (separator == NULL || separator == assignment) {
                fprintf(stderr, "invalid guest environment assignment; expected NAME=VALUE\n");
                return 1;
            }
            option_index += 2;
        } else {
            break;
        }
    }
    last_option_index = option_index;
    if (option_index < argc) {
        if (strcmp(argv[option_index], "--") != 0) {
            fprintf(stderr, "unexpected argument: %s\n", argv[option_index]);
            return 1;
        }
        ++option_index;
    }
    guest_count += argc - option_index;
    guest_argv = (const char **)malloc((size_t)guest_count * sizeof(*guest_argv));
    if (guest_argv == NULL) {
        fprintf(stderr, "out of memory\n");
        return 1;
    }
    guest_argv[0] = argv[3];
    for (guest_index = 1; guest_index < guest_count; ++guest_index)
        guest_argv[guest_index] = argv[option_index + guest_index - 1];
    emulator = xxemul_create_image_file(format, argv[3], &status);
    if (emulator == NULL) {
        fprintf(stderr, "load failed: %s\n", xxemul_status_string(status));
        free(guest_argv);
        return 2;
    }
    if (format == XXEMUL_IMAGE_PE32 || format == XXEMUL_IMAGE_PE64
        || format == XXEMUL_IMAGE_ELF32 || format == XXEMUL_IMAGE_ELF64
        || format == XXEMUL_IMAGE_COM || format == XXEMUL_IMAGE_MZ) {
        status = xxemul_start_process(emulator, format, argv[3], workdir,
            guest_count, guest_argv);
        if (status != XXEMUL_STATUS_OK) {
            fprintf(stderr, "process start failed: %s\n",
                xxemul_status_string(status));
            free(guest_argv);
            xxemul_destroy(emulator);
            return 2;
        }
    }
    free(guest_argv);
    for (env_index = first_option_index; env_index < last_option_index;) {
        if (strcmp(argv[env_index], "--env") == 0) {
            status = set_guest_environment_assignment(
                emulator, argv[env_index + 1]);
            if (status != XXEMUL_STATUS_OK) {
                fprintf(stderr, "guest environment failed: %s\n",
                    xxemul_status_string(status));
                xxemul_destroy(emulator);
                return 2;
            }
            env_index += 2;
        } else if (strcmp(argv[env_index], "--dump-strings") == 0) {
            env_index += 3;
        } else {
            env_index += 2;
        }
    }
    if ((format == XXEMUL_IMAGE_COM || format == XXEMUL_IMAGE_MZ)
        && xxemul_get_mode(emulator) == XXEMUL_MODE_X86_16) {
        xxemul_dos_set_output_callback(emulator, dos_output, stdout);
    }
    for (;;) {
        if (trace_after == UINT64_MAX) {
            uint64_t stage_executed = 0u;
            status = xxemul_run(emulator, limit - executed, &stage_executed);
            executed += stage_executed;
        } else {
            xxemul_step_info info;
            status = XXEMUL_STATUS_LIMIT_REACHED;
            while (executed < limit) {
            if (executed >= trace_after) {
                xxemul_x86_state before;
                uint64_t trace_pc = current_pc(emulator,
                    xxemul_get_arch(emulator));
                if (xxemul_format_current(emulator, text,
                    sizeof(text)) == 0u)
                    strcpy(text, "<api/decode error>");
                printf("%" PRIu64 "  %016" PRIx64 "  %s", executed,
                    trace_pc, text);
                if (format == XXEMUL_IMAGE_PE32
                    || format == XXEMUL_IMAGE_PE64) {
                    const char *api = xxemul_windows_thunk_name(
                        emulator, trace_pc);
                    if (api != NULL) printf(" API=%s", api);
                }
                if (xxemul_get_x86_state(emulator, &before)
                    == XXEMUL_STATUS_OK) {
                    printf("  ax=%08" PRIx64 " bx=%08" PRIx64
                        " cx=%08" PRIx64 " dx=%08" PRIx64
                        " si=%08" PRIx64 " di=%08" PRIx64
                        " bp=%08" PRIx64 " sp=%08" PRIx64
                        " cs=%04x ds=%04x es=%04x ss=%04x"
                        " flags=%08" PRIx64,
                        before.gpr[XXEMUL_X86_RAX],
                        before.gpr[XXEMUL_X86_RBX],
                        before.gpr[XXEMUL_X86_RCX],
                        before.gpr[XXEMUL_X86_RDX],
                        before.gpr[XXEMUL_X86_RSI],
                        before.gpr[XXEMUL_X86_RDI],
                        before.gpr[XXEMUL_X86_RBP],
                        before.gpr[XXEMUL_X86_RSP],
                        before.segment[XXEMUL_X86_CS],
                        before.segment[XXEMUL_X86_DS],
                        before.segment[XXEMUL_X86_ES],
                        before.segment[XXEMUL_X86_SS], before.flags);
                    if ((format == XXEMUL_IMAGE_PE32
                            || format == XXEMUL_IMAGE_PE64)
                        && strstr(text, "int3") != NULL) {
                        uint8_t pointer_bytes[4];
                        uint64_t pointer = before.gpr[XXEMUL_X86_RDX];
                        char name[80];
                        size_t i;
                        if (format == XXEMUL_IMAGE_PE64
                            || xxemul_read_memory(emulator,
                            before.gpr[XXEMUL_X86_RSP] + 8u,
                            pointer_bytes, sizeof(pointer_bytes))
                            == XXEMUL_STATUS_OK) {
                            if (format == XXEMUL_IMAGE_PE32)
                                pointer = (uint32_t)pointer_bytes[0]
                                    | ((uint32_t)pointer_bytes[1] << 8u)
                                    | ((uint32_t)pointer_bytes[2] << 16u)
                                    | ((uint32_t)pointer_bytes[3] << 24u);
                            for (i = 0u; i + 1u < sizeof(name); ++i) {
                                uint8_t ch;
                                if (xxemul_read_memory(emulator,
                                    pointer + i, &ch, 1u)
                                    != XXEMUL_STATUS_OK
                                    || (ch != 0u && (ch < 32u || ch > 126u)))
                                    break;
                                name[i] = (char)ch;
                                if (ch == 0u) {
                                    printf("  arg2=\"%s\"", name);
                                    break;
                                }
                            }
                        }
                    }
                }
                fputc('\n', stdout);
            }
                status = xxemul_step(emulator, &info);
                if (status == XXEMUL_STATUS_OK
                    || (status == XXEMUL_STATUS_HALTED && info.size != 0u))
                    ++executed;
                if (status != XXEMUL_STATUS_OK) break;
            }
            if (executed == limit && status == XXEMUL_STATUS_OK)
                status = XXEMUL_STATUS_LIMIT_REACHED;
        }
        if (status == XXEMUL_STATUS_HALTED
            && (format == XXEMUL_IMAGE_ELF32
                || format == XXEMUL_IMAGE_ELF64)
            && executed < limit && exec_transitions < 8u) {
            xxemul_status next_status;
            xxemul *next = xxemul_create_exec_successor(
                emulator, &next_status);
            if (next != NULL) {
                xxemul_destroy(emulator);
                emulator = next;
                ++exec_transitions;
                printf("exec transition %u at instruction %" PRIu64 "\n",
                    exec_transitions, executed);
                continue;
            }
            if (next_status != XXEMUL_STATUS_INVALID_ARGUMENT)
                status = next_status;
        }
        break;
    }
    pc = current_pc(emulator, xxemul_get_arch(emulator));
    if (format == XXEMUL_IMAGE_COM || format == XXEMUL_IMAGE_MZ) {
        xxemul_x86_state state;
        if (xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK) {
            pc = xxemul_dos_linear(state.segment[XXEMUL_X86_CS],
                (uint16_t)state.ip);
        }
    }
    if (xxemul_format_current(emulator, text, sizeof(text)) == 0u) {
        strcpy(text, "<decode error>");
    }
    printf("\nstop: %s after %" PRIu64 " instructions at 0x%016" PRIx64
           " (%s)\n", xxemul_status_string(status), executed, pc, text);
    if (format == XXEMUL_IMAGE_PE32 || format == XXEMUL_IMAGE_PE64) {
        const char *api = xxemul_windows_thunk_name(emulator, pc);
        if (api != NULL) printf("Windows API: %s\n", api);
    }
    if (status == XXEMUL_STATUS_DECODE_ERROR) {
        uint8_t bytes[15];
        size_t count;
        size_t index;
        for (count = sizeof(bytes); count > 0u; --count) {
            if (xxemul_read_memory(emulator, pc, bytes, count)
                == XXEMUL_STATUS_OK) break;
        }
        if (count != 0u) {
            fputs("bytes:", stdout);
            for (index = 0u; index < count; ++index)
                printf(" %02x", bytes[index]);
            fputc('\n', stdout);
        }
    }
    if (dump_length != 0u) {
        char printable[256];
        size_t length = 0u;
        size_t i;
        uint64_t start = 0u;
        for (i = 0u; i <= dump_length; ++i) {
            uint8_t byte = 0u;
            int valid = i < dump_length
                && xxemul_read_memory(emulator, dump_address + i,
                    &byte, 1u) == XXEMUL_STATUS_OK;
            if (valid && byte >= 32u && byte <= 126u
                && length + 1u < sizeof(printable)) {
                if (length == 0u) start = dump_address + i;
                printable[length++] = (char)byte;
            } else {
                if (length >= 4u) {
                    printable[length] = '\0';
                    printf("string %016" PRIx64 " %s\n", start, printable);
                }
                length = 0u;
            }
        }
    }
    if (xxemul_get_arch(emulator) == XXEMUL_ARCH_X86) {
        xxemul_x86_state state;
        if (xxemul_get_x86_state(emulator, &state) == XXEMUL_STATUS_OK) {
            printf("x86: ax=%016" PRIx64 " bx=%016" PRIx64
                   " cx=%016" PRIx64 " dx=%016" PRIx64
                   " si=%016" PRIx64 " di=%016" PRIx64
                   " sp=%016" PRIx64 " flags=%016" PRIx64
                   " cs=%04x ds=%04x es=%04x ss=%04x\n",
                state.gpr[XXEMUL_X86_RAX], state.gpr[XXEMUL_X86_RBX],
                state.gpr[XXEMUL_X86_RCX], state.gpr[XXEMUL_X86_RDX],
                state.gpr[XXEMUL_X86_RSI], state.gpr[XXEMUL_X86_RDI],
                state.gpr[XXEMUL_X86_RSP], state.flags,
                state.segment[XXEMUL_X86_CS], state.segment[XXEMUL_X86_DS],
                state.segment[XXEMUL_X86_ES], state.segment[XXEMUL_X86_SS]);
        }
    }
    if (status == XXEMUL_STATUS_HALTED
        && (format == XXEMUL_IMAGE_COM || format == XXEMUL_IMAGE_MZ)) {
        uint8_t exit_code = 0u;
        xxemul_dos_get_exit_code(emulator, &exit_code);
        printf("DOS exit code: %u\n", (unsigned)exit_code);
    }
    if (status == XXEMUL_STATUS_HALTED
        && format != XXEMUL_IMAGE_COM && format != XXEMUL_IMAGE_MZ)
        printf("process exit code: %d\n", xxemul_process_exit_code(emulator));
    xxemul_destroy(emulator);
    return status == XXEMUL_STATUS_HALTED ? 0
        : status == XXEMUL_STATUS_LIMIT_REACHED ? 3 : 2;
}

int main(int argc, char **argv)
{
    xxemul_config config;
    xxemul_status status;
    xxemul_step_info info;
    xxemul *emulator;
    uint8_t *code;
    uint64_t base;
    char *end;
    char text[256];
    unsigned long byte_value;
    int index;
    int exit_code = 0;

    if (argc >= 2 && strcmp(argv[1], "--image") == 0) {
        return run_image(argc, argv);
    }
    if (argc >= 2 && strcmp(argv[1], "--run") == 0) {
        return run_image_quiet(argc, argv);
    }
    if (argc >= 2 && strcmp(argv[1], "--dos") == 0) {
        return run_dos(argc, argv);
    }

    if (argc < 4) {
        fprintf(stderr,
            "usage: %s <x86-16|x86-32|x86-64|arm-a32|arm-t32|arm-a64> "
            "<base-address> <hex-byte> [hex-byte ...]\n"
            "       %s --image <com|mz|pe32|pe64|elf32|elf64|macho32|macho64> "
            "<file> [instruction-limit]\n"
            "       %s --run <com|mz|pe32|pe64|elf32|elf64|macho32|macho64> "
            "<file> [instruction-limit] [--env NAME=VALUE]... [-- guest-args...]\n"
            "       %s --dos <com|mz> <file> [instruction-limit]\n",
            argv[0],
            argv[0],
            argv[0],
            argv[0]);
        return 1;
    }
    memset(&config, 0, sizeof(config));
    if (!parse_mode(argv[1], &config.arch, &config.mode)) {
        fprintf(stderr, "unknown mode: %s\n", argv[1]);
        return 1;
    }
    errno = 0;
    base = strtoull(argv[2], &end, 0);
    if (errno != 0 || *argv[2] == '\0' || *end != '\0') {
        fprintf(stderr, "invalid base address: %s\n", argv[2]);
        return 1;
    }

    config.code_size = (size_t)(argc - 3);
    code = (uint8_t *)malloc(config.code_size);
    if (code == NULL) {
        fprintf(stderr, "out of memory\n");
        return 1;
    }
    for (index = 3; index < argc; ++index) {
        errno = 0;
        byte_value = strtoul(argv[index], &end, 16);
        if (errno != 0 || *argv[index] == '\0' || *end != '\0'
            || byte_value > 0xffu) {
            fprintf(stderr, "invalid byte: %s\n", argv[index]);
            free(code);
            return 1;
        }
        code[index - 3] = (uint8_t)byte_value;
    }

    config.region_address = base;
    config.entry_address = base;
    config.code = code;
    config.region_size = config.code_size + 4096u;
    emulator = xxemul_create(&config, &status);
    free(code);
    if (emulator == NULL) {
        fprintf(stderr, "create failed: %s\n", xxemul_status_string(status));
        return 1;
    }

    for (index = 0; index < 100; ++index) {
        uint64_t pc = current_pc(emulator, config.arch);
        size_t length = xxemul_format_current(emulator, text, sizeof(text));
        printf("%016" PRIx64 "  %s\n", pc,
            length == 0u ? "<decode error>" : text);
        status = xxemul_step(emulator, &info);
        if (status != XXEMUL_STATUS_OK) {
            printf("stop: %s at 0x%016" PRIx64 "\n",
                xxemul_status_string(status), info.address);
            if (status != XXEMUL_STATUS_HALTED) {
                exit_code = 2;
            }
            break;
        }
    }
    if (index == 100) {
        printf("stop: instruction limit reached\n");
    }
    xxemul_destroy(emulator);
    return exit_code;
}
