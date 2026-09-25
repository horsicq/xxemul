#include "xxemul_internal.h"
#include "platforms/xxemul_windows.h"
#include "platforms/xxemul_linux.h"
#include "platforms/xxemul_dos_files.h"

#include <limits.h>
#include <stdlib.h>
#include <string.h>

static void xxemul_linux_output_bridge(
    void *context, int descriptor, const void *bytes, size_t size)
{
    xxemul_emit_output((xxemul *)context, descriptor, bytes, size);
}

int xxemul_emit_output(xxemul *emulator, int stream,
    const void *bytes, size_t size)
{
    if (emulator == NULL || emulator->stream_output == NULL) return 0;
    emulator->stream_output(emulator->stream_output_context,
        stream, bytes, size);
    return 1;
}

static int xxemul_mode_matches_arch(xxemul_arch arch, xxemul_mode mode)
{
    if (arch == XXEMUL_ARCH_X86) {
        return mode == XXEMUL_MODE_X86_16
            || mode == XXEMUL_MODE_X86_32
            || mode == XXEMUL_MODE_X86_64;
    }
    if (arch == XXEMUL_ARCH_ARM) {
        return mode == XXEMUL_MODE_ARM_A32
            || mode == XXEMUL_MODE_ARM_T32
            || mode == XXEMUL_MODE_ARM_A64;
    }
    return 0;
}

static int xxemul_region_contains(
    const xxemul *emulator,
    uint64_t address,
    size_t size,
    size_t *offset)
{
    uint64_t relative;

    if (emulator == NULL || address < emulator->region_address) {
        return 0;
    }
    relative = address - emulator->region_address;
    if (relative > (uint64_t)emulator->region_size) {
        return 0;
    }
    if (size > emulator->region_size - (size_t)relative) {
        return 0;
    }
    if (offset != NULL) {
        *offset = (size_t)relative;
    }
    return 1;
}

static int xxemul_config_addressable(const xxemul_config *config)
{
    uint64_t last_address;

    if (config->region_size == 0
        || (uint64_t)(config->region_size - 1) > UINT64_MAX - config->region_address) {
        return 0;
    }
    last_address = config->region_address + (uint64_t)(config->region_size - 1);
    if ((config->mode == XXEMUL_MODE_X86_16 && last_address > UINT16_MAX)
        || ((config->mode == XXEMUL_MODE_X86_32
             || config->mode == XXEMUL_MODE_ARM_A32
             || config->mode == XXEMUL_MODE_ARM_T32)
            && last_address > UINT32_MAX)) {
        return 0;
    }
    return config->entry_address >= config->region_address
        && config->entry_address <= last_address;
}

xxemul *xxemul_create_empty(
    xxemul_arch arch, xxemul_mode mode,
    uint64_t region_address, size_t region_size,
    xxemul_status *status)
{
    xxemul *emulator;

    emulator = (xxemul *)xx_mem_calloc(1, sizeof(*emulator));
    if (emulator == NULL) {
        if (status != NULL) {
            *status = XXEMUL_STATUS_OUT_OF_MEMORY;
        }
        return NULL;
    }
    emulator->region_data = (uint8_t *)xx_mem_calloc(1, region_size);
    if (emulator->region_data == NULL) {
        xx_mem_free(emulator);
        if (status != NULL) {
            *status = XXEMUL_STATUS_OUT_OF_MEMORY;
        }
        return NULL;
    }
    emulator->arch = arch;
    emulator->mode = mode;
    if (arch == XXEMUL_ARCH_X86) {
        cdisasm_x86_mode decode_mode = mode == XXEMUL_MODE_X86_16
            ? CDISASM_X86_MODE_16
            : mode == XXEMUL_MODE_X86_32
                ? CDISASM_X86_MODE_32 : CDISASM_X86_MODE_64;
        if (cdisasm_x86_cpu_decode_flag_mask(
                CDISASM_CPU_X86, decode_mode,
                &emulator->x86_decode_flags) != CDISASM_STATUS_OK) {
            xx_mem_free(emulator->region_data);
            xx_mem_free(emulator);
            if (status != NULL) *status = XXEMUL_STATUS_INVALID_ARGUMENT;
            return NULL;
        }
    }
    emulator->region_address = region_address;
    emulator->region_size = region_size;
    emulator->video_mode = 3u;
    emulator->text_attribute = 7u;
    emulator->x87_control = 0x037fu;
    if (status != NULL) {
        *status = XXEMUL_STATUS_OK;
    }
    return emulator;
}

xxemul *xxemul_create(const xxemul_config *config, xxemul_status *status)
{
    xxemul *emulator;
    size_t stack_alignment;
    uint64_t stack_top;

    if (status != NULL) {
        *status = XXEMUL_STATUS_INVALID_ARGUMENT;
    }
    if (config == NULL
        || !xxemul_mode_matches_arch(config->arch, config->mode)
        || config->code == NULL
        || config->code_size == 0
        || config->region_size < config->code_size
        || config->region_size > (size_t)LONG_MAX
        || !xxemul_config_addressable(config)) {
        return NULL;
    }
    if ((config->mode == XXEMUL_MODE_ARM_A32
         || config->mode == XXEMUL_MODE_ARM_A64)
        && (config->entry_address & UINT64_C(3)) != 0) {
        return NULL;
    }
    if (config->mode == XXEMUL_MODE_ARM_T32
        && (config->entry_address & UINT64_C(1)) != 0) {
        return NULL;
    }
    emulator = xxemul_create_empty(
        config->arch, config->mode, config->region_address,
        config->region_size, status);
    if (emulator == NULL) {
        return NULL;
    }
    xx_mem_copy(emulator->region_data, config->code, config->code_size);

    stack_alignment = config->arch == XXEMUL_ARCH_ARM ? 16u
        : (config->mode == XXEMUL_MODE_X86_16 ? 2u
           : (config->mode == XXEMUL_MODE_X86_32 ? 4u : 8u));
    stack_top = config->region_address + (uint64_t)config->region_size;
    stack_top &= ~((uint64_t)stack_alignment - UINT64_C(1));

    if (config->arch == XXEMUL_ARCH_X86) {
        emulator->x86.ip = config->entry_address;
        emulator->x86.flags = UINT64_C(2);
        emulator->x86.gpr[XXEMUL_X86_RSP] = stack_top;
    } else {
        emulator->arm.pc = config->entry_address;
        emulator->arm.sp = stack_top;
    }

    if (status != NULL) {
        *status = XXEMUL_STATUS_OK;
    }
    return emulator;
}

void xxemul_destroy(xxemul *emulator)
{
    if (emulator == NULL) {
        return;
    }
    xxemul_windows_destroy(emulator->windows);
    xxemul_linux_destroy(emulator->linux_process);
    xxemul_dos_files_stop(emulator);
    xx_mem_free(emulator->x86_decode_cache);
    xx_mem_free(emulator->region_data);
    xx_mem_free(emulator);
}

xxemul_status xxemul_start_process(
    xxemul *emulator, xxemul_image_format format,
    const char *program_path, const char *working_directory,
    int argc, const char *const *argv)
{
    xxemul_status status = XXEMUL_STATUS_INVALID_ARGUMENT;

    if (emulator == NULL || program_path == NULL || working_directory == NULL
        || argc < 0 || (argc > 0 && argv == NULL)
        || emulator->windows != NULL || emulator->linux_process != NULL) {
        return status;
    }
    if (format == XXEMUL_IMAGE_PE32 || format == XXEMUL_IMAGE_PE64) {
        size_t skip = argc > 0 ? 1u : 0u;
        emulator->windows = xxemul_windows_create(
            emulator, program_path, working_directory,
            argv == NULL ? NULL : argv + skip, (size_t)argc - skip, &status);
        return emulator->windows == NULL ? status : XXEMUL_STATUS_OK;
    }
    if (format == XXEMUL_IMAGE_ELF32 || format == XXEMUL_IMAGE_ELF64) {
        emulator->linux_process = xxemul_linux_create(
            emulator, program_path, working_directory, argc, argv);
        if (emulator->linux_process == NULL)
            return XXEMUL_STATUS_INVALID_IMAGE;
        xxemul_linux_set_output(emulator->linux_process,
            xxemul_linux_output_bridge, emulator);
        return XXEMUL_STATUS_OK;
    }
    if (format == XXEMUL_IMAGE_COM || format == XXEMUL_IMAGE_MZ) {
        const char *basename = program_path;
        const char *cursor;
        for (cursor = program_path; *cursor != '\0'; ++cursor) {
            if (*cursor == '/' || *cursor == '\\') basename = cursor + 1;
        }
        return xxemul_dos_files_start(emulator, working_directory,
            basename, (size_t)argc - (argc > 0 ? 1u : 0u),
            argc > 0 ? argv + 1 : NULL);
    }
    return XXEMUL_STATUS_UNSUPPORTED_IMAGE;
}

xxemul_status xxemul_set_guest_environment(
    xxemul *emulator, const char *name, const char *value)
{
    if (emulator == NULL || name == NULL || name[0] == '\0'
        || strchr(name, '=') != NULL || value == NULL) {
        return XXEMUL_STATUS_INVALID_ARGUMENT;
    }
    if (emulator->windows == NULL) {
        return XXEMUL_STATUS_UNSUPPORTED_IMAGE;
    }
    return xxemul_windows_set_environment(emulator->windows, name, value);
}

int xxemul_process_exit_code(const xxemul *emulator)
{
    if (emulator == NULL) return -1;
    if (emulator->windows != NULL)
        return (int)xxemul_windows_exit_code(emulator->windows);
    if (emulator->linux_process != NULL)
        return xxemul_linux_exit_code(emulator->linux_process);
    if (emulator->dos_mode) return (int)emulator->exit_code;
    return -1;
}

xxemul *xxemul_create_exec_successor(
    xxemul *emulator, xxemul_status *status)
{
    xxemul_linux_process *previous;
    const uint8_t *image;
    const char *path;
    const char **argv = NULL;
    const char **envp = NULL;
    xxemul *successor = NULL;
    xxemul_image_format format;
    size_t image_size = 0u;
    size_t argc;
    size_t envc;
    size_t index;

    if (status != NULL) *status = XXEMUL_STATUS_INVALID_ARGUMENT;
    if (emulator == NULL || emulator->linux_process == NULL) return NULL;
    previous = emulator->linux_process;
    image = xxemul_linux_exec_image(previous, &image_size);
    if (image == NULL || image_size < 5u
        || image[0] != 0x7fu || image[1] != 'E' || image[2] != 'L'
        || image[3] != 'F') return NULL;
    format = image[4] == 1u ? XXEMUL_IMAGE_ELF32
        : image[4] == 2u ? XXEMUL_IMAGE_ELF64 : 0u;
    if (format == 0u) return NULL;
    argc = xxemul_linux_exec_argc(previous);
    envc = xxemul_linux_exec_envc(previous);
    if (argc > INT_MAX || envc > INT_MAX) return NULL;
    argv = (const char **)calloc(argc == 0u ? 1u : argc, sizeof(*argv));
    envp = (const char **)calloc(envc == 0u ? 1u : envc, sizeof(*envp));
    if (argv == NULL || envp == NULL) {
        if (status != NULL) *status = XXEMUL_STATUS_OUT_OF_MEMORY;
        goto done;
    }
    for (index = 0u; index < argc; ++index)
        argv[index] = xxemul_linux_exec_argument(previous, index);
    for (index = 0u; index < envc; ++index)
        envp[index] = xxemul_linux_exec_environment(previous, index);
    path = xxemul_linux_exec_path(previous);
    if (path == NULL || *path == '\0')
        path = argc == 0u ? "upx" : argv[0];
    successor = xxemul_create_image(format, image, image_size, status);
    if (successor == NULL) goto done;
    successor->linux_process = xxemul_linux_create_image(
        successor, image, image_size, path,
        xxemul_linux_working_directory(previous),
        (int)argc, argv, (int)envc, envp);
    if (successor->linux_process != NULL) {
        successor->stream_output = emulator->stream_output;
        successor->stream_output_context = emulator->stream_output_context;
        successor->memory_hook = emulator->memory_hook;
        successor->memory_hook_context = emulator->memory_hook_context;
        successor->debug_traps = emulator->debug_traps;
        xxemul_linux_set_output(successor->linux_process,
            xxemul_linux_output_bridge, successor);
    }
    if (successor->linux_process == NULL) {
        xxemul_destroy(successor);
        successor = NULL;
        if (status != NULL) *status = XXEMUL_STATUS_INVALID_IMAGE;
    } else if (status != NULL) {
        *status = XXEMUL_STATUS_OK;
    }
done:
    free(argv);
    free(envp);
    return successor;
}

xxemul_arch xxemul_get_arch(const xxemul *emulator)
{
    return emulator == NULL ? UINT32_C(0) : emulator->arch;
}

xxemul_mode xxemul_get_mode(const xxemul *emulator)
{
    return emulator == NULL ? UINT32_C(0) : emulator->mode;
}

uint64_t xxemul_get_region_address(const xxemul *emulator)
{
    return emulator == NULL ? UINT64_C(0) : emulator->region_address;
}

size_t xxemul_get_region_size(const xxemul *emulator)
{
    return emulator == NULL ? 0 : emulator->region_size;
}

xxemul_status xxemul_read_memory(
    xxemul *emulator,
    uint64_t address,
    void *buffer,
    size_t size)
{
    size_t offset;
    int mapped;

    if (size == 0) {
        return emulator == NULL ? XXEMUL_STATUS_INVALID_ARGUMENT
            : XXEMUL_STATUS_OK;
    }
    if (emulator != NULL && buffer != NULL && emulator->linux_process != NULL) {
        mapped = xxemul_linux_mapping_read(
            emulator->linux_process, address, buffer, size);
        if (mapped != 0) return mapped > 0
            ? XXEMUL_STATUS_OK : XXEMUL_STATUS_ADDRESS_FAULT;
    }
    if (buffer == NULL || !xxemul_region_contains(emulator, address, size, &offset)) {
        return buffer == NULL ? XXEMUL_STATUS_INVALID_ARGUMENT
            : XXEMUL_STATUS_ADDRESS_FAULT;
    }
    xx_mem_copy(buffer, emulator->region_data + offset, size);
    return XXEMUL_STATUS_OK;
}

xxemul_status xxemul_write_memory(
    xxemul *emulator,
    uint64_t address,
    const void *buffer,
    size_t size)
{
    size_t offset;
    int mapped;

    if (size == 0) {
        return emulator == NULL ? XXEMUL_STATUS_INVALID_ARGUMENT
            : XXEMUL_STATUS_OK;
    }
    if (emulator != NULL && buffer != NULL && emulator->linux_process != NULL) {
        mapped = xxemul_linux_mapping_write(
            emulator->linux_process, address, buffer, size);
        if (mapped != 0) return mapped > 0
            ? XXEMUL_STATUS_OK : XXEMUL_STATUS_ADDRESS_FAULT;
    }
    if (buffer == NULL || !xxemul_region_contains(emulator, address, size, &offset)) {
        return buffer == NULL ? XXEMUL_STATUS_INVALID_ARGUMENT
            : XXEMUL_STATUS_ADDRESS_FAULT;
    }
    xx_mem_copy(emulator->region_data + offset, buffer, size);
    return XXEMUL_STATUS_OK;
}

uint64_t xxemul_mask_for_size(uint8_t size)
{
    if (size >= 8u) {
        return UINT64_MAX;
    }
    if (size == 0u) {
        return UINT64_C(0);
    }
    return (UINT64_C(1) << (size * 8u)) - UINT64_C(1);
}

uint64_t xxemul_sign_extend(uint64_t value, uint8_t size)
{
    uint64_t mask;
    uint64_t sign;

    if (size == 0u || size >= 8u) {
        return value;
    }
    mask = xxemul_mask_for_size(size);
    sign = UINT64_C(1) << (size * 8u - 1u);
    value &= mask;
    return (value ^ sign) - sign;
}

xxemul_status xxemul_load_integer(
    xxemul *emulator,
    uint64_t address,
    uint8_t size,
    uint64_t *value)
{
    uint8_t bytes[8];
    uint64_t result = UINT64_C(0);
    uint8_t index;
    xxemul_status status;

    if (value == NULL || size == 0u || size > sizeof(bytes)) {
        return XXEMUL_STATUS_INVALID_ARGUMENT;
    }
    status = xxemul_read_memory(emulator, address, bytes, size);
    if (status != XXEMUL_STATUS_OK) {
        return status;
    }
    for (index = 0; index < size; ++index) {
        result |= (uint64_t)bytes[index] << (index * 8u);
    }
    *value = result;
    return XXEMUL_STATUS_OK;
}

xxemul_status xxemul_store_integer(
    xxemul *emulator,
    uint64_t address,
    uint8_t size,
    uint64_t value)
{
    uint8_t bytes[8];
    uint8_t index;

    if (size == 0u || size > sizeof(bytes)) {
        return XXEMUL_STATUS_INVALID_ARGUMENT;
    }
    for (index = 0; index < size; ++index) {
        bytes[index] = (uint8_t)(value >> (index * 8u));
    }
    return xxemul_write_memory(emulator, address, bytes, size);
}

xxemul_status xxemul_get_x86_state(
    const xxemul *emulator,
    xxemul_x86_state *state)
{
    if (emulator == NULL || state == NULL || emulator->arch != XXEMUL_ARCH_X86) {
        return XXEMUL_STATUS_INVALID_ARGUMENT;
    }
    *state = emulator->x86;
    return XXEMUL_STATUS_OK;
}

xxemul_status xxemul_set_x86_state(
    xxemul *emulator,
    const xxemul_x86_state *state)
{
    if (emulator == NULL || state == NULL || emulator->arch != XXEMUL_ARCH_X86) {
        return XXEMUL_STATUS_INVALID_ARGUMENT;
    }
    emulator->x86 = *state;
    emulator->x86.flags |= UINT64_C(2);
    emulator->halted = 0;
    return XXEMUL_STATUS_OK;
}

xxemul_status xxemul_get_arm_state(
    const xxemul *emulator,
    xxemul_arm_state *state)
{
    if (emulator == NULL || state == NULL || emulator->arch != XXEMUL_ARCH_ARM) {
        return XXEMUL_STATUS_INVALID_ARGUMENT;
    }
    *state = emulator->arm;
    return XXEMUL_STATUS_OK;
}

xxemul_status xxemul_set_arm_state(
    xxemul *emulator,
    const xxemul_arm_state *state)
{
    if (emulator == NULL || state == NULL || emulator->arch != XXEMUL_ARCH_ARM) {
        return XXEMUL_STATUS_INVALID_ARGUMENT;
    }
    emulator->arm = *state;
    emulator->halted = 0;
    return XXEMUL_STATUS_OK;
}

static xxemul_status xxemul_step_inner(
    xxemul *emulator, xxemul_step_info *info);

xxemul_status xxemul_step(xxemul *emulator, xxemul_step_info *info)
{
    xxemul_status status;

    if (emulator == NULL) {
        return XXEMUL_STATUS_INVALID_ARGUMENT;
    }
    emulator->in_step = 1;
    status = xxemul_step_inner(emulator, info);
    emulator->in_step = 0;
    emulator->x86_fetching = 0;
    return status;
}

static xxemul_status xxemul_step_inner(
    xxemul *emulator, xxemul_step_info *info)
{
    xxemul_status status;
    if (emulator == NULL) {
        return XXEMUL_STATUS_INVALID_ARGUMENT;
    }
    if (info != NULL) {
        xx_mem_zero(info, sizeof(*info));
    }
    if (emulator->halted) {
        return XXEMUL_STATUS_HALTED;
    }
    if (emulator->arch == XXEMUL_ARCH_X86) {
        uint64_t fault_ip;
        if (emulator->windows != NULL
            && xxemul_windows_try_step(emulator->windows, info, &status)) {
            if (status == XXEMUL_STATUS_HALTED) emulator->halted = 1;
            return status;
        }
        fault_ip = emulator->x86.ip;
        status = xxemul_x86_step(emulator, info);
        if (status == XXEMUL_STATUS_ADDRESS_FAULT && emulator->dos_mode) {
            return xxemul_x86_dispatch_pending_page_fault(
                emulator, info, fault_ip);
        }
        return status;
    }
    return xxemul_arm_step(emulator, info);
}

xxemul_status xxemul_run(
    xxemul *emulator,
    uint64_t instruction_limit,
    uint64_t *instructions_executed)
{
    uint64_t executed = UINT64_C(0);
    xxemul_step_info info;
    xxemul_status status;

    if (emulator == NULL || instruction_limit == 0) {
        return XXEMUL_STATUS_INVALID_ARGUMENT;
    }
    while (executed < instruction_limit) {
        status = xxemul_step(emulator, &info);
        if (status == XXEMUL_STATUS_OK ||
            (status == XXEMUL_STATUS_HALTED && info.size != 0u)) {
            ++executed;
        }
        if (status != XXEMUL_STATUS_OK) {
            if (instructions_executed != NULL) {
                *instructions_executed = executed;
            }
            return status;
        }
    }
    if (instructions_executed != NULL) {
        *instructions_executed = executed;
    }
    return XXEMUL_STATUS_LIMIT_REACHED;
}

size_t xxemul_format_current(
    xxemul *emulator,
    char *buffer,
    size_t buffer_size)
{
    if (buffer != NULL && buffer_size > 0) {
        buffer[0] = '\0';
    }
    if (emulator == NULL || emulator->halted) {
        return 0;
    }
    if (emulator->arch == XXEMUL_ARCH_X86) {
        return xxemul_x86_format_current(emulator, buffer, buffer_size);
    }
    return xxemul_arm_format_current(emulator, buffer, buffer_size);
}

const char *xxemul_status_string(xxemul_status status)
{
    switch (status) {
    case XXEMUL_STATUS_OK:
        return "ok";
    case XXEMUL_STATUS_HALTED:
        return "halted";
    case XXEMUL_STATUS_LIMIT_REACHED:
        return "instruction limit reached";
    case XXEMUL_STATUS_INVALID_ARGUMENT:
        return "invalid argument";
    case XXEMUL_STATUS_OUT_OF_MEMORY:
        return "out of memory";
    case XXEMUL_STATUS_ADDRESS_FAULT:
        return "address fault";
    case XXEMUL_STATUS_DECODE_ERROR:
        return "decode error";
    case XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION:
        return "unsupported instruction";
    case XXEMUL_STATUS_IO_ERROR:
        return "I/O error";
    case XXEMUL_STATUS_INVALID_IMAGE:
        return "invalid executable image";
    case XXEMUL_STATUS_INPUT_REQUIRED:
        return "keyboard input required";
    case XXEMUL_STATUS_UNSUPPORTED_IMAGE:
        return "unsupported executable image";
    case XXEMUL_STATUS_BREAKPOINT:
        return "breakpoint";
    default:
        return "unknown status";
    }
}

xxemul_status xxemul_set_output_callback(
    xxemul *emulator, xxemul_output_callback callback, void *context)
{
    if (emulator == NULL) return XXEMUL_STATUS_INVALID_ARGUMENT;
    emulator->stream_output = callback;
    emulator->stream_output_context = context;
    return XXEMUL_STATUS_OK;
}

xxemul_status xxemul_set_memory_hook(
    xxemul *emulator, xxemul_memory_hook hook, void *context)
{
    if (emulator == NULL) return XXEMUL_STATUS_INVALID_ARGUMENT;
    emulator->memory_hook = hook;
    emulator->memory_hook_context = context;
    return XXEMUL_STATUS_OK;
}

xxemul_status xxemul_set_debug_traps(xxemul *emulator, int enabled)
{
    if (emulator == NULL) return XXEMUL_STATUS_INVALID_ARGUMENT;
    emulator->debug_traps = enabled != 0;
    return XXEMUL_STATUS_OK;
}

xxemul_status xxemul_x86_linear_address(
    const xxemul *emulator, unsigned segment_index, uint64_t offset,
    uint64_t *address)
{
    if (emulator == NULL || address == NULL
        || emulator->arch != XXEMUL_ARCH_X86
        || segment_index >= XXEMUL_X86_SEGMENT_COUNT) {
        return XXEMUL_STATUS_INVALID_ARGUMENT;
    }
    if (emulator->dos_mode) {
        if (emulator->dos_segments[segment_index].valid) {
            *address = (uint64_t)emulator->dos_segments[segment_index].base
                + (offset & UINT32_MAX);
        } else {
            *address = xxemul_dos_physical(emulator,
                emulator->x86.segment[segment_index], (uint16_t)offset);
        }
        return XXEMUL_STATUS_OK;
    }
    *address = offset;
    return XXEMUL_STATUS_OK;
}

xxemul_status xxemul_get_current_address(
    const xxemul *emulator, uint64_t *address)
{
    if (emulator == NULL || address == NULL) {
        return XXEMUL_STATUS_INVALID_ARGUMENT;
    }
    if (emulator->arch == XXEMUL_ARCH_ARM) {
        *address = emulator->arm.pc;
        return XXEMUL_STATUS_OK;
    }
    return xxemul_x86_linear_address(
        emulator, XXEMUL_X86_CS, emulator->x86.ip, address);
}

int xxemul_is_halted(const xxemul *emulator)
{
    return emulator == NULL || emulator->halted;
}

const char *xxemul_symbol_name(const xxemul *emulator, uint64_t address)
{
    if (emulator == NULL || emulator->windows == NULL) return NULL;
    return xxemul_windows_thunk_name(emulator, address);
}
