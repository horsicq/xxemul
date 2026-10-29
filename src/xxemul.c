#include "xxemul_internal.h"
#include "platforms/xxemul_windows.h"
#include "platforms/xxemul_linux.h"
#include "platforms/xxemul_darwin.h"
#include "platforms/xxemul_dos_files.h"

#include <limits.h>
#include <stdlib.h>
#include <string.h>

static void xxemul_linux_output_bridge(void *context, int descriptor, const void *bytes, size_t size)
{
    xxemul_emit_output((xxemul *)context, descriptor, bytes, size);
}

int xxemul_emit_output(xxemul *emulator, int stream, const void *bytes, size_t size)
{
    if (emulator == NULL || emulator->stream_output == NULL) return 0;
    emulator->stream_output(emulator->stream_output_context, stream, bytes, size);
    return 1;
}

static int xxemul_mode_matches_arch(xxemul_arch arch, xxemul_mode mode)
{
    if (arch == XXEMUL_ARCH_X86) {
        return mode == XXEMUL_MODE_X86_16 || mode == XXEMUL_MODE_X86_32 || mode == XXEMUL_MODE_X86_64;
    }
    if (arch == XXEMUL_ARCH_ARM) {
        return mode == XXEMUL_MODE_ARM_A32 || mode == XXEMUL_MODE_ARM_T32 || mode == XXEMUL_MODE_ARM_A64;
    }
    if (arch == XXEMUL_ARCH_MIPS) return mode == XXEMUL_MODE_MIPS32 || mode == XXEMUL_MODE_MIPS32_BE;
    return 0;
}

static int xxemul_region_contains(const xxemul *emulator, uint64_t address, size_t size, size_t *offset)
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

    if (config->region_size == 0 || (uint64_t)(config->region_size - 1) > UINT64_MAX - config->region_address) {
        return 0;
    }
    last_address = config->region_address + (uint64_t)(config->region_size - 1);
    if ((config->mode == XXEMUL_MODE_X86_16 && last_address > UINT16_MAX) ||
        ((config->mode == XXEMUL_MODE_X86_32 || config->mode == XXEMUL_MODE_ARM_A32 || config->mode == XXEMUL_MODE_ARM_T32 ||
          config->arch == XXEMUL_ARCH_MIPS) && last_address > UINT32_MAX)) {
        return 0;
    }
    return config->entry_address >= config->region_address && config->entry_address <= last_address;
}

xxemul *xxemul_create_empty(xxemul_arch arch, xxemul_mode mode, uint64_t region_address, size_t region_size, xxemul_status *status)
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
        cdisasm_x86_mode decode_mode = mode == XXEMUL_MODE_X86_16 ? CDISASM_X86_MODE_16 : mode == XXEMUL_MODE_X86_32 ? CDISASM_X86_MODE_32 : CDISASM_X86_MODE_64;
        emulator->dos_pic_master_offset = 8u;
        emulator->dos_pic_slave_offset = 0x70u;
        if (cdisasm_x86_cpu_decode_flag_mask(CDISASM_CPU_X86, decode_mode, &emulator->x86_decode_flags) != CDISASM_STATUS_OK) {
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
    if (config == NULL || !xxemul_mode_matches_arch(config->arch, config->mode) || config->code == NULL || config->code_size == 0 ||
        config->region_size < config->code_size || config->region_size > (size_t)LONG_MAX || !xxemul_config_addressable(config)) {
        return NULL;
    }
    if ((config->mode == XXEMUL_MODE_ARM_A32 || config->mode == XXEMUL_MODE_ARM_A64 || config->arch == XXEMUL_ARCH_MIPS) && (config->entry_address & UINT64_C(3)) != 0) {
        return NULL;
    }
    if (config->mode == XXEMUL_MODE_ARM_T32 && (config->entry_address & UINT64_C(1)) != 0) {
        return NULL;
    }
    emulator = xxemul_create_empty(config->arch, config->mode, config->region_address, config->region_size, status);
    if (emulator == NULL) {
        return NULL;
    }
    xx_mem_copy(emulator->region_data, config->code, config->code_size);

    stack_alignment = config->arch == XXEMUL_ARCH_ARM ? 16u : (config->arch == XXEMUL_ARCH_MIPS ? 8u :
        (config->mode == XXEMUL_MODE_X86_16 ? 2u : (config->mode == XXEMUL_MODE_X86_32 ? 4u : 8u)));
    stack_top = config->region_address + (uint64_t)config->region_size;
    stack_top &= ~((uint64_t)stack_alignment - UINT64_C(1));

    if (config->arch == XXEMUL_ARCH_X86) {
        emulator->x86.ip = config->entry_address;
        emulator->x86.flags = UINT64_C(2);
        emulator->x86.gpr[XXEMUL_X86_RSP] = stack_top;
    } else if (config->arch == XXEMUL_ARCH_MIPS) {
        emulator->mips.pc = (uint32_t)config->entry_address;
        emulator->mips.gpr[29] = (uint32_t)stack_top;
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
    xxemul_elf_primary_destroy(emulator);
    xxemul_linux_destroy(emulator->linux_process);
    xxemul_darwin_destroy(emulator->darwin);
    xxemul_dos_files_stop(emulator);
    xx_mem_free(emulator->x86_decode_cache);
    xx_mem_free(emulator->region_data);
    xx_mem_free(emulator);
}

xxemul_status xxemul_start_process(xxemul *emulator, xxemul_image_format format, const char *program_path, const char *working_directory, int argc,
                                   const char *const *argv)
{
    xxemul_status status = XXEMUL_STATUS_INVALID_ARGUMENT;

    if (emulator == NULL || program_path == NULL || working_directory == NULL || argc < 0 || (argc > 0 && argv == NULL) || emulator->windows != NULL ||
        emulator->linux_process != NULL) {
        return status;
    }
    if (format == XXEMUL_IMAGE_MACHO32 || format == XXEMUL_IMAGE_MACHO64) {
        if (emulator->darwin == NULL) return XXEMUL_STATUS_UNSUPPORTED_IMAGE;
        return xxemul_darwin_start(emulator->darwin, program_path, working_directory, argc, argv);
    }
    if (emulator->darwin != NULL) return XXEMUL_STATUS_INVALID_ARGUMENT;
    if (format == XXEMUL_IMAGE_PE32 || format == XXEMUL_IMAGE_PE64) {
        size_t skip = argc > 0 ? 1u : 0u;
        emulator->windows = xxemul_windows_create(emulator, program_path, working_directory, argv == NULL ? NULL : argv + skip, (size_t)argc - skip, &status);
        return emulator->windows == NULL ? status : XXEMUL_STATUS_OK;
    }
    if (format == XXEMUL_IMAGE_ELF32 || format == XXEMUL_IMAGE_ELF64) {
        emulator->linux_process = xxemul_linux_create(emulator, program_path, working_directory, argc, argv);
        if (emulator->linux_process == NULL) return XXEMUL_STATUS_INVALID_IMAGE;
        xxemul_linux_set_output(emulator->linux_process, xxemul_linux_output_bridge, emulator);
        if (emulator->elf_primary != NULL) {
            status = xxemul_elf_primary_start(emulator);
            if (status != XXEMUL_STATUS_OK) {
                xxemul_linux_destroy(emulator->linux_process);
                emulator->linux_process = NULL;
            }
            return status;
        }
        return XXEMUL_STATUS_OK;
    }
    if (format == XXEMUL_IMAGE_COM || format == XXEMUL_IMAGE_MZ) {
        const char *basename = program_path;
        const char *cursor;
        for (cursor = program_path; *cursor != '\0'; ++cursor) {
            if (*cursor == '/' || *cursor == '\\') basename = cursor + 1;
        }
        return xxemul_dos_files_start(emulator, working_directory, basename, (size_t)argc - (argc > 0 ? 1u : 0u), argc > 0 ? argv + 1 : NULL);
    }
    return XXEMUL_STATUS_UNSUPPORTED_IMAGE;
}

xxemul_status xxemul_set_guest_environment(xxemul *emulator, const char *name, const char *value)
{
    if (emulator == NULL || name == NULL || name[0] == '\0' || strchr(name, '=') != NULL || value == NULL) {
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
    if (emulator->windows != NULL) return (int)xxemul_windows_exit_code(emulator->windows);
    if (emulator->linux_process != NULL) return xxemul_linux_exit_code(emulator->linux_process);
    if (emulator->darwin != NULL) return xxemul_darwin_exit_code(emulator->darwin);
    if (emulator->dos_mode) return (int)emulator->exit_code;
    return -1;
}

const char *xxemul_process_error(const xxemul *emulator)
{
    const char *elf_error = xxemul_elf_primary_error(emulator);
    if (elf_error != NULL) return elf_error;
    if (emulator == NULL || emulator->darwin == NULL) return NULL;
    return xxemul_darwin_last_error(emulator->darwin);
}

xxemul *xxemul_create_exec_successor(xxemul *emulator, xxemul_status *status)
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
    if (image == NULL || image_size < 5u || image[0] != 0x7fu || image[1] != 'E' || image[2] != 'L' || image[3] != 'F') return NULL;
    format = image[4] == 1u ? XXEMUL_IMAGE_ELF32 : image[4] == 2u ? XXEMUL_IMAGE_ELF64 : 0u;
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
    for (index = 0u; index < argc; ++index) argv[index] = xxemul_linux_exec_argument(previous, index);
    for (index = 0u; index < envc; ++index) envp[index] = xxemul_linux_exec_environment(previous, index);
    path = xxemul_linux_exec_path(previous);
    if (path == NULL || *path == '\0') path = argc == 0u ? "upx" : argv[0];
    successor = xxemul_create_image(format, image, image_size, status);
    if (successor == NULL) goto done;
    successor->linux_process = xxemul_linux_create_image(successor, image, image_size, path, xxemul_linux_working_directory(previous), (int)argc, argv, (int)envc, envp);
    if (successor->linux_process != NULL) {
        successor->stream_output = emulator->stream_output;
        successor->stream_output_context = emulator->stream_output_context;
        successor->memory_hook = emulator->memory_hook;
        successor->memory_hook_context = emulator->memory_hook_context;
        successor->debug_traps = emulator->debug_traps;
        xxemul_linux_set_output(successor->linux_process, xxemul_linux_output_bridge, successor);
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

xxemul_status xxemul_read_memory(xxemul *emulator, uint64_t address, void *buffer, size_t size)
{
    size_t offset;
    int mapped;

    if (size == 0) {
        return emulator == NULL ? XXEMUL_STATUS_INVALID_ARGUMENT : XXEMUL_STATUS_OK;
    }
    if (emulator != NULL && buffer != NULL && emulator->linux_process != NULL) {
        mapped = xxemul_linux_mapping_read(emulator->linux_process, address, buffer, size);
        if (mapped != 0) return mapped > 0 ? XXEMUL_STATUS_OK : XXEMUL_STATUS_ADDRESS_FAULT;
    }
    if (buffer == NULL || !xxemul_region_contains(emulator, address, size, &offset)) {
        if (emulator && emulator->in_step && buffer) {
            emulator->fault_address = address;
            emulator->fault_access = emulator->x86_fetching ? 8u : 0u;
            emulator->fault_address_valid = 1;
        }
        return buffer == NULL ? XXEMUL_STATUS_INVALID_ARGUMENT : XXEMUL_STATUS_ADDRESS_FAULT;
    }
    xx_mem_copy(buffer, emulator->region_data + offset, size);
    return XXEMUL_STATUS_OK;
}

xxemul_status xxemul_write_memory(xxemul *emulator, uint64_t address, const void *buffer, size_t size)
{
    size_t offset;
    int mapped;

    if (size == 0) {
        return emulator == NULL ? XXEMUL_STATUS_INVALID_ARGUMENT : XXEMUL_STATUS_OK;
    }
    /* Host/debugger writes and guest stores conservatively invalidate an
     * outstanding MIPS LL/SC reservation, including writes through mmap. */
    if (emulator != NULL && emulator->arch == XXEMUL_ARCH_MIPS) emulator->mips_reservation_valid = 0;
    if (emulator != NULL && buffer != NULL && emulator->linux_process != NULL) {
        mapped = xxemul_linux_mapping_write(emulator->linux_process, address, buffer, size);
        if (mapped != 0) return mapped > 0 ? XXEMUL_STATUS_OK : XXEMUL_STATUS_ADDRESS_FAULT;
    }
    if (buffer == NULL || !xxemul_region_contains(emulator, address, size, &offset)) {
        if (emulator && emulator->in_step && buffer) {
            emulator->fault_address = address;
            emulator->fault_access = 1u;
            emulator->fault_address_valid = 1;
        }
        return buffer == NULL ? XXEMUL_STATUS_INVALID_ARGUMENT : XXEMUL_STATUS_ADDRESS_FAULT;
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

xxemul_status xxemul_load_integer(xxemul *emulator, uint64_t address, uint8_t size, uint64_t *value)
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

xxemul_status xxemul_store_integer(xxemul *emulator, uint64_t address, uint8_t size, uint64_t value)
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

xxemul_status xxemul_get_x86_state(const xxemul *emulator, xxemul_x86_state *state)
{
    if (emulator == NULL || state == NULL || emulator->arch != XXEMUL_ARCH_X86) {
        return XXEMUL_STATUS_INVALID_ARGUMENT;
    }
    *state = emulator->x86;
    return XXEMUL_STATUS_OK;
}

xxemul_status xxemul_set_x86_state(xxemul *emulator, const xxemul_x86_state *state)
{
    unsigned index;
    if (emulator == NULL || state == NULL || emulator->arch != XXEMUL_ARCH_X86) {
        return XXEMUL_STATUS_INVALID_ARGUMENT;
    }
    /* A real-mode debugger selector write must reload its segment base,
     * just as a guest MOV/POP to that segment would. Keep unchanged hidden
     * caches, including unreal-mode limits, and leave protected descriptors
     * under their existing instruction/DPMI handling. */
    if (emulator->dos_mode && emulator->mode == XXEMUL_MODE_X86_16 && !(emulator->dos_cr0 & 1u)) {
        for (index = 0; index < XXEMUL_X86_SEGMENT_COUNT; ++index)
            if (emulator->x86.segment[index] != state->segment[index]) emulator->dos_segments[index].valid = 0;
    }
    emulator->x86 = *state;
    emulator->x86.flags |= UINT64_C(2);
    emulator->halted = 0;
    return XXEMUL_STATUS_OK;
}

xxemul_status xxemul_get_arm_state(const xxemul *emulator, xxemul_arm_state *state)
{
    if (emulator == NULL || state == NULL || emulator->arch != XXEMUL_ARCH_ARM) {
        return XXEMUL_STATUS_INVALID_ARGUMENT;
    }
    *state = emulator->arm;
    return XXEMUL_STATUS_OK;
}

xxemul_status xxemul_set_arm_state(xxemul *emulator, const xxemul_arm_state *state)
{
    if (emulator == NULL || state == NULL || emulator->arch != XXEMUL_ARCH_ARM) {
        return XXEMUL_STATUS_INVALID_ARGUMENT;
    }
    emulator->arm = *state;
    emulator->halted = 0;
    return XXEMUL_STATUS_OK;
}

xxemul_status xxemul_get_mips_state(const xxemul *emulator, xxemul_mips_state *state)
{
    if (emulator == NULL || state == NULL || emulator->arch != XXEMUL_ARCH_MIPS) return XXEMUL_STATUS_INVALID_ARGUMENT;
    *state = emulator->mips;
    state->gpr[0] = 0;
    return XXEMUL_STATUS_OK;
}

xxemul_status xxemul_set_mips_state(xxemul *emulator, const xxemul_mips_state *state)
{
    if (emulator == NULL || state == NULL || emulator->arch != XXEMUL_ARCH_MIPS || (state->pc & 3u))
        return XXEMUL_STATUS_INVALID_ARGUMENT;
    if (emulator->mips.pc != state->pc) emulator->mips_delay_pending = 0;
    emulator->mips = *state;
    emulator->mips.gpr[0] = 0;
    emulator->mips_reservation_valid = 0;
    emulator->halted = 0;
    return XXEMUL_STATUS_OK;
}

static xxemul_status xxemul_step_inner(xxemul *emulator, xxemul_step_info *info);

xxemul_status xxemul_step(xxemul *emulator, xxemul_step_info *info)
{
    xxemul_status status;

    if (emulator == NULL) {
        return XXEMUL_STATUS_INVALID_ARGUMENT;
    }
    emulator->in_step = 1;
    status = xxemul_step_inner(emulator, info);
    status = xxemul_elf_primary_after_step(emulator, status);
    emulator->x86_fetching = 0;
    if (status == XXEMUL_STATUS_OK && emulator->dos_mode) {
        xxemul_bios_advance_clock(emulator);
        /* The dispatcher owns shared interrupt eligibility. Protected DPMI
         * clients use its bounded default-BIOS virtual timer service. */
        status = xxemul_x86_dos_dispatch_irq0(emulator, info);
    }
    emulator->in_step = 0;
    return status;
}

static xxemul_status xxemul_step_inner(xxemul *emulator, xxemul_step_info *info)
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
    if (emulator->elf_primary != NULL && xxemul_elf_primary_try_step(emulator, info, &status)) return status;
    if (emulator->windows != NULL && xxemul_windows_try_step(emulator->windows, info, &status)) {
        if (status == XXEMUL_STATUS_HALTED) emulator->halted = 1;
        return status;
    }
    if (emulator->arch == XXEMUL_ARCH_X86) {
        uint64_t fault_ip;
        xxemul_x86_state before;
        fault_ip = emulator->x86.ip;
        if (emulator->windows) before = emulator->x86;
        emulator->fault_address_valid = 0;
        status = xxemul_x86_step(emulator, info);
        if (status == XXEMUL_STATUS_ADDRESS_FAULT && emulator->dos_mode) {
            return xxemul_x86_dispatch_pending_page_fault(emulator, info, fault_ip);
        }
        if (emulator->windows && xxemul_windows_try_exception(emulator->windows, &before, status, info)) return XXEMUL_STATUS_OK;
        if (emulator->windows && status == XXEMUL_STATUS_OK && (before.flags & 0x100u) &&
            xxemul_windows_try_exception(emulator->windows, &emulator->x86, XXEMUL_WINDOWS_SINGLE_STEP_FAULT, info)) return XXEMUL_STATUS_OK;
        return status;
    }
    if (emulator->arch == XXEMUL_ARCH_MIPS) return xxemul_mips_step(emulator, info);
    if (emulator->darwin != NULL && xxemul_darwin_try_step(emulator->darwin, info, &status)) {
        if (status == XXEMUL_STATUS_HALTED) emulator->halted = 1;
        return status;
    }
    return xxemul_arm_step(emulator, info);
}

xxemul_status xxemul_run(xxemul *emulator, uint64_t instruction_limit, uint64_t *instructions_executed)
{
    uint64_t executed = UINT64_C(0);
    xxemul_step_info info;
    xxemul_status status;

    if (emulator == NULL || instruction_limit == 0) {
        return XXEMUL_STATUS_INVALID_ARGUMENT;
    }
    while (executed < instruction_limit) {
        status = xxemul_step(emulator, &info);
        if (status == XXEMUL_STATUS_OK || (status == XXEMUL_STATUS_HALTED && info.size != 0u)) {
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

size_t xxemul_format_current(xxemul *emulator, char *buffer, size_t buffer_size)
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
    if (emulator->arch == XXEMUL_ARCH_MIPS) return xxemul_mips_format_current(emulator, buffer, buffer_size);
    return xxemul_arm_format_current(emulator, buffer, buffer_size);
}

xxemul_status xxemul_set_output_callback(xxemul *emulator, xxemul_output_callback callback, void *context)
{
    if (emulator == NULL) return XXEMUL_STATUS_INVALID_ARGUMENT;
    emulator->stream_output = callback;
    emulator->stream_output_context = context;
    return XXEMUL_STATUS_OK;
}

xxemul_status xxemul_set_memory_hook(xxemul *emulator, xxemul_memory_hook hook, void *context)
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

xxemul_status xxemul_x86_linear_address(const xxemul *emulator, unsigned segment_index, uint64_t offset, uint64_t *address)
{
    if (emulator == NULL || address == NULL || emulator->arch != XXEMUL_ARCH_X86 || segment_index >= XXEMUL_X86_SEGMENT_COUNT) {
        return XXEMUL_STATUS_INVALID_ARGUMENT;
    }
    if (emulator->dos_mode) {
        if (emulator->dos_segments[segment_index].valid) {
            *address = (uint64_t)emulator->dos_segments[segment_index].base + (offset & UINT32_MAX);
        } else {
            *address = xxemul_dos_physical(emulator, emulator->x86.segment[segment_index], (uint16_t)offset);
        }
        return XXEMUL_STATUS_OK;
    }
    *address = offset;
    return XXEMUL_STATUS_OK;
}

xxemul_status xxemul_get_current_address(const xxemul *emulator, uint64_t *address)
{
    if (emulator == NULL || address == NULL) {
        return XXEMUL_STATUS_INVALID_ARGUMENT;
    }
    if (emulator->arch == XXEMUL_ARCH_ARM) {
        *address = emulator->arm.pc;
        return XXEMUL_STATUS_OK;
    }
    if (emulator->arch == XXEMUL_ARCH_MIPS) { *address = emulator->mips.pc; return XXEMUL_STATUS_OK; }
    return xxemul_x86_linear_address(emulator, XXEMUL_X86_CS, emulator->x86.ip, address);
}

xxemul_status xxemul_get_stack_address(const xxemul *emulator, uint64_t *address)
{
    uint64_t mask, offset;
    if (emulator == NULL || address == NULL || !xxemul_mode_matches_arch(emulator->arch, emulator->mode)) {
        return XXEMUL_STATUS_INVALID_ARGUMENT;
    }
    if (emulator->arch == XXEMUL_ARCH_ARM) {
        *address = emulator->arm.sp & (emulator->mode == XXEMUL_MODE_ARM_A64 ? UINT64_MAX : UINT32_MAX);
        return XXEMUL_STATUS_OK;
    }
    if (emulator->arch == XXEMUL_ARCH_MIPS) { *address = emulator->mips.gpr[29]; return XXEMUL_STATUS_OK; }
    mask = emulator->mode == XXEMUL_MODE_X86_16 ? UINT16_MAX
        : emulator->mode == XXEMUL_MODE_X86_32 ? UINT32_MAX : UINT64_MAX;
    /* Match xxemul_x86_stack_mask: SS.B controls protected-mode stack
     * addressing independently of the current code segment's width. */
    if (emulator->dos_mode && emulator->dos_segments[XXEMUL_X86_SS].valid) {
        mask = (emulator->dos_segments[XXEMUL_X86_SS].flags & 4u) != 0u ? UINT32_MAX : UINT16_MAX;
    }
    offset = emulator->x86.gpr[XXEMUL_X86_RSP] & mask;
    if (emulator->dos_mode) {
        uint64_t base = emulator->dos_segments[XXEMUL_X86_SS].valid
            ? emulator->dos_segments[XXEMUL_X86_SS].base : (uint32_t)emulator->x86.segment[XXEMUL_X86_SS] << 4u;
        /* Guest stack accesses wrap the segment sum to 32 bits. With paging
         * disabled their remaining address translation is the A20 gate. Do
         * not mask linear bit 20 before paging, whose page tables use it. */
        uint32_t linear = (uint32_t)(base + offset);
        if ((emulator->dos_cr0 & UINT32_C(0x80000000)) == 0u && (emulator->dos_port_92 & 2u) == 0u)
            linear &= ~UINT32_C(0x100000);
        *address = linear;
        return XXEMUL_STATUS_OK;
    }
    *address = offset;
    return XXEMUL_STATUS_OK;
}

xxemul_status xxemul_x86_get_segment_base(const xxemul *emulator, unsigned segment_index, uint64_t *base)
{
    if (emulator == NULL || base == NULL || emulator->arch != XXEMUL_ARCH_X86 || segment_index >= XXEMUL_X86_SEGMENT_COUNT) {
        return XXEMUL_STATUS_INVALID_ARGUMENT;
    }
    if (emulator->dos_mode) return xxemul_x86_linear_address(emulator, segment_index, 0, base);
    *base = 0;
    /* Match the effective-address calculation used by x86 guest accesses. */
    if (segment_index == XXEMUL_X86_FS || segment_index == XXEMUL_X86_GS) {
        if (emulator->windows != NULL) {
            *base = xxemul_windows_segment_base(emulator->windows, (uint8_t)segment_index);
        } else if (emulator->linux_process != NULL) {
            *base = xxemul_linux_segment_base(emulator->linux_process, segment_index, emulator->x86.segment[segment_index]);
        }
    }
    return XXEMUL_STATUS_OK;
}

int xxemul_is_halted(const xxemul *emulator)
{
    return emulator == NULL || emulator->halted;
}

const char *xxemul_symbol_name(const xxemul *emulator, uint64_t address)
{
    if (emulator == NULL) return NULL;
    if (emulator->darwin != NULL) return xxemul_darwin_symbol(emulator->darwin, address);
    if (emulator->windows != NULL) return xxemul_windows_thunk_name(emulator, address);
    return NULL;
}

const char *xxemul_symbol_qualified_name(const xxemul *emulator, uint64_t address)
{
    if (emulator != NULL && emulator->windows != NULL) return xxemul_windows_thunk_qualified_name(emulator, address);
    return xxemul_symbol_name(emulator, address);
}
