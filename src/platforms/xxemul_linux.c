#include "xxemul_linux.h"
#include "xxemul_internal.h"
#include <xxemul/xxemul_elf.h>

#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define LINUX_MAX_FDS 64
#define LINUX_MAX_MAPS 128
#define LINUX_MAX_FILE (64u * 1024u * 1024u)
#define LINUX_MAX_MAP (128u * 1024u * 1024u)
#define LINUX_MAX_EXEC_STRINGS 128u
#define LINUX_PAGE UINT64_C(4096)

#define LINUX_EPERM 1
#define LINUX_ENOENT 2
#define LINUX_EIO 5
#define LINUX_EBADF 9
#define LINUX_ENOMEM 12
#define LINUX_EACCES 13
#define LINUX_EFAULT 14
#define LINUX_EINVAL 22
#define LINUX_EFBIG 27
#define LINUX_ENOSYS 38

typedef struct linux_file {
    int used;
    int open;
    int writable;
    int dirty;
    int self;
    uint8_t *data;
    size_t size;
    size_t capacity;
    uint64_t offset;
    char host_path[1024];
} linux_file;

typedef struct linux_map {
    int used;
    int shared;
    int fd;
    uint64_t generation;
    uint64_t base;
    uint64_t size;
    uint64_t file_offset;
    uint8_t *data;
} linux_map;

struct xxemul_linux_process {
    xxemul *emulator;
    int is_64;
    int big_endian;
    int freebsd;
    uint64_t freebsd_arguments[8];
    int legacy_stat;
    int argument_fault;
    int exited;
    int exit_code;
    int exec_fd;
    int exec_is_at;
    int exec_dirfd;
    uint64_t exec_flags;
    char exec_path[1024];
    char *exec_argv[LINUX_MAX_EXEC_STRINGS + 1u];
    char *exec_envp[LINUX_MAX_EXEC_STRINGS + 1u];
    size_t exec_argc;
    size_t exec_envc;
    uint8_t *exec_owned_image;
    size_t exec_owned_size;
    uint64_t next_map;
    uint64_t map_generation;
    uint64_t brk_base;
    uint64_t brk_current;
    uint64_t fs_base;
    uint64_t gs_base;
    uint64_t tls_base[3];
    char self_path[1024];
    char workdir[1024];
    uint8_t *self_data;
    size_t self_size;
    uint8_t auxv_data[17u * 2u * 8u];
    size_t auxv_size;
    linux_file files[LINUX_MAX_FDS];
    linux_map maps[LINUX_MAX_MAPS];
    xxemul_linux_output_callback output;
    void *output_context;
    int syscall_stats_enabled;
    uint64_t syscall_total;
    uint64_t syscall_counts[512];
    uint32_t first_syscalls[32];
    size_t first_syscall_count;
};

/* Guest byte order applies to ELF headers, auxv, iovec and syscall structs. */
static uint64_t linux_load_value(const xxemul_linux_process *process, const uint8_t *data, unsigned width)
{
    uint64_t value = 0;
    unsigned index;
    for (index = 0; index < width; ++index)
        value |= (uint64_t)data[index] << (8u * (process->big_endian ? width - 1u - index : index));
    return value;
}

static void linux_put_value(const xxemul_linux_process *process, uint8_t *data, size_t offset, uint64_t value, unsigned width)
{
    unsigned index;
    for (index = 0; index < width; ++index)
        data[offset + index] = (uint8_t)(value >> (8u * (process->big_endian ? width - 1u - index : index)));
}

static uint64_t linux_align_up(uint64_t value, uint64_t alignment)
{
    return (value + alignment - 1u) & ~(alignment - 1u);
}

static uint64_t linux_error(unsigned number)
{
    return (uint64_t)-(int64_t)number;
}

static int linux_copy_string(char *target, size_t capacity, const char *source)
{
    size_t size;
    if (source == NULL) return 0;
    size = strlen(source);
    if (size >= capacity) return 0;
    memcpy(target, source, size + 1u);
    return 1;
}

static uint8_t *linux_read_file(const char *path, size_t *size)
{
    xx_io_device *io;
    int64_t length;
    uint8_t *data;
    io = xx_io_file_open(path, "rb");
    if (io == NULL) return NULL;
    length = xx_io_total_size(io);
    if (length < 0 || length > (int64_t)LINUX_MAX_FILE) {
        xx_io_close(io);
        return NULL;
    }
    data = (uint8_t *)malloc((size_t)length + 1u);
    if (data == NULL || xx_io_read(io, data, (size_t)length) != length) {
        free(data);
        xx_io_close(io);
        return NULL;
    }
    xx_io_close(io);
    *size = (size_t)length;
    return data;
}

static int linux_file_reserve(linux_file *file, size_t size)
{
    uint8_t *new_data;
    size_t capacity;
    if (size > LINUX_MAX_FILE) return 0;
    if (size <= file->capacity) {
        if (size > file->size) memset(file->data + file->size, 0, size - file->size);
        if (size > file->size) file->size = size;
        return 1;
    }
    capacity = file->capacity == 0 ? 4096u : file->capacity;
    while (capacity < size) {
        if (capacity > LINUX_MAX_FILE / 2u) {
            capacity = LINUX_MAX_FILE;
            break;
        }
        capacity *= 2u;
    }
    new_data = (uint8_t *)realloc(file->data, capacity);
    if (new_data == NULL) return 0;
    file->data = new_data;
    file->capacity = capacity;
    if (size > file->size) memset(file->data + file->size, 0, size - file->size);
    if (size > file->size) file->size = size;
    return 1;
}

static linux_file *linux_fd(xxemul_linux_process *process, int fd)
{
    if (fd < 3 || fd >= LINUX_MAX_FDS || !process->files[fd].used) return NULL;
    return &process->files[fd];
}

static int linux_new_fd(xxemul_linux_process *process)
{
    int index;
    for (index = 3; index < LINUX_MAX_FDS; ++index) {
        if (!process->files[index].used) {
            process->files[index].used = 1;
            process->files[index].open = 1;
            return index;
        }
    }
    return -1;
}

static int linux_file_save(linux_file *file)
{
    xx_io_device *io;
    if (!file->dirty || file->host_path[0] == '\0') return 1;
    io = xx_io_file_open(file->host_path, "wb");
    if (io == NULL) return 0;
    if (xx_io_write(io, file->data, file->size) != (ssize_t)file->size) {
        xx_io_close(io);
        return 0;
    }
    if (xx_io_close(io) != 0) return 0;
    file->dirty = 0;
    return 1;
}

static linux_map *linux_find_map(xxemul_linux_process *process, uint64_t address)
{
    int index;
    linux_map *best = NULL;
    for (index = 0; index < LINUX_MAX_MAPS; ++index) {
        linux_map *map = &process->maps[index];
        if (map->used && address >= map->base && address - map->base < map->size && (best == NULL || map->generation > best->generation)) best = map;
    }
    return best;
}

static int linux_map_transfer(xxemul_linux_process *process, uint64_t address, void *buffer, size_t size, int write)
{
    uint8_t *bytes = (uint8_t *)buffer;
    size_t completed = 0;
    linux_map *map;
    if (size == 0) return 1;
    map = linux_find_map(process, address);
    if (map == NULL) return 0;
    while (completed < size) {
        size_t offset;
        size_t chunk;
        map = linux_find_map(process, address + completed);
        if (map == NULL) return -1;
        offset = (size_t)(address + completed - map->base);
        chunk = size - completed;
        if (chunk > (size_t)map->size - offset) chunk = (size_t)map->size - offset;
        if (write) {
            int i;
            if (map->shared && map->fd >= 3) {
                linux_file *file = linux_fd(process, map->fd);
                uint64_t file_offset = map->file_offset + offset;
                if (file == NULL || file_offset > LINUX_MAX_FILE || chunk > LINUX_MAX_FILE - file_offset || !linux_file_reserve(file, (size_t)file_offset + chunk))
                    return -1;
                memcpy(file->data + file_offset, bytes + completed, chunk);
                file->dirty = file->host_path[0] != '\0';
                for (i = 0; i < LINUX_MAX_MAPS; ++i) {
                    linux_map *alias = &process->maps[i];
                    uint64_t begin = file_offset > alias->file_offset ? file_offset : alias->file_offset;
                    uint64_t end = file_offset + chunk;
                    if (!alias->used || !alias->shared || alias == map || alias->fd != map->fd) continue;
                    if (end > alias->file_offset + alias->size) end = alias->file_offset + alias->size;
                    if (end > begin) memcpy(alias->data + begin - alias->file_offset, file->data + begin, (size_t)(end - begin));
                }
            }
            memcpy(map->data + offset, bytes + completed, chunk);
        } else {
            memcpy(bytes + completed, map->data + offset, chunk);
        }
        completed += chunk;
    }
    return 1;
}

int xxemul_linux_mapping_read(xxemul_linux_process *process, uint64_t address, void *buffer, size_t size)
{
    if (process == NULL || (buffer == NULL && size != 0)) return -1;
    return linux_map_transfer(process, address, buffer, size, 0);
}

int xxemul_linux_mapping_write(xxemul_linux_process *process, uint64_t address, const void *buffer, size_t size)
{
    if (process == NULL || (buffer == NULL && size != 0)) return -1;
    return linux_map_transfer(process, address, (void *)buffer, size, 1);
}

static int linux_guest_read(xxemul_linux_process *process, uint64_t address, void *buffer, size_t size)
{
    int mapped = xxemul_linux_mapping_read(process, address, buffer, size);
    return mapped == 1 || (mapped == 0 && xxemul_read_memory(process->emulator, address, buffer, size) == XXEMUL_STATUS_OK);
}

static int linux_guest_write(xxemul_linux_process *process, uint64_t address, const void *buffer, size_t size)
{
    int mapped = xxemul_linux_mapping_write(process, address, buffer, size);
    return mapped == 1 || (mapped == 0 && xxemul_write_memory(process->emulator, address, buffer, size) == XXEMUL_STATUS_OK);
}

static int linux_guest_value(xxemul_linux_process *process, uint64_t address, unsigned width, uint64_t *value)
{
    uint8_t data[8];
    *value = 0;
    if (width > sizeof(data) || !linux_guest_read(process, address, data, width)) return 0;
    *value = linux_load_value(process, data, width);
    return 1;
}

static int linux_guest_store(xxemul_linux_process *process, uint64_t address, unsigned width, uint64_t value)
{
    uint8_t data[8];
    if (width > sizeof(data)) return 0;
    linux_put_value(process, data, 0, value, width);
    return linux_guest_write(process, address, data, width);
}

static int linux_guest_string(xxemul_linux_process *process, uint64_t address, char *buffer, size_t capacity)
{
    size_t index;
    if (address == 0 || capacity == 0) return 0;
    for (index = 0; index + 1u < capacity; ++index) {
        if (!linux_guest_read(process, address + index, buffer + index, 1u)) return 0;
        if (buffer[index] == '\0') return 1;
    }
    buffer[capacity - 1u] = '\0';
    return 0;
}

static int linux_phdr_info(const xxemul_linux_process *process, uint64_t *address, uint64_t *entry_size, uint64_t *count, uint64_t *load_bias)
{
    const uint8_t *image = process->self_data;
    size_t size = process->self_size;
    uint64_t offset;
    uint64_t index;
    if (size < (process->is_64 ? 64u : 52u) || memcmp(image, "\177ELF", 4u) != 0) return 0;
    offset = process->is_64 ? linux_load_value(process, image + 32, 8u) : linux_load_value(process, image + 28, 4u);
    *entry_size = linux_load_value(process, image + (process->is_64 ? 54 : 42), 2u);
    *count = linux_load_value(process, image + (process->is_64 ? 56 : 44), 2u);
    if (*entry_size < (process->is_64 ? 56u : 32u) || *count > 256u || offset > size || *count > (size - (size_t)offset) / *entry_size) return 0;
    *load_bias = 0;
    if (!process->freebsd && linux_load_value(process, image + 16u, 2u) == 3u) {
        const xxemul_elf_shared_info *primary = xxemul_elf_primary_get_info(process->emulator);
        if (primary) *load_bias = primary->load_bias;
        else {
            uint64_t low = UINT64_MAX;
            /* A shared_create caller may attach a Linux context without
             * registering the module as the primary image. Its arena starts
             * at the page-aligned lowest nonempty PT_LOAD virtual address. */
            for (index = 0; index < *count; ++index) {
                const uint8_t *ph = image + offset + index * *entry_size;
                uint64_t memory_size = linux_load_value(process, ph + (process->is_64 ? 40u : 20u), process->is_64 ? 8u : 4u);
                uint64_t virtual_address = linux_load_value(process, ph + (process->is_64 ? 16u : 8u), process->is_64 ? 8u : 4u);
                if (linux_load_value(process, ph, 4u) == 1u && memory_size && virtual_address < low) low = virtual_address;
            }
            if (low == UINT64_MAX) return 0;
            low &= ~(LINUX_PAGE - 1u);
            if (process->emulator->region_address < low) return 0;
            *load_bias = process->emulator->region_address - low;
        }
    }
    for (index = 0; index < *count; ++index) {
        const uint8_t *ph = image + offset + index * *entry_size;
        uint64_t file_offset = process->is_64 ? linux_load_value(process, ph + 8, 8u) : linux_load_value(process, ph + 4, 4u);
        uint64_t virtual_address = process->is_64 ? linux_load_value(process, ph + 16, 8u) : linux_load_value(process, ph + 8, 4u);
        uint64_t file_size = process->is_64 ? linux_load_value(process, ph + 32, 8u) : linux_load_value(process, ph + 16, 4u);
        if (linux_load_value(process, ph, 4u) == 1u && offset >= file_offset && offset - file_offset <= file_size && *count * *entry_size <= file_size - (offset - file_offset)) {
            uint64_t relative = offset - file_offset;
            if (virtual_address > UINT64_MAX - relative || virtual_address + relative > UINT64_MAX - *load_bias) return 0;
            *address = *load_bias + virtual_address + relative;
            return 1;
        }
    }
    return 0;
}

static int linux_initial_stack(xxemul_linux_process *process, int argc, const char *const *argv, int envc, const char *const *envp)
{
    static const uint64_t linux_aux_types[] = {3, 4, 5, 6, 7, 8, 9, 11, 12, 13, 14, 16, 17, 23, 25, 31, 0};
    static const uint64_t freebsd_aux_types[] = {3, 4, 5, 6, 7, 8, 9, 11, 12, 13, 14, 15, 16, 17, 19, 23, 0};
    const uint64_t *aux_types = process->freebsd ? freebsd_aux_types : linux_aux_types;
    const size_t aux_count = sizeof(linux_aux_types) / sizeof(linux_aux_types[0]);
    uint64_t aux_values[sizeof(linux_aux_types) / sizeof(linux_aux_types[0])] = {0};
    uint64_t arg_address[129];
    uint64_t env_address[129];
    uint64_t stack_top = process->emulator->region_address + process->emulator->region_size;
    uint64_t cursor = (stack_top - 0x100u) & ~UINT64_C(15);
    uint64_t low = stack_top - 1024u * 1024u;
    uint64_t phdr, phent, phnum, random_address, execfn_address, sp, entry, load_bias;
    uint8_t random_bytes[16];
    unsigned width = process->is_64 ? 8u : 4u;
    int index;
    size_t i;
    if (argc < 0 || argc > (int)LINUX_MAX_EXEC_STRINGS || envc < 0 || envc > (int)LINUX_MAX_EXEC_STRINGS || (argc > 0 && argv == NULL) || (envc > 0 && envp == NULL) ||
        !linux_phdr_info(process, &phdr, &phent, &phnum, &load_bias))
        return 0;
    for (index = 0; index < argc; ++index) {
        const char *value = argv[index];
        size_t length;
        if (value == NULL) return 0;
        length = strlen(value) + 1u;
        if (length > 4096u || cursor < low + length) return 0;
        cursor = (cursor - length) & ~((uint64_t)width - 1u);
        if (!linux_guest_write(process, cursor, value, length)) return 0;
        arg_address[index] = cursor;
    }
    for (index = 0; index < envc; ++index) {
        const char *value = envp[index];
        size_t length;
        if (value == NULL) return 0;
        length = strlen(value) + 1u;
        if (length > 4096u || cursor < low + length) return 0;
        cursor = (cursor - length) & ~((uint64_t)width - 1u);
        if (!linux_guest_write(process, cursor, value, length)) return 0;
        env_address[index] = cursor;
    }
    {
        size_t length = strlen(process->self_path) + 1u;
        if (cursor < low + length) return 0;
        cursor = (cursor - length) & ~((uint64_t)width - 1u);
        if (!linux_guest_write(process, cursor, process->self_path, length)) return 0;
        execfn_address = cursor;
    }
    if (cursor < low + sizeof(random_bytes)) return 0;
    random_address = (cursor - sizeof(random_bytes)) & ~UINT64_C(15);
    memset(random_bytes, 0x5a, sizeof(random_bytes));
    if (!linux_guest_write(process, random_address, random_bytes, sizeof(random_bytes))) return 0;
    /* Preserve the Thumb entry bit in AT_ENTRY even though the CPU keeps an
     * aligned PC and records its instruction set separately. */
    entry = linux_load_value(process, process->self_data + 24u, width);
    if (entry) {
        if (entry > UINT64_MAX - load_bias) return 0;
        entry += load_bias;
    }
    aux_values[0] = phdr;
    aux_values[1] = phent;
    aux_values[2] = phnum;
    aux_values[3] = LINUX_PAGE;
    aux_values[6] = entry;
    if (process->freebsd) {
        aux_values[11] = execfn_address; /* AT_EXECPATH */
        aux_values[12] = random_address; /* AT_CANARY */
        aux_values[13] = sizeof(random_bytes);
        aux_values[14] = 1; /* AT_NCPUS */
        aux_values[15] = 3; /* AT_STACKPROT: read/write */
    } else {
        aux_values[12] = 100u;
        aux_values[14] = random_address;
        aux_values[15] = execfn_address;
    }
    i = 1u + (size_t)argc + 1u + (size_t)envc + 1u + 2u * aux_count;
    if (random_address < low + i * width) return 0;
    sp = (random_address - i * width) & ~UINT64_C(15);
    if (sp < low) return 0;
    cursor = sp;
    if (!linux_guest_store(process, cursor, width, (uint64_t)argc)) return 0;
    cursor += width;
    for (index = 0; index < argc; ++index, cursor += width)
        if (!linux_guest_store(process, cursor, width, arg_address[index])) return 0;
    if (!linux_guest_store(process, cursor, width, 0)) return 0;
    cursor += width;
    for (index = 0; index < envc; ++index, cursor += width)
        if (!linux_guest_store(process, cursor, width, env_address[index])) return 0;
    if (!linux_guest_store(process, cursor, width, 0)) return 0;
    cursor += width;
    process->auxv_size = aux_count * 2u * width;
    for (i = 0; i < aux_count; ++i) {
        if (!linux_guest_store(process, cursor, width, aux_types[i]) || !linux_guest_store(process, cursor + width, width, aux_values[i])) return 0;
        linux_put_value(process, process->auxv_data, i * 2u * width, aux_types[i], width);
        linux_put_value(process, process->auxv_data, (i * 2u + 1u) * width, aux_values[i], width);
        cursor += 2u * width;
    }
    if (process->emulator->arch == XXEMUL_ARCH_X86) {
        process->emulator->x86.gpr[XXEMUL_X86_RSP] = sp;
        process->emulator->x86.segment[XXEMUL_X86_CS] = process->is_64 ? 0x33u : 0x23u;
        process->emulator->x86.segment[XXEMUL_X86_SS] = 0x2bu;
        process->emulator->x86.segment[XXEMUL_X86_DS] = 0x2bu;
        process->emulator->x86.segment[XXEMUL_X86_ES] = 0x2bu;
    } else if (process->emulator->arch == XXEMUL_ARCH_ARM) {
        process->emulator->arm.sp = sp;
        /* Linux starts a static image with no dynamic-linker finalizer. */
        process->emulator->arm.gpr[0] = 0;
    } else {
        process->emulator->mips.gpr[29] = (uint32_t)sp;
        process->emulator->mips.gpr[2] = 0;
    }
    return 1;
}

static xxemul_linux_process *linux_new_process(xxemul *emulator, const char *guest_executable_path, const char *working_directory)
{
    xxemul_linux_process *process;
    if (emulator == NULL || guest_executable_path == NULL || working_directory == NULL ||
        !((emulator->arch == XXEMUL_ARCH_X86 && (emulator->mode == XXEMUL_MODE_X86_32 || emulator->mode == XXEMUL_MODE_X86_64)) ||
          (emulator->arch == XXEMUL_ARCH_ARM && (emulator->mode == XXEMUL_MODE_ARM_A32 || emulator->mode == XXEMUL_MODE_ARM_T32 || emulator->mode == XXEMUL_MODE_ARM_A64)) ||
          (emulator->arch == XXEMUL_ARCH_MIPS && (emulator->mode == XXEMUL_MODE_MIPS32 || emulator->mode == XXEMUL_MODE_MIPS32_BE))))
        return NULL;
    process = (xxemul_linux_process *)calloc(1u, sizeof(*process));
    if (process == NULL) return NULL;
    process->emulator = emulator;
    process->is_64 = emulator->mode == XXEMUL_MODE_X86_64 || emulator->mode == XXEMUL_MODE_ARM_A64;
    process->big_endian = emulator->mode == XXEMUL_MODE_MIPS32_BE;
    process->next_map = process->is_64 ? UINT64_C(0x100000000) : UINT64_C(0x10000000);
    process->exec_fd = -1;
#if defined(_MSC_VER)
    {
        size_t value_size = 0u;
        process->syscall_stats_enabled = getenv_s(&value_size, NULL, 0u, "XXEMUL_LINUX_SYSCALL_STATS") == 0 && value_size != 0u;
    }
#else
    process->syscall_stats_enabled = getenv("XXEMUL_LINUX_SYSCALL_STATS") != NULL;
#endif
    if (!linux_copy_string(process->self_path, sizeof(process->self_path), guest_executable_path) ||
        !linux_copy_string(process->workdir, sizeof(process->workdir), working_directory))
        goto failed;
    return process;
failed:
    xxemul_linux_destroy(process);
    return NULL;
}

/* Select the guest kernel ABI from the actual ELF, never the host OS.
 * FreeBSD support is deliberately limited to canonical static i386 images;
 * historical EI_PAD branding must not accidentally execute Linux syscalls. */
static int elf_process_abi(xxemul_linux_process *process)
{
    const uint8_t *image = process->self_data;
    size_t size = process->self_size;
    uint64_t phoff, count, entry_size, index;
    if (size < 52u || memcmp(image, "\177ELF", 4) || (image[4] != 1 && image[4] != 2)) return 0;
    if (image[7] == 0 && !memcmp(image + 8, "FreeBSD", 7)) return 0;
    if (image[7] == 0 || image[7] == 3) return 1;
    if (image[7] == 97 && image[4] == 1 && image[5] == 1 &&
        process->emulator->arch == XXEMUL_ARCH_ARM && !process->is_64) return 1; /* ELFOSABI_ARM */
    if (image[7] != 9 || image[4] != 1 || image[5] != 1 || process->emulator->arch != XXEMUL_ARCH_X86 ||
        process->emulator->mode != XXEMUL_MODE_X86_32 || linux_load_value(process, image + 16, 2) != 2 ||
        linux_load_value(process, image + 18, 2) != 3) return 0;
    phoff = linux_load_value(process, image + 28, 4);
    entry_size = linux_load_value(process, image + 42, 2);
    count = linux_load_value(process, image + 44, 2);
    if (!count || count > 256 || entry_size != 32 || phoff > size || count > (size - (size_t)phoff) / entry_size) return 0;
    for (index = 0; index < count; ++index) {
        uint64_t type = linux_load_value(process, image + phoff + index * entry_size, 4);
        if (type == 2 || type == 3) return 0; /* PT_DYNAMIC / PT_INTERP */
    }
    process->freebsd = 1;
    return 1;
}

xxemul_linux_process *xxemul_linux_create(xxemul *emulator, const char *executable_path, const char *working_directory, int argc, const char *const *argv)
{
    xxemul_linux_process *process = linux_new_process(emulator, executable_path, working_directory);
    if (process == NULL) return NULL;
    process->self_data = linux_read_file(executable_path, &process->self_size);
    if (process->self_data == NULL || !elf_process_abi(process) || !linux_initial_stack(process, argc, argv, 0, NULL)) goto failed;
    return process;
failed:
    xxemul_linux_destroy(process);
    return NULL;
}

xxemul_linux_process *xxemul_linux_create_image(xxemul *emulator, const uint8_t *image, size_t image_size, const char *guest_executable_path,
                                                const char *working_directory, int argc, const char *const *argv, int envc, const char *const *envp)
{
    xxemul_linux_process *process;
    if (image == NULL || image_size == 0u || image_size > LINUX_MAX_FILE) return NULL;
    process = linux_new_process(emulator, guest_executable_path, working_directory);
    if (process == NULL) return NULL;
    process->self_data = (uint8_t *)malloc(image_size);
    if (process->self_data == NULL) goto failed;
    memcpy(process->self_data, image, image_size);
    process->self_size = image_size;
    if (!elf_process_abi(process) || !linux_initial_stack(process, argc, argv, envc, envp)) goto failed;
    return process;
failed:
    xxemul_linux_destroy(process);
    return NULL;
}

void xxemul_linux_destroy(xxemul_linux_process *process)
{
    int index;
    if (process == NULL) return;
    if (process->syscall_stats_enabled) {
        size_t number;
        fprintf(stderr, "%s %s syscall total=%" PRIu64, process->freebsd ? "freebsd" : "linux", process->emulator->arch == XXEMUL_ARCH_X86 ? (process->is_64 ? "amd64" : "i386") :
            process->emulator->arch == XXEMUL_ARCH_ARM ? (process->is_64 ? "arm64" : "arm-eabi") :
            (process->big_endian ? "mips-o32-be" : "mips-o32-le"), process->syscall_total);
        for (number = 0; number < sizeof(process->syscall_counts) / sizeof(process->syscall_counts[0]); ++number) {
            if (process->syscall_counts[number] != 0u) fprintf(stderr, " %zu=%" PRIu64, number, process->syscall_counts[number]);
        }
        fputs(" first=", stderr);
        for (number = 0; number < process->first_syscall_count; ++number) fprintf(stderr, "%s%u", number == 0u ? "" : ",", process->first_syscalls[number]);
        fputc('\n', stderr);
    }
    for (index = 3; index < LINUX_MAX_FDS; ++index) {
        linux_file_save(&process->files[index]);
        free(process->files[index].data);
    }
    for (index = 0; index < LINUX_MAX_MAPS; ++index) free(process->maps[index].data);
    for (index = 0; index < (int)process->exec_argc; ++index) free(process->exec_argv[index]);
    for (index = 0; index < (int)process->exec_envc; ++index) free(process->exec_envp[index]);
    free(process->exec_owned_image);
    free(process->self_data);
    free(process);
}

void xxemul_linux_set_output(xxemul_linux_process *process, xxemul_linux_output_callback callback, void *context)
{
    if (process == NULL) return;
    process->output = callback;
    process->output_context = context;
}

int xxemul_linux_has_exited(const xxemul_linux_process *process)
{
    return process != NULL && process->exited;
}

int xxemul_linux_exit_code(const xxemul_linux_process *process)
{
    return process == NULL ? -1 : process->exit_code;
}

const uint8_t *xxemul_linux_exec_image(const xxemul_linux_process *process, size_t *size)
{
    const linux_file *file;
    if (size != NULL) *size = 0;
    if (process != NULL && process->exec_owned_image != NULL) {
        if (size != NULL) *size = process->exec_owned_size;
        return process->exec_owned_image;
    }
    if (process == NULL || process->exec_fd < 3 || process->exec_fd >= LINUX_MAX_FDS) return NULL;
    file = &process->files[process->exec_fd];
    if (!file->used) return NULL;
    if (size != NULL) *size = file->size;
    return file->data;
}

const char *xxemul_linux_working_directory(const xxemul_linux_process *process)
{
    return process == NULL ? NULL : process->workdir;
}

const char *xxemul_linux_exec_path(const xxemul_linux_process *process)
{
    return xxemul_linux_exec_image(process, NULL) == NULL ? NULL : process->exec_path;
}

int xxemul_linux_exec_is_at(const xxemul_linux_process *process)
{
    return process != NULL && process->exec_is_at;
}

int xxemul_linux_exec_dirfd(const xxemul_linux_process *process)
{
    return process == NULL ? -1 : process->exec_dirfd;
}

uint64_t xxemul_linux_exec_flags(const xxemul_linux_process *process)
{
    return process == NULL ? 0u : process->exec_flags;
}

size_t xxemul_linux_exec_argc(const xxemul_linux_process *process)
{
    return process == NULL ? 0u : process->exec_argc;
}

const char *xxemul_linux_exec_argument(const xxemul_linux_process *process, size_t index)
{
    return process == NULL || index >= process->exec_argc ? NULL : process->exec_argv[index];
}

size_t xxemul_linux_exec_envc(const xxemul_linux_process *process)
{
    return process == NULL ? 0u : process->exec_envc;
}

const char *xxemul_linux_exec_environment(const xxemul_linux_process *process, size_t index)
{
    return process == NULL || index >= process->exec_envc ? NULL : process->exec_envp[index];
}

uint64_t xxemul_linux_segment_base(const xxemul_linux_process *process, unsigned segment_index, uint16_t selector)
{
    unsigned entry = selector >> 3;
    if (process == NULL) return 0;
    if (process->is_64) {
        if (segment_index == XXEMUL_X86_FS) return process->fs_base;
        if (segment_index == XXEMUL_X86_GS) return process->gs_base;
    }
    if ((segment_index == XXEMUL_X86_FS || segment_index == XXEMUL_X86_GS) && entry >= 6u && entry <= 8u) return process->tls_base[entry - 6u];
    return 0;
}

static uint64_t linux_arg(xxemul_linux_process *process, unsigned index)
{
    static const unsigned amd64[] = {XXEMUL_X86_RDI, XXEMUL_X86_RSI, XXEMUL_X86_RDX, XXEMUL_X86_R10, XXEMUL_X86_R8, XXEMUL_X86_R9};
    static const unsigned i386[] = {XXEMUL_X86_RBX, XXEMUL_X86_RCX, XXEMUL_X86_RDX, XXEMUL_X86_RSI, XXEMUL_X86_RDI, XXEMUL_X86_RBP};
    xxemul *emulator = process->emulator;
    uint64_t value;
    if (process->freebsd) return index < 8u ? process->freebsd_arguments[index] : 0;
    if (index >= 6u) return 0;
    if (emulator->arch == XXEMUL_ARCH_ARM)
        return emulator->arm.gpr[index] & (process->is_64 ? UINT64_MAX : UINT32_MAX);
    if (emulator->arch == XXEMUL_ARCH_MIPS) {
        if (index < 4u) return emulator->mips.gpr[4u + index];
        /* The o32 caller reserves four argument slots even for register args. */
        if (!linux_guest_value(process, (uint64_t)emulator->mips.gpr[29] + index * 4u, 4u, &value)) {
            process->argument_fault = 1;
            return 0;
        }
        return value;
    }
    return emulator->x86.gpr[process->is_64 ? amd64[index] : i386[index]] & (process->is_64 ? UINT64_MAX : UINT32_MAX);
}

static void linux_result(xxemul_linux_process *process, uint64_t result)
{
    xxemul *emulator = process->emulator;
    if (process->freebsd) {
        int error = result >= (uint64_t)-(int64_t)4095;
        uint32_t value = error ? (uint32_t)(0u - result) : (uint32_t)result;
        if (error && value == LINUX_ENOSYS) value = 78; /* FreeBSD ENOSYS */
        emulator->x86.gpr[XXEMUL_X86_RAX] = value;
        emulator->x86.flags = (emulator->x86.flags & ~UINT64_C(1)) | (unsigned)error;
    } else if (emulator->arch == XXEMUL_ARCH_ARM) {
        emulator->arm.gpr[0] = process->is_64 ? result : (uint32_t)result;
    } else if (emulator->arch == XXEMUL_ARCH_MIPS) {
        int error = result >= (uint64_t)-(int64_t)4095;
        uint32_t value = error ? (uint32_t)(0u - result) : (uint32_t)result;
        /* Most errno values used here are common; ENOSYS differs on MIPS. */
        if (error && value == LINUX_ENOSYS) value = 89u;
        emulator->mips.gpr[2] = value;
        emulator->mips.gpr[7] = error ? 1u : 0u;
    } else emulator->x86.gpr[XXEMUL_X86_RAX] = process->is_64 ? result : (uint32_t)result;
}

static int linux_host_path(xxemul_linux_process *process, const char *guest, char *host, size_t capacity)
{
    const char *name = guest;
    const char separator =
#if defined(_WIN32)
        '\\';
#else
        '/';
#endif
    size_t root_size = strlen(process->workdir);
    size_t name_size;
    if (name[0] == '.' && name[1] == '/') name += 2;
    name_size = strlen(name);
    if (name_size == 0 || name_size > 255u || strstr(name, "..") != NULL || strchr(name, '/') != NULL || strchr(name, '\\') != NULL || strchr(name, ':') != NULL ||
        root_size + name_size + 2u > capacity)
        return 0;
    memcpy(host, process->workdir, root_size);
    if (root_size > 0 && host[root_size - 1u] != '\\' && host[root_size - 1u] != '/') host[root_size++] = separator;
    memcpy(host + root_size, name, name_size + 1u);
    return 1;
}

static uint64_t linux_open(xxemul_linux_process *process, const char *guest, uint64_t flags, int memfd)
{
    linux_file *file;
    int fd = linux_new_fd(process);
    int exists;
    if (process->emulator->arch == XXEMUL_ARCH_MIPS) {
        uint64_t original = flags;
        flags &= ~UINT64_C(0x548);
        if (original & 0x100u) flags |= 0x40u; /* O_CREAT */
        if (original & 0x008u) flags |= 0x400u; /* O_APPEND */
    }
    if (process->syscall_stats_enabled && !memfd) fprintf(stderr, "linux open path=\"%s\" flags=0x%" PRIx64 "\n", guest, flags);
    if (fd < 0) return linux_error(LINUX_ENOMEM);
    file = &process->files[fd];
    file->writable = memfd || (flags & 3u) != 0u;
    if (memfd) return (uint64_t)fd;
    if (strcmp(guest, "/proc/self/exe") == 0 || strcmp(guest, process->self_path) == 0) {
        file->data = (uint8_t *)malloc(process->self_size + 1u);
        if (file->data == NULL) goto no_memory;
        memcpy(file->data, process->self_data, process->self_size);
        file->size = file->capacity = process->self_size;
        file->self = 1;
        file->writable = 0;
        return (uint64_t)fd;
    }
    if (!process->freebsd && strcmp(guest, "/proc/self/auxv") == 0) {
        if ((flags & 3u) != 0u) {
            memset(file, 0, sizeof(*file));
            return linux_error(LINUX_EACCES);
        }
        file->data = (uint8_t *)malloc(process->auxv_size + 1u);
        if (file->data == NULL) goto no_memory;
        memcpy(file->data, process->auxv_data, process->auxv_size);
        file->size = file->capacity = process->auxv_size;
        file->writable = 0;
        return (uint64_t)fd;
    }
    if (!linux_host_path(process, guest, file->host_path, sizeof(file->host_path))) {
        memset(file, 0, sizeof(*file));
        return linux_error(LINUX_EPERM);
    }
    exists = xx_io_file_exists_a(file->host_path);
    if (!exists && (flags & 0x40u) == 0u) {
        memset(file, 0, sizeof(*file));
        return linux_error(LINUX_ENOENT);
    }
    if (exists && (flags & 0x200u) == 0u) {
        file->data = linux_read_file(file->host_path, &file->size);
        if (file->data == NULL) goto no_memory;
        file->capacity = file->size;
    }
    if (!exists || (flags & 0x200u) != 0u) file->dirty = 1;
    if ((flags & 0x400u) != 0u) file->offset = file->size;
    return (uint64_t)fd;
no_memory:
    free(file->data);
    memset(file, 0, sizeof(*file));
    return linux_error(LINUX_ENOMEM);
}

static void linux_sync_file_maps(xxemul_linux_process *process, int fd, uint64_t offset, size_t size)
{
    linux_file *file = linux_fd(process, fd);
    int index;
    if (file == NULL) return;
    for (index = 0; index < LINUX_MAX_MAPS; ++index) {
        linux_map *map = &process->maps[index];
        uint64_t begin, end;
        if (!map->used || !map->shared || map->fd != fd) continue;
        begin = offset > map->file_offset ? offset : map->file_offset;
        end = offset + size;
        if (end > map->file_offset + map->size) end = map->file_offset + map->size;
        if (end > begin) memcpy(map->data + begin - map->file_offset, file->data + begin, (size_t)(end - begin));
    }
}

static uint64_t linux_file_write(xxemul_linux_process *process, int fd, uint64_t guest_address, uint64_t count, uint64_t offset, int advance)
{
    linux_file *file = linux_fd(process, fd);
    uint8_t *buffer;
    if (file == NULL || !file->open) return linux_error(LINUX_EBADF);
    if (!file->writable) return linux_error(LINUX_EACCES);
    if (count > LINUX_MAX_FILE || offset > LINUX_MAX_FILE || count > LINUX_MAX_FILE - offset) return linux_error(LINUX_EFBIG);
    if (count == 0) return 0;
    buffer = (uint8_t *)malloc((size_t)count);
    if (buffer == NULL) return linux_error(LINUX_ENOMEM);
    if (!linux_guest_read(process, guest_address, buffer, (size_t)count)) {
        free(buffer);
        return linux_error(LINUX_EFAULT);
    }
    if (!linux_file_reserve(file, (size_t)(offset + count))) {
        free(buffer);
        return linux_error(LINUX_ENOMEM);
    }
    memcpy(file->data + offset, buffer, (size_t)count);
    linux_sync_file_maps(process, fd, offset, (size_t)count);
    free(buffer);
    file->dirty = file->host_path[0] != '\0';
    if (advance) file->offset = offset + count;
    return count;
}

static uint64_t linux_write(xxemul_linux_process *process, int fd, uint64_t address, uint64_t count)
{
    if (fd == 1 || fd == 2) {
        uint8_t *bytes;
        if (count > 1024u * 1024u) return linux_error(LINUX_EINVAL);
        if (count == 0) return 0;
        bytes = (uint8_t *)malloc((size_t)count);
        if (bytes == NULL) return linux_error(LINUX_ENOMEM);
        if (!linux_guest_read(process, address, bytes, (size_t)count)) {
            free(bytes);
            return linux_error(LINUX_EFAULT);
        }
        if (process->output != NULL) process->output(process->output_context, fd, bytes, (size_t)count);
        free(bytes);
        return count;
    }
    if (fd < 3) return linux_error(LINUX_EBADF);
    {
        linux_file *file = linux_fd(process, fd);
        if (file == NULL) return linux_error(LINUX_EBADF);
        return linux_file_write(process, fd, address, count, file->offset, 1);
    }
}

static uint64_t linux_read(xxemul_linux_process *process, int fd, uint64_t address, uint64_t count)
{
    linux_file *file = linux_fd(process, fd);
    size_t available;
    if (fd == 0) return 0;
    if (file == NULL || !file->open) return linux_error(LINUX_EBADF);
    if (file->offset >= file->size) return 0;
    available = file->size - (size_t)file->offset;
    if (count < available) available = (size_t)count;
    if (!linux_guest_write(process, address, file->data + file->offset, available)) return linux_error(LINUX_EFAULT);
    file->offset += available;
    return available;
}

static uint64_t linux_writev(xxemul_linux_process *process, int fd, uint64_t vector, uint64_t count)
{
    uint64_t result = 0;
    uint64_t index;
    unsigned width = process->is_64 ? 8u : 4u;
    if (count > 1024u) return linux_error(LINUX_EINVAL);
    for (index = 0; index < count; ++index) {
        uint64_t address, size, written;
        uint64_t entry = vector + index * width * 2u;
        if (!linux_guest_value(process, entry, width, &address) || !linux_guest_value(process, entry + width, width, &size)) return linux_error(LINUX_EFAULT);
        if (size > 1024u * 1024u || result > 1024u * 1024u - size) return linux_error(LINUX_EINVAL);
        written = linux_write(process, fd, address, size);
        if ((int64_t)written < 0) return written;
        result += written;
        if (written != size) break;
    }
    return result;
}

static uint64_t linux_lseek(xxemul_linux_process *process, int fd, int64_t displacement, uint64_t whence)
{
    linux_file *file = linux_fd(process, fd);
    uint64_t base;
    uint64_t position;
    if (file == NULL || !file->open) return linux_error(LINUX_EBADF);
    if (whence > 2u) return linux_error(LINUX_EINVAL);
    base = whence == 1u ? file->offset : (whence == 2u ? file->size : 0u);
    if (displacement < 0) {
        uint64_t negative = (uint64_t)(-(displacement + 1)) + 1u;
        if (negative > base) return linux_error(LINUX_EINVAL);
        position = base - negative;
    } else {
        if ((uint64_t)displacement > LINUX_MAX_FILE - base) return linux_error(LINUX_EINVAL);
        position = base + (uint64_t)displacement;
    }
    file->offset = position;
    return position;
}

/* Linux stat layouts differ even between 32-bit ABIs. Store each field in
 * guest byte order rather than copying a host structure. */
static int linux_stat_buffer(xxemul_linux_process *process, uint64_t address, uint64_t size)
{
    uint8_t data[144];
    size_t length;
    memset(data, 0, sizeof(data));
    if (process->emulator->arch == XXEMUL_ARCH_MIPS) {
        length = process->legacy_stat ? 144u : 104u;
        linux_put_value(process, data, 0, 1, 4);
        linux_put_value(process, data, 16, 1, process->legacy_stat ? 4 : 8);
        linux_put_value(process, data, process->legacy_stat ? 20 : 24, 0100644u, 4);
        linux_put_value(process, data, process->legacy_stat ? 24 : 28, 1, 4);
        linux_put_value(process, data, process->legacy_stat ? 48 : 56, size, process->legacy_stat ? 4 : 8);
        linux_put_value(process, data, process->legacy_stat ? 80 : 88, 4096, 4);
        linux_put_value(process, data, process->legacy_stat ? 84 : 96, (size + 511u) / 512u, process->legacy_stat ? 4 : 8);
    } else if (process->emulator->arch == XXEMUL_ARCH_ARM) {
        if (process->is_64) {
            length = 128u;
            linux_put_value(process, data, 0, 1, 8);
            linux_put_value(process, data, 8, 1, 8);
            linux_put_value(process, data, 16, 0100644u, 4);
            linux_put_value(process, data, 20, 1, 4);
            linux_put_value(process, data, 48, size, 8);
            linux_put_value(process, data, 56, 4096, 4);
            linux_put_value(process, data, 64, (size + 511u) / 512u, 8);
        } else if (process->legacy_stat) {
            length = 64u;
            linux_put_value(process, data, 0, 1, 4);
            linux_put_value(process, data, 4, 1, 4);
            linux_put_value(process, data, 8, 0100644u, 2);
            linux_put_value(process, data, 10, 1, 2);
            linux_put_value(process, data, 20, size, 4);
            linux_put_value(process, data, 24, 4096, 4);
            linux_put_value(process, data, 28, (size + 511u) / 512u, 4);
        } else {
            length = 104u;
            linux_put_value(process, data, 0, 1, 8);
            linux_put_value(process, data, 12, 1, 4);
            linux_put_value(process, data, 16, 0100644u, 4);
            linux_put_value(process, data, 20, 1, 4);
            linux_put_value(process, data, 48, size, 8);
            linux_put_value(process, data, 56, 4096, 4);
            linux_put_value(process, data, 64, (size + 511u) / 512u, 8);
            linux_put_value(process, data, 96, 1, 8);
        }
    } else if (process->is_64) {
        length = 144u;
        linux_put_value(process, data, 0, 1, 8);
        linux_put_value(process, data, 8, 1, 8);
        linux_put_value(process, data, 16, 1, 8);
        linux_put_value(process, data, 24, 0100644u, 4);
        linux_put_value(process, data, 48, size, 8);
        linux_put_value(process, data, 56, 4096, 8);
        linux_put_value(process, data, 64, (size + 511u) / 512u, 8);
    } else {
        length = 96u;
        linux_put_value(process, data, 0, 1, 8);
        linux_put_value(process, data, 12, 1, 4);
        linux_put_value(process, data, 16, 0100644u, 4);
        linux_put_value(process, data, 20, 1, 4);
        linux_put_value(process, data, 44, size, 8);
        linux_put_value(process, data, 52, 4096, 4);
        linux_put_value(process, data, 56, (size + 511u) / 512u, 8);
        linux_put_value(process, data, 88, 1, 8);
    }
    return linux_guest_write(process, address, data, length);
}

static int linux_host_size(xxemul_linux_process *process, const char *guest, uint64_t *size)
{
    char path[1024];
    xx_io_device *io;
    int64_t length;
    if (strcmp(guest, "/proc/self/exe") == 0 || strcmp(guest, process->self_path) == 0) {
        *size = process->self_size;
        return 1;
    }
    if (!linux_host_path(process, guest, path, sizeof(path))) return 0;
    io = xx_io_file_open(path, "rb");
    if (io == NULL) return 0;
    length = xx_io_total_size(io);
    xx_io_close(io);
    if (length < 0) return 0;
    *size = (uint64_t)length;
    return 1;
}

static uint64_t linux_fstat(xxemul_linux_process *process, int fd, uint64_t address)
{
    linux_file *file;
    if (fd >= 0 && fd <= 2) return linux_stat_buffer(process, address, 0) ? 0 : linux_error(LINUX_EFAULT);
    file = linux_fd(process, fd);
    if (file == NULL || !file->open) return linux_error(LINUX_EBADF);
    return linux_stat_buffer(process, address, file->size) ? 0 : linux_error(LINUX_EFAULT);
}

static uint64_t linux_stat(xxemul_linux_process *process, uint64_t path_address, uint64_t result_address)
{
    char guest[1024];
    uint64_t size;
    if (!linux_guest_string(process, path_address, guest, sizeof(guest))) return linux_error(LINUX_EFAULT);
    if (!linux_host_size(process, guest, &size)) return linux_error(LINUX_ENOENT);
    return linux_stat_buffer(process, result_address, size) ? 0 : linux_error(LINUX_EFAULT);
}

static uint64_t linux_statx(xxemul_linux_process *process)
{
    char guest[1024];
    uint8_t data[256];
    uint64_t size;
    uint64_t address = linux_arg(process, 4);
    int fd = (int)(int32_t)linux_arg(process, 0);
    if (!linux_guest_string(process, linux_arg(process, 1), guest, sizeof(guest))) return linux_error(LINUX_EFAULT);
    if (guest[0] == '\0' && (linux_arg(process, 2) & 0x1000u) != 0u) {
        linux_file *file = linux_fd(process, fd);
        if (file == NULL) return linux_error(LINUX_EBADF);
        size = file->size;
    } else if (!linux_host_size(process, guest, &size)) {
        return linux_error(LINUX_ENOENT);
    }
    memset(data, 0, sizeof(data));
    linux_put_value(process, data, 0, 0x7ffu, 4);
    linux_put_value(process, data, 4, 4096u, 4);
    linux_put_value(process, data, 16, 1u, 4);
    linux_put_value(process, data, 28, 0100644u, 2);
    linux_put_value(process, data, 32, 1u, 8);
    linux_put_value(process, data, 40, size, 8);
    linux_put_value(process, data, 48, (size + 511u) / 512u, 8);
    return linux_guest_write(process, address, data, sizeof(data)) ? 0 : linux_error(LINUX_EFAULT);
}

static uint64_t linux_mmap(xxemul_linux_process *process, uint64_t address, uint64_t length, uint64_t flags, int fd, uint64_t offset)
{
    uint64_t size;
    linux_file *file = NULL;
    linux_map *map = NULL;
    int index;
    if (length == 0 || length > LINUX_MAX_MAP || length > UINT64_MAX - LINUX_PAGE + 1u) return linux_error(LINUX_EINVAL);
    size = linux_align_up(length, LINUX_PAGE);
    if (size > LINUX_MAX_MAP) return linux_error(LINUX_ENOMEM);
    if ((flags & 0x20u) == 0u) {
        file = linux_fd(process, fd);
        if (file == NULL || !file->open) return linux_error(LINUX_EBADF);
    }
    if ((flags & 0x10u) != 0u) {
        if ((address & (LINUX_PAGE - 1u)) != 0u || address == 0u) return linux_error(LINUX_EINVAL);
        if (address > UINT64_MAX - size) return linux_error(LINUX_ENOMEM);
    } else {
        uint64_t original_start = process->emulator->region_address;
        uint64_t original_end = original_start + process->emulator->region_size;
        uint64_t ceiling = process->is_64 ? UINT64_C(0x700000000000) : UINT64_C(0xf0000000);
        if (address == 0 || (address & (LINUX_PAGE - 1u)) != 0u) address = process->next_map;
        if (address > ceiling - size - (LINUX_PAGE - 1u)) address = process->next_map;
        address = linux_align_up(address, LINUX_PAGE);
        for (;;) {
            int conflict = address < original_end && original_start < address + size;
            if (!conflict) {
                for (index = 0; index < LINUX_MAX_MAPS; ++index) {
                    linux_map *candidate = &process->maps[index];
                    if (candidate->used && address < candidate->base + candidate->size && candidate->base < address + size) {
                        conflict = 1;
                        break;
                    }
                }
            }
            if (!conflict) break;
            if (address > ceiling - size) return linux_error(LINUX_ENOMEM);
            address = linux_align_up(address + size, LINUX_PAGE);
        }
        process->next_map = address + size;
    }
    if (!process->is_64 && (address > UINT32_MAX || size > UINT32_MAX - address)) return linux_error(LINUX_ENOMEM);
    for (index = 0; index < LINUX_MAX_MAPS; ++index) {
        if (!process->maps[index].used) {
            map = &process->maps[index];
            break;
        }
    }
    if (map == NULL) return linux_error(LINUX_ENOMEM);
    map->data = (uint8_t *)calloc(1u, (size_t)size);
    if (map->data == NULL) return linux_error(LINUX_ENOMEM);
    map->base = address;
    map->size = size;
    map->fd = file == NULL ? -1 : fd;
    map->file_offset = offset;
    map->shared = file != NULL && (flags & 1u) != 0u;
    map->generation = ++process->map_generation;
    map->used = 1;
    if (file != NULL && offset < file->size) {
        size_t available = file->size - (size_t)offset;
        if (available > (size_t)size) available = (size_t)size;
        memcpy(map->data, file->data + offset, available);
    }
    return address;
}

static uint64_t linux_munmap(xxemul_linux_process *process, uint64_t address, uint64_t length)
{
    int index;
    if (length == 0 || (address & (LINUX_PAGE - 1u)) != 0u) return linux_error(LINUX_EINVAL);
    if (address > UINT64_MAX - length) return linux_error(LINUX_EINVAL);
    for (index = 0; index < LINUX_MAX_MAPS; ++index) {
        linux_map *map = &process->maps[index];
        if (map->used && address <= map->base && length >= map->size && address + length >= map->base + map->size) {
            free(map->data);
            memset(map, 0, sizeof(*map));
        }
    }
    return 0;
}

static uint64_t linux_brk(xxemul_linux_process *process, uint64_t requested)
{
    if (process->brk_base == 0u) {
        uint64_t result = linux_mmap(process, 0, 16u * 1024u * 1024u, 0x22u, -1, 0);
        if ((int64_t)result < 0) return 0;
        process->brk_base = result;
        process->brk_current = result;
    }
    if (requested >= process->brk_base && requested <= process->brk_base + 16u * 1024u * 1024u) process->brk_current = requested;
    return process->brk_current;
}

static uint64_t linux_readlink(xxemul_linux_process *process, uint64_t address, uint64_t output, uint64_t capacity)
{
    char guest[1024];
    size_t length;
    if (!linux_guest_string(process, address, guest, sizeof(guest))) return linux_error(LINUX_EFAULT);
    if (strcmp(guest, "/proc/self/exe") != 0) return linux_error(LINUX_ENOENT);
    length = strlen(process->self_path);
    if (capacity < length) length = (size_t)capacity;
    return linux_guest_write(process, output, process->self_path, length) ? length : linux_error(LINUX_EFAULT);
}

static int linux_fd_path(const char *path)
{
    const char *marker = strstr(path, "/fd/");
    char *end;
    long fd;
    if (marker == NULL) return -1;
    fd = strtol(marker + 4, &end, 10);
    if (end == marker + 4 || *end != '\0' || fd < 3 || fd >= LINUX_MAX_FDS) return -1;
    return (int)fd;
}

static void linux_clear_exec_vectors(xxemul_linux_process *process)
{
    size_t index;
    for (index = 0; index < process->exec_argc; ++index) {
        free(process->exec_argv[index]);
        process->exec_argv[index] = NULL;
    }
    for (index = 0; index < process->exec_envc; ++index) {
        free(process->exec_envp[index]);
        process->exec_envp[index] = NULL;
    }
    process->exec_argc = 0;
    process->exec_envc = 0;
}

static unsigned linux_capture_exec_vector(xxemul_linux_process *process, uint64_t address, char **strings, size_t *count)
{
    unsigned width = process->is_64 ? 8u : 4u;
    size_t index;
    *count = 0;
    if (address == 0u) return 0;
    for (index = 0; index <= LINUX_MAX_EXEC_STRINGS; ++index) {
        uint64_t string_address;
        char buffer[4096];
        size_t length;
        if (!linux_guest_value(process, address + index * width, width, &string_address)) return LINUX_EFAULT;
        if (string_address == 0u) return 0;
        if (index == LINUX_MAX_EXEC_STRINGS) return 7u; /* E2BIG */
        if (!linux_guest_string(process, string_address, buffer, sizeof(buffer))) return LINUX_EFAULT;
        length = strlen(buffer) + 1u;
        strings[index] = (char *)malloc(length);
        if (strings[index] == NULL) return LINUX_ENOMEM;
        memcpy(strings[index], buffer, length);
        *count = index + 1u;
    }
    return 7u;
}

static uint64_t linux_execve(xxemul_linux_process *process, int at)
{
    int fd = -1;
    char path[1024];
    char host_path[1024];
    uint8_t *owned_image = NULL;
    size_t owned_size = 0;
    unsigned error;
    linux_file *file;
    uint64_t path_address = linux_arg(process, at ? 1u : 0u);
    uint64_t flags = at ? linux_arg(process, 4) : 0u;
    if (process->argument_fault) return linux_error(LINUX_EFAULT);
    if (at && (flags & ~UINT64_C(0x1100)) != 0u) return linux_error(LINUX_EINVAL);
    if (!linux_guest_string(process, path_address, path, sizeof(path))) return linux_error(LINUX_EFAULT);
    if (process->syscall_stats_enabled) fprintf(stderr, "linux exec path=\"%s\" flags=0x%" PRIx64 "\n", path, flags);
    if (at && path[0] == '\0' && (flags & 0x1000u) != 0u) {
        fd = (int)(int32_t)linux_arg(process, 0);
    } else {
        if (path[0] == '\0') return linux_error(LINUX_ENOENT);
        fd = linux_fd_path(path);
    }
    file = linux_fd(process, fd);
    if (file == NULL || !file->open) {
        fd = -1;
        if (strcmp(path, process->self_path) == 0 || strcmp(path, "/proc/self/exe") == 0) {
            owned_image = (uint8_t *)malloc(process->self_size);
            if (owned_image == NULL) return linux_error(LINUX_ENOMEM);
            memcpy(owned_image, process->self_data, process->self_size);
            owned_size = process->self_size;
        } else if (linux_host_path(process, path, host_path, sizeof(host_path))) {
            owned_image = linux_read_file(host_path, &owned_size);
            if (owned_image == NULL) return linux_error(LINUX_ENOENT);
        } else {
            return linux_error(LINUX_ENOENT);
        }
    }
    linux_clear_exec_vectors(process);
    error = linux_capture_exec_vector(process, linux_arg(process, at ? 2u : 1u), process->exec_argv, &process->exec_argc);
    if (error == 0u) error = linux_capture_exec_vector(process, linux_arg(process, at ? 3u : 2u), process->exec_envp, &process->exec_envc);
    if (error != 0u) {
        linux_clear_exec_vectors(process);
        free(owned_image);
        return linux_error(error);
    }
    memcpy(process->exec_path, path, strlen(path) + 1u);
    process->exec_is_at = at;
    process->exec_dirfd = at ? (int)(int32_t)linux_arg(process, 0) : -1;
    process->exec_flags = flags;
    process->exec_owned_image = owned_image;
    process->exec_owned_size = owned_size;
    process->exec_fd = fd;
    process->exited = 1;
    process->exit_code = 0;
    process->emulator->halted = 1;
    return 0;
}

static uint64_t linux_dispatch_amd64(xxemul_linux_process *process, uint32_t number)
{
    uint64_t a = linux_arg(process, 0);
    uint64_t b = linux_arg(process, 1);
    uint64_t c = linux_arg(process, 2);
    uint64_t d = linux_arg(process, 3);
    uint64_t result;
    char path[1024];
    linux_file *file;
    switch (number) {
        case 0: return linux_read(process, (int)a, b, c);
        case 1: return linux_write(process, (int)a, b, c);
        case 2:
        case 257:
            if (!linux_guest_string(process, number == 257 ? b : a, path, sizeof(path))) return linux_error(LINUX_EFAULT);
            return linux_open(process, path, number == 257 ? c : b, 0);
        case 3:
            file = linux_fd(process, (int)a);
            if (file == NULL) return a < 3u ? 0 : linux_error(LINUX_EBADF);
            if (!file->open) return linux_error(LINUX_EBADF);
            if (!linux_file_save(file)) return linux_error(LINUX_EIO);
            file->open = 0;
            return 0;
        case 4:
        case 6: return linux_stat(process, a, b);
        case 5: return linux_fstat(process, (int)a, b);
        case 8: return linux_lseek(process, (int)a, (int64_t)b, c);
        case 9: return linux_mmap(process, a, b, d, (int)(int64_t)linux_arg(process, 4), linux_arg(process, 5));
        case 10: return 0; /* page permissions are not enforced by flat memory */
        case 11: return linux_munmap(process, a, b);
        case 12: return linux_brk(process, a);
        case 18: return linux_file_write(process, (int)a, b, c, d, 0);
        case 20: return linux_writev(process, (int)a, b, c);
        case 26: return 0; /* shared mappings are synchronized on every write */
        case 32:
        case 33: return a; /* no independent cursor is needed by the packer */
        case 59: return linux_execve(process, 0);
        case 60:
        case 231:
            process->exited = 1;
            process->exit_code = (int)(a & 255u);
            process->emulator->halted = 1;
            return 0;
        case 77:
            file = linux_fd(process, (int)a);
            if (file == NULL || !file->open) return linux_error(LINUX_EBADF);
            if (!file->writable) return linux_error(LINUX_EACCES);
            if (b > LINUX_MAX_FILE) return linux_error(LINUX_EFBIG);
            if (!linux_file_reserve(file, (size_t)b)) return linux_error(LINUX_ENOMEM);
            file->size = (size_t)b;
            file->dirty = file->host_path[0] != '\0';
            return 0;
        case 89: return linux_readlink(process, a, b, c);
        case 158:
            if (a == 0x1002u) {
                process->fs_base = b;
                return 0;
            }
            if (a == 0x1001u) {
                process->gs_base = b;
                return 0;
            }
            if (a == 0x1003u || a == 0x1004u)
                return linux_guest_store(process, b, 8u, a == 0x1003u ? process->fs_base : process->gs_base) ? 0 : linux_error(LINUX_EFAULT);
            return linux_error(LINUX_EINVAL);
        case 262:
            if (d & 0x1000u) {
                if (!linux_guest_string(process, b, path, sizeof(path))) return linux_error(LINUX_EFAULT);
                if (path[0] == '\0') return linux_fstat(process, (int)a, c);
            }
            return linux_stat(process, b, c);
        case 267: return linux_readlink(process, b, c, d);
        case 319: return linux_open(process, "", 0, 1);
        case 322: return linux_execve(process, 1);
        case 332: return linux_statx(process);
        case 13:
        case 14:
        case 21:
        case 218:
        case 273:
        case 302:
        case 334: return 0;
        case 228: return linux_guest_store(process, b, 8u, 0) && linux_guest_store(process, b + 8u, 8u, 0) ? 0 : linux_error(LINUX_EFAULT);
        case 318:
            if (b > 4096u) return linux_error(LINUX_EINVAL);
            if (b != 0u) {
                uint8_t bytes[4096];
                memset(bytes, 0x5au, (size_t)b);
                if (!linux_guest_write(process, a, bytes, (size_t)b)) return linux_error(LINUX_EFAULT);
            }
            return b;
        default: result = linux_error(LINUX_ENOSYS); return result;
    }
}

static uint64_t linux_dispatch_i386(xxemul_linux_process *process, uint32_t number)
{
    uint64_t a = linux_arg(process, 0);
    uint64_t b = linux_arg(process, 1);
    uint64_t c = linux_arg(process, 2);
    uint64_t d = linux_arg(process, 3);
    char path[1024];
    linux_file *file;
    uint64_t value;
    switch (number) {
        case 1:
        case 252:
            process->exited = 1;
            process->exit_code = (int)(a & 255u);
            process->emulator->halted = 1;
            return 0;
        case 3: return linux_read(process, (int)a, b, c);
        case 4: return linux_write(process, (int)a, b, c);
        case 5:
        case 295:
            if (!linux_guest_string(process, number == 295 ? b : a, path, sizeof(path))) return linux_error(LINUX_EFAULT);
            return linux_open(process, path, number == 295 ? c : b, 0);
        case 6:
            file = linux_fd(process, (int)a);
            if (file == NULL) return a < 3u ? 0 : linux_error(LINUX_EBADF);
            if (!file->open) return linux_error(LINUX_EBADF);
            if (!linux_file_save(file)) return linux_error(LINUX_EIO);
            file->open = 0;
            return 0;
        case 11: return linux_execve(process, 0);
        case 19: return linux_lseek(process, (int)a, (int32_t)b, c);
        case 41:
        case 63: return a;
        case 45: return linux_brk(process, a);
        case 85: return linux_readlink(process, a, b, c);
        case 90: {
            uint64_t args[6];
            unsigned index;
            for (index = 0; index < 6u; ++index) {
                if (!linux_guest_value(process, a + index * 4u, 4u, &args[index])) return linux_error(LINUX_EFAULT);
            }
            return linux_mmap(process, args[0], args[1], args[3], (int)(int32_t)args[4], args[5]);
        }
        case 91: return linux_munmap(process, a, b);
        case 93:
        case 194:
            file = linux_fd(process, (int)a);
            if (file == NULL || !file->open) return linux_error(LINUX_EBADF);
            if (!file->writable) return linux_error(LINUX_EACCES);
            if (b > LINUX_MAX_FILE || !linux_file_reserve(file, (size_t)b)) return linux_error(LINUX_EFBIG);
            file->size = (size_t)b;
            file->dirty = file->host_path[0] != '\0';
            return 0;
        case 125: return 0;
        case 140: {
            uint64_t whence = linux_arg(process, 4);
            if (process->argument_fault) return linux_error(LINUX_EFAULT);
            value = linux_lseek(process, (int)a, (int64_t)((b << 32) | c), whence);
            if ((int64_t)value < 0) return value;
            return linux_guest_store(process, d, 8u, value) ? 0 : linux_error(LINUX_EFAULT);
        }
        case 144: return 0;
        case 146: return linux_writev(process, (int)a, b, c);
        case 175:
        case 174:
        case 258:
        case 311:
        case 33: return 0;
        case 181: return linux_file_write(process, (int)a, b, c, ((uint64_t)linux_arg(process, 4) << 32) | d, 0);
        case 192: return linux_mmap(process, a, b, d, (int)(int32_t)linux_arg(process, 4), linux_arg(process, 5) * LINUX_PAGE);
        case 195:
        case 196: return linux_stat(process, a, b);
        case 197: return linux_fstat(process, (int)a, b);
        case 243: {
            uint64_t descriptor = a;
            uint64_t entry, base;
            if (!linux_guest_value(process, descriptor, 4u, &entry) || !linux_guest_value(process, descriptor + 4u, 4u, &base)) return linux_error(LINUX_EFAULT);
            if (entry == UINT32_MAX) entry = 6u;
            if (entry < 6u || entry > 8u) return linux_error(LINUX_EINVAL);
            if (!linux_guest_store(process, descriptor, 4u, entry)) return linux_error(LINUX_EFAULT);
            process->tls_base[entry - 6u] = base;
            return 0;
        }
        case 305: return linux_readlink(process, b, c, d);
        case 356: return linux_open(process, "", 0, 1);
        case 358: return linux_execve(process, 1);
        case 383: return linux_statx(process);
        default: return linux_error(LINUX_ENOSYS);
    }
}

/* Reuse the service implementations above, translating ABI syscall numbers
 * only. Register extraction remains tied to the guest architecture. */
static uint64_t linux_dispatch_arm32(xxemul_linux_process *process, uint32_t number)
{
    uint64_t a = linux_arg(process, 0), b = linux_arg(process, 1);
    uint64_t c = linux_arg(process, 2);
    process->legacy_stat = number >= 106u && number <= 108u;
    switch (number) {
        case 1: case 3: case 4: case 5: case 6: case 11: case 19:
        case 33: case 41: case 45: case 63: case 85: case 91: case 93:
        case 125: case 140: case 144: case 146: case 174: case 175:
        case 192: case 195: case 196: case 197:
            return linux_dispatch_i386(process, number);
        case 106: case 107: return linux_stat(process, a, b);
        case 108: return linux_fstat(process, (int)a, b);
        case 20: case 64: case 224: return 1000; /* stable process identities */
        case 24: case 47: case 49: case 50: case 199: case 200: case 201: case 202: return 0;
        case 67: case 118: case 126: case 148: case 256: case 338: case 369:
        case 0xf0002: return 0; /* cacheflush: instruction memory is coherent */
        case 181: {
            /* EABI aligns a 64-bit syscall argument to an even register pair. */
            uint64_t offset = linux_arg(process, 4) | linux_arg(process, 5) << 32;
            return linux_file_write(process, (int)a, b, c, offset, 0);
        }
        case 194: {
            uint64_t length = c | linux_arg(process, 3) << 32;
            linux_file *file = linux_fd(process, (int)a);
            if (file == NULL || !file->open) return linux_error(LINUX_EBADF);
            if (!file->writable) return linux_error(LINUX_EACCES);
            if (length > LINUX_MAX_FILE || !linux_file_reserve(file, (size_t)length)) return linux_error(LINUX_EFBIG);
            file->size = (size_t)length;
            file->dirty = file->host_path[0] != '\0';
            return 0;
        }
        case 248: return linux_dispatch_i386(process, 1);
        case 263: return linux_guest_store(process, b, 4, 0) && linux_guest_store(process, b + 4, 4, 0) ? 0 : linux_error(LINUX_EFAULT);
        case 322: return linux_dispatch_i386(process, 295);
        case 327: return linux_dispatch_amd64(process, 262);
        case 332: return linux_dispatch_i386(process, 305);
        case 384: return linux_dispatch_amd64(process, 318);
        case 385: return linux_dispatch_i386(process, 356);
        case 387: return linux_dispatch_i386(process, 358);
        case 397: return linux_statx(process);
        default: return linux_error(LINUX_ENOSYS);
    }
}

static uint64_t linux_dispatch_arm64(xxemul_linux_process *process, uint32_t number)
{
    uint32_t service;
    switch (number) {
        case 23: service = 32; break; /* dup */
        case 24: service = 33; break; /* dup3 */
        case 46: service = 77; break;
        case 48: return 0;
        case 56: service = 257; break;
        case 57: service = 3; break;
        case 62: service = 8; break;
        case 63: service = 0; break;
        case 64: service = 1; break;
        case 66: service = 20; break;
        case 68: service = 18; break;
        case 78: service = 267; break;
        case 79: service = 262; break;
        case 80: service = 5; break;
        case 82: case 83: case 96: case 99: return 0;
        case 93: case 94: service = 60; break;
        case 113: service = 228; break;
        case 134: service = 13; break;
        case 135: service = 14; break;
        case 172: case 173: case 178: return 1000;
        case 174: case 175: case 176: case 177: return 0;
        case 214: service = 12; break;
        case 215: service = 11; break;
        case 221: service = 59; break;
        case 222: service = 9; break;
        case 226: service = 10; break;
        case 227: service = 26; break;
        case 261: service = 302; break;
        case 278: service = 318; break;
        case 279: service = 319; break;
        case 281: service = 322; break;
        case 291: return linux_statx(process);
        case 293: service = 334; break;
        default: return linux_error(LINUX_ENOSYS);
    }
    return linux_dispatch_amd64(process, service);
}

static uint64_t linux_mips_mmap(xxemul_linux_process *process, int pages)
{
    uint64_t flags = linux_arg(process, 3);
    uint64_t offset = linux_arg(process, 5);
    int fd = (int)(int32_t)linux_arg(process, 4);
    if (process->argument_fault) return linux_error(LINUX_EFAULT);
    /* MIPS MAP_ANONYMOUS is 0x800; the shared mapper uses generic 0x20. */
    flags = (flags & ~UINT64_C(0x820)) | ((flags & 0x800u) ? 0x20u : 0u);
    return linux_mmap(process, linux_arg(process, 0), linux_arg(process, 1), flags, fd, pages ? offset * LINUX_PAGE : offset);
}

static uint64_t linux_dispatch_mips32(xxemul_linux_process *process, uint32_t number)
{
    uint32_t service;
    uint64_t a = linux_arg(process, 0), b = linux_arg(process, 1);
    if (number < 4000u) return linux_error(LINUX_ENOSYS);
    number -= 4000u;
    process->legacy_stat = number >= 106u && number <= 108u;
    switch (number) {
        case 1: case 3: case 4: case 5: case 6: case 11: case 19: case 33:
        case 41: case 45: case 63: case 85: case 91: case 93: case 125:
        case 140: case 144: case 146: service = number; break;
        case 20: case 64: case 222: return 1000;
        case 24: case 47: case 49: case 50: return 0;
        case 67: case 118: case 126: case 147: case 148: case 152:
        case 194: case 195: case 252: case 283: case 309: case 338: return 0;
        case 90: return linux_mips_mmap(process, 0);
        case 106: case 107: return linux_stat(process, a, b);
        case 108: return linux_fstat(process, (int)a, b);
        case 201: {
            uint64_t low = linux_arg(process, process->big_endian ? 5 : 4);
            uint64_t high = linux_arg(process, process->big_endian ? 4 : 5);
            if (process->argument_fault) return linux_error(LINUX_EFAULT);
            return linux_file_write(process, (int)a, b, linux_arg(process, 2), (high << 32) | low, 0);
        }
        case 210: return linux_mips_mmap(process, 1);
        case 212: {
            uint64_t low = linux_arg(process, process->big_endian ? 3 : 2);
            uint64_t high = linux_arg(process, process->big_endian ? 2 : 3);
            uint64_t length = (high << 32) | low;
            linux_file *file = linux_fd(process, (int)a);
            if (file == NULL || !file->open) return linux_error(LINUX_EBADF);
            if (!file->writable) return linux_error(LINUX_EACCES);
            if (length > LINUX_MAX_FILE || !linux_file_reserve(file, (size_t)length)) return linux_error(LINUX_EFBIG);
            file->size = (size_t)length;
            file->dirty = file->host_path[0] != '\0';
            return 0;
        }
        case 213: case 214: return linux_stat(process, a, b);
        case 215: return linux_fstat(process, (int)a, b);
        case 246: service = 1; break;
        case 263: return linux_guest_store(process, b, 4, 0) && linux_guest_store(process, b + 4, 4, 0) ? 0 : linux_error(LINUX_EFAULT);
        case 288: service = 295; break;
        case 293: return linux_dispatch_amd64(process, 262);
        case 298: service = 305; break;
        case 353: return linux_dispatch_amd64(process, 318);
        case 354: service = 356; break;
        case 356: service = 358; break;
        case 366: return linux_statx(process);
        default: return linux_error(LINUX_ENOSYS);
    }
    return linux_dispatch_i386(process, service);
}

/* FreeBSD rounds mprotect's address down and its end up, and skips holes
 * while protecting existing mappings. Permissions remain advisory here. */
static uint64_t freebsd_mprotect(uint64_t address, uint64_t length)
{
    uint64_t size, page_offset = address & (LINUX_PAGE - 1u);
    address -= page_offset;
    if (length > UINT32_MAX - page_offset) return linux_error(LINUX_EINVAL);
    size = linux_align_up(length + page_offset, LINUX_PAGE);
    if (size > UINT32_MAX - address) return linux_error(LINUX_EINVAL);
    return 0;
}

/* FreeBSD/i386 INT80 uses EAX plus stack words after a dummy return PC.
 * SYS_syscall(0) adds one syscall-number word; __syscall(198) adds a quad.
 * The compat6 mmap(197) ABI includes an explicit pad before off_t. */
static uint64_t freebsd_dispatch_i386(xxemul_linux_process *process, uint32_t number)
{
    uint64_t parameters = (uint64_t)(uint32_t)process->emulator->x86.gpr[XXEMUL_X86_RSP] + 4u;
    uint64_t *args = process->freebsd_arguments;
    uint64_t value, offset, flags;
    unsigned count, index;
    char path[1024];
    linux_file *file;
    memset(args, 0, sizeof(process->freebsd_arguments));
    if (number == 0 || number == 198) {
        if (!linux_guest_value(process, parameters, 4, &value)) return linux_error(LINUX_EFAULT);
        parameters += number == 198 ? 8u : 4u;
        number = (uint32_t)value;
    }
    switch (number) {
        case 1: case 6: count = 1; break;
        case 3: case 4: case 5: case 74: case 121: count = 3; break;
        case 20: count = 0; break;
        case 73: count = 2; break;
        case 197: count = 8; break;
        case 477: count = 7; break;
        case 199: count = 5; break;
        default: return linux_error(LINUX_ENOSYS);
    }
    for (index = 0; index < count; ++index) {
        if (parameters > UINT32_MAX || 4u > UINT64_C(0x100000000) - parameters ||
            !linux_guest_value(process, parameters, 4, &args[index])) return linux_error(LINUX_EFAULT);
        parameters += 4;
    }
    switch (number) {
        case 1:
            process->exited = 1;
            process->exit_code = (int)(args[0] & 255u);
            process->emulator->halted = 1;
            return 0;
        case 3: return linux_read(process, (int)(int32_t)args[0], args[1], args[2]);
        case 4: return linux_write(process, (int)(int32_t)args[0], args[1], args[2]);
        case 5:
            if (!linux_guest_string(process, args[0], path, sizeof(path))) return linux_error(LINUX_EFAULT);
            if ((args[1] & ~UINT64_C(0x60b)) || (args[1] & 3u) == 3u) return linux_error(LINUX_EINVAL);
            /* FreeBSD O_CREAT/TRUNC/APPEND differ from their Linux bits. */
            flags = args[1] & 3u;
            if (args[1] & 0x200u) flags |= 0x40u;
            if (args[1] & 0x400u) flags |= 0x200u;
            if (args[1] & 0x8u) flags |= 0x400u;
            return linux_open(process, path, flags, 0);
        case 6:
            file = linux_fd(process, (int)args[0]);
            if (!file || !file->open) return args[0] < 3u ? 0 : linux_error(LINUX_EBADF);
            if (!linux_file_save(file)) return linux_error(LINUX_EIO);
            file->open = 0;
            return 0;
        case 20: return 1000;
        case 73: return linux_munmap(process, args[0], args[1]);
        case 74: return freebsd_mprotect(args[0], args[1]);
        case 121: return linux_writev(process, (int)(int32_t)args[0], args[1], args[2]);
        case 197: case 477:
            if ((args[2] & ~UINT64_C(7)) || (args[3] & ~UINT64_C(0x1013)) ||
                ((args[3] & 3u) != 1u && (args[3] & 3u) != 2u)) return linux_error(LINUX_EINVAL);
            offset = number == 197 ? (args[7] << 32) | args[6] : (args[6] << 32) | args[5];
            if ((offset & 4095u) || (offset & (UINT64_C(1) << 63))) return linux_error(LINUX_EINVAL);
            if ((args[3] & 0x1000u) && ((int32_t)args[4] != -1 || offset)) return linux_error(LINUX_EINVAL);
            flags = args[3] & 0x13u;
            if (args[3] & 0x1000u) flags |= 0x20u;
            return linux_mmap(process, args[0], args[1], flags, (int)(int32_t)args[4], offset);
        case 199:
            offset = (args[3] << 32) | args[2];
            value = linux_lseek(process, (int)(int32_t)args[0], (int64_t)offset, args[4]);
            if (value < (uint64_t)-(int64_t)4095) process->emulator->x86.gpr[XXEMUL_X86_RDX] = (uint32_t)(value >> 32);
            return value;
        default: return linux_error(LINUX_ENOSYS);
    }
}

xxemul_status xxemul_linux_dispatch(xxemul_linux_process *process)
{
    xxemul *emulator;
    uint32_t number;
    uint64_t result;
    if (process == NULL || process->emulator == NULL || process->exited) return XXEMUL_STATUS_INVALID_ARGUMENT;
    emulator = process->emulator;
    if (emulator->arch == XXEMUL_ARCH_ARM) number = (uint32_t)emulator->arm.gpr[process->is_64 ? 8 : 7];
    else if (emulator->arch == XXEMUL_ARCH_MIPS) number = emulator->mips.gpr[2];
    else number = (uint32_t)emulator->x86.gpr[XXEMUL_X86_RAX];
    if (process->syscall_stats_enabled) {
        uint32_t slot = emulator->arch == XXEMUL_ARCH_MIPS && number >= 4000u ? number - 4000u : number;
        ++process->syscall_total;
        if (slot < sizeof(process->syscall_counts) / sizeof(process->syscall_counts[0])) ++process->syscall_counts[slot];
        if (process->first_syscall_count < sizeof(process->first_syscalls) / sizeof(process->first_syscalls[0]))
            process->first_syscalls[process->first_syscall_count++] = number;
    }
    process->argument_fault = 0;
    process->legacy_stat = 0;
    if (process->freebsd) result = freebsd_dispatch_i386(process, number);
    else if (emulator->arch == XXEMUL_ARCH_ARM)
        result = process->is_64 ? linux_dispatch_arm64(process, number) : linux_dispatch_arm32(process, number);
    else if (emulator->arch == XXEMUL_ARCH_MIPS) result = linux_dispatch_mips32(process, number);
    else result = process->is_64 ? linux_dispatch_amd64(process, number) : linux_dispatch_i386(process, number);
    if (process->argument_fault) result = linux_error(LINUX_EFAULT);
    linux_result(process, result);
    return process->exited ? XXEMUL_STATUS_HALTED : XXEMUL_STATUS_OK;
}
