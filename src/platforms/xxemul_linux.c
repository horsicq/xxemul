#include "xxemul_linux.h"
#include "xxemul_internal.h"

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

static uint16_t linux_u16(const uint8_t *data)
{
    return (uint16_t)(data[0] | (uint16_t)data[1] << 8);
}

static uint32_t linux_u32(const uint8_t *data)
{
    return (uint32_t)data[0] | (uint32_t)data[1] << 8
        | (uint32_t)data[2] << 16 | (uint32_t)data[3] << 24;
}

static uint64_t linux_u64(const uint8_t *data)
{
    return (uint64_t)linux_u32(data) | (uint64_t)linux_u32(data + 4) << 32;
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

static linux_map *linux_find_map(
    xxemul_linux_process *process, uint64_t address)
{
    int index;
    linux_map *best = NULL;
    for (index = 0; index < LINUX_MAX_MAPS; ++index) {
        linux_map *map = &process->maps[index];
        if (map->used && address >= map->base
            && address - map->base < map->size
            && (best == NULL || map->generation > best->generation))
            best = map;
    }
    return best;
}

static int linux_map_transfer(
    xxemul_linux_process *process, uint64_t address,
    void *buffer, size_t size, int write)
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
                if (file == NULL || file_offset > LINUX_MAX_FILE
                    || chunk > LINUX_MAX_FILE - file_offset
                    || !linux_file_reserve(file, (size_t)file_offset + chunk))
                    return -1;
                memcpy(file->data + file_offset, bytes + completed, chunk);
                file->dirty = file->host_path[0] != '\0';
                for (i = 0; i < LINUX_MAX_MAPS; ++i) {
                    linux_map *alias = &process->maps[i];
                    uint64_t begin = file_offset > alias->file_offset
                        ? file_offset : alias->file_offset;
                    uint64_t end = file_offset + chunk;
                    if (!alias->used || !alias->shared || alias == map
                        || alias->fd != map->fd) continue;
                    if (end > alias->file_offset + alias->size)
                        end = alias->file_offset + alias->size;
                    if (end > begin) memcpy(alias->data + begin - alias->file_offset,
                        file->data + begin, (size_t)(end - begin));
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

int xxemul_linux_mapping_read(
    xxemul_linux_process *process, uint64_t address,
    void *buffer, size_t size)
{
    if (process == NULL || (buffer == NULL && size != 0)) return -1;
    return linux_map_transfer(process, address, buffer, size, 0);
}

int xxemul_linux_mapping_write(
    xxemul_linux_process *process, uint64_t address,
    const void *buffer, size_t size)
{
    if (process == NULL || (buffer == NULL && size != 0)) return -1;
    return linux_map_transfer(process, address, (void *)buffer, size, 1);
}

static int linux_guest_read(
    xxemul_linux_process *process, uint64_t address,
    void *buffer, size_t size)
{
    int mapped = xxemul_linux_mapping_read(process, address, buffer, size);
    return mapped == 1 || (mapped == 0 && xxemul_read_memory(
        process->emulator, address, buffer, size) == XXEMUL_STATUS_OK);
}

static int linux_guest_write(
    xxemul_linux_process *process, uint64_t address,
    const void *buffer, size_t size)
{
    int mapped = xxemul_linux_mapping_write(process, address, buffer, size);
    return mapped == 1 || (mapped == 0 && xxemul_write_memory(
        process->emulator, address, buffer, size) == XXEMUL_STATUS_OK);
}

static int linux_guest_value(
    xxemul_linux_process *process, uint64_t address,
    unsigned width, uint64_t *value)
{
    uint8_t data[8];
    unsigned index;
    *value = 0;
    if (width > sizeof(data) || !linux_guest_read(process, address, data, width))
        return 0;
    for (index = 0; index < width; ++index)
        *value |= (uint64_t)data[index] << (8u * index);
    return 1;
}

static int linux_guest_store(
    xxemul_linux_process *process, uint64_t address,
    unsigned width, uint64_t value)
{
    uint8_t data[8];
    unsigned index;
    if (width > sizeof(data)) return 0;
    for (index = 0; index < width; ++index)
        data[index] = (uint8_t)(value >> (8u * index));
    return linux_guest_write(process, address, data, width);
}

static int linux_guest_string(
    xxemul_linux_process *process, uint64_t address,
    char *buffer, size_t capacity)
{
    size_t index;
    if (address == 0 || capacity == 0) return 0;
    for (index = 0; index + 1u < capacity; ++index) {
        if (!linux_guest_read(process, address + index, buffer + index, 1u))
            return 0;
        if (buffer[index] == '\0') return 1;
    }
    buffer[capacity - 1u] = '\0';
    return 0;
}

static int linux_phdr_info(
    const xxemul_linux_process *process,
    uint64_t *address, uint64_t *entry_size, uint64_t *count)
{
    const uint8_t *image = process->self_data;
    size_t size = process->self_size;
    uint64_t offset;
    uint64_t index;
    if (size < (process->is_64 ? 64u : 52u)
        || memcmp(image, "\177ELF", 4u) != 0) return 0;
    offset = process->is_64 ? linux_u64(image + 32) : linux_u32(image + 28);
    *entry_size = linux_u16(image + (process->is_64 ? 54 : 42));
    *count = linux_u16(image + (process->is_64 ? 56 : 44));
    if (*entry_size < (process->is_64 ? 56u : 32u)
        || *count > 256u || offset > size
        || *count > (size - (size_t)offset) / *entry_size) return 0;
    for (index = 0; index < *count; ++index) {
        const uint8_t *ph = image + offset + index * *entry_size;
        uint64_t file_offset = process->is_64 ? linux_u64(ph + 8) : linux_u32(ph + 4);
        uint64_t virtual_address = process->is_64
            ? linux_u64(ph + 16) : linux_u32(ph + 8);
        uint64_t file_size = process->is_64
            ? linux_u64(ph + 32) : linux_u32(ph + 16);
        if (linux_u32(ph) == 1u && offset >= file_offset
            && offset - file_offset <= file_size
            && *count * *entry_size <= file_size - (offset - file_offset)) {
            *address = virtual_address + offset - file_offset;
            return 1;
        }
    }
    return 0;
}

static int linux_initial_stack(
    xxemul_linux_process *process, int argc, const char *const *argv,
    int envc, const char *const *envp)
{
    static const uint64_t aux_types[] = {
        3, 4, 5, 6, 7, 8, 9, 11, 12, 13, 14, 16, 17, 23, 25, 31, 0
    };
    uint64_t aux_values[sizeof(aux_types) / sizeof(aux_types[0])] = {0};
    uint64_t arg_address[129];
    uint64_t env_address[129];
    uint64_t stack_top = process->emulator->region_address
        + process->emulator->region_size;
    uint64_t cursor = (stack_top - 0x100u) & ~UINT64_C(15);
    uint64_t low = stack_top - 1024u * 1024u;
    uint64_t phdr, phent, phnum, random_address, execfn_address, sp, entry;
    uint8_t random_bytes[16];
    unsigned width = process->is_64 ? 8u : 4u;
    int index;
    size_t i;
    if (argc < 0 || argc > (int)LINUX_MAX_EXEC_STRINGS
        || envc < 0 || envc > (int)LINUX_MAX_EXEC_STRINGS
        || (argc > 0 && argv == NULL) || (envc > 0 && envp == NULL)
        || !linux_phdr_info(process, &phdr, &phent, &phnum)) return 0;
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
        if (!linux_guest_write(process, cursor, process->self_path, length))
            return 0;
        execfn_address = cursor;
    }
    if (cursor < low + sizeof(random_bytes)) return 0;
    random_address = (cursor - sizeof(random_bytes)) & ~UINT64_C(15);
    memset(random_bytes, 0x5a, sizeof(random_bytes));
    if (!linux_guest_write(process, random_address, random_bytes,
            sizeof(random_bytes))) return 0;
    entry = process->emulator->x86.ip;
    aux_values[0] = phdr;
    aux_values[1] = phent;
    aux_values[2] = phnum;
    aux_values[3] = LINUX_PAGE;
    aux_values[6] = entry;
    aux_values[12] = 100u;
    aux_values[14] = random_address;
    aux_values[15] = execfn_address;
    i = 1u + (size_t)argc + 1u + (size_t)envc + 1u
        + 2u * sizeof(aux_types) / sizeof(aux_types[0]);
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
    for (i = 0; i < sizeof(aux_types) / sizeof(aux_types[0]); ++i) {
        if (!linux_guest_store(process, cursor, width, aux_types[i])
            || !linux_guest_store(process, cursor + width, width, aux_values[i]))
            return 0;
        cursor += 2u * width;
    }
    process->emulator->x86.gpr[XXEMUL_X86_RSP] = sp;
    process->emulator->x86.segment[XXEMUL_X86_CS] = process->is_64 ? 0x33u : 0x23u;
    process->emulator->x86.segment[XXEMUL_X86_SS] = 0x2bu;
    process->emulator->x86.segment[XXEMUL_X86_DS] = 0x2bu;
    process->emulator->x86.segment[XXEMUL_X86_ES] = 0x2bu;
    return 1;
}

static xxemul_linux_process *linux_new_process(
    xxemul *emulator, const char *guest_executable_path,
    const char *working_directory)
{
    xxemul_linux_process *process;
    if (emulator == NULL || emulator->arch != XXEMUL_ARCH_X86
        || (emulator->mode != XXEMUL_MODE_X86_32
            && emulator->mode != XXEMUL_MODE_X86_64)
        || guest_executable_path == NULL || working_directory == NULL)
        return NULL;
    process = (xxemul_linux_process *)calloc(1u, sizeof(*process));
    if (process == NULL) return NULL;
    process->emulator = emulator;
    process->is_64 = emulator->mode == XXEMUL_MODE_X86_64;
    process->next_map = process->is_64
        ? UINT64_C(0x100000000) : UINT64_C(0x10000000);
    process->exec_fd = -1;
#if defined(_MSC_VER)
    {
        size_t value_size = 0u;
        process->syscall_stats_enabled = getenv_s(&value_size, NULL, 0u,
            "XXEMUL_LINUX_SYSCALL_STATS") == 0 && value_size != 0u;
    }
#else
    process->syscall_stats_enabled = getenv("XXEMUL_LINUX_SYSCALL_STATS") != NULL;
#endif
    if (!linux_copy_string(process->self_path, sizeof(process->self_path),
            guest_executable_path)
        || !linux_copy_string(process->workdir, sizeof(process->workdir),
            working_directory)) goto failed;
    return process;
failed:
    xxemul_linux_destroy(process);
    return NULL;
}

xxemul_linux_process *xxemul_linux_create(
    xxemul *emulator, const char *executable_path,
    const char *working_directory, int argc, const char *const *argv)
{
    xxemul_linux_process *process = linux_new_process(
        emulator, executable_path, working_directory);
    if (process == NULL) return NULL;
    process->self_data = linux_read_file(executable_path, &process->self_size);
    if (process->self_data == NULL
        || !linux_initial_stack(process, argc, argv, 0, NULL))
        goto failed;
    return process;
failed:
    xxemul_linux_destroy(process);
    return NULL;
}

xxemul_linux_process *xxemul_linux_create_image(
    xxemul *emulator, const uint8_t *image, size_t image_size,
    const char *guest_executable_path, const char *working_directory,
    int argc, const char *const *argv,
    int envc, const char *const *envp)
{
    xxemul_linux_process *process;
    if (image == NULL || image_size == 0u || image_size > LINUX_MAX_FILE)
        return NULL;
    process = linux_new_process(emulator, guest_executable_path,
        working_directory);
    if (process == NULL) return NULL;
    process->self_data = (uint8_t *)malloc(image_size);
    if (process->self_data == NULL) goto failed;
    memcpy(process->self_data, image, image_size);
    process->self_size = image_size;
    if (!linux_initial_stack(process, argc, argv, envc, envp))
        goto failed;
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
        fprintf(stderr, "linux %s syscall total=%" PRIu64,
            process->is_64 ? "amd64" : "i386", process->syscall_total);
        for (number = 0; number < sizeof(process->syscall_counts)
                / sizeof(process->syscall_counts[0]); ++number) {
            if (process->syscall_counts[number] != 0u)
                fprintf(stderr, " %zu=%" PRIu64, number,
                    process->syscall_counts[number]);
        }
        fputs(" first=", stderr);
        for (number = 0; number < process->first_syscall_count; ++number)
            fprintf(stderr, "%s%u", number == 0u ? "" : ",",
                process->first_syscalls[number]);
        fputc('\n', stderr);
    }
    for (index = 3; index < LINUX_MAX_FDS; ++index) {
        linux_file_save(&process->files[index]);
        free(process->files[index].data);
    }
    for (index = 0; index < LINUX_MAX_MAPS; ++index)
        free(process->maps[index].data);
    for (index = 0; index < (int)process->exec_argc; ++index)
        free(process->exec_argv[index]);
    for (index = 0; index < (int)process->exec_envc; ++index)
        free(process->exec_envp[index]);
    free(process->exec_owned_image);
    free(process->self_data);
    free(process);
}

void xxemul_linux_set_output(
    xxemul_linux_process *process,
    xxemul_linux_output_callback callback, void *context)
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

const uint8_t *xxemul_linux_exec_image(
    const xxemul_linux_process *process, size_t *size)
{
    const linux_file *file;
    if (size != NULL) *size = 0;
    if (process != NULL && process->exec_owned_image != NULL) {
        if (size != NULL) *size = process->exec_owned_size;
        return process->exec_owned_image;
    }
    if (process == NULL || process->exec_fd < 3
        || process->exec_fd >= LINUX_MAX_FDS) return NULL;
    file = &process->files[process->exec_fd];
    if (!file->used) return NULL;
    if (size != NULL) *size = file->size;
    return file->data;
}

const char *xxemul_linux_working_directory(
    const xxemul_linux_process *process)
{
    return process == NULL ? NULL : process->workdir;
}

const char *xxemul_linux_exec_path(const xxemul_linux_process *process)
{
    return xxemul_linux_exec_image(process, NULL) == NULL
        ? NULL : process->exec_path;
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

const char *xxemul_linux_exec_argument(
    const xxemul_linux_process *process, size_t index)
{
    return process == NULL || index >= process->exec_argc
        ? NULL : process->exec_argv[index];
}

size_t xxemul_linux_exec_envc(const xxemul_linux_process *process)
{
    return process == NULL ? 0u : process->exec_envc;
}

const char *xxemul_linux_exec_environment(
    const xxemul_linux_process *process, size_t index)
{
    return process == NULL || index >= process->exec_envc
        ? NULL : process->exec_envp[index];
}

uint64_t xxemul_linux_segment_base(
    const xxemul_linux_process *process, unsigned segment_index,
    uint16_t selector)
{
    unsigned entry = selector >> 3;
    if (process == NULL) return 0;
    if (process->is_64) {
        if (segment_index == XXEMUL_X86_FS) return process->fs_base;
        if (segment_index == XXEMUL_X86_GS) return process->gs_base;
    }
    if ((segment_index == XXEMUL_X86_FS || segment_index == XXEMUL_X86_GS)
        && entry >= 6u && entry <= 8u) return process->tls_base[entry - 6u];
    return 0;
}

static uint64_t linux_arg(const xxemul_linux_process *process, unsigned index)
{
    static const unsigned amd64[] = {
        XXEMUL_X86_RDI, XXEMUL_X86_RSI, XXEMUL_X86_RDX,
        XXEMUL_X86_R10, XXEMUL_X86_R8, XXEMUL_X86_R9
    };
    static const unsigned i386[] = {
        XXEMUL_X86_RBX, XXEMUL_X86_RCX, XXEMUL_X86_RDX,
        XXEMUL_X86_RSI, XXEMUL_X86_RDI, XXEMUL_X86_RBP
    };
    if (index >= 6u) return 0;
    return process->emulator->x86.gpr[process->is_64
        ? amd64[index] : i386[index]] & (process->is_64
        ? UINT64_MAX : UINT32_MAX);
}

static void linux_result(xxemul_linux_process *process, uint64_t result)
{
    process->emulator->x86.gpr[XXEMUL_X86_RAX] = process->is_64
        ? result : (uint32_t)result;
}

static int linux_host_path(
    xxemul_linux_process *process, const char *guest,
    char *host, size_t capacity)
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
    if (name_size == 0 || name_size > 255u
        || strstr(name, "..") != NULL || strchr(name, '/') != NULL
        || strchr(name, '\\') != NULL || strchr(name, ':') != NULL
        || root_size + name_size + 2u > capacity) return 0;
    memcpy(host, process->workdir, root_size);
    if (root_size > 0 && host[root_size - 1u] != '\\'
        && host[root_size - 1u] != '/') host[root_size++] = separator;
    memcpy(host + root_size, name, name_size + 1u);
    return 1;
}

static uint64_t linux_open(
    xxemul_linux_process *process, const char *guest, uint64_t flags,
    int memfd)
{
    linux_file *file;
    int fd = linux_new_fd(process);
    int exists;
    if (process->syscall_stats_enabled && !memfd)
        fprintf(stderr, "linux open path=\"%s\" flags=0x%" PRIx64 "\n",
            guest, flags);
    if (fd < 0) return linux_error(LINUX_ENOMEM);
    file = &process->files[fd];
    file->writable = memfd || (flags & 3u) != 0u;
    if (memfd) return (uint64_t)fd;
    if (strcmp(guest, "/proc/self/exe") == 0
        || strcmp(guest, process->self_path) == 0) {
        file->data = (uint8_t *)malloc(process->self_size + 1u);
        if (file->data == NULL) goto no_memory;
        memcpy(file->data, process->self_data, process->self_size);
        file->size = file->capacity = process->self_size;
        file->self = 1;
        file->writable = 0;
        return (uint64_t)fd;
    }
    if (!linux_host_path(process, guest, file->host_path,
            sizeof(file->host_path))) {
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

static void linux_sync_file_maps(
    xxemul_linux_process *process, int fd,
    uint64_t offset, size_t size)
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
        if (end > map->file_offset + map->size)
            end = map->file_offset + map->size;
        if (end > begin) memcpy(map->data + begin - map->file_offset,
            file->data + begin, (size_t)(end - begin));
    }
}

static uint64_t linux_file_write(
    xxemul_linux_process *process, int fd,
    uint64_t guest_address, uint64_t count,
    uint64_t offset, int advance)
{
    linux_file *file = linux_fd(process, fd);
    uint8_t *buffer;
    if (file == NULL || !file->open) return linux_error(LINUX_EBADF);
    if (!file->writable) return linux_error(LINUX_EACCES);
    if (count > LINUX_MAX_FILE || offset > LINUX_MAX_FILE
        || count > LINUX_MAX_FILE - offset) return linux_error(LINUX_EFBIG);
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

static uint64_t linux_write(
    xxemul_linux_process *process, int fd,
    uint64_t address, uint64_t count)
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
        if (process->output != NULL)
            process->output(process->output_context, fd, bytes, (size_t)count);
        free(bytes);
        return count;
    }
    if (fd < 3) return linux_error(LINUX_EBADF);
    {
        linux_file *file = linux_fd(process, fd);
        if (file == NULL) return linux_error(LINUX_EBADF);
        return linux_file_write(process, fd, address, count,
            file->offset, 1);
    }
}

static uint64_t linux_read(
    xxemul_linux_process *process, int fd,
    uint64_t address, uint64_t count)
{
    linux_file *file = linux_fd(process, fd);
    size_t available;
    if (fd == 0) return 0;
    if (file == NULL || !file->open) return linux_error(LINUX_EBADF);
    if (file->offset >= file->size) return 0;
    available = file->size - (size_t)file->offset;
    if (count < available) available = (size_t)count;
    if (!linux_guest_write(process, address, file->data + file->offset,
            available)) return linux_error(LINUX_EFAULT);
    file->offset += available;
    return available;
}

static uint64_t linux_writev(
    xxemul_linux_process *process, int fd,
    uint64_t vector, uint64_t count)
{
    uint64_t result = 0;
    uint64_t index;
    unsigned width = process->is_64 ? 8u : 4u;
    if (count > 1024u) return linux_error(LINUX_EINVAL);
    for (index = 0; index < count; ++index) {
        uint64_t address, size, written;
        uint64_t entry = vector + index * width * 2u;
        if (!linux_guest_value(process, entry, width, &address)
            || !linux_guest_value(process, entry + width, width, &size))
            return linux_error(LINUX_EFAULT);
        if (size > 1024u * 1024u || result > 1024u * 1024u - size)
            return linux_error(LINUX_EINVAL);
        written = linux_write(process, fd, address, size);
        if ((int64_t)written < 0) return written;
        result += written;
        if (written != size) break;
    }
    return result;
}

static uint64_t linux_lseek(
    xxemul_linux_process *process, int fd,
    int64_t displacement, uint64_t whence)
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
        if ((uint64_t)displacement > LINUX_MAX_FILE - base)
            return linux_error(LINUX_EINVAL);
        position = base + (uint64_t)displacement;
    }
    file->offset = position;
    return position;
}

static int linux_stat_buffer(
    xxemul_linux_process *process, uint64_t address, uint64_t size)
{
    uint8_t data[144];
    size_t length = process->is_64 ? 144u : 96u;
    memset(data, 0, sizeof(data));
    if (process->is_64) {
        data[0] = data[8] = data[16] = 1u;
        data[24] = 0xa4u; data[25] = 0x81u;
        data[48] = (uint8_t)size;
        data[49] = (uint8_t)(size >> 8);
        data[50] = (uint8_t)(size >> 16);
        data[51] = (uint8_t)(size >> 24);
        data[56] = 0u; data[57] = 0x10u;
        data[64] = (uint8_t)((size + 511u) / 512u);
    } else {
        data[0] = 1u; data[12] = 1u;
        data[16] = 0xa4u; data[17] = 0x81u;
        data[20] = 1u;
        data[44] = (uint8_t)size;
        data[45] = (uint8_t)(size >> 8);
        data[46] = (uint8_t)(size >> 16);
        data[47] = (uint8_t)(size >> 24);
        data[53] = 0x10u;
        data[56] = (uint8_t)((size + 511u) / 512u);
        data[88] = 1u;
    }
    return linux_guest_write(process, address, data, length);
}

static int linux_host_size(
    xxemul_linux_process *process, const char *guest,
    uint64_t *size)
{
    char path[1024];
    xx_io_device *io;
    int64_t length;
    if (strcmp(guest, "/proc/self/exe") == 0
        || strcmp(guest, process->self_path) == 0) {
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

static uint64_t linux_fstat(
    xxemul_linux_process *process, int fd, uint64_t address)
{
    linux_file *file;
    if (fd >= 0 && fd <= 2) return linux_stat_buffer(process, address, 0)
        ? 0 : linux_error(LINUX_EFAULT);
    file = linux_fd(process, fd);
    if (file == NULL || !file->open) return linux_error(LINUX_EBADF);
    return linux_stat_buffer(process, address, file->size)
        ? 0 : linux_error(LINUX_EFAULT);
}

static uint64_t linux_stat(
    xxemul_linux_process *process,
    uint64_t path_address, uint64_t result_address)
{
    char guest[1024];
    uint64_t size;
    if (!linux_guest_string(process, path_address, guest, sizeof(guest)))
        return linux_error(LINUX_EFAULT);
    if (!linux_host_size(process, guest, &size))
        return linux_error(LINUX_ENOENT);
    return linux_stat_buffer(process, result_address, size)
        ? 0 : linux_error(LINUX_EFAULT);
}

static void linux_put_value(uint8_t *data, size_t offset,
    uint64_t value, unsigned width)
{
    unsigned index;
    for (index = 0; index < width; ++index)
        data[offset + index] = (uint8_t)(value >> (8u * index));
}

static uint64_t linux_statx(xxemul_linux_process *process)
{
    char guest[1024];
    uint8_t data[256];
    uint64_t size;
    uint64_t address = linux_arg(process, 4);
    int fd = (int)(int32_t)linux_arg(process, 0);
    if (!linux_guest_string(process, linux_arg(process, 1),
            guest, sizeof(guest))) return linux_error(LINUX_EFAULT);
    if (guest[0] == '\0' && (linux_arg(process, 2) & 0x1000u) != 0u) {
        linux_file *file = linux_fd(process, fd);
        if (file == NULL) return linux_error(LINUX_EBADF);
        size = file->size;
    } else if (!linux_host_size(process, guest, &size)) {
        return linux_error(LINUX_ENOENT);
    }
    memset(data, 0, sizeof(data));
    linux_put_value(data, 0, 0x7ffu, 4);
    linux_put_value(data, 4, 4096u, 4);
    linux_put_value(data, 16, 1u, 4);
    linux_put_value(data, 28, 0100644u, 2);
    linux_put_value(data, 32, 1u, 8);
    linux_put_value(data, 40, size, 8);
    linux_put_value(data, 48, (size + 511u) / 512u, 8);
    return linux_guest_write(process, address, data, sizeof(data))
        ? 0 : linux_error(LINUX_EFAULT);
}

static uint64_t linux_mmap(
    xxemul_linux_process *process, uint64_t address,
    uint64_t length, uint64_t flags, int fd, uint64_t offset)
{
    uint64_t size;
    linux_file *file = NULL;
    linux_map *map = NULL;
    int index;
    if (length == 0 || length > LINUX_MAX_MAP
        || length > UINT64_MAX - LINUX_PAGE + 1u)
        return linux_error(LINUX_EINVAL);
    size = linux_align_up(length, LINUX_PAGE);
    if (size > LINUX_MAX_MAP) return linux_error(LINUX_ENOMEM);
    if ((flags & 0x20u) == 0u) {
        file = linux_fd(process, fd);
        if (file == NULL || !file->open) return linux_error(LINUX_EBADF);
    }
    if ((flags & 0x10u) != 0u) {
        if ((address & (LINUX_PAGE - 1u)) != 0u || address == 0u)
            return linux_error(LINUX_EINVAL);
        if (address > UINT64_MAX - size) return linux_error(LINUX_ENOMEM);
    } else {
        uint64_t original_start = process->emulator->region_address;
        uint64_t original_end = original_start + process->emulator->region_size;
        uint64_t ceiling = process->is_64
            ? UINT64_C(0x700000000000) : UINT64_C(0xf0000000);
        if (address == 0 || (address & (LINUX_PAGE - 1u)) != 0u)
            address = process->next_map;
        if (address > ceiling - size - (LINUX_PAGE - 1u))
            address = process->next_map;
        address = linux_align_up(address, LINUX_PAGE);
        for (;;) {
            int conflict = address < original_end
                && original_start < address + size;
            if (!conflict) {
                for (index = 0; index < LINUX_MAX_MAPS; ++index) {
                    linux_map *candidate = &process->maps[index];
                    if (candidate->used && address < candidate->base + candidate->size
                        && candidate->base < address + size) {
                        conflict = 1;
                        break;
                    }
                }
            }
            if (!conflict) break;
            if (address > ceiling - size)
                return linux_error(LINUX_ENOMEM);
            address = linux_align_up(address + size, LINUX_PAGE);
        }
        process->next_map = address + size;
    }
    if (!process->is_64 && (address > UINT32_MAX
        || size > UINT32_MAX - address)) return linux_error(LINUX_ENOMEM);
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

static uint64_t linux_munmap(
    xxemul_linux_process *process, uint64_t address, uint64_t length)
{
    int index;
    if (length == 0 || (address & (LINUX_PAGE - 1u)) != 0u)
        return linux_error(LINUX_EINVAL);
    if (address > UINT64_MAX - length) return linux_error(LINUX_EINVAL);
    for (index = 0; index < LINUX_MAX_MAPS; ++index) {
        linux_map *map = &process->maps[index];
        if (map->used && address <= map->base
            && length >= map->size && address + length >= map->base + map->size) {
            free(map->data);
            memset(map, 0, sizeof(*map));
        }
    }
    return 0;
}

static uint64_t linux_brk(
    xxemul_linux_process *process, uint64_t requested)
{
    if (process->brk_base == 0u) {
        uint64_t result = linux_mmap(process, 0, 16u * 1024u * 1024u,
            0x22u, -1, 0);
        if ((int64_t)result < 0) return 0;
        process->brk_base = result;
        process->brk_current = result;
    }
    if (requested >= process->brk_base
        && requested <= process->brk_base + 16u * 1024u * 1024u)
        process->brk_current = requested;
    return process->brk_current;
}

static uint64_t linux_readlink(
    xxemul_linux_process *process, uint64_t address,
    uint64_t output, uint64_t capacity)
{
    char guest[1024];
    size_t length;
    if (!linux_guest_string(process, address, guest, sizeof(guest)))
        return linux_error(LINUX_EFAULT);
    if (strcmp(guest, "/proc/self/exe") != 0)
        return linux_error(LINUX_ENOENT);
    length = strlen(process->self_path);
    if (capacity < length) length = (size_t)capacity;
    return linux_guest_write(process, output, process->self_path, length)
        ? length : linux_error(LINUX_EFAULT);
}

static int linux_fd_path(const char *path)
{
    const char *marker = strstr(path, "/fd/");
    char *end;
    long fd;
    if (marker == NULL) return -1;
    fd = strtol(marker + 4, &end, 10);
    if (end == marker + 4 || *end != '\0' || fd < 3 || fd >= LINUX_MAX_FDS)
        return -1;
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

static unsigned linux_capture_exec_vector(
    xxemul_linux_process *process, uint64_t address,
    char **strings, size_t *count)
{
    unsigned width = process->is_64 ? 8u : 4u;
    size_t index;
    *count = 0;
    if (address == 0u) return 0;
    for (index = 0; index <= LINUX_MAX_EXEC_STRINGS; ++index) {
        uint64_t string_address;
        char buffer[4096];
        size_t length;
        if (!linux_guest_value(process, address + index * width,
                width, &string_address)) return LINUX_EFAULT;
        if (string_address == 0u) return 0;
        if (index == LINUX_MAX_EXEC_STRINGS) return 7u; /* E2BIG */
        if (!linux_guest_string(process, string_address,
                buffer, sizeof(buffer))) return LINUX_EFAULT;
        length = strlen(buffer) + 1u;
        strings[index] = (char *)malloc(length);
        if (strings[index] == NULL) return LINUX_ENOMEM;
        memcpy(strings[index], buffer, length);
        *count = index + 1u;
    }
    return 7u;
}

static uint64_t linux_execve(
    xxemul_linux_process *process, int at)
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
    if (at && (flags & ~UINT64_C(0x1100)) != 0u)
        return linux_error(LINUX_EINVAL);
    if (!linux_guest_string(process, path_address, path, sizeof(path)))
        return linux_error(LINUX_EFAULT);
    if (process->syscall_stats_enabled)
        fprintf(stderr, "linux exec path=\"%s\" flags=0x%" PRIx64 "\n",
            path, flags);
    if (at && path[0] == '\0' && (flags & 0x1000u) != 0u) {
        fd = (int)(int32_t)linux_arg(process, 0);
    } else {
        if (path[0] == '\0') return linux_error(LINUX_ENOENT);
        fd = linux_fd_path(path);
    }
    file = linux_fd(process, fd);
    if (file == NULL || !file->open) {
        fd = -1;
        if (strcmp(path, process->self_path) == 0
            || strcmp(path, "/proc/self/exe") == 0) {
            owned_image = (uint8_t *)malloc(process->self_size);
            if (owned_image == NULL) return linux_error(LINUX_ENOMEM);
            memcpy(owned_image, process->self_data, process->self_size);
            owned_size = process->self_size;
        } else if (linux_host_path(process, path, host_path,
                sizeof(host_path))) {
            owned_image = linux_read_file(host_path, &owned_size);
            if (owned_image == NULL) return linux_error(LINUX_ENOENT);
        } else {
            return linux_error(LINUX_ENOENT);
        }
    }
    linux_clear_exec_vectors(process);
    error = linux_capture_exec_vector(process,
        linux_arg(process, at ? 2u : 1u),
        process->exec_argv, &process->exec_argc);
    if (error == 0u) error = linux_capture_exec_vector(process,
        linux_arg(process, at ? 3u : 2u),
        process->exec_envp, &process->exec_envc);
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

static uint64_t linux_dispatch_amd64(
    xxemul_linux_process *process, uint32_t number)
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
        if (!linux_guest_string(process, number == 257 ? b : a,
                path, sizeof(path))) return linux_error(LINUX_EFAULT);
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
    case 9: return linux_mmap(process, a, b, d, (int)(int64_t)linux_arg(process, 4),
            linux_arg(process, 5));
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
        if (!linux_file_reserve(file, (size_t)b))
            return linux_error(LINUX_ENOMEM);
        file->size = (size_t)b;
        file->dirty = file->host_path[0] != '\0';
        return 0;
    case 89: return linux_readlink(process, a, b, c);
    case 158:
        if (a == 0x1002u) { process->fs_base = b; return 0; }
        if (a == 0x1001u) { process->gs_base = b; return 0; }
        if (a == 0x1003u || a == 0x1004u)
            return linux_guest_store(process, b, 8u,
                a == 0x1003u ? process->fs_base : process->gs_base)
                ? 0 : linux_error(LINUX_EFAULT);
        return linux_error(LINUX_EINVAL);
    case 262:
        if (d & 0x1000u) {
            if (!linux_guest_string(process, b, path, sizeof(path)))
                return linux_error(LINUX_EFAULT);
            if (path[0] == '\0') return linux_fstat(process, (int)a, c);
        }
        return linux_stat(process, b, c);
    case 267: return linux_readlink(process, b, c, d);
    case 319: return linux_open(process, "", 0, 1);
    case 322: return linux_execve(process, 1);
    case 332: return linux_statx(process);
    case 13: case 14: case 21: case 218: case 273: case 302: case 334:
        return 0;
    case 228:
        return linux_guest_store(process, b, 8u, 0)
            && linux_guest_store(process, b + 8u, 8u, 0)
            ? 0 : linux_error(LINUX_EFAULT);
    case 318:
        if (b > 4096u) return linux_error(LINUX_EINVAL);
        if (b != 0u) {
            uint8_t bytes[4096];
            memset(bytes, 0x5au, (size_t)b);
            if (!linux_guest_write(process, a, bytes, (size_t)b))
                return linux_error(LINUX_EFAULT);
        }
        return b;
    default:
        result = linux_error(LINUX_ENOSYS);
        return result;
    }
}

static uint64_t linux_dispatch_i386(
    xxemul_linux_process *process, uint32_t number)
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
        if (!linux_guest_string(process, number == 295 ? b : a,
                path, sizeof(path))) return linux_error(LINUX_EFAULT);
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
            if (!linux_guest_value(process, a + index * 4u, 4u, &args[index]))
                return linux_error(LINUX_EFAULT);
        }
        return linux_mmap(process, args[0], args[1], args[3],
            (int)(int32_t)args[4], args[5]);
    }
    case 91: return linux_munmap(process, a, b);
    case 93:
    case 194:
        file = linux_fd(process, (int)a);
        if (file == NULL || !file->open) return linux_error(LINUX_EBADF);
        if (!file->writable) return linux_error(LINUX_EACCES);
        if (b > LINUX_MAX_FILE || !linux_file_reserve(file, (size_t)b))
            return linux_error(LINUX_EFBIG);
        file->size = (size_t)b;
        file->dirty = file->host_path[0] != '\0';
        return 0;
    case 125: return 0;
    case 140: {
        uint64_t offset = a; /* fd remains arg0; offset is args1:args2 */
        (void)offset;
        value = linux_lseek(process, (int)a,
            (int64_t)((b << 32) | c), linux_arg(process, 4));
        if ((int64_t)value < 0) return value;
        return linux_guest_store(process, d, 8u, value)
            ? 0 : linux_error(LINUX_EFAULT);
    }
    case 144: return 0;
    case 146: return linux_writev(process, (int)a, b, c);
    case 175: case 174: case 258: case 311: case 33: return 0;
    case 181: return linux_file_write(process, (int)a, b, c,
        ((uint64_t)linux_arg(process, 4) << 32) | d, 0);
    case 192: return linux_mmap(process, a, b, d, (int)(int32_t)linux_arg(process, 4),
        linux_arg(process, 5) * LINUX_PAGE);
    case 195:
    case 196: return linux_stat(process, a, b);
    case 197: return linux_fstat(process, (int)a, b);
    case 243: {
        uint64_t descriptor = a;
        uint64_t entry, base;
        if (!linux_guest_value(process, descriptor, 4u, &entry)
            || !linux_guest_value(process, descriptor + 4u, 4u, &base))
            return linux_error(LINUX_EFAULT);
        if (entry == UINT32_MAX) entry = 6u;
        if (entry < 6u || entry > 8u) return linux_error(LINUX_EINVAL);
        if (!linux_guest_store(process, descriptor, 4u, entry))
            return linux_error(LINUX_EFAULT);
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

xxemul_status xxemul_linux_dispatch(xxemul_linux_process *process)
{
    uint32_t number;
    uint64_t result;
    if (process == NULL || process->emulator == NULL || process->exited)
        return XXEMUL_STATUS_INVALID_ARGUMENT;
    number = (uint32_t)process->emulator->x86.gpr[XXEMUL_X86_RAX];
    if (process->syscall_stats_enabled) {
        ++process->syscall_total;
        if (number < sizeof(process->syscall_counts)
                / sizeof(process->syscall_counts[0]))
            ++process->syscall_counts[number];
        if (process->first_syscall_count < sizeof(process->first_syscalls)
                / sizeof(process->first_syscalls[0]))
            process->first_syscalls[process->first_syscall_count++] = number;
    }
    result = process->is_64
        ? linux_dispatch_amd64(process, number)
        : linux_dispatch_i386(process, number);
    linux_result(process, result);
    return process->exited ? XXEMUL_STATUS_HALTED : XXEMUL_STATUS_OK;
}
