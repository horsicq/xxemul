#if !defined(_WIN32)
#define _POSIX_C_SOURCE 200809L
#endif

#include "xxemul_dos_files.h"
#include "xxemul_internal.h"

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <stdatomic.h>
#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#endif

#define DOS_MAX_HANDLES 64u
#define DOS_MAX_PATH 2048u
#define DOS_MAX_GUEST_PATH 260u
#define DOS_MAX_FILE_SIZE (64u * 1024u * 1024u)
#define DOS_CF UINT64_C(1)
#define DOS_SFT_SEGMENT 0x0600u
#define DOS_SFT_TABLE_PARAGRAPHS 0x0040u
#define DOS_SFT_ENTRIES_PER_TABLE 16u
#define DOS_SFT_ENTRY_SIZE 0x3bu
#define DOS_LOL_SEGMENT 0x0720u
#define DOS_LOL_OFFSET 0x0002u
#define DOS_JFT_SEGMENT 0x0730u

typedef struct dos_handle {
    xx_io_device *device;
    uint8_t access;
    char *host_path;
} dos_handle;

typedef struct dos_session {
    xxemul *emulator;
    char root[DOS_MAX_PATH];
    dos_handle handles[DOS_MAX_HANDLES];
    uint16_t allocation_strategy;
    struct dos_session *next;
} dos_session;

typedef struct dos_file_metadata {
    uint16_t attributes;
    uint16_t time;
    uint16_t date;
    uint32_t size;
} dos_file_metadata;

static dos_session *dos_sessions;
#if defined(_WIN32)
static SRWLOCK dos_sessions_lock = SRWLOCK_INIT;
#else
static atomic_flag dos_sessions_lock = ATOMIC_FLAG_INIT;
#endif

static void dos_lock(void)
{
#if defined(_WIN32)
    AcquireSRWLockExclusive(&dos_sessions_lock);
#else
    while (atomic_flag_test_and_set_explicit(
        &dos_sessions_lock, memory_order_acquire)) {
    }
#endif
}

static void dos_unlock(void)
{
#if defined(_WIN32)
    ReleaseSRWLockExclusive(&dos_sessions_lock);
#else
    atomic_flag_clear_explicit(&dos_sessions_lock, memory_order_release);
#endif
}

static dos_session *dos_find(xxemul *emulator)
{
    dos_session *session;

    for (session = dos_sessions; session != NULL; session = session->next) {
        if (session->emulator == emulator) {
            return session;
        }
    }
    return NULL;
}

static void dos_result(xxemul *emulator, uint16_t value, int error)
{
    emulator->x86.gpr[XXEMUL_X86_RAX] = value;
    if (error) {
        emulator->x86.flags |= DOS_CF;
    } else {
        emulator->x86.flags &= ~DOS_CF;
    }
}

static void xxemul_dos_write_word(uint8_t *data, uint16_t value)
{
    data[0] = (uint8_t)value;
    data[1] = (uint8_t)(value >> 8u);
}

static int dos_guest_name_at(xxemul *emulator, uint16_t offset,
    char *buffer, size_t capacity)
{
    uint16_t segment = emulator->x86.segment[XXEMUL_X86_DS];
    size_t index;

    for (index = 0u; index + 1u < capacity; ++index) {
        uint8_t c = emulator->region_data[
            xxemul_dos_linear(segment, (uint16_t)(offset + index))];
        buffer[index] = (char)c;
        if (c == 0u) {
            return index != 0u;
        }
    }
    buffer[capacity - 1u] = '\0';
    return 0;
}

static int dos_guest_name(
    xxemul *emulator, char *buffer, size_t capacity)
{
    return dos_guest_name_at(emulator,
        (uint16_t)emulator->x86.gpr[XXEMUL_X86_RDX], buffer, capacity);
}

#if !defined(_WIN32)
static int dos_case_equal(const char *left, const char *right)
{
    while (*left != '\0' && *right != '\0') {
        if (tolower((unsigned char)*left)
            != tolower((unsigned char)*right)) {
            return 0;
        }
        ++left;
        ++right;
    }
    return *left == *right;
}

static int dos_find_case_name(
    const char *directory, const char *requested,
    char *actual, size_t capacity)
{
    DIR *dir = opendir(directory);
    struct dirent *entry;
    int found = 0;

    if (dir == NULL) {
        return 0;
    }
    while ((entry = readdir(dir)) != NULL) {
        size_t length = strlen(entry->d_name);
        if (length < capacity
            && dos_case_equal(entry->d_name, requested)) {
            memcpy(actual, entry->d_name, length + 1u);
            found = 1;
            if (strcmp(actual, requested) == 0) {
                break;
            }
        }
    }
    closedir(dir);
    return found;
}
#endif

static int dos_path_kind(const char *path)
{
#if defined(_WIN32)
    DWORD attributes = GetFileAttributesA(path);
    if (attributes == INVALID_FILE_ATTRIBUTES) {
        return 0;
    }
    if ((attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0u) {
        return -1;
    }
    return (attributes & FILE_ATTRIBUTE_DIRECTORY) != 0u ? 2 : 1;
#else
    struct stat info;
    if (lstat(path, &info) != 0) {
        return 0;
    }
    if (S_ISLNK(info.st_mode)) {
        return -1;
    }
    if (S_ISDIR(info.st_mode)) {
        return 2;
    }
    return S_ISREG(info.st_mode) ? 1 : -1;
#endif
}

/* Resolve DOS paths component by component; no symlink or reparse point may
 * redirect an xxfclib open outside the configured workspace. */
static uint16_t dos_resolve(
    const dos_session *session, const char *guest,
    char *host, size_t capacity, int creating)
{
    const char *cursor = guest;
    size_t used = strlen(session->root);
    int components = 0;

    if (used + 1u >= capacity) {
        return 3u;
    }
    memcpy(host, session->root, used + 1u);
    if (isalpha((unsigned char)cursor[0]) && cursor[1] == ':') {
        cursor += 2;
    }
    while (*cursor == '/' || *cursor == '\\') {
        ++cursor;
    }
    while (*cursor != '\0') {
        char component[DOS_MAX_GUEST_PATH];
        size_t length = 0u;
        size_t parent_length;
        int kind;
        int last;

        while (*cursor != '\0' && *cursor != '/' && *cursor != '\\') {
            unsigned char c = (unsigned char)*cursor++;
            if (c < 32u || c == ':' || c == '*' || c == '?'
                || c == '"' || c == '<' || c == '>' || c == '|'
                || length + 1u >= sizeof(component)) {
                return 3u;
            }
            component[length++] = (char)c;
        }
        component[length] = '\0';
        while (*cursor == '/' || *cursor == '\\') {
            ++cursor;
        }
        if (length == 0u || strcmp(component, ".") == 0) {
            continue;
        }
        if (strcmp(component, "..") == 0) {
            return 3u;
        }
        last = *cursor == '\0';
        parent_length = used;
#if !defined(_WIN32)
        {
            char actual[DOS_MAX_GUEST_PATH];
            if (dos_find_case_name(host, component, actual,
                    sizeof(actual))) {
                memcpy(component, actual, strlen(actual) + 1u);
                length = strlen(component);
            }
        }
#endif
        if (used + 1u + length >= capacity) {
            return 3u;
        }
        host[used++] = '/';
        memcpy(host + used, component, length + 1u);
        used += length;
        kind = dos_path_kind(host);
        if (kind < 0 || (!last && kind != 2)
            || (last && kind == 2)) {
            return 5u;
        }
        if (last && kind == 0 && !creating) {
            return 2u;
        }
        if (!last && kind == 0) {
            return 3u;
        }
        if (last && kind == 0 && creating) {
            host[parent_length] = '\0';
            if (dos_path_kind(host) != 2) {
                return 3u;
            }
            host[parent_length] = '/';
        }
        ++components;
    }
    return components != 0 ? 0u : 3u;
}

static void dos_sft_update(xxemul *emulator,
    const dos_session *session, uint16_t handle);

static uint16_t dos_open_file_path(xxemul *emulator,
    dos_session *session, const char *guest,
    uint8_t access, int creating)
{
    char host[DOS_MAX_PATH];
    xx_io_device *device;
    char *saved_path;
    uint16_t error;
    uint16_t handle;
    const char *mode;

    if (session == NULL) {
        return 3u;
    }
    if (access > 2u) {
        return 12u;
    }
    error = dos_resolve(session, guest, host, sizeof(host), creating);
    if (error != 0u) {
        return error;
    }
    for (handle = 5u; handle < DOS_MAX_HANDLES; ++handle) {
        if (session->handles[handle].device == NULL) {
            break;
        }
    }
    if (handle == DOS_MAX_HANDLES) {
        return 4u;
    }
    saved_path = (char *)malloc(strlen(host) + 1u);
    if (saved_path == NULL) {
        return 8u;
    }
    memcpy(saved_path, host, strlen(host) + 1u);
    mode = creating ? "w+b" : access == 0u ? "rb" : "r+b";
    device = xx_io_file_open(host, mode);
    if (device == NULL) {
        free(saved_path);
        return errno == ENOENT ? 2u : errno == EMFILE ? 4u : 5u;
    }
    session->handles[handle].device = device;
    session->handles[handle].access = creating ? 2u : access;
    session->handles[handle].host_path = saved_path;
    emulator->region_data[xxemul_dos_linear(DOS_JFT_SEGMENT, handle)]
        = (uint8_t)handle;
    if (handle < 20u) {
        emulator->region_data[xxemul_dos_linear(
            emulator->psp_segment, (uint16_t)(0x18u + handle))]
            = (uint8_t)handle;
    }
    dos_sft_update(emulator, session, handle);
    dos_result(emulator, handle, 0);
    return 0u;
}

static uint16_t dos_open_file(
    xxemul *emulator, dos_session *session, int creating)
{
    char guest[DOS_MAX_GUEST_PATH];

    if (!dos_guest_name(emulator, guest, sizeof(guest))) {
        return 3u;
    }
    return dos_open_file_path(emulator, session, guest,
        creating ? 2u : (uint8_t)emulator->x86.gpr[XXEMUL_X86_RAX] & 3u,
        creating);
}

static uint16_t dos_open_extended(
    xxemul *emulator, dos_session *session)
{
    char guest[DOS_MAX_GUEST_PATH];
    char host[DOS_MAX_PATH];
    uint16_t action = (uint16_t)emulator->x86.gpr[XXEMUL_X86_RDX];
    uint8_t access = (uint8_t)emulator->x86.gpr[XXEMUL_X86_RBX] & 7u;
    uint16_t error;
    uint16_t result_action;
    int existing;
    int creating;

    if ((uint8_t)emulator->x86.gpr[XXEMUL_X86_RAX] != 0u
        || (action & ~0x13u) != 0u
        || (action & 3u) > 2u || access > 2u) {
        return 1u;
    }
    if (session == NULL || !dos_guest_name_at(emulator,
        (uint16_t)emulator->x86.gpr[XXEMUL_X86_RSI],
        guest, sizeof(guest))) {
        return 3u;
    }
    error = dos_resolve(session, guest, host, sizeof(host), 1);
    if (error != 0u) {
        return error;
    }
    existing = dos_path_kind(host) == 1;
    if (existing) {
        if ((action & 3u) == 0u) {
            return 80u;
        }
        creating = (action & 3u) == 2u;
        if (creating && access == 0u) {
            return 5u;
        }
        result_action = creating ? 3u : 1u;
    } else {
        if ((action & 0x10u) == 0u) {
            return 2u;
        }
        creating = 1;
        result_action = 2u;
    }
    error = dos_open_file_path(emulator, session, guest,
        access, creating);
    if (error == 0u) {
        emulator->x86.gpr[XXEMUL_X86_RCX] = result_action;
    }
    return error;
}

static int dos_host_metadata(const char *host, dos_file_metadata *metadata)
{
    memset(metadata, 0, sizeof(*metadata));
#if defined(_WIN32)
    {
        WIN32_FILE_ATTRIBUTE_DATA info;
        FILETIME local_time;
        if (!GetFileAttributesExA(host, GetFileExInfoStandard, &info))
            return 0;
        metadata->attributes = (uint16_t)(info.dwFileAttributes & 0x27u);
        metadata->size = info.nFileSizeHigh == 0u
            ? info.nFileSizeLow : UINT32_MAX;
        if (FileTimeToLocalFileTime(&info.ftLastWriteTime, &local_time))
            FileTimeToDosDateTime(&local_time,
                &metadata->date, &metadata->time);
    }
#else
    {
        struct stat info;
        struct tm local;
        const char *basename = strrchr(host, '/');
        if (stat(host, &info) != 0 || !S_ISREG(info.st_mode)) return 0;
        metadata->attributes = 0x20u;
        if ((info.st_mode & S_IWUSR) == 0)
            metadata->attributes |= 1u;
        if (basename != NULL && basename[1] == '.')
            metadata->attributes |= 2u;
        metadata->size = (uint64_t)info.st_size <= UINT32_MAX
            ? (uint32_t)info.st_size : UINT32_MAX;
        if (localtime_r(&info.st_mtime, &local) != NULL
            && local.tm_year >= 80 && local.tm_year <= 207) {
            metadata->date = (uint16_t)(
                ((local.tm_year - 80) << 9u)
                | ((local.tm_mon + 1) << 5u) | local.tm_mday);
            metadata->time = (uint16_t)(
                (local.tm_hour << 11u) | (local.tm_min << 5u)
                | (local.tm_sec / 2));
        }
    }
#endif
    return 1;
}

static int dos_set_host_time(const char *host,
    uint16_t date, uint16_t clock)
{
    if ((date & 31u) == 0u || ((date >> 5u) & 15u) == 0u
        || ((date >> 5u) & 15u) > 12u
        || (clock & 31u) > 29u
        || ((clock >> 5u) & 63u) > 59u
        || ((clock >> 11u) & 31u) > 23u) {
        return 0;
    }
#if defined(_WIN32)
    {
        FILETIME local_time;
        FILETIME utc_time;
        HANDLE file;
        int success;

        if (!DosDateTimeToFileTime(date, clock, &local_time)
            || !LocalFileTimeToFileTime(&local_time, &utc_time)) {
            return 0;
        }
        file = CreateFileA(host, FILE_WRITE_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (file == INVALID_HANDLE_VALUE) {
            return 0;
        }
        success = SetFileTime(file, NULL, NULL, &utc_time) != 0;
        CloseHandle(file);
        return success;
    }
#else
    {
        struct tm local = {0};
        struct timespec times[2];
        time_t timestamp;

        local.tm_year = (int)(date >> 9u) + 80;
        local.tm_mon = (int)((date >> 5u) & 15u) - 1;
        local.tm_mday = (int)(date & 31u);
        local.tm_hour = (int)(clock >> 11u);
        local.tm_min = (int)((clock >> 5u) & 63u);
        local.tm_sec = (int)(clock & 31u) * 2;
        local.tm_isdst = -1;
        timestamp = mktime(&local);
        if (timestamp == (time_t)-1) {
            return 0;
        }
        times[0].tv_sec = 0;
        times[0].tv_nsec = UTIME_OMIT;
        times[1].tv_sec = timestamp;
        times[1].tv_nsec = 0;
        return utimensat(AT_FDCWD, host, times, 0) == 0;
    }
#endif
}

static uint8_t *dos_sft_entry(xxemul *emulator, uint16_t handle)
{
    uint16_t segment = (uint16_t)(DOS_SFT_SEGMENT
        + (handle / DOS_SFT_ENTRIES_PER_TABLE)
            * DOS_SFT_TABLE_PARAGRAPHS);
    uint16_t offset = (uint16_t)(6u
        + (handle % DOS_SFT_ENTRIES_PER_TABLE) * DOS_SFT_ENTRY_SIZE);
    return emulator->region_data + xxemul_dos_linear(segment, offset);
}

static void dos_sft_update(xxemul *emulator,
    const dos_session *session, uint16_t handle)
{
    uint8_t *entry = dos_sft_entry(emulator, handle);
    const dos_handle *file;
    dos_file_metadata metadata;
    const char *name;
    const char *dot;
    int64_t position;
    size_t index;

    memset(entry, 0, DOS_SFT_ENTRY_SIZE);
    if (handle < 5u) {
        xxemul_dos_write_word(entry, 1u);
        xxemul_dos_write_word(entry + 2u, 2u);
        xxemul_dos_write_word(entry + 5u, 0x80d3u);
        memcpy(entry + 0x20u, "CON        ", 11u);
        return;
    }
    if (session == NULL) {
        return;
    }
    file = &session->handles[handle];
    if (file->device == NULL || file->host_path == NULL) {
        return;
    }
    xxemul_dos_write_word(entry, 1u);
    xxemul_dos_write_word(entry + 2u, file->access);
    xxemul_dos_write_word(entry + 5u, 2u);
    xxemul_dos_write_word(entry + 0x31u, emulator->psp_segment);
    if (dos_host_metadata(file->host_path, &metadata)) {
        entry[4u] = (uint8_t)metadata.attributes;
        xxemul_dos_write_word(entry + 0x0du, metadata.time);
        xxemul_dos_write_word(entry + 0x0fu, metadata.date);
        xxemul_dos_write_word(entry + 0x11u, (uint16_t)metadata.size);
        xxemul_dos_write_word(entry + 0x13u,
            (uint16_t)(metadata.size >> 16u));
    }
    position = xx_io_tell(file->device);
    if (position >= 0 && position <= UINT32_MAX) {
        xxemul_dos_write_word(entry + 0x15u, (uint16_t)position);
        xxemul_dos_write_word(entry + 0x17u,
            (uint16_t)((uint64_t)position >> 16u));
    }
    memset(entry + 0x20u, ' ', 11u);
    name = strrchr(file->host_path, '/');
    name = name == NULL ? file->host_path : name + 1u;
    dot = strrchr(name, '.');
    for (index = 0u; index < 8u && name[index] != '\0'
        && (dot == NULL || name + index < dot); ++index) {
        entry[0x20u + index] = (uint8_t)toupper(
            (unsigned char)name[index]);
    }
    if (dot != NULL) {
        for (index = 0u; index < 3u && dot[index + 1u] != '\0';
            ++index) {
            entry[0x28u + index] = (uint8_t)toupper(
                (unsigned char)dot[index + 1u]);
        }
    }
}

static void dos_kernel_initialize(xxemul *emulator,
    dos_session *session)
{
    uint8_t *memory = emulator->region_data;
    uint8_t *lol = memory + xxemul_dos_linear(
        DOS_LOL_SEGMENT, DOS_LOL_OFFSET);
    uint8_t *jft = memory + xxemul_dos_linear(DOS_JFT_SEGMENT, 0u);
    uint8_t *psp = memory + xxemul_dos_linear(emulator->psp_segment, 0u);
    uint16_t table;
    uint16_t handle;

    memset(memory + xxemul_dos_linear(DOS_SFT_SEGMENT, 0u), 0,
        DOS_MAX_HANDLES / DOS_SFT_ENTRIES_PER_TABLE * 0x400u);
    memset(lol - 2u, 0, 0x42u);
    memset(jft, 0xff, DOS_MAX_HANDLES);
    memset(psp + 0x18u, 0xff, 20u);
    xxemul_dos_write_word(lol - 2u,
        (uint16_t)(emulator->psp_segment - 1u));
    xxemul_dos_write_word(lol + 4u, 0u);
    xxemul_dos_write_word(lol + 6u, DOS_SFT_SEGMENT);
    lol[0x20u] = 1u;
    lol[0x21u] = 26u;
    for (table = 0u; table < DOS_MAX_HANDLES
            / DOS_SFT_ENTRIES_PER_TABLE; ++table) {
        uint16_t segment = (uint16_t)(DOS_SFT_SEGMENT
            + table * DOS_SFT_TABLE_PARAGRAPHS);
        uint8_t *header = memory + xxemul_dos_linear(segment, 0u);
        int last = table + 1u == DOS_MAX_HANDLES
            / DOS_SFT_ENTRIES_PER_TABLE;
        xxemul_dos_write_word(header, last ? 0xffffu : 0u);
        xxemul_dos_write_word(header + 2u, last ? 0xffffu
            : (uint16_t)(segment + DOS_SFT_TABLE_PARAGRAPHS));
        xxemul_dos_write_word(header + 4u,
            DOS_SFT_ENTRIES_PER_TABLE);
    }
    for (handle = 0u; handle < 5u; ++handle) {
        jft[handle] = (uint8_t)handle;
        psp[0x18u + handle] = (uint8_t)handle;
        dos_sft_update(emulator, session, handle);
    }
    xxemul_dos_write_word(psp + 0x32u, DOS_MAX_HANDLES);
    xxemul_dos_write_word(psp + 0x34u, 0u);
    xxemul_dos_write_word(psp + 0x36u, DOS_JFT_SEGMENT);
}

void xxemul_dos_files_initialize_kernel(xxemul *emulator)
{
    if (emulator != NULL && emulator->dos_mode) {
        dos_kernel_initialize(emulator, NULL);
    }
}

static uint16_t dos_file_attributes(xxemul *emulator,
    const dos_session *session)
{
    char guest[DOS_MAX_GUEST_PATH];
    char host[DOS_MAX_PATH];
    uint16_t error;
    dos_file_metadata metadata;

    if (session == NULL || !dos_guest_name(emulator, guest, sizeof(guest)))
        return 3u;
    if ((uint8_t)emulator->x86.gpr[XXEMUL_X86_RAX] != 0u)
        return 1u;
    error = dos_resolve(session, guest, host, sizeof(host), 0);
    if (error != 0u) return error;
    if (!dos_host_metadata(host, &metadata)) return 5u;
    emulator->x86.gpr[XXEMUL_X86_RCX] =
        (emulator->x86.gpr[XXEMUL_X86_RCX] & ~UINT64_C(0xffff))
            | metadata.attributes;
    dos_result(emulator, 0u, 0);
    return 0u;
}

static uint16_t dos_delete_file(xxemul *emulator,
    const dos_session *session)
{
    char guest[DOS_MAX_GUEST_PATH];
    char host[DOS_MAX_PATH];
    uint16_t error;

    if (session == NULL || !dos_guest_name(emulator, guest, sizeof(guest))) {
        return 3u;
    }
    error = dos_resolve(session, guest, host, sizeof(host), 0);
    if (error != 0u) {
        return error;
    }
    if (remove(host) != 0) {
        return errno == ENOENT ? 2u : 5u;
    }
    dos_result(emulator, 0u, 0);
    return 0u;
}

static uint16_t dos_find_first(xxemul *emulator,
    const dos_session *session)
{
    char guest[DOS_MAX_GUEST_PATH];
    char host[DOS_MAX_PATH];
    const char *basename;
    dos_file_metadata metadata;
    uint8_t record[43] = {0};
    uint16_t error;
    uint32_t dta;
    size_t index;

    if (session == NULL || !dos_guest_name(emulator, guest, sizeof(guest)))
        return 3u;
    error = dos_resolve(session, guest, host, sizeof(host), 0);
    if (error != 0u) return error == 2u ? 18u : error;
    if (!dos_host_metadata(host, &metadata)) return 18u;
    basename = strrchr(host, '/');
    basename = basename == NULL ? host : basename + 1u;
    if (strlen(basename) > 12u) return 18u;
    record[0x15u] = (uint8_t)metadata.attributes;
    record[0x16u] = (uint8_t)metadata.time;
    record[0x17u] = (uint8_t)(metadata.time >> 8u);
    record[0x18u] = (uint8_t)metadata.date;
    record[0x19u] = (uint8_t)(metadata.date >> 8u);
    for (index = 0u; index < 4u; ++index)
        record[0x1au + index] = (uint8_t)(metadata.size >> (index * 8u));
    for (index = 0u; basename[index] != '\0'; ++index)
        record[0x1eu + index] = (uint8_t)toupper(
            (unsigned char)basename[index]);
    dta = xxemul_dos_linear(emulator->dos_dta_segment,
        emulator->dos_dta_offset);
    if (xxemul_write_memory(emulator, dta, record, sizeof(record))
        != XXEMUL_STATUS_OK) return 5u;
    dos_result(emulator, 0u, 0);
    return 0u;
}

static uint16_t dos_transfer(
    xxemul *emulator, dos_session *session, int writing)
{
    uint16_t handle = (uint16_t)emulator->x86.gpr[XXEMUL_X86_RBX];
    uint16_t count = (uint16_t)emulator->x86.gpr[XXEMUL_X86_RCX];
    uint16_t segment = emulator->x86.segment[XXEMUL_X86_DS];
    uint16_t offset = (uint16_t)emulator->x86.gpr[XXEMUL_X86_RDX];
    xx_io_device *device;
    uint8_t *buffer;
    ssize_t transferred;
    size_t index;

    if (session == NULL || handle < 5u || handle >= DOS_MAX_HANDLES
        || session->handles[handle].device == NULL) {
        return 6u;
    }
    if ((writing && session->handles[handle].access == 0u)
        || (!writing && session->handles[handle].access == 1u)) {
        return 5u;
    }
    if (count == 0u) {
        dos_result(emulator, 0u, 0);
        return 0u;
    }
    device = session->handles[handle].device;
    if (writing) {
        int64_t current = xx_io_tell(device);
        if (current < 0 || current > DOS_MAX_FILE_SIZE
            || count > DOS_MAX_FILE_SIZE - (uint64_t)current) {
            return 0x27u;
        }
    }
    buffer = (uint8_t *)malloc(count);
    if (buffer == NULL) {
        return 8u;
    }
    if (writing) {
        for (index = 0u; index < count; ++index) {
            buffer[index] = emulator->region_data[
                xxemul_dos_linear(segment, (uint16_t)(offset + index))];
        }
        transferred = xx_io_write(device, buffer, count);
    } else {
        transferred = xx_io_read(device, buffer, count);
        if (transferred > 0) {
            for (index = 0u; index < (size_t)transferred; ++index) {
                emulator->region_data[
                    xxemul_dos_linear(segment, (uint16_t)(offset + index))]
                    = buffer[index];
            }
        }
    }
    free(buffer);
    if (transferred < 0 || transferred > count) {
        return 5u;
    }
    dos_sft_update(emulator, session, handle);
    dos_result(emulator, (uint16_t)transferred, 0);
    return 0u;
}

static uint16_t dos_seek(xxemul *emulator, dos_session *session)
{
    uint16_t handle = (uint16_t)emulator->x86.gpr[XXEMUL_X86_RBX];
    uint8_t origin = (uint8_t)emulator->x86.gpr[XXEMUL_X86_RAX];
    uint32_t raw = ((uint32_t)(uint16_t)emulator->x86.gpr[XXEMUL_X86_RCX]
        << 16) | (uint16_t)emulator->x86.gpr[XXEMUL_X86_RDX];
    int64_t offset = (int32_t)raw;
    int64_t position;
    xx_io_device *device;

    if (session == NULL || handle < 5u || handle >= DOS_MAX_HANDLES
        || session->handles[handle].device == NULL) {
        return 6u;
    }
    if (origin > 2u) {
        return 1u;
    }
    device = session->handles[handle].device;
    if (xx_io_seek64(device, offset,
            origin == 0u ? SEEK_SET : origin == 1u ? SEEK_CUR : SEEK_END)
        != 0) {
        return 1u;
    }
    position = xx_io_tell(device);
    if (position < 0 || position > UINT32_MAX) {
        return 1u;
    }
    dos_sft_update(emulator, session, handle);
    emulator->x86.gpr[XXEMUL_X86_RDX] = (uint16_t)(position >> 16);
    dos_result(emulator, (uint16_t)position, 0);
    return 0u;
}

static int dos_root_path(char *root, size_t capacity, const char *workdir)
{
#if defined(_WIN32)
    DWORD attributes;
    if (_fullpath(root, workdir, capacity) == NULL) {
        return 0;
    }
    attributes = GetFileAttributesA(root);
    return attributes != INVALID_FILE_ATTRIBUTES
        && (attributes & FILE_ATTRIBUTE_DIRECTORY) != 0u
        && (attributes & FILE_ATTRIBUTE_REPARSE_POINT) == 0u;
#else
    struct stat info;
    char *resolved = realpath(workdir, NULL);
    size_t length;

    if (resolved == NULL) {
        return 0;
    }
    length = strlen(resolved);
    if (length >= capacity) {
        free(resolved);
        return 0;
    }
    memcpy(root, resolved, length + 1u);
    free(resolved);
    return stat(root, &info) == 0 && S_ISDIR(info.st_mode);
#endif
}

static int dos_tail(uint8_t tail[128],
    size_t argc, const char *const *argv)
{
    size_t length = 0u;
    size_t argument;

    memset(tail, 0, 128u);
    for (argument = 0u; argument < argc; ++argument) {
        const char *value = argv[argument];
        size_t index;
        size_t count;
        int quote;

        if (value == NULL) {
            return 0;
        }
        count = strlen(value);
        quote = strpbrk(value, " \t") != NULL;
        if (strpbrk(value, "\r\n\"") != NULL
            || length + 1u + count + (quote ? 2u : 0u) > 126u) {
            return 0;
        }
        tail[++length] = ' ';
        if (quote) {
            tail[++length] = '"';
        }
        for (index = 0u; index < count; ++index) {
            tail[++length] = (uint8_t)value[index];
        }
        if (quote) {
            tail[++length] = '"';
        }
    }
    tail[0] = (uint8_t)length;
    tail[length + 1u] = 0x0du;
    return 1;
}

static int dos_environment(
    uint8_t environment[512], const char *guest_exe_name)
{
    const char *base = guest_exe_name;
    const char *cursor;
    size_t length;
    size_t index;

    for (cursor = guest_exe_name; *cursor != '\0'; ++cursor) {
        if (*cursor == '/' || *cursor == '\\') {
            base = cursor + 1;
        }
    }
    length = strlen(base);
    if (length == 0u || length > 200u) {
        return 0;
    }
    memset(environment, 0, 512u);
    memcpy(environment, "PATH=C:\\\0", 9u);
    environment[10] = 1u;
    environment[12] = 'C';
    environment[13] = ':';
    environment[14] = '\\';
    for (index = 0u; index < length; ++index) {
        unsigned char c = (unsigned char)base[index];
        if (c < 32u || c == ':' || c == '\\') {
            return 0;
        }
        environment[15u + index] = (uint8_t)toupper(c);
    }
    return 1;
}

xxemul_status xxemul_dos_files_start(
    xxemul *emulator, const char *workdir, const char *guest_exe_name,
    size_t argc, const char *const *argv)
{
    dos_session *session;
    uint8_t tail[128];
    uint8_t environment[512];
    uint8_t *psp;

    if (emulator == NULL || !emulator->dos_mode || workdir == NULL
        || guest_exe_name == NULL || (argc != 0u && argv == NULL)) {
        return XXEMUL_STATUS_INVALID_ARGUMENT;
    }
    session = (dos_session *)calloc(1u, sizeof(*session));
    if (session == NULL) {
        return XXEMUL_STATUS_OUT_OF_MEMORY;
    }
    if (!dos_root_path(session->root, sizeof(session->root), workdir)) {
        free(session);
        return XXEMUL_STATUS_IO_ERROR;
    }
    if (!dos_environment(environment, guest_exe_name)
        || !dos_tail(tail, argc, argv)) {
        free(session);
        return XXEMUL_STATUS_INVALID_ARGUMENT;
    }
    xxemul_dos_files_stop(emulator);
    psp = emulator->region_data
        + xxemul_dos_linear(emulator->psp_segment, 0u);
    memcpy(emulator->region_data + 0x7000u,
        environment, sizeof(environment));
    memcpy(psp + 0x80u, tail, sizeof(tail));
    psp[0x2cu] = 0x00u;
    psp[0x2du] = 0x07u;
    session->emulator = emulator;
    dos_kernel_initialize(emulator, session);
    dos_lock();
    session->next = dos_sessions;
    dos_sessions = session;
    dos_unlock();
    return XXEMUL_STATUS_OK;
}

void xxemul_dos_files_stop(xxemul *emulator)
{
    dos_session **link;
    dos_session *session = NULL;
    size_t index;

    dos_lock();
    for (link = &dos_sessions; *link != NULL; link = &(*link)->next) {
        if ((*link)->emulator == emulator) {
            session = *link;
            *link = session->next;
            break;
        }
    }
    dos_unlock();
    if (session == NULL) {
        return;
    }
    for (index = 5u; index < DOS_MAX_HANDLES; ++index) {
        if (session->handles[index].device != NULL) {
            xx_io_close(session->handles[index].device);
        }
        free(session->handles[index].host_path);
    }
    free(session);
}

int xxemul_dos_files_list_of_lists(
    xxemul *emulator, uint16_t *segment, uint16_t *offset)
{
    if (emulator == NULL || !emulator->dos_mode
        || segment == NULL || offset == NULL) {
        return 0;
    }
    *segment = DOS_LOL_SEGMENT;
    *offset = DOS_LOL_OFFSET;
    return 1;
}

uint16_t xxemul_dos_files_allocation_strategy(xxemul *emulator)
{
    dos_session *session;
    uint16_t strategy;

    dos_lock();
    session = dos_find(emulator);
    strategy = session != NULL ? session->allocation_strategy : 0u;
    dos_unlock();
    return strategy;
}

int xxemul_dos_files_set_allocation_strategy(
    xxemul *emulator, uint16_t strategy)
{
    dos_session *session;
    int success = 0;

    if (strategy > 2u
        && (strategy < 0x40u || strategy > 0x42u)
        && (strategy < 0x80u || strategy > 0x82u)) {
        return 0;
    }
    dos_lock();
    session = dos_find(emulator);
    if (session != NULL) {
        session->allocation_strategy = strategy;
        success = 1;
    }
    dos_unlock();
    return success;
}

static uint16_t dos_cluster_count(uint64_t bytes)
{
    uint64_t clusters = bytes / 4096u;
    return (uint16_t)(clusters > UINT16_MAX ? UINT16_MAX : clusters);
}

int xxemul_dos_files_drive_space(
    xxemul *emulator, uint16_t *available, uint16_t *total)
{
    dos_session *session;
    uint64_t available_bytes = 0u;
    uint64_t total_bytes = 0u;
    int success = 0;

    if (available == NULL || total == NULL) {
        return 0;
    }
    dos_lock();
    session = dos_find(emulator);
    if (session != NULL) {
#if defined(_WIN32)
        ULARGE_INTEGER available_size;
        ULARGE_INTEGER total_size;

        if (GetDiskFreeSpaceExA(session->root, &available_size,
            &total_size, NULL)) {
            available_bytes = available_size.QuadPart;
            total_bytes = total_size.QuadPart;
            success = 1;
        }
#else
        struct statvfs info;

        if (statvfs(session->root, &info) == 0) {
            uint64_t unit = info.f_frsize != 0u
                ? (uint64_t)info.f_frsize : (uint64_t)info.f_bsize;
            uint64_t blocks = (uint64_t)info.f_blocks;
            uint64_t free_blocks = (uint64_t)info.f_bavail;

            total_bytes = unit != 0u && blocks > UINT64_MAX / unit
                ? UINT64_MAX : blocks * unit;
            available_bytes = unit != 0u
                && free_blocks > UINT64_MAX / unit
                ? UINT64_MAX : free_blocks * unit;
            success = 1;
        }
#endif
    }
    dos_unlock();
    if (!success) {
        return 0;
    }
    *total = dos_cluster_count(total_bytes);
    *available = dos_cluster_count(available_bytes);
    if (*available > *total) {
        *available = *total;
    }
    return 1;
}

xxemul_status xxemul_dos_files_interrupt(xxemul *emulator, uint8_t function)
{
    dos_session *session;
    uint16_t error = 1u;

    if (emulator == NULL || !emulator->dos_mode) {
        return XXEMUL_STATUS_INVALID_ARGUMENT;
    }
    dos_lock();
    session = dos_find(emulator);
    switch (function) {
    case 0x44u: {
        uint8_t subfunction = (uint8_t)emulator->x86.gpr[XXEMUL_X86_RAX];
        uint16_t handle = (uint16_t)emulator->x86.gpr[XXEMUL_X86_RBX];
        if (subfunction != 0u) {
            error = 1u;
        } else if (handle <= 2u) {
            emulator->x86.gpr[XXEMUL_X86_RDX] = 0x80d3u;
            emulator->x86.flags &= ~DOS_CF;
            error = 0u;
        } else if (session != NULL && handle >= 5u
            && handle < DOS_MAX_HANDLES
            && session->handles[handle].device != NULL) {
            emulator->x86.gpr[XXEMUL_X86_RDX] = 2u;
            emulator->x86.flags &= ~DOS_CF;
            error = 0u;
        } else {
            error = 6u;
        }
        break;
    }
    case 0x57u: {
        uint8_t subfunction = (uint8_t)emulator->x86.gpr[XXEMUL_X86_RAX];
        uint16_t handle = (uint16_t)emulator->x86.gpr[XXEMUL_X86_RBX];
        dos_file_metadata metadata;

        if (session == NULL || handle < 5u || handle >= DOS_MAX_HANDLES
            || session->handles[handle].device == NULL) {
            error = 6u;
        } else if (subfunction == 0u
            && dos_host_metadata(session->handles[handle].host_path,
                &metadata)) {
            emulator->x86.gpr[XXEMUL_X86_RCX] = metadata.time;
            emulator->x86.gpr[XXEMUL_X86_RDX] = metadata.date;
            emulator->x86.flags &= ~DOS_CF;
            error = 0u;
        } else if (subfunction == 1u
            && dos_set_host_time(session->handles[handle].host_path,
                (uint16_t)emulator->x86.gpr[XXEMUL_X86_RDX],
                (uint16_t)emulator->x86.gpr[XXEMUL_X86_RCX])) {
            dos_sft_update(emulator, session, handle);
            emulator->x86.flags &= ~DOS_CF;
            error = 0u;
        } else {
            error = subfunction > 1u ? 1u : 5u;
        }
        break;
    }
    case 0x3cu:
    case 0x3du:
        error = dos_open_file(emulator, session, function == 0x3cu);
        break;
    case 0x6cu:
        error = dos_open_extended(emulator, session);
        break;
    case 0x3eu: {
        uint16_t handle = (uint16_t)emulator->x86.gpr[XXEMUL_X86_RBX];
        if (handle <= 4u) {
            dos_result(emulator, 0u, 0);
            error = 0u;
        } else if (session != NULL && handle < DOS_MAX_HANDLES
            && session->handles[handle].device != NULL) {
            xx_io_device *device = session->handles[handle].device;
            session->handles[handle].device = NULL;
            free(session->handles[handle].host_path);
            session->handles[handle].host_path = NULL;
            emulator->region_data[xxemul_dos_linear(
                DOS_JFT_SEGMENT, handle)] = 0xffu;
            if (handle < 20u) {
                emulator->region_data[xxemul_dos_linear(
                    emulator->psp_segment, (uint16_t)(0x18u + handle))]
                    = 0xffu;
            }
            dos_sft_update(emulator, session, handle);
            error = xx_io_close(device) == 0 ? 0u : 5u;
            if (error == 0u) {
                dos_result(emulator, 0u, 0);
            }
        } else {
            error = 6u;
        }
        break;
    }
    case 0x41u:
        error = dos_delete_file(emulator, session);
        break;
    case 0x3fu:
    case 0x40u:
        error = dos_transfer(emulator, session, function == 0x40u);
        break;
    case 0x42u:
        error = dos_seek(emulator, session);
        break;
    case 0x43u:
        error = dos_file_attributes(emulator, session);
        break;
    case 0x4eu:
        error = dos_find_first(emulator, session);
        break;
    default:
        dos_unlock();
        return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    }
    if (error != 0u) {
        dos_result(emulator, error, 1);
    }
    dos_unlock();
    return XXEMUL_STATUS_OK;
}
