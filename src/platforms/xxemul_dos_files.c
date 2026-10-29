#if !defined(_WIN32)
#define _XOPEN_SOURCE 700
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
#define DOS_MAX_SEARCH_RESULTS 4096u
#define DOS_MAX_SEARCHES 16u
#define DOS_CF UINT64_C(1)
#define DOS_SFT_SEGMENT 0x0600u
#define DOS_SFT_TABLE_PARAGRAPHS 0x0040u
#define DOS_SFT_ENTRIES_PER_TABLE 16u
#define DOS_SFT_ENTRY_SIZE 0x3bu
#define DOS_LOL_SEGMENT 0x0720u
#define DOS_LOL_OFFSET 0x0002u
#define DOS_JFT_SEGMENT 0x0730u
#define DOS_MAX_PROCESS_DEPTH 8u

typedef struct dos_handle {
    xx_io_device *device;
    uint8_t access;
    char *host_path;
    uint8_t no_inherit;
    uint8_t sft;
    uint16_t owner;
} dos_handle;

typedef struct dos_search {
    uint32_t dta;
    uint8_t (*records)[43];
    size_t count;
    size_t next_record;
    struct dos_search *next;
} dos_search;

typedef struct dos_temp_attributes {
    char path[DOS_MAX_PATH];
    uint16_t attributes;
    struct dos_temp_attributes *next;
} dos_temp_attributes;

typedef struct dos_parent {
    xxemul_x86_state state;
    xxemul_x86_segment_cache segments[6];
    xxemul_mode mode;
    uint16_t psp, dta_segment, dta_offset;
    uint8_t vectors[12];
    dos_handle handles[DOS_MAX_HANDLES];
    dos_search *searches;
    uint32_t input_buffer;
    uint8_t input_count, input_pending, flush_pending, flush_function;
    uint16_t flush_cs, flush_ip, flush_ds, flush_dx;
} dos_parent;

typedef struct dos_session {
    xxemul *emulator;
    char root[DOS_MAX_PATH];
    dos_handle handles[DOS_MAX_HANDLES];
    uint16_t allocation_strategy;
    dos_search *searches;
    dos_temp_attributes *temp_attributes;
    uint32_t temp_sequence;
    uint32_t input_buffer;
    uint8_t input_count;
    uint8_t input_pending;
    uint8_t flush_pending;
    uint8_t flush_function;
    uint16_t flush_cs, flush_ip, flush_ds, flush_dx;
    dos_parent parents[DOS_MAX_PROCESS_DEPTH];
    unsigned depth;
    uint16_t child_status;
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
    while (atomic_flag_test_and_set_explicit(&dos_sessions_lock, memory_order_acquire)) {
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

/* Called with dos_sessions_lock held. Input-only sessions have no root and
 * therefore cannot resolve host files until xxemul_start_process is called. */
static dos_session *dos_find_or_create(xxemul *emulator)
{
    dos_session *session = dos_find(emulator);
    if (!session) {
        session = (dos_session *)calloc(1u, sizeof(*session));
        if (!session) return NULL;
        session->emulator = emulator;
        session->next = dos_sessions; dos_sessions = session;
    }
    return session;
}

/* Each process has its own handle table and path strings, but inherited
 * handles retain the same open description (and therefore file cursor). */
static int dos_drop_handle(dos_session *session, unsigned handle)
{
    xx_io_device *device = session->handles[handle].device;
    unsigned i, level;
    session->handles[handle].device = NULL;
    free(session->handles[handle].host_path);
    session->handles[handle].host_path = NULL;
    session->handles[handle].no_inherit = 0;
    if (!device) return 0;
    for (i = 5u; i < DOS_MAX_HANDLES; ++i)
        if (session->handles[i].device == device) return 0;
    for (level = 0; level < session->depth; ++level)
        for (i = 5u; i < DOS_MAX_HANDLES; ++i)
            if (session->parents[level].handles[i].device == device) return 0;
    return xx_io_close(device);
}

static uint16_t dos_free_sft(const dos_session *session)
{
    unsigned index, i, level;
    for (index = 5u; index < DOS_MAX_HANDLES; ++index) {
        int used = 0;
        for (i = 5u; i < DOS_MAX_HANDLES; ++i)
            if (session->handles[i].device && session->handles[i].sft == index) used = 1;
        for (level = 0; level < session->depth; ++level)
            for (i = 5u; i < DOS_MAX_HANDLES; ++i)
                if (session->parents[level].handles[i].device && session->parents[level].handles[i].sft == index) used = 1;
        if (!used) return (uint16_t)index;
    }
    return DOS_MAX_HANDLES;
}

static void dos_forget_temp_attributes(dos_session *session, const char *host)
{
    dos_temp_attributes **link;
    for (link = &session->temp_attributes; *link; link = &(*link)->next) if (!strcmp((*link)->path, host)) {
        dos_temp_attributes *entry = *link; *link = entry->next; free(entry); return;
    }
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

static uint32_t dos_jft_address(const xxemul *emulator, uint16_t handle)
{
    const uint8_t *psp = emulator->region_data + ((uint32_t)emulator->psp_segment << 4u);
    uint16_t offset = (uint16_t)(psp[0x34] | ((uint16_t)psp[0x35] << 8u));
    uint16_t segment = (uint16_t)(psp[0x36] | ((uint16_t)psp[0x37] << 8u));
    return xxemul_dos_linear(segment, (uint16_t)(offset + handle));
}

static int dos_guest_name_segment(xxemul *emulator, uint16_t segment, uint16_t offset, char *buffer, size_t capacity)
{
    size_t index;

    for (index = 0u; index + 1u < capacity; ++index) {
        uint8_t c = emulator->region_data[xxemul_dos_linear(segment, (uint16_t)(offset + index))];
        buffer[index] = (char)c;
        if (c == 0u) {
            return index != 0u;
        }
    }
    buffer[capacity - 1u] = '\0';
    return 0;
}

static int dos_guest_name_at(xxemul *emulator, uint16_t offset, char *buffer, size_t capacity)
{
    return dos_guest_name_segment(emulator, emulator->x86.segment[XXEMUL_X86_DS], offset, buffer, capacity);
}

static int dos_guest_name(xxemul *emulator, char *buffer, size_t capacity)
{
    return dos_guest_name_at(emulator, (uint16_t)emulator->x86.gpr[XXEMUL_X86_RDX], buffer, capacity);
}

#if !defined(_WIN32)
static int dos_case_equal(const char *left, const char *right)
{
    while (*left != '\0' && *right != '\0') {
        if (tolower((unsigned char)*left) != tolower((unsigned char)*right)) {
            return 0;
        }
        ++left;
        ++right;
    }
    return *left == *right;
}

static int dos_find_case_name(const char *directory, const char *requested, char *actual, size_t capacity)
{
    DIR *dir = opendir(directory);
    struct dirent *entry;
    int found = 0;

    if (dir == NULL) {
        return 0;
    }
    while ((entry = readdir(dir)) != NULL) {
        size_t length = strlen(entry->d_name);
        if (length < capacity && dos_case_equal(entry->d_name, requested)) {
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
static uint16_t dos_resolve(const dos_session *session, const char *guest, char *host, size_t capacity, int creating)
{
    const char *cursor = guest;
    size_t used = strlen(session->root);
    int components = 0;

    /* Mode 2 resolves an existing directory for bounded FindFirst searches. */
    int directory = creating == 2;
    if (used == 0u || used + 1u >= capacity) {
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
            if (c < 32u || c == ':' || c == '*' || c == '?' || c == '"' || c == '<' || c == '>' || c == '|' || length + 1u >= sizeof(component)) {
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
            if (dos_find_case_name(host, component, actual, sizeof(actual))) {
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
        if (!last && kind == 0) {
            return 3u;
        }
        if (kind < 0 || (!last && kind != 2) || (last && (directory ? kind != 2 : kind == 2))) {
            return 5u;
        }
        if (last && kind == 0 && !creating) {
            return 2u;
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
    return components != 0 || directory ? 0u : 3u;
}

static void dos_sft_update(xxemul *emulator, const dos_session *session, uint16_t handle);

static uint16_t dos_open_file_path(xxemul *emulator, dos_session *session, const char *guest, uint8_t access, int creating)
{
    char host[DOS_MAX_PATH];
    xx_io_device *device;
    char *saved_path;
    uint16_t error;
    uint16_t handle;
    uint16_t sft;
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
    sft = dos_free_sft(session);
    if (sft == DOS_MAX_HANDLES) return 4u;
    saved_path = (char *)malloc(strlen(host) + 1u);
    if (saved_path == NULL) {
        return 8u;
    }
    memcpy(saved_path, host, strlen(host) + 1u);
    mode = creating == 3 ? "w+bx" : creating ? "w+b" : access == 0u ? "rb" : "r+b";
    device = xx_io_file_open(host, mode);
    if (device == NULL) {
        free(saved_path);
        return errno == ENOENT ? 2u : errno == EMFILE ? 4u : creating == 3 && errno == EEXIST ? 80u : 5u;
    }
    session->handles[handle].device = device;
    session->handles[handle].access = creating ? 2u : access;
    session->handles[handle].host_path = saved_path;
    session->handles[handle].no_inherit = 0;
    session->handles[handle].sft = (uint8_t)sft;
    session->handles[handle].owner = emulator->psp_segment;
    if (creating) dos_forget_temp_attributes(session, host);
    emulator->region_data[dos_jft_address(emulator, handle)] = (uint8_t)sft;
    if (handle < 20u) {
        emulator->region_data[xxemul_dos_linear(emulator->psp_segment, (uint16_t)(0x18u + handle))] = (uint8_t)sft;
    }
    dos_sft_update(emulator, session, handle);
    dos_result(emulator, handle, 0);
    return 0u;
}

static uint16_t dos_open_file(xxemul *emulator, dos_session *session, int creating)
{
    char guest[DOS_MAX_GUEST_PATH];
    uint8_t mode = (uint8_t)emulator->x86.gpr[XXEMUL_X86_RAX];
    uint16_t error;

    if (!dos_guest_name(emulator, guest, sizeof(guest))) {
        return 3u;
    }
    error = dos_open_file_path(emulator, session, guest, creating ? 2u : mode & 3u, creating);
    if (!error && !creating)
        session->handles[(uint16_t)emulator->x86.gpr[XXEMUL_X86_RAX]].no_inherit = (mode & 0x80u) != 0;
    return error;
}

static uint16_t dos_open_extended(xxemul *emulator, dos_session *session)
{
    char guest[DOS_MAX_GUEST_PATH];
    char host[DOS_MAX_PATH];
    uint16_t action = (uint16_t)emulator->x86.gpr[XXEMUL_X86_RDX];
    uint8_t access = (uint8_t)emulator->x86.gpr[XXEMUL_X86_RBX] & 7u;
    uint8_t no_inherit = (emulator->x86.gpr[XXEMUL_X86_RBX] & 0x80u) != 0u;
    uint16_t error;
    uint16_t result_action;
    int existing;
    int creating;

    if ((uint8_t)emulator->x86.gpr[XXEMUL_X86_RAX] != 0u || (action & ~0x13u) != 0u || (action & 3u) > 2u || access > 2u) {
        return 1u;
    }
    if (session == NULL || !dos_guest_name_at(emulator, (uint16_t)emulator->x86.gpr[XXEMUL_X86_RSI], guest, sizeof(guest))) {
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
    error = dos_open_file_path(emulator, session, guest, access, creating);
    if (error == 0u) {
        session->handles[(uint16_t)emulator->x86.gpr[XXEMUL_X86_RAX]].no_inherit = no_inherit;
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
        if (!GetFileAttributesExA(host, GetFileExInfoStandard, &info)) return 0;
        metadata->attributes = (uint16_t)(info.dwFileAttributes & 0x37u);
        metadata->size = info.nFileSizeHigh == 0u ? info.nFileSizeLow : UINT32_MAX;
        if (FileTimeToLocalFileTime(&info.ftLastWriteTime, &local_time)) FileTimeToDosDateTime(&local_time, &metadata->date, &metadata->time);
    }
#else
    {
        struct stat info;
        struct tm local;
        const char *basename = strrchr(host, '/');
        if (stat(host, &info) != 0 || (!S_ISREG(info.st_mode) && !S_ISDIR(info.st_mode))) return 0;
        metadata->attributes = S_ISDIR(info.st_mode) ? 0x10u : 0x20u;
        if ((info.st_mode & S_IWUSR) == 0) metadata->attributes |= 1u;
        if (basename != NULL && basename[1] == '.') metadata->attributes |= 2u;
        metadata->size = (uint64_t)info.st_size <= UINT32_MAX ? (uint32_t)info.st_size : UINT32_MAX;
        if (localtime_r(&info.st_mtime, &local) != NULL && local.tm_year >= 80 && local.tm_year <= 207) {
            metadata->date = (uint16_t)(((local.tm_year - 80) << 9u) | ((local.tm_mon + 1) << 5u) | local.tm_mday);
            metadata->time = (uint16_t)((local.tm_hour << 11u) | (local.tm_min << 5u) | (local.tm_sec / 2));
        }
    }
#endif
    return 1;
}

static int dos_metadata(const dos_session *session, const char *host, dos_file_metadata *metadata)
{
    const dos_temp_attributes *entry;
    if (!dos_host_metadata(host, metadata)) return 0;
    for (entry = session ? session->temp_attributes : NULL; entry; entry = entry->next)
        if (!strcmp(entry->path, host)) { metadata->attributes = entry->attributes; break; }
    return 1;
}

static uint16_t dos_create_temporary(xxemul *emulator, dos_session *session)
{
    char prefix[128], guest[128], host[DOS_MAX_PATH];
    uint16_t attributes = (uint16_t)emulator->x86.gpr[XXEMUL_X86_RCX];
    uint16_t segment = emulator->x86.segment[XXEMUL_X86_DS];
    uint16_t offset = (uint16_t)emulator->x86.gpr[XXEMUL_X86_RDX];
    size_t length, i;
    unsigned attempt;
    if (!session || !dos_guest_name(emulator, prefix, sizeof(prefix))) return 3u;
    if (attributes & ~0x27u) return 5u;
    length = strlen(prefix);
    for (attempt = 0; attempt < 4096u; ++attempt) {
        uint16_t error, handle;
        dos_temp_attributes *entry = NULL;
        unsigned sequence = ++session->temp_sequence % 100000u;
        int count = snprintf(guest, sizeof(guest), "%s%sTMP%05u.TMP", prefix,
                             length && prefix[length - 1u] != '/' && prefix[length - 1u] != '\\' && prefix[length - 1u] != ':' ? "\\" : "", sequence);
        if (count < 0 || count >= (int)sizeof(guest)) return 3u;
        error = dos_resolve(session, guest, host, sizeof(host), 1);
        if (error) return error;
        if (dos_path_kind(host) != 0) continue;
        if (attributes & 6u) {
            dos_temp_attributes *p;
            size_t entries = 0u;
            for (p = session->temp_attributes; p; p = p->next) ++entries;
            if (entries >= 4096u || !(entry = (dos_temp_attributes *)calloc(1u, sizeof(*entry)))) return 8u;
            strcpy(entry->path, host); entry->attributes = attributes | 0x20u;
        }
        /* Exclusive creation prevents a concurrent file from being replaced
         * between the existence check and opening the chosen short name. */
        error = dos_open_file_path(emulator, session, guest, 2u, 3);
        if (error) { free(entry); if (error == 80u) continue; return error; }
        handle = (uint16_t)emulator->x86.gpr[XXEMUL_X86_RAX];
#if defined(_WIN32)
        if (!SetFileAttributesA(host, attributes | FILE_ATTRIBUTE_ARCHIVE)) error = 5u;
#else
        if (attributes & 1u) {
            struct stat info;
            if (stat(host, &info) != 0 || chmod(host, info.st_mode & ~(S_IWUSR | S_IWGRP | S_IWOTH)) != 0) error = 5u;
        }
#endif
        if (error) {
            dos_drop_handle(session, handle);
            emulator->region_data[dos_jft_address(emulator, handle)] = 0xffu;
            if (handle < 20u) emulator->region_data[xxemul_dos_linear(emulator->psp_segment, (uint16_t)(0x18u + handle))] = 0xffu;
            dos_sft_update(emulator, session, handle);
            remove(host); free(entry); return error;
        }
        if (entry) { entry->next = session->temp_attributes; session->temp_attributes = entry; }
        for (i = 0; i <= (size_t)count; ++i)
            emulator->region_data[xxemul_dos_linear(segment, (uint16_t)(offset + i))] = (uint8_t)guest[i];
        dos_sft_update(emulator, session, handle);
        return 0u;
    }
    return 80u;
}

/* AH=5B creates a compatibility-mode read/write handle, but must never
 * truncate an existing DOS name. AL is unspecified, not a subfunction. */
static uint16_t dos_create_new(xxemul *emulator, dos_session *session)
{
    char guest[DOS_MAX_GUEST_PATH], host[DOS_MAX_PATH];
    uint16_t attributes = (uint16_t)emulator->x86.gpr[XXEMUL_X86_RCX];
    uint16_t error, handle;
    dos_temp_attributes *entry = NULL;
    if (!session || !dos_guest_name(emulator, guest, sizeof(guest))) return 3u;
    if (attributes & ~0x27u) return 5u;
    error = dos_resolve(session, guest, host, sizeof(host), 1);
    if (error) return error;
    if (dos_path_kind(host) != 0) return 80u;
    if (attributes & 6u) {
        dos_temp_attributes *p;
        size_t entries = 0u;
        for (p = session->temp_attributes; p; p = p->next) ++entries;
        if (entries >= 4096u || !(entry = (dos_temp_attributes *)calloc(1u, sizeof(*entry)))) return 8u;
        strcpy(entry->path, host); entry->attributes = attributes | 0x20u;
    }
    /* Resolve case-insensitively, then also use exclusive host creation to
     * protect against a file appearing after the initial existence check. */
    error = dos_open_file_path(emulator, session, guest, 2u, 3);
    if (error) { free(entry); return error == 2u ? 3u : error; }
    handle = (uint16_t)emulator->x86.gpr[XXEMUL_X86_RAX];
#if defined(_WIN32)
    if (!SetFileAttributesA(host, attributes | FILE_ATTRIBUTE_ARCHIVE)) error = 5u;
#else
    if (attributes & 1u) {
        struct stat info;
        if (stat(host, &info) != 0 || chmod(host, info.st_mode & ~(S_IWUSR | S_IWGRP | S_IWOTH)) != 0) error = 5u;
    }
#endif
    if (error) {
        dos_drop_handle(session, handle);
        emulator->region_data[dos_jft_address(emulator, handle)] = 0xffu;
        if (handle < 20u) emulator->region_data[xxemul_dos_linear(emulator->psp_segment, (uint16_t)(0x18u + handle))] = 0xffu;
        dos_sft_update(emulator, session, handle);
        remove(host); free(entry); return error;
    }
    if (entry) { entry->next = session->temp_attributes; session->temp_attributes = entry; }
    dos_sft_update(emulator, session, handle);
    return 0u;
}

static int dos_set_host_time(const char *host, uint16_t date, uint16_t clock)
{
    if ((date & 31u) == 0u || ((date >> 5u) & 15u) == 0u || ((date >> 5u) & 15u) > 12u || (clock & 31u) > 29u || ((clock >> 5u) & 63u) > 59u ||
        ((clock >> 11u) & 31u) > 23u) {
        return 0;
    }
#if defined(_WIN32)
    {
        FILETIME local_time;
        FILETIME utc_time;
        HANDLE file;
        int success;

        if (!DosDateTimeToFileTime(date, clock, &local_time) || !LocalFileTimeToFileTime(&local_time, &utc_time)) {
            return 0;
        }
        file = CreateFileA(host, FILE_WRITE_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
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
    uint16_t segment = (uint16_t)(DOS_SFT_SEGMENT + (handle / DOS_SFT_ENTRIES_PER_TABLE) * DOS_SFT_TABLE_PARAGRAPHS);
    uint16_t offset = (uint16_t)(6u + (handle % DOS_SFT_ENTRIES_PER_TABLE) * DOS_SFT_ENTRY_SIZE);
    return emulator->region_data + xxemul_dos_linear(segment, offset);
}

static void dos_sft_fill(xxemul *emulator, const dos_session *session, uint16_t handle)
{
    uint8_t *entry = dos_sft_entry(emulator, handle);
    const dos_handle *file = NULL;
    dos_file_metadata metadata;
    const char *name;
    const char *dot;
    int have_metadata;
    int64_t live_size;
    int64_t position;
    size_t index;
    unsigned level, references = 0;

    memset(entry, 0, DOS_SFT_ENTRY_SIZE);
    if (handle < 5u) {
        xxemul_dos_write_word(entry, (uint16_t)(session ? session->depth + 1u : 1u));
        xxemul_dos_write_word(entry + 2u, 2u);
        xxemul_dos_write_word(entry + 5u, 0x80d3u);
        memcpy(entry + 0x20u, "CON        ", 11u);
        return;
    }
    if (session == NULL) {
        return;
    }
    for (index = 5u; index < DOS_MAX_HANDLES; ++index)
        if (session->handles[index].device && session->handles[index].sft == handle) {
            file = &session->handles[index]; ++references;
        }
    for (level = 0; level < session->depth; ++level)
        for (index = 5u; index < DOS_MAX_HANDLES; ++index)
            if (session->parents[level].handles[index].device && session->parents[level].handles[index].sft == handle) {
                if (!file) file = &session->parents[level].handles[index];
                ++references;
            }
    if (file == NULL || file->host_path == NULL) {
        return;
    }
    xxemul_dos_write_word(entry, (uint16_t)references);
    xxemul_dos_write_word(entry + 2u, file->access);
    xxemul_dos_write_word(entry + 5u, 2u);
    xxemul_dos_write_word(entry + 0x31u, file->owner);
    have_metadata = dos_metadata(session, file->host_path, &metadata);
    if (have_metadata) {
        entry[4u] = (uint8_t)metadata.attributes;
        xxemul_dos_write_word(entry + 0x0du, metadata.time);
        xxemul_dos_write_word(entry + 0x0fu, metadata.date);
    }
    /* The path metadata can lag writes buffered by an open FILE stream.  The
       SFT describes the live handle, so prefer its size while it is open. */
    live_size = xx_io_total_size(file->device);
    if (live_size >= 0 && live_size <= UINT32_MAX) {
        metadata.size = (uint32_t)live_size;
        have_metadata = 1;
    }
    if (have_metadata) {
        xxemul_dos_write_word(entry + 0x11u, (uint16_t)metadata.size);
        xxemul_dos_write_word(entry + 0x13u, (uint16_t)(metadata.size >> 16u));
    }
    position = xx_io_tell(file->device);
    if (position >= 0 && position <= UINT32_MAX) {
        xxemul_dos_write_word(entry + 0x15u, (uint16_t)position);
        xxemul_dos_write_word(entry + 0x17u, (uint16_t)((uint64_t)position >> 16u));
    }
    memset(entry + 0x20u, ' ', 11u);
    name = strrchr(file->host_path, '/');
    name = name == NULL ? file->host_path : name + 1u;
    dot = strrchr(name, '.');
    for (index = 0u; index < 8u && name[index] != '\0' && (dot == NULL || name + index < dot); ++index) {
        entry[0x20u + index] = (uint8_t)toupper((unsigned char)name[index]);
    }
    if (dot != NULL) {
        for (index = 0u; index < 3u && dot[index + 1u] != '\0'; ++index) {
            entry[0x28u + index] = (uint8_t)toupper((unsigned char)dot[index + 1u]);
        }
    }
}

static void dos_sft_update(xxemul *emulator, const dos_session *session, uint16_t handle)
{
    dos_sft_fill(emulator, session, handle < 5u || !session ? handle : session->handles[handle].sft);
}

static void dos_kernel_initialize(xxemul *emulator, dos_session *session)
{
    uint8_t *memory = emulator->region_data;
    uint8_t *lol = memory + xxemul_dos_linear(DOS_LOL_SEGMENT, DOS_LOL_OFFSET);
    uint8_t *jft = memory + xxemul_dos_linear(DOS_JFT_SEGMENT, 0u);
    uint8_t *psp = memory + xxemul_dos_linear(emulator->psp_segment, 0u);
    uint16_t table;
    uint16_t handle;

    memset(memory + xxemul_dos_linear(DOS_SFT_SEGMENT, 0u), 0, DOS_MAX_HANDLES / DOS_SFT_ENTRIES_PER_TABLE * 0x400u);
    memset(lol - 2u, 0, 0x42u);
    memset(jft, 0xff, DOS_MAX_HANDLES);
    memset(psp + 0x18u, 0xff, 20u);
    xxemul_dos_write_word(lol - 2u, (uint16_t)(emulator->psp_segment - 1u));
    xxemul_dos_write_word(lol + 4u, 0u);
    xxemul_dos_write_word(lol + 6u, DOS_SFT_SEGMENT);
    lol[0x20u] = 1u;
    lol[0x21u] = 26u;
    for (table = 0u; table < DOS_MAX_HANDLES / DOS_SFT_ENTRIES_PER_TABLE; ++table) {
        uint16_t segment = (uint16_t)(DOS_SFT_SEGMENT + table * DOS_SFT_TABLE_PARAGRAPHS);
        uint8_t *header = memory + xxemul_dos_linear(segment, 0u);
        int last = table + 1u == DOS_MAX_HANDLES / DOS_SFT_ENTRIES_PER_TABLE;
        xxemul_dos_write_word(header, last ? 0xffffu : 0u);
        xxemul_dos_write_word(header + 2u, last ? 0xffffu : (uint16_t)(segment + DOS_SFT_TABLE_PARAGRAPHS));
        xxemul_dos_write_word(header + 4u, DOS_SFT_ENTRIES_PER_TABLE);
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

static uint16_t dos_file_attributes(xxemul *emulator, const dos_session *session)
{
    char guest[DOS_MAX_GUEST_PATH];
    char host[DOS_MAX_PATH];
    uint16_t error;
    dos_file_metadata metadata;

    if (session == NULL || !dos_guest_name(emulator, guest, sizeof(guest))) return 3u;
    if ((uint8_t)emulator->x86.gpr[XXEMUL_X86_RAX] != 0u) return 1u;
    error = dos_resolve(session, guest, host, sizeof(host), 0);
    if (error != 0u) return error;
    if (!dos_metadata(session, host, &metadata)) return 5u;
    emulator->x86.gpr[XXEMUL_X86_RCX] = (emulator->x86.gpr[XXEMUL_X86_RCX] & ~UINT64_C(0xffff)) | metadata.attributes;
    dos_result(emulator, 0u, 0);
    return 0u;
}

static uint16_t dos_delete_file(xxemul *emulator, dos_session *session)
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
    dos_forget_temp_attributes(session, host);
    dos_result(emulator, 0u, 0);
    return 0u;
}

/* Expand the DOS 8.3 wildcard fields, including '?' matching padded spaces.
 * A bare '*' is the traditional '*.*'; names requiring synthesized LFN aliases
 * are deliberately excluded from this short-name service. */
static int dos_short_pattern(const char *name, uint8_t fields[11], int pattern)
{
    unsigned field = 0u, index = 0u;
    int star = 0;
    if (!*name || !strcmp(name, ".") || !strcmp(name, "..")) return 0;
    memset(fields, ' ', 11u);
    if (pattern && !strcmp(name, "*")) { memset(fields, '?', 11u); return 1; }
    for (; *name; ++name) {
        unsigned char c = (unsigned char)*name;
        if (c == '.') {
            if (field != 0u) return 0;
            field = 8u; index = 0u; star = 0;
            continue;
        }
        if (c <= 32u || strchr("\\/:\"<>|", c)) return 0;
        if (c == '*' && pattern) {
            while (index < (field ? 3u : 8u)) fields[field + index++] = '?';
            star = 1;
            continue;
        }
        if (star) continue;
        if ((!pattern && (c == '*' || c == '?')) || index >= (field ? 3u : 8u)) return 0;
        fields[field + index++] = (uint8_t)toupper(c);
    }
    return fields[0] != ' ';
}

static int dos_search_compare(const void *a, const void *b)
{ return strcmp((const char *)a + 0x1eu, (const char *)b + 0x1eu); }

static uint16_t dos_search_add(const dos_session *session, dos_search *search, const char *directory, const char *name, const uint8_t pattern[11], uint16_t attributes)
{
    uint8_t fields[11], record[43] = {0};
    dos_file_metadata metadata;
    char host[DOS_MAX_PATH];
    uint8_t (*grown)[43];
    size_t i;
    if (!dos_short_pattern(name, fields, 0)) return 0u;
    for (i = 0; i < 11u; ++i) if (pattern[i] != '?' && pattern[i] != fields[i]) return 0u;
    if (snprintf(host, sizeof(host), "%s/%s", directory, name) >= (int)sizeof(host)) return 0u;
    if (dos_path_kind(host) <= 0 || !dos_metadata(session, host, &metadata)) return 0u;
    /* A broad mask such as 00FFh includes normal files. Only a volume-only
     * search (ignoring readonly/archive/device bits) excludes them. */
    if ((metadata.attributes & (2u | 4u | 0x10u) & ~attributes) != 0u ||
        (((attributes & 0xffu) & ~(1u | 0x20u | 0x40u)) == 8u)) return 0u;
    if (search->count == DOS_MAX_SEARCH_RESULTS) return 8u;
    grown = (uint8_t (*)[43])realloc(search->records, (search->count + 1u) * sizeof(record));
    if (!grown) return 8u;
    search->records = grown;
    record[0x15u] = (uint8_t)metadata.attributes;
    xxemul_dos_write_word(record + 0x16u, metadata.time);
    xxemul_dos_write_word(record + 0x18u, metadata.date);
    for (i = 0; i < 4u; ++i) record[0x1au + i] = (uint8_t)(metadata.size >> (8u * i));
    for (i = 0; name[i]; ++i) record[0x1eu + i] = (uint8_t)toupper((unsigned char)name[i]);
    memcpy(search->records[search->count++], record, sizeof(record));
    return 0u;
}

static uint16_t dos_find_next(xxemul *emulator, dos_session *session)
{
    uint32_t dta = xxemul_dos_linear(emulator->dos_dta_segment, emulator->dos_dta_offset);
    dos_search *search;
    if (!session) return 18u;
    for (search = session->searches; search; search = search->next) if (search->dta == dta) break;
    if (!search || search->next_record >= search->count) return 18u;
    if (xxemul_write_memory(emulator, dta, search->records[search->next_record], 43u) != XXEMUL_STATUS_OK) return 5u;
    ++search->next_record;
    dos_result(emulator, 0u, 0);
    return 0u;
}

static uint16_t dos_find_first(xxemul *emulator, dos_session *session)
{
    char guest[DOS_MAX_GUEST_PATH], directory[DOS_MAX_PATH], *name, *cursor;
    uint8_t pattern[11];
    uint16_t error = 0u, attributes = (uint16_t)emulator->x86.gpr[XXEMUL_X86_RCX];
    uint32_t dta = xxemul_dos_linear(emulator->dos_dta_segment, emulator->dos_dta_offset);
    dos_search *search, **link;
    unsigned searches = 0u;
    if (!session || !dos_guest_name(emulator, guest, sizeof(guest))) return 3u;
    for (link = &session->searches; *link;) {
        if ((*link)->dta == dta) {
            search = *link; *link = search->next; free(search->records); free(search);
        } else { ++searches; link = &(*link)->next; }
    }
    if (searches >= DOS_MAX_SEARCHES) return 8u;
    name = guest;
    for (cursor = guest; *cursor; ++cursor) if (*cursor == '/' || *cursor == '\\' || *cursor == ':') name = cursor + 1;
    if (!dos_short_pattern(name, pattern, 1)) return 3u;
    if (name == guest) error = dos_resolve(session, "\\", directory, sizeof(directory), 2);
    else { *name = '\0'; error = dos_resolve(session, guest, directory, sizeof(directory), 2); }
    if (error) return error;
    search = (dos_search *)calloc(1u, sizeof(*search));
    if (!search) return 8u;
    search->dta = dta;
#if defined(_WIN32)
    {
        WIN32_FIND_DATAA data;
        HANDLE handle;
        char wildcard[DOS_MAX_PATH];
        if (snprintf(wildcard, sizeof(wildcard), "%s/*", directory) >= (int)sizeof(wildcard)) error = 3u;
        else {
            handle = FindFirstFileA(wildcard, &data);
            if (handle == INVALID_HANDLE_VALUE) error = 18u;
            else {
                do { error = dos_search_add(session, search, directory, data.cFileName, pattern, attributes); }
                while (!error && FindNextFileA(handle, &data));
                FindClose(handle);
            }
        }
    }
#else
    {
        DIR *handle = opendir(directory);
        struct dirent *entry;
        if (!handle) error = 3u;
        else {
            while (!error && (entry = readdir(handle)) != NULL)
                error = dos_search_add(session, search, directory, entry->d_name, pattern, attributes);
            closedir(handle);
        }
    }
#endif
    if (!error && !search->count) error = 18u;
    if (error) { free(search->records); free(search); return error; }
    qsort(search->records, search->count, sizeof(search->records[0]), dos_search_compare);
    search->next = session->searches; session->searches = search;
    return dos_find_next(emulator, session);
}

static uint16_t dos_rename_file(xxemul *emulator, dos_session *session)
{
    char source[DOS_MAX_GUEST_PATH], destination[DOS_MAX_GUEST_PATH];
    char old_path[DOS_MAX_PATH], new_path[DOS_MAX_PATH];
    char *replacements[DOS_MAX_PROCESS_DEPTH + 1u][DOS_MAX_HANDLES] = {{0}};
    dos_handle *tables[DOS_MAX_PROCESS_DEPTH + 1u];
    uint16_t error;
    size_t i, level;
    if (!session || !dos_guest_name(emulator, source, sizeof(source)) ||
        !dos_guest_name_segment(emulator, emulator->x86.segment[XXEMUL_X86_ES], (uint16_t)emulator->x86.gpr[XXEMUL_X86_RDI], destination, sizeof(destination))) return 3u;
    error = dos_resolve(session, source, old_path, sizeof(old_path), 0);
    if (error) return error;
    error = dos_resolve(session, destination, new_path, sizeof(new_path), 1);
    if (error) return error;
    if (dos_path_kind(new_path) != 0) return 5u;
    tables[0] = session->handles;
    for (level = 0; level < session->depth; ++level) tables[level + 1u] = session->parents[level].handles;
    for (level = 0; level <= session->depth && !error; ++level)
        for (i = 5u; i < DOS_MAX_HANDLES; ++i) if (tables[level][i].host_path && !strcmp(tables[level][i].host_path, old_path)) {
            replacements[level][i] = (char *)malloc(strlen(new_path) + 1u);
            if (!replacements[level][i]) { error = 8u; break; }
            strcpy(replacements[level][i], new_path);
        }
    if (!error && rename(old_path, new_path) != 0) error = errno == ENOENT ? 2u : 5u;
    if (!error) {
        dos_temp_attributes *entry;
        for (entry = session->temp_attributes; entry; entry = entry->next)
            if (!strcmp(entry->path, old_path)) strcpy(entry->path, new_path);
    }
    for (level = 0; level <= session->depth; ++level)
        for (i = 5u; i < DOS_MAX_HANDLES; ++i) if (replacements[level][i]) {
            if (!error) {
                free(tables[level][i].host_path);
                tables[level][i].host_path = replacements[level][i];
                dos_sft_fill(emulator, session, tables[level][i].sft);
            } else free(replacements[level][i]);
        }
    if (!error) dos_result(emulator, 0u, 0);
    return error;
}

static uint16_t dos_transfer(xxemul *emulator, dos_session *session, int writing)
{
    uint16_t handle = (uint16_t)emulator->x86.gpr[XXEMUL_X86_RBX];
    uint16_t count = (uint16_t)emulator->x86.gpr[XXEMUL_X86_RCX];
    uint16_t segment = emulator->x86.segment[XXEMUL_X86_DS];
    uint16_t offset = (uint16_t)emulator->x86.gpr[XXEMUL_X86_RDX];
    xx_io_device *device;
    uint8_t *buffer;
    ssize_t transferred;
    size_t index;

    if (session == NULL || handle < 5u || handle >= DOS_MAX_HANDLES || session->handles[handle].device == NULL) {
        return 6u;
    }
    if ((writing && session->handles[handle].access == 0u) || (!writing && session->handles[handle].access == 1u)) {
        return 5u;
    }
    if (count == 0u) {
        if (writing) {
            int64_t current = xx_io_tell(session->handles[handle].device);
            if (current < 0 || current > DOS_MAX_FILE_SIZE || xx_io_resize(session->handles[handle].device, current) != 0) return 5u;
            dos_sft_update(emulator, session, handle);
        }
        dos_result(emulator, 0u, 0);
        return 0u;
    }
    device = session->handles[handle].device;
    if (writing) {
        int64_t current = xx_io_tell(device);
        if (current < 0 || current > DOS_MAX_FILE_SIZE || count > DOS_MAX_FILE_SIZE - (uint64_t)current) {
            return 0x27u;
        }
    }
    buffer = (uint8_t *)malloc(count);
    if (buffer == NULL) {
        return 8u;
    }
    if (writing) {
        for (index = 0u; index < count; ++index) {
            buffer[index] = emulator->region_data[xxemul_dos_linear(segment, (uint16_t)(offset + index))];
        }
        transferred = xx_io_write(device, buffer, count);
    } else {
        transferred = xx_io_read(device, buffer, count);
        if (transferred > 0) {
            for (index = 0u; index < (size_t)transferred; ++index) {
                emulator->region_data[xxemul_dos_linear(segment, (uint16_t)(offset + index))] = buffer[index];
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
    uint32_t raw = ((uint32_t)(uint16_t)emulator->x86.gpr[XXEMUL_X86_RCX] << 16) | (uint16_t)emulator->x86.gpr[XXEMUL_X86_RDX];
    int64_t offset = (int32_t)raw;
    int64_t position;
    xx_io_device *device;

    if (session == NULL || handle < 5u || handle >= DOS_MAX_HANDLES || session->handles[handle].device == NULL) {
        return 6u;
    }
    if (origin > 2u) {
        return 1u;
    }
    device = session->handles[handle].device;
    if (xx_io_seek64(device, offset, origin == 0u ? SEEK_SET : origin == 1u ? SEEK_CUR : SEEK_END) != 0) {
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
    return attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_DIRECTORY) != 0u && (attributes & FILE_ATTRIBUTE_REPARSE_POINT) == 0u;
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

static int dos_tail(uint8_t tail[128], size_t argc, const char *const *argv)
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
        if (strpbrk(value, "\r\n\"") != NULL || length + 1u + count + (quote ? 2u : 0u) > 126u) {
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

static int dos_environment(uint8_t environment[512], const char *guest_exe_name)
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

xxemul_status xxemul_dos_files_start(xxemul *emulator, const char *workdir, const char *guest_exe_name, size_t argc, const char *const *argv)
{
    dos_session *session;
    uint8_t tail[128];
    uint8_t environment[512];
    uint8_t *psp;

    if (emulator == NULL || !emulator->dos_mode || workdir == NULL || guest_exe_name == NULL || (argc != 0u && argv == NULL)) {
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
    if (!dos_environment(environment, guest_exe_name) || !dos_tail(tail, argc, argv)) {
        free(session);
        return XXEMUL_STATUS_INVALID_ARGUMENT;
    }
    xxemul_dos_files_stop(emulator);
    psp = emulator->region_data + xxemul_dos_linear(emulator->psp_segment, 0u);
    memcpy(emulator->region_data + 0x7000u, environment, sizeof(environment));
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
    for (;;) {
        for (index = 5u; index < DOS_MAX_HANDLES; ++index) dos_drop_handle(session, (unsigned)index);
        if (!session->depth) break;
        --session->depth;
        memcpy(session->handles, session->parents[session->depth].handles, sizeof(session->handles));
        while (session->parents[session->depth].searches) {
            dos_search *search = session->parents[session->depth].searches;
            session->parents[session->depth].searches = search->next;
            free(search->records); free(search);
        }
    }
    while (session->searches) {
        dos_search *search = session->searches;
        session->searches = search->next;
        free(search->records);
        free(search);
    }
    while (session->temp_attributes) {
        dos_temp_attributes *entry = session->temp_attributes;
        session->temp_attributes = entry->next; free(entry);
    }
    free(session);
}

xxemul_status xxemul_dos_buffered_input(xxemul *emulator)
{
    uint16_t segment = emulator->x86.segment[XXEMUL_X86_DS];
    uint16_t offset = (uint16_t)emulator->x86.gpr[XXEMUL_X86_RDX];
    uint32_t address = xxemul_dos_linear(segment, offset);
    uint8_t maximum = emulator->region_data[address];
    dos_session *session;
    if (!maximum) return XXEMUL_STATUS_OK;
    dos_lock();
    session = dos_find_or_create(emulator);
    if (!session) { dos_unlock(); return XXEMUL_STATUS_OUT_OF_MEMORY; }
    if (!session->input_pending || session->input_buffer != address) {
        session->input_buffer = address;
        session->input_count = 0u;
        session->input_pending = 1u;
        emulator->region_data[xxemul_dos_linear(segment, (uint16_t)(offset + 1u))] = 0u;
    }
    if (session->input_count >= maximum) session->input_count = (uint8_t)(maximum - 1u);
    while (emulator->key_count) {
        uint8_t character = (uint8_t)emulator->key_queue[emulator->key_head];
        emulator->key_head = (uint8_t)((emulator->key_head + 1u) % 32u);
        --emulator->key_count;
        if (character == 0u || character == 0xe0u || character == '\n') continue;
        if (character == '\r') {
            emulator->region_data[xxemul_dos_linear(segment, (uint16_t)(offset + 2u + session->input_count))] = '\r';
            session->input_pending = 0u;
            xxemul_video_putc(emulator, '\r');
            xxemul_video_putc(emulator, '\n');
            dos_unlock();
            return XXEMUL_STATUS_OK;
        }
        if (character == '\b') {
            if (session->input_count) {
                --session->input_count;
                xxemul_video_putc(emulator, '\b'); xxemul_video_putc(emulator, ' '); xxemul_video_putc(emulator, '\b');
            }
        } else if (session->input_count + 1u < maximum) {
            emulator->region_data[xxemul_dos_linear(segment, (uint16_t)(offset + 2u + session->input_count++))] = character;
            xxemul_video_putc(emulator, character);
        } else xxemul_video_putc(emulator, '\a');
        emulator->region_data[xxemul_dos_linear(segment, (uint16_t)(offset + 1u))] = session->input_count;
    }
    dos_unlock();
    return XXEMUL_STATUS_INPUT_REQUIRED;
}

xxemul_status xxemul_dos_flush_input_begin(xxemul *emulator, uint8_t function)
{
    dos_session *session;
    uint16_t cs = emulator->x86.segment[XXEMUL_X86_CS], ip = (uint16_t)emulator->x86.ip;
    uint16_t ds = emulator->x86.segment[XXEMUL_X86_DS], dx = (uint16_t)emulator->x86.gpr[XXEMUL_X86_RDX];
    dos_lock();
    session = dos_find_or_create(emulator);
    if (!session) { dos_unlock(); return XXEMUL_STATUS_OUT_OF_MEMORY; }
    if (!session->flush_pending || session->flush_function != function || session->flush_cs != cs || session->flush_ip != ip ||
        session->flush_ds != ds || session->flush_dx != dx) {
        emulator->key_head = emulator->key_count = 0u;
        session->input_pending = 0u;
        session->flush_pending = 1u;
        session->flush_function = function;
        session->flush_cs = cs; session->flush_ip = ip;
        session->flush_ds = ds; session->flush_dx = dx;
    }
    dos_unlock();
    return XXEMUL_STATUS_OK;
}

void xxemul_dos_flush_input_end(xxemul *emulator, xxemul_status status)
{
    dos_session *session;
    if (status == XXEMUL_STATUS_INPUT_REQUIRED) return;
    dos_lock();
    session = dos_find(emulator);
    if (session) session->flush_pending = 0u;
    dos_unlock();
}

int xxemul_dos_files_list_of_lists(xxemul *emulator, uint16_t *segment, uint16_t *offset)
{
    if (emulator == NULL || !emulator->dos_mode || segment == NULL || offset == NULL) {
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

int xxemul_dos_files_set_allocation_strategy(xxemul *emulator, uint16_t strategy)
{
    dos_session *session;
    int success = 0;

    if (strategy > 2u && (strategy < 0x40u || strategy > 0x42u) && (strategy < 0x80u || strategy > 0x82u)) {
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

int xxemul_dos_files_drive_space(xxemul *emulator, uint16_t *available, uint16_t *total)
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

        if (GetDiskFreeSpaceExA(session->root, &available_size, &total_size, NULL)) {
            available_bytes = available_size.QuadPart;
            total_bytes = total_size.QuadPart;
            success = 1;
        }
#else
        struct statvfs info;

        if (statvfs(session->root, &info) == 0) {
            uint64_t unit = info.f_frsize != 0u ? (uint64_t)info.f_frsize : (uint64_t)info.f_bsize;
            uint64_t blocks = (uint64_t)info.f_blocks;
            uint64_t free_blocks = (uint64_t)info.f_bavail;

            total_bytes = unit != 0u && blocks > UINT64_MAX / unit ? UINT64_MAX : blocks * unit;
            available_bytes = unit != 0u && free_blocks > UINT64_MAX / unit ? UINT64_MAX : free_blocks * unit;
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

typedef struct dos_child_image {
    uint8_t *bytes;
    size_t size, header, body, relocations, table;
    uint16_t minalloc, maxalloc, cs, ip, ss, sp;
    int mz;
} dos_child_image;

static uint16_t dos_word(const uint8_t *p)
{ return (uint16_t)(p[0] | ((uint16_t)p[1] << 8u)); }

uint16_t xxemul_dos_files_mcb_head(const xxemul *emulator)
{
    uint16_t head = dos_word(emulator->region_data + ((uint32_t)DOS_LOL_SEGMENT << 4u) + DOS_LOL_OFFSET - 2u);
    return head >= 0x0813u && head < 0xa000u ? head : 0x0813u;
}

static void dos_real_read(xxemul *emulator, uint16_t segment, uint16_t offset, void *output, size_t size)
{
    uint8_t *p = (uint8_t *)output;
    size_t i;
    for (i = 0; i < size; ++i)
        p[i] = emulator->region_data[xxemul_dos_physical(emulator, segment, (uint16_t)(offset + i))];
}

static uint16_t dos_child_read(dos_session *session, const char *name, char *host, dos_child_image *image)
{
    xx_io_device *file;
    int64_t size;
    size_t done = 0, i;
    uint16_t error = dos_resolve(session, name, host, DOS_MAX_PATH, 0);
    if (error) return error;
    file = xx_io_file_open(host, "rb");
    if (!file) return errno == ENOENT ? 2u : 5u;
    size = xx_io_size(file);
    if (size <= 0 || size > DOS_MAX_FILE_SIZE) { xx_io_close(file); return 11u; }
    image->bytes = (uint8_t *)malloc((size_t)size);
    if (!image->bytes) { xx_io_close(file); return 8u; }
    image->size = (size_t)size;
    while (done < image->size) {
        long count = xx_io_read(file, image->bytes + done, (long)(image->size - done));
        if (count <= 0) { error = 5u; break; }
        done += (size_t)count;
    }
    xx_io_close(file);
    if (error) return error;
    image->mz = image->size >= 2u && (dos_word(image->bytes) == 0x5a4du || dos_word(image->bytes) == 0x4d5au);
    if (!image->mz) {
        if (image->size >= 0xff00u) return 8u;
        image->body = image->size;
        return 0u;
    }
    if (image->size < 28u) return 11u;
    {
        const uint8_t *p = image->bytes;
        uint16_t pages = dos_word(p + 4u), last = dos_word(p + 2u);
        size_t declared;
        if (!pages || last > 512u || dos_word(p + 26u)) return 11u;
        declared = ((size_t)pages - 1u) * 512u + (last ? last : 512u);
        image->header = (size_t)dos_word(p + 8u) * 16u;
        image->relocations = dos_word(p + 6u); image->table = dos_word(p + 24u);
        if (image->header < 28u || image->header >= declared || declared > image->size ||
            (image->relocations && (image->table > image->header || image->relocations > (image->header - image->table) / 4u))) return 11u;
        image->body = declared - image->header;
        if (image->body > 0x90000u) return 8u;
        if (image->header >= 64u) {
            uint32_t other = (uint32_t)dos_word(p + 60u) | ((uint32_t)dos_word(p + 62u) << 16u);
            if (other <= image->size && image->size - other >= 2u &&
                ((p[other] == 'P' && p[other + 1u] == 'E') || (p[other] == 'N' && p[other + 1u] == 'E'))) return 11u;
        }
        image->minalloc = dos_word(p + 10u); image->maxalloc = dos_word(p + 12u);
        image->ss = dos_word(p + 14u); image->sp = dos_word(p + 16u);
        image->ip = dos_word(p + 20u); image->cs = dos_word(p + 22u);
        for (i = 0; i < image->relocations; ++i) {
            const uint8_t *entry = p + image->table + i * 4u;
            size_t site = (size_t)dos_word(entry + 2u) * 16u + dos_word(entry);
            if (site >= image->body || image->body - site < 2u) return 11u;
        }
    }
    return 0u;
}

/* Reuse the conventional MCB allocator without changing the calling state. */
static uint16_t dos_process_memory(xxemul *emulator, uint16_t function, uint16_t argument, uint16_t *value)
{
    xxemul_x86_state saved = emulator->x86;
    xxemul_status status;
    uint16_t error;
    emulator->x86.gpr[XXEMUL_X86_RAX] = (uint16_t)(function << 8u);
    emulator->x86.gpr[XXEMUL_X86_RBX] = argument;
    if (function == 0x49u) emulator->x86.segment[XXEMUL_X86_ES] = argument;
    status = xxemul_msdos_interrupt(emulator, 0x21u);
    error = status != XXEMUL_STATUS_OK ? 8u : emulator->x86.flags & DOS_CF ? (uint16_t)emulator->x86.gpr[XXEMUL_X86_RAX] : 0u;
    if (value) *value = (uint16_t)emulator->x86.gpr[error ? XXEMUL_X86_RBX : XXEMUL_X86_RAX];
    emulator->x86 = saved;
    return error;
}

static void dos_process_handles(xxemul *emulator, dos_session *session)
{
    uint8_t *psp = emulator->region_data + ((uint32_t)emulator->psp_segment << 4u);
    unsigned i;
    for (i = 0; i < DOS_MAX_HANDLES; ++i) {
        uint8_t value = i < 5u ? (uint8_t)i : session->handles[i].device ? session->handles[i].sft : 0xffu;
        emulator->region_data[dos_jft_address(emulator, (uint16_t)i)] = value;
        if (i < 20u) psp[0x18u + i] = value;
        dos_sft_fill(emulator, session, (uint16_t)i);
    }
    xxemul_dos_write_word(psp + 0x32u, DOS_MAX_HANDLES);
}

static void dos_process_segments(xxemul *emulator)
{
    unsigned i;
    for (i = 0; i < 6u; ++i) {
        xxemul_x86_segment_cache *cache = emulator->dos_segments + i;
        cache->base = (uint32_t)emulator->x86.segment[i] << 4u;
        cache->limit = 0xffffu; cache->access = i == XXEMUL_X86_CS ? 0x9bu : 0x93u;
        cache->flags = 0u; cache->valid = 1u;
    }
}

xxemul_status xxemul_dos_files_exec(xxemul *emulator)
{
    dos_session *session;
    dos_parent parent;
    dos_handle inherited[DOS_MAX_HANDLES] = {{0}};
    dos_child_image image = {0};
    char name[DOS_MAX_GUEST_PATH], host[DOS_MAX_PATH];
    uint8_t block[14], tail[128] = {0}, fcb[32] = {0}, *environment = NULL;
    uint16_t env_segment, env_block = 0, child = 0, allocation = 0, largest = 0, load = 0;
    uint16_t error = 0, command_segment, command_offset;
    size_t env_size = 0, env_capacity = 0x8000u + DOS_MAX_GUEST_PATH + 4u, i;
    uint32_t minimum, maximum, body_paragraphs;
    xxemul_x86_state state;

    if (!emulator || !emulator->dos_mode) return XXEMUL_STATUS_INVALID_ARGUMENT;
    dos_lock(); session = dos_find(emulator); dos_unlock();
    if (!session || (uint8_t)emulator->x86.gpr[XXEMUL_X86_RAX] ||
        (emulator->dos_cr0 & 1u) || emulator->mode != XXEMUL_MODE_X86_16) { dos_result(emulator, 1u, 1); return XXEMUL_STATUS_OK; }
    if (session->depth >= DOS_MAX_PROCESS_DEPTH) { dos_result(emulator, 8u, 1); return XXEMUL_STATUS_OK; }
    for (i = 0; i < 6u; ++i) if (emulator->dos_segments[i].valid &&
        (emulator->dos_segments[i].base != (uint32_t)emulator->x86.segment[i] * 16u || emulator->dos_segments[i].flags)) {
        dos_result(emulator, 1u, 1); return XXEMUL_STATUS_OK;
    }
    if (!dos_guest_name(emulator, name, sizeof(name))) { dos_result(emulator, 3u, 1); return XXEMUL_STATUS_OK; }
    error = dos_child_read(session, name, host, &image);
    if (error) goto fail;
    dos_real_read(emulator, emulator->x86.segment[XXEMUL_X86_ES], (uint16_t)emulator->x86.gpr[XXEMUL_X86_RBX], block, sizeof(block));
    command_offset = dos_word(block + 2u); command_segment = dos_word(block + 4u);
    dos_real_read(emulator, command_segment, command_offset, tail, 1u);
    if (tail[0] > 126u) { error = 10u; goto fail; }
    dos_real_read(emulator, command_segment, command_offset, tail, (size_t)tail[0] + 2u);
    if (tail[tail[0] + 1u] != '\r') { error = 10u; goto fail; }
    for (i = 0; i < 2u; ++i) {
        uint16_t offset = dos_word(block + 6u + i * 4u), segment = dos_word(block + 8u + i * 4u);
        if (offset || segment) dos_real_read(emulator, segment, offset, fcb + i * 16u, 16u);
    }
    env_segment = dos_word(block);
    if (!env_segment) env_segment = dos_word(emulator->region_data + ((uint32_t)emulator->psp_segment << 4u) + 0x2cu);
    environment = (uint8_t *)calloc(1u, env_capacity);
    if (!environment) { error = 8u; goto fail; }
    if (env_segment) {
        for (env_size = 0; env_size < 0x8000u; ++env_size) {
            dos_real_read(emulator, env_segment, (uint16_t)env_size, environment + env_size, 1u);
            if (env_size && !environment[env_size] && !environment[env_size - 1u]) { ++env_size; break; }
        }
        if (env_size == 0x8000u && !(environment[env_size - 1u] == 0 && environment[env_size - 2u] == 0)) { error = 10u; goto fail; }
    } else env_size = 2u;
    environment[env_size++] = 1u; environment[env_size++] = 0u;
    {
        const char *relative = host + strlen(session->root);
        while (*relative == '/' || *relative == '\\') ++relative;
        if (strlen(relative) > DOS_MAX_GUEST_PATH - 4u) { error = 10u; goto fail; }
        environment[env_size++] = 'C'; environment[env_size++] = ':'; environment[env_size++] = '\\';
        while (*relative) {
            uint8_t c = (uint8_t)*relative++;
            environment[env_size++] = c == '/' ? '\\' : (uint8_t)toupper(c);
        }
        environment[env_size++] = 0u;
    }
    memset(&parent, 0, sizeof(parent));
    parent.state = emulator->x86; memcpy(parent.segments, emulator->dos_segments, sizeof(parent.segments));
    parent.mode = emulator->mode; parent.psp = emulator->psp_segment;
    parent.dta_segment = emulator->dos_dta_segment; parent.dta_offset = emulator->dos_dta_offset;
    memcpy(parent.vectors, emulator->region_data + 0x22u * 4u, sizeof(parent.vectors));
    parent.state.ip = emulator->dos_call_next_ip;
    if (emulator->x86.segment[XXEMUL_X86_CS] == 0xf000u && emulator->x86.ip == 0x100u) {
        uint8_t frame[6]; uint16_t sp = (uint16_t)emulator->x86.gpr[XXEMUL_X86_RSP];
        dos_real_read(emulator, emulator->x86.segment[XXEMUL_X86_SS], sp, frame, sizeof(frame));
        parent.state.ip = dos_word(frame); parent.state.segment[XXEMUL_X86_CS] = dos_word(frame + 2u);
        parent.state.flags = dos_word(frame + 4u) | 2u;
        parent.state.gpr[XXEMUL_X86_RSP] = (parent.state.gpr[XXEMUL_X86_RSP] & ~UINT64_C(0xffff)) | (uint16_t)(sp + 6u);
        parent.segments[XXEMUL_X86_CS].base = (uint32_t)parent.state.segment[XXEMUL_X86_CS] << 4u;
        parent.segments[XXEMUL_X86_CS].limit = 0xffffu;
        parent.segments[XXEMUL_X86_CS].flags = 0; parent.segments[XXEMUL_X86_CS].access = 0x9bu;
        parent.segments[XXEMUL_X86_CS].valid = 1;
    }
    parent.state.flags &= ~DOS_CF;
    parent.state.gpr[XXEMUL_X86_RAX] = 0;
    for (i = 5u; i < DOS_MAX_HANDLES; ++i) if (session->handles[i].device && !session->handles[i].no_inherit) {
        inherited[i] = session->handles[i]; inherited[i].host_path = NULL;
        if (session->handles[i].host_path) {
            inherited[i].host_path = (char *)malloc(strlen(session->handles[i].host_path) + 1u);
            if (!inherited[i].host_path) { error = 8u; goto fail; }
            strcpy(inherited[i].host_path, session->handles[i].host_path);
        }
    }
    error = dos_process_memory(emulator, 0x48u, (uint16_t)((env_size + 15u) / 16u + DOS_MAX_HANDLES / 16u), &env_block);
    if (error) goto fail;
    dos_process_memory(emulator, 0x48u, 0xffffu, &largest);
    body_paragraphs = (uint32_t)((image.body + 15u) / 16u);
    minimum = image.mz ? 16u + body_paragraphs + image.minalloc : (uint32_t)((image.body + 0x100u + 15u) / 16u);
    maximum = !image.mz || !image.maxalloc ? largest : 16u + body_paragraphs + image.maxalloc;
    if (minimum > largest || minimum > 0xffffu) { error = 8u; goto fail; }
    if (maximum > largest) maximum = largest;
    if (maximum < minimum) maximum = minimum;
    allocation = (uint16_t)maximum;
    error = dos_process_memory(emulator, 0x48u, allocation, &child);
    if (error) goto fail;
    load = image.mz && !image.maxalloc ? (uint16_t)(child + allocation - body_paragraphs) : (uint16_t)(child + 16u);
    state = emulator->x86;
    memset(state.gpr, 0, sizeof(state.gpr));
    for (i = 0; i < 6u; ++i) state.segment[i] = child;
    state.ip = image.mz ? image.ip : 0x100u;
    state.segment[XXEMUL_X86_CS] = image.mz ? (uint16_t)(load + image.cs) : child;
    state.segment[XXEMUL_X86_SS] = image.mz ? (uint16_t)(load + image.ss) : child;
    state.gpr[XXEMUL_X86_RSP] = image.mz ? image.sp : (uint16_t)((allocation >= 0x1000u ? 0x10000u : (uint32_t)allocation * 16u) - 2u);
    state.gpr[XXEMUL_X86_RAX] = (fcb[0] <= 26u ? 0u : 0xffu) | (fcb[16] <= 26u ? 0u : 0xff00u);
    state.flags = 0x202u;
    {
        uint32_t begin = (uint32_t)child * 16u, end = begin + (uint32_t)allocation * 16u;
        uint32_t pc = (uint32_t)state.segment[XXEMUL_X86_CS] * 16u + (uint16_t)state.ip;
        uint32_t stack_base = (uint32_t)state.segment[XXEMUL_X86_SS] * 16u;
        uint32_t stack = (uint32_t)state.segment[XXEMUL_X86_SS] * 16u + (uint16_t)(state.gpr[XXEMUL_X86_RSP] - 2u);
        if (end > 0xa0000u || (uint32_t)load * 16u + image.body > end || pc < begin + 0x100u || pc >= end ||
            stack_base >= 0xa0000u || stack_base + (uint16_t)state.gpr[XXEMUL_X86_RSP] > 0xa0000u ||
            stack < begin + 0x100u || stack > end - 2u) { error = 11u; goto fail; }
    }
    /* All fallible work is complete. Commit only to child-owned memory. */
    {
        uint8_t *psp = emulator->region_data + ((uint32_t)child << 4u);
        uint8_t *body = emulator->region_data + ((uint32_t)load << 4u);
        memset(psp, 0, 256u); psp[0] = 0xcd; psp[1] = 0x20;
        xxemul_dos_write_word(psp + 2u, (uint16_t)(child + allocation));
        xxemul_dos_write_word(psp + 0x16u, parent.psp);
        xxemul_dos_write_word(psp + 0x2cu, env_block);
        xxemul_dos_write_word(psp + 0x34u, 0u);
        xxemul_dos_write_word(psp + 0x36u, (uint16_t)(env_block + (env_size + 15u) / 16u));
        memcpy(psp + 0x0au, parent.vectors, 12u);
        xxemul_dos_write_word(psp + 0x0au, (uint16_t)parent.state.ip);
        xxemul_dos_write_word(psp + 0x0cu, parent.state.segment[XXEMUL_X86_CS]);
        memcpy(emulator->region_data + 0x22u * 4u, psp + 0x0au, 4u);
        psp[0x50] = 0xcd; psp[0x51] = 0x21; psp[0x52] = 0xcb;
        memcpy(psp + 0x80u, tail, sizeof(tail)); memcpy(psp + 0x5cu, fcb, sizeof(fcb));
        memcpy(emulator->region_data + ((uint32_t)env_block << 4u), environment, env_size);
        memcpy(body, image.bytes + image.header, image.body);
        if (image.mz) for (i = 0; i < image.relocations; ++i) {
            const uint8_t *entry = image.bytes + image.table + i * 4u;
            uint8_t *at = body + (size_t)dos_word(entry + 2u) * 16u + dos_word(entry);
            xxemul_dos_write_word(at, (uint16_t)(dos_word(at) + load));
        }
        else xxemul_dos_write_word(psp + (uint16_t)state.gpr[XXEMUL_X86_RSP], 0u);
        xxemul_dos_write_word(emulator->region_data + (((uint32_t)child - 1u) << 4u) + 1u, child);
        xxemul_dos_write_word(emulator->region_data + (((uint32_t)env_block - 1u) << 4u) + 1u, child);
    }
    memcpy(parent.handles, session->handles, sizeof(parent.handles)); parent.searches = session->searches;
    parent.input_buffer = session->input_buffer; parent.input_count = session->input_count; parent.input_pending = session->input_pending;
    parent.flush_pending = session->flush_pending; parent.flush_function = session->flush_function;
    parent.flush_cs = session->flush_cs; parent.flush_ip = session->flush_ip; parent.flush_ds = session->flush_ds; parent.flush_dx = session->flush_dx;
    session->parents[session->depth++] = parent;
    memcpy(session->handles, inherited, sizeof(session->handles)); session->searches = NULL;
    session->input_pending = 0; session->flush_pending = 0; session->child_status = 0;
    emulator->psp_segment = child; emulator->dos_dta_segment = child; emulator->dos_dta_offset = 0x80u;
    emulator->x86 = state; emulator->mode = XXEMUL_MODE_X86_16; emulator->halted = 0;
    dos_process_segments(emulator); dos_process_handles(emulator, session);
    emulator->dos_context_transfer = 1u;
    free(image.bytes); free(environment);
    return XXEMUL_STATUS_OK;
fail:
    if (child) dos_process_memory(emulator, 0x49u, child, NULL);
    if (env_block) dos_process_memory(emulator, 0x49u, env_block, NULL);
    for (i = 5u; i < DOS_MAX_HANDLES; ++i) free(inherited[i].host_path);
    free(image.bytes); free(environment); dos_result(emulator, error ? error : 11u, 1);
    return XXEMUL_STATUS_OK;
}

int xxemul_dos_files_return_to_parent(xxemul *emulator, uint8_t code, xxemul_status *status)
{
    dos_session *session;
    dos_parent *parent;
    uint8_t vectors[12];
    uint16_t segment = xxemul_dos_files_mcb_head(emulator);
    unsigned i;
    dos_lock(); session = dos_find(emulator); dos_unlock();
    if (!session || !session->depth) return 0;
    if ((emulator->dos_cr0 & 1u) || emulator->mode != XXEMUL_MODE_X86_16) { *status = XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION; return 1; }
    parent = &session->parents[session->depth - 1u];
    dos_real_read(emulator, emulator->psp_segment, 0x0au, vectors, sizeof(vectors));
    /* A custom termination trampoline needs its own calling convention and
     * is outside the bounded normal EXEC/return path. Reject before cleanup. */
    if (dos_word(vectors) != (uint16_t)parent->state.ip || dos_word(vectors + 2u) != parent->state.segment[XXEMUL_X86_CS]) {
        *status = XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION; return 1;
    }
    /* Validate the complete chain before freeing any child-owned block. */
    for (;;) {
        uint8_t *mcb = emulator->region_data + ((uint32_t)segment << 4u);
        uint32_t next = (uint32_t)segment + 1u + dos_word(mcb + 3u);
        if ((mcb[0] != 'M' && mcb[0] != 'Z') || next > 0xa000u || next <= segment) { *status = XXEMUL_STATUS_ADDRESS_FAULT; return 1; }
        if (mcb[0] == 'Z') break;
        segment = (uint16_t)next;
    }
    segment = xxemul_dos_files_mcb_head(emulator);
    for (;;) {
        uint8_t *mcb = emulator->region_data + ((uint32_t)segment << 4u);
        uint16_t next = (uint16_t)(segment + 1u + dos_word(mcb + 3u));
        if (dos_word(mcb + 1u) == emulator->psp_segment) xxemul_dos_write_word(mcb + 1u, 0u);
        if (mcb[0] == 'Z') break;
        segment = next;
    }
    for (i = 5u; i < DOS_MAX_HANDLES; ++i) dos_drop_handle(session, i);
    while (session->searches) {
        dos_search *search = session->searches; session->searches = search->next;
        free(search->records); free(search);
    }
    parent = &session->parents[--session->depth];
    memcpy(session->handles, parent->handles, sizeof(session->handles)); session->searches = parent->searches;
    session->input_buffer = parent->input_buffer; session->input_count = parent->input_count; session->input_pending = parent->input_pending;
    session->flush_pending = parent->flush_pending; session->flush_function = parent->flush_function;
    session->flush_cs = parent->flush_cs; session->flush_ip = parent->flush_ip; session->flush_ds = parent->flush_ds; session->flush_dx = parent->flush_dx;
    session->child_status = code;
    emulator->x86 = parent->state; emulator->mode = parent->mode;
    memcpy(emulator->dos_segments, parent->segments, sizeof(parent->segments));
    emulator->psp_segment = parent->psp; emulator->dos_dta_segment = parent->dta_segment; emulator->dos_dta_offset = parent->dta_offset;
    memcpy(emulator->region_data + 0x22u * 4u, vectors, sizeof(vectors));
    emulator->halted = 0; emulator->dos_context_transfer = 1u;
    dos_process_handles(emulator, session);
    *status = XXEMUL_STATUS_OK;
    return 1;
}

uint16_t xxemul_dos_files_child_status(xxemul *emulator)
{
    dos_session *session; uint16_t result = 0;
    dos_lock(); session = dos_find(emulator);
    if (session) { result = session->child_status; session->child_status = 0; }
    dos_unlock(); return result;
}

int xxemul_dos_files_child_active(xxemul *emulator)
{
    dos_session *session; int active;
    dos_lock(); session = dos_find(emulator); active = session && session->depth;
    dos_unlock(); return active;
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
            } else if (session != NULL && handle >= 5u && handle < DOS_MAX_HANDLES && session->handles[handle].device != NULL) {
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

            if (session == NULL || handle < 5u || handle >= DOS_MAX_HANDLES || session->handles[handle].device == NULL) {
                error = 6u;
            } else if (subfunction == 0u && dos_metadata(session, session->handles[handle].host_path, &metadata)) {
                emulator->x86.gpr[XXEMUL_X86_RCX] = metadata.time;
                emulator->x86.gpr[XXEMUL_X86_RDX] = metadata.date;
                emulator->x86.flags &= ~DOS_CF;
                error = 0u;
            } else if (subfunction == 1u &&
                       dos_set_host_time(session->handles[handle].host_path, (uint16_t)emulator->x86.gpr[XXEMUL_X86_RDX], (uint16_t)emulator->x86.gpr[XXEMUL_X86_RCX])) {
                dos_sft_update(emulator, session, handle);
                emulator->x86.flags &= ~DOS_CF;
                error = 0u;
            } else {
                error = subfunction > 1u ? 1u : 5u;
            }
            break;
        }
        case 0x3cu:
        case 0x3du: error = dos_open_file(emulator, session, function == 0x3cu); break;
        case 0x6cu: error = dos_open_extended(emulator, session); break;
        case 0x5au: error = dos_create_temporary(emulator, session); break;
        case 0x5bu: error = dos_create_new(emulator, session); break;
        case 0x3eu: {
            uint16_t handle = (uint16_t)emulator->x86.gpr[XXEMUL_X86_RBX];
            if (handle <= 4u) {
                dos_result(emulator, 0u, 0);
                error = 0u;
            } else if (session != NULL && handle < DOS_MAX_HANDLES && session->handles[handle].device != NULL) {
                int closed = dos_drop_handle(session, handle);
                emulator->region_data[dos_jft_address(emulator, handle)] = 0xffu;
                if (handle < 20u) {
                    emulator->region_data[xxemul_dos_linear(emulator->psp_segment, (uint16_t)(0x18u + handle))] = 0xffu;
                }
                dos_sft_update(emulator, session, handle);
                error = closed == 0 ? 0u : 5u;
                if (error == 0u) {
                    dos_result(emulator, 0u, 0);
                }
            } else {
                error = 6u;
            }
            break;
        }
        case 0x41u: error = dos_delete_file(emulator, session); break;
        case 0x3fu:
        case 0x40u: error = dos_transfer(emulator, session, function == 0x40u); break;
        case 0x42u: error = dos_seek(emulator, session); break;
        case 0x43u: error = dos_file_attributes(emulator, session); break;
        case 0x4eu: error = dos_find_first(emulator, session); break;
        case 0x4fu: error = dos_find_next(emulator, session); break;
        case 0x56u: error = dos_rename_file(emulator, session); break;
        default: dos_unlock(); return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    }
    if (error != 0u) {
        dos_result(emulator, error, 1);
    }
    dos_unlock();
    return XXEMUL_STATUS_OK;
}
