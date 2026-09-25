#if !defined(_WIN32) && !defined(_POSIX_C_SOURCE)
#define _POSIX_C_SOURCE 200809L
#endif

#include "xxemul_internal.h"
#include "xxemul_dos_files.h"

#include <time.h>

#define XXEMUL_DOS_CF UINT64_C(1)
#define XXEMUL_DOS_MCB_START 0x0813u
#define XXEMUL_DOS_MCB_END 0xa000u
#define XXEMUL_DOS_TRUENAME_SIZE 128u

static void xxemul_dos_set_ax(xxemul *emulator, uint16_t value);

static int xxemul_dos_local_time(struct tm *result)
{
    time_t now = time(NULL);

    if (now == (time_t)-1) return 0;
#if defined(_WIN32)
    return localtime_s(result, &now) == 0;
#else
    return localtime_r(&now, result) != NULL;
#endif
}

static uint16_t xxemul_dos_read_word(const uint8_t *data)
{
    return (uint16_t)(data[0] | ((uint16_t)data[1] << 8));
}

static void xxemul_dos_write_word(uint8_t *data, uint16_t value)
{
    data[0] = (uint8_t)value;
    data[1] = (uint8_t)(value >> 8);
}

static uint8_t *xxemul_dos_mcb(xxemul *emulator, uint16_t segment)
{
    if (segment < XXEMUL_DOS_MCB_START || segment >= XXEMUL_DOS_MCB_END) {
        return NULL;
    }
    return emulator->region_data + ((uint32_t)segment << 4);
}

static int xxemul_dos_mcb_next(
    xxemul *emulator, uint16_t segment, uint16_t *next)
{
    uint8_t *mcb = xxemul_dos_mcb(emulator, segment);
    uint32_t after;

    if (mcb == NULL || (mcb[0] != 'M' && mcb[0] != 'Z')) {
        return 0;
    }
    after = (uint32_t)segment + 1u + xxemul_dos_read_word(mcb + 3u);
    if (after > XXEMUL_DOS_MCB_END
        || (mcb[0] == 'M' && after >= XXEMUL_DOS_MCB_END)) {
        return 0;
    }
    *next = (uint16_t)after;
    return 1;
}

static void xxemul_dos_result(xxemul *emulator, uint16_t value, int error)
{
    xxemul_dos_set_ax(emulator, value);
    if (error) {
        emulator->x86.flags |= XXEMUL_DOS_CF;
    } else {
        emulator->x86.flags &= ~XXEMUL_DOS_CF;
    }
}

static xxemul_status xxemul_dos_memory_allocate(xxemul *emulator)
{
    uint16_t requested = (uint16_t)emulator->x86.gpr[XXEMUL_X86_RBX];
    uint16_t segment = XXEMUL_DOS_MCB_START;
    uint16_t largest = 0u;
    uint16_t chosen_segment = 0u;
    uint16_t chosen_size = 0u;
    uint16_t strategy = xxemul_dos_files_allocation_strategy(emulator);
    uint16_t next;

    if ((strategy & 0x40u) != 0u) {
        emulator->x86.gpr[XXEMUL_X86_RBX] = 0u;
        xxemul_dos_result(emulator, 8u, 1);
        return XXEMUL_STATUS_OK;
    }
    strategy &= 3u;

    while (xxemul_dos_mcb_next(emulator, segment, &next)) {
        uint8_t *mcb = xxemul_dos_mcb(emulator, segment);
        uint16_t size = xxemul_dos_read_word(mcb + 3u);

        if (xxemul_dos_read_word(mcb + 1u) == 0u) {
            while (mcb[0] == 'M') {
                uint8_t *following = xxemul_dos_mcb(emulator, next);
                uint16_t following_next;

                if (following == NULL
                    || !xxemul_dos_mcb_next(emulator, next, &following_next)
                    || xxemul_dos_read_word(following + 1u) != 0u) {
                    break;
                }
                size = (uint16_t)(size + 1u
                    + xxemul_dos_read_word(following + 3u));
                mcb[0] = following[0];
                xxemul_dos_write_word(mcb + 3u, size);
                next = following_next;
            }
            if (size > largest) {
                largest = size;
            }
            if (requested != 0u && size >= requested) {
                if (strategy == 0u) {
                    chosen_segment = segment;
                    chosen_size = size;
                    break;
                }
                if (chosen_segment == 0u || strategy == 2u
                    || size < chosen_size) {
                    chosen_segment = segment;
                    chosen_size = size;
                }
            }
        }
        if (mcb[0] == 'Z') {
            break;
        }
        segment = next;
    }
    if (chosen_segment != 0u) {
        uint8_t *mcb = xxemul_dos_mcb(emulator, chosen_segment);

        if (strategy == 2u && chosen_size > requested) {
            uint16_t high_segment = (uint16_t)(chosen_segment
                + chosen_size - requested);
            uint8_t *high_mcb = xxemul_dos_mcb(emulator, high_segment);

            high_mcb[0] = mcb[0];
            xxemul_dos_write_word(high_mcb + 1u, emulator->psp_segment);
            xxemul_dos_write_word(high_mcb + 3u, requested);
            mcb[0] = 'M';
            xxemul_dos_write_word(mcb + 3u,
                (uint16_t)(chosen_size - requested - 1u));
            chosen_segment = high_segment;
        } else {
            if (chosen_size > requested + 1u) {
                uint16_t split = (uint16_t)(chosen_segment + requested + 1u);
                uint8_t *free_mcb = xxemul_dos_mcb(emulator, split);

                free_mcb[0] = mcb[0];
                xxemul_dos_write_word(free_mcb + 1u, 0u);
                xxemul_dos_write_word(free_mcb + 3u,
                    (uint16_t)(chosen_size - requested - 1u));
                mcb[0] = 'M';
                xxemul_dos_write_word(mcb + 3u, requested);
            }
            xxemul_dos_write_word(mcb + 1u, emulator->psp_segment);
        }
        xxemul_dos_result(emulator, (uint16_t)(chosen_segment + 1u), 0);
        return XXEMUL_STATUS_OK;
    }
    emulator->x86.gpr[XXEMUL_X86_RBX] = largest;
    xxemul_dos_result(emulator, 8u, 1);
    return XXEMUL_STATUS_OK;
}

static uint8_t *xxemul_dos_owned_mcb(xxemul *emulator, uint16_t block)
{
    uint16_t segment = XXEMUL_DOS_MCB_START;
    uint16_t next;

    if (block <= XXEMUL_DOS_MCB_START) {
        return NULL;
    }
    while (xxemul_dos_mcb_next(emulator, segment, &next)) {
        uint8_t *mcb = xxemul_dos_mcb(emulator, segment);
        if ((uint16_t)(segment + 1u) == block) {
            return xxemul_dos_read_word(mcb + 1u)
                    == emulator->psp_segment ? mcb : NULL;
        }
        if (mcb[0] == 'Z') {
            break;
        }
        segment = next;
    }
    return NULL;
}

static xxemul_status xxemul_dos_memory_free(xxemul *emulator)
{
    uint8_t *mcb = xxemul_dos_owned_mcb(
        emulator, emulator->x86.segment[XXEMUL_X86_ES]);

    if (mcb == NULL || emulator->x86.segment[XXEMUL_X86_ES]
            == emulator->psp_segment) {
        xxemul_dos_result(emulator, 9u, 1);
        return XXEMUL_STATUS_OK;
    }
    xxemul_dos_write_word(mcb + 1u, 0u);
    xxemul_dos_result(emulator, 0u, 0);
    return XXEMUL_STATUS_OK;
}

static xxemul_status xxemul_dos_memory_resize(xxemul *emulator)
{
    uint16_t block = emulator->x86.segment[XXEMUL_X86_ES];
    uint16_t requested = (uint16_t)emulator->x86.gpr[XXEMUL_X86_RBX];
    uint8_t *mcb = xxemul_dos_owned_mcb(emulator, block);
    uint16_t size;
    uint16_t possible;
    uint8_t final_type;
    uint16_t segment;
    uint16_t next;

    if (mcb == NULL) {
        xxemul_dos_result(emulator, 9u, 1);
        return XXEMUL_STATUS_OK;
    }
    segment = (uint16_t)(block - 1u);
    size = xxemul_dos_read_word(mcb + 3u);
    possible = size;
    final_type = mcb[0];
    next = (uint16_t)(segment + size + 1u);
    while (requested > possible && final_type == 'M') {
        uint8_t *following = xxemul_dos_mcb(emulator, next);
        uint16_t following_next;

        if (following == NULL
            || !xxemul_dos_mcb_next(emulator, next, &following_next)
            || xxemul_dos_read_word(following + 1u) != 0u) {
            break;
        }
        possible = (uint16_t)(possible + 1u
            + xxemul_dos_read_word(following + 3u));
        final_type = following[0];
        next = following_next;
    }
    if (requested > possible) {
        emulator->x86.gpr[XXEMUL_X86_RBX] = possible;
        xxemul_dos_result(emulator, 8u, 1);
        return XXEMUL_STATUS_OK;
    }
    size = possible;
    mcb[0] = final_type;
    xxemul_dos_write_word(mcb + 3u, size);
    if (size > requested + 1u) {
        uint16_t split = (uint16_t)(segment + requested + 1u);
        uint8_t *free_mcb = xxemul_dos_mcb(emulator, split);

        free_mcb[0] = mcb[0];
        xxemul_dos_write_word(free_mcb + 1u, 0u);
        xxemul_dos_write_word(free_mcb + 3u,
            (uint16_t)(size - requested - 1u));
        mcb[0] = 'M';
        xxemul_dos_write_word(mcb + 3u, requested);
    }
    if (block == emulator->psp_segment) {
        uint16_t end = (uint16_t)(block + xxemul_dos_read_word(mcb + 3u));
        uint8_t *psp = emulator->region_data + ((uint32_t)block << 4);
        xxemul_dos_write_word(psp + 2u, end);
    }
    xxemul_dos_result(emulator, 0u, 0);
    return XXEMUL_STATUS_OK;
}

static uint8_t xxemul_dos_ah(const xxemul *emulator)
{
    return (uint8_t)(emulator->x86.gpr[XXEMUL_X86_RAX] >> 8);
}

static void xxemul_dos_set_ax(xxemul *emulator, uint16_t value)
{
    emulator->x86.gpr[XXEMUL_X86_RAX] = value;
}

static xxemul_status xxemul_dos_output_string(xxemul *emulator)
{
    uint16_t offset = (uint16_t)emulator->x86.gpr[XXEMUL_X86_RDX];
    uint16_t segment = emulator->x86.segment[XXEMUL_X86_DS];
    uint32_t count;

    for (count = 0u; count < 0x10000u; ++count, ++offset) {
        uint8_t character = emulator->region_data[
            xxemul_dos_linear(segment, offset)];
        if (character == '$') {
            emulator->x86.gpr[XXEMUL_X86_RAX] =
                (emulator->x86.gpr[XXEMUL_X86_RAX] & 0xff00u) | '$';
            return XXEMUL_STATUS_OK;
        }
        xxemul_video_putc(emulator, character);
    }
    return XXEMUL_STATUS_ADDRESS_FAULT;
}

static xxemul_status xxemul_dos_write_handle(xxemul *emulator)
{
    uint16_t handle = (uint16_t)emulator->x86.gpr[XXEMUL_X86_RBX];
    uint16_t count = (uint16_t)emulator->x86.gpr[XXEMUL_X86_RCX];
    uint16_t offset = (uint16_t)emulator->x86.gpr[XXEMUL_X86_RDX];
    uint16_t segment = emulator->x86.segment[XXEMUL_X86_DS];
    uint32_t index;

    if (handle != 1u && handle != 2u) {
        xxemul_dos_set_ax(emulator, 6u);
        emulator->x86.flags |= XXEMUL_DOS_CF;
        return XXEMUL_STATUS_OK;
    }
    for (index = 0u; index < count; ++index) {
        xxemul_video_putc(emulator, emulator->region_data[
            xxemul_dos_linear(segment, (uint16_t)(offset + index))]);
    }
    xxemul_dos_set_ax(emulator, count);
    emulator->x86.flags &= ~XXEMUL_DOS_CF;
    return XXEMUL_STATUS_OK;
}

static xxemul_status xxemul_dos_read_key(xxemul *emulator, int echo)
{
    uint16_t key;

    if (emulator->key_count == 0u) {
        return XXEMUL_STATUS_INPUT_REQUIRED;
    }
    key = emulator->key_queue[emulator->key_head];
    emulator->key_head = (uint8_t)((emulator->key_head + 1u) % 32u);
    --emulator->key_count;
    emulator->x86.gpr[XXEMUL_X86_RAX] =
        (emulator->x86.gpr[XXEMUL_X86_RAX] & 0xff00u) | (key & 0xffu);
    if (echo) {
        xxemul_video_putc(emulator, (uint8_t)key);
    }
    return XXEMUL_STATUS_OK;
}

static int xxemul_dos_path_separator(uint8_t character)
{
    return character == '/' || character == '\\';
}

static uint16_t xxemul_dos_canonicalize_path(
    const uint8_t source[128], uint8_t result[128], size_t *result_size)
{
    size_t cursor = 0u;
    size_t used = 3u;

    if (source[0] == 0u) return 2u;
    if (xxemul_dos_path_separator(source[0])
        && xxemul_dos_path_separator(source[1])) return 3u;
    if (source[1] == ':') {
        uint8_t drive = source[0];

        if (drive >= 'a' && drive <= 'z') drive -= 'a' - 'A';
        if (drive != 'C') return 3u;
        cursor = 2u;
        if (source[cursor] == 0u) return 2u;
    }
    result[0] = 'C';
    result[1] = ':';
    result[2] = '\\';
    while (source[cursor] != 0u) {
        size_t begin;
        size_t length;
        size_t index;

        while (xxemul_dos_path_separator(source[cursor])) ++cursor;
        if (source[cursor] == 0u) break;
        begin = cursor;
        while (source[cursor] != 0u
            && !xxemul_dos_path_separator(source[cursor])) ++cursor;
        length = cursor - begin;
        if (length == 1u && source[begin] == '.') continue;
        if (length == 2u && source[begin] == '.'
            && source[begin + 1u] == '.') {
            if (used == 3u) return 3u;
            while (used > 3u && result[used - 1u] != '\\') --used;
            if (used > 3u) --used;
            continue;
        }
        if (used > 3u) {
            if (used + 1u >= XXEMUL_DOS_TRUENAME_SIZE) return 3u;
            result[used++] = '\\';
        }
        if (length >= XXEMUL_DOS_TRUENAME_SIZE - used) return 3u;
        for (index = 0u; index < length; ++index) {
            uint8_t character = source[begin + index];

            if (character < 32u || character == 127u
                || character == ':' || character == '*' || character == '?'
                || character == '"' || character == '<'
                || character == '>' || character == '|') return 3u;
            if (character >= 'a' && character <= 'z')
                character -= 'a' - 'A';
            result[used++] = character;
        }
    }
    result[used] = 0u;
    *result_size = used + 1u;
    return 0u;
}

static xxemul_status xxemul_dos_truename(xxemul *emulator)
{
    uint16_t input_segment = emulator->x86.segment[XXEMUL_X86_DS];
    uint16_t input_offset = (uint16_t)emulator->x86.gpr[XXEMUL_X86_RSI];
    uint16_t output_segment = emulator->x86.segment[XXEMUL_X86_ES];
    uint16_t output_offset = (uint16_t)emulator->x86.gpr[XXEMUL_X86_RDI];
    uint8_t source[128];
    uint8_t result[128];
    uint8_t probe;
    size_t source_size;
    size_t result_size;
    size_t index;
    uint16_t error;

    for (source_size = 0u; source_size < sizeof(source); ++source_size) {
        uint32_t address = xxemul_dos_linear(input_segment,
            (uint16_t)(input_offset + source_size));

        if (xxemul_read_memory(emulator, address,
                &source[source_size], 1u) != XXEMUL_STATUS_OK) {
            xxemul_dos_result(emulator, 3u, 1);
            return XXEMUL_STATUS_OK;
        }
        if (source[source_size] == 0u) break;
    }
    if (source_size == sizeof(source)) {
        xxemul_dos_result(emulator, 3u, 1);
        return XXEMUL_STATUS_OK;
    }
    error = xxemul_dos_canonicalize_path(source, result, &result_size);
    if (error != 0u) {
        xxemul_dos_result(emulator, error, 1);
        return XXEMUL_STATUS_OK;
    }
    for (index = 0u; index < result_size; ++index) {
        uint32_t address = xxemul_dos_linear(output_segment,
            (uint16_t)(output_offset + index));

        if (xxemul_read_memory(emulator, address, &probe, 1u)
            != XXEMUL_STATUS_OK) {
            xxemul_dos_result(emulator, 3u, 1);
            return XXEMUL_STATUS_OK;
        }
    }
    for (index = 0u; index < result_size; ++index) {
        uint32_t address = xxemul_dos_linear(output_segment,
            (uint16_t)(output_offset + index));

        if (xxemul_write_memory(emulator, address, result + index, 1u)
            != XXEMUL_STATUS_OK) {
            xxemul_dos_result(emulator, 3u, 1);
            return XXEMUL_STATUS_OK;
        }
    }
    xxemul_dos_result(emulator, 0u, 0);
    return XXEMUL_STATUS_OK;
}

xxemul_status xxemul_msdos_interrupt(xxemul *emulator, uint8_t vector)
{
    uint8_t function;
    uint8_t character;
    xxemul_status status;

    if (vector == 0x20u) {
        emulator->exit_code = 0u;
        emulator->halted = 1;
        return XXEMUL_STATUS_HALTED;
    }
    if (vector == 0x29u) {
        xxemul_video_putc(emulator,
            (uint8_t)emulator->x86.gpr[XXEMUL_X86_RAX]);
        return XXEMUL_STATUS_OK;
    }
    if (vector != 0x21u) {
        return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    }
    function = xxemul_dos_ah(emulator);
    switch (function) {
    case 0x00u:
        emulator->exit_code = 0u;
        emulator->halted = 1;
        return XXEMUL_STATUS_HALTED;
    case 0x4cu:
        emulator->exit_code = (uint8_t)emulator->x86.gpr[XXEMUL_X86_RAX];
        emulator->halted = 1;
        return XXEMUL_STATUS_HALTED;
    case 0x02u:
        character = (uint8_t)emulator->x86.gpr[XXEMUL_X86_RDX];
        xxemul_video_putc(emulator, character);
        emulator->x86.gpr[XXEMUL_X86_RAX] =
            (emulator->x86.gpr[XXEMUL_X86_RAX] & 0xff00u) | character;
        break;
    case 0x06u:
        character = (uint8_t)emulator->x86.gpr[XXEMUL_X86_RDX];
        if (character == 0xffu) {
            if (emulator->key_count == 0u) {
                emulator->x86.flags |= UINT64_C(0x40);
                emulator->x86.gpr[XXEMUL_X86_RAX] &= 0xff00u;
                return XXEMUL_STATUS_OK;
            }
            status = xxemul_dos_read_key(emulator, 0);
            emulator->x86.flags &= ~UINT64_C(0x40);
            return status;
        }
        xxemul_video_putc(emulator, character);
        emulator->x86.gpr[XXEMUL_X86_RAX] =
            (emulator->x86.gpr[XXEMUL_X86_RAX] & 0xff00u) | character;
        break;
    case 0x09u:
        status = xxemul_dos_output_string(emulator);
        if (status != XXEMUL_STATUS_OK) {
            return status;
        }
        break;
    case 0x01u:
    case 0x07u:
    case 0x08u:
        status = xxemul_dos_read_key(emulator, function == 0x01u);
        if (status != XXEMUL_STATUS_OK) {
            return status;
        }
        break;
    case 0x0bu:
        emulator->x86.gpr[XXEMUL_X86_RAX] =
            (emulator->x86.gpr[XXEMUL_X86_RAX] & 0xff00u)
            | (emulator->key_count == 0u ? 0x00u : 0xffu);
        break;
    case 0x30u:
        xxemul_dos_set_ax(emulator, 0x0005u);
        break;
    case 0x2au:
    case 0x2cu: {
        struct tm local;
        if (!xxemul_dos_local_time(&local)) {
            xxemul_dos_result(emulator, 1u, 1);
            return XXEMUL_STATUS_OK;
        }
        if (function == 0x2au) {
            emulator->x86.gpr[XXEMUL_X86_RAX] = (uint8_t)local.tm_wday;
            emulator->x86.gpr[XXEMUL_X86_RCX] =
                (uint16_t)(local.tm_year + 1900);
            emulator->x86.gpr[XXEMUL_X86_RDX] =
                ((uint16_t)(local.tm_mon + 1) << 8u)
                    | (uint8_t)local.tm_mday;
        } else {
            emulator->x86.gpr[XXEMUL_X86_RCX] =
                ((uint16_t)local.tm_hour << 8u)
                    | (uint8_t)local.tm_min;
            emulator->x86.gpr[XXEMUL_X86_RDX] =
                (uint16_t)local.tm_sec << 8u;
        }
        break;
    }
    case 0x19u:
        emulator->x86.gpr[XXEMUL_X86_RAX] =
            (emulator->x86.gpr[XXEMUL_X86_RAX] & ~UINT64_C(0xff)) | 2u;
        break;
    case 0x1au:
        emulator->dos_dta_segment = emulator->x86.segment[XXEMUL_X86_DS];
        emulator->dos_dta_offset =
            (uint16_t)emulator->x86.gpr[XXEMUL_X86_RDX];
        break;
    case 0x0eu:
        emulator->x86.gpr[XXEMUL_X86_RAX] =
            (emulator->x86.gpr[XXEMUL_X86_RAX] & ~UINT64_C(0xff)) | 26u;
        break;
    case 0x25u: {
        uint8_t interrupt = (uint8_t)emulator->x86.gpr[XXEMUL_X86_RAX];
        uint8_t *entry = emulator->region_data + (size_t)interrupt * 4u;
        xxemul_dos_write_word(entry,
            (uint16_t)emulator->x86.gpr[XXEMUL_X86_RDX]);
        xxemul_dos_write_word(entry + 2u,
            emulator->x86.segment[XXEMUL_X86_DS]);
        break;
    }
    case 0x2fu:
        emulator->x86.segment[XXEMUL_X86_ES] = emulator->dos_dta_segment;
        emulator->x86.gpr[XXEMUL_X86_RBX] = emulator->dos_dta_offset;
        break;
    case 0x35u: {
        uint8_t interrupt = (uint8_t)emulator->x86.gpr[XXEMUL_X86_RAX];
        const uint8_t *entry = emulator->region_data
            + (size_t)interrupt * 4u;
        emulator->x86.gpr[XXEMUL_X86_RBX] = xxemul_dos_read_word(entry);
        emulator->x86.segment[XXEMUL_X86_ES] =
            xxemul_dos_read_word(entry + 2u);
        break;
    }
    case 0x33u:
        if ((uint8_t)emulator->x86.gpr[XXEMUL_X86_RAX] <= 1u) {
            emulator->x86.gpr[XXEMUL_X86_RDX] = 0u;
        } else {
            xxemul_dos_result(emulator, 1u, 1);
            return XXEMUL_STATUS_OK;
        }
        break;
    case 0x36u: {
        uint8_t drive = (uint8_t)emulator->x86.gpr[XXEMUL_X86_RDX];
        uint16_t available;
        uint16_t total;

        if ((drive != 0u && drive != 3u)
            || !xxemul_dos_files_drive_space(emulator, &available, &total)) {
            xxemul_dos_result(emulator, UINT16_MAX, 0);
            return XXEMUL_STATUS_OK;
        }
        emulator->x86.gpr[XXEMUL_X86_RBX] = available;
        emulator->x86.gpr[XXEMUL_X86_RCX] = 512u;
        emulator->x86.gpr[XXEMUL_X86_RDX] = total;
        xxemul_dos_result(emulator, 8u, 0);
        return XXEMUL_STATUS_OK;
    }
    case 0x44u:
        return xxemul_dos_files_interrupt(emulator, function);
    case 0x47u: {
        uint8_t drive = (uint8_t)emulator->x86.gpr[XXEMUL_X86_RDX];
        uint32_t buffer = xxemul_dos_linear(
            emulator->x86.segment[XXEMUL_X86_DS],
            (uint16_t)emulator->x86.gpr[XXEMUL_X86_RSI]);
        uint8_t empty = 0u;
        if (drive != 0u && drive != 3u) {
            xxemul_dos_result(emulator, 15u, 1);
            return XXEMUL_STATUS_OK;
        }
        if (xxemul_write_memory(emulator, buffer, &empty, 1u)
            != XXEMUL_STATUS_OK) return XXEMUL_STATUS_ADDRESS_FAULT;
        break;
    }
    case 0x48u:
        return xxemul_dos_memory_allocate(emulator);
    case 0x58u:
        if ((uint8_t)emulator->x86.gpr[XXEMUL_X86_RAX] == 0u) {
            xxemul_dos_result(emulator,
                xxemul_dos_files_allocation_strategy(emulator), 0);
        } else if ((uint8_t)emulator->x86.gpr[XXEMUL_X86_RAX] == 1u
            && xxemul_dos_files_set_allocation_strategy(emulator,
                (uint16_t)emulator->x86.gpr[XXEMUL_X86_RBX])) {
            xxemul_dos_result(emulator, 0u, 0);
        } else if ((uint8_t)emulator->x86.gpr[XXEMUL_X86_RAX] == 2u) {
            xxemul_dos_result(emulator, 0x5800u, 0);
        } else {
            xxemul_dos_result(emulator, 1u, 1);
        }
        return XXEMUL_STATUS_OK;
    case 0x60u:
        return xxemul_dos_truename(emulator);
    case 0x49u:
        return xxemul_dos_memory_free(emulator);
    case 0x4au:
        return xxemul_dos_memory_resize(emulator);
    case 0x3cu:
    case 0x3du:
    case 0x3eu:
    case 0x3fu:
    case 0x41u:
    case 0x42u:
    case 0x43u:
    case 0x4eu:
    case 0x57u:
    case 0x6cu:
        return xxemul_dos_files_interrupt(emulator, function);
    case 0x40u:
        return (uint16_t)emulator->x86.gpr[XXEMUL_X86_RBX] <= 2u
            ? xxemul_dos_write_handle(emulator)
            : xxemul_dos_files_interrupt(emulator, function);
    case 0x50u:
        emulator->psp_segment = (uint16_t)emulator->x86.gpr[XXEMUL_X86_RBX];
        break;
    case 0x52u: {
        uint16_t segment;
        uint16_t offset;

        if (!xxemul_dos_files_list_of_lists(emulator, &segment, &offset)) {
            return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
        }
        emulator->x86.segment[XXEMUL_X86_ES] = segment;
        emulator->x86.gpr[XXEMUL_X86_RBX] = offset;
        break;
    }
    case 0x51u:
    case 0x62u:
        emulator->x86.gpr[XXEMUL_X86_RBX] = emulator->psp_segment;
        break;
    case 0x71u:
        xxemul_dos_result(emulator, 0x7100u, 1);
        return XXEMUL_STATUS_OK;
    default:
        return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    }
    emulator->x86.flags &= ~XXEMUL_DOS_CF;
    return XXEMUL_STATUS_OK;
}
