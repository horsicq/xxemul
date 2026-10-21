#include "xxemul_internal.h"
#include "xxemul_arm_auth.h"
#include "platforms/xxemul_darwin.h"

#include <xxfclib/formats/executable/macho/xx_macho.h>

#include <string.h>

static int xxemul_macho_machine_mode(uint32_t cpu_type, xxemul_image_format format, uint64_t *entry, xxemul_arch *arch, xxemul_mode *mode)
{
    switch (cpu_type) {
        case 7u:
            if (format != XXEMUL_IMAGE_MACHO32) return 0;
            *arch = XXEMUL_ARCH_X86;
            *mode = XXEMUL_MODE_X86_32;
            return 1;
        case 0x01000007u:
            if (format != XXEMUL_IMAGE_MACHO64) return 0;
            *arch = XXEMUL_ARCH_X86;
            *mode = XXEMUL_MODE_X86_64;
            return 1;
        case 12u:
            if (format != XXEMUL_IMAGE_MACHO32) return 0;
            *arch = XXEMUL_ARCH_ARM;
            *mode = (*entry & 1u) != 0u ? XXEMUL_MODE_ARM_T32 : XXEMUL_MODE_ARM_A32;
            *entry &= ~UINT64_C(1);
            return 1;
        case 0x0100000cu:
            if (format != XXEMUL_IMAGE_MACHO64) return 0;
            *arch = XXEMUL_ARCH_ARM;
            *mode = XXEMUL_MODE_ARM_A64;
            return 1;
        default: return 0;
    }
}

static int xxemul_macho_is_pagezero(const xx_macho_segment *segment)
{
    return strcmp(segment->name, "__PAGEZERO") == 0 && segment->file_size == 0u && segment->initial_protection == 0u;
}

#include "xxemul_macho_fixups.h"

static uint32_t macho_fat_u32(const uint8_t *p, int little)
{
    if (little) return macho_u32(p);
    return (uint32_t)p[3] | (uint32_t)p[2] << 8 | (uint32_t)p[1] << 16 | (uint32_t)p[0] << 24;
}

static uint64_t macho_fat_u64(const uint8_t *p, int little)
{
    if (little) return macho_u64(p);
    return (uint64_t)macho_fat_u32(p + 4, 0) | (uint64_t)macho_fat_u32(p, 0) << 32;
}

static xxemul_status macho_unixthread(const uint8_t *image, size_t size,
                                     xxemul_arm_state *state, int *found)
{
    size_t offset = 32u, commands_end;
    uint32_t i, count;
    *found = 0;
    memset(state, 0, sizeof(*state));
    if (size < 32u || !macho_range(size, offset, macho_u32(image + 20u))) return XXEMUL_STATUS_INVALID_IMAGE;
    commands_end = offset + macho_u32(image + 20u);
    count = macho_u32(image + 16u);
    if (count > (commands_end - offset) / 8u) return XXEMUL_STATUS_INVALID_IMAGE;
    for (i = 0; i < count; ++i) {
        uint32_t command, length;
        unsigned reg;
        if (!macho_range(commands_end, offset, 8u)) return XXEMUL_STATUS_INVALID_IMAGE;
        command = macho_u32(image + offset);
        length = macho_u32(image + offset + 4u);
        if (length < 8u || !macho_range(commands_end, offset, length)) return XXEMUL_STATUS_INVALID_IMAGE;
        if (command == 5u) { /* LC_UNIXTHREAD / ARM_THREAD_STATE64 */
            if (*found || macho_u32(image + 4u) != UINT32_C(0x0100000c) || length != 288u ||
                macho_u32(image + offset + 8u) != 6u || macho_u32(image + offset + 12u) != 68u)
                return XXEMUL_STATUS_UNSUPPORTED_IMAGE;
            for (reg = 0; reg < 31u; ++reg) state->gpr[reg] = macho_u64(image + offset + 16u + reg * 8u);
            state->sp = macho_u64(image + offset + 264u);
            state->pc = macho_u64(image + offset + 272u);
            state->pstate = macho_u32(image + offset + 280u) & UINT32_C(0xf0000000);
            *found = 1;
        }
        offset += length;
    }
    return offset == commands_end ? XXEMUL_STATUS_OK : XXEMUL_STATUS_INVALID_IMAGE;
}

/* FAT headers contain offsets in the container, whereas every thin slice's
 * load commands use offsets relative to that slice. Select, then parse once
 * through the existing thin path. Never dispatch a guest binary to the host. */
static int macho_load_fat(xxemul_image_format format, const uint8_t *image, size_t size,
                          xxemul **result, xxemul_status *status)
{
    uint32_t magic, count, i;
    uint64_t best_offset = 0, best_size = 0;
    uint32_t best_subtype = 0;
    int little, wide, best_rank = 0;
    size_t record_size;
    xx_io_device *slice;
    if (size < 4u) return 0;
    magic = macho_fat_u32(image, 0);
    if (magic != UINT32_C(0xcafebabe) && magic != UINT32_C(0xbebafeca) &&
        magic != UINT32_C(0xcafebabf) && magic != UINT32_C(0xbfbafeca)) return 0;
    *result = NULL;
    *status = XXEMUL_STATUS_INVALID_IMAGE;
    if (size < 8u) return 1;
    little = magic == UINT32_C(0xbebafeca) || magic == UINT32_C(0xbfbafeca);
    wide = magic == UINT32_C(0xcafebabf) || magic == UINT32_C(0xbfbafeca);
    record_size = wide ? 32u : 20u;
    count = macho_fat_u32(image + 4, little);
    if (!count || !macho_range(size, 8u, (uint64_t)count * record_size)) return 1;
    for (i = 0; i < count; ++i) {
        const uint8_t *record = image + 8u + (size_t)i * record_size;
        uint32_t cpu = macho_fat_u32(record, little), subtype = macho_fat_u32(record + 4u, little);
        uint64_t offset = wide ? macho_fat_u64(record + 8u, little) : macho_fat_u32(record + 8u, little);
        uint64_t length = wide ? macho_fat_u64(record + 16u, little) : macho_fat_u32(record + 12u, little);
        uint32_t alignment = macho_fat_u32(record + (wide ? 24u : 16u), little);
        int rank = cpu == UINT32_C(0x0100000c) ? ((subtype & 0xffffffu) == 2u ? 2 :
                                                                (subtype & 0xffffffu) == 0u ? 1 : 0) : 0;
        if (alignment > 63u || !length || offset < 8u + (uint64_t)count * record_size ||
            (offset & ((UINT64_C(1) << alignment) - 1u)) || !macho_range(size, offset, length) ||
            (wide && macho_fat_u32(record + 28u, little))) return 1;
        if (rank > best_rank) { best_rank = rank; best_offset = offset; best_size = length; best_subtype = subtype; }
    }
    if (!best_rank || format != XXEMUL_IMAGE_MACHO64) { *status = XXEMUL_STATUS_UNSUPPORTED_IMAGE; return 1; }
    if (best_size < 32u || macho_u32(image + (size_t)best_offset) != UINT32_C(0xfeedfacf) ||
        macho_u32(image + (size_t)best_offset + 4u) != UINT32_C(0x0100000c) ||
        macho_u32(image + (size_t)best_offset + 8u) != best_subtype) return 1;
    slice = xx_io_mem_open_ro(image + (size_t)best_offset, (size_t)best_size);
    if (!slice) { *status = XXEMUL_STATUS_OUT_OF_MEMORY; return 1; }
    *result = xxemul_load_macho(XXEMUL_IMAGE_MACHO64, image + (size_t)best_offset, (size_t)best_size, slice, status);
    xx_io_close(slice);
    return 1;
}

xxemul *xxemul_load_macho(xxemul_image_format format, const uint8_t *image, size_t image_size, xx_io_device *io, xxemul_status *status)
{
    xx_macho macho;
    xxemul *emulator = NULL;
    xxemul_arch arch;
    xxemul_mode mode;
    uint64_t base = UINT64_MAX;
    uint64_t end = 0u;
    uint64_t entry = 0u;
    uint32_t index;
    int entry_mapped = 0;
    int darwin = 0;
    uint64_t runtime_base = 0, allocation_end;
    xxemul_macho_linkedit linkedit;
    xxemul_arm_state thread_state;
    int has_thread = 0;

    if (macho_load_fat(format, image, image_size, &emulator, status)) return emulator;
    xx_macho_init(&macho, io, 0);
    *status = XXEMUL_STATUS_INVALID_IMAGE;
    if (!xx_macho_handle_base_info(&macho.format, NULL) || xx_macho_is_64(&macho) != (format == XXEMUL_IMAGE_MACHO64)) {
        goto done;
    }
    if (xx_macho_get_file_type(&macho) != XX_MACHO_FILE_EXECUTE || (macho.magic != XX_MACHO_MAGIC_32 && macho.magic != XX_MACHO_MAGIC_64)) {
        *status = XXEMUL_STATUS_UNSUPPORTED_IMAGE;
        goto done;
    }
    if (format == XXEMUL_IMAGE_MACHO64) {
        *status = macho_unixthread(image, image_size, &thread_state, &has_thread);
        if (*status != XXEMUL_STATUS_OK) goto done;
    }
    if ((!macho.has_main_entry && !has_thread) || (macho.has_main_entry && has_thread)) {
        *status = XXEMUL_STATUS_UNSUPPORTED_IMAGE;
        goto done;
    }
    if (has_thread) entry = thread_state.pc;
    *status = XXEMUL_STATUS_INVALID_IMAGE;
    for (index = 0u; index < xx_macho_get_number_of_segments(&macho); ++index) {
        const xx_macho_segment *segment = xx_macho_get_segment(&macho, index);
        uint64_t segment_end;

        if (segment == NULL) {
            goto done;
        }
        if (xxemul_macho_is_pagezero(segment)) {
            continue;
        }
        if (segment->file_size > segment->virtual_size || segment->file_offset > image_size || segment->file_size > image_size - segment->file_offset ||
            segment->virtual_address > UINT64_MAX - segment->virtual_size) {
            goto done;
        }
        if (segment->virtual_size == 0u) continue;
        segment_end = segment->virtual_address + segment->virtual_size;
        if (segment->virtual_address < base) {
            base = segment->virtual_address;
        }
        if (segment_end > end) {
            end = segment_end;
        }
        if (macho.has_main_entry && segment->file_size != 0u && macho.main_entry_offset >= segment->file_offset && macho.main_entry_offset - segment->file_offset < segment->file_size &&
            (segment->initial_protection & 4u) != 0u) {
            entry = segment->virtual_address + macho.main_entry_offset - segment->file_offset;
            entry_mapped = 1;
        }
        if (has_thread && entry >= segment->virtual_address && entry - segment->virtual_address < segment->file_size &&
            (segment->initial_protection & 4u) != 0u) entry_mapped = 1;
    }
    if (base == UINT64_MAX || !entry_mapped) {
        goto done;
    }
    if (!xxemul_macho_machine_mode(xx_macho_get_cpu_type(&macho), format, &entry, &arch, &mode)) {
        *status = XXEMUL_STATUS_UNSUPPORTED_IMAGE;
        goto done;
    }
    *status = macho_linkedit(image, image_size, format == XXEMUL_IMAGE_MACHO64, &linkedit);
    if (*status != XXEMUL_STATUS_OK) goto done;
    darwin = arch == XXEMUL_ARCH_ARM && mode == XXEMUL_MODE_ARM_A64;
    /* 32-bit chains and dyld opcode streams need
     * separate implementations; never execute an image with encoded pointers. */
    if ((linkedit.has_fixups && !darwin) || (darwin && (linkedit.has_old_fixups || linkedit.has_initializers))) {
        *status = XXEMUL_STATUS_UNSUPPORTED_IMAGE;
        goto done;
    }
    base &= ~UINT64_C(0xfff);
    allocation_end = end;
    if (darwin) {
        if (has_thread) {
            if (end - base > XXEMUL_DARWIN_IMAGE_WINDOW_SIZE || base > UINT64_MAX - XXEMUL_DARWIN_IMAGE_WINDOW_SIZE) {
                *status = XXEMUL_STATUS_UNSUPPORTED_IMAGE;
                goto done;
            }
            end = base + XXEMUL_DARWIN_IMAGE_WINDOW_SIZE;
        }
        if (end > UINT64_MAX - (uint64_t)XXEMUL_DARWIN_ARENA_SIZE -
                (has_thread ? (uint64_t)XXEMUL_DARWIN_VM_ARENA_SIZE : 0u) - UINT64_C(0xfff)) {
            *status = XXEMUL_STATUS_UNSUPPORTED_IMAGE;
            goto done;
        }
        runtime_base = (end + UINT64_C(0xfff)) & ~UINT64_C(0xfff);
        allocation_end = runtime_base + XXEMUL_DARWIN_ARENA_SIZE;
        if (has_thread) allocation_end += XXEMUL_DARWIN_VM_ARENA_SIZE;
    }
    emulator = xxemul_image_allocate(arch, mode, base, allocation_end - base, entry, 1, status);
    if (emulator == NULL) {
        goto done;
    }
    for (index = 0u; index < xx_macho_get_number_of_segments(&macho); ++index) {
        const xx_macho_segment *segment = xx_macho_get_segment(&macho, index);

        if (!xxemul_macho_is_pagezero(segment) && segment->file_size != 0u) {
            xx_mem_copy(emulator->region_data + (size_t)(segment->virtual_address - base), image + (size_t)segment->file_offset, (size_t)segment->file_size);
        }
    }
    if (darwin) {
        emulator->darwin = xxemul_darwin_create(emulator, runtime_base, status);
        if (emulator->darwin == NULL) goto failed;
        if (has_thread) {
            uint64_t stack = emulator->arm.sp;
            if (thread_state.sp && (thread_state.sp < allocation_end || thread_state.sp > stack || (thread_state.sp & 15u))) {
                *status = XXEMUL_STATUS_UNSUPPORTED_IMAGE;
                goto failed;
            }
            emulator->arm = thread_state;
            if (!emulator->arm.sp) emulator->arm.sp = stack;
            *status = xxemul_darwin_kernel_entry(emulator->darwin, image, image_size);
            if (*status != XXEMUL_STATUS_OK) goto failed;
        }
        if (linkedit.has_fixups) {
            *status = macho_chained_fixups(emulator, image, &linkedit, &macho, base, 0);
            if (*status != XXEMUL_STATUS_OK) goto failed;
        }
    }
    goto done;
failed:
    xxemul_destroy(emulator);
    emulator = NULL;
done:
    xx_macho_destroy(&macho);
    return emulator;
}

/* The packed program has already executed its decompressor and segment
 * mapper before reaching the modeled dyld entry. Reconstruct only metadata's
 * file view from those live guest segments; never read an unpacked host file. */
xxemul_status xxemul_macho_bind_restored(xxemul *emulator, uint64_t header_address, uint64_t *main_address)
{
    uint8_t header[32], *commands = NULL, *image = NULL;
    uint64_t file_size = 0, preferred_base = UINT64_MAX, window_end;
    size_t command_size, offset;
    uint32_t count, i;
    int64_t slide;
    xx_io_device *io = NULL;
    xx_macho macho;
    xxemul_macho_linkedit linkedit;
    xxemul_status status = XXEMUL_STATUS_INVALID_IMAGE;
    int initialized = 0, entry_found = 0;
    if (!emulator || !emulator->darwin || !main_address || emulator->arch != XXEMUL_ARCH_ARM || emulator->mode != XXEMUL_MODE_ARM_A64)
        return XXEMUL_STATUS_INVALID_ARGUMENT;
    *main_address = 0;
    if (emulator->region_address > UINT64_MAX - XXEMUL_DARWIN_IMAGE_WINDOW_SIZE) return status;
    window_end = emulator->region_address + XXEMUL_DARWIN_IMAGE_WINDOW_SIZE;
    if (header_address < emulator->region_address || header_address > window_end - sizeof(header) ||
        xxemul_read_memory(emulator, header_address, header, sizeof(header)) != XXEMUL_STATUS_OK ||
        macho_u32(header) != UINT32_C(0xfeedfacf) || macho_u32(header + 4u) != UINT32_C(0x0100000c) || macho_u32(header + 12u) != 2u) return status;
    command_size = macho_u32(header + 20u);
    count = macho_u32(header + 16u);
    if (command_size > 1024u * 1024u || command_size > window_end - header_address - sizeof(header) || count > command_size / 8u) return status;
    commands = xx_mem_alloc(sizeof(header) + command_size);
    if (!commands) return XXEMUL_STATUS_OUT_OF_MEMORY;
    if (xxemul_read_memory(emulator, header_address, commands, sizeof(header) + command_size) != XXEMUL_STATUS_OK) goto done;
    offset = sizeof(header);
    for (i = 0; i < count; ++i) {
        uint32_t command, length;
        uint64_t file_offset, bytes;
        if (!macho_range(sizeof(header) + command_size, offset, 8u)) goto done;
        command = macho_u32(commands + offset);
        length = macho_u32(commands + offset + 4u);
        if (length < 8u || !macho_range(sizeof(header) + command_size, offset, length)) goto done;
        if (command == 0x19u) {
            if (length < 72u) goto done;
            file_offset = macho_u64(commands + offset + 40u);
            bytes = macho_u64(commands + offset + 48u);
            if (bytes > macho_u64(commands + offset + 32u) || file_offset > 64u * 1024u * 1024u || bytes > 64u * 1024u * 1024u - file_offset) goto done;
            if (bytes && !file_offset) {
                if (preferred_base != UINT64_MAX) goto done;
                preferred_base = macho_u64(commands + offset + 24u);
            }
            if (bytes && file_offset + bytes > file_size) file_size = file_offset + bytes;
        }
        offset += length;
    }
    if (offset != sizeof(header) + command_size || preferred_base == UINT64_MAX || file_size < offset) goto done;
    if (header_address >= preferred_base) {
        if (header_address - preferred_base > INT64_MAX) goto done;
        slide = (int64_t)(header_address - preferred_base);
    } else {
        if (preferred_base - header_address > INT64_MAX) goto done;
        slide = -(int64_t)(preferred_base - header_address);
    }
    image = xx_mem_calloc(1, (size_t)file_size);
    if (!image) { status = XXEMUL_STATUS_OUT_OF_MEMORY; goto done; }
    offset = sizeof(header);
    for (i = 0; i < count; ++i) {
        uint32_t length = macho_u32(commands + offset + 4u);
        if (macho_u32(commands + offset) == 0x19u) {
            uint64_t address, virtual_size = macho_u64(commands + offset + 32u);
            uint64_t file_offset = macho_u64(commands + offset + 40u), bytes = macho_u64(commands + offset + 48u);
            int pagezero = !memcmp(commands + offset + 8u, "__PAGEZERO\0", 11u) && !bytes && !macho_u32(commands + offset + 60u);
            if (!pagezero && virtual_size) {
                if (macho_add_signed(macho_u64(commands + offset + 24u), slide, &address) != XXEMUL_STATUS_OK ||
                    address < emulator->region_address || address > window_end || virtual_size > window_end - address) goto done;
                if (bytes && xxemul_read_memory(emulator, address, image + (size_t)file_offset, (size_t)bytes) != XXEMUL_STATUS_OK) goto done;
            }
        }
        offset += length;
    }
    /* The metadata used to reconstruct the file view must itself come from
     * the same restored header, not an overlapping segment's file range. */
    if (memcmp(image, commands, sizeof(header) + command_size)) goto done;
    io = xx_io_mem_open_ro(image, (size_t)file_size);
    if (!io) { status = XXEMUL_STATUS_OUT_OF_MEMORY; goto done; }
    xx_macho_init(&macho, io, 0);
    initialized = 1;
    if (!xx_macho_handle_base_info(&macho.format, NULL) || !macho.has_main_entry || !xx_macho_is_64(&macho)) goto done;
    status = macho_linkedit(image, (size_t)file_size, 1, &linkedit);
    if (status != XXEMUL_STATUS_OK) goto done;
    if (linkedit.has_old_fixups || linkedit.has_initializers) { status = XXEMUL_STATUS_UNSUPPORTED_IMAGE; goto done; }
    status = XXEMUL_STATUS_INVALID_IMAGE;
    for (i = 0; i < xx_macho_get_number_of_segments(&macho); ++i) {
        const xx_macho_segment *segment = xx_macho_get_segment(&macho, i);
        uint64_t target;
        if (!segment) goto done;
        if ((segment->initial_protection & 4u) && macho.main_entry_offset >= segment->file_offset &&
            macho.main_entry_offset - segment->file_offset < segment->file_size) {
            if (entry_found || segment->virtual_address > UINT64_MAX - (macho.main_entry_offset - segment->file_offset)) goto done;
            target = segment->virtual_address + macho.main_entry_offset - segment->file_offset;
            if (macho_add_signed(target, slide, main_address) != XXEMUL_STATUS_OK || (*main_address & 3u)) goto done;
            entry_found = 1;
        }
    }
    if (!entry_found) goto done;
    status = linkedit.has_fixups ? macho_chained_fixups(emulator, image, &linkedit, &macho, preferred_base, slide) : XXEMUL_STATUS_OK;
done:
    if (initialized) xx_macho_destroy(&macho);
    if (io) xx_io_close(io);
    xx_mem_free(image);
    xx_mem_free(commands);
    if (status != XXEMUL_STATUS_OK) *main_address = 0;
    return status;
}
