#include "xxemul_internal.h"

#include <xxfclib/formats/elf/xx_elf.h>
#include "xxemul/xxemul_elf.h"

#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

static int xxemul_elf_machine_mode(
    uint16_t machine, xxemul_image_format format,
    uint64_t *entry, xxemul_arch *arch, xxemul_mode *mode)
{
    switch (machine) {
    case 3u:
        if (format != XXEMUL_IMAGE_ELF32) return 0;
        *arch = XXEMUL_ARCH_X86;
        *mode = XXEMUL_MODE_X86_32;
        return 1;
    case 62u:
        if (format != XXEMUL_IMAGE_ELF64) return 0;
        *arch = XXEMUL_ARCH_X86;
        *mode = XXEMUL_MODE_X86_64;
        return 1;
    case 40u:
        if (format != XXEMUL_IMAGE_ELF32) return 0;
        *arch = XXEMUL_ARCH_ARM;
        *mode = (*entry & 1u) != 0u
            ? XXEMUL_MODE_ARM_T32 : XXEMUL_MODE_ARM_A32;
        *entry &= ~UINT64_C(1);
        return 1;
    case 183u:
        if (format != XXEMUL_IMAGE_ELF64) return 0;
        *arch = XXEMUL_ARCH_ARM;
        *mode = XXEMUL_MODE_ARM_A64;
        return 1;
    default:
        return 0;
    }
}

xxemul *xxemul_load_elf(
    xxemul_image_format format, const uint8_t *image,
    size_t image_size, xx_io_device *io, xxemul_status *status)
{
    xx_elf elf;
    xxemul *emulator = NULL;
    xxemul_arch arch;
    xxemul_mode mode;
    uint64_t entry;
    uint64_t base = UINT64_MAX;
    uint64_t end = 0u;
    uint64_t index;
    int entry_mapped = 0;

    xx_elf_init(&elf, io, 0);
    *status = XXEMUL_STATUS_INVALID_IMAGE;
    if (!xx_elf_handle_base_info(&elf.format, NULL)
        || xx_elf_is_64(&elf) != (format == XXEMUL_IMAGE_ELF64)) {
        goto done;
    }
    if (xx_elf_get_type(&elf) != XX_ELF_TYPE_EXEC
        || elf.data_encoding != XX_ELF_DATA_LSB) {
        *status = XXEMUL_STATUS_UNSUPPORTED_IMAGE;
        goto done;
    }
    entry = xx_elf_get_entry_point(&elf);
    if (!xxemul_elf_machine_mode(
            xx_elf_get_machine(&elf), format, &entry, &arch, &mode)) {
        *status = XXEMUL_STATUS_UNSUPPORTED_IMAGE;
        goto done;
    }
    for (index = 0u; index < xx_elf_get_number_of_program_headers(&elf);
         ++index) {
        const xx_elf_program_header *program =
            xx_elf_get_program_header(&elf, index);
        uint64_t program_end;

        if (program == NULL) {
            goto done;
        }
        if (program->type != XX_ELF_PROGRAM_LOAD
            || program->memory_size == 0u) {
            continue;
        }
        if (program->file_size > program->memory_size
            || program->offset > image_size
            || program->virtual_address > UINT64_MAX - program->memory_size) {
            goto done;
        }
        /* UPX-packed ELFs give the first PT_LOAD a file_size rounded up to a
         * page, which can run a few bytes past the physical end of the file;
         * the kernel simply zero-fills the tail. Tolerate that here rather
         * than rejecting the image - the copy below clamps to what exists. */
        program_end = program->virtual_address + program->memory_size;
        if (program->virtual_address < base) {
            base = program->virtual_address;
        }
        if (program_end > end) {
            end = program_end;
        }
        if (entry >= program->virtual_address && entry < program_end
            && (program->flags & 1u) != 0u) {
            entry_mapped = 1;
        }
    }
    if (base == UINT64_MAX || !entry_mapped) {
        goto done;
    }
    base &= ~UINT64_C(0xfff);
    emulator = xxemul_image_allocate(
        arch, mode, base, end - base, entry, 1, status);
    if (emulator == NULL) {
        goto done;
    }
    for (index = 0u; index < xx_elf_get_number_of_program_headers(&elf);
         ++index) {
        const xx_elf_program_header *program =
            xx_elf_get_program_header(&elf, index);

        if (program->type == XX_ELF_PROGRAM_LOAD
            && program->file_size != 0u) {
            uint64_t copy = program->file_size;
            if (copy > image_size - program->offset)
                copy = image_size - program->offset;   /* clamp to the file */
            xx_mem_copy(emulator->region_data
                    + (size_t)(program->virtual_address - base),
                image + (size_t)program->offset,
                (size_t)copy);
        }
    }
done:
    xx_elf_destroy(&elf);
    return emulator;
}

/* Shared objects deliberately have a separate API: no dependency loading,
 * host execution, implicit symbol stubs, or executable-entry assumptions. */
#define ELF_SHARED_MAX_PHDRS 128u
#define ELF_SHARED_MAX_DYNAMIC 4096u
#define ELF_SHARED_MAX_INITIALIZERS 4096u

typedef struct shared_segment {
    uint64_t address, offset, file_size, memory_size;
    uint32_t flags;
} shared_segment;

typedef struct shared_symbol {
    uint64_t value, size, resolved;
    uint32_t name;
    uint16_t section, version;
    uint8_t info, other, was_resolved;
} shared_symbol;

typedef struct shared_dynamic {
    uint64_t hash, gnu_hash, strings, string_size, symbols, symbol_size;
    uint64_t rel, rel_size, rel_entry, rela, rela_size, rela_entry;
    uint64_t jump_rel, jump_size, jump_kind, init, init_array, init_array_size;
    uint64_t versions, version_need, version_need_count, version_def, version_def_count;
    uint64_t seen;
} shared_dynamic;

struct xxemul_elf_shared {
    xxemul *emulator;
    xxemul_elf_shared_info info;
    xxemul_elf_shared_config config;
    shared_segment segments[ELF_SHARED_MAX_PHDRS];
    size_t segment_count, allocated;
    shared_symbol *symbols;
    uint32_t symbol_count;
    char *strings;
    size_t string_size;
    const char **version_names;
    size_t version_count;
    uint64_t *initializers;
    size_t initializer_count;
    unsigned width;
};

typedef struct shared_input {
    const uint8_t *data;
    size_t size;
    xxemul_elf_shared *module;
    xxemul_elf_result *result;
} shared_input;

static uint16_t shared_u16(const uint8_t *p) {
    return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}
static uint32_t shared_u32(const uint8_t *p) {
    return (uint32_t)shared_u16(p) | ((uint32_t)shared_u16(p + 2) << 16);
}
static uint64_t shared_u64(const uint8_t *p) {
    return (uint64_t)shared_u32(p) | ((uint64_t)shared_u32(p + 4) << 32);
}
static uint64_t shared_word(const uint8_t *p, unsigned width) {
    return width == 8 ? shared_u64(p) : shared_u32(p);
}
static void shared_store(uint8_t *p, uint64_t value, unsigned width) {
    unsigned i;
    for (i = 0; i < width; ++i) p[i] = (uint8_t)(value >> (i * 8));
}
static int shared_fail(shared_input *input, xxemul_status status,
    const char *format, ...) {
    va_list arguments;
    input->result->status = status;
    va_start(arguments, format);
    (void)vsnprintf(input->result->diagnostic,
        sizeof(input->result->diagnostic), format, arguments);
    va_end(arguments);
    return 0;
}
static int shared_file_range(const shared_input *input, uint64_t offset, uint64_t size) {
    return offset <= input->size && size <= input->size - (size_t)offset;
}
/* Dynamic metadata must have physical file bytes, not merely zero-filled BSS. */
static const uint8_t *shared_raw(const shared_input *input, uint64_t address, uint64_t size) {
    size_t i;
    for (i = 0; i < input->module->segment_count; ++i) {
        const shared_segment *segment = &input->module->segments[i];
        uint64_t relative;
        if (address < segment->address) continue;
        relative = address - segment->address;
        if (relative <= segment->file_size && size <= segment->file_size - relative &&
            shared_file_range(input, segment->offset + relative, size))
            return input->data + (size_t)(segment->offset + relative);
    }
    return NULL;
}
static uint8_t *shared_mapped(xxemul_elf_shared *module, uint64_t address,
    uint64_t size, int executable) {
    size_t i;
    for (i = 0; i < module->segment_count; ++i) {
        const shared_segment *segment = &module->segments[i];
        uint64_t relative;
        if (address < segment->address || (executable && !(segment->flags & 1u))) continue;
        relative = address - segment->address;
        if (relative <= segment->memory_size && size <= segment->memory_size - relative)
            return module->emulator->region_data +
                (size_t)(module->info.load_bias + address - module->info.image_address);
    }
    return NULL;
}
static void *shared_alloc(shared_input *input, size_t count, size_t size) {
    size_t bytes;
    void *memory;
    if (size && count > SIZE_MAX / size) {
        shared_fail(input, XXEMUL_STATUS_LIMIT_REACHED, "ELF metadata allocation overflow");
        return NULL;
    }
    bytes = count * size;
    if (bytes > input->module->config.max_memory_bytes - input->module->allocated) {
        shared_fail(input, XXEMUL_STATUS_LIMIT_REACHED, "ELF memory budget exceeded");
        return NULL;
    }
    memory = xx_mem_calloc(count ? count : 1, size ? size : 1);
    if (!memory) {
        shared_fail(input, XXEMUL_STATUS_OUT_OF_MEMORY, "ELF metadata allocation failed");
        return NULL;
    }
    input->module->allocated += bytes;
    return memory;
}
static int shared_page_size(size_t requested, size_t *rounded) {
    if (requested > SIZE_MAX - 4095u) return 0;
    *rounded = (requested + 4095u) & ~(size_t)4095u;
    return *rounded != 0;
}

static int shared_headers(shared_input *input, uint64_t *dynamic_address,
    uint64_t *dynamic_size, uint64_t *section_offset, uint16_t *section_count,
    uint16_t *section_entry) {
    xxemul_elf_shared *module = input->module;
    const uint8_t *data = input->data;
    uint64_t phoff, low = UINT64_MAX, high = 0, entry = 0, first_exec = UINT64_MAX;
    uint64_t dynamic_offset = 0;
    uint16_t phcount, phsize;
    unsigned i;
    int is64;
    if (input->size < 52 || memcmp(data, "\177ELF", 4) ||
        (data[4] != 1 && data[4] != 2) || data[5] != 1 || data[6] != 1)
        return shared_fail(input, XXEMUL_STATUS_INVALID_IMAGE, "expected little-endian ELF32/ELF64");
    is64 = data[4] == 2;
    module->width = is64 ? 8u : 4u;
    if (input->size < (is64 ? 64u : 52u) || shared_u16(data + 16) != 3 || shared_u32(data + 20) != 1)
        return shared_fail(input, XXEMUL_STATUS_INVALID_IMAGE, "expected an ET_DYN shared ELF image");
    module->info.machine = shared_u16(data + 18);
    if (!xxemul_elf_machine_mode(module->info.machine,
            is64 ? XXEMUL_IMAGE_ELF64 : XXEMUL_IMAGE_ELF32,
            &entry, &module->info.arch, &module->info.mode))
        return shared_fail(input, XXEMUL_STATUS_UNSUPPORTED_IMAGE, "unsupported shared ELF machine %u", module->info.machine);
    phoff = is64 ? shared_u64(data + 32) : shared_u32(data + 28);
    phsize = shared_u16(data + (is64 ? 54 : 42));
    phcount = shared_u16(data + (is64 ? 56 : 44));
    *section_offset = is64 ? shared_u64(data + 40) : shared_u32(data + 32);
    *section_entry = shared_u16(data + (is64 ? 58 : 46));
    *section_count = shared_u16(data + (is64 ? 60 : 48));
    if (shared_u16(data + (is64 ? 52 : 40)) != (is64 ? 64u : 52u) ||
        phsize != (is64 ? 56u : 32u) || !phcount || phcount > ELF_SHARED_MAX_PHDRS ||
        !shared_file_range(input, phoff, (uint64_t)phsize * phcount))
        return shared_fail(input, XXEMUL_STATUS_INVALID_IMAGE, "invalid/bounded ELF program header table");
    for (i = 0; i < phcount; ++i) {
        const uint8_t *p = data + (size_t)phoff + (size_t)i * phsize;
        uint32_t type = shared_u32(p), flags = shared_u32(p + (is64 ? 4 : 24));
        uint64_t offset = is64 ? shared_u64(p + 8) : shared_u32(p + 4);
        uint64_t address = is64 ? shared_u64(p + 16) : shared_u32(p + 8);
        uint64_t file_size = is64 ? shared_u64(p + 32) : shared_u32(p + 16);
        uint64_t memory_size = is64 ? shared_u64(p + 40) : shared_u32(p + 20);
        uint64_t alignment = is64 ? shared_u64(p + 48) : shared_u32(p + 28);
        if (type == 7 && memory_size)
            return shared_fail(input, XXEMUL_STATUS_UNSUPPORTED_IMAGE, "ELF TLS is not supported");
        if (type == 2) {
            if (*dynamic_size || !file_size || file_size > memory_size)
                return shared_fail(input, XXEMUL_STATUS_INVALID_IMAGE, "invalid/duplicate PT_DYNAMIC");
            *dynamic_address = address;
            *dynamic_size = file_size;
            dynamic_offset = offset;
        }
        if (type != 1 || !memory_size) continue;
        if (file_size > memory_size || !shared_file_range(input, offset, file_size) ||
            address > UINT64_MAX - memory_size ||
            (alignment > 1 && ((alignment & (alignment - 1)) ||
             (address & (alignment - 1)) != (offset & (alignment - 1)))))
            return shared_fail(input, XXEMUL_STATUS_INVALID_IMAGE, "invalid PT_LOAD extent/alignment");
        {
            size_t j;
            for (j = 0; j < module->segment_count; ++j) {
                const shared_segment *s = &module->segments[j];
                if (address < s->address + s->memory_size && s->address < address + memory_size)
                    return shared_fail(input, XXEMUL_STATUS_UNSUPPORTED_IMAGE, "overlapping PT_LOAD segments are not supported");
            }
        }
        module->segments[module->segment_count].address = address;
        module->segments[module->segment_count].offset = offset;
        module->segments[module->segment_count].file_size = file_size;
        module->segments[module->segment_count].memory_size = memory_size;
        module->segments[module->segment_count++].flags = flags;
        if (address < low) low = address;
        if (address + memory_size > high) high = address + memory_size;
        if ((flags & 1u) && address < first_exec) first_exec = address;
    }
    if (!module->segment_count || !*dynamic_size || first_exec == UINT64_MAX || high > UINT64_MAX - 4095)
        return shared_fail(input, XXEMUL_STATUS_INVALID_IMAGE, "shared ELF needs loadable code and dynamic metadata");
    if (!shared_file_range(input, dynamic_offset, *dynamic_size) ||
        shared_raw(input, *dynamic_address, *dynamic_size) != data + (size_t)dynamic_offset)
        return shared_fail(input, XXEMUL_STATUS_INVALID_IMAGE, "PT_DYNAMIC does not match its file-backed PT_LOAD range");
    low &= ~UINT64_C(4095);
    high = (high + 4095) & ~UINT64_C(4095);
    if (module->info.load_bias & 4095u)
        return shared_fail(input, XXEMUL_STATUS_INVALID_ARGUMENT, "ELF load bias must be page aligned");
    {
        uint64_t span = high - low, total;
        size_t auxiliary, stack;
        xxemul_status status;
        if (!shared_page_size(module->config.auxiliary_bytes, &auxiliary) ||
            !shared_page_size(module->config.stack_bytes, &stack) || span > SIZE_MAX ||
            span > UINT64_MAX - auxiliary || span + auxiliary > UINT64_MAX - stack)
            return shared_fail(input, XXEMUL_STATUS_LIMIT_REACHED, "ELF arena size overflow");
        total = span + auxiliary + stack;
        if (total > module->config.max_memory_bytes - module->allocated ||
            module->info.load_bias > UINT64_MAX - low ||
            module->info.load_bias + low > UINT64_MAX - total ||
            (!is64 && module->info.load_bias + low + total - 1 > UINT32_MAX))
            return shared_fail(input, XXEMUL_STATUS_LIMIT_REACHED, "ELF mapped memory exceeds budget/address width");
        module->info.image_address = module->info.load_bias + low;
        module->info.image_size = (size_t)span;
        module->info.auxiliary_address = module->info.image_address + span;
        module->info.auxiliary_size = auxiliary;
        module->info.stack_address = module->info.auxiliary_address + auxiliary;
        module->info.stack_size = stack;
        module->emulator = xxemul_create_empty(module->info.arch, module->info.mode,
            module->info.image_address, (size_t)total, &status);
        if (!module->emulator) return shared_fail(input, status, "ELF guest CPU allocation failed");
        module->allocated += (size_t)total;
        if (module->info.arch == XXEMUL_ARCH_X86) {
            module->emulator->x86.ip = module->info.load_bias + first_exec;
            module->emulator->x86.flags = 2;
            module->emulator->x86.gpr[XXEMUL_X86_RSP] = (module->info.image_address + total) & ~UINT64_C(15);
        } else {
            module->emulator->arm.pc = module->info.load_bias + first_exec;
            module->emulator->arm.sp = (module->info.image_address + total) & ~UINT64_C(15);
        }
    }
    for (i = 0; i < module->segment_count; ++i) {
        const shared_segment *s = &module->segments[i];
        xx_mem_copy(shared_mapped(module, s->address, s->file_size, 0),
            data + (size_t)s->offset, (size_t)s->file_size);
    }
    return 1;
}

static int shared_dynamic_info(shared_input *input, uint64_t address,
    uint64_t size, shared_dynamic *dynamic) {
    unsigned width = input->module->width;
    uint64_t i, count = size / (width * 2u);
    const uint8_t *data = shared_raw(input, address, size);
    if (!data || size % (width * 2u) || count > ELF_SHARED_MAX_DYNAMIC)
        return shared_fail(input, XXEMUL_STATUS_INVALID_IMAGE, "invalid/bounded PT_DYNAMIC extent");
    for (i = 0; i < count; ++i) {
        uint64_t tag = shared_word(data + (size_t)i * width * 2u, width);
        uint64_t value = shared_word(data + (size_t)i * width * 2u + width, width);
        uint64_t *destination = NULL;
        unsigned bit = 0;
        if (!tag) {
            if ((dynamic->rel && ((dynamic->seen & (UINT64_C(1) << 12)) == 0 || (dynamic->seen & (UINT64_C(1) << 13)) == 0)) ||
                (dynamic->rela && ((dynamic->seen & (UINT64_C(1) << 6)) == 0 || (dynamic->seen & (UINT64_C(1) << 7)) == 0)) ||
                (dynamic->jump_rel && ((dynamic->seen & (UINT64_C(1) << 1)) == 0 || (dynamic->seen & (UINT64_C(1) << 14)) == 0)) ||
                (dynamic->init_array && (dynamic->seen & (UINT64_C(1) << 17)) == 0))
                return shared_fail(input, XXEMUL_STATUS_INVALID_IMAGE, "missing companion ELF dynamic size/entry tags");
            return 1;
        }
        switch (tag) {
        case 2: destination = &dynamic->jump_size; bit = 1; break;
        case 4: destination = &dynamic->hash; bit = 2; break;
        case 5: destination = &dynamic->strings; bit = 3; break;
        case 6: destination = &dynamic->symbols; bit = 4; break;
        case 7: destination = &dynamic->rela; bit = 5; break;
        case 8: destination = &dynamic->rela_size; bit = 6; break;
        case 9: destination = &dynamic->rela_entry; bit = 7; break;
        case 10: destination = &dynamic->string_size; bit = 8; break;
        case 11: destination = &dynamic->symbol_size; bit = 9; break;
        case 12: destination = &dynamic->init; bit = 10; break;
        case 17: destination = &dynamic->rel; bit = 11; break;
        case 18: destination = &dynamic->rel_size; bit = 12; break;
        case 19: destination = &dynamic->rel_entry; bit = 13; break;
        case 20: destination = &dynamic->jump_kind; bit = 14; break;
        case 23: destination = &dynamic->jump_rel; bit = 15; break;
        case 25: destination = &dynamic->init_array; bit = 16; break;
        case 27: destination = &dynamic->init_array_size; bit = 17; break;
        case UINT64_C(0x6ffffef5): destination = &dynamic->gnu_hash; bit = 18; break;
        case UINT64_C(0x6ffffff0): destination = &dynamic->versions; bit = 19; break;
        case UINT64_C(0x6ffffffe): destination = &dynamic->version_need; bit = 20; break;
        case UINT64_C(0x6fffffff): destination = &dynamic->version_need_count; bit = 21; break;
        case UINT64_C(0x6ffffffc): destination = &dynamic->version_def; bit = 22; break;
        case UINT64_C(0x6ffffffd): destination = &dynamic->version_def_count; bit = 23; break;
        case 32: case 33: /* ET_DYN cannot acquire executable preinitializers. */
        case 35: case 36: case 37: /* RELR */
        case UINT64_C(0x6000000f): case UINT64_C(0x60000010):
        case UINT64_C(0x60000011): case UINT64_C(0x60000012):
        case UINT64_C(0x6fffe000): case UINT64_C(0x6fffe001): case UINT64_C(0x6fffe003):
        case UINT64_C(0x6ffffefb): case UINT64_C(0x6ffffefc): /* Audit modules */
        case UINT64_C(0x7ffffffd): case UINT64_C(0x7fffffff): /* Symbol filters */
            if (value) return shared_fail(input, XXEMUL_STATUS_UNSUPPORTED_IMAGE,
                "unsupported ELF dynamic tag 0x%llx", (unsigned long long)tag);
            break;
        default: break; /* Binding/lifetime hints do not execute code. */
        }
        if (destination) {
            if (dynamic->seen & (UINT64_C(1) << bit))
                return shared_fail(input, XXEMUL_STATUS_INVALID_IMAGE, "duplicate ELF dynamic tag 0x%llx", (unsigned long long)tag);
            dynamic->seen |= UINT64_C(1) << bit;
            *destination = value;
        }
    }
    return shared_fail(input, XXEMUL_STATUS_INVALID_IMAGE, "unterminated PT_DYNAMIC");
}

static int shared_symbol_count(shared_input *input, const shared_dynamic *dynamic,
    uint64_t section_offset, uint16_t section_count, uint16_t section_entry,
    uint32_t *symbol_count) {
    const uint8_t *data;
    uint32_t count = 0, limit = input->module->config.max_symbols;
    if (dynamic->hash) {
        uint32_t buckets;
        uint64_t i;
        data = shared_raw(input, dynamic->hash, 8);
        if (!data) return shared_fail(input, XXEMUL_STATUS_INVALID_IMAGE, "invalid DT_HASH header");
        buckets = shared_u32(data); count = shared_u32(data + 4);
        if (!buckets || buckets > limit || !count || count > limit ||
            !shared_raw(input, dynamic->hash, 8 + ((uint64_t)buckets + count) * 4))
            return shared_fail(input, count > limit ? XXEMUL_STATUS_LIMIT_REACHED : XXEMUL_STATUS_INVALID_IMAGE,
                "invalid/bounded DT_HASH symbol count");
        data = shared_raw(input, dynamic->hash, 8 + ((uint64_t)buckets + count) * 4);
        for (i = 0; i < (uint64_t)buckets + count; ++i)
            if (shared_u32(data + 8 + (size_t)i * 4) >= count)
                return shared_fail(input, XXEMUL_STATUS_INVALID_IMAGE, "DT_HASH index is outside the symbol table");
    } else if (dynamic->gnu_hash) {
        uint32_t buckets, first, bloom, highest = 0, i;
        uint64_t buckets_address, chain_address;
        data = shared_raw(input, dynamic->gnu_hash, 16);
        if (!data) return shared_fail(input, XXEMUL_STATUS_INVALID_IMAGE, "invalid GNU hash header");
        buckets = shared_u32(data); first = shared_u32(data + 4); bloom = shared_u32(data + 8);
        if (!buckets || !bloom || (bloom & (bloom - 1u)) || buckets > limit || first > limit || bloom > limit ||
            dynamic->gnu_hash > UINT64_MAX - 16 - (uint64_t)bloom * input->module->width - (uint64_t)buckets * 4)
            return shared_fail(input, XXEMUL_STATUS_LIMIT_REACHED, "GNU hash dimensions exceed limits");
        buckets_address = dynamic->gnu_hash + 16 + (uint64_t)bloom * input->module->width;
        chain_address = buckets_address + (uint64_t)buckets * 4;
        if (!shared_raw(input, dynamic->gnu_hash, chain_address - dynamic->gnu_hash))
            return shared_fail(input, XXEMUL_STATUS_INVALID_IMAGE, "truncated GNU hash bloom/buckets");
        data = shared_raw(input, buckets_address, (uint64_t)buckets * 4);
        if (!data) return shared_fail(input, XXEMUL_STATUS_INVALID_IMAGE, "truncated GNU hash buckets");
        for (i = 0; i < buckets; ++i) {
            uint32_t symbol = shared_u32(data + (size_t)i * 4);
            if (symbol && (symbol < first || symbol >= limit))
                return shared_fail(input, XXEMUL_STATUS_INVALID_IMAGE, "invalid GNU hash bucket index");
            if (symbol > highest) highest = symbol;
        }
        count = first;
        if (highest) {
            uint32_t symbol = highest;
            for (;;) {
                uint64_t offset = (uint64_t)(symbol - first) * 4;
                if (symbol >= limit || chain_address > UINT64_MAX - offset ||
                    !(data = shared_raw(input, chain_address + offset, 4)))
                    return shared_fail(input, symbol >= limit ? XXEMUL_STATUS_LIMIT_REACHED : XXEMUL_STATUS_INVALID_IMAGE,
                        "unterminated/bounded GNU hash chain");
                ++symbol;
                if (shared_u32(data) & 1u) { count = symbol; break; }
            }
        }
    } else if (section_count && section_offset) {
        uint16_t i;
        unsigned expected = input->module->width == 8 ? 64u : 40u;
        if (section_entry != expected ||
            !shared_file_range(input, section_offset, (uint64_t)section_count * section_entry))
            return shared_fail(input, XXEMUL_STATUS_INVALID_IMAGE, "invalid ELF section table for dynamic symbols");
        for (i = 0; i < section_count; ++i) {
            const uint8_t *p = input->data + (size_t)section_offset + (size_t)i * section_entry;
            uint64_t address, size, entry;
            if (shared_u32(p + 4) != 11) continue;
            address = input->module->width == 8 ? shared_u64(p + 16) : shared_u32(p + 12);
            size = input->module->width == 8 ? shared_u64(p + 32) : shared_u32(p + 20);
            entry = input->module->width == 8 ? shared_u64(p + 56) : shared_u32(p + 36);
            if (address != dynamic->symbols) continue;
            if (count || !entry || entry != dynamic->symbol_size || size % entry || size / entry > limit)
                return shared_fail(input, XXEMUL_STATUS_INVALID_IMAGE, "invalid dynamic symbol section");
            count = (uint32_t)(size / entry);
        }
    }
    if (!count || count > limit)
        return shared_fail(input, XXEMUL_STATUS_INVALID_IMAGE, "cannot bound dynamic symbol table (hash/section required)");
    *symbol_count = count;
    return 1;
}

static int shared_version_name(shared_input *input, uint16_t index, uint32_t name) {
    xxemul_elf_shared *module = input->module;
    if (!index || index >= 0x8000 || name >= module->string_size || !module->strings[name] ||
        !memchr(module->strings + name, 0, module->string_size - name > 4096 ? 4096 : module->string_size - name))
        return shared_fail(input, XXEMUL_STATUS_INVALID_IMAGE, "invalid ELF symbol version index/name");
    if (index < module->version_count) {
        if (module->version_names[index])
            return shared_fail(input, XXEMUL_STATUS_INVALID_IMAGE, "duplicate ELF symbol version index");
        module->version_names[index] = module->strings + name;
    }
    return 1;
}

static int shared_version_next(shared_input *input, uint64_t *address,
    uint32_t next, unsigned minimum) {
    if (next < minimum || *address > UINT64_MAX - next)
        return shared_fail(input, XXEMUL_STATUS_INVALID_IMAGE, "invalid ELF symbol version chain offset");
    *address += next;
    return 1;
}

static int shared_versions(shared_input *input, const shared_dynamic *dynamic) {
    xxemul_elf_shared *module = input->module;
    uint64_t address;
    uint32_t i, work = 0;
    if (dynamic->version_need_count > ELF_SHARED_MAX_DYNAMIC ||
        dynamic->version_def_count > ELF_SHARED_MAX_DYNAMIC)
        return shared_fail(input, XXEMUL_STATUS_LIMIT_REACHED, "ELF symbol version record limit reached");
    if ((dynamic->version_need_count && !dynamic->version_need) ||
        (dynamic->version_def_count && !dynamic->version_def) ||
        (module->version_count > 2 && !dynamic->version_need_count && !dynamic->version_def_count))
        return shared_fail(input, XXEMUL_STATUS_INVALID_IMAGE, "missing ELF symbol version records");
    address = dynamic->version_need;
    for (i = 0; i < dynamic->version_need_count; ++i) {
        const uint8_t *p = shared_raw(input, address, 16);
        uint64_t auxiliary = address;
        uint16_t count, j;
        uint32_t next;
        if (!p || shared_u16(p) != 1 || !(count = shared_u16(p + 2)) ||
            shared_u32(p + 4) >= module->string_size)
            return shared_fail(input, XXEMUL_STATUS_INVALID_IMAGE, "invalid ELF Verneed record");
        next = shared_u32(p + 12);
        if (!shared_version_next(input, &auxiliary, shared_u32(p + 8), 16)) return 0;
        for (j = 0; j < count; ++j) {
            uint32_t auxiliary_next;
            uint16_t index;
            if (++work > module->config.max_symbols)
                return shared_fail(input, XXEMUL_STATUS_LIMIT_REACHED, "ELF symbol version work limit reached");
            p = shared_raw(input, auxiliary, 16);
            if (!p || (index = shared_u16(p + 6) & 0x7fffu) < 2 ||
                !shared_version_name(input, index, p ? shared_u32(p + 8) : 0))
                return input->result->status ? 0 : shared_fail(input, XXEMUL_STATUS_INVALID_IMAGE, "invalid ELF Vernaux record");
            auxiliary_next = shared_u32(p + 12);
            if (j + 1 == count) {
                if (auxiliary_next) return shared_fail(input, XXEMUL_STATUS_INVALID_IMAGE, "unterminated ELF Vernaux chain");
            } else if (!shared_version_next(input, &auxiliary, auxiliary_next, 16)) return 0;
        }
        if (i + 1 == dynamic->version_need_count) {
            if (next) return shared_fail(input, XXEMUL_STATUS_INVALID_IMAGE, "unterminated ELF Verneed chain");
        } else if (!shared_version_next(input, &address, next, 16)) return 0;
    }
    address = dynamic->version_def;
    for (i = 0; i < dynamic->version_def_count; ++i) {
        const uint8_t *p = shared_raw(input, address, 20);
        uint64_t auxiliary = address;
        uint16_t count, index, j;
        uint32_t next;
        if (!p || shared_u16(p) != 1 || !(count = shared_u16(p + 6)))
            return shared_fail(input, XXEMUL_STATUS_INVALID_IMAGE, "invalid ELF Verdef record");
        index = shared_u16(p + 4);
        next = shared_u32(p + 16);
        if (!shared_version_next(input, &auxiliary, shared_u32(p + 12), 20)) return 0;
        for (j = 0; j < count; ++j) {
            uint32_t auxiliary_next;
            if (++work > module->config.max_symbols)
                return shared_fail(input, XXEMUL_STATUS_LIMIT_REACHED, "ELF symbol version work limit reached");
            p = shared_raw(input, auxiliary, 8);
            if (!p || shared_u32(p) >= module->string_size)
                return shared_fail(input, XXEMUL_STATUS_INVALID_IMAGE, "invalid ELF Verdaux record");
            if (!j && !shared_version_name(input, index, shared_u32(p))) return 0;
            auxiliary_next = shared_u32(p + 4);
            if (j + 1 == count) {
                if (auxiliary_next) return shared_fail(input, XXEMUL_STATUS_INVALID_IMAGE, "unterminated ELF Verdaux chain");
            } else if (!shared_version_next(input, &auxiliary, auxiliary_next, 8)) return 0;
        }
        if (i + 1 == dynamic->version_def_count) {
            if (next) return shared_fail(input, XXEMUL_STATUS_INVALID_IMAGE, "unterminated ELF Verdef chain");
        } else if (!shared_version_next(input, &address, next, 20)) return 0;
    }
    for (i = 0; i < module->symbol_count; ++i) {
        uint16_t version = module->symbols[i].version & 0x7fffu;
        if (version > 1 && !module->version_names[version])
            return shared_fail(input, XXEMUL_STATUS_INVALID_IMAGE, "ELF symbol version index has no definition");
    }
    return 1;
}

static int shared_symbols(shared_input *input, const shared_dynamic *dynamic,
    uint64_t section_offset, uint16_t section_count, uint16_t section_entry) {
    xxemul_elf_shared *module = input->module;
    const uint8_t *strings, *symbols, *versions = NULL;
    uint32_t count, i;
    unsigned entry = module->width == 8 ? 24u : 16u;
    if (!dynamic->symbols || !dynamic->strings || !dynamic->string_size ||
        dynamic->string_size > SIZE_MAX || dynamic->symbol_size != entry ||
        !shared_symbol_count(input, dynamic, section_offset, section_count, section_entry, &count))
        return input->result->status ? 0 : shared_fail(input, XXEMUL_STATUS_INVALID_IMAGE, "missing/invalid dynamic symbol metadata");
    strings = shared_raw(input, dynamic->strings, dynamic->string_size);
    symbols = shared_raw(input, dynamic->symbols, (uint64_t)count * entry);
    if (dynamic->versions) versions = shared_raw(input, dynamic->versions, (uint64_t)count * 2);
    if (!strings || !symbols || (dynamic->versions && !versions) || strings[0] || strings[dynamic->string_size - 1])
        return shared_fail(input, XXEMUL_STATUS_INVALID_IMAGE, "invalid dynamic string/symbol/version table extent");
    module->strings = (char *)shared_alloc(input, (size_t)dynamic->string_size, 1);
    module->symbols = (shared_symbol *)shared_alloc(input, count, sizeof(*module->symbols));
    if (!module->strings || !module->symbols) return 0;
    xx_mem_copy(module->strings, strings, (size_t)dynamic->string_size);
    module->string_size = (size_t)dynamic->string_size;
    module->symbol_count = count;
    for (i = 0; i < count; ++i) {
        shared_symbol *symbol = &module->symbols[i];
        const uint8_t *p = symbols + (size_t)i * entry;
        symbol->name = shared_u32(p);
        symbol->value = module->width == 8 ? shared_u64(p + 8) : shared_u32(p + 4);
        symbol->size = module->width == 8 ? shared_u64(p + 16) : shared_u32(p + 8);
        symbol->info = p[module->width == 8 ? 4 : 12];
        symbol->other = p[module->width == 8 ? 5 : 13];
        symbol->section = shared_u16(p + (module->width == 8 ? 6 : 14));
        if (symbol->name >= module->string_size ||
            !memchr(module->strings + symbol->name, 0,
                module->string_size - symbol->name > 4096 ? 4096 : module->string_size - symbol->name))
            return shared_fail(input, XXEMUL_STATUS_INVALID_IMAGE, "dynamic symbol %u has invalid name offset", i);
        symbol->version = versions ? shared_u16(versions + (size_t)i * 2) : 1;
        if ((size_t)(symbol->version & 0x7fffu) + 1 > module->version_count)
            module->version_count = (size_t)(symbol->version & 0x7fffu) + 1;
    }
    if (module->symbols[0].name || module->symbols[0].value || module->symbols[0].size ||
        module->symbols[0].info || module->symbols[0].other || module->symbols[0].section)
        return shared_fail(input, XXEMUL_STATUS_INVALID_IMAGE, "dynamic symbol zero must be the null symbol");
    if (module->version_count < 2) module->version_count = 2;
    module->version_names = (const char **)shared_alloc(input, module->version_count, sizeof(*module->version_names));
    return module->version_names && shared_versions(input, dynamic);
}

static int shared_symbol_address(shared_input *input, uint32_t index, uint64_t *address) {
    xxemul_elf_shared *module = input->module;
    shared_symbol *symbol;
    unsigned type;
    if (index >= module->symbol_count)
        return shared_fail(input, XXEMUL_STATUS_INVALID_IMAGE, "relocation symbol index %u is out of bounds", index);
    if (!index) { *address = 0; return 1; }
    symbol = &module->symbols[index];
    type = symbol->info & 15u;
    if (type == 6 || type == 10 || symbol->section == 0xfff2)
        return shared_fail(input, XXEMUL_STATUS_UNSUPPORTED_IMAGE, "unsupported ELF TLS/IFUNC/common symbol %s", module->strings + symbol->name);
    if (!symbol->section) {
        xxemul_status status;
        if (!symbol->was_resolved) {
            uint64_t resolved = 0;
            int weak = (symbol->info >> 4) == 2;
            if (!module->config.import_resolver)
                return shared_fail(input, XXEMUL_STATUS_UNSUPPORTED_IMAGE, "unresolved ELF import: %s", module->strings + symbol->name);
            status = module->config.import_resolver(module->config.import_context,
                module->emulator, &module->info, module->strings + symbol->name,
                (symbol->version & 0x7fffu) > 1 ? module->version_names[symbol->version & 0x7fffu] : NULL,
                weak, &resolved);
            if (status != XXEMUL_STATUS_OK)
                return shared_fail(input, status, "ELF import resolver rejected %s (status %u)", module->strings + symbol->name, (unsigned)status);
            if ((!resolved && !weak) || (module->width == 4 && resolved > UINT32_MAX))
                return shared_fail(input, XXEMUL_STATUS_ADDRESS_FAULT, "invalid guest address for ELF import %s", module->strings + symbol->name);
            symbol->resolved = resolved;
            symbol->was_resolved = 1;
            ++input->result->imports;
        }
        *address = symbol->resolved;
    } else if (symbol->section == 0xfff1) *address = symbol->value;
    else {
        if (symbol->section >= 0xff00 || symbol->value > UINT64_MAX - module->info.load_bias ||
            !shared_mapped(module, module->info.machine == 40 ? symbol->value & ~UINT64_C(1) : symbol->value, 1, 0))
            return shared_fail(input, XXEMUL_STATUS_INVALID_IMAGE, "defined ELF symbol is outside PT_LOAD: %s", module->strings + symbol->name);
        *address = module->info.load_bias + symbol->value;
    }
    return 1;
}

static int shared_relocate_one(shared_input *input, const uint8_t *p, int rela) {
    xxemul_elf_shared *module = input->module;
    uint64_t offset = shared_word(p, module->width), info = shared_word(p + module->width, module->width);
    uint32_t type = module->width == 8 ? (uint32_t)info : (uint32_t)(info & 255u);
    uint32_t symbol = module->width == 8 ? (uint32_t)(info >> 32) : (uint32_t)(info >> 8);
    uint64_t addend, value = 0, address = 0, place, thumb = 0;
    uint8_t *target;
    unsigned width = module->width;
    int operation = 0, check = 0; /* 1 relative, 2 S+A, 3 S, 4 S+A-P */
    if (!type || (module->info.machine == 183 && type == 256)) return 1;
    switch (module->info.machine) {
    case 62:
        switch (type) {
        case 1: operation = 2; break;
        case 2: width = 4; operation = 4; check = 2; break;
        case 6: case 7: operation = 3; break;
        case 8: operation = 1; break;
        case 10: width = 4; operation = 2; check = 1; break;
        case 11: width = 4; operation = 2; check = 2; break;
        default: break;
        }
        break;
    case 3:
        switch (type) {
        case 1: operation = 2; break;
        case 2: operation = 4; break;
        case 6: case 7: operation = 3; break;
        case 8: operation = 1; break;
        default: break;
        }
        break;
    case 40:
        switch (type) {
        case 2: operation = 2; break;
        case 3: operation = 4; break;
        case 21: case 22: operation = 2; break;
        case 23: operation = 1; break;
        default: break;
        }
        break;
    case 183:
        switch (type) {
        case 257: operation = 2; break;
        case 258: width = 4; operation = 2; check = 3; break;
        case 260: operation = 4; break;
        case 261: width = 4; operation = 4; check = 2; break;
        case 1025: case 1026: operation = 2; break;
        case 1027: operation = 1; break;
        default: break;
        }
        break;
    default: break;
    }
    if (!operation)
        return shared_fail(input, XXEMUL_STATUS_UNSUPPORTED_IMAGE, "unsupported ELF relocation %u for machine %u", type, module->info.machine);
    target = shared_mapped(module, offset, width, 0);
    if (!target || offset > UINT64_MAX - module->info.load_bias || (operation == 1 && symbol))
        return shared_fail(input, XXEMUL_STATUS_INVALID_IMAGE, "invalid ELF relocation target/symbol at 0x%llx", (unsigned long long)offset);
    if ((module->info.machine == 40 && type >= 21 && type <= 23 && (offset & 3u)) ||
        (module->info.machine == 183 && type >= 1025 && type <= 1027 && (offset & 7u)))
        return shared_fail(input, XXEMUL_STATUS_INVALID_IMAGE, "unaligned ELF dynamic relocation target");
    if (rela) addend = shared_word(p + module->width * 2u, module->width);
    else {
        addend = shared_word(target, width);
        if (module->width == 8 && width == 4 && (addend & UINT64_C(0x80000000))) addend |= UINT64_C(0xffffffff00000000);
    }
    /* AAELF32: a REL JUMP_SLOT always has A=0. Its initial GOT word is a
     * lazy-binding trampoline, not an implicit addend. */
    if (module->info.machine == 40 && type == 22 && !rela) addend = 0;
    place = module->info.load_bias + offset;
    if (operation != 1 && !shared_symbol_address(input, symbol, &address)) return 0;
    if (module->info.machine == 40 && symbol < module->symbol_count &&
        (module->symbols[symbol].info & 15u) == 2) {
        thumb = address & 1u;
        address &= ~UINT64_C(1);
    }
    switch (operation) {
    case 1: value = module->info.load_bias + addend; break;
    case 2: value = (address + addend) | thumb; break;
    case 3: value = address; break;
    case 4: value = ((address + addend) | thumb) - place; break;
    default: break;
    }
    if ((check == 1 && value > UINT32_MAX) ||
        (check == 2 && value != (uint64_t)(int64_t)(int32_t)(uint32_t)value) ||
        (check == 3 && value > UINT32_MAX && value < UINT64_C(0xffffffff80000000)))
        return shared_fail(input, XXEMUL_STATUS_INVALID_IMAGE, "ELF relocation %u overflows its 32-bit result", type);
    shared_store(target, value, width);
    return 1;
}

static int shared_relocation_table(shared_input *input, uint64_t address,
    uint64_t size, uint64_t entry, int rela) {
    uint64_t expected = input->module->width * (rela ? 3u : 2u), i, count;
    const uint8_t *data;
    if (!size) {
        if (entry && entry != expected)
            return shared_fail(input, XXEMUL_STATUS_INVALID_IMAGE, "invalid ELF relocation entry size");
        return 1;
    }
    if (!address || entry != expected || size % expected || !(data = shared_raw(input, address, size)))
        return shared_fail(input, XXEMUL_STATUS_INVALID_IMAGE, "invalid ELF %s relocation table", rela ? "RELA" : "REL");
    count = size / expected;
    if (count > input->module->config.max_relocations - input->result->relocations)
        return shared_fail(input, XXEMUL_STATUS_LIMIT_REACHED, "ELF relocation count limit reached");
    for (i = 0; i < count; ++i) {
        if (!shared_relocate_one(input, data + (size_t)(i * expected), rela)) return 0;
        ++input->result->relocations;
    }
    return 1;
}

static int shared_initializers(shared_input *input, const shared_dynamic *dynamic) {
    xxemul_elf_shared *module = input->module;
    uint64_t count = dynamic->init_array_size / module->width, i;
    uint8_t *array = NULL;
    if (dynamic->init_array_size % module->width || count >= ELF_SHARED_MAX_INITIALIZERS ||
        (dynamic->init_array_size && (!dynamic->init_array ||
         !(array = shared_mapped(module, dynamic->init_array, dynamic->init_array_size, 0)))))
        return shared_fail(input, XXEMUL_STATUS_INVALID_IMAGE, "invalid/bounded DT_INIT_ARRAY");
    if (!count && !dynamic->init) return 1;
    module->initializers = (uint64_t *)shared_alloc(input, (size_t)count + (dynamic->init ? 1u : 0u), sizeof(uint64_t));
    if (!module->initializers) return 0;
    if (dynamic->init) {
        uint64_t code = module->info.machine == 40 ? dynamic->init & ~UINT64_C(1) : dynamic->init;
        if (!shared_mapped(module, code, 1, 1) || dynamic->init > UINT64_MAX - module->info.load_bias)
            return shared_fail(input, XXEMUL_STATUS_INVALID_IMAGE, "DT_INIT is outside executable PT_LOAD");
        module->initializers[module->initializer_count++] = module->info.load_bias + dynamic->init;
    }
    for (i = 0; i < count; ++i) {
        uint64_t address = shared_word(array + (size_t)i * module->width, module->width);
        uint64_t code = module->info.machine == 40 ? address & ~UINT64_C(1) : address;
        if (!address || address == (module->width == 8 ? UINT64_MAX : UINT32_MAX)) continue;
        if (code < module->info.load_bias || !shared_mapped(module, code - module->info.load_bias, 1, 1))
            return shared_fail(input, XXEMUL_STATUS_INVALID_IMAGE, "DT_INIT_ARRAY entry is outside executable PT_LOAD");
        module->initializers[module->initializer_count++] = address;
    }
    return 1;
}

xxemul_elf_shared *xxemul_elf_shared_create(const void *image, size_t image_size,
    const xxemul_elf_shared_config *config, xxemul_elf_result *result) {
    xxemul_elf_result local_result;
    xxemul_elf_shared *module;
    shared_input input;
    shared_dynamic dynamic;
    uint64_t dynamic_address = 0, dynamic_size = 0, section_offset = 0;
    uint16_t section_count = 0, section_entry = 0;
    if (!result) result = &local_result;
    xx_mem_zero(result, sizeof(*result));
    result->status = XXEMUL_STATUS_INVALID_ARGUMENT;
    if (!image || !image_size) {
        (void)snprintf(result->diagnostic, sizeof(result->diagnostic), "invalid ELF image argument");
        return NULL;
    }
    module = (xxemul_elf_shared *)xx_mem_calloc(1, sizeof(*module));
    if (!module) {
        result->status = XXEMUL_STATUS_OUT_OF_MEMORY;
        (void)snprintf(result->diagnostic, sizeof(result->diagnostic), "ELF module allocation failed");
        return NULL;
    }
    if (config) module->config = *config;
    if (!module->config.load_bias) module->config.load_bias = UINT64_C(0x10000000);
    if (!module->config.max_memory_bytes) module->config.max_memory_bytes = 64u * 1024u * 1024u;
    if (!module->config.stack_bytes) module->config.stack_bytes = 1024u * 1024u;
    if (!module->config.auxiliary_bytes) module->config.auxiliary_bytes = 1024u * 1024u;
    if (!module->config.max_symbols) module->config.max_symbols = 65536;
    if (!module->config.max_relocations) module->config.max_relocations = 1048576;
    module->info.load_bias = module->config.load_bias;
    module->allocated = sizeof(*module) + sizeof(xxemul);
    input.data = (const uint8_t *)image; input.size = image_size;
    input.module = module; input.result = result;
    xx_mem_zero(&dynamic, sizeof(dynamic));
    result->status = XXEMUL_STATUS_OK;
    if (module->allocated > module->config.max_memory_bytes || image_size > module->config.max_memory_bytes) {
        shared_fail(&input, XXEMUL_STATUS_LIMIT_REACHED, "ELF input/metadata exceeds memory budget");
        goto failed;
    }
    if (!shared_headers(&input, &dynamic_address, &dynamic_size,
            &section_offset, &section_count, &section_entry) ||
        !shared_dynamic_info(&input, dynamic_address, dynamic_size, &dynamic) ||
        !shared_symbols(&input, &dynamic, section_offset, section_count, section_entry)) goto failed;
    if (dynamic.jump_size && dynamic.jump_kind != 7 && dynamic.jump_kind != 17) {
        shared_fail(&input, XXEMUL_STATUS_INVALID_IMAGE, "invalid DT_PLTREL kind"); goto failed;
    }
    /* Do not apply an overlapping table twice: REL implicit addends change. */
    if ((dynamic.rel_size && dynamic.rela_size && dynamic.rel < dynamic.rela + dynamic.rela_size && dynamic.rela < dynamic.rel + dynamic.rel_size) ||
        (dynamic.jump_size && dynamic.rel_size && dynamic.jump_rel < dynamic.rel + dynamic.rel_size && dynamic.rel < dynamic.jump_rel + dynamic.jump_size) ||
        (dynamic.jump_size && dynamic.rela_size && dynamic.jump_rel < dynamic.rela + dynamic.rela_size && dynamic.rela < dynamic.jump_rel + dynamic.jump_size)) {
        shared_fail(&input, XXEMUL_STATUS_UNSUPPORTED_IMAGE, "overlapping ELF relocation tables"); goto failed;
    }
    if (!shared_relocation_table(&input, dynamic.rel, dynamic.rel_size, dynamic.rel_entry, 0) ||
        !shared_relocation_table(&input, dynamic.rela, dynamic.rela_size, dynamic.rela_entry, 1) ||
        !shared_relocation_table(&input, dynamic.jump_rel, dynamic.jump_size,
            module->width * (dynamic.jump_kind == 7 ? 3u : 2u), dynamic.jump_kind == 7) ||
        !shared_initializers(&input, &dynamic)) goto failed;
    (void)snprintf(result->diagnostic, sizeof(result->diagnostic), "shared ELF loaded and relocated; constructors not executed");
    return module;
failed:
    xxemul_elf_shared_destroy(module);
    return NULL;
}

void xxemul_elf_shared_destroy(xxemul_elf_shared *module) {
    if (!module) return;
    xxemul_destroy(module->emulator);
    xx_mem_free(module->symbols);
    xx_mem_free(module->strings);
    xx_mem_free(module->version_names);
    xx_mem_free(module->initializers);
    xx_mem_free(module);
}
xxemul *xxemul_elf_shared_emulator(xxemul_elf_shared *module) {
    return module ? module->emulator : NULL;
}
const xxemul_elf_shared_info *xxemul_elf_shared_get_info(const xxemul_elf_shared *module) {
    return module ? &module->info : NULL;
}
xxemul_status xxemul_elf_shared_find_export(const xxemul_elf_shared *module,
    const char *name, uint64_t *address) {
    uint32_t i;
    if (address) *address = 0;
    if (!module || !name || !*name || !address) return XXEMUL_STATUS_INVALID_ARGUMENT;
    for (i = 1; i < module->symbol_count; ++i) {
        const shared_symbol *symbol = &module->symbols[i];
        unsigned binding = symbol->info >> 4, visibility = symbol->other & 3u;
        if (!symbol->section || (binding != 1 && binding != 2) || visibility == 1 || visibility == 2 ||
            !(symbol->version & 0x7fffu) || (symbol->version & 0x8000u) ||
            strcmp(module->strings + symbol->name, name)) continue;
        if ((symbol->info & 15u) == 6 || (symbol->info & 15u) == 10 ||
            symbol->section == 0xfff2) return XXEMUL_STATUS_UNSUPPORTED_IMAGE;
        if (symbol->section == 0xfff1) { *address = symbol->value; return XXEMUL_STATUS_OK; }
        if (symbol->section >= 0xff00 || symbol->value > UINT64_MAX - module->info.load_bias ||
            !shared_mapped((xxemul_elf_shared *)module,
                module->info.machine == 40 ? symbol->value & ~UINT64_C(1) : symbol->value, 1, 0))
            return XXEMUL_STATUS_INVALID_IMAGE;
        *address = module->info.load_bias + symbol->value;
        return XXEMUL_STATUS_OK;
    }
    return XXEMUL_STATUS_ADDRESS_FAULT;
}
size_t xxemul_elf_shared_initializer_count(const xxemul_elf_shared *module) {
    return module ? module->initializer_count : 0;
}
xxemul_status xxemul_elf_shared_initializer_at(const xxemul_elf_shared *module,
    size_t index, uint64_t *address) {
    if (address) *address = 0;
    if (!module || !address) return XXEMUL_STATUS_INVALID_ARGUMENT;
    if (index >= module->initializer_count) return XXEMUL_STATUS_ADDRESS_FAULT;
    *address = module->initializers[index];
    return XXEMUL_STATUS_OK;
}
