/* Copyright (c) 2026 hors<horsicq@gmail.com>
 * SPDX-License-Identifier: MIT */
#ifndef XXEMUL_XXEMUL_ELF_H
#define XXEMUL_XXEMUL_ELF_H

#include "xxemul.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct xxemul_elf_shared xxemul_elf_shared;

typedef struct xxemul_elf_shared_info {
    uint64_t load_bias;
    uint64_t image_address;
    size_t image_size;
    uint64_t auxiliary_address;
    size_t auxiliary_size;
    uint64_t stack_address;
    size_t stack_size;
    xxemul_arch arch;
    xxemul_mode mode;
    uint16_t machine;
} xxemul_elf_shared_info;

/** Resolve an undefined ELF symbol to an explicit guest address. The CPU and
 * auxiliary arena are available for writing guest thunks/data. A successful
 * zero address is permitted only for weak symbols. Version is NULL for an
 * unversioned import, otherwise its exact ELF version name. No host code runs. */
typedef xxemul_status (*xxemul_elf_import_resolver)(
    void *context, xxemul *emulator, const xxemul_elf_shared_info *info,
    const char *name, const char *version, int is_weak, uint64_t *address);

typedef struct xxemul_elf_shared_config {
    /** Zero selects 0x10000000. Added to ELF virtual addresses. */
    uint64_t load_bias;
    /** Zero selects 64 MiB, including mapped memory and loader metadata. */
    size_t max_memory_bytes;
    /** Zero selects 1 MiB each. Both arenas are rounded to pages. */
    size_t stack_bytes;
    size_t auxiliary_bytes;
    /** Zero selects 65536 symbols and 1048576 relocations. */
    uint32_t max_symbols;
    uint32_t max_relocations;
    xxemul_elf_import_resolver import_resolver;
    void *import_context;
} xxemul_elf_shared_config;

typedef struct xxemul_elf_result {
    xxemul_status status;
    uint32_t relocations;
    uint32_t imports;
    char diagnostic[256];
} xxemul_elf_result;

/** Loads little-endian ET_DYN PT_LOAD segments and BSS, applies supported
 * REL/RELA relocations, and owns its CPU. The input need not outlive this call.
 * Dependencies are supplied through the import resolver, never auto-loaded.
 * TLS, used IFUNC symbols, packed relocations and unknown relocation types
 * fail explicitly. Constructors are only
 * inventoried: the caller must execute them with the guest ABI and a budget. */
XXEMUL_API xxemul_elf_shared *xxemul_elf_shared_create(
    const void *image, size_t image_size,
    const xxemul_elf_shared_config *config, xxemul_elf_result *result);
XXEMUL_API void xxemul_elf_shared_destroy(xxemul_elf_shared *module);
/** Borrowed CPU/info; both remain valid until module destruction. */
XXEMUL_API xxemul *xxemul_elf_shared_emulator(xxemul_elf_shared *module);
XXEMUL_API const xxemul_elf_shared_info *xxemul_elf_shared_get_info(
    const xxemul_elf_shared *module);
/** Looks up a defined visible global/weak dynamic symbol; missing names return
 * ADDRESS_FAULT. Clears address on failure. ARM function addresses retain the
 * Thumb bit. Does not execute the symbol. */
XXEMUL_API xxemul_status xxemul_elf_shared_find_export(
    const xxemul_elf_shared *module, const char *name, uint64_t *address);
/** DT_INIT precedes the relocated DT_INIT_ARRAY, excluding null/-1 entries.
 * Initializer addresses must belong to an executable PT_LOAD segment. */
XXEMUL_API size_t xxemul_elf_shared_initializer_count(
    const xxemul_elf_shared *module);
XXEMUL_API xxemul_status xxemul_elf_shared_initializer_at(
    const xxemul_elf_shared *module, size_t index, uint64_t *address);

#ifdef __cplusplus
}
#endif
#endif
