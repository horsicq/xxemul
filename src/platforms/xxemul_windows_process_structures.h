#ifndef XXEMUL_WINDOWS_PROCESS_STRUCTURES_H
#define XXEMUL_WINDOWS_PROCESS_STRUCTURES_H

#include "xxemul_windows_unwind64.h"

typedef int (*xxemul_windows_process_write)(void *context, uint64_t address,
                                           const void *bytes, size_t size);
typedef struct xxemul_windows_process_memory {
    xxemul_windows_unwind64_read read;
    xxemul_windows_process_write write;
    void *context;
} xxemul_windows_process_memory;

typedef struct xxemul_windows_process_layout {
    unsigned pointer_size, peb_size, teb_size, parameters_size;
    unsigned tib_self, tib_stack_base, tib_stack_limit, client_id, static_tls, peb_pointer;
    unsigned last_error, last_status, tls_slots, tls_expansion, deallocation_stack;
    unsigned image_base, loader, parameters, process_heap, fast_peb_lock, loader_lock;
    unsigned tls_bitmap, tls_bitmap_bits, tls_expansion_bitmap, tls_expansion_bitmap_bits;
    unsigned number_of_heaps, maximum_number_of_heaps, process_heaps, global_flags;
    unsigned os_major, os_minor, os_build, os_platform, session_id;
    unsigned heap_flags, heap_force_flags;
} xxemul_windows_process_layout;

/* Windows 10 / NT6+ compatible pointer-width layout. These are declared guest
 * model fields, not a promise of undocumented fields for every OS release. */
const xxemul_windows_process_layout *xxemul_windows_process_get_layout(int is64);

typedef struct xxemul_windows_unicode_value {
    uint64_t address;
    uint16_t length, maximum_length; /* UTF-16 bytes, excludes/includes NUL. */
} xxemul_windows_unicode_value;

typedef struct xxemul_windows_process_description {
    int is64;
    uint64_t peb, loader, parameters, image_base;
    uint64_t heap, heap_list, heap_start, heap_limit;
    uint64_t fast_peb_lock, loader_lock;
    uint64_t tls_bitmap, tls_expansion_bitmap;
    uint64_t environment, environment_bytes;
    uint64_t standard_input, standard_output, standard_error, console_handle;
    xxemul_windows_unicode_value image_path, command_line, current_directory, dll_path;
    const uint64_t *heaps;
    uint32_t heap_count, heap_capacity, tls_capacity;
    uint32_t major_version, minor_version, build_number, platform_id, session_id;
    uint32_t processor_count, subsystem, subsystem_major, subsystem_minor;
    uint64_t affinity_mask;
    uint32_t heap_flags, heap_force_flags;
    unsigned inherited_address_space, being_debugged, loader_initialized;
    unsigned process_initializing, using_vectored_exceptions, using_vectored_continue;
    uint32_t global_flags;
} xxemul_windows_process_description;

typedef struct xxemul_windows_thread_description {
    int is64;
    uint64_t teb, peb, stack_base, stack_limit, deallocation_stack;
    uint64_t exception_list, static_tls, tls_expansion;
    uint64_t process_id, thread_id;
    uint32_t last_error, last_status, locale;
    const uint64_t *tls_values;
    uint32_t tls_count;
} xxemul_windows_thread_description;

/* Initialization writes only declared fields and preserves pre-existing
 * loader lists/Unicode payloads. A reserved TEB is cleared only on creation.
 * Synchronizers never overwrite the guest's exception registration chain. */
xxemul_status xxemul_windows_process_initialize(
    const xxemul_windows_process_memory *memory,
    const xxemul_windows_process_description *description);
xxemul_status xxemul_windows_process_initialize_heap(
    const xxemul_windows_process_memory *memory, int is64, uint64_t heap,
    uint64_t heap_start, uint64_t heap_limit, uint32_t flags, uint32_t force_flags);
xxemul_status xxemul_windows_thread_initialize(
    const xxemul_windows_process_memory *memory,
    const xxemul_windows_thread_description *description);
xxemul_status xxemul_windows_process_update_parameters(
    const xxemul_windows_process_memory *memory,
    const xxemul_windows_process_description *description);
xxemul_status xxemul_windows_process_update_heaps(
    const xxemul_windows_process_memory *memory,
    const xxemul_windows_process_description *description);
xxemul_status xxemul_windows_process_update_tls_bitmap(
    const xxemul_windows_process_memory *memory,
    const xxemul_windows_process_description *description,
    const uint32_t *allocated_bits, uint32_t allocated_dwords);
xxemul_status xxemul_windows_thread_update_tls(
    const xxemul_windows_process_memory *memory,
    const xxemul_windows_thread_description *description);
xxemul_status xxemul_windows_thread_update_errors(
    const xxemul_windows_process_memory *memory, int is64, uint64_t teb,
    uint32_t last_error, uint32_t last_status);
xxemul_status xxemul_windows_process_validate_heap(
    const xxemul_windows_process_memory *memory,
    const xxemul_windows_process_description *description, int *valid);
xxemul_status xxemul_windows_process_update_exception_flags(
    const xxemul_windows_process_memory *memory, int is64, uint64_t peb,
    int initializing, int using_veh, int using_vch);

#endif
