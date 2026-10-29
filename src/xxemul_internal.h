#ifndef XXEMUL_INTERNAL_H
#define XXEMUL_INTERNAL_H

#include "xxemul/xxemul.h"

#include <cdisasm/cdisasm.h>
#include <cdisasm/cdisasm_format.h>
#include <xxfclib/io/xx_io.h>
#include <xxfclib/memory/xx_memory.h>

#include <stddef.h>
#include <stdint.h>

typedef struct xxemul_windows xxemul_windows;
typedef struct xxemul_linux_process xxemul_linux_process;
typedef struct xxemul_darwin xxemul_darwin;
typedef struct xxemul_elf_shared xxemul_elf_shared;
typedef struct xxemul_x86_decode_cache_entry xxemul_x86_decode_cache_entry;

typedef struct xxemul_x86_segment_cache {
    uint32_t base;
    uint32_t limit;
    uint8_t access;
    uint8_t flags;
    uint8_t valid;
} xxemul_x86_segment_cache;

typedef struct xxemul_dpmi_memory_block {
    uint32_t base;
    uint32_t size;
    uint32_t handle;
} xxemul_dpmi_memory_block;

/* Host-owned DPMI interrupt entries use actual protected code and IDT gates.
 * Keep the descriptor outside the client allocator's ordinary low selectors. */
#define XXEMUL_DPMI_HOST_SELECTOR 0x0ff8u
#define XXEMUL_DPMI_HOST_CODE_BASE 0x0f0000u
#define XXEMUL_DPMI_HOST_VECTOR_BASE 0x0400u
#define XXEMUL_DPMI_IDT_BASE 0x101000u
#define XXEMUL_DPMI_STACK_SELECTOR 0x0ff0u
#define XXEMUL_DPMI_CALLBACK_SLOTS 16u
#define XXEMUL_DPMI_TRANSITIONS 8u

typedef struct xxemul_dpmi_callback {
    uint32_t procedure_offset, packet_offset;
    uint16_t procedure_selector, packet_selector, stack_alias;
    uint8_t active;
} xxemul_dpmi_callback;

typedef struct xxemul_dpmi_transition {
    xxemul_x86_state state;
    xxemul_x86_segment_cache segments[6];
    xxemul_mode mode;
    uint32_t cr0, packet_offset;
    uint16_t packet_selector, real_ss, real_sp;
    uint8_t kind, callback, resume_host, vector, real_port92, real_kbc;
} xxemul_dpmi_transition;

struct xxemul {
    xxemul_arch arch;
    xxemul_mode mode;
    cdisasm_x86_decode_flags x86_decode_flags;
    xxemul_x86_decode_cache_entry *x86_decode_cache;
    uint64_t region_address;
    size_t region_size;
    uint8_t *region_data;
    xxemul_windows *windows;
    xxemul_linux_process *linux_process;
    xxemul_darwin *darwin;
    int halted;
    int dos_mode;
    uint16_t psp_segment;
    uint16_t dos_dta_segment;
    uint16_t dos_dta_offset;
    uint8_t exit_code;
    uint8_t video_mode;
    uint8_t cursor_row;
    uint8_t cursor_column;
    uint8_t text_attribute;
    uint16_t key_queue[32];
    uint8_t key_head;
    uint8_t key_count;
    xxemul_dos_output_callback output_callback;
    void *output_context;
    xxemul_output_callback stream_output;
    void *stream_output_context;
    xxemul_memory_hook memory_hook;
    void *memory_hook_context;
    int in_step;
    int x86_fetching;
    int debug_traps;
    uint64_t fault_address;
    unsigned fault_access;
    int fault_address_valid;
    xxemul_x86_state x86;
    double x87_stack[8];
    uint64_t x87_int_val[8];
    uint8_t x87_is_int[8];
    uint8_t x87_depth;
    uint8_t x87_top;
    uint16_t x87_control;
    uint16_t x87_status;
    xxemul_arm_state arm;
    xxemul_mips_state mips;
    uint32_t mips_branch_target;
    int mips_delay_pending;
    uint32_t mips_reservation;
    int mips_reservation_valid;
    uint8_t dos_port_92;
    uint8_t dos_kbc_output;
    uint8_t dos_kbc_command;
    uint8_t dos_kbc_data;
    uint8_t dos_kbc_data_ready;
    uint8_t dos_pic_master_mask;
    uint8_t dos_pic_slave_mask;
    uint8_t dos_pic_master_stage;
    uint8_t dos_pic_slave_stage;
    uint8_t dos_pic_master_icw4;
    uint8_t dos_pic_slave_icw4;
    uint8_t dos_pic_master_offset;
    uint8_t dos_pic_slave_offset;
    uint8_t dos_vga_retrace;
    uint8_t dos_pit_counter;
    uint32_t dos_timer_instructions;
    uint32_t dos_cr0;
    uint32_t dos_cr2;
    uint32_t dos_pending_page_fault_error;
    uint32_t dos_cr3;
    uint32_t dos_dr[8];
    uint32_t dos_gdtr_base;
    uint32_t dos_idtr_base;
    uint32_t dos_tr_base;
    uint32_t dos_tr_limit;
    uint32_t dos_ldtr_base;
    uint32_t dos_ldtr_limit;
    uint16_t dos_gdtr_limit;
    uint16_t dos_idtr_limit;
    uint16_t dos_tr_selector;
    uint16_t dos_ldtr_selector;
    uint16_t dos_dpmi_next_selector;
    uint32_t dos_dpmi_heap_next;
    uint32_t dos_dpmi_next_memory_handle;
    xxemul_dpmi_memory_block dos_dpmi_memory[128];
    uint16_t dos_dpmi_dos_segment[512];
    uint8_t dos_dpmi_dos_descriptors[512];
    xxemul_x86_segment_cache dos_segments[6];
    uint8_t dos_dpmi_prepared;
    uint8_t dos_dpmi_client32;
    uint8_t dos_irq0_pending;
    uint8_t dos_irq0_in_service;
    uint8_t dos_irq0_shadow;
    uint64_t dos_call_next_ip;
    uint8_t dos_context_transfer;
    xxemul_dpmi_callback dos_dpmi_callbacks[XXEMUL_DPMI_CALLBACK_SLOTS];
    xxemul_dpmi_transition dos_dpmi_transitions[XXEMUL_DPMI_TRANSITIONS];
    uint8_t dos_dpmi_transition_depth;
    uint8_t dos_dpmi_resume_host;
    xxemul_elf_shared *elf_primary;
};

xxemul *xxemul_create_empty(xxemul_arch arch, xxemul_mode mode, uint64_t region_address, size_t region_size, xxemul_status *status);

xxemul *xxemul_image_allocate(xxemul_arch arch, xxemul_mode mode, uint64_t base, uint64_t image_span, uint64_t entry, int unix_stack, xxemul_status *status);
xxemul *xxemul_load_pe(xxemul_image_format format, const uint8_t *image, size_t image_size, xx_io_device *io, uint64_t image_base, xxemul_status *status);
xxemul *xxemul_load_elf(xxemul_image_format format, const uint8_t *image, size_t image_size, xx_io_device *io, uint64_t image_base, xxemul_status *status);
void xxemul_elf_primary_destroy(xxemul *emulator);
xxemul_status xxemul_elf_primary_start(xxemul *emulator);
int xxemul_elf_primary_try_step(xxemul *emulator, xxemul_step_info *info, xxemul_status *status);
xxemul_status xxemul_elf_primary_after_step(xxemul *emulator, xxemul_status status);
const char *xxemul_elf_primary_error(const xxemul *emulator);
xxemul *xxemul_load_macho(xxemul_image_format format, const uint8_t *image, size_t image_size, xx_io_device *io, xxemul_status *status);
int xxemul_load_com(xxemul *emulator, const uint8_t *image, size_t image_size, xx_io_device *io);
int xxemul_load_msdos_exe(xxemul *emulator, const uint8_t *image, size_t image_size, xx_io_device *io);
xxemul *xxemul_create_dos_at(xxemul_dos_format format, const void *image, size_t image_size, uint64_t image_base, xxemul_status *status);

xxemul_status xxemul_msdos_interrupt(xxemul *emulator, uint8_t vector);
xxemul_status xxemul_bios_interrupt(xxemul *emulator, uint8_t vector);
void xxemul_bios_advance_clock(xxemul *emulator);
void xxemul_bios_initialize_timer(xxemul *emulator);
int xxemul_bios_timer_is_default(const xxemul *emulator);
void xxemul_bios_service_timer(xxemul *emulator);
xxemul_status xxemul_dpmi_enter(xxemul *emulator);
xxemul_status xxemul_dpmi_interrupt(xxemul *emulator);
xxemul_status xxemul_dpmi_reflect_interrupt(xxemul *emulator, uint8_t vector);
int xxemul_dpmi_try_transition(xxemul *emulator, xxemul_step_info *info, xxemul_status *status);
int xxemul_dpmi_prepare(xxemul *emulator);
uint32_t xxemul_dos_physical(const xxemul *emulator, uint16_t segment, uint16_t offset);
void xxemul_video_clear(xxemul *emulator);
void xxemul_video_putc(xxemul *emulator, uint8_t character);
/* Deliver guest console bytes to the stream callback; returns 0 when none. */
int xxemul_emit_output(xxemul *emulator, int stream, const void *bytes, size_t size);

uint64_t xxemul_mask_for_size(uint8_t size);
uint64_t xxemul_sign_extend(uint64_t value, uint8_t size);
xxemul_status xxemul_load_integer(xxemul *emulator, uint64_t address, uint8_t size, uint64_t *value);
xxemul_status xxemul_store_integer(xxemul *emulator, uint64_t address, uint8_t size, uint64_t value);

xxemul_status xxemul_x86_step(xxemul *emulator, xxemul_step_info *info);
xxemul_status xxemul_x86_dispatch_pending_page_fault(xxemul *emulator, xxemul_step_info *info, uint64_t fault_ip);
xxemul_status xxemul_x86_dos_dispatch_irq0(xxemul *emulator, xxemul_step_info *info);
size_t xxemul_x86_format_current(xxemul *emulator, char *buffer, size_t buffer_size);

xxemul_status xxemul_arm_step(xxemul *emulator, xxemul_step_info *info);
size_t xxemul_arm_format_current(xxemul *emulator, char *buffer, size_t buffer_size);

xxemul_status xxemul_mips_step(xxemul *emulator, xxemul_step_info *info);
size_t xxemul_mips_format_current(xxemul *emulator, char *buffer, size_t buffer_size);

#endif
