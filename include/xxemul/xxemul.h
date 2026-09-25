#ifndef XXEMUL_XXEMUL_H
#define XXEMUL_XXEMUL_H

#include <stddef.h>
#include <stdint.h>

#if defined(_WIN32) || defined(__CYGWIN__)
#  if defined(XXEMUL_STATIC)
#    define XXEMUL_API
#  elif defined(XXEMUL_BUILDING_LIBRARY)
#    define XXEMUL_API __declspec(dllexport)
#  else
#    define XXEMUL_API __declspec(dllimport)
#  endif
#else
#  define XXEMUL_API
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef struct xxemul xxemul;

typedef uint32_t xxemul_arch;
#define XXEMUL_ARCH_X86 UINT32_C(1)
#define XXEMUL_ARCH_ARM UINT32_C(2)

typedef uint32_t xxemul_mode;
#define XXEMUL_MODE_X86_16 UINT32_C(16)
#define XXEMUL_MODE_X86_32 UINT32_C(32)
#define XXEMUL_MODE_X86_64 UINT32_C(64)
#define XXEMUL_MODE_ARM_A32 UINT32_C(0x101)
#define XXEMUL_MODE_ARM_T32 UINT32_C(0x102)
#define XXEMUL_MODE_ARM_A64 UINT32_C(0x103)

typedef uint32_t xxemul_status;
#define XXEMUL_STATUS_OK UINT32_C(0)
#define XXEMUL_STATUS_HALTED UINT32_C(1)
#define XXEMUL_STATUS_LIMIT_REACHED UINT32_C(2)
#define XXEMUL_STATUS_INVALID_ARGUMENT UINT32_C(3)
#define XXEMUL_STATUS_OUT_OF_MEMORY UINT32_C(4)
#define XXEMUL_STATUS_ADDRESS_FAULT UINT32_C(5)
#define XXEMUL_STATUS_DECODE_ERROR UINT32_C(6)
#define XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION UINT32_C(7)
#define XXEMUL_STATUS_IO_ERROR UINT32_C(8)
#define XXEMUL_STATUS_INVALID_IMAGE UINT32_C(9)
#define XXEMUL_STATUS_INPUT_REQUIRED UINT32_C(10)
#define XXEMUL_STATUS_UNSUPPORTED_IMAGE UINT32_C(11)
/** A guest INT3 executed while debug traps are enabled. IP is already past
 * the trapping instruction, as on hardware. */
#define XXEMUL_STATUS_BREAKPOINT UINT32_C(12)

#define XXEMUL_DISPLAY_WIDTH 640u
#define XXEMUL_DISPLAY_HEIGHT 480u

typedef uint32_t xxemul_dos_format;
#define XXEMUL_DOS_COM UINT32_C(1)
#define XXEMUL_DOS_MZ UINT32_C(2)

typedef uint32_t xxemul_image_format;
#define XXEMUL_IMAGE_COM UINT32_C(1)
#define XXEMUL_IMAGE_MZ UINT32_C(2)
#define XXEMUL_IMAGE_PE32 UINT32_C(3)
#define XXEMUL_IMAGE_PE64 UINT32_C(4)
#define XXEMUL_IMAGE_ELF32 UINT32_C(5)
#define XXEMUL_IMAGE_ELF64 UINT32_C(6)
#define XXEMUL_IMAGE_MACHO32 UINT32_C(7)
#define XXEMUL_IMAGE_MACHO64 UINT32_C(8)

enum {
    XXEMUL_X86_ES = 0,
    XXEMUL_X86_CS,
    XXEMUL_X86_SS,
    XXEMUL_X86_DS,
    XXEMUL_X86_FS,
    XXEMUL_X86_GS,
    XXEMUL_X86_SEGMENT_COUNT
};

enum {
    XXEMUL_X86_RAX = 0,
    XXEMUL_X86_RCX,
    XXEMUL_X86_RDX,
    XXEMUL_X86_RBX,
    XXEMUL_X86_RSP,
    XXEMUL_X86_RBP,
    XXEMUL_X86_RSI,
    XXEMUL_X86_RDI,
    XXEMUL_X86_R8,
    XXEMUL_X86_R9,
    XXEMUL_X86_R10,
    XXEMUL_X86_R11,
    XXEMUL_X86_R12,
    XXEMUL_X86_R13,
    XXEMUL_X86_R14,
    XXEMUL_X86_R15,
    XXEMUL_X86_GPR_COUNT
};

typedef struct xxemul_x86_state {
    uint64_t gpr[XXEMUL_X86_GPR_COUNT];
    uint64_t ip;
    uint64_t flags;
    uint16_t segment[XXEMUL_X86_SEGMENT_COUNT];
    uint8_t xmm[16][16];
} xxemul_x86_state;

#define XXEMUL_ARM_GPR_COUNT 31u

typedef struct xxemul_arm_state {
    uint64_t gpr[XXEMUL_ARM_GPR_COUNT];
    uint64_t sp;
    uint64_t pc;
    uint32_t pstate;
    uint32_t reserved;
} xxemul_arm_state;

/**
 * Configuration for the initial flat-region backend.
 *
 * The emulator owns a zero-filled region_size-byte copy, places code_size
 * bytes at its beginning, starts at entry_address, and initializes the stack
 * pointer to the aligned end of the same region.
 */
typedef struct xxemul_config {
    xxemul_arch arch;
    xxemul_mode mode;
    uint64_t region_address;
    uint64_t entry_address;
    const void *code;
    size_t code_size;
    size_t region_size;
} xxemul_config;

typedef struct xxemul_step_info {
    uint64_t address;
    uint64_t next_address;
    uint32_t size;
    uint32_t instruction_id;
} xxemul_step_info;

/** Receives bytes written through DOS or BIOS teletype output. */
typedef void (*xxemul_dos_output_callback)(void *context, uint8_t byte);

XXEMUL_API xxemul *xxemul_create(
    const xxemul_config *config,
    xxemul_status *status);
/** Loads an explicitly selected executable format into owned memory. */
XXEMUL_API xxemul *xxemul_create_image(
    xxemul_image_format format,
    const void *image,
    size_t image_size,
    xxemul_status *status);
XXEMUL_API xxemul *xxemul_create_image_file(
    xxemul_image_format format,
    const char *path,
    xxemul_status *status);
/** Explicit DOS format; COM has no signature and is never auto-detected. */
XXEMUL_API xxemul *xxemul_create_dos(
    xxemul_dos_format format,
    const void *image,
    size_t image_size,
    xxemul_status *status);
/** Reads a COM or MZ file through xxfclib's file device. */
XXEMUL_API xxemul *xxemul_create_dos_file(
    xxemul_dos_format format,
    const char *path,
    xxemul_status *status);
/** Initialize guest OS services for a loaded PE or ELF image.
 * argv includes argv[0]; host file access is confined to working_directory. */
XXEMUL_API xxemul_status xxemul_start_process(
    xxemul *emulator, xxemul_image_format format,
    const char *program_path, const char *working_directory,
    int argc, const char *const *argv);
/** Set one explicit guest variable after process start. The name must be
 * nonempty and contain no '='; an empty value is allowed. Does not read the
 * host environment. Currently supported only for Windows guests. */
XXEMUL_API xxemul_status xxemul_set_guest_environment(
    xxemul *emulator, const char *name, const char *value);
/** Create a replacement emulator after a Linux memfd exec; caller owns both. */
XXEMUL_API xxemul *xxemul_create_exec_successor(
    xxemul *emulator, xxemul_status *status);
XXEMUL_API int xxemul_process_exit_code(const xxemul *emulator);
XXEMUL_API void xxemul_destroy(xxemul *emulator);

/** Real-mode segment:offset to 20-bit physical address. */
XXEMUL_API uint32_t xxemul_dos_linear(uint16_t segment, uint16_t offset);
XXEMUL_API xxemul_status xxemul_dos_get_exit_code(
    const xxemul *emulator, uint8_t *exit_code);
/** Enqueue an ASCII key for INT 16h; scan code is returned in AH. */
XXEMUL_API xxemul_status xxemul_dos_push_key(
    xxemul *emulator, uint8_t ascii, uint8_t scan_code);
XXEMUL_API xxemul_status xxemul_dos_set_output_callback(
    xxemul *emulator, xxemul_dos_output_callback callback, void *context);
/** Render 0xAARRGGBB pixels into rows of stride_pixels uint32_t values. */
XXEMUL_API xxemul_status xxemul_display_render(
    xxemul *emulator, uint32_t *pixels, size_t stride_pixels);
XXEMUL_API uint8_t xxemul_display_get_mode(const xxemul *emulator);

XXEMUL_API xxemul_arch xxemul_get_arch(const xxemul *emulator);
XXEMUL_API xxemul_mode xxemul_get_mode(const xxemul *emulator);
XXEMUL_API uint64_t xxemul_get_region_address(const xxemul *emulator);
XXEMUL_API size_t xxemul_get_region_size(const xxemul *emulator);

XXEMUL_API xxemul_status xxemul_read_memory(
    xxemul *emulator,
    uint64_t address,
    void *buffer,
    size_t size);
XXEMUL_API xxemul_status xxemul_write_memory(
    xxemul *emulator,
    uint64_t address,
    const void *buffer,
    size_t size);

XXEMUL_API xxemul_status xxemul_get_x86_state(
    const xxemul *emulator,
    xxemul_x86_state *state);
XXEMUL_API xxemul_status xxemul_set_x86_state(
    xxemul *emulator,
    const xxemul_x86_state *state);
XXEMUL_API xxemul_status xxemul_get_arm_state(
    const xxemul *emulator,
    xxemul_arm_state *state);
XXEMUL_API xxemul_status xxemul_set_arm_state(
    xxemul *emulator,
    const xxemul_arm_state *state);

XXEMUL_API xxemul_status xxemul_step(
    xxemul *emulator,
    xxemul_step_info *info);
XXEMUL_API xxemul_status xxemul_run(
    xxemul *emulator,
    uint64_t instruction_limit,
    uint64_t *instructions_executed);

/** Returns the required character count, excluding the terminating NUL. */
XXEMUL_API size_t xxemul_format_current(
    xxemul *emulator,
    char *buffer,
    size_t buffer_size);

XXEMUL_API const char *xxemul_status_string(xxemul_status status);

/* ------------------------------------------------------------------------ */
/*  Debugger support                                                        */
/* ------------------------------------------------------------------------ */

/** Guest stdout/stderr bytes from any platform layer (DOS, Windows, Linux).
 * stream is 1 for stdout and 2 for stderr. When set, it takes precedence over
 * the per-byte DOS output callback and over writing to the host streams. */
typedef void (*xxemul_output_callback)(
    void *context, int stream, const void *bytes, size_t size);

/** Observes guest data accesses made by xxemul_step (instruction fetches
 * and debugger-originated xxemul_read_memory/xxemul_write_memory calls are
 * not reported). is_write is nonzero for stores. */
typedef void (*xxemul_memory_hook)(
    void *context, uint64_t address, size_t size, int is_write);

XXEMUL_API xxemul_status xxemul_set_output_callback(
    xxemul *emulator, xxemul_output_callback callback, void *context);
XXEMUL_API xxemul_status xxemul_set_memory_hook(
    xxemul *emulator, xxemul_memory_hook hook, void *context);
/** When enabled, a guest INT3 (and INT 3 outside DOS) returns
 * XXEMUL_STATUS_BREAKPOINT instead of halting the emulator. */
XXEMUL_API xxemul_status xxemul_set_debug_traps(
    xxemul *emulator, int enabled);
/** Linear address of the next instruction (CS base applied in DOS modes). */
XXEMUL_API xxemul_status xxemul_get_current_address(
    const xxemul *emulator, uint64_t *address);
/** Linear address of segment:offset using the current segment state. */
XXEMUL_API xxemul_status xxemul_x86_linear_address(
    const xxemul *emulator, unsigned segment_index, uint64_t offset,
    uint64_t *address);
XXEMUL_API int xxemul_is_halted(const xxemul *emulator);
/** Name of a synthetic OS entry point (for example a PE import thunk), or
 * NULL. The string is borrowed from the emulator. */
XXEMUL_API const char *xxemul_symbol_name(
    const xxemul *emulator, uint64_t address);

#ifdef __cplusplus
}
#endif

#endif
