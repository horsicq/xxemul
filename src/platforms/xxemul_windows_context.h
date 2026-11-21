#ifndef XXEMUL_WINDOWS_CONTEXT_H
#define XXEMUL_WINDOWS_CONTEXT_H

#include "xxemul/xxemul.h"

#define XXEMUL_WINDOWS_CONTEXT32_SIZE 0x2ccu
#define XXEMUL_WINDOWS_CONTEXT64_SIZE 0x4d0u
#define XXEMUL_WINDOWS_CONTEXT_ARM32_SIZE 0x1a0u
#define XXEMUL_WINDOWS_CONTEXT_ARM64_SIZE 0x390u
#define XXEMUL_WINDOWS_CONTEXT32_ALL UINT32_C(0x1003f)
#define XXEMUL_WINDOWS_CONTEXT64_ALL UINT32_C(0x10001f)
#define XXEMUL_WINDOWS_CONTEXT_ARM32_ALL UINT32_C(0x20000f)
#define XXEMUL_WINDOWS_CONTEXT_ARM64_ALL UINT32_C(0x40000f)

size_t xxemul_windows_context_size(const xxemul *emulator);
uint32_t xxemul_windows_context_all(const xxemul *emulator);
/* Buffers use Windows little-endian CONTEXT layouts. Capture changes only
 * requested groups and ContextFlags, preserving other caller-owned bytes.
 * Restore validates all selected groups before committing any CPU state.
 * XSTATE/AVX extensions are outside the modeled architectural state. */
xxemul_status xxemul_windows_context_validate(const xxemul *emulator,
                                             const uint8_t *bytes, size_t size);
xxemul_status xxemul_windows_context_capture(const xxemul *emulator,
                                            const xxemul_x86_state *override_cpu,
                                            uint8_t *bytes, size_t size,
                                            uint32_t flags);
xxemul_status xxemul_windows_context_capture_arm(const xxemul *emulator,
                                                const xxemul_arm_state *override_cpu,
                                                uint8_t *bytes, size_t size,
                                                uint32_t flags);
xxemul_status xxemul_windows_context_restore(xxemul *emulator,
                                            const uint8_t *bytes, size_t size);
/* FXSAVE-compatible region, used by CONTEXT and native FX instructions. */
xxemul_status xxemul_windows_fxsave(const xxemul *emulator, uint8_t bytes[512]);
xxemul_status xxemul_windows_fxrstor(xxemul *emulator, const uint8_t bytes[512]);
/* Canonical physical bits are shared with MMX. Legacy images retain all
 * eight logical register payloads and full tags; untracked IP/DP/opcode
 * fields remain a fail-closed restriction. Numeric arithmetic separately
 * requires the inherited exactly represented contiguous-stack subset. */
uint16_t xxemul_x87_saved_tags(const xxemul *emulator);
xxemul_status xxemul_x87_prepare_numeric(xxemul *emulator);
void xxemul_x87_commit_numeric(xxemul *emulator);
xxemul_status xxemul_x87_legacy_save(const xxemul *emulator, uint8_t *bytes, size_t size);
xxemul_status xxemul_x87_legacy_restore(xxemul *emulator, const uint8_t *bytes, size_t size);

#endif
