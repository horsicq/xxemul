/* Copyright (c) 2026 hors<horsicq@gmail.com> */

#ifndef XXEMUL_WINDOWS_SEH_CRT_H
#define XXEMUL_WINDOWS_SEH_CRT_H

#include <stdint.h>

/* Internal asynchronous x86 compiler-SEH state.  The OS registration is the
 * Next/Handler pair, not the private two DWORDs preceding that pair. */
typedef struct win_seh_crt_state {
    uint64_t registration, frame_pointer, table, record, context;
    uint64_t cookie_address, cookie_function, handler;
    uint32_t cookie, check_value;
    int32_t cookie_offsets[4];
    int32_t level, terminal, goal, selected_level, selected_parent, filter_result;
    unsigned action, resume_action, check_index, visited;
    uint8_t active, version4, cookie_bad, transferring;
} win_seh_crt_state;

#define WIN_SEH_CALL_CRT_COOKIE 16u
#define WIN_SEH_CALL_CRT_FILTER 17u
#define WIN_SEH_CALL_CRT_FINALLY 18u

#endif
