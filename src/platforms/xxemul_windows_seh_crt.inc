/* x86 compiler SEH personalities.  Included after the common OS dispatcher.
 * Independently implemented from the documented CRT personality contract and
 * LLVM's published Windows compiler metadata ABI; no CRT implementation code.
 * All funclets and EH4 cookie checkers execute as ordinary guest instructions.
 */
enum { WIN_CRT_SEARCH, WIN_CRT_FILTER_RESULT, WIN_CRT_LOCAL, WIN_CRT_TRANSFER };

static xxemul_status win_seh_crt_continue(xxemul_windows *process, win_seh_frame *frame);

static int win_seh_crt_address(uint64_t base, int32_t displacement, uint64_t *address)
{
    int64_t value = (int64_t)base + displacement;
    if (value <= 0 || value > UINT32_MAX) return 0;
    *address = (uint64_t)value;
    return 1;
}

static int win_seh_crt_level(const win_seh_crt_state *state, int32_t level)
{
    return level == state->terminal || (level >= 0 && level < 0x1000);
}

static xxemul_status win_seh_crt_disposition(xxemul_windows *process, win_seh_frame *frame, unsigned disposition)
{
    frame->crt.active = 0u;
    frame->call_kind = WIN_SEH_CALL_FRAME;
    process->emulator->x86.gpr[XXEMUL_X86_RAX] = disposition;
    return win_seh_return(process, NULL);
}

/* Start or resume the two actual guest fastcall cookie checks.  EAX is void
 * garbage on their return.  The independent equality check also rejects a
 * corrupted cookie if a malformed checker returns without reporting it. */
static xxemul_status win_seh_crt_cookies(xxemul_windows *process, win_seh_frame *frame, unsigned resume)
{
    win_seh_crt_state *state = &frame->crt;
    state->resume_action = resume;
    if (state->version4) {
        while (state->check_index < 2u) {
            unsigned index = state->check_index++ * 2u;
            uint64_t slot, xor_address, stored, expected;
            xxemul_status status;
            if (!index && state->cookie_offsets[0] == -2) continue;
            if (!win_seh_crt_address(state->frame_pointer, state->cookie_offsets[index], &slot) ||
                !win_seh_crt_address(state->frame_pointer, state->cookie_offsets[index + 1u], &xor_address) ||
                !win_load(process, slot, 4u, &stored) ||
                !win_load(process, state->cookie_address, 4u, &expected)) return XXEMUL_STATUS_ADDRESS_FAULT;
            state->check_value = (uint32_t)stored ^ (uint32_t)xor_address;
            state->cookie_bad = state->check_value != (uint32_t)expected;
            status = win_seh_invoke(process, frame, state->cookie_function, WIN_SEH_CALL_CRT_COOKIE, NULL, 0u);
            if (status == XXEMUL_STATUS_OK) {
                process->emulator->x86.gpr[XXEMUL_X86_RCX] = state->check_value;
                process->emulator->x86.gpr[XXEMUL_X86_RBP] = state->frame_pointer;
                process->emulator->x86.flags &= ~UINT64_C(0x400);
            }
            return status;
        }
    }
    state->action = resume;
    state->check_index = 0u;
    return win_seh_crt_continue(process, frame);
}

static xxemul_status win_seh_crt_entry(xxemul_windows *process, win_seh_crt_state *state,
                                      int32_t *parent, uint64_t *filter, uint64_t *handler)
{
    uint8_t bytes[12];
    uint64_t address;
    if (!win_seh_crt_level(state, state->level) || state->level == state->terminal ||
        ++state->visited > 0x1000u) return XXEMUL_STATUS_INVALID_IMAGE;
    address = state->table + (uint64_t)(uint32_t)state->level * 12u;
    if (address > UINT32_MAX - sizeof(bytes) || !win_read(process, address, bytes, sizeof(bytes)))
        return XXEMUL_STATUS_ADDRESS_FAULT;
    *parent = (int32_t)win_le32(bytes);
    *filter = win_le32(bytes + 4u);
    *handler = win_le32(bytes + 8u);
    if (!win_seh_crt_level(state, *parent) || *parent >= state->level || !*handler)
        return XXEMUL_STATUS_INVALID_IMAGE;
    return XXEMUL_STATUS_OK;
}

static xxemul_status win_seh_crt_transfer(xxemul_windows *process, win_seh_frame *frame)
{
    win_seh_crt_state *state = &frame->crt;
    xxemul *emulator = process->emulator;
    uint64_t saved_sp, stack_low, stack_high;
    xxemul_status status;
    if (!win_load(process, state->registration - 8u, 4u, &saved_sp) ||
        !win_load(process, win_current_teb(process) + 4u, 4u, &stack_high) ||
        !win_load(process, win_current_teb(process) + 8u, 4u, &stack_low)) return XXEMUL_STATUS_ADDRESS_FAULT;
    if (stack_high <= stack_low || saved_sp < stack_low || saved_sp > stack_high - 4u)
        return XXEMUL_STATUS_INVALID_IMAGE;
    if (!win_store(process, state->registration + 12u, 4u, (uint32_t)state->selected_parent) ||
        !win_store(process, win_current_teb(process), 4u, state->registration)) return XXEMUL_STATUS_ADDRESS_FAULT;
    status = xxemul_windows_context_restore(emulator, frame->saved_context, xxemul_windows_context_size(emulator));
    if (status != XXEMUL_STATUS_OK) return status;
    emulator->x86.gpr[XXEMUL_X86_RBP] = state->frame_pointer;
    emulator->x86.gpr[XXEMUL_X86_RSP] = saved_sp;
    emulator->x86.gpr[XXEMUL_X86_RAX] = frame->code;
    emulator->x86.flags &= ~UINT64_C(0x500); /* DF and TF are clear at funclet entry. */
    emulator->x86.ip = state->handler;
    emulator->halted = 0u;
    --process->seh_depth;
    /* Any abandoned nested dispatcher below the selected frame must retire. */
    while (process->seh_depth && saved_sp >= win_seh_saved_sp(process, &process->seh_frames[process->seh_depth - 1u]))
        --process->seh_depth;
    return XXEMUL_STATUS_OK;
}

static xxemul_status win_seh_crt_continue(xxemul_windows *process, win_seh_frame *frame)
{
    win_seh_crt_state *state = &frame->crt;
    int32_t parent;
    uint64_t filter, handler;
    xxemul_status status;
    if (state->action == WIN_CRT_TRANSFER) return win_seh_crt_transfer(process, frame);
    if (state->action == WIN_CRT_FILTER_RESULT) {
        if (state->filter_result < 0) return win_seh_crt_disposition(process, frame, 0u);
        if (state->filter_result > 0) {
            frame->crt_target = *state;
            frame->crt_target.transferring = 1u;
            frame->target_frame = state->registration;
            frame->target_ip = state->handler;
            frame->kind = WIN_SEH_UNWIND;
            frame->phase = WIN_SEH_FRAMES;
            frame->flags |= 2u;
            frame->registration = frame->original_registration;
            frame->searched = 0u;
            state->active = 0u;
            frame->call_kind = WIN_SEH_CALL_NONE;
            if (!win_store(process, win_current_teb(process), 4u, frame->registration)) return XXEMUL_STATUS_ADDRESS_FAULT;
            return win_seh_next(process, frame);
        }
        state->level = state->selected_parent;
        state->action = WIN_CRT_SEARCH;
    }
    for (;;) {
        if (state->action == WIN_CRT_LOCAL && state->level == state->goal) {
            if (state->transferring) return win_seh_crt_cookies(process, frame, WIN_CRT_TRANSFER);
            return win_seh_crt_disposition(process, frame, 1u);
        }
        if (state->level == state->terminal) {
            if (state->action == WIN_CRT_LOCAL && state->goal != state->terminal) return XXEMUL_STATUS_INVALID_IMAGE;
            return win_seh_crt_disposition(process, frame, 1u);
        }
        status = win_seh_crt_entry(process, state, &parent, &filter, &handler);
        if (status != XXEMUL_STATUS_OK) return status;
        if (state->action == WIN_CRT_LOCAL) {
            state->level = parent;
            if (!win_store(process, state->registration + 12u, 4u, (uint32_t)parent)) return XXEMUL_STATUS_ADDRESS_FAULT;
            if (filter) continue;
            status = win_seh_invoke(process, frame, handler, WIN_SEH_CALL_CRT_FINALLY, NULL, 0u);
        } else {
            if (!filter) { state->level = parent; continue; }
            state->selected_level = state->level;
            state->selected_parent = parent;
            state->handler = handler;
            status = win_seh_invoke(process, frame, filter, WIN_SEH_CALL_CRT_FILTER, NULL, 0u);
        }
        if (status == XXEMUL_STATUS_OK) {
            process->emulator->x86.gpr[XXEMUL_X86_RBP] = state->frame_pointer;
            process->emulator->x86.flags &= ~UINT64_C(0x400);
        }
        return status;
    }
}

static int win_seh_crt_return(xxemul_windows *process, win_seh_frame *frame,
                              uint32_t result, xxemul_status *status)
{
    win_seh_crt_state *state = &frame->crt;
    if (frame->call_kind != WIN_SEH_CALL_CRT_COOKIE && frame->call_kind != WIN_SEH_CALL_CRT_FILTER &&
        frame->call_kind != WIN_SEH_CALL_CRT_FINALLY) return 0;
    if (!state->active) { *status = XXEMUL_STATUS_INVALID_IMAGE; return 1; }
    if (frame->call_kind == WIN_SEH_CALL_CRT_COOKIE) {
        if (state->cookie_bad) *status = win_seh_terminate(process, 0xc0000409u);
        else *status = win_seh_crt_cookies(process, frame, state->resume_action);
    } else if (frame->call_kind == WIN_SEH_CALL_CRT_FILTER) {
        state->filter_result = (int32_t)result;
        *status = win_seh_crt_cookies(process, frame, WIN_CRT_FILTER_RESULT);
    } else *status = win_seh_crt_cookies(process, frame, WIN_CRT_LOCAL);
    return 1;
}

static int win_seh_crt_finish_target(xxemul_windows *process, win_seh_frame *frame, xxemul_status *status)
{
    uint64_t level;
    if (!frame->crt_target.active || !frame->crt_target.transferring) return 0;
    frame->crt = frame->crt_target;
    frame->crt_target.active = 0u;
    if (!win_load(process, frame->crt.registration + 12u, 4u, &level)) { *status = XXEMUL_STATUS_ADDRESS_FAULT; return 1; }
    frame->crt.level = (int32_t)level;
    frame->crt.goal = frame->crt.selected_level;
    frame->crt.visited = 0u;
    frame->crt.check_index = 0u;
    /* The target registration remains linked while its local cleanups run.
     * Retain the same nested-dispatch guard used around ordinary OS handlers,
     * so an exception in a finally does not reenter an already exited scope. */
    if (!win_store(process, frame->dispatcher, 4u, frame->crt.registration) ||
        !win_store(process, frame->dispatcher + 4u, 4u, process->runtime_base + WIN_SEH_NESTED_OFFSET) ||
        !win_store(process, frame->dispatcher + 8u, 4u, frame->crt.registration) ||
        !win_store(process, win_current_teb(process), 4u, frame->dispatcher)) {
        *status = XXEMUL_STATUS_ADDRESS_FAULT; return 1;
    }
    *status = win_seh_crt_cookies(process, frame, WIN_CRT_LOCAL);
    return 1;
}

static int win_seh_crt_api(xxemul_windows *process, const char *name,
                           const uint64_t *arguments, xxemul_status *status)
{
    win_seh_frame *frame;
    win_seh_crt_state *state;
    uint64_t table, level, low, high;
    unsigned first, index;
    int version4 = win_equal(name, "_except_handler4_common");
    if (!win_equal(name, "_except_handler3") && !version4) return 0;
    if (process->emulator->arch != XXEMUL_ARCH_X86 || win_word_size(process->emulator) != 4u || !process->seh_depth) {
        *status = XXEMUL_STATUS_UNSUPPORTED_IMAGE; return 1;
    }
    frame = &process->seh_frames[process->seh_depth - 1u];
    first = version4 ? 2u : 0u;
    if (frame->call_kind != WIN_SEH_CALL_FRAME || arguments[first] != frame->record ||
        arguments[first + 1u] != frame->registration || arguments[first + 2u] != frame->context) {
        *status = XXEMUL_STATUS_INVALID_ARGUMENT; return 1;
    }
    state = &frame->crt;
    memset(state, 0, sizeof(*state));
    state->registration = frame->registration;
    if (!win_load(process, win_current_teb(process) + 4u, 4u, &high) ||
        !win_load(process, win_current_teb(process) + 8u, 4u, &low) ||
        state->registration < low + 8u || high < 16u || state->registration > high - 16u ||
        !win_load(process, state->registration + 8u, 4u, &table) ||
        !win_load(process, state->registration + 12u, 4u, &level)) {
        *status = XXEMUL_STATUS_ADDRESS_FAULT; return 1;
    }
    state->frame_pointer = state->registration + 16u;
    state->record = arguments[first];
    state->context = arguments[first + 2u];
    state->version4 = (uint8_t)version4;
    state->terminal = version4 ? -2 : -1;
    state->goal = state->terminal;
    state->level = (int32_t)level;
    if (!win_seh_crt_level(state, state->level)) { *status = XXEMUL_STATUS_INVALID_IMAGE; return 1; }
    if (version4) {
        uint64_t cookie;
        uint8_t header[16];
        state->cookie_address = arguments[0];
        state->cookie_function = arguments[1];
        if (!state->cookie_function || !win_load(process, state->cookie_address, 4u, &cookie)) {
            *status = XXEMUL_STATUS_ADDRESS_FAULT; return 1;
        }
        state->cookie = (uint32_t)cookie;
        table ^= cookie;
        if (table > UINT32_MAX - 16u || !win_read(process, table, header, sizeof(header))) {
            *status = XXEMUL_STATUS_ADDRESS_FAULT; return 1;
        }
        for (index = 0; index < 4u; ++index) state->cookie_offsets[index] = (int32_t)win_le32(header + index * 4u);
        table += 16u;
    }
    state->table = table;
    state->active = 1u;
    if (!win_store(process, frame->pointers, 4u, state->record) ||
        !win_store(process, frame->pointers + 4u, 4u, state->context) ||
        !win_store(process, state->registration - 4u, 4u, frame->pointers)) {
        *status = XXEMUL_STATUS_ADDRESS_FAULT; return 1;
    }
    *status = win_seh_crt_cookies(process, frame, frame->kind == WIN_SEH_UNWIND ? WIN_CRT_LOCAL : WIN_CRT_SEARCH);
    return 1;
}
