/* Ordinary-thread FLS profile: independent indices and actual guest callbacks.
 * Explicit fibers and undocumented FlsGetValue2 remain unsupported. No guest
 * callback runs on abrupt termination or host emulator destruction. */
static xxemul_status win_fls_continue(xxemul_windows *, int, xxemul_step_info *);

static win_fls_frame *win_fls_current(xxemul_windows *process)
{
    win_thread_context *thread = &process->threads[process->thread_current];
    win_fls_frame *frame;
    if (!thread->fls_top || thread->fls_top > WIN_FLS_FRAMES) return NULL;
    frame = &process->fls_frames[thread->fls_top - 1u];
    return frame->active && frame->owner_id == thread->id ? frame : NULL;
}

static int win_fls_exit_name(const char *name)
{
    return !strcmp(name, "ExitProcess") || !strcmp(name, "ExitThread") ||
           !strcmp(name, "exit") || !strcmp(name, "_exit") ||
           !strcmp(name, "TerminateProcess") || !strcmp(name, "TerminateThread");
}

static int win_fls_api_name(const char *name)
{
    return !strcmp(name, "FlsAlloc") || !strcmp(name, "FlsFree") ||
           !strcmp(name, "FlsGetValue") || !strcmp(name, "FlsSetValue");
}

static int win_fls_unsupported_name(const char *name)
{
    return !strcmp(name, "FlsGetValue2") || !strcmp(name, "CreateFiber") ||
           !strcmp(name, "CreateFiberEx") || !strcmp(name, "DeleteFiber") ||
           !strcmp(name, "SwitchToFiber") || !strcmp(name, "ConvertThreadToFiber") ||
           !strcmp(name, "ConvertThreadToFiberEx") || !strcmp(name, "ConvertFiberToThread");
}

static win_fls_frame *win_fls_new_frame(xxemul_windows *process, unsigned kind)
{
    win_thread_context *thread = &process->threads[process->thread_current];
    win_fls_frame *frame;
    unsigned index;
    for (index = 0u; index < WIN_FLS_FRAMES && process->fls_frames[index].active; ++index) {}
    if (index == WIN_FLS_FRAMES) return NULL;
    frame = &process->fls_frames[index];
    memset(frame, 0, sizeof(*frame));
    frame->active = 1u;
    frame->kind = (uint8_t)kind;
    frame->owner_id = thread->id;
    frame->previous = thread->fls_top;
    thread->fls_top = (uint8_t)(index + 1u);
    return frame;
}

static int win_fls_has_values(const xxemul_windows *process)
{
    const win_thread_context *thread = &process->threads[process->thread_current];
    unsigned index;
    if (thread->fls_cleanup_done) return 0;
    for (index = 1u; index < WIN_FLS_SLOTS; ++index)
        if (thread->fls_values[index]) return 1;
    return 0;
}

static void win_fls_abandon_thread(xxemul_windows *process, size_t slot)
{
    win_thread_context *thread = &process->threads[slot];
    unsigned index;
    /* Abrupt death drops owned metadata without manufacturing guest cleanup. */
    for (index = 0u; index < WIN_FLS_FRAMES; ++index) {
        win_fls_frame *frame = &process->fls_frames[index];
        if (!frame->active || frame->owner_id != thread->id) continue;
        if (frame->kind == WIN_FLS_FREE && frame->slot < WIN_FLS_SLOTS) {
            win_fls_slot *entry = &process->fls_slots[frame->slot];
            if (entry->generation == frame->generation && entry->retiring) {
                entry->allocated = entry->retiring = 0u;
                entry->callback = 0u;
            }
        }
        if (process->fls_pending == index + 1u) process->fls_pending = 0u;
        memset(frame, 0, sizeof(*frame));
    }
    memset(thread->fls_values, 0, sizeof(thread->fls_values));
    thread->fls_top = 0u;
    thread->fls_cleanup_done = 1u;
}

static xxemul_status win_fls_api(xxemul_windows *process, const char *name,
                                const uint64_t *arguments, uint64_t *result)
{
    win_thread_context *thread = &process->threads[process->thread_current];
    uint8_t width = win_word_size(process->emulator);
    uint32_t index = (uint32_t)arguments[0];
    win_fls_slot *entry;
    unsigned owner;
    *result = 0u;
    if (process->emulator->arch != XXEMUL_ARCH_X86) return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    if (!strcmp(name, "FlsAlloc")) {
        for (index = 1u; index < WIN_FLS_SLOTS; ++index)
            if (!process->fls_slots[index].allocated && process->fls_slots[index].generation != UINT64_MAX) break;
        if (index == WIN_FLS_SLOTS) {
            process->last_error = 8u;
            *result = UINT32_MAX;
            return XXEMUL_STATUS_OK;
        }
        entry = &process->fls_slots[index];
        ++entry->generation;
        entry->callback = width == 4u ? (uint32_t)arguments[0] : arguments[0];
        entry->allocated = 1u;
        entry->retiring = 0u;
        for (owner = 0u; owner < WIN_MAX_THREADS; ++owner) process->threads[owner].fls_values[index] = 0u;
        *result = index;
        return XXEMUL_STATUS_OK;
    }
    if (!index || index >= WIN_FLS_SLOTS || !process->fls_slots[index].allocated) {
        process->last_error = 87u;
        return XXEMUL_STATUS_OK;
    }
    entry = &process->fls_slots[index];
    if (entry->retiring) return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    if (!strcmp(name, "FlsGetValue")) {
        *result = thread->fls_values[index];
        process->last_error = 0u;
    } else if (!strcmp(name, "FlsSetValue")) {
        thread->fls_values[index] = width == 4u ? (uint32_t)arguments[1] : arguments[1];
        *result = 1u;
    } else {
        win_fls_frame *frame;
        int callbacks = 0;
        for (owner = 0u; owner < WIN_MAX_THREADS; ++owner)
            if (process->threads[owner].fls_values[index] && entry->callback) callbacks = 1;
        if (!callbacks) {
            for (owner = 0u; owner < WIN_MAX_THREADS; ++owner) process->threads[owner].fls_values[index] = 0u;
            entry->allocated = 0u;
            entry->callback = 0u;
            *result = 1u;
            return XXEMUL_STATUS_OK;
        }
        frame = win_fls_new_frame(process, WIN_FLS_FREE);
        if (!frame) { process->last_error = 8u; return XXEMUL_STATUS_OK; }
        frame->slot = (uint16_t)index;
        frame->generation = entry->generation;
        frame->callback = entry->callback;
        for (owner = 0u; owner < WIN_MAX_THREADS; ++owner) {
            frame->values[owner] = process->threads[owner].fls_values[index];
            process->threads[owner].fls_values[index] = 0u;
        }
        entry->retiring = 1u;
        process->fls_pending = (uint8_t)(frame - process->fls_frames + 1u);
        *result = 1u;
    }
    return XXEMUL_STATUS_OK;
}

static xxemul_status win_fls_invoke(xxemul_windows *process, win_fls_frame *frame,
                                   uint64_t callback, uint64_t value, xxemul_step_info *info)
{
    xxemul *emulator = process->emulator;
    uint8_t width = win_word_size(emulator), bytes[8] = {0};
    uint64_t stack = frame->caller.gpr[XXEMUL_X86_RSP], sp;
    if (stack < 0x40u) return XXEMUL_STATUS_ADDRESS_FAULT;
    sp = (stack & ~UINT64_C(15)) - (width == 8u ? 40u : 16u);
    if (width == 8u) win_put64(bytes, process->runtime_base + WIN_FLS_RETURN_OFFSET);
    else {
        win_put32(bytes, (uint32_t)(process->runtime_base + WIN_FLS_RETURN_OFFSET));
        win_put32(bytes + 4u, (uint32_t)value);
    }
    if (!win_write(process, sp, bytes, sizeof(bytes))) return XXEMUL_STATUS_ADDRESS_FAULT;
    frame->control = emulator->x87_control;
    frame->mxcsr = emulator->x86_mxcsr;
    frame->call_sp = sp;
    frame->invoking = 1u;
    emulator->x86 = frame->caller;
    emulator->x86.gpr[XXEMUL_X86_RSP] = sp;
    if (width == 8u) emulator->x86.gpr[XXEMUL_X86_RCX] = value;
    emulator->x86.ip = callback;
    if (info) { memset(info, 0, sizeof(*info)); info->address = frame->caller.ip; info->next_address = callback; }
    return XXEMUL_STATUS_OK;
}

static xxemul_status win_fls_continue(xxemul_windows *process, int returned, xxemul_step_info *info)
{
    win_thread_context *thread = &process->threads[process->thread_current];
    win_fls_frame *frame = win_fls_current(process);
    xxemul *emulator = process->emulator;
    unsigned index;
    if (!frame) return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    if (returned) {
        static const unsigned nonvolatile32[] = {3u,5u,6u,7u};
        static const unsigned nonvolatile64[] = {3u,5u,6u,7u,12u,13u,14u,15u};
        uint8_t width = win_word_size(emulator);
        if (!frame->invoking || emulator->x86.gpr[XXEMUL_X86_RSP] != frame->call_sp + 8u ||
            (emulator->x86.flags & UINT64_C(0x400)) || emulator->x87_control != frame->control ||
            ((emulator->x86_mxcsr ^ frame->mxcsr) & ~UINT32_C(0x3f))) return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
        for (index = 0u; index < (width == 8u ? 8u : 4u); ++index) {
            unsigned reg = width == 8u ? nonvolatile64[index] : nonvolatile32[index];
            if (emulator->x86.gpr[reg] != frame->caller.gpr[reg]) return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
        }
        if (width == 8u && memcmp(emulator->x86.xmm[6], frame->caller.xmm[6], 10u * 16u)) return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
        frame->invoking = 0u;
        /* Exit traversal already removed the old value before invocation.
         * Preserve any callback-created replacement, including a new slot
         * generation, until an explicit free or the real context teardown. */
        emulator->x86 = frame->caller;
        emulator->x87_control = frame->control;
        emulator->x86_mxcsr = frame->mxcsr;
    }
    if (frame->kind == WIN_FLS_FREE) {
        while (frame->cursor < WIN_MAX_THREADS) {
            uint64_t value = frame->values[frame->cursor++];
            if (value) return win_fls_invoke(process, frame, frame->callback, value, info);
        }
        {
            win_fls_slot *entry = &process->fls_slots[frame->slot];
            if (!entry->allocated || !entry->retiring || entry->generation != frame->generation)
                return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
            entry->allocated = entry->retiring = 0u;
            entry->callback = 0u;
        }
    } else {
        while (frame->cursor < WIN_FLS_SLOTS) {
            uint64_t value;
            win_fls_slot *entry;
            index = frame->cursor++;
            entry = &process->fls_slots[index];
            if (!entry->allocated || entry->retiring || entry->generation != frame->generations[index]) continue;
            value = thread->fls_values[index];
            thread->fls_values[index] = 0u;
            if (value && entry->callback) {
                frame->slot = (uint16_t)index;
                frame->generation = entry->generation;
                return win_fls_invoke(process, frame, entry->callback, value, info);
            }
        }
        thread->fls_cleanup_done = 1u;
    }
    {
        unsigned kind = frame->kind;
        uint32_t code = frame->exit_code;
        thread->fls_top = frame->previous;
        memset(frame, 0, sizeof(*frame));
        if (kind == WIN_FLS_THREAD_EXIT) return win_thread_finish(process, code, info);
        if (kind == WIN_FLS_PROCESS_EXIT) return win_dll_exit(process, code, info);
    }
    return XXEMUL_STATUS_OK;
}

static xxemul_status win_fls_start_exit(xxemul_windows *process, unsigned kind, uint32_t code,
                                       xxemul_step_info *info)
{
    win_fls_frame *frame;
    unsigned index;
    if (win_fls_current(process) || process->emulator->arch != XXEMUL_ARCH_X86)
        return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    frame = win_fls_new_frame(process, kind);
    if (!frame) return XXEMUL_STATUS_LIMIT_REACHED;
    frame->caller = process->emulator->x86;
    frame->cursor = 1u;
    frame->exit_code = code;
    for (index = 1u; index < WIN_FLS_SLOTS; ++index)
        frame->generations[index] = process->fls_slots[index].generation;
    return win_fls_continue(process, 0, info);
}
