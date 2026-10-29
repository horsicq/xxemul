/* Serialized loader notifications. Every callback executes guest instructions. */
static xxemul_status win_dll_continue(xxemul_windows *process, int returned, xxemul_step_info *info);
static xxemul_status win_dll_exit(xxemul_windows *process, uint32_t code, xxemul_step_info *info);
static int win_dll_exit_needed(xxemul_windows *process);

static int win_dll_module_notifying(const xxemul_windows *process, size_t slot)
{
    size_t i;
    for (i = 0u; i < process->dll_depth; ++i)
        if (process->dll_frames[i].notifying && process->dll_frames[i].current_slot < WIN_MAX_MODULES &&
            win_dll_reaches(process, slot, process->dll_frames[i].current_slot, 0u)) return 1;
    return 0;
}

static void win_dll_event(win_dll_frame *frame, xxemul_windows *process, size_t slot, unsigned reason)
{
    frame->current_slot = (uint16_t)slot;
    frame->current_generation = slot < WIN_MAX_MODULES ? process->modules[slot].generation : 0u;
    frame->reason = (uint8_t)reason;
    frame->callback_index = 0u;
    frame->phase = 0u;
    frame->notifying = 1u;
    if (slot < WIN_MAX_MODULES && reason == 1u) process->modules[slot].initializing = 1u;
}

static xxemul_status win_dll_invoke(xxemul_windows *process, win_dll_frame *frame, uint64_t address,
                                  int tls, xxemul_step_info *info)
{
    uint8_t width = win_word_size(process->emulator);
    uint64_t stack = frame->caller.gpr[XXEMUL_X86_RSP], sp;
    uint64_t base = frame->current_slot < WIN_MAX_MODULES ? process->modules[frame->current_slot].base : process->image_base;
    /* TLS callback Reserved is always NULL; DllMain has loader-specific data. */
    uint64_t reserved = tls ? 0u : (((frame->startup && frame->reason == 1u) || frame->exiting) ? 1u : 0u);
    if (stack < 0x50u) return XXEMUL_STATUS_ADDRESS_FAULT;
    sp = width == 8u ? ((stack - 0x40u) & ~UINT64_C(0xf)) - 8u : stack - 16u;
    if (!win_store(process, sp, width, process->runtime_base + WIN_DLL_RETURN_OFFSET)) return XXEMUL_STATUS_ADDRESS_FAULT;
    process->emulator->x86 = frame->caller;
    if (width == 8u) {
        process->emulator->x86.gpr[XXEMUL_X86_RCX] = base;
        process->emulator->x86.gpr[XXEMUL_X86_RDX] = frame->reason;
        process->emulator->x86.gpr[XXEMUL_X86_R8] = reserved;
    } else if (!win_store(process, sp + 4u, 4u, base) || !win_store(process, sp + 8u, 4u, frame->reason) ||
               !win_store(process, sp + 12u, 4u, reserved)) return XXEMUL_STATUS_ADDRESS_FAULT;
    process->emulator->x86.ip = address;
    process->emulator->x86.gpr[XXEMUL_X86_RSP] = sp;
    frame->invoking_tls = (uint8_t)tls;
    if (info) {
        memset(info, 0, sizeof(*info));
        info->address = frame->caller.ip;
        info->next_address = address;
    }
    return XXEMUL_STATUS_OK;
}

static xxemul_status win_dll_continue(xxemul_windows *process, int returned, xxemul_step_info *info)
{
    win_dll_frame *frame;
    size_t slot, i;
    uint64_t order;
    if (!process->dll_depth) return XXEMUL_STATUS_INVALID_IMAGE;
    frame = &process->dll_frames[process->dll_depth - 1u];
    if (frame->owner_id != process->threads[process->thread_current].id) return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    for (;;) {
        if (frame->notifying) {
            win_module *module = frame->current_slot < WIN_MAX_MODULES ? &process->modules[frame->current_slot] : NULL;
            win_tls_image *tls = module ? &module->tls : &process->main_tls;
            if (module && (!module->live || module->generation != frame->current_generation)) return XXEMUL_STATUS_INVALID_IMAGE;
            if (returned && !frame->invoking_tls && frame->reason == 1u &&
                !(uint32_t)process->emulator->x86.gpr[XXEMUL_X86_RAX]) {
                /* A TLS callback is VOID; only DllMain can reject attachment. */
                module->initializing = 0u;
                module->initialized = 1u; /* Failed entry still receives rollback detach. */
                frame->failed = 1u;
                frame->unload_mask |= win_dll_dependencies_release(process, frame->root_slot);
                frame->notifying = 0u;
                returned = 0;
                continue;
            }
            returned = 0;
            if (frame->phase == 0u) {
                uint64_t callback;
                if (!win_tls_callback_at(process, tls, frame->callback_index, &callback)) return XXEMUL_STATUS_ADDRESS_FAULT;
                if (callback) {
                    ++frame->callback_index;
                    return win_dll_invoke(process, frame, callback, 1, info);
                }
                frame->phase = 1u;
            }
            if (frame->phase == 1u) {
                frame->phase = 2u;
                if (module && module->entry_rva &&
                    !((frame->reason == 2u || frame->reason == 3u) && module->thread_callbacks_disabled))
                    return win_dll_invoke(process, frame, module->base + module->entry_rva, 0, info);
            }
            frame->notifying = 0u;
            if (!module) frame->main_pending = 0u;
            else if (frame->reason == 1u) { module->initializing = 0u; module->initialized = 1u; }
            else if (frame->reason == 0u) {
                frame->unload_mask &= ~(UINT32_C(1) << frame->current_slot);
                module->initialized = 0u;
                if (!frame->exiting) win_dll_discard(process, frame->current_slot);
            } else frame->notify_mask &= ~(UINT32_C(1) << frame->current_slot);
        }
        if (frame->mode == 1u) {
            /* Snapshot generations prevent a nested unload/reload from turning
             * an old thread notification into a call into a different image. */
            slot = WIN_MAX_MODULES;
            order = frame->reason == 2u ? UINT64_MAX : 0u;
            for (i = 0u; i < process->module_count; ++i) {
                win_module *module = &process->modules[i];
                if (!(frame->notify_mask & (UINT32_C(1) << i))) continue;
                if (!module->live || !module->initialized || module->generation != frame->notify_generations[i]) {
                    frame->notify_mask &= ~(UINT32_C(1) << i);
                    continue;
                }
                if ((frame->reason == 2u && module->init_order < order) ||
                    (frame->reason == 3u && module->init_order >= order)) { slot = i; order = module->init_order; }
            }
            if (slot < WIN_MAX_MODULES) { win_dll_event(frame, process, slot, frame->reason); continue; }
        } else if (frame->mode == 0u || frame->mode == 3u) {
            while (frame->unload_mask) {
                slot = WIN_MAX_MODULES;
                order = 0u;
                for (i = 0u; i < process->module_count; ++i) {
                    size_t parent;
                    int required = 0;
                    if (!(frame->unload_mask & (UINT32_C(1) << i))) continue;
                    if (!process->modules[i].live) { frame->unload_mask &= ~(UINT32_C(1) << i); continue; }
                    for (parent = 0u; parent < process->module_count; ++parent)
                        if ((frame->unload_mask & (UINT32_C(1) << parent)) && process->modules[parent].live &&
                            (process->modules[parent].dependencies & (UINT32_C(1) << i))) { required = 1; break; }
                    if (!required && process->modules[i].init_order >= order) { slot = i; order = process->modules[i].init_order; }
                }
                if (slot == WIN_MAX_MODULES) return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
                if (process->modules[slot].initialized && !process->modules[slot].data_only) {
                    win_dll_event(frame, process, slot, 0u);
                    break;
                }
                frame->unload_mask &= ~(UINT32_C(1) << slot);
                if (!frame->exiting) win_dll_discard(process, slot);
            }
            if (frame->notifying) continue;
            if (!frame->unloading && !frame->failed) {
                slot = WIN_MAX_MODULES;
                order = UINT64_MAX;
                for (i = 0u; i < process->module_count; ++i) {
                    win_module *module = &process->modules[i];
                    if (module->real && module->live && !module->initialized && !module->initializing &&
                        module->init_order && module->init_order < order) { slot = i; order = module->init_order; }
                }
                if (slot < WIN_MAX_MODULES) { win_dll_event(frame, process, slot, 1u); continue; }
            }
        }
        if (frame->main_pending) { win_dll_event(frame, process, WIN_MAX_MODULES, frame->reason); continue; }
        break;
    }
    process->emulator->x86 = frame->caller;
    if (frame->failed) {
        if (frame->startup && frame->mode != 3u) { --process->dll_depth; return XXEMUL_STATUS_INVALID_IMAGE; }
        process->emulator->x86.gpr[XXEMUL_X86_RAX] = 0u;
        process->last_error = 1114u;
        (void)win_store(process, process->runtime_base + (win_word_size(process->emulator) == 8u ? 0x68u : 0x34u), 4u, 1114u);
    }
    if (info) {
        memset(info, 0, sizeof(*info));
        info->address = process->runtime_base + WIN_DLL_RETURN_OFFSET;
        info->next_address = process->emulator->x86.ip;
    }
    if (frame->mode == 3u) {
        win_module *primary = &process->modules[process->main_dll_slot - 1u];
        if (!frame->failed) primary->references = UINT32_MAX;
        process->main_dll_complete = 1u;
        process->exit_code = frame->failed ? 1114u : 0u;
        process->emulator->exit_code = (uint8_t)process->exit_code;
        process->emulator->x86.ip = process->runtime_base + WIN_PROCESS_RETURN_OFFSET;
        process->emulator->halted = 1u;
        --process->dll_depth;
        return XXEMUL_STATUS_HALTED;
    }
    if (frame->exiting) {
        /* Process detach keeps DLL mappings and TLS alive until EXE TLS has
         * also returned. Those callbacks may still call DLL code. */
        for (i = 0u; i < process->module_count; ++i)
            if (process->modules[i].real && process->modules[i].live) win_dll_discard(process, i);
        process->process_terminated = 1u;
        process->exit_code = frame->exit_code;
        process->emulator->exit_code = (uint8_t)frame->exit_code;
        process->emulator->halted = 1;
        --process->dll_depth;
        return XXEMUL_STATUS_HALTED;
    }
    if (frame->mode == 1u && frame->reason == 3u) {
        uint32_t code = frame->exit_code;
        --process->dll_depth;
        return win_thread_finish_raw(process, code, info);
    }
    --process->dll_depth;
    return XXEMUL_STATUS_OK;
}

static win_dll_frame *win_dll_frame_begin(xxemul_windows *process)
{
    win_dll_frame *frame;
    if (process->dll_depth >= WIN_DLL_DEPTH) return NULL;
    frame = &process->dll_frames[process->dll_depth++];
    memset(frame, 0, sizeof(*frame));
    frame->caller = process->emulator->x86;
    frame->owner_id = process->threads[process->thread_current].id;
    return frame;
}

static xxemul_status win_dll_begin(xxemul_windows *process, size_t root, int unloading, int startup, xxemul_step_info *info)
{
    win_dll_frame *frame = win_dll_frame_begin(process);
    if (!frame) return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    frame->root_slot = (uint16_t)root;
    frame->unloading = (uint8_t)unloading;
    frame->startup = (uint8_t)startup;
    if (unloading) frame->unload_mask = win_dll_dependencies_release(process, root);
    return win_dll_continue(process, 0, info);
}

static int win_dll_uninitialized(xxemul_windows *process, size_t *slot)
{
    size_t i;
    if (process->dll_exiting) return 0;
    for (i = 0u; i < process->module_count; ++i) {
        win_module *module = &process->modules[i];
        if (module->real && module->live && !module->initialized && !module->initializing && module->init_order) { *slot = i; return 1; }
    }
    return 0;
}

static xxemul_status win_dll_main_begin(xxemul_windows *process, xxemul_step_info *info)
{
    win_dll_frame *frame = win_dll_frame_begin(process);
    if (!frame) return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    frame->mode = 2u;
    frame->main_pending = 1u;
    frame->reason = 1u;
    return win_dll_continue(process, 0, info);
}

static xxemul_status win_dll_startup_begin(xxemul_windows *process, xxemul_step_info *info)
{
    win_dll_frame *frame = win_dll_frame_begin(process);
    size_t i;
    if (!frame) return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    frame->startup = 1u;
    frame->reason = 1u;
    if (process->main_dll_slot) {
        frame->mode = 3u;
        frame->startup = 0u; /* Primary DLL loading uses LoadLibrary arguments. */
        frame->root_slot = (uint16_t)(process->main_dll_slot - 1u);
    }
    frame->main_pending = (uint8_t)(process->main_tls.callbacks != 0u);
    for (i = 0u; !process->main_dll_slot && i < process->module_count; ++i)
        if (process->modules[i].real && process->modules[i].live && !process->modules[i].initialized) {
            frame->root_slot = (uint16_t)i;
            break;
        }
    return win_dll_continue(process, 0, info);
}

static xxemul_status win_dll_thread_begin(xxemul_windows *process, unsigned reason, uint32_t code, xxemul_step_info *info)
{
    win_dll_frame *frame = win_dll_frame_begin(process);
    size_t i;
    if (!frame) return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    frame->mode = 1u;
    frame->reason = (uint8_t)reason;
    frame->exit_code = code;
    frame->main_pending = (uint8_t)(process->tls_started && process->main_tls.callbacks != 0u);
    for (i = 0u; i < process->module_count; ++i) {
        win_module *module = &process->modules[i];
        if (module->real && module->live && module->initialized && !module->data_only &&
            (!module->thread_callbacks_disabled || module->tls.callbacks)) {
            frame->notify_mask |= UINT32_C(1) << i;
            frame->notify_generations[i] = module->generation;
        }
    }
    return win_dll_continue(process, 0, info);
}

static int win_dll_exit_needed(xxemul_windows *process)
{
    size_t i;
    if (process->dll_exiting) return 0;
    if (process->tls_started && process->main_tls.callbacks) return 1;
    for (i = 0u; i < process->module_count; ++i) if (process->modules[i].real && process->modules[i].live) return 1;
    return 0;
}

static xxemul_status win_dll_exit(xxemul_windows *process, uint32_t code, xxemul_step_info *info)
{
    win_dll_frame *frame = win_dll_frame_begin(process);
    size_t i;
    if (!frame) return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    frame->unloading = 1u;
    frame->exiting = 1u;
    frame->exit_code = code;
    frame->reason = 0u;
    frame->main_pending = (uint8_t)(process->tls_started && process->main_tls.callbacks != 0u);
    process->dll_exiting = 1u;
    for (i = 0u; i < process->module_count; ++i) if (process->modules[i].real && process->modules[i].live) {
        process->modules[i].references = 0u;
        frame->unload_mask |= UINT32_C(1) << i;
    }
    return win_dll_continue(process, 0, info);
}

static int win_dll_last_thread(xxemul_windows *process)
{
    unsigned i;
    for (i = 0u; i < WIN_MAX_THREADS; ++i) if (i != process->thread_current && process->threads[i].active) return 0;
    return 1;
}
