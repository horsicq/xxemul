/* Finite current-thread WH_CBT/WH_MSGFILTER chains. Every callback executes as
 * guest code. Snapshot membership is fixed per event; eligibility is rechecked
 * before each invocation. CallNext owns a separate saved caller and position. */
static uint32_t win_hook_owner(const xxemul_windows *p)
{ return p->threads[p->thread_current].id; }

static void win_hook_collect(win_hook_record *h)
{
    if (h->allocated && !h->enabled && !h->references) {
        uint64_t generation = h->generation;
        memset(h, 0, sizeof(*h));
        h->generation = generation;
    }
}

static win_hook_call *win_hook_current(xxemul_windows *p)
{
    win_hook_call *top = NULL;
    uint32_t owner = win_hook_owner(p);
    unsigned i;
    for (i = 0u; i < WIN_HOOK_CALLS; ++i) {
        win_hook_call *c = &p->hooks.calls[i];
        if (c->active && c->invoking && c->owner_id == owner &&
            (!top || c->sequence > top->sequence)) top = c;
    }
    return top;
}

static win_hook_event *win_hook_event_for(xxemul_windows *p, const win_hook_call *c)
{
    win_hook_event *e;
    if (!c->active || c->event_slot >= WIN_HOOK_EVENTS) return NULL;
    e = &p->hooks.events[c->event_slot];
    return e->active && e->owner_id == c->owner_id &&
           e->sequence == c->event_sequence ? e : NULL;
}

static xxemul_status win_hook_snapshot(xxemul_windows *p, int id, int code,
                                      int wide, win_hook_token *tokens,
                                      unsigned *count)
{
    unsigned i, n = 0u;
    uint32_t owner = win_hook_owner(p);
    if (id != 5 && id != -1) return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    for (i = 0u; i < WIN_HOOK_SLOTS; ++i) {
        const win_hook_record *h = &p->hooks.records[i];
        unsigned at;
        if (!h->allocated || !h->enabled || h->owner_id != owner || h->id != id) continue;
        if ((id == 5 && code != 3 && code != 4) || h->wide != (uint8_t)!!wide)
            return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
        at = n++;
        while (at && p->hooks.records[tokens[at - 1u].slot].sequence < h->sequence) {
            tokens[at] = tokens[at - 1u];
            --at;
        }
        tokens[at].slot = (uint16_t)i;
        tokens[at].generation = h->generation;
    }
    *count = n;
    return XXEMUL_STATUS_OK;
}

static int win_hook_room(const xxemul_windows *p, int event)
{
    unsigned i;
    if (p->hooks.call_sequence == UINT64_MAX ||
        (event && p->hooks.event_sequence == UINT64_MAX)) return 0;
    for (i = 0u; i < WIN_HOOK_CALLS && p->hooks.calls[i].active; ++i) {}
    if (i == WIN_HOOK_CALLS) return 0;
    if (event) {
        for (i = 0u; i < WIN_HOOK_EVENTS && p->hooks.events[i].active; ++i) {}
        if (i == WIN_HOOK_EVENTS) return 0;
    }
    return 1;
}

static xxemul_status win_hook_event_supported(xxemul_windows *p, int id,
                                              int code, int wide)
{
    win_hook_token tokens[WIN_HOOK_SLOTS];
    unsigned count;
    xxemul_status status = win_hook_snapshot(p, id, code, wide, tokens, &count);
    if (status == XXEMUL_STATUS_OK && count && !win_hook_room(p, 1))
        status = XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    return status;
}

static xxemul_status win_cbt_event_supported(xxemul_windows *p, int code, int wide)
{ return win_hook_event_supported(p, 5, code, wide); }

static xxemul_status win_msgfilter_event_supported(xxemul_windows *p, int code,
                                                   int wide)
{ return win_hook_event_supported(p, -1, code, wide); }

static win_hook_call *win_hook_alloc_call(xxemul_windows *p, win_hook_event *event,
                                         int root, int code, uint64_t wp,
                                         uint64_t lp, unsigned start)
{
    win_hook_call *c;
    unsigned i;
    if (p->hooks.call_sequence == UINT64_MAX) return NULL;
    for (i = 0u; i < WIN_HOOK_CALLS && p->hooks.calls[i].active; ++i) {}
    if (i == WIN_HOOK_CALLS) return NULL;
    c = &p->hooks.calls[i];
    memset(c, 0, sizeof(*c));
    c->active = 1u;
    c->root = (uint8_t)!!root;
    c->owner_id = win_hook_owner(p);
    c->sequence = ++p->hooks.call_sequence;
    c->event_slot = (uint16_t)(event - p->hooks.events);
    c->event_sequence = event->sequence;
    c->start_index = (uint16_t)start;
    c->current_index = UINT16_MAX;
    c->hook_slot = UINT16_MAX;
    c->code = (int32_t)code;
    c->wparam = wp;
    c->lparam = lp;
    ++event->calls;
    return c;
}

static void win_hook_abort_new_call(xxemul_windows *p, win_hook_call *c)
{
    win_hook_event *event = win_hook_event_for(p, c);
    int root = c->root;
    if (event && event->calls) --event->calls;
    memset(c, 0, sizeof(*c));
    if (root && event && !event->calls) memset(event, 0, sizeof(*event));
}

static xxemul_status win_hook_finish(xxemul_windows *p, win_hook_call *c,
                                    uint64_t value, xxemul_step_info *info)
{
    win_hook_event *event = win_hook_event_for(p, c);
    xxemul *emu = p->emulator;
    xxemul_x86_state caller;
    uint32_t mxcsr, resume_kind, creator_slot;
    uint16_t control;
    uint64_t creator_sequence;
    int root;
    if (!event || !event->calls || c->invoking) return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    root = c->root;
    if (root && event->calls != 1u) return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    caller = c->caller;
    control = c->control;
    mxcsr = (c->mxcsr & ~UINT32_C(0x3f)) | (emu->x86_mxcsr & UINT32_C(0x3f));
    resume_kind = event->resume_kind;
    creator_slot = event->creator_slot;
    creator_sequence = event->creator_sequence;
    --event->calls;
    memset(c, 0, sizeof(*c));
    if (root) memset(event, 0, sizeof(*event));
    emu->x86 = caller;
    emu->x87_control = control;
    emu->x86_mxcsr = mxcsr;
    if (win_word_size(emu) == 4u) value = (uint32_t)value;
    emu->x86.gpr[XXEMUL_X86_RAX] = root && resume_kind == WIN_HOOK_RESUME_API ? !!value : value;
    if (info) { memset(info, 0, sizeof(*info)); info->address = caller.ip; info->next_address = caller.ip; }
    if (root && resume_kind != WIN_HOOK_RESUME_API)
        return win_cbt_creator_resume(p, resume_kind, creator_slot, creator_sequence, value, info);
    return XXEMUL_STATUS_OK;
}

static xxemul_status win_hook_dispatch(xxemul_windows *p, win_hook_call *c,
                                      xxemul_step_info *info)
{
    win_hook_event *event = win_hook_event_for(p, c);
    xxemul *emu = p->emulator;
    uint8_t width = win_word_size(emu), bytes[40] = {0};
    uint64_t stack, sp;
    unsigned index;
    if (!event || c->owner_id != win_hook_owner(p)) return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    for (index = c->start_index; index < event->count; ++index) {
        const win_hook_token *token = &event->tokens[index];
        win_hook_record *h = &p->hooks.records[token->slot];
        if (!h->allocated || !h->enabled || h->generation != token->generation ||
            h->owner_id != c->owner_id || h->id != event->id) continue;
        stack = c->caller.gpr[XXEMUL_X86_RSP];
        /* A synthetic callback frame cannot be represented below this bound.
         * No guest store has occurred, so this is a typed profile boundary. */
        if (stack < 64u) { win_hook_abort_new_call(p, c); return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION; }
        sp = (stack & ~UINT64_C(15)) - (width == 8u ? 40u : 32u);
        if (width == 8u) win_put64(bytes, p->runtime_base + WIN_CBT_RETURN_OFFSET);
        else {
            win_put32(bytes, (uint32_t)(p->runtime_base + WIN_CBT_RETURN_OFFSET));
            win_put32(bytes + 4u, (uint32_t)c->code);
            win_put32(bytes + 8u, (uint32_t)c->wparam);
            win_put32(bytes + 12u, (uint32_t)c->lparam);
        }
        if (!win_write(p, sp, bytes, width == 8u ? 40u : 16u)) {
            win_hook_abort_new_call(p, c);
            return XXEMUL_STATUS_ADDRESS_FAULT;
        }
        c->current_index = (uint16_t)index;
        c->hook_slot = token->slot;
        c->hook_generation = token->generation;
        c->call_sp = sp;
        c->invoking = 1u;
        ++h->references;
        emu->x86 = c->caller;
        emu->x86.gpr[XXEMUL_X86_RSP] = sp;
        if (width == 8u) {
            emu->x86.gpr[XXEMUL_X86_RCX] = (uint32_t)c->code;
            emu->x86.gpr[XXEMUL_X86_RDX] = c->wparam;
            emu->x86.gpr[XXEMUL_X86_R8] = c->lparam;
        }
        emu->x86.ip = h->procedure;
        if (info) { memset(info, 0, sizeof(*info)); info->address = c->caller.ip; info->next_address = h->procedure; }
        return XXEMUL_STATUS_OK;
    }
    return win_hook_finish(p, c, 0u, info);
}

static xxemul_status win_hook_begin(xxemul_windows *p, int id, int code,
                                   uint64_t wp, uint64_t lp, int wide,
                                   unsigned kind, unsigned slot, uint64_t sequence,
                                   xxemul_step_info *info)
{
    win_hook_token tokens[WIN_HOOK_SLOTS];
    win_hook_event *event;
    win_hook_call *call;
    xxemul_status status;
    unsigned count, index;
    status = win_hook_snapshot(p, id, code, wide, tokens, &count);
    if (status != XXEMUL_STATUS_OK) return status;
    if (!count) {
        if (kind != WIN_HOOK_RESUME_API) return win_cbt_creator_resume(p, kind, slot, sequence, 0u, info);
        p->emulator->x86.gpr[XXEMUL_X86_RAX] = 0u;
        if (info) info->next_address = p->emulator->x86.ip;
        return XXEMUL_STATUS_OK;
    }
    if (p->emulator->arch != XXEMUL_ARCH_X86 || !win_hook_room(p, 1))
        return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    for (index = 0u; index < WIN_HOOK_EVENTS && p->hooks.events[index].active; ++index) {}
    if (index == WIN_HOOK_EVENTS) return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    event = &p->hooks.events[index];
    memset(event, 0, sizeof(*event));
    event->active = 1u;
    event->owner_id = win_hook_owner(p);
    event->sequence = ++p->hooks.event_sequence;
    event->id = (int32_t)id;
    event->wide = (uint8_t)!!wide;
    event->resume_kind = kind;
    event->creator_slot = slot;
    event->creator_sequence = sequence;
    event->count = (uint16_t)count;
    memcpy(event->tokens, tokens, count * sizeof(tokens[0]));
    call = win_hook_alloc_call(p, event, 1, code, wp, lp, 0u);
    if (!call) { memset(event, 0, sizeof(*event)); return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION; }
    call->caller = p->emulator->x86;
    call->control = p->emulator->x87_control;
    call->mxcsr = p->emulator->x86_mxcsr;
    return win_hook_dispatch(p, call, info);
}

static xxemul_status win_cbt_begin(xxemul_windows *p, int code, uint64_t wp,
                                  uint64_t lp, int wide, unsigned kind,
                                  unsigned slot, uint64_t sequence,
                                  xxemul_step_info *info)
{ return win_hook_begin(p, 5, code, wp, lp, wide, kind, slot, sequence, info); }

static xxemul_status win_msgfilter_begin(xxemul_windows *p, int code, uint64_t wp,
                                        uint64_t lp, int wide, unsigned kind,
                                        unsigned slot, uint64_t sequence,
                                        xxemul_step_info *info)
{ return win_hook_begin(p, -1, code, wp, lp, wide, kind, slot, sequence, info); }

static xxemul_status win_cbt_return(xxemul_windows *p, xxemul_step_info *info)
{
    static const unsigned nv32[] = {3u, 5u, 6u, 7u};
    static const unsigned nv64[] = {3u, 5u, 6u, 7u, 12u, 13u, 14u, 15u};
    win_hook_call *c = win_hook_current(p);
    win_hook_event *event;
    win_hook_record *h;
    xxemul *emu = p->emulator;
    uint8_t width = win_word_size(emu);
    uint64_t result = emu->x86.gpr[XXEMUL_X86_RAX];
    unsigned i;
    if (!c || !(event = win_hook_event_for(p, c)) || c->hook_slot >= WIN_HOOK_SLOTS ||
        emu->x86.ip != p->runtime_base + WIN_CBT_RETURN_OFFSET ||
        emu->x86.gpr[XXEMUL_X86_RSP] != c->call_sp + (width == 8u ? 8u : 16u) ||
        (emu->x86.flags & UINT64_C(0x400)) || emu->x87_control != c->control ||
        ((emu->x86_mxcsr ^ c->mxcsr) & ~UINT32_C(0x3f)))
        return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    (void)event;
    for (i = 0u; i < (width == 8u ? 8u : 4u); ++i) {
        unsigned reg = width == 8u ? nv64[i] : nv32[i];
        if (emu->x86.gpr[reg] != c->caller.gpr[reg]) return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    }
    if (width == 8u && memcmp(emu->x86.xmm[6], c->caller.xmm[6], 10u * 16u))
        return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    h = &p->hooks.records[c->hook_slot];
    if (!h->allocated || h->generation != c->hook_generation || !h->references)
        return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    --h->references;
    win_hook_collect(h);
    c->invoking = 0u;
    return win_hook_finish(p, c, result, info);
}

static int win_cbt_api_pending(const xxemul_windows *p)
{
    const win_hook_pending *pending = &p->hooks.pending[p->thread_current];
    return pending->kind && pending->owner_id == win_hook_owner(p);
}

static xxemul_status win_cbt_api_continue(xxemul_windows *p, xxemul_step_info *info)
{
    win_hook_pending pending = p->hooks.pending[p->thread_current];
    win_hook_call *c;
    if (!pending.kind || pending.owner_id != win_hook_owner(p)) return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    memset(&p->hooks.pending[p->thread_current], 0, sizeof(pending));
    if (pending.kind == WIN_HOOK_PENDING_FILTER)
        return win_msgfilter_begin(p, pending.code, 0u, pending.lparam, pending.wide,
                                    WIN_HOOK_RESUME_API, 0u, 0u, info);
    if (pending.kind != WIN_HOOK_PENDING_NEXT || pending.call_slot >= WIN_HOOK_CALLS)
        return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    c = &p->hooks.calls[pending.call_slot];
    if (!c->active || c->owner_id != pending.owner_id || c->invoking || c->root)
        return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    c->caller = p->emulator->x86;
    c->control = p->emulator->x87_control;
    c->mxcsr = p->emulator->x86_mxcsr;
    return win_hook_dispatch(p, c, info);
}

static int win_cbt_api(xxemul_windows *p, const win_api *api, const uint64_t *a,
                       uint64_t *result, xxemul_status *status)
{
    const char *name = api->name;
    int set = !strcmp(name, "SetWindowsHookExA") || !strcmp(name, "SetWindowsHookExW");
    int filter = !strcmp(name, "CallMsgFilterA") || !strcmp(name, "CallMsgFilterW");
    int next = !strcmp(name, "CallNextHookEx");
    unsigned i;
    uint8_t width = win_word_size(p->emulator);
    uint32_t owner = win_hook_owner(p);
    win_hook_pending *pending = &p->hooks.pending[p->thread_current];
    if (!set && !filter && !next && strcmp(name, "UnhookWindowsHookEx")) return 0;
    *status = XXEMUL_STATUS_OK;
    *result = 0u;
    if (p->emulator->arch != XXEMUL_ARCH_X86) { *status = XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION; return 1; }
    if (set) {
        win_hook_record *h;
        uint64_t procedure = width == 4u ? (uint32_t)a[1] : a[1];
        int32_t id = (int32_t)a[0];
        if (!procedure) { p->last_error = 87u; return 1; }
        if ((id != 5 && id != -1) || a[2] || !(uint32_t)a[3] || (uint32_t)a[3] != owner) {
            *status = XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION; return 1;
        }
        if (!win_memory_span(p, procedure, 1u)) { p->last_error = 998u; return 1; }
        for (i = 0u; i < WIN_HOOK_SLOTS && (p->hooks.records[i].allocated || p->hooks.records[i].generation == UINT64_MAX); ++i) {}
        if (i == WIN_HOOK_SLOTS || p->hooks.handle_sequence == WIN_HOOK_HANDLE_LIMIT ||
            p->hooks.registration_sequence == UINT64_MAX) { p->last_error = 8u; return 1; }
        h = &p->hooks.records[i];
        ++h->generation;
        h->handle = WIN_HOOK_HANDLE_BASE + ++p->hooks.handle_sequence;
        h->procedure = procedure;
        h->sequence = ++p->hooks.registration_sequence;
        h->owner_id = owner;
        h->id = id;
        h->wide = (uint8_t)win_suffix(name, "W");
        h->allocated = h->enabled = 1u;
        *result = h->handle;
        return 1;
    }
    if (!strcmp(name, "UnhookWindowsHookEx")) {
        uint64_t handle = width == 4u ? (uint32_t)a[0] : a[0];
        for (i = 0u; i < WIN_HOOK_SLOTS; ++i) {
            win_hook_record *h = &p->hooks.records[i];
            if (h->allocated && h->enabled && h->handle == handle) {
                h->enabled = 0u; win_hook_collect(h); *result = 1u; return 1;
            }
        }
        p->last_error = 1404u;
        return 1;
    }
    if (pending->kind) { *status = XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION; return 1; }
    if (next) {
        win_hook_call *parent = win_hook_current(p), *child;
        win_hook_event *event;
        if (!parent) return 1; /* HHOOK is intentionally not inspected. */
        event = win_hook_event_for(p, parent);
        if (!event || parent->current_index >= event->count) { *status = XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION; return 1; }
        child = win_hook_alloc_call(p, event, 0, (int32_t)a[1],
                                   width == 4u ? (uint32_t)a[2] : a[2],
                                   width == 4u ? (uint32_t)a[3] : a[3],
                                   (unsigned)parent->current_index + 1u);
        if (!child) { *status = XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION; return 1; }
        pending->owner_id = owner;
        pending->call_slot = (uint16_t)(child - p->hooks.calls);
        pending->kind = WIN_HOOK_PENDING_NEXT;
        return 1;
    }
    if (filter) {
        uint8_t message[48];
        win_hook_token tokens[WIN_HOOK_SLOTS];
        unsigned count;
        uint64_t pointer = width == 4u ? (uint32_t)a[0] : a[0];
        if (!win_read(p, pointer, message, width == 8u ? 48u : 28u)) { *status = XXEMUL_STATUS_ADDRESS_FAULT; return 1; }
        *status = win_hook_snapshot(p, -1, (int32_t)a[1], win_suffix(name, "W"), tokens, &count);
        if (*status != XXEMUL_STATUS_OK || !count) return 1;
        if (!win_hook_room(p, 1)) { *status = XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION; return 1; }
        pending->owner_id = owner;
        pending->kind = WIN_HOOK_PENDING_FILTER;
        pending->code = (int32_t)a[1];
        pending->lparam = pointer;
        pending->wide = (uint8_t)win_suffix(name, "W");
        return 1;
    }
    return 1;
}

static void win_cbt_abandon_thread(xxemul_windows *p, uint32_t owner)
{
    unsigned i;
    for (i = 0u; i < WIN_HOOK_CALLS; ++i) {
        win_hook_call *c = &p->hooks.calls[i];
        if (!c->active || c->owner_id != owner) continue;
        if (c->invoking && c->hook_slot < WIN_HOOK_SLOTS) {
            win_hook_record *h = &p->hooks.records[c->hook_slot];
            if (h->allocated && h->generation == c->hook_generation && h->references) --h->references;
        }
        memset(c, 0, sizeof(*c));
    }
    for (i = 0u; i < WIN_HOOK_EVENTS; ++i)
        if (p->hooks.events[i].active && p->hooks.events[i].owner_id == owner)
            memset(&p->hooks.events[i], 0, sizeof(p->hooks.events[i]));
    for (i = 0u; i < WIN_MAX_THREADS; ++i)
        if (p->hooks.pending[i].kind && p->hooks.pending[i].owner_id == owner)
            memset(&p->hooks.pending[i], 0, sizeof(p->hooks.pending[i]));
    for (i = 0u; i < WIN_HOOK_SLOTS; ++i) {
        win_hook_record *h = &p->hooks.records[i];
        if (h->allocated && h->owner_id == owner) h->enabled = 0u;
        win_hook_collect(h);
    }
}
