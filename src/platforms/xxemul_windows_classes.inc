/* Process-local guest window classes. No host windows or procedure calls are
 * manufactured here: successful registration retains the actual guest class. */
static win_gui_class *win_gui_object_class(xxemul_windows *p,const win_gui_object *o)
{
    size_t i;
    for(i=0;i<WIN_GUI_CLASSES;i++)if(p->gui_classes[i].active&&p->gui_classes[i].atom==o->class_ordinal)
        return &p->gui_classes[i];
    return NULL;
}
static win_gui_class *win_gui_class_find(xxemul_windows *process, uint64_t instance,
                                       uint64_t selector, int wide, uint32_t *error)
{
    uint16_t name[256]; size_t i; int atom = selector && selector <= 0xffffu;
    *error = 1411u;
    if (!atom) {
        uint32_t read_error = win_reg_name(process, selector, wide, name, 256u, 0);
        if (read_error || !name[0]) { *error = read_error == 998u ? 998u : 87u; return NULL; }
    }
    for (i = 0u; i < WIN_GUI_CLASSES; ++i) {
        win_gui_class *c = &process->gui_classes[i];
        if (!c->active || (c->instance != instance && !(c->style & 0x4000u))) continue;
        if (atom ? c->atom == (uint16_t)selector : win_reg_name_equal(c->name, name)) return c;
    }
    return NULL;
}

static int win_gui_class_call(xxemul_windows *process, const char *api,
                              const uint64_t *arg, uint64_t *result)
{
    int wide = win_suffix(api, "W"); uint8_t width = win_word_size(process->emulator);
    int extended = win_equal(api, "RegisterClassExA") || win_equal(api, "RegisterClassExW") ||
        win_equal(api, "GetClassInfoExA") || win_equal(api, "GetClassInfoExW");
    unsigned size = width == 8u ? (extended ? 80u : 72u) : (extended ? 48u : 40u);
    unsigned proc_offset = width == 8u ? 8u : (extended ? 8u : 4u);
    unsigned extra_offset = width == 8u ? 16u : (extended ? 12u : 8u);
    unsigned instance_offset = width == 8u ? 24u : (extended ? 20u : 16u);
    uint32_t error; win_gui_class *c; size_t i;
    if (win_equal(api, "RegisterClassA") || win_equal(api, "RegisterClassW") ||
        win_equal(api, "RegisterClassExA") || win_equal(api, "RegisterClassExW")) {
        win_gui_class value; uint8_t strings[1536] = {0}; uint64_t fields[6], loaded, menu;
        uint16_t menu_name[256] = {0}; unsigned slot;
        memset(&value, 0, sizeof(value));
        if (!win_memory_span(process, arg[0], size) || !win_load(process, arg[0], 4u, &loaded)) {
            process->last_error = 998u; return 1;
        }
        if (extended && loaded != size) { process->last_error = 87u; return 1; }
        if (extended && !win_load(process, arg[0] + 4u, 4u, &loaded)) { process->last_error = 998u; return 1; }
        value.style = (uint32_t)loaded;
        if (!win_load(process, arg[0] + proc_offset, width, &value.procedure) ||
            !win_load(process, arg[0] + extra_offset, 4u, &loaded)) { process->last_error = 998u; return 1; }
        value.class_extra = (uint32_t)loaded;
        if (!win_load(process, arg[0] + extra_offset + 4u, 4u, &loaded)) { process->last_error = 998u; return 1; }
        value.window_extra = (uint32_t)loaded;
        for (i = 0u; i < 6u; ++i)
            if (!win_load(process, arg[0] + instance_offset + i * width, width, &fields[i])) {
                process->last_error = 998u; return 1;
            }
        value.instance = fields[0]; value.icon = fields[1]; value.cursor = fields[2]; value.brush = fields[3]; menu = fields[4];
        if (extended && !win_load(process, arg[0] + instance_offset + 6u * width, width, &value.small_icon)) {
            process->last_error = 998u; return 1;
        }
        error = fields[5] <= 0xffffu ? 87u : win_reg_name(process, fields[5], wide, value.name, 256u, 0);
        if (error || !value.name[0] || !value.procedure || !win_memory_span(process, value.procedure, 1u) ||
            value.class_extra > 4096u || value.window_extra > 4096u) {
            process->last_error = error == 998u ? 998u : 87u; return 1;
        }
        for (slot = 0u; slot < WIN_GUI_CLASSES; ++slot) {
            c = &process->gui_classes[slot];
            if (c->active && win_reg_name_equal(c->name, value.name) &&
                (c->instance == value.instance || (c->style & 0x4000u) || (value.style & 0x4000u))) {
                process->last_error = 1410u; return 1;
            }
        }
        for (slot = 0u; slot < WIN_GUI_CLASSES && process->gui_classes[slot].active; ++slot) {}
        if (slot == WIN_GUI_CLASSES || process->gui_class_sequence >= 0x4000u) { process->last_error = 8u; return 1; }
        if (menu > 0xffffu) {
            error = win_reg_name(process, menu, wide, menu_name, 256u, 0);
            if (error) { process->last_error = error == 998u ? 998u : 87u; return 1; }
            value.menu_named = 1u;
        } else value.menu_atom = menu;
        for (i = 0u; i < 256u; ++i) {
            strings[i] = win_reg_unansi(value.name[i]); win_put16(strings + 256u + i * 2u, value.name[i]);
            strings[768u + i] = win_reg_unansi(menu_name[i]); win_put16(strings + 1024u + i * 2u, menu_name[i]);
        }
        value.strings = win_heap_alloc(process, sizeof(strings) + value.class_extra);
        if (!value.strings) { process->last_error = 8u; return 1; }
        /* These are class-owned strings, not a caller HeapAlloc block. */
        { win_allocation *allocation = win_find_allocation(process, value.strings); if (allocation) allocation->heap_owner = UINT64_MAX; }
        if (!win_write(process, value.strings, strings, sizeof(strings))) {
            win_allocation *allocation = win_find_allocation(process, value.strings);
            if (allocation) allocation->active = 0u;
            process->last_error = 998u; return 1;
        }
        if (value.class_extra) memset(process->emulator->region_data + (size_t)(value.strings + sizeof(strings) - process->emulator->region_address), 0, value.class_extra);
        value.active = 1u; value.wide = (uint8_t)wide; value.atom = (uint16_t)(0xc000u + process->gui_class_sequence++);
        process->gui_classes[slot] = value; *result = value.atom; return 1;
    }
    if (win_equal(api, "GetClassInfoA") || win_equal(api, "GetClassInfoW") ||
        win_equal(api, "GetClassInfoExA") || win_equal(api, "GetClassInfoExW")) {
        uint8_t output[80] = {0}; uint64_t fields[6], caller_size;
        c = win_gui_class_find(process, arg[0], arg[1], wide, &error);
        if (!c) { process->last_error = error; return 1; }
        if (!win_memory_span(process, arg[2], size)) { process->last_error = 998u; return 1; }
        if (extended && (!win_load(process, arg[2], 4u, &caller_size) || caller_size != size)) {
            process->last_error = 87u; return 1;
        }
        if (extended) { win_put32(output, size); win_put32(output + 4u, c->style); }
        else win_put32(output, c->style);
        if (width == 8u) win_put64(output + proc_offset, c->procedure); else win_put32(output + proc_offset, (uint32_t)c->procedure);
        win_put32(output + extra_offset, c->class_extra); win_put32(output + extra_offset + 4u, c->window_extra);
        fields[0] = c->instance; fields[1] = c->icon; fields[2] = c->cursor; fields[3] = c->brush;
        fields[4] = c->menu_named ? c->strings + (wide ? 1024u : 768u) : c->menu_atom;
        fields[5] = c->strings + (wide ? 256u : 0u);
        for (i = 0u; i < 6u; ++i) {
            if (width == 8u) win_put64(output + instance_offset + i * width, fields[i]);
            else win_put32(output + instance_offset + i * width, (uint32_t)fields[i]);
        }
        if (extended) {
            if (width == 8u) win_put64(output + instance_offset + 6u * width, c->small_icon);
            else win_put32(output + instance_offset + 6u * width, (uint32_t)c->small_icon);
        }
        if (!win_write(process, arg[2], output, size)) { process->last_error = 998u; return 1; }
        *result = 1u; return 1;
    }
    if (win_equal(api, "UnregisterClassA") || win_equal(api, "UnregisterClassW")) {
        c = win_gui_class_find(process, arg[1], arg[0], wide, &error);
        if (!c) { process->last_error = error; return 1; }
        if (c->instance != arg[1]) { process->last_error = 1411u; return 1; }
        for (i = 0u; i < WIN_GUI_OBJECTS; ++i)
            if (process->gui_objects[i].active && process->gui_objects[i].class_ordinal == c->atom) {
                process->last_error = 1412u; return 1;
            }
        { win_allocation *allocation = win_find_allocation(process, c->strings); if (allocation) allocation->active = 0u; }
        memset(c, 0, sizeof(*c)); *result = 1u; return 1;
    }
    return 0;
}
