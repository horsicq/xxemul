/* Bounded process-local file sections. Included after the handle primitives.
 * One live view per section/backing file is supported; additional simultaneous
 * views fail explicitly rather than pretending independent copies are coherent.
 * The existing flat Windows memory model does not enforce page permissions. */
static int win_mapping_flush(xxemul_windows *process, win_handle *mapping, uint64_t address, uint64_t length)
{
    uint64_t offset, count;
    uint8_t *bytes;
    if (!mapping->view_address || address < mapping->view_address ||
        address - mapping->view_address >= mapping->view_size) { process->last_error = 487u; return 0; }
    offset = address - mapping->view_address;
    count = length ? length : mapping->view_size - offset;
    if (count > mapping->view_size - offset) { process->last_error = 87u; return 0; }
    if (!(mapping->view_access & 2u) || (mapping->view_access & 1u)) return 1;
    bytes = process->emulator->region_data + (size_t)(address - process->emulator->region_address);
    if (mapping->io && (xx_io_seek64(mapping->io, (int64_t)(mapping->view_offset + offset), SEEK_SET) != 0 ||
                        xx_io_write(mapping->io, bytes, (size_t)count) != (int64_t)count ||
                        xx_io_seek64(mapping->io, 0, SEEK_CUR) != 0)) {
        process->last_error = 29u; return 0;
    }
    memcpy(mapping->mapping_data + mapping->view_offset + offset, bytes, (size_t)count);
    return 1;
}

static uint64_t win_mapping_create(xxemul_windows *process, const char *api_name, const uint64_t *arg)
{
    uint64_t size = ((uint64_t)(uint32_t)arg[3] << 32u) | (uint32_t)arg[4];
    uint32_t protect = (uint32_t)arg[2] & 0xffu;
    uint32_t extra = (uint32_t)arg[2] & ~0xffu;
    uint64_t invalid = win_word_size(process->emulator) == 8u ? UINT64_MAX : UINT32_MAX;
    win_handle *file = NULL, *entry;
    xx_io_device *backing = NULL;
    uint8_t *data;
    char name[128] = {0};
    size_t slot, index;
    int writable = protect == 4u || protect == 0x40u;
    if (arg[5] && !win_guest_string(process, arg[5], name, sizeof(name), win_suffix(api_name, "W"))) {
        process->last_error = 998u; return 0;
    }
    if (*name) for (index = 0u; index < WIN_MAX_HANDLES; ++index) {
        win_handle *existing = &process->handles[index];
        uint64_t handle;
        size_t alias;
        if (!existing->in_use || existing->kind == WIN_HANDLE_ALIAS || strcmp(existing->name, name)) continue;
        if (existing->kind != WIN_HANDLE_MAPPING) { process->last_error = 6u; return 0; }
        handle = existing->closed ? 0u : 0x100u + index;
        for (alias = 0u; !handle && alias < WIN_MAX_HANDLES; ++alias)
            if (process->handles[alias].in_use && process->handles[alias].kind == WIN_HANDLE_ALIAS &&
                process->handles[alias].root_slot == index) handle = 0x100u + alias;
        handle = handle ? win_duplicate_handle(process, handle, 0) : 0u;
        process->last_error = handle ? 183u : 4u;
        return handle;
    }
    if (extra != 0u && extra != 0x8000000u) { process->last_error = 50u; return 0; }
    if (protect != 2u && protect != 4u && protect != 8u && protect != 0x20u && protect != 0x40u && protect != 0x80u) {
        process->last_error = 87u; return 0;
    }
    if (arg[0] != invalid) {
        int64_t file_size;
        file = win_handle_at(process, arg[0]);
        if (!file || file->kind != WIN_HANDLE_FILE || !file->io || !*file->file_path) { process->last_error = 6u; return 0; }
        if (!(file->file_access & 0x80000000u) || (writable && !(file->file_access & 0x40000000u))) {
            process->last_error = 5u; return 0;
        }
        file_size = xx_io_total_size(file->io);
        if (file_size < 0) { process->last_error = 6u; return 0; }
        if (!size) size = (uint64_t)file_size;
        if (!size) { process->last_error = 1006u; return 0; }
        if (size > (uint64_t)file_size && !writable) { process->last_error = 5u; return 0; }
    } else if (!size) { process->last_error = 87u; return 0; }
    if (size > WIN_MAX_IO) { process->last_error = 8u; return 0; }
    for (slot = 0u; slot < WIN_MAX_HANDLES && process->handles[slot].in_use; ++slot) {}
    if (slot == WIN_MAX_HANDLES) { process->last_error = 4u; return 0; }
    data = (uint8_t *)calloc(1u, (size_t)size);
    if (!data) { process->last_error = 8u; return 0; }
    if (file) {
        backing = xx_io_file_open(file->file_path, writable ? "r+b" : "rb");
        if (!backing) { free(data); process->last_error = 5u; return 0; }
        if ((uint64_t)xx_io_total_size(backing) < size && xx_io_resize(backing, (int64_t)size) != 0) {
            xx_io_close(backing); free(data); process->last_error = 112u; return 0;
        }
        if (!xx_io_read_at(backing, 0, data, (size_t)size)) {
            xx_io_close(backing); free(data); process->last_error = 30u; return 0;
        }
    }
    entry = &process->handles[slot];
    memset(entry, 0, sizeof(*entry));
    entry->kind = WIN_HANDLE_MAPPING;
    entry->mapping_size = size;
    entry->mapping_protect = protect;
    entry->mapping_data = data;
    entry->io = backing;
    entry->references = 1u;
    entry->root_slot = (uint16_t)slot;
    entry->in_use = 1u;
    (void)win_copy(entry->name, sizeof(entry->name), name);
    if (file) (void)win_copy(entry->file_path, sizeof(entry->file_path), file->file_path);
    process->last_error = 0u;
    return 0x100u + slot;
}

static uint64_t win_mapping_view(xxemul_windows *process, const char *api_name, const uint64_t *arg)
{
    win_handle *entry = win_handle_at(process, arg[0]);
    uint64_t offset = ((uint64_t)(uint32_t)arg[2] << 32u) | (uint32_t)arg[3];
    uint64_t count = arg[4], allocation, address, reference;
    uint32_t access = (uint32_t)arg[1];
    size_t index;
    if (!entry || entry->kind != WIN_HANDLE_MAPPING) { process->last_error = 6u; return 0; }
    if (strcmp(api_name, "MapViewOfFileEx") == 0 && arg[5]) { process->last_error = 50u; return 0; }
    if (access == 0xf001fu) access = 2u;
    if (!(access & 7u) || (access & ~0x27u) || ((access & 1u) && (access & 2u))) { process->last_error = 87u; return 0; }
    if (((access & 2u) && entry->mapping_protect != 4u && entry->mapping_protect != 0x40u) ||
        ((access & 0x20u) && entry->mapping_protect < 0x20u)) { process->last_error = 5u; return 0; }
    if (offset & 0xffffu) { process->last_error = 1132u; return 0; }
    if (offset >= entry->mapping_size) { process->last_error = 87u; return 0; }
    if (!count) count = entry->mapping_size - offset;
    if (count > entry->mapping_size - offset) { process->last_error = 87u; return 0; }
    for (index = 0u; index < WIN_MAX_HANDLES; ++index) {
        win_handle *other = &process->handles[index];
        if (other->kind == WIN_HANDLE_MAPPING && other->view_address &&
            (other == entry || (*entry->file_path && !strcmp(other->file_path, entry->file_path)))) {
            process->last_error = 50u; return 0;
        }
    }
    reference = win_duplicate_handle(process, arg[0], 0);
    if (!reference) { process->last_error = 4u; return 0; }
    allocation = win_heap_alloc(process, count + 0xffffu);
    if (!allocation) { (void)win_close_handle(process, reference); process->last_error = 8u; return 0; }
    address = (allocation + 0xffffu) & ~UINT64_C(0xffff);
    if (entry->io && !xx_io_read_at(entry->io, (int64_t)offset, entry->mapping_data + offset, (size_t)count)) {
        win_find_allocation(process, allocation)->active = 0u;
        (void)win_close_handle(process, reference); process->last_error = 30u; return 0;
    }
    if (!win_write(process, address, entry->mapping_data + offset, (size_t)count)) {
        win_find_allocation(process, allocation)->active = 0u;
        (void)win_close_handle(process, reference); process->last_error = 998u; return 0;
    }
    entry->view_address = address;
    entry->view_allocation = allocation;
    entry->view_size = count;
    entry->view_offset = offset;
    entry->view_access = access;
    entry->view_reference = reference;
    process->last_error = 0u;
    return address;
}

static int win_mapping_release(xxemul_windows *process, uint64_t address, uint64_t length, int unmap)
{
    size_t index;
    for (index = 0u; index < WIN_MAX_HANDLES; ++index) {
        win_handle *entry = &process->handles[index];
        if (entry->kind != WIN_HANDLE_MAPPING || !entry->view_address || address < entry->view_address ||
            address - entry->view_address >= entry->view_size) continue;
        if (unmap && address != entry->view_address) break;
        if (!win_mapping_flush(process, entry, address, length)) return 0;
        if (unmap) {
            win_allocation *allocation = win_find_allocation(process, entry->view_allocation);
            uint64_t reference = entry->view_reference;
            if (allocation) allocation->active = 0u;
            entry->view_address = entry->view_reference = entry->view_allocation = 0u;
            (void)win_close_handle(process, reference);
        }
        return 1;
    }
    process->last_error = 487u;
    return 0;
}
