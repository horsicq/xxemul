/* Bounded static TLS image storage and callback-table admission.
 * Included after the core memory/allocation helpers. Guest callbacks are
 * dispatched separately; no guest pointer is ever called as a host pointer.
 */
static int win_tls_guest_span(const xxemul_windows *process, uint64_t address, uint64_t size)
{
    uint64_t region = process->emulator->region_address;
    uint64_t extent = process->emulator->region_size;
    return address >= region && size <= extent && address - region <= extent - size;
}

static int win_tls_image_span(const win_tls_image *tls, uint64_t address, uint64_t size)
{
    return address >= tls->base && size <= tls->image_size &&
           address - tls->base <= tls->image_size - size;
}

static int win_tls_callback_at(xxemul_windows *process, const win_tls_image *tls,
                               unsigned index, uint64_t *callback)
{
    uint8_t width = win_word_size(process->emulator);
    uint64_t address, offset = (uint64_t)index * width;
    *callback = 0u;
    if (index > WIN_MAX_TLS_CALLBACKS) return 0;
    if (!tls->callbacks) return 1;
    if (tls->callbacks > UINT64_MAX - offset) return 0;
    address = tls->callbacks + offset;
    if (!win_tls_image_span(tls, address, width) ||
        !win_load(process, address, width, callback)) return 0;
    /* The cap counts nonnull callbacks, not the required terminator. */
    if (*callback && (index == WIN_MAX_TLS_CALLBACKS ||
                      !win_tls_guest_span(process, *callback, 1u))) return 0;
    return 1;
}

static void win_tls_deallocate(xxemul_windows *process, uint64_t allocation)
{
    win_allocation *block;
    if (!allocation) return;
    block = win_find_allocation(process, allocation);
    if (block) block->active = 0u;
}

static int win_tls_clear(xxemul_windows *process, uint64_t address, size_t size)
{
    static const uint8_t zeroes[256] = {0};
    while (size) {
        size_t amount = size < sizeof(zeroes) ? size : sizeof(zeroes);
        if (!win_write(process, address, zeroes, amount)) return 0;
        address += amount;
        size -= amount;
    }
    return 1;
}

static int win_tls_allocate_block(xxemul_windows *process, const win_tls_image *tls,
                                   uint64_t *allocation, uint64_t *data)
{
    size_t amount = tls->data_size ? tls->data_size : win_word_size(process->emulator);
    size_t alignment = tls->alignment ? tls->alignment : 1u;
    uint64_t raw;
    *allocation = *data = 0u;
    if (amount > WIN_MAX_IO || alignment > 8192u || (alignment & (alignment - 1u)) ||
        amount > SIZE_MAX - (alignment - 1u)) {
        process->last_error = 193u;
        return 0;
    }
    raw = win_heap_alloc(process, amount + alignment - 1u);
    if (!raw) { process->last_error = 8u; return 0; }
    if (raw > UINT64_MAX - (alignment - 1u)) {
        win_tls_deallocate(process, raw);
        process->last_error = 193u;
        return 0;
    }
    *data = (raw + alignment - 1u) & ~((uint64_t)alignment - 1u);
    if (!win_tls_guest_span(process, *data, amount) ||
        !win_tls_clear(process, *data, amount) ||
        (tls->data_size && (!tls->template_data ||
          !win_write(process, *data, tls->template_data, tls->data_size)))) {
        win_tls_deallocate(process, raw);
        *data = 0u;
        process->last_error = 193u;
        return 0;
    }
    *allocation = raw;
    return 1;
}

static void win_tls_thread_release(xxemul_windows *process, win_thread_context *thread)
{
    size_t index;
    for (index = 0u; index < WIN_STATIC_TLS_SLOTS; ++index) {
        win_tls_deallocate(process, thread->static_tls_allocations[index]);
        thread->static_tls_allocations[index] = 0u;
    }
    win_tls_deallocate(process, thread->tls_allocation);
    thread->tls_allocation = thread->tls_array = 0u;
}

static int win_tls_thread_create(xxemul_windows *process, win_thread_context *thread)
{
    uint8_t width = win_word_size(process->emulator);
    uint64_t allocations[WIN_STATIC_TLS_SLOTS] = {0};
    uint64_t vector, data;
    uint32_t seen = 0u;
    size_t index, image;
    if (thread->tls_allocation) { process->last_error = 193u; return 0; }
    vector = win_heap_alloc(process, WIN_STATIC_TLS_SLOTS * width);
    if (!vector) { process->last_error = 8u; return 0; }
    if (!win_tls_clear(process, vector, WIN_STATIC_TLS_SLOTS * width)) {
        process->last_error = 193u;
        goto failed;
    }
    for (image = 0u; image <= process->module_count; ++image) {
        const win_tls_image *tls;
        if (!image) tls = &process->main_tls;
        else {
            const win_module *module = &process->modules[image - 1u];
            if (!module->real || !module->live || module->data_only) continue;
            tls = &module->tls;
        }
        if (!tls->present && !tls->data_size) continue;
        index = tls->index;
        if (index >= WIN_STATIC_TLS_SLOTS || (seen & (UINT32_C(1) << index))) {
            process->last_error = 193u;
            goto failed;
        }
        seen |= UINT32_C(1) << index;
        if (!win_tls_allocate_block(process, tls, &allocations[index], &data)) goto failed;
        if (!win_store(process, vector + index * width, width, data)) {
            process->last_error = 193u;
            goto failed;
        }
    }
    thread->tls_array = thread->tls_allocation = vector;
    memcpy(thread->static_tls_allocations, allocations, sizeof(allocations));
    return 1;
failed:
    for (index = 0u; index < WIN_STATIC_TLS_SLOTS; ++index)
        win_tls_deallocate(process, allocations[index]);
    win_tls_deallocate(process, vector);
    return 0;
}

static void win_tls_release_image(xxemul_windows *process, win_tls_image *tls)
{
    size_t thread;
    if ((tls->present || tls->data_size || tls->template_data) && tls->index < WIN_STATIC_TLS_SLOTS) {
        uint8_t width = win_word_size(process->emulator);
        for (thread = 0u; thread < WIN_MAX_THREADS; ++thread) {
            win_thread_context *context = &process->threads[thread];
            if (context->tls_array && win_tls_guest_span(process,
                  context->tls_array + (uint64_t)tls->index * width, width))
                (void)win_store(process, context->tls_array + (uint64_t)tls->index * width, width, 0u);
            win_tls_deallocate(process, context->static_tls_allocations[tls->index]);
            context->static_tls_allocations[tls->index] = 0u;
        }
    }
    free(tls->template_data);
    memset(tls, 0, sizeof(*tls));
}

static int win_tls_bind_image(xxemul_windows *process, win_tls_image *tls,
                              uint64_t base, uint64_t image_size, uint32_t rva,
                              uint32_t dirsize, uint32_t index, int main_image)
{
    win_tls_image candidate;
    uint8_t directory[40], width = win_word_size(process->emulator);
    uint64_t start = 0u, end = 0u, index_address = 0u, old_index = 0u;
    uint64_t allocations[WIN_MAX_THREADS] = {0}, data[WIN_MAX_THREADS] = {0};
    uint64_t old_cells[WIN_MAX_THREADS] = {0};
    uint32_t zero_fill = 0u, alignment_bits = 0u;
    size_t thread, published = 0u;
    int index_published = 0;
    memset(&candidate, 0, sizeof(candidate));
    if (tls->present || tls->data_size || tls->template_data || index >= WIN_STATIC_TLS_SLOTS ||
        !image_size || !win_tls_guest_span(process, base, image_size)) goto invalid;
    candidate.base = base;
    candidate.image_size = image_size;
    candidate.index = index;
    candidate.alignment = width;
    if (!rva) {
        if (dirsize) goto invalid;
        if (!main_image) { *tls = candidate; return 1; }
        candidate.data_size = width;
    } else {
        size_t required = width == 8u ? 40u : 24u;
        uint64_t raw_size, total;
        unsigned callback_index;
        /* Native loaders accept an omitted TLS DataDirectory size. The
         * directory structure must still fit fully inside this image. */
        if (rva > image_size || required > image_size - rva ||
            (dirsize && (dirsize < required || dirsize > image_size - rva)) ||
            !win_read(process, base + rva, directory, required)) goto invalid;
        start = width == 8u ? win_le64(directory) : win_le32(directory);
        end = width == 8u ? win_le64(directory + 8u) : win_le32(directory + 4u);
        index_address = width == 8u ? win_le64(directory + 16u) : win_le32(directory + 8u);
        candidate.callbacks = width == 8u ? win_le64(directory + 24u) : win_le32(directory + 12u);
        zero_fill = win_le32(directory + (width == 8u ? 32u : 16u));
        alignment_bits = (win_le32(directory + (width == 8u ? 36u : 20u)) >> 20u) & 15u;
        if (end < start || alignment_bits == 15u) goto invalid;
        raw_size = end - start;
        if (raw_size > WIN_MAX_IO || zero_fill > WIN_MAX_IO - raw_size) goto invalid;
        total = raw_size + zero_fill;
        if ((raw_size && !win_tls_image_span(&candidate, start, raw_size)) ||
            (index_address && !win_tls_image_span(&candidate, index_address, 4u)) ||
            (total && !index_address)) goto invalid;
        candidate.present = 1u;
        candidate.data_size = (size_t)total;
        candidate.alignment = alignment_bits ? (size_t)1u << (alignment_bits - 1u) : 16u;
        for (callback_index = 0u; callback_index <= WIN_MAX_TLS_CALLBACKS; ++callback_index) {
            uint64_t callback;
            if (!win_tls_callback_at(process, &candidate, callback_index, &callback)) goto invalid;
            if (!callback) break;
            if (process->emulator->arch != XXEMUL_ARCH_X86) goto invalid;
        }
    }
    candidate.template_data = (uint8_t *)calloc(candidate.data_size ? candidate.data_size : width, 1u);
    if (!candidate.template_data) { process->last_error = 8u; goto failed; }
    if (end > start && !win_read(process, start, candidate.template_data, (size_t)(end - start))) goto invalid;
    if (index_address && !win_load(process, index_address, 4u, &old_index)) goto invalid;
    for (thread = 0u; thread < WIN_MAX_THREADS; ++thread) {
        win_thread_context *context = &process->threads[thread];
        uint64_t cell;
        if (!context->active) continue;
        cell = context->tls_array + (uint64_t)index * width;
        if (!context->tls_array || context->static_tls_allocations[index] ||
            !win_tls_guest_span(process, cell, width) || !win_load(process, cell, width, &old_cells[thread])) goto invalid;
        if (!win_tls_allocate_block(process, &candidate, &allocations[thread], &data[thread])) goto failed;
    }
    /* All host/guest allocations are ready before any public TLS cell or
     * AddressOfIndex changes. Restore both on a failed publication. */
    if (index_address) {
        if (!win_store(process, index_address, 4u, index)) goto invalid;
        index_published = 1;
    }
    for (thread = 0u; thread < WIN_MAX_THREADS; ++thread) {
        if (!process->threads[thread].active) continue;
        if (!win_store(process, process->threads[thread].tls_array + (uint64_t)index * width, width, data[thread])) goto invalid;
        published = thread + 1u;
    }
    *tls = candidate;
    for (thread = 0u; thread < WIN_MAX_THREADS; ++thread)
        if (allocations[thread]) process->threads[thread].static_tls_allocations[index] = allocations[thread];
    return 1;
invalid:
    process->last_error = 193u;
failed:
    for (thread = 0u; thread < published; ++thread)
        if (process->threads[thread].active)
            (void)win_store(process, process->threads[thread].tls_array + (uint64_t)index * width, width, old_cells[thread]);
    if (index_published) (void)win_store(process, index_address, 4u, old_index);
    for (thread = 0u; thread < WIN_MAX_THREADS; ++thread) win_tls_deallocate(process, allocations[thread]);
    free(candidate.template_data);
    return 0;
}
