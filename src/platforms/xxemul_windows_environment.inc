/* Process-local environment and virtual CWD. Included after the path/CP1252
 * helpers; no host process environment or host chdir is used. */
static int win_set_guest_directory(xxemul_windows *process, const char *guest)
{
    char host[2048], root[2048], normalized[1024];
    size_t root_length, suffix_length, i, length;
    uint8_t width = win_word_size(process->emulator);
    uint64_t descriptor = process->runtime_base + 0x4000u + (width == 8u ? 0x38u : 0x24u);
    if (!guest || !*guest) { process->last_error = 87u; return 0; }
    if (!win_guest_path(process, guest, host, sizeof(host)) || !win_working_root(process, root, sizeof(root))) {
        process->last_error = 3u; return 0;
    }
#if defined(_WIN32)
    {
        DWORD attributes = GetFileAttributesA(host);
        if (attributes == INVALID_FILE_ATTRIBUTES) { process->last_error = GetLastError(); return 0; }
        if (!(attributes & FILE_ATTRIBUTE_DIRECTORY)) { process->last_error = 267u; return 0; }
    }
#else
    {
        struct stat attributes;
        if (stat(host, &attributes)) { process->last_error = errno == EACCES ? 5u : 3u; return 0; }
        if (!S_ISDIR(attributes.st_mode)) { process->last_error = 267u; return 0; }
    }
#endif
    root_length = strlen(root);
    while (root_length > 1u && root[root_length - 1u] == '/') --root_length;
    if (strncmp(host, root, root_length) || (host[root_length] && host[root_length] != '/')) {
        process->last_error = 5u; return 0;
    }
    suffix_length = strlen(host + root_length);
    if (suffix_length && host[root_length] == '/') --suffix_length;
    if (suffix_length > sizeof(normalized) - 4u) { process->last_error = 206u; return 0; }
    memcpy(normalized, "C:\\", 4u);
    for (i = 0u; i < suffix_length; ++i) {
        char character = host[root_length + 1u + i];
        normalized[3u + i] = character == '/' ? '\\' : character;
    }
    normalized[3u + suffix_length] = 0;
    length = strlen(normalized);
    if (!win_write_wide(process, process->runtime_base + 0x18c00u, normalized, 1024u) ||
        !win_store(process, descriptor, 2u, length * 2u) ||
        !win_store(process, descriptor + 2u, 2u, (length + 1u) * 2u) ||
        !win_store(process, descriptor + (width == 8u ? 8u : 4u), width, process->runtime_base + 0x18c00u)) {
        process->last_error = 998u; return 0;
    }
    memcpy(process->guest_directory, normalized, length + 1u);
    return 1;
}

/* The existing environment block uses the modeled ANSI code page (1252).
 * Unrepresentable Unicode fails explicitly rather than silently changing it. */
static int win_environment_text(xxemul_windows *process, uint64_t address, int wide, char *out, size_t capacity)
{
    size_t i;
    if (!address) { process->last_error = 87u; return 0; }
    for (i = 0u; i < capacity; ++i) {
        uint64_t value;
        uint8_t encoded;
        if (address > UINT64_MAX - i * (wide ? 2u : 1u) ||
            !win_load(process, address + i * (wide ? 2u : 1u), wide ? 2u : 1u, &value)) {
            process->last_error = 998u; return 0;
        }
        encoded = wide ? win_reg_unansi((uint16_t)value) : (uint8_t)value;
        if (wide && win_reg_ansi(encoded) != value) { process->last_error = 1113u; return 0; }
        out[i] = (char)encoded;
        if (!value) return 1;
    }
    process->last_error = 206u;
    return 0;
}

static xxemul_status win_environment_call(xxemul_windows *process, const char *name, const uint64_t *arg, uint64_t *result)
{
    char key[WIN_ENV_MAX_BYTES], value[WIN_ENV_MAX_BYTES];
    int wide = win_suffix(name, "W");
    size_t offset = 0u, length, i;
    *result = 0u;
    if (!win_environment_text(process, arg[0], wide, key, sizeof(key))) return XXEMUL_STATUS_OK;
    if (!key[0] || strchr(key, '=')) { process->last_error = 87u; return XXEMUL_STATUS_OK; }
    if (win_prefix(name, "SetEnvironmentVariable")) {
        xxemul_status status;
        if (arg[1] && !win_environment_text(process, arg[1], wide, value, sizeof(value))) return XXEMUL_STATUS_OK;
        status = xxemul_windows_set_environment(process, key, arg[1] ? value : NULL);
        if (status == XXEMUL_STATUS_OK) *result = 1u;
        else process->last_error = status == XXEMUL_STATUS_OUT_OF_MEMORY ? 8u : 998u;
        return XXEMUL_STATUS_OK;
    }
    while (offset + 1u < process->environment_size && process->environment_data[offset]) {
        const char *entry = process->environment_data + offset;
        if (win_environment_match(entry, key)) {
            const char *contents = strchr(entry, '=') + 1u;
            length = strlen(contents);
            if ((uint32_t)arg[2] <= length) { *result = length + 1u; return XXEMUL_STATUS_OK; }
            if (!arg[1] || !win_memory_span(process, arg[1], (length + 1u) * (wide ? 2u : 1u))) {
                process->last_error = 998u; return XXEMUL_STATUS_OK;
            }
            if (wide) {
                for (i = 0u; i <= length; ++i)
                    if (!win_store(process, arg[1] + i * 2u, 2u, win_reg_ansi((uint8_t)contents[i]))) return XXEMUL_STATUS_ADDRESS_FAULT;
            } else if (!win_write(process, arg[1], contents, length + 1u)) return XXEMUL_STATUS_ADDRESS_FAULT;
            *result = length;
            if (!length) process->last_error = 0u;
            return XXEMUL_STATUS_OK;
        }
        offset += strlen(entry) + 1u;
    }
    process->last_error = 203u;
    return XXEMUL_STATUS_OK;
}

static xxemul_status win_current_directory_call(xxemul_windows *process, const char *name, const uint64_t *arg, uint64_t *result)
{
    int wide = win_suffix(name, "W");
    size_t length = strlen(process->guest_directory);
    char directory[1024];
    *result = 0u;
    if (win_prefix(name, "SetCurrentDirectory")) {
        if (!arg[0] || !win_guest_string(process, arg[0], directory, sizeof(directory), wide)) {
            process->last_error = arg[0] ? 998u : 87u; return XXEMUL_STATUS_OK;
        }
        *result = win_set_guest_directory(process, directory) ? 1u : 0u;
        return XXEMUL_STATUS_OK;
    }
    if ((uint32_t)arg[0] <= length) { *result = length + 1u; return XXEMUL_STATUS_OK; }
    if (!arg[1] || !win_memory_span(process, arg[1], (length + 1u) * (wide ? 2u : 1u))) {
        process->last_error = 998u; return XXEMUL_STATUS_OK;
    }
    if (wide) {
        if (!win_write_wide(process, arg[1], process->guest_directory, length + 1u)) return XXEMUL_STATUS_ADDRESS_FAULT;
    } else if (!win_write(process, arg[1], process->guest_directory, length + 1u)) return XXEMUL_STATUS_ADDRESS_FAULT;
    *result = length;
    return XXEMUL_STATUS_OK;
}
