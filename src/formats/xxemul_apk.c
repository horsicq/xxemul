#include "../xxemul_dex_internal.h"

#include <xxfclib/formats/apk/xx_apk.h>
#include <xxfclib/io/xx_io.h>
#include <xxfclib/memory/xx_memory.h>

#include <stdlib.h>
#include <string.h>

#define APK_DEX_LIMIT ((size_t)256 * 1024 * 1024)
#define APK_TOTAL_LIMIT ((size_t)1024 * 1024 * 1024)

static int apk_copy_metadata(char **destination, const char *source) {
    size_t size;
    if (!source || !*source) return 1;
    size = strlen(source) + 1;
    *destination = (char *)malloc(size);
    if (!*destination) return 0;
    memcpy(*destination, source, size);
    return 1;
}

xxemul_dex_program *xxemul_dex_create_apk(const void *data, size_t size, xxemul_status *status) {
    xxemul_dex_program *program = NULL;
    xx_io_device *device = NULL;
    xx_apk apk;
    size_t i, count, total = 0;
    xxemul_status result = XXEMUL_STATUS_INVALID_IMAGE;
    int initialized = 0;
    if (status) *status = XXEMUL_STATUS_INVALID_ARGUMENT;
    if (!data || !size) return NULL;
    if (size > APK_TOTAL_LIMIT) goto done;
    device = xx_io_mem_open_ro(data, size);
    if (!device) { result = XXEMUL_STATUS_OUT_OF_MEMORY; goto done; }
    xx_apk_init(&apk, device, 0); initialized = 1;
    /* xxfclib owns APK discovery and verifies selected members' size and
     * CRC. Extraction stays in memory, never archive-derived output paths. */
    if (!xx_apk_handle_base_info(xx_apk_to_format(&apk), NULL) || !xx_apk_analyze_dex(&apk, NULL)) goto done;
    count = xx_apk_get_dex_count(&apk);
    if (!count || count > 128 || strcmp(xx_apk_get_dex_name(&apk, 0), "classes.dex")) goto done;
    program = (xxemul_dex_program *)calloc(1, sizeof(*program));
    if (!program) { result = XXEMUL_STATUS_OUT_OF_MEMORY; goto done; }
    program->is_apk = 1;
    for (i = 0; i < count; ++i) {
        uint8_t *decoded = NULL;
        size_t decoded_size = 0;
        const char *name = xx_apk_get_dex_name(&apk, i);
        if (!xx_apk_read_dex(&apk, i, APK_DEX_LIMIT, &decoded, &decoded_size, NULL)) goto done;
        if (decoded_size > APK_TOTAL_LIMIT - total) { xx_mem_free(decoded); goto done; }
        total += decoded_size;
        result = xxemul_dex_append(program, decoded, decoded_size, name);
        xx_mem_free(decoded);
        if (result != XXEMUL_STATUS_OK) goto done;
        /* A later failing member must not reuse the previous success. */
        result = XXEMUL_STATUS_INVALID_IMAGE;
    }
    if (xx_apk_analyze(&apk, NULL)) {
        if (!apk_copy_metadata(&program->manifest, xx_apk_get_manifest(&apk)) ||
            !apk_copy_metadata(&program->package_name, xx_apk_get_package_name(&apk)) ||
            !apk_copy_metadata(&program->launcher_activity, xx_apk_get_launcher_activity(&apk))) {
            result = XXEMUL_STATUS_OUT_OF_MEMORY; goto done;
        }
    }
    result = XXEMUL_STATUS_OK;
done:
    if (initialized) xx_apk_destroy(&apk);
    if (device) xx_io_close(device);
    if (result != XXEMUL_STATUS_OK) { xxemul_dex_destroy(program); program = NULL; }
    if (status) *status = result;
    return program;
}
