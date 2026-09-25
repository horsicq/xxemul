#include "xxemul_viewer_app.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int xxemul_viewer_app_init(
    xxemul_viewer_app *app, int argc, char **argv)
{
    static const uint8_t demo_image[] = {
        0xba, 0x0c, 0x01, 0xb4, 0x09, 0xcd, 0x21,
        0xb8, 0x00, 0x4c, 0xcd, 0x21,
        'x', 'x', 'e', 'm', 'u', 'l', ' ', 'D', 'O', 'S', ' ',
        'd', 'e', 'm', 'o', '$'
    };
    xxemul_dos_format format;
    xxemul_status status;

    if (app == NULL) {
        return 1;
    }
    memset(app, 0, sizeof(*app));
    if (!((argc == 2 && strcmp(argv[1], "demo") == 0)
        || (argc == 3 && (strcmp(argv[1], "com") == 0
            || strcmp(argv[1], "mz") == 0)))) {
        fprintf(stderr, "usage: xxemul_viewer demo | com|mz <file>\n");
        return 2;
    }
    if (argc == 2) {
        app->emulator = xxemul_create_dos(
            XXEMUL_DOS_COM, demo_image, sizeof(demo_image), &status);
    } else {
        format = strcmp(argv[1], "com") == 0
            ? XXEMUL_DOS_COM : XXEMUL_DOS_MZ;
        app->emulator = xxemul_create_dos_file(
            format, argv[2], &status);
    }
    if (app->emulator == NULL) {
        fprintf(stderr, "load failed: %s\n", xxemul_status_string(status));
        return 1;
    }
    app->pixels = (uint32_t *)malloc(
        XXEMUL_DISPLAY_WIDTH * XXEMUL_DISPLAY_HEIGHT
        * sizeof(*app->pixels));
    if (app->pixels == NULL) {
        xxemul_viewer_app_destroy(app);
        fprintf(stderr, "display allocation failed\n");
        return 1;
    }
    app->last_status = XXEMUL_STATUS_OK;
    app->running = 1;
    return 0;
}

void xxemul_viewer_app_destroy(xxemul_viewer_app *app)
{
    if (app == NULL) {
        return;
    }
    free(app->pixels);
    xxemul_destroy(app->emulator);
    memset(app, 0, sizeof(*app));
}

void xxemul_viewer_app_tick(xxemul_viewer_app *app)
{
    unsigned index;
    xxemul_status status = XXEMUL_STATUS_OK;

    if (app == NULL || !app->running) {
        return;
    }
    for (index = 0u; index < 5000u; ++index) {
        status = xxemul_step(app->emulator, NULL);
        if (status != XXEMUL_STATUS_OK) {
            break;
        }
    }
    if (status == XXEMUL_STATUS_HALTED) {
        xxemul_dos_get_exit_code(app->emulator, &app->exit_code);
        app->running = 0;
    } else if (status != XXEMUL_STATUS_OK
        && status != XXEMUL_STATUS_INPUT_REQUIRED) {
        app->running = 0;
    }
    app->last_status = status;
}

void xxemul_viewer_app_title(
    const xxemul_viewer_app *app, char *buffer, size_t buffer_size)
{
    if (buffer == NULL || buffer_size == 0u) {
        return;
    }
    if (app == NULL || app->running) {
        snprintf(buffer, buffer_size, "xxemul");
    } else if (app->last_status == XXEMUL_STATUS_HALTED) {
        snprintf(buffer, buffer_size, "xxemul - exited (%u)",
            app->exit_code);
    } else {
        snprintf(buffer, buffer_size, "xxemul - %s",
            xxemul_status_string(app->last_status));
    }
}
