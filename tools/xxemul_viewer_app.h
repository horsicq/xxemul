#ifndef XXEMUL_VIEWER_APP_H
#define XXEMUL_VIEWER_APP_H

#include "xxemul/xxemul.h"

#include <stddef.h>
#include <stdint.h>

typedef struct xxemul_viewer_app {
    xxemul *emulator;
    uint32_t *pixels;
    xxemul_status last_status;
    uint8_t exit_code;
    int running;
} xxemul_viewer_app;

int xxemul_viewer_app_init(
    xxemul_viewer_app *app, int argc, char **argv);
void xxemul_viewer_app_destroy(xxemul_viewer_app *app);
void xxemul_viewer_app_tick(xxemul_viewer_app *app);
void xxemul_viewer_app_title(
    const xxemul_viewer_app *app, char *buffer, size_t buffer_size);

#endif
