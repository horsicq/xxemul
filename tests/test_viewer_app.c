#include "xxemul_viewer_app.h"

#include <stdio.h>
#include <string.h>

int main(void)
{
    char *arguments[] = {"xxemul_viewer", "demo"};
    xxemul_viewer_app app;
    char title[128];

    if (xxemul_viewer_app_init(&app, 2, arguments) != 0) {
        return 1;
    }
    xxemul_viewer_app_tick(&app);
    xxemul_viewer_app_title(&app, title, sizeof(title));
    if (app.running || app.last_status != XXEMUL_STATUS_HALTED
        || strstr(title, "exited (0)") == NULL
        || xxemul_display_render(app.emulator, app.pixels,
            XXEMUL_DISPLAY_WIDTH) != XXEMUL_STATUS_OK
        || app.pixels[0] != 0xff000000u) {
        fprintf(stderr, "viewer demo failed: %s\n", title);
        xxemul_viewer_app_destroy(&app);
        return 1;
    }
    xxemul_viewer_app_destroy(&app);
    puts("viewer app tests passed");
    return 0;
}
