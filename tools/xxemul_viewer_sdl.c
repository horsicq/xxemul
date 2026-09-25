#define SDL_MAIN_HANDLED
#include <SDL.h>

#include "xxemul_viewer_app.h"

#include <stdint.h>
#include <stdio.h>

static uint8_t xxemul_viewer_scan_code(SDL_Scancode scan)
{
    static const uint8_t letters[26] = {
        0x1e, 0x30, 0x2e, 0x20, 0x12, 0x21, 0x22,
        0x23, 0x17, 0x24, 0x25, 0x26, 0x32, 0x31,
        0x18, 0x19, 0x10, 0x13, 0x1f, 0x14, 0x16,
        0x2f, 0x11, 0x2d, 0x15, 0x2c
    };

    if (scan >= SDL_SCANCODE_A && scan <= SDL_SCANCODE_Z) {
        return letters[scan - SDL_SCANCODE_A];
    }
    if (scan >= SDL_SCANCODE_1 && scan <= SDL_SCANCODE_0) {
        return (uint8_t)(2u + scan - SDL_SCANCODE_1);
    }
    return 0u;
}

static void xxemul_viewer_keydown(
    xxemul_viewer_app *app, SDL_Keycode key)
{
    uint8_t ascii = 0u;
    uint8_t scan = 0u;

    switch (key) {
    case SDLK_RETURN:
    case SDLK_KP_ENTER: ascii = '\r'; scan = 0x1cu; break;
    case SDLK_BACKSPACE: ascii = '\b'; scan = 0x0eu; break;
    case SDLK_ESCAPE: ascii = 0x1bu; scan = 0x01u; break;
    case SDLK_TAB: ascii = '\t'; scan = 0x0fu; break;
    case SDLK_UP: scan = 0x48u; break;
    case SDLK_DOWN: scan = 0x50u; break;
    case SDLK_LEFT: scan = 0x4bu; break;
    case SDLK_RIGHT: scan = 0x4du; break;
    default: return;
    }
    (void)xxemul_dos_push_key(app->emulator, ascii, scan);
}

static void xxemul_viewer_event(
    xxemul_viewer_app *app, const SDL_Event *event,
    int *quit, uint8_t *pending_scan)
{
    switch (event->type) {
    case SDL_QUIT:
        *quit = 1;
        break;
    case SDL_KEYDOWN:
        *pending_scan = xxemul_viewer_scan_code(
            event->key.keysym.scancode);
        xxemul_viewer_keydown(app, event->key.keysym.sym);
        break;
    case SDL_TEXTINPUT: {
        const unsigned char *character =
            (const unsigned char *)event->text.text;

        while (*character != 0u) {
            if (*character < 128u && *character >= 32u) {
                (void)xxemul_dos_push_key(
                    app->emulator, *character, *pending_scan);
            }
            ++character;
        }
        *pending_scan = 0u;
        break;
    }
    default:
        break;
    }
}

int main(int argc, char **argv)
{
    xxemul_viewer_app app;
    SDL_Window *window = NULL;
    SDL_Renderer *renderer = NULL;
    SDL_Texture *texture = NULL;
    SDL_Event event;
    uint8_t pending_scan = 0u;
    int quit = 0;
    int result;
    int was_running;
    char title[128];

    result = xxemul_viewer_app_init(&app, argc, argv);
    if (result != 0) {
        return result;
    }
    SDL_SetMainReady();
    if (SDL_Init(SDL_INIT_VIDEO | SDL_INIT_EVENTS) != 0) {
        fprintf(stderr, "SDL init failed: %s\n", SDL_GetError());
        result = 1;
        goto done;
    }
    SDL_SetHint(SDL_HINT_RENDER_SCALE_QUALITY, "0");
    window = SDL_CreateWindow("xxemul", SDL_WINDOWPOS_CENTERED,
        SDL_WINDOWPOS_CENTERED, XXEMUL_DISPLAY_WIDTH,
        XXEMUL_DISPLAY_HEIGHT, SDL_WINDOW_SHOWN | SDL_WINDOW_RESIZABLE);
    if (window == NULL) {
        fprintf(stderr, "SDL window failed: %s\n", SDL_GetError());
        result = 1;
        goto done;
    }
    renderer = SDL_CreateRenderer(window, -1,
        SDL_RENDERER_ACCELERATED | SDL_RENDERER_PRESENTVSYNC);
    if (renderer == NULL) {
        renderer = SDL_CreateRenderer(window, -1, SDL_RENDERER_SOFTWARE);
    }
    if (renderer == NULL
        || SDL_RenderSetLogicalSize(renderer,
            XXEMUL_DISPLAY_WIDTH, XXEMUL_DISPLAY_HEIGHT) != 0) {
        fprintf(stderr, "SDL renderer failed: %s\n", SDL_GetError());
        result = 1;
        goto done;
    }
    texture = SDL_CreateTexture(renderer, SDL_PIXELFORMAT_ARGB8888,
        SDL_TEXTUREACCESS_STREAMING, XXEMUL_DISPLAY_WIDTH,
        XXEMUL_DISPLAY_HEIGHT);
    if (texture == NULL) {
        fprintf(stderr, "SDL texture failed: %s\n", SDL_GetError());
        result = 1;
        goto done;
    }
    SDL_StartTextInput();
    for (;;) {
        if (SDL_WaitEventTimeout(&event, 16) != 0) {
            xxemul_viewer_event(&app, &event, &quit, &pending_scan);
            while (SDL_PollEvent(&event) != 0) {
                xxemul_viewer_event(&app, &event, &quit, &pending_scan);
            }
        }
        if (quit) {
            break;
        }
        was_running = app.running;
        xxemul_viewer_app_tick(&app);
        if (was_running && !app.running) {
            xxemul_viewer_app_title(&app, title, sizeof(title));
            SDL_SetWindowTitle(window, title);
        }
        if (xxemul_display_render(app.emulator, app.pixels,
                XXEMUL_DISPLAY_WIDTH) != XXEMUL_STATUS_OK
            || SDL_UpdateTexture(texture, NULL, app.pixels,
                XXEMUL_DISPLAY_WIDTH * (int)sizeof(*app.pixels)) != 0) {
            fprintf(stderr, "SDL frame update failed: %s\n", SDL_GetError());
            result = 1;
            break;
        }
        SDL_SetRenderDrawColor(renderer, 0u, 0u, 0u, 255u);
        SDL_RenderClear(renderer);
        SDL_RenderCopy(renderer, texture, NULL, NULL);
        SDL_RenderPresent(renderer);
    }
done:
    if (texture != NULL) {
        SDL_DestroyTexture(texture);
    }
    if (renderer != NULL) {
        SDL_DestroyRenderer(renderer);
    }
    if (window != NULL) {
        SDL_DestroyWindow(window);
    }
    SDL_Quit();
    xxemul_viewer_app_destroy(&app);
    return result;
}
