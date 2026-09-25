#include "xxemul_viewer_app.h"

#include <windows.h>

#include <string.h>

static xxemul_viewer_app xxemul_viewer;

static void xxemul_viewer_tick(HWND window)
{
    char title[128];
    int was_running = xxemul_viewer.running;

    xxemul_viewer_app_tick(&xxemul_viewer);
    if (was_running && !xxemul_viewer.running) {
        xxemul_viewer_app_title(&xxemul_viewer, title, sizeof(title));
        SetWindowTextA(window, title);
    }
    InvalidateRect(window, NULL, FALSE);
}

static void xxemul_viewer_paint(HWND window)
{
    PAINTSTRUCT paint;
    HDC dc = BeginPaint(window, &paint);
    RECT client;
    BITMAPINFO bitmap;
    int width;
    int height;
    int draw_width;
    int draw_height;
    int left;
    int top;

    GetClientRect(window, &client);
    width = client.right - client.left;
    height = client.bottom - client.top;
    FillRect(dc, &client, (HBRUSH)GetStockObject(BLACK_BRUSH));
    if (width > 0 && height > 0) {
        draw_width = width;
        draw_height = draw_width * 3 / 4;
        if (draw_height > height) {
            draw_height = height;
            draw_width = draw_height * 4 / 3;
        }
        left = (width - draw_width) / 2;
        top = (height - draw_height) / 2;
        memset(&bitmap, 0, sizeof(bitmap));
        bitmap.bmiHeader.biSize = sizeof(bitmap.bmiHeader);
        bitmap.bmiHeader.biWidth = XXEMUL_DISPLAY_WIDTH;
        bitmap.bmiHeader.biHeight = -(LONG)XXEMUL_DISPLAY_HEIGHT;
        bitmap.bmiHeader.biPlanes = 1;
        bitmap.bmiHeader.biBitCount = 32;
        bitmap.bmiHeader.biCompression = BI_RGB;
        xxemul_display_render(xxemul_viewer.emulator,
            xxemul_viewer.pixels, XXEMUL_DISPLAY_WIDTH);
        SetStretchBltMode(dc, COLORONCOLOR);
        StretchDIBits(dc, left, top, draw_width, draw_height,
            0, 0, XXEMUL_DISPLAY_WIDTH, XXEMUL_DISPLAY_HEIGHT,
            xxemul_viewer.pixels, &bitmap, DIB_RGB_COLORS, SRCCOPY);
    }
    EndPaint(window, &paint);
}

static LRESULT CALLBACK xxemul_viewer_window_proc(
    HWND window, UINT message, WPARAM word, LPARAM long_value)
{
    switch (message) {
    case WM_TIMER:
        xxemul_viewer_tick(window);
        return 0;
    case WM_CHAR:
        xxemul_dos_push_key(xxemul_viewer.emulator,
            (uint8_t)word, (uint8_t)((long_value >> 16) & 0xff));
        return 0;
    case WM_PAINT:
        xxemul_viewer_paint(window);
        return 0;
    case WM_DESTROY:
        KillTimer(window, 1u);
        PostQuitMessage(0);
        return 0;
    default:
        return DefWindowProcA(window, message, word, long_value);
    }
}

int main(int argc, char **argv)
{
    int result;
    HINSTANCE instance = GetModuleHandleA(NULL);
    WNDCLASSA window_class;
    HWND window;
    RECT bounds = {0, 0, XXEMUL_DISPLAY_WIDTH, XXEMUL_DISPLAY_HEIGHT};
    MSG message;

    result = xxemul_viewer_app_init(&xxemul_viewer, argc, argv);
    if (result != 0) {
        return result;
    }
    memset(&window_class, 0, sizeof(window_class));
    window_class.lpfnWndProc = xxemul_viewer_window_proc;
    window_class.hInstance = instance;
    window_class.lpszClassName = "xxemul_viewer";
    window_class.hCursor = LoadCursorA(NULL, IDC_ARROW);
    if (RegisterClassA(&window_class) == 0) {
        xxemul_viewer_app_destroy(&xxemul_viewer);
        return 1;
    }
    AdjustWindowRect(&bounds, WS_OVERLAPPEDWINDOW, FALSE);
    window = CreateWindowExA(0, window_class.lpszClassName, "xxemul",
        WS_OVERLAPPEDWINDOW | WS_VISIBLE, CW_USEDEFAULT, CW_USEDEFAULT,
        bounds.right - bounds.left, bounds.bottom - bounds.top,
        NULL, NULL, instance, NULL);
    if (window == NULL) {
        xxemul_viewer_app_destroy(&xxemul_viewer);
        return 1;
    }
    SetTimer(window, 1u, 16u, NULL);
    while (GetMessageA(&message, NULL, 0, 0) > 0) {
        TranslateMessage(&message);
        DispatchMessageA(&message);
    }
    xxemul_viewer_app_destroy(&xxemul_viewer);
    return (int)message.wParam;
}
