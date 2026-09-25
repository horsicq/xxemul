#include "xxemul_internal.h"

#define XXEMUL_TEXT_BASE 0xb8000u
#define XXEMUL_GRAPHICS_BASE 0xa0000u
#define XXEMUL_TEXT_COLUMNS 80u
#define XXEMUL_TEXT_ROWS 25u
#define XXEMUL_TEXT_CELL_HEIGHT 19u
#define XXEMUL_TEXT_TOP \
    ((XXEMUL_DISPLAY_HEIGHT - XXEMUL_TEXT_ROWS * XXEMUL_TEXT_CELL_HEIGHT) / 2u)

static const uint32_t xxemul_vga_colors[16] = {
    0xff000000u, 0xff0000aau, 0xff00aa00u, 0xff00aaaau,
    0xffaa0000u, 0xffaa00aau, 0xffaa5500u, 0xffaaaaaau,
    0xff555555u, 0xff5555ffu, 0xff55ff55u, 0xff55ffffu,
    0xffff5555u, 0xffff55ffu, 0xffffff55u, 0xffffffffu
};

/* Five-column raster glyphs; lower-case is distinct and all other bytes fall back to '?'. */
static const uint8_t xxemul_font[95][7] = {
    ['!' - 32] = {4, 4, 4, 4, 4, 0, 4},
    ['"' - 32] = {10, 10, 10, 0, 0, 0, 0},
    ['#' - 32] = {10, 31, 10, 10, 31, 10, 0},
    ['$' - 32] = {4, 15, 20, 14, 5, 30, 4},
    ['%' - 32] = {17, 2, 4, 8, 17, 0, 0},
    ['&' - 32] = {12, 18, 20, 8, 21, 18, 13},
    ['\'' - 32] = {4, 4, 8, 0, 0, 0, 0},
    ['(' - 32] = {2, 4, 8, 8, 8, 4, 2},
    [')' - 32] = {8, 4, 2, 2, 2, 4, 8},
    ['*' - 32] = {0, 10, 4, 31, 4, 10, 0},
    ['+' - 32] = {0, 4, 4, 31, 4, 4, 0},
    [',' - 32] = {0, 0, 0, 0, 4, 4, 8},
    ['-' - 32] = {0, 0, 0, 31, 0, 0, 0},
    ['.' - 32] = {0, 0, 0, 0, 0, 12, 12},
    ['/' - 32] = {1, 2, 2, 4, 8, 8, 16},
    ['0' - 32] = {14, 17, 19, 21, 25, 17, 14},
    ['1' - 32] = {4, 12, 4, 4, 4, 4, 14},
    ['2' - 32] = {14, 17, 1, 2, 4, 8, 31},
    ['3' - 32] = {30, 1, 1, 14, 1, 1, 30},
    ['4' - 32] = {2, 6, 10, 18, 31, 2, 2},
    ['5' - 32] = {31, 16, 16, 30, 1, 1, 30},
    ['6' - 32] = {14, 16, 16, 30, 17, 17, 14},
    ['7' - 32] = {31, 1, 2, 4, 8, 8, 8},
    ['8' - 32] = {14, 17, 17, 14, 17, 17, 14},
    ['9' - 32] = {14, 17, 17, 15, 1, 1, 14},
    [':' - 32] = {0, 4, 4, 0, 4, 4, 0},
    [';' - 32] = {0, 4, 4, 0, 4, 4, 8},
    ['<' - 32] = {2, 4, 8, 16, 8, 4, 2},
    ['=' - 32] = {0, 0, 31, 0, 31, 0, 0},
    ['>' - 32] = {8, 4, 2, 1, 2, 4, 8},
    ['?' - 32] = {14, 17, 1, 2, 4, 0, 4},
    ['@' - 32] = {14, 17, 23, 21, 23, 16, 14},
    ['A' - 32] = {14, 17, 17, 31, 17, 17, 17},
    ['B' - 32] = {30, 17, 17, 30, 17, 17, 30},
    ['C' - 32] = {14, 17, 16, 16, 16, 17, 14},
    ['D' - 32] = {28, 18, 17, 17, 17, 18, 28},
    ['E' - 32] = {31, 16, 16, 30, 16, 16, 31},
    ['F' - 32] = {31, 16, 16, 30, 16, 16, 16},
    ['G' - 32] = {14, 17, 16, 23, 17, 17, 15},
    ['H' - 32] = {17, 17, 17, 31, 17, 17, 17},
    ['I' - 32] = {14, 4, 4, 4, 4, 4, 14},
    ['J' - 32] = {7, 2, 2, 2, 18, 18, 12},
    ['K' - 32] = {17, 18, 20, 24, 20, 18, 17},
    ['L' - 32] = {16, 16, 16, 16, 16, 16, 31},
    ['M' - 32] = {17, 27, 21, 21, 17, 17, 17},
    ['N' - 32] = {17, 25, 21, 19, 17, 17, 17},
    ['O' - 32] = {14, 17, 17, 17, 17, 17, 14},
    ['P' - 32] = {30, 17, 17, 30, 16, 16, 16},
    ['Q' - 32] = {14, 17, 17, 17, 21, 18, 13},
    ['R' - 32] = {30, 17, 17, 30, 20, 18, 17},
    ['S' - 32] = {15, 16, 16, 14, 1, 1, 30},
    ['T' - 32] = {31, 4, 4, 4, 4, 4, 4},
    ['U' - 32] = {17, 17, 17, 17, 17, 17, 14},
    ['V' - 32] = {17, 17, 17, 17, 17, 10, 4},
    ['W' - 32] = {17, 17, 17, 21, 21, 21, 10},
    ['X' - 32] = {17, 17, 10, 4, 10, 17, 17},
    ['Y' - 32] = {17, 17, 10, 4, 4, 4, 4},
    ['Z' - 32] = {31, 1, 2, 4, 8, 16, 31},
    ['[' - 32] = {14, 8, 8, 8, 8, 8, 14},
    ['\\' - 32] = {16, 8, 8, 4, 2, 2, 1},
    [']' - 32] = {14, 2, 2, 2, 2, 2, 14},
    ['^' - 32] = {4, 10, 17, 0, 0, 0, 0},
    ['_' - 32] = {0, 0, 0, 0, 0, 0, 31},
    ['`' - 32] = {8, 4, 0, 0, 0, 0, 0},
    ['a' - 32] = {0, 0, 14, 1, 15, 17, 15},
    ['b' - 32] = {16, 16, 22, 25, 17, 17, 30},
    ['c' - 32] = {0, 0, 14, 17, 16, 17, 14},
    ['d' - 32] = {1, 1, 13, 19, 17, 17, 15},
    ['e' - 32] = {0, 0, 14, 17, 31, 16, 14},
    ['f' - 32] = {6, 9, 8, 28, 8, 8, 8},
    ['g' - 32] = {0, 15, 17, 17, 15, 1, 14},
    ['h' - 32] = {16, 16, 22, 25, 17, 17, 17},
    ['i' - 32] = {4, 0, 12, 4, 4, 4, 14},
    ['j' - 32] = {2, 0, 6, 2, 2, 18, 12},
    ['k' - 32] = {16, 16, 18, 20, 24, 20, 18},
    ['l' - 32] = {12, 4, 4, 4, 4, 4, 14},
    ['m' - 32] = {0, 0, 26, 21, 21, 21, 21},
    ['n' - 32] = {0, 0, 22, 25, 17, 17, 17},
    ['o' - 32] = {0, 0, 14, 17, 17, 17, 14},
    ['p' - 32] = {0, 0, 30, 17, 30, 16, 16},
    ['q' - 32] = {0, 0, 15, 17, 15, 1, 1},
    ['r' - 32] = {0, 0, 22, 25, 16, 16, 16},
    ['s' - 32] = {0, 0, 15, 16, 14, 1, 30},
    ['t' - 32] = {8, 8, 28, 8, 8, 9, 6},
    ['u' - 32] = {0, 0, 17, 17, 17, 19, 13},
    ['v' - 32] = {0, 0, 17, 17, 17, 10, 4},
    ['w' - 32] = {0, 0, 17, 17, 21, 21, 10},
    ['x' - 32] = {0, 0, 17, 10, 4, 10, 17},
    ['y' - 32] = {0, 0, 17, 17, 15, 1, 14},
    ['z' - 32] = {0, 0, 31, 2, 4, 8, 31},
    ['{' - 32] = {3, 4, 4, 8, 4, 4, 3},
    ['|' - 32] = {4, 4, 4, 4, 4, 4, 4},
    ['}' - 32] = {24, 4, 4, 2, 4, 4, 24},
    ['~' - 32] = {0, 0, 9, 22, 0, 0, 0}
};

static uint32_t xxemul_graphics_color(uint8_t index)
{
    uint8_t red;
    uint8_t green;
    uint8_t blue;
    uint8_t cube;

    if (index < 16u) {
        return xxemul_vga_colors[index];
    }
    if (index < 232u) {
        cube = (uint8_t)(index - 16u);
        red = (uint8_t)((cube / 36u) * 51u);
        green = (uint8_t)(((cube / 6u) % 6u) * 51u);
        blue = (uint8_t)((cube % 6u) * 51u);
    } else {
        red = green = blue = (uint8_t)((index - 232u) * 10u + 8u);
    }
    return 0xff000000u | ((uint32_t)red << 16)
        | ((uint32_t)green << 8) | blue;
}

void xxemul_video_clear(xxemul *emulator)
{
    size_t cell;

    if (emulator->video_mode == 0x13u) {
        xx_mem_zero(emulator->region_data + XXEMUL_GRAPHICS_BASE,
            320u * 200u);
        return;
    }
    for (cell = 0u; cell < XXEMUL_TEXT_COLUMNS * XXEMUL_TEXT_ROWS;
         ++cell) {
        emulator->region_data[XXEMUL_TEXT_BASE + cell * 2u] = ' ';
        emulator->region_data[XXEMUL_TEXT_BASE + cell * 2u + 1u] =
            emulator->text_attribute;
    }
}

void xxemul_video_putc(xxemul *emulator, uint8_t character)
{
    uint8_t *text = emulator->region_data + XXEMUL_TEXT_BASE;
    size_t cell;
    size_t column;

    if (xxemul_emit_output(emulator, 1, &character, 1u)) {
        /* delivered to the stream callback */
    } else if (emulator->output_callback != NULL) {
        emulator->output_callback(emulator->output_context, character);
    }
    if (character == '\r') {
        emulator->cursor_column = 0u;
    } else if (character == '\n') {
        ++emulator->cursor_row;
    } else if (character == '\b') {
        if (emulator->cursor_column > 0u) {
            --emulator->cursor_column;
        }
    } else if (character == '\t') {
        column = ((size_t)emulator->cursor_column + 8u) & ~7u;
        emulator->cursor_column = (uint8_t)(column > 79u ? 79u : column);
    } else if (character >= 32u) {
        cell = (size_t)emulator->cursor_row * XXEMUL_TEXT_COLUMNS
            + emulator->cursor_column;
        if (cell < XXEMUL_TEXT_COLUMNS * XXEMUL_TEXT_ROWS) {
            text[cell * 2u] = character;
            text[cell * 2u + 1u] = emulator->text_attribute;
        }
        ++emulator->cursor_column;
    }
    if (emulator->cursor_column >= XXEMUL_TEXT_COLUMNS) {
        emulator->cursor_column = 0u;
        ++emulator->cursor_row;
    }
    if (emulator->cursor_row >= XXEMUL_TEXT_ROWS) {
        xx_mem_move(text, text + XXEMUL_TEXT_COLUMNS * 2u,
            (XXEMUL_TEXT_ROWS - 1u) * XXEMUL_TEXT_COLUMNS * 2u);
        for (cell = (XXEMUL_TEXT_ROWS - 1u) * XXEMUL_TEXT_COLUMNS;
             cell < XXEMUL_TEXT_ROWS * XXEMUL_TEXT_COLUMNS; ++cell) {
            text[cell * 2u] = ' ';
            text[cell * 2u + 1u] = emulator->text_attribute;
        }
        emulator->cursor_row = XXEMUL_TEXT_ROWS - 1u;
    }
}

uint8_t xxemul_display_get_mode(const xxemul *emulator)
{
    return emulator != NULL && emulator->dos_mode
        ? emulator->video_mode : 0xffu;
}

xxemul_status xxemul_display_render(
    xxemul *emulator, uint32_t *pixels, size_t stride_pixels)
{
    size_t x;
    size_t y;
    const uint8_t *video;

    if (emulator == NULL || !emulator->dos_mode || pixels == NULL
        || stride_pixels < XXEMUL_DISPLAY_WIDTH) {
        return XXEMUL_STATUS_INVALID_ARGUMENT;
    }
    if (emulator->video_mode == 0x13u) {
        video = emulator->region_data + XXEMUL_GRAPHICS_BASE;
        for (y = 0u; y < XXEMUL_DISPLAY_HEIGHT; ++y) {
            size_t source_y = y * 200u / XXEMUL_DISPLAY_HEIGHT;
            for (x = 0u; x < XXEMUL_DISPLAY_WIDTH; ++x) {
                pixels[y * stride_pixels + x] = xxemul_graphics_color(
                    video[source_y * 320u + x / 2u]);
            }
        }
        return XXEMUL_STATUS_OK;
    }
    video = emulator->region_data + XXEMUL_TEXT_BASE;
    for (y = 0u; y < XXEMUL_DISPLAY_HEIGHT; ++y) {
        for (x = 0u; x < XXEMUL_DISPLAY_WIDTH; ++x) {
            uint32_t color = xxemul_vga_colors[0];
            if (y >= XXEMUL_TEXT_TOP
                && y < XXEMUL_TEXT_TOP
                    + XXEMUL_TEXT_ROWS * XXEMUL_TEXT_CELL_HEIGHT) {
                size_t cell_y = (y - XXEMUL_TEXT_TOP)
                    / XXEMUL_TEXT_CELL_HEIGHT;
                size_t cell_x = x / 8u;
                size_t cell = (cell_y * 80u + cell_x) * 2u;
                uint8_t character = video[cell];
                uint8_t attribute = video[cell + 1u];
                size_t local_x = x % 8u;
                size_t local_y = (y - XXEMUL_TEXT_TOP)
                    % XXEMUL_TEXT_CELL_HEIGHT;
                uint8_t glyph_row;

                color = xxemul_vga_colors[(attribute >> 4) & 7u];
                if (character < 32u || character > 126u) {
                    character = '?';
                }
                if (local_x >= 1u && local_x <= 5u
                    && local_y >= 2u && local_y < 17u) {
                    glyph_row = xxemul_font[character - 32u]
                        [(local_y - 2u) * 7u / 15u];
                    if ((glyph_row & (1u << (5u - local_x))) != 0u) {
                        color = xxemul_vga_colors[attribute & 15u];
                    }
                }
            }
            pixels[y * stride_pixels + x] = color;
        }
    }
    return XXEMUL_STATUS_OK;
}
