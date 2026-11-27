/* Copyright (c) 2026 hors<horsicq@gmail.com> */

#include "xxemul_internal.h"

#include <stdlib.h>
#include <string.h>

/* One flat, zero-based map includes Exec's low memory and a bounded runtime
 * arena. Default images, heap and stack all stay in the 24-bit address space. */
#define HUNK_MAX_REGION (256u * 1024u * 1024u)
#define HUNK_RUNTIME (1024u * 1024u + 8192u + 16u)

typedef struct hunk_reader {
    const uint8_t *data;
    size_t size, pos;
    int failed;
} hunk_reader;
typedef struct hunk_segment {
    uint32_t address, size;
} hunk_segment;

static uint32_t read_be(const uint8_t *p)
{
    return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3];
}
static void write_be(uint8_t *p, uint32_t n)
{
    p[0] = (uint8_t)(n >> 24);
    p[1] = (uint8_t)(n >> 16);
    p[2] = (uint8_t)(n >> 8);
    p[3] = (uint8_t)n;
}
static uint32_t take(hunk_reader *r, unsigned n)
{
    uint32_t value = 0;
    unsigned i;
    if (n > r->size - r->pos) {
        r->failed = 1;
        return 0;
    }
    for (i = 0; i < n; ++i) value = value << 8 | r->data[r->pos++];
    return value;
}
static int skip(hunk_reader *r, uint64_t n)
{
    if (n > r->size - r->pos) {
        r->failed = 1;
        return 0;
    }
    r->pos += (size_t)n;
    return 1;
}

/* RELRELOC32 is documented with longword fields, but AmigaDOS V39+ also
 * reads the compact word form. Validate without applying before choosing a
 * dialect, so a failed longword probe cannot relocate any bytes twice. */
static int relocations(hunk_reader *r, xxemul *e, const hunk_segment *segments, uint32_t current, uint32_t first, uint32_t count, unsigned width, int relative, int apply)
{
    uint32_t n, i, target, offset;
    while ((n = take(r, width)) != 0 && !r->failed) {
        target = take(r, width);
        if (target < first || target - first >= count || n > (r->size - r->pos) / width) return 0;
        target -= first;
        for (i = 0; i < n; ++i) {
            offset = take(r, width);
            if (r->failed || segments[current].size < 4 || offset > segments[current].size - 4) return 0;
            if (apply) {
                uint8_t *patch = e->region_data + segments[current].address + offset;
                uint32_t value = read_be(patch) + segments[target].address;
                if (relative) value -= segments[current].address + offset;
                write_be(patch, value);
            }
        }
    }
    if (width == 2 && (r->pos & 3u)) (void)take(r, 2);
    return !r->failed;
}

xxemul *xxemul_load_amigahunk(const uint8_t *image, size_t size, uint64_t base, xxemul_status *status)
{
    hunk_reader r = {image, size, 0, 0};
    hunk_segment *segments = NULL;
    xxemul *e = NULL;
    uint32_t table, first, last, count, i, current = 0;
    uint64_t end;
    int body = 0;
    *status = XXEMUL_STATUS_INVALID_IMAGE;
    if ((take(&r, 4) & 0x3fffffffu) != 0x3f3 || r.failed) goto fail;
    if (take(&r, 4)) {
        *status = XXEMUL_STATUS_UNSUPPORTED_IMAGE;
        goto fail;
    }
    table = take(&r, 4);
    first = take(&r, 4);
    last = take(&r, 4);
    if (r.failed || first > last || last >= table) goto fail;
    count = last - first + 1;
    if (count > (r.size - r.pos) / 4 || count > 65536u) goto fail;
    if (!base) base = 0x200000u;
    if ((base & 3u) || base < 0x20000u || base > HUNK_MAX_REGION - HUNK_RUNTIME) goto fail;
    segments = calloc(count, sizeof(*segments));
    if (!segments) {
        *status = XXEMUL_STATUS_OUT_OF_MEMORY;
        goto fail;
    }
    end = base;
    for (i = 0; i < count; ++i) {
        uint32_t raw = take(&r, 4);
        uint64_t bytes = (uint64_t)(raw & 0x3fffffffu) * 4;
        if ((raw >> 30) == 3) (void)take(&r, 4);
        if (r.failed || bytes + 8 + end > HUNK_MAX_REGION - HUNK_RUNTIME) goto fail;
        segments[i].address = (uint32_t)end + 8;
        segments[i].size = (uint32_t)bytes;
        end += bytes + 8;
    }
    if (!segments[0].size) goto fail;
    e = xxemul_create_empty(XXEMUL_ARCH_M68K, XXEMUL_MODE_M68K_68000, 0, (size_t)end + HUNK_RUNTIME, status);
    if (!e) goto fail;
    *status = XXEMUL_STATUS_INVALID_IMAGE;
    for (i = 0; i < count; ++i) {
        write_be(e->region_data + segments[i].address - 8, segments[i].size + 8);
        /* The seglist BPTR addresses the link word, not the size word. */
        write_be(e->region_data + segments[i].address - 4, i + 1 < count ? (segments[i + 1].address - 4) >> 2 : 0);
    }
    while (r.pos < r.size && !r.failed) {
        uint32_t type = take(&r, 4) & 0x3fffffffu;
        uint32_t n;
        if (r.failed) goto fail;
        if (type == 0x3f5 || type == 0x3f6) {
            *status = XXEMUL_STATUS_UNSUPPORTED_IMAGE;
            goto fail;
        }
        if (type == 0x3e8 || type == 0x3f1) {
            n = take(&r, 4);
            if (!skip(&r, (uint64_t)n * 4)) goto fail;
        } else if (type == 0x3f0) {
            while ((n = take(&r, 4)) != 0 && !r.failed) {
                if (!skip(&r, (uint64_t)n * 4 + 4)) goto fail;
            }
        } else if (current >= count) goto fail;
        else if (type >= 0x3e9 && type <= 0x3eb) {
            uint64_t bytes;
            if (body) goto fail;
            n = take(&r, 4);
            bytes = (uint64_t)n * 4;
            if (r.failed || bytes > segments[current].size) goto fail;
            if (type != 0x3eb) {
                size_t pos = r.pos;
                if (!skip(&r, bytes)) goto fail;
                memcpy(e->region_data + segments[current].address, r.data + pos, (size_t)bytes);
            }
            body = 1;
        } else if (type == 0x3f2) {
            if (!body) goto fail;
            ++current;
            body = 0;
        } else if (type == 0x3ec || type == 0x3fc || type == 0x3f7 || type == 0x3fd) {
            unsigned width = (type == 0x3fc || type == 0x3f7) ? 2 : 4;
            if (!body) goto fail;
            if (type == 0x3fd) {
                hunk_reader probe = r;
                if (!relocations(&probe, e, segments, current, first, count, 4, 1, 0)) {
                    probe = r;
                    width = 2;
                    if (!relocations(&probe, e, segments, current, first, count, 2, 1, 0)) goto fail;
                }
            }
            if (!relocations(&r, e, segments, current, first, count, width, type == 0x3fd, 1)) goto fail;
        } else goto fail;
    }
    if (r.failed || current != count || body) goto fail;
    e->amiga_hunk_base = (uint32_t)base;
    e->amiga_hunk_end = (uint32_t)end;
    e->m68k.pc = segments[0].address;
    e->m68k.a[7] = ((uint32_t)e->region_size - 8) & ~3u;
    e->m68k.usp = e->m68k.a[7];
    free(segments);
    *status = XXEMUL_STATUS_OK;
    return e;
fail:
    free(segments);
    xxemul_destroy(e);
    return NULL;
}
