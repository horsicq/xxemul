#ifndef XX_WIN_LZNT1_DECODE_H
#define XX_WIN_LZNT1_DECODE_H

#include <stdint.h>
#include <stddef.h>

/*
 * Original pure-C MS-XCA LZNT1 chunk decoder (codec only).
 * Returns 1 on success, 0 on malformed input or invalid host arguments.
 * *out_size is assigned only on success. No allocations, I/O, or globals.
 */
static int xx_win_lznt1_decode(const uint8_t *src, size_t src_size,
                               uint8_t *dst, size_t dst_cap, size_t *out_size)
{
    size_t sp = 0, produced = 0;
    int done_chunk = 0;

    if (!src || !out_size)
        return 0;
    if (!dst && dst_cap)
        return 0;
    if (src_size < 2)
        return 0;

    for (;;) {
        size_t remaining, pad, payload_len, avail, chunk_start, p;
        uint16_t hdr;
        int compressed;

        if (src_size - sp < 2) {          /* end of input */
            if (!done_chunk)
                return 0;                 /* shorter than 2 bytes initially */
            break;                        /* 0 or 1 trailing byte ignored */
        }
        hdr = (uint16_t)((uint16_t)src[sp] |
                         (uint16_t)((uint16_t)src[sp + 1] << 8));
        if (hdr == 0)
            break;                        /* terminator ignores the rest */
        payload_len = (size_t)(hdr & 0x0fff) + 1;
        compressed = (hdr & 0x8000) != 0; /* signature bits 14:12 ignored */
        if (src_size - sp - 2 < payload_len)
            return 0;                     /* incomplete declared payload */

        remaining = dst_cap - produced;
        if (remaining == 0)
            break;                        /* full destination: prefix success */

        /* pad to the 4096 boundary before a next complete nonzero chunk */
        if (done_chunk && (produced & 4095)) {
            pad = 4096 - (produced & 4095);
            if (remaining <= pad)
                break;                    /* success without partial padding */
            for (p = 0; p < pad; p++)
                dst[produced + p] = 0;
            produced += pad;
            remaining -= pad;
        }

        chunk_start = produced;
        avail = payload_len;
        sp += 2;

        if (!compressed) {                /* raw chunk */
            size_t c = payload_len < remaining ? payload_len : remaining;
            for (p = 0; p < c; p++)
                dst[produced + p] = src[sp + p];
            produced += c;
            remaining -= c;
            sp += avail;
            done_chunk = 1;
            continue;
        }

        p = 0;
        while (p < avail) {
            uint8_t flags = src[sp + p++];
            int b;
            for (b = 0; b < 8; b++) {
                size_t u, disp, len, c, i, t;
                unsigned lb, tok;

                if (p >= avail)
                    break;                /* payload end: ignore unused bits */
                if (remaining == 0)
                    goto chunk_done;      /* capacity reached inside chunk */
                u = produced - chunk_start;
                if (flags & (1u << b)) {              /* match token */
                    if (p + 2 > avail)
                        return 0;         /* token bytes absent */
                    tok = (unsigned)src[sp + p] |
                          ((unsigned)src[sp + p + 1] << 8);
                    p += 2;
                    lb = 12;
                    t = u ? u - 1 : 0;
                    while (t >= 16) { lb--; t >>= 1; }
                    disp = (tok >> lb) + 1;
                    len = (tok & ((1u << lb) - 1)) + 3;
                    if (disp > u || u + len > 4096)
                        return 0;         /* bad or over-limit backreference */
                    c = len < remaining ? len : remaining;
                    for (i = 0; i < c; i++)
                        dst[produced + i] = dst[produced - disp + i];
                    produced += c;
                    remaining -= c;
                    if (c < len)
                        goto chunk_done;  /* run clipped by destination */
                } else {                              /* literal byte */
                    if (p + 1 > avail)
                        return 0;
                    if (u + 1 > 4096)
                        return 0;
                    dst[produced++] = src[sp + p++];
                    remaining--;
                }
            }
        }
chunk_done:
        sp += avail;                      /* advance to declared chunk end */
        done_chunk = 1;
    }

    *out_size = produced;
    return 1;
}

#endif /* XX_WIN_LZNT1_DECODE_H */
