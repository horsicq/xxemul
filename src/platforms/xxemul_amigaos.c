/* Copyright (c) 2026 hors<horsicq@gmail.com> */

#include "xxemul_amigaos.h"
#include "xxemul_internal.h"
#include "xxemul_dos_files.h"

#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define EXEC_BASE 0x10000u
#define DOS_BASE 0x12000u
#define STUBS 0x14000u
#define EXIT_STUB 0x15000u
#define ARGUMENTS 0x16000u
#define TASK 0x18000u
#define COMMAND 0x18200u
#define CLI 0x18400u
#define HANDLES 0x18800u
#define SLOT_COUNT 256u
#define FILE_COUNT 64u
#define STACK_SIZE 8192u
#define TEXT_LIMIT (1024u * 1024u)

typedef struct amiga_block {
    uint32_t address, size;
    int used;
    struct amiga_block *next;
} amiga_block;
struct xxemul_amigaos {
    xxemul *e;
    xxemul_status terminal;
    int exit_code;
    uint32_t ioerr, signals;
    char error[192], root[2048];
    FILE *files[FILE_COUNT];
    uint8_t console[FILE_COUNT]; /* 1: input, 2: output */
    amiga_block *blocks;
};

/* NDK exec_lib.fd / dos_lib.fd LVOs (positive magnitudes below).
 * Every six-byte vector JMPs to a distinct line-A/RTS stub. Keeping the stub
 * separate lets SetFunction return a callable original function address. */
typedef struct amiga_lvo {
    unsigned library, lvo;
    const char *name;
} amiga_lvo;
#define EX(n, s) {0, n, "exec.library/" s}
#define DOS(n, s) {1, n, "dos.library/" s}
static const amiga_lvo lvos[] = {
    EX(552, "OpenLibrary"), EX(408, "OldOpenLibrary"), EX(414, "CloseLibrary"), EX(198, "AllocMem"),  EX(210, "FreeMem"),     EX(684, "AllocVec"),   EX(690, "FreeVec"),
    EX(294, "FindTask"),    EX(132, "Forbid"),         EX(138, "Permit"),       EX(306, "SetSignal"), EX(318, "Wait"),        EX(372, "GetMsg"),     EX(378, "ReplyMsg"),
    EX(384, "WaitPort"),    EX(624, "CopyMem"),        EX(630, "CopyMemQuick"), EX(522, "RawDoFmt"),  EX(420, "SetFunction"), DOS(60, "Output"),     DOS(54, "Input"),
    DOS(48, "Write"),       DOS(42, "Read"),           DOS(30, "Open"),         DOS(36, "Close"),     DOS(66, "Seek"),        DOS(72, "DeleteFile"), DOS(132, "IoErr"),
    DOS(948, "PutStr"),     DOS(954, "VPrintf"),       DOS(354, "VFPrintf"),    DOS(342, "FPuts"),    DOS(312, "FPutC"),      DOS(198, "Delay"),     DOS(144, "Exit"),
    DOS(192, "DateStamp"),  DOS(462, "SetIoErr")};
#undef EX
#undef DOS

static void put16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)v;
}
static void put32(uint8_t *p, uint32_t v)
{
    put16(p, (uint16_t)(v >> 16));
    put16(p + 2, (uint16_t)v);
}
static uint32_t be32(const uint8_t *p)
{
    return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3];
}
static uint32_t library_base(unsigned lib)
{
    return lib ? DOS_BASE : EXEC_BASE;
}
static uint32_t stub(unsigned lib, unsigned slot)
{
    return STUBS + (lib * SLOT_COUNT + slot - 1) * 4;
}
static uint32_t handle(unsigned i)
{
    return (HANDLES + i * 64) >> 2;
}

static void stop(xxemul_amigaos *p, xxemul_status status, const char *message)
{
    p->terminal = status;
    p->e->halted = 1;
    if (message) snprintf(p->error, sizeof(p->error), "%s", message);
}
static int read_guest(xxemul_amigaos *p, uint32_t a, void *data, size_t n)
{
    if ((uint64_t)a + n > UINT64_C(0x100000000) || xxemul_read_memory(p->e, a, data, n) != XXEMUL_STATUS_OK) {
        stop(p, XXEMUL_STATUS_ADDRESS_FAULT, "AmigaOS: invalid guest read");
        return 0;
    }
    return 1;
}
static int write_guest(xxemul_amigaos *p, uint32_t a, const void *data, size_t n)
{
    if ((uint64_t)a + n > UINT64_C(0x100000000) || xxemul_write_memory(p->e, a, data, n) != XXEMUL_STATUS_OK) {
        stop(p, XXEMUL_STATUS_ADDRESS_FAULT, "AmigaOS: invalid guest write");
        return 0;
    }
    return 1;
}
static uint32_t get_number(xxemul_amigaos *p, uint32_t a, unsigned size)
{
    uint8_t b[4] = {0, 0, 0, 0};
    if (!read_guest(p, a, b + 4 - size, size)) return 0;
    return be32(b);
}
static int store_number(xxemul_amigaos *p, uint32_t a, uint32_t v)
{
    uint8_t b[4];
    put32(b, v);
    return write_guest(p, a, b, 4);
}
static int guest_string(xxemul_amigaos *p, uint32_t a, char *s, size_t capacity)
{
    size_t i;
    for (i = 0; i < capacity; ++i) {
        if ((uint64_t)a + i > UINT32_MAX || !read_guest(p, a + (uint32_t)i, s + i, 1)) return 0;
        if (!s[i]) return 1;
    }
    stop(p, XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION, "AmigaOS: string exceeds service limit");
    return 0;
}
static uint32_t allocate(xxemul_amigaos *p, uint32_t size, uint32_t flags)
{
    amiga_block *b;
    uint32_t aligned;
    if (!size || size > UINT32_MAX - 7) return 0;
    aligned = (size + 7) & ~7u;
    for (b = p->blocks; b; b = b->next)
        if (!b->used && b->size >= aligned) {
            if (b->size > aligned) {
                amiga_block *tail = calloc(1, sizeof(*tail));
                if (!tail) return 0;
                tail->address = b->address + aligned;
                tail->size = b->size - aligned;
                tail->next = b->next;
                b->next = tail;
                b->size = aligned;
            }
            b->used = 1;
            if (flags & 0x10000u) memset(p->e->region_data + b->address, 0, b->size);
            return b->address;
        }
    return 0;
}
static void release(xxemul_amigaos *p, uint32_t address)
{
    amiga_block *b;
    if (!address) return;
    for (b = p->blocks; b; b = b->next)
        if (b->address == address && b->used) {
            b->used = 0;
            break;
        }
    for (b = p->blocks; b && b->next;) {
        if (!b->used && !b->next->used) {
            amiga_block *next = b->next;
            b->size += next->size;
            b->next = next->next;
            free(next);
        } else b = b->next;
    }
}
static int file_index(xxemul_amigaos *p, uint32_t fh)
{
    uint64_t address = (uint64_t)fh * 4;
    unsigned i;
    if (address < HANDLES || (address - HANDLES) % 64) return -1;
    i = (unsigned)((address - HANDLES) / 64);
    if (i >= FILE_COUNT || (!p->files[i] && !p->console[i])) return -1;
    return (int)i;
}
static uint32_t write_bytes(xxemul_amigaos *p, uint32_t fh, const void *data, size_t size)
{
    int i = file_index(p, fh);
    if (i < 0 || p->console[i] == 1) {
        p->ioerr = 209;
        return UINT32_MAX;
    }
    if (p->console[i]) {
        xxemul_emit_output(p->e, 1, data, size);
    } else if (fseek(p->files[i], 0, SEEK_CUR) || fwrite(data, 1, size, p->files[i]) != size) {
        p->ioerr = 221;
        return UINT32_MAX;
    }
    p->ioerr = 0;
    return (uint32_t)size;
}
static uint32_t transfer(xxemul_amigaos *p, uint32_t fh, uint32_t address, uint32_t size, int writing)
{
    uint8_t buffer[4096];
    uint32_t done = 0;
    int i = file_index(p, fh);
    if (i < 0 || size > INT32_MAX) {
        p->ioerr = 209;
        return UINT32_MAX;
    }
    if ((uint64_t)address + size > p->e->region_size) {
        stop(p, XXEMUL_STATUS_ADDRESS_FAULT, "dos.library: invalid Read/Write buffer");
        return UINT32_MAX;
    }
    if (!writing && p->files[i] && fseek(p->files[i], 0, SEEK_CUR)) {
        p->ioerr = 219;
        return UINT32_MAX;
    }
    while (done < size) {
        size_t n = size - done < sizeof(buffer) ? size - done : sizeof(buffer);
        if (writing) {
            if (!read_guest(p, address + done, buffer, n) || write_bytes(p, fh, buffer, n) == UINT32_MAX) return UINT32_MAX;
        } else {
            if (p->console[i]) {
                p->ioerr = 0;
                return done;
            } /* CLI stdin has deterministic EOF. */
            n = fread(buffer, 1, n, p->files[i]);
            if (!n) {
                if (ferror(p->files[i])) {
                    p->ioerr = 212;
                    return UINT32_MAX;
                }
                break;
            }
            if (!write_guest(p, address + done, buffer, n)) return UINT32_MAX;
        }
        done += (uint32_t)n;
    }
    p->ioerr = 0;
    return done;
}
static int resolve(xxemul_amigaos *p, uint32_t address, char host[2048], int creating)
{
    char name[260];
    uint16_t error;
    if (!guest_string(p, address, name, sizeof(name))) return 0;
    /* Device names other than the console are deliberately not host paths. */
    if (strchr(name, ':') || name[0] == '/' || name[0] == '\\') {
        p->ioerr = 205;
        return 0;
    }
    error = xxemul_host_resolve(p->root, name, host, 2048, creating);
    if (error) {
        p->ioerr = error == 2 ? 205 : 214;
        return 0;
    }
    return 1;
}
static uint32_t open_file(xxemul_amigaos *p, uint32_t name_address, uint32_t mode)
{
    char name[260], host[2048];
    unsigned i;
    if (mode != 1004 && mode != 1005 && mode != 1006) {
        p->ioerr = 209;
        return 0;
    }
    if (!guest_string(p, name_address, name, sizeof(name))) return 0;
    for (i = 2; i < FILE_COUNT && (p->files[i] || p->console[i]); ++i) {
    }
    if (i == FILE_COUNT) {
        p->ioerr = 103;
        return 0;
    }
    if (!strcmp(name, "*") || !strcmp(name, "CONSOLE:")) p->console[i] = 2;
    else {
        if (!resolve(p, name_address, host, mode != 1005)) return 0;
        p->files[i] = fopen(host, mode == 1006 ? "w+b" : "r+b");
        if (!p->files[i] && mode == 1005 && (errno == EACCES || errno == EROFS)) p->files[i] = fopen(host, "rb");
        if (!p->files[i] && mode == 1004 && errno == ENOENT) p->files[i] = fopen(host, "w+b");
        if (!p->files[i]) {
            p->ioerr = errno == ENOENT ? 205 : 214;
            return 0;
        }
    }
    p->ioerr = 0;
    return handle(i);
}

typedef struct text_buffer {
    char *data;
    size_t size, capacity;
} text_buffer;
static int append(text_buffer *b, const char *data, size_t n)
{
    if (n > TEXT_LIMIT - b->size) return 0;
    if (b->size + n + 1 > b->capacity) {
        size_t capacity = (b->size + n + 1) * 2;
        char *next = realloc(b->data, capacity);
        if (!next) return 0;
        b->data = next;
        b->capacity = capacity;
    }
    memcpy(b->data + b->size, data, n);
    b->size += n;
    b->data[b->size] = 0;
    return 1;
}
/* RawDoFmt and DOS V*Printf consume WORD numbers unless 'l' is present.
 * Pointers and BPTRs always occupy four bytes. No host varargs
 * are ever taken from guest memory. Width/precision are bounded to 4096. */
static int format_text(xxemul_amigaos *p, uint32_t fmt, uint32_t *arguments, text_buffer *out)
{
    char format[65536], string[65536], number[8192];
    size_t i = 0;
    if (!guest_string(p, fmt, format, sizeof(format))) return 0;
    while (format[i]) {
        unsigned width = 0, precision = 0, size;
        int left = 0, zero = 0, plus = 0, space = 0, alternate = 0, have_precision = 0, longword = 0;
        uint32_t value;
        char spec;
        const char *data;
        size_t length, padding;
        if (format[i] != '%') {
            if (!append(out, format + i++, 1)) goto limit;
            continue;
        }
        ++i;
        if (format[i] == '%') {
            if (!append(out, format + i++, 1)) goto limit;
            continue;
        }
        for (;;) {
            char f = format[i];
            if (f == '-') left = 1;
            else if (f == '0') zero = 1;
            else if (f == '+') plus = 1;
            else if (f == ' ') space = 1;
            else if (f == '#') alternate = 1;
            else break;
            ++i;
        }
        while (format[i] >= '0' && format[i] <= '9') {
            width = width * 10 + (unsigned)(format[i++] - '0');
            if (width > 4096) goto limit;
        }
        if (format[i] == '.') {
            ++i;
            have_precision = 1;
            while (format[i] >= '0' && format[i] <= '9') {
                precision = precision * 10 + (unsigned)(format[i++] - '0');
                if (precision > 4096) goto limit;
            }
        }
        if (format[i] == 'l') {
            longword = 1;
            ++i;
        }
        spec = format[i];
        if (!spec) goto unsupported;
        ++i;
        if (!strchr("diuxXscb", spec)) goto unsupported;
        size = longword || spec == 's' || spec == 'b' ? 4 : 2;
        value = get_number(p, *arguments, size);
        if (p->terminal || *arguments > UINT32_MAX - size) return 0;
        *arguments += size;
        if (spec == 's' || spec == 'b') {
            if (!value) {
                string[0] = 0;
                length = 0;
            } else if (spec == 's') {
                if (!guest_string(p, value, string, sizeof(string))) return 0;
                length = strlen(string);
            } else {
                uint8_t n;
                if (value > UINT32_MAX / 4 || !read_guest(p, value * 4, &n, 1) || !read_guest(p, value * 4 + 1, string, n)) return 0;
                length = n;
            }
            if (have_precision && length > precision) length = precision;
            data = string;
        } else if (spec == 'c') {
            string[0] = (char)value;
            data = string;
            length = 1;
        } else {
            char control[48];
            int n;
            snprintf(control, sizeof(control), "%%%s%s%s%s%s%u", left ? "-" : "", plus ? "+" : "", space ? " " : "", alternate ? "#" : "", zero ? "0" : "", width);
            if (have_precision) snprintf(control + strlen(control), sizeof(control) - strlen(control), ".%u", precision);
            if (spec == 'd' || spec == 'i') {
                strncat(control, PRId32, sizeof(control) - strlen(control) - 1);
                n = snprintf(number, sizeof(number), control, size == 2 ? (int32_t)(int16_t)value : (int32_t)value);
            } else {
                strncat(control, spec == 'u' ? PRIu32 : spec == 'x' ? PRIx32 : PRIX32, sizeof(control) - strlen(control) - 1);
                n = snprintf(number, sizeof(number), control, value);
            }
            if (n < 0 || (size_t)n >= sizeof(number)) goto limit;
            if (!append(out, number, (size_t)n)) goto limit;
            continue;
        }
        padding = width > length ? width - length : 0;
        if (!left)
            while (padding--)
                if (!append(out, " ", 1)) goto limit;
        if (!append(out, data, length)) goto limit;
        if (left)
            while (padding--)
                if (!append(out, " ", 1)) goto limit;
    }
    return 1;
unsupported:
    stop(p, XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION, "AmigaOS: unsupported format conversion");
    return 0;
limit:
    stop(p, XXEMUL_STATUS_OUT_OF_MEMORY, "AmigaOS: formatted output exceeds bounded service capacity");
    return 0;
}
static void raw_format(xxemul_amigaos *p)
{
    xxemul_m68k_state *r = &p->e->m68k;
    text_buffer out = {0};
    uint32_t arguments = r->a[1];
    uint8_t code[4];
    int mode = r->a[2] <= 2 ? (int)r->a[2] : -1;
    /* Native RAWFMTFUNC_STRING (0), SERIAL (1), COUNT (2), or the documented
     * move.b d0,(a3)+; rts callback. Arbitrary guest callbacks are not run. */
    if (mode < 0 && read_guest(p, r->a[2], code, sizeof(code)) && !memcmp(code, "\x16\xc0\x4e\x75", 4)) mode = 0;
    if (mode < 0) {
        if (!p->terminal) stop(p, XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION, "exec.library/RawDoFmt: unsupported PutChProc");
        return;
    }
    if (format_text(p, r->a[0], &arguments, &out)) {
        if (!append(&out, "", 1)) stop(p, XXEMUL_STATUS_OUT_OF_MEMORY, "exec.library/RawDoFmt: output limit");
        else if (mode == 0) {
            if (write_guest(p, r->a[3], out.data, out.size)) r->a[3] += (uint32_t)out.size;
        } else if (mode == 1) xxemul_emit_output(p->e, 1, out.data, out.size - 1);
        else {
            uint32_t count = get_number(p, r->a[3], 4);
            if (!p->terminal) store_number(p, r->a[3], count + (uint32_t)out.size);
        }
        r->a[1] = arguments;
        r->d[0] = arguments;
    }
    free(out.data);
}
static uint32_t dos_format(xxemul_amigaos *p, uint32_t fh, uint32_t fmt, uint32_t args)
{
    text_buffer out = {0};
    uint32_t result = UINT32_MAX;
    if (format_text(p, fmt, &args, &out)) result = write_bytes(p, fh, out.data ? out.data : "", out.size);
    free(out.data);
    return result;
}
static void unknown(xxemul_amigaos *p, unsigned lib, unsigned lvo)
{
    char message[128];
    snprintf(message, sizeof(message), "%s.library: unsupported LVO -%u", lib ? "dos" : "exec", lvo);
    stop(p, XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION, message);
}
static void exec_call(xxemul_amigaos *p, unsigned lvo)
{
    xxemul_m68k_state *r = &p->e->m68k;
    uint32_t value, mask;
    char name[260];
    switch (lvo) {
        case 552:
        case 408:
            if (!guest_string(p, r->a[1], name, sizeof(name))) break;
            value = !strcmp(name, "exec.library") ? EXEC_BASE : !strcmp(name, "dos.library") ? DOS_BASE : 0;
            r->d[0] = lvo == 552 && r->d[0] > 40 ? 0 : value;
            break;
        case 414:
        case 132:
        case 138:
        case 378: break;
        case 198:
        case 684: r->d[0] = allocate(p, r->d[0], r->d[1]); break;
        case 210:
        case 690: release(p, r->a[1]); break;
        case 294: r->d[0] = r->a[1] == 0 ? TASK : 0; break;
        case 306:
            value = p->signals;
            mask = r->d[1];
            p->signals = (value & ~mask) | (r->d[0] & mask);
            store_number(p, TASK + 26, p->signals);
            r->d[0] = value;
            break;
        case 318:
            value = p->signals & r->d[0];
            p->signals &= ~value;
            r->d[0] = value;
            store_number(p, TASK + 26, p->signals);
            if (!value) stop(p, XXEMUL_STATUS_HALTED, "exec.library/Wait: no pending signal; no asynchronous signal source");
            break;
        case 372: r->d[0] = 0; break;
        case 384: stop(p, XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION, "exec.library/WaitPort: Workbench startup is unsupported; process is CLI-started"); break;
        case 624:
        case 630: {
            uint32_t size = r->d[0];
            uint8_t *copy;
            if (!size) break;
            if (size > p->e->region_size || (uint64_t)r->a[0] + size > p->e->region_size || (uint64_t)r->a[1] + size > p->e->region_size) {
                stop(p, XXEMUL_STATUS_ADDRESS_FAULT, "exec.library/CopyMem: invalid buffer");
                break;
            }
            copy = malloc(size);
            if (!copy) {
                stop(p, XXEMUL_STATUS_OUT_OF_MEMORY, "exec.library/CopyMem: allocation failed");
                break;
            }
            if (read_guest(p, r->a[0], copy, size)) write_guest(p, r->a[1], copy, size);
            free(copy);
            break;
        }
        case 522: raw_format(p); break;
        case 420: {
            int32_t offset = (int32_t)r->a[0];
            unsigned lib;
            uint32_t address;
            uint8_t jump[6];
            if ((r->a[1] != EXEC_BASE && r->a[1] != DOS_BASE) || offset >= 0 || offset % 6 || offset < -(int32_t)(SLOT_COUNT * 6)) {
                r->d[0] = 0;
                break;
            }
            lib = r->a[1] == DOS_BASE;
            address = library_base(lib) + offset;
            value = get_number(p, address + 2, 4);
            put16(jump, 0x4ef9);
            put32(jump + 2, r->d[0]);
            if (write_guest(p, address, jump, sizeof(jump))) r->d[0] = value;
            break;
        }
        default: unknown(p, 0, lvo); break;
    }
}
static void dos_call(xxemul_amigaos *p, unsigned lvo)
{
    xxemul_m68k_state *r = &p->e->m68k;
    uint32_t d1 = r->d[1], d2 = r->d[2], d3 = r->d[3];
    char string[65536], host[2048];
    int i;
    switch (lvo) {
        case 60: r->d[0] = handle(1); break;
        case 54: r->d[0] = handle(0); break;
        case 30: r->d[0] = open_file(p, d1, d2); break;
        case 36:
            i = file_index(p, d1);
            r->d[0] = 0;
            if (i < 0) p->ioerr = 209;
            else {
                int error = p->files[i] ? fclose(p->files[i]) : 0;
                p->files[i] = NULL;
                if (i > 1) p->console[i] = 0;
                p->ioerr = error ? 221 : 0;
                r->d[0] = error ? 0 : UINT32_MAX;
            }
            break;
        case 48:
        case 42: r->d[0] = transfer(p, d1, d2, d3, lvo == 48); break;
        case 66:
            i = file_index(p, d1);
            r->d[0] = UINT32_MAX;
            if (i < 0 || !p->files[i] || (int32_t)d3 < -1 || (int32_t)d3 > 1) p->ioerr = 219;
            else {
                long old = ftell(p->files[i]);
                if (old < 0 || (uint64_t)old > INT32_MAX || fseek(p->files[i], (int32_t)d2, d3 == UINT32_MAX ? SEEK_SET : d3 == 0 ? SEEK_CUR : SEEK_END)) p->ioerr = 219;
                else {
                    r->d[0] = (uint32_t)old;
                    p->ioerr = 0;
                }
            }
            break;
        case 72:
            r->d[0] = 0;
            if (resolve(p, d1, host, 0)) {
                if (!remove(host)) {
                    r->d[0] = UINT32_MAX;
                    p->ioerr = 0;
                } else p->ioerr = 222;
            }
            break;
        case 132: r->d[0] = p->ioerr; break;
        case 462:
            r->d[0] = p->ioerr;
            p->ioerr = d1;
            break;
        case 948:
        case 342:
            if (guest_string(p, lvo == 948 ? d1 : d2, string, sizeof(string)))
                r->d[0] = write_bytes(p, lvo == 948 ? handle(1) : d1, string, strlen(string)) == UINT32_MAX ? UINT32_MAX : 0;
            break;
        case 312: {
            uint8_t ch = (uint8_t)d2;
            r->d[0] = write_bytes(p, d1, &ch, 1) == UINT32_MAX ? UINT32_MAX : ch;
            break;
        }
        case 954: r->d[0] = dos_format(p, handle(1), d1, d2); break;
        case 354: r->d[0] = dos_format(p, d1, d2, d3); break;
        case 198: break; /* Deterministic virtual Delay: no wall-clock sleeping. */
        case 144:
            p->exit_code = (int32_t)d1;
            stop(p, XXEMUL_STATUS_HALTED, NULL);
            break;
        case 192: {
            time_t now = time(NULL);
            uint64_t seconds = now > 252460800 ? (uint64_t)now - 252460800u : 0;
            uint8_t stamp[12];
            put32(stamp, (uint32_t)(seconds / 86400));
            put32(stamp + 4, (uint32_t)(seconds % 86400 / 60));
            put32(stamp + 8, (uint32_t)(seconds % 60 * 50));
            if (write_guest(p, d1, stamp, sizeof(stamp))) r->d[0] = d1;
            break;
        }
        default: unknown(p, 1, lvo); break;
    }
}
static xxemul_status trap(xxemul *e, uint32_t vector, uint16_t opcode, void *context)
{
    xxemul_amigaos *p = context;
    uint32_t id = opcode & 0xfffu;
    if (vector != 10) return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    if (e->m68k.pc == EXIT_STUB && opcode == 0xafff) {
        p->exit_code = (int32_t)e->m68k.d[0];
        stop(p, XXEMUL_STATUS_HALTED, NULL);
    } else if (id < SLOT_COUNT * 2 && e->m68k.pc == STUBS + id * 4) {
        if (id / SLOT_COUNT) dos_call(p, (id % SLOT_COUNT + 1) * 6);
        else exec_call(p, (id + 1) * 6);
    } else return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    /* Hook OK consumes line-A. after_step preserves the service's terminal
     * status instead of asking the CPU to deliver a hardware exception. */
    return XXEMUL_STATUS_OK;
}

xxemul_status xxemul_amigaos_start(xxemul *e, const char *program, const char *workdir, int argc, const char *const *argv)
{
    xxemul_amigaos *p;
    uint8_t *memory;
    uint32_t sp, heap;
    size_t length = 0, name_length;
    const char *name = program, *cursor;
    unsigned lib, slot;
    int i;
    if (e->arch != XXEMUL_ARCH_M68K || !e->amiga_hunk_base || e->amigaos) return XXEMUL_STATUS_UNSUPPORTED_IMAGE;
    for (i = 1; i < argc; ++i) {
        size_t n;
        if (!argv[i]) return XXEMUL_STATUS_INVALID_ARGUMENT;
        n = strlen(argv[i]);
        size_t separator = i > 1 ? 1u : 0u;
        if (length + separator > 4094 || n > 4094 - length - separator) return XXEMUL_STATUS_INVALID_ARGUMENT;
        length += n + separator;
    }
    if (length > 4094) return XXEMUL_STATUS_INVALID_ARGUMENT;
    p = calloc(1, sizeof(*p));
    if (!p) return XXEMUL_STATUS_OUT_OF_MEMORY;
    p->e = e;
    p->exit_code = -1;
    if (!xxemul_host_root_path(p->root, sizeof(p->root), workdir)) {
        free(p);
        return XXEMUL_STATUS_IO_ERROR;
    }
    p->blocks = calloc(1, sizeof(*p->blocks));
    if (!p->blocks) {
        free(p);
        return XXEMUL_STATUS_OUT_OF_MEMORY;
    }
    heap = (e->amiga_hunk_end + 7) & ~7u;
    p->blocks->address = heap;
    p->blocks->size = 1024u * 1024u;
    memory = e->region_data;
    for (lib = 0; lib < 2; ++lib)
        for (slot = 1; slot <= SLOT_COUNT; ++slot) {
            uint32_t address = library_base(lib) - slot * 6, target = stub(lib, slot);
            put16(memory + address, 0x4ef9);
            put32(memory + address + 2, target);
            put16(memory + target, (uint16_t)(0xa000 + lib * SLOT_COUNT + slot - 1));
            put16(memory + target + 2, 0x4e75);
        }
    put32(memory + 4, EXEC_BASE);
    put16(memory + EXIT_STUB, 0xafff);
    /* Minimal NDK Library/ExecBase fields: lib_NegSize/PosSize/Version and
     * ExecBase.ThisTask at 276. ABI structures retain their 68000 packing. */
    for (lib = 0; lib < 2; ++lib) {
        uint32_t b = library_base(lib);
        memory[b + 8] = 9;
        put16(memory + b + 16, SLOT_COUNT * 6);
        put16(memory + b + 18, lib ? 64 : 632);
        put16(memory + b + 20, 40);
    }
    put32(memory + EXEC_BASE + 276, TASK);
    memory[TASK + 8] = 13; /* NT_PROCESS */
    put32(memory + TASK + 58, (uint32_t)e->region_size - STACK_SIZE);
    put32(memory + TASK + 62, (uint32_t)e->region_size);
    memory[TASK + 92 + 8] = 4;                      /* pr_MsgPort.mp_Node.ln_Type = NT_MSGPORT */
    put32(memory + TASK + 92 + 16, TASK);           /* mp_SigTask */
    put32(memory + TASK + 92 + 20, TASK + 92 + 24); /* empty mp_MsgList */
    put32(memory + TASK + 92 + 28, TASK + 92 + 20);
    put32(memory + TASK + 132, STACK_SIZE);
    put32(memory + TASK + 156, handle(0));
    put32(memory + TASK + 160, handle(1));
    put32(memory + TASK + 172, CLI >> 2);
    put32(memory + CLI + 16, COMMAND >> 2); /* cli_CommandName */
    put32(memory + CLI + 28, handle(0));
    put32(memory + CLI + 32, handle(0));
    put32(memory + CLI + 48, handle(1));
    put32(memory + CLI + 52, STACK_SIZE / 4);
    put32(memory + CLI + 56, handle(1));
    put32(memory + CLI + 60, (e->amiga_hunk_base + 4) >> 2);
    for (cursor = program; *cursor; ++cursor)
        if (*cursor == '/' || *cursor == ':' || *cursor == '\\') name = cursor + 1;
    name_length = strlen(name);
    if (name_length > 255) name_length = 255;
    memory[COMMAND] = (uint8_t)name_length;
    memcpy(memory + COMMAND + 1, name, name_length);
    put32(memory + TASK + 10, COMMAND + 1);
    length = 0;
    for (i = 1; i < argc; ++i) {
        size_t n = strlen(argv[i]);
        if (i > 1) memory[ARGUMENTS + length++] = ' ';
        memcpy(memory + ARGUMENTS + length, argv[i], n);
        length += n;
    }
    memory[ARGUMENTS + length++] = '\n';
    memory[ARGUMENTS + length] = 0;
    p->console[0] = 1;
    p->console[1] = 2;
    sp = ((uint32_t)e->region_size - 8) & ~3u;
    put32(memory + sp, EXIT_STUB);
    put32(memory + sp + 4, STACK_SIZE);
    e->m68k.a[7] = sp;
    e->m68k.usp = sp;
    e->m68k.sr = 0;
    e->m68k.a[0] = ARGUMENTS;
    e->m68k.d[0] = (uint32_t)length;
    e->m68k.a[1] = e->m68k.a[2] = 0;
    e->amigaos = p;
    e->m68k_trap_hook = trap;
    e->m68k_trap_context = p;
    return XXEMUL_STATUS_OK;
}
void xxemul_amigaos_destroy(xxemul_amigaos *p)
{
    unsigned i;
    if (!p) return;
    for (i = 0; i < FILE_COUNT; ++i)
        if (p->files[i]) fclose(p->files[i]);
    while (p->blocks) {
        amiga_block *next = p->blocks->next;
        free(p->blocks);
        p->blocks = next;
    }
    free(p);
}
int xxemul_amigaos_exit_code(const xxemul_amigaos *p)
{
    return p->exit_code;
}
const char *xxemul_amigaos_error(const xxemul_amigaos *p)
{
    return p->error[0] ? p->error : NULL;
}
xxemul_status xxemul_amigaos_after_step(const xxemul_amigaos *p, xxemul_status status)
{
    return p && p->terminal ? p->terminal : status;
}
const char *xxemul_amigaos_symbol(const xxemul_amigaos *p, uint64_t address)
{
    size_t i;
    (void)p;
    if (address == EXIT_STUB) return "AmigaOS/CLIExit";
    for (i = 0; i < sizeof(lvos) / sizeof(lvos[0]); ++i) {
        if (address == library_base(lvos[i].library) - lvos[i].lvo || address == stub(lvos[i].library, lvos[i].lvo / 6)) return lvos[i].name;
    }
    return NULL;
}
