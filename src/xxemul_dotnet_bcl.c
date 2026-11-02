/* Copyright (c) 2026 hors<horsicq@gmail.com>
 * SPDX-License-Identifier: MIT
 * Explicit bounded managed services. No CLR, process launch or unpacking
 * script is used: guest loaders and loaded entry points execute as real CIL. */
#include "xxemul/xxemul_dotnet_bcl.h"
#include "xxemul_dotnet_internal.h"
#include <xxfclib/formats/executable/dotnet/xx_dotnet_resources.h>
#include <xxfclib/algo/sha/xx_sha.h>
#include <xxfclib/algo/deflate/xx_deflate.h>
#include <xxfclib/algo/crc/xx_crc.h>
#include <xxfclib/io/xx_io.h>
#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <math.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct bcl_module bcl_module;
typedef struct bcl_object bcl_object;
typedef enum bcl_kind {
    BCL_STREAM,
    BCL_HASH,
    BCL_ENCODING,
    BCL_ASSEMBLY,
    BCL_METHOD,
    BCL_TYPE,
    BCL_RESOURCE_MANAGER,
    BCL_WRITER,
    BCL_DOMAIN,
    BCL_DELEGATE,
    BCL_EXCEPTION,
    BCL_CONSTANT
} bcl_kind;
struct bcl_object {
    bcl_object *next;
    xxemul_dotnet_vm *vm;
    uint32_t reference;
    bcl_kind kind;
    bcl_module *module;
    size_t index;
    uint8_t *bytes;
    size_t length, capacity, position;
    unsigned closed, codec, decoded, channel, insensitive;
    uint32_t source;
    char *name;
    xxemul_dotnet_value target;
    uint32_t method_token;
};
struct bcl_module {
    bcl_module *next;
    const xxemul_dotnet_program *program;
    xxemul_dotnet_vm *vm;
    int owned, invoking;
    char *location;
};
struct xxemul_dotnet_bcl_host {
    xxemul_dotnet_bcl_config config;
    xxemul_dotnet_bcl_statistics statistics;
    bcl_module *modules, *entry_module;
    bcl_object *objects, *resolver;
    size_t module_count, native_bytes, output_bytes;
    uint64_t remaining_instructions;
    unsigned executing, invoke_depth;
    char *entry_path, *filesystem_root;
    char diagnostic[512];
};

static xxemul_status bcl_dispatch(void *, xxemul_dotnet_vm *, const xxemul_dotnet_method_info *, const xxemul_dotnet_value *, size_t, xxemul_dotnet_value *);
static int bcl_assignable(void *, const char *, const char *);
static int framework_assembly(const char *assembly);
static xxemul_dotnet_value value(xxemul_dotnet_value_kind kind, uint64_t bits)
{
    xxemul_dotnet_value v;
    v.kind = kind;
    v.bits = bits;
    return v;
}
static xxemul_dotnet_value object_value(uint32_t reference)
{
    return value(XXEMUL_DOTNET_VALUE_OBJECT, reference);
}
static xxemul_status host_fail(xxemul_dotnet_bcl_host *h, xxemul_status status, const char *format, ...)
{
    va_list ap;
    if (!h->diagnostic[0]) {
        va_start(ap, format);
        vsnprintf(h->diagnostic, sizeof(h->diagnostic), format, ap);
        va_end(ap);
    }
    return status;
}
static void *host_alloc(xxemul_dotnet_bcl_host *h, size_t bytes)
{
    void *p;
    if (!bytes)
        bytes = 1;
    if (bytes > h->config.max_native_bytes - h->native_bytes)
        return NULL;
    p = calloc(bytes, 1);
    if (p)
        h->native_bytes += bytes;
    return p;
}
static void host_free(xxemul_dotnet_bcl_host *h, void *p, size_t bytes)
{
    if (!p)
        return;
    if (!bytes)
        bytes = 1;
    free(p);
    h->native_bytes -= bytes;
}
static char *host_string(xxemul_dotnet_bcl_host *h, const char *s, size_t n)
{
    char *p;
    if (n == SIZE_MAX || !(p = host_alloc(h, n + 1)))
        return NULL;
    if (n)
        memcpy(p, s, n);
    return p;
}
static bcl_object *lookup(xxemul_dotnet_bcl_host *h, const xxemul_dotnet_vm *vm, uint32_t reference)
{
    bcl_object *o;
    for (o = h->objects; o; o = o->next)
        if (o->vm == vm && o->reference == reference)
            return o;
    return NULL;
}
static bcl_object *attach(xxemul_dotnet_bcl_host *h, xxemul_dotnet_vm *vm, uint32_t reference, bcl_kind kind)
{
    bcl_object *o = lookup(h, vm, reference);
    if (o)
        return o->kind == kind ? o : NULL;
    o = host_alloc(h, sizeof(*o));
    if (!o)
        return NULL;
    o->vm = vm;
    o->reference = reference;
    o->kind = kind;
    o->next = h->objects;
    h->objects = o;
    return o;
}
static xxemul_status new_host_object(xxemul_dotnet_bcl_host *h, xxemul_dotnet_vm *vm, const char *type, bcl_kind kind, bcl_object **out)
{
    uint32_t reference;
    xxemul_status status = xxemul_dotnet_vm_new_object(vm, type, &reference);
    if (status != XXEMUL_STATUS_OK)
        return status;
    *out = attach(h, vm, reference, kind);
    return *out ? XXEMUL_STATUS_OK : host_fail(h, XXEMUL_STATUS_LIMIT_REACHED, "BCL host storage budget reached");
}
static const char *get_string(xxemul_dotnet_vm *vm, xxemul_dotnet_value v, size_t *size)
{
    if (size)
        *size = 0;
    return v.kind == XXEMUL_DOTNET_VALUE_OBJECT && v.bits <= UINT32_MAX ? xxemul_dotnet_vm_get_string(vm, (uint32_t)v.bits, size) : NULL;
}
static int integer(xxemul_dotnet_value v, int64_t *n)
{
    if (v.kind == XXEMUL_DOTNET_VALUE_I4) {
        int32_t x;
        uint32_t bits = (uint32_t)v.bits;
        memcpy(&x, &bits, 4);
        *n = x;
        return 1;
    }
    if (v.kind == XXEMUL_DOTNET_VALUE_I8 || v.kind == XXEMUL_DOTNET_VALUE_NATIVE) {
        memcpy(n, &v.bits, 8);
        return 1;
    }
    return 0;
}
static xxemul_status text_result(xxemul_dotnet_vm *vm, const char *s, size_t n, xxemul_dotnet_value *out)
{
    uint32_t r;
    xxemul_status status = xxemul_dotnet_vm_new_string(vm, s, n, &r);
    if (status == XXEMUL_STATUS_OK)
        *out = object_value(r);
    return status;
}
/* VM strings are canonical UTF8 with the surrogate extension for lone UTF16
 * units. String indexing/slicing is nevertheless always in UTF16 units. */
static xxemul_status utf16_units(xxemul_dotnet_bcl_host *h, const char *s, size_t n, uint16_t **units, size_t *count)
{
    size_t at = 0, used = 0;
    uint16_t *p;
    *units = NULL;
    *count = 0;
    if (n > SIZE_MAX / sizeof(uint16_t) - 1 || !(p = host_alloc(h, (n + 1) * sizeof(*p))))
        return XXEMUL_STATUS_LIMIT_REACHED;
    while (at < n) {
        uint32_t ch;
        unsigned need, j;
        uint8_t first = (uint8_t)s[at++];
        if (first < 0x80) {
            p[used++] = first;
            continue;
        }
        need = first >= 0xc2 && first <= 0xdf ? 1 : first >= 0xe0 && first <= 0xef ? 2 : first >= 0xf0 && first <= 0xf4 ? 3 : 0;
        if (!need || need > n - at)
            goto bad;
        ch = first & ((1u << (6 - need)) - 1);
        for (j = 0; j < need; ++j) {
            uint8_t b = (uint8_t)s[at++];
            if ((b & 0xc0) != 0x80)
                goto bad;
            ch = (ch << 6) | (b & 63);
        }
        if ((need == 1 && ch < 0x80) || (need == 2 && ch < 0x800) || (need == 3 && ch < 0x10000) || ch > 0x10ffff)
            goto bad;
        if (ch >= 0x10000) {
            ch -= 0x10000;
            p[used++] = (uint16_t)(0xd800 + (ch >> 10));
            p[used++] = (uint16_t)(0xdc00 + (ch & 1023));
        } else
            p[used++] = (uint16_t)ch;
    }
    *units = p;
    *count = used;
    return XXEMUL_STATUS_OK;
bad:
    host_free(h, p, (n + 1) * sizeof(*p));
    return XXEMUL_STATUS_DECODE_ERROR;
}
static xxemul_status units_to_text(xxemul_dotnet_bcl_host *h, xxemul_dotnet_vm *vm, const uint16_t *p, size_t count, xxemul_dotnet_value *out)
{
    size_t i, n = 0;
    char *text;
    xxemul_status status;
    if (count > (SIZE_MAX - 1) / 3 || !(text = host_alloc(h, count * 3 + 1)))
        return XXEMUL_STATUS_LIMIT_REACHED;
    for (i = 0; i < count; ++i) {
        uint32_t ch = p[i];
        if (ch >= 0xd800 && ch <= 0xdbff && i + 1 < count && p[i + 1] >= 0xdc00 && p[i + 1] <= 0xdfff) {
            ch = 0x10000 + ((ch - 0xd800) << 10) + p[++i] - 0xdc00;
        }
        if (ch < 0x80)
            text[n++] = (char)ch;
        else if (ch < 0x800) {
            text[n++] = (char)(0xc0 | (ch >> 6));
            text[n++] = (char)(0x80 | (ch & 63));
        } else if (ch < 0x10000) {
            text[n++] = (char)(0xe0 | (ch >> 12));
            text[n++] = (char)(0x80 | ((ch >> 6) & 63));
            text[n++] = (char)(0x80 | (ch & 63));
        } else {
            text[n++] = (char)(0xf0 | (ch >> 18));
            text[n++] = (char)(0x80 | ((ch >> 12) & 63));
            text[n++] = (char)(0x80 | ((ch >> 6) & 63));
            text[n++] = (char)(0x80 | (ch & 63));
        }
    }
    status = text_result(vm, text, n, out);
    host_free(h, text, count * 3 + 1);
    return status;
}
static xxemul_status bytes_result(xxemul_dotnet_vm *vm, const uint8_t *p, size_t n, xxemul_dotnet_value *out)
{
    uint32_t r;
    size_t i;
    xxemul_status status = xxemul_dotnet_vm_new_array(vm, "System.Byte", n, &r);
    if (status != XXEMUL_STATUS_OK)
        return status;
    for (i = 0; i < n; ++i)
        if ((status = xxemul_dotnet_vm_array_set(vm, r, i, value(XXEMUL_DOTNET_VALUE_I4, p[i]))) != XXEMUL_STATUS_OK)
            return status;
    *out = object_value(r);
    return XXEMUL_STATUS_OK;
}
static xxemul_status byte_array(xxemul_dotnet_bcl_host *h, xxemul_dotnet_vm *vm, xxemul_dotnet_value array, uint8_t **data, size_t *size)
{
    const char *type;
    size_t i;
    xxemul_dotnet_value item;
    xxemul_status status;
    *data = NULL;
    *size = 0;
    if (array.kind != XXEMUL_DOTNET_VALUE_OBJECT || array.bits > UINT32_MAX || !(type = xxemul_dotnet_vm_object_type(vm, (uint32_t)array.bits)) ||
        strcmp(type, "System.Byte[]") || xxemul_dotnet_vm_array_length(vm, (uint32_t)array.bits, size) != XXEMUL_STATUS_OK || *size > h->config.max_image_bytes)
        return xxemul_dotnet_vm_raise_type(vm, "System.ArgumentException");
    *data = host_alloc(h, *size);
    if (!*data)
        return XXEMUL_STATUS_LIMIT_REACHED;
    for (i = 0; i < *size; ++i) {
        status = xxemul_dotnet_vm_array_get(vm, (uint32_t)array.bits, i, &item);
        if (status != XXEMUL_STATUS_OK || item.kind != XXEMUL_DOTNET_VALUE_I4 || item.bits > 255) {
            host_free(h, *data, *size);
            *data = NULL;
            return XXEMUL_STATUS_DECODE_ERROR;
        }
        (*data)[i] = (uint8_t)item.bits;
    }
    return XXEMUL_STATUS_OK;
}
static bcl_module *module_for(xxemul_dotnet_bcl_host *h, const xxemul_dotnet_program *program)
{
    bcl_module *m;
    for (m = h->modules; m; m = m->next)
        if (m->program == program)
            return m;
    return NULL;
}
static bcl_module *register_module(xxemul_dotnet_bcl_host *h, const xxemul_dotnet_program *program, int owned, const char *location)
{
    bcl_module *m = module_for(h, program);
    if (m)
        return m;
    if (h->module_count >= h->config.max_loaded_assemblies || !(m = host_alloc(h, sizeof(*m))))
        return NULL;
    m->program = program;
    m->owned = owned;
    m->location = host_string(h, location, strlen(location));
    if (!m->location) {
        host_free(h, m, sizeof(*m));
        return NULL;
    }
    m->next = h->modules;
    h->modules = m;
    ++h->module_count;
    ++h->statistics.assemblies_loaded;
    return m;
}
static xxemul_status assembly_object(xxemul_dotnet_bcl_host *h, xxemul_dotnet_vm *vm, bcl_module *module, xxemul_dotnet_value *out)
{
    bcl_object *o;
    xxemul_status status;
    if (!module) {
        *out = object_value(0);
        return XXEMUL_STATUS_OK;
    }
    for (o = h->objects; o; o = o->next)
        if (o->vm == vm && o->kind == BCL_ASSEMBLY && o->module == module) {
            *out = object_value(o->reference);
            return XXEMUL_STATUS_OK;
        }
    status = new_host_object(h, vm, "System.Reflection.Assembly", BCL_ASSEMBLY, &o);
    if (status == XXEMUL_STATUS_OK) {
        o->module = module;
        *out = object_value(o->reference);
    }
    return status;
}
static const char *parent_type(const char *type)
{
    if (!strcmp(type, "System.Text.UTF8Encoding"))
        return "System.Text.Encoding";
    if (!strcmp(type, "System.IO.MemoryStream") || !strcmp(type, "System.IO.FileStream") || !strcmp(type, "System.IO.UnmanagedMemoryStream") ||
        !strcmp(type, "System.IO.Compression.DeflateStream") || !strcmp(type, "System.IO.Compression.GZipStream") ||
        !strcmp(type, "ICSharpCode.SharpZipLib.Zip.Compression.Streams.InflaterInputStream"))
        return "System.IO.Stream";
    if (!strcmp(type, "System.IO.Stream") || !strcmp(type, "System.Security.Cryptography.HashAlgorithm"))
        return "System.IDisposable";
    if (!strcmp(type, "System.Security.Cryptography.SHA256") || !strcmp(type, "System.Security.Cryptography.SHA256Managed"))
        return "System.Security.Cryptography.HashAlgorithm";
    if (!strcmp(type, "System.Reflection.MethodInfo"))
        return "System.Reflection.MethodBase";
    if (!strcmp(type, "System.Reflection.MethodBase"))
        return "System.Reflection.MemberInfo";
    if (!strcmp(type, "System.ResolveEventHandler"))
        return "System.MulticastDelegate";
    if (!strcmp(type, "System.MulticastDelegate"))
        return "System.Delegate";
    if (!strcmp(type, "System.ObjectDisposedException"))
        return "System.InvalidOperationException";
    if (!strcmp(type, "System.FieldAccessException") || !strcmp(type, "System.MissingMethodException"))
        return "System.MemberAccessException";
    if (!strcmp(type, "System.MemberAccessException"))
        return "System.SystemException";
    if (!strcmp(type, "System.SystemException") || !strcmp(type, "System.ApplicationException"))
        return "System.Exception";
    if (!strcmp(type, "System.Reflection.TargetInvocationException"))
        return "System.ApplicationException";
    if (!strcmp(type, "System.Reflection.TargetParameterCountException"))
        return "System.ApplicationException";
    if (!strcmp(type, "System.IO.InvalidDataException") || !strcmp(type, "System.IO.FileNotFoundException") ||
        !strcmp(type, "System.IO.DirectoryNotFoundException"))
        return "System.IO.IOException";
    if (!strcmp(type, "System.ArgumentOutOfRangeException") || !strcmp(type, "System.ArgumentNullException"))
        return "System.ArgumentException";
    if (!strcmp(type, "System.ArgumentException") || !strcmp(type, "System.InvalidOperationException") || !strcmp(type, "System.NullReferenceException") ||
        !strcmp(type, "System.IndexOutOfRangeException") || !strcmp(type, "System.DivideByZeroException") || !strcmp(type, "System.OverflowException") ||
        !strcmp(type, "System.NotSupportedException") || !strcmp(type, "System.InvalidCastException") || !strcmp(type, "System.ObjectDisposedException") ||
        !strcmp(type, "System.FormatException") || !strcmp(type, "System.UnauthorizedAccessException") || !strcmp(type, "System.IO.IOException") ||
        !strcmp(type, "System.TypeLoadException") || !strcmp(type, "System.MissingMethodException") ||
        !strcmp(type, "System.Resources.MissingManifestResourceException") || !strcmp(type, "System.FieldAccessException") ||
        !strcmp(type, "System.BadImageFormatException"))
        return "System.SystemException";
    return NULL;
}
static int bcl_assignable(void *context, const char *source, const char *destination)
{
    unsigned i;
    (void)context;
    if (!strcmp(source, destination) || !strcmp(destination, "System.Object"))
        return 1;
    if (strlen(source) >= 2 && !strcmp(source + strlen(source) - 2, "[]")) {
        if (!strcmp(destination, "System.Array") || !strcmp(destination, "System.Collections.IEnumerable") ||
            !strcmp(destination, "System.Collections.ICollection") || !strcmp(destination, "System.Collections.IList"))
            return 1;
        return 0;
    }
    for (i = 0; i < 32 && source; ++i) {
        if (!strcmp(source, destination))
            return 1;
        source = parent_type(source);
    }
    return -1;
}
static xxemul_status buffer_reserve(xxemul_dotnet_bcl_host *h, bcl_object *o, size_t capacity)
{
    uint8_t *bytes;
    size_t target;
    if (capacity <= o->capacity)
        return XXEMUL_STATUS_OK;
    if (capacity > h->config.max_image_bytes)
        return XXEMUL_STATUS_LIMIT_REACHED;
    target = o->capacity ? o->capacity : h->config.max_image_bytes < 256 ? h->config.max_image_bytes : 256;
    while (target < capacity) {
        if (target > h->config.max_image_bytes / 2) {
            target = h->config.max_image_bytes;
            break;
        }
        target *= 2;
    }
    if (target > h->config.max_native_bytes - h->native_bytes + o->capacity)
        return XXEMUL_STATUS_LIMIT_REACHED;
    bytes = realloc(o->bytes, target);
    if (!bytes)
        return XXEMUL_STATUS_OUT_OF_MEMORY;
    memset(bytes + o->capacity, 0, target - o->capacity);
    h->native_bytes += target - o->capacity;
    o->bytes = bytes;
    o->capacity = target;
    return XXEMUL_STATUS_OK;
}
static xxemul_status sync_array_stream(xxemul_dotnet_vm *vm, bcl_object *o)
{
    size_t i;
    xxemul_dotnet_value item;
    xxemul_status status;
    if (o->codec || !o->insensitive || !o->source)
        return XXEMUL_STATUS_OK;
    for (i = 0; i < o->length; ++i) {
        if ((status = xxemul_dotnet_vm_array_get(vm, o->source, i, &item)) != XXEMUL_STATUS_OK)
            return status;
        if (item.kind != XXEMUL_DOTNET_VALUE_I4 || item.bits > 255)
            return XXEMUL_STATUS_DECODE_ERROR;
        o->bytes[i] = (uint8_t)item.bits;
    }
    return XXEMUL_STATUS_OK;
}
typedef struct bcl_decode_sink {
    uint8_t *bytes;
    size_t capacity, position;
    int limit_reached;
} bcl_decode_sink;
static ssize_t decode_write(xx_io_device *device, const void *data, size_t size)
{
    bcl_decode_sink *sink = device->priv;
    if (size > sink->capacity - sink->position) {
        sink->limit_reached = 1;
        return -1;
    }
    if (size)
        memcpy(sink->bytes + sink->position, data, size);
    sink->position += size;
    return (ssize_t)size;
}
static int64_t decode_tell(xx_io_device *device)
{
    return (int64_t)((bcl_decode_sink *)device->priv)->position;
}
static void close_stream(xxemul_dotnet_bcl_host *h, xxemul_dotnet_vm *vm, bcl_object *o)
{
    o->closed = 1;
    if (o->codec) {
        bcl_object *source = lookup(h, vm, o->source);
        if (source && !o->channel)
            close_stream(h, vm, source);
        host_free(h, o->bytes, o->capacity);
        o->bytes = NULL;
        o->capacity = 0;
    }
}
static xxemul_status stream_decode(xxemul_dotnet_bcl_host *h, xxemul_dotnet_vm *vm, bcl_object *o)
{
    bcl_object *source;
    xx_io_device *src = NULL, sink_device = {0}, *dst = &sink_device;
    bcl_decode_sink sink = {0};
    xx_pd_struct pd = xx_pd_init();
    uint8_t *decoded;
    const uint8_t *input;
    size_t capacity = h->config.max_image_bytes;
    int64_t consumed = 0, written;
    size_t offset = 0, input_size;
    int okay = 0;
    xxemul_status status;
    if (!o->codec || o->decoded)
        return XXEMUL_STATUS_OK;
    source = lookup(h, vm, o->source);
    if (!source || source->kind != BCL_STREAM || source->closed)
        return xxemul_dotnet_vm_raise_type(vm, "System.ObjectDisposedException");
    if (source->position > source->length)
        return XXEMUL_STATUS_DECODE_ERROR;
    if ((status = sync_array_stream(vm, source)) != XXEMUL_STATUS_OK)
        return status;
    input_size = source->length - source->position;
    input = input_size ? source->bytes + source->position : (const uint8_t *)"";
    if (capacity > h->config.max_native_bytes - h->native_bytes)
        capacity = h->config.max_native_bytes - h->native_bytes;
    if (!capacity)
        return XXEMUL_STATUS_LIMIT_REACHED;
    decoded = host_alloc(h, capacity);
    if (!decoded)
        return XXEMUL_STATUS_LIMIT_REACHED;
    sink.bytes = decoded;
    sink.capacity = capacity;
    sink_device.priv = &sink;
    sink_device.write = decode_write;
    sink_device.tell = decode_tell;
    src = xx_io_mem_open_ro(input, input_size);
    if (src && dst) {
        if (o->codec == 1) {
            okay = input_size >= 6 && xx_zlib_stream_header_is_valid(input, input_size) &&
                   xx_deflate_unpack_device_ex(src, 2, (int64_t)input_size - 6, dst, false, (size_t)1 << ((input[0] >> 4) + 8), NULL, 0, &consumed, &pd) &&
                   consumed == (int64_t)input_size - 6;
        } else if (o->codec == 2) {
            okay = xx_deflate_unpack_device_ex(src, 0, (int64_t)input_size, dst, false, 0, NULL, 0, &consumed, &pd) && consumed == (int64_t)input_size;
        } else {
            const uint8_t *p = input;
            uint8_t flags = 0;
            if (input_size >= 18 && p[0] == 31 && p[1] == 139 && p[2] == 8 && !(p[3] & 0xe0)) {
                flags = p[3];
                offset = 10;
                if (flags & 4) {
                    size_t n;
                    if (input_size - offset < 2)
                        goto decoded_done;
                    n = p[offset] | (size_t)p[offset + 1] << 8;
                    offset += 2;
                    if (n > input_size - offset)
                        goto decoded_done;
                    offset += n;
                }
                if (flags & 8) {
                    while (offset < input_size && p[offset])
                        ++offset;
                    if (offset == input_size)
                        goto decoded_done;
                    ++offset;
                }
                if (flags & 16) {
                    while (offset < input_size && p[offset])
                        ++offset;
                    if (offset == input_size)
                        goto decoded_done;
                    ++offset;
                }
                if (flags & 2) {
                    uint16_t expected;
                    if (input_size - offset < 2)
                        goto decoded_done;
                    expected = (uint16_t)(p[offset] | (uint16_t)p[offset + 1] << 8);
                    if ((uint16_t)xx_crc32(XX_CRC_TYPE_CRC32, p, offset) != expected)
                        goto decoded_done;
                    offset += 2;
                }
                if (offset <= input_size && input_size - offset >= 8)
                    okay = xx_deflate_unpack_device_ex(src, (int64_t)offset, (int64_t)(input_size - offset - 8), dst, false, 0, NULL, 0, &consumed, &pd) &&
                           consumed == (int64_t)(input_size - offset - 8);
            }
        }
    }
decoded_done:
    written = dst ? xx_io_tell(dst) : -1;
    if (written < 0 || (uint64_t)written > capacity)
        okay = 0;
    if (okay && o->codec == 1)
        okay = xx_zlib_stream_trailer_matches(input, input_size, decoded, (size_t)written);
    if (okay && o->codec == 3) {
        const uint8_t *tail = source->bytes + source->length - 8;
        okay = xxemul_dotnet_u32(tail) == xx_crc32(XX_CRC_TYPE_CRC32, decoded, (size_t)written) && xxemul_dotnet_u32(tail + 4) == (uint32_t)written;
    }
    if (src)
        xx_io_close(src);
    if (!okay) {
        host_free(h, decoded, capacity);
        if (sink.limit_reached)
            return host_fail(h, XXEMUL_STATUS_LIMIT_REACHED, "decompressed stream exceeds configured storage bound");
        return xxemul_dotnet_vm_raise_type(vm, "System.IO.InvalidDataException");
    }
    {
        size_t actual = written ? (size_t)written : 1;
        uint8_t *smaller = realloc(decoded, actual);
        if (!smaller) {
            host_free(h, decoded, capacity);
            return XXEMUL_STATUS_OUT_OF_MEMORY;
        }
        decoded = smaller;
        h->native_bytes -= capacity - actual;
        capacity = actual;
    }
    o->bytes = decoded;
    o->capacity = capacity;
    o->length = (size_t)written;
    o->decoded = 1;
    source->position = source->length;
    return XXEMUL_STATUS_OK;
}
static xxemul_status clone_value(xxemul_dotnet_bcl_host *h, xxemul_dotnet_vm *from, xxemul_dotnet_vm *to, xxemul_dotnet_value in, xxemul_dotnet_value *out,
                                 unsigned depth)
{
    const char *text, *type;
    size_t n, i;
    uint32_t ref;
    xxemul_status status;
    xxemul_dotnet_value item, cloned;
    if (from == to || in.kind != XXEMUL_DOTNET_VALUE_OBJECT || !in.bits) {
        *out = in;
        return XXEMUL_STATUS_OK;
    }
    if (depth > 32)
        return XXEMUL_STATUS_LIMIT_REACHED;
    text = xxemul_dotnet_vm_get_string(from, (uint32_t)in.bits, &n);
    if (text)
        return text_result(to, text, n, out);
    type = xxemul_dotnet_vm_object_type(from, (uint32_t)in.bits);
    if (!type)
        return XXEMUL_STATUS_ADDRESS_FAULT;
    if (xxemul_dotnet_vm_unbox(from, (uint32_t)in.bits, &item) == XXEMUL_STATUS_OK) {
        status = xxemul_dotnet_vm_box(to, type, item, &ref);
        if (status == XXEMUL_STATUS_OK)
            *out = object_value(ref);
        return status;
    }
    n = strlen(type);
    if (n >= 2 && !strcmp(type + n - 2, "[]")) {
        char *element = host_string(h, type, n - 2);
        size_t length;
        if (!element)
            return XXEMUL_STATUS_LIMIT_REACHED;
        status = xxemul_dotnet_vm_array_length(from, (uint32_t)in.bits, &length);
        if (status == XXEMUL_STATUS_OK)
            status = xxemul_dotnet_vm_new_array(to, element, length, &ref);
        host_free(h, element, n - 1);
        if (status != XXEMUL_STATUS_OK)
            return status;
        for (i = 0; i < length; ++i) {
            if ((status = xxemul_dotnet_vm_array_get(from, (uint32_t)in.bits, i, &item)) != XXEMUL_STATUS_OK ||
                (status = clone_value(h, from, to, item, &cloned, depth + 1)) != XXEMUL_STATUS_OK ||
                (status = xxemul_dotnet_vm_array_set(to, ref, i, cloned)) != XXEMUL_STATUS_OK)
                return status;
        }
        *out = object_value(ref);
        return XXEMUL_STATUS_OK;
    }
    return host_fail(h, XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION, "cross-assembly reference type is unsupported: %s", type);
}
static xxemul_status intrinsic_callback(void *context, xxemul_dotnet_vm *vm, const xxemul_dotnet_method_info *m, const xxemul_dotnet_value *a, size_t count,
                                        xxemul_dotnet_value *result, int *handled)
{
    xxemul_dotnet_bcl_host *h = context;
    *handled = 0;
    if ((h->config.flags & XXEMUL_DOTNET_BCL_SHARPZIP_STREAMS) &&
        !strcmp(m->type_name, "ICSharpCode.SharpZipLib.Zip.Compression.Streams.InflaterInputStream") &&
        (!strcmp(m->name, ".ctor") || !strcmp(m->name, "Read") || !strcmp(m->name, "Close") || !strcmp(m->name, "Dispose"))) {
        *handled = 1;
        return bcl_dispatch(h, vm, m, a, count, result);
    }
    return XXEMUL_STATUS_OK;
}
static xxemul_status field_callback(void *context, xxemul_dotnet_vm *vm, const xxemul_dotnet_field_info *field, int store, xxemul_dotnet_value *result,
                                    int *handled)
{
    xxemul_dotnet_bcl_host *h = context;
    bcl_object *o;
    xxemul_status status;
    uint32_t reference;
    *handled = 0;
    if (!framework_assembly(field->assembly_name))
        return XXEMUL_STATUS_OK;
    if (!strcmp(field->type_name, "System.String") && !strcmp(field->name, "Empty") && !strcmp(field->signature, "System.String")) {
        *handled = 1;
        if (store)
            return xxemul_dotnet_vm_raise_type(vm, "System.FieldAccessException");
        for (o = h->objects; o; o = o->next)
            if (o->vm == vm && o->kind == BCL_CONSTANT && o->name && !strcmp(o->name, "System.String.Empty")) {
                *result = object_value(o->reference);
                return XXEMUL_STATUS_OK;
            }
        status = xxemul_dotnet_vm_new_string(vm, "", 0, &reference);
        if (status != XXEMUL_STATUS_OK)
            return status;
        o = attach(h, vm, reference, BCL_CONSTANT);
        if (!o)
            return XXEMUL_STATUS_LIMIT_REACHED;
        o->name = host_string(h, "System.String.Empty", 19);
        if (!o->name)
            return XXEMUL_STATUS_LIMIT_REACHED;
        *result = object_value(reference);
        return XXEMUL_STATUS_OK;
    }
    return XXEMUL_STATUS_OK;
}
static xxemul_status ensure_vm(xxemul_dotnet_bcl_host *h, bcl_module *module, uint64_t budget)
{
    xxemul_dotnet_vm_config config;
    xxemul_status status;
    if (module->vm)
        return XXEMUL_STATUS_OK;
    memset(&config, 0, sizeof(config));
    config.max_instructions = budget;
    config.max_heap_bytes = h->config.max_heap_bytes;
    config.external_callback = bcl_dispatch;
    config.external_context = h;
    config.intrinsic_callback = intrinsic_callback;
    config.intrinsic_context = h;
    config.field_callback = field_callback;
    config.field_context = h;
    config.assignability_callback = bcl_assignable;
    config.assignability_context = h;
    config.trace_callback = h->config.trace_callback;
    config.trace_context = h->config.trace_context;
    config.shared_instruction_budget = &h->remaining_instructions;
    module->vm = xxemul_dotnet_vm_create(module->program, &config, &status);
    return module->vm ? XXEMUL_STATUS_OK : status;
}
static xxemul_status reflected_invoke(xxemul_dotnet_bcl_host *h, xxemul_dotnet_vm *caller, bcl_object *method, const xxemul_dotnet_value *a, size_t count,
                                      xxemul_dotnet_value *out)
{
    const xxemul_dotnet_method *target;
    xxemul_dotnet_value *arguments = NULL, item;
    size_t n = 0, i, offset = 0;
    xxemul_dotnet_result result;
    xxemul_status status;
    uint64_t used = xxemul_dotnet_vm_instruction_count(caller), budget;
    uint32_t boxed;
    if (count != 3 || !method || method->kind != BCL_METHOD || !method->module)
        return XXEMUL_STATUS_INVALID_ARGUMENT;
    if (h->invoke_depth >= 16)
        return host_fail(h, XXEMUL_STATUS_LIMIT_REACHED, "managed host call depth reached");
    target = &method->module->program->methods[method->index];
    if (a[2].bits && xxemul_dotnet_vm_array_length(caller, (uint32_t)a[2].bits, &n) != XXEMUL_STATUS_OK)
        return xxemul_dotnet_vm_raise_type(caller, "System.ArgumentException");
    if (n != target->signature.parameter_count)
        return xxemul_dotnet_vm_raise_type(caller, "System.Reflection.TargetParameterCountException");
    if (used >= h->config.max_instructions)
        return XXEMUL_STATUS_LIMIT_REACHED;
    budget = h->config.max_instructions - used;
    if ((status = ensure_vm(h, method->module, budget)) != XXEMUL_STATUS_OK)
        return status;
    arguments = host_alloc(h, (n + (target->signature.has_this ? 1 : 0)) * sizeof(*arguments));
    if (!arguments)
        return XXEMUL_STATUS_LIMIT_REACHED;
    if (target->signature.has_this) {
        status = clone_value(h, caller, method->module->vm, a[1], &arguments[0], 0);
        if (status != XXEMUL_STATUS_OK)
            goto done;
        offset = 1;
    }
    for (i = 0; i < n; ++i) {
        if ((status = xxemul_dotnet_vm_array_get(caller, (uint32_t)a[2].bits, i, &item)) != XXEMUL_STATUS_OK)
            goto done;
        if (item.kind == XXEMUL_DOTNET_VALUE_OBJECT && item.bits &&
            xxemul_dotnet_vm_unbox(caller, (uint32_t)item.bits, &arguments[i + offset]) == XXEMUL_STATUS_OK)
            continue;
        if ((status = clone_value(h, caller, method->module->vm, item, &arguments[i + offset], 0)) != XXEMUL_STATUS_OK)
            goto done;
    }
    ++h->statistics.reflected_invocations;
    ++h->invoke_depth;
    {
        int nested = method->module->invoking;
        uint64_t already;
        method->module->invoking = 1;
        status = nested ? xxemul_dotnet_vm_invoke_nested(method->module->vm, method->index, arguments, n + offset, &result)
                        : xxemul_dotnet_vm_invoke(method->module->vm, method->index, arguments, n + offset, &result);
        method->module->invoking = nested;
        --h->invoke_depth;
        already = xxemul_dotnet_vm_instruction_count(caller) - used;
        if (caller != method->module->vm && result.instructions > already &&
            xxemul_dotnet_vm_consume_instructions(caller, result.instructions - already) != XXEMUL_STATUS_OK)
            status = XXEMUL_STATUS_LIMIT_REACHED;
    }
    if (status != XXEMUL_STATUS_OK) {
        uint32_t exception = xxemul_dotnet_vm_exception(method->module->vm);
        if (exception && status == XXEMUL_STATUS_ADDRESS_FAULT) {
            const char *type = xxemul_dotnet_vm_object_type(method->module->vm, exception);
            bcl_object *inner, *wrapper, *source = lookup(h, method->module->vm, exception);
            status = new_host_object(h, caller, type ? type : "System.Exception", BCL_EXCEPTION, &inner);
            if (status != XXEMUL_STATUS_OK)
                goto done;
            inner->name = host_string(h, source && source->name ? source->name : "", source && source->name ? strlen(source->name) : 0);
            if (!inner->name) {
                status = XXEMUL_STATUS_LIMIT_REACHED;
                goto done;
            }
            status = new_host_object(h, caller, "System.Reflection.TargetInvocationException", BCL_EXCEPTION, &wrapper);
            if (status != XXEMUL_STATUS_OK)
                goto done;
            wrapper->name = host_string(h, "Exception has been thrown by the target of an invocation.", 57);
            wrapper->target = object_value(inner->reference);
            if (!wrapper->name) {
                status = XXEMUL_STATUS_LIMIT_REACHED;
                goto done;
            }
            status = xxemul_dotnet_vm_raise(caller, wrapper->reference);
            goto done;
        }
        host_fail(h, status, "loaded assembly invocation failed: %s", result.diagnostic);
        goto done;
    }
    if (result.value.kind == XXEMUL_DOTNET_VALUE_VOID)
        *out = object_value(0);
    else if (result.value.kind == XXEMUL_DOTNET_VALUE_OBJECT)
        status = clone_value(h, method->module->vm, caller, result.value, out, 0);
    else {
        status = xxemul_dotnet_vm_box(caller, target->signature.return_type.name, result.value, &boxed);
        if (status == XXEMUL_STATUS_OK)
            *out = object_value(boxed);
    }
done:
    host_free(h, arguments, (n + (target->signature.has_this ? 1 : 0)) * sizeof(*arguments));
    return status;
}

static xxemul_status stringify(xxemul_dotnet_bcl_host *h, xxemul_dotnet_vm *vm, xxemul_dotnet_value in, char **text, size_t *size)
{
    const char *s, *type;
    char number[128];
    xxemul_dotnet_value unboxed;
    int64_t integer_value;
    bcl_object *o;
    *text = NULL;
    *size = 0;
    if (in.kind == XXEMUL_DOTNET_VALUE_OBJECT) {
        if (!in.bits) {
            *text = host_string(h, "", 0);
            return *text ? XXEMUL_STATUS_OK : XXEMUL_STATUS_LIMIT_REACHED;
        }
        s = get_string(vm, in, size);
        if (s) {
            *text = host_string(h, s, *size);
            return *text ? XXEMUL_STATUS_OK : XXEMUL_STATUS_LIMIT_REACHED;
        }
        type = xxemul_dotnet_vm_object_type(vm, (uint32_t)in.bits);
        if (!type)
            return XXEMUL_STATUS_ADDRESS_FAULT;
        if (xxemul_dotnet_vm_unbox(vm, (uint32_t)in.bits, &unboxed) == XXEMUL_STATUS_OK) {
            if (!strcmp(type, "System.Boolean")) {
                s = unboxed.bits ? "True" : "False";
                *size = strlen(s);
                *text = host_string(h, s, *size);
                return *text ? XXEMUL_STATUS_OK : XXEMUL_STATUS_LIMIT_REACHED;
            }
            if (!strcmp(type, "System.Char")) {
                uint16_t unit = (uint16_t)unboxed.bits;
                xxemul_dotnet_value character;
                xxemul_status status = units_to_text(h, vm, &unit, 1, &character);
                return status == XXEMUL_STATUS_OK ? stringify(h, vm, character, text, size) : status;
            }
            if (!strcmp(type, "System.UInt32") || !strcmp(type, "System.UInt64")) {
                snprintf(number, sizeof(number), "%" PRIu64, !strcmp(type, "System.UInt32") ? (uint32_t)unboxed.bits : unboxed.bits);
                *size = strlen(number);
                *text = host_string(h, number, *size);
                return *text ? XXEMUL_STATUS_OK : XXEMUL_STATUS_LIMIT_REACHED;
            }
            return stringify(h, vm, unboxed, text, size);
        }
        o = lookup(h, vm, (uint32_t)in.bits);
        s = o && (o->kind == BCL_TYPE || o->kind == BCL_EXCEPTION) && o->name ? o->name : type;
        *size = strlen(s);
        *text = host_string(h, s, *size);
        return *text ? XXEMUL_STATUS_OK : XXEMUL_STATUS_LIMIT_REACHED;
    }
    if (integer(in, &integer_value))
        snprintf(number, sizeof(number), "%" PRId64, integer_value);
    else if (in.kind == XXEMUL_DOTNET_VALUE_F)
        return host_fail(h, XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION, "floating-point default formatting is unsupported");
    else
        return XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
    *size = strlen(number);
    *text = host_string(h, number, *size);
    return *text ? XXEMUL_STATUS_OK : XXEMUL_STATUS_LIMIT_REACHED;
}
static xxemul_status emit(xxemul_dotnet_bcl_host *h, unsigned stream, const char *p, size_t n)
{
    if (n > h->config.max_output_bytes - h->output_bytes)
        return host_fail(h, XXEMUL_STATUS_LIMIT_REACHED, "managed output budget reached");
    h->output_bytes += n;
    if (h->config.output_callback)
        h->config.output_callback(h->config.output_context, stream, p, n);
    return XXEMUL_STATUS_OK;
}
static int framework_assembly(const char *assembly)
{
    static const char *const names[] = {"mscorlib",
                                        "System.Private.CoreLib",
                                        "System.Runtime",
                                        "System.Console",
                                        "System",
                                        "System.Core",
                                        "System.Text.Encoding",
                                        "System.Text.Encoding.Extensions",
                                        "System.Security.Cryptography",
                                        "System.Security.Cryptography.Algorithms",
                                        "System.IO.Compression",
                                        "System.Resources.ResourceManager",
                                        "netstandard"};
    size_t i;
    if (!assembly)
        return 0;
    for (i = 0; i < sizeof(names) / sizeof(names[0]); ++i)
        if (!strcmp(assembly, names[i]))
            return 1;
    return 0;
}
static int framework_scope(const xxemul_dotnet_method_info *m)
{
    return framework_assembly(m->assembly_name);
}
static int glob_match(const char *pattern, size_t pn, const char *text, size_t tn)
{
    size_t pi = 0, ti = 0, star = SIZE_MAX, retry = 0;
    while (ti < tn) {
        if (pi < pn && (pattern[pi] == '?' || pattern[pi] == text[ti])) {
            ++pi;
            ++ti;
        } else if (pi < pn && pattern[pi] == '*') {
            star = pi++;
            retry = ti;
        } else if (star != SIZE_MAX) {
            pi = star + 1;
            ti = ++retry;
        } else
            return 0;
    }
    while (pi < pn && pattern[pi] == '*')
        ++pi;
    return pi == pn;
}
typedef struct service_signature {
    const char *type, *name, *signature;
} service_signature;
static int supported_signature(const xxemul_dotnet_method_info *method)
{
    static const service_signature list[] = {
#define S(t, n, s) {t, n, s}
        S("System.Object", ".ctor", "()System.Void"),
        S("System.Object", "GetType", "()System.Type"),
        S("System.Object", "ToString", "()System.String"),
        S("System.Object", "ReferenceEquals", "(System.Object,System.Object)System.Boolean"),
        S("System.Text.UTF8Encoding", ".ctor", "()System.Void"),
        S("System.Text.UTF8Encoding", ".ctor", "(System.Boolean)System.Void"),
        S("System.Text.UTF8Encoding", ".ctor", "(System.Boolean,System.Boolean)System.Void"),
        S("System.Text.Encoding", "get_UTF8", "()System.Text.Encoding"),
        S("System.Text.Encoding", "GetBytes", "(System.String)System.Byte[]"),
        S("System.Text.Encoding", "GetString", "(System.Byte[])System.String"),
        S("System.Console", "set_OutputEncoding", "(System.Text.Encoding)System.Void"),
        S("System.Console", "get_Error", "()System.IO.TextWriter"),
        S("System.Console", "get_Out", "()System.IO.TextWriter"),
        S("System.Reflection.Assembly", "GetExecutingAssembly", "()System.Reflection.Assembly"),
        S("System.Reflection.Assembly", "GetEntryAssembly", "()System.Reflection.Assembly"),
        S("System.Reflection.Assembly", "Load", "(System.Byte[])System.Reflection.Assembly"),
        S("System.Reflection.Assembly", "get_Location", "()System.String"),
        S("System.Reflection.Assembly", "GetManifestResourceStream", "(System.String)System.IO.Stream"),
        S("System.Reflection.Assembly", "get_EntryPoint", "()System.Reflection.MethodInfo"),
        S("System.Reflection.MethodBase", "GetParameters", "()System.Reflection.ParameterInfo[]"),
        S("System.Reflection.MethodInfo", "GetParameters", "()System.Reflection.ParameterInfo[]"),
        S("System.Reflection.MethodBase", "Invoke", "(System.Object,System.Object[])System.Object"),
        S("System.Reflection.MethodInfo", "Invoke", "(System.Object,System.Object[])System.Object"),
        S("System.Resources.ResourceManager", ".ctor", "(System.String,System.Reflection.Assembly)System.Void"),
        S("System.Resources.ResourceManager", "GetObject", "(System.String)System.Object"),
        S("System.IO.MemoryStream", ".ctor", "()System.Void"),
        S("System.IO.MemoryStream", ".ctor", "(System.Byte[])System.Void"),
        S("System.IO.MemoryStream", "ToArray", "()System.Byte[]"),
        S("System.IO.Compression.DeflateStream", ".ctor", "(System.IO.Stream,System.IO.Compression.CompressionMode)System.Void"),
        S("System.IO.Compression.DeflateStream", ".ctor", "(System.IO.Stream,System.IO.Compression.CompressionMode,System.Boolean)System.Void"),
        S("System.IO.Compression.GZipStream", ".ctor", "(System.IO.Stream,System.IO.Compression.CompressionMode)System.Void"),
        S("System.IO.Compression.GZipStream", ".ctor", "(System.IO.Stream,System.IO.Compression.CompressionMode,System.Boolean)System.Void"),
        S("ICSharpCode.SharpZipLib.Zip.Compression.Streams.InflaterInputStream", ".ctor", "(System.IO.Stream)System.Void"),
        S("System.Security.Cryptography.SHA256", "Create", "()System.Security.Cryptography.SHA256"),
        S("System.Security.Cryptography.HashAlgorithm", "ComputeHash", "(System.IO.Stream)System.Byte[]"),
        S("System.Security.Cryptography.HashAlgorithm", "ComputeHash", "(System.Byte[])System.Byte[]"),
        S("System.IDisposable", "Dispose", "()System.Void"),
        S("System.Security.Cryptography.HashAlgorithm", "Dispose", "()System.Void"),
        S("System.Security.Cryptography.SHA256", "Dispose", "()System.Void"),
        S("System.BitConverter", "ToString", "(System.Byte[])System.String"),
        S("System.String", "Concat", "(System.Object)System.String"),
        S("System.String", "Concat", "(System.Object,System.Object)System.String"),
        S("System.String", "Concat", "(System.Object,System.Object,System.Object)System.String"),
        S("System.String", "Concat", "(System.Object[])System.String"),
        S("System.String", "Concat", "(System.String,System.String)System.String"),
        S("System.String", "Concat", "(System.String,System.String,System.String)System.String"),
        S("System.String", "Concat", "(System.String,System.String,System.String,System.String)System.String"),
        S("System.String", "Concat", "(System.String[])System.String"),
        S("System.String", "op_Equality", "(System.String,System.String)System.Boolean"),
        S("System.String", "op_Inequality", "(System.String,System.String)System.Boolean"),
        S("System.String", "Equals", "(System.String)System.Boolean"),
        S("System.String", "Equals", "(System.String,System.String)System.Boolean"),
        S("System.String", "Replace", "(System.String,System.String)System.String"),
        S("System.String", "ToLower", "()System.String"),
        S("System.String", "ToLowerInvariant", "()System.String"),
        S("System.String", "ToUpperInvariant", "()System.String"),
        S("System.String", "StartsWith", "(System.String)System.Boolean"),
        S("System.String", "Substring", "(System.Int32)System.String"),
        S("System.String", "Substring", "(System.Int32,System.Int32)System.String"),
        S("System.String", "get_Chars", "(System.Int32)System.Char"),
        S("System.String", "get_Length", "()System.Int32"),
        S("System.String", "ToString", "()System.String"),
        S("System.Int32", "Parse", "(System.String)System.Int32"),
        S("System.AppDomain", "get_CurrentDomain", "()System.AppDomain"),
        S("System.ResolveEventHandler", ".ctor", "(System.Object,System.IntPtr)System.Void"),
        S("System.AppDomain", "add_AssemblyResolve", "(System.ResolveEventHandler)System.Void"),
        S("System.IO.Path", "GetDirectoryName", "(System.String)System.String"),
        S("System.IO.Path", "GetFileName", "(System.String)System.String"),
        S("System.IO.Path", "GetFileNameWithoutExtension", "(System.String)System.String"),
        S("System.IO.Directory", "GetFiles", "(System.String,System.String)System.String[]"),
        S("System.IO.File", "Exists", "(System.String)System.Boolean"),
        S("System.IO.File", "OpenRead", "(System.String)System.IO.FileStream"),
        S("System.Exception", ".ctor", "()System.Void"),
        S("System.Exception", ".ctor", "(System.String)System.Void"),
        S("System.Exception", "GetType", "()System.Type"),
        S("System.Exception", "get_Message", "()System.String"),
        S("System.Exception", "get_InnerException", "()System.Exception"),
        S("System.Type", "ToString", "()System.String"),
        S("System.Type", "get_FullName", "()System.String"),
        S("System.Type", "GetTypeFromHandle", "(System.RuntimeTypeHandle)System.Type"),
        S("System.Environment", "get_NewLine", "()System.String"),
        S("System.Version", "ToString", "()System.String")
#undef S
    };
    size_t i;
    for (i = 0; i < sizeof(list) / sizeof(list[0]); ++i)
        if (!strcmp(method->type_name, list[i].type) && !strcmp(method->name, list[i].name) && !strcmp(method->signature, list[i].signature))
            return 1;
    if (!strcmp(method->type_name, "System.Console") || !strcmp(method->type_name, "System.IO.TextWriter")) {
        static const char *const types[] = {"System.String", "System.Object", "System.Int32",   "System.Int64",
                                            "System.UInt32", "System.UInt64", "System.Boolean", "System.Char"};
        if (strcmp(method->name, "Write") && strcmp(method->name, "WriteLine"))
            return 0;
        if (!strcmp(method->signature, "()System.Void"))
            return 1;
        for (i = 0; i < sizeof(types) / sizeof(types[0]); ++i) {
            char signature[128];
            snprintf(signature, sizeof(signature), "(%s)System.Void", types[i]);
            if (!strcmp(method->signature, signature))
                return 1;
        }
    }
    if (!strcmp(method->type_name, "System.IO.Stream") || !strcmp(method->type_name, "System.IO.MemoryStream") ||
        !strcmp(method->type_name, "System.IO.FileStream") || !strcmp(method->type_name, "System.IO.UnmanagedMemoryStream") ||
        !strcmp(method->type_name, "System.IO.Compression.DeflateStream") || !strcmp(method->type_name, "System.IO.Compression.GZipStream") ||
        !strcmp(method->type_name, "ICSharpCode.SharpZipLib.Zip.Compression.Streams.InflaterInputStream")) {
        if ((!strcmp(method->name, "Close") || !strcmp(method->name, "Flush") || !strcmp(method->name, "Dispose")) &&
            !strcmp(method->signature, "()System.Void"))
            return 1;
        if (!strcmp(method->name, "Dispose") && !strcmp(method->signature, "(System.Boolean)System.Void"))
            return 1;
        if (!strcmp(method->name, "Seek") && !strcmp(method->signature, "(System.Int64,System.IO.SeekOrigin)System.Int64"))
            return 1;
        if ((!strcmp(method->name, "get_Length") || !strcmp(method->name, "get_Position")) && !strcmp(method->signature, "()System.Int64"))
            return 1;
        if (!strcmp(method->name, "Read") && !strcmp(method->signature, "(System.Byte[],System.Int32,System.Int32)System.Int32"))
            return 1;
        if (!strcmp(method->name, "Write") && !strcmp(method->signature, "(System.Byte[],System.Int32,System.Int32)System.Void"))
            return 1;
    }
    return 0;
}

/* Service implementation below intentionally selects explicit types/methods.
 * An unrecognized overload or service returns UNSUPPORTED_INSTRUCTION. */
static xxemul_status bcl_dispatch(void *context, xxemul_dotnet_vm *vm, const xxemul_dotnet_method_info *m, const xxemul_dotnet_value *a, size_t count,
                                  xxemul_dotnet_value *out)
{
    xxemul_dotnet_bcl_host *h = context;
    const char *t = m->type_name, *name = m->name, *s = NULL;
    size_t n = 0, i;
    int64_t x = 0, y = 0, z = 0;
    bcl_object *o = count && a[0].kind == XXEMUL_DOTNET_VALUE_OBJECT ? lookup(h, vm, (uint32_t)a[0].bits) : NULL;
    xxemul_status status = XXEMUL_STATUS_OK;
    const xxemul_dotnet_program *program = xxemul_dotnet_vm_get_program(vm);
    bcl_module *module = module_for(h, program);
    *out = value(XXEMUL_DOTNET_VALUE_VOID, 0);
    ++h->statistics.service_calls;
    if (!strcmp(t, "ICSharpCode.SharpZipLib.Zip.Compression.Streams.InflaterInputStream")) {
        if (!(h->config.flags & XXEMUL_DOTNET_BCL_SHARPZIP_STREAMS))
            goto unsupported;
    } else if (!framework_scope(m))
        goto unsupported;
    if (!supported_signature(m))
        goto unsupported;
    if (!strcmp(t, "System.Object") && !strcmp(name, ".ctor") && count == 1)
        return XXEMUL_STATUS_OK;
    if ((!strcmp(t, "System.Object") || !strcmp(t, "System.Exception")) && !strcmp(name, "GetType") && count == 1) {
        const char *type = xxemul_dotnet_vm_object_type(vm, (uint32_t)a[0].bits);
        if (!type)
            return xxemul_dotnet_vm_raise_type(vm, "System.NullReferenceException");
        status = new_host_object(h, vm, "System.Type", BCL_TYPE, &o);
        if (status != XXEMUL_STATUS_OK)
            return status;
        o->name = host_string(h, type, strlen(type));
        if (!o->name)
            return XXEMUL_STATUS_LIMIT_REACHED;
        *out = object_value(o->reference);
        return XXEMUL_STATUS_OK;
    }
    if (!strcmp(t, "System.Object") && !strcmp(name, "ReferenceEquals") && count == 2) {
        *out = value(XXEMUL_DOTNET_VALUE_I4, a[0].kind == a[1].kind && a[0].bits == a[1].bits);
        return XXEMUL_STATUS_OK;
    }
    if ((!strcmp(t, "System.Object") || !strcmp(t, "System.Type") || !strcmp(t, "System.Version")) && !strcmp(name, "ToString") && count == 1) {
        char *text;
        status = stringify(h, vm, a[0], &text, &n);
        if (status != XXEMUL_STATUS_OK)
            return status;
        status = text_result(vm, text, n, out);
        host_free(h, text, n + 1);
        return status;
    }
    if (!strcmp(t, "System.Exception")) {
        if (!strcmp(name, ".ctor") && (count == 1 || count == 2)) {
            s = count == 2 ? get_string(vm, a[1], &n) : "";
            if (!s) {
                if (a[1].bits)
                    return xxemul_dotnet_vm_raise_type(vm, "System.ArgumentException");
                s = "";
                n = 0;
            }
            o = attach(h, vm, (uint32_t)a[0].bits, BCL_EXCEPTION);
            if (!o)
                return XXEMUL_STATUS_LIMIT_REACHED;
            o->name = host_string(h, s, n);
            return o->name ? XXEMUL_STATUS_OK : XXEMUL_STATUS_LIMIT_REACHED;
        }
        if (!strcmp(name, "get_Message") && count == 1)
            return text_result(vm, o && o->kind == BCL_EXCEPTION && o->name ? o->name : "", o && o->kind == BCL_EXCEPTION && o->name ? strlen(o->name) : 0,
                               out);
        if (!strcmp(name, "get_InnerException") && count == 1) {
            *out = o && o->kind == BCL_EXCEPTION ? o->target : object_value(0);
            if (out->kind == XXEMUL_DOTNET_VALUE_VOID)
                *out = object_value(0);
            return XXEMUL_STATUS_OK;
        }
    }
    if (!strcmp(t, "System.Type") && count == 1) {
        if (!strcmp(name, "GetTypeFromHandle") && a[0].kind == XXEMUL_DOTNET_VALUE_NATIVE) {
            s = xxemul_dotnet_type_name(program, (uint32_t)a[0].bits);
            if (!s)
                return XXEMUL_STATUS_INVALID_IMAGE;
            status = new_host_object(h, vm, "System.Type", BCL_TYPE, &o);
            if (status != XXEMUL_STATUS_OK)
                return status;
            o->name = host_string(h, s, strlen(s));
            if (!o->name)
                return XXEMUL_STATUS_LIMIT_REACHED;
            *out = object_value(o->reference);
            return XXEMUL_STATUS_OK;
        }
        if (!strcmp(name, "get_FullName") && o && o->kind == BCL_TYPE)
            return text_result(vm, o->name, strlen(o->name), out);
    }
    if (!strcmp(t, "System.Environment") && !count) {
        if (!strcmp(name, "get_NewLine"))
            return text_result(vm, "\n", 1, out);
    }
    if (!strcmp(t, "System.Text.UTF8Encoding") && !strcmp(name, ".ctor") && (count == 1 || count == 2 || count == 3)) {
        o = attach(h, vm, (uint32_t)a[0].bits, BCL_ENCODING);
        if (!o)
            return XXEMUL_STATUS_LIMIT_REACHED;
        o->channel = count > 1 ? (unsigned)!!a[1].bits : 0;
        return XXEMUL_STATUS_OK;
    }
    if (!strcmp(t, "System.Text.Encoding") && !strcmp(name, "get_UTF8") && count == 0) {
        for (o = h->objects; o; o = o->next)
            if (o->vm == vm && o->kind == BCL_ENCODING && o->index == 1) {
                *out = object_value(o->reference);
                return XXEMUL_STATUS_OK;
            }
        status = new_host_object(h, vm, "System.Text.UTF8Encoding", BCL_ENCODING, &o);
        if (status == XXEMUL_STATUS_OK) {
            o->index = 1;
            *out = object_value(o->reference);
        }
        return status;
    }
    if (!strcmp(t, "System.Console")) {
        if (!strcmp(name, "set_OutputEncoding") && count == 1) {
            o = lookup(h, vm, (uint32_t)a[0].bits);
            return o && o->kind == BCL_ENCODING ? XXEMUL_STATUS_OK : XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION;
        }
        if ((!strcmp(name, "get_Error") || !strcmp(name, "get_Out")) && count == 0) {
            unsigned channel = !strcmp(name, "get_Error") ? 2 : 1;
            for (o = h->objects; o; o = o->next)
                if (o->vm == vm && o->kind == BCL_WRITER && o->channel == channel) {
                    *out = object_value(o->reference);
                    return XXEMUL_STATUS_OK;
                }
            status = new_host_object(h, vm, "System.IO.TextWriter", BCL_WRITER, &o);
            if (status == XXEMUL_STATUS_OK) {
                o->channel = channel;
                *out = object_value(o->reference);
            }
            return status;
        }
    }
    if ((!strcmp(t, "System.Console") || !strcmp(t, "System.IO.TextWriter")) && (!strcmp(name, "Write") || !strcmp(name, "WriteLine"))) {
        unsigned channel = 1;
        size_t begin = 0;
        char *text = NULL;
        if (!strcmp(t, "System.IO.TextWriter")) {
            if (!o || o->kind != BCL_WRITER)
                goto unsupported;
            channel = o->channel;
            begin = 1;
        }
        if (count > begin + 1)
            goto unsupported;
        if (count > begin) {
            if (!strcmp(m->signature, "(System.Boolean)System.Void")) {
                s = a[begin].bits ? "True" : "False";
                n = strlen(s);
                text = host_string(h, s, n);
                status = text ? XXEMUL_STATUS_OK : XXEMUL_STATUS_LIMIT_REACHED;
            } else if (!strcmp(m->signature, "(System.Char)System.Void")) {
                uint16_t unit = (uint16_t)a[begin].bits;
                xxemul_dotnet_value character;
                status = units_to_text(h, vm, &unit, 1, &character);
                if (status == XXEMUL_STATUS_OK)
                    status = stringify(h, vm, character, &text, &n);
            } else if (!strcmp(m->signature, "(System.UInt32)System.Void") || !strcmp(m->signature, "(System.UInt64)System.Void")) {
                char number[32];
                uint64_t bits = !strcmp(m->signature, "(System.UInt32)System.Void") ? (uint32_t)a[begin].bits : a[begin].bits;
                snprintf(number, sizeof(number), "%" PRIu64, bits);
                n = strlen(number);
                text = host_string(h, number, n);
                status = text ? XXEMUL_STATUS_OK : XXEMUL_STATUS_LIMIT_REACHED;
            } else
                status = stringify(h, vm, a[begin], &text, &n);
            if (status != XXEMUL_STATUS_OK)
                return status;
            status = emit(h, channel, text, n);
            host_free(h, text, n + 1);
            if (status != XXEMUL_STATUS_OK)
                return status;
        }
        if (!strcmp(name, "WriteLine"))
            return emit(h, channel, "\n", 1);
        return XXEMUL_STATUS_OK;
    }
    if (!strcmp(t, "System.Reflection.Assembly")) {
        if ((!strcmp(name, "GetExecutingAssembly") || !strcmp(name, "GetCallingAssembly")) && count == 0)
            return assembly_object(h, vm, module, out);
        if (!strcmp(name, "GetEntryAssembly") && count == 0)
            return assembly_object(h, vm, h->entry_module, out);
        if (!strcmp(name, "Load") && count == 1) {
            uint8_t *bytes;
            size_t size;
            xxemul_dotnet_program *loaded;
            bcl_module *new_module;
            status = byte_array(h, vm, a[0], &bytes, &size);
            if (status != XXEMUL_STATUS_OK)
                return status;
            loaded = xxemul_dotnet_create(bytes, size, &status);
            host_free(h, bytes, size);
            if (!loaded)
                return status == XXEMUL_STATUS_INVALID_IMAGE ? xxemul_dotnet_vm_raise_type(vm, "System.BadImageFormatException") : status;
            new_module = register_module(h, loaded, 1, "");
            if (!new_module) {
                xxemul_dotnet_destroy(loaded);
                return XXEMUL_STATUS_LIMIT_REACHED;
            }
            return assembly_object(h, vm, new_module, out);
        }
        if (!o || o->kind != BCL_ASSEMBLY)
            goto unsupported;
        if (!strcmp(name, "get_Location") && count == 1)
            return text_result(vm, o->module->location, strlen(o->module->location), out);
        if (!strcmp(name, "GetManifestResourceStream") && count == 2) {
            const xxemul_dotnet_resource_info *resource;
            s = get_string(vm, a[1], &n);
            if (!s || memchr(s, 0, n))
                return xxemul_dotnet_vm_raise_type(vm, "System.ArgumentException");
            resource = xxemul_dotnet_resource_find(o->module->program, s);
            if (!resource || resource->implementation) {
                *out = object_value(0);
                return XXEMUL_STATUS_OK;
            }
            status = new_host_object(h, vm, "System.IO.UnmanagedMemoryStream", BCL_STREAM, &o);
            if (status != XXEMUL_STATUS_OK)
                return status;
            if ((status = buffer_reserve(h, o, resource->size)) != XXEMUL_STATUS_OK)
                return status;
            if (resource->size)
                memcpy(o->bytes, resource->data, resource->size);
            o->length = resource->size;
            o->channel = 2;
            *out = object_value(o->reference);
            return XXEMUL_STATUS_OK;
        }
        if (!strcmp(name, "get_EntryPoint") && count == 1) {
            size_t entry = xxemul_dotnet_entry_point(o->module->program);
            bcl_module *owner = o->module;
            if (entry == SIZE_MAX) {
                *out = object_value(0);
                return XXEMUL_STATUS_OK;
            }
            status = new_host_object(h, vm, "System.Reflection.MethodInfo", BCL_METHOD, &o);
            if (status == XXEMUL_STATUS_OK) {
                o->module = owner;
                o->index = entry;
                *out = object_value(o->reference);
            }
            return status;
        }
    }
    if ((!strcmp(t, "System.Reflection.MethodBase") || !strcmp(t, "System.Reflection.MethodInfo")) && o && o->kind == BCL_METHOD) {
        if (!strcmp(name, "GetParameters") && count == 1) {
            uint32_t array;
            size_t length = o->module->program->methods[o->index].signature.parameter_count;
            status = xxemul_dotnet_vm_new_array(vm, "System.Reflection.ParameterInfo", length, &array);
            if (status != XXEMUL_STATUS_OK)
                return status;
            for (i = 0; i < length; ++i) {
                uint32_t parameter;
                status = xxemul_dotnet_vm_new_object(vm, "System.Reflection.ParameterInfo", &parameter);
                if (status != XXEMUL_STATUS_OK)
                    return status;
                status = xxemul_dotnet_vm_array_set(vm, array, i, object_value(parameter));
                if (status != XXEMUL_STATUS_OK)
                    return status;
            }
            *out = object_value(array);
            return XXEMUL_STATUS_OK;
        }
        if (!strcmp(name, "Invoke"))
            return reflected_invoke(h, vm, o, a, count, out);
    }
    if (!strcmp(t, "System.Resources.ResourceManager")) {
        if (!strcmp(name, ".ctor") && count == 3) {
            bcl_object *assembly = lookup(h, vm, (uint32_t)a[2].bits);
            s = get_string(vm, a[1], &n);
            if (!s || memchr(s, 0, n) || !assembly || assembly->kind != BCL_ASSEMBLY)
                return xxemul_dotnet_vm_raise_type(vm, "System.ArgumentException");
            o = attach(h, vm, (uint32_t)a[0].bits, BCL_RESOURCE_MANAGER);
            if (!o)
                return XXEMUL_STATUS_LIMIT_REACHED;
            o->module = assembly->module;
            o->name = host_string(h, s, n);
            return o->name ? XXEMUL_STATUS_OK : XXEMUL_STATUS_LIMIT_REACHED;
        }
        if (!strcmp(name, "GetObject") && count == 2 && o && o->kind == BCL_RESOURCE_MANAGER) {
            const xxemul_dotnet_resource_info *resource;
            xx_dotnet_resources view;
            xx_dotnet_resource_entry entry;
            const char *error = NULL;
            char *container;
            s = get_string(vm, a[1], &n);
            if (!s)
                return xxemul_dotnet_vm_raise_type(vm, "System.ArgumentNullException");
            i = strlen(o->name);
            container = host_alloc(h, i + 11);
            if (!container)
                return XXEMUL_STATUS_LIMIT_REACHED;
            memcpy(container, o->name, i);
            memcpy(container + i, ".resources", 11);
            resource = xxemul_dotnet_resource_find(o->module->program, container);
            host_free(h, container, i + 11);
            if (!resource || resource->implementation)
                return xxemul_dotnet_vm_raise_type(vm, "System.Resources.MissingManifestResourceException");
            if (!xx_dotnet_resources_open(resource->data, resource->size, &view, &error))
                return xxemul_dotnet_vm_raise_type(vm, "System.IO.InvalidDataException");
            if (!xx_dotnet_resources_find(&view, (const uint8_t *)s, n, &entry, &error)) {
                if (error)
                    return xxemul_dotnet_vm_raise_type(vm, "System.IO.InvalidDataException");
                *out = object_value(0);
                return XXEMUL_STATUS_OK;
            }
            if (entry.type == 0) {
                *out = object_value(0);
                return XXEMUL_STATUS_OK;
            }
            if (entry.type == 32)
                return bytes_result(vm, entry.data, entry.size, out);
            if (entry.type == 1)
                return text_result(vm, (const char *)entry.data, entry.size, out);
            if (entry.type == 33) {
                status = new_host_object(h, vm, "System.IO.UnmanagedMemoryStream", BCL_STREAM, &o);
                if (status != XXEMUL_STATUS_OK)
                    return status;
                if ((status = buffer_reserve(h, o, entry.size)) != XXEMUL_STATUS_OK)
                    return status;
                if (entry.size)
                    memcpy(o->bytes, entry.data, entry.size);
                o->length = entry.size;
                o->channel = 2;
                *out = object_value(o->reference);
                return XXEMUL_STATUS_OK;
            }
            if (entry.type >= 2 && entry.type <= 13) {
                static const char *const names[] = {"System.Boolean", "System.Char",   "System.Byte",  "System.SByte",  "System.Int16",  "System.UInt16",
                                                    "System.Int32",   "System.UInt32", "System.Int64", "System.UInt64", "System.Single", "System.Double"};
                uint64_t bits = 0;
                uint32_t reference;
                xxemul_dotnet_value primitive;
                for (i = 0; i < entry.size; ++i)
                    bits |= (uint64_t)entry.data[i] << (i * 8);
                primitive = value(entry.type >= 10 && entry.type <= 11 ? XXEMUL_DOTNET_VALUE_I8 : XXEMUL_DOTNET_VALUE_I4, bits);
                if (entry.type == 5)
                    primitive.bits = (uint32_t)(int32_t)(int8_t)bits;
                if (entry.type == 6)
                    primitive.bits = (uint32_t)(int32_t)(int16_t)bits;
                if (entry.type == 12) {
                    uint32_t raw = (uint32_t)bits;
                    float f;
                    double d;
                    memcpy(&f, &raw, 4);
                    d = f;
                    memcpy(&bits, &d, 8);
                    primitive = value(XXEMUL_DOTNET_VALUE_F, bits);
                }
                if (entry.type == 13)
                    primitive = value(XXEMUL_DOTNET_VALUE_F, bits);
                status = xxemul_dotnet_vm_box(vm, names[entry.type - 2], primitive, &reference);
                if (status == XXEMUL_STATUS_OK)
                    *out = object_value(reference);
                return status;
            }
            return host_fail(h, XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION, "ResourceManager value type %u unsupported", entry.type);
        }
    }
    if (!strcmp(t, "System.IO.MemoryStream") && !strcmp(name, ".ctor") && (count == 1 || count == 2)) {
        uint8_t *bytes = NULL;
        size_t size = 0;
        o = attach(h, vm, (uint32_t)a[0].bits, BCL_STREAM);
        if (!o)
            return XXEMUL_STATUS_LIMIT_REACHED;
        if (count == 2) {
            status = byte_array(h, vm, a[1], &bytes, &size);
            if (status != XXEMUL_STATUS_OK)
                return status;
            o->bytes = bytes;
            o->length = size;
            o->capacity = size ? size : 1;
            o->source = (uint32_t)a[1].bits;
            o->insensitive = 1;
        }
        return XXEMUL_STATUS_OK;
    }
    if ((!strcmp(t, "System.IO.Compression.DeflateStream") || !strcmp(t, "System.IO.Compression.GZipStream") ||
         !strcmp(t, "ICSharpCode.SharpZipLib.Zip.Compression.Streams.InflaterInputStream")) &&
        !strcmp(name, ".ctor")) {
        bcl_object *source;
        if (count < 2 || count > 4 || !(source = lookup(h, vm, (uint32_t)a[1].bits)) || source->kind != BCL_STREAM)
            goto unsupported;
        if (strcmp(t, "ICSharpCode.SharpZipLib.Zip.Compression.Streams.InflaterInputStream") && (count < 3 || a[2].bits != 0))
            goto unsupported;
        o = attach(h, vm, (uint32_t)a[0].bits, BCL_STREAM);
        if (!o)
            return XXEMUL_STATUS_LIMIT_REACHED;
        o->source = (uint32_t)a[1].bits;
        o->codec = !strcmp(t, "System.IO.Compression.DeflateStream") ? 2 : !strcmp(t, "System.IO.Compression.GZipStream") ? 3 : 1;
        o->channel = count == 4 && a[3].bits ? 1 : 0;
        if (o->codec == 1)
            ++h->statistics.sharpzip_streams;
        return XXEMUL_STATUS_OK;
    }
    if (o && o->kind == BCL_STREAM &&
        (!strcmp(t, "System.IO.Stream") || !strcmp(t, "System.IO.MemoryStream") || !strcmp(t, "System.IO.FileStream") ||
         !strcmp(t, "System.IO.UnmanagedMemoryStream") || !strcmp(t, "System.IO.Compression.DeflateStream") || !strcmp(t, "System.IO.Compression.GZipStream") ||
         !strcmp(t, "ICSharpCode.SharpZipLib.Zip.Compression.Streams.InflaterInputStream"))) {
        if ((!strcmp(name, "Close") || !strcmp(name, "Dispose")) && (count == 1 || count == 2)) {
            close_stream(h, vm, o);
            return XXEMUL_STATUS_OK;
        }
        if (!strcmp(name, "ToArray") && count == 1 && !o->codec && !strcmp(t, "System.IO.MemoryStream")) {
            if ((status = sync_array_stream(vm, o)) != XXEMUL_STATUS_OK)
                return status;
            return bytes_result(vm, o->bytes, o->length, out);
        }
        if (o->closed)
            return xxemul_dotnet_vm_raise_type(vm, "System.ObjectDisposedException");
        if (!strcmp(name, "Read") && count == 4) {
            size_t array_length, read;
            xxemul_dotnet_value item;
            if (!integer(a[2], &x) || !integer(a[3], &y) || x < 0 || y < 0 ||
                xxemul_dotnet_vm_array_length(vm, (uint32_t)a[1].bits, &array_length) != XXEMUL_STATUS_OK || (uint64_t)x > array_length ||
                (uint64_t)y > array_length - (size_t)x)
                return xxemul_dotnet_vm_raise_type(vm, "System.ArgumentOutOfRangeException");
            if (!y) {
                ++h->statistics.stream_reads;
                *out = value(XXEMUL_DOTNET_VALUE_I4, 0);
                return XXEMUL_STATUS_OK;
            }
            if ((status = sync_array_stream(vm, o)) != XXEMUL_STATUS_OK)
                return status;
            if ((status = stream_decode(h, vm, o)) != XXEMUL_STATUS_OK)
                return status;
            read = o->position < o->length ? o->length - o->position : 0;
            if (read > (size_t)y)
                read = (size_t)y;
            for (i = 0; i < read; ++i) {
                item = value(XXEMUL_DOTNET_VALUE_I4, o->bytes[o->position + i]);
                if ((status = xxemul_dotnet_vm_array_set(vm, (uint32_t)a[1].bits, (size_t)x + i, item)) != XXEMUL_STATUS_OK)
                    return status;
            }
            o->position += read;
            ++h->statistics.stream_reads;
            *out = value(XXEMUL_DOTNET_VALUE_I4, read);
            return XXEMUL_STATUS_OK;
        }
        if (!strcmp(name, "Write") && count == 4) {
            size_t array_length;
            xxemul_dotnet_value item;
            if (o->codec || o->channel == 2)
                return xxemul_dotnet_vm_raise_type(vm, "System.NotSupportedException");
            if (!integer(a[2], &x) || !integer(a[3], &y) || x < 0 || y < 0 ||
                xxemul_dotnet_vm_array_length(vm, (uint32_t)a[1].bits, &array_length) != XXEMUL_STATUS_OK || (uint64_t)x > array_length ||
                (uint64_t)y > array_length - (size_t)x || o->position > h->config.max_image_bytes || (uint64_t)y > h->config.max_image_bytes - o->position)
                return xxemul_dotnet_vm_raise_type(vm, "System.ArgumentOutOfRangeException");
            if (o->insensitive && o->position + (size_t)y > o->length)
                return xxemul_dotnet_vm_raise_type(vm, "System.NotSupportedException");
            if ((status = buffer_reserve(h, o, o->position + (size_t)y)) != XXEMUL_STATUS_OK)
                return status;
            for (i = 0; i < (size_t)y; ++i) {
                if ((status = xxemul_dotnet_vm_array_get(vm, (uint32_t)a[1].bits, (size_t)x + i, &item)) != XXEMUL_STATUS_OK)
                    return status;
                if (item.kind != XXEMUL_DOTNET_VALUE_I4 || item.bits > 255)
                    return XXEMUL_STATUS_DECODE_ERROR;
                o->bytes[o->position + i] = (uint8_t)item.bits;
                if (o->insensitive && (status = xxemul_dotnet_vm_array_set(vm, o->source, o->position + i, item)) != XXEMUL_STATUS_OK)
                    return status;
            }
            o->position += (size_t)y;
            if (o->length < o->position)
                o->length = o->position;
            ++h->statistics.stream_writes;
            return XXEMUL_STATUS_OK;
        }
        if (!strcmp(name, "Flush") && count == 1)
            return XXEMUL_STATUS_OK;
        if (!strcmp(name, "Seek") && count == 3) {
            int64_t target;
            if (o->codec || !integer(a[1], &x) || !integer(a[2], &y) || y < 0 || y > 2)
                goto unsupported;
            target = y == 0 ? 0 : y == 1 ? (int64_t)o->position : (int64_t)o->length;
            if ((x > 0 && target > INT64_MAX - x) || (x < 0 && target < INT64_MIN - x))
                return xxemul_dotnet_vm_raise_type(vm, "System.IO.IOException");
            target += x;
            if (target < 0 || (uint64_t)target > h->config.max_image_bytes)
                return xxemul_dotnet_vm_raise_type(vm, "System.IO.IOException");
            o->position = (size_t)target;
            *out = value(XXEMUL_DOTNET_VALUE_I8, (uint64_t)target);
            return XXEMUL_STATUS_OK;
        }
        if (!strcmp(name, "get_Length") && count == 1 && !o->codec) {
            *out = value(XXEMUL_DOTNET_VALUE_I8, o->length);
            return XXEMUL_STATUS_OK;
        }
        if (!strcmp(name, "get_Position") && count == 1 && !o->codec) {
            *out = value(XXEMUL_DOTNET_VALUE_I8, o->position);
            return XXEMUL_STATUS_OK;
        }
    }
    if (!strcmp(t, "System.Security.Cryptography.SHA256") && !strcmp(name, "Create") && count == 0) {
        status = new_host_object(h, vm, "System.Security.Cryptography.SHA256", BCL_HASH, &o);
        if (status == XXEMUL_STATUS_OK)
            *out = object_value(o->reference);
        return status;
    }
    if (!strcmp(t, "System.Security.Cryptography.HashAlgorithm") && !strcmp(name, "ComputeHash") && count == 2 && o && o->kind == BCL_HASH) {
        bcl_object *stream = lookup(h, vm, (uint32_t)a[1].bits);
        uint8_t digest[32];
        if (o->closed)
            return xxemul_dotnet_vm_raise_type(vm, "System.ObjectDisposedException");
        if (!strcmp(m->signature, "(System.Byte[])System.Byte[]")) {
            uint8_t *bytes;
            size_t length;
            status = byte_array(h, vm, a[1], &bytes, &length);
            if (status != XXEMUL_STATUS_OK)
                return status;
            int okay = xx_sha256_memory(bytes, length, digest);
            host_free(h, bytes, length);
            if (!okay)
                return XXEMUL_STATUS_INVALID_ARGUMENT;
            ++h->statistics.sha256_operations;
            return bytes_result(vm, digest, sizeof(digest), out);
        }
        if (!stream || stream->kind != BCL_STREAM || stream->closed)
            return xxemul_dotnet_vm_raise_type(vm, "System.ArgumentException");
        if ((status = sync_array_stream(vm, stream)) != XXEMUL_STATUS_OK)
            return status;
        if ((status = stream_decode(h, vm, stream)) != XXEMUL_STATUS_OK)
            return status;
        if (stream->position > stream->length)
            return XXEMUL_STATUS_DECODE_ERROR;
        if (!xx_sha256_memory(stream->length > stream->position ? stream->bytes + stream->position : (const uint8_t *)"", stream->length - stream->position,
                              digest))
            return XXEMUL_STATUS_INVALID_ARGUMENT;
        stream->position = stream->length;
        ++h->statistics.sha256_operations;
        return bytes_result(vm, digest, sizeof(digest), out);
    }
    if ((!strcmp(t, "System.IDisposable") || !strcmp(t, "System.Security.Cryptography.HashAlgorithm") || !strcmp(t, "System.Security.Cryptography.SHA256")) &&
        !strcmp(name, "Dispose") && count == 1) {
        if (o && o->kind == BCL_STREAM) {
            close_stream(h, vm, o);
            return XXEMUL_STATUS_OK;
        }
        if (o && o->kind == BCL_HASH) {
            o->closed = 1;
            return XXEMUL_STATUS_OK;
        }
        goto unsupported;
    }
    if (!strcmp(t, "System.BitConverter") && !strcmp(name, "ToString") && count == 1) {
        uint8_t *bytes;
        size_t length;
        char *hex;
        static const char digits[] = "0123456789ABCDEF";
        status = byte_array(h, vm, a[0], &bytes, &length);
        if (status != XXEMUL_STATUS_OK)
            return status;
        if (length > (h->config.max_native_bytes - 1) / 3) {
            host_free(h, bytes, length);
            return XXEMUL_STATUS_LIMIT_REACHED;
        }
        n = length ? length * 3 - 1 : 0;
        hex = host_alloc(h, n + 1);
        if (!hex) {
            host_free(h, bytes, length);
            return XXEMUL_STATUS_LIMIT_REACHED;
        }
        for (i = 0; i < length; ++i) {
            hex[i * 3] = digits[bytes[i] >> 4];
            hex[i * 3 + 1] = digits[bytes[i] & 15];
            if (i + 1 < length)
                hex[i * 3 + 2] = '-';
        }
        status = text_result(vm, hex, n, out);
        host_free(h, hex, n + 1);
        host_free(h, bytes, length);
        return status;
    }
    if (!strcmp(t, "System.String")) {
        if (!strcmp(name, "Concat")) {
            char *text = NULL;
            size_t total = 0, items = count;
            uint32_t array = 0;
            xxemul_dotnet_value item;
            if (count == 1 && a[0].kind == XXEMUL_DOTNET_VALUE_OBJECT && xxemul_dotnet_vm_array_length(vm, (uint32_t)a[0].bits, &items) == XXEMUL_STATUS_OK)
                array = (uint32_t)a[0].bits;
            text = host_alloc(h, 1);
            if (!text)
                return XXEMUL_STATUS_LIMIT_REACHED;
            for (i = 0; i < items; ++i) {
                char *part, *grown;
                size_t part_size;
                if (array) {
                    if ((status = xxemul_dotnet_vm_array_get(vm, array, i, &item)) != XXEMUL_STATUS_OK)
                        goto concat_done;
                } else
                    item = a[i];
                status = stringify(h, vm, item, &part, &part_size);
                if (status != XXEMUL_STATUS_OK)
                    goto concat_done;
                if (part_size > h->config.max_native_bytes - total - 1 || part_size > h->config.max_native_bytes - h->native_bytes) {
                    host_free(h, part, part_size + 1);
                    status = XXEMUL_STATUS_LIMIT_REACHED;
                    goto concat_done;
                }
                grown = realloc(text, total + part_size + 1);
                if (!grown) {
                    host_free(h, part, part_size + 1);
                    status = XXEMUL_STATUS_OUT_OF_MEMORY;
                    goto concat_done;
                }
                text = grown;
                h->native_bytes += part_size;
                memcpy(text + total, part, part_size);
                total += part_size;
                text[total] = 0;
                host_free(h, part, part_size + 1);
            }
            status = text_result(vm, text, total, out);
        concat_done:
            host_free(h, text, total + 1);
            return status;
        }
        if ((!strcmp(name, "op_Equality") || !strcmp(name, "Equals") || !strcmp(name, "op_Inequality")) && count == 2) {
            size_t na, nb;
            const char *sa = get_string(vm, a[0], &na), *sb = get_string(vm, a[1], &nb);
            int equal;
            if (!sa && !a[0].bits)
                equal = !sb && !a[1].bits;
            else
                equal = sa && sb && na == nb && !memcmp(sa, sb, na);
            if (!strcmp(name, "op_Inequality"))
                equal = !equal;
            *out = value(XXEMUL_DOTNET_VALUE_I4, (unsigned)equal);
            return XXEMUL_STATUS_OK;
        }
        if (!count || (s = get_string(vm, a[0], &n)) == NULL)
            return xxemul_dotnet_vm_raise_type(vm, "System.NullReferenceException");
        if (!strcmp(name, "Replace") && count == 3) {
            size_t old_size, new_size, at = 0, total = 0;
            const char *old = get_string(vm, a[1], &old_size), *replacement = get_string(vm, a[2], &new_size);
            char *buffer;
            if (!old || !old_size)
                return xxemul_dotnet_vm_raise_type(vm, "System.ArgumentException");
            if (!replacement) {
                if (a[2].bits)
                    return XXEMUL_STATUS_INVALID_ARGUMENT;
                replacement = "";
                new_size = 0;
            }
            while (at < n) {
                if (old_size <= n - at && !memcmp(s + at, old, old_size)) {
                    if (new_size > h->config.max_native_bytes - total)
                        return XXEMUL_STATUS_LIMIT_REACHED;
                    total += new_size;
                    at += old_size;
                } else {
                    ++at;
                    ++total;
                }
            }
            buffer = host_alloc(h, total + 1);
            if (!buffer)
                return XXEMUL_STATUS_LIMIT_REACHED;
            at = 0;
            i = 0;
            while (at < n) {
                if (old_size <= n - at && !memcmp(s + at, old, old_size)) {
                    memcpy(buffer + i, replacement, new_size);
                    i += new_size;
                    at += old_size;
                } else
                    buffer[i++] = s[at++];
            }
            status = text_result(vm, buffer, total, out);
            host_free(h, buffer, total + 1);
            return status;
        }
        if ((!strcmp(name, "ToLower") || !strcmp(name, "ToLowerInvariant") || !strcmp(name, "ToUpperInvariant")) && count == 1) {
            char *copy = host_string(h, s, n);
            if (!copy)
                return XXEMUL_STATUS_LIMIT_REACHED;
            for (i = 0; i < n; ++i) {
                unsigned char ch = (unsigned char)copy[i];
                if (ch < 0x80)
                    copy[i] = (char)(!strcmp(name, "ToUpperInvariant") ? toupper(ch) : tolower(ch));
                else {
                    host_free(h, copy, n + 1);
                    return host_fail(h, XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION, "non-ASCII invariant case conversion is unsupported");
                }
            }
            status = text_result(vm, copy, n, out);
            host_free(h, copy, n + 1);
            return status;
        }
        if (!strcmp(name, "StartsWith") && count == 2) {
            size_t length;
            const char *prefix = get_string(vm, a[1], &length);
            if (!prefix)
                return xxemul_dotnet_vm_raise_type(vm, "System.ArgumentNullException");
            *out = value(XXEMUL_DOTNET_VALUE_I4, length <= n && !memcmp(s, prefix, length));
            return XXEMUL_STATUS_OK;
        }
        if ((!strcmp(name, "Substring") && (count == 2 || count == 3)) || (!strcmp(name, "get_Chars") && count == 2)) {
            uint16_t *units;
            size_t length;
            if ((status = utf16_units(h, s, n, &units, &length)) != XXEMUL_STATUS_OK)
                return status;
            if (!integer(a[1], &x) || x < 0 || (uint64_t)x > length) {
                host_free(h, units, (n + 1) * sizeof(*units));
                return xxemul_dotnet_vm_raise_type(vm, "System.ArgumentOutOfRangeException");
            }
            if (!strcmp(name, "get_Chars")) {
                if ((uint64_t)x == length) {
                    host_free(h, units, (n + 1) * sizeof(*units));
                    return xxemul_dotnet_vm_raise_type(vm, "System.IndexOutOfRangeException");
                }
                *out = value(XXEMUL_DOTNET_VALUE_I4, units[x]);
                status = XXEMUL_STATUS_OK;
            } else {
                y = (int64_t)length - x;
                if (count == 3 && (!integer(a[2], &y) || y < 0 || (uint64_t)y > length - (size_t)x)) {
                    host_free(h, units, (n + 1) * sizeof(*units));
                    return xxemul_dotnet_vm_raise_type(vm, "System.ArgumentOutOfRangeException");
                }
                status = units_to_text(h, vm, units + x, (size_t)y, out);
            }
            host_free(h, units, (n + 1) * sizeof(*units));
            return status;
        }
        if (!strcmp(name, "get_Length") && count == 1) {
            size_t units = 0;
            for (i = 0; i < n; ++i) {
                unsigned char c = (unsigned char)s[i];
                if ((c & 0xc0) != 0x80)
                    units += c >= 0xf0 ? 2 : 1;
            }
            *out = value(XXEMUL_DOTNET_VALUE_I4, units);
            return XXEMUL_STATUS_OK;
        }
        if (!strcmp(name, "ToString") && count == 1) {
            *out = a[0];
            return XXEMUL_STATUS_OK;
        }
    }
    if (!strcmp(t, "System.Int32") && !strcmp(name, "Parse") && count == 1) {
        char *end;
        long parsed;
        s = get_string(vm, a[0], &n);
        if (!s)
            return xxemul_dotnet_vm_raise_type(vm, "System.ArgumentNullException");
        if (memchr(s, 0, n))
            return xxemul_dotnet_vm_raise_type(vm, "System.FormatException");
        errno = 0;
        parsed = strtol(s, &end, 10);
        while (*end && isspace((unsigned char)*end))
            ++end;
        if (end == s || *end)
            return xxemul_dotnet_vm_raise_type(vm, "System.FormatException");
        if (errno == ERANGE || parsed < INT32_MIN || parsed > INT32_MAX)
            return xxemul_dotnet_vm_raise_type(vm, "System.OverflowException");
        *out = value(XXEMUL_DOTNET_VALUE_I4, (uint32_t)(int32_t)parsed);
        return XXEMUL_STATUS_OK;
    }
    if (!strcmp(t, "System.AppDomain") && !strcmp(name, "get_CurrentDomain") && count == 0) {
        for (o = h->objects; o; o = o->next)
            if (o->vm == vm && o->kind == BCL_DOMAIN) {
                *out = object_value(o->reference);
                return XXEMUL_STATUS_OK;
            }
        status = new_host_object(h, vm, "System.AppDomain", BCL_DOMAIN, &o);
        if (status == XXEMUL_STATUS_OK)
            *out = object_value(o->reference);
        return status;
    }
    if (!strcmp(t, "System.ResolveEventHandler") && !strcmp(name, ".ctor") && count == 3) {
        if (a[2].kind != XXEMUL_DOTNET_VALUE_NATIVE || a[2].bits > UINT32_MAX || xxemul_dotnet_resolve_token(program, (uint32_t)a[2].bits) == SIZE_MAX)
            return XXEMUL_STATUS_DECODE_ERROR;
        o = attach(h, vm, (uint32_t)a[0].bits, BCL_DELEGATE);
        if (!o)
            return XXEMUL_STATUS_LIMIT_REACHED;
        o->module = module;
        o->target = a[1];
        o->method_token = (uint32_t)a[2].bits;
        return XXEMUL_STATUS_OK;
    }
    if (!strcmp(t, "System.AppDomain") && !strcmp(name, "add_AssemblyResolve") && count == 2 && o && o->kind == BCL_DOMAIN) {
        bcl_object *handler = lookup(h, vm, (uint32_t)a[1].bits);
        if (!handler || handler->kind != BCL_DELEGATE)
            return xxemul_dotnet_vm_raise_type(vm, "System.ArgumentException");
        h->resolver = handler;
        return XXEMUL_STATUS_OK;
    }
    if (!strcmp(t, "System.IO.Path") && count == 1) {
        s = get_string(vm, a[0], &n);
        if (!s)
            return xxemul_dotnet_vm_raise_type(vm, "System.ArgumentNullException");
        if (!strcmp(name, "GetDirectoryName")) {
            size_t end = n;
            while (end && s[end - 1] != '/' && s[end - 1] != '\\')
                --end;
            if (!end) {
                *out = object_value(0);
                return XXEMUL_STATUS_OK;
            }
            if (end > 1)
                --end;
            return text_result(vm, s, end, out);
        }
        if (!strcmp(name, "GetFileName") || !strcmp(name, "GetFileNameWithoutExtension")) {
            size_t start = n, end = n;
            while (start && s[start - 1] != '/' && s[start - 1] != '\\')
                --start;
            if (!strcmp(name, "GetFileNameWithoutExtension")) {
                for (i = n; i > start; --i)
                    if (s[i - 1] == '.') {
                        end = i - 1;
                        break;
                    }
            }
            return text_result(vm, s + start, end - start, out);
        }
    }
    if (!strcmp(t, "System.IO.Directory") && !strcmp(name, "GetFiles") && count == 2) {
        size_t pattern_size;
        const char *pattern = get_string(vm, a[1], &pattern_size);
        uint32_t array;
        s = get_string(vm, a[0], &n);
        if (!s || !pattern)
            return xxemul_dotnet_vm_raise_type(vm, "System.ArgumentException");
        {
            bcl_module *member;
            size_t matches = 0, at = 0, base = strlen(h->entry_path);
            while (base && h->entry_path[base - 1] != '/' && h->entry_path[base - 1] != '\\')
                --base;
            if (base > 1)
                --base;
            if (n != base || memcmp(s, h->entry_path, base))
                return xxemul_dotnet_vm_raise_type(vm, "System.IO.DirectoryNotFoundException");
            for (member = h->modules; member; member = member->next) {
                size_t length = strlen(member->location), start = length;
                while (start && member->location[start - 1] != '/' && member->location[start - 1] != '\\')
                    --start;
                if (length && start && start - 1 == n && !memcmp(member->location, s, n) &&
                    glob_match(pattern, pattern_size, member->location + start, length - start))
                    ++matches;
            }
            status = xxemul_dotnet_vm_new_array(vm, "System.String", matches, &array);
            if (status != XXEMUL_STATUS_OK)
                return status;
            for (member = h->modules; member; member = member->next) {
                size_t length = strlen(member->location), start = length;
                xxemul_dotnet_value text;
                while (start && member->location[start - 1] != '/' && member->location[start - 1] != '\\')
                    --start;
                if (length && start && start - 1 == n && !memcmp(member->location, s, n) &&
                    glob_match(pattern, pattern_size, member->location + start, length - start)) {
                    if ((status = text_result(vm, member->location, length, &text)) != XXEMUL_STATUS_OK ||
                        (status = xxemul_dotnet_vm_array_set(vm, array, at++, text)) != XXEMUL_STATUS_OK)
                        return status;
                }
            }
            *out = object_value(array);
            return XXEMUL_STATUS_OK;
        }
    }
    if (!strcmp(t, "System.IO.File") && count == 1) {
        bcl_module *member;
        s = get_string(vm, a[0], &n);
        if (!s) {
            if (!strcmp(name, "Exists")) {
                *out = value(XXEMUL_DOTNET_VALUE_I4, 0);
                return XXEMUL_STATUS_OK;
            }
            return xxemul_dotnet_vm_raise_type(vm, "System.ArgumentNullException");
        }
        for (member = h->modules; member; member = member->next)
            if (strlen(member->location) == n && !memcmp(member->location, s, n) && n)
                break;
        if (!strcmp(name, "Exists")) {
            *out = value(XXEMUL_DOTNET_VALUE_I4, member != NULL);
            return XXEMUL_STATUS_OK;
        }
        if (!strcmp(name, "OpenRead")) {
            const uint8_t *bytes;
            size_t length;
            if (!member)
                return xxemul_dotnet_vm_raise_type(vm, "System.IO.FileNotFoundException");
            bytes = xxemul_dotnet_data(member->program, &length);
            status = new_host_object(h, vm, "System.IO.FileStream", BCL_STREAM, &o);
            if (status != XXEMUL_STATUS_OK)
                return status;
            if ((status = buffer_reserve(h, o, length)) != XXEMUL_STATUS_OK)
                return status;
            memcpy(o->bytes, bytes, length);
            o->length = length;
            o->channel = 2;
            *out = object_value(o->reference);
            return XXEMUL_STATUS_OK;
        }
    }
unsupported:
    (void)y;
    (void)z;
    return host_fail(h, XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION, "unsupported CLR/BCL service: %s", m->selector);
}

xxemul_dotnet_bcl_host *xxemul_dotnet_bcl_host_create(const xxemul_dotnet_bcl_config *config, xxemul_status *status)
{
    xxemul_dotnet_bcl_host *h = calloc(1, sizeof(*h));
    if (status)
        *status = XXEMUL_STATUS_OUT_OF_MEMORY;
    if (!h)
        return NULL;
    if (config)
        h->config = *config;
    if (!h->config.max_instructions)
        h->config.max_instructions = UINT64_C(1000000);
    if (!h->config.max_heap_bytes)
        h->config.max_heap_bytes = 0x1000000;
    if (!h->config.max_native_bytes)
        h->config.max_native_bytes = 0x4000000;
    if (!h->config.max_image_bytes)
        h->config.max_image_bytes = 0x1000000;
    if (!h->config.max_output_bytes)
        h->config.max_output_bytes = 0x400000;
    if (!h->config.max_loaded_assemblies)
        h->config.max_loaded_assemblies = 16;
    if (h->config.max_image_bytes > 0x10000000 || h->config.max_native_bytes > SIZE_MAX / 2 || h->config.max_loaded_assemblies > 256 ||
        (h->config.flags & ~XXEMUL_DOTNET_BCL_SHARPZIP_STREAMS) || h->config.filesystem_root) {
        if (status)
            *status = h->config.filesystem_root ? XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION : XXEMUL_STATUS_INVALID_ARGUMENT;
        free(h);
        return NULL;
    }
    h->entry_path = host_string(h, h->config.logical_entry_path ? h->config.logical_entry_path : "/app/program.exe",
                                strlen(h->config.logical_entry_path ? h->config.logical_entry_path : "/app/program.exe"));
    if (!h->entry_path) {
        if (status)
            *status = XXEMUL_STATUS_LIMIT_REACHED;
        free(h);
        return NULL;
    }
    if (status)
        *status = XXEMUL_STATUS_OK;
    return h;
}
void xxemul_dotnet_bcl_host_destroy(xxemul_dotnet_bcl_host *h)
{
    bcl_object *o, *next;
    bcl_module *m, *mn;
    if (!h)
        return;
    for (o = h->objects; o; o = next) {
        next = o->next;
        host_free(h, o->bytes, o->capacity);
        if (o->name)
            host_free(h, o->name, strlen(o->name) + 1);
        host_free(h, o, sizeof(*o));
    }
    for (m = h->modules; m; m = mn) {
        mn = m->next;
        if (m->vm)
            xxemul_dotnet_vm_destroy(m->vm);
        if (m->owned)
            xxemul_dotnet_destroy((xxemul_dotnet_program *)m->program);
        host_free(h, m->location, strlen(m->location) + 1);
        host_free(h, m, sizeof(*m));
    }
    host_free(h, h->entry_path, strlen(h->entry_path) + 1);
    free(h);
}
static xxemul_status bcl_execute_impl(xxemul_dotnet_bcl_host *h, const xxemul_dotnet_program *program, int argc, const char *const *argv,
                                      xxemul_dotnet_result *result)
{
    bcl_module *module;
    size_t entry, i;
    uint32_t array;
    xxemul_dotnet_value argument;
    xxemul_status status;
    if (!h || !program || !result || argc < 0 || (argc && !argv) || h->executing)
        return XXEMUL_STATUS_INVALID_ARGUMENT;
    memset(result, 0, sizeof(*result));
    h->diagnostic[0] = 0;
    h->output_bytes = 0;
    h->remaining_instructions = h->config.max_instructions;
    {
        size_t size;
        xxemul_dotnet_data(program, &size);
        if (size > h->config.max_image_bytes)
            return host_fail(h, XXEMUL_STATUS_LIMIT_REACHED, "root image exceeds configured bound");
    }
    if (h->entry_module)
        return host_fail(h, XXEMUL_STATUS_INVALID_ARGUMENT, "host already executed an entry; create a fresh host for a new process");
    module = register_module(h, program, 0, h->entry_path);
    if (!module)
        return XXEMUL_STATUS_LIMIT_REACHED;
    h->entry_module = module;
    entry = xxemul_dotnet_entry_point(program);
    if (entry == SIZE_MAX)
        return host_fail(h, XXEMUL_STATUS_INVALID_IMAGE, "managed entry point is missing");
    if ((status = ensure_vm(h, module, h->config.max_instructions)) != XXEMUL_STATUS_OK)
        return status;
    status = xxemul_dotnet_vm_new_array(module->vm, "System.String", (size_t)argc, &array);
    if (status != XXEMUL_STATUS_OK)
        return status;
    for (i = 0; i < (size_t)argc; ++i) {
        xxemul_dotnet_value text;
        if (!argv[i])
            return XXEMUL_STATUS_INVALID_ARGUMENT;
        if ((status = text_result(module->vm, argv[i], strlen(argv[i]), &text)) != XXEMUL_STATUS_OK ||
            (status = xxemul_dotnet_vm_array_set(module->vm, array, i, text)) != XXEMUL_STATUS_OK)
            return status;
    }
    h->executing = 1;
    module->invoking = 1;
    argument = object_value(array);
    status = xxemul_dotnet_vm_invoke(module->vm, entry, &argument, program->methods[entry].signature.parameter_count ? 1 : 0, result);
    module->invoking = 0;
    h->executing = 0;
    h->statistics.managed_instructions = h->config.max_instructions - h->remaining_instructions;
    if (status != XXEMUL_STATUS_OK && !h->diagnostic[0])
        snprintf(h->diagnostic, sizeof(h->diagnostic), "%s", result->diagnostic);
    return status;
}
xxemul_status xxemul_dotnet_bcl_execute(xxemul_dotnet_bcl_host *h, const xxemul_dotnet_program *program, int argc, const char *const *argv,
                                        xxemul_dotnet_result *result)
{
    xxemul_status status;
    if (!result)
        return XXEMUL_STATUS_INVALID_ARGUMENT;
    memset(result, 0, sizeof(*result));
    status = bcl_execute_impl(h, program, argc, argv, result);
    result->status = status;
    if (status != XXEMUL_STATUS_OK && h) {
        if (!h->diagnostic[0])
            snprintf(h->diagnostic, sizeof(h->diagnostic), "managed BCL execution failed with status %u", (unsigned)status);
        if (!result->diagnostic[0])
            snprintf(result->diagnostic, sizeof(result->diagnostic), "%.*s", (int)sizeof(result->diagnostic) - 1, h->diagnostic);
    }
    return status;
}
const char *xxemul_dotnet_bcl_diagnostic(const xxemul_dotnet_bcl_host *h)
{
    return h ? h->diagnostic : "invalid BCL host";
}
const xxemul_dotnet_bcl_statistics *xxemul_dotnet_bcl_get_statistics(const xxemul_dotnet_bcl_host *h)
{
    return h ? &h->statistics : NULL;
}
