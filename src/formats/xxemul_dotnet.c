#include "../xxemul_dotnet_internal.h"

#include <xxfclib/formats/dotnet/xx_dotnet_inspect.h>
#include <xxfclib/formats/dotnet/xx_dotnet_reader.h>
#include <xxfclib/io/xx_io.h>
#include <xxfclib/memory/xx_memory.h>
#include <xxbyte/xxbyte_dotnet.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DN_IMAGE_LIMIT ((size_t)256 * 1024 * 1024)
#define DN_METADATA_LIMIT ((size_t)32 * 1024 * 1024)
#define DN_STRING_LIMIT ((size_t)65536)
#define DN_COUNT_LIMIT ((size_t)200000)
#define DN_SIGNATURE_LIMIT ((size_t)65536)
#define DN_ARGUMENT_LIMIT ((size_t)1024)
#define DN_DEPTH_LIMIT 32
#define DN_WORK_LIMIT ((size_t)128 * 1024 * 1024)
#define DN_TOKEN(table, rid) (((uint32_t)(table) << 24) | (uint32_t)(rid))

typedef struct dn_loader {
    xxemul_dotnet_program *program;
    xx_dotnet_inspection inspection;
    const xx_dotnet_inspect_cli *cli;
    size_t work;
    xxemul_status status;
    uint8_t *type_visiting;
} dn_loader;

typedef struct dn_signature_reader {
    dn_loader *loader;
    const uint8_t *data;
    size_t size, position, budget;
} dn_signature_reader;

static int dn_fail(dn_loader *loader, xxemul_status status) {
    if (loader->status == XXEMUL_STATUS_OK) loader->status = status;
    return 0;
}
static int dn_work(dn_loader *loader, size_t amount) {
    if (amount > loader->work) return dn_fail(loader, XXEMUL_STATUS_INVALID_IMAGE);
    loader->work -= amount; return 1;
}
static int dn_range(size_t size, size_t offset, size_t amount) {
    return offset <= size && amount <= size - offset;
}
static char *dn_copy(dn_loader *loader, const char *value, size_t size) {
    char *copy;
    if (!dn_work(loader, size) || size == SIZE_MAX) return NULL;
    copy = (char *)malloc(size + 1);
    if (!copy) { dn_fail(loader, XXEMUL_STATUS_OUT_OF_MEMORY); return NULL; }
    memcpy(copy, value, size); copy[size] = 0; return copy;
}
static char *dn_join(dn_loader *loader, const char *a, const char *separator, const char *b) {
    size_t x = strlen(a), y = strlen(separator), z = strlen(b);
    char *result;
    if (x > DN_SIGNATURE_LIMIT || y > DN_SIGNATURE_LIMIT - x || z > DN_SIGNATURE_LIMIT - x - y) {
        dn_fail(loader, XXEMUL_STATUS_INVALID_IMAGE); return NULL;
    }
    if (!dn_work(loader, x + y + z)) return NULL;
    result = (char *)malloc(x + y + z + 1);
    if (!result) { dn_fail(loader, XXEMUL_STATUS_OUT_OF_MEMORY); return NULL; }
    memcpy(result, a, x); memcpy(result + x, separator, y); memcpy(result + x + y, b, z + 1);
    return result;
}

static int dn_compressed(const uint8_t *data, size_t size, size_t *position, uint32_t *value) {
    uint8_t first;
    uint32_t result;
    size_t pos = *position;
    if (pos >= size) return 0;
    first = data[pos++];
    if (!(first & 0x80)) result = first;
    else if ((first & 0xc0) == 0x80) {
        if (pos >= size) return 0;
        result = ((uint32_t)(first & 0x3f) << 8) | data[pos++];
        if (result < 0x80) return 0;
    } else if ((first & 0xe0) == 0xc0) {
        if (!dn_range(size, pos, 3)) return 0;
        result = ((uint32_t)(first & 0x1f) << 24) | ((uint32_t)data[pos] << 16) |
            ((uint32_t)data[pos + 1] << 8) | data[pos + 2]; pos += 3;
        if (result < 0x4000) return 0;
    } else return 0;
    *position = pos; *value = result; return 1;
}

static uint32_t dn_index(const uint8_t **row, int width) {
    uint32_t value = width == 4 ? xxemul_dotnet_u32(*row) : xxemul_dotnet_u16(*row);
    *row += width; return value;
}
static const uint8_t *dn_row(dn_loader *loader, unsigned table, uint32_t rid) {
    int64_t offset;
    uint32_t width;
    if (!xx_dotnet_inspect_table_row(&loader->inspection, table, rid, &offset, &width)) {
        dn_fail(loader, XXEMUL_STATUS_INVALID_IMAGE); return NULL;
    }
    if (offset < 0 || (uint64_t)offset > SIZE_MAX ||
        !dn_range(loader->program->size, (size_t)offset, width) || !dn_work(loader, width)) {
        dn_fail(loader, XXEMUL_STATUS_INVALID_IMAGE); return NULL;
    }
    return loader->program->data + (size_t)offset;
}
static char *dn_heap_string(dn_loader *loader, uint32_t index) {
    const xx_dotnet_inspect_cli *cli = loader->cli;
    const uint8_t *data;
    const void *end;
    size_t available;
    if (cli->nStringsOffset < 0 || index >= (uint64_t)cli->nStringsSize) {
        dn_fail(loader, XXEMUL_STATUS_INVALID_IMAGE); return NULL;
    }
    data = loader->program->data + (size_t)cli->nStringsOffset + index;
    available = (size_t)cli->nStringsSize - index;
    if (available > DN_STRING_LIMIT) available = DN_STRING_LIMIT;
    end = memchr(data, 0, available);
    if (!end) { dn_fail(loader, XXEMUL_STATUS_INVALID_IMAGE); return NULL; }
    return dn_copy(loader, (const char *)data, (size_t)((const uint8_t *)end - data));
}
static int dn_blob(dn_loader *loader, uint32_t index, const uint8_t **data, size_t *size) {
    int64_t offset;
    uint32_t length;
    if (!xx_dotnet_inspect_blob(&loader->inspection, index, &offset, &length) ||
        offset < 0 || (uint64_t)offset > SIZE_MAX ||
        !dn_range(loader->program->size, (size_t)offset, length)) return dn_fail(loader, XXEMUL_STATUS_INVALID_IMAGE);
    *data = loader->program->data + (size_t)offset; *size = length; return dn_work(loader, 1);
}

static int dn_rva(dn_loader *loader, uint32_t rva, size_t amount, size_t *offset, size_t *available) {
    const xx_pe_inspection *pe = &loader->inspection.pe;
    size_t i;
    if (rva < pe->nSizeOfHeaders && dn_range(pe->nSizeOfHeaders, rva, amount) &&
        dn_range(loader->program->size, rva, amount)) {
        *offset = rva; if (available) *available = pe->nSizeOfHeaders - rva; return 1;
    }
    for (i = 0; i < (size_t)pe->nSectionCount; ++i) {
        const xx_pe_inspect_section *section = pe->pSections + i;
        uint64_t delta;
        if (rva < section->nVirtualAddress) continue;
        delta = (uint64_t)rva - section->nVirtualAddress;
        if (delta < section->nSizeOfRawData && amount <= (uint64_t)section->nSizeOfRawData - delta) {
            uint64_t raw = (uint64_t)section->nPointerToRawData + delta;
            if (raw > SIZE_MAX || !dn_range(loader->program->size, (size_t)raw, amount)) break;
            *offset = (size_t)raw;
            if (available) *available = section->nSizeOfRawData - (size_t)delta;
            return 1;
        }
    }
    return dn_fail(loader, XXEMUL_STATUS_INVALID_IMAGE);
}

/* Supplement the inspection's metadata view with complete raw-backed PE and
 * stream extents. Virtual zero-fill must never become metadata or IL bytes. */
static int dn_validate_image(dn_loader *loader) {
    xxemul_dotnet_program *program = loader->program;
    const xx_pe_inspection *pe = &loader->inspection.pe;
    const xx_dotnet_inspect_cli *cli = loader->cli;
    const uint8_t *data = program->data;
    size_t i, j, cor, meta, position, metadata_size;
    uint32_t version_size;
    uint16_t count;
    struct { uint32_t offset, size; char name[33]; } streams[32];
    if (!pe->bValid || !cli->bValid || !loader->inspection.bIsNet || pe->nSectionCount < 1 || pe->nSectionCount > 96 ||
        pe->nSizeOfHeaders > program->size || (pe->nMagic != 0x10b && pe->nMagic != 0x20b))
        return dn_fail(loader, XXEMUL_STATUS_INVALID_IMAGE);
    program->pointer_size = pe->bIs64 ? 8 : 4;
    for (i = 0; i < (size_t)pe->nSectionCount; ++i) {
        const xx_pe_inspect_section *a = pe->pSections + i;
        if (!dn_range(program->size, a->nPointerToRawData, a->nSizeOfRawData)) return dn_fail(loader, XXEMUL_STATUS_INVALID_IMAGE);
        for (j = 0; j < i; ++j) {
            const xx_pe_inspect_section *b = pe->pSections + j;
            if (a->nSizeOfRawData && b->nSizeOfRawData &&
                (uint64_t)a->nPointerToRawData < (uint64_t)b->nPointerToRawData + b->nSizeOfRawData &&
                (uint64_t)b->nPointerToRawData < (uint64_t)a->nPointerToRawData + a->nSizeOfRawData)
                return dn_fail(loader, XXEMUL_STATUS_INVALID_IMAGE);
            if (a->nSizeOfRawData && b->nSizeOfRawData &&
                (uint64_t)a->nVirtualAddress < (uint64_t)b->nVirtualAddress + b->nSizeOfRawData &&
                (uint64_t)b->nVirtualAddress < (uint64_t)a->nVirtualAddress + a->nSizeOfRawData)
                return dn_fail(loader, XXEMUL_STATUS_INVALID_IMAGE);
        }
    }
    if (pe->pDirSize[14] < 72 || !dn_rva(loader, pe->pDirRVA[14], pe->pDirSize[14], &cor, NULL) ||
        cor != (uint64_t)cli->nCliOffset || xxemul_dotnet_u32(data + cor) < 72 ||
        xxemul_dotnet_u32(data + cor) > pe->pDirSize[14]) return dn_fail(loader, XXEMUL_STATUS_INVALID_IMAGE);
    if (cli->nFlags & 0x10) return dn_fail(loader, XXEMUL_STATUS_UNSUPPORTED_IMAGE);
    metadata_size = xxemul_dotnet_u32(data + cor + 12);
    if (metadata_size < 20 || metadata_size > DN_METADATA_LIMIT ||
        !dn_rva(loader, xxemul_dotnet_u32(data + cor + 8), metadata_size, &meta, NULL) ||
        meta != (uint64_t)cli->nMetaOffset || metadata_size != (uint64_t)cli->nMetaSize ||
        xxemul_dotnet_u32(data + meta) != UINT32_C(0x424a5342)) return dn_fail(loader, XXEMUL_STATUS_INVALID_IMAGE);
    version_size = xxemul_dotnet_u32(data + meta + 12);
    if (version_size > 4096 || !dn_range(metadata_size, 16, (size_t)version_size + 4)) return dn_fail(loader, XXEMUL_STATUS_INVALID_IMAGE);
    position = 16 + ((version_size + 3u) & ~3u);
    if (!dn_range(metadata_size, position, 4)) return dn_fail(loader, XXEMUL_STATUS_INVALID_IMAGE);
    count = xxemul_dotnet_u16(data + meta + position + 2); position += 4;
    if (!count || count > 32) return dn_fail(loader, XXEMUL_STATUS_INVALID_IMAGE);
    memset(streams, 0, sizeof(streams));
    for (i = 0; i < count; ++i) {
        size_t length;
        if (!dn_range(metadata_size, position, 9)) return dn_fail(loader, XXEMUL_STATUS_INVALID_IMAGE);
        streams[i].offset = xxemul_dotnet_u32(data + meta + position);
        streams[i].size = xxemul_dotnet_u32(data + meta + position + 4); position += 8;
        for (length = 0; length < 32 && position + length < metadata_size && data[meta + position + length]; ++length) {}
        if (!length || length == 32 || position + length >= metadata_size) return dn_fail(loader, XXEMUL_STATUS_INVALID_IMAGE);
        memcpy(streams[i].name, data + meta + position, length);
        position += (length + 4) & ~(size_t)3;
        if (position > metadata_size || !dn_range(metadata_size, streams[i].offset, streams[i].size)) return dn_fail(loader, XXEMUL_STATUS_INVALID_IMAGE);
        for (j = 0; j < i; ++j) {
            if (!strcmp(streams[i].name, streams[j].name) ||
                ((!strcmp(streams[i].name, "#~") || !strcmp(streams[i].name, "#-")) &&
                 (!strcmp(streams[j].name, "#~") || !strcmp(streams[j].name, "#-")))) return dn_fail(loader, XXEMUL_STATUS_INVALID_IMAGE);
            if (streams[i].size && streams[j].size &&
                (uint64_t)streams[i].offset < (uint64_t)streams[j].offset + streams[j].size &&
                (uint64_t)streams[j].offset < (uint64_t)streams[i].offset + streams[i].size) return dn_fail(loader, XXEMUL_STATUS_INVALID_IMAGE);
        }
    }
    for (i = 0; i < count; ++i) if (streams[i].size && streams[i].offset < position) return dn_fail(loader, XXEMUL_STATUS_INVALID_IMAGE);
    if (cli->nTablesOffset < (int64_t)meta || !dn_range(meta + metadata_size, (size_t)cli->nTablesOffset, (size_t)cli->nTablesSize) ||
        cli->nStringsOffset <= 0 || cli->nStringsSize < 1 || cli->nBlobOffset <= 0 || cli->nBlobSize < 1 ||
        data[(size_t)cli->nStringsOffset] || data[(size_t)cli->nBlobOffset] ||
        (cli->nUSSize && data[(size_t)cli->nUSOffset]) || (cli->nGuidSize % 16)) return dn_fail(loader, XXEMUL_STATUS_INVALID_IMAGE);
    if (cli->pRows[3] || cli->pRows[5] || cli->pRows[7] || cli->pRows[19] || cli->pRows[22])
        return dn_fail(loader, XXEMUL_STATUS_UNSUPPORTED_IMAGE); /* Unoptimized pointer tables. */
    program->entry_point_token = cli->nEntryPointToken;
    if (program->entry_point_token && ((program->entry_point_token >> 24) != 6 ||
        !(program->entry_point_token & 0xffffff) || (program->entry_point_token & 0xffffff) > cli->pRows[6]))
        return dn_fail(loader, XXEMUL_STATUS_UNSUPPORTED_IMAGE);
    return 1;
}

/* Table schemas validate every encoded heap/table reference, including rows
 * not otherwise needed by the interpreter. Coded indices use the exact tag
 * sets from ECMA-335 II.24.2.6; reserved tags never alias a real table. */
enum { DN_U2 = 1, DN_U4, DN_STRING, DN_GUID, DN_BLOB, DN_U8 };
#define DT(t) (0x100 + (t))
#define DC(c) (0x200 + (c))
#define DL(t) (0x300 + (t))
typedef struct { uint8_t count; uint16_t columns[9]; } dn_schema;
static const dn_schema dn_schemas[45] = {
    {5,{DN_U2,DN_STRING,DN_GUID,DN_GUID,DN_GUID}},
    {3,{DC(0),DN_STRING,DN_STRING}},
    {6,{DN_U4,DN_STRING,DN_STRING,DC(1),DL(4),DL(6)}},
    {1,{DT(4)}}, {3,{DN_U2,DN_STRING,DN_BLOB}}, {1,{DT(6)}},
    {6,{DN_U4,DN_U2,DN_U2,DN_STRING,DN_BLOB,DL(8)}}, {1,{DT(8)}},
    {3,{DN_U2,DN_U2,DN_STRING}}, {2,{DT(2),DC(1)}},
    {3,{DC(2),DN_STRING,DN_BLOB}}, {3,{DN_U2,DC(3),DN_BLOB}},
    {3,{DC(4),DC(5),DN_BLOB}}, {2,{DC(6),DN_BLOB}}, {3,{DN_U2,DC(7),DN_BLOB}},
    {3,{DN_U2,DN_U4,DT(2)}}, {2,{DN_U4,DT(4)}}, {1,{DN_BLOB}},
    {2,{DT(2),DL(20)}}, {1,{DT(20)}}, {3,{DN_U2,DN_STRING,DC(1)}},
    {2,{DT(2),DL(23)}}, {1,{DT(23)}}, {3,{DN_U2,DN_STRING,DN_BLOB}},
    {3,{DN_U2,DT(6),DC(8)}}, {3,{DT(2),DC(9),DC(9)}},
    {1,{DN_STRING}}, {1,{DN_BLOB}}, {4,{DN_U2,DC(10),DN_STRING,DT(26)}},
    {2,{DN_U4,DT(4)}}, {2,{DN_U4,DN_U4}}, {1,{DN_U4}},
    {9,{DN_U4,DN_U2,DN_U2,DN_U2,DN_U2,DN_U4,DN_BLOB,DN_STRING,DN_STRING}},
    {1,{DN_U4}}, {3,{DN_U4,DN_U4,DN_U4}},
    {9,{DN_U2,DN_U2,DN_U2,DN_U2,DN_U4,DN_BLOB,DN_STRING,DN_STRING,DN_BLOB}},
    {2,{DN_U4,DT(35)}}, {4,{DN_U4,DN_U4,DN_U4,DT(35)}},
    {3,{DN_U4,DN_STRING,DN_BLOB}}, {5,{DN_U4,DN_U4,DN_STRING,DN_STRING,DC(11)}},
    {4,{DN_U4,DN_U4,DN_STRING,DC(11)}}, {2,{DT(2),DT(2)}},
    {4,{DN_U2,DN_U2,DC(12),DN_STRING}}, {2,{DC(9),DN_BLOB}}, {2,{DT(42),DC(1)}}
};
static const uint8_t dn_coded_bits[13] = {2,2,3,2,5,3,1,2,1,1,1,2,1};
static const int8_t dn_coded_tables[13][32] = {
    {0,26,35,1,-1,-1,-1,-1}, {2,1,27,-1}, {2,1,26,6,27,-1,-1,-1},
    {4,8,23,-1},
    {6,4,1,2,8,9,10,0,14,23,20,17,26,27,32,35,38,39,40,42,44,43,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1},
    {-1,-1,6,10,-1,-1,-1,-1}, {4,8}, {2,6,32,-1}, {20,23}, {6,10}, {4,6}, {38,35,39,-1}, {2,6}
};
static unsigned dn_coded_width(const xx_dotnet_inspect_cli *cli, unsigned kind) {
    unsigned i, tags = 1u << dn_coded_bits[kind];
    for (i = 0; i < tags; ++i) {
        int table = dn_coded_tables[kind][i];
        if (table >= 0 && cli->pRows[table] >= (1u << (16 - dn_coded_bits[kind]))) return 4;
    }
    return 2;
}
static int dn_coded_token(dn_loader *loader, unsigned kind, uint32_t value, uint32_t *token) {
    unsigned bits = dn_coded_bits[kind], tag = value & ((1u << bits) - 1);
    uint32_t rid = value >> bits;
    int table = dn_coded_tables[kind][tag];
    *token = 0;
    if (!value) return 1;
    if (table < 0 || !rid || rid > loader->cli->pRows[table]) return dn_fail(loader, XXEMUL_STATUS_INVALID_IMAGE);
    *token = DN_TOKEN(table, rid); return 1;
}
static int dn_validate_tables(dn_loader *loader) {
    const xx_dotnet_inspect_cli *cli = loader->cli;
    size_t total = 0;
    unsigned table;
    for (table = 0; table < 64; ++table) {
        uint32_t rid;
        if (!cli->pRows[table]) continue;
        if (table >= 45 || cli->pRows[table] > DN_COUNT_LIMIT - total) return dn_fail(loader, XXEMUL_STATUS_INVALID_IMAGE);
        total += cli->pRows[table];
        for (rid = 1; rid <= cli->pRows[table]; ++rid) {
            const uint8_t *row = dn_row(loader, table, rid), *start = row;
            unsigned column;
            if (!row) return 0;
            for (column = 0; column < dn_schemas[table].count; ++column) {
                unsigned spec = dn_schemas[table].columns[column];
                uint32_t value = 0, token;
                if (spec == DN_U2) row += 2;
                else if (spec == DN_U4) row += 4;
                else if (spec == DN_U8) row += 8;
                else if (spec == DN_STRING) {
                    char *text;
                    value = dn_index(&row, cli->nStringIndexSize);
                    text = dn_heap_string(loader, value); if (!text) return 0; free(text);
                } else if (spec == DN_GUID) {
                    value = dn_index(&row, cli->nGuidIndexSize);
                    if (value > (uint64_t)cli->nGuidSize / 16) return dn_fail(loader, XXEMUL_STATUS_INVALID_IMAGE);
                } else if (spec == DN_BLOB) {
                    const uint8_t *blob; size_t size;
                    value = dn_index(&row, cli->nBlobIndexSize);
                    if (!dn_blob(loader, value, &blob, &size)) return 0;
                } else if ((spec & 0xf00) == 0x100 || (spec & 0xf00) == 0x300) {
                    unsigned target = spec & 0xff;
                    value = dn_index(&row, cli->pIndexSize[target]);
                    if (value > cli->pRows[target] + ((spec & 0xf00) == 0x300 ? 1u : 0u)) return dn_fail(loader, XXEMUL_STATUS_INVALID_IMAGE);
                    if ((spec & 0xf00) == 0x300 && !value) return dn_fail(loader, XXEMUL_STATUS_INVALID_IMAGE);
                } else if ((spec & 0xf00) == 0x200) {
                    unsigned kind = spec & 0xff;
                    value = dn_index(&row, (int)dn_coded_width(cli, kind));
                    if (!dn_coded_token(loader, kind, value, &token)) return 0;
                }
            }
            if ((size_t)(row - start) != (size_t)cli->pElementSize[table]) return dn_fail(loader, XXEMUL_STATUS_INVALID_IMAGE);
        }
    }
    return 1;
}
#undef DT
#undef DC
#undef DL

static void dn_type_free(xxemul_dotnet_type *type) {
    free(type->name); memset(type, 0, sizeof(*type));
}
static void dn_signature_free(xxemul_dotnet_signature *signature) {
    size_t i;
    dn_type_free(&signature->return_type);
    if (signature->parameters) for (i = 0; i < signature->parameter_count; ++i) dn_type_free(signature->parameters + i);
    free(signature->parameters); memset(signature, 0, sizeof(*signature));
}
static int dn_sig_byte(dn_signature_reader *reader, uint8_t *value) {
    if (!reader->budget || reader->position >= reader->size) return dn_fail(reader->loader, XXEMUL_STATUS_INVALID_IMAGE);
    --reader->budget; *value = reader->data[reader->position++]; return 1;
}
static int dn_sig_uint(dn_signature_reader *reader, uint32_t *value) {
    if (!reader->budget || !dn_compressed(reader->data, reader->size, &reader->position, value)) return dn_fail(reader->loader, XXEMUL_STATUS_INVALID_IMAGE);
    --reader->budget; return 1;
}
static int dn_sig_signed(dn_signature_reader *reader) {
    uint8_t first;
    uint32_t encoded, bits;
    int32_t value;
    if (!dn_sig_byte(reader, &first)) return 0;
    if (!(first & 0x80)) { encoded = first; bits = 7; }
    else if ((first & 0xc0) == 0x80) {
        uint8_t last;
        if (!dn_sig_byte(reader, &last)) return 0;
        encoded = ((uint32_t)(first & 0x3f) << 8) | last; bits = 14;
    } else if ((first & 0xe0) == 0xc0) {
        uint8_t a, b, c;
        if (!dn_sig_byte(reader, &a) || !dn_sig_byte(reader, &b) || !dn_sig_byte(reader, &c)) return 0;
        encoded = ((uint32_t)(first & 31) << 24) | ((uint32_t)a << 16) | ((uint32_t)b << 8) | c; bits = 29;
    } else return dn_fail(reader->loader, XXEMUL_STATUS_INVALID_IMAGE);
    value = (int32_t)(encoded >> 1);
    if (encoded & 1) value -= (int32_t)(UINT32_C(1) << (bits - 1));
    if ((bits == 14 && value >= -64 && value <= 63) || (bits == 29 && value >= -8192 && value <= 8191))
        return dn_fail(reader->loader, XXEMUL_STATUS_INVALID_IMAGE);
    return 1;
}
static const char *dn_resolve_type_name(dn_loader *loader, uint32_t token, unsigned depth);
static int dn_parse_type(dn_signature_reader *reader, xxemul_dotnet_type *type, unsigned depth, int allow_void);
static int dn_parse_signature(dn_signature_reader *reader, xxemul_dotnet_signature *signature, unsigned depth);

static const char *dn_primitive_name(uint8_t kind) {
    switch (kind) {
        case 0x01:return "System.Void"; case 0x02:return "System.Boolean"; case 0x03:return "System.Char";
        case 0x04:return "System.SByte"; case 0x05:return "System.Byte"; case 0x06:return "System.Int16";
        case 0x07:return "System.UInt16"; case 0x08:return "System.Int32"; case 0x09:return "System.UInt32";
        case 0x0a:return "System.Int64"; case 0x0b:return "System.UInt64"; case 0x0c:return "System.Single";
        case 0x0d:return "System.Double"; case 0x0e:return "System.String"; case 0x16:return "System.TypedReference";
        case 0x18:return "System.IntPtr"; case 0x19:return "System.UIntPtr"; case 0x1c:return "System.Object";
        default:return NULL;
    }
}

static int dn_parse_type(dn_signature_reader *reader, xxemul_dotnet_type *type, unsigned depth, int allow_void) {
    dn_loader *loader = reader->loader;
    uint8_t kind;
    uint32_t value, token;
    const char *primitive;
    xxemul_dotnet_type child;
    memset(type, 0, sizeof(*type)); memset(&child, 0, sizeof(child));
    if (depth > DN_DEPTH_LIMIT || !dn_sig_byte(reader, &kind)) return dn_fail(loader, XXEMUL_STATUS_INVALID_IMAGE);
    type->element_type = kind; type->supported = 1;
    primitive = dn_primitive_name(kind);
    if (primitive) {
        if (kind == 1 && !allow_void) return dn_fail(loader, XXEMUL_STATUS_INVALID_IMAGE);
        if (kind == 0x16) type->supported = 0;
        type->name = dn_copy(loader, primitive, strlen(primitive));
    } else if (kind == 0x11 || kind == 0x12) {
        const char *name;
        if (!dn_sig_uint(reader, &value) || !dn_coded_token(loader, 1, value, &token) || !token) return dn_fail(loader, XXEMUL_STATUS_INVALID_IMAGE);
        name = dn_resolve_type_name(loader, token, depth + 1);
        if (!name) return 0;
        type->token = token; type->supported = kind == 0x12;
        type->name = dn_copy(loader, name, strlen(name));
    } else if (kind == 0x0f || kind == 0x10 || kind == 0x1d || kind == 0x45 || kind == 0x1f || kind == 0x20) {
        const char *suffix = kind == 0x0f ? "*" : kind == 0x10 ? "&" : kind == 0x1d ? "[]" : "";
        if (kind == 0x1f || kind == 0x20) {
            if (!dn_sig_uint(reader, &value) || !dn_coded_token(loader, 1, value, &token) || !token) return dn_fail(loader, XXEMUL_STATUS_INVALID_IMAGE);
        }
        if (!dn_parse_type(reader, &child, depth + 1, kind == 0x0f ? 1 : kind == 0x1d || kind == 0x10 || kind == 0x45 ? 0 : allow_void)) return 0;
        type->token = child.token;
        type->array_element_type = child.element_type;
        type->supported = kind == 0x1d && child.supported && child.element_type != 1;
        type->name = dn_join(loader, child.name, suffix, "");
        dn_type_free(&child);
    } else if (kind == 0x13 || kind == 0x1e) {
        char name[32];
        if (!dn_sig_uint(reader, &value)) return 0;
        snprintf(name, sizeof(name), kind == 0x13 ? "!%u" : "!!%u", value);
        type->name = dn_copy(loader, name, strlen(name)); type->supported = 0;
    } else if (kind == 0x14) {
        uint32_t rank, count, i;
        char shape[35];
        if (!dn_parse_type(reader, &child, depth + 1, 0) || !dn_sig_uint(reader, &rank) || !rank || rank > 32 ||
            !dn_sig_uint(reader, &count) || count > rank) goto invalid_child;
        for (i = 0; i < count; ++i) if (!dn_sig_uint(reader, &value)) goto invalid_child;
        if (!dn_sig_uint(reader, &count) || count > rank) goto invalid_child;
        for (i = 0; i < count; ++i) if (!dn_sig_signed(reader)) goto invalid_child;
        shape[0] = '[';
        if (rank == 1) { shape[1] = '*'; shape[2] = ']'; shape[3] = 0; }
        else { for (i = 1; i < rank; ++i) shape[i] = ','; shape[rank] = ']'; shape[rank + 1] = 0; }
        type->name = dn_join(loader, child.name, shape, ""); type->supported = 0; dn_type_free(&child);
    } else if (kind == 0x15) {
        uint8_t base_kind;
        uint32_t count, i;
        const char *name;
        char *rendered;
        if (!dn_sig_byte(reader, &base_kind) || (base_kind != 0x11 && base_kind != 0x12) ||
            !dn_sig_uint(reader, &value) || !dn_coded_token(loader, 1, value, &token) || !token ||
            !dn_sig_uint(reader, &count) || !count || count > DN_ARGUMENT_LIMIT) return dn_fail(loader, XXEMUL_STATUS_INVALID_IMAGE);
        name = dn_resolve_type_name(loader, token, depth + 1); if (!name) return 0;
        rendered = dn_join(loader, name, "<", ""); if (!rendered) return 0;
        for (i = 0; i < count; ++i) {
            char *next;
            if (!dn_parse_type(reader, &child, depth + 1, 0)) { free(rendered); return 0; }
            next = dn_join(loader, rendered, i ? "," : "", child.name);
            free(rendered); dn_type_free(&child); rendered = next; if (!rendered) return 0;
        }
        type->name = dn_join(loader, rendered, ">", ""); free(rendered); type->token = token; type->supported = 0;
    } else if (kind == 0x1b) {
        xxemul_dotnet_signature signature;
        memset(&signature, 0, sizeof(signature));
        if (!dn_parse_signature(reader, &signature, depth + 1)) { dn_signature_free(&signature); return 0; }
        dn_signature_free(&signature);
        type->name = dn_copy(loader, "methodptr", 9); type->supported = 0;
    } else return dn_fail(loader, XXEMUL_STATUS_INVALID_IMAGE);
    return type->name != NULL;
invalid_child:
    dn_type_free(&child); return dn_fail(loader, XXEMUL_STATUS_INVALID_IMAGE);
}

static int dn_parse_signature(dn_signature_reader *reader, xxemul_dotnet_signature *signature, unsigned depth) {
    dn_loader *loader = reader->loader;
    uint8_t flags;
    uint32_t count, generic_count = 0;
    size_t i;
    if (depth > DN_DEPTH_LIMIT || !dn_sig_byte(reader, &flags)) return dn_fail(loader, XXEMUL_STATUS_INVALID_IMAGE);
    if ((flags & 0x80) || ((flags & 0x0f) > 5 && (flags & 0x0f) != 9 && (flags & 0x0f) != 11) ||
        ((flags & 0x40) && !(flags & 0x20))) return dn_fail(loader, XXEMUL_STATUS_INVALID_IMAGE);
    signature->has_this = (flags & 0x20) != 0; signature->explicit_this = (flags & 0x40) != 0;
    signature->generic = (flags & 0x10) != 0; signature->vararg = (flags & 0x0f) == 5;
    signature->supported = !(flags & 0x5f);
    if (signature->generic && (!dn_sig_uint(reader, &generic_count) || !generic_count || generic_count > DN_ARGUMENT_LIMIT)) return dn_fail(loader, XXEMUL_STATUS_INVALID_IMAGE);
    if (!dn_sig_uint(reader, &count) || count > DN_ARGUMENT_LIMIT) return dn_fail(loader, XXEMUL_STATUS_INVALID_IMAGE);
    signature->parameter_count = count;
    if (count) {
        signature->parameters = (xxemul_dotnet_type *)calloc(count, sizeof(*signature->parameters));
        if (!signature->parameters) return dn_fail(loader, XXEMUL_STATUS_OUT_OF_MEMORY);
    }
    if (!dn_parse_type(reader, &signature->return_type, depth + 1, 1)) return 0;
    if (!signature->return_type.supported) signature->supported = 0;
    for (i = 0; i < count; ++i) {
        if (reader->position < reader->size && reader->data[reader->position] == 0x41) {
            if (!signature->vararg) return dn_fail(loader, XXEMUL_STATUS_INVALID_IMAGE);
            ++reader->position; signature->supported = 0;
        }
        if (!dn_parse_type(reader, signature->parameters + i, depth + 1, 0)) return 0;
        if (!signature->parameters[i].supported) signature->supported = 0;
    }
    return 1;
}

static size_t dn_type_index(const xxemul_dotnet_program *program, uint32_t token) {
    uint32_t rid = token & 0xffffff;
    if (!rid) return SIZE_MAX;
    switch (token >> 24) {
        case 2:return rid <= program->type_def_count ? rid - 1 : SIZE_MAX;
        case 1:return rid <= program->type_ref_count ? program->type_def_count + rid - 1 : SIZE_MAX;
        case 27:return rid <= program->type_spec_count ? program->type_def_count + program->type_ref_count + rid - 1 : SIZE_MAX;
        default:return SIZE_MAX;
    }
}

static const char *dn_resolve_type_name(dn_loader *loader, uint32_t token, unsigned depth) {
    xxemul_dotnet_program *program = loader->program;
    size_t index = dn_type_index(program, token);
    xxemul_dotnet_class *type;
    if (index == SIZE_MAX || depth > DN_DEPTH_LIMIT) { dn_fail(loader, XXEMUL_STATUS_INVALID_IMAGE); return NULL; }
    type = program->types + index;
    if (type->name) return type->name;
    if (loader->type_visiting[index]) { dn_fail(loader, XXEMUL_STATUS_INVALID_IMAGE); return NULL; }
    loader->type_visiting[index] = 1;
    if ((token >> 24) == 27) {
        const uint8_t *row = dn_row(loader, 27, token & 0xffffff), *blob;
        size_t size;
        uint32_t blob_index;
        dn_signature_reader reader;
        xxemul_dotnet_type signature_type;
        memset(&signature_type, 0, sizeof(signature_type));
        if (!row) return NULL;
        blob_index = dn_index(&row, loader->cli->nBlobIndexSize);
        if (!dn_blob(loader, blob_index, &blob, &size) || !size || size > DN_SIGNATURE_LIMIT) return NULL;
        reader.loader = loader; reader.data = blob; reader.size = size; reader.position = 0; reader.budget = DN_SIGNATURE_LIMIT;
        if (!dn_parse_type(&reader, &signature_type, depth + 1, 0) || reader.position != size) {
            dn_type_free(&signature_type); dn_fail(loader, XXEMUL_STATUS_INVALID_IMAGE); return NULL;
        }
        type->name = signature_type.name; signature_type.name = NULL; dn_type_free(&signature_type);
    } else {
        unsigned table = token >> 24;
        const uint8_t *row = dn_row(loader, table, token & 0xffffff);
        uint32_t name_index, namespace_index;
        char *name, *ns;
        if (!row) return NULL;
        row += table == 2 ? 4 : loader->cli->nResolutionScopeSize;
        name_index = dn_index(&row, loader->cli->nStringIndexSize);
        namespace_index = dn_index(&row, loader->cli->nStringIndexSize);
        name = dn_heap_string(loader, name_index); ns = dn_heap_string(loader, namespace_index);
        if (!name || !ns || !*name) { free(name); free(ns); dn_fail(loader, XXEMUL_STATUS_INVALID_IMAGE); return NULL; }
        if (type->resolution_scope && (type->resolution_scope >> 24) == 1) {
            const char *outer = dn_resolve_type_name(loader, type->resolution_scope, depth + 1);
            if (outer) type->name = dn_join(loader, outer, "+", name);
        } else if (table == 2 && type->resolution_scope) {
            const char *outer = dn_resolve_type_name(loader, type->resolution_scope, depth + 1);
            if (outer) type->name = dn_join(loader, outer, "+", name);
        } else type->name = dn_join(loader, ns, *ns ? "." : "", name);
        free(name); free(ns);
    }
    loader->type_visiting[index] = 0;
    return type->name;
}

static int dn_load_types(dn_loader *loader) {
    xxemul_dotnet_program *program = loader->program;
    const xx_dotnet_inspect_cli *cli = loader->cli;
    uint32_t rid;
    size_t i;
    program->type_def_count = cli->pRows[2]; program->type_ref_count = cli->pRows[1]; program->type_spec_count = cli->pRows[27];
    program->type_count = program->type_def_count + program->type_ref_count + program->type_spec_count;
    if (!program->type_def_count || program->type_count > DN_COUNT_LIMIT) return dn_fail(loader, XXEMUL_STATUS_INVALID_IMAGE);
    program->types = (xxemul_dotnet_class *)calloc(program->type_count, sizeof(*program->types));
    loader->type_visiting = (uint8_t *)calloc(program->type_count, 1);
    if (!program->types || !loader->type_visiting) return dn_fail(loader, XXEMUL_STATUS_OUT_OF_MEMORY);
    for (rid = 1; rid <= program->type_def_count; ++rid) {
        xxemul_dotnet_class *type = program->types + rid - 1;
        const uint8_t *row = dn_row(loader, 2, rid);
        uint32_t extends;
        if (!row) return 0;
        type->token = DN_TOKEN(2, rid); type->flags = xxemul_dotnet_u32(row); row += 4 + 2 * cli->nStringIndexSize;
        extends = dn_index(&row, cli->nTypeDefOrRefSize);
        if (!dn_coded_token(loader, 1, extends, &type->extends_token)) return 0;
        type->field_begin = dn_index(&row, cli->nFieldListSize); type->method_begin = dn_index(&row, cli->nMethodListSize);
        if (rid > 1) {
            xxemul_dotnet_class *previous = type - 1;
            if (type->field_begin < previous->field_begin || type->method_begin < previous->method_begin) return dn_fail(loader, XXEMUL_STATUS_INVALID_IMAGE);
            previous->field_end = type->field_begin; previous->method_end = type->method_begin;
        } else if (type->field_begin != 1 || type->method_begin != 1) return dn_fail(loader, XXEMUL_STATUS_INVALID_IMAGE);
    }
    program->types[program->type_def_count - 1].field_end = cli->pRows[4] + 1;
    program->types[program->type_def_count - 1].method_end = cli->pRows[6] + 1;
    for (rid = 1; rid <= program->type_ref_count; ++rid) {
        xxemul_dotnet_class *type = program->types + program->type_def_count + rid - 1;
        const uint8_t *row = dn_row(loader, 1, rid);
        if (!row) return 0;
        type->token = DN_TOKEN(1, rid);
        if (!dn_coded_token(loader, 0, dn_index(&row, cli->nResolutionScopeSize), &type->resolution_scope)) return 0;
    }
    for (rid = 1; rid <= program->type_spec_count; ++rid) program->types[program->type_def_count + program->type_ref_count + rid - 1].token = DN_TOKEN(27, rid);
    for (rid = 1; rid <= cli->pRows[41]; ++rid) {
        const uint8_t *row = dn_row(loader, 41, rid);
        uint32_t nested, outer;
        if (!row) return 0;
        nested = dn_index(&row, cli->pIndexSize[2]); outer = dn_index(&row, cli->pIndexSize[2]);
        if (!nested || !outer || nested == outer || program->types[nested - 1].resolution_scope) return dn_fail(loader, XXEMUL_STATUS_INVALID_IMAGE);
        program->types[nested - 1].resolution_scope = DN_TOKEN(2, outer);
    }
    for (rid = 1; rid <= cli->pRows[42]; ++rid) {
        const uint8_t *row = dn_row(loader, 42, rid);
        uint32_t owner;
        if (!row) return 0;
        row += 4;
        if (!dn_coded_token(loader, 12, dn_index(&row, (int)dn_coded_width(cli, 12)), &owner) || !owner) return dn_fail(loader, XXEMUL_STATUS_INVALID_IMAGE);
        if ((owner >> 24) == 2) program->types[(owner & 0xffffff) - 1].is_generic = 1;
    }
    for (rid = 1; rid <= cli->pRows[25]; ++rid) {
        const uint8_t *row = dn_row(loader, 25, rid);
        uint32_t owner, body, declaration;
        if (!row) return 0;
        owner = dn_index(&row, cli->pIndexSize[2]);
        if (!owner || !dn_coded_token(loader, 9, dn_index(&row, cli->nMethodDefOrRefSize), &body) || !body ||
            !dn_coded_token(loader, 9, dn_index(&row, cli->nMethodDefOrRefSize), &declaration) || !declaration)
            return dn_fail(loader, XXEMUL_STATUS_INVALID_IMAGE);
        program->types[owner - 1].has_method_impl = 1;
    }
    for (i = 0; i < program->type_count; ++i) if (!dn_resolve_type_name(loader, program->types[i].token, 0)) return 0;
    /* A local inheritance cycle is invalid even when no method uses it.
     * Three colors make the walk linear for long shared base chains. */
    memset(loader->type_visiting, 0, program->type_count);
    for (i = 0; i < program->type_def_count; ++i) {
        size_t current = i;
        while (current != SIZE_MAX && !loader->type_visiting[current]) {
            uint32_t parent = program->types[current].extends_token;
            loader->type_visiting[current] = 1;
            current = (parent >> 24) == 2 ? (parent & 0xffffff) - 1 : SIZE_MAX;
        }
        if (current != SIZE_MAX && loader->type_visiting[current] == 1) return dn_fail(loader, XXEMUL_STATUS_INVALID_IMAGE);
        current = i;
        while (current != SIZE_MAX && loader->type_visiting[current] == 1) {
            uint32_t parent = program->types[current].extends_token;
            loader->type_visiting[current] = 2;
            current = (parent >> 24) == 2 ? (parent & 0xffffff) - 1 : SIZE_MAX;
        }
    }
    return 1;
}

static int dn_load_fields(dn_loader *loader) {
    xxemul_dotnet_program *program = loader->program;
    const xx_dotnet_inspect_cli *cli = loader->cli;
    size_t owner = 0;
    uint32_t rid;
    program->field_count = cli->pRows[4];
    if (!program->field_count) return 1;
    program->fields = (xxemul_dotnet_field *)calloc(program->field_count, sizeof(*program->fields));
    if (!program->fields) return dn_fail(loader, XXEMUL_STATUS_OUT_OF_MEMORY);
    for (rid = 1; rid <= program->field_count; ++rid) {
        xxemul_dotnet_field *field = program->fields + rid - 1;
        const uint8_t *row = dn_row(loader, 4, rid), *blob;
        uint32_t name_index, blob_index;
        size_t size;
        dn_signature_reader reader;
        if (!row) return 0;
        while (owner + 1 < program->type_def_count && rid >= program->types[owner].field_end) ++owner;
        field->token = DN_TOKEN(4, rid); field->owner_token = program->types[owner].token;
        field->flags = xxemul_dotnet_u16(row); row += 2;
        name_index = dn_index(&row, cli->nStringIndexSize); blob_index = dn_index(&row, cli->nBlobIndexSize);
        field->name = dn_heap_string(loader, name_index);
        if (!field->name || !dn_blob(loader, blob_index, &blob, &size) || size < 2 || size > DN_SIGNATURE_LIMIT || blob[0] != 6) return dn_fail(loader, XXEMUL_STATUS_INVALID_IMAGE);
        reader.loader = loader; reader.data = blob; reader.size = size; reader.position = 1; reader.budget = DN_SIGNATURE_LIMIT;
        if (!dn_parse_type(&reader, &field->type, 0, 0) || reader.position != size) return dn_fail(loader, XXEMUL_STATUS_INVALID_IMAGE);
    }
    return 1;
}

static int dn_render_method(dn_loader *loader, xxemul_dotnet_method *method) {
    char *rendered = dn_copy(loader, "(", 1), *next, *selector;
    size_t i;
    if (!rendered) return 0;
    for (i = 0; i < method->signature.parameter_count; ++i) {
        next = dn_join(loader, rendered, i ? "," : "", method->signature.parameters[i].name);
        free(rendered); rendered = next; if (!rendered) return 0;
    }
    next = dn_join(loader, rendered, ")", method->signature.return_type.name); free(rendered);
    if (!next) return 0;
    method->info.signature = next;
    selector = dn_join(loader, method->info.type_name, "::", method->info.name); if (!selector) return 0;
    next = dn_join(loader, selector, "", method->info.signature); free(selector);
    method->info.selector = next; return next != NULL;
}

static int dn_load_local_signature(dn_loader *loader, xxemul_dotnet_method *method, uint32_t token) {
    const uint8_t *row, *blob;
    uint32_t count, index;
    size_t size, i;
    dn_signature_reader reader;
    if (!token) return 1;
    if ((token >> 24) != 17 || !(token & 0xffffff)) return dn_fail(loader, XXEMUL_STATUS_INVALID_IMAGE);
    row = dn_row(loader, 17, token & 0xffffff); if (!row) return 0;
    index = dn_index(&row, loader->cli->nBlobIndexSize);
    if (!dn_blob(loader, index, &blob, &size) || size < 2 || size > DN_SIGNATURE_LIMIT || blob[0] != 7) return dn_fail(loader, XXEMUL_STATUS_INVALID_IMAGE);
    reader.loader = loader; reader.data = blob; reader.size = size; reader.position = 1; reader.budget = DN_SIGNATURE_LIMIT;
    if (!dn_sig_uint(&reader, &count) || count > DN_ARGUMENT_LIMIT) return dn_fail(loader, XXEMUL_STATUS_INVALID_IMAGE);
    method->local_count = count;
    if (count) {
        method->locals = (xxemul_dotnet_type *)calloc(count, sizeof(*method->locals));
        if (!method->locals) return dn_fail(loader, XXEMUL_STATUS_OUT_OF_MEMORY);
    }
    for (i = 0; i < count; ++i) {
        if (!dn_parse_type(&reader, method->locals + i, 0, 0)) return 0;
        if (!method->locals[i].supported) method->info.is_executable = 0;
    }
    if (reader.position != size) return dn_fail(loader, XXEMUL_STATUS_INVALID_IMAGE);
    return 1;
}

static int dn_load_body(dn_loader *loader, xxemul_dotnet_method *method) {
    xx_dotnet_method_body body;
    if (!method->info.rva) return 1;
    /* Native/runtime-provided bodies are retained as inventory, never IL. */
    if ((method->info.impl_flags & 3) != 0 || (method->info.impl_flags & 4)) return 1;
    if (!xx_dotnet_inspect_method_body(&loader->inspection, method->info.rva, &body) ||
        body.code_size > 16u * 1024u * 1024u || body.code_offset < 0 || (uint64_t)body.code_offset > SIZE_MAX ||
        !dn_range(loader->program->size, (size_t)body.code_offset, body.code_size))
        return dn_fail(loader, XXEMUL_STATUS_INVALID_IMAGE);
    method->code = loader->program->data + (size_t)body.code_offset;
    method->info.code_size = body.code_size; method->info.max_stack = body.max_stack;
    method->info.init_locals = body.init_locals;
    method->info.has_exception_handlers = body.has_exception_handlers;
    method->info.is_executable = method->signature.supported && !body.has_exception_handlers &&
        !(method->info.flags & (0x400u | 0x2000u));
    if (!dn_load_local_signature(loader, method, body.local_signature_token)) return 0;
    if ((method->owner_token >> 24) == 2 && loader->program->types[(method->owner_token & 0xffffff) - 1].is_generic)
        method->info.is_executable = 0;
    return 1;
}

static int dn_load_methods(dn_loader *loader) {
    xxemul_dotnet_program *program = loader->program;
    const xx_dotnet_inspect_cli *cli = loader->cli;
    size_t owner = 0, count;
    uint32_t rid, previous_param = 1;
    program->method_def_count = cli->pRows[6]; program->memberref_count = cli->pRows[10];
    count = program->method_def_count + program->memberref_count;
    if (count > DN_COUNT_LIMIT) return dn_fail(loader, XXEMUL_STATUS_INVALID_IMAGE);
    program->method_count = count;
    if (count) {
        program->methods = (xxemul_dotnet_method *)calloc(count, sizeof(*program->methods));
        if (!program->methods) return dn_fail(loader, XXEMUL_STATUS_OUT_OF_MEMORY);
    }
    if (program->memberref_count) {
        program->memberref_map = (size_t *)malloc(program->memberref_count * sizeof(*program->memberref_map));
        if (!program->memberref_map) return dn_fail(loader, XXEMUL_STATUS_OUT_OF_MEMORY);
        for (count = 0; count < program->memberref_count; ++count) program->memberref_map[count] = SIZE_MAX;
    }
    count = 0;
    for (rid = 1; rid <= program->method_def_count + program->memberref_count; ++rid) {
        int defined = rid <= program->method_def_count;
        uint32_t table_rid = defined ? rid : rid - (uint32_t)program->method_def_count;
        unsigned table = defined ? 6 : 10;
        const uint8_t *row = dn_row(loader, table, table_rid), *blob;
        uint32_t name_index, blob_index, parent = 0;
        size_t size;
        dn_signature_reader reader;
        xxemul_dotnet_method *method = program->methods + count;
        if (!row) return 0;
        method->info.token = DN_TOKEN(table, table_rid); method->info.is_defined = defined;
        if (defined) {
            uint32_t param;
            while (owner + 1 < program->type_def_count && table_rid >= program->types[owner].method_end) ++owner;
            method->owner_token = program->types[owner].token;
            method->info.type_name = program->types[owner].name;
            method->info.rva = xxemul_dotnet_u32(row); method->info.impl_flags = xxemul_dotnet_u16(row + 4);
            method->info.flags = xxemul_dotnet_u16(row + 6); row += 8;
            name_index = dn_index(&row, cli->nStringIndexSize); blob_index = dn_index(&row, cli->nBlobIndexSize);
            param = dn_index(&row, cli->pIndexSize[8]);
            if (param < previous_param || param > cli->pRows[8] + 1) return dn_fail(loader, XXEMUL_STATUS_INVALID_IMAGE);
            previous_param = param;
        } else {
            if (!dn_coded_token(loader, 2, dn_index(&row, cli->nMemberRefParentSize), &parent) || !parent) return dn_fail(loader, XXEMUL_STATUS_INVALID_IMAGE);
            name_index = dn_index(&row, cli->nStringIndexSize); blob_index = dn_index(&row, cli->nBlobIndexSize);
            if ((parent >> 24) == 6) {
                method->owner_token = program->methods[(parent & 0xffffff) - 1].owner_token;
                method->info.type_name = program->methods[(parent & 0xffffff) - 1].info.type_name;
            } else if ((parent >> 24) == 26) method->info.type_name = "<external-module>";
            else {
                size_t type_index = dn_type_index(program, parent);
                if (type_index == SIZE_MAX) return dn_fail(loader, XXEMUL_STATUS_INVALID_IMAGE);
                method->owner_token = parent; method->info.type_name = program->types[type_index].name;
                method->local_reference = (parent >> 24) == 2 ||
                    ((parent >> 24) == 1 && (program->types[type_index].resolution_scope >> 24) == 0);
            }
        }
        if (!dn_blob(loader, blob_index, &blob, &size) || !size || size > DN_SIGNATURE_LIMIT) return dn_fail(loader, XXEMUL_STATUS_INVALID_IMAGE);
        /* MemberRef also represents fields; those are not callable methods. */
        if (!defined && blob[0] == 6) {
            xxemul_dotnet_type field_type;
            memset(&field_type, 0, sizeof(field_type));
            reader.loader = loader; reader.data = blob; reader.size = size; reader.position = 1; reader.budget = DN_SIGNATURE_LIMIT;
            if (!dn_parse_type(&reader, &field_type, 0, 0) || reader.position != size) {
                dn_type_free(&field_type); return dn_fail(loader, XXEMUL_STATUS_INVALID_IMAGE);
            }
            dn_type_free(&field_type); memset(method, 0, sizeof(*method)); continue;
        }
        method->info.name = dn_heap_string(loader, name_index);
        if (!method->info.name || !*method->info.name) return dn_fail(loader, XXEMUL_STATUS_INVALID_IMAGE);
        reader.loader = loader; reader.data = blob; reader.size = size; reader.position = 0; reader.budget = DN_SIGNATURE_LIMIT;
        if (!dn_parse_signature(&reader, &method->signature, 0) || reader.position != size) return dn_fail(loader, XXEMUL_STATUS_INVALID_IMAGE);
        method->info.has_this = method->signature.has_this;
        if (defined && ((method->info.flags & 0x10) != 0) == method->signature.has_this) return dn_fail(loader, XXEMUL_STATUS_INVALID_IMAGE);
        if (!dn_render_method(loader, method)) return 0;
        if (defined && !dn_load_body(loader, method)) return 0;
        if (!defined) program->memberref_map[table_rid - 1] = count;
        ++count;
    }
    program->method_count = count;
    return 1;
}

static int dn_load_user_strings(dn_loader *loader) {
    xxemul_dotnet_program *program = loader->program;
    const xx_dotnet_inspect_cli *cli = loader->cli;
    const uint8_t *heap;
    size_t position = 1, count = 0, total = 0;
    if (!cli->nUSSize) return 1;
    if (cli->nUSSize < 0 || (uint64_t)cli->nUSSize > DN_METADATA_LIMIT || cli->nUSOffset < 0) return dn_fail(loader, XXEMUL_STATUS_INVALID_IMAGE);
    heap = program->data + (size_t)cli->nUSOffset;
    while (position < (size_t)cli->nUSSize) {
        uint32_t length;
        if (!dn_compressed(heap, (size_t)cli->nUSSize, &position, &length) || !dn_range((size_t)cli->nUSSize, position, length))
            return dn_fail(loader, XXEMUL_STATUS_INVALID_IMAGE);
        if (length && (!(length & 1u) || length > 0x100000 || heap[position + length - 1] > 1)) return dn_fail(loader, XXEMUL_STATUS_INVALID_IMAGE);
        if (length && ++count > 100000) return dn_fail(loader, XXEMUL_STATUS_INVALID_IMAGE);
        position += length;
    }
    if (!count) return 1;
    program->user_strings = (xxemul_dotnet_string *)calloc(count, sizeof(*program->user_strings));
    if (!program->user_strings) return dn_fail(loader, XXEMUL_STATUS_OUT_OF_MEMORY);
    position = 1;
    while (position < (size_t)cli->nUSSize) {
        uint32_t length, index = (uint32_t)position;
        size_t units, i, used = 0;
        xxemul_dotnet_string *string;
        if (!dn_compressed(heap, (size_t)cli->nUSSize, &position, &length)) return dn_fail(loader, XXEMUL_STATUS_INVALID_IMAGE);
        if (!length) continue;
        units = (length - 1) / 2;
        string = program->user_strings + program->user_string_count++;
        string->offset = index; string->text = (char *)malloc(units * 3 + 1);
        if (!string->text) return dn_fail(loader, XXEMUL_STATUS_OUT_OF_MEMORY);
        for (i = 0; i < units; ++i) {
            uint32_t point = xxemul_dotnet_u16(heap + position + i * 2);
            if (point >= 0xd800 && point <= 0xdbff && i + 1 < units) {
                uint32_t low = xxemul_dotnet_u16(heap + position + (i + 1) * 2);
                if (low >= 0xdc00 && low <= 0xdfff) { point = 0x10000 + ((point - 0xd800) << 10) + low - 0xdc00; ++i; }
            }
            /* Unpaired UTF-16 units are preserved in the UTF-8 surrogate
             * extension, avoiding collisions between distinct CLR strings. */
            if (point < 0x80) string->text[used++] = (char)point;
            else if (point < 0x800) {
                string->text[used++] = (char)(0xc0 | (point >> 6)); string->text[used++] = (char)(0x80 | (point & 63));
            } else if (point < 0x10000) {
                string->text[used++] = (char)(0xe0 | (point >> 12)); string->text[used++] = (char)(0x80 | ((point >> 6) & 63));
                string->text[used++] = (char)(0x80 | (point & 63));
            } else {
                string->text[used++] = (char)(0xf0 | (point >> 18)); string->text[used++] = (char)(0x80 | ((point >> 12) & 63));
                string->text[used++] = (char)(0x80 | ((point >> 6) & 63)); string->text[used++] = (char)(0x80 | (point & 63));
            }
        }
        string->text[used] = 0; string->size = used;
        if (used > DN_METADATA_LIMIT - total || !dn_work(loader, used)) return dn_fail(loader, XXEMUL_STATUS_INVALID_IMAGE);
        total += used; position += length;
    }
    return 1;
}

void xxemul_dotnet_destroy(xxemul_dotnet_program *program) {
    size_t i, j;
    if (!program) return;
    if (program->methods) for (i = 0; i < program->method_count; ++i) {
        xxemul_dotnet_method *method = program->methods + i;
        free((char *)method->info.name); free((char *)method->info.signature); free((char *)method->info.selector);
        dn_signature_free(&method->signature);
        if (method->locals) for (j = 0; j < method->local_count; ++j) dn_type_free(method->locals + j);
        free(method->locals);
    }
    if (program->types) for (i = 0; i < program->type_count; ++i) free(program->types[i].name);
    if (program->fields) for (i = 0; i < program->field_count; ++i) { free(program->fields[i].name); dn_type_free(&program->fields[i].type); }
    if (program->user_strings) for (i = 0; i < program->user_string_count; ++i) free(program->user_strings[i].text);
    free(program->methods); free(program->memberref_map); free(program->types); free(program->fields); free(program->user_strings);
    free(program->assembly_name); free(program->data); free(program);
}

xxemul_dotnet_program *xxemul_dotnet_create(const void *data, size_t size, xxemul_status *status) {
    dn_loader loader;
    xxemul_dotnet_program *program = NULL;
    xx_io_device *device = NULL;
    char *assembly_name = NULL;
    if (status) *status = XXEMUL_STATUS_INVALID_ARGUMENT;
    if (!data || !size) return NULL;
    memset(&loader, 0, sizeof(loader)); loader.status = XXEMUL_STATUS_OK; loader.work = DN_WORK_LIMIT;
    if (size > DN_IMAGE_LIMIT || size < 64) { loader.status = XXEMUL_STATUS_INVALID_IMAGE; goto done; }
    program = (xxemul_dotnet_program *)calloc(1, sizeof(*program));
    if (!program) { loader.status = XXEMUL_STATUS_OUT_OF_MEMORY; goto done; }
    loader.program = program; loader.cli = &loader.inspection.cli;
    program->size = size; program->data = (uint8_t *)malloc(size);
    if (!program->data) { loader.status = XXEMUL_STATUS_OUT_OF_MEMORY; goto done; }
    memcpy(program->data, data, size);
    device = xx_io_mem_open_ro(program->data, size);
    if (!device) { loader.status = XXEMUL_STATUS_OUT_OF_MEMORY; goto done; }
    if (!xx_dotnet_inspect_analyze_from_device(&loader.inspection, device, 0, NULL)) { loader.status = XXEMUL_STATUS_INVALID_IMAGE; goto done; }
    if (!dn_validate_image(&loader) || !dn_validate_tables(&loader) || !dn_load_types(&loader) || !dn_load_fields(&loader) ||
        !dn_load_methods(&loader) || !dn_load_user_strings(&loader)) {
        if (loader.status == XXEMUL_STATUS_OK) loader.status = XXEMUL_STATUS_INVALID_IMAGE;
        goto done;
    }
    assembly_name = xx_dotnet_inspect_net_assembly_name(&loader.inspection);
    if (!assembly_name) { loader.status = XXEMUL_STATUS_OUT_OF_MEMORY; goto done; }
    program->assembly_name = dn_copy(&loader, assembly_name, strlen(assembly_name));
    if (!program->assembly_name) goto done;
done:
    xx_mem_free(assembly_name);
    free(loader.type_visiting);
    xx_dotnet_inspect_free(&loader.inspection);
    if (device) xx_io_close(device);
    if (loader.status != XXEMUL_STATUS_OK) { xxemul_dotnet_destroy(program); program = NULL; }
    if (status) *status = loader.status;
    return program;
}

xxemul_dotnet_program *xxemul_dotnet_create_file(const char *path, xxemul_status *status) {
    xx_io_device *file;
    int64_t length;
    uint8_t *data;
    xxemul_dotnet_program *program;
    if (status) *status = XXEMUL_STATUS_INVALID_ARGUMENT;
    if (!path) return NULL;
    file = xx_io_file_open(path, "rb");
    if (!file) { if (status) *status = XXEMUL_STATUS_IO_ERROR; return NULL; }
    length = xx_io_total_size(file);
    if (length < 0 || (uint64_t)length > DN_IMAGE_LIMIT) {
        xx_io_close(file); if (status) *status = XXEMUL_STATUS_IO_ERROR; return NULL;
    }
    data = (uint8_t *)malloc(length ? (size_t)length : 1);
    if (!data) { xx_io_close(file); if (status) *status = XXEMUL_STATUS_OUT_OF_MEMORY; return NULL; }
    if (!xx_io_read_at(file, 0, data, (size_t)length)) {
        free(data); xx_io_close(file); if (status) *status = XXEMUL_STATUS_IO_ERROR; return NULL;
    }
    xx_io_close(file); program = xxemul_dotnet_create(data, (size_t)length, status); free(data); return program;
}

const char *xxemul_dotnet_assembly_name(const xxemul_dotnet_program *program) { return program ? program->assembly_name : NULL; }
uint32_t xxemul_dotnet_entry_point_token(const xxemul_dotnet_program *program) { return program ? program->entry_point_token : 0; }
size_t xxemul_dotnet_entry_point(const xxemul_dotnet_program *program) { return xxemul_dotnet_resolve_token(program, xxemul_dotnet_entry_point_token(program)); }
size_t xxemul_dotnet_method_count(const xxemul_dotnet_program *program) { return program ? program->method_count : 0; }
const xxemul_dotnet_method_info *xxemul_dotnet_method_info_at(const xxemul_dotnet_program *program, size_t index) {
    return program && index < program->method_count ? &program->methods[index].info : NULL;
}
size_t xxemul_dotnet_find_method(const xxemul_dotnet_program *program, const char *selector) {
    size_t i, fallback = SIZE_MAX;
    if (!program || !selector) return SIZE_MAX;
    for (i = 0; i < program->method_count; ++i) if (!strcmp(program->methods[i].info.selector, selector)) {
        if (program->methods[i].info.is_defined) return i;
        if (fallback == SIZE_MAX) fallback = i;
    }
    return fallback;
}
size_t xxemul_dotnet_resolve_token(const xxemul_dotnet_program *program, uint32_t token) {
    uint32_t rid = token & 0xffffff;
    size_t index;
    if (!program || !rid) return SIZE_MAX;
    if ((token >> 24) == 6) return rid <= program->method_def_count ? rid - 1 : SIZE_MAX;
    if ((token >> 24) != 10 || rid > program->memberref_count) return SIZE_MAX;
    index = program->memberref_map[rid - 1];
    if (index != SIZE_MAX && program->methods[index].local_reference) {
        size_t local = xxemul_dotnet_find_method(program, program->methods[index].info.selector);
        if (local != SIZE_MAX && program->methods[local].info.is_defined) return local;
    }
    return index;
}
const char *xxemul_dotnet_type_name(const xxemul_dotnet_program *program, uint32_t token) {
    size_t index;
    if (!program) return NULL;
    index = dn_type_index(program, token);
    return index != SIZE_MAX ? program->types[index].name : NULL;
}
const char *xxemul_dotnet_user_string(const xxemul_dotnet_program *program, uint32_t token, size_t *size) {
    size_t low = 0, high;
    uint32_t offset = token & 0xffffff;
    if (size) *size = 0;
    if (!program || (token >> 24) != 0x70 || !offset) return NULL;
    high = program->user_string_count;
    while (low < high) {
        size_t middle = low + (high - low) / 2;
        if (program->user_strings[middle].offset < offset) low = middle + 1; else high = middle;
    }
    if (low >= program->user_string_count || program->user_strings[low].offset != offset) return NULL;
    if (size) *size = program->user_strings[low].size;
    return program->user_strings[low].text;
}

static size_t dn_disassembly_resolver(void *context, const xxbyte_instruction *instruction,
    uint32_t operand_index, char *buffer, size_t buffer_size) {
    const xxemul_dotnet_program *program = (const xxemul_dotnet_program *)context;
    const xxbyte_operand *operand;
    uint32_t token;
    const char *text = NULL;
    size_t index;
    if (operand_index >= instruction->operand_count || !buffer_size) return 0;
    operand = instruction->operands + operand_index;
    if (operand->type != XXBYTE_OPERAND_TOKEN) return 0;
    token = (uint32_t)operand->value;
    if ((token >> 24) == 0x70) {
        size_t size;
        text = xxemul_dotnet_user_string(program, token, &size);
        if (text) { int length = snprintf(buffer, buffer_size, "\"%.*s\"", (int)(size > 256 ? 256 : size), text); return length > 0 ? (size_t)length : 0; }
    } else if ((index = xxemul_dotnet_resolve_token(program, token)) != SIZE_MAX) text = program->methods[index].info.selector;
    else if ((token >> 24) == 4 && (token & 0xffffff) && (token & 0xffffff) <= program->field_count) text = program->fields[(token & 0xffffff) - 1].name;
    else text = xxemul_dotnet_type_name(program, token);
    if (text) { int length = snprintf(buffer, buffer_size, "%s", text); return length > 0 ? (size_t)length : 0; }
    return 0;
}
xxemul_status xxemul_dotnet_disassemble(const xxemul_dotnet_program *program, size_t method_index,
    uint32_t byte_offset, char *text, size_t text_size, uint32_t *instruction_size) {
    const xxemul_dotnet_method *method;
    xxbyte_instruction instruction;
    if (instruction_size) *instruction_size = 0;
    if (text && text_size) text[0] = 0;
    if (!program || method_index >= program->method_count || !text || !text_size || !instruction_size) return XXEMUL_STATUS_INVALID_ARGUMENT;
    method = program->methods + method_index;
    if (!method->code || byte_offset >= method->info.code_size) return XXEMUL_STATUS_ADDRESS_FAULT;
    if (xxbyte_decode(XXBYTE_FAMILY_DOTNET, XXBYTE_DOTNET_MODE_DEFAULT, method->code + byte_offset,
        method->info.code_size - byte_offset, byte_offset, &instruction) != XXBYTE_STATUS_OK) return XXEMUL_STATUS_DECODE_ERROR;
    if (!xxbyte_format_ex(&instruction, XXBYTE_FORMAT_DEFAULT, dn_disassembly_resolver, (void *)program, text, text_size)) return XXEMUL_STATUS_DECODE_ERROR;
    *instruction_size = instruction.size; return XXEMUL_STATUS_OK;
}
