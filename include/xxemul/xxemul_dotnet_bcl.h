/* Copyright (c) 2026 hors<horsicq@gmail.com>
 * SPDX-License-Identifier: MIT */
#ifndef XXEMUL_DOTNET_BCL_H
#define XXEMUL_DOTNET_BCL_H

#include "xxemul_dotnet_runtime.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct xxemul_dotnet_bcl_host xxemul_dotnet_bcl_host;
typedef void (*xxemul_dotnet_bcl_output_callback)(void *context, unsigned stream, const char *data, size_t size);

/** Explicit compatibility implementation of SharpZipLib's public decompression
 * stream interface. It uses xxfclib's checked zlib decoder; it never extracts a
 * managed application or skips its managed loader. */
#define XXEMUL_DOTNET_BCL_SHARPZIP_STREAMS UINT32_C(1)

typedef struct xxemul_dotnet_bcl_config {
    uint64_t max_instructions;    /* Default 1,000,000, including child VMs. */
    size_t max_heap_bytes;        /* Default 16 MiB per managed VM. */
    size_t max_native_bytes;      /* Default 64 MiB of service objects/buffers. */
    size_t max_image_bytes;       /* Default 16 MiB per PE or stream buffer. */
    size_t max_output_bytes;      /* Default 4 MiB per entry invocation. */
    size_t max_loaded_assemblies; /* Default 16, including the root. */
    uint32_t flags;
    const char *logical_entry_path; /* Default /app/program.exe, copied. */
    /** Reserved for an explicitly sandboxed read-only filesystem provider.
     * This version rejects non-NULL roots. The virtual directory exposes only
     * registered assembly images; no arbitrary host file access is allowed. */
    const char *filesystem_root;
    xxemul_dotnet_bcl_output_callback output_callback;
    void *output_context;
    xxemul_dotnet_trace_callback trace_callback;
    void *trace_context;
} xxemul_dotnet_bcl_config;

typedef struct xxemul_dotnet_bcl_statistics {
    uint64_t service_calls, reflected_invocations, stream_reads, stream_writes;
    uint64_t sha256_operations, assemblies_loaded, managed_instructions;
    uint64_t sharpzip_streams;
} xxemul_dotnet_bcl_statistics;

XXEMUL_API xxemul_dotnet_bcl_host *xxemul_dotnet_bcl_host_create(const xxemul_dotnet_bcl_config *config, xxemul_status *status);
XXEMUL_API void xxemul_dotnet_bcl_host_destroy(xxemul_dotnet_bcl_host *host);
/** Execute the actual CLI entry with a real System.String[] vector. The
 * borrowed root program must outlive host. Assembly.Load creates bounded
 * parsed child programs and reflection invokes their real CIL. Unknown
 * services fail explicitly. Reentrant top-level execute calls are rejected. */
XXEMUL_API xxemul_status xxemul_dotnet_bcl_execute(xxemul_dotnet_bcl_host *host, const xxemul_dotnet_program *program, int argc, const char *const *argv,
                                                   xxemul_dotnet_result *result);
XXEMUL_API const char *xxemul_dotnet_bcl_diagnostic(const xxemul_dotnet_bcl_host *host);
XXEMUL_API const xxemul_dotnet_bcl_statistics *xxemul_dotnet_bcl_get_statistics(const xxemul_dotnet_bcl_host *host);

#ifdef __cplusplus
}
#endif
#endif
