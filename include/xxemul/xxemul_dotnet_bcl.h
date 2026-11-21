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
/** Optional native-guest provider for validated scalar ImplMap declarations.
 * It must execute the requested guest function, decrement remaining_budget for
 * each native instruction, and return its typed result/actual LastError. It
 * must never execute a host DLL or implicitly accept an unsupported import.
 * Arguments and method metadata are borrowed for the duration of the call. */
typedef xxemul_status (*xxemul_dotnet_bcl_pinvoke_callback)(void *context, xxemul_dotnet_vm *vm,
    const xxemul_dotnet_method_info *method, const xxemul_dotnet_value *arguments,
    size_t argument_count, xxemul_dotnet_value *result, uint32_t *last_error,
    uint64_t *remaining_budget);

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
    uint64_t native_calls, native_instructions;
} xxemul_dotnet_bcl_statistics;

XXEMUL_API xxemul_dotnet_bcl_host *xxemul_dotnet_bcl_host_create(const xxemul_dotnet_bcl_config *config, xxemul_status *status);
XXEMUL_API void xxemul_dotnet_bcl_host_destroy(xxemul_dotnet_bcl_host *host);
/** Configure before execute; NULL disables native dispatch. Zero budget with a
 * provider selects 1,000,000 native instructions, shared by all calls and child
 * VMs during entry execution. This setter keeps the input config ABI intact.
 * Without a provider, P/Invoke remains explicitly unsupported. SetLastError
 * declarations retain the actual returned native error for Marshal's getter;
 * unflagged calls preserve the last captured error (Framework-style policy). */
XXEMUL_API xxemul_status xxemul_dotnet_bcl_set_pinvoke_callback(xxemul_dotnet_bcl_host *host,
    xxemul_dotnet_bcl_pinvoke_callback callback, void *context, uint64_t max_native_instructions);
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
