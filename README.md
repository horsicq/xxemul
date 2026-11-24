# xxemul

A C11 instruction emulator for executable analysis and unpacking.

- **CPUs:** x86 (16/32/64-bit), ARM (A32, Thumb, A64/arm64e), MIPS32/MIPS64, MC68000.
- **Bytecode (optional):** Dalvik (APK/DEX) and .NET CIL.
- **Loaders:** flat memory region, COM, MZ, PE32/PE64, ELF32/ELF64, Mach-O, Amiga Hunk.
- **Runtimes:** partial models of DOS/BIOS, Windows (Win32 API, DLLs, TLS, threads, child processes),
  Linux/FreeBSD syscalls, Darwin, and AmigaOS Exec/DOS.

These are bounded models, not full operating systems. Anything that is not modeled stops with an explicit
error status instead of being guessed.

## Dependencies

- [`xxfclib`](../xxfclib): memory, file I/O and format parsing. Default location `../xxfclib`; change it with
  `-DXXEMUL_XXFCLIB_SOURCE_DIR=<path>`.
- `cdisasm`: decodes all native instructions.
- `xxbyte`: decodes DEX and CIL bytecode. Change its location with `-DXXEMUL_XXBYTE_SOURCE_DIR=<path>`.

## Build

```text
cmake -S . -B build
cmake --build build --config Release
cmake --install build --config Release --prefix /path/to/xxemul
```

| Option | Default | Effect |
|---|---|---|
| `XXEMUL_ENABLE_DEX` | ON | APK/DEX loader and Dalvik interpreter |
| `XXEMUL_ENABLE_DOTNET` | OFF | Managed PE loader and CIL interpreter |
| `XXEMUL_CDISASM_EXTRA_OPCODES` | ON | Extra x86 decoding (x87 and others, needed for UPX stubs) |
| `XXEMUL_BUILD_TESTS` | top level only | Tests |
| `XXEMUL_BUILD_CLI`, `XXEMUL_BUILD_VIEWER` | ON | Command-line runner and DOS display viewer |

## Usage

```c
#include <xxemul/xxemul.h>
```

1. Create an emulator. Use `xxemul_create_image_file(...)` for a file, or `xxemul_create_image_file_at(...)` to
   load it at a chosen base. COM files have no signature, so you always pass the format explicitly.
2. Call `xxemul_start_process(...)` to set up the OS model: stack, arguments and environment.
3. Run it with `xxemul_step` or `xxemul_run`. Read the CPU state with `xxemul_get_x86_state` (and the matching
   ARM/MIPS/M68K functions). Read and write guest memory with `xxemul_read_memory` / `xxemul_write_memory`.

Other headers:

| Header | Purpose |
|---|---|
| `xxemul/xxemul_elf.h` | Load an ELF shared object and call its exports |
| `xxemul/xxemul_dex.h`, `xxemul_dex_runtime.h` | APK/DEX loading and the Dalvik VM |
| `xxemul/xxemul_dotnet*.h` | .NET assembly loading, CIL VM and BCL host |

Debugger hooks:
- `xxemul_set_debug_traps`: breakpoints.
- `xxemul_set_memory_hook`: guest data reads and writes.
- `xxemul_set_output_callback`: console output.
- `xxemul_symbol_name`: names of import and library stubs.

## More documentation

- [docs/DETAILS.md](docs/DETAILS.md): full scope, limits, load-address rules and per-platform notes.
- [docs/PINVOKE.md](docs/PINVOKE.md): managed-to-native calls.
- `../../XAPKEmul/README.md` and `../../XDotNetEmul/README.md`: the APK and .NET console front ends.
