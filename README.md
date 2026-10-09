# xxemul

`xxemul` is a pure C11 instruction emulator for x86, ARM and Dalvik. It accepts a
caller-supplied flat region, or explicitly loads COM, MZ, PE32, PE64, ELF32,
ELF64, Mach-O 32, and Mach-O 64 images. The loaders use format parsers from
the sibling `xxfclib`.

APK and standalone DEX loading are available through `xxemul/xxemul_dex.h`.
The bounded Dalvik interpreter is in `xxemul/xxemul_dex_runtime.h`, using
the sibling `xxbyte` decoder. APK inventory, manifest metadata, extraction and
bounded DEX structure readers come from `xxfclib`. The loader supports
multidex APKs and standard little-endian DEX
035 and 037-040; DEX 041 containers and optimized ODEX are rejected.
Android and Java services require an explicit host callback. This extension
does not supply a full Android runtime or UI. See the sibling
`../../XAPKEmul/README.md` for console usage and the APK integration fixture.
Set `XXEMUL_ENABLE_DEX=OFF` to build only the native CPU emulators, or set
`XXEMUL_XXBYTE_SOURCE_DIR` to select a different xxbyte source tree.

DEX VM host services can use `xxemul_dex_vm_new_byte_array`, range-checked
byte-array length/read/write helpers and `xxemul_dex_vm_is_instance`.
Optional `xxemul_dex_intercept_callback` runs after receiver/argument checks
and class initialization, allowing an explicit host model to handle selected
methods that also have DEX bodies. An unhandled call continues normally;
handled return kinds/references are validated like external calls. XAPKEmul's
`--android-host` uses this for headless Activity setup with File/Base64/stream
services. Its Oxygen regression executes actual app bytecode and checks the
721-byte generated file and the existing-file branch. The host model also
loads APK native libraries with the ELF shared-object API below and executes
bounded JNI exports on all four Android ABIs. It supplies a small JNI subset;
UI, exception dispatch and general Android JNI services remain unsupported.

Managed PE assemblies can be loaded and inspected through
`xxemul/xxemul_dotnet.h`, and executed through the bounded typed CIL interpreter
in `xxemul/xxemul_dotnet_runtime.h`. Enable `XXEMUL_ENABLE_DOTNET=ON` to build
this optional backend; `xxbyte` then includes the DOTNET decoder, alongside
DEX if both are enabled. See `../../XDotNetEmul/README.md` for console usage,
test assemblies, host callbacks and runtime limitations. The application uses
the focused xxfclib `dotnet_emul` profile; general native emulator consumers
can continue using the default full xxfclib profile.

## Current scope

- x86 16-bit, 32-bit, and 64-bit decode modes
- ARM A32, T32, and A64 decode modes
- Structured decoding and formatting through `cdisasm`
- Generated x86 decode families enabled by default for x87 and other UPX
  guest instructions
- One bounded, zero-filled, read/write/execute flat region
- Register state, memory access, single-step, bounded run, and disassembly APIs
- Initial scalar instructions: moves, integer arithmetic and logic, compares,
  basic loads/stores, stack operations, calls, returns, and branches
- Explicit halt, decode, address, and unsupported-instruction results
- COM/MZ loading into real-mode memory with A20 high-memory aliases, PSP
  creation, and MZ relocations
- PE32/PE64 preferred-base section mapping; ELF32/ELF64 `ET_EXEC` segment
  mapping, including zero-filled BSS and a minimal empty stack
- Separate bounded ELF32/ELF64 `ET_DYN` API with shared-object relocations,
  explicit version-aware guest import resolution and constructor inventory
- ARM BX/BLX interworking and Thumb call/return address handling
- Thin Mach-O 32/64 executable segment mapping with `LC_MAIN` entry points
- 16-bit segment registers, segment overrides, and a minimal DOS/BIOS layer
- Experimental DOS file calls, PE import/API thunks, and Linux syscall/process
  setup for running executable images
- 640x480 headless pixel renderer

The DOS layer implements selected INT 20h/21h/29h filesystem, console, and
process services, plus selected BIOS INT 10h/11h/12h/16h services.
Keyboard reads return `XXEMUL_STATUS_INPUT_REQUIRED` until a key is queued.
Unsupported services and instructions return `XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION`.

The display renders 80x25 VGA text memory at `0xB8000`, or mode 13h
320x200 indexed memory at `0xA0000` scaled to 640x480. The graphics palette
is fixed; VGA DAC port programming, sound, timers, and hardware-accurate
timing are not implemented. DOS filesystem services are incomplete. Port 92h,
basic keyboard-controller A20 control, and PIC mask/setup registers are
modeled, but the chipset is not hardware-accurate. DOS MZ loading currently
uses a low load address. This is an incremental DOS environment, not a full
MS-DOS replacement.

The DOS DPMI host supports the entry switch, descriptor allocation and setup,
memory allocation, and real-mode INT 21h simulation needed by the bundled
FASM_DOS 1.73.35 executable. It does not implement the full DPMI API.

## xxfclib dependency

The build uses the real sibling `xxfclib` for allocation, file/memory I/O,
and executable-format parsing. Its default
location is `../xxfclib`; use a different source tree with:

```text
-DXXEMUL_XXFCLIB_SOURCE_DIR=<path-to-xxfclib>
```

The format is explicit because a COM file has no signature. PE supports x86,
x86-64, ARM32, and ARM64 machine types; ELF supports x86, x86-64, ARM32, and
ARM64 in little-endian `ET_EXEC` images. PE images use their preferred base;
ELF images use `PT_LOAD` virtual addresses. Image regions and file inputs are
currently capped at 128 MiB. PE import thunks and a subset of Windows API
calls are emulated, along with selected Linux syscalls and an executable
handoff. The separate shared ELF API supports the bounded dynamic-loading
subset described below. Memory permissions and full process ABIs are not
implemented. Mach-O supports little-endian thin executables with
`LC_MAIN`; fat binaries, `LC_UNIXTHREAD` entry points, dyld, and macOS system
services are not implemented. COM, MS-DOS EXE, PE, ELF, and Mach-O loaders
live in separate `src/formats` C files. `src/platforms/xxemul_dos_loader.c`
owns shared DOS setup, while `src/xxemul_image.c` owns image dispatch and
file I/O.

## Shared ELF API

`xxemul/xxemul_elf.h` owns a guest CPU and mapped little-endian `ET_DYN` image
for i386, x86-64, ARM32 or AArch64. `xxemul_elf_shared_create` maps PT_LOAD
segments/BSS, allocates bounded auxiliary/stack arenas, and applies supported
REL/RELA relocations. An explicit resolver receives each undefined symbol and
its ELF version name and returns a guest address. Dependencies are never loaded
on the host. The result contains relocation/import counts and a diagnostic.

Use `xxemul_elf_shared_find_export` for visible dynamic exports and
`xxemul_elf_shared_initializer_count`/`initializer_at` for DT_INIT followed by
relocated DT_INIT_ARRAY entries. The loader inventories constructors; callers
execute them with a guest ABI and an instruction budget. CPU and layout getters
remain valid until `xxemul_elf_shared_destroy`. The input bytes need not outlive
creation. ARM function addresses retain their Thumb bit.

Unsupported relocations, TLS, IFUNC and packed relocations fail explicitly.
The original ET_EXEC loader and executable process setup remain separate.
XAPKEmul's native bridge supplies Android import models, executes initialization
and JNI_OnLoad, and binds DEX native declarations to JNI exports. See its README
for the implemented JNI subset and actual Oxygen APK integration tests.

## Build

```text
cmake -S . -B build
cmake --build build --config Release
cmake --install build --config Release --prefix /path/to/xxemul
```

`XXEMUL_CDISASM_EXTRA_OPCODES` defaults to ON. The UPX experiments require
non-base decode families such as x87; an OFF build retains the smaller scalar
instruction set.

## Library API

Library callers can load bytes with `xxemul_create_dos`, load a path via
`xxemul_create_dos_file`, execute with `xxemul_step`/`xxemul_run`, queue input
using `xxemul_dos_push_key`, and fill a caller-owned 640x480 ARGB buffer with
`xxemul_display_render`. `xxemul_get_x86_state` exposes CS/DS/ES/SS and IP;
`xxemul_dos_linear` returns a 20-bit wrapped address for memory API calls;
CPU memory accesses also honor the emulated A20 gate.
Use `xxemul_create_image` or `xxemul_create_image_file` for all eight explicit
formats.

## Debugger support

These hooks are used by the xxcdebug emulator backend:

- `xxemul_set_debug_traps`: a guest `INT3` (or `INT 3` outside DOS)
  returns `XXEMUL_STATUS_BREAKPOINT` with IP past the instruction, instead
  of halting.
- `xxemul_set_memory_hook`: reports guest data reads and writes during
  `xxemul_step`. Instruction fetches are not reported.
- `xxemul_set_output_callback`: one stdout/stderr stream for the DOS,
  Windows and Linux layers.
- `xxemul_get_current_address`, `xxemul_x86_linear_address`: linear
  addresses through real-mode/DPMI segment state.
- `xxemul_is_halted`, `xxemul_symbol_name` (PE import thunk names).
