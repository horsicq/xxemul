# xxemul

`xxemul` is a pure C11 instruction emulator for x86 and ARM. It accepts a
caller-supplied flat region, or explicitly loads COM, MZ, PE32, PE64, ELF32,
ELF64, Mach-O 32, and Mach-O 64 images. The loaders use format parsers from
the sibling `xxfclib`.

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
handoff. Shared libraries, dynamic relocation, memory permissions, and full
process ABIs are not implemented. Mach-O supports little-endian thin executables with
`LC_MAIN`; fat binaries, `LC_UNIXTHREAD` entry points, dyld, and macOS system
services are not implemented. COM, MS-DOS EXE, PE, ELF, and Mach-O loaders
live in separate `src/formats` C files. `src/platforms/xxemul_dos_loader.c`
owns shared DOS setup, while `src/xxemul_image.c` owns image dispatch and
file I/O.

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
