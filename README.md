# xxemul

`xxemul` is a pure C11 instruction emulator for x86, ARM, MIPS32 and Dalvik. It accepts a
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
- MIPS32 little/big endian integer execution with delayed branches, HI/LO,
  aligned/unaligned loads and stores, and Linux o32 syscalls
- Structured decoding and formatting through `cdisasm` in every native mode:
  x86 16/32/64, ARM A32, Thumb T32, ARM A64 (including arm64e), and MIPS32
- ARM64e PAC/AUT, XPAC, authenticated branches and returns execute from
  `cdisasm` A64 mnemonics and structured operands, with software pointer
  authentication shared by the Mach-O loader and Darwin runtime
- A64 `CTR_EL0`, `DC CVAU`, `IC IVAU`, and memory/instruction barriers for
  guest code that decompresses or modifies instructions. The interpreter
  models coherent memory and decodes the current bytes at every ARM step.
- Generated x86 decode families enabled by default for x87 and other UPX
  guest instructions
- One bounded, zero-filled, read/write/execute flat region
- Register state, memory access, single-step, bounded run, and disassembly APIs
- Initial scalar instructions: moves, integer arithmetic and logic, compares,
  basic loads/stores, stack operations, calls, returns, and branches
- Explicit halt, decode, address, and unsupported-instruction results
- COM/MZ loading into real-mode memory with A20 high-memory aliases, PSP
  creation, explicit DOS load addresses, and MZ relocations
- PE32/PE64 preferred-base or explicit-base section mapping with validated
  HIGH/LOW/HIGHLOW/DIR64 base relocations; ELF32/ELF64 `ET_EXEC` segment
  mapping, including zero-filled BSS and a minimal empty stack
- Separate bounded ELF32/ELF64 `ET_DYN` API with shared-object relocations,
  explicit version-aware guest import resolution and constructor inventory
- Primary Linux i386/AMD64 shared objects through the image API, with SysV
  DT_INIT/DT_INIT_ARRAY execution and retained initialized exports
- ARM BX/BLX interworking and Thumb call/return address handling
- Thin Mach-O executable segment mapping with `LC_MAIN` entry points and
  ARM64 UPX `LC_UNIXTHREAD` startup; compatible arm64/arm64e universal slices
- 16-bit segment registers, segment overrides, and a minimal DOS/BIOS layer
- Experimental DOS file calls, PE import/API thunks, and Linux syscall/process
  setup for running executable images
- 640x480 headless pixel renderer

Native execution consumes `cdisasm` mnemonics, operands, and instruction
metadata, including far x86 pointers, ARM shifts, bitfields, SIMD arrangements,
and system-call instructions. Decoder rejection is reported without local
opcode fallbacks or stripping prefixes and retrying. A decoded instruction
still requires execution support in xxemul. DEX and .NET CIL use the separate
`xxbyte` decoder; they are not native instruction sets supported by `cdisasm`.

The DOS layer implements selected INT 20h/21h/29h filesystem, console, and
process services, plus selected BIOS INT 10h/11h/12h/16h services.
Keyboard reads return `XXEMUL_STATUS_INPUT_REQUIRED` until a key is queued.
Unsupported services and instructions return `XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION`.

The display renders 80x25 VGA text memory at `0xB8000`, or mode 13h
320x200 indexed memory at `0xA0000` scaled to 640x480. The graphics palette
is fixed; VGA DAC port programming, sound, timers, and hardware-accurate
timing are not implemented. DOS filesystem services are incomplete. Port 92h,
basic keyboard-controller A20 control, and PIC mask/setup registers are
modeled, but the chipset is not hardware-accurate. DOS loading defaults to
program/module address `0x8240` and accepts explicit addresses in conventional
RAM as described below. This is an incremental DOS environment, not a full
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
ARM64 in little-endian `ET_EXEC` images, plus MIPS32 o32 in either byte order.
Compressed MIPS encodings, n32/n64 and Release 6 are rejected. PE images use their preferred base;
Static ELF images use `PT_LOAD` virtual addresses; supported primary libraries
add a load bias. Image regions and file inputs are
currently capped at 128 MiB. PE import thunks and a subset of Windows API
calls are emulated, along with selected Linux syscalls and an executable
handoff. The separate shared ELF API supports the bounded dynamic-loading
subset described below. Memory permissions and full process ABIs are not
implemented. The Darwin backend models supported libc/libc++/POSIX services
for arm64/arm64e `LC_MAIN` executables and compatible universal slices.
ARM64 UPX `LC_UNIXTHREAD` images execute their guest decompressor with kernel
startup arguments, bounded mappings, and the legacy x8/`svc #0` ABI. A virtual
dyld entry binds the image restored in guest memory and calls its `LC_MAIN`;
Apple's dyld and arbitrary dylibs are not executed. The restored-image window
is 16 MiB, with separate 32 MiB runtime and mapping arenas; protection masks
are metadata, not enforced page permissions. Unsupported constructors,
imports and old dyld fixup streams remain unsupported. COM, MS-DOS EXE, PE, ELF, and Mach-O loaders
live in separate `src/formats` C files. `src/platforms/xxemul_dos_loader.c`
owns shared DOS setup, while `src/xxemul_image.c` owns image dispatch and
file I/O.

The Linux process bridge supports i386, AMD64, ARM32 EABI, AArch64 and
MIPS32 o32 stack/auxv and syscall conventions. MIPS errors use `a3` and the
positive `v0` errno; guest stack words, stat fields and syscall data follow
the selected byte order. `xxemul_mips_state` and its get/set functions expose
GPR0–31, PC, HI and LO. Mode selects byte order. Guest CPU data accesses
notify memory observers after successful transfers; instruction fetch and
host memory inspection do not notify them. LL/SC uses a conservative
single-emulator reservation invalidated by writes, without a multiprocessor
atomic-memory model.

The ELF process bridge also models native FreeBSD i386 static executables
with canonical OSABI 9. It selects FreeBSD stack arguments, auxiliary-vector
tags, syscall numbers, mapping flags and positive errno/carry-flag results.
It reuses bounded guest mappings and confined file I/O. FreeBSD AMD64,
dynamic loading and legacy `e_ident` branding are unsupported. See the
[FreeBSD UPX guide](../xxdebugscript/samples/README_FREEBSD.md) for fixture
generation and validation with UPX 3.94.

Static owned ARM32, ARM64 and MIPS32 LE/BE ELF fixtures packed with UPX
4.2.4 NRV2E/LZMA have been unpacked through both script adapters and executed
afresh in the debugger. The fixture programs use modeled write/exit calls;
this does not establish arbitrary libc, dynamic-linker or native-host support.

## Windows process model

PE32/PE64 execution supplies bounded, process-local Win32 and CRT services.
Guest paths use a virtual `C:\` rooted at the selected working directory;
file operations and enumeration access real files below that root. Registry
keys and archive attributes are process-local metadata. Temporary files,
copies, truncation, legacy HFILE I/O and file-section writeback perform real
I/O. POSIX traversal rejects symlinks. File sections currently permit one live
view per backing file or section; extra views fail explicitly. Read-only view
permissions are not enforced by the flat memory model.

The x86/x64 bridge loads real guest PE DLLs, resolves named, ordinal, data and
forwarded exports, binds dependencies, applies relocations and calls guest
`DllMain` for process attach/detach. Reference counts, pinned modules and loader
lists track module lifetime. Resource handles include a load generation so an
unloaded module's handles cannot refer to a later DLL at the same address.

An x86/x64 DLL can also be the main analysis image. The PE `IMAGE_FILE_DLL`
flag selects this mode automatically, regardless of filename. Dependencies
initialize first, then the primary image's TLS callbacks and
`DllMain(image_base, DLL_PROCESS_ATTACH, NULL)` run as guest instructions.
Successful initialization completes the load phase with `HALTED` and code zero;
a FALSE return or dependency initialization failure reports code 1114 and runs
rollback notifications. This is a loader result rather than an invocation of
guest `ExitProcess`. The initialized primary image stays mapped and pinned,
with real export lookup and self-module handles, for inspection or export calls.
An absent DLL entrypoint completes without executing image headers; TLS
callbacks still run when present. Main EXE return/exit behavior is separate.

Static TLS and TLS callbacks are supported for x86/x64 EXEs and guest DLLs.
Each thread gets an aligned copy of every image's initialized template and
zero-fill, addressed by the image's DWORD TLS index through the TEB vector.
Loading a DLL initializes TLS storage for existing threads without inventing
earlier thread-attach notifications. TLS callbacks execute in array order before
the image's `DllMain`, for process/thread attach and normal detach. The callback
return value is ignored and its reserved argument is NULL. New thread routines
start after their attach notifications; waits signal only after normal detach.
The last normally exiting thread receives process detach only. Forced
`TerminateProcess`/`TerminateThread` bypass these callbacks.

Callback lists are bounded to 64 entries plus a NULL terminator, static TLS data
to 16 MiB per image and alignment to 8192 bytes. Image metadata, template,
callback-array and DWORD index spans are checked before publication. A zero
directory-size field is accepted when the complete TLS structure fits.
Callback target addresses follow the existing flat guest memory model.
`DisableThreadLibraryCalls` fails for active static TLS or a callback array.
Loader notifications are serialized: creating a thread inside a callback queues
its startup until the callback returns; yielding inside TLS callbacks or
`DllMain` remains unsupported. ARM TLS callback-bearing images are rejected.
Cyclic dependencies, delay imports and CLR modules fail explicitly. There are
at most 24 modules and eight nested initialization frames, with a 16 MiB bound
per dependency DLL file/image. Primary images use the normal PE image limits.

`CreateProcessA/W` creates a separate guest CPU and address space, including
cross-bitness x86/x64 children. Guest arguments, environment and current directory
are process-local. Cooperative execution supports suspended creation, child
process/thread handles, waits, exit codes, resume/suspend and termination.
Closing public handles does not stop a live child. The session owns the entire
tree: at most eight processes, four child levels and 256 MiB of guest regions;
each child also has a `0x40000000` instruction bound. Executable lookup uses the
parent executable's directory followed by guest CWD. Guest PATH/system-directory
search and arbitrary inherited handles or pipe redirection are unsupported.
Standard console output is forwarded to the session callback. Destroying the
root emulator tears down the tree.

Current-directory and environment APIs update the guest process state without
changing the host CWD. Real no-overwrite `MoveFileA/W` is supported on Linux and
macOS; other POSIX hosts return an explicit unsupported error. Resource APIs
read bounded numeric/named PE resource trees from the EXE and live guest DLLs.

The x86/x64 cooperative scheduler supports the main thread and seven workers,
individual stacks, static/dynamic TLS, register and floating-point state,
thread-local errors, suspend/resume, waits and termination. It does not model
parallel host execution. ARM thread creation, APCs and yielding through active
SEH frames remain unsupported.

Headless modal dialogs parse bounded standard/extended numeric RT_DIALOG
resources and execute the real guest dialog procedure, including worker-thread
completion. Text, font and selected progress messages retain actual object
state. A dialog that requires user interaction returns
`XXEMUL_STATUS_INPUT_REQUIRED`; no commands are injected automatically.
Custom window classes, arbitrary message queues and general desktop rendering
are outside this model. Unsupported calls must be distinguished from modeled
exports when assessing a program's result.

Formatting, heap ownership, CRT file operations, INI reads, guest memory
status and selected en-US/CP1252/CP437 locale services have public API tests
on both x86 and x64. This remains a selected Windows API model, not a complete
Windows installation: x64 exception unwinding and CRT `_except_handler3`
execution are unsupported. Unsupported APIs and execution faults remain errors.

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

The ordinary ELF image constructors also load little-endian i386 and AMD64
shared libraries with PT_DYNAMIC, without PT_INTERP, DF_1_PIE or DT_NEEDED
dependencies. Their ELF entry may be zero, or may alias DT_INIT when a valid
SONAME identifies the library, as in the tested UPX shared-library wrapper.
`xxemul_start_process` supplies the Linux stack and
syscall context, then schedules DT_INIT followed by the live DT_INIT_ARRAY
using `(argc, argv, envp)`. The array is read after DT_INIT, allowing a loader
to restore its callbacks first. Successful initialization halts with result
zero and leaves exports mapped for guest calls. Initializer return values
are ignored. `xxemul_elf_primary_get_info`, `find_export` and `get_entry`
expose the layout, dynamic exports and first initializer to analysis clients.
The analysis entry is zero when no initializer exists. ELF e_entry remains
metadata and is not used to invoke the library as an executable.
Linux `/proc/self/auxv` exposes the same guest-width auxiliary vector as the
initial stack, with biased addresses for shared objects.

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

For PE32/PE64 rebasing, use `xxemul_create_image_at` or
`xxemul_create_image_file_at` with an explicit load base. Zero selects the
preferred address. The loader validates the full relocation table and applies
HIGH, LOW, HIGHLOW (PE32), and DIR64 (PE64) fixups before execution. The mapped
PE header retains the preferred ImageBase; region/entry getters use the actual
address. Unsupported relocation types and malformed tables return an error.
An empty relocation directory is valid when relocations are not marked
stripped, as with a position-independent UPX PE64 loader stub.
For a primary ELF shared library, `_at` selects the actual first mapped
PT_LOAD address. Zero selects the shared loader's default bias, 0x10000000.
Static ELF and Mach-O images reject an explicit load base.

The same `_at` constructors support COM and MZ. Here `image_base` is the
first COM program byte or the first MZ load-module byte after its file header;
it is not the PSP address or the MZ entry address. The loader derives the PSP
segment as `(image_base >> 4) - 0x10` before initializing the PSP, MCB and DOS
kernel structures. Thus `image_base=0x10000` uses PSP segment `0x0ff0`, while
`0x18000` uses `0x17f0`. Zero retains PSP `0x0814` and program/module base
`0x8240`; `xxemul_create_dos` and `xxemul_create_dos_file` retain that default.

An explicit DOS address must be paragraph aligned, at least `0x8240` and
below `0xa0000`, preserving the fixed DOS kernel and environment regions.
COM additionally requires an address at most `0x90100` so PSP:FFFE stays in
conventional RAM. MZ body, minimum allocation, entry and stack bounds are
validated by its loader, and segment relocation words receive the actual
module load segment. DOS `xxemul_get_region_address()` remains zero: its
region models flat physical memory. Use register/linear-address getters for
the program's current address. The debugger/script `imageBase()` likewise
remains zero for DOS.

`xxemul_dos_load_base_tests` covers default and explicit COM/MZ placements,
PSP/kernel initialization, consumed MZ relocations, execution and invalid
address bounds. It is registered when `XXEMUL_BUILD_TESTS` and
`BUILD_TESTING` are enabled.

## Debugger support

The modeled Windows bridge also accepts ARM32 WinCE and Windows ARM64 PE
images, with AAPCS32/AAPCS64 argument and return handling. It includes the
COREDLL/kernel32 operations needed by the real UPX ARM stubs, including
CacheSync and FlushInstructionCache. See the bounded
[ARM UPX sample](../xxdebugscript/samples/README_ARM.md) for generated inputs
and unpack/rebase/debugger tests. This does not run the native Windows OS.

These hooks are used by the xxdebug emulator backend:

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
