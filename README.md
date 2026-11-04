# xxemul

A C11 instruction emulator for x86, ARM, MIPS and Dalvik, with optional
.NET CIL support. It loads flat code, DOS COM/MZ, PE, ELF and Mach-O images.

- Step or run instructions; inspect registers and memory.
- Executable loaders, modeled operating-system services and debugger hooks.
- APK/DEX support by default; enable CIL with `XXEMUL_ENABLE_DOTNET=ON`.

Instruction and runtime support is limited to the implemented subsets.

## Build

See [build instructions](docs/BUILD.md).

CMake consumers link `xxemul::xxemul`. See the
[public API](include/xxemul/xxemul.h), [APK example](../../XAPKEmul/README.md)
and [.NET example](../../XDotNetEmul/README.md).
Licensed under [MIT](LICENSE).
