# xxemul

A C11 emulator for x86, ARM, MIPS, and Motorola 68000, with optional Dalvik
and .NET CIL support. It models parts of DOS, Windows, Linux, FreeBSD, macOS,
and AmigaOS for binary analysis.

Build with CMake and sibling checkouts of `xxfclib`, `cdisasm`, and `xxbyte`
(for bytecode support). Link `xxemul::xxemul`. See the
[public headers](include/xxemul/) for supported formats and limitations.

```sh
cmake -S . -B build
cmake --build build --config Release
```

License: [MIT](LICENSE).
