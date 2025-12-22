# Platform Support Strategy

This document describes how monacc supports multiple platforms while maintaining code quality and platform independence.

## Overview

The monacc project supports:
- **Linux x86_64** (primary target, syscall-only freestanding binaries)
- **Darwin AArch64** (macOS arm64, hosted builds using libc)

## Design Principles

### 1. Platform Independence in `/tools`

The tools directory (`/tools/*.c`) contains **architecture-independent and platform-independent** code. Tools only use abstractions provided by the core library (`core/mc_*.h`).

**Key rules:**
- Tools MUST NOT contain platform-specific `#ifdef` checks
- Tools MUST NOT use platform-specific APIs directly
- Tools MUST use only the `mc_sys_*` and `mc_*` abstractions from `core/`

### 2. Platform-Specific Code in `/core`

All platform-specific code is isolated in the `/core` directory through a modular header structure:

```
core/
├── mc_platform.h              # Platform detection (MC_OS_*, MC_ARCH_*)
├── mc_syscall.h               # Platform selector
├── mc_syscall_linux_x86_64.h  # Linux syscall implementation
├── mc_syscall_darwin.h        # Darwin hosted (clang+libc) implementation
└── mc_syscall_darwin_monacc.h # Darwin native (monacc-generated) shims
```

**Platform selection flow:**
1. `mc_platform.h` defines detection macros (`MC_OS_LINUX`, `MC_OS_DARWIN`, `MC_ARCH_X86_64`, `MC_ARCH_AARCH64`)
2. `mc_syscall.h` includes the appropriate implementation based on platform
3. Platform-specific headers provide the same abstraction layer with different implementations

### 3. Multi-Platform Compiler Support

The `monacc` compiler (`compiler/monacc_codegen.c`) includes backends for:
- **x86_64 SysV ABI** (Linux freestanding, original target)
- **AArch64 Darwin** (macOS hosted, new target)

Backend selection is controlled by the `--target` flag:
- Default: x86_64 Linux (freestanding)
- `--target aarch64-darwin`: AArch64 macOS (hosted, uses external clang for assembly/linking)

## Implementation Details

### Abstraction Layer

The core library provides a consistent abstraction across platforms:

**Functions:**
- `mc_sys_read()`, `mc_sys_write()`, `mc_sys_open()`, etc. - I/O operations
- `mc_syscall0()` through `mc_syscall6()` - Low-level syscall interface
- `mc_exit()` - Platform-agnostic exit

**Constants:**
- `MC_O_*` - File open flags
- `MC_E*` - Error codes (errno values)
- `MC_AT_*` - *at() family flags
- `MC_S_*` - File mode bits
- `MC_AF_*`, `MC_SOCK_*` - Network constants

**Structs:**
- `mc_stat`, `mc_statfs` - File metadata
- `mc_timespec` - Time representation
- `mc_utsname` - System information
- `mc_sockaddr_in6` - Network addresses

### Platform Implementations

#### Linux x86_64 (Freestanding)
- Direct syscall invocations via inline assembly
- No libc dependency
- Produces static ELF binaries with only kernel dependencies
- Numeric constants match Linux kernel ABI

#### Darwin AArch64 (Hosted)
- Uses system libc (read, write, openat, socket, etc.)
- Maps Linux-style API to POSIX calls
- Translates between Linux and Darwin struct layouts
- Returns `-errno` to match Linux syscall convention
- Two variants:
  - `mc_syscall_darwin.h` - For host toolchain (clang) builds
  - `mc_syscall_darwin_monacc.h` - For monacc-generated binaries

## Build System

The Makefile supports multiple build configurations:

### Linux Build (Default)
```bash
make              # Build with Linux x86_64 target
make test         # Run test suite
```

### Darwin Build
```bash
make darwin-tools           # Build hosted tools with clang
make darwin-monacc          # Build monacc compiler
make darwin-native-smoke    # Test native aarch64-darwin target
```

On macOS, `make` and `make test` default to `darwin-native-smoke` for better UX.

## Testing Strategy

Platform-specific testing ensures quality across targets:

1. **Linux Tests** - Full test suite on Linux x86_64
2. **Darwin Hosted Tests** - Smoke tests for clang-built tools
3. **Darwin Native Tests** - Regression tests for monacc aarch64-darwin backend

## Output Quality Guarantee

The design maintains output quality for both platforms:

1. **No compromises for Linux/x86_64**: The original Linux target is unchanged; platform abstraction adds zero overhead to Linux builds
2. **Optimal Darwin builds**: Darwin builds use platform-native APIs and tooling for best performance
3. **Compiler quality**: Each backend generates idiomatic code for its target platform

## Future Platform Support

To add a new platform:

1. Create `core/mc_syscall_<platform>.h` with the abstraction layer
2. Update `core/mc_platform.h` to detect the new platform
3. Update `core/mc_syscall.h` to include the new header
4. Optionally add a compiler backend in `compiler/monacc_codegen.c`
5. Update build system with platform-specific targets
6. Add platform-specific tests

No changes to `/tools` should be necessary if the abstraction layer is complete.

## Summary

The platform support strategy achieves:
- ✅ Platform independence in `/tools` directory
- ✅ Platform-specific code isolated in `/core` directory  
- ✅ Multi-platform compiler support (Linux/x86-64 and Darwin/AArch64)
- ✅ High output quality maintained for both platforms
- ✅ Clean abstraction layer for future platform additions
