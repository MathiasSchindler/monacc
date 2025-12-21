# macOS (arm64) hosted build plan

Date: 2025-12-21

This document describes a **hosted** port that allows the monacc userland tools (in `tools/`) to **compile and link on macOS arm64 using Apple clang**, without requiring `monacc`.

Scope constraints:

- **In scope**: Build tools on macOS using the system toolchain (`clang` + system libc).
- **Out of scope**: Running/bootstrapping with `monacc` on macOS, syscall-only/freestanding binaries on macOS.
- **Goal**: No changes to `tools/` source if possible; concentrate changes in `core/`.

## Problem statement

Today, `tools/*.c` depend on `core/mc_syscall.h` and `core/mc_net.h` which are Linux x86_64-specific:

- raw inline `syscall` asm stubs (x86_64-only)
- Linux syscall-number constants (`MC_SYS_*`)
- Linux numeric `errno` constants (`MC_E*`) and flag constants (`MC_O_*`, `MC_AT_*`, ...)
- Linux-only directory iteration (`getdents64`)
- Linux-only ABI structs (`statfs`, `stat`, `dirent64`)

On macOS, the equivalents exist but via different APIs/ABIs (libc/POSIX + BSD structs), and numeric constants differ.

## Strategy

Keep the **tool-facing API stable**:

- functions: `mc_sys_*()` and `mc_syscall0..6()`
- constants: `MC_E*`, `MC_O_*`, `MC_AT_*`, `MC_S_IF*`, `MC_AF_INET6`, ...
- structs: `mc_timespec`, `mc_stat`, `mc_statfs`, `mc_utsname`, `mc_sockaddr_in6`, ...

Then provide **platform backends** in `core/`:

- Linux x86_64 backend remains unchanged (raw syscalls).
- Darwin hosted backend uses libc/POSIX (`read`, `write`, `openat`, `socket`, ...) and returns `-errno` on failure to match existing tool expectations.

This keeps the macOS port from affecting Linux, because:

- macOS code lives in separate headers/files.
- selection is done via `__APPLE__` / `__linux__` and arch macros.
- the normal Linux build path stays identical.

## Implementation plan (incremental milestones)

### Milestone 1: Make headers compile on macOS

1. Add a small platform header `core/mc_platform.h` that defines:
   - `MC_OS_LINUX` / `MC_OS_DARWIN`
   - `MC_ARCH_X86_64` / `MC_ARCH_AARCH64`

2. Split `core/mc_syscall.h` into:
   - `core/mc_syscall_linux_x86_64.h` (existing content)
   - `core/mc_syscall_darwin.h` (new hosted backend)
   - `core/mc_syscall.h` becomes a thin selector.

3. Do the same for `core/mc_net.h` if needed (at minimum map `MC_AF_INET6`, `MC_SOCK_*`, etc. to platform values on macOS).

### Milestone 2: Darwin hosted syscall wrappers

Implement the `mc_sys_*` wrappers on macOS using libc/POSIX calls and the project convention of returning `-errno` on error.

Key points:

- Provide `mc_syscall0..6` on macOS only as a **compatibility shim**.
   - macOS deprecates `syscall(2)`, so the shim does **not** use raw syscalls.
   - Currently, only `MC_SYS_exit` / `MC_SYS_exit_group` are handled (via `_exit(2)`); all other raw syscalls return `-MC_ENOSYS`.
- Prefer libc/POSIX APIs for `mc_sys_*` wrappers, not raw syscall numbers.

Wrappers needed (current inventory):

- IO/files: `read`, `write`, `close`, `openat`, `fstat`, `fstatat`, `lseek`, `ftruncate`, `mkdirat`, `unlinkat`, `renameat`, `linkat`, `symlinkat`, `readlinkat`, `getcwd`, `faccessat`, `fchmodat`, `fchownat`, `utimensat`
- Process: `execve`, `fork`, `vfork`, `wait4`, `dup2`, `chdir`
- Time/signal: `clock_gettime`, `nanosleep`, `kill`, `uname`, `sigaction` (to implement the `rt_sigaction` wrapper contract)
- Memory: `mmap`, `munmap`
- Net/poll: `socket`, `connect`, `accept`, `sendto`, `recvfrom`, `shutdown`, `bind`, `listen`, `getsockname`, `setsockopt`, `getsockopt`, `poll`, `fcntl`
- Misc: `getuid`, `getgid`, `getgroups`, `getrandom`, `statfs`, `sched_getaffinity`

### Milestone 3: Remove Linux-only directory iteration

Replace Linux `getdents64` usage in `core/mc_io.c`:

- Keep public `mc_for_each_dirent(dirfd, cb, ctx)`.
- On macOS implement via `dup(dirfd)` + `fdopendir` + `readdir`.
- Preserve “don’t close the caller’s dirfd” semantics.

### Milestone 4: Make hosted macOS build target

Add a Make target such as `darwin-tools`:

- output directory: `bin-host/`
- compiler: `clang`
- links against system libc (default crt), **not** `-nostdlib`
- compiles tools + the needed `core/*.c` files (excluding Linux-only startup like `core/mc_start.c`)

Optionally add `darwin-tools-smoke` / compile-only checks.

## Known limitations (expected)

Even after successful compilation/linking, some tools will not behave identically on macOS because they intentionally rely on Linux interfaces:

- `/proc` parsing tools (`ps`, `mount` listing, etc.)
- Linux-specific syscalls/flags (may map to `ENOSYS`)
- `dmesg` uses Linux `syslog(2)`/klogctl by syscall number; on macOS it will likely fail at runtime (but should compile).

The initial goal is **compile+link**; runtime compatibility can be improved tool-by-tool later if desired.

## Build (intended)

On macOS:

- `make darwin-tools` (new)
- `make darwin-smoke` (new; builds + runs a tiny hosted sanity check)
- `make darwin-net-smoke` (new; builds + checks IPv6 connect via `tcp6` and a simple fetch via `wtf`)

Notes:

- `make -j <n> darwin-tools` works (the build is per-tool target based, not a single loop).
- The hosted tool targets list `core/*.h` as prerequisites, so changes to headers like `core/mc_syscall_darwin.h` trigger rebuilds (prevents stale `bin-host/*` binaries after core header edits).
- Hosted binaries are **not** code-signed by default; the size reductions come from normal compiler/linker flags.
   - The hosted build uses `-Os`, `-ffunction-sections/-fdata-sections`, and `-Wl,-dead_strip` to avoid pulling in unused core code.

This should produce `bin-host/<tool>` binaries compiled with Apple clang.
