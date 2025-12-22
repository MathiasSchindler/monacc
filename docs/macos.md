# macOS (arm64) status and plan

Date: 2025-12-22

This document tracks two related macOS efforts:

1) **Hosted tools (clang)**: compile/link `tools/*` on macOS arm64 into `bin-host/*` using Apple clang.
2) **Native `aarch64-darwin` target (monacc)**: `bin-host/monacc --target aarch64-darwin` emits arm64 assembly and drives external `clang` to assemble/link Mach-O.

Scope constraints (pragmatic, current):

- **In scope**:
   - Hosted tool builds on macOS using the system toolchain (`clang` + system libc).
   - A bring-up `aarch64-darwin` backend in monacc sufficient to compile and run a growing tool subset.
- **Out of scope (for now)**:
   - syscall-only/freestanding binaries on macOS
   - internal Mach-O object emission and internal Mach-O linking
   - full macOS SDK header compatibility (we keep using small shims)

Goal:

- No changes to `tools/` source if possible; concentrate platform glue in `core/` and validate via `darwin-*-smoke` targets.

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

## Current status (2025-12-22)

### Hosted tools (clang)

- `make darwin-tools` builds hosted macOS binaries into `bin-host/`.
- `make darwin-smoke` and `make darwin-net-smoke` provide quick runtime checks.

### Native `aarch64-darwin` target (monacc)

- `bin-host/monacc --target aarch64-darwin` produces native Mach-O arm64 binaries (via external `clang`).
- Regression anchor: `make darwin-native-smoke`.

Native tools currently covered by `darwin-native-smoke` (built by monacc):

- `true-mc`, `false-mc`, `echo-mc`, `basename-mc`, `dirname-mc`
- `whoami-mc`, `pwd-mc`, `hostname-mc`, `id-mc`, `uname-mc`
- `yes-mc`, `seq-mc`, `time-mc`, `kill-mc`, `chown-mc`, `ln-mc`, `touch-mc`, `mkdir-mc`

Notable recent bring-up increments:

- Darwin monacc shim (`core/mc_syscall_darwin_monacc.h`) gained libc-backed wrappers/constants for `openat`/`close`/`utimensat`/`mkdirat`, `MC_O_*` flags, and `MC_EEXIST`.
- `aarch64-darwin` backend grew:
   - struct/aggregate copies via `EXPR_MEMCPY` (simple byte loop)
   - calls with more than 6 arguments (x0..x7 + stack args)

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

---

## Native arm64-darwin monacc compiler port (outline)

This section is about porting **monacc the C compiler** to produce **native arm64 macOS (Darwin) binaries**.

Goal (as requested):

- **Target**: `arm64-apple-darwin` (native)
- **First milestone toolchain**: use external assembler and linker (practically: drive them via `clang`)
- **Not a goal initially**: internal object emission and internal linker on macOS

### Where monacc is today (relevant constraints)

The compiler is currently designed around:

- **Target ISA/ABI**: Linux x86_64 SysV
- **Output**: AT&T x86_64 assembly; optionally internal ELF64 `.o` emission and internal linking
- **Link model**: freestanding `_start` / syscall-oriented outputs for the in-tree userland tools

Porting to native arm64-darwin therefore requires *real backend work* (instruction set + ABI) and a different binary format/toolchain path.

### Recommended approach (staged)

#### Stage 0 — Host monacc on macOS (compiler runs on Darwin)

Make `monacc` itself compile and run as a **hosted** macOS executable (libc-based). This is independent of what it targets.

Typical work:

- Replace Linux-only syscall code paths in the compiler runtime (`compiler/monacc_sys.c`) with macOS/POSIX equivalents.
- Make the build use Apple clang defaults for a hosted binary (no `-nostdlib`, no custom `_start`).

Deliverable:

- `bin-host/monacc` runs on macOS as a hosted (libc-linked) executable.
- Build targets:
   - `make darwin-monacc`
   - `make darwin-monacc-smoke` (compiles `examples/hello.c` into an ELF output to validate the hosted compiler runs)

#### Stage 1 — Add an arm64-darwin codegen backend (assembly only)

Implement a new backend that emits **AArch64 (arm64) assembly** following the macOS ABI.

Key design choice:

- Start with a **hosted target** that emits a `main` symbol and relies on the platform CRT + libc.
   - This avoids having to implement Darwin syscalls + a custom `_start` early.
   - You can still keep monacc’s language subset and avoid full libc headers initially by compiling tiny examples.

Major technical pieces:

- Calling convention: AAPCS64 / Darwin arm64
   - args in `x0..x7`, return in `x0`, stack 16-byte alignment, callee-saved registers, etc.
- Instruction selection for the subset currently supported by monacc:
   - integer ops, loads/stores, address calc, branches/condition codes, calls
   - function prologues/epilogues, stack locals
- ABI details that impact correctness:
   - struct layout/alignment rules, integer promotions, varargs ABI (can be deferred if you restrict features)

Deliverable:

- `monacc` can compile a small “hello world” style program to assembly for arm64-darwin.

Current repo status:

- `bin-host/monacc --target aarch64-darwin` exists.
- The backend is intentionally minimal for bring-up, but now supports a small (useful) subset:
   - locals (1/2/4/8-byte) + assignment
   - address-of (`&`) and dereference (`*`) for 4/8-byte loads/stores (minimal subset)
   - arithmetic: `+` / `-`
   - bitwise: `&` `|` `^` `~`
   - shifts: `<<` `>>` (signed/unsigned right shift)
   - comparisons as expressions: `== != < <= > >=` (returns 0/1)
   - integer mul/div/mod: `* / %` (32-bit)
   - short-circuit boolean ops: `&&` / `||` (returns 0/1)
   - control flow: `if`, `while`, `break`, `continue`
   - direct calls with up to 8 register args + stack args (ints in `wN`, pointers in `xN`)
   - string literals (emitted into `__TEXT,__const`)
   - global 1/2/4-byte loads and simple global emission for initialized scalars (plus basic global stores)

Notes on integer widths

- `char`/`short` loads now apply correct sign/zero extension when promoted to `int` (validated by Darwin native smoke tests).

### Current status, trajectory, and next milestones

The Darwin backend is now at the point where it can compile and run a growing set of “real C” patterns on macOS arm64, while still being intentionally conservative:

- It is still a **bring-up backend**: lots of constructs fail fast with a clear error.
- The pipeline is stable end-to-end via `clang` (assemble/link), and we keep correctness anchored by `make darwin-native-smoke`.

Near-term (next “high leverage” increments)

- **More expression coverage**: comma operator, more unary/cast cases, and more 64-bit expression coverage.
- **Pre/post increment/decrement**: `++i`, `i++`, `--i`, `i--` (including use as expression statements).

Medium-term

- **Richer globals**: more init forms (init blobs, arrays/struct init), more reliable section placement.
- **Function pointers**: `&fn`, calls through function pointers.
- **Structs**: layout + member access + copies (still incremental; member access + basic copies are now supported in the bring-up backend).

Longer-term / harder parts

- **Floats** and ABI details.
- **Varargs** calling convention.
- **Inline asm** (currently x86_64-shaped) for arm64.

The guiding principle remains: expand one small feature at a time, add a focused `examples/ret42_*.c` test, and extend `darwin-native-smoke` so regressions get caught immediately.

#### Stage 2 — External assemble + link (via clang)

On macOS, the most robust way to use “external `as` and `ld`” is to drive them through `clang`:

- Assemble: `clang -c out.s -o out.o`
- Link: `clang out.o -o a.out`

Reasons:

- Darwin/Mach-O has a lot of defaults (platform load commands, SDK selection, min version, codesigning entitlements in some cases) that `clang` manages reliably.

Implementation notes:

- You may need Mach-O symbol spelling conventions (notably leading underscores for global symbols) and section directives compatible with Apple’s assembler.

Deliverable:

- `./monacc … -o hello` produces a native arm64 macOS executable that runs.

Current repo status:

- `make darwin-native-smoke` builds `bin-host/monacc`, compiles several `examples/ret42_*.c` programs to native arm64 macOS binaries, and runs them (expects exit code 42). The smoke suite now includes cases that exercise control flow, calls with args, string literal pointer args (`puts`), globals, pointer arithmetic + indexing, `char/short` sign/zero extension, and `++/--`.

#### Stage 3 — Expand coverage until it can compile real code

Once Stage 2 works for a tiny subset, expand incrementally:

- more expression forms
- more robust stack layout and register allocation decisions
- globals (data / rodata) and relocations (initially let the assembler handle most relocations)
- function pointers

At this stage, it becomes realistic to compile larger self-tests and potentially a subset of the tools *as hosted programs*.

#### Stage 4 (optional, later) — Native Mach-O object emission / internal linker

Only if desired:

- Implement Mach-O `.o` writing (replacement for `compiler/monacc_elfobj.c`).
- Implement a Mach-O link step or a minimal internal linker.

This is a large chunk of work; using `clang` to assemble/link is the pragmatic early path.

### Known hard parts / risk areas

- **New backend**: the existing codegen is deeply x86_64-shaped (register set, instruction forms, SysV rules).
- **Inline asm**: current inline-asm support is x86_64-oriented; arm64 support is non-trivial. Consider initially treating inline asm as unsupported on the Darwin target.
- **Runtime model choice**: “freestanding syscall-only Darwin binaries” is possible but significantly harder than a hosted `main` + libc target.

### What has been done already (macOS work so far)

Both tracks are active:

- A hosted macOS build path for tools (Apple clang).
- A hosted macOS build of the compiler plus an `aarch64-darwin` target backend used by `darwin-native-smoke`.

Completed changes (high level):

- Added a Darwin hosted backend in `core/` (`core/mc_syscall_darwin.h`) so tools can run on macOS by calling libc/POSIX and returning `-errno`.
- Kept Linux syscall-only behavior isolated (Linux x86_64 inline-syscall backend lives in `core/mc_syscall_linux_x86_64.h`).
- Added hosted build targets and output isolation in the top-level Makefile:
   - `make darwin-tools` → builds tools into `bin-host/`
   - `make darwin-smoke` and `make darwin-net-smoke` → basic runtime validation
- Fixed IPv6 networking ABI issues on macOS (sockaddr translation) and ensured hosted tools rebuild when core headers change (Makefile header prerequisites).

Tool-side source changes (kept minimal; unavoidable portability nits):

- `tools/pwd.c`: removed an x86-only inline `hlt` on error paths (replaced with a normal exit).
- `tools/who.c`: renamed a field that collided with macOS header macros (`__unused`).

Everything else for the tools port was implemented in `core/` and the Makefile.
