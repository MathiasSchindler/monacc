# monacc specification

Date: 2025-12-17

This document captures the goals, constraints, and design decisions for monacc: a self-hosting C compiler for Linux x86_64 with an integrated syscall-only userland.

## Overview

monacc is two things in one:

1. **A C compiler** — small, fast, self-hosting
2. **A userland toolkit** — 99 syscall-only command-line tools built with that compiler

Both components share a common design philosophy: syscall-only, minimal dependencies, Linux x86_64 only.

---

## Part 1: The Compiler

### Goals

**Primary**
- Build a tiny C compiler that can compile all userland tools for Linux x86_64.
- Make it self-hosting (the compiler can compile itself).

**Secondary**
- Keep the compiler small (code size + binary size).
- Keep compilation fast (single-pass-ish; minimal allocations).

### Non-goals

- Full C11 / GCC compatibility.
- Cross-architecture or cross-OS support.
- Full preprocessor (function-like macros, token pasting, full `#if` expression evaluation).
- Debug info, sanitizers, "fancy" diagnostics.
- Implementing GNU inline-asm constraints.
- Full behavioral compatibility with gcc/clang for all edge cases.

### Platform + Scope

- **Target ABI**: Linux x86_64 SysV
- **Data model**: LP64 (`long` is 64-bit)
- **Output**: AT&T x86_64 assembly; by default assembled internally into an ELF64 relocatable (`--emit-obj`) and linked by monacc’s internal linker (`--link-internal`)
   - Fallbacks exist for bring-up/debugging: external `as` (`EMITOBJ=0`) and external `ld` (`LINKINT=0`).
- **Runtime model**: freestanding binaries (syscall-only)

### Compiler Pipeline

1. **Tokenizer**
   - C tokens + numeric literals
   - String/char literals (treated as bytes)
   - Skip comments

2. **Micro-preprocessor**
   - `#include "..."` with include search paths
   - Object-like `#define NAME <replacement...>`
   - `#pragma once`
   - Macro expansion with recursion guard
   - Basic conditionals: `#ifdef/#ifndef/#else/#endif`

3. **Parser + Type Checker**
   - Expressions: integer ops, unary ops, casts, `sizeof`, ternary
   - Declarations: globals, locals, prototypes/definitions
   - Types: `int/char/void`, pointers, arrays, structs, enums, typedefs
   - Parse-and-skip for some GCC extensions (`__attribute__`, `__asm__`)

4. **Codegen (x86_64 SysV)**
   - Emit AT&T assembly
   - Link using monacc’s internal linker by default
   - Dead static function elimination (uncalled `static` functions not emitted)
   - Basic inlining for `static inline` functions with trivial bodies
   - Size-focused: skip no-op constructs, inline trivial `main()`
   - Direct register loading for syscall/function call arguments (avoids push/pop)
   - Optimized conditional branches (comparison → direct jump, no setcc+test)

### Language Subset

The language subset is intentionally tool-driven; monacc does not aim for full C.

**Supported:**
- Integers and pointers (core)
- Type modifiers: `unsigned`, `signed`, `short`, `long`
- `long long` treated the same as `long`
- Structs, enums, typedefs
- Function pointers
- Variadic parameter marker `...` (no full stdarg semantics)

**Not supported:**
- Floating-point
- Function-like macros
- Full `#if` expression evaluation

### Inline Asm Support

monacc supports GNU-style inline assembly:

- `__asm__ volatile` statements with input/output operands
- Common constraint letters: `=a`, `r`, `m`, `i`, `n`, `D`, `S`, `d`, `c`, digit constraints (`0`-`9`)
- Clobber lists (`"rcx"`, `"r11"`, `"memory"`)
- Operand modifiers: `%0`, `%1`, etc.

Notes:
- Sized operand modifiers like `%w0` (16-bit) and `%b0` (8-bit) are supported.
- This is still a pragmatic subset: monacc does not aim to implement the full GNU inline-asm feature set (e.g. complex constraints, constraint alternatives, or exact gcc/clang edge-case behavior).

This allows the `core/mc_syscall.h` syscall wrappers to use inline asm directly, keeping the tools portable between gcc/clang and monacc.

---

## Part 2: The Userland Tools

### Purpose

Build a small, fast, minimal set of command-line tools for a single target:

- **OS**: Linux
- **Arch**: x86_64  
- **Language**: C
- **Dependencies**: Syscalls only (no libc)

This is explicitly **not** trying to be POSIX-complete or portable.

### Non-goals

- Cross-platform support (BSD/macOS/Windows)
- Cross-architecture support (ARM, 32-bit)
- Full GNU coreutils compatibility
- Locale/i18n, wide characters, multibyte correctness beyond "treat UTF-8 as bytes"
- Fancy UX (colors, paging, interactive prompts by default)
- Filesystem feature completeness (ACLs, xattrs, SELinux labels)

### Design Principles

1. **Syscall-first**: Implement behavior using Linux syscalls directly
2. **Minimal bytes**: Optimize for small static binaries; keep code small
3. **Predictable performance**: Avoid allocations; stream data; minimize copies
4. **Explicit limitations**: Document what's intentionally unsupported
5. **Simple parsing**: Small flag subsets; consistent behavior once settled
6. **Consistent exit codes**: 0 success, 1 operational failure, 2 usage error
7. **No global state**: No hidden caches; no background daemons

### Build Strategy

- No libc usage in tool logic (no `printf`, `malloc`, `strerror`, ...)
- Minimal runtime entrypoint (`_start`) provided by the project
- Link with `-nostdlib` and flags to reduce ELF overhead

### CLI Conventions

- Prefer short options; support `--` to end option parsing
- If a tool reads input and no files are given: read stdin
- `-` as an operand means stdin/stdout where relevant
- Error messages are short and stable

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Operational error (I/O error, missing file, partial failure) |
| 2 | Usage error (invalid flags, missing required args) |

---

## Part 3: Shared Principles

### Development Principles

These principles guide day-to-day changes across compiler + tools:

1. **Test-driven changes**: every change must pass `make test`.
2. **Priority order: Run → Small → Fast**: correctness first, then size, then performance.
3. **Self-contained ecosystem**: prefer solutions that reduce external toolchain assumptions.

### Security Model

- Not intended to be setuid/setgid
- Prefer `*at()` syscalls to reduce TOCTOU
- Avoid following symlinks in destructive operations unless explicitly required

### Style Conventions

- C dialect: C11 subset
- No dynamic allocation in tools (fixed buffers, documented limits)
- All outputs via direct `write()` wrappers
- Avoid `stdio.h` entirely

### Known Limitations

- No locale-aware behavior
- Fixed buffer sizes (documented in code)
- Error strings are minimal (errno numbers rather than strerror text)
- Single platform: Linux x86_64 only

---

## Leverage: We Control Everything

Because both the compiler and the tools are in-tree, we can choose between:

- **Extending monacc** when a missing feature is core C, small to implement, and broadly useful
- **Adapting tools** when the construct is GCC-specific or a one-off

Policy:
- Prefer shared `mc_*` APIs
- Keep tools and compiler buildable with gcc/clang as the reference
- No `#ifdef MONACC` blocks remain in tools (as of 2025-12-17)

---

## Related: kernel/

This repository also contains an experimental x86_64 kernel in kernel/.

It is a separate subproject intended to run monacc-built userland under QEMU (Linux syscall ABI). The kernel has its own documentation:

- kernel/status.md
- kernel/plan.md
