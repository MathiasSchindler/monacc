# monacc

**A self-hosting C compiler for Linux x86_64 with a complete syscall-only userland.**

monacc is a small C compiler that can compile itself and a full suite of Unix command-line tools — all without external dependencies beyond the Linux kernel.

## What is this?

This project combines two pieces:

1. **monacc** — A C compiler targeting Linux x86_64 (SysV ABI)
2. **A userland toolkit** — 70 Unix utilities (`cat`, `ls`, `grep`, `sh`, `awk`, etc.)

The compiler compiles the tools. The tools provide the environment needed to build and test the compiler. It's a closed loop.

## Goals

- **Self-hosting**: The compiler can compile itself.
- **Zero runtime dependencies**: Built binaries talk directly to the Linux kernel via syscalls.
- **Minimal toolchain**: Reduce reliance on external assembler/linker (in progress).
- **Small and fast**: Size-optimized binaries, single-pass-ish compilation.

## Project Structure

```
monacc-unified/
├── compiler/       # C compiler implementation
├── core/           # Shared core library (mc_*) used by compiler + tools
├── tools/          # 70 Unix command-line utilities
├── examples/       # Compiler test programs
├── tests/          # Unified test suite
├── scripts/        # Build helpers
├── kernel/         # Optional: minimal x86_64 kernel for running monacc userland under QEMU
└── bin/            # Build output (compiler + all tools)
```

## Kernel (optional)

This repo also contains an experimental kernel in kernel/.

It is a separate subproject intended to run monacc-built userland under QEMU (Linux x86_64 syscall ABI). It is not required to build or use monacc on Linux.

- Status and build/run notes: kernel/status.md
- Roadmap and implementation plan: kernel/plan.md

## Quick Start

```sh
make              # Build everything (compiler, then tools)
make test         # Run the test suite
```

### What gets built

After `make`, the `bin/` directory contains:

| Binary | Description |
|--------|-------------|
| `monacc` | The C compiler |
| `cat`, `ls`, `cp`, `rm`, ... | File utilities |
| `grep`, `sed`, `awk`, ... | Text processing |
| `sh` | A minimal POSIX-ish shell |
| `find`, `xargs`, `test`, ... | Scripting utilities |
| ... | 70 tools total |

## Bootstrapping Sequence

```
Phase 0: Build monacc with host compiler (gcc/clang)
         └─> bin/monacc

Phase 1: Build userland tools with bin/monacc
         └─> bin/{cat,ls,sh,grep,awk,...}

Phase 2: Self-host the compiler
         └─> bin/monacc-self (built by bin/monacc)

Phase 3: (Future) Run build/tests using bin/sh and bin/* tools
         └─> Fully self-contained build environment
```

## Language Subset

monacc implements a subset of C sufficient for systems programming:

**Supported:**
- Integer types: `char`, `short`, `int`, `long` (signed/unsigned)
- Pointers, arrays, structs, enums, typedefs
- Control flow: `if/else`, `while`, `for`, `switch/case`, `goto`
- Operators: arithmetic, bitwise, logical, comparison
- Function pointers, variadic parameter marker (`...`)
- Preprocessor: `#include`, `#define` (object-like), `#ifdef/#ifndef/#else/#endif`, `#pragma once`

**Not supported:**
- Floating-point
- Function-like macros
- `long long` as distinct from `long`
- Full `#if` expression evaluation

## Userland Tools

70 utilities covering common Unix operations:

| Category | Tools |
|----------|-------|
| Basics | `true`, `false`, `echo`, `yes`, `sleep`, `pwd` |
| Files | `cat`, `cp`, `mv`, `rm`, `ln`, `touch`, `mkdir`, `rmdir`, `chmod`, `chown` |
| Text | `head`, `tail`, `sort`, `uniq`, `grep`, `sed`, `awk`, `tr`, `cut`, `wc` |
| Info | `ls`, `stat`, `df`, `du`, `find`, `which`, `uname`, `date`, `id` |
| Scripting | `sh`, `env`, `test`, `printf`, `seq`, `xargs`, `expr` |
| System | `ps`, `kill`, `time`, `diff`, `cmp` |

All tools:
- Use syscalls directly (no libc)
- Are statically linked
- Have no runtime dependencies beyond the Linux kernel
- ELF outputs omit section headers by default for smaller file size (use `--keep-shdr` to retain them for debugging)
- Current sizes (monacc-built, stripped): ~195 bytes (`true`) up to ~29KB (`sh`) (exact sizes change as codegen improves)

## Build Requirements

**To build monacc (Phase 0):**
- A C compiler (`gcc` or `clang`)
- GNU linker (`ld`)
- Linux x86_64

**After Phase 1:**
- Only `as` and `ld` are needed (monacc replaces the C compiler)
- By default, the build uses internal ELF object emission (`--emit-obj`) which eliminates `as`
    (set `EMITOBJ=0` to force the external assembler).

## Current Status

| Milestone | Status |
|-----------|--------|
| Compiler builds | ✅ |
| All 70 tools compile with monacc | ✅ |
| Tools pass test suite | ✅ |
| Compiler self-hosts (compiles itself) | ✅ |
| Self-hosted compiler runs examples | ✅ |
| Internal ELF object emission | 🔄 Experimental |
| Build scripts run on built `sh` | 🔜 Planned |

## Design Principles

1. **Syscalls only** — No libc dependency in output binaries
2. **Static binaries** — Each tool is standalone
3. **Size-oriented** — Compiled with `-Os`, LTO, `--gc-sections`
4. **Scope-limited** — Implements what's needed, not everything
5. **Single platform** — Linux x86_64 only, no abstraction layers

## License

**CC0 1.0 Universal (Public Domain)**

This project is released into the public domain. You can copy, modify, and distribute it without permission or attribution.

## Provenance

The vast majority of this code was written with assistance from large language models:
- Claude Opus 4.5 (Anthropic)
- GPT-5.2 (Preview)

This is stated explicitly so readers have the right context when evaluating the code.

## Author

Created by Mathias with substantial help from AI assistants via GitHub Copilot.
