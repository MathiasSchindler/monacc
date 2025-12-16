# monacc status

Date: 2025-12-16 (Updated)

This document tracks the current state of the monacc compiler and userland tools.

---

## Part 1: Compiler Status

### Build

- `make` produces a size-optimized stripped binary (~103 KB) + all 70 tools
- `make test` runs the full test suite (39 examples + tool tests)
- `make selfhost` builds the compiler with itself
- `make clean` removes build artifacts

### Codebase Shape

- Multi-file compiler under `compiler/monacc_*.c` with shared header `compiler/monacc.h`
  - `monacc_main.c` — entry point and argument handling
  - `monacc_front.c` — tokenizer and lexer
  - `monacc_pp.c` — preprocessor
  - `monacc_parse.c` — parser (~2,500 lines)
  - `monacc_ast.c` — AST node creation
  - `monacc_codegen.c` — code generation (~2,300 lines)
  - `monacc_str.c` — string builder utilities (~350 lines)
  - `monacc_elfobj.c` — ELF object emission (experimental)
  - `monacc_fmt.c` — formatting helpers
  - `monacc_sys.c` — syscall wrappers
- Entry: custom `_start` (Linux x86_64) in `core/mc_start.c`
- Build flags: `-nostartfiles -Wl,-e,_start -fno-stack-protector`

### Toolchain

- By default, monacc uses internal ELF object emission (`--emit-obj`) and then links with `ld`
- Fallback: external `as` + `ld` (e.g. with `EMITOBJ=0` in the Makefile)
- Supports `--toolchain <dir>`, `--as <path>`, `--ld <path>` overrides (note: `--as` is only used in the external-assembler path)

### Frontend

#### Tokenizer / Lexer

**Works:**
- Identifiers, integer literals, string/char literals
- Operators: arithmetic, comparisons, logical ops, bitwise `&`, `|`, `^`
- Compound assignments: `|=`, `^=`, etc.

**Limitations:**
- Not a full C lexer (only what tools require)

#### Micro-preprocessor

**Works:**
- `#include "..."` with search (including-file directory + `-I` directories)
- `#include <...>` (parsed same as `"..."`)
- Object-like `#define NAME replacement`
- `-DNAME[=VALUE]`
- `#pragma once`
- `#ifdef/#ifndef/#else/#endif`
- Macro expansion with recursion guard

**Intentional limitations:**
- No function-like macros
- No full `#if` expression evaluation

### Parser / Type System

**Works:**
- Statements: blocks, `return`, `if/else`, `while`, `for`, `break`, `continue`, `switch/case`, `goto`
- Types: `int/char/void`, pointers, structs, enums
- Inline struct definitions (`struct { int a; } x;`)
- Type modifiers: `unsigned`, `signed`, `short`, `long`
- `long long` treated same as `long`
- Integer constant expressions (enum initializers, array sizes)
- `typedef` with multiple declarators, function-pointer syntax
- Direct and indirect calls (function pointers)
- SysV >6 args support
- Variadic marker `...` in prototypes
- Adjacent string literal concatenation (`"a" "b"`)

### Codegen

- Emits AT&T x86_64 assembly
- Links with `ld --gc-sections` (unused code/data dropped)
- Size optimizations: `ld -n`, `-z max-page-size=0x1000`, `-z common-page-size=0x1000`
- Supports multiple `.c` inputs → single binary
- Dead code elimination: uncalled `static` functions are not emitted
- Basic inlining: `static inline` functions with single `return expr;` body are inlined at call sites
- Trivial main inlining: `main() { return N; }` is inlined directly into `_start`
- Skip codegen for `(void)param;` cast-to-void statements
- Direct register loading: syscall and function call arguments that are constants are loaded directly into target registers (avoids push/pop sequences)
- Optimized conditional branches: comparison expressions in `if`/`while`/`for` conditions emit `cmp` + direct conditional jump (e.g., `jne`) instead of `setcc` + `test` + `jz`

### Self-hosting Status

- monacc can compile itself into `.o` files
- Linked with host toolchain → `monacc-self`
- `monacc-self` can compile and run example programs
- Uses a minimal SELFHOST shim header (`compiler/monacc_selfhost.h`) to avoid relying on full libc headers/macros
- Codegen avoids varargs formatting in SELFHOST builds

---

## Part 2: Tool Status

All 70 tools compile and link successfully with monacc.

### Tool Feature Matrix

| Tool | Current Features | Notes |
|------|------------------|-------|
| `[` / `test` | Condition evaluation (`-e`, `-f`, `-d`, `-z`, `-n`, `=`, `!=`, `-eq`, `-lt`, etc.) | Shell scripting |
| `awk` | `print`, fields `$n`, `/regex/`, numeric patterns, `-F` | Designed for pipelines |
| `basename` | Strip path prefix; suffix stripping | Pure string logic |
| `cat` | Stream files/stdin, `-n`, `-b`, `-s` | — |
| `chmod` | Numeric + symbolic modes | Uses `fchmodat` |
| `chown` | Numeric `uid:gid` only | Syscall-only |
| `clear` | ANSI `\033[H\033[2J` | — |
| `cmp` | Bytewise compare; exit 0/1 | — |
| `col` | Handles `\b` and `\r` overstrikes | Fixed max columns |
| `column` | Align whitespace-delimited columns | Fixed input caps |
| `cp` | Regular files + symlinks; `-r/-R`, `-p` | Recursion depth capped |
| `cut` | `-f` fields; `-d` delimiter | — |
| `date` | Epoch seconds; `+FORMAT` (UTC) | Uses `clock_gettime` |
| `df` | `statfs`-based totals; `-h`, `-T`, `-H` | — |
| `diff` | Line-based diff; `-u` unified | First mismatch only |
| `dirname` | Path parent | Pure string logic |
| `du` | Directory traversal; `-s` | Byte sizes |
| `echo` | `-n`, `-e/-E` escapes | — |
| `env` | Print env; `-i`, `-u`, `-0`; exec | — |
| `expr` | Arithmetic/comparison (`+ - * / %`, `= != < <= > >=`) | — |
| `false` | Exit 1 | — |
| `find` | `-name`, `-type`, `-mindepth/-maxdepth`, `-exec`, `-print` | No symlink dir follow |
| `free` | `/proc/meminfo` mem/swap | KiB values |
| `grep` | Regex matching; `-i/-v/-c/-n/-q/-F` | BRE-ish subset |
| `head` | `-n N`, `-c N` | — |
| `hexdump` | Canonical hex+ASCII | 16-byte rows |
| `hostname` | `uname` nodename | — |
| `id` | Numeric `uid/gid/groups`; `-u`, `-g` | — |
| `init` | Minimal init | — |
| `kill` | `kill PID...`; `kill -N PID...`; `kill -l` | — |
| `ln` | Hard link; `-s`, `-f` | — |
| `ls` | `-a`, `-l`, `-h`, `-R`; name-sorted | Recursion depth capped |
| `mkdir` | `-p`, `-m MODE` | — |
| `more` | Minimal pager (24 lines) | — |
| `mount` | Lists mounts via `/proc/self/mountinfo` | Read-only |
| `mv` | `renameat` fast-path; EXDEV fallback | — |
| `nl` | Number lines; `-ba` | — |
| `nproc` | Online CPUs via affinity | — |
| `od` | Octal dump (bytewise) | — |
| `paste` | Merge files; `-d`, `-s` | — |
| `printf` | `%s/%d/%u/%x/%c/%%`; width/precision | — |
| `ps` | PID + comm from `/proc` | — |
| `pwd` | Print cwd | — |
| `readlink` | Print symlink target; `-f` canonicalize | — |
| `realpath` | Same as `readlink -f` | Alias |
| `rev` | Reverse bytes per line | Fixed max line |
| `rm` | Unlink; `-f`, `-r`, `-d` | Recursion depth capped |
| `rmdir` | Remove empty dir; `-p` | — |
| `sed` | `s/REGEX/REPL/[g][p]`, `d`, `p`, `-n`, `-e`; addressing; hold space | Captures `\(\)` + `\1..\9` |
| `seq` | Integer sequences | `seq LAST`, `seq FIRST LAST`, `seq FIRST INCR LAST` |
| `sh` | `-c CMD`, `sh FILE`; pipes, `&&/||`, redirects, quotes; `if/while/for`; `$NAME`, `$0..$N`, `$#`, `$@` | Minimal shell |
| `sleep` | Seconds; decimal fractions | Uses `nanosleep` |
| `sort` | In-memory; `-r`, `-u`, `-n` | — |
| `stat` | File info; `-l` lstat | — |
| `strings` | Printable ASCII runs; `-n N` | — |
| `tail` | `-n N`, `-c N`, `-f` follow | — |
| `tee` | Write to stdout + files; `-a` | — |
| `test` | Same as `[` | — |
| `time` | Run cmd; print elapsed | — |
| `touch` | Create if missing; `-t` set times | — |
| `tr` | 1:1 translate; `-d`, `-s` | — |
| `true` | Exit 0 | — |
| `uname` | System info; `-m`, `-a` | — |
| `uniq` | Adjacent de-dup; `-c`, `-d`, `-u` | — |
| `uptime` | `/proc/uptime` + loadavg | — |
| `watch` | Rerun command every N seconds | Ctrl-C to stop |
| `wc` | `-l/-w/-c` | — |
| `which` | Search `$PATH`; `-a` all matches | — |
| `who` | `USER TTY` from utmp | May be empty |
| `whoami` | Numeric uid | — |
| `xargs` | `-n N`, `-I REPL` | — |
| `yes` | Repeat line to stdout | — |

---

## Part 3: Dependency Reduction

### Current State

| Phase | Dependencies |
|-------|--------------|
| Building monacc | Host `cc` (gcc/clang), system headers |
| Running monacc | Hosted program (can be static) |
| Building tools | Default: internal `--emit-obj` + `ld` (external `as` optional fallback) |
| Running tools | Linux kernel only |

### Progress

**Implemented:**
- Custom `_start` entrypoint (no CRT)
- Internal syscall wrappers (no libc `syscall()`)
- Internal string/memory functions (`monacc_strlen`, `monacc_memcpy`, etc.)
- Internal allocator (mmap-backed bump allocator)
- Internal file I/O via raw syscalls
- Internal process spawning (`clone/execve/wait4`)
- Internal PATH search (`xexecvp`)
- Toolchain pinning (`--toolchain`, `--as`, `--ld`)
- Experimental ELF object emission (`--emit-obj`)

**Remaining:**
- External `as` no longer required for the default build (kept as an optional fallback)
- External `ld` still required
- Host `cc` needed to bootstrap

---

## Part 4: Testing

### Test Suite

`make test` runs:
1. **Example programs** (39 tests) — compiler correctness
2. **Tool smoke tests** — basic functionality
3. **Tool integration tests** — realistic usage
4. **Tool realworld tests** — recipe-style scenarios

### Test Results

| Suite | Status |
|-------|--------|
| Compiler examples | ✅ 39/39 pass |
| Tool tests | ✅ All pass |
| Self-hosting | ✅ monacc-self builds and runs simple examples |

**Note:** The previously reported selfhosted inline-asm breakage is no longer reproducible on current `main`: `bin/monacc-self` can compile+run `examples/asm_syscall.c` and `examples/inline_asm.c`. The earlier failure was due to SELFHOST varargs handling (missing `va_list`), which is now fixed.

**Note:** The `--emit-obj` test runs as part of `make test` by default and is treated like a normal test (it will fail `make test` if it fails). You can skip it with `SELFTEST_EMITOBJ=0 make test`.

---

## Summary

| Milestone | Status |
|-----------|--------|
| Compiler builds | ✅ |
| All 70 tools compile | ✅ |
| Tools pass tests | ✅ |
| Self-hosting works | ✅ (simple examples) |
| Selfhost inline asm | ✅ Works on current `main` |
| Internal ELF emission | ✅ SELFTEST_EMITOBJ probe passes (still incomplete overall) |
| No external assembler | 🔜 Planned |
| No external linker | 🔜 Planned |

---

## Kernel (separate subproject)

This repository also includes an optional kernel in kernel/ that is intended to run monacc-built userland under QEMU. Kernel progress and plans are tracked separately:

- kernel/status.md (current implemented state; Phases 0–3 completed)
- kernel/plan.md (roadmap, design notes, and monacc-specific kernel workarounds)
