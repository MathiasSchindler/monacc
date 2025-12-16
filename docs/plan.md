# monacc - Codebase Unification Plan

Date: 2025-12-16

This document outlines the roadmap for eliminating redundancies, removing shims, and improving the monacc codebase following the merger of the compiler and tools projects.

---

## Guiding Principles

1. **No shims when a clean solution exists.** Since we control the entire toolchain, we can either:
   - Improve the compiler to support the construct
   - Change the source code to only use what the compiler provides

2. **Prefer shared `mc_*` APIs** over `#ifdef MONACC` or `#ifdef SELFHOST` branches.

3. **Verify assumptions before acting.** Recent progress on inline asm support may have invalidated some workarounds. Always check current compiler capabilities before implementing a fix.

4. **Test-driven changes.** Every change must pass `make test` (all 29 compiler examples + tool tests).

5. **Priority order: Run → Small → Fast.** Code must work correctly first, then be small, then be fast.

6. **Self-contained ecosystem.** All tools within scope are in this codebase. There is no third-party software dependency outside this repository. The compiler, tools, and kernel form a complete system.

---

## Long-Term Vision

The end state for monacc:

1. **Fully self-contained** — no external `as`, `ld`, or libc required
2. **Self-hosting** — monacc compiles itself
3. **Complete userland** — all tools in `tools/` compile and run
4. **Kernel support** — the kernel in `kernel/` compiles and boots

The `core/` directory is effectively the project's own minimal libc — syscall-based, no external dependencies, exactly what's needed and nothing more.

---

## Phase 0: Compiler Size Reduction

The monacc binary is currently ~100 KB. This phase focuses on reducing compiler size through code deduplication without removing any features.

### 0.1 Deduplicate `cg_binop()` Peephole Patterns

**What:** The `cg_binop()` function in `compiler/monacc_codegen.c` (lines 943-1377) contains ~300 lines of nearly identical peephole optimization code. The patterns for constant LHS and constant RHS are mirrors of each other.

**Why:** This is pure code duplication that inflates the binary by ~2-4 KB without adding any functionality. The same optimizations (inc/dec for ±1, shift for power-of-2 multiply, etc.) are written twice.

**How:**
1. Extract a helper function:
   ```c
   static void emit_arith_imm(CG *cg, ExprKind kind, long long imm, int is_lhs_const);
   ```
2. Have both the constant-LHS and constant-RHS paths call this helper
3. The helper handles the operation emission; the caller handles operand evaluation order

**Testing:**
```bash
make clean && make
make test
# Verify binary size decreased
ls -la bin/monacc
```

---

### 0.2 Extract Load/Store Size Helpers

**What:** The same 1/2/4/8-byte load and store patterns appear 10+ times throughout `monacc_codegen.c` for handling different lvalue sizes and signedness.

**Why:** Each occurrence is ~15-20 lines of repetitive if/else chains. Extracting helpers removes ~150 lines of duplicate code and ~2-3 KB from the binary.

**How:**
1. Create helper functions:
   ```c
   static void emit_load(CG *cg, const char *addr, int size, int is_unsigned);
   static void emit_store(CG *cg, const char *addr, int size);
   ```
2. Replace all inline size-switch patterns with calls to these helpers
3. Patterns to consolidate: EXPR_VAR, EXPR_GLOBAL, EXPR_DEREF, EXPR_INDEX, EXPR_MEMBER, PREINC, PREDEC, POSTINC, POSTDEC

**Testing:**
```bash
make clean && make
make test
```

---

### 0.3 Generic AST Visitor Pattern

**What:** Three similar recursive AST walker functions exist:
- `expr_count_var_uses()` + `stmt_count_var_uses()`
- `expr_contains_nonsyscall_call()` + `stmt_contains_nonsyscall_call()`
- `expr_uses_frame_pointer()` + `stmt_uses_frame_pointer()`

Each pair has identical traversal structure, differing only in what they check.

**Why:** ~200 lines of repetitive traversal code. A generic visitor removes duplication and makes adding new analyses easier.

**How:**
1. Create a generic visitor:
   ```c
   typedef int (*ExprPredicate)(const Expr *e, void *ctx);
   typedef int (*StmtPredicate)(const Stmt *s, void *ctx);
   int expr_any(const Expr *e, ExprPredicate pred, void *ctx);
   int stmt_any(const Stmt *s, ExprPredicate epred, StmtPredicate spred, void *ctx);
   ```
2. Reimplement existing functions using the visitor:
   ```c
   static int is_var_use(const Expr *e, void *ctx) {
       int *off = ctx;
       return e->kind == EXPR_VAR && e->var_offset == *off;
   }
   int expr_count_var_uses(const Expr *e, int off) {
       return expr_any(e, is_var_use, &off);
   }
   ```

**Testing:**
```bash
make clean && make
make test
```

---

### 0.4 Consolidate `str_appendf_*` Format Parsing

**What:** `compiler/monacc_str.c` has 7 type-specific format functions (`str_appendf_i64`, `str_appendf_u64`, `str_appendf_s`, etc.), each with ~30 lines of nearly identical format string parsing.

**Why:** The format parsing logic (finding `%s`, `%d`, etc.) is duplicated in each function. A single parser with callbacks would be smaller.

**How:**
1. Create an internal format string iterator:
   ```c
   // Walks format string, calls back for each literal span and each format specifier
   static void fmt_walk(const char *fmt, void (*on_lit)(const char *, size_t, void *),
                        void (*on_spec)(char spec, void *), void *ctx);
   ```
2. Reimplement `str_appendf_*` using this walker
3. Each function provides its own `on_spec` callback that appends the appropriate value

**Testing:**
```bash
make clean && make
make selfhost
make test
```

---

### 0.5 Size Reduction Summary

| Change | Est. Code Reduction | Est. Binary Reduction |
|--------|---------------------|----------------------|
| Deduplicate `cg_binop()` | ~300 lines | 2-4 KB |
| Extract load/store helpers | ~150 lines | 2-3 KB |
| Generic AST visitor | ~200 lines | 1-2 KB |
| Consolidate `str_appendf_*` | ~150 lines | 1-2 KB |
| **Total** | **~800 lines** | **6-11 KB** |

**Target:** Reduce monacc binary from ~100 KB to ~85-90 KB (10-15% reduction) through deduplication alone.

---

## Phase 1: Low-Hanging Fruit (Quick Wins)

### 1.1 Eliminate `vfork`/`fork` Shim in Tools

**What:** Multiple tools have this pattern:
```c
mc_i64 pid =
#ifdef MONACC
    mc_sys_fork();
#else
    mc_sys_vfork();
#endif
```

**Why:**
- `vfork()` is a micro-optimization that adds complexity
- Modern Linux `fork()` with CoW is efficient for these small tools
- The tools immediately call `execve()` after fork, so there's no significant benefit
- Removing the shim simplifies the code and eliminates a `#ifdef`

**How:**
1. Replace all `#ifdef MONACC ... mc_sys_fork() ... #else ... mc_sys_vfork()` blocks with just `mc_sys_fork()`
2. Remove dead `vfork` references

**Affected files:** `tools/init.c`, `tools/time.c`, `tools/watch.c`, `tools/find.c`, `tools/sh.c`, `tools/xargs.c`

**Before proceeding:** Check if monacc now properly supports the inline asm in `mc_sys_vfork()`. If it does, we could use `vfork` everywhere instead. Test by compiling a tool that uses `vfork` with monacc and verify it works.

**Testing:**
```bash
make clean && make
make test
# Specifically test fork-heavy tools:
bin/sh -c 'echo hello | cat'
bin/find . -name "*.c" -exec echo {} \;
bin/time bin/true
```

---

### 1.2 Consolidate Duplicated Helper Functions in Tools

**What:** Several functions are copy-pasted across tools with different prefixes:

| Function | Appears in |
|----------|------------|
| `*_exit_code_from_wait_status()` | `time.c`, `watch.c`, `find.c`, `xargs.c`, `sh.c` |
| `*_execvp()` (PATH search + exec) | `time.c`, `watch.c`, `find.c`, `xargs.c`, `sh.c` |

**Why:** Code duplication increases maintenance burden and binary sizes. These are general-purpose utilities that belong in `core/`.

**How:**
1. Add functions to `core/mc.h` and `core/mc_io.c`:
   - `mc_wait_exitcode(mc_i32 status)` 
   - `mc_execvp(const char *file, char **argv, char **envp)`
2. Update each tool to use the shared implementation
3. Remove per-tool duplicates

**Testing:**
```bash
make clean && make
make test
```

---

### 1.3 Unify Type Aliases

**What:** The codebase uses both `size_t`/`ssize_t` (via `monacc_libc.h`) and `mc_usize`/`mc_isize` (via `mc_types.h`).

**Why:** Having two naming conventions for the same types creates confusion and makes the codebase harder to understand. The `mc_*` types are the project's own definitions; `size_t` etc. are shims for libc compatibility.

**How:**
1. In `compiler/` files, replace `size_t` → `mc_usize`, `ssize_t` → `mc_isize`
2. Remove the type redefinitions from `monacc_libc.h`
3. Keep `monacc_libc.h` minimal (just POSIX constants like `O_RDONLY`)

**Testing:**
```bash
make clean && make
make selfhost  # Verify self-hosted build still works
make test
```

---

## Phase 2: Compiler/Core Integration

### 2.1 Unify `str_appendf` API

**What:** `compiler/monacc_str.c` has two implementations:
- `#ifdef SELFHOST`: Type-specific functions (`str_appendf_i64`, `str_appendf_s`, etc.) that manually parse format strings
- `#else`: Variadic `str_appendf(fmt, ...)` using `va_list`

**Why:** The type-specific functions already exist and work. Making them the canonical API:
- Removes the need for varargs support in monacc
- Is slightly more type-safe
- Simplifies the code (one implementation instead of two)

**How:**
1. Keep `str_appendf_i64`, `str_appendf_u64`, `str_appendf_s`, `str_appendf_ss`, `str_appendf_si`, `str_appendf_su`, `str_appendf_is` as the primary API
2. In non-SELFHOST builds, have these call the existing implementation (no change needed)
3. Remove the variadic `str_appendf(fmt, ...)` or deprecate it
4. Update callers in `compiler/*.c` to use the type-specific functions directly

**Testing:**
```bash
make clean && make
make selfhost
# Run self-hosted compiler on example programs
bin/monacc-self examples/hello.c -o /tmp/hello && /tmp/hello
make test
```

---

### 2.2 Evaluate Compiler's Current Inline Asm Capabilities

**What:** The compiler has inline asm support including:
- GNU-style `__asm__ volatile` parsing
- Constraint handling (`=a`, `r`, `m`, `i`, `n`, `0`-`9`)
- `%w0`/`%b0` operand modifiers for sized registers
- Clobber lists

**Why:** Recent progress on inline asm may have invalidated workarounds. Before making changes, we need to know what actually works.

**How:**
1. Test: Can monacc compile the inline asm syscall stubs in `core/mc_syscall.h`?
   ```bash
   # Test: compile a tool without -DMONACC and see if inline asm works
   bin/monacc -c core/mc_syscall.h -o /tmp/test.o
   ```

2. If inline asm works, the `#ifdef MONACC` path in `mc_syscall.h` (which declares `mc_syscall0..6` as extern) may be obsolete.

**Testing:**
Create a test program that uses inline asm syscalls directly:
```c
// examples/asm_syscall.c
#include "core/mc.h"

int main(void) {
    mc_sys_write(1, "Hello via inline asm\n", 21);
    return 0;
}
```
```bash
bin/monacc examples/asm_syscall.c -o /tmp/asm_test
/tmp/asm_test
```

---

### 2.3 Eliminate SELFHOST Syscall Fallback

**What:** `compiler/monacc_sys.c` has parallel syscall implementations:
```c
#ifdef SELFHOST
static int xs_openat(...) { return syscall(MC_SYS_openat, ...); }
#else
static int xsys_openat(...) { return mc_sys_openat(...); }
#endif
```

**Why:** This duplication exists because SELFHOST builds couldn't use the inline asm syscall stubs. If monacc now handles inline asm (or the `mc_syscall0..6` lowering), this shim is obsolete.

**How:**
1. If inline asm works in monacc: remove the `#ifdef SELFHOST` branches
2. If not: ensure `mc_syscall0..6` lowering works in self-hosted builds

**Dependencies:** Phase 2.2 must confirm inline asm syscalls work in self-hosted builds.

**Testing:**
```bash
make selfhost
bin/monacc-self examples/hello.c -o /tmp/hello && /tmp/hello
make test
```

---

## Phase 3: Deeper Unification

### 3.1 Merge Compiler Utilities into Core

**What:**
| `compiler/` file | `core/` equivalent | Overlap |
|------------------|-------------------|---------|
| `monacc_str.c` | (none) | String builder |
| `monacc_fmt.c` | `mc_fmt.c` | Error formatting |
| `monacc_sys.c` | `mc_io.c`, `mc_syscall.h` | File I/O, syscalls |

**Why:** The compiler maintains parallel implementations of utilities that could be shared with tools. Unifying reduces total code size and maintenance burden.

**How:**
1. Move `Str` (string builder) to `core/` as it's useful for tools too
2. Consolidate I/O wrappers into `core/mc_io.c`
3. Have compiler link against `core/` objects

**Challenges:**
- The compiler has its own allocator (`monacc_malloc`) for SELFHOST compatibility
- Need to ensure no circular dependencies

**Testing:**
```bash
make clean && make
make selfhost
make test
```

---

### 3.2 Shrink or Eliminate `compiler/selfhost/` Headers

**What:** `compiler/selfhost/` contains minimal stub headers so monacc can compile itself without full libc headers:
- `errno.h`, `fcntl.h`, `limits.h`, `stdarg.h`, `stdbool.h`, `stdint.h`, `stdio.h`, `stdlib.h`, `string.h`, `unistd.h`

**Why:** These stubs are a compatibility layer. As monacc improves and uses `core/` directly, they become unnecessary.

**How:**
1. Audit each stub header: what declarations are actually used?
2. Move essential declarations to `monacc_libc.h` or `mc_*.h`
3. Eventually: compile with `-I core` only

**Testing:**
```bash
make selfhost
bin/monacc-self examples/hello.c -o /tmp/hello && /tmp/hello
make test
```

---

## Phase 4: Eliminate External Dependencies

### 4.1 Eliminate `as` Dependency

**What:** Currently, monacc emits textual assembly and calls external `as` to assemble it.

**Why:** The long-term goal is a fully self-contained toolchain with no external dependencies.

**How:** `monacc_elfobj.c` already implements an internal x86_64 ELF assembler. The `--emit-obj` flag uses it.
1. Verify `--emit-obj` produces correct output for all examples
2. Make internal assembly the default path
3. Remove the external `as` invocation

**Testing:**
```bash
# Test internal assembler on all examples
for ex in examples/*.c; do
    bin/monacc --emit-obj "$ex" -o /tmp/test && echo "OK: $ex"
done
make test
```

---

### 4.2 Eliminate `ld` Dependency

**What:** Currently, monacc relies on external `ld` for linking.

**Why:** Same as above — full self-containment.

**How:** Implement a minimal ELF linker in the compiler. This is the most complex remaining dependency.

**Note:** This is a significant undertaking. May be deferred or implemented incrementally.

---

## Phase 5: Compiler Improvements (If Needed)

These items should only be pursued if they unlock significant codebase simplification or are required for tools/kernel.

### 5.1 Fix `sizeof(array)` Bug

**What:** `sizeof(array)` returns the element size instead of the array size. Documented in `kernel/status.md`.

**Why:** This is a correctness bug that requires workarounds in the kernel and potentially tools.

**How:** Fix in `compiler/monacc_parse.c` or `monacc_codegen.c`.

**Testing:**
```c
// examples/sizeof_array.c
int main(void) {
    int arr[10];
    if (sizeof(arr) != 40) return 1;  // Should be 10 * 4 = 40
    return 0;
}
```
```bash
bin/monacc examples/sizeof_array.c -o /tmp/test && /tmp/test && echo OK
```

---

### 5.2 Fix `__attribute__((packed))` Struct Layout

**What:** Packed attribute is not honored for struct member offsets. Documented in `kernel/status.md`.

**Why:** Required for kernel hardware structures (TSS, etc.) and any protocol/binary format handling.

**How:** Fix in parser/type system to track `is_packed` and skip alignment padding.

**Testing:**
```c
// examples/packed_struct.c
struct __attribute__((packed)) test {
    char a;
    int b;  // Should be at offset 1, not 4
};
int main(void) {
    if (sizeof(struct test) != 5) return 1;
    return 0;
}
```
```bash
bin/monacc examples/packed_struct.c -o /tmp/test && /tmp/test && echo OK
```

---

### 5.3 Consider Varargs Support

**What:** monacc doesn't support `va_list`, `va_start`, `va_arg`.

**Why:** SELFHOST builds need manual format string parsing; can't use variadic functions.

**Decision point:**
- If Phase 2.1 (type-specific `str_appendf_*`) works well, varargs may not be needed
- Varargs is complex to implement correctly (ABI-specific register/stack handling)
- All tools in scope are in this codebase — we can avoid varargs if desired

**Recommendation:** Defer unless there's a strong use case within the project's own code.

---

## Validation Checklist

Before declaring any phase complete:

- [ ] `make clean && make` succeeds
- [ ] `make test` passes (all compiler examples + all tool tests)
- [ ] `make selfhost` succeeds
- [ ] `bin/monacc-self examples/hello.c -o /tmp/hello && /tmp/hello` works
- [ ] No new `#ifdef MONACC` or `#ifdef SELFHOST` blocks added
- [ ] Any removed `#ifdef` blocks are documented in commit message
- [ ] Binary size tracked (should not increase without justification)

---

## Notes on Testing

### Running specific test suites
```bash
# All tests
make test

# Compiler examples only
sh tests/run_examples.sh

# Tool tests only
sh tests/run.sh smoke
sh tests/run.sh integration
sh tests/run.sh realworld
```

### Debugging failures
```bash
# Verbose test output
SB_TEST_VERBOSE=1 sh tests/run.sh

# Run a single tool manually
bin/monacc tools/cat.c -o /tmp/cat && /tmp/cat /etc/passwd
```

### Checking binary size
```bash
ls -la bin/monacc
size bin/monacc
```

---

## Appendix: Current `#ifdef` Usage

As of 2025-12-16, the following files contain `#ifdef MONACC` or `#ifdef SELFHOST`:

**Tools (MONACC shim):**
- `tools/init.c` - vfork/fork
- `tools/time.c` - vfork/fork
- `tools/watch.c` - vfork/fork
- `tools/find.c` - vfork/fork
- `tools/sh.c` - vfork/fork
- `tools/xargs.c` - vfork/fork

**Compiler (SELFHOST shim):**
- `compiler/monacc_str.c` - varargs workaround
- `compiler/monacc_fmt.c` - varargs workaround
- `compiler/monacc_sys.c` - syscall path
- `compiler/monacc_ast.c` - debug output
- `compiler/monacc.h` - API exposure
- `compiler/monacc_libc.h` - type definitions
- `compiler/monacc_main.c` - emit-obj restriction

**Core:**
- `core/mc_syscall.h` - inline asm vs extern declaration
- `core/mc_vsnprintf.c` - hosted-only implementation

*Note: This list may be incomplete. Run a code search to verify before starting work.*
