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

---

## Phase 1: Low-Hanging Fruit (Quick Wins)

### 1.1 Eliminate `vfork`/`fork` Shim in Tools

**Current state:**
Multiple tools have this pattern:
```c
mc_i64 pid =
#ifdef MONACC
    mc_sys_fork();
#else
    mc_sys_vfork();
#endif
```

**Affected files:** `tools/init.c`, `tools/time.c`, `tools/watch.c`, `tools/find.c`, `tools/sh.c`, `tools/xargs.c`

**Goal:** Use `mc_sys_fork()` unconditionally everywhere.

**Rationale:**
- `vfork()` is a micro-optimization that adds complexity
- Modern Linux `fork()` with CoW is efficient for these small tools
- The tools immediately call `execve()` after fork, so there's no significant benefit

**Implementation:**
1. Replace all `#ifdef MONACC ... mc_sys_fork() ... #else ... mc_sys_vfork()` blocks with just `mc_sys_fork()`
2. Remove dead `vfork` references

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

**Current state:**
Several functions are copy-pasted across tools with different prefixes:

| Function | Appears in |
|----------|------------|
| `*_exit_code_from_wait_status()` | `time.c`, `watch.c`, `find.c`, `xargs.c`, `sh.c` |
| `*_execvp()` (PATH search + exec) | `time.c`, `watch.c`, `find.c`, `xargs.c`, `sh.c` |

**Goal:** Move common functionality to `core/`:
- `mc_wait_exitcode(mc_i32 status)` → `core/mc_io.c`
- `mc_execvp(const char *file, char **argv, char **envp)` → `core/mc_io.c`

**Implementation:**
1. Add functions to `core/mc.h` and `core/mc_io.c`
2. Update each tool to use the shared implementation
3. Remove per-tool duplicates

**Testing:**
```bash
make clean && make
make test
```

---

### 1.3 Unify Type Aliases

**Current state:**
The codebase uses both `size_t`/`ssize_t` (via `monacc_libc.h`) and `mc_usize`/`mc_isize` (via `mc_types.h`).

**Goal:** Standardize on `mc_*` types throughout.

**Implementation:**
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

**Current state:**
`compiler/monacc_str.c` has two implementations:
- `#ifdef SELFHOST`: Type-specific functions (`str_appendf_i64`, `str_appendf_s`, etc.) that manually parse format strings
- `#else`: Variadic `str_appendf(fmt, ...)` using `va_list`

**Goal:** Make the type-specific functions the canonical API.

**Rationale:**
- The type-specific functions already exist and work
- They don't require varargs support
- They're slightly more type-safe

**Implementation:**
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

**Current state:**
The compiler has inline asm support including:
- GNU-style `__asm__ volatile` parsing
- Constraint handling (`=a`, `r`, `m`, `i`, `n`, `0`-`9`)
- `%w0`/`%b0` operand modifiers for sized registers
- Clobber lists

**Before proceeding with further changes, verify:**

1. Can monacc compile the inline asm syscall stubs in `core/mc_syscall.h`?
   ```bash
   # Test: compile a tool without -DMONACC and see if inline asm works
   bin/monacc -c core/mc_syscall.h -o /tmp/test.o
   ```

2. If inline asm works, the `#ifdef MONACC` path in `mc_syscall.h` (which declares `mc_syscall0..6` as extern) may be obsolete.

**Goal:** Document which inline asm features work and update the codebase accordingly.

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

**Current state:**
`compiler/monacc_sys.c` has parallel syscall implementations:
```c
#ifdef SELFHOST
static int xs_openat(...) { return syscall(MC_SYS_openat, ...); }
#else
static int xsys_openat(...) { return mc_sys_openat(...); }
#endif
```

**Goal:** Use the same syscall path in both builds.

**Dependencies:**
- Phase 2.2 must confirm inline asm syscalls work in self-hosted builds
- Or: self-hosted builds should use `mc_syscall0..6` (which monacc lowers to `syscall` instructions)

**Implementation:**
1. If inline asm works in monacc: remove the `#ifdef SELFHOST` branches
2. If not: ensure `mc_syscall0..6` lowering works in self-hosted builds

**Testing:**
```bash
make selfhost
bin/monacc-self examples/hello.c -o /tmp/hello && /tmp/hello
make test
```

---

## Phase 3: Deeper Unification

### 3.1 Merge Compiler Utilities into Core

**Current state:**
| `compiler/` file | `core/` equivalent | Overlap |
|------------------|-------------------|---------|
| `monacc_str.c` | (none) | String builder |
| `monacc_fmt.c` | `mc_fmt.c` | Error formatting |
| `monacc_sys.c` | `mc_io.c`, `mc_syscall.h` | File I/O, syscalls |

**Goal:** The compiler should use `core/` directly rather than maintaining parallel implementations.

**Implementation:**
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

**Current state:**
`compiler/selfhost/` contains minimal stub headers so monacc can compile itself without full libc headers:
- `errno.h`, `fcntl.h`, `limits.h`, `stdarg.h`, `stdbool.h`, `stdint.h`, `stdio.h`, `stdlib.h`, `string.h`, `unistd.h`

**Goal:** As monacc's preprocessor improves, reduce reliance on these stubs.

**Implementation:**
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

## Phase 4: Compiler Improvements (If Needed)

These items should only be pursued if they unlock significant codebase simplification.

### 4.1 Fix `sizeof(array)` Bug

**Current state:**
`sizeof(array)` returns the element size instead of the array size. Documented in `kernel/status.md`.

**Impact:**
- Kernel code has hardcoded sizes as workarounds
- Any tool code using `sizeof(array)` is broken when compiled with monacc

**Implementation:**
Fix in `compiler/monacc_parse.c` or `monacc_codegen.c`.

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

### 4.2 Fix `__attribute__((packed))` Struct Layout

**Current state:**
Packed attribute is not honored for struct member offsets. Documented in `kernel/status.md`.

**Impact:**
- Kernel TSS struct has wrong layout
- Any code using packed structs for hardware/protocol structures is broken

**Implementation:**
Fix in parser/type system to track `is_packed` and skip alignment padding.

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

### 4.3 Consider Varargs Support

**Current state:**
monacc doesn't support `va_list`, `va_start`, `va_arg`.

**Impact:**
- SELFHOST builds need manual format string parsing
- Can't use variadic `printf`-style functions

**Decision point:**
- If Phase 2.1 (type-specific `str_appendf_*`) works well, varargs may not be needed
- Varargs is complex to implement correctly (ABI-specific register/stack handling)

**Recommendation:** Defer unless there's a strong use case.

---

## Validation Checklist

Before declaring any phase complete:

- [ ] `make clean && make` succeeds
- [ ] `make test` passes (29 compiler examples + all tool tests)
- [ ] `make selfhost` succeeds
- [ ] `bin/monacc-self examples/hello.c -o /tmp/hello && /tmp/hello` works
- [ ] No new `#ifdef MONACC` or `#ifdef SELFHOST` blocks added
- [ ] Any removed `#ifdef` blocks are documented in commit message

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
