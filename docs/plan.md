# monacc - Future Roadmap

Date: 2025-12-16

This document outlines remaining work and future directions for monacc.

---

## Guiding Principles

1. **No shims when a clean solution exists.** Since we control the entire toolchain, we can either:
   - Improve the compiler to support the construct
   - Change the source code to only use what the compiler provides

2. **Prefer shared `mc_*` APIs** over `#ifdef MONACC` or `#ifdef SELFHOST` branches.

3. **Test-driven changes.** Every change must pass `make test`.

4. **Priority order: Run → Small → Fast.** Code must work correctly first, then be small, then be fast.

5. **Self-contained ecosystem.** The compiler, tools, and kernel form a complete system with no third-party dependencies.

---

## Long-Term Vision

The end state for monacc:

1. **Fully self-contained** — no external `as`, `ld`, or libc required
2. **Self-hosting** — monacc compiles itself ✅ (achieved)
3. **Complete userland** — all tools in `tools/` compile and run ✅ (achieved)
4. **Kernel support** — the kernel in `kernel/` compiles and boots ✅ (achieved)

The `core/` directory is effectively the project's own minimal libc — syscall-based, no external dependencies.

---

## Remaining Work

### Phase 1: Eliminate External `as` (In Progress)

**Current state:** `--emit-obj` works for ~50% of examples. The internal assembler in `monacc_elfobj.c` needs additional instruction support.

**Missing patterns identified:**
- `asm: unsupported 1-op insn '%s'` — various single-operand instructions
- `asm: unsupported directive '%.*s'` — `.section` variants, alignment directives
- `asm: bad register` — edge cases in register parsing
- `asm: shift form` — addressing mode variants

**Goal:** Make `--emit-obj` work for all examples, then make it the default.

**Testing:**
```bash
for ex in examples/*.c; do
    bin/monacc --emit-obj "$ex" -o /tmp/test && echo "OK: $ex" || echo "FAIL: $ex"
done
```

---

### Phase 2: Eliminate External `ld`

**What:** Implement a minimal ELF linker inside monacc.

**Why:** Full self-containment — no external tools required.

**Complexity:** This is the most significant remaining dependency. The linker needs to:
- Parse ELF relocatable objects
- Resolve symbols across translation units
- Apply relocations
- Emit a final executable

**Approach options:**
1. Single-TU mode (current) — emit executable directly, no linking needed
2. Minimal linker — only handle the patterns monacc actually generates
3. Full linker — general-purpose ELF linking

**Recommendation:** Option 2 — a minimal linker tailored to monacc's output.

---

### Phase 3: Code Consolidation (Optional)

These items would reduce code duplication but are not blocking any functionality.

#### 3.1 Merge Compiler Utilities into Core

The compiler maintains some utilities that could be shared with `core/`, but only
where it *actually* reduces duplication.

| `compiler/` | `core/` equivalent | Opportunity |
|-------------|-------------------|-------------|
| `monacc_str.c` (Str builder) | (none) | Only move if another user appears |
| `monacc_sys.c` (process helpers) | `mc_io.c` | Already partially consolidated |

**What’s already done:** common process helpers that were duplicated in tools (`execvp` search and wait-status decoding) now live in `core/` as `mc_execvp()` and `mc_wait_exitcode()`.

**What remains (if worth it):**
- Audit `compiler/monacc_sys.c` for any remaining general-purpose helpers that overlap with `core/` (or should be promoted to `core/`).
- Keep compiler-specific pieces (allocator, compile driver glue) in `compiler/`.

**Note:** the compiler uses `monacc_malloc`, which makes “move to core” non-trivial unless we also define a clean allocator boundary.

#### 3.2 Remove `compiler/selfhost/` Headers (Done)

Historically, the compiler had a `compiler/selfhost/` directory of stub libc headers for self-hosting. That directory is now removed; self-host builds use a single shim header.

**Current stub surface:** `compiler/monacc_selfhost.h` (only)

---

### Phase 4: Kernel Compatibility (Low Priority)

The kernel documents several monacc limitations requiring workarounds (see `kernel/status.md`):

1. **No `%w`/`%b` operand modifiers** — sized register references in inline asm
2. **Compound literal struct assignment** — only copies 8 bytes for large structs
3. **`extern` array declarations** — create local BSS instead of external reference
4. **`static` local arrays** — placed on stack instead of BSS

These are documented and have workarounds. Fixes would be nice but are not urgent.

---

## Validation Checklist

Before declaring any phase complete:

- [ ] `make clean && make` succeeds
- [ ] `make test` passes (all 37 examples + tool tests)
- [ ] `make selfhost` succeeds
- [ ] `bin/monacc-self examples/asm_syscall.c -o /tmp/test && /tmp/test` works
- [ ] Binary size tracked (~103 KB baseline)

Optional (informational) probes:

- [ ] `SELFTEST=1 make test` runs the compiler self-host probe (host-built `bin/monacc` builds and runs `build/selftest/monacc-self`)
- [ ] `SELFTEST_EMITOBJ=1 make test` runs the `--emit-obj` probe (expected to fail until Phase 1 is complete)

---

## Current `#ifdef SELFHOST` Usage

Only 7 blocks remain in the compiler, all acceptable:

| File | Count | Purpose |
|------|-------|---------|
| `monacc_ast.c` | 3 | Extra debug output on "too many locals" |
| `monacc.h` | 2 | API exposure, header paths |
| `monacc_libc.h` | 1 | `bool` typedef |
| `monacc_main.c` | 1 | Usage message (avoids varargs) |

No `#ifdef MONACC` blocks remain in tools or core.
