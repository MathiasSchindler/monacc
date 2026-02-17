# monacc bugs: implementation plan

This document tracks **C-compatibility bugs / missing features** discovered while using monacc to build low-level code (notably the experimental kernel in `kernel/`).

It is intentionally pragmatic:
- Keep monacc small and self-hosting.
- Fix correctness bugs that cause silent miscompiles first.
- Add features only when they reduce friction without ballooning scope.

---

## Design principles

1. **Correctness before convenience**
   - Prefer fixing miscompiles / semantic violations over adding new language features.
   - If a feature exists (`sizeof`, `packed`, `extern`), it must behave correctly.

2. **Tiny, testable steps**
   - Every fix ships with at least one regression test that fails before and passes after.
   - Prefer single-purpose tests with stable, deterministic outputs.

3. **Minimize cross-cutting changes**
   - Contain fixes to the smallest subsystem: parser, type checker, layout engine, codegen, linker, asm.

4. **Keep the kernel’s needs in mind, but don’t overfit**
   - The kernel is a great stress test for C semantics (struct layout, packed, ABI),
     but fixes should improve general toolchain correctness.

5. **Own the ABI rules**
   - For Linux x86_64 SysV ABI: struct layout, alignment, and calling convention must match.

---

## Project scope

### Primary goal

Fix the high-impact monacc bugs discovered during kernel bring-up so that:
- Kernel code can be written in idiomatic C with fewer workarounds.
- monacc behaves closer to GCC/Clang for the supported subset of C.

### Non-goals (for now)

- Full GNU inline-asm compatibility with every constraint/operand modifier.
- Full x86 instruction coverage in the internal assembler (unless explicitly chosen).
- Full preprocessor `#if` expression evaluation, function-like macros, etc.

---

## Discovered bugs / gaps

This list is seeded from `kernel/plan.md` (“monacc limitations discovered”) and classified by priority.

### P0: correctness bugs (fix ASAP)

#### 1) `sizeof(array)` returns element size / pointer size

- **Symptom**: `sizeof(uint64_t gdt[7])` returns `8` instead of `56`.
- **Impact**: silently wrong limits/offsets; causes hard-to-debug faults.
- **Likely root cause**: array-to-pointer decay happening too early in type analysis.

**Fix sketch**
- In expression typing, treat arrays as arrays in `sizeof` (and in other contexts where decay must not occur).
- Ensure decay is applied only in the standard places (function call arguments, most rvalues), not for `sizeof`, unary `&`, or string literals in initializers.

**Regression tests**
- Compile + run a tiny program printing (or returning) `sizeof` values for:
  - local array
  - global array
  - array parameter (should be pointer size)
  - `sizeof(*(int(*)[7])0)` patterns
- Add a compile-time-ish check pattern via `switch`/`case` or `typedef char check[(cond)?1:-1];` if supported.

**Status**: fixed (regression test: `sizeof-array`).

---

#### 2) `__attribute__((packed))` not honored for member offsets

- **Symptom**: packed structs still get natural alignment member offsets.
- **Impact**: breaks IDT/GDT/TSS and other binary layouts.

**Fix sketch**
- In the struct layout engine:
  - When `packed` is active, set member alignment to `1` (or to the type’s minimum alignment constraints as per GCC semantics; for most packed structs, alignment becomes 1).
  - Compute offsets using packed rules.
  - Track both **size** and **alignment** of the overall struct.

**Regression tests**
- Test a packed struct with mixed-width fields and verify:
  - `offsetof(struct, field)` (via `&((T*)0)->field`) equals expected constant.
  - `sizeof(struct)` equals expected.
  - `alignof(struct)` behavior if supported; otherwise validate that arrays of the struct are contiguous.

  **Status**: fixed (regression test: `packed-offsetof`).

---

#### 3) `sizeof(packed struct)` returns wrong value

- **Symptom**: `sizeof(struct tss64)` incorrect (104 expected, 112 observed).
- **Impact**: ABI / hardware structure sizes wrong.

**Fix sketch**
- Usually fixed by the same layout engine changes as (2).
- Ensure tail padding rules are applied correctly under `packed`.

**Regression tests**
- Include a canonical packed struct example where `sizeof` is known and sensitive.

**Status**: fixed (regression test: `packed-size`).

---

#### 4) Compound literal struct assignment only copies 8 bytes

- **Symptom**: `tss = (struct tss64){0};` only zeroes/copies 8 bytes.
- **Impact**: pervasive miscompiles; breaks idiomatic C initialization.

**Fix sketch**
- Fix struct copy lowering:
  - For aggregate assignments, emit a byte copy of the full object size.
  - Use `rep movsb` style lowering (or loop) for large copies.
  - For “all zeros” compound literals, consider emitting a memset-like loop.
- Confirm the IR/codegen uses the correct size (ties back to struct layout).

**Regression tests**
- Program that assigns `{0}` into a struct with fields beyond the first 8 bytes and checks they are zero.
- Another program that assigns a non-zero compound literal and checks all fields.

**Status**: fixed (regression test: `compound-literal-assign`).

---

#### 5) `extern` array declarations / definitions fail to link (symbol binding)

- **Symptom**: multi-TU programs can fail to link because the defining TU emits the symbol as *local* (not global), so references remain undefined.
- **Impact**: breaks common patterns like `extern unsigned char blob[];` across translation units.

**Fix sketch**
- Ensure non-`static` global definitions emit global binding (e.g. via `.globl` in assembly output), so the internal assembler/ELF writer produces `STB_GLOBAL` symbols.
- Keep `extern` declarations as declarations only (no storage emission).

**Regression tests**
- Two-file compile/link test:
  - TU A defines `unsigned char blob[] = {1,2,3};`
  - TU B declares `extern unsigned char blob[];` and reads values.

**Status**: fixed (regression test: `extern-array-link`).

Additional coverage: `extern-array-values` checks that the bytes are correct at runtime.

---

### P1: quality-of-life / compatibility

#### 6) `static` local arrays placed on stack, not BSS

- **Symptom**: `static uint8_t buf[16384];` inside a function allocates on stack.
- **Impact**: stack blowups; wrong lifetime/storage class.

**Fix sketch**
- Ensure function-scope `static` creates a global (or TU-scope) symbol with internal linkage.
- Emit exactly one instance and reference it.

**Regression tests**
- Program that returns address of a function-local static array, calls function twice, verifies same pointer.
- Optionally add a size-of-binary/section placement check if you have an ELF reader test harness.

**Status**: fixed (regression tests: `static-local-storage`, `static-local-recursion`).

---

#### 7) Missing `__builtin_unreachable()`

- **Symptom**: not recognized.
- **Impact**: mostly optimization / clarity.

**Fix sketch**
- Parse builtin and lower to a trap or an “unreachable” IR node.
- In codegen, can emit `ud2` or nothing if the control path already exits.

**Regression tests**
- Compile-only test ensuring builtin is accepted.
- Runtime test where reachable path does not trigger trap.

**Status**: fixed (regression test: `builtin-unreachable`).

---

#### 8) No `%w` / `%b` operand modifiers in inline asm

- **Symptom**: GCC-style inline asm modifiers unsupported.
- **Impact**: friction porting low-level code.

**Fix sketch (choose one)**
- **Option A (minimal)**: accept `%bN/%wN/%kN/%qN` and map them to the correct register name.
- **Option B (broader)**: implement a small subset of GCC inline-asm formatting rules.

**Regression tests**
- Compile-only asm-format tests: verify emitted assembly contains expected register names.

**Status**: fixed for `%b/%w/%k/%q` (regression test: `asm-modifiers`).

---

#### 9) Global `const char *` string initializer dropped

- **Symptom**: `static const char *p = "literal";` behaves as if `p == NULL` at runtime.
- **Impact**: common CLI patterns crash when the pointer is used.
- **Likely root cause**: unsupported global initializer got silently ignored, leaving the symbol in `.bss`.

**Fix sketch**
- Support pointer-to-string-literal global init by emitting a `.data.*` entry with an absolute relocation to the `.LC*` label.
- Ensure the internal assembler and linker support `R_X86_64_64` for `.quad <symbol>`.

**Status**: fixed (regression test: `global-strptr-init`).

---

### P2: deliberate limitation / product choice

#### 9) Privileged / rare instructions rejected by internal assembler

- **Symptom**: monacc internal assembler rejects some instructions (`cli`, `hlt`, `mov %cr2`, …).
- **Impact**: kernel bring-up friction.

**Recommendation**
- Keep this as-is unless you want monacc’s assembler to become a general-purpose x86 assembler.
- Prefer `.S` files assembled by GNU `as` for privileged instructions.

**Alternative low-risk improvement**
- Add an explicit “external asm mode” or document the recommended pattern.

**Regression tests**
- None required if kept as a deliberate limitation; if adding passthrough/external mode, add a build test.

---

## Implementation plan (phased)

### Phase A: Layout + `sizeof` correctness (highest leverage)

1. Fix array decay timing so `sizeof(array)` is correct.
2. Fix struct layout engine:
   - packed member offsets
   - packed size computation
   - alignment computation
3. Fix aggregate assignment/copy to use correct object size.

**Exit criteria**
- Kernel no longer needs the `sizeof(array)` workaround for GDT.
- Kernel no longer needs raw byte-offset hacks for packed structs.
- `{0}` assignment correctly initializes entire structs.

**Status**: complete (covered by `sizeof-array`, `packed-offsetof`, `packed-size`, `compound-literal-assign`).

### Phase B: Linkage/storage-class correctness

1. Fix `extern` array declarations / undefined symbol references.
2. Fix function-scope `static` storage.

**Exit criteria**
- Kernel can use idiomatic `extern unsigned char foo[];` patterns.
- Function-local statics behave like GCC/Clang.

**Status**: complete (covered by `extern-array-link`, `extern-array-values`, `static-local-storage`, `static-local-recursion`).

### Phase C: Compatibility polish

1. Implement `__builtin_unreachable()`.
2. Add `%w/%b` modifiers support (if you want to reduce asm friction).

**Status**: mostly complete.
- `__builtin_unreachable()` is implemented (`builtin-unreachable`).
- Operand modifiers `%b/%w/%k/%q` are implemented (`asm-modifiers`).
- Internal assembler supports `test $imm, r/m` and constant-data directives `.word`/`.long` (`asm-test-imm-mem-and-directives`).

---

## Where to implement (code pointers)

This is intentionally approximate; the exact file boundaries may shift.

- **Type system / expression typing**: array decay rules, `sizeof` handling.
- **Struct layout engine**: member offset computation, packing, alignment.
- **Codegen for aggregates**: struct copy/assign, compound literals, memset-like lowering.
- **ELF symbol emission / linker**: extern declarations, undefined symbols, relocation generation.
- **Inline-asm formatter**: operand modifier parsing and register name rendering.

---

## Regression test strategy

### Principles

- Tests should be runnable via existing `make test` or a dedicated lightweight harness.
- Prefer small C programs that return exit status (0/1) over printing.
- Keep tests deterministic (no timing, no randomness).

### Suggested harness layout

- Add C test sources under `tests/` (or a new folder like `tests/compiler-bugs/`).
- Each test should:
  - compile with monacc
  - run on the host Linux x86_64
  - exit 0 on pass, non-zero on fail

### Integration with `make test`

This repo already has a Makefile-driven test harness with opt-in probes.

- Tests live in `tests/compiler/bugs/`.
- Runner script: `tests/compiler/monaccbugs.sh`.
- Default: runs as part of `make test`.
- Opt-out: `SELFTEST_MONACCBUGS=0 make test`.

As each bug is fixed, its corresponding test should start passing and will then prevent regressions.

### Concrete tests to add

- `sizeof-array.c`
- `packed-offsetof.c`
- `packed-size.c`
- `compound-literal-assign.c`
- `extern-array-def.c` + `extern-array-use.c` + `extern-array-values.c`
- `static-local-storage.c`
- `static-local-recursion.c`
- `builtin-unreachable.c`
- `asm-modifiers.c`
- `asm-test-imm-mem-and-directives.c`

If you want, I can also wire these into the existing test runner once you tell me where you prefer compiler-regression tests to live (under `tests/` vs `examples/`).
