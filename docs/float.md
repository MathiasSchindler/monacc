
# Floating-Point Support Proposal (Mandelbrot First)

Date: 2025-12-17

This document proposes a concrete, repo-aligned plan to add floating-point support to monacc, with a first “big milestone” of generating a Mandelbrot BMP.

Unlike older drafts, this version is written to match the current codebase:

- monacc already ships an internal assembler (`--emit-obj`) and internal linker (`--link-internal`) and the default build does not require external `as`/`ld`.
- The compiler’s type representation is centered around `BaseType` + `ptr` + `struct_id` fields (not a separate `Type` object).
- The internal linker’s relocation support is currently narrow (PC-relative only), which influences how we should encode float constants.

---

## Goals

**Milestone A (Mandelbrot):**

- Support `float` (32-bit IEEE-754) in the language subset.
- Support float literals, `+ - * /`, comparisons, `if/while/for` conditions, and `int ↔ float` conversions.
- Support passing/returning `float` in function calls (SysV ABI).
- Add a new tool: `tools/mandelbrot.c` that writes a BMP to stdout.

**Milestone B (later):**

- Optional `double`.
- Minimal math helpers (`sqrtss`-based `mc_sqrtf`, then approximations for `expf/tanhf` if/when needed).

## Non-goals (initially)

- Full C FP semantics (NaNs, infinities, signed zero edge cases).
- `printf` float formatting.
- Complex libm equivalents.

---

## Hard Constraints (project-aligned)

1. **No new runtime deps**: produced binaries remain syscall-only.
2. **Keep toolchain self-contained**: float support must work with `--emit-obj` + `--link-internal`.
3. **Compiler must remain self-hostable**: any new compiler-side logic (especially literal parsing) must not require floats in the compiler implementation.

Notes on current behavior:

- `--keep-shdr` is a debug aid: monacc trims section headers by default.
- `--emit-obj` is currently not supported when compiling the compiler in `SELFHOST` mode (the selfhosted compiler can still compile code, but it won’t be able to assemble internally unless that limitation is lifted).

---

## Phase 0: Baseline Tests + Observability

Add tests first so each later phase can be validated via `make test`.

### 0.1 New example tests (return 42 on success)

Add example programs under `examples/`:

- `float_basic.c`: declare a `float`, return a value derived from it.
- `float_arith.c`: `+ - * /` with a few constants.
- `float_cmp.c`: comparisons in `if`/`while`.
- `float_convert.c`: `int ↔ float` conversions.
- `float_call.c`: `float` args and return values.

### 0.2 Multi-object internal link test

Add:

- `multi_obj_main.c` calls `helper()`.
- `multi_obj_helper.c` defines `helper()`.

This keeps pressure on `link_internal_exec_objs()` as float support expands.

### 0.3 Debug workflow

When debugging float bring-up:

- Use `--keep-shdr` and `--dump-elfsec` to inspect output layout.
- Use `--dump-elfobj` to inspect internal `.o` generation.

---

## Phase 1: Frontend Representation (float as a first-class type)

### 1.1 Tokenizer

Extend `compiler/monacc_front.c` to recognize float literals and emit a distinct token kind (e.g. `TOK_FLOAT_LIT`).

Supported literal spellings for Milestone A:

- `123.0`, `0.5`, `.5`, `5.`, `1e-3`, `1.0e+2`
- Optional `f` suffix

### 1.2 Type system

Extend `BaseType` in `compiler/monacc.h` with:

- `BT_FLOAT` (and later `BT_DOUBLE` if desired)

Propagate float-ness through the existing structs that carry `{ base, ptr, struct_id, is_unsigned }`:

- `Expr`
- `Local`
- `Function` (params/return)
- `GlobalVar`

### 1.3 Parser + semantic rules

Update `compiler/monacc_parse.c`:

- Parse `float` as a declspec.
- Produce float-typed expressions for float literals.
- Implement minimal usual arithmetic conversions:
  - `int op float` → convert int to float
  - comparisons: compare as floats

---

## Phase 2: Float literal → bits (without using floats in the compiler)

The compiler must be able to turn a float literal token into an IEEE-754 bit pattern *without* relying on host floating-point or libc.

Proposal:

- Implement a small decimal parser that produces a normalized mantissa/exponent and rounds to nearest-even for `float`.
- Store the result as `mc_u32 fbits` on the float-literal AST node.

This avoids bootstrapping traps and keeps self-hosting viable.

---

## Phase 3: Codegen (SSE scalar, SysV ABI)

### 3.1 Register model

Introduce a float evaluation path that uses:

- `%xmm0` for the “current expression result”
- `%xmm1` as a scratch register

Stack spilling is fine early on; optimize later.

### 3.2 Instructions needed for Mandelbrot

Emit:

- `movss` (load/store/reg-reg)
- `addss`, `subss`, `mulss`, `divss`
- `ucomiss` + conditional jumps (`jb/jbe/ja/jae/je/jne`) for comparisons
- `cvtsi2ss`, `cvtss2si` for conversions

### 3.3 Calling convention

Implement SysV x86_64 float calling convention:

- float args: `%xmm0..%xmm7`
- float return: `%xmm0`

For Milestone A, it’s acceptable to first support:

- “all-float params” functions (plus `int` for loop counters),

and then extend to full mixed int/float argument assignment.

---

## Phase 4: Internal assembler support (XMM + SSE encodings)

monacc’s internal assembler in `compiler/monacc_elfobj.c` must be extended to accept the new assembly patterns codegen will emit.

### 4.1 Parse XMM registers

Add `%xmm0..%xmm15` to the register parser.

### 4.2 Encode SSE scalar instructions

Implement encoders for the instruction forms codegen uses.

Key point: prioritize only the exact forms emitted (reg/reg and reg/mem variants) to keep the assembler minimal.

---

## Phase 5: Constants + relocations (keep internal linker happy)

The internal linker currently supports only PC-relative relocations (`R_X86_64_PC32` / `R_X86_64_PLT32`).

To avoid widening relocation support early, design constant loads so that:

- float constants live in `.rodata` labels
- codegen uses RIP-relative addressing to load them
- the internal assembler emits PC-relative relocations for those references

### 5.1 Prefer `.byte` for constant emission (first)

Today the internal assembler already supports `.byte` and `.zero`.

For the first bring-up, emit float constants as four `.byte` values (little-endian IEEE-754 bits). This avoids needing `.long`.

Later (pure QoL): add `.long` once the system works.

### 5.2 If new relocation types are needed

If the internal `.o` ends up containing relocations that aren’t PC32/PLT32, extend both:

- `compiler/monacc_elfobj.c` (emission of that relocation)
- `compiler/monacc_link.c` (application of that relocation)

Likely candidates: `R_X86_64_32S`.

---

## Phase 6: Mandelbrot tool

Add `tools/mandelbrot.c`:

- Minimal CLI: `-w/-h/-i` plus optional center/zoom
- Write a 24-bit BMP to stdout
- Fixed palette (or simple grayscale) to keep it tiny

Once float arithmetic works, Mandelbrot becomes a very strong “visual correctness” test.

---

## Risks + mitigations

- **ABI complexity**: mixed int/float arguments are subtle. Start with a constrained subset, then generalize.
- **Assembler surface area**: keep instruction support exactly to what codegen emits.
- **Relocations**: keep constant references RIP-relative to stay within current internal linker support.

