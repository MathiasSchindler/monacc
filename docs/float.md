# Floating-Point Support (Current Status)

Date: 2025-12-19

monacc now supports a practical subset of IEEE-754 **binary32** (`float`) that is sufficient for non-libc, syscall-only programs and for the Mandelbrot benchmark tool.

## What was implemented

- **Frontend support for `float`**: the `float` keyword is a first-class scalar type (`BT_FLOAT`) in the existing `{ base, ptr, struct_id, is_unsigned }` type representation.
- **Float literals without host FP**: decimal literals (including `.5`, `5.`, `1e2`, and `f` suffix) are parsed and converted to an IEEE-754 binary32 bit-pattern in the compiler itself (no libc / no host floating-point dependency).
- **Codegen using scalar SSE**:
  - Arithmetic: `+ - * /` lowered to `addss/subss/mulss/divss`.
  - Comparisons lowered via `ucomiss` and conditional branches.
  - Conversions: `int -> float` via `cvtsi2ss`, `float -> int` via `cvttss2si` (trunc toward zero).
  - Implementation detail: floats are tracked as **raw 32-bit bits** in integer registers and moved into XMM registers only for actual FP operations.
- **SysV ABI support for float calls (binary32)**:
  - Passing `float` parameters in `%xmm0..%xmm7` (separate from integer args in `%rdi..%r9`).
  - Returning `float` in `%xmm0`.
  - Stack passing for `float` args beyond `%xmm7`.
- **Internal assembler + linker compatibility**:
  - The internal assembler now supports `jp/jnp` (parity Jcc) which is used for unordered (NaN) handling in float comparisons.
  - The instruction forms used by float arithmetic/comparisons/call plumbing work with `--emit-obj` and `--link-internal`.

## Coverage / tests

These are exercised by the example programs:

- `examples/float_arith.c` (basic ops + conversions)
- `examples/float_div.c` (division + truncation semantics)
- `examples/float_cmp.c` (comparisons)
- `examples/float_neg.c` (unary minus)
- `examples/float_lits.c` (literal parsing: dot forms + exponents)

Float calling convention coverage:

- `examples/float_call_ret.c` (pass/return `float` via SysV ABI)
- `examples/float_call_mixed.c` (mixed int/float argument assignment)
- `examples/float_call_many.c` (>8 float args -> stack passing)

Cast + call-site coverage:

- `examples/float_cast_callargs.c` (float↔int casts used directly as call arguments, incl. function pointers)

There is also a syscall-only benchmark tool:

- `tools/mandelbrot.c`

## What is still missing

- **`double` support** (binary64) and any `long double`.
- **Full C/IEEE edge semantics**: NaNs/infinities/signed-zero corner cases are not a goal yet, and behavior may differ from full C.
- **Varargs and float formatting/parsing**: no `printf` float formatting and no libm-like surface.
- **Broader typing/usage surface**: more coverage for floats inside structs/arrays, globals, and more complex expressions would be useful.

## Notes / gotchas

- **Float casts as call arguments**: previously, float↔int casts could be miscompiled when used *directly* as call arguments because the call fast-path treated casts as “simple args” (bit moves) instead of emitting real SSE conversion code. This is fixed and guarded by `examples/float_cast_callargs.c`.

## Implementation plan (towards a syscall-only GPT-2 124M runner)

This plan is written to keep changes incremental and regression-tested. The guiding idea is:

- Keep produced binaries syscall-only.
- Keep the toolchain self-contained (`--emit-obj` + `--link-internal`).
- Prefer adding tests/examples before or together with each new capability.

### Phase 1: Float calling convention (SysV x86_64) ✅ Implemented

Goal: allow idiomatic C code for inference kernels without “pass everything via pointers” contortions.

Implementation (done):

- Extend the type checker / call lowering so `float` parameters are passed in `%xmm0..%xmm7` and returned in `%xmm0`.
- Support **mixed int/pointer + float** argument assignment per SysV ABI (separate integer and SSE register sequences).
- Define stack spill behavior when float args exceed `%xmm7`.

Tests (done):

- `examples/float_call_ret.c`: function takes/returns `float`, caller checks via `(int)` conversion.
- `examples/float_call_mixed.c`: signature like `f(int a, float b, int c, float d, ...)` verifying each arg arrives intact.
- `examples/float_call_many.c`: >8 float args to force stack passing.

### Phase 2: Internal assembler coverage for XMM/SSE patterns used by Phase 1 ✅ Implemented

Goal: ensure `--emit-obj` stays first-class for float code.

Implementation (done):

- Ensure parsing/encoding covers the exact instruction forms emitted for call/ret paths (moves between GPRs/XMM and stack).
- Keep scope tight: only forms the codegen emits.

Tests (done):

- Add a `SELFTEST_EMITOBJ`-style probe compiling the new float-call examples with `--emit-obj` + `--link-internal`.

### Phase 3: Broaden float storage semantics (globals/arrays/structs)

Goal: make float tensors representable in “normal C” layouts.

Implementation:

- Validate and fix (if needed) `float` loads/stores through:
  - global `float` variables
  - global/local arrays of float (`float a[N]`)
  - pointers to float (`float *p`) and indexing
  - float struct fields (`struct { float x; }`)

Tests to add:

- `examples/float_global.c`: global float init + readback.
- `examples/float_array.c`: fill + sum + compare.
- `examples/float_struct.c`: store/load float members.

### Phase 4: “No-libm” math primitives needed by Transformers

Goal: provide the handful of operations needed for stable softmax + layernorm without pulling in libc.

Implementation (core helpers):

- `mc_expf(float)`: polynomial/range-reduced approximation suitable for softmax.
- `mc_rsqrtf(float)` or `mc_sqrtf(float)`: use `rsqrtss` + Newton refinement, or `sqrtss`.
- Optional: `mc_tanhf(float)` *or* choose a GELU approximation that avoids `tanhf`.

Tests to add:

- `examples/float_expf.c`: sanity points and monotonicity checks.
- `examples/float_rsqrtf.c`: relative error bound checks for a small set of inputs.
- `examples/float_softmax.c`: stable softmax invariants (sum ≈ 1, argmax preserved under shifting by constant).

### Phase 5: Performance path for matmul (SSE first)

Goal: GPT-2 124M in FP32 is dominated by GEMMs; scalar FP will be too slow for “nostalgic” interactive runs.

Implementation:

- Add a minimal packed-float SSE toolbox (either via inline asm in the GPT tool, or via carefully-scoped assembler support if emitting it from C/codegen).
- Implement a baseline matmul kernel:
  - Start with scalar correctness kernel.
  - Add an SSE kernel (e.g. 4-float wide inner loop) behind a runtime CPU feature check if desired.

Tests to add:

- `tools/gemmtest.c` (or an example): compare SIMD kernel output to scalar reference for a few small matrix sizes.
- A performance “smoke benchmark” (non-failing) can be added later; correctness tests should remain deterministic.

### Phase 6: Build a syscall-only `gpt2` tool around the primitives

Goal: prove the point with the real GPT-2 124M weights.

Implementation:

- Weight loading:
  - Prefer `mmap` of a flat weight file format (generated by a tiny conversion script).
  - Keep the on-disk format simple (little-endian, aligned, with a header).
- Token I/O:
  - Start with token IDs as input (space-separated ints) and emit token IDs.
  - Optional later: implement GPT-2 BPE using `encoder.json` + `vocab.bpe` loaded from disk.
- Core forward pass:
  - Embedding + attention + MLP + logits + sampling.
  - Keep everything in contiguous buffers; avoid dynamic allocation where possible.

Tests to add:

- `tools/gpt2-smoke.c` or a test mode in `tools/gpt2.c` that runs a tiny synthetic model (e.g. 1 layer, small dims) with a known output.
- Optional “golden” test vectors produced by a reference implementation for the same tiny model.

### Notes on scope control

- `double` can be deferred: GPT-2 inference is typically float32.
- Full IEEE corner semantics can be deferred: focus on stable numerics for exp/softmax/layernorm.
- Keep each phase shippable with tests and keep `SELFTEST_EMITOBJ=1` green.

