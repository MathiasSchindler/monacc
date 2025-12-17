# Float Support Implementation Plan

Date: 2025-12-17

This document outlines the step-by-step plan for adding floating-point support to monacc, driven by the Mandelbrot fractal generator as the initial use case and GPT-2 inference as the long-term goal.

---

## Guiding Principles

These principles are inherited from the monacc project philosophy and apply to all float-related work:

1. **Syscalls only** — No libc dependency; all I/O via direct Linux syscalls
2. **No third-party software** — No external libraries, no libm, no glibc
3. **Single platform** — Linux x86_64 only; no portability abstractions
4. **C language** — All implementation in C (the subset monacc supports)
5. **Self-contained toolchain** — Internal assembler and linker; no external `as`/`ld`

### Priority Order

All implementation decisions follow this strict priority:

| Priority | Goal | Rationale |
|----------|------|-----------|
| **1. Working** | Correctness first | A slow correct program beats a fast wrong one |
| **2. Small** | Minimize binary size | Follows monacc's size-oriented philosophy |
| **3. Fast** | Performance last | Optimize only after correct and small |

---

## Driving Use Cases

### Phase A: Mandelbrot Fractal Generator

**Why Mandelbrot first:**
- Simple float operations: `+ - * <` only
- Visual validation — correctness is immediately obvious
- Small code footprint (~200 lines)
- No transcendental functions needed
- Output: BMP file (no graphics dependencies)

**Float features exercised:**
- `float` type declarations and literals
- Basic arithmetic (`+`, `-`, `*`)
- Comparisons (`<`, `>`)
- Int↔float conversions
- Float function arguments and returns

### Phase B: GPT-2 Inference (Future)

**Additional requirements beyond Mandelbrot:**
- `double` type (optional, may use `float` throughout)
- Transcendental functions: `expf()`, `tanhf()`, `sqrtf()`
- Large `.rodata` sections (model weights)
- Matrix multiplication (performance-sensitive)

---

## Implementation Phases

### Phase 0: Foundation Preparation

Before touching float code, stabilize the existing toolchain.

#### 0.1 Add Missing Assembler Directives

**File:** `compiler/monacc_elfobj.c`

Add support for:
```asm
.long 0x40490fdb      # 32-bit constant (for float literals)
.quad 0x400921fb...   # 64-bit constant (for double literals)
```

**Implementation:**
```c
static void parse_long_directive(AsmState *st, const char *p, const char *end) {
    if (!st->cur) die("asm: .long outside section");
    p += mc_strlen(".long");
    // Parse comma-separated 32-bit values
    // bin_put_u32_le(&st->cur->data, value);
}
```

**Test:** Add `examples/rodata_const.c` that uses a global `const int` array.

#### 0.2 Add Missing Relocation Type (if needed)

**File:** `compiler/monacc_link.c`

Extend relocation handling to support `R_X86_64_32S`:
```c
#define R_X86_64_32S 11

// In relocation application loop:
if (rtype == R_X86_64_32S) {
    mc_i64 val = (mc_i64)S + (mc_i64)rels[i].r_addend;
    if (val < -2147483648ll || val > 2147483647ll) {
        die("link-internal: 32S relocation overflow");
    }
    put_u32_le(out + (mc_usize)out_off, (mc_u32)(mc_i32)val);
}
```

**Note:** This may not be needed if codegen uses RIP-relative addressing for all float constants. Verify during implementation.

#### 0.3 Clean Up Minor Issues

**File:** `compiler/monacc_elfobj.c`

- Consolidate duplicate `starts_with` / `starts_with_span` functions
- Simplify `span_len()` to `return (mc_usize)(end - p);`
- Add placeholder comments for future SSE instruction locations

#### 0.4 Add Multi-Object Linking Test

Create test that exercises `link_internal_exec_objs()` with multiple `.o` files:
```
examples/
  multi_obj_main.c    # calls helper()
  multi_obj_helper.c  # defines helper()
```

---

### Phase 1: Compiler Frontend (Float Types)

#### 1.1 Tokenizer: Float Literals

**File:** `compiler/monacc_front.c`

Recognize float literal patterns:
- `3.14` — decimal with dot
- `3.14f` — explicit float suffix
- `1e-5` — scientific notation
- `.5` — leading dot
- `5.` — trailing dot

**Implementation approach:**
```c
// In tokenizer, after integer literal detection:
// If we see '.' or 'e'/'E' after digits, switch to float parsing
// Store as raw string initially; convert to IEEE 754 bits in codegen
```

**Token type:** Add `TOK_FLOAT_LIT` to token enum.

#### 1.2 Type System: Float Types

**File:** `compiler/monacc.h`

Extend the `Type` structure:
```c
enum {
    TYPE_VOID,
    TYPE_CHAR,
    TYPE_SHORT,
    TYPE_INT,
    TYPE_LONG,
    TYPE_FLOAT,   // NEW: 32-bit IEEE 754
    TYPE_DOUBLE,  // NEW: 64-bit IEEE 754 (optional for Phase A)
    TYPE_PTR,
    TYPE_ARRAY,
    TYPE_STRUCT,
    TYPE_ENUM,
    TYPE_FUNC,
};
```

Add helper functions:
```c
int is_float_type(Type *t);    // float or double
int is_arithmetic_type(Type *t); // int types + float types
int float_type_size(Type *t);  // 4 for float, 8 for double
```

#### 1.3 Parser: Float Declarations

**File:** `compiler/monacc_parse.c`

Handle `float` and `double` as type specifiers:
```c
// In parse_declspec():
if (match("float")) {
    // set base type to TYPE_FLOAT
}
if (match("double")) {
    // set base type to TYPE_DOUBLE
}
```

Handle float literals in expressions:
```c
// In parse_primary():
if (tok->kind == TOK_FLOAT_LIT) {
    // Create AST node for float constant
    // Store IEEE 754 bits for codegen
}
```

#### 1.4 Type Checker: Float Operations

**File:** `compiler/monacc_parse.c`

Implement "usual arithmetic conversions" for mixed int/float:
- `int + float` → `float`
- `float + double` → `double`
- Comparisons between int and float: convert int to float first

---

### Phase 2: Assembler (SSE Instructions)

#### 2.1 XMM Register Parsing

**File:** `compiler/monacc_elfobj.c`

Add XMM register recognition:
```c
// Extend parse_reg_name() or add parse_xmm_reg():
// %xmm0 through %xmm15

typedef struct {
    int reg;   // 0..15
    int is_xmm; // 1 for XMM, 0 for GPR
    int width; // 32 for float, 64 for double (in XMM context)
} Reg;
```

#### 2.2 SSE Instruction Encoding

**File:** `compiler/monacc_elfobj.c`

Implement encoders for essential SSE instructions:

| Instruction | Opcode | Description |
|-------------|--------|-------------|
| `movss` | `F3 0F 10/11` | Move scalar single |
| `movsd` | `F2 0F 10/11` | Move scalar double |
| `addss` | `F3 0F 58` | Add scalar single |
| `subss` | `F3 0F 5C` | Subtract scalar single |
| `mulss` | `F3 0F 59` | Multiply scalar single |
| `divss` | `F3 0F 5E` | Divide scalar single |
| `ucomiss` | `0F 2E` | Compare scalar single (sets EFLAGS) |
| `cvtsi2ss` | `F3 0F 2A` | Convert int to float |
| `cvtss2si` | `F3 0F 2D` | Convert float to int |

**Encoding pattern:**
```c
static void encode_movss_reg_reg(Str *s, int src_xmm, int dst_xmm) {
    // F3 0F 10 /r (load form) or F3 0F 11 /r (store form)
    bin_put_u8(s, 0xF3);
    // REX prefix if xmm8-xmm15 involved
    int rex_r = (dst_xmm >> 3) & 1;
    int rex_b = (src_xmm >> 3) & 1;
    if (rex_r || rex_b) {
        bin_put_u8(s, 0x40 | (rex_r << 2) | rex_b);
    }
    bin_put_u8(s, 0x0F);
    bin_put_u8(s, 0x10);
    emit_modrm(s, 3, dst_xmm & 7, src_xmm & 7);
}
```

#### 2.3 Memory Operands for SSE

Support RIP-relative addressing for float constants:
```asm
movss .LC0(%rip), %xmm0   # load float constant from .rodata
```

This reuses existing RIP-relative infrastructure.

---

### Phase 3: Codegen (Float Code Generation)

#### 3.1 Float Constant Emission

**File:** `compiler/monacc_codegen.c`

Emit float constants to `.rodata`:
```c
// For float literal 3.14f:
// 1. Convert to IEEE 754 bits: 0x4048f5c3
// 2. Emit to .rodata section:
//    .section .rodata.cst4,"aM",@progbits,4
//    .LC0:
//    .long 0x4048f5c3
// 3. Reference via RIP-relative: movss .LC0(%rip), %xmm0
```

**IEEE 754 conversion (no libm):**
```c
// Manual float-to-bits conversion
// This is the tricky part without libc
// Option 1: Use union type punning (if compiler supports)
// Option 2: Parse float string and build IEEE 754 manually
```

#### 3.2 Float Expression Codegen

**File:** `compiler/monacc_codegen.c`

Generate SSE instructions for float operations:
```c
// Binary operations use pattern:
// 1. Evaluate left operand → %xmm0
// 2. Push %xmm0 to stack (or use another XMM reg)
// 3. Evaluate right operand → %xmm0
// 4. Pop left operand → %xmm1
// 5. Perform operation: addss %xmm1, %xmm0

static void cg_float_binop(Node *node) {
    cg_expr(node->lhs);  // result in %xmm0
    // save to stack: sub $16, %rsp; movss %xmm0, (%rsp)
    cg_expr(node->rhs);  // result in %xmm0
    // restore: movss (%rsp), %xmm1; add $16, %rsp
    
    switch (node->op) {
        case '+': emit("addss %%xmm1, %%xmm0"); break;
        case '-': emit("subss %%xmm1, %%xmm0"); break;
        case '*': emit("mulss %%xmm1, %%xmm0"); break;
        case '/': emit("divss %%xmm1, %%xmm0"); break;
    }
}
```

#### 3.3 Float Comparisons

Generate compare + branch for float conditionals:
```c
// For: if (x < 4.0f)
// Emit:
//   movss .LC_4_0(%rip), %xmm1
//   ucomiss %xmm1, %xmm0    # compare xmm0 with xmm1
//   jae .Lfalse             # jump if above or equal (opposite of <)
```

**Important:** `ucomiss` sets EFLAGS differently than integer `cmp`:
- Use `ja`/`jae`/`jb`/`jbe` for unsigned-style comparison
- Handle unordered (NaN) cases if needed (use `jp` to check parity flag)

#### 3.4 Float Function Calls (SysV ABI)

**SysV x86_64 ABI for floats:**
- Float/double arguments: `%xmm0` through `%xmm7` (first 8)
- Float/double return value: `%xmm0`
- Caller-saved: all XMM registers

```c
// For call: float result = sqrtf(x);
// 1. Load x into %xmm0 (first float arg)
// 2. call sqrtf
// 3. Result is in %xmm0
```

#### 3.5 Int↔Float Conversions

```c
// int to float:
//   cvtsi2ss %eax, %xmm0   (32-bit int)
//   cvtsi2ss %rax, %xmm0   (64-bit int)

// float to int:
//   cvtss2si %xmm0, %eax   (truncates toward zero)
```

---

### Phase 4: Mandelbrot Tool

#### 4.1 BMP Output Support

**File:** `tools/mandelbrot.c`

BMP format (uncompressed, 24-bit):
- 14-byte file header
- 40-byte DIB header (BITMAPINFOHEADER)
- Raw BGR pixel data (bottom-up row order)
- Row padding to 4-byte boundary

```c
static void write_bmp_header(int fd, int w, int h) {
    unsigned char hdr[54];
    mc_memset(hdr, 0, 54);
    
    int row_size = (w * 3 + 3) & ~3;  // pad to 4 bytes
    int img_size = row_size * h;
    int file_size = 54 + img_size;
    
    // BMP signature
    hdr[0] = 'B'; hdr[1] = 'M';
    // File size (little-endian)
    hdr[2] = file_size & 0xff;
    hdr[3] = (file_size >> 8) & 0xff;
    hdr[4] = (file_size >> 16) & 0xff;
    hdr[5] = (file_size >> 24) & 0xff;
    // Pixel data offset
    hdr[10] = 54;
    // DIB header size
    hdr[14] = 40;
    // Width, height, planes, bpp...
    // ... (complete implementation)
    
    mc_write(fd, hdr, 54);
}
```

#### 4.2 Mandelbrot Core

```c
static int mandel_iter(float cx, float cy, int max_iter) {
    float zx = 0.0f;
    float zy = 0.0f;
    int i = 0;
    
    while (i < max_iter) {
        float zx2 = zx * zx;
        float zy2 = zy * zy;
        if (zx2 + zy2 > 4.0f) break;
        
        float new_zx = zx2 - zy2 + cx;
        zy = 2.0f * zx * zy + cy;
        zx = new_zx;
        i++;
    }
    return i;
}
```

#### 4.3 CLI Interface

```bash
mandelbrot [options] > output.bmp

Options:
  -w WIDTH    Image width (default: 800)
  -h HEIGHT   Image height (default: 600)
  -x CENTER_X Center X coordinate (default: -0.5)
  -y CENTER_Y Center Y coordinate (default: 0.0)
  -z ZOOM     Zoom level (default: 1.5)
  -i MAX_ITER Maximum iterations (default: 256)
```

---

### Phase 5: Math Functions (for GPT-2)

#### 5.1 Implement in `core/mc_math.c`

Without libm, implement essential functions manually:

| Function | Algorithm | Notes |
|----------|-----------|-------|
| `mc_expf(x)` | Taylor series or range reduction + polynomial | Most complex |
| `mc_logf(x)` | Range reduction + polynomial | Needed for softmax |
| `mc_sqrtf(x)` | Newton-Raphson or `sqrtss` instruction | SSE has `sqrtss` |
| `mc_tanhf(x)` | `(exp(2x)-1)/(exp(2x)+1)` | Builds on expf |
| `mc_fabsf(x)` | Clear sign bit | Trivial |

**Note:** x86_64 SSE provides `sqrtss` instruction, so `mc_sqrtf` can be a single instruction.

#### 5.2 Accuracy vs Size Tradeoff

Following priority order (working > small > fast):
1. **First:** Naive implementations that are obviously correct
2. **Then:** Reduce code size where possible
3. **Last:** Optimize for speed only if needed

---

## Testing Strategy

### Unit Tests (per phase)

| Phase | Test File | What It Tests |
|-------|-----------|---------------|
| 1 | `examples/float_basic.c` | Float declaration, literal, return |
| 1 | `examples/float_arith.c` | `+ - * /` operations |
| 1 | `examples/float_cmp.c` | Comparisons in if/while |
| 2 | `examples/float_call.c` | Float function args and returns |
| 3 | `examples/float_convert.c` | Int↔float conversions |
| 4 | `tools/mandelbrot.c` | Integration test |

### Validation

```bash
# After each phase:
make clean
make test           # All existing tests must pass
make mandelbrot     # (Phase 4+)
./bin/mandelbrot > /tmp/test.bmp
# Visually inspect test.bmp
```

---

## Risk Assessment

| Risk | Likelihood | Mitigation |
|------|------------|------------|
| IEEE 754 bit conversion without libc | Medium | Use union type punning; test exhaustively |
| SSE instruction encoding bugs | Medium | Compare output with `objdump` of gcc-compiled code |
| Float constant relocation issues | Low | Verify with `--keep-shdr` and `readelf` |
| NaN/Inf edge cases | Low | Defer to Phase 5; Mandelbrot doesn't need them |
| Performance (GPT-2) | Medium | Accept slow first; optimize later if needed |

---

## Timeline Estimate

| Phase | Effort | Dependencies |
|-------|--------|--------------|
| Phase 0 | 1-2 days | None |
| Phase 1 | 3-4 days | Phase 0 |
| Phase 2 | 3-4 days | Phase 1 |
| Phase 3 | 4-5 days | Phase 1, 2 |
| Phase 4 | 2-3 days | Phase 3 |
| Phase 5 | 5-7 days | Phase 4 (optional for Mandelbrot) |

**Total for Mandelbrot:** ~2-3 weeks
**Total including GPT-2 math:** ~4-5 weeks

---

## Appendix: IEEE 754 Single-Precision Format

```
31 30    23 22                    0
 S EEEEEEEE MMMMMMMMMMMMMMMMMMMMMMM
 │ │      │ │
 │ │      │ └─ 23-bit mantissa (fraction)
 │ │      └─── 8-bit exponent (biased by 127)
 │ └────────── sign bit (0 = positive)
```

**Examples:**
| Value | Hex | Binary |
|-------|-----|--------|
| 0.0f | `0x00000000` | all zeros |
| 1.0f | `0x3f800000` | exp=127, mantissa=0 |
| 2.0f | `0x40000000` | exp=128, mantissa=0 |
| 3.14159f | `0x40490fdb` | |
| -1.0f | `0xbf800000` | sign=1 |

---

## Appendix: x86_64 SSE Quick Reference

### Register Usage (SysV ABI)
- `%xmm0-%xmm7`: Function arguments (float/double)
- `%xmm0`: Return value
- `%xmm0-%xmm15`: All caller-saved

### Common Instructions
```asm
# Move
movss   mem, %xmm0      # load float
movss   %xmm0, mem      # store float
movss   %xmm1, %xmm0    # reg-to-reg

# Arithmetic
addss   %xmm1, %xmm0    # xmm0 += xmm1
subss   %xmm1, %xmm0    # xmm0 -= xmm1
mulss   %xmm1, %xmm0    # xmm0 *= xmm1
divss   %xmm1, %xmm0    # xmm0 /= xmm1

# Compare (sets EFLAGS)
ucomiss %xmm1, %xmm0    # compare xmm0 with xmm1
# Then use: ja, jae, jb, jbe, je, jne, jp (parity = unordered)

# Convert
cvtsi2ss %eax, %xmm0    # int32 → float
cvtsi2ss %rax, %xmm0    # int64 → float
cvtss2si %xmm0, %eax    # float → int32
cvtss2si %xmm0, %rax    # float → int64

# Square root (hardware instruction)
sqrtss  %xmm1, %xmm0    # xmm0 = sqrt(xmm1)
```

### Opcode Prefixes
| Prefix | Meaning |
|--------|---------|
| `F3 0F` | Scalar single (float) |
| `F2 0F` | Scalar double |
| `0F` (no prefix) | Packed single (4 floats) |
| `66 0F` | Packed double (2 doubles) |
