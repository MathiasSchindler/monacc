# Binary Size Analysis for monacc

**Date:** December 2025  
**Compilers compared:** monacc (self-hosting), gcc-15, clang-21  
**Platform:** Linux x86_64

## Executive Summary

The monacc compiler produces binaries approximately **2.1× larger** than GCC and **2.0× larger** than Clang on average. For 95 tools, total binary size is:

| Compiler | Total Size | vs GCC |
|----------|-----------|--------|
| monacc   | 819 KB    | 2.11×  |
| gcc-15   | 387 KB    | 1.00×  |
| clang-21 | 408 KB    | 1.05×  |

This is *remarkably good* for a self-hosting compiler. The analysis below identifies specific causes and actionable improvements.

---

## Part 1: Low-Hanging Fruit (Easy Wins)

### 1.1 Frame Pointer Prologues — **HIGH IMPACT**

**Observation from TSV:**
```
prologue_fp:  monacc=2171, gcc=0, clang=0
```

monacc generates frame pointer prologues (`push rbp; mov rbp,rsp`) for *every* function. GCC/Clang with `-fomit-frame-pointer` (the default at `-O2`) emit zero.

**Impact estimate:** Each prologue adds:
- 1 byte: `push rbp` (0x55)
- 3 bytes: `mov rbp, rsp` (48 89 E5)
- 1 byte: `pop rbp` (5D) in epilogue
- Plus the frame pointer `leave` (0xC9) or `mov rsp,rbp` patterns

At 2171 prologues × ~5-7 bytes = **~11-15 KB** of avoidable overhead.

**Recommendation:**
- Add an `-fomit-frame-pointer` mode to monacc
- For leaf functions that don't need stack frames, skip prologue entirely
- This single change could reduce binary size by ~1.5-2%

### 1.2 Excessive Register Spilling — **HIGH IMPACT**

**Observation from TSV:**
```
push: monacc=11212, gcc=4385, clang=4379  (2.6× more)
pop:  monacc=10882, gcc=3220, clang=3137  (3.4× more)
```

monacc is spilling far more registers. Each push/pop pair is 2 bytes minimum.

**Root cause candidates:**
1. Conservative register allocator that over-spills callee-saved registers
2. Using RBP as frame pointer leaves one fewer general register
3. Possibly not tracking register liveness across basic blocks

**Recommendation:**
- Audit register allocation strategy
- Consider linear-scan or graph-coloring allocator improvements
- Track which callee-saved registers are actually modified

### 1.3 Less Aggressive Inlining — **MEDIUM IMPACT**

**Observation from TSV:**
```
call: monacc=12121, gcc=5830, clang=5201  (2.1× more)
```

monacc has twice as many CALL instructions, suggesting less inlining.

**But interestingly:**
```
call_ppm: monacc=15810, gcc=20675, clang=16284
```

The call *density* (per text byte) is actually lower in monacc! This means:
- monacc code is less dense overall
- GCC inlines heavily, making remaining code very call-heavy

**Recommendation:**
- Inline small leaf functions (< 20 instructions)
- Inline functions called only once
- Consider a simple cost/benefit heuristic: if (call_overhead > function_body_size) inline

### 1.4 Dead Code Elimination — **MEDIUM IMPACT**

Looking at source code patterns in `core/`:

```c
// mc_io.c - functions may be included even if unused
mc_i64 mc_write_hex_u64(mc_i32 fd, mc_u64 v) { ... }
void mc_write_hex_nibble(...) { ... }
```

Tools like `true.c` and `false.c` include `mc.h` but use almost nothing:

```c
// true.c - only needs mc_exit(), but links entire core
__attribute__((used)) int main(int argc, char **argv, char **envp) {
    (void)argc; (void)argv; (void)envp;
    return 0;
}
```

**Observation from TSV:**
```
true.c:  monacc=129B, gcc=856B, clang=600B
false.c: monacc=132B, gcc=856B, clang=608B
```

Wait — monacc actually **wins** on minimal programs! The 129 bytes for `true` is excellent.

**However**, for larger programs, unused functions may be included.

**Recommendation:**
- Ensure monacc performs function-level dead code elimination
- Mark functions with `static` where possible to enable DCE
- Consider `-ffunction-sections` + `--gc-sections` equivalent

---

## Part 2: Code Quality Indicators

### 2.1 Zeroing Idioms — **monacc does this well!**

```
xor_zero:  monacc=15718, gcc=3160, clang=3496
mov_imm0:  monacc=53,    gcc=15,   clang=75
```

monacc strongly prefers `xor reg,reg` over `mov reg,0`. This is optimal.

**Status:** ✅ No action needed

### 2.2 LEA Usage — **monacc does this well!**

```
lea: monacc=10433, gcc=4065, clang=4236
```

High LEA usage suggests monacc is doing address computation strength reduction.

**Status:** ✅ No action needed

### 2.3 Stack Traffic Anomaly — **Investigate**

```
stack_load:  monacc=93,   gcc=2070, clang=2829
stack_store: monacc=0,    gcc=1874, clang=1658
```

These numbers are suspiciously low for monacc. Either:
1. The pattern matcher in matrixstat doesn't recognize monacc's stack addressing mode
2. monacc uses RBP-relative addressing that wasn't counted
3. monacc genuinely has different stack access patterns

**Recommendation:**
- Add a diagnostic pass to dump addressing modes used
- Verify the matrixstat tool's pattern matching for monacc output

---

## Part 3: Instruction Sequence Patterns

### 3.1 Conditional Branches

```
jcc: monacc=28499, gcc=11100, clang=12320  (2.6× more)
```

monacc generates significantly more conditional branches. This could indicate:
- Less branch folding/simplification
- Not using CMOV for simple conditionals
- Different control flow graph structure

**Recommendation:**
- Use `setcc` + arithmetic instead of branches where profitable
- Use `cmov` for `x = cond ? a : b` patterns
- Implement branch-to-branch optimization (eliminate jump-to-jump)

### 3.2 Unconditional Jumps

```
jmp: monacc=8511, gcc=3596, clang=2822  (2.4× more)
```

Excess jumps often indicate:
- Poor basic block layout
- Not falling through to likely successors
- Generating jumps where fall-through is possible

**Recommendation:**
- Implement basic block reordering to maximize fall-through
- Eliminate jumps to next instruction
- Thread jumps that lead to other jumps

### 3.3 RET Instruction Count

```
ret: monacc=4626, gcc=3507, clang=3193
```

More RET instructions than necessary could indicate:
- Multiple return points per function that could be merged
- Tail calls not being converted to jumps

**Recommendation:**
- Consider tail call optimization
- Merge multiple returns to single exit point where beneficial

---

## Part 4: Analysis Tool Recommendations

### 4.1 Missing Analysis Capabilities

To further diagnose size issues, consider building these tools:

#### 4.1.1 Instruction Histogram
```
Tool: insthistogram <binary>
Output:
  mov:   12345 (23.4%)
  push:   5678 (10.7%)
  call:   3456 (6.5%)
  ...
```

**Purpose:** Compare instruction mix between compilers

#### 4.1.2 Function Size Report
```
Tool: funcsizes <binary>
Output:
  0x1234 main            1234 bytes
  0x2000 mc_write_all     156 bytes
  0x2100 mc_strlen         32 bytes
  ...
```

**Purpose:** Identify functions that are unexpectedly large

#### 4.1.3 Prologue/Epilogue Analyzer
```
Tool: prologues <binary>
Output:
  Frame pointer prologues: 234
  Leaf functions (no prologue): 12
  Functions with stack frame: 189
  Average stack frame size: 48 bytes
```

**Purpose:** Quantify frame pointer overhead

#### 4.1.4 Addressing Mode Analyzer
```
Tool: addrmode <binary>
Output:
  [rsp+disp8]:  1234
  [rbp-disp8]:  5678
  [rip+disp32]: 890
  [reg+reg*scale]: 123
```

**Purpose:** Understand stack/memory access patterns

### 4.2 Comparative Disassembly Tool

For specific functions, generate side-by-side comparison:

```
Tool: cmpdis <monacc_bin> <gcc_bin> <func_name>
Output:
  monacc (45 bytes)          | gcc (23 bytes)
  ----------------------------|--------------------
  push rbp                   | 
  mov rbp, rsp               |
  push rbx                   | push rbx
  sub rsp, 0x20              | sub rsp, 0x18
  mov rbx, rdi               | mov rbx, rdi
  ...                        | ...
```

---

## Part 5: Source-Level Patterns

### 5.1 Static vs Non-Static Functions

Looking at `core/mc_io.c`:

```c
mc_i64 mc_write_all(mc_i32 fd, const void *buf, mc_usize len) { ... }
mc_i64 mc_write_str(mc_i32 fd, const char *s) { ... }
```

These are external symbols. Consider:
- Making helper functions `static`
- Using `__attribute__((visibility("hidden")))` for internal symbols

### 5.2 Inline Functions in Headers

`mc_syscall.h` has inline syscall wrappers:

```c
static inline mc_i64 mc_sys_read(mc_i32 fd, void *buf, mc_usize len) {
    return mc_syscall3(MC_SYS_read, (mc_i64)fd, (mc_i64)buf, (mc_i64)len);
}
```

These are correctly marked `static inline`. If monacc doesn't inline them, each call site gets a copy.

**Check:** Verify monacc respects `inline` hints.

### 5.3 String Literals

Pattern observed in `mc_io.c`:

```c
(void)mc_write_str(2, argv0);
(void)mc_write_str(2, ": ");
(void)mc_write_str(2, ctx);
(void)mc_write_str(2, ": errno=");
```

Multiple small string literals. Consider:
- String deduplication (identical strings share storage)
- Combining sequential writes into single formatted output

### 5.4 Error Handling Paths

Many tools have patterns like:

```c
if (fd < 0) {
    mc_die_errno(argv0, path, fd);
}
```

The `mc_die_errno` calls are unlikely paths. Consider:
- Marking with `__builtin_expect(fd < 0, 0)`
- Moving error paths to cold sections

---

## Part 6: Specific Per-Tool Analysis

### 6.1 Minimal Tools (true/false)

**monacc wins!**
```
true:  monacc=129B, gcc=856B, clang=600B
false: monacc=132B, gcc=856B, clang=608B
```

The ~6× advantage suggests monacc has excellent minimal runtime. GCC/Clang likely include CRT overhead.

### 6.2 Shell (sh.c)

```
sh: monacc=57KB, gcc=21KB, clang=25KB  (2.7×)
```

The shell is the largest tool and shows the typical 2.7× ratio. At 2725 lines of source, this is a good candidate for detailed analysis.

**Specific patterns in sh.c:**
- Many small helper functions (`sh_write_err`, `sh_write_err2`, etc.)
- Deep nesting in `sh_expand_word` and `sh_tokenize`
- Large switch statements in tokenizer

### 6.3 GPT-2 Inference (gpt2.c)

```
gpt2: monacc=53KB, gcc=22KB, clang=25KB  (2.4×)
```

Compute-heavy with floating-point operations. Check:
- FP register save/restore overhead
- Loop unrolling differences
- SIMD instruction usage (if any)

### 6.4 Crypto Tools (aes128, sha256, gcm128)

```
aes128: monacc=8.8KB, gcc=3.7KB, clang=4.5KB  (2.4×)
sha256: monacc=8.5KB, gcc=3.4KB, clang=3.3KB  (2.5×)
```

These have tight loops with specific bit manipulation. Good targets for:
- Loop optimization analysis
- Checking if rotate instructions are used
- Verifying constant folding

---

## Part 7: Recommended Action Plan

### Phase 1: Quick Wins (1-2 weeks)
1. **Implement frame pointer omission** — Expected: 1.5-2% reduction
2. **Add jump-to-next elimination** — Expected: 0.5-1% reduction
3. **Verify inline function handling** — Expected: 1-2% reduction

### Phase 2: Register Allocation (2-4 weeks)
4. **Improve register allocator liveness tracking**
5. **Reduce callee-saved register usage**
6. **Consider register coalescing**

Expected combined: 5-10% reduction

### Phase 3: Control Flow (2-4 weeks)
7. **Implement CMOV for simple conditionals**
8. **Basic block reordering for fall-through**
9. **Tail call optimization**

Expected combined: 3-5% reduction

### Phase 4: Analysis Tools (ongoing)
10. **Build instruction histogram tool**
11. **Build function size reporter**
12. **Build comparative disassembler**

---

## Part 8: Measurement Methodology

### Current Metrics

The `matrixstat.tsv` data provides excellent coverage:
- Per-function instruction counts
- Opcode pattern frequencies
- Density metrics (ppm)

### Suggested Additional Metrics

1. **Code density**: `text_bytes / n_instructions`
2. **Branch ratio**: `(jcc + jmp) / text_bytes`
3. **Spill ratio**: `(push + pop) / (2 * n_functions)`
4. **Average function size**: `text_bytes / n_functions`

### Regression Testing

Set up CI to track:
```bash
./matrixstat bin/monacc_/ bin/gcc_15_/ bin/clang_21_/ > matrixstat.tsv
# Alert if monacc size increases by >5% without justification
```

---

## Conclusion

The monacc compiler is in excellent shape for a self-hosting compiler. The 2× size overhead is primarily explained by:

1. **Frame pointers everywhere** (~11-15 KB overhead)
2. **Conservative register allocation** (2.6× more push/pop)
3. **Less aggressive inlining** (2× more calls)
4. **More control flow instructions** (2.6× more jumps/branches)

None of these are fundamental architectural issues. With the improvements outlined above, it should be possible to reduce the gap from 2× to 1.4-1.5× within a few months of focused work.

The fact that monacc produces *smaller* binaries for trivial programs (`true`/`false`) demonstrates that the core code generation is sound — the overhead is in optimization passes that GCC/Clang have had decades to develop.

---

*Generated from analysis of matrixstat.tsv and source code in core/ and tools/*
