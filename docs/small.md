# Binary Size Optimization Guide

This document provides tools for analyzing monacc's code generation and a roadmap for producing smaller binaries.

## Part 1: Binary Comparison Script

The script `scripts/compare_codegen.sh` compares monacc-generated binaries against the best-in-class (typically gcc-15 or clang-20) to identify code bloat sources.

For broader “instruction-shape” statistics across the full compiler matrix, see [docs/matrixstat.md](docs/matrixstat.md) (`bin/matrixstat`).

### Usage

```bash
# Compare a single tool
./scripts/compare_codegen.sh yes

# Compare all tools, sorted by size ratio (worst first)
./scripts/compare_codegen.sh --all

# Show detailed disassembly comparison
./scripts/compare_codegen.sh --detail yes
```

### Example Output

```
$ ./scripts/compare_codegen.sh --all | head -15
Tool         monacc vs best (ratio)    instructions      push/pop      setcc     movslq    [compiler]
-----------------------------------------------------------------------------------------------------------
awk           13772 vs   5776 bytes (2.38x)  insns: 4351 vs 1408  push/pop: 544 vs  80  setcc: 34 vs 14  movslq: 67 vs  8  [gcc_15_]
sh            21955 vs   9528 bytes (2.30x)  insns: 6717 vs 2292  push/pop: 830 vs  98  setcc: 31 vs 13  movslq: 152 vs 17  [gcc_15_]
sed           16427 vs   7472 bytes (2.19x)  insns: 5005 vs 1838  push/pop: 733 vs 147  setcc: 25 vs 11  movslq: 140 vs 10  [gcc_15_]
find          11157 vs   5408 bytes (2.06x)  insns: 3404 vs 1237  push/pop: 421 vs  98  setcc:  8 vs  4  movslq: 126 vs  9  [gcc_15_]
...
yes            2356 vs   1592 bytes (1.47x)  insns:  723 vs  286  push/pop:  87 vs  26  setcc:  6 vs  5  movslq: 30 vs  4  [clang_20_]
```

Note: for very small tools, fixed ELF header/program-header overhead matters. This repo intentionally uses a size-oriented single-PT_LOAD layout; even one extra program header (e.g. PT_GNU_STACK) costs 56 bytes in every ELF64 output.

### Key Metrics Explained

| Metric | What it measures | Optimization target |
|--------|------------------|---------------------|
| **bytes ratio** | Overall binary size inflation | < 1.5x is good |
| **insns** | Total instruction count | Fewer = better |
| **push/pop** | Stack-based expression evaluation | Should be ~equal to gcc |
| **setcc** | Boolean materialization overhead | Ideally 0-2 per function |
| **movslq** | Unnecessary sign extensions | Minimize via type tracking |

---

## Part 2: Optimization Priorities

Based on analysis of `yes`, `echo`, and other small tools, here are the identified optimization opportunities ranked by impact.

### Phase 1: Foundation (Biggest Wins)

#### P0: Register Allocator
**Expected impact: 30-40% size reduction**

Currently monacc generates code that:
- Spills all variables to stack
- Reloads them for every use
- Uses push/pop for expression temporaries

```asm
; CURRENT: accessing loop variable 'i' multiple times
movslq -0x1030(%rbp),%rax   ; load i
...
movslq -0x1030(%rbp),%rax   ; load i again (same value!)
...
movslq -0x1030(%rbp),%rax   ; and again...

; TARGET: keep i in a register
; (no loads needed, just use %ebx directly)
```

**Implementation approach:**
1. Start with local-only linear scan allocator
2. Track live ranges within basic blocks
3. Allocate caller-saved registers first (rax, rcx, rdx, rsi, rdi, r8-r11)
4. Spill to stack only when registers exhausted

---

#### P1: Eliminate Boolean Materialization  
**Expected impact: 5-10% size reduction**

Currently monacc tends to materialize comparisons to 0/1 when a boolean *value* is required, but for control-flow (e.g. `if/while/for`) we should prefer emitting a direct conditional jump.

**Status (Dec 2025): implemented for control-flow**

Control-flow statements now use a branch-form emitter (`cg_cond_branch`) that handles:
- Comparisons (`== != < <= > >=`) as `cmp/test + jcc`
- Short-circuit `&&` / `||` without intermediate 0/1 booleans
- Logical `!` via inverted branch sense
- Ternary `?:` in condition context by branching into the selected arm

Quick spot-check after the change:

```
yes            2356 vs   1592 bytes (1.47x)  insns:  723 vs  286  push/pop:  87 vs  26  setcc:  6 vs  5  movslq: 30 vs  4  [clang_20_]
```

```asm
; BEFORE: if (argc > 0)
movslq -0x8(%rbp),%rax
test   %rax,%rax
setg   %al                  ; comparison → 0 or 1
movzbl %al,%eax             ; zero-extend
test   %rax,%rax            ; test the boolean
je     .Lfalse

; TARGET: direct conditional jump
cmp    $0,%edi
jle    .Lfalse
```

**Implementation approach:**
1. Recognize `if (expr)` pattern in AST
2. Generate comparison + conditional jump directly
3. Short-circuit `&&` and `||` without intermediate booleans

---

### Phase 2: Peephole Optimizations

#### P2: Push/Pop Elimination
**Expected impact: 10-15% size reduction**

**Status (Dec 2025): partially implemented (targeted codegen fast-paths)**

Instead of a full post-pass peephole optimizer, monacc now avoids some of the most common push/pop patterns directly during expression codegen:
- Stores to locals/globals and simple struct members are emitted as direct memory stores (no “compute address → push → RHS → pop”).
- Constant-index stores (`base[const] = rhs`) can use `lea`/`mov` addressing directly when the base is an addressable array or a pointer value.

Quick spot-check: `yes` improved from the earlier `1.56x` to about `1.47x` bytes ratio.

Current biggest offenders (from `--all`) remain `awk`, `sh`, `sed`, `find` (and `tail`), with push/pop counts that are still far from gcc/clang. That makes them good targets for verifying each incremental push/pop reduction.

Separately, call/syscall lowering now recognizes more “simple args” that can be loaded directly into ABI argument registers without using the push/pop staging path. In particular, common pointer arguments like `&local`, `&global`, and simple `&array[const]` address computations are treated as direct `lea` loads.

This was further expanded to include common pointer arithmetic like `ptr + const` / `ptr - const` (scaled by element size when applicable). These now lower as “load base pointer into arg reg; add/sub imm” rather than going through the stack.

The same mechanism also handles a conservative subset of `ptr ± idx` where `idx` is a simple scalar local/global load and the scale is 1/2/4/8. This uses `%r11` as a dedicated scratch register so it won’t clobber already-loaded ABI arg registers.

This was expanded further to accept small side-effect-free scalar arithmetic in the index, e.g. `p + (i + 1)` / `p + (i - 1)`, by allowing `idx +/- imm32` in the “simple scalar” predicate.

##### P2/P6 Next Steps (Evidence-Driven)

The push/pop gap in the large tools (`awk`, `sh`, `sed`, `find`, `tail`) is still the most obvious signal in `--all`. The following next steps are plausible and measurable:

1. **Broaden “simple index” recognition (still side-effect-free):**
    - Next plausible expansion: accept a limited `idx + idx2` (both scalar loads) for scale=1 using a single `lea` into the scratch.
    - Evidence sources: `./scripts/compare_codegen.sh --detail TOOL` (look for push/pop staging around pointer arithmetic feeding calls/syscalls), and the global `push/pop` counts in `--all`.

2. **Fold address arithmetic into a single `lea` when possible:**
    - Many remaining patterns are “load ptr; add imm; add idx*scale” emitted as separate instructions.
    - Evidence sources: `--detail TOOL` disassembly; count instruction sequences manually; correlate with `insns` and `push/pop` deltas.

3. **Extend regression coverage for each expansion:**
    - The example suite is a good place for targeted ABI/call-lowering tests because it runs via `make test`.
    - Evidence sources: `make test` (correctness), and adding focused examples like `examples/addr_deref_syscall.c` to ensure the new paths assemble and execute.

Many push/pop pairs can be eliminated:

```asm
; CURRENT: computing &struct + offset
lea    -0x20(%rbp),%rax
add    $0x8,%rax
push   %rax                 ; save address
mov    $0x0,%eax            ; compute value
pop    %rcx                 ; restore address  
mov    %rax,(%rcx)          ; store

; TARGET: direct addressing
movq   $0x0,-0x18(%rbp)     ; single instruction!
```

**Implementation approach:**
1. Post-codegen peephole pass
2. Pattern match `push X; ... ; pop Y` → `mov X, Y` when no stack changes between
3. Combine `lea + add` into single `lea` with offset

---

#### P3: Dead Code Elimination
**Expected impact: 3-5% size reduction**

```asm
; CURRENT: redundant operations
xor    %eax,%eax
xor    %eax,%eax            ; duplicate!

; Also: unused function prologues, unreachable code after returns
```

---

#### P3b: Emit Initialized Data for Static Locals (and Globals)
**Expected impact: 1-5% overall, but can be huge for tiny tools**

Today monacc emits all globals into `.bss` using `.zero`, which means it cannot represent initialized objects directly in the binary image. For “initialized static locals” it compensates by generating runtime one-time initialization:

```c
static char s[] = "abc";  // inside a function
```

becomes roughly:

```c
if (!guard) {
    memcpy(storage, "abc\0", 4);
    guard = 1;
}
```

That adds a hidden guard variable plus extra branches and a memcpy sequence, which is disproportionately expensive in tiny programs (for example `clear`).

**Implementation approach (minimal, high value):**
1. Extend `GlobalVar` to optionally carry a simple initializer (start with “string bytes for `char[]`”).
2. For static locals with constant initializers, skip emitting the guard + runtime init statements.
3. In the ELF/asm emitter, emit such globals into `.data.*` as `.byte ...` plus optional `.zero` padding. Ensure the linker layout is packed (single PT_LOAD) so introducing small `.data` does not add large alignment padding.


---

### Phase 3: Type System Improvements

#### P4: Proper Type Width Tracking
**Expected impact: 5% size reduction**

Avoid unnecessary sign/zero extensions:

```asm
; CURRENT: int loop variable
movslq -0x8(%rbp),%rax      ; sign-extend int to long
imul   $0x8,%rax,%rax       ; 64-bit multiply

; TARGET: if we know value fits in 32 bits
mov    -0x8(%rbp),%eax      ; 32-bit load (smaller encoding)
shl    $3,%eax              ; shift instead of multiply
```

---

#### P5: Constant Folding & Propagation
**Expected impact: 2-5% size reduction**

```asm
; CURRENT: multiply by constant 8
imul   $0x8,%rax,%rax

; TARGET: recognized power-of-2
shl    $3,%rax              ; 3 bytes vs 4 bytes, faster too
```

---

### Phase 4: ABI & Calling Convention

#### P6: Direct Syscall Argument Setup
**Expected impact: 3-5% size reduction**

```asm
; CURRENT: syscall args via stack
push   %rax
push   %rax  
push   %rax
push   %rax
pop    %r10
pop    %rdx
pop    %rsi
pop    %rdi
mov    $0xd,%eax
syscall

; TARGET: direct register setup
mov    $0xd,%edi
xor    %esi,%esi
xor    %edx,%edx
xor    %r10d,%r10d
mov    $0xd,%eax
syscall
```

---

### Implementation Roadmap

```
Week 1-2:  P0 - Basic register allocator for locals
           └─ Expected: 30-40% improvement
           
Week 3:    P1 - Direct conditional jumps
           └─ Expected: cumulative 40-50% improvement
           
Week 4:    P2 - Peephole optimizer framework
           └─ Expected: cumulative 50-60% improvement
           
Week 5+:   P3-P6 - Incremental refinements
           └─ Expected: approaching gcc/clang parity
```

### Validation

After each optimization phase, run:

```bash
# Rebuild all binaries
MULTI=1 make clean test

# Compare against baseline
./scripts/compare_codegen.sh --all > after_P0.txt
diff baseline.txt after_P0.txt

# Verify correctness
make test  # all tests must still pass
```

---

## Appendix: Quick Reference

### Disassemble monacc binary (no sections)
```bash
objdump -D -b binary -m i386:x86-64 bin/TOOL | less
```

### Compare specific function
```bash
# Find main in monacc binary (look for call pattern after _start)
objdump -D -b binary -m i386:x86-64 bin/yes | grep -A200 'call.*0x100'
```

### Count bloat indicators
```bash
# Push/pop ratio (should be close to 1.0)
echo "monacc:"; objdump -D -b binary -m i386:x86-64 bin/yes | grep -c 'push\|pop'
echo "gcc:"; objdump -d bin/gcc_15_/yes | grep -c 'push\|pop'
```
