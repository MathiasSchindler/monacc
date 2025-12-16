# Binary Size Optimization Guide

This document provides tools for analyzing monacc's code generation and a roadmap for producing smaller binaries.

## Part 1: Binary Comparison Script

The script `scripts/compare_codegen.sh` compares monacc-generated binaries against the best-in-class (typically gcc-15 or clang-20) to identify code bloat sources.

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
awk           14140 vs   5776 bytes (2.44x)  insns: 4713 vs 1408  push/pop: 904 vs  80  setcc: 34 vs 14  movslq: 69 vs  8  [gcc_15_]
sh            22672 vs   9528 bytes (2.37x)  insns: 7348 vs 2292  push/pop: 1460 vs  98  setcc: 31 vs 13  movslq: 156 vs 17  [gcc_15_]
sed           16972 vs   7472 bytes (2.27x)  insns: 5518 vs 1838  push/pop: 1243 vs 147  setcc: 25 vs 11  movslq: 141 vs 10  [gcc_15_]
find          11459 vs   5408 bytes (2.11x)  insns: 3686 vs 1237  push/pop: 697 vs  98  setcc:  8 vs  4  movslq: 130 vs  9  [gcc_15_]
...
yes            2420 vs   1592 bytes (1.52x)  insns:  791 vs  286  push/pop: 153 vs  26  setcc:  6 vs  5  movslq: 30 vs  4  [clang_20_]
```

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
yes            2420 vs   1592 bytes (1.52x)  insns:  791 vs  286  push/pop: 153 vs  26  setcc:  6 vs  5  movslq: 30 vs  4  [clang_20_]
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

Quick spot-check: `yes` improved from the earlier `1.56x` to about `1.52x` bytes ratio.

Current biggest offenders (from `--all`) remain `awk`, `sh`, `sed`, `find` (and `tail`), with push/pop counts that are still far from gcc/clang. That makes them good targets for verifying each incremental push/pop reduction.

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
