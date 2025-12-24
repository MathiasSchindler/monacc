# Backend Modularization Status

## Goal
Split `monacc_codegen.c` (7846 lines) into focused x86_64 backend modules.

## Current Implementation
Due to the complexity and tight coupling of the existing code, this is being done in phases:

### Phase 1: Structure Establishment (COMPLETE)
- ✅ Created `back/x64/` directory
- ✅ Documented module responsibilities
- ✅ Identified code boundaries

### Phase 2: Code Extraction (IN PROGRESS)
The following approach is being used:

1. **Keep core in monacc_codegen.c** with clear section markers showing module boundaries
2. **Extract cleanly separable code** first (emit functions, data sections)
3. **Gradual migration** of tightly coupled code as dependencies are resolved

### Recommended Next Steps

1. Extract `emit.c`:
   - emit_load_* functions (lines ~801-930 of monacc_codegen.c)
   - emit_store_* functions (lines ~961-1027)
   - Helper: u64_pow2_shift

2. Extract `fixup.c`:
   - String literal emission (lines ~4651-4670)
   - Global variable emission (lines ~4672-4739)
   - _start stub generation (lines ~4741-4803)

3. Extract `frame.c`:
   - Prologue generation (lines ~4831-4836)
   - Epilogue generation (lines ~4884-4889)
   - Parameter spilling (lines ~4838-4875)

4. Extract `abi.c`:
   - fn_can_be_frameless (line ~1053)
   - expr_is_syscall_builtin (line ~323)
   - expr_is_simple_* functions (lines ~334-475)
   - cg_call (line ~1355)
   - cg_sret_call (line ~1754)

5. Extract `regalloc.c`:
   - cg_expr_to_reg* functions (lines ~477-788)

6. Extract `isel.c` (most complex - do last):
   - cg_expr (line ~2658)
   - cg_binop (line ~2175)
   - cg_stmt (line ~4336)
   - cg_asm_stmt (line ~4040)
   - All supporting functions

## Why This Approach?

The existing code has significant coupling:
- Shared CG state structure
- Cross-module function calls
- Forward declarations dependencies

A "big bang" rewrite risks breaking the build. Incremental extraction with testing at each step is safer and more maintainable.
