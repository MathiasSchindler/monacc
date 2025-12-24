# Implementation Guide: Backend Module Split

## Overview
This guide documents how to complete the modularization of the x86_64 backend.

## Prerequisites
- All placeholder module files exist in `compiler/back/x64/`
- Build system still works (verified)
- Module responsibilities are documented

## Implementation Steps

### Step 1: Create Internal Header
Create `compiler/back/x64/x64_internal.h`:

```c
#pragma once

#include "../../monacc_libc.h"
#include "../../mc.h"
#include "../../monacc_base.h"
#include "../../include/monacc/diag.h"
#include "../../include/monacc/util.h"
#include "../../include/monacc/ast.h"
#include "../../include/monacc/backend.h"
#include "../../mc_compiler.h"

// CG struct from monacc_codegen.c (lines 12-36)
typedef struct CG {
    Str out;
    int label_id;
    const char *fn_name;
    int frameless;
    BaseType ret_base;
    int ret_ptr;
    int ret_struct_id;
    int ret_size;
    int sret_offset;
    int loop_sp;
    int break_label[64];
    int cont_label[64];
    struct {
        char name[128];
        int id;
    } labels[256];
    int nlabels;
    const Program *prg;
} CG;

// SwitchCtx struct from monacc_codegen.c (lines 97-105)
typedef struct SwitchCtx {
    const Stmt *case_nodes[256];
    long long case_values[256];
    int case_labels[256];
    int ncases;
    const Stmt *default_node;
    int default_label;
} SwitchCtx;

// Utility inline function
static inline int new_label(CG *cg) { return cg->label_id++; }

// Function declarations for cross-module calls
// (Add as functions are extracted)
```

### Step 2: Extract emit.c
Lines 790-1027 from monacc_codegen.c:
- `u64_pow2_shift()` - helper
- `emit_load_mem()`, `emit_load_disp()`, `emit_load_disp_reg()` 
- `emit_load_rip()`, `emit_load_rip_reg()`, `emit_load_rip_disp()`
- `emit_store_mem()`, `emit_store_disp()`
- `emit_store_rip()`, `emit_store_rip_disp()`

### Step 3: Update Makefile
Add to `COMPILER_SRC`:
```makefile
COMPILER_SRC := \
...
compiler/monacc_codegen.c \
compiler/back/x64/emit.c \
...
```

### Step 4: Test Build
```bash
make clean
make
# Should build successfully
```

### Step 5: Extract Remaining Modules
Repeat for fixup.c, frame.c, abi.c, regalloc.c, isel.c in that order.

## Testing Strategy
After each module extraction:
1. Verify clean build
2. Run `make test` to ensure no regressions
3. Check binary sizes haven't changed significantly

## Common Pitfalls
- **Circular dependencies**: May need forward declarations in x64_internal.h
- **Static functions**: Need to become non-static for cross-module calls
- **Macro dependencies**: Ensure all macros are visible
- **Missing includes**: Each module needs complete includes

## Completion Criteria
- [ ] All 6 modules contain real extracted code
- [ ] No code duplication
- [ ] Build passes cleanly
- [ ] All tests pass
- [ ] monacc_codegen.c only contains AArch64 code + coordinator
