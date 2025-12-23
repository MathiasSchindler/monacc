# Monacc Compiler Signature Adapters

## Overview

During Phase 2 of the monacc compiler structural rebase, many function signatures were updated to accept an explicit `mc_compiler *ctx` parameter instead of relying on global state. This document describes the adapter/glue functions that provide backward compatibility during this transition.

## Problem

Before Phase 2, functions like `emit_x86_64_sysv_freestanding()` accessed global state implicitly:

```c
// Old signature (implicit global state)
void emit_x86_64_sysv_freestanding(const Program *prg, Str *out);
```

After Phase 2, these functions require an explicit context parameter:

```c
// New signature (explicit context)
void emit_x86_64_sysv_freestanding(mc_compiler *ctx, const Program *prg, Str *out);
```

This signature change can break existing code, test scripts, or tools that call these functions directly.

## Solution: Adapter Functions

The `monacc_adapters.h` header provides backward-compatible glue functions that:

1. **Create a temporary context** with default settings
2. **Call the new function signature** with the temporary context
3. **Clean up the context** after the call

### Example

```c
#include "monacc_adapters.h"

// Old code that doesn't have a context available:
Program prg;
Str output = {0};

// Use the adapter function (creates temporary context internally)
emit_x86_64_sysv_freestanding_noCtx(&prg, &output);

// New code with proper context:
mc_compiler ctx;
mc_compiler_init(&ctx);
emit_x86_64_sysv_freestanding(&ctx, &prg, &output);
mc_compiler_destroy(&ctx);
```

## Available Adapters

### Preprocessor API
- `preprocess_file_noCtx()` - Preprocessor with temporary context

### Backend Code Generation API
- `emit_x86_64_sysv_freestanding_noCtx()` - x86-64 SysV ABI code generation
- `emit_x86_64_sysv_freestanding_with_start_noCtx()` - x86-64 with startup code
- `emit_aarch64_darwin_hosted_noCtx()` - AArch64 Darwin code generation

### Object File API
- `assemble_x86_64_elfobj_noCtx()` - Internal assembler

### AST Utilities API
- `ast_dump_noCtx()` - AST debugging output

## Helper Macro

For easier migration, use the `MONACC_CALL_NOCTX` macro:

```c
// Instead of:
emit_x86_64_sysv_freestanding_noCtx(&prg, &output);

// You can write:
MONACC_CALL_NOCTX(emit_x86_64_sysv_freestanding, &prg, &output);
```

This makes it easier to search for adapter usage during migration.

## Migration Path

### Phase 2 (Current)
- ✅ Adapters created and available in `monacc_adapters.h`
- Existing code can use adapters for backward compatibility
- New code should use explicit context passing

### Phase 3
- Mark adapters as deprecated with warnings
- Update remaining code to use explicit contexts

### Phase 4+
- Remove adapters once all code is migrated
- Only explicit context passing remains

## Best Practices

### DO ✅
- Use adapters for quick compatibility during migration
- Use adapters in test scripts that don't need full context control
- Use `MONACC_CALL_NOCTX` macro for easy searching

### DON'T ❌
- Use adapters in new production code
- Use adapters when you already have a context available
- Chain multiple adapter calls (creates/destroys context each time)

### Performance Note

Adapter functions create and destroy a temporary `mc_compiler` context on each call. If you're making multiple calls, it's more efficient to create the context once:

```c
// Inefficient (creates context 3 times):
preprocess_file_noCtx(cfg1, mt, ot, "file1.c", &out1);
preprocess_file_noCtx(cfg2, mt, ot, "file2.c", &out2);
preprocess_file_noCtx(cfg3, mt, ot, "file3.c", &out3);

// Efficient (creates context once):
mc_compiler ctx;
mc_compiler_init(&ctx);
preprocess_file(&ctx, cfg1, mt, ot, "file1.c", &out1);
preprocess_file(&ctx, cfg2, mt, ot, "file2.c", &out2);
preprocess_file(&ctx, cfg3, mt, ot, "file3.c", &out3);
mc_compiler_destroy(&ctx);
```

## Implementation Details

All adapter functions are implemented as **macros** in `monacc_adapters.h` (not inline functions, since monacc doesn't support `static inline`). This ensures:
- No runtime overhead beyond the context creation/destruction
- Works with monacc's C subset
- No additional object files needed

The macros use `do { ... } while (0)` blocks to ensure they work correctly in all contexts (e.g., in if-statements without braces).

## Testing

Run the adapter test suite to verify functionality:

```bash
./tests/compiler/test-adapters.sh
```

## Related Documentation

- `docs/compiler-architecture.md` - Overall architecture and rebase plan
- `docs/compiler-rebase-progress.md` - Phase 2 progress tracking
- `compiler/mc_compiler.h` - Compiler context structure
- `compiler/include/monacc/backend.h` - New backend API signatures
- `compiler/include/monacc/pp.h` - New preprocessor API signatures
