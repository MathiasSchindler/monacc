# Monacc Frontend API

This document describes the stable frontend API for the monacc compiler.

## Overview

The monacc frontend is responsible for transforming C source code into a typed Abstract Syntax Tree (AST) that can be consumed by the backend for code generation.

The frontend is organized into three main phases:

1. **Preprocessing** (`preprocess_file`) - Expands macros, includes files, handles directives
2. **Parsing** (`parse_program`) - Parses preprocessed source into AST
3. **Semantic Analysis** (`sema_analyze`) - Validates and enriches AST with type information

## API Contract

### Phase 1: Preprocessing

```c
void preprocess_file(mc_compiler *ctx, 
                    const PPConfig *cfg,
                    MacroTable *mt, 
                    OnceTable *ot,
                    const char *path, 
                    Str *out);
```

**Purpose**: Preprocesses a C source file and produces expanded source text.

**Inputs**:
- `ctx` - Compiler context (for diagnostics and options)
- `cfg` - Preprocessor configuration (include paths, etc.)
- `mt` - Macro table (for `#define` tracking)
- `ot` - Once table (for `#pragma once` tracking)
- `path` - Path to source file to preprocess

**Outputs**:
- `out` - String containing preprocessed source code

**Behavior**:
- Processes `#include` directives recursively
- Expands object-like macros (`#define`)
- Handles conditional compilation (`#ifdef`, `#ifndef`, etc.)
- Tracks `#pragma once` to prevent duplicate includes
- Dies on preprocessing errors

### Phase 2: Parsing

```c
void parse_program(Parser *p, Program *out);
```

**Purpose**: Parses preprocessed C source into an Abstract Syntax Tree.

**Inputs**:
- `p` - Parser state (initialized with preprocessed source)

**Outputs**:
- `out` - Program structure (AST) containing:
  - Functions with statement bodies
  - Global variable declarations
  - Type definitions (structs, typedefs, enums)
  - String literals
  - Constants

**AST Structure**:
- **Program**: Top-level container
  - `Function[]` - Function definitions
  - `GlobalVar[]` - Global variables
  - `StructDef[]` - Structure definitions
  - `Typedef[]` - Type aliases
  - `ConstDef[]` - Enum constants
  - `StringLit[]` - String literals

- **Function**: Function definition
  - `name` - Function name
  - `Stmt *body` - Statement tree (function body)
  - Return type information
  - Parameter information
  - Stack layout

- **Stmt**: Statement node (recursive)
  - `kind` - Statement type (block, if, while, for, etc.)
  - `Expr *expr` - Associated expression (if any)
  - Nested statements

- **Expr**: Expression node (recursive)
  - `kind` - Expression type (literal, variable, binary op, etc.)
  - Type information (`base`, `ptr`, `struct_id`, `is_unsigned`, `lval_size`)
  - Subexpressions (`lhs`, `rhs`, `third`)

**Current Implementation Note**:

The parser currently performs type analysis during parsing (single-pass compilation). This means:
- Expression nodes contain complete type information
- Type checking is performed inline with parsing
- The resulting AST is already a typed AST

This is an implementation detail. The API contract allows for future separation where:
- `parse_program()` produces a partially typed AST
- `sema_analyze()` performs the actual type checking

**Behavior**:
- Parses top-level declarations (functions, globals, types)
- Builds expression and statement trees
- Currently: Assigns types to expressions during parsing
- Dies on syntax errors

### Phase 3: Semantic Analysis

```c
int sema_analyze(mc_compiler *ctx, Program *prg);
```

**Purpose**: Performs semantic analysis on a parsed AST to produce a fully typed AST.

**Inputs**:
- `ctx` - Compiler context (for diagnostics)
- `prg` - Parsed AST (may contain partial type information)

**Outputs**:
- `prg` - Modified in-place to contain complete type information (typed AST)

**Returns**:
- `0` on success
- Non-zero on semantic errors

**Semantic Checks** (current and planned):
- Type checking and type inference
- Symbol resolution and scope analysis
- Semantic validation:
  - `break`/`continue` only in loops
  - `return` matches function return type
  - Assignment type compatibility
  - Function call argument types
  - Array bounds (where determinable)
- Type annotations and implicit conversions

**Current Implementation Note**:

Since the parser currently performs type analysis, `sema_analyze()` primarily validates that the AST is well-formed. It checks:
- All expressions have valid type information
- Type information is consistent
- AST structure is valid

**Future Work**:

When type checking is separated from parsing:
- Parser will produce a minimally typed AST (just type names)
- `sema_analyze()` will perform:
  - Full type checking
  - Type inference
  - Implicit conversion insertion
  - Constant folding
  - Dead code detection

**Validation API**:

```c
int sema_validate(mc_compiler *ctx, const Program *prg);
```

Helper function to validate that a Program structure is well-formed. Used for debugging and testing. Returns 0 if valid, non-zero otherwise.

## Usage Example

```c
#include "mc_compiler.h"
#include "monacc.h"

int main(void) {
    mc_compiler ctx;
    mc_compiler_init(&ctx);
    
    // Phase 1: Preprocess
    PPConfig cfg = {0};
    MacroTable mt = {0};
    OnceTable ot = {0};
    Str pp = {0};
    preprocess_file(&ctx, &cfg, &mt, &ot, "input.c", &pp);
    
    // Phase 2: Parse
    Parser p = {0};
    p.ctx = &ctx;
    p.lx.path = "input.c";
    p.lx.src = pp.buf;
    p.lx.len = pp.len;
    p.lx.mt = &mt;
    parser_next(&p);
    
    Program prg = {0};
    p.prg = &prg;
    parse_program(&p, &prg);
    
    // Phase 3: Semantic analysis
    if (sema_analyze(&ctx, &prg) != 0) {
        die("semantic analysis failed");
    }
    
    // AST is now ready for backend code generation
    
    mc_compiler_destroy(&ctx);
    return 0;
}
```

## Testing

The frontend API is tested in `tests/compiler/test-sema-api.sh`, which verifies:
- Sema phase is executed during compilation
- Sema phase runs between parsing and code generation
- Compilation succeeds with sema enabled
- Complex programs (structs, function pointers) work correctly

Run the test:
```bash
./tests/compiler/test-sema-api.sh
```

## Future Evolution

The frontend API is designed to support future architectural improvements:

1. **Cleaner Separation**: Move type checking from parser to sema
2. **Better Diagnostics**: Separate parse errors from type errors
3. **Multi-pass Analysis**: Support analyses that require global information
4. **Advanced Features**: Enable features that need multiple passes:
   - Global type inference
   - Whole-program optimization
   - More sophisticated error recovery

The API contract remains stable even as the implementation evolves.

## See Also

- `compiler/include/monacc/pp.h` - Preprocessor and parser API definitions
- `compiler/include/monacc/sema.h` - Semantic analysis API definitions
- `compiler/include/monacc/ast.h` - AST node type definitions
- `docs/compiler-architecture.md` - Overall compiler architecture
- `docs/compiler-rebase-progress.md` - Structural rebase progress
