# Monacc Compiler Architecture

## Overview

This document describes the monacc compiler architecture, both current state and the target state after the structural rebase (as outlined in the epic issue).

## Current State (Before Rebase)

### File Organization

```
compiler/
├── mc_compiler.c         # Compiler context (Phase 2 foundation)
├── mc_compiler.h         # Compiler context header
├── monacc.h              # Monolithic header (all types, all declarations)
├── monacc_ast.c          # AST utilities
├── monacc_codegen.c      # Code generation (x86-64 and aarch64)
├── monacc_elfobj.c       # ELF object file emission
├── monacc_elfread.c      # ELF object file reading
├── monacc_fmt.c          # Formatting utilities
├── monacc_front.c        # Frontend (diagnostics, helpers)
├── monacc_libc.h         # Minimal libc interface
├── monacc_link.c         # Internal linker
├── monacc_main.c         # Driver / entry point
├── monacc_parse.c        # Parser
├── monacc_pp.c           # Preprocessor + lexer
├── monacc_selfhost.h     # Self-hosting compatibility
├── monacc_str.c          # String utilities
├── monacc_sys.c          # System call wrappers
└── monacc_sys.h          # System call wrapper headers
```

### Key Issues

1. **Monolithic Header**: `monacc.h` contains all types, structures, and function declarations. This creates tight coupling and makes it hard to understand module boundaries.

2. **Mixed Responsibilities**: Some files mix multiple concerns:
   - `monacc_pp.c` contains both preprocessor and lexer
   - `monacc_codegen.c` contains all backend logic (ABI, instruction selection, register allocation, emission, etc.)

3. **Unclear Boundaries**: No clear separation between:
   - Frontend (lexer, parser, sema) and backend (codegen, asm)
   - Backend and object file writer
   - Object file writer and linker

4. **Global State**: Some global state still exists, though Phase 2 started consolidating it into `mc_compiler`.

## Target State (After Rebase)

### Directory Structure

```
compiler/
├── include/monacc/        # Public module headers
│   ├── ast.h             # AST types and structures
│   ├── backend.h         # Backend interface
│   ├── diag.h            # Diagnostics
│   ├── lex.h             # Lexer interface
│   ├── parse.h           # Parser interface
│   ├── sema.h            # Semantic analysis
│   └── token.h           # Token types
│
├── src/
│   ├── driver/           # Driver/entry point
│   │   └── monacc_main.c
│   │
│   ├── front/            # Frontend
│   │   ├── lex/          # Lexer
│   │   │   └── lex.c
│   │   ├── parse/        # Parser
│   │   │   └── parse.c
│   │   ├── pp/           # Preprocessor
│   │   │   └── pp.c
│   │   ├── sema/         # Semantic analysis
│   │   │   └── sema.c
│   │   ├── ast.c         # AST utilities
│   │   └── diag.c        # Diagnostics
│   │
│   ├── back/             # Backend
│   │   └── x64/          # x86-64 backend
│   │       ├── abi.c     # SysV ABI logic
│   │       ├── isel.c    # Instruction selection
│   │       ├── regalloc.c # Register allocation
│   │       ├── frame.c   # Stack frame/prologue/epilogue
│   │       ├── emit.c    # Code emission
│   │       └── fixup.c   # Relocation/fixup
│   │
│   ├── elf/              # ELF object file support
│   │   ├── elf_types.h   # ELF constants/structures
│   │   ├── elf_read.c    # ELF reading
│   │   └── elf_write.c   # ELF writing
│   │
│   ├── link/             # Internal linker
│   │   └── link.c
│   │
│   └── util/             # Utilities
│       ├── str.c         # String utilities
│       ├── fmt.c         # Formatting
│       └── sys.c         # System wrappers
│
├── mc_compiler.c          # Compiler context
└── mc_compiler.h          # Compiler context header
```

### Module Boundaries

#### Frontend
- **Preprocessor** (`front/pp/`): Handles `#include`, `#define`, etc. Outputs expanded source.
- **Lexer** (`front/lex/`): Tokenizes source → Token stream
- **Parser** (`front/parse/`): Parses tokens → AST
- **Semantic Analysis** (`front/sema/`): Type checking, symbol resolution (future)
- **AST** (`front/ast.c`): AST data structures and utilities
- **Diagnostics** (`front/diag.c`): Error/warning reporting

**Contract**: Frontend produces a fully validated AST. No backend or ELF dependencies.

#### Backend
- **ABI** (`back/x64/abi.c`): Calling convention, parameter passing
- **Instruction Selection** (`back/x64/isel.c`): Lowering AST → machine instructions
- **Register Allocation** (`back/x64/regalloc.c`): Register allocation
- **Frame** (`back/x64/frame.c`): Stack frame layout, prologue/epilogue
- **Emission** (`back/x64/emit.c`): Emit assembly or object code
- **Fixup** (`back/x64/fixup.c`): Relocation information

**Contract**: Backend takes AST, produces assembly or object code. Uses clean interface to object writer.

#### Object Writer
- **ELF Types** (`elf/elf_types.h`): ELF constants, structures
- **ELF Read** (`elf/elf_read.c`): Read/parse ELF files
- **ELF Write** (`elf/elf_write.c`): Write ELF files

**Contract**: Object writer provides clean API for creating/reading ELF files. No knowledge of backend or AST.

#### Linker
- **Link** (`link/link.c`): Links object files into executable

**Contract**: Linker operates on ELF object files only. No frontend or backend dependencies.

## Migration Strategy

The rebase is organized into phases (see main epic issue):

1. **Phase 1**: Lock invariants (tests, debug tools) ✓ COMPLETE
2. **Phase 2**: Introduce explicit compiler context
3. **Phase 3**: Split monolithic header
4. **Phase 4**: Rebase frontend
5. **Phase 5**: Split backend
6. **Phase 6**: Isolate object writer
7. **Phase 7**: Refactor linker
8. **Phase 8**: Move files to new structure
9. **Phase 9**: Post-rebase validation

Each phase maintains a working compiler with passing tests.

## Current Progress

- ✓ Phase 1 complete: Tests and debug infrastructure in place
- Phase 2 started: `mc_compiler` context exists but not fully integrated
- Phases 3-9: Not started

## Testing Strategy

- Phase 1 smoke tests verify basic compilation
- Self-hosting tests verify compiler can compile itself
- Example programs provide regression testing
- New `--dump-ast` flag aids debugging during refactoring

## Next Steps

Continue Phase 2 by:
1. Identifying remaining global state
2. Moving globals into `mc_compiler` context
3. Threading context through function signatures
4. ✅ Using adapter functions to minimize disruption (`monacc_adapters.h` - COMPLETED)

**Adapter Functions (Phase 2 Interim Solution)**

To minimize breakage during signature changes, adapter macros have been created in
`compiler/monacc_adapters.h`. These provide backward-compatible wrappers for functions
whose signatures changed to accept `mc_compiler *ctx` parameters.

The adapters:
- Create temporary contexts with default settings
- Call the new signatures internally
- Enable gradual migration of existing code
- Are documented in `docs/adapters.md`

This approach allows:
- External tools to continue working during the transition
- Incremental migration rather than big-bang changes
- Clear deprecation path for future phases

Then proceed to Phase 3 to begin splitting headers.
