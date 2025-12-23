# Monacc Compiler Structural Rebase - Progress Tracker

This document tracks the ongoing structural rebase of the monacc compiler as outlined in the epic issue.

## Overview

The structural rebase aims to:
- Decrease coupling between compiler components
- Establish clear architectural boundaries
- Prepare the compiler for future growth and maintainability
- Keep the build/test pipeline working at all times

## Phase 1 – Lock Invariants and Add Safeguards ✅ COMPLETE

**Status:** Complete  
**Documentation:** `docs/phase1-safeguards.md`, `docs/compiler-architecture.md`

### Completed Items
- ✅ Minimal compiler smoke test exists (`tests/compiler/phase1-smoke.sh`)
- ✅ CI integration in Makefile test target
- ✅ Debug toggles available:
  - `--dump-pp <path>` - dump preprocessed output
  - `--dump-elfobj <file.o>` - dump ELF object internals
  - `--dump-elfsec <file>` - dump ELF section info
  - `--dump-ast <file>` - dump parsed AST (**NEW**)
  - `--trace-selfhost` - trace compilation steps
  - `MONACC_TRACE=1` - environment variable tracing
- ✅ Test for AST dump functionality (`tests/compiler/test-dump-ast.sh`)
- ✅ Architecture documentation (`docs/compiler-architecture.md`)

### Tests
All Phase 1 tests passing consistently.

---

## Phase 2 – Introduce Explicit Compiler Context Object 🔄 IN PROGRESS

**Status:** Approximately 50% complete

### Completed Items
- ✅ `struct mc_compiler` and `mc_options` defined in `mc_compiler.h`
- ✅ `mc_compiler_init()` and `mc_compiler_destroy()` implemented
- ✅ Converted `main()` to use `mc_compiler` context
- ✅ Moved all command-line options into `ctx.opts`:
  - `out_path`, `dump_*_path`, `as_prog`, `ld_prog`
  - `dump_ast_path` (**NEW**)
  - `compile_only`, `emit_obj`, `link_internal`
  - `use_nmagic`, `keep_shdr`, `target`
  - `pp_config` (include directories)
  - `cmd_defines` (command-line -D defines)
- ✅ Cleanup handled by `mc_compiler_destroy()`
- ✅ Trace state integrated into context (`trace_force`, `trace_cached`)
- ✅ No global variables found in audit

### Current State
The compiler context is initialized in `main()` and properly manages:
- All compiler options and flags
- Preprocessor configuration
- Command-line defines
- Tracing/debugging state
- Resource cleanup on exit

The context is threaded through key functions like `compile_to_obj()`.

### Remaining Work
- [ ] Unify `Target` enum with `mc_target` enum in mc_compiler.h
- [ ] Thread context through more frontend functions (preprocess_file, parse_program)
- [ ] Thread context through backend functions (emit_x86_64_*, emit_aarch64_*)
- [ ] Consider adding diagnostics subsystem to context
- [ ] Consider adding memory arenas to context

### Test Status
- ✅ Phase 1 smoke tests passing
- ✅ Command-line options working correctly
- ✅ -D define flag working
- ✅ Example programs compile and run

---

## Phase 3 – Split `monacc.h` into Proper Module Headers

**Status:** Not started

### Planned Work
- [ ] Create `compiler/include/monacc/` directory structure
- [ ] Create module-specific headers:
  - `diag.h` - diagnostics and error reporting
  - `token.h` - token types and lexer interface
  - `ast.h` - AST node definitions
  - `types.h` - type system
  - `backend.h` - backend interface
  - `elf.h` - ELF-specific definitions
- [ ] Migrate declarations from `monacc.h` to appropriate headers
- [ ] Update includes throughout codebase
- [ ] Keep `monacc.h` as umbrella header during transition

---

## Phase 4 – Rebase & Clean Up Frontend

**Status:** Not started

### Planned Work
- [ ] Define stable frontend API
- [ ] Split preprocessor:
  - Move to `compiler/src/front/pp/`
  - Separate tokenizer to `lex/`
  - Separate parser to `parse/`
- [ ] Create/complete `ast.c`/`ast.h` with AST construction API
- [ ] Create `sema.c`/`sema.h` for semantic analysis
- [ ] Ensure frontend has no backend dependencies

---

## Phase 5 – Backend Modernization

**Status:** Not started

### Planned Modules
- `back/x64/abi.c` - SysV ABI logic
- `back/x64/isel.c` - instruction selection/lowering
- `back/x64/regalloc.c` - register allocation
- `back/x64/frame.c` - stack frame/prologue/epilogue
- `back/x64/emit.c` - code emission
- `back/x64/fixup.c` - relocation/fixup

### Work
- [ ] Carve up `monacc_codegen.c` (325k+ LOC)
- [ ] Create private headers for backend modules
- [ ] Expose single backend API: `mc_backend_codegen(...)`

---

## Phase 6 – Object Writer Isolation (ELF)

**Status:** Not started

### Planned Work
- [ ] Create `elf/elf_types.h` with ELF constants and structs
- [ ] Create `elf/elf_write.c` for ELF writing logic
- [ ] Define backend→object contract
- [ ] Migrate ELF logic from codegen to ELF module

---

## Phase 7 – Linker Refactor

**Status:** Not started

### Planned Work
- [ ] Define contract: `mc_link_internal(objects[], opts) -> exe bytes`
- [ ] Move logic from `monacc_link.c`
- [ ] Remove frontend/AST dependencies
- [ ] Separate symbol resolution, relocation, layout

---

## Phase 8 – Move Files, Finalize Structure

**Status:** Not started

### Target Directory Structure
```
compiler/
├── include/monacc/
│   ├── compiler.h
│   ├── diag.h
│   ├── token.h
│   ├── ast.h
│   └── ...
├── src/
│   ├── driver/
│   ├── front/
│   │   ├── lex/
│   │   ├── parse/
│   │   ├── pp/
│   │   └── sema/
│   ├── back/
│   │   └── x64/
│   ├── elf/
│   ├── link/
│   └── util/
└── minimal.ld
```

### Work
- [ ] Move source files to new structure
- [ ] Update Makefile build rules
- [ ] Remove umbrella `monacc.h`
- [ ] Clean up vestigial modules

---

## Phase 9 – Post-Rebase Validation

**Status:** Not started

### Validation Checklist
- [ ] All Phase 1 tests pass
- [ ] Bootstrap path works (host CC → bin/monacc)
- [ ] Self-host path works (bin/monacc → bin/monacc-self)
- [ ] Stage-2 self-hosting (bin/monacc-self → bin/monacc-self2)
- [ ] Stage-3 self-hosting (bin/monacc-self2 → bin/monacc-self3)
- [ ] Full test suite passes (`make test`)
- [ ] Documentation added to major headers/modules

---

## Notes

- Each phase should be completed and tested before moving to the next
- All changes maintain backward compatibility with existing tests
- Build system remains functional throughout the rebase
- Self-hosting capability is preserved at each step

---

## Recent Commits

- `5b27fd1` - Add compiler architecture documentation for structural rebase
- `ba03df9` - Add test for --dump-ast functionality  
- `bffb2f2` - Add --dump-ast debug flag (Phase 1 optional debug toggle)
- `afa7fb9` - Initial plan
- `42b0142` - Phase 2 (partial): Move cmd_defines into mc_compiler context
- `060d2c1` - Phase 2 (partial): Begin using mc_compiler context in main()

## Last Updated

2025-12-23
