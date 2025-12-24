# x86_64 Backend Modules

This directory contains the x86_64 code generation backend, split from the monolithic `monacc_codegen.c`.

## Module Organization

### Modules To Be Implemented

The following modules have placeholder files created but code not yet extracted:

- `emit.c` - Low-level assembly instruction emission
  - Lines to extract from monacc_codegen.c: ~790-1027 (~250 lines)
  - emit_load_*, emit_store_* functions

- `abi.c` - SysV ABI compliance
  - Parameter classification and calling conventions
  - SRET (struct return) handling  
  - Syscall builtin detection
  
- `isel.c` - Instruction selection/lowering
  - Expression code generation
  - Statement code generation
  - Binary operations, comparisons
  - Control flow
  
- `regalloc.c` - Register allocation
  - Register selection for temporaries
  - Spill code generation
  
- `frame.c` - Stack frame management
  - Prologue/epilogue generation
  - Parameter spilling
  - Stack layout
  
- `fixup.c` - Data sections and relocations
  - .rodata, .data, .bss emission
  - _start stub generation
  - Relocation handling

## Current Status

**Phase 1 (Completed)**: Directory structure created, placeholder files established, implementation guide documented

**Phase 2 (Not Started)**: Code extraction from monacc_codegen.c

The bulk of x86_64 codegen logic remains in `../../monacc_codegen.c`.
Clear section markers and documentation indicate which code belongs in which module.

## Integration

New backend files must be added to the Makefile's `COMPILER_SRC` list.
See `../../Makefile` (root of project).
