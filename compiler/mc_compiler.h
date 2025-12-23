#pragma once

// Compiler Context Module (mc_compiler.h)
// ========================================
// 
// This module provides the central compiler context structure that encapsulates
// all compiler state, making the compiler more modular, testable, and easier to
// reason about.
//
// Part of Phase 2 of the monacc compiler structural rebase. This phase focuses
// on eliminating global variables by moving them into an explicit compiler
// context that gets threaded through the compilation pipeline.
//
// Current State (Phase 2):
//   - Compiler options and configuration (mc_options)
//   - Tracing/debugging state
//   - Lifecycle management (init/destroy)
//
// Future Phases:
//   - Phase 3: Split monolithic monacc.h into focused module headers
//   - Later: Diagnostics subsystem, memory arena management, etc.

#include "monacc.h"

// Forward declarations
typedef struct mc_compiler mc_compiler;
typedef struct mc_diag mc_diag;
typedef struct mc_arena mc_arena;

// Command-line define (-D flag)
typedef struct {
    char *name;
    char *repl;
} CmdDefine;

// Compilation target
typedef enum {
    MC_TARGET_X86_64_LINUX = 0,
    MC_TARGET_AARCH64_DARWIN = 1,
} mc_target;

// Compiler options
typedef struct {
    // Output paths
    const char *out_path;
    const char *dump_pp_path;
    const char *dump_elfobj_path;
    const char *dump_elfsec_path;
    const char *dump_ast_path;      // --dump-ast (dump parsed AST)
    
    // Toolchain selection
    const char *as_prog;
    const char *ld_prog;
    char *as_prog_alloc;  // Needs to be freed
    char *ld_prog_alloc;  // Needs to be freed
    
    // Target and modes
    mc_target target;
    int compile_only;     // -c flag
    int emit_obj;         // --emit-obj (use internal assembler)
    int link_internal;    // --link-internal (use internal linker)
    int use_nmagic;       // ELF NMAGIC flag
    int keep_shdr;        // Keep section headers in output
    
    // Preprocessor config
    PPConfig pp_config;
    
    // Command-line defines
    CmdDefine *cmd_defines;
    int ncmd_defines;
} mc_options;

// Compiler context - holds all compiler state
// 
// This structure is the single source of truth for all compiler-wide state.
// It is passed through the compilation pipeline from the driver (main) down
// through frontend (preprocessor, lexer, parser) and backend (codegen, asm, link).
//
// Evolution:
//   Phase 2 (current): Basic state consolidation (options, trace state)
//   Future phases: Diagnostics, memory arenas, symbol tables, etc.
struct mc_compiler {
    mc_options opts;
    
    // Diagnostics (future: move error reporting here)
    // mc_diag *diag;
    
    // Memory arenas (future: move allocations here)
    // mc_arena *arena;
    
    // Tracing/debugging state
    // These control optional trace output for debugging compiler behavior.
    // Set via --trace-selfhost or MONACC_TRACE environment variable.
    int trace_enabled;
    int trace_force;    // Force tracing (--trace-selfhost)
    int trace_cached;   // Cached environment check result (-1 = unchecked)
    
    // Code generation state
    // Label counters for backend code generation (per-compilation unit state)
    int a64_expr_label_id;  // aarch64 expression label counter
    
    // Memory allocator state (future: move allocator into context)
    // Currently these are unused; the allocator in monacc_sys.c uses globals.
    // Future work: thread context through monacc_malloc/calloc/realloc to enable
    // per-context memory arenas and better isolation between compilation units.
    unsigned char *alloc_cur;  // Current allocation pointer
    mc_usize alloc_left;       // Remaining bytes in current allocation chunk
};

// Initialize compiler context with default options
void mc_compiler_init(mc_compiler *ctx);

// Clean up compiler context
void mc_compiler_destroy(mc_compiler *ctx);

// Parse target string to target enum
mc_target mc_parse_target(const char *s);
