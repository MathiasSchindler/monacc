#pragma once

// Compiler context structure
// This structure encapsulates all global compiler state, making the compiler
// more modular and testable. Part of Phase 2 structural rebase.

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
struct mc_compiler {
    mc_options opts;
    
    // Diagnostics (future: move error reporting here)
    // mc_diag *diag;
    
    // Memory arenas (future: move allocations here)
    // mc_arena *arena;
    
    // State tracking
    int trace_enabled;
};

// Initialize compiler context with default options
void mc_compiler_init(mc_compiler *ctx);

// Clean up compiler context
void mc_compiler_destroy(mc_compiler *ctx);

// Parse target string to target enum
mc_target mc_parse_target(const char *s);
