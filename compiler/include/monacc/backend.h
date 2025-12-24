#pragma once

// Backend Code Generation Module (backend.h)
// ===========================================
//
// This header defines the backend code generation interfaces for the monacc
// compiler, specifically assembly emission for different target platforms.
//
// Part of Phase 5 of the monacc compiler structural rebase: Backend Modernization
// The backend now exposes a single unified API (mc_backend_codegen) that handles
// all target platforms and configuration options.
//
// For ELF object file operations, see monacc/elf.h
// For internal linker operations, see monacc/link.h

#include "mc_types.h"
#include "ast.h"    // For Program
#include "util.h"   // For Str

// Forward declarations
typedef struct mc_compiler mc_compiler;

// ===== Backend Configuration =====

// Backend codegen options
typedef struct {
    int with_start;  // Generate _start entry point (only applicable to freestanding targets like x86_64-linux)
} mc_backend_options;

// ===== Unified Code Generation API =====

// Generate assembly code for the given program.
// 
// This is the single entry point for all backend code generation.
// The target platform is determined from ctx->opts.target.
// Additional options can be specified via the opts parameter.
//
// Parameters:
//   ctx  - Compiler context (contains target platform and configuration)
//   prg  - The program to compile
//   out  - Output string buffer for generated assembly
//   opts - Backend-specific options (may be NULL for defaults)
void mc_backend_codegen(mc_compiler *ctx, const Program *prg, Str *out, const mc_backend_options *opts);


