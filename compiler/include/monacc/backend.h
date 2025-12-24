#pragma once

// Backend Code Generation Module (backend.h)
// ===========================================
//
// This header defines the backend code generation interfaces for the monacc
// compiler, specifically assembly emission for different target platforms.
//
// Part of Phase 3 of the monacc compiler structural rebase: splitting the
// monolithic monacc.h into focused module headers.
//
// For ELF object file operations, see monacc/elf.h
// For internal linker operations, see monacc/link.h

#include "mc_types.h"
#include "ast.h"    // For Program
#include "util.h"   // For Str

// Forward declarations
typedef struct mc_compiler mc_compiler;

// ===== Code Generation APIs =====

// Emit x86_64 assembly for Linux (SysV ABI, freestanding)
void emit_x86_64_sysv_freestanding(mc_compiler *ctx, const Program *prg, Str *out);
void emit_x86_64_sysv_freestanding_with_start(mc_compiler *ctx, const Program *prg, Str *out, int with_start);

// Emit aarch64 assembly for macOS (Darwin, hosted)
void emit_aarch64_darwin_hosted(mc_compiler *ctx, const Program *prg, Str *out);


