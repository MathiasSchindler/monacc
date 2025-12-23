#pragma once

// Backend Code Generation Module (backend.h)
// ===========================================
//
// This header defines the backend code generation interfaces for the monacc
// compiler, including assembly emission, object file generation, and linking.
//
// Part of Phase 3 of the monacc compiler structural rebase: splitting the
// monolithic monacc.h into focused module headers.

#include "mc_types.h"

// Forward declarations
typedef struct mc_compiler mc_compiler;

// The following types are defined in ast.h and util.h
// which are included before this header in monacc_modules.h
// No forward declarations needed here.

// ===== Code Generation APIs =====

// Emit x86_64 assembly for Linux (SysV ABI, freestanding)
void emit_x86_64_sysv_freestanding(mc_compiler *ctx, const Program *prg, Str *out);
void emit_x86_64_sysv_freestanding_with_start(mc_compiler *ctx, const Program *prg, Str *out, int with_start);

// Emit aarch64 assembly for macOS (Darwin, hosted)
void emit_aarch64_darwin_hosted(mc_compiler *ctx, const Program *prg, Str *out);

// ===== Object File and Linking =====

// Internal toolchain reduction: assemble monacc-emitted x86_64 assembly into an ELF64 relocatable object.
void assemble_x86_64_elfobj(mc_compiler *ctx, const char *asm_buf, mc_usize asm_len, const char *out_o_path);

// ELF utilities (bring-up for internal linker)
void elfobj_dump(const char *path);
void elfsec_dump(const char *path);

// Minimal internal linker (Step 2): link a single .o into an ET_EXEC without relocations.
void link_internal_exec_single_obj(const char *obj_path, const char *out_path);

// Step 4: link multiple objects into a single executable.
void link_internal_exec_objs(const char **obj_paths, int nobj_paths, const char *out_path, int keep_shdr);
