#pragma once

// Monacc Compiler Signature Adapters (monacc_adapters.h)
// ========================================================
//
// This header provides backward-compatible glue functions / adapters for
// functions whose signatures changed during the Phase 2 compiler context
// refactoring.
//
// Purpose:
//   - Minimize breakage during the transition from global state to explicit
//     context passing
//   - Allow gradual migration of code to the new signatures
//   - Provide a clear deprecation path for old-style calls
//
// Usage:
//   Include this header when you need to call compiler functions but don't
//   have an mc_compiler context available. These adapters will create a
//   temporary context with default settings.
//
// Migration Path:
//   Phase 2: Create adapters (this file)
//   Phase 3: Mark adapters as deprecated
//   Phase 4+: Remove adapters once all code is migrated
//
// Important:
//   - These adapters create temporary contexts - use sparingly
//   - Prefer passing the actual mc_compiler context when available
//   - Do not use adapters in new code
//
// Implementation Note:
//   Since monacc doesn't support 'static inline' functions, these adapters
//   are implemented as macro wrappers that create temporary contexts.

#include "mc_compiler.h"
#include "monacc.h"

// ===== Preprocessor API Adapters =====

// Adapter: preprocess_file without context
// Creates a temporary default context for preprocessing
#define preprocess_file_noCtx(cfg, mt, ot, path, out) \
    do { \
        mc_compiler _adapter_ctx; \
        mc_compiler_init(&_adapter_ctx); \
        if (cfg) { \
            _adapter_ctx.opts.pp_config = *(cfg); \
        } \
        preprocess_file(&_adapter_ctx, cfg, mt, ot, path, out); \
        _adapter_ctx.opts.pp_config.include_dirs = NULL; \
        _adapter_ctx.opts.pp_config.ninclude_dirs = 0; \
        mc_compiler_destroy(&_adapter_ctx); \
    } while (0)

// ===== Backend Code Generation API Adapters =====

// Adapter: emit_x86_64_sysv_freestanding without context
#define emit_x86_64_sysv_freestanding_noCtx(prg, out) \
    do { \
        mc_compiler _adapter_ctx; \
        mc_compiler_init(&_adapter_ctx); \
        emit_x86_64_sysv_freestanding(&_adapter_ctx, prg, out); \
        mc_compiler_destroy(&_adapter_ctx); \
    } while (0)

// Adapter: emit_x86_64_sysv_freestanding_with_start without context
#define emit_x86_64_sysv_freestanding_with_start_noCtx(prg, out, with_start) \
    do { \
        mc_compiler _adapter_ctx; \
        mc_compiler_init(&_adapter_ctx); \
        emit_x86_64_sysv_freestanding_with_start(&_adapter_ctx, prg, out, with_start); \
        mc_compiler_destroy(&_adapter_ctx); \
    } while (0)

// Adapter: emit_aarch64_darwin_hosted without context
#define emit_aarch64_darwin_hosted_noCtx(prg, out) \
    do { \
        mc_compiler _adapter_ctx; \
        mc_compiler_init(&_adapter_ctx); \
        emit_aarch64_darwin_hosted(&_adapter_ctx, prg, out); \
        mc_compiler_destroy(&_adapter_ctx); \
    } while (0)

// ===== Object File API Adapters =====

// Adapter: assemble_x86_64_elfobj without context
#define assemble_x86_64_elfobj_noCtx(asm_buf, asm_len, out_o_path) \
    do { \
        mc_compiler _adapter_ctx; \
        mc_compiler_init(&_adapter_ctx); \
        assemble_x86_64_elfobj(&_adapter_ctx, asm_buf, asm_len, out_o_path); \
        mc_compiler_destroy(&_adapter_ctx); \
    } while (0)

// ===== AST Utilities API Adapters =====

// Adapter: ast_dump without context
#define ast_dump_noCtx(prg, path) \
    do { \
        mc_compiler _adapter_ctx; \
        mc_compiler_init(&_adapter_ctx); \
        ast_dump(&_adapter_ctx, prg, path); \
        mc_compiler_destroy(&_adapter_ctx); \
    } while (0)

// ===== Migration Helper Macros =====

// These macros can be used to mark code that needs migration:
// 
// Before Phase 2:
//   emit_x86_64_sysv_freestanding(prg, out);
//
// During Phase 2 (using adapter):
//   MONACC_CALL_NOCTX(emit_x86_64_sysv_freestanding, prg, out);
//
// After Phase 2 (with context):
//   emit_x86_64_sysv_freestanding(ctx, prg, out);

#define MONACC_CALL_NOCTX(func, ...) func##_noCtx(__VA_ARGS__)

