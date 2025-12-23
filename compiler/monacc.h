#pragma once

#ifdef SELFHOST
#include "monacc_selfhost.h"
#endif

// Minimal libc surface used across the compiler.
#include "monacc_libc.h"

// Shared core helpers (string/mem, syscalls, parsing, etc).
#include "mc.h"

// Forward declarations for compiler context (defined in mc_compiler.h)
typedef struct mc_compiler mc_compiler;

// ===== Module Headers =====
// The compiler is organized into focused modules. All type definitions,
// function declarations, and APIs have been migrated to their narrowest
// reasonable headers:
//   - monacc/diag.h    - Diagnostic and error reporting
//   - monacc/token.h   - Token types and lexer
//   - monacc/ast.h     - AST node types and program structure
//   - monacc/pp.h      - Preprocessor and parser
//   - monacc/backend.h - Code generation and linking
//   - monacc/util.h    - String builders and file I/O
//
// This header includes all module headers for backward compatibility.
#include "include/monacc_modules.h"
// ===== End Module Headers =====

void *monacc_malloc(mc_usize size);
void *monacc_calloc(mc_usize nmemb, mc_usize size);
void *monacc_realloc(void *ptr, mc_usize size);
void monacc_free(void *ptr);

// ===== Self-host friendly integer bounds =====
// monacc's lexer currently ignores integer suffixes (u/U/l/L), and tokenizes
// negative literals as unary '-' applied to a positive literal token.
//
// This means the source-level literal `-2147483648LL` becomes `-(2147483648)`
// during self-host builds. Since 2147483648 does not fit in signed-32, it gets
// treated as an unsigned 32-bit literal, which breaks i32 range checks and can
// cascade into miscompilations (notably signed-vs-unsigned compares against
// small literals).
//
// Use expressions that only contain in-range positive literals.
#define MC_I32_MIN (-2147483647LL - 1LL)
#define MC_I32_MAX (2147483647LL)
#define MC_U32_MAX (0xffffffffULL)


