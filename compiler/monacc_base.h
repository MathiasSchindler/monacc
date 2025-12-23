#pragma once

// Monacc Compiler Base Definitions (monacc_base.h)
// =================================================
//
// This header provides base definitions needed across the monacc compiler:
// - Memory allocation functions (monacc_malloc, monacc_calloc, etc.)
// - Self-host friendly integer bounds macros
//
// This header should be included after monacc_libc.h and mc.h but before
// any module headers.

#include "monacc_libc.h"
#include "mc.h"

// ===== Memory Allocation =====

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
