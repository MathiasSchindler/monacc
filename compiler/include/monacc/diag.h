#pragma once

// Diagnostics Module (diag.h)
// ============================
//
// This header defines the diagnostic and error reporting interfaces for the
// monacc compiler.
//
// Part of Phase 3 of the monacc compiler structural rebase: splitting the
// monolithic monacc.h into focused module headers.

#include "mc_types.h"

// ===== Error Reporting APIs =====

// Fatal error with formatted message
__attribute__((noreturn, format(printf, 1, 2)))
void die(const char *fmt, ...);

// Fatal error with integer value
__attribute__((noreturn))
void die_i64(const char *prefix, long long v, const char *suffix);

// Error message (non-fatal)
__attribute__((format(printf, 1, 2)))
void errf(const char *fmt, ...);

#ifndef SELFHOST
// Formatted output helpers (not available in self-host builds)
int mc_vsnprintf(char *dst, mc_usize cap, const char *fmt, va_list ap);
__attribute__((format(printf, 3, 4)))
int mc_snprintf(char *dst, mc_usize cap, const char *fmt, ...);
#endif
