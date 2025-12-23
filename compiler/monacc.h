#pragma once

#ifdef SELFHOST
#include "monacc_selfhost.h"
#endif

// Minimal libc surface used across the compiler.
#include "monacc_libc.h"

// Shared core helpers (string/mem, syscalls, parsing, etc).
#include "mc.h"

// Monacc base definitions (memory allocation, integer bounds).
#include "monacc_base.h"

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
// New code should include specific module headers as needed.
#include "include/monacc_modules.h"
// ===== End Module Headers =====

