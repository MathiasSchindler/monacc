#pragma once

// Preprocessor Expression Parser (ppexpr.h)
// ==========================================
//
// This header defines the interface for parsing preprocessor conditional
// expressions (#if, #elif) in the monacc compiler.
//
// The ppexpr module evaluates constant expressions in preprocessor directives,
// supporting arithmetic, logical, and bitwise operations, as well as the
// 'defined' operator.

#include "mc_types.h"
#include "token.h"  // For MacroTable

// Evaluate a preprocessor conditional expression.
//
// This function parses and evaluates expressions used in #if and #elif
// directives, such as:
//   #if defined(FOO) && (BAR > 10)
//   #elif VERSION >= 2
//
// Parameters:
//   mt       - Macro table for looking up defined macros and their values
//   expr     - Start of the expression string to parse
//   expr_end - End of the expression string
//
// Returns:
//   Non-zero if the expression evaluates to true, zero otherwise
int pp_eval_if_expr(const MacroTable *mt, const char *expr, const char *expr_end);
