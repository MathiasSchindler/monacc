#pragma once

// Semantic Analysis Module (sema.h)
// ===================================
//
// This header defines the semantic analysis interface for the monacc compiler.
// Semantic analysis takes a parsed AST and performs type checking, symbol
// resolution, and semantic validation to produce a fully typed AST.
//
// Part of Phase 4 of the monacc compiler structural rebase: establishing a
// stable frontend API that separates parsing from semantic analysis.
//
// Frontend API Contract:
//   1. parse() - Produces an AST from source code (may have partial type info)
//   2. sema()  - Performs semantic analysis and produces a fully typed AST
//
// Current Implementation Note:
//   The monacc compiler currently performs type analysis during parsing
//   (single-pass compilation). This module defines the API contract for
//   future separation of concerns, where parsing and semantic analysis
//   can be cleanly separated.

#include "mc_types.h"
#include "ast.h"

// Forward declarations
typedef struct mc_compiler mc_compiler;
typedef struct Program Program;

// ===== Semantic Analysis API =====

// Perform semantic analysis on a parsed AST.
//
// This function takes a Program (AST) produced by parse_program() and performs:
//   - Type checking and type inference
//   - Symbol resolution and scope analysis
//   - Semantic validation (e.g., break/continue in loops, return in functions)
//   - Type annotations and conversions
//
// Input:
//   ctx - Compiler context (for diagnostics and options)
//   prg - Parsed AST (may contain partial type information)
//
// Output:
//   prg - Modified in-place to contain full type information (typed AST)
//
// Returns:
//   0 on success (prg now contains a fully typed AST)
//   Non-zero on semantic errors (compilation should abort)
//
// Current Implementation:
//   Since monacc currently performs type analysis during parsing, this
//   function validates that the AST is already well-formed. In the future,
//   this will perform the actual type checking and semantic analysis.
int sema_analyze(mc_compiler *ctx, Program *prg);

// Validate that a Program structure is well-formed (typed AST invariants).
//
// This function checks that:
//   - All expressions have valid type information
//   - All symbols are properly resolved
//   - Semantic constraints are satisfied
//
// This is primarily a validation/assertion function used for debugging
// and verifying the AST after parsing or semantic analysis.
//
// Returns:
//   0 if AST is well-formed
//   Non-zero if validation fails
int sema_validate(mc_compiler *ctx, const Program *prg);
