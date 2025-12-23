#pragma once

// Preprocessor Module (pp.h)
// ===========================
//
// This header defines the preprocessor interfaces for the monacc compiler,
// including file preprocessing and parser state management.
//
// Part of Phase 3 of the monacc compiler structural rebase: splitting the
// monolithic monacc.h into focused module headers.

#include "mc_types.h"
#include "token.h"  // For Lexer, Token, TokenKind, PPConfig, MacroTable, OnceTable
#include "ast.h"    // For Program
#include "util.h"   // For Str

// Forward declarations
typedef struct mc_compiler mc_compiler;

// ===== Parser State =====

typedef struct Parser {
    Lexer lx;
    Token tok;
    Program *prg;
    mc_compiler *ctx;  // Compiler context for diagnostics, tracing
    char cur_fn_name[128];
} Parser;

// ===== Preprocessor APIs =====

void preprocess_file(mc_compiler *ctx, const PPConfig *cfg, MacroTable *mt, OnceTable *ot, const char *path, Str *out);

// ===== Parser APIs =====

void parser_next(Parser *p);
void expect(Parser *p, TokenKind k, const char *what);
void expect_ident(Parser *p, const char **out_start, mc_usize *out_len);

void parse_program(Parser *p, Program *out);
