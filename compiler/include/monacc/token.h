#pragma once

// Token and Lexer Module (token.h)
// ==================================
//
// This header defines the token types, lexer state, and tokenization APIs
// used by the monacc compiler frontend.
//
// Part of Phase 3 of the monacc compiler structural rebase: splitting the
// monolithic monacc.h into focused module headers.

#include "mc_types.h"

// ===== Token Types =====

typedef enum {
    TOK_EOF = 0,
    TOK_IDENT,
    TOK_NUM,
    TOK_FLOATNUM,
    TOK_STR,
    TOK_CHAR,
    TOK_KW_INT,
    TOK_KW_CHAR,
    TOK_KW_VOID,
    TOK_KW_FLOAT,
    TOK_KW_TYPEDEF,
    TOK_KW_ENUM,
    TOK_KW_SIZEOF,
    TOK_KW_STRUCT,
    TOK_KW_EXTERN,
    TOK_KW_STATIC,
    TOK_KW_RETURN,
    TOK_KW_IF,
    TOK_KW_ELSE,
    TOK_KW_WHILE,
    TOK_KW_FOR,
    TOK_KW_BREAK,
    TOK_KW_CONTINUE,
    TOK_KW_SWITCH,
    TOK_KW_CASE,
    TOK_KW_DEFAULT,
    TOK_KW_GOTO,
    TOK_LPAREN,
    TOK_RPAREN,
    TOK_LBRACK,
    TOK_RBRACK,
    TOK_LBRACE,
    TOK_RBRACE,
    TOK_SEMI,
    TOK_COMMA,
    TOK_DOT,
    TOK_ELLIPSIS,
    TOK_PLUS,
    TOK_PLUSPLUS,
    TOK_MINUS,
    TOK_MINUSMINUS,
    TOK_PLUSEQ,
    TOK_MINUSEQ,
    TOK_ARROW,
    TOK_STAR,
    TOK_MULEQ,
    TOK_AMP,
    TOK_ANDEQ,
    TOK_ANDAND,
    TOK_CARET,
    TOK_XOREQ,
    TOK_SLASH,
    TOK_DIVEQ,
    TOK_PERCENT,
    TOK_MODEQ,
    TOK_ASSIGN,
    TOK_EQ,
    TOK_NE,
    TOK_BANG,
    TOK_TILDE,
    TOK_PIPE,
    TOK_OREQ,
    TOK_OROR,
    TOK_LT,
    TOK_SHL,
    TOK_SHLEQ,
    TOK_LE,
    TOK_GT,
    TOK_SHR,
    TOK_SHREQ,
    TOK_GE,
    TOK_QMARK,
    TOK_COLON,
} TokenKind;

typedef struct {
    TokenKind kind;
    const char *start;
    mc_usize len;
    long long num;
    int line;
    int col;
} Token;

// ===== Preprocessor Types =====

typedef struct {
    char name[128];
    char *repl;
} Macro;

typedef struct {
    Macro *macros;
    int n;
    int cap;
} MacroTable;

typedef struct {
    char **include_dirs;
    int ninclude_dirs;
} PPConfig;

typedef struct {
    char **paths;
    int n;
    int cap;
} OnceTable;

// ===== Lexer State =====

typedef struct {
    const char *src;
    mc_usize len;
    mc_usize pos;
    char name[128];
} LexExp;

typedef struct {
    const char *path;
    const char *src;
    mc_usize len;
    mc_usize pos;
    int line;
    int col;

    const MacroTable *mt;
    LexExp exp[64];
    int exp_n;
} Lexer;

// ===== Token/Lexer APIs =====

const char *tok_kind_name(TokenKind k);

const char *mt_lookup(const MacroTable *mt, const char *name, mc_usize name_len);
void mt_define(MacroTable *mt, const char *name, mc_usize name_len, const char *repl);

int is_ident_cont(unsigned char c);

Token lex_next(Lexer *lx);
