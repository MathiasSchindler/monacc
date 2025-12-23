#pragma once

// Token Module (token.h)
// ======================
//
// Token types and structures for the lexer/parser.
// Part of Phase 3 of the monacc compiler structural rebase.
//
// This module defines:
// - TokenKind enum: All token types recognized by the lexer
// - Token struct: Token representation with location information

#include "mc.h"

// Token types recognized by the lexer
typedef enum {
    TOK_EOF = 0,
    TOK_IDENT,
    TOK_NUM,
    TOK_FLOATNUM,
    TOK_STR,
    TOK_CHAR,
    
    // Keywords
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
    
    // Delimiters
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
    
    // Operators
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

// Token structure - represents a lexed token with source location
typedef struct {
    TokenKind kind;
    const char *start;  // Pointer to token text in source
    mc_usize len;       // Length of token text
    long long num;      // Parsed value for numeric tokens
    int line;           // Line number in source
    int col;            // Column number in source
} Token;
