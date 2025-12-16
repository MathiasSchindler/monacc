#include "monacc.h"

__attribute__((noreturn, format(printf, 1, 2)))
void die(const char *fmt, ...) {
    // Minimal formatter for common diagnostic patterns.
    // This avoids pulling in full printf while still giving actionable errors.
    va_list ap;
    va_start(ap, fmt);

    for (const char *p = fmt; p && *p; p++) {
        if (*p != '%') {
            xwrite_best_effort(2, p, 1);
            continue;
        }
        p++;
        if (!*p) break;

        if (*p == '%') {
            xwrite_best_effort(2, "%", 1);
            continue;
        }

        if (*p == 's') {
            const char *s = va_arg(ap, const char *);
            if (!s) s = "(null)";
            xwrite_best_effort(2, s, mc_strlen(s));
            continue;
        }

        if (*p == 'c') {
            char c = (char)va_arg(ap, int);
            xwrite_best_effort(2, &c, 1);
            continue;
        }

        if (*p == 'd') {
            char buf[32];
            int n = mc_snprint_cstr_i64_cstr(buf, sizeof(buf), "", (mc_i64)va_arg(ap, int), "");
            if (n > 0) xwrite_best_effort(2, buf, (mc_usize)n);
            continue;
        }

        if (*p == 'u') {
            char buf[32];
            int n = mc_snprint_cstr_u64_cstr(buf, sizeof(buf), "", (mc_u64)va_arg(ap, unsigned int), "");
            if (n > 0) xwrite_best_effort(2, buf, (mc_usize)n);
            continue;
        }

        // %.*s
        if (*p == '.') {
            const char *q = p;
            if (q[1] == '*' && q[2] == 's') {
                int n = va_arg(ap, int);
                const char *s = va_arg(ap, const char *);
                if (!s) s = "(null)";
                if (n < 0) n = 0;
                xwrite_best_effort(2, s, (mc_usize)n);
                p += 2;
                continue;
            }
        }

        // Unknown format: print it literally to avoid hiding the error.
        xwrite_best_effort(2, "%", 1);
        xwrite_best_effort(2, p, 1);
    }

    va_end(ap);
    xwrite_best_effort(2, "\n", 1);
    _exit(1);
}

__attribute__((noreturn))
void die_i64(const char *prefix, long long v, const char *suffix) {
    if (!prefix) prefix = "";
    if (!suffix) suffix = "";
    xwrite_best_effort(2, prefix, mc_strlen(prefix));
    char buf[32];
    int n = mc_snprint_cstr_i64_cstr(buf, sizeof(buf), "", (mc_i64)v, "");
    if (n > 0) xwrite_best_effort(2, buf, (mc_usize)n);
    xwrite_best_effort(2, suffix, mc_strlen(suffix));
    xwrite_best_effort(2, "\n", 1);
    _exit(1);
}

const char *tok_kind_name(TokenKind k) {
    switch (k) {
        case TOK_EOF: return "eof";
        case TOK_IDENT: return "identifier";
        case TOK_NUM: return "number";
        case TOK_STR: return "string";
        case TOK_CHAR: return "char";
        case TOK_KW_INT: return "int";
        case TOK_KW_CHAR: return "char";
        case TOK_KW_VOID: return "void";
        case TOK_KW_TYPEDEF: return "typedef";
        case TOK_KW_ENUM: return "enum";
        case TOK_KW_SIZEOF: return "sizeof";
        case TOK_KW_STRUCT: return "struct";
        case TOK_KW_EXTERN: return "extern";
        case TOK_KW_STATIC: return "static";
        case TOK_KW_RETURN: return "return";
        case TOK_KW_IF: return "if";
        case TOK_KW_ELSE: return "else";
        case TOK_KW_WHILE: return "while";
        case TOK_KW_FOR: return "for";
        case TOK_KW_BREAK: return "break";
        case TOK_KW_CONTINUE: return "continue";
        case TOK_KW_GOTO: return "goto";
        case TOK_KW_SWITCH: return "switch";
        case TOK_KW_CASE: return "case";
        case TOK_KW_DEFAULT: return "default";
        case TOK_LPAREN: return "(";
        case TOK_RPAREN: return ")";
        case TOK_LBRACK: return "[";
        case TOK_RBRACK: return "]";
        case TOK_LBRACE: return "{";
        case TOK_RBRACE: return "}";
        case TOK_SEMI: return ";";
        case TOK_COMMA: return ",";
        case TOK_DOT: return ".";
        case TOK_ELLIPSIS: return "...";
        case TOK_PLUS: return "+";
        case TOK_PLUSPLUS: return "++";
        case TOK_PLUSEQ: return "+=";
        case TOK_MINUS: return "-";
        case TOK_MINUSMINUS: return "--";
        case TOK_MINUSEQ: return "-=";
        case TOK_ARROW: return "->";
        case TOK_STAR: return "*";
        case TOK_MULEQ: return "*=";
        case TOK_AMP: return "&";
        case TOK_ANDEQ: return "&=";
        case TOK_ANDAND: return "&&";
        case TOK_CARET: return "^";
        case TOK_XOREQ: return "^=";
        case TOK_SLASH: return "/";
        case TOK_DIVEQ: return "/=";
        case TOK_PERCENT: return "%";
        case TOK_MODEQ: return "%=";
        case TOK_ASSIGN: return "=";
        case TOK_EQ: return "==";
        case TOK_NE: return "!=";
        case TOK_BANG: return "!";
        case TOK_TILDE: return "~";
        case TOK_PIPE: return "|";
        case TOK_OREQ: return "|=";
        case TOK_OROR: return "||";
        case TOK_LT: return "<";
        case TOK_SHL: return "<<";
        case TOK_SHLEQ: return "<<=";
        case TOK_LE: return "<=";
        case TOK_GT: return ">";
        case TOK_SHR: return ">>";
        case TOK_SHREQ: return ">>=";
        case TOK_GE: return ">=";
        case TOK_QMARK: return "?";
        case TOK_COLON: return ":";
    }
    return "?";
}

const char *mt_lookup(const MacroTable *mt, const char *name, mc_usize name_len) {
    if (!mt) return NULL;
    for (int i = mt->n - 1; i >= 0; i--) {
        const Macro *m = &mt->macros[i];
        if (mc_strlen(m->name) == name_len && mc_memcmp(m->name, name, name_len) == 0) {
            return m->repl;
        }
    }
    return NULL;
}

void mt_define(MacroTable *mt, const char *name, mc_usize name_len, const char *repl) {
    if (!mt) return;
    // Replace if already present.
    for (int i = 0; i < mt->n; i++) {
        Macro *m = &mt->macros[i];
        if (mc_strlen(m->name) == name_len && mc_memcmp(m->name, name, name_len) == 0) {
            monacc_free(m->repl);
            {
                const char *src = repl ? repl : "";
                mc_usize n = mc_strlen(src) + 1;
                m->repl = (char *)monacc_malloc(n);
                if (!m->repl) die("oom");
                mc_memcpy(m->repl, src, n);
            }
            return;
        }
    }
    if (mt->n + 1 > mt->cap) {
        int ncap = mt->cap ? mt->cap * 2 : 128;
        Macro *nm = (Macro *)monacc_realloc(mt->macros, (mc_usize)ncap * sizeof(*nm));
        if (!nm) die("oom");
        mt->macros = nm;
        mt->cap = ncap;
    }
    Macro *m = &mt->macros[mt->n++];
    mc_memset(m, 0, sizeof(*m));
    if (name_len == 0 || name_len >= sizeof(m->name)) die("macro name too long");
    mc_memcpy(m->name, name, name_len);
    m->name[name_len] = 0;
    {
        const char *src = repl ? repl : "";
        mc_usize n = mc_strlen(src) + 1;
        m->repl = (char *)monacc_malloc(n);
        if (!m->repl) die("oom");
        mc_memcpy(m->repl, src, n);
    }
}

static int lex_is_expanding(Lexer *lx, const char *name, mc_usize name_len) {
    for (int i = 0; i < lx->exp_n; i++) {
        if (mc_strlen(lx->exp[i].name) == name_len && mc_memcmp(lx->exp[i].name, name, name_len) == 0) return 1;
    }
    return 0;
}

static void lex_push_macro(Lexer *lx, const char *name, mc_usize name_len, const char *repl) {
    if (lx->exp_n >= (int)(sizeof(lx->exp) / sizeof(lx->exp[0]))) {
        die("macro expansion too deep");
    }
    LexExp *e = &lx->exp[lx->exp_n++];
    mc_memset(e, 0, sizeof(*e));
    e->src = repl ? repl : "";
    e->len = mc_strlen(e->src);
    e->pos = 0;
    if (name_len >= sizeof(e->name)) name_len = sizeof(e->name) - 1;
    mc_memcpy(e->name, name, name_len);
    e->name[name_len] = 0;
}

static int is_ident_start(unsigned char c) {
    return (c == '_') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
}

int is_ident_cont(unsigned char c) {
    return is_ident_start(c) || (c >= '0' && c <= '9');
}

static void lex_pop_exhausted(Lexer *lx) {
    while (lx->exp_n > 0) {
        LexExp *e = &lx->exp[lx->exp_n - 1];
        if (e->pos < e->len) break;
        lx->exp_n--;
    }
}

void parser_next(Parser *p) { p->tok = lex_next(&p->lx); }

void expect(Parser *p, TokenKind k, const char *what) {
    if (p->tok.kind != k) {
        int prev_len = (int)p->tok.len;
        if (prev_len > 24) prev_len = 24;
        die("%s:%d:%d: expected %s (got %s '%.*s')", p->lx.path, p->tok.line, p->tok.col, what, tok_kind_name(p->tok.kind),
            prev_len, p->tok.start);
    }
    parser_next(p);
}

void expect_ident(Parser *p, const char **out_start, mc_usize *out_len) {
    if (p->tok.kind != TOK_IDENT) {
        die("%s:%d:%d: expected identifier", p->lx.path, p->tok.line, p->tok.col);
    }
    *out_start = p->tok.start;
    *out_len = p->tok.len;
    parser_next(p);
}

static const char *lex_cur_ptr(Lexer *lx) {
    lex_pop_exhausted(lx);
    if (lx->exp_n > 0) {
        LexExp *e = &lx->exp[lx->exp_n - 1];
        return e->src + e->pos;
    }
    return lx->src + lx->pos;
}

// Like lex_cur_ptr(), but does not pop an exhausted macro expansion.
// This avoids computing token lengths across different buffers when an expansion
// ends exactly at a token boundary.
static const char *lex_cur_ptr_nopop(Lexer *lx) {
    if (lx->exp_n > 0) {
        LexExp *e = &lx->exp[lx->exp_n - 1];
        return e->src + e->pos;
    }
    return lx->src + lx->pos;
}

static unsigned char peekc(Lexer *lx) {
    lex_pop_exhausted(lx);
    if (lx->exp_n > 0) {
        LexExp *e = &lx->exp[lx->exp_n - 1];
        if (e->pos >= e->len) return 0;
        return (unsigned char)e->src[e->pos];
    }
    if (lx->pos >= lx->len) return 0;
    return (unsigned char)lx->src[lx->pos];
}

// Peek without popping an exhausted macro expansion.
// While scanning a token, we must not implicitly jump from an expansion buffer
// back into the base source buffer, or token lengths can become invalid.
static unsigned char peekc_nopop(Lexer *lx) {
    if (lx->exp_n > 0) {
        LexExp *e = &lx->exp[lx->exp_n - 1];
        if (e->pos >= e->len) return 0;
        return (unsigned char)e->src[e->pos];
    }
    if (lx->pos >= lx->len) return 0;
    return (unsigned char)lx->src[lx->pos];
}

static unsigned char peekc2(Lexer *lx) {
    lex_pop_exhausted(lx);
    if (lx->exp_n > 0) {
        LexExp *e = &lx->exp[lx->exp_n - 1];
        if (e->pos + 1 >= e->len) return 0;
        return (unsigned char)e->src[e->pos + 1];
    }
    if (lx->pos + 1 >= lx->len) return 0;
    return (unsigned char)lx->src[lx->pos + 1];
}

static unsigned char getc_lex(Lexer *lx) {
    lex_pop_exhausted(lx);
    if (lx->exp_n > 0) {
        LexExp *e = &lx->exp[lx->exp_n - 1];
        if (e->pos >= e->len) return 0;
        unsigned char c = (unsigned char)e->src[e->pos++];
        // Do not update line/col from macro expansions.
        return c;
    }
    if (lx->pos >= lx->len) return 0;
    unsigned char c = (unsigned char)lx->src[lx->pos++];
    if (c == '\n') {
        lx->line++;
        lx->col = 1;
    } else {
        lx->col++;
    }
    return c;
}

static void skip_ws_and_comments(Lexer *lx) {
    for (;;) {
        unsigned char c = peekc(lx);
        if (c == ' ' || c == '\t' || c == '\r' || c == '\n') {
            (void)getc_lex(lx);
            continue;
        }
        if (c == '/') {
            if (peekc2(lx) == '/') {
                (void)getc_lex(lx);
                (void)getc_lex(lx);
                while (peekc(lx) && peekc(lx) != '\n') (void)getc_lex(lx);
                continue;
            }
            if (peekc2(lx) == '*') {
                (void)getc_lex(lx);
                (void)getc_lex(lx);
                while (peekc(lx)) {
                    unsigned char a = getc_lex(lx);
                    if (a == '*' && peekc(lx) == '/') {
                        (void)getc_lex(lx);
                        break;
                    }
                }
                continue;
            }
        }
        return;
    }
}

Token lex_next(Lexer *lx) {
restart:
    skip_ws_and_comments(lx);

    Token t;
    mc_memset(&t, 0, sizeof(t));
    t.start = lex_cur_ptr(lx);
    t.line = lx->line;
    t.col = lx->col;

    unsigned char c = peekc(lx);
    if (!c) {
        t.kind = TOK_EOF;
        t.len = 0;
        return t;
    }

    if (is_ident_start(c)) {
        (void)getc_lex(lx);
        while (is_ident_cont(peekc_nopop(lx))) (void)getc_lex(lx);
        t.len = (mc_usize)(lex_cur_ptr_nopop(lx) - t.start);
        if (t.len == 3 && mc_memcmp(t.start, "int", 3) == 0) {
            t.kind = TOK_KW_INT;
        } else if (t.len == 4 && mc_memcmp(t.start, "char", 4) == 0) {
            t.kind = TOK_KW_CHAR;
        } else if (t.len == 4 && mc_memcmp(t.start, "void", 4) == 0) {
            t.kind = TOK_KW_VOID;
        } else if (t.len == 7 && mc_memcmp(t.start, "typedef", 7) == 0) {
            t.kind = TOK_KW_TYPEDEF;
        } else if (t.len == 4 && mc_memcmp(t.start, "enum", 4) == 0) {
            t.kind = TOK_KW_ENUM;
        } else if (t.len == 6 && mc_memcmp(t.start, "sizeof", 6) == 0) {
            t.kind = TOK_KW_SIZEOF;
        } else if (t.len == 6 && mc_memcmp(t.start, "struct", 6) == 0) {
            t.kind = TOK_KW_STRUCT;
        } else if (t.len == 6 && mc_memcmp(t.start, "extern", 6) == 0) {
            t.kind = TOK_KW_EXTERN;
        } else if (t.len == 6 && mc_memcmp(t.start, "static", 6) == 0) {
            t.kind = TOK_KW_STATIC;
        } else if (t.len == 6 && mc_memcmp(t.start, "return", 6) == 0) {
            t.kind = TOK_KW_RETURN;
        } else if (t.len == 2 && mc_memcmp(t.start, "if", 2) == 0) {
            t.kind = TOK_KW_IF;
        } else if (t.len == 4 && mc_memcmp(t.start, "else", 4) == 0) {
            t.kind = TOK_KW_ELSE;
        } else if (t.len == 5 && mc_memcmp(t.start, "while", 5) == 0) {
            t.kind = TOK_KW_WHILE;
        } else if (t.len == 3 && mc_memcmp(t.start, "for", 3) == 0) {
            t.kind = TOK_KW_FOR;
        } else if (t.len == 5 && mc_memcmp(t.start, "break", 5) == 0) {
            t.kind = TOK_KW_BREAK;
        } else if (t.len == 8 && mc_memcmp(t.start, "continue", 8) == 0) {
            t.kind = TOK_KW_CONTINUE;
        } else if (t.len == 6 && mc_memcmp(t.start, "switch", 6) == 0) {
            t.kind = TOK_KW_SWITCH;
        } else if (t.len == 4 && mc_memcmp(t.start, "case", 4) == 0) {
            t.kind = TOK_KW_CASE;
        } else if (t.len == 7 && mc_memcmp(t.start, "default", 7) == 0) {
            t.kind = TOK_KW_DEFAULT;
        } else if (t.len == 4 && mc_memcmp(t.start, "goto", 4) == 0) {
            t.kind = TOK_KW_GOTO;
        } else {
            t.kind = TOK_IDENT;
        }
        if (t.kind == TOK_IDENT && lx->mt) {
            const char *repl = mt_lookup(lx->mt, t.start, t.len);
            if (repl && !lex_is_expanding(lx, t.start, t.len)) {
                lex_push_macro(lx, t.start, t.len, repl);
                goto restart;
            }
        }
        return t;
    }

    if (c >= '0' && c <= '9') {
        // Integer literal (subset): decimal/octal/hex + common suffixes (u/U/l/L).
        unsigned long long v = 0;
        int base = 10;

        // Consume first digit using lexer helpers so this works for macro-expansion buffers too.
        unsigned char first = getc_lex(lx);
        v = (unsigned long long)(first - '0');

        if (first == '0') {
            unsigned char n1 = peekc_nopop(lx);
            if (n1 == 'x' || n1 == 'X') {
                base = 16;
                (void)getc_lex(lx); // 'x'
                v = 0;
            } else if (n1 >= '0' && n1 <= '7') {
                base = 8;
                v = 0;
            } else {
                base = 10;
                v = 0;
            }
        }

        if (base == 16) {
            while (1) {
                unsigned char ch = peekc_nopop(lx);
                int d = -1;
                if (ch >= '0' && ch <= '9') d = (int)(ch - '0');
                else if (ch >= 'a' && ch <= 'f') d = 10 + (int)(ch - 'a');
                else if (ch >= 'A' && ch <= 'F') d = 10 + (int)(ch - 'A');
                if (d < 0) break;
                (void)getc_lex(lx);
                v = (v << 4) + (unsigned long long)d;
            }
        } else if (base == 8) {
            while (peekc_nopop(lx) >= '0' && peekc_nopop(lx) <= '7') {
                unsigned char d = getc_lex(lx);
                v = (v << 3) + (unsigned long long)(d - '0');
            }
        } else {
            while (peekc_nopop(lx) >= '0' && peekc_nopop(lx) <= '9') {
                unsigned char d = getc_lex(lx);
                v = v * 10 + (unsigned long long)(d - '0');
            }
        }

        // Consume common integer suffixes: u/U/l/L (including LL, ULL, etc).
        while (peekc_nopop(lx) == 'u' || peekc_nopop(lx) == 'U' || peekc_nopop(lx) == 'l' || peekc_nopop(lx) == 'L') {
            (void)getc_lex(lx);
        }

        t.kind = TOK_NUM;
        t.len = (mc_usize)(lex_cur_ptr_nopop(lx) - t.start);
        t.num = (long long)v;
        return t;
    }

    if (c == '"') {
        (void)getc_lex(lx);
        for (;;) {
            unsigned char ch = peekc_nopop(lx);
            if (!ch || ch == '\n') {
                die("%s:%d:%d: unterminated string literal", lx->path, t.line, t.col);
            }
            if (ch == '"') {
                (void)getc_lex(lx);
                break;
            }
            if (ch == '\\') {
                (void)getc_lex(lx);
                if (!peekc_nopop(lx)) {
                    die("%s:%d:%d: unterminated string escape", lx->path, t.line, t.col);
                }
                (void)getc_lex(lx);
                continue;
            }
            (void)getc_lex(lx);
        }
        t.kind = TOK_STR;
        t.len = (mc_usize)(lex_cur_ptr_nopop(lx) - t.start);
        return t;
    }

    if (c == '\'') {
        (void)getc_lex(lx);
        for (;;) {
            unsigned char ch = peekc_nopop(lx);
            if (!ch || ch == '\n') {
                die("%s:%d:%d: unterminated char literal", lx->path, t.line, t.col);
            }
            if (ch == '\'') {
                (void)getc_lex(lx);
                break;
            }
            if (ch == '\\') {
                (void)getc_lex(lx);
                if (!peekc_nopop(lx)) {
                    die("%s:%d:%d: unterminated char escape", lx->path, t.line, t.col);
                }
                (void)getc_lex(lx);
                continue;
            }
            (void)getc_lex(lx);
        }
        t.kind = TOK_CHAR;
        t.len = (mc_usize)(lex_cur_ptr_nopop(lx) - t.start);
        return t;
    }

    (void)getc_lex(lx);
    t.len = 1;

    // Two-char operators.
    if (c == '=' && peekc(lx) == '=') {
        (void)getc_lex(lx);
        t.kind = TOK_EQ;
        t.len = 2;
        return t;
    }
    if (c == '-' && peekc(lx) == '>') {
        (void)getc_lex(lx);
        t.kind = TOK_ARROW;
        t.len = 2;
        return t;
    }
    if (c == '+' && peekc(lx) == '+') {
        (void)getc_lex(lx);
        t.kind = TOK_PLUSPLUS;
        t.len = 2;
        return t;
    }
    if (c == '+' && peekc(lx) == '=') {
        (void)getc_lex(lx);
        t.kind = TOK_PLUSEQ;
        t.len = 2;
        return t;
    }
    if (c == '-' && peekc(lx) == '-') {
        (void)getc_lex(lx);
        t.kind = TOK_MINUSMINUS;
        t.len = 2;
        return t;
    }
    if (c == '-' && peekc(lx) == '=') {
        (void)getc_lex(lx);
        t.kind = TOK_MINUSEQ;
        t.len = 2;
        return t;
    }
    if (c == '*' && peekc(lx) == '=') {
        (void)getc_lex(lx);
        t.kind = TOK_MULEQ;
        t.len = 2;
        return t;
    }
    if (c == '!' && peekc(lx) == '=') {
        (void)getc_lex(lx);
        t.kind = TOK_NE;
        t.len = 2;
        return t;
    }
    if (c == '&' && peekc(lx) == '&') {
        (void)getc_lex(lx);
        t.kind = TOK_ANDAND;
        t.len = 2;
        return t;
    }
    if (c == '&' && peekc(lx) == '=') {
        (void)getc_lex(lx);
        t.kind = TOK_ANDEQ;
        t.len = 2;
        return t;
    }
    if (c == '|' && peekc(lx) == '|') {
        (void)getc_lex(lx);
        t.kind = TOK_OROR;
        t.len = 2;
        return t;
    }
    if (c == '|' && peekc(lx) == '=') {
        (void)getc_lex(lx);
        t.kind = TOK_OREQ;
        t.len = 2;
        return t;
    }
    if (c == '^' && peekc(lx) == '=') {
        (void)getc_lex(lx);
        t.kind = TOK_XOREQ;
        t.len = 2;
        return t;
    }
    if (c == '/' && peekc(lx) == '=') {
        (void)getc_lex(lx);
        t.kind = TOK_DIVEQ;
        t.len = 2;
        return t;
    }
    if (c == '%' && peekc(lx) == '=') {
        (void)getc_lex(lx);
        t.kind = TOK_MODEQ;
        t.len = 2;
        return t;
    }
    if (c == '<' && peekc(lx) == '<') {
        (void)getc_lex(lx);
        if (peekc(lx) == '=') {
            (void)getc_lex(lx);
            t.kind = TOK_SHLEQ;
            t.len = 3;
        } else {
            t.kind = TOK_SHL;
            t.len = 2;
        }
        return t;
    }
    if (c == '<' && peekc(lx) == '=') {
        (void)getc_lex(lx);
        t.kind = TOK_LE;
        t.len = 2;
        return t;
    }
    if (c == '>' && peekc(lx) == '>') {
        (void)getc_lex(lx);
        if (peekc(lx) == '=') {
            (void)getc_lex(lx);
            t.kind = TOK_SHREQ;
            t.len = 3;
        } else {
            t.kind = TOK_SHR;
            t.len = 2;
        }
        return t;
    }
    if (c == '>' && peekc(lx) == '=') {
        (void)getc_lex(lx);
        t.kind = TOK_GE;
        t.len = 2;
        return t;
    }

    switch (c) {
        case '(':
            t.kind = TOK_LPAREN;
            return t;
        case ')':
            t.kind = TOK_RPAREN;
            return t;
        case '[':
            t.kind = TOK_LBRACK;
            return t;
        case ']':
            t.kind = TOK_RBRACK;
            return t;
        case '{':
            t.kind = TOK_LBRACE;
            return t;
        case '}':
            t.kind = TOK_RBRACE;
            return t;
        case ';':
            t.kind = TOK_SEMI;
            return t;
        case ',':
            t.kind = TOK_COMMA;
            return t;
        case '.':
            if (peekc(lx) == '.' && peekc2(lx) == '.') {
                (void)getc_lex(lx);
                (void)getc_lex(lx);
                t.kind = TOK_ELLIPSIS;
                t.len = 3;
                return t;
            }
            t.kind = TOK_DOT;
            return t;
        case '+':
            t.kind = TOK_PLUS;
            return t;
        case '-':
            t.kind = TOK_MINUS;
            return t;
        case '*':
            t.kind = TOK_STAR;
            return t;
        case '&':
            t.kind = TOK_AMP;
            return t;
        case '|':
            t.kind = TOK_PIPE;
            return t;
        case '^':
            t.kind = TOK_CARET;
            return t;
        case '/':
            t.kind = TOK_SLASH;
            return t;
        case '%':
            t.kind = TOK_PERCENT;
            return t;
        case '=':
            t.kind = TOK_ASSIGN;
            return t;
        case '!':
            t.kind = TOK_BANG;
            return t;
        case '~':
            t.kind = TOK_TILDE;
            return t;
        case '<':
            t.kind = TOK_LT;
            return t;
        case '>':
            t.kind = TOK_GT;
            return t;
        case '?':
            t.kind = TOK_QMARK;
            return t;
        case ':':
            t.kind = TOK_COLON;
            return t;
        default:
            die("%s:%d:%d: unexpected character '%c'", lx->path, t.line, t.col, (char)c);
            __builtin_unreachable();
    }
}

