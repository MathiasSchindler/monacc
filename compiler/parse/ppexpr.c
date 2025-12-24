#include "monacc_libc.h"
#include "mc.h"
#include "monacc_base.h"
#include "include/monacc/token.h"
#include "include/monacc/ppexpr.h"

// ===== Preprocessor Expression Parser (tiny) =====
//
// This module implements a recursive descent parser for preprocessor
// conditional expressions (#if, #elif). It supports:
//   - Integer literals (decimal, hex)
//   - Identifier lookup (treated as 0 if undefined, or macro value if defined)
//   - defined(NAME) operator
//   - Arithmetic: + - * / %
//   - Bitwise: & | ^ ~ << >>
//   - Logical: && || !
//   - Relational: < <= > >= == !=
//   - Parentheses for grouping

typedef struct {
    const MacroTable *mt;
    const char *p;
    const char *end;
} PPExpr;

static void ppexpr_skip_ws(PPExpr *x) {
    while (x->p < x->end && (*x->p == ' ' || *x->p == '\t')) x->p++;
}

static int ppexpr_match(PPExpr *x, const char *lit) {
    const char *p = x->p;
    const char *q = lit;
    while (p < x->end && *q && *p == *q) {
        p++;
        q++;
    }
    if (*q) return 0;
    x->p = p;
    return 1;
}

static int ppexpr_is_ident_start(unsigned char c) {
    return (c == '_') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
}

static int ppexpr_is_ident_cont(unsigned char c) {
    return ppexpr_is_ident_start(c) || (c >= '0' && c <= '9');
}

static long long ppexpr_parse_int_literal(const char *s, mc_usize n, int *ok) {
    *ok = 0;
    if (n == 0) return 0;
    int neg = 0;
    mc_usize i = 0;
    if (s[i] == '+') {
        i++;
    } else if (s[i] == '-') {
        neg = 1;
        i++;
    }
    if (i >= n) return 0;
    int base = 10;
    if (i + 1 < n && s[i] == '0' && (s[i + 1] == 'x' || s[i + 1] == 'X')) {
        base = 16;
        i += 2;
        if (i >= n) return 0;
    }
    long long v = 0;
    for (; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        int d = -1;
        if (c >= '0' && c <= '9') d = (int)(c - '0');
        else if (base == 16 && c >= 'a' && c <= 'f') d = 10 + (int)(c - 'a');
        else if (base == 16 && c >= 'A' && c <= 'F') d = 10 + (int)(c - 'A');
        else break;
        if (d >= base) break;
        v = v * base + d;
        *ok = 1;
    }
    return neg ? -v : v;
}

static long long ppexpr_macro_to_int(const MacroTable *mt, const char *name, mc_usize name_len) {
    const char *repl = mt_lookup(mt, name, name_len);
    if (!repl) return 0;
    // Try to parse a simple integer literal replacement; otherwise treat as 0.
    const char *p = repl;
    while (*p == ' ' || *p == '\t') p++;
    const char *q = p;
    while (*q && *q != ' ' && *q != '\t') q++;
    int ok = 0;
    long long v = ppexpr_parse_int_literal(p, (mc_usize)(q - p), &ok);
    return ok ? v : 0;
}

static long long ppexpr_parse_lor(PPExpr *x);

static long long ppexpr_parse_primary(PPExpr *x) {
    ppexpr_skip_ws(x);

    // defined NAME / defined(NAME)
    {
        const char *save = x->p;
        if (ppexpr_match(x, "defined")) {
            ppexpr_skip_ws(x);
            int paren = 0;
            if (x->p < x->end && *x->p == '(') {
                paren = 1;
                x->p++;
                ppexpr_skip_ws(x);
            }
            const char *name = x->p;
            if (x->p < x->end && ppexpr_is_ident_start((unsigned char)*x->p)) {
                x->p++;
                while (x->p < x->end && ppexpr_is_ident_cont((unsigned char)*x->p)) x->p++;
                mc_usize name_len = (mc_usize)(x->p - name);
                ppexpr_skip_ws(x);
                if (paren) {
                    if (x->p < x->end && *x->p == ')') x->p++;
                }
                return mt_lookup(x->mt, name, name_len) ? 1 : 0;
            }
            // Bad defined(...) usage; treat as 0.
            x->p = save;
        }
    }

    if (x->p < x->end && *x->p == '(') {
        x->p++;
        long long v = ppexpr_parse_lor(x);
        ppexpr_skip_ws(x);
        if (x->p < x->end && *x->p == ')') x->p++;
        return v;
    }

    if (x->p < x->end && (unsigned char)*x->p >= '0' && (unsigned char)*x->p <= '9') {
        const char *s = x->p;
        x->p++;
        while (x->p < x->end) {
            unsigned char c = (unsigned char)*x->p;
            if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') || c == 'x' || c == 'X') {
                x->p++;
            } else {
                break;
            }
        }
        int ok = 0;
        long long v = ppexpr_parse_int_literal(s, (mc_usize)(x->p - s), &ok);
        return ok ? v : 0;
    }

    if (x->p < x->end && ppexpr_is_ident_start((unsigned char)*x->p)) {
        const char *name = x->p;
        x->p++;
        while (x->p < x->end && ppexpr_is_ident_cont((unsigned char)*x->p)) x->p++;
        return ppexpr_macro_to_int(x->mt, name, (mc_usize)(x->p - name));
    }

    // Unknown token -> 0
    return 0;
}

static long long ppexpr_parse_unary(PPExpr *x) {
    ppexpr_skip_ws(x);
    if (x->p < x->end && *x->p == '!') {
        x->p++;
        return !ppexpr_parse_unary(x);
    }
    if (x->p < x->end && *x->p == '~') {
        x->p++;
        return ~ppexpr_parse_unary(x);
    }
    if (x->p < x->end && *x->p == '+') {
        x->p++;
        return +ppexpr_parse_unary(x);
    }
    if (x->p < x->end && *x->p == '-') {
        x->p++;
        return -ppexpr_parse_unary(x);
    }
    return ppexpr_parse_primary(x);
}

static long long ppexpr_parse_mul(PPExpr *x) {
    long long v = ppexpr_parse_unary(x);
    for (;;) {
        ppexpr_skip_ws(x);
        if (x->p < x->end && *x->p == '*') {
            x->p++;
            v = v * ppexpr_parse_unary(x);
            continue;
        }
        if (x->p < x->end && *x->p == '/') {
            x->p++;
            long long r = ppexpr_parse_unary(x);
            v = (r == 0) ? 0 : (v / r);
            continue;
        }
        if (x->p < x->end && *x->p == '%') {
            x->p++;
            long long r = ppexpr_parse_unary(x);
            v = (r == 0) ? 0 : (v % r);
            continue;
        }
        return v;
    }
}

static long long ppexpr_parse_add(PPExpr *x) {
    long long v = ppexpr_parse_mul(x);
    for (;;) {
        ppexpr_skip_ws(x);
        if (x->p < x->end && *x->p == '+') {
            x->p++;
            v = v + ppexpr_parse_mul(x);
            continue;
        }
        if (x->p < x->end && *x->p == '-') {
            x->p++;
            v = v - ppexpr_parse_mul(x);
            continue;
        }
        return v;
    }
}

static long long ppexpr_parse_shift(PPExpr *x) {
    long long v = ppexpr_parse_add(x);
    for (;;) {
        ppexpr_skip_ws(x);
        if (x->p + 1 < x->end && x->p[0] == '<' && x->p[1] == '<') {
            x->p += 2;
            v = v << ppexpr_parse_add(x);
            continue;
        }
        if (x->p + 1 < x->end && x->p[0] == '>' && x->p[1] == '>') {
            x->p += 2;
            v = v >> ppexpr_parse_add(x);
            continue;
        }
        return v;
    }
}

static long long ppexpr_parse_rel(PPExpr *x) {
    long long v = ppexpr_parse_shift(x);
    for (;;) {
        ppexpr_skip_ws(x);
        if (x->p + 1 < x->end && x->p[0] == '<' && x->p[1] == '=') {
            x->p += 2;
            v = (v <= ppexpr_parse_shift(x)) ? 1 : 0;
            continue;
        }
        if (x->p + 1 < x->end && x->p[0] == '>' && x->p[1] == '=') {
            x->p += 2;
            v = (v >= ppexpr_parse_shift(x)) ? 1 : 0;
            continue;
        }
        if (x->p < x->end && *x->p == '<') {
            x->p++;
            v = (v < ppexpr_parse_shift(x)) ? 1 : 0;
            continue;
        }
        if (x->p < x->end && *x->p == '>') {
            x->p++;
            v = (v > ppexpr_parse_shift(x)) ? 1 : 0;
            continue;
        }
        return v;
    }
}

static long long ppexpr_parse_eq(PPExpr *x) {
    long long v = ppexpr_parse_rel(x);
    for (;;) {
        ppexpr_skip_ws(x);
        if (x->p + 1 < x->end && x->p[0] == '=' && x->p[1] == '=') {
            x->p += 2;
            v = (v == ppexpr_parse_rel(x)) ? 1 : 0;
            continue;
        }
        if (x->p + 1 < x->end && x->p[0] == '!' && x->p[1] == '=') {
            x->p += 2;
            v = (v != ppexpr_parse_rel(x)) ? 1 : 0;
            continue;
        }
        return v;
    }
}

static long long ppexpr_parse_band(PPExpr *x) {
    long long v = ppexpr_parse_eq(x);
    for (;;) {
        ppexpr_skip_ws(x);
        if (x->p < x->end && *x->p == '&' && !(x->p + 1 < x->end && x->p[1] == '&')) {
            x->p++;
            v = v & ppexpr_parse_eq(x);
            continue;
        }
        return v;
    }
}

static long long ppexpr_parse_bxor(PPExpr *x) {
    long long v = ppexpr_parse_band(x);
    for (;;) {
        ppexpr_skip_ws(x);
        if (x->p < x->end && *x->p == '^') {
            x->p++;
            v = v ^ ppexpr_parse_band(x);
            continue;
        }
        return v;
    }
}

static long long ppexpr_parse_bor(PPExpr *x) {
    long long v = ppexpr_parse_bxor(x);
    for (;;) {
        ppexpr_skip_ws(x);
        if (x->p < x->end && *x->p == '|' && !(x->p + 1 < x->end && x->p[1] == '|')) {
            x->p++;
            v = v | ppexpr_parse_bxor(x);
            continue;
        }
        return v;
    }
}

static long long ppexpr_parse_land(PPExpr *x) {
    long long v = ppexpr_parse_bor(x);
    for (;;) {
        ppexpr_skip_ws(x);
        if (x->p + 1 < x->end && x->p[0] == '&' && x->p[1] == '&') {
            x->p += 2;
            long long r = ppexpr_parse_bor(x);
            v = ((v != 0) && (r != 0)) ? 1 : 0;
            continue;
        }
        return v;
    }
}

static long long ppexpr_parse_lor(PPExpr *x) {
    long long v = ppexpr_parse_land(x);
    for (;;) {
        ppexpr_skip_ws(x);
        if (x->p + 1 < x->end && x->p[0] == '|' && x->p[1] == '|') {
            x->p += 2;
            long long r = ppexpr_parse_land(x);
            v = ((v != 0) || (r != 0)) ? 1 : 0;
            continue;
        }
        return v;
    }
}

int pp_eval_if_expr(const MacroTable *mt, const char *q, const char *line_end) {
    PPExpr x;
    x.mt = mt;
    x.p = q;
    x.end = line_end;
    long long v = ppexpr_parse_lor(&x);
    return v != 0;
}
