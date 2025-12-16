// monacc_str.c - String builder for code generation
// Extracted from monacc_codegen.c for better modularity

#include "monacc.h"

// ===== String Builder =====

void str_reserve(Str *s, mc_usize add) {
    if (s->len + add <= s->cap) return;
        mc_usize ncap = s->cap ? s->cap : 4096;
    while (ncap < s->len + add) ncap *= 2;
    char *nb = (char *)monacc_realloc(s->buf, ncap);
    if (!nb) die("oom");
    s->buf = nb;
    s->cap = ncap;
}

void str_append_bytes(Str *s, const char *buf, mc_usize n) {
    if (!buf || n == 0) return;
    str_reserve(s, n + 1);
    mc_memcpy(s->buf + s->len, buf, n);
    s->len += n;
    s->buf[s->len] = 0;
}

static void str_append_cstr(Str *s, const char *cstr) {
    if (!cstr) return;
    str_append_bytes(s, cstr, mc_strlen(cstr));
}

static void str_append_u64_dec(Str *s, unsigned long long v) {
    char tmp[32];
    int n = 0;
    if (v == 0) {
        tmp[n++] = '0';
    } else {
        while (v > 0) {
            unsigned long long q = v / 10ULL;
            unsigned long long r = v - q * 10ULL;
            tmp[n++] = (char)('0' + (int)r);
            v = q;
        }
    }
    for (int i = 0; i < n / 2; i++) {
        char c = tmp[i];
        tmp[i] = tmp[n - 1 - i];
        tmp[n - 1 - i] = c;
    }
    str_append_bytes(s, tmp, (mc_usize)n);
}

static void str_append_i64_dec(Str *s, long long v) {
    if (v < 0) {
        str_append_bytes(s, "-", 1);
        unsigned long long u = (unsigned long long)(-(v + 1)) + 1ULL;
        str_append_u64_dec(s, u);
        return;
    }
    str_append_u64_dec(s, (unsigned long long)v);
}

typedef enum {
    FMT_TOK_END = 0,
    FMT_TOK_LIT,
    FMT_TOK_ESC_PERCENT,
    FMT_TOK_CONV,
    FMT_TOK_BAD,
} FmtTokKind;

typedef struct {
    FmtTokKind kind;
    const char *lit;
    mc_usize lit_len;
    char conv;  // 'd', 'u', 's'
    int is_ll;  // for %lld
} FmtTok;

static const char *fmt_next_tok(const char *p, FmtTok *t) {
    t->kind = FMT_TOK_END;
    t->lit = NULL;
    t->lit_len = 0;
    t->conv = 0;
    t->is_ll = 0;

    if (!p || !*p) return p;

    if (*p != '%') {
        const char *q = p;
        while (*q && *q != '%') q++;
        t->kind = FMT_TOK_LIT;
        t->lit = p;
        t->lit_len = (mc_usize)(q - p);
        return q;
    }

    // '%' sequence
    if (p[1] == '%') {
        t->kind = FMT_TOK_ESC_PERCENT;
        return p + 2;
    }
    if (p[1] == 'd' || p[1] == 'u' || p[1] == 's') {
        t->kind = FMT_TOK_CONV;
        t->conv = p[1];
        return p + 2;
    }
    if (p[1] == 'l' && p[2] == 'l' && p[3] == 'd') {
        t->kind = FMT_TOK_CONV;
        t->conv = 'd';
        t->is_ll = 1;
        return p + 4;
    }
    if (p[1] == 'l' && p[2] == 'l' && p[3] == 'u') {
        t->kind = FMT_TOK_CONV;
        t->conv = 'u';
        t->is_ll = 1;
        return p + 4;
    }

    t->kind = FMT_TOK_BAD;
    return p + 1;
}

typedef enum {
    FMT_ARG_CSTR = 1,
    FMT_ARG_I64,
    FMT_ARG_U64,
} FmtArgKind;

typedef struct {
    FmtArgKind kind;
    const char *s;
    long long i;
    unsigned long long u;
} FmtArg;

static void str_appendf_args(Str *s, const char *fmt, const FmtArg *args, int nargs, int allow_conv) {
    const char *p = fmt;
    int used = 0;
    while (p && *p) {
        FmtTok tok;
        p = fmt_next_tok(p, &tok);
        if (tok.kind == FMT_TOK_LIT) {
            str_append_bytes(s, tok.lit, tok.lit_len);
            continue;
        }
        if (tok.kind == FMT_TOK_ESC_PERCENT) {
            str_append_bytes(s, "%", 1);
            continue;
        }
        if (tok.kind != FMT_TOK_CONV) {
            die("unsupported format");
        }

        if (!allow_conv) {
            // Emit the offending format for easier progress tracking.
            xwrite_best_effort(2, "unsupported str_appendf fmt: ", 26);
            xwrite_best_effort(2, fmt, mc_strlen(fmt));
            xwrite_best_effort(2, "\n", 1);
            die("unsupported str_appendf fmt");
        }

        if (used >= nargs) die("unexpected extra conversion");
        const FmtArg *a = &args[used++];
        if (tok.conv == 's') {
            if (a->kind != FMT_ARG_CSTR) die("string conversion type mismatch");
            str_append_cstr(s, a->s);
            continue;
        }
        if (tok.conv == 'd') {
            if (a->kind != FMT_ARG_I64) die("integer conversion type mismatch");
            str_append_i64_dec(s, a->i);
            continue;
        }
        if (tok.conv == 'u') {
            if (a->kind != FMT_ARG_U64) die("unsigned conversion type mismatch");
            str_append_u64_dec(s, a->u);
            continue;
        }
        die("unsupported conversion");
    }
    if (used != nargs) die("expected exactly one conversion");
}

// `str_appendf`: allow only '%%' escapes (no conversions).
void str_appendf(Str *s, const char *fmt) {
    str_appendf_args(s, fmt, NULL, 0, 0);
}

void str_appendf_i64(Str *s, const char *fmt, long long v) {
    FmtArg a;
    a.kind = FMT_ARG_I64;
    a.i = v;
    a.s = NULL;
    a.u = 0;
    str_appendf_args(s, fmt, &a, 1, 1);
}

void str_appendf_u64(Str *s, const char *fmt, unsigned long long v) {
    FmtArg a;
    a.kind = FMT_ARG_U64;
    a.u = v;
    a.s = NULL;
    a.i = 0;
    str_appendf_args(s, fmt, &a, 1, 1);
}

void str_appendf_s(Str *s, const char *fmt, const char *v) {
    FmtArg a;
    a.kind = FMT_ARG_CSTR;
    a.s = v;
    a.i = 0;
    a.u = 0;
    str_appendf_args(s, fmt, &a, 1, 1);
}

void str_appendf_ss(Str *s, const char *fmt, const char *s0, const char *s1) {
    FmtArg args[2];
    args[0].kind = FMT_ARG_CSTR;
    args[0].s = s0;
    args[0].i = 0;
    args[0].u = 0;
    args[1].kind = FMT_ARG_CSTR;
    args[1].s = s1;
    args[1].i = 0;
    args[1].u = 0;
    str_appendf_args(s, fmt, args, 2, 1);
}

void str_appendf_si(Str *s, const char *fmt, const char *s0, long long i0) {
    FmtArg args[2];
    args[0].kind = FMT_ARG_CSTR;
    args[0].s = s0;
    args[0].i = 0;
    args[0].u = 0;
    args[1].kind = FMT_ARG_I64;
    args[1].s = NULL;
    args[1].i = i0;
    args[1].u = 0;
    str_appendf_args(s, fmt, args, 2, 1);
}

void str_appendf_su(Str *s, const char *fmt, const char *s0, unsigned long long u0) {
    FmtArg args[2];
    args[0].kind = FMT_ARG_CSTR;
    args[0].s = s0;
    args[0].i = 0;
    args[0].u = 0;
    args[1].kind = FMT_ARG_U64;
    args[1].s = NULL;
    args[1].i = 0;
    args[1].u = u0;
    str_appendf_args(s, fmt, args, 2, 1);
}

void str_appendf_is(Str *s, const char *fmt, long long i0, const char *s0) {
    FmtArg args[2];
    args[0].kind = FMT_ARG_I64;
    args[0].s = NULL;
    args[0].i = i0;
    args[0].u = 0;
    args[1].kind = FMT_ARG_CSTR;
    args[1].s = s0;
    args[1].i = 0;
    args[1].u = 0;
    str_appendf_args(s, fmt, args, 2, 1);
}

