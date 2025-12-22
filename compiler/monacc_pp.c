#include "monacc.h"

// Keep path buffers explicit to avoid pulling in <limits.h> for PATH_MAX.
#ifndef MONACC_PATH_MAX
#define MONACC_PATH_MAX 4096
#endif

static char *pp_strip_comments_and_trim(const char *s, mc_usize len) {
    // Remove C comments from a single line of macro replacement text.
    // This matches typical preprocessing behavior (comments are removed before macro replacement is stored).
    char *out = (char *)monacc_malloc(len + 1);
    if (!out) die("oom");
    mc_usize j = 0;
    int in_str = 0;
    int in_chr = 0;

    for (mc_usize i = 0; i < len; i++) {
        char c = s[i];
        char n = (i + 1 < len) ? s[i + 1] : 0;

        if (!in_str && !in_chr) {
            if (c == '/' && n == '/') {
                break; // rest of line is comment
            }
            if (c == '/' && n == '*') {
                i += 2;
                while (i + 1 < len) {
                    if (s[i] == '*' && s[i + 1] == '/') {
                        i++;
                        break;
                    }
                    i++;
                }
                continue;
            }
            if (c == '"') {
                in_str = 1;
            } else if (c == '\'') {
                in_chr = 1;
            }
            out[j++] = c;
            continue;
        }

        // Inside string/char: copy, honoring escapes.
        out[j++] = c;
        if (c == '\\') {
            if (i + 1 < len) {
                out[j++] = s[++i];
            }
            continue;
        }
        if (in_str && c == '"') {
            in_str = 0;
        } else if (in_chr && c == '\'') {
            in_chr = 0;
        }
    }

    while (j > 0 && (out[j - 1] == ' ' || out[j - 1] == '\t')) j--;
    out[j] = 0;
    return out;
}

// ===== Preprocessor (tiny) =====

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

static int pp_eval_if_expr(const MacroTable *mt, const char *q, const char *line_end) {
    PPExpr x;
    x.mt = mt;
    x.p = q;
    x.end = line_end;
    long long v = ppexpr_parse_lor(&x);
    return v != 0;
}

static int once_contains(const OnceTable *ot, const char *path) {
    for (int i = 0; i < ot->n; i++) {
        if (mc_strcmp(ot->paths[i], path) == 0) return 1;
    }
    return 0;
}

static void once_add(OnceTable *ot, const char *path) {
    if (once_contains(ot, path)) return;
    if (ot->n + 1 > ot->cap) {
        int ncap = ot->cap ? ot->cap * 2 : 64;
        char **np = (char **)monacc_realloc(ot->paths, (mc_usize)ncap * sizeof(char *));
        if (!np) die("oom");
        ot->paths = np;
        ot->cap = ncap;
    }
    mc_usize n = mc_strlen(path) + 1;
    ot->paths[ot->n] = (char *)monacc_malloc(n);
    if (!ot->paths[ot->n]) die("oom");
    mc_memcpy(ot->paths[ot->n], path, n);
    ot->n++;
}

static char *slurp_file(const char *path, mc_usize *out_len) {
    int fd = xopen_ro(path);

    mc_usize cap = 4096;
    char *buf = (char *)monacc_malloc(cap);
    if (!buf) die("oom");
    mc_usize n = 0;

    for (;;) {
        if (n + 1 >= cap) {
            mc_usize ncap = cap * 2;
            char *nb = (char *)monacc_realloc(buf, ncap);
            if (!nb) die("oom");
            buf = nb;
            cap = ncap;
        }

        mc_isize r = xread_retry(fd, buf + n, (cap - 1) - n);
        if (r < 0) die("read %s failed", path);
        if (r == 0) break;
        n += (mc_usize)r;
    }
    buf[n] = 0;

    xclose_checked(fd, "close", path);
    if (out_len) *out_len = n;
    return buf;
}

static void path_dirname(const char *in, char *out, mc_usize out_cap) {
    const char *slash = mc_strrchr(in, '/');
    if (!slash) {
        if (out_cap) {
            out[0] = '.';
            if (out_cap > 1) out[1] = 0;
        }
        return;
    }
    mc_usize n = (mc_usize)(slash - in);
    if (n == 0) n = 1;
    if (n + 1 > out_cap) die("path too long");
    mc_memcpy(out, in, n);
    out[n] = 0;
}

static int file_exists(const char *path) {
    int fd = xopen_ro_try(path);
    if (fd >= 0) {
        xclose_best_effort(fd);
        return 1;
    }

    // If the path exists but is not readable, treat it as "found" so the
    // later open() in slurp_file reports a useful error.
    if (xpath_exists(path)) return 1;

    return 0;
}

static void resolve_include(const PPConfig *cfg, const char *including_path, const char *inc, char *out, mc_usize out_cap) {
    char dir[MONACC_PATH_MAX];
    path_dirname(including_path, dir, sizeof(dir));

    mc_usize dir_n = mc_strlen(dir);
    mc_usize inc_n = mc_strlen(inc);
    if (dir_n + 1 + inc_n + 1 > out_cap) {
        die("include path too long");
    }
    mc_memcpy(out, dir, dir_n);
    out[dir_n] = '/';
    mc_memcpy(out + dir_n + 1, inc, inc_n);
    out[dir_n + 1 + inc_n] = 0;
    if (file_exists(out)) return;
    for (int i = 0; i < cfg->ninclude_dirs; i++) {
        const char *base = cfg->include_dirs[i];
        mc_usize base_n = mc_strlen(base);
        if (base_n + 1 + inc_n + 1 > out_cap) {
            continue;
        }
        mc_memcpy(out, base, base_n);
        out[base_n] = '/';
        mc_memcpy(out + base_n + 1, inc, inc_n);
        out[base_n + 1 + inc_n] = 0;
        if (file_exists(out)) return;
    }
    die("include not found: %s (from %s)", inc, including_path);
}

void preprocess_file(const PPConfig *cfg, MacroTable *mt, OnceTable *ot, const char *path, Str *out) {
    if (once_contains(ot, path)) return;
    mc_usize len = 0;
    char *src = slurp_file(path, &len);
    const char *p = src;
    const char *end = src + len;

    // Minimal conditional compilation stack.
    // Each level stores whether this block is "active" (should emit) and whether we've seen an #else.
    int if_active[64];
    int if_else_seen[64];
    int if_taken[64];
    int if_sp = 0;
    if_active[if_sp] = 1;
    if_else_seen[if_sp] = 0;
    if_taken[if_sp] = 0;

    while (p < end) {
        const char *line = p;
        const char *nl = mc_memchr(p, '\n', (mc_usize)(end - p));
        const char *line_end = nl ? nl : end;

        const char *q = line;
        while (q < line_end && (*q == ' ' || *q == '\t' || *q == '\r')) q++;
        if (q < line_end && *q == '#') {
            q++;
            while (q < line_end && (*q == ' ' || *q == '\t')) q++;

            // conditionals
            if ((mc_usize)(line_end - q) >= 2 && mc_memcmp(q, "if", 2) == 0 &&
                !((mc_usize)(line_end - q) >= 5 && mc_memcmp(q, "ifdef", 5) == 0) &&
                !((mc_usize)(line_end - q) >= 6 && mc_memcmp(q, "ifndef", 6) == 0)) {
                q += 2;
                int parent_active = if_active[if_sp];
                if (if_sp + 1 >= (int)(sizeof(if_active) / sizeof(if_active[0]))) {
                    die("%s: too many nested #if", path);
                }
                if_sp++;
                if_else_seen[if_sp] = 0;
                int cond = 0;
                if (parent_active) {
                    cond = pp_eval_if_expr(mt, q, line_end);
                }
                if_taken[if_sp] = parent_active && cond;
                if_active[if_sp] = parent_active && cond;
                str_appendf(out, "\n");
            } else if ((mc_usize)(line_end - q) >= 5 && mc_memcmp(q, "ifdef", 5) == 0) {
                q += 5;
                while (q < line_end && (*q == ' ' || *q == '\t')) q++;
                const char *name = q;
                while (q < line_end && is_ident_cont((unsigned char)*q)) q++;
                mc_usize name_len = (mc_usize)(q - name);
                int parent_active = if_active[if_sp];
                int is_def = (name_len > 0 && mt_lookup(mt, name, name_len) != NULL);
                if (if_sp + 1 >= (int)(sizeof(if_active) / sizeof(if_active[0]))) {
                    die("%s: too many nested #if", path);
                }
                if_sp++;
                if_else_seen[if_sp] = 0;
                if_taken[if_sp] = parent_active && is_def;
                if_active[if_sp] = parent_active && is_def;
                str_appendf(out, "\n");
            } else if ((mc_usize)(line_end - q) >= 6 && mc_memcmp(q, "ifndef", 6) == 0) {
                q += 6;
                while (q < line_end && (*q == ' ' || *q == '\t')) q++;
                const char *name = q;
                while (q < line_end && is_ident_cont((unsigned char)*q)) q++;
                mc_usize name_len = (mc_usize)(q - name);
                int parent_active = if_active[if_sp];
                int is_def = (name_len > 0 && mt_lookup(mt, name, name_len) != NULL);
                if (if_sp + 1 >= (int)(sizeof(if_active) / sizeof(if_active[0]))) {
                    die("%s: too many nested #if", path);
                }
                if_sp++;
                if_else_seen[if_sp] = 0;
                if_taken[if_sp] = parent_active && !is_def;
                if_active[if_sp] = parent_active && !is_def;
                str_appendf(out, "\n");
            } else if ((mc_usize)(line_end - q) >= 4 && mc_memcmp(q, "elif", 4) == 0) {
                if (if_sp == 0) die("%s: #elif without #if", path);
                if (if_else_seen[if_sp]) die("%s: #elif after #else", path);
                q += 4;
                int parent_active = if_active[if_sp - 1];
                if (!parent_active || if_taken[if_sp]) {
                    if_active[if_sp] = 0;
                    str_appendf(out, "\n");
                } else {
                    int cond = pp_eval_if_expr(mt, q, line_end);
                    if_active[if_sp] = parent_active && cond;
                    if_taken[if_sp] = parent_active && cond;
                    str_appendf(out, "\n");
                }
            } else if ((mc_usize)(line_end - q) >= 4 && mc_memcmp(q, "else", 4) == 0) {
                if (if_sp == 0) die("%s: #else without #if", path);
                if (if_else_seen[if_sp]) die("%s: duplicate #else", path);
                if_else_seen[if_sp] = 1;
                int parent_active = if_active[if_sp - 1];
                if_active[if_sp] = parent_active && !if_taken[if_sp];
                if_taken[if_sp] = 1;
                str_appendf(out, "\n");
            } else if ((mc_usize)(line_end - q) >= 5 && mc_memcmp(q, "endif", 5) == 0) {
                if (if_sp == 0) die("%s: #endif without #if", path);
                if_sp--;
                str_appendf(out, "\n");
            } else if ((mc_usize)(line_end - q) >= 5 && mc_memcmp(q, "error", 5) == 0) {
                if (!if_active[if_sp]) {
                    str_appendf(out, "\n");
                    p = nl ? (nl + 1) : end;
                    continue;
                }
                q += 5;
                while (q < line_end && (*q == ' ' || *q == '\t')) q++;
                die("%s: #error %.*s", path, (int)(line_end - q), q);
            } else if ((mc_usize)(line_end - q) >= 7 && mc_memcmp(q, "include", 7) == 0) {
                if (!if_active[if_sp]) {
                    str_appendf(out, "\n");
                    p = nl ? (nl + 1) : end;
                    continue;
                }
                q += 7;
                while (q < line_end && (*q == ' ' || *q == '\t')) q++;
                char close = 0;
                if (q < line_end && *q == '"') {
                    close = '"';
                    q++;
                } else if (q < line_end && *q == '<') {
                    close = '>';
                    q++;
                } else {
                    die("bad #include in %s", path);
                }
                const char *s = q;
                while (q < line_end && *q != close) q++;
                if (q >= line_end) die("bad #include in %s", path);
                mc_usize n = (mc_usize)(q - s);
                if (n == 0 || n >= MONACC_PATH_MAX) die("include path too long");
                char inc[MONACC_PATH_MAX];
                mc_memcpy(inc, s, n);
                inc[n] = 0;
                char full[MONACC_PATH_MAX];
                resolve_include(cfg, path, inc, full, sizeof(full));
                preprocess_file(cfg, mt, ot, full, out);
                str_appendf(out, "\n");
            } else if ((mc_usize)(line_end - q) >= 6 && mc_memcmp(q, "define", 6) == 0) {
                if (!if_active[if_sp]) {
                    str_appendf(out, "\n");
                    p = nl ? (nl + 1) : end;
                    continue;
                }
                q += 6;
                while (q < line_end && (*q == ' ' || *q == '\t')) q++;
                const char *name = q;
                while (q < line_end && is_ident_cont((unsigned char)*q)) q++;
                mc_usize name_len = (mc_usize)(q - name);
                while (q < line_end && (*q == ' ' || *q == '\t')) q++;
                // rest is replacement (object-like only)
                mc_usize repl_len = (mc_usize)(line_end - q);
                char *repl = pp_strip_comments_and_trim(q, repl_len);
                mt_define(mt, name, name_len, repl);
                monacc_free(repl);
                str_appendf(out, "\n");
            } else if ((mc_usize)(line_end - q) >= 6 && mc_memcmp(q, "pragma", 6) == 0) {
                if (!if_active[if_sp]) {
                    str_appendf(out, "\n");
                    p = nl ? (nl + 1) : end;
                    continue;
                }
                q += 6;
                while (q < line_end && (*q == ' ' || *q == '\t')) q++;
                if ((mc_usize)(line_end - q) >= 4 && mc_memcmp(q, "once", 4) == 0) {
                    once_add(ot, path);
                }
                str_appendf(out, "\n");
            } else {
                // ignore unknown directive
                str_appendf(out, "\n");
            }
        } else {
            if (!if_active[if_sp]) {
                str_appendf(out, "\n");
                p = nl ? (nl + 1) : end;
                continue;
            }
            mc_usize n = (mc_usize)(line_end - line);
            str_reserve(out, n + 1);
            mc_memcpy(out->buf + out->len, line, n);
            out->len += n;
            out->buf[out->len] = 0;
            str_appendf(out, "\n");
        }

        p = nl ? (nl + 1) : end;
    }

    monacc_free(src);
}

