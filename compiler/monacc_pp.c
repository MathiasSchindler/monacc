#include "monacc.h"

// Keep path buffers explicit to avoid pulling in <limits.h> for PATH_MAX.
#ifndef MONACC_PATH_MAX
#define MONACC_PATH_MAX 4096
#endif

static char *pp_strip_comments_and_trim(const char *s, size_t len) {
    // Remove C comments from a single line of macro replacement text.
    // This matches typical preprocessing behavior (comments are removed before macro replacement is stored).
    char *out = (char *)monacc_malloc(len + 1);
    if (!out) die("oom");
    size_t j = 0;
    int in_str = 0;
    int in_chr = 0;

    for (size_t i = 0; i < len; i++) {
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
        char **np = (char **)monacc_realloc(ot->paths, (size_t)ncap * sizeof(char *));
        if (!np) die("oom");
        ot->paths = np;
        ot->cap = ncap;
    }
    size_t n = mc_strlen(path) + 1;
    ot->paths[ot->n] = (char *)monacc_malloc(n);
    if (!ot->paths[ot->n]) die("oom");
    mc_memcpy(ot->paths[ot->n], path, n);
    ot->n++;
}

static char *slurp_file(const char *path, size_t *out_len) {
    int fd = xopen_ro(path);

    size_t cap = 4096;
    char *buf = (char *)monacc_malloc(cap);
    if (!buf) die("oom");
    size_t n = 0;

    for (;;) {
        if (n + 1 >= cap) {
            size_t ncap = cap * 2;
            char *nb = (char *)monacc_realloc(buf, ncap);
            if (!nb) die("oom");
            buf = nb;
            cap = ncap;
        }

        ssize_t r = xread_retry(fd, buf + n, (cap - 1) - n);
        if (r < 0) die("read %s failed", path);
        if (r == 0) break;
        n += (size_t)r;
    }
    buf[n] = 0;

    xclose_checked(fd, "close", path);
    if (out_len) *out_len = n;
    return buf;
}

static void path_dirname(const char *in, char *out, size_t out_cap) {
    const char *slash = mc_strrchr(in, '/');
    if (!slash) {
        if (out_cap) {
            out[0] = '.';
            if (out_cap > 1) out[1] = 0;
        }
        return;
    }
    size_t n = (size_t)(slash - in);
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

static void resolve_include(const PPConfig *cfg, const char *including_path, const char *inc, char *out, size_t out_cap) {
    char dir[MONACC_PATH_MAX];
    path_dirname(including_path, dir, sizeof(dir));

    size_t dir_n = mc_strlen(dir);
    size_t inc_n = mc_strlen(inc);
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
        size_t base_n = mc_strlen(base);
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
    size_t len = 0;
    char *src = slurp_file(path, &len);
    const char *p = src;
    const char *end = src + len;

    // Minimal conditional compilation stack.
    // Each level stores whether this block is "active" (should emit) and whether we've seen an #else.
    int if_active[64];
    int if_else_seen[64];
    int if_sp = 0;
    if_active[if_sp] = 1;
    if_else_seen[if_sp] = 0;

    while (p < end) {
        const char *line = p;
        const char *nl = mc_memchr(p, '\n', (size_t)(end - p));
        const char *line_end = nl ? nl : end;

        const char *q = line;
        while (q < line_end && (*q == ' ' || *q == '\t' || *q == '\r')) q++;
        if (q < line_end && *q == '#') {
            q++;
            while (q < line_end && (*q == ' ' || *q == '\t')) q++;

            // conditionals
            if ((size_t)(line_end - q) >= 5 && mc_memcmp(q, "ifdef", 5) == 0) {
                q += 5;
                while (q < line_end && (*q == ' ' || *q == '\t')) q++;
                const char *name = q;
                while (q < line_end && is_ident_cont((unsigned char)*q)) q++;
                size_t name_len = (size_t)(q - name);
                int parent_active = if_active[if_sp];
                int is_def = (name_len > 0 && mt_lookup(mt, name, name_len) != NULL);
                if (if_sp + 1 >= (int)(sizeof(if_active) / sizeof(if_active[0]))) {
                    die("%s: too many nested #if", path);
                }
                if_sp++;
                if_else_seen[if_sp] = 0;
                if_active[if_sp] = parent_active && is_def;
                str_appendf(out, "\n");
            } else if ((size_t)(line_end - q) >= 6 && mc_memcmp(q, "ifndef", 6) == 0) {
                q += 6;
                while (q < line_end && (*q == ' ' || *q == '\t')) q++;
                const char *name = q;
                while (q < line_end && is_ident_cont((unsigned char)*q)) q++;
                size_t name_len = (size_t)(q - name);
                int parent_active = if_active[if_sp];
                int is_def = (name_len > 0 && mt_lookup(mt, name, name_len) != NULL);
                if (if_sp + 1 >= (int)(sizeof(if_active) / sizeof(if_active[0]))) {
                    die("%s: too many nested #if", path);
                }
                if_sp++;
                if_else_seen[if_sp] = 0;
                if_active[if_sp] = parent_active && !is_def;
                str_appendf(out, "\n");
            } else if ((size_t)(line_end - q) >= 4 && mc_memcmp(q, "else", 4) == 0) {
                if (if_sp == 0) die("%s: #else without #if", path);
                if (if_else_seen[if_sp]) die("%s: duplicate #else", path);
                if_else_seen[if_sp] = 1;
                int parent_active = if_active[if_sp - 1];
                if_active[if_sp] = parent_active && !if_active[if_sp];
                str_appendf(out, "\n");
            } else if ((size_t)(line_end - q) >= 5 && mc_memcmp(q, "endif", 5) == 0) {
                if (if_sp == 0) die("%s: #endif without #if", path);
                if_sp--;
                str_appendf(out, "\n");
            } else if ((size_t)(line_end - q) >= 7 && mc_memcmp(q, "include", 7) == 0) {
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
                size_t n = (size_t)(q - s);
                if (n == 0 || n >= MONACC_PATH_MAX) die("include path too long");
                char inc[MONACC_PATH_MAX];
                mc_memcpy(inc, s, n);
                inc[n] = 0;
                char full[MONACC_PATH_MAX];
                resolve_include(cfg, path, inc, full, sizeof(full));
                preprocess_file(cfg, mt, ot, full, out);
                str_appendf(out, "\n");
            } else if ((size_t)(line_end - q) >= 6 && mc_memcmp(q, "define", 6) == 0) {
                if (!if_active[if_sp]) {
                    str_appendf(out, "\n");
                    p = nl ? (nl + 1) : end;
                    continue;
                }
                q += 6;
                while (q < line_end && (*q == ' ' || *q == '\t')) q++;
                const char *name = q;
                while (q < line_end && is_ident_cont((unsigned char)*q)) q++;
                size_t name_len = (size_t)(q - name);
                while (q < line_end && (*q == ' ' || *q == '\t')) q++;
                // rest is replacement (object-like only)
                size_t repl_len = (size_t)(line_end - q);
                char *repl = pp_strip_comments_and_trim(q, repl_len);
                mt_define(mt, name, name_len, repl);
                monacc_free(repl);
                str_appendf(out, "\n");
            } else if ((size_t)(line_end - q) >= 6 && mc_memcmp(q, "pragma", 6) == 0) {
                if (!if_active[if_sp]) {
                    str_appendf(out, "\n");
                    p = nl ? (nl + 1) : end;
                    continue;
                }
                q += 6;
                while (q < line_end && (*q == ' ' || *q == '\t')) q++;
                if ((size_t)(line_end - q) >= 4 && mc_memcmp(q, "once", 4) == 0) {
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
            size_t n = (size_t)(line_end - line);
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

