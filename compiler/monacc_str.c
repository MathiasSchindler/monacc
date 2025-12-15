// monacc_str.c - String builder for code generation
// Extracted from monacc_codegen.c for better modularity

#include "monacc.h"

// ===== String Builder =====

void str_reserve(Str *s, size_t add) {
    if (s->len + add <= s->cap) return;
    size_t ncap = s->cap ? s->cap : 4096;
    while (ncap < s->len + add) ncap *= 2;
    char *nb = (char *)monacc_realloc(s->buf, ncap);
    if (!nb) die("oom");
    s->buf = nb;
    s->cap = ncap;
}

void str_append_bytes(Str *s, const char *buf, size_t n) {
    if (!buf || n == 0) return;
    str_reserve(s, n + 1);
    mc_memcpy(s->buf + s->len, buf, n);
    s->len += n;
    s->buf[s->len] = 0;
}

#ifdef SELFHOST

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
    str_append_bytes(s, tmp, (size_t)n);
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

// SELFHOST: no stdarg; allow only '%%' escapes (no conversions).
void str_appendf(Str *s, const char *fmt, ...) {
    for (const char *p = fmt; p && *p; ) {
        if (*p != '%') {
            const char *q = p;
            while (*q && *q != '%') q++;
            str_append_bytes(s, p, (size_t)(q - p));
            p = q;
            continue;
        }
        if (p[1] == '%') {
            str_append_bytes(s, "%", 1);
            p += 2;
            continue;
        }
        // Emit the offending format for easier progress tracking.
        xwrite_best_effort(2, "SELFHOST: unsupported str_appendf fmt: ", 36);
        xwrite_best_effort(2, fmt, mc_strlen(fmt));
        xwrite_best_effort(2, "\n", 1);
        die("SELFHOST: unsupported str_appendf fmt");
    }
}

void str_appendf_i64(Str *s, const char *fmt, long long v) {
    int used = 0;
    for (const char *p = fmt; p && *p; ) {
        if (*p != '%') {
            const char *q = p;
            while (*q && *q != '%') q++;
            str_append_bytes(s, p, (size_t)(q - p));
            p = q;
            continue;
        }
        if (p[1] == '%') {
            str_append_bytes(s, "%", 1);
            p += 2;
            continue;
        }
        if (p[1] == 'd') {
            if (++used != 1) die("SELFHOST: unexpected extra conversion");
            str_append_i64_dec(s, v);
            p += 2;
            continue;
        }
        if (p[1] == 'l' && p[2] == 'l' && p[3] == 'd') {
            if (++used != 1) die("SELFHOST: unexpected extra conversion");
            str_append_i64_dec(s, v);
            p += 4;
            continue;
        }
        die("SELFHOST: unsupported integer format");
    }
    if (used != 1) die("SELFHOST: expected exactly one integer conversion");
}

void str_appendf_u64(Str *s, const char *fmt, unsigned long long v) {
    int used = 0;
    for (const char *p = fmt; p && *p; ) {
        if (*p != '%') {
            const char *q = p;
            while (*q && *q != '%') q++;
            str_append_bytes(s, p, (size_t)(q - p));
            p = q;
            continue;
        }
        if (p[1] == '%') {
            str_append_bytes(s, "%", 1);
            p += 2;
            continue;
        }
        if (p[1] == 'u') {
            if (++used != 1) die("SELFHOST: unexpected extra conversion");
            str_append_u64_dec(s, v);
            p += 2;
            continue;
        }
        die("SELFHOST: unsupported unsigned format");
    }
    if (used != 1) die("SELFHOST: expected exactly one unsigned conversion");
}

void str_appendf_s(Str *s, const char *fmt, const char *v) {
    int used = 0;
    for (const char *p = fmt; p && *p; ) {
        if (*p != '%') {
            const char *q = p;
            while (*q && *q != '%') q++;
            str_append_bytes(s, p, (size_t)(q - p));
            p = q;
            continue;
        }
        if (p[1] == '%') {
            str_append_bytes(s, "%", 1);
            p += 2;
            continue;
        }
        if (p[1] == 's') {
            if (++used != 1) die("SELFHOST: unexpected extra conversion");
            str_append_cstr(s, v);
            p += 2;
            continue;
        }
        die("SELFHOST: unsupported string format");
    }
    if (used != 1) die("SELFHOST: expected exactly one string conversion");
}

void str_appendf_ss(Str *s, const char *fmt, const char *s0, const char *s1) {
    int state = 0;
    for (const char *p = fmt; p && *p; ) {
        if (*p != '%') {
            const char *q = p;
            while (*q && *q != '%') q++;
            str_append_bytes(s, p, (size_t)(q - p));
            p = q;
            continue;
        }
        if (p[1] == '%') {
            str_append_bytes(s, "%", 1);
            p += 2;
            continue;
        }
        if (state == 0 && p[1] == 's') {
            str_append_cstr(s, s0);
            state = 1;
            p += 2;
            continue;
        }
        if (state == 1 && p[1] == 's') {
            str_append_cstr(s, s1);
            state = 2;
            p += 2;
            continue;
        }
        die("SELFHOST: unsupported multi-arg format");
    }
    if (state != 2) die("SELFHOST: expected %s then %s");
}

void str_appendf_si(Str *s, const char *fmt, const char *s0, long long i0) {
    int state = 0;
    for (const char *p = fmt; p && *p; ) {
        if (*p != '%') {
            const char *q = p;
            while (*q && *q != '%') q++;
            str_append_bytes(s, p, (size_t)(q - p));
            p = q;
            continue;
        }
        if (p[1] == '%') {
            str_append_bytes(s, "%", 1);
            p += 2;
            continue;
        }
        if (state == 0 && p[1] == 's') {
            str_append_cstr(s, s0);
            state = 1;
            p += 2;
            continue;
        }
        if (state == 1 && p[1] == 'd') {
            str_append_i64_dec(s, i0);
            state = 2;
            p += 2;
            continue;
        }
        die("SELFHOST: unsupported multi-arg format");
    }
    if (state != 2) die("SELFHOST: expected %s then %d");
}

void str_appendf_su(Str *s, const char *fmt, const char *s0, unsigned long long u0) {
    int state = 0;
    for (const char *p = fmt; p && *p; ) {
        if (*p != '%') {
            const char *q = p;
            while (*q && *q != '%') q++;
            str_append_bytes(s, p, (size_t)(q - p));
            p = q;
            continue;
        }
        if (p[1] == '%') {
            str_append_bytes(s, "%", 1);
            p += 2;
            continue;
        }
        if (state == 0 && p[1] == 's') {
            str_append_cstr(s, s0);
            state = 1;
            p += 2;
            continue;
        }
        if (state == 1 && p[1] == 'u') {
            str_append_u64_dec(s, u0);
            state = 2;
            p += 2;
            continue;
        }
        die("SELFHOST: unsupported multi-arg format");
    }
    if (state != 2) die("SELFHOST: expected %s then %u");
}

void str_appendf_is(Str *s, const char *fmt, long long i0, const char *s0) {
    int state = 0;
    for (const char *p = fmt; p && *p; ) {
        if (*p != '%') {
            const char *q = p;
            while (*q && *q != '%') q++;
            str_append_bytes(s, p, (size_t)(q - p));
            p = q;
            continue;
        }
        if (p[1] == '%') {
            str_append_bytes(s, "%", 1);
            p += 2;
            continue;
        }
        if (state == 0 && p[1] == 'd') {
            str_append_i64_dec(s, i0);
            state = 1;
            p += 2;
            continue;
        }
        if (state == 1 && p[1] == 's') {
            str_append_cstr(s, s0);
            state = 2;
            p += 2;
            continue;
        }
        die("SELFHOST: unsupported multi-arg format");
    }
    if (state != 2) die("SELFHOST: expected %d then %s");
}

#else

__attribute__((format(printf, 2, 3)))
void str_appendf(Str *s, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);

    char stack_buf[1024];
    va_list ap2;
    va_copy(ap2, ap);
    int n = mc_vsnprintf(stack_buf, sizeof(stack_buf), fmt, ap2);
    va_end(ap2);

    if (n < 0) {
        va_end(ap);
        return;
    }

    if ((size_t)n < sizeof(stack_buf)) {
        str_append_bytes(s, stack_buf, (size_t)n);
        va_end(ap);
        return;
    }

    size_t need = (size_t)n + 1;
    char *heap_buf = (char *)monacc_malloc(need);
    if (!heap_buf) {
        str_append_bytes(s, stack_buf, sizeof(stack_buf) - 1);
        va_end(ap);
        return;
    }

    (void)mc_vsnprintf(heap_buf, need, fmt, ap);
    str_append_bytes(s, heap_buf, (size_t)n);
    monacc_free(heap_buf);
    va_end(ap);
}

void str_appendf_i64(Str *s, const char *fmt, long long v) { str_appendf(s, fmt, v); }
void str_appendf_u64(Str *s, const char *fmt, unsigned long long v) { str_appendf(s, fmt, v); }
void str_appendf_s(Str *s, const char *fmt, const char *v) { str_appendf(s, fmt, v); }
void str_appendf_ss(Str *s, const char *fmt, const char *s0, const char *s1) { str_appendf(s, fmt, s0, s1); }
void str_appendf_si(Str *s, const char *fmt, const char *s0, long long i0) { str_appendf(s, fmt, s0, i0); }
void str_appendf_su(Str *s, const char *fmt, const char *s0, unsigned long long u0) { str_appendf(s, fmt, s0, u0); }
void str_appendf_is(Str *s, const char *fmt, long long i0, const char *s0) { str_appendf(s, fmt, i0, s0); }

#endif
