#include "monacc.h"

#ifndef SELFHOST
#endif

// ===== Codegen =====

void str_reserve(Str *s, size_t add) {
    if (s->len + add <= s->cap) return;
    size_t ncap = s->cap ? s->cap : 4096;
    while (ncap < s->len + add) ncap *= 2;
    char *nb = (char *)monacc_realloc(s->buf, ncap);
    if (!nb) die("oom");
    s->buf = nb;
    s->cap = ncap;
}

static void str_append_bytes(Str *s, const char *buf, size_t n) {
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

static void str_appendf_i64(Str *s, const char *fmt, long long v);
static void str_appendf_u64(Str *s, const char *fmt, unsigned long long v);
static void str_appendf_s(Str *s, const char *fmt, const char *v);
static void str_appendf_ss(Str *s, const char *fmt, const char *s0, const char *s1);
static void str_appendf_si(Str *s, const char *fmt, const char *s0, long long i0);
static void str_appendf_su(Str *s, const char *fmt, const char *s0, unsigned long long u0);

static void str_appendf_i64(Str *s, const char *fmt, long long v) {
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

static void str_appendf_u64(Str *s, const char *fmt, unsigned long long v) {
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

static void str_appendf_s(Str *s, const char *fmt, const char *v) {
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

static void str_appendf_ss(Str *s, const char *fmt, const char *s0, const char *s1) {
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

static void str_appendf_si(Str *s, const char *fmt, const char *s0, long long i0) {
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

static void str_appendf_su(Str *s, const char *fmt, const char *s0, unsigned long long u0) {
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

static void str_appendf_is(Str *s, const char *fmt, long long i0, const char *s0) {
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

__attribute__((unused)) static void str_appendf_i64(Str *s, const char *fmt, long long v) { str_appendf(s, fmt, v); }
__attribute__((unused)) static void str_appendf_u64(Str *s, const char *fmt, unsigned long long v) { str_appendf(s, fmt, v); }
__attribute__((unused)) static void str_appendf_s(Str *s, const char *fmt, const char *v) { str_appendf(s, fmt, v); }
__attribute__((unused)) static void str_appendf_ss(Str *s, const char *fmt, const char *s0, const char *s1) { str_appendf(s, fmt, s0, s1); }
__attribute__((unused)) static void str_appendf_si(Str *s, const char *fmt, const char *s0, long long i0) { str_appendf(s, fmt, s0, i0); }
__attribute__((unused)) static void str_appendf_su(Str *s, const char *fmt, const char *s0, unsigned long long u0) { str_appendf(s, fmt, s0, u0); }
__attribute__((unused)) static void str_appendf_is(Str *s, const char *fmt, long long i0, const char *s0) { str_appendf(s, fmt, i0, s0); }

#endif

typedef struct {
    Str out;
    int label_id;
    const char *fn_name;

    int frameless;

    BaseType ret_base;
    int ret_ptr;
    int ret_struct_id;
    int ret_size;
    int sret_offset;

    int loop_sp;
    int break_label[64];
    int cont_label[64];

    struct {
        char name[128];
        int id;
    } labels[256];
    int nlabels;

    const Program *prg;  // For inlining: access to function definitions
} CG;

static int new_label(CG *cg) { return cg->label_id++; }

static void cg_expr(CG *cg, const Expr *e);

static int cg_label_id(CG *cg, const char *name) {
    for (int i = 0; i < cg->nlabels; i++) {
        if (mc_strcmp(cg->labels[i].name, name) == 0) return cg->labels[i].id;
    }
    return -1;
}

static void cg_add_label(CG *cg, const char *name) {
    if (!name || !name[0]) return;
    if (cg_label_id(cg, name) >= 0) return;
    if (cg->nlabels >= (int)(sizeof(cg->labels) / sizeof(cg->labels[0]))) {
        die("too many labels");
    }
    int i = cg->nlabels++;
    size_t max = sizeof(cg->labels[i].name) - 1;
    size_t n = mc_strlen(name);
    if (n > max) n = max;
    mc_memcpy(cg->labels[i].name, name, n);
    cg->labels[i].name[n] = 0;
    cg->labels[i].id = new_label(cg);
}

static void cg_collect_labels(CG *cg, const Stmt *s) {
    if (!s) return;
    switch (s->kind) {
        case STMT_LABEL:
            cg_add_label(cg, s->label);
            cg_collect_labels(cg, s->label_stmt);
            return;
        case STMT_BLOCK:
            for (const Stmt *cur = s->block_first; cur; cur = cur->next) {
                cg_collect_labels(cg, cur);
            }
            return;
        case STMT_IF:
            cg_collect_labels(cg, s->if_then);
            cg_collect_labels(cg, s->if_else);
            return;
        case STMT_WHILE:
            cg_collect_labels(cg, s->while_body);
            return;
        case STMT_FOR:
            cg_collect_labels(cg, s->for_init);
            cg_collect_labels(cg, s->for_body);
            return;
        case STMT_SWITCH:
            // Labels are function-scoped; still collect inside switch.
            cg_collect_labels(cg, s->switch_body);
            return;
        default:
            return;
    }
}

typedef struct {
    const Stmt *case_nodes[256];
    long long case_values[256];
    int case_labels[256];
    int ncases;

    const Stmt *default_node;
    int default_label;
} SwitchCtx;

static int stmt_may_fallthrough(const Stmt *s);

static int stmt_list_may_fallthrough(const Stmt *first) {
    int reachable = 1;
    for (const Stmt *it = first; it; it = it->next) {
        if (!reachable) break;
        reachable = stmt_may_fallthrough(it);
    }
    return reachable;
}

static int stmt_may_fallthrough(const Stmt *s) {
    if (!s) return 1;
    switch (s->kind) {
        case STMT_RETURN:
        case STMT_GOTO:
        case STMT_BREAK:
        case STMT_CONTINUE:
            return 0;
        case STMT_BLOCK:
            return stmt_list_may_fallthrough(s->block_first);
        case STMT_IF:
            // If either branch can fall through, the if can fall through.
            if (!s->if_else) return 1;
            return stmt_may_fallthrough(s->if_then) || stmt_may_fallthrough(s->if_else);
        case STMT_WHILE:
        case STMT_FOR:
        case STMT_SWITCH:
            // Conservative: assume loops/switch can fall through.
            return 1;
        case STMT_CASE:
        case STMT_DEFAULT:
        case STMT_LABEL:
        case STMT_EXPR:
        case STMT_DECL:
            return 1;
        default:
            return 1;
    }
}


static int expr_count_var_uses(const Expr *e, int off) {
    if (!e) return 0;
    int n = 0;
    if (e->kind == EXPR_VAR && e->var_offset == off) n++;
    n += expr_count_var_uses(e->lhs, off);
    n += expr_count_var_uses(e->rhs, off);
    n += expr_count_var_uses(e->third, off);
    for (int i = 0; i < e->nargs; i++) {
        n += expr_count_var_uses(e->args[i], off);
    }
    for (int i = 0; i < e->ninits; i++) {
        n += expr_count_var_uses(e->inits[i].value, off);
    }
    return n;
}

static int stmt_count_var_uses(const Stmt *s, int off) {
    if (!s) return 0;
    int n = 0;
    switch (s->kind) {
        case STMT_BLOCK:
            for (const Stmt *cur = s->block_first; cur; cur = cur->next) {
                n += stmt_count_var_uses(cur, off);
            }
            return n;
        case STMT_IF:
            n += expr_count_var_uses(s->if_cond, off);
            n += stmt_count_var_uses(s->if_then, off);
            n += stmt_count_var_uses(s->if_else, off);
            return n;
        case STMT_WHILE:
            n += expr_count_var_uses(s->while_cond, off);
            n += stmt_count_var_uses(s->while_body, off);
            return n;
        case STMT_FOR:
            n += stmt_count_var_uses(s->for_init, off);
            n += expr_count_var_uses(s->for_cond, off);
            n += expr_count_var_uses(s->for_inc, off);
            n += stmt_count_var_uses(s->for_body, off);
            return n;
        case STMT_SWITCH:
            n += expr_count_var_uses(s->switch_expr, off);
            n += stmt_count_var_uses(s->switch_body, off);
            return n;
        case STMT_LABEL:
            return stmt_count_var_uses(s->label_stmt, off);
        case STMT_DECL:
            n += expr_count_var_uses(s->decl_init, off);
            return n;
        case STMT_RETURN:
        case STMT_EXPR:
            return expr_count_var_uses(s->expr, off);
        default:
            return 0;
    }
}

static int expr_is_syscall_builtin(const Expr *e) {
    if (!e || e->kind != EXPR_CALL) return 0;
    if (e->callee[0] == 0) return 0;
    if ((mc_strncmp(e->callee, "mc_syscall", 10) != 0) && (mc_strncmp(e->callee, "sb_syscall", 10) != 0)) return 0;
    if (e->callee[10] < '0' || e->callee[10] > '6') return 0;
    if (e->callee[11] != 0) return 0;
    return 1;
}

// Check if an expression is "simple" - a constant or string literal that can be
// loaded directly into any register without side effects or clobbering other regs.
static int expr_is_simple_const(const Expr *e) {
    if (!e) return 0;
    if (e->kind == EXPR_NUM) return 1;
    if (e->kind == EXPR_STR) return 1;
    return 0;
}

// Emit code to load a simple constant expression directly into a specific register.
// Returns 1 if successful, 0 if the expression is not simple.
static int cg_expr_to_reg(CG *cg, const Expr *e, const char *reg64, const char *reg32) {
    if (!e) return 0;
    if (e->kind == EXPR_NUM) {
        if (e->num == 0) {
            // xor reg32, reg32 is smaller than mov $0, reg
            str_appendf_ss(&cg->out, "  xor %s, %s\n", reg32, reg32);
        } else if (e->num > 0 && e->num <= 0x7fffffffLL) {
            // Use 32-bit mov which zero-extends
            str_appendf_is(&cg->out, "  mov $%d, %s\n", (long long)e->num, reg32);
        } else {
            str_appendf_is(&cg->out, "  mov $%d, %s\n", (long long)e->num, reg64);
        }
        return 1;
    }
    if (e->kind == EXPR_STR) {
        str_appendf_is(&cg->out, "  lea .LC%d(%%rip), %s\n", (long long)e->str_id, reg64);
        return 1;
    }
    return 0;
}

static int u64_pow2_shift(unsigned long long v) {
    if (v == 0) return -1;
    if ((v & (v - 1ULL)) != 0ULL) return -1;
    int sh = 0;
    while (v > 1ULL) {
        v >>= 1ULL;
        sh++;
    }
    return sh;
}

// Check if expression is a comparison that can directly control a jump.
static int expr_is_comparison(const Expr *e) {
    if (!e) return 0;
    switch (e->kind) {
        case EXPR_EQ:
        case EXPR_NE:
        case EXPR_LT:
        case EXPR_LE:
        case EXPR_GT:
        case EXPR_GE:
            return 1;
        default:
            return 0;
    }
}

static int expr_contains_nonsyscall_call(const Expr *e) {
    if (!e) return 0;
    switch (e->kind) {
        case EXPR_CALL:
            if (!expr_is_syscall_builtin(e)) return 1;
            break;
        case EXPR_SRET_CALL:
            return 1;
        default:
            break;
    }
    if (expr_contains_nonsyscall_call(e->lhs)) return 1;
    if (expr_contains_nonsyscall_call(e->rhs)) return 1;
    if (expr_contains_nonsyscall_call(e->third)) return 1;
    for (int i = 0; i < e->nargs; i++) {
        if (expr_contains_nonsyscall_call(e->args[i])) return 1;
    }
    for (int i = 0; i < e->ninits; i++) {
        if (expr_contains_nonsyscall_call(e->inits[i].value)) return 1;
    }
    return 0;
}

static int expr_uses_frame_pointer(const Expr *e) {
    if (!e) return 0;
    // Any access to locals/temps uses rbp-relative addressing in this codegen.
    if (e->kind == EXPR_VAR || e->kind == EXPR_COMPOUND || e->kind == EXPR_SRET_CALL) {
        if (e->var_offset != 0) return 1;
        return 1;
    }
    if (expr_uses_frame_pointer(e->lhs)) return 1;
    if (expr_uses_frame_pointer(e->rhs)) return 1;
    if (expr_uses_frame_pointer(e->third)) return 1;
    for (int i = 0; i < e->nargs; i++) {
        if (expr_uses_frame_pointer(e->args[i])) return 1;
    }
    for (int i = 0; i < e->ninits; i++) {
        if (expr_uses_frame_pointer(e->inits[i].value)) return 1;
    }
    return 0;
}

static int stmt_contains_nonsyscall_call(const Stmt *s) {
    if (!s) return 0;
    switch (s->kind) {
        case STMT_BLOCK:
            for (const Stmt *cur = s->block_first; cur; cur = cur->next) {
                if (stmt_contains_nonsyscall_call(cur)) return 1;
            }
            return 0;
        case STMT_IF:
            if (expr_contains_nonsyscall_call(s->if_cond)) return 1;
            if (stmt_contains_nonsyscall_call(s->if_then)) return 1;
            if (stmt_contains_nonsyscall_call(s->if_else)) return 1;
            return 0;
        case STMT_WHILE:
            if (expr_contains_nonsyscall_call(s->while_cond)) return 1;
            return stmt_contains_nonsyscall_call(s->while_body);
        case STMT_FOR:
            if (stmt_contains_nonsyscall_call(s->for_init)) return 1;
            if (expr_contains_nonsyscall_call(s->for_cond)) return 1;
            if (expr_contains_nonsyscall_call(s->for_inc)) return 1;
            return stmt_contains_nonsyscall_call(s->for_body);
        case STMT_SWITCH:
            if (expr_contains_nonsyscall_call(s->switch_expr)) return 1;
            return stmt_contains_nonsyscall_call(s->switch_body);
        case STMT_LABEL:
            return stmt_contains_nonsyscall_call(s->label_stmt);
        case STMT_RETURN:
        case STMT_EXPR:
        case STMT_DECL:
            return expr_contains_nonsyscall_call(s->expr ? s->expr : s->decl_init);
        case STMT_CASE:
        case STMT_DEFAULT:
        case STMT_GOTO:
        case STMT_BREAK:
        case STMT_CONTINUE:
            return 0;
        default:
            return 0;
    }
}

static int stmt_uses_frame_pointer(const Stmt *s) {
    if (!s) return 0;
    switch (s->kind) {
        case STMT_BLOCK:
            for (const Stmt *cur = s->block_first; cur; cur = cur->next) {
                if (stmt_uses_frame_pointer(cur)) return 1;
            }
            return 0;
        case STMT_IF:
            if (expr_uses_frame_pointer(s->if_cond)) return 1;
            if (stmt_uses_frame_pointer(s->if_then)) return 1;
            if (stmt_uses_frame_pointer(s->if_else)) return 1;
            return 0;
        case STMT_WHILE:
            if (expr_uses_frame_pointer(s->while_cond)) return 1;
            return stmt_uses_frame_pointer(s->while_body);
        case STMT_FOR:
            if (stmt_uses_frame_pointer(s->for_init)) return 1;
            if (expr_uses_frame_pointer(s->for_cond)) return 1;
            if (expr_uses_frame_pointer(s->for_inc)) return 1;
            return stmt_uses_frame_pointer(s->for_body);
        case STMT_SWITCH:
            if (expr_uses_frame_pointer(s->switch_expr)) return 1;
            return stmt_uses_frame_pointer(s->switch_body);
        case STMT_LABEL:
            return stmt_uses_frame_pointer(s->label_stmt);
        case STMT_RETURN:
        case STMT_EXPR:
            return expr_uses_frame_pointer(s->expr);
        case STMT_DECL:
            if (s->decl_offset != 0) return 1;
            return expr_uses_frame_pointer(s->decl_init);
        case STMT_CASE:
        case STMT_DEFAULT:
        case STMT_GOTO:
        case STMT_BREAK:
        case STMT_CONTINUE:
            return 0;
        default:
            return 0;
    }
}

static int fn_can_be_frameless(const Function *fn) {
    if (!fn || !fn->has_body) return 0;
    if (fn->stack_size != 0) return 0;
    if (fn->sret_offset != 0) return 0;
    for (int i = 0; i < 6; i++) {
        if (fn->param_offsets[i] != 0) return 0;
    }
    // Frameless functions start with rsp misaligned by 8 bytes (SysV). That's OK
    // only if we don't emit CALL instructions (we still allow syscall builtins).
    if (stmt_contains_nonsyscall_call(fn->body)) return 0;
    if (stmt_uses_frame_pointer(fn->body)) return 0;
    return 1;
}

// Check if a statement is a no-op (void)var cast that we skip in codegen.
static int stmt_is_void_cast_discard(const Stmt *s) {
    if (!s || s->kind != STMT_EXPR) return 0;
    const Expr *e = s->expr;
    if (!e || e->kind != EXPR_CAST) return 0;
    if (e->base != BT_VOID || e->ptr != 0) return 0;
    if (!e->lhs || e->lhs->kind != EXPR_VAR) return 0;
    return 1;
}

// Check if a function body is trivial: only (void)param; discards and return N;
// Returns the constant return value in *ret_val, or -1 if not trivial.
static int fn_is_trivial_return(const Function *fn, long long *ret_val) {
    if (!fn || !fn->has_body) return 0;
    const Stmt *body = fn->body;
    if (!body) return 0;

    // Body must be a block.
    if (body->kind != STMT_BLOCK) return 0;

    const Stmt *final_ret = NULL;
    for (const Stmt *s = body->block_first; s; s = s->next) {
        if (s->kind == STMT_EXPR && stmt_is_void_cast_discard(s)) {
            // Skip (void)param; discards.
            continue;
        }
        if (s->kind == STMT_RETURN) {
            // This should be the last meaningful statement.
            if (s->next != NULL) return 0; // Something after return.
            final_ret = s;
            break;
        }
        // Any other statement makes it non-trivial.
        return 0;
    }

    if (!final_ret) return 0;

    // Return expression must be a constant number.
    const Expr *e = final_ret->expr;
    if (!e) {
        // return; with no value => return 0 for main.
        *ret_val = 0;
        return 1;
    }
    if (e->kind == EXPR_NUM) {
        *ret_val = e->num;
        return 1;
    }
    return 0;
}

typedef struct {
    int kind;
    int reg;
    int stack_bytes;
    int struct_size;
} CallArgInfo;

enum {
    CALLARG_REG = 1,
    CALLARG_STACK_SCALAR = 2,
    CALLARG_STACK_STRUCT = 3,
};

static void switch_collect(SwitchCtx *sw, const Stmt *s) {
    if (!s) return;
    switch (s->kind) {
        case STMT_CASE:
            if (sw->ncases >= (int)(sizeof(sw->case_nodes) / sizeof(sw->case_nodes[0]))) {
                die("too many case labels");
            }
            sw->case_nodes[sw->ncases] = s;
            sw->case_values[sw->ncases] = s->case_value;
            sw->ncases++;
            return;
        case STMT_DEFAULT:
            if (sw->default_node) {
                die("duplicate default label");
            }
            sw->default_node = s;
            return;
        case STMT_SWITCH:
            // Do not recurse into nested switches.
            return;
        case STMT_BLOCK:
            for (const Stmt *cur = s->block_first; cur; cur = cur->next) {
                switch_collect(sw, cur);
            }
            return;
        case STMT_IF:
            switch_collect(sw, s->if_then);
            switch_collect(sw, s->if_else);
            return;
        case STMT_WHILE:
            switch_collect(sw, s->while_body);
            return;
        case STMT_FOR:
            switch_collect(sw, s->for_init);
            switch_collect(sw, s->for_body);
            return;
        default:
            return;
    }
}

static int switch_case_label_for(const SwitchCtx *sw, const Stmt *node) {
    for (int i = 0; i < sw->ncases; i++) {
        if (sw->case_nodes[i] == node) return sw->case_labels[i];
    }
    return -1;
}

static int cg_lval_addr(CG *cg, const Expr *e) {
    if (!e) die("internal: not an lvalue");
    if (e->kind == EXPR_VAR) {
        str_appendf_i64(&cg->out, "  lea %d(%%rbp), %%rax\n", e->var_offset);
        return e->lval_size ? e->lval_size : 8;
    }
    if (e->kind == EXPR_COND_LVAL) {
        int l_else = new_label(cg);
        int l_end = new_label(cg);
        cg_expr(cg, e->lhs);
        str_appendf(&cg->out, "  test %%rax, %%rax\n");
        str_appendf_i64(&cg->out, "  je .L%d\n", l_else);
        (void)cg_lval_addr(cg, e->rhs);
        str_appendf_i64(&cg->out, "  jmp .L%d\n", l_end);
        str_appendf_i64(&cg->out, ".L%d:\n", l_else);
        (void)cg_lval_addr(cg, e->third);
        str_appendf_i64(&cg->out, ".L%d:\n", l_end);
        return e->lval_size ? e->lval_size : 8;
    }
    if (e->kind == EXPR_SRET_CALL) {
        // Produces an addressable temporary as the result.
        cg_expr(cg, e);
        return e->lval_size ? e->lval_size : 8;
    }
    if (e->kind == EXPR_COMPOUND) {
        // Initialize the temporary stack object and return its address.
        str_appendf_i64(&cg->out, "  lea %d(%%rbp), %%rdi\n", e->var_offset);
        if (e->init_zero) {
            str_appendf(&cg->out, "  xor %%eax, %%eax\n");
            str_appendf_i64(&cg->out, "  mov $%d, %%rcx\n", e->lval_size);
            str_appendf(&cg->out, "  cld\n");
            str_appendf(&cg->out, "  rep stosb\n");
            str_appendf_i64(&cg->out, "  lea %d(%%rbp), %%rdi\n", e->var_offset);
        }
        for (int i = 0; i < e->ninits; i++) {
            const InitEnt *in = &e->inits[i];
            cg_expr(cg, in->value);
            // cg_expr may clobber caller-saved regs (including %rdi). Recompute base.
            str_appendf_i64(&cg->out, "  lea %d(%%rbp), %%rdi\n", e->var_offset);
            if (in->store_size == 1) {
                str_appendf_i64(&cg->out, "  mov %%al, %d(%%rdi)\n", in->off);
            } else if (in->store_size == 2) {
                str_appendf_i64(&cg->out, "  mov %%ax, %d(%%rdi)\n", in->off);
            } else if (in->store_size == 4) {
                str_appendf_i64(&cg->out, "  mov %%eax, %d(%%rdi)\n", in->off);
            } else {
                str_appendf_i64(&cg->out, "  mov %%rax, %d(%%rdi)\n", in->off);
            }
        }
        str_appendf_i64(&cg->out, "  lea %d(%%rbp), %%rax\n", e->var_offset);
        return e->lval_size ? e->lval_size : 8;
    }
    if (e->kind == EXPR_DEREF) {
        cg_expr(cg, e->lhs);
        return e->lval_size ? e->lval_size : 8;
    }
    if (e->kind == EXPR_INDEX) {
        // Address = base + idx*scale
        cg_expr(cg, e->lhs);
        str_appendf(&cg->out, "  push %%rax\n");
        cg_expr(cg, e->rhs);
        str_appendf(&cg->out, "  pop %%rcx\n");
        int scale = (e->ptr_scale > 0) ? e->ptr_scale : 8;
        if (scale != 1) {
            str_appendf_i64(&cg->out, "  imul $%d, %%rax\n", scale);
        }
        str_appendf(&cg->out, "  add %%rcx, %%rax\n");
        return e->lval_size ? e->lval_size : 8;
    }
    if (e->kind == EXPR_MEMBER) {
        if (e->member_is_arrow) {
            cg_expr(cg, e->lhs);
        } else {
            (void)cg_lval_addr(cg, e->lhs);
        }
        if (e->member_off) {
            str_appendf_i64(&cg->out, "  add $%d, %%rax\n", e->member_off);
        }
        return e->lval_size ? e->lval_size : 8;
    }
    die("internal: not an lvalue");
}

static void cg_expr(CG *cg, const Expr *e) {
    if (!e) {
        // empty expression => 0
        str_appendf(&cg->out, "  xor %%eax, %%eax\n");
        return;
    }
    switch (e->kind) {
        case EXPR_NUM:
            if (e->num == 0) {
                str_appendf(&cg->out, "  xor %%eax, %%eax\n");
                return;
            }
            // Prefer shorter encodings when the value is representable as a 32-bit immediate.
            // Using %eax zero-extends to %rax, which is correct for non-negative values.
            if ((e->num > 0 && e->num <= 0x7fffffffLL) ||
                (e->is_unsigned && e->num > 0 && e->num <= 0xffffffffLL)) {
                str_appendf_i64(&cg->out, "  mov $%lld, %%eax\n", e->num);
            } else {
                str_appendf_i64(&cg->out, "  mov $%lld, %%rax\n", e->num);
            }
            return;
        case EXPR_FNADDR:
            if (e->callee[0] == 0) die("internal: fnaddr missing name");
            str_appendf_s(&cg->out, "  lea %s(%%rip), %%rax\n", e->callee);
            return;
        case EXPR_VAR:
            // Struct/aggregate values are not representable in a single register here.
            // If such an lvalue is evaluated as an rvalue (typically in a discarded context),
            // leave %rax as its address.
            if (e->base == BT_STRUCT && e->ptr == 0 && e->lval_size > 8) {
                str_appendf_i64(&cg->out, "  lea %d(%%rbp), %%rax\n", e->var_offset);
            } else if (e->lval_size == 0) {
                str_appendf_i64(&cg->out, "  lea %d(%%rbp), %%rax\n", e->var_offset);
            } else if (e->lval_size == 1) {
                str_appendf_i64(&cg->out, "  movzb %d(%%rbp), %%eax\n", e->var_offset);
            } else if (e->lval_size == 2) {
                if (e->is_unsigned) {
                    str_appendf_i64(&cg->out, "  movzw %d(%%rbp), %%eax\n", e->var_offset);
                } else {
                    str_appendf_i64(&cg->out, "  movswq %d(%%rbp), %%rax\n", e->var_offset);
                }
            } else if (e->lval_size == 4) {
                if (e->is_unsigned) {
                    str_appendf_i64(&cg->out, "  mov %d(%%rbp), %%eax\n", e->var_offset);
                } else {
                    str_appendf_i64(&cg->out, "  movslq %d(%%rbp), %%rax\n", e->var_offset);
                }
            } else if (e->lval_size == 8) {
                str_appendf_i64(&cg->out, "  mov %d(%%rbp), %%rax\n", e->var_offset);
            } else {
                die("rvalue load size %d not supported", e->lval_size);
            }
            return;
        case EXPR_STR:
            str_appendf_i64(&cg->out, "  lea .LC%d(%%rip), %%rax\n", e->str_id);
            return;
        case EXPR_ASSIGN:
            {
                int sz = cg_lval_addr(cg, e->lhs);
                str_appendf(&cg->out, "  push %%rax\n");
                cg_expr(cg, e->rhs);
                str_appendf(&cg->out, "  pop %%rcx\n");
                if (sz == 1) {
                    str_appendf(&cg->out, "  mov %%al, (%%rcx)\n");
                } else if (sz == 2) {
                    str_appendf(&cg->out, "  mov %%ax, (%%rcx)\n");
                } else if (sz == 4) {
                    str_appendf(&cg->out, "  mov %%eax, (%%rcx)\n");
                } else {
                    str_appendf(&cg->out, "  mov %%rax, (%%rcx)\n");
                }
                return;
            }
        case EXPR_MEMCPY: {
            int sz = e->lval_size;
            if (sz <= 0) die("internal: memcpy size %d", sz);
            (void)cg_lval_addr(cg, e->lhs);
            str_appendf(&cg->out, "  mov %%rax, %%rdi\n");
            str_appendf(&cg->out, "  push %%rdi\n");
            (void)cg_lval_addr(cg, e->rhs);
            str_appendf(&cg->out, "  mov %%rax, %%rsi\n");
            str_appendf(&cg->out, "  pop %%rdi\n");
            str_appendf_i64(&cg->out, "  mov $%d, %%rcx\n", sz);
            str_appendf(&cg->out, "  cld\n");
            str_appendf(&cg->out, "  rep movsb\n");
            str_appendf(&cg->out, "  xor %%eax, %%eax\n");
            return;
        }
        case EXPR_COND: {
            int l_else = new_label(cg);
            int l_end = new_label(cg);
            cg_expr(cg, e->lhs);
            str_appendf(&cg->out, "  test %%rax, %%rax\n");
            str_appendf_i64(&cg->out, "  je .L%d\n", l_else);
            cg_expr(cg, e->rhs);
            str_appendf_i64(&cg->out, "  jmp .L%d\n", l_end);
            str_appendf_i64(&cg->out, ".L%d:\n", l_else);
            cg_expr(cg, e->third);
            str_appendf_i64(&cg->out, ".L%d:\n", l_end);
            return;
        }
        case EXPR_CALL: {
            // Built-in syscalls (Linux x86_64): mc_syscall0..6 (and legacy sb_syscall0..6)
            // Signature: *_syscallN(n, a1..aN) -> rax
            if (e->callee[0] != 0 &&
                ((mc_strncmp(e->callee, "mc_syscall", 10) == 0) || (mc_strncmp(e->callee, "sb_syscall", 10) == 0)) &&
                e->callee[10] >= '0' && e->callee[10] <= '6' &&
                e->callee[11] == 0) {
                int n = (int)(e->callee[10] - '0');
                if (e->nargs != n + 1) {
                    die("syscall%d expects %d args", n, n + 1);
                }
                // Linux x86_64 syscall regs: rax=n, rdi,rsi,rdx,r10,r8,r9.
                static const char *sreg64[7] = {"%rax", "%rdi", "%rsi", "%rdx", "%r10", "%r8", "%r9"};
                static const char *sreg32[7] = {"%eax", "%edi", "%esi", "%edx", "%r10d", "%r8d", "%r9d"};

                // Count how many args need the push/pop path (complex expressions).
                int need_stack = 0;
                for (int i = 0; i < e->nargs; i++) {
                    if (!expr_is_simple_const(e->args[i])) need_stack++;
                }

                if (need_stack == 0) {
                    // All args are simple constants - load directly into target regs.
                    for (int i = 0; i < e->nargs; i++) {
                        (void)cg_expr_to_reg(cg, e->args[i], sreg64[i], sreg32[i]);
                    }
                } else {
                    // Mixed: evaluate complex args first (push), then load simple ones directly.
                    // Push complex args left-to-right.
                    for (int i = 0; i < e->nargs; i++) {
                        if (!expr_is_simple_const(e->args[i])) {
                            cg_expr(cg, e->args[i]);
                            str_appendf(&cg->out, "  push %%rax\n");
                        }
                    }
                    // Pop complex args into regs right-to-left.
                    for (int i = e->nargs - 1; i >= 0; i--) {
                        if (!expr_is_simple_const(e->args[i])) {
                            str_appendf_s(&cg->out, "  pop %s\n", sreg64[i]);
                        }
                    }
                    // Load simple const args directly.
                    for (int i = 0; i < e->nargs; i++) {
                        if (expr_is_simple_const(e->args[i])) {
                            (void)cg_expr_to_reg(cg, e->args[i], sreg64[i], sreg32[i]);
                        }
                    }
                }
                str_appendf(&cg->out, "  syscall\n");
                return;
            }

            // Check if this is a call to an inlineable static inline function.
            // If so, clone the inline expression with arguments substituted for parameters
            // and emit code for the inlined expression instead of a call.
            if (e->callee[0] != 0 && cg->prg) {
                const Function *callee_fn = program_find_fn(cg->prg, e->callee, mc_strlen(e->callee));
                if (callee_fn && callee_fn->inline_expr) {
                    // Create substituted expression
                    Expr *inlined = expr_clone_with_subst(
                        callee_fn->inline_expr,
                        callee_fn->param_offsets,
                        callee_fn->nparams,
                        e->args
                    );
                    // Emit code for the inlined expression
                    cg_expr(cg, inlined);
                    // Note: We don't free inlined - monacc uses arena-style allocation
                    return;
                }
            }

            // Minimal SysV ABI support:
            // - Integer/pointer args use up to 6 regs.
            // - Struct-by-value args larger than 16 bytes are passed in memory on the stack.
            //   (Required for sysbox/tools/expr.c which passes a 32-byte struct by value.)
            // Other aggregate classes are not implemented.
            if (e->callee[0] == 0) {
                // Indirect call via function pointer (no signature info): keep legacy behavior.
                static const char *areg[6] = {"%rdi", "%rsi", "%rdx", "%rcx", "%r8", "%r9"};
                int nreg = e->nargs;
                if (nreg > 6) nreg = 6;
                int nstack = e->nargs - nreg;

                int pad = (nstack & 1) ? 8 : 0;
                if (pad) {
                    str_appendf(&cg->out, "  sub $8, %%rsp\n");
                }
                for (int i = e->nargs - 1; i >= 6; i--) {
                    cg_expr(cg, e->args[i]);
                    str_appendf(&cg->out, "  push %%rax\n");
                }
                for (int i = 0; i < nreg; i++) {
                    cg_expr(cg, e->args[i]);
                    str_appendf(&cg->out, "  push %%rax\n");
                }
                for (int i = nreg - 1; i >= 0; i--) {
                    str_appendf(&cg->out, "  pop %%rax\n");
                    str_appendf_s(&cg->out, "  mov %%rax, %s\n", areg[i]);
                }
                if (!e->lhs) die("internal: indirect call missing callee");
                cg_expr(cg, e->lhs);
                str_appendf(&cg->out, "  mov %%rax, %%r11\n");
                str_appendf(&cg->out, "  xor %%eax, %%eax\n");
                str_appendf(&cg->out, "  call *%%r11\n");
                if (nstack > 0) {
                    str_appendf_i64(&cg->out, "  add $%d, %%rsp\n", 8 * nstack);
                }
                if (pad) {
                    str_appendf(&cg->out, "  add $8, %%rsp\n");
                }
                return;
            }

            static const char *areg[6] = {"%rdi", "%rsi", "%rdx", "%rcx", "%r8", "%r9"};
            static const char *areg32[6] = {"%edi", "%esi", "%edx", "%ecx", "%r8d", "%r9d"};
            CallArgInfo ai[64];
            if (e->nargs > (int)(sizeof(ai) / sizeof(ai[0]))) {
                die("too many call args");
            }

            int reg_used = 0;
            int stack_bytes = 0;
            for (int i = 0; i < e->nargs; i++) {
                const Expr *a = e->args[i];
                if (a && a->base == BT_STRUCT && a->ptr == 0 && a->lval_size > 0 && a->lval_size <= 16) {
                    die("struct args <= 16 bytes not supported");
                }
                if (a && a->base == BT_STRUCT && a->ptr == 0 && a->lval_size > 16) {
                    int slot = align_up(a->lval_size, 8);
                    ai[i].kind = CALLARG_STACK_STRUCT;
                    ai[i].reg = -1;
                    ai[i].stack_bytes = slot;
                    ai[i].struct_size = a->lval_size;
                    stack_bytes += slot;
                } else if (reg_used < 6) {
                    ai[i].kind = CALLARG_REG;
                    ai[i].reg = reg_used++;
                    ai[i].stack_bytes = 0;
                    ai[i].struct_size = 0;
                } else {
                    ai[i].kind = CALLARG_STACK_SCALAR;
                    ai[i].reg = -1;
                    ai[i].stack_bytes = 8;
                    ai[i].struct_size = 0;
                    stack_bytes += 8;
                }
            }

            // Keep stack 16B-aligned at call site.
            int pad = (stack_bytes & 15) ? 8 : 0;
            if (pad) {
                str_appendf(&cg->out, "  sub $8, %%rsp\n");
            }

            // Push/copy stack args right-to-left.
            for (int i = e->nargs - 1; i >= 0; i--) {
                if (ai[i].kind == CALLARG_STACK_SCALAR) {
                    cg_expr(cg, e->args[i]);
                    str_appendf(&cg->out, "  push %%rax\n");
                } else if (ai[i].kind == CALLARG_STACK_STRUCT) {
                    (void)cg_lval_addr(cg, e->args[i]);
                    str_appendf(&cg->out, "  mov %%rax, %%rsi\n");
                    str_appendf_i64(&cg->out, "  sub $%d, %%rsp\n", ai[i].stack_bytes);
                    str_appendf(&cg->out, "  mov %%rsp, %%rdi\n");
                    str_appendf_i64(&cg->out, "  mov $%d, %%rcx\n", ai[i].struct_size);
                    str_appendf(&cg->out, "  cld\n");
                    str_appendf(&cg->out, "  rep movsb\n");
                }
            }

            // Evaluate reg args: push complex ones, load simple ones directly at the end.
            for (int i = 0; i < e->nargs; i++) {
                if (ai[i].kind != CALLARG_REG) continue;
                if (!expr_is_simple_const(e->args[i])) {
                    cg_expr(cg, e->args[i]);
                    str_appendf(&cg->out, "  push %%rax\n");
                }
            }
            // Pop complex args into registers right-to-left.
            for (int i = e->nargs - 1; i >= 0; i--) {
                if (ai[i].kind != CALLARG_REG) continue;
                if (!expr_is_simple_const(e->args[i])) {
                    str_appendf_s(&cg->out, "  pop %s\n", areg[ai[i].reg]);
                }
            }
            // Load simple const args directly into target registers.
            for (int i = 0; i < e->nargs; i++) {
                if (ai[i].kind != CALLARG_REG) continue;
                if (expr_is_simple_const(e->args[i])) {
                    (void)cg_expr_to_reg(cg, e->args[i], areg[ai[i].reg], areg32[ai[i].reg]);
                }
            }

            str_appendf(&cg->out, "  xor %%eax, %%eax\n");
            str_appendf_s(&cg->out, "  call %s\n", e->callee);

            if (stack_bytes > 0) {
                str_appendf_i64(&cg->out, "  add $%d, %%rsp\n", stack_bytes);
            }
            if (pad) {
                str_appendf(&cg->out, "  add $8, %%rsp\n");
            }
            return;
        }
        case EXPR_SRET_CALL: {
            // Call a known function returning a struct by value using an sret pointer.
            // We allocate a stack temporary at e->var_offset and pass its address in %rdi.
            static const char *areg[5] = {"%rsi", "%rdx", "%rcx", "%r8", "%r9"};
            CallArgInfo ai[64];
            if (e->nargs > (int)(sizeof(ai) / sizeof(ai[0]))) {
                die("too many call args");
            }

            int reg_used = 0;
            int stack_bytes = 0;
            for (int i = 0; i < e->nargs; i++) {
                const Expr *a = e->args[i];
                if (a && a->base == BT_STRUCT && a->ptr == 0 && a->lval_size > 0 && a->lval_size <= 16) {
                    die("struct args <= 16 bytes not supported");
                }
                if (a && a->base == BT_STRUCT && a->ptr == 0 && a->lval_size > 16) {
                    int slot = align_up(a->lval_size, 8);
                    ai[i].kind = CALLARG_STACK_STRUCT;
                    ai[i].reg = -1;
                    ai[i].stack_bytes = slot;
                    ai[i].struct_size = a->lval_size;
                    stack_bytes += slot;
                } else if (reg_used < 5) {
                    ai[i].kind = CALLARG_REG;
                    ai[i].reg = reg_used++;
                    ai[i].stack_bytes = 0;
                    ai[i].struct_size = 0;
                } else {
                    ai[i].kind = CALLARG_STACK_SCALAR;
                    ai[i].reg = -1;
                    ai[i].stack_bytes = 8;
                    ai[i].struct_size = 0;
                    stack_bytes += 8;
                }
            }

            int pad = (stack_bytes & 15) ? 8 : 0;
            if (pad) {
                str_appendf(&cg->out, "  sub $8, %%rsp\n");
            }

            // Push/copy stack args right-to-left.
            for (int i = e->nargs - 1; i >= 0; i--) {
                if (ai[i].kind == CALLARG_STACK_SCALAR) {
                    cg_expr(cg, e->args[i]);
                    str_appendf(&cg->out, "  push %%rax\n");
                } else if (ai[i].kind == CALLARG_STACK_STRUCT) {
                    (void)cg_lval_addr(cg, e->args[i]);
                    str_appendf(&cg->out, "  mov %%rax, %%rsi\n");
                    str_appendf_i64(&cg->out, "  sub $%d, %%rsp\n", ai[i].stack_bytes);
                    str_appendf(&cg->out, "  mov %%rsp, %%rdi\n");
                    str_appendf_i64(&cg->out, "  mov $%d, %%rcx\n", ai[i].struct_size);
                    str_appendf(&cg->out, "  cld\n");
                    str_appendf(&cg->out, "  rep movsb\n");
                }
            }

            // Evaluate reg args left-to-right and push temporarily.
            for (int i = 0; i < e->nargs; i++) {
                if (ai[i].kind != CALLARG_REG) continue;
                cg_expr(cg, e->args[i]);
                str_appendf(&cg->out, "  push %%rax\n");
            }

            // Set sret pointer.
            str_appendf_i64(&cg->out, "  lea %d(%%rbp), %%rdi\n", e->var_offset);

            // Pop into registers right-to-left.
            for (int i = e->nargs - 1; i >= 0; i--) {
                if (ai[i].kind != CALLARG_REG) continue;
                str_appendf(&cg->out, "  pop %%rax\n");
                str_appendf_s(&cg->out, "  mov %%rax, %s\n", areg[ai[i].reg]);
            }

            if (e->callee[0] == 0) {
                die("internal: sret call missing callee name");
            }
            str_appendf(&cg->out, "  xor %%eax, %%eax\n");
            str_appendf_s(&cg->out, "  call %s\n", e->callee);

            if (stack_bytes > 0) {
                str_appendf_i64(&cg->out, "  add $%d, %%rsp\n", stack_bytes);
            }
            if (pad) {
                str_appendf(&cg->out, "  add $8, %%rsp\n");
            }

            // Result is the address of the temporary.
            str_appendf_i64(&cg->out, "  lea %d(%%rbp), %%rax\n", e->var_offset);
            return;
        }
        case EXPR_COMPOUND:
            (void)cg_lval_addr(cg, e);
            return;
        case EXPR_POS:
            cg_expr(cg, e->lhs);
            return;
        case EXPR_NEG:
            cg_expr(cg, e->lhs);
            str_appendf(&cg->out, "  neg %%rax\n");
            return;
        case EXPR_NOT:
            cg_expr(cg, e->lhs);
            str_appendf(&cg->out, "  test %%rax, %%rax\n");
            str_appendf(&cg->out, "  sete %%al\n");
            str_appendf(&cg->out, "  movzb %%al, %%eax\n");
            return;
        case EXPR_BNOT:
            cg_expr(cg, e->lhs);
            str_appendf(&cg->out, "  not %%rax\n");
            return;
        case EXPR_CAST:
            cg_expr(cg, e->lhs);
            if (e->ptr == 0 && e->base == BT_VOID) {
                // Value is discarded; keep a well-defined register value.
                str_appendf(&cg->out, "  xor %%eax, %%eax\n");
                return;
            }
            // Normalize the value in %rax to match the destination type size/signedness.
            // This is important for correct comparisons of smaller integer types.
            int dst_sz = 8;
            if (e->ptr > 0) {
                dst_sz = 8;
            } else if (e->base == BT_CHAR) {
                dst_sz = 1;
            } else if (e->base == BT_SHORT) {
                dst_sz = 2;
            } else if (e->base == BT_INT) {
                dst_sz = 4;
            } else if (e->base == BT_LONG) {
                dst_sz = 8;
            } else {
                // Struct casts are not expected here; leave the value as-is.
                dst_sz = 8;
            }

            if (dst_sz == 1) {
                if (e->is_unsigned) {
                    str_appendf(&cg->out, "  movzb %%al, %%eax\n");
                } else {
                    str_appendf(&cg->out, "  movsbq %%al, %%rax\n");
                }
            } else if (dst_sz == 2) {
                if (e->is_unsigned) {
                    str_appendf(&cg->out, "  movzw %%ax, %%eax\n");
                } else {
                    str_appendf(&cg->out, "  movswq %%ax, %%rax\n");
                }
            } else if (dst_sz == 4) {
                if (e->is_unsigned) {
                    str_appendf(&cg->out, "  mov %%eax, %%eax\n");
                } else {
                    str_appendf(&cg->out, "  movslq %%eax, %%rax\n");
                }
            }
            return;
        case EXPR_PREINC:
        case EXPR_PREDEC: {
            int sz = cg_lval_addr(cg, e->lhs);
            if (sz != 1 && sz != 2 && sz != 4 && sz != 8) {
                die("pre ++/-- size %d not supported", sz);
            }
            // addr in %rax
            str_appendf(&cg->out, "  mov %%rax, %%rcx\n");
            if (sz == 1) {
                str_appendf(&cg->out, "  movzb (%%rcx), %%eax\n");
            } else if (sz == 2) {
                if (e->is_unsigned) {
                    str_appendf(&cg->out, "  movzw (%%rcx), %%eax\n");
                } else {
                    str_appendf(&cg->out, "  movswq (%%rcx), %%rax\n");
                }
            } else if (sz == 4) {
                if (e->is_unsigned) {
                    str_appendf(&cg->out, "  mov (%%rcx), %%eax\n");
                } else {
                    str_appendf(&cg->out, "  movslq (%%rcx), %%rax\n");
                }
            } else {
                str_appendf(&cg->out, "  mov (%%rcx), %%rax\n");
            }

            long long delta = (long long)(e->post_delta > 0 ? e->post_delta : 1);
            if (e->kind == EXPR_PREDEC) delta = -delta;

            if (delta == 1) {
                str_appendf(&cg->out, "  add $1, %%rax\n");
            } else if (delta == -1) {
                str_appendf(&cg->out, "  sub $1, %%rax\n");
            } else if (delta > 0) {
                str_appendf_i64(&cg->out, "  add $%lld, %%rax\n", delta);
            } else {
                str_appendf_i64(&cg->out, "  sub $%lld, %%rax\n", -delta);
            }

            // Truncate to the lvalue type (wrap like the store does).
            if (sz == 1) {
                str_appendf(&cg->out, "  and $0xff, %%eax\n");
            } else if (sz == 2) {
                if (e->is_unsigned) {
                    str_appendf(&cg->out, "  and $0xffff, %%eax\n");
                } else {
                    str_appendf(&cg->out, "  movswq %%ax, %%rax\n");
                }
            } else if (sz == 4) {
                if (e->is_unsigned) {
                    str_appendf(&cg->out, "  mov %%eax, %%eax\n");
                } else {
                    str_appendf(&cg->out, "  movslq %%eax, %%rax\n");
                }
            }

            if (sz == 1) {
                str_appendf(&cg->out, "  mov %%al, (%%rcx)\n");
            } else if (sz == 2) {
                str_appendf(&cg->out, "  mov %%ax, (%%rcx)\n");
            } else if (sz == 4) {
                str_appendf(&cg->out, "  mov %%eax, (%%rcx)\n");
            } else {
                str_appendf(&cg->out, "  mov %%rax, (%%rcx)\n");
            }
            // result is new value already in %rax
            return;
        }
        case EXPR_POSTINC:
        case EXPR_POSTDEC: {
            int sz = cg_lval_addr(cg, e->lhs);
            if (sz != 1 && sz != 2 && sz != 4 && sz != 8) {
                die("post ++/-- size %d not supported", sz);
            }
            // addr in %rax
            str_appendf(&cg->out, "  mov %%rax, %%rcx\n");
            if (sz == 1) {
                str_appendf(&cg->out, "  movzb (%%rcx), %%eax\n");
                str_appendf(&cg->out, "  mov %%rax, %%rdx\n");
            } else if (sz == 2) {
                if (e->is_unsigned) {
                    str_appendf(&cg->out, "  movzw (%%rcx), %%eax\n");
                } else {
                    str_appendf(&cg->out, "  movswq (%%rcx), %%rax\n");
                }
                str_appendf(&cg->out, "  mov %%rax, %%rdx\n");
            } else if (sz == 4) {
                if (e->is_unsigned) {
                    str_appendf(&cg->out, "  mov (%%rcx), %%eax\n");
                } else {
                    str_appendf(&cg->out, "  movslq (%%rcx), %%rax\n");
                }
                str_appendf(&cg->out, "  mov %%rax, %%rdx\n");
            } else {
                str_appendf(&cg->out, "  mov (%%rcx), %%rax\n");
                str_appendf(&cg->out, "  mov %%rax, %%rdx\n");
            }

            long long delta = (long long)(e->post_delta > 0 ? e->post_delta : 1);
            if (e->kind == EXPR_POSTDEC) delta = -delta;

            if (delta == 1) {
                str_appendf(&cg->out, "  add $1, %%rax\n");
            } else if (delta == -1) {
                str_appendf(&cg->out, "  sub $1, %%rax\n");
            } else if (delta > 0) {
                str_appendf_i64(&cg->out, "  add $%lld, %%rax\n", delta);
            } else {
                str_appendf_i64(&cg->out, "  sub $%lld, %%rax\n", -delta);
            }

            // Truncate to the lvalue type (wrap like the store does).
            if (sz == 1) {
                str_appendf(&cg->out, "  and $0xff, %%eax\n");
            } else if (sz == 2) {
                if (e->is_unsigned) {
                    str_appendf(&cg->out, "  and $0xffff, %%eax\n");
                } else {
                    str_appendf(&cg->out, "  movswq %%ax, %%rax\n");
                }
            } else if (sz == 4) {
                if (e->is_unsigned) {
                    str_appendf(&cg->out, "  mov %%eax, %%eax\n");
                } else {
                    str_appendf(&cg->out, "  movslq %%eax, %%rax\n");
                }
            }

            if (sz == 1) {
                str_appendf(&cg->out, "  mov %%al, (%%rcx)\n");
            } else if (sz == 2) {
                str_appendf(&cg->out, "  mov %%ax, (%%rcx)\n");
            } else if (sz == 4) {
                str_appendf(&cg->out, "  mov %%eax, (%%rcx)\n");
            } else {
                str_appendf(&cg->out, "  mov %%rax, (%%rcx)\n");
            }
            // result is old value
            str_appendf(&cg->out, "  mov %%rdx, %%rax\n");
            return;
        }
        case EXPR_ADDR:
            (void)cg_lval_addr(cg, e->lhs);
            return;
        case EXPR_DEREF:
            cg_expr(cg, e->lhs);
            if (e->lval_size > 8) {
                // Keep address in %rax.
                return;
            }
            if (e->lval_size == 1) {
                str_appendf(&cg->out, "  movzb (%%rax), %%eax\n");
            } else if (e->lval_size == 2) {
                if (e->is_unsigned) {
                    str_appendf(&cg->out, "  movzw (%%rax), %%eax\n");
                } else {
                    str_appendf(&cg->out, "  movswq (%%rax), %%rax\n");
                }
            } else if (e->lval_size == 4) {
                if (e->is_unsigned) {
                    str_appendf(&cg->out, "  mov (%%rax), %%eax\n");
                } else {
                    str_appendf(&cg->out, "  movslq (%%rax), %%rax\n");
                }
            } else {
                str_appendf(&cg->out, "  mov (%%rax), %%rax\n");
            }
            return;
        case EXPR_INDEX:
            // rvalue load via computed address
            (void)cg_lval_addr(cg, e);
            if (e->lval_size == 0 || e->lval_size > 8) {
                return;
            }
            if (e->lval_size == 1) {
                str_appendf(&cg->out, "  movzb (%%rax), %%eax\n");
            } else if (e->lval_size == 2) {
                if (e->is_unsigned) {
                    str_appendf(&cg->out, "  movzw (%%rax), %%eax\n");
                } else {
                    str_appendf(&cg->out, "  movswq (%%rax), %%rax\n");
                }
            } else if (e->lval_size == 4) {
                if (e->is_unsigned) {
                    str_appendf(&cg->out, "  mov (%%rax), %%eax\n");
                } else {
                    str_appendf(&cg->out, "  movslq (%%rax), %%rax\n");
                }
            } else {
                str_appendf(&cg->out, "  mov (%%rax), %%rax\n");
            }
            return;
        case EXPR_MEMBER:
            // rvalue load via computed address
            (void)cg_lval_addr(cg, e);
            if (e->lval_size == 0 || e->lval_size > 8) {
                return;
            }
            if (e->lval_size == 1) {
                str_appendf(&cg->out, "  movzb (%%rax), %%eax\n");
            } else if (e->lval_size == 2) {
                if (e->is_unsigned) {
                    str_appendf(&cg->out, "  movzw (%%rax), %%eax\n");
                } else {
                    str_appendf(&cg->out, "  movswq (%%rax), %%rax\n");
                }
            } else if (e->lval_size == 4) {
                if (e->is_unsigned) {
                    str_appendf(&cg->out, "  mov (%%rax), %%eax\n");
                } else {
                    str_appendf(&cg->out, "  movslq (%%rax), %%rax\n");
                }
            } else if (e->lval_size == 8) {
                str_appendf(&cg->out, "  mov (%%rax), %%rax\n");
            } else {
                die("member rvalue load size %d not supported", e->lval_size);
            }
            return;
        case EXPR_LAND: {
            int l_false = new_label(cg);
            int l_end = new_label(cg);
            cg_expr(cg, e->lhs);
            str_appendf(&cg->out, "  test %%rax, %%rax\n");
            str_appendf_i64(&cg->out, "  je .L%d\n", l_false);
            cg_expr(cg, e->rhs);
            str_appendf(&cg->out, "  test %%rax, %%rax\n");
            str_appendf(&cg->out, "  setne %%al\n");
            str_appendf(&cg->out, "  movzb %%al, %%eax\n");
            str_appendf_i64(&cg->out, "  jmp .L%d\n", l_end);
            str_appendf_i64(&cg->out, ".L%d:\n", l_false);
            str_appendf(&cg->out, "  xor %%eax, %%eax\n");
            str_appendf_i64(&cg->out, ".L%d:\n", l_end);
            return;
        }
        case EXPR_LOR: {
            int l_true = new_label(cg);
            int l_end = new_label(cg);
            cg_expr(cg, e->lhs);
            str_appendf(&cg->out, "  test %%rax, %%rax\n");
            str_appendf_i64(&cg->out, "  jne .L%d\n", l_true);
            cg_expr(cg, e->rhs);
            str_appendf(&cg->out, "  test %%rax, %%rax\n");
            str_appendf(&cg->out, "  setne %%al\n");
            str_appendf(&cg->out, "  movzb %%al, %%eax\n");
            str_appendf_i64(&cg->out, "  jmp .L%d\n", l_end);
            str_appendf_i64(&cg->out, ".L%d:\n", l_true);
            str_appendf(&cg->out, "  mov $1, %%eax\n");
            str_appendf_i64(&cg->out, ".L%d:\n", l_end);
            return;
        }
        case EXPR_ADD:
        case EXPR_SUB:
        case EXPR_SHL:
        case EXPR_SHR:
        case EXPR_BAND:
        case EXPR_BXOR:
        case EXPR_BOR:
        case EXPR_MUL:
        case EXPR_DIV:
        case EXPR_MOD:
        case EXPR_EQ:
        case EXPR_NE:
        case EXPR_LT:
        case EXPR_LE:
        case EXPR_GT:
        case EXPR_GE: {
            // Peepholes for constant RHS: avoid push/pop and generate shorter immediates.
            // Safe because EXPR_NUM has no side effects.
            if (e->lhs && e->lhs->kind == EXPR_NUM) {
                long long imm = e->lhs->num;
                // Comparisons: compare rhs against immediate and flip the condition as needed.
                if (e->kind == EXPR_EQ || e->kind == EXPR_NE ||
                    e->kind == EXPR_LT || e->kind == EXPR_LE ||
                    e->kind == EXPR_GT || e->kind == EXPR_GE) {
                    // Evaluate rhs into %rax.
                    cg_expr(cg, e->rhs);
                    if (imm == 0) {
                        str_appendf(&cg->out, "  test %%rax, %%rax\n");
                    } else if (imm >= -2147483648LL && imm <= 2147483647LL) {
                        str_appendf_i64(&cg->out, "  cmp $%lld, %%rax\n", imm);
                    } else {
                        goto slow_binop;
                    }

                    int use_unsigned = (e->lhs && (e->lhs->ptr > 0 || e->lhs->is_unsigned)) ||
                                       (e->rhs && (e->rhs->ptr > 0 || e->rhs->is_unsigned));

                    // We computed flags for (%rax - imm). Map (imm ? %rax) to a condition.
                    const char *cc = "e";
                    if (e->kind == EXPR_EQ) cc = "e";
                    else if (e->kind == EXPR_NE) cc = "ne";
                    else if (e->kind == EXPR_LT) cc = use_unsigned ? "a" : "g";   // imm < rhs  <=> rhs > imm
                    else if (e->kind == EXPR_LE) cc = use_unsigned ? "ae" : "ge"; // imm <= rhs <=> rhs >= imm
                    else if (e->kind == EXPR_GT) cc = use_unsigned ? "b" : "l";   // imm > rhs  <=> rhs < imm
                    else if (e->kind == EXPR_GE) cc = use_unsigned ? "be" : "le"; // imm >= rhs <=> rhs <= imm

                    str_appendf_s(&cg->out, "  set%s %%al\n", cc);
                    str_appendf(&cg->out, "  movzb %%al, %%eax\n");
                    return;
                }

                // Commutative operations: evaluate rhs into %rax and apply immediate.
                // This preserves safety because lhs is a pure constant.
                if (imm >= -2147483648LL && imm <= 2147483647LL) {
                    if (e->kind == EXPR_ADD) {
                        long long addimm = imm;
                        // Handle ptr arithmetic where lhs is index side.
                        if (e->ptr_scale > 0) {
                            if (e->ptr_index_side != 2) goto slow_binop;
                            addimm = imm * (long long)e->ptr_scale;
                            if (addimm < -2147483648LL || addimm > 2147483647LL) goto slow_binop;
                        }
                        cg_expr(cg, e->rhs);
                        if (addimm == 0) return;
                        if (addimm == 1) {
                            str_appendf(&cg->out, "  inc %%rax\n");
                        } else if (addimm == -1) {
                            str_appendf(&cg->out, "  dec %%rax\n");
                        } else {
                            str_appendf_i64(&cg->out, "  add $%lld, %%rax\n", addimm);
                        }
                        return;
                    }
                    if (e->kind == EXPR_BAND) {
                        cg_expr(cg, e->rhs);
                        if (imm == -1) return;
                        if (imm == 0) {
                            str_appendf(&cg->out, "  xor %%eax, %%eax\n");
                        } else {
                            str_appendf_i64(&cg->out, "  and $%lld, %%rax\n", imm);
                        }
                        return;
                    }
                    if (e->kind == EXPR_BOR) {
                        cg_expr(cg, e->rhs);
                        if (imm == 0) return;
                        str_appendf_i64(&cg->out, "  or $%lld, %%rax\n", imm);
                        return;
                    }
                    if (e->kind == EXPR_BXOR) {
                        cg_expr(cg, e->rhs);
                        if (imm == 0) return;
                        if (imm == -1) {
                            str_appendf(&cg->out, "  not %%rax\n");
                        } else {
                            str_appendf_i64(&cg->out, "  xor $%lld, %%rax\n", imm);
                        }
                        return;
                    }
                    if (e->kind == EXPR_MUL && e->ptr_scale == 0) {
                        cg_expr(cg, e->rhs);
                        if (imm == 0) {
                            str_appendf(&cg->out, "  xor %%eax, %%eax\n");
                            return;
                        }
                        if (imm == 1) return;
                        if (imm == -1) {
                            str_appendf(&cg->out, "  neg %%rax\n");
                            return;
                        }
                        // Strength-reduce small power-of-two multiplies for smaller code.
                        if (imm == 2) {
                            str_appendf(&cg->out, "  add %%rax, %%rax\n");
                            return;
                        }
                        if (imm == -2) {
                            str_appendf(&cg->out, "  add %%rax, %%rax\n");
                            str_appendf(&cg->out, "  neg %%rax\n");
                            return;
                        }
                        if (imm > 0 && imm <= 0x80000000LL) {
                            int sh = u64_pow2_shift((unsigned long long)imm);
                            if (sh > 0 && sh <= 31) {
                                str_appendf_i64(&cg->out, "  shl $%d, %%rax\n", sh);
                                return;
                            }
                        }
                        if (imm < 0) {
                            long long u = -imm;
                            if (u > 0 && u <= 0x80000000LL) {
                                int sh = u64_pow2_shift((unsigned long long)u);
                                if (sh > 0 && sh <= 31) {
                                    str_appendf_i64(&cg->out, "  shl $%d, %%rax\n", sh);
                                    str_appendf(&cg->out, "  neg %%rax\n");
                                    return;
                                }
                            }
                        }
                        str_appendf_i64(&cg->out, "  imul $%lld, %%rax, %%rax\n", imm);
                        return;
                    }
                }

                // Non-commutative subtraction with constant lhs: imm - rhs => neg(rhs) + imm.
                if (e->kind == EXPR_SUB && e->ptr_scale == 0 &&
                    imm >= -2147483648LL && imm <= 2147483647LL) {
                    cg_expr(cg, e->rhs);
                    str_appendf(&cg->out, "  neg %%rax\n");
                    if (imm != 0) {
                        str_appendf_i64(&cg->out, "  add $%lld, %%rax\n", imm);
                    }
                    return;
                }
            }

            if (e->rhs && e->rhs->kind == EXPR_NUM) {
                long long imm = e->rhs->num;
                // Comparisons: emit test/cmp immediate directly.
                if (e->kind == EXPR_EQ || e->kind == EXPR_NE ||
                    e->kind == EXPR_LT || e->kind == EXPR_LE ||
                    e->kind == EXPR_GT || e->kind == EXPR_GE) {
                    cg_expr(cg, e->lhs);
                    if (imm == 0) {
                        str_appendf(&cg->out, "  test %%rax, %%rax\n");
                    } else if (imm >= -2147483648LL && imm <= 2147483647LL) {
                        str_appendf_i64(&cg->out, "  cmp $%lld, %%rax\n", imm);
                    } else {
                        // Immediate doesn't fit in signed imm32 for cmpq; fall back.
                        goto slow_binop;
                    }
                    int use_unsigned = (e->lhs && (e->lhs->ptr > 0 || e->lhs->is_unsigned)) ||
                                       (e->rhs && (e->rhs->ptr > 0 || e->rhs->is_unsigned));
                    const char *cc = "e";
                    if (e->kind == EXPR_EQ) cc = "e";
                    else if (e->kind == EXPR_NE) cc = "ne";
                    else if (e->kind == EXPR_LT) cc = use_unsigned ? "b" : "l";
                    else if (e->kind == EXPR_LE) cc = use_unsigned ? "be" : "le";
                    else if (e->kind == EXPR_GT) cc = use_unsigned ? "a" : "g";
                    else if (e->kind == EXPR_GE) cc = use_unsigned ? "ae" : "ge";
                    str_appendf_s(&cg->out, "  set%s %%al\n", cc);
                    str_appendf(&cg->out, "  movzb %%al, %%eax\n");
                    return;
                }

                // Shifts: use immediate count when in range.
                if ((e->kind == EXPR_SHL || e->kind == EXPR_SHR) &&
                    e->ptr_scale == 0 && imm >= 0 && imm <= 63) {
                    cg_expr(cg, e->lhs);
                    if (imm == 0) return;
                    if (e->kind == EXPR_SHL) {
                        if (imm == 1) {
                            // Smaller than shl $1, %rax.
                            str_appendf(&cg->out, "  add %%rax, %%rax\n");
                        } else {
                            str_appendf_i64(&cg->out, "  shl $%lld, %%rax\n", imm);
                        }
                    } else {
                        if ((e->lhs && (e->lhs->ptr > 0 || e->lhs->is_unsigned)) ||
                            (e->rhs && (e->rhs->ptr > 0 || e->rhs->is_unsigned))) {
                            str_appendf_i64(&cg->out, "  shr $%lld, %%rax\n", imm);
                        } else {
                            str_appendf_i64(&cg->out, "  sar $%lld, %%rax\n", imm);
                        }
                    }
                    return;
                }

                // Division/modulo by 1 are worth special-casing (saves a full idiv sequence).
                if ((e->kind == EXPR_DIV || e->kind == EXPR_MOD) && imm == 1) {
                    cg_expr(cg, e->lhs);
                    if (e->kind == EXPR_MOD) {
                        str_appendf(&cg->out, "  xor %%eax, %%eax\n");
                    }
                    return;
                }

                // Unsigned division/modulo by a power of two.
                // For unsigned/pointer values, x / 2^k == x >> k, and x % 2^k == x & (2^k-1).
                if ((e->kind == EXPR_DIV || e->kind == EXPR_MOD) && imm > 1) {
                    int use_unsigned = (e->lhs && (e->lhs->ptr > 0 || e->lhs->is_unsigned)) ||
                                       (e->rhs && (e->rhs->ptr > 0 || e->rhs->is_unsigned));
                    if (use_unsigned) {
                        unsigned long long uimm = (unsigned long long)imm;
                        int sh = u64_pow2_shift(uimm);
                        if (sh >= 1 && sh <= 63) {
                            cg_expr(cg, e->lhs);
                            if (e->kind == EXPR_DIV) {
                                str_appendf_i64(&cg->out, "  shr $%d, %%rax\n", sh);
                            } else {
                                unsigned long long mask = uimm - 1ULL;
                                // AND immediate is sign-extended imm32 in x86-64.
                                if (mask <= 0x7fffffffULL) {
                                    str_appendf_u64(&cg->out, "  and $%llu, %%rax\n", mask);
                                    return;
                                }
                                // For larger masks, fall back to the generic path.
                                goto slow_binop;
                            }
                            return;
                        }
                    }
                }

                // add/sub and bitwise ops: immediate encodings are smaller when imm32 fits.
                if (imm >= -2147483648LL && imm <= 2147483647LL) {
                    if (e->kind == EXPR_ADD) {
                        // For pointer arithmetic, only optimize when RHS is the index side.
                        if (e->ptr_scale > 0 && e->ptr_index_side != 1) goto slow_binop;
                        long long addimm = imm;
                        if (e->ptr_scale > 0 && e->ptr_index_side == 1) {
                            addimm = imm * (long long)e->ptr_scale;
                            if (addimm < -2147483648LL || addimm > 2147483647LL) goto slow_binop;
                        }
                        cg_expr(cg, e->lhs);
                        if (addimm == 0) return;
                        if (addimm == 1) {
                            str_appendf(&cg->out, "  inc %%rax\n");
                        } else if (addimm == -1) {
                            str_appendf(&cg->out, "  dec %%rax\n");
                        } else {
                            str_appendf_i64(&cg->out, "  add $%lld, %%rax\n", addimm);
                        }
                        return;
                    }
                    if (e->kind == EXPR_SUB) {
                        if (e->ptr_scale > 0 && e->ptr_index_side != 1) goto slow_binop;
                        long long subimm = imm;
                        if (e->ptr_scale > 0 && e->ptr_index_side == 1) {
                            subimm = imm * (long long)e->ptr_scale;
                            if (subimm < -2147483648LL || subimm > 2147483647LL) goto slow_binop;
                        }
                        cg_expr(cg, e->lhs);
                        if (subimm == 0) return;
                        if (subimm == 1) {
                            str_appendf(&cg->out, "  dec %%rax\n");
                        } else if (subimm == -1) {
                            str_appendf(&cg->out, "  inc %%rax\n");
                        } else {
                            str_appendf_i64(&cg->out, "  sub $%lld, %%rax\n", subimm);
                        }
                        return;
                    }
                    if (e->kind == EXPR_BAND) {
                        cg_expr(cg, e->lhs);
                        if (imm == -1) return;
                        if (imm == 0) {
                            str_appendf(&cg->out, "  xor %%eax, %%eax\n");
                        } else {
                            str_appendf_i64(&cg->out, "  and $%lld, %%rax\n", imm);
                        }
                        return;
                    }
                    if (e->kind == EXPR_BOR) {
                        cg_expr(cg, e->lhs);
                        if (imm == 0) return;
                        str_appendf_i64(&cg->out, "  or $%lld, %%rax\n", imm);
                        return;
                    }
                    if (e->kind == EXPR_BXOR) {
                        cg_expr(cg, e->lhs);
                        if (imm == 0) return;
                        if (imm == -1) {
                            str_appendf(&cg->out, "  not %%rax\n");
                        } else {
                            str_appendf_i64(&cg->out, "  xor $%lld, %%rax\n", imm);
                        }
                        return;
                    }
                    if (e->kind == EXPR_MUL && e->ptr_scale == 0) {
                        cg_expr(cg, e->lhs);
                        if (imm == 0) {
                            str_appendf(&cg->out, "  xor %%eax, %%eax\n");
                            return;
                        }
                        if (imm == 1) return;
                        if (imm == -1) {
                            str_appendf(&cg->out, "  neg %%rax\n");
                            return;
                        }
                        if (imm == 2) {
                            str_appendf(&cg->out, "  add %%rax, %%rax\n");
                            return;
                        }
                        if (imm == -2) {
                            str_appendf(&cg->out, "  add %%rax, %%rax\n");
                            str_appendf(&cg->out, "  neg %%rax\n");
                            return;
                        }
                        if (imm > 0 && imm <= 0x80000000LL) {
                            int sh = u64_pow2_shift((unsigned long long)imm);
                            if (sh > 0 && sh <= 31) {
                                str_appendf_i64(&cg->out, "  shl $%d, %%rax\n", sh);
                                return;
                            }
                        }
                        if (imm < 0) {
                            long long u = -imm;
                            if (u > 0 && u <= 0x80000000LL) {
                                int sh = u64_pow2_shift((unsigned long long)u);
                                if (sh > 0 && sh <= 31) {
                                    str_appendf_i64(&cg->out, "  shl $%d, %%rax\n", sh);
                                    str_appendf(&cg->out, "  neg %%rax\n");
                                    return;
                                }
                            }
                        }
                        str_appendf_i64(&cg->out, "  imul $%lld, %%rax, %%rax\n", imm);
                        return;
                    }
                }
            }

        slow_binop:
            cg_expr(cg, e->lhs);
            str_appendf(&cg->out, "  push %%rax\n");
            cg_expr(cg, e->rhs);
            str_appendf(&cg->out, "  pop %%rcx\n");
            if ((e->kind == EXPR_ADD || e->kind == EXPR_SUB) && e->ptr_scale > 0) {
                if (e->ptr_index_side == 1) {
                    if (e->ptr_scale != 1) {
                        str_appendf_i64(&cg->out, "  imul $%d, %%rax\n", e->ptr_scale);
                    }
                } else if (e->ptr_index_side == 2) {
                    if (e->ptr_scale != 1) {
                        str_appendf_i64(&cg->out, "  imul $%d, %%rcx\n", e->ptr_scale);
                    }
                }
            }
            switch (e->kind) {
                case EXPR_ADD:
                    str_appendf(&cg->out, "  add %%rcx, %%rax\n");
                    return;
                case EXPR_SUB:
                    // rcx = lhs, rax = rhs => lhs - rhs
                    str_appendf(&cg->out, "  sub %%rax, %%rcx\n");
                    str_appendf(&cg->out, "  mov %%rcx, %%rax\n");
                    return;
                case EXPR_BAND:
                    str_appendf(&cg->out, "  and %%rcx, %%rax\n");
                    return;
                case EXPR_BXOR:
                    str_appendf(&cg->out, "  xor %%rcx, %%rax\n");
                    return;
                case EXPR_BOR:
                    str_appendf(&cg->out, "  or %%rcx, %%rax\n");
                    return;
                case EXPR_SHL:
                    // rcx=lhs, rax=rhs(count)
                    str_appendf(&cg->out, "  mov %%rcx, %%rdx\n");
                    str_appendf(&cg->out, "  mov %%al, %%cl\n");
                    str_appendf(&cg->out, "  mov %%rdx, %%rax\n");
                    str_appendf(&cg->out, "  shl %%cl, %%rax\n");
                    return;
                case EXPR_SHR:
                    str_appendf(&cg->out, "  mov %%rcx, %%rdx\n");
                    str_appendf(&cg->out, "  mov %%al, %%cl\n");
                    str_appendf(&cg->out, "  mov %%rdx, %%rax\n");
                    if ((e->lhs && (e->lhs->ptr > 0 || e->lhs->is_unsigned)) || (e->rhs && (e->rhs->ptr > 0 || e->rhs->is_unsigned))) {
                        str_appendf(&cg->out, "  shr %%cl, %%rax\n");
                    } else {
                        str_appendf(&cg->out, "  sar %%cl, %%rax\n");
                    }
                    return;
                case EXPR_MUL:
                    str_appendf(&cg->out, "  imul %%rcx, %%rax\n");
                    return;
                case EXPR_DIV:
                case EXPR_MOD:
                    // Division/modulo (signed or unsigned)
                    // rcx=lhs, rax=rhs currently
                    str_appendf(&cg->out, "  mov %%rax, %%rdi\n"); // rhs
                    str_appendf(&cg->out, "  mov %%rcx, %%rax\n"); // lhs
                    if ((e->lhs && (e->lhs->ptr > 0 || e->lhs->is_unsigned)) || (e->rhs && (e->rhs->ptr > 0 || e->rhs->is_unsigned))) {
                        str_appendf(&cg->out, "  xor %%edx, %%edx\n");
                        str_appendf(&cg->out, "  div %%rdi\n");
                    } else {
                        str_appendf(&cg->out, "  cqo\n");
                        str_appendf(&cg->out, "  idiv %%rdi\n");
                    }
                    if (e->kind == EXPR_MOD) {
                        str_appendf(&cg->out, "  mov %%rdx, %%rax\n");
                    }
                    return;
                case EXPR_EQ:
                case EXPR_NE:
                case EXPR_LT:
                case EXPR_LE:
                case EXPR_GT:
                case EXPR_GE: {
                    // Compare lhs (rcx) vs rhs (rax) => setcc into al
                    str_appendf(&cg->out, "  cmp %%rax, %%rcx\n");
                    int use_unsigned = (e->lhs && (e->lhs->ptr > 0 || e->lhs->is_unsigned)) || (e->rhs && (e->rhs->ptr > 0 || e->rhs->is_unsigned));
                    const char *cc = "e";
                    if (e->kind == EXPR_EQ) cc = "e";
                    else if (e->kind == EXPR_NE) cc = "ne";
                    else if (e->kind == EXPR_LT) cc = use_unsigned ? "b" : "l";
                    else if (e->kind == EXPR_LE) cc = use_unsigned ? "be" : "le";
                    else if (e->kind == EXPR_GT) cc = use_unsigned ? "a" : "g";
                    else if (e->kind == EXPR_GE) cc = use_unsigned ? "ae" : "ge";
                    str_appendf_s(&cg->out, "  set%s %%al\n", cc);
                    str_appendf(&cg->out, "  movzb %%al, %%eax\n");
                    return;
                }
                default:
                    break;
            }
            break;
        }
        default:
            break;
    }
    die("internal: unhandled expr kind");
}

// Emit a conditional branch for a comparison expression.
// If jump_on_false, jump to label when condition is false; otherwise jump when true.
// Returns 1 if handled (optimized path), 0 if caller should use cg_expr + test.
static int cg_cond_branch(CG *cg, const Expr *e, int label, int jump_on_false) {
    if (!e) return 0;

    // Handle comparison expressions directly.
    if (expr_is_comparison(e)) {
        int use_unsigned = (e->lhs && (e->lhs->ptr > 0 || e->lhs->is_unsigned)) ||
                           (e->rhs && (e->rhs->ptr > 0 || e->rhs->is_unsigned));

        // Check for constant RHS - common case like "x >= 0" or "x < 0"
        if (e->rhs && e->rhs->kind == EXPR_NUM) {
            long long imm = e->rhs->num;
            cg_expr(cg, e->lhs);
            if (imm == 0) {
                str_appendf(&cg->out, "  test %%rax, %%rax\n");
            } else if (imm >= -2147483648LL && imm <= 2147483647LL) {
                str_appendf_i64(&cg->out, "  cmp $%d, %%rax\n", imm);
            } else {
                return 0; // Fall back to generic path
            }

            // Determine jump condition
            const char *jcc = "je";
            if (jump_on_false) {
                // Jump when condition is FALSE
                if (e->kind == EXPR_EQ) jcc = "jne";
                else if (e->kind == EXPR_NE) jcc = "je";
                else if (e->kind == EXPR_LT) jcc = use_unsigned ? "jae" : "jge";
                else if (e->kind == EXPR_LE) jcc = use_unsigned ? "ja" : "jg";
                else if (e->kind == EXPR_GT) jcc = use_unsigned ? "jbe" : "jle";
                else if (e->kind == EXPR_GE) jcc = use_unsigned ? "jb" : "jl";
            } else {
                // Jump when condition is TRUE
                if (e->kind == EXPR_EQ) jcc = "je";
                else if (e->kind == EXPR_NE) jcc = "jne";
                else if (e->kind == EXPR_LT) jcc = use_unsigned ? "jb" : "jl";
                else if (e->kind == EXPR_LE) jcc = use_unsigned ? "jbe" : "jle";
                else if (e->kind == EXPR_GT) jcc = use_unsigned ? "ja" : "jg";
                else if (e->kind == EXPR_GE) jcc = use_unsigned ? "jae" : "jge";
            }
            str_appendf_si(&cg->out, "  %s .L%d\n", jcc, (long long)label);
            return 1;
        }

        // General case: evaluate both sides
        cg_expr(cg, e->lhs);
        str_appendf(&cg->out, "  push %%rax\n");
        cg_expr(cg, e->rhs);
        str_appendf(&cg->out, "  pop %%rcx\n");
        str_appendf(&cg->out, "  cmp %%rax, %%rcx\n");

        const char *jcc = "je";
        if (jump_on_false) {
            if (e->kind == EXPR_EQ) jcc = "jne";
            else if (e->kind == EXPR_NE) jcc = "je";
            else if (e->kind == EXPR_LT) jcc = use_unsigned ? "jae" : "jge";
            else if (e->kind == EXPR_LE) jcc = use_unsigned ? "ja" : "jg";
            else if (e->kind == EXPR_GT) jcc = use_unsigned ? "jbe" : "jle";
            else if (e->kind == EXPR_GE) jcc = use_unsigned ? "jb" : "jl";
        } else {
            if (e->kind == EXPR_EQ) jcc = "je";
            else if (e->kind == EXPR_NE) jcc = "jne";
            else if (e->kind == EXPR_LT) jcc = use_unsigned ? "jb" : "jl";
            else if (e->kind == EXPR_LE) jcc = use_unsigned ? "jbe" : "jle";
            else if (e->kind == EXPR_GT) jcc = use_unsigned ? "ja" : "jg";
            else if (e->kind == EXPR_GE) jcc = use_unsigned ? "jae" : "jge";
        }
        str_appendf_si(&cg->out, "  %s .L%d\n", jcc, (long long)label);
        return 1;
    }

    return 0; // Not handled - use generic path
}

static void cg_stmt(CG *cg, const Stmt *s, int ret_label, const SwitchCtx *sw);

static void cg_stmt_list(CG *cg, const Stmt *first, int ret_label, const SwitchCtx *sw) {
    for (const Stmt *cur = first; cur; cur = cur->next) {
        cg_stmt(cg, cur, ret_label, sw);
    }
}

static void cg_stmt(CG *cg, const Stmt *s, int ret_label, const SwitchCtx *sw) {
    if (!s) return;
    switch (s->kind) {
        case STMT_BLOCK:
            cg_stmt_list(cg, s->block_first, ret_label, sw);
            return;
        case STMT_RETURN:
            if (cg->ret_base == BT_STRUCT && cg->ret_ptr == 0) {
                if (!s->expr) {
                    die("return value required");
                }
                int sz = cg->ret_size;
                if (sz <= 0) die("internal: bad struct return size");

                // Source address in %rax.
                (void)cg_lval_addr(cg, s->expr);
                str_appendf(&cg->out, "  mov %%rax, %%rsi\n");

                // Destination address in %rdi from sret slot.
                if (cg->sret_offset == 0) {
                    die("internal: missing sret slot");
                }
                str_appendf_i64(&cg->out, "  mov %d(%%rbp), %%rdi\n", cg->sret_offset);

                str_appendf_i64(&cg->out, "  mov $%d, %%rcx\n", sz);
                str_appendf(&cg->out, "  cld\n");
                str_appendf(&cg->out, "  rep movsb\n");

                // ABI: return sret pointer in %rax.
                str_appendf_i64(&cg->out, "  mov %d(%%rbp), %%rax\n", cg->sret_offset);
                str_appendf_i64(&cg->out, "  jmp .Lret%d\n", ret_label);
            } else {
                cg_expr(cg, s->expr);
                str_appendf_i64(&cg->out, "  jmp .Lret%d\n", ret_label);
            }
            return;
        case STMT_LABEL: {
            int lid = cg_label_id(cg, s->label);
            if (lid < 0) {
                die("internal: unknown label '%s'", s->label);
            }
            str_appendf_i64(&cg->out, ".Llbl%d:\n", lid);
            cg_stmt(cg, s->label_stmt, ret_label, sw);
            return;
        }
        case STMT_GOTO: {
            int lid = cg_label_id(cg, s->label);
            if (lid < 0) {
                die("unknown label '%s'", s->label);
            }
            str_appendf_i64(&cg->out, "  jmp .Llbl%d\n", lid);
            return;
        }
        case STMT_BREAK:
            if (cg->loop_sp <= 0) {
                die("break not within loop");
            }
            str_appendf_i64(&cg->out, "  jmp .L%d\n", cg->break_label[cg->loop_sp - 1]);
            return;
        case STMT_CONTINUE:
            if (cg->loop_sp <= 0) {
                die("continue not within loop");
            }
            str_appendf_i64(&cg->out, "  jmp .L%d\n", cg->cont_label[cg->loop_sp - 1]);
            return;
        case STMT_EXPR:
            // Skip codegen for (void)var - these are explicit discards that need no code.
            if (s->expr && s->expr->kind == EXPR_CAST &&
                s->expr->base == BT_VOID && s->expr->ptr == 0 &&
                s->expr->lhs && s->expr->lhs->kind == EXPR_VAR) {
                return;
            }
            if (s->expr) cg_expr(cg, s->expr);
            return;
        case STMT_DECL:
            if (s->decl_init) {
                cg_expr(cg, s->decl_init);
                if (s->decl_store_size == 1) {
                    str_appendf_i64(&cg->out, "  mov %%al, %d(%%rbp)\n", s->decl_offset);
                } else if (s->decl_store_size == 2) {
                    str_appendf_i64(&cg->out, "  mov %%ax, %d(%%rbp)\n", s->decl_offset);
                } else if (s->decl_store_size == 4) {
                    str_appendf_i64(&cg->out, "  mov %%eax, %d(%%rbp)\n", s->decl_offset);
                } else {
                    str_appendf_i64(&cg->out, "  mov %%rax, %d(%%rbp)\n", s->decl_offset);
                }
            }
            return;
        case STMT_IF: {
            int l_else = new_label(cg);
            int l_end = new_label(cg);
            int target = s->if_else ? l_else : l_end;
            // Try optimized comparison branch (jump on false)
            if (!cg_cond_branch(cg, s->if_cond, target, 1)) {
                // Fall back to generic path
                cg_expr(cg, s->if_cond);
                str_appendf(&cg->out, "  test %%rax, %%rax\n");
                str_appendf_i64(&cg->out, "  jz .L%d\n", target);
            }
            if (s->if_else) {
                cg_stmt(cg, s->if_then, ret_label, sw);
                str_appendf_i64(&cg->out, "  jmp .L%d\n", l_end);
                str_appendf_i64(&cg->out, ".L%d:\n", l_else);
                cg_stmt(cg, s->if_else, ret_label, sw);
                str_appendf_i64(&cg->out, ".L%d:\n", l_end);
            } else {
                cg_stmt(cg, s->if_then, ret_label, sw);
                str_appendf_i64(&cg->out, ".L%d:\n", l_end);
            }
            return;
        }
        case STMT_WHILE: {
            int l_cont = new_label(cg);
            int l_break = new_label(cg);
            if (cg->loop_sp >= (int)(sizeof(cg->break_label) / sizeof(cg->break_label[0]))) {
                die("loop nesting too deep");
            }
            cg->break_label[cg->loop_sp] = l_break;
            cg->cont_label[cg->loop_sp] = l_cont;
            cg->loop_sp++;

            str_appendf_i64(&cg->out, ".L%d:\n", l_cont);
            // Try optimized comparison branch (jump on false -> break)
            if (!cg_cond_branch(cg, s->while_cond, l_break, 1)) {
                cg_expr(cg, s->while_cond);
                str_appendf(&cg->out, "  test %%rax, %%rax\n");
                str_appendf_i64(&cg->out, "  jz .L%d\n", l_break);
            }
            cg_stmt(cg, s->while_body, ret_label, sw);
            str_appendf_i64(&cg->out, "  jmp .L%d\n", l_cont);
            str_appendf_i64(&cg->out, ".L%d:\n", l_break);

            cg->loop_sp--;
            return;
        }
        case STMT_FOR: {
            int l_begin = new_label(cg);
            int l_cont = new_label(cg);
            int l_break = new_label(cg);
            if (cg->loop_sp >= (int)(sizeof(cg->break_label) / sizeof(cg->break_label[0]))) {
                die("loop nesting too deep");
            }
            cg->break_label[cg->loop_sp] = l_break;
            cg->cont_label[cg->loop_sp] = l_cont;
            cg->loop_sp++;

            if (s->for_init) cg_stmt(cg, s->for_init, ret_label, sw);
            str_appendf_i64(&cg->out, ".L%d:\n", l_begin);
            if (s->for_cond) {
                // Try optimized comparison branch
                if (!cg_cond_branch(cg, s->for_cond, l_break, 1)) {
                    cg_expr(cg, s->for_cond);
                    str_appendf(&cg->out, "  test %%rax, %%rax\n");
                    str_appendf_i64(&cg->out, "  jz .L%d\n", l_break);
                }
            }
            cg_stmt(cg, s->for_body, ret_label, sw);

            str_appendf_i64(&cg->out, ".L%d:\n", l_cont);
            if (s->for_inc) cg_expr(cg, s->for_inc);
            str_appendf_i64(&cg->out, "  jmp .L%d\n", l_begin);
            str_appendf_i64(&cg->out, ".L%d:\n", l_break);

            cg->loop_sp--;
            return;
        }
        case STMT_SWITCH: {
            SwitchCtx ctx = {0};
            switch_collect(&ctx, s->switch_body);

            // Allocate labels for cases/default.
            for (int i = 0; i < ctx.ncases; i++) {
                ctx.case_labels[i] = new_label(cg);
            }

            int l_break = new_label(cg);
            ctx.default_label = ctx.default_node ? new_label(cg) : l_break;

            // Make break inside switch jump to switch end.
            if (cg->loop_sp >= (int)(sizeof(cg->break_label) / sizeof(cg->break_label[0]))) {
                die("loop nesting too deep");
            }
            cg->break_label[cg->loop_sp] = l_break;
            cg->cont_label[cg->loop_sp] = (cg->loop_sp > 0) ? cg->cont_label[cg->loop_sp - 1] : -1;
            cg->loop_sp++;

            // Evaluate controlling expression once.
            cg_expr(cg, s->switch_expr);

            // Dispatch: compare against each case and jump to its label.
            for (int i = 0; i < ctx.ncases; i++) {
                str_appendf_i64(&cg->out, "  cmp $%lld, %%rax\n", ctx.case_values[i]);
                str_appendf_i64(&cg->out, "  je .L%d\n", ctx.case_labels[i]);
            }
            if (ctx.default_node) {
                str_appendf_i64(&cg->out, "  jmp .L%d\n", ctx.default_label);
            } else {
                str_appendf_i64(&cg->out, "  jmp .L%d\n", l_break);
            }

            // Emit body with active switch context so case/default nodes become labels.
            cg_stmt(cg, s->switch_body, ret_label, &ctx);

            str_appendf_i64(&cg->out, ".L%d:\n", l_break);

            cg->loop_sp--;
            return;
        }
        case STMT_CASE: {
            if (!sw) die("case not within switch");
            int l = switch_case_label_for(sw, s);
            if (l < 0) die("internal: missing case label");
            str_appendf_i64(&cg->out, ".L%d:\n", l);
            return;
        }
        case STMT_DEFAULT:
            if (!sw) die("default not within switch");
            if (!sw->default_node) die("internal: missing default label");
            if (sw->default_node != s) {
                // This can happen if we accidentally passed the wrong switch context down.
                die("internal: default label mismatch");
            }
            str_appendf_i64(&cg->out, ".L%d:\n", sw->default_label);
            return;
        default:
            break;
    }
    die("internal: unhandled stmt kind");
}

void emit_x86_64_sysv_freestanding_with_start(const Program *prg, Str *out, int with_start) {
    CG cg = {0};
    cg.out = *out;
    cg.prg = prg;

    if (prg->nstrs > 0) {
        for (int i = 0; i < prg->nstrs; i++) {
            const StringLit *sl = &prg->strs[i];
            // Put each string in its own rodata subsection so --gc-sections can drop unused strings.
            str_appendf_i64(&cg.out, ".section .rodata.LC%d,\"a\",@progbits\n", i);
            str_appendf_i64(&cg.out, ".LC%d:\n", i);
            for (size_t off = 0; off < sl->len; ) {
                str_appendf(&cg.out, "  .byte ");
                size_t n = sl->len - off;
                if (n > 16) n = 16;
                for (size_t j = 0; j < n; j++) {
                    unsigned int b = (unsigned int)sl->data[off + j];
                    str_appendf_su(&cg.out, "%s%u", (j == 0) ? "" : ", ", (unsigned long long)b);
                }
                str_appendf(&cg.out, "\n");
                off += n;
            }
            str_appendf(&cg.out, "\n");
        }
    }

    if (with_start) {
        const Function *main_fn = NULL;
        const char *entry = NULL;
        for (int i = 0; i < prg->nfns; i++) {
            if (prg->fns[i].has_body && mc_strcmp(prg->fns[i].name, "main") == 0) {
                main_fn = &prg->fns[i];
                entry = prg->fns[i].name;
                break;
            }
        }
        if (!entry) {
            for (int i = 0; i < prg->nfns; i++) {
                if (prg->fns[i].has_body) {
                    entry = prg->fns[i].name;
                    break;
                }
            }
        }
        if (!entry) {
            die("internal: no function bodies to use as entry");
        }

        // Check if main is trivial (only (void)param discards + return N).
        // If so, inline it into _start to save function call overhead.
        long long trivial_ret = 0;
        int is_trivial = main_fn && fn_is_trivial_return(main_fn, &trivial_ret);

        if (is_trivial) {
            // Inline trivial main: just exit with the constant return value.
            // 60 is SYS_exit on x86_64.
            str_appendf(&cg.out,
                ".section .text._start,\"ax\",@progbits\n"
                ".globl _start\n"
                "_start:\n");
            if (trivial_ret == 0) {
                str_appendf(&cg.out, "  xor %%edi, %%edi\n");
            } else if (trivial_ret > 0 && trivial_ret <= 127) {
                str_appendf_i64(&cg.out, "  mov $%lld, %%edi\n", trivial_ret);
            } else {
                str_appendf_i64(&cg.out, "  mov $%lld, %%edi\n", trivial_ret);
            }
            str_appendf(&cg.out,
                "  mov $60, %%eax\n"
                "  syscall\n\n");
        } else {
            // Full _start that calls entry(argc, argv, envp) and does exit(ret).
            // 60 is SYS_exit on x86_64 (fits in imm8, smaller than exit_group=231).
            str_appendf_s(&cg.out,
                ".section .text._start,\"ax\",@progbits\n"
                ".globl _start\n"
                "_start:\n"
                "  xor %%ebp, %%ebp\n"
                "  mov (%%rsp), %%rdi\n"           // argc
                "  lea 8(%%rsp), %%rsi\n"          // argv
                "  lea 16(%%rsp,%%rdi,8), %%rdx\n" // envp
                "  call %s\n"
                "  mov %%eax, %%edi\n"
                "  mov $60, %%eax\n"
                "  syscall\n"
                "  hlt\n\n",
                entry);
        }
    }

    for (int i = 0; i < prg->nfns; i++) {
        const Function *fn = &prg->fns[i];
        if (!fn->has_body) continue;
        // Skip uncalled static functions - they would be gc'd by linker anyway,
        // but skipping them here reduces object file size and compile time.
        if (fn->is_static && !fn->is_called) continue;
        // Skip static inline functions that are inlineable - all calls were inlined
        if (fn->is_static && fn->is_inline && fn->inline_expr) continue;
        cg.fn_name = fn->name;
        cg.frameless = fn_can_be_frameless(fn);
        cg.nlabels = 0;
        cg_collect_labels(&cg, fn->body);

        cg.ret_base = fn->ret_base;
        cg.ret_ptr = fn->ret_ptr;
        cg.ret_struct_id = fn->ret_struct_id;
        cg.ret_size = fn->ret_size;
        cg.sret_offset = fn->sret_offset;

        // Put each function in its own text subsection so --gc-sections can drop unused helpers.
        // This is especially important for sysbox/src/sb.c where each tool only uses a subset.
        str_appendf_s(&cg.out, ".section .text.%s,\"ax\",@progbits\n", fn->name);
        if (!fn->is_static) {
            str_appendf_s(&cg.out, ".globl %s\n", fn->name);
        }
        str_appendf_s(&cg.out, "%s:\n", fn->name);
        if (!cg.frameless) {
            str_appendf(&cg.out, "  push %%rbp\n  mov %%rsp, %%rbp\n");
            if (fn->stack_size > 0) {
                str_appendf_i64(&cg.out, "  sub $%d, %%rsp\n", fn->stack_size);
            }
        }

        // Spill hidden sret pointer if present.
        if (!cg.frameless && fn->sret_offset != 0) {
            str_appendf_i64(&cg.out, "  mov %%rdi, %d(%%rbp)\n", fn->sret_offset);
        }

        // Spill incoming integer/pointer args to their stack slots (bound params).
        static const char *areg64[6] = {"%rdi", "%rsi", "%rdx", "%rcx", "%r8", "%r9"};
        static const char *areg32[6] = {"%edi", "%esi", "%edx", "%ecx", "%r8d", "%r9d"};
        static const char *areg16[6] = {"%di", "%si", "%dx", "%cx", "%r8w", "%r9w"};
        static const char *areg8[6] = {"%dil", "%sil", "%dl", "%cl", "%r8b", "%r9b"};
        for (int pi = 0; pi < 6; pi++) {
            int off = fn->param_offsets[pi];
            if (off == 0) continue;
            // If the parameter local is never referenced, skip the spill.
            // This is safe and reduces output size.
            if (stmt_count_var_uses(fn->body, off) == 0) continue;
            int sz = fn->param_sizes[pi];
            if (sz == 1) {
                str_appendf(&cg.out, "  mov %s, %d(%%rbp)\n", areg8[pi], off);
            } else if (sz == 2) {
                str_appendf(&cg.out, "  mov %s, %d(%%rbp)\n", areg16[pi], off);
            } else if (sz == 4) {
                str_appendf(&cg.out, "  mov %s, %d(%%rbp)\n", areg32[pi], off);
            } else {
                str_appendf(&cg.out, "  mov %s, %d(%%rbp)\n", areg64[pi], off);
            }
        }

        int ret_label = new_label(&cg);
        cg_stmt(&cg, fn->body, ret_label, NULL);
        // Only emit a default return value if control can fall through
        // to the end of the function body.
        if (stmt_may_fallthrough(fn->body)) {
            str_appendf(&cg.out, "  xor %%eax, %%eax\n");
        }
        str_appendf_i64(&cg.out, ".Lret%d:\n", ret_label);
        if (cg.frameless) {
            str_appendf(&cg.out, "  ret\n\n");
        } else {
            str_appendf(&cg.out, "  leave\n  ret\n\n");
        }
    }

    *out = cg.out;
}

void emit_x86_64_sysv_freestanding(const Program *prg, Str *out) {
    emit_x86_64_sysv_freestanding_with_start(prg, out, 1);
}

