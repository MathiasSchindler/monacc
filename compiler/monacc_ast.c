#include "monacc.h"

#ifdef SELFHOST
static void sb_write_cstr(int fd, const char *s) {
    if (!s) return;
    xwrite_best_effort(fd, s, mc_strlen(s));
}

static void sb_write_u64_dec(int fd, unsigned long long v) {
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
    xwrite_best_effort(fd, tmp, (mc_usize)n);
}

static void sb_write_bytes(int fd, const char *s, mc_usize n) {
    if (!s || n == 0) return;
    xwrite_best_effort(fd, s, n);
}
#endif

int local_add_fixed(Locals *ls, const char *nm, mc_usize nm_len, BaseType base, int ptr, int struct_id, int is_unsigned, int lval_size,
                           int alloc_size, int array_stride, int offset) {
    if (ls->nlocals >= (int)(sizeof(ls->locals) / sizeof(ls->locals[0]))) {
#ifdef SELFHOST
        sb_write_cstr(2, "SELFHOST: too many locals (fixed) n=");
        sb_write_u64_dec(2, (unsigned long long)ls->nlocals);
        sb_write_cstr(2, " cap=");
        sb_write_u64_dec(2, (unsigned long long)(sizeof(ls->locals) / sizeof(ls->locals[0])));
        sb_write_cstr(2, " name='");
        sb_write_bytes(2, nm, nm_len);
        sb_write_cstr(2, "'\n");
#endif
        die("too many locals");
    }
    if (nm_len == 0 || nm_len >= sizeof(ls->locals[0].name)) {
        die("local name too long");
    }
    Local *l = &ls->locals[ls->nlocals++];
    mc_memcpy(l->name, nm, nm_len);
    l->name[nm_len] = 0;
    l->offset = offset;
    l->global_id = -1;
    l->base = base;
    l->ptr = ptr;
    l->struct_id = struct_id;
    l->is_unsigned = is_unsigned;
    l->size = lval_size;
    l->alloc_size = alloc_size;
    l->array_stride = array_stride;
    return l->offset;
}

Expr *new_expr(ExprKind k) {
    Expr *e = (Expr *)monacc_calloc(1, sizeof(*e));
    if (!e) die("oom");
    e->kind = k;
    return e;
}

// Clone an expression tree, substituting parameter references with argument expressions.
// param_offsets: array of parameter stack offsets (from Function.param_offsets)
// nparams: number of parameters
// args: array of argument expressions to substitute (same order as params)
// When an EXPR_VAR with var_offset matching a param_offset is found, it's replaced
// with a clone of the corresponding argument expression.
Expr *expr_clone_with_subst(const Expr *e, const int *param_offsets, int nparams, Expr **args) {
    if (!e) return NULL;

    // Check if this is a parameter reference that should be substituted
    if (e->kind == EXPR_VAR) {
        for (int i = 0; i < nparams; i++) {
            if (param_offsets[i] != 0 && e->var_offset == param_offsets[i]) {
                // Substitute with a clone of the argument
                return expr_clone_with_subst(args[i], NULL, 0, NULL);
            }
        }
    }

    // Clone the expression
    Expr *c = new_expr(e->kind);
    *c = *e;  // Copy all fields

    // Recursively clone children
    c->lhs = expr_clone_with_subst(e->lhs, param_offsets, nparams, args);
    c->rhs = expr_clone_with_subst(e->rhs, param_offsets, nparams, args);
    c->third = expr_clone_with_subst(e->third, param_offsets, nparams, args);

    // Clone argument array if present
    if (e->args && e->nargs > 0) {
        c->args = (Expr **)monacc_calloc((mc_usize)e->nargs, sizeof(Expr *));
        if (!c->args) die("oom");
        for (int i = 0; i < e->nargs; i++) {
            c->args[i] = expr_clone_with_subst(e->args[i], param_offsets, nparams, args);
        }
    }

    // Clone inits array if present (for compound literals)
    if (e->inits && e->ninits > 0) {
        c->inits = (InitEnt *)monacc_calloc((mc_usize)e->ninits, sizeof(InitEnt));
        if (!c->inits) die("oom");
        for (int i = 0; i < e->ninits; i++) {
            c->inits[i] = e->inits[i];
            c->inits[i].value = expr_clone_with_subst(e->inits[i].value, param_offsets, nparams, args);
        }
    }

    return c;
}

Stmt *new_stmt(StmtKind k) {
    Stmt *s = (Stmt *)monacc_calloc(1, sizeof(*s));
    if (!s) die("oom");
    s->kind = k;
    return s;
}

const Local *local_find(const Locals *ls, const char *nm, mc_usize nm_len) {
    for (int i = ls->nlocals - 1; i >= 0; i--) {
        const Local *l = &ls->locals[i];
        if (mc_strlen(l->name) == nm_len && mc_memcmp(l->name, nm, nm_len) == 0) {
            return l;
        }
    }
    return NULL;
}

int local_add(Locals *ls, const char *nm, mc_usize nm_len, BaseType base, int ptr, int struct_id, int is_unsigned, int lval_size,
                     int alloc_size, int array_stride) {
    if (ls->nlocals >= (int)(sizeof(ls->locals) / sizeof(ls->locals[0]))) {
#ifdef SELFHOST
        sb_write_cstr(2, "SELFHOST: too many locals n=");
        sb_write_u64_dec(2, (unsigned long long)ls->nlocals);
        sb_write_cstr(2, " cap=");
        sb_write_u64_dec(2, (unsigned long long)(sizeof(ls->locals) / sizeof(ls->locals[0])));
        sb_write_cstr(2, " next_offset=");
        sb_write_u64_dec(2, (unsigned long long)ls->next_offset);
        sb_write_cstr(2, " name='");
        sb_write_bytes(2, nm, nm_len);
        sb_write_cstr(2, "'\n");
#endif
        die("too many locals");
    }
    if (nm_len == 0 || nm_len >= sizeof(ls->locals[0].name)) {
        die("local name too long");
    }
    // Simple stack allocation with 8-byte alignment.
    if (alloc_size < 1) alloc_size = 1;
    int alloc = (alloc_size + 7) & ~7;
    if (alloc < 8) alloc = 8;
    ls->next_offset -= alloc;
    Local *l = &ls->locals[ls->nlocals++];
    mc_memcpy(l->name, nm, nm_len);
    l->name[nm_len] = 0;
    l->offset = ls->next_offset;
    l->global_id = -1;
    l->base = base;
    l->ptr = ptr;
    l->struct_id = struct_id;
    l->is_unsigned = is_unsigned;
    l->size = lval_size;
    l->alloc_size = alloc_size;
    l->array_stride = array_stride;
    return l->offset;
}

int local_add_globalref(Locals *ls, const char *nm, mc_usize nm_len, int global_id, BaseType base, int ptr, int struct_id, int is_unsigned, int lval_size,
                        int alloc_size, int array_stride) {
    if (ls->nlocals >= (int)(sizeof(ls->locals) / sizeof(ls->locals[0]))) {
        die("too many locals");
    }
    if (nm_len == 0 || nm_len >= sizeof(ls->locals[0].name)) {
        die("local name too long");
    }
    Local *l = &ls->locals[ls->nlocals++];
    mc_memcpy(l->name, nm, nm_len);
    l->name[nm_len] = 0;
    l->offset = 0;
    l->global_id = global_id;
    l->base = base;
    l->ptr = ptr;
    l->struct_id = struct_id;
    l->is_unsigned = is_unsigned;
    l->size = lval_size;
    l->alloc_size = alloc_size;
    l->array_stride = array_stride;
    return 0;
}

// Check if a function is a candidate for inlining:
// - Must be static inline
// - Body must be a block containing exactly one statement
// - That statement must be STMT_RETURN with an expression
// If inlineable, returns the return expression; otherwise returns NULL.
static Expr *fn_get_inline_expr(const Function *fn) {
    if (!fn->is_static || !fn->is_inline || !fn->has_body || !fn->body) {
        return NULL;
    }
    // Body should be a STMT_BLOCK
    Stmt *body = fn->body;
    if (body->kind != STMT_BLOCK) {
        return NULL;
    }
    // The block should contain exactly one statement
    Stmt *first = body->block_first;
    if (!first || first->next != NULL) {
        return NULL;
    }
    // That statement should be STMT_RETURN with an expression
    if (first->kind != STMT_RETURN || !first->expr) {
        return NULL;
    }
    return first->expr;
}

void program_add_fn(Program *p, const Function *fn) {
    // Check if function is inlineable and set inline_expr
    Expr *ie = fn_get_inline_expr(fn);

    // Replace if present (prototype or prior definition).
    for (int i = 0; i < p->nfns; i++) {
        Function *cur = &p->fns[i];
        if (mc_strcmp(cur->name, fn->name) == 0) {
            // Prefer a definition over a prototype.
            if (cur->has_body && !fn->has_body) {
                return;
            }
            // Preserve is_called flag from earlier entry (forward declaration may have been called).
            int was_called = cur->is_called;
            *cur = *fn;
            cur->is_called |= was_called;
            cur->inline_expr = ie;
            return;
        }
    }
    if (p->nfns + 1 > p->cap) {
        int ncap = p->cap ? p->cap * 2 : 16;
        Function *nf = (Function *)monacc_realloc(p->fns, (mc_usize)ncap * sizeof(*nf));
        if (!nf) die("oom");
        p->fns = nf;
        p->cap = ncap;
    }
    p->fns[p->nfns] = *fn;
    p->fns[p->nfns].inline_expr = ie;
    p->nfns++;
}

const Function *program_find_fn(const Program *p, const char *name, mc_usize name_len) {
    if (!p || !name || name_len == 0) return NULL;
    if (name_len >= 128) return NULL;
    char buf[128];
    mc_memcpy(buf, name, name_len);
    buf[name_len] = 0;
    for (int i = p->nfns - 1; i >= 0; i--) {
        const Function *fn = &p->fns[i];
        if (mc_strcmp(fn->name, buf) == 0) return fn;
    }
    return NULL;
}

void program_mark_fn_called(Program *p, const char *name, mc_usize name_len) {
    if (!p || !name || name_len == 0) return;
    if (name_len >= 128) return;
    char buf[128];
    mc_memcpy(buf, name, name_len);
    buf[name_len] = 0;
    for (int i = p->nfns - 1; i >= 0; i--) {
        Function *fn = &p->fns[i];
        if (mc_strcmp(fn->name, buf) == 0) {
            fn->is_called = 1;
            return;
        }
    }
}

const Typedef *program_find_typedef(const Program *p, const char *name, mc_usize name_len) {
    if (!p || !name || name_len == 0) return NULL;
    for (int i = p->ntypedefs - 1; i >= 0; i--) {
        const Typedef *td = &p->typedefs[i];
        if (mc_strlen(td->name) == name_len && mc_memcmp(td->name, name, name_len) == 0) {
            return td;
        }
    }
    return NULL;
}

void program_add_typedef(Program *p, const char *name, mc_usize name_len, BaseType base, int ptr, int struct_id, int is_unsigned) {
    if (!p) die("internal: no program context");
    if (!name || name_len == 0 || name_len >= sizeof(p->typedefs[0].name)) {
        die("typedef name too long");
    }
    // Replace if present.
    for (int i = 0; i < p->ntypedefs; i++) {
        Typedef *td = &p->typedefs[i];
        if (mc_strlen(td->name) == name_len && mc_memcmp(td->name, name, name_len) == 0) {
            td->base = base;
            td->ptr = ptr;
            td->struct_id = struct_id;
            td->is_unsigned = is_unsigned;
            return;
        }
    }
    if (p->ntypedefs + 1 > p->typedefcap) {
        int ncap = p->typedefcap ? p->typedefcap * 2 : 64;
        Typedef *nt = (Typedef *)monacc_realloc(p->typedefs, (mc_usize)ncap * sizeof(*nt));
        if (!nt) die("oom");
        p->typedefs = nt;
        p->typedefcap = ncap;
    }
    Typedef *td = &p->typedefs[p->ntypedefs++];
    mc_memcpy(td->name, name, name_len);
    td->name[name_len] = 0;
    td->base = base;
    td->ptr = ptr;
    td->struct_id = struct_id;
    td->is_unsigned = is_unsigned;
}

const ConstDef *program_find_const(const Program *p, const char *name, mc_usize name_len) {
    if (!p || !name || name_len == 0) return NULL;
    for (int i = p->nconsts - 1; i >= 0; i--) {
        const ConstDef *c = &p->consts[i];
        if (mc_strlen(c->name) == name_len && mc_memcmp(c->name, name, name_len) == 0) {
            return c;
        }
    }
    return NULL;
}

void program_add_const(Program *p, const char *name, mc_usize name_len, long long value) {
    if (!p) die("internal: no program context");
    if (!name || name_len == 0 || name_len >= sizeof(p->consts[0].name)) {
        die("const name too long");
    }
    // Replace if present.
    for (int i = 0; i < p->nconsts; i++) {
        ConstDef *c = &p->consts[i];
        if (mc_strlen(c->name) == name_len && mc_memcmp(c->name, name, name_len) == 0) {
            c->value = value;
            return;
        }
    }
    if (p->nconsts + 1 > p->constcap) {
        int ncap = p->constcap ? p->constcap * 2 : 128;
        ConstDef *nc = (ConstDef *)monacc_realloc(p->consts, (mc_usize)ncap * sizeof(*nc));
        if (!nc) die("oom");
        p->consts = nc;
        p->constcap = ncap;
    }
    ConstDef *c = &p->consts[p->nconsts++];
    mc_memcpy(c->name, name, name_len);
    c->name[name_len] = 0;
    c->value = value;
}

int program_add_str(Program *p, const unsigned char *data, mc_usize len) {
    if (!p) die("internal: no program context");
    if (p->nstrs + 1 > p->strcap) {
        int ncap = p->strcap ? p->strcap * 2 : 32;
        StringLit *ns = (StringLit *)monacc_realloc(p->strs, (mc_usize)ncap * sizeof(*ns));
        if (!ns) die("oom");
        p->strs = ns;
        p->strcap = ncap;
    }
    unsigned char *cpy = (unsigned char *)monacc_malloc(len);
    if (!cpy) die("oom");
    mc_memcpy(cpy, data, len);
    p->strs[p->nstrs].data = cpy;
    p->strs[p->nstrs].len = len;
    return p->nstrs++;
}

int type_sizeof(const Program *prg, BaseType base, int ptr, int struct_id);

static int program_find_struct_id(const Program *p, const char *name, mc_usize name_len) {
    if (!p) return -1;
    for (int i = 0; i < p->nstructs; i++) {
        const StructDef *sd = &p->structs[i];
        if (mc_strlen(sd->name) == name_len && mc_memcmp(sd->name, name, name_len) == 0) {
            return i;
        }
    }
    return -1;
}

int program_get_or_add_struct(Program *p, const char *name, mc_usize name_len) {
    if (!p) die("internal: no program context");
    int id = program_find_struct_id(p, name, name_len);
    if (id >= 0) return id;
    if (p->nstructs + 1 > p->structcap) {
        int ncap = p->structcap ? p->structcap * 2 : 32;
        StructDef *ns = (StructDef *)monacc_realloc(p->structs, (mc_usize)ncap * sizeof(*ns));
        if (!ns) die("oom");
        p->structs = ns;
        p->structcap = ncap;
    }
    StructDef *sd = &p->structs[p->nstructs];
    mc_memset(sd, 0, sizeof(*sd));
    if (name_len == 0 || name_len >= sizeof(sd->name)) {
        die("struct name too long");
    }
    mc_memcpy(sd->name, name, name_len);
    sd->name[name_len] = 0;
    sd->align = 1;
    sd->size = 0;
    return p->nstructs++;
}

int program_add_anon_struct(Program *p) {
    char buf[64];
    // Ensure unique name within this compilation unit.
    mc_snprint_cstr_u64_cstr(buf, sizeof(buf), "__anon_struct_", (mc_u64)p->nstructs, "");
    return program_get_or_add_struct(p, buf, mc_strlen(buf));
}

const StructMember *struct_find_member(const Program *prg, int struct_id, const char *name, mc_usize name_len) {
    if (!prg || struct_id < 0 || struct_id >= prg->nstructs) return NULL;
    const StructDef *sd = &prg->structs[struct_id];
    for (int i = 0; i < sd->nmembers; i++) {
        const StructMember *m = &sd->members[i];
        if (mc_strlen(m->name) == name_len && mc_memcmp(m->name, name, name_len) == 0) {
            return m;
        }
    }
    return NULL;
}

int align_up(int x, int a) {
    if (a <= 1) return x;
    int r = x % a;
    return r ? (x + (a - r)) : x;
}

int type_alignof(const Program *prg, BaseType base, int ptr, int struct_id) {
    if (ptr > 0) return 8;
    if (base == BT_CHAR) return 1;
    if (base == BT_SHORT) return 2;
    if (base == BT_INT) return 4;
    if (base == BT_LONG) return 8;
    if (base == BT_FLOAT) return 4;
    if (base == BT_VOID) return 1;
    if (base == BT_STRUCT) {
        if (!prg || struct_id < 0 || struct_id >= prg->nstructs) return 8;
        int a = prg->structs[struct_id].align;
        return a > 0 ? a : 8;
    }
    return 8;
}

int type_sizeof(const Program *prg, BaseType base, int ptr, int struct_id) {
    if (ptr > 0) return 8;
    if (base == BT_CHAR) return 1;
    if (base == BT_SHORT) return 2;
    if (base == BT_INT) return 4;
    if (base == BT_LONG) return 8;
    if (base == BT_FLOAT) return 4;
    if (base == BT_VOID) {
        die("invalid sizeof(void)");
    }
    if (base == BT_STRUCT) {
        if (!prg || struct_id < 0 || struct_id >= prg->nstructs) {
            die("unknown struct size");
        }
        int sz = prg->structs[struct_id].size;
        if (sz <= 0) {
            die("incomplete struct size");
        }
        return sz;
    }
    return 8;
}

void program_add_global(Program *p, const GlobalVar *gv) {
    // Check if already present
    for (int i = 0; i < p->nglobals; i++) {
        if (mc_strcmp(p->globals[i].name, gv->name) == 0) {
            // Prefer a real definition over an extern declaration.
            if (p->globals[i].is_extern && !gv->is_extern) {
                p->globals[i] = *gv;
            }
            // Otherwise keep the existing entry (definition beats extern; first wins for extern-only).
            return;
        }
    }
    if (p->nglobals + 1 > p->globalcap) {
        int ncap = p->globalcap ? p->globalcap * 2 : 16;
        GlobalVar *ng = (GlobalVar *)monacc_realloc(p->globals, (mc_usize)ncap * sizeof(*ng));
        if (!ng) die("oom");
        p->globals = ng;
        p->globalcap = ncap;
    }
    p->globals[p->nglobals] = *gv;
    p->nglobals++;
}

int program_find_global(const Program *p, const char *name, mc_usize name_len) {
    if (!p || !name || name_len == 0) return -1;
    if (name_len >= 128) return -1;
    for (int i = 0; i < p->nglobals; i++) {
        if (mc_strncmp(p->globals[i].name, name, name_len) == 0 &&
            p->globals[i].name[name_len] == 0) {
            return i;
        }
    }
    return -1;
}
