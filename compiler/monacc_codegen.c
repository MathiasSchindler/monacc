#include "monacc.h"

// ===== Codegen =====

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
        case STMT_ASM:
            // Count uses in asm operand expressions
            for (int i = 0; i < s->asm_noutputs; i++) {
                n += expr_count_var_uses(s->asm_outputs[i].expr, off);
            }
            for (int i = 0; i < s->asm_ninputs; i++) {
                n += expr_count_var_uses(s->asm_inputs[i].expr, off);
            }
            return n;
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
    if (e->kind == EXPR_GLOBAL) {
        const GlobalVar *gv = &cg->prg->globals[e->global_id];
        str_appendf_s(&cg->out, "  lea %s(%%rip), %%rax\n", gv->name);
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
        int scale = (e->ptr_scale > 0) ? e->ptr_scale : 8;

        // Optimize constant index: avoid push/pop, use immediate offset
        if (e->rhs && e->rhs->kind == EXPR_NUM) {
            long long idx = e->rhs->num;
            long long offset = idx * (long long)scale;
            cg_expr(cg, e->lhs);
            if (offset == 0) {
                // Index 0: base address is already correct
            } else if (offset >= -2147483648LL && offset <= 2147483647LL) {
                // Fits in imm32
                if (offset == 1) {
                    str_appendf(&cg->out, "  inc %%rax\n");
                } else if (offset == -1) {
                    str_appendf(&cg->out, "  dec %%rax\n");
                } else {
                    str_appendf_i64(&cg->out, "  add $%lld, %%rax\n", offset);
                }
            } else {
                // Large offset: load into rcx and add
                str_appendf_i64(&cg->out, "  mov $%lld, %%rcx\n", offset);
                str_appendf(&cg->out, "  add %%rcx, %%rax\n");
            }
            return e->lval_size ? e->lval_size : 8;
        }

        // General case: push/pop for non-constant index
        cg_expr(cg, e->lhs);
        str_appendf(&cg->out, "  push %%rax\n");
        cg_expr(cg, e->rhs);
        str_appendf(&cg->out, "  pop %%rcx\n");
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

// Helper: emit code for function calls (EXPR_CALL).
static void cg_call(CG *cg, const Expr *e) {
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
}

// Helper: emit code for struct-returning calls (EXPR_SRET_CALL).
static void cg_sret_call(CG *cg, const Expr *e) {
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
}

// Helper: emit code for binary operations (arithmetic, bitwise, comparisons).
// Returns after emitting code - caller should return immediately after calling this.
static void cg_binop(CG *cg, const Expr *e) {
    // Peepholes for constant LHS: avoid push/pop and generate shorter immediates.
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

    // Peepholes for constant RHS.
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
    // General case: evaluate both operands, push/pop to get them in registers.
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
    die("internal: unhandled binop kind");
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
        case EXPR_GLOBAL: {
            const GlobalVar *gv = &cg->prg->globals[e->global_id];
            // For arrays, return address; for scalars, load value
            if (e->lval_size == 0) {
                // Array decay: return address
                str_appendf_s(&cg->out, "  lea %s(%%rip), %%rax\n", gv->name);
            } else if (e->base == BT_STRUCT && e->ptr == 0 && e->lval_size > 8) {
                str_appendf_s(&cg->out, "  lea %s(%%rip), %%rax\n", gv->name);
            } else if (e->lval_size == 1) {
                str_appendf_s(&cg->out, "  movzb %s(%%rip), %%eax\n", gv->name);
            } else if (e->lval_size == 2) {
                if (e->is_unsigned) {
                    str_appendf_s(&cg->out, "  movzw %s(%%rip), %%eax\n", gv->name);
                } else {
                    str_appendf_s(&cg->out, "  movswq %s(%%rip), %%rax\n", gv->name);
                }
            } else if (e->lval_size == 4) {
                if (e->is_unsigned) {
                    str_appendf_s(&cg->out, "  mov %s(%%rip), %%eax\n", gv->name);
                } else {
                    str_appendf_s(&cg->out, "  movslq %s(%%rip), %%rax\n", gv->name);
                }
            } else {
                str_appendf_s(&cg->out, "  mov %s(%%rip), %%rax\n", gv->name);
            }
            return;
        }
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
        case EXPR_CALL:
            cg_call(cg, e);
            return;
        case EXPR_SRET_CALL:
            cg_sret_call(cg, e);
            return;
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
        case EXPR_GE:
            cg_binop(cg, e);
            return;
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

// ===== Inline Assembly Code Generation =====
//
// Constraint mapping for x86_64:
//   "a" -> %rax/%eax/%ax/%al
//   "b" -> %rbx/%ebx/%bx/%bl
//   "c" -> %rcx/%ecx/%cx/%cl
//   "d" -> %rdx/%edx/%dx/%dl
//   "D" -> %rdi/%edi/%di/%dil
//   "S" -> %rsi/%esi/%si/%sil
//   "r" -> any GPR (we pick from available)
//   "m" -> memory operand
//   "i"/"n" -> immediate (integer constant)
//   "0"-"9" -> same location as operand N

typedef struct {
    const char *r64;
    const char *r32;
    const char *r16;
    const char *r8;
} RegSet;

static const RegSet asm_regs[] = {
    {"%rax", "%eax", "%ax", "%al"},
    {"%rbx", "%ebx", "%bx", "%bl"},
    {"%rcx", "%ecx", "%cx", "%cl"},
    {"%rdx", "%edx", "%dx", "%dl"},
    {"%rsi", "%esi", "%si", "%sil"},
    {"%rdi", "%edi", "%di", "%dil"},
    {"%r8", "%r8d", "%r8w", "%r8b"},
    {"%r9", "%r9d", "%r9w", "%r9b"},
    {"%r10", "%r10d", "%r10w", "%r10b"},
    {"%r11", "%r11d", "%r11w", "%r11b"},
    {"%r12", "%r12d", "%r12w", "%r12b"},
    {"%r13", "%r13d", "%r13w", "%r13b"},
    {"%r14", "%r14d", "%r14w", "%r14b"},
    {"%r15", "%r15d", "%r15w", "%r15b"},
};

// Map constraint character to register index, or -1 for non-register constraints
static int asm_constraint_to_reg(char c) {
    switch (c) {
        case 'a': return 0;  // rax
        case 'b': return 1;  // rbx
        case 'c': return 2;  // rcx
        case 'd': return 3;  // rdx
        case 'S': return 4;  // rsi
        case 'D': return 5;  // rdi
        default: return -1;
    }
}

// Operand binding for asm codegen
typedef struct {
    int kind;           // 0=reg, 1=mem, 2=imm
    int reg_idx;        // for kind=0: index into asm_regs
    int mem_offset;     // for kind=1: rbp-relative offset
    long long imm_val;  // for kind=2: immediate value
    int is_output;
    int is_inout;
    int size;           // 1=byte, 2=word, 4=dword, 8=qword
    const Expr *expr;
} AsmBinding;

// Get the size of an expression's type in bytes
static int expr_type_size(const Expr *e) {
    if (!e) return 8;
    // For pointer types, always 8 bytes
    if (e->ptr > 0) return 8;
    switch (e->base) {
        case BT_CHAR: return 1;
        case BT_SHORT: return 2;
        case BT_INT: return 4;
        case BT_LONG: return 8;
        case BT_VOID: return 0;
        default: return 8;
    }
}

// Get the appropriate register name for a given size
static const char *asm_reg_for_size(int reg_idx, int size) {
    if (reg_idx < 0 || reg_idx >= 14) return "%rax";
    switch (size) {
        case 1: return asm_regs[reg_idx].r8;
        case 2: return asm_regs[reg_idx].r16;
        case 4: return asm_regs[reg_idx].r32;
        default: return asm_regs[reg_idx].r64;
    }
}

static void cg_asm_stmt(CG *cg, const Stmt *s) {
    // Allocate bindings for all operands
    int total_ops = s->asm_noutputs + s->asm_ninputs;
    AsmBinding *bindings = NULL;
    if (total_ops > 0) {
        bindings = (AsmBinding *)monacc_calloc((size_t)total_ops, sizeof(AsmBinding));
    }

    // Track which registers are used
    int reg_used[16] = {0};
    int next_scratch = 6; // Start from r8 for "r" constraints

    // Process outputs first (they determine where values go)
    for (int i = 0; i < s->asm_noutputs; i++) {
        const AsmOperand *op = &s->asm_outputs[i];
        AsmBinding *b = &bindings[i];
        b->is_output = 1;
        b->is_inout = op->is_inout;
        b->expr = op->expr;
        b->size = expr_type_size(op->expr);

        // Skip '=' or '+' prefix
        const char *cstr = op->constraint;
        if (*cstr == '=' || *cstr == '+') cstr++;

        // Check for specific register constraint
        int ridx = asm_constraint_to_reg(*cstr);
        if (ridx >= 0) {
            b->kind = 0;
            b->reg_idx = ridx;
            reg_used[ridx] = 1;
        } else if (*cstr == 'r') {
            // Allocate a scratch register
            while (next_scratch < 14 && reg_used[next_scratch]) next_scratch++;
            b->kind = 0;
            b->reg_idx = next_scratch;
            reg_used[next_scratch] = 1;
            next_scratch++;
        } else if (*cstr == 'm') {
            b->kind = 1;
            // For memory operand, get the lvalue address offset
            if (b->expr && b->expr->kind == EXPR_VAR) {
                b->mem_offset = b->expr->var_offset;
            } else {
                die("asm: 'm' constraint requires a simple variable");
            }
        } else {
            die("asm: unsupported output constraint '%s'", op->constraint);
        }
    }

    // Process inputs
    for (int i = 0; i < s->asm_ninputs; i++) {
        const AsmOperand *op = &s->asm_inputs[i];
        AsmBinding *b = &bindings[s->asm_noutputs + i];
        b->is_output = 0;
        b->expr = op->expr;
        b->size = expr_type_size(op->expr);

        const char *cstr = op->constraint;

        // Check for matching constraint (0-9)
        if (*cstr >= '0' && *cstr <= '9') {
            int match = *cstr - '0';
            if (match >= s->asm_noutputs) {
                die("asm: matching constraint '%c' out of range", *cstr);
            }
            b->kind = bindings[match].kind;
            b->reg_idx = bindings[match].reg_idx;
            b->mem_offset = bindings[match].mem_offset;
            b->size = bindings[match].size;
            continue;
        }

        // Check for "Nd" (short for dx, used in port I/O)
        // "N" means 8-bit unsigned constant, "d" means %edx
        // Together "Nd" is commonly used for port numbers (16-bit in %dx)
        if (cstr[0] == 'N' && cstr[1] == 'd') {
            b->kind = 0;
            b->reg_idx = 3; // rdx
            b->size = 2;    // port numbers are 16-bit
            reg_used[3] = 1;
            continue;
        }

        int ridx = asm_constraint_to_reg(*cstr);
        if (ridx >= 0) {
            b->kind = 0;
            b->reg_idx = ridx;
            reg_used[ridx] = 1;
        } else if (*cstr == 'r') {
            // Allocate a scratch register
            while (next_scratch < 14 && reg_used[next_scratch]) next_scratch++;
            b->kind = 0;
            b->reg_idx = next_scratch;
            reg_used[next_scratch] = 1;
            next_scratch++;
        } else if (*cstr == 'm') {
            b->kind = 1;
            if (b->expr && b->expr->kind == EXPR_VAR) {
                b->mem_offset = b->expr->var_offset;
            } else {
                die("asm: 'm' constraint requires a simple variable");
            }
        } else if (*cstr == 'i' || *cstr == 'n') {
            b->kind = 2;
            if (b->expr && b->expr->kind == EXPR_NUM) {
                b->imm_val = b->expr->num;
            } else {
                die("asm: 'i'/'n' constraint requires a constant");
            }
        } else {
            die("asm: unsupported input constraint '%s'", op->constraint);
        }
    }

    // Load input values into their designated registers.
    // Strategy: cg_expr always returns in rax, so we need to be careful about
    // register conflicts. We evaluate all non-constant inputs and push to stack,
    // then pop into target registers. Constants are loaded directly at the end.
    // rax-targeted inputs are handled last to avoid being clobbered.

    // First pass: evaluate non-constant, non-rax inputs and push to stack
    for (int i = 0; i < s->asm_ninputs; i++) {
        AsmBinding *b = &bindings[s->asm_noutputs + i];
        if (b->kind == 0 && b->reg_idx != 0) {
            // Not rax - need to evaluate and save
            if (b->expr->kind != EXPR_NUM) {
                cg_expr(cg, b->expr);
                str_appendf(&cg->out, "  push %%rax\n");
            }
        }
    }

    // Second pass: pop into target registers (reverse order)
    for (int i = s->asm_ninputs - 1; i >= 0; i--) {
        AsmBinding *b = &bindings[s->asm_noutputs + i];
        if (b->kind == 0 && b->reg_idx != 0) {
            if (b->expr->kind != EXPR_NUM) {
                str_appendf_s(&cg->out, "  pop %s\n", asm_regs[b->reg_idx].r64);
            } else {
                // Load constant directly
                str_appendf_is(&cg->out, "  mov $%lld, %s\n", b->expr->num, asm_regs[b->reg_idx].r64);
            }
        }
    }

    // Third pass: load rax-targeted inputs last (so they don't get clobbered)
    for (int i = 0; i < s->asm_ninputs; i++) {
        AsmBinding *b = &bindings[s->asm_noutputs + i];
        if (b->kind == 0 && b->reg_idx == 0) {
            cg_expr(cg, b->expr);
        }
    }

    // For input-output operands (+), also load the initial value
    for (int i = 0; i < s->asm_noutputs; i++) {
        AsmBinding *b = &bindings[i];
        if (b->is_inout && b->kind == 0) {
            cg_expr(cg, b->expr);
            if (b->reg_idx != 0) {
                str_appendf_s(&cg->out, "  mov %%rax, %s\n", asm_regs[b->reg_idx].r64);
            }
        }
    }

    // Emit the assembly template with operand substitution
    // Template uses %0, %1, ... or %%reg for literal %
    const char *tmpl = s->asm_template;
    str_append_bytes(&cg->out, "  ", 2);
    while (*tmpl) {
        if (*tmpl == '%') {
            tmpl++;
            if (*tmpl == '%') {
                // Literal %
                str_append_bytes(&cg->out, "%", 1);
                tmpl++;
            } else if (*tmpl >= '0' && *tmpl <= '9') {
                // Operand reference
                int opnum = 0;
                while (*tmpl >= '0' && *tmpl <= '9') {
                    opnum = opnum * 10 + (*tmpl - '0');
                    tmpl++;
                }
                if (opnum >= total_ops) {
                    die("asm: operand %%%d out of range", opnum);
                }
                AsmBinding *b = &bindings[opnum];
                if (b->kind == 0) {
                    const char *regname = asm_reg_for_size(b->reg_idx, b->size);
                    str_append_bytes(&cg->out, regname, mc_strlen(regname));
                } else if (b->kind == 1) {
                    char buf[32];
                    int n = mc_snprintf(buf, sizeof(buf), "%d(%%rbp)", b->mem_offset);
                    str_append_bytes(&cg->out, buf, (size_t)n);
                } else if (b->kind == 2) {
                    char buf[32];
                    int n = mc_snprintf(buf, sizeof(buf), "$%lld", b->imm_val);
                    str_append_bytes(&cg->out, buf, (size_t)n);
                }
            } else if (*tmpl == 'w') {
                // %w0 = 16-bit version
                tmpl++;
                if (*tmpl >= '0' && *tmpl <= '9') {
                    int opnum = *tmpl - '0';
                    tmpl++;
                    if (opnum < total_ops && bindings[opnum].kind == 0) {
                        str_append_bytes(&cg->out, asm_regs[bindings[opnum].reg_idx].r16,
                                        mc_strlen(asm_regs[bindings[opnum].reg_idx].r16));
                    }
                }
            } else if (*tmpl == 'b') {
                // %b0 = 8-bit version
                tmpl++;
                if (*tmpl >= '0' && *tmpl <= '9') {
                    int opnum = *tmpl - '0';
                    tmpl++;
                    if (opnum < total_ops && bindings[opnum].kind == 0) {
                        str_append_bytes(&cg->out, asm_regs[bindings[opnum].reg_idx].r8,
                                        mc_strlen(asm_regs[bindings[opnum].reg_idx].r8));
                    }
                }
            } else {
                // Unknown modifier or register name, pass through
                str_append_bytes(&cg->out, "%", 1);
            }
        } else if (*tmpl == '\\' && tmpl[1] == 'n') {
            // \n in template -> newline with indentation
            str_append_bytes(&cg->out, "\n  ", 3);
            tmpl += 2;
        } else if (*tmpl == '\n') {
            // Actual newline in template
            str_append_bytes(&cg->out, "\n  ", 3);
            tmpl++;
        } else {
            str_append_bytes(&cg->out, tmpl, 1);
            tmpl++;
        }
    }
    str_append_bytes(&cg->out, "\n", 1);

    // Store output values back to their destinations
    for (int i = 0; i < s->asm_noutputs; i++) {
        AsmBinding *b = &bindings[i];
        if (b->kind == 0 && b->expr) {
            // Move result from register to lvalue
            if (b->expr->kind == EXPR_VAR) {
                int off = b->expr->var_offset;
                int sz = b->expr->lval_size;
                const char *src;
                if (sz == 1) src = asm_regs[b->reg_idx].r8;
                else if (sz == 2) src = asm_regs[b->reg_idx].r16;
                else if (sz == 4) src = asm_regs[b->reg_idx].r32;
                else src = asm_regs[b->reg_idx].r64;
                str_appendf_si(&cg->out, "  mov %s, %d(%%rbp)\n", src, (long long)off);
            } else {
                // For non-variable lvalues, evaluate address and store
                // For now, just put result in rax
                if (b->reg_idx != 0) {
                    str_appendf_s(&cg->out, "  mov %s, %%rax\n", asm_regs[b->reg_idx].r64);
                }
            }
        }
        // Memory outputs are already in place
    }

    monacc_free(bindings);
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
        case STMT_ASM:
            cg_asm_stmt(cg, s);
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

    // Emit global variables in .bss section
    if (prg->nglobals > 0) {
        for (int i = 0; i < prg->nglobals; i++) {
            const GlobalVar *gv = &prg->globals[i];
            if (gv->is_extern) continue;
            // Each global in its own section for --gc-sections
            str_appendf_s(&cg.out, ".section .bss.%s,\"aw\",@nobits\n", gv->name);
            // Compute alignment (use power of 2, max 8)
            int align = (gv->elem_size >= 8) ? 8 : (gv->elem_size >= 4) ? 4 : (gv->elem_size >= 2) ? 2 : 1;
            str_appendf_is(&cg.out, ".align %d\n%s:\n", (long long)align, gv->name);
            str_appendf_i64(&cg.out, "  .zero %d\n\n", gv->size);
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

