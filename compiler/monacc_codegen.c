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
static void cg_normalize_scalar_result(CG *cg, const Expr *e);

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
    mc_usize max = sizeof(cg->labels[i].name) - 1;
    mc_usize n = mc_strlen(name);
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


typedef int (*ExprPredFn)(const Expr *e, void *ctx);
typedef int (*ExprSumFn)(const Expr *e, void *ctx);
typedef int (*StmtPredFn)(const Stmt *s, void *ctx);

static int expr_any(const Expr *e, ExprPredFn pred, void *ctx) {
    if (!e) return 0;
    if (pred && pred(e, ctx)) return 1;
    if (expr_any(e->lhs, pred, ctx)) return 1;
    if (expr_any(e->rhs, pred, ctx)) return 1;
    if (expr_any(e->third, pred, ctx)) return 1;
    for (int i = 0; i < e->nargs; i++) {
        if (expr_any(e->args[i], pred, ctx)) return 1;
    }
    for (int i = 0; i < e->ninits; i++) {
        if (expr_any(e->inits[i].value, pred, ctx)) return 1;
    }
    return 0;
}

static int expr_sum(const Expr *e, ExprSumFn fn, void *ctx) {
    if (!e) return 0;
    int n = 0;
    if (fn) n += fn(e, ctx);
    n += expr_sum(e->lhs, fn, ctx);
    n += expr_sum(e->rhs, fn, ctx);
    n += expr_sum(e->third, fn, ctx);
    for (int i = 0; i < e->nargs; i++) {
        n += expr_sum(e->args[i], fn, ctx);
    }
    for (int i = 0; i < e->ninits; i++) {
        n += expr_sum(e->inits[i].value, fn, ctx);
    }
    return n;
}

static int stmt_any(const Stmt *s, StmtPredFn spred, void *sctx, ExprPredFn epred, void *ectx) {
    if (!s) return 0;
    if (spred && spred(s, sctx)) return 1;
    switch (s->kind) {
        case STMT_BLOCK:
            for (const Stmt *cur = s->block_first; cur; cur = cur->next) {
                if (stmt_any(cur, spred, sctx, epred, ectx)) return 1;
            }
            return 0;
        case STMT_IF:
            if (expr_any(s->if_cond, epred, ectx)) return 1;
            if (stmt_any(s->if_then, spred, sctx, epred, ectx)) return 1;
            if (stmt_any(s->if_else, spred, sctx, epred, ectx)) return 1;
            return 0;
        case STMT_WHILE:
            if (expr_any(s->while_cond, epred, ectx)) return 1;
            return stmt_any(s->while_body, spred, sctx, epred, ectx);
        case STMT_FOR:
            if (stmt_any(s->for_init, spred, sctx, epred, ectx)) return 1;
            if (expr_any(s->for_cond, epred, ectx)) return 1;
            if (expr_any(s->for_inc, epred, ectx)) return 1;
            return stmt_any(s->for_body, spred, sctx, epred, ectx);
        case STMT_SWITCH:
            if (expr_any(s->switch_expr, epred, ectx)) return 1;
            return stmt_any(s->switch_body, spred, sctx, epred, ectx);
        case STMT_LABEL:
            return stmt_any(s->label_stmt, spred, sctx, epred, ectx);
        case STMT_DECL:
            return expr_any(s->decl_init, epred, ectx);
        case STMT_RETURN:
        case STMT_EXPR:
            return expr_any(s->expr, epred, ectx);
        case STMT_ASM:
            for (int i = 0; i < s->asm_noutputs; i++) {
                if (expr_any(s->asm_outputs[i].expr, epred, ectx)) return 1;
            }
            for (int i = 0; i < s->asm_ninputs; i++) {
                if (expr_any(s->asm_inputs[i].expr, epred, ectx)) return 1;
            }
            return 0;
        default:
            return 0;
    }
}

static int stmt_sum_expr(const Stmt *s, ExprSumFn efn, void *ectx) {
    if (!s) return 0;
    int n = 0;
    switch (s->kind) {
        case STMT_BLOCK:
            for (const Stmt *cur = s->block_first; cur; cur = cur->next) {
                n += stmt_sum_expr(cur, efn, ectx);
            }
            return n;
        case STMT_IF:
            n += expr_sum(s->if_cond, efn, ectx);
            n += stmt_sum_expr(s->if_then, efn, ectx);
            n += stmt_sum_expr(s->if_else, efn, ectx);
            return n;
        case STMT_WHILE:
            n += expr_sum(s->while_cond, efn, ectx);
            n += stmt_sum_expr(s->while_body, efn, ectx);
            return n;
        case STMT_FOR:
            n += stmt_sum_expr(s->for_init, efn, ectx);
            n += expr_sum(s->for_cond, efn, ectx);
            n += expr_sum(s->for_inc, efn, ectx);
            n += stmt_sum_expr(s->for_body, efn, ectx);
            return n;
        case STMT_SWITCH:
            n += expr_sum(s->switch_expr, efn, ectx);
            n += stmt_sum_expr(s->switch_body, efn, ectx);
            return n;
        case STMT_LABEL:
            return stmt_sum_expr(s->label_stmt, efn, ectx);
        case STMT_DECL:
            return expr_sum(s->decl_init, efn, ectx);
        case STMT_RETURN:
        case STMT_EXPR:
            return expr_sum(s->expr, efn, ectx);
        case STMT_ASM:
            for (int i = 0; i < s->asm_noutputs; i++) {
                n += expr_sum(s->asm_outputs[i].expr, efn, ectx);
            }
            for (int i = 0; i < s->asm_ninputs; i++) {
                n += expr_sum(s->asm_inputs[i].expr, efn, ectx);
            }
            return n;
        default:
            return 0;
    }
}

static int expr_is_syscall_builtin(const Expr *e);

static int expr_pred_contains_nonsyscall_call(const Expr *e, void *ctx) {
    (void)ctx;
    if (!e) return 0;
    if (e->kind == EXPR_CALL && !expr_is_syscall_builtin(e)) return 1;
    if (e->kind == EXPR_SRET_CALL) return 1;
    return 0;
}

static int expr_pred_uses_frame_pointer(const Expr *e, void *ctx) {
    (void)ctx;
    if (!e) return 0;
    // Any access to addressable stack storage uses rbp-relative addressing.
    // Note: var_offset can be negative (locals) or positive (stack args).
    if (e->kind == EXPR_VAR || e->kind == EXPR_COMPOUND || e->kind == EXPR_SRET_CALL) {
        return (e->var_offset != 0);
    }
    return 0;
}

static int stmt_pred_decl_uses_frame_pointer(const Stmt *s, void *ctx) {
    (void)ctx;
    if (!s) return 0;
    if (s->kind == STMT_DECL && s->decl_offset != 0) return 1;
    return 0;
}


typedef struct {
    int off;
} VarUseCtx;

static int expr_sum_var_uses(const Expr *e, void *ctx) {
    VarUseCtx *c = (VarUseCtx *)ctx;
    if (e->kind == EXPR_VAR && e->var_offset == c->off) return 1;
    return 0;
}

static int stmt_count_var_uses(const Stmt *s, int off) {
    VarUseCtx ctx;
    mc_memset(&ctx, 0, sizeof(ctx));
    ctx.off = off;
    return stmt_sum_expr(s, expr_sum_var_uses, &ctx);
}

static int expr_is_syscall_builtin(const Expr *e) {
    if (!e || e->kind != EXPR_CALL) return 0;
    if (e->callee[0] == 0) return 0;
    if ((mc_strncmp(e->callee, "mc_syscall", 10) != 0) && (mc_strncmp(e->callee, "sb_syscall", 10) != 0)) return 0;
    if (e->callee[10] < '0' || e->callee[10] > '6') return 0;
    if (e->callee[11] != 0) return 0;
    return 1;
}

static int expr_is_simple_arg(const Expr *e);

static int expr_is_simple_scalar_arg(const Expr *e) {
    if (!e) return 0;
    if (e->kind == EXPR_CAST || e->kind == EXPR_POS) return expr_is_simple_scalar_arg(e->lhs);

    // Allow a small, side-effect-free subset of integer arithmetic so pointer
    // args like `p + (i + 1)` can still be lowered via the direct-arg path.
    // Keep this conservative: only +/- with an immediate.
    if ((e->kind == EXPR_ADD || e->kind == EXPR_SUB) && e->ptr_scale == 0) {
        if (!e->lhs || !e->rhs) return 0;
        if (e->rhs->kind == EXPR_NUM && expr_is_simple_scalar_arg(e->lhs)) return 1;
        if (e->kind == EXPR_ADD && e->lhs->kind == EXPR_NUM && expr_is_simple_scalar_arg(e->rhs)) return 1;
        return 0;
    }

    if (e->kind == EXPR_NUM) return 1;
    if (e->kind == EXPR_VAR) {
        if (e->lval_size == 1 || e->lval_size == 2 || e->lval_size == 4 || e->lval_size == 8) return 1;
        return 0;
    }
    if (e->kind == EXPR_GLOBAL) {
        if (e->lval_size == 1 || e->lval_size == 2 || e->lval_size == 4 || e->lval_size == 8) return 1;
        return 0;
    }
    return 0;
}

static int expr_is_simple_addr_arg(const Expr *e) {
    if (!e) return 0;
    if (e->kind == EXPR_CAST || e->kind == EXPR_POS) return expr_is_simple_addr_arg(e->lhs);

    // &*p  -> p (when p is a simple value load)
    if (e->kind == EXPR_DEREF) return expr_is_simple_arg(e->lhs);

    if (e->kind == EXPR_VAR) return 1;
    if (e->kind == EXPR_COMPOUND) return 1;
    if (e->kind == EXPR_GLOBAL) return 1;

    if (e->kind == EXPR_MEMBER) {
        // Non-arrow members: base is addressable with a fixed rbp displacement.
        // Arrow members: allow when base pointer value is a simple arg (load + add off).
        if (e->member_is_arrow) return expr_is_simple_arg(e->lhs);
        if (!e->lhs) return 0;
        if (e->lhs->kind == EXPR_VAR || e->lhs->kind == EXPR_COMPOUND) return 1;
        return 0;
    }

    if (e->kind == EXPR_INDEX && e->lhs && e->rhs && e->rhs->kind == EXPR_NUM) {
        // Only constant-index on addressable objects (stack/global arrays), or on a
        // simple pointer value (load pointer + add imm offset).
        const Expr *base = e->lhs;
        if (base->kind == EXPR_COMPOUND) return 1;
        if (base->kind == EXPR_VAR && base->lval_size == 0) return 1;
        if (base->kind == EXPR_VAR && base->lval_size != 0) return 1;
        if (base->kind == EXPR_GLOBAL && base->lval_size == 0) return 1;
        if (base->kind == EXPR_GLOBAL && base->lval_size != 0) return 1;
        return 0;
    }

    return 0;
}

// Slightly broader than expr_is_simple_const: expressions that can be loaded
// directly into *any* register without side effects, and without needing a
// scratch save/restore scheme.
//
// Currently limited to immediates, string/fn addresses, and addressable objects
// (array decay / large structs) where the value is an address computed via lea.
static int expr_is_simple_arg(const Expr *e) {
    if (!e) return 0;
    if (e->kind == EXPR_POS) return expr_is_simple_arg(e->lhs);
    if (e->kind == EXPR_CAST) {
        // Only treat casts as "simple" when they don't require real codegen.
        // In particular, float casts require SSE conversions and must not go
        // through the "load into any reg" fast path used by call lowering.
        if (!e->lhs) return 0;
        if ((e->ptr == 0 && (e->base == BT_FLOAT || e->base == BT_STRUCT)) ||
            (e->lhs->ptr == 0 && (e->lhs->base == BT_FLOAT || e->lhs->base == BT_STRUCT))) {
            return 0;
        }
        return expr_is_simple_arg(e->lhs);
    }
    if (e->kind == EXPR_ADDR) return expr_is_simple_addr_arg(e->lhs);

    // Pointer +/- immediate (e.g. buf+1, argv+8). Treat as simple when the pointer
    // side is a simple arg and the offset is a constant.
    if ((e->kind == EXPR_ADD || e->kind == EXPR_SUB) && e->ptr_scale > 0) {
        const Expr *ptr_e = NULL;
        const Expr *imm_e = NULL;
        if (e->kind == EXPR_ADD) {
            if (e->ptr_index_side == 1) {
                ptr_e = e->lhs;
                imm_e = e->rhs;
            } else if (e->ptr_index_side == 2) {
                ptr_e = e->rhs;
                imm_e = e->lhs;
            }
        } else {
            // For SUB, only pointer - int is supported and ptr_index_side==1.
            if (e->ptr_index_side == 1) {
                ptr_e = e->lhs;
                imm_e = e->rhs;
            }
        }
        if (ptr_e && imm_e && expr_is_simple_scalar_arg(imm_e)) {
            // Conservative: only scale values supported by LEA.
            if (!(e->ptr_scale == 1 || e->ptr_scale == 2 || e->ptr_scale == 4 || e->ptr_scale == 8)) return 0;
            if (imm_e->kind == EXPR_NUM) {
                long long off = imm_e->num * (long long)e->ptr_scale;
                if (off >= MC_I32_MIN && off <= MC_I32_MAX) {
                    return expr_is_simple_arg(ptr_e);
                }
            } else {
                // ptr + idx where idx is a simple scalar load.
                return expr_is_simple_arg(ptr_e);
            }
        }
    }

    if (e->kind == EXPR_NUM) return 1;
    if (e->kind == EXPR_STR) return 1;
    if (e->kind == EXPR_FNADDR) return 1;
    if (e->kind == EXPR_VAR) {
        if (e->lval_size == 0) return 1; // array decay / addressable object
        if (e->base == BT_STRUCT && e->ptr == 0 && e->lval_size > 8) return 1;
        if (e->lval_size == 1 || e->lval_size == 2 || e->lval_size == 4 || e->lval_size == 8) return 1;
        return 0;
    }
    if (e->kind == EXPR_GLOBAL) {
        if (e->lval_size == 0) return 1; // array decay / addressable object
        if (e->base == BT_STRUCT && e->ptr == 0 && e->lval_size > 8) return 1;
        if (e->lval_size == 1 || e->lval_size == 2 || e->lval_size == 4 || e->lval_size == 8) return 1;
        return 0;
    }
    return 0;
}

// Conservative predicate: returns 1 if cg_expr(e) will not clobber %rcx.
// This is used to replace certain push/pop save/restore sequences with
// `mov %rax, %rcx` when we need to preserve an address/value across a simple RHS.


// Emit code to load a simple constant expression directly into a specific register.
// Returns 1 if successful, 0 if the expression is not simple.
static int cg_expr_to_reg(CG *cg, const Expr *e, const char *reg64, const char *reg32) {
    if (!e) return 0;
    if (e->kind == EXPR_NUM) {
        if (e->ptr == 0 && e->base == BT_FLOAT) {
            mc_u32 bits = (mc_u32)e->num;
            if (bits == 0) {
                str_appendf_ss(&cg->out, "  xor %s, %s\n", reg32, reg32);
            } else {
                str_appendf_u64(&cg->out, "  mov $%u, ", (unsigned long long)bits);
                str_appendf_s(&cg->out, "%s\n", reg32);
            }
            return 1;
        }
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

static void emit_load_disp_reg(CG *cg, int disp, const char *base, int size, int is_unsigned, const char *reg64, const char *reg32);
static void emit_load_rip_reg(CG *cg, const char *sym, int size, int is_unsigned, const char *reg64, const char *reg32);

// Emit code to load a "simple arg" directly into a specific register.
// Returns 1 if successful, 0 otherwise.
static int cg_expr_to_reg_simple_arg(CG *cg, const Expr *e, const char *reg64, const char *reg32) {
    if (!e) return 0;
    if (e->kind == EXPR_POS) return cg_expr_to_reg_simple_arg(cg, e->lhs, reg64, reg32);
    if (e->kind == EXPR_CAST) {
        // IMPORTANT: casts can change width/signedness. Do not drop them.
        // Keep this path limited to scalar integer/pointer casts that we can
        // implement without clobbering other ABI argument registers.
        if (!e->lhs) return 0;
        if ((e->ptr == 0 && (e->base == BT_FLOAT || e->base == BT_STRUCT)) ||
            (e->lhs->ptr == 0 && (e->lhs->base == BT_FLOAT || e->lhs->base == BT_STRUCT))) {
            return 0;
        }

        // Load the source expression into the target register.
        if (!cg_expr_to_reg_simple_arg(cg, e->lhs, reg64, reg32)) return 0;

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
        }

        int src_sz = 8;
        if (e->lhs) {
            src_sz = type_sizeof(cg->prg, e->lhs->base, e->lhs->ptr, e->lhs->struct_id);
        }

        // If we're widening a signed 32-bit integer to 64-bit, we must
        // explicitly sign-extend because many loads now leave upper bits as 0.
        if (dst_sz == 8 && src_sz == 4) {
            if (e->lhs->ptr == 0 && !e->lhs->is_unsigned &&
                e->lhs->base != BT_LONG && e->lhs->base != BT_FLOAT && e->lhs->base != BT_STRUCT) {
                str_appendf_ss(&cg->out, "  movslq %s, %s\n", reg32, reg64);
            }
        }
        return 1;
    }

    // Simple scalar arithmetic: scalar +/- imm32. This is primarily used by the
    // ptr+idx lowering path when idx is parenthesized (e.g. `p + (i + 1)`).
    if ((e->kind == EXPR_ADD || e->kind == EXPR_SUB) && e->ptr_scale == 0) {
        const Expr *base = NULL;
        long long imm = 0;
        if (!e->lhs || !e->rhs) return 0;
        if (e->rhs->kind == EXPR_NUM && expr_is_simple_scalar_arg(e->lhs)) {
            base = e->lhs;
            imm = e->rhs->num;
            if (e->kind == EXPR_SUB) imm = -imm;
        } else if (e->kind == EXPR_ADD && e->lhs->kind == EXPR_NUM && expr_is_simple_scalar_arg(e->rhs)) {
            base = e->rhs;
            imm = e->lhs->num;
        }
        if (base) {
            if (imm < MC_I32_MIN || imm > MC_I32_MAX) return 0;
            if (!cg_expr_to_reg_simple_arg(cg, base, reg64, reg32)) return 0;
            if (imm != 0) {
                if (imm > 0) {
                    str_appendf_i64(&cg->out, "  add $%lld, ", imm);
                } else {
                    str_appendf_i64(&cg->out, "  sub $%lld, ", -imm);
                }
                str_appendf_s(&cg->out, "%s\n", reg64);
            }
            return 1;
        }
    }

    // Pointer +/- immediate (e.g. buf+1). Load pointer into the target reg and add/sub.
    if ((e->kind == EXPR_ADD || e->kind == EXPR_SUB) && e->ptr_scale > 0) {
        const Expr *ptr_e = NULL;
        const Expr *imm_e = NULL;
        int sign = 1;
        if (e->kind == EXPR_ADD) {
            if (e->ptr_index_side == 1) {
                ptr_e = e->lhs;
                imm_e = e->rhs;
            } else if (e->ptr_index_side == 2) {
                ptr_e = e->rhs;
                imm_e = e->lhs;
            }
        } else {
            // For SUB, only pointer - int is supported and ptr_index_side==1.
            if (e->ptr_index_side == 1) {
                ptr_e = e->lhs;
                imm_e = e->rhs;
                sign = -1;
            }
        }

        if (ptr_e && imm_e && expr_is_simple_scalar_arg(imm_e)) {
            if (!(e->ptr_scale == 1 || e->ptr_scale == 2 || e->ptr_scale == 4 || e->ptr_scale == 8)) return 0;

            if (imm_e->kind == EXPR_NUM) {
                long long off = imm_e->num * (long long)e->ptr_scale;
                off *= (long long)sign;
                if (off >= MC_I32_MIN && off <= MC_I32_MAX) {
                    if (!cg_expr_to_reg_simple_arg(cg, ptr_e, reg64, reg32)) return 0;
                    if (off != 0) {
                        if (off > 0) {
                            str_appendf_i64(&cg->out, "  add $%lld, ", off);
                        } else {
                            str_appendf_i64(&cg->out, "  sub $%lld, ", -off);
                        }
                        str_appendf_s(&cg->out, "%s\n", reg64);
                    }
                    return 1;
                }
            } else {
                // ptr +/- idx where idx is a simple scalar load.
                // Use %r11 as a dedicated scratch so we don't clobber any ABI arg regs.
                if (!cg_expr_to_reg_simple_arg(cg, ptr_e, reg64, reg32)) return 0;
                if (!cg_expr_to_reg_simple_arg(cg, imm_e, "%r11", "%r11d")) return 0;

                if (imm_e->ptr == 0 && imm_e->lval_size == 4 && !imm_e->is_unsigned &&
                    imm_e->base != BT_LONG && imm_e->base != BT_FLOAT && imm_e->base != BT_STRUCT) {
                    str_appendf(&cg->out, "  movslq %%r11d, %%r11\n");
                }

                if (e->ptr_scale != 1) {
                    int sh = (e->ptr_scale == 2) ? 1 : (e->ptr_scale == 4) ? 2 : 3;
                    str_appendf_is(&cg->out, "  shl $%d, %s\n", (long long)sh, "%r11");
                }

                if (sign > 0) {
                    // lea (%reg64,%r11), %reg64
                    str_appendf_ss(&cg->out, "  lea (%s,%%r11), %s\n", reg64, reg64);
                } else {
                    str_appendf_ss(&cg->out, "  sub %s, %s\n", "%r11", reg64);
                }
                return 1;
            }
        }
    }

    if (e->kind == EXPR_ADDR) {
        const Expr *lhs = e->lhs;
        while (lhs && (lhs->kind == EXPR_CAST || lhs->kind == EXPR_POS)) lhs = lhs->lhs;

        if (!lhs) return 0;
        if (lhs->kind == EXPR_DEREF) {
            // &*p  -> p (when p can be loaded directly into the target reg)
            if (!lhs->lhs) return 0;
            return cg_expr_to_reg_simple_arg(cg, lhs->lhs, reg64, reg32);
        }
        if (lhs->kind == EXPR_VAR || lhs->kind == EXPR_COMPOUND) {
            str_appendf_is(&cg->out, "  lea %d(%%rbp), %s\n", (long long)lhs->var_offset, reg64);
            return 1;
        }
        if (lhs->kind == EXPR_GLOBAL) {
            if (!cg->prg) return 0;
            const GlobalVar *gv = &cg->prg->globals[lhs->global_id];
            str_appendf_ss(&cg->out, "  lea %s(%%rip), %s\n", gv->name, reg64);
            return 1;
        }
        if (lhs->kind == EXPR_MEMBER) {
            if (lhs->member_is_arrow) {
                // &p->m  -> load p + add off
                if (!lhs->lhs) return 0;
                if (!cg_expr_to_reg_simple_arg(cg, lhs->lhs, reg64, reg32)) return 0;
                if (lhs->member_off) {
                    str_appendf_i64(&cg->out, "  add $%d, ", (long long)lhs->member_off);
                    str_appendf_s(&cg->out, "%s\n", reg64);
                }
                return 1;
            }
            if (!lhs->lhs) return 0;
            if (lhs->lhs->kind == EXPR_VAR || lhs->lhs->kind == EXPR_COMPOUND) {
                int disp = lhs->lhs->var_offset + lhs->member_off;
                str_appendf_is(&cg->out, "  lea %d(%%rbp), %s\n", (long long)disp, reg64);
                return 1;
            }
            return 0;
        }
        if (lhs->kind == EXPR_INDEX && lhs->lhs && lhs->rhs && lhs->rhs->kind == EXPR_NUM) {
            long long idx = lhs->rhs->num;
            int scale = (lhs->ptr_scale > 0) ? lhs->ptr_scale : 8;
            long long off = idx * (long long)scale;
            if (off < MC_I32_MIN || off > MC_I32_MAX) return 0;

            const Expr *base = lhs->lhs;
            if (base->kind == EXPR_COMPOUND) {
                int disp = base->var_offset + (int)off;
                str_appendf_is(&cg->out, "  lea %d(%%rbp), %s\n", (long long)disp, reg64);
                return 1;
            }
            if (base->kind == EXPR_VAR && base->lval_size == 0) {
                int disp = base->var_offset + (int)off;
                str_appendf_is(&cg->out, "  lea %d(%%rbp), %s\n", (long long)disp, reg64);
                return 1;
            }
            if (base->kind == EXPR_GLOBAL && base->lval_size == 0) {
                if (!cg->prg) return 0;
                const GlobalVar *gv = &cg->prg->globals[base->global_id];
                if (off == 0) {
                    str_appendf_ss(&cg->out, "  lea %s(%%rip), %s\n", gv->name, reg64);
                } else {
                    str_appendf_si(&cg->out, "  lea %s%+d(%%rip), ", gv->name, (long long)(int)off);
                    str_appendf_s(&cg->out, "%s\n", reg64);
                }
                return 1;
            }

            // Pointer base: load pointer value then add the constant scaled offset.
            if (base->kind == EXPR_VAR && base->lval_size != 0) {
                if (!cg_expr_to_reg_simple_arg(cg, base, reg64, reg32)) return 0;
                if (off != 0) {
                    str_appendf_i64(&cg->out, "  add $%lld, ", off);
                    str_appendf_s(&cg->out, "%s\n", reg64);
                }
                return 1;
            }
            if (base->kind == EXPR_GLOBAL && base->lval_size != 0) {
                if (!cg_expr_to_reg_simple_arg(cg, base, reg64, reg32)) return 0;
                if (off != 0) {
                    str_appendf_i64(&cg->out, "  add $%lld, ", off);
                    str_appendf_s(&cg->out, "%s\n", reg64);
                }
                return 1;
            }
            return 0;
        }
        return 0;
    }
    if (e->kind == EXPR_NUM || e->kind == EXPR_STR) {
        return cg_expr_to_reg(cg, e, reg64, reg32);
    }
    if (e->kind == EXPR_FNADDR) {
        if (e->callee[0] == 0) return 0;
        str_appendf_ss(&cg->out, "  lea %s(%%rip), %s\n", e->callee, reg64);
        return 1;
    }
    if (e->kind == EXPR_VAR) {
        if (e->lval_size == 0 || (e->base == BT_STRUCT && e->ptr == 0 && e->lval_size > 8)) {
            str_appendf_is(&cg->out, "  lea %d(%%rbp), %s\n", (long long)e->var_offset, reg64);
            return 1;
        }
        if (e->lval_size == 1 || e->lval_size == 2 || e->lval_size == 4 || e->lval_size == 8) {
            emit_load_disp_reg(cg, e->var_offset, "%rbp", e->lval_size, e->is_unsigned, reg64, reg32);
            return 1;
        }
        return 0;
    }
    if (e->kind == EXPR_GLOBAL) {
        if (!cg->prg) return 0;
        const GlobalVar *gv = &cg->prg->globals[e->global_id];
        if (e->lval_size == 0 || (e->base == BT_STRUCT && e->ptr == 0 && e->lval_size > 8)) {
            str_appendf_ss(&cg->out, "  lea %s(%%rip), %s\n", gv->name, reg64);
            return 1;
        }
        if (e->lval_size == 1 || e->lval_size == 2 || e->lval_size == 4 || e->lval_size == 8) {
            emit_load_rip_reg(cg, gv->name, e->lval_size, e->is_unsigned, reg64, reg32);
            return 1;
        }
        return 0;
    }
    return 0;
}

// Like cg_expr_to_reg_simple_arg, but rolls back output on failure.
static int cg_expr_to_reg_simple_arg_try(CG *cg, const Expr *e, const char *reg64, const char *reg32) {
    if (!cg) return 0;
    mc_usize old_len = cg->out.len;
    int ok = cg_expr_to_reg_simple_arg(cg, e, reg64, reg32);
    if (!ok) {
        cg->out.len = old_len;
        if (cg->out.buf) cg->out.buf[old_len] = 0;
    }
    return ok;
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

static void emit_load_mem(CG *cg, const char *mem, int size, int is_unsigned) {
    if (size == 1) {
        str_appendf_s(&cg->out, "  movzb %s, %%eax\n", mem);
        return;
    }
    if (size == 2) {
        if (is_unsigned) {
            str_appendf_s(&cg->out, "  movzw %s, %%eax\n", mem);
        } else {
            str_appendf_s(&cg->out, "  movswq %s, %%rax\n", mem);
        }
        return;
    }
    if (size == 4) {
        // Keep 32-bit scalars in %eax and avoid eager sign-extension.
        (void)is_unsigned;
        str_appendf_s(&cg->out, "  mov %s, %%eax\n", mem);
        return;
    }
    if (size == 8) {
        str_appendf_s(&cg->out, "  mov %s, %%rax\n", mem);
        return;
    }
    die("rvalue load size %d not supported", size);
}

static void emit_load_disp(CG *cg, int disp, const char *base, int size, int is_unsigned) {
    if (size == 1) {
        str_appendf_is(&cg->out, "  movzb %d(%s), %%eax\n", (long long)disp, base);
        return;
    }
    if (size == 2) {
        if (is_unsigned) {
            str_appendf_is(&cg->out, "  movzw %d(%s), %%eax\n", (long long)disp, base);
        } else {
            str_appendf_is(&cg->out, "  movswq %d(%s), %%rax\n", (long long)disp, base);
        }
        return;
    }
    if (size == 4) {
        (void)is_unsigned;
        str_appendf_is(&cg->out, "  mov %d(%s), %%eax\n", (long long)disp, base);
        return;
    }
    if (size == 8) {
        str_appendf_is(&cg->out, "  mov %d(%s), %%rax\n", (long long)disp, base);
        return;
    }
    die("rvalue load size %d not supported", size);
}
static void emit_load_disp_reg(CG *cg, int disp, const char *base, int size, int is_unsigned, const char *reg64, const char *reg32) {
    if (size == 1) {
        str_appendf_is(&cg->out, "  movzb %d(%s), ", (long long)disp, base);
        str_appendf_s(&cg->out, "%s\n", reg32);
        return;
    }
    if (size == 2) {
        if (is_unsigned) {
            str_appendf_is(&cg->out, "  movzw %d(%s), ", (long long)disp, base);
            str_appendf_s(&cg->out, "%s\n", reg32);
        } else {
            str_appendf_is(&cg->out, "  movswq %d(%s), ", (long long)disp, base);
            str_appendf_s(&cg->out, "%s\n", reg64);
        }
        return;
    }
    if (size == 4) {
        (void)is_unsigned;
        (void)reg64;
        str_appendf_is(&cg->out, "  mov %d(%s), ", (long long)disp, base);
        str_appendf_s(&cg->out, "%s\n", reg32);
        return;
    }
    if (size == 8) {
        str_appendf_is(&cg->out, "  mov %d(%s), ", (long long)disp, base);
        str_appendf_s(&cg->out, "%s\n", reg64);
        return;
    }
    die("rvalue load size %d not supported", size);
}

static void emit_load_rip(CG *cg, const char *sym, int size, int is_unsigned) {
    if (size == 1) {
        str_appendf_s(&cg->out, "  movzb %s(%%rip), %%eax\n", sym);
        return;
    }
    if (size == 2) {
        if (is_unsigned) {
            str_appendf_s(&cg->out, "  movzw %s(%%rip), %%eax\n", sym);
        } else {
            str_appendf_s(&cg->out, "  movswq %s(%%rip), %%rax\n", sym);
        }
        return;
    }
    if (size == 4) {
        (void)is_unsigned;
        str_appendf_s(&cg->out, "  mov %s(%%rip), %%eax\n", sym);
        return;
    }
    if (size == 8) {
        str_appendf_s(&cg->out, "  mov %s(%%rip), %%rax\n", sym);
        return;
    }
    die("rvalue load size %d not supported", size);
}
static void emit_load_rip_reg(CG *cg, const char *sym, int size, int is_unsigned, const char *reg64, const char *reg32) {
    if (size == 1) {
        str_appendf_ss(&cg->out, "  movzb %s(%%rip), %s\n", sym, reg32);
        return;
    }
    if (size == 2) {
        if (is_unsigned) {
            str_appendf_ss(&cg->out, "  movzw %s(%%rip), %s\n", sym, reg32);
        } else {
            str_appendf_ss(&cg->out, "  movswq %s(%%rip), %s\n", sym, reg64);
        }
        return;
    }
    if (size == 4) {
        (void)is_unsigned;
        (void)reg64;
        str_appendf_ss(&cg->out, "  mov %s(%%rip), %s\n", sym, reg32);
        return;
    }
    if (size == 8) {
        str_appendf_ss(&cg->out, "  mov %s(%%rip), %s\n", sym, reg64);
        return;
    }
    die("rvalue load size %d not supported", size);
}

static void emit_load_rip_disp(CG *cg, const char *sym, int disp, int size, int is_unsigned) {
    if (disp == 0) {
        emit_load_rip(cg, sym, size, is_unsigned);
        return;
    }
    if (size == 1) {
        str_appendf_si(&cg->out, "  movzb %s+%d(%%rip), %%eax\n", sym, (long long)disp);
        return;
    }
    if (size == 2) {
        if (is_unsigned) {
            str_appendf_si(&cg->out, "  movzw %s+%d(%%rip), %%eax\n", sym, (long long)disp);
        } else {
            str_appendf_si(&cg->out, "  movswq %s+%d(%%rip), %%rax\n", sym, (long long)disp);
        }
        return;
    }
    if (size == 4) {
        (void)is_unsigned;
        str_appendf_si(&cg->out, "  mov %s+%d(%%rip), %%eax\n", sym, (long long)disp);
        return;
    }
    if (size == 8) {
        str_appendf_si(&cg->out, "  mov %s+%d(%%rip), %%rax\n", sym, (long long)disp);
        return;
    }
    die("rvalue load size %d not supported", size);
}

static void emit_store_mem(CG *cg, const char *mem, int size) {
    if (size == 1) {
        str_appendf_s(&cg->out, "  mov %%al, %s\n", mem);
    } else if (size == 2) {
        str_appendf_s(&cg->out, "  mov %%ax, %s\n", mem);
    } else if (size == 4) {
        str_appendf_s(&cg->out, "  mov %%eax, %s\n", mem);
    } else {
        str_appendf_s(&cg->out, "  mov %%rax, %s\n", mem);
    }
}

static void emit_store_disp(CG *cg, int disp, const char *base, int size) {
    if (size == 1) {
        str_appendf_is(&cg->out, "  mov %%al, %d(%s)\n", (long long)disp, base);
    } else if (size == 2) {
        str_appendf_is(&cg->out, "  mov %%ax, %d(%s)\n", (long long)disp, base);
    } else if (size == 4) {
        str_appendf_is(&cg->out, "  mov %%eax, %d(%s)\n", (long long)disp, base);
    } else {
        str_appendf_is(&cg->out, "  mov %%rax, %d(%s)\n", (long long)disp, base);
    }
}

static void emit_store_rip(CG *cg, const char *sym, int size) {
    if (size == 1) {
        str_appendf_s(&cg->out, "  mov %%al, %s(%%rip)\n", sym);
        return;
    }
    if (size == 2) {
        str_appendf_s(&cg->out, "  mov %%ax, %s(%%rip)\n", sym);
        return;
    }
    if (size == 4) {
        str_appendf_s(&cg->out, "  mov %%eax, %s(%%rip)\n", sym);
        return;
    }
    if (size == 8) {
        str_appendf_s(&cg->out, "  mov %%rax, %s(%%rip)\n", sym);
        return;
    }
    die("rvalue store size %d not supported", size);
}

static void emit_store_rip_disp(CG *cg, const char *sym, int disp, int size) {
    if (disp == 0) {
        emit_store_rip(cg, sym, size);
        return;
    }
    if (size == 1) {
        str_appendf_si(&cg->out, "  mov %%al, %s+%d(%%rip)\n", sym, (long long)disp);
        return;
    }
    if (size == 2) {
        str_appendf_si(&cg->out, "  mov %%ax, %s+%d(%%rip)\n", sym, (long long)disp);
        return;
    }
    if (size == 4) {
        str_appendf_si(&cg->out, "  mov %%eax, %s+%d(%%rip)\n", sym, (long long)disp);
        return;
    }
    if (size == 8) {
        str_appendf_si(&cg->out, "  mov %%rax, %s+%d(%%rip)\n", sym, (long long)disp);
        return;
    }
    die("rvalue store size %d not supported", size);
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

static int stmt_contains_nonsyscall_call(const Stmt *s) {
    return stmt_any(s, NULL, NULL, expr_pred_contains_nonsyscall_call, NULL);
}

static int stmt_uses_frame_pointer(const Stmt *s) {
    return stmt_any(s, stmt_pred_decl_uses_frame_pointer, NULL, expr_pred_uses_frame_pointer, NULL);
}

static int fn_can_be_frameless(const Function *fn) {
    if (!fn || !fn->has_body) return 0;
    if (fn->stack_size != 0) return 0;
    if (fn->sret_offset != 0) return 0;
    // Presence of parameter stack slots does not necessarily require a frame if
    // the parameters are never actually referenced (the prologue spill will be
    // skipped and codegen won't touch the slot). Treat unused params like they
    // don't exist so leaf/trivial functions can stay frameless.
    for (int i = 0; i < 6; i++) {
        int off = fn->param_offsets[i];
        if (off == 0) continue;
        if (stmt_count_var_uses(fn->body, off) != 0) return 0;
    }
    for (int i = 0; i < 8; i++) {
        int off = fn->xmm_param_offsets[i];
        if (off == 0) continue;
        if (stmt_count_var_uses(fn->body, off) != 0) return 0;
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
    int is_float;
} CallArgInfo;

enum {
    CALLARG_REG_INT = 1,
    CALLARG_REG_XMM = 2,
    CALLARG_STACK_SCALAR = 3,
    CALLARG_STACK_STRUCT = 4,
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
            emit_store_disp(cg, in->off, "%rdi", in->store_size);
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
        int scale = 8;
        if (e->ptr_scale > 0) {
            scale = e->ptr_scale;
        } else if (e->lval_size > 0) {
            // Fall back to element size for indexing (e.g. char* and arrays).
            scale = e->lval_size;
        }

        // Optimize constant index: avoid push/pop, use immediate offset
        if (e->rhs && e->rhs->kind == EXPR_NUM) {
            long long idx = e->rhs->num;
            long long offset = idx * (long long)scale;
            // If the base is a known addressable object, fold into the lea.
            if (e->lhs && e->lhs->kind == EXPR_VAR && e->lhs->lval_size == 0 &&
                offset >= MC_I32_MIN && offset <= MC_I32_MAX) {
                int disp = e->lhs->var_offset + (int)offset;
                str_appendf_i64(&cg->out, "  lea %d(%%rbp), %%rax\n", disp);
                return e->lval_size ? e->lval_size : 8;
            }
            if (e->lhs && e->lhs->kind == EXPR_COMPOUND &&
                offset >= MC_I32_MIN && offset <= MC_I32_MAX) {
                int disp = e->lhs->var_offset + (int)offset;
                str_appendf_i64(&cg->out, "  lea %d(%%rbp), %%rax\n", disp);
                return e->lval_size ? e->lval_size : 8;
            }
            if (e->lhs && e->lhs->kind == EXPR_GLOBAL && e->lhs->lval_size == 0 &&
                offset >= MC_I32_MIN && offset <= MC_I32_MAX) {
                const GlobalVar *gv = &cg->prg->globals[e->lhs->global_id];
                if (offset == 0) {
                    str_appendf_s(&cg->out, "  lea %s(%%rip), %%rax\n", gv->name);
                } else {
                    str_appendf_si(&cg->out, "  lea %s+%d(%%rip), %%rax\n", gv->name, offset);
                }
                return e->lval_size ? e->lval_size : 8;
            }

            // Fallback: compute base address then add the offset.
            cg_expr(cg, e->lhs);
            if (offset == 0) {
                // Index 0: base address is already correct
            } else if (offset >= MC_I32_MIN && offset <= MC_I32_MAX) {
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

        // The index operand is an integer that participates in pointer arithmetic.
        // Ensure it's sign-extended before using it in 64-bit address arithmetic.
        // Note: don't rely on lval_size here (rvalue expressions often have lval_size==0).
        if (e->rhs && e->rhs->ptr == 0 && !e->rhs->is_unsigned &&
            e->rhs->base != BT_FLOAT && e->rhs->base != BT_STRUCT) {
            str_appendf(&cg->out, "  cdqe\n");
        }
        if (scale != 1) {
            str_appendf_i64(&cg->out, "  imul $%d, %%rax\n", scale);
        }
        str_appendf(&cg->out, "  add %%rcx, %%rax\n");
        return e->lval_size ? e->lval_size : 8;
    }
    if (e->kind == EXPR_MEMBER) {
        if (e->member_is_arrow) {
            cg_expr(cg, e->lhs);
            if (e->member_off) {
                str_appendf_i64(&cg->out, "  add $%d, %%rax\n", e->member_off);
            }
            return e->lval_size ? e->lval_size : 8;
        }

        // For non-arrow members, try to fold the offset into a single lea when possible.
        if (e->lhs && e->lhs->kind == EXPR_VAR) {
            int disp = e->lhs->var_offset + e->member_off;
            str_appendf_i64(&cg->out, "  lea %d(%%rbp), %%rax\n", disp);
            return e->lval_size ? e->lval_size : 8;
        }
        if (e->lhs && e->lhs->kind == EXPR_COMPOUND) {
            int disp = e->lhs->var_offset + e->member_off;
            str_appendf_i64(&cg->out, "  lea %d(%%rbp), %%rax\n", disp);
            return e->lval_size ? e->lval_size : 8;
        }

        (void)cg_lval_addr(cg, e->lhs);
        if (e->member_off) {
            str_appendf_i64(&cg->out, "  add $%d, %%rax\n", e->member_off);
        }
        return e->lval_size ? e->lval_size : 8;
    }
    die("internal: not an lvalue");
}

// Helper: emit code for function calls (EXPR_CALL).
static void cg_call(CG *cg, const Expr *e) {
    // Minimal builtin support.
    // GCC/Clang treat __builtin_unreachable() as a hint that the control path
    // is impossible; if executed, it's undefined behavior. We lower it to a
    // UD2 trap (0x0f 0x0b) without emitting an external call.
    if (e->callee[0] != 0 && mc_strcmp(e->callee, "__builtin_unreachable") == 0) {
        if (e->nargs != 0) {
            die("__builtin_unreachable expects 0 args");
        }
        str_appendf(&cg->out, "  .byte 15, 11\n");
        return;
    }

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
            if (!expr_is_simple_arg(e->args[i])) need_stack++;
        }

        if (need_stack == 0) {
            // All args are simple - load directly into target regs.
            for (int i = 0; i < e->nargs; i++) {
                (void)cg_expr_to_reg_simple_arg(cg, e->args[i], sreg64[i], sreg32[i]);
            }
        } else if (need_stack == 1 && !expr_is_simple_arg(e->args[0])) {
            // Common mixed case: syscall number is complex but all other args are simple.
            // We can avoid stack shuffling because cg_expr_to_reg_simple_arg doesn't clobber %rax.
            cg_expr(cg, e->args[0]);
            for (int i = 1; i < e->nargs; i++) {
                (void)cg_expr_to_reg_simple_arg(cg, e->args[i], sreg64[i], sreg32[i]);
            }
        } else {
            // Mixed: evaluate complex args first (push), then load simple ones directly.
            // Push complex args left-to-right.
            for (int i = 0; i < e->nargs; i++) {
                if (!expr_is_simple_arg(e->args[i])) {
                    cg_expr(cg, e->args[i]);
                    str_appendf(&cg->out, "  push %%rax\n");
                }
            }
            // Pop complex args into regs right-to-left.
            for (int i = e->nargs - 1; i >= 0; i--) {
                if (!expr_is_simple_arg(e->args[i])) {
                    str_appendf_s(&cg->out, "  pop %s\n", sreg64[i]);
                }
            }
            // Load simple const args directly.
            for (int i = 0; i < e->nargs; i++) {
                if (expr_is_simple_arg(e->args[i])) {
                    (void)cg_expr_to_reg_simple_arg(cg, e->args[i], sreg64[i], sreg32[i]);
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

        CallArgInfo ai[64];
        if (e->nargs > (int)(sizeof(ai) / sizeof(ai[0]))) {
            die("too many call args");
        }

        int int_used = 0;
        int xmm_used = 0;
        int stack_bytes = 0;
        for (int i = 0; i < e->nargs; i++) {
            const Expr *a = e->args[i];
            if (a && a->base == BT_STRUCT && a->ptr == 0 && a->lval_size > 0) {
                // No signature info: keep conservative legacy (structs by value not supported here).
                die("indirect call: struct args not supported");
            }
            int is_float = (a && a->ptr == 0 && a->base == BT_FLOAT);
            if (is_float) {
                if (xmm_used < 8) {
                    ai[i].kind = CALLARG_REG_XMM;
                    ai[i].reg = xmm_used++;
                    ai[i].stack_bytes = 0;
                    ai[i].struct_size = 0;
                    ai[i].is_float = 1;
                } else {
                    ai[i].kind = CALLARG_STACK_SCALAR;
                    ai[i].reg = -1;
                    ai[i].stack_bytes = 8;
                    ai[i].struct_size = 0;
                    ai[i].is_float = 1;
                    stack_bytes += 8;
                }
            } else if (int_used < 6) {
                ai[i].kind = CALLARG_REG_INT;
                ai[i].reg = int_used++;
                ai[i].stack_bytes = 0;
                ai[i].struct_size = 0;
                ai[i].is_float = 0;
            } else {
                ai[i].kind = CALLARG_STACK_SCALAR;
                ai[i].reg = -1;
                ai[i].stack_bytes = 8;
                ai[i].struct_size = 0;
                ai[i].is_float = 0;
                stack_bytes += 8;
            }
        }

        // Keep stack 16B-aligned at call site.
        int pad = (stack_bytes & 15) ? 8 : 0;
        if (pad) {
            str_appendf(&cg->out, "  sub $8, %%rsp\n");
        }

        // Push stack args right-to-left.
        for (int i = e->nargs - 1; i >= 0; i--) {
            if (ai[i].kind != CALLARG_STACK_SCALAR) continue;
            cg_expr(cg, e->args[i]);
            const Expr *a = e->args[i];
            if (ai[i].is_float) {
                // Ensure upper bits are clear for 32-bit payload.
                str_appendf(&cg->out, "  mov %%eax, %%eax\n");
            } else if (a && a->ptr == 0 && a->lval_size == 4 && !a->is_unsigned &&
                       a->base != BT_LONG && a->base != BT_FLOAT && a->base != BT_STRUCT) {
                if (!(a->kind == EXPR_NUM && a->num >= 0 && a->num <= 0x7fffffffLL)) {
                    str_appendf(&cg->out, "  cdqe\n");
                }
            }
            str_appendf(&cg->out, "  push %%rax\n");
        }

        // Evaluate complex reg args: push.
        for (int i = 0; i < e->nargs; i++) {
            if (ai[i].kind != CALLARG_REG_INT && ai[i].kind != CALLARG_REG_XMM) continue;
            if (!expr_is_simple_arg(e->args[i])) {
                cg_expr(cg, e->args[i]);
                str_appendf(&cg->out, "  push %%rax\n");
            }
        }

        // Pop complex reg args into their ABI regs right-to-left.
        for (int i = e->nargs - 1; i >= 0; i--) {
            if (ai[i].kind != CALLARG_REG_INT && ai[i].kind != CALLARG_REG_XMM) continue;
            if (!expr_is_simple_arg(e->args[i])) {
                if (ai[i].kind == CALLARG_REG_INT) {
                    str_appendf_s(&cg->out, "  pop %s\n", areg[ai[i].reg]);
                } else {
                    str_appendf(&cg->out, "  pop %%rax\n");
                    str_appendf_i64(&cg->out, "  movd %%eax, %%xmm%lld\n", (long long)ai[i].reg);
                }
            }
        }

        // Load simple reg args directly.
        for (int i = 0; i < e->nargs; i++) {
            if (ai[i].kind != CALLARG_REG_INT && ai[i].kind != CALLARG_REG_XMM) continue;
            if (!expr_is_simple_arg(e->args[i])) continue;
            if (ai[i].kind == CALLARG_REG_INT) {
                cg_expr(cg, e->args[i]);
                str_appendf_s(&cg->out, "  mov %%rax, %s\n", areg[ai[i].reg]);
            } else {
                (void)cg_expr_to_reg_simple_arg(cg, e->args[i], "%rax", "%eax");
                str_appendf_i64(&cg->out, "  movd %%eax, %%xmm%lld\n", (long long)ai[i].reg);
            }
        }

        if (!e->lhs) die("internal: indirect call missing callee");
        cg_expr(cg, e->lhs);
        str_appendf(&cg->out, "  mov %%rax, %%r11\n");

        // SysV varargs ABI: %al holds the number of used XMM regs.
        if (xmm_used == 0) {
            str_appendf(&cg->out, "  xor %%eax, %%eax\n");
        } else {
            str_appendf_i64(&cg->out, "  mov $%d, %%eax\n", (long long)xmm_used);
        }
        str_appendf(&cg->out, "  call *%%r11\n");

        // If this call is used as a float expression, the return arrives in %xmm0.
        if (e->ptr == 0 && e->base == BT_FLOAT) {
            str_appendf(&cg->out, "  movd %%xmm0, %%eax\n");
        }

        if (stack_bytes > 0) {
            str_appendf_i64(&cg->out, "  add $%d, %%rsp\n", (long long)stack_bytes);
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

    // Determine when a signed 32-bit scalar argument must be sign-extended to 64-bit.
    // SysV ABI allows upper bits to be unspecified for <=32-bit integer args, so we can
    // skip extension when the callee parameter is 32-bit. But when the callee expects
    // a 64-bit integer (e.g. long/long long) and the argument expression is 32-bit,
    // we must extend to preserve negative values.
    int need_sext[64];
    for (int i = 0; i < e->nargs; i++) need_sext[i] = 0;
    const Function *callee_sig = NULL;
    if (cg->prg && e->callee[0] != 0) {
        callee_sig = program_find_fn(cg->prg, e->callee, mc_strlen(e->callee));
    }
    for (int i = 0; i < e->nargs; i++) {
        const Expr *a = e->args[i];
        if (!a) continue;
        if (!(a->ptr == 0 && a->lval_size == 4 && !a->is_unsigned &&
              a->base != BT_LONG && a->base != BT_FLOAT && a->base != BT_STRUCT)) {
            continue;
        }
        int want64 = 1; // conservative default when we don't know the signature
        if (callee_sig && i < callee_sig->nparams) {
            want64 = (callee_sig->param_sizes[i] == 8);
        }
        if (want64) need_sext[i] = 1;
    }

    int int_used = 0;
    int xmm_used = 0;
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
            ai[i].is_float = 0;
            stack_bytes += slot;
        } else if (a && a->ptr == 0 && a->base == BT_FLOAT) {
            if (xmm_used < 8) {
                ai[i].kind = CALLARG_REG_XMM;
                ai[i].reg = xmm_used++;
                ai[i].stack_bytes = 0;
                ai[i].struct_size = 0;
                ai[i].is_float = 1;
            } else {
                ai[i].kind = CALLARG_STACK_SCALAR;
                ai[i].reg = -1;
                ai[i].stack_bytes = 8;
                ai[i].struct_size = 0;
                ai[i].is_float = 1;
                stack_bytes += 8;
            }
        } else if (int_used < 6) {
            ai[i].kind = CALLARG_REG_INT;
            ai[i].reg = int_used++;
            ai[i].stack_bytes = 0;
            ai[i].struct_size = 0;
            ai[i].is_float = 0;
        } else {
            ai[i].kind = CALLARG_STACK_SCALAR;
            ai[i].reg = -1;
            ai[i].stack_bytes = 8;
            ai[i].struct_size = 0;
            ai[i].is_float = 0;
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
            const Expr *a = e->args[i];
            if (ai[i].is_float) {
                str_appendf(&cg->out, "  mov %%eax, %%eax\n");
            } else if (need_sext[i] && !(a && a->kind == EXPR_NUM && a->num >= 0 && a->num <= 0x7fffffffLL)) {
                str_appendf(&cg->out, "  cdqe\n");
            }
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
        if (ai[i].kind != CALLARG_REG_INT && ai[i].kind != CALLARG_REG_XMM) continue;
        if (!expr_is_simple_arg(e->args[i])) {
            cg_expr(cg, e->args[i]);
            str_appendf(&cg->out, "  push %%rax\n");
        }
    }
    // Pop complex args into registers right-to-left.
    for (int i = e->nargs - 1; i >= 0; i--) {
        if (ai[i].kind != CALLARG_REG_INT && ai[i].kind != CALLARG_REG_XMM) continue;
        if (!expr_is_simple_arg(e->args[i])) {
            if (ai[i].kind == CALLARG_REG_INT) {
                str_appendf_s(&cg->out, "  pop %s\n", areg[ai[i].reg]);
                const Expr *a = e->args[i];
                if (need_sext[i] && !(a && a->kind == EXPR_NUM && a->num >= 0 && a->num <= 0x7fffffffLL)) {
                    str_appendf_ss(&cg->out, "  movslq %s, %s\n", areg32[ai[i].reg], areg[ai[i].reg]);
                }
            } else {
                str_appendf(&cg->out, "  pop %%rax\n");
                str_appendf_i64(&cg->out, "  movd %%eax, %%xmm%lld\n", (long long)ai[i].reg);
            }
        }
    }
    // Load simple const args directly into target registers.
    for (int i = 0; i < e->nargs; i++) {
        if (ai[i].kind != CALLARG_REG_INT && ai[i].kind != CALLARG_REG_XMM) continue;
        if (!expr_is_simple_arg(e->args[i])) continue;
        if (ai[i].kind == CALLARG_REG_INT) {
            (void)cg_expr_to_reg_simple_arg(cg, e->args[i], areg[ai[i].reg], areg32[ai[i].reg]);
            const Expr *a = e->args[i];
            if (need_sext[i] && !(a && a->kind == EXPR_NUM && a->num >= 0 && a->num <= 0x7fffffffLL)) {
                str_appendf_ss(&cg->out, "  movslq %s, %s\n", areg32[ai[i].reg], areg[ai[i].reg]);
            }
        } else {
            (void)cg_expr_to_reg_simple_arg(cg, e->args[i], "%rax", "%eax");
            str_appendf_i64(&cg->out, "  movd %%eax, %%xmm%lld\n", (long long)ai[i].reg);
        }
    }

    // SysV varargs ABI: %al holds the number of used XMM regs.
    if (xmm_used == 0) {
        str_appendf(&cg->out, "  xor %%eax, %%eax\n");
    } else {
        str_appendf_i64(&cg->out, "  mov $%d, %%eax\n", (long long)xmm_used);
    }
    str_appendf_s(&cg->out, "  call %s\n", e->callee);

    // If this call is used as a float expression, the return arrives in %xmm0.
    if (e->ptr == 0 && e->base == BT_FLOAT) {
        str_appendf(&cg->out, "  movd %%xmm0, %%eax\n");
    }

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
    static const char *areg32[5] = {"%esi", "%edx", "%ecx", "%r8d", "%r9d"};
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
            ai[i].is_float = 0;
            stack_bytes += slot;
        } else if (reg_used < 5) {
            ai[i].kind = CALLARG_REG_INT;
            ai[i].reg = reg_used++;
            ai[i].stack_bytes = 0;
            ai[i].struct_size = 0;
            ai[i].is_float = 0;
        } else {
            ai[i].kind = CALLARG_STACK_SCALAR;
            ai[i].reg = -1;
            ai[i].stack_bytes = 8;
            ai[i].struct_size = 0;
            ai[i].is_float = 0;
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

    // Evaluate reg args: push complex ones, load simple ones directly at the end.
    for (int i = 0; i < e->nargs; i++) {
        if (ai[i].kind != CALLARG_REG_INT) continue;
        if (!expr_is_simple_arg(e->args[i])) {
            cg_expr(cg, e->args[i]);
            str_appendf(&cg->out, "  push %%rax\n");
        }
    }

    // Set sret pointer.
    str_appendf_i64(&cg->out, "  lea %d(%%rbp), %%rdi\n", e->var_offset);

    // Pop complex args into registers right-to-left.
    for (int i = e->nargs - 1; i >= 0; i--) {
        if (ai[i].kind != CALLARG_REG_INT) continue;
        if (!expr_is_simple_arg(e->args[i])) {
            str_appendf_s(&cg->out, "  pop %s\n", areg[ai[i].reg]);
        }
    }
    // Load simple args directly into target registers.
    for (int i = 0; i < e->nargs; i++) {
        if (ai[i].kind != CALLARG_REG_INT) continue;
        if (expr_is_simple_arg(e->args[i])) {
            (void)cg_expr_to_reg_simple_arg(cg, e->args[i], areg[ai[i].reg], areg32[ai[i].reg]);
        }
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

static int cg_cmp_imm(CG *cg, const Expr *e, long long imm, int is_lhs_const) {
    if (!e) return 0;
    if (!(e->kind == EXPR_EQ || e->kind == EXPR_NE ||
          e->kind == EXPR_LT || e->kind == EXPR_LE ||
          e->kind == EXPR_GT || e->kind == EXPR_GE)) {
        return 0;
    }

    const Expr *other = is_lhs_const ? e->rhs : e->lhs;
    int use32 = 0;
    if (other && other->ptr == 0 && other->base != BT_LONG && other->base != BT_FLOAT && other->base != BT_STRUCT) {
        if (other->lval_size == 4) use32 = 1;
    }

    // Evaluate the non-constant side into %rax/%eax.
    cg_expr(cg, other);

    if (imm == 0) {
        if (use32) str_appendf(&cg->out, "  test %%eax, %%eax\n");
        else str_appendf(&cg->out, "  test %%rax, %%rax\n");
    } else if (imm >= MC_I32_MIN && imm <= MC_I32_MAX) {
        if (use32) str_appendf_i64(&cg->out, "  cmp $%lld, %%eax\n", imm);
        else str_appendf_i64(&cg->out, "  cmp $%lld, %%rax\n", imm);
    } else {
        return 0;
    }

    int use_unsigned = 0;
    if (e->lhs && (e->lhs->ptr > 0 || e->lhs->is_unsigned)) use_unsigned = 1;
    if (e->rhs && (e->rhs->ptr > 0 || e->rhs->is_unsigned)) use_unsigned = 1;

    // Flags were computed for (%rax - imm). Choose cc for either:
    // - lhs OP rhs, when rhs is the immediate
    // - imm OP %rax, when lhs is the immediate (flip direction)
    const char *cc = "e";
    if (e->kind == EXPR_EQ) cc = "e";
    else if (e->kind == EXPR_NE) cc = "ne";
    else if (!is_lhs_const) {
        if (e->kind == EXPR_LT) {
            if (use_unsigned) cc = "b";
            else cc = "l";
        } else if (e->kind == EXPR_LE) {
            if (use_unsigned) cc = "be";
            else cc = "le";
        } else if (e->kind == EXPR_GT) {
            if (use_unsigned) cc = "a";
            else cc = "g";
        } else if (e->kind == EXPR_GE) {
            if (use_unsigned) cc = "ae";
            else cc = "ge";
        }
    } else {
        // imm OP %rax
        if (e->kind == EXPR_LT) {
            // imm < rhs  <=> rhs > imm
            if (use_unsigned) cc = "a";
            else cc = "g";
        } else if (e->kind == EXPR_LE) {
            // imm <= rhs <=> rhs >= imm
            if (use_unsigned) cc = "ae";
            else cc = "ge";
        } else if (e->kind == EXPR_GT) {
            // imm > rhs  <=> rhs < imm
            if (use_unsigned) cc = "b";
            else cc = "l";
        } else if (e->kind == EXPR_GE) {
            // imm >= rhs <=> rhs <= imm
            if (use_unsigned) cc = "be";
            else cc = "le";
        }
    }

    str_appendf_s(&cg->out, "  set%s %%al\n", cc);
    str_appendf(&cg->out, "  movzb %%al, %%eax\n");
    return 1;
}

static int cg_binop_imm_simple(CG *cg, const Expr *e, long long imm, int is_lhs_const) {
    if (!e) return 0;

    int use32 = 0;
    if (e->ptr == 0 && e->ptr_scale == 0 && e->base != BT_LONG && e->base != BT_FLOAT && e->base != BT_STRUCT) {
        if (e->lval_size == 4) use32 = 1;
    }

    const Expr *other = is_lhs_const ? e->rhs : e->lhs;

    // Add/sub/bitwise/mul immediate peepholes. (Shifts/div/mod have their own logic.)
    if (e->kind == EXPR_ADD) {
        if (!(imm >= MC_I32_MIN && imm <= MC_I32_MAX)) return 0;

        long long addimm = imm;
        if (e->ptr_scale > 0) {
            // For pointer arithmetic, only optimize when the immediate is on the index side.
            if ((is_lhs_const && e->ptr_index_side != 2) || (!is_lhs_const && e->ptr_index_side != 1)) return 0;
            addimm = imm * (long long)e->ptr_scale;
            if (addimm < MC_I32_MIN || addimm > MC_I32_MAX) return 0;
        }

        cg_expr(cg, other);
        if (addimm == 0) return 1;
        if (use32) {
            if (addimm == 1) str_appendf(&cg->out, "  inc %%eax\n");
            else if (addimm == -1) str_appendf(&cg->out, "  dec %%eax\n");
            else str_appendf_i64(&cg->out, "  add $%lld, %%eax\n", addimm);
        } else {
            if (addimm == 1) str_appendf(&cg->out, "  inc %%rax\n");
            else if (addimm == -1) str_appendf(&cg->out, "  dec %%rax\n");
            else str_appendf_i64(&cg->out, "  add $%lld, %%rax\n", addimm);
        }
        return 1;
    }

    if (e->kind == EXPR_SUB) {
        if (!(imm >= MC_I32_MIN && imm <= MC_I32_MAX)) return 0;

        if (is_lhs_const) {
            if (e->ptr_scale != 0) return 0;
            cg_expr(cg, other);
            if (use32) {
                str_appendf(&cg->out, "  neg %%eax\n");
                if (imm != 0) str_appendf_i64(&cg->out, "  add $%lld, %%eax\n", imm);
            } else {
                str_appendf(&cg->out, "  neg %%rax\n");
                if (imm != 0) str_appendf_i64(&cg->out, "  add $%lld, %%rax\n", imm);
            }
            return 1;
        }

        // rhs immediate
        if (e->ptr_scale > 0 && e->ptr_index_side != 1) return 0;
        long long subimm = imm;
        if (e->ptr_scale > 0) {
            subimm = imm * (long long)e->ptr_scale;
            if (subimm < MC_I32_MIN || subimm > MC_I32_MAX) return 0;
        }

        cg_expr(cg, other);
        if (subimm == 0) return 1;
        if (use32) {
            if (subimm == 1) str_appendf(&cg->out, "  dec %%eax\n");
            else if (subimm == -1) str_appendf(&cg->out, "  inc %%eax\n");
            else str_appendf_i64(&cg->out, "  sub $%lld, %%eax\n", subimm);
        } else {
            if (subimm == 1) str_appendf(&cg->out, "  dec %%rax\n");
            else if (subimm == -1) str_appendf(&cg->out, "  inc %%rax\n");
            else str_appendf_i64(&cg->out, "  sub $%lld, %%rax\n", subimm);
        }
        return 1;
    }

    if (!(imm >= MC_I32_MIN && imm <= MC_I32_MAX)) return 0;

    if (e->kind == EXPR_BAND) {
        cg_expr(cg, other);
        if (imm == -1) return 1;
        if (imm == 0) str_appendf(&cg->out, "  xor %%eax, %%eax\n");
        else if (use32) str_appendf_i64(&cg->out, "  and $%lld, %%eax\n", imm);
        else str_appendf_i64(&cg->out, "  and $%lld, %%rax\n", imm);
        return 1;
    }
    if (e->kind == EXPR_BOR) {
        cg_expr(cg, other);
        if (imm == 0) return 1;
        if (use32) str_appendf_i64(&cg->out, "  or $%lld, %%eax\n", imm);
        else str_appendf_i64(&cg->out, "  or $%lld, %%rax\n", imm);
        return 1;
    }
    if (e->kind == EXPR_BXOR) {
        cg_expr(cg, other);
        if (imm == 0) return 1;
        if (imm == -1) {
            if (use32) str_appendf(&cg->out, "  not %%eax\n");
            else str_appendf(&cg->out, "  not %%rax\n");
        } else {
            if (use32) str_appendf_i64(&cg->out, "  xor $%lld, %%eax\n", imm);
            else str_appendf_i64(&cg->out, "  xor $%lld, %%rax\n", imm);
        }
        return 1;
    }

    if (e->kind == EXPR_MUL && e->ptr_scale == 0) {
        cg_expr(cg, other);
        if (imm == 0) {
            str_appendf(&cg->out, "  xor %%eax, %%eax\n");
            return 1;
        }
        if (imm == 1) return 1;
        if (imm == -1) {
            if (use32) str_appendf(&cg->out, "  neg %%eax\n");
            else str_appendf(&cg->out, "  neg %%rax\n");
            return 1;
        }
        // Strength-reduce power-of-two multiplies for smaller code.
        long long mag = (imm < 0) ? -imm : imm;
        if (mag > 0 && mag <= 0x80000000LL) {
            int sh = u64_pow2_shift((unsigned long long)mag);
            if (sh > 0 && sh <= 31) {
                if (sh == 1) {
                    // Smaller than shl $1, %rax.
                    if (use32) str_appendf(&cg->out, "  add %%eax, %%eax\n");
                    else str_appendf(&cg->out, "  add %%rax, %%rax\n");
                } else {
                    if (use32) str_appendf_i64(&cg->out, "  shl $%d, %%eax\n", sh);
                    else str_appendf_i64(&cg->out, "  shl $%d, %%rax\n", sh);
                }
                if (imm < 0) {
                    if (use32) str_appendf(&cg->out, "  neg %%eax\n");
                    else str_appendf(&cg->out, "  neg %%rax\n");
                }
                return 1;
            }
        }
        if (use32) str_appendf_i64(&cg->out, "  imul $%lld, %%eax, %%eax\n", imm);
        else str_appendf_i64(&cg->out, "  imul $%lld, %%rax, %%rax\n", imm);
        return 1;
    }

    return 0;
}

static int cg_binop_mem_rhs(CG *cg, const Expr *e, int use32) {
    if (!cg || !e || !e->lhs || !e->rhs) return 0;
    if (e->ptr_scale != 0) return 0;

    // Only handle a plain stack/global scalar on RHS (no side effects).
    const Expr *rhs = e->rhs;
    if (!(rhs->kind == EXPR_VAR || rhs->kind == EXPR_GLOBAL)) return 0;
    if (rhs->lval_size == 0) return 0;
    if (!(rhs->lval_size == 4 || rhs->lval_size == 8)) return 0;

    // For now, only apply when RHS size matches the chosen op width.
    if (use32 && rhs->lval_size != 4) return 0;
    if (!use32 && rhs->lval_size != 8) return 0;

    // Compute lhs into %rax/%eax and then use a direct mem operand.
    cg_expr(cg, e->lhs);

    char mem[160];
    if (rhs->kind == EXPR_VAR) {
        int n = mc_snprint_cstr_i64_cstr(mem, sizeof(mem), "", (mc_i64)rhs->var_offset, "(%rbp)");
        if (n <= 0 || (mc_usize)n >= sizeof(mem)) return 0;
    } else {
        const GlobalVar *gv = &cg->prg->globals[rhs->global_id];
        int n = mc_snprint_cstr_cstr(mem, sizeof(mem), gv->name, "(%rip)");
        if (n <= 0 || (mc_usize)n >= sizeof(mem)) return 0;
    }

    switch (e->kind) {
        case EXPR_ADD:
            if (use32) str_appendf_s(&cg->out, "  add %s, %%eax\n", mem);
            else str_appendf_s(&cg->out, "  add %s, %%rax\n", mem);
            return 1;
        case EXPR_SUB:
            if (use32) str_appendf_s(&cg->out, "  sub %s, %%eax\n", mem);
            else str_appendf_s(&cg->out, "  sub %s, %%rax\n", mem);
            return 1;
        case EXPR_BAND:
            if (use32) str_appendf_s(&cg->out, "  and %s, %%eax\n", mem);
            else str_appendf_s(&cg->out, "  and %s, %%rax\n", mem);
            return 1;
        case EXPR_BXOR:
            if (use32) str_appendf_s(&cg->out, "  xor %s, %%eax\n", mem);
            else str_appendf_s(&cg->out, "  xor %s, %%rax\n", mem);
            return 1;
        case EXPR_BOR:
            if (use32) str_appendf_s(&cg->out, "  or %s, %%eax\n", mem);
            else str_appendf_s(&cg->out, "  or %s, %%rax\n", mem);
            return 1;
        case EXPR_MUL:
            if (use32) str_appendf_s(&cg->out, "  imul %s, %%eax\n", mem);
            else str_appendf_s(&cg->out, "  imul %s, %%rax\n", mem);
            return 1;
        case EXPR_EQ:
        case EXPR_NE:
        case EXPR_LT:
        case EXPR_LE:
        case EXPR_GT:
        case EXPR_GE:
        {
            if (use32) str_appendf_s(&cg->out, "  cmp %s, %%eax\n", mem);
            else str_appendf_s(&cg->out, "  cmp %s, %%rax\n", mem);

            int use_unsigned = 0;
            if (e->lhs && (e->lhs->ptr > 0 || e->lhs->is_unsigned)) use_unsigned = 1;
            if (e->rhs && (e->rhs->ptr > 0 || e->rhs->is_unsigned)) use_unsigned = 1;
            const char *cc = "e";
            if (e->kind == EXPR_EQ) cc = "e";
            else if (e->kind == EXPR_NE) cc = "ne";
            else if (e->kind == EXPR_LT) {
                if (use_unsigned) cc = "b";
                else cc = "l";
            } else if (e->kind == EXPR_LE) {
                if (use_unsigned) cc = "be";
                else cc = "le";
            } else if (e->kind == EXPR_GT) {
                if (use_unsigned) cc = "a";
                else cc = "g";
            } else if (e->kind == EXPR_GE) {
                if (use_unsigned) cc = "ae";
                else cc = "ge";
            }

            str_appendf_s(&cg->out, "  set%s %%al\n", cc);
            str_appendf(&cg->out, "  movzb %%al, %%eax\n");
            return 1;
        }
        default:
            break;
    }
    return 0;
}

// Helper: emit code for binary operations (arithmetic, bitwise, comparisons).
// Returns after emitting code - caller should return immediately after calling this.
static void cg_binop(CG *cg, const Expr *e) {
    int use32 = 0;
    if (e && e->ptr == 0 && e->ptr_scale == 0 && e->base != BT_VOID && e->base != BT_STRUCT && e->base != BT_FLOAT && e->base != BT_LONG) {
        if (e->lval_size == 4) use32 = 1;
    }

    // Float scalar ops: represent float values as raw 32-bit bits in integer registers.
    // When a binary op involves floats, lower it via SSE scalar instructions.
    // This is deliberately minimal: it supports register-only operations emitted by the compiler.
    if (e && e->ptr == 0 && (e->kind == EXPR_ADD || e->kind == EXPR_SUB || e->kind == EXPR_MUL || e->kind == EXPR_DIV)) {
        if ((e->lhs && e->lhs->ptr == 0 && e->lhs->base == BT_FLOAT) || (e->rhs && e->rhs->ptr == 0 && e->rhs->base == BT_FLOAT)) {
            // Common case in float-heavy code (e.g. mandelbrot): both operands are
            // simple scalars. Avoid push/pop by loading them into fixed regs.
            if (expr_is_simple_arg(e->lhs) && expr_is_simple_arg(e->rhs) &&
                cg_expr_to_reg_simple_arg_try(cg, e->lhs, "%rcx", "%ecx") &&
                cg_expr_to_reg_simple_arg_try(cg, e->rhs, "%rax", "%eax")) {
                // loaded
            } else {
                cg_expr(cg, e->lhs);
                str_appendf(&cg->out, "  push %%rax\n");
                cg_expr(cg, e->rhs);
                str_appendf(&cg->out, "  pop %%rcx\n");
            }

            // xmm1 = lhs, xmm0 = rhs (promote integers to float as needed)
            if (e->lhs && e->lhs->ptr == 0 && e->lhs->base == BT_FLOAT) {
                str_appendf(&cg->out, "  movd %%ecx, %%xmm1\n");
            } else {
                int lhs_sz = e->lhs ? type_sizeof(cg->prg, e->lhs->base, e->lhs->ptr, e->lhs->struct_id) : 8;
                if (lhs_sz == 4 && e->lhs && e->lhs->ptr == 0 && e->lhs->base != BT_LONG) {
                    str_appendf(&cg->out, "  cvtsi2ss %%ecx, %%xmm1\n");
                } else {
                    str_appendf(&cg->out, "  cvtsi2ss %%rcx, %%xmm1\n");
                }
            }
            if (e->rhs && e->rhs->ptr == 0 && e->rhs->base == BT_FLOAT) {
                str_appendf(&cg->out, "  movd %%eax, %%xmm0\n");
            } else {
                int rhs_sz = e->rhs ? type_sizeof(cg->prg, e->rhs->base, e->rhs->ptr, e->rhs->struct_id) : 8;
                if (rhs_sz == 4 && e->rhs && e->rhs->ptr == 0 && e->rhs->base != BT_LONG) {
                    str_appendf(&cg->out, "  cvtsi2ss %%eax, %%xmm0\n");
                } else {
                    str_appendf(&cg->out, "  cvtsi2ss %%rax, %%xmm0\n");
                }
            }

            if (e->kind == EXPR_ADD) {
                str_appendf(&cg->out, "  addss %%xmm0, %%xmm1\n");
            } else if (e->kind == EXPR_SUB) {
                str_appendf(&cg->out, "  subss %%xmm0, %%xmm1\n");
            } else if (e->kind == EXPR_MUL) {
                str_appendf(&cg->out, "  mulss %%xmm0, %%xmm1\n");
            } else {
                str_appendf(&cg->out, "  divss %%xmm0, %%xmm1\n");
            }

            // Result bits back to %eax
            str_appendf(&cg->out, "  movd %%xmm1, %%eax\n");
            return;
        }
    }

    if (e && (e->kind == EXPR_EQ || e->kind == EXPR_NE || e->kind == EXPR_LT || e->kind == EXPR_LE || e->kind == EXPR_GT || e->kind == EXPR_GE)) {
        if ((e->lhs && e->lhs->ptr == 0 && e->lhs->base == BT_FLOAT) || (e->rhs && e->rhs->ptr == 0 && e->rhs->base == BT_FLOAT)) {
            if (expr_is_simple_arg(e->lhs) && expr_is_simple_arg(e->rhs) &&
                cg_expr_to_reg_simple_arg_try(cg, e->lhs, "%rcx", "%ecx") &&
                cg_expr_to_reg_simple_arg_try(cg, e->rhs, "%rax", "%eax")) {
                // loaded
            } else {
                cg_expr(cg, e->lhs);
                str_appendf(&cg->out, "  push %%rax\n");
                cg_expr(cg, e->rhs);
                str_appendf(&cg->out, "  pop %%rcx\n");
            }

            // xmm1 = lhs, xmm0 = rhs (promote integers to float as needed)
            if (e->lhs && e->lhs->ptr == 0 && e->lhs->base == BT_FLOAT) {
                str_appendf(&cg->out, "  movd %%ecx, %%xmm1\n");
            } else {
                int lhs_sz = e->lhs ? type_sizeof(cg->prg, e->lhs->base, e->lhs->ptr, e->lhs->struct_id) : 8;
                if (lhs_sz == 4 && e->lhs && e->lhs->ptr == 0 && e->lhs->base != BT_LONG) {
                    str_appendf(&cg->out, "  cvtsi2ss %%ecx, %%xmm1\n");
                } else {
                    str_appendf(&cg->out, "  cvtsi2ss %%rcx, %%xmm1\n");
                }
            }
            if (e->rhs && e->rhs->ptr == 0 && e->rhs->base == BT_FLOAT) {
                str_appendf(&cg->out, "  movd %%eax, %%xmm0\n");
            } else {
                int rhs_sz = e->rhs ? type_sizeof(cg->prg, e->rhs->base, e->rhs->ptr, e->rhs->struct_id) : 8;
                if (rhs_sz == 4 && e->rhs && e->rhs->ptr == 0 && e->rhs->base != BT_LONG) {
                    str_appendf(&cg->out, "  cvtsi2ss %%eax, %%xmm0\n");
                } else {
                    str_appendf(&cg->out, "  cvtsi2ss %%rax, %%xmm0\n");
                }
            }
            str_appendf(&cg->out, "  ucomiss %%xmm0, %%xmm1\n");

            const char *cc = "e";
            if (e->kind == EXPR_EQ) cc = "e";
            else if (e->kind == EXPR_NE) cc = "ne";
            else if (e->kind == EXPR_LT) cc = "b";
            else if (e->kind == EXPR_LE) cc = "be";
            else if (e->kind == EXPR_GT) cc = "a";
            else if (e->kind == EXPR_GE) cc = "ae";

            str_appendf_s(&cg->out, "  set%s %%al\n", cc);
            str_appendf(&cg->out, "  movzb %%al, %%eax\n");
            return;
        }
    }

    // Peepholes for constant LHS: avoid push/pop and generate shorter immediates.
    // Safe because EXPR_NUM has no side effects.
    if (e->lhs && e->lhs->kind == EXPR_NUM) {
        long long imm = e->lhs->num;
        if (cg_cmp_imm(cg, e, imm, 1)) return;
        if (cg_binop_imm_simple(cg, e, imm, 1)) return;
    }

    // Peepholes for constant RHS.
    if (e->rhs && e->rhs->kind == EXPR_NUM) {
        long long imm = e->rhs->num;
        if (cg_cmp_imm(cg, e, imm, 0)) return;

        // Shifts: use immediate count when in range.
        if ((e->kind == EXPR_SHL || e->kind == EXPR_SHR) &&
            e->ptr_scale == 0 && imm >= 0 && imm <= 63) {
            cg_expr(cg, e->lhs);
            if (imm == 0) return;
            if (e->kind == EXPR_SHL) {
                if (imm == 1) {
                    // Smaller than shl $1, %rax.
                    if (use32) str_appendf(&cg->out, "  add %%eax, %%eax\n");
                    else str_appendf(&cg->out, "  add %%rax, %%rax\n");
                } else {
                    if (use32) str_appendf_i64(&cg->out, "  shl $%lld, %%eax\n", imm);
                    else str_appendf_i64(&cg->out, "  shl $%lld, %%rax\n", imm);
                }
            } else {
                if ((e->lhs && (e->lhs->ptr > 0 || e->lhs->is_unsigned)) ||
                    (e->rhs && (e->rhs->ptr > 0 || e->rhs->is_unsigned))) {
                    if (use32) str_appendf_i64(&cg->out, "  shr $%lld, %%eax\n", imm);
                    else str_appendf_i64(&cg->out, "  shr $%lld, %%rax\n", imm);
                } else {
                    if (use32) str_appendf_i64(&cg->out, "  sar $%lld, %%eax\n", imm);
                    else str_appendf_i64(&cg->out, "  sar $%lld, %%rax\n", imm);
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
            int use_unsigned = 0;
            if (e->lhs && (e->lhs->ptr > 0 || e->lhs->is_unsigned)) use_unsigned = 1;
            if (e->rhs && (e->rhs->ptr > 0 || e->rhs->is_unsigned)) use_unsigned = 1;
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

        if (cg_binop_imm_simple(cg, e, imm, 0)) return;
    }

    // Peepholes for a stack/global RHS: avoid push/pop by using a direct memory operand.
    if (cg_binop_mem_rhs(cg, e, use32)) return;

slow_binop:
    // General case: evaluate both operands, push/pop to get them in registers.
    cg_expr(cg, e->lhs);
    str_appendf(&cg->out, "  push %%rax\n");
    cg_expr(cg, e->rhs);
    str_appendf(&cg->out, "  pop %%rcx\n");
    if ((e->kind == EXPR_ADD || e->kind == EXPR_SUB) && e->ptr_scale > 0) {
        if (e->ptr_index_side == 1) {
            if (e->rhs && e->rhs->ptr == 0 && e->rhs->lval_size == 4 && !e->rhs->is_unsigned && e->rhs->base != BT_LONG && e->rhs->base != BT_FLOAT) {
                str_appendf(&cg->out, "  cdqe\n");
            }
            if (e->ptr_scale != 1) {
                str_appendf_i64(&cg->out, "  imul $%d, %%rax\n", e->ptr_scale);
            }
        } else if (e->ptr_index_side == 2) {
            if (e->lhs && e->lhs->ptr == 0 && e->lhs->lval_size == 4 && !e->lhs->is_unsigned && e->lhs->base != BT_LONG && e->lhs->base != BT_FLOAT) {
                str_appendf(&cg->out, "  movslq %%ecx, %%rcx\n");
            }
            if (e->ptr_scale != 1) {
                str_appendf_i64(&cg->out, "  imul $%d, %%rcx\n", e->ptr_scale);
            }
        }
    }
    switch (e->kind) {
        case EXPR_ADD:
            if (use32) str_appendf(&cg->out, "  add %%ecx, %%eax\n");
            else str_appendf(&cg->out, "  add %%rcx, %%rax\n");
            return;
        case EXPR_SUB:
            // rcx = lhs, rax = rhs => lhs - rhs
            if (use32) {
                str_appendf(&cg->out, "  sub %%eax, %%ecx\n");
                str_appendf(&cg->out, "  mov %%ecx, %%eax\n");
            } else {
                str_appendf(&cg->out, "  sub %%rax, %%rcx\n");
                str_appendf(&cg->out, "  mov %%rcx, %%rax\n");
            }
            return;
        case EXPR_BAND:
            if (use32) str_appendf(&cg->out, "  and %%ecx, %%eax\n");
            else str_appendf(&cg->out, "  and %%rcx, %%rax\n");
            return;
        case EXPR_BXOR:
            if (use32) str_appendf(&cg->out, "  xor %%ecx, %%eax\n");
            else str_appendf(&cg->out, "  xor %%rcx, %%rax\n");
            return;
        case EXPR_BOR:
            if (use32) str_appendf(&cg->out, "  or %%ecx, %%eax\n");
            else str_appendf(&cg->out, "  or %%rcx, %%rax\n");
            return;
        case EXPR_SHL:
            // rcx=lhs, rax=rhs(count)
            if (use32) {
                str_appendf(&cg->out, "  mov %%ecx, %%edx\n");
                str_appendf(&cg->out, "  mov %%al, %%cl\n");
                str_appendf(&cg->out, "  mov %%edx, %%eax\n");
                str_appendf(&cg->out, "  shl %%cl, %%eax\n");
            } else {
                str_appendf(&cg->out, "  mov %%rcx, %%rdx\n");
                str_appendf(&cg->out, "  mov %%al, %%cl\n");
                str_appendf(&cg->out, "  mov %%rdx, %%rax\n");
                str_appendf(&cg->out, "  shl %%cl, %%rax\n");
            }
            return;
        case EXPR_SHR:
            if (use32) {
                str_appendf(&cg->out, "  mov %%ecx, %%edx\n");
                str_appendf(&cg->out, "  mov %%al, %%cl\n");
                str_appendf(&cg->out, "  mov %%edx, %%eax\n");
                if ((e->lhs && (e->lhs->ptr > 0 || e->lhs->is_unsigned)) || (e->rhs && (e->rhs->ptr > 0 || e->rhs->is_unsigned))) {
                    str_appendf(&cg->out, "  shr %%cl, %%eax\n");
                } else {
                    str_appendf(&cg->out, "  sar %%cl, %%eax\n");
                }
            } else {
                str_appendf(&cg->out, "  mov %%rcx, %%rdx\n");
                str_appendf(&cg->out, "  mov %%al, %%cl\n");
                str_appendf(&cg->out, "  mov %%rdx, %%rax\n");
                if ((e->lhs && (e->lhs->ptr > 0 || e->lhs->is_unsigned)) || (e->rhs && (e->rhs->ptr > 0 || e->rhs->is_unsigned))) {
                    str_appendf(&cg->out, "  shr %%cl, %%rax\n");
                } else {
                    str_appendf(&cg->out, "  sar %%cl, %%rax\n");
                }
            }
            return;
        case EXPR_MUL:
            if (use32) str_appendf(&cg->out, "  imul %%ecx, %%eax\n");
            else str_appendf(&cg->out, "  imul %%rcx, %%rax\n");
            return;
        case EXPR_DIV:
        case EXPR_MOD:
            // Division/modulo (signed or unsigned)
            // rcx=lhs, rax=rhs currently
            if (use32) {
                str_appendf(&cg->out, "  mov %%eax, %%edi\n"); // rhs
                str_appendf(&cg->out, "  mov %%ecx, %%eax\n"); // lhs
                if ((e->lhs && (e->lhs->ptr > 0 || e->lhs->is_unsigned)) || (e->rhs && (e->rhs->ptr > 0 || e->rhs->is_unsigned))) {
                    str_appendf(&cg->out, "  xor %%edx, %%edx\n");
                    str_appendf(&cg->out, "  div %%edi\n");
                } else {
                    str_appendf(&cg->out, "  cdq\n");
                    str_appendf(&cg->out, "  idiv %%edi\n");
                }
                if (e->kind == EXPR_MOD) {
                    str_appendf(&cg->out, "  mov %%edx, %%eax\n");
                }
            } else {
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
            }
            return;
        case EXPR_EQ:
        case EXPR_NE:
        case EXPR_LT:
        case EXPR_LE:
        case EXPR_GT:
        case EXPR_GE:
        {
            // Compare lhs (rcx) vs rhs (rax) => setcc into al
            if (use32) str_appendf(&cg->out, "  cmp %%eax, %%ecx\n");
            else str_appendf(&cg->out, "  cmp %%rax, %%rcx\n");
            int use_unsigned = 0;
            if (e->lhs && (e->lhs->ptr > 0 || e->lhs->is_unsigned)) use_unsigned = 1;
            if (e->rhs && (e->rhs->ptr > 0 || e->rhs->is_unsigned)) use_unsigned = 1;
            const char *cc = "e";
            if (e->kind == EXPR_EQ) cc = "e";
            else if (e->kind == EXPR_NE) cc = "ne";
            else if (e->kind == EXPR_LT) {
                if (use_unsigned) cc = "b";
                else cc = "l";
            } else if (e->kind == EXPR_LE) {
                if (use_unsigned) cc = "be";
                else cc = "le";
            } else if (e->kind == EXPR_GT) {
                if (use_unsigned) cc = "a";
                else cc = "g";
            } else if (e->kind == EXPR_GE) {
                if (use_unsigned) cc = "ae";
                else cc = "ge";
            }
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
            if (e->ptr == 0 && e->base == BT_FLOAT) {
                mc_u32 bits = (mc_u32)e->num;
                if (bits == 0) {
                    str_appendf(&cg->out, "  xor %%eax, %%eax\n");
                } else {
                    str_appendf_u64(&cg->out, "  mov $%u, %%eax\n", (unsigned long long)bits);
                }
                return;
            }
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
            } else {
                emit_load_disp(cg, e->var_offset, "%rbp", e->lval_size, e->is_unsigned);
            }
            return;
        case EXPR_GLOBAL:
        {
            const GlobalVar *gv = &cg->prg->globals[e->global_id];
            // For arrays, return address; for scalars, load value
            if (e->lval_size == 0) {
                // Array decay: return address
                str_appendf_s(&cg->out, "  lea %s(%%rip), %%rax\n", gv->name);
            } else if (e->base == BT_STRUCT && e->ptr == 0 && e->lval_size > 8) {
                str_appendf_s(&cg->out, "  lea %s(%%rip), %%rax\n", gv->name);
            } else {
                int sz = (e->lval_size == 1 || e->lval_size == 2 || e->lval_size == 4 || e->lval_size == 8) ? e->lval_size : 8;
                emit_load_rip(cg, gv->name, sz, e->is_unsigned);
            }
            return;
        }
        case EXPR_STR:
            str_appendf_i64(&cg->out, "  lea .LC%d(%%rip), %%rax\n", e->str_id);
            return;
        case EXPR_ASSIGN:
            {
                if (!e->lhs) die("internal: assign missing lhs");

                // Fast paths: store directly to known memory locations.
                // This avoids materializing an address and saving/restoring it via push/pop.
                int sz = (e->lhs->lval_size > 0) ? e->lhs->lval_size : 8;
                if (sz == 1 || sz == 2 || sz == 4 || sz == 8) {
                    if (e->lhs->kind == EXPR_VAR) {
                        cg_expr(cg, e->rhs);
                        emit_store_disp(cg, e->lhs->var_offset, "%rbp", sz);
                        return;
                    }
                    if (e->lhs->kind == EXPR_GLOBAL) {
                        const GlobalVar *gv = &cg->prg->globals[e->lhs->global_id];
                        cg_expr(cg, e->rhs);
                        emit_store_rip(cg, gv->name, sz);
                        return;
                    }
                    if (e->lhs->kind == EXPR_MEMBER && !e->lhs->member_is_arrow && e->lhs->lhs) {
                        // Simple struct member of a local temporary/variable.
                        if (e->lhs->lhs->kind == EXPR_VAR || e->lhs->lhs->kind == EXPR_COMPOUND) {
                            int disp = e->lhs->lhs->var_offset + e->lhs->member_off;
                            cg_expr(cg, e->rhs);
                            emit_store_disp(cg, disp, "%rbp", sz);
                            return;
                        }
                    }

                    // base[const] = rhs where base is addressable without clobbering %rax.
                    if (e->lhs->kind == EXPR_INDEX && e->lhs->lhs && e->lhs->rhs && e->lhs->rhs->kind == EXPR_NUM) {
                        long long idx = e->lhs->rhs->num;
                        int scale = (e->lhs->ptr_scale > 0) ? e->lhs->ptr_scale : 8;
                        long long off = idx * (long long)scale;
                        // Only handle imm32 offsets.
                        if (off >= MC_I32_MIN && off <= MC_I32_MAX) {
                            const Expr *base = e->lhs->lhs;
                            if (base->kind == EXPR_COMPOUND) {
                                // Addressable stack object.
                                int disp = base->var_offset + (int)off;
                                cg_expr(cg, e->rhs);
                                emit_store_disp(cg, disp, "%rbp", sz);
                                return;
                            }
                            if (base->kind == EXPR_VAR) {
                                cg_expr(cg, e->rhs);
                                if (base->lval_size == 0) {
                                    // Local array: base is an addressable object.
                                    int disp = base->var_offset + (int)off;
                                    emit_store_disp(cg, disp, "%rbp", sz);
                                } else {
                                    // Pointer scalar: base is a pointer value stored in memory.
                                    str_appendf_i64(&cg->out, "  mov %d(%%rbp), %%rcx\n", base->var_offset);
                                    if (off != 0) {
                                        str_appendf_i64(&cg->out, "  add $%lld, %%rcx\n", off);
                                    }
                                    emit_store_mem(cg, "(%rcx)", sz);
                                }
                                return;
                            }
                            if (base->kind == EXPR_GLOBAL) {
                                const GlobalVar *gv = &cg->prg->globals[base->global_id];
                                cg_expr(cg, e->rhs);
                                if (base->lval_size == 0) {
                                    // Global array: addressable object.
                                    emit_store_rip_disp(cg, gv->name, (int)off, sz);
                                } else {
                                    // Global pointer scalar: load pointer value.
                                    str_appendf_s(&cg->out, "  mov %s(%%rip), %%rcx\n", gv->name);
                                    if (off != 0) {
                                        str_appendf_i64(&cg->out, "  add $%lld, %%rcx\n", off);
                                    }
                                    emit_store_mem(cg, "(%rcx)", sz);
                                }
                                return;
                            }
                        }
                    }
                }

                // Generic path: compute lvalue address, preserve it across rhs evaluation.
                sz = cg_lval_addr(cg, e->lhs);
                str_appendf(&cg->out, "  push %%rax\n");
                cg_expr(cg, e->rhs);
                str_appendf(&cg->out, "  pop %%rcx\n");
                emit_store_mem(cg, "(%rcx)", sz);
                return;
            }
        case EXPR_MEMCPY:
        {
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
        case EXPR_COND:
        {
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
            cg_normalize_scalar_result(cg, e);
            return;
        case EXPR_SRET_CALL:
            cg_sret_call(cg, e);
            return;
        case EXPR_COMPOUND:
            (void)cg_lval_addr(cg, e);
            return;
        case EXPR_POS:
            cg_expr(cg, e->lhs);
            cg_normalize_scalar_result(cg, e);
            return;
        case EXPR_NEG:
            cg_expr(cg, e->lhs);
            if (e->ptr == 0 && e->base == BT_FLOAT) {
                // Flip the sign bit of the IEEE-754 binary32 payload.
                str_appendf(&cg->out, "  xor $0x80000000, %%eax\n");
                cg_normalize_scalar_result(cg, e);
                return;
            }
            if (e->ptr == 0 && e->base != BT_FLOAT && e->base != BT_STRUCT) {
                int sz = type_sizeof(cg->prg, e->base, e->ptr, e->struct_id);
                if (sz == 4) {
                    str_appendf(&cg->out, "  neg %%eax\n");
                } else {
                    str_appendf(&cg->out, "  neg %%rax\n");
                }
            } else {
                str_appendf(&cg->out, "  neg %%rax\n");
            }
            cg_normalize_scalar_result(cg, e);
            return;
        case EXPR_NOT:
            cg_expr(cg, e->lhs);
            str_appendf(&cg->out, "  test %%rax, %%rax\n");
            str_appendf(&cg->out, "  sete %%al\n");
            str_appendf(&cg->out, "  movzb %%al, %%eax\n");
            return;
        case EXPR_BNOT:
            cg_expr(cg, e->lhs);
            if (e->ptr == 0 && e->base != BT_LONG && e->base != BT_FLOAT && e->base != BT_STRUCT && e->lval_size == 4) {
                str_appendf(&cg->out, "  not %%eax\n");
            } else {
                str_appendf(&cg->out, "  not %%rax\n");
            }
            cg_normalize_scalar_result(cg, e);
            return;
        case EXPR_CAST:
            if (e->ptr == 0 && e->base == BT_VOID) {
                cg_expr(cg, e->lhs);
                // Value is discarded; keep a well-defined register value.
                str_appendf(&cg->out, "  xor %%eax, %%eax\n");
                return;
            }

            // int -> float: convert and keep the raw IEEE-754 bits in %eax.
            if (e->ptr == 0 && e->base == BT_FLOAT) {
                if (e->lhs && e->lhs->ptr == 0 && e->lhs->base == BT_FLOAT) {
                    cg_expr(cg, e->lhs);
                    return;
                }

                cg_expr(cg, e->lhs);
                // Use the 32-bit form when the source is a 32-bit integer to preserve
                // signedness without relying on a prior sign-extension.
                int src_sz = 8;
                if (e->lhs) {
                    src_sz = type_sizeof(cg->prg, e->lhs->base, e->lhs->ptr, e->lhs->struct_id);
                }
                if (src_sz == 4 && e->lhs && e->lhs->ptr == 0 && e->lhs->base != BT_LONG) {
                    str_appendf(&cg->out, "  cvtsi2ss %%eax, %%xmm0\n");
                } else {
                    // cvtsi2ss r/m64, xmm (F3 REX.W 0F 2A /r)
                    str_appendf(&cg->out, "  cvtsi2ss %%rax, %%xmm0\n");
                }
                // movd xmm, r/m32 (66 0F 7E /r)
                str_appendf(&cg->out, "  movd %%xmm0, %%eax\n");
                return;
            }

            // float -> int: treat %eax as raw float bits, convert via SSE.
            if (e->lhs && e->lhs->ptr == 0 && e->lhs->base == BT_FLOAT) {
                cg_expr(cg, e->lhs);
                str_appendf(&cg->out, "  movd %%eax, %%xmm0\n");

                int dst_sz = 8;
                if (e->ptr > 0) {
                    die("cast float->ptr not supported");
                } else if (e->base == BT_CHAR) {
                    dst_sz = 1;
                } else if (e->base == BT_SHORT) {
                    dst_sz = 2;
                } else if (e->base == BT_INT) {
                    dst_sz = 4;
                } else if (e->base == BT_LONG) {
                    dst_sz = 8;
                }

                if (dst_sz == 8) {
                    str_appendf(&cg->out, "  cvttss2si %%xmm0, %%rax\n");
                } else {
                    str_appendf(&cg->out, "  cvttss2si %%xmm0, %%eax\n");
                }

                // Normalize to match destination integer type.
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
                    // cvttss2si to %eax already produces a 32-bit value.
                }
                return;
            }

            cg_expr(cg, e->lhs);
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

            int src_sz = 8;
            if (e->lhs) {
                src_sz = type_sizeof(cg->prg, e->lhs->base, e->lhs->ptr, e->lhs->struct_id);
            }

            // Widening casts to 64-bit now need explicit extension because we no longer
            // keep 32-bit signed values sign-extended in %rax.
            if (dst_sz == 8 && src_sz < 8) {
                if (src_sz == 1) {
                    if (e->lhs && (e->lhs->ptr > 0 || e->lhs->is_unsigned)) {
                        str_appendf(&cg->out, "  movzb %%al, %%eax\n");
                    } else {
                        str_appendf(&cg->out, "  movsbq %%al, %%rax\n");
                    }
                } else if (src_sz == 2) {
                    if (e->lhs && (e->lhs->ptr > 0 || e->lhs->is_unsigned)) {
                        str_appendf(&cg->out, "  movzw %%ax, %%eax\n");
                    } else {
                        str_appendf(&cg->out, "  movswq %%ax, %%rax\n");
                    }
                } else if (src_sz == 4) {
                    if (e->lhs && (e->lhs->ptr > 0 || e->lhs->is_unsigned)) {
                        // 32-bit values in %eax are already zero-extended into %rax.
                    } else {
                        str_appendf(&cg->out, "  cdqe\n");
                    }
                }
                return;
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
                // Truncating to 32-bit: only force a 32-bit write when the source
                // is wider than 32-bit (e.g. cast from long/pointer).
                if (src_sz > 4) {
                    str_appendf(&cg->out, "  mov %%eax, %%eax\n");
                }
            }
            return;
        case EXPR_PREINC:
        case EXPR_PREDEC:
        {
            int sz = cg_lval_addr(cg, e->lhs);
            if (sz != 1 && sz != 2 && sz != 4 && sz != 8) {
                die("pre ++/-- size %d not supported", sz);
            }
            // addr in %rax
            str_appendf(&cg->out, "  mov %%rax, %%rcx\n");
            emit_load_mem(cg, "(%rcx)", sz, e->is_unsigned);

            long long delta = (long long)(e->post_delta > 0 ? e->post_delta : 1);
            if (e->kind == EXPR_PREDEC) delta = -delta;

            if (sz == 4) {
                if (delta == 1) {
                    str_appendf(&cg->out, "  add $1, %%eax\n");
                } else if (delta == -1) {
                    str_appendf(&cg->out, "  sub $1, %%eax\n");
                } else if (delta > 0) {
                    str_appendf_i64(&cg->out, "  add $%lld, %%eax\n", delta);
                } else {
                    str_appendf_i64(&cg->out, "  sub $%lld, %%eax\n", -delta);
                }
            } else {
                if (delta == 1) {
                    str_appendf(&cg->out, "  add $1, %%rax\n");
                } else if (delta == -1) {
                    str_appendf(&cg->out, "  sub $1, %%rax\n");
                } else if (delta > 0) {
                    str_appendf_i64(&cg->out, "  add $%lld, %%rax\n", delta);
                } else {
                    str_appendf_i64(&cg->out, "  sub $%lld, %%rax\n", -delta);
                }
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
                // 32-bit ops already wrap and clear the high 32 bits.
            }

            emit_store_mem(cg, "(%rcx)", sz);
            // result is new value already in %rax
            return;
        }
        case EXPR_POSTINC:
        case EXPR_POSTDEC:
        {
            int sz = cg_lval_addr(cg, e->lhs);
            if (sz != 1 && sz != 2 && sz != 4 && sz != 8) {
                die("post ++/-- size %d not supported", sz);
            }
            // addr in %rax
            str_appendf(&cg->out, "  mov %%rax, %%rcx\n");
            emit_load_mem(cg, "(%rcx)", sz, e->is_unsigned);
            str_appendf(&cg->out, "  mov %%rax, %%rdx\n");

            long long delta = (long long)(e->post_delta > 0 ? e->post_delta : 1);
            if (e->kind == EXPR_POSTDEC) delta = -delta;

            if (sz == 4) {
                if (delta == 1) {
                    str_appendf(&cg->out, "  add $1, %%eax\n");
                } else if (delta == -1) {
                    str_appendf(&cg->out, "  sub $1, %%eax\n");
                } else if (delta > 0) {
                    str_appendf_i64(&cg->out, "  add $%lld, %%eax\n", delta);
                } else {
                    str_appendf_i64(&cg->out, "  sub $%lld, %%eax\n", -delta);
                }
            } else {
                if (delta == 1) {
                    str_appendf(&cg->out, "  add $1, %%rax\n");
                } else if (delta == -1) {
                    str_appendf(&cg->out, "  sub $1, %%rax\n");
                } else if (delta > 0) {
                    str_appendf_i64(&cg->out, "  add $%lld, %%rax\n", delta);
                } else {
                    str_appendf_i64(&cg->out, "  sub $%lld, %%rax\n", -delta);
                }
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
                // 32-bit ops already wrap and clear the high 32 bits.
            }

            emit_store_mem(cg, "(%rcx)", sz);
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
            emit_load_mem(cg, "(%rax)", e->lval_size, e->is_unsigned);
            return;
        case EXPR_INDEX:
            // Constant-index rvalue fast path for addressable objects.
            if (e->lval_size && e->lval_size <= 8 && e->lhs && e->rhs && e->rhs->kind == EXPR_NUM) {
                long long idx = e->rhs->num;
                int scale = 8;
                if (e->ptr_scale > 0) {
                    scale = e->ptr_scale;
                } else if (e->lval_size > 0) {
                    scale = e->lval_size;
                }
                long long off = idx * (long long)scale;
                if (off >= MC_I32_MIN && off <= MC_I32_MAX) {
                    const Expr *base = e->lhs;
                    if (base->kind == EXPR_COMPOUND) {
                        emit_load_disp(cg, base->var_offset + (int)off, "%rbp", e->lval_size, e->is_unsigned);
                        return;
                    }
                    if (base->kind == EXPR_VAR && base->lval_size == 0) {
                        emit_load_disp(cg, base->var_offset + (int)off, "%rbp", e->lval_size, e->is_unsigned);
                        return;
                    }
                    if (base->kind == EXPR_GLOBAL && base->lval_size == 0) {
                        const GlobalVar *gv = &cg->prg->globals[base->global_id];
                        emit_load_rip_disp(cg, gv->name, (int)off, e->lval_size, e->is_unsigned);
                        return;
                    }
                }
            }
            // rvalue load via computed address
            (void)cg_lval_addr(cg, e);
            if (e->lval_size == 0 || e->lval_size > 8) {
                return;
            }
            emit_load_mem(cg, "(%rax)", e->lval_size, e->is_unsigned);
            return;
        case EXPR_MEMBER:
            // Member rvalue fast path for non-arrow members of addressable objects.
            if (!e->member_is_arrow && e->lval_size && e->lval_size <= 8 && e->lhs) {
                const Expr *base = e->lhs;
                int off = e->member_off;
                if (base->kind == EXPR_VAR) {
                    emit_load_disp(cg, base->var_offset + off, "%rbp", e->lval_size, e->is_unsigned);
                    return;
                }
                if (base->kind == EXPR_COMPOUND) {
                    emit_load_disp(cg, base->var_offset + off, "%rbp", e->lval_size, e->is_unsigned);
                    return;
                }
                if (base->kind == EXPR_GLOBAL) {
                    const GlobalVar *gv = &cg->prg->globals[base->global_id];
                    emit_load_rip_disp(cg, gv->name, off, e->lval_size, e->is_unsigned);
                    return;
                }
            }
            // rvalue load via computed address
            (void)cg_lval_addr(cg, e);
            if (e->lval_size == 0 || e->lval_size > 8) {
                return;
            }
            emit_load_mem(cg, "(%rax)", e->lval_size, e->is_unsigned);
            return;
        case EXPR_LAND:
        {
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
        case EXPR_LOR:
        {
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
            cg_normalize_scalar_result(cg, e);
            return;
        default:
            break;
    }
    die("internal: unhandled expr kind");
}

static void cg_normalize_scalar_result(CG *cg, const Expr *e) {
    if (!e) return;
    if (e->ptr > 0) return;
    if (e->base == BT_VOID || e->base == BT_STRUCT) return;

    // Keep the value in %rax consistent with the expression's type.
    // This is important for correct 32-bit wraparound arithmetic (e.g. SHA-256).
    if (e->lval_size == 1) {
        if (e->is_unsigned) {
            str_appendf(&cg->out, "  movzb %%al, %%eax\n");
        } else {
            str_appendf(&cg->out, "  movsbq %%al, %%rax\n");
        }
    } else if (e->lval_size == 2) {
        if (e->is_unsigned) {
            str_appendf(&cg->out, "  movzw %%ax, %%eax\n");
        } else {
            str_appendf(&cg->out, "  movswq %%ax, %%rax\n");
        }
    } else if (e->lval_size == 4) {
        // 32-bit ops already wrap and keep %rax zero-extended.
    }
}

// Emit a conditional branch for a comparison expression.
// If jump_on_false, jump to label when condition is false; otherwise jump when true.
// Returns 1 if handled (optimized path), 0 if caller should use cg_expr + test.
static int cg_cond_branch(CG *cg, const Expr *e, int label, int jump_on_false) {
    if (!e) return 0;

    // Constant conditions: resolve at compile-time.
    if (e->kind == EXPR_NUM) {
        int is_true = (e->num != 0);
        if ((jump_on_false && !is_true) || (!jump_on_false && is_true)) {
            str_appendf_i64(&cg->out, "  jmp .L%d\n", (long long)label);
        }
        return 1;
    }

    // Casts do not affect zero/non-zero truthiness; skip them for branching.
    if (e->kind == EXPR_CAST || e->kind == EXPR_POS) {
        if (e->lhs) return cg_cond_branch(cg, e->lhs, label, jump_on_false);
    }

    // Logical NOT: invert the sense.
    if (e->kind == EXPR_NOT) {
        if (e->lhs) return cg_cond_branch(cg, e->lhs, label, !jump_on_false);
        return 0;
    }

    // Short-circuit logical AND.
    if (e->kind == EXPR_LAND) {
        if (jump_on_false) {
            // Jump to label if either side is false.
            if (!cg_cond_branch(cg, e->lhs, label, 1)) {
                cg_expr(cg, e->lhs);
                str_appendf(&cg->out, "  test %%rax, %%rax\n");
                str_appendf_i64(&cg->out, "  jz .L%d\n", (long long)label);
            }
            if (!cg_cond_branch(cg, e->rhs, label, 1)) {
                cg_expr(cg, e->rhs);
                str_appendf(&cg->out, "  test %%rax, %%rax\n");
                str_appendf_i64(&cg->out, "  jz .L%d\n", (long long)label);
            }
            return 1;
        }
        // Jump to label if both sides are true.
        int l_false = new_label(cg);
        if (!cg_cond_branch(cg, e->lhs, l_false, 1)) {
            cg_expr(cg, e->lhs);
            str_appendf(&cg->out, "  test %%rax, %%rax\n");
            str_appendf_i64(&cg->out, "  jz .L%d\n", (long long)l_false);
        }
        if (!cg_cond_branch(cg, e->rhs, l_false, 1)) {
            cg_expr(cg, e->rhs);
            str_appendf(&cg->out, "  test %%rax, %%rax\n");
            str_appendf_i64(&cg->out, "  jz .L%d\n", (long long)l_false);
        }
        str_appendf_i64(&cg->out, "  jmp .L%d\n", (long long)label);
        str_appendf_i64(&cg->out, ".L%d:\n", (long long)l_false);
        return 1;
    }

    // Short-circuit logical OR.
    if (e->kind == EXPR_LOR) {
        if (jump_on_false) {
            // Jump to label only if both sides are false.
            int l_end = new_label(cg);
            // If LHS is true, skip RHS.
            if (!cg_cond_branch(cg, e->lhs, l_end, 0)) {
                cg_expr(cg, e->lhs);
                str_appendf(&cg->out, "  test %%rax, %%rax\n");
                str_appendf_i64(&cg->out, "  jnz .L%d\n", (long long)l_end);
            }
            if (!cg_cond_branch(cg, e->rhs, label, 1)) {
                cg_expr(cg, e->rhs);
                str_appendf(&cg->out, "  test %%rax, %%rax\n");
                str_appendf_i64(&cg->out, "  jz .L%d\n", (long long)label);
            }
            str_appendf_i64(&cg->out, ".L%d:\n", (long long)l_end);
            return 1;
        }
        // Jump to label if either side is true.
        if (cg_cond_branch(cg, e->lhs, label, 0)) {
            // handled
        } else {
            cg_expr(cg, e->lhs);
            str_appendf(&cg->out, "  test %%rax, %%rax\n");
            str_appendf_i64(&cg->out, "  jnz .L%d\n", (long long)label);
        }
        if (cg_cond_branch(cg, e->rhs, label, 0)) {
            // handled
        } else {
            cg_expr(cg, e->rhs);
            str_appendf(&cg->out, "  test %%rax, %%rax\n");
            str_appendf_i64(&cg->out, "  jnz .L%d\n", (long long)label);
        }
        return 1;
    }

    // Conditional operator: branch on the selected arm.
    if (e->kind == EXPR_COND) {
        int l_else = new_label(cg);
        int l_end = new_label(cg);
        if (!cg_cond_branch(cg, e->lhs, l_else, 1)) {
            cg_expr(cg, e->lhs);
            str_appendf(&cg->out, "  test %%rax, %%rax\n");
            str_appendf_i64(&cg->out, "  jz .L%d\n", (long long)l_else);
        }
        // then arm
        if (!cg_cond_branch(cg, e->rhs, label, jump_on_false)) {
            cg_expr(cg, e->rhs);
            str_appendf(&cg->out, "  test %%rax, %%rax\n");
            str_appendf_si(&cg->out, "  %s .L%d\n", jump_on_false ? "jz" : "jnz", (long long)label);
        }
        str_appendf_i64(&cg->out, "  jmp .L%d\n", (long long)l_end);
        str_appendf_i64(&cg->out, ".L%d:\n", (long long)l_else);
        // else arm
        if (!cg_cond_branch(cg, e->third, label, jump_on_false)) {
            cg_expr(cg, e->third);
            str_appendf(&cg->out, "  test %%rax, %%rax\n");
            str_appendf_si(&cg->out, "  %s .L%d\n", jump_on_false ? "jz" : "jnz", (long long)label);
        }
        str_appendf_i64(&cg->out, ".L%d:\n", (long long)l_end);
        return 1;
    }

    // Handle comparison expressions directly.
    if (expr_is_comparison(e)) {
        // Float comparisons: branch directly using SSE flags from ucomiss.
        // Must handle unordered (NaN): all ordered comparisons are false, != is true.
        if ((e->lhs && e->lhs->ptr == 0 && e->lhs->base == BT_FLOAT) ||
            (e->rhs && e->rhs->ptr == 0 && e->rhs->base == BT_FLOAT)) {
            int lhs_in_ecx = 1;  // default for push/pop fallback: lhs in %ecx, rhs in %eax

            if (expr_is_simple_arg(e->lhs) && expr_is_simple_arg(e->rhs) &&
                cg_expr_to_reg_simple_arg_try(cg, e->lhs, "%rcx", "%ecx") &&
                cg_expr_to_reg_simple_arg_try(cg, e->rhs, "%rax", "%eax")) {
                lhs_in_ecx = 1;
            } else {
                mc_usize old_len = cg->out.len;

                // Try: compute LHS (possibly complex) into %eax, load RHS as simple into %ecx.
                cg_expr(cg, e->lhs);
                if (cg_expr_to_reg_simple_arg_try(cg, e->rhs, "%rcx", "%ecx")) {
                    lhs_in_ecx = 0; // lhs in %eax, rhs in %ecx
                } else {
                    // Roll back and try the other direction.
                    cg->out.len = old_len;
                    if (cg->out.buf) cg->out.buf[old_len] = 0;

                    cg_expr(cg, e->rhs);
                    if (cg_expr_to_reg_simple_arg_try(cg, e->lhs, "%rcx", "%ecx")) {
                        lhs_in_ecx = 1; // lhs in %ecx, rhs in %eax
                    } else {
                        // Roll back and use the conservative push/pop evaluation.
                        cg->out.len = old_len;
                        if (cg->out.buf) cg->out.buf[old_len] = 0;

                        cg_expr(cg, e->lhs);
                        str_appendf(&cg->out, "  push %%rax\n");
                        cg_expr(cg, e->rhs);
                        str_appendf(&cg->out, "  pop %%rcx\n");
                        lhs_in_ecx = 1;
                    }
                }
            }

            const char *lhs32 = lhs_in_ecx ? "%ecx" : "%eax";
            const char *lhs64 = lhs_in_ecx ? "%rcx" : "%rax";
            const char *rhs32 = lhs_in_ecx ? "%eax" : "%ecx";
            const char *rhs64 = lhs_in_ecx ? "%rax" : "%rcx";

            // xmm1 = lhs, xmm0 = rhs (promote integers to float as needed)
            if (e->lhs && e->lhs->ptr == 0 && e->lhs->base == BT_FLOAT) {
                str_appendf_s(&cg->out, "  movd %s, %%xmm1\n", lhs32);
            } else {
                int lhs_sz = e->lhs ? type_sizeof(cg->prg, e->lhs->base, e->lhs->ptr, e->lhs->struct_id) : 8;
                if (lhs_sz == 4 && e->lhs && e->lhs->ptr == 0 && e->lhs->base != BT_LONG) {
                    str_appendf_s(&cg->out, "  cvtsi2ss %s, %%xmm1\n", lhs32);
                } else {
                    str_appendf_s(&cg->out, "  cvtsi2ss %s, %%xmm1\n", lhs64);
                }
            }
            if (e->rhs && e->rhs->ptr == 0 && e->rhs->base == BT_FLOAT) {
                str_appendf_s(&cg->out, "  movd %s, %%xmm0\n", rhs32);
            } else {
                int rhs_sz = e->rhs ? type_sizeof(cg->prg, e->rhs->base, e->rhs->ptr, e->rhs->struct_id) : 8;
                if (rhs_sz == 4 && e->rhs && e->rhs->ptr == 0 && e->rhs->base != BT_LONG) {
                    str_appendf_s(&cg->out, "  cvtsi2ss %s, %%xmm0\n", rhs32);
                } else {
                    str_appendf_s(&cg->out, "  cvtsi2ss %s, %%xmm0\n", rhs64);
                }
            }
            str_appendf(&cg->out, "  ucomiss %%xmm0, %%xmm1\n");

            const char *jcc = "je";
            int need_skip = 0;
            if (jump_on_false) {
                if (e->kind == EXPR_EQ) {
                    // false if unordered or not equal
                    str_appendf_i64(&cg->out, "  jp .L%d\n", (long long)label);
                    jcc = "jne";
                } else if (e->kind == EXPR_NE) {
                    // false only if ordered and equal
                    need_skip = 1;
                    jcc = "je";
                } else if (e->kind == EXPR_LT) {
                    // false if unordered or >=
                    str_appendf_i64(&cg->out, "  jp .L%d\n", (long long)label);
                    jcc = "jae";
                } else if (e->kind == EXPR_LE) {
                    // false if unordered or >
                    str_appendf_i64(&cg->out, "  jp .L%d\n", (long long)label);
                    jcc = "ja";
                } else if (e->kind == EXPR_GT) {
                    // false if <= or unordered (unordered satisfies jbe)
                    jcc = "jbe";
                } else if (e->kind == EXPR_GE) {
                    // false if < or unordered (unordered satisfies jb)
                    jcc = "jb";
                }
            } else {
                if (e->kind == EXPR_EQ) {
                    // true only if ordered and equal
                    need_skip = 1;
                    jcc = "je";
                } else if (e->kind == EXPR_NE) {
                    // true if unordered or not equal
                    str_appendf_i64(&cg->out, "  jp .L%d\n", (long long)label);
                    jcc = "jne";
                } else if (e->kind == EXPR_LT) {
                    // true only if ordered and <
                    need_skip = 1;
                    jcc = "jb";
                } else if (e->kind == EXPR_LE) {
                    // true only if ordered and <=
                    need_skip = 1;
                    jcc = "jbe";
                } else if (e->kind == EXPR_GT) {
                    // true if > (unordered does not satisfy ja)
                    jcc = "ja";
                } else if (e->kind == EXPR_GE) {
                    // true if >= (unordered does not satisfy jae)
                    jcc = "jae";
                }
            }

            if (need_skip) {
                int l_skip = new_label(cg);
                str_appendf_i64(&cg->out, "  jp .L%d\n", (long long)l_skip);
                str_appendf_si(&cg->out, "  %s .L%d\n", jcc, (long long)label);
                str_appendf_i64(&cg->out, ".L%d:\n", (long long)l_skip);
            } else {
                str_appendf_si(&cg->out, "  %s .L%d\n", jcc, (long long)label);
            }
            return 1;
        }

        int use_unsigned = 0;
        if (e->lhs && (e->lhs->ptr > 0 || e->lhs->is_unsigned)) use_unsigned = 1;
        if (e->rhs && (e->rhs->ptr > 0 || e->rhs->is_unsigned)) use_unsigned = 1;

        int lhs_i32 = (e->lhs && e->lhs->ptr == 0 && e->lhs->base != BT_LONG &&
                       e->lhs->base != BT_FLOAT && e->lhs->base != BT_STRUCT &&
                       e->lhs->lval_size == 4);
        int rhs_i32 = (e->rhs && e->rhs->ptr == 0 && e->rhs->base != BT_LONG &&
                       e->rhs->base != BT_FLOAT && e->rhs->base != BT_STRUCT &&
                       e->rhs->lval_size == 4);
        int cmp_i32 = lhs_i32 && rhs_i32;
        int lhs_i32_signed = lhs_i32 && e->lhs && !e->lhs->is_unsigned;
        int rhs_i32_signed = rhs_i32 && e->rhs && !e->rhs->is_unsigned;
        int lhs_is64 = (e->lhs && (e->lhs->ptr > 0 || e->lhs->base == BT_LONG));
        int rhs_is64 = (e->rhs && (e->rhs->ptr > 0 || e->rhs->base == BT_LONG));

        // Constant RHS (common: x == 0, x < 0, ...). Only use immediates that fit.
        if (e->rhs && e->rhs->kind == EXPR_NUM) {
            long long imm = e->rhs->num;
            int use32 = lhs_i32;
            int use64 = !use32 && lhs_is64;

            // Common zero-compare branch peepholes.
            // For signed compares, `test` gives SF/ZF with OF=0, enabling js/jns/jle/jg.
            // For unsigned compares against 0, many outcomes are constant.
            if ((imm == 0) && (use32 || use64)) {
                cg_expr(cg, e->lhs);
                if (use32) str_appendf(&cg->out, "  test %%eax, %%eax\n");
                else str_appendf(&cg->out, "  test %%rax, %%rax\n");

                // Unsigned/pointer comparisons against 0.
                // NOTE: For the imm==0 peephole, decide based on the LHS only.
                // This avoids self-hosted miscompilations where the broader
                // use_unsigned computation can become unreliable, which would
                // incorrectly treat signed `x >= 0` as an unsigned tautology.
                int lhs_unsignedish = 0;
                if (e->lhs && (e->lhs->ptr > 0 || e->lhs->is_unsigned)) lhs_unsignedish = 1;
                if (lhs_unsignedish) {
                    // x < 0  -> false
                    // x >= 0 -> true
                    if (e->kind == EXPR_LT || e->kind == EXPR_GE) {
                        int always_true = (e->kind == EXPR_GE);
                        if ((!jump_on_false && always_true) || (jump_on_false && !always_true)) {
                            str_appendf_i64(&cg->out, "  jmp .L%d\n", (long long)label);
                        }
                        return 1;
                    }

                    // x <= 0 -> x == 0
                    // x > 0  -> x != 0
                    const char *jcc = "jz";
                    if (e->kind == EXPR_LE) {
                        jcc = jump_on_false ? "jnz" : "jz";
                    } else if (e->kind == EXPR_GT) {
                        jcc = jump_on_false ? "jz" : "jnz";
                    } else if (e->kind == EXPR_EQ) {
                        jcc = jump_on_false ? "jnz" : "jz";
                    } else if (e->kind == EXPR_NE) {
                        jcc = jump_on_false ? "jz" : "jnz";
                    } else {
                        // EXPR_LE/GT/EQ/NE handled; LT/GE returned above.
                        jcc = "jz";
                    }
                    str_appendf_si(&cg->out, "  %s .L%d\n", jcc, (long long)label);
                    return 1;
                }

                // Signed compares against 0.
                if (e->kind == EXPR_EQ || e->kind == EXPR_NE) {
                    const char *jcc = "je";
                    if (jump_on_false) {
                        jcc = (e->kind == EXPR_EQ) ? "jne" : "je";
                    } else {
                        jcc = (e->kind == EXPR_EQ) ? "je" : "jne";
                    }
                    str_appendf_si(&cg->out, "  %s .L%d\n", jcc, (long long)label);
                    return 1;
                }
                if (e->kind == EXPR_LT) {
                    str_appendf_si(&cg->out, "  %s .L%d\n", jump_on_false ? "jge" : "jl", (long long)label);
                    return 1;
                }
                if (e->kind == EXPR_GE) {
                    str_appendf_si(&cg->out, "  %s .L%d\n", jump_on_false ? "jl" : "jge", (long long)label);
                    return 1;
                }
                if (e->kind == EXPR_LE) {
                    str_appendf_si(&cg->out, "  %s .L%d\n", jump_on_false ? "jg" : "jle", (long long)label);
                    return 1;
                }
                if (e->kind == EXPR_GT) {
                    str_appendf_si(&cg->out, "  %s .L%d\n", jump_on_false ? "jle" : "jg", (long long)label);
                    return 1;
                }
            }

            if ((imm == 0) && (e->kind == EXPR_EQ || e->kind == EXPR_NE) && (use32 || use64)) {
                cg_expr(cg, e->lhs);
                if (use32) str_appendf(&cg->out, "  test %%eax, %%eax\n");
                else str_appendf(&cg->out, "  test %%rax, %%rax\n");

                const char *jcc = "je";
                if (jump_on_false) {
                    jcc = (e->kind == EXPR_EQ) ? "jne" : "je";
                } else {
                    jcc = (e->kind == EXPR_EQ) ? "je" : "jne";
                }
                str_appendf_si(&cg->out, "  %s .L%d\n", jcc, (long long)label);
                return 1;
            }

            if ((imm >= MC_I32_MIN && imm <= MC_I32_MAX) && (use32 || use64)) {
                cg_expr(cg, e->lhs);
                if (use32) str_appendf_i64(&cg->out, "  cmp $%lld, %%eax\n", imm);
                else str_appendf_i64(&cg->out, "  cmp $%lld, %%rax\n", imm);

                const char *jcc = "je";
                if (jump_on_false) {
                    if (e->kind == EXPR_EQ) jcc = "jne";
                    else if (e->kind == EXPR_NE) jcc = "je";
                    else if (e->kind == EXPR_LT) {
                        if (use_unsigned) jcc = "jae";
                        else jcc = "jge";
                    } else if (e->kind == EXPR_LE) {
                        if (use_unsigned) jcc = "ja";
                        else jcc = "jg";
                    } else if (e->kind == EXPR_GT) {
                        if (use_unsigned) jcc = "jbe";
                        else jcc = "jle";
                    } else if (e->kind == EXPR_GE) {
                        if (use_unsigned) jcc = "jb";
                        else jcc = "jl";
                    }
                } else {
                    if (e->kind == EXPR_EQ) jcc = "je";
                    else if (e->kind == EXPR_NE) jcc = "jne";
                    else if (e->kind == EXPR_LT) {
                        if (use_unsigned) jcc = "jb";
                        else jcc = "jl";
                    } else if (e->kind == EXPR_LE) {
                        if (use_unsigned) jcc = "jbe";
                        else jcc = "jle";
                    } else if (e->kind == EXPR_GT) {
                        if (use_unsigned) jcc = "ja";
                        else jcc = "jg";
                    } else if (e->kind == EXPR_GE) {
                        if (use_unsigned) jcc = "jae";
                        else jcc = "jge";
                    }
                }
                str_appendf_si(&cg->out, "  %s .L%d\n", jcc, (long long)label);
                return 1;
            }
        }

        // Fast path: RHS is a plain stack/global scalar memory operand.
        if (e->rhs && (e->rhs->kind == EXPR_VAR || e->rhs->kind == EXPR_GLOBAL) &&
            (e->rhs->lval_size == 4 || e->rhs->lval_size == 8) && e->ptr_scale == 0) {
            char mem[160];
            int have_mem = 0;
            if (e->rhs->kind == EXPR_VAR) {
                int n = mc_snprint_cstr_i64_cstr(mem, sizeof(mem), "", (mc_i64)e->rhs->var_offset, "(%rbp)");
                have_mem = (n > 0 && (mc_usize)n < sizeof(mem));
            } else {
                const GlobalVar *gv = &cg->prg->globals[e->rhs->global_id];
                int n = mc_snprint_cstr_cstr(mem, sizeof(mem), gv->name, "(%rip)");
                have_mem = (n > 0 && (mc_usize)n < sizeof(mem));
            }

            if (have_mem) {
                int can_cmp32 = cmp_i32 && e->rhs->lval_size == 4;
                int can_cmp64 = lhs_is64 && e->rhs->lval_size == 8;
                if (can_cmp32 || can_cmp64) {
                    cg_expr(cg, e->lhs);
                    if (can_cmp64) str_appendf_s(&cg->out, "  cmp %s, %%rax\n", mem);
                    else str_appendf_s(&cg->out, "  cmp %s, %%eax\n", mem);

                    const char *jcc = "je";
                    if (jump_on_false) {
                        if (e->kind == EXPR_EQ) jcc = "jne";
                        else if (e->kind == EXPR_NE) jcc = "je";
                        else if (e->kind == EXPR_LT) {
                            if (use_unsigned) jcc = "jae";
                            else jcc = "jge";
                        } else if (e->kind == EXPR_LE) {
                            if (use_unsigned) jcc = "ja";
                            else jcc = "jg";
                        } else if (e->kind == EXPR_GT) {
                            if (use_unsigned) jcc = "jbe";
                            else jcc = "jle";
                        } else if (e->kind == EXPR_GE) {
                            if (use_unsigned) jcc = "jb";
                            else jcc = "jl";
                        }
                    } else {
                        if (e->kind == EXPR_EQ) jcc = "je";
                        else if (e->kind == EXPR_NE) jcc = "jne";
                        else if (e->kind == EXPR_LT) {
                            if (use_unsigned) jcc = "jb";
                            else jcc = "jl";
                        } else if (e->kind == EXPR_LE) {
                            if (use_unsigned) jcc = "jbe";
                            else jcc = "jle";
                        } else if (e->kind == EXPR_GT) {
                            if (use_unsigned) jcc = "ja";
                            else jcc = "jg";
                        } else if (e->kind == EXPR_GE) {
                            if (use_unsigned) jcc = "jae";
                            else jcc = "jge";
                        }
                    }
                    str_appendf_si(&cg->out, "  %s .L%d\n", jcc, (long long)label);
                    return 1;
                }
            }
        }

        // Fast path: avoid push/pop if either side can be loaded as a simple arg.
        // This is especially common around loops and call-result compares.
        {
            mc_usize old_len = cg->out.len;

            int lhs_trivial = (e->lhs && (e->lhs->kind == EXPR_VAR || e->lhs->kind == EXPR_GLOBAL ||
                                          e->lhs->kind == EXPR_NUM || e->lhs->kind == EXPR_STR ||
                                          e->lhs->kind == EXPR_FNADDR));
            int rhs_trivial = (e->rhs && (e->rhs->kind == EXPR_VAR || e->rhs->kind == EXPR_GLOBAL ||
                                          e->rhs->kind == EXPR_NUM || e->rhs->kind == EXPR_STR ||
                                          e->rhs->kind == EXPR_FNADDR));

            // Try: lhs computed into %rax, rhs loaded into %rcx.
            cg_expr(cg, e->lhs);
            if (rhs_trivial && cg_expr_to_reg_simple_arg_try(cg, e->rhs, "%rcx", "%ecx")) {
                if (cmp_i32) {
                    str_appendf(&cg->out, "  cmp %%ecx, %%eax\n");
                } else {
                    if (rhs_is64 && lhs_i32_signed) {
                        str_appendf(&cg->out, "  cdqe\n");
                    }
                    if (lhs_is64 && rhs_i32_signed) {
                        str_appendf(&cg->out, "  movslq %%ecx, %%rcx\n");
                    }
                    str_appendf(&cg->out, "  cmp %%rcx, %%rax\n");
                }

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

            // Roll back and try: rhs computed into %rax, lhs loaded into %rcx.
            cg->out.len = old_len;
            if (cg->out.buf) cg->out.buf[old_len] = 0;

            cg_expr(cg, e->rhs);
            if (lhs_trivial && cg_expr_to_reg_simple_arg_try(cg, e->lhs, "%rcx", "%ecx")) {
                if (cmp_i32) {
                    str_appendf(&cg->out, "  cmp %%eax, %%ecx\n");
                } else {
                    if (rhs_is64 && lhs_i32_signed) {
                        str_appendf(&cg->out, "  movslq %%ecx, %%rcx\n");
                    }
                    if (lhs_is64 && rhs_i32_signed) {
                        str_appendf(&cg->out, "  cdqe\n");
                    }
                    str_appendf(&cg->out, "  cmp %%rax, %%rcx\n");
                }

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

            cg->out.len = old_len;
            if (cg->out.buf) cg->out.buf[old_len] = 0;
        }

        // Fast path: compare against a dereferenced pointer RHS when we can load the
        // pointer expression as a simple arg. Avoids push/pop; uses %rdx for saved LHS.
        if (e->rhs && e->rhs->kind == EXPR_DEREF && e->rhs->lhs && (e->rhs->lval_size == 4 || e->rhs->lval_size == 8)) {
            int rhs_sz = e->rhs->lval_size;
            int can_cmp32 = cmp_i32 && rhs_sz == 4;
            int can_cmp64 = lhs_is64 && rhs_sz == 8;
            if (can_cmp32 || can_cmp64) {
                mc_usize old_len = cg->out.len;

                cg_expr(cg, e->lhs);
                if (can_cmp64) {
                    str_appendf(&cg->out, "  mov %%rax, %%rdx\n");
                } else {
                    str_appendf(&cg->out, "  mov %%eax, %%edx\n");
                }

                // Load pointer value into %rcx without clobbering %rdx.
                if (!cg_expr_to_reg_simple_arg_try(cg, e->rhs->lhs, "%rcx", "%ecx")) {
                    cg->out.len = old_len;
                    if (cg->out.buf) cg->out.buf[old_len] = 0;
                    goto general_cmp;
                }

                if (can_cmp64) {
                    str_appendf(&cg->out, "  cmp (%%rcx), %%rdx\n");
                } else {
                    str_appendf(&cg->out, "  cmp (%%rcx), %%edx\n");
                }

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
        }

    general_cmp:
        // General case: evaluate both sides.
        cg_expr(cg, e->lhs);
        str_appendf(&cg->out, "  push %%rax\n");
        cg_expr(cg, e->rhs);
        str_appendf(&cg->out, "  pop %%rcx\n");
        if (cmp_i32) {
            str_appendf(&cg->out, "  cmp %%eax, %%ecx\n");
        } else {
            // Mixed-width compare: ensure signed 32-bit operands are sign-extended
            // before a 64-bit cmp. (Unsigned 32-bit values are already zero-extended.)
            if (rhs_is64 && lhs_i32_signed) {
                str_appendf(&cg->out, "  movslq %%ecx, %%rcx\n");
            }
            if (lhs_is64 && rhs_i32_signed) {
                str_appendf(&cg->out, "  cdqe\n");
            }
            str_appendf(&cg->out, "  cmp %%rax, %%rcx\n");
        }

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

    // Generic scalar truthiness (no boolean materialization): eval and test.
    cg_expr(cg, e);
    str_appendf(&cg->out, "  test %%rax, %%rax\n");
    str_appendf_si(&cg->out, "  %s .L%d\n", jump_on_false ? "jz" : "jnz", (long long)label);
    return 1;
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

// NOTE: Avoid a global table of pointers here.
// The selfhost compiler historically produced broken code when emitting register
// names through an initialized pointer table, leading to empty operands like
// `pop` or `mov , -16(%rbp)` in the output assembly.

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
    int sz = 8;
    if (size == 1) sz = 1;
    else if (size == 2) sz = 2;
    else if (size == 4) sz = 4;

    switch (reg_idx) {
        case 0: return (sz == 1) ? "%al" : (sz == 2) ? "%ax" : (sz == 4) ? "%eax" : "%rax";
        case 1: return (sz == 1) ? "%bl" : (sz == 2) ? "%bx" : (sz == 4) ? "%ebx" : "%rbx";
        case 2: return (sz == 1) ? "%cl" : (sz == 2) ? "%cx" : (sz == 4) ? "%ecx" : "%rcx";
        case 3: return (sz == 1) ? "%dl" : (sz == 2) ? "%dx" : (sz == 4) ? "%edx" : "%rdx";
        case 4: return (sz == 1) ? "%sil" : (sz == 2) ? "%si" : (sz == 4) ? "%esi" : "%rsi";
        case 5: return (sz == 1) ? "%dil" : (sz == 2) ? "%di" : (sz == 4) ? "%edi" : "%rdi";
        case 6: return (sz == 1) ? "%r8b" : (sz == 2) ? "%r8w" : (sz == 4) ? "%r8d" : "%r8";
        case 7: return (sz == 1) ? "%r9b" : (sz == 2) ? "%r9w" : (sz == 4) ? "%r9d" : "%r9";
        case 8: return (sz == 1) ? "%r10b" : (sz == 2) ? "%r10w" : (sz == 4) ? "%r10d" : "%r10";
        case 9: return (sz == 1) ? "%r11b" : (sz == 2) ? "%r11w" : (sz == 4) ? "%r11d" : "%r11";
        case 10: return (sz == 1) ? "%r12b" : (sz == 2) ? "%r12w" : (sz == 4) ? "%r12d" : "%r12";
        case 11: return (sz == 1) ? "%r13b" : (sz == 2) ? "%r13w" : (sz == 4) ? "%r13d" : "%r13";
        case 12: return (sz == 1) ? "%r14b" : (sz == 2) ? "%r14w" : (sz == 4) ? "%r14d" : "%r14";
        case 13: return (sz == 1) ? "%r15b" : (sz == 2) ? "%r15w" : (sz == 4) ? "%r15d" : "%r15";
        default: return "%rax";
    }
}

static void cg_asm_stmt(CG *cg, const Stmt *s) {
    // Allocate bindings for all operands
    int total_ops = s->asm_noutputs + s->asm_ninputs;
    AsmBinding *bindings = NULL;
    if (total_ops > 0) {
        bindings = (AsmBinding *)monacc_calloc((mc_usize)total_ops, sizeof(AsmBinding));
    }

    // Track which registers are used
    int reg_used[14];
    mc_memset(reg_used, 0, sizeof(reg_used));
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
            if (next_scratch >= 14) die("asm: out of scratch registers");
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
            if (next_scratch >= 14) die("asm: out of scratch registers");
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
    int pushed = 0;
    for (int i = 0; i < s->asm_ninputs; i++) {
        AsmBinding *b = &bindings[s->asm_noutputs + i];
        if (b->kind == 0 && b->reg_idx != 0) {
            // Not rax - need to evaluate and save
            if (b->expr->kind != EXPR_NUM) {
                cg_expr(cg, b->expr);
                str_appendf(&cg->out, "  push %%rax\n");
                pushed++;
            }
        }
    }

    // Second pass: pop into target registers (reverse order)
    for (int i = s->asm_ninputs - 1; i >= 0; i--) {
        AsmBinding *b = &bindings[s->asm_noutputs + i];
        if (b->kind == 0 && b->reg_idx != 0) {
            if (b->expr->kind != EXPR_NUM) {
                str_appendf_s(&cg->out, "  pop %s\n", asm_reg_for_size(b->reg_idx, 8));
            } else {
                // Load constant directly
                str_appendf_is(&cg->out, "  mov $%lld, %s\n", b->expr->num, asm_reg_for_size(b->reg_idx, 8));
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
                str_appendf_s(&cg->out, "  mov %%rax, %s\n", asm_reg_for_size(b->reg_idx, 8));
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
            } else if (*tmpl == 'b' || *tmpl == 'w' || *tmpl == 'k' || *tmpl == 'q' || (*tmpl >= '0' && *tmpl <= '9')) {
                // Operand reference, optionally with a size modifier:
                //   %0   -> natural operand size
                //   %b0  -> 8-bit reg name
                //   %w0  -> 16-bit reg name
                //   %k0  -> 32-bit reg name
                //   %q0  -> 64-bit reg name
                int forced_size = 0;
                if (*tmpl == 'b') { forced_size = 1; tmpl++; }
                else if (*tmpl == 'w') { forced_size = 2; tmpl++; }
                else if (*tmpl == 'k') { forced_size = 4; tmpl++; }
                else if (*tmpl == 'q') { forced_size = 8; tmpl++; }

                if (!(*tmpl >= '0' && *tmpl <= '9')) {
                    die("asm: missing operand number after %%%c", forced_size == 1 ? 'b' : forced_size == 2 ? 'w' : forced_size == 4 ? 'k' : forced_size == 8 ? 'q' : '?');
                }

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
                    int sz = forced_size ? forced_size : b->size;
                    const char *regname = asm_reg_for_size(b->reg_idx, sz);
                    str_append_bytes(&cg->out, regname, mc_strlen(regname));
                } else {
                    if (forced_size) {
                        die("asm: %%-modifier only supported for register operands");
                    }
                    if (b->kind == 1) {
                        char buf[32];
                        int n = mc_snprint_cstr_i64_cstr(buf, sizeof(buf), "", (mc_i64)b->mem_offset, "(%%rbp)");
                        if (n <= 0 || (mc_usize)n >= sizeof(buf)) die("asm: bad mem ref");
                        str_append_bytes(&cg->out, buf, (mc_usize)n);
                    } else if (b->kind == 2) {
                        char buf[32];
                        int n = mc_snprint_cstr_i64_cstr(buf, sizeof(buf), "$", (mc_i64)b->imm_val, "");
                        if (n <= 0 || (mc_usize)n >= sizeof(buf)) die("asm: bad imm");
                        str_append_bytes(&cg->out, buf, (mc_usize)n);
                    }
                }
            } else {
                // Unknown % sequence: pass through literally.
                // This keeps behavior predictable and avoids infinite loops.
                str_append_bytes(&cg->out, "%", 1);
                if (*tmpl) {
                    str_append_bytes(&cg->out, tmpl, 1);
                    tmpl++;
                }
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
        if (b->kind != 0 || !b->expr) continue;

        int sz = b->size;
        if (!(sz == 1 || sz == 2 || sz == 4 || sz == 8)) {
            die("asm: unsupported output size %d", sz);
        }
        const char *src = asm_reg_for_size(b->reg_idx, sz);

        if (b->expr->kind == EXPR_VAR) {
            str_appendf_si(&cg->out, "  mov %s, %d(%%rbp)\n", src, (long long)b->expr->var_offset);
            continue;
        }
        if (b->expr->kind == EXPR_GLOBAL) {
            const GlobalVar *gv = &cg->prg->globals[b->expr->global_id];
            str_appendf_ss(&cg->out, "  mov %s, %s(%%rip)\n", src, gv->name);
            continue;
        }

        // Conservative fallback: preserve value across address computation.
        const char *dst = (sz == 1) ? "%al" : (sz == 2) ? "%ax" : (sz == 4) ? "%eax" : "%rax";
        if (mc_strcmp(src, dst) != 0) {
            str_appendf_ss(&cg->out, "  mov %s, %s\n", src, dst);
        }
        str_appendf(&cg->out, "  push %rax\n");
        (void)cg_lval_addr(cg, b->expr);
        str_appendf(&cg->out, "  mov %rax, %rcx\n");
        str_appendf(&cg->out, "  pop %rax\n");
        emit_store_mem(cg, "(%rcx)", sz);
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

                // Ensure the return value in %rax matches the function's return type width.
                // With the 32-bit-int optimization, signed 32-bit values are no longer
                // kept sign-extended in %rax, so widening returns must extend explicitly.
                int dst_sz = 8;
                if (cg->ret_ptr > 0) {
                    dst_sz = 8;
                } else if (cg->ret_base == BT_CHAR) {
                    dst_sz = 1;
                } else if (cg->ret_base == BT_SHORT) {
                    dst_sz = 2;
                } else if (cg->ret_base == BT_INT) {
                    dst_sz = 4;
                } else if (cg->ret_base == BT_LONG) {
                    dst_sz = 8;
                } else if (cg->ret_base == BT_FLOAT) {
                    dst_sz = 4;
                }

                if (dst_sz == 8 && s->expr) {
                    int src_sz = type_sizeof(cg->prg, s->expr->base, s->expr->ptr, s->expr->struct_id);
                    if (src_sz == 1) {
                        if (s->expr->ptr > 0 || s->expr->is_unsigned) {
                            str_appendf(&cg->out, "  movzb %%al, %%eax\n");
                        } else {
                            str_appendf(&cg->out, "  movsbq %%al, %%rax\n");
                        }
                    } else if (src_sz == 2) {
                        if (s->expr->ptr > 0 || s->expr->is_unsigned) {
                            str_appendf(&cg->out, "  movzw %%ax, %%eax\n");
                        } else {
                            str_appendf(&cg->out, "  movswq %%ax, %%rax\n");
                        }
                    } else if (src_sz == 4) {
                        if (s->expr->ptr > 0 || s->expr->is_unsigned) {
                            // 32-bit return values in %eax are already zero-extended.
                        } else {
                            str_appendf(&cg->out, "  cdqe\n");
                        }
                    }
                }

                // SysV ABI: float return values live in %xmm0.
                // Internally, float expressions are represented as raw 32-bit bits in %eax.
                if (cg->ret_ptr == 0 && cg->ret_base == BT_FLOAT) {
                    str_appendf(&cg->out, "  movd %%eax, %%xmm0\n");
                }

                str_appendf_i64(&cg->out, "  jmp .Lret%d\n", ret_label);
            }
            return;
        case STMT_LABEL:
        {
            int lid = cg_label_id(cg, s->label);
            if (lid < 0) {
                die("internal: unknown label '%s'", s->label);
            }
            str_appendf_i64(&cg->out, ".Llbl%d:\n", lid);
            cg_stmt(cg, s->label_stmt, ret_label, sw);
            return;
        }
        case STMT_GOTO:
        {
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
                // Optimization: store scalar locals as 8 bytes with proper extension.
                int sz = s->decl_store_size;
                if (sz == 1 || sz == 2 || sz == 4) {
                    // Use the init expression's signedness for extension.
                    int is_unsigned = s->decl_init->is_unsigned;
                    if (sz == 1) {
                        if (is_unsigned) {
                            str_appendf(&cg->out, "  movzb %%al, %%eax\n");
                        } else {
                            str_appendf(&cg->out, "  movsbq %%al, %%rax\n");
                        }
                    } else if (sz == 2) {
                        if (is_unsigned) {
                            str_appendf(&cg->out, "  movzw %%ax, %%eax\n");
                        } else {
                            str_appendf(&cg->out, "  movswq %%ax, %%rax\n");
                        }
                    } else { // sz == 4
                        if (is_unsigned) {
                            // %eax write already zero-extends into %rax.
                        } else {
                            str_appendf(&cg->out, "  cdqe\n");
                        }
                    }
                    emit_store_disp(cg, s->decl_offset, "%rbp", 8);
                } else {
                    emit_store_disp(cg, s->decl_offset, "%rbp", sz);
                }
            }
            return;
        case STMT_IF:
        {
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
        case STMT_WHILE:
        {
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
        case STMT_FOR:
        {
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
        case STMT_SWITCH:
        {
            SwitchCtx ctx;
            mc_memset(&ctx, 0, sizeof(ctx));
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
        case STMT_CASE:
        {
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
    CG cg;
    mc_memset(&cg, 0, sizeof(cg));
    cg.out = *out;
    cg.prg = prg;

    if (prg->nstrs > 0) {
        for (int i = 0; i < prg->nstrs; i++) {
            const StringLit *sl = &prg->strs[i];
            // Put each string in its own rodata subsection so --gc-sections can drop unused strings.
            str_appendf_i64(&cg.out, ".section .rodata.LC%d,\"a\",@progbits\n", i);
            str_appendf_i64(&cg.out, ".LC%d:\n", i);
            for (mc_usize off = 0; off < sl->len; ) {
                str_appendf(&cg.out, "  .byte ");
                mc_usize n = sl->len - off;
                if (n > 16) n = 16;
                for (mc_usize j = 0; j < n; j++) {
                    unsigned int b = (unsigned int)sl->data[off + j];
                    str_appendf_su(&cg.out, "%s%u", (j == 0) ? "" : ", ", (unsigned long long)b);
                }
                str_appendf(&cg.out, "\n");
                off += n;
            }
            str_appendf(&cg.out, "\n");
        }
    }

    // Emit global variables. Most are in .bss (zero-init only), but we support a minimal
    // initializer form (currently: string bytes for char arrays), emitted into .data.
    if (prg->nglobals > 0) {
        for (int i = 0; i < prg->nglobals; i++) {
            const GlobalVar *gv = &prg->globals[i];
            if (gv->is_extern) continue;

            // Compute alignment (use power of 2, max 8)
            int align = (gv->elem_size >= 8) ? 8 : (gv->elem_size >= 4) ? 4 : (gv->elem_size >= 2) ? 2 : 1;

            if (gv->has_init && gv->init_str_id >= 0) {
                // Each global in its own section for --gc-sections.
                // Needs to be writable for cases like `static char s[] = "abc"; s[0] = ...;`.
                str_appendf_s(&cg.out, ".section .data.%s,\"aw\",@progbits\n", gv->name);
                if (!gv->is_static) {
                    str_appendf_s(&cg.out, ".globl %s\n", gv->name);
                }
                str_appendf_is(&cg.out, ".align %d\n%s:\n", (long long)align, gv->name);

                if (gv->init_str_id >= prg->nstrs) {
                    die("internal: bad init_str_id %d", gv->init_str_id);
                }
                const StringLit *sl = &prg->strs[gv->init_str_id];
                mc_usize len = sl->len;
                if (gv->size > 0 && len > (mc_usize)gv->size) len = (mc_usize)gv->size;

                for (mc_usize off = 0; off < len; ) {
                    str_appendf(&cg.out, "  .byte ");
                    mc_usize n = len - off;
                    if (n > 16) n = 16;
                    for (mc_usize j = 0; j < n; j++) {
                        unsigned int b = (unsigned int)sl->data[off + j];
                        str_appendf_su(&cg.out, "%s%u", (j == 0) ? "" : ", ", (unsigned long long)b);
                    }
                    str_appendf(&cg.out, "\n");
                    off += n;
                }
                if (gv->size > (int)len) {
                    str_appendf_i64(&cg.out, "  .zero %d\n\n", gv->size - (int)len);
                } else {
                    str_appendf(&cg.out, "\n");
                }
                continue;
            }

            // Default: .bss (zero-init only)
            // Each global in its own section for --gc-sections
            str_appendf_s(&cg.out, ".section .bss.%s,\"aw\",@nobits\n", gv->name);
            if (!gv->is_static) {
                str_appendf_s(&cg.out, ".globl %s\n", gv->name);
            }
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
                str_appendf_si(&cg.out, "  mov %s, %d(%%rbp)\n", areg8[pi], (long long)off);
            } else if (sz == 2) {
                str_appendf_si(&cg.out, "  mov %s, %d(%%rbp)\n", areg16[pi], (long long)off);
            } else if (sz == 4) {
                str_appendf_si(&cg.out, "  mov %s, %d(%%rbp)\n", areg32[pi], (long long)off);
            } else {
                str_appendf_si(&cg.out, "  mov %s, %d(%%rbp)\n", areg64[pi], (long long)off);
            }
        }

        // Spill incoming float args (%xmm0..%xmm7) to their stack slots (bound params).
        static const char *xmmreg[8] = {"%xmm0", "%xmm1", "%xmm2", "%xmm3", "%xmm4", "%xmm5", "%xmm6", "%xmm7"};
        for (int xi = 0; xi < 8; xi++) {
            int off = fn->xmm_param_offsets[xi];
            if (off == 0) continue;
            if (stmt_count_var_uses(fn->body, off) == 0) continue;
            // Move low 32-bit float payload to GPR, then store.
            str_appendf_s(&cg.out, "  movd %s, %%eax\n", xmmreg[xi]);
            str_appendf_i64(&cg.out, "  mov %%eax, %d(%%rbp)\n", (long long)off);
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

