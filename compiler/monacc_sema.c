#include "monacc_libc.h"
#include "mc.h"
#include "monacc_base.h"
#include "include/monacc/diag.h"
#include "include/monacc/ast.h"
#include "include/monacc/sema.h"
#include "mc_compiler.h"

// ===== Semantic Analysis Implementation =====
//
// This module implements semantic analysis for the monacc compiler.
//
// Current Implementation Note:
//   The monacc compiler currently performs type analysis during parsing
//   (single-pass compilation). This implementation provides a validation
//   layer that verifies the AST is already well-formed.
//
//   Future work will move type checking and semantic analysis from the
//   parser into this module, enabling cleaner separation of concerns.

// Validate expression type information
static int validate_expr(mc_compiler *ctx, const Expr *e) {
    (void)ctx; // Reserved for future diagnostics
    
    if (!e) return 0;
    
    // Validate that type information is present
    // All expressions should have base type set
    if (e->base < BT_INT || e->base > BT_STRUCT) {
        return -1;
    }
    
    // Validate pointer indirection
    if (e->ptr < 0) {
        return -1;
    }
    
    // Validate struct references
    if (e->base == BT_STRUCT && e->struct_id < 0) {
        return -1;
    }
    
    // Validate lval_size for typed expressions
    // (Arrays may have lval_size = 0)
    
    // Recursively validate sub-expressions
    if (validate_expr(ctx, e->lhs) != 0) return -1;
    if (validate_expr(ctx, e->rhs) != 0) return -1;
    if (validate_expr(ctx, e->third) != 0) return -1;
    
    // Validate call arguments
    for (int i = 0; i < e->nargs; i++) {
        if (validate_expr(ctx, e->args[i]) != 0) return -1;
    }
    
    // Validate compound literal initializers
    for (int i = 0; i < e->ninits; i++) {
        if (validate_expr(ctx, e->inits[i].value) != 0) return -1;
    }
    
    return 0;
}

// Validate statement structure
static int validate_stmt(mc_compiler *ctx, const Stmt *s) {
    (void)ctx; // Reserved for future diagnostics
    
    if (!s) return 0;
    
    // Validate expressions in statements
    if (s->expr && validate_expr(ctx, s->expr) != 0) return -1;
    if (s->decl_init && validate_expr(ctx, s->decl_init) != 0) return -1;
    if (s->if_cond && validate_expr(ctx, s->if_cond) != 0) return -1;
    if (s->while_cond && validate_expr(ctx, s->while_cond) != 0) return -1;
    if (s->for_cond && validate_expr(ctx, s->for_cond) != 0) return -1;
    if (s->for_inc && validate_expr(ctx, s->for_inc) != 0) return -1;
    if (s->switch_expr && validate_expr(ctx, s->switch_expr) != 0) return -1;
    
    // Validate nested statements
    if (validate_stmt(ctx, s->block_first) != 0) return -1;
    if (validate_stmt(ctx, s->if_then) != 0) return -1;
    if (validate_stmt(ctx, s->if_else) != 0) return -1;
    if (validate_stmt(ctx, s->while_body) != 0) return -1;
    if (validate_stmt(ctx, s->for_init) != 0) return -1;
    if (validate_stmt(ctx, s->for_body) != 0) return -1;
    if (validate_stmt(ctx, s->switch_body) != 0) return -1;
    if (validate_stmt(ctx, s->label_stmt) != 0) return -1;
    
    // Validate inline assembly operands
    for (int i = 0; i < s->asm_noutputs; i++) {
        if (validate_expr(ctx, s->asm_outputs[i].expr) != 0) return -1;
    }
    for (int i = 0; i < s->asm_ninputs; i++) {
        if (validate_expr(ctx, s->asm_inputs[i].expr) != 0) return -1;
    }
    
    // Validate statement chains
    if (validate_stmt(ctx, s->next) != 0) return -1;
    
    return 0;
}

// Validate function structure
static int validate_function(mc_compiler *ctx, const Function *fn) {
    (void)ctx; // Reserved for future diagnostics
    
    if (!fn) return 0;
    
    // Validate function body
    if (fn->body && validate_stmt(ctx, fn->body) != 0) return -1;
    
    // Validate inlineable expression
    if (fn->inline_expr && validate_expr(ctx, fn->inline_expr) != 0) return -1;
    
    return 0;
}

int sema_validate(mc_compiler *ctx, const Program *prg) {
    if (!prg) return -1;
    
    // Validate all functions
    for (int i = 0; i < prg->nfns; i++) {
        if (validate_function(ctx, &prg->fns[i]) != 0) {
            return -1;
        }
    }
    
    // Struct definitions, typedefs, constants, and global variables
    // are validated during parsing. Additional validation could be
    // added here if needed.
    
    return 0;
}

int sema_analyze(mc_compiler *ctx, Program *prg) {
    // Current implementation: The parser already performs type analysis,
    // so we just validate that the AST is well-formed.
    //
    // Future work: Move type checking from parser to here, enabling:
    //   1. Cleaner separation between syntax and semantics
    //   2. Better error messages (separate parse errors from type errors)
    //   3. Potential for multi-pass compilation
    //   4. Support for features that require global analysis
    
    (void)ctx; // Reserved for future use
    
    // Validate the AST structure
    if (sema_validate(ctx, prg) != 0) {
        return -1;
    }
    
    // Future semantic analysis passes would go here:
    //   - Symbol resolution
    //   - Type checking and inference
    //   - Constant folding
    //   - Dead code detection
    //   - Etc.
    
    return 0;
}
