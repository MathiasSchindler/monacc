#pragma once

// Abstract Syntax Tree Module (ast.h)
// ====================================
//
// This header defines the AST node types, expressions, statements, and
// program structure used by the monacc compiler.
//
// Part of Phase 3 of the monacc compiler structural rebase: splitting the
// monolithic monacc.h into focused module headers.

#include "mc_types.h"

// Forward declarations
typedef struct mc_compiler mc_compiler;
typedef struct Expr Expr;
typedef struct Stmt Stmt;
typedef struct Program Program;

// ===== Base Types =====

// BaseType is used by Function prototypes.
typedef enum {
    BT_INT = 0,
    BT_CHAR = 1,
    BT_SHORT = 2,
    BT_LONG = 3,
    BT_FLOAT = 4,
    BT_VOID = 5,
    BT_STRUCT = 6,
} BaseType;

// ===== Expression Types =====

typedef enum {
    EXPR_NUM,
    EXPR_VAR,
    EXPR_GLOBAL,
    EXPR_STR,
    EXPR_FNADDR,
    EXPR_ASSIGN,
    EXPR_MEMCPY,
    EXPR_COND,
    EXPR_COND_LVAL,
    EXPR_LOR,
    EXPR_LAND,
    EXPR_ADD,
    EXPR_SUB,
    EXPR_SHL,
    EXPR_SHR,
    EXPR_BAND,
    EXPR_BXOR,
    EXPR_BOR,
    EXPR_MUL,
    EXPR_DIV,
    EXPR_MOD,
    EXPR_EQ,
    EXPR_NE,
    EXPR_LT,
    EXPR_LE,
    EXPR_GT,
    EXPR_GE,
    EXPR_NEG,
    EXPR_POS,
    EXPR_NOT,
    EXPR_BNOT,
    EXPR_CAST,
    EXPR_PREINC,
    EXPR_PREDEC,
    EXPR_POSTINC,
    EXPR_POSTDEC,
    EXPR_COMPOUND,
    EXPR_ADDR,
    EXPR_DEREF,
    EXPR_INDEX,
    EXPR_MEMBER,
    EXPR_CALL,
    EXPR_SRET_CALL,
} ExprKind;

typedef struct {
    int off;           // byte offset from base address
    int store_size;    // 1 or 8
    struct Expr *value;
} InitEnt;

struct Expr {
    ExprKind kind;
    struct Expr *lhs;
    struct Expr *rhs;
    struct Expr *third; // for EXPR_COND: else-expression
    long long num;
    int var_offset; // rbp-relative negative offset (e.g. -8, -16)
    int var_alloc_size; // for EXPR_VAR arrays: total bytes of the object
    int global_id;  // for EXPR_GLOBAL: index into program globals array
    int str_id;
    BaseType base;
    int ptr;
    int struct_id; // valid if base==BT_STRUCT
    int is_unsigned;
    int lval_size; // for lvalues: store/load size in bytes (1 or 8)
    int ptr_scale; // for pointer +/- int: scaling of integer operand (1 or 8), else 0
    int ptr_index_side; // 0=none, 1=rhs is index, 2=lhs is index
    int array_stride; // for array-of-array decay (scale in bytes for first index), else 0
    int member_off; // for EXPR_MEMBER
    int member_is_arrow; // for EXPR_MEMBER
    int post_delta; // for EXPR_{PRE,POST}{INC,DEC}: delta to add/subtract (already scaled)

    // For EXPR_COMPOUND: addressable temporary object with initialization.
    // Storage is a stack slot at var_offset(%rbp) of size lval_size bytes.
    int init_zero; // whether to zero the whole object first
    InitEnt *inits;
    int ninits;

    char callee[128];
    struct Expr **args;
    int nargs;
};

// ===== Statement Types =====

typedef enum {
    STMT_BLOCK,
    STMT_RETURN,
    STMT_IF,
    STMT_WHILE,
    STMT_FOR,
    STMT_SWITCH,
    STMT_CASE,
    STMT_DEFAULT,
    STMT_LABEL,
    STMT_GOTO,
    STMT_BREAK,
    STMT_CONTINUE,
    STMT_EXPR,
    STMT_DECL,
    STMT_ASM,
} StmtKind;

// Inline asm operand (input or output).
// Constraint chars: "a"=rax, "b"=rbx, "c"=rcx, "d"=rdx, "D"=rdi, "S"=rsi,
//                   "r"=any GPR, "m"=memory, "i"/"n"=immediate,
//                   "0"-"9"=same as operand N
// Modifier: "="=output (write-only), "+"=input-output
typedef struct {
    char constraint[16];   // e.g. "=a", "r", "Nd", "m"
    int is_output;         // constraint starts with '=' or '+'
    int is_inout;          // constraint starts with '+'
    struct Expr *expr;     // the C expression
} AsmOperand;

struct Stmt {
    StmtKind kind;
    struct Stmt *next; // for block lists

    // STMT_BLOCK: first
    struct Stmt *block_first;

    // STMT_RETURN / STMT_EXPR: expr
    Expr *expr;

    // STMT_DECL: offset + optional init
    int decl_offset;
    int decl_store_size; // bytes (1 or 8)
    Expr *decl_init;

    // STMT_IF: cond, then, else
    Expr *if_cond;
    struct Stmt *if_then;
    struct Stmt *if_else;

    // STMT_WHILE: cond, body
    Expr *while_cond;
    struct Stmt *while_body;

    // STMT_FOR: init stmt (decl or expr or empty), cond expr (optional),
    // inc expr (optional), body stmt
    struct Stmt *for_init;
    Expr *for_cond;
    Expr *for_inc;
    struct Stmt *for_body;

    // STMT_SWITCH: controlling expression + body statement
    Expr *switch_expr;
    struct Stmt *switch_body;

    // STMT_CASE: constant value (integer constant expression)
    long long case_value;

    // STMT_LABEL / STMT_GOTO
    char label[128];
    struct Stmt *label_stmt; // for STMT_LABEL

    // STMT_ASM: inline assembly
    char *asm_template;        // template string (e.g. "mov %1, %0")
    AsmOperand *asm_outputs;   // output operands
    int asm_noutputs;
    AsmOperand *asm_inputs;    // input operands
    int asm_ninputs;
    char **asm_clobbers;       // clobber list (e.g. "memory", "rcx")
    int asm_nclobbers;
    int asm_is_volatile;       // __asm__ volatile
};

// ===== Local Variables =====

typedef struct {
    char name[128];
    int offset; // negative rbp offset
    int global_id; // >=0 => references a global symbol instead of stack storage
    BaseType base;
    int ptr;
    int struct_id;
    int is_unsigned;
    int size; // lvalue load/store size in bytes (1 or 8), or 0 for arrays
    int alloc_size; // bytes reserved on stack
    int array_stride; // for 2D local arrays: scale in bytes for first index, else 0
} Local;

typedef struct {
    Local locals[512];
    int nlocals;
    int next_offset; // grows negatively
} Locals;

// ===== Functions and Global Declarations =====

typedef struct {
    char name[128];
    struct Stmt *body;
    int is_static;
    int is_inline;    // Declared with 'inline' keyword
    int is_called;    // Set when function is referenced (call or address-of)
    int has_body;

    // For inlining: if body is just "return <expr>;" with no locals, store the expr
    struct Expr *inline_expr;  // Non-null if function is inlineable

    // Return type (subset)
    BaseType ret_base;
    int ret_ptr;
    int ret_struct_id;
    int ret_is_unsigned;
    int ret_size;     // for struct returns (bytes), else 0
    int sret_offset;  // stack slot containing hidden sret pointer (rbp-relative), else 0

    int stack_size;
    int nparams;
    int param_offsets[6];
    int param_sizes[6];

    // SysV ABI (subset): float parameters passed in %xmm0..%xmm7.
    // If a float parameter is bound to a local, the codegen prologue spills it
    // from the corresponding XMM register into this stack slot.
    int xmm_param_offsets[8];
    int xmm_param_sizes[8];
} Function;

typedef struct {
    unsigned char *data;
    mc_usize len;
} StringLit;

typedef struct {
    char name[128];
    BaseType base;
    int ptr;
    int struct_id;
    int is_unsigned;
} Typedef;

typedef struct {
    char name[128];
    long long value;
} ConstDef;

typedef struct {
    char name[128];
    BaseType base;
    int ptr;
    int struct_id;
    int is_unsigned;
    int array_len; // 0 => not an array member; else number of elements
    int array_len2; // optional 2nd dimension (0 => 1D)
    int offset;
    int size;
} StructMember;

typedef struct {
    char name[128];
    StructMember *members;
    int nmembers;
    int cap;
    int size;
    int align;
    int is_packed;
} StructDef;

typedef struct {
    char name[128];
    BaseType base;
    int ptr;
    int struct_id;
    int is_unsigned;
    int is_static;
    int size;           // total size in bytes
    int elem_size;      // element size for arrays, else same as size
    int array_len;      // number of elements if array; -1 => incomplete (extern T name[]); 0 => not an array
    int is_extern;

    // Optional initializer support (minimal).
    // If has_init is set and init_str_id >= 0, codegen will emit this global into a .data.* section.
    // init_kind controls how init_str_id is interpreted:
    // - 0: raw bytes (Program.strs[init_str_id]) copied into .data.* (used for numeric scalars and arrays)
    // - 1: pointer to string literal .LC<init_str_id> (writes an address-sized word)
    int has_init;
    int init_str_id; // index into Program.strs
    int init_kind;
} GlobalVar;

// ===== Program Structure =====

struct Program {
    Function *fns;
    int nfns;
    int cap;

    StringLit *strs;
    int nstrs;
    int strcap;

    StructDef *structs;
    int nstructs;
    int structcap;

    Typedef *typedefs;
    int ntypedefs;
    int typedefcap;

    ConstDef *consts;
    int nconsts;
    int constcap;

    GlobalVar *globals;
    int nglobals;
    int globalcap;
};

// ===== AST Utilities =====

// AST utilities (Phase 1: optional debug dumps)
void ast_dump(mc_compiler *ctx, const Program *prg, const char *path);

// AST/program helpers used across modules
Expr *new_expr(ExprKind k);
Expr *expr_clone_with_subst(const Expr *e, const int *param_offsets, int nparams, Expr **args);
Stmt *stmt_clone_with_subst(const Stmt *s, const int *param_offsets, int nparams, Expr **args);
Stmt *new_stmt(StmtKind k);
const Local *local_find(const Locals *ls, const char *nm, mc_usize nm_len);
int local_add(Locals *ls, const char *nm, mc_usize nm_len, BaseType base, int ptr, int struct_id, int is_unsigned, int lval_size, int alloc_size,
              int array_stride);
int local_add_globalref(Locals *ls, const char *nm, mc_usize nm_len, int global_id, BaseType base, int ptr, int struct_id, int is_unsigned, int lval_size,
                        int alloc_size, int array_stride);
int local_add_fixed(Locals *ls, const char *nm, mc_usize nm_len, BaseType base, int ptr, int struct_id, int is_unsigned, int lval_size, int alloc_size,
                    int array_stride,
                    int offset);

int program_add_str(Program *p, const unsigned char *data, mc_usize len);
const Typedef *program_find_typedef(const Program *p, const char *nm, mc_usize nm_len);
void program_add_typedef(Program *p, const char *nm, mc_usize nm_len, BaseType base, int ptr, int struct_id, int is_unsigned);
const ConstDef *program_find_const(const Program *p, const char *nm, mc_usize nm_len);
void program_add_const(Program *p, const char *nm, mc_usize nm_len, long long value);
void program_add_fn(Program *p, const Function *fn);
const Function *program_find_fn(const Program *p, const char *nm, mc_usize nm_len);
void program_mark_fn_called(Program *p, const char *nm, mc_usize nm_len);

int program_get_or_add_struct(Program *p, const char *name, mc_usize name_len);
int program_add_anon_struct(Program *p);
const StructMember *struct_find_member(const Program *prg, int struct_id, const char *name, mc_usize name_len);

int align_up(int x, int a);
int type_alignof(const Program *prg, BaseType base, int ptr, int struct_id);
int type_sizeof(const Program *prg, BaseType base, int ptr, int struct_id);
void program_add_global(Program *p, const GlobalVar *gv);
int program_find_global(const Program *p, const char *name, mc_usize name_len);
