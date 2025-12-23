#pragma once

#ifdef SELFHOST
#include "monacc_selfhost.h"
#endif

// Minimal libc surface used across the compiler.
#include "monacc_libc.h"

// Shared core helpers (string/mem, syscalls, parsing, etc).
#include "mc.h"

void *monacc_malloc(mc_usize size);
void *monacc_calloc(mc_usize nmemb, mc_usize size);
void *monacc_realloc(void *ptr, mc_usize size);
void monacc_free(void *ptr);

// ===== Self-host friendly integer bounds =====
// monacc's lexer currently ignores integer suffixes (u/U/l/L), and tokenizes
// negative literals as unary '-' applied to a positive literal token.
//
// This means the source-level literal `-2147483648LL` becomes `-(2147483648)`
// during self-host builds. Since 2147483648 does not fit in signed-32, it gets
// treated as an unsigned 32-bit literal, which breaks i32 range checks and can
// cascade into miscompilations (notably signed-vs-unsigned compares against
// small literals).
//
// Use expressions that only contain in-range positive literals.
#define MC_I32_MIN (-2147483647LL - 1LL)
#define MC_I32_MAX (2147483647LL)
#define MC_U32_MAX (0xffffffffULL)

// ELF utilities (bring-up for internal linker)
void elfobj_dump(const char *path);
void elfsec_dump(const char *path);

// Minimal internal linker (Step 2): link a single .o into an ET_EXEC without relocations.
void link_internal_exec_single_obj(const char *obj_path, const char *out_path);

// Step 4: link multiple objects into a single executable.
void link_internal_exec_objs(const char **obj_paths, int nobj_paths, const char *out_path, int keep_shdr);

// ===== Shared core types =====

typedef struct {
    char name[128];
    char *repl;
} Macro;

typedef struct {
    Macro *macros;
    int n;
    int cap;
} MacroTable;

typedef struct {
    char **include_dirs;
    int ninclude_dirs;
} PPConfig;

typedef struct {
    char **paths;
    int n;
    int cap;
} OnceTable;

typedef struct {
    const char *src;
    mc_usize len;
    mc_usize pos;
    char name[128];
} LexExp;

typedef struct {
    const char *path;
    const char *src;
    mc_usize len;
    mc_usize pos;
    int line;
    int col;

    const MacroTable *mt;
    LexExp exp[64];
    int exp_n;
} Lexer;

typedef enum {
    TOK_EOF = 0,
    TOK_IDENT,
    TOK_NUM,
    TOK_FLOATNUM,
    TOK_STR,
    TOK_CHAR,
    TOK_KW_INT,
    TOK_KW_CHAR,
    TOK_KW_VOID,
    TOK_KW_FLOAT,
    TOK_KW_TYPEDEF,
    TOK_KW_ENUM,
    TOK_KW_SIZEOF,
    TOK_KW_STRUCT,
    TOK_KW_EXTERN,
    TOK_KW_STATIC,
    TOK_KW_RETURN,
    TOK_KW_IF,
    TOK_KW_ELSE,
    TOK_KW_WHILE,
    TOK_KW_FOR,
    TOK_KW_BREAK,
    TOK_KW_CONTINUE,
    TOK_KW_SWITCH,
    TOK_KW_CASE,
    TOK_KW_DEFAULT,
    TOK_KW_GOTO,
    TOK_LPAREN,
    TOK_RPAREN,
    TOK_LBRACK,
    TOK_RBRACK,
    TOK_LBRACE,
    TOK_RBRACE,
    TOK_SEMI,
    TOK_COMMA,
    TOK_DOT,
    TOK_ELLIPSIS,
    TOK_PLUS,
    TOK_PLUSPLUS,
    TOK_MINUS,
    TOK_MINUSMINUS,
    TOK_PLUSEQ,
    TOK_MINUSEQ,
    TOK_ARROW,
    TOK_STAR,
    TOK_MULEQ,
    TOK_AMP,
    TOK_ANDEQ,
    TOK_ANDAND,
    TOK_CARET,
    TOK_XOREQ,
    TOK_SLASH,
    TOK_DIVEQ,
    TOK_PERCENT,
    TOK_MODEQ,
    TOK_ASSIGN,
    TOK_EQ,
    TOK_NE,
    TOK_BANG,
    TOK_TILDE,
    TOK_PIPE,
    TOK_OREQ,
    TOK_OROR,
    TOK_LT,
    TOK_SHL,
    TOK_SHLEQ,
    TOK_LE,
    TOK_GT,
    TOK_SHR,
    TOK_SHREQ,
    TOK_GE,
    TOK_QMARK,
    TOK_COLON,
} TokenKind;

typedef struct {
    TokenKind kind;
    const char *start;
    mc_usize len;
    long long num;
    int line;
    int col;
} Token;

typedef struct Program Program;

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

typedef struct {
    Lexer lx;
    Token tok;
    Program *prg;
    char cur_fn_name[128];
} Parser;

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

// ===== AST / locals =====

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

typedef struct Expr {
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
} Expr;

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

typedef struct Stmt {
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
} Stmt;

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

// ===== Shared string builder =====

typedef struct {
    char *buf;
    mc_usize len;
    mc_usize cap;
} Str;

// ===== Cross-module APIs =====

__attribute__((noreturn, format(printf, 1, 2)))
void die(const char *fmt, ...);

__attribute__((noreturn))
void die_i64(const char *prefix, long long v, const char *suffix);

__attribute__((format(printf, 1, 2)))
void errf(const char *fmt, ...);

#ifndef SELFHOST
int mc_vsnprintf(char *dst, mc_usize cap, const char *fmt, va_list ap);
__attribute__((format(printf, 3, 4)))
int mc_snprintf(char *dst, mc_usize cap, const char *fmt, ...);
#endif

#ifdef SELFHOST
// SELFHOST builds intentionally stub out stdarg support in-tree; avoid relying on it.
// Avoid exposing variadic formatting APIs.
#endif

const char *tok_kind_name(TokenKind k);

const char *mt_lookup(const MacroTable *mt, const char *name, mc_usize name_len);
void mt_define(MacroTable *mt, const char *name, mc_usize name_len, const char *repl);

int is_ident_cont(unsigned char c);

Token lex_next(Lexer *lx);

void parser_next(Parser *p);
void expect(Parser *p, TokenKind k, const char *what);
void expect_ident(Parser *p, const char **out_start, mc_usize *out_len);

void str_reserve(Str *s, mc_usize add);
void str_append_bytes(Str *s, const char *buf, mc_usize n);
// `str_appendf` supports only literals and `%%`.
// Use typed helpers for conversions.
void str_appendf(Str *s, const char *fmt);
void str_appendf_i64(Str *s, const char *fmt, long long v);
void str_appendf_u64(Str *s, const char *fmt, unsigned long long v);
void str_appendf_s(Str *s, const char *fmt, const char *v);
void str_appendf_ss(Str *s, const char *fmt, const char *s0, const char *s1);
void str_appendf_si(Str *s, const char *fmt, const char *s0, long long i0);
void str_appendf_su(Str *s, const char *fmt, const char *s0, unsigned long long u0);
void str_appendf_is(Str *s, const char *fmt, long long i0, const char *s0);

void preprocess_file(const PPConfig *cfg, MacroTable *mt, OnceTable *ot, const char *path, Str *out);

void parse_program(Parser *p, Program *out);

void write_file(const char *path, const char *data, mc_usize len);

// ===== Syscall wrappers (hosted + selfhost) =====

int xopen_ro(const char *path);
int xopen_ro_try(const char *path);
int xopen_wtrunc(const char *path, int mode);
int xopen_rdwr_try(const char *path);
mc_isize xread_retry(int fd, void *buf, mc_usize len);
void xwrite_all(int fd, const void *buf, mc_usize len);
void xwrite_best_effort(int fd, const void *buf, mc_usize len);
void xclose_best_effort(int fd);
void xclose_checked(int fd, const char *what, const char *path);

mc_i64 xlseek_retry(int fd, mc_i64 offset, int whence);
int xftruncate_best_effort(int fd, mc_i64 length);

void xunlink_best_effort(const char *path);

// Returns 1 if path exists (even if not readable), else 0.
int xpath_exists(const char *path);

int xexecvp(const char *file, char *const argv[]);

// Directory listing (Linux getdents64). Hosted-first.
// The record layout matches the Linux kernel ABI.
typedef struct {
    uint64_t d_ino;
    int64_t d_off;
    uint16_t d_reclen;
    uint8_t d_type;
    char d_name[];
} linux_dirent64;

mc_isize xgetdents64_retry(int fd, void *buf, mc_usize len);

typedef struct {
    int fd;
    mc_usize pos;
    mc_usize end;
    char buf[8192];
} DirIter;

void diriter_init_fd(DirIter *it, int fd);
void diriter_open(DirIter *it, const char *path);
void diriter_close(DirIter *it);
int diriter_next(DirIter *it, const linux_dirent64 **out_ent);
int run_cmd(char *const argv[]);

void emit_x86_64_sysv_freestanding(const Program *prg, Str *out);
void emit_x86_64_sysv_freestanding_with_start(const Program *prg, Str *out, int with_start);
void emit_aarch64_darwin_hosted(const Program *prg, Str *out);

// Internal toolchain reduction: assemble monacc-emitted x86_64 assembly into an ELF64 relocatable object.
void assemble_x86_64_elfobj(const char *asm_buf, mc_usize asm_len, const char *out_o_path);

// AST utilities (Phase 1: optional debug dumps)
void ast_dump(const Program *prg, const char *path);

// AST/program helpers used across modules
Expr *new_expr(ExprKind k);
Expr *expr_clone_with_subst(const Expr *e, const int *param_offsets, int nparams, Expr **args);
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
