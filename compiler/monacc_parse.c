#include "monacc.h"

// ===== Parsing (recursive descent) =====

static int tok_is(Parser *p, TokenKind k) { return p->tok.kind == k; }

static int consume(Parser *p, TokenKind k) {
    if (p->tok.kind != k) return 0;
    parser_next(p);
    return 1;
}

static Token parser_peek(Parser *p) {
    // One-token lookahead without mutating the real parser state.
    Parser tmp = *p;
    parser_next(&tmp);
    return tmp.tok;
}

static Expr *parse_expr(Parser *p, Locals *ls);
static Stmt *parse_stmt(Parser *p, Locals *ls);
static Expr *parse_assign(Parser *p, Locals *ls);
static Expr *parse_cond(Parser *p, Locals *ls);
static Expr *parse_logor(Parser *p, Locals *ls);
static Expr *parse_logand(Parser *p, Locals *ls);
static Expr *parse_bitor(Parser *p, Locals *ls);
static Expr *parse_bitxor(Parser *p, Locals *ls);
static Expr *parse_bitand(Parser *p, Locals *ls);
static Expr *parse_eq(Parser *p, Locals *ls);
static Expr *parse_rel(Parser *p, Locals *ls);
static Expr *parse_shift(Parser *p, Locals *ls);
static void skip_paren_group(Parser *p);
static void parse_declarator_name(Parser *p, const char **out_nm, size_t *out_nm_len, int *io_ptr);

static int tok_is_ident(Parser *p, const char *s) {
    size_t n = mc_strlen(s);
    return p->tok.kind == TOK_IDENT && p->tok.len == n && mc_memcmp(p->tok.start, s, n) == 0;
}

static void skip_balanced(Parser *p, TokenKind open, TokenKind close) {
    if (!consume(p, open)) return;
    int depth = 1;
    while (depth > 0) {
        if (p->tok.kind == TOK_EOF) {
            die("%s:%d:%d: unexpected EOF in grouped tokens", p->lx.path, p->tok.line, p->tok.col);
        }
        if (consume(p, open)) {
            depth++;
            continue;
        }
        if (consume(p, close)) {
            depth--;
            continue;
        }
        parser_next(p);
    }
}

static long long expr_sizeof(Parser *p, const Expr *inner) {
    if (!inner) return 0;

    // Arrays do not decay under sizeof.
    if (inner->kind == EXPR_VAR && inner->lval_size == 0 && inner->var_alloc_size > 0) {
        return (long long)inner->var_alloc_size;
    }

    // Global arrays do not decay under sizeof either.
    if (inner->kind == EXPR_GLOBAL && inner->lval_size == 0 && inner->var_alloc_size > 0) {
        return (long long)inner->var_alloc_size;
    }

    // sizeof(extern T name[]) is invalid (incomplete type).
    if (inner->kind == EXPR_GLOBAL && inner->lval_size == 0 && p && p->prg) {
        const GlobalVar *gv = &p->prg->globals[inner->global_id];
        if (gv->array_len < 0) {
            die("%s:%d:%d: invalid sizeof incomplete array", p->lx.path, p->tok.line, p->tok.col);
        }
    }

    // String literals are arrays; sizeof("abc") is 4 (includes the trailing NUL).
    if (inner->kind == EXPR_STR && p && p->prg && inner->str_id >= 0 && inner->str_id < p->prg->nstrs) {
        return (long long)p->prg->strs[inner->str_id].len;
    }

    // Array members: parse_postfix models them as a decayed pointer (ptr+1) with lval_size=0.
    // Under sizeof, recover the true member size from the struct definition.
    if (inner->kind == EXPR_MEMBER && inner->lval_size == 0 && p && p->prg) {
        const Expr *lhs = inner->lhs;
        if (lhs && lhs->base == BT_STRUCT && lhs->struct_id >= 0 && lhs->struct_id < p->prg->nstructs) {
            const StructDef *sd = &p->prg->structs[lhs->struct_id];
            for (int i = 0; i < sd->nmembers; i++) {
                const StructMember *m = &sd->members[i];
                if (m->offset == inner->member_off) {
                    return (long long)m->size;
                }
            }
        }
    }

    return (long long)type_sizeof(p->prg, inner->base, inner->ptr, inner->struct_id);
}

static int consume_gcc_attrs_has_packed(Parser *p) {
    int packed = 0;
    for (;;) {
        if (tok_is_ident(p, "__attribute__") || tok_is_ident(p, "__attribute")) {
            parser_next(p);
            if (consume(p, TOK_LPAREN)) {
                int depth = 1;
                while (depth > 0) {
                    if (p->tok.kind == TOK_EOF) {
                        die("%s:%d:%d: unexpected EOF in __attribute__", p->lx.path, p->tok.line, p->tok.col);
                    }
                    if (tok_is_ident(p, "packed")) packed = 1;
                    if (consume(p, TOK_LPAREN)) {
                        depth++;
                        continue;
                    }
                    if (consume(p, TOK_RPAREN)) {
                        depth--;
                        continue;
                    }
                    parser_next(p);
                }
            }
            continue;
        }
        if (tok_is_ident(p, "__asm__") || tok_is_ident(p, "__asm")) {
            parser_next(p);
            if (tok_is(p, TOK_LPAREN)) {
                skip_balanced(p, TOK_LPAREN, TOK_RPAREN);
            }
            continue;
        }
        break;
    }
    return packed;
}

static void skip_gcc_attrs(Parser *p) {
    (void)consume_gcc_attrs_has_packed(p);
}

static void struct_relayout(Parser *p, int struct_id) {
    if (!p || !p->prg) return;
    if (struct_id < 0 || struct_id >= p->prg->nstructs) return;
    StructDef *sd = &p->prg->structs[struct_id];

    int off = 0;
    int maxa = 1;
    for (int i = 0; i < sd->nmembers; i++) {
        StructMember *m = &sd->members[i];
        int al = sd->is_packed ? 1 : type_alignof(p->prg, m->base, m->ptr, m->struct_id);
        off = align_up(off, al);
        m->offset = off;
        off += m->size;
        if (al > maxa) maxa = al;
    }
    sd->align = sd->is_packed ? 1 : maxa;
    sd->size = align_up(off, sd->align);
    if (sd->size == 0) sd->size = 1;
}

static int skip_type_qualifiers(Parser *p, int *io_is_unsigned, int *io_is_short, int *io_is_long) {
    int any = 0;
    for (;;) {
        if (tok_is_ident(p, "const") || tok_is_ident(p, "volatile") || tok_is_ident(p, "register") ||
            tok_is_ident(p, "restrict") || tok_is_ident(p, "__restrict") || tok_is_ident(p, "__restrict__") ||
            tok_is_ident(p, "inline") || tok_is_ident(p, "__inline") || tok_is_ident(p, "__inline__") ||
            tok_is_ident(p, "signed") || tok_is_ident(p, "unsigned") || tok_is_ident(p, "short") ||
            tok_is_ident(p, "long")) {
            if (io_is_unsigned) {
                if (tok_is_ident(p, "unsigned")) *io_is_unsigned = 1;
                if (tok_is_ident(p, "signed")) *io_is_unsigned = 0;
            }
            if (io_is_short) {
                if (tok_is_ident(p, "short")) *io_is_short = 1;
            }
            if (io_is_long) {
                if (tok_is_ident(p, "long")) *io_is_long += 1;
            }
            parser_next(p);
            any = 1;
            continue;
        }
        break;
    }
    return any;
}

static int looks_like_type_start(Parser *p) {
    if (tok_is(p, TOK_KW_INT) || tok_is(p, TOK_KW_CHAR) || tok_is(p, TOK_KW_VOID) || tok_is(p, TOK_KW_STRUCT) ||
        tok_is(p, TOK_KW_ENUM))
        return 1;
    if (p->tok.kind == TOK_IDENT) {
        if (p->prg && program_find_typedef(p->prg, p->tok.start, p->tok.len)) return 1;
        if (tok_is_ident(p, "const") || tok_is_ident(p, "volatile") || tok_is_ident(p, "register") ||
            tok_is_ident(p, "restrict") || tok_is_ident(p, "__restrict") || tok_is_ident(p, "__restrict__") ||
            tok_is_ident(p, "inline") || tok_is_ident(p, "__inline") || tok_is_ident(p, "__inline__") ||
            tok_is_ident(p, "signed") || tok_is_ident(p, "unsigned") || tok_is_ident(p, "short") ||
            tok_is_ident(p, "long")) {
            return 1;
        }
    }
    return 0;
}

static void parse_struct_def(Parser *p, int struct_id);

static long long eval_const_expr(Parser *p, const Expr *e) {
    if (!e) die("%s:%d:%d: internal: null constant expression", p->lx.path, p->tok.line, p->tok.col);
    switch (e->kind) {
    case EXPR_NUM:
        return e->num;
    case EXPR_POS:
        return +eval_const_expr(p, e->lhs);
    case EXPR_NEG:
        return -eval_const_expr(p, e->lhs);
    case EXPR_NOT:
        return !eval_const_expr(p, e->lhs);
    case EXPR_BNOT:
        return ~eval_const_expr(p, e->lhs);
    case EXPR_CAST:
        // For now we treat casts in constant expressions as value-preserving.
        // (We don't model width/sign precisely yet; sysbox mainly uses casts for 0/NULL.)
        return eval_const_expr(p, e->lhs);
    case EXPR_MUL:
        return eval_const_expr(p, e->lhs) * eval_const_expr(p, e->rhs);
    case EXPR_DIV: {
        long long a = eval_const_expr(p, e->lhs);
        long long b = eval_const_expr(p, e->rhs);
        if (b == 0) die("%s:%d:%d: division by zero in constant expression", p->lx.path, p->tok.line, p->tok.col);
        return a / b;
    }
    case EXPR_MOD: {
        long long a = eval_const_expr(p, e->lhs);
        long long b = eval_const_expr(p, e->rhs);
        if (b == 0) die("%s:%d:%d: modulo by zero in constant expression", p->lx.path, p->tok.line, p->tok.col);
        return a % b;
    }
    case EXPR_ADD:
        return eval_const_expr(p, e->lhs) + eval_const_expr(p, e->rhs);
    case EXPR_SUB:
        return eval_const_expr(p, e->lhs) - eval_const_expr(p, e->rhs);
    case EXPR_SHL:
        return eval_const_expr(p, e->lhs) << eval_const_expr(p, e->rhs);
    case EXPR_SHR:
        return eval_const_expr(p, e->lhs) >> eval_const_expr(p, e->rhs);
    case EXPR_BAND:
        return eval_const_expr(p, e->lhs) & eval_const_expr(p, e->rhs);
    case EXPR_BXOR:
        return eval_const_expr(p, e->lhs) ^ eval_const_expr(p, e->rhs);
    case EXPR_BOR:
        return eval_const_expr(p, e->lhs) | eval_const_expr(p, e->rhs);
    case EXPR_EQ:
        return eval_const_expr(p, e->lhs) == eval_const_expr(p, e->rhs);
    case EXPR_NE:
        return eval_const_expr(p, e->lhs) != eval_const_expr(p, e->rhs);
    case EXPR_LT:
        return eval_const_expr(p, e->lhs) < eval_const_expr(p, e->rhs);
    case EXPR_LE:
        return eval_const_expr(p, e->lhs) <= eval_const_expr(p, e->rhs);
    case EXPR_GT:
        return eval_const_expr(p, e->lhs) > eval_const_expr(p, e->rhs);
    case EXPR_GE:
        return eval_const_expr(p, e->lhs) >= eval_const_expr(p, e->rhs);
    case EXPR_LAND:
        return eval_const_expr(p, e->lhs) && eval_const_expr(p, e->rhs);
    case EXPR_LOR:
        return eval_const_expr(p, e->lhs) || eval_const_expr(p, e->rhs);
    case EXPR_COND:
        return eval_const_expr(p, e->lhs) ? eval_const_expr(p, e->rhs) : eval_const_expr(p, e->third);
    default:
        die("%s:%d:%d: expected integer constant expression", p->lx.path, p->tok.line, p->tok.col);
    }
}

static void parse_enum_def(Parser *p) {
    // Minimal: parse enumerators and record values as constants.
    // enum [Name]? { A [= num]?, B, ... }
    // We treat enum type as int.
    expect(p, TOK_LBRACE, "'{'");
    long long v = 0;
    while (!tok_is(p, TOK_RBRACE)) {
        if (tok_is(p, TOK_EOF)) {
            die("%s:%d:%d: unexpected EOF in enum", p->lx.path, p->tok.line, p->tok.col);
        }
        const char *nm = NULL;
        size_t nm_len = 0;
        expect_ident(p, &nm, &nm_len);
        skip_gcc_attrs(p);
        if (consume(p, TOK_ASSIGN)) {
            Expr *init = parse_expr(p, NULL);
            v = eval_const_expr(p, init);
        }
        program_add_const(p->prg, nm, nm_len, v);
        v++;
        if (consume(p, TOK_COMMA)) {
            if (tok_is(p, TOK_RBRACE)) break;
            continue;
        }
        break;
    }
    expect(p, TOK_RBRACE, "'}'");
}

static void parse_type_spec(Parser *p, BaseType *out_base, int *out_ptr, int *out_struct_id, int *out_is_unsigned, int parse_ptr_stars) {
    int is_unsigned = 0;
    int is_short = 0;
    int is_long = 0;
    int had_quals = skip_type_qualifiers(p, &is_unsigned, &is_short, &is_long);
    BaseType base = BT_INT;
    int ptr = 0;
    int sid = -1;

    if (p->tok.kind == TOK_IDENT && p->prg) {
        const Typedef *td = program_find_typedef(p->prg, p->tok.start, p->tok.len);
        if (td) {
            base = td->base;
            ptr = td->ptr;
            sid = td->struct_id;
            is_unsigned = td->is_unsigned;
            parser_next(p);
            (void)skip_type_qualifiers(p, &is_unsigned, &is_short, &is_long);
            if (parse_ptr_stars) {
                while (consume(p, TOK_STAR)) {
                    ptr++;
                    (void)skip_type_qualifiers(p, &is_unsigned, &is_short, &is_long);
                }
            }
            if (out_base) *out_base = base;
            if (out_ptr) *out_ptr = ptr;
            if (out_struct_id) *out_struct_id = sid;
            if (out_is_unsigned) *out_is_unsigned = is_unsigned;
            return;
        }
    }

    if (consume(p, TOK_KW_INT)) {
        base = BT_INT;
    } else if (consume(p, TOK_KW_CHAR)) {
        base = BT_CHAR;
    } else if (consume(p, TOK_KW_VOID)) {
        base = BT_VOID;
    } else if (consume(p, TOK_KW_STRUCT)) {
        const char *nm = NULL;
        size_t nm_len = 0;

        int saw_packed = 0;

        // Allow GCC-style attributes between 'struct' and the tag name.
        saw_packed |= consume_gcc_attrs_has_packed(p);

        if (p->tok.kind == TOK_IDENT) {
            expect_ident(p, &nm, &nm_len);
            sid = program_get_or_add_struct(p->prg, nm, nm_len);
        } else {
            // anonymous struct (e.g. typedef struct { ... } Name;)
            sid = program_add_anon_struct(p->prg);
        }

        // Allow attributes after the tag name.
        saw_packed |= consume_gcc_attrs_has_packed(p);

        if (tok_is(p, TOK_LBRACE)) {
            parse_struct_def(p, sid);
        }

        // Allow attributes after the definition: `struct S { ... } __attribute__((packed))`.
        saw_packed |= consume_gcc_attrs_has_packed(p);
        if (sid >= 0 && sid < p->prg->nstructs && saw_packed) {
            p->prg->structs[sid].is_packed = 1;
            struct_relayout(p, sid);
        }

        base = BT_STRUCT;
    } else if (consume(p, TOK_KW_ENUM)) {
        // enum [Name]? [{...}]?
        if (p->tok.kind == TOK_IDENT) {
            parser_next(p);
        }
        if (tok_is(p, TOK_LBRACE)) {
            parse_enum_def(p);
        }
        base = BT_INT;
    } else {
        if (had_quals) {
            base = BT_INT;
        } else {
            die("%s:%d:%d: expected type", p->lx.path, p->tok.line, p->tok.col);
        }
    }

    (void)skip_type_qualifiers(p, &is_unsigned, &is_short, &is_long);

    // Apply width modifiers (subset): short/long => BT_SHORT/BT_LONG (implies int).
    // Treat 'long long' the same as 'long' (8 bytes) for now.
    if (is_short && is_long) {
        die("%s:%d:%d: invalid type modifiers: short and long", p->lx.path, p->tok.line, p->tok.col);
    }
    if (base == BT_INT) {
        if (is_short) {
            base = BT_SHORT;
        } else if (is_long) {
            base = BT_LONG;
        }
    }

    if (parse_ptr_stars) {
        while (consume(p, TOK_STAR)) {
            ptr++;
            (void)skip_type_qualifiers(p, &is_unsigned, &is_short, &is_long);
        }
    }

    if (out_base) *out_base = base;
    if (out_ptr) *out_ptr = ptr;
    if (out_struct_id) *out_struct_id = sid;
    if (out_is_unsigned) *out_is_unsigned = is_unsigned;
}

static int hexval(unsigned char c) {
    if (c >= '0' && c <= '9') return (int)(c - '0');
    if (c >= 'a' && c <= 'f') return 10 + (int)(c - 'a');
    if (c >= 'A' && c <= 'F') return 10 + (int)(c - 'A');
    return -1;
}

static unsigned char parse_escape_seq(Parser *p, const Token *at, const char **pp, const char *end) {
    if (*pp >= end) {
        die("%s:%d:%d: invalid escape sequence", p->lx.path, at->line, at->col);
    }
    unsigned char c = (unsigned char)**pp;
    (*pp)++;
    switch (c) {
        case 'n':
            return (unsigned char)'\n';
        case 'b':
            return (unsigned char)'\b';
        case 't':
            return (unsigned char)'\t';
        case 'v':
            return (unsigned char)'\v';
        case 'f':
            return (unsigned char)'\f';
        case 'r':
            return (unsigned char)'\r';
        case 'a':
            return (unsigned char)'\a';
        case '\\':
            return (unsigned char)'\\';
        case '\'':
            return (unsigned char)'\'';
        case '"':
            return (unsigned char)'"';
        case '?':
            return (unsigned char)'?';
        case '0':
        case '1':
        case '2':
        case '3':
        case '4':
        case '5':
        case '6':
        case '7': {
            // Octal: up to 3 digits (we already consumed one).
            unsigned int v = (unsigned int)(c - '0');
            for (int i = 0; i < 2 && *pp < end; i++) {
                unsigned char d = (unsigned char)**pp;
                if (d < '0' || d > '7') break;
                (*pp)++;
                v = (v << 3) | (unsigned int)(d - '0');
            }
            return (unsigned char)(v & 0xffu);
        }
        case 'x': {
            unsigned int v = 0;
            int nd = 0;
            while (*pp < end) {
                int hv = hexval((unsigned char)**pp);
                if (hv < 0) break;
                (*pp)++;
                v = (v << 4) | (unsigned int)hv;
                nd++;
            }
            if (nd == 0) {
                die("%s:%d:%d: invalid hex escape", p->lx.path, at->line, at->col);
            }
            return (unsigned char)(v & 0xffu);
        }
        default:
            // Permissive: unknown escapes become the escaped char.
            return c;
    }
}

static unsigned char parse_char_literal(Parser *p, const Token *t) {
    if (t->len < 2 || t->start[0] != '\'' || t->start[t->len - 1] != '\'') {
        die("%s:%d:%d: invalid char literal", p->lx.path, t->line, t->col);
    }
    const char *q = t->start + 1;
    const char *end = t->start + t->len - 1;
    if (q >= end) {
        die("%s:%d:%d: empty char literal", p->lx.path, t->line, t->col);
    }
    unsigned char v = 0;
    if (*q == '\\') {
        q++;
        v = parse_escape_seq(p, t, &q, end);
    } else {
        v = (unsigned char)*q;
        q++;
    }
    if (q != end) {
        die("%s:%d:%d: multi-character char literal not supported", p->lx.path, t->line, t->col);
    }
    return v;
}

static unsigned char *parse_string_literal(Parser *p, const Token *t, size_t *out_len) {
    if (t->len < 2 || t->start[0] != '"' || t->start[t->len - 1] != '"') {
        die("%s:%d:%d: invalid string literal", p->lx.path, t->line, t->col);
    }
    const char *q = t->start + 1;
    const char *end = t->start + t->len - 1;
    size_t cap = 64;
    size_t len = 0;
    unsigned char *buf = (unsigned char *)monacc_malloc(cap);
    if (!buf) die("oom");
    while (q < end) {
        unsigned char c = (unsigned char)*q++;
        if (c == '\\') {
            c = parse_escape_seq(p, t, &q, end);
        }
        if (len + 1 > cap) {
            size_t ncap = cap * 2;
            unsigned char *nb = (unsigned char *)monacc_realloc(buf, ncap);
            if (!nb) die("oom");
            buf = nb;
            cap = ncap;
        }
        buf[len++] = c;
    }
    // Ensure trailing NUL in memory.
    if (len + 1 > cap) {
        unsigned char *nb = (unsigned char *)monacc_realloc(buf, cap + 1);
        if (!nb) die("oom");
        buf = nb;
        cap++;
    }
    buf[len++] = 0;
    *out_len = len;
    return buf;
}

static Expr *parse_primary(Parser *p, Locals *ls) {
    if (consume(p, TOK_LPAREN)) {
        Expr *e = parse_expr(p, ls);
            expect(p, TOK_RPAREN, "')'");
        return e;
    }
    if (p->tok.kind == TOK_NUM) {
        Expr *e = new_expr(EXPR_NUM);
        e->num = p->tok.num;
        e->base = BT_INT;
        e->ptr = 0;
        e->struct_id = -1;
        e->is_unsigned = 0;
        e->lval_size = 8;
        parser_next(p);
        return e;
    }
    if (p->tok.kind == TOK_CHAR) {
        Token t = p->tok;
        unsigned char v = parse_char_literal(p, &t);
        parser_next(p);
        Expr *e = new_expr(EXPR_NUM);
        e->num = (long long)v;
        e->base = BT_INT;
        e->ptr = 0;
        e->struct_id = -1;
        e->is_unsigned = 0;
        e->lval_size = 8;
        return e;
    }
    if (p->tok.kind == TOK_STR) {
        // Support C string literal concatenation: "a" "b" => "ab"
        size_t acc_len = 0;
        unsigned char *acc = NULL;

        Token t0 = p->tok;
        acc = parse_string_literal(p, &t0, &acc_len);
        parser_next(p);

        while (p->tok.kind == TOK_STR) {
            Token t1 = p->tok;
            size_t b_len = 0;
            unsigned char *b = parse_string_literal(p, &t1, &b_len);

            if (acc_len == 0 || b_len == 0) die("internal: bad string literal length");
            // Replace previous trailing NUL with next string including its NUL.
            size_t new_len = (acc_len - 1) + b_len;
            unsigned char *nb = (unsigned char *)monacc_realloc(acc, new_len);
            if (!nb) die("oom");
            acc = nb;
            mc_memcpy(acc + (acc_len - 1), b, b_len);
            acc_len = new_len;

            monacc_free(b);
            parser_next(p);
        }

        int id = program_add_str(p->prg, acc, acc_len);
        monacc_free(acc);
        Expr *e = new_expr(EXPR_STR);
        e->str_id = id;
        e->base = BT_CHAR;
        e->ptr = 1;
        e->struct_id = -1;
        e->is_unsigned = 0;
        e->lval_size = 8;
        return e;
    }
    if (p->tok.kind == TOK_IDENT) {
        Token ident = p->tok;
        parser_next(p);

        const Local *l = ls ? local_find(ls, ident.start, ident.len) : NULL;

        if (consume(p, TOK_LPAREN)) {
            const Function *fn_sig = NULL;
            if (!l) {
                fn_sig = program_find_fn(p->prg, ident.start, ident.len);
                // Mark the function as called (for dead-code elimination of static functions)
                program_mark_fn_called(p->prg, ident.start, ident.len);
            }

            int is_sret = 0;
            int sret_size = 0;
            int sret_sid = -1;
            if (fn_sig && fn_sig->ret_base == BT_STRUCT && fn_sig->ret_ptr == 0) {
                is_sret = 1;
                sret_size = fn_sig->ret_size;
                sret_sid = fn_sig->ret_struct_id;
                if (sret_size <= 0) {
                    sret_size = type_sizeof(p->prg, BT_STRUCT, 0, sret_sid);
                }
                if (!ls) {
                    die("%s:%d:%d: struct-return call not supported at top-level", p->lx.path, ident.line, ident.col);
                }
            }

            Expr *e = new_expr(is_sret ? EXPR_SRET_CALL : EXPR_CALL);
            // If the identifier is a local pointer variable, treat this as an indirect call.
            if (l) {
                if (l->global_id >= 0) {
                    Expr *callee = new_expr(EXPR_GLOBAL);
                    callee->global_id = l->global_id;
                    const GlobalVar *gv = &p->prg->globals[l->global_id];
                    callee->base = gv->base;
                    callee->ptr = gv->ptr;
                    callee->struct_id = gv->struct_id;
                    callee->is_unsigned = gv->is_unsigned;
                    callee->lval_size = (gv->base == BT_STRUCT && gv->ptr == 0) ? gv->size : ((gv->elem_size == 1) ? 1 : (gv->elem_size == 2) ? 2 : (gv->elem_size == 4) ? 4 : 8);
                    e->lhs = callee;
                } else {
                if (l->ptr == 0) {
                    die("%s:%d:%d: cannot call non-pointer '%.*s'", p->lx.path, ident.line, ident.col, (int)ident.len, ident.start);
                }
                if (is_sret) {
                    die("%s:%d:%d: struct-return via indirect call not supported", p->lx.path, ident.line, ident.col);
                }
                Expr *callee = new_expr(EXPR_VAR);
                callee->var_offset = l->offset;
                callee->var_alloc_size = l->alloc_size;
                callee->base = l->base;
                callee->ptr = l->ptr;
                callee->struct_id = l->struct_id;
                callee->is_unsigned = l->is_unsigned;
                callee->lval_size = l->size;
                e->lhs = callee;
                }
            } else {
                if (ident.len == 0 || ident.len >= sizeof(e->callee)) {
                    die("%s:%d:%d: callee name too long", p->lx.path, ident.line, ident.col);
                }
                mc_memcpy(e->callee, ident.start, ident.len);
                e->callee[ident.len] = 0;
            }

            Expr **args = NULL;
            int nargs = 0;
            int cap = 0;
            if (!tok_is(p, TOK_RPAREN)) {
                for (;;) {
                    if (nargs + 1 > cap) {
                        int ncap = cap ? cap * 2 : 4;
                        Expr **na = (Expr **)monacc_realloc(args, (size_t)ncap * sizeof(*na));
                        if (!na) die("oom");
                        args = na;
                        cap = ncap;
                    }
                    args[nargs++] = parse_expr(p, ls);
                    if (consume(p, TOK_COMMA)) continue;
                    break;
                }
            }
            expect(p, TOK_RPAREN, "')'");
            e->args = args;
            e->nargs = nargs;

            if (is_sret) {
                // Materialize struct return into a temporary stack object.
                char tmpnm[64];
                mc_snprint_cstr_u64_cstr(tmpnm, sizeof(tmpnm), "__monacc_sretcall", (mc_u64)ls->nlocals, "");
                int off = local_add(ls, tmpnm, mc_strlen(tmpnm), BT_STRUCT, 0, sret_sid, 0, sret_size, sret_size, 0);
                e->var_offset = off;
                e->base = BT_STRUCT;
                e->ptr = 0;
                e->struct_id = sret_sid;
                e->is_unsigned = 0;
                e->lval_size = sret_size;
            } else if (fn_sig) {
                e->base = fn_sig->ret_base;
                e->ptr = fn_sig->ret_ptr;
                e->struct_id = fn_sig->ret_struct_id;
                e->is_unsigned = fn_sig->ret_is_unsigned;
                if (e->base == BT_VOID && e->ptr == 0) {
                    // Void return: keep a well-defined register value.
                    e->lval_size = 8;
                } else {
                    int sz = type_sizeof(p->prg, e->base, e->ptr, e->struct_id);
                    e->lval_size = (sz == 1) ? 1 : (sz == 2) ? 2 : (sz == 4) ? 4 : 8;
                }
            } else {
                e->base = BT_INT;
                e->ptr = 0;
                e->struct_id = -1;
                e->is_unsigned = 0;
                e->lval_size = 8;
            }
            return e;
        }

        if (!l) {
            const ConstDef *c = program_find_const(p->prg, ident.start, ident.len);
            if (c) {
                Expr *e = new_expr(EXPR_NUM);
                e->num = c->value;
                e->base = BT_INT;
                e->ptr = 0;
                e->struct_id = -1;
                e->is_unsigned = 0;
                e->lval_size = 8;
                return e;
            }

            const Function *fn = program_find_fn(p->prg, ident.start, ident.len);
            if (fn) {
                // Mark the function as used (address taken counts as used)
                program_mark_fn_called(p->prg, ident.start, ident.len);
                Expr *e = new_expr(EXPR_FNADDR);
                if (ident.len == 0 || ident.len >= sizeof(e->callee)) {
                    die("%s:%d:%d: callee name too long", p->lx.path, ident.line, ident.col);
                }
                mc_memcpy(e->callee, ident.start, ident.len);
                e->callee[ident.len] = 0;
                e->base = BT_VOID;
                e->ptr = 1;
                e->struct_id = -1;
                e->is_unsigned = 1;
                e->lval_size = 8;
                return e;
            }

            int gid = program_find_global(p->prg, ident.start, ident.len);
            if (gid >= 0) {
                const GlobalVar *gv = &p->prg->globals[gid];
                Expr *e = new_expr(EXPR_GLOBAL);
                e->global_id = gid;
                e->base = gv->base;
                e->ptr = gv->ptr;
                e->struct_id = gv->struct_id;
                e->is_unsigned = gv->is_unsigned;
                // For arrays, the expression decays to a pointer
                if (gv->array_len != 0) {
                    e->ptr++;
                    e->lval_size = 0; // array, not a direct lvalue
                    e->var_alloc_size = gv->size;
                } else {
                    // For structs, preserve the true object size so assignments can memcpy the full object.
                    if (gv->base == BT_STRUCT && gv->ptr == 0) {
                        e->lval_size = gv->size;
                    } else {
                        e->lval_size = (gv->elem_size == 1) ? 1 : (gv->elem_size == 2) ? 2 : (gv->elem_size == 4) ? 4 : 8;
                    }
                }
                return e;
            }

            die("%s:%d:%d: unknown identifier '%.*s'", p->lx.path, ident.line, ident.col, (int)ident.len, ident.start);
        }
        Expr *e = new_expr(EXPR_VAR);
        if (l->global_id >= 0) {
            const GlobalVar *gv = &p->prg->globals[l->global_id];
            Expr *g = new_expr(EXPR_GLOBAL);
            g->global_id = l->global_id;
            g->base = gv->base;
            g->ptr = gv->ptr;
            g->struct_id = gv->struct_id;
            g->is_unsigned = gv->is_unsigned;
            if (gv->array_len != 0) {
                g->ptr++;
                g->lval_size = 0;
                g->var_alloc_size = gv->size;
            } else if (gv->base == BT_STRUCT && gv->ptr == 0) {
                g->lval_size = gv->size;
            } else {
                g->lval_size = (gv->elem_size == 1) ? 1 : (gv->elem_size == 2) ? 2 : (gv->elem_size == 4) ? 4 : 8;
            }
            return g;
        }
        e->var_offset = l->offset;
        e->var_alloc_size = l->alloc_size;
        e->base = l->base;
        e->ptr = l->ptr;
        e->struct_id = l->struct_id;
        e->is_unsigned = l->is_unsigned;
        e->lval_size = l->size;
        e->array_stride = l->array_stride;
        return e;
    }
    int show = (int)(p->tok.len > 24 ? 24 : p->tok.len);
    die("%s:%d:%d: expected expression (got %s '%.*s')", p->lx.path, p->tok.line, p->tok.col, tok_kind_name(p->tok.kind),
        show, p->tok.start ? p->tok.start : "");
}

static int ptr_pointee_size(const Program *prg, BaseType base, int ptr, int struct_id) {
    if (ptr <= 0) return 8;
    if (ptr == 1 && base == BT_VOID) return 1;
    if (ptr == 1) return type_sizeof(prg, base, 0, struct_id);
    return 8;
}

static int expr_is_lvalue(const Expr *e) {
    if (!e) return 0;
    return e->kind == EXPR_VAR || e->kind == EXPR_GLOBAL || e->kind == EXPR_DEREF || e->kind == EXPR_INDEX || e->kind == EXPR_MEMBER || e->kind == EXPR_COMPOUND ||
           e->kind == EXPR_SRET_CALL || e->kind == EXPR_COND_LVAL;
}

static Expr *parse_struct_init_compound(Parser *p, Locals *ls, int sid);

static Expr *parse_postfix(Parser *p, Locals *ls) {
    Expr *e = parse_primary(p, ls);
    for (;;) {
        if (consume(p, TOK_PLUSPLUS)) {
            if (!expr_is_lvalue(e) || e->lval_size == 0) {
                die("%s:%d:%d: cannot apply ++ to this expression", p->lx.path, p->tok.line, p->tok.col);
            }
            Expr *n = new_expr(EXPR_POSTINC);
            n->lhs = e;
            n->base = e->base;
            n->ptr = e->ptr;
            n->struct_id = e->struct_id;
            n->is_unsigned = e->is_unsigned;
            n->lval_size = e->lval_size;
            n->post_delta = (e->ptr > 0) ? ptr_pointee_size(p->prg, e->base, e->ptr, e->struct_id) : 1;
            e = n;
            continue;
        }
        if (consume(p, TOK_MINUSMINUS)) {
            if (!expr_is_lvalue(e) || e->lval_size == 0) {
                die("%s:%d:%d: cannot apply -- to this expression", p->lx.path, p->tok.line, p->tok.col);
            }
            Expr *n = new_expr(EXPR_POSTDEC);
            n->lhs = e;
            n->base = e->base;
            n->ptr = e->ptr;
            n->struct_id = e->struct_id;
            n->is_unsigned = e->is_unsigned;
            n->lval_size = e->lval_size;
            n->post_delta = (e->ptr > 0) ? ptr_pointee_size(p->prg, e->base, e->ptr, e->struct_id) : 1;
            e = n;
            continue;
        }
        if (consume(p, TOK_LBRACK)) {
            Expr *idx = parse_expr(p, ls);
            expect(p, TOK_RBRACK, "']'");
            if (e->ptr <= 0) {
                die("%s:%d:%d: subscripted value is not a pointer", p->lx.path, p->tok.line, p->tok.col);
            }
            int scale = 0;
            int row_from_2d = 0;
            if (e->array_stride > 0 && e->ptr >= 2) {
                // First index of an array-of-array (e.g. T a[N][M]): a[i] is an lvalue of array type.
                // When used as an rvalue it decays to the address of the row; it is NOT a stored pointer.
                row_from_2d = 1;
                scale = e->array_stride;
            } else {
                scale = ptr_pointee_size(p->prg, e->base, e->ptr, e->struct_id);
            }
            Expr *n = new_expr(EXPR_INDEX);
            n->lhs = e;
            n->rhs = idx;
            n->base = e->base;
            n->ptr = e->ptr - 1;
            n->struct_id = e->struct_id;
            n->ptr_scale = scale;
            n->lval_size = row_from_2d ? 0 : type_sizeof(p->prg, n->base, n->ptr, n->struct_id);
            e = n;
            continue;
        }
        if (tok_is(p, TOK_DOT) || tok_is(p, TOK_ARROW)) {
            int is_arrow = consume(p, TOK_ARROW);
            if (!is_arrow) (void)consume(p, TOK_DOT);
            const char *mn = NULL;
            size_t mn_len = 0;
            expect_ident(p, &mn, &mn_len);

            int sid = -1;
            if (is_arrow) {
                if (e->base != BT_STRUCT || e->ptr <= 0) {
                    die("%s:%d:%d: '->' requires pointer-to-struct", p->lx.path, p->tok.line, p->tok.col);
                }
                sid = e->struct_id;
            } else {
                if (e->base != BT_STRUCT || e->ptr != 0) {
                    die("%s:%d:%d: '.' requires struct value", p->lx.path, p->tok.line, p->tok.col);
                }
                sid = e->struct_id;
            }
            const StructMember *m = struct_find_member(p->prg, sid, mn, mn_len);
            if (!m) {
                die("%s:%d:%d: unknown struct member '%.*s'", p->lx.path, p->tok.line, p->tok.col, (int)mn_len, mn);
            }
            Expr *n = new_expr(EXPR_MEMBER);
            n->lhs = e;
            n->member_off = m->offset;
            n->member_is_arrow = is_arrow;
            n->base = m->base;
            n->struct_id = m->struct_id;
            n->is_unsigned = m->is_unsigned;
            if (m->array_len) {
                // Array member decays. For 2D arrays, allow lines[i][j] by modeling
                // it as pointer-to-pointer with a stride on the first index.
                if (m->array_len2 > 0) {
                    int esz = type_sizeof(p->prg, m->base, m->ptr, m->struct_id);
                    n->ptr = m->ptr + 2;
                    n->array_stride = esz * m->array_len2;
                } else {
                    n->ptr = m->ptr + 1;
                }
                n->lval_size = 0; // special: rvalue is address (no load)
            } else {
                n->ptr = m->ptr;
                n->lval_size = type_sizeof(p->prg, n->base, n->ptr, n->struct_id);
            }
            e = n;
            continue;
        }
        return e;
    }
}

static Expr *parse_unary(Parser *p, Locals *ls) {
    if (consume(p, TOK_PLUSPLUS)) {
        Expr *inner = parse_unary(p, ls);
        if (!expr_is_lvalue(inner) || inner->lval_size == 0) {
            die("%s:%d:%d: cannot apply ++ to this expression", p->lx.path, p->tok.line, p->tok.col);
        }
        Expr *e = new_expr(EXPR_PREINC);
        e->lhs = inner;
        e->base = inner->base;
        e->ptr = inner->ptr;
        e->struct_id = inner->struct_id;
        e->is_unsigned = inner->is_unsigned;
        e->lval_size = inner->lval_size;
        e->post_delta = (inner->ptr > 0) ? ptr_pointee_size(p->prg, inner->base, inner->ptr, inner->struct_id) : 1;
        return e;
    }
    if (consume(p, TOK_MINUSMINUS)) {
        Expr *inner = parse_unary(p, ls);
        if (!expr_is_lvalue(inner) || inner->lval_size == 0) {
            die("%s:%d:%d: cannot apply -- to this expression", p->lx.path, p->tok.line, p->tok.col);
        }
        Expr *e = new_expr(EXPR_PREDEC);
        e->lhs = inner;
        e->base = inner->base;
        e->ptr = inner->ptr;
        e->struct_id = inner->struct_id;
        e->is_unsigned = inner->is_unsigned;
        e->lval_size = inner->lval_size;
        e->post_delta = (inner->ptr > 0) ? ptr_pointee_size(p->prg, inner->base, inner->ptr, inner->struct_id) : 1;
        return e;
    }

    // C cast: (type) expr
    if (tok_is(p, TOK_LPAREN)) {
        Parser bak = *p;
        parser_next(p);
        if (looks_like_type_start(p)) {
            BaseType tb = BT_INT;
            int tptr = 0;
            int tsid = -1;
            int tis_unsigned = 0;
            parse_type_spec(p, &tb, &tptr, &tsid, &tis_unsigned, 1);
            skip_gcc_attrs(p);

            // Support function-pointer casts like: (void (*)(int))1
            if (tok_is(p, TOK_LPAREN)) {
                Parser bak2 = *p;
                parser_next(p);
                skip_gcc_attrs(p);
                if (!consume(p, TOK_STAR)) {
                    *p = bak2;
                } else {
                    tptr++;
                    if (p->tok.kind == TOK_IDENT) {
                        parser_next(p);
                    }
                    skip_gcc_attrs(p);
                    expect(p, TOK_RPAREN, "')'");
                    skip_gcc_attrs(p);
                    if (tok_is(p, TOK_LPAREN)) {
                        skip_balanced(p, TOK_LPAREN, TOK_RPAREN);
                        skip_gcc_attrs(p);
                    }
                }
            }

            if (consume(p, TOK_RPAREN)) {
                // C99 compound literal: (type){ ... }
                if (tok_is(p, TOK_LBRACE)) {
                    if (tb != BT_STRUCT || tptr != 0) {
                        die("%s:%d:%d: compound literal only supported for struct values", bak.lx.path, bak.tok.line, bak.tok.col);
                    }
                    return parse_struct_init_compound(p, ls, tsid);
                }
                Expr *inner = parse_unary(p, ls);
                if (tb == BT_STRUCT && tptr == 0) {
                    die("%s:%d:%d: cast to struct value not supported", bak.lx.path, bak.tok.line, bak.tok.col);
                }
                Expr *e = new_expr(EXPR_CAST);
                e->lhs = inner;
                e->base = tb;
                e->ptr = tptr;
                e->struct_id = tsid;
                e->is_unsigned = tis_unsigned;
                if (tb == BT_VOID && tptr == 0) {
                    // (void)expr is common for intentionally discarding a value.
                    e->lval_size = 0;
                } else {
                    int sz = type_sizeof(p->prg, tb, tptr, tsid);
                    e->lval_size = (sz == 1) ? 1 : (sz == 2) ? 2 : (sz == 4) ? 4 : 8;
                }
                return e;
            }
        }
        *p = bak;
    }

    if (consume(p, TOK_KW_SIZEOF)) {
        long long sz = 0;
        if (consume(p, TOK_LPAREN)) {
            if (looks_like_type_start(p)) {
                BaseType b = BT_INT;
                int ptr = 0;
                int sid = -1;
                parse_type_spec(p, &b, &ptr, &sid, NULL, 1);
                skip_gcc_attrs(p);
                expect(p, TOK_RPAREN, "')'");
                sz = (long long)type_sizeof(p->prg, b, ptr, sid);
            } else {
                Expr *inner = parse_expr(p, ls);
                expect(p, TOK_RPAREN, "')'");
                sz = expr_sizeof(p, inner);
            }
        } else {
            Expr *inner = parse_unary(p, ls);
            sz = expr_sizeof(p, inner);
        }
        Expr *e = new_expr(EXPR_NUM);
        e->num = sz;
        e->base = BT_INT;
        e->ptr = 0;
        e->struct_id = -1;
        e->is_unsigned = 0;
        e->lval_size = 8;
        return e;
    }
    if (consume(p, TOK_PLUS)) {
        Expr *e = new_expr(EXPR_POS);
        e->lhs = parse_unary(p, ls);
        e->base = e->lhs ? e->lhs->base : BT_INT;
        e->ptr = e->lhs ? e->lhs->ptr : 0;
        e->struct_id = e->lhs ? e->lhs->struct_id : -1;
        e->lval_size = 8;
        return e;
    }
    if (consume(p, TOK_MINUS)) {
        Expr *e = new_expr(EXPR_NEG);
        e->lhs = parse_unary(p, ls);
        e->base = BT_INT;
        e->ptr = 0;
        e->struct_id = -1;
        e->lval_size = 8;
        return e;
    }
    if (consume(p, TOK_BANG)) {
        Expr *e = new_expr(EXPR_NOT);
        e->lhs = parse_unary(p, ls);
        e->base = BT_INT;
        e->ptr = 0;
        e->struct_id = -1;
        e->lval_size = 8;
        return e;
    }
    if (consume(p, TOK_TILDE)) {
        Expr *e = new_expr(EXPR_BNOT);
        e->lhs = parse_unary(p, ls);
        e->base = BT_INT;
        e->ptr = 0;
        e->struct_id = -1;
        e->lval_size = 8;
        return e;
    }
    if (consume(p, TOK_AMP)) {
        Expr *e = new_expr(EXPR_ADDR);
        e->lhs = parse_unary(p, ls);
        if (!e->lhs) die("internal: addr-of missing operand");
        e->base = e->lhs->base;
        e->ptr = e->lhs->ptr + 1;
        e->struct_id = e->lhs->struct_id;
        e->lval_size = 8;
        return e;
    }
    if (consume(p, TOK_STAR)) {
        Expr *e = new_expr(EXPR_DEREF);
        e->lhs = parse_unary(p, ls);
        if (!e->lhs || e->lhs->ptr <= 0) {
            die("%s:%d:%d: cannot dereference non-pointer", p->lx.path, p->tok.line, p->tok.col);
        }
        e->base = e->lhs->base;
        e->ptr = e->lhs->ptr - 1;
        e->struct_id = e->lhs->struct_id;
        e->lval_size = type_sizeof(p->prg, e->base, e->ptr, e->struct_id);
        return e;
    }
    return parse_postfix(p, ls);
}

static Expr *parse_mul(Parser *p, Locals *ls) {
    Expr *e = parse_unary(p, ls);
    for (;;) {
        if (consume(p, TOK_STAR)) {
            Expr *n = new_expr(EXPR_MUL);
            n->lhs = e;
            n->rhs = parse_unary(p, ls);
            e = n;
            continue;
        }
        if (consume(p, TOK_SLASH)) {
            Expr *n = new_expr(EXPR_DIV);
            n->lhs = e;
            n->rhs = parse_unary(p, ls);
            e = n;
            continue;
        }
        if (consume(p, TOK_PERCENT)) {
            Expr *n = new_expr(EXPR_MOD);
            n->lhs = e;
            n->rhs = parse_unary(p, ls);
            e = n;
            continue;
        }
        return e;
    }
}

static Expr *parse_add(Parser *p, Locals *ls) {
    Expr *e = parse_mul(p, ls);
    for (;;) {
        if (consume(p, TOK_PLUS)) {
            Expr *n = new_expr(EXPR_ADD);
            n->lhs = e;
            n->rhs = parse_mul(p, ls);
            // pointer + int or int + pointer
            if (n->lhs && n->rhs && n->lhs->ptr > 0 && n->rhs->ptr == 0) {
                n->base = n->lhs->base;
                n->ptr = n->lhs->ptr;
                n->struct_id = n->lhs->struct_id;
                n->ptr_scale = ptr_pointee_size(p->prg, n->lhs->base, n->lhs->ptr, n->lhs->struct_id);
                n->ptr_index_side = 1;
            } else if (n->lhs && n->rhs && n->lhs->ptr == 0 && n->rhs->ptr > 0) {
                n->base = n->rhs->base;
                n->ptr = n->rhs->ptr;
                n->struct_id = n->rhs->struct_id;
                n->ptr_scale = ptr_pointee_size(p->prg, n->rhs->base, n->rhs->ptr, n->rhs->struct_id);
                n->ptr_index_side = 2;
            } else {
                n->base = BT_INT;
                n->ptr = 0;
                n->struct_id = -1;
            }
            n->lval_size = 8;
            e = n;
            continue;
        }
        if (consume(p, TOK_MINUS)) {
            Expr *n = new_expr(EXPR_SUB);
            n->lhs = e;
            n->rhs = parse_mul(p, ls);
            if (n->lhs && n->rhs && n->lhs->ptr > 0 && n->rhs->ptr == 0) {
                n->base = n->lhs->base;
                n->ptr = n->lhs->ptr;
                n->struct_id = n->lhs->struct_id;
                n->ptr_scale = ptr_pointee_size(p->prg, n->lhs->base, n->lhs->ptr, n->lhs->struct_id);
                n->ptr_index_side = 1;
            } else if (n->lhs && n->rhs && n->lhs->ptr == 0 && n->rhs->ptr > 0) {
                die("%s:%d:%d: int - pointer not supported", p->lx.path, p->tok.line, p->tok.col);
            } else {
                n->base = BT_INT;
                n->ptr = 0;
                n->struct_id = -1;
            }
            n->lval_size = 8;
            e = n;
            continue;
        }
        return e;
    }
}

static Expr *parse_shift(Parser *p, Locals *ls) {
    Expr *e = parse_add(p, ls);
    for (;;) {
        if (consume(p, TOK_SHL)) {
            Expr *n = new_expr(EXPR_SHL);
            n->lhs = e;
            n->rhs = parse_add(p, ls);
            n->base = BT_INT;
            n->ptr = 0;
            n->struct_id = -1;
            n->lval_size = 8;
            e = n;
            continue;
        }
        if (consume(p, TOK_SHR)) {
            Expr *n = new_expr(EXPR_SHR);
            n->lhs = e;
            n->rhs = parse_add(p, ls);
            n->base = BT_INT;
            n->ptr = 0;
            n->struct_id = -1;
            n->lval_size = 8;
            e = n;
            continue;
        }
        return e;
    }
}

static Expr *parse_rel(Parser *p, Locals *ls) {
    Expr *e = parse_shift(p, ls);
    for (;;) {
        if (consume(p, TOK_LT)) {
            Expr *n = new_expr(EXPR_LT);
            n->lhs = e;
            n->rhs = parse_shift(p, ls);
            e = n;
            continue;
        }
        if (consume(p, TOK_LE)) {
            Expr *n = new_expr(EXPR_LE);
            n->lhs = e;
            n->rhs = parse_shift(p, ls);
            e = n;
            continue;
        }
        if (consume(p, TOK_GT)) {
            Expr *n = new_expr(EXPR_GT);
            n->lhs = e;
            n->rhs = parse_shift(p, ls);
            e = n;
            continue;
        }
        if (consume(p, TOK_GE)) {
            Expr *n = new_expr(EXPR_GE);
            n->lhs = e;
            n->rhs = parse_shift(p, ls);
            e = n;
            continue;
        }
        return e;
    }
}

static Expr *parse_eq(Parser *p, Locals *ls) {
    Expr *e = parse_rel(p, ls);
    for (;;) {
        if (consume(p, TOK_EQ)) {
            Expr *n = new_expr(EXPR_EQ);
            n->lhs = e;
            n->rhs = parse_rel(p, ls);
            e = n;
            continue;
        }
        if (consume(p, TOK_NE)) {
            Expr *n = new_expr(EXPR_NE);
            n->lhs = e;
            n->rhs = parse_rel(p, ls);
            e = n;
            continue;
        }
        return e;
    }
}

static Expr *parse_bitand(Parser *p, Locals *ls) {
    Expr *e = parse_eq(p, ls);
    while (consume(p, TOK_AMP)) {
        Expr *n = new_expr(EXPR_BAND);
        n->lhs = e;
        n->rhs = parse_eq(p, ls);
        n->base = BT_INT;
        n->ptr = 0;
        n->struct_id = -1;
        n->lval_size = 8;
        e = n;
    }
    return e;
}

static Expr *parse_bitxor(Parser *p, Locals *ls) {
    Expr *e = parse_bitand(p, ls);
    while (consume(p, TOK_CARET)) {
        Expr *n = new_expr(EXPR_BXOR);
        n->lhs = e;
        n->rhs = parse_bitand(p, ls);
        n->base = BT_INT;
        n->ptr = 0;
        n->struct_id = -1;
        n->lval_size = 8;
        e = n;
    }
    return e;
}

static Expr *parse_bitor(Parser *p, Locals *ls) {
    Expr *e = parse_bitxor(p, ls);
    while (consume(p, TOK_PIPE)) {
        Expr *n = new_expr(EXPR_BOR);
        n->lhs = e;
        n->rhs = parse_bitxor(p, ls);
        n->base = BT_INT;
        n->ptr = 0;
        n->struct_id = -1;
        n->lval_size = 8;
        e = n;
    }
    return e;
}

static Expr *parse_logand(Parser *p, Locals *ls) {
    Expr *e = parse_bitor(p, ls);
    while (consume(p, TOK_ANDAND)) {
        Expr *n = new_expr(EXPR_LAND);
        n->lhs = e;
        n->rhs = parse_bitor(p, ls);
        n->base = BT_INT;
        n->ptr = 0;
        n->struct_id = -1;
        n->lval_size = 8;
        e = n;
    }
    return e;
}

static Expr *parse_logor(Parser *p, Locals *ls) {
    Expr *e = parse_logand(p, ls);
    while (consume(p, TOK_OROR)) {
        Expr *n = new_expr(EXPR_LOR);
        n->lhs = e;
        n->rhs = parse_logand(p, ls);
        n->base = BT_INT;
        n->ptr = 0;
        n->struct_id = -1;
        n->lval_size = 8;
        e = n;
    }
    return e;
}

static Expr *parse_cond(Parser *p, Locals *ls) {
    Expr *c = parse_logor(p, ls);
    if (consume(p, TOK_QMARK)) {
        Expr *t = parse_assign(p, ls);
        expect(p, TOK_COLON, "':'");
        Expr *f = parse_cond(p, ls);

        // If both branches are struct lvalues of the same type, the conditional yields an lvalue.
        if (t && f && t->base == BT_STRUCT && t->ptr == 0 && f->base == BT_STRUCT && f->ptr == 0 && t->struct_id == f->struct_id &&
            expr_is_lvalue(t) && expr_is_lvalue(f)) {
            Expr *e = new_expr(EXPR_COND_LVAL);
            e->lhs = c;
            e->rhs = t;
            e->third = f;
            e->base = BT_STRUCT;
            e->ptr = 0;
            e->struct_id = t->struct_id;
            e->lval_size = type_sizeof(p->prg, BT_STRUCT, 0, e->struct_id);
            return e;
        }

        Expr *e = new_expr(EXPR_COND);
        e->lhs = c;
        e->rhs = t;
        e->third = f;
        // Minimal typing: keep branch type if identical, else int.
        if (t && f && t->base == f->base && t->ptr == f->ptr && t->struct_id == f->struct_id) {
            e->base = t->base;
            e->ptr = t->ptr;
            e->struct_id = t->struct_id;
        } else {
            e->base = BT_INT;
            e->ptr = 0;
            e->struct_id = -1;
        }
        e->lval_size = 8;
        return e;
    }
    return c;
}

static Expr *parse_assign(Parser *p, Locals *ls) {
    Expr *e = parse_cond(p, ls);
    if (consume(p, TOK_ASSIGN)) {
        if (!expr_is_lvalue(e)) {
            die("%s:%d:%d: left side of assignment must be an lvalue", p->lx.path, p->tok.line, p->tok.col);
        }
        if (e->lval_size == 0) {
            die("%s:%d:%d: cannot assign to array", p->lx.path, p->tok.line, p->tok.col);
        }

        // Struct assignment: lower to a memcpy-style copy (only supports lvalue RHS).
        if (e->base == BT_STRUCT && e->ptr == 0) {
            Expr *rhs = parse_assign(p, ls);
            if (!expr_is_lvalue(rhs) || rhs->lval_size == 0) {
                die("%s:%d:%d: struct assignment requires lvalue rhs", p->lx.path, p->tok.line, p->tok.col);
            }
            if (rhs->base != BT_STRUCT || rhs->ptr != 0 || rhs->struct_id != e->struct_id) {
                die("%s:%d:%d: struct assignment type mismatch", p->lx.path, p->tok.line, p->tok.col);
            }
            Expr *n = new_expr(EXPR_MEMCPY);
            n->lhs = e;
            n->rhs = rhs;
            n->base = BT_VOID;
            n->ptr = 0;
            n->struct_id = -1;
            n->lval_size = e->lval_size; // bytes to copy
            return n;
        }

        if (e->lval_size != 1 && e->lval_size != 2 && e->lval_size != 4 && e->lval_size != 8) {
            die("%s:%d:%d: assignment size %d not supported", p->lx.path, p->tok.line, p->tok.col, e->lval_size);
        }
        Expr *n = new_expr(EXPR_ASSIGN);
        n->lhs = e;
        n->rhs = parse_assign(p, ls);
        n->base = e->base;
        n->ptr = e->ptr;
        n->struct_id = e->struct_id;
        n->is_unsigned = e->is_unsigned;
        n->lval_size = e->lval_size;
        return n;
    }

    TokenKind compound = TOK_EOF;
    if (consume(p, TOK_PLUSEQ)) compound = TOK_PLUSEQ;
    else if (consume(p, TOK_MINUSEQ)) compound = TOK_MINUSEQ;
    else if (consume(p, TOK_MULEQ)) compound = TOK_MULEQ;
    else if (consume(p, TOK_DIVEQ)) compound = TOK_DIVEQ;
    else if (consume(p, TOK_MODEQ)) compound = TOK_MODEQ;
    else if (consume(p, TOK_ANDEQ)) compound = TOK_ANDEQ;
    else if (consume(p, TOK_OREQ)) compound = TOK_OREQ;
    else if (consume(p, TOK_XOREQ)) compound = TOK_XOREQ;
    else if (consume(p, TOK_SHLEQ)) compound = TOK_SHLEQ;
    else if (consume(p, TOK_SHREQ)) compound = TOK_SHREQ;

    if (compound != TOK_EOF) {
        if (!expr_is_lvalue(e)) {
            die("%s:%d:%d: left side of assignment must be an lvalue", p->lx.path, p->tok.line, p->tok.col);
        }
        if (e->lval_size == 0) {
            die("%s:%d:%d: cannot assign to array", p->lx.path, p->tok.line, p->tok.col);
        }
        if (e->lval_size != 1 && e->lval_size != 2 && e->lval_size != 4 && e->lval_size != 8) {
            die("%s:%d:%d: assignment size %d not supported", p->lx.path, p->tok.line, p->tok.col, e->lval_size);
        }

        Expr *rhs = parse_assign(p, ls);
        Expr *calc = NULL;

        if (compound == TOK_PLUSEQ) {
            Expr *n = new_expr(EXPR_ADD);
            n->lhs = e;
            n->rhs = rhs;
            if (n->lhs && n->rhs && n->lhs->ptr > 0 && n->rhs->ptr == 0) {
                n->base = n->lhs->base;
                n->ptr = n->lhs->ptr;
                n->struct_id = n->lhs->struct_id;
                n->ptr_scale = ptr_pointee_size(p->prg, n->lhs->base, n->lhs->ptr, n->lhs->struct_id);
                n->ptr_index_side = 1;
            } else if (n->lhs && n->rhs && n->lhs->ptr == 0 && n->rhs->ptr > 0) {
                n->base = n->rhs->base;
                n->ptr = n->rhs->ptr;
                n->struct_id = n->rhs->struct_id;
                n->ptr_scale = ptr_pointee_size(p->prg, n->rhs->base, n->rhs->ptr, n->rhs->struct_id);
                n->ptr_index_side = 2;
            } else {
                n->base = BT_INT;
                n->ptr = 0;
                n->struct_id = -1;
            }
            n->lval_size = 8;
            calc = n;
        } else if (compound == TOK_MINUSEQ) {
            Expr *n = new_expr(EXPR_SUB);
            n->lhs = e;
            n->rhs = rhs;
            if (n->lhs && n->rhs && n->lhs->ptr > 0 && n->rhs->ptr == 0) {
                n->base = n->lhs->base;
                n->ptr = n->lhs->ptr;
                n->struct_id = n->lhs->struct_id;
                n->ptr_scale = ptr_pointee_size(p->prg, n->lhs->base, n->lhs->ptr, n->lhs->struct_id);
                n->ptr_index_side = 1;
            } else {
                n->base = BT_INT;
                n->ptr = 0;
                n->struct_id = -1;
            }
            n->lval_size = 8;
            calc = n;
        } else if (compound == TOK_MULEQ) {
            Expr *n = new_expr(EXPR_MUL);
            n->lhs = e;
            n->rhs = rhs;
            calc = n;
        } else if (compound == TOK_DIVEQ) {
            Expr *n = new_expr(EXPR_DIV);
            n->lhs = e;
            n->rhs = rhs;
            calc = n;
        } else if (compound == TOK_MODEQ) {
            Expr *n = new_expr(EXPR_MOD);
            n->lhs = e;
            n->rhs = rhs;
            calc = n;
        } else if (compound == TOK_ANDEQ) {
            Expr *n = new_expr(EXPR_BAND);
            n->lhs = e;
            n->rhs = rhs;
            n->base = BT_INT;
            n->ptr = 0;
            n->struct_id = -1;
            n->lval_size = 8;
            calc = n;
        } else if (compound == TOK_OREQ) {
            Expr *n = new_expr(EXPR_BOR);
            n->lhs = e;
            n->rhs = rhs;
            n->base = BT_INT;
            n->ptr = 0;
            n->struct_id = -1;
            n->lval_size = 8;
            calc = n;
        } else if (compound == TOK_XOREQ) {
            Expr *n = new_expr(EXPR_BXOR);
            n->lhs = e;
            n->rhs = rhs;
            n->base = BT_INT;
            n->ptr = 0;
            n->struct_id = -1;
            n->lval_size = 8;
            calc = n;
        } else if (compound == TOK_SHLEQ) {
            Expr *n = new_expr(EXPR_SHL);
            n->lhs = e;
            n->rhs = rhs;
            n->base = BT_INT;
            n->ptr = 0;
            n->struct_id = -1;
            n->lval_size = 8;
            calc = n;
        } else if (compound == TOK_SHREQ) {
            Expr *n = new_expr(EXPR_SHR);
            n->lhs = e;
            n->rhs = rhs;
            n->base = BT_INT;
            n->ptr = 0;
            n->struct_id = -1;
            n->lval_size = 8;
            calc = n;
        }

        Expr *a = new_expr(EXPR_ASSIGN);
        a->lhs = e;
        a->rhs = calc;
        a->base = e->base;
        a->ptr = e->ptr;
        a->struct_id = e->struct_id;
        a->is_unsigned = e->is_unsigned;
        a->lval_size = e->lval_size;
        return a;
    }
    return e;
}

static Expr *parse_expr(Parser *p, Locals *ls) {
    return parse_assign(p, ls);
}

static Stmt *parse_block(Parser *p, Locals *ls) {
    expect(p, TOK_LBRACE, "'{'" );
    Stmt *blk = new_stmt(STMT_BLOCK);
    Stmt *tail = NULL;
    while (!tok_is(p, TOK_RBRACE)) {
        if (tok_is(p, TOK_EOF)) {
            die("%s:%d:%d: unexpected end of file in block", p->lx.path, p->tok.line, p->tok.col);
        }
        Stmt *s = parse_stmt(p, ls);
        if (!blk->block_first) blk->block_first = s;
        if (tail) tail->next = s;
        tail = s;
        while (tail && tail->next) tail = tail->next;
    }
    expect(p, TOK_RBRACE, "'}'");
    return blk;
}

static Stmt *parse_decl(Parser *p, Locals *ls) {
    // Local decl subset: type-spec <ident> [= expr] ;
    int saw_static = 0;
    for (;;) {
        if (consume(p, TOK_KW_EXTERN)) {
            continue;
        }
        if (consume(p, TOK_KW_STATIC)) {
            saw_static = 1;
            continue;
        }
        if (tok_is_ident(p, "inline") || tok_is_ident(p, "__inline") || tok_is_ident(p, "__inline__")) {
            parser_next(p);
            continue;
        }
        break;
    }

    BaseType base = BT_INT;
    int base_ptr = 0;
    int sid = -1;
    int is_unsigned = 0;
    parse_type_spec(p, &base, &base_ptr, &sid, &is_unsigned, 0);
    skip_gcc_attrs(p);

    Stmt *head = NULL;
    Stmt *tail = NULL;

    for (;;) {
        int ptr = base_ptr;
        const char *nm = NULL;
        size_t nm_len = 0;
        parse_declarator_name(p, &nm, &nm_len, &ptr);
        skip_gcc_attrs(p);

        if (base == BT_VOID && ptr == 0) {
            die("%s:%d:%d: cannot declare object of type void", p->lx.path, p->tok.line, p->tok.col);
        }

        // Support fixed-size local arrays: T name[N];
        // We represent them as (pointer-to-element) for expression typing, but keep alloc_size for sizeof(name).
        int lval_size = type_sizeof(p->prg, base, ptr, sid);
        int alloc_size = lval_size;
        int array_stride = 0;
        int unsized_array = 0;
        int is_array = 0;
        int array_elems = 0;
        if (consume(p, TOK_LBRACK)) {
            is_array = 1;
            if (consume(p, TOK_RBRACK)) {
                // Unsized 1D array: T name[] = initializer;
                // We'll deduce size from the initializer (string or { ... }).
                unsized_array = 1;
                alloc_size = 0;
                // array expression decays to pointer
                ptr++;
                lval_size = 0;
            } else {
            Expr *len_e = parse_expr(p, ls);
            long long n = eval_const_expr(p, len_e);
            expect(p, TOK_RBRACK, "']'");
            if (n <= 0 || n > 0x7fffffffLL) {
                die("%s:%d:%d: invalid local array length", p->lx.path, p->tok.line, p->tok.col);
            }
            array_elems = (int)n;

            if (consume(p, TOK_LBRACK)) {
                // 2D local array: T name[N][M]
                if (consume(p, TOK_RBRACK)) {
                    die("%s:%d:%d: unsized local arrays not supported", p->lx.path, p->tok.line, p->tok.col);
                }
                Expr *len2_e = parse_expr(p, ls);
                long long n2 = eval_const_expr(p, len2_e);
                expect(p, TOK_RBRACK, "']'");
                if (n2 <= 0 || n2 > 0x7fffffffLL) {
                    die("%s:%d:%d: invalid local array length", p->lx.path, p->tok.line, p->tok.col);
                }
                long long total = n * n2;
                if (total <= 0 || total > 0x7fffffffLL) {
                    die("%s:%d:%d: invalid local array size", p->lx.path, p->tok.line, p->tok.col);
                }
                alloc_size = (int)total * lval_size;
                array_stride = (int)n2 * lval_size;
                // array-of-array expression decays to pointer-to-array; model as ptr+2 with stride.
                ptr += 2;
                lval_size = 0;
            } else {
                alloc_size = (int)n * lval_size;
                // array expression decays to pointer
                ptr++;
                lval_size = 0;
            }
            }
        }

        if (saw_static && array_stride == 0) {
            // Static local storage (subset):
            // - Supports implicit zero-init.
            // - Supports scalar init: static int x = expr;
            // - Supports 1D array init: static T a[N] = {..}; and static char s[] = "...";
            // Initialization runs once via a hidden guard variable.
            if (!p->prg) die("internal: no program context");

            int has_init = tok_is(p, TOK_ASSIGN);

            // Parse initializer for arrays early so we can deduce size for unsized arrays.
            // For scalars/structs we use the existing parse_expr path.
            InitEnt *static_array_inits = NULL;
            int static_array_ninits = 0;
            int static_array_init_is_string = 0;
            int static_array_string_id = -1;

            if (has_init && is_array && lval_size == 0 && base != BT_STRUCT) {
                (void)consume(p, TOK_ASSIGN);

                int elem_ptr = ptr - 1;
                int elem_size = type_sizeof(p->prg, base, elem_ptr, sid);
                if (elem_size != 1 && elem_size != 2 && elem_size != 4 && elem_size != 8) {
                    die("%s:%d:%d: array element size %d not supported", p->lx.path, p->tok.line, p->tok.col, elem_size);
                }

                if (p->tok.kind == TOK_STR) {
                    Expr *se = parse_expr(p, ls);
                    static_array_init_is_string = 1;
                    static_array_string_id = se->str_id;
                    const StringLit *sl = &p->prg->strs[se->str_id];
                    if (elem_size != 1 || base != BT_CHAR || elem_ptr != 0) {
                        die("%s:%d:%d: string initializer only supported for char arrays", p->lx.path, p->tok.line, p->tok.col);
                    }
                    int need = (int)sl->len;
                    if (!unsized_array) {
                        if (alloc_size < need) {
                            die("%s:%d:%d: string initializer too long", p->lx.path, p->tok.line, p->tok.col);
                        }
                    } else {
                        alloc_size = need;
                        if (alloc_size < 1) alloc_size = 1;
                        array_elems = alloc_size;
                        unsized_array = 0;
                    }
                } else if (consume(p, TOK_LBRACE)) {
                    int cap = 0;
                    while (!tok_is(p, TOK_RBRACE)) {
                        if (tok_is(p, TOK_EOF)) {
                            die("%s:%d:%d: unexpected EOF in array initializer", p->lx.path, p->tok.line, p->tok.col);
                        }
                        if (static_array_ninits + 1 > cap) {
                            int ncap = cap ? cap * 2 : 8;
                            InitEnt *ni = (InitEnt *)monacc_realloc(static_array_inits, (size_t)ncap * sizeof(*static_array_inits));
                            if (!ni) die("oom");
                            static_array_inits = ni;
                            cap = ncap;
                        }
                        Expr *val = parse_expr(p, ls);
                        static_array_inits[static_array_ninits].off = static_array_ninits * elem_size;
                        static_array_inits[static_array_ninits].store_size = elem_size;
                        static_array_inits[static_array_ninits].value = val;
                        static_array_ninits++;
                        skip_gcc_attrs(p);
                        if (consume(p, TOK_COMMA)) {
                            skip_gcc_attrs(p);
                            if (tok_is(p, TOK_RBRACE)) break;
                            continue;
                        }
                        break;
                    }
                    expect(p, TOK_RBRACE, "'}'");

                    if (unsized_array) {
                        if (static_array_ninits <= 0) {
                            die("%s:%d:%d: empty unsized array initializer", p->lx.path, p->tok.line, p->tok.col);
                        }
                        alloc_size = static_array_ninits * elem_size;
                        array_elems = static_array_ninits;
                        unsized_array = 0;
                    } else {
                        if (alloc_size < static_array_ninits * elem_size) {
                            die("%s:%d:%d: too many array initializer elements", p->lx.path, p->tok.line, p->tok.col);
                        }
                    }
                } else {
                    die("%s:%d:%d: initializer for this type not supported", p->lx.path, p->tok.line, p->tok.col);
                }
            }

            if (unsized_array) {
                die("%s:%d:%d: static local unsized arrays require an initializer", p->lx.path, p->tok.line, p->tok.col);
            }
            if (array_stride != 0) {
                die("%s:%d:%d: static local 2D arrays are not supported", p->lx.path, p->tok.line, p->tok.col);
            }

            char gname[128];
            char guard_name[128];
            mc_u64 seq = (mc_u64)ls->nlocals;
            if (p->cur_fn_name[0]) {
                mc_snprint_cstr_cstr_u64_cstr(gname, sizeof(gname), "__monacc_static_", p->cur_fn_name, seq, "");
                mc_snprint_cstr_cstr_u64_cstr(guard_name, sizeof(guard_name), "__monacc_static_guard_", p->cur_fn_name, seq, "");
            } else {
                mc_snprint_cstr_u64_cstr(gname, sizeof(gname), "__monacc_static_", seq, "");
                mc_snprint_cstr_u64_cstr(guard_name, sizeof(guard_name), "__monacc_static_guard_", seq, "");
            }

            GlobalVar gv = {0};
            if (mc_strlen(gname) >= sizeof(gv.name)) die("internal: static local global name too long");
            mc_memcpy(gv.name, gname, mc_strlen(gname));
            gv.name[mc_strlen(gname)] = 0;
            gv.base = base;
            gv.struct_id = sid;
            gv.is_unsigned = is_unsigned;
            gv.is_static = 1;
            gv.is_extern = 0;

            if (is_array) {
                int elem_ptr = ptr - 1;
                if (elem_ptr < 0) die("internal: bad static array ptr");
                gv.ptr = elem_ptr;
                if (array_elems <= 0) {
                    int esz = type_sizeof(p->prg, base, elem_ptr, sid);
                    if (esz <= 0) die("internal: bad elem size");
                    array_elems = alloc_size / esz;
                }
                gv.array_len = array_elems;
                gv.elem_size = type_sizeof(p->prg, base, elem_ptr, sid);
                gv.size = alloc_size;
            } else {
                gv.ptr = ptr;
                gv.array_len = 0;
                gv.elem_size = type_sizeof(p->prg, base, ptr, sid);
                gv.size = gv.elem_size;
            }

            int gid_existing = program_find_global(p->prg, gv.name, mc_strlen(gv.name));
            if (gid_existing < 0) {
                program_add_global(p->prg, &gv);
                gid_existing = program_find_global(p->prg, gv.name, mc_strlen(gv.name));
            }
            if (gid_existing < 0) die("internal: failed to add static local global");

            // Hidden guard global (0 => not initialized, 1 => initialized)
            GlobalVar gguard = {0};
            if (mc_strlen(guard_name) >= sizeof(gguard.name)) die("internal: static local guard name too long");
            mc_memcpy(gguard.name, guard_name, mc_strlen(guard_name));
            gguard.name[mc_strlen(guard_name)] = 0;
            gguard.base = BT_LONG;
            gguard.ptr = 0;
            gguard.struct_id = -1;
            gguard.is_unsigned = 0;
            gguard.is_static = 1;
            gguard.is_extern = 0;
            gguard.array_len = 0;
            gguard.elem_size = 8;
            gguard.size = 8;
            int gid_guard = program_find_global(p->prg, gguard.name, mc_strlen(gguard.name));
            if (gid_guard < 0) {
                program_add_global(p->prg, &gguard);
                gid_guard = program_find_global(p->prg, gguard.name, mc_strlen(gguard.name));
            }
            if (gid_guard < 0) die("internal: failed to add static local guard global");

            (void)local_add_globalref(ls, nm, nm_len, gid_existing, base, (is_array ? (ptr - 1) : ptr), sid, is_unsigned, lval_size, alloc_size, array_stride);

            if (has_init) {
                // Condition: if (!guard)
                Expr *guard_val = new_expr(EXPR_GLOBAL);
                guard_val->global_id = gid_guard;
                guard_val->base = BT_LONG;
                guard_val->ptr = 0;
                guard_val->struct_id = -1;
                guard_val->is_unsigned = 0;
                guard_val->lval_size = 8;

                Expr *cond = new_expr(EXPR_NOT);
                cond->lhs = guard_val;
                cond->base = BT_INT;
                cond->ptr = 0;
                cond->struct_id = -1;
                cond->is_unsigned = 0;
                cond->lval_size = 8;

                Stmt *then_block = new_stmt(STMT_BLOCK);
                Stmt *then_head = NULL;
                Stmt *then_tail = NULL;

                // Emit initialization statements.
                if (is_array && (static_array_init_is_string || static_array_inits)) {
                    if (static_array_init_is_string) {
                        Expr *dst = new_expr(EXPR_GLOBAL);
                        dst->global_id = gid_existing;
                        dst->base = base;
                        dst->ptr = (ptr - 1) + 1; // array decays
                        dst->struct_id = sid;
                        dst->is_unsigned = is_unsigned;
                        dst->lval_size = 0;
                        dst->var_alloc_size = alloc_size;

                        Expr *src_str = new_expr(EXPR_STR);
                        src_str->str_id = static_array_string_id;
                        src_str->base = BT_CHAR;
                        src_str->ptr = 1;
                        src_str->struct_id = -1;
                        src_str->is_unsigned = 0;
                        src_str->lval_size = 8;

                        Expr *src = new_expr(EXPR_DEREF);
                        src->lhs = src_str;
                        src->base = BT_CHAR;
                        src->ptr = 0;
                        src->struct_id = -1;
                        src->is_unsigned = 0;
                        src->lval_size = 1;

                        const StringLit *sl = &p->prg->strs[static_array_string_id];
                        Expr *mc = new_expr(EXPR_MEMCPY);
                        mc->lhs = dst;
                        mc->rhs = src;
                        mc->base = BT_VOID;
                        mc->ptr = 0;
                        mc->struct_id = -1;
                        mc->is_unsigned = 0;
                        mc->lval_size = (int)sl->len;

                        Stmt *st = new_stmt(STMT_EXPR);
                        st->expr = mc;
                        then_head = then_tail = st;
                    } else {
                        int elem_size = static_array_inits[0].store_size;
                        for (int ii = 0; ii < static_array_ninits; ii++) {
                            const InitEnt *in = &static_array_inits[ii];
                            if (elem_size <= 0) elem_size = in->store_size;
                            long long idx = (long long)in->off / (long long)elem_size;

                            Expr *arr = new_expr(EXPR_GLOBAL);
                            arr->global_id = gid_existing;
                            arr->base = base;
                            arr->ptr = (ptr - 1) + 1; // array decays
                            arr->struct_id = sid;
                            arr->is_unsigned = is_unsigned;
                            arr->lval_size = 0;
                            arr->var_alloc_size = alloc_size;

                            Expr *idx_e = new_expr(EXPR_NUM);
                            idx_e->num = idx;
                            idx_e->base = BT_LONG;
                            idx_e->ptr = 0;
                            idx_e->struct_id = -1;
                            idx_e->is_unsigned = 0;
                            idx_e->lval_size = 8;

                            Expr *el = new_expr(EXPR_INDEX);
                            el->lhs = arr;
                            el->rhs = idx_e;
                            el->base = base;
                            el->ptr = (ptr - 1);
                            el->struct_id = sid;
                            el->is_unsigned = is_unsigned;
                            el->ptr_scale = elem_size;
                            el->lval_size = elem_size;

                            Expr *as = new_expr(EXPR_ASSIGN);
                            as->lhs = el;
                            as->rhs = in->value;
                            as->base = base;
                            as->ptr = (ptr - 1);
                            as->struct_id = sid;
                            as->is_unsigned = is_unsigned;
                            as->lval_size = elem_size;

                            Stmt *st = new_stmt(STMT_EXPR);
                            st->expr = as;
                            if (!then_head) then_head = st;
                            if (then_tail) then_tail->next = st;
                            then_tail = st;
                        }
                    }
                } else {
                    // Scalar initializer: static int x = expr;
                    if (!consume(p, TOK_ASSIGN)) {
                        die("internal: expected '=' for static initializer");
                    }
                    Expr *rhs = parse_expr(p, ls);
                    Expr *lhs = new_expr(EXPR_GLOBAL);
                    lhs->global_id = gid_existing;
                    lhs->base = base;
                    lhs->ptr = ptr;
                    lhs->struct_id = sid;
                    lhs->is_unsigned = is_unsigned;
                    lhs->lval_size = (lval_size == 1 || lval_size == 2 || lval_size == 4 || lval_size == 8) ? lval_size : 8;

                    Expr *as = new_expr(EXPR_ASSIGN);
                    as->lhs = lhs;
                    as->rhs = rhs;
                    as->base = base;
                    as->ptr = ptr;
                    as->struct_id = sid;
                    as->is_unsigned = is_unsigned;
                    as->lval_size = lhs->lval_size;

                    Stmt *st = new_stmt(STMT_EXPR);
                    st->expr = as;
                    then_head = then_tail = st;
                }

                // guard = 1
                Expr *guard_lhs = new_expr(EXPR_GLOBAL);
                guard_lhs->global_id = gid_guard;
                guard_lhs->base = BT_LONG;
                guard_lhs->ptr = 0;
                guard_lhs->struct_id = -1;
                guard_lhs->is_unsigned = 0;
                guard_lhs->lval_size = 8;

                Expr *one = new_expr(EXPR_NUM);
                one->num = 1;
                one->base = BT_LONG;
                one->ptr = 0;
                one->struct_id = -1;
                one->is_unsigned = 0;
                one->lval_size = 8;

                Expr *gset = new_expr(EXPR_ASSIGN);
                gset->lhs = guard_lhs;
                gset->rhs = one;
                gset->base = BT_LONG;
                gset->ptr = 0;
                gset->struct_id = -1;
                gset->is_unsigned = 0;
                gset->lval_size = 8;

                Stmt *stg = new_stmt(STMT_EXPR);
                stg->expr = gset;
                if (!then_head) then_head = stg;
                if (then_tail) then_tail->next = stg;
                then_tail = stg;

                then_block->block_first = then_head;

                Stmt *ifs = new_stmt(STMT_IF);
                ifs->if_cond = cond;
                ifs->if_then = then_block;
                ifs->if_else = NULL;

                if (!head) head = ifs;
                if (tail) tail->next = ifs;
                tail = ifs;
                while (tail && tail->next) tail = tail->next;
            }

            // Declaration is a no-op (storage already exists in the hidden global).
            Stmt *s = new_stmt(STMT_DECL);
            s->decl_offset = 0;
            s->decl_store_size = 0;
            if (!head) head = s;
            if (tail) tail->next = s;
            tail = s;
            while (tail && tail->next) tail = tail->next;

            skip_gcc_attrs(p);
            if (consume(p, TOK_COMMA)) {
                skip_gcc_attrs(p);
                continue;
            }
            break;
        }

        // Parse optional initializer early for unsized arrays so we can deduce alloc_size.
        InitEnt *array_inits = NULL;
        int array_ninits = 0;
        int array_init_zero = 0;

        if (tok_is(p, TOK_ASSIGN)) {
            if (is_array && lval_size == 0 && base != BT_STRUCT) {
                // Array initializer (subset): string literal or { expr, expr, ... }
                // Deduce size for unsized arrays.
                (void)consume(p, TOK_ASSIGN);

                int elem_ptr = ptr - 1;
                int elem_size = type_sizeof(p->prg, base, elem_ptr, sid);
                if (elem_size != 1 && elem_size != 2 && elem_size != 4 && elem_size != 8) {
                    die("%s:%d:%d: array element size %d not supported", p->lx.path, p->tok.line, p->tok.col, elem_size);
                }

                if (p->tok.kind == TOK_STR) {
                    Expr *se = parse_expr(p, ls);
                    const StringLit *sl = &p->prg->strs[se->str_id];
                    if (elem_size != 1 || base != BT_CHAR || elem_ptr != 0) {
                        die("%s:%d:%d: string initializer only supported for char arrays", p->lx.path, p->tok.line, p->tok.col);
                    }
                    int need = (int)sl->len;
                    if (!unsized_array) {
                        if (alloc_size < need) {
                            die("%s:%d:%d: string initializer too long", p->lx.path, p->tok.line, p->tok.col);
                        }
                    } else {
                        alloc_size = need;
                        if (alloc_size < 1) alloc_size = 1;
                    }

                    array_init_zero = 1;
                    array_ninits = (int)sl->len;
                    array_inits = (InitEnt *)monacc_calloc((size_t)array_ninits, sizeof(*array_inits));
                    if (!array_inits) die("oom");
                    for (int i = 0; i < array_ninits; i++) {
                        Expr *bv = new_expr(EXPR_NUM);
                        bv->num = (long long)sl->data[i];
                        bv->base = BT_INT;
                        bv->ptr = 0;
                        bv->struct_id = -1;
                        bv->is_unsigned = 0;
                        bv->lval_size = 8;
                        array_inits[i].off = i;
                        array_inits[i].store_size = 1;
                        array_inits[i].value = bv;
                    }
                } else if (consume(p, TOK_LBRACE)) {
                    array_init_zero = 1;
                    int cap = 0;
                    while (!tok_is(p, TOK_RBRACE)) {
                        if (tok_is(p, TOK_EOF)) {
                            die("%s:%d:%d: unexpected EOF in array initializer", p->lx.path, p->tok.line, p->tok.col);
                        }
                        if (array_ninits + 1 > cap) {
                            int ncap = cap ? cap * 2 : 8;
                            InitEnt *ni = (InitEnt *)monacc_realloc(array_inits, (size_t)ncap * sizeof(*array_inits));
                            if (!ni) die("oom");
                            array_inits = ni;
                            cap = ncap;
                        }
                        Expr *val = parse_expr(p, ls);
                        array_inits[array_ninits].off = array_ninits * elem_size;
                        array_inits[array_ninits].store_size = elem_size;
                        array_inits[array_ninits].value = val;
                        array_ninits++;
                        skip_gcc_attrs(p);
                        if (consume(p, TOK_COMMA)) {
                            skip_gcc_attrs(p);
                            if (tok_is(p, TOK_RBRACE)) break;
                            continue;
                        }
                        break;
                    }
                    expect(p, TOK_RBRACE, "'}'");

                    if (unsized_array) {
                        if (array_ninits <= 0) {
                            die("%s:%d:%d: empty unsized array initializer", p->lx.path, p->tok.line, p->tok.col);
                        }
                        alloc_size = array_ninits * elem_size;
                    } else {
                        if (alloc_size < array_ninits * elem_size) {
                            die("%s:%d:%d: too many array initializer elements", p->lx.path, p->tok.line, p->tok.col);
                        }
                    }
                } else {
                    die("%s:%d:%d: initializer for this type not supported", p->lx.path, p->tok.line, p->tok.col);
                }

                // Convert collected inits into a compound initializer expression once we know final offset.
                // We'll build this after allocating the local.
            } else {
                // Not an array initializer we handle here; leave for the existing logic below.
            }
        }

        int off = local_add(ls, nm, nm_len, base, ptr, sid, is_unsigned, lval_size, alloc_size, array_stride);

        Stmt *s = new_stmt(STMT_DECL);
        s->decl_offset = off;
        s->decl_store_size = (lval_size == 1 || lval_size == 2 || lval_size == 4 || lval_size == 8) ? lval_size : 0;
        if (array_inits) {
            // Emit array initialization as a side-effecting compound initializer expression.
            Expr *e = new_expr(EXPR_COMPOUND);
            e->var_offset = off;
            e->base = base;
            e->ptr = ptr;
            e->struct_id = sid;
            e->lval_size = alloc_size;
            e->init_zero = array_init_zero;
            e->inits = array_inits;
            e->ninits = array_ninits;

            Stmt *as = new_stmt(STMT_EXPR);
            as->expr = e;
            s->next = as;
        } else if (consume(p, TOK_ASSIGN)) {
            if (s->decl_store_size != 0) {
                s->decl_init = parse_expr(p, ls);
            } else if (base == BT_STRUCT && ptr == 0) {
                Expr *init = NULL;
                if (tok_is(p, TOK_LBRACE)) {
                    init = parse_struct_init_compound(p, ls, sid);
                } else {
                    init = parse_expr(p, ls);
                }
                if (!expr_is_lvalue(init) || init->lval_size == 0) {
                    die("%s:%d:%d: struct initializer requires lvalue", p->lx.path, p->tok.line, p->tok.col);
                }
                if (init->base != BT_STRUCT || init->ptr != 0 || init->struct_id != sid) {
                    die("%s:%d:%d: struct initializer type mismatch", p->lx.path, p->tok.line, p->tok.col);
                }

                Expr *dst = new_expr(EXPR_VAR);
                dst->var_offset = off;
                dst->base = base;
                dst->ptr = 0;
                dst->struct_id = sid;
                dst->lval_size = type_sizeof(p->prg, base, 0, sid);

                Expr *cpy = new_expr(EXPR_MEMCPY);
                cpy->lhs = dst;
                cpy->rhs = init;
                cpy->base = BT_VOID;
                cpy->ptr = 0;
                cpy->struct_id = -1;
                cpy->lval_size = dst->lval_size;

                Stmt *as = new_stmt(STMT_EXPR);
                as->expr = cpy;
                s->next = as;
            } else {
                die("%s:%d:%d: initializer for this type not supported", p->lx.path, p->tok.line, p->tok.col);
            }
        }

        if (!head) head = s;
        if (tail) tail->next = s;
        tail = s;
        while (tail && tail->next) tail = tail->next;

        skip_gcc_attrs(p);
        if (consume(p, TOK_COMMA)) {
            skip_gcc_attrs(p);
            continue;
        }
        break;
    }

    expect(p, TOK_SEMI, "';'");
    return head;
}

static void parse_struct_init_list(Parser *p, Locals *ls, int sid, Expr *out) {
    expect(p, TOK_LBRACE, "'{'");

    out->init_zero = 1;
    out->inits = NULL;
    out->ninits = 0;

    // Support simple {0} as a common zero-init pattern.
    if (p->tok.kind == TOK_NUM && p->tok.num == 0) {
        parser_next(p);
        skip_gcc_attrs(p);
        if (consume(p, TOK_RBRACE)) {
            return;
        }
        // If it wasn't a lone 0, treat as unsupported initializer form.
        die("%s:%d:%d: only {0} or designated initializers are supported", p->lx.path, p->tok.line, p->tok.col);
    }

    while (!tok_is(p, TOK_RBRACE)) {
        skip_gcc_attrs(p);
        if (!consume(p, TOK_DOT)) {
            die("%s:%d:%d: only designated struct initializers are supported", p->lx.path, p->tok.line, p->tok.col);
        }
        const char *mn = NULL;
        size_t mn_len = 0;
        expect_ident(p, &mn, &mn_len);
        skip_gcc_attrs(p);
        expect(p, TOK_ASSIGN, "'='");
        Expr *val = parse_expr(p, ls);

        const StructMember *m = struct_find_member(p->prg, sid, mn, mn_len);
        if (!m) {
            die("%s:%d:%d: unknown struct member '%.*s'", p->lx.path, p->tok.line, p->tok.col, (int)mn_len, mn);
        }
        if (m->array_len) {
            die("%s:%d:%d: array member initializers not supported", p->lx.path, p->tok.line, p->tok.col);
        }
        int sz = type_sizeof(p->prg, m->base, m->ptr, m->struct_id);
        int store_sz = (sz == 1) ? 1 : (sz == 2) ? 2 : (sz == 4) ? 4 : 8;
        if (store_sz != 1 && store_sz != 2 && store_sz != 4 && store_sz != 8) {
            die("%s:%d:%d: member init size %d not supported", p->lx.path, p->tok.line, p->tok.col, store_sz);
        }

        InitEnt *ni = (InitEnt *)monacc_realloc(out->inits, (size_t)(out->ninits + 1) * sizeof(*out->inits));
        if (!ni) die("oom");
        out->inits = ni;
        out->inits[out->ninits].off = m->offset;
        out->inits[out->ninits].store_size = store_sz;
        out->inits[out->ninits].value = val;
        out->ninits++;

        skip_gcc_attrs(p);
        if (consume(p, TOK_COMMA)) {
            skip_gcc_attrs(p);
            continue;
        }
        break;
    }
    expect(p, TOK_RBRACE, "'}'");
}

static Expr *parse_struct_init_compound(Parser *p, Locals *ls, int sid) {
    if (!ls) die("%s:%d:%d: compound literal not supported at top-level", p->lx.path, p->tok.line, p->tok.col);

    int sz = type_sizeof(p->prg, BT_STRUCT, 0, sid);

    char tmpnm[64];
    mc_snprint_cstr_u64_cstr(tmpnm, sizeof(tmpnm), "__monacc_cl", (mc_u64)ls->nlocals, "");
    int off = local_add(ls, tmpnm, mc_strlen(tmpnm), BT_STRUCT, 0, sid, 0, sz, sz, 0);

    Expr *e = new_expr(EXPR_COMPOUND);
    e->var_offset = off;
    e->base = BT_STRUCT;
    e->ptr = 0;
    e->struct_id = sid;
    e->lval_size = sz;

    parse_struct_init_list(p, ls, sid, e);
    return e;
}

// ===== Inline Assembly Parsing =====
// Parses GNU-style inline asm:
//   __asm__ [volatile] ( "template" [: outputs [: inputs [: clobbers]]] );
//
// Operand format: [constraint] (expr)  or  "constraint" (expr)
// Constraint examples: "=a", "r", "m", "Nd", "+r"

static char *parse_asm_string(Parser *p) {
    // Parse one or more adjacent string literals and concatenate them.
    if (p->tok.kind != TOK_STR) {
        die("%s:%d:%d: expected string literal in asm", p->lx.path, p->tok.line, p->tok.col);
    }
    Str buf = {0};
    while (p->tok.kind == TOK_STR) {
        str_append_bytes(&buf, p->tok.start + 1, p->tok.len - 2); // skip quotes
        parser_next(p);
    }
    char *result = (char *)monacc_malloc(buf.len + 1);
    if (buf.buf) mc_memcpy(result, buf.buf, buf.len);
    result[buf.len] = 0;
    monacc_free(buf.buf);
    return result;
}

static void parse_asm_operands(Parser *p, Locals *ls, AsmOperand **out_ops, int *out_n) {
    // Parse a list of asm operands: "constraint" (expr) [, "constraint" (expr) ...]
    *out_ops = NULL;
    *out_n = 0;
    if (!tok_is(p, TOK_STR)) return; // empty list

    AsmOperand *ops = NULL;
    int n = 0;
    int cap = 0;
    for (;;) {
        if (!tok_is(p, TOK_STR)) break;
        // Parse constraint string
        const char *cstr = p->tok.start + 1;
        size_t clen = p->tok.len - 2;
        if (clen >= sizeof(((AsmOperand *)0)->constraint)) {
            die("%s:%d:%d: asm constraint too long", p->lx.path, p->tok.line, p->tok.col);
        }
        parser_next(p);

        // Parse (expr)
        expect(p, TOK_LPAREN, "'('");
        Expr *e = parse_expr(p, ls);
        expect(p, TOK_RPAREN, "')'");

        // Grow array
        if (n >= cap) {
            cap = cap ? cap * 2 : 4;
            ops = (AsmOperand *)monacc_realloc(ops, (size_t)cap * sizeof(AsmOperand));
        }
        mc_memset(&ops[n], 0, sizeof(AsmOperand));
        mc_memcpy(ops[n].constraint, cstr, clen);
        ops[n].constraint[clen] = 0;
        ops[n].is_output = (cstr[0] == '=' || cstr[0] == '+');
        ops[n].is_inout = (cstr[0] == '+');
        ops[n].expr = e;
        n++;

        if (!consume(p, TOK_COMMA)) break;
    }
    *out_ops = ops;
    *out_n = n;
}

static void parse_asm_clobbers(Parser *p, char ***out_clobs, int *out_n) {
    // Parse a list of clobber strings: "reg" [, "reg" ...]
    *out_clobs = NULL;
    *out_n = 0;
    if (!tok_is(p, TOK_STR)) return;

    char **clobs = NULL;
    int n = 0;
    int cap = 0;
    for (;;) {
        if (!tok_is(p, TOK_STR)) break;
        const char *cstr = p->tok.start + 1;
        size_t clen = p->tok.len - 2;
        parser_next(p);

        // Grow array
        if (n >= cap) {
            cap = cap ? cap * 2 : 4;
            clobs = (char **)monacc_realloc(clobs, (size_t)cap * sizeof(char *));
        }
        clobs[n] = (char *)monacc_malloc(clen + 1);
        mc_memcpy(clobs[n], cstr, clen);
        clobs[n][clen] = 0;
        n++;

        if (!consume(p, TOK_COMMA)) break;
    }
    *out_clobs = clobs;
    *out_n = n;
}

static Stmt *parse_asm_stmt(Parser *p, Locals *ls) {
    // Already consumed __asm__ or __asm
    Stmt *s = new_stmt(STMT_ASM);

    // Optional: volatile / __volatile__
    s->asm_is_volatile = 0;
    if (tok_is_ident(p, "volatile") || tok_is_ident(p, "__volatile__")) {
        s->asm_is_volatile = 1;
        parser_next(p);
    }

    // Optional: goto (we skip but don't specially handle)
    if (tok_is_ident(p, "goto")) {
        parser_next(p);
    }

    expect(p, TOK_LPAREN, "'('");

    // Parse template string
    s->asm_template = parse_asm_string(p);

    // Parse optional sections: outputs, inputs, clobbers
    s->asm_outputs = NULL;
    s->asm_noutputs = 0;
    s->asm_inputs = NULL;
    s->asm_ninputs = 0;
    s->asm_clobbers = NULL;
    s->asm_nclobbers = 0;

    if (consume(p, TOK_COLON)) {
        // Outputs
        parse_asm_operands(p, ls, &s->asm_outputs, &s->asm_noutputs);
        if (consume(p, TOK_COLON)) {
            // Inputs
            parse_asm_operands(p, ls, &s->asm_inputs, &s->asm_ninputs);
            if (consume(p, TOK_COLON)) {
                // Clobbers
                parse_asm_clobbers(p, &s->asm_clobbers, &s->asm_nclobbers);
            }
        }
    }

    expect(p, TOK_RPAREN, "')'");
    expect(p, TOK_SEMI, "';'");
    return s;
}

static Stmt *parse_stmt(Parser *p, Locals *ls) {
    if (consume(p, TOK_SEMI)) {
        // Empty statement.
        return new_stmt(STMT_EXPR);
    }
    if (p->tok.kind == TOK_IDENT) {
        Token t = p->tok;
        Token next = parser_peek(p);
        if (next.kind == TOK_COLON) {
            // label: <stmt>
            Stmt *s = new_stmt(STMT_LABEL);
            if (t.len == 0 || t.len >= sizeof(s->label)) {
                die("%s:%d:%d: label name too long", p->lx.path, t.line, t.col);
            }
            mc_memcpy(s->label, t.start, t.len);
            s->label[t.len] = 0;
            parser_next(p);
            expect(p, TOK_COLON, "':'");
            s->label_stmt = parse_stmt(p, ls);
            return s;
        }
    }
    if (consume(p, TOK_KW_CASE)) {
        // case <const-expr> :
        Stmt *s = new_stmt(STMT_CASE);
        Expr *ce = parse_expr(p, ls);
        s->case_value = eval_const_expr(p, ce);
        expect(p, TOK_COLON, "':'");
        return s;
    }
    if (consume(p, TOK_KW_DEFAULT)) {
        // default :
        Stmt *s = new_stmt(STMT_DEFAULT);
        expect(p, TOK_COLON, "':'");
        return s;
    }
    if (tok_is(p, TOK_LBRACE)) {
        return parse_block(p, ls);
    }
    if (consume(p, TOK_KW_BREAK)) {
        Stmt *s = new_stmt(STMT_BREAK);
        expect(p, TOK_SEMI, "';'");
        return s;
    }
    if (consume(p, TOK_KW_CONTINUE)) {
        Stmt *s = new_stmt(STMT_CONTINUE);
        expect(p, TOK_SEMI, "';'");
        return s;
    }
    if (consume(p, TOK_KW_RETURN)) {
        Stmt *s = new_stmt(STMT_RETURN);
        if (!consume(p, TOK_SEMI)) {
            s->expr = parse_expr(p, ls);
            expect(p, TOK_SEMI, "';'");
        }
        return s;
    }
    if (consume(p, TOK_KW_GOTO)) {
        Stmt *s = new_stmt(STMT_GOTO);
        const char *nm = NULL;
        size_t nm_len = 0;
        expect_ident(p, &nm, &nm_len);
        if (nm_len == 0 || nm_len >= sizeof(s->label)) {
            die("%s:%d:%d: label name too long", p->lx.path, p->tok.line, p->tok.col);
        }
        mc_memcpy(s->label, nm, nm_len);
        s->label[nm_len] = 0;
        expect(p, TOK_SEMI, "';'");
        return s;
    }
    if (consume(p, TOK_KW_IF)) {
        Stmt *s = new_stmt(STMT_IF);
        expect(p, TOK_LPAREN, "'('");
        s->if_cond = parse_expr(p, ls);
        expect(p, TOK_RPAREN, "')'");
        s->if_then = parse_stmt(p, ls);
        if (consume(p, TOK_KW_ELSE)) {
            s->if_else = parse_stmt(p, ls);
        }
        return s;
    }
    if (consume(p, TOK_KW_WHILE)) {
        Stmt *s = new_stmt(STMT_WHILE);
        expect(p, TOK_LPAREN, "'('");
        s->while_cond = parse_expr(p, ls);
        expect(p, TOK_RPAREN, "')'");
        s->while_body = parse_stmt(p, ls);
        return s;
    }
    if (consume(p, TOK_KW_FOR)) {
        Stmt *s = new_stmt(STMT_FOR);
        expect(p, TOK_LPAREN, "'('");
        // init
        if (!tok_is(p, TOK_SEMI)) {
            if (looks_like_type_start(p) || tok_is(p, TOK_KW_EXTERN) || tok_is(p, TOK_KW_STATIC)) {
                s->for_init = parse_decl(p, ls);
            } else {
                Stmt *init = new_stmt(STMT_EXPR);
                init->expr = parse_expr(p, ls);
                expect(p, TOK_SEMI, "';'");
                s->for_init = init;
            }
        } else {
            expect(p, TOK_SEMI, "';'");
        }
        // cond
        if (!tok_is(p, TOK_SEMI)) {
            s->for_cond = parse_expr(p, ls);
        }
        expect(p, TOK_SEMI, "';'");
        // inc
        if (!tok_is(p, TOK_RPAREN)) {
            s->for_inc = parse_expr(p, ls);
        }
        expect(p, TOK_RPAREN, "')'");
        s->for_body = parse_stmt(p, ls);
        return s;
    }
    if (consume(p, TOK_KW_SWITCH)) {
        Stmt *s = new_stmt(STMT_SWITCH);
        expect(p, TOK_LPAREN, "'('");
        s->switch_expr = parse_expr(p, ls);
        expect(p, TOK_RPAREN, "')'");
        s->switch_body = parse_stmt(p, ls);
        return s;
    }
    // Inline assembly: __asm__ / __asm / asm
    if (tok_is_ident(p, "__asm__") || tok_is_ident(p, "__asm") || tok_is_ident(p, "asm")) {
        parser_next(p);
        return parse_asm_stmt(p, ls);
    }
    if (looks_like_type_start(p) || tok_is(p, TOK_KW_EXTERN) || tok_is(p, TOK_KW_STATIC)) {
        return parse_decl(p, ls);
    }

    // expression statement (possibly empty)
    if (consume(p, TOK_SEMI)) {
        return new_stmt(STMT_EXPR);
    }
    Stmt *s = new_stmt(STMT_EXPR);
    s->expr = parse_expr(p, ls);
    expect(p, TOK_SEMI, "';'");
    return s;
}

typedef struct {
    BaseType base;
    int ptr;
    int struct_id;
    int is_unsigned;
    const char *name;
    size_t name_len;
} ParamTmp;

static ParamTmp *parse_param_list(Parser *p, int *out_nparams) {
    // Parse parameters (subset) and return a heap array of ParamTmp.
    // Grammar (subset): type-spec ident? (, type-spec ident?)*
    if (out_nparams) *out_nparams = 0;
    if (tok_is(p, TOK_RPAREN)) return NULL;

    // Variadic-only: f(...)
    if (tok_is(p, TOK_ELLIPSIS)) {
        parser_next(p);
        return NULL;
    }

    ParamTmp *ps = NULL;
    int n = 0;
    int cap = 0;
    for (;;) {
        if (tok_is(p, TOK_ELLIPSIS)) {
            // Variadic marker must appear at the end.
            parser_next(p);
            if (!tok_is(p, TOK_RPAREN)) {
                die("%s:%d:%d: '...' must be last parameter", p->lx.path, p->tok.line, p->tok.col);
            }
            break;
        }
        BaseType b = BT_INT;
        int ptr = 0;
        int sid = -1;
        int is_unsigned = 0;
        parse_type_spec(p, &b, &ptr, &sid, &is_unsigned, 1);
        skip_gcc_attrs(p);

        const char *nm = NULL;
        size_t nm_len = 0;
        if (tok_is(p, TOK_IDENT) || tok_is(p, TOK_LPAREN)) {
            parse_declarator_name(p, &nm, &nm_len, &ptr);
        }

        // Parameter arrays decay to pointers: T name[] or T name[N]
        if (consume(p, TOK_LBRACK)) {
            // Skip length tokens if present.
            while (!tok_is(p, TOK_RBRACK)) {
                if (tok_is(p, TOK_EOF)) {
                    die("%s:%d:%d: unexpected EOF in parameter array", p->lx.path, p->tok.line, p->tok.col);
                }
                parser_next(p);
            }
            expect(p, TOK_RBRACK, "']'");
            ptr++;
            skip_gcc_attrs(p);
        }

        if (n + 1 > cap) {
            int ncap = cap ? cap * 2 : 8;
            ParamTmp *np = (ParamTmp *)monacc_realloc(ps, (size_t)ncap * sizeof(*np));
            if (!np) die("oom");
            ps = np;
            cap = ncap;
        }
        ps[n].base = b;
        ps[n].ptr = ptr;
        ps[n].struct_id = sid;
        ps[n].is_unsigned = is_unsigned;
        ps[n].name = nm;
        ps[n].name_len = nm_len;
        n++;

        if (consume(p, TOK_COMMA)) {
            // Trailing variadic marker: f(T a, ...)
            if (tok_is(p, TOK_ELLIPSIS)) {
                parser_next(p);
                if (!tok_is(p, TOK_RPAREN)) {
                    die("%s:%d:%d: '...' must be last parameter", p->lx.path, p->tok.line, p->tok.col);
                }
                break;
            }
            continue;
        }
        break;
    }
    if (out_nparams) *out_nparams = n;
    return ps;
}

static void skip_paren_group(Parser *p) {
    // Assumes current token is '('. Consumes through matching ')', allowing nesting.
    expect(p, TOK_LPAREN, "'('");
    int depth = 1;
    while (depth > 0) {
        if (p->tok.kind == TOK_EOF) {
            die("%s:%d:%d: unexpected EOF in parenthesized group", p->lx.path, p->tok.line, p->tok.col);
        }
        if (consume(p, TOK_LPAREN)) {
            depth++;
            continue;
        }
        if (consume(p, TOK_RPAREN)) {
            depth--;
            continue;
        }
        parser_next(p);
    }
}

static void parse_declarator_name(Parser *p, const char **out_nm, size_t *out_nm_len, int *io_ptr) {
    // Minimal declarator handling:
    // - name
    // - (*name)(...)  (function pointer; we treat as pointer and skip params)
    if (io_ptr) {
        while (consume(p, TOK_STAR)) {
            (*io_ptr)++;
            (void)skip_type_qualifiers(p, NULL, NULL, NULL);
        }
    }
    if (tok_is(p, TOK_IDENT)) {
        expect_ident(p, out_nm, out_nm_len);
        return;
    }
    if (consume(p, TOK_LPAREN)) {
        skip_gcc_attrs(p);
        int extra_ptr = 0;
        while (consume(p, TOK_STAR)) {
            extra_ptr++;
            (void)skip_type_qualifiers(p, NULL, NULL, NULL);
        }
        if (extra_ptr == 0) {
            die("%s:%d:%d: expected declarator", p->lx.path, p->tok.line, p->tok.col);
        }
        expect_ident(p, out_nm, out_nm_len);
        skip_gcc_attrs(p);
        expect(p, TOK_RPAREN, "')'");
        skip_gcc_attrs(p);
        if (tok_is(p, TOK_LPAREN)) {
            // Function pointer: skip parameter list.
            skip_paren_group(p);
        }
        if (io_ptr) *io_ptr += extra_ptr;
        return;
    }
    die("%s:%d:%d: expected identifier", p->lx.path, p->tok.line, p->tok.col);
}

static void parse_struct_def(Parser *p, int struct_id) {
    StructDef *sd = &p->prg->structs[struct_id];
    sd->nmembers = 0;
    sd->size = 0;
    sd->align = 1;

    expect(p, TOK_LBRACE, "'{'");

    int off = 0;
    int maxa = 1;
    while (!tok_is(p, TOK_RBRACE)) {
        if (tok_is(p, TOK_EOF)) {
            die("%s:%d:%d: unexpected EOF in struct definition", p->lx.path, p->tok.line, p->tok.col);
        }
        if (consume(p, TOK_SEMI)) {
            continue;
        }

        BaseType b = BT_INT;
        int ptr = 0;
        int sid = -1;
        int is_unsigned = 0;
        parse_type_spec(p, &b, &ptr, &sid, &is_unsigned, 0);
        skip_gcc_attrs(p);

        const char *mn = NULL;
        size_t mn_len = 0;
        parse_declarator_name(p, &mn, &mn_len, &ptr);
        skip_gcc_attrs(p);

        int array_len = 0;
        int array_len2 = 0;
        if (consume(p, TOK_LBRACK)) {
            // Arrays: T name[N]; and flexible: T name[];
            // Also support a 2nd dimension: T name[N][M];
            if (consume(p, TOK_RBRACK)) {
                array_len = -1; // flexible array member
                skip_gcc_attrs(p);
            } else {
                Expr *len_e = parse_expr(p, NULL);
                long long n = eval_const_expr(p, len_e);
                expect(p, TOK_RBRACK, "']'");
                skip_gcc_attrs(p);
                if (n <= 0) {
                    die("%s:%d:%d: array length must be positive", p->lx.path, p->tok.line, p->tok.col);
                }
                if (n > 0x7fffffffLL) {
                    die("%s:%d:%d: array length too large", p->lx.path, p->tok.line, p->tok.col);
                }
                array_len = (int)n;

                if (consume(p, TOK_LBRACK)) {
                    if (consume(p, TOK_RBRACK)) {
                        die("%s:%d:%d: unsized 2nd array dimension not supported", p->lx.path, p->tok.line, p->tok.col);
                    }
                    Expr *len2_e = parse_expr(p, NULL);
                    long long n2 = eval_const_expr(p, len2_e);
                    expect(p, TOK_RBRACK, "']'");
                    skip_gcc_attrs(p);
                    if (n2 <= 0) {
                        die("%s:%d:%d: array length must be positive", p->lx.path, p->tok.line, p->tok.col);
                    }
                    if (n2 > 0x7fffffffLL) {
                        die("%s:%d:%d: array length too large", p->lx.path, p->tok.line, p->tok.col);
                    }
                    array_len2 = (int)n2;
                }
            }
        }

        expect(p, TOK_SEMI, "';'");

        if (b == BT_VOID && ptr == 0) {
            die("%s:%d:%d: invalid struct member type void", p->lx.path, p->tok.line, p->tok.col);
        }

        int al = sd->is_packed ? 1 : type_alignof(p->prg, b, ptr, sid);
        int esz = type_sizeof(p->prg, b, ptr, sid);
        int sz = esz;
        if (array_len == -1) {
            sz = 0;
        } else if (array_len > 0) {
            long long total = (long long)esz * (long long)array_len;
            if (array_len2 > 0) {
                total *= (long long)array_len2;
            }
            if (total > 0x7fffffffLL) {
                die("%s:%d:%d: struct member array too large", p->lx.path, p->tok.line, p->tok.col);
            }
            sz = (int)total;
        }
        off = align_up(off, al);

        if (sd->nmembers + 1 > sd->cap) {
            int ncap = sd->cap ? sd->cap * 2 : 8;
            StructMember *nmemb = (StructMember *)monacc_realloc(sd->members, (size_t)ncap * sizeof(*nmemb));
            if (!nmemb) die("oom");
            sd->members = nmemb;
            sd->cap = ncap;
        }
        StructMember *m = &sd->members[sd->nmembers++];
        if (mn_len == 0 || mn_len >= sizeof(m->name)) {
            die("%s:%d:%d: struct member name too long", p->lx.path, p->tok.line, p->tok.col);
        }
        mc_memcpy(m->name, mn, mn_len);
        m->name[mn_len] = 0;
        m->base = b;
        m->ptr = ptr;
        m->struct_id = sid;
        m->is_unsigned = is_unsigned;
        m->array_len = array_len;
        m->array_len2 = array_len2;
        m->offset = off;
        m->size = sz;

        off += sz;
        if (array_len == -1) {
            // Flexible array member must be last.
            while (consume(p, TOK_SEMI)) {
            }
            if (!tok_is(p, TOK_RBRACE)) {
                die("%s:%d:%d: flexible array member must be last", p->lx.path, p->tok.line, p->tok.col);
            }
        }
        if (al > maxa) maxa = al;
    }

    expect(p, TOK_RBRACE, "'}'");
    sd->align = sd->is_packed ? 1 : maxa;
    sd->size = align_up(off, sd->align);
    if (sd->size == 0) sd->size = 1;
}

static Function parse_function_body(Parser *p, BaseType ret_base, int ret_ptr, int ret_struct_id, int ret_is_unsigned,
                                   const char *nm, size_t nm_len, const ParamTmp *params, int nparams) {
    Function fn = {0};
    if (nm_len == 0 || nm_len >= sizeof(fn.name)) {
        die("%s:%d:%d: function name too long", p->lx.path, p->tok.line, p->tok.col);
    }
    mc_memcpy(fn.name, nm, nm_len);
    fn.name[nm_len] = 0;
    fn.has_body = 1;

    fn.ret_base = ret_base;
    fn.ret_ptr = ret_ptr;
    fn.ret_struct_id = ret_struct_id;
    fn.ret_is_unsigned = ret_is_unsigned;
    fn.ret_size = 0;
    fn.sret_offset = 0;

    fn.nparams = 0;
    for (int i = 0; i < 6; i++) {
        fn.param_offsets[i] = 0;
        fn.param_sizes[i] = 0;
    }

    Locals ls = {0};
    ls.next_offset = 0;

    // Track current function name (used for static local symbol naming).
    if (nm_len > 0 && nm_len < sizeof(p->cur_fn_name)) {
        mc_memcpy(p->cur_fn_name, nm, nm_len);
        p->cur_fn_name[nm_len] = 0;
    } else {
        p->cur_fn_name[0] = 0;
    }

    int is_sret = (ret_base == BT_STRUCT && ret_ptr == 0);
    if (is_sret) {
        int sz = type_sizeof(p->prg, BT_STRUCT, 0, ret_struct_id);
        fn.ret_size = sz;
        // Hidden first argument is a pointer to return storage.
        // Spill it into a local slot so return statements can access it.
        const char *sret_nm = "__monacc_sret";
        fn.sret_offset = local_add(&ls, sret_nm, mc_strlen(sret_nm), BT_VOID, 1, -1, 1, 8, 8, 0);
    }

    // Bind named parameters as locals.
    // SysV x86_64 (subset):
    // - Integer/pointer args use up to 6 regs (%rdi..%r9), with the rest on stack at +16(%rbp), +24(%rbp), ...
    // - Large struct-by-value args (>16 bytes) are passed in memory on the stack (do not consume register slots).
    //   This is required for sysbox/tools/expr.c where `struct expr_val` (32 bytes) is passed by value.
    int reg_used = 0;
    int stack_off_bytes = 0;
    int reg_limit = is_sret ? 5 : 6;

    // C: f(void) means “no parameters”.
    if (nparams == 1 && params[0].base == BT_VOID && params[0].ptr == 0 && (!params[0].name || params[0].name_len == 0)) {
        nparams = 0;
    }
    for (int i = 0; i < nparams; i++) {
        if (params[i].base == BT_VOID && params[i].ptr == 0) {
            die("%s:%d:%d: invalid parameter type void", p->lx.path, p->tok.line, p->tok.col);
        }

        int has_name = (params[i].name && params[i].name_len > 0);
        int sz = type_sizeof(p->prg, params[i].base, params[i].ptr, params[i].struct_id);
        int is_struct_val = (params[i].base == BT_STRUCT && params[i].ptr == 0);

        if (is_struct_val && sz > 0 && sz <= 16) {
            die("%s:%d:%d: struct parameters <= 16 bytes not supported", p->lx.path, p->tok.line, p->tok.col);
        }

        if (is_struct_val && sz > 16) {
            // Passed in memory on stack.
            int off = 16 + stack_off_bytes;
            stack_off_bytes += align_up(sz, 8);
            if (has_name) {
                (void)local_add_fixed(&ls, params[i].name, params[i].name_len, params[i].base, params[i].ptr, params[i].struct_id, params[i].is_unsigned, sz,
                                      sz, 0, off);
            }
            continue;
        }

        int lsz = (sz == 1) ? 1 : (sz == 2) ? 2 : (sz == 4) ? 4 : 8;
        if (reg_used < reg_limit) {
            int reg_index = is_sret ? (reg_used + 1) : reg_used;
            reg_used++;
            if (has_name) {
                int off = local_add(&ls, params[i].name, params[i].name_len, params[i].base, params[i].ptr, params[i].struct_id, params[i].is_unsigned, lsz,
                                    lsz, 0);
                fn.param_offsets[reg_index] = off;
                fn.param_sizes[reg_index] = lsz;
                if (fn.nparams < reg_index + 1) fn.nparams = reg_index + 1;
            }
        } else {
            int off = 16 + stack_off_bytes;
            stack_off_bytes += 8;
            if (has_name) {
                (void)local_add_fixed(&ls, params[i].name, params[i].name_len, params[i].base, params[i].ptr, params[i].struct_id, params[i].is_unsigned, lsz,
                                      lsz, 0, off);
            }
        }
    }

    fn.body = parse_block(p, &ls);
    p->cur_fn_name[0] = 0;
    fn.stack_size = -ls.next_offset;
    fn.stack_size = (fn.stack_size + 15) & ~15;
    return fn;
}

void parse_program(Parser *p, Program *out) {
    while (p->tok.kind != TOK_EOF) {
        skip_gcc_attrs(p);

        if (consume(p, TOK_KW_TYPEDEF)) {
            skip_gcc_attrs(p);
            BaseType base = BT_INT;
            int ptr = 0;
            int sid = -1;
            int is_unsigned = 0;
            parse_type_spec(p, &base, &ptr, &sid, &is_unsigned, 0);
            skip_gcc_attrs(p);

            // Support: typedef struct { ... } Name;
            if (base == BT_STRUCT && ptr == 0 && tok_is(p, TOK_LBRACE)) {
                parse_struct_def(p, sid);
                skip_gcc_attrs(p);
            }

            int base_ptr = ptr;
            for (;;) {
                const char *nm = NULL;
                size_t nm_len = 0;
                int dptr = base_ptr;
                parse_declarator_name(p, &nm, &nm_len, &dptr);
                skip_gcc_attrs(p);
                program_add_typedef(out, nm, nm_len, base, dptr, sid, is_unsigned);
                if (consume(p, TOK_COMMA)) {
                    skip_gcc_attrs(p);
                    continue;
                }
                break;
            }
            expect(p, TOK_SEMI, "';'");
            continue;
        }

        int saw_static = 0;
        int saw_inline = 0;
        int saw_extern = 0;
        for (;;) {
            int did = 0;
            if (consume(p, TOK_KW_EXTERN)) {
                saw_extern = 1;
                did = 1;
            } else if (consume(p, TOK_KW_STATIC)) {
                saw_static = 1;
                did = 1;
            } else if (tok_is_ident(p, "inline") || tok_is_ident(p, "__inline") || tok_is_ident(p, "__inline__")) {
                parser_next(p);
                saw_inline = 1;
                did = 1;
            }
            if (!did) break;
            skip_gcc_attrs(p);
        }

        if (!looks_like_type_start(p)) {
            die("%s:%d:%d: expected top-level declaration", p->lx.path, p->tok.line, p->tok.col);
        }

        BaseType base = BT_INT;
        int ptr = 0;
        int sid = -1;
        int is_unsigned = 0;
        parse_type_spec(p, &base, &ptr, &sid, &is_unsigned, 0);
        skip_gcc_attrs(p);

        // Allow tag-only/constant-only declarations like: enum { A=1, B=2 };
        if (tok_is(p, TOK_SEMI)) {
            parser_next(p);
            continue;
        }

        // struct tag definition or forward-decl
        if (base == BT_STRUCT && ptr == 0 && tok_is(p, TOK_LBRACE)) {
            parse_struct_def(p, sid);
            skip_gcc_attrs(p);
            expect(p, TOK_SEMI, "';'");
            continue;
        }
        if (base == BT_STRUCT && ptr == 0 && tok_is(p, TOK_SEMI)) {
            // forward decl: struct S;
            parser_next(p);
            continue;
        }

        // declarator name
        const char *nm = NULL;
        size_t nm_len = 0;
        parse_declarator_name(p, &nm, &nm_len, &ptr);
        skip_gcc_attrs(p);

        // function prototype/definition
        if (consume(p, TOK_LPAREN)) {
            int nparams = 0;
            ParamTmp *params = parse_param_list(p, &nparams);
            expect(p, TOK_RPAREN, "')'");
            skip_gcc_attrs(p);
            if (consume(p, TOK_SEMI)) {
                Function proto = {0};
                if (nm_len == 0 || nm_len >= sizeof(proto.name)) {
                    die("%s:%d:%d: function name too long", p->lx.path, p->tok.line, p->tok.col);
                }
                mc_memcpy(proto.name, nm, nm_len);
                proto.name[nm_len] = 0;
                proto.is_static = saw_static;
                proto.is_inline = saw_inline;
                proto.has_body = 0;
                proto.ret_base = base;
                proto.ret_ptr = ptr;
                proto.ret_struct_id = sid;
                proto.ret_is_unsigned = is_unsigned;
                proto.ret_size = (base == BT_STRUCT && ptr == 0) ? type_sizeof(p->prg, BT_STRUCT, 0, sid) : 0;
                proto.sret_offset = 0;
                program_add_fn(out, &proto);

                monacc_free(params);
                continue;
            }
            Function fn = parse_function_body(p, base, ptr, sid, is_unsigned, nm, nm_len, params, nparams);
            fn.is_static = saw_static;
            fn.is_inline = saw_inline;
            monacc_free(params);
            program_add_fn(out, &fn);
            continue;
        }

        // Global variables
        // Handle array syntax: T name[N] or T name[]
        int array_len = 0;
        if (consume(p, TOK_LBRACK)) {
            if (tok_is(p, TOK_NUM)) {
                array_len = (int)p->tok.num;
                parser_next(p);
            } else {
                // Incomplete array (only valid as an extern declaration in this compiler).
                array_len = -1;
            }
            expect(p, TOK_RBRACK, "']'");
            skip_gcc_attrs(p);
        }

        if (array_len < 0 && !saw_extern) {
            die("%s:%d:%d: incomplete global array requires extern", p->lx.path, p->tok.line, p->tok.col);
        }

        GlobalVar gv = {0};
        if (nm_len == 0 || nm_len >= sizeof(gv.name)) {
            die("%s:%d:%d: global variable name too long", p->lx.path, p->tok.line, p->tok.col);
        }
        mc_memcpy(gv.name, nm, nm_len);
        gv.name[nm_len] = 0;
        gv.base = base;
        gv.ptr = ptr;
        gv.struct_id = sid;
        gv.is_unsigned = is_unsigned;
        gv.is_static = saw_static;
        gv.array_len = array_len;
        gv.is_extern = saw_extern;

        int elem_size = type_sizeof(p->prg, base, ptr, sid);
        gv.elem_size = elem_size;
        if (array_len > 0) {
            gv.size = elem_size * array_len;
        } else if (array_len < 0) {
            gv.size = 0;
        } else {
            gv.size = elem_size;
        }

        program_add_global(out, &gv);

        // Skip initializer if present (= ...)
        if (consume(p, TOK_ASSIGN)) {
            if (saw_extern) {
                die("%s:%d:%d: extern global initializers are not supported", p->lx.path, p->tok.line, p->tok.col);
            }
            // Skip to semicolon, handling braces for struct/array initializers
            int brace_depth = 0;
            while (p->tok.kind != TOK_EOF) {
                if (tok_is(p, TOK_LBRACE)) {
                    brace_depth++;
                    parser_next(p);
                } else if (tok_is(p, TOK_RBRACE)) {
                    if (brace_depth > 0) brace_depth--;
                    parser_next(p);
                } else if (tok_is(p, TOK_SEMI) && brace_depth == 0) {
                    break;
                } else {
                    parser_next(p);
                }
            }
        }
        expect(p, TOK_SEMI, "';'");
    }
    if (out->nfns == 0) {
        // Allow files with only global variables (no functions)
        // die("%s: no functions found", p->lx.path);
    }
}

void write_file(const char *path, const char *data, size_t len) {
    int fd = xopen_wtrunc(path, 0644);
    xwrite_all(fd, data, len);
    xclose_checked(fd, "close", path);
}

