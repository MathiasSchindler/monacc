#include "monacc.h"

// Internal assembler: converts monacc-emitted x86_64 AT&T-ish assembly into an ELF64 relocatable object (.o).
//
// Scope (by design): supports exactly the directives/instructions monacc_codegen emits today.
// This keeps the implementation small while letting us drop the external `as` dependency incrementally.

// ===== Minimal ELF64 types/constants (avoid <elf.h>) =====

#define EI_NIDENT 16

#define ELFCLASS64 2
#define ELFDATA2LSB 1
#define EV_CURRENT 1

#define ET_REL 1
#define EM_X86_64 62

#define SHT_NULL 0
#define SHT_PROGBITS 1
#define SHT_SYMTAB 2
#define SHT_STRTAB 3
#define SHT_RELA 4
#define SHT_NOBITS 8

#define SHF_WRITE 0x1
#define SHF_ALLOC 0x2
#define SHF_EXECINSTR 0x4

#define STB_LOCAL 0
#define STB_GLOBAL 1

#define STT_NOTYPE 0
#define STT_OBJECT 1
#define STT_FUNC 2
#define STT_SECTION 3

#define SHN_UNDEF 0

#define R_X86_64_PC32 2
#define R_X86_64_PLT32 4

typedef struct {
    unsigned char e_ident[EI_NIDENT];
    uint16_t e_type;
    uint16_t e_machine;
    uint32_t e_version;
    uint64_t e_entry;
    uint64_t e_phoff;
    uint64_t e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsize;
    uint16_t e_phentsize;
    uint16_t e_phnum;
    uint16_t e_shentsize;
    uint16_t e_shnum;
    uint16_t e_shstrndx;
} Elf64_Ehdr;

typedef struct {
    uint32_t sh_name;
    uint32_t sh_type;
    uint64_t sh_flags;
    uint64_t sh_addr;
    uint64_t sh_offset;
    uint64_t sh_size;
    uint32_t sh_link;
    uint32_t sh_info;
    uint64_t sh_addralign;
    uint64_t sh_entsize;
} Elf64_Shdr;

typedef struct {
    uint32_t st_name;
    unsigned char st_info;
    unsigned char st_other;
    uint16_t st_shndx;
    uint64_t st_value;
    uint64_t st_size;
} Elf64_Sym;

typedef struct {
    uint64_t r_offset;
    uint64_t r_info;
    int64_t r_addend;
} Elf64_Rela;

static unsigned char elf_st_info(unsigned char bind, unsigned char type) {
    return (unsigned char)((bind << 4) | (type & 0x0f));
}

static uint64_t elf_r_info(uint32_t sym, uint32_t type) {
    return ((uint64_t)sym << 32) | (uint64_t)type;
}

// ===== Small binary buffer helpers =====

static void bin_reserve(Str *s, size_t add) {
    if (s->len + add <= s->cap) return;
    size_t ncap = s->cap ? s->cap : 4096;
    while (ncap < s->len + add) ncap *= 2;
    char *nb = (char *)monacc_realloc(s->buf, ncap);
    if (!nb) die("oom");
    s->buf = nb;
    s->cap = ncap;
}

static void bin_put(Str *s, const void *p, size_t n) {
    if (!p || n == 0) return;
    bin_reserve(s, n);
    mc_memcpy(s->buf + s->len, p, n);
    s->len += n;
}

static void bin_put_u8(Str *s, unsigned int v) {
    unsigned char b = (unsigned char)v;
    bin_put(s, &b, 1);
}

static void bin_put_u32_le(Str *s, uint32_t v) {
    unsigned char b[4];
    b[0] = (unsigned char)(v & 0xff);
    b[1] = (unsigned char)((v >> 8) & 0xff);
    b[2] = (unsigned char)((v >> 16) & 0xff);
    b[3] = (unsigned char)((v >> 24) & 0xff);
    bin_put(s, b, 4);
}

static void bin_put_u64_le(Str *s, uint64_t v) {
    unsigned char b[8];
    for (int i = 0; i < 8; i++) b[i] = (unsigned char)((v >> (8 * i)) & 0xff);
    bin_put(s, b, 8);
}

static void bin_patch_u32_le(Str *s, size_t off, uint32_t v) {
    if (!s || off + 4 > s->len) die("internal: patch out of range");
    s->buf[off + 0] = (char)(v & 0xff);
    s->buf[off + 1] = (char)((v >> 8) & 0xff);
    s->buf[off + 2] = (char)((v >> 16) & 0xff);
    s->buf[off + 3] = (char)((v >> 24) & 0xff);
}

static uint64_t align_up_u64(uint64_t x, uint64_t a) {
    if (a == 0) return x;
    uint64_t m = a - 1;
    return (x + m) & ~m;
}

// ===== Minimal assembler state =====

typedef struct {
    uint64_t r_offset;
    char *sym_name;
    uint32_t r_type;
    int64_t addend;
} PendingRela;

typedef struct {
    char *name;
    uint32_t sh_type;
    uint64_t sh_flags;
    uint64_t sh_addralign;
    uint64_t sh_entsize;

    Str data; // SHT_PROGBITS payload

    PendingRela *rela;
    int nrela;
    int caprela;

    uint32_t sec_index; // assigned during finalize
} ObjSection;

typedef struct {
    char *name;
    int is_global;
    int is_defined;
    ObjSection *sec;
    uint64_t value; // section offset
    uint64_t size;
    unsigned char type; // STT_*
} ObjSym;

// These small helper records are used during object emission.
// Kept at file scope so SELFHOST builds can compile this file.
typedef struct { ObjSection *sec; uint32_t name_off; } SecName;
typedef struct { ObjSym *sym; uint32_t idx; } SymIndex;
typedef struct {
    ObjSection *for_sec;
    uint32_t name_off;
    Str data;
    uint32_t sec_index;
} RelaSec;

typedef struct {
    ObjSection *sec;
    size_t disp_off; // offset of the rel32/disp32 field within sec->data
    char *target;
    int is_jcc;
    int cc; // 0=je/jz, 1=jne
} Fixup;

typedef struct {
    ObjSection **secs;
    int nsecs;
    int capsecs;

    ObjSym *syms;
    int nsyms;
    int capsyms;

    Fixup *fix;
    int nfix;
    int capfix;

    ObjSection *cur;
} AsmState;

static char *xstrdup_n(const char *p, size_t n) {
    char *s = (char *)monacc_malloc(n + 1);
    if (!s) die("oom");
    mc_memcpy(s, p, n);
    s[n] = 0;
    return s;
}

static int is_local_label_name(const char *name) {
    // gas-style local/temporary labels are typically .L* (including .LC*).
    return name && name[0] == '.' && name[1] == 'L';
}

static int is_space(char c) {
    return c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '\f' || c == '\v';
}

static const char *skip_ws(const char *p, const char *end) {
    while (p < end && is_space(*p)) p++;
    return p;
}

static const char *rskip_ws(const char *p, const char *end) {
    while (end > p && is_space(end[-1])) end--;
    return end;
}

static size_t span_len(const char *p, const char *end) {
    size_t n = 0;
    while (p < end) {
        n++;
        p++;
    }
    return n;
}

static int starts_with(const char *p, const char *end, const char *lit) {
    size_t n = mc_strlen(lit);
    if ((unsigned long)(end - p) < n) return 0;
    return mc_memcmp(p, lit, n) == 0;
}

static ObjSection *get_or_add_section(AsmState *st, const char *name, size_t name_len, uint64_t sh_flags) {
    for (int i = 0; i < st->nsecs; i++) {
        ObjSection *s = st->secs[i];
        if (mc_strlen(s->name) == name_len && mc_memcmp(s->name, name, name_len) == 0) {
            // Keep the first flags we saw; they should match.
            return s;
        }
    }

    if (st->nsecs + 1 > st->capsecs) {
        int ncap = st->capsecs ? st->capsecs * 2 : 32;
        ObjSection **ns = (ObjSection **)monacc_realloc(st->secs, (unsigned long)ncap * sizeof(*ns));
        if (!ns) die("oom");
        st->secs = ns;
        st->capsecs = ncap;
    }
    ObjSection *s = (ObjSection *)monacc_malloc(sizeof(*s));
    if (!s) die("oom");
    mc_memset(s, 0, sizeof(*s));
    s->name = xstrdup_n(name, name_len);
    s->sh_type = SHT_PROGBITS;
    s->sh_flags = sh_flags;
    s->sh_addralign = 1;
    s->sh_entsize = 0;
    s->data.buf = NULL;
    s->data.len = 0;
    s->data.cap = 0;
    st->secs[st->nsecs++] = s;
    return s;
}

static ObjSym *find_sym(AsmState *st, const char *name, size_t name_len) {
    for (int i = 0; i < st->nsyms; i++) {
        ObjSym *s = &st->syms[i];
        if (mc_strlen(s->name) == name_len && mc_memcmp(s->name, name, name_len) == 0) return s;
    }
    return NULL;
}

static ObjSym *get_or_add_sym(AsmState *st, const char *name, size_t name_len) {
    ObjSym *s = find_sym(st, name, name_len);
    if (s) return s;
    if (st->nsyms + 1 > st->capsyms) {
        int ncap = st->capsyms ? st->capsyms * 2 : 64;
        ObjSym *ns = (ObjSym *)monacc_realloc(st->syms, (unsigned long)ncap * sizeof(*ns));
        if (!ns) die("oom");
        st->syms = ns;
        st->capsyms = ncap;
    }
    s = &st->syms[st->nsyms++];
    mc_memset(s, 0, sizeof(*s));
    s->name = xstrdup_n(name, name_len);
    s->is_global = 0;
    s->is_defined = 0;
    s->sec = NULL;
    s->value = 0;
    s->size = 0;
    s->type = STT_NOTYPE;
    return s;
}

static void sec_add_rela(ObjSection *sec, uint64_t off, const char *sym, uint32_t r_type, int64_t addend) {
    if (sec->nrela + 1 > sec->caprela) {
        int ncap = sec->caprela ? sec->caprela * 2 : 16;
        PendingRela *nr = (PendingRela *)monacc_realloc(sec->rela, (unsigned long)ncap * sizeof(*nr));
        if (!nr) die("oom");
        sec->rela = nr;
        sec->caprela = ncap;
    }
    PendingRela *r = &sec->rela[sec->nrela++];
    r->r_offset = off;
    r->sym_name = (char *)sym; // points at an owned string elsewhere
    r->r_type = r_type;
    r->addend = addend;
}

static void add_fixup(AsmState *st, ObjSection *sec, size_t disp_off, const char *target, size_t target_len, int is_jcc, int cc) {
    if (st->nfix + 1 > st->capfix) {
        int ncap = st->capfix ? st->capfix * 2 : 64;
        Fixup *nf = (Fixup *)monacc_realloc(st->fix, (unsigned long)ncap * sizeof(*nf));
        if (!nf) die("oom");
        st->fix = nf;
        st->capfix = ncap;
    }
    Fixup *f = &st->fix[st->nfix++];
    f->sec = sec;
    f->disp_off = disp_off;
    f->target = xstrdup_n(target, target_len);
    f->is_jcc = is_jcc;
    f->cc = cc;
}

// ===== x86_64 encoder =====

typedef struct {
    int reg;   // 0..15
    int width; // 8/16/32/64
    int needs_rex_byte; // for spl/bpl/sil/dil
} Reg;

typedef struct {
    int has_base;
    int base;
    int has_index;
    int index;
    int scale; // 1,2,4,8
    int32_t disp;
    int riprel;
    char *sym; // for sym(%rip)
} Mem;

typedef enum { OP_NONE = 0, OP_REG, OP_IMM, OP_MEM, OP_SYM } OpKind;

typedef struct {
    OpKind kind;
    Reg reg;
    long long imm;
    Mem mem;
    char *sym; // for call sym / jmp sym
    int indirect; // leading '*' (e.g. call *%r11)
} Operand;

static int parse_int64(const char *p, const char *end, long long *out) {
    p = skip_ws(p, end);
    if (p >= end) return 0;
    int neg = 0;
    if (*p == '-') {
        neg = 1;
        p++;
    } else if (*p == '+') {
        p++;
    }
    if (p >= end || *p < '0' || *p > '9') return 0;
    unsigned long long v = 0;
    while (p < end && *p >= '0' && *p <= '9') {
        v = v * 10ULL + (unsigned long long)(*p - '0');
        p++;
    }
    long long sv;
    if (neg) {
        // clamp-ish; our immediates are small enough for toolchain.
        sv = -(long long)v;
    } else {
        sv = (long long)v;
    }
    *out = sv;
    return 1;
}

static int reg_name_match(const char *p, size_t n, const char *lit, int reg, int width, int needs_rex, Reg *out) {
    size_t m = mc_strlen(lit);
    if (n == m && mc_memcmp(p, lit, m) == 0) {
        out->reg = reg;
        out->width = width;
        out->needs_rex_byte = needs_rex;
        return 1;
    }
    return 0;
}

static int parse_reg_name(const char *p, const char *end, Reg *out) {
    if (p >= end || *p != '%') return 0;
    p++;
    size_t n = (unsigned long)(end - p);

    // r8..r15 (optionally with b/w/d suffix)
    if (n >= 2 && p[0] == 'r' && p[1] >= '8' && p[1] <= '9') {
        int r = p[1] - '0';
        int width = 64;
        int needs_rex = 0;
        if (n >= 3) {
            char s = p[2];
            if (s == 'b') width = 8;
            else if (s == 'w') width = 16;
            else if (s == 'd') width = 32;
        }
        out->reg = r;
        out->width = width;
        out->needs_rex_byte = needs_rex;
        return 1;
    }
    if (n >= 3 && p[0] == 'r' && p[1] == '1' && p[2] >= '0' && p[2] <= '5') {
        int r = 10 + (p[2] - '0');
        int width = 64;
        int needs_rex = 0;
        if (n >= 4) {
            char s = p[3];
            if (s == 'b') width = 8;
            else if (s == 'w') width = 16;
            else if (s == 'd') width = 32;
        }
        out->reg = r;
        out->width = width;
        out->needs_rex_byte = needs_rex;
        return 1;
    }

    // classic registers
    if (reg_name_match(p, n, "rax", 0, 64, 0, out)) return 1;
    if (reg_name_match(p, n, "eax", 0, 32, 0, out)) return 1;
    if (reg_name_match(p, n, "ax", 0, 16, 0, out)) return 1;
    if (reg_name_match(p, n, "al", 0, 8, 0, out)) return 1;

    if (reg_name_match(p, n, "rcx", 1, 64, 0, out)) return 1;
    if (reg_name_match(p, n, "ecx", 1, 32, 0, out)) return 1;
    if (reg_name_match(p, n, "cx", 1, 16, 0, out)) return 1;
    if (reg_name_match(p, n, "cl", 1, 8, 0, out)) return 1;

    if (reg_name_match(p, n, "rdx", 2, 64, 0, out)) return 1;
    if (reg_name_match(p, n, "edx", 2, 32, 0, out)) return 1;
    if (reg_name_match(p, n, "dx", 2, 16, 0, out)) return 1;
    if (reg_name_match(p, n, "dl", 2, 8, 0, out)) return 1;

    if (reg_name_match(p, n, "rbx", 3, 64, 0, out)) return 1;
    if (reg_name_match(p, n, "ebx", 3, 32, 0, out)) return 1;
    if (reg_name_match(p, n, "bx", 3, 16, 0, out)) return 1;
    if (reg_name_match(p, n, "bl", 3, 8, 0, out)) return 1;

    if (reg_name_match(p, n, "rsp", 4, 64, 0, out)) return 1;
    if (reg_name_match(p, n, "esp", 4, 32, 0, out)) return 1;
    if (reg_name_match(p, n, "sp", 4, 16, 0, out)) return 1;
    if (reg_name_match(p, n, "spl", 4, 8, 1, out)) return 1;

    if (reg_name_match(p, n, "rbp", 5, 64, 0, out)) return 1;
    if (reg_name_match(p, n, "ebp", 5, 32, 0, out)) return 1;
    if (reg_name_match(p, n, "bp", 5, 16, 0, out)) return 1;
    if (reg_name_match(p, n, "bpl", 5, 8, 1, out)) return 1;

    if (reg_name_match(p, n, "rsi", 6, 64, 0, out)) return 1;
    if (reg_name_match(p, n, "esi", 6, 32, 0, out)) return 1;
    if (reg_name_match(p, n, "si", 6, 16, 0, out)) return 1;
    if (reg_name_match(p, n, "sil", 6, 8, 1, out)) return 1;

    if (reg_name_match(p, n, "rdi", 7, 64, 0, out)) return 1;
    if (reg_name_match(p, n, "edi", 7, 32, 0, out)) return 1;
    if (reg_name_match(p, n, "di", 7, 16, 0, out)) return 1;
    if (reg_name_match(p, n, "dil", 7, 8, 1, out)) return 1;

    if (reg_name_match(p, n, "rip", -1, 64, 0, out)) return 1;

    return 0;
}

static void emit_rex(Str *s, int w, int r, int x, int b, int force) {
    unsigned char rex = 0x40;
    if (w) rex |= 0x08;
    if (r) rex |= 0x04;
    if (x) rex |= 0x02;
    if (b) rex |= 0x01;
    if (rex != 0x40 || force) bin_put_u8(s, rex);
}

static void emit_modrm(Str *s, int mod, int reg, int rm) {
    unsigned char b = (unsigned char)(((mod & 3) << 6) | ((reg & 7) << 3) | (rm & 7));
    bin_put_u8(s, b);
}

static void emit_sib(Str *s, int scale, int index, int base) {
    int ss = 0;
    if (scale == 1) ss = 0;
    else if (scale == 2) ss = 1;
    else if (scale == 4) ss = 2;
    else if (scale == 8) ss = 3;
    else die("internal: bad scale");
    unsigned char b = (unsigned char)(((ss & 3) << 6) | ((index & 7) << 3) | (base & 7));
    bin_put_u8(s, b);
}

static void encode_modrm_rm(Str *s, int reg_field, const Mem *m, int w, int op_is_byte, int *out_rex_r, int *out_rex_x, int *out_rex_b, int *out_force_rex) {
    (void)op_is_byte;
    if (m->riprel) {
        // [rip + disp32] encoded as mod=00 rm=101 disp32
        emit_modrm(s, 0, reg_field, 5);
        bin_put_u32_le(s, (uint32_t)m->disp);
        *out_rex_r |= (reg_field >> 3) & 1;
        return;
    }

    int base = m->has_base ? m->base : 5;
    int index = m->has_index ? m->index : 4; // 4 means no index
    int need_sib = 0;
    if (m->has_index) need_sib = 1;
    if (base == 4 || base == 12) need_sib = 1; // rsp/r12 require sib

    int rex_r = (reg_field >> 3) & 1;
    int rex_x = (index >> 3) & 1;
    int rex_b = (base >> 3) & 1;

    int mod = 0;
    int32_t disp = m->disp;
    int rm_field = base & 7;

    // Special cases: rbp/r13 with mod=00 means disp32, so force disp8=0.
    if (!m->has_index && !need_sib && disp == 0 && (rm_field == 5)) {
        mod = 1;
    }

    if (disp == 0 && mod == 0) {
        mod = 0;
    } else if (disp >= -128 && disp <= 127) {
        mod = 1;
    } else {
        mod = 2;
    }

    if (need_sib) {
        emit_modrm(s, mod, reg_field, 4);
        emit_sib(s, m->scale ? m->scale : 1, index & 7, base & 7);
    } else {
        emit_modrm(s, mod, reg_field, rm_field);
    }

    if (mod == 1) {
        bin_put_u8(s, (unsigned char)(disp & 0xff));
    } else if (mod == 2 || (mod == 0 && rm_field == 5)) {
        bin_put_u32_le(s, (uint32_t)disp);
    }

    *out_rex_r |= rex_r;
    *out_rex_x |= rex_x;
    *out_rex_b |= rex_b;
    if (w) {
        // nothing extra
    }

    // For byte ops using spl/bpl/sil/dil, force a rex prefix.
    if (*out_force_rex) {
        // already forced
    }
}

static int parse_mem(const char *p, const char *end, Mem *out) {
    mc_memset(out, 0, sizeof(*out));
    out->scale = 1;

    const char *lpar = NULL;
    for (const char *q = p; q < end; q++) {
        if (*q == '(') {
            lpar = q;
            break;
        }
    }
    if (!lpar) return 0;

    const char *before = p;
    const char *before_end = lpar;
    before_end = rskip_ws(before, before_end);
    before = skip_ws(before, before_end);

    const char *rpar = NULL;
    for (const char *q = lpar; q < end; q++) {
        if (*q == ')') {
            rpar = q;
            break;
        }
    }
    if (!rpar) die("asm: missing )");

    // Parse disp/symbol before (
    if (before < before_end) {
        long long disp = 0;
        if (parse_int64(before, before_end, &disp)) {
            out->disp = (int32_t)disp;
        } else {
            // symbol
            out->sym = xstrdup_n(before, (unsigned long)(before_end - before));
        }
    }

    // Inside parens: base[,index[,scale]]
    const char *in = lpar + 1;
    const char *in_end = rpar;

    // Split by commas (up to 3 parts)
    const char *parts[3] = {0};
    const char *parts_end[3] = {0};
    int np = 0;
    const char *cur = in;
    for (const char *q = in; q <= in_end; q++) {
        if (q == in_end || *q == ',') {
            if (np < 3) {
                parts[np] = cur;
                parts_end[np] = q;
                np++;
            }
            cur = q + 1;
        }
    }

    if (np < 1) die("asm: bad mem");

    // base
    {
        const char *b = skip_ws(parts[0], parts_end[0]);
        const char *be = rskip_ws(b, parts_end[0]);
        if (b < be) {
            Reg r = {0};
            if (!parse_reg_name(b, be, &r)) die("asm: bad base reg");
            if (r.reg == -1) {
                // %rip
                out->riprel = 1;
                if (!out->sym) die("asm: riprel requires symbol");
                out->has_base = 0;
            } else {
                out->has_base = 1;
                out->base = r.reg;
            }
        }
    }

    if (np >= 2) {
        const char *b = skip_ws(parts[1], parts_end[1]);
        const char *be = rskip_ws(b, parts_end[1]);
        if (b < be) {
            Reg r = {0};
            if (!parse_reg_name(b, be, &r)) die("asm: bad index reg");
            out->has_index = 1;
            out->index = r.reg;
        }
    }
    if (np >= 3) {
        long long sc = 1;
        if (!parse_int64(parts[2], parts_end[2], &sc)) die("asm: bad scale");
        if (!(sc == 1 || sc == 2 || sc == 4 || sc == 8)) die("asm: bad scale");
        out->scale = (int)sc;
    }

    // For riprel, disp field is 0 and we rely on relocation.
    if (out->riprel) {
        out->disp = 0;
    }

    return 1;
}

static Operand parse_operand(AsmState *st, const char *p, const char *end) {
    Operand op;
    mc_memset(&op, 0, sizeof(op));
    p = skip_ws(p, end);
    end = rskip_ws(p, end);
    if (p >= end) {
        op.kind = OP_NONE;
        return op;
    }

    if (*p == '*') {
        op.indirect = 1;
        p++;
        p = skip_ws(p, end);
        end = rskip_ws(p, end);
        if (p >= end) die("asm: bad indirect operand");
    }

    if (*p == '$') {
        if (op.indirect) die("asm: indirect immediate");
        long long v = 0;
        if (!parse_int64(p + 1, end, &v)) die("asm: bad immediate");
        op.kind = OP_IMM;
        op.imm = v;
        return op;
    }

    if (*p == '%') {
        Reg r = {0};
        if (!parse_reg_name(p, end, &r)) die("asm: bad register");
        if (r.reg == -1) die("asm: rip register not allowed here");
        op.kind = OP_REG;
        op.reg = r;
        return op;
    }

    // memory?
    Mem m;
    if (parse_mem(p, end, &m)) {
        if (op.indirect) {
            // We only currently support indirect calls/jmps via registers.
            // Allowing *mem is easy to add later if we need it.
            die("asm: indirect mem unsupported");
        }
        op.kind = OP_MEM;
        op.mem = m;
        return op;
    }

    // symbol (call foo / jmp .L123)
    op.kind = OP_SYM;
    op.sym = xstrdup_n(p, (unsigned long)(end - p));
    (void)st;
    return op;
}

static void encode_call_reg(Str *s, const Reg *r) {
    if (r->width != 64) die("asm: call reg expects 64-bit reg");
    int rex_b = (r->reg >> 3) & 1;
    emit_rex(s, 1, 0, 0, rex_b, 0);
    bin_put_u8(s, 0xFF);
    // FF /2
    emit_modrm(s, 3, 2, r->reg & 7);
}

static void encode_jmp_reg(Str *s, const Reg *r) {
    if (r->width != 64) die("asm: jmp reg expects 64-bit reg");
    int rex_b = (r->reg >> 3) & 1;
    emit_rex(s, 1, 0, 0, rex_b, 0);
    bin_put_u8(s, 0xFF);
    // FF /4
    emit_modrm(s, 3, 4, r->reg & 7);
}

static void emit_imm32(Str *s, long long imm) {
    bin_put_u32_le(s, (uint32_t)imm);
}

static void emit_imm64(Str *s, long long imm) {
    bin_put_u64_le(s, (uint64_t)imm);
}

static void encode_push_pop(Str *s, int is_push, const Reg *r) {
    if (r->width != 64) die("asm: push/pop requires 64-bit reg");
    int rex_b = (r->reg >> 3) & 1;
    emit_rex(s, 0, 0, 0, rex_b, 0);
    bin_put_u8(s, (unsigned int)((is_push ? 0x50 : 0x58) + (r->reg & 7)));
}

static void encode_mov_imm_reg(Str *s, long long imm, const Reg *dst) {
    int rex_b = (dst->reg >> 3) & 1;
    if (dst->width == 64) {
        emit_rex(s, 1, 0, 0, rex_b, 0);
        bin_put_u8(s, (unsigned int)(0xB8 + (dst->reg & 7)));
        emit_imm64(s, imm);
        return;
    }
    if (dst->width == 32) {
        emit_rex(s, 0, 0, 0, rex_b, 0);
        bin_put_u8(s, (unsigned int)(0xB8 + (dst->reg & 7)));
        emit_imm32(s, imm);
        return;
    }
    die("asm: mov imm reg width");
}

static void encode_mov_reg_rm(Str *s, const Reg *src, const Operand *dst) {
    if (dst->kind != OP_MEM && dst->kind != OP_REG) die("asm: mov dst kind");
    int w = (src->width == 64);
    int op8 = (src->width == 8);
    int op16 = (src->width == 16);

    int rex_r = (src->reg >> 3) & 1;
    int force = (op8 && src->needs_rex_byte);

    if (op16) bin_put_u8(s, 0x66);

    if (dst->kind == OP_REG) {
        int rm = dst->reg.reg;
        int rex_b2 = (rm >> 3) & 1;
        int force2 = (op8 && dst->reg.needs_rex_byte);
        emit_rex(s, w, rex_r, 0, rex_b2, force || force2);
        bin_put_u8(s, op8 ? 0x88 : 0x89);
        emit_modrm(s, 3, src->reg & 7, rm & 7);
        return;
    }

    Mem *m = (Mem *)&dst->mem;
    // riprel store not emitted by codegen.
    if (m->riprel) die("asm: riprel store unsupported");
    // Emit REX later; we need rm bits.
    Str tmp = {0};
    // Encode opcode and ModRM/SIB/disp into tmp after rex.
    (void)tmp;

    // Build REX bits and ModRM into main buffer.
    emit_rex(s, w, rex_r, 0, 0, force);
    bin_put_u8(s, op8 ? 0x88 : 0x89);

    // Now ModRM/SIB/disp
    int rr = 0, rx = 0, rb = 0, fr = force;
    (void)fr;
    encode_modrm_rm(s, src->reg & 7, m, w, op8, &rr, &rx, &rb, &force);
    // Patch REX bits we might have missed? For simplicity, require regs < 8 in mem operands except r8.. which we do support.
    (void)rr; (void)rx; (void)rb;
}

static void encode_mov_rm_reg(Str *s, const Operand *src, const Reg *dst) {
    if (src->kind != OP_MEM && src->kind != OP_REG) die("asm: mov src kind");
    int w = (dst->width == 64);
    int op8 = (dst->width == 8);
    int op16 = (dst->width == 16);

    int rex_r = (dst->reg >> 3) & 1;
    int force = (op8 && dst->needs_rex_byte);

    if (op16) bin_put_u8(s, 0x66);

    if (src->kind == OP_REG) {
        int rm = src->reg.reg;
        int rex_b = (rm >> 3) & 1;
        int force2 = (op8 && src->reg.needs_rex_byte);
        emit_rex(s, w, rex_r, 0, rex_b, force || force2);
        bin_put_u8(s, op8 ? 0x8A : 0x8B);
        emit_modrm(s, 3, dst->reg & 7, rm & 7);
        return;
    }

    const Mem *m = &src->mem;
    if (m->riprel) {
        // lea handles riprel; loads with riprel not emitted by codegen today.
        die("asm: riprel load unsupported");
    }

    emit_rex(s, w, rex_r, 0, 0, force);
    bin_put_u8(s, op8 ? 0x8A : 0x8B);

    int rr = 0, rx = 0, rb = 0, fr = force;
    (void)fr;
    encode_modrm_rm(s, dst->reg & 7, m, w, op8, &rr, &rx, &rb, &force);
    (void)rr; (void)rx; (void)rb;
}

static void encode_binop_rr(Str *s, const char *mnem, const Reg *src, const Reg *dst) {
    int w = (dst->width == 64);
    if (src->width != dst->width) die("asm: binop width mismatch");
    int op16 = (dst->width == 16);
    int op8 = (dst->width == 8);
    if (op8) die("asm: binop byte not needed");

    unsigned int opc = 0;
    if (!mc_strcmp(mnem, "add")) opc = 0x01;
    else if (!mc_strcmp(mnem, "sub")) opc = 0x29;
    else if (!mc_strcmp(mnem, "and")) opc = 0x21;
    else if (!mc_strcmp(mnem, "or")) opc = 0x09;
    else if (!mc_strcmp(mnem, "xor")) opc = 0x31;
    else if (!mc_strcmp(mnem, "cmp")) opc = 0x39;
    else if (!mc_strcmp(mnem, "test")) opc = 0x85;
    else if (!mc_strcmp(mnem, "imul")) {
        // imul r/m64, r64 (0f af /r): src first, dst second.
        int rex_r = (dst->reg >> 3) & 1;
        int rex_b = (src->reg >> 3) & 1;
        if (op16) bin_put_u8(s, 0x66);
        emit_rex(s, w, rex_r, 0, rex_b, 0);
        bin_put_u8(s, 0x0f);
        bin_put_u8(s, 0xaf);
        emit_modrm(s, 3, dst->reg & 7, src->reg & 7);
        return;
    } else {
        die("asm: unknown binop");
    }

    if (op16) bin_put_u8(s, 0x66);
    int rex_r = (src->reg >> 3) & 1;
    int rex_b = (dst->reg >> 3) & 1;
    emit_rex(s, w, rex_r, 0, rex_b, 0);
    bin_put_u8(s, opc);
    emit_modrm(s, 3, src->reg & 7, dst->reg & 7);
}

static void encode_binop_imm(Str *s, const char *mnem, long long imm, const Reg *dst) {
    int w = (dst->width == 64);
    if (dst->width != 64 && dst->width != 32) die("asm: imm binop width");

    unsigned int subop = 0;
    if (!mc_strcmp(mnem, "add")) subop = 0;
    else if (!mc_strcmp(mnem, "or")) subop = 1;
    else if (!mc_strcmp(mnem, "and")) subop = 4;
    else if (!mc_strcmp(mnem, "sub")) subop = 5;
    else if (!mc_strcmp(mnem, "xor")) subop = 6;
    else if (!mc_strcmp(mnem, "cmp")) subop = 7;
    else die("asm: imm binop");

    int rex_b = (dst->reg >> 3) & 1;

    // Use imm8 when possible.
    if (imm >= -128 && imm <= 127) {
        emit_rex(s, w, 0, 0, rex_b, 0);
        bin_put_u8(s, 0x83);
        emit_modrm(s, 3, (int)subop, dst->reg & 7);
        bin_put_u8(s, (unsigned char)(imm & 0xff));
        return;
    }

    emit_rex(s, w, 0, 0, rex_b, 0);
    bin_put_u8(s, 0x81);
    emit_modrm(s, 3, (int)subop, dst->reg & 7);
    emit_imm32(s, imm);
}

static void encode_shift_cl(Str *s, const char *mnem, const Reg *dst) {
    int w = (dst->width == 64);
    if (!w) die("asm: shift expects 64-bit");
    unsigned int subop = 0;
    if (!mc_strcmp(mnem, "shl")) subop = 4;
    else if (!mc_strcmp(mnem, "shr")) subop = 5;
    else if (!mc_strcmp(mnem, "sar")) subop = 7;
    else die("asm: shift");

    int rex_b = (dst->reg >> 3) & 1;
    emit_rex(s, 1, 0, 0, rex_b, 0);
    bin_put_u8(s, 0xD3);
    emit_modrm(s, 3, (int)subop, dst->reg & 7);
}

static void encode_unop(Str *s, const char *mnem, const Reg *dst) {
    int w = (dst->width == 64);
    if (!w) die("asm: unop expects 64-bit");
    unsigned int subop = 0;
    if (!mc_strcmp(mnem, "not")) subop = 2;
    else if (!mc_strcmp(mnem, "neg")) subop = 3;
    else die("asm: unop");
    int rex_b = (dst->reg >> 3) & 1;
    emit_rex(s, 1, 0, 0, rex_b, 0);
    bin_put_u8(s, 0xF7);
    emit_modrm(s, 3, (int)subop, dst->reg & 7);
}

static void encode_div(Str *s, int is_signed, const Reg *src) {
    if (src->width != 64) die("asm: div expects 64-bit");
    int rex_b = (src->reg >> 3) & 1;
    emit_rex(s, 1, 0, 0, rex_b, 0);
    bin_put_u8(s, 0xF7);
    emit_modrm(s, 3, is_signed ? 7 : 6, src->reg & 7);
}

static void encode_lea(Str *s, const Mem *m, const Reg *dst) {
    if (dst->width != 64) die("asm: lea dest must be 64-bit");
    int rex_r = (dst->reg >> 3) & 1;
    int rex_x = 0;
    int rex_b = 0;
    int force = 0;

    emit_rex(s, 1, rex_r, 0, 0, 0);
    bin_put_u8(s, 0x8D);

    if (m->riprel) {
        // modrm: reg=dst, rm=101, disp32=0; relocation fills disp32.
        emit_modrm(s, 0, dst->reg & 7, 5);
        bin_put_u32_le(s, 0);
        return;
    }

    Mem mm = *m;
    // use encode_modrm_rm but need to set reg_field=dst
    encode_modrm_rm(s, dst->reg & 7, &mm, 1, 0, &rex_r, &rex_x, &rex_b, &force);
    (void)rex_x; (void)rex_b; (void)force;
}

static void encode_setcc(Str *s, const char *mnem, const Reg *dst) {
    if (dst->width != 8) die("asm: setcc expects byte reg");
    unsigned int cc = 0;
    if (!mc_strcmp(mnem, "sete")) cc = 0x94;
    else if (!mc_strcmp(mnem, "setne")) cc = 0x95;
    else if (!mc_strcmp(mnem, "setb")) cc = 0x92;
    else if (!mc_strcmp(mnem, "setbe")) cc = 0x96;
    else if (!mc_strcmp(mnem, "seta")) cc = 0x97;
    else if (!mc_strcmp(mnem, "setae")) cc = 0x93;
    else if (!mc_strcmp(mnem, "setl")) cc = 0x9C;
    else if (!mc_strcmp(mnem, "setle")) cc = 0x9E;
    else if (!mc_strcmp(mnem, "setg")) cc = 0x9F;
    else if (!mc_strcmp(mnem, "setge")) cc = 0x9D;
    else die("asm: unsupported setcc");

    int rex_b = (dst->reg >> 3) & 1;
    int force = dst->needs_rex_byte;
    emit_rex(s, 0, 0, 0, rex_b, force);
    bin_put_u8(s, 0x0F);
    bin_put_u8(s, cc);
    emit_modrm(s, 3, 0, dst->reg & 7);
}

static void encode_movzx(Str *s, int is_word, const Operand *src, const Reg *dst) {
    if (dst->width != 32) die("asm: movz expects 32-bit dst");
    int rex_r = (dst->reg >> 3) & 1;
    if (is_word) {
        emit_rex(s, 0, rex_r, 0, 0, 0);
        bin_put_u8(s, 0x0F);
        bin_put_u8(s, 0xB7);
    } else {
        emit_rex(s, 0, rex_r, 0, 0, 0);
        bin_put_u8(s, 0x0F);
        bin_put_u8(s, 0xB6);
    }

    if (src->kind == OP_REG) {
        emit_modrm(s, 3, dst->reg & 7, src->reg.reg & 7);
        return;
    }
    if (src->kind == OP_MEM) {
        int rr = 0, rx = 0, rb = 0, fr = 0;
        encode_modrm_rm(s, dst->reg & 7, &src->mem, 0, 1, &rr, &rx, &rb, &fr);
        return;
    }
    die("asm: movz src");
}

static void encode_movsx(Str *s, int src_width, const Operand *src, const Reg *dst) {
    if (dst->width != 64) die("asm: movs* expects 64-bit dst");
    int rex_r = (dst->reg >> 3) & 1;
    emit_rex(s, 1, rex_r, 0, 0, 0);

    if (src_width == 8) {
        bin_put_u8(s, 0x0F);
        bin_put_u8(s, 0xBE);
    } else if (src_width == 16) {
        bin_put_u8(s, 0x0F);
        bin_put_u8(s, 0xBF);
    } else if (src_width == 32) {
        // movsxd
        bin_put_u8(s, 0x63);
    } else {
        die("asm: movsx width");
    }

    if (src->kind == OP_REG) {
        emit_modrm(s, 3, dst->reg & 7, src->reg.reg & 7);
        return;
    }
    if (src->kind == OP_MEM) {
        int rr = 0, rx = 0, rb = 0, fr = 0;
        encode_modrm_rm(s, dst->reg & 7, &src->mem, 1, 0, &rr, &rx, &rb, &fr);
        return;
    }
    die("asm: movsx src");
}

static void encode_imul_imm(Str *s, long long imm, const Reg *dst) {
    if (dst->width != 64) die("asm: imul imm expects 64-bit dst");
    int rex_r = (dst->reg >> 3) & 1;
    int rex_b = rex_r;

    if (imm >= -128 && imm <= 127) {
        emit_rex(s, 1, rex_r, 0, rex_b, 0);
        bin_put_u8(s, 0x6B);
        emit_modrm(s, 3, dst->reg & 7, dst->reg & 7);
        bin_put_u8(s, (unsigned char)(imm & 0xff));
        return;
    }

    emit_rex(s, 1, rex_r, 0, rex_b, 0);
    bin_put_u8(s, 0x69);
    emit_modrm(s, 3, dst->reg & 7, dst->reg & 7);
    emit_imm32(s, imm);
}

// ===== Assembler driver (parses our limited assembly dialect) =====

static void parse_section_directive(AsmState *st, const char *p, const char *end) {
    // .section NAME,"flags",@progbits
    p += mc_strlen(".section");
    p = skip_ws(p, end);
    const char *name = p;
    while (p < end && *p != ',' && !is_space(*p)) p++;
    const char *name_end = p;

    uint64_t flags = 0;
    while (p < end && *p != '"') p++;
    if (p < end && *p == '"') {
        p++;
        while (p < end && *p != '"') {
            if (*p == 'a') flags |= SHF_ALLOC;
            else if (*p == 'x') flags |= SHF_EXECINSTR;
            else if (*p == 'w') flags |= SHF_WRITE;
            p++;
        }
    }

    ObjSection *sec;
    sec = get_or_add_section(st, name, span_len(name, name_end), flags);
    st->cur = sec;
}

static void parse_globl_directive(AsmState *st, const char *p, const char *end) {
    p += mc_strlen(".globl");
    p = skip_ws(p, end);
    const char *nm = p;
    const char *nm_end = rskip_ws(nm, end);
    if (nm >= nm_end) die("asm: .globl missing name");
    ObjSym *s;
    s = get_or_add_sym(st, nm, span_len(nm, nm_end));
    s->is_global = 1;
}

static void define_label(AsmState *st, const char *p, const char *end) {
    if (!st->cur) die("asm: label without section");
    const char *nm = p;
    const char *nm_end = end;
    if (nm_end > nm && nm_end[-1] == ':') nm_end--;
    nm_end = rskip_ws(nm, nm_end);
    nm = skip_ws(nm, nm_end);
    if (nm >= nm_end) return;

    ObjSym *s;
    s = get_or_add_sym(st, nm, span_len(nm, nm_end));
    s->is_defined = 1;
    s->sec = st->cur;
    s->value = st->cur->data.len;
    if (st->cur->sh_flags & SHF_EXECINSTR) {
        s->type = STT_FUNC;
    } else {
        s->type = STT_NOTYPE;
    }
}

static void parse_byte_directive(AsmState *st, const char *p, const char *end) {
    if (!st->cur) die("asm: .byte outside section");
    p += mc_strlen(".byte");
    for (;;) {
        p = skip_ws(p, end);
        if (p >= end) break;
        const char *q = p;
        while (q < end && *q != ',') q++;
        long long v = 0;
        if (!parse_int64(p, q, &v)) die("asm: bad .byte value");
        if (v < 0 || v > 255) die("asm: .byte out of range");
        bin_put_u8(&st->cur->data, (unsigned int)v);
        p = q;
        if (p < end && *p == ',') p++;
    }
}

static void parse_operands_top(const char *p, const char *end, const char **out_a, const char **out_ae, const char **out_b, const char **out_be) {
    *out_a = *out_ae = *out_b = *out_be = NULL;
    p = skip_ws(p, end);
    if (p >= end) return;

    int depth = 0;
    const char *comma = NULL;
    for (const char *q = p; q < end; q++) {
        if (*q == '(') depth++;
        else if (*q == ')') depth--;
        else if (*q == ',' && depth == 0) {
            comma = q;
            break;
        }
    }
    if (!comma) {
        *out_a = p;
        *out_ae = end;
        return;
    }
    *out_a = p;
    *out_ae = comma;
    *out_b = comma + 1;
    *out_be = end;
}

static void assemble_insn(AsmState *st, const char *p, const char *end) {
    if (!st->cur) die("asm: instruction without section");
    p = skip_ws(p, end);
    if (p >= end) return;

    // mnemonic
    const char *m0 = p;
    while (p < end && !is_space(*p)) p++;
    const char *m1 = p;
    m1 = rskip_ws(m0, m1);

    // Handle "rep movsb" / "rep stosb"
    if (mc_strlen("rep") == (unsigned long)(m1 - m0) && mc_memcmp(m0, "rep", 3) == 0) {
        p = skip_ws(p, end);
        const char *m20 = p;
        while (p < end && !is_space(*p)) p++;
        const char *m21 = rskip_ws(m20, p);
        if ((unsigned long)(m21 - m20) == 5 && mc_memcmp(m20, "movsb", 5) == 0) {
            bin_put_u8(&st->cur->data, 0xF3);
            bin_put_u8(&st->cur->data, 0xA4);
            return;
        }
        if ((unsigned long)(m21 - m20) == 5 && mc_memcmp(m20, "stosb", 5) == 0) {
            bin_put_u8(&st->cur->data, 0xF3);
            bin_put_u8(&st->cur->data, 0xAA);
            return;
        }
        die("asm: unsupported rep op");
    }

    // Copy mnemonic to a temp NUL-terminated buffer.
    char mnem[16];
    size_t mn = (unsigned long)(m1 - m0);
    if (mn >= sizeof(mnem)) die("asm: mnemonic too long");
    mc_memcpy(mnem, m0, mn);
    mnem[mn] = 0;

    const char *op_a = NULL, *op_ae = NULL, *op_b = NULL, *op_be = NULL;
    parse_operands_top(p, end, &op_a, &op_ae, &op_b, &op_be);

    if (!mc_strcmp(mnem, "syscall")) {
        bin_put_u8(&st->cur->data, 0x0F);
        bin_put_u8(&st->cur->data, 0x05);
        return;
    }
    if (!mc_strcmp(mnem, "hlt")) {
        bin_put_u8(&st->cur->data, 0xF4);
        return;
    }
    if (!mc_strcmp(mnem, "cld")) {
        bin_put_u8(&st->cur->data, 0xFC);
        return;
    }
    if (!mc_strcmp(mnem, "leave")) {
        bin_put_u8(&st->cur->data, 0xC9);
        return;
    }
    if (!mc_strcmp(mnem, "ret")) {
        bin_put_u8(&st->cur->data, 0xC3);
        return;
    }
    if (!mc_strcmp(mnem, "cqo")) {
        bin_put_u8(&st->cur->data, 0x48);
        bin_put_u8(&st->cur->data, 0x99);
        return;
    }

    // Single-operand
    if (!op_b) {
        Operand a = parse_operand(st, op_a, op_ae);
        if (!mc_strncmp(mnem, "set", 3)) {
            if (a.kind != OP_REG) die("asm: setcc expects reg");
            encode_setcc(&st->cur->data, mnem, &a.reg);
            return;
        }
        if (!mc_strcmp(mnem, "push")) {
            if (a.kind != OP_REG) die("asm: push expects reg");
            encode_push_pop(&st->cur->data, 1, &a.reg);
            return;
        }
        if (!mc_strcmp(mnem, "pop")) {
            if (a.kind != OP_REG) die("asm: pop expects reg");
            encode_push_pop(&st->cur->data, 0, &a.reg);
            return;
        }
        if (!mc_strcmp(mnem, "neg") || !mc_strcmp(mnem, "not")) {
            if (a.kind != OP_REG) die("asm: unop expects reg");
            encode_unop(&st->cur->data, mnem, &a.reg);
            return;
        }
        if (!mc_strcmp(mnem, "div")) {
            if (a.kind != OP_REG) die("asm: div expects reg");
            encode_div(&st->cur->data, 0, &a.reg);
            return;
        }
        if (!mc_strcmp(mnem, "idiv")) {
            if (a.kind != OP_REG) die("asm: idiv expects reg");
            encode_div(&st->cur->data, 1, &a.reg);
            return;
        }
        if (!mc_strcmp(mnem, "jmp")) {
            if (a.kind == OP_REG) {
                if (!a.indirect) die("asm: jmp reg requires '*'");
                encode_jmp_reg(&st->cur->data, &a.reg);
                return;
            }
            if (a.kind != OP_SYM || a.indirect) die("asm: jmp expects label");
            // e9 disp32
            bin_put_u8(&st->cur->data, 0xE9);
            size_t disp_off = st->cur->data.len;
            bin_put_u32_le(&st->cur->data, 0);
            add_fixup(st, st->cur, disp_off, a.sym, mc_strlen(a.sym), 0, 0);
            return;
        }
        if (!mc_strcmp(mnem, "call")) {
            if (a.kind == OP_REG) {
                if (!a.indirect) die("asm: call reg requires '*'");
                encode_call_reg(&st->cur->data, &a.reg);
                return;
            }
            if (a.kind != OP_SYM || a.indirect) die("asm: call expects symbol");
            bin_put_u8(&st->cur->data, 0xE8);
            size_t disp_off = st->cur->data.len;
            bin_put_u32_le(&st->cur->data, 0);
            ObjSym *sym = get_or_add_sym(st, a.sym, mc_strlen(a.sym));
            sec_add_rela(st->cur, (uint64_t)disp_off, sym->name, R_X86_64_PLT32, -4);
            return;
        }
        if (!mc_strcmp(mnem, "je") || !mc_strcmp(mnem, "jz") || !mc_strcmp(mnem, "jne")) {
            if (a.kind != OP_SYM) die("asm: jcc expects label");
            bin_put_u8(&st->cur->data, 0x0F);
            bin_put_u8(&st->cur->data, (!mc_strcmp(mnem, "jne")) ? 0x85 : 0x84);
            size_t disp_off = st->cur->data.len;
            bin_put_u32_le(&st->cur->data, 0);
            add_fixup(st, st->cur, disp_off, a.sym, mc_strlen(a.sym), 1, (!mc_strcmp(mnem, "jne")) ? 1 : 0);
            return;
        }
        die("asm: unsupported 1-op insn '%s'", mnem);
    }

    // Two-operand
    Operand a = parse_operand(st, op_a, op_ae);
    Operand b = parse_operand(st, op_b, op_be);

    if (!mc_strcmp(mnem, "mov")) {
        if (a.kind == OP_IMM && b.kind == OP_REG) {
            encode_mov_imm_reg(&st->cur->data, a.imm, &b.reg);
            return;
        }
        if (a.kind == OP_REG && (b.kind == OP_REG || b.kind == OP_MEM)) {
            encode_mov_reg_rm(&st->cur->data, &a.reg, &b);
            return;
        }
        if ((a.kind == OP_REG || a.kind == OP_MEM) && b.kind == OP_REG) {
            encode_mov_rm_reg(&st->cur->data, &a, &b.reg);
            return;
        }
        die("asm: mov form");
    }

    if (!mc_strcmp(mnem, "lea")) {
        if (a.kind != OP_MEM || b.kind != OP_REG) die("asm: lea form");
        // rip-relative lea needs relocation if symbolic.
        if (a.mem.riprel && a.mem.sym) {
            encode_lea(&st->cur->data, &a.mem, &b.reg);
            // relocation is at the disp32 field (end-4)
            size_t disp_off = st->cur->data.len - 4;
            ObjSym *sym = get_or_add_sym(st, a.mem.sym, mc_strlen(a.mem.sym));
            sec_add_rela(st->cur, (uint64_t)disp_off, sym->name, R_X86_64_PC32, -4);
            return;
        }
        encode_lea(&st->cur->data, &a.mem, &b.reg);
        return;
    }

    if (!mc_strcmp(mnem, "add") || !mc_strcmp(mnem, "sub") || !mc_strcmp(mnem, "and") || !mc_strcmp(mnem, "or") ||
        !mc_strcmp(mnem, "xor") || !mc_strcmp(mnem, "cmp") || !mc_strcmp(mnem, "test")) {
        if (a.kind == OP_IMM && b.kind == OP_REG) {
            encode_binop_imm(&st->cur->data, mnem, a.imm, &b.reg);
            return;
        }
        if (a.kind == OP_REG && b.kind == OP_REG) {
            encode_binop_rr(&st->cur->data, mnem, &a.reg, &b.reg);
            return;
        }
        die("asm: binop form");
    }

    if (!mc_strcmp(mnem, "imul")) {
        if (a.kind == OP_IMM && b.kind == OP_REG) {
            encode_imul_imm(&st->cur->data, a.imm, &b.reg);
            return;
        }
        if (a.kind == OP_REG && b.kind == OP_REG) {
            encode_binop_rr(&st->cur->data, "imul", &a.reg, &b.reg);
            return;
        }
        die("asm: imul form");
    }

    if (!mc_strcmp(mnem, "shl") || !mc_strcmp(mnem, "shr") || !mc_strcmp(mnem, "sar")) {
        if (a.kind != OP_REG || b.kind != OP_REG) die("asm: shift form");
        // only %cl is supported as the shift count
        if (!(a.reg.reg == 1 && a.reg.width == 8)) die("asm: shift count must be cl");
        encode_shift_cl(&st->cur->data, mnem, &b.reg);
        return;
    }

    if (!mc_strcmp(mnem, "movzb")) {
        // movzbl src8, dst32
        if (b.kind != OP_REG) die("asm: movzb dst");
        encode_movzx(&st->cur->data, 0, &a, &b.reg);
        return;
    }
    if (!mc_strcmp(mnem, "movzw")) {
        if (b.kind != OP_REG) die("asm: movzw dst");
        encode_movzx(&st->cur->data, 1, &a, &b.reg);
        return;
    }
    if (!mc_strcmp(mnem, "movsbq")) {
        if (b.kind != OP_REG) die("asm: movsbq dst");
        encode_movsx(&st->cur->data, 8, &a, &b.reg);
        return;
    }
    if (!mc_strcmp(mnem, "movswq")) {
        if (b.kind != OP_REG) die("asm: movswq dst");
        encode_movsx(&st->cur->data, 16, &a, &b.reg);
        return;
    }
    if (!mc_strcmp(mnem, "movslq")) {
        if (b.kind != OP_REG) die("asm: movslq dst");
        encode_movsx(&st->cur->data, 32, &a, &b.reg);
        return;
    }

    die("asm: unsupported insn");
}

static void resolve_fixups(AsmState *st) {
    for (int i = 0; i < st->nfix; i++) {
        Fixup *f = &st->fix[i];
        ObjSym *t = find_sym(st, f->target, mc_strlen(f->target));
        if (!t || !t->is_defined || t->sec != f->sec) {
            die("asm: unresolved local label");
        }
        int64_t P = (int64_t)f->disp_off;
        int64_t S = (int64_t)t->value;
        int64_t disp = S - (P + 4);
        if (disp < -(1LL << 31) || disp > ((1LL << 31) - 1)) die("asm: branch out of range");
        bin_patch_u32_le(&f->sec->data, f->disp_off, (uint32_t)(int32_t)disp);
    }
}

static uint32_t add_strtab(Str *strtab, const char *s) {
    if (!s || !*s) return 0;
    uint32_t off = (uint32_t)strtab->len;
    size_t n = mc_strlen(s);
    bin_put(strtab, s, n);
    bin_put_u8(strtab, 0);
    return off;
}

static void assemble_write_obj(AsmState *st, const char *out_o_path) {
    resolve_fixups(st);

    // Make unresolved (undefined) non-local symbols global so they can be
    // resolved across objects by the linker.
    for (int i = 0; i < st->nsyms; i++) {
        ObjSym *s = &st->syms[i];
        if (!s->is_defined && !is_local_label_name(s->name)) {
            s->is_global = 1;
        }
    }

    // Assign indices for user sections (starting at 1; 0 is SHT_NULL).
    uint32_t idx = 1;
    for (int i = 0; i < st->nsecs; i++) {
        st->secs[i]->sec_index = idx++;
    }

    // Build .shstrtab
    Str shstr = {0};
    bin_put_u8(&shstr, 0);

    // Helper to record sh_name offsets.
    SecName *sec_names = (SecName *)monacc_calloc((unsigned long)(st->nsecs + 8), sizeof(*sec_names));
    if (!sec_names) die("oom");
    for (int i = 0; i < st->nsecs; i++) {
        sec_names[i].sec = st->secs[i];
        sec_names[i].name_off = add_strtab(&shstr, st->secs[i]->name);
    }

    uint32_t shstrtab_name_off = add_strtab(&shstr, ".shstrtab");
    uint32_t strtab_name_off = add_strtab(&shstr, ".strtab");
    uint32_t symtab_name_off = add_strtab(&shstr, ".symtab");

    // Build .strtab and .symtab
    Str strtab = {0};
    bin_put_u8(&strtab, 0);

    // Symbol table: null + locals + globals
    // Determine local vs global ordering.
    int nlocals = 0;
    int nglobals = 0;
    for (int i = 0; i < st->nsyms; i++) {
        if (st->syms[i].is_global) nglobals++;
        else nlocals++;
    }

    int nsyms_out = 1 + nlocals + nglobals;
    Elf64_Sym *symtab = (Elf64_Sym *)monacc_calloc((unsigned long)nsyms_out, sizeof(*symtab));
    if (!symtab) die("oom");

    // Map symbol name -> symtab index.
    SymIndex *sym_index = (SymIndex *)monacc_calloc((unsigned long)st->nsyms, sizeof(*sym_index));
    if (!sym_index) die("oom");

    int out_i = 1;
    for (int pass = 0; pass < 2; pass++) {
        for (int i = 0; i < st->nsyms; i++) {
            ObjSym *s = &st->syms[i];
            if ((pass == 0) != (!s->is_global)) continue;

            uint32_t name_off = add_strtab(&strtab, s->name);
            Elf64_Sym es;
            mc_memset(&es, 0, sizeof(es));
            es.st_name = name_off;
            es.st_info = elf_st_info((unsigned char)(s->is_global ? STB_GLOBAL : STB_LOCAL), s->type);
            es.st_other = 0;
            es.st_shndx = (uint16_t)(s->is_defined ? s->sec->sec_index : SHN_UNDEF);
            es.st_value = s->is_defined ? s->value : 0;
            es.st_size = s->size;
            symtab[out_i] = es;

            sym_index[i].sym = s;
            sym_index[i].idx = (uint32_t)out_i;
            out_i++;
        }
    }

    uint32_t symtab_local_end = (uint32_t)(1 + nlocals);

    // Build relocation sections payloads.
    // We'll create a .rela<secname> for each section with relocations.
    RelaSec *rela_secs = NULL;
    int nrela_secs = 0;
    int caprela_secs = 0;

    for (int i = 0; i < st->nsecs; i++) {
        ObjSection *sec = st->secs[i];
        if (sec->nrela == 0) continue;

        if (nrela_secs + 1 > caprela_secs) {
            int ncap = caprela_secs ? caprela_secs * 2 : 8;
            RelaSec *nr = (RelaSec *)monacc_realloc(rela_secs, (unsigned long)ncap * sizeof(*nr));
            if (!nr) die("oom");
            rela_secs = nr;
            caprela_secs = ncap;
        }

        RelaSec *rs = &rela_secs[nrela_secs++];
        mc_memset(rs, 0, sizeof(*rs));
        rs->for_sec = sec;

        // Name: .rela + secname
        Str nm = {0};
        bin_put(&nm, ".rela", 5);
        bin_put(&nm, sec->name, mc_strlen(sec->name));
        bin_put_u8(&nm, 0);
        rs->name_off = add_strtab(&shstr, nm.buf);
        monacc_free(nm.buf);

        // Payload: Elf64_Rela entries
        for (int ri = 0; ri < sec->nrela; ri++) {
            PendingRela *pr = &sec->rela[ri];
            ObjSym *sym = find_sym(st, pr->sym_name, mc_strlen(pr->sym_name));
            if (!sym) die("internal: missing symbol for relocation");

            uint32_t symidx = 0;
            for (int si = 0; si < st->nsyms; si++) {
                if (sym_index[si].sym == sym) {
                    symidx = sym_index[si].idx;
                    break;
                }
            }
            if (!symidx) die("internal: symidx 0");

            Elf64_Rela er;
            er.r_offset = pr->r_offset;
            er.r_info = elf_r_info(symidx, pr->r_type);
            er.r_addend = pr->addend;
            bin_put(&rs->data, &er, sizeof(er));
        }
    }

    // Now build section headers list.
    // Sections in file order:
    // 0: NULL
    // 1..N: user sections
    // then .shstrtab, .strtab, .symtab, then .rela* sections

    int shnum = 1 + st->nsecs + 3 + nrela_secs;
    Elf64_Shdr *shdrs = (Elf64_Shdr *)monacc_calloc((unsigned long)shnum, sizeof(*shdrs));
    if (!shdrs) die("oom");

    // Build file image.
    Str file = {0};

    // ELF header placeholder
    Elf64_Ehdr eh;
    mc_memset(&eh, 0, sizeof(eh));
    eh.e_ident[0] = 0x7f;
    eh.e_ident[1] = 'E';
    eh.e_ident[2] = 'L';
    eh.e_ident[3] = 'F';
    eh.e_ident[4] = ELFCLASS64;
    eh.e_ident[5] = ELFDATA2LSB;
    eh.e_ident[6] = EV_CURRENT;
    eh.e_type = ET_REL;
    eh.e_machine = EM_X86_64;
    eh.e_version = EV_CURRENT;
    eh.e_ehsize = (uint16_t)sizeof(Elf64_Ehdr);
    eh.e_shentsize = (uint16_t)sizeof(Elf64_Shdr);
    eh.e_shnum = (uint16_t)shnum;

    bin_put(&file, &eh, sizeof(eh));

    // Section 0 header is all zeros.

    // Write user section data and fill shdrs
    uint32_t sh_i = 1;
    for (int i = 0; i < st->nsecs; i++) {
        ObjSection *sec = st->secs[i];
        // Align
        uint64_t align = sec->sh_addralign ? sec->sh_addralign : 1;
        uint64_t off = align_up_u64((uint64_t)file.len, align);
        while ((uint64_t)file.len < off) bin_put_u8(&file, 0);

        Elf64_Shdr sh;
        mc_memset(&sh, 0, sizeof(sh));
        sh.sh_name = sec_names[i].name_off;
        sh.sh_type = sec->sh_type;
        sh.sh_flags = sec->sh_flags;
        sh.sh_offset = (uint64_t)file.len;
        sh.sh_size = (uint64_t)sec->data.len;
        sh.sh_addralign = align;
        sh.sh_entsize = sec->sh_entsize;
        shdrs[sh_i] = sh;
        sh_i++;

        bin_put(&file, sec->data.buf, sec->data.len);
    }

    // .shstrtab
    uint32_t shstrtab_index = sh_i;
    {
        uint64_t off = align_up_u64((uint64_t)file.len, 1);
        while ((uint64_t)file.len < off) bin_put_u8(&file, 0);
        Elf64_Shdr sh;
        mc_memset(&sh, 0, sizeof(sh));
        sh.sh_name = shstrtab_name_off;
        sh.sh_type = SHT_STRTAB;
        sh.sh_flags = 0;
        sh.sh_offset = (uint64_t)file.len;
        sh.sh_size = (uint64_t)shstr.len;
        sh.sh_addralign = 1;
        shdrs[sh_i++] = sh;
        bin_put(&file, shstr.buf, shstr.len);
    }

    // .strtab
    uint32_t strtab_index = sh_i;
    {
        uint64_t off = align_up_u64((uint64_t)file.len, 1);
        while ((uint64_t)file.len < off) bin_put_u8(&file, 0);
        Elf64_Shdr sh;
        mc_memset(&sh, 0, sizeof(sh));
        sh.sh_name = strtab_name_off;
        sh.sh_type = SHT_STRTAB;
        sh.sh_flags = 0;
        sh.sh_offset = (uint64_t)file.len;
        sh.sh_size = (uint64_t)strtab.len;
        sh.sh_addralign = 1;
        shdrs[sh_i++] = sh;
        bin_put(&file, strtab.buf, strtab.len);
    }

    // .symtab
    uint32_t symtab_index = sh_i;
    {
        uint64_t off = align_up_u64((uint64_t)file.len, 8);
        while ((uint64_t)file.len < off) bin_put_u8(&file, 0);
        Elf64_Shdr sh;
        mc_memset(&sh, 0, sizeof(sh));
        sh.sh_name = symtab_name_off;
        sh.sh_type = SHT_SYMTAB;
        sh.sh_flags = 0;
        sh.sh_offset = (uint64_t)file.len;
        sh.sh_size = (uint64_t)nsyms_out * sizeof(Elf64_Sym);
        sh.sh_link = strtab_index;
        sh.sh_info = symtab_local_end;
        sh.sh_addralign = 8;
        sh.sh_entsize = sizeof(Elf64_Sym);
        shdrs[sh_i++] = sh;
        bin_put(&file, symtab, (unsigned long)sh.sh_size);
    }

    // .rela* sections
    for (int i = 0; i < nrela_secs; i++) {
        RelaSec *rs = &rela_secs[i];
        uint64_t off = align_up_u64((uint64_t)file.len, 8);
        while ((uint64_t)file.len < off) bin_put_u8(&file, 0);

        Elf64_Shdr sh;
        mc_memset(&sh, 0, sizeof(sh));
        sh.sh_name = rs->name_off;
        sh.sh_type = SHT_RELA;
        sh.sh_flags = 0;
        sh.sh_offset = (uint64_t)file.len;
        sh.sh_size = (uint64_t)rs->data.len;
        sh.sh_link = symtab_index;
        sh.sh_info = rs->for_sec->sec_index;
        sh.sh_addralign = 8;
        sh.sh_entsize = sizeof(Elf64_Rela);
        shdrs[sh_i++] = sh;
        bin_put(&file, rs->data.buf, rs->data.len);
    }

    if (sh_i != (uint32_t)shnum) die("internal: shnum mismatch");

    // Section header table at end
    uint64_t shoff = align_up_u64((uint64_t)file.len, 8);
    while ((uint64_t)file.len < shoff) bin_put_u8(&file, 0);

    // Patch ELF header
    ((Elf64_Ehdr *)file.buf)->e_shoff = shoff;
    ((Elf64_Ehdr *)file.buf)->e_shstrndx = (uint16_t)shstrtab_index;

    bin_put(&file, shdrs, (unsigned long)shnum * sizeof(Elf64_Shdr));

    write_file(out_o_path, file.buf, file.len);

    // cleanup
    monacc_free(sec_names);
    monacc_free(sym_index);
    monacc_free(symtab);
    monacc_free(rela_secs);
    monacc_free(shdrs);
    monacc_free(shstr.buf);
    monacc_free(strtab.buf);
    monacc_free(file.buf);
}

static void asmstate_free(AsmState *st) {
    if (!st) return;

    for (int i = 0; i < st->nfix; i++) {
        monacc_free(st->fix[i].target);
    }
    monacc_free(st->fix);

    for (int i = 0; i < st->nsyms; i++) {
        monacc_free(st->syms[i].name);
    }
    monacc_free(st->syms);

    for (int i = 0; i < st->nsecs; i++) {
        ObjSection *sec = st->secs[i];
        if (!sec) continue;
        monacc_free(sec->name);
        monacc_free(sec->data.buf);
        monacc_free(sec->rela);
        monacc_free(sec);
    }
    monacc_free(st->secs);

    st->secs = NULL;
    st->nsecs = st->capsecs = 0;
    st->syms = NULL;
    st->nsyms = st->capsyms = 0;
    st->fix = NULL;
    st->nfix = st->capfix = 0;
    st->cur = NULL;
}

void assemble_x86_64_elfobj(const char *asm_buf, size_t asm_len, const char *out_o_path) {
    AsmState st;
    mc_memset(&st, 0, sizeof(st));

    const char *p = asm_buf;
    const char *end = asm_buf + asm_len;

    while (p < end) {
        const char *line = p;
        while (p < end && *p != '\n') p++;
        const char *line_end = p;
        if (p < end && *p == '\n') p++;

        const char *a = skip_ws(line, line_end);
        const char *b = rskip_ws(a, line_end);
        if (a >= b) continue;

        // label? (including gas-style local labels like .LC0:)
        if (b > a) {
            const char *colon = NULL;
            for (const char *q = a; q < b; q++) {
                if (*q == ':') {
                    colon = q;
                    break;
                }
                if (is_space(*q)) break;
            }
            if (colon && colon + 1 == b) {
                define_label(&st, a, b);
                continue;
            }
        }

        // Directives / instructions
        if (*a == '.') {
            if (starts_with(a, b, ".section")) {
                parse_section_directive(&st, a, b);
                continue;
            }
            if (starts_with(a, b, ".globl")) {
                parse_globl_directive(&st, a, b);
                continue;
            }
            if (starts_with(a, b, ".byte")) {
                parse_byte_directive(&st, a, b);
                continue;
            }
            const char *q = a;
            while (q < b && !is_space(*q)) q++;
            die("asm: unsupported directive '%.*s'", (int)(q - a), a);
        }

        assemble_insn(&st, a, b);
    }

    assemble_write_obj(&st, out_o_path);
    asmstate_free(&st);
}
