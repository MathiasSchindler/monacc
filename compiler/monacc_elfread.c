#include "monacc_libc.h"
#include "mc.h"
#include "monacc_base.h"
#include "include/monacc/diag.h"
#include "include/monacc/util.h"
#include "include/monacc/elf.h"

// Minimal ELF64 ET_REL reader used for testing/bring-up of an internal linker.

// ELF constants
#define EI_NIDENT 16
#define ELFCLASS64 2
#define ELFDATA2LSB 1
#define EV_CURRENT 1

#define ET_REL 1
#define ET_EXEC 2

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

#define R_X86_64_64 1
#define R_X86_64_PC32 2
#define R_X86_64_PLT32 4
#define R_X86_64_32 10
#define R_X86_64_32S 11

typedef struct {
    unsigned char e_ident[EI_NIDENT];
    mc_u16 e_type;
    mc_u16 e_machine;
    mc_u32 e_version;
    mc_u64 e_entry;
    mc_u64 e_phoff;
    mc_u64 e_shoff;
    mc_u32 e_flags;
    mc_u16 e_ehsize;
    mc_u16 e_phentsize;
    mc_u16 e_phnum;
    mc_u16 e_shentsize;
    mc_u16 e_shnum;
    mc_u16 e_shstrndx;
} Elf64_Ehdr;

typedef struct {
    mc_u32 sh_name;
    mc_u32 sh_type;
    mc_u64 sh_flags;
    mc_u64 sh_addr;
    mc_u64 sh_offset;
    mc_u64 sh_size;
    mc_u32 sh_link;
    mc_u32 sh_info;
    mc_u64 sh_addralign;
    mc_u64 sh_entsize;
} Elf64_Shdr;

typedef struct {
    mc_u32 st_name;
    unsigned char st_info;
    unsigned char st_other;
    mc_u16 st_shndx;
    mc_u64 st_value;
    mc_u64 st_size;
} Elf64_Sym;

typedef struct {
    mc_u64 r_offset;
    mc_u64 r_info;
    mc_i64 r_addend;
} Elf64_Rela;

static mc_u32 elf64_r_sym(mc_u64 r_info) {
    return (mc_u32)(r_info >> 32);
}
static mc_u32 elf64_r_type(mc_u64 r_info) {
    return (mc_u32)(r_info & 0xffffffffu);
}

static const char *sec_type_name(mc_u32 t) {
    switch (t) {
    case SHT_NULL: return "NULL";
    case SHT_PROGBITS: return "PROGBITS";
    case SHT_SYMTAB: return "SYMTAB";
    case SHT_STRTAB: return "STRTAB";
    case SHT_RELA: return "RELA";
    case SHT_NOBITS: return "NOBITS";
    default: return "?";
    }
}

static const char *ehdr_type_name(mc_u16 t) {
    switch (t) {
    case ET_REL: return "ET_REL";
    case ET_EXEC: return "ET_EXEC";
    default: return "ET_?";
    }
}

static void sec_flags_to_str(mc_u64 f, char out[8]) {
    int p = 0;
    if (f & SHF_WRITE) out[p++] = 'W';
    if (f & SHF_ALLOC) out[p++] = 'A';
    if (f & SHF_EXECINSTR) out[p++] = 'X';
    out[p] = 0;
}

static const char *reloc_type_name(mc_u32 t) {
    switch (t) {
    case R_X86_64_64: return "R_X86_64_64";
    case R_X86_64_PC32: return "R_X86_64_PC32";
    case R_X86_64_PLT32: return "R_X86_64_PLT32";
    case R_X86_64_32: return "R_X86_64_32";
    case R_X86_64_32S: return "R_X86_64_32S";
    default: return "R_X86_64_?";
    }
}

static void out_cstr(const char *s) {
    if (!s) s = "(null)";
    xwrite_best_effort(2, s, mc_strlen(s));
}

static void out_u64_dec(mc_u64 v) {
    char tmp[32];
    mc_usize n = 0;
    if (v == 0) {
        tmp[n++] = '0';
    } else {
        while (v > 0) {
            tmp[n++] = (char)('0' + (char)(v % 10));
            v /= 10;
        }
    }
    while (n--) xwrite_best_effort(2, &tmp[n], 1);
}

static void out_i64_dec(mc_i64 v) {
    if (v < 0) {
        out_cstr("-");
        // Avoid overflow for INT64_MIN.
        mc_u64 u = (mc_u64)(-(v + 1)) + 1;
        out_u64_dec(u);
        return;
    }
    out_u64_dec((mc_u64)v);
}

static void out_nl(void) {
    out_cstr("\n");
}

static void *checked_slice(const unsigned char *buf, mc_usize len, mc_u64 off, mc_u64 sz, const char *what) {
    if (off > (mc_u64)len) die("elfread: %s out of range", what);
    if (sz > (mc_u64)len - off) die("elfread: %s out of range", what);
    return (void *)(buf + (mc_usize)off);
}

static unsigned char *slurp_file_bin(const char *path, mc_usize *out_len) {
    int fd = xopen_ro(path);

    mc_usize cap = 4096;
    unsigned char *buf = (unsigned char *)monacc_malloc(cap);
    if (!buf) die("oom");
    mc_usize n = 0;

    for (;;) {
        if (n >= cap) {
            mc_usize ncap = cap * 2;
            unsigned char *nb = (unsigned char *)monacc_realloc(buf, ncap);
            if (!nb) die("oom");
            buf = nb;
            cap = ncap;
        }

        mc_isize r = xread_retry(fd, (char *)buf + n, cap - n);
        if (r < 0) die("elfread: read %s failed", path);
        if (r == 0) break;
        n += (mc_usize)r;
    }

    xclose_checked(fd, "close", path);
    if (out_len) *out_len = n;
    return buf;
}

void elfobj_dump(const char *path) {
    mc_usize file_len = 0;
    unsigned char *file = slurp_file_bin(path, &file_len);

    if (file_len < sizeof(Elf64_Ehdr)) die("elfread: %s: too small", path);
    Elf64_Ehdr *eh = (Elf64_Ehdr *)file;

    if (!(eh->e_ident[0] == 0x7f && eh->e_ident[1] == 'E' && eh->e_ident[2] == 'L' && eh->e_ident[3] == 'F')) {
        die("elfread: %s: not an ELF file", path);
    }
    if (eh->e_ident[4] != ELFCLASS64) die("elfread: %s: not ELF64", path);
    if (eh->e_ident[5] != ELFDATA2LSB) die("elfread: %s: not little-endian", path);
    if (eh->e_ident[6] != EV_CURRENT) die("elfread: %s: bad ELF version", path);
    if (eh->e_type != ET_REL) die("elfread: %s: expected ET_REL", path);
    if (eh->e_machine != EM_X86_64) die("elfread: %s: expected EM_X86_64", path);

    if (eh->e_shoff == 0 || eh->e_shnum == 0) die("elfread: %s: missing section headers", path);
    if (eh->e_shentsize != (mc_u16)sizeof(Elf64_Shdr)) {
        die("elfread: %s: unexpected shentsize", path);
    }

    (void)checked_slice(file, file_len, eh->e_shoff, (mc_u64)eh->e_shnum * (mc_u64)sizeof(Elf64_Shdr), "section headers");
    Elf64_Shdr *shdrs = (Elf64_Shdr *)(file + (mc_usize)eh->e_shoff);

    if (eh->e_shstrndx >= eh->e_shnum) die("elfread: %s: bad e_shstrndx", path);
    Elf64_Shdr *shstr = &shdrs[eh->e_shstrndx];
    if (shstr->sh_type != SHT_STRTAB) die("elfread: %s: shstrtab is not STRTAB", path);
    const char *shstrtab = (const char *)checked_slice(file, file_len, shstr->sh_offset, shstr->sh_size, "shstrtab");

    out_cstr("elfobj: ");
    out_cstr(path);
    out_nl();
    out_cstr("ehdr: type=ET_REL machine=EM_X86_64 shnum=");
    out_u64_dec((mc_u64)eh->e_shnum);
    out_nl();

    // Find first symtab (if present)
    const Elf64_Sym *symtab = NULL;
    mc_usize symtab_n = 0;
    const char *strtab = NULL;
    mc_usize strtab_sz = 0;
    for (mc_u16 i = 0; i < eh->e_shnum; i++) {
        if (shdrs[i].sh_type != SHT_SYMTAB) continue;
        if (shdrs[i].sh_entsize != sizeof(Elf64_Sym)) continue;
        symtab = (const Elf64_Sym *)checked_slice(file, file_len, shdrs[i].sh_offset, shdrs[i].sh_size, "symtab");
        symtab_n = (mc_usize)(shdrs[i].sh_size / sizeof(Elf64_Sym));

        if (shdrs[i].sh_link < eh->e_shnum) {
            Elf64_Shdr *st = &shdrs[shdrs[i].sh_link];
            if (st->sh_type == SHT_STRTAB) {
                strtab = (const char *)checked_slice(file, file_len, st->sh_offset, st->sh_size, "strtab");
                strtab_sz = (mc_usize)st->sh_size;
            }
        }
        break;
    }

    out_cstr("sections:\n");
    for (mc_u16 i = 0; i < eh->e_shnum; i++) {
        const Elf64_Shdr *sh = &shdrs[i];
        const char *name = "";
        if (sh->sh_name < (mc_u32)shstr->sh_size) name = shstrtab + sh->sh_name;
        char flg[8];
        sec_flags_to_str(sh->sh_flags, flg);
        out_cstr("  [");
        out_u64_dec((mc_u64)i);
        out_cstr("] ");
        out_cstr(name);
        out_cstr(" type=");
        out_cstr(sec_type_name(sh->sh_type));
        out_cstr(" flags=");
        out_cstr(flg);
        out_cstr(" off=");
        out_u64_dec((mc_u64)sh->sh_offset);
        out_cstr(" size=");
        out_u64_dec((mc_u64)sh->sh_size);
        out_cstr(" align=");
        out_u64_dec((mc_u64)sh->sh_addralign);
        out_nl();
    }

    if (symtab) {
        out_cstr("symbols: n=");
        out_u64_dec((mc_u64)symtab_n);
        out_nl();
    } else {
        out_cstr("symbols: n=0 (no symtab)\n");
    }

    // Relocations
    out_cstr("relocations:\n");
    int any_rela = 0;
    for (mc_u16 i = 0; i < eh->e_shnum; i++) {
        const Elf64_Shdr *sh = &shdrs[i];
        if (sh->sh_type != SHT_RELA) continue;
        if (sh->sh_entsize != sizeof(Elf64_Rela)) continue;
        any_rela = 1;
        const char *relsec_name = "";
        if (sh->sh_name < (mc_u32)shstr->sh_size) relsec_name = shstrtab + sh->sh_name;

        const char *tgt_name = "";
        if (sh->sh_info < eh->e_shnum) {
            const Elf64_Shdr *tgt = &shdrs[sh->sh_info];
            if (tgt->sh_name < (mc_u32)shstr->sh_size) tgt_name = shstrtab + tgt->sh_name;
        }

        const Elf64_Rela *rels = (const Elf64_Rela *)checked_slice(file, file_len, sh->sh_offset, sh->sh_size, "rela");
        mc_usize nrel = (mc_usize)(sh->sh_size / sizeof(Elf64_Rela));
        out_cstr("  ");
        out_cstr(relsec_name);
        out_cstr(" -> ");
        out_cstr(tgt_name);
        out_cstr(": n=");
        out_u64_dec((mc_u64)nrel);
        out_nl();

        for (mc_usize j = 0; j < nrel; j++) {
            mc_u32 rtype = elf64_r_type(rels[j].r_info);
            mc_u32 rsym = elf64_r_sym(rels[j].r_info);
            const char *sname = "<nosym>";
            if (symtab && strtab && rsym < (mc_u32)symtab_n) {
                mc_u32 noff = symtab[rsym].st_name;
                if (noff < (mc_u32)strtab_sz) sname = strtab + noff;
                else sname = "<badname>";
            }

        out_cstr("    off=");
        out_u64_dec((mc_u64)rels[j].r_offset);
        out_cstr(" type=");
        out_cstr(reloc_type_name(rtype));
        out_cstr("(");
        out_u64_dec((mc_u64)rtype);
        out_cstr(") sym=");
        out_cstr(sname);
        out_cstr(" addend=");
        out_i64_dec((mc_i64)rels[j].r_addend);
        out_nl();
        }
    }
    if (!any_rela) out_cstr("  (none)\n");

    monacc_free(file);
}

void elfsec_dump(const char *path) {
    mc_usize file_len = 0;
    unsigned char *file = slurp_file_bin(path, &file_len);

    if (file_len < sizeof(Elf64_Ehdr)) die("elfread: %s: too small", path);
    Elf64_Ehdr *eh = (Elf64_Ehdr *)file;

    if (!(eh->e_ident[0] == 0x7f && eh->e_ident[1] == 'E' && eh->e_ident[2] == 'L' && eh->e_ident[3] == 'F')) {
        die("elfread: %s: not an ELF file", path);
    }
    if (eh->e_ident[4] != ELFCLASS64) die("elfread: %s: not ELF64", path);
    if (eh->e_ident[5] != ELFDATA2LSB) die("elfread: %s: not little-endian", path);
    if (eh->e_ident[6] != EV_CURRENT) die("elfread: %s: bad ELF version", path);

    out_cstr("elfsec: ");
    out_cstr(path);
    out_nl();

    out_cstr("ehdr: type=");
    out_cstr(ehdr_type_name(eh->e_type));
    out_cstr("(");
    out_u64_dec((mc_u64)eh->e_type);
    out_cstr(") shoff=");
    out_u64_dec((mc_u64)eh->e_shoff);
    out_cstr(" shnum=");
    out_u64_dec((mc_u64)eh->e_shnum);
    out_cstr(" shstrndx=");
    out_u64_dec((mc_u64)eh->e_shstrndx);
    out_nl();

    if (eh->e_shoff == 0 || eh->e_shnum == 0) {
        out_cstr("sections: (none)\n");
        monacc_free(file);
        return;
    }

    if (eh->e_shentsize != (mc_u16)sizeof(Elf64_Shdr)) {
        die("elfread: %s: unexpected shentsize", path);
    }

    (void)checked_slice(file, file_len, eh->e_shoff, (mc_u64)eh->e_shnum * (mc_u64)sizeof(Elf64_Shdr), "section headers");
    Elf64_Shdr *shdrs = (Elf64_Shdr *)(file + (mc_usize)eh->e_shoff);

    const char *shstrtab = NULL;
    mc_u64 shstr_sz = 0;
    if (eh->e_shstrndx < eh->e_shnum) {
        Elf64_Shdr *shstr = &shdrs[eh->e_shstrndx];
        if (shstr->sh_type == SHT_STRTAB) {
            shstrtab = (const char *)checked_slice(file, file_len, shstr->sh_offset, shstr->sh_size, "shstrtab");
            shstr_sz = shstr->sh_size;
        }
    }

    out_cstr("sections:\n");
    for (mc_u16 i = 0; i < eh->e_shnum; i++) {
        const Elf64_Shdr *sh = &shdrs[i];
        const char *name = "";
        if (shstrtab && sh->sh_name < (mc_u32)shstr_sz) name = shstrtab + sh->sh_name;

        char flg[8];
        sec_flags_to_str(sh->sh_flags, flg);
        out_cstr("  [");
        out_u64_dec((mc_u64)i);
        out_cstr("] ");
        out_cstr(name);
        out_cstr(" type=");
        out_cstr(sec_type_name(sh->sh_type));
        out_cstr(" flags=");
        out_cstr(flg);
        out_cstr(" addr=");
        out_u64_dec((mc_u64)sh->sh_addr);
        out_cstr(" off=");
        out_u64_dec((mc_u64)sh->sh_offset);
        out_cstr(" size=");
        out_u64_dec((mc_u64)sh->sh_size);
        out_nl();
    }

    monacc_free(file);
}
