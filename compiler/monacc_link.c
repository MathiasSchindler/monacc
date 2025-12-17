#include "monacc.h"
#include "monacc_sys.h"

// Step 2 (docs/ldremoval.md): Minimal internal link of a single ELF64 ET_REL object
// into a runnable ELF64 ET_EXEC, without applying relocations.

// ELF constants
#define EI_NIDENT 16
#define ELFCLASS64 2
#define ELFDATA2LSB 1
#define EV_CURRENT 1

#define ET_REL 1
#define ET_EXEC 2

#define EM_X86_64 62

#define PT_LOAD 1

#define PF_X 0x1
#define PF_W 0x2
#define PF_R 0x4

#define SHT_NULL 0
#define SHT_PROGBITS 1
#define SHT_SYMTAB 2
#define SHT_STRTAB 3
#define SHT_RELA 4
#define SHT_REL 9
#define SHT_NOBITS 8

#define R_X86_64_PC32 2
#define R_X86_64_PLT32 4

#define STB_LOCAL 0
#define STB_GLOBAL 1
#define STB_WEAK 2

#define SHN_UNDEF 0
#define SHN_ABS 0xfff1u

#define SHF_WRITE 0x1
#define SHF_ALLOC 0x2
#define SHF_EXECINSTR 0x4

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
    mc_u32 p_type;
    mc_u32 p_flags;
    mc_u64 p_offset;
    mc_u64 p_vaddr;
    mc_u64 p_paddr;
    mc_u64 p_filesz;
    mc_u64 p_memsz;
    mc_u64 p_align;
} Elf64_Phdr;

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

static void put_u32_le(unsigned char *p, mc_u32 v) {
    p[0] = (unsigned char)(v & 0xffu);
    p[1] = (unsigned char)((v >> 8) & 0xffu);
    p[2] = (unsigned char)((v >> 16) & 0xffu);
    p[3] = (unsigned char)((v >> 24) & 0xffu);
}

static mc_u64 align_up_u64(mc_u64 v, mc_u64 a) {
    if (a <= 1) return v;
    mc_u64 r = v % a;
    if (r == 0) return v;
    return v + (a - r);
}

static void *checked_slice(const unsigned char *buf, mc_usize len, mc_u64 off, mc_u64 sz, const char *what) {
    if (off > (mc_u64)len) die("link-internal: %s out of range", what);
    if (sz > (mc_u64)len - off) die("link-internal: %s out of range", what);
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
        if (r < 0) die("link-internal: read %s failed", path);
        if (r == 0) break;
        n += (mc_usize)r;
    }

    xclose_checked(fd, "close", path);
    if (out_len) *out_len = n;
    return buf;
}

static void write_file_mode(const char *path, const void *data, mc_usize len, int mode) {
    int fd = xopen_wtrunc(path, mode);
    xwrite_all(fd, data, len);
    xclose_checked(fd, "close", path);
}

typedef struct {
    const char *path;
    unsigned char *file;
    mc_usize file_len;

    Elf64_Ehdr *eh;
    Elf64_Shdr *shdrs;
    const char *shstrtab;
    mc_usize shstr_sz;

    const Elf64_Sym *symtab;
    mc_usize symtab_n;
    const char *strtab;
    mc_usize strtab_sz;

    Elf64_Shdr *relsecs;
    mc_u16 nrelsecs;

    mc_u64 *sec_vaddr;   // indexed by shndx
    mc_u64 *sec_fileoff; // indexed by shndx (0 for NOBITS)
    unsigned char *sec_keep; // indexed by shndx (GC reachability)
} InputObj;

typedef struct {
    const char *name;
    int obji;
    mc_u32 symi;
    unsigned char bind;
    int defined;
} GlobalSym;

static unsigned char sym_bind(const Elf64_Sym *s) {
    return (unsigned char)(s->st_info >> 4);
}

static const char *sym_name(const InputObj *in, mc_u32 symi) {
    if (!in->symtab || !in->strtab) return "";
    if (symi >= (mc_u32)in->symtab_n) return "";
    mc_u32 noff = in->symtab[symi].st_name;
    if (noff >= (mc_u32)in->strtab_sz) return "";
    return in->strtab + noff;
}

static int starts_with_lit(const char *s, const char *lit) {
    mc_usize n = mc_strlen(lit);
    if (!s) return 0;
    return mc_memcmp(s, lit, n) == 0;
}

// Layout order buckets: text, rodata, data, other alloc (progbits). NOBITS handled separately.
static int sec_rank(const char *name, mc_u64 sh_flags) {
    if (name && starts_with_lit(name, ".text")) return 0;
    if (sh_flags & SHF_EXECINSTR) return 0;
    if (name && starts_with_lit(name, ".rodata")) return 1;
    if (name && starts_with_lit(name, ".data")) return 2;
    if (sh_flags & SHF_WRITE) return 2;
    return 3;
}

static int sec_is_rx(const Elf64_Shdr *sh) {
    if (!sh) return 1;
    if ((sh->sh_flags & SHF_ALLOC) == 0) return 1;
    // Keep executable + read-only alloc sections in RX.
    if (sh->sh_flags & SHF_EXECINSTR) return 1;
    if (sh->sh_flags & SHF_WRITE) return 0;
    return 1;
}

static int find_global_sym(const GlobalSym *gs, int ngs, const char *name) {
    for (int i = 0; i < ngs; i++) {
        if (!gs[i].name || !name) continue;
        if (mc_strcmp(gs[i].name, name) == 0) return i;
    }
    return -1;
}

static mc_u32 shstr_add(char *buf, mc_usize cap, mc_usize *io_len, const char *s) {
    mc_usize n = mc_strlen(s);
    if (*io_len + n + 1 > cap) die("link-internal: shstrtab overflow");
    mc_u32 off = (mc_u32)(*io_len);
    mc_memcpy(buf + *io_len, s, n);
    *io_len += n;
    buf[(*io_len)++] = 0;
    return off;
}

static mc_u64 sym_addr_in_obj(const InputObj *in, mc_u32 symi) {
    const Elf64_Sym *s = &in->symtab[symi];
    mc_u16 shndx = s->st_shndx;
    if (shndx == SHN_ABS) return s->st_value;
    if (shndx == SHN_UNDEF) return 0;
    if (shndx >= in->eh->e_shnum) die("link-internal: bad symbol shndx");
    if (in->sec_vaddr[shndx] == 0) die("link-internal: symbol section not mapped");
    return in->sec_vaddr[shndx] + s->st_value;
}

static void input_obj_parse(InputObj *in, const char *obj_path) {
    mc_memset(in, 0, sizeof(*in));
    in->path = obj_path;
    in->file = slurp_file_bin(obj_path, &in->file_len);

    if (in->file_len < sizeof(Elf64_Ehdr)) die("link-internal: %s: too small", obj_path);
    in->eh = (Elf64_Ehdr *)in->file;

    if (!(in->eh->e_ident[0] == 0x7f && in->eh->e_ident[1] == 'E' && in->eh->e_ident[2] == 'L' && in->eh->e_ident[3] == 'F')) {
        die("link-internal: %s: not an ELF file", obj_path);
    }
    if (in->eh->e_ident[4] != ELFCLASS64) die("link-internal: %s: not ELF64", obj_path);
    if (in->eh->e_ident[5] != ELFDATA2LSB) die("link-internal: %s: not little-endian", obj_path);
    if (in->eh->e_ident[6] != EV_CURRENT) die("link-internal: %s: bad ELF version", obj_path);
    if (in->eh->e_type != ET_REL) die("link-internal: %s: expected ET_REL", obj_path);
    if (in->eh->e_machine != EM_X86_64) die("link-internal: %s: expected EM_X86_64", obj_path);

    if (in->eh->e_shoff == 0 || in->eh->e_shnum == 0) die("link-internal: %s: missing section headers", obj_path);
    if (in->eh->e_shentsize != (mc_u16)sizeof(Elf64_Shdr)) die("link-internal: %s: unexpected shentsize", obj_path);

    (void)checked_slice(in->file, in->file_len, in->eh->e_shoff, (mc_u64)in->eh->e_shnum * (mc_u64)sizeof(Elf64_Shdr), "section headers");
    in->shdrs = (Elf64_Shdr *)(in->file + (mc_usize)in->eh->e_shoff);

    if (in->eh->e_shstrndx >= in->eh->e_shnum) die("link-internal: %s: bad e_shstrndx", obj_path);
    Elf64_Shdr *shstr = &in->shdrs[in->eh->e_shstrndx];
    if (shstr->sh_type != SHT_STRTAB) die("link-internal: %s: shstrtab is not STRTAB", obj_path);
    in->shstrtab = (const char *)checked_slice(in->file, in->file_len, shstr->sh_offset, shstr->sh_size, "shstrtab");
    in->shstr_sz = (mc_usize)shstr->sh_size;

    // Find first symtab.
    for (mc_u16 i = 0; i < in->eh->e_shnum; i++) {
        if (in->shdrs[i].sh_type != SHT_SYMTAB) continue;
        if (in->shdrs[i].sh_entsize != sizeof(Elf64_Sym)) continue;
        in->symtab = (const Elf64_Sym *)checked_slice(in->file, in->file_len, in->shdrs[i].sh_offset, in->shdrs[i].sh_size, "symtab");
        in->symtab_n = (mc_usize)(in->shdrs[i].sh_size / sizeof(Elf64_Sym));
        if (in->shdrs[i].sh_link < in->eh->e_shnum) {
            Elf64_Shdr *st = &in->shdrs[in->shdrs[i].sh_link];
            if (st->sh_type == SHT_STRTAB) {
                in->strtab = (const char *)checked_slice(in->file, in->file_len, st->sh_offset, st->sh_size, "strtab");
                in->strtab_sz = (mc_usize)st->sh_size;
            }
        }
        break;
    }
    if (!in->symtab || !in->strtab) die("link-internal: %s: missing symtab/strtab", obj_path);

    // Collect relocation sections (RELA only).
    for (mc_u16 i = 0; i < in->eh->e_shnum; i++) {
        Elf64_Shdr *sh = &in->shdrs[i];
        if (sh->sh_type == SHT_REL && sh->sh_size != 0) {
            const char *nm = "";
            if (sh->sh_name < (mc_u32)in->shstr_sz) nm = in->shstrtab + sh->sh_name;
            die("link-internal: SHT_REL relocations not supported (section %s)", nm);
        }
        if (sh->sh_type != SHT_RELA) continue;
        if (sh->sh_size == 0) continue;
        if (sh->sh_entsize != sizeof(Elf64_Rela)) die("link-internal: unexpected RELA entsize");
        in->nrelsecs++;
    }
    if (in->nrelsecs) {
        in->relsecs = (Elf64_Shdr *)monacc_malloc((mc_usize)in->nrelsecs * sizeof(*in->relsecs));
        if (!in->relsecs) die("oom");
        mc_u16 w = 0;
        for (mc_u16 i = 0; i < in->eh->e_shnum; i++) {
            Elf64_Shdr *sh = &in->shdrs[i];
            if (sh->sh_type != SHT_RELA) continue;
            if (sh->sh_size == 0) continue;
            in->relsecs[w++] = *sh;
        }
    }
}

static void input_obj_free(InputObj *in) {
    if (!in) return;
    if (in->relsecs) monacc_free(in->relsecs);
    if (in->sec_vaddr) monacc_free(in->sec_vaddr);
    if (in->sec_fileoff) monacc_free(in->sec_fileoff);
    if (in->sec_keep) monacc_free(in->sec_keep);
    if (in->file) monacc_free(in->file);
    mc_memset(in, 0, sizeof(*in));
}

static void mark_keep(InputObj *in, mc_u16 shndx) {
    if (!in) return;
    if (shndx == SHN_UNDEF || shndx == SHN_ABS) return;
    if (shndx >= in->eh->e_shnum) return;
    const Elf64_Shdr *sh = &in->shdrs[shndx];
    if ((sh->sh_flags & SHF_ALLOC) == 0) return;
    in->sec_keep[shndx] = 1;
}

void link_internal_exec_objs(const char **obj_paths, int nobj_paths, const char *out_path, int keep_shdr) {
    if (!obj_paths || nobj_paths <= 0) die("link-internal: no input objects");

    InputObj *ins = (InputObj *)monacc_calloc((mc_usize)nobj_paths, sizeof(*ins));
    if (!ins) die("oom");

    for (int i = 0; i < nobj_paths; i++) {
        input_obj_parse(&ins[i], obj_paths[i]);
        ins[i].sec_vaddr = (mc_u64 *)monacc_calloc((mc_usize)ins[i].eh->e_shnum, sizeof(mc_u64));
        ins[i].sec_fileoff = (mc_u64 *)monacc_calloc((mc_usize)ins[i].eh->e_shnum, sizeof(mc_u64));
        ins[i].sec_keep = (unsigned char *)monacc_calloc((mc_usize)ins[i].eh->e_shnum, 1);
        if (!ins[i].sec_vaddr || !ins[i].sec_fileoff || !ins[i].sec_keep) die("oom");
    }

    // Build global symbol table from definitions.
    GlobalSym *gs = NULL;
    int ngs = 0;
    int capgs = 0;

    for (int oi = 0; oi < nobj_paths; oi++) {
        InputObj *in = &ins[oi];
        for (mc_u32 si = 0; si < (mc_u32)in->symtab_n; si++) {
            const Elf64_Sym *s = &in->symtab[si];
            unsigned char b = sym_bind(s);
            if (b == STB_LOCAL) continue;
            const char *nm = sym_name(in, si);
            if (!nm || *nm == 0) continue;
            int defined = (s->st_shndx != SHN_UNDEF);

            int idx = find_global_sym(gs, ngs, nm);
            if (idx < 0) {
                if (ngs + 1 > capgs) {
                    int ncap = capgs ? capgs * 2 : 128;
                    GlobalSym *ng = (GlobalSym *)monacc_realloc(gs, (mc_usize)ncap * sizeof(*ng));
                    if (!ng) die("oom");
                    gs = ng;
                    capgs = ncap;
                }
                GlobalSym *g = &gs[ngs++];
                mc_memset(g, 0, sizeof(*g));
                g->name = nm;
                g->obji = oi;
                g->symi = si;
                g->bind = b;
                g->defined = defined;
            } else {
                GlobalSym *g = &gs[idx];
                // Prefer a definition over undefined.
                if (!g->defined && defined) {
                    g->obji = oi;
                    g->symi = si;
                    g->defined = 1;
                    g->bind = b;
                } else if (g->defined && defined) {
                    // Resolve duplicates: prefer non-weak.
                    if (g->bind == STB_WEAK && b != STB_WEAK) {
                        g->obji = oi;
                        g->symi = si;
                        g->bind = b;
                    } else if (g->bind != STB_WEAK && b == STB_WEAK) {
                        // keep existing
                    } else {
                        die("link-internal: duplicate global symbol %s", nm);
                    }
                }
            }
        }
    }

    // Step 7: GC sections (approximate ld --gc-sections) by keeping only sections
    // reachable from _start via relocations.
    {
        int start_gi = find_global_sym(gs, ngs, "_start");
        if (start_gi < 0 || !gs[start_gi].defined) die("link-internal: missing _start symbol");

        int wcap = 0;
        for (int oi = 0; oi < nobj_paths; oi++) wcap += (int)ins[oi].eh->e_shnum;
        int *work_oi = (int *)monacc_malloc((mc_usize)wcap * sizeof(*work_oi));
        mc_u16 *work_si = (mc_u16 *)monacc_malloc((mc_usize)wcap * sizeof(*work_si));
        if (!work_oi || !work_si) die("oom");
        int wn = 0;

        // Root: section containing _start.
        {
            InputObj *def = &ins[gs[start_gi].obji];
            const Elf64_Sym *s = &def->symtab[gs[start_gi].symi];
            mc_u16 shndx = s->st_shndx;
            mark_keep(def, shndx);
            work_oi[wn] = gs[start_gi].obji;
            work_si[wn] = shndx;
            wn++;
        }

        // Traverse relocations out of kept sections and keep their defining sections.
        while (wn > 0) {
            wn--;
            int oi = work_oi[wn];
            mc_u16 si = work_si[wn];
            InputObj *in = &ins[oi];

            for (mc_u16 rsi = 0; rsi < in->nrelsecs; rsi++) {
                const Elf64_Shdr *rsh = &in->relsecs[rsi];
                if (rsh->sh_info != si) continue;
                if (rsh->sh_info >= in->eh->e_shnum) die("link-internal: bad relocation target section index");

                const Elf64_Rela *rels = (const Elf64_Rela *)checked_slice(in->file, in->file_len, rsh->sh_offset, rsh->sh_size, "rela");
                mc_usize nrel = (mc_usize)(rsh->sh_size / sizeof(Elf64_Rela));

                for (mc_usize i = 0; i < nrel; i++) {
                    mc_u32 rsym = elf64_r_sym(rels[i].r_info);
                    if (rsym >= (mc_u32)in->symtab_n) die("link-internal: bad relocation symbol index");
                    const Elf64_Sym *s = &in->symtab[rsym];

                    InputObj *def = NULL;
                    mc_u32 def_symi = 0;
                    if (s->st_shndx != SHN_UNDEF) {
                        def = in;
                        def_symi = rsym;
                    } else {
                        const char *nm = sym_name(in, rsym);
                        int gi = find_global_sym(gs, ngs, nm);
                        if (gi < 0 || !gs[gi].defined) {
                            die("link-internal: undefined symbol %s", nm && *nm ? nm : "<noname>");
                        }
                        def = &ins[gs[gi].obji];
                        def_symi = gs[gi].symi;
                    }

                    mc_u16 shndx = def->symtab[def_symi].st_shndx;
                    if (shndx == SHN_UNDEF || shndx == SHN_ABS) continue;
                    if (shndx >= def->eh->e_shnum) die("link-internal: bad symbol shndx");
                    if ((def->shdrs[shndx].sh_flags & SHF_ALLOC) == 0) continue;

                    if (!def->sec_keep[shndx]) {
                        def->sec_keep[shndx] = 1;
                        if (wn >= wcap) die("link-internal: internal error: gc work overflow");
                        work_oi[wn] = (int)(def - ins);
                        work_si[wn] = shndx;
                        wn++;
                    }
                }
            }
        }

        monacc_free(work_oi);
        monacc_free(work_si);
    }

    // Step 5: layout with separate RX and RW PT_LOAD segments.
    // RX holds headers + .text + .rodata (+ other non-writable alloc PROGBITS).
    // RW holds .data (+ other writable alloc PROGBITS) and .bss as memsz>filesz.
    const mc_u64 base_vaddr = 0x400000ull;

    // Avoid paying for a second program header when we don't have any RW content.
    // This matters for very small binaries like `true`/`false`.
    int want_rw = 0;
    for (int oi = 0; oi < nobj_paths && !want_rw; oi++) {
        InputObj *in = &ins[oi];
        for (mc_u16 si = 0; si < in->eh->e_shnum; si++) {
            const Elf64_Shdr *sh = &in->shdrs[si];
            if ((sh->sh_flags & SHF_ALLOC) == 0) continue;
            if (!in->sec_keep[si]) continue;
            if (sh->sh_flags & SHF_WRITE) {
                want_rw = 1;
                break;
            }
        }
    }

    mc_u16 phnum = (mc_u16)(want_rw ? 2 : 1);
    const mc_u64 hdr_end = (mc_u64)sizeof(Elf64_Ehdr) + (mc_u64)phnum * (mc_u64)sizeof(Elf64_Phdr);

    mc_u64 rx_file = hdr_end;
    mc_u64 rx_mem = hdr_end;

    // RX PROGBITS alloc sections in ranked order.
    for (int rank = 0; rank <= 3; rank++) {
        for (int oi = 0; oi < nobj_paths; oi++) {
            InputObj *in = &ins[oi];
            for (mc_u16 si = 0; si < in->eh->e_shnum; si++) {
                const Elf64_Shdr *sh = &in->shdrs[si];
                if ((sh->sh_flags & SHF_ALLOC) == 0) continue;
                if (!in->sec_keep[si]) continue;
                if (!sec_is_rx(sh)) continue;
                if (sh->sh_type == SHT_NOBITS) continue;
                if (sh->sh_size == 0) continue;
                const char *nm = "";
                if (sh->sh_name < (mc_u32)in->shstr_sz) nm = in->shstrtab + sh->sh_name;
                if (sec_rank(nm, sh->sh_flags) != rank) continue;

                mc_u64 align = sh->sh_addralign ? sh->sh_addralign : 1;
                rx_file = align_up_u64(rx_file, align);
                rx_mem = rx_file;
                in->sec_fileoff[si] = rx_file;
                in->sec_vaddr[si] = base_vaddr + rx_mem;
                rx_file += sh->sh_size;
                rx_mem = rx_file;
            }
        }
    }

    mc_u64 rx_file_end = rx_file;
    mc_u64 rx_mem_end = rx_mem;

    // Start RW segment aligned to page to satisfy p_offset%align == p_vaddr%align.
    mc_u64 rw_file_start = align_up_u64(rx_file_end, 0x1000ull);
    mc_u64 rw_mem_start = align_up_u64(rx_mem_end, 0x1000ull);
    mc_u64 rw_file = rw_file_start;
    mc_u64 rw_mem = rw_mem_start;

    int has_rw = 0;

    // RW PROGBITS alloc sections in ranked order (mostly .data*).
    for (int rank = 0; rank <= 3; rank++) {
        for (int oi = 0; oi < nobj_paths; oi++) {
            InputObj *in = &ins[oi];
            for (mc_u16 si = 0; si < in->eh->e_shnum; si++) {
                const Elf64_Shdr *sh = &in->shdrs[si];
                if ((sh->sh_flags & SHF_ALLOC) == 0) continue;
                if (!in->sec_keep[si]) continue;
                if (sec_is_rx(sh)) continue;
                if (sh->sh_type == SHT_NOBITS) continue;
                if (sh->sh_size == 0) continue;
                const char *nm = "";
                if (sh->sh_name < (mc_u32)in->shstr_sz) nm = in->shstrtab + sh->sh_name;
                if (sec_rank(nm, sh->sh_flags) != rank) continue;

                mc_u64 align = sh->sh_addralign ? sh->sh_addralign : 1;
                rw_file = align_up_u64(rw_file, align);
                rw_mem = rw_file; // keep file/mem in lockstep for PROGBITS
                in->sec_fileoff[si] = rw_file;
                in->sec_vaddr[si] = base_vaddr + (rw_mem_start + (rw_file - rw_file_start));
                rw_file += sh->sh_size;
                rw_mem = rw_file;
                has_rw = 1;
            }
        }
    }

    // RW NOBITS alloc sections (.bss*)
    for (int oi = 0; oi < nobj_paths; oi++) {
        InputObj *in = &ins[oi];
        for (mc_u16 si = 0; si < in->eh->e_shnum; si++) {
            const Elf64_Shdr *sh = &in->shdrs[si];
            if ((sh->sh_flags & SHF_ALLOC) == 0) continue;
            if (!in->sec_keep[si]) continue;
            if (sec_is_rx(sh)) continue;
            if (sh->sh_type != SHT_NOBITS) continue;
            if (sh->sh_size == 0) continue;
            mc_u64 align = sh->sh_addralign ? sh->sh_addralign : 1;
            rw_mem = align_up_u64(rw_mem, align);
            in->sec_fileoff[si] = 0;
            in->sec_vaddr[si] = base_vaddr + (rw_mem_start + (rw_mem - rw_file_start));
            rw_mem += sh->sh_size;
            has_rw = 1;
        }
    }

    mc_u64 rw_file_end = rw_file;
    mc_u64 rw_mem_end = rw_mem;

    // Resolve entrypoint (_start) using global map.
    mc_u64 entry = 0;
    {
        int idx = find_global_sym(gs, ngs, "_start");
        if (idx < 0 || !gs[idx].defined) die("link-internal: missing _start symbol");
        InputObj *def = &ins[gs[idx].obji];
        entry = sym_addr_in_obj(def, gs[idx].symi);
        if (entry == 0) die("link-internal: _start is undefined");
    }

    mc_u64 seg_file_end = has_rw ? rw_file_end : rx_file_end;
    // Note: for RX-only outputs, the memory image is just RX.
    unsigned char *out = (unsigned char *)monacc_calloc((mc_usize)seg_file_end, 1);
    if (!out) die("oom");

    // Copy allocated section contents.
    for (int oi = 0; oi < nobj_paths; oi++) {
        InputObj *in = &ins[oi];
        for (mc_u16 si = 0; si < in->eh->e_shnum; si++) {
            const Elf64_Shdr *sh = &in->shdrs[si];
            if ((sh->sh_flags & SHF_ALLOC) == 0) continue;
            if (!in->sec_keep[si]) continue;
            if (sh->sh_type == SHT_NOBITS) continue;
            if (sh->sh_size == 0) continue;
            mc_u64 dst_off = in->sec_fileoff[si];
            if (dst_off == 0) continue;
            if (dst_off + sh->sh_size > seg_file_end) die("link-internal: internal error: section overflow");
            const void *src = checked_slice(in->file, in->file_len, sh->sh_offset, sh->sh_size, "section data");
            mc_memcpy(out + (mc_usize)dst_off, src, (mc_usize)sh->sh_size);
        }
    }

    // Apply relocations.
    for (int oi = 0; oi < nobj_paths; oi++) {
        InputObj *in = &ins[oi];
        for (mc_u16 rsi = 0; rsi < in->nrelsecs; rsi++) {
            const Elf64_Shdr *rsh = &in->relsecs[rsi];
            if (rsh->sh_info >= in->eh->e_shnum) die("link-internal: bad relocation target section index");
            mc_u16 tgt = (mc_u16)rsh->sh_info;
            if (!in->sec_keep[tgt]) continue;
            const Elf64_Shdr *tsh = &in->shdrs[tgt];
            if ((tsh->sh_flags & SHF_ALLOC) == 0) continue;
            if (tsh->sh_type == SHT_NOBITS) die("link-internal: relocation against NOBITS target section");
            if (in->sec_vaddr[tgt] == 0 || in->sec_fileoff[tgt] == 0) die("link-internal: relocation target section not mapped");

            const Elf64_Rela *rels = (const Elf64_Rela *)checked_slice(in->file, in->file_len, rsh->sh_offset, rsh->sh_size, "rela");
            mc_usize nrel = (mc_usize)(rsh->sh_size / sizeof(Elf64_Rela));

            for (mc_usize i = 0; i < nrel; i++) {
                mc_u32 rtype = elf64_r_type(rels[i].r_info);
                mc_u32 rsym = elf64_r_sym(rels[i].r_info);
                if (rsym >= (mc_u32)in->symtab_n) die("link-internal: bad relocation symbol index");

                const Elf64_Sym *s = &in->symtab[rsym];
                const char *nm = sym_name(in, rsym);
                mc_u64 S = 0;

                if (s->st_shndx != SHN_UNDEF) {
                    S = sym_addr_in_obj(in, rsym);
                } else {
                    int gi = find_global_sym(gs, ngs, nm);
                    if (gi < 0 || !gs[gi].defined) {
                        die("link-internal: undefined symbol %s", nm && *nm ? nm : "<noname>");
                    }
                    InputObj *def = &ins[gs[gi].obji];
                    S = sym_addr_in_obj(def, gs[gi].symi);
                }

                mc_u64 P = in->sec_vaddr[tgt] + rels[i].r_offset;
                mc_u64 out_off = in->sec_fileoff[tgt] + rels[i].r_offset;

                if (rels[i].r_offset + 4 > tsh->sh_size) die("link-internal: relocation overflows target section");
                if (out_off + 4 > seg_file_end) die("link-internal: relocation overflows output image");

                if (rtype == R_X86_64_PC32 || rtype == R_X86_64_PLT32) {
                    mc_i64 disp = (mc_i64)((mc_i64)S + (mc_i64)rels[i].r_addend - (mc_i64)P);
                    mc_i64 pc32_min = -((mc_i64)1 << 31);
                    mc_i64 pc32_max = (((mc_i64)1 << 31) - 1);
                    if (disp < pc32_min || disp > pc32_max) {
                        const char *tgt_nm = "";
                        if (tsh->sh_name < (mc_u32)in->shstr_sz) tgt_nm = in->shstrtab + tsh->sh_name;

#ifdef SELFHOST
                        char nbuf[64];
                        xwrite_best_effort(2, "link-internal: PC32 relocation overflow: obj=", 45);
                        xwrite_best_effort(2, in->path ? in->path : "<obj>", mc_strlen(in->path ? in->path : "<obj>"));
                        xwrite_best_effort(2, " sec=", 5);
                        xwrite_best_effort(2, (tgt_nm && *tgt_nm) ? tgt_nm : "<sec>", mc_strlen((tgt_nm && *tgt_nm) ? tgt_nm : "<sec>"));
                        xwrite_best_effort(2, " off=", 5);
                        {
                            int nn = mc_snprint_cstr_u64_cstr(nbuf, sizeof(nbuf), "", (mc_u64)rels[i].r_offset, "");
                            if (nn > 0) xwrite_best_effort(2, nbuf, (mc_usize)nn);
                        }
                        xwrite_best_effort(2, " sym=", 5);
                        xwrite_best_effort(2, (nm && *nm) ? nm : "<sym>", mc_strlen((nm && *nm) ? nm : "<sym>"));
                        xwrite_best_effort(2, " S=", 3);
                        {
                            int nn = mc_snprint_cstr_u64_cstr(nbuf, sizeof(nbuf), "", (mc_u64)S, "");
                            if (nn > 0) xwrite_best_effort(2, nbuf, (mc_usize)nn);
                        }
                        xwrite_best_effort(2, " P=", 3);
                        {
                            int nn = mc_snprint_cstr_u64_cstr(nbuf, sizeof(nbuf), "", (mc_u64)P, "");
                            if (nn > 0) xwrite_best_effort(2, nbuf, (mc_usize)nn);
                        }
                        xwrite_best_effort(2, " add=", 5);
                        {
                            int nn = mc_snprint_cstr_i64_cstr(nbuf, sizeof(nbuf), "", (mc_i64)rels[i].r_addend, "");
                            if (nn > 0) xwrite_best_effort(2, nbuf, (mc_usize)nn);
                        }
                        xwrite_best_effort(2, " disp=", 6);
                        {
                            int nn = mc_snprint_cstr_i64_cstr(nbuf, sizeof(nbuf), "", (mc_i64)disp, "");
                            if (nn > 0) xwrite_best_effort(2, nbuf, (mc_usize)nn);
                        }
                        xwrite_best_effort(2, "\n", 1);
                        die("link-internal: PC32 relocation overflow");
#else
                        die("link-internal: PC32 relocation overflow: obj=%s sec=%s off=0x%llx sym=%s S=0x%llx P=0x%llx add=%lld disp=%lld",
                            in->path ? in->path : "<obj>",
                            (tgt_nm && *tgt_nm) ? tgt_nm : "<sec>",
                            (unsigned long long)rels[i].r_offset,
                            (nm && *nm) ? nm : "<sym>",
                            (unsigned long long)S,
                            (unsigned long long)P,
                            (long long)rels[i].r_addend,
                            (long long)disp);
#endif
                    }
                    put_u32_le(out + (mc_usize)out_off, (mc_u32)(mc_i32)disp);
                } else {
                    die("link-internal: unsupported relocation type");
                }
            }
        }
    }

    // Optionally append section headers and shstrtab for debugging.
    mc_u64 out_len = seg_file_end;
    mc_u64 shoff = 0;
    mc_u16 shnum = 0;
    mc_u16 shstrndx = 0;

    if (keep_shdr) {
        // Compute coarse output section ranges.
        mc_u64 text_off_min = (mc_u64)-1, text_off_max = 0;
        mc_u64 ro_off_min = (mc_u64)-1, ro_off_max = 0;
        mc_u64 data_off_min = (mc_u64)-1, data_off_max = 0;
        mc_u64 text_addr_min = (mc_u64)-1, text_addr_max = 0;
        mc_u64 ro_addr_min = (mc_u64)-1, ro_addr_max = 0;
        mc_u64 data_addr_min = (mc_u64)-1, data_addr_max = 0;
        mc_u64 bss_addr_min = (mc_u64)-1, bss_addr_max = 0;

        for (int oi = 0; oi < nobj_paths; oi++) {
            InputObj *in = &ins[oi];
            for (mc_u16 si = 0; si < in->eh->e_shnum; si++) {
                const Elf64_Shdr *sh = &in->shdrs[si];
                if ((sh->sh_flags & SHF_ALLOC) == 0) continue;
                if (sh->sh_size == 0) continue;

                mc_u64 addr0 = in->sec_vaddr[si];
                if (addr0 == 0) continue;
                mc_u64 addr1 = addr0 + sh->sh_size;

                if (sh->sh_type == SHT_NOBITS) {
                    if (addr0 < bss_addr_min) bss_addr_min = addr0;
                    if (addr1 > bss_addr_max) bss_addr_max = addr1;
                    continue;
                }

                mc_u64 off0 = in->sec_fileoff[si];
                if (off0 == 0) continue;
                mc_u64 off1 = off0 + sh->sh_size;

                if (sh->sh_flags & SHF_EXECINSTR) {
                    if (off0 < text_off_min) text_off_min = off0;
                    if (off1 > text_off_max) text_off_max = off1;
                    if (addr0 < text_addr_min) text_addr_min = addr0;
                    if (addr1 > text_addr_max) text_addr_max = addr1;
                } else if (sh->sh_flags & SHF_WRITE) {
                    if (off0 < data_off_min) data_off_min = off0;
                    if (off1 > data_off_max) data_off_max = off1;
                    if (addr0 < data_addr_min) data_addr_min = addr0;
                    if (addr1 > data_addr_max) data_addr_max = addr1;
                } else {
                    if (off0 < ro_off_min) ro_off_min = off0;
                    if (off1 > ro_off_max) ro_off_max = off1;
                    if (addr0 < ro_addr_min) ro_addr_min = addr0;
                    if (addr1 > ro_addr_max) ro_addr_max = addr1;
                }
            }
        }

        // Build shstrtab.
        char shstr[256];
        mc_usize shstr_len = 0;
        shstr[shstr_len++] = 0; // null

        // We emit: NULL, .text?, .rodata?, .data?, .bss?, .shstrtab
        Elf64_Shdr shdr_out[8];
        mc_memset(shdr_out, 0, sizeof(shdr_out));
        int idx = 1; // [0] NULL

        mc_u32 nm_text = 0, nm_ro = 0, nm_data = 0, nm_bss = 0, nm_shstr = 0;
        if (text_off_min != (mc_u64)-1 && text_off_max > text_off_min) nm_text = shstr_add(shstr, sizeof(shstr), &shstr_len, ".text");
        if (ro_off_min != (mc_u64)-1 && ro_off_max > ro_off_min) nm_ro = shstr_add(shstr, sizeof(shstr), &shstr_len, ".rodata");
        if (data_off_min != (mc_u64)-1 && data_off_max > data_off_min) nm_data = shstr_add(shstr, sizeof(shstr), &shstr_len, ".data");
        if (bss_addr_min != (mc_u64)-1 && bss_addr_max > bss_addr_min) nm_bss = shstr_add(shstr, sizeof(shstr), &shstr_len, ".bss");
        nm_shstr = shstr_add(shstr, sizeof(shstr), &shstr_len, ".shstrtab");

        if (nm_text) {
            Elf64_Shdr *s = &shdr_out[idx++];
            s->sh_name = nm_text;
            s->sh_type = SHT_PROGBITS;
            s->sh_flags = SHF_ALLOC | SHF_EXECINSTR;
            s->sh_addr = text_addr_min;
            s->sh_offset = text_off_min;
            s->sh_size = text_addr_max - text_addr_min;
            s->sh_addralign = 16;
        }
        if (nm_ro) {
            Elf64_Shdr *s = &shdr_out[idx++];
            s->sh_name = nm_ro;
            s->sh_type = SHT_PROGBITS;
            s->sh_flags = SHF_ALLOC;
            s->sh_addr = ro_addr_min;
            s->sh_offset = ro_off_min;
            s->sh_size = ro_addr_max - ro_addr_min;
            s->sh_addralign = 16;
        }
        if (nm_data) {
            Elf64_Shdr *s = &shdr_out[idx++];
            s->sh_name = nm_data;
            s->sh_type = SHT_PROGBITS;
            s->sh_flags = SHF_ALLOC | SHF_WRITE;
            s->sh_addr = data_addr_min;
            s->sh_offset = data_off_min;
            s->sh_size = data_addr_max - data_addr_min;
            s->sh_addralign = 8;
        }
        if (nm_bss) {
            Elf64_Shdr *s = &shdr_out[idx++];
            s->sh_name = nm_bss;
            s->sh_type = SHT_NOBITS;
            s->sh_flags = SHF_ALLOC | SHF_WRITE;
            s->sh_addr = bss_addr_min;
            s->sh_offset = 0;
            s->sh_size = bss_addr_max - bss_addr_min;
            s->sh_addralign = 8;
        }

        // Append shstrtab and section headers at end of file.
        mc_u64 shstr_off = out_len;
        shoff = align_up_u64(shstr_off + (mc_u64)shstr_len, 8);

        // shstrtab section header.
        {
            Elf64_Shdr *s = &shdr_out[idx++];
            s->sh_name = nm_shstr;
            s->sh_type = SHT_STRTAB;
            s->sh_flags = 0;
            s->sh_addr = 0;
            s->sh_offset = shstr_off;
            s->sh_size = (mc_u64)shstr_len;
            s->sh_addralign = 1;
        }

        out_len = shoff + (mc_u64)idx * (mc_u64)sizeof(Elf64_Shdr);

        unsigned char *nr = (unsigned char *)monacc_realloc(out, (mc_usize)out_len);
        if (!nr) die("oom");
        out = nr;
        mc_memset(out + (mc_usize)seg_file_end, 0, (mc_usize)(out_len - seg_file_end));

        mc_memcpy(out + (mc_usize)shstr_off, shstr, shstr_len);
        mc_memcpy(out + (mc_usize)shoff, shdr_out, (mc_usize)idx * sizeof(Elf64_Shdr));

        shnum = (mc_u16)idx;
        shstrndx = (mc_u16)(idx - 1);
    }

    // Write ELF header + program headers.
    {
        Elf64_Ehdr eh;
        mc_memset(&eh, 0, sizeof(eh));
        eh.e_ident[0] = 0x7f;
        eh.e_ident[1] = 'E';
        eh.e_ident[2] = 'L';
        eh.e_ident[3] = 'F';
        eh.e_ident[4] = ELFCLASS64;
        eh.e_ident[5] = ELFDATA2LSB;
        eh.e_ident[6] = EV_CURRENT;
        eh.e_type = ET_EXEC;
        eh.e_machine = EM_X86_64;
        eh.e_version = EV_CURRENT;
        eh.e_entry = entry;
        eh.e_phoff = (mc_u64)sizeof(Elf64_Ehdr);
        eh.e_ehsize = (mc_u16)sizeof(Elf64_Ehdr);
        eh.e_phentsize = (mc_u16)sizeof(Elf64_Phdr);
        eh.e_phnum = (mc_u16)(has_rw ? 2 : 1);

        if (keep_shdr) {
            eh.e_shoff = shoff;
            eh.e_shentsize = (mc_u16)sizeof(Elf64_Shdr);
            eh.e_shnum = shnum;
            eh.e_shstrndx = shstrndx;
        }

        Elf64_Phdr ph[2];
        mc_memset(ph, 0, sizeof(ph));

        // RX segment includes headers and RX section bytes.
        ph[0].p_type = PT_LOAD;
        ph[0].p_flags = PF_R | PF_X;
        ph[0].p_offset = 0;
        ph[0].p_vaddr = base_vaddr;
        ph[0].p_paddr = base_vaddr;
        ph[0].p_filesz = rx_file_end;
        ph[0].p_memsz = rx_mem_end;
        ph[0].p_align = 0x1000ull;

        if (has_rw) {
            ph[1].p_type = PT_LOAD;
            ph[1].p_flags = PF_R | PF_W;
            ph[1].p_offset = rw_file_start;
            ph[1].p_vaddr = base_vaddr + rw_mem_start;
            ph[1].p_paddr = base_vaddr + rw_mem_start;
            ph[1].p_filesz = rw_file_end - rw_file_start;
            ph[1].p_memsz = rw_mem_end - rw_mem_start;
            ph[1].p_align = 0x1000ull;
        }

        mc_memcpy(out, &eh, sizeof(eh));
        mc_memcpy(out + sizeof(eh), ph, (mc_usize)eh.e_phnum * sizeof(Elf64_Phdr));
    }

    write_file_mode(out_path, out, (mc_usize)out_len, 0755);

    monacc_free(out);
    if (gs) monacc_free(gs);
    for (int i = 0; i < nobj_paths; i++) {
        input_obj_free(&ins[i]);
    }
    monacc_free(ins);
}

void link_internal_exec_single_obj(const char *obj_path, const char *out_path) {
    link_internal_exec_objs(&obj_path, 1, out_path, 0);
}
