#include "mc.h"

// matrixstat: scan bin/*_*/TOOL ELF64 files and count a handful of x86_64 opcode patterns
// (push/pop/call/jcc/jmp/ret/setcc/movsxd/syscall) from executable PROGBITS sections.
//
// This is intentionally not a full disassembler: it’s a cheap, stable heuristic
// to spot codegen-shape deltas across the compiler matrix.

#define DT_DIR 4
#define DT_REG 8

#ifndef PROT_READ
#define PROT_READ 0x1
#endif
#ifndef MAP_PRIVATE
#define MAP_PRIVATE 0x02
#endif

#define EI_NIDENT 16

struct elf64_ehdr {
    mc_u8 e_ident[EI_NIDENT];
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
};

struct elf64_shdr {
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
};

struct elf64_phdr {
    mc_u32 p_type;
    mc_u32 p_flags;
    mc_u64 p_offset;
    mc_u64 p_vaddr;
    mc_u64 p_paddr;
    mc_u64 p_filesz;
    mc_u64 p_memsz;
    mc_u64 p_align;
};

#define SHT_PROGBITS 1u
#define SHF_EXECINSTR 0x4u

#define PT_LOAD 1u
#define PF_X 0x1u

struct stats {
    mc_u64 n_files;
    mc_u64 n_ok;
    mc_u64 n_err;

    mc_u64 file_bytes;
    mc_u64 text_bytes;

    mc_u64 push;
    mc_u64 pop;
    mc_u64 call;
    mc_u64 indirect_call;
    mc_u64 ret;
    mc_u64 leave;
    mc_u64 jcc;
    mc_u64 jmp;
    mc_u64 setcc;
    mc_u64 movsxd;
    mc_u64 syscall;

    // More actionable “compiler quality” signals.
    mc_u64 prologue_fp;    // push rbp; mov rbp,rsp
    mc_u64 stack_sub;      // sub rsp, imm
    mc_u64 stack_add;      // add rsp, imm
    mc_u64 stack_load;     // mov/load from [rsp+disp]
    mc_u64 stack_store;    // mov/store to [rsp+disp]
    mc_u64 xor_zero;       // xor reg, reg
    mc_u64 mov_imm0;       // mov reg, 0
    mc_u64 lea;            // lea usage
};

typedef enum {
    MF_NONE = 0,
    MF_FILE_BYTES,
    MF_TEXT_BYTES,
    MF_PUSH,
    MF_POP,
    MF_CALL,
    MF_INDIRECT_CALL,
    MF_RET,
    MF_LEAVE,
    MF_JCC,
    MF_JMP,
    MF_SETCC,
    MF_MOVSXD,
    MF_SYSCALL,

    MF_PROLOGUE_FP,
    MF_STACK_SUB,
    MF_STACK_ADD,
    MF_STACK_LOAD,
    MF_STACK_STORE,
    MF_XOR_ZERO,
    MF_MOV_IMM0,
    MF_LEA,
} MetricField;

static mc_u64 metric_get(const struct stats *s, MetricField f) {
    switch (f) {
        case MF_FILE_BYTES: return s->file_bytes;
        case MF_TEXT_BYTES: return s->text_bytes;
        case MF_PUSH: return s->push;
        case MF_POP: return s->pop;
        case MF_CALL: return s->call;
        case MF_INDIRECT_CALL: return s->indirect_call;
        case MF_RET: return s->ret;
        case MF_LEAVE: return s->leave;
        case MF_JCC: return s->jcc;
        case MF_JMP: return s->jmp;
        case MF_SETCC: return s->setcc;
        case MF_MOVSXD: return s->movsxd;
        case MF_SYSCALL: return s->syscall;

        case MF_PROLOGUE_FP: return s->prologue_fp;
        case MF_STACK_SUB: return s->stack_sub;
        case MF_STACK_ADD: return s->stack_add;
        case MF_STACK_LOAD: return s->stack_load;
        case MF_STACK_STORE: return s->stack_store;
        case MF_XOR_ZERO: return s->xor_zero;
        case MF_MOV_IMM0: return s->mov_imm0;
        case MF_LEA: return s->lea;
        case MF_NONE:
        default: return 0;
    }
}

static mc_u64 metric_score(const struct stats *s, MetricField f, int ratio_mode) {
    mc_u64 v = metric_get(s, f);
    if (!ratio_mode) return v;
    // Density score: events per text byte, scaled to avoid floating point.
    // Score units: per 1,000,000 bytes (ppm-ish).
    if (s->text_bytes == 0) return 0;
    if (v > (mc_u64)(~(mc_u64)0) / 1000000ULL) return (mc_u64)(~(mc_u64)0);
    return (v * 1000000ULL) / s->text_bytes;
}

static MetricField metric_parse(const char *s) {
    if (!s || !s[0]) return MF_NONE;
    if (mc_streq(s, "file_bytes")) return MF_FILE_BYTES;
    if (mc_streq(s, "text_bytes")) return MF_TEXT_BYTES;
    if (mc_streq(s, "push")) return MF_PUSH;
    if (mc_streq(s, "pop")) return MF_POP;
    if (mc_streq(s, "call")) return MF_CALL;
    if (mc_streq(s, "icall") || mc_streq(s, "indirect_call")) return MF_INDIRECT_CALL;
    if (mc_streq(s, "ret")) return MF_RET;
    if (mc_streq(s, "leave")) return MF_LEAVE;
    if (mc_streq(s, "jcc")) return MF_JCC;
    if (mc_streq(s, "jmp")) return MF_JMP;
    if (mc_streq(s, "setcc")) return MF_SETCC;
    if (mc_streq(s, "movsxd")) return MF_MOVSXD;
    if (mc_streq(s, "syscall")) return MF_SYSCALL;

    if (mc_streq(s, "prologue_fp")) return MF_PROLOGUE_FP;
    if (mc_streq(s, "stack_sub")) return MF_STACK_SUB;
    if (mc_streq(s, "stack_add")) return MF_STACK_ADD;
    if (mc_streq(s, "stack_load")) return MF_STACK_LOAD;
    if (mc_streq(s, "stack_store")) return MF_STACK_STORE;
    if (mc_streq(s, "xor_zero")) return MF_XOR_ZERO;
    if (mc_streq(s, "mov_imm0")) return MF_MOV_IMM0;
    if (mc_streq(s, "lea")) return MF_LEA;
    return MF_NONE;
}

struct stats_row {
    char tool[64];
    struct stats s;
};

static void sort_rows_desc(struct stats_row *rows, mc_u32 n, MetricField f, int ratio_mode);

static void stats_add(struct stats *dst, const struct stats *src) {
    dst->n_files += src->n_files;
    dst->n_ok += src->n_ok;
    dst->n_err += src->n_err;

    dst->file_bytes += src->file_bytes;
    dst->text_bytes += src->text_bytes;
    dst->push += src->push;
    dst->pop += src->pop;
    dst->call += src->call;
    dst->indirect_call += src->indirect_call;
    dst->ret += src->ret;
    dst->leave += src->leave;
    dst->jcc += src->jcc;
    dst->jmp += src->jmp;
    dst->setcc += src->setcc;
    dst->movsxd += src->movsxd;
    dst->syscall += src->syscall;

    dst->prologue_fp += src->prologue_fp;
    dst->stack_sub += src->stack_sub;
    dst->stack_add += src->stack_add;
    dst->stack_load += src->stack_load;
    dst->stack_store += src->stack_store;
    dst->xor_zero += src->xor_zero;
    dst->mov_imm0 += src->mov_imm0;
    dst->lea += src->lea;
}

static mc_u64 ppm_u64(mc_u64 v, mc_u64 denom) {
    if (denom == 0) return 0;
    if (v > (mc_u64)(~(mc_u64)0) / 1000000ULL) return (mc_u64)(~(mc_u64)0);
    return (v * 1000000ULL) / denom;
}

static int all_zero_bytes(const mc_u8 *p, mc_usize n) {
    for (mc_usize i = 0; i < n; i++) {
        if (p[i] != 0) return 0;
    }
    return 1;
}

static int is_rsp_sib_mem(mc_u8 modrm, mc_u8 sib) {
    mc_u8 mod = (modrm >> 6) & 3u;
    mc_u8 rm = modrm & 7u;
    if (mod == 3u) return 0;
    if (rm != 4u) return 0; // needs SIB
    mc_u8 base = sib & 7u;
    return base == 4u; // rsp
}

static int is_dirname_matrix(const char *name) {
    // Match gcc_15_ / clang_20_ / monacc_ etc.
    mc_usize n = mc_strlen(name);
    if (n < 2) return 0;
    return name[n - 1] == '_';
}

static void scan_exec_bytes(const mc_u8 *p, mc_usize n, struct stats *out) {
    out->text_bytes += (mc_u64)n;

    for (mc_usize i = 0; i < n; i++) {
        // Frame-pointer prologue: 55 48 89 E5
        if (i + 3 < n && p[i] == 0x55 && p[i + 1] == 0x48 && p[i + 2] == 0x89 && p[i + 3] == 0xE5) {
            out->prologue_fp++;
            i += 3;
            continue;
        }

        // syscall: 0F 05
        if (p[i] == 0x0F && i + 1 < n && p[i + 1] == 0x05) {
            out->syscall++;
            i += 1;
            continue;
        }

        // leave
        if (p[i] == 0xC9) {
            out->leave++;
            continue;
        }

        // Stack adjust: sub/add rsp, imm
        if (i + 3 < n && p[i] == 0x48 && p[i + 1] == 0x83 && p[i + 2] == 0xEC) {
            out->stack_sub++;
            i += 3;
            continue;
        }
        if (i + 6 < n && p[i] == 0x48 && p[i + 1] == 0x81 && p[i + 2] == 0xEC) {
            out->stack_sub++;
            i += 6;
            continue;
        }
        if (i + 3 < n && p[i] == 0x48 && p[i + 1] == 0x83 && p[i + 2] == 0xC4) {
            out->stack_add++;
            i += 3;
            continue;
        }
        if (i + 6 < n && p[i] == 0x48 && p[i + 1] == 0x81 && p[i + 2] == 0xC4) {
            out->stack_add++;
            i += 6;
            continue;
        }

        // Indirect call: FF /2
        if (p[i] == 0xFF && i + 1 < n) {
            mc_u8 modrm = p[i + 1];
            mc_u8 reg = (modrm >> 3) & 7u;
            if (reg == 2u) {
                out->indirect_call++;
                i += 1;
                continue;
            }
        }

        // lea (with/without REX prefix)
        if (p[i] == 0x8D) {
            out->lea++;
            continue;
        }
        if (p[i] >= 0x40 && p[i] <= 0x4F && i + 1 < n && p[i + 1] == 0x8D) {
            out->lea++;
            i += 1;
            continue;
        }

        // xor reg, reg (with/without REX prefix)
        if ((p[i] == 0x31 || p[i] == 0x33) && i + 1 < n) {
            mc_u8 modrm = p[i + 1];
            mc_u8 mod = (modrm >> 6) & 3u;
            mc_u8 reg = (modrm >> 3) & 7u;
            mc_u8 rm = modrm & 7u;
            if (mod == 3u && reg == rm) {
                out->xor_zero++;
                i += 1;
                continue;
            }
        }
        if (p[i] >= 0x40 && p[i] <= 0x4F && i + 2 < n && (p[i + 1] == 0x31 || p[i + 1] == 0x33)) {
            mc_u8 modrm = p[i + 2];
            mc_u8 mod = (modrm >> 6) & 3u;
            mc_u8 reg = (modrm >> 3) & 7u;
            mc_u8 rm = modrm & 7u;
            if (mod == 3u && reg == rm) {
                out->xor_zero++;
                i += 2;
                continue;
            }
        }

        // mov reg, 0 (B8+r imm32/imm64)
        if (p[i] >= 0xB8 && p[i] <= 0xBF) {
            // imm32
            if (i + 4 < n && all_zero_bytes(&p[i + 1], 4)) {
                out->mov_imm0++;
                i += 4;
                continue;
            }
        }
        if (p[i] >= 0x40 && p[i] <= 0x4F && i + 1 < n && p[i + 1] >= 0xB8 && p[i + 1] <= 0xBF) {
            mc_u8 rex = p[i];
            int w = (rex & 0x08) != 0;
            mc_usize imm_len = w ? 8u : 4u;
            if (i + 1 + imm_len < n && all_zero_bytes(&p[i + 2], imm_len)) {
                out->mov_imm0++;
                i += 1 + imm_len;
                continue;
            }
        }

        // Stack slot traffic proxy: mov/load/store involving [rsp+disp]
        // (minimal ModRM+SIB handling; counts only common mov forms).
        {
            mc_usize j = i;
            mc_u8 rex = 0;
            if (j < n && p[j] >= 0x40 && p[j] <= 0x4F) {
                rex = p[j];
                (void)rex;
                j++;
            }
            if (j < n) {
                mc_u8 op = p[j];
                int is_load = (op == 0x8A || op == 0x8B);
                int is_store = (op == 0x88 || op == 0x89);
                if ((is_load || is_store) && j + 2 < n) {
                    mc_u8 modrm = p[j + 1];
                    mc_u8 rm = modrm & 7u;
                    mc_u8 mod = (modrm >> 6) & 3u;
                    if (mod != 3u && rm == 4u) {
                        mc_u8 sib = p[j + 2];
                        if (is_rsp_sib_mem(modrm, sib)) {
                            if (is_load) out->stack_load++; else out->stack_store++;
                            mc_usize disp = 0;
                            if (mod == 1u) disp = 1;
                            else if (mod == 2u) disp = 4;
                            // Skip over the instruction bytes we know about.
                            mc_usize len = (j - i) + 1 + 1 + 1 + disp;
                            if (len > 0) i += (len - 1);
                            continue;
                        }
                    }
                }
            }
        }

        // REX-prefix forms we care about.
        if (p[i] == 0x41 && i + 1 < n) {
            mc_u8 b = p[i + 1];
            if (b >= 0x50 && b <= 0x57) {
                out->push++;
                i += 1;
                continue;
            }
            if (b >= 0x58 && b <= 0x5F) {
                out->pop++;
                i += 1;
                continue;
            }
        }

        // movsxd r64, r/m32 (aka movslq): REX.W + 63 /r
        if (p[i] >= 0x48 && p[i] <= 0x4F && i + 1 < n && p[i + 1] == 0x63) {
            out->movsxd++;
            i += 1;
            continue;
        }

        // setcc: [optional REX] 0F 90..9F /r
        if (p[i] >= 0x40 && p[i] <= 0x4F) {
            if (i + 2 < n && p[i + 1] == 0x0F && (p[i + 2] & 0xF0u) == 0x90u) {
                out->setcc++;
                i += 2;
                continue;
            }
        }
        if (p[i] == 0x0F && i + 1 < n && (p[i + 1] & 0xF0u) == 0x90u) {
            out->setcc++;
            i += 1;
            continue;
        }

        // jcc: 0F 8? imm32  (6 bytes), or 7? imm8 (2 bytes)
        if (p[i] == 0x0F && i + 1 < n && (p[i + 1] & 0xF0u) == 0x80u) {
            out->jcc++;
            // Skip imm32 if present.
            if (i + 5 < n) i += 5;
            continue;
        }
        if (p[i] >= 0x70 && p[i] <= 0x7F) {
            out->jcc++;
            if (i + 1 < n) i += 1;
            continue;
        }

        // call rel32: E8 imm32
        if (p[i] == 0xE8) {
            out->call++;
            if (i + 4 < n) i += 4;
            continue;
        }

        // jmp: E9 imm32 or EB imm8
        if (p[i] == 0xE9) {
            out->jmp++;
            if (i + 4 < n) i += 4;
            continue;
        }
        if (p[i] == 0xEB) {
            out->jmp++;
            if (i + 1 < n) i += 1;
            continue;
        }

        // ret: C3 or C2 imm16
        if (p[i] == 0xC3) {
            out->ret++;
            continue;
        }
        if (p[i] == 0xC2) {
            out->ret++;
            if (i + 2 < n) i += 2;
            continue;
        }

        // push/pop reg: 50..57, 58..5F
        if (p[i] >= 0x50 && p[i] <= 0x57) {
            out->push++;
            continue;
        }
        if (p[i] >= 0x58 && p[i] <= 0x5F) {
            out->pop++;
            continue;
        }

        // movsxd without an explicit REX.W prefix (rare): 63 /r
        if (p[i] == 0x63) {
            out->movsxd++;
            continue;
        }
    }
}

static int analyze_elf_fd(mc_i32 fd, struct stats *out) {
    struct mc_stat st;
    mc_i64 rc = mc_sys_fstat(fd, &st);
    if (rc < 0) return 0;
    if (st.st_size <= 0) return 0;

    out->file_bytes = (mc_u64)st.st_size;

    mc_i64 map = mc_sys_mmap(0, (mc_usize)st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (map < 0) return 0;

    const mc_u8 *base = (const mc_u8 *)(mc_usize)map;
    if ((mc_usize)st.st_size < sizeof(struct elf64_ehdr)) return 0;

    const struct elf64_ehdr *eh = (const struct elf64_ehdr *)base;
    if (!(eh->e_ident[0] == 0x7f && eh->e_ident[1] == 'E' && eh->e_ident[2] == 'L' && eh->e_ident[3] == 'F')) return 0;
    // EI_CLASS=2 (ELF64), EI_DATA=1 (little)
    if (eh->e_ident[4] != 2) return 0;
    if (eh->e_ident[5] != 1) return 0;

    int scanned_any = 0;

    // Prefer section headers when they exist (gcc/clang typically keep them).
    // monacc intentionally produces section-header-less ELFs to reduce size.
    if (eh->e_shoff && eh->e_shnum && eh->e_shentsize == (mc_u16)sizeof(struct elf64_shdr)) {
        mc_u64 shoff = eh->e_shoff;
        mc_u16 shnum = eh->e_shnum;
        mc_u64 sht_bytes = (mc_u64)eh->e_shentsize * (mc_u64)shnum;
        if (shoff + sht_bytes <= (mc_u64)st.st_size) {
            const struct elf64_shdr *sh = (const struct elf64_shdr *)(base + (mc_usize)shoff);
            for (mc_u16 i = 0; i < shnum; i++) {
                if (sh[i].sh_type != SHT_PROGBITS) continue;
                if ((sh[i].sh_flags & (mc_u64)SHF_EXECINSTR) == 0) continue;
                if (sh[i].sh_size == 0) continue;
                if (sh[i].sh_offset + sh[i].sh_size > (mc_u64)st.st_size) continue;
                scan_exec_bytes(base + (mc_usize)sh[i].sh_offset, (mc_usize)sh[i].sh_size, out);
                scanned_any = 1;
            }
        }
    }

    // Fallback: scan executable LOAD segments (what the kernel uses).
    // Note: for monacc's minimal layout this includes more than just .text.
    if (!scanned_any) {
        mc_u64 phoff = eh->e_phoff;
        mc_u16 phentsize = eh->e_phentsize;
        mc_u16 phnum = eh->e_phnum;

        if (phoff && phnum && phentsize == (mc_u16)sizeof(struct elf64_phdr)) {
            mc_u64 pht_bytes = (mc_u64)phentsize * (mc_u64)phnum;
            if (phoff + pht_bytes <= (mc_u64)st.st_size) {
                const struct elf64_phdr *ph = (const struct elf64_phdr *)(base + (mc_usize)phoff);
                for (mc_u16 i = 0; i < phnum; i++) {
                    if (ph[i].p_type != (mc_u32)PT_LOAD) continue;
                    if ((ph[i].p_flags & (mc_u32)PF_X) == 0) continue;
                    if (ph[i].p_filesz == 0) continue;
                    if (ph[i].p_offset + ph[i].p_filesz > (mc_u64)st.st_size) continue;
                    scan_exec_bytes(base + (mc_usize)ph[i].p_offset, (mc_usize)ph[i].p_filesz, out);
                    scanned_any = 1;
                }
            }
        }
    }

    (void)mc_sys_munmap((void *)(mc_usize)map, (mc_usize)st.st_size);
    return scanned_any;
}

static void write_u64_field(mc_u64 v) {
    (void)mc_write_u64_dec(1, v);
    (void)mc_write_str(1, "\t");
}

static void print_header(void) {
    mc_write_str(1,
        "compiler\ttool\tn_files\tn_ok\tn_err\tfile_bytes\ttext_bytes\t"
        "push\tpop\tcall\ticall\tret\tleave\tjcc\tjmp\tsetcc\tmovsxd\tsyscall\t"
        "prologue_fp\tstack_sub\tstack_add\tstack_load\tstack_store\txor_zero\tmov_imm0\tlea\t"
        "push_ppm\tcall_ppm\tsetcc_ppm\tmovsxd_ppm\n");
}

static void print_row(const char *compiler, const char *tool, const struct stats *s) {
    mc_write_str(1, compiler);
    mc_write_str(1, "\t");
    mc_write_str(1, tool);
    mc_write_str(1, "\t");

    write_u64_field(s->n_files);
    write_u64_field(s->n_ok);
    write_u64_field(s->n_err);

    write_u64_field(s->file_bytes);
    write_u64_field(s->text_bytes);
    write_u64_field(s->push);
    write_u64_field(s->pop);
    write_u64_field(s->call);
    write_u64_field(s->indirect_call);
    write_u64_field(s->ret);
    write_u64_field(s->leave);
    write_u64_field(s->jcc);
    write_u64_field(s->jmp);
    write_u64_field(s->setcc);
    write_u64_field(s->movsxd);

    write_u64_field(s->syscall);

    write_u64_field(s->prologue_fp);
    write_u64_field(s->stack_sub);
    write_u64_field(s->stack_add);
    write_u64_field(s->stack_load);
    write_u64_field(s->stack_store);
    write_u64_field(s->xor_zero);
    write_u64_field(s->mov_imm0);
    write_u64_field(s->lea);

    // Derived densities (ppm-ish): events per 1,000,000 text bytes.
    write_u64_field(ppm_u64(s->push, s->text_bytes));
    write_u64_field(ppm_u64(s->call, s->text_bytes));
    write_u64_field(ppm_u64(s->setcc, s->text_bytes));

    // Last field ends the line.
    (void)mc_write_u64_dec(1, ppm_u64(s->movsxd, s->text_bytes));
    (void)mc_write_str(1, "\n");
}

static void sort_rows_desc(struct stats_row *rows, mc_u32 n, MetricField f, int ratio_mode) {
    // Selection sort: tiny n (<= ~100), stable behavior not required.
    for (mc_u32 i = 0; i < n; i++) {
        mc_u32 best = i;
        mc_u64 bestv = metric_score(&rows[i].s, f, ratio_mode);
        for (mc_u32 j = i + 1; j < n; j++) {
            mc_u64 v = metric_score(&rows[j].s, f, ratio_mode);
            if (v > bestv) {
                best = j;
                bestv = v;
            } else if (v == bestv) {
                // Tie-break: prefer larger absolute count.
                mc_u64 a = metric_get(&rows[j].s, f);
                mc_u64 b = metric_get(&rows[best].s, f);
                if (a > b) {
                    best = j;
                    bestv = v;
                }
            }
        }
        if (best != i) {
            struct stats_row tmp = rows[i];
            rows[i] = rows[best];
            rows[best] = tmp;
        }
    }
}

struct tool_iter_ctx {
    const char *argv0;
    const char *compiler;
    mc_i32 dirfd;
    const char *only_tool;
    int per_tool;
    int top_mode;
    int top_ratio_mode;
    MetricField top_field;
    mc_u32 top_n;

    struct stats_row rows[256];
    mc_u32 n_rows;
    struct stats total;
};

static int tool_cb(void *vctx, const char *name, mc_u8 d_type) {
    struct tool_iter_ctx *ctx = (struct tool_iter_ctx *)vctx;
    if (mc_is_dot_or_dotdot(name)) return 0;

    if (ctx->only_tool && ctx->only_tool[0]) {
        if (!mc_streq(ctx->only_tool, name)) return 0;
    }

    // We only want regular files in compiler subdirs.
    if (d_type != DT_REG && d_type != 0) {
        // d_type can be 0 on some filesystems; handle via fstatat.
        if (d_type != DT_REG) {
            // fallthrough to stat-based filtering
        }
    }

    struct mc_stat st;
    mc_i64 s = mc_sys_newfstatat(ctx->dirfd, name, &st, 0);
    if (s < 0) return 0;
    if ((st.st_mode & MC_S_IFMT) != MC_S_IFREG) return 0;

    mc_i32 fd = (mc_i32)mc_sys_openat(ctx->dirfd, name, MC_O_RDONLY | MC_O_CLOEXEC, 0);
    if (fd < 0) return 0;

    struct stats stt;
    mc_memset(&stt, 0, sizeof(stt));
    stt.n_files = 1;
    if (analyze_elf_fd(fd, &stt)) {
        stt.n_ok = 1;
        stats_add(&ctx->total, &stt);
        if (ctx->top_mode) {
            if (ctx->n_rows < (mc_u32)(sizeof(ctx->rows) / sizeof(ctx->rows[0]))) {
                struct stats_row *r = &ctx->rows[ctx->n_rows++];
                mc_memset(r, 0, sizeof(*r));
                // Tool names are short in this repo; truncate conservatively.
                mc_usize nn = mc_strlen(name);
                if (nn >= sizeof(r->tool)) nn = sizeof(r->tool) - 1;
                mc_memcpy(r->tool, name, nn);
                r->tool[nn] = 0;
                r->s = stt;
            }
        } else if (ctx->per_tool) {
            print_row(ctx->compiler, name, &stt);
        }
    } else {
        stt.n_err = 1;
        stats_add(&ctx->total, &stt);
    }

    (void)mc_sys_close(fd);
    return 0;
}

struct compiler_iter_ctx {
    const char *argv0;
    mc_i32 bindirfd;
    const char *only_compiler;
    const char *only_tool;
    int per_tool;
    int top_mode;
    int top_ratio_mode;
    MetricField top_field;
    mc_u32 top_n;
};

static int compiler_cb(void *vctx, const char *name, mc_u8 d_type) {
    struct compiler_iter_ctx *ctx = (struct compiler_iter_ctx *)vctx;
    if (mc_is_dot_or_dotdot(name)) return 0;

    // Filter to matrix dirs by name; also verify it is a directory.
    if (!is_dirname_matrix(name)) return 0;

    if (ctx->only_compiler && ctx->only_compiler[0]) {
        if (!mc_streq(ctx->only_compiler, name)) return 0;
    }

    // Verify directory via stat (d_type is not reliable on all FS).
    struct mc_stat st;
    mc_i64 s = mc_sys_newfstatat(ctx->bindirfd, name, &st, 0);
    if (s < 0) return 0;
    if ((st.st_mode & MC_S_IFMT) != MC_S_IFDIR) return 0;

    mc_i32 dirfd = (mc_i32)mc_sys_openat(ctx->bindirfd, name, MC_O_RDONLY | MC_O_DIRECTORY | MC_O_CLOEXEC, 0);
    if (dirfd < 0) return 0;

    struct tool_iter_ctx tctx;
    mc_memset(&tctx, 0, sizeof(tctx));
    tctx.argv0 = ctx->argv0;
    tctx.compiler = name;
    tctx.dirfd = dirfd;
    tctx.only_tool = ctx->only_tool;
    tctx.per_tool = ctx->per_tool;
    tctx.top_mode = ctx->top_mode;
    tctx.top_ratio_mode = ctx->top_ratio_mode;
    tctx.top_field = ctx->top_field;
    tctx.top_n = ctx->top_n;

    (void)mc_for_each_dirent(dirfd, tool_cb, &tctx);

    if (tctx.top_mode) {
        sort_rows_desc(tctx.rows, tctx.n_rows, tctx.top_field, tctx.top_ratio_mode);
        mc_u32 limit = tctx.top_n;
        if (limit > tctx.n_rows) limit = tctx.n_rows;
        for (mc_u32 i = 0; i < limit; i++) {
            print_row(tctx.compiler, tctx.rows[i].tool, &tctx.rows[i].s);
        }
    }

    // Emit total line for this compiler dir.
    print_row(name, "__TOTAL__", &tctx.total);

    (void)mc_sys_close(dirfd);
    return 0;
}

static void usage(const char *argv0) {
    mc_die_usage(argv0,
        "matrixstat [--per-tool] [--only COMPILER_DIR] [--tool TOOL] [--top FIELD N] [--top-ratio FIELD N]\n"
        "\n"
        "Scans bin/*_*/ ELF64 executables and prints opcode-pattern counts\n"
        "from executable sections (.text / SHF_EXECINSTR). Output is TSV.\n"
    "If section headers are missing, falls back to scanning executable PT_LOAD.\n"
        "\n"
        "Options:\n"
        "  --per-tool         Print one row per tool (plus totals).\n"
    "  --only NAME         Only scan one compiler dir (e.g. monacc_).\n"
    "  --tool NAME         Only scan one tool within each compiler dir (e.g. yes).\n"
    "  --top FIELD N       Print only the top-N tools per compiler dir by FIELD,\n"
    "                     then the __TOTAL__ row. Implies --per-tool.\n"
    "  --top-ratio FIELD N Like --top, but ranks by FIELD density per text_bytes.\n"
    "\n"
    "Top fields:\n"
    "  file_bytes text_bytes\n"
    "  push pop call icall ret leave jcc jmp setcc movsxd syscall\n"
    "  prologue_fp stack_sub stack_add stack_load stack_store xor_zero mov_imm0 lea\n");
}

int main(int argc, char **argv) {
    int per_tool = 0;
    const char *only = 0;
    const char *tool = 0;
    int top_mode = 0;
    int top_ratio_mode = 0;
    MetricField top_field = MF_NONE;
    mc_u32 top_n = 0;

    for (int i = 1; i < argc; i++) {
        if (mc_streq(argv[i], "--per-tool")) {
            per_tool = 1;
            continue;
        }
        if (mc_streq(argv[i], "--only")) {
            if (i + 1 >= argc) usage(argv[0]);
            only = argv[++i];
            continue;
        }
        if (mc_streq(argv[i], "--tool")) {
            if (i + 1 >= argc) usage(argv[0]);
            tool = argv[++i];
            continue;
        }
        if (mc_streq(argv[i], "--top")) {
            if (i + 2 >= argc) usage(argv[0]);
            top_field = metric_parse(argv[i + 1]);
            if (top_field == MF_NONE) usage(argv[0]);
            mc_u64 nn = 0;
            if (mc_parse_u64_dec(argv[i + 2], &nn) != 0) usage(argv[0]);
            if (nn > 1000000ULL) nn = 1000000ULL;
            top_n = (mc_u32)nn;
            top_mode = 1;
            top_ratio_mode = 0;
            per_tool = 1;
            i += 2;
            continue;
        }
        if (mc_streq(argv[i], "--top-ratio")) {
            if (i + 2 >= argc) usage(argv[0]);
            top_field = metric_parse(argv[i + 1]);
            if (top_field == MF_NONE) usage(argv[0]);
            mc_u64 nn = 0;
            if (mc_parse_u64_dec(argv[i + 2], &nn) != 0) usage(argv[0]);
            if (nn > 1000000ULL) nn = 1000000ULL;
            top_n = (mc_u32)nn;
            top_mode = 1;
            top_ratio_mode = 1;
            per_tool = 1;
            i += 2;
            continue;
        }
        if (mc_streq(argv[i], "-h") || mc_streq(argv[i], "--help")) usage(argv[0]);
        usage(argv[0]);
    }

    mc_i32 bindirfd = (mc_i32)mc_sys_openat(MC_AT_FDCWD, "bin", MC_O_RDONLY | MC_O_DIRECTORY | MC_O_CLOEXEC, 0);
    if (bindirfd < 0) mc_die_errno(argv[0], "open bin", bindirfd);

    print_header();

    struct compiler_iter_ctx cctx;
    mc_memset(&cctx, 0, sizeof(cctx));
    cctx.argv0 = argv[0];
    cctx.bindirfd = bindirfd;
    cctx.only_compiler = only;
    cctx.only_tool = tool;
    cctx.per_tool = per_tool;
    cctx.top_mode = top_mode;
    cctx.top_ratio_mode = top_ratio_mode;
    cctx.top_field = top_field;
    cctx.top_n = top_n;

    (void)mc_for_each_dirent(bindirfd, compiler_cb, &cctx);

    (void)mc_sys_close(bindirfd);
    return 0;
}
