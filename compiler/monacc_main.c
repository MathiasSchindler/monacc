#include "monacc.h"

static int g_trace_force = 0;
static int g_trace_cached = -1;

static int trace_enabled(void) {
    if (g_trace_force) return 1;
    if (g_trace_cached >= 0) return g_trace_cached;
    g_trace_cached = 0;
    char **envp = mc_get_start_envp();
    const char *v = envp ? mc_getenv_kv(envp, "MONACC_TRACE=") : NULL;
    if (v && *v && mc_strcmp(v, "0") != 0) g_trace_cached = 1;
    return g_trace_cached;
}

static void trace_write(const char *s) {
    if (!s) s = "";
    xwrite_best_effort(2, s, mc_strlen(s));
}

static void trace_checkpoint(const char *what, const char *path) {
    if (!trace_enabled()) return;
    trace_write("TRACE: ");
    trace_write(what ? what : "?");
    if (path && *path) {
        trace_write(": ");
        trace_write(path);
    }
    trace_write("\n");
}

// Post-link ELF shrinking: Linux only needs program headers at runtime.
// Dropping the section header table (SHT) and truncating the file to the end of
// PT_LOAD data reduces file size for all produced tools.

#define EI_NIDENT 16
#define ELFCLASS64 2
#define ELFDATA2LSB 1
#define PT_LOAD 1

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

static void elf_trim_shdr_best_effort(const char *path) {
    int fd = xopen_rdwr_try(path);
    if (fd < 0) return;

    Elf64_Ehdr eh;
    mc_isize r = xread_retry(fd, &eh, sizeof(eh));
    if (r != (mc_isize)sizeof(eh)) {
        xclose_best_effort(fd);
        return;
    }

    {
        const unsigned char magic[4] = {0x7f, 'E', 'L', 'F'};
        if (mc_memcmp(eh.e_ident, magic, 4) != 0) goto out;
        if (eh.e_ident[4] != ELFCLASS64) goto out;
        if (eh.e_ident[5] != ELFDATA2LSB) goto out;
        if (eh.e_ehsize != (mc_u16)sizeof(Elf64_Ehdr)) goto out;
        if (eh.e_phentsize != (mc_u16)sizeof(Elf64_Phdr)) goto out;
        if (eh.e_phnum == 0 || eh.e_phoff == 0) goto out;
        // Sanity: avoid excessive reads on corrupted outputs.
        if (eh.e_phnum > 32) goto out;
    }

    mc_i64 file_size = xlseek_retry(fd, 0, MC_SEEK_END);
    if (file_size < 0) goto out;

    if (xlseek_retry(fd, (mc_i64)eh.e_phoff, MC_SEEK_SET) < 0) goto out;

    Elf64_Phdr phdr_stack[8];
    Elf64_Phdr *phdrs = phdr_stack;
    int phdr_dyn = 0;
    if (eh.e_phnum > (mc_u16)(sizeof(phdr_stack) / sizeof(phdr_stack[0]))) {
        phdrs = (Elf64_Phdr *)monacc_malloc((mc_usize)eh.e_phnum * sizeof(*phdrs));
        if (!phdrs) goto out;
        phdr_dyn = 1;
    }

    mc_usize phdr_bytes = (mc_usize)eh.e_phnum * sizeof(*phdrs);
    r = xread_retry(fd, phdrs, phdr_bytes);
    if (r != (mc_isize)phdr_bytes) goto out_free;

    mc_u64 max_load_end = 0;
    for (mc_u16 i = 0; i < eh.e_phnum; i++) {
        if (phdrs[i].p_type != PT_LOAD) continue;
        mc_u64 end = phdrs[i].p_offset + phdrs[i].p_filesz;
        if (end > max_load_end) max_load_end = end;
    }

    if (max_load_end == 0) goto out_free;
    if ((mc_i64)max_load_end > file_size) goto out_free;

    // Zero out section header table pointers. Runtime does not need SHT.
    eh.e_shoff = 0;
    eh.e_shentsize = 0;
    eh.e_shnum = 0;
    eh.e_shstrndx = 0;

    if (xlseek_retry(fd, 0, MC_SEEK_SET) >= 0) {
        xwrite_best_effort(fd, &eh, sizeof(eh));
    }

    // Truncate away the section headers and shstrtab.
    if ((mc_u64)file_size > max_load_end) {
        (void)xftruncate_best_effort(fd, (mc_i64)max_load_end);
    }

out_free:
    if (phdr_dyn) monacc_free(phdrs);
out:
    xclose_best_effort(fd);
}

static MC_NORETURN void usage(const char *argv0) {
    (void)argv0;
#ifdef SELFHOST
    const char *msg =
        "usage: monacc <input1.c> [input2.c ...] -o <output> [-c] [--target <x86_64-linux|aarch64-darwin>] [--emit-obj] [--link-internal] [--trace-selfhost] [--dump-elfobj <file.o>] [--dump-elfsec <file>] [-I dir ...] [-DNAME[=VALUE] ...] [--dump-pp <path>] [--no-nmagic] [--keep-shdr] [--toolchain <dir>] [--as <path>] [--ld <path>]\n"
        "notes: defaults to internal asm/link (equivalent to --emit-obj --link-internal); use --as/--ld/--toolchain to force external tools\n";
    (void)xwrite_best_effort(2, msg, mc_strlen(msg));
#else
    errf("usage: monacc <input1.c> [input2.c ...] -o <output> [-c] [--target <x86_64-linux|aarch64-darwin>] [--emit-obj] [--link-internal] [--trace-selfhost] [--dump-elfobj <file.o>] [--dump-elfsec <file>] [-I dir ...] [-DNAME[=VALUE] ...] [--dump-pp <path>] [--no-nmagic] [--keep-shdr] [--toolchain <dir>] [--as <path>] [--ld <path>]\n"
         "notes: defaults to internal asm/link (equivalent to --emit-obj --link-internal); use --as/--ld/--toolchain to force external tools\n");
#endif
    _exit(2);
}

static int ends_with_lit(const char *s, const char *lit) {
    if (!s || !lit) return 0;
    mc_usize ns = mc_strlen(s);
    mc_usize nl = mc_strlen(lit);
    if (nl > ns) return 0;
    return mc_memcmp(s + (ns - nl), lit, nl) == 0;
}

typedef enum {
    TARGET_X86_64_LINUX = 0,
    TARGET_AARCH64_DARWIN = 1,
} Target;

static Target parse_target_or_die(const char *argv0, const char *s) {
    if (!s) usage(argv0);
    if (!mc_strcmp(s, "x86_64-linux")) return TARGET_X86_64_LINUX;
    if (!mc_strcmp(s, "aarch64-darwin")) return TARGET_AARCH64_DARWIN;
    usage(argv0);
}

typedef struct {
    char *name;
    char *repl;
} CmdDefine;

static char *join_dir_prog(const char *dir, const char *prog) {
    mc_usize dlen = mc_strlen(dir);
    mc_usize plen = mc_strlen(prog);
    int need_slash = (dlen > 0 && dir[dlen - 1] != '/');
    mc_usize n = dlen + (need_slash ? 1u : 0u) + plen + 1u;
    char *out = (char *)monacc_malloc(n);
    if (!out) die("oom");
    mc_memcpy(out, dir, dlen);
    mc_usize pos = dlen;
    if (need_slash) out[pos++] = '/';
    mc_memcpy(out + pos, prog, plen);
    out[pos + plen] = 0;
    return out;
}

static void cmd_define_add(CmdDefine **defs, int *ndefs, const char *name, mc_usize name_len, const char *repl) {
    CmdDefine *nd = (CmdDefine *)monacc_realloc(*defs, (mc_usize)(*ndefs + 1) * sizeof(**defs));
    if (!nd) die("oom");
    *defs = nd;
    CmdDefine *d = &(*defs)[(*ndefs)++];

    d->name = (char *)monacc_malloc(name_len + 1);
    if (!d->name) die("oom");
    mc_memcpy(d->name, name, name_len);
    d->name[name_len] = 0;

    {
        const char *src = repl ? repl : "1";
        mc_usize n = mc_strlen(src);
        d->repl = (char *)monacc_malloc(n + 1);
        if (!d->repl) die("oom");
        mc_memcpy(d->repl, src, n + 1);
    }
}

static void mt_apply_cmd_defines(MacroTable *mt, const CmdDefine *defs, int ndefs) {
    for (int i = 0; i < ndefs; i++) {
        mt_define(mt, defs[i].name, mc_strlen(defs[i].name), defs[i].repl);
    }
}

static void compile_to_obj(Target target, const char *in_path, const char *tmp_s, const char *tmp_o, const PPConfig *cfg,
                           const CmdDefine *defs, int ndefs, int with_start, const char *dump_pp_path, const char *as_prog, int emit_obj) {
    trace_checkpoint("read input", in_path);

    MacroTable mt;
    mc_memset(&mt, 0, sizeof(mt));
    mt_apply_cmd_defines(&mt, defs, ndefs);

    OnceTable ot;
    mc_memset(&ot, 0, sizeof(ot));
    Str pp;
    mc_memset(&pp, 0, sizeof(pp));

    trace_checkpoint("preprocess start", in_path);
    preprocess_file(cfg, &mt, &ot, in_path, &pp);
    trace_checkpoint("preprocess end", in_path);

    if (dump_pp_path) {
        write_file(dump_pp_path, pp.buf ? pp.buf : "", pp.len);
    }

    Parser p;
    mc_memset(&p, 0, sizeof(p));
    p.lx.path = in_path;
    p.lx.src = pp.buf;
    p.lx.len = pp.len;
    p.lx.pos = 0;
    p.lx.line = 1;
    p.lx.col = 1;
    p.lx.mt = &mt;
    parser_next(&p);

    Program prg;
    mc_memset(&prg, 0, sizeof(prg));
    p.prg = &prg;

    trace_checkpoint("parse start", in_path);
    parse_program(&p, &prg);
    trace_checkpoint("parse end", in_path);

    Str out_asm;
    mc_memset(&out_asm, 0, sizeof(out_asm));

    trace_checkpoint("codegen start", in_path);
    if (target == TARGET_X86_64_LINUX) {
        emit_x86_64_sysv_freestanding_with_start(&prg, &out_asm, with_start);
    } else if (target == TARGET_AARCH64_DARWIN) {
        (void)with_start;
        emit_aarch64_darwin_hosted(&prg, &out_asm);
    } else {
        die("internal: unknown target");
    }
    trace_checkpoint("codegen end", in_path);

    // Always emit the textual assembly as well; it's used by the external 'as' path
    // and helps diagnose internal object emission failures.
    write_file(tmp_s, out_asm.buf, out_asm.len);

    if (emit_obj) {
        if (target != TARGET_X86_64_LINUX) {
            die("emit-obj is only supported for x86_64-linux today");
        }
        trace_checkpoint("assemble (internal) start", tmp_o);
        assemble_x86_64_elfobj(out_asm.buf ? out_asm.buf : "", out_asm.len, tmp_o);
        trace_checkpoint("assemble (internal) end", tmp_o);
    } else {
        trace_checkpoint("assemble (external) start", tmp_o);
        char *as_argv[8];
        if (target == TARGET_AARCH64_DARWIN) {
            // Drive the platform assembler via clang.
            int k = 0;
            as_argv[k++] = (char *)(as_prog ? as_prog : "clang");
            as_argv[k++] = "-c";
            as_argv[k++] = (char *)tmp_s;
            as_argv[k++] = "-o";
            as_argv[k++] = (char *)tmp_o;
            as_argv[k] = NULL;
        } else {
            as_argv[0] = (char *)(as_prog ? as_prog : "as");
            as_argv[1] = "--64";
            as_argv[2] = (char *)tmp_s;
            as_argv[3] = "-o";
            as_argv[4] = (char *)tmp_o;
            as_argv[5] = NULL;
        }
        int rc = run_cmd(as_argv);
        if (rc != 0) die_i64("as failed (", rc, ")");
        trace_checkpoint("assemble (external) end", tmp_o);
    }

    monacc_free(out_asm.buf);
    monacc_free(pp.buf);
    for (int i = 0; i < mt.n; i++) {
        monacc_free(mt.macros[i].repl);
    }
    monacc_free(mt.macros);
    for (int i = 0; i < ot.n; i++) {
        monacc_free(ot.paths[i]);
    }
    monacc_free(ot.paths);
    for (int i = 0; i < prg.nstrs; i++) {
        monacc_free(prg.strs[i].data);
    }
    monacc_free(prg.strs);
    monacc_free(prg.fns);
    monacc_free(prg.structs);
    monacc_free(prg.typedefs);
    monacc_free(prg.consts);
}

int main(int argc, char **argv) {
    char **in_paths = NULL;
    int nin_paths = 0;
    const char *out_path = NULL;
    const char *dump_pp_path = NULL;
    const char *dump_elfobj_path = NULL;
    const char *dump_elfsec_path = NULL;
    const char *as_prog = "as";
    const char *ld_prog = "ld";
    char *as_prog_alloc = NULL;
    char *ld_prog_alloc = NULL;
    int compile_only = 0;
    int use_nmagic = 1;
    // Default to the self-contained toolchain.
    // External as/ld remain available for bring-up/debugging via --as/--ld/--toolchain.
    int emit_obj = 1;
    int link_internal = 1;
    int keep_shdr = 0;
    Target target = TARGET_X86_64_LINUX;
    PPConfig cfg;
    mc_memset(&cfg, 0, sizeof(cfg));

    CmdDefine *defs = NULL;
    int ndefs = 0;

    for (int i = 1; i < argc; i++) {
        if (!mc_strcmp(argv[i], "-o")) {
            if (i + 1 >= argc) usage(argv[0]);
            out_path = argv[++i];
        } else if (!mc_strcmp(argv[i], "-c")) {
            compile_only = 1;
        } else if (!mc_strcmp(argv[i], "-I")) {
            if (i + 1 >= argc) usage(argv[0]);
            cfg.include_dirs = (char **)monacc_realloc(cfg.include_dirs, (mc_usize)(cfg.ninclude_dirs + 1) * sizeof(char *));
            if (!cfg.include_dirs) die("oom");
            cfg.include_dirs[cfg.ninclude_dirs++] = argv[++i];
        } else if (!mc_strncmp(argv[i], "-D", 2)) {
            const char *arg = argv[i] + 2;
            if (*arg == 0) {
                if (i + 1 >= argc) usage(argv[0]);
                arg = argv[++i];
            }
            const char *eq = mc_strchr(arg, '=');
            if (!eq) {
                cmd_define_add(&defs, &ndefs, arg, mc_strlen(arg), "1");
            } else {
                cmd_define_add(&defs, &ndefs, arg, (mc_usize)(eq - arg), eq + 1);
            }
        } else if (argv[i][0] == '-') {
            if (!mc_strcmp(argv[i], "--target")) {
                if (i + 1 >= argc) usage(argv[0]);
                target = parse_target_or_die(argv[0], argv[++i]);
                // aarch64-darwin bring-up uses external clang asm/link.
                if (target == TARGET_AARCH64_DARWIN) {
                    emit_obj = 0;
                    link_internal = 0;
                    if (as_prog_alloc) {
                        monacc_free(as_prog_alloc);
                        as_prog_alloc = NULL;
                    }
                    if (ld_prog_alloc) {
                        monacc_free(ld_prog_alloc);
                        ld_prog_alloc = NULL;
                    }
                    as_prog = "clang";
                    ld_prog = "clang";
                }
                continue;
            }
            if (!mc_strcmp(argv[i], "--dump-pp")) {
                if (i + 1 >= argc) usage(argv[0]);
                dump_pp_path = argv[++i];
                continue;
            }
            if (!mc_strcmp(argv[i], "--dump-elfobj")) {
                if (i + 1 >= argc) usage(argv[0]);
                dump_elfobj_path = argv[++i];
                continue;
            }
            if (!mc_strcmp(argv[i], "--dump-elfsec")) {
                if (i + 1 >= argc) usage(argv[0]);
                dump_elfsec_path = argv[++i];
                continue;
            }
            if (!mc_strcmp(argv[i], "--no-nmagic")) {
                use_nmagic = 0;
                continue;
            }
            if (!mc_strcmp(argv[i], "--keep-shdr")) {
                keep_shdr = 1;
                continue;
            }
            if (!mc_strcmp(argv[i], "--emit-obj")) {
                emit_obj = 1;
                continue;
            }
            if (!mc_strcmp(argv[i], "--link-internal")) {
                link_internal = 1;
                continue;
            }
            if (!mc_strcmp(argv[i], "--trace-selfhost")) {
                g_trace_force = 1;
                continue;
            }
            if (!mc_strcmp(argv[i], "--toolchain")) {
                if (i + 1 >= argc) usage(argv[0]);
                const char *dir = argv[++i];
                if (as_prog_alloc) monacc_free(as_prog_alloc);
                if (ld_prog_alloc) monacc_free(ld_prog_alloc);
                as_prog_alloc = join_dir_prog(dir, "as");
                ld_prog_alloc = join_dir_prog(dir, "ld");
                as_prog = as_prog_alloc;
                ld_prog = ld_prog_alloc;
                // Toolchain selection is meaningful only for external as/ld.
                emit_obj = 0;
                link_internal = 0;
                continue;
            }
            if (!mc_strcmp(argv[i], "--as")) {
                if (i + 1 >= argc) usage(argv[0]);
                if (as_prog_alloc) {
                    monacc_free(as_prog_alloc);
                    as_prog_alloc = NULL;
                }
                as_prog = argv[++i];
                emit_obj = 0;
                continue;
            }
            if (!mc_strcmp(argv[i], "--ld")) {
                if (i + 1 >= argc) usage(argv[0]);
                if (ld_prog_alloc) {
                    monacc_free(ld_prog_alloc);
                    ld_prog_alloc = NULL;
                }
                ld_prog = argv[++i];
                link_internal = 0;
                continue;
            }
            usage(argv[0]);
        } else {
            in_paths = (char **)monacc_realloc(in_paths, (mc_usize)(nin_paths + 1) * sizeof(char *));
            if (!in_paths) die("oom");
            in_paths[nin_paths++] = argv[i];
        }
    }

    if (dump_elfobj_path) {
        elfobj_dump(dump_elfobj_path);
        return 0;
    }

    if (dump_elfsec_path) {
        elfsec_dump(dump_elfsec_path);
        return 0;
    }

    if (nin_paths < 1 || !out_path) usage(argv[0]);

    if (trace_enabled()) {
        trace_checkpoint("start", argv[0]);
        trace_checkpoint(emit_obj ? "mode: --emit-obj" : "mode: external as", NULL);
        trace_checkpoint(link_internal ? "mode: --link-internal" : "mode: external ld", NULL);
    }

    // Link-only mode: if all inputs are .o files, skip compilation.
    // This is primarily used to run the internal linker in a fresh process.
    int all_obj_inputs = 1;
    for (int i = 0; i < nin_paths; i++) {
        if (!ends_with_lit(in_paths[i], ".o")) {
            all_obj_inputs = 0;
            break;
        }
    }

    if (all_obj_inputs) {
        if (compile_only) die("-c does not accept .o inputs");

        if (link_internal) {
            if (target != TARGET_X86_64_LINUX) {
                die("link-internal is only supported for x86_64-linux today");
            }
            trace_checkpoint("link (internal) start", out_path);
            link_internal_exec_objs((const char **)in_paths, nin_paths, out_path, keep_shdr);
            trace_checkpoint("link (internal) end", out_path);
        } else {
            trace_checkpoint("link (external) start", out_path);
            int base = 0;
            int argc_ld = nin_paths + 32;
            char **ld_argv = (char **)monacc_calloc((mc_usize)argc_ld + 1, sizeof(char *));
            if (!ld_argv) die("oom");
            if (target == TARGET_AARCH64_DARWIN) {
                ld_argv[base++] = (char *)(ld_prog ? ld_prog : "clang");
            } else {
                ld_argv[base++] = (char *)(ld_prog ? ld_prog : "ld");
                ld_argv[base++] = "-nostdlib";
                ld_argv[base++] = "-static";
                ld_argv[base++] = "-s";
                ld_argv[base++] = "--gc-sections";
                ld_argv[base++] = "--build-id=none";
                if (use_nmagic) {
                    ld_argv[base++] = "-n";
                }
                ld_argv[base++] = "-z";
                ld_argv[base++] = "noseparate-code";
                ld_argv[base++] = "-z";
                ld_argv[base++] = "max-page-size=0x1000";
                ld_argv[base++] = "-z";
                ld_argv[base++] = "common-page-size=0x1000";
                ld_argv[base++] = "-e";
                ld_argv[base++] = "_start";

                if (xpath_exists("compiler/minimal.ld")) {
                    ld_argv[base++] = "-T";
                    ld_argv[base++] = "compiler/minimal.ld";
                }
            }

            for (int i = 0; i < nin_paths; i++) {
                ld_argv[base++] = in_paths[i];
            }
            ld_argv[base++] = "-o";
            ld_argv[base++] = (char *)out_path;
            ld_argv[base] = NULL;
            int rc = run_cmd(ld_argv);
            monacc_free(ld_argv);
            if (rc != 0) die_i64("ld failed (", rc, ")");
            trace_checkpoint("link (external) end", out_path);
        }

        if (target == TARGET_X86_64_LINUX && !keep_shdr) {
            elf_trim_shdr_best_effort(out_path);
        }

        if (as_prog_alloc) monacc_free(as_prog_alloc);
        if (ld_prog_alloc) monacc_free(ld_prog_alloc);
        monacc_free(cfg.include_dirs);
        for (int i = 0; i < ndefs; i++) {
            monacc_free(defs[i].name);
            monacc_free(defs[i].repl);
        }
        monacc_free(defs);
        monacc_free(in_paths);
        return 0;
    }

    if (compile_only) {
        if (nin_paths != 1) {
            die("-c requires exactly one input file");
        }
        char tmp_s[4096];
        if (mc_snprint_cstr_cstr(tmp_s, sizeof(tmp_s), out_path, ".s") >= (int)sizeof(tmp_s)) die("path too long");
        // In -c mode we intentionally do not emit _start.
        compile_to_obj(target, in_paths[0], tmp_s, out_path, &cfg, defs, ndefs, 0, dump_pp_path, as_prog, emit_obj);
        if (!emit_obj) xunlink_best_effort(tmp_s);

        if (as_prog_alloc) monacc_free(as_prog_alloc);
        if (ld_prog_alloc) monacc_free(ld_prog_alloc);

        monacc_free(cfg.include_dirs);
        for (int i = 0; i < ndefs; i++) {
            monacc_free(defs[i].name);
            monacc_free(defs[i].repl);
        }
        monacc_free(defs);
        monacc_free(in_paths);
        return 0;
    }

    // Compile each input to its own .o (only the first input emits _start).
    char **obj_paths = (char **)monacc_calloc((mc_usize)nin_paths, sizeof(char *));
    if (!obj_paths) die("oom");
    char **asm_paths = (char **)monacc_calloc((mc_usize)nin_paths, sizeof(char *));
    if (!asm_paths) die("oom");

    for (int i = 0; i < nin_paths; i++) {
        char tmp_s[4096];
        char tmp_o[4096];
        if (mc_snprint_cstr_cstr_u64_cstr(tmp_s, sizeof(tmp_s), out_path, ".", (mc_u64)i, ".s") >= (int)sizeof(tmp_s)) {
            die("path too long");
        }
        if (mc_snprint_cstr_cstr_u64_cstr(tmp_o, sizeof(tmp_o), out_path, ".", (mc_u64)i, ".o") >= (int)sizeof(tmp_o)) {
            die("path too long");
        }

        {
            mc_usize ns = mc_strlen(tmp_s) + 1;
            mc_usize no = mc_strlen(tmp_o) + 1;
            asm_paths[i] = (char *)monacc_malloc(ns);
            obj_paths[i] = (char *)monacc_malloc(no);
            if (!asm_paths[i] || !obj_paths[i]) die("oom");
            mc_memcpy(asm_paths[i], tmp_s, ns);
            mc_memcpy(obj_paths[i], tmp_o, no);
        }

        compile_to_obj(target, in_paths[i], tmp_s, tmp_o, &cfg, defs, ndefs, i == 0, dump_pp_path, as_prog, emit_obj);
    }

    // Link all objects.
    // Size-oriented defaults: we emit per-function/per-string sections and link with --gc-sections.
    {
        if (link_internal) {
            if (target != TARGET_X86_64_LINUX) {
                die("link-internal is only supported for x86_64-linux today");
            }
            trace_checkpoint("link (internal) re-exec start", out_path);
            // Run the internal linker in a fresh process to isolate it from any allocator state
            // left behind by the compile phase (important for large self-host builds).
            int argc_lnk = nin_paths + 9;
            char **lnk_argv = (char **)monacc_calloc((mc_usize)argc_lnk + 1, sizeof(char *));
            if (!lnk_argv) die("oom");
            int base = 0;
            lnk_argv[base++] = argv[0];
            lnk_argv[base++] = "--link-internal";
            if (g_trace_force) {
                lnk_argv[base++] = "--trace-selfhost";
            }
            if (keep_shdr) {
                lnk_argv[base++] = "--keep-shdr";
            }
            for (int i = 0; i < nin_paths; i++) {
                lnk_argv[base++] = obj_paths[i];
            }
            lnk_argv[base++] = "-o";
            lnk_argv[base++] = (char *)out_path;
            lnk_argv[base] = NULL;
            int rc = run_cmd(lnk_argv);
            monacc_free(lnk_argv);
            if (rc != 0) die_i64("link-internal failed (", rc, ")");
            trace_checkpoint("link (internal) re-exec end", out_path);
        } else {
            trace_checkpoint("link (external) start", out_path);
            int base = 0;
            // Allocate with slack to keep this robust as flags change.
            int argc_ld = nin_paths + 32;
            char **ld_argv = (char **)monacc_calloc((mc_usize)argc_ld + 1, sizeof(char *));
            if (!ld_argv) die("oom");
            if (target == TARGET_AARCH64_DARWIN) {
                // Drive the native linker via clang.
                ld_argv[base++] = (char *)(ld_prog ? ld_prog : "clang");
            } else {
                ld_argv[base++] = (char *)(ld_prog ? ld_prog : "ld");
                ld_argv[base++] = "-nostdlib";
                ld_argv[base++] = "-static";
                ld_argv[base++] = "-s";
                ld_argv[base++] = "--gc-sections";
                ld_argv[base++] = "--build-id=none";
                // Reduce file-size padding by avoiding page alignment between segments (nmagic).
                // This is slightly less conventional; can be disabled with --no-nmagic.
                if (use_nmagic) {
                    ld_argv[base++] = "-n";
                }
                ld_argv[base++] = "-z";
                ld_argv[base++] = "noseparate-code";
                // Use 4K page sizes to reduce alignment padding in the output file.
                ld_argv[base++] = "-z";
                ld_argv[base++] = "max-page-size=0x1000";
                ld_argv[base++] = "-z";
                ld_argv[base++] = "common-page-size=0x1000";
                ld_argv[base++] = "-e";
                ld_argv[base++] = "_start";

                // Prefer the repo's minimal linker script when available: it keeps a single
                // PT_LOAD (RWX) and packs .text/.rodata/.data/.bss tightly to minimize padding.
                // This also makes small initialized data (e.g. static-local string init) affordable.
                if (xpath_exists("compiler/minimal.ld")) {
                    ld_argv[base++] = "-T";
                    ld_argv[base++] = "compiler/minimal.ld";
                }
            }

            for (int i = 0; i < nin_paths; i++) {
                ld_argv[base++] = obj_paths[i];
            }
            ld_argv[base++] = "-o";
            ld_argv[base++] = (char *)out_path;
            ld_argv[base] = NULL;
            int rc = run_cmd(ld_argv);
            monacc_free(ld_argv);
            if (rc != 0) die_i64("ld failed (", rc, ")");
            trace_checkpoint("link (external) end", out_path);
        }
    }

    if (target == TARGET_X86_64_LINUX && !keep_shdr) {
        elf_trim_shdr_best_effort(out_path);
    }

    // Best-effort cleanup.
    for (int i = 0; i < nin_paths; i++) {
        xunlink_best_effort(asm_paths[i]);
        xunlink_best_effort(obj_paths[i]);
        monacc_free(asm_paths[i]);
        monacc_free(obj_paths[i]);
    }
    monacc_free(asm_paths);
    monacc_free(obj_paths);
    if (as_prog_alloc) monacc_free(as_prog_alloc);
    if (ld_prog_alloc) monacc_free(ld_prog_alloc);
    monacc_free(cfg.include_dirs);
    for (int i = 0; i < ndefs; i++) {
        monacc_free(defs[i].name);
        monacc_free(defs[i].repl);
    }
    monacc_free(defs);
    monacc_free(in_paths);
    return 0;
}
