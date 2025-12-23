#include "mc_compiler.h"

void mc_compiler_init(mc_compiler *ctx) {
    if (!ctx) return;
    
    mc_memset(ctx, 0, sizeof(*ctx));
    
    // Set default options
    ctx->opts.target = MC_TARGET_X86_64_LINUX;
    ctx->opts.as_prog = "as";
    ctx->opts.ld_prog = "ld";
    ctx->opts.emit_obj = 1;        // Default to internal object emission
    ctx->opts.link_internal = 1;   // Default to internal linking
    ctx->opts.use_nmagic = 1;      // Default to NMAGIC
    ctx->opts.keep_shdr = 0;       // Default to stripping section headers
    ctx->opts.compile_only = 0;
    
    // Initialize trace state
    ctx->trace_enabled = 0;
    ctx->trace_force = 0;
    ctx->trace_cached = -1;
    
    // Initialize code generation state
    ctx->a64_expr_label_id = 0;
}

void mc_compiler_destroy(mc_compiler *ctx) {
    if (!ctx) return;
    
    // Free allocated toolchain paths
    if (ctx->opts.as_prog_alloc) {
        monacc_free(ctx->opts.as_prog_alloc);
        ctx->opts.as_prog_alloc = NULL;
    }
    if (ctx->opts.ld_prog_alloc) {
        monacc_free(ctx->opts.ld_prog_alloc);
        ctx->opts.ld_prog_alloc = NULL;
    }
    
    // Free include directories
    if (ctx->opts.pp_config.include_dirs) {
        monacc_free(ctx->opts.pp_config.include_dirs);
        ctx->opts.pp_config.include_dirs = NULL;
    }
    
    // Free command-line defines
    if (ctx->opts.cmd_defines) {
        for (int i = 0; i < ctx->opts.ncmd_defines; i++) {
            if (ctx->opts.cmd_defines[i].name) {
                monacc_free((void *)ctx->opts.cmd_defines[i].name);
            }
            if (ctx->opts.cmd_defines[i].repl) {
                monacc_free((void *)ctx->opts.cmd_defines[i].repl);
            }
        }
        monacc_free(ctx->opts.cmd_defines);
        ctx->opts.cmd_defines = NULL;
    }
}

mc_target mc_parse_target(const char *s) {
    if (!s) return MC_TARGET_X86_64_LINUX;
    
    if (mc_strcmp(s, "x86_64-linux") == 0) {
        return MC_TARGET_X86_64_LINUX;
    }
    if (mc_strcmp(s, "aarch64-darwin") == 0) {
        return MC_TARGET_AARCH64_DARWIN;
    }
    
    // Unknown target defaults to x86_64-linux
    return MC_TARGET_X86_64_LINUX;
}
