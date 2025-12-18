#include "mc.h"

#define sh_print_errno mc_print_errno

// Minimal syscall-only shell.
// Subset:
// - sh [-c CMD] [FILE]
// - separators: ';' and newlines
// - pipelines: |
// - conditionals: && and ||
// - redirections: <, >, >>, N<, N>, N>>, N>&M (dup)
// - quoting: single '...' and double "..." (backslash escapes in double)
// - background: cmd & (no job control; best-effort zombie reaping)
// - builtins: cd [DIR], exit [N], wait [PID]
// Subset variable support:
// - Assignments: NAME=VALUE (no export/env).
// - Expansion: $NAME, $0..$N, $#, $@/$*, $? and $!.
// No command substitution ($(..)), no globbing, no job control.

#define SH_MAX_LINE 8192

// Script execution reads the whole file into a fixed buffer so multi-line
// constructs (if/while/for) can work.
#define SH_MAX_PROG 65536

// Tokenization limits for a whole script. These are intentionally modest.
#define SH_MAX_TOKS 2048
#define SH_MAX_WORDBUF 65536

// Marker byte embedded in wordbuf to indicate the next byte is a literal that
// must not be interpreted by the expander (used for single quotes and \ escapes).
#define SH_ESC ((char)0x01)

#define SH_MAX_ARGS 64
#define SH_MAX_CMDS 16

#define SH_MAX_VARS 64
#define SH_VAR_NAME_MAX 32
#define SH_VAR_VAL_MAX 256

#define SH_MAX_FUNCS 32

// Per-function stored body text (retokenized on each call).
#define SH_FUNC_BODY_MAX 4096
#define SH_FUNC_CALL_MAX_TOKS 512
#define SH_FUNC_CALL_WORDBUF 8192

struct sh_func {
	char name[SH_VAR_NAME_MAX];
	char body[SH_FUNC_BODY_MAX];
};

struct sh_funcs {
	mc_u32 n;
	struct sh_func funcs[SH_MAX_FUNCS];
};

enum sh_tok_kind {
	SH_TOK_WORD = 0,
	SH_TOK_PIPE,
	SH_TOK_OR_IF,
	SH_TOK_SEMI,
	SH_TOK_BG,
	SH_TOK_AND_IF,
	SH_TOK_REDIR_IN,
	SH_TOK_REDIR_OUT,
	SH_TOK_REDIR_OUT_APP,
	SH_TOK_REDIR_DUP_OUT,
	SH_TOK_END,
};

struct sh_tok {
	enum sh_tok_kind kind;
	const char *s;
	mc_usize n;
	mc_i32 fd; // for redirections: -1 means default
};

struct sh_var {
	char name[SH_VAR_NAME_MAX];
	char val[SH_VAR_VAL_MAX];
};

struct sh_vars {
	mc_u32 n;
	struct sh_var vars[SH_MAX_VARS];
};

struct sh_ctx {
	char **envp;
	struct sh_vars vars;
	mc_i32 last_rc;
	mc_i32 last_bg_pid;
	mc_i32 opt_errexit;
	mc_i32 opt_nounset;
	struct sh_funcs funcs;
	char trap_exit[64];
	int trap_exit_set;
	int in_func_depth;
	int ret_pending;
	int ret_depth;
	int ret_code;
	int cmdsub_used;
	mc_i32 last_cmdsub_rc;
	// Positional parameters:
	// - In script mode: $0 is script path; $1.. are args.
	// - In -c mode: if extra args are provided, first becomes $0, rest $1..
	const char *posv[32];
	mc_u32 posc;
};


#define SH_MAX_REDIRS 8

enum sh_redir_kind {
	SH_REDIR_IN_FILE = 0,
	SH_REDIR_OUT_FILE,
	SH_REDIR_OUT_APP,
	SH_REDIR_DUP_OUT,
};

struct sh_redir_op {
	enum sh_redir_kind kind;
	mc_i32 fd;
	const char *path;
	int target_fd;
};

struct sh_cmd {
	const char *argv[SH_MAX_ARGS + 1];
	mc_u32 argc;
	mc_u32 nredirs;
	struct sh_redir_op redirs[SH_MAX_REDIRS];
};

// Forward declarations needed for hosted compilers (C99+ forbids implicit decls).
struct sh_tok;
struct sh_ctx;
static int sh_is_name_char(char c);
static mc_i32 sh_eval_range(const char *argv0, struct sh_tok *toks, mc_u32 start, mc_u32 end, char **envp, struct sh_ctx *ctx);

static int sh_parse_fd_dec(const char *s, mc_i32 *out_fd) {
	if (!s || !*s || !out_fd) return -1;
	mc_u32 v = 0;
	for (mc_usize i = 0; s[i]; i++) {
		char c = s[i];
		if (c < '0' || c > '9') return -1;
		v = (v * 10u) + (mc_u32)(c - '0');
		if (v > 1024u) return -1;
	}
	*out_fd = (mc_i32)v;
	return 0;
}

static void sh_write_err(const char *argv0, const char *msg) {
	(void)mc_write_str(2, argv0);
	(void)mc_write_str(2, ": ");
	(void)mc_write_str(2, msg);
	(void)mc_write_str(2, "\n");
}

static void sh_write_err2(const char *argv0, const char *a, const char *b) {
	(void)mc_write_str(2, argv0);
	(void)mc_write_str(2, ": ");
	(void)mc_write_str(2, a);
	(void)mc_write_str(2, b);
	(void)mc_write_str(2, "\n");
}

static int sh_is_funcname_char(char c) {
	return sh_is_name_char(c);
}

static int sh_word_ends_with(const char *s, const char *suf) {
	if (!s || !suf) return 0;
	mc_usize sn = mc_strlen(s);
	mc_usize un = mc_strlen(suf);
	if (un > sn) return 0;
	return mc_streq(s + (sn - un), suf);
}

static int sh_func_set(struct sh_ctx *ctx, const char *name, struct sh_tok *toks, mc_u32 body_start, mc_u32 body_end, const char *argv0) {
	if (!ctx || !name || !*name) return -1;
	// Replace if exists.
	for (mc_u32 i = 0; i < ctx->funcs.n; i++) {
		if (mc_streq(ctx->funcs.funcs[i].name, name)) {
			// Reuse slot.
			break;
		}
	}
	if (ctx->funcs.n >= SH_MAX_FUNCS) {
		sh_write_err(argv0, "too many functions");
		return -1;
	}
	struct sh_func *f = 0;
	for (mc_u32 i = 0; i < ctx->funcs.n; i++) {
		if (mc_streq(ctx->funcs.funcs[i].name, name)) {
			f = &ctx->funcs.funcs[i];
			break;
		}
	}
	if (!f) f = &ctx->funcs.funcs[ctx->funcs.n++];
	mc_usize i = 0;
	for (; name[i] && i + 1 < sizeof(f->name); i++) f->name[i] = name[i];
	f->name[i] = 0;
	// Serialize tokens in [body_start, body_end) into f->body.
	if (!toks || body_end < body_start) {
		sh_write_err(argv0, "bad function body");
		return -1;
	}
	mc_usize boff = 0;
	for (mc_u32 ti = body_start; ti < body_end; ti++) {
		struct sh_tok t = toks[ti];
		const char *emit = 0;
		if (t.kind == SH_TOK_WORD) {
			// Copy word bytes (may include SH_ESC markers).
			for (mc_usize k = 0; t.s && k < t.n; k++) {
				if (boff + 2 >= sizeof(f->body)) {
					sh_write_err(argv0, "function body too big");
					return -1;
				}
				f->body[boff++] = t.s[k];
			}
			// Space separate tokens.
			if (boff + 2 >= sizeof(f->body)) {
				sh_write_err(argv0, "function body too big");
				return -1;
			}
			f->body[boff++] = ' ';
			continue;
		}
		// Operators/separators.
		switch (t.kind) {
			case SH_TOK_SEMI: emit = ";"; break;
			case SH_TOK_PIPE: emit = "|"; break;
			case SH_TOK_OR_IF: emit = "||"; break;
			case SH_TOK_AND_IF: emit = "&&"; break;
			case SH_TOK_BG: emit = "&"; break;
			case SH_TOK_REDIR_IN: emit = "<"; break;
			case SH_TOK_REDIR_OUT: emit = ">"; break;
			case SH_TOK_REDIR_OUT_APP: emit = ">>"; break;
			case SH_TOK_REDIR_DUP_OUT: emit = ">&"; break;
			default: emit = 0; break;
		}
		if (emit) {
			for (mc_usize k = 0; emit[k]; k++) {
				if (boff + 2 >= sizeof(f->body)) {
					sh_write_err(argv0, "function body too big");
					return -1;
				}
				f->body[boff++] = emit[k];
			}
			if (boff + 2 >= sizeof(f->body)) {
				sh_write_err(argv0, "function body too big");
				return -1;
			}
			f->body[boff++] = ' ';
			continue;
		}
		// Ignore unknown token kinds.
	}
	// Trim trailing spaces.
	while (boff > 0 && (f->body[boff - 1] == ' ' || f->body[boff - 1] == '\t')) boff--;
	f->body[boff] = 0;
	return 0;
}

static const struct sh_func *sh_func_lookup(const struct sh_ctx *ctx, const char *name) {
	if (!ctx || !name || !*name) return 0;
	for (mc_u32 i = 0; i < ctx->funcs.n; i++) {
		if (mc_streq(ctx->funcs.funcs[i].name, name)) return &ctx->funcs.funcs[i];
	}
	return 0;
}

static int sh_is_name_start(char c) {
	return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c == '_';
}

static int sh_is_name_char(char c) {
	return sh_is_name_start(c) || (c >= '0' && c <= '9');
}

static int sh_is_digit(char c) {
	return (c >= '0' && c <= '9');
}

static const char *sh_vars_lookup(const struct sh_vars *vars, const char *name, mc_usize n) {
	if (!vars || !name || n == 0) return 0;
	for (mc_u32 i = vars->n; i > 0; i--) {
		const struct sh_var *v = &vars->vars[i - 1];
		// Compare name with NUL-terminated v->name.
		mc_usize j = 0;
		for (; j < n && v->name[j] != 0; j++) {
			if (v->name[j] != name[j]) break;
		}
		if (j == n && v->name[j] == 0) {
			return v->val;
		}
	}
	return 0;
}

static const char *sh_pos_lookup(const struct sh_ctx *ctx, mc_u32 idx) {
	if (!ctx) return 0;
	if (idx >= ctx->posc) return 0;
	return ctx->posv[idx];
}

static int sh_parse_i64_simple(const char *s, mc_i64 *out) {
	if (!s || !*s || !out) return -1;
	mc_i64 v = 0;
	if (mc_parse_i64_dec(s, &v) != 0) return -1;
	*out = v;
	return 0;
}

static int sh_append_i64_dec(char *buf, mc_usize buf_sz, mc_usize *ioff, mc_i64 v, const char *argv0) {
	char tmp[64];
	char *p = tmp;
	if (mc_snprint_cstr_i64_cstr(p, sizeof(tmp), "", v, "") < 0) {
		sh_write_err(argv0, "bad number");
		return -1;
	}
	for (mc_usize i = 0; tmp[i]; i++) {
		if (*ioff + 2 > buf_sz) {
			sh_write_err(argv0, "line too long");
			return -1;
		}
		buf[(*ioff)++] = tmp[i];
	}
	return 0;
}

static int sh_arith_parse_term(const char **pp, struct sh_ctx *ctx, mc_i64 *out_term, const char *argv0) {
	if (!pp || !*pp || !out_term) return -1;
	const char *p = *pp;
	while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;
	if (*p == 0) return -1;
	if (sh_is_digit(*p) || *p == '-' || *p == '+') {
		// Parse an integer term, allowing trailing expression characters.
		int neg = 0;
		if (*p == '+' || *p == '-') {
			neg = (*p == '-') ? 1 : 0;
			p++;
		}
		if (!sh_is_digit(*p)) {
			sh_write_err(argv0, "bad arithmetic");
			return -1;
		}
		mc_i64 v = 0;
		while (sh_is_digit(*p)) {
			v = (v * 10) + (mc_i64)(*p - '0');
			p++;
		}
		*out_term = neg ? -v : v;
		*pp = p;
		return 0;
	}
	if (sh_is_name_start(*p)) {
		const char *ns = p;
		mc_usize nn = 0;
		while (*p && sh_is_name_char(*p)) { p++; nn++; }
		const char *val = (ctx) ? sh_vars_lookup(&ctx->vars, ns, nn) : 0;
		if (!val) {
			if (ctx && ctx->opt_nounset) {
				sh_write_err(argv0, "unset variable in arithmetic");
				return -1;
			}
			*out_term = 0;
			*pp = p;
			return 0;
		}
		mc_i64 v = 0;
		if (sh_parse_i64_simple(val, &v) != 0) v = 0;
		*out_term = v;
		*pp = p;
		return 0;
	}
	sh_write_err(argv0, "bad arithmetic");
	return -1;
}

static int sh_eval_arith_expr(const char *expr, struct sh_ctx *ctx, mc_i64 *out, const char *argv0) {
	// Tiny arithmetic evaluator for $(( ... )):
	// supports: integers, VAR (decimal), + and - with left-to-right evaluation.
	if (!expr || !out) return -1;
	const char *p = expr;
	mc_i64 acc = 0;
	mc_i64 term0 = 0;
	if (sh_arith_parse_term(&p, ctx, &term0, argv0) != 0) {
		sh_write_err(argv0, "bad arithmetic");
		return -1;
	}
	acc = term0;

	for (;;) {
		while (*p == ' ' || *p == '\t') p++;
		if (*p == 0) break;
		char op = *p;
		if (op != '+' && op != '-') {
			sh_write_err(argv0, "bad arithmetic");
			return -1;
		}
		p++;
		mc_i64 term = 0;
		if (sh_arith_parse_term(&p, ctx, &term, argv0) != 0) {
			sh_write_err(argv0, "bad arithmetic");
			return -1;
		}
		acc = (op == '+') ? (acc + term) : (acc - term);
	}
	*out = acc;
	return 0;
}

static int sh_read_file(const char *argv0, const char *path, char *buf, mc_usize cap) {
	if (!path || !*path || !buf || cap < 2) return -1;
	mc_i64 ofd = mc_sys_openat(MC_AT_FDCWD, path, MC_O_RDONLY | MC_O_CLOEXEC, 0);
	if (ofd < 0) {
		sh_print_errno(argv0, "open", ofd);
		return -1;
	}
	mc_i32 fd = (mc_i32)ofd;
	mc_usize off = 0;
	for (;;) {
		if (off + 1 >= cap) {
			sh_write_err(argv0, "script too big");
			(void)mc_sys_close(fd);
			return -1;
		}
		mc_i64 n = mc_sys_read(fd, buf + off, (mc_usize)(cap - off - 1));
		if (n < 0) {
			sh_print_errno(argv0, "read", n);
			(void)mc_sys_close(fd);
			return -1;
		}
		if (n == 0) break;
		off += (mc_usize)n;
	}
	buf[off] = 0;
	(void)mc_sys_close(fd);
	return 0;
}

static int sh_append_u64_dec(char *buf, mc_usize buf_sz, mc_usize *ioff, mc_u64 v, const char *argv0) {
	// Appends decimal v (no trailing NUL). Returns 0 on success.
	char tmp[32];
	mc_usize n = 0;
	if (v == 0) {
		tmp[n++] = '0';
	} else {
		while (v && n < sizeof(tmp)) {
			tmp[n++] = (char)('0' + (v % 10u));
			v /= 10u;
		}
	}
	if (*ioff + n + 1 > buf_sz) {
		sh_write_err(argv0, "line too long");
		return -1;
	}
	for (mc_usize i = 0; i < n; i++) buf[(*ioff)++] = tmp[n - 1 - i];
	return 0;
}

static int sh_append_pos_join(char *buf, mc_usize buf_sz, mc_usize *ioff, const struct sh_ctx *ctx, const char *argv0) {
	// Joins $1..$N with single spaces (does not include $0).
	if (!ctx || ctx->posc <= 1) return 0;
	for (mc_u32 i = 1; i < ctx->posc; i++) {
		const char *s = ctx->posv[i];
		if (!s) continue;
		if (i != 1) {
			if (*ioff + 2 > buf_sz) {
				sh_write_err(argv0, "line too long");
				return -1;
			}
			buf[(*ioff)++] = ' ';
		}
		for (mc_usize k = 0; s[k]; k++) {
			if (*ioff + 2 > buf_sz) {
				sh_write_err(argv0, "line too long");
				return -1;
			}
			buf[(*ioff)++] = s[k];
		}
	}
	return 0;
}

static int sh_vars_push(struct sh_vars *vars, const char *name, const char *val, const char *argv0) {
	if (!vars || !name || !val) return -1;
	if (vars->n >= SH_MAX_VARS) {
		sh_write_err(argv0, "variable stack full");
		return -1;
	}
	struct sh_var *v = &vars->vars[vars->n++];
	// Copy name.
	mc_usize ni = 0;
	for (; name[ni] && ni + 1 < sizeof(v->name); ni++) v->name[ni] = name[ni];
	v->name[ni] = 0;
	// Copy value.
	mc_usize vi = 0;
	for (; val[vi] && vi + 1 < sizeof(v->val); vi++) v->val[vi] = val[vi];
	v->val[vi] = 0;
	return 0;
}

static int sh_vars_set(struct sh_vars *vars, const char *name, const char *val, const char *argv0) {
	// Set or replace NAME=VAL at the current scope.
	// Unlike push/pop (used for for-loop shadowing), this avoids unbounded growth.
	if (!vars || !name || !val) return -1;
	for (mc_u32 i = vars->n; i > 0; i--) {
		struct sh_var *v = &vars->vars[i - 1];
		// Compare name with NUL-terminated v->name.
		mc_usize j = 0;
		for (; name[j] && v->name[j]; j++) {
			if (name[j] != v->name[j]) break;
		}
		if (name[j] == 0 && v->name[j] == 0) {
			mc_usize vi = 0;
			for (; val[vi] && vi + 1 < sizeof(v->val); vi++) v->val[vi] = val[vi];
			v->val[vi] = 0;
			return 0;
		}
	}
	return sh_vars_push(vars, name, val, argv0);
}

static void sh_vars_pop(struct sh_vars *vars) {
	if (!vars || vars->n == 0) return;
	vars->n--;
}

static const char *sh_expand_word(const char *in, struct sh_ctx *ctx, char *buf, mc_usize buf_sz, mc_usize *ioff, const char *argv0);
static int sh_tokenize(const char *line, char *wordbuf, mc_usize wordbuf_sz, struct sh_tok *toks, mc_u32 *out_ntoks, const char *argv0);

static const char *sh_expand_param_word(const char *rhs, mc_usize rn, struct sh_ctx *ctx, char *out, mc_usize out_sz, mc_usize *out_off, const char *argv0) {
	// Expand RHS of ${...:=word} / ${...:-word} as a shell word (quote removal + $ expansions).
	char tmp_rhs[256];
	if (rn + 1 > sizeof(tmp_rhs)) {
		sh_write_err(argv0, "param rhs too long");
		return 0;
	}
	for (mc_usize k = 0; k < rn; k++) tmp_rhs[k] = rhs[k];
	tmp_rhs[rn] = 0;

	char wbuf[SH_MAX_LINE];
	struct sh_tok toks[64];
	mc_u32 nt = 0;
	if (sh_tokenize(tmp_rhs, wbuf, sizeof(wbuf), toks, &nt, argv0) != 0) return 0;

	int first = 1;
	for (mc_u32 ti = 0; ti < nt; ti++) {
		if (toks[ti].kind == SH_TOK_END) break;
		if (toks[ti].kind != SH_TOK_WORD || !toks[ti].s) {
			sh_write_err(argv0, "bad param rhs");
			return 0;
		}
		if (!first) {
			if (*out_off + 2 > out_sz) {
				sh_write_err(argv0, "line too long");
				return 0;
			}
			out[(*out_off)++] = ' ';
		}
		first = 0;
		const char *rhs_ex = sh_expand_word(toks[ti].s, ctx, out, out_sz, out_off, argv0);
		if (!rhs_ex) return 0;
		(void)rhs_ex;
	}
	out[*out_off] = 0;
	return out;
}

static int sh_cmdsub(const char *cmd, struct sh_ctx *ctx, char *buf, mc_usize buf_sz, mc_usize *ioff, const char *argv0) {
	// Minimal $(...) command substitution. No nesting, no quoting awareness.
	// Captures stdout, replaces newlines with spaces, strips trailing newlines.
	if (!cmd) return 0;
	mc_i32 pipefd[2];
	mc_i64 pr = mc_sys_pipe2(pipefd, MC_O_CLOEXEC);
	if (pr < 0) {
		sh_print_errno(argv0, "pipe2", pr);
		return -1;
	}
	// IMPORTANT: command substitution runs shell evaluation in the child.
	// Using vfork() here is unsafe because the child mutates stack/heap state
	// before exiting. Use fork().
	mc_i64 vr = mc_sys_fork();
	if (vr < 0) {
		sh_print_errno(argv0, "fork", vr);
		(void)mc_sys_close(pipefd[0]);
		(void)mc_sys_close(pipefd[1]);
		return -1;
	}
	if (vr == 0) {
		(void)mc_sys_close(pipefd[0]);
		(void)mc_sys_dup2(pipefd[1], 1);
		(void)mc_sys_close(pipefd[1]);
		static char wordbuf[SH_MAX_WORDBUF];
		static struct sh_tok toks[SH_MAX_TOKS];
		mc_u32 ntoks = 0;
		if (sh_tokenize(cmd, wordbuf, sizeof(wordbuf), toks, &ntoks, argv0) != 0) mc_exit(2);
		struct sh_ctx sub = *ctx;
		// subshell-like: do not propagate last_rc/bg_pid changes back.
		sub.last_rc = ctx ? ctx->last_rc : 0;
		sub.last_bg_pid = 0;
		char **sub_envp = (ctx && ctx->envp) ? ctx->envp : mc_get_start_envp();
		mc_i32 rc = sh_eval_range(argv0, toks, 0, ntoks, sub_envp, &sub);
		mc_exit(rc);
	}
	(void)mc_sys_close(pipefd[1]);
	char tmp[512];
	mc_usize outn = 0;
	for (;;) {
		mc_i64 n = mc_sys_read(pipefd[0], tmp, sizeof(tmp));
		if (n < 0) break;
		if (n == 0) break;
		for (mc_i64 k = 0; k < n; k++) {
			char c = tmp[k];
			if (c == '\n') c = ' ';
			if (outn + 1 >= sizeof(tmp)) { /* no-op */ }
			if (*ioff + 2 > buf_sz) {
				sh_write_err(argv0, "line too long");
				(void)mc_sys_close(pipefd[0]);
				return -1;
			}
			buf[(*ioff)++] = c;
			outn++;
		}
	}
	(void)mc_sys_close(pipefd[0]);
	// Wait child.
	mc_i32 st = 0;
	mc_i64 wr = mc_sys_wait4((mc_i32)vr, &st, 0, 0);
	mc_i32 rc = 0;
	if (wr < 0) {
		rc = 1;
	} else {
		mc_i32 sig = (st & 127);
		if (sig != 0) rc = 128 + sig;
		else rc = (st >> 8) & 255;
	}
	if (ctx) {
		ctx->cmdsub_used = 1;
		ctx->last_cmdsub_rc = rc;
	}
	// Trim trailing spaces.
	while (*ioff > 0 && buf[*ioff - 1] == ' ') (*ioff)--;
	(void)outn;
	return 0;
}

static const char *sh_env_lookup(char **envp, const char *name, mc_usize nn) {
	if (!envp || !name || nn == 0) return 0;
	for (mc_usize i = 0; envp[i]; i++) {
		const char *e = envp[i];
		mc_usize j = 0;
		while (e[j] && e[j] != '=') j++;
		if (e[j] != '=') continue;
		if (j != nn) continue;
		// Compare NAME part.
		int ok = 1;
		for (mc_usize k = 0; k < nn; k++) {
			if (e[k] != name[k]) {
				ok = 0;
				break;
			}
		}
		if (!ok) continue;
		return e + j + 1;
	}
	return 0;
}

static const char *sh_expand_word(const char *in, struct sh_ctx *ctx, char *buf, mc_usize buf_sz, mc_usize *ioff, const char *argv0) {
	// Expands:
	// - $NAME: for-loop variables (stack)
	// - $0..$N: positional parameters
	// - $#: number of positional parameters (excluding $0)
	// - $@ and $*: join $1..$N with spaces
	// No ${} support.
	if (!in) return "";
	mc_usize start = *ioff;
	const char *p = in;
	while (*p) {
		char c = *p++;
		if (c == SH_ESC) {
			char lit = *p ? *p++ : 0;
			if (lit == 0) {
				sh_write_err(argv0, "bad escape");
				return 0;
			}
			if (*ioff + 2 > buf_sz) {
				sh_write_err(argv0, "line too long");
				return 0;
			}
			buf[(*ioff)++] = lit;
			continue;
		}
		// Arithmetic expansion $((...)) must be checked before $(...).
		if (c == '$' && *p == '(' && *(p + 1) == '(') {
			p += 2;
			const char *es = p;
			mc_usize en = 0;
			while (*p && !(*p == ')' && *(p + 1) == ')')) { p++; en++; }
			if (!*p) {
				sh_write_err(argv0, "unterminated arithmetic expansion");
				return 0;
			}
			char expr[256];
			if (en + 1 > sizeof(expr)) {
				sh_write_err(argv0, "arithmetic expansion too long");
				return 0;
			}
			for (mc_usize k = 0; k < en; k++) expr[k] = es[k];
			expr[en] = 0;
			p += 2; // consume '))'
			mc_i64 v = 0;
			if (sh_eval_arith_expr(expr, ctx, &v, argv0) != 0) return 0;
			if (sh_append_i64_dec(buf, buf_sz, ioff, v, argv0) != 0) return 0;
			continue;
		}
			// Command substitution $(...) (quote-aware, supports nested parentheses).
			if (c == '$' && *p == '(') {
				p++;
				const char *cs = p;
				int in_sq = 0;
				int in_dq = 0;
				mc_i32 depth = 1;
				mc_usize cn = 0;
				while (*p) {
					char cc = *p;
					if (in_sq) {
						if (cc == '\'') in_sq = 0;
					} else if (in_dq) {
						if (cc == '"') in_dq = 0;
						else if (cc == '\\') {
							// skip escaped byte
							p++;
							cn++;
							if (!*p) break;
							p++;
							cn++;
							continue;
						}
					} else {
						if (cc == '\\') {
							p++;
							cn++;
							if (!*p) break;
							p++;
							cn++;
							continue;
						}
						if (cc == '\'') in_sq = 1;
						else if (cc == '"') in_dq = 1;
						else if (cc == '(') depth++;
						else if (cc == ')') {
							depth--;
							if (depth == 0) break;
						}
					}
					p++;
					cn++;
				}
				if (*p != ')' || depth != 0) {
					sh_write_err(argv0, "unterminated command substitution");
					return 0;
				}
				char cmd[1024];
				if (cn + 1 > sizeof(cmd)) {
					sh_write_err(argv0, "command substitution too long");
					return 0;
				}
				for (mc_usize i2 = 0; i2 < cn; i2++) cmd[i2] = cs[i2];
				cmd[cn] = 0;
				p++; // consume ')'
				if (sh_cmdsub(cmd, ctx, buf, buf_sz, ioff, argv0) != 0) return 0;
				continue;
			}
		if (c == '$' && *p == '!') {
			p++;
			mc_u64 v = 0;
			if (ctx && ctx->last_bg_pid > 0) v = (mc_u64)ctx->last_bg_pid;
			if (sh_append_u64_dec(buf, buf_sz, ioff, v, argv0) != 0) return 0;
			continue;
		}
		if (c == '$' && *p == '?') {
			p++;
			mc_u64 v = 0;
			if (ctx) {
				mc_i64 lr = (mc_i64)ctx->last_rc;
				if (lr < 0) lr = 0;
				v = (mc_u64)lr;
			}
			if (sh_append_u64_dec(buf, buf_sz, ioff, v, argv0) != 0) return 0;
			continue;
		}
		if (c == '$' && *p == '#') {
			p++;
			mc_u64 argc1 = 0;
			if (ctx && ctx->posc > 1) argc1 = (mc_u64)(ctx->posc - 1);
			if (sh_append_u64_dec(buf, buf_sz, ioff, argc1, argv0) != 0) return 0;
			continue;
		}
		if (c == '$' && (*p == '@' || *p == '*')) {
			p++;
			if (sh_append_pos_join(buf, buf_sz, ioff, ctx, argv0) != 0) return 0;
			continue;
		}
		if (c == '$' && sh_is_digit(*p)) {
			// Positional parameter: one or more digits.
			const char *ds = p;
			mc_usize dn = 0;
			while (*p && sh_is_digit(*p)) {
				p++;
				dn++;
			}
			mc_u32 idx = 0;
			if (mc_parse_u32_dec_n(ds, dn, &idx) == 0) {
				const char *val = sh_pos_lookup(ctx, idx);
				if (val) {
					for (mc_usize k = 0; val[k]; k++) {
						if (*ioff + 2 > buf_sz) {
							sh_write_err(argv0, "line too long");
							return 0;
						}
						buf[(*ioff)++] = val[k];
					}
					continue;
				}
			}
			// Unknown positional: expand to empty (or error under -u).
			if (ctx && ctx->opt_nounset) {
				sh_write_err(argv0, "unset positional parameter");
				return 0;
			}
			continue;
		}
		if (c == '$' && sh_is_name_start(*p)) {
			const char *ns = p;
			mc_usize nn = 0;
			while (*p && sh_is_name_char(*p)) {
				p++;
				nn++;
			}
			const char *val = 0;
			if (ctx) val = sh_vars_lookup(&ctx->vars, ns, nn);
			if (!val) val = sh_env_lookup(ctx ? ctx->envp : 0, ns, nn);
			if (val) {
				for (mc_usize k = 0; val[k]; k++) {
					if (*ioff + 2 > buf_sz) {
						sh_write_err(argv0, "line too long");
						return 0;
					}
					buf[(*ioff)++] = val[k];
				}
				continue;
			}
			// Unknown var expands to empty (or error under -u).
			if (ctx && ctx->opt_nounset) {
				sh_write_err(argv0, "unset variable");
				return 0;
			}
			continue;
		}
		if (c == '$' && *p == '{') {
			p++;
			const char *ns = p;
			mc_usize nn = 0;
			if (sh_is_digit(*p)) {
				while (*p && sh_is_digit(*p)) { p++; nn++; }
			} else {
				if (!sh_is_name_start(*p)) {
					sh_write_err(argv0, "bad parameter expansion");
					return 0;
				}
				while (*p && sh_is_name_char(*p)) { p++; nn++; }
			}
			const char *op = p;
			// Read operator
			int op_kind = 0;
			if (*p == ':' && (*(p + 1) == '=' || *(p + 1) == '?' || *(p + 1) == '-')) {
				op_kind = *(p + 1);
				p += 2;
			} else if (*p == '}') {
				op_kind = 0;
			} else {
				sh_write_err(argv0, "bad parameter expansion");
				return 0;
			}
			const char *rhs = p;
			mc_usize rn = 0;
			while (*p && *p != '}') { p++; rn++; }
			if (*p != '}') {
				sh_write_err(argv0, "unterminated parameter expansion");
				return 0;
			}
			p++; // consume '}'
			// Lookup parameter.
			const char *val = 0;
			char name_buf[SH_VAR_NAME_MAX];
			int is_pos = 0;
			mc_u32 pos_idx = 0;
			if (nn > 0 && sh_is_digit(ns[0])) {
				is_pos = 1;
				if (mc_parse_u32_dec_n(ns, nn, &pos_idx) != 0) pos_idx = 0;
				val = sh_pos_lookup(ctx, pos_idx);
			} else {
				mc_usize ni = 0;
				for (; ni < nn && ni + 1 < sizeof(name_buf); ni++) name_buf[ni] = ns[ni];
				name_buf[ni] = 0;
				val = 0;
				if (ctx) val = sh_vars_lookup(&ctx->vars, ns, nn);
				if (!val) val = sh_env_lookup(ctx ? ctx->envp : 0, ns, nn);
			}
			int is_unset_or_empty = (!val || !*val);
			if (op_kind == '=') {
				if (is_pos) {
					sh_write_err(argv0, "cannot assign to positional parameter");
					return 0;
				}
				if (is_unset_or_empty) {
					char rhs_buf[SH_VAR_VAL_MAX];
					mc_usize roff = 0;
					const char *rhs_ex = sh_expand_param_word(rhs, rn, ctx, rhs_buf, sizeof(rhs_buf), &roff, argv0);
					if (!rhs_ex) return 0;
					if (sh_vars_set(&ctx->vars, name_buf, rhs_ex, argv0) != 0) return 0;
					val = sh_vars_lookup(&ctx->vars, ns, nn);
				}
			} else if (op_kind == '?') {
				if (is_unset_or_empty) {
					if (rn > 0) {
						char msg[256];
						mc_usize mi = 0;
						for (; mi < rn && mi + 1 < sizeof(msg); mi++) msg[mi] = rhs[mi];
						msg[mi] = 0;
						sh_write_err2(argv0, "parameter: ", msg);
					} else {
						sh_write_err(argv0, "parameter expansion error");
					}
					return 0;
				}
			} else if (op_kind == '-') {
				if (is_unset_or_empty) {
					// substitute RHS
					char rhs_buf[SH_VAR_VAL_MAX];
					mc_usize roff = 0;
					const char *rhs_ex = sh_expand_param_word(rhs, rn, ctx, rhs_buf, sizeof(rhs_buf), &roff, argv0);
					if (!rhs_ex) return 0;
					val = rhs_ex;
				}
			}
			if (val) {
				for (mc_usize k = 0; val[k]; k++) {
					if (*ioff + 2 > buf_sz) {
						sh_write_err(argv0, "line too long");
						return 0;
					}
					buf[(*ioff)++] = val[k];
				}
			}
			(void)op;
			continue;
		}
		if (c == '$' && *p == '(' && *(p + 1) == '(') {
			// Arithmetic expansion $((...))
			p += 2;
			const char *es = p;
			mc_usize en = 0;
			while (*p && !(*p == ')' && *(p + 1) == ')')) { p++; en++; }
			if (!*p) {
				sh_write_err(argv0, "unterminated arithmetic expansion");
				return 0;
			}
			char expr[256];
			if (en + 1 > sizeof(expr)) {
				sh_write_err(argv0, "arithmetic expansion too long");
				return 0;
			}
			for (mc_usize k = 0; k < en; k++) expr[k] = es[k];
			expr[en] = 0;
			p += 2; // consume '))'
			mc_i64 v = 0;
			if (sh_eval_arith_expr(expr, ctx, &v, argv0) != 0) return 0;
			if (sh_append_i64_dec(buf, buf_sz, ioff, v, argv0) != 0) return 0;
			continue;
		}
		if (*ioff + 2 > buf_sz) {
			sh_write_err(argv0, "line too long");
			return 0;
		}
		buf[(*ioff)++] = c;
	}
	if (*ioff + 1 > buf_sz) {
		sh_write_err(argv0, "line too long");
		return 0;
	}
	buf[(*ioff)++] = 0;
	return buf + start;
}

static int sh_is_assign_word(const char *w, mc_usize *out_eq) {
	// Accept NAME=VALUE where NAME matches [A-Za-z_][A-Za-z0-9_]*.
	if (!w || !*w) return 0;
	mc_usize i = 0;
	if (!sh_is_name_start(w[i])) return 0;
	for (; w[i]; i++) {
		if (w[i] == '=') {
			if (out_eq) *out_eq = i;
			return 1;
		}
		if (!sh_is_name_char(w[i])) return 0;
	}
	return 0;
}

static int sh_tokenize(const char *line, char *wordbuf, mc_usize wordbuf_sz, struct sh_tok *toks, mc_u32 *out_ntoks, const char *argv0) {
	mc_u32 nt = 0;
	mc_usize woff = 0;
	const char *p = line;
	while (*p) {
		// Skip whitespace
		while (*p == ' ' || *p == '\t' || *p == '\r') p++;
		if (*p == '\n') {
			// Newlines act like ';' separators for script tokenization.
			toks[nt++] = (struct sh_tok){ .kind = SH_TOK_SEMI, .s = p, .n = 1 };
			p++;
			continue;
		}
		if (*p == 0) break;

		// Comment (only if starts a token): skip to end of line.
		if (*p == '#') {
			while (*p && *p != '\n') p++;
			continue;
		}

		if (nt + 1 >= SH_MAX_TOKS) {
			sh_write_err(argv0, "line too complex");
			return -1;
		}

		if (*p == ';') {
			toks[nt] = (struct sh_tok){ .kind = SH_TOK_SEMI, .s = p, .n = 1 };
			toks[nt].fd = -1;
			nt++;
			p++;
			continue;
		}
		if (*p == '&') {
			if (*(p + 1) == '&') {
				toks[nt] = (struct sh_tok){ .kind = SH_TOK_AND_IF, .s = p, .n = 2 };
				toks[nt].fd = -1;
				nt++;
				p += 2;
				continue;
			}
			toks[nt] = (struct sh_tok){ .kind = SH_TOK_BG, .s = p, .n = 1 };
			toks[nt].fd = -1;
			nt++;
			p++;
			continue;
		}
		if (*p == '|') {
			if (*(p + 1) == '|') {
				toks[nt] = (struct sh_tok){ .kind = SH_TOK_OR_IF, .s = p, .n = 2 };
				toks[nt].fd = -1;
				nt++;
				p += 2;
			} else {
				toks[nt] = (struct sh_tok){ .kind = SH_TOK_PIPE, .s = p, .n = 1 };
				toks[nt].fd = -1;
				nt++;
				p++;
			}
			continue;
		}

		// Redirections with optional leading fd digits (e.g., 2>file, 3>>file).
		if (sh_is_digit(*p)) {
			const char *ds = p;
			mc_usize dn = 0;
			while (sh_is_digit(*p)) {
				p++;
				dn++;
			}
			if (*p == '<' || *p == '>') {
				mc_u32 fd_u = 0;
				if (mc_parse_u32_dec_n(ds, dn, &fd_u) != 0 || fd_u > 1024u) {
					sh_write_err(argv0, "bad redir fd");
					return -1;
				}
				if (*p == '<') {
					toks[nt] = (struct sh_tok){ .kind = SH_TOK_REDIR_IN, .s = p, .n = 1 };
					toks[nt].fd = (mc_i32)fd_u;
					nt++;
					p++;
					continue;
				}
				// '>'
				if (*(p + 1) == '&') {
					toks[nt] = (struct sh_tok){ .kind = SH_TOK_REDIR_DUP_OUT, .s = p, .n = 2 };
					toks[nt].fd = (mc_i32)fd_u;
					nt++;
					p += 2;
					continue;
				}
				if (*(p + 1) == '>') {
					toks[nt] = (struct sh_tok){ .kind = SH_TOK_REDIR_OUT_APP, .s = p, .n = 2 };
					toks[nt].fd = (mc_i32)fd_u;
					nt++;
					p += 2;
					continue;
				}
				toks[nt] = (struct sh_tok){ .kind = SH_TOK_REDIR_OUT, .s = p, .n = 1 };
				toks[nt].fd = (mc_i32)fd_u;
				nt++;
				p++;
				continue;
			}
			// Not a redirection; rewind and parse as a WORD.
			p = ds;
		}

		if (*p == '<') {
			toks[nt] = (struct sh_tok){ .kind = SH_TOK_REDIR_IN, .s = p, .n = 1 };
			toks[nt].fd = -1;
			nt++;
			p++;
			continue;
		}
		if (*p == '>') {
			if (*(p + 1) == '&') {
				toks[nt] = (struct sh_tok){ .kind = SH_TOK_REDIR_DUP_OUT, .s = p, .n = 2 };
				toks[nt].fd = -1;
				nt++;
				p += 2;
				continue;
			}
			if (*(p + 1) == '>') {
				toks[nt] = (struct sh_tok){ .kind = SH_TOK_REDIR_OUT_APP, .s = p, .n = 2 };
				toks[nt].fd = -1;
				nt++;
				p += 2;
			} else {
				toks[nt] = (struct sh_tok){ .kind = SH_TOK_REDIR_OUT, .s = p, .n = 1 };
				toks[nt].fd = -1;
				nt++;
				p++;
			}
			continue;
		}

		// WORD (supports quotes)
		if (woff + 1 >= wordbuf_sz) {
			sh_write_err(argv0, "line too long");
			return -1;
		}
		char *w_start = wordbuf + woff;
		char *w_out = w_start;
		while (*p) {
			char c = *p;
			if (c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == ';' || c == '|' || c == '&' || c == '<' || c == '>') {
				break;
			}
			// Keep parameter/arith/cmdsub expansions intact even if they contain spaces.
			// This is critical for harness scripts that use: $((N + 2)) and X=$(cmd with args).
			if (c == '$' && *(p + 1) == '(') {
				// $((...)) arithmetic expansion
				if (*(p + 2) == '(') {
					if ((mc_usize)(w_out - wordbuf) + 4 > wordbuf_sz) {
						sh_write_err(argv0, "line too long");
						return -1;
					}
					*w_out++ = '$';
					*w_out++ = '(';
					*w_out++ = '(';
					p += 3;
					while (*p && !(*p == ')' && *(p + 1) == ')')) {
						if ((mc_usize)(w_out - wordbuf) + 2 > wordbuf_sz) {
							sh_write_err(argv0, "line too long");
							return -1;
						}
						*w_out++ = *p++;
					}
					if (!*p) {
						sh_write_err(argv0, "unterminated arithmetic expansion");
						return -1;
					}
					if ((mc_usize)(w_out - wordbuf) + 3 > wordbuf_sz) {
						sh_write_err(argv0, "line too long");
						return -1;
					}
					*w_out++ = ')';
					*w_out++ = ')';
					p += 2;
					continue;
				}
				// $(...) command substitution
				if ((mc_usize)(w_out - wordbuf) + 3 > wordbuf_sz) {
					sh_write_err(argv0, "line too long");
					return -1;
				}
				*w_out++ = '$';
				*w_out++ = '(';
				p += 2;
				int in_sq = 0;
				int in_dq = 0;
				mc_i32 depth = 1;
				while (*p) {
					char cc = *p;
					if (in_sq) {
						if (cc == '\'') in_sq = 0;
						// no escapes in single quotes
					} else if (in_dq) {
						if (cc == '"') {
							in_dq = 0;
						} else if (cc == '\\') {
							if ((mc_usize)(w_out - wordbuf) + 3 > wordbuf_sz) {
								sh_write_err(argv0, "line too long");
								return -1;
							}
							*w_out++ = *p++;
							if (!*p) break;
							*w_out++ = *p++;
							continue;
						}
						// Parens inside double-quotes do not affect cmdsub termination.
					} else {
						if (cc == '\\') {
							if ((mc_usize)(w_out - wordbuf) + 3 > wordbuf_sz) {
								sh_write_err(argv0, "line too long");
								return -1;
							}
							*w_out++ = *p++;
							if (!*p) break;
							*w_out++ = *p++;
							continue;
						}
						if (cc == '\'') in_sq = 1;
						else if (cc == '"') in_dq = 1;
						else if (cc == '(') depth++;
						else if (cc == ')') {
							depth--;
							if (depth == 0) break;
						}
					}
					if ((mc_usize)(w_out - wordbuf) + 2 > wordbuf_sz) {
						sh_write_err(argv0, "line too long");
						return -1;
					}
					*w_out++ = *p++;
				}
				if (*p != ')' || depth != 0) {
					sh_write_err(argv0, "unterminated command substitution");
					return -1;
				}
				if ((mc_usize)(w_out - wordbuf) + 2 > wordbuf_sz) {
					sh_write_err(argv0, "line too long");
					return -1;
				}
				*w_out++ = ')';
				p++;
				continue;
			}
			if (c == '$' && *(p + 1) == '{') {
				// ${...} parameter expansion
				if ((mc_usize)(w_out - wordbuf) + 3 > wordbuf_sz) {
					sh_write_err(argv0, "line too long");
					return -1;
				}
				*w_out++ = '$';
				*w_out++ = '{';
				p += 2;
				while (*p && *p != '}') {
					if ((mc_usize)(w_out - wordbuf) + 2 > wordbuf_sz) {
						sh_write_err(argv0, "line too long");
						return -1;
					}
					*w_out++ = *p++;
				}
				if (*p != '}') {
					sh_write_err(argv0, "unterminated parameter expansion");
					return -1;
				}
				if ((mc_usize)(w_out - wordbuf) + 2 > wordbuf_sz) {
					sh_write_err(argv0, "line too long");
					return -1;
				}
				*w_out++ = '}';
				p++;
				continue;
			}
			if (c == '\'' || c == '"') {
				char q = c;
				p++;
				while (*p && *p != q) {
					char qc = *p;
					if (q == '"' && qc == '\\') {
						p++;
						if (!*p) break;
						char esc = *p;
						if (esc == 'n') {
							qc = '\n';
							if ((mc_usize)(w_out - wordbuf) + 2 > wordbuf_sz) {
								sh_write_err(argv0, "line too long");
								return -1;
							}
							*w_out++ = qc;
							p++;
							continue;
						}
						if (esc == 't') {
							qc = '\t';
							if ((mc_usize)(w_out - wordbuf) + 2 > wordbuf_sz) {
								sh_write_err(argv0, "line too long");
								return -1;
							}
							*w_out++ = qc;
							p++;
							continue;
						}
						qc = esc;
						// Escaped byte inside double-quotes: mark literal.
						if ((mc_usize)(w_out - wordbuf) + 3 > wordbuf_sz) {
							sh_write_err(argv0, "line too long");
							return -1;
						}
						*w_out++ = SH_ESC;
						*w_out++ = qc;
						p++;
						continue;
					}
					if (q == '\'' ) {
						// Single quotes: bytes are literal, no expansion.
						if ((mc_usize)(w_out - wordbuf) + 3 > wordbuf_sz) {
							sh_write_err(argv0, "line too long");
							return -1;
						}
						*w_out++ = SH_ESC;
						*w_out++ = qc;
						p++;
						continue;
					}
					if ((mc_usize)(w_out - wordbuf) + 2 > wordbuf_sz) {
						sh_write_err(argv0, "line too long");
						return -1;
					}
					*w_out++ = qc;
					p++;
				}
				if (*p != q) {
					sh_write_err(argv0, "unterminated quote");
					return -1;
				}
				p++;
				continue;
			}
			if (c == '\\') {
				// Simple escape: take next byte literally.
				p++;
				if (!*p) break;
				if ((mc_usize)(w_out - wordbuf) + 3 > wordbuf_sz) {
					sh_write_err(argv0, "line too long");
					return -1;
				}
				*w_out++ = SH_ESC;
				*w_out++ = *p++;
				continue;
			}
			if ((mc_usize)(w_out - wordbuf) + 2 > wordbuf_sz) {
				sh_write_err(argv0, "line too long");
				return -1;
			}
			*w_out++ = *p++;
		}
		*w_out = 0;
		mc_usize wn = (mc_usize)(w_out - w_start);
		toks[nt] = (struct sh_tok){ .kind = SH_TOK_WORD, .s = w_start, .n = wn };
		toks[nt].fd = -1;
		nt++;
		woff += wn + 1;
	}
	if (nt + 1 >= SH_MAX_TOKS) {
		sh_write_err(argv0, "line too complex");
		return -1;
	}
	toks[nt] = (struct sh_tok){ .kind = SH_TOK_END, .s = p, .n = 0 };
	toks[nt].fd = -1;
	nt++;
	*out_ntoks = nt;
	return 0;
}

static int sh_tok_is_word(const struct sh_tok *t, const char *w) {
	return t && t->kind == SH_TOK_WORD && w && mc_streq(t->s, w);
}

static void sh_consume_sep(struct sh_tok *toks, mc_u32 end, mc_u32 *io, int *next_and, int *next_or) {
	if (!toks || !io) return;
	mc_u32 i = *io;
	if (i >= end) return;
	// Note: background '&' is treated as a separator like ';'.
	if (toks[i].kind == SH_TOK_AND_IF) {
		if (next_and) *next_and = 1;
		if (next_or) *next_or = 0;
		i++;
	} else if (toks[i].kind == SH_TOK_OR_IF) {
		if (next_or) *next_or = 1;
		if (next_and) *next_and = 0;
		i++;
	} else if (toks[i].kind == SH_TOK_SEMI || toks[i].kind == SH_TOK_BG) {
		i++;
	}
	*io = i;
}

static int sh_consume_bg(struct sh_tok *toks, mc_u32 end, mc_u32 *io) {
	if (!toks || !io) return 0;
	mc_u32 i = *io;
	if (i >= end) return 0;
	if (toks[i].kind == SH_TOK_BG) {
		*io = i + 1;
		return 1;
	}
	return 0;
}

static void sh_reap_zombies(const char *argv0) {
	// Best-effort: reap any finished background children.
	// Linux WNOHANG == 1.
	for (;;) {
		mc_i32 st = 0;
		mc_i64 wr = mc_sys_wait4(-1, &st, 1, 0);
		if (wr <= 0) break;
		(void)argv0;
	}
}

static int sh_parse_pipeline(struct sh_tok *toks, mc_u32 ntoks, mc_u32 *io, struct sh_cmd *cmds, mc_u32 *out_ncmds, struct sh_ctx *ctx,
				   char *argbuf, mc_usize argbuf_sz, mc_usize *io_argoff, const char *argv0) {
	mc_u32 i = *io;
	mc_u32 nc = 0;
	while (1) {
		if (nc >= SH_MAX_CMDS) {
			sh_write_err(argv0, "too many pipeline commands");
			return -1;
		}
		struct sh_cmd *cmd = &cmds[nc];
		cmd->argc = 0;
		cmd->nredirs = 0;

		int saw_word = 0;
		int saw_cmd = 0;
		while (i < ntoks) {
			enum sh_tok_kind k = toks[i].kind;
			if (k == SH_TOK_WORD) {
				saw_word = 1;
				// Handle leading NAME=VALUE assignments.
				if (!saw_cmd) {
					mc_usize eq = 0;
					if (sh_is_assign_word(toks[i].s, &eq)) {
						// Expand VALUE portion.
						const char *val_src = toks[i].s + eq + 1;
						const char *val_ex = sh_expand_word(val_src, ctx, argbuf, argbuf_sz, io_argoff, argv0);
						if (!val_ex) return -1;
						// Copy NAME into a temporary NUL-terminated buffer.
						char name[SH_VAR_NAME_MAX];
						mc_usize ni = 0;
						for (; ni < eq && ni + 1 < sizeof(name); ni++) name[ni] = toks[i].s[ni];
						name[ni] = 0;
						if (sh_vars_set(&ctx->vars, name, val_ex, argv0) != 0) return -1;
						i++;
						continue;
					}
				}
				saw_cmd = 1;
				if (cmd->argc + 1 >= SH_MAX_ARGS) {
					sh_write_err(argv0, "too many args");
					return -1;
				}
				// Special-case $@/$* so callers can forward argv correctly.
				if (ctx && toks[i].s && (mc_streq(toks[i].s, "$@") || mc_streq(toks[i].s, "$*"))) {
					for (mc_u32 pi = 1; pi < ctx->posc; pi++) {
						if (cmd->argc + 1 >= SH_MAX_ARGS) {
							sh_write_err(argv0, "too many args");
							return -1;
						}
						cmd->argv[cmd->argc++] = ctx->posv[pi];
					}
					i++;
					continue;
				}
				const char *ex = sh_expand_word(toks[i].s, ctx, argbuf, argbuf_sz, io_argoff, argv0);
				if (!ex) return -1;
				cmd->argv[cmd->argc++] = ex;
				i++;
				continue;
			}
			if (k == SH_TOK_REDIR_IN || k == SH_TOK_REDIR_OUT || k == SH_TOK_REDIR_OUT_APP || k == SH_TOK_REDIR_DUP_OUT) {
				enum sh_tok_kind rk = k;
				mc_i32 redir_fd = toks[i].fd;
				i++;
				if (i >= ntoks || toks[i].kind != SH_TOK_WORD) {
					sh_write_err(argv0, "redir missing path");
					return -1;
				}
				if (cmd->nredirs >= SH_MAX_REDIRS) {
					sh_write_err(argv0, "too many redirections");
					return -1;
				}
				const char *rhs_ex = sh_expand_word(toks[i].s, ctx, argbuf, argbuf_sz, io_argoff, argv0);
				if (!rhs_ex) return -1;
				if (rk == SH_TOK_REDIR_DUP_OUT) {
					mc_i32 lhs = (redir_fd >= 0) ? redir_fd : 1;
					mc_i32 rhs = -1;
					if (sh_parse_fd_dec(rhs_ex, &rhs) != 0) {
						sh_write_err(argv0, "bad dup redir fd");
						return -1;
					}
					cmd->redirs[cmd->nredirs++] = (struct sh_redir_op){
						.kind = SH_REDIR_DUP_OUT,
						.fd = lhs,
						.path = 0,
						.target_fd = rhs,
					};
				} else if (rk == SH_TOK_REDIR_IN) {
					mc_i32 lhs = (redir_fd >= 0) ? redir_fd : 0;
					cmd->redirs[cmd->nredirs++] = (struct sh_redir_op){
						.kind = SH_REDIR_IN_FILE,
						.fd = lhs,
						.path = rhs_ex,
						.target_fd = -1,
					};
				} else {
					mc_i32 lhs = (redir_fd >= 0) ? redir_fd : 1;
					cmd->redirs[cmd->nredirs++] = (struct sh_redir_op){
						.kind = (rk == SH_TOK_REDIR_OUT_APP) ? SH_REDIR_OUT_APP : SH_REDIR_OUT_FILE,
						.fd = lhs,
						.path = rhs_ex,
						.target_fd = -1,
					};
				}
				i++;
				continue;
			}
			break;
		}

		if (!saw_word) {
			// Empty command; allow at end.
			return -1;
		}
		cmd->argv[cmd->argc] = 0;
		nc++;

		if (i < ntoks && toks[i].kind == SH_TOK_PIPE) {
			i++;
			continue;
		}
		break;
	}
	*io = i;
	*out_ncmds = nc;
	return 0;
}

static int sh_tokenize(const char *line, char *wordbuf, mc_usize wordbuf_sz, struct sh_tok *toks, mc_u32 *out_ntoks, const char *argv0);

static void sh_run_trap_exit(const char *argv0, struct sh_ctx *ctx, char **envp) {
	if (!ctx || !ctx->trap_exit_set || !ctx->trap_exit[0]) return;
	char wordbuf[SH_MAX_LINE];
	struct sh_tok toks[SH_FUNC_CALL_MAX_TOKS];
	mc_u32 nt = 0;
	if (sh_tokenize(ctx->trap_exit, wordbuf, sizeof(wordbuf), toks, &nt, argv0) != 0) return;
	(void)sh_eval_range(argv0, toks, 0, nt, envp, ctx);
}

static void sh_do_exit(const char *argv0, struct sh_ctx *ctx, char **envp, mc_i32 code) {
	sh_run_trap_exit(argv0, ctx, envp);
	mc_exit(code);
}

static int sh_match_pat(const char *pat, const char *s) {
	// Minimal glob matcher supporting '*', '?', and literal bytes.
	if (!pat) pat = "";
	if (!s) s = "";
	const char *p = pat;
	const char *t = s;
	const char *star = 0;
	const char *star_t = 0;
	while (*t) {
		if (*p == '*') {
			star = p++;
			star_t = t;
			continue;
		}
		if (*p == '?' || *p == *t) {
			p++;
			t++;
			continue;
		}
		if (star) {
			p = star + 1;
			t = ++star_t;
			continue;
		}
		return 0;
	}
	while (*p == '*') p++;
	return (*p == 0);
}

static mc_i32 sh_exec_case(const char *argv0, struct sh_tok *toks, mc_u32 end, mc_u32 *pi, int should_run, char **envp, struct sh_ctx *ctx, mc_i32 last_rc) {
	// case WORD in PAT) LIST ;; ... esac
	mc_u32 i = *pi;
	if ((i + 2) >= end) {
		sh_write_err(argv0, "case: syntax");
		return 2;
	}
	char wbuf[SH_MAX_LINE];
	mc_usize woff = 0;
	if (!toks[i + 1].s) {
		sh_write_err(argv0, "case: missing word");
		return 2;
	}
	const char *wexp = sh_expand_word(toks[i + 1].s, ctx, wbuf, sizeof(wbuf), &woff, argv0);
	if (!wexp) return 2;
	if (toks[i + 2].kind != SH_TOK_WORD || !toks[i + 2].s || !mc_streq(toks[i + 2].s, "in")) {
		sh_write_err(argv0, "case: missing in");
		return 2;
	}
	i += 3;
	int matched = 0;
	for (;;) {
		while (i < end && toks[i].kind == SH_TOK_SEMI) i++;
		if (i >= end || toks[i].kind == SH_TOK_END) {
			sh_write_err(argv0, "case: missing esac");
			return 2;
		}
		if (toks[i].kind == SH_TOK_WORD && toks[i].s && mc_streq(toks[i].s, "esac")) {
			i++;
			*pi = i;
			return last_rc;
		}

		// Parse patterns until ')'. Patterns may be split by SH_TOK_PIPE tokens.
		char patbuf[256];
		mc_usize poff = 0;
		int clause_match = 0;
		int any_pat = 0;
		for (;;) {
			if (i >= end) {
				sh_write_err(argv0, "case: unterminated pattern");
				return 2;
			}
			if (toks[i].kind == SH_TOK_WORD && toks[i].s) {
				const char *ps = toks[i].s;
				mc_usize pn = toks[i].n;
				int ends = 0;
				if (mc_streq(ps, ")")) {
					ends = 1;
					pn = 0;
				} else if (pn > 0 && ps[pn - 1] == ')') {
					ends = 1;
					pn--;
				}
				for (mc_usize k = 0; k < pn; k++) {
					if (poff + 2 >= sizeof(patbuf)) {
						sh_write_err(argv0, "case: pattern too long");
						return 2;
					}
					patbuf[poff++] = ps[k];
				}
				patbuf[poff] = 0;
				if (ends) {
					if (poff > 0) {
						any_pat = 1;
						// Expand pattern (allows $NAME in patterns) and ignore optional leading '(' syntax.
						char psrc[256];
						mc_usize si = 0;
						for (; patbuf[si] && si + 1 < sizeof(psrc); si++) psrc[si] = patbuf[si];
						psrc[si] = 0;
						mc_usize ti = 0;
						while (psrc[ti] == ' ' || psrc[ti] == '\t') ti++;
						if (psrc[ti] == '(') ti++;
						while (psrc[ti] == ' ' || psrc[ti] == '\t') ti++;
						char pexp[256];
						mc_usize po = 0;
						const char *pex = sh_expand_word(psrc + ti, ctx, pexp, sizeof(pexp), &po, argv0);
						if (pex) {
							pexp[po] = 0;
							if (!matched && sh_match_pat(pexp, wexp)) clause_match = 1;
						}
					}
					i++;
					break;
				}
				i++;
				continue;
			}
			if (toks[i].kind == SH_TOK_PIPE) {
				if (poff > 0) {
					any_pat = 1;
					char psrc[256];
					mc_usize si = 0;
					for (; patbuf[si] && si + 1 < sizeof(psrc); si++) psrc[si] = patbuf[si];
					psrc[si] = 0;
					mc_usize ti = 0;
					while (psrc[ti] == ' ' || psrc[ti] == '\t') ti++;
					if (psrc[ti] == '(') ti++;
					while (psrc[ti] == ' ' || psrc[ti] == '\t') ti++;
					char pexp[256];
					mc_usize po = 0;
					const char *pex = sh_expand_word(psrc + ti, ctx, pexp, sizeof(pexp), &po, argv0);
					if (pex) {
						pexp[po] = 0;
						if (!matched && sh_match_pat(pexp, wexp)) clause_match = 1;
					}
				}
				poff = 0;
				patbuf[0] = 0;
				i++;
				continue;
			}
			sh_write_err(argv0, "case: bad pattern");
			return 2;
		}
		if (!any_pat) {
			sh_write_err(argv0, "case: empty pattern");
			return 2;
		}

		// Body until ';;' (approximated as two consecutive semis) or esac.
		mc_u32 body_start = i;
		mc_u32 body_end = i;
		for (;;) {
			if (i >= end || toks[i].kind == SH_TOK_END) {
				sh_write_err(argv0, "case: missing esac");
				return 2;
			}
			if (toks[i].kind == SH_TOK_WORD && toks[i].s && mc_streq(toks[i].s, "esac")) {
				body_end = i;
				break;
			}
			if (toks[i].kind == SH_TOK_SEMI && (i + 1) < end && toks[i + 1].kind == SH_TOK_SEMI) {
				body_end = i;
				while (i < end && toks[i].kind == SH_TOK_SEMI) i++;
				break;
			}
			i++;
		}
		if (should_run && clause_match && !matched) {
			matched = 1;
			last_rc = sh_eval_range(argv0, toks, body_start, body_end, envp, ctx);
			if (ctx) ctx->last_rc = last_rc;
		}
		// Continue to next clause.
	}
}

static int sh_scan_block_end(struct sh_tok *toks, mc_u32 i, mc_u32 end, const char *kw_end, const char *kw_else, mc_u32 *out_else, mc_u32 *out_end) {
	// Scans for a matching end keyword (fi/done), tracking nested if/while/for.
	// If kw_else is non-null, also reports an else position (only at depth 0).
	mc_u32 depth_if = 0;
	mc_u32 depth_loop = 0;
	mc_u32 else_pos = (mc_u32)-1;
	for (; i < end; i++) {
		if (toks[i].kind != SH_TOK_WORD) continue;
		if (sh_tok_is_word(&toks[i], "if")) {
			depth_if++;
			continue;
		}
		if (sh_tok_is_word(&toks[i], "while") || sh_tok_is_word(&toks[i], "for")) {
			depth_loop++;
			continue;
		}
		if (sh_tok_is_word(&toks[i], "fi")) {
			if (depth_if == 0 && depth_loop == 0 && kw_end && mc_streq(kw_end, "fi")) {
				*out_else = else_pos;
				*out_end = i;
				return 0;
			}
			if (depth_if > 0) depth_if--;
			continue;
		}
		if (sh_tok_is_word(&toks[i], "done")) {
			if (depth_if == 0 && depth_loop == 0 && kw_end && mc_streq(kw_end, "done")) {
				*out_else = else_pos;
				*out_end = i;
				return 0;
			}
			if (depth_loop > 0) depth_loop--;
			continue;
		}
		if (kw_else && sh_tok_is_word(&toks[i], kw_else)) {
			if (depth_if == 0 && depth_loop == 0 && else_pos == (mc_u32)-1) {
				else_pos = i;
			}
			continue;
		}
	}
	return -1;
}

static mc_i32 sh_exec_if(const char *argv0, struct sh_tok *toks, mc_u32 end, mc_u32 *io, int should_run, char **envp, struct sh_ctx *ctx, mc_i32 last_rc) {
	mc_u32 i = *io;
	// toks[i] == "if"
	i++;
	// find "then"
	mc_u32 then_pos = (mc_u32)-1;
	for (mc_u32 j = i; j < end; j++) {
		if (toks[j].kind == SH_TOK_WORD && mc_streq(toks[j].s, "then")) {
			then_pos = j;
			break;
		}
	}
	if (then_pos == (mc_u32)-1) {
		sh_write_err(argv0, "if: missing then");
		return 2;
	}
	mc_u32 else_pos = (mc_u32)-1;
	mc_u32 fi_pos = (mc_u32)-1;
	if (sh_scan_block_end(toks, then_pos + 1, end, "fi", "else", &else_pos, &fi_pos) != 0) {
		sh_write_err(argv0, "if: missing fi");
		return 2;
	}
	*io = fi_pos + 1;
	if (!should_run) {
		return last_rc;
	}

	mc_i32 cond_rc = sh_eval_range(argv0, toks, i, then_pos, envp, ctx);
	if (cond_rc == 0) {
		return sh_eval_range(argv0, toks, then_pos + 1, (else_pos == (mc_u32)-1) ? fi_pos : else_pos, envp, ctx);
	}
	if (else_pos != (mc_u32)-1) {
		return sh_eval_range(argv0, toks, else_pos + 1, fi_pos, envp, ctx);
	}
	return cond_rc;
}

static mc_i32 sh_exec_while(const char *argv0, struct sh_tok *toks, mc_u32 end, mc_u32 *io, int should_run, char **envp, struct sh_ctx *ctx, mc_i32 last_rc) {
	mc_u32 i = *io;
	// toks[i] == "while"
	i++;
	// find "do"
	mc_u32 do_pos = (mc_u32)-1;
	for (mc_u32 j = i; j < end; j++) {
		if (toks[j].kind == SH_TOK_WORD && mc_streq(toks[j].s, "do")) {
			do_pos = j;
			break;
		}
	}
	if (do_pos == (mc_u32)-1) {
		sh_write_err(argv0, "while: missing do");
		return 2;
	}
	mc_u32 ignore_else = (mc_u32)-1;
	mc_u32 done_pos = (mc_u32)-1;
	if (sh_scan_block_end(toks, do_pos + 1, end, "done", 0, &ignore_else, &done_pos) != 0) {
		sh_write_err(argv0, "while: missing done");
		return 2;
	}
	*io = done_pos + 1;
	if (!should_run) {
		return last_rc;
	}

	mc_i32 body_rc = 0;
	int ran = 0;
	for (;;) {
		mc_i32 cond_rc = sh_eval_range(argv0, toks, i, do_pos, envp, ctx);
		if (cond_rc != 0) {
			return ran ? body_rc : cond_rc;
		}
		ran = 1;
		body_rc = sh_eval_range(argv0, toks, do_pos + 1, done_pos, envp, ctx);
	}
}

static mc_i32 sh_exec_for(const char *argv0, struct sh_tok *toks, mc_u32 end, mc_u32 *io, int should_run, char **envp, struct sh_ctx *ctx, mc_i32 last_rc) {
	mc_u32 i = *io;
	// toks[i] == "for"
	i++;
	if (i >= end || toks[i].kind != SH_TOK_WORD) {
		sh_write_err(argv0, "for: missing variable name");
		return 2;
	}
	const char *varname = toks[i].s;
	i++;
	// require "in"
	while (i < end && toks[i].kind == SH_TOK_SEMI) i++;
	if (i >= end || !sh_tok_is_word(&toks[i], "in")) {
		sh_write_err(argv0, "for: expected 'in'");
		return 2;
	}
	i++;
	// scan items until "do"
	mc_u32 do_pos = (mc_u32)-1;
	for (mc_u32 j = i; j < end; j++) {
		if (toks[j].kind == SH_TOK_WORD && mc_streq(toks[j].s, "do")) {
			do_pos = j;
			break;
		}
	}
	if (do_pos == (mc_u32)-1) {
		sh_write_err(argv0, "for: missing do");
		return 2;
	}
	mc_u32 ignore_else = (mc_u32)-1;
	mc_u32 done_pos = (mc_u32)-1;
	if (sh_scan_block_end(toks, do_pos + 1, end, "done", 0, &ignore_else, &done_pos) != 0) {
		sh_write_err(argv0, "for: missing done");
		return 2;
	}
	*io = done_pos + 1;
	if (!should_run) {
		return last_rc;
	}

	// Collect items (WORD tokens) from [i, do_pos).
	const char *items[64];
	mc_u32 nitems = 0;
	for (mc_u32 j = i; j < do_pos; j++) {
		if (toks[j].kind == SH_TOK_SEMI) continue;
		if (toks[j].kind != SH_TOK_WORD) {
			sh_write_err(argv0, "for: bad item list");
			return 2;
		}
		if (nitems >= 64) {
			sh_write_err(argv0, "for: too many items");
			return 2;
		}
		items[nitems++] = toks[j].s;
	}

	mc_i32 rc = 0;
	for (mc_u32 it = 0; it < nitems; it++) {
		if (sh_vars_push(&ctx->vars, varname, items[it], argv0) != 0) return 2;
		rc = sh_eval_range(argv0, toks, do_pos + 1, done_pos, envp, ctx);
		sh_vars_pop(&ctx->vars);
	}
	return rc;
}

static mc_i32 sh_status_to_exit(mc_i32 st) {
	return mc_wait_exitcode(st);
}

static mc_i32 sh_exec_search(const char *argv0, char **envp, const char *cmd, char *const argv_exec[]) {
	// Returns only on error; prints message. Exit code to use: 127 for not found, 126 for other exec failure.
	if (!cmd || !*cmd) {
		sh_write_err(argv0, "empty command");
		return 127;
	}
	if (mc_has_slash(cmd)) {
		mc_i64 r = mc_sys_execve(cmd, argv_exec, envp);
		sh_print_errno(argv0, "execve", r);
		return 126;
	}

	const char *path_env = mc_getenv_kv(envp, "PATH=");
	if (!path_env) {
		path_env = "/bin:/usr/bin";
	}

	char cand[4096];
	const char *p = path_env;
	mc_i64 last_err = -MC_ENOENT;
	while (1) {
		const char *seg = p;
		while (*p && *p != ':') p++;
		mc_usize seg_len = (mc_usize)(p - seg);
		mc_usize cmd_len = mc_strlen(cmd);

		if (seg_len == 0) {
			// current directory
			if (cmd_len + 1 <= sizeof(cand)) {
				for (mc_usize i = 0; i < cmd_len; i++) cand[i] = cmd[i];
				cand[cmd_len] = 0;
				mc_i64 r = mc_sys_execve(cand, argv_exec, envp);
				if (r >= 0) return 0;
				last_err = r;
				// continue on ENOENT/ENOTDIR
			}
		} else {
			int needs_slash = 1;
			if (seg_len > 0 && seg[seg_len - 1] == '/') needs_slash = 0;
			mc_usize total = seg_len + (needs_slash ? 1u : 0u) + cmd_len;
			if (total + 1 <= sizeof(cand)) {
				for (mc_usize i = 0; i < seg_len; i++) cand[i] = seg[i];
				mc_usize off = seg_len;
				if (needs_slash) cand[off++] = '/';
				for (mc_usize i = 0; i < cmd_len; i++) cand[off + i] = cmd[i];
				cand[off + cmd_len] = 0;
				mc_i64 r = mc_sys_execve(cand, argv_exec, envp);
				if (r >= 0) return 0;
				last_err = r;
			}
		}

		if (*p == ':') {
			p++;
			continue;
		}
		break;
	}

	if (last_err == -MC_ENOENT || last_err == -MC_ENOTDIR) {
		sh_write_err2(argv0, cmd, ": not found");
		return 127;
	}
	sh_print_errno(argv0, "execve", last_err);
	return 126;
}

static mc_i32 sh_run_pipeline(const char *argv0, struct sh_cmd *cmds, mc_u32 ncmds, char **envp, int background, mc_i32 *out_last_pid) {
	mc_i32 pids[SH_MAX_CMDS];
	mc_u32 pn = 0;
	mc_i32 in_fd = -1;

	for (mc_u32 ci = 0; ci < ncmds; ci++) {
		mc_i32 pipefd[2] = { -1, -1 };
		int has_next = (ci + 1 < ncmds);
		if (has_next) {
			mc_i64 pr = mc_sys_pipe2(pipefd, MC_O_CLOEXEC);
			if (pr < 0) {
				sh_print_errno(argv0, "pipe2", pr);
				return 1;
			}
		}

		mc_i64 vr = mc_sys_fork();
		if (vr < 0) {
			sh_print_errno(argv0, "fork", vr);
			return 1;
		}
		if (vr == 0) {
			// child
			if (in_fd != -1) {
				mc_i64 dr = mc_sys_dup2(in_fd, 0);
				if (dr < 0) {
					sh_print_errno(argv0, "dup2", dr);
					mc_exit(127);
				}
			}
			if (has_next) {
				mc_i64 dr = mc_sys_dup2(pipefd[1], 1);
				if (dr < 0) {
					sh_print_errno(argv0, "dup2", dr);
					mc_exit(127);
				}
			}
			// Close pipe fds
			if (in_fd != -1) (void)mc_sys_close(in_fd);
			if (has_next) {
				(void)mc_sys_close(pipefd[0]);
				(void)mc_sys_close(pipefd[1]);
			}

			// Apply redirections
			for (mc_u32 ri = 0; ri < cmds[ci].nredirs; ri++) {
				const struct sh_redir_op *r = &cmds[ci].redirs[ri];
				if (r->kind == SH_REDIR_DUP_OUT) {
					mc_i64 dr = mc_sys_dup2(r->target_fd, r->fd);
					if (dr < 0) {
						sh_print_errno(argv0, "dup2", dr);
						mc_exit(1);
					}
					continue;
				}
				if (!r->path || !*r->path) {
					sh_write_err(argv0, "redir missing path");
					mc_exit(2);
				}
				if (r->kind == SH_REDIR_IN_FILE) {
					mc_i64 fd = mc_sys_openat(MC_AT_FDCWD, r->path, MC_O_RDONLY | MC_O_CLOEXEC, 0);
					if (fd < 0) {
						sh_print_errno(argv0, "open", fd);
						mc_exit(1);
					}
					mc_i64 dr = mc_sys_dup2((mc_i32)fd, r->fd);
					if (dr < 0) {
						sh_print_errno(argv0, "dup2", dr);
						mc_exit(1);
					}
					(void)mc_sys_close((mc_i32)fd);
					continue;
				}
				mc_i32 flags = MC_O_WRONLY | MC_O_CREAT | MC_O_CLOEXEC;
				flags |= (r->kind == SH_REDIR_OUT_APP) ? MC_O_APPEND : MC_O_TRUNC;
				mc_i64 fd = mc_sys_openat(MC_AT_FDCWD, r->path, flags, 0666);
				if (fd < 0) {
					sh_print_errno(argv0, "open", fd);
					mc_exit(1);
				}
				mc_i64 dr = mc_sys_dup2((mc_i32)fd, r->fd);
				if (dr < 0) {
					sh_print_errno(argv0, "dup2", dr);
					mc_exit(1);
				}
				(void)mc_sys_close((mc_i32)fd);
			}

			// Exec
			mc_i32 rc = sh_exec_search(argv0, envp, cmds[ci].argv[0], (char *const *)cmds[ci].argv);
			mc_exit(rc);
		}

		// parent
		pids[pn++] = (mc_i32)vr;
		if (in_fd != -1) (void)mc_sys_close(in_fd);
		if (has_next) {
			(void)mc_sys_close(pipefd[1]);
			in_fd = pipefd[0];
		} else {
			in_fd = -1;
		}
	}
	if (in_fd != -1) (void)mc_sys_close(in_fd);

	if (pn > 0 && out_last_pid) *out_last_pid = pids[pn - 1];
	if (background) {
		// For a background pipeline, consider spawn success as rc=0.
		// Caller may use $! to refer to the last element pid.
		return 0;
	}

	// Wait all, but return last pipeline element status.
	mc_i32 last_status = 0;
	for (mc_u32 wi = 0; wi < pn; wi++) {
		mc_i32 st = 0;
		mc_i64 wr = mc_sys_wait4(pids[wi], &st, 0, 0);
		if (wr < 0) {
			sh_print_errno(argv0, "wait4", wr);
			last_status = (mc_i32)wr;
			continue;
		}
		if (wi + 1 == pn) last_status = st;
	}
	return sh_status_to_exit(last_status);
}

static int sh_is_builtin(const char *s, const char *name) {
	if (!s || !name) return 0;
	return mc_streq(s, name);
}

static mc_i32 sh_eval_range(const char *argv0, struct sh_tok *toks, mc_u32 start, mc_u32 end, char **envp, struct sh_ctx *ctx) {
	if (ctx) ctx->envp = envp;
	mc_u32 i = start;
	mc_i32 last_rc = 0;
	int next_and = 0;
	int next_or = 0;
	char argbuf[SH_MAX_LINE];
	mc_usize argoff = 0;

	while (i < end) {
		sh_reap_zombies(argv0);
		while (i < end && toks[i].kind == SH_TOK_SEMI) i++;
		if (i >= end || toks[i].kind == SH_TOK_END) break;

		// If a function has issued `return`, stop executing immediately and
		// propagate the return code up to the function-call wrapper.
		if (ctx && ctx->ret_pending && ctx->ret_depth <= ctx->in_func_depth) {
			return ctx->ret_code;
		}

		// Function definition: name() { ... }
		if (ctx && toks[i].kind == SH_TOK_WORD && toks[i].s && sh_word_ends_with(toks[i].s, "()")) {
			const char *w = toks[i].s;
			mc_usize wn = mc_strlen(w);
			// Extract name.
			char fname[SH_VAR_NAME_MAX];
			mc_usize fn = 0;
			for (; fn + 2 < wn && fn + 1 < sizeof(fname); fn++) {
				char fc = w[fn];
				if (!sh_is_funcname_char(fc)) break;
				fname[fn] = fc;
			}
			fname[fn] = 0;
			if (fn > 0 && mc_streq(w + fn, "()") && (i + 1) < end && toks[i + 1].kind == SH_TOK_WORD && mc_streq(toks[i + 1].s, "{")) {
				mc_u32 j = i + 2;
				for (; j < end; j++) {
					if (toks[j].kind == SH_TOK_WORD && toks[j].s && mc_streq(toks[j].s, "}")) break;
				}
				if (j >= end) {
					sh_write_err(argv0, "unterminated function body");
					return 2;
				}
				if (sh_func_set(ctx, fname, toks, i + 2, j, argv0) != 0) return 2;
				i = j + 1;
				sh_consume_sep(toks, end, &i, &next_and, &next_or);
				continue;
			}
		}

		int should_run = 1;
		int in_cond_chain = (next_and || next_or);
		if (next_and) should_run = (last_rc == 0);
		if (next_or) should_run = (last_rc != 0);
		next_and = 0;
		next_or = 0;

		// Reset per-command expansion buffer.
		argoff = 0;
		if (ctx) {
			ctx->cmdsub_used = 0;
			ctx->last_cmdsub_rc = 0;
		}

		// Control flow
		if (toks[i].kind == SH_TOK_WORD && mc_streq(toks[i].s, "if")) {
			last_rc = sh_exec_if(argv0, toks, end, &i, should_run, envp, ctx, last_rc);
			if (ctx) ctx->last_rc = last_rc;
			sh_consume_sep(toks, end, &i, &next_and, &next_or);
			continue;
		}
		if (toks[i].kind == SH_TOK_WORD && mc_streq(toks[i].s, "while")) {
			last_rc = sh_exec_while(argv0, toks, end, &i, should_run, envp, ctx, last_rc);
			if (ctx) ctx->last_rc = last_rc;
			sh_consume_sep(toks, end, &i, &next_and, &next_or);
			continue;
		}
		if (toks[i].kind == SH_TOK_WORD && mc_streq(toks[i].s, "for")) {
			last_rc = sh_exec_for(argv0, toks, end, &i, should_run, envp, ctx, last_rc);
			if (ctx) ctx->last_rc = last_rc;
			sh_consume_sep(toks, end, &i, &next_and, &next_or);
			continue;
		}
		if (toks[i].kind == SH_TOK_WORD && mc_streq(toks[i].s, "case")) {
			last_rc = sh_exec_case(argv0, toks, end, &i, should_run, envp, ctx, last_rc);
			if (ctx) ctx->last_rc = last_rc;
			sh_consume_sep(toks, end, &i, &next_and, &next_or);
			continue;
		}

		// Simple command / pipeline
		struct sh_cmd cmds[SH_MAX_CMDS];
		mc_u32 ncmds = 0;
		if (sh_parse_pipeline(toks, end, &i, cmds, &ncmds, ctx, argbuf, sizeof(argbuf), &argoff, argv0) != 0) {
			while (i < end && toks[i].kind != SH_TOK_SEMI && toks[i].kind != SH_TOK_END) i++;
			last_rc = 2;
			continue;
		}
		int background = sh_consume_bg(toks, end, &i);
		sh_consume_sep(toks, end, &i, &next_and, &next_or);
		if (!should_run) continue;

		// Assignment-only statement.
		if (ncmds == 1 && cmds[0].argc == 0) {
			last_rc = (ctx && ctx->cmdsub_used) ? ctx->last_cmdsub_rc : 0;
			if (ctx) ctx->last_rc = last_rc;
			if (ctx && ctx->opt_errexit && last_rc != 0 && !in_cond_chain) {
				sh_do_exit(argv0, ctx, envp, last_rc);
			}
			continue;
		}

		if (ncmds == 1 && cmds[0].argc > 0) {
			const char *cmd0 = cmds[0].argv[0];
			// Function call
			if (ctx) {
				const struct sh_func *f = sh_func_lookup(ctx, cmd0);
				if (f) {
					// Tokenize the stored function body on each call.
					char f_wordbuf[SH_FUNC_CALL_WORDBUF];
					struct sh_tok f_toks[SH_FUNC_CALL_MAX_TOKS];
					mc_u32 f_nt = 0;
					if (sh_tokenize(f->body, f_wordbuf, sizeof(f_wordbuf), f_toks, &f_nt, argv0) != 0) {
						last_rc = 2;
						ctx->last_rc = last_rc;
						continue;
					}
					// Temporarily replace positional parameters for function body.
					const char *saved_posv[32];
					mc_u32 saved_posc = ctx->posc;
					for (mc_u32 pi = 0; pi < saved_posc && pi < (mc_u32)(sizeof(saved_posv) / sizeof(saved_posv[0])); pi++) {
						saved_posv[pi] = ctx->posv[pi];
					}
					// Keep $0 as-is.
					ctx->posc = 1;
					ctx->posv[0] = (saved_posc > 0) ? saved_posv[0] : cmd0;
					for (mc_u32 ai = 1; ai < cmds[0].argc && ctx->posc < (mc_u32)(sizeof(ctx->posv) / sizeof(ctx->posv[0])); ai++) {
						ctx->posv[ctx->posc++] = cmds[0].argv[ai];
					}
					if (ctx) ctx->in_func_depth++;
					last_rc = sh_eval_range(argv0, f_toks, 0, f_nt, envp, ctx);
					if (ctx) {
						// If a `return` was issued at this depth, consume it here.
						if (ctx->ret_pending && ctx->ret_depth == ctx->in_func_depth) {
							last_rc = ctx->ret_code;
							ctx->ret_pending = 0;
						}
						ctx->in_func_depth--;
					}
					// Restore positionals
					ctx->posc = saved_posc;
					for (mc_u32 pi = 0; pi < saved_posc && pi < (mc_u32)(sizeof(saved_posv) / sizeof(saved_posv[0])); pi++) {
						ctx->posv[pi] = saved_posv[pi];
					}
					ctx->last_rc = last_rc;
					continue;
				}
			}

			if (sh_is_builtin(cmd0, "return")) {
				if (!ctx || ctx->in_func_depth <= 0) {
					sh_write_err(argv0, "return: not in function");
					last_rc = 2;
					if (ctx) ctx->last_rc = last_rc;
					continue;
				}
				mc_i32 code = 0;
				if (cmds[0].argc >= 2) {
					mc_i64 v = 0;
					if (mc_parse_i64_dec(cmds[0].argv[1], &v) != 0) code = 2;
					else code = (mc_i32)v;
				}
				ctx->ret_pending = 1;
				ctx->ret_depth = ctx->in_func_depth;
				ctx->ret_code = code;
				ctx->last_rc = code;
				return code;
			}
			if (sh_is_builtin(cmd0, "cd")) {
				const char *dir = 0;
				if (cmds[0].argc >= 3 && mc_streq(cmds[0].argv[1], "--")) dir = cmds[0].argv[2];
				else if (cmds[0].argc >= 2) dir = cmds[0].argv[1];
				else dir = mc_getenv_kv(envp, "HOME=");
				if (!dir || !*dir) {
					sh_write_err(argv0, "cd: missing directory (and HOME unset)");
					last_rc = 1;
				} else {
					mc_i64 cr = mc_sys_chdir(dir);
					if (cr < 0) {
						sh_print_errno(argv0, "chdir", cr);
						last_rc = 1;
					} else {
						last_rc = 0;
					}
				}
				continue;
			}
			if (sh_is_builtin(cmd0, "exit")) {
				mc_i32 code = 0;
				if (cmds[0].argc >= 2) {
					mc_i64 v = 0;
					if (mc_parse_i64_dec(cmds[0].argv[1], &v) != 0) code = 2;
					else code = (mc_i32)v;
				}
				sh_do_exit(argv0, ctx, envp, code);
			}
			if (sh_is_builtin(cmd0, "wait")) {
				// wait [PID]
				if (cmds[0].argc >= 2) {
					mc_i64 pid64 = 0;
					if (mc_parse_i64_dec(cmds[0].argv[1], &pid64) != 0 || pid64 <= 0 || pid64 > 1u<<30) {
						sh_write_err(argv0, "wait: bad pid");
						last_rc = 2;
					} else {
						mc_i32 st = 0;
						mc_i64 wr = mc_sys_wait4((mc_i32)pid64, &st, 0, 0);
						if (wr < 0) {
							last_rc = 1;
						} else {
							last_rc = sh_status_to_exit(st);
						}
					}
				} else {
					// Wait for all children.
					for (;;) {
						mc_i32 st = 0;
						mc_i64 wr = mc_sys_wait4(-1, &st, 0, 0);
						if (wr < 0) break;
						last_rc = sh_status_to_exit(st);
					}
					if (last_rc < 0) last_rc = 0;
				}
				if (ctx) ctx->last_rc = last_rc;
				continue;
			}
			if (sh_is_builtin(cmd0, "shift")) {
				mc_u32 n = 1;
				if (cmds[0].argc >= 2 && cmds[0].argv[1]) {
					mc_u64 v = 0;
					if (mc_parse_u64_dec(cmds[0].argv[1], &v) != 0) {
						sh_write_err(argv0, "shift: bad count");
						last_rc = 2;
						if (ctx) ctx->last_rc = last_rc;
						continue;
					}
					n = (mc_u32)v;
				}
				if (!ctx) {
					last_rc = 0;
					continue;
				}
				mc_u32 argc1 = (ctx->posc > 0) ? (ctx->posc - 1) : 0;
				if (n > argc1) {
					sh_write_err(argv0, "shift: out of range");
					last_rc = 1;
					ctx->last_rc = last_rc;
					continue;
				}
				for (mc_u32 i2 = 1; i2 + n < ctx->posc; i2++) {
					ctx->posv[i2] = ctx->posv[i2 + n];
				}
				ctx->posc -= n;
				last_rc = 0;
				ctx->last_rc = last_rc;
				continue;
			}
			if (sh_is_builtin(cmd0, ":")) {
				last_rc = 0;
				if (ctx) ctx->last_rc = last_rc;
				continue;
			}
			if (sh_is_builtin(cmd0, "set")) {
				// set [-e/+e] [-u/+u]
				for (mc_u32 ai = 1; ai < cmds[0].argc; ai++) {
					const char *a = cmds[0].argv[ai];
					if (!a) continue;
					if (mc_streq(a, "-e")) ctx->opt_errexit = 1;
					else if (mc_streq(a, "+e")) ctx->opt_errexit = 0;
					else if (mc_streq(a, "-u")) ctx->opt_nounset = 1;
					else if (mc_streq(a, "+u")) ctx->opt_nounset = 0;
				}
				last_rc = 0;
				ctx->last_rc = last_rc;
				continue;
			}
			if (sh_is_builtin(cmd0, "trap")) {
				// Minimal: support only EXIT/0 trap; ignore other signals.
				last_rc = 0;
				if (ctx && cmds[0].argc >= 3 && cmds[0].argv[1]) {
					const char *handler = cmds[0].argv[1];
					for (mc_u32 ai = 2; ai < cmds[0].argc; ai++) {
						const char *sig = cmds[0].argv[ai];
						if (!sig) continue;
						if (mc_streq(sig, "EXIT") || mc_streq(sig, "0")) {
							mc_usize hi = 0;
							for (; handler[hi] && hi + 1 < sizeof(ctx->trap_exit); hi++) ctx->trap_exit[hi] = handler[hi];
							ctx->trap_exit[hi] = 0;
							ctx->trap_exit_set = 1;
						}
					}
				}
				if (ctx) ctx->last_rc = last_rc;
				continue;
			}
			if (sh_is_builtin(cmd0, ".")) {
				if (cmds[0].argc < 2) {
					sh_write_err(argv0, ".: missing path");
					last_rc = 2;
					if (ctx) ctx->last_rc = last_rc;
					continue;
				}
				static char prog[SH_MAX_PROG];
				if (sh_read_file(argv0, cmds[0].argv[1], prog, sizeof(prog)) != 0) {
					last_rc = 1;
					if (ctx) ctx->last_rc = last_rc;
					continue;
				}
				static char wordbuf2[SH_MAX_WORDBUF];
				static struct sh_tok toks2[SH_MAX_TOKS];
				mc_u32 nt2 = 0;
				if (sh_tokenize(prog, wordbuf2, sizeof(wordbuf2), toks2, &nt2, argv0) != 0) {
					last_rc = 2;
					if (ctx) ctx->last_rc = last_rc;
					continue;
				}
				last_rc = sh_eval_range(argv0, toks2, 0, nt2, envp, ctx);
				if (ctx) ctx->last_rc = last_rc;
				continue;
			}
		}
		mc_i32 last_pid = 0;
		last_rc = sh_run_pipeline(argv0, cmds, ncmds, envp, background, &last_pid);
		if (background && ctx) ctx->last_bg_pid = last_pid;
		if (ctx) ctx->last_rc = last_rc;
		if (ctx && ctx->opt_errexit && last_rc != 0 && !in_cond_chain) {
			sh_do_exit(argv0, ctx, envp, last_rc);
		}
	}
	if (ctx) ctx->last_rc = last_rc;
	return last_rc;
}

struct sh_reader {
	mc_i32 fd;
	char buf[4096];
	mc_usize off;
	mc_usize len;
};

static mc_i32 sh_reader_fill(struct sh_reader *r) {
	r->off = 0;
	mc_i64 n = mc_sys_read(r->fd, r->buf, sizeof(r->buf));
	if (n < 0) return (mc_i32)n;
	r->len = (mc_usize)n;
	return (mc_i32)n;
}

static int sh_read_line(struct sh_reader *r, char *out, mc_usize out_sz, mc_usize *out_n) {
	// Returns: 1 line read, 0 EOF, -1 error.
	mc_usize n = 0;
	while (1) {
		if (r->off >= r->len) {
			mc_i32 fr = sh_reader_fill(r);
			if (fr < 0) return -1;
			if (fr == 0) {
				if (n == 0) return 0;
				out[n] = 0;
				*out_n = n;
				return 1;
			}
		}
		char c = r->buf[r->off++];
		if (c == '\n') {
			out[n] = 0;
			*out_n = n;
			return 1;
		}
		if (n + 1 >= out_sz) {
			return -1;
		}
		out[n++] = c;
	}
}

__attribute__((used)) int main(int argc, char **argv, char **envp) {
	const char *argv0 = (argc > 0 && argv && argv[0]) ? argv[0] : "sh";

	int i = 1;
	const char *cmd_str = 0;
	const char *file = 0;

	for (; i < argc; i++) {
		const char *a = argv[i];
		if (!a) break;
		if (mc_streq(a, "-c")) {
			if (i + 1 >= argc || !argv[i + 1]) {
				mc_die_usage(argv0, "sh [-c CMD] [FILE]");
			}
			cmd_str = argv[++i];
			continue;
		}
		if (mc_streq(a, "--")) {
			i++;
			break;
		}
		// First non-flag is FILE unless -c was used.
		if (cmd_str) {
			break;
		}
		file = a;
		i++;
		break;
	}
	// Remaining argv after FILE (or after -c CMD) become positional parameters.
	int rest_i = i;

	if (cmd_str) {
		static char prog[SH_MAX_PROG];
		mc_usize n = mc_strlen(cmd_str);
		if (n + 1 > sizeof(prog)) {
			sh_write_err(argv0, "-c command too long");
			return 2;
		}
		for (mc_usize j = 0; j <= n; j++) prog[j] = cmd_str[j];
		static char wordbuf[SH_MAX_WORDBUF];
		static struct sh_tok toks[SH_MAX_TOKS];
		mc_u32 ntoks = 0;
		if (sh_tokenize(prog, wordbuf, sizeof(wordbuf), toks, &ntoks, argv0) != 0) return 2;
		struct sh_ctx ctx;
		ctx.envp = envp;
		ctx.vars.n = 0;
		ctx.last_rc = 0;
		ctx.last_bg_pid = 0;
		ctx.opt_errexit = 0;
		ctx.opt_nounset = 0;
		ctx.funcs.n = 0;
		ctx.trap_exit[0] = 0;
		ctx.trap_exit_set = 0;
		ctx.in_func_depth = 0;
		ctx.ret_pending = 0;
		ctx.ret_depth = 0;
		ctx.ret_code = 0;
		ctx.cmdsub_used = 0;
		ctx.last_cmdsub_rc = 0;
		ctx.posc = 0;
		// -c semantics: if extra args exist, first becomes $0, rest are $1..
		if (rest_i < argc && argv[rest_i]) {
			for (; rest_i < argc && argv[rest_i] && ctx.posc < (mc_u32)(sizeof(ctx.posv) / sizeof(ctx.posv[0])); rest_i++) {
				ctx.posv[ctx.posc++] = argv[rest_i];
			}
		}
		mc_i32 rc = sh_eval_range(argv0, toks, 0, ntoks, envp, &ctx);
		sh_run_trap_exit(argv0, &ctx, envp);
		return rc;
	}

	if (file) {
		// Script file mode: read whole file and evaluate as a single token stream.
		mc_i64 ofd = mc_sys_openat(MC_AT_FDCWD, file, MC_O_RDONLY | MC_O_CLOEXEC, 0);
		if (ofd < 0) {
			sh_print_errno(argv0, "open", ofd);
			return 1;
		}
		mc_i32 fd = (mc_i32)ofd;
		static char prog[SH_MAX_PROG];
		mc_usize off = 0;
		for (;;) {
			if (off + 1 >= sizeof(prog)) {
				sh_write_err(argv0, "script too big");
				(void)mc_sys_close(fd);
				return 2;
			}
			mc_i64 n = mc_sys_read(fd, prog + off, (mc_usize)(sizeof(prog) - off - 1));
			if (n < 0) {
				sh_print_errno(argv0, "read", n);
				(void)mc_sys_close(fd);
				return 1;
			}
			if (n == 0) break;
			off += (mc_usize)n;
		}
		prog[off] = 0;
		(void)mc_sys_close(fd);
		static char wordbuf[SH_MAX_WORDBUF];
		static struct sh_tok toks[SH_MAX_TOKS];
		mc_u32 ntoks = 0;
		if (sh_tokenize(prog, wordbuf, sizeof(wordbuf), toks, &ntoks, argv0) != 0) return 2;
		struct sh_ctx ctx;
		ctx.envp = envp;
		ctx.vars.n = 0;
		ctx.last_rc = 0;
		ctx.last_bg_pid = 0;
		ctx.opt_errexit = 0;
		ctx.opt_nounset = 0;
		ctx.funcs.n = 0;
		ctx.trap_exit[0] = 0;
		ctx.trap_exit_set = 0;
		ctx.in_func_depth = 0;
		ctx.ret_pending = 0;
		ctx.ret_depth = 0;
		ctx.ret_code = 0;
		ctx.cmdsub_used = 0;
		ctx.last_cmdsub_rc = 0;
		ctx.posc = 0;
		// Script semantics: $0 is script path.
		ctx.posv[ctx.posc++] = file;
		for (; rest_i < argc && argv[rest_i] && ctx.posc < (mc_u32)(sizeof(ctx.posv) / sizeof(ctx.posv[0])); rest_i++) {
			ctx.posv[ctx.posc++] = argv[rest_i];
		}
		mc_i32 rc = sh_eval_range(argv0, toks, 0, ntoks, envp, &ctx);
		sh_run_trap_exit(argv0, &ctx, envp);
		return rc;
	}

	// Interactive stdin mode.
	struct sh_reader r = { .fd = 0, .off = 0, .len = 0 };
	char line[SH_MAX_LINE];
	mc_i32 last_rc = 0;
	struct sh_ctx ictx;
	ictx.envp = envp;
	ictx.vars.n = 0;
	ictx.last_bg_pid = 0;
	ictx.opt_errexit = 0;
	ictx.opt_nounset = 0;
	ictx.funcs.n = 0;
	ictx.trap_exit[0] = 0;
	ictx.trap_exit_set = 0;
	ictx.in_func_depth = 0;
	ictx.ret_pending = 0;
	ictx.ret_depth = 0;
	ictx.ret_code = 0;
	ictx.cmdsub_used = 0;
	ictx.last_cmdsub_rc = 0;
	ictx.posc = 0;

	// Show a prompt only when stdin is a tty.
	// TCGETS is 0x5401 on Linux.
	int interactive = 0;
	{
		mc_u8 dummy[64];
		mc_i64 ir = mc_sys_ioctl(0, 0x5401u, dummy);
		if (ir >= 0) interactive = 1;
	}
	for (;;) {
		if (interactive) {
			char cwd[512];
			mc_i64 cr = mc_sys_getcwd(cwd, sizeof(cwd));
			if (cr >= 0) {
				(void)mc_write_str(1, cwd);
				(void)mc_write_str(1, " $ ");
			} else {
				(void)mc_write_str(1, "$ ");
			}
		}
		mc_usize ln = 0;
		int rr = sh_read_line(&r, line, sizeof(line), &ln);
		if (rr < 0) {
			sh_write_err(argv0, "read error or line too long");
			return 1;
		}
		if (rr == 0) break;
		char *p = line;
		while (*p == ' ' || *p == '\t' || *p == '\r') p++;
		if (*p == 0) continue;
		static char wordbuf[SH_MAX_WORDBUF];
		static struct sh_tok toks[SH_MAX_TOKS];
		mc_u32 ntoks = 0;
		if (sh_tokenize(line, wordbuf, sizeof(wordbuf), toks, &ntoks, argv0) != 0) {
			last_rc = 2;
			continue;
		}
		last_rc = sh_eval_range(argv0, toks, 0, ntoks, envp, &ictx);
	}
	return last_rc;
}
