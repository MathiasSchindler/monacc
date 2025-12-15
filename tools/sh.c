#include "mc.h"

#define sh_print_errno mc_print_errno

// Minimal syscall-only shell.
// Subset:
// - sh [-c CMD] [FILE]
// - separators: ';' and newlines
// - pipelines: |
// - conditionals: && and ||
// - redirections: <, >, >>
// - quoting: single '...' and double "..." (backslash escapes in double)
// - builtins: cd [DIR], exit [N]
// No variable expansion, no globbing, no job control.

#define SH_MAX_LINE 8192

// Script execution reads the whole file into a fixed buffer so multi-line
// constructs (if/while/for) can work.
#define SH_MAX_PROG 65536

// Tokenization limits for a whole script. These are intentionally modest.
#define SH_MAX_TOKS 2048
#define SH_MAX_WORDBUF 65536

#define SH_MAX_ARGS 64
#define SH_MAX_CMDS 16

#define SH_MAX_VARS 8
#define SH_VAR_NAME_MAX 32
#define SH_VAR_VAL_MAX 256

enum sh_tok_kind {
	SH_TOK_WORD = 0,
	SH_TOK_PIPE,
	SH_TOK_OR_IF,
	SH_TOK_SEMI,
	SH_TOK_AND_IF,
	SH_TOK_REDIR_IN,
	SH_TOK_REDIR_OUT,
	SH_TOK_REDIR_OUT_APP,
	SH_TOK_END,
};

struct sh_tok {
	enum sh_tok_kind kind;
	const char *s;
	mc_usize n;
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
	struct sh_vars vars;
	// Positional parameters:
	// - In script mode: $0 is script path; $1.. are args.
	// - In -c mode: if extra args are provided, first becomes $0, rest $1..
	const char *posv[32];
	mc_u32 posc;
};

struct sh_redir {
	const char *in_path;
	mc_usize in_len;
	const char *out_path;
	mc_usize out_len;
	int out_append;
};

struct sh_cmd {
	const char *argv[SH_MAX_ARGS + 1];
	mc_u32 argc;
	struct sh_redir redir;
};

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

static void sh_vars_pop(struct sh_vars *vars) {
	if (!vars || vars->n == 0) return;
	vars->n--;
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
			// Unknown positional: expand to empty.
			continue;
		}
		if (c == '$' && sh_is_name_start(*p)) {
			const char *ns = p;
			mc_usize nn = 0;
			while (*p && sh_is_name_char(*p)) {
				p++;
				nn++;
			}
			const char *val = sh_vars_lookup(&ctx->vars, ns, nn);
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
			// Unknown var: keep literal $NAME.
			if (*ioff + 1 + nn + 1 > buf_sz) {
				sh_write_err(argv0, "line too long");
				return 0;
			}
			buf[(*ioff)++] = '$';
			for (mc_usize k = 0; k < nn; k++) buf[(*ioff)++] = ns[k];
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
			toks[nt++] = (struct sh_tok){ .kind = SH_TOK_SEMI, .s = p, .n = 1 };
			p++;
			continue;
		}
		if (*p == '&') {
			if (*(p + 1) == '&') {
				toks[nt++] = (struct sh_tok){ .kind = SH_TOK_AND_IF, .s = p, .n = 2 };
				p += 2;
				continue;
			}
			sh_write_err(argv0, "unsupported token '&'");
			return -1;
		}
		if (*p == '|') {
			if (*(p + 1) == '|') {
				toks[nt++] = (struct sh_tok){ .kind = SH_TOK_OR_IF, .s = p, .n = 2 };
				p += 2;
			} else {
				toks[nt++] = (struct sh_tok){ .kind = SH_TOK_PIPE, .s = p, .n = 1 };
				p++;
			}
			continue;
		}
		if (*p == '<') {
			toks[nt++] = (struct sh_tok){ .kind = SH_TOK_REDIR_IN, .s = p, .n = 1 };
			p++;
			continue;
		}
		if (*p == '>') {
			if (*(p + 1) == '>') {
				toks[nt++] = (struct sh_tok){ .kind = SH_TOK_REDIR_OUT_APP, .s = p, .n = 2 };
				p += 2;
			} else {
				toks[nt++] = (struct sh_tok){ .kind = SH_TOK_REDIR_OUT, .s = p, .n = 1 };
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
			if (c == '\'' || c == '"') {
				char q = c;
				p++;
				while (*p && *p != q) {
					char qc = *p;
					if (q == '"' && qc == '\\') {
						p++;
						if (!*p) break;
						char esc = *p;
						if (esc == 'n') qc = '\n';
						else if (esc == 't') qc = '\t';
						else qc = esc;
						if ((mc_usize)(w_out - wordbuf) + 2 > wordbuf_sz) {
							sh_write_err(argv0, "line too long");
							return -1;
						}
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
				if ((mc_usize)(w_out - wordbuf) + 2 > wordbuf_sz) {
					sh_write_err(argv0, "line too long");
					return -1;
				}
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
		toks[nt++] = (struct sh_tok){ .kind = SH_TOK_WORD, .s = w_start, .n = wn };
		woff += wn + 1;
	}
	if (nt + 1 >= SH_MAX_TOKS) {
		sh_write_err(argv0, "line too complex");
		return -1;
	}
	toks[nt++] = (struct sh_tok){ .kind = SH_TOK_END, .s = p, .n = 0 };
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
	if (toks[i].kind == SH_TOK_AND_IF) {
		if (next_and) *next_and = 1;
		if (next_or) *next_or = 0;
		i++;
	} else if (toks[i].kind == SH_TOK_OR_IF) {
		if (next_or) *next_or = 1;
		if (next_and) *next_and = 0;
		i++;
	} else if (toks[i].kind == SH_TOK_SEMI) {
		i++;
	}
	*io = i;
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
		cmd->redir.in_path = 0;
		cmd->redir.in_len = 0;
		cmd->redir.out_path = 0;
		cmd->redir.out_len = 0;
		cmd->redir.out_append = 0;

		int saw_word = 0;
		while (i < ntoks) {
			enum sh_tok_kind k = toks[i].kind;
			if (k == SH_TOK_WORD) {
				saw_word = 1;
				if (cmd->argc + 1 >= SH_MAX_ARGS) {
					sh_write_err(argv0, "too many args");
					return -1;
				}
				const char *ex = sh_expand_word(toks[i].s, ctx, argbuf, argbuf_sz, io_argoff, argv0);
				if (!ex) return -1;
				cmd->argv[cmd->argc++] = ex;
				i++;
				continue;
			}
			if (k == SH_TOK_REDIR_IN || k == SH_TOK_REDIR_OUT || k == SH_TOK_REDIR_OUT_APP) {
				enum sh_tok_kind rk = k;
				i++;
				if (i >= ntoks || toks[i].kind != SH_TOK_WORD) {
					sh_write_err(argv0, "redir missing path");
					return -1;
				}
				const char *path_ex = sh_expand_word(toks[i].s, ctx, argbuf, argbuf_sz, io_argoff, argv0);
				if (!path_ex) return -1;
				if (rk == SH_TOK_REDIR_IN) {
					cmd->redir.in_path = path_ex;
					cmd->redir.in_len = toks[i].n;
				} else {
					cmd->redir.out_path = path_ex;
					cmd->redir.out_len = toks[i].n;
					cmd->redir.out_append = (rk == SH_TOK_REDIR_OUT_APP);
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

static mc_i32 sh_eval_range(const char *argv0, struct sh_tok *toks, mc_u32 start, mc_u32 end, char **envp, struct sh_ctx *ctx);

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
	// Linux wait status encoding.
	if ((st & 0x7f) == 0) {
		return (mc_i32)((st >> 8) & 0xff);
	}
	return (mc_i32)(128 + (st & 0x7f));
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

static mc_i32 sh_run_pipeline(const char *argv0, struct sh_cmd *cmds, mc_u32 ncmds, char **envp) {
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

		mc_i64 vr =
#ifdef MONACC
				mc_sys_fork();
#else
				mc_sys_vfork();
#endif
		if (vr < 0) {
			sh_print_errno(argv0, "vfork", vr);
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
			if (cmds[ci].redir.in_path) {
				mc_i64 fd = mc_sys_openat(MC_AT_FDCWD, cmds[ci].redir.in_path, MC_O_RDONLY | MC_O_CLOEXEC, 0);
				if (fd < 0) {
					sh_print_errno(argv0, "open", fd);
					mc_exit(1);
				}
				mc_i64 dr = mc_sys_dup2((mc_i32)fd, 0);
				if (dr < 0) {
					sh_print_errno(argv0, "dup2", dr);
					mc_exit(1);
				}
				(void)mc_sys_close((mc_i32)fd);
			}
			if (cmds[ci].redir.out_path) {
				mc_i32 flags = MC_O_WRONLY | MC_O_CREAT | MC_O_CLOEXEC;
				flags |= cmds[ci].redir.out_append ? MC_O_APPEND : MC_O_TRUNC;
				mc_i64 fd = mc_sys_openat(MC_AT_FDCWD, cmds[ci].redir.out_path, flags, 0666);
				if (fd < 0) {
					sh_print_errno(argv0, "open", fd);
					mc_exit(1);
				}
				mc_i64 dr = mc_sys_dup2((mc_i32)fd, 1);
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
	mc_u32 i = start;
	mc_i32 last_rc = 0;
	int next_and = 0;
	int next_or = 0;
	char argbuf[SH_MAX_LINE];
	mc_usize argoff = 0;

	while (i < end) {
		while (i < end && toks[i].kind == SH_TOK_SEMI) i++;
		if (i >= end || toks[i].kind == SH_TOK_END) break;

		int should_run = 1;
		if (next_and) should_run = (last_rc == 0);
		if (next_or) should_run = (last_rc != 0);
		next_and = 0;
		next_or = 0;

		// Reset per-command expansion buffer.
		argoff = 0;

		// Control flow
		if (toks[i].kind == SH_TOK_WORD && mc_streq(toks[i].s, "if")) {
			last_rc = sh_exec_if(argv0, toks, end, &i, should_run, envp, ctx, last_rc);
			sh_consume_sep(toks, end, &i, &next_and, &next_or);
			continue;
		}
		if (toks[i].kind == SH_TOK_WORD && mc_streq(toks[i].s, "while")) {
			last_rc = sh_exec_while(argv0, toks, end, &i, should_run, envp, ctx, last_rc);
			sh_consume_sep(toks, end, &i, &next_and, &next_or);
			continue;
		}
		if (toks[i].kind == SH_TOK_WORD && mc_streq(toks[i].s, "for")) {
			last_rc = sh_exec_for(argv0, toks, end, &i, should_run, envp, ctx, last_rc);
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
		sh_consume_sep(toks, end, &i, &next_and, &next_or);
		if (!should_run) continue;

		if (ncmds == 1 && cmds[0].argc > 0) {
			const char *cmd0 = cmds[0].argv[0];
			if (sh_is_builtin(cmd0, "cd")) {
				const char *dir = 0;
				if (cmds[0].argc >= 2) dir = cmds[0].argv[1];
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
				mc_exit(code);
			}
		}
		last_rc = sh_run_pipeline(argv0, cmds, ncmds, envp);
	}
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
		ctx.vars.n = 0;
		ctx.posc = 0;
		// -c semantics: if extra args exist, first becomes $0, rest are $1..
		if (rest_i < argc && argv[rest_i]) {
			for (; rest_i < argc && argv[rest_i] && ctx.posc < (mc_u32)(sizeof(ctx.posv) / sizeof(ctx.posv[0])); rest_i++) {
				ctx.posv[ctx.posc++] = argv[rest_i];
			}
		}
		return sh_eval_range(argv0, toks, 0, ntoks, envp, &ctx);
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
		ctx.vars.n = 0;
		ctx.posc = 0;
		// Script semantics: $0 is script path.
		ctx.posv[ctx.posc++] = file;
		for (; rest_i < argc && argv[rest_i] && ctx.posc < (mc_u32)(sizeof(ctx.posv) / sizeof(ctx.posv[0])); rest_i++) {
			ctx.posv[ctx.posc++] = argv[rest_i];
		}
		return sh_eval_range(argv0, toks, 0, ntoks, envp, &ctx);
	}

	// Interactive stdin mode.
	struct sh_reader r = { .fd = 0, .off = 0, .len = 0 };
	char line[SH_MAX_LINE];
	mc_i32 last_rc = 0;
	struct sh_ctx ictx;
	ictx.vars.n = 0;
	ictx.posc = 0;
	for (;;) {
		(void)mc_write_str(1, "$ ");
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
