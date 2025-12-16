#include "mc.h"

// Minimal find subset (syscall-only):
// - Usage: find [PATH...] [EXPR]
// - PATH: defaults to '.' if none.
// - EXPR (AND-only; left-to-right):
//     -name PAT    (PAT supports '*' and '?' only; match against basename)
//     -type [f|d|l]
//     -mindepth N
//     -maxdepth N
//     -print       (default action if no action is specified)
//     -exec CMD... {} ... \;   (run once per match)
// - Traversal is pre-order; does not follow symlinks when recursing.


struct find_expr {
	const char *name_pat;
	int has_type;
	mc_u32 type_mode; // MC_S_IFREG/MC_S_IFDIR/MC_S_IFLNK
	int has_mindepth;
	mc_i32 mindepth;
	int has_maxdepth;
	mc_i32 maxdepth;

	int has_action;
	int do_print;

	int has_exec;
	int exec_argc;
	const char **exec_argv; // points into argv[]; length exec_argc
};

static const char *find_basename(const char *path) {
	if (!path) return "";
	const char *last = path;
	for (const char *p = path; *p; p++) {
		if (*p == '/') last = p + 1;
	}
	// If path ends with '/', last points to NUL, return empty.
	return last;
}

static int find_match_name(const char *pat, const char *s) {
	// Glob match with '*' and '?', no character classes.
	// Escape support: backslash escapes next char.
	const char *p = pat;
	const char *t = s;
	const char *star_p = 0;
	const char *star_t = 0;

	while (*t) {
		char pc = *p;
		if (pc == '\\' && p[1]) {
			pc = p[1];
			if (pc == *t) {
				p += 2;
				t++;
				continue;
			}
		} else if (pc == '?') {
			p++;
			t++;
			continue;
		} else if (pc == '*') {
			star_p = ++p;
			star_t = t;
			continue;
		} else if (pc && pc == *t) {
			p++;
			t++;
			continue;
		}

		if (star_p) {
			p = star_p;
			t = ++star_t;
			continue;
		}
		return 0;
	}

	// Consume remaining stars.
	while (*p == '*') p++;
	// Allow trailing escape to be treated literally (but it can't match empty).
	return *p == 0;
}

static int find_match(const struct find_expr *e, const char *path, const struct mc_stat *st, mc_i32 depth) {
	if (e->has_mindepth && depth < e->mindepth) return 0;
	if (e->name_pat) {
		const char *bn = find_basename(path);
		if (!find_match_name(e->name_pat, bn)) return 0;
	}
	if (e->has_type) {
		mc_u32 t = st->st_mode & MC_S_IFMT;
		if (t != e->type_mode) return 0;
	}
	return 1;
}

static void find_print_path_or_die(const char *argv0, const char *path) {
	if (mc_write_str(1, path) < 0) mc_die_errno(argv0, "write", -1);
	if (mc_write_all(1, "\n", 1) < 0) mc_die_errno(argv0, "write", -1);
}

static const char *find_exec_subst_braces(const char *arg, const char *path, char *storage, mc_usize storage_cap, mc_usize *io_used) {
	if (!arg) arg = "";
	if (!path) path = "";
	if (!storage || storage_cap == 0 || !io_used) return 0;

	// Fast path: no "{}".
	int needs = 0;
	for (const char *p = arg; *p; p++) {
		if (p[0] == '{' && p[1] == '}') {
			needs = 1;
			break;
		}
	}
	if (!needs) return arg;

	mc_usize path_len = mc_strlen(path);
	mc_usize out_len = 0;
	for (const char *p = arg; *p; ) {
		if (p[0] == '{' && p[1] == '}') {
			out_len += path_len;
			p += 2;
		} else {
			out_len += 1;
			p += 1;
		}
	}

	if (out_len + 1 > storage_cap - *io_used) return 0;
	char *dst = &storage[*io_used];
	*io_used += out_len + 1;

	mc_usize k = 0;
	for (const char *p = arg; *p; ) {
		if (p[0] == '{' && p[1] == '}') {
			for (mc_usize j = 0; j < path_len; j++) dst[k + j] = path[j];
			k += path_len;
			p += 2;
		} else {
			dst[k++] = *p++;
		}
	}
	dst[k] = 0;
	return dst;
}

static void find_run_exec(const char *argv0, const struct find_expr *e, const char *path, char **envp, int *any_fail) {
	if (!e->has_exec || e->exec_argc <= 0 || !e->exec_argv) {
		return;
	}

	char repl_storage[16384];
	mc_usize repl_used = 0;

	// Keep this intentionally small: fixed argv size, no heap.
	char *argv_exec[64];
	int outc = 0;
	for (int i = 0; i < e->exec_argc && outc + 1 < (int)(sizeof(argv_exec) / sizeof(argv_exec[0])); i++) {
		const char *a = e->exec_argv[i];
		const char *r = find_exec_subst_braces(a, path, repl_storage, (mc_usize)sizeof(repl_storage), &repl_used);
		if (!r) {
			(void)mc_write_str(2, argv0);
			(void)mc_write_str(2, ": -exec: substitution too large\n");
			*any_fail = 1;
			return;
		}
		argv_exec[outc++] = (char *)r;
	}
	argv_exec[outc] = 0;
	if (outc == 0) {
		*any_fail = 1;
		return;
	}

	mc_i64 pid = mc_sys_fork();
	if (pid < 0) {
		mc_print_errno(argv0, "fork", pid);
		*any_fail = 1;
		return;
	}
	if (pid == 0) {
		mc_i64 r = mc_execvp(argv_exec[0], argv_exec, envp);
		(void)mc_write_str(2, argv0);
		(void)mc_write_str(2, ": -exec: ");
		(void)mc_write_str(2, argv_exec[0]);
		(void)mc_write_str(2, ": errno=");
		mc_write_hex_u64(2, (mc_u64)(-r));
		(void)mc_write_str(2, "\n");
		mc_exit(127);
	}

	mc_i32 status = 0;
	mc_i64 w = mc_sys_wait4((mc_i32)pid, &status, 0, 0);
	if (w < 0) {
		mc_print_errno(argv0, "wait4", w);
		*any_fail = 1;
		return;
	}
	int rc = (int)mc_wait_exitcode(status);
	if (rc != 0) {
		*any_fail = 1;
	}
}

static void find_walk(const char *argv0, const struct find_expr *e, const char *path, mc_i32 depth, char **envp, int *any_fail);

struct find_dir_iter_ctx {
	const char *argv0;
	const struct find_expr *expr;
	const char *path;
	mc_i32 depth;
	char **envp;
	int *any_fail;
};

static int find_dir_iter_cb(void *ctxp, const char *name, mc_u8 d_type) {
	(void)d_type;
	struct find_dir_iter_ctx *ctx = (struct find_dir_iter_ctx *)ctxp;
	char child[4096];
	mc_join_path_or_die(ctx->argv0, ctx->path, name, child, (mc_usize)sizeof(child));
	find_walk(ctx->argv0, ctx->expr, child, ctx->depth + 1, ctx->envp, ctx->any_fail);
	return 0;
}

static void find_walk(const char *argv0, const struct find_expr *e, const char *path, mc_i32 depth, char **envp, int *any_fail) {
	if (depth > 64) {
		mc_print_errno(argv0, path, (mc_i64)-MC_ELOOP);
		*any_fail = 1;
		return;
	}

	struct mc_stat st;
	mc_i64 sr = mc_sys_newfstatat(MC_AT_FDCWD, path, &st, MC_AT_SYMLINK_NOFOLLOW);
	if (sr < 0) {
		mc_print_errno(argv0, path, sr);
		*any_fail = 1;
		return;
	}

	if (find_match(e, path, &st, depth)) {
		if (e->do_print) {
			find_print_path_or_die(argv0, path);
		}
		if (e->has_exec) {
			find_run_exec(argv0, e, path, envp, any_fail);
		}
	}

	// Stop recursion if maxdepth reached.
	if (e->has_maxdepth && depth >= e->maxdepth) {
		return;
	}

	mc_u32 t = st.st_mode & MC_S_IFMT;
	if (t != MC_S_IFDIR) return;

	// Do not recurse into symlinked dirs (O_NOFOLLOW).
	mc_i64 dfd = mc_sys_openat(MC_AT_FDCWD, path, MC_O_RDONLY | MC_O_CLOEXEC | MC_O_DIRECTORY | MC_O_NOFOLLOW, 0);
	if (dfd < 0) {
		// If it's a symlink, just don't recurse.
		if ((mc_u64)(-dfd) == (mc_u64)MC_ELOOP) return;
		mc_print_errno(argv0, path, dfd);
		*any_fail = 1;
		return;
	}

	struct find_dir_iter_ctx ictx = {
		.argv0 = argv0,
		.expr = e,
		.path = path,
		.depth = depth,
		.envp = envp,
		.any_fail = any_fail,
	};
	mc_i64 ir = mc_for_each_dirent((mc_i32)dfd, find_dir_iter_cb, &ictx);
	if (ir < 0) {
		(void)mc_sys_close((mc_i32)dfd);
		mc_print_errno(argv0, "getdents64", ir);
		*any_fail = 1;
		return;
	}

	(void)mc_sys_close((mc_i32)dfd);
}

__attribute__((used)) int main(int argc, char **argv, char **envp) {
	const char *argv0 = (argc > 0 && argv && argv[0]) ? argv[0] : "find";

	struct find_expr expr = {0};
	int i = 1;

	// Collect paths: any leading args not starting with '-' and not equal to '--'.
	int path_start = i;
	int n_paths = 0;
	for (; i < argc; i++) {
		const char *a = argv[i];
		if (!a) break;
		if (mc_streq(a, "--")) {
			i++;
			break;
		}
		if (a[0] == '-') break;
		n_paths++;
	}

	// Parse expression tokens.
	for (; i < argc; i++) {
		const char *a = argv[i];
		if (!a) continue;
		if (mc_streq(a, "-print")) {
			expr.has_action = 1;
			expr.do_print = 1;
			continue;
		}
		if (mc_streq(a, "-name")) {
			i++;
			if (i >= argc || !argv[i]) mc_die_usage(argv0, "find [PATH...] [-name PAT] [-type f|d|l] [-mindepth N] [-maxdepth N] [-print] [-exec CMD... {} ... \\;]");
			expr.name_pat = argv[i];
			continue;
		}
		if (mc_streq(a, "-type")) {
			i++;
			if (i >= argc || !argv[i]) mc_die_usage(argv0, "find [PATH...] [-name PAT] [-type f|d|l] [-mindepth N] [-maxdepth N] [-print] [-exec CMD... {} ... \\;]");
			const char *t = argv[i];
			if (!t[0] || t[1]) mc_die_usage(argv0, "find: -type expects one of f,d,l");
			expr.has_type = 1;
			if (t[0] == 'f') expr.type_mode = MC_S_IFREG;
			else if (t[0] == 'd') expr.type_mode = MC_S_IFDIR;
			else if (t[0] == 'l') expr.type_mode = MC_S_IFLNK;
			else mc_die_usage(argv0, "find: -type expects one of f,d,l");
			continue;
		}
		if (mc_streq(a, "-mindepth")) {
			i++;
			if (i >= argc || !argv[i]) mc_die_usage(argv0, "find [PATH...] [-name PAT] [-type f|d|l] [-mindepth N] [-maxdepth N] [-print] [-exec CMD... {} ... \\;]");
			mc_i32 v = 0;
			if (mc_parse_i32_dec(argv[i], &v) != 0 || v < 0) mc_die_usage(argv0, "find: -mindepth expects non-negative integer");
			expr.has_mindepth = 1;
			expr.mindepth = v;
			continue;
		}
		if (mc_streq(a, "-maxdepth")) {
			i++;
			if (i >= argc || !argv[i]) mc_die_usage(argv0, "find [PATH...] [-name PAT] [-type f|d|l] [-mindepth N] [-maxdepth N] [-print] [-exec CMD... {} ... \\;]");
			mc_i32 v = 0;
			if (mc_parse_i32_dec(argv[i], &v) != 0 || v < 0) mc_die_usage(argv0, "find: -maxdepth expects non-negative integer");
			expr.has_maxdepth = 1;
			expr.maxdepth = v;
			continue;
		}
		if (mc_streq(a, "-exec")) {
			int start = i + 1;
			int end = start;
			for (; end < argc; end++) {
				const char *t = argv[end];
				if (!t) continue;
				if (mc_streq(t, ";") || mc_streq(t, "\\;")) {
					break;
				}
			}
			if (start >= argc || end >= argc) {
				mc_die_usage(argv0, "find: -exec expects: -exec CMD... {} ... \\;");
			}
			if (end - start <= 0) {
				mc_die_usage(argv0, "find: -exec expects at least a command");
			}
			if (end - start >= 63) {
				mc_die_usage(argv0, "find: -exec supports up to 62 args");
			}
			expr.has_action = 1;
			expr.has_exec = 1;
			expr.exec_argv = (const char **)&argv[start];
			expr.exec_argc = end - start;
			i = end; // skip until terminator
			continue;
		}
		// Unknown token.
		mc_die_usage(argv0, "find [PATH...] [-name PAT] [-type f|d|l] [-mindepth N] [-maxdepth N] [-print] [-exec CMD... {} ... \\;]");
	}

	if (!expr.has_action) {
		expr.do_print = 1;
	}

	int any_fail = 0;
	if (n_paths == 0) {
		find_walk(argv0, &expr, ".", 0, envp, &any_fail);
		return any_fail ? 1 : 0;
	}

	for (int pi = 0; pi < n_paths; pi++) {
		const char *p = argv[path_start + pi];
		if (!p) continue;
		find_walk(argv0, &expr, p, 0, envp, &any_fail);
	}

	return any_fail ? 1 : 0;
}
