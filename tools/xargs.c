#include "mc.h"

static int find_executable(char **envp, const char *cmd, char *out_path, mc_usize out_sz) {
	if (!cmd || !*cmd) return 0;
	if (mc_has_slash(cmd)) {
		// Use directly.
		mc_usize n = mc_strlen(cmd);
		if (n + 1 > out_sz) return 0;
		for (mc_usize i = 0; i < n; i++) out_path[i] = cmd[i];
		out_path[n] = 0;
		return 1;
	}

	const char *path_env = mc_getenv_kv(envp, "PATH=");
	if (!path_env) return 0;

	char cand[4096];
	const char *p = path_env;
	while (1) {
		const char *seg = p;
		while (*p && *p != ':') {
			p++;
		}
		mc_usize seg_len = (mc_usize)(p - seg);
		mc_usize cmd_len = mc_strlen(cmd);

		// Empty segment means current directory.
		if (seg_len == 0) {
			if (cmd_len + 1 <= sizeof(cand)) {
				for (mc_usize i = 0; i < cmd_len; i++) cand[i] = cmd[i];
				cand[cmd_len] = 0;
				mc_i64 r = mc_sys_faccessat(MC_AT_FDCWD, cand, MC_X_OK, 0);
				if (r >= 0) {
					if (cmd_len + 1 > out_sz) return 0;
					for (mc_usize i = 0; i < cmd_len; i++) out_path[i] = cand[i];
					out_path[cmd_len] = 0;
					return 1;
				}
			}
		} else {
			int needs_slash = 1;
			if (seg_len > 0 && seg[seg_len - 1] == '/') needs_slash = 0;
			mc_usize total = seg_len + (needs_slash ? 1 : 0) + cmd_len;
			if (total + 1 <= sizeof(cand)) {
				for (mc_usize i = 0; i < seg_len; i++) cand[i] = seg[i];
				mc_usize off = seg_len;
				if (needs_slash) cand[off++] = '/';
				for (mc_usize i = 0; i < cmd_len; i++) cand[off + i] = cmd[i];
				cand[off + cmd_len] = 0;
				mc_i64 r = mc_sys_faccessat(MC_AT_FDCWD, cand, MC_X_OK, 0);
				if (r >= 0) {
					if (total + 1 > out_sz) return 0;
					for (mc_usize i = 0; i < total; i++) out_path[i] = cand[i];
					out_path[total] = 0;
					return 1;
				}
			}
		}

		if (*p == ':') {
			p++;
			continue;
		}
		break;
	}

	return 0;
}

static int is_ws(char c) {
	return c == ' ' || c == '\n' || c == '\t' || c == '\r' || c == '\v' || c == '\f';
}

static int status_ok(mc_i32 st) {
	return mc_wait_exitcode(st) == 0;
}

static int run_one(const char *argv0, const char *path, char **argv_exec, char **envp) {
	mc_i64 pid = mc_sys_fork();
	if (pid < 0) {
		mc_die_errno(argv0, "fork", pid);
	}
	if (pid == 0) {
		mc_i64 r = mc_sys_execve(path, argv_exec, envp);
		// If exec fails, we must _exit.
		mc_die_errno(argv0, "execve", r);
	}

	mc_i32 st = 0;
	mc_i64 w = mc_sys_wait4((mc_i32)pid, &st, 0, 0);
	if (w < 0) {
		mc_die_errno(argv0, "wait4", w);
	}
	return status_ok(st) ? 0 : 1;
}

__attribute__((used)) int main(int argc, char **argv, char **envp) {
	const char *argv0 = (argc > 0 && argv && argv[0]) ? argv[0] : "xargs";

	mc_u32 max_per = 0; // 0 means "use maximum possible"
	const char *repl = 0;
	mc_usize repl_len = 0;

	int ai = 1;
	for (; ai < argc; ai++) {
		const char *a = argv[ai];
		if (!a) break;
		if (mc_streq(a, "--")) {
			ai++;
			break;
		}
		if (a[0] != '-') break;
		if (mc_streq(a, "-n")) {
			if (repl) mc_die_usage(argv0, "xargs [-n N] [-I REPL] -- CMD [ARGS...]");
			ai++;
			if (ai >= argc || !argv[ai]) mc_die_usage(argv0, "xargs [-n N] -- CMD [ARGS...]");
			if (mc_parse_u32_dec(argv[ai], &max_per) != 0 || max_per == 0) {
				mc_die_usage(argv0, "xargs [-n N] -- CMD [ARGS...]");
			}
			continue;
		}
		if (mc_streq(a, "-I")) {
			if (max_per) mc_die_usage(argv0, "xargs [-n N] [-I REPL] -- CMD [ARGS...]");
			ai++;
			if (ai >= argc || !argv[ai]) mc_die_usage(argv0, "xargs [-n N] [-I REPL] -- CMD [ARGS...]");
			repl = argv[ai];
			repl_len = mc_strlen(repl);
			if (repl_len == 0) mc_die_usage(argv0, "xargs [-n N] [-I REPL] -- CMD [ARGS...]");
			continue;
		}
		mc_die_usage(argv0, "xargs [-n N] -- CMD [ARGS...]");
	}

	if (ai >= argc || !argv[ai]) {
		mc_die_usage(argv0, repl ? "xargs [-I REPL] -- CMD [ARGS...]" : "xargs [-n N] -- CMD [ARGS...]");
	}

	const char *cmd = argv[ai++];

	// Collect fixed args that come after CMD.
	char *fixed[64];
	int fixed_n = 0;
	for (; ai < argc; ai++) {
		if (!argv[ai]) continue;
		if (fixed_n >= (int)(sizeof(fixed) / sizeof(fixed[0]))) {
			mc_die_usage(argv0, "xargs [-n N] -- CMD [ARGS...] (too many fixed args)"
			);
		}
		fixed[fixed_n++] = argv[ai];
	}

	char exec_path[4096];
	if (!find_executable(envp, cmd, exec_path, sizeof(exec_path))) {
		(void)mc_write_str(2, argv0);
		(void)mc_write_str(2, ": ");
		(void)mc_write_str(2, cmd);
		(void)mc_write_str(2, ": not found\n");
		return 1;
	}

	// -I REPL mode: run once per input token, replacing REPL in template args.
	if (repl) {
		char argbuf[8192];
		mc_usize arg_off = 0;
		int in_token = 0;
		int saw_any = 0;
		int saw_fail = 0;
		char inbuf[4096];

		for (;;) {
			mc_i64 r = mc_sys_read(0, inbuf, sizeof(inbuf));
			if (r < 0) mc_die_errno(argv0, "read", r);
			if (r == 0) break;
			for (mc_i64 bi = 0; bi < r; bi++) {
				char c = inbuf[bi];
				if (is_ws(c)) {
					if (!in_token) continue;
					if (arg_off + 1 > sizeof(argbuf)) {
						(void)mc_write_str(2, argv0);
						(void)mc_write_str(2, ": args too long\n");
						return 1;
					}
					argbuf[arg_off++] = 0;
					in_token = 0;
					saw_any = 1;

					char *tok = argbuf;
					// Build argv.
					char *argv_exec[256];
					mc_u32 k = 0;
					argv_exec[k++] = (char *)exec_path;

					char repbuf[8192];
					mc_usize roff = 0;
					int replaced_any = 0;
					for (int fi = 0; fi < fixed_n; fi++) {
						const char *templ = fixed[fi];
						if (!templ) templ = "";
						// Check if templ contains repl.
						int has = 0;
						for (const char *tp = templ; *tp; tp++) {
							if (*tp == repl[0] && mc_starts_with_n(tp, repl, repl_len)) {
								has = 1;
								break;
							}
						}
						if (!has) {
							if (k + 1 >= 256) mc_die_usage(argv0, "xargs: too many args");
							argv_exec[k++] = fixed[fi];
							continue;
						}
						replaced_any = 1;
						mc_usize start = roff;
						const char *tp = templ;
						while (*tp) {
							if (*tp == repl[0] && mc_starts_with_n(tp, repl, repl_len)) {
								mc_usize tn = mc_strlen(tok);
								if (roff + tn + 1 > sizeof(repbuf)) mc_die_usage(argv0, "xargs: args too long");
								for (mc_usize ti = 0; ti < tn; ti++) repbuf[roff++] = tok[ti];
								tp += repl_len;
								continue;
							}
							if (roff + 2 > sizeof(repbuf)) mc_die_usage(argv0, "xargs: args too long");
							repbuf[roff++] = *tp++;
						}
						repbuf[roff++] = 0;
						if (k + 1 >= 256) mc_die_usage(argv0, "xargs: too many args");
						argv_exec[k++] = &repbuf[start];
					}

					if (!replaced_any) {
						// If template has no REPL anywhere, append the token.
						if (k + 1 >= 256) mc_die_usage(argv0, "xargs: too many args");
						argv_exec[k++] = tok;
					}
					argv_exec[k] = 0;

					if (run_one(argv0, exec_path, argv_exec, envp) != 0) saw_fail = 1;
					arg_off = 0;
					continue;
				}

				// non-whitespace
				if (!in_token) {
					arg_off = 0;
					in_token = 1;
				}
				if (arg_off + 1 > sizeof(argbuf)) {
					(void)mc_write_str(2, argv0);
					(void)mc_write_str(2, ": args too long\n");
					return 1;
				}
				argbuf[arg_off++] = c;
			}
		}

		if (in_token) {
			if (arg_off + 1 > sizeof(argbuf)) {
				(void)mc_write_str(2, argv0);
				(void)mc_write_str(2, ": args too long\n");
				return 1;
			}
			argbuf[arg_off++] = 0;
			saw_any = 1;

			char *tok = argbuf;
			char *argv_exec[256];
			mc_u32 k = 0;
			argv_exec[k++] = (char *)exec_path;
			char repbuf[8192];
			mc_usize roff = 0;
			int replaced_any = 0;
			for (int fi = 0; fi < fixed_n; fi++) {
				const char *templ = fixed[fi];
				if (!templ) templ = "";
				int has = 0;
				for (const char *tp = templ; *tp; tp++) {
					if (*tp == repl[0] && mc_starts_with_n(tp, repl, repl_len)) { has = 1; break; }
				}
				if (!has) {
					argv_exec[k++] = fixed[fi];
					continue;
				}
				replaced_any = 1;
				mc_usize start = roff;
				const char *tp = templ;
				while (*tp) {
					if (*tp == repl[0] && mc_starts_with_n(tp, repl, repl_len)) {
						mc_usize tn = mc_strlen(tok);
						if (roff + tn + 1 > sizeof(repbuf)) mc_die_usage(argv0, "xargs: args too long");
						for (mc_usize ti = 0; ti < tn; ti++) repbuf[roff++] = tok[ti];
						tp += repl_len;
						continue;
					}
					repbuf[roff++] = *tp++;
				}
				repbuf[roff++] = 0;
				argv_exec[k++] = &repbuf[start];
			}
			if (!replaced_any) argv_exec[k++] = tok;
			argv_exec[k] = 0;
			if (run_one(argv0, exec_path, argv_exec, envp) != 0) saw_fail = 1;
		}

		if (!saw_any) return 0;
		return saw_fail ? 1 : 0;
	}

	// Cap by our fixed argv buffer.
	const mc_u32 argv_cap = 256;
	mc_u32 batch_cap = argv_cap - 1u - (mc_u32)fixed_n - 1u; // cmd + fixed + batch + NULL
	if (batch_cap > 200u) batch_cap = 200u;
	if (max_per == 0) {
		max_per = batch_cap;
	}
	if (max_per > batch_cap) {
		mc_die_usage(argv0, "xargs [-n N] -- CMD [ARGS...] (N too large)"
		);
	}

	char argbuf[8192];
	mc_usize arg_off = 0;
	mc_u32 batch_n = 0;
	char *batch_args[200];
	int saw_any = 0;

	char inbuf[4096];
	int in_token = 0;
	for (;;) {
		mc_i64 r = mc_sys_read(0, inbuf, sizeof(inbuf));
		if (r < 0) {
			mc_die_errno(argv0, "read", r);
		}
		if (r == 0) break;
		for (mc_i64 i = 0; i < r; i++) {
			char c = inbuf[i];
			if (is_ws(c)) {
				if (in_token) {
					if (arg_off + 1 > sizeof(argbuf)) {
						(void)mc_write_str(2, argv0);
						(void)mc_write_str(2, ": args too long\n");
						return 1;
					}
					argbuf[arg_off++] = 0;
					in_token = 0;
					batch_n++;
					saw_any = 1;
					if (batch_n >= max_per) {
						char *argv_exec[256];
						mc_u32 k = 0;
						argv_exec[k++] = (char *)exec_path;
						for (int fi = 0; fi < fixed_n; fi++) argv_exec[k++] = fixed[fi];
						for (mc_u32 bi = 0; bi < batch_n; bi++) argv_exec[k++] = batch_args[bi];
						argv_exec[k] = 0;
						if (run_one(argv0, exec_path, argv_exec, envp) != 0) {
							// Continue but remember failure.
							saw_any = 2;
						}
						batch_n = 0;
						arg_off = 0;
					}
				}
				continue;
			}

			// non-whitespace
			if (!in_token) {
				if (batch_n >= (mc_u32)(sizeof(batch_args) / sizeof(batch_args[0]))) {
					(void)mc_write_str(2, argv0);
					(void)mc_write_str(2, ": too many args\n");
					return 1;
				}
				batch_args[batch_n] = &argbuf[arg_off];
				in_token = 1;
			}
			if (arg_off + 1 > sizeof(argbuf)) {
				(void)mc_write_str(2, argv0);
				(void)mc_write_str(2, ": args too long\n");
				return 1;
			}
			argbuf[arg_off++] = c;
		}
	}

	if (in_token) {
		if (arg_off + 1 > sizeof(argbuf)) {
			(void)mc_write_str(2, argv0);
			(void)mc_write_str(2, ": args too long\n");
			return 1;
		}
		argbuf[arg_off++] = 0;
		batch_n++;
		saw_any = 1;
	}

	if (batch_n > 0) {
		char *argv_exec[256];
		mc_u32 k = 0;
		argv_exec[k++] = (char *)exec_path;
		for (int fi = 0; fi < fixed_n; fi++) argv_exec[k++] = fixed[fi];
		for (mc_u32 bi = 0; bi < batch_n; bi++) argv_exec[k++] = batch_args[bi];
		argv_exec[k] = 0;
		if (run_one(argv0, exec_path, argv_exec, envp) != 0) {
			saw_any = 2;
		}
	}

	// If there was no input, do nothing.
	if (!saw_any) return 0;
	// saw_any==2 indicates some invocation failed.
	return (saw_any == 2) ? 1 : 0;
}
