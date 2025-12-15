#include "mc.h"

static int env_find_executable(char **envp, const char *cmd, char *out_path, mc_usize out_sz) {
	if (!cmd || !*cmd) return 0;
	if (mc_has_slash(cmd)) {
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
		while (*p && *p != ':') p++;
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
			mc_usize total = seg_len + (needs_slash ? 1u : 0u) + cmd_len;
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


static int env_is_assignment(const char *s) {
	if (!s || !*s) return 0;
	if (*s == '=') return 0;
	for (const char *p = s; *p; p++) {
		if (*p == '=') return 1;
	}
	return 0;
}

static int env_is_valid_key(const char *s) {
	// Minimal: KEY must be non-empty and contain no '='.
	// (We intentionally do not validate against POSIX name rules.)
	if (!s || !*s) return 0;
	for (const char *p = s; *p; p++) {
		if (*p == '=') return 0;
	}
	return 1;
}

static mc_usize env_key_len(const char *assign) {
	mc_usize n = 0;
	while (assign[n] && assign[n] != '=') n++;
	return n;
}

static int env_key_matches(const char *env_entry, const char *assign, mc_usize key_len) {
	// Compare KEY portion and require env_entry[key_len] == '='
	for (mc_usize i = 0; i < key_len; i++) {
		if (env_entry[i] != assign[i]) return 0;
		if (env_entry[i] == 0) return 0;
	}
	return env_entry[key_len] == '=';
}

static void env_unset_inplace(char **env, mc_u32 *env_n, const char *key, mc_usize key_len) {
	if (!env || !env_n || !key || key_len == 0) return;
	mc_u32 out = 0;
	for (mc_u32 i = 0; i < *env_n; i++) {
		char *e = env[i];
		if (!e) continue;
		if (env_key_matches(e, key, key_len)) {
			continue;
		}
		env[out++] = e;
	}
	*env_n = out;
}

__attribute__((used)) int main(int argc, char **argv, char **envp) {
	const char *argv0 = (argc > 0 && argv && argv[0]) ? argv[0] : "env";

	int clear_env = 0;
	int null_sep = 0;

	int i = 1;
	for (; i < argc; i++) {
		const char *a = argv[i];
		if (!a) break;
		if (mc_streq(a, "--")) {
			i++;
			break;
		}
		if (mc_streq(a, "-u")) {
			// -u can appear interleaved with assignments; handle in the next phase.
			break;
		}
		if (a[0] != '-') break;
		if (mc_streq(a, "-i")) {
			clear_env = 1;
			continue;
		}
		if (mc_streq(a, "-0")) {
			null_sep = 1;
			continue;
		}
		mc_die_usage(argv0, "env [-i] [-0] [-u NAME]... [NAME=VALUE...] [CMD [ARGS...]]");
	}

	// Build a new env pointer list.
	char *new_env[256];
	mc_u32 new_n = 0;

	if (!clear_env) {
		for (mc_u32 ei = 0; envp && envp[ei]; ei++) {
			if (new_n + 1 >= (mc_u32)(sizeof(new_env) / sizeof(new_env[0]))) {
				mc_die_usage(argv0, "env: environment too large");
			}
			new_env[new_n++] = envp[ei];
		}
	}

	// Apply modifications (interleaved): -u NAME and NAME=VALUE.
	for (; i < argc; ) {
		const char *a = argv[i];
		if (!a) {
			i++;
			continue;
		}
		if (mc_streq(a, "--")) {
			i++;
			break;
		}
		if (mc_streq(a, "-0")) {
			null_sep = 1;
			i++;
			continue;
		}
		if (mc_streq(a, "-u")) {
			if (i + 1 >= argc || !argv[i + 1]) {
				mc_die_usage(argv0, "env [-i] [-0] [-u NAME]... [NAME=VALUE...] [CMD [ARGS...]]");
			}
			const char *k = argv[i + 1];
			if (!env_is_valid_key(k)) {
				mc_die_usage(argv0, "env [-i] [-0] [-u NAME]... [NAME=VALUE...] [CMD [ARGS...]]");
			}
			env_unset_inplace(new_env, &new_n, k, mc_strlen(k));
			i += 2;
			continue;
		}
		if (!env_is_assignment(a)) {
			break;
		}

		mc_usize klen = env_key_len(a);
		int replaced = 0;
		for (mc_u32 ei = 0; ei < new_n; ei++) {
			const char *e = new_env[ei];
			if (!e) continue;
			if (env_key_matches(e, a, klen)) {
				new_env[ei] = (char *)a;
				replaced = 1;
				break;
			}
		}
		if (!replaced) {
			if (new_n + 1 >= (mc_u32)(sizeof(new_env) / sizeof(new_env[0]))) {
				mc_die_usage(argv0, "env: too many assignments");
			}
			new_env[new_n++] = (char *)a;
		}
		i++;
	}
	new_env[new_n] = 0;

	// If no CMD: print environment.
	if (i >= argc || !argv[i]) {
		char sep = null_sep ? (char)0 : '\n';
		for (mc_u32 ei = 0; ei < new_n; ei++) {
			const char *e = new_env[ei];
			if (!e) continue;
			mc_i64 w = mc_write_str(1, e);
			if (w < 0) mc_die_errno(argv0, "write", w);
			w = mc_write_all(1, &sep, 1);
			if (w < 0) mc_die_errno(argv0, "write", w);
		}
		return 0;
	}

	// Exec CMD with modified env.
	const char *cmd = argv[i++];
	if (!cmd || !*cmd) {
		mc_die_usage(argv0, "env [-i] [-0] [-u NAME]... [NAME=VALUE...] [CMD [ARGS...]]");
	}

	// Build argv for exec: argv0 is the original cmd token.
	char *argv_exec[256];
	mc_u32 an = 0;
	argv_exec[an++] = (char *)cmd;
	for (; i < argc; i++) {
		if (an + 1 >= (mc_u32)(sizeof(argv_exec) / sizeof(argv_exec[0]))) {
			mc_die_usage(argv0, "env: too many args");
		}
		argv_exec[an++] = argv[i];
	}
	argv_exec[an] = 0;

	char exec_path[4096];
	if (!env_find_executable(new_env, cmd, exec_path, sizeof(exec_path))) {
		(void)mc_write_str(2, argv0);
		(void)mc_write_str(2, ": ");
		(void)mc_write_str(2, cmd);
		(void)mc_write_str(2, ": not found\n");
		return 1;
	}

	mc_i64 r = mc_sys_execve(exec_path, argv_exec, new_env);
	// Only reaches here on error.
	mc_print_errno(argv0, "execve", r);
	return 1;
}
