#include "mc.h"

static int which_try_path(const char *argv0, const char *path) {
	mc_i64 r = mc_sys_faccessat(MC_AT_FDCWD, path, MC_X_OK, 0);
	if (r < 0) {
		return 0;
	}
	r = mc_write_str(1, path);
	if (r < 0) mc_die_errno(argv0, "write", r);
	r = mc_write_all(1, "\n", 1);
	if (r < 0) mc_die_errno(argv0, "write", r);
	return 1;
}

static int which_find(const char *argv0, char **envp, const char *cmd, int all) {
	if (!cmd || !*cmd) {
		return 0;
	}

	if (mc_has_slash(cmd)) {
		return which_try_path(argv0, cmd);
	}

	const char *path_env = mc_getenv_kv(envp, "PATH=");
	if (!path_env) {
		return 0;
	}

	char cand[4096];
	const char *p = path_env;
	int found = 0;
	while (1) {
		const char *seg = p;
		while (*p && *p != ':') {
			p++;
		}
		mc_usize seg_len = (mc_usize)(p - seg);
		mc_usize cmd_len = mc_strlen(cmd);

		// Empty segment means current directory.
		if (seg_len == 0) {
			if (cmd_len + 1 > sizeof(cand)) {
				return found;
			}
			for (mc_usize i = 0; i < cmd_len; i++) {
				cand[i] = cmd[i];
			}
			cand[cmd_len] = 0;
			if (which_try_path(argv0, cand)) {
				found = 1;
				if (!all) return 1;
			}
		} else {
			int needs_slash = 1;
			if (seg_len > 0 && seg[seg_len - 1] == '/') {
				needs_slash = 0;
			}
			mc_usize total = seg_len + (needs_slash ? 1 : 0) + cmd_len;
			if (total + 1 > sizeof(cand)) {
				return found;
			}
			for (mc_usize i = 0; i < seg_len; i++) {
				cand[i] = seg[i];
			}
			mc_usize off = seg_len;
			if (needs_slash) {
				cand[off++] = '/';
			}
			for (mc_usize i = 0; i < cmd_len; i++) {
				cand[off + i] = cmd[i];
			}
			cand[off + cmd_len] = 0;
			if (which_try_path(argv0, cand)) {
				found = 1;
				if (!all) return 1;
			}
		}

		if (*p == ':') {
			p++;
			continue;
		}
		break;
	}

	return found;
}

__attribute__((used)) int main(int argc, char **argv, char **envp) {
	const char *argv0 = (argc > 0 && argv && argv[0]) ? argv[0] : "which";
	int all = 0;

	int i = 1;
	for (; i < argc; i++) {
		const char *a = argv[i];
		if (!a) break;
		if (mc_streq(a, "--")) {
			i++;
			break;
		}
		if (mc_streq(a, "-a")) {
			all = 1;
			continue;
		}
		if (a[0] == '-' && a[1] != 0) {
			mc_die_usage(argv0, "which [-a] CMD...");
		}
		break;
	}

	if (i >= argc) {
		mc_die_usage(argv0, "which [-a] CMD...");
	}

	int ok = 1;
	for (; i < argc; i++) {
		const char *cmd = argv[i];
		if (!cmd) continue;
		if (!which_find(argv0, envp, cmd, all)) {
			ok = 0;
		}
	}

	return ok ? 0 : 1;
}
