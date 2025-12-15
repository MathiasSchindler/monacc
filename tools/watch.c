#include "mc.h"

static int watch_has_slash(const char *s) {
	if (!s) return 0;
	for (const char *p = s; *p; p++) {
		if (*p == '/') return 1;
	}
	return 0;
}

static const char *watch_getenv(char **envp, const char *key_eq) {
	return mc_getenv_kv(envp, key_eq);
}

static mc_i64 watch_try_exec_path(const char *path, char **argv, char **envp) {
	return mc_sys_execve(path, argv, envp);
}

static mc_i64 watch_execvp(const char *file, char **argv, char **envp) {
	if (!file || !*file) {
		return (mc_i64)-MC_ENOENT;
	}
	if (watch_has_slash(file)) {
		return watch_try_exec_path(file, argv, envp);
	}

	const char *path_env = watch_getenv(envp, "PATH=");
	if (!path_env || !*path_env) {
		path_env = "/bin:/usr/bin";
	}

	char full[4096];
	mc_usize fn = mc_strlen(file);

	const char *p = path_env;
	for (;;) {
		const char *seg = p;
		while (*p && *p != ':') {
			p++;
		}
		mc_usize seglen = (mc_usize)(p - seg);

		// dir + '/' + file + '\0'
		if (seglen + 1 + fn + 1 <= sizeof(full)) {
			mc_usize k = 0;
			for (; k < seglen; k++) full[k] = seg[k];
			if (k == 0) {
				full[k++] = '.';
			}
			if (full[k - 1] != '/') {
				full[k++] = '/';
			}
			for (mc_usize j = 0; j < fn; j++) full[k + j] = file[j];
			k += fn;
			full[k] = 0;

			mc_i64 r = watch_try_exec_path(full, argv, envp);
			if (r < 0) {
				mc_u64 e = (mc_u64)(-r);
				if (e != (mc_u64)MC_ENOENT && e != (mc_u64)MC_ENOTDIR) {
					return r;
				}
			}
		}

		if (*p == ':') {
			p++;
			continue;
		}
		break;
	}

	return (mc_i64)-MC_ENOENT;
}

static int watch_exit_code_from_wait_status(mc_i32 status) {
	mc_u32 u = (mc_u32)status;
	mc_u32 sig = u & 0x7Fu;
	if (sig != 0) {
		return 128 + (int)sig;
	}
	return (int)((u >> 8) & 0xFFu);
}

__attribute__((used)) int main(int argc, char **argv, char **envp) {
	const char *argv0 = (argc > 0 && argv && argv[0]) ? argv[0] : "watch";

	mc_u64 interval = 2;

	int i = 1;
	for (; i < argc; i++) {
		const char *a = argv[i];
		if (!a) break;
		if (mc_streq(a, "--")) {
			i++;
			break;
		}
		if (mc_streq(a, "-n")) {
			if (i + 1 >= argc || !argv[i + 1]) mc_die_usage(argv0, "watch [-n SECS] [--] CMD [ARGS...]");
			if (mc_parse_u64_dec(argv[++i], &interval) != 0) mc_die_usage(argv0, "watch [-n SECS] [--] CMD [ARGS...]");
			continue;
		}
		if (a[0] == '-') mc_die_usage(argv0, "watch [-n SECS] [--] CMD [ARGS...]");
		break;
	}

	if (i >= argc) mc_die_usage(argv0, "watch [-n SECS] [--] CMD [ARGS...]");

	char **cmd_argv = &argv[i];
	const char *cmd = argv[i] ? argv[i] : "";

	while (1) {
		// Clear screen + home
		(void)mc_write_str(1, "\033[H\033[2J");
		(void)mc_write_str(1, "Every ");
		(void)mc_write_u64_dec(1, interval);
		(void)mc_write_str(1, "s: ");
		(void)mc_write_str(1, cmd);
		(void)mc_write_str(1, "\n\n");

		mc_i64 pid =
#ifdef MONACC
				mc_sys_fork();
#else
				mc_sys_vfork();
#endif
		if (pid < 0) mc_die_errno(argv0, "vfork", pid);
		if (pid == 0) {
			mc_i64 er = watch_execvp(cmd, cmd_argv, envp);
			(void)mc_write_str(2, argv0);
			(void)mc_write_str(2, ": ");
			(void)mc_write_str(2, cmd);
			(void)mc_write_str(2, ": errno=");
			mc_write_hex_u64(2, (mc_u64)(-er));
			(void)mc_write_str(2, "\n");
			mc_exit(127);
		}

		mc_i32 status = 0;
		mc_i64 w = mc_sys_wait4((mc_i32)pid, &status, 0, 0);
		if (w < 0) mc_die_errno(argv0, "wait4", w);
		(void)watch_exit_code_from_wait_status(status);

		struct mc_timespec ts;
		ts.tv_sec = (mc_i64)interval;
		ts.tv_nsec = 0;
		(void)mc_sys_nanosleep(&ts, 0);
	}
}
