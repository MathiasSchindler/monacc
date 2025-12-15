#include "mc.h"

static const char *time_getenv(char **envp, const char *key_eq) {
	if (!envp || !key_eq) {
		return 0;
	}
	mc_usize klen = mc_strlen(key_eq);
	for (mc_usize i = 0; envp[i]; i++) {
		const char *e = envp[i];
		int ok = 1;
		for (mc_usize j = 0; j < klen; j++) {
			if (e[j] != key_eq[j]) {
				ok = 0;
				break;
			}
		}
		if (ok) {
			return e + klen;
		}
	}
	return 0;
}

static int time_has_slash(const char *s) {
	if (!s) return 0;
	for (const char *p = s; *p; p++) {
		if (*p == '/') return 1;
	}
	return 0;
}

static mc_i64 time_try_exec_path(const char *path, char **argv, char **envp) {
	return mc_sys_execve(path, argv, envp);
}

static mc_i64 time_execvp(const char *file, char **argv, char **envp) {
	if (!file || !*file) {
		return (mc_i64)-MC_ENOENT;
	}
	if (time_has_slash(file)) {
		return time_try_exec_path(file, argv, envp);
	}

	const char *path_env = time_getenv(envp, "PATH=");
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

			mc_i64 r = time_try_exec_path(full, argv, envp);
			// If execve failed with ENOENT/ENOTDIR, continue searching; otherwise return.
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

static void time_write_u64_09(mc_i32 fd, mc_u64 v) {
	char buf[9];
	for (int i = 8; i >= 0; i--) {
		mc_u64 q = v / 10u;
		mc_u64 r = v - q * 10u;
		buf[i] = (char)('0' + (char)r);
		v = q;
	}
	(void)mc_write_all(fd, buf, 9);
}

static int time_exit_code_from_wait_status(mc_i32 status) {
	mc_u32 u = (mc_u32)status;
	mc_u32 sig = u & 0x7Fu;
	if (sig != 0) {
		return 128 + (int)sig;
	}
	return (int)((u >> 8) & 0xFFu);
}

__attribute__((used)) int main(int argc, char **argv, char **envp) {
	const char *argv0 = (argc > 0 && argv && argv[0]) ? argv[0] : "time";

	int i = 1;
	for (; i < argc; i++) {
		const char *a = argv[i];
		if (!a || a[0] != '-' || mc_streq(a, "-")) {
			break;
		}
		if (mc_streq(a, "--")) {
			i++;
			break;
		}
		mc_die_usage(argv0, "time [--] CMD [ARGS...]");
	}

	if (i >= argc) {
		mc_die_usage(argv0, "time [--] CMD [ARGS...]");
	}

	char **cmd_argv = &argv[i];
	const char *cmd = argv[i] ? argv[i] : "";

	struct mc_timespec t0;
	struct mc_timespec t1;
	mc_i64 r = mc_sys_clock_gettime(MC_CLOCK_MONOTONIC, &t0);
	if (r < 0) {
		mc_die_errno(argv0, "clock_gettime", r);
	}

	mc_i64 pid =
#ifdef MONACC
			mc_sys_fork();
#else
			mc_sys_vfork();
#endif
	if (pid < 0) {
		mc_die_errno(argv0, "vfork", pid);
	}

	if (pid == 0) {
		mc_i64 er = time_execvp(cmd, cmd_argv, envp);
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
	if (w < 0) {
		mc_die_errno(argv0, "wait4", w);
	}

	r = mc_sys_clock_gettime(MC_CLOCK_MONOTONIC, &t1);
	if (r < 0) {
		mc_die_errno(argv0, "clock_gettime", r);
	}

	mc_i64 sec = t1.tv_sec - t0.tv_sec;
	mc_i64 nsec = t1.tv_nsec - t0.tv_nsec;
	if (nsec < 0) {
		sec -= 1;
		nsec += 1000000000LL;
	}
	if (sec < 0) {
		sec = 0;
		nsec = 0;
	}

	(void)mc_write_str(2, "real ");
	(void)mc_write_i64_dec(2, sec);
	(void)mc_write_str(2, ".");
	time_write_u64_09(2, (mc_u64)nsec);
	(void)mc_write_str(2, "\n");

	return time_exit_code_from_wait_status(status);
}
