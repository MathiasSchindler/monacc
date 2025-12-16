#include "mc.h"

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

	mc_i64 pid = mc_sys_fork();
	if (pid < 0) {
		mc_die_errno(argv0, "fork", pid);
	}

	if (pid == 0) {
		mc_i64 er = mc_execvp(cmd, cmd_argv, envp);
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
	return (int)mc_wait_exitcode(status);
}
