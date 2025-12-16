#include "mc.h"
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

		mc_i64 pid = mc_sys_fork();
		if (pid < 0) mc_die_errno(argv0, "fork", pid);
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
		if (w < 0) mc_die_errno(argv0, "wait4", w);
		(void)mc_wait_exitcode(status);

		struct mc_timespec ts;
		ts.tv_sec = (mc_i64)interval;
		ts.tv_nsec = 0;
		(void)mc_sys_nanosleep(&ts, 0);
	}
}
