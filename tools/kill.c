#include "mc.h"

static int kill_is_digit(char c) {
	return (c >= '0' && c <= '9');
}

static int kill_parse_signal_opt(const char *a, mc_i32 *out_sig) {
	// Accept -N where N is a positive decimal integer.
	if (!a || a[0] != '-' || a[1] == '\0') {
		return 0;
	}
	for (mc_u32 i = 1; a[i] != '\0'; i++) {
		if (!kill_is_digit(a[i])) {
			return 0;
		}
	}
	mc_u32 sig_u = 0;
	if (mc_parse_u32_dec(a + 1, &sig_u) != 0) {
		return 0;
	}
	if (sig_u == 0 || sig_u > 128) {
		return 0;
	}
	*out_sig = (mc_i32)sig_u;
	return 1;
}

__attribute__((used)) int main(int argc, char **argv, char **envp) {
	(void)envp;
	const char *argv0 = (argc > 0 && argv && argv[0]) ? argv[0] : "kill";

	int opt_list = 0;
	mc_i32 sig = 15; // SIGTERM

	int i = 1;
	for (; i < argc; i++) {
		const char *a = argv[i];
		if (!a) break;
		if (mc_streq(a, "--")) {
			i++;
			break;
		}
		if (a[0] != '-') {
			break;
		}
		if (mc_streq(a, "-l")) {
			opt_list = 1;
			continue;
		}
		if (kill_parse_signal_opt(a, &sig)) {
			continue;
		}
		mc_die_usage(argv0, "kill [-l] [-N] PID...");
	}

	if (opt_list) {
		if (i != argc) {
			mc_die_usage(argv0, "kill [-l] [-N] PID...");
		}
		// Minimal: list signal numbers (one per line).
		for (mc_u64 s = 1; s <= 64; s++) {
			mc_i64 w = mc_write_u64_dec(1, s);
			if (w < 0) mc_die_errno(argv0, "write", w);
			w = mc_write_all(1, "\n", 1);
			if (w < 0) mc_die_errno(argv0, "write", w);
		}
		return 0;
	}

	if (i >= argc) {
		mc_die_usage(argv0, "kill [-l] [-N] PID...");
	}

	int any_fail = 0;
	for (; i < argc; i++) {
		const char *pid_s = argv[i];
		if (!pid_s) break;
		mc_i64 pid64 = 0;
		if (mc_parse_i64_dec(pid_s, &pid64) != 0 || pid64 <= 0 || pid64 > 2147483647) {
			mc_die_usage(argv0, "kill [-l] [-N] PID...");
		}
		mc_i64 r = mc_sys_kill((mc_i32)pid64, sig);
		if (r < 0) {
			mc_print_errno(argv0, pid_s, r);
			any_fail = 1;
		}
	}

	return any_fail ? 1 : 0;
}
