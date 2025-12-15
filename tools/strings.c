#include "mc.h"

static int is_printable(mc_u8 c) {
	// ASCII printable + tab.
	if (c == (mc_u8)'\t') return 1;
	return (c >= 0x20 && c <= 0x7e);
}

static void strings_scan_fd(const char *argv0, mc_i32 fd, mc_u32 minlen) {
	(void)argv0;
	mc_u8 buf[32768];

	// Hold the first minlen bytes of a candidate run.
	mc_u8 prefix[256];
	if (minlen > (mc_u32)sizeof(prefix)) {
		minlen = (mc_u32)sizeof(prefix);
	}

	mc_u32 run = 0;
	int emitting = 0;

	while (1) {
		mc_i64 n = mc_sys_read(fd, buf, sizeof(buf));
		if (n < 0) mc_die_errno(argv0, "read", n);
		if (n == 0) break;

		for (mc_i64 i = 0; i < n; i++) {
			mc_u8 c = buf[i];
			if (is_printable(c)) {
				if (!emitting) {
					if (run < minlen) {
						prefix[run] = c;
					}
					run++;
					if (run == minlen) {
						(void)mc_write_all(1, prefix, minlen);
						emitting = 1;
					}
				} else {
					(void)mc_write_all(1, &c, 1);
					run++;
				}
				continue;
			}

			// run ended
			if (emitting) {
				(void)mc_write_all(1, "\n", 1);
			}
			run = 0;
			emitting = 0;
		}
	}

	if (emitting) {
		(void)mc_write_all(1, "\n", 1);
	}
}

__attribute__((used)) int main(int argc, char **argv, char **envp) {
	(void)envp;
	const char *argv0 = (argc > 0 && argv && argv[0]) ? argv[0] : "strings";

	mc_u32 minlen = 4;

	int i = 1;
	for (; i < argc; i++) {
		const char *a = argv[i];
		if (!a) break;
		if (mc_streq(a, "--")) {
			i++;
			break;
		}
		if (mc_streq(a, "-n")) {
			if (i + 1 >= argc || !argv[i + 1]) mc_die_usage(argv0, "strings [-n N] [FILE...]");
			mc_u32 v = 0;
			if (mc_parse_u32_dec(argv[++i], &v) != 0 || v == 0) mc_die_usage(argv0, "strings [-n N] [FILE...]");
			minlen = v;
			continue;
		}
		if (a[0] == '-') mc_die_usage(argv0, "strings [-n N] [FILE...]");
		break;
	}

	if (i >= argc) {
		strings_scan_fd(argv0, 0, minlen);
		return 0;
	}

	int rc = 0;
	for (; i < argc; i++) {
		const char *path = argv[i];
		if (!path) continue;
		mc_i64 fd = mc_sys_openat(MC_AT_FDCWD, path, MC_O_RDONLY | MC_O_CLOEXEC, 0);
		if (fd < 0) {
			mc_die_errno(argv0, path, fd);
		}
		strings_scan_fd(argv0, (mc_i32)fd, minlen);
		(void)mc_sys_close((mc_i32)fd);
	}
	return rc;
}
