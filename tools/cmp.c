#include "mc.h"

static int cmp_is_stdin(const char *p) {
	return p && mc_streq(p, "-");
}

static mc_i32 cmp_open_ro(const char *argv0, const char *path) {
	if (cmp_is_stdin(path)) {
		return 0;
	}
	mc_i64 fd = mc_sys_openat(MC_AT_FDCWD, path, MC_O_RDONLY | MC_O_CLOEXEC, 0);
	if (fd < 0) {
		mc_die_errno(argv0, path, fd);
	}
	return (mc_i32)fd;
}

static void cmp_close_if_needed(mc_i32 fd) {
	if (fd != 0) {
		(void)mc_sys_close(fd);
	}
}

static void cmp_write_differ(const char *argv0, const char *a, const char *b, mc_u64 byte_no) {
	(void)mc_write_str(2, argv0);
	(void)mc_write_str(2, ": ");
	(void)mc_write_str(2, a);
	(void)mc_write_str(2, " ");
	(void)mc_write_str(2, b);
	(void)mc_write_str(2, " differ: byte ");
	(void)mc_write_u64_dec(2, byte_no);
	(void)mc_write_str(2, "\n");
}

__attribute__((used)) int main(int argc, char **argv, char **envp) {
	(void)envp;
	const char *argv0 = (argc > 0 && argv && argv[0]) ? argv[0] : "cmp";

	int silent = 0;
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
		if (mc_streq(a, "-s")) {
			silent = 1;
			continue;
		}
		mc_die_usage(argv0, "cmp [-s] [--] FILE1 FILE2");
	}

	if (argc - i != 2) {
		mc_die_usage(argv0, "cmp [-s] [--] FILE1 FILE2");
	}

	const char *p1 = argv[i];
	const char *p2 = argv[i + 1];
	if (!p1) p1 = "";
	if (!p2) p2 = "";

	mc_i32 fd1 = cmp_open_ro(argv0, p1);
	mc_i32 fd2 = cmp_open_ro(argv0, p2);

	mc_u8 b1[32768];
	mc_u8 b2[32768];
	mc_u64 off = 0;

	for (;;) {
		mc_i64 r1 = mc_sys_read(fd1, b1, (mc_usize)sizeof(b1));
		if (r1 < 0) {
			cmp_close_if_needed(fd1);
			cmp_close_if_needed(fd2);
			mc_die_errno(argv0, "read", r1);
		}
		mc_i64 r2 = mc_sys_read(fd2, b2, (mc_usize)sizeof(b2));
		if (r2 < 0) {
			cmp_close_if_needed(fd1);
			cmp_close_if_needed(fd2);
			mc_die_errno(argv0, "read", r2);
		}

		if (r1 == 0 && r2 == 0) {
			break;
		}

		mc_u32 n1 = (mc_u32)((r1 < 0) ? 0 : r1);
		mc_u32 n2 = (mc_u32)((r2 < 0) ? 0 : r2);
		mc_u32 n = (n1 < n2) ? n1 : n2;

		for (mc_u32 k = 0; k < n; k++) {
			if (b1[k] != b2[k]) {
				cmp_close_if_needed(fd1);
				cmp_close_if_needed(fd2);
				if (!silent) {
					cmp_write_differ(argv0, p1, p2, off + (mc_u64)k + 1);
				}
				return 1;
			}
		}

		if (n1 != n2) {
			cmp_close_if_needed(fd1);
			cmp_close_if_needed(fd2);
			if (!silent) {
				cmp_write_differ(argv0, p1, p2, off + (mc_u64)n + 1);
			}
			return 1;
		}

		off += (mc_u64)n;
	}

	cmp_close_if_needed(fd1);
	cmp_close_if_needed(fd2);
	return 0;
}
