#include "mc.h"

#define OD_COLS 16u

static mc_usize od_u64_octal(char *buf, mc_usize cap, mc_u64 v) {
	char tmp[32];
	mc_usize n = 0;
	if (v == 0) {
		if (cap) buf[0] = '0';
		return cap ? 1u : 0u;
	}
	while (v && n < sizeof(tmp)) {
		mc_u64 q = v / 8u;
		mc_u64 r = v - q * 8u;
		tmp[n++] = (char)('0' + (char)r);
		v = q;
	}
	mc_usize out = (n < cap) ? n : cap;
	for (mc_usize i = 0; i < out; i++) buf[i] = tmp[n - 1 - i];
	return n;
}

static void od_write_octal_padded(const char *argv0, mc_u64 v, mc_u32 width) {
	char buf[32];
	mc_usize n = od_u64_octal(buf, sizeof(buf), v);
	if ((mc_u32)n < width) {
		char z = '0';
		for (mc_u32 i = 0; i < width - (mc_u32)n; i++) {
			mc_i64 w = mc_write_all(1, &z, 1);
			if (w < 0) mc_die_errno(argv0, "write", w);
		}
	}
	mc_i64 w = mc_write_all(1, buf, n);
	if (w < 0) mc_die_errno(argv0, "write", w);
}

static void od_write_byte_octal(const char *argv0, mc_u8 b) {
	char out[3];
	out[2] = (char)('0' + (b & 7u));
	out[1] = (char)('0' + ((b >> 3) & 7u));
	out[0] = (char)('0' + ((b >> 6) & 3u));
	mc_i64 w = mc_write_all(1, out, 3);
	if (w < 0) mc_die_errno(argv0, "write", w);
}

static mc_i32 od_open_or_stdin(const char *argv0, const char *path) {
	if (mc_streq(path, "-")) return 0;
	mc_i64 fd = mc_sys_openat(MC_AT_FDCWD, path, MC_O_RDONLY | MC_O_CLOEXEC, 0);
	if (fd < 0) mc_die_errno(argv0, path, fd);
	return (mc_i32)fd;
}

__attribute__((used)) int main(int argc, char **argv, char **envp) {
	(void)envp;
	const char *argv0 = (argc > 0 && argv && argv[0]) ? argv[0] : "od";

	int opt_no_addr = 0;

	int i = 1;
	for (; i < argc; i++) {
		const char *a = argv[i];
		if (!a) break;
		if (mc_streq(a, "--")) {
			i++;
			break;
		}
		if (a[0] != '-' || mc_streq(a, "-")) break;
		if (mc_streq(a, "-An") || (mc_streq(a, "-A") && (i + 1 < argc) && mc_streq(argv[i + 1], "n"))) {
			opt_no_addr = 1;
			if (mc_streq(a, "-A")) i++;
			continue;
		}
		mc_die_usage(argv0, "od [-An] [FILE...]");
	}

	int nfiles = argc - i;
	const char *paths[32];
	if (nfiles <= 0) {
		paths[0] = "-";
		nfiles = 1;
	} else {
		if (nfiles > 32) mc_die_usage(argv0, "od [-An] [FILE...]");
		for (int k = 0; k < nfiles; k++) paths[k] = argv[i + k];
	}

	mc_u8 row[OD_COLS];
	mc_u32 row_n = 0;
	mc_u64 off = 0;

	for (int f = 0; f < nfiles; f++) {
		mc_i32 fd = od_open_or_stdin(argv0, paths[f]);
		mc_u8 buf[4096];
		for (;;) {
			mc_i64 r = mc_sys_read(fd, buf, (mc_usize)sizeof(buf));
			if (r < 0) mc_die_errno(argv0, "read", r);
			if (r == 0) break;
			for (mc_i64 j = 0; j < r; j++) {
				row[row_n++] = buf[j];
				off++;
				if (row_n == OD_COLS) {
					if (!opt_no_addr) {
						od_write_octal_padded(argv0, off - OD_COLS, 7);
					}
					for (mc_u32 k = 0; k < row_n; k++) {
						char sp = ' ';
						mc_i64 w = mc_write_all(1, &sp, 1);
						if (w < 0) mc_die_errno(argv0, "write", w);
						od_write_byte_octal(argv0, row[k]);
					}
					char nl = '\n';
					mc_i64 w = mc_write_all(1, &nl, 1);
					if (w < 0) mc_die_errno(argv0, "write", w);
					row_n = 0;
				}
			}
		}
		if (fd != 0) (void)mc_sys_close(fd);
	}

	if (row_n) {
		if (!opt_no_addr) {
			od_write_octal_padded(argv0, off - (mc_u64)row_n, 7);
		}
		for (mc_u32 k = 0; k < row_n; k++) {
			char sp = ' ';
			mc_i64 w = mc_write_all(1, &sp, 1);
			if (w < 0) mc_die_errno(argv0, "write", w);
			od_write_byte_octal(argv0, row[k]);
		}
		char nl = '\n';
		mc_i64 w = mc_write_all(1, &nl, 1);
		if (w < 0) mc_die_errno(argv0, "write", w);
	}

	if (!opt_no_addr) {
		od_write_octal_padded(argv0, off, 7);
		char nl = '\n';
		mc_i64 w = mc_write_all(1, &nl, 1);
		if (w < 0) mc_die_errno(argv0, "write", w);
	}
	return 0;
}
