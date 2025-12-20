#include "mc.h"

// Minimal xxd-like hexdumper.
// Supported:
//   xxd [-l N] [-s OFF] [-g1] [FILE]
// Default grouping is 1 byte (like -g1).

static mc_u8 hex_digit(mc_u8 v) {
	v &= 0xF;
	return (v < 10) ? (mc_u8)('0' + v) : (mc_u8)('a' + (v - 10));
}

static void write_hex_u32_fixed8(mc_u32 v) {
	char out[8];
	for (int i = 7; i >= 0; i--) {
		out[i] = (char)hex_digit((mc_u8)v);
		v >>= 4;
	}
	(void)mc_write_all(1, out, 8);
}

static void write_hex_byte(mc_u8 b) {
	char out[2];
	out[0] = (char)hex_digit((mc_u8)(b >> 4));
	out[1] = (char)hex_digit((mc_u8)(b & 0xF));
	(void)mc_write_all(1, out, 2);
}

static int is_ascii_print(mc_u8 c) {
	return (c >= 0x20 && c <= 0x7e);
}

static void discard_bytes(const char *argv0, mc_i32 fd, mc_u64 n) {
	mc_u8 buf[4096];
	mc_u64 left = n;
	while (left) {
		mc_usize want = (left > (mc_u64)sizeof(buf)) ? (mc_usize)sizeof(buf) : (mc_usize)left;
		mc_i64 r = mc_sys_read(fd, buf, want);
		if (r < 0) mc_die_errno(argv0, "read", r);
		if (r == 0) break;
		left -= (mc_u64)r;
	}
}

static void xxd_fd(const char *argv0, mc_i32 fd, mc_u64 start_off, mc_u64 limit_len, int have_limit) {
	mc_u8 buf[16];
	mc_u64 off = start_off;
	mc_u64 left = limit_len;

	if (start_off) {
		mc_i64 r = mc_sys_lseek(fd, (mc_i64)start_off, 0 /* SEEK_SET */);
		if (r < 0) {
			// Likely non-seekable (stdin/pipe): fall back to discarding.
			discard_bytes(argv0, fd, start_off);
		}
	}

	while (1) {
		mc_usize want = sizeof(buf);
		if (have_limit && left < (mc_u64)want) want = (mc_usize)left;
		if (have_limit && want == 0) break;

		mc_i64 n = mc_sys_read(fd, buf, want);
		if (n < 0) mc_die_errno(argv0, "read", n);
		if (n == 0) break;

		write_hex_u32_fixed8((mc_u32)off);
		(void)mc_write_str(1, ": ");

		for (int i = 0; i < 16; i++) {
			if (i < n) {
				write_hex_byte(buf[i]);
			} else {
				(void)mc_write_str(1, "  ");
			}
			if (i == 7) (void)mc_write_str(1, "  ");
			else (void)mc_write_str(1, " ");
		}

		(void)mc_write_str(1, " ");
		for (int i = 0; i < n; i++) {
			mc_u8 c = buf[i];
			if (!is_ascii_print(c)) c = (mc_u8)'.';
			(void)mc_write_all(1, &c, 1);
		}
		(void)mc_write_str(1, "\n");

		off += (mc_u64)n;
		if (have_limit) left -= (mc_u64)n;
	}
}

__attribute__((used)) int main(int argc, char **argv, char **envp) {
	(void)envp;
	const char *argv0 = (argc > 0 && argv && argv[0]) ? argv[0] : "xxd";

	mc_u64 start_off = 0;
	mc_u64 limit_len = 0;
	int have_limit = 0;

	int i = 1;
	for (; i < argc; i++) {
		const char *a = argv[i];
		if (!a) break;
		if (mc_streq(a, "--")) { i++; break; }
		if (a[0] != '-') break;
		if (mc_streq(a, "-g1")) {
			// Default behavior.
			continue;
		}
		if (mc_streq(a, "-l")) {
			if (i + 1 >= argc) mc_die_usage(argv0, "xxd [-l N] [-s OFF] [-g1] [FILE]");
			mc_u64 v = 0;
			if (mc_parse_u64_dec(argv[i + 1], &v) != 0) mc_die_usage(argv0, "xxd [-l N] [-s OFF] [-g1] [FILE]");
			limit_len = v;
			have_limit = 1;
			i++;
			continue;
		}
		if (mc_streq(a, "-s")) {
			if (i + 1 >= argc) mc_die_usage(argv0, "xxd [-l N] [-s OFF] [-g1] [FILE]");
			mc_u64 v = 0;
			if (mc_parse_u64_dec(argv[i + 1], &v) != 0) mc_die_usage(argv0, "xxd [-l N] [-s OFF] [-g1] [FILE]");
			start_off = v;
			i++;
			continue;
		}
		mc_die_usage(argv0, "xxd [-l N] [-s OFF] [-g1] [FILE]");
	}

	if (i >= argc) {
		xxd_fd(argv0, 0, start_off, limit_len, have_limit);
		return 0;
	}

	const char *path = argv[i];
	mc_i64 fd = mc_sys_openat(MC_AT_FDCWD, path, MC_O_RDONLY | MC_O_CLOEXEC, 0);
	if (fd < 0) mc_die_errno(argv0, path, fd);
	xxd_fd(argv0, (mc_i32)fd, start_off, limit_len, have_limit);
	(void)mc_sys_close((mc_i32)fd);
	return 0;
}
