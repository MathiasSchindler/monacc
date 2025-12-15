#include "mc.h"

static mc_u8 hex_digit(mc_u8 v) {
	v &= 0xF;
	return (v < 10) ? (mc_u8)('0' + v) : (mc_u8)('a' + (v - 10));
}

static void write_hex_u64_fixed16(mc_u64 v) {
	char out[16];
	for (int i = 15; i >= 0; i--) {
		out[i] = (char)hex_digit((mc_u8)v);
		v >>= 4;
	}
	(void)mc_write_all(1, out, 16);
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

static void hexdump_fd(const char *argv0, mc_i32 fd) {
	(void)argv0;
	mc_u8 buf[16];
	mc_u64 off = 0;
	while (1) {
		mc_i64 n = mc_sys_read(fd, buf, sizeof(buf));
		if (n < 0) mc_die_errno(argv0, "read", n);
		if (n == 0) break;

		write_hex_u64_fixed16(off);
		(void)mc_write_str(1, "  ");

		for (int i = 0; i < 16; i++) {
			if (i < n) {
				write_hex_byte(buf[i]);
			} else {
				(void)mc_write_str(1, "  ");
			}
			if (i == 7) {
				(void)mc_write_str(1, "  ");
			} else {
				(void)mc_write_str(1, " ");
			}
		}

		(void)mc_write_str(1, "|");
		for (int i = 0; i < n; i++) {
			mc_u8 c = buf[i];
			if (!is_ascii_print(c)) c = (mc_u8)'.';
			(void)mc_write_all(1, &c, 1);
		}
		for (int i = (int)n; i < 16; i++) {
			(void)mc_write_all(1, " ", 1);
		}
		(void)mc_write_str(1, "|\n");

		off += (mc_u64)n;
	}
}

__attribute__((used)) int main(int argc, char **argv, char **envp) {
	(void)envp;
	const char *argv0 = (argc > 0 && argv && argv[0]) ? argv[0] : "hexdump";

	int i = 1;
	for (; i < argc; i++) {
		const char *a = argv[i];
		if (!a) break;
		if (mc_streq(a, "--")) {
			i++;
			break;
		}
		if (a[0] == '-') mc_die_usage(argv0, "hexdump [FILE...]");
		break;
	}

	if (i >= argc) {
		hexdump_fd(argv0, 0);
		return 0;
	}

	for (; i < argc; i++) {
		const char *path = argv[i];
		if (!path) continue;
		mc_i64 fd = mc_sys_openat(MC_AT_FDCWD, path, MC_O_RDONLY | MC_O_CLOEXEC, 0);
		if (fd < 0) mc_die_errno(argv0, path, fd);
		hexdump_fd(argv0, (mc_i32)fd);
		(void)mc_sys_close((mc_i32)fd);
	}
	return 0;
}
