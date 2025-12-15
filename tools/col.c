#include "mc.h"

#define COL_MAX_COLS 4096

static int is_printable_or_tab(mc_u8 c) {
	if (c == (mc_u8)'\t') return 1;
	return (c >= 0x20 && c <= 0x7e);
}

static void col_flush_line(mc_u8 *line, mc_u32 len) {
	for (mc_u32 i = 0; i < len; i++) {
		mc_u8 c = line[i];
		if (c == 0) c = (mc_u8)' ';
		(void)mc_write_all(1, &c, 1);
	}
	(void)mc_write_all(1, "\n", 1);
}

static void col_fd(const char *argv0, mc_i32 fd) {
	(void)argv0;
	mc_u8 in[4096];
	mc_u8 line[COL_MAX_COLS];
	mc_u32 cursor = 0;
	mc_u32 linelen = 0;

	// initialize line buffer to zeros; output replaces 0 with spaces.
	for (mc_u32 i = 0; i < COL_MAX_COLS; i++) line[i] = 0;

	while (1) {
		mc_i64 n = mc_sys_read(fd, in, sizeof(in));
		if (n < 0) mc_die_errno(argv0, "read", n);
		if (n == 0) break;
		for (mc_i64 i = 0; i < n; i++) {
			mc_u8 c = in[i];
			if (c == (mc_u8)'\n') {
				col_flush_line(line, linelen);
				cursor = 0;
				linelen = 0;
				for (mc_u32 k = 0; k < COL_MAX_COLS; k++) line[k] = 0;
				continue;
			}
			if (c == (mc_u8)'\f') {
				// treat form feed as newline
				col_flush_line(line, linelen);
				cursor = 0;
				linelen = 0;
				for (mc_u32 k = 0; k < COL_MAX_COLS; k++) line[k] = 0;
				continue;
			}
			if (c == (mc_u8)'\r') {
				cursor = 0;
				continue;
			}
			if (c == (mc_u8)'\b') {
				if (cursor > 0) cursor--;
				continue;
			}
			if (!is_printable_or_tab(c)) {
				continue;
			}

			if (cursor >= COL_MAX_COLS) {
				mc_die_errno(argv0, "line too wide", (mc_i64)-MC_EINVAL);
			}
			line[cursor] = c;
			cursor++;
			if (cursor > linelen) linelen = cursor;
		}
	}

	// flush last line (if any content)
	if (linelen) {
		col_flush_line(line, linelen);
	}
}

__attribute__((used)) int main(int argc, char **argv, char **envp) {
	(void)envp;
	const char *argv0 = (argc > 0 && argv && argv[0]) ? argv[0] : "col";

	int i = 1;
	for (; i < argc; i++) {
		const char *a = argv[i];
		if (!a) break;
		if (mc_streq(a, "--")) {
			i++;
			break;
		}
		if (a[0] == '-') mc_die_usage(argv0, "col [FILE...]");
		break;
	}

	if (i >= argc) {
		col_fd(argv0, 0);
		return 0;
	}

	for (; i < argc; i++) {
		const char *path = argv[i];
		if (!path) continue;
		mc_i64 fd = mc_sys_openat(MC_AT_FDCWD, path, MC_O_RDONLY | MC_O_CLOEXEC, 0);
		if (fd < 0) mc_die_errno(argv0, path, fd);
		col_fd(argv0, (mc_i32)fd);
		(void)mc_sys_close((mc_i32)fd);
	}
	return 0;
}
