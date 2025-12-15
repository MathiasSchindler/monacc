#include "mc.h"

struct cat_outbuf {
	mc_u8 buf[4096];
	mc_usize len;
};

static void cat_out_flush(const char *argv0, struct cat_outbuf *out) {
	if (!out || out->len == 0) {
		return;
	}
	mc_i64 w = mc_write_all(1, out->buf, out->len);
	if (w < 0) {
		mc_die_errno(argv0, "write", w);
	}
	out->len = 0;
}

static void cat_out_write_byte(const char *argv0, struct cat_outbuf *out, mc_u8 b) {
	if (out->len == sizeof(out->buf)) {
		cat_out_flush(argv0, out);
	}
	out->buf[out->len++] = b;
}

static void cat_write_line_prefix(const char *argv0, mc_u64 line_no) {
	if (mc_write_u64_dec(1, line_no) < 0) mc_die_errno(argv0, "write", -1);
	if (mc_write_all(1, "\t", 1) < 0) mc_die_errno(argv0, "write", -1);
}

enum cat_number_mode {
	CAT_NUM_NONE = 0,
	CAT_NUM_ALL = 1,
	CAT_NUM_NONBLANK = 2,
};

static void cat_fd_raw(const char *argv0, mc_i32 fd) {
	mc_u8 buf[32768];
	for (;;) {
		mc_i64 r = mc_sys_read(fd, buf, (mc_usize)sizeof(buf));
		if (r < 0) {
			mc_die_errno(argv0, "read", r);
		}
		if (r == 0) {
			break;
		}
		mc_i64 w = mc_write_all(1, buf, (mc_usize)r);
		if (w < 0) {
			mc_die_errno(argv0, "write", w);
		}
	}
}

static void cat_fd_filtered(const char *argv0, mc_i32 fd, int squeeze_blank, enum cat_number_mode number_mode, mc_u64 *line_no, int *at_line_start, int *prev_blank_line, int *cur_line_blank) {
	mc_u8 buf[32768];
	struct cat_outbuf out = {.len = 0};

	for (;;) {
		mc_i64 r = mc_sys_read(fd, buf, (mc_usize)sizeof(buf));
		if (r < 0) {
			mc_die_errno(argv0, "read", r);
		}
		if (r == 0) {
			break;
		}

		mc_u32 n = (mc_u32)r;
		for (mc_u32 i = 0; i < n; i++) {
			mc_u8 b = buf[i];

			if (*at_line_start) {
				// Squeeze blank lines: if this line is blank and previous output line was blank, skip it.
				if (squeeze_blank && b == '\n' && *prev_blank_line) {
					continue;
				}

				if (number_mode == CAT_NUM_ALL) {
					cat_out_flush(argv0, &out);
					cat_write_line_prefix(argv0, *line_no);
					*at_line_start = 0;
				}
				// For CAT_NUM_NONBLANK, delay prefix until first non-newline byte.
			}

			if (*at_line_start && number_mode == CAT_NUM_NONBLANK && b != '\n') {
				cat_out_flush(argv0, &out);
				cat_write_line_prefix(argv0, *line_no);
				(*line_no)++;
				*at_line_start = 0;
				*cur_line_blank = 0;
			}

			if (b != '\n') {
				*cur_line_blank = 0;
			}

			cat_out_write_byte(argv0, &out, b);
			if (b == '\n') {
				*at_line_start = 1;
				*prev_blank_line = *cur_line_blank ? 1 : 0;
				*cur_line_blank = 1;
				if (number_mode == CAT_NUM_ALL) {
					(*line_no)++;
				}
			}
		}
	}

	cat_out_flush(argv0, &out);
}

static void cat_path(const char *argv0, const char *path, int squeeze_blank, enum cat_number_mode number_mode, mc_u64 *line_no, int *at_line_start, int *prev_blank_line, int *cur_line_blank) {
	if (mc_streq(path, "-")) {
		if (!squeeze_blank && number_mode == CAT_NUM_NONE) {
			cat_fd_raw(argv0, 0);
		} else {
			cat_fd_filtered(argv0, 0, squeeze_blank, number_mode, line_no, at_line_start, prev_blank_line, cur_line_blank);
		}
		return;
	}

	mc_i64 fd = mc_sys_openat(MC_AT_FDCWD, path, MC_O_RDONLY | MC_O_CLOEXEC, 0);
	if (fd < 0) {
		mc_die_errno(argv0, path, fd);
	}

	if (!squeeze_blank && number_mode == CAT_NUM_NONE) {
		cat_fd_raw(argv0, (mc_i32)fd);
	} else {
		cat_fd_filtered(argv0, (mc_i32)fd, squeeze_blank, number_mode, line_no, at_line_start, prev_blank_line, cur_line_blank);
	}
	(void)mc_sys_close((mc_i32)fd);
}

__attribute__((used)) int main(int argc, char **argv, char **envp) {
	(void)envp;

	const char *argv0 = (argc > 0 && argv && argv[0]) ? argv[0] : "cat";
	int squeeze_blank = 0;
	enum cat_number_mode number_mode = CAT_NUM_NONE;

	int i = 1;
	for (; i < argc; i++) {
		const char *a = argv[i];
		if (!a || a[0] != '-' || mc_streq(a, "-")) break;
		if (mc_streq(a, "--")) {
			i++;
			break;
		}
		if (mc_streq(a, "-n")) {
			number_mode = CAT_NUM_ALL;
			continue;
		}
		if (mc_streq(a, "-b")) {
			number_mode = CAT_NUM_NONBLANK;
			continue;
		}
		if (mc_streq(a, "-s")) {
			squeeze_blank = 1;
			continue;
		}
		mc_die_usage(argv0, "cat [-n] [-b] [-s] [--] [FILE...]");
	}

	mc_u64 line_no = 1;
	int at_line_start = 1;
	int prev_blank_line = 0;
	int cur_line_blank = 1;

	if (i >= argc) {
		if (!squeeze_blank && number_mode == CAT_NUM_NONE) {
			cat_fd_raw(argv0, 0);
		} else {
			cat_fd_filtered(argv0, 0, squeeze_blank, number_mode, &line_no, &at_line_start, &prev_blank_line, &cur_line_blank);
		}
		return 0;
	}

	for (; i < argc; i++) {
		const char *path = argv[i] ? argv[i] : "";
		cat_path(argv0, path, squeeze_blank, number_mode, &line_no, &at_line_start, &prev_blank_line, &cur_line_blank);
	}

	return 0;
}
