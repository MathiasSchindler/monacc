#include "mc.h"

#define UNIQ_READ_BUF_SIZE 32768u
#define UNIQ_LINE_MAX 65536u

struct uniq_reader {
	mc_i32 fd;
	mc_u8 buf[UNIQ_READ_BUF_SIZE];
	mc_u32 pos;
	mc_u32 len;
	int eof;
};

static MC_NORETURN void uniq_die_msg(const char *argv0, const char *msg) {
	(void)mc_write_str(2, argv0);
	(void)mc_write_str(2, ": ");
	(void)mc_write_str(2, msg);
	(void)mc_write_str(2, "\n");
	mc_exit(1);
}

static int uniq_fill(struct uniq_reader *r, const char *argv0) {
	if (r->eof) {
		return 0;
	}
	mc_i64 n = mc_sys_read(r->fd, r->buf, (mc_usize)sizeof(r->buf));
	if (n < 0) {
		mc_die_errno(argv0, "read", n);
	}
	if (n == 0) {
		r->eof = 1;
		r->pos = 0;
		r->len = 0;
		return 0;
	}
	r->pos = 0;
	r->len = (mc_u32)n;
	return 1;
}

// Reads one line (without the trailing '\n') into out[].
// Returns 1 if a line was read, 0 on EOF with no data.
static int uniq_read_line(struct uniq_reader *r, const char *argv0, mc_u8 *out, mc_u32 *out_len) {
	mc_u32 n = 0;
	int have_any = 0;

	for (;;) {
		if (r->pos >= r->len) {
			if (!uniq_fill(r, argv0)) {
				break;
			}
		}

		while (r->pos < r->len) {
			mc_u8 c = r->buf[r->pos++];
			have_any = 1;
			if (c == (mc_u8)'\n') {
				*out_len = n;
				return 1;
			}
			if (n >= UNIQ_LINE_MAX) {
				uniq_die_msg(argv0, "line too long");
			}
			out[n++] = c;
		}
	}

	if (!have_any) {
		return 0;
	}
	*out_len = n;
	return 1;
}

static int uniq_lines_equal(const mc_u8 *a, mc_u32 alen, const mc_u8 *b, mc_u32 blen) {
	if (alen != blen) {
		return 0;
	}
	for (mc_u32 i = 0; i < alen; i++) {
		if (a[i] != b[i]) {
			return 0;
		}
	}
	return 1;
}

static void uniq_write_group(const char *argv0, const mc_u8 *line, mc_u32 len, mc_u64 count, int opt_c, int opt_d, int opt_u) {
	int print_it = 1;
	if (opt_d) {
		print_it = (count > 1);
	}
	if (opt_u) {
		print_it = (count == 1);
	}
	if (!print_it) {
		return;
	}

	if (opt_c) {
		mc_i64 w = mc_write_u64_dec(1, count);
		if (w < 0) mc_die_errno(argv0, "write", w);
		w = mc_write_all(1, " ", 1);
		if (w < 0) mc_die_errno(argv0, "write", w);
	}

	mc_i64 w = mc_write_all(1, line, (mc_usize)len);
	if (w < 0) mc_die_errno(argv0, "write", w);
	w = mc_write_all(1, "\n", 1);
	if (w < 0) mc_die_errno(argv0, "write", w);
}

static void uniq_fd(const char *argv0, mc_i32 fd, int opt_c, int opt_d, int opt_u, mc_u8 *prev, mc_u32 *prev_len, mc_u64 *group_count, int *have_prev) {
	struct uniq_reader r;
	r.fd = fd;
	r.pos = 0;
	r.len = 0;
	r.eof = 0;

	mc_u8 cur[UNIQ_LINE_MAX];
	mc_u32 cur_len = 0;

	for (;;) {
		int ok = uniq_read_line(&r, argv0, cur, &cur_len);
		if (!ok) {
			break;
		}

		if (!*have_prev) {
			for (mc_u32 i = 0; i < cur_len; i++) prev[i] = cur[i];
			*prev_len = cur_len;
			*group_count = 1;
			*have_prev = 1;
			continue;
		}

		if (uniq_lines_equal(prev, *prev_len, cur, cur_len)) {
			(*group_count)++;
			continue;
		}

		uniq_write_group(argv0, prev, *prev_len, *group_count, opt_c, opt_d, opt_u);

		for (mc_u32 i = 0; i < cur_len; i++) prev[i] = cur[i];
		*prev_len = cur_len;
		*group_count = 1;
	}
}

__attribute__((used)) int main(int argc, char **argv, char **envp) {
	(void)envp;
	const char *argv0 = (argc > 0 && argv && argv[0]) ? argv[0] : "uniq";

	int opt_c = 0;
	int opt_d = 0;
	int opt_u = 0;

	int i = 1;
	for (; i < argc; i++) {
		const char *a = argv[i];
		if (!a) break;
		if (mc_streq(a, "--")) {
			i++;
			break;
		}
		if (a[0] != '-' || mc_streq(a, "-")) {
			break;
		}
		if (mc_streq(a, "-c")) {
			opt_c = 1;
			continue;
		}
		if (mc_streq(a, "-d")) {
			opt_d = 1;
			continue;
		}
		if (mc_streq(a, "-u")) {
			opt_u = 1;
			continue;
		}
		mc_die_usage(argv0, "uniq [-c] [-d|-u] [FILE...]");
	}

	if (opt_d && opt_u) {
		mc_die_usage(argv0, "uniq [-c] [-d|-u] [FILE...]");
	}

	// Keep group state across multiple FILE operands to behave like a concatenated stream.
	static mc_u8 prev[UNIQ_LINE_MAX];
	mc_u32 prev_len = 0;
	mc_u64 group_count = 0;
	int have_prev = 0;

	if (i >= argc) {
		uniq_fd(argv0, 0, opt_c, opt_d, opt_u, prev, &prev_len, &group_count, &have_prev);
	} else {
		for (; i < argc; i++) {
			const char *path = argv[i];
			if (!path) break;
			if (mc_streq(path, "-")) {
				uniq_fd(argv0, 0, opt_c, opt_d, opt_u, prev, &prev_len, &group_count, &have_prev);
				continue;
			}
			mc_i64 fd = mc_sys_openat(MC_AT_FDCWD, path, MC_O_RDONLY | MC_O_CLOEXEC, 0);
			if (fd < 0) {
				mc_die_errno(argv0, path, fd);
			}
			uniq_fd(argv0, (mc_i32)fd, opt_c, opt_d, opt_u, prev, &prev_len, &group_count, &have_prev);
			(void)mc_sys_close((mc_i32)fd);
		}
	}

	if (have_prev) {
		uniq_write_group(argv0, prev, prev_len, group_count, opt_c, opt_d, opt_u);
	}
	return 0;
}
