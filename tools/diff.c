#include "mc.h"

#define DIFF_UNIFIED_CTX 3u

struct diff_ctx_ring {
	mc_u8 lines[DIFF_UNIFIED_CTX][4096];
	mc_usize lens[DIFF_UNIFIED_CTX];
	mc_u32 count; // number of valid lines (<= DIFF_UNIFIED_CTX)
	mc_u32 head;  // next write index
};

struct diff_reader {
	mc_i32 fd;
	mc_u32 pos;
	mc_u32 len;
	int eof;
	mc_u8 buf[4096];
};

static int diff_is_stdin(const char *p) {
	return p && mc_streq(p, "-");
}

static mc_i32 diff_open_ro(const char *argv0, const char *path) {
	if (diff_is_stdin(path)) {
		return 0;
	}
	mc_i64 fd = mc_sys_openat(MC_AT_FDCWD, path, MC_O_RDONLY | MC_O_CLOEXEC, 0);
	if (fd < 0) {
		mc_die_errno(argv0, path, fd);
	}
	return (mc_i32)fd;
}

static void diff_close_if_needed(mc_i32 fd) {
	if (fd != 0) {
		(void)mc_sys_close(fd);
	}
}

static int diff_reader_fill(const char *argv0, struct diff_reader *r) {
	if (r->eof) {
		return 0;
	}
	mc_i64 n = mc_sys_read(r->fd, r->buf, sizeof(r->buf));
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

static int diff_reader_getc(const char *argv0, struct diff_reader *r, mc_u8 *out, int *out_eof) {
	if (r->pos >= r->len) {
		if (!diff_reader_fill(argv0, r)) {
			*out_eof = 1;
			return 0;
		}
	}
	*out = r->buf[r->pos++];
	*out_eof = 0;
	return 1;
}

static int diff_read_line(const char *argv0, struct diff_reader *r, mc_u8 *dst, mc_usize cap, mc_usize *out_len, int *out_eof) {
	if (!dst || cap == 0 || !out_len || !out_eof) {
		return -1;
	}
	*out_len = 0;
	*out_eof = 0;

	for (;;) {
		mc_u8 c = 0;
		int eof = 0;
		if (!diff_reader_getc(argv0, r, &c, &eof)) {
			*out_eof = 1;
			return 0;
		}
		if (*out_len + 1 > cap) {
			// Line too long.
			return -1;
		}
		dst[*out_len] = c;
		(*out_len)++;
		if (c == '\n') {
			return 0;
		}
	}
}

static void diff_write_line_prefixed(const char *argv0, const char *prefix, const mc_u8 *line, mc_usize len) {
	mc_i64 w = mc_write_all(1, prefix, mc_strlen(prefix));
	if (w < 0) mc_die_errno(argv0, "write", w);
	w = mc_write_all(1, line, len);
	if (w < 0) mc_die_errno(argv0, "write", w);
	if (len == 0 || line[len - 1] != '\n') {
		w = mc_write_all(1, "\n", 1);
		if (w < 0) mc_die_errno(argv0, "write", w);
	}
}

static void diff_ctx_push(struct diff_ctx_ring *rb, const mc_u8 *line, mc_usize len) {
	mc_u32 idx = rb->head % DIFF_UNIFIED_CTX;
	if (len > sizeof(rb->lines[idx])) {
		len = sizeof(rb->lines[idx]);
	}
	for (mc_usize i = 0; i < len; i++) {
		rb->lines[idx][i] = line[i];
	}
	rb->lens[idx] = len;
	rb->head = (rb->head + 1u) % DIFF_UNIFIED_CTX;
	if (rb->count < DIFF_UNIFIED_CTX) {
		rb->count++;
	}
}

static void diff_write_unified_header(const char *argv0, const char *p1, const char *p2) {
	(void)argv0;
	(void)mc_write_str(1, "--- ");
	(void)mc_write_str(1, p1);
	(void)mc_write_str(1, "\n");
	(void)mc_write_str(1, "+++ ");
	(void)mc_write_str(1, p2);
	(void)mc_write_str(1, "\n");
}

static void diff_write_unified_hunk_header(mc_u64 start1, mc_u64 count1, mc_u64 start2, mc_u64 count2) {
	(void)mc_write_str(1, "@@ -");
	(void)mc_write_u64_dec(1, start1);
	(void)mc_write_str(1, ",");
	(void)mc_write_u64_dec(1, count1);
	(void)mc_write_str(1, " +");
	(void)mc_write_u64_dec(1, start2);
	(void)mc_write_str(1, ",");
	(void)mc_write_u64_dec(1, count2);
	(void)mc_write_str(1, " @@\n");
}

__attribute__((used)) int main(int argc, char **argv, char **envp) {
	(void)envp;
	const char *argv0 = (argc > 0 && argv && argv[0]) ? argv[0] : "diff";

	int unified = 0;

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
		if (mc_streq(a, "-u")) {
			unified = 1;
			continue;
		}
		mc_die_usage(argv0, "diff [-u] [--] FILE1 FILE2");
	}
	if (argc - i != 2) {
		mc_die_usage(argv0, "diff [-u] [--] FILE1 FILE2");
	}

	const char *p1 = argv[i];
	const char *p2 = argv[i + 1];
	if (!p1) p1 = "";
	if (!p2) p2 = "";

	mc_i32 fd1 = diff_open_ro(argv0, p1);
	mc_i32 fd2 = diff_open_ro(argv0, p2);

	struct diff_reader r1 = {.fd = fd1, .pos = 0, .len = 0, .eof = 0};
	struct diff_reader r2 = {.fd = fd2, .pos = 0, .len = 0, .eof = 0};

	mc_u8 l1[4096];
	mc_u8 l2[4096];
	mc_u64 line_no = 1;

	struct diff_ctx_ring rb = {0};

	for (;;) {
		mc_usize n1 = 0;
		mc_usize n2 = 0;
		int eof1 = 0;
		int eof2 = 0;

		if (diff_read_line(argv0, &r1, l1, sizeof(l1), &n1, &eof1) != 0) {
			diff_close_if_needed(fd1);
			diff_close_if_needed(fd2);
			mc_die_errno(argv0, "line too long", (mc_i64)-MC_EINVAL);
		}
		if (diff_read_line(argv0, &r2, l2, sizeof(l2), &n2, &eof2) != 0) {
			diff_close_if_needed(fd1);
			diff_close_if_needed(fd2);
			mc_die_errno(argv0, "line too long", (mc_i64)-MC_EINVAL);
		}

		if (eof1 && eof2) {
			break;
		}

		int same = 0;
		if (eof1 == eof2 && n1 == n2) {
			same = 1;
			for (mc_usize k = 0; k < n1; k++) {
				if (l1[k] != l2[k]) {
					same = 0;
					break;
				}
			}
		}

		if (!same) {
			if (!unified) {
				(void)mc_write_str(1, "diff: line ");
				(void)mc_write_u64_dec(1, line_no);
				(void)mc_write_str(1, "\n");
				if (!eof1) diff_write_line_prefixed(argv0, "< ", l1, n1);
				else diff_write_line_prefixed(argv0, "< ", (const mc_u8 *)"", 0);
				if (!eof2) diff_write_line_prefixed(argv0, "> ", l2, n2);
				else diff_write_line_prefixed(argv0, "> ", (const mc_u8 *)"", 0);
			} else {
				mc_u64 pre = (mc_u64)rb.count;
				mc_u64 start = (line_no > pre) ? (line_no - pre) : 1;

				mc_u64 rm = eof1 ? 0 : 1;
				mc_u64 add = eof2 ? 0 : 1;
				mc_u64 count1 = pre + rm;
				mc_u64 count2 = pre + add;

				diff_write_unified_header(argv0, p1, p2);
				diff_write_unified_hunk_header(start, count1, start, count2);

				// Write up to DIFF_UNIFIED_CTX previous matching lines as context.
				mc_u32 oldest = (rb.head + DIFF_UNIFIED_CTX - rb.count) % DIFF_UNIFIED_CTX;
				for (mc_u32 k = 0; k < rb.count; k++) {
					mc_u32 idx = (oldest + k) % DIFF_UNIFIED_CTX;
					diff_write_line_prefixed(argv0, " ", rb.lines[idx], rb.lens[idx]);
				}

				if (!eof1) diff_write_line_prefixed(argv0, "-", l1, n1);
				if (!eof2) diff_write_line_prefixed(argv0, "+", l2, n2);
			}

			diff_close_if_needed(fd1);
			diff_close_if_needed(fd2);
			return 1;
		}

		if (unified) {
			diff_ctx_push(&rb, l1, n1);
		}

		line_no++;
	}

	diff_close_if_needed(fd1);
	diff_close_if_needed(fd2);
	return 0;
}
