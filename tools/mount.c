#include "mc.h"

#define MOUNT_LINE_MAX 8192

struct r {
	mc_i32 fd;
	char buf[4096];
	mc_usize off;
	mc_usize len;
};

static mc_i32 r_fill(struct r *r) {
	r->off = 0;
	mc_i64 n = mc_sys_read(r->fd, r->buf, sizeof(r->buf));
	if (n < 0) return (mc_i32)n;
	r->len = (mc_usize)n;
	return (mc_i32)n;
}

static int r_read_line(struct r *r, char *out, mc_usize out_sz, mc_usize *out_n) {
	// Returns: 1 line, 0 EOF, -1 error.
	mc_usize n = 0;
	while (1) {
		if (r->off >= r->len) {
			mc_i32 fr = r_fill(r);
			if (fr < 0) return -1;
			if (fr == 0) {
				if (n == 0) return 0;
				out[n] = 0;
				*out_n = n;
				return 1;
			}
		}
		char c = r->buf[r->off++];
		if (c == '\n') {
			out[n] = 0;
			*out_n = n;
			return 1;
		}
		if (n + 1 >= out_sz) return -1;
		out[n++] = c;
	}
}

static int tok_next(const char *s, mc_usize *io, mc_usize n, mc_usize *out_s, mc_usize *out_n) {
	// Tokenize by spaces; no unescaping.
	mc_usize i = *io;
	while (i < n && (s[i] == ' ' || s[i] == '\t')) i++;
	if (i >= n) {
		*out_s = i;
		*out_n = 0;
		*io = i;
		return 0;
	}
	mc_usize start = i;
	while (i < n && s[i] != ' ' && s[i] != '\t') i++;
	*out_s = start;
	*out_n = i - start;
	*io = i;
	return 1;
}

__attribute__((used)) int main(int argc, char **argv, char **envp) {
	(void)envp;
	const char *argv0 = (argc > 0 && argv && argv[0]) ? argv[0] : "mount";

	int i = 1;
	for (; i < argc; i++) {
		const char *a = argv[i];
		if (!a) break;
		if (mc_streq(a, "--")) {
			i++;
			break;
		}
		if (a[0] == '-') mc_die_usage(argv0, "mount");
		break;
	}
	if (i != argc) mc_die_usage(argv0, "mount");

	mc_i64 fd = mc_sys_openat(MC_AT_FDCWD, "/proc/self/mountinfo", MC_O_RDONLY | MC_O_CLOEXEC, 0);
	if (fd < 0) mc_die_errno(argv0, "/proc/self/mountinfo", fd);

	struct r rr = { .fd = (mc_i32)fd, .off = 0, .len = 0 };
	char line[MOUNT_LINE_MAX];
	mc_usize ln = 0;
	while (1) {
		int rc = r_read_line(&rr, line, sizeof(line), &ln);
		if (rc < 0) {
			mc_die_errno(argv0, "read", -MC_EINVAL);
		}
		if (rc == 0) break;
		if (ln == 0) continue;

		// mountinfo format:
		// id parent major:minor root mount_point options optional_fields... - fstype source superoptions
		mc_usize off = 0;
		mc_usize ts = 0, tn = 0;
		// skip 4 tokens
		for (int k = 0; k < 4; k++) {
			if (!tok_next(line, &off, ln, &ts, &tn) || tn == 0) {
				goto next_line;
			}
		}
		// mount point
		if (!tok_next(line, &off, ln, &ts, &tn) || tn == 0) goto next_line;
		mc_usize mp_s = ts;
		mc_usize mp_n = tn;

		// scan for token "-"
		mc_usize fst_s = 0, fst_n = 0;
		mc_usize src_s = 0, src_n = 0;
		while (tok_next(line, &off, ln, &ts, &tn) && tn > 0) {
			if (tn == 1 && line[ts] == '-') {
				if (!tok_next(line, &off, ln, &fst_s, &fst_n) || fst_n == 0) goto next_line;
				if (!tok_next(line, &off, ln, &src_s, &src_n) || src_n == 0) goto next_line;
				break;
			}
		}
		if (fst_n == 0 || src_n == 0) goto next_line;

		(void)mc_write_all(1, line + mp_s, mp_n);
		(void)mc_write_all(1, "\t", 1);
		(void)mc_write_all(1, line + fst_s, fst_n);
		(void)mc_write_all(1, "\t", 1);
		(void)mc_write_all(1, line + src_s, src_n);
		(void)mc_write_all(1, "\n", 1);

	next_line:
		;
	}

	(void)mc_sys_close((mc_i32)fd);
	return 0;
}
