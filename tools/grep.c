#include "mc.h"

#define GREP_READ_BUF_SIZE 32768u
#define GREP_LINE_MAX 65536u

struct grep_reader {
	mc_i32 fd;
	mc_u8 buf[GREP_READ_BUF_SIZE];
	mc_u32 pos;
	mc_u32 len;
	int eof;
};

static MC_NORETURN void grep_die_msg(const char *argv0, const char *msg) {
	(void)mc_write_str(2, argv0);
	(void)mc_write_str(2, ": ");
	(void)mc_write_str(2, msg);
	(void)mc_write_str(2, "\n");
	mc_exit(1);
}

static int grep_is_upper_ascii(mc_u8 c) {
	return (c >= (mc_u8)'A' && c <= (mc_u8)'Z');
}

static mc_u8 grep_tolower_ascii(mc_u8 c) {
	if (grep_is_upper_ascii(c)) {
		return (mc_u8)(c + (mc_u8)('a' - 'A'));
	}
	return c;
}

static int grep_fill(struct grep_reader *r, const char *argv0) {
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
static int grep_read_line(struct grep_reader *r, const char *argv0, mc_u8 *out, mc_u32 *out_len) {
	mc_u32 n = 0;
	int have_any = 0;

	for (;;) {
		if (r->pos >= r->len) {
			if (!grep_fill(r, argv0)) {
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
			if (n >= GREP_LINE_MAX) {
				grep_die_msg(argv0, "line too long");
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

static int grep_match_at(const mc_u8 *hay, mc_u32 hlen, const mc_u8 *needle, mc_u32 nlen, mc_u32 pos, int insensitive) {
	if (pos + nlen > hlen) {
		return 0;
	}
	for (mc_u32 i = 0; i < nlen; i++) {
		mc_u8 hc = hay[pos + i];
		mc_u8 nc = needle[i];
		if (insensitive) {
			hc = grep_tolower_ascii(hc);
			nc = grep_tolower_ascii(nc);
		}
		if (hc != nc) {
			return 0;
		}
	}
	return 1;
}

static int grep_line_matches(const mc_u8 *line, mc_u32 line_len, const mc_u8 *pat, mc_u32 pat_len, int insensitive) {
	if (pat_len == 0) {
		return 1;
	}
	if (pat_len > line_len) {
		return 0;
	}
	for (mc_u32 i = 0; i + pat_len <= line_len; i++) {
		if (grep_match_at(line, line_len, pat, pat_len, i, insensitive)) {
			return 1;
		}
	}
	return 0;
}


static int grep_line_matches_regex(const char *pattern, mc_u8 *line, mc_u32 line_len, mc_u32 flags) {
	// The line buffer is guaranteed to have room for a trailing NUL.
	if (line_len >= GREP_LINE_MAX) return 0;
	line[line_len] = 0;
	const char *ms = 0;
	const char *me = 0;
	int r = mc_regex_match_first(pattern, (const char *)line, flags, &ms, &me, 0);
	if (r < 0) return -1;
	return r;
}

static mc_i64 grep_write_line(const mc_u8 *line, mc_u32 line_len, int with_lineno, mc_u64 lineno) {
	mc_i64 w;
	if (with_lineno) {
		w = mc_write_u64_dec(1, lineno);
		if (w < 0) return w;
		w = mc_write_all(1, ":", 1);
		if (w < 0) return w;
	}
	w = mc_write_all(1, line, (mc_usize)line_len);
	if (w < 0) return w;
	w = mc_write_all(1, "\n", 1);
	return w;
}

static int grep_fd(const char *argv0, mc_i32 fd, const char *pattern, const mc_u8 *pat, mc_u32 pat_len, int use_fixed, int opt_i, int opt_v, int opt_c, int opt_n, int opt_q, mc_u64 *io_count, int *io_matched) {
	struct grep_reader r;
	r.fd = fd;
	r.pos = 0;
	r.len = 0;
	r.eof = 0;

	mc_u8 line[GREP_LINE_MAX];
	mc_u32 line_len = 0;
	mc_u64 lineno = 0;

	for (;;) {
		int ok = grep_read_line(&r, argv0, line, &line_len);
		if (!ok) {
			break;
		}
		lineno++;

		int m;
		if (use_fixed) {
			m = grep_line_matches(line, line_len, pat, pat_len, opt_i);
		} else {
			mc_u32 flags = opt_i ? MC_REGEX_ICASE : 0u;
			m = grep_line_matches_regex(pattern, line, line_len, flags);
			if (m < 0) {
				mc_die_usage(argv0, "grep [-i] [-v] [-c] [-n] [-q] [-F] PATTERN [FILE...] (invalid regex)");
			}
		}
		if (opt_v) {
			m = !m;
		}
		if (!m) {
			continue;
		}

		*io_matched = 1;
		(*io_count)++;

		if (opt_q) {
			return 0;
		}
		if (!opt_c) {
			mc_i64 w = grep_write_line(line, line_len, opt_n, lineno);
			if (w < 0) {
				mc_die_errno(argv0, "write", w);
			}
		}
	}

	return 0;
}

__attribute__((used)) int main(int argc, char **argv, char **envp) {
	(void)envp;
	const char *argv0 = (argc > 0 && argv && argv[0]) ? argv[0] : "grep";

	int opt_i = 0;
	int opt_v = 0;
	int opt_c = 0;
	int opt_n = 0;
	int opt_q = 0;
	int opt_F = 0;

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
		if (mc_streq(a, "-i")) {
			opt_i = 1;
			continue;
		}
		if (mc_streq(a, "-v")) {
			opt_v = 1;
			continue;
		}
		if (mc_streq(a, "-c")) {
			opt_c = 1;
			continue;
		}
		if (mc_streq(a, "-n")) {
			opt_n = 1;
			continue;
		}
		if (mc_streq(a, "-q")) {
			opt_q = 1;
			continue;
		}
		if (mc_streq(a, "-F")) {
			opt_F = 1;
			continue;
		}
		mc_die_usage(argv0, "grep [-i] [-v] [-c] [-n] [-q] [-F] PATTERN [FILE...]");
	}

	if (i >= argc || !argv[i]) {
		mc_die_usage(argv0, "grep [-i] [-v] [-c] [-n] [-q] [-F] PATTERN [FILE...]");
	}
	const char *pattern = argv[i++];

	mc_u8 pat[GREP_LINE_MAX];
	mc_usize pat_len_usz = mc_strlen(pattern);
	if (pat_len_usz >= (mc_usize)GREP_LINE_MAX) {
		mc_die_usage(argv0, "grep [-i] [-v] [-c] [-n] [-q] [-F] PATTERN [FILE...]");
	}
	mc_u32 pat_len = (mc_u32)pat_len_usz;
	for (mc_u32 k = 0; k < pat_len; k++) {
		pat[k] = (mc_u8)pattern[k];
	}

	if (!opt_F) {
		// Validate the pattern once up front.
		const char *ms = 0;
		const char *me = 0;
		int r = mc_regex_match_first(pattern, "", opt_i ? MC_REGEX_ICASE : 0u, &ms, &me, 0);
		if (r < 0) {
			mc_die_usage(argv0, "grep [-i] [-v] [-c] [-n] [-q] [-F] PATTERN [FILE...] (invalid regex)");
		}
	}

	int matched = 0;
	mc_u64 count = 0;

	if (i >= argc) {
		(void)grep_fd(argv0, 0, pattern, pat, pat_len, opt_F, opt_i, opt_v, opt_c, opt_n, opt_q, &count, &matched);
	} else {
		for (; i < argc; i++) {
			const char *path = argv[i];
			if (!path) break;
			if (mc_streq(path, "-")) {
				(void)grep_fd(argv0, 0, pattern, pat, pat_len, opt_F, opt_i, opt_v, opt_c, opt_n, opt_q, &count, &matched);
				if (opt_q && matched) {
					return 0;
				}
				continue;
			}
			mc_i64 fd = mc_sys_openat(MC_AT_FDCWD, path, MC_O_RDONLY | MC_O_CLOEXEC, 0);
			if (fd < 0) {
				mc_print_errno(argv0, path, fd);
				continue;
			}
			(void)grep_fd(argv0, (mc_i32)fd, pattern, pat, pat_len, opt_F, opt_i, opt_v, opt_c, opt_n, opt_q, &count, &matched);
			(void)mc_sys_close((mc_i32)fd);
			if (opt_q && matched) {
				return 0;
			}
		}
	}

	if (opt_c && !opt_q) {
		mc_i64 w = mc_write_u64_dec(1, count);
		if (w < 0) mc_die_errno(argv0, "write", w);
		w = mc_write_all(1, "\n", 1);
		if (w < 0) mc_die_errno(argv0, "write", w);
	}

	if (matched) {
		return 0;
	}
	// No matches (or operational errors). Either way, exit 1.
	return 1;
}
