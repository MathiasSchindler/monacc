#include "mc.h"

static int rlf_copy(char *dst, mc_usize dstsz, const char *src) {
	if (!dst || dstsz == 0) {
		return -1;
	}
	if (!src) {
		src = "";
	}
	mc_usize i = 0;
	for (; src[i] != '\0'; i++) {
		if (i + 1 >= dstsz) {
			return -1;
		}
		dst[i] = src[i];
	}
	dst[i] = '\0';
	return 0;
}

static int rlf_append(char *dst, mc_usize dstsz, const char *src) {
	mc_usize dlen = mc_strlen(dst);
	if (!src) {
		return 0;
	}
	for (mc_usize i = 0; src[i] != '\0'; i++) {
		if (dlen + 1 >= dstsz) {
			return -1;
		}
		dst[dlen++] = src[i];
	}
	dst[dlen] = '\0';
	return 0;
}

static int rlf_append_n(char *dst, mc_usize dstsz, const char *src, mc_usize n) {
	mc_usize dlen = mc_strlen(dst);
	for (mc_usize i = 0; i < n; i++) {
		if (dlen + 1 >= dstsz) {
			return -1;
		}
		dst[dlen++] = src[i];
	}
	dst[dlen] = '\0';
	return 0;
}

static int rlf_streq_n(const char *s, mc_usize n, const char *lit) {
	for (mc_usize i = 0; i < n; i++) {
		if (lit[i] == '\0') {
			return 0;
		}
		if (s[i] != lit[i]) {
			return 0;
		}
	}
	return (lit[n] == '\0');
}

static int rlf_ends_with(const char *s, const char *suffix) {
	if (!s || !suffix) {
		return 0;
	}
	mc_usize slen = mc_strlen(s);
	mc_usize tlen = mc_strlen(suffix);
	if (tlen > slen) {
		return 0;
	}
	return mc_streq(s + (slen - tlen), suffix);
}

static void rlf_pop_one_component(char *path) {
	mc_usize len = mc_strlen(path);
	if (len == 0) {
		return;
	}
	if (len == 1 && path[0] == '/') {
		return;
	}
	while (len > 1 && path[len - 1] == '/') {
		path[--len] = '\0';
	}
	while (len > 1 && path[len - 1] != '/') {
		path[--len] = '\0';
	}
	while (len > 1 && path[len - 1] == '/') {
		path[--len] = '\0';
	}
	if (len == 0) {
		path[0] = '/';
		path[1] = '\0';
	}
}

static mc_i64 rlf_make_abs(const char *in, char out[4096]) {
	if (!in) {
		return -MC_EINVAL;
	}
	if (in[0] == '/') {
		if (rlf_copy(out, 4096, in) != 0) {
			return -MC_EINVAL;
		}
		return 0;
	}

	char cwd[4096];
	mc_i64 r = mc_sys_getcwd(cwd, (mc_usize)sizeof(cwd));
	if (r < 0) {
		return r;
	}
	cwd[sizeof(cwd) - 1] = '\0';
	if (rlf_copy(out, 4096, cwd) != 0) {
		return -MC_EINVAL;
	}
	if (!(out[0] == '/' && out[1] == '\0')) {
		if (rlf_append(out, 4096, "/") != 0) {
			return -MC_EINVAL;
		}
	}
	if (rlf_append(out, 4096, in) != 0) {
		return -MC_EINVAL;
	}
	return 0;
}

static mc_i64 rlf_canonicalize(const char *path, char out[4096]) {
	char pending[4096];
	mc_i64 ar = rlf_make_abs(path, pending);
	if (ar < 0) {
		return ar;
	}

	int depth = 0;
	for (;;) {
		char resolved[4096];
		resolved[0] = '/';
		resolved[1] = '\0';

		const char *p = pending;
		while (*p == '/') {
			p++;
		}

		for (;;) {
			while (*p == '/') {
				p++;
			}
			if (*p == '\0') {
				if (rlf_copy(out, 4096, resolved) != 0) {
					return -MC_EINVAL;
				}
				return 0;
			}

			const char *cstart = p;
			while (*p != '\0' && *p != '/') {
				p++;
			}
			mc_usize clen = (mc_usize)(p - cstart);
			if (clen == 0) {
				continue;
			}
			if (rlf_streq_n(cstart, clen, ".")) {
				continue;
			}
			if (rlf_streq_n(cstart, clen, "..")) {
				rlf_pop_one_component(resolved);
				continue;
			}

			char parent[4096];
			if (rlf_copy(parent, 4096, resolved) != 0) {
				return -MC_EINVAL;
			}

			if (!(resolved[0] == '/' && resolved[1] == '\0')) {
				if (rlf_append(resolved, 4096, "/") != 0) {
					return -MC_EINVAL;
				}
			}
			if (rlf_append_n(resolved, 4096, cstart, clen) != 0) {
				return -MC_EINVAL;
			}

			struct mc_stat st;
			mc_i64 sr = mc_sys_newfstatat(MC_AT_FDCWD, resolved, &st, MC_AT_SYMLINK_NOFOLLOW);
			if (sr < 0) {
				return sr;
			}
			if ((st.st_mode & MC_S_IFMT) == MC_S_IFLNK) {
				depth++;
				if (depth > 40) {
					return -MC_ELOOP;
				}

				char linkbuf[4096];
				mc_i64 n = mc_sys_readlinkat(MC_AT_FDCWD, resolved, linkbuf, (mc_usize)(sizeof(linkbuf) - 1u));
				if (n < 0) {
					return n;
				}
				linkbuf[(mc_usize)n] = '\0';

				char next[4096];
				next[0] = '\0';
				if (linkbuf[0] == '/') {
					if (rlf_copy(next, 4096, linkbuf) != 0) {
						return -MC_EINVAL;
					}
				} else {
					if (rlf_copy(next, 4096, parent) != 0) {
						return -MC_EINVAL;
					}
					if (!(next[0] == '/' && next[1] == '\0')) {
						if (rlf_append(next, 4096, "/") != 0) {
							return -MC_EINVAL;
						}
					}
					if (rlf_append(next, 4096, linkbuf) != 0) {
						return -MC_EINVAL;
					}
				}
				// Append the remaining suffix starting at p (may be "" or "/...").
				if (*p != '\0') {
					if (rlf_append(next, 4096, p) != 0) {
						return -MC_EINVAL;
					}
				}

				// Restart with new absolute pending path.
				mc_i64 mr = rlf_make_abs(next, pending);
				if (mr < 0) {
					return mr;
				}
				break;
			}
		}
	}
}

__attribute__((used)) int main(int argc, char **argv, char **envp) {
	(void)envp;
	const char *argv0 = (argc > 0 && argv && argv[0]) ? argv[0] : "readlink";
	int invoked_realpath = mc_streq(argv0, "realpath") || rlf_ends_with(argv0, "/realpath");
	const char *usage = invoked_realpath ? "realpath PATH" : "readlink [-f] PATH";
	int canonical = invoked_realpath ? 1 : 0;

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
		if (!invoked_realpath && mc_streq(a, "-f")) {
			canonical = 1;
			continue;
		}
		mc_die_usage(argv0, usage);
	}

	if ((argc - i) != 1) {
		mc_die_usage(argv0, usage);
	}

	const char *path = argv[i];
	if (canonical) {
		char out[4096];
		mc_i64 rr = rlf_canonicalize(path, out);
		if (rr < 0) {
			mc_die_errno(argv0, invoked_realpath ? "realpath" : "readlink -f", rr);
		}
		mc_i64 w = mc_write_all(1, out, mc_strlen(out));
		if (w < 0) {
			mc_die_errno(argv0, "write", w);
		}
		w = mc_write_all(1, "\n", 1);
		if (w < 0) {
			mc_die_errno(argv0, "write", w);
		}
		return 0;
	}

	char buf[4096];
	mc_i64 n = mc_sys_readlinkat(MC_AT_FDCWD, path, buf, (mc_usize)sizeof(buf));
	if (n < 0) {
		mc_die_errno(argv0, "readlinkat", n);
	}

	// readlink does not NUL-terminate.
	mc_i64 w = mc_write_all(1, buf, (mc_usize)n);
	if (w < 0) {
		mc_die_errno(argv0, "write", w);
	}
	w = mc_write_all(1, "\n", 1);
	if (w < 0) {
		mc_die_errno(argv0, "write", w);
	}
	return 0;
}
