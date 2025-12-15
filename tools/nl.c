#include "mc.h"

#define NL_LINE_CAP 4096

struct nl_lr {
	mc_i32 fd;
	mc_u8 buf[4096];
	mc_u32 pos;
	mc_u32 len;
	int eof;
};

static int nl_lr_read_line(const char *argv0, struct nl_lr *lr, char *out, mc_u32 cap, mc_u32 *out_len, int *out_had_nl) {
	if (!lr || !out || cap == 0 || !out_len || !out_had_nl) return 0;
	*out_len = 0;
	*out_had_nl = 0;

	for (;;) {
		if (lr->eof) {
			return (*out_len > 0) ? 1 : 0;
		}
		if (lr->pos == lr->len) {
			mc_i64 r = mc_sys_read(lr->fd, lr->buf, (mc_usize)sizeof(lr->buf));
			if (r < 0) mc_die_errno(argv0, "read", r);
			if (r == 0) {
				lr->eof = 1;
				return (*out_len > 0) ? 1 : 0;
			}
			lr->pos = 0;
			lr->len = (mc_u32)r;
		}

		mc_u8 c = lr->buf[lr->pos++];
		if (c == (mc_u8)'\n') {
			*out_had_nl = 1;
			return 1;
		}
		if (*out_len + 1 >= cap) {
			(void)mc_write_str(2, argv0);
			(void)mc_write_str(2, ": line too long\n");
			mc_exit(1);
		}
		out[(*out_len)++] = (char)c;
	}
}

static mc_usize nl_u64_dec(char *buf, mc_usize cap, mc_u64 v) {
	char tmp[32];
	mc_usize n = 0;
	if (v == 0) {
		if (cap) buf[0] = '0';
		return cap ? 1u : 0u;
	}
	while (v && n < sizeof(tmp)) {
		mc_u64 q = v / 10u;
		mc_u64 r = v - q * 10u;
		tmp[n++] = (char)('0' + (char)r);
		v = q;
	}
	mc_usize out = (n < cap) ? n : cap;
	for (mc_usize i = 0; i < out; i++) buf[i] = tmp[n - 1 - i];
	return n;
}

static void nl_write_pad(const char *argv0, char ch, mc_u32 n) {
	char buf[64];
	for (mc_u32 i = 0; i < (mc_u32)sizeof(buf); i++) buf[i] = ch;
	while (n) {
		mc_u32 chunk = n;
		if (chunk > (mc_u32)sizeof(buf)) chunk = (mc_u32)sizeof(buf);
		mc_i64 w = mc_write_all(1, buf, (mc_usize)chunk);
		if (w < 0) mc_die_errno(argv0, "write", w);
		n -= chunk;
	}
}

__attribute__((used)) int main(int argc, char **argv, char **envp) {
	(void)envp;
	const char *argv0 = (argc > 0 && argv && argv[0]) ? argv[0] : "nl";

	int number_all = 0; // default: number non-empty only
	mc_u32 width = 6;
	const char *sep = "\t";

	int i = 1;
	for (; i < argc; i++) {
		const char *a = argv[i];
		if (!a) break;
		if (mc_streq(a, "--")) {
			i++;
			break;
		}
		if (a[0] != '-' || mc_streq(a, "-")) break;

		if (mc_streq(a, "-ba")) {
			number_all = 1;
			continue;
		}
		if (mc_streq(a, "-bt")) {
			number_all = 0;
			continue;
		}
		if (mc_streq(a, "-w")) {
			if (i + 1 >= argc) mc_die_usage(argv0, "nl [-ba|-bt] [-w WIDTH] [-s SEP] [FILE]");
			if (mc_parse_u32_dec(argv[++i], &width) != 0 || width == 0) {
				mc_die_usage(argv0, "nl [-ba|-bt] [-w WIDTH] [-s SEP] [FILE]");
			}
			continue;
		}
		if (a[1] == 'w' && a[2]) {
			if (mc_parse_u32_dec(a + 2, &width) != 0 || width == 0) {
				mc_die_usage(argv0, "nl [-ba|-bt] [-w WIDTH] [-s SEP] [FILE]");
			}
			continue;
		}
		if (mc_streq(a, "-s")) {
			if (i + 1 >= argc) mc_die_usage(argv0, "nl [-ba|-bt] [-w WIDTH] [-s SEP] [FILE]");
			sep = argv[++i];
			continue;
		}
		if (a[1] == 's' && a[2]) {
			sep = a + 2;
			continue;
		}

		mc_die_usage(argv0, "nl [-ba|-bt] [-w WIDTH] [-s SEP] [FILE]");
	}

	const char *path = 0;
	int npos = argc - i;
	if (npos == 0) {
		path = "-";
	} else if (npos == 1) {
		path = argv[i];
	} else {
		mc_die_usage(argv0, "nl [-ba|-bt] [-w WIDTH] [-s SEP] [FILE]");
	}

	mc_i32 fd = 0;
	if (!mc_streq(path, "-")) {
		mc_i64 rfd = mc_sys_openat(MC_AT_FDCWD, path, MC_O_RDONLY | MC_O_CLOEXEC, 0);
		if (rfd < 0) mc_die_errno(argv0, path, rfd);
		fd = (mc_i32)rfd;
	}

	struct nl_lr lr = {0};
	lr.fd = fd;

	char line[NL_LINE_CAP];
	mc_u64 n = 1;
	for (;;) {
		mc_u32 len = 0;
		int had_nl = 0;
		int ok = nl_lr_read_line(argv0, &lr, line, (mc_u32)sizeof(line), &len, &had_nl);
		if (!ok) break;

		int is_blank = (len == 0);
		if (!number_all && is_blank) {
			if (had_nl) {
				char c = '\n';
				mc_i64 w = mc_write_all(1, &c, 1);
				if (w < 0) mc_die_errno(argv0, "write", w);
			}
			continue;
		}

		char numbuf[32];
		mc_usize nd = nl_u64_dec(numbuf, sizeof(numbuf), n);
		if ((mc_u32)nd < width) nl_write_pad(argv0, ' ', width - (mc_u32)nd);
		mc_i64 w = mc_write_all(1, numbuf, nd);
		if (w < 0) mc_die_errno(argv0, "write", w);

		w = mc_write_str(1, sep);
		if (w < 0) mc_die_errno(argv0, "write", w);

		if (len) {
			w = mc_write_all(1, line, (mc_usize)len);
			if (w < 0) mc_die_errno(argv0, "write", w);
		}
		if (had_nl) {
			char c = '\n';
			w = mc_write_all(1, &c, 1);
			if (w < 0) mc_die_errno(argv0, "write", w);
		}

		n++;
	}

	if (fd != 0) (void)mc_sys_close(fd);
	return 0;
}
