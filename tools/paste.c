#include "mc.h"

#define PASTE_MAX_FILES 32
#define PASTE_LINE_CAP 4096

struct paste_lr {
	mc_i32 fd;
	mc_u8 buf[4096];
	mc_u32 pos;
	mc_u32 len;
	int eof;
};

static MC_NORETURN void paste_die(const char *argv0, const char *msg) {
	(void)mc_write_str(2, argv0);
	(void)mc_write_str(2, ": ");
	(void)mc_write_str(2, msg);
	(void)mc_write_str(2, "\n");
	mc_exit(1);
}

static int paste_lr_read_line(const char *argv0, struct paste_lr *lr, char *out, mc_u32 cap, mc_u32 *out_len, int *out_had_nl) {
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
			paste_die(argv0, "line too long");
		}
		out[(*out_len)++] = (char)c;
	}
}

static mc_i32 paste_open_or_stdin(const char *argv0, const char *path) {
	if (mc_streq(path, "-")) return 0;
	mc_i64 fd = mc_sys_openat(MC_AT_FDCWD, path, MC_O_RDONLY | MC_O_CLOEXEC, 0);
	if (fd < 0) mc_die_errno(argv0, path, fd);
	return (mc_i32)fd;
}

__attribute__((used)) int main(int argc, char **argv, char **envp) {
	(void)envp;
	const char *argv0 = (argc > 0 && argv && argv[0]) ? argv[0] : "paste";

	int opt_serial = 0;
	const char *delims = "\t";
	mc_u32 deln = 1;

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
		if (mc_streq(a, "-s")) {
			opt_serial = 1;
			continue;
		}
		if (mc_streq(a, "-d")) {
			if (i + 1 >= argc) mc_die_usage(argv0, "paste [-s] [-d LIST] [FILE...] ");
			delims = argv[++i];
			deln = (mc_u32)mc_strlen(delims);
			if (deln == 0) mc_die_usage(argv0, "paste [-s] [-d LIST] [FILE...]");
			continue;
		}
		if (a[1] == 'd' && a[2]) {
			delims = a + 2;
			deln = (mc_u32)mc_strlen(delims);
			if (deln == 0) mc_die_usage(argv0, "paste [-s] [-d LIST] [FILE...]");
			continue;
		}
		mc_die_usage(argv0, "paste [-s] [-d LIST] [FILE...]");
	}

	int nfiles = argc - i;
	const char *paths[PASTE_MAX_FILES];
	if (nfiles <= 0) {
		paths[0] = "-";
		nfiles = 1;
	} else {
		if (nfiles > PASTE_MAX_FILES) mc_die_usage(argv0, "paste [-s] [-d LIST] [FILE...]");
		for (int k = 0; k < nfiles; k++) paths[k] = argv[i + k];
	}

	int stdin_count = 0;
	for (int k = 0; k < nfiles; k++) {
		if (mc_streq(paths[k], "-")) stdin_count++;
	}
	if (stdin_count > 1) {
		// Multiple '-' are ambiguous for this minimal implementation.
		mc_die_usage(argv0, "paste [-s] [-d LIST] [FILE...]");
	}

	if (opt_serial) {
		char line[PASTE_LINE_CAP];
		for (int k = 0; k < nfiles; k++) {
			mc_i32 fd = paste_open_or_stdin(argv0, paths[k]);
			struct paste_lr lr = {0};
			lr.fd = fd;

			mc_u32 lineno = 0;
			for (;;) {
				mc_u32 n = 0;
				int had_nl = 0;
				int ok = paste_lr_read_line(argv0, &lr, line, (mc_u32)sizeof(line), &n, &had_nl);
				if (!ok) break;
				if (lineno > 0) {
					char d = delims[(lineno - 1u) % deln];
					mc_i64 w = mc_write_all(1, &d, 1);
					if (w < 0) mc_die_errno(argv0, "write", w);
				}
				if (n) {
					mc_i64 w = mc_write_all(1, line, (mc_usize)n);
					if (w < 0) mc_die_errno(argv0, "write", w);
				}
				lineno++;
			}
			{
				char nl = '\n';
				mc_i64 w = mc_write_all(1, &nl, 1);
				if (w < 0) mc_die_errno(argv0, "write", w);
			}
			if (fd != 0) (void)mc_sys_close(fd);
		}
		return 0;
	}

	// Parallel mode.
	struct paste_lr lrs[PASTE_MAX_FILES];
	for (int k = 0; k < nfiles; k++) {
		lrs[k].fd = paste_open_or_stdin(argv0, paths[k]);
		lrs[k].pos = 0;
		lrs[k].len = 0;
		lrs[k].eof = 0;
	}

	static char lines[PASTE_MAX_FILES][PASTE_LINE_CAP];
	mc_u32 lens[PASTE_MAX_FILES];
	int had_nl[PASTE_MAX_FILES];

	for (;;) {
		int any = 0;
		for (int k = 0; k < nfiles; k++) {
			lens[k] = 0;
			had_nl[k] = 0;
			int ok = paste_lr_read_line(argv0, &lrs[k], lines[k], (mc_u32)sizeof(lines[k]), &lens[k], &had_nl[k]);
			if (ok) any = 1;
		}
		if (!any) break;

		for (int k = 0; k < nfiles; k++) {
			if (k > 0) {
				char d = delims[(mc_u32)(k - 1) % deln];
				mc_i64 w = mc_write_all(1, &d, 1);
				if (w < 0) mc_die_errno(argv0, "write", w);
			}
			if (lens[k]) {
				mc_i64 w = mc_write_all(1, lines[k], (mc_usize)lens[k]);
				if (w < 0) mc_die_errno(argv0, "write", w);
			}
		}
		{
			char nl = '\n';
			mc_i64 w = mc_write_all(1, &nl, 1);
			if (w < 0) mc_die_errno(argv0, "write", w);
		}
	}

	for (int k = 0; k < nfiles; k++) {
		if (lrs[k].fd != 0) (void)mc_sys_close(lrs[k].fd);
	}
	return 0;
}
