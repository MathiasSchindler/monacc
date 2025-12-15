#include "mc.h"

#define REV_LINE_MAX 65536

struct r {
	mc_i32 fd;
	mc_u8 buf[4096];
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

static int r_getc(struct r *r, mc_u8 *out) {
	if (r->off >= r->len) {
		mc_i32 fr = r_fill(r);
		if (fr < 0) return -1;
		if (fr == 0) return 0;
	}
	*out = r->buf[r->off++];
	return 1;
}

static void rev_fd(const char *argv0, mc_i32 fd) {
	mc_u8 line[REV_LINE_MAX];
	mc_usize n = 0;
	struct r rr = { .fd = fd, .off = 0, .len = 0 };

	while (1) {
		mc_u8 c = 0;
		int rc = r_getc(&rr, &c);
		if (rc < 0) mc_die_errno(argv0, "read", (mc_i64)-MC_EINVAL);
		if (rc == 0) {
			// flush last partial line
			for (mc_usize i = 0; i < n / 2; i++) {
				mc_u8 t = line[i];
				line[i] = line[n - 1 - i];
				line[n - 1 - i] = t;
			}
			if (n) (void)mc_write_all(1, line, n);
			break;
		}
		if (c == '\n') {
			for (mc_usize i = 0; i < n / 2; i++) {
				mc_u8 t = line[i];
				line[i] = line[n - 1 - i];
				line[n - 1 - i] = t;
			}
			if (n) (void)mc_write_all(1, line, n);
			(void)mc_write_all(1, "\n", 1);
			n = 0;
			continue;
		}
		if (n + 1 >= sizeof(line)) {
			mc_die_errno(argv0, "line too long", (mc_i64)-MC_EINVAL);
		}
		line[n++] = c;
	}
}

__attribute__((used)) int main(int argc, char **argv, char **envp) {
	(void)envp;
	const char *argv0 = (argc > 0 && argv && argv[0]) ? argv[0] : "rev";

	int i = 1;
	for (; i < argc; i++) {
		const char *a = argv[i];
		if (!a) break;
		if (mc_streq(a, "--")) {
			i++;
			break;
		}
		if (a[0] == '-') mc_die_usage(argv0, "rev [FILE...]");
		break;
	}

	if (i >= argc) {
		rev_fd(argv0, 0);
		return 0;
	}

	for (; i < argc; i++) {
		const char *path = argv[i];
		if (!path) continue;
		mc_i64 fd = mc_sys_openat(MC_AT_FDCWD, path, MC_O_RDONLY | MC_O_CLOEXEC, 0);
		if (fd < 0) mc_die_errno(argv0, path, fd);
		rev_fd(argv0, (mc_i32)fd);
		(void)mc_sys_close((mc_i32)fd);
	}
	return 0;
}
