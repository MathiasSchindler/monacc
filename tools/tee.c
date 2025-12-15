#include "mc.h"

#define TEE_MAX_OUT 32

static mc_i64 tee_open_out(const char *path, int append) {
	mc_i32 flags = MC_O_WRONLY | MC_O_CREAT | MC_O_CLOEXEC;
	if (append) {
		flags |= MC_O_APPEND;
	} else {
		flags |= MC_O_TRUNC;
	}
	return mc_sys_openat(MC_AT_FDCWD, path, flags, 0666);
}

__attribute__((used)) int main(int argc, char **argv, char **envp) {
	(void)envp;
	const char *argv0 = (argc > 0 && argv && argv[0]) ? argv[0] : "tee";
	int append = 0;

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
		if (a[1] && a[1] != '-' && a[2]) {
			// Combined short options.
			for (mc_u32 j = 1; a[j]; j++) {
				if (a[j] == 'a') append = 1;
				else mc_die_usage(argv0, "tee [-a] [FILE...]");
			}
			continue;
		}
		if (mc_streq(a, "-a")) {
			append = 1;
			continue;
		}
		mc_die_usage(argv0, "tee [-a] [FILE...]");
	}

	mc_i32 out_fds[TEE_MAX_OUT];
	const char *out_names[TEE_MAX_OUT];
	int out_n = 0;
	int had_error = 0;

	// stdout is always output 0.
	out_fds[out_n] = 1;
	out_names[out_n] = "write";
	out_n++;

	for (; i < argc; i++) {
		const char *path = argv[i];
		if (!path) break;
		if (mc_streq(path, "-")) {
			// Treat '-' as stdout.
			continue;
		}
		if (out_n >= TEE_MAX_OUT) {
			mc_die_usage(argv0, "tee [-a] [FILE...]");
		}
		mc_i64 fd = tee_open_out(path, append);
		if (fd < 0) {
			mc_print_errno(argv0, path, fd);
			had_error = 1;
			continue;
		}
		out_fds[out_n] = (mc_i32)fd;
		out_names[out_n] = path;
		out_n++;
	}

	mc_u8 buf[32768];
	for (;;) {
		mc_i64 r = mc_sys_read(0, buf, (mc_usize)sizeof(buf));
		if (r < 0) {
			mc_die_errno(argv0, "read", r);
		}
		if (r == 0) {
			break;
		}

		for (int oi = 0; oi < out_n; oi++) {
			mc_i32 fd = out_fds[oi];
			if (fd < 0) {
				continue;
			}
			mc_i64 w = mc_write_all(fd, buf, (mc_usize)r);
			if (w < 0) {
				if (fd == 1) {
					mc_die_errno(argv0, "write", w);
				}
				mc_print_errno(argv0, out_names[oi], w);
				had_error = 1;
				(void)mc_sys_close(fd);
				out_fds[oi] = -1;
			}
		}
	}

	for (int oi = 1; oi < out_n; oi++) {
		if (out_fds[oi] >= 0) {
			(void)mc_sys_close(out_fds[oi]);
		}
	}

	return had_error ? 1 : 0;
}
