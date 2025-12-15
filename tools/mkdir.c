#include "mc.h"

static mc_usize mc_strnlen(const char *s, mc_usize max) {
	mc_usize n = 0;
	while (n < max && s && s[n]) {
		n++;
	}
	return n;
}

static void mkdir_p(const char *argv0, const char *path, mc_u32 mode) {
	if (!path || !*path) {
		mc_die_usage(argv0, "mkdir [-p] [-m MODE] DIR");
	}

	// Keep this small and deterministic; refuse extremely long paths.
	char cur[4096];
	const mc_usize path_len = mc_strnlen(path, sizeof(cur));
	if (path_len == sizeof(cur)) {
		mc_die_errno(argv0, path, (mc_i64)-MC_EINVAL);
	}

	// Special-case paths consisting only of slashes: mkdir -p / => success.
	int any_non_slash = 0;
	for (mc_usize k = 0; k < path_len; k++) {
		if (path[k] != '/') {
			any_non_slash = 1;
			break;
		}
	}
	if (!any_non_slash) {
		return;
	}

	mc_usize cur_len = 0;
	mc_usize i = 0;
	if (path[0] == '/') {
		cur[cur_len++] = '/';
		i = 1;
		while (i < path_len && path[i] == '/') {
			i++;
		}
	}

	while (i < path_len) {
		// Parse next component.
		mc_usize start = i;
		while (i < path_len && path[i] != '/') {
			i++;
		}
		mc_usize comp_len = i - start;

		while (i < path_len && path[i] == '/') {
			i++;
		}

		if (comp_len == 0) {
			continue;
		}

		if (cur_len > 0 && cur[cur_len - 1] != '/') {
			if (cur_len + 1 >= sizeof(cur)) {
				mc_die_errno(argv0, path, (mc_i64)-MC_EINVAL);
			}
			cur[cur_len++] = '/';
		}
		if (cur_len + comp_len + 1 > sizeof(cur)) {
			mc_die_errno(argv0, path, (mc_i64)-MC_EINVAL);
		}

		for (mc_usize k = 0; k < comp_len; k++) {
			cur[cur_len + k] = path[start + k];
		}
		cur_len += comp_len;
		cur[cur_len] = 0;

		mc_i64 r = mc_sys_mkdirat(MC_AT_FDCWD, cur, mode);
		if (r < 0) {
			mc_u64 e = (mc_u64)(-r);
			if (e == (mc_u64)MC_EEXIST) {
				// Confirm the existing path is a directory.
				mc_i64 fd = mc_sys_openat(MC_AT_FDCWD, cur, MC_O_RDONLY | MC_O_CLOEXEC | MC_O_DIRECTORY, 0);
				if (fd < 0) {
					mc_die_errno(argv0, cur, fd);
				}
				(void)mc_sys_close((mc_i32)fd);
			} else {
				mc_die_errno(argv0, cur, r);
			}
		}
	}
}

__attribute__((used)) int main(int argc, char **argv, char **envp) {
	(void)envp;

	const char *argv0 = (argc > 0 && argv && argv[0]) ? argv[0] : "mkdir";
	int parents = 0;
	mc_u32 mode = 0777;

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
		if (mc_streq(a, "-p")) {
			parents = 1;
			continue;
		}
		if (mc_streq(a, "-m")) {
			if (i + 1 >= argc) {
				mc_die_usage(argv0, "mkdir [-p] [-m MODE] DIR");
			}
			const char *m = argv[++i];
			if (mc_parse_u32_octal(m, &mode) != 0 || mode > 07777u) {
				mc_die_usage(argv0, "mkdir [-p] [-m MODE] DIR");
			}
			continue;
		}
		mc_die_usage(argv0, "mkdir [-p] [-m MODE] DIR");
	}

	if (argc - i != 1) {
		mc_die_usage(argv0, "mkdir [-p] [-m MODE] DIR");
	}

	const char *path = argv[i] ? argv[i] : "";
	if (parents) {
		mkdir_p(argv0, path, mode);
		return 0;
	}

	mc_i64 r = mc_sys_mkdirat(MC_AT_FDCWD, path, mode);
	if (r < 0) mc_die_errno(argv0, path, r);
	return 0;
}
