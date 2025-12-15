#include "mc.h"

__attribute__((used)) int main(int argc, char **argv, char **envp) {
	(void)envp;
	const char *argv0 = (argc > 0 && argv && argv[0]) ? argv[0] : "ln";
	int symbolic = 0;
	int force = 0;

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
			// Combined short options: -sf
			for (mc_u32 j = 1; a[j]; j++) {
				if (a[j] == 's') symbolic = 1;
				else if (a[j] == 'f') force = 1;
				else mc_die_usage(argv0, "ln [-s] [-f] [--] SRC DST");
			}
			continue;
		}
		if (mc_streq(a, "-s")) {
			symbolic = 1;
			continue;
		}
		if (mc_streq(a, "-f")) {
			force = 1;
			continue;
		}
		mc_die_usage(argv0, "ln [-s] [-f] [--] SRC DST");
	}

	if ((argc - i) != 2) {
		mc_die_usage(argv0, "ln [-s] [-f] [--] SRC DST");
	}

	const char *src = argv[i];
	const char *dst = argv[i + 1];
	if (force) {
		mc_i64 ur = mc_sys_unlinkat(MC_AT_FDCWD, dst, 0);
		if (ur < 0 && (mc_u64)(-ur) != (mc_u64)MC_ENOENT) {
			mc_die_errno(argv0, "unlinkat", ur);
		}
	}

	mc_i64 r;
	if (symbolic) {
		r = mc_sys_symlinkat(src, MC_AT_FDCWD, dst);
	} else {
		r = mc_sys_linkat(MC_AT_FDCWD, src, MC_AT_FDCWD, dst, 0);
	}
	if (r < 0) {
		mc_die_errno(argv0, symbolic ? "symlinkat" : "linkat", r);
	}
	return 0;
}
