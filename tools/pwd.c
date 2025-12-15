#include "mc.h"

__attribute__((used)) int main(int argc, char **argv, char **envp) {
	(void)argc;
	(void)envp;

	const char *argv0 = (argv && argv[0]) ? argv[0] : "pwd";

	// Fixed-buffer strategy: try small first, then a larger cap.
	char buf1[4096];
	mc_i64 r1 = mc_sys_getcwd(buf1, (mc_usize)sizeof(buf1));
	if (r1 >= 0) {
		if (mc_write_str(1, buf1) < 0 || mc_write_all(1, "\n", 1) < 0) {
			mc_die_errno(argv0, "write", -1);
		}
		return 0;
	}

	// If the cwd is longer than buf1, Linux returns -ERANGE.
	// Retry with a larger (still fixed) buffer.
	char buf2[65536];
	mc_i64 r2 = mc_sys_getcwd(buf2, (mc_usize)sizeof(buf2));
	if (r2 < 0) {
		mc_die_errno(argv0, "getcwd", r2);
	}

	if (mc_write_str(1, buf2) < 0 || mc_write_all(1, "\n", 1) < 0) {
		mc_die_errno(argv0, "write", -1);
	}
	return 0;
}
