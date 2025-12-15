#include "mc.h"

static mc_i64 mc_write_cstr_ln(const char *s) {
	mc_i64 r = mc_write_str(1, s);
	if (r < 0) return r;
	return mc_write_all(1, "\n", 1);
}

__attribute__((used)) int main(int argc, char **argv, char **envp) {
	(void)envp;
	const char *argv0 = (argc > 0 && argv && argv[0]) ? argv[0] : "hostname";
	if (argc > 1) {
		mc_die_usage(argv0, "hostname");
	}

	struct mc_utsname u;
	mc_i64 r = mc_sys_uname(&u);
	if (r < 0) mc_die_errno(argv0, "uname", r);

	mc_i64 w = mc_write_cstr_ln(u.nodename);
	if (w < 0) mc_die_errno(argv0, "write", w);
	return 0;
}
