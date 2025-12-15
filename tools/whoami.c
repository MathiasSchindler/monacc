#include "mc.h"

__attribute__((used)) int main(int argc, char **argv, char **envp) {
	(void)argv;
	(void)envp;
	const char *argv0 = (argc > 0 && argv && argv[0]) ? argv[0] : "whoami";

	// Minimal sysbox behavior: print numeric uid (no /etc/passwd parsing).
	mc_i64 uid = mc_sys_getuid();
	if (uid < 0) {
		mc_die_errno(argv0, "getuid", uid);
	}
	if (mc_write_u64_dec(1, (mc_u64)uid) < 0) mc_die_errno(argv0, "write", -1);
	if (mc_write_all(1, "\n", 1) < 0) mc_die_errno(argv0, "write", -1);
	return 0;
}
