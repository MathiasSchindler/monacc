#include "mc.h"

__attribute__((used)) int main(int argc, char **argv, char **envp) {
	(void)envp;
	const char *argv0 = (argc > 0 && argv && argv[0]) ? argv[0] : "chown";

	int i = 1;
	if (i < argc && argv[i] && mc_streq(argv[i], "--")) {
		i++;
	}

	if (argc - i < 2) {
		mc_die_usage(argv0, "chown UID[:GID] FILE...");
	}

	mc_u32 uid, gid;
	if (mc_parse_uid_gid(argv[i], &uid, &gid) != 0) {
		mc_die_usage(argv0, "chown UID[:GID] FILE...");
	}
	i++;

	int any_fail = 0;
	for (; i < argc; i++) {
		const char *path = argv[i] ? argv[i] : "";
		mc_i64 r = mc_sys_fchownat(MC_AT_FDCWD, path, uid, gid, 0);
		if (r < 0) {
			mc_print_errno(argv0, path, r);
			any_fail = 1;
		}
	}

	return any_fail ? 1 : 0;
}
