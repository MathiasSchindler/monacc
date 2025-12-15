#include "mc.h"


#define ID_MAX_GROUPS 256

static mc_i64 id_write_kv_u64(const char *k, mc_u64 v) {
	mc_i64 w = mc_write_str(1, k);
	if (w < 0) return w;
	w = mc_write_u64_dec(1, v);
	return w;
}

__attribute__((used)) int main(int argc, char **argv, char **envp) {
	(void)envp;
	const char *argv0 = (argc > 0 && argv && argv[0]) ? argv[0] : "id";

	int opt_u = 0;
	int opt_g = 0;

	int i = 1;
	for (; i < argc; i++) {
		const char *a = argv[i];
		if (!a) break;
		if (mc_streq(a, "--")) {
			i++;
			break;
		}
		if (a[0] != '-') {
			break;
		}
		if (mc_streq(a, "-u")) {
			opt_u = 1;
			continue;
		}
		if (mc_streq(a, "-g")) {
			opt_g = 1;
			continue;
		}
		mc_die_usage(argv0, "id [-u|-g]");
	}

	if (i != argc) {
		mc_die_usage(argv0, "id [-u|-g]");
	}
	if (opt_u && opt_g) {
		mc_die_usage(argv0, "id [-u|-g]");
	}

	mc_i64 uid = mc_sys_getuid();
	mc_i64 gid = mc_sys_getgid();
	if (uid < 0) {
		mc_print_errno(argv0, "getuid", uid);
		return 1;
	}
	if (gid < 0) {
		mc_print_errno(argv0, "getgid", gid);
		return 1;
	}

	if (opt_u) {
		mc_i64 w = mc_write_i64_dec(1, uid);
		if (w < 0) mc_die_errno(argv0, "write", w);
		w = mc_write_all(1, "\n", 1);
		if (w < 0) mc_die_errno(argv0, "write", w);
		return 0;
	}
	if (opt_g) {
		mc_i64 w = mc_write_i64_dec(1, gid);
		if (w < 0) mc_die_errno(argv0, "write", w);
		w = mc_write_all(1, "\n", 1);
		if (w < 0) mc_die_errno(argv0, "write", w);
		return 0;
	}

	mc_i64 ng = mc_sys_getgroups(0, (mc_u32 *)0);
	if (ng < 0) {
		mc_print_errno(argv0, "getgroups", ng);
		return 1;
	}
	if (ng > ID_MAX_GROUPS) {
		(void)mc_write_str(2, argv0);
		(void)mc_write_str(2, ": too many groups\n");
		return 1;
	}

	mc_u32 groups[ID_MAX_GROUPS];
	for (mc_i64 k = 0; k < ng; k++) {
		groups[(mc_u32)k] = 0;
	}
	if (ng > 0) {
		mc_i64 r = mc_sys_getgroups((mc_i32)ng, groups);
		if (r < 0) {
			mc_print_errno(argv0, "getgroups", r);
			return 1;
		}
	}

	mc_i64 w = id_write_kv_u64("uid=", (mc_u64)uid);
	if (w < 0) mc_die_errno(argv0, "write", w);
	w = mc_write_all(1, " ", 1);
	if (w < 0) mc_die_errno(argv0, "write", w);
	w = id_write_kv_u64("gid=", (mc_u64)gid);
	if (w < 0) mc_die_errno(argv0, "write", w);
	w = mc_write_all(1, " ", 1);
	if (w < 0) mc_die_errno(argv0, "write", w);
	w = mc_write_str(1, "groups=");
	if (w < 0) mc_die_errno(argv0, "write", w);

	// Match common `id -G` ordering: primary gid first, then supplementary.
	w = mc_write_u64_dec(1, (mc_u64)gid);
	if (w < 0) mc_die_errno(argv0, "write", w);

	for (mc_i64 k = 0; k < ng; k++) {
		mc_u32 gk = groups[(mc_u32)k];
		if ((mc_u64)gk == (mc_u64)gid) {
			continue;
		}
		w = mc_write_all(1, ",", 1);
		if (w < 0) mc_die_errno(argv0, "write", w);
		w = mc_write_u64_dec(1, (mc_u64)gk);
		if (w < 0) mc_die_errno(argv0, "write", w);
	}

	w = mc_write_all(1, "\n", 1);
	if (w < 0) mc_die_errno(argv0, "write", w);
	return 0;
}
