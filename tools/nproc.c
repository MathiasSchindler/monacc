#include "mc.h"

static int mc_popcount_u8(mc_u8 b) {
	int c = 0;
	while (b) {
		c += (b & 1u) ? 1 : 0;
		b >>= 1;
	}
	return c;
}

__attribute__((used)) int main(int argc, char **argv, char **envp) {
	(void)envp;
	const char *argv0 = (argc > 0 && argv && argv[0]) ? argv[0] : "nproc";
	if (argc > 1) {
		mc_die_usage(argv0, "nproc");
	}

	mc_u8 mask[128];
	for (mc_usize i = 0; i < sizeof(mask); i++) mask[i] = 0;

	mc_i64 r = mc_sys_sched_getaffinity(0, (mc_usize)sizeof(mask), mask);
	if (r < 0) mc_die_errno(argv0, "sched_getaffinity", r);

	int n = 0;
	for (mc_usize i = 0; i < sizeof(mask); i++) {
		n += mc_popcount_u8(mask[i]);
	}
	if (n <= 0) n = 1;

	mc_i64 w = mc_write_i64_dec(1, (mc_i64)n);
	if (w < 0) mc_die_errno(argv0, "write", w);
	w = mc_write_all(1, "\n", 1);
	if (w < 0) mc_die_errno(argv0, "write", w);
	return 0;
}
