#include "mc.h"

static void ignore_sigpipe_best_effort(void) {
	struct mc_sigaction sa;
	sa.sa_handler = (void (*)(int))1; // SIG_IGN
	sa.sa_flags = 0;
	sa.sa_restorer = 0;
	sa.sa_mask[0] = 0;
	(void)mc_sys_rt_sigaction(MC_SIGPIPE, &sa, 0, 8);
}

__attribute__((used)) int main(int argc, char **argv, char **envp) {
	(void)envp;
	ignore_sigpipe_best_effort();

	char buf[4096];
	mc_usize n = 0;

	int ai = 1;
	if (ai < argc && argv && argv[ai] && argv[ai][0] == '-' && argv[ai][1] == '-' && argv[ai][2] == 0) {
		ai++;
	}

	if (ai >= argc) {
		buf[0] = 'y';
		n = 1;
	} else {
		for (int i = ai; i < argc; i++) {
			const char *s = argv[i] ? argv[i] : "";
			if (i != ai) {
				if (n + 1 >= sizeof(buf)) {
					return 2;
				}
				buf[n++] = ' ';
			}
			for (const char *p = s; *p; p++) {
				if (n + 1 >= sizeof(buf)) {
					return 2;
				}
				buf[n++] = *p;
			}
		}
	}

	if (n + 1 > sizeof(buf)) {
		return 2;
	}
	buf[n++] = '\n';

	for (;;) {
		mc_usize off = 0;
		while (off < n) {
			mc_i64 r = mc_sys_write(1, buf + off, n - off);
			if (r < 0) {
				if (r == -(mc_i64)MC_EPIPE) {
					return 0;
				}
				return 1;
			}
			if (r == 0) {
				return 0;
			}
			off += (mc_usize)r;
		}
	}
}
