#include "mc.h"

__attribute__((used)) int main(int argc, char **argv, char **envp) {
	(void)envp;
	const char *argv0 = (argc > 0 && argv && argv[0]) ? argv[0] : "clear";
	if (argc > 1) {
		mc_die_usage(argv0, "clear");
	}
	// ANSI clear screen + home cursor.
	const char *seq = "\033[H\033[2J";
	mc_i64 r = mc_write_all(1, seq, 7);
	if (r < 0) mc_die_errno(argv0, "write", r);
	return 0;
}
