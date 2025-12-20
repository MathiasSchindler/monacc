#include "mc.h"

// Convenience wrapper: uncpio behaves like `cpio -i`.
// Usage: uncpio [FILE]

__attribute__((used)) int main(int argc, char **argv, char **envp) {
	const char *argv0 = (argc > 0 && argv && argv[0]) ? argv[0] : "uncpio";
	if (argc > 2) mc_die_usage(argv0, "uncpio [FILE]");

	char *newargv[4];
	newargv[0] = (char *)"cpio";
	newargv[1] = (char *)"-i";
	newargv[2] = (argc == 2) ? argv[1] : MC_NULL;
	newargv[3] = MC_NULL;

	mc_i64 r = mc_execvp("cpio", newargv, envp);
	if (r < 0) mc_die_errno(argv0, "exec cpio", r);
	return 127;
}
