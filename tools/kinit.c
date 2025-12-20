#include "mc.h"

// Tiny kernel bring-up init.
// Designed for the monacc kernel: only relies on write(1) and execve/exit.

__attribute__((used)) int main(int argc, char **argv, char **envp) {
	(void)argc;
	(void)argv;
	(void)envp;

	(void)mc_write_str(1, "[kinit] execve(/bin/ls -R /)\\n");
	char *a[] = { (char *)"/bin/ls", (char *)"-R", (char *)"/", 0 };
	char *e[] = { (char *)"PATH=/bin", 0 };
	mc_i64 r = mc_sys_execve("/bin/ls", a, e);
	(void)mc_write_str(1, "[kinit] execve failed: ");
	(void)mc_write_i64_dec(1, r);
	(void)mc_write_str(1, "\\n");
	mc_exit(111);
}
