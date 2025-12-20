#include "mc.h"

// Tiny kernel bring-up init.
// Designed for the monacc kernel: only relies on write(1) and exit(60).

__attribute__((used)) int main(int argc, char **argv, char **envp) {
	(void)argc;
	(void)argv;
	(void)envp;

	(void)mc_write_str(1, "[kinit] execve(/bin/echo)\\n");
	char *a[] = { (char *)"/bin/echo", (char *)"hello-from-execve", 0 };
	char *e[] = { (char *)"PATH=/bin", 0 };
	mc_i64 r = mc_sys_execve("/bin/echo", a, e);
	(void)mc_write_str(1, "[kinit] execve failed: ");
	(void)mc_write_i64_dec(1, r);
	(void)mc_write_str(1, "\\n");
	mc_exit(111);
}
