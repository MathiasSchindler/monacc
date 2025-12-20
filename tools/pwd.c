#include "mc.h"

__attribute__((used)) int main(int argc, char **argv, char **envp) {
	(void)argc;
	(void)argv;
	(void)envp;

	// Keep the implementation minimal: use the raw syscall return length and avoid
	// pulling in generic I/O/error helpers.
	char buf[65536];
	mc_i64 n = mc_sys_getcwd(buf, (mc_usize)sizeof(buf));
	if (n < 0) {
		// Keep behavior simple: nonzero exit on failure.
		(void)mc_syscall1(MC_SYS_exit_group, 1);
		for (;;) {
			__asm__ volatile("hlt");
		}
	}

	// Linux getcwd returns the number of bytes written, including the NUL.
	mc_usize len = (n > 0) ? (mc_usize)(n - 1) : 0;

	// Best-effort write loop (handles short writes).
	const mc_u8 *p = (const mc_u8 *)buf;
	mc_usize off = 0;
	while (off < len) {
		mc_i64 w = mc_sys_write(1, p + off, len - off);
		if (w <= 0) {
			(void)mc_syscall1(MC_SYS_exit_group, 1);
			for (;;) {
				__asm__ volatile("hlt");
			}
		}
		off += (mc_usize)w;
	}
	(void)mc_sys_write(1, "\n", 1);
	return 0;
}
