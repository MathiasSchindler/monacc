#include "mc.h"

// Minimal initramfs PID 1 for sysbox.
// Responsibilities:
// - create /proc, /sys, /dev mountpoints
// - mount devtmpfs, proc, sysfs
// - connect stdio to /dev/console
// - spawn /bin/sh in a loop

static void init_mkdir(const char *argv0, const char *path, mc_u32 mode) {
	mc_i64 r = mc_sys_mkdirat(MC_AT_FDCWD, path, mode);
	if (r < 0) {
		// Ignore EEXIST.
		if ((mc_u64)(-r) == (mc_u64)MC_EEXIST) return;
		mc_die_errno(argv0, path, r);
	}
}

static void init_try_mount(const char *argv0, const char *source, const char *target, const char *fstype) {
	mc_i64 r = mc_sys_mount(source, target, fstype, 0, 0);
	if (r < 0) {
		// For early bring-up, mount failures are fatal: without /dev/console + /proc,
		// the environment is hard to use/debug.
		mc_die_errno(argv0, "mount", r);
	}
}

static void init_stdio_to_console(const char *argv0) {
	(void)argv0;
	mc_i64 fd = mc_sys_openat(MC_AT_FDCWD, "/dev/console", MC_O_RDWR | MC_O_CLOEXEC, 0);
	if (fd < 0) {
		// Try /dev/tty0 as a fallback (may exist on some setups).
		fd = mc_sys_openat(MC_AT_FDCWD, "/dev/tty0", MC_O_RDWR | MC_O_CLOEXEC, 0);
	}
	if (fd < 0) {
		// If we can't open a console, keep going; writes may be lost, but the shell
		// might still function if the kernel wired fds.
		return;
	}

	if (fd != 0) (void)mc_sys_dup2((mc_i32)fd, 0);
	if (fd != 1) (void)mc_sys_dup2((mc_i32)fd, 1);
	if (fd != 2) (void)mc_sys_dup2((mc_i32)fd, 2);
	if (fd > 2) (void)mc_sys_close((mc_i32)fd);

	(void)mc_write_str(1, "\n[sysbox] init: console attached\n");
}

static MC_NORETURN void init_spawn_shell_loop(const char *argv0) {
	char *shell_argv[] = { (char *)"/bin/sh", 0 };
	char *shell_envp[] = { (char *)"PATH=/bin", (char *)"HOME=/", (char *)"TERM=linux", 0 };

	for (;;) {
		(void)mc_write_str(1, "[sysbox] init: starting /bin/sh\n");
		mc_i64 vr =
#ifdef MONACC
				mc_sys_fork();
#else
				mc_sys_vfork();
#endif
		if (vr < 0) {
			mc_die_errno(argv0, "vfork", vr);
		}
		if (vr == 0) {
			(void)mc_sys_execve("/bin/sh", shell_argv, shell_envp);
			// If exec fails, exit child so init can continue.
			mc_exit(127);
		}

		mc_i32 st = 0;
		mc_i64 wr = mc_sys_wait4((mc_i32)vr, &st, 0, 0);
		if (wr < 0) {
			mc_die_errno(argv0, "wait4", wr);
		}

		(void)mc_write_str(1, "[sysbox] init: /bin/sh exited; restarting\n");
	}
}

__attribute__((used)) int main(int argc, char **argv, char **envp) {
	(void)argc;
	(void)envp;
	const char *argv0 = (argv && argv[0]) ? argv[0] : "init";

	init_mkdir(argv0, "/proc", 0755);
	init_mkdir(argv0, "/sys", 0755);
	init_mkdir(argv0, "/dev", 0755);

	// Mount a minimal set of virtual filesystems.
	init_try_mount(argv0, "devtmpfs", "/dev", "devtmpfs");
	init_try_mount(argv0, "proc", "/proc", "proc");
	init_try_mount(argv0, "sysfs", "/sys", "sysfs");

	init_stdio_to_console(argv0);

	init_spawn_shell_loop(argv0);
}
