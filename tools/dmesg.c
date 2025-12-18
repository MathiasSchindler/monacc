#include "mc.h"

// Minimal dmesg using the syslog(2) syscall (a.k.a. klogctl).
// Linux x86_64: __NR_syslog == 103.
//
// Supported:
//   dmesg        (print kernel ring buffer)
//   dmesg -c     (print and clear)

#define MC_SYS_syslog 103

#define SYSLOG_ACTION_READ_ALL 3
#define SYSLOG_ACTION_READ_CLEAR 4
#define SYSLOG_ACTION_SIZE_BUFFER 10

static mc_i64 dmesg_syslog(mc_i32 action, char *buf, mc_i32 len) {
	return mc_syscall3(MC_SYS_syslog, (mc_i64)action, (mc_i64)buf, (mc_i64)len);
}

__attribute__((used)) int main(int argc, char **argv, char **envp) {
	(void)envp;
	const char *argv0 = (argc > 0 && argv && argv[0]) ? argv[0] : "dmesg";

	int clear = 0;
	if (argc > 1) {
		if (argc == 2 && argv[1] && mc_streq(argv[1], "-c")) {
			clear = 1;
		} else {
			mc_die_usage(argv0, "dmesg [-c]");
		}
	}

	mc_i64 sz = dmesg_syslog(SYSLOG_ACTION_SIZE_BUFFER, 0, 0);
	if (sz < 0) {
		mc_die_errno(argv0, "syslog(SIZE_BUFFER)", sz);
	}

	// Cap buffer size to keep stack usage reasonable.
	// If kernel buffer is larger, output will be truncated.
	mc_i32 cap = 256 * 1024;
	if (sz > cap) sz = cap;
	if (sz < 4096) sz = 4096;

	static char buf[256 * 1024];
	mc_i32 action = clear ? SYSLOG_ACTION_READ_CLEAR : SYSLOG_ACTION_READ_ALL;
	mc_i64 n = dmesg_syslog(action, buf, (mc_i32)sz);
	if (n < 0) {
		mc_die_errno(argv0, "syslog(READ)", n);
	}

	if (n > 0) {
		mc_i64 w = mc_write_all(1, buf, (mc_usize)n);
		if (w < 0) mc_die_errno(argv0, "write", w);
		// Ensure trailing newline.
		if (buf[n - 1] != '\n') {
			w = mc_write_all(1, "\n", 1);
			if (w < 0) mc_die_errno(argv0, "write", w);
		}
	}
	return 0;
}
