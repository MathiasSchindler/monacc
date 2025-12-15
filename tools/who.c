#include "mc.h"

#define WHO_UT_LINESIZE 32
#define WHO_UT_NAMESIZE 32
#define WHO_UT_HOSTSIZE 256

#define WHO_USER_PROCESS 7

struct who_exit_status {
	mc_u16 e_termination;
	mc_u16 e_exit;
};

struct who_timeval {
	mc_i64 tv_sec;
	mc_i64 tv_usec;
};

struct who_utmp {
	mc_u16 ut_type;
	mc_i32 ut_pid;
	char ut_line[WHO_UT_LINESIZE];
	char ut_id[4];
	char ut_user[WHO_UT_NAMESIZE];
	char ut_host[WHO_UT_HOSTSIZE];
	struct who_exit_status ut_exit;
	mc_i32 ut_session;
	struct who_timeval ut_tv;
	mc_i32 ut_addr_v6[4];
	char __unused[20];
};

static mc_usize who_cstrnlen(const char *s, mc_usize max) {
	mc_usize n = 0;
	while (n < max && s[n]) n++;
	return n;
}

static mc_i32 who_open_utmp(const char *argv0) {
	mc_i64 fd = mc_sys_openat(MC_AT_FDCWD, "/run/utmp", MC_O_RDONLY | MC_O_CLOEXEC, 0);
	if (fd < 0 && (mc_u64)(-fd) == (mc_u64)MC_ENOENT) {
		fd = mc_sys_openat(MC_AT_FDCWD, "/var/run/utmp", MC_O_RDONLY | MC_O_CLOEXEC, 0);
	}
	if (fd < 0) {
		mc_u64 e = (mc_u64)(-fd);
		if (e == (mc_u64)MC_ENOENT) {
			return -1; // treat as empty
		}
		mc_die_errno(argv0, "utmp", fd);
	}
	return (mc_i32)fd;
}

__attribute__((used)) int main(int argc, char **argv, char **envp) {
	(void)envp;
	const char *argv0 = (argc > 0 && argv && argv[0]) ? argv[0] : "who";

	int i = 1;
	for (; i < argc; i++) {
		const char *a = argv[i];
		if (!a || a[0] != '-' || mc_streq(a, "-")) break;
		if (mc_streq(a, "--")) {
			i++;
			break;
		}
		mc_die_usage(argv0, "who");
	}
	if (i != argc) {
		mc_die_usage(argv0, "who");
	}

	mc_i32 fd = who_open_utmp(argv0);
	if (fd < 0) {
		// No utmp present; treat as no output.
		return 0;
	}

	struct who_utmp u;
	for (;;) {
		mc_i64 r = mc_sys_read(fd, &u, (mc_usize)sizeof(u));
		if (r < 0) {
			(void)mc_sys_close(fd);
			mc_die_errno(argv0, "read", r);
		}
		if (r == 0) {
			break;
		}
		if (r != (mc_i64)sizeof(u)) {
			// Partial record; ignore tail.
			break;
		}

		if (u.ut_type != WHO_USER_PROCESS) {
			continue;
		}
		mc_usize un = who_cstrnlen(u.ut_user, WHO_UT_NAMESIZE);
		mc_usize ln = who_cstrnlen(u.ut_line, WHO_UT_LINESIZE);
		if (un == 0 || ln == 0) {
			continue;
		}

		mc_i64 w = mc_write_all(1, u.ut_user, un);
		if (w < 0) {
			(void)mc_sys_close(fd);
			mc_die_errno(argv0, "write", w);
		}
		w = mc_write_all(1, " ", 1);
		if (w < 0) {
			(void)mc_sys_close(fd);
			mc_die_errno(argv0, "write", w);
		}
		w = mc_write_all(1, u.ut_line, ln);
		if (w < 0) {
			(void)mc_sys_close(fd);
			mc_die_errno(argv0, "write", w);
		}
		w = mc_write_all(1, "\n", 1);
		if (w < 0) {
			(void)mc_sys_close(fd);
			mc_die_errno(argv0, "write", w);
		}
	}

	(void)mc_sys_close(fd);
	return 0;
}
