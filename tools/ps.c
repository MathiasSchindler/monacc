#include "mc.h"

static int ps_is_all_digits(const char *s) {
	if (!s || !*s) return 0;
	for (const char *p = s; *p; p++) {
		if (*p < '0' || *p > '9') return 0;
	}
	return 1;
}

static mc_usize ps_strnlen0(const char *s, mc_usize max) {
	mc_usize n = 0;
	while (n < max && s && s[n]) n++;
	return n;
}

static void ps_write_pid_cmd(mc_u32 pid, const char *cmd, mc_usize cmdlen) {
	(void)mc_write_u64_dec(1, (mc_u64)pid);
	(void)mc_write_all(1, " ", 1);
	(void)mc_write_all(1, cmd, cmdlen);
	(void)mc_write_all(1, "\n", 1);
}

static void ps_write_pid_ppid_state_cmd(mc_u32 pid, mc_u32 ppid, mc_u8 state, const char *cmd, mc_usize cmdlen) {
	(void)mc_write_u64_dec(1, (mc_u64)pid);
	(void)mc_write_all(1, " ", 1);
	(void)mc_write_u64_dec(1, (mc_u64)ppid);
	(void)mc_write_all(1, " ", 1);
	(void)mc_write_all(1, &state, 1);
	(void)mc_write_all(1, " ", 1);
	(void)mc_write_all(1, cmd, cmdlen);
	(void)mc_write_all(1, "\n", 1);
}

static int ps_parse_u32_dec_span(const mc_u8 *p, mc_u32 n, mc_u32 *out) {
	if (!p || n == 0) return -1;
	mc_u32 i = 0;
	while (i < n && (p[i] == ' ' || p[i] == '\t' || p[i] == '\n')) i++;
	if (i >= n) return -1;
	if (p[i] < '0' || p[i] > '9') return -1;
	mc_u64 v = 0;
	while (i < n && p[i] >= '0' && p[i] <= '9') {
		v = v * 10u + (mc_u64)(p[i] - '0');
		if (v > 0xFFFFFFFFu) return -1;
		i++;
	}
	*out = (mc_u32)v;
	return 0;
}

static void ps_parse_and_print_stat(const char *argv0, mc_i32 procfd, const char *pidname) {
	char rel[64];
	mc_usize pn = ps_strnlen0(pidname, 32);
	if (pn == 0 || pn + 5 + 1 > sizeof(rel)) {
		return;
	}
	for (mc_usize i = 0; i < pn; i++) rel[i] = pidname[i];
	rel[pn + 0] = '/';
	rel[pn + 1] = 's';
	rel[pn + 2] = 't';
	rel[pn + 3] = 'a';
	rel[pn + 4] = 't';
	rel[pn + 5] = 0;

	mc_i64 fd = mc_sys_openat(procfd, rel, MC_O_RDONLY | MC_O_CLOEXEC, 0);
	if (fd < 0) {
		return;
	}

	mc_u8 buf[1024];
	mc_i64 n = mc_sys_read((mc_i32)fd, buf, sizeof(buf) - 1);
	(void)mc_sys_close((mc_i32)fd);
	if (n <= 0) {
		return;
	}
	buf[(mc_u32)n] = 0;

	// Extract comm: second field in /proc/PID/stat, in parentheses. Use first '(' and last ')'.
	mc_u32 l = (mc_u32)n;
	mc_u32 lp = 0xFFFFFFFFu;
	mc_u32 rp = 0xFFFFFFFFu;
	for (mc_u32 i = 0; i < l; i++) {
		if (buf[i] == '(') {
			lp = i;
			break;
		}
	}
	for (mc_u32 i = l; i > 0; i--) {
		if (buf[i - 1] == ')') {
			rp = i - 1;
			break;
		}
	}
	if (lp == 0xFFFFFFFFu || rp == 0xFFFFFFFFu || rp <= lp + 1) {
		return;
	}

	// pid from directory name
	mc_u32 pid = 0;
	if (mc_parse_u32_dec(pidname, &pid) != 0) {
		return;
	}

	// state + ppid: after ") ", then "<state> <ppid>"
	if (rp + 3u >= l) {
		return;
	}
	if (buf[rp + 1] != ' ') {
		return;
	}
	mc_u8 state = buf[rp + 2];
	mc_u32 ppid = 0;
	if (ps_parse_u32_dec_span(buf + rp + 3u, l - (rp + 3u), &ppid) != 0) {
		return;
	}

	const char *cmd = (const char *)&buf[lp + 1];
	mc_usize cmdlen = (mc_usize)(rp - (lp + 1));
	ps_write_pid_ppid_state_cmd(pid, ppid, state, cmd, cmdlen);
	(void)argv0;
}

__attribute__((used)) int main(int argc, char **argv, char **envp) {
	(void)envp;
	const char *argv0 = (argc > 0 && argv && argv[0]) ? argv[0] : "ps";

	int i = 1;
	for (; i < argc; i++) {
		const char *a = argv[i];
		if (!a || a[0] != '-' || mc_streq(a, "-")) break;
		if (mc_streq(a, "--")) {
			i++;
			break;
		}
		mc_die_usage(argv0, "ps");
	}
	if (i != argc) {
		mc_die_usage(argv0, "ps");
	}

	mc_i64 procfd = mc_sys_openat(MC_AT_FDCWD, "/proc", MC_O_RDONLY | MC_O_CLOEXEC | MC_O_DIRECTORY, 0);
	if (procfd < 0) {
		mc_die_errno(argv0, "/proc", procfd);
	}

	(void)mc_write_all(1, "PID PPID S CMD\n", 15);

	mc_u8 d_buf[32768];
	for (;;) {
		mc_i64 nread = mc_sys_getdents64((mc_i32)procfd, d_buf, (mc_u32)sizeof(d_buf));
		if (nread < 0) {
			mc_die_errno(argv0, "getdents64", nread);
		}
		if (nread == 0) break;

		mc_u32 bpos = 0;
		while (bpos < (mc_u32)nread) {
			struct mc_dirent64 *d = (struct mc_dirent64 *)(d_buf + bpos);
			const char *name = d->d_name;
			if (ps_is_all_digits(name)) {
				ps_parse_and_print_stat(argv0, (mc_i32)procfd, name);
			}
			bpos += d->d_reclen;
		}
	}

	(void)mc_sys_close((mc_i32)procfd);
	return 0;
}
