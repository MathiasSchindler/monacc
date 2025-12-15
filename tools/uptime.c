#include "mc.h"

static mc_usize tok_len(const char *s) {
	mc_usize n = 0;
	while (s && s[n] && s[n] != ' ' && s[n] != '\t' && s[n] != '\n' && s[n] != '\r') n++;
	return n;
}

static int read_small_file(const char *argv0, const char *path, char *buf, mc_usize cap, mc_usize *out_n) {
	mc_i64 fd = mc_sys_openat(MC_AT_FDCWD, path, MC_O_RDONLY | MC_O_CLOEXEC, 0);
	if (fd < 0) {
		mc_die_errno(argv0, path, fd);
	}
	mc_i64 n = mc_sys_read((mc_i32)fd, buf, cap - 1);
	(void)mc_sys_close((mc_i32)fd);
	if (n < 0) {
		mc_die_errno(argv0, "read", n);
	}
	buf[(mc_usize)n] = 0;
	*out_n = (mc_usize)n;
	return 0;
}

__attribute__((used)) int main(int argc, char **argv, char **envp) {
	(void)envp;
	const char *argv0 = (argc > 0 && argv && argv[0]) ? argv[0] : "uptime";

	int i = 1;
	for (; i < argc; i++) {
		const char *a = argv[i];
		if (!a) break;
		if (mc_streq(a, "--")) {
			i++;
			break;
		}
		if (a[0] == '-') {
			mc_die_usage(argv0, "uptime");
		}
		break;
	}
	if (i != argc) {
		mc_die_usage(argv0, "uptime");
	}

	char up[256];
	mc_usize upn = 0;
	read_small_file(argv0, "/proc/uptime", up, sizeof(up), &upn);
	(void)upn;

	char la[256];
	mc_usize lan = 0;
	read_small_file(argv0, "/proc/loadavg", la, sizeof(la), &lan);
	(void)lan;

	// /proc/uptime: "<uptime> <idle>"
	// /proc/loadavg: "<l1> <l5> <l15> ..."
	const char *upt = up;
	mc_usize uptl = tok_len(upt);

	const char *p = la;
	const char *l1 = p;
	mc_usize l1l = tok_len(l1);
	p += l1l;
	while (*p == ' ' || *p == '\t') p++;
	const char *l5 = p;
	mc_usize l5l = tok_len(l5);
	p += l5l;
	while (*p == ' ' || *p == '\t') p++;
	const char *l15 = p;
	mc_usize l15l = tok_len(l15);

	(void)mc_write_str(1, "up ");
	(void)mc_write_all(1, upt, uptl);
	(void)mc_write_str(1, " load ");
	(void)mc_write_all(1, l1, l1l);
	(void)mc_write_all(1, " ", 1);
	(void)mc_write_all(1, l5, l5l);
	(void)mc_write_all(1, " ", 1);
	(void)mc_write_all(1, l15, l15l);
	(void)mc_write_all(1, "\n", 1);
	return 0;
}
