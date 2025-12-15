#include "mc.h"

static int parse_meminfo_u64(const char *buf, const char *key, mc_u64 *out) {
	// Match lines like: "Key: <num> kB"
	if (!buf || !key || !out) return 0;
	mc_usize klen = mc_strlen(key);
	for (const char *p = buf; *p;) {
		const char *line = p;
		while (*p && *p != '\n') p++;
		mc_usize linelen = (mc_usize)(p - line);
		if (*p == '\n') p++;

		if (linelen < klen) continue;
		int ok = 1;
		for (mc_usize i = 0; i < klen; i++) {
			if (line[i] != key[i]) {
				ok = 0;
				break;
			}
		}
		if (!ok) continue;

		const char *q = line + klen;
		while (*q && (*q == ' ' || *q == '\t')) q++;
		mc_u64 v = 0;
		const char *r = q;
		if (mc_parse_u64_dec_prefix(&r, &v) != 0) continue;
		*out = v;
		return 1;
	}
	return 0;
}

__attribute__((used)) int main(int argc, char **argv, char **envp) {
	(void)envp;
	const char *argv0 = (argc > 0 && argv && argv[0]) ? argv[0] : "free";

	int i = 1;
	for (; i < argc; i++) {
		const char *a = argv[i];
		if (!a) break;
		if (mc_streq(a, "--")) {
			i++;
			break;
		}
		if (a[0] == '-') mc_die_usage(argv0, "free");
		break;
	}
	if (i != argc) mc_die_usage(argv0, "free");

	mc_i64 fd = mc_sys_openat(MC_AT_FDCWD, "/proc/meminfo", MC_O_RDONLY | MC_O_CLOEXEC, 0);
	if (fd < 0) mc_die_errno(argv0, "/proc/meminfo", fd);

	char buf[32768];
	mc_i64 n = mc_sys_read((mc_i32)fd, buf, sizeof(buf) - 1);
	(void)mc_sys_close((mc_i32)fd);
	if (n < 0) mc_die_errno(argv0, "read", n);
	buf[(mc_usize)n] = 0;

	mc_u64 mem_total = 0, mem_free = 0, mem_avail = 0, buffers = 0, cached = 0;
	mc_u64 swap_total = 0, swap_free = 0;
	(void)parse_meminfo_u64(buf, "MemTotal:", &mem_total);
	(void)parse_meminfo_u64(buf, "MemFree:", &mem_free);
	(void)parse_meminfo_u64(buf, "MemAvailable:", &mem_avail);
	(void)parse_meminfo_u64(buf, "Buffers:", &buffers);
	(void)parse_meminfo_u64(buf, "Cached:", &cached);
	(void)parse_meminfo_u64(buf, "SwapTotal:", &swap_total);
	(void)parse_meminfo_u64(buf, "SwapFree:", &swap_free);

	(void)mc_write_str(1, "mem\t");
	(void)mc_write_u64_dec(1, mem_total);
	(void)mc_write_all(1, "\t", 1);
	(void)mc_write_u64_dec(1, mem_free);
	(void)mc_write_all(1, "\t", 1);
	(void)mc_write_u64_dec(1, mem_avail);
	(void)mc_write_all(1, "\t", 1);
	(void)mc_write_u64_dec(1, buffers);
	(void)mc_write_all(1, "\t", 1);
	(void)mc_write_u64_dec(1, cached);
	(void)mc_write_all(1, "\n", 1);

	(void)mc_write_str(1, "swap\t");
	(void)mc_write_u64_dec(1, swap_total);
	(void)mc_write_all(1, "\t", 1);
	(void)mc_write_u64_dec(1, swap_free);
	(void)mc_write_all(1, "\n", 1);

	return 0;
}
