#include "mc.h"

static void write_perm3(mc_u32 perm) {
	char p[3];
	p[0] = (char)('0' + ((perm >> 6) & 7u));
	p[1] = (char)('0' + ((perm >> 3) & 7u));
	p[2] = (char)('0' + (perm & 7u));
	(void)mc_write_all(1, p, 3);
}

static void write_type(mc_u32 mode) {
	mc_u32 t = mode & MC_S_IFMT;
	if (t == MC_S_IFREG) {
		(void)mc_write_str(1, "reg");
		return;
	}
	if (t == MC_S_IFDIR) {
		(void)mc_write_str(1, "dir");
		return;
	}
	if (t == MC_S_IFLNK) {
		(void)mc_write_str(1, "lnk");
		return;
	}
	(void)mc_write_str(1, "other");
}

static void warn_errno(const char *argv0, const char *path, mc_i64 err_neg) {
	mc_u64 e = (err_neg < 0) ? (mc_u64)(-err_neg) : (mc_u64)err_neg;
	(void)mc_write_str(2, argv0);
	(void)mc_write_str(2, ": ");
	(void)mc_write_str(2, path);
	(void)mc_write_str(2, ": errno=");
	mc_write_hex_u64(2, e);
	(void)mc_write_str(2, "\n");
}

__attribute__((used)) int main(int argc, char **argv, char **envp) {
	(void)envp;
	const char *argv0 = (argc > 0 && argv && argv[0]) ? argv[0] : "stat";

	int nofollow = 0;
	int i = 1;
	for (; i < argc; i++) {
		const char *a = argv[i];
		if (!a) break;
		if (mc_streq(a, "--")) {
			i++;
			break;
		}
		if (a[0] != '-' || mc_streq(a, "-")) {
			break;
		}
		if (mc_streq(a, "-l")) {
			nofollow = 1;
			continue;
		}
		if (mc_streq(a, "-L")) {
			nofollow = 0;
			continue;
		}
		mc_die_usage(argv0, "stat [-l|-L] FILE...");
	}

	if (i >= argc) {
		mc_die_usage(argv0, "stat [-l|-L] FILE...");
	}

	int rc = 0;
	for (; i < argc; i++) {
		const char *path = argv[i];
		if (!path || mc_streq(path, "--")) {
			continue;
		}

		struct mc_stat st;
		// Use newfstatat to avoid blocking on special files (e.g. FIFOs) while still following symlinks.
		mc_i64 r = mc_sys_newfstatat(MC_AT_FDCWD, path, &st, nofollow ? MC_AT_SYMLINK_NOFOLLOW : 0);
		if (r < 0) {
			warn_errno(argv0, path, r);
			rc = 1;
			continue;
		}

		// Output: <path>: type=<...> perm=<...> uid=<...> gid=<...> size=<...>
		(void)mc_write_str(1, path);
		(void)mc_write_str(1, ": type=");
		write_type(st.st_mode);
		(void)mc_write_str(1, " perm=");
		write_perm3((mc_u32)(st.st_mode & 0777u));
		(void)mc_write_str(1, " uid=");
		(void)mc_write_u64_dec(1, (mc_u64)st.st_uid);
		(void)mc_write_str(1, " gid=");
		(void)mc_write_u64_dec(1, (mc_u64)st.st_gid);
		(void)mc_write_str(1, " size=");
		{
			mc_u64 sz = (st.st_size < 0) ? 0 : (mc_u64)st.st_size;
			(void)mc_write_u64_dec(1, sz);
		}
		(void)mc_write_all(1, "\n", 1);
	}

	return rc;
}
