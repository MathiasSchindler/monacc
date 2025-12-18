#include "mc.h"

#define LS_MAX_DEPTH 64
#define LS_MAX_ENTRIES 1024u
#define LS_NAMEPOOL_CAP 32768u

static void ls_write_mode(const char *argv0, mc_u32 mode) {
	char p[10];
	p[0] = (mode & 0400u) ? 'r' : '-';
	p[1] = (mode & 0200u) ? 'w' : '-';
	p[2] = (mode & 0100u) ? 'x' : '-';
	p[3] = (mode & 0040u) ? 'r' : '-';
	p[4] = (mode & 0020u) ? 'w' : '-';
	p[5] = (mode & 0010u) ? 'x' : '-';
	p[6] = (mode & 0004u) ? 'r' : '-';
	p[7] = (mode & 0002u) ? 'w' : '-';
	p[8] = (mode & 0001u) ? 'x' : '-';
	p[9] = 0;

	char type = '?';
	mc_u32 t = mode & MC_S_IFMT;
	if (t == MC_S_IFDIR) type = 'd';
	else if (t == MC_S_IFREG) type = '-';
	else if (t == MC_S_IFLNK) type = 'l';

	if (mc_write_all(1, &type, 1) < 0 || mc_write_all(1, p, 9) < 0) {
		mc_die_errno(argv0, "write", -1);
	}
}

static void ls_write_size(const char *argv0, mc_u64 size, int human) {
	if (!human) {
		if (mc_write_u64_dec(1, size) < 0) mc_die_errno(argv0, "write", -1);
		return;
	}

	char suf = 0;
	while (size >= 1024u) {
		if (!suf) suf = 'K';
		else if (suf == 'K') suf = 'M';
		else if (suf == 'M') suf = 'G';
		else if (suf == 'G') suf = 'T';
		else break;
		size /= 1024u;
	}
	if (mc_write_u64_dec(1, size) < 0) mc_die_errno(argv0, "write", -1);
	if (suf) {
		if (mc_write_all(1, &suf, 1) < 0) mc_die_errno(argv0, "write", -1);
	}
}

static void ls_write_mtime_utc(const char *argv0, mc_i64 t) {
	if (t < 0) t = 0;
	mc_i64 days = t / 86400;
	mc_i64 secs = t - days * 86400;
	mc_i64 hour = secs / 3600;
	secs -= hour * 3600;
	mc_i64 minute = secs / 60;

	// Civil-from-days (1970-01-01 is day 0). Hinnant algorithm.
	mc_i64 z = days + 719468;
	mc_i64 era = (z >= 0 ? z : z - 146096) / 146097;
	mc_i64 doe = z - era * 146097;
	mc_i64 yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
	mc_i64 y = yoe + era * 400;
	mc_i64 doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
	mc_i64 mp = (5 * doy + 2) / 153;
	mc_i64 d = doy - (153 * mp + 2) / 5 + 1;
	mc_i64 m = mp + (mp < 10 ? 3 : -9);
	y += (m <= 2);

	char ts[16];
	if (y < 0 || y > 9999) {
		// Very unlikely for our use; fall back to raw epoch seconds.
		if (mc_write_i64_dec(1, t) < 0) mc_die_errno(argv0, "write", -1);
		return;
	}
	{
		mc_u32 yy = (mc_u32)y;
		ts[0] = (char)('0' + (yy / 1000u) % 10u);
		ts[1] = (char)('0' + (yy / 100u) % 10u);
		ts[2] = (char)('0' + (yy / 10u) % 10u);
		ts[3] = (char)('0' + (yy / 1u) % 10u);
	}
	ts[4] = '-';
	{
		mc_u32 mm = (mc_u32)m;
		ts[5] = (char)('0' + (mm / 10u) % 10u);
		ts[6] = (char)('0' + (mm / 1u) % 10u);
	}
	ts[7] = '-';
	{
		mc_u32 dd = (mc_u32)d;
		ts[8] = (char)('0' + (dd / 10u) % 10u);
		ts[9] = (char)('0' + (dd / 1u) % 10u);
	}
	ts[10] = ' ';
	{
		mc_u32 hh = (mc_u32)hour;
		ts[11] = (char)('0' + (hh / 10u) % 10u);
		ts[12] = (char)('0' + (hh / 1u) % 10u);
	}
	ts[13] = ':';
	{
		mc_u32 mi = (mc_u32)minute;
		ts[14] = (char)('0' + (mi / 10u) % 10u);
		ts[15] = (char)('0' + (mi / 1u) % 10u);
	}

	if (mc_write_all(1, ts, sizeof(ts)) < 0) mc_die_errno(argv0, "write", -1);
}

static void ls_print_long_at(const char *argv0, mc_i32 dirfd, const char *name, int human) {
	struct mc_stat st;
	mc_i64 r = mc_sys_newfstatat(dirfd, name, &st, MC_AT_SYMLINK_NOFOLLOW);
	if (r < 0) {
		mc_die_errno(argv0, name, r);
	}

	ls_write_mode(argv0, st.st_mode);
	if (mc_write_all(1, " ", 1) < 0) mc_die_errno(argv0, "write", -1);
	if (mc_write_u64_dec(1, st.st_nlink) < 0) mc_die_errno(argv0, "write", -1);
	if (mc_write_all(1, " ", 1) < 0) mc_die_errno(argv0, "write", -1);
	if (mc_write_u64_dec(1, st.st_uid) < 0) mc_die_errno(argv0, "write", -1);
	if (mc_write_all(1, " ", 1) < 0) mc_die_errno(argv0, "write", -1);
	if (mc_write_u64_dec(1, st.st_gid) < 0) mc_die_errno(argv0, "write", -1);
	if (mc_write_all(1, " ", 1) < 0) mc_die_errno(argv0, "write", -1);
	ls_write_size(argv0, (mc_u64)st.st_size, human);
	if (mc_write_all(1, " ", 1) < 0) mc_die_errno(argv0, "write", -1);
	ls_write_mtime_utc(argv0, st.st_mtime);
	if (mc_write_all(1, " ", 1) < 0) mc_die_errno(argv0, "write", -1);
	if (mc_write_all(1, name, mc_strlen(name)) < 0 || mc_write_all(1, "\n", 1) < 0) {
		mc_die_errno(argv0, "write", -1);
	}
}

static int ls_strcmp(const char *a, const char *b) {
	if (!a) a = "";
	if (!b) b = "";
	for (;;) {
		mc_u8 ac = (mc_u8)*a;
		mc_u8 bc = (mc_u8)*b;
		if (ac != bc) return (ac < bc) ? -1 : 1;
		if (ac == 0) return 0;
		a++;
		b++;
	}
}

static void ls_sort_name_offs(mc_u32 *offs, mc_u32 n, const char *pool) {
	// Insertion sort (small N, no libc).
	for (mc_u32 i = 1; i < n; i++) {
		mc_u32 key = offs[i];
		mc_u32 j = i;
		while (j > 0) {
			const char *a = pool + key;
			const char *b = pool + offs[j - 1];
			if (ls_strcmp(a, b) >= 0) break;
			offs[j] = offs[j - 1];
			j--;
		}
		offs[j] = key;
	}
}

static void ls_dir(const char *argv0, const char *path, int show_all, int long_mode, int human, int recursive, int is_first, int depth, int *any_fail) {
	if (depth > LS_MAX_DEPTH) {
		mc_print_errno(argv0, path, (mc_i64)-MC_ELOOP);
		if (any_fail) *any_fail = 1;
		return;
	}
	mc_i64 fd = mc_sys_openat(MC_AT_FDCWD, path, MC_O_RDONLY | MC_O_CLOEXEC | MC_O_DIRECTORY, 0);
	if (fd < 0) {
		// If the operand is a file, GNU ls prints it. Minimal behavior: print operand.
		// openat(O_DIRECTORY) returns -ENOTDIR in that case.
		if ((mc_u64)(-fd) == (mc_u64)MC_ENOTDIR) {
			if (long_mode) {
				ls_print_long_at(argv0, MC_AT_FDCWD, path, human);
				return;
			}
			if (mc_write_str(1, path) < 0 || mc_write_all(1, "\n", 1) < 0) mc_die_errno(argv0, "write", -1);
			return;
		}
		mc_die_errno(argv0, path, fd);
	}

	if (recursive) {
		if (!is_first) {
			if (mc_write_all(1, "\n", 1) < 0) mc_die_errno(argv0, "write", -1);
		}
		if (mc_write_str(1, path) < 0 || mc_write_all(1, ":\n", 2) < 0) mc_die_errno(argv0, "write", -1);
	}

	// Collect entries for sorted output (bounded; falls back to streaming).
	char namepool[LS_NAMEPOOL_CAP];
	mc_u32 namepool_len = 0;
	mc_u32 name_offs[LS_MAX_ENTRIES];
	mc_u32 name_n = 0;
	int too_many = 0;

	// Collect subdirectories for -R without allocating.
	char subpool[32768];
	mc_u32 subpool_len = 0;
	mc_u32 sub_offs[256];
	mc_u32 sub_n = 0;
	int warned_pool = 0;
	int streaming = 0;

	mc_u8 buf[32768];
	for (;;) {
		mc_i64 nread = mc_sys_getdents64((mc_i32)fd, buf, (mc_u32)sizeof(buf));
		if (nread < 0) {
			mc_die_errno(argv0, "getdents64", nread);
		}
		if (nread == 0) {
			break;
		}

		mc_u32 bpos = 0;
		while (bpos < (mc_u32)nread) {
			struct mc_dirent64 *d = (struct mc_dirent64 *)(buf + bpos);
			const char *name = d->d_name;
			int visible = show_all || (name[0] != '.');
			if (visible && !streaming) {
				mc_usize nlen = mc_strlen(name);
				if (name_n < LS_MAX_ENTRIES && namepool_len + (mc_u32)nlen + 1u <= (mc_u32)sizeof(namepool)) {
					name_offs[name_n++] = namepool_len;
					for (mc_usize k = 0; k < nlen; k++) {
						namepool[namepool_len + (mc_u32)k] = name[k];
					}
					namepool[namepool_len + (mc_u32)nlen] = 0;
					namepool_len += (mc_u32)nlen + 1u;
				} else {
					// Directory too large to buffer: flush what we have and fall back to streaming.
					streaming = 1;
					too_many = 1;
					for (mc_u32 pi = 0; pi < name_n; pi++) {
						const char *pname = namepool + name_offs[pi];
						if (long_mode) {
							ls_print_long_at(argv0, (mc_i32)fd, pname, human);
						} else {
							if (mc_write_all(1, pname, mc_strlen(pname)) < 0 || mc_write_all(1, "\n", 1) < 0) {
								mc_die_errno(argv0, "write", -1);
							}
						}
					}
					name_n = 0;
					namepool_len = 0;
				}
			}

			if (visible && streaming) {
				if (long_mode) {
					ls_print_long_at(argv0, (mc_i32)fd, name, human);
				} else {
					if (mc_write_all(1, name, mc_strlen(name)) < 0 || mc_write_all(1, "\n", 1) < 0) {
						mc_die_errno(argv0, "write", -1);
					}
				}
			}

			if (recursive && visible && !mc_is_dot_or_dotdot(name)) {
				struct mc_stat st;
				mc_i64 sr = mc_sys_newfstatat((mc_i32)fd, name, &st, MC_AT_SYMLINK_NOFOLLOW);
				if (sr >= 0 && ((st.st_mode & MC_S_IFMT) == MC_S_IFDIR)) {
					// Copy name into subpool for later recursion.
					mc_usize nlen = mc_strlen(name);
					if (sub_n < (mc_u32)(sizeof(sub_offs) / sizeof(sub_offs[0])) && subpool_len + (mc_u32)nlen + 1u <= (mc_u32)sizeof(subpool)) {
						sub_offs[sub_n] = subpool_len;
						for (mc_usize k = 0; k < nlen; k++) {
							subpool[subpool_len + (mc_u32)k] = name[k];
						}
						subpool[subpool_len + (mc_u32)nlen] = 0;
						subpool_len += (mc_u32)nlen + 1u;
						sub_n++;
					} else {
						if (!warned_pool) {
							(void)mc_write_str(2, argv0);
							(void)mc_write_str(2, ": warning: too many subdirectories, some not recursed\n");
							warned_pool = 1;
						}
					}
				}
			}
			bpos += d->d_reclen;
		}
	}

	if (!streaming) {
		ls_sort_name_offs(name_offs, name_n, namepool);
		// Print entries in sorted order.
		for (mc_u32 pi = 0; pi < name_n; pi++) {
			const char *name = namepool + name_offs[pi];
			if (long_mode) {
				ls_print_long_at(argv0, (mc_i32)fd, name, human);
			} else {
				if (mc_write_all(1, name, mc_strlen(name)) < 0 || mc_write_all(1, "\n", 1) < 0) {
					mc_die_errno(argv0, "write", -1);
				}
			}
		}

		// Listing is sorted. Recursion order will be sorted separately.
	}

	(void)mc_sys_close((mc_i32)fd);

	if (recursive) {
		ls_sort_name_offs(sub_offs, sub_n, subpool);
		for (mc_u32 si = 0; si < sub_n; si++) {
			const char *subname = subpool + sub_offs[si];
			char child[4096];
			mc_join_path_or_die(argv0, path, subname, child, (mc_usize)sizeof(child));
			ls_dir(argv0, child, show_all, long_mode, human, recursive, 0, depth + 1, any_fail);
		}
	}

	if (too_many) {
		(void)mc_write_str(2, argv0);
		(void)mc_write_str(2, ": warning: directory too large to sort; output may be unsorted\n");
	}
}

__attribute__((used)) int main(int argc, char **argv, char **envp) {
	(void)envp;

	const char *argv0 = (argc > 0 && argv && argv[0]) ? argv[0] : "ls";
	int show_all = 0;
	int long_mode = 0;
	int human = 0;
	int recursive = 0;

	int i = 1;
	for (; i < argc; i++) {
		const char *a = argv[i];
		if (!a || a[0] != '-' || mc_streq(a, "-")) {
			break;
		}
		if (mc_streq(a, "--")) {
			i++;
			break;
		}
		if (a[1] && a[1] != '-' && a[2]) {
			// Combined short options: -alh
			for (mc_u32 j = 1; a[j]; j++) {
				if (a[j] == 'a') show_all = 1;
				else if (a[j] == 'l') long_mode = 1;
				else if (a[j] == 'h') human = 1;
				else if (a[j] == 'R') recursive = 1;
				else mc_die_usage(argv0, "ls [-a] [-l] [-h] [-R] [DIR]");
			}
			continue;
		}
		if (mc_streq(a, "-a")) {
			show_all = 1;
			continue;
		}
		if (mc_streq(a, "-l")) {
			long_mode = 1;
			continue;
		}
		if (mc_streq(a, "-h")) {
			human = 1;
			continue;
		}
		if (mc_streq(a, "-R")) {
			recursive = 1;
			continue;
		}
		mc_die_usage(argv0, "ls [-a] [-l] [-h] [-R] [DIR]");
	}

	int remaining = argc - i;
	int any_fail = 0;
	if (remaining == 0) {
		ls_dir(argv0, ".", show_all, long_mode, human, recursive, 1, 0, &any_fail);
		return any_fail ? 1 : 0;
	}
	if (remaining == 1) {
		ls_dir(argv0, argv[i], show_all, long_mode, human, recursive, 1, 0, &any_fail);
		return any_fail ? 1 : 0;
	}

	mc_die_usage(argv0, "ls [-a] [-l] [-h] [-R] [DIR]");
}
