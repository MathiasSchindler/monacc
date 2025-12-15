#include "mc.h"

#define rm_print_err mc_print_errno


#define RM_MAX_DEPTH 64

static int rm_unlinkat_maybe(mc_i32 dirfd, const char *name, mc_i32 flags, int force, mc_i64 *out_err) {
	mc_i64 r = mc_sys_unlinkat(dirfd, name, flags);
	if (r >= 0) {
		return 0;
	}
	if (force && (mc_u64)(-r) == (mc_u64)MC_ENOENT) {
		return 0;
	}
	*out_err = r;
	return -1;
}

static int rm_dirfd_contents(const char *argv0, mc_i32 dirfd, int force, int recursive, int depth);

static int rm_entry_dirfd(const char *argv0, mc_i32 parentfd, const char *name, int force, int recursive, int depth) {
	if (depth > RM_MAX_DEPTH) {
		rm_print_err(argv0, name, (mc_i64)-MC_ELOOP);
		return -1;
	}
	// First try as a non-directory entry (regular file, symlink, etc.).
	mc_i64 err = 0;
	if (rm_unlinkat_maybe(parentfd, name, 0, force, &err) == 0) {
		return 0;
	}

	if (!recursive) {
		rm_print_err(argv0, name, err);
		return -1;
	}

	// If it might be a directory, open it with O_NOFOLLOW to avoid recursing into symlinks.
	mc_i64 cfd = mc_sys_openat(parentfd, name, MC_O_RDONLY | MC_O_CLOEXEC | MC_O_DIRECTORY | MC_O_NOFOLLOW, 0);
	if (cfd < 0) {
		if ((mc_u64)(-cfd) == (mc_u64)MC_ELOOP) {
			// It's a symlink; remove the link itself.
			mc_i64 err2 = 0;
			if (rm_unlinkat_maybe(parentfd, name, 0, force, &err2) == 0) {
				return 0;
			}
			rm_print_err(argv0, name, err2);
			return -1;
		}
		// Not a directory (or can't open it). Report the original unlink error.
		rm_print_err(argv0, name, err);
		return -1;
	}

	int any_fail = 0;
	if (rm_dirfd_contents(argv0, (mc_i32)cfd, force, recursive, depth + 1) != 0) {
		any_fail = 1;
	}
	(void)mc_sys_close((mc_i32)cfd);

	// Remove the now-empty directory entry.
	mc_i64 err3 = 0;
	if (rm_unlinkat_maybe(parentfd, name, MC_AT_REMOVEDIR, force, &err3) != 0) {
		rm_print_err(argv0, name, err3);
		any_fail = 1;
	}
	return any_fail ? -1 : 0;
}

static int rm_dirfd_contents(const char *argv0, mc_i32 dirfd, int force, int recursive, int depth) {
	mc_u8 buf[32768];
	int any_fail = 0;

	for (;;) {
		mc_i64 nread = mc_sys_getdents64(dirfd, buf, (mc_u32)sizeof(buf));
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
			if (!mc_is_dot_or_dotdot(name)) {
				if (rm_entry_dirfd(argv0, dirfd, name, force, recursive, depth) != 0) {
					any_fail = 1;
				}
			}
			bpos += d->d_reclen;
		}
	}

	return any_fail ? -1 : 0;
}

static int rm_path(const char *argv0, const char *path, int force, int recursive, int dir_ok) {
	// Fast path: try unlink first.
	mc_i64 err = 0;
	if (rm_unlinkat_maybe(MC_AT_FDCWD, path, 0, force, &err) == 0) {
		return 0;
	}

	if (!recursive && dir_ok) {
		mc_u64 e = (mc_u64)(-err);
		if (e == (mc_u64)MC_EISDIR || e == (mc_u64)MC_EPERM) {
			mc_i64 errd = 0;
			if (rm_unlinkat_maybe(MC_AT_FDCWD, path, MC_AT_REMOVEDIR, force, &errd) == 0) {
				return 0;
			}
			rm_print_err(argv0, path, errd);
			return -1;
		}
	}

	if (!recursive) {
		rm_print_err(argv0, path, err);
		return -1;
	}

	// If it might be a directory, open it with O_NOFOLLOW to avoid following symlinks.
	mc_i64 dfd = mc_sys_openat(MC_AT_FDCWD, path, MC_O_RDONLY | MC_O_CLOEXEC | MC_O_DIRECTORY | MC_O_NOFOLLOW, 0);
	if (dfd < 0) {
		if ((mc_u64)(-dfd) == (mc_u64)MC_ELOOP) {
			// It's a symlink; remove the link itself.
			mc_i64 err2 = 0;
			if (rm_unlinkat_maybe(MC_AT_FDCWD, path, 0, force, &err2) == 0) {
				return 0;
			}
			rm_print_err(argv0, path, err2);
			return -1;
		}
		// Not a directory (or can't open it). Report the original unlink error.
		rm_print_err(argv0, path, err);
		return -1;
	}

	int any_fail = 0;
	if (rm_dirfd_contents(argv0, (mc_i32)dfd, force, recursive, 0) != 0) {
		any_fail = 1;
	}
	(void)mc_sys_close((mc_i32)dfd);

	// Remove the now-empty directory.
	mc_i64 err3 = 0;
	if (rm_unlinkat_maybe(MC_AT_FDCWD, path, MC_AT_REMOVEDIR, force, &err3) != 0) {
		rm_print_err(argv0, path, err3);
		any_fail = 1;
	}
	return any_fail ? -1 : 0;
}

__attribute__((used)) int main(int argc, char **argv, char **envp) {
	(void)envp;

	const char *argv0 = (argc > 0 && argv && argv[0]) ? argv[0] : "rm";
	int force = 0;
	int recursive = 0;
	int dir_ok = 0;

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
			// Combined short options: -rf
			for (mc_u32 j = 1; a[j]; j++) {
				if (a[j] == 'f') force = 1;
				else if (a[j] == 'r') recursive = 1;
				else if (a[j] == 'd') dir_ok = 1;
				else mc_die_usage(argv0, "rm [-f] [-r] [-d] [--] FILE...");
			}
			continue;
		}
		if (mc_streq(a, "-f")) {
			force = 1;
			continue;
		}
		if (mc_streq(a, "-r")) {
			recursive = 1;
			continue;
		}
		if (mc_streq(a, "-d")) {
			dir_ok = 1;
			continue;
		}
		mc_die_usage(argv0, "rm [-f] [-r] [-d] [--] FILE...");
	}

	if (i >= argc) {
		mc_die_usage(argv0, "rm [-f] [-r] [-d] [--] FILE...");
	}

	int any_fail = 0;
	for (; i < argc; i++) {
		const char *path = argv[i] ? argv[i] : "";
		if (rm_path(argv0, path, force, recursive, dir_ok) != 0) {
			any_fail = 1;
		}
	}

	return any_fail ? 1 : 0;
}
