#include "mc.h"

#define CP_MAX_DEPTH 64

static void cp_stream(const char *argv0, mc_i32 src_fd, mc_i32 dst_fd) {
	mc_u8 buf[32768];
	for (;;) {
		mc_i64 r = mc_sys_read(src_fd, buf, (mc_usize)sizeof(buf));
		if (r < 0) {
			mc_die_errno(argv0, "read", r);
		}
		if (r == 0) {
			break;
		}
		mc_i64 w = mc_write_all(dst_fd, buf, (mc_usize)r);
		if (w < 0) {
			mc_die_errno(argv0, "write", w);
		}
	}
}

static void cp_preserve_at(const char *argv0, mc_i32 dirfd, const char *name, const struct mc_stat *st) {
	// Mode
	mc_u32 mode = (mc_u32)(st->st_mode & 07777u);
	mc_i64 r = mc_sys_fchmodat(dirfd, name, mode, 0);
	if (r < 0) {
		mc_die_errno(argv0, "chmod", r);
	}

	// Owner/group (may fail for non-root; ignore EPERM).
	r = mc_sys_fchownat(dirfd, name, st->st_uid, st->st_gid, 0);
	if (r < 0 && (mc_u64)(-r) != (mc_u64)MC_EPERM) {
		mc_die_errno(argv0, "chown", r);
	}

	// Times (best-effort; ignore EPERM).
	struct mc_timespec ts[2];
	ts[0].tv_sec = (mc_i64)st->st_atime;
	ts[0].tv_nsec = (mc_i64)st->st_atime_nsec;
	ts[1].tv_sec = (mc_i64)st->st_mtime;
	ts[1].tv_nsec = (mc_i64)st->st_mtime_nsec;
	r = mc_sys_utimensat(dirfd, name, ts, 0);
	if (r < 0 && (mc_u64)(-r) != (mc_u64)MC_EPERM) {
		mc_die_errno(argv0, "utimensat", r);
	}
}

static void cp_copy_symlink_at(const char *argv0, mc_i32 src_dirfd, const char *src_name, mc_i32 dst_dirfd, const char *dst_name, int preserve) {
	char target[4096];
	mc_i64 n = mc_sys_readlinkat(src_dirfd, src_name, target, sizeof(target) - 1);
	if (n < 0) {
		mc_die_errno(argv0, src_name, n);
	}
	target[(mc_usize)n] = 0;

	// Best-effort: overwrite existing destination.
	mc_i64 ur = mc_sys_unlinkat(dst_dirfd, dst_name, 0);
	if (ur < 0 && (mc_u64)(-ur) != (mc_u64)MC_ENOENT) {
		// If it's a directory, do not remove it.
		mc_die_errno(argv0, dst_name, ur);
	}

	mc_i64 r = mc_sys_symlinkat(target, dst_dirfd, dst_name);
	if (r < 0) {
		mc_die_errno(argv0, dst_name, r);
	}

	if (preserve) {
		// Best-effort: preserve symlink timestamps when supported.
		struct mc_stat st;
		mc_i64 sr = mc_sys_newfstatat(src_dirfd, src_name, &st, MC_AT_SYMLINK_NOFOLLOW);
		if (sr < 0) {
			return;
		}
		struct mc_timespec ts[2];
		ts[0].tv_sec = (mc_i64)st.st_atime;
		ts[0].tv_nsec = (mc_i64)st.st_atime_nsec;
		ts[1].tv_sec = (mc_i64)st.st_mtime;
		ts[1].tv_nsec = (mc_i64)st.st_mtime_nsec;
		(void)mc_sys_utimensat(dst_dirfd, dst_name, ts, MC_AT_SYMLINK_NOFOLLOW);
	}
}

static void cp_copy_file_at(const char *argv0, mc_i32 src_dirfd, const char *src_name, mc_i32 dst_dirfd, const char *dst_name, int preserve) {
	mc_i64 src_fd = mc_sys_openat(src_dirfd, src_name, MC_O_RDONLY | MC_O_CLOEXEC | MC_O_NOFOLLOW, 0);
	if (src_fd < 0) {
		if ((mc_u64)(-src_fd) == (mc_u64)MC_ELOOP) {
			cp_copy_symlink_at(argv0, src_dirfd, src_name, dst_dirfd, dst_name, preserve);
			return;
		}
		mc_die_errno(argv0, src_name, src_fd);
	}

	struct mc_stat st;
	mc_i64 sr = mc_sys_fstat((mc_i32)src_fd, &st);
	if (sr < 0) {
		(void)mc_sys_close((mc_i32)src_fd);
		mc_die_errno(argv0, "fstat", sr);
	}
	const mc_u32 type = st.st_mode & MC_S_IFMT;
	if (type != MC_S_IFREG) {
		(void)mc_sys_close((mc_i32)src_fd);
		mc_die_errno(argv0, src_name, (type == MC_S_IFDIR) ? (mc_i64)-MC_EISDIR : (mc_i64)-MC_EINVAL);
	}

	mc_i64 dst_fd = mc_sys_openat(dst_dirfd, dst_name, MC_O_WRONLY | MC_O_CREAT | MC_O_TRUNC | MC_O_CLOEXEC, 0666);
	if (dst_fd < 0) {
		(void)mc_sys_close((mc_i32)src_fd);
		mc_die_errno(argv0, dst_name, dst_fd);
	}

	cp_stream(argv0, (mc_i32)src_fd, (mc_i32)dst_fd);
	(void)mc_sys_close((mc_i32)dst_fd);
	(void)mc_sys_close((mc_i32)src_fd);

	if (preserve) {
		cp_preserve_at(argv0, dst_dirfd, dst_name, &st);
	}
}

static void cp_mkdirat_if_needed(const char *argv0, mc_i32 dirfd, const char *name) {
	mc_i64 r = mc_sys_mkdirat(dirfd, name, 0777);
	if (r >= 0) {
		return;
	}
	if ((mc_u64)(-r) == (mc_u64)MC_EEXIST) {
		// Confirm it's a directory.
		mc_i64 fd = mc_sys_openat(dirfd, name, MC_O_RDONLY | MC_O_CLOEXEC | MC_O_DIRECTORY, 0);
		if (fd < 0) {
			mc_die_errno(argv0, name, fd);
		}
		(void)mc_sys_close((mc_i32)fd);
		return;
	}
	mc_die_errno(argv0, name, r);
}

static void cp_dir_contents(const char *argv0, mc_i32 src_dirfd, mc_i32 dst_dirfd, int preserve, int depth);

static void cp_copy_entry(const char *argv0, mc_i32 src_dirfd, const char *name, mc_i32 dst_dirfd, int preserve, int depth) {
	if (mc_is_dot_or_dotdot(name)) {
		return;
	}
	if (depth > CP_MAX_DEPTH) {
		mc_die_errno(argv0, name, (mc_i64)-MC_ELOOP);
	}

	// Try to treat it as a directory without following symlinks.
	mc_i64 dfd = mc_sys_openat(src_dirfd, name, MC_O_RDONLY | MC_O_CLOEXEC | MC_O_DIRECTORY | MC_O_NOFOLLOW, 0);
	if (dfd >= 0) {
		struct mc_stat st_dir;
		mc_i64 sr = mc_sys_fstat((mc_i32)dfd, &st_dir);
		if (sr < 0) {
			(void)mc_sys_close((mc_i32)dfd);
			mc_die_errno(argv0, "fstat", sr);
		}

		cp_mkdirat_if_needed(argv0, dst_dirfd, name);
		mc_i64 out_dfd = mc_sys_openat(dst_dirfd, name, MC_O_RDONLY | MC_O_CLOEXEC | MC_O_DIRECTORY, 0);
		if (out_dfd < 0) {
			(void)mc_sys_close((mc_i32)dfd);
			mc_die_errno(argv0, name, out_dfd);
		}

		cp_dir_contents(argv0, (mc_i32)dfd, (mc_i32)out_dfd, preserve, depth + 1);
		(void)mc_sys_close((mc_i32)out_dfd);
		(void)mc_sys_close((mc_i32)dfd);

		if (preserve) {
			cp_preserve_at(argv0, dst_dirfd, name, &st_dir);
		}
		return;
	}

	// If it's a symlink, copy the link itself (never dereference).
	if ((mc_u64)(-dfd) == (mc_u64)MC_ELOOP) {
		cp_copy_symlink_at(argv0, src_dirfd, name, dst_dirfd, name, preserve);
		return;
	}

	// Not a directory: copy as a regular file.
	cp_copy_file_at(argv0, src_dirfd, name, dst_dirfd, name, preserve);
}

static void cp_dir_contents(const char *argv0, mc_i32 src_dirfd, mc_i32 dst_dirfd, int preserve, int depth) {
	if (depth > CP_MAX_DEPTH) {
		mc_die_errno(argv0, "cp: recursion too deep", (mc_i64)-MC_ELOOP);
	}
	mc_u8 buf[32768];
	for (;;) {
		mc_i64 nread = mc_sys_getdents64(src_dirfd, buf, (mc_u32)sizeof(buf));
		if (nread < 0) {
			mc_die_errno(argv0, "getdents64", nread);
		}
		if (nread == 0) {
			break;
		}

		mc_u32 bpos = 0;
		while (bpos < (mc_u32)nread) {
			struct mc_dirent64 *d = (struct mc_dirent64 *)(buf + bpos);
			cp_copy_entry(argv0, src_dirfd, d->d_name, dst_dirfd, preserve, depth);
			bpos += d->d_reclen;
		}
	}
}

__attribute__((used)) int main(int argc, char **argv, char **envp) {
	(void)envp;

	const char *argv0 = (argc > 0 && argv && argv[0]) ? argv[0] : "cp";
	int recursive = 0;
	int preserve = 0;

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
			// Combined short options: -rp
			for (mc_u32 j = 1; a[j]; j++) {
				if (a[j] == 'r') recursive = 1;
				else if (a[j] == 'R') recursive = 1;
				else if (a[j] == 'p') preserve = 1;
				else mc_die_usage(argv0, "cp [-r] [-p] [--] SRC DST");
			}
			continue;
		}
		if (mc_streq(a, "-r")) {
			recursive = 1;
			continue;
		}
		if (mc_streq(a, "-R")) {
			recursive = 1;
			continue;
		}
		if (mc_streq(a, "-p")) {
			preserve = 1;
			continue;
		}
		mc_die_usage(argv0, "cp [-r] [-p] [--] SRC DST");
	}

	if (argc - i != 2) {
		mc_die_usage(argv0, "cp [-r] [-p] [--] SRC DST");
	}

	const char *src = argv[i] ? argv[i] : "";
	const char *dst = argv[i + 1] ? argv[i + 1] : "";

	// If not recursive, keep minimal behavior: regular files only.
	if (!recursive) {
		cp_copy_file_at(argv0, MC_AT_FDCWD, src, MC_AT_FDCWD, dst, preserve);
		return 0;
	}

	// Recursive: if SRC is a directory, copy its contents into DST.
	mc_i64 src_dfd = mc_sys_openat(MC_AT_FDCWD, src, MC_O_RDONLY | MC_O_CLOEXEC | MC_O_DIRECTORY | MC_O_NOFOLLOW, 0);
	if (src_dfd < 0) {
		// Not a directory; treat as a file (or symlink) copy.
		cp_copy_file_at(argv0, MC_AT_FDCWD, src, MC_AT_FDCWD, dst, preserve);
		return 0;
	}

	struct mc_stat st_dir;
	mc_i64 sr = mc_sys_fstat((mc_i32)src_dfd, &st_dir);
	if (sr < 0) {
		(void)mc_sys_close((mc_i32)src_dfd);
		mc_die_errno(argv0, "fstat", sr);
	}

	// Create destination directory (or ensure it exists as a directory).
	cp_mkdirat_if_needed(argv0, MC_AT_FDCWD, dst);
	mc_i64 dst_dfd = mc_sys_openat(MC_AT_FDCWD, dst, MC_O_RDONLY | MC_O_CLOEXEC | MC_O_DIRECTORY, 0);
	if (dst_dfd < 0) {
		(void)mc_sys_close((mc_i32)src_dfd);
		mc_die_errno(argv0, dst, dst_dfd);
	}

	cp_dir_contents(argv0, (mc_i32)src_dfd, (mc_i32)dst_dfd, preserve, 0);
	(void)mc_sys_close((mc_i32)dst_dfd);
	(void)mc_sys_close((mc_i32)src_dfd);

	if (preserve) {
		cp_preserve_at(argv0, MC_AT_FDCWD, dst, &st_dir);
	}
	return 0;
}
