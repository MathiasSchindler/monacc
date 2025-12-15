#include "mc.h"

static void mv_unlink_dest_if_exists(const char *argv0, const char *dst) {
	mc_i64 r = mc_sys_unlinkat(MC_AT_FDCWD, dst, 0);
	if (r < 0 && (mc_u64)(-r) != (mc_u64)MC_ENOENT) {
		// If DST is a directory, unlinkat returns -EISDIR, matching rename's failure.
		mc_die_errno(argv0, "unlink dst", r);
	}
}

static void mv_copy_regular_file(const char *argv0, const char *src, const char *dst, mc_u32 mode0777) {
	mc_i64 sfd = mc_sys_openat(MC_AT_FDCWD, src, MC_O_RDONLY | MC_O_CLOEXEC, 0);
	if (sfd < 0) mc_die_errno(argv0, src, sfd);

	mc_i64 dfd = mc_sys_openat(MC_AT_FDCWD, dst, MC_O_WRONLY | MC_O_CREAT | MC_O_TRUNC | MC_O_CLOEXEC, mode0777);
	if (dfd < 0) {
		(void)mc_sys_close((mc_i32)sfd);
		mc_die_errno(argv0, dst, dfd);
	}

	mc_u8 buf[32768];
	for (;;) {
		mc_i64 r = mc_sys_read((mc_i32)sfd, buf, (mc_usize)sizeof(buf));
		if (r < 0) {
			(void)mc_sys_close((mc_i32)dfd);
			(void)mc_sys_close((mc_i32)sfd);
			mc_die_errno(argv0, "read", r);
		}
		if (r == 0) break;
		mc_i64 w = mc_write_all((mc_i32)dfd, buf, (mc_usize)r);
		if (w < 0) {
			(void)mc_sys_close((mc_i32)dfd);
			(void)mc_sys_close((mc_i32)sfd);
			mc_die_errno(argv0, "write", w);
		}
	}

	(void)mc_sys_close((mc_i32)dfd);
	(void)mc_sys_close((mc_i32)sfd);
}

static void mv_copy_regular_file_at(const char *argv0, mc_i32 src_dirfd, const char *src_name, mc_i32 dst_dirfd, const char *dst_name, mc_u32 mode0777) {
	mc_i64 sfd = mc_sys_openat(src_dirfd, src_name, MC_O_RDONLY | MC_O_CLOEXEC, 0);
	if (sfd < 0) mc_die_errno(argv0, "open src", sfd);

	mc_i64 dfd = mc_sys_openat(dst_dirfd, dst_name, MC_O_WRONLY | MC_O_CREAT | MC_O_TRUNC | MC_O_CLOEXEC, mode0777);
	if (dfd < 0) {
		(void)mc_sys_close((mc_i32)sfd);
		mc_die_errno(argv0, "open dst", dfd);
	}

	mc_u8 buf[32768];
	for (;;) {
		mc_i64 r = mc_sys_read((mc_i32)sfd, buf, (mc_usize)sizeof(buf));
		if (r < 0) {
			(void)mc_sys_close((mc_i32)dfd);
			(void)mc_sys_close((mc_i32)sfd);
			mc_die_errno(argv0, "read", r);
		}
		if (r == 0) break;
		mc_i64 w = mc_write_all((mc_i32)dfd, buf, (mc_usize)r);
		if (w < 0) {
			(void)mc_sys_close((mc_i32)dfd);
			(void)mc_sys_close((mc_i32)sfd);
			mc_die_errno(argv0, "write", w);
		}
	}

	(void)mc_sys_close((mc_i32)dfd);
	(void)mc_sys_close((mc_i32)sfd);
}

static void mv_copy_symlink(const char *argv0, const char *src, const char *dst) {
	// Replace destination if it exists (rename semantics).
	mv_unlink_dest_if_exists(argv0, dst);

	char target[4096];
	mc_i64 n = mc_sys_readlinkat(MC_AT_FDCWD, src, target, sizeof(target) - 1);
	if (n < 0) mc_die_errno(argv0, "readlink", n);
	target[(mc_usize)n] = 0;

	mc_i64 r = mc_sys_symlinkat(target, MC_AT_FDCWD, dst);
	if (r < 0) mc_die_errno(argv0, "symlink", r);
}

static void mv_copy_symlink_at(const char *argv0, mc_i32 src_dirfd, const char *src_name, mc_i32 dst_dirfd, const char *dst_name) {
	// Replace destination if it exists (rename semantics).
	mc_i64 r = mc_sys_unlinkat(dst_dirfd, dst_name, 0);
	if (r < 0 && (mc_u64)(-r) != (mc_u64)MC_ENOENT) {
		mc_die_errno(argv0, "unlink dst", r);
	}

	char target[4096];
	mc_i64 n = mc_sys_readlinkat(src_dirfd, src_name, target, sizeof(target) - 1);
	if (n < 0) mc_die_errno(argv0, "readlink", n);
	target[(mc_usize)n] = 0;

	r = mc_sys_symlinkat(target, dst_dirfd, dst_name);
	if (r < 0) mc_die_errno(argv0, "symlink", r);
}

static void mv_copy_unlink_at_depth(const char *argv0, mc_i32 src_dirfd, const char *src_name, mc_i32 dst_dirfd, const char *dst_name, int depth);

static void mv_copy_dir_at_depth(const char *argv0, mc_i32 src_parentfd, const char *src_name, mc_i32 dst_parentfd, const char *dst_name, mc_u32 mode0777, int depth) {
	if (depth > 64) {
		mc_die_usage(argv0, "mv SRC DST");
	}

	// Create destination directory (must not exist).
	mc_i64 mr = mc_sys_mkdirat(dst_parentfd, dst_name, mode0777);
	if (mr < 0) {
		mc_die_errno(argv0, "mkdir dst", mr);
	}

	mc_i64 sfd = mc_sys_openat(src_parentfd, src_name, MC_O_RDONLY | MC_O_CLOEXEC | MC_O_DIRECTORY, 0);
	if (sfd < 0) mc_die_errno(argv0, "open src dir", sfd);

	mc_i64 dfd = mc_sys_openat(dst_parentfd, dst_name, MC_O_RDONLY | MC_O_CLOEXEC | MC_O_DIRECTORY, 0);
	if (dfd < 0) {
		(void)mc_sys_close((mc_i32)sfd);
		mc_die_errno(argv0, "open dst dir", dfd);
	}

	mc_u8 buf[32768];
	for (;;) {
		mc_i64 nread = mc_sys_getdents64((mc_i32)sfd, buf, (mc_u32)sizeof(buf));
		if (nread < 0) {
			(void)mc_sys_close((mc_i32)dfd);
			(void)mc_sys_close((mc_i32)sfd);
			mc_die_errno(argv0, "getdents64", nread);
		}
		if (nread == 0) break;
		mc_u32 bpos = 0;
		while (bpos < (mc_u32)nread) {
			struct mc_dirent64 *d = (struct mc_dirent64 *)(buf + bpos);
			const char *name = d->d_name;
			if (!mc_is_dot_or_dotdot(name)) {
				mv_copy_unlink_at_depth(argv0, (mc_i32)sfd, name, (mc_i32)dfd, name, depth + 1);
			}
			bpos += d->d_reclen;
		}
	}

	(void)mc_sys_close((mc_i32)dfd);
	(void)mc_sys_close((mc_i32)sfd);

	// Remove now-empty source directory.
	mc_i64 ur = mc_sys_unlinkat(src_parentfd, src_name, MC_AT_REMOVEDIR);
	if (ur < 0) mc_die_errno(argv0, "rmdir src", ur);
}

static void mv_copy_unlink_at_depth(const char *argv0, mc_i32 src_dirfd, const char *src_name, mc_i32 dst_dirfd, const char *dst_name, int depth) {
	struct mc_stat st;
	mc_i64 r = mc_sys_newfstatat(src_dirfd, src_name, &st, MC_AT_SYMLINK_NOFOLLOW);
	if (r < 0) mc_die_errno(argv0, "stat src", r);

	mc_u32 t = st.st_mode & MC_S_IFMT;
	if (t == MC_S_IFREG) {
		mv_copy_regular_file_at(argv0, src_dirfd, src_name, dst_dirfd, dst_name, (mc_u32)(st.st_mode & 0777u));
		r = mc_sys_unlinkat(src_dirfd, src_name, 0);
		if (r < 0) mc_die_errno(argv0, "unlink src", r);
		return;
	}
	if (t == MC_S_IFLNK) {
		mv_copy_symlink_at(argv0, src_dirfd, src_name, dst_dirfd, dst_name);
		r = mc_sys_unlinkat(src_dirfd, src_name, 0);
		if (r < 0) mc_die_errno(argv0, "unlink src", r);
		return;
	}
	if (t == MC_S_IFDIR) {
		mv_copy_dir_at_depth(argv0, src_dirfd, src_name, dst_dirfd, dst_name, (mc_u32)(st.st_mode & 0777u), depth);
		return;
	}

	mc_die_usage(argv0, "mv SRC DST");
}

static void mv_copy_unlink(const char *argv0, const char *src, const char *dst) {
	struct mc_stat st;
	mc_i64 r = mc_sys_newfstatat(MC_AT_FDCWD, src, &st, MC_AT_SYMLINK_NOFOLLOW);
	if (r < 0) mc_die_errno(argv0, src, r);

	mc_u32 t = st.st_mode & MC_S_IFMT;
	if (t == MC_S_IFREG) {
		mv_copy_regular_file(argv0, src, dst, (mc_u32)(st.st_mode & 0777u));
	} else if (t == MC_S_IFLNK) {
		mv_copy_symlink(argv0, src, dst);
	} else if (t == MC_S_IFDIR) {
		// Minimal semantics for cross-FS directory moves:
		// - only supports DST not existing
		struct mc_stat dstst;
		mc_i64 dr = mc_sys_newfstatat(MC_AT_FDCWD, dst, &dstst, MC_AT_SYMLINK_NOFOLLOW);
		if (dr >= 0) {
			mc_die_errno(argv0, "dst exists", (mc_i64)-MC_EEXIST);
		}
		if ((mc_u64)(-dr) != (mc_u64)MC_ENOENT) {
			mc_die_errno(argv0, "stat dst", dr);
		}
		mv_copy_dir_at_depth(argv0, MC_AT_FDCWD, src, MC_AT_FDCWD, dst, (mc_u32)(st.st_mode & 0777u), 0);
		return;
	} else {
		// Keep minimal: no cross-FS directory moves or special files.
		mc_die_usage(argv0, "mv SRC DST");
	}

	r = mc_sys_unlinkat(MC_AT_FDCWD, src, 0);
	if (r < 0) mc_die_errno(argv0, "unlink src", r);
}

__attribute__((used)) int main(int argc, char **argv, char **envp) {
	(void)envp;

	const char *argv0 = (argc > 0 && argv && argv[0]) ? argv[0] : "mv";

	int i = 1;
	if (i < argc && argv[i] && mc_streq(argv[i], "--")) {
		i++;
	}

	if (argc - i != 2) {
		mc_die_usage(argv0, "mv SRC DST");
	}

	const char *src = argv[i] ? argv[i] : "";
	const char *dst = argv[i + 1] ? argv[i + 1] : "";

	mc_i64 r = mc_sys_renameat(MC_AT_FDCWD, src, MC_AT_FDCWD, dst);
	if (r < 0) {
		if ((mc_u64)(-r) == (mc_u64)MC_EXDEV) {
			mv_copy_unlink(argv0, src, dst);
			return 0;
		}
		mc_die_errno(argv0, "rename", r);
	}

	return 0;
}
