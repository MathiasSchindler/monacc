#include "mc.h"

// Minimal tar (ustar) implementation.
// Supported:
//   tar cf ARCHIVE.tar PATH...
//   tar xf ARCHIVE.tar
// Notes:
// - Uses UTC mtime, stores modes/uid/gid.
// - Handles regular files, directories, symlinks.

#define TAR_BLOCK 512u
#define TAR_MAX_PATH 4096
#define TAR_MAX_DEPTH 64

struct tar_hdr {
	char name[100];
	char mode[8];
	char uid[8];
	char gid[8];
	char size[12];
	char mtime[12];
	char chksum[8];
	char typeflag;
	char linkname[100];
	char magic[6];
	char version[2];
	char uname[32];
	char gname[32];
	char devmajor[8];
	char devminor[8];
	char prefix[155];
	char pad[12];
};

static int tar_is_zero_block(const mc_u8 *b) {
	for (mc_u32 i = 0; i < TAR_BLOCK; i++) {
		if (b[i] != 0) return 0;
	}
	return 1;
}

static void tar_write_octal(char *dst, mc_usize n, mc_u64 v) {
	// Write as zero-padded octal, NUL-terminated.
	if (n == 0) return;
	for (mc_usize i = 0; i < n; i++) dst[i] = '0';
	dst[n - 1] = 0;
	if (n < 2) return;
	for (mc_usize i = n - 2;; i--) {
		dst[i] = (char)('0' + (char)(v & 7u));
		v >>= 3;
		if (i == 0 || v == 0) break;
	}
}

static mc_u64 tar_parse_octal(const char *src, mc_usize n) {
	mc_u64 v = 0;
	for (mc_usize i = 0; i < n; i++) {
		char c = src[i];
		if (c == 0 || c == ' ') break;
		if (c < '0' || c > '7') break;
		v = (v << 3) + (mc_u64)(c - '0');
	}
	return v;
}

static void tar_zero(void *p, mc_usize n) {
	mc_u8 *b = (mc_u8 *)p;
	for (mc_usize i = 0; i < n; i++) b[i] = 0;
}

static void tar_copy_str(char *dst, mc_usize dst_n, const char *src) {
	mc_usize i = 0;
	for (; i + 1 < dst_n && src[i]; i++) dst[i] = src[i];
	if (dst_n) dst[i < dst_n ? i : (dst_n - 1)] = 0;
}

static void tar_set_name_prefix(const char *argv0, struct tar_hdr *h, const char *path) {
	// ustar supports prefix (155) + name (100) split at '/'.
	mc_usize len = mc_strlen(path);
	if (len <= sizeof(h->name)) {
		for (mc_usize i = 0; i < len; i++) h->name[i] = path[i];
		return;
	}
	// Find split point where suffix fits in name.
	mc_usize best = 0;
	for (mc_usize i = 0; i < len; i++) {
		if (path[i] == '/') {
			mc_usize suffix = len - (i + 1);
			if (suffix > 0 && suffix <= sizeof(h->name) && i <= sizeof(h->prefix)) {
				best = i;
			}
		}
	}
	if (best == 0) {
		mc_die_errno(argv0, "path too long for ustar", (mc_i64)-MC_EINVAL);
	}
	for (mc_usize i = 0; i < best; i++) h->prefix[i] = path[i];
	for (mc_usize i = best + 1; i < len; i++) h->name[i - (best + 1)] = path[i];
}

static const char *tar_store_path(const char *p) {
	// Prefer relative archive paths.
	while (p[0] == '.' && p[1] == '/') p += 2;
	while (p[0] == '/') p++;
	return p;
}

static int tar_is_safe_extract_path(const char *p) {
	// Disallow absolute paths and ".." path traversal.
	if (!p || p[0] == 0) return 0;
	if (p[0] == '/') return 0;
	// Scan path components.
	{
		mc_usize start = 0;
		for (mc_usize i = 0;; i++) {
			if (p[i] == '/' || p[i] == 0) {
				mc_usize n = i - start;
				if (n == 2 && p[start] == '.' && p[start + 1] == '.') return 0;
				if (p[i] == 0) break;
				start = i + 1;
			}
		}
	}
	return 1;
}

static void tar_write_block(const char *argv0, mc_i32 fd, const void *buf, mc_usize n) {
	mc_i64 r = mc_write_all(fd, buf, n);
	if (r < 0) mc_die_errno(argv0, "write", r);
}

static void tar_write_padding(const char *argv0, mc_i32 fd, mc_u64 size) {
	mc_u64 pad = (TAR_BLOCK - (size % TAR_BLOCK)) % TAR_BLOCK;
	if (pad == 0) return;
	mc_u8 zero[TAR_BLOCK];
	tar_zero(zero, sizeof(zero));
	tar_write_block(argv0, fd, zero, (mc_usize)pad);
}

static void tar_emit_header(const char *argv0, mc_i32 fd, const char *tar_path, const struct mc_stat *st, char typeflag, const char *linkname) {
	struct tar_hdr h;
	tar_zero(&h, sizeof(h));

	tar_set_name_prefix(argv0, &h, tar_path);

	// Numeric fields (octal)
	mc_u32 mode = (mc_u32)(st->st_mode & 07777u);
	tar_write_octal(h.mode, sizeof(h.mode), (mc_u64)mode);
	tar_write_octal(h.uid, sizeof(h.uid), (mc_u64)st->st_uid);
	tar_write_octal(h.gid, sizeof(h.gid), (mc_u64)st->st_gid);
	mc_u64 size = 0;
	if (typeflag == '0') size = (mc_u64)st->st_size;
	tar_write_octal(h.size, sizeof(h.size), size);
	tar_write_octal(h.mtime, sizeof(h.mtime), (mc_u64)st->st_mtime);

	// ustar magic
	h.magic[0] = 'u'; h.magic[1] = 's'; h.magic[2] = 't'; h.magic[3] = 'a'; h.magic[4] = 'r'; h.magic[5] = 0;
	h.version[0] = '0'; h.version[1] = '0';

	h.typeflag = typeflag;
	if (typeflag == '2' && linkname) {
		tar_copy_str(h.linkname, sizeof(h.linkname), linkname);
	}

	// checksum: sum of bytes with chksum treated as spaces.
	for (mc_usize i = 0; i < sizeof(h.chksum); i++) h.chksum[i] = ' ';
	mc_u32 sum = 0;
	{
		const mc_u8 *b = (const mc_u8 *)&h;
		for (mc_usize i = 0; i < TAR_BLOCK; i++) sum += (mc_u32)b[i];
	}
	tar_write_octal(h.chksum, sizeof(h.chksum), (mc_u64)sum);
	// tar often ends checksum with space/NUL; we already NUL-terminate.

	tar_write_block(argv0, fd, &h, TAR_BLOCK);
}

static void tar_stream_file(const char *argv0, mc_i32 in_fd, mc_i32 out_fd, mc_u64 size) {
	mc_u8 buf[32768];
	mc_u64 left = size;
	while (left) {
		mc_usize want = (left > (mc_u64)sizeof(buf)) ? (mc_usize)sizeof(buf) : (mc_usize)left;
		mc_i64 r = mc_sys_read(in_fd, buf, want);
		if (r < 0) mc_die_errno(argv0, "read", r);
		if (r == 0) mc_die_errno(argv0, "unexpected EOF", (mc_i64)-MC_EINVAL);
		mc_i64 w = mc_write_all(out_fd, buf, (mc_usize)r);
		if (w < 0) mc_die_errno(argv0, "write", w);
		left -= (mc_u64)r;
	}
}

static void tar_add_at(const char *argv0, mc_i32 ar_fd, mc_i32 dirfd, const char *name, const char *tar_path, int depth);

static void tar_add_dir_contents(const char *argv0, mc_i32 ar_fd, mc_i32 dirfd, const char *tar_prefix, int depth) {
	mc_u8 buf[32768];
	for (;;) {
		mc_i64 nread = mc_sys_getdents64(dirfd, buf, (mc_u32)sizeof(buf));
		if (nread < 0) mc_die_errno(argv0, "getdents64", nread);
		if (nread == 0) break;
		mc_u32 bpos = 0;
		while (bpos < (mc_u32)nread) {
			struct mc_dirent64 *d = (struct mc_dirent64 *)(buf + bpos);
			const char *name = d->d_name;
			if (!mc_is_dot_or_dotdot(name)) {
				char child_tar[TAR_MAX_PATH];
				// child tar path = tar_prefix + name
				mc_usize pfx_len = mc_strlen(tar_prefix);
				mc_usize nlen = mc_strlen(name);
				if (pfx_len + nlen + 2u >= sizeof(child_tar)) {
					mc_die_errno(argv0, "tar path too long", (mc_i64)-MC_EINVAL);
				}
				for (mc_usize i = 0; i < pfx_len; i++) child_tar[i] = tar_prefix[i];
				for (mc_usize i = 0; i < nlen; i++) child_tar[pfx_len + i] = name[i];
				child_tar[pfx_len + nlen] = 0;
				tar_add_at(argv0, ar_fd, dirfd, name, child_tar, depth + 1);
			}
			bpos += d->d_reclen;
		}
	}
}


static void tar_add_at(const char *argv0, mc_i32 ar_fd, mc_i32 dirfd, const char *name, const char *tar_path, int depth) {
	if (depth > TAR_MAX_DEPTH) mc_die_errno(argv0, "tar: recursion too deep", (mc_i64)-MC_ELOOP);

	// Try directory without following symlinks.
	mc_i64 dfd = mc_sys_openat(dirfd, name, MC_O_RDONLY | MC_O_CLOEXEC | MC_O_DIRECTORY | MC_O_NOFOLLOW, 0);
	if (dfd >= 0) {
		struct mc_stat st;
		mc_i64 sr = mc_sys_fstat((mc_i32)dfd, &st);
		if (sr < 0) {
			(void)mc_sys_close((mc_i32)dfd);
			mc_die_errno(argv0, "fstat", sr);
		}
		// Ensure tar directory name ends with '/'.
		char tname[TAR_MAX_PATH];
		mc_usize tlen = mc_strlen(tar_path);
		if (tlen + 2u >= sizeof(tname)) mc_die_errno(argv0, "tar path too long", (mc_i64)-MC_EINVAL);
		for (mc_usize i = 0; i < tlen; i++) tname[i] = tar_path[i];
		if (tlen == 0 || tname[tlen - 1] != '/') {
			tname[tlen++] = '/';
		}
		tname[tlen] = 0;

		tar_emit_header(argv0, ar_fd, tname, &st, '5', 0);
		tar_add_dir_contents(argv0, ar_fd, (mc_i32)dfd, tname, depth);
		(void)mc_sys_close((mc_i32)dfd);
		return;
	}

	// If it's a symlink, archive the link itself.
	if ((mc_u64)(-dfd) == (mc_u64)MC_ELOOP) {
		struct mc_stat st;
		mc_i64 sr = mc_sys_newfstatat(dirfd, name, &st, MC_AT_SYMLINK_NOFOLLOW);
		if (sr < 0) mc_die_errno(argv0, name, sr);
		char target[256];
		mc_i64 n = mc_sys_readlinkat(dirfd, name, target, sizeof(target) - 1);
		if (n < 0) mc_die_errno(argv0, name, n);
		target[(mc_usize)n] = 0;
		tar_emit_header(argv0, ar_fd, tar_path, &st, '2', target);
		return;
	}

	// Otherwise treat as regular file.
	mc_i64 fd = mc_sys_openat(dirfd, name, MC_O_RDONLY | MC_O_CLOEXEC | MC_O_NOFOLLOW, 0);
	if (fd < 0) {
		mc_die_errno(argv0, name, fd);
	}
	struct mc_stat st;
	mc_i64 sr = mc_sys_fstat((mc_i32)fd, &st);
	if (sr < 0) {
		(void)mc_sys_close((mc_i32)fd);
		mc_die_errno(argv0, "fstat", sr);
	}
	if ((st.st_mode & MC_S_IFMT) != MC_S_IFREG) {
		(void)mc_sys_close((mc_i32)fd);
		mc_die_errno(argv0, name, (mc_i64)-MC_EINVAL);
	}

	tar_emit_header(argv0, ar_fd, tar_path, &st, '0', 0);
	tar_stream_file(argv0, (mc_i32)fd, ar_fd, (mc_u64)st.st_size);
	tar_write_padding(argv0, ar_fd, (mc_u64)st.st_size);
	(void)mc_sys_close((mc_i32)fd);
}

static void tar_add_path(const char *argv0, mc_i32 ar_fd, const char *fs_path) {
	const char *tp = tar_store_path(fs_path);
	if (tp[0] == 0) return;
	tar_add_at(argv0, ar_fd, MC_AT_FDCWD, fs_path, tp, 0);
}

static void tar_mkdirs(const char *argv0, const char *path) {
	// Create parent directories for path (best effort).
	char tmp[TAR_MAX_PATH];
	mc_usize len = mc_strlen(path);
	if (len >= sizeof(tmp)) mc_die_errno(argv0, "path too long", (mc_i64)-MC_EINVAL);
	for (mc_usize i = 0; i <= len; i++) tmp[i] = path[i];

	for (mc_usize i = 1; i < len; i++) {
		if (tmp[i] == '/') {
			tmp[i] = 0;
			mc_i64 r = mc_sys_mkdirat(MC_AT_FDCWD, tmp, 0777);
			if (r < 0 && (mc_u64)(-r) != (mc_u64)MC_EEXIST) {
				mc_die_errno(argv0, "mkdir", r);
			}
			tmp[i] = '/';
		}
	}
}

static void tar_discard(const char *argv0, mc_i32 fd, mc_u64 n) {
	mc_u8 buf[32768];
	mc_u64 left = n;
	while (left) {
		mc_usize want = (left > (mc_u64)sizeof(buf)) ? (mc_usize)sizeof(buf) : (mc_usize)left;
		mc_i64 r = mc_sys_read(fd, buf, want);
		if (r < 0) mc_die_errno(argv0, "read", r);
		if (r == 0) mc_die_errno(argv0, "unexpected EOF", (mc_i64)-MC_EINVAL);
		left -= (mc_u64)r;
	}
}

static void tar_extract(const char *argv0, mc_i32 ar_fd) {
	mc_u8 blk[TAR_BLOCK];
	int saw_zero = 0;
	for (;;) {
		mc_i64 r = mc_sys_read(ar_fd, blk, sizeof(blk));
		if (r < 0) mc_die_errno(argv0, "read", r);
		if (r == 0) break;
		if (r != (mc_i64)sizeof(blk)) mc_die_errno(argv0, "short read", (mc_i64)-MC_EINVAL);

		if (tar_is_zero_block(blk)) {
			if (saw_zero) break;
			saw_zero = 1;
			continue;
		}
		saw_zero = 0;

		const struct tar_hdr *h = (const struct tar_hdr *)blk;
		mc_u64 size = tar_parse_octal(h->size, sizeof(h->size));
		mc_u64 mode = tar_parse_octal(h->mode, sizeof(h->mode));

		char path[TAR_MAX_PATH];
		mc_usize p = 0;
		if (h->prefix[0]) {
			for (mc_usize i = 0; i < sizeof(h->prefix) && h->prefix[i]; i++) {
				if (p + 1 >= sizeof(path)) mc_die_errno(argv0, "path too long", (mc_i64)-MC_EINVAL);
				path[p++] = h->prefix[i];
			}
			if (p + 1 >= sizeof(path)) mc_die_errno(argv0, "path too long", (mc_i64)-MC_EINVAL);
			path[p++] = '/';
		}
		for (mc_usize i = 0; i < sizeof(h->name) && h->name[i]; i++) {
			if (p + 1 >= sizeof(path)) mc_die_errno(argv0, "path too long", (mc_i64)-MC_EINVAL);
			path[p++] = h->name[i];
		}
		path[p] = 0;
		if (path[0] == 0) break;
		if (!tar_is_safe_extract_path(path)) {
			mc_die_errno(argv0, "unsafe tar path", (mc_i64)-MC_EINVAL);
		}

		char type = h->typeflag ? h->typeflag : '0';
		if (type == '5') {
			// Directory
			tar_mkdirs(argv0, path);
			mc_i64 mr = mc_sys_mkdirat(MC_AT_FDCWD, path, (mc_u32)(mode ? mode : 0777u));
			if (mr < 0 && (mc_u64)(-mr) != (mc_u64)MC_EEXIST) mc_die_errno(argv0, "mkdir", mr);
			(void)mc_sys_fchmodat(MC_AT_FDCWD, path, (mc_u32)(mode ? mode : 0777u), 0);
			// No payload
		} else if (type == '2') {
			// Symlink
			tar_mkdirs(argv0, path);
			// Best-effort: overwrite existing
			mc_i64 ur = mc_sys_unlinkat(MC_AT_FDCWD, path, 0);
			if (ur < 0 && (mc_u64)(-ur) != (mc_u64)MC_ENOENT) {
				// Might be a directory; ignore and attempt anyway.
			}
			char target[101];
			mc_usize tn = 0;
			for (; tn < 100 && h->linkname[tn]; tn++) target[tn] = h->linkname[tn];
			target[tn] = 0;
			mc_i64 sr = mc_sys_symlinkat(target, MC_AT_FDCWD, path);
			if (sr < 0) mc_die_errno(argv0, "symlink", sr);
			// No payload
		} else {
			// Regular file
			tar_mkdirs(argv0, path);
			mc_i64 fd = mc_sys_openat(MC_AT_FDCWD, path, MC_O_WRONLY | MC_O_CREAT | MC_O_TRUNC | MC_O_CLOEXEC, 0666);
			if (fd < 0) mc_die_errno(argv0, "open", fd);
			tar_stream_file(argv0, ar_fd, (mc_i32)fd, size);
			(void)mc_sys_close((mc_i32)fd);
			(void)mc_sys_fchmodat(MC_AT_FDCWD, path, (mc_u32)(mode ? mode : 0666u), 0);
			// Skip padding
			mc_u64 pad = (TAR_BLOCK - (size % TAR_BLOCK)) % TAR_BLOCK;
			if (pad) tar_discard(argv0, ar_fd, pad);
			continue;
		}

		// For non-regular entries, discard any payload+padding (should be 0)
		if (size) {
			tar_discard(argv0, ar_fd, size);
		}
		mc_u64 pad = (TAR_BLOCK - (size % TAR_BLOCK)) % TAR_BLOCK;
		if (pad) tar_discard(argv0, ar_fd, pad);
	}
}

static void tar_usage(const char *argv0) {
	mc_die_usage(argv0, "tar cf ARCHIVE.tar PATH... | tar xf ARCHIVE.tar");
}

__attribute__((used)) int main(int argc, char **argv, char **envp) {
	(void)envp;
	const char *argv0 = (argc > 0 && argv && argv[0]) ? argv[0] : "tar";
	if (argc < 3) tar_usage(argv0);

	const char *flags = argv[1];
	int create = 0;
	int extract = 0;
	int have_f = 0;
	for (mc_usize i = 0; flags[i]; i++) {
		char c = flags[i];
		if (c == 'c') create = 1;
		else if (c == 'x') extract = 1;
		else if (c == 'f') have_f = 1;
		else if (c == 't') { /* ignore for now */ }
		else {
			// Ignore unknown flags for now.
		}
	}
	if ((create && extract) || (!create && !extract) || !have_f) {
		tar_usage(argv0);
	}

	const char *archive = argv[2];
	mc_i64 ar_fd;
	if (create) {
		ar_fd = mc_sys_openat(MC_AT_FDCWD, archive, MC_O_WRONLY | MC_O_CREAT | MC_O_TRUNC | MC_O_CLOEXEC, 0666);
		if (ar_fd < 0) mc_die_errno(argv0, archive, ar_fd);
		for (int i = 3; i < argc; i++) {
			const char *p = argv[i];
			if (!p) continue;
			tar_add_path(argv0, (mc_i32)ar_fd, p);
		}
		// Two zero blocks
		mc_u8 zero[TAR_BLOCK];
		tar_zero(zero, sizeof(zero));
		tar_write_block(argv0, (mc_i32)ar_fd, zero, sizeof(zero));
		tar_write_block(argv0, (mc_i32)ar_fd, zero, sizeof(zero));
		(void)mc_sys_close((mc_i32)ar_fd);
		return 0;
	}

	ar_fd = mc_sys_openat(MC_AT_FDCWD, archive, MC_O_RDONLY | MC_O_CLOEXEC, 0);
	if (ar_fd < 0) mc_die_errno(argv0, archive, ar_fd);
	tar_extract(argv0, (mc_i32)ar_fd);
	(void)mc_sys_close((mc_i32)ar_fd);
	return 0;
}
