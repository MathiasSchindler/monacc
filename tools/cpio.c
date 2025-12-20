#include "mc.h"

// Minimal cpio (newc) tool.
// Supported:
//   cpio -t [FILE]    # list
//   cpio -i [FILE]    # extract into cwd
//   cpio -o           # create newc from newline-separated file list on stdin
//
// Notes:
// - Extract supports directories + regular files.
// - Create supports directories + regular files.
// - Ignores symlinks/devices/mtimes beyond encoding.

#define CPIO_HDR_LEN 110u

static int is_hex(mc_u8 c) {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

static int hex_val(mc_u8 c) {
	if (c >= '0' && c <= '9') return (int)(c - '0');
	if (c >= 'a' && c <= 'f') return 10 + (int)(c - 'a');
	if (c >= 'A' && c <= 'F') return 10 + (int)(c - 'A');
	return -1;
}

static int parse_hex_u32_n(const mc_u8 *s, mc_usize n, mc_u32 *out) {
	mc_u32 v = 0;
	for (mc_usize i = 0; i < n; i++) {
		if (!is_hex(s[i])) return -1;
		int hv = hex_val(s[i]);
		if (hv < 0) return -1;
		v = (v << 4) | (mc_u32)hv;
	}
	*out = v;
	return 0;
}

static int parse_hex_u64_n(const mc_u8 *s, mc_usize n, mc_u64 *out) {
	mc_u64 v = 0;
	for (mc_usize i = 0; i < n; i++) {
		if (!is_hex(s[i])) return -1;
		int hv = hex_val(s[i]);
		if (hv < 0) return -1;
		v = (v << 4) | (mc_u64)hv;
	}
	*out = v;
	return 0;
}

static mc_u32 pad4(mc_u32 n) {
	return (4u - (n & 3u)) & 3u;
}

static void read_exact(const char *argv0, mc_i32 fd, void *buf, mc_usize n) {
	mc_u8 *p = (mc_u8 *)buf;
	mc_usize left = n;
	while (left) {
		mc_i64 r = mc_sys_read(fd, p, left);
		if (r < 0) mc_die_errno(argv0, "read", r);
		if (r == 0) mc_die_errno(argv0, "unexpected EOF", (mc_i64)-MC_EINVAL);
		p += (mc_usize)r;
		left -= (mc_usize)r;
	}
}

static void write_exact(const char *argv0, mc_i32 fd, const void *buf, mc_usize n) {
	mc_i64 w = mc_write_all(fd, buf, n);
	if (w < 0) mc_die_errno(argv0, "write", w);
}

static void discard_exact(const char *argv0, mc_i32 fd, mc_u64 n) {
	mc_u8 buf[4096];
	mc_u64 left = n;
	while (left) {
		mc_usize want = (left > (mc_u64)sizeof(buf)) ? (mc_usize)sizeof(buf) : (mc_usize)left;
		mc_i64 r = mc_sys_read(fd, buf, want);
		if (r < 0) mc_die_errno(argv0, "read", r);
		if (r == 0) mc_die_errno(argv0, "unexpected EOF", (mc_i64)-MC_EINVAL);
		left -= (mc_u64)r;
	}
}

static int is_safe_path(const char *p) {
	if (!p || p[0] == 0) return 0;
	if (p[0] == '/') return 0;
	// Disallow .. components.
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

static const char *store_path(const char *p) {
	while (p[0] == '.' && p[1] == '/') p += 2;
	while (p[0] == '/') p++;
	return p;
}

static void mkdirs(const char *argv0, const char *path) {
	char tmp[4096];
	mc_usize len = mc_strlen(path);
	if (len >= sizeof(tmp)) mc_die_errno(argv0, "path too long", (mc_i64)-MC_EINVAL);
	for (mc_usize i = 0; i <= len; i++) tmp[i] = path[i];
	for (mc_usize i = 1; i < len; i++) {
		if (tmp[i] == '/') {
			tmp[i] = 0;
			mc_i64 r = mc_sys_mkdirat(MC_AT_FDCWD, tmp, 0777);
			if (r < 0 && (mc_u64)(-r) != (mc_u64)MC_EEXIST) mc_die_errno(argv0, "mkdir", r);
			tmp[i] = '/';
		}
	}
}

struct cpio_newc {
	mc_u32 mode;
	mc_u32 uid;
	mc_u32 gid;
	mc_u32 nlink;
	mc_u32 mtime;
	mc_u64 filesize;
	mc_u32 namesize;
};

static void read_newc_header(const char *argv0, mc_i32 fd, struct cpio_newc *h) {
	mc_u8 hdr[CPIO_HDR_LEN];
	read_exact(argv0, fd, hdr, sizeof(hdr));
	// magic
	if (!(hdr[0] == '0' && hdr[1] == '7' && hdr[2] == '0' && hdr[3] == '7' && hdr[4] == '0' && hdr[5] == '1')) {
		mc_die_errno(argv0, "cpio: bad magic", (mc_i64)-MC_EINVAL);
	}
	// Parse fields (ASCII hex)
	(void)parse_hex_u32_n(hdr + 14, 8, &h->mode);
	(void)parse_hex_u32_n(hdr + 22, 8, &h->uid);
	(void)parse_hex_u32_n(hdr + 30, 8, &h->gid);
	(void)parse_hex_u32_n(hdr + 38, 8, &h->nlink);
	(void)parse_hex_u32_n(hdr + 46, 8, &h->mtime);
	(void)parse_hex_u64_n(hdr + 54, 8, &h->filesize);
	(void)parse_hex_u32_n(hdr + 94, 8, &h->namesize);
	// Basic validation
	if (h->namesize == 0 || h->namesize > 4096u) mc_die_errno(argv0, "cpio: bad namesize", (mc_i64)-MC_EINVAL);
}

static void list_or_extract(const char *argv0, mc_i32 fd, int do_extract) {
	for (;;) {
		struct cpio_newc h;
		read_newc_header(argv0, fd, &h);

		char name[4096];
		read_exact(argv0, fd, name, (mc_usize)h.namesize);
		name[h.namesize - 1] = 0;
		discard_exact(argv0, fd, pad4(CPIO_HDR_LEN + h.namesize));

		if (mc_streq(name, "TRAILER!!!")) break;
		const char *p = store_path(name);
		if (!is_safe_path(p)) mc_die_errno(argv0, "cpio: unsafe path", (mc_i64)-MC_EINVAL);

		if (!do_extract) {
			(void)mc_write_str(1, p);
			(void)mc_write_str(1, "\n");
			discard_exact(argv0, fd, h.filesize);
			discard_exact(argv0, fd, pad4((mc_u32)h.filesize));
			continue;
		}

		mc_u32 mode_type = h.mode & 0170000u;
		if (mode_type == 0040000u) {
			// Directory
			mkdirs(argv0, p);
			mc_i64 r = mc_sys_mkdirat(MC_AT_FDCWD, p, h.mode & 07777u);
			if (r < 0 && (mc_u64)(-r) != (mc_u64)MC_EEXIST) mc_die_errno(argv0, "mkdir", r);
			(void)mc_sys_fchmodat(MC_AT_FDCWD, p, h.mode & 07777u, 0);
			// directories have no data
			discard_exact(argv0, fd, h.filesize);
			discard_exact(argv0, fd, pad4((mc_u32)h.filesize));
			continue;
		}
		if (mode_type == 0100000u) {
			// Regular file
			mkdirs(argv0, p);
			mc_i64 out = mc_sys_openat(MC_AT_FDCWD, p, MC_O_WRONLY | MC_O_CREAT | MC_O_TRUNC | MC_O_CLOEXEC, 0666);
			if (out < 0) mc_die_errno(argv0, "open", out);
			mc_u8 buf[32768];
			mc_u64 left = h.filesize;
			while (left) {
				mc_usize want = (left > (mc_u64)sizeof(buf)) ? (mc_usize)sizeof(buf) : (mc_usize)left;
				mc_i64 rr = mc_sys_read(fd, buf, want);
				if (rr < 0) mc_die_errno(argv0, "read", rr);
				if (rr == 0) mc_die_errno(argv0, "unexpected EOF", (mc_i64)-MC_EINVAL);
				write_exact(argv0, (mc_i32)out, buf, (mc_usize)rr);
				left -= (mc_u64)rr;
			}
			(void)mc_sys_close((mc_i32)out);
			(void)mc_sys_fchmodat(MC_AT_FDCWD, p, h.mode & 07777u, 0);
			discard_exact(argv0, fd, pad4((mc_u32)h.filesize));
			continue;
		}

		// Unsupported type: skip payload.
		discard_exact(argv0, fd, h.filesize);
		discard_exact(argv0, fd, pad4((mc_u32)h.filesize));
	}
}

static void write_hex_u32_field(char *dst, mc_u32 v) {
	for (int i = 7; i >= 0; i--) {
		int d = (int)(v & 0xFu);
		dst[i] = (char)((d < 10) ? ('0' + d) : ('a' + (d - 10)));
		v >>= 4;
	}
}

static void emit_newc_header(const char *argv0, mc_i32 out_fd, const char *name, const struct mc_stat *st, mc_u32 mode, mc_u64 filesize) {
	char hdr[CPIO_HDR_LEN];
	// magic
	hdr[0] = '0'; hdr[1] = '7'; hdr[2] = '0'; hdr[3] = '7'; hdr[4] = '0'; hdr[5] = '1';
	// rest as zeros
	for (mc_usize i = 6; i < sizeof(hdr); i++) hdr[i] = '0';
	// ino
	write_hex_u32_field(hdr + 6, 0);
	write_hex_u32_field(hdr + 14, mode);
	write_hex_u32_field(hdr + 22, (mc_u32)st->st_uid);
	write_hex_u32_field(hdr + 30, (mc_u32)st->st_gid);
	write_hex_u32_field(hdr + 38, 1);
	write_hex_u32_field(hdr + 46, (mc_u32)st->st_mtime);
	write_hex_u32_field(hdr + 54, (mc_u32)filesize);
	write_hex_u32_field(hdr + 62, 0);
	write_hex_u32_field(hdr + 70, 0);
	write_hex_u32_field(hdr + 78, 0);
	write_hex_u32_field(hdr + 86, 0);
	mc_u32 namesize = (mc_u32)mc_strlen(name) + 1u;
	write_hex_u32_field(hdr + 94, namesize);
	write_hex_u32_field(hdr + 102, 0);
	write_exact(argv0, out_fd, hdr, sizeof(hdr));
	write_exact(argv0, out_fd, name, namesize);
	// pad after header+name to 4
	mc_u32 pad = pad4(CPIO_HDR_LEN + namesize);
	if (pad) {
		mc_u8 z[4] = {0, 0, 0, 0};
		write_exact(argv0, out_fd, z, pad);
	}
}

static void stream_file(const char *argv0, mc_i32 in_fd, mc_i32 out_fd, mc_u64 size) {
	mc_u8 buf[32768];
	mc_u64 left = size;
	while (left) {
		mc_usize want = (left > (mc_u64)sizeof(buf)) ? (mc_usize)sizeof(buf) : (mc_usize)left;
		mc_i64 r = mc_sys_read(in_fd, buf, want);
		if (r < 0) mc_die_errno(argv0, "read", r);
		if (r == 0) mc_die_errno(argv0, "unexpected EOF", (mc_i64)-MC_EINVAL);
		write_exact(argv0, out_fd, buf, (mc_usize)r);
		left -= (mc_u64)r;
	}
}

static void emit_pad4(const char *argv0, mc_i32 out_fd, mc_u64 n) {
	mc_u32 p = pad4((mc_u32)n);
	if (!p) return;
	mc_u8 z[4] = {0, 0, 0, 0};
	write_exact(argv0, out_fd, z, p);
}

static void create_from_stdin_list(const char *argv0) {
	// Read newline-separated paths from stdin. Keep it simple and line-buffered.
	char line[4096];
	mc_usize used = 0;
	for (;;) {
		mc_i64 r = mc_sys_read(0, line + used, sizeof(line) - used);
		if (r < 0) mc_die_errno(argv0, "read", r);
		if (r == 0) break;
		used += (mc_usize)r;
		mc_usize start = 0;
		for (mc_usize i = 0; i < used; i++) {
			if (line[i] == '\n') {
				line[i] = 0;
				const char *path0 = line + start;
				start = i + 1;
				if (path0[0] == 0) continue;
				const char *p = store_path(path0);
				if (!is_safe_path(p)) mc_die_errno(argv0, "cpio: unsafe path", (mc_i64)-MC_EINVAL);

				struct mc_stat st;
				mc_i64 sr = mc_sys_newfstatat(MC_AT_FDCWD, path0, &st, MC_AT_SYMLINK_NOFOLLOW);
				if (sr < 0) mc_die_errno(argv0, path0, sr);

				mc_u32 type = st.st_mode & MC_S_IFMT;
				if (type == MC_S_IFDIR) {
					emit_newc_header(argv0, 1, p, &st, 0040000u | (st.st_mode & 07777u), 0);
					continue;
				}
				if (type == MC_S_IFREG) {
					mc_i64 in = mc_sys_openat(MC_AT_FDCWD, path0, MC_O_RDONLY | MC_O_CLOEXEC, 0);
					if (in < 0) mc_die_errno(argv0, path0, in);
					emit_newc_header(argv0, 1, p, &st, 0100000u | (st.st_mode & 07777u), (mc_u64)st.st_size);
					stream_file(argv0, (mc_i32)in, 1, (mc_u64)st.st_size);
					(void)mc_sys_close((mc_i32)in);
					emit_pad4(argv0, 1, (mc_u64)st.st_size);
					continue;
				}
				// skip other types
			}
		}
		// move remainder
		if (start) {
			mc_usize rem = used - start;
			for (mc_usize j = 0; j < rem; j++) line[j] = line[start + j];
			used = rem;
			if (used == sizeof(line)) mc_die_errno(argv0, "cpio: line too long", (mc_i64)-MC_EINVAL);
		}
	}
	if (used) {
		// trailing line without newline
		line[used] = 0;
		const char *path0 = line;
		if (path0[0]) {
			const char *p = store_path(path0);
			if (!is_safe_path(p)) mc_die_errno(argv0, "cpio: unsafe path", (mc_i64)-MC_EINVAL);
			struct mc_stat st;
			mc_i64 sr = mc_sys_newfstatat(MC_AT_FDCWD, path0, &st, MC_AT_SYMLINK_NOFOLLOW);
			if (sr < 0) mc_die_errno(argv0, path0, sr);
			mc_u32 type = st.st_mode & MC_S_IFMT;
			if (type == MC_S_IFDIR) {
				emit_newc_header(argv0, 1, p, &st, 0040000u | (st.st_mode & 07777u), 0);
			} else if (type == MC_S_IFREG) {
				mc_i64 in = mc_sys_openat(MC_AT_FDCWD, path0, MC_O_RDONLY | MC_O_CLOEXEC, 0);
				if (in < 0) mc_die_errno(argv0, path0, in);
				emit_newc_header(argv0, 1, p, &st, 0100000u | (st.st_mode & 07777u), (mc_u64)st.st_size);
				stream_file(argv0, (mc_i32)in, 1, (mc_u64)st.st_size);
				(void)mc_sys_close((mc_i32)in);
				emit_pad4(argv0, 1, (mc_u64)st.st_size);
			}
		}
	}

	// TRAILER!!!
	struct mc_stat fake;
	mc_memset(&fake, 0, sizeof(fake));
	emit_newc_header(argv0, 1, "TRAILER!!!", &fake, 0, 0);
}

static void usage(const char *argv0) {
	mc_die_usage(argv0, "cpio -t [FILE] | cpio -i [FILE] | cpio -o");
}

__attribute__((used)) int main(int argc, char **argv, char **envp) {
	(void)envp;
	const char *argv0 = (argc > 0 && argv && argv[0]) ? argv[0] : "cpio";
	if (argc < 2) usage(argv0);
	int do_t = 0;
	int do_i = 0;
	int do_o = 0;
	const char *mode = argv[1];
	if (mc_streq(mode, "-t")) do_t = 1;
	else if (mc_streq(mode, "-i")) do_i = 1;
	else if (mc_streq(mode, "-o")) do_o = 1;
	else usage(argv0);

	if (do_o) {
		if (argc != 2) usage(argv0);
		create_from_stdin_list(argv0);
		return 0;
	}

	// list/extract
	mc_i32 fd = 0;
	if (argc == 3) {
		mc_i64 r = mc_sys_openat(MC_AT_FDCWD, argv[2], MC_O_RDONLY | MC_O_CLOEXEC, 0);
		if (r < 0) mc_die_errno(argv0, argv[2], r);
		fd = (mc_i32)r;
	} else if (argc != 2) {
		usage(argv0);
	}
	list_or_extract(argv0, fd, do_i);
	if (fd != 0) (void)mc_sys_close(fd);
	return 0;
}
