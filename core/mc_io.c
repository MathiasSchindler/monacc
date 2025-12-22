#include "mc.h"

#if MC_OS_DARWIN && !defined(__MONACC__)
#include <dirent.h>
#include <errno.h>
#include <unistd.h>
#endif

MC_NORETURN void mc_exit(mc_i32 code) {
	#if MC_OS_DARWIN
	// Hosted macOS build: use libc-provided _exit.
	// (Tools are not syscall-only on macOS.)
	_exit((int)code);
	#if defined(__MONACC__)
	for (;;) {
	}
	#else
	__builtin_unreachable();
	#endif
	#else
	(void)mc_syscall1(MC_SYS_exit_group, (mc_i64)code);
	(void)mc_syscall1(MC_SYS_exit, (mc_i64)code);
	for (;;) {
		__asm__ volatile("hlt");
	}
	#endif
}

mc_i64 mc_write_all(mc_i32 fd, const void *buf, mc_usize len) {
	const mc_u8 *p = (const mc_u8 *)buf;
	mc_usize off = 0;
	while (off < len) {
		mc_i64 r = mc_sys_write(fd, p + off, len - off);
		if (r < 0) return r;
		if (r == 0) return -1;
		off += (mc_usize)r;
	}
	return 0;
}

mc_i64 mc_write_str(mc_i32 fd, const char *s) {
	return mc_write_all(fd, s, mc_strlen(s));
}

static void mc_write_hex_nibble(mc_i32 fd, mc_u8 v) {
	char c;
	v &= 0xF;
	c = (v < 10) ? (char)('0' + v) : (char)('a' + (v - 10));
	(void)mc_write_all(fd, &c, 1);
}

void mc_write_hex_u64(mc_i32 fd, mc_u64 v) {
	(void)mc_write_str(fd, "0x");
	int started = 0;
	for (int shift = 60; shift >= 0; shift -= 4) {
		mc_u8 nib = (mc_u8)((v >> (mc_u64)shift) & 0xFULL);
		if (!started) {
			if (nib == 0 && shift != 0) continue;
			started = 1;
		}
		mc_write_hex_nibble(fd, nib);
	}
}

mc_i64 mc_write_u64_dec(mc_i32 fd, mc_u64 v) {
	char buf[32];
	mc_usize n = 0;
	if (v == 0) {
		char c = '0';
		return mc_write_all(fd, &c, 1);
	}
	while (v != 0) {
		mc_u64 q = v / 10;
		mc_u64 r = v - q * 10;
		buf[n++] = (char)('0' + (char)r);
		v = q;
	}
	for (mc_usize i = 0; i < n / 2; i++) {
		char t = buf[i];
		buf[i] = buf[n - 1 - i];
		buf[n - 1 - i] = t;
	}
	return mc_write_all(fd, buf, n);
}

mc_i64 mc_write_i64_dec(mc_i32 fd, mc_i64 v) {
	if (v < 0) {
		mc_i64 r = mc_write_all(fd, "-", 1);
		if (r < 0) return r;
		mc_u64 mag = (v == (mc_i64)0x8000000000000000ULL) ? (mc_u64)0x8000000000000000ULL : (mc_u64)(-v);
		return mc_write_u64_dec(fd, mag);
	}
	return mc_write_u64_dec(fd, (mc_u64)v);
}

mc_i64 mc_for_each_dirent(mc_i32 dirfd, mc_dirent_cb cb, void *ctx) {
	if (dirfd < 0 || !cb) return (mc_i64)-MC_EINVAL;

	#if defined(__MONACC__) && MC_OS_DARWIN
	// When compiling tools with monacc on Darwin, avoid pulling in macOS SDK
	// headers (dirent/unistd/errno). Directory iteration isn't needed for the
	// first batch of tools (true/echo), so stub it out for now.
	(void)ctx;
	return (mc_i64)-MC_ENOSYS;
	#else

	#if MC_OS_DARWIN
	// Darwin has no getdents64; iterate via fdopendir/readdir.
	// Preserve the Linux behavior of not consuming/closing the caller's fd.
	int dupfd = dup(dirfd);
	if (dupfd < 0) return (mc_i64)-(mc_i64)errno;
	DIR *d = fdopendir(dupfd);
	if (!d) {
		int e = errno;
		(void)close(dupfd);
		return (mc_i64)-(mc_i64)e;
	}
	for (;;) {
		errno = 0;
		struct dirent *ent = readdir(d);
		if (!ent) {
			int e = errno;
			(void)closedir(d);
			if (e != 0) return (mc_i64)-(mc_i64)e;
			return 0;
		}
		const char *name = ent->d_name;
		if (!mc_is_dot_or_dotdot(name)) {
			mc_u8 dt = (mc_u8)ent->d_type;
			int rc = cb(ctx, name, dt);
			if (rc != 0) {
				(void)closedir(d);
				return 0;
			}
		}
	}
	#else
	mc_u8 buf[32768];
	for (;;) {
		mc_i64 nread = mc_sys_getdents64(dirfd, buf, (mc_u32)sizeof(buf));
		if (nread < 0) return nread;
		if (nread == 0) return 0;

		mc_u32 bpos = 0;
		while (bpos < (mc_u32)nread) {
			struct mc_dirent64 *d = (struct mc_dirent64 *)(buf + bpos);
			if (d->d_reclen == 0) return (mc_i64)-MC_EINVAL;
			const char *name = d->d_name;
			if (!mc_is_dot_or_dotdot(name)) {
				int rc = cb(ctx, name, d->d_type);
				if (rc != 0) return 0;
			}
			bpos += d->d_reclen;
		}
	}
	#endif
	#endif
}


MC_NORETURN void mc_die_usage(const char *argv0, const char *usage) {
	(void)mc_write_str(2, argv0);
	(void)mc_write_str(2, ": usage: ");
	(void)mc_write_str(2, usage);
	(void)mc_write_str(2, "\n");
	mc_exit(2);
}

static void mc_write_errno_line(const char *argv0, const char *ctx, mc_i64 err_neg) {
	mc_u64 e = (err_neg < 0) ? (mc_u64)(-err_neg) : (mc_u64)err_neg;
	(void)mc_write_str(2, argv0);
	(void)mc_write_str(2, ": ");
	(void)mc_write_str(2, ctx);
	(void)mc_write_str(2, ": errno=");
	mc_write_hex_u64(2, e);
	(void)mc_write_str(2, "\n");
}

MC_NORETURN void mc_die_errno(const char *argv0, const char *ctx, mc_i64 err_neg) {
	mc_write_errno_line(argv0, ctx, err_neg);
	mc_exit(1);
}

void mc_print_errno(const char *argv0, const char *ctx, mc_i64 err_neg) {
	mc_write_errno_line(argv0, ctx, err_neg);
}

void mc_join_path_or_die(const char *argv0, const char *base, const char *name, char *out, mc_usize out_cap) {
	mc_usize blen = mc_strlen(base);
	mc_usize nlen = mc_strlen(name);
	int need_slash = 1;

	if (blen == 0 || (blen == 1 && base[0] == '.')) {
		if (nlen + 1 > out_cap) mc_die_errno(argv0, "path", (mc_i64)-MC_EINVAL);
		for (mc_usize i = 0; i < nlen; i++) out[i] = name[i];
		out[nlen] = 0;
		return;
	}
	if (blen > 0 && base[blen - 1] == '/') need_slash = 0;

	mc_usize total = blen + (need_slash ? 1u : 0u) + nlen;
	if (total + 1 > out_cap) mc_die_errno(argv0, "path", (mc_i64)-MC_EINVAL);
	for (mc_usize i = 0; i < blen; i++) out[i] = base[i];
	mc_usize off = blen;
	if (need_slash) out[off++] = '/';
	for (mc_usize i = 0; i < nlen; i++) out[off + i] = name[i];
	out[total] = 0;
}

mc_i32 mc_wait_exitcode(mc_i32 status) {
	mc_u32 u = (mc_u32)status;
	mc_u32 sig = u & 0x7Fu;
	if (sig != 0) {
		return (mc_i32)(128 + (mc_i32)sig);
	}
	return (mc_i32)((u >> 8) & 0xFFu);
}

mc_i64 mc_execvp(const char *file, char **argv, char **envp) {
	if (!file || !*file) {
		return (mc_i64)-MC_ENOENT;
	}
	if (mc_has_slash(file)) {
		return mc_sys_execve(file, argv, envp);
	}

	const char *path_env = mc_getenv_kv(envp, "PATH=");
	if (!path_env || !*path_env) {
		path_env = "/bin:/usr/bin";
	}

	char full[4096];
	mc_usize fn = mc_strlen(file);

	const char *p = path_env;
	for (;;) {
		const char *seg = p;
		while (*p && *p != ':') {
			p++;
		}
		mc_usize seglen = (mc_usize)(p - seg);

		// dir + '/' + file + '\0'
		if (seglen + 1u + fn + 1u <= (mc_usize)sizeof(full)) {
			mc_usize k = 0;
			for (; k < seglen; k++) full[k] = seg[k];
			if (k == 0) {
				full[k++] = '.';
			}
			if (full[k - 1] != '/') {
				full[k++] = '/';
			}
			for (mc_usize j = 0; j < fn; j++) full[k + j] = file[j];
			k += fn;
			full[k] = 0;

			mc_i64 r = mc_sys_execve(full, argv, envp);
			// If execve failed with ENOENT/ENOTDIR, continue searching; otherwise return.
			if (r < 0) {
				mc_u64 e = (mc_u64)(-r);
				if (e != (mc_u64)MC_ENOENT && e != (mc_u64)MC_ENOTDIR) {
					return r;
				}
			}
		}

		if (*p == ':') {
			p++;
			continue;
		}
		break;
	}

	return (mc_i64)-MC_ENOENT;
}
