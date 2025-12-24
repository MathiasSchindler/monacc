#include "kernel.h"
#include "sys.h"
#include "proc.h"
#include "fs.h"

void kmemcpy(void *dst, const void *src, size_t n) {
	uint8_t *d = (uint8_t *)dst;
	const uint8_t *s = (const uint8_t *)src;
	for (size_t i = 0; i < n; i++) d[i] = s[i];
}

void kmemset(void *dst, uint8_t v, uint64_t n) {
	uint8_t *p = (uint8_t *)dst;
	for (uint64_t i = 0; i < n; i++) p[i] = v;
}

uint64_t kstrnlen(const char *s, uint64_t maxn) {
	uint64_t n = 0;
	while (n < maxn) {
		if (s[n] == 0) return n;
		n++;
	}
	return maxn;
}

int kcopy_cstr(char *dst, uint64_t cap, const char *src) {
	if (!dst || cap == 0) return -1;
	if (!src) {
		dst[0] = 0;
		return -1;
	}
	uint64_t n = kstrnlen(src, cap - 1);
	if (n >= cap - 1) {
		dst[0] = 0;
		return -1;
	}
	for (uint64_t i = 0; i < n; i++) dst[i] = src[i];
	dst[n] = 0;
	return 0;
}

const char *skip_leading_slash(const char *s) {
	while (*s == '/') s++;
	return s;
}

const char *skip_dot_slash2(const char *s) {
	while (s && s[0] == '.' && s[1] == '/') s += 2;
	return s;
}

int is_dot(const char *s) {
	return s && s[0] == '.' && s[1] == 0;
}

int is_dotdot(const char *s) {
	return s && s[0] == '.' && s[1] == '.' && s[2] == 0;
}

void kstrcpy_cap(char *dst, uint64_t cap, const char *src) {
	if (!dst || cap == 0) return;
	uint64_t i = 0;
	for (; i + 1 < cap && src && src[i]; i++) {
		dst[i] = src[i];
	}
	dst[i] = 0;
}

uint64_t align_up_u64(uint64_t v, uint64_t a) {
	return (v + (a - 1)) & ~(a - 1);
}

uint64_t align_down_u64(uint64_t v, uint64_t a) {
	return v & ~(a - 1);
}

uint64_t fnv1a64(const char *s) {
	uint64_t h = 1469598103934665603ull;
	for (uint64_t i = 0; s && s[i]; i++) {
		h ^= (uint8_t)s[i];
		h *= 1099511628211ull;
	}
	return h;
}

void kstat_clear(struct mc_stat *st) {
	uint8_t *p = (uint8_t *)st;
	for (uint64_t i = 0; i < sizeof(*st); i++) p[i] = 0;
}

void kstat_fill(struct mc_stat *st, uint32_t mode, uint64_t size) {
	kstat_clear(st);
	st->st_mode = mode;
	st->st_nlink = 1;
	st->st_uid = 0;
	st->st_gid = 0;
	st->st_size = (int64_t)size;
	st->st_blksize = (int64_t)PAGE_SIZE;
	st->st_blocks = (int64_t)((size + 511u) / 512u);
}

int resolve_path(char *out, uint64_t cap, int dirfd, const char *pathname) {
	if (!out || cap == 0) return -1;
	out[0] = 0;
	if (!pathname) return -1;

	const char *p = pathname;
	if (p[0] == '/') {
		p = skip_leading_slash(p);
		p = skip_dot_slash2(p);
		(void)kcopy_cstr(out, cap, p);
		return 0;
	}

	const char *base = 0;
	if (dirfd == AT_FDCWD) {
		base = (g_cur ? g_cur->cwd : "");
	} else {
		struct kfile *d = kfd_get_dir(dirfd);
		if (!d) return -2;
		base = d->path;
	}
	const char *rel = skip_dot_slash2(p);
	if (is_dot(rel) || rel[0] == 0) {
		(void)kcopy_cstr(out, cap, base);
		return 0;
	}
	if (is_dotdot(rel)) {
		(void)kcopy_cstr(out, cap, "");
		return 0;
	}
	if (!base || base[0] == 0) {
		(void)kcopy_cstr(out, cap, rel);
		return 0;
	}
	char tmp[KEXEC_MAX_STR];
	(void)kcopy_cstr(tmp, sizeof(tmp), base);
	uint64_t bl = kstrnlen(tmp, sizeof(tmp));
	if (bl + 1 >= sizeof(tmp)) return -1;
	tmp[bl] = '/';
	tmp[bl + 1] = 0;
	char relbuf[KEXEC_MAX_STR];
	if (kcopy_cstr(relbuf, sizeof(relbuf), rel) != 0) return -1;
	uint64_t rl = kstrnlen(relbuf, sizeof(relbuf));
	if (bl + 1 + rl + 1 > sizeof(tmp)) return -1;
	for (uint64_t i = 0; i <= rl; i++) tmp[bl + 1 + i] = relbuf[i];
	(void)kcopy_cstr(out, cap, tmp);
	return 0;
}

uint64_t user_stack_push_bytes(uint64_t sp, const void *data, uint64_t n) {
	sp -= n;
	kmemcpy((void *)sp, data, (size_t)n);
	return sp;
}

uint64_t user_stack_push_u64(uint64_t sp, uint64_t v) {
	return user_stack_push_bytes(sp, &v, 8);
}

void serial_write_u64_dec(uint64_t v) {
	char buf[32];
	int i = 0;
	if (v == 0) {
		serial_putc('0');
		return;
	}
	while (v > 0 && i < (int)sizeof(buf)) {
		buf[i++] = (char)('0' + (v % 10));
		v /= 10;
	}
	while (i--) serial_putc(buf[i]);
}

void serial_write_hex(uint64_t v) {
	const char *hex = "0123456789abcdef";
	char buf[16];
	int i;
	for (i = 0; i < 16; i++) {
		buf[15 - i] = hex[v & 0xf];
		v >>= 4;
	}
	/* Skip leading zeros but keep at least one digit */
	for (i = 0; i < 15 && buf[i] == '0'; i++);
	while (i < 16) serial_putc(buf[i++]);
}

void ktrace_sys(const char *name, uint64_t nr) {
	serial_write("[k] pid ");
	serial_write_u64_dec(g_cur ? (uint64_t)g_cur->pid : 0);
	serial_write(" syscall ");
	serial_write_u64_dec(nr);
	serial_write(" ");
	serial_write(name);
	serial_write(" ursp=");
	serial_write_hex(syscall_user_rsp);
	serial_write("\n");
}
