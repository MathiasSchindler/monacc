#include "kernel.h"

#define KEXEC_MAX_ARGS 16
#define KEXEC_MAX_STR  256

/* Userland tools (e.g. ls) use large on-stack buffers; 8 pages is too small. */
#define USER_STACK_PAGES 256

#ifndef KDEBUG_SYSCALLS
#define KDEBUG_SYSCALLS 0
#endif

void serial_init(void);
void serial_write(const char *s);
void gdt_tss_init(void);
void tss_load(void);
void idt_init(void);
void syscall_init(void);

/* From arch/syscall_entry.S: used to override the user RSP for execve(). */
extern uint64_t syscall_user_rsp;

/* Get user program address from linker symbol via function pointer trick.
 * This avoids monacc issues with extern array declarations. */
void userprog_start_func(void);
void userprog_end_func(void);

/* Embedded monacc-built ELF tools (from user/*.S incbin). */
void user_elf_echo_start(void);
void user_elf_echo_end(void);

struct regs {
	uint64_t r15;
	uint64_t r14;
	uint64_t r13;
	uint64_t r12;
	uint64_t r11;
	uint64_t r10;
	uint64_t r9;
	uint64_t r8;
	uint64_t rdi;
	uint64_t rsi;
	uint64_t rbp;
	uint64_t rbx;
	uint64_t rdx;
	uint64_t rcx;
	uint64_t rax;
};

static void kmemcpy(void *dst, const void *src, size_t n) {
	uint8_t *d = (uint8_t *)dst;
	const uint8_t *s = (const uint8_t *)src;
	for (size_t i = 0; i < n; i++) d[i] = s[i];
}

static uint64_t kstrnlen(const char *s, uint64_t maxn) {
	uint64_t n = 0;
	while (n < maxn) {
		if (s[n] == 0) return n;
		n++;
	}
	return maxn;
}

static int kcopy_cstr(char *dst, uint64_t cap, const char *src) {
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

static const char *skip_leading_slash(const char *s) {
	while (*s == '/') s++;
	return s;
}

/* initramfs module cached for syscalls like execve(). */
static const uint8_t *g_initramfs = 0;
static uint64_t g_initramfs_sz = 0;
/* Very small initramfs-backed FD table.
 * Kernel reserves 0,1,2 for stdin/stdout/stderr.
 */
#define KFD_MAX 32

enum kfd_kind {
	KFD_KIND_NONE = 0,
	KFD_KIND_FILE = 1,
	KFD_KIND_DIR  = 2,
};

struct kfd_file {
	uint8_t used;
	uint8_t writable;
	uint8_t kind;
	uint8_t dir_emit; /* 0: '.', 1: '..', 2+: cpio children */
	const uint8_t *data;
	uint64_t size;
	uint64_t off;
	uint32_t mode;
	uint32_t _pad2;
	char path[KEXEC_MAX_STR];
	uint64_t scan_off;
	uint64_t dir_off;
};

static struct kfd_file g_fds[KFD_MAX];

static void kmemset(void *dst, uint8_t v, uint64_t n) {
	uint8_t *p = (uint8_t *)dst;
	for (uint64_t i = 0; i < n; i++) p[i] = v;
}

static uint64_t align_up_u64(uint64_t v, uint64_t a) {
	return (v + (a - 1)) & ~(a - 1);
}

static uint64_t fnv1a64(const char *s) {
	uint64_t h = 1469598103934665603ull;
	for (uint64_t i = 0; s && s[i]; i++) {
		h ^= (uint8_t)s[i];
		h *= 1099511628211ull;
	}
	return h;
}

static int kfd_alloc_file(const uint8_t *data, uint64_t size, uint32_t mode) {
	for (int i = 0; i < KFD_MAX; i++) {
		if (!g_fds[i].used) {
			kmemset(&g_fds[i], 0, sizeof(g_fds[i]));
			g_fds[i].used = 1;
			g_fds[i].writable = 0;
			g_fds[i].kind = (uint8_t)KFD_KIND_FILE;
			g_fds[i].data = data;
			g_fds[i].size = size;
			g_fds[i].off = 0;
			g_fds[i].mode = mode;
			return 3 + i;
		}
	}
	return -1;
}

static int kfd_alloc_dir(const char *path, uint32_t mode) {
	for (int i = 0; i < KFD_MAX; i++) {
		if (!g_fds[i].used) {
			kmemset(&g_fds[i], 0, sizeof(g_fds[i]));
			g_fds[i].used = 1;
			g_fds[i].writable = 0;
			g_fds[i].kind = (uint8_t)KFD_KIND_DIR;
			g_fds[i].mode = mode;
			if (path) {
				(void)kcopy_cstr(g_fds[i].path, (uint64_t)sizeof(g_fds[i].path), path);
			}
			g_fds[i].scan_off = 0;
			g_fds[i].dir_emit = 0;
			g_fds[i].dir_off = 0;
			return 3 + i;
		}
	}
	return -1;
}

static struct kfd_file *kfd_get(int fd) {
	if (fd < 3) return 0;
	int idx = fd - 3;
	if (idx < 0 || idx >= KFD_MAX) return 0;
	if (!g_fds[idx].used) return 0;
	return &g_fds[idx];
}

static struct kfd_file *kfd_get_file(int fd) {
	struct kfd_file *f = kfd_get(fd);
	if (!f) return 0;
	if (f->kind != (uint8_t)KFD_KIND_FILE) return 0;
	return f;
}

static struct kfd_file *kfd_get_dir(int fd) {
	struct kfd_file *f = kfd_get(fd);
	if (!f) return 0;
	if (f->kind != (uint8_t)KFD_KIND_DIR) return 0;
	return f;
}

static int kfd_close(int fd) {
	struct kfd_file *f = kfd_get(fd);
	if (!f) return -1;
	kmemset(f, 0, sizeof(*f));
	return 0;
}

static void kstat_clear(struct mc_stat *st) {
	uint8_t *p = (uint8_t *)st;
	for (uint64_t i = 0; i < sizeof(*st); i++) p[i] = 0;
}

static void kstat_fill(struct mc_stat *st, uint32_t mode, uint64_t size) {
	kstat_clear(st);
	st->st_mode = mode;
	st->st_nlink = 1;
	st->st_uid = 0;
	st->st_gid = 0;
	st->st_size = (int64_t)size;
	st->st_blksize = (int64_t)PAGE_SIZE;
	st->st_blocks = (int64_t)((size + 511u) / 512u);
}

static void kstrcpy_cap(char *dst, uint64_t cap, const char *src) {
	if (!dst || cap == 0) return;
	uint64_t i = 0;
	for (; i + 1 < cap && src && src[i]; i++) {
		dst[i] = src[i];
	}
	dst[i] = 0;
}

static int is_dot(const char *s) {
	return s && s[0] == '.' && s[1] == 0;
}

static int is_dotdot(const char *s) {
	return s && s[0] == '.' && s[1] == '.' && s[2] == 0;
}

static const char *skip_dot_slash2(const char *s) {
	while (s && s[0] == '.' && s[1] == '/') s += 2;
	return s;
}

static int resolve_path(char *out, uint64_t cap, int dirfd, const char *pathname) {
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
		base = "";
	} else {
		struct kfd_file *d = kfd_get_dir(dirfd);
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

/* Track current user stack so execve() can replace it. */
static uint64_t g_user_stack_base = 0;
static uint64_t g_user_stack_pages = 0;

static uint64_t align_down_u64(uint64_t v, uint64_t a) {
	return v & ~(a - 1);
}

static uint64_t user_stack_push_bytes(uint64_t sp, const void *data, uint64_t n) {
	sp -= n;
	kmemcpy((void *)sp, data, (size_t)n);
	return sp;
}

static uint64_t user_stack_push_u64(uint64_t sp, uint64_t v) {
	return user_stack_push_bytes(sp, &v, 8);
}

static void serial_write_u64_dec(uint64_t v) {
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

static void serial_write_hex(uint64_t v) {
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

void syscall_handler(struct regs *r) {
	if (KDEBUG_SYSCALLS) {
		serial_write("[k] syscall ");
		serial_write_hex(r->rax);
		serial_write("\n");
	}

	switch (r->rax) {
	case 0: { /* read(fd, buf, count) */
		int fd = (int)r->rdi;
		uint8_t *buf = (uint8_t *)r->rsi;
		uint64_t count = r->rdx;
		if (!buf) {
			r->rax = (uint64_t)(-(int64_t)14); /* -EFAULT */
			return;
		}
		if (count == 0) {
			r->rax = 0;
			return;
		}
		if (fd == 0) {
			uint64_t i = 0;
			for (; i < count; i++) {
				char c = serial_getc();
				buf[i] = (uint8_t)c;
				if (c == '\n') {
					i++;
					break;
				}
			}
			r->rax = i;
			return;
		}
		{
			struct kfd_file *f = kfd_get_file(fd);
			if (!f) {
				if (kfd_get_dir(fd)) {
					r->rax = (uint64_t)(-(int64_t)21); /* -EISDIR */
					return;
				}
				r->rax = (uint64_t)(-(int64_t)9); /* -EBADF */
				return;
			}
			uint64_t avail = (f->off < f->size) ? (f->size - f->off) : 0;
			uint64_t n = (count < avail) ? count : avail;
			for (uint64_t i = 0; i < n; i++) {
				buf[i] = f->data[f->off + i];
			}
			f->off += n;
			r->rax = n;
			return;
		}
	}
	case 1: { /* write(fd, buf, count) */
		int fd = (int)r->rdi;
		const uint8_t *buf = (const uint8_t *)r->rsi;
		uint64_t count = r->rdx;
		if (!buf) {
			r->rax = (uint64_t)(-(int64_t)14); /* -EFAULT */
			return;
		}
		if (count == 0) {
			r->rax = 0;
			return;
		}
		if (fd != 1 && fd != 2) {
			r->rax = (uint64_t)(-(int64_t)9); /* -EBADF */
			return;
		}
		for (uint64_t i = 0; i < count; i++) {
			serial_putc((char)buf[i]);
		}
		r->rax = count;
		return;
	}
	case 3: { /* close(fd) */
		int fd = (int)r->rdi;
		if (fd <= 2) {
			r->rax = 0;
			return;
		}
		if (kfd_close(fd) != 0) {
			r->rax = (uint64_t)(-(int64_t)9); /* -EBADF */
			return;
		}
		r->rax = 0;
		return;
	}
	case 5: { /* fstat(fd, st) */
		int fd = (int)r->rdi;
		struct mc_stat *st = (struct mc_stat *)r->rsi;
		if (!st) {
			r->rax = (uint64_t)(-(int64_t)14); /* -EFAULT */
			return;
		}
		if (fd == 0 || fd == 1 || fd == 2) {
			kstat_fill(st, (uint32_t)(0020000u | 0600u), 0); /* S_IFCHR | 0600 */
			r->rax = 0;
			return;
		}
		struct kfd_file *d = kfd_get_dir(fd);
		if (d) {
			kstat_fill(st, d->mode ? d->mode : (uint32_t)(S_IFDIR | 0555u), 0);
			r->rax = 0;
			return;
		}
		struct kfd_file *f = kfd_get_file(fd);
		if (!f) {
			r->rax = (uint64_t)(-(int64_t)9); /* -EBADF */
			return;
		}
		kstat_fill(st, f->mode ? f->mode : (uint32_t)(S_IFREG | 0444u), f->size);
		r->rax = 0;
		return;
	}
	case 8: { /* lseek(fd, offset, whence) */
		int fd = (int)r->rdi;
		int64_t off = (int64_t)r->rsi;
		int whence = (int)r->rdx;
		if (kfd_get_dir(fd)) {
			r->rax = (uint64_t)(-(int64_t)29); /* -ESPIPE */
			return;
		}
		struct kfd_file *f = kfd_get_file(fd);
		if (!f) {
			if (fd == 0 || fd == 1 || fd == 2) {
				r->rax = (uint64_t)(-(int64_t)29); /* -ESPIPE */
				return;
			}
			r->rax = (uint64_t)(-(int64_t)9); /* -EBADF */
			return;
		}
		int64_t base;
		if (whence == SEEK_SET) base = 0;
		else if (whence == SEEK_CUR) base = (int64_t)f->off;
		else if (whence == SEEK_END) base = (int64_t)f->size;
		else {
			r->rax = (uint64_t)(-(int64_t)22); /* -EINVAL */
			return;
		}
		int64_t npos = base + off;
		if (npos < 0) {
			r->rax = (uint64_t)(-(int64_t)22); /* -EINVAL */
			return;
		}
		f->off = (uint64_t)npos;
		r->rax = (uint64_t)npos;
		return;
	}
	case 9: { /* mmap(addr, len, prot, flags, fd, offset) */
		uint64_t addr = r->rdi;
		uint64_t len = r->rsi;
		uint64_t prot = r->rdx;
		uint64_t flags = r->r10;
		int64_t fd = (int64_t)r->r8;
		uint64_t offset = r->r9;
		(void)addr;
		(void)prot;

		if (!(flags & MAP_ANONYMOUS) || !(flags & MAP_PRIVATE) || fd != -1 || offset != 0) {
			r->rax = (uint64_t)(-(int64_t)22); /* -EINVAL */
			return;
		}
		uint64_t pages = (len + PAGE_SIZE - 1) / PAGE_SIZE;
		if (pages == 0) pages = 1;
		uint64_t paddr = pmm_alloc_pages((uint32_t)pages);
		if (paddr == 0) {
			r->rax = (uint64_t)(-(int64_t)12); /* -ENOMEM */
			return;
		}
		uint8_t *p = (uint8_t *)paddr;
		for (uint64_t i = 0; i < pages * PAGE_SIZE; i++) p[i] = 0;
		r->rax = paddr;
		return;
	}
	case 11: { /* munmap(addr, len) */
		uint64_t addr = r->rdi;
		uint64_t len = r->rsi;
		uint64_t pages = (len + PAGE_SIZE - 1) / PAGE_SIZE;
		if (pages == 0) pages = 1;
		pmm_free_pages(addr, (uint32_t)pages);
		r->rax = 0;
		return;
	}
	case 257: { /* openat(dirfd, pathname, flags, mode) */
		int dirfd = (int)r->rdi;
		const char *pathname = (const char *)r->rsi;
		uint64_t flags = r->rdx;
		(void)r->r10;

		if (!pathname) {
			r->rax = (uint64_t)(-(int64_t)14); /* -EFAULT */
			return;
		}
		if (!g_initramfs || g_initramfs_sz == 0) {
			r->rax = (uint64_t)(-(int64_t)2); /* -ENOENT */
			return;
		}
		if ((flags & 3u) != 0u) {
			r->rax = (uint64_t)(-(int64_t)13); /* -EACCES */
			return;
		}
		if (flags & O_CREAT) {
			r->rax = (uint64_t)(-(int64_t)30); /* -EROFS */
			return;
		}

		char pathbuf[KEXEC_MAX_STR];
		if (kcopy_cstr(pathbuf, KEXEC_MAX_STR, pathname) != 0) {
			r->rax = (uint64_t)(-(int64_t)14);
			return;
		}

		char full[KEXEC_MAX_STR];
		int rr = resolve_path(full, sizeof(full), dirfd, pathbuf);
		if (rr != 0) {
			r->rax = (uint64_t)(-(int64_t)9); /* -EBADF */
			return;
		}
		const char *p = skip_leading_slash(full);
		p = skip_dot_slash2(p);

		uint32_t mode = 0;
		uint64_t size = 0;
		int st = cpio_newc_stat(g_initramfs, g_initramfs_sz, p, &mode, &size);
		if (flags & O_DIRECTORY) {
			if (p[0] == 0) {
				mode = (uint32_t)(S_IFDIR | 0555u);
				int fd = kfd_alloc_dir(p, mode);
				if (fd < 0) {
					r->rax = (uint64_t)(-(int64_t)24);
					return;
				}
				r->rax = (uint64_t)fd;
				return;
			}
			if (st == 0) {
				if ((mode & S_IFMT) != S_IFDIR) {
					r->rax = (uint64_t)(-(int64_t)20); /* -ENOTDIR */
					return;
				}
				int fd = kfd_alloc_dir(p, mode);
				if (fd < 0) {
					r->rax = (uint64_t)(-(int64_t)24);
					return;
				}
				r->rax = (uint64_t)fd;
				return;
			}
			/* Implied directory if any entry exists below. */
			if (cpio_newc_has_prefix(g_initramfs, g_initramfs_sz, p)) {
				mode = (uint32_t)(S_IFDIR | 0555u);
				int fd = kfd_alloc_dir(p, mode);
				if (fd < 0) {
					r->rax = (uint64_t)(-(int64_t)24);
					return;
				}
				r->rax = (uint64_t)fd;
				return;
			}
			r->rax = (uint64_t)(-(int64_t)2); /* -ENOENT */
			return;
		}

		/* Regular file open */
		if (st != 0) {
			r->rax = (uint64_t)(-(int64_t)2); /* -ENOENT */
			return;
		}
		if ((mode & S_IFMT) == S_IFDIR) {
			r->rax = (uint64_t)(-(int64_t)21); /* -EISDIR */
			return;
		}
		const uint8_t *data = 0;
		if (cpio_newc_find(g_initramfs, g_initramfs_sz, p, &data, &size) != 0) {
			r->rax = (uint64_t)(-(int64_t)5); /* -EIO */
			return;
		}
		int fd = kfd_alloc_file(data, size, mode);
		if (fd < 0) {
			r->rax = (uint64_t)(-(int64_t)24); /* -EMFILE */
			return;
		}
		r->rax = (uint64_t)fd;
		return;
	}
	case 217: { /* getdents64(fd, dirp, count) */
		int fd = (int)r->rdi;
		uint8_t *dirp = (uint8_t *)r->rsi;
		uint64_t count = r->rdx;
		if (!dirp) {
			r->rax = (uint64_t)(-(int64_t)14); /* -EFAULT */
			return;
		}
		if (count < sizeof(struct mc_dirent64) + 2) {
			r->rax = 0;
			return;
		}
		struct kfd_file *d = kfd_get_dir(fd);
		if (!d) {
			r->rax = (uint64_t)(-(int64_t)20); /* -ENOTDIR */
			return;
		}
		if (!g_initramfs || g_initramfs_sz == 0) {
			r->rax = 0;
			return;
		}
		uint64_t pos = 0;
		while (pos + sizeof(struct mc_dirent64) + 2 <= count) {
			char name_tmp[256];
			uint8_t dt = DT_UNKNOWN;
			int have = 0;
			if (d->dir_emit == 0) {
				(void)kcopy_cstr(name_tmp, sizeof(name_tmp), ".");
				dt = DT_DIR;
				d->dir_emit = 1;
				have = 1;
			} else if (d->dir_emit == 1) {
				(void)kcopy_cstr(name_tmp, sizeof(name_tmp), "..");
				dt = DT_DIR;
				d->dir_emit = 2;
				have = 1;
			} else {
				have = cpio_newc_dir_next(g_initramfs, g_initramfs_sz, d->path, &d->scan_off,
							  name_tmp, sizeof(name_tmp), &dt);
				if (have <= 0) break;
			}

			uint64_t namelen = kstrnlen(name_tmp, sizeof(name_tmp));
			uint64_t reclen = (uint64_t)sizeof(struct mc_dirent64) + namelen + 1;
			reclen = align_up_u64(reclen, 8);
			if (pos + reclen > count) break;

			struct mc_dirent64 *ent = (struct mc_dirent64 *)(dirp + pos);
			char full[KEXEC_MAX_STR];
			full[0] = 0;
			if (d->path[0] == 0) {
				(void)kcopy_cstr(full, sizeof(full), name_tmp);
			} else {
				char tmp[KEXEC_MAX_STR];
				(void)kcopy_cstr(tmp, sizeof(tmp), d->path);
				uint64_t bl = kstrnlen(tmp, sizeof(tmp));
				if (bl + 1 < sizeof(tmp)) {
					tmp[bl] = '/';
					tmp[bl + 1] = 0;
					(void)kcopy_cstr(full, sizeof(full), tmp);
					uint64_t fl = kstrnlen(full, sizeof(full));
					for (uint64_t i = 0; i <= namelen && fl + i < sizeof(full); i++) full[fl + i] = name_tmp[i];
				}
			}
			ent->d_ino = fnv1a64(full);
			ent->d_off = (int64_t)(++d->dir_off);
			ent->d_reclen = (uint16_t)reclen;
			ent->d_type = dt;
			for (uint64_t i = 0; i <= namelen; i++) ent->d_name[i] = name_tmp[i];

			pos += reclen;
		}
		r->rax = pos;
		return;
	}
	case 262: { /* newfstatat(dirfd, pathname, st, flags) */
		int dirfd = (int)r->rdi;
		const char *pathname = (const char *)r->rsi;
		struct mc_stat *st = (struct mc_stat *)r->rdx;
		uint64_t flags = r->r10;
		(void)flags;

		if (!st) {
			r->rax = (uint64_t)(-(int64_t)14); /* -EFAULT */
			return;
		}
		/* dirfd supports AT_FDCWD or a directory fd from openat(O_DIRECTORY). */
		if (!pathname) {
			r->rax = (uint64_t)(-(int64_t)14);
			return;
		}
		if (!g_initramfs || g_initramfs_sz == 0) {
			r->rax = (uint64_t)(-(int64_t)2);
			return;
		}
		char pathbuf[KEXEC_MAX_STR];
		if (kcopy_cstr(pathbuf, KEXEC_MAX_STR, pathname) != 0) {
			r->rax = (uint64_t)(-(int64_t)14);
			return;
		}
		if (is_dot(pathbuf)) {
			kstat_fill(st, (uint32_t)(S_IFDIR | 0555u), 0);
			r->rax = 0;
			return;
		}
		if (is_dotdot(pathbuf)) {
			kstat_fill(st, (uint32_t)(S_IFDIR | 0555u), 0);
			r->rax = 0;
			return;
		}
		char full[KEXEC_MAX_STR];
		int rr = resolve_path(full, sizeof(full), dirfd, pathbuf);
		if (rr != 0) {
			r->rax = (uint64_t)(-(int64_t)9); /* -EBADF */
			return;
		}
		const char *p = skip_leading_slash(full);
		p = skip_dot_slash2(p);
		if (!p[0]) {
			kstat_fill(st, (uint32_t)(S_IFDIR | 0555u), 0);
			r->rax = 0;
			return;
		}
		uint32_t mode = 0;
		uint64_t size = 0;
		if (cpio_newc_stat(g_initramfs, g_initramfs_sz, p, &mode, &size) != 0) {
			if (cpio_newc_has_prefix(g_initramfs, g_initramfs_sz, p)) {
				kstat_fill(st, (uint32_t)(S_IFDIR | 0555u), 0);
				r->rax = 0;
				return;
			}
			r->rax = (uint64_t)(-(int64_t)2); /* -ENOENT */
			return;
		}
		kstat_fill(st, mode, size);
		r->rax = 0;
		return;
	}
	case 269: { /* faccessat(dirfd, pathname, mode, flags) */
		int dirfd = (int)r->rdi;
		const char *pathname = (const char *)r->rsi;
		uint64_t mode_req = r->rdx;
		uint64_t flags = r->r10;
		(void)flags;

		if (dirfd != AT_FDCWD) {
			r->rax = (uint64_t)(-(int64_t)22); /* -EINVAL */
			return;
		}
		if (!pathname) {
			r->rax = (uint64_t)(-(int64_t)14); /* -EFAULT */
			return;
		}
		if (!g_initramfs || g_initramfs_sz == 0) {
			r->rax = (uint64_t)(-(int64_t)2);
			return;
		}
		char pathbuf[KEXEC_MAX_STR];
		if (kcopy_cstr(pathbuf, KEXEC_MAX_STR, pathname) != 0) {
			r->rax = (uint64_t)(-(int64_t)14);
			return;
		}
		const char *p = skip_leading_slash(pathbuf);
		uint32_t mode = 0;
		uint64_t size = 0;
		if (cpio_newc_stat(g_initramfs, g_initramfs_sz, p, &mode, &size) != 0) {
			(void)size;
			r->rax = (uint64_t)(-(int64_t)2); /* -ENOENT */
			return;
		}
		/* Read-only initramfs policy. */
		if (mode_req & 2u) {
			r->rax = (uint64_t)(-(int64_t)13); /* -EACCES */
			return;
		}
		if ((mode_req & 4u) && ((mode & 0444u) == 0)) {
			r->rax = (uint64_t)(-(int64_t)13);
			return;
		}
		if ((mode_req & 1u) && ((mode & 0111u) == 0)) {
			r->rax = (uint64_t)(-(int64_t)13);
			return;
		}
		r->rax = 0;
		return;
	}
	case 102: /* getuid() */
		r->rax = 0;
		return;
	case 104: /* getgid() */
		r->rax = 0;
		return;
	case 115: { /* getgroups(size, list) */
		int size = (int)r->rdi;
		uint32_t *list = (uint32_t *)r->rsi;
		(void)list;
		if (size == 0) {
			r->rax = 0;
			return;
		}
		/* No supplementary groups. */
		r->rax = 0;
		return;
	}
	case 63: { /* uname(buf) */
		struct mc_utsname *u = (struct mc_utsname *)r->rdi;
		if (!u) {
			r->rax = (uint64_t)(-(int64_t)14); /* -EFAULT */
			return;
		}
		kstrcpy_cap(u->sysname, sizeof(u->sysname), "monacc");
		kstrcpy_cap(u->nodename, sizeof(u->nodename), "monacc");
		kstrcpy_cap(u->release, sizeof(u->release), "0.1");
		kstrcpy_cap(u->version, sizeof(u->version), "monacc-kernel");
		kstrcpy_cap(u->machine, sizeof(u->machine), "x86_64");
		kstrcpy_cap(u->domainname, sizeof(u->domainname), "");
		r->rax = 0;
		return;
	}
	case 79: { /* getcwd(buf, size) */
		char *buf = (char *)r->rdi;
		uint64_t size = r->rsi;
		if (!buf) {
			r->rax = (uint64_t)(-(int64_t)14); /* -EFAULT */
			return;
		}
		if (size < 2) {
			r->rax = (uint64_t)(-(int64_t)22); /* -EINVAL */
			return;
		}
		buf[0] = '/';
		buf[1] = 0;
		r->rax = 2;
		return;
	}
	case 59: { /* execve(filename, argv, envp) */
		const char *filename = (const char *)r->rdi;
		const uint64_t *argvp = (const uint64_t *)r->rsi;
		(void)r->rdx;

		if (!filename) {
			r->rax = (uint64_t)(-(int64_t)14);
			return;
		}
		if (!g_initramfs || g_initramfs_sz == 0) {
			r->rax = (uint64_t)(-(int64_t)2);
			return;
		}

		char filename_buf[KEXEC_MAX_STR];
		if (kcopy_cstr(filename_buf, KEXEC_MAX_STR, filename) != 0) {
			r->rax = (uint64_t)(-(int64_t)14);
			return;
		}
		const char *path = skip_leading_slash(filename_buf);
		if (!path[0]) {
			r->rax = (uint64_t)(-(int64_t)2);
			return;
		}

		char argv_buf[KEXEC_MAX_ARGS][KEXEC_MAX_STR];
		uint64_t argc = 0;
		if (argvp) {
			for (; argc < KEXEC_MAX_ARGS; argc++) {
				uint64_t p = argvp[argc];
				if (p == 0) break;
				if (kcopy_cstr(argv_buf[argc], KEXEC_MAX_STR, (const char *)p) != 0) {
					r->rax = (uint64_t)(-(int64_t)7); /* -E2BIG */
					return;
				}
			}
		}
		if (argc == 0) {
			if (kcopy_cstr(argv_buf[0], KEXEC_MAX_STR, filename_buf) != 0) {
				r->rax = (uint64_t)(-(int64_t)14);
				return;
			}
			argc = 1;
		}

		const uint8_t *img = 0;
		uint64_t img_sz = 0;
		if (cpio_newc_find(g_initramfs, g_initramfs_sz, path, &img, &img_sz) != 0) {
			r->rax = (uint64_t)(-(int64_t)2);
			return;
		}
		uint64_t user_entry = 0;
		uint64_t brk_init = 0;
		if (elf_load_exec(img, img_sz, &user_entry, &brk_init) != 0) {
			r->rax = (uint64_t)(-(int64_t)8); /* -ENOEXEC */
			return;
		}

		if (g_user_stack_base && g_user_stack_pages) {
			pmm_free_pages(g_user_stack_base, (uint32_t)g_user_stack_pages);
			g_user_stack_base = 0;
			g_user_stack_pages = 0;
		}
		uint64_t stack_pages = USER_STACK_PAGES;
		uint64_t stack_base = pmm_alloc_pages((uint32_t)stack_pages);
		if (stack_base == 0) {
			r->rax = (uint64_t)(-(int64_t)12);
			return;
		}
		g_user_stack_base = stack_base;
		g_user_stack_pages = stack_pages;
		uint64_t sp = align_down_u64(stack_base + stack_pages * PAGE_SIZE, 16);

		uint64_t u_argv_ptrs[KEXEC_MAX_ARGS];
		for (uint64_t i = 0; i < argc; i++) {
			uint64_t len = kstrnlen(argv_buf[argc - 1 - i], KEXEC_MAX_STR);
			sp = user_stack_push_bytes(sp, argv_buf[argc - 1 - i], len + 1);
			u_argv_ptrs[argc - 1 - i] = sp;
		}
		const char *env0 = "PATH=/bin";
		sp = user_stack_push_bytes(sp, env0, 10);
		uint64_t u_env0 = sp;
		sp = align_down_u64(sp, 16);
		sp = user_stack_push_u64(sp, 0);
		sp = user_stack_push_u64(sp, 0);
		sp = user_stack_push_u64(sp, 0);
		sp = user_stack_push_u64(sp, u_env0);
		sp = user_stack_push_u64(sp, 0);
		for (uint64_t i = 0; i < argc; i++) {
			sp = user_stack_push_u64(sp, u_argv_ptrs[argc - 1 - i]);
		}
		sp = user_stack_push_u64(sp, argc);

		syscall_user_rsp = sp;
		r->rcx = user_entry;
		r->rax = 0;
		return;
	}
	case 60: /* exit(code) */
		serial_write("Process exited with code ");
		serial_write_u64_dec(r->rdi);
		serial_write("\n");
		outb(0xF4, 0x10);
		halt_forever();
	case 231: /* exit_group(code) */
		serial_write("Process exited with code ");
		serial_write_u64_dec(r->rdi);
		serial_write("\n");
		outb(0xF4, 0x10);
		halt_forever();
	default:
		r->rax = (uint64_t)(-(int64_t)38); /* -ENOSYS */
		return;
	}
}

__attribute__((noreturn)) void kmain(void) {
	serial_init();
	serial_write("monacc kernel\n");

	/* Initialize physical memory manager */
	serial_write("[k] pmm_init...\n");
	pmm_init();
	serial_write("[k] pmm_init ok\n");

	/* Set up GDT (with ring-3 segments) + TSS, then IDT with int 0x80 gate. */
	serial_write("[k] gdt_tss_init...\n");
	gdt_tss_init();
	serial_write("[k] gdt_tss_init ok\n");
	serial_write("[k] idt_init...\n");
	idt_init();
	serial_write("[k] idt_init ok\n");

	/* Remap PIC away from exception vectors and mask all IRQs.
	 * This makes it safe to run ring3 with IF=1 even before a full IRQ subsystem exists.
	 */
	serial_write("[k] pic_init...\n");
	pic_init();
	serial_write("[k] pic_init ok\n");

	serial_write("[k] tss_load...\n");
	tss_load();
	serial_write("[k] tss_load ok\n");

	serial_write("[k] syscall_init...\n");
	syscall_init();
	serial_write("[k] syscall_init ok\n");

	/* Load and run a real monacc-built ELF tool (embedded as bytes). */
	{
		const uint8_t *imgp = (const uint8_t *)user_elf_echo_start;
		uint64_t img_sz = (uint64_t)user_elf_echo_end - (uint64_t)user_elf_echo_start;
		const char *boot_arg0 = "echo";
		const char *boot_arg1 = "hello";
		uint64_t boot_argc = 2;

		/* If GRUB provided an initramfs module, prefer loading /bin/echo from it. */
		uint64_t mod_start = 0, mod_end = 0;
		if (mb2_find_first_module(mb2_info_ptr, &mod_start, &mod_end) == 0) {
			serial_write("[k] found multiboot2 module\n");
			g_initramfs = (const uint8_t *)mod_start;
			g_initramfs_sz = mod_end - mod_start;
			if (mod_end > mod_start) {
				uint64_t m_start = mod_start & ~(uint64_t)(PAGE_SIZE - 1);
				uint64_t m_end = (mod_end + (PAGE_SIZE - 1)) & ~(uint64_t)(PAGE_SIZE - 1);
				if (m_end > m_start && m_start >= 0x400000) {
					(void)pmm_reserve_pages(m_start, (uint32_t)((m_end - m_start) / PAGE_SIZE));
				}
			}
			const uint8_t *f = 0;
			uint64_t fsz = 0;
			if (cpio_newc_find((const uint8_t *)mod_start, mod_end - mod_start, "init", &f, &fsz) == 0) {
				serial_write("[k] initramfs: using /init\n");
				imgp = f;
				img_sz = fsz;
				boot_arg0 = "/init";
				boot_arg1 = 0;
				boot_argc = 1;
			} else if (cpio_newc_find((const uint8_t *)mod_start, mod_end - mod_start, "bin/echo", &f, &fsz) == 0) {
				serial_write("[k] initramfs: /init not found; using bin/echo\n");
				imgp = f;
				img_sz = fsz;
				boot_arg0 = "/bin/echo";
				boot_arg1 = "hello";
				boot_argc = 2;
			} else {
				serial_write("[k] initramfs: init and bin/echo not found; using embedded\n");
			}
		}
		uint64_t user_entry = 0;
		uint64_t brk_init = 0;

		serial_write("[k] elf_load_exec(echo)...\n");
		if (elf_load_exec(imgp, img_sz, &user_entry, &brk_init) != 0) {
			serial_write("[k] elf_load_exec failed\n");
			halt_forever();
		}
		serial_write("[k] elf_load_exec ok\n");

		/* Allocate a user stack in free RAM and set up argc/argv.
		 * Stack format: argc, argv[], NULL, envp(NULL), auxv(AT_NULL).
		 */
		uint64_t stack_pages = USER_STACK_PAGES;
		uint64_t stack_base = pmm_alloc_pages((uint32_t)stack_pages);
		if (stack_base == 0) {
			serial_write("[k] no memory for user stack\n");
			halt_forever();
		}
		g_user_stack_base = stack_base;
		g_user_stack_pages = stack_pages;
		uint64_t sp = stack_base + stack_pages * PAGE_SIZE;
		sp = align_down_u64(sp, 16);

		/* Copy argument strings into user stack memory. */
		uint64_t u_arg0 = 0;
		uint64_t u_arg1 = 0;
		uint64_t arg0_len = kstrnlen(boot_arg0, KEXEC_MAX_STR);
		sp = user_stack_push_bytes(sp, boot_arg0, arg0_len + 1);
		u_arg0 = sp;
		if (boot_argc > 1 && boot_arg1) {
			uint64_t arg1_len = kstrnlen(boot_arg1, KEXEC_MAX_STR);
			sp = user_stack_push_bytes(sp, boot_arg1, arg1_len + 1);
			u_arg1 = sp;
		}

		/* Align before pushing pointers. */
		sp = align_down_u64(sp, 16);

		/* auxv terminator: AT_NULL (0), 0 */
		sp = user_stack_push_u64(sp, 0);
		sp = user_stack_push_u64(sp, 0);
		/* envp terminator */
		sp = user_stack_push_u64(sp, 0);
		/* argv terminator */
		sp = user_stack_push_u64(sp, 0);
		/* argv pointers */
		if (boot_argc > 1 && u_arg1) {
			sp = user_stack_push_u64(sp, u_arg1);
		}
		sp = user_stack_push_u64(sp, u_arg0);
		/* argc */
		sp = user_stack_push_u64(sp, boot_argc);

		serial_write("Entering userland...\n");
		enter_user(user_entry, sp);
	}

	halt_forever();
}
