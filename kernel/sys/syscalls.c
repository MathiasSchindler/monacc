#include "kernel.h"
#include "proc.h"
#include "fs.h"
#include "sys.h"

/* Embedded monacc-built ELF tools (from user/*.S incbin). */
extern void user_elf_echo_start(void);
extern void user_elf_echo_end(void);

void syscall_handler(struct regs *r) {
	/* If we haven't established a current process yet, treat the first syscall
	 * as coming from the boot process (PID 1). */
	if (!g_cur) {
		struct kproc *p = kproc_alloc(0);
		if (!p) {
			serial_write("[k] kproc_alloc failed\n");
			halt_forever();
		}
		g_cur = p;
		g_cur->regs = *r;
		g_cur->user_rsp = syscall_user_rsp;
		g_cur->user_stack_base = 0;
		g_cur->user_stack_pages = 0;
		syscall_kstack_top = g_cur->kstack_base + (uint64_t)g_cur->kstack_pages * PAGE_SIZE;
	}

	/* Persist the current process image before potentially switching away.
	 * This makes global data in the fixed ET_EXEC region coherent per-process.
	 */
	kproc_img_save(g_cur);

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
		if (fd == 0 && !kfd_get(0)) {
			uint64_t i = 0;
			while (i < count) {
				char c = serial_getc();
				/* Basic cooked-mode behavior for serial console:
				 * - echo input
				 * - CR -> LF
				 * - backspace/delete editing
				 * - Ctrl-D at start => EOF
				 */
				if (c == '\r') c = '\n';
				if ((uint8_t)c == 0x04) { /* ^D */
					if (i == 0) {
						r->rax = 0;
						return;
					}
					break;
				}
				if (c == '\b' || (uint8_t)c == 0x7f) {
					if (i > 0) {
						i--;
						serial_putc('\b');
						serial_putc(' ');
						serial_putc('\b');
					}
					continue;
				}
				buf[i++] = (uint8_t)c;
				if (c == '\n') {
					serial_putc('\r');
					serial_putc('\n');
					break;
				}
				serial_putc(c);
			}
			r->rax = i;
			return;
		}
		{
			struct kfile *pf = kfd_get_pipe(fd);
			if (pf) {
				if (pf->pipe_end != 0) {
					r->rax = (uint64_t)(-(int64_t)9); /* -EBADF */
					return;
				}
				struct kpipe *pp = kpipe_get(pf->pipe_id);
				if (!pp) {
					r->rax = (uint64_t)(-(int64_t)9);
					return;
				}
				if (pp->count == 0) {
					if (pp->write_refs == 0) {
						r->rax = 0; /* EOF */
						return;
					}
					/* Block until data becomes available. */
					g_cur->state = KPROC_WAITING;
					g_cur->wait_kind = KWAIT_PIPE_READ;
					g_cur->wait_obj = pf->pipe_id;
					r->rcx -= 2; /* retry syscall */
					struct kproc *next = kproc_pick_next();
					if (next != g_cur) {
						kproc_switch(r, next);
					}
					return;
				}
				uint64_t n = (count < (uint64_t)pp->count) ? count : (uint64_t)pp->count;
				for (uint64_t i = 0; i < n; i++) {
					buf[i] = pp->buf[pp->rpos];
					pp->rpos = (pp->rpos + 1u) % KPIPE_BUF;
					pp->count--;
				}
				kpipe_wake_waiters(pf->pipe_id);
				r->rax = n;
				return;
			}
		}
		{
			struct kfile *f = kfd_get_file(fd);
			if (!f) {
				if (kfd_get_dir(fd)) {
					r->rax = (uint64_t)(-(int64_t)21); /* -EISDIR */
					return;
				}
				if (kfd_get_pipe(fd)) {
					r->rax = (uint64_t)(-(int64_t)9); /* -EBADF */
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
			/* Not stdio: allow writing to pipes if mapped. */
			struct kfile *pf = kfd_get_pipe(fd);
			if (!pf || pf->pipe_end != 1) {
				r->rax = (uint64_t)(-(int64_t)9); /* -EBADF */
				return;
			}
			struct kpipe *pp = kpipe_get(pf->pipe_id);
			if (!pp) {
				r->rax = (uint64_t)(-(int64_t)9);
				return;
			}
			if (pp->read_refs == 0) {
				r->rax = (uint64_t)(-(int64_t)32); /* -EPIPE */
				return;
			}
			if (pp->count == KPIPE_BUF) {
				/* Block until space becomes available. */
				g_cur->state = KPROC_WAITING;
				g_cur->wait_kind = KWAIT_PIPE_WRITE;
				g_cur->wait_obj = pf->pipe_id;
				r->rcx -= 2; /* retry syscall */
				struct kproc *next = kproc_pick_next();
				if (next != g_cur) {
					kproc_switch(r, next);
				}
				return;
			}
			uint64_t space = (uint64_t)(KPIPE_BUF - pp->count);
			uint64_t n = (count < space) ? count : space;
			for (uint64_t i = 0; i < n; i++) {
				pp->buf[pp->wpos] = buf[i];
				pp->wpos = (pp->wpos + 1u) % KPIPE_BUF;
				pp->count++;
			}
			kpipe_wake_waiters(pf->pipe_id);
			r->rax = n;
			return;
		}
		/* Stdout/stderr: if redirected, handle it; otherwise serial. */
		struct kfile *pf = kfd_get_pipe(fd);
		if (pf) {
			if (pf->pipe_end != 1) {
				r->rax = (uint64_t)(-(int64_t)9);
				return;
			}
			struct kpipe *pp = kpipe_get(pf->pipe_id);
			if (!pp) {
				r->rax = (uint64_t)(-(int64_t)9);
				return;
			}
			if (pp->read_refs == 0) {
				r->rax = (uint64_t)(-(int64_t)32);
				return;
			}
			if (pp->count == KPIPE_BUF) {
				g_cur->state = KPROC_WAITING;
				g_cur->wait_kind = KWAIT_PIPE_WRITE;
				g_cur->wait_obj = pf->pipe_id;
				r->rcx -= 2;
				struct kproc *next = kproc_pick_next();
				if (next != g_cur) {
					kproc_switch(r, next);
				}
				return;
			}
			uint64_t space = (uint64_t)(KPIPE_BUF - pp->count);
			uint64_t n = (count < space) ? count : space;
			for (uint64_t i = 0; i < n; i++) {
				pp->buf[pp->wpos] = buf[i];
				pp->wpos = (pp->wpos + 1u) % KPIPE_BUF;
				pp->count++;
			}
			kpipe_wake_waiters(pf->pipe_id);
			r->rax = n;
			return;
		}
		for (uint64_t i = 0; i < count; i++) serial_putc((char)buf[i]);
		r->rax = count;
		return;
	}
	case 3: { /* close(fd) */
		int fd = (int)r->rdi;
		if (fd <= 2) {
			/* If redirected, close the redirection target. */
			(void)kfd_close(fd);
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
	case 33: { /* dup2(oldfd, newfd) */
		int oldfd = (int)r->rdi;
		int newfd = (int)r->rsi;
		if (!g_cur) {
			r->rax = (uint64_t)(-(int64_t)9);
			return;
		}
		if (oldfd < 0 || oldfd >= KFD_MAX || newfd < 0 || newfd >= KFD_MAX) {
			r->rax = (uint64_t)(-(int64_t)9); /* -EBADF */
			return;
		}
		if (g_cur->fds[oldfd] < 0) {
			r->rax = (uint64_t)(-(int64_t)9);
			return;
		}
		if (oldfd == newfd) {
			r->rax = (uint64_t)newfd;
			return;
		}
		if (kfd_install(g_cur, newfd, (uint32_t)g_cur->fds[oldfd]) != 0) {
			r->rax = (uint64_t)(-(int64_t)9);
			return;
		}
		r->rax = (uint64_t)newfd;
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
			if (kfd_get(fd)) {
				/* redirected stdio */
			} else {
				kstat_fill(st, (uint32_t)(0020000u | 0600u), 0); /* S_IFCHR | 0600 */
				r->rax = 0;
				return;
			}
		}
		struct kfile *d = kfd_get_dir(fd);
		if (d) {
			kstat_fill(st, d->mode ? d->mode : (uint32_t)(S_IFDIR | 0555u), 0);
			r->rax = 0;
			return;
		}
		struct kfile *pf = kfd_get_pipe(fd);
		if (pf) {
			kstat_fill(st, (uint32_t)(0010000u | 0600u), 0); /* S_IFIFO | 0600 */
			r->rax = 0;
			return;
		}
		struct kfile *f = kfd_get_file(fd);
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
		if (kfd_get_pipe(fd)) {
			r->rax = (uint64_t)(-(int64_t)29); /* -ESPIPE */
			return;
		}
		struct kfile *f = kfd_get_file(fd);
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
		uint64_t paddr = pmm_alloc_pages_high((uint32_t)pages);
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
				int id = kfile_alloc_dir(p, mode);
				if (id < 0) {
					r->rax = (uint64_t)(-(int64_t)24);
					return;
				}
				int fd = kfd_install_first_free(g_cur, 3, (uint32_t)id);
				if (fd < 0) {
					kfile_free((uint32_t)id);
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
				int id = kfile_alloc_dir(p, mode);
				if (id < 0) {
					r->rax = (uint64_t)(-(int64_t)24);
					return;
				}
				int fd = kfd_install_first_free(g_cur, 3, (uint32_t)id);
				if (fd < 0) {
					kfile_free((uint32_t)id);
					r->rax = (uint64_t)(-(int64_t)24);
					return;
				}
				r->rax = (uint64_t)fd;
				return;
			}
			/* Implied directory if any entry exists below. */
			if (cpio_newc_has_prefix(g_initramfs, g_initramfs_sz, p)) {
				mode = (uint32_t)(S_IFDIR | 0555u);
				int id = kfile_alloc_dir(p, mode);
				if (id < 0) {
					r->rax = (uint64_t)(-(int64_t)24);
					return;
				}
				int fd = kfd_install_first_free(g_cur, 3, (uint32_t)id);
				if (fd < 0) {
					kfile_free((uint32_t)id);
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
		int id = kfile_alloc_file(data, size, mode);
		if (id < 0) {
			r->rax = (uint64_t)(-(int64_t)24); /* -EMFILE */
			return;
		}
		int fd = kfd_install_first_free(g_cur, 3, (uint32_t)id);
		if (fd < 0) {
			kfile_free((uint32_t)id);
			r->rax = (uint64_t)(-(int64_t)24);
			return;
		}
		r->rax = (uint64_t)fd;
		return;
	}
	case 293: { /* pipe2(int pipefd[2], int flags) */
		int *pipefd = (int *)r->rdi;
		uint64_t flags = r->rsi;
		if (!pipefd) {
			r->rax = (uint64_t)(-(int64_t)14); /* -EFAULT */
			return;
		}
		/* Accept 0 or O_CLOEXEC (ignored for now). */
		if (flags != 0 && flags != 0x80000u) {
			r->rax = (uint64_t)(-(int64_t)22); /* -EINVAL */
			return;
		}
		int pipe_id = kpipe_alloc();
		if (pipe_id < 0) {
			r->rax = (uint64_t)(-(int64_t)12); /* -ENOMEM */
			return;
		}
		int rid = kfile_alloc_pipe_end((uint32_t)pipe_id, 0);
		int wid = kfile_alloc_pipe_end((uint32_t)pipe_id, 1);
		if (rid < 0 || wid < 0) {
			if (rid >= 0) kfile_free((uint32_t)rid);
			if (wid >= 0) kfile_free((uint32_t)wid);
			/* No refs yet, so free is safe. */
			kmemset(&g_pipes[pipe_id], 0, sizeof(g_pipes[pipe_id]));
			r->rax = (uint64_t)(-(int64_t)24); /* -EMFILE */
			return;
		}
		int rfd = kfd_install_first_free(g_cur, 3, (uint32_t)rid);
		if (rfd < 0) {
			kfile_free((uint32_t)rid);
			kfile_free((uint32_t)wid);
			kmemset(&g_pipes[pipe_id], 0, sizeof(g_pipes[pipe_id]));
			r->rax = (uint64_t)(-(int64_t)24);
			return;
		}
		int wfd = kfd_install_first_free(g_cur, 3, (uint32_t)wid);
		if (wfd < 0) {
			(void)kfd_close(rfd);
			kfile_free((uint32_t)wid);
			/* pipe might still have refs from rfd; close already decref'd. */
			kpipe_free_if_unused((uint32_t)pipe_id);
			r->rax = (uint64_t)(-(int64_t)24);
			return;
		}
		pipefd[0] = rfd;
		pipefd[1] = wfd;
		r->rax = 0;
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
		struct kfile *d = kfd_get_dir(fd);
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
		const char *cwd = (g_cur ? g_cur->cwd : "");
		if (!cwd || cwd[0] == 0) {
			buf[0] = '/';
			buf[1] = 0;
			r->rax = 2;
			return;
		}
		uint64_t n = kstrnlen(cwd, KEXEC_MAX_STR);
		if (n + 2 > size) {
			r->rax = (uint64_t)(-(int64_t)34); /* -ERANGE */
			return;
		}
		buf[0] = '/';
		for (uint64_t i = 0; i < n; i++) buf[1 + i] = cwd[i];
		buf[1 + n] = 0;
		r->rax = 2 + n;
		return;
	}
	case 80: { /* chdir(path) */
		const char *path = (const char *)r->rdi;
		if (!path) {
			r->rax = (uint64_t)(-(int64_t)14); /* -EFAULT */
			return;
		}
		if (!g_initramfs || g_initramfs_sz == 0) {
			r->rax = (uint64_t)(-(int64_t)2); /* -ENOENT */
			return;
		}
		char pathbuf[KEXEC_MAX_STR];
		if (kcopy_cstr(pathbuf, sizeof(pathbuf), path) != 0) {
			r->rax = (uint64_t)(-(int64_t)14);
			return;
		}
		char full[KEXEC_MAX_STR];
		if (resolve_path(full, sizeof(full), AT_FDCWD, pathbuf) != 0) {
			r->rax = (uint64_t)(-(int64_t)22); /* -EINVAL */
			return;
		}
		const char *p = skip_leading_slash(full);
		p = skip_dot_slash2(p);
		if (!p[0]) {
			g_cur->cwd[0] = 0;
			r->rax = 0;
			return;
		}
		uint32_t mode = 0;
		uint64_t sz0 = 0;
		int st = cpio_newc_stat(g_initramfs, g_initramfs_sz, p, &mode, &sz0);
		(void)sz0;
		if (st == 0) {
			if ((mode & S_IFMT) != S_IFDIR) {
				r->rax = (uint64_t)(-(int64_t)20); /* -ENOTDIR */
				return;
			}
			(void)kcopy_cstr(g_cur->cwd, sizeof(g_cur->cwd), p);
			r->rax = 0;
			return;
		}
		if (cpio_newc_has_prefix(g_initramfs, g_initramfs_sz, p)) {
			(void)kcopy_cstr(g_cur->cwd, sizeof(g_cur->cwd), p);
			r->rax = 0;
			return;
		}
		r->rax = (uint64_t)(-(int64_t)2); /* -ENOENT */
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
		/* Debug: show argv as seen by the kernel. */
		serial_write("[k] execve argv:\n");
		for (uint64_t ai = 0; ai < argc; ai++) {
			serial_write("    [");
			serial_write_u64_dec(ai);
			serial_write("] ");
			serial_write(argv_buf[ai]);
			serial_write("\n");
		}

		const uint8_t *img = 0;
		uint64_t img_sz = 0;
		if (cpio_newc_find(g_initramfs, g_initramfs_sz, path, &img, &img_sz) != 0) {
			r->rax = (uint64_t)(-(int64_t)2);
			return;
		}
		serial_write("[k] execve img_sz=0x");
		serial_write_hex(img_sz);
		serial_write("\n");
		if (img && img_sz > (0xb6a8ull + 16ull)) {
			serial_write("[k] execve src@0xb6a8: ");
			for (int i = 0; i < 16; i++) {
				uint8_t b = img[0xb6a8ull + (uint64_t)i];
				const char *hex = "0123456789abcdef";
				serial_putc(hex[(b >> 4) & 0xf]);
				serial_putc(hex[b & 0xf]);
				if (i != 15) serial_putc(' ');
			}
			serial_write("\n");
		}
		uint64_t user_entry = 0;
		uint64_t brk_init = 0;
		if (elf_load_exec(img, img_sz, &user_entry, &brk_init) != 0) {
			r->rax = (uint64_t)(-(int64_t)8); /* -ENOEXEC */
			return;
		}
		/* Sanity-check that deeper text bytes are present (sh entry calls into 0x40b6a8). */
		{
			volatile const uint8_t *p = (volatile const uint8_t *)0x40b6a8;
			serial_write("[k] execve sh@40b6a8 bytes: ");
			for (int i = 0; i < 16; i++) {
				uint8_t b = p[i];
				const char *hex = "0123456789abcdef";
				serial_putc(hex[(b >> 4) & 0xf]);
				serial_putc(hex[b & 0xf]);
				if (i != 15) serial_putc(' ');
			}
			serial_write("\n");
		}
		serial_write("[k] execve ok entry=0x");
		serial_write_hex(user_entry);
		serial_write(" brk=0x");
		serial_write_hex(brk_init);
		serial_write("\n");

		/* Track the executable image range for process snapshotting. */
		g_cur->img_base = USER_IMG_BASE;
		g_cur->img_end = brk_init;
		if (kproc_ensure_img_backup(g_cur, brk_init) != 0) {
			r->rax = (uint64_t)(-(int64_t)12); /* -ENOMEM */
			return;
		}

		/* Ensure this process has a stack backup buffer.
		 * The *active* stack is always the fixed USER_STACK_BASE..USER_STACK_TOP range.
		 */
		if (g_cur->user_stack_pages != USER_STACK_PAGES) {
			if (g_cur->user_stack_base && g_cur->user_stack_pages) {
				pmm_free_pages(g_cur->user_stack_base, g_cur->user_stack_pages);
			}
			g_cur->user_stack_base = 0;
			g_cur->user_stack_pages = 0;
		}
		if (!g_cur->user_stack_base) {
			uint64_t buf = pmm_alloc_pages_high((uint32_t)USER_STACK_PAGES);
			if (!buf) {
				r->rax = (uint64_t)(-(int64_t)12);
				return;
			}
			g_cur->user_stack_base = buf;
			g_cur->user_stack_pages = (uint32_t)USER_STACK_PAGES;
		}
		uint64_t sp = align_down_u64(USER_STACK_TOP, 16);

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
		g_cur->user_rsp = sp;
		kproc_stack_save(g_cur);
		r->rcx = user_entry;
		r->rax = 0;
		/* Save the new post-exec image into the backup buffer. */
		kproc_img_save(g_cur);
		return;
	}
	case 57: { /* fork() */
				ktrace_sys("fork", 57);
		/* Minimal fork: clone stack + image snapshot; mmaps are not copied.
		 * This is sufficient for the monacc shell's fork+exec usage.
		 */
		struct kproc *child = kproc_alloc(g_cur->pid);
		if (!child) {
			r->rax = (uint64_t)(-(int64_t)12); /* -ENOMEM */
			return;
		}
		child->img_base = g_cur->img_base;
		child->img_end = g_cur->img_end;
		if (kproc_ensure_img_backup(child, child->img_end) != 0) {
			kproc_free(child);
			r->rax = (uint64_t)(-(int64_t)12);
			return;
		}
		/* Child starts with the same image snapshot as parent. */
		kproc_img_save(g_cur);
		kmemcpy((void *)child->img_backup, (const void *)g_cur->img_backup, (size_t)(g_cur->img_end - g_cur->img_base));

		/* Clone the fixed virtual user stack via per-process backup buffers.
		 * Under identity mapping the child must use the same stack *addresses*
		 * as the parent, or pointers-into-stack break.
		 */
		if (!g_cur->user_stack_base || g_cur->user_stack_pages != USER_STACK_PAGES) {
			serial_write("[k] fork: missing parent stack backup\n");
			kproc_free(child);
			r->rax = (uint64_t)(-(int64_t)38); /* -ENOSYS */
			return;
		}
		child->user_stack_pages = (uint32_t)USER_STACK_PAGES;
		child->user_stack_base = pmm_alloc_pages_high((uint32_t)USER_STACK_PAGES);
		if (!child->user_stack_base) {
			kproc_free(child);
			r->rax = (uint64_t)(-(int64_t)12);
			return;
		}
		g_cur->user_rsp = syscall_user_rsp;
		kproc_stack_save(g_cur);
		kmemcpy((void *)child->user_stack_base, (const void *)g_cur->user_stack_base, (size_t)USER_STACK_PAGES * PAGE_SIZE);
		child->user_rsp = syscall_user_rsp;

		child->regs = *r;
		child->regs.rax = 0;
		child->regs.rcx = r->rcx;
		child->regs.r11 = r->r11;

		/* Inherit cwd and file descriptors (shared open file descriptions). */
		(void)kcopy_cstr(child->cwd, sizeof(child->cwd), g_cur->cwd);
		for (int fd = 0; fd < KFD_MAX; fd++) {
			child->fds[fd] = g_cur->fds[fd];
			if (child->fds[fd] >= 0) {
				kfile_incref((uint32_t)child->fds[fd]);
			}
		}

		/* Parent sees child's PID. */
		r->rax = child->pid;
		return;
	}
	case 61: { /* wait4(pid, wstatus, options, rusage) */
				ktrace_sys("wait4", 61);
		int pid = (int)r->rdi;
		int *wstatus = (int *)r->rsi;
		uint64_t options = r->rdx;
		(void)r->r10;

		/* WNOHANG=1 in Linux. */
		const uint64_t WNOHANG = 1;

		/* Look for any matching zombie child. */
		for (int i = 0; i < KPROC_MAX; i++) {
			struct kproc *c = &g_procs[i];
			if (!c->used) continue;
			if (c->ppid != g_cur->pid) continue;
			if (pid != -1 && (uint32_t)pid != c->pid) continue;
			if (c->state != KPROC_ZOMBIE) continue;
			if (wstatus) *wstatus = 0;
			uint32_t cpid = c->pid;
			kproc_free(c);
			r->rax = cpid;
			return;
		}

		/* No children at all? */
		int have_child = 0;
		for (int i = 0; i < KPROC_MAX; i++) {
			struct kproc *c = &g_procs[i];
			if (!c->used) continue;
			if (c->ppid != g_cur->pid) continue;
			if (pid != -1 && (uint32_t)pid != c->pid) continue;
			have_child = 1;
			break;
		}
		if (!have_child) {
			r->rax = (uint64_t)(-(int64_t)10); /* -ECHILD */
			return;
		}
		if (options & WNOHANG) {
			r->rax = 0;
			return;
		}

		/* Block and schedule someone else. */
		g_cur->state = KPROC_WAITING;
		g_cur->wait_kind = KWAIT_CHILD;
		g_cur->wait_obj = (pid == -1) ? 0u : (uint32_t)pid;
		struct kproc *next = kproc_pick_next();
		kproc_switch(r, next);
		return;
	}
	case 16: { /* ioctl(fd, request, argp) */
		int fd = (int)r->rdi;
		uint64_t req = r->rsi;
		void *argp = (void *)r->rdx;

		/* Minimal tty detection for monacc /bin/sh interactive prompt.
		 * Linux TCGETS is 0x5401.
		 */
		if (req == 0x5401u) {
			if (fd == 0 || fd == 1 || fd == 2) {
				if (argp) kmemset(argp, 0, 64);
				r->rax = 0;
				return;
			}
			r->rax = (uint64_t)(-(int64_t)25); /* -ENOTTY */
			return;
		}

		r->rax = (uint64_t)(-(int64_t)38); /* -ENOSYS */
		return;
	}
	case 60: /* exit(code) */
	case 231: /* exit_group(code) */
	{
		uint64_t code = r->rdi;
		/* Mark current process as zombie, wake waiters, and switch.
		 * If PID 1 exits and no runnable tasks remain, end QEMU.
		 */
		uint32_t pid = g_cur ? g_cur->pid : 0;
		if (g_cur) {
			kproc_close_all_fds(g_cur);
			g_cur->state = KPROC_ZOMBIE;
		}
		for (int i = 0; i < KPROC_MAX; i++) {
			struct kproc *p = &g_procs[i];
			if (!p->used) continue;
			if (p->state != KPROC_WAITING) continue;
			if (p->wait_kind != KWAIT_CHILD) continue;
			if (p->wait_obj != 0 && p->wait_obj != pid) continue;
			p->state = KPROC_RUNNABLE;
			p->wait_kind = KWAIT_NONE;
			p->wait_obj = 0;
		}
		if (pid == 1) {
			serial_write("Process exited with code ");
			serial_write_u64_dec(code);
			serial_write("\n");
			outb(0xF4, 0x10);
			halt_forever();
		}
		struct kproc *next = kproc_pick_next();
		kproc_switch(r, next);
		kproc_die_if_no_runnable();
		return;
	}
	default:
		r->rax = (uint64_t)(-(int64_t)38); /* -ENOSYS */
		return;
	}
}

