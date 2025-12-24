#include "kernel.h"
#include "fs.h"
#include "proc.h"
#include "sys.h"
#include "net.h"

/* Global file/pipe state */
struct kpipe g_pipes[KPIPE_MAX];
struct kfile g_kfiles[KFILE_MAX];

/* Initramfs module cached for syscalls like execve(). */
const uint8_t *g_initramfs = 0;
uint64_t g_initramfs_sz = 0;

/* Pipe operations */
struct kpipe *kpipe_get(uint32_t pipe_id) {
	if (pipe_id >= (uint32_t)KPIPE_MAX) return 0;
	if (!g_pipes[pipe_id].used) return 0;
	return &g_pipes[pipe_id];
}

int kpipe_alloc(void) {
	for (int i = 0; i < KPIPE_MAX; i++) {
		if (!g_pipes[i].used) {
			kmemset(&g_pipes[i], 0, sizeof(g_pipes[i]));
			g_pipes[i].used = 1;
			return i;
		}
	}
	return -1;
}

void kpipe_free_if_unused(uint32_t pipe_id) {
	struct kpipe *p = kpipe_get(pipe_id);
	if (!p) return;
	if (p->read_refs == 0 && p->write_refs == 0) {
		kmemset(p, 0, sizeof(*p));
	}
}

void kpipe_wake_waiters(uint32_t pipe_id) {
	struct kpipe *pp = kpipe_get(pipe_id);
	for (int i = 0; i < KPROC_MAX; i++) {
		struct kproc *p = &g_procs[i];
		if (!p->used) continue;
		if (p->state != KPROC_WAITING) continue;
		if (p->wait_obj != pipe_id) continue;
		if (p->wait_kind == KWAIT_PIPE_READ) {
			if (!pp || pp->count > 0 || (pp && pp->write_refs == 0)) {
				p->state = KPROC_RUNNABLE;
				p->wait_kind = KWAIT_NONE;
				p->wait_obj = 0;
			}
		} else if (p->wait_kind == KWAIT_PIPE_WRITE) {
			if (!pp || (pp->count < KPIPE_BUF && pp->read_refs > 0)) {
				p->state = KPROC_RUNNABLE;
				p->wait_kind = KWAIT_NONE;
				p->wait_obj = 0;
			}
		}
	}
}

/* File operations */
struct kfile *kfile_get(uint32_t id) {
	if (id >= (uint32_t)KFILE_MAX) return 0;
	if (!g_kfiles[id].used) return 0;
	return &g_kfiles[id];
}

int kfile_alloc(void) {
	for (int i = 0; i < KFILE_MAX; i++) {
		if (!g_kfiles[i].used) {
			kmemset(&g_kfiles[i], 0, sizeof(g_kfiles[i]));
			g_kfiles[i].used = 1;
			g_kfiles[i].refcnt = 0;
			return i;
		}
	}
	return -1;
}

void kfile_free(uint32_t id) {
	struct kfile *f = kfile_get(id);
	if (!f) return;
	kmemset(f, 0, sizeof(*f));
}

int kfile_alloc_file(const uint8_t *data, uint64_t size, uint32_t mode) {
	int id = kfile_alloc();
	if (id < 0) return -1;
	struct kfile *f = &g_kfiles[id];
	f->writable = 0;
	f->kind = (uint8_t)KFILE_KIND_FILE;
	f->data = data;
	f->size = size;
	f->off = 0;
	f->mode = mode;
	return id;
}

int kfile_alloc_dir(const char *path, uint32_t mode) {
	int id = kfile_alloc();
	if (id < 0) return -1;
	struct kfile *d = &g_kfiles[id];
	d->writable = 0;
	d->kind = (uint8_t)KFILE_KIND_DIR;
	d->mode = mode;
	if (path) {
		(void)kcopy_cstr(d->path, (uint64_t)sizeof(d->path), path);
	}
	d->scan_off = 0;
	d->dir_emit = 0;
	d->dir_off = 0;
	return id;
}

int kfile_alloc_pipe_end(uint32_t pipe_id, uint8_t end) {
	int id = kfile_alloc();
	if (id < 0) return -1;
	struct kfile *f = &g_kfiles[id];
	f->kind = (uint8_t)KFILE_KIND_PIPE;
	f->pipe_id = pipe_id;
	f->pipe_end = end;
	return id;
}

int kfile_alloc_net(uint32_t handle, uint32_t domain, uint32_t type, uint32_t proto) {
	int id = kfile_alloc();
	if (id < 0) return -1;
	struct kfile *f = &g_kfiles[id];
	f->kind = (uint8_t)KFILE_KIND_NET;
	f->net_handle = handle;
	f->net_domain = domain;
	f->net_type = type;
	f->net_proto = proto;
	f->net_flags = 0;
	return id;
}

void kfile_incref(uint32_t id) {
	struct kfile *f = kfile_get(id);
	if (!f) return;
	f->refcnt++;
	if (f->kind == (uint8_t)KFILE_KIND_PIPE) {
		struct kpipe *p = kpipe_get(f->pipe_id);
		if (p) {
			if (f->pipe_end == 0) p->read_refs++;
			else p->write_refs++;
			kpipe_wake_waiters(f->pipe_id);
		}
	}
}

void kfile_decref(uint32_t id) {
	struct kfile *f = kfile_get(id);
	if (!f) return;
	if (f->refcnt == 0) return;
	f->refcnt--;
	if (f->kind == (uint8_t)KFILE_KIND_PIPE) {
		struct kpipe *p = kpipe_get(f->pipe_id);
		if (p) {
			if (f->pipe_end == 0) {
				if (p->read_refs) p->read_refs--;
			} else {
				if (p->write_refs) p->write_refs--;
			}
			kpipe_wake_waiters(f->pipe_id);
			kpipe_free_if_unused(f->pipe_id);
		}
	}
	if (f->refcnt == 0) {
		if (f->kind == (uint8_t)KFILE_KIND_NET) {
			// Best-effort close; ignore errors (proxy may be absent).
			(void)netproxy_close(f->net_handle);
		}
		kfile_free(id);
	}
}

/* File descriptor operations */
int kfd_alloc_fd(struct kproc *p, int start_fd) {
	if (!p) return -1;
	if (start_fd < 0) start_fd = 0;
	for (int fd = start_fd; fd < KFD_MAX; fd++) {
		if (p->fds[fd] < 0) return fd;
	}
	return -1;
}

int kfd_install(struct kproc *p, int fd, uint32_t kfile_id) {
	if (!p) return -1;
	if (fd < 0 || fd >= KFD_MAX) return -1;
	if (p->fds[fd] >= 0) {
		kfile_decref((uint32_t)p->fds[fd]);
		p->fds[fd] = -1;
	}
	p->fds[fd] = (int32_t)kfile_id;
	kfile_incref(kfile_id);
	return 0;
}

int kfd_install_first_free(struct kproc *p, int start_fd, uint32_t kfile_id) {
	int fd = kfd_alloc_fd(p, start_fd);
	if (fd < 0) return -1;
	if (kfd_install(p, fd, kfile_id) != 0) return -1;
	return fd;
}

struct kfile *kfd_get(int fd) {
	if (!g_cur) return 0;
	if (fd < 0 || fd >= KFD_MAX) return 0;
	int32_t id = g_cur->fds[fd];
	if (id < 0) return 0;
	return kfile_get((uint32_t)id);
}

struct kfile *kfd_get_file(int fd) {
	struct kfile *f = kfd_get(fd);
	if (!f) return 0;
	if (f->kind != (uint8_t)KFILE_KIND_FILE) return 0;
	return f;
}

struct kfile *kfd_get_dir(int fd) {
	struct kfile *f = kfd_get(fd);
	if (!f) return 0;
	if (f->kind != (uint8_t)KFILE_KIND_DIR) return 0;
	return f;
}

struct kfile *kfd_get_pipe(int fd) {
	struct kfile *f = kfd_get(fd);
	if (!f) return 0;
	if (f->kind != (uint8_t)KFILE_KIND_PIPE) return 0;
	return f;
}

struct kfile *kfd_get_net(int fd) {
	struct kfile *f = kfd_get(fd);
	if (!f) return 0;
	if (f->kind != (uint8_t)KFILE_KIND_NET) return 0;
	return f;
}

int kfd_close(int fd) {
	if (!g_cur) return -1;
	if (fd < 0 || fd >= KFD_MAX) return -1;
	if (fd <= 2 && g_cur->fds[fd] < 0) return 0;
	if (g_cur->fds[fd] < 0) return -1;
	kfile_decref((uint32_t)g_cur->fds[fd]);
	g_cur->fds[fd] = -1;
	return 0;
}

void kproc_close_all_fds(struct kproc *p) {
	if (!p) return;
	for (int fd = 0; fd < KFD_MAX; fd++) {
		if (p->fds[fd] >= 0) {
			kfile_decref((uint32_t)p->fds[fd]);
			p->fds[fd] = -1;
		}
	}
}
