#ifndef FS_H
#define FS_H

#include "kernel.h"
#include "proc.h"

#define KFILE_MAX 256
#define KPIPE_MAX 64
#define KPIPE_BUF 4096

enum kfile_kind {
	KFILE_KIND_NONE = 0,
	KFILE_KIND_FILE = 1,
	KFILE_KIND_DIR  = 2,
	KFILE_KIND_PIPE = 3,
	KFILE_KIND_NET  = 4,
};

/* Pipe structure */
struct kpipe {
	uint8_t used;
	uint8_t _pad[3];
	uint32_t read_refs;
	uint32_t write_refs;
	uint32_t rpos;
	uint32_t wpos;
	uint32_t count;
	uint8_t buf[KPIPE_BUF];
};

/* File/directory/pipe wrapper */
struct kfile {
	uint8_t used;
	uint8_t writable;
	uint8_t kind;
	uint8_t pipe_end;
	uint32_t refcnt;

	uint8_t dir_emit;
	const uint8_t *data;
	uint64_t size;
	uint64_t off;
	uint32_t mode;
	uint32_t pipe_id;
	uint8_t inline_data[128];
	char path[KEXEC_MAX_STR];
	uint64_t scan_off;
	uint64_t dir_off;

	// KFILE_KIND_NET
	uint32_t net_handle;
	uint32_t net_domain;
	uint32_t net_type;
	uint32_t net_proto;
	uint32_t net_flags;
};

/* Pipe operations */
struct kpipe *kpipe_get(uint32_t pipe_id);
int kpipe_alloc(void);
void kpipe_free_if_unused(uint32_t pipe_id);
void kpipe_wake_waiters(uint32_t pipe_id);

/* File operations */
struct kfile *kfile_get(uint32_t id);
int kfile_alloc(void);
void kfile_free(uint32_t id);
int kfile_alloc_file(const uint8_t *data, uint64_t size, uint32_t mode);
int kfile_alloc_dir(const char *path, uint32_t mode);
int kfile_alloc_pipe_end(uint32_t pipe_id, uint8_t end);
int kfile_alloc_net(uint32_t handle, uint32_t domain, uint32_t type, uint32_t proto);
void kfile_incref(uint32_t id);
void kfile_decref(uint32_t id);

/* File descriptor operations */
int kfd_alloc_fd(struct kproc *p, int start_fd);
int kfd_install(struct kproc *p, int fd, uint32_t kfile_id);
int kfd_install_first_free(struct kproc *p, int start_fd, uint32_t kfile_id);
struct kfile *kfd_get(int fd);
struct kfile *kfd_get_file(int fd);
struct kfile *kfd_get_dir(int fd);
struct kfile *kfd_get_pipe(int fd);
struct kfile *kfd_get_net(int fd);
int kfd_close(int fd);
void kproc_close_all_fds(struct kproc *p);

/* Initramfs */
extern const uint8_t *g_initramfs;
extern uint64_t g_initramfs_sz;

/* Global file/pipe state */
extern struct kpipe g_pipes[KPIPE_MAX];
extern struct kfile g_kfiles[KFILE_MAX];

#endif
