#pragma once

#include "mc_types.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysctl.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "mc_net.h"

// macOS headers define some member-name macros (e.g. st_atime, sa_handler).
// These break our tool-facing structs (mc_stat, mc_sigaction, mc_in6_addr) that
// intentionally use Linux-like member names.
//
// Undefine them for the remainder of the translation unit so tools can safely
// use e.g. `struct mc_sigaction sa; sa.sa_handler = ...`.
#if defined(sa_handler)
#undef sa_handler
#endif
#if defined(st_atime)
#undef st_atime
#endif
#if defined(st_mtime)
#undef st_mtime
#endif
#if defined(st_ctime)
#undef st_ctime
#endif

// Minimal errno mapping (use the host values so tools comparing against MC_E* work).
#define MC_ENOENT ENOENT
#define MC_EPERM EPERM
#define MC_ENOSYS ENOSYS
#define MC_EAGAIN EAGAIN
#define MC_EINTR EINTR
#define MC_EEXIST EEXIST
#define MC_EINPROGRESS EINPROGRESS
#define MC_EPIPE EPIPE
#define MC_EXDEV EXDEV
#define MC_EADDRNOTAVAIL EADDRNOTAVAIL
#define MC_ENOTDIR ENOTDIR
#define MC_EISDIR EISDIR
#define MC_EINVAL EINVAL
#define MC_ENETUNREACH ENETUNREACH
#define MC_EHOSTUNREACH EHOSTUNREACH
#define MC_ECONNREFUSED ECONNREFUSED
#define MC_ETIMEDOUT ETIMEDOUT
#define MC_EISCONN EISCONN
#define MC_ESPIPE ESPIPE
#define MC_ELOOP ELOOP
#define MC_ENOTEMPTY ENOTEMPTY

// access(2) mode bits
#define MC_F_OK F_OK
#define MC_X_OK X_OK
#define MC_W_OK W_OK
#define MC_R_OK R_OK

// *at helpers
#define MC_AT_FDCWD AT_FDCWD
#define MC_AT_REMOVEDIR AT_REMOVEDIR
#define MC_AT_SYMLINK_NOFOLLOW AT_SYMLINK_NOFOLLOW
#define MC_AT_SYMLINK_FOLLOW AT_SYMLINK_FOLLOW

// faccessat flags
#if defined(AT_EACCESS)
#define MC_AT_EACCESS AT_EACCESS
#else
#define MC_AT_EACCESS 0
#endif

// open(2) flags
#define MC_O_RDONLY O_RDONLY
#define MC_O_WRONLY O_WRONLY
#define MC_O_RDWR O_RDWR
#define MC_O_CREAT O_CREAT
#define MC_O_APPEND O_APPEND
#define MC_O_TRUNC O_TRUNC

#if defined(O_NOFOLLOW)
#define MC_O_NOFOLLOW O_NOFOLLOW
#else
#define MC_O_NOFOLLOW 0
#endif

#if defined(O_CLOEXEC)
#define MC_O_CLOEXEC O_CLOEXEC
#else
#define MC_O_CLOEXEC 0
#endif

#if defined(O_DIRECTORY)
#define MC_O_DIRECTORY O_DIRECTORY
#else
#define MC_O_DIRECTORY 0
#endif

// lseek whence
#define MC_SEEK_SET SEEK_SET
#define MC_SEEK_CUR SEEK_CUR
#define MC_SEEK_END SEEK_END

// Signals
#define MC_SIGPIPE SIGPIPE

// clock ids
#define MC_CLOCK_REALTIME CLOCK_REALTIME
#define MC_CLOCK_MONOTONIC CLOCK_MONOTONIC

// Compatibility for a couple of tools that directly call mc_syscall with MC_SYS_exit_group.
// There is no exit_group on Darwin; map to SYS_exit.
#define MC_SYS_exit SYS_exit
#define MC_SYS_exit_group SYS_exit

struct mc_timespec {
	mc_i64 tv_sec;
	mc_i64 tv_nsec;
};

struct mc_utsname {
	char sysname[65];
	char nodename[65];
	char release[65];
	char version[65];
	char machine[65];
	char domainname[65];
};

// Keep the Linux-shaped structs as the tool-facing ABI and translate from host structs.
struct mc_statfs {
	mc_i64 f_type;
	mc_i64 f_bsize;
	mc_u64 f_blocks;
	mc_u64 f_bfree;
	mc_u64 f_bavail;
	mc_u64 f_files;
	mc_u64 f_ffree;
	mc_i64 f_fsid[2];
	mc_i64 f_namelen;
	mc_i64 f_frsize;
	mc_i64 f_flags;
	mc_i64 f_spare[4];
};

struct mc_sigaction {
	void (*sa_handler)(int);
	unsigned long sa_flags;
	void (*sa_restorer)(void);
	unsigned long sa_mask[1];
};

#define MC_S_IFMT S_IFMT
#define MC_S_IFREG S_IFREG
#define MC_S_IFDIR S_IFDIR
#define MC_S_IFLNK S_IFLNK

struct mc_dirent64 {
	mc_u64 d_ino;
	mc_i64 d_off;
	mc_u16 d_reclen;
	mc_u8 d_type;
	char d_name[];
} __attribute__((packed));

struct mc_stat {
	mc_u64 st_dev;
	mc_u64 st_ino;
	mc_u64 st_nlink;
	mc_u32 st_mode;
	mc_u32 st_uid;
	mc_u32 st_gid;
	mc_u32 __pad0;
	mc_u64 st_rdev;
	mc_i64 st_size;
	mc_i64 st_blksize;
	mc_i64 st_blocks;
	mc_u64 st_atime;
	mc_u64 st_atime_nsec;
	mc_u64 st_mtime;
	mc_u64 st_mtime_nsec;
	mc_u64 st_ctime;
	mc_u64 st_ctime_nsec;
	mc_i64 mc__unused[3];
};

static inline mc_i64 mc__neg_errno(void) {
	return (mc_i64)-(mc_i64)errno;
}

static inline void mc__stat_from_host(struct mc_stat *out, const struct stat *st) {
	memset(out, 0, sizeof(*out));
	out->st_dev = (mc_u64)st->st_dev;
	out->st_ino = (mc_u64)st->st_ino;
	out->st_nlink = (mc_u64)st->st_nlink;
	out->st_mode = (mc_u32)st->st_mode;
	out->st_uid = (mc_u32)st->st_uid;
	out->st_gid = (mc_u32)st->st_gid;
	out->st_rdev = (mc_u64)st->st_rdev;
	out->st_size = (mc_i64)st->st_size;
	out->st_blksize = (mc_i64)st->st_blksize;
	out->st_blocks = (mc_i64)st->st_blocks;

	// Darwin provides st_atimespec/st_mtimespec/st_ctimespec.
	out->st_atime = (mc_u64)st->st_atimespec.tv_sec;
	out->st_atime_nsec = (mc_u64)st->st_atimespec.tv_nsec;
	out->st_mtime = (mc_u64)st->st_mtimespec.tv_sec;
	out->st_mtime_nsec = (mc_u64)st->st_mtimespec.tv_nsec;
	out->st_ctime = (mc_u64)st->st_ctimespec.tv_sec;
	out->st_ctime_nsec = (mc_u64)st->st_ctimespec.tv_nsec;
}

// Raw syscall dispatch (Darwin hosted)
static inline mc_i64 mc_syscall0(mc_i64 n) {
	(void)n;
	return (mc_i64)-MC_ENOSYS;
}

static inline mc_i64 mc_syscall1(mc_i64 n, mc_i64 a1) {
	// A couple of tools/paths use the raw syscall helpers for process exit.
	// On Darwin, we implement those directly and return ENOSYS otherwise.
	if (n == MC_SYS_exit || n == MC_SYS_exit_group) {
		_exit((int)a1);
	}
	(void)n;
	(void)a1;
	return (mc_i64)-MC_ENOSYS;
}

static inline mc_i64 mc_syscall2(mc_i64 n, mc_i64 a1, mc_i64 a2) {
	(void)n;
	(void)a1;
	(void)a2;
	return (mc_i64)-MC_ENOSYS;
}

static inline mc_i64 mc_syscall3(mc_i64 n, mc_i64 a1, mc_i64 a2, mc_i64 a3) {
	(void)n;
	(void)a1;
	(void)a2;
	(void)a3;
	return (mc_i64)-MC_ENOSYS;
}

static inline mc_i64 mc_syscall4(mc_i64 n, mc_i64 a1, mc_i64 a2, mc_i64 a3, mc_i64 a4) {
	(void)n;
	(void)a1;
	(void)a2;
	(void)a3;
	(void)a4;
	return (mc_i64)-MC_ENOSYS;
}

static inline mc_i64 mc_syscall5(mc_i64 n, mc_i64 a1, mc_i64 a2, mc_i64 a3, mc_i64 a4, mc_i64 a5) {
	(void)n;
	(void)a1;
	(void)a2;
	(void)a3;
	(void)a4;
	(void)a5;
	return (mc_i64)-MC_ENOSYS;
}

static inline mc_i64 mc_syscall6(mc_i64 n, mc_i64 a1, mc_i64 a2, mc_i64 a3, mc_i64 a4, mc_i64 a5, mc_i64 a6) {
	(void)n;
	(void)a1;
	(void)a2;
	(void)a3;
	(void)a4;
	(void)a5;
	(void)a6;
	return (mc_i64)-MC_ENOSYS;
}

// Common syscall wrappers (Darwin hosted)
static inline mc_i64 mc_sys_read(mc_i32 fd, void *buf, mc_usize len) {
	ssize_t r = read(fd, buf, (size_t)len);
	if (r < 0) return mc__neg_errno();
	return (mc_i64)r;
}

static inline mc_i64 mc_sys_write(mc_i32 fd, const void *buf, mc_usize len) {
	ssize_t r = write(fd, buf, (size_t)len);
	if (r < 0) return mc__neg_errno();
	return (mc_i64)r;
}

static inline mc_i64 mc_sys_ioctl(mc_i32 fd, mc_u64 req, void *arg) {
	int r = ioctl(fd, (unsigned long)req, arg);
	if (r < 0) return mc__neg_errno();
	return (mc_i64)r;
}

static inline mc_i64 mc_sys_getuid(void) {
	return (mc_i64)getuid();
}

static inline mc_i64 mc_sys_getgid(void) {
	return (mc_i64)getgid();
}

static inline mc_i64 mc_sys_getgroups(mc_i32 size, mc_u32 *list) {
	int n = getgroups((int)size, (gid_t *)list);
	if (n < 0) return mc__neg_errno();
	return (mc_i64)n;
}

static inline mc_i64 mc_sys_fstat(mc_i32 fd, struct mc_stat *st) {
	struct stat s;
	if (fstat(fd, &s) < 0) return mc__neg_errno();
	mc__stat_from_host(st, &s);
	return 0;
}

static inline mc_i64 mc_sys_lseek(mc_i32 fd, mc_i64 offset, mc_i32 whence) {
	off_t r = lseek(fd, (off_t)offset, whence);
	if (r == (off_t)-1) return mc__neg_errno();
	return (mc_i64)r;
}

static inline mc_i64 mc_sys_ftruncate(mc_i32 fd, mc_i64 length) {
	if (ftruncate(fd, (off_t)length) < 0) return mc__neg_errno();
	return 0;
}

static inline mc_i64 mc_sys_newfstatat(mc_i32 dirfd, const char *path, struct mc_stat *st, mc_i32 flags) {
	struct stat s;
	if (fstatat(dirfd, path, &s, flags) < 0) return mc__neg_errno();
	mc__stat_from_host(st, &s);
	return 0;
}

static inline mc_i64 mc_sys_fchmodat(mc_i32 dirfd, const char *path, mc_u32 mode, mc_i32 flags) {
	if (fchmodat(dirfd, path, (mode_t)mode, flags) < 0) return mc__neg_errno();
	return 0;
}

static inline mc_i64 mc_sys_faccessat(mc_i32 dirfd, const char *path, mc_i32 mode, mc_i32 flags) {
	if (faccessat(dirfd, path, mode, flags) < 0) return mc__neg_errno();
	return 0;
}

static inline mc_i64 mc_sys_fchownat(mc_i32 dirfd, const char *path, mc_u32 uid, mc_u32 gid, mc_i32 flags) {
	if (fchownat(dirfd, path, (uid_t)uid, (gid_t)gid, flags) < 0) return mc__neg_errno();
	return 0;
}

static inline mc_i64 mc_sys_close(mc_i32 fd) {
	if (close(fd) < 0) return mc__neg_errno();
	return 0;
}

static inline mc_i64 mc_sys_openat(mc_i32 dirfd, const char *path, mc_i32 flags, mc_u32 mode) {
	int fd = openat(dirfd, path, flags, (mode_t)mode);
	if (fd < 0) return mc__neg_errno();
	return (mc_i64)fd;
}

static inline mc_i32 mc__mmap_translate_linux_flags_to_host(mc_i32 flags) {
	// Tools often use Linux numeric MAP_* values (e.g. MAP_ANONYMOUS==32).
	// Translate the common subset to the host constants.
	int out = 0;
	if (flags & 0x1) out |= MAP_SHARED;   // Linux MAP_SHARED
	if (flags & 0x2) out |= MAP_PRIVATE;  // Linux MAP_PRIVATE
	if (flags & 0x10) out |= MAP_FIXED;   // Linux MAP_FIXED
	if (flags & 0x20) {
		// Linux MAP_ANONYMOUS
		#if defined(MAP_ANONYMOUS)
		out |= MAP_ANONYMOUS;
		#elif defined(MAP_ANON)
		out |= MAP_ANON;
		#endif
	}
	return (mc_i32)out;
}

static inline mc_i64 mc_sys_mmap(void *addr, mc_usize len, mc_i32 prot, mc_i32 flags, mc_i32 fd, mc_i64 offset) {
	int host_flags = mc__mmap_translate_linux_flags_to_host(flags);
	void *p = mmap(addr, (size_t)len, prot, host_flags, fd, (off_t)offset);
	if (p == MAP_FAILED) return mc__neg_errno();
	return (mc_i64)(uintptr_t)p;
}

static inline mc_i64 mc_sys_munmap(void *addr, mc_usize len) {
	if (munmap(addr, (size_t)len) < 0) return mc__neg_errno();
	return 0;
}

static inline mc_i64 mc_sys_mkdirat(mc_i32 dirfd, const char *path, mc_u32 mode) {
	if (mkdirat(dirfd, path, (mode_t)mode) < 0) return mc__neg_errno();
	return 0;
}

static inline mc_i64 mc_sys_unlinkat(mc_i32 dirfd, const char *path, mc_i32 flags) {
	if (unlinkat(dirfd, path, flags) < 0) return mc__neg_errno();
	return 0;
}

static inline mc_i64 mc_sys_renameat(mc_i32 olddirfd, const char *oldpath, mc_i32 newdirfd, const char *newpath) {
	if (renameat(olddirfd, oldpath, newdirfd, newpath) < 0) return mc__neg_errno();
	return 0;
}

static inline mc_i64 mc_sys_getcwd(char *buf, mc_usize size) {
	char *r = getcwd(buf, (size_t)size);
	if (!r) return mc__neg_errno();
	// Linux getcwd(2) returns the number of bytes written, including the NUL.
	return (mc_i64)(strlen(buf) + 1);
}

static inline mc_i64 mc_sys_getdents64(mc_i32 fd, void *dirp, mc_u32 count) {
	(void)fd;
	(void)dirp;
	(void)count;
	return (mc_i64)-MC_ENOSYS;
}

static inline mc_i64 mc_sys_linkat(mc_i32 olddirfd, const char *oldpath, mc_i32 newdirfd, const char *newpath, mc_i32 flags) {
	if (linkat(olddirfd, oldpath, newdirfd, newpath, flags) < 0) return mc__neg_errno();
	return 0;
}

static inline mc_i64 mc_sys_symlinkat(const char *target, mc_i32 newdirfd, const char *linkpath) {
	if (symlinkat(target, newdirfd, linkpath) < 0) return mc__neg_errno();
	return 0;
}

static inline mc_i64 mc_sys_readlinkat(mc_i32 dirfd, const char *path, char *buf, mc_usize bufsz) {
	ssize_t n = readlinkat(dirfd, path, buf, (size_t)bufsz);
	if (n < 0) return mc__neg_errno();
	return (mc_i64)n;
}

static inline mc_i64 mc_sys_clock_gettime(mc_i32 clockid, struct mc_timespec *tp) {
	struct timespec t;
	if (clock_gettime(clockid, &t) < 0) return mc__neg_errno();
	tp->tv_sec = (mc_i64)t.tv_sec;
	tp->tv_nsec = (mc_i64)t.tv_nsec;
	return 0;
}

static inline mc_i64 mc_sys_nanosleep(const struct mc_timespec *req, struct mc_timespec *rem) {
	struct timespec r;
	r.tv_sec = (time_t)req->tv_sec;
	r.tv_nsec = (long)req->tv_nsec;
	struct timespec rr;
	int rc = nanosleep(&r, rem ? &rr : NULL);
	if (rc < 0) return mc__neg_errno();
	if (rem) {
		rem->tv_sec = (mc_i64)rr.tv_sec;
		rem->tv_nsec = (mc_i64)rr.tv_nsec;
	}
	return 0;
}

static inline mc_i64 mc_sys_uname(struct mc_utsname *buf) {
	struct utsname u;
	if (uname(&u) < 0) return mc__neg_errno();
	memset(buf, 0, sizeof(*buf));
	strncpy(buf->sysname, u.sysname, sizeof(buf->sysname) - 1);
	strncpy(buf->nodename, u.nodename, sizeof(buf->nodename) - 1);
	strncpy(buf->release, u.release, sizeof(buf->release) - 1);
	strncpy(buf->version, u.version, sizeof(buf->version) - 1);
	strncpy(buf->machine, u.machine, sizeof(buf->machine) - 1);
	return 0;
}

static inline mc_i64 mc_sys_statfs(const char *path, struct mc_statfs *buf) {
	struct statfs s;
	if (statfs(path, &s) < 0) return mc__neg_errno();
	memset(buf, 0, sizeof(*buf));
	buf->f_bsize = (mc_i64)s.f_bsize;
	buf->f_blocks = (mc_u64)s.f_blocks;
	buf->f_bfree = (mc_u64)s.f_bfree;
	buf->f_bavail = (mc_u64)s.f_bavail;
	buf->f_files = (mc_u64)s.f_files;
	buf->f_ffree = (mc_u64)s.f_ffree;
	buf->f_fsid[0] = (mc_i64)s.f_fsid.val[0];
	buf->f_fsid[1] = (mc_i64)s.f_fsid.val[1];
	// Darwin's `struct statfs` does not expose a max-name-length field.
	// Linux tools typically only use this for display, so provide a reasonable default.
	buf->f_namelen = 255;
	buf->f_flags = (mc_i64)s.f_flags;
	return 0;
}

static inline mc_i64 mc_sys_rt_sigaction(mc_i32 signum, const struct mc_sigaction *act, struct mc_sigaction *oldact, mc_usize sigsetsize) {
	(void)sigsetsize;
	struct sigaction sa;
	struct sigaction old;
	struct sigaction *psa = NULL;
	struct sigaction *pold = oldact ? &old : NULL;
	if (act) {
		memset(&sa, 0, sizeof(sa));
		sa.__sigaction_u.__sa_handler = act->sa_handler;
		sa.sa_flags = 0;
		sigemptyset(&sa.sa_mask);
		psa = &sa;
	}
	if (sigaction(signum, psa, pold) < 0) return mc__neg_errno();
	if (oldact) {
		memset(oldact, 0, sizeof(*oldact));
		oldact->sa_handler = old.__sigaction_u.__sa_handler;
	}
	return 0;
}

static inline mc_i64 mc_sys_kill(mc_i32 pid, mc_i32 sig) {
	if (kill((pid_t)pid, sig) < 0) return mc__neg_errno();
	return 0;
}

static inline mc_i64 mc_sys_utimensat(mc_i32 dirfd, const char *path, const struct mc_timespec times[2], mc_i32 flags) {
	struct timespec ts[2];
	if (times) {
		ts[0].tv_sec = (time_t)times[0].tv_sec;
		ts[0].tv_nsec = (long)times[0].tv_nsec;
		ts[1].tv_sec = (time_t)times[1].tv_sec;
		ts[1].tv_nsec = (long)times[1].tv_nsec;
	}
	if (utimensat(dirfd, path, times ? ts : NULL, flags) < 0) return mc__neg_errno();
	return 0;
}

static inline mc_i64 mc_sys_execve(const char *pathname, char *const argv[], char *const envp[]) {
	if (execve(pathname, argv, envp) < 0) return mc__neg_errno();
	return 0;
}

static inline mc_i64 mc_sys_pipe2(mc_i32 pipefd[2], mc_i32 flags) {
	int fds[2];
	if (pipe(fds) < 0) return mc__neg_errno();

	// Emulate CLOEXEC/NONBLOCK if requested.
	if (flags) {
		for (int i = 0; i < 2; i++) {
			if (flags & 0x02000000) {
				int fdflags = fcntl(fds[i], F_GETFD);
				if (fdflags >= 0) (void)fcntl(fds[i], F_SETFD, fdflags | FD_CLOEXEC);
			}
			if (flags & 0x00004000) {
				int fl = fcntl(fds[i], F_GETFL);
				if (fl >= 0) (void)fcntl(fds[i], F_SETFL, fl | O_NONBLOCK);
			}
		}
	}

	pipefd[0] = (mc_i32)fds[0];
	pipefd[1] = (mc_i32)fds[1];
	return 0;
}

static inline mc_i64 mc_sys_dup2(mc_i32 oldfd, mc_i32 newfd) {
	int r = dup2(oldfd, newfd);
	if (r < 0) return mc__neg_errno();
	return (mc_i64)r;
}

static inline mc_i64 mc_sys_mount(const char *source, const char *target, const char *filesystemtype, mc_u64 mountflags, const void *data) {
	(void)source;
	(void)target;
	(void)filesystemtype;
	(void)mountflags;
	(void)data;
	return (mc_i64)-MC_ENOSYS;
}

static inline mc_i64 mc_sys_chdir(const char *path) {
	if (chdir(path) < 0) return mc__neg_errno();
	return 0;
}

static inline mc_i64 mc_sys_sched_getaffinity(mc_i32 pid, mc_usize cpusetsize, void *mask) {
	(void)pid;
	mc_u8 *m = (mc_u8 *)mask;
	for (mc_usize i = 0; i < cpusetsize; i++) m[i] = 0;

	int ncpu = 1;
	size_t len = sizeof(ncpu);
	if (sysctlbyname("hw.logicalcpu", &ncpu, &len, NULL, 0) != 0 || ncpu <= 0) {
		ncpu = 1;
	}

	for (int i = 0; i < ncpu; i++) {
		mc_usize byte = (mc_usize)i / 8u;
		mc_u8 bit = (mc_u8)(1u << (mc_u8)((mc_usize)i % 8u));
		if (byte < cpusetsize) {
			m[byte] |= bit;
		}
	}
	return 0;
}

static inline mc_i64 mc_sys_vfork(void) {
	// vfork() is deprecated on macOS; fork() is fine for hosted tools.
	pid_t p = fork();
	if (p < 0) return mc__neg_errno();
	return (mc_i64)p;
}

static inline mc_i64 mc_sys_fork(void) {
	pid_t p = fork();
	if (p < 0) return mc__neg_errno();
	return (mc_i64)p;
}

static inline mc_i64 mc_sys_wait4(mc_i32 pid, mc_i32 *wstatus, mc_i32 options, void *rusage) {
	pid_t r = wait4((pid_t)pid, (int *)wstatus, options, (struct rusage *)rusage);
	if (r < 0) return mc__neg_errno();
	return (mc_i64)r;
}

// Networking / polling

static inline int mc__sockaddr_in6_to_host(const void *addr, mc_u32 addrlen, struct sockaddr_in6 *out) {
	if (!addr || !out) return 0;
	if (addrlen < (mc_u32)sizeof(struct mc_sockaddr_in6)) return 0;
	const struct mc_sockaddr_in6 *in6 = (const struct mc_sockaddr_in6 *)addr;
	if (in6->sin6_family != (mc_u16)MC_AF_INET6) return 0;

	memset(out, 0, sizeof(*out));
	out->sin6_len = (uint8_t)sizeof(*out);
	out->sin6_family = AF_INET6;
	out->sin6_port = (in_port_t)in6->sin6_port;
	out->sin6_flowinfo = (uint32_t)in6->sin6_flowinfo;
	memcpy(&out->sin6_addr, in6->sin6_addr.s6_addr, 16);
	out->sin6_scope_id = (uint32_t)in6->sin6_scope_id;
	return 1;
}

static inline int mc__sockaddr_from_host(void *addr, mc_u32 *addrlen_inout, const struct sockaddr_storage *src, socklen_t srclen) {
	if (!addr || !addrlen_inout || !src) return 0;

	if (src->ss_family == AF_INET6) {
		if (*addrlen_inout < (mc_u32)sizeof(struct mc_sockaddr_in6)) return 0;
		if (srclen < (socklen_t)sizeof(struct sockaddr_in6)) return 0;
		const struct sockaddr_in6 *h = (const struct sockaddr_in6 *)src;
		struct mc_sockaddr_in6 *out = (struct mc_sockaddr_in6 *)addr;
		memset(out, 0, sizeof(*out));
		out->sin6_family = (mc_u16)MC_AF_INET6;
		out->sin6_port = (mc_u16)h->sin6_port;
		out->sin6_flowinfo = (mc_u32)h->sin6_flowinfo;
		memcpy(out->sin6_addr.s6_addr, &h->sin6_addr, 16);
		out->sin6_scope_id = (mc_u32)h->sin6_scope_id;
		*addrlen_inout = (mc_u32)sizeof(*out);
		return 1;
	}

	return 0;
}

static inline mc_i64 mc_sys_socket(mc_i32 domain, mc_i32 type, mc_i32 protocol) {
	int fd = socket(domain, type, protocol);
	if (fd < 0) return mc__neg_errno();
	return (mc_i64)fd;
}

static inline mc_i64 mc_sys_connect(mc_i32 sockfd, const void *addr, mc_u32 addrlen) {
	struct sockaddr_in6 h6;
	if (mc__sockaddr_in6_to_host(addr, addrlen, &h6)) {
		if (connect(sockfd, (const struct sockaddr *)&h6, (socklen_t)sizeof(h6)) < 0) return mc__neg_errno();
		return 0;
	}
	if (connect(sockfd, (const struct sockaddr *)addr, (socklen_t)addrlen) < 0) return mc__neg_errno();
	return 0;
}

static inline mc_i64 mc_sys_bind(mc_i32 sockfd, const void *addr, mc_u32 addrlen) {
	struct sockaddr_in6 h6;
	if (mc__sockaddr_in6_to_host(addr, addrlen, &h6)) {
		if (bind(sockfd, (const struct sockaddr *)&h6, (socklen_t)sizeof(h6)) < 0) return mc__neg_errno();
		return 0;
	}
	if (bind(sockfd, (const struct sockaddr *)addr, (socklen_t)addrlen) < 0) return mc__neg_errno();
	return 0;
}

static inline mc_i64 mc_sys_listen(mc_i32 sockfd, mc_i32 backlog) {
	if (listen(sockfd, backlog) < 0) return mc__neg_errno();
	return 0;
}

static inline mc_i64 mc_sys_accept(mc_i32 sockfd, void *addr, mc_u32 *addrlen_inout) {
	struct sockaddr_storage ss;
	socklen_t sl = sizeof(ss);
	int fd = accept(sockfd, addrlen_inout ? (struct sockaddr *)&ss : NULL, addrlen_inout ? &sl : NULL);
	if (fd < 0) return mc__neg_errno();
	if (addrlen_inout) {
		mc_u32 outlen = *addrlen_inout;
		if (!mc__sockaddr_from_host(addr, &outlen, &ss, sl)) {
			// Best-effort: report no address.
			outlen = 0;
		}
		*addrlen_inout = outlen;
	}
	return (mc_i64)fd;
}

static inline mc_i64 mc_sys_shutdown(mc_i32 sockfd, mc_i32 how) {
	if (shutdown(sockfd, how) < 0) return mc__neg_errno();
	return 0;
}

static inline mc_i64 mc_sys_getsockname(mc_i32 sockfd, void *addr, mc_u32 *addrlen_inout) {
	struct sockaddr_storage ss;
	socklen_t sl = sizeof(ss);
	if (getsockname(sockfd, addrlen_inout ? (struct sockaddr *)&ss : NULL, addrlen_inout ? &sl : NULL) < 0) return mc__neg_errno();
	if (addrlen_inout) {
		mc_u32 outlen = *addrlen_inout;
		if (!mc__sockaddr_from_host(addr, &outlen, &ss, sl)) {
			outlen = 0;
		}
		*addrlen_inout = outlen;
	}
	return 0;
}

static inline mc_i64 mc_sys_sendto(mc_i32 sockfd, const void *buf, mc_usize len, mc_i32 flags, const void *dest_addr, mc_u32 addrlen) {
	struct sockaddr_in6 h6;
	if (mc__sockaddr_in6_to_host(dest_addr, addrlen, &h6)) {
		ssize_t n = sendto(sockfd, buf, (size_t)len, flags, (const struct sockaddr *)&h6, (socklen_t)sizeof(h6));
		if (n < 0) return mc__neg_errno();
		return (mc_i64)n;
	}
	ssize_t n = sendto(sockfd, buf, (size_t)len, flags, (const struct sockaddr *)dest_addr, (socklen_t)addrlen);
	if (n < 0) return mc__neg_errno();
	return (mc_i64)n;
}

static inline mc_i64 mc_sys_recvfrom(mc_i32 sockfd, void *buf, mc_usize len, mc_i32 flags, void *src_addr, mc_u32 *addrlen_inout) {
	struct sockaddr_storage ss;
	socklen_t sl = sizeof(ss);
	ssize_t n = recvfrom(sockfd, buf, (size_t)len, flags, addrlen_inout ? (struct sockaddr *)&ss : NULL, addrlen_inout ? &sl : NULL);
	if (n < 0) return mc__neg_errno();
	if (addrlen_inout) {
		mc_u32 outlen = *addrlen_inout;
		if (!mc__sockaddr_from_host(src_addr, &outlen, &ss, sl)) {
			outlen = 0;
		}
		*addrlen_inout = outlen;
	}
	return (mc_i64)n;
}

static inline mc_i64 mc_sys_setsockopt(mc_i32 sockfd, mc_i32 level, mc_i32 optname, const void *optval, mc_u32 optlen) {
	if (setsockopt(sockfd, level, optname, optval, (socklen_t)optlen) < 0) return mc__neg_errno();
	return 0;
}

static inline mc_i64 mc_sys_getsockopt(mc_i32 sockfd, mc_i32 level, mc_i32 optname, void *optval, mc_u32 *optlen_inout) {
	socklen_t sl = optlen_inout ? (socklen_t)*optlen_inout : 0;
	if (getsockopt(sockfd, level, optname, optval, optlen_inout ? &sl : NULL) < 0) return mc__neg_errno();
	if (optlen_inout) *optlen_inout = (mc_u32)sl;
	return 0;
}

static inline mc_i64 mc_sys_poll(void *fds, mc_u64 nfds, mc_i32 timeout_ms) {
	int r = poll((struct pollfd *)fds, (nfds_t)nfds, timeout_ms);
	if (r < 0) return mc__neg_errno();
	return (mc_i64)r;
}

static inline mc_i64 mc_sys_fcntl(mc_i32 fd, mc_i32 cmd, mc_i64 arg) {
	int r = fcntl(fd, cmd, (long)arg);
	if (r < 0) return mc__neg_errno();
	return (mc_i64)r;
}

static inline mc_i64 mc_sys_getrandom(void *buf, mc_usize buflen, mc_u32 flags) {
	(void)flags;
	arc4random_buf(buf, (size_t)buflen);
	return (mc_i64)buflen;
}
