#pragma once

#include "mc_types.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>

#include "mc_net.h"

// Emscripten headers define some member-name macros that conflict with our
// tool-facing structs. Undefine them so we can use Linux-like names.
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

// Minimal errno mapping (use host values).
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

// Compatibility constants (numbers are unused in the emscripten build).
#define MC_SYS_exit 60
#define MC_SYS_exit_group 231

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

// Keep Linux-shaped structs as the tool-facing ABI.
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
};

static inline mc_i64 mc_sys_errno(mc_i64 ret) {
	return (ret < 0) ? -(mc_i64)errno : ret;
}

// Generic syscall fallback (unsupported in wasm; keep for compatibility).
static inline mc_i64 mc_syscall(mc_i64 num, mc_i64 a1, mc_i64 a2, mc_i64 a3, mc_i64 a4, mc_i64 a5, mc_i64 a6) {
	(void)num;
	(void)a1;
	(void)a2;
	(void)a3;
	(void)a4;
	(void)a5;
	(void)a6;
	return -MC_ENOSYS;
}

#define mc_syscall0(n) mc_syscall((n), 0, 0, 0, 0, 0, 0)
#define mc_syscall1(n, a1) mc_syscall((n), (mc_i64)(a1), 0, 0, 0, 0, 0)
#define mc_syscall2(n, a1, a2) mc_syscall((n), (mc_i64)(a1), (mc_i64)(a2), 0, 0, 0, 0)
#define mc_syscall3(n, a1, a2, a3) mc_syscall((n), (mc_i64)(a1), (mc_i64)(a2), (mc_i64)(a3), 0, 0, 0)
#define mc_syscall4(n, a1, a2, a3, a4) mc_syscall((n), (mc_i64)(a1), (mc_i64)(a2), (mc_i64)(a3), (mc_i64)(a4), 0, 0)
#define mc_syscall5(n, a1, a2, a3, a4, a5) mc_syscall((n), (mc_i64)(a1), (mc_i64)(a2), (mc_i64)(a3), (mc_i64)(a4), (mc_i64)(a5), 0)
#define mc_syscall6(n, a1, a2, a3, a4, a5, a6) mc_syscall((n), (mc_i64)(a1), (mc_i64)(a2), (mc_i64)(a3), (mc_i64)(a4), (mc_i64)(a5), (mc_i64)(a6))

static inline mc_i64 mc_sys_read(mc_i32 fd, void *buf, mc_usize len) {
	return mc_sys_errno((mc_i64)read(fd, buf, (size_t)len));
}

static inline mc_i64 mc_sys_write(mc_i32 fd, const void *buf, mc_usize len) {
	return mc_sys_errno((mc_i64)write(fd, buf, (size_t)len));
}

static inline mc_i64 mc_sys_close(mc_i32 fd) {
	return mc_sys_errno((mc_i64)close(fd));
}

static inline mc_i64 mc_sys_openat(mc_i32 dirfd, const char *path, mc_i32 flags, mc_u32 mode) {
	if (dirfd != MC_AT_FDCWD) return -MC_ENOSYS;
	return mc_sys_errno((mc_i64)open(path, flags, mode));
}

static inline mc_i64 mc_sys_mkdirat(mc_i32 dirfd, const char *path, mc_u32 mode) {
	if (dirfd != MC_AT_FDCWD) return -MC_ENOSYS;
	return mc_sys_errno((mc_i64)mkdir(path, (mode_t)mode));
}

static inline mc_i64 mc_sys_fchownat(mc_i32 dirfd, const char *path, mc_u32 uid, mc_u32 gid, mc_i32 flags) {
	(void)flags;
	if (dirfd != MC_AT_FDCWD) return -MC_ENOSYS;
	return mc_sys_errno((mc_i64)chown(path, uid, gid));
}

static inline mc_i64 mc_sys_newfstatat(mc_i32 dirfd, const char *path, struct mc_stat *st, mc_i32 flags) {
	if (dirfd != MC_AT_FDCWD) return -MC_ENOSYS;
	struct stat host_st;
	int r = fstatat(dirfd, path, &host_st, flags);
	if (r < 0) return mc_sys_errno((mc_i64)r);
	if (!st) return 0;
	st->st_dev = host_st.st_dev;
	st->st_ino = host_st.st_ino;
	st->st_nlink = host_st.st_nlink;
	st->st_mode = host_st.st_mode;
	st->st_uid = host_st.st_uid;
	st->st_gid = host_st.st_gid;
	st->st_rdev = host_st.st_rdev;
	st->st_size = host_st.st_size;
	st->st_blksize = host_st.st_blksize;
	st->st_blocks = host_st.st_blocks;
	st->st_atime = host_st.st_atim.tv_sec;
	st->st_atime_nsec = host_st.st_atim.tv_nsec;
	st->st_mtime = host_st.st_mtim.tv_sec;
	st->st_mtime_nsec = host_st.st_mtim.tv_nsec;
	st->st_ctime = host_st.st_ctim.tv_sec;
	st->st_ctime_nsec = host_st.st_ctim.tv_nsec;
	return 0;
}

static inline mc_i64 mc_sys_unlinkat(mc_i32 dirfd, const char *path, mc_i32 flags) {
	if (dirfd != MC_AT_FDCWD) return -MC_ENOSYS;
	if (flags & MC_AT_REMOVEDIR) {
		return mc_sys_errno((mc_i64)rmdir(path));
	}
	return mc_sys_errno((mc_i64)unlink(path));
}

static inline mc_i64 mc_sys_renameat(mc_i32 olddirfd, const char *oldpath, mc_i32 newdirfd, const char *newpath) {
	if (olddirfd != MC_AT_FDCWD || newdirfd != MC_AT_FDCWD) return -MC_ENOSYS;
	return mc_sys_errno((mc_i64)rename(oldpath, newpath));
}

static inline mc_i64 mc_sys_linkat(mc_i32 olddirfd, const char *oldpath, mc_i32 newdirfd, const char *newpath, mc_i32 flags) {
	(void)flags;
	if (olddirfd != MC_AT_FDCWD || newdirfd != MC_AT_FDCWD) return -MC_ENOSYS;
	return mc_sys_errno((mc_i64)link(oldpath, newpath));
}

static inline mc_i64 mc_sys_symlinkat(const char *oldpath, mc_i32 newdirfd, const char *newpath) {
	if (newdirfd != MC_AT_FDCWD) return -MC_ENOSYS;
	return mc_sys_errno((mc_i64)symlink(oldpath, newpath));
}

static inline mc_i64 mc_sys_readlinkat(mc_i32 dirfd, const char *path, char *buf, mc_usize bufsz) {
	if (dirfd != MC_AT_FDCWD) return -MC_ENOSYS;
	return mc_sys_errno((mc_i64)readlink(path, buf, (size_t)bufsz));
}

static inline mc_i64 mc_sys_fchmodat(mc_i32 dirfd, const char *path, mc_u32 mode, mc_i32 flags) {
	(void)flags;
	if (dirfd != MC_AT_FDCWD) return -MC_ENOSYS;
	return mc_sys_errno((mc_i64)chmod(path, (mode_t)mode));
}

static inline mc_i64 mc_sys_faccessat(mc_i32 dirfd, const char *path, mc_i32 mode, mc_i32 flags) {
	(void)flags;
	if (dirfd != MC_AT_FDCWD) return -MC_ENOSYS;
	return mc_sys_errno((mc_i64)access(path, mode));
}

static inline mc_i64 mc_sys_getcwd(char *buf, mc_usize size) {
	char *res = getcwd(buf, (size_t)size);
	if (!res) return -((mc_i64)errno);
	return (mc_i64)strlen(res);
}

static inline mc_i64 mc_sys_getdents64(mc_i32 fd, void *buf, mc_usize size) {
	(void)fd;
	(void)buf;
	(void)size;
	return -MC_ENOSYS;
}

static inline mc_i64 mc_sys_clock_gettime(mc_i32 clk, struct mc_timespec *ts) {
	struct timespec host_ts;
	int r = clock_gettime(clk, &host_ts);
	if (r < 0) return mc_sys_errno((mc_i64)r);
	if (ts) {
		ts->tv_sec = host_ts.tv_sec;
		ts->tv_nsec = host_ts.tv_nsec;
	}
	return 0;
}

static inline mc_i64 mc_sys_kill(mc_i32 pid, mc_i32 sig) {
	return mc_sys_errno((mc_i64)kill(pid, sig));
}

static inline mc_i64 mc_sys_uname(struct mc_utsname *out) {
	if (!out) return -MC_EINVAL;
	struct utsname host;
	int r = uname(&host);
	if (r < 0) return mc_sys_errno((mc_i64)r);
	memset(out, 0, sizeof(*out));
	(void)memcpy(out->sysname, host.sysname, sizeof(out->sysname) - 1);
	(void)memcpy(out->nodename, host.nodename, sizeof(out->nodename) - 1);
	(void)memcpy(out->release, host.release, sizeof(out->release) - 1);
	(void)memcpy(out->version, host.version, sizeof(out->version) - 1);
	(void)memcpy(out->machine, host.machine, sizeof(out->machine) - 1);
	return 0;
}

static inline mc_i64 mc_sys_sched_getaffinity(mc_i32 pid, mc_usize size, mc_u64 *mask) {
	(void)pid;
	(void)size;
	(void)mask;
	return -MC_ENOSYS;
}

static inline mc_i64 mc_sys_execve(const char *path, char *const argv[], char *const envp[]) {
	(void)path;
	(void)argv;
	(void)envp;
	return -MC_ENOSYS;
}

static inline mc_i64 mc_sys_fork(void) {
	return -MC_ENOSYS;
}

static inline mc_i64 mc_sys_vfork(void) {
	return -MC_ENOSYS;
}

static inline mc_i64 mc_sys_wait4(mc_i32 pid, mc_i32 *status, mc_i32 options, void *rusage) {
	(void)pid;
	(void)status;
	(void)options;
	(void)rusage;
	return -MC_ENOSYS;
}

static inline mc_i64 mc_sys_ftruncate(mc_i32 fd, mc_i64 len) {
	return mc_sys_errno((mc_i64)ftruncate(fd, (off_t)len));
}

static inline mc_i64 mc_sys_pipe2(mc_i32 fds[2], mc_i32 flags) {
	(void)flags;
	return mc_sys_errno((mc_i64)pipe(fds));
}

static inline mc_i64 mc_sys_dup2(mc_i32 oldfd, mc_i32 newfd) {
	return mc_sys_errno((mc_i64)dup2(oldfd, newfd));
}

static inline mc_i64 mc_sys_chdir(const char *path) {
	return mc_sys_errno((mc_i64)chdir(path));
}

static inline mc_i64 mc_sys_mount(const char *source, const char *target, const char *fstype, mc_u64 flags, const void *data) {
	(void)source;
	(void)target;
	(void)fstype;
	(void)flags;
	(void)data;
	return -MC_ENOSYS;
}

static inline mc_i64 mc_sys_statfs(const char *path, struct mc_statfs *out) {
	(void)path;
	(void)out;
	return -MC_ENOSYS;
}

static inline mc_i64 mc_sys_rt_sigaction(mc_i32 sig, const struct mc_sigaction *act, struct mc_sigaction *oldact) {
	(void)sig;
	(void)act;
	(void)oldact;
	return 0;
}

static inline mc_i64 mc_sys_utimensat(mc_i32 dirfd, const char *path, const struct mc_timespec times[2], mc_i32 flags) {
	if (dirfd != MC_AT_FDCWD) return -MC_ENOSYS;
	struct timespec host_times[2];
	if (times) {
		host_times[0].tv_sec = times[0].tv_sec;
		host_times[0].tv_nsec = times[0].tv_nsec;
		host_times[1].tv_sec = times[1].tv_sec;
		host_times[1].tv_nsec = times[1].tv_nsec;
	}
	int r = utimensat(dirfd, path, times ? host_times : 0, flags);
	return mc_sys_errno((mc_i64)r);
}

static inline mc_i64 mc_sys_socket(mc_i32 domain, mc_i32 type, mc_i32 protocol) {
	return mc_sys_errno((mc_i64)socket(domain, type, protocol));
}

static inline mc_i64 mc_sys_connect(mc_i32 fd, const struct mc_sockaddr *addr, mc_u32 addrlen) {
	return mc_sys_errno((mc_i64)connect(fd, (const struct sockaddr *)addr, (socklen_t)addrlen));
}

static inline mc_i64 mc_sys_accept(mc_i32 fd, struct mc_sockaddr *addr, mc_u32 *addrlen) {
	socklen_t len = addrlen ? (socklen_t)(*addrlen) : 0;
	int r = accept(fd, (struct sockaddr *)addr, addrlen ? &len : 0);
	if (addrlen) *addrlen = (mc_u32)len;
	return mc_sys_errno((mc_i64)r);
}

static inline mc_i64 mc_sys_sendto(mc_i32 fd, const void *buf, mc_usize len, mc_i32 flags, const struct mc_sockaddr *addr, mc_u32 addrlen) {
	return mc_sys_errno((mc_i64)sendto(fd, buf, (size_t)len, flags, (const struct sockaddr *)addr, (socklen_t)addrlen));
}

static inline mc_i64 mc_sys_recvfrom(mc_i32 fd, void *buf, mc_usize len, mc_i32 flags, struct mc_sockaddr *addr, mc_u32 *addrlen) {
	socklen_t len_in = addrlen ? (socklen_t)(*addrlen) : 0;
	int r = (int)recvfrom(fd, buf, (size_t)len, flags, (struct sockaddr *)addr, addrlen ? &len_in : 0);
	if (addrlen) *addrlen = (mc_u32)len_in;
	return mc_sys_errno((mc_i64)r);
}

static inline mc_i64 mc_sys_shutdown(mc_i32 fd, mc_i32 how) {
	return mc_sys_errno((mc_i64)shutdown(fd, how));
}

static inline mc_i64 mc_sys_bind(mc_i32 fd, const struct mc_sockaddr *addr, mc_u32 addrlen) {
	return mc_sys_errno((mc_i64)bind(fd, (const struct sockaddr *)addr, (socklen_t)addrlen));
}

static inline mc_i64 mc_sys_listen(mc_i32 fd, mc_i32 backlog) {
	return mc_sys_errno((mc_i64)listen(fd, backlog));
}

static inline mc_i64 mc_sys_getsockname(mc_i32 fd, struct mc_sockaddr *addr, mc_u32 *addrlen) {
	socklen_t len = addrlen ? (socklen_t)(*addrlen) : 0;
	int r = getsockname(fd, (struct sockaddr *)addr, addrlen ? &len : 0);
	if (addrlen) *addrlen = (mc_u32)len;
	return mc_sys_errno((mc_i64)r);
}

static inline mc_i64 mc_sys_setsockopt(mc_i32 fd, mc_i32 level, mc_i32 optname, const void *optval, mc_u32 optlen) {
	return mc_sys_errno((mc_i64)setsockopt(fd, level, optname, optval, (socklen_t)optlen));
}

static inline mc_i64 mc_sys_getsockopt(mc_i32 fd, mc_i32 level, mc_i32 optname, void *optval, mc_u32 *optlen) {
	socklen_t len = optlen ? (socklen_t)(*optlen) : 0;
	int r = getsockopt(fd, level, optname, optval, optlen ? &len : 0);
	if (optlen) *optlen = (mc_u32)len;
	return mc_sys_errno((mc_i64)r);
}

static inline mc_i64 mc_sys_poll(struct mc_pollfd *fds, mc_u32 nfds, mc_i32 timeout) {
	return mc_sys_errno((mc_i64)poll((struct pollfd *)fds, nfds, timeout));
}

static inline mc_i64 mc_sys_fcntl(mc_i32 fd, mc_i32 cmd, mc_i64 arg) {
	return mc_sys_errno((mc_i64)fcntl(fd, cmd, (long)arg));
}

static inline mc_i64 mc_sys_getrandom(void *buf, mc_usize len, mc_u32 flags) {
	(void)buf;
	(void)len;
	(void)flags;
	return -MC_ENOSYS;
}

static inline mc_i64 mc_sys_nanosleep(const struct mc_timespec *req, struct mc_timespec *rem) {
	struct timespec host_req;
	struct timespec host_rem;
	if (req) {
		host_req.tv_sec = req->tv_sec;
		host_req.tv_nsec = req->tv_nsec;
	}
	int r = nanosleep(req ? &host_req : 0, rem ? &host_rem : 0);
	if (r < 0) return mc_sys_errno((mc_i64)r);
	if (rem) {
		rem->tv_sec = host_rem.tv_sec;
		rem->tv_nsec = host_rem.tv_nsec;
	}
	return 0;
}

static inline mc_i64 mc_sys_mmap(void *addr, mc_usize len, mc_i32 prot, mc_i32 flags, mc_i32 fd, mc_i64 off) {
	void *res = mmap(addr, (size_t)len, prot, flags, fd, (off_t)off);
	if (res == MAP_FAILED) return -((mc_i64)errno);
	return (mc_i64)(intptr_t)res;
}

static inline mc_i64 mc_sys_munmap(void *addr, mc_usize len) {
	return mc_sys_errno((mc_i64)munmap(addr, (size_t)len));
}

static inline mc_i64 mc_sys_lseek(mc_i32 fd, mc_i64 off, mc_i32 whence) {
	return mc_sys_errno((mc_i64)lseek(fd, (off_t)off, whence));
}

static inline mc_i64 mc_sys_ioctl(mc_i32 fd, mc_i64 req, void *arg) {
	return mc_sys_errno((mc_i64)ioctl(fd, (unsigned long)req, arg));
}

static inline mc_i64 mc_sys_fstat(mc_i32 fd, struct mc_stat *st) {
	struct stat host_st;
	int r = fstat(fd, &host_st);
	if (r < 0) return mc_sys_errno((mc_i64)r);
	if (!st) return 0;
	st->st_dev = host_st.st_dev;
	st->st_ino = host_st.st_ino;
	st->st_nlink = host_st.st_nlink;
	st->st_mode = host_st.st_mode;
	st->st_uid = host_st.st_uid;
	st->st_gid = host_st.st_gid;
	st->st_rdev = host_st.st_rdev;
	st->st_size = host_st.st_size;
	st->st_blksize = host_st.st_blksize;
	st->st_blocks = host_st.st_blocks;
	st->st_atime = host_st.st_atim.tv_sec;
	st->st_atime_nsec = host_st.st_atim.tv_nsec;
	st->st_mtime = host_st.st_mtim.tv_sec;
	st->st_mtime_nsec = host_st.st_mtim.tv_nsec;
	st->st_ctime = host_st.st_ctim.tv_sec;
	st->st_ctime_nsec = host_st.st_ctim.tv_nsec;
	return 0;
}

static inline mc_i64 mc_sys_getuid(void) {
	return (mc_i64)getuid();
}

static inline mc_i64 mc_sys_getgid(void) {
	return (mc_i64)getgid();
}

static inline mc_i64 mc_sys_getgroups(mc_i32 size, mc_u32 *list) {
	return mc_sys_errno((mc_i64)getgroups(size, (gid_t *)list));
}

static inline mc_i64 mc_sys_exit(mc_i32 code) {
	_exit(code);
	return 0;
}

static inline mc_i64 mc_sys_exit_group(mc_i32 code) {
	_exit(code);
	return 0;
}