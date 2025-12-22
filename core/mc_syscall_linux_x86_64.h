#pragma once
#include "mc_types.h"

// Linux x86_64 syscall numbers (subset used by tools + compiler)
#define MC_SYS_nanosleep 35
#define MC_SYS_read 0
#define MC_SYS_write 1
#define MC_SYS_ioctl 16
#define MC_SYS_fstat 5
#define MC_SYS_lseek 8
#define MC_SYS_mmap 9
#define MC_SYS_munmap 11
#define MC_SYS_close 3
#define MC_SYS_getuid 102
#define MC_SYS_getgid 104
#define MC_SYS_getgroups 115
#define MC_SYS_openat 257
#define MC_SYS_mkdirat 258
#define MC_SYS_fchownat 260
#define MC_SYS_newfstatat 262
#define MC_SYS_unlinkat 263
#define MC_SYS_renameat 264
#define MC_SYS_linkat 265
#define MC_SYS_symlinkat 266
#define MC_SYS_readlinkat 267
#define MC_SYS_fchmodat 268
#define MC_SYS_faccessat 269
#define MC_SYS_getcwd 79
#define MC_SYS_getdents64 217
#define MC_SYS_clock_gettime 228
#define MC_SYS_kill 62
#define MC_SYS_uname 63
#define MC_SYS_sched_getaffinity 204
#define MC_SYS_execve 59
#define MC_SYS_fork 57
#define MC_SYS_vfork 58
#define MC_SYS_wait4 61
#define MC_SYS_ftruncate 77
#define MC_SYS_pipe2 293
#define MC_SYS_dup2 33
#define MC_SYS_chdir 80
#define MC_SYS_mount 165
#define MC_SYS_statfs 137
#define MC_SYS_rt_sigaction 13
#define MC_SYS_utimensat 280
#define MC_SYS_socket 41
#define MC_SYS_connect 42
#define MC_SYS_accept 43
#define MC_SYS_sendto 44
#define MC_SYS_recvfrom 45
#define MC_SYS_shutdown 48
#define MC_SYS_bind 49
#define MC_SYS_listen 50
#define MC_SYS_getsockname 51
#define MC_SYS_setsockopt 54
#define MC_SYS_getsockopt 55
#define MC_SYS_poll 7
#define MC_SYS_fcntl 72
#define MC_SYS_getrandom 318
#define MC_SYS_exit 60
#define MC_SYS_exit_group 231

// openat flags/values (minimal subset)
#define MC_AT_FDCWD (-100)
#define MC_O_RDONLY 0
#define MC_O_WRONLY 1
#define MC_O_RDWR 2
#define MC_O_CREAT 0100
#define MC_O_APPEND 02000
#define MC_O_TRUNC 01000
#define MC_O_NOFOLLOW 0400000
#define MC_O_CLOEXEC 02000000
#define MC_O_DIRECTORY 0200000

// unlinkat flags
#define MC_AT_REMOVEDIR 0x200

// *at flags
#define MC_AT_SYMLINK_NOFOLLOW 0x100
// linkat flags
#define MC_AT_SYMLINK_FOLLOW 0x400

// faccessat flags
#define MC_AT_EACCESS 0x200

// access(2) mode bits
#define MC_F_OK 0
#define MC_X_OK 1
#define MC_W_OK 2
#define MC_R_OK 4

// Minimal errno values (Linux)
#define MC_ENOENT 2
#define MC_EPERM 1
#define MC_EAGAIN 11
#define MC_EINTR 4
#define MC_EEXIST 17
#define MC_EINPROGRESS 115
#define MC_EPIPE 32
#define MC_EXDEV 18
#define MC_EADDRNOTAVAIL 99
#define MC_ENOTDIR 20
#define MC_EISDIR 21
#define MC_EINVAL 22
#define MC_ENETUNREACH 101
#define MC_EHOSTUNREACH 113
#define MC_ECONNREFUSED 111
#define MC_ETIMEDOUT 110
#define MC_EISCONN 106
#define MC_ESPIPE 29
#define MC_ELOOP 40
#define MC_ENOTEMPTY 39

// lseek whence
#define MC_SEEK_SET 0
#define MC_SEEK_CUR 1
#define MC_SEEK_END 2

// Signals (minimal)
#define MC_SIGPIPE 13

// clock_gettime clocks
#define MC_CLOCK_REALTIME 0
#define MC_CLOCK_MONOTONIC 1

// Kernel ABI timespec (x86_64)
struct mc_timespec {
	mc_i64 tv_sec;
	mc_i64 tv_nsec;
};

// uname(2)
struct mc_utsname {
	char sysname[65];
	char nodename[65];
	char release[65];
	char version[65];
	char machine[65];
	char domainname[65];
};

// statfs(2) (Linux kernel ABI)
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

// rt_sigaction(2) (minimal; only used to ignore SIGPIPE)
struct mc_sigaction {
	void (*sa_handler)(int);
	unsigned long sa_flags;
	void (*sa_restorer)(void);
	unsigned long sa_mask[1];
};

// File type bits (st_mode)
#define MC_S_IFMT 0170000
#define MC_S_IFREG 0100000
#define MC_S_IFDIR 0040000
#define MC_S_IFLNK 0120000

// getdents64(2) entry (Linux kernel ABI)
struct mc_dirent64 {
	mc_u64 d_ino;
	mc_i64 d_off;
	mc_u16 d_reclen;
	mc_u8 d_type;
	char d_name[];
} __attribute__((packed));

// Linux x86_64 struct stat (kernel ABI). Only a subset is commonly used.
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
	mc_i64 __unused[3];
};

// Raw syscall dispatch.
//
// We use inline asm stubs for all builds.
static inline mc_i64 mc_syscall0(mc_i64 n) {
	mc_i64 ret;
	__asm__ volatile("syscall" : "=a"(ret) : "a"(n) : "rcx", "r11", "memory");
	return ret;
}

static inline mc_i64 mc_syscall1(mc_i64 n, mc_i64 a1) {
	mc_i64 ret;
	__asm__ volatile("syscall" : "=a"(ret) : "a"(n), "D"(a1) : "rcx", "r11", "memory");
	return ret;
}

static inline mc_i64 mc_syscall2(mc_i64 n, mc_i64 a1, mc_i64 a2) {
	mc_i64 ret;
	__asm__ volatile("syscall" : "=a"(ret) : "a"(n), "D"(a1), "S"(a2) : "rcx", "r11", "memory");
	return ret;
}

static inline mc_i64 mc_syscall3(mc_i64 n, mc_i64 a1, mc_i64 a2, mc_i64 a3) {
	mc_i64 ret;
	__asm__ volatile("syscall" : "=a"(ret) : "a"(n), "D"(a1), "S"(a2), "d"(a3) : "rcx", "r11", "memory");
	return ret;
}

static inline mc_i64 mc_syscall4(mc_i64 n, mc_i64 a1, mc_i64 a2, mc_i64 a3, mc_i64 a4) {
	mc_i64 ret;
	register mc_i64 r10 __asm__("r10") = a4;
	__asm__ volatile("syscall" : "=a"(ret) : "a"(n), "D"(a1), "S"(a2), "d"(a3), "r"(r10) : "rcx", "r11", "memory");
	return ret;
}

static inline mc_i64 mc_syscall5(mc_i64 n, mc_i64 a1, mc_i64 a2, mc_i64 a3, mc_i64 a4, mc_i64 a5) {
	mc_i64 ret;
	register mc_i64 r10 __asm__("r10") = a4;
	register mc_i64 r8 __asm__("r8") = a5;
	__asm__ volatile("syscall" : "=a"(ret) : "a"(n), "D"(a1), "S"(a2), "d"(a3), "r"(r10), "r"(r8) : "rcx", "r11", "memory");
	return ret;
}

static inline mc_i64 mc_syscall6(mc_i64 n, mc_i64 a1, mc_i64 a2, mc_i64 a3, mc_i64 a4, mc_i64 a5, mc_i64 a6) {
	mc_i64 ret;
	register mc_i64 r10 __asm__("r10") = a4;
	register mc_i64 r8 __asm__("r8") = a5;
	register mc_i64 r9 __asm__("r9") = a6;
	__asm__ volatile(
		"syscall"
		: "=a"(ret)
		: "a"(n), "D"(a1), "S"(a2), "d"(a3), "r"(r10), "r"(r8), "r"(r9)
		: "rcx", "r11", "memory");
	return ret;
}

// Common syscall wrappers
static inline mc_i64 mc_sys_read(mc_i32 fd, void *buf, mc_usize len) {
	return mc_syscall3(MC_SYS_read, (mc_i64)fd, (mc_i64)buf, (mc_i64)len);
}

static inline mc_i64 mc_sys_write(mc_i32 fd, const void *buf, mc_usize len) {
	return mc_syscall3(MC_SYS_write, (mc_i64)fd, (mc_i64)buf, (mc_i64)len);
}

static inline mc_i64 mc_sys_ioctl(mc_i32 fd, mc_u64 req, void *arg) {
	return mc_syscall3(MC_SYS_ioctl, (mc_i64)fd, (mc_i64)req, (mc_i64)arg);
}

static inline mc_i64 mc_sys_getuid(void) {
	return mc_syscall0(MC_SYS_getuid);
}

static inline mc_i64 mc_sys_getgid(void) {
	return mc_syscall0(MC_SYS_getgid);
}

static inline mc_i64 mc_sys_getgroups(mc_i32 size, mc_u32 *list) {
	return mc_syscall2(MC_SYS_getgroups, (mc_i64)size, (mc_i64)list);
}

static inline mc_i64 mc_sys_fstat(mc_i32 fd, struct mc_stat *st) {
	return mc_syscall2(MC_SYS_fstat, (mc_i64)fd, (mc_i64)st);
}

static inline mc_i64 mc_sys_lseek(mc_i32 fd, mc_i64 offset, mc_i32 whence) {
	return mc_syscall3(MC_SYS_lseek, (mc_i64)fd, (mc_i64)offset, (mc_i64)whence);
}

static inline mc_i64 mc_sys_ftruncate(mc_i32 fd, mc_i64 length) {
	return mc_syscall2(MC_SYS_ftruncate, (mc_i64)fd, (mc_i64)length);
}

static inline mc_i64 mc_sys_newfstatat(mc_i32 dirfd, const char *path, struct mc_stat *st, mc_i32 flags) {
	return mc_syscall4(MC_SYS_newfstatat, (mc_i64)dirfd, (mc_i64)path, (mc_i64)st, (mc_i64)flags);
}

static inline mc_i64 mc_sys_fchmodat(mc_i32 dirfd, const char *path, mc_u32 mode, mc_i32 flags) {
	return mc_syscall4(MC_SYS_fchmodat, (mc_i64)dirfd, (mc_i64)path, (mc_i64)mode, (mc_i64)flags);
}

static inline mc_i64 mc_sys_faccessat(mc_i32 dirfd, const char *path, mc_i32 mode, mc_i32 flags) {
	return mc_syscall4(MC_SYS_faccessat, (mc_i64)dirfd, (mc_i64)path, (mc_i64)mode, (mc_i64)flags);
}

static inline mc_i64 mc_sys_fchownat(mc_i32 dirfd, const char *path, mc_u32 uid, mc_u32 gid, mc_i32 flags) {
	return mc_syscall5(MC_SYS_fchownat, (mc_i64)dirfd, (mc_i64)path, (mc_i64)uid, (mc_i64)gid, (mc_i64)flags);
}

static inline mc_i64 mc_sys_close(mc_i32 fd) {
	return mc_syscall1(MC_SYS_close, (mc_i64)fd);
}

static inline mc_i64 mc_sys_openat(mc_i32 dirfd, const char *path, mc_i32 flags, mc_u32 mode) {
	return mc_syscall4(MC_SYS_openat, (mc_i64)dirfd, (mc_i64)path, (mc_i64)flags, (mc_i64)mode);
}

static inline mc_i64 mc_sys_mmap(void *addr, mc_usize len, mc_i32 prot, mc_i32 flags, mc_i32 fd, mc_i64 offset) {
	return mc_syscall6(MC_SYS_mmap, (mc_i64)addr, (mc_i64)len, (mc_i64)prot, (mc_i64)flags, (mc_i64)fd, (mc_i64)offset);
}

static inline mc_i64 mc_sys_munmap(void *addr, mc_usize len) {
	return mc_syscall2(MC_SYS_munmap, (mc_i64)addr, (mc_i64)len);
}

static inline mc_i64 mc_sys_mkdirat(mc_i32 dirfd, const char *path, mc_u32 mode) {
	return mc_syscall3(MC_SYS_mkdirat, (mc_i64)dirfd, (mc_i64)path, (mc_i64)mode);
}

static inline mc_i64 mc_sys_unlinkat(mc_i32 dirfd, const char *path, mc_i32 flags) {
	return mc_syscall3(MC_SYS_unlinkat, (mc_i64)dirfd, (mc_i64)path, (mc_i64)flags);
}

static inline mc_i64 mc_sys_renameat(mc_i32 olddirfd, const char *oldpath, mc_i32 newdirfd, const char *newpath) {
	return mc_syscall4(MC_SYS_renameat, (mc_i64)olddirfd, (mc_i64)oldpath, (mc_i64)newdirfd, (mc_i64)newpath);
}

static inline mc_i64 mc_sys_getcwd(char *buf, mc_usize size) {
	return mc_syscall2(MC_SYS_getcwd, (mc_i64)buf, (mc_i64)size);
}

static inline mc_i64 mc_sys_getdents64(mc_i32 fd, void *dirp, mc_u32 count) {
	return mc_syscall3(MC_SYS_getdents64, (mc_i64)fd, (mc_i64)dirp, (mc_i64)count);
}

static inline mc_i64 mc_sys_linkat(mc_i32 olddirfd, const char *oldpath, mc_i32 newdirfd, const char *newpath, mc_i32 flags) {
	return mc_syscall5(MC_SYS_linkat, (mc_i64)olddirfd, (mc_i64)oldpath, (mc_i64)newdirfd, (mc_i64)newpath, (mc_i64)flags);
}

static inline mc_i64 mc_sys_symlinkat(const char *target, mc_i32 newdirfd, const char *linkpath) {
	return mc_syscall3(MC_SYS_symlinkat, (mc_i64)target, (mc_i64)newdirfd, (mc_i64)linkpath);
}

static inline mc_i64 mc_sys_readlinkat(mc_i32 dirfd, const char *path, char *buf, mc_usize bufsz) {
	return mc_syscall4(MC_SYS_readlinkat, (mc_i64)dirfd, (mc_i64)path, (mc_i64)buf, (mc_i64)bufsz);
}

static inline mc_i64 mc_sys_clock_gettime(mc_i32 clockid, struct mc_timespec *tp) {
	return mc_syscall2(MC_SYS_clock_gettime, (mc_i64)clockid, (mc_i64)tp);
}

static inline mc_i64 mc_sys_nanosleep(const struct mc_timespec *req, struct mc_timespec *rem) {
	return mc_syscall2(MC_SYS_nanosleep, (mc_i64)req, (mc_i64)rem);
}

static inline mc_i64 mc_sys_uname(struct mc_utsname *buf) {
	return mc_syscall1(MC_SYS_uname, (mc_i64)buf);
}

static inline mc_i64 mc_sys_statfs(const char *path, struct mc_statfs *buf) {
	return mc_syscall2(MC_SYS_statfs, (mc_i64)path, (mc_i64)buf);
}

static inline mc_i64 mc_sys_rt_sigaction(mc_i32 signum, const struct mc_sigaction *act, struct mc_sigaction *oldact, mc_usize sigsetsize) {
	return mc_syscall4(MC_SYS_rt_sigaction, (mc_i64)signum, (mc_i64)act, (mc_i64)oldact, (mc_i64)sigsetsize);
}

static inline mc_i64 mc_sys_kill(mc_i32 pid, mc_i32 sig) {
	return mc_syscall2(MC_SYS_kill, (mc_i64)pid, (mc_i64)sig);
}

static inline mc_i64 mc_sys_utimensat(mc_i32 dirfd, const char *path, const struct mc_timespec times[2], mc_i32 flags) {
	return mc_syscall4(MC_SYS_utimensat, (mc_i64)dirfd, (mc_i64)path, (mc_i64)times, (mc_i64)flags);
}

static inline mc_i64 mc_sys_execve(const char *pathname, char *const argv[], char *const envp[]) {
	return mc_syscall3(MC_SYS_execve, (mc_i64)pathname, (mc_i64)argv, (mc_i64)envp);
}

static inline mc_i64 mc_sys_pipe2(mc_i32 pipefd[2], mc_i32 flags) {
	return mc_syscall2(MC_SYS_pipe2, (mc_i64)pipefd, (mc_i64)flags);
}

static inline mc_i64 mc_sys_dup2(mc_i32 oldfd, mc_i32 newfd) {
	return mc_syscall2(MC_SYS_dup2, (mc_i64)oldfd, (mc_i64)newfd);
}

static inline mc_i64 mc_sys_mount(const char *source, const char *target, const char *filesystemtype, mc_u64 mountflags, const void *data) {
	return mc_syscall5(MC_SYS_mount, (mc_i64)source, (mc_i64)target, (mc_i64)filesystemtype, (mc_i64)mountflags, (mc_i64)data);
}

static inline mc_i64 mc_sys_chdir(const char *path) {
	return mc_syscall1(MC_SYS_chdir, (mc_i64)path);
}

static inline mc_i64 mc_sys_sched_getaffinity(mc_i32 pid, mc_usize cpusetsize, void *mask) {
	return mc_syscall3(MC_SYS_sched_getaffinity, (mc_i64)pid, (mc_i64)cpusetsize, (mc_i64)mask);
}

static inline mc_i64 mc_sys_vfork(void) {
	return mc_syscall0(MC_SYS_vfork);
}

static inline mc_i64 mc_sys_fork(void) {
	return mc_syscall0(MC_SYS_fork);
}

static inline mc_i64 mc_sys_wait4(mc_i32 pid, mc_i32 *wstatus, mc_i32 options, void *rusage) {
	return mc_syscall4(MC_SYS_wait4, (mc_i64)pid, (mc_i64)wstatus, (mc_i64)options, (mc_i64)rusage);
}

// Networking / polling
static inline mc_i64 mc_sys_socket(mc_i32 domain, mc_i32 type, mc_i32 protocol) {
	return mc_syscall3(MC_SYS_socket, (mc_i64)domain, (mc_i64)type, (mc_i64)protocol);
}

static inline mc_i64 mc_sys_connect(mc_i32 sockfd, const void *addr, mc_u32 addrlen) {
	return mc_syscall3(MC_SYS_connect, (mc_i64)sockfd, (mc_i64)addr, (mc_i64)addrlen);
}

static inline mc_i64 mc_sys_bind(mc_i32 sockfd, const void *addr, mc_u32 addrlen) {
	return mc_syscall3(MC_SYS_bind, (mc_i64)sockfd, (mc_i64)addr, (mc_i64)addrlen);
}

static inline mc_i64 mc_sys_listen(mc_i32 sockfd, mc_i32 backlog) {
	return mc_syscall2(MC_SYS_listen, (mc_i64)sockfd, (mc_i64)backlog);
}

static inline mc_i64 mc_sys_accept(mc_i32 sockfd, void *addr, mc_u32 *addrlen_inout) {
	return mc_syscall3(MC_SYS_accept, (mc_i64)sockfd, (mc_i64)addr, (mc_i64)addrlen_inout);
}

static inline mc_i64 mc_sys_shutdown(mc_i32 sockfd, mc_i32 how) {
	return mc_syscall2(MC_SYS_shutdown, (mc_i64)sockfd, (mc_i64)how);
}

static inline mc_i64 mc_sys_getsockname(mc_i32 sockfd, void *addr, mc_u32 *addrlen_inout) {
	return mc_syscall3(MC_SYS_getsockname, (mc_i64)sockfd, (mc_i64)addr, (mc_i64)addrlen_inout);
}

static inline mc_i64 mc_sys_sendto(mc_i32 sockfd, const void *buf, mc_usize len, mc_i32 flags, const void *dest_addr, mc_u32 addrlen) {
	return mc_syscall6(MC_SYS_sendto, (mc_i64)sockfd, (mc_i64)buf, (mc_i64)len, (mc_i64)flags, (mc_i64)dest_addr, (mc_i64)addrlen);
}

static inline mc_i64 mc_sys_recvfrom(mc_i32 sockfd, void *buf, mc_usize len, mc_i32 flags, void *src_addr, mc_u32 *addrlen_inout) {
	return mc_syscall6(MC_SYS_recvfrom, (mc_i64)sockfd, (mc_i64)buf, (mc_i64)len, (mc_i64)flags, (mc_i64)src_addr, (mc_i64)addrlen_inout);
}

static inline mc_i64 mc_sys_setsockopt(mc_i32 sockfd, mc_i32 level, mc_i32 optname, const void *optval, mc_u32 optlen) {
	return mc_syscall5(MC_SYS_setsockopt, (mc_i64)sockfd, (mc_i64)level, (mc_i64)optname, (mc_i64)optval, (mc_i64)optlen);
}

static inline mc_i64 mc_sys_getsockopt(mc_i32 sockfd, mc_i32 level, mc_i32 optname, void *optval, mc_u32 *optlen_inout) {
	return mc_syscall5(MC_SYS_getsockopt, (mc_i64)sockfd, (mc_i64)level, (mc_i64)optname, (mc_i64)optval, (mc_i64)optlen_inout);
}

static inline mc_i64 mc_sys_poll(void *fds, mc_u64 nfds, mc_i32 timeout_ms) {
	return mc_syscall3(MC_SYS_poll, (mc_i64)fds, (mc_i64)nfds, (mc_i64)timeout_ms);
}

static inline mc_i64 mc_sys_fcntl(mc_i32 fd, mc_i32 cmd, mc_i64 arg) {
	return mc_syscall3(MC_SYS_fcntl, (mc_i64)fd, (mc_i64)cmd, (mc_i64)arg);
}

static inline mc_i64 mc_sys_getrandom(void *buf, mc_usize buflen, mc_u32 flags) {
	return mc_syscall3(MC_SYS_getrandom, (mc_i64)buf, (mc_i64)buflen, (mc_i64)flags);
}
