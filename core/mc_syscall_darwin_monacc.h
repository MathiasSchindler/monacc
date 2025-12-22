#pragma once

#include "mc_types.h"
#include "mc_net.h"

// Minimal Darwin hosted syscall shims for compilation with monacc.
//
// Rationale:
// - monacc intentionally has a tiny preprocessor and does not aim to parse the macOS SDK headers.
// - this header provides just enough declarations/constants to compile a first batch of tools
//   as hosted macOS programs (linked by clang), without including any system headers.
//
// As we bring up more tools, we can expand this header (or replace pieces with generated values).

// Minimal errno values used in core/ and some tools.
// (Taken from the host system's errno(3) values on macOS.)
#define MC_ENOSYS 78
#define MC_EINVAL 22
#define MC_EINTR 4
#define MC_EAGAIN 35
#define MC_ENOENT 2
#define MC_ENOTDIR 20
#define MC_EISDIR 21
#define MC_EPIPE 32
#define MC_ESPIPE 29
#define MC_EPERM 1
#define MC_EEXIST 17
#define MC_EINPROGRESS 36
#define MC_EISCONN 56
#define MC_ENOTEMPTY 66
#define MC_ELOOP 62
#define MC_EXDEV 18

// Networking/tools commonly use this for poll/connect timeouts.
// macOS errno(3): ETIMEDOUT == 60
#define MC_ETIMEDOUT 60

// seek(2) whence values (same on Linux and Darwin)
#define MC_SEEK_SET 0
#define MC_SEEK_CUR 1
#define MC_SEEK_END 2

#define MC_SIGPIPE 13

// Minimal AT_* constants used by a few tools.
#define MC_AT_FDCWD -2
// Linux constant value; translated to Darwin in wrappers where needed.
#define MC_AT_REMOVEDIR 0x0200
// Linux constant value; translated to Darwin in wrappers where needed.
#define MC_AT_SYMLINK_NOFOLLOW 0x100

// access(2) mode bits (POSIX).
#define MC_F_OK 0
#define MC_X_OK 1
#define MC_W_OK 2
#define MC_R_OK 4

// faccessat(2) flags (Linux-shaped). On macOS AT_EACCESS exists but has a different value;
// translate in mc_sys_faccessat.
#define MC_AT_EACCESS 0x0200

// File type bits (Linux-shaped tool ABI).
#define MC_S_IFMT 0170000
#define MC_S_IFREG 0100000
#define MC_S_IFDIR 0040000
#define MC_S_IFLNK 0120000

// Minimal open(2) flags used by a few tools.
// These are monacc-facing flags; we translate them to Darwin's libc flags.
#define MC_O_RDONLY   0x0000
#define MC_O_WRONLY   0x0001
#define MC_O_RDWR     0x0002
#define MC_O_CREAT    0x0040
#define MC_O_TRUNC    0x0200
#define MC_O_APPEND   0x0008
#define MC_O_CLOEXEC  0x80000
#define MC_O_DIRECTORY 0x10000
#define MC_O_NOFOLLOW 0400000

// For early bring-up, most constants are left undefined until a tool needs them.

// Minimal libc declarations (kept for future expansion; not all are used yet).
extern void _exit(int);
extern long write(int, const void *, unsigned long);
extern long read(int, void *, unsigned long);
extern int execve(const char *, char *const[], char *const[]);
extern char *getcwd(char *, unsigned long);
extern unsigned int getuid(void);
extern unsigned int getgid(void);
extern int getgroups(int, unsigned int *);
extern int uname(void *);
extern void *signal(int, void *);
extern int fork(void);
extern int waitpid(int, int *, int);
extern int clock_gettime(int, void *);
extern int nanosleep(const void *, void *);
extern int kill(int, int);
extern int fchownat(int, const char *, unsigned int, unsigned int, int);
extern int unlinkat(int, const char *, int);
extern int linkat(int, const char *, int, const char *, int);
extern int symlinkat(const char *, int, const char *);
extern int openat(int, const char *, int, ...);
extern int fcntl(int, int, ...);
extern int close(int);
extern long long lseek(int, long long, int);
extern int utimensat(int, const char *, const void *, int);
extern int mkdirat(int, const char *, int);
extern int renameat(int, const char *, int, const char *);
extern long readlinkat(int, const char *, char *, unsigned long);
extern int fstatat(int, const char *, void *, int);
extern int fstat(int, void *);
extern int fchmodat(int, const char *, int, int);
extern int faccessat(int, const char *, int, int);
extern int sysctlbyname(const char *, void *, unsigned long *, void *, unsigned long);
extern int dup(int);
extern void *fdopendir(int);
extern void *readdir(void *);
extern int closedir(void *);
extern int *__error(void);

// Minimal socket/poll libc declarations for hosted networking tools.
extern int socket(int, int, int);
extern int connect(int, const void *, mc_u32);
extern int getsockname(int, void *, mc_u32 *);
extern int setsockopt(int, int, int, const void *, mc_u32);
extern int getsockopt(int, int, int, void *, mc_u32 *);
extern long sendto(int, const void *, mc_usize, int, const void *, mc_u32);
extern long recvfrom(int, void *, mc_usize, int, void *, mc_u32 *);
extern int poll(void *, unsigned long, int);
extern void arc4random_buf(void *, unsigned long);

struct mc_utsname {
    char sysname[65];
    char nodename[65];
    char release[65];
    char version[65];
    char machine[65];
    char domainname[65];
};

struct mc_sigaction {
    void (*sa_handler)(int);
    unsigned long sa_flags;
    void (*sa_restorer)(void);
    unsigned long sa_mask[1];
};

struct mc_timespec {
    mc_i64 tv_sec;
    mc_i64 tv_nsec;
};

struct mc__host_timespec {
    long tv_sec;
    long tv_nsec;
};

// getdents64(2) entry (Linux-shaped tool ABI).
struct mc_dirent64 {
    mc_u64 d_ino;
    mc_i64 d_off;
    mc_u16 d_reclen;
    mc_u8 d_type;
    char d_name[];
} __attribute__((packed));

// Linux-shaped struct stat (tool ABI). Only a subset is commonly used.
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

// Darwin clock ids used by tools/time.c (kept minimal).
#define MC_CLOCK_REALTIME 0
#define MC_CLOCK_MONOTONIC 6

struct mc__host_utsname {
    char sysname[256];
    char nodename[256];
    char release[256];
    char version[256];
    char machine[256];
};

static inline mc_usize mc__cstrlen(const char *s) {
    const char *p = s;
    while (*p) p++;
    return (mc_usize)(p - s);
}

static inline void mc__cstr_copy_trunc65(char dst[65], const char *src) {
    mc_usize i = 0;
    for (; i < 64 && src[i]; i++) dst[i] = src[i];
    dst[i] = 0;
}

static inline mc_i64 mc__neg_errno(void) {
    int *ep = __error();
    if (!ep) return (mc_i64)-(mc_i64)MC_EINVAL;
    return (mc_i64)-(mc_i64)(*ep);
}

static inline mc_u16 mc__load_le_u16(const mc_u8 *p) {
    return (mc_u16)((mc_u16)p[0] | ((mc_u16)p[1] << 8));
}

static inline mc_u32 mc__load_le_u32(const mc_u8 *p) {
    return (mc_u32)((mc_u32)p[0] | ((mc_u32)p[1] << 8) | ((mc_u32)p[2] << 16) | ((mc_u32)p[3] << 24));
}

static inline mc_u64 mc__load_le_u64(const mc_u8 *p) {
    return (mc_u64)p[0]
        | ((mc_u64)p[1] << 8)
        | ((mc_u64)p[2] << 16)
        | ((mc_u64)p[3] << 24)
        | ((mc_u64)p[4] << 32)
        | ((mc_u64)p[5] << 40)
        | ((mc_u64)p[6] << 48)
        | ((mc_u64)p[7] << 56);
}

static inline void mc__memzero(void *dst, mc_usize n) {
    mc_u8 *p = (mc_u8 *)dst;
    for (mc_usize i = 0; i < n; i++) p[i] = 0;
}

// Raw syscall dispatch: not available in this hosted shim.
static inline mc_i64 mc_syscall0(mc_i64 n) { (void)n; return (mc_i64)-MC_ENOSYS; }
static inline mc_i64 mc_syscall1(mc_i64 n, mc_i64 a1) { (void)n; (void)a1; return (mc_i64)-MC_ENOSYS; }
static inline mc_i64 mc_syscall2(mc_i64 n, mc_i64 a1, mc_i64 a2) { (void)n; (void)a1; (void)a2; return (mc_i64)-MC_ENOSYS; }
static inline mc_i64 mc_syscall3(mc_i64 n, mc_i64 a1, mc_i64 a2, mc_i64 a3) { (void)n; (void)a1; (void)a2; (void)a3; return (mc_i64)-MC_ENOSYS; }
static inline mc_i64 mc_syscall4(mc_i64 n, mc_i64 a1, mc_i64 a2, mc_i64 a3, mc_i64 a4) { (void)n; (void)a1; (void)a2; (void)a3; (void)a4; return (mc_i64)-MC_ENOSYS; }
static inline mc_i64 mc_syscall5(mc_i64 n, mc_i64 a1, mc_i64 a2, mc_i64 a3, mc_i64 a4, mc_i64 a5) { (void)n; (void)a1; (void)a2; (void)a3; (void)a4; (void)a5; return (mc_i64)-MC_ENOSYS; }
static inline mc_i64 mc_syscall6(mc_i64 n, mc_i64 a1, mc_i64 a2, mc_i64 a3, mc_i64 a4, mc_i64 a5, mc_i64 a6) { (void)n; (void)a1; (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; return (mc_i64)-MC_ENOSYS; }

static inline mc_i64 mc_sys_read(mc_i32 fd, void *buf, mc_usize len) {
    long r = read((int)fd, buf, (unsigned long)len);
    if (r < 0) return mc__neg_errno();
    return (mc_i64)r;
}

static inline mc_i64 mc_sys_write(mc_i32 fd, const void *buf, mc_usize len) {
    long r = write((int)fd, buf, (unsigned long)len);
    if (r < 0) return mc__neg_errno();
    return (mc_i64)r;
}

// ---- networking shims (Darwin hosted) ----

// Host sockaddr layouts (minimal, SDK-free). Values are stable on macOS.
#define MC__HOST_AF_INET6 30

struct mc__host_in6_addr {
    mc_u8 s6_addr[16];
};

struct mc__host_sockaddr_in6 {
    mc_u8 sin6_len;
    mc_u8 sin6_family;
    mc_u16 sin6_port;
    mc_u32 sin6_flowinfo;
    struct mc__host_in6_addr sin6_addr;
    mc_u32 sin6_scope_id;
};

struct mc__host_sockaddr_storage {
    mc_u8 ss_len;
    mc_u8 ss_family;
    mc_u8 __data[126];
};

static inline void mc__memcpy_u8(mc_u8 *dst, const mc_u8 *src, mc_usize n) {
    for (mc_usize i = 0; i < n; i++) dst[i] = src[i];
}

static inline int mc__sockaddr_in6_to_host(const void *addr, mc_u32 addrlen, struct mc__host_sockaddr_in6 *out) {
    if (!addr || !out) return 0;
    if (addrlen < (mc_u32)sizeof(struct mc_sockaddr_in6)) return 0;
    const struct mc_sockaddr_in6 *in6 = (const struct mc_sockaddr_in6 *)addr;
    if (in6->sin6_family != (mc_u16)MC_AF_INET6) return 0;
    mc__memzero(out, (mc_usize)sizeof(*out));
    out->sin6_len = (mc_u8)sizeof(*out);
    out->sin6_family = (mc_u8)MC__HOST_AF_INET6;
    out->sin6_port = in6->sin6_port;
    out->sin6_flowinfo = in6->sin6_flowinfo;
    mc__memcpy_u8(out->sin6_addr.s6_addr, in6->sin6_addr.s6_addr, 16);
    out->sin6_scope_id = in6->sin6_scope_id;
    return 1;
}

static inline int mc__sockaddr_from_host(void *addr, mc_u32 *addrlen_inout, const struct mc__host_sockaddr_storage *src) {
    if (!addr || !addrlen_inout || !src) return 0;
    if (src->ss_family != (mc_u8)MC__HOST_AF_INET6) return 0;
    if (*addrlen_inout < (mc_u32)sizeof(struct mc_sockaddr_in6)) return 0;
    const struct mc__host_sockaddr_in6 *h = (const struct mc__host_sockaddr_in6 *)src;
    struct mc_sockaddr_in6 *out = (struct mc_sockaddr_in6 *)addr;
    mc__memzero(out, (mc_usize)sizeof(*out));
    out->sin6_family = (mc_u16)MC_AF_INET6;
    out->sin6_port = h->sin6_port;
    out->sin6_flowinfo = h->sin6_flowinfo;
    mc__memcpy_u8(out->sin6_addr.s6_addr, h->sin6_addr.s6_addr, 16);
    out->sin6_scope_id = h->sin6_scope_id;
    *addrlen_inout = (mc_u32)sizeof(*out);
    return 1;
}

static inline mc_i64 mc_sys_socket(mc_i32 domain, mc_i32 type, mc_i32 protocol) {
    int fd = socket((int)domain, (int)type, (int)protocol);
    if (fd < 0) return mc__neg_errno();
    return (mc_i64)fd;
}

static inline mc_i64 mc_sys_connect(mc_i32 sockfd, const void *addr, mc_u32 addrlen) {
    struct mc__host_sockaddr_in6 h6;
    if (mc__sockaddr_in6_to_host(addr, addrlen, &h6)) {
        if (connect((int)sockfd, (const void *)&h6, (mc_u32)sizeof(h6)) < 0) return mc__neg_errno();
        return 0;
    }

    if (connect((int)sockfd, addr, (mc_u32)addrlen) < 0) return mc__neg_errno();
    return 0;
}

static inline mc_i64 mc_sys_getsockname(mc_i32 sockfd, void *addr, mc_u32 *addrlen_inout) {
    struct mc__host_sockaddr_storage ss;
    mc_u32 sl = (mc_u32)sizeof(ss);
    if (getsockname((int)sockfd, addrlen_inout ? (void *)&ss : (void *)0, addrlen_inout ? &sl : (mc_u32 *)0) < 0) {
        return mc__neg_errno();
    }
    if (addrlen_inout) {
        mc_u32 outlen = *addrlen_inout;
        if (!mc__sockaddr_from_host(addr, &outlen, &ss)) outlen = 0;
        *addrlen_inout = outlen;
    }
    return 0;
}

static inline mc_i64 mc_sys_sendto(mc_i32 sockfd, const void *buf, mc_usize len, mc_i32 flags, const void *dest_addr, mc_u32 addrlen) {
    struct mc__host_sockaddr_in6 h6;
    if (mc__sockaddr_in6_to_host(dest_addr, addrlen, &h6)) {
        long n = sendto((int)sockfd, buf, (mc_usize)len, (int)flags, (const void *)&h6, (mc_u32)sizeof(h6));
        if (n < 0) return mc__neg_errno();
        return (mc_i64)n;
    }
    long n = sendto((int)sockfd, buf, (mc_usize)len, (int)flags, dest_addr, (mc_u32)addrlen);
    if (n < 0) return mc__neg_errno();
    return (mc_i64)n;
}

static inline mc_i64 mc_sys_recvfrom(mc_i32 sockfd, void *buf, mc_usize len, mc_i32 flags, void *src_addr, mc_u32 *addrlen_inout) {
    struct mc__host_sockaddr_storage ss;
    mc_u32 sl = (mc_u32)sizeof(ss);
    long n = recvfrom((int)sockfd, buf, (mc_usize)len, (int)flags, addrlen_inout ? (void *)&ss : (void *)0, addrlen_inout ? &sl : (mc_u32 *)0);
    if (n < 0) return mc__neg_errno();
    if (addrlen_inout) {
        mc_u32 outlen = *addrlen_inout;
        if (!mc__sockaddr_from_host(src_addr, &outlen, &ss)) outlen = 0;
        *addrlen_inout = outlen;
    }
    return (mc_i64)n;
}

static inline mc_i64 mc_sys_setsockopt(mc_i32 sockfd, mc_i32 level, mc_i32 optname, const void *optval, mc_u32 optlen) {
    if (setsockopt((int)sockfd, (int)level, (int)optname, optval, (mc_u32)optlen) < 0) return mc__neg_errno();
    return 0;
}

static inline mc_i64 mc_sys_getsockopt(mc_i32 sockfd, mc_i32 level, mc_i32 optname, void *optval, mc_u32 *optlen_inout) {
    mc_u32 sl = optlen_inout ? *optlen_inout : 0;
    if (getsockopt((int)sockfd, (int)level, (int)optname, optval, optlen_inout ? &sl : (mc_u32 *)0) < 0) return mc__neg_errno();
    if (optlen_inout) *optlen_inout = sl;
    return 0;
}

static inline mc_i64 mc_sys_poll(void *fds, mc_u64 nfds, mc_i32 timeout_ms) {
    int r = poll(fds, (unsigned long)nfds, (int)timeout_ms);
    if (r < 0) return mc__neg_errno();
    return (mc_i64)r;
}

static inline mc_i64 mc_sys_getrandom(void *buf, mc_usize buflen, mc_u32 flags) {
    (void)flags;
    arc4random_buf(buf, (unsigned long)buflen);
    return (mc_i64)buflen;
}

static inline mc_i64 mc_sys_fcntl(mc_i32 fd, mc_i32 cmd, mc_i64 arg) {
    // Darwin fcntl(2) command values (stable) without <fcntl.h>.
    const int F_GETFL_D = 3;
    const int F_SETFL_D = 4;
    // Darwin O_NONBLOCK is 0x0004.
    const long O_NONBLOCK_D = 0x0004;

    // Our tool ABI uses Linux-shaped bits for MC_O_NONBLOCK. Translate just that bit.
    if ((int)cmd == F_SETFL_D || (int)cmd == (int)MC_F_SETFL) {
        long cur = fcntl((int)fd, F_GETFL_D, 0);
        if (cur < 0) return mc__neg_errno();
        long want = cur;
        if ((arg & (mc_i64)MC_O_NONBLOCK) != 0) want |= O_NONBLOCK_D;
        else want &= ~O_NONBLOCK_D;
        long r = fcntl((int)fd, F_SETFL_D, want);
        if (r < 0) return mc__neg_errno();
        return (mc_i64)r;
    }

    if ((int)cmd == F_GETFL_D || (int)cmd == (int)MC_F_GETFL) {
        long r = fcntl((int)fd, F_GETFL_D, 0);
        if (r < 0) return mc__neg_errno();
        mc_i64 out = (mc_i64)r;
        // Normalize the nonblock bit back to our tool ABI.
        if ((r & O_NONBLOCK_D) != 0) out |= (mc_i64)MC_O_NONBLOCK;
        return out;
    }

    long r = fcntl((int)fd, (int)cmd, (long)arg);
    if (r < 0) return mc__neg_errno();
    return (mc_i64)r;
}

static inline mc_i64 mc_sys_nanosleep(const struct mc_timespec *req, struct mc_timespec *rem) {
    struct mc__host_timespec hreq;
    struct mc__host_timespec hrem;
    if (!req) return (mc_i64)-(mc_i64)MC_EINVAL;
    hreq.tv_sec = (long)req->tv_sec;
    hreq.tv_nsec = (long)req->tv_nsec;
    int r = nanosleep((const void *)&hreq, rem ? (void *)&hrem : (void *)0);
    if (r < 0) return mc__neg_errno();
    if (rem) {
        rem->tv_sec = (mc_i64)hrem.tv_sec;
        rem->tv_nsec = (mc_i64)hrem.tv_nsec;
    }
    return 0;
}

static inline mc_i64 mc_sys_lseek(mc_i32 fd, mc_i64 offset, mc_i32 whence) {
    long long r = lseek((int)fd, (long long)offset, (int)whence);
    if (r < 0) return mc__neg_errno();
    return (mc_i64)r;
}

static inline mc_i64 mc_sys_execve(const char *pathname, char *const argv[], char *const envp[]) {
    if (execve(pathname, argv, envp) < 0) return mc__neg_errno();
    return 0;
}

static inline mc_i64 mc_sys_getuid(void) {
    return (mc_i64)(mc_u64)getuid();
}

static inline mc_i64 mc_sys_getgid(void) {
    return (mc_i64)(mc_u64)getgid();
}

static inline mc_i64 mc_sys_getgroups(mc_i32 size, mc_u32 *list) {
    int r = getgroups((int)size, (unsigned int *)list);
    if (r < 0) return mc__neg_errno();
    return (mc_i64)r;
}

// Linux ABI shape: return number of bytes written including NUL on success.
static inline mc_i64 mc_sys_getcwd(char *buf, mc_usize size) {
    if (!getcwd(buf, (unsigned long)size)) return mc__neg_errno();
    mc_usize n = mc__cstrlen(buf);
    return (mc_i64)(n + 1);
}

static inline mc_i64 mc_sys_uname(struct mc_utsname *buf) {
    struct mc__host_utsname u;
    if (uname(&u) < 0) return mc__neg_errno();
    mc__cstr_copy_trunc65(buf->sysname, u.sysname);
    mc__cstr_copy_trunc65(buf->nodename, u.nodename);
    mc__cstr_copy_trunc65(buf->release, u.release);
    mc__cstr_copy_trunc65(buf->version, u.version);
    mc__cstr_copy_trunc65(buf->machine, u.machine);
    buf->domainname[0] = 0;
    return 0;
}

static inline mc_i64 mc_sys_fork(void) {
    int r = fork();
    if (r < 0) return mc__neg_errno();
    return (mc_i64)r;
}

static inline mc_i64 mc_sys_wait4(mc_i32 pid, mc_i32 *status, mc_i32 options, void *rusage) {
    (void)rusage;
    int r = waitpid((int)pid, (int *)status, (int)options);
    if (r < 0) return mc__neg_errno();
    return (mc_i64)r;
}

static inline mc_i64 mc_sys_clock_gettime(mc_i32 clk_id, struct mc_timespec *tp) {
    struct mc__host_timespec ht;
    if (clock_gettime((int)clk_id, (void *)&ht) < 0) return mc__neg_errno();
    tp->tv_sec = (mc_i64)ht.tv_sec;
    tp->tv_nsec = (mc_i64)ht.tv_nsec;
    return 0;
}

static inline mc_i64 mc_sys_kill(mc_i32 pid, mc_i32 sig) {
    if (kill((int)pid, (int)sig) < 0) return mc__neg_errno();
    return 0;
}

static inline mc_i64 mc_sys_fchownat(mc_i32 dirfd, const char *path, mc_u32 uid, mc_u32 gid, mc_i32 flags) {
    if (fchownat((int)dirfd, path, (unsigned int)uid, (unsigned int)gid, (int)flags) < 0) return mc__neg_errno();
    return 0;
}

static inline mc_i64 mc_sys_unlinkat(mc_i32 dirfd, const char *path, mc_i32 flags) {
    // Darwin uses different AT_* flag values; translate the subset we use.
    const int AT_REMOVEDIR_D = 0x0080;
    int dflags = 0;
    if (flags & (mc_i32)MC_AT_REMOVEDIR) dflags |= AT_REMOVEDIR_D;
    if (unlinkat((int)dirfd, path, dflags) < 0) return mc__neg_errno();
    return 0;
}

static inline mc_i64 mc_sys_linkat(mc_i32 olddirfd, const char *oldpath, mc_i32 newdirfd, const char *newpath, mc_i32 flags) {
    if (linkat((int)olddirfd, oldpath, (int)newdirfd, newpath, (int)flags) < 0) return mc__neg_errno();
    return 0;
}

static inline mc_i64 mc_sys_symlinkat(const char *target, mc_i32 newdirfd, const char *linkpath) {
    if (symlinkat(target, (int)newdirfd, linkpath) < 0) return mc__neg_errno();
    return 0;
}

static inline int mc__darwin_open_flags_from_mc(int mc_flags) {
    // Darwin flag values (hardcoded to avoid pulling in <fcntl.h>).
    // These are stable across modern macOS releases.
    const int O_RDONLY_D = 0x0000;
    const int O_WRONLY_D = 0x0001;
    const int O_RDWR_D = 0x0002;
    const int O_CREAT_D = 0x0200;
    const int O_TRUNC_D = 0x0400;
    const int O_APPEND_D = 0x0008;
    const int O_CLOEXEC_D = 0x1000000;
    const int O_DIRECTORY_D = 0x100000;
    const int O_NOFOLLOW_D = 0x0100;

    int out = 0;
    int acc = mc_flags & 0x3;
    if (acc == MC_O_WRONLY) out |= O_WRONLY_D;
    else if (acc == MC_O_RDWR) out |= O_RDWR_D;
    else out |= O_RDONLY_D;

    if (mc_flags & MC_O_CREAT) out |= O_CREAT_D;
    if (mc_flags & MC_O_TRUNC) out |= O_TRUNC_D;
    if (mc_flags & MC_O_APPEND) out |= O_APPEND_D;
    if (mc_flags & MC_O_CLOEXEC) out |= O_CLOEXEC_D;
    if (mc_flags & MC_O_DIRECTORY) out |= O_DIRECTORY_D;
    if (mc_flags & MC_O_NOFOLLOW) out |= O_NOFOLLOW_D;
    return out;
}

static inline mc_i64 mc_sys_openat(mc_i32 dirfd, const char *path, mc_i32 flags, mc_u32 mode) {
    int oflags = mc__darwin_open_flags_from_mc((int)flags);
    int r = openat((int)dirfd, path, oflags, (int)mode);
    if (r < 0) return mc__neg_errno();
    return (mc_i64)r;
}

static inline mc_i64 mc_sys_close(mc_i32 fd) {
    if (close((int)fd) < 0) return mc__neg_errno();
    return 0;
}

static inline mc_i64 mc_sys_utimensat(mc_i32 dirfd, const char *pathname, const struct mc_timespec times[2], mc_i32 flags) {
    struct mc__host_timespec ht[2];
    if (times) {
        ht[0].tv_sec = (long)times[0].tv_sec;
        ht[0].tv_nsec = (long)times[0].tv_nsec;
        ht[1].tv_sec = (long)times[1].tv_sec;
        ht[1].tv_nsec = (long)times[1].tv_nsec;
        if (utimensat((int)dirfd, pathname, (const void *)ht, (int)flags) < 0) return mc__neg_errno();
        return 0;
    }
    if (utimensat((int)dirfd, pathname, (const void *)0, (int)flags) < 0) return mc__neg_errno();
    return 0;
}

static inline mc_i64 mc_sys_mkdirat(mc_i32 dirfd, const char *path, mc_u32 mode) {
    if (mkdirat((int)dirfd, path, (int)mode) < 0) return mc__neg_errno();
    return 0;
}

static inline mc_i64 mc_sys_renameat(mc_i32 olddirfd, const char *oldpath, mc_i32 newdirfd, const char *newpath) {
    if (renameat((int)olddirfd, oldpath, (int)newdirfd, newpath) < 0) return mc__neg_errno();
    return 0;
}

static inline mc_i64 mc_sys_readlinkat(mc_i32 dirfd, const char *path, char *buf, mc_usize bufsiz) {
    long r = readlinkat((int)dirfd, path, buf, (unsigned long)bufsiz);
    if (r < 0) return mc__neg_errno();
    return (mc_i64)r;
}

static inline void mc__stat_from_hostbuf(struct mc_stat *out, const mc_u8 hostst[144]) {
    // This is a small, stable ABI translation for the current macOS host:
    // sizeof(struct stat)=144
    // st_dev:off0(u32) st_mode:off4(u16) st_nlink:off6(u16) st_ino:off8(u64)
    // st_uid:off16(u32) st_gid:off20(u32) st_rdev:off24(u32)
    // st_atimespec:off32(2x i64) st_mtimespec:off48 st_ctimespec:off64
    // st_size:off96(i64)
    mc__memzero(out, sizeof(*out));
    out->st_dev = (mc_u64)mc__load_le_u32(hostst + 0);
    out->st_mode = (mc_u32)mc__load_le_u16(hostst + 4);
    out->st_nlink = (mc_u64)mc__load_le_u16(hostst + 6);
    out->st_ino = mc__load_le_u64(hostst + 8);
    out->st_uid = mc__load_le_u32(hostst + 16);
    out->st_gid = mc__load_le_u32(hostst + 20);
    out->st_rdev = (mc_u64)mc__load_le_u32(hostst + 24);
    out->st_size = (mc_i64)mc__load_le_u64(hostst + 96);
    out->st_atime = mc__load_le_u64(hostst + 32);
    out->st_atime_nsec = mc__load_le_u64(hostst + 40);
    out->st_mtime = mc__load_le_u64(hostst + 48);
    out->st_mtime_nsec = mc__load_le_u64(hostst + 56);
    out->st_ctime = mc__load_le_u64(hostst + 64);
    out->st_ctime_nsec = mc__load_le_u64(hostst + 72);
}

static inline mc_i64 mc_sys_newfstatat(mc_i32 dirfd, const char *path, struct mc_stat *out, mc_i32 flags) {
    // Darwin uses different AT_* flag values; translate the subset we use.
    const int AT_SYMLINK_NOFOLLOW_D = 0x20;
    int dflags = 0;
    if (flags & (mc_i32)MC_AT_SYMLINK_NOFOLLOW) dflags |= AT_SYMLINK_NOFOLLOW_D;

    mc_u8 hostst[144];
    if (fstatat((int)dirfd, path, (void *)hostst, dflags) < 0) return mc__neg_errno();
    if (out) mc__stat_from_hostbuf(out, hostst);
    return 0;
}

static inline mc_i64 mc_sys_fstat(mc_i32 fd, struct mc_stat *out) {
    mc_u8 hostst[144];
    if (fstat((int)fd, (void *)hostst) < 0) return mc__neg_errno();
    if (out) mc__stat_from_hostbuf(out, hostst);
    return 0;
}

static inline mc_i64 mc_sys_fchmodat(mc_i32 dirfd, const char *path, mc_u32 mode, mc_i32 flags) {
    if (fchmodat((int)dirfd, path, (int)mode, (int)flags) < 0) return mc__neg_errno();
    return 0;
}

static inline mc_i64 mc_sys_faccessat(mc_i32 dirfd, const char *path, mc_i32 mode, mc_i32 flags) {
    // Translate Linux AT_EACCESS (0x200) to Darwin's AT_EACCESS (0x10).
    const int AT_EACCESS_D = 0x10;
    int dflags = 0;
    if (flags & (mc_i32)MC_AT_EACCESS) dflags |= AT_EACCESS_D;
    if (faccessat((int)dirfd, path, (int)mode, dflags) < 0) return mc__neg_errno();
    return 0;
}

static inline mc_u32 mc__align_u32(mc_u32 v, mc_u32 a) {
    return (v + (a - 1u)) & ~(a - 1u);
}

static inline mc_i64 mc_sys_getdents64(mc_i32 fd, void *dirp, mc_u32 count) {
    // Emulate Linux getdents64(2) using fdopendir(3)/readdir(3) on a dup() of FD.
    // dup() shares the file offset with FD, so repeated calls advance as expected.
    int dfd = dup((int)fd);
    if (dfd < 0) return mc__neg_errno();

    void *dir = fdopendir(dfd);
    if (!dir) {
        (void)close(dfd);
        return mc__neg_errno();
    }

    mc_u8 *out = (mc_u8 *)dirp;
    mc_u32 pos = 0;
    int *ep = __error();

    for (;;) {
        if (ep) *ep = 0;
        void *ent = readdir(dir);
        if (!ent) {
            if (ep && *ep != 0) {
                mc_i64 er = mc__neg_errno();
                (void)closedir(dir);
                return er;
            }
            break;
        }

        // Host struct dirent layout (macOS):
        // d_ino:off0(u64) d_namlen:off18(u16) d_reclen:off16(u16) d_type:off20(u8) d_name:off21
        const mc_u8 *p = (const mc_u8 *)ent;
        mc_u64 ino = mc__load_le_u64(p + 0);
        mc_u16 namlen = mc__load_le_u16(p + 18);
        mc_u8 dtype = p[20];
        const char *name = (const char *)(p + 21);

        mc_u32 reclen = (mc_u32)sizeof(struct mc_dirent64) + (mc_u32)namlen + 1u;
        reclen = mc__align_u32(reclen, 8u);
        if (reclen > (mc_u32)0xFFFFu) {
            (void)closedir(dir);
            return (mc_i64)-MC_EINVAL;
        }
        if (pos + reclen > count) {
            break;
        }

        struct mc_dirent64 *d = (struct mc_dirent64 *)(out + pos);
        d->d_ino = ino;
        d->d_off = 0;
        d->d_reclen = (mc_u16)reclen;
        d->d_type = dtype;
        for (mc_u16 i = 0; i < namlen; i++) d->d_name[i] = name[i];
        d->d_name[namlen] = 0;

        pos += reclen;
    }

    (void)closedir(dir);
    return (mc_i64)pos;
}

static inline mc_i64 mc_sys_sched_getaffinity(mc_i32 pid, mc_usize cpusetsize, void *mask) {
    (void)pid;
    if (!mask || cpusetsize == 0) return (mc_i64)-MC_EINVAL;

    mc_u8 *m = (mc_u8 *)mask;
    for (mc_usize i = 0; i < cpusetsize; i++) m[i] = 0;

    int ncpu = 1;
    unsigned long len = (unsigned long)sizeof(ncpu);
    if (sysctlbyname("hw.logicalcpu", &ncpu, &len, (void *)0, 0) != 0 || ncpu <= 0) {
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

// Linux rt_sigaction is not available on Darwin; this is only used as a
// best-effort hint by some tools (e.g. ignore SIGPIPE). Return ENOSYS.
static inline mc_i64 mc_sys_rt_sigaction(mc_i32 sig, const struct mc_sigaction *act, struct mc_sigaction *oldact, mc_usize sigsetsize) {
    (void)oldact;
    (void)sigsetsize;
    // Best-effort: only handle the common case used by tools/yes.
    // If it fails, keep running; the tool will still work but may receive SIGPIPE.
    if (sig == (mc_i32)MC_SIGPIPE && act && act->sa_handler == (void (*)(int))1) {
        void *prev = signal((int)MC_SIGPIPE, (void *)1);
        if (prev == (void *)-1) return mc__neg_errno();
        return 0;
    }
    return (mc_i64)-MC_ENOSYS;
}
