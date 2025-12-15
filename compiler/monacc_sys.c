#include "monacc.h"

#ifndef SELFHOST
static int xsys_is_err(long r) {
    // Linux raw syscalls return -errno on failure, in range [-4095, -1].
    return (unsigned long)r >= (unsigned long)-4095;
}

static int xsys_openat(const char *path, int flags, unsigned int mode) {
    long r = (long)mc_sys_openat((mc_i32)MC_AT_FDCWD, path, (mc_i32)flags, (mc_u32)mode);
    if (xsys_is_err(r)) return -1;
    return (int)r;
}

static int xsys_close(int fd) {
    long r = (long)mc_sys_close((mc_i32)fd);
    if (xsys_is_err(r)) return -1;
    return 0;
}

static ssize_t xsys_read(int fd, void *buf, size_t len) {
    long r = (long)mc_sys_read((mc_i32)fd, buf, (mc_usize)len);
    if (xsys_is_err(r)) return (ssize_t)-1;
    return (ssize_t)r;
}

static ssize_t xsys_write(int fd, const void *buf, size_t len) {
    long r = (long)mc_sys_write((mc_i32)fd, buf, (mc_usize)len);
    if (xsys_is_err(r)) return (ssize_t)-1;
    return (ssize_t)r;
}

static mc_i64 xsys_lseek(int fd, mc_i64 offset, int whence) {
    long r = (long)mc_sys_lseek((mc_i32)fd, (mc_i64)offset, (mc_i32)whence);
    if (xsys_is_err(r)) return (mc_i64)-1;
    return (mc_i64)r;
}

static int xsys_ftruncate(int fd, mc_i64 length) {
    long r = (long)mc_sys_ftruncate((mc_i32)fd, (mc_i64)length);
    if (xsys_is_err(r)) return -1;
    return 0;
}

static int xsys_unlink(const char *path) {
    long r = (long)mc_sys_unlinkat((mc_i32)MC_AT_FDCWD, path, 0);
    if (xsys_is_err(r)) return -1;
    return 0;
}

static pid_t xsys_fork(void) {
    long r = (long)mc_sys_fork();
    if (xsys_is_err(r)) return (pid_t)-1;
    return (pid_t)r;
}

static int xsys_waitpid(pid_t pid, int *status, int options) {
    long r = (long)mc_sys_wait4((mc_i32)pid, (mc_i32 *)status, (mc_i32)options, 0);
    if (xsys_is_err(r)) return -1;
    return (int)r;
}

static int xsys_execve(const char *path, char *const argv[], char *const envp[]) {
    long r = (long)mc_sys_execve(path, argv, envp);
    if (xsys_is_err(r)) return -1;
    return -1;
}

__attribute__((noreturn)) void _exit(int status) {
    (void)mc_syscall1(MC_SYS_exit, (mc_i64)status);
    for (;;) {
    }
}

static int xsys_path_exists(const char *path) {
    // We only care whether it exists; struct size is plenty for kernel ABI.
    struct {
        unsigned long _pad[32];
    } st;
    long r = (long)mc_sys_newfstatat((mc_i32)MC_AT_FDCWD, path, (struct mc_stat *)&st, 0);
    return xsys_is_err(r) ? 0 : 1;
}
#endif

#ifdef SELFHOST
// Avoid pulling in <unistd.h>/<fcntl.h>. Declare just what we use.
pid_t fork(void);
pid_t waitpid(pid_t pid, int *status, int options);
void _exit(int status);

// Use libc's `syscall()` as a minimal escape hatch in SELFHOST builds.
// This avoids relying on the `execve` symbol while keeping the code C-only
// (SELFHOST can't compile inline-asm syscall stubs).
long syscall(long number, ...);

static int xs_openat(const char *path, int flags, unsigned int mode) {
    return (int)syscall(MC_SYS_openat, (long)MC_AT_FDCWD, path, flags, mode);
}

static int xs_close(int fd) {
    return (int)syscall(MC_SYS_close, fd);
}

static ssize_t xs_read(int fd, void *buf, size_t count) {
    return (ssize_t)syscall(MC_SYS_read, fd, buf, count);
}

static ssize_t xs_write(int fd, const void *buf, size_t count) {
    return (ssize_t)syscall(MC_SYS_write, fd, buf, count);
}

static int xs_unlink(const char *path) {
    return (int)syscall(MC_SYS_unlinkat, (long)MC_AT_FDCWD, path, 0);
}

static mc_i64 xs_lseek(int fd, mc_i64 offset, int whence) {
    return (mc_i64)syscall(MC_SYS_lseek, fd, offset, whence);
}

static int xs_ftruncate(int fd, mc_i64 length) {
    return (int)syscall(MC_SYS_ftruncate, fd, length);
}
#endif

#ifndef SELFHOST
static char **g_start_envp;

void mc_set_start_envp(char **envp) {
    g_start_envp = envp;
}
#endif

// Tiny syscall wrappers used to gradually shrink libc surface area.
//
// NOTE: We intentionally avoid reading/setting errno to keep the compiler's
// libc surface minimal and keep SELFHOST predictable.

// ===== Minimal allocator =====
//
// Hosted build: avoid libc malloc family by using an mmap-backed bump allocator.
// We keep `free()` as a no-op; this is fine for the compiler's short-lived process.
//
// SELFHOST build: delegate to libc allocation for simplicity.

#ifdef SELFHOST

// Avoid pulling in <stdlib.h> (SELFHOST uses stub headers). Declare just what we use.
void *malloc(size_t size);
void *calloc(size_t nmemb, size_t size);
void *realloc(void *ptr, size_t size);
void free(void *ptr);

void *monacc_malloc(size_t size) {
    return malloc(size);
}

void *monacc_calloc(size_t nmemb, size_t size) {
    return calloc(nmemb, size);
}

void *monacc_realloc(void *ptr, size_t size) {
    return realloc(ptr, size);
}

void monacc_free(void *ptr) {
    free(ptr);
}

#else
//
#ifndef PROT_READ
#define PROT_READ 0x1
#endif
#ifndef PROT_WRITE
#define PROT_WRITE 0x2
#endif
#ifndef MAP_PRIVATE
#define MAP_PRIVATE 0x02
#endif
#ifndef MAP_ANONYMOUS
#define MAP_ANONYMOUS 0x20
#endif

typedef struct {
    size_t size;
} MonaccAllocHdr;

static unsigned char *g_alloc_cur;
static size_t g_alloc_left;

static size_t align_up_size(size_t n, size_t a) {
    return (n + (a - 1)) & ~(a - 1);
}

static void *xsys_mmap_anon(size_t len) {
    long r = (long)mc_syscall6(MC_SYS_mmap, (mc_i64)0, (mc_i64)len, (mc_i64)(PROT_READ | PROT_WRITE),
                              (mc_i64)(MAP_PRIVATE | MAP_ANONYMOUS), (mc_i64)-1, (mc_i64)0);
    if (xsys_is_err(r)) return NULL;
    return (void *)r;
}

void *monacc_malloc(size_t size) {
    if (size == 0) size = 1;

    const size_t align = 16;
    size_t total = sizeof(MonaccAllocHdr) + size;
    total = align_up_size(total, align);

    if (total < size) return NULL; // overflow

    if (total > g_alloc_left) {
        size_t chunk = 1u << 20; // 1 MiB
        size_t need = (total > chunk) ? total : chunk;
        need = align_up_size(need, 4096);
        void *mem = xsys_mmap_anon(need);
        if (!mem) return NULL;
        g_alloc_cur = (unsigned char *)mem;
        g_alloc_left = need;
    }

    MonaccAllocHdr *h = (MonaccAllocHdr *)g_alloc_cur;
    h->size = size;
    void *ret = (void *)(h + 1);

    g_alloc_cur += total;
    g_alloc_left -= total;
    return ret;
}

void *monacc_calloc(size_t nmemb, size_t size) {
    if (nmemb && size > (size_t)-1 / nmemb) return NULL;
    size_t n = nmemb * size;
    void *p = monacc_malloc(n);
    if (!p) return NULL;
    mc_memset(p, 0, n);
    return p;
}

void *monacc_realloc(void *ptr, size_t size) {
    if (!ptr) return monacc_malloc(size);
    if (size == 0) return NULL;

    MonaccAllocHdr *h = ((MonaccAllocHdr *)ptr) - 1;
    size_t old = h->size;
    void *np = monacc_malloc(size);
    if (!np) return NULL;
    size_t ncopy = (old < size) ? old : size;
    mc_memcpy(np, ptr, ncopy);
    return np;
}

void monacc_free(void *ptr) {
    (void)ptr;
}

#endif

static int xexecve_impl(const char *path, char *argv[], char *envp[]) {
#ifdef SELFHOST
    return (int)syscall(MC_SYS_execve, path, argv, envp);
#else
    return xsys_execve(path, argv, envp);
#endif
}

static char **xenvp_from_proc(void) {
    int fd;
#ifdef SELFHOST
    fd = xs_openat("/proc/self/environ", O_RDONLY | O_CLOEXEC, 0);
#else
    fd = xsys_openat("/proc/self/environ", O_RDONLY | O_CLOEXEC, 0);
#endif

    // If we can't read /proc, let the caller fall back.
    if (fd < 0) return NULL;

    size_t cap = 4096;
    size_t n = 0;
    char *buf = (char *)monacc_malloc(cap);
    if (!buf) {
        (void)xclose_best_effort(fd);
        return NULL;
    }

    for (;;) {
        if (n + 1 >= cap) {
            size_t ncap = cap * 2;
            char *nb = (char *)monacc_realloc(buf, ncap);
            if (!nb) {
                (void)xclose_best_effort(fd);
                return NULL;
            }
            buf = nb;
            cap = ncap;
        }

        ssize_t r = xread_retry(fd, buf + n, cap - n - 1);
        if (r <= 0) break;
        n += (size_t)r;
    }

    (void)xclose_best_effort(fd);

    // Ensure an extra NUL terminator.
    buf[n] = 0;

    // Count NUL-separated entries.
    int nenv = 0;
    for (size_t i = 0; i < n; i++) {
        if (buf[i] == 0) nenv++;
    }

    // Always provide a valid envp (at minimum: {NULL}).
    char **envp = (char **)monacc_malloc((size_t)(nenv + 1) * sizeof(char *));
    if (!envp) return NULL;

    int ei = 0;
    char *p = buf;
    char *end = buf + n;
    while (p < end) {
        if (*p) {
            envp[ei++] = p;
            while (p < end && *p) p++;
        }
        if (p < end && *p == 0) p++;
    }
    envp[ei] = NULL;

    // Intentionally leak `buf` and `envp` on failure paths; if execve succeeds,
    // the process image is replaced.
    return envp;
}

static const char *xgetenv_from_envp(char **envp, const char *key) {
    if (!envp) return NULL;
    size_t klen = mc_strlen(key);
    for (char **ep = envp; *ep; ep++) {
        const char *kv = *ep;
        if (mc_strncmp(kv, key, klen) == 0 && kv[klen] == '=') return kv + klen + 1;
    }
    return NULL;
}

int xexecvp(const char *file, char *const argv[]) {
    static char *empty_envp[] = { NULL };

    int proc_ok = 1;
    char **envp = xenvp_from_proc();
    if (!envp) proc_ok = 0;

#ifndef SELFHOST
    if (!proc_ok && g_start_envp) envp = g_start_envp;
#endif
    if (!envp) envp = empty_envp;

    // If the file contains a slash, do not search PATH.
    if (mc_strchr(file, '/')) {
        (void)xexecve_impl(file, (char **)argv, envp);
        return -1;
    }

    const char *path = xgetenv_from_envp(envp, "PATH");
    if (!path || !*path) path = "/usr/local/bin:/usr/bin:/bin";

    const char *p = path;
    while (*p) {
        const char *seg = p;
        while (*p && *p != ':') p++;
        size_t seglen = (size_t)(p - seg);

        // Empty segment means current directory.
        const char *dir = seg;
        size_t dirlen = seglen;
        char full[4096];

        if (dirlen == 0) {
            dir = ".";
            dirlen = 1;
        }

        // Build "dir/file".
        size_t filelen = mc_strlen(file);
        if (dirlen + 1 + filelen + 1 < sizeof(full)) {
            mc_memcpy(full, dir, dirlen);
            full[dirlen] = '/';
            mc_memcpy(full + dirlen + 1, file, filelen);
            full[dirlen + 1 + filelen] = 0;
            (void)xexecve_impl(full, (char **)argv, envp);
        }

        if (*p == ':') p++;
    }

    return -1;
}

int xopen_ro(const char *path) {
    int fd;
#ifdef SELFHOST
    fd = xs_openat(path, O_RDONLY | O_CLOEXEC, 0);
#else
    fd = xsys_openat(path, O_RDONLY | O_CLOEXEC, 0);
#endif
    if (fd < 0) die("open %s failed", path);
    return fd;
}

int xopen_ro_try(const char *path) {
#ifdef SELFHOST
    return xs_openat(path, O_RDONLY | O_CLOEXEC, 0);
#else
    return xsys_openat(path, O_RDONLY | O_CLOEXEC, 0);
#endif
}

int xopen_rdwr_try(const char *path) {
#ifdef SELFHOST
    return xs_openat(path, O_RDWR | O_CLOEXEC, 0);
#else
    return xsys_openat(path, O_RDWR | O_CLOEXEC, 0);
#endif
}

static pid_t xfork_checked(void) {
#ifdef SELFHOST
    pid_t pid = fork();
#else
    pid_t pid = xsys_fork();
#endif
    if (pid < 0) die("fork failed");
    return pid;
}

static int xwaitpid_exitcode(pid_t pid) {
    int st = 0;
#ifdef SELFHOST
    if (waitpid(pid, &st, 0) < 0) die("waitpid failed");
#else
    if (xsys_waitpid(pid, &st, 0) < 0) die("waitpid failed");
#endif

    // Avoid sys/wait.h macros for SELFHOST compatibility.
    // Linux wait status encoding: low 7 bits are signal, 0 => exited.
    if ((st & 0x7f) != 0) return 1;
    return (st >> 8) & 0xff;
}

int run_cmd(char *const argv[]) {
    pid_t pid = xfork_checked();
    if (pid == 0) {
        xexecvp(argv[0], argv);
#ifdef SELFHOST
        const char *msg = "exec failed\n";
        xwrite_best_effort(2, msg, mc_strlen(msg));
#else
    errf("exec %s failed\n", argv[0]);
#endif
        _exit(127);
    }

    return xwaitpid_exitcode(pid);
}

int xopen_wtrunc(const char *path, int mode) {
    int fd;
#ifdef SELFHOST
    fd = xs_openat(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, (unsigned int)mode);
#else
    fd = xsys_openat(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, (unsigned int)mode);
#endif
    if (fd < 0) die("open %s failed", path);
    return fd;
}

ssize_t xread_retry(int fd, void *buf, size_t len) {
#ifdef SELFHOST
    return xs_read(fd, buf, len);
#else
    return xsys_read(fd, buf, len);
#endif
}

mc_i64 xlseek_retry(int fd, mc_i64 offset, int whence) {
#ifdef SELFHOST
    return xs_lseek(fd, offset, whence);
#else
    return xsys_lseek(fd, offset, whence);
#endif
}

int xftruncate_best_effort(int fd, mc_i64 length) {
#ifdef SELFHOST
    (void)xs_ftruncate(fd, length);
#else
    (void)xsys_ftruncate(fd, length);
#endif
    return 0;
}

void xwrite_all(int fd, const void *buf, size_t len) {
    const char *p = (const char *)buf;
    while (len) {
    ssize_t w;
#ifdef SELFHOST
    w = xs_write(fd, p, len);
#else
    w = xsys_write(fd, p, len);
#endif
        if (w < 0) {
            die("write failed");
        }
        if (w == 0) die("write: short write");
        p += (size_t)w;
        len -= (size_t)w;
    }
}

void xwrite_best_effort(int fd, const void *buf, size_t len) {
    const char *p = (const char *)buf;
    while (len) {
    ssize_t w;
#ifdef SELFHOST
    w = xs_write(fd, p, len);
#else
    w = xsys_write(fd, p, len);
#endif
        if (w < 0) {
            return;
        }
        if (w == 0) return;
        p += (size_t)w;
        len -= (size_t)w;
    }
}

void xclose_best_effort(int fd) {
#ifdef SELFHOST
    (void)xs_close(fd);
#else
    (void)xsys_close(fd);
#endif
}

void xclose_checked(int fd, const char *what, const char *path) {
#ifdef SELFHOST
    int rc = xs_close(fd);
#else
    int rc = xsys_close(fd);
#endif
    if (rc != 0) {
        if (path) die("%s %s failed", what, path);
        die("%s failed", what);
    }
}

void xunlink_best_effort(const char *path) {
#ifdef SELFHOST
    (void)xs_unlink(path);
#else
    (void)xsys_unlink(path);
#endif
}

int xpath_exists(const char *path) {
#ifdef SELFHOST
    // SELFHOST: best-effort only; we avoid pulling in stat-family headers.
    // If it's unreadable, this may return 0, and the later open() will report an error.
    int fd = xopen_ro_try(path);
    if (fd >= 0) {
        xclose_best_effort(fd);
        return 1;
    }
    return 0;
#else
    return xsys_path_exists(path);
#endif
}

// ===== Directory iteration (hosted-first) =====

ssize_t xgetdents64_retry(int fd, void *buf, size_t len) {
#ifdef SELFHOST
    (void)fd;
    (void)buf;
    (void)len;
    die("SELFHOST: xgetdents64_retry unsupported");
#else
    long r = (long)mc_sys_getdents64((mc_i32)fd, buf, (mc_u32)len);
    if (xsys_is_err(r)) return (ssize_t)-1;
    return (ssize_t)r;
#endif
}

void diriter_init_fd(DirIter *it, int fd) {
    it->fd = fd;
    it->pos = 0;
    it->end = 0;
}

void diriter_open(DirIter *it, const char *path) {
    diriter_init_fd(it, xopen_ro(path));
}

void diriter_close(DirIter *it) {
    if (it->fd >= 0) {
        xclose_checked(it->fd, "close", NULL);
        it->fd = -1;
    }
}

int diriter_next(DirIter *it, const linux_dirent64 **out_ent) {
    for (;;) {
        if (it->pos >= it->end) {
            ssize_t n = xgetdents64_retry(it->fd, it->buf, sizeof(it->buf));
            if (n < 0) die("getdents64 failed");
            if (n == 0) return 0;
            it->pos = 0;
            it->end = (size_t)n;
        }

        if (it->end - it->pos < sizeof(linux_dirent64)) {
            die("getdents64: short record");
        }

        const linux_dirent64 *d = (const linux_dirent64 *)(it->buf + it->pos);
        size_t reclen = (size_t)d->d_reclen;
        if (reclen < sizeof(linux_dirent64)) {
            die("getdents64: bad reclen");
        }
        if (it->pos + reclen > it->end) {
            die("getdents64: record overruns buffer");
        }

        it->pos += reclen;
        if (out_ent) *out_ent = d;
        return 1;
    }
}
