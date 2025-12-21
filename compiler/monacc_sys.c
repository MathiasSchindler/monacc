#include "monacc.h"

static int xsys_is_err(long r) {
    // Core syscall wrappers return -errno on failure, in range [-4095, -1].
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

static mc_isize xsys_read(int fd, void *buf, mc_usize len) {
    long r = (long)mc_sys_read((mc_i32)fd, buf, (mc_usize)len);
    if (xsys_is_err(r)) return (mc_isize)-1;
    return (mc_isize)r;
}

static mc_isize xsys_write(int fd, const void *buf, mc_usize len) {
    long r = (long)mc_sys_write((mc_i32)fd, buf, (mc_usize)len);
    if (xsys_is_err(r)) return (mc_isize)-1;
    return (mc_isize)r;
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

#if !MC_OS_DARWIN
__attribute__((noreturn)) void _exit(int status) {
    (void)mc_syscall1(MC_SYS_exit, (mc_i64)status);
    for (;;) {
    }
}
#endif

static int xsys_path_exists(const char *path) {
    // We only care whether it exists; struct size is plenty for kernel ABI.
    struct {
        unsigned long _pad[32];
    } st;
    long r = (long)mc_sys_newfstatat((mc_i32)MC_AT_FDCWD, path, (struct mc_stat *)&st, 0);
    return xsys_is_err(r) ? 0 : 1;
}

// Tiny syscall wrappers used to gradually shrink libc surface area.
//
// NOTE: We intentionally avoid reading/setting errno to keep the compiler's
// libc surface minimal and keep SELFHOST predictable.

// ===== Minimal allocator =====
//
// Hosted build: avoid libc malloc family by using an mmap-backed bump allocator.
// We keep `free()` as a no-op; this is fine for the compiler's short-lived process.
//
// SELFHOST build: also uses the bump allocator to keep the output libc-free.

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

// Always use Linux-shaped MAP_* bits in the compiler/runtime.
// On hosted Darwin builds, core translates these to the host constants.
#ifndef MONACC_MAP_PRIVATE
#define MONACC_MAP_PRIVATE 0x02
#endif
#ifndef MONACC_MAP_ANONYMOUS
#define MONACC_MAP_ANONYMOUS 0x20
#endif

typedef struct {
    mc_usize size;
} MonaccAllocHdr;

static unsigned char *g_alloc_cur;
static mc_usize g_alloc_left;

static mc_usize align_up_size(mc_usize n, mc_usize a) {
    return (n + (a - 1)) & ~(a - 1);
}

static void *xsys_mmap_anon(mc_usize len) {
    long r;
    #if MC_OS_DARWIN
    r = (long)mc_sys_mmap((void *)0, (mc_usize)len, (mc_i32)(PROT_READ | PROT_WRITE),
                          (mc_i32)(MONACC_MAP_PRIVATE | MONACC_MAP_ANONYMOUS), (mc_i32)-1, (mc_i64)0);
    #else
    r = (long)mc_syscall6(MC_SYS_mmap, (mc_i64)0, (mc_i64)len, (mc_i64)(PROT_READ | PROT_WRITE),
                          (mc_i64)(MONACC_MAP_PRIVATE | MONACC_MAP_ANONYMOUS), (mc_i64)-1, (mc_i64)0);
    #endif
    if (xsys_is_err(r)) return NULL;
    return (void *)r;
}

void *monacc_malloc(mc_usize size) {
    if (size == 0) size = 1;

    const mc_usize align = 16;
    mc_usize total = sizeof(MonaccAllocHdr) + size;
    total = align_up_size(total, align);

    if (total < size) return NULL; // overflow

    if (total > g_alloc_left) {
        mc_usize chunk = 1u << 20; // 1 MiB
        mc_usize need = (total > chunk) ? total : chunk;
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

void *monacc_calloc(mc_usize nmemb, mc_usize size) {
    if (nmemb && size > (mc_usize)-1 / nmemb) return NULL;
    mc_usize n = nmemb * size;
    void *p = monacc_malloc(n);
    if (!p) return NULL;
    mc_memset(p, 0, n);
    return p;
}

void *monacc_realloc(void *ptr, mc_usize size) {
    if (!ptr) return monacc_malloc(size);
    if (size == 0) return NULL;

    MonaccAllocHdr *h = ((MonaccAllocHdr *)ptr) - 1;
    mc_usize old = h->size;
    void *np = monacc_malloc(size);
    if (!np) return NULL;
    mc_usize ncopy = (old < size) ? old : size;
    mc_memcpy(np, ptr, ncopy);
    return np;
}

void monacc_free(void *ptr) {
    (void)ptr;
}


static int xexecve_impl(const char *path, char *argv[], char *envp[]) {
    return xsys_execve(path, argv, envp);
}

static char **xenvp_from_proc(void) {
    int fd;
    fd = xsys_openat("/proc/self/environ", O_RDONLY | O_CLOEXEC, 0);

    // If we can't read /proc, let the caller fall back.
    if (fd < 0) return NULL;

    mc_usize cap = 4096;
    mc_usize n = 0;
    char *buf = (char *)monacc_malloc(cap);
    if (!buf) {
        (void)xclose_best_effort(fd);
        return NULL;
    }

    for (;;) {
        if (n + 1 >= cap) {
            mc_usize ncap = cap * 2;
            char *nb = (char *)monacc_realloc(buf, ncap);
            if (!nb) {
                (void)xclose_best_effort(fd);
                return NULL;
            }
            buf = nb;
            cap = ncap;
        }

        mc_isize r = xread_retry(fd, buf + n, cap - n - 1);
        if (r <= 0) break;
        n += (mc_usize)r;
    }

    (void)xclose_best_effort(fd);

    // Ensure an extra NUL terminator.
    buf[n] = 0;

    // Count NUL-separated entries.
    int nenv = 0;
    for (mc_usize i = 0; i < n; i++) {
        if (buf[i] == 0) nenv++;
    }

    // Always provide a valid envp (at minimum: {NULL}).
    char **envp = (char **)monacc_malloc((mc_usize)(nenv + 1) * sizeof(char *));
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
    mc_usize klen = mc_strlen(key);
    for (char **ep = envp; *ep; ep++) {
        const char *kv = *ep;
        if (mc_strncmp(kv, key, klen) == 0 && kv[klen] == '=') return kv + klen + 1;
    }
    return NULL;
}

int xexecvp(const char *file, char *const argv[]) {
    static char *empty_envp[1] = { NULL };

    int proc_ok = 1;
    char **envp = xenvp_from_proc();
    if (!envp) proc_ok = 0;

    char **start_envp = mc_get_start_envp();
    if (!proc_ok && start_envp) envp = start_envp;
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
        mc_usize seglen = (mc_usize)(p - seg);

        // Empty segment means current directory.
        const char *dir = seg;
        mc_usize dirlen = seglen;
        char full[4096];

        if (dirlen == 0) {
            dir = ".";
            dirlen = 1;
        }

        // Build "dir/file".
        mc_usize filelen = mc_strlen(file);
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
    int fd = xsys_openat(path, O_RDONLY | O_CLOEXEC, 0);
    if (fd < 0) die("open %s failed", path);
    return fd;
}

int xopen_ro_try(const char *path) {
    return xsys_openat(path, O_RDONLY | O_CLOEXEC, 0);
}

int xopen_rdwr_try(const char *path) {
    return xsys_openat(path, O_RDWR | O_CLOEXEC, 0);
}

static pid_t xfork_checked(void) {
    pid_t pid = xsys_fork();
    if (pid < 0) die("fork failed");
    return pid;
}

static int xwaitpid_exitcode(pid_t pid) {
    int st = 0;
    if (xsys_waitpid(pid, &st, 0) < 0) die("waitpid failed");

    // Avoid sys/wait.h macros for SELFHOST compatibility.
    // Linux wait status encoding: low 7 bits are signal, 0 => exited.
    if ((st & 0x7f) != 0) return 1;
    return (st >> 8) & 0xff;
}

int run_cmd(char *const argv[]) {
    pid_t pid = xfork_checked();
    if (pid == 0) {
        xexecvp(argv[0], argv);
        const char *pfx = "exec ";
        xwrite_best_effort(2, pfx, mc_strlen(pfx));
        if (argv && argv[0]) {
            xwrite_best_effort(2, argv[0], mc_strlen(argv[0]));
        } else {
            const char *unknown = "(null)";
            xwrite_best_effort(2, unknown, mc_strlen(unknown));
        }
        const char *sfx = " failed\n";
        xwrite_best_effort(2, sfx, mc_strlen(sfx));
        #if MC_OS_DARWIN
        mc_exit(127);
        #else
        _exit(127);
        #endif
    }

    return xwaitpid_exitcode(pid);
}

int xopen_wtrunc(const char *path, int mode) {
    int fd = xsys_openat(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, (unsigned int)mode);
    if (fd < 0) die("open %s failed", path);
    return fd;
}

mc_isize xread_retry(int fd, void *buf, mc_usize len) {
    return xsys_read(fd, buf, len);
}

mc_i64 xlseek_retry(int fd, mc_i64 offset, int whence) {
    return xsys_lseek(fd, offset, whence);
}

int xftruncate_best_effort(int fd, mc_i64 length) {
    (void)xsys_ftruncate(fd, length);
    return 0;
}

void xwrite_all(int fd, const void *buf, mc_usize len) {
    const char *p = (const char *)buf;
    while (len) {
    mc_isize w;
    w = xsys_write(fd, p, len);
        if (w < 0) {
            die("write failed");
        }
        if (w == 0) die("write: short write");
        p += (mc_usize)w;
        len -= (mc_usize)w;
    }
}

void xwrite_best_effort(int fd, const void *buf, mc_usize len) {
    const char *p = (const char *)buf;
    while (len) {
    mc_isize w;
    w = xsys_write(fd, p, len);
        if (w < 0) {
            return;
        }
        if (w == 0) return;
        p += (mc_usize)w;
        len -= (mc_usize)w;
    }
}

void xclose_best_effort(int fd) {
    (void)xsys_close(fd);
}

void xclose_checked(int fd, const char *what, const char *path) {
    int rc = xsys_close(fd);
    if (rc != 0) {
        if (path) die("%s %s failed", what, path);
        die("%s failed", what);
    }
}

void xunlink_best_effort(const char *path) {
    (void)xsys_unlink(path);
}

int xpath_exists(const char *path) {
    return xsys_path_exists(path);
}

// ===== Directory iteration (hosted-first) =====

mc_isize xgetdents64_retry(int fd, void *buf, mc_usize len) {
    long r = (long)mc_sys_getdents64((mc_i32)fd, buf, (mc_u32)len);
    if (xsys_is_err(r)) return (mc_isize)-1;
    return (mc_isize)r;
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
            mc_isize n = xgetdents64_retry(it->fd, it->buf, sizeof(it->buf));
            if (n < 0) die("getdents64 failed");
            if (n == 0) return 0;
            it->pos = 0;
            it->end = (mc_usize)n;
        }

        if (it->end - it->pos < sizeof(linux_dirent64)) {
            die("getdents64: short record");
        }

        const linux_dirent64 *d = (const linux_dirent64 *)(it->buf + it->pos);
        mc_usize reclen = (mc_usize)d->d_reclen;
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
