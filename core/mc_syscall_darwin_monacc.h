#pragma once

#include "mc_types.h"

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

// For early bring-up, most constants are left undefined until a tool needs them.

// Minimal libc declarations (kept for future expansion; not all are used yet).
extern void _exit(int);
extern long write(int, const void *, unsigned long);
extern long read(int, void *, unsigned long);
extern int execve(const char *, char *const[], char *const[]);
extern int *__error(void);

static inline mc_i64 mc__neg_errno(void) {
    int *ep = __error();
    if (!ep) return (mc_i64)-(mc_i64)MC_EINVAL;
    return (mc_i64)-(mc_i64)(*ep);
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

static inline mc_i64 mc_sys_execve(const char *pathname, char *const argv[], char *const envp[]) {
    if (execve(pathname, argv, envp) < 0) return mc__neg_errno();
    return 0;
}
