#pragma once

// Utility Module (util.h)
// ========================
//
// This header defines shared utility types and functions used across the
// monacc compiler, including string builders and file I/O.
//
// Part of Phase 3 of the monacc compiler structural rebase: splitting the
// monolithic monacc.h into focused module headers.

#include "mc_types.h"

// ===== String Builder =====

typedef struct {
    char *buf;
    mc_usize len;
    mc_usize cap;
} Str;

void str_reserve(Str *s, mc_usize add);
void str_append_bytes(Str *s, const char *buf, mc_usize n);
// `str_appendf` supports only literals and `%%`.
// Use typed helpers for conversions.
void str_appendf(Str *s, const char *fmt);
void str_appendf_i64(Str *s, const char *fmt, long long v);
void str_appendf_u64(Str *s, const char *fmt, unsigned long long v);
void str_appendf_s(Str *s, const char *fmt, const char *v);
void str_appendf_ss(Str *s, const char *fmt, const char *s0, const char *s1);
void str_appendf_si(Str *s, const char *fmt, const char *s0, long long i0);
void str_appendf_su(Str *s, const char *fmt, const char *s0, unsigned long long u0);
void str_appendf_is(Str *s, const char *fmt, long long i0, const char *s0);

// ===== File I/O =====

void write_file(const char *path, const char *data, mc_usize len);

// ===== Syscall wrappers (hosted + selfhost) =====

int xopen_ro(const char *path);
int xopen_ro_try(const char *path);
int xopen_wtrunc(const char *path, int mode);
int xopen_rdwr_try(const char *path);
mc_isize xread_retry(int fd, void *buf, mc_usize len);
void xwrite_all(int fd, const void *buf, mc_usize len);
void xwrite_best_effort(int fd, const void *buf, mc_usize len);
void xclose_best_effort(int fd);
void xclose_checked(int fd, const char *what, const char *path);

mc_i64 xlseek_retry(int fd, mc_i64 offset, int whence);
int xftruncate_best_effort(int fd, mc_i64 length);

void xunlink_best_effort(const char *path);

// Returns 1 if path exists (even if not readable), else 0.
int xpath_exists(const char *path);

int xexecvp(const char *file, char *const argv[]);

// Directory listing (Linux getdents64). Hosted-first.
// The record layout matches the Linux kernel ABI.
typedef struct {
    uint64_t d_ino;
    int64_t d_off;
    uint16_t d_reclen;
    uint8_t d_type;
    char d_name[];
} linux_dirent64;

mc_isize xgetdents64_retry(int fd, void *buf, mc_usize len);

typedef struct {
    int fd;
    mc_usize pos;
    mc_usize end;
    char buf[8192];
} DirIter;

void diriter_init_fd(DirIter *it, int fd);
void diriter_open(DirIter *it, const char *path);
void diriter_close(DirIter *it);
int diriter_next(DirIter *it, const linux_dirent64 **out_ent);
int run_cmd(char *const argv[]);
