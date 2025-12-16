#pragma once

// Split-out syscall wrapper declarations so we can include them without
// pulling in the whole monacc.h if we ever want that later.
// For now, monacc.h forwards these too.

#include "monacc_libc.h"

int xopen_ro(const char *path);
int xopen_ro_try(const char *path);
int xopen_wtrunc(const char *path, int mode);
mc_isize xread_retry(int fd, void *buf, mc_usize len);
void xwrite_all(int fd, const void *buf, mc_usize len);

// Best-effort variant for diagnostics: ignores errors.
void xwrite_best_effort(int fd, const void *buf, mc_usize len);

void xclose_best_effort(int fd);

void xclose_checked(int fd, const char *what, const char *path);

void xunlink_best_effort(const char *path);

int xpath_exists(const char *path);

int xexecvp(const char *file, char *const argv[]);

mc_isize xgetdents64_retry(int fd, void *buf, mc_usize len);
