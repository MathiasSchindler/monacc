#pragma once

#include "mc_types.h"
#include "mc_syscall.h"

#define MC_NORETURN __attribute__((noreturn))
#define MC_INLINE static inline __attribute__((always_inline))

// Exit
MC_NORETURN void mc_exit(mc_i32 code);

// Strings / memory
mc_usize mc_strlen(const char *s);
int mc_strcmp(const char *a, const char *b);
int mc_strncmp(const char *a, const char *b, mc_usize n);
int mc_streq(const char *a, const char *b);
int mc_starts_with_n(const char *s, const char *pre, mc_usize n);
int mc_has_slash(const char *s);
int mc_is_dot_or_dotdot(const char *name);
const char *mc_getenv_kv(char **envp, const char *key_eq);

void *mc_memcpy(void *dst, const void *src, mc_usize n);
void *mc_memmove(void *dst, const void *src, mc_usize n);
void *mc_memset(void *dst, int c, mc_usize n);
int mc_memcmp(const void *a, const void *b, mc_usize n);
void *mc_memchr(const void *s, int c, mc_usize n);
char *mc_strchr(const char *s, int c);
char *mc_strrchr(const char *s, int c);

// Parsing
int mc_parse_u64_dec(const char *s, mc_u64 *out);
int mc_parse_u32_dec(const char *s, mc_u32 *out);
int mc_parse_u32_octal(const char *s, mc_u32 *out);
int mc_parse_i64_dec(const char *s, mc_i64 *out);
int mc_parse_i32_dec(const char *s, mc_i32 *out);
int mc_parse_uid_gid(const char *s, mc_u32 *out_uid, mc_u32 *out_gid);

int mc_parse_u64_dec_prefix(const char **ps, mc_u64 *out);
int mc_parse_u32_dec_prefix(const char **ps, mc_u32 *out);
int mc_parse_i64_dec_prefix(const char **ps, mc_i64 *out);
int mc_parse_u32_dec_n(const char *s, mc_usize n, mc_u32 *out);

// Small snprintf-like helpers (no stdarg required)
int mc_snprint_cstr_cstr(char *dst, mc_usize cap, const char *a, const char *b);
int mc_snprint_cstr_u64_cstr(char *dst, mc_usize cap, const char *a, mc_u64 u, const char *b);
int mc_snprint_cstr_cstr_u64_cstr(char *dst, mc_usize cap, const char *a, const char *mid, mc_u64 u, const char *b);

// I/O helpers
mc_i64 mc_write_all(mc_i32 fd, const void *buf, mc_usize len);
mc_i64 mc_write_str(mc_i32 fd, const char *s);
void mc_write_hex_u64(mc_i32 fd, mc_u64 v);
mc_i64 mc_write_u64_dec(mc_i32 fd, mc_u64 v);
mc_i64 mc_write_i64_dec(mc_i32 fd, mc_i64 v);

// Directory iteration
typedef int (*mc_dirent_cb)(void *ctx, const char *name, mc_u8 d_type);
mc_i64 mc_for_each_dirent(mc_i32 dirfd, mc_dirent_cb cb, void *ctx);

// Common UX helpers
MC_NORETURN void mc_die_usage(const char *argv0, const char *usage);
MC_NORETURN void mc_die_errno(const char *argv0, const char *ctx, mc_i64 err_neg);
void mc_print_errno(const char *argv0, const char *ctx, mc_i64 err_neg);
void mc_join_path_or_die(const char *argv0, const char *base, const char *name, char *out, mc_usize out_cap);

// Regex (compat signature with old sb)
#define MC_REGEX_MAX_CAPS 9u
#define MC_REGEX_ICASE 0x1u

struct mc_regex_caps {
	const char *start[MC_REGEX_MAX_CAPS + 1];
	const char *end[MC_REGEX_MAX_CAPS + 1];
	mc_u32 n;
};

int mc_regex_match_first(const char *re, const char *text, mc_u32 flags,
	const char **out_start, const char **out_end, struct mc_regex_caps *out_caps);

MC_INLINE mc_u8 mc_tolower_ascii(mc_u8 c) {
	return (c >= (mc_u8)'A' && c <= (mc_u8)'Z') ? (mc_u8)(c + (mc_u8)('a' - 'A')) : c;
}

MC_INLINE int mc_is_space_ascii(mc_u8 c) {
	return (c == (mc_u8)' ' || c == (mc_u8)'\n' || c == (mc_u8)'\t' || c == (mc_u8)'\r' || c == (mc_u8)'\v' || c == (mc_u8)'\f');
}
