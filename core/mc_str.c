#include "mc.h"

mc_usize mc_strlen(const char *s) {
	const char *p = s;
	while (*p) p++;
	return (mc_usize)(p - s);
}

void *mc_memcpy(void *dst, const void *src, mc_usize n) {
	mc_u8 *d = (mc_u8 *)dst;
	const mc_u8 *s = (const mc_u8 *)src;
	for (mc_usize i = 0; i < n; i++) d[i] = s[i];
	return dst;
}

void *mc_memmove(void *dst, const void *src, mc_usize n) {
	mc_u8 *d = (mc_u8 *)dst;
	const mc_u8 *s = (const mc_u8 *)src;
	if (d == s || n == 0) return dst;
	if (d < s) {
		for (mc_usize i = 0; i < n; i++) d[i] = s[i];
	} else {
		for (mc_usize i = n; i > 0; i--) d[i - 1] = s[i - 1];
	}
	return dst;
}

void *mc_memset(void *dst, int c, mc_usize n) {
	mc_u8 *d = (mc_u8 *)dst;
	mc_u8 uc = (mc_u8)c;
	for (mc_usize i = 0; i < n; i++) d[i] = uc;
	return dst;
}

int mc_memcmp(const void *a, const void *b, mc_usize n) {
	const mc_u8 *pa = (const mc_u8 *)a;
	const mc_u8 *pb = (const mc_u8 *)b;
	for (mc_usize i = 0; i < n; i++) {
		if (pa[i] != pb[i]) return (int)pa[i] - (int)pb[i];
	}
	return 0;
}

void *mc_memchr(const void *s, int c, mc_usize n) {
	const mc_u8 *p = (const mc_u8 *)s;
	mc_u8 uc = (mc_u8)c;
	for (mc_usize i = 0; i < n; i++) {
		if (p[i] == uc) return (void *)(p + i);
	}
	return MC_NULL;
}

int mc_strcmp(const char *a, const char *b) {
	const mc_u8 *pa = (const mc_u8 *)a;
	const mc_u8 *pb = (const mc_u8 *)b;
	for (;;) {
		mc_u8 ca = *pa++;
		mc_u8 cb = *pb++;
		if (ca != cb) return (int)ca - (int)cb;
		if (ca == 0) return 0;
	}
}

int mc_strncmp(const char *a, const char *b, mc_usize n) {
	const mc_u8 *pa = (const mc_u8 *)a;
	const mc_u8 *pb = (const mc_u8 *)b;
	for (mc_usize i = 0; i < n; i++) {
		mc_u8 ca = pa[i];
		mc_u8 cb = pb[i];
		if (ca != cb) return (int)ca - (int)cb;
		if (ca == 0) return 0;
	}
	return 0;
}

int mc_streq(const char *a, const char *b) {
	while (*a && *b) {
		if (*a != *b) return 0;
		a++;
		b++;
	}
	return *a == *b;
}

int mc_starts_with_n(const char *s, const char *pre, mc_usize n) {
	for (mc_usize i = 0; i < n; i++) {
		if (s[i] != pre[i]) return 0;
		if (pre[i] == 0) return 0;
	}
	return 1;
}

char *mc_strchr(const char *s, int c) {
	mc_u8 uc = (mc_u8)c;
	const mc_u8 *p = (const mc_u8 *)s;
	for (;;) {
		if (*p == uc) return (char *)p;
		if (*p == 0) return MC_NULL;
		p++;
	}
}

char *mc_strrchr(const char *s, int c) {
	mc_u8 uc = (mc_u8)c;
	const mc_u8 *p = (const mc_u8 *)s;
	const mc_u8 *last = MC_NULL;
	for (;;) {
		if (*p == uc) last = p;
		if (*p == 0) return (char *)last;
		p++;
	}
}

int mc_has_slash(const char *s) {
	for (const char *p = s; *p; p++) {
		if (*p == '/') return 1;
	}
	return 0;
}

int mc_is_dot_or_dotdot(const char *name) {
	if (!name) return 0;
	if (name[0] != '.') return 0;
	if (name[1] == 0) return 1;
	if (name[1] == '.' && name[2] == 0) return 1;
	return 0;
}

const char *mc_getenv_kv(char **envp, const char *key_eq) {
	if (!envp || !key_eq) return MC_NULL;
	mc_usize kn = mc_strlen(key_eq);
	for (mc_usize i = 0; envp[i]; i++) {
		const char *e = envp[i];
		if (!e) continue;
		if (mc_starts_with_n(e, key_eq, kn)) return e + kn;
	}
	return MC_NULL;
}
