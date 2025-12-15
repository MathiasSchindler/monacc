#include "mc.h"

int mc_parse_u64_dec(const char *s, mc_u64 *out) {
	if (!s || !*s || !out) return -1;
	mc_u64 v = 0;
	for (const char *p = s; *p; p++) {
		char c = *p;
		if (c < '0' || c > '9') return -1;
		mc_u64 d = (mc_u64)(c - '0');
		if (v > (mc_u64)(~(mc_u64)0) / 10) return -1;
		v *= 10;
		if (v > (mc_u64)(~(mc_u64)0) - d) return -1;
		v += d;
	}
	*out = v;
	return 0;
}

int mc_parse_u32_dec(const char *s, mc_u32 *out) {
	if (!s || !*s || !out) return -1;
	mc_u64 v = 0;
	if (mc_parse_u64_dec(s, &v) != 0) return -1;
	if (v > 0xFFFFFFFFu) return -1;
	*out = (mc_u32)v;
	return 0;
}

int mc_parse_u32_octal(const char *s, mc_u32 *out) {
	if (!s || !*s || !out) return -1;
	mc_u64 v = 0;
	for (const char *p = s; *p; p++) {
		char c = *p;
		if (c < '0' || c > '7') return -1;
		mc_u64 d = (mc_u64)(c - '0');
		if (v > 0xFFFFFFFFu / 8u) return -1;
		v = v * 8u + d;
		if (v > 0xFFFFFFFFu) return -1;
	}
	*out = (mc_u32)v;
	return 0;
}

int mc_parse_i64_dec(const char *s, mc_i64 *out) {
	if (!s || !*s || !out) return -1;
	int neg = 0;
	if (*s == '-') {
		neg = 1;
		s++;
		if (!*s) return -1;
	}
	mc_u64 mag = 0;
	if (mc_parse_u64_dec(s, &mag) != 0) return -1;
	if (!neg) {
		if (mag > (mc_u64)0x7FFFFFFFFFFFFFFFULL) return -1;
		*out = (mc_i64)mag;
		return 0;
	}
	if (mag > (mc_u64)0x8000000000000000ULL) return -1;
	if (mag == (mc_u64)0x8000000000000000ULL) {
		*out = (mc_i64)0x8000000000000000ULL;
		return 0;
	}
	*out = -(mc_i64)mag;
	return 0;
}

int mc_parse_u64_dec_prefix(const char **ps, mc_u64 *out) {
	if (!ps || !*ps || !out) return -1;
	const char *s = *ps;
	if (*s < '0' || *s > '9') return -1;
	mc_u64 v = 0;
	while (*s >= '0' && *s <= '9') {
		mc_u64 d = (mc_u64)(*s - '0');
		if (v > (mc_u64)(~(mc_u64)0) / 10) return -1;
		v *= 10;
		if (v > (mc_u64)(~(mc_u64)0) - d) return -1;
		v += d;
		s++;
	}
	*ps = s;
	*out = v;
	return 0;
}

int mc_parse_u32_dec_prefix(const char **ps, mc_u32 *out) {
	if (!ps || !*ps || !out) return -1;
	const char *s = *ps;
	if (*s < '0' || *s > '9') return -1;
	mc_u32 v = 0;
	while (*s >= '0' && *s <= '9') {
		mc_u32 d = (mc_u32)(*s - '0');
		if (v > 0xFFFFFFFFu / 10u) return -1;
		v = v * 10u;
		if (v > 0xFFFFFFFFu - d) return -1;
		v += d;
		s++;
	}
	*ps = s;
	*out = v;
	return 0;
}

int mc_parse_i64_dec_prefix(const char **ps, mc_i64 *out) {
	if (!ps || !*ps || !out) return -1;
	const char *s = *ps;
	int neg = 0;
	if (*s == '+' || *s == '-') {
		neg = (*s == '-');
		s++;
	}
	if (*s < '0' || *s > '9') return -1;
	mc_u64 mag = 0;
	while (*s >= '0' && *s <= '9') {
		mc_u64 d = (mc_u64)(*s - '0');
		if (mag > (mc_u64)(~(mc_u64)0) / 10) return -1;
		mag *= 10;
		if (mag > (mc_u64)(~(mc_u64)0) - d) return -1;
		mag += d;
		s++;
	}
	if (!neg) {
		if (mag > (mc_u64)0x7FFFFFFFFFFFFFFFULL) return -1;
		*out = (mc_i64)mag;
		*ps = s;
		return 0;
	}
	if (mag > (mc_u64)0x8000000000000000ULL) return -1;
	if (mag == (mc_u64)0x8000000000000000ULL) {
		*out = (mc_i64)0x8000000000000000ULL;
		*ps = s;
		return 0;
	}
	*out = -(mc_i64)mag;
	*ps = s;
	return 0;
}

int mc_parse_u32_dec_n(const char *s, mc_usize n, mc_u32 *out) {
	if (!s || n == 0 || !out) return -1;
	mc_u32 v = 0;
	for (mc_usize i = 0; i < n; i++) {
		char c = s[i];
		if (c < '0' || c > '9') return -1;
		mc_u32 d = (mc_u32)(c - '0');
		if (v > 0xFFFFFFFFu / 10u) return -1;
		v = v * 10u;
		if (v > 0xFFFFFFFFu - d) return -1;
		v += d;
	}
	*out = v;
	return 0;
}

int mc_parse_i32_dec(const char *s, mc_i32 *out) {
	if (!s || !*s || !out) return -1;
	const char *p = s;
	mc_i64 v = 0;
	if (mc_parse_i64_dec_prefix(&p, &v) != 0) return -1;
	if (*p != 0) return -1;
	if (v < (mc_i64)(-2147483647 - 1) || v > (mc_i64)2147483647) return -1;
	*out = (mc_i32)v;
	return 0;
}

int mc_parse_uid_gid(const char *s, mc_u32 *out_uid, mc_u32 *out_gid) {
	if (!s || !*s || !out_uid || !out_gid) return -1;
	const char *colon = MC_NULL;
	for (const char *p = s; *p; p++) {
		if (*p == ':') { colon = p; break; }
	}
	if (!colon) {
		mc_u32 uid;
		if (mc_parse_u32_dec(s, &uid) != 0) return -1;
		*out_uid = uid;
		*out_gid = 0xFFFFFFFFu;
		return 0;
	}
	{
		mc_u64 v = 0;
		if (colon == s) return -1;
		for (const char *p = s; p < colon; p++) {
			char c = *p;
			if (c < '0' || c > '9') return -1;
			mc_u64 d = (mc_u64)(c - '0');
			if (v > (mc_u64)(~(mc_u64)0) / 10) return -1;
			v = v * 10 + d;
			if (v > 0xFFFFFFFFu) return -1;
		}
		*out_uid = (mc_u32)v;
	}
	if (*(colon + 1) == 0) {
		*out_gid = 0xFFFFFFFFu;
		return 0;
	}
	{
		mc_u32 gid;
		if (mc_parse_u32_dec(colon + 1, &gid) != 0) return -1;
		*out_gid = gid;
	}
	return 0;
}
