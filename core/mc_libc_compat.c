#include "mc.h"

void *(memcpy)(void *dst, const void *src, mc_usize n) {
	return mc_memcpy(dst, src, n);
}

void *(memmove)(void *dst, const void *src, mc_usize n) {
	return mc_memmove(dst, src, n);
}

void *(memset)(void *dst, int c, mc_usize n) {
	return mc_memset(dst, c, n);
}

int memcmp(const void *a, const void *b, mc_usize n) {
	return mc_memcmp(a, b, n);
}

mc_usize strlen(const char *s) {
	return mc_strlen(s);
}

int strcmp(const char *a, const char *b) {
	return mc_strcmp(a, b);
}

int strncmp(const char *a, const char *b, mc_usize n) {
	return mc_strncmp(a, b, n);
}

char *strchr(const char *s, int c) {
	return mc_strchr(s, c);
}

char *strrchr(const char *s, int c) {
	return mc_strrchr(s, c);
}
