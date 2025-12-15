#pragma once

// Minimal string stub for monacc self-hosting probes.

size_t strlen(const char *s);
int strcmp(const char *a, const char *b);
int strncmp(const char *a, const char *b, size_t n);

void *memcpy(void *dst, const void *src, size_t n);
void *memmove(void *dst, const void *src, size_t n);
void *memset(void *dst, int c, size_t n);
int memcmp(const void *a, const void *b, size_t n);

void *memchr(const void *s, int c, size_t n);

char *strdup(const char *s);
char *strrchr(const char *s, int c);
char *strchr(const char *s, int c);
