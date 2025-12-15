#pragma once

// Minimal stdio stub for monacc self-hosting probes.

#include <stdarg.h>

#ifndef NULL
#define NULL ((void *)0)
#endif

typedef struct FILE FILE;

// monacc does not currently model external global variables during self-host probes.
// Keep call sites parseable by mapping stderr to a simple constant.
#define stderr 0

#define SEEK_SET 0
#define SEEK_END 2

// Declare only what monacc uses directly.
int fprintf(FILE *stream, const char *fmt, ...);
int vfprintf(FILE *stream, const char *fmt, va_list ap);
int fputc(int c, FILE *stream);

FILE *fopen(const char *path, const char *mode);
int fclose(FILE *f);
int fseek(FILE *f, long off, int whence);
long ftell(FILE *f);
size_t fread(void *ptr, size_t size, size_t nmemb, FILE *stream);
size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream);

int snprintf(char *str, size_t size, const char *format, ...);
int vsnprintf(char *str, size_t size, const char *format, va_list ap);
