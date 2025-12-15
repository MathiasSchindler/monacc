#pragma once

// Minimal stdlib stub for monacc self-hosting probes.

#ifndef NULL
#define NULL ((void *)0)
#endif

void *malloc(size_t size);
void *calloc(size_t nmemb, size_t size);
void *realloc(void *ptr, size_t size);
void free(void *ptr);

void exit(int status);
