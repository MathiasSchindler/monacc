#pragma once

// Minimal fcntl.h stub for self-host probes.
// We only need open() and a few O_* flags.

// Linux x86_64 values.
#define O_RDONLY 0
#define O_WRONLY 1
#define O_RDWR 2

#define O_CREAT 0100
#define O_TRUNC 01000
#define O_CLOEXEC 02000000

int open(const char *pathname, int flags, ...);
