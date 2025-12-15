#pragma once

// Minimal stat stub.
struct stat {
    // Opaque padding: must be large enough for the host libc's struct stat,
    // because libc stat() writes the full structure.
    unsigned long _pad[32];
};

int stat(const char *path, struct stat *st);
