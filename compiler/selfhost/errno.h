#pragma once

// Minimal errno stub for monacc self-hosting probes.
// Avoid relying on a global variable symbol that the self-hosting compiler
// doesn't model; use the libc errno accessor instead.
int *__errno_location(void);
#define errno (*__errno_location())

// Minimal errno values used by monacc.
// Linux x86_64: EINTR is 4.
#define EINTR 4

// Linux x86_64 common errno values.
#define ENOENT 2
#define EACCES 13
#define ENOTDIR 20
