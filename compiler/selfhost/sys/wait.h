#pragma once

pid_t waitpid();

// In real libc these are macros.
// monacc's preprocessor does not support function-like macros, so provide
// static functions with the same names.
static int WIFEXITED(int status) { return (status & 0x7f) == 0; }
static int WEXITSTATUS(int status) { return (status >> 8) & 0xff; }
