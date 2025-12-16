#pragma once

// Minimal libc surface used by the hosted compiler.
//
// We keep this as explicit prototypes to avoid pulling in large libc headers
// via src/monacc.h, and to make the self-host probe predictable.

#include "mc_types.h"
#include "mc_syscall.h"

// Minimal sys/types subset (avoid pulling in <sys/types.h>).
// Prefer mc_usize/mc_isize directly in the compiler.
typedef int pid_t;
typedef unsigned int mode_t;

// Minimal stdint subset (avoid pulling in <stdint.h>).
// monacc targets Linux x86_64 (LP64).
typedef mc_i8 int8_t;
typedef mc_u8 uint8_t;
typedef mc_i16 int16_t;
typedef mc_u16 uint16_t;
typedef mc_i32 int32_t;
typedef mc_u32 uint32_t;
typedef mc_i64 int64_t;
typedef mc_u64 uint64_t;
typedef mc_intptr intptr_t;
typedef mc_uintptr uintptr_t;

// Minimal stdbool subset (avoid pulling in <stdbool.h>).
#ifdef SELFHOST
#ifndef __bool_true_false_are_defined
typedef int bool;
#define true 1
#define false 0
#define __bool_true_false_are_defined 1
#endif
#endif

// Minimal stdarg subset (avoid pulling in <stdarg.h>).
// Hosted builds can use compiler builtins; SELFHOST builds avoid varargs.
#ifndef SELFHOST
typedef __builtin_va_list va_list;
#define va_start(ap, last) __builtin_va_start(ap, last)
#define va_end(ap) __builtin_va_end(ap)
#define va_arg(ap, type) __builtin_va_arg(ap, type)
#define va_copy(dest, src) __builtin_va_copy(dest, src)
#endif

#ifndef NULL
#define NULL ((void *)0)
#endif

#ifndef INT_MAX
#define INT_MAX 2147483647
#endif

// ===== Minimal Linux/POSIX API surface =====
// Keep this explicit to avoid pulling in large libc headers.

// open(2) flags (Linux).
#ifndef O_RDONLY
#define O_RDONLY MC_O_RDONLY
#endif
#ifndef O_WRONLY
#define O_WRONLY MC_O_WRONLY
#endif
#ifndef O_RDWR
#define O_RDWR MC_O_RDWR
#endif
#ifndef O_CREAT
#define O_CREAT MC_O_CREAT
#endif
#ifndef O_TRUNC
#define O_TRUNC MC_O_TRUNC
#endif
#ifndef O_CLOEXEC
#define O_CLOEXEC MC_O_CLOEXEC
#endif

#ifndef O_APPEND
#define O_APPEND MC_O_APPEND
#endif

#ifndef O_NOFOLLOW
#define O_NOFOLLOW MC_O_NOFOLLOW
#endif

#ifndef O_DIRECTORY
#define O_DIRECTORY MC_O_DIRECTORY
#endif

#ifndef AT_FDCWD
#define AT_FDCWD MC_AT_FDCWD
#endif

// (open/read/write/close/unlink are implemented via raw syscalls in monacc_sys.c)

__attribute__((noreturn)) void _exit(int status);


