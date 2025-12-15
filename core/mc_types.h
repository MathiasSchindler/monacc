#pragma once

// Fixed-width integers (LP64 model: Linux x86_64)
typedef unsigned long      mc_usize;
typedef long               mc_isize;
typedef unsigned long long mc_u64;
typedef long long          mc_i64;
typedef unsigned int       mc_u32;
typedef int                mc_i32;
typedef unsigned short     mc_u16;
typedef short              mc_i16;
typedef unsigned char      mc_u8;
typedef signed char        mc_i8;

// Pointer-sized integers
typedef long               mc_intptr;
typedef unsigned long      mc_uintptr;

// Booleans (C89 compatible)
#ifndef __bool_true_false_are_defined
typedef int mc_bool;
#define mc_true 1
#define mc_false 0
#define __bool_true_false_are_defined 1
#endif

#ifndef MC_NULL
#define MC_NULL ((void *)0)
#endif

#ifndef MC_INT_MAX
#define MC_INT_MAX 2147483647
#endif
