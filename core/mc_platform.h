#pragma once

// Platform detection helpers for building the tools with a host toolchain.
// Linux remains the primary target; Darwin support is for hosted macOS builds.

#if defined(__linux__)
#define MC_OS_LINUX 1
#else
#define MC_OS_LINUX 0
#endif

#if defined(__APPLE__) && defined(__MACH__)
#define MC_OS_DARWIN 1
#else
#define MC_OS_DARWIN 0
#endif

#if defined(__x86_64__)
#define MC_ARCH_X86_64 1
#else
#define MC_ARCH_X86_64 0
#endif

#if defined(__aarch64__)
#define MC_ARCH_AARCH64 1
#else
#define MC_ARCH_AARCH64 0
#endif
