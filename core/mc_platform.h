#pragma once

// Platform detection helpers for building the tools with a host toolchain.
// Linux remains the primary target; Darwin support is for hosted macOS builds.
// Emscripten support is for browser/WASM builds.

#ifdef __linux__
#define MC_OS_LINUX 1
#else
#define MC_OS_LINUX 0
#endif

#ifdef __EMSCRIPTEN__
#define MC_OS_EMSCRIPTEN 1
#else
#define MC_OS_EMSCRIPTEN 0
#endif

#ifdef __APPLE__
#ifdef __MACH__
#define MC_OS_DARWIN 1
#else
#define MC_OS_DARWIN 0
#endif
#else
#define MC_OS_DARWIN 0
#endif

#ifdef __x86_64__
#define MC_ARCH_X86_64 1
#else
#define MC_ARCH_X86_64 0
#endif

#ifdef __aarch64__
#define MC_ARCH_AARCH64 1
#else
#define MC_ARCH_AARCH64 0
#endif

#ifdef __wasm32__
#define MC_ARCH_WASM32 1
#else
#define MC_ARCH_WASM32 0
#endif
