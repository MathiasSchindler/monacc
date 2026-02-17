#pragma once

#include "mc_platform.h"

#if MC_OS_LINUX && MC_ARCH_X86_64
#include "mc_syscall_linux_x86_64.h"
#elif MC_OS_EMSCRIPTEN
#include "mc_syscall_emscripten.h"
#elif MC_OS_DARWIN
#if defined(__MONACC__)
#include "mc_syscall_darwin_monacc.h"
#else
#include "mc_syscall_darwin.h"
#endif
#else
#error "Unsupported platform for core/mc_syscall.h"
#endif

