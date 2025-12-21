#pragma once

#include "mc_platform.h"

#if MC_OS_LINUX && MC_ARCH_X86_64
#include "mc_syscall_linux_x86_64.h"
#elif MC_OS_DARWIN
#include "mc_syscall_darwin.h"
#else
#error "Unsupported platform for core/mc_syscall.h"
#endif

