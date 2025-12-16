// Minimal Linux x86_64 entrypoint.
// Parses argc/argv/envp from the initial stack and calls main.
//
// This file is intended for hosted (cc/clang) builds only.

#include "mc.h"

int main(int argc, char **argv);

__attribute__((noreturn, used, noinline)) static void mc_start_c(long *sp) {
	int argc = (int)sp[0];
	char **argv = (char **)(sp + 1);
	char **envp = argv + argc + 1;
	mc_set_start_envp(envp);
	mc_exit((mc_i32)main(argc, argv));
}

__attribute__((naked, noreturn)) void _start(void) {
	__asm__ volatile(
		"mov %rsp, %rdi\n"
		"andq $-16, %rsp\n"
		"call mc_start_c\n"
	);
}
