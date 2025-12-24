#ifndef PROC_H
#define PROC_H

#include "kernel.h"

#define KEXEC_MAX_ARGS 16
#define KEXEC_MAX_STR  256
#define USER_STACK_PAGES 2048
#define USER_STACK_TOP  0x07FF8000ULL
#define USER_STACK_BASE (USER_STACK_TOP - (uint64_t)USER_STACK_PAGES * PAGE_SIZE)
#define USER_IMG_BASE 0x400000ull
#define KPROC_MAX 16
#define KFD_MAX 64

enum kwait_kind {
	KWAIT_NONE = 0,
	KWAIT_CHILD = 1,
	KWAIT_PIPE_READ = 2,
	KWAIT_PIPE_WRITE = 3,
};

struct regs {
	uint64_t r15;
	uint64_t r14;
	uint64_t r13;
	uint64_t r12;
	uint64_t r11;
	uint64_t r10;
	uint64_t r9;
	uint64_t r8;
	uint64_t rdi;
	uint64_t rsi;
	uint64_t rbp;
	uint64_t rbx;
	uint64_t rdx;
	uint64_t rcx;
	uint64_t rax;
};

enum kproc_state {
	KPROC_UNUSED = 0,
	KPROC_RUNNABLE = 1,
	KPROC_WAITING = 2,
	KPROC_ZOMBIE = 3,
};

struct kproc {
	uint8_t used;
	uint8_t state;
	uint16_t _pad;
	uint32_t pid;
	uint32_t ppid;
	uint32_t wait_kind;
	uint32_t wait_obj;

	char cwd[KEXEC_MAX_STR];
	int32_t fds[KFD_MAX];

	struct regs regs;
	uint64_t user_rsp;

	uint64_t img_base;
	uint64_t img_end;
	uint64_t img_backup;
	uint32_t img_pages;

	uint64_t user_stack_base;
	uint32_t user_stack_pages;

	uint64_t kstack_base;
	uint32_t kstack_pages;
};

/* Process management */
struct kproc *kproc_alloc(uint32_t ppid);
void kproc_free(struct kproc *p);
int kproc_ensure_img_backup(struct kproc *p, uint64_t img_end);
void kproc_img_save(struct kproc *p);
void kproc_img_restore(struct kproc *p);
void kproc_stack_save(struct kproc *p);
void kproc_stack_restore(struct kproc *p);

/* Scheduler */
struct kproc *kproc_pick_next(void);
void kproc_switch(struct regs *frame, struct kproc *next);
void kproc_die_if_no_runnable(void);

/* Global process state (exported for syscalls) */
extern struct kproc g_procs[KPROC_MAX];
extern struct kproc *g_cur;
extern uint32_t g_next_pid;

#endif
