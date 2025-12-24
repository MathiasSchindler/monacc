#include "kernel.h"
#include "proc.h"
#include "sys.h"

struct kproc *kproc_pick_next(void) {
	if (!g_cur) {
		for (int i = 0; i < KPROC_MAX; i++) {
			if (g_procs[i].used && g_procs[i].state == KPROC_RUNNABLE) return &g_procs[i];
		}
		return 0;
	}
	int start = 0;
	for (int i = 0; i < KPROC_MAX; i++) {
		if (&g_procs[i] == g_cur) { start = i + 1; break; }
	}
	for (int off = 0; off < KPROC_MAX; off++) {
		int idx = (start + off) % KPROC_MAX;
		if (g_procs[idx].used && g_procs[idx].state == KPROC_RUNNABLE) return &g_procs[idx];
	}
	return g_cur;
}

void kproc_switch(struct regs *frame, struct kproc *next) {
	if (!frame || !next || !next->used) return;
	if (g_cur && g_cur->used) {
		g_cur->regs = *frame;
		g_cur->user_rsp = syscall_user_rsp;
		kproc_stack_save(g_cur);
		kproc_img_save(g_cur);
	}
	g_cur = next;
	k_current_pid = (uint64_t)g_cur->pid;
	kproc_stack_restore(g_cur);
	kproc_img_restore(g_cur);
	*frame = g_cur->regs;
	syscall_user_rsp = g_cur->user_rsp;
	syscall_kstack_top = g_cur->kstack_base + (uint64_t)g_cur->kstack_pages * PAGE_SIZE;
}

void kproc_die_if_no_runnable(void) {
	for (int i = 0; i < KPROC_MAX; i++) {
		if (g_procs[i].used && g_procs[i].state == KPROC_RUNNABLE) return;
	}
	serial_write("[k] no runnable processes; halting\n");
	halt_forever();
}
