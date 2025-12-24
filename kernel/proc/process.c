#include "kernel.h"
#include "proc.h"
#include "fs.h"
#include "sys.h"

/* Global process state */
struct kproc g_procs[KPROC_MAX];
struct kproc *g_cur = 0;
uint32_t g_next_pid = 1;

static uint64_t pages_for_range(uint64_t start, uint64_t end) {
	if (end <= start) return 0;
	uint64_t sz = end - start;
	return (sz + PAGE_SIZE - 1) / PAGE_SIZE;
}

struct kproc *kproc_alloc(uint32_t ppid) {
	for (int i = 0; i < KPROC_MAX; i++) {
		if (!g_procs[i].used) {
			struct kproc *p = &g_procs[i];
			kmemset(p, 0, sizeof(*p));
			p->used = 1;
			p->state = KPROC_RUNNABLE;
			p->pid = g_next_pid++;
			p->ppid = ppid;
			p->img_base = USER_IMG_BASE;
			p->img_end = USER_IMG_BASE;
			p->wait_kind = KWAIT_NONE;
			p->wait_obj = 0;
			p->cwd[0] = 0;
			for (int fd = 0; fd < KFD_MAX; fd++) p->fds[fd] = -1;
			/* Per-proc kernel stack (used by SYSCALL entry stub). */
			p->kstack_pages = 8;
			p->kstack_base = pmm_alloc_pages_high(p->kstack_pages);
			if (!p->kstack_base) {
				kmemset(p, 0, sizeof(*p));
				return 0;
			}
			return p;
		}
	}
	return 0;
}

void kproc_free(struct kproc *p) {
	if (!p || !p->used) return;
	kproc_close_all_fds(p);
	if (p->img_backup && p->img_pages) {
		pmm_free_pages(p->img_backup, p->img_pages);
	}
	if (p->user_stack_base && p->user_stack_pages) {
		pmm_free_pages(p->user_stack_base, p->user_stack_pages);
	}
	if (p->kstack_base && p->kstack_pages) {
		pmm_free_pages(p->kstack_base, p->kstack_pages);
	}
	kmemset(p, 0, sizeof(*p));
}

int kproc_ensure_img_backup(struct kproc *p, uint64_t img_end) {
	if (!p) return -1;
	uint64_t pages64 = pages_for_range(p->img_base, img_end);
	if (pages64 == 0) pages64 = 1;
	if (pages64 > 0x7fffffff) return -1;
	uint32_t pages = (uint32_t)pages64;
	if (p->img_backup && p->img_pages == pages) {
		p->img_end = img_end;
		return 0;
	}
	if (p->img_backup && p->img_pages) {
		pmm_free_pages(p->img_backup, p->img_pages);
		p->img_backup = 0;
		p->img_pages = 0;
	}
	uint64_t buf = pmm_alloc_pages_high(pages);
	if (!buf) return -1;
	p->img_backup = buf;
	p->img_pages = pages;
	p->img_end = img_end;
	return 0;
}

void kproc_img_save(struct kproc *p) {
	if (!p || !p->img_backup || p->img_end <= p->img_base) return;
	uint64_t n = p->img_end - p->img_base;
	kmemcpy((void *)p->img_backup, (const void *)p->img_base, (size_t)n);
}

void kproc_img_restore(struct kproc *p) {
	if (!p || !p->img_backup || p->img_end <= p->img_base) return;
	uint64_t n = p->img_end - p->img_base;
	kmemcpy((void *)p->img_base, (const void *)p->img_backup, (size_t)n);
}

void kproc_stack_save(struct kproc *p) {
	if (!p || !p->user_stack_base || p->user_stack_pages == 0) return;
	uint64_t n = (uint64_t)p->user_stack_pages * PAGE_SIZE;
	kmemcpy((void *)p->user_stack_base, (const void *)USER_STACK_BASE, (size_t)n);
}

void kproc_stack_restore(struct kproc *p) {
	if (!p || !p->user_stack_base || p->user_stack_pages == 0) return;
	uint64_t n = (uint64_t)p->user_stack_pages * PAGE_SIZE;
	kmemcpy((void *)USER_STACK_BASE, (const void *)p->user_stack_base, (size_t)n);
}
