#include "kernel.h"

/* MSR numbers */
#define IA32_EFER   0xC0000080u
#define IA32_STAR   0xC0000081u
#define IA32_LSTAR  0xC0000082u
#define IA32_SFMASK 0xC0000084u

/* EFER bits */
#define EFER_SCE (1u << 0)

/* Global state used by arch/syscall_entry.S (defined in syscall_entry.S) */
extern uint64_t syscall_kstack_top;
extern uint64_t syscall_user_rsp;

static uint8_t syscall_stack[16384] __attribute__((aligned(16)));

extern void syscall_entry(void);

void syscall_init(void) {
	/* One-process bring-up: a single shared syscall stack is enough for now. */
	syscall_kstack_top = (uint64_t)(syscall_stack + sizeof(syscall_stack));

	/* Enable SYSCALL/SYSRET. */
	uint64_t efer = rdmsr(IA32_EFER);
	efer |= (uint64_t)EFER_SCE;
	wrmsr(IA32_EFER, efer);

	/* Segment selectors come from the GDT layout in arch/gdt.c:
	 *  - kernel code: 0x08
	 *  - kernel data: 0x10
	 *  - user code:   0x18 (RPL set by CPU on return)
	 *  - user data:   0x20
	 *
	 * For simplicity (and because we're not using SYSRET yet for initial entry),
	 * we set STAR using the conventional selector values and rely on sysretq to
	 * return to the existing user segments.
	 */
	uint64_t star = ((uint64_t)0x18 << 48) | ((uint64_t)0x08 << 32);
	wrmsr(IA32_STAR, star);
	wrmsr(IA32_LSTAR, (uint64_t)syscall_entry);

	/* Mask flags on syscall entry (clears these bits in RFLAGS).
	 * Clear IF (disable interrupts) + DF.
	 */
	wrmsr(IA32_SFMASK, (1ull << 9) | (1ull << 10));
}
