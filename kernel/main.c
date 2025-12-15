#include "kernel.h"

void serial_init(void);
void serial_write(const char *s);
void gdt_tss_init(void);
void tss_load(void);
void idt_init(void);

extern const uint8_t userprog_start[];
extern const uint8_t userprog_end[];

struct regs {
	uint64_t r15, r14, r13, r12, r11, r10, r9, r8;
	uint64_t rdi, rsi, rbp, rbx, rdx, rcx, rax;
};

static void kmemcpy(void *dst, const void *src, size_t n) {
	uint8_t *d = (uint8_t *)dst;
	const uint8_t *s = (const uint8_t *)src;
	for (size_t i = 0; i < n; i++) d[i] = s[i];
}

static void serial_write_u64_dec(uint64_t v) {
	char buf[32];
	int i = 0;
	if (v == 0) {
		serial_putc('0');
		return;
	}
	while (v > 0 && i < (int)sizeof(buf)) {
		buf[i++] = (char)('0' + (v % 10));
		v /= 10;
	}
	while (i--) serial_putc(buf[i]);
}

void syscall_handler(struct regs *r) {
	/* Linux x86_64 syscall numbers */
	switch (r->rax) {
	case 0: { /* read(fd, buf, count) */
		uint64_t fd = r->rdi;
		uint8_t *buf = (uint8_t *)r->rsi;
		uint64_t count = r->rdx;
		if (fd != 0 || buf == 0 || count == 0) {
			r->rax = 0;
			return;
		}
		uint64_t i = 0;
		for (; i < count; i++) {
			char c = serial_getc();
			buf[i] = (uint8_t)c;
			if (c == '\n') {
				i++;
				break;
			}
		}
		r->rax = i;
		return;
	}
	case 1: { /* write(fd, buf, count) */
		uint64_t fd = r->rdi;
		const uint8_t *buf = (const uint8_t *)r->rsi;
		uint64_t count = r->rdx;
		if ((fd != 1 && fd != 2) || buf == 0 || count == 0) {
			r->rax = 0;
			return;
		}
		for (uint64_t i = 0; i < count; i++) {
			serial_putc((char)buf[i]);
		}
		r->rax = count;
		return;
	}
	case 60: /* exit(code) */
		serial_write("Process exited with code ");
		serial_write_u64_dec(r->rdi);
		serial_write("\n");
		outb(0xF4, 0x10);
		for (;;) __asm__ volatile("hlt");
	default:
		/* -ENOSYS */
		r->rax = (uint64_t)(-(int64_t)38);
		return;
	}
}

static __attribute__((noreturn)) void enter_user(uint64_t user_rip, uint64_t user_rsp) {
	const uint64_t USER_CS = 0x18 | 3;
	const uint64_t USER_DS = 0x20 | 3;

	__asm__ volatile(
		"cli\n"
		"movw %w0, %%ax\n"
		"mov %%ax, %%ds\n"
		"mov %%ax, %%es\n"
		"mov %%ax, %%fs\n"
		"mov %%ax, %%gs\n"
		"pushq %0\n"      /* SS */
		"pushq %1\n"      /* RSP */
		"pushfq\n"
		"orq $0x200, (%%rsp)\n" /* IF */
		"pushq %2\n"      /* CS */
		"pushq %3\n"      /* RIP */
		"iretq\n"
		:
		: "r"(USER_DS), "r"(user_rsp), "r"(USER_CS), "r"(user_rip)
		: "rax", "memory");
	__builtin_unreachable();
}

static __attribute__((noreturn)) void halt_forever(void) {
	for (;;) {
		__asm__ volatile ("hlt");
	}
}

__attribute__((noreturn)) void kmain(void) {
	serial_init();
	serial_write("monacc kernel\n");

	/* Set up GDT (with ring-3 segments) + TSS, then IDT with int 0x80 gate. */
	serial_write("[k] gdt_tss_init...\n");
	gdt_tss_init();
	serial_write("[k] gdt_tss_init ok\n");
	serial_write("[k] tss_load...\n");
	tss_load();
	serial_write("[k] tss_load ok\n");
	serial_write("[k] idt_init...\n");
	idt_init();
	serial_write("[k] idt_init ok\n");

	/* Copy the tiny user program to a known low address and jump to ring 3. */
	uint8_t *user_dst = (uint8_t *)0x200000;
	size_t user_len = (size_t)(userprog_end - userprog_start);
	kmemcpy(user_dst, userprog_start, user_len);

	uint64_t user_stack_top = 0x300000;
	serial_write("Entering userland...\n");
	enter_user((uint64_t)user_dst, user_stack_top);

	halt_forever();
}
