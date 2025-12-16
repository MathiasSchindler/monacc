#include "kernel.h"

void serial_init(void);
void serial_write(const char *s);
void gdt_tss_init(void);
void tss_load(void);
void idt_init(void);

/* Get user program address from linker symbol via function pointer trick.
 * This avoids monacc issues with extern array declarations. */
void userprog_start_func(void);
void userprog_end_func(void);

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

static void serial_write_hex(uint64_t v) {
	const char *hex = "0123456789abcdef";
	char buf[16];
	int i;
	for (i = 0; i < 16; i++) {
		buf[15 - i] = hex[v & 0xf];
		v >>= 4;
	}
	/* Skip leading zeros but keep at least one digit */
	for (i = 0; i < 15 && buf[i] == '0'; i++);
	while (i < 16) serial_putc(buf[i++]);
}

void syscall_handler(struct regs *r) {
	serial_write("[k] syscall ");
	serial_write_hex(r->rax);
	serial_write("\n");
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
	case 9: { /* mmap(addr, len, prot, flags, fd, offset) */
		uint64_t addr = r->rdi;
		uint64_t len = r->rsi;
		uint64_t prot = r->rdx;
		uint64_t flags = r->r10;
		int64_t fd = (int64_t)r->r8;
		uint64_t offset = r->r9;
		
		serial_write("[k] mmap: len=");
		serial_write_u64_dec(len);
		serial_write(" flags=0x");
		serial_write_hex(flags);
		serial_write("\n");
		
		/* We only support anonymous private mappings */
		if (!(flags & MAP_ANONYMOUS) || !(flags & MAP_PRIVATE)) {
			serial_write("[k] mmap: bad flags\n");
			r->rax = (uint64_t)-22;  /* -EINVAL */
			return;
		}
		/* fd must be -1 for anonymous, offset must be 0 */
		if (fd != -1 || offset != 0) {
			serial_write("[k] mmap: bad fd/offset\n");
			r->rax = (uint64_t)-22;  /* -EINVAL */
			return;
		}
		/* We ignore addr hint for now (always pick our own address) */
		(void)addr;
		(void)prot;  /* We always map read+write for now */
		
		/* Round up length to page size */
		uint64_t pages = (len + PAGE_SIZE - 1) / PAGE_SIZE;
		if (pages == 0) pages = 1;
		
		uint64_t paddr = pmm_alloc_pages((uint32_t)pages);
		if (paddr == 0) {
			serial_write("[k] mmap: out of memory\n");
			r->rax = (uint64_t)-12;  /* -ENOMEM */
			return;
		}
		
		/* Zero the allocated memory (mmap guarantees zeroed pages) */
		uint8_t *p = (uint8_t *)paddr;
		uint64_t i;
		for (i = 0; i < pages * PAGE_SIZE; i++) {
			p[i] = 0;
		}
		
		serial_write("[k] mmap: returning 0x");
		serial_write_hex(paddr);
		serial_write("\n");
		
		/* Since we use identity mapping, physical = virtual */
		r->rax = paddr;
		return;
	}
	case 11: { /* munmap(addr, len) */
		uint64_t addr = r->rdi;
		uint64_t len = r->rsi;
		
		uint64_t pages = (len + PAGE_SIZE - 1) / PAGE_SIZE;
		if (pages == 0) pages = 1;
		
		pmm_free_pages(addr, (uint32_t)pages);
		r->rax = 0;
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
	for (;;) { __asm__ volatile("hlt"); }
}

static __attribute__((noreturn)) void halt_forever(void) {
	for (;;) {
		__asm__ volatile ("hlt");
	}
}

__attribute__((noreturn)) void kmain(void) {
	serial_init();
	serial_write("monacc kernel\n");

	/* Initialize physical memory manager */
	serial_write("[k] pmm_init...\n");
	pmm_init();
	serial_write("[k] pmm_init ok\n");

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

	/* Run the user program from its embedded location in the kernel.
	 * We don't copy it because it uses RIP-relative addressing for strings.
	 * User stack is at a separate location (0x300000). */
	uint64_t user_stack_top = 0x300000;
	uint64_t user_entry = (uint64_t)userprog_start_func;
	serial_write("Entering userland...\n");
	enter_user(user_entry, user_stack_top);

	halt_forever();
}
