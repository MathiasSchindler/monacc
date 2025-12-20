#include "kernel.h"

struct exc_frame {
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
	uint64_t vector;
	uint64_t err;
	uint64_t rip;
	uint64_t cs;
	uint64_t rflags;
	uint64_t rsp;
	uint64_t ss;
};

static void serial_write_hex_u64(uint64_t v) {
	static const char hex[] = "0123456789abcdef";
	serial_write("0x");
	for (int i = 15; i >= 0; i--) {
		uint8_t nib = (uint8_t)((v >> (i * 4)) & 0xFULL);
		serial_putc(hex[nib]);
	}
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

__attribute__((noreturn)) void exception_handler(struct exc_frame *f) {
	disable_interrupts();

	serial_write("\n[k] EXCEPTION vector=");
	serial_write_u64_dec(f->vector);
	serial_write(" err=");
	serial_write_hex_u64(f->err);
	serial_write("\n");

	serial_write("    RIP=");
	serial_write_hex_u64(f->rip);
	serial_write(" CS=");
	serial_write_hex_u64(f->cs);
	serial_write(" RFLAGS=");
	serial_write_hex_u64(f->rflags);
	serial_write("\n");

	if ((f->cs & 3) != 0) {
		serial_write("    RSP=");
		serial_write_hex_u64(f->rsp);
		serial_write(" SS=");
		serial_write_hex_u64(f->ss);
		serial_write("\n");
	}

	if (f->vector == 14) {
		uint64_t cr2 = read_cr2();
		serial_write("    CR2=");
		serial_write_hex_u64(cr2);
		serial_write("\n");
	}

	serial_write("    RAX=");
	serial_write_hex_u64(f->rax);
	serial_write(" RBX=");
	serial_write_hex_u64(f->rbx);
	serial_write(" RCX=");
	serial_write_hex_u64(f->rcx);
	serial_write(" RDX=");
	serial_write_hex_u64(f->rdx);
	serial_write("\n");

	serial_write("    RSI=");
	serial_write_hex_u64(f->rsi);
	serial_write(" RDI=");
	serial_write_hex_u64(f->rdi);
	serial_write(" RBP=");
	serial_write_hex_u64(f->rbp);
	serial_write("\n");

	serial_write("[k] Halting.\n");
	halt_forever();
}
