#include "kernel.h"

extern uint64_t k_current_pid;

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

static void serial_write_hex_u8(uint8_t v) {
	static const char hex[] = "0123456789abcdef";
	serial_putc(hex[(v >> 4) & 0xF]);
	serial_putc(hex[v & 0xF]);
}

static void dump_bytes16(const char *label, uint64_t addr) {
	serial_write("    ");
	serial_write(label);
	serial_write(" @ ");
	serial_write_hex_u64(addr);
	serial_write(": ");
	volatile const uint8_t *p = (volatile const uint8_t *)addr;
	for (int i = 0; i < 16; i++) {
		serial_write_hex_u8(p[i]);
		if (i != 15) serial_putc(' ');
	}
	serial_write("\n");
}

__attribute__((noreturn)) void exception_handler(struct exc_frame *f) {
	disable_interrupts();

	serial_write("\n[k] EXCEPTION vector=");
	serial_write_u64_dec(f->vector);
	serial_write(" pid=");
	serial_write_u64_dec(k_current_pid);
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
		dump_bytes16("RIP bytes", f->rip);
		dump_bytes16("RSP bytes", f->rsp);
		/* Helpful for diagnosing execve/startup issues: dump the well-known user image entry region.
		 * USER_IMG_BASE is 0x400000 in this kernel.
		 */
		if (f->vector == 6 || f->vector == 13) {
			dump_bytes16("0x4000b0 bytes", 0x4000b0);
			dump_bytes16("0x4000c0 bytes", 0x4000c0);
			dump_bytes16("0x40b6a8 bytes", 0x40b6a8);
		}
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
