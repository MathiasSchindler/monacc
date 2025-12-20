#include "kernel.h"

#define PIC1_CMD  0x20
#define PIC1_DATA 0x21
#define PIC2_CMD  0xA0
#define PIC2_DATA 0xA1

#define ICW1_INIT 0x10
#define ICW1_ICW4 0x01
#define ICW4_8086 0x01

static void io_wait(void) {
	/* Historically: outb(0x80, 0). QEMU tolerates it and it is simple. */
	outb(0x80, 0);
}

void pic_init(void) {
	/* Remap PIC to 0x20-0x2F and mask all IRQs.
	 * This avoids IRQ vectors colliding with CPU exceptions (0x00-0x1F).
	 */
	uint8_t a1 = inb(PIC1_DATA);
	uint8_t a2 = inb(PIC2_DATA);

	outb(PIC1_CMD, ICW1_INIT | ICW1_ICW4);
	io_wait();
	outb(PIC2_CMD, ICW1_INIT | ICW1_ICW4);
	io_wait();

	outb(PIC1_DATA, 0x20);
	io_wait();
	outb(PIC2_DATA, 0x28);
	io_wait();

	outb(PIC1_DATA, 4);
	io_wait();
	outb(PIC2_DATA, 2);
	io_wait();

	outb(PIC1_DATA, ICW4_8086);
	io_wait();
	outb(PIC2_DATA, ICW4_8086);
	io_wait();

	/* Mask all IRQs for now. */
	outb(PIC1_DATA, 0xFF);
	outb(PIC2_DATA, 0xFF);

	(void)a1;
	(void)a2;
}
