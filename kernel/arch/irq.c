#include "kernel.h"

#define PIC1_CMD 0x20
#define PIC2_CMD 0xA0
#define PIC_EOI  0x20

void irq_handler(uint64_t vec) {
	/* Acknowledge PIC IRQs if they fire.
	 * Master PIC: vectors 0x20-0x27
	 * Slave PIC:  vectors 0x28-0x2F (EOI slave then master)
	 */
	if (vec >= 0x28 && vec <= 0x2F) {
		outb(PIC2_CMD, PIC_EOI);
	}
	outb(PIC1_CMD, PIC_EOI);
}
