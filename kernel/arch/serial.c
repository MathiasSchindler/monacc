#include "kernel.h"

#define COM1 0x3F8

static int serial_tx_ready(void) {
	return (inb(COM1 + 5) & 0x20) != 0;
}

static int serial_rx_ready(void) {
	return (inb(COM1 + 5) & 0x01) != 0;
}

void serial_init(void) {
	outb(COM1 + 1, 0x00); // disable interrupts
	outb(COM1 + 3, 0x80); // DLAB on
	outb(COM1 + 0, 0x01); // divisor low  (115200 baud with 115200 base)
	outb(COM1 + 1, 0x00); // divisor high
	outb(COM1 + 3, 0x03); // 8N1
	outb(COM1 + 2, 0xC7); // enable FIFO, clear, 14-byte threshold
	outb(COM1 + 4, 0x0B); // IRQs off, RTS/DSR set
}

void serial_putc(char c) {
	while (!serial_tx_ready()) {
		// spin
	}
	outb(COM1, (uint8_t)c);
}

char serial_getc(void) {
	while (!serial_rx_ready()) {
		// spin
	}
	return (char)inb(COM1);
}

void serial_write(const char *s) {
	for (; *s; s++) {
		if (*s == '\n') {
			serial_putc('\r');
		}
		serial_putc(*s);
	}
}
