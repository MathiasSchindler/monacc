#include "kernel.h"

#define COM2 0x2F8

static int serial2_tx_ready(void) {
	return (inb(COM2 + 5) & 0x20) != 0;
}

static int serial2_rx_ready(void) {
	return (inb(COM2 + 5) & 0x01) != 0;
}

void serial2_init(void) {
	outb(COM2 + 1, 0x00); // disable interrupts
	outb(COM2 + 3, 0x80); // DLAB on
	outb(COM2 + 0, 0x01); // divisor low  (115200 baud with 115200 base)
	outb(COM2 + 1, 0x00); // divisor high
	outb(COM2 + 3, 0x03); // 8N1
	outb(COM2 + 2, 0xC7); // enable FIFO, clear, 14-byte threshold
	outb(COM2 + 4, 0x0B); // IRQs off, RTS/DSR set
}

void serial2_putc(char c) {
	while (!serial2_tx_ready()) {
		// spin
	}
	outb(COM2, (uint8_t)c);
}

int serial2_try_getc(char *out) {
	if (!out) return 0;
	if (!serial2_rx_ready()) return 0;
	*out = (char)inb(COM2);
	return 1;
}

char serial2_getc(void) {
	while (!serial2_rx_ready()) {
		// spin
	}
	return (char)inb(COM2);
}

void serial2_write(const void *buf, uint64_t n) {
	const uint8_t *p = (const uint8_t *)buf;
	if (!p) return;
	for (uint64_t i = 0; i < n; i++) {
		serial2_putc((char)p[i]);
	}
}

void serial2_read(void *buf, uint64_t n) {
	uint8_t *p = (uint8_t *)buf;
	if (!p) return;
	for (uint64_t i = 0; i < n; i++) {
		p[i] = (uint8_t)serial2_getc();
	}
}
