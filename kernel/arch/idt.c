#include "kernel.h"

struct idt_entry {
	uint16_t offset_low;
	uint16_t selector;
	uint8_t ist;
	uint8_t type_attr;
	uint16_t offset_mid;
	uint32_t offset_high;
	uint32_t zero;
} __attribute__((packed));

struct idt_ptr {
	uint16_t limit;
	uint64_t base;
} __attribute__((packed));

extern void isr80(void);

static struct idt_entry idt[256];

static void idt_set_gate(int vec, void (*handler)(void), uint8_t type_attr) {
	uint64_t addr = (uint64_t)handler;
	idt[vec].offset_low = (uint16_t)(addr & 0xFFFF);
	idt[vec].selector = 0x08; /* kernel code */
	idt[vec].ist = 0;
	idt[vec].type_attr = type_attr;
	idt[vec].offset_mid = (uint16_t)((addr >> 16) & 0xFFFF);
	idt[vec].offset_high = (uint32_t)((addr >> 32) & 0xFFFFFFFF);
	idt[vec].zero = 0;
}

void idt_init(void) {
	for (int i = 0; i < 256; i++) {
		idt[i] = (struct idt_entry){0};
	}

	/* int 0x80: present | DPL=3 | interrupt gate */
	idt_set_gate(0x80, isr80, 0xEE);

	struct idt_ptr idtr;
	idtr.limit = (uint16_t)(sizeof(idt) - 1);
	idtr.base = (uint64_t)idt;
	__asm__ volatile("lidt %0" :: "m"(idtr));
}
