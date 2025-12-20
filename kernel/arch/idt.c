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
extern void isr6(void);
extern void isr8(void);
extern void isr13(void);
extern void isr14(void);

/* PIC IRQ stubs (after remap to 0x20-0x2F). */
extern void isr32(void);
extern void isr33(void);
extern void isr34(void);
extern void isr35(void);
extern void isr36(void);
extern void isr37(void);
extern void isr38(void);
extern void isr39(void);
extern void isr40(void);
extern void isr41(void);
extern void isr42(void);
extern void isr43(void);
extern void isr44(void);
extern void isr45(void);
extern void isr46(void);
extern void isr47(void);

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

	/* Exceptions: present | DPL=0 | interrupt gate */
	idt_set_gate(6, isr6, 0x8E);   /* #UD */
	idt_set_gate(8, isr8, 0x8E);   /* #DF */
	idt_set_gate(13, isr13, 0x8E); /* #GP */
	idt_set_gate(14, isr14, 0x8E); /* #PF */

	/* PIC IRQs: present | DPL=0 | interrupt gate */
	idt_set_gate(0x20, isr32, 0x8E);
	idt_set_gate(0x21, isr33, 0x8E);
	idt_set_gate(0x22, isr34, 0x8E);
	idt_set_gate(0x23, isr35, 0x8E);
	idt_set_gate(0x24, isr36, 0x8E);
	idt_set_gate(0x25, isr37, 0x8E);
	idt_set_gate(0x26, isr38, 0x8E);
	idt_set_gate(0x27, isr39, 0x8E);
	idt_set_gate(0x28, isr40, 0x8E);
	idt_set_gate(0x29, isr41, 0x8E);
	idt_set_gate(0x2A, isr42, 0x8E);
	idt_set_gate(0x2B, isr43, 0x8E);
	idt_set_gate(0x2C, isr44, 0x8E);
	idt_set_gate(0x2D, isr45, 0x8E);
	idt_set_gate(0x2E, isr46, 0x8E);
	idt_set_gate(0x2F, isr47, 0x8E);

	/* Note: monacc's sizeof(array) returns element size, not array size.
	 * Compute manually: 256 entries * 16 bytes = 4096 bytes.
	 * Use byte array for IDTR to avoid monacc struct memory operand issues. */
	uint8_t idtr[10];
	uint16_t lim = (uint16_t)(256 * 16 - 1);
	uint64_t base = (uint64_t)idt;
	idtr[0] = (uint8_t)(lim & 0xFF);
	idtr[1] = (uint8_t)(lim >> 8);
	idtr[2] = (uint8_t)(base);
	idtr[3] = (uint8_t)(base >> 8);
	idtr[4] = (uint8_t)(base >> 16);
	idtr[5] = (uint8_t)(base >> 24);
	idtr[6] = (uint8_t)(base >> 32);
	idtr[7] = (uint8_t)(base >> 40);
	idtr[8] = (uint8_t)(base >> 48);
	idtr[9] = (uint8_t)(base >> 56);
	lidt(idtr);
}
