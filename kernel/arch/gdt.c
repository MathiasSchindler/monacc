#include "kernel.h"

struct tss64 {
	uint32_t reserved0;
	uint64_t rsp0;
	uint64_t rsp1;
	uint64_t rsp2;
	uint64_t reserved1;
	uint64_t ist1;
	uint64_t ist2;
	uint64_t ist3;
	uint64_t ist4;
	uint64_t ist5;
	uint64_t ist6;
	uint64_t ist7;
	uint64_t reserved2;
	uint16_t reserved3;
	uint16_t iomap_base;
} __attribute__((packed));

static uint64_t gdt[7];
static struct tss64 tss;
static uint8_t kstack0[16384] __attribute__((aligned(16)));

static uint64_t make_seg(uint8_t access, uint8_t flags) {
	/* Flat segment: limit=0xFFFFF, base=0 */
	uint64_t limit_low = 0xFFFF;
	uint64_t limit_high = 0xF;
	uint64_t base_low = 0;
	uint64_t base_mid = 0;
	uint64_t base_high = 0;

	uint64_t desc = 0;
	desc |= limit_low;
	desc |= base_low << 16;
	desc |= base_mid << 32;
	desc |= (uint64_t)access << 40;
	desc |= limit_high << 48;
	desc |= (uint64_t)flags << 52;
	desc |= base_high << 56;
	return desc;
}

static void set_tss_desc(int idx, uint64_t base, uint32_t limit) {
	/* Build the 16-byte 64-bit TSS descriptor byte-by-byte.
	 * Avoid wide left shifts here: monacc has historically had issues that can
	 * silently produce an invalid descriptor, and then `ltr` will #GP. */
	uint8_t *p = (uint8_t *)&gdt[idx];

	/* bytes 0-1: limit[0:15] */
	p[0] = (uint8_t)(limit);
	p[1] = (uint8_t)(limit >> 8);

	/* bytes 2-4: base[0:23] */
	p[2] = (uint8_t)(base);
	p[3] = (uint8_t)(base >> 8);
	p[4] = (uint8_t)(base >> 16);

	/* byte 5: access (P=1, DPL=0, S=0, type=0x9 available TSS) */
	p[5] = 0x89;

	/* byte 6: limit[16:19] in low nibble; flags in high nibble (0 for TSS) */
	p[6] = (uint8_t)((limit >> 16) & 0x0F);

	/* byte 7: base[24:31] */
	p[7] = (uint8_t)(base >> 24);

	/* bytes 8-11: base[32:63] */
	p[8] = (uint8_t)(base >> 32);
	p[9] = (uint8_t)(base >> 40);
	p[10] = (uint8_t)(base >> 48);
	p[11] = (uint8_t)(base >> 56);

	/* bytes 12-15: reserved */
	p[12] = 0;
	p[13] = 0;
	p[14] = 0;
	p[15] = 0;
}

extern void gdt_reload(uint16_t code_sel, uint16_t data_sel);

void gdt_tss_init(void) {
	/* selectors:
	 * 0x00 null
	 * 0x08 kernel code
	 * 0x10 kernel data
	 * 0x18 user code
	 * 0x20 user data
	 * 0x28/0x30 TSS
	 */
	gdt[0] = 0;
	gdt[1] = make_seg(0x9A, 0xA); /* kernel code: L=1 */
	gdt[2] = make_seg(0x92, 0xC); /* kernel data */
	gdt[3] = make_seg(0xFA, 0xA); /* user code */
	gdt[4] = make_seg(0xF2, 0xC); /* user data */
	gdt[5] = 0;
	gdt[6] = 0;

	/* kstack0 is at file scope to ensure it's in BSS, not on function stack.
	 */
	tss = (struct tss64){0};
	tss.rsp0 = (uint64_t)(kstack0 + sizeof(kstack0));
	/* No I/O bitmap: set iomap_base to end of TSS. */
	tss.iomap_base = (uint16_t)sizeof(tss);

	set_tss_desc(5, (uint64_t)&tss, (uint32_t)(sizeof(tss) - 1));

	/* Build GDT pointer in a byte array: 2-byte limit + 8-byte base */
	uint8_t gdtr[10];
	uint16_t lim = (uint16_t)(sizeof(gdt) - 1);
	uint64_t base = (uint64_t)gdt;
	gdtr[0] = (uint8_t)(lim & 0xFF);
	gdtr[1] = (uint8_t)(lim >> 8);
	gdtr[2] = (uint8_t)(base);
	gdtr[3] = (uint8_t)(base >> 8);
	gdtr[4] = (uint8_t)(base >> 16);
	gdtr[5] = (uint8_t)(base >> 24);
	gdtr[6] = (uint8_t)(base >> 32);
	gdtr[7] = (uint8_t)(base >> 40);
	gdtr[8] = (uint8_t)(base >> 48);
	gdtr[9] = (uint8_t)(base >> 56);
	lgdt(gdtr);

	/* Reload segments + CS via far return. */
	gdt_reload(0x08, 0x10);
}

void tss_load(void) {
	/* TSS selector at index 5 => 0x28 */
	ltr((uint16_t)0x28);
}
