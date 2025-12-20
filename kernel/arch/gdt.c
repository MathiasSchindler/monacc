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
	uint64_t lo = 0;
	lo |= (limit & 0xFFFFULL);
	lo |= (base & 0xFFFFFFULL) << 16;
	lo |= 0x89ULL << 40; /* present | type=available TSS (0x9) */
	lo |= ((uint64_t)(limit >> 16) & 0xFULL) << 48;
	lo |= ((base >> 24) & 0xFFULL) << 56;

	uint64_t hi = 0;
	hi |= (base >> 32) & 0xFFFFFFFFULL;

	gdt[idx] = lo;
	gdt[idx + 1] = hi;
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
	 * Note: monacc doesn't handle static local arrays correctly.
	 * Also, monacc's sizeof returns wrong value for packed structs.
	 * TSS64 is exactly 104 bytes (0x68).
	 * monacc's compound literal copy only copies 8 bytes - must zero manually.
	 * monacc also doesn't honor __attribute__((packed)) for struct layout,
	 * so we must use raw byte offsets:
	 *   RSP0 at offset 4 (8 bytes)
	 *   iomap_base at offset 102 (2 bytes) */
	{
		uint8_t *p = (uint8_t *)&tss;
		int i;
		for (i = 0; i < 104; i++) {
			p[i] = 0;
		}
		/* RSP0 at offset 4 (8 bytes, little-endian) */
		{
			uint64_t rsp0val = (uint64_t)(kstack0 + 16384);
			p[4] = (uint8_t)(rsp0val);
			p[5] = (uint8_t)(rsp0val >> 8);
			p[6] = (uint8_t)(rsp0val >> 16);
			p[7] = (uint8_t)(rsp0val >> 24);
			p[8] = (uint8_t)(rsp0val >> 32);
			p[9] = (uint8_t)(rsp0val >> 40);
			p[10] = (uint8_t)(rsp0val >> 48);
			p[11] = (uint8_t)(rsp0val >> 56);
		}
		/* iomap_base at offset 102 (2 bytes) */
		p[102] = 104;  /* low byte */
		p[103] = 0;    /* high byte */
	}

	set_tss_desc(5, (uint64_t)&tss, (uint32_t)(104 - 1));  /* limit = 103 */

	/* Build GDT pointer in a byte array: 2-byte limit + 8-byte base */
	/* Note: sizeof(gdt) doesn't work correctly in monacc for arrays,
	   so we compute it as 7 * sizeof(uint64_t) = 56 */
	uint8_t gdtr[10];
	uint16_t lim = (uint16_t)(7 * 8 - 1);  /* 7 entries * 8 bytes - 1 = 55 */
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
