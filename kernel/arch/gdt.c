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

struct gdt_ptr {
	uint16_t limit;
	uint64_t base;
} __attribute__((packed));

static uint64_t gdt[7];
static struct tss64 tss;

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

static void gdt_reload(uint16_t code_sel, uint16_t data_sel) {
	__asm__ volatile(
		"movw %w0, %%ds\n"
		"movw %w0, %%es\n"
		"movw %w0, %%ss\n"
		"pushq %1\n"
		"leaq 1f(%%rip), %%rax\n"
		"pushq %%rax\n"
		"lretq\n"
		"1:\n"
		:
		: "r"(data_sel), "r"((uint64_t)code_sel)
		: "rax", "memory");
}

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

	static uint8_t kstack0[16384] __attribute__((aligned(16)));
	tss = (struct tss64){0};
	tss.rsp0 = (uint64_t)(kstack0 + sizeof(kstack0));
	tss.iomap_base = sizeof(struct tss64);

	set_tss_desc(5, (uint64_t)&tss, (uint32_t)(sizeof(tss) - 1));

	struct gdt_ptr gdtr;
	gdtr.limit = (uint16_t)(sizeof(gdt) - 1);
	gdtr.base = (uint64_t)gdt;
	__asm__ volatile("lgdt %0" :: "m"(gdtr));

	/* Reload segments + CS via far return. */
	gdt_reload(0x08, 0x10);
}

void tss_load(void) {
	/* TSS selector at index 5 => 0x28 */
	__asm__ volatile("ltr %0" :: "r"((uint16_t)0x28));
}
