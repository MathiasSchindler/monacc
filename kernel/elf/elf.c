#include "kernel.h"

/* Minimal ELF64 loader for a single-process, identity-mapped kernel.
 *
 * Constraints/assumptions (true for monacc-built tools like bin/echo):
 * - ELF64 little-endian, ET_EXEC
 * - One or more PT_LOAD segments
 * - No relocations (we don't implement a dynamic linker yet)
 * - Paging identity-maps at least the first 1GiB and marks it user-accessible
 */

static uint16_t rd_u16(const uint8_t *p) {
	return (uint16_t)p[0] | (uint16_t)((uint16_t)p[1] << 8);
}

static uint32_t rd_u32(const uint8_t *p) {
	return (uint32_t)p[0] |
	       (uint32_t)((uint32_t)p[1] << 8) |
	       (uint32_t)((uint32_t)p[2] << 16) |
	       (uint32_t)((uint32_t)p[3] << 24);
}

static uint64_t rd_u64(const uint8_t *p) {
	uint64_t lo = (uint64_t)rd_u32(p);
	uint64_t hi = (uint64_t)rd_u32(p + 4);
	return lo | (hi << 32);
}

static uint64_t align_down(uint64_t v, uint64_t a) {
	return v & ~(a - 1);
}

static uint64_t align_up(uint64_t v, uint64_t a) {
	return (v + (a - 1)) & ~(a - 1);
}

static void kmemcpy_u8(uint8_t *dst, const uint8_t *src, uint64_t n) {
	uint64_t i;
	for (i = 0; i < n; i++) dst[i] = src[i];
}

static void kmemset_u8(uint8_t *dst, uint8_t val, uint64_t n) {
	uint64_t i;
	for (i = 0; i < n; i++) dst[i] = val;
}

/* Loads an ET_EXEC ELF into memory at its p_vaddr and returns entry + initial brk.
 * Returns 0 on success, non-zero on failure.
 */
int elf_load_exec(const uint8_t *img, uint64_t img_sz, uint64_t *entry_out, uint64_t *brk_init_out) {
	/* ELF header offsets (ELF64): */
	/* e_ident[0..15] */
	/* e_type @ 16 (2) */
	/* e_machine @ 18 (2) */
	/* e_version @ 20 (4) */
	/* e_entry @ 24 (8) */
	/* e_phoff @ 32 (8) */
	/* e_ehsize @ 52 (2) */
	/* e_phentsize @ 54 (2) */
	/* e_phnum @ 56 (2) */

	if (img_sz < 64) return -1;
	if (!(img[0] == 0x7f && img[1] == 'E' && img[2] == 'L' && img[3] == 'F')) return -2;
	if (img[4] != 2) return -3; /* ELFCLASS64 */
	if (img[5] != 1) return -4; /* little endian */

	{
		uint16_t e_type = rd_u16(img + 16);
		uint16_t e_machine = rd_u16(img + 18);
		uint64_t e_entry = rd_u64(img + 24);
		uint64_t e_phoff = rd_u64(img + 32);
		uint16_t e_ehsize = rd_u16(img + 52);
		uint16_t e_phentsize = rd_u16(img + 54);
		uint16_t e_phnum = rd_u16(img + 56);

		if (e_ehsize != 64) return -5;
		if (e_type != 2) return -6;     /* ET_EXEC */
		if (e_machine != 0x3e) return -7; /* EM_X86_64 */
		if (e_phentsize < 56) return -8;
		if (e_phnum == 0) return -9;
		if (e_phoff + (uint64_t)e_phentsize * (uint64_t)e_phnum > img_sz) return -10;

		uint64_t brk_max = 0;
		uint16_t i;
		for (i = 0; i < e_phnum; i++) {
			const uint8_t *ph = img + e_phoff + (uint64_t)i * (uint64_t)e_phentsize;
			uint32_t p_type = rd_u32(ph + 0);
			uint32_t p_flags = rd_u32(ph + 4);
			uint64_t p_offset = rd_u64(ph + 8);
			uint64_t p_vaddr = rd_u64(ph + 16);
			uint64_t p_filesz = rd_u64(ph + 32);
			uint64_t p_memsz = rd_u64(ph + 40);
			uint64_t p_align = rd_u64(ph + 48);

			(void)p_flags;
			(void)p_align;

			if (p_type != 1) continue; /* PT_LOAD */
			if (p_memsz < p_filesz) return -11;
			if (p_offset + p_filesz > img_sz) return -12;
			if ((p_vaddr & (PAGE_SIZE - 1)) != 0) {
				/* monacc tools are page-aligned; keep it simple for now */
				return -13;
			}

			/* Reserve the pages backing this segment so PMM won't hand them out. */
			{
				uint64_t seg_start = align_down(p_vaddr, PAGE_SIZE);
				uint64_t seg_end = align_up(p_vaddr + p_memsz, PAGE_SIZE);
				uint64_t pages = (seg_end - seg_start) / PAGE_SIZE;
				if (pages == 0) pages = 1;
				if (pmm_reserve_pages(seg_start, (uint32_t)pages) != 0) return -14;
			}

			/* Copy file bytes, then zero BSS tail. */
			kmemcpy_u8((uint8_t *)p_vaddr, img + p_offset, p_filesz);
			if (p_memsz > p_filesz) {
				kmemset_u8((uint8_t *)(p_vaddr + p_filesz), 0, p_memsz - p_filesz);
			}

			if (p_vaddr + p_memsz > brk_max) brk_max = p_vaddr + p_memsz;
		}

		if (entry_out) *entry_out = e_entry;
		if (brk_init_out) *brk_init_out = align_up(brk_max, PAGE_SIZE);
		return 0;
	}
}
