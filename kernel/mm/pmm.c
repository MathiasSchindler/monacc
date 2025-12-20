/* Physical Memory Manager - bitmap-based page allocator
 * 
 * Manages physical pages above the kernel area.
 * For simplicity, we start allocating from a fixed address (4 MiB)
 * and support up to 128 MiB of physical memory.
 */

#include "kernel.h"

/* Physical memory layout:
 * 0x000000 - 0x100000: Low memory (legacy, avoid)
 * 0x100000 - 0x400000: Kernel code/data/BSS (~3 MiB)
 * 0x400000 - end:      Available for allocation
 *
 * We'll manage pages from 4 MiB to 128 MiB = 124 MiB = 31744 pages
 * Bitmap needs 31744 / 8 = 3968 bytes
 */

#define PMM_START_ADDR  0x00400000   /* 4 MiB */
#define PMM_END_ADDR    0x08000000   /* 128 MiB */
#define PMM_NUM_PAGES   31744        /* (128M - 4M) / 4K - hardcoded for monacc */
#define BITMAP_SIZE     3968         /* PMM_NUM_PAGES / 8 - hardcoded for monacc */

/* Bitmap: 1 = allocated, 0 = free */
static uint8_t pmm_bitmap[BITMAP_SIZE];

/* Next page to check (for faster allocation) */
static uint32_t pmm_next_page;

void pmm_init(void) {
	/* Mark all pages as free */
	uint32_t i;
	for (i = 0; i < BITMAP_SIZE; i++) {
		pmm_bitmap[i] = 0;
	}
	pmm_next_page = 0;
}

/* Allocate a single physical page, returns physical address or 0 on failure */
uint64_t pmm_alloc_page(void) {
	uint32_t i;
	/* Linear search from pmm_next_page */
	for (i = 0; i < PMM_NUM_PAGES; i++) {
		uint32_t page = (pmm_next_page + i) % PMM_NUM_PAGES;
		uint32_t byte_idx = page / 8;
		uint32_t bit_idx = page % 8;
		uint8_t mask = (uint8_t)(1 << bit_idx);
		
		if ((pmm_bitmap[byte_idx] & mask) == 0) {
			/* Mark as allocated */
			pmm_bitmap[byte_idx] = pmm_bitmap[byte_idx] | mask;
			pmm_next_page = (page + 1) % PMM_NUM_PAGES;
			return PMM_START_ADDR + ((uint64_t)page * PAGE_SIZE);
		}
	}
	return 0;  /* Out of memory */
}

/* Free a physical page */
void pmm_free_page(uint64_t paddr) {
	uint32_t page;
	uint32_t byte_idx;
	uint32_t bit_idx;
	uint8_t mask;
	
	if (paddr < PMM_START_ADDR || paddr >= PMM_END_ADDR) {
		return;  /* Invalid address */
	}
	if (paddr & (PAGE_SIZE - 1)) {
		return;  /* Not page-aligned */
	}
	
	page = (uint32_t)((paddr - PMM_START_ADDR) / PAGE_SIZE);
	byte_idx = page / 8;
	bit_idx = page % 8;
	mask = (uint8_t)(1 << bit_idx);
	
	pmm_bitmap[byte_idx] = pmm_bitmap[byte_idx] & ~mask;
}

/* Allocate n contiguous physical pages, returns start address or 0 on failure */
uint64_t pmm_alloc_pages(uint32_t n) {
	uint32_t start;
	uint32_t j;
	
	if (n == 0) return 0;
	if (n == 1) return pmm_alloc_page();
	
	/* Search for n contiguous free pages */
	for (start = 0; start <= PMM_NUM_PAGES - n; start++) {
		int found = 1;
		for (j = 0; j < n; j++) {
			uint32_t page = start + j;
			uint32_t byte_idx = page / 8;
			uint32_t bit_idx = page % 8;
			uint8_t mask = (uint8_t)(1 << bit_idx);
			if (pmm_bitmap[byte_idx] & mask) {
				found = 0;
				break;
			}
		}
		if (found) {
			/* Mark all as allocated */
			for (j = 0; j < n; j++) {
				uint32_t page = start + j;
				uint32_t byte_idx = page / 8;
				uint32_t bit_idx = page % 8;
				uint8_t mask = (uint8_t)(1 << bit_idx);
				pmm_bitmap[byte_idx] = pmm_bitmap[byte_idx] | mask;
			}
			return PMM_START_ADDR + ((uint64_t)start * PAGE_SIZE);
		}
	}
	return 0;  /* Not enough contiguous memory */
}

/* Allocate n contiguous physical pages from the high end of the PMM range.
 * Useful for keeping large allocations (e.g. user stacks) away from low memory
 * which is often used by ET_EXEC user images.
 */
uint64_t pmm_alloc_pages_high(uint32_t n) {
	uint32_t start;
	uint32_t j;

	if (n == 0) return 0;
	if (n == 1) {
		for (start = PMM_NUM_PAGES; start > 0; start--) {
			uint32_t page = start - 1;
			uint32_t byte_idx = page / 8;
			uint32_t bit_idx = page % 8;
			uint8_t mask = (uint8_t)(1 << bit_idx);
			if ((pmm_bitmap[byte_idx] & mask) == 0) {
				pmm_bitmap[byte_idx] = pmm_bitmap[byte_idx] | mask;
				return PMM_START_ADDR + ((uint64_t)page * PAGE_SIZE);
			}
		}
		return 0;
	}
	if (n > PMM_NUM_PAGES) return 0;

	/* Search for n contiguous free pages, starting from the highest possible. */
	for (start = PMM_NUM_PAGES - n; ; start--) {
		int found = 1;
		for (j = 0; j < n; j++) {
			uint32_t page = start + j;
			uint32_t byte_idx = page / 8;
			uint32_t bit_idx = page % 8;
			uint8_t mask = (uint8_t)(1 << bit_idx);
			if (pmm_bitmap[byte_idx] & mask) {
				found = 0;
				break;
			}
		}
		if (found) {
			for (j = 0; j < n; j++) {
				uint32_t page = start + j;
				uint32_t byte_idx = page / 8;
				uint32_t bit_idx = page % 8;
				uint8_t mask = (uint8_t)(1 << bit_idx);
				pmm_bitmap[byte_idx] = pmm_bitmap[byte_idx] | mask;
			}
			return PMM_START_ADDR + ((uint64_t)start * PAGE_SIZE);
		}
		if (start == 0) break;
	}
	return 0;
}

/* Free n contiguous physical pages starting at paddr */
void pmm_free_pages(uint64_t paddr, uint32_t n) {
	uint32_t i;
	for (i = 0; i < n; i++) {
		pmm_free_page(paddr + (uint64_t)i * PAGE_SIZE);
	}
}

/* Reserve n contiguous pages starting at paddr.
 * This is used for loading ET_EXEC user programs at fixed addresses.
 * Returns 0 on success, non-zero on invalid range.
 */
int pmm_reserve_pages(uint64_t paddr, uint32_t n) {
	uint32_t i;
	if (n == 0) return 0;
	if (paddr < PMM_START_ADDR || paddr >= PMM_END_ADDR) return -1;
	if (paddr & (PAGE_SIZE - 1)) return -2;
	if (paddr + (uint64_t)n * PAGE_SIZE > PMM_END_ADDR) return -3;

	for (i = 0; i < n; i++) {
		uint64_t a = paddr + (uint64_t)i * PAGE_SIZE;
		uint32_t page = (uint32_t)((a - PMM_START_ADDR) / PAGE_SIZE);
		uint32_t byte_idx = page / 8;
		uint32_t bit_idx = page % 8;
		uint8_t mask = (uint8_t)(1 << bit_idx);
		pmm_bitmap[byte_idx] = pmm_bitmap[byte_idx] | mask;
	}
	return 0;
}
