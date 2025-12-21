#include "kernel.h"

/* Xen PVH start info parsing.
 * The loader passes a physical pointer to struct hvm_start_info in %ebx.
 * We only need the first module (initramfs).
 *
 * Layout reference (public): xen/include/public/arch-x86/hvm/start_info.h
 */

#define XEN_HVM_START_MAGIC_VALUE 0x336ec578u

static uint32_t rd_u32(const uint8_t *p) {
	return (uint32_t)p[0] |
	       ((uint32_t)p[1] << 8) |
	       ((uint32_t)p[2] << 16) |
	       ((uint32_t)p[3] << 24);
}

static uint64_t rd_u64(const uint8_t *p) {
	return (uint64_t)p[0] |
	       ((uint64_t)p[1] << 8) |
	       ((uint64_t)p[2] << 16) |
	       ((uint64_t)p[3] << 24) |
	       ((uint64_t)p[4] << 32) |
	       ((uint64_t)p[5] << 40) |
	       ((uint64_t)p[6] << 48) |
	       ((uint64_t)p[7] << 56);
}

int pvh_find_first_module(uint64_t pvh_start_info_ptr, uint64_t *mod_start_out, uint64_t *mod_end_out) {
	if (pvh_start_info_ptr == 0) return -1;
	const uint8_t *si = (const uint8_t *)pvh_start_info_ptr;

	uint32_t magic = rd_u32(si + 0);
	if (magic != XEN_HVM_START_MAGIC_VALUE) return -2;

	uint32_t nr_modules = rd_u32(si + 12);
	uint64_t modlist_paddr = rd_u64(si + 16);
	if (nr_modules == 0 || modlist_paddr == 0) return -3;

	/* struct hvm_modlist_entry { u64 paddr; u64 size; u64 cmdline_paddr; u64 reserved; } */
	const uint8_t *m0 = (const uint8_t *)modlist_paddr;
	uint64_t paddr = rd_u64(m0 + 0);
	uint64_t size = rd_u64(m0 + 8);
	if (paddr == 0 || size == 0) return -4;

	if (mod_start_out) *mod_start_out = paddr;
	if (mod_end_out) *mod_end_out = paddr + size;
	return 0;
}
