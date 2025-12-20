#include "kernel.h"

/* Multiboot2 info parsing (GRUB/Multiboot2).
 * We only need modules for initramfs bring-up.
 */

#define MB2_TAG_END     0
#define MB2_TAG_MODULE  3

static uint32_t rd_u32(const uint8_t *p) {
	return (uint32_t)p[0] |
	       ((uint32_t)p[1] << 8) |
	       ((uint32_t)p[2] << 16) |
	       ((uint32_t)p[3] << 24);
}

static uint64_t align_up_u64(uint64_t v, uint64_t a) {
	return (v + (a - 1)) & ~(a - 1);
}

int mb2_find_first_module(uint64_t mb2_info_ptr, uint64_t *mod_start_out, uint64_t *mod_end_out) {
	if (mb2_info_ptr == 0) return -1;
	const uint8_t *info = (const uint8_t *)mb2_info_ptr;
	uint32_t total_size = rd_u32(info + 0);
	if (total_size < 16) return -2;

	uint64_t off = 8;
	while (off + 8 <= (uint64_t)total_size) {
		const uint8_t *tag = info + off;
		uint32_t type = rd_u32(tag + 0);
		uint32_t size = rd_u32(tag + 4);
		if (size < 8) return -3;

		if (type == MB2_TAG_END) {
			break;
		}

		if (type == MB2_TAG_MODULE) {
			/* struct multiboot_tag_module: u32 type,size, u32 mod_start, u32 mod_end, char cmdline[] */
			uint32_t mod_start = rd_u32(tag + 8);
			uint32_t mod_end = rd_u32(tag + 12);
			if (mod_end <= mod_start) return -4;
			if (mod_start_out) *mod_start_out = (uint64_t)mod_start;
			if (mod_end_out) *mod_end_out = (uint64_t)mod_end;
			return 0;
		}

		off += align_up_u64((uint64_t)size, 8);
	}

	return -5;
}
