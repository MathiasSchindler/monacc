#include "kernel.h"

/* Minimal CPIO "newc" reader.
 * Format: ASCII hex fields, 110-byte header, name+NUL padded to 4, data padded to 4.
 */

static uint32_t hex_u32_8(const uint8_t *p) {
	uint32_t v = 0;
	for (int i = 0; i < 8; i++) {
		uint8_t c = p[i];
		uint32_t d;
		if (c >= '0' && c <= '9') d = (uint32_t)(c - '0');
		else if (c >= 'a' && c <= 'f') d = (uint32_t)(c - 'a' + 10);
		else if (c >= 'A' && c <= 'F') d = (uint32_t)(c - 'A' + 10);
		else return 0;
		v = (v << 4) | d;
	}
	return v;
}

static uint64_t align_up_u64(uint64_t v, uint64_t a) {
	return (v + (a - 1)) & ~(a - 1);
}

static int streq(const char *a, const char *b) {
	while (*a && *b) {
		if (*a != *b) return 0;
		a++;
		b++;
	}
	return *a == 0 && *b == 0;
}

static const char *skip_dot_slash(const char *s) {
	if (s[0] == '.' && s[1] == '/') return s + 2;
	return s;
}

int cpio_newc_find(const uint8_t *cpio, uint64_t cpio_sz, const char *path,
                  const uint8_t **data_out, uint64_t *size_out) {
	uint64_t off = 0;
	while (off + 110 <= cpio_sz) {
		const uint8_t *h = cpio + off;
		/* c_magic[6] */
		if (!(h[0] == '0' && h[1] == '7' && h[2] == '0' && h[3] == '7' && h[4] == '0' && h[5] == '1')) {
			return -1;
		}
		uint32_t mode = hex_u32_8(h + 14);
		uint32_t filesize = hex_u32_8(h + 54);
		uint32_t namesize = hex_u32_8(h + 94);
		(void)mode;
		if (namesize == 0) return -2;

		off += 110;
		if (off + (uint64_t)namesize > cpio_sz) return -3;
		const char *name = (const char *)(cpio + off);

		/* Names are NUL-terminated, length includes NUL. */
		const char *name_norm = skip_dot_slash(name);
		if (streq(name_norm, "TRAILER!!!")) {
			return -4;
		}

		off = align_up_u64(off + (uint64_t)namesize, 4);
		if (off + (uint64_t)filesize > cpio_sz) return -5;

		if (streq(name_norm, path)) {
			if (data_out) *data_out = cpio + off;
			if (size_out) *size_out = (uint64_t)filesize;
			return 0;
		}

		off = align_up_u64(off + (uint64_t)filesize, 4);
	}
	return -6;
}
