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

static int starts_with(const char *s, const char *pfx) {
	if (!s || !pfx) return 0;
	for (;;) {
		char pc = *pfx;
		if (pc == 0) return 1;
		if (*s != pc) return 0;
		s++;
		pfx++;
	}
}

static uint64_t cstrnlen_local(const char *s, uint64_t cap) {
	uint64_t n = 0;
	while (n < cap && s && s[n]) n++;
	return n;
}

static void comp_first(const char *rest, char *out, uint64_t cap, uint8_t *is_dir_out) {
	if (!out || cap == 0) return;
	out[0] = 0;
	if (is_dir_out) *is_dir_out = 0;
	if (!rest) return;
	uint64_t i = 0;
	for (; rest[i] && rest[i] != '/' && i + 1 < cap; i++) {
		out[i] = rest[i];
	}
	out[i] = 0;
	if (is_dir_out) *is_dir_out = (rest[i] == '/');
}

static int seen_before_child(const uint8_t *cpio, uint64_t cpio_sz, const char *dirpath,
			     const char *child, uint64_t stop_off) {
	uint64_t off = 0;
	uint64_t dirlen = cstrnlen_local(dirpath, 4096);
	char want[256];
	want[0] = 0;
	if (child) {
		uint64_t i = 0;
		for (; i + 1 < sizeof(want) && child[i]; i++) {
			want[i] = child[i];
		}
		want[i] = 0;
	}
	while (off + 110 <= cpio_sz && off < stop_off) {
		const uint8_t *h = cpio + off;
		if (!(h[0] == '0' && h[1] == '7' && h[2] == '0' && h[3] == '7' && h[4] == '0' && h[5] == '1')) {
			return 0;
		}
		uint32_t filesize = hex_u32_8(h + 54);
		uint32_t namesize = hex_u32_8(h + 94);
		if (namesize == 0) return 0;

		off += 110;
		if (off + (uint64_t)namesize > cpio_sz) return 0;
		const char *name = (const char *)(cpio + off);
		const char *name_norm = skip_dot_slash(name);
		if (streq(name_norm, "TRAILER!!!")) return 0;
		off = align_up_u64(off + (uint64_t)namesize, 4);
		if (off + (uint64_t)filesize > cpio_sz) return 0;

		const char *rest = 0;
		if (dirlen == 0) {
			rest = name_norm;
		} else {
			if (starts_with(name_norm, dirpath) && name_norm[dirlen] == '/') {
				rest = name_norm + dirlen + 1;
			}
		}
		if (rest && rest[0]) {
			char tmp[256];
			uint8_t is_dir = 0;
			comp_first(rest, tmp, sizeof(tmp), &is_dir);
			(void)is_dir;
			if (tmp[0] && streq(tmp, want)) return 1;
		}

		off = align_up_u64(off + (uint64_t)filesize, 4);
	}
	return 0;
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

int cpio_newc_stat(const uint8_t *cpio, uint64_t cpio_sz, const char *path,
			  uint32_t *mode_out, uint64_t *size_out) {
	uint64_t off = 0;
	while (off + 110 <= cpio_sz) {
		const uint8_t *h = cpio + off;
		if (!(h[0] == '0' && h[1] == '7' && h[2] == '0' && h[3] == '7' && h[4] == '0' && h[5] == '1')) {
			return -1;
		}
		uint32_t mode = hex_u32_8(h + 14);
		uint32_t filesize = hex_u32_8(h + 54);
		uint32_t namesize = hex_u32_8(h + 94);
		if (namesize == 0) return -2;

		off += 110;
		if (off + (uint64_t)namesize > cpio_sz) return -3;
		const char *name = (const char *)(cpio + off);
		const char *name_norm = skip_dot_slash(name);
		if (streq(name_norm, "TRAILER!!!")) {
			return -4;
		}
		off = align_up_u64(off + (uint64_t)namesize, 4);
		if (off + (uint64_t)filesize > cpio_sz) return -5;

		if (streq(name_norm, path)) {
			if (mode_out) *mode_out = mode;
			if (size_out) *size_out = (uint64_t)filesize;
			return 0;
		}

		off = align_up_u64(off + (uint64_t)filesize, 4);
	}
	return -6;
}

int cpio_newc_has_prefix(const uint8_t *cpio, uint64_t cpio_sz, const char *dirpath) {
	uint64_t off = 0;
	uint64_t dirlen = cstrnlen_local(dirpath, 4096);
	while (off + 110 <= cpio_sz) {
		const uint8_t *h = cpio + off;
		if (!(h[0] == '0' && h[1] == '7' && h[2] == '0' && h[3] == '7' && h[4] == '0' && h[5] == '1')) {
			return 0;
		}
		uint32_t filesize = hex_u32_8(h + 54);
		uint32_t namesize = hex_u32_8(h + 94);
		if (namesize == 0) return 0;
		off += 110;
		if (off + (uint64_t)namesize > cpio_sz) return 0;
		const char *name = (const char *)(cpio + off);
		const char *name_norm = skip_dot_slash(name);
		if (streq(name_norm, "TRAILER!!!")) return 0;
		off = align_up_u64(off + (uint64_t)namesize, 4);
		if (off + (uint64_t)filesize > cpio_sz) return 0;

		if (dirlen == 0) {
			return 1;
		}
		if (starts_with(name_norm, dirpath) && name_norm[dirlen] == '/') {
			return 1;
		}
		off = align_up_u64(off + (uint64_t)filesize, 4);
	}
	return 0;
}

int cpio_newc_dir_next(const uint8_t *cpio, uint64_t cpio_sz, const char *dirpath,
			       uint64_t *scan_off_inout, char *name_out, uint64_t name_cap,
			       uint8_t *dtype_out) {
	if (!scan_off_inout || !name_out || name_cap == 0) return -1;
	uint64_t off = *scan_off_inout;
	uint64_t dirlen = cstrnlen_local(dirpath, 4096);
	while (off + 110 <= cpio_sz) {
		uint64_t entry_off = off;
		const uint8_t *h = cpio + off;
		if (!(h[0] == '0' && h[1] == '7' && h[2] == '0' && h[3] == '7' && h[4] == '0' && h[5] == '1')) {
			return -2;
		}
		uint32_t mode = hex_u32_8(h + 14);
		uint32_t filesize = hex_u32_8(h + 54);
		uint32_t namesize = hex_u32_8(h + 94);
		if (namesize == 0) return -3;
		off += 110;
		if (off + (uint64_t)namesize > cpio_sz) return -4;
		const char *name = (const char *)(cpio + off);
		const char *name_norm = skip_dot_slash(name);
		if (streq(name_norm, "TRAILER!!!")) {
			*scan_off_inout = off;
			return 0;
		}
		off = align_up_u64(off + (uint64_t)namesize, 4);
		if (off + (uint64_t)filesize > cpio_sz) return -5;

		const char *rest = 0;
		if (dirlen == 0) {
			rest = name_norm;
		} else {
			if (starts_with(name_norm, dirpath) && name_norm[dirlen] == '/') {
				rest = name_norm + dirlen + 1;
			}
		}

		if (rest && rest[0]) {
			uint8_t is_dir = 0;
			comp_first(rest, name_out, name_cap, &is_dir);
			if (name_out[0]) {
				if (!seen_before_child(cpio, cpio_sz, dirpath, name_out, entry_off)) {
					uint8_t dt = DT_UNKNOWN;
					if (is_dir) dt = DT_DIR;
					else {
						uint32_t t = mode & 0170000u;
						if (t == 0040000u) dt = DT_DIR;
						else if (t == 0120000u) dt = DT_LNK;
						else if (t == 0100000u) dt = DT_REG;
					}
					if (dtype_out) *dtype_out = dt;
					off = align_up_u64(off + (uint64_t)filesize, 4);
					*scan_off_inout = off;
					return 1;
				}
			}
		}

		off = align_up_u64(off + (uint64_t)filesize, 4);
	}
	*scan_off_inout = off;
	return 0;
}
