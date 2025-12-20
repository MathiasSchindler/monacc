// bmpview - display BMP image as ASCII art
// Usage: bmpview [FILE]  or  cat image.bmp | bmpview
// Reads 24-bit uncompressed BMP and renders to console using ASCII brightness ramp.

#include "mc.h"

// BMP file header (14 bytes)
struct bmp_file_header {
	mc_u8 magic[2];        // 'B', 'M'
	mc_u32 file_size;
	mc_u16 reserved1;
	mc_u16 reserved2;
	mc_u32 data_offset;
} __attribute__((packed));

// BMP info header (BITMAPINFOHEADER, 40 bytes)
struct bmp_info_header {
	mc_u32 header_size;    // 40 for BITMAPINFOHEADER
	mc_i32 width;
	mc_i32 height;         // positive = bottom-up, negative = top-down
	mc_u16 planes;         // must be 1
	mc_u16 bits_per_pixel; // 24 for RGB
	mc_u32 compression;    // 0 = uncompressed
	mc_u32 image_size;
	mc_i32 x_ppm;
	mc_i32 y_ppm;
	mc_u32 colors_used;
	mc_u32 colors_important;
} __attribute__((packed));

// ASCII brightness ramp (dark to light)
static const char RAMP[] = "@%#*+=-:. ";
#define RAMP_LEN 10

// Read exactly n bytes from fd, returns 0 on success, -1 on error/EOF
static int read_exact(mc_i32 fd, void *buf, mc_usize n) {
	mc_u8 *p = (mc_u8 *)buf;
	while (n > 0) {
		mc_i64 r = mc_sys_read(fd, p, n);
		if (r <= 0) return -1;
		p += r;
		n -= (mc_usize)r;
	}
	return 0;
}

// Skip n bytes from fd
static int skip_bytes(mc_i32 fd, mc_usize n) {
	mc_u8 tmp[256];
	while (n > 0) {
		mc_usize chunk = n > sizeof(tmp) ? sizeof(tmp) : n;
		if (read_exact(fd, tmp, chunk) < 0) return -1;
		n -= chunk;
	}
	return 0;
}

static void print_usage(void) {
	mc_write_str(1, "Usage: bmpview [FILE]\n");
	mc_write_str(1, "Display BMP image as ASCII art.\n");
	mc_write_str(1, "Reads from stdin if no FILE given.\n");
}

int main(int argc, char **argv) {
	const char *argv0 = argv[0];
	mc_i32 fd = 0; // stdin by default

	// Parse args
	int i = 1;
	while (i < argc && argv[i][0] == '-') {
		if (mc_streq(argv[i], "--")) {
			i++;
			break;
		}
		if (mc_streq(argv[i], "-h") || mc_streq(argv[i], "--help")) {
			print_usage();
			return 0;
		}
		print_usage();
		return 2;
	}

	// Open file if provided
	if (i < argc) {
		const char *path = argv[i];
		if (!mc_streq(path, "-")) {
			fd = (mc_i32)mc_sys_openat(MC_AT_FDCWD, path, MC_O_RDONLY, 0);
			if (fd < 0) {
				mc_die_errno(argv0, path, fd);
			}
		}
	}

	// Read BMP file header
	struct bmp_file_header fhdr;
	if (read_exact(fd, &fhdr, sizeof(fhdr)) < 0) {
		mc_write_str(2, argv0);
		mc_write_str(2, ": failed to read BMP header\n");
		return 1;
	}

	// Check magic
	if (fhdr.magic[0] != 'B' || fhdr.magic[1] != 'M') {
		mc_write_str(2, argv0);
		mc_write_str(2, ": not a BMP file\n");
		return 1;
	}

	// Read BMP info header
	struct bmp_info_header ihdr;
	if (read_exact(fd, &ihdr, sizeof(ihdr)) < 0) {
		mc_write_str(2, argv0);
		mc_write_str(2, ": failed to read BMP info header\n");
		return 1;
	}

	// Validate format
	if (ihdr.bits_per_pixel != 24) {
		mc_write_str(2, argv0);
		mc_write_str(2, ": only 24-bit BMP supported\n");
		return 1;
	}
	if (ihdr.compression != 0) {
		mc_write_str(2, argv0);
		mc_write_str(2, ": only uncompressed BMP supported\n");
		return 1;
	}

	mc_i32 width = ihdr.width;
	mc_i32 height = ihdr.height;
	int bottom_up = 1;
	if (height < 0) {
		height = -height;
		bottom_up = 0;
	}

	if (width <= 0 || height <= 0 || width > 16384 || height > 16384) {
		mc_write_str(2, argv0);
		mc_write_str(2, ": invalid image dimensions\n");
		return 1;
	}

	// Skip to pixel data
	mc_usize headers_read = sizeof(fhdr) + sizeof(ihdr);
	if (fhdr.data_offset > headers_read) {
		if (skip_bytes(fd, fhdr.data_offset - headers_read) < 0) {
			mc_write_str(2, argv0);
			mc_write_str(2, ": failed to seek to pixel data\n");
			return 1;
		}
	}

	// BMP rows are padded to 4-byte boundaries
	mc_usize row_size = (mc_usize)width * 3;
	mc_usize row_padding = (4 - (row_size % 4)) % 4;
	mc_usize padded_row_size = row_size + row_padding;

	// Allocate row buffer (max reasonable width)
	#define MAX_ROW_BYTES (16384 * 3 + 4)
	mc_u8 row_buf[MAX_ROW_BYTES];

	// Output buffer for ASCII line (width + newline)
	#define MAX_WIDTH 16384
	char out_buf[MAX_WIDTH + 2];

	// Read all rows into memory for bottom-up handling
	// For large images we'd need mmap, but for typical use this is fine
	#define MAX_IMAGE_BYTES (16384 * 16384 * 3)
	
	// Simple approach: read row by row and store, then output
	// For streaming, we'd need to buffer all rows if bottom-up
	
	// Allocate pixel buffer on stack for small images, otherwise fail gracefully
	mc_usize total_pixels = (mc_usize)width * (mc_usize)height * 3;
	if (total_pixels > 4 * 1024 * 1024) {
		mc_write_str(2, argv0);
		mc_write_str(2, ": image too large (max ~1300x1300)\n");
		return 1;
	}

	// Use mmap for pixel buffer
	mc_i64 map_ret = mc_sys_mmap(0, total_pixels, 3 /* PROT_READ|PROT_WRITE */, 
		0x22 /* MAP_PRIVATE|MAP_ANONYMOUS */, -1, 0);
	if (map_ret < 0) {
		mc_write_str(2, argv0);
		mc_write_str(2, ": failed to allocate memory\n");
		return 1;
	}
	mc_u8 *pixels = (mc_u8 *)map_ret;

	// Read all pixel data
	for (mc_i32 y = 0; y < height; y++) {
		mc_usize row_offset = (mc_usize)y * (mc_usize)width * 3;
		if (read_exact(fd, pixels + row_offset, row_size) < 0) {
			mc_write_str(2, argv0);
			mc_write_str(2, ": failed to read pixel data\n");
			return 1;
		}
		// Skip padding
		if (row_padding > 0) {
			if (skip_bytes(fd, row_padding) < 0) {
				mc_write_str(2, argv0);
				mc_write_str(2, ": failed to read row padding\n");
				return 1;
			}
		}
	}

	// Output ASCII art
	// BMP stores pixels as BGR
	for (mc_i32 y = 0; y < height; y++) {
		mc_i32 src_y = bottom_up ? (height - 1 - y) : y;
		mc_u8 *row = pixels + (mc_usize)src_y * (mc_usize)width * 3;

		for (mc_i32 x = 0; x < width; x++) {
			mc_u8 b = row[x * 3 + 0];
			mc_u8 g = row[x * 3 + 1];
			mc_u8 r = row[x * 3 + 2];

			// Compute luminance (simple average or weighted)
			// Weighted: Y = 0.299*R + 0.587*G + 0.114*B
			// Approximate: (R + R + G + G + G + B) / 6
			mc_u32 lum = ((mc_u32)r * 2 + (mc_u32)g * 3 + (mc_u32)b) / 6;
			
			// Map to ramp index
			mc_u32 idx = (lum * (RAMP_LEN - 1)) / 255;
			if (idx >= RAMP_LEN) idx = RAMP_LEN - 1;

			out_buf[x] = RAMP[idx];
		}
		out_buf[width] = '\n';
		mc_write_all(1, out_buf, (mc_usize)width + 1);
	}

	mc_sys_munmap(pixels, total_pixels);

	if (fd > 0) {
		mc_sys_close(fd);
	}

	return 0;
}
