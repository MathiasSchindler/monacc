#include "mc.h"

static void write_all_or_die(const char *argv0, const void *buf, mc_usize n) {
	mc_i64 r = mc_write_all(1, buf, n);
	if (r < 0) mc_die_errno(argv0, "write", r);
}

static void put_u8(const char *argv0, mc_u8 v) {
	write_all_or_die(argv0, &v, 1);
}

static void put_le16(const char *argv0, mc_u16 v) {
	mc_u8 b[2];
	b[0] = (mc_u8)(v & 0xffu);
	b[1] = (mc_u8)((v >> 8) & 0xffu);
	write_all_or_die(argv0, b, 2);
}

static void put_le32(const char *argv0, mc_u32 v) {
	mc_u8 b[4];
	b[0] = (mc_u8)(v & 0xffu);
	b[1] = (mc_u8)((v >> 8) & 0xffu);
	b[2] = (mc_u8)((v >> 16) & 0xffu);
	b[3] = (mc_u8)((v >> 24) & 0xffu);
	write_all_or_die(argv0, b, 4);
}

static void put_le32_i(const char *argv0, mc_i32 v) {
	put_le32(argv0, (mc_u32)v);
}

static void emit_bmp_header(const char *argv0, mc_u32 w, mc_u32 h) {
	mc_u32 rowbytes = (w * 3u + 3u) & ~3u;
	mc_u32 imgbytes = rowbytes * h;
	mc_u32 filebytes = 54u + imgbytes;

	// BITMAPFILEHEADER (14 bytes)
	put_u8(argv0, (mc_u8)'B');
	put_u8(argv0, (mc_u8)'M');
	put_le32(argv0, filebytes);
	put_le16(argv0, 0);
	put_le16(argv0, 0);
	put_le32(argv0, 54u);

	// BITMAPINFOHEADER (40 bytes)
	put_le32(argv0, 40u);
	put_le32_i(argv0, (mc_i32)w);
	put_le32_i(argv0, (mc_i32)h);
	put_le16(argv0, 1u);
	put_le16(argv0, 24u);
	put_le32(argv0, 0u);
	put_le32(argv0, imgbytes);
	put_le32(argv0, 0u);
	put_le32(argv0, 0u);
	put_le32(argv0, 0u);
	put_le32(argv0, 0u);
}

__attribute__((used)) int main(int argc, char **argv, char **envp) {
	(void)envp;
	const char *argv0 = (argc > 0 && argv && argv[0]) ? argv[0] : "mandelbrot";

	mc_u32 w = 160;
	mc_u32 h = 120;
	mc_u32 iters = 64;

	int i = 1;
	for (; i < argc; i++) {
		const char *a = argv[i];
		if (!a) break;
		if (mc_streq(a, "--")) {
			i++;
			break;
		}
		if (!mc_streq(a, "-w") && !mc_streq(a, "-h") && !mc_streq(a, "-i")) {
			mc_die_usage(argv0, "mandelbrot [-w W] [-h H] [-i ITERS]");
		}
		if (i + 1 >= argc) {
			mc_die_usage(argv0, "mandelbrot [-w W] [-h H] [-i ITERS]");
		}
		mc_u32 v = 0;
		if (mc_parse_u32_dec(argv[i + 1], &v) != 0) {
			mc_die_usage(argv0, "mandelbrot [-w W] [-h H] [-i ITERS]");
		}
		if (mc_streq(a, "-w")) w = v;
		else if (mc_streq(a, "-h")) h = v;
		else iters = v;
		i++;
	}

	if (w == 0 || h == 0 || iters == 0) {
		mc_die_usage(argv0, "mandelbrot [-w W] [-h H] [-i ITERS]");
	}

	emit_bmp_header(argv0, w, h);

	mc_u32 rowbytes = (w * 3u + 3u) & ~3u;
	mc_u32 pad = rowbytes - w * 3u;

	// View rectangle (roughly centered). Keep everything inline to avoid
	// relying on float calling convention.
	float x0 = -2.0f;
	float x1 = 1.0f;
	float y0 = -1.2f;
	float y1 = 1.2f;

	float inv_wm1 = (w > 1) ? (1.0f / (float)(w - 1u)) : 0.0f;
	float inv_hm1 = (h > 1) ? (1.0f / (float)(h - 1u)) : 0.0f;

	// BMP is bottom-up when height is positive.
	for (mc_u32 yy = 0; yy < h; yy++) {
		mc_u32 y = (h - 1u) - yy;
		float fy = (float)y * inv_hm1;
		float ci = y0 + (y1 - y0) * fy;
		for (mc_u32 x = 0; x < w; x++) {
			float fx = (float)x * inv_wm1;
			float cr = x0 + (x1 - x0) * fx;

			float zr = 0.0f;
			float zi = 0.0f;
			mc_u32 n = 0;
			for (; n < iters; n++) {
				float zr2 = zr * zr;
				float zi2 = zi * zi;
				if (zr2 + zi2 > 4.0f) break;
				float zri = zr * zi;
				zi = zri + zri + ci;
				zr = zr2 - zi2 + cr;
			}

			mc_u32 v = 0;
			if (n < iters) {
				v = 255u - (n * 255u) / iters;
			}
			mc_u8 c = (mc_u8)(v & 0xffu);
			// 24-bit BMP pixels are B,G,R.
			put_u8(argv0, c);
			put_u8(argv0, c);
			put_u8(argv0, c);
		}
		for (mc_u32 p = 0; p < pad; p++) {
			put_u8(argv0, 0);
		}
	}

	return 0;
}
