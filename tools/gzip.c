#include "mc.h"

// Minimal gzip: emits a valid gzip stream using DEFLATE stored blocks (no compression).
// Supported usage:
//   gzip <in >out.gz
//   gzip [FILE]   (reads FILE, writes to stdout)

#define GZ_BLOCK_MAX 65535u

static mc_u32 gz_crc32_update(mc_u32 crc, const mc_u8 *buf, mc_usize n) {
	crc = ~crc;
	for (mc_usize i = 0; i < n; i++) {
		crc ^= (mc_u32)buf[i];
		for (mc_u32 k = 0; k < 8; k++) {
			mc_u32 m = (mc_u32)-(mc_i32)(crc & 1u);
			crc = (crc >> 1) ^ (0xEDB88320u & m);
		}
	}
	return ~crc;
}

struct gz_bw {
	mc_i32 fd;
	mc_u64 bitbuf;
	mc_u32 bitcnt;
};

static void gz_bw_put_bits(const char *argv0, struct gz_bw *bw, mc_u32 bits, mc_u32 nbits) {
	bw->bitbuf |= ((mc_u64)bits) << bw->bitcnt;
	bw->bitcnt += nbits;
	while (bw->bitcnt >= 8u) {
		mc_u8 b = (mc_u8)(bw->bitbuf & 0xFFu);
		if (mc_write_all(bw->fd, &b, 1) < 0) mc_die_errno(argv0, "write", -1);
		bw->bitbuf >>= 8;
		bw->bitcnt -= 8u;
	}
}

static void gz_bw_align_byte(const char *argv0, struct gz_bw *bw) {
	// Pad with 0 bits up to the next byte boundary.
	while ((bw->bitcnt & 7u) != 0u) {
		gz_bw_put_bits(argv0, bw, 0u, 1u);
	}
}

static void gz_bw_flush(const char *argv0, struct gz_bw *bw) {
	while (bw->bitcnt) {
		mc_u8 b = (mc_u8)(bw->bitbuf & 0xFFu);
		if (mc_write_all(bw->fd, &b, 1) < 0) mc_die_errno(argv0, "write", -1);
		bw->bitbuf >>= 8;
		bw->bitcnt = (bw->bitcnt >= 8u) ? (bw->bitcnt - 8u) : 0u;
	}
}

static void gz_write_u16_le(const char *argv0, mc_i32 fd, mc_u32 v) {
	mc_u8 b[2];
	b[0] = (mc_u8)(v & 0xFFu);
	b[1] = (mc_u8)((v >> 8) & 0xFFu);
	if (mc_write_all(fd, b, 2) < 0) mc_die_errno(argv0, "write", -1);
}

static void gz_write_u32_le(const char *argv0, mc_i32 fd, mc_u32 v) {
	mc_u8 b[4];
	b[0] = (mc_u8)(v & 0xFFu);
	b[1] = (mc_u8)((v >> 8) & 0xFFu);
	b[2] = (mc_u8)((v >> 16) & 0xFFu);
	b[3] = (mc_u8)((v >> 24) & 0xFFu);
	if (mc_write_all(fd, b, 4) < 0) mc_die_errno(argv0, "write", -1);
}

static void gz_write_header(const char *argv0, mc_i32 out_fd) {
	mc_u8 h[10];
	h[0] = 0x1f;
	h[1] = 0x8b;
	h[2] = 8;      // CM=DEFLATE
	h[3] = 0;      // FLG
	h[4] = 0; h[5] = 0; h[6] = 0; h[7] = 0; // MTIME
	h[8] = 0;      // XFL
	h[9] = 255;    // OS=unknown
	if (mc_write_all(out_fd, h, sizeof(h)) < 0) mc_die_errno(argv0, "write", -1);
}

static void gz_write_deflate_store(const char *argv0, mc_i32 in_fd, mc_i32 out_fd) {
	struct gz_bw bw = {0};
	bw.fd = out_fd;
	mc_u8 buf[32768];
	mc_u32 crc = 0;
	mc_u32 isize = 0;
	int first = 1;

	for (;;) {
		mc_i64 r = mc_sys_read(in_fd, buf, sizeof(buf));
		if (r < 0) mc_die_errno(argv0, "read", r);
		if (r == 0) break;
		mc_usize off = 0;
		while (off < (mc_usize)r) {
			mc_usize chunk = (mc_usize)r - off;
			if (chunk > (mc_usize)GZ_BLOCK_MAX) chunk = (mc_usize)GZ_BLOCK_MAX;

			// Stored block header: BFINAL (set later) + BTYPE=00
			// We'll assume not final unless this is the last chunk and EOF follows.
			// Since we don't know yet, we pessimistically write BFINAL=0 here and
			// handle the final empty block later.
			(void)first;
			gz_bw_put_bits(argv0, &bw, 0u, 1u); // BFINAL=0
			gz_bw_put_bits(argv0, &bw, 0u, 2u); // BTYPE=00
			gz_bw_align_byte(argv0, &bw);

			gz_write_u16_le(argv0, out_fd, (mc_u32)chunk);
			gz_write_u16_le(argv0, out_fd, (mc_u32)(~(mc_u32)chunk));
			if (mc_write_all(out_fd, buf + off, chunk) < 0) mc_die_errno(argv0, "write", -1);

			crc = gz_crc32_update(crc, buf + off, chunk);
			isize += (mc_u32)chunk;
			off += chunk;
			first = 0;
		}
	}

	// Final empty stored block with BFINAL=1.
	gz_bw_put_bits(argv0, &bw, 1u, 1u);
	gz_bw_put_bits(argv0, &bw, 0u, 2u);
	gz_bw_align_byte(argv0, &bw);
	gz_write_u16_le(argv0, out_fd, 0u);
	gz_write_u16_le(argv0, out_fd, 0xFFFFu);
	gz_bw_flush(argv0, &bw);

	// Trailer
	gz_write_u32_le(argv0, out_fd, crc);
	gz_write_u32_le(argv0, out_fd, isize);
}

static void gz_usage(const char *argv0) {
	mc_die_usage(argv0, "gzip [FILE]  (writes .gz to stdout)");
}

__attribute__((used)) int main(int argc, char **argv, char **envp) {
	(void)envp;
	const char *argv0 = (argc > 0 && argv && argv[0]) ? argv[0] : "gzip";
	mc_i32 in_fd = 0;
	if (argc > 2) gz_usage(argv0);
	if (argc == 2 && !mc_streq(argv[1], "-")) {
		mc_i64 fd = mc_sys_openat(MC_AT_FDCWD, argv[1], MC_O_RDONLY | MC_O_CLOEXEC, 0);
		if (fd < 0) mc_die_errno(argv0, argv[1], fd);
		in_fd = (mc_i32)fd;
	}

	gz_write_header(argv0, 1);
	gz_write_deflate_store(argv0, in_fd, 1);
	if (argc == 2 && in_fd != 0) (void)mc_sys_close(in_fd);
	return 0;
}
