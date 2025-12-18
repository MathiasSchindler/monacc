#include "mc.h"

// Minimal gunzip (gzip decompressor).
// Supported usage:
//   gunzip <in.gz >out
//   gunzip [FILE]   (reads FILE, writes to stdout)
//
// Implements DEFLATE inflate for stored/fixed/dynamic blocks.

#define GZ_BLOCK 512u
#define GZ_WINSZ 32768u
#define GZ_MAXBITS 15u

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

struct gz_br {
	mc_i32 fd;
	mc_u8 buf[32768];
	mc_usize off;
	mc_usize len;
	mc_u64 bitbuf;
	mc_u32 bitcnt;
};

static mc_i64 gz_fill(struct gz_br *br) {
	br->off = 0;
	mc_i64 r = mc_sys_read(br->fd, br->buf, sizeof(br->buf));
	if (r < 0) return r;
	br->len = (mc_usize)r;
	return r;
}

static mc_i64 gz_need(struct gz_br *br) {
	if (br->off < br->len) return 1;
	return gz_fill(br);
}

static mc_i64 gz_read_u8(struct gz_br *br, mc_u8 *out) {
	mc_i64 r = gz_need(br);
	if (r <= 0) return r;
	*out = br->buf[br->off++];
	return 1;
}

static mc_i64 gz_read_n(struct gz_br *br, mc_u8 *dst, mc_usize n) {
	mc_usize got = 0;
	while (got < n) {
		mc_i64 r = gz_need(br);
		if (r <= 0) return (got == 0) ? r : (mc_i64)got;
		mc_usize avail = br->len - br->off;
		mc_usize take = n - got;
		if (take > avail) take = avail;
		mc_memcpy(dst + got, br->buf + br->off, take);
		br->off += take;
		got += take;
	}
	return (mc_i64)got;
}

static mc_i64 gz_br_ensure_bits(struct gz_br *br, mc_u32 n) {
	while (br->bitcnt < n) {
		mc_u8 b;
		mc_i64 r = gz_read_u8(br, &b);
		if (r <= 0) return r;
		br->bitbuf |= ((mc_u64)b) << br->bitcnt;
		br->bitcnt += 8u;
	}
	return 1;
}

static mc_u32 gz_br_peek_bits(struct gz_br *br, mc_u32 n) {
	return (mc_u32)(br->bitbuf & ((n == 32u) ? 0xFFFFFFFFu : ((1u << n) - 1u)));
}

static void gz_br_drop_bits(struct gz_br *br, mc_u32 n) {
	br->bitbuf >>= n;
	br->bitcnt -= n;
}

static mc_i64 gz_br_get_bits(struct gz_br *br, mc_u32 n, mc_u32 *out) {
	mc_i64 r = gz_br_ensure_bits(br, n);
	if (r <= 0) return r;
	*out = gz_br_peek_bits(br, n);
	gz_br_drop_bits(br, n);
	return 1;
}

static void gz_br_align_byte(struct gz_br *br) {
	mc_u32 drop = br->bitcnt & 7u;
	if (drop) gz_br_drop_bits(br, drop);
}

static mc_u32 gz_revbits(mc_u32 v, mc_u32 n) {
	mc_u32 r = 0;
	for (mc_u32 i = 0; i < n; i++) {
		r = (r << 1) | (v & 1u);
		v >>= 1;
	}
	return r;
}

struct gz_huff {
	mc_u16 sym[1u << GZ_MAXBITS];
	mc_u8 bits[1u << GZ_MAXBITS];
};

static void gz_huff_clear(struct gz_huff *h) {
	for (mc_u32 i = 0; i < (1u << GZ_MAXBITS); i++) {
		h->sym[i] = 0;
		h->bits[i] = 0;
	}
}

static int gz_huff_build(struct gz_huff *h, const mc_u8 *lens, mc_u32 nsyms) {
	mc_u16 count[GZ_MAXBITS + 1];
	mc_u16 next[GZ_MAXBITS + 1];
	for (mc_u32 i = 0; i <= GZ_MAXBITS; i++) {
		count[i] = 0;
		next[i] = 0;
	}
	for (mc_u32 i = 0; i < nsyms; i++) {
		mc_u32 L = lens[i];
		if (L > GZ_MAXBITS) return 0;
		if (L) count[L]++;
	}

	mc_u32 code = 0;
	for (mc_u32 bits = 1; bits <= GZ_MAXBITS; bits++) {
		code = (code + count[bits - 1]) << 1;
		next[bits] = (mc_u16)code;
	}

	gz_huff_clear(h);
	for (mc_u32 sym = 0; sym < nsyms; sym++) {
		mc_u32 L = lens[sym];
		if (!L) continue;
		mc_u32 c = (mc_u32)next[L]++;
		mc_u32 rc = gz_revbits(c, L);
		mc_u32 fill = 1u << (GZ_MAXBITS - L);
		for (mc_u32 j = 0; j < fill; j++) {
			mc_u32 idx = rc | (j << L);
			h->sym[idx] = (mc_u16)sym;
			h->bits[idx] = (mc_u8)L;
		}
	}
	return 1;
}

static mc_i64 gz_huff_decode(const char *argv0, struct gz_br *br, const struct gz_huff *h, mc_u32 *out_sym) {
	mc_i64 r = gz_br_ensure_bits(br, GZ_MAXBITS);
	if (r <= 0) return r;
	mc_u32 idx = gz_br_peek_bits(br, GZ_MAXBITS);
	mc_u32 n = h->bits[idx];
	if (n == 0) {
		mc_die_errno(argv0, "bad huffman code", (mc_i64)-MC_EINVAL);
	}
	*out_sym = (mc_u32)h->sym[idx];
	gz_br_drop_bits(br, n);
	return 1;
}

struct gz_out {
	mc_i32 fd;
	mc_u8 win[GZ_WINSZ];
	mc_u32 wpos;
	mc_u8 obuf[32768];
	mc_usize olen;
	mc_u32 crc;
	mc_u32 isize;
};

static void gz_out_flush(const char *argv0, struct gz_out *out) {
	if (out->olen == 0) return;
	mc_i64 r = mc_write_all(out->fd, out->obuf, out->olen);
	if (r < 0) mc_die_errno(argv0, "write", r);
	out->olen = 0;
}

static void gz_out_byte(const char *argv0, struct gz_out *out, mc_u8 b) {
	out->win[out->wpos & (GZ_WINSZ - 1u)] = b;
	out->wpos++;
	out->obuf[out->olen++] = b;
	if (out->olen == sizeof(out->obuf)) gz_out_flush(argv0, out);
	out->crc = gz_crc32_update(out->crc, &b, 1);
	out->isize++;
}

static void gz_out_copy(const char *argv0, struct gz_out *out, mc_u32 dist, mc_u32 len) {
	if (dist == 0 || dist > GZ_WINSZ) mc_die_errno(argv0, "bad distance", (mc_i64)-MC_EINVAL);
	for (mc_u32 i = 0; i < len; i++) {
		mc_u32 src = (out->wpos - dist) & (GZ_WINSZ - 1u);
		mc_u8 b = out->win[src];
		gz_out_byte(argv0, out, b);
	}
}

static void gz_skip_cstring(const char *argv0, struct gz_br *br) {
	for (;;) {
		mc_u8 b;
		mc_i64 r = gz_read_u8(br, &b);
		if (r <= 0) mc_die_errno(argv0, "truncated gzip header", (mc_i64)-MC_EINVAL);
		if (b == 0) break;
	}
}


static mc_i64 gz_br_read_u8_aligned(struct gz_br *br, mc_u8 *out) {
	// If we have already pulled bytes into the bit-buffer during inflate, consume them first.
	if (br->bitcnt >= 8u) {
		*out = (mc_u8)(br->bitbuf & 0xFFu);
		gz_br_drop_bits(br, 8u);
		return 1;
	}
	return gz_read_u8(br, out);
}

static mc_u32 gz_read_u32_le_aligned(const char *argv0, struct gz_br *br) {
	mc_u8 b[4];
	for (mc_u32 i = 0; i < 4; i++) {
		mc_i64 r = gz_br_read_u8_aligned(br, &b[i]);
		if (r != 1) mc_die_errno(argv0, "truncated gzip trailer", (mc_i64)-MC_EINVAL);
	}
	return (mc_u32)b[0] | ((mc_u32)b[1] << 8) | ((mc_u32)b[2] << 16) | ((mc_u32)b[3] << 24);
}

static void gz_parse_header(const char *argv0, struct gz_br *br) {
	mc_u8 h[10];
	mc_i64 r = gz_read_n(br, h, sizeof(h));
	if (r != (mc_i64)sizeof(h)) mc_die_errno(argv0, "bad gzip header", (mc_i64)-MC_EINVAL);
	if (h[0] != 0x1f || h[1] != 0x8b) mc_die_errno(argv0, "not gzip", (mc_i64)-MC_EINVAL);
	if (h[2] != 8) mc_die_errno(argv0, "unsupported gzip method", (mc_i64)-MC_EINVAL);
	mc_u8 flg = h[3];

	// Skip optional fields.
	if (flg & 0x04u) {
		mc_u8 xlen_b[2];
		r = gz_read_n(br, xlen_b, 2);
		if (r != 2) mc_die_errno(argv0, "truncated gzip header", (mc_i64)-MC_EINVAL);
		mc_u32 xlen = (mc_u32)xlen_b[0] | ((mc_u32)xlen_b[1] << 8);
		while (xlen) {
			mc_u8 tmp[256];
			mc_u32 take = (xlen > (mc_u32)sizeof(tmp)) ? (mc_u32)sizeof(tmp) : xlen;
			r = gz_read_n(br, tmp, take);
			if (r != (mc_i64)take) mc_die_errno(argv0, "truncated gzip header", (mc_i64)-MC_EINVAL);
			xlen -= take;
		}
	}
	if (flg & 0x08u) gz_skip_cstring(argv0, br); // FNAME
	if (flg & 0x10u) gz_skip_cstring(argv0, br); // FCOMMENT
	if (flg & 0x02u) {
		mc_u8 tmp[2];
		r = gz_read_n(br, tmp, 2);
		if (r != 2) mc_die_errno(argv0, "truncated gzip header", (mc_i64)-MC_EINVAL);
	}
}

static void gz_fixed_tables(struct gz_huff *litlen, struct gz_huff *dist) {
	mc_u8 ll[288];
	for (mc_u32 i = 0; i <= 143; i++) ll[i] = 8;
	for (mc_u32 i = 144; i <= 255; i++) ll[i] = 9;
	for (mc_u32 i = 256; i <= 279; i++) ll[i] = 7;
	for (mc_u32 i = 280; i <= 287; i++) ll[i] = 8;
	(void)gz_huff_build(litlen, ll, 288);
	mc_u8 dl[32];
	for (mc_u32 i = 0; i < 32; i++) dl[i] = 5;
	(void)gz_huff_build(dist, dl, 32);
}

static void gz_dynamic_tables(const char *argv0, struct gz_br *br, struct gz_huff *litlen, struct gz_huff *dist) {
	mc_u32 HLIT, HDIST, HCLEN;
	if (gz_br_get_bits(br, 5, &HLIT) <= 0) mc_die_errno(argv0, "truncated deflate", (mc_i64)-MC_EINVAL);
	if (gz_br_get_bits(br, 5, &HDIST) <= 0) mc_die_errno(argv0, "truncated deflate", (mc_i64)-MC_EINVAL);
	if (gz_br_get_bits(br, 4, &HCLEN) <= 0) mc_die_errno(argv0, "truncated deflate", (mc_i64)-MC_EINVAL);
	HLIT += 257;
	HDIST += 1;
	HCLEN += 4;

	static const mc_u8 order[19] = { 16,17,18, 0,8,7,9,6,10,5,11,4,12,3,13,2,14,1,15 };
	mc_u8 clen[19];
	for (mc_u32 i = 0; i < 19; i++) clen[i] = 0;
	for (mc_u32 i = 0; i < HCLEN; i++) {
		mc_u32 v;
		if (gz_br_get_bits(br, 3, &v) <= 0) mc_die_errno(argv0, "truncated deflate", (mc_i64)-MC_EINVAL);
		clen[order[i]] = (mc_u8)v;
	}
	struct gz_huff ch;
	if (!gz_huff_build(&ch, clen, 19)) mc_die_errno(argv0, "bad huffman table", (mc_i64)-MC_EINVAL);

	mc_u32 total = HLIT + HDIST;
	mc_u8 lens[320];
	for (mc_u32 i = 0; i < total; i++) lens[i] = 0;

	mc_u32 i = 0;
	mc_u32 prev = 0;
	while (i < total) {
		mc_u32 sym;
		(void)gz_huff_decode(argv0, br, &ch, &sym);
		if (sym <= 15) {
			lens[i++] = (mc_u8)sym;
			prev = sym;
			continue;
		}
		if (sym == 16) {
			mc_u32 extra;
			if (gz_br_get_bits(br, 2, &extra) <= 0) mc_die_errno(argv0, "truncated deflate", (mc_i64)-MC_EINVAL);
			mc_u32 rep = 3 + extra;
			for (mc_u32 k = 0; k < rep && i < total; k++) lens[i++] = (mc_u8)prev;
			continue;
		}
		if (sym == 17) {
			mc_u32 extra;
			if (gz_br_get_bits(br, 3, &extra) <= 0) mc_die_errno(argv0, "truncated deflate", (mc_i64)-MC_EINVAL);
			mc_u32 rep = 3 + extra;
			for (mc_u32 k = 0; k < rep && i < total; k++) lens[i++] = 0;
			prev = 0;
			continue;
		}
		if (sym == 18) {
			mc_u32 extra;
			if (gz_br_get_bits(br, 7, &extra) <= 0) mc_die_errno(argv0, "truncated deflate", (mc_i64)-MC_EINVAL);
			mc_u32 rep = 11 + extra;
			for (mc_u32 k = 0; k < rep && i < total; k++) lens[i++] = 0;
			prev = 0;
			continue;
		}
		mc_die_errno(argv0, "bad huffman code", (mc_i64)-MC_EINVAL);
	}

	if (!gz_huff_build(litlen, lens, HLIT)) mc_die_errno(argv0, "bad litlen table", (mc_i64)-MC_EINVAL);
	if (!gz_huff_build(dist, lens + HLIT, HDIST)) mc_die_errno(argv0, "bad dist table", (mc_i64)-MC_EINVAL);
}

static void gz_inflate(const char *argv0, struct gz_br *br, struct gz_out *out) {
	static const mc_u16 len_base[29] = {
		3,4,5,6,7,8,9,10, 11,13,15,17, 19,23,27,31,
		35,43,51,59, 67,83,99,115, 131,163,195,227,258
	};
	static const mc_u8 len_extra[29] = {
		0,0,0,0,0,0,0,0, 1,1,1,1, 2,2,2,2,
		3,3,3,3, 4,4,4,4, 5,5,5,5,0
	};
	static const mc_u16 dist_base[30] = {
		1,2,3,4,5,7,9,13, 17,25,33,49, 65,97,129,193,
		257,385,513,769, 1025,1537,2049,3073, 4097,6145,8193,12289,16385,24577
	};
	static const mc_u8 dist_extra[30] = {
		0,0,0,0,1,1,2,2, 3,3,4,4, 5,5,6,6,
		7,7,8,8, 9,9,10,10, 11,11,12,12,13,13
	};

	for (;;) {
		mc_u32 bfinal, btype;
		if (gz_br_get_bits(br, 1, &bfinal) <= 0) mc_die_errno(argv0, "truncated deflate", (mc_i64)-MC_EINVAL);
		if (gz_br_get_bits(br, 2, &btype) <= 0) mc_die_errno(argv0, "truncated deflate", (mc_i64)-MC_EINVAL);

		if (btype == 0) {
			gz_br_align_byte(br);
			mc_u8 lenb[4];
			mc_i64 r = gz_read_n(br, lenb, 4);
			if (r != 4) mc_die_errno(argv0, "truncated deflate", (mc_i64)-MC_EINVAL);
			mc_u32 len = (mc_u32)lenb[0] | ((mc_u32)lenb[1] << 8);
			mc_u32 nlen = (mc_u32)lenb[2] | ((mc_u32)lenb[3] << 8);
			if ((len ^ 0xFFFFu) != nlen) mc_die_errno(argv0, "bad stored block", (mc_i64)-MC_EINVAL);
			while (len) {
				mc_u8 tmp[32768];
				mc_u32 take = (len > (mc_u32)sizeof(tmp)) ? (mc_u32)sizeof(tmp) : len;
				r = gz_read_n(br, tmp, take);
				if (r != (mc_i64)take) mc_die_errno(argv0, "truncated deflate", (mc_i64)-MC_EINVAL);
				for (mc_u32 i = 0; i < take; i++) gz_out_byte(argv0, out, tmp[i]);
				len -= take;
			}
		} else {
			struct gz_huff litlen, dist;
			if (btype == 1) {
				gz_fixed_tables(&litlen, &dist);
			} else if (btype == 2) {
				gz_dynamic_tables(argv0, br, &litlen, &dist);
			} else {
				mc_die_errno(argv0, "unsupported block type", (mc_i64)-MC_EINVAL);
			}

			for (;;) {
				mc_u32 sym;
				(void)gz_huff_decode(argv0, br, &litlen, &sym);
				if (sym < 256) {
					gz_out_byte(argv0, out, (mc_u8)sym);
					continue;
				}
				if (sym == 256) break;
				if (sym < 257 || sym > 285) mc_die_errno(argv0, "bad length", (mc_i64)-MC_EINVAL);
				mc_u32 li = sym - 257;
				mc_u32 extra = len_extra[li];
				mc_u32 v = 0;
				if (extra) {
					if (gz_br_get_bits(br, extra, &v) <= 0) mc_die_errno(argv0, "truncated deflate", (mc_i64)-MC_EINVAL);
				}
				mc_u32 length = (mc_u32)len_base[li] + v;

				mc_u32 dsym;
				(void)gz_huff_decode(argv0, br, &dist, &dsym);
				if (dsym > 29) mc_die_errno(argv0, "bad distance", (mc_i64)-MC_EINVAL);
				extra = dist_extra[dsym];
				v = 0;
				if (extra) {
					if (gz_br_get_bits(br, extra, &v) <= 0) mc_die_errno(argv0, "truncated deflate", (mc_i64)-MC_EINVAL);
				}
				mc_u32 distance = (mc_u32)dist_base[dsym] + v;
				gz_out_copy(argv0, out, distance, length);
			}
		}

		if (bfinal) break;
	}
}

static void gz_usage(const char *argv0) {
	mc_die_usage(argv0, "gunzip [FILE]  (writes uncompressed to stdout)");
}

__attribute__((used)) int main(int argc, char **argv, char **envp) {
	(void)envp;
	const char *argv0 = (argc > 0 && argv && argv[0]) ? argv[0] : "gunzip";
	if (argc > 2) gz_usage(argv0);

	mc_i32 in_fd = 0;
	if (argc == 2 && !mc_streq(argv[1], "-")) {
		mc_i64 fd = mc_sys_openat(MC_AT_FDCWD, argv[1], MC_O_RDONLY | MC_O_CLOEXEC, 0);
		if (fd < 0) mc_die_errno(argv0, argv[1], fd);
		in_fd = (mc_i32)fd;
	}

	struct gz_br br;
	br.fd = in_fd;
	br.off = 0;
	br.len = 0;
	br.bitbuf = 0;
	br.bitcnt = 0;

	struct gz_out out;
	out.fd = 1;
	out.wpos = 0;
	out.olen = 0;
	out.crc = 0;
	out.isize = 0;
	for (mc_u32 i = 0; i < GZ_WINSZ; i++) out.win[i] = 0;

	gz_parse_header(argv0, &br);
	gz_inflate(argv0, &br, &out);
	gz_out_flush(argv0, &out);
	gz_br_align_byte(&br);

	mc_u32 want_crc = gz_read_u32_le_aligned(argv0, &br);
	mc_u32 want_size = gz_read_u32_le_aligned(argv0, &br);
	if (want_crc != out.crc || want_size != out.isize) {
		mc_die_errno(argv0, "gzip CRC/size mismatch", (mc_i64)-MC_EINVAL);
	}

	if (argc == 2 && in_fd != 0) (void)mc_sys_close(in_fd);
	return 0;
}
