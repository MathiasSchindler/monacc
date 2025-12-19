#include "mc.h"
#include "mc_sha256.h"

static mc_u32 rotr32(mc_u32 x, mc_u32 n) {
	return (mc_u32)((x >> n) | (x << (32u - n)));
}

static mc_u32 load_be32(const mc_u8 *p) {
	return ((mc_u32)p[0] << 24) | ((mc_u32)p[1] << 16) | ((mc_u32)p[2] << 8) | ((mc_u32)p[3] << 0);
}

static mc_u32 load_le32(const mc_u8 *p) {
	return ((mc_u32)p[0] << 0) | ((mc_u32)p[1] << 8) | ((mc_u32)p[2] << 16) | ((mc_u32)p[3] << 24);
}

static void store_be32(mc_u8 *p, mc_u32 v) {
	p[0] = (mc_u8)((v >> 24) & 0xFFu);
	p[1] = (mc_u8)((v >> 16) & 0xFFu);
	p[2] = (mc_u8)((v >> 8) & 0xFFu);
	p[3] = (mc_u8)((v >> 0) & 0xFFu);
}

static void store_be64(mc_u8 *p, mc_u64 v) {
	p[0] = (mc_u8)((v >> 56) & 0xFFu);
	p[1] = (mc_u8)((v >> 48) & 0xFFu);
	p[2] = (mc_u8)((v >> 40) & 0xFFu);
	p[3] = (mc_u8)((v >> 32) & 0xFFu);
	p[4] = (mc_u8)((v >> 24) & 0xFFu);
	p[5] = (mc_u8)((v >> 16) & 0xFFu);
	p[6] = (mc_u8)((v >> 8) & 0xFFu);
	p[7] = (mc_u8)((v >> 0) & 0xFFu);
}

static mc_u32 ch(mc_u32 x, mc_u32 y, mc_u32 z) {
	return (x & y) ^ (~x & z);
}

static mc_u32 maj(mc_u32 x, mc_u32 y, mc_u32 z) {
	return (x & y) ^ (x & z) ^ (y & z);
}

static mc_u32 bsig0(mc_u32 x) {
	return rotr32(x, 2) ^ rotr32(x, 13) ^ rotr32(x, 22);
}

static mc_u32 bsig1(mc_u32 x) {
	return rotr32(x, 6) ^ rotr32(x, 11) ^ rotr32(x, 25);
}

static mc_u32 ssig0(mc_u32 x) {
	return rotr32(x, 7) ^ rotr32(x, 18) ^ (x >> 3);
}

static mc_u32 ssig1(mc_u32 x) {
	return rotr32(x, 17) ^ rotr32(x, 19) ^ (x >> 10);
}

static const mc_u8 *sha256_k_bytes(void) {
	// Little-endian u32 constants (RFC 6234 / FIPS 180-4).
	return (const mc_u8 *)
		"\x98\x2f\x8a\x42\x91\x44\x37\x71\xcf\xfb\xc0\xb5\xa5\xdb\xb5\xe9"
		"\x5b\xc2\x56\x39\xf1\x11\xf1\x59\xa4\x82\x3f\x92\xd5\x5e\x1c\xab"
		"\x98\xaa\x07\xd8\x01\x5b\x83\x12\xbe\x85\x31\x24\xc3\x7d\x0c\x55"
		"\x74\x5d\xbe\x72\xfe\xb1\xde\x80\xa7\x06\xdc\x9b\x74\xf1\x9b\xc1"
		"\xc1\x69\x9b\xe4\x86\x47\xbe\xef\xc6\x9d\xc1\x0f\xcc\xa1\x0c\x24"
		"\x6f\x2c\xe9\x2d\xaa\x84\x74\x4a\xdc\xa9\xb0\x5c\xda\x88\xf9\x76"
		"\x52\x51\x3e\x98\x6d\xc6\x31\xa8\xc8\x27\x03\xb0\xc7\x7f\x59\xbf"
		"\xf3\x0b\xe0\xc6\x47\x91\xa7\xd5\x51\x63\xca\x06\x67\x29\x29\x14"
		"\x85\x0a\xb7\x27\x38\x21\x1b\x2e\xfc\x6d\x2c\x4d\x13\x0d\x38\x53"
		"\x54\x73\x0a\x65\xbb\x0a\x6a\x76\x2e\xc9\xc2\x81\x85\x2c\x72\x92"
		"\xa1\xe8\xbf\xa2\x4b\x66\x1a\xa8\x70\x8b\x4b\xc2\xa3\x51\x6c\xc7"
		"\x19\xe8\x92\xd1\x24\x06\x99\xd6\x85\x35\x0e\xf4\x70\xa0\x6a\x10"
		"\x16\xc1\xa4\x19\x08\x6c\x37\x1e\x4c\x77\x48\x27\xb5\xbc\xb0\x34"
		"\xb3\x0c\x1c\x39\x4a\xaa\xd8\x4e\x4f\xca\x9c\x5b\xf3\x6f\x2e\x68"
		"\xee\x82\x8f\x74\x6f\x63\xa5\x78\x14\x78\xc8\x84\x08\x02\xc7\x8c"
		"\xfa\xff\xbe\x90\xeb\x6c\x50\xa4\xf7\xa3\xf9\xbe\xf2\x78\x71\xc6";
}

static void sha256_transform(mc_sha256_ctx *ctx, const mc_u8 block[64]) {
	mc_u32 w[64];
	for (mc_u32 i = 0; i < 16; i++) {
		w[i] = load_be32(block + (mc_usize)(i * 4u));
	}
	for (mc_u32 i = 16; i < 64; i++) {
		w[i] = ssig1(w[i - 2]) + w[i - 7] + ssig0(w[i - 15]) + w[i - 16];
	}

	mc_u32 a = ctx->state[0];
	mc_u32 b = ctx->state[1];
	mc_u32 c = ctx->state[2];
	mc_u32 d = ctx->state[3];
	mc_u32 e = ctx->state[4];
	mc_u32 f = ctx->state[5];
	mc_u32 g = ctx->state[6];
	mc_u32 h = ctx->state[7];
	const mc_u8 *kb = sha256_k_bytes();

	for (mc_u32 i = 0; i < 64; i++) {
		mc_u32 t1 = h + bsig1(e) + ch(e, f, g) + load_le32(kb + (mc_usize)(i * 4u)) + w[i];
		mc_u32 t2 = bsig0(a) + maj(a, b, c);
		h = g;
		g = f;
		f = e;
		e = d + t1;
		d = c;
		c = b;
		b = a;
		a = t1 + t2;
	}

	ctx->state[0] += a;
	ctx->state[1] += b;
	ctx->state[2] += c;
	ctx->state[3] += d;
	ctx->state[4] += e;
	ctx->state[5] += f;
	ctx->state[6] += g;
	ctx->state[7] += h;
}

void mc_sha256_init(mc_sha256_ctx *ctx) {
	ctx->state[0] = 0x6a09e667u;
	ctx->state[1] = 0xbb67ae85u;
	ctx->state[2] = 0x3c6ef372u;
	ctx->state[3] = 0xa54ff53au;
	ctx->state[4] = 0x510e527fu;
	ctx->state[5] = 0x9b05688cu;
	ctx->state[6] = 0x1f83d9abu;
	ctx->state[7] = 0x5be0cd19u;
	ctx->count_bytes = 0;
	ctx->buffer_len = 0;
}

void mc_sha256_update(mc_sha256_ctx *ctx, const void *data, mc_usize len) {
	const mc_u8 *p = (const mc_u8 *)data;
	ctx->count_bytes += (mc_u64)len;

	if (ctx->buffer_len != 0) {
		mc_u32 need = (mc_u32)(MC_SHA256_BLOCK_SIZE - ctx->buffer_len);
		mc_u32 take = (mc_u32)len;
		if (take > need) take = need;
		mc_memcpy(ctx->buffer + ctx->buffer_len, p, (mc_usize)take);
		ctx->buffer_len += take;
		p += take;
		len -= (mc_usize)take;
		if (ctx->buffer_len == MC_SHA256_BLOCK_SIZE) {
			sha256_transform(ctx, ctx->buffer);
			ctx->buffer_len = 0;
		}
	}

	while (len >= MC_SHA256_BLOCK_SIZE) {
		sha256_transform(ctx, p);
		p += MC_SHA256_BLOCK_SIZE;
		len -= MC_SHA256_BLOCK_SIZE;
	}

	if (len != 0) {
		mc_memcpy(ctx->buffer, p, len);
		ctx->buffer_len = (mc_u32)len;
	}
}

void mc_sha256_final(mc_sha256_ctx *ctx, mc_u8 out[MC_SHA256_DIGEST_SIZE]) {
	mc_u8 pad[MC_SHA256_BLOCK_SIZE + 8];
	mc_u64 bit_len = ctx->count_bytes * 8u;

	pad[0] = 0x80u;
	mc_u32 pad_zeros;
	if (ctx->buffer_len < 56u) {
		pad_zeros = (mc_u32)(56u - ctx->buffer_len - 1u);
	} else {
		pad_zeros = (mc_u32)(64u + 56u - ctx->buffer_len - 1u);
	}
	mc_memset(pad + 1, 0, (mc_usize)pad_zeros);
	store_be64(pad + 1 + pad_zeros, bit_len);

	mc_sha256_update(ctx, pad, (mc_usize)(1u + pad_zeros + 8u));

	for (mc_u32 i = 0; i < 8; i++) {
		store_be32(out + (mc_usize)(i * 4u), ctx->state[i]);
	}

	mc_memset(ctx, 0, sizeof(*ctx));
}

void mc_sha256(const void *data, mc_usize len, mc_u8 out[MC_SHA256_DIGEST_SIZE]) {
	mc_sha256_ctx ctx;
	mc_sha256_init(&ctx);
	mc_sha256_update(&ctx, data, len);
	mc_sha256_final(&ctx, out);
}
