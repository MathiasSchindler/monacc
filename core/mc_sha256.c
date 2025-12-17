#include "mc.h"
#include "mc_sha256.h"

static mc_u32 rotr32(mc_u32 x, mc_u32 n) {
	return (mc_u32)((x >> n) | (x << (32u - n)));
}

static mc_u32 load_be32(const mc_u8 *p) {
	return ((mc_u32)p[0] << 24) | ((mc_u32)p[1] << 16) | ((mc_u32)p[2] << 8) | ((mc_u32)p[3] << 0);
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

static const mc_u32 k[64] = {
	0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
	0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
	0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
	0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
	0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
	0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
	0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
	0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u, 0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u,
};

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

	for (mc_u32 i = 0; i < 64; i++) {
		mc_u32 t1 = h + bsig1(e) + ch(e, f, g) + k[i] + w[i];
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
