#include "mc.h"
#include "mc_hmac.h"

void mc_hmac_sha256_init(mc_hmac_sha256_ctx *ctx, const mc_u8 *key, mc_usize key_len) {
	mc_u8 key_hash[MC_SHA256_DIGEST_SIZE];
	const mc_u8 *k = key;
	mc_usize klen = key_len;

	if (klen > MC_SHA256_BLOCK_SIZE) {
		mc_sha256(key, key_len, key_hash);
		k = key_hash;
		klen = MC_SHA256_DIGEST_SIZE;
	}

	mc_u8 ipad[MC_SHA256_BLOCK_SIZE];
	for (mc_u32 i = 0; i < MC_SHA256_BLOCK_SIZE; i++) {
		ipad[i] = 0x36u;
		ctx->opad[i] = 0x5cu;
	}
	for (mc_usize i = 0; i < klen; i++) {
		ipad[i] ^= k[i];
		ctx->opad[i] ^= k[i];
	}

	mc_sha256_init(&ctx->inner);
	mc_sha256_update(&ctx->inner, ipad, MC_SHA256_BLOCK_SIZE);

	mc_memset(key_hash, 0, sizeof(key_hash));
	mc_memset(ipad, 0, sizeof(ipad));
}

void mc_hmac_sha256_update(mc_hmac_sha256_ctx *ctx, const void *data, mc_usize len) {
	mc_sha256_update(&ctx->inner, data, len);
}

void mc_hmac_sha256_final(mc_hmac_sha256_ctx *ctx, mc_u8 out[MC_SHA256_DIGEST_SIZE]) {
	mc_u8 inner_hash[MC_SHA256_DIGEST_SIZE];
	mc_sha256_final(&ctx->inner, inner_hash);

	mc_sha256_ctx outer;
	mc_sha256_init(&outer);
	mc_sha256_update(&outer, ctx->opad, MC_SHA256_BLOCK_SIZE);
	mc_sha256_update(&outer, inner_hash, MC_SHA256_DIGEST_SIZE);
	mc_sha256_final(&outer, out);

	mc_memset(inner_hash, 0, sizeof(inner_hash));
	mc_memset(&outer, 0, sizeof(outer));
}

void mc_hmac_sha256(const mc_u8 *key, mc_usize key_len, const void *data, mc_usize data_len, mc_u8 out[MC_SHA256_DIGEST_SIZE]) {
	mc_hmac_sha256_ctx ctx;
	mc_hmac_sha256_init(&ctx, key, key_len);
	mc_hmac_sha256_update(&ctx, data, data_len);
	mc_hmac_sha256_final(&ctx, out);
	mc_memset(&ctx, 0, sizeof(ctx));
}
