#pragma once

#include "mc_types.h"
#include "mc_sha256.h"

typedef struct {
	mc_sha256_ctx inner;
	mc_u8 opad[MC_SHA256_BLOCK_SIZE];
} mc_hmac_sha256_ctx;

void mc_hmac_sha256_init(mc_hmac_sha256_ctx *ctx, const mc_u8 *key, mc_usize key_len);
void mc_hmac_sha256_update(mc_hmac_sha256_ctx *ctx, const void *data, mc_usize len);
void mc_hmac_sha256_final(mc_hmac_sha256_ctx *ctx, mc_u8 out[MC_SHA256_DIGEST_SIZE]);

void mc_hmac_sha256(const mc_u8 *key, mc_usize key_len, const void *data, mc_usize data_len, mc_u8 out[MC_SHA256_DIGEST_SIZE]);
