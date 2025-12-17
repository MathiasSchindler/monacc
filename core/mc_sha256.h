#pragma once

#include "mc_types.h"

#define MC_SHA256_BLOCK_SIZE 64u
#define MC_SHA256_DIGEST_SIZE 32u

typedef struct {
	mc_u32 state[8];
	mc_u64 count_bytes;
	mc_u8 buffer[MC_SHA256_BLOCK_SIZE];
	mc_u32 buffer_len;
} mc_sha256_ctx;

void mc_sha256_init(mc_sha256_ctx *ctx);
void mc_sha256_update(mc_sha256_ctx *ctx, const void *data, mc_usize len);
void mc_sha256_final(mc_sha256_ctx *ctx, mc_u8 out[MC_SHA256_DIGEST_SIZE]);

void mc_sha256(const void *data, mc_usize len, mc_u8 out[MC_SHA256_DIGEST_SIZE]);
