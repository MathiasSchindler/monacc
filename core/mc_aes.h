#pragma once

#include "mc_types.h"

#define MC_AES128_KEY_SIZE 16u
#define MC_AES128_BLOCK_SIZE 16u
#define MC_AES128_ROUNDS 10u

typedef struct {
	// 11 round keys × 16 bytes = 176 bytes = 44 u32 words
	mc_u32 rk[44];
} mc_aes128_ctx;

void mc_aes128_init(mc_aes128_ctx *ctx, const mc_u8 key[MC_AES128_KEY_SIZE]);

void mc_aes128_encrypt_block(const mc_aes128_ctx *ctx, const mc_u8 in[MC_AES128_BLOCK_SIZE], mc_u8 out[MC_AES128_BLOCK_SIZE]);
void mc_aes128_decrypt_block(const mc_aes128_ctx *ctx, const mc_u8 in[MC_AES128_BLOCK_SIZE], mc_u8 out[MC_AES128_BLOCK_SIZE]);
