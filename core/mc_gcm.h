#pragma once

#include "mc_types.h"

#define MC_GCM_TAG_SIZE 16
#define MC_GCM_IV_SIZE 12

// AES-128-GCM (AEAD) one-shot helpers.
//
// Returns 0 on success.
int mc_aes128_gcm_encrypt(
	const mc_u8 key[16],
	const mc_u8 iv[MC_GCM_IV_SIZE],
	const mc_u8 *aad, mc_usize aad_len,
	const mc_u8 *plaintext, mc_usize pt_len,
	mc_u8 *ciphertext,
	mc_u8 tag[MC_GCM_TAG_SIZE]
);

// Returns 0 on success, -1 on authentication failure.
int mc_aes128_gcm_decrypt(
	const mc_u8 key[16],
	const mc_u8 iv[MC_GCM_IV_SIZE],
	const mc_u8 *aad, mc_usize aad_len,
	const mc_u8 *ciphertext, mc_usize ct_len,
	const mc_u8 tag[MC_GCM_TAG_SIZE],
	mc_u8 *plaintext
);
