#pragma once

#include "mc_types.h"
#include "mc_sha256.h"

void mc_hkdf_extract(const mc_u8 *salt, mc_usize salt_len, const mc_u8 *ikm, mc_usize ikm_len, mc_u8 prk[MC_SHA256_DIGEST_SIZE]);

void mc_hkdf_expand(const mc_u8 prk[MC_SHA256_DIGEST_SIZE], const mc_u8 *info, mc_usize info_len, mc_u8 *okm, mc_usize okm_len);

void mc_hkdf(const mc_u8 *salt, mc_usize salt_len, const mc_u8 *ikm, mc_usize ikm_len, const mc_u8 *info, mc_usize info_len, mc_u8 *okm, mc_usize okm_len);
