#include "mc.h"
#include "mc_hkdf.h"
#include "mc_hmac.h"

void mc_hkdf_extract(const mc_u8 *salt, mc_usize salt_len, const mc_u8 *ikm, mc_usize ikm_len, mc_u8 prk[MC_SHA256_DIGEST_SIZE]) {
	mc_u8 zeros[MC_SHA256_DIGEST_SIZE];
	if (!salt || salt_len == 0) {
		mc_memset(zeros, 0, sizeof(zeros));
		salt = zeros;
		salt_len = MC_SHA256_DIGEST_SIZE;
	}
	mc_hmac_sha256(salt, salt_len, ikm, ikm_len, prk);
	mc_memset(zeros, 0, sizeof(zeros));
}

void mc_hkdf_expand(const mc_u8 prk[MC_SHA256_DIGEST_SIZE], const mc_u8 *info, mc_usize info_len, mc_u8 *okm, mc_usize okm_len) {
	if (!okm || okm_len == 0) return;
	if (!prk) {
		mc_memset(okm, 0, okm_len);
		return;
	}

	// RFC 5869: N = ceil(L/HashLen), N must be <= 255.
	mc_usize n = (okm_len + (MC_SHA256_DIGEST_SIZE - 1u)) / MC_SHA256_DIGEST_SIZE;
	if (n > 255u) {
		mc_memset(okm, 0, okm_len);
		return;
	}

	mc_u8 t[MC_SHA256_DIGEST_SIZE];
	mc_usize tlen = 0;
	mc_usize out_off = 0;

	for (mc_u32 i = 1; i <= (mc_u32)n; i++) {
		mc_hmac_sha256_ctx h;
		mc_hmac_sha256_init(&h, prk, MC_SHA256_DIGEST_SIZE);
		if (tlen != 0) mc_hmac_sha256_update(&h, t, tlen);
		if (info && info_len != 0) mc_hmac_sha256_update(&h, info, info_len);
		mc_u8 c = (mc_u8)i;
		mc_hmac_sha256_update(&h, &c, 1);
		mc_hmac_sha256_final(&h, t);
		mc_memset(&h, 0, sizeof(h));

		tlen = MC_SHA256_DIGEST_SIZE;
		mc_usize take = okm_len - out_off;
		if (take > MC_SHA256_DIGEST_SIZE) take = MC_SHA256_DIGEST_SIZE;
		mc_memcpy(okm + out_off, t, take);
		out_off += take;
	}

	mc_memset(t, 0, sizeof(t));
}

void mc_hkdf(const mc_u8 *salt, mc_usize salt_len, const mc_u8 *ikm, mc_usize ikm_len, const mc_u8 *info, mc_usize info_len, mc_u8 *okm,
            mc_usize okm_len) {
	mc_u8 prk[MC_SHA256_DIGEST_SIZE];
	mc_hkdf_extract(salt, salt_len, ikm, ikm_len, prk);
	mc_hkdf_expand(prk, info, info_len, okm, okm_len);
	mc_memset(prk, 0, sizeof(prk));
}
