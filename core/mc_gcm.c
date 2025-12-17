#include "mc.h"
#include "mc_aes.h"
#include "mc_gcm.h"

static void xor16(mc_u8 out[16], const mc_u8 a[16], const mc_u8 b[16]) {
	for (int i = 0; i < 16; i++) out[i] = (mc_u8)(a[i] ^ b[i]);
}

static void store_be64(mc_u8 *p, mc_u64 v) {
	p[0] = (mc_u8)(v >> 56);
	p[1] = (mc_u8)(v >> 48);
	p[2] = (mc_u8)(v >> 40);
	p[3] = (mc_u8)(v >> 32);
	p[4] = (mc_u8)(v >> 24);
	p[5] = (mc_u8)(v >> 16);
	p[6] = (mc_u8)(v >> 8);
	p[7] = (mc_u8)(v >> 0);
}

// Increment the low 32 bits, treated as a big-endian integer.
static void inc32(mc_u8 counter[16]) {
	mc_u32 x = ((mc_u32)counter[12] << 24) | ((mc_u32)counter[13] << 16) | ((mc_u32)counter[14] << 8) | (mc_u32)counter[15];
	x++;
	counter[12] = (mc_u8)(x >> 24);
	counter[13] = (mc_u8)(x >> 16);
	counter[14] = (mc_u8)(x >> 8);
	counter[15] = (mc_u8)(x >> 0);
}

static void shift_right_one(mc_u8 v[16]) {
	mc_u8 carry = 0;
	for (int i = 0; i < 16; i++) {
		mc_u8 b = v[i];
		mc_u8 new_carry = (mc_u8)(b & 1u);
		v[i] = (mc_u8)((b >> 1) | (carry ? 0x80u : 0x00u));
		carry = new_carry;
	}
}

// Multiply X by H in GF(2^128) with the GCM reduction polynomial.
// Inputs/outputs are 16-byte big-endian values.
static void ghash_mul(mc_u8 x[16], const mc_u8 h[16]) {
	mc_u8 z[16];
	mc_u8 v[16];
	mc_memset(z, 0, sizeof(z));
	mc_memcpy(v, h, sizeof(v));

	for (int byte = 0; byte < 16; byte++) {
		mc_u8 xb = x[byte];
		for (int bit = 0; bit < 8; bit++) {
			if (xb & 0x80u) {
				for (int i = 0; i < 16; i++) z[i] = (mc_u8)(z[i] ^ v[i]);
			}
			mc_u8 lsb = (mc_u8)(v[15] & 1u);
			shift_right_one(v);
			if (lsb) {
				// R = 0xe1 || 0^120
				v[0] = (mc_u8)(v[0] ^ 0xe1u);
			}
			xb = (mc_u8)(xb << 1);
		}
	}

	mc_memcpy(x, z, 16);
}

static void ghash_update(mc_u8 y[16], const mc_u8 h[16], const mc_u8 *data, mc_usize len) {
	mc_u8 block[16];
	while (len >= 16) {
		for (int i = 0; i < 16; i++) y[i] = (mc_u8)(y[i] ^ data[i]);
		ghash_mul(y, h);
		data += 16;
		len -= 16;
	}
	if (len) {
		mc_memset(block, 0, sizeof(block));
		mc_memcpy(block, data, len);
		for (int i = 0; i < 16; i++) y[i] = (mc_u8)(y[i] ^ block[i]);
		ghash_mul(y, h);
	}
}

static void ghash_final_lengths(mc_u8 y[16], const mc_u8 h[16], mc_usize aad_len, mc_usize ct_len) {
	mc_u8 lens[16];
	mc_u64 a_bits = (mc_u64)aad_len * 8u;
	mc_u64 c_bits = (mc_u64)ct_len * 8u;
	store_be64(lens + 0, a_bits);
	store_be64(lens + 8, c_bits);
	for (int i = 0; i < 16; i++) y[i] = (mc_u8)(y[i] ^ lens[i]);
	ghash_mul(y, h);
}

static void aes128_ctr_xor(const mc_aes128_ctx *aes, mc_u8 counter[16], const mc_u8 *in, mc_u8 *out, mc_usize len) {
	mc_u8 stream[16];
	while (len) {
		mc_aes128_encrypt_block(aes, counter, stream);
		inc32(counter);
		mc_usize n = (len < 16) ? len : 16;
		for (mc_usize i = 0; i < n; i++) out[i] = (mc_u8)(in[i] ^ stream[i]);
		in += n;
		out += n;
		len -= n;
	}
}

static int ct_memeq(const mc_u8 *a, const mc_u8 *b, mc_usize n) {
	mc_u8 diff = 0;
	for (mc_usize i = 0; i < n; i++) diff |= (mc_u8)(a[i] ^ b[i]);
	return diff == 0;
}

int mc_aes128_gcm_encrypt(
	const mc_u8 key[16],
	const mc_u8 iv[MC_GCM_IV_SIZE],
	const mc_u8 *aad, mc_usize aad_len,
	const mc_u8 *plaintext, mc_usize pt_len,
	mc_u8 *ciphertext,
	mc_u8 tag[MC_GCM_TAG_SIZE]
) {
	mc_aes128_ctx aes;
	mc_aes128_init(&aes, key);

	// H = AES_K(0^128)
	mc_u8 h[16];
	mc_u8 zero[16];
	mc_memset(zero, 0, sizeof(zero));
	mc_aes128_encrypt_block(&aes, zero, h);

	// J0 = IV || 0x00000001 (96-bit IV case, as used by TLS 1.3)
	mc_u8 j0[16];
	mc_memcpy(j0, iv, MC_GCM_IV_SIZE);
	j0[12] = 0;
	j0[13] = 0;
	j0[14] = 0;
	j0[15] = 1;

	// Encrypt: C = P XOR AES_K(inc32(J0)) stream
	mc_u8 ctr[16];
	mc_memcpy(ctr, j0, sizeof(ctr));
	inc32(ctr);
	if (pt_len) aes128_ctr_xor(&aes, ctr, plaintext, ciphertext, pt_len);

	// GHASH over AAD and ciphertext, then lengths.
	mc_u8 y[16];
	mc_memset(y, 0, sizeof(y));
	if (aad_len) ghash_update(y, h, aad, aad_len);
	if (pt_len) ghash_update(y, h, ciphertext, pt_len);
	ghash_final_lengths(y, h, aad_len, pt_len);

	// Tag = AES_K(J0) XOR GHASH
	mc_u8 s[16];
	mc_aes128_encrypt_block(&aes, j0, s);
	xor16(tag, s, y);
	return 0;
}

int mc_aes128_gcm_decrypt(
	const mc_u8 key[16],
	const mc_u8 iv[MC_GCM_IV_SIZE],
	const mc_u8 *aad, mc_usize aad_len,
	const mc_u8 *ciphertext, mc_usize ct_len,
	const mc_u8 tag[MC_GCM_TAG_SIZE],
	mc_u8 *plaintext
) {
	mc_aes128_ctx aes;
	mc_aes128_init(&aes, key);

	mc_u8 h[16];
	mc_u8 zero[16];
	mc_memset(zero, 0, sizeof(zero));
	mc_aes128_encrypt_block(&aes, zero, h);

	mc_u8 j0[16];
	mc_memcpy(j0, iv, MC_GCM_IV_SIZE);
	j0[12] = 0;
	j0[13] = 0;
	j0[14] = 0;
	j0[15] = 1;

	mc_u8 y[16];
	mc_memset(y, 0, sizeof(y));
	if (aad_len) ghash_update(y, h, aad, aad_len);
	if (ct_len) ghash_update(y, h, ciphertext, ct_len);
	ghash_final_lengths(y, h, aad_len, ct_len);

	mc_u8 s[16];
	mc_aes128_encrypt_block(&aes, j0, s);
	mc_u8 exp_tag[16];
	xor16(exp_tag, s, y);

	if (!ct_memeq(exp_tag, tag, 16)) return -1;

	mc_u8 ctr[16];
	mc_memcpy(ctr, j0, sizeof(ctr));
	inc32(ctr);
	if (ct_len) aes128_ctr_xor(&aes, ctr, ciphertext, plaintext, ct_len);
	return 0;
}
