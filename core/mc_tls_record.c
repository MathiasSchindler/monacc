#include "mc.h"
#include "mc_gcm.h"
#include "mc_tls_record.h"

static void store_be16(mc_u8 *p, mc_u16 v) {
	p[0] = (mc_u8)(v >> 8);
	p[1] = (mc_u8)(v >> 0);
}

static mc_u16 load_be16(const mc_u8 *p) {
	return (mc_u16)(((mc_u16)p[0] << 8) | (mc_u16)p[1]);
}

static void make_nonce(mc_u8 nonce[12], const mc_u8 iv[12], mc_u64 seq) {
	mc_memcpy(nonce, iv, 12);
	// nonce = iv XOR seq (seq is 64-bit BE, left-padded to 12 bytes)
	for (int i = 0; i < 8; i++) {
		nonce[11 - i] ^= (mc_u8)(seq >> (8 * i));
	}
}

int mc_tls_record_encrypt(
	const mc_u8 key[16],
	const mc_u8 iv[12],
	mc_u64 seq,
	mc_u8 inner_type,
	const mc_u8 *plaintext, mc_usize pt_len,
	mc_u8 *record_out, mc_usize record_cap, mc_usize *record_len_out
) {
	if (!record_out || !record_len_out) return -1;
	if (!plaintext && pt_len) return -1;

	// TLSInnerPlaintext = content || type || padding
	mc_usize inner_len = pt_len + 1u;
	mc_usize ct_len = inner_len;
	mc_usize rec_len = MC_TLS_RECORD_HEADER_SIZE + ct_len + MC_GCM_TAG_SIZE;
	if (rec_len > record_cap) return -1;
	if (ct_len > 0xffffu) return -1;

	mc_u8 *hdr = record_out;
	hdr[0] = (mc_u8)MC_TLS_CONTENT_APPLICATION_DATA; // TLSCiphertext.opaque_type
	hdr[1] = 0x03;
	hdr[2] = 0x03; // legacy_record_version
	store_be16(hdr + 3, (mc_u16)(ct_len + MC_GCM_TAG_SIZE));

	mc_u8 nonce[12];
	make_nonce(nonce, iv, seq);

	// Plaintext buffer for AEAD.
	mc_u8 *ct = record_out + MC_TLS_RECORD_HEADER_SIZE;
	if (pt_len) mc_memcpy(ct, plaintext, pt_len);
	ct[pt_len] = inner_type;

	mc_u8 tag[16];
	if (mc_aes128_gcm_encrypt(key, nonce, hdr, MC_TLS_RECORD_HEADER_SIZE, ct, inner_len, ct, tag) != 0) return -1;
	mc_memcpy(ct + ct_len, tag, 16);

	*record_len_out = rec_len;
	return 0;
}

int mc_tls_record_decrypt(
	const mc_u8 key[16],
	const mc_u8 iv[12],
	mc_u64 seq,
	const mc_u8 *record, mc_usize record_len,
	mc_u8 *inner_type_out,
	mc_u8 *plaintext_out, mc_usize plaintext_cap, mc_usize *pt_len_out
) {
	if (!record || record_len < MC_TLS_RECORD_HEADER_SIZE + MC_GCM_TAG_SIZE) return -1;
	if (!inner_type_out || !plaintext_out || !pt_len_out) return -1;

	const mc_u8 *hdr = record;
	if (hdr[0] != (mc_u8)MC_TLS_CONTENT_APPLICATION_DATA) return -1;
	if (hdr[1] != 0x03 || hdr[2] != 0x03) return -1;

	mc_u16 len16 = load_be16(hdr + 3);
	mc_usize enc_len = (mc_usize)len16;
	if (MC_TLS_RECORD_HEADER_SIZE + enc_len != record_len) return -1;
	if (enc_len < MC_GCM_TAG_SIZE) return -1;

	mc_usize ct_len = enc_len - MC_GCM_TAG_SIZE;
	const mc_u8 *ct = record + MC_TLS_RECORD_HEADER_SIZE;
	const mc_u8 *tag = ct + ct_len;

	if (ct_len > plaintext_cap) return -1;

	mc_u8 nonce[12];
	make_nonce(nonce, iv, seq);

	// Decrypt into plaintext_out. We keep the full TLSInnerPlaintext first.
	if (mc_aes128_gcm_decrypt(key, nonce, hdr, MC_TLS_RECORD_HEADER_SIZE, ct, ct_len, tag, plaintext_out) != 0) {
		return -1;
	}

	// Remove zero padding, then split off the trailing content type.
	mc_usize i = ct_len;
	while (i > 0 && plaintext_out[i - 1] == 0) i--;
	if (i == 0) return -1;
	mc_u8 inner_type = plaintext_out[i - 1];
	mc_usize content_len = i - 1;

	*inner_type_out = inner_type;
	*pt_len_out = content_len;
	return 0;
}
