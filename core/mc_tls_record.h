#pragma once

#include "mc_types.h"

// TLS 1.3 record layer helpers (AES-128-GCM).
//
// These helpers implement the TLSCiphertext framing and TLSInnerPlaintext
// padding/type scheme (no padding added currently).

#define MC_TLS_RECORD_HEADER_SIZE 5

#define MC_TLS_CONTENT_CHANGE_CIPHER_SPEC 20
#define MC_TLS_CONTENT_ALERT 21
#define MC_TLS_CONTENT_HANDSHAKE 22
#define MC_TLS_CONTENT_APPLICATION_DATA 23

// Encrypts a TLS 1.3 record.
//
// outer type is always application_data (23) for encrypted TLS 1.3 records.
// legacy_record_version is 0x0303.
//
// Returns 0 on success, -1 on error.
int mc_tls_record_encrypt(
	const mc_u8 key[16],
	const mc_u8 iv[12],
	mc_u64 seq,
	mc_u8 inner_type,
	const mc_u8 *plaintext, mc_usize pt_len,
	mc_u8 *record_out, mc_usize record_cap, mc_usize *record_len_out
);

// Decrypts a TLS 1.3 record produced by mc_tls_record_encrypt.
//
// On success, writes the inner content type to inner_type_out and the
// plaintext (without the trailing type/padding) to plaintext_out.
// Returns 0 on success, -1 on auth failure or parse error.
int mc_tls_record_decrypt(
	const mc_u8 key[16],
	const mc_u8 iv[12],
	mc_u64 seq,
	const mc_u8 *record, mc_usize record_len,
	mc_u8 *inner_type_out,
	mc_u8 *plaintext_out, mc_usize plaintext_cap, mc_usize *pt_len_out
);
