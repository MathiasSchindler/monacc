#pragma once

#include "mc_types.h"
#include "mc_sha256.h"

// TLS 1.3 key schedule helpers (SHA-256 only).
// Implements RFC 8446 HKDF-Expand-Label / Derive-Secret and Finished.

// HKDF-Expand-Label(Secret, Label, Context, Length)
// Label is the TLS label without the "tls13 " prefix.
// Returns 0 on success, -1 on error.
int mc_tls13_hkdf_expand_label(
	const mc_u8 secret[MC_SHA256_DIGEST_SIZE],
	const char *label,
	const mc_u8 *context,
	mc_usize context_len,
	mc_u8 *out,
	mc_usize out_len
);

// Derive-Secret(Secret, Label, Messages)
// Here, transcript_hash is Hash(Messages).
// Returns 0 on success, -1 on error.
int mc_tls13_derive_secret(
	const mc_u8 secret[MC_SHA256_DIGEST_SIZE],
	const char *label,
	const mc_u8 transcript_hash[MC_SHA256_DIGEST_SIZE],
	mc_u8 out[MC_SHA256_DIGEST_SIZE]
);

// finished_key = HKDF-Expand-Label(base_key, "finished", "", Hash.length)
// Returns 0 on success, -1 on error.
int mc_tls13_finished_key(
	const mc_u8 base_key[MC_SHA256_DIGEST_SIZE],
	mc_u8 out[MC_SHA256_DIGEST_SIZE]
);

// verify_data = HMAC(finished_key, transcript_hash)
void mc_tls13_finished_verify_data(
	const mc_u8 finished_key[MC_SHA256_DIGEST_SIZE],
	const mc_u8 transcript_hash[MC_SHA256_DIGEST_SIZE],
	mc_u8 out[MC_SHA256_DIGEST_SIZE]
);
