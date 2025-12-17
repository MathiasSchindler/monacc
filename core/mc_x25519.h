#pragma once

#include "mc_types.h"

#define MC_X25519_KEY_SIZE 32

// Generate X25519 public key from a 32-byte private key.
// private_key is clamped internally per RFC 7748.
void mc_x25519_public(mc_u8 public_key[MC_X25519_KEY_SIZE], const mc_u8 private_key[MC_X25519_KEY_SIZE]);

// Compute X25519 shared secret.
// Returns 0 on success, -1 if the result is all-zero (bad peer key).
// private_key is clamped internally per RFC 7748.
int mc_x25519_shared(
	mc_u8 shared[MC_X25519_KEY_SIZE],
	const mc_u8 private_key[MC_X25519_KEY_SIZE],
	const mc_u8 peer_public[MC_X25519_KEY_SIZE]
);
