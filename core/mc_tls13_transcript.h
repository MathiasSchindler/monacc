#pragma once

#include "mc_types.h"
#include "mc_sha256.h"

// TLS 1.3 transcript hash (SHA-256 only).
// The transcript is the concatenation of handshake messages (including
// their 4-byte handshake headers).

struct mc_tls13_transcript {
	mc_sha256_ctx sha;
};

void mc_tls13_transcript_init(struct mc_tls13_transcript *t);
void mc_tls13_transcript_update(struct mc_tls13_transcript *t, const mc_u8 *data, mc_usize len);
void mc_tls13_transcript_final(const struct mc_tls13_transcript *t, mc_u8 out[MC_SHA256_DIGEST_SIZE]);
