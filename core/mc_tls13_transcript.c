#include "mc.h"
#include "mc_tls13_transcript.h"

void mc_tls13_transcript_init(struct mc_tls13_transcript *t) {
	if (!t) return;
	mc_sha256_init(&t->sha);
}

void mc_tls13_transcript_update(struct mc_tls13_transcript *t, const mc_u8 *data, mc_usize len) {
	if (!t) return;
	if (!data && len) return;
	mc_sha256_update(&t->sha, data, len);
}

void mc_tls13_transcript_final(const struct mc_tls13_transcript *t, mc_u8 out[MC_SHA256_DIGEST_SIZE]) {
	if (!out) return;
	if (!t) {
		mc_memset(out, 0, MC_SHA256_DIGEST_SIZE);
		return;
	}
	mc_sha256_ctx tmp = t->sha;
	mc_sha256_final(&tmp, out);
	mc_memset(&tmp, 0, sizeof(tmp));
}
