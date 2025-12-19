#include "mc.h"
#include "mc_hkdf.h"
#include "mc_hmac.h"
#include "mc_tls13.h"

static void store_be16(mc_u8 *p, mc_u16 v) {
	p[0] = (mc_u8)(v >> 8);
	p[1] = (mc_u8)(v >> 0);
}

static mc_usize cstr_len(const char *s) {
	mc_usize n = 0;
	if (!s) return 0;
	while (s[n]) n++;
	return n;
}

int mc_tls13_hkdf_expand_label(
	const mc_u8 secret[MC_SHA256_DIGEST_SIZE],
	const char *label,
	const mc_u8 *context,
	mc_usize context_len,
	mc_u8 *out,
	mc_usize out_len
) {
	if (!out || out_len == 0) return -1;
	if (!secret) {
		mc_memset(out, 0, out_len);
		return -1;
	}

	// HKDFLabel:
	// struct {
	//   uint16 length;
	//   opaque label<7..255>; // "tls13 " + label
	//   opaque context<0..255>;
	// } HKDFLabel;
	const char *prefix = "tls13 ";
	mc_usize prefix_len = 6u;
	mc_usize label_len = cstr_len(label);
	mc_usize full_label_len = prefix_len + label_len;
	if (full_label_len > 255u) return -1;
	if (context_len > 255u) return -1;
	if (out_len > 0xffffu) return -1;

	mc_u8 info[2u + 1u + 255u + 1u + 255u];
	mc_usize off = 0;
	store_be16(info + off, (mc_u16)out_len);
	off += 2;
	info[off++] = (mc_u8)full_label_len;
	mc_memcpy(info + off, prefix, prefix_len);
	off += prefix_len;
	if (label_len) {
		mc_memcpy(info + off, label, label_len);
		off += label_len;
	}
	info[off++] = (mc_u8)context_len;
	if (context_len) {
		if (!context) return -1;
		mc_memcpy(info + off, context, context_len);
		off += context_len;
	}

	mc_hkdf_expand(secret, info, off, out, out_len);
	mc_memset(info, 0, sizeof(info));
	return 0;
}

int mc_tls13_derive_secret(
	const mc_u8 secret[MC_SHA256_DIGEST_SIZE],
	const char *label,
	const mc_u8 transcript_hash[MC_SHA256_DIGEST_SIZE],
	mc_u8 out[MC_SHA256_DIGEST_SIZE]
) {
	if (!out) return -1;
	if (!transcript_hash) {
		mc_memset(out, 0, MC_SHA256_DIGEST_SIZE);
		return -1;
	}
	return mc_tls13_hkdf_expand_label(secret, label, transcript_hash, MC_SHA256_DIGEST_SIZE, out, MC_SHA256_DIGEST_SIZE);
}

int mc_tls13_finished_key(
	const mc_u8 base_key[MC_SHA256_DIGEST_SIZE],
	mc_u8 out[MC_SHA256_DIGEST_SIZE]
) {
	return mc_tls13_hkdf_expand_label(base_key, "finished", MC_NULL, 0, out, MC_SHA256_DIGEST_SIZE);
}

void mc_tls13_finished_verify_data(
	const mc_u8 finished_key[MC_SHA256_DIGEST_SIZE],
	const mc_u8 transcript_hash[MC_SHA256_DIGEST_SIZE],
	mc_u8 out[MC_SHA256_DIGEST_SIZE]
) {
	if (!out) return;
	if (!finished_key || !transcript_hash) {
		mc_memset(out, 0, MC_SHA256_DIGEST_SIZE);
		return;
	}
	mc_hmac_sha256(finished_key, MC_SHA256_DIGEST_SIZE, transcript_hash, MC_SHA256_DIGEST_SIZE, out);
}
