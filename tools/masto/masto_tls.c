#include "masto_tls.h"

#include "mc_gcm.h"
#include "mc_hkdf.h"
#include "mc_hmac.h"
#include "mc_net.h"
#include "mc_sha256.h"
#include "mc_tls13.h"
#include "mc_tls13_handshake.h"
#include "mc_tls13_transcript.h"
#include "mc_tls_record.h"
#include "mc_x25519.h"

#define TLS_PLAINTEXT_HDR 5u
#define TLS_MAX_RECORD (65535u)

#define HS_FINISHED 20u
#define HS_ENCRYPTED_EXTENSIONS 8u
#define HS_CERTIFICATE 11u
#define HS_CERTIFICATE_VERIFY 15u

static void store_be16(mc_u8 *p, mc_u16 v) {
	p[0] = (mc_u8)(v >> 8);
	p[1] = (mc_u8)(v >> 0);
}

static mc_u16 load_be16(const mc_u8 *p) {
	return (mc_u16)(((mc_u16)p[0] << 8) | (mc_u16)p[1]);
}

static int read_exact(mc_i32 fd, void *buf, mc_usize n) {
	mc_u8 *p = (mc_u8 *)buf;
	while (n) {
		mc_i64 r = mc_sys_read(fd, p, n);
		if (r <= 0) return -1;
		p += (mc_usize)r;
		n -= (mc_usize)r;
	}
	return 0;
}

static int write_all(mc_i32 fd, const void *buf, mc_usize n) {
	return mc_write_all(fd, buf, n) == 0 ? 0 : -1;
}

static int tls_read_record(mc_i32 fd, mc_u8 *buf, mc_usize cap, mc_usize *out_len) {
	if (!buf || cap < TLS_PLAINTEXT_HDR || !out_len) return -1;
	if (read_exact(fd, buf, TLS_PLAINTEXT_HDR) != 0) return -1;
	mc_u16 len16 = load_be16(buf + 3);
	mc_usize len = (mc_usize)len16;
	if (len > TLS_MAX_RECORD) return -1;
	if (TLS_PLAINTEXT_HDR + len > cap) return -1;
	if (read_exact(fd, buf + TLS_PLAINTEXT_HDR, len) != 0) return -1;
	*out_len = TLS_PLAINTEXT_HDR + len;
	return 0;
}

static int tls_send_plain_handshake(mc_i32 fd, const mc_u8 *hs, mc_usize hs_len) {
	mc_u8 hdr[TLS_PLAINTEXT_HDR];
	hdr[0] = (mc_u8)MC_TLS_CONTENT_HANDSHAKE;
	hdr[1] = 0x03;
	hdr[2] = 0x03; // legacy_record_version (0x0303 is widely accepted)
	store_be16(hdr + 3, (mc_u16)hs_len);
	if (write_all(fd, hdr, sizeof(hdr)) != 0) return -1;
	if (hs_len && write_all(fd, hs, hs_len) != 0) return -1;
	return 0;
}

static int hs_buf_append(mc_u8 *hs_buf, mc_usize cap, mc_usize *io_len, const mc_u8 *data, mc_usize n) {
	if (!hs_buf || !io_len) return -1;
	if (*io_len + n > cap) return -1;
	if (n) mc_memcpy(hs_buf + *io_len, data, n);
	*io_len += n;
	return 0;
}

static int hs_buf_consume(mc_u8 *hs_buf, mc_usize *io_len, mc_usize n) {
	if (!hs_buf || !io_len) return -1;
	if (n > *io_len) return -1;
	mc_usize rem = *io_len - n;
	if (rem) mc_memmove(hs_buf, hs_buf + n, rem);
	*io_len = rem;
	return 0;
}

static int parse_handshake_header(const mc_u8 *p, mc_usize n, mc_u8 *type_out, mc_u32 *len_out) {
	if (!p || n < 4 || !type_out || !len_out) return -1;
	*type_out = p[0];
	*len_out = ((mc_u32)p[1] << 16) | ((mc_u32)p[2] << 8) | (mc_u32)p[3];
	return 0;
}

static int derive_traffic_key_iv(const mc_u8 secret[MC_SHA256_DIGEST_SIZE], mc_u8 key_out[16], mc_u8 iv_out[12]) {
	if (mc_tls13_hkdf_expand_label(secret, "key", MC_NULL, 0, key_out, 16) != 0) return -1;
	if (mc_tls13_hkdf_expand_label(secret, "iv", MC_NULL, 0, iv_out, 12) != 0) return -1;
	return 0;
}

static int decrypt_and_feed_hs(
	mc_u8 *hs_buf, mc_usize hs_cap, mc_usize *hs_len,
	struct mc_tls13_transcript *transcript,
	const mc_u8 s_hs_key[16], const mc_u8 s_hs_iv[12], mc_u64 *s_hs_seq,
	const mc_u8 *record, mc_usize record_len,
	mc_u8 *tmp_plain, mc_usize tmp_cap
) {
	mc_u8 inner_type = 0;
	mc_usize pt_len = 0;
	if (mc_tls_record_decrypt(s_hs_key, s_hs_iv, *s_hs_seq, record, record_len, &inner_type, tmp_plain, tmp_cap, &pt_len) != 0) {
		return -1;
	}
	(*s_hs_seq)++;
	if (inner_type == (mc_u8)MC_TLS_CONTENT_HANDSHAKE) {
		if (hs_buf_append(hs_buf, hs_cap, hs_len, tmp_plain, pt_len) != 0) return -1;
		(void)transcript; // transcript is updated per-message when parsed.
		return 0;
	}
	// Ignore alerts/others for now.
	return 0;
}

int masto_tls13_handshake(struct masto_tls13 *out, mc_i32 fd, const char *sni) {
	if (!out || fd < 0 || !sni || !*sni) return -1;
	mc_memset(out, 0, sizeof(*out));
	out->fd = fd;

	// Generate client random, session id, and x25519 keypair.
	mc_u8 random32[32];
	mc_u8 session_id[32];
	mc_u8 x_priv[32];
	mc_u8 x_pub[32];
	if (mc_sys_getrandom(random32, sizeof(random32), 0) < 0) return -1;
	if (mc_sys_getrandom(session_id, sizeof(session_id), 0) < 0) return -1;
	if (mc_sys_getrandom(x_priv, sizeof(x_priv), 0) < 0) return -1;
	mc_x25519_public(x_pub, x_priv);

	mc_u8 client_hello[1024];
	mc_usize ch_len = 0;
	mc_usize sni_len = mc_strlen(sni);
	if (mc_tls13_build_client_hello(sni, sni_len, random32, session_id, sizeof(session_id), x_pub, client_hello, sizeof(client_hello), &ch_len) != 0) {
		return -1;
	}

	struct mc_tls13_transcript tr;
	mc_tls13_transcript_init(&tr);
	mc_tls13_transcript_update(&tr, client_hello, ch_len);

	if (tls_send_plain_handshake(fd, client_hello, ch_len) != 0) return -1;

	// Read plaintext records until we get ServerHello.
	mc_u8 rec[TLS_PLAINTEXT_HDR + 32768];
	mc_usize rec_len = 0;
	mc_u8 hs_buf[65536];
	mc_usize hs_len = 0;

	struct mc_tls13_server_hello sh;
	mc_u8 got_sh = 0;
	for (int iter = 0; iter < 64 && !got_sh; iter++) {
		if (tls_read_record(fd, rec, sizeof(rec), &rec_len) != 0) return -1;
		mc_u8 rtype = rec[0];
		mc_usize payload_len = rec_len - TLS_PLAINTEXT_HDR;
		const mc_u8 *payload = rec + TLS_PLAINTEXT_HDR;
		if (rtype == (mc_u8)MC_TLS_CONTENT_HANDSHAKE) {
			if (hs_buf_append(hs_buf, sizeof(hs_buf), &hs_len, payload, payload_len) != 0) return -1;
			// Try parse first full handshake message.
			mc_u8 htype = 0;
			mc_u32 hlen = 0;
			if (hs_len >= 4 && parse_handshake_header(hs_buf, hs_len, &htype, &hlen) == 0) {
				if (hs_len >= 4u + (mc_usize)hlen) {
					mc_usize msg_len = 4u + (mc_usize)hlen;
					if (htype == (mc_u8)MC_TLS13_HANDSHAKE_SERVER_HELLO) {
						if (mc_tls13_parse_server_hello(hs_buf, msg_len, &sh) != 0) return -1;
						mc_tls13_transcript_update(&tr, hs_buf, msg_len);
						(void)hs_buf_consume(hs_buf, &hs_len, msg_len);
						got_sh = 1;
					}
				}
			}
		} else if (rtype == (mc_u8)MC_TLS_CONTENT_CHANGE_CIPHER_SPEC) {
			// ignore
		} else if (rtype == (mc_u8)MC_TLS_CONTENT_ALERT) {
			return -1;
		}
	}
	if (!got_sh) return -1;
	if (sh.selected_version != 0x0304) return -1;
	if (sh.key_share_group != MC_TLS13_GROUP_X25519 || sh.key_share_len != 32) return -1;

	// Derive handshake keys.
	mc_u8 ecdhe[32];
	if (mc_x25519_shared(ecdhe, x_priv, sh.key_share) != 0) return -1;

	mc_u8 empty_hash[32];
	mc_sha256(MC_NULL, 0, empty_hash);

	mc_u8 early_secret[32];
	mc_hkdf_extract(MC_NULL, 0, MC_NULL, 0, early_secret);

	mc_u8 derived_secret[32];
	if (mc_tls13_derive_secret(early_secret, "derived", empty_hash, derived_secret) != 0) return -1;

	mc_u8 handshake_secret[32];
	mc_hkdf_extract(derived_secret, 32, ecdhe, 32, handshake_secret);

	mc_u8 ch_sh_hash[32];
	mc_tls13_transcript_final(&tr, ch_sh_hash);

	mc_u8 c_hs_traffic[32];
	mc_u8 s_hs_traffic[32];
	if (mc_tls13_derive_secret(handshake_secret, "c hs traffic", ch_sh_hash, c_hs_traffic) != 0) return -1;
	if (mc_tls13_derive_secret(handshake_secret, "s hs traffic", ch_sh_hash, s_hs_traffic) != 0) return -1;

	mc_u8 c_hs_key[16], c_hs_iv[12];
	mc_u8 s_hs_key[16], s_hs_iv[12];
	if (derive_traffic_key_iv(c_hs_traffic, c_hs_key, c_hs_iv) != 0) return -1;
	if (derive_traffic_key_iv(s_hs_traffic, s_hs_key, s_hs_iv) != 0) return -1;
	mc_u64 c_hs_seq = 0;
	mc_u64 s_hs_seq = 0;

	// Now read encrypted handshake messages until server Finished.
	mc_u8 tmp_plain[65536];
	mc_u8 server_finished_body[32];
	mc_u8 got_finished = 0;

	for (int iter = 0; iter < 512 && !got_finished; iter++) {
		if (tls_read_record(fd, rec, sizeof(rec), &rec_len) != 0) return -1;
		mc_u8 rtype = rec[0];
		if (rtype == (mc_u8)MC_TLS_CONTENT_APPLICATION_DATA) {
			if (decrypt_and_feed_hs(hs_buf, sizeof(hs_buf), &hs_len, &tr, s_hs_key, s_hs_iv, &s_hs_seq, rec, rec_len, tmp_plain, sizeof(tmp_plain)) != 0) {
				return -1;
			}
			// Parse as many handshake messages as are complete.
			for (;;) {
				if (hs_len < 4) break;
				mc_u8 htype = 0;
				mc_u32 hlen = 0;
				if (parse_handshake_header(hs_buf, hs_len, &htype, &hlen) != 0) return -1;
				mc_usize msg_len = 4u + (mc_usize)hlen;
				if (hs_len < msg_len) break;

				// For all handshake messages, update transcript.
				if (htype == HS_FINISHED) {
					if (hlen != 32u) return -1;
					mc_memcpy(server_finished_body, hs_buf + 4u, 32u);

					// Verify server Finished (over transcript up to but excluding Finished).
					mc_u8 th[32];
					mc_tls13_transcript_final(&tr, th);
					mc_u8 s_fin_key[32];
					mc_u8 exp[32];
					if (mc_tls13_finished_key(s_hs_traffic, s_fin_key) != 0) return -1;
					mc_tls13_finished_verify_data(s_fin_key, th, exp);
					if (mc_memcmp(exp, server_finished_body, 32) != 0) return -1;
					mc_memset(s_fin_key, 0, sizeof(s_fin_key));
					mc_memset(exp, 0, sizeof(exp));

					// Now include server Finished into transcript.
					mc_tls13_transcript_update(&tr, hs_buf, msg_len);
					got_finished = 1;
				} else {
					// EncryptedExtensions / Certificate / CertificateVerify etc.
					mc_tls13_transcript_update(&tr, hs_buf, msg_len);
				}

				(void)hs_buf_consume(hs_buf, &hs_len, msg_len);
				if (got_finished) break;
			}
		} else if (rtype == (mc_u8)MC_TLS_CONTENT_CHANGE_CIPHER_SPEC) {
			// ignore
		} else if (rtype == (mc_u8)MC_TLS_CONTENT_ALERT) {
			return -1;
		}
	}
	if (!got_finished) return -1;

	// Send client Finished.
	mc_u8 th2[32];
	mc_tls13_transcript_final(&tr, th2);
	mc_u8 c_fin_key[32];
	mc_u8 c_verify[32];
	if (mc_tls13_finished_key(c_hs_traffic, c_fin_key) != 0) return -1;
	mc_tls13_finished_verify_data(c_fin_key, th2, c_verify);
	mc_memset(c_fin_key, 0, sizeof(c_fin_key));

	mc_u8 fin_msg[4u + 32u];
	fin_msg[0] = (mc_u8)HS_FINISHED;
	fin_msg[1] = 0;
	fin_msg[2] = 0;
	fin_msg[3] = 32;
	mc_memcpy(fin_msg + 4, c_verify, 32);
	mc_memset(c_verify, 0, sizeof(c_verify));

	mc_u8 enc_record[TLS_PLAINTEXT_HDR + 32768];
	mc_usize enc_len = 0;
	if (mc_tls_record_encrypt(c_hs_key, c_hs_iv, c_hs_seq, (mc_u8)MC_TLS_CONTENT_HANDSHAKE, fin_msg, sizeof(fin_msg), enc_record, sizeof(enc_record), &enc_len) != 0) {
		return -1;
	}
	c_hs_seq++;
	if (write_all(fd, enc_record, enc_len) != 0) return -1;

	// Add client Finished to transcript.
	mc_tls13_transcript_update(&tr, fin_msg, sizeof(fin_msg));
	mc_memset(fin_msg, 0, sizeof(fin_msg));

	// Derive application traffic secrets.
	mc_u8 derived2[32];
	if (mc_tls13_derive_secret(handshake_secret, "derived", empty_hash, derived2) != 0) return -1;
	mc_u8 master_secret[32];
	mc_hkdf_extract(derived2, 32, MC_NULL, 0, master_secret);

	mc_u8 th3[32];
	mc_tls13_transcript_final(&tr, th3);
	mc_u8 c_ap_traffic[32];
	mc_u8 s_ap_traffic[32];
	if (mc_tls13_derive_secret(master_secret, "c ap traffic", th3, c_ap_traffic) != 0) return -1;
	if (mc_tls13_derive_secret(master_secret, "s ap traffic", th3, s_ap_traffic) != 0) return -1;

	if (derive_traffic_key_iv(c_ap_traffic, out->c_app_key, out->c_app_iv) != 0) return -1;
	if (derive_traffic_key_iv(s_ap_traffic, out->s_app_key, out->s_app_iv) != 0) return -1;
	out->c_app_seq = 0;
	out->s_app_seq = 0;

	// Best-effort wipe secrets we no longer need.
	mc_memset(x_priv, 0, sizeof(x_priv));
	mc_memset(ecdhe, 0, sizeof(ecdhe));
	mc_memset(early_secret, 0, sizeof(early_secret));
	mc_memset(derived_secret, 0, sizeof(derived_secret));
	mc_memset(handshake_secret, 0, sizeof(handshake_secret));
	mc_memset(master_secret, 0, sizeof(master_secret));
	mc_memset(c_hs_traffic, 0, sizeof(c_hs_traffic));
	mc_memset(s_hs_traffic, 0, sizeof(s_hs_traffic));
	mc_memset(c_hs_key, 0, sizeof(c_hs_key));
	mc_memset(c_hs_iv, 0, sizeof(c_hs_iv));
	mc_memset(s_hs_key, 0, sizeof(s_hs_key));
	mc_memset(s_hs_iv, 0, sizeof(s_hs_iv));
	mc_memset(c_ap_traffic, 0, sizeof(c_ap_traffic));
	mc_memset(s_ap_traffic, 0, sizeof(s_ap_traffic));
	mc_memset(th2, 0, sizeof(th2));
	mc_memset(th3, 0, sizeof(th3));
	mc_memset(empty_hash, 0, sizeof(empty_hash));

	return 0;
}
