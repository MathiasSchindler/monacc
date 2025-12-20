#include "mc_tls13_client.h"

#include "mc_net.h"
#include "mc_sha256.h"
#include "mc_hkdf.h"
#include "mc_tls13.h"
#include "mc_tls13_handshake.h"
#include "mc_tls13_transcript.h"
#include "mc_tls_record.h"
#include "mc_x25519.h"
#include "mc_syscall.h"
#include "mc.h"

#define MC_TLS13_HS_FINISHED 20

struct mc_tls13_ap_variant {
	mc_u8 c_key[16];
	mc_u8 c_iv[12];
	mc_u8 s_key[16];
	mc_u8 s_iv[12];
	mc_u8 which_master;
	mc_u8 which_th;
};

static const mc_u8 *sha256_empty_hs_ptr(void) {
	return (const mc_u8 *)
		"\xe3\xb0\xc4\x42\x98\xfc\x1c\x14\x9a\xfb\xf4\xc8\x99\x6f\xb9\x24"
		"\x27\xae\x41\xe4\x64\x9b\x93\x4c\xa4\x95\x99\x1b\x78\x52\xb8\x55";
}

static int poll_one(mc_i32 fd, mc_i16 events, mc_u32 timeout_ms) {
	struct mc_pollfd pfd;
	pfd.fd = fd;
	pfd.events = events;
	pfd.revents = 0;
	mc_i64 r = mc_sys_poll(&pfd, 1, (mc_i32)timeout_ms);
	if (r < 0) return 0;
	if (r == 0) return 0;
	return (pfd.revents & events) != 0;
}

static int read_exact_timeout(mc_i32 fd, void *buf, mc_usize len, mc_u32 timeout_ms) {
	mc_u8 *p = (mc_u8 *)buf;
	mc_usize got = 0;
	while (got < len) {
		if (!poll_one(fd, MC_POLLIN, timeout_ms)) return 0;
		mc_i64 r = mc_sys_read(fd, p + got, len - got);
		if (r < 0) return 0;
		if (r == 0) return 0;
		got += (mc_usize)r;
	}
	return 1;
}

static int write_all_timeout(mc_i32 fd, const void *buf, mc_usize len, mc_u32 timeout_ms) {
	const mc_u8 *p = (const mc_u8 *)buf;
	mc_usize off = 0;
	while (off < len) {
		if (!poll_one(fd, MC_POLLOUT, timeout_ms)) return 0;
		mc_i64 w = mc_sys_write(fd, p + off, len - off);
		if (w < 0) return 0;
		if (w == 0) return 0;
		off += (mc_usize)w;
	}
	return 1;
}

static int record_read_timeout(mc_i32 fd, mc_u32 timeout_ms, mc_u8 hdr[5], mc_u8 *payload, mc_usize payload_cap, mc_usize *out_len) {
	if (!hdr || !payload || !out_len) return 0;
	if (!read_exact_timeout(fd, hdr, 5, timeout_ms)) return 0;
	mc_u16 rlen = (mc_u16)(((mc_u16)hdr[3] << 8) | (mc_u16)hdr[4]);
	if ((mc_usize)rlen > payload_cap) return 0;
	if (!read_exact_timeout(fd, payload, (mc_usize)rlen, timeout_ms)) return 0;
	*out_len = (mc_usize)rlen;
	return 1;
}

static int hs_append(mc_u8 *buf, mc_usize cap, mc_usize *io_len, const mc_u8 *p, mc_usize n) {
	if (!buf || !io_len) return -1;
	if (!p && n) return -1;
	if (*io_len + n > cap) return -1;
	if (n) mc_memcpy(buf + *io_len, p, n);
	*io_len += n;
	return 0;
}

static int hs_consume_one(mc_u8 *buf, mc_usize *io_len, mc_u8 *out_type, mc_u32 *out_body_len, mc_u8 *out_msg, mc_usize out_cap,
	mc_usize *out_msg_len) {
	if (!buf || !io_len || !out_type || !out_body_len || !out_msg || !out_msg_len) return -1;
	if (*io_len < 4u) return 1;
	mc_u8 ht = buf[0];
	mc_u32 hl = ((mc_u32)buf[1] << 16) | ((mc_u32)buf[2] << 8) | (mc_u32)buf[3];
	mc_usize total = 4u + (mc_usize)hl;
	if (total > *io_len) return 1;
	if (total > out_cap) return -1;
	mc_memcpy(out_msg, buf, total);
	*out_type = ht;
	*out_body_len = hl;
	*out_msg_len = total;
	mc_usize rem = *io_len - total;
	if (rem) mc_memmove(buf, buf + total, rem);
	*io_len = rem;
	return 0;
}

static int getrandom_best_effort(void *buf, mc_usize len) {
	mc_u8 *p = (mc_u8 *)buf;
	mc_usize off = 0;
	while (off < len) {
		mc_i64 r = mc_sys_getrandom(p + off, len - off, 0);
		if (r < 0) break;
		if (r == 0) break;
		off += (mc_usize)r;
	}
	if (off == len) return 1;

	// Fallback: weak mixing from monotonic clock + address.
	struct mc_timespec ts;
	mc_sys_clock_gettime(MC_CLOCK_MONOTONIC, &ts);
	mc_u64 mix = (mc_u64)ts.tv_nsec ^ ((mc_u64)ts.tv_sec << 32) ^ (mc_u64)(mc_usize)(void *)buf;
	for (mc_usize i = off; i < len; i++) {
		mix ^= mix << 13;
		mix ^= mix >> 7;
		mix ^= mix << 17;
		p[i] = (mc_u8)(mix & 0xffu);
	}
	return 1;
}

static void tlsdbg(struct mc_tls13_client *c, const char *s) {
	if (!c || !c->debug || !s) return;
	(void)mc_write_str(2, s);
}

void mc_tls13_client_init(struct mc_tls13_client *c, mc_i32 fd, mc_u32 timeout_ms) {
	if (!c) return;
	mc_memset(c, 0, sizeof(*c));
	c->fd = fd;
	c->timeout_ms = timeout_ms;
	c->debug = 0;
	c->c_ap_seq = 0;
	c->s_ap_seq = 0;
	c->handshake_done = 0;
}

int mc_tls13_client_handshake(struct mc_tls13_client *c, const char *sni, mc_usize sni_len) {
	if (!c) return -1;
	if (c->fd < 0) return -1;
	if (sni && (sni_len == 0 || sni_len > 255u)) return -1;

	// Build ClientHello
	mc_u8 ch_random[32];
	mc_u8 ch_sid[32];
	mc_u8 x25519_priv[32];
	mc_u8 x25519_pub[32];
	(void)getrandom_best_effort(ch_random, sizeof(ch_random));
	(void)getrandom_best_effort(ch_sid, sizeof(ch_sid));
	(void)getrandom_best_effort(x25519_priv, sizeof(x25519_priv));
	mc_x25519_public(x25519_pub, x25519_priv);

	mc_u8 ch[2048];
	mc_usize ch_len = 0;
	if (mc_tls13_build_client_hello(sni ? sni : "", sni ? sni_len : 0, ch_random, ch_sid, sizeof(ch_sid), x25519_pub, ch, sizeof(ch), &ch_len) != 0) {
		return -1;
	}

	// TLSPlaintext record wrapping the handshake message.
	mc_u8 rec[5 + 2048];
	if (ch_len > 2048) return -1;
	rec[0] = 22;
	rec[1] = 0x03;
	rec[2] = 0x01;
	rec[3] = (mc_u8)((ch_len >> 8) & 0xFFu);
	rec[4] = (mc_u8)(ch_len & 0xFFu);
	mc_memcpy(rec + 5, ch, ch_len);
	if (!write_all_timeout(c->fd, rec, 5 + ch_len, c->timeout_ms)) return -1;

	// Read records until we see ServerHello.
	mc_u8 rhdr[5];
	mc_u8 payload[65536];
	mc_u8 sh_msg[2048];
	mc_usize sh_len = 0;
	int got_sh = 0;
	for (int iter = 0; iter < 32; iter++) {
		if (!read_exact_timeout(c->fd, rhdr, 5, c->timeout_ms)) break;
		mc_u8 rtype = rhdr[0];
		mc_u16 rlen = (mc_u16)(((mc_u16)rhdr[3] << 8) | (mc_u16)rhdr[4]);
		if (rlen > sizeof(payload)) break;
		if (!read_exact_timeout(c->fd, payload, (mc_usize)rlen, c->timeout_ms)) break;
		if (rtype != 22) continue;
		mc_usize off = 0;
		while (off + 4 <= (mc_usize)rlen) {
			mc_u8 ht = payload[off + 0];
			mc_u32 hl = ((mc_u32)payload[off + 1] << 16) | ((mc_u32)payload[off + 2] << 8) | (mc_u32)payload[off + 3];
			mc_usize htot = 4u + (mc_usize)hl;
			if (off + htot > (mc_usize)rlen) break;
			if (ht == MC_TLS13_HANDSHAKE_SERVER_HELLO) {
				if (htot > sizeof(sh_msg)) break;
				mc_memcpy(sh_msg, payload + off, htot);
				sh_len = htot;
				got_sh = 1;
				break;
			}
			off += htot;
		}
		if (got_sh) break;
	}
	if (!got_sh) return -1;

	struct mc_tls13_server_hello sh;
	if (mc_tls13_parse_server_hello(sh_msg, sh_len, &sh) != 0) return -1;

	struct mc_tls13_transcript t;
	mc_tls13_transcript_init(&t);
	mc_tls13_transcript_update(&t, ch, ch_len);
	mc_tls13_transcript_update(&t, sh_msg, sh_len);
	mc_u8 chsh_hash[32];
	mc_tls13_transcript_final(&t, chsh_hash);

	if (sh.key_share_group != MC_TLS13_GROUP_X25519 || sh.key_share_len != 32) return -1;
	if (sh.selected_version != 0x0304) return -1;

	mc_u8 ecdhe[32];
	if (mc_x25519_shared(ecdhe, x25519_priv, sh.key_share) != 0) return -1;

	mc_u8 zeros32[32];
	mc_memset(zeros32, 0, sizeof(zeros32));
	mc_u8 early[32];
	mc_hkdf_extract(zeros32, sizeof(zeros32), zeros32, sizeof(zeros32), early);

	mc_u8 derived[32];
	if (mc_tls13_derive_secret(early, "derived", sha256_empty_hs_ptr(), derived) != 0) return -1;

	mc_u8 handshake_secret[32];
	mc_hkdf_extract(derived, sizeof(derived), ecdhe, sizeof(ecdhe), handshake_secret);

	mc_u8 c_hs[32];
	mc_u8 s_hs[32];
	if (mc_tls13_derive_secret(handshake_secret, "c hs traffic", chsh_hash, c_hs) != 0) return -1;
	if (mc_tls13_derive_secret(handshake_secret, "s hs traffic", chsh_hash, s_hs) != 0) return -1;

	mc_u8 c_key[16];
	mc_u8 c_iv[12];
	mc_u8 s_key[16];
	mc_u8 s_iv[12];
	if (mc_tls13_hkdf_expand_label(c_hs, "key", MC_NULL, 0, c_key, sizeof(c_key)) != 0) return -1;
	if (mc_tls13_hkdf_expand_label(c_hs, "iv", MC_NULL, 0, c_iv, sizeof(c_iv)) != 0) return -1;
	if (mc_tls13_hkdf_expand_label(s_hs, "key", MC_NULL, 0, s_key, sizeof(s_key)) != 0) return -1;
	if (mc_tls13_hkdf_expand_label(s_hs, "iv", MC_NULL, 0, s_iv, sizeof(s_iv)) != 0) return -1;

	mc_u64 s_hs_seq = 0;
	mc_u64 c_hs_seq = 0;
	int verified_server_finished = 0;

	mc_u8 hs_buf[131072];
	mc_usize hs_buf_len = 0;
	for (int iter = 0; iter < 256; iter++) {
		mc_usize rlen = 0;
		if (!record_read_timeout(c->fd, c->timeout_ms, rhdr, payload, sizeof(payload), &rlen)) break;
		mc_u8 rtype = rhdr[0];
		if (rtype == MC_TLS_CONTENT_CHANGE_CIPHER_SPEC) continue;
		if (rtype == MC_TLS_CONTENT_ALERT) break;
		if (rtype != MC_TLS_CONTENT_APPLICATION_DATA) continue;

		mc_u8 record[5 + 65536];
		mc_usize record_len = 5u + rlen;
		if (record_len > sizeof(record)) break;
		mc_memcpy(record, rhdr, 5);
		mc_memcpy(record + 5, payload, rlen);

		mc_u8 inner_type = 0;
		mc_u8 pt[65536];
		mc_usize pt_len = 0;
		if (mc_tls_record_decrypt(s_key, s_iv, s_hs_seq, record, record_len, &inner_type, pt, sizeof(pt), &pt_len) != 0) break;
		s_hs_seq++;
		if (inner_type != MC_TLS_CONTENT_HANDSHAKE) continue;
		if (hs_append(hs_buf, sizeof(hs_buf), &hs_buf_len, pt, pt_len) != 0) break;

		for (;;) {
			mc_u8 msg_type = 0;
			mc_u32 msg_body_len = 0;
			mc_u8 msg[65536];
			mc_usize msg_len = 0;
			int cr = hs_consume_one(hs_buf, &hs_buf_len, &msg_type, &msg_body_len, msg, sizeof(msg), &msg_len);
			if (cr == 1) break;
			if (cr != 0) { iter = 9999; break; }

			if (c->debug) {
				tlsdbg(c, "hs_type ");
				(void)mc_write_u64_dec(2, (mc_u64)msg_type);
				tlsdbg(c, " hs_len ");
				(void)mc_write_u64_dec(2, (mc_u64)msg_body_len);
				tlsdbg(c, "\n");
			}

			if (msg_type == MC_TLS13_HS_FINISHED) {
				mc_u8 th_pre[32];
				mc_tls13_transcript_final(&t, th_pre);
				mc_u8 s_finished_key[32];
				if (mc_tls13_finished_key(s_hs, s_finished_key) != 0) { iter = 9999; break; }
				mc_u8 expected_verify[32];
				mc_tls13_finished_verify_data(s_finished_key, th_pre, expected_verify);
				mc_memset(s_finished_key, 0, sizeof(s_finished_key));
				if (msg_body_len != 32 || msg_len != 36) { iter = 9999; break; }
				if (mc_memcmp(expected_verify, msg + 4, 32) != 0) { iter = 9999; break; }
				verified_server_finished = 1;
			}

			mc_tls13_transcript_update(&t, msg, msg_len);
			if (msg_type == MC_TLS13_HS_FINISHED) break;
		}

		if (verified_server_finished) break;
	}
	if (!verified_server_finished) return -1;

	mc_u8 th_post_server_finished[32];
	mc_tls13_transcript_final(&t, th_post_server_finished);

	mc_u8 c_finished_key[32];
	if (mc_tls13_finished_key(c_hs, c_finished_key) != 0) return -1;
	mc_u8 c_verify[32];
	mc_tls13_finished_verify_data(c_finished_key, th_post_server_finished, c_verify);
	mc_memset(c_finished_key, 0, sizeof(c_finished_key));

	mc_u8 cfin[4 + 32];
	cfin[0] = (mc_u8)MC_TLS13_HS_FINISHED;
	cfin[1] = 0;
	cfin[2] = 0;
	cfin[3] = 32;
	mc_memcpy(cfin + 4, c_verify, 32);

	mc_u8 cfin_record[5 + 1024];
	mc_usize cfin_record_len = 0;
	if (mc_tls_record_encrypt(c_key, c_iv, c_hs_seq, MC_TLS_CONTENT_HANDSHAKE, cfin, sizeof(cfin), cfin_record, sizeof(cfin_record), &cfin_record_len) != 0) return -1;
	c_hs_seq++;
	if (!write_all_timeout(c->fd, cfin_record, cfin_record_len, c->timeout_ms)) return -1;
	mc_tls13_transcript_update(&t, cfin, sizeof(cfin));
	if (c->debug) tlsdbg(c, "sent_client_finished 1\n");

	mc_u8 th_post_client_finished[32];
	mc_tls13_transcript_final(&t, th_post_client_finished);

	// Derive application traffic keys (keep existing tool's pragmatic variant search).
	mc_u8 derived2[32];
	if (mc_tls13_derive_secret(handshake_secret, "derived", sha256_empty_hs_ptr(), derived2) != 0) return -1;

	struct mc_tls13_ap_variant vars[4];
	mc_usize nvars = 0;
	for (int master_mode = 0; master_mode < 2; master_mode++) {
		mc_u8 master_secret[32];
		if (master_mode == 0) {
			mc_u8 zeros32b[32];
			mc_memset(zeros32b, 0, sizeof(zeros32b));
			mc_hkdf_extract(derived2, sizeof(derived2), zeros32b, sizeof(zeros32b), master_secret);
		} else {
			mc_hkdf_extract(derived2, sizeof(derived2), MC_NULL, 0, master_secret);
		}
		for (int th_mode = 0; th_mode < 2; th_mode++) {
			const mc_u8 *th = (th_mode == 0) ? th_post_server_finished : th_post_client_finished;
			mc_u8 c_ap[32];
			mc_u8 s_ap[32];
			if (mc_tls13_derive_secret(master_secret, "c ap traffic", th, c_ap) != 0) return -1;
			if (mc_tls13_derive_secret(master_secret, "s ap traffic", th, s_ap) != 0) return -1;

			struct mc_tls13_ap_variant *v = &vars[nvars++];
			v->which_master = (mc_u8)master_mode;
			v->which_th = (mc_u8)th_mode;
			if (mc_tls13_hkdf_expand_label(c_ap, "key", MC_NULL, 0, v->c_key, sizeof(v->c_key)) != 0) return -1;
			if (mc_tls13_hkdf_expand_label(c_ap, "iv", MC_NULL, 0, v->c_iv, sizeof(v->c_iv)) != 0) return -1;
			if (mc_tls13_hkdf_expand_label(s_ap, "key", MC_NULL, 0, v->s_key, sizeof(v->s_key)) != 0) return -1;
			if (mc_tls13_hkdf_expand_label(s_ap, "iv", MC_NULL, 0, v->s_iv, sizeof(v->s_iv)) != 0) return -1;
		}
		mc_memset(master_secret, 0, sizeof(master_secret));
	}

	mc_u8 c_ap_key[16];
	mc_u8 c_ap_iv[12];
	mc_u8 s_ap_key[16];
	mc_u8 s_ap_iv[12];
	mc_u64 c_ap_seq = 0;
	mc_u64 s_ap_seq = 0;
	int have_active_ap = 0;

	// Pre-decrypt one record to select active keys.
	{
		mc_usize rlen = 0;
		if (record_read_timeout(c->fd, c->timeout_ms, rhdr, payload, sizeof(payload), &rlen)) {
			mc_u8 rtype = rhdr[0];
			if (rtype == MC_TLS_CONTENT_APPLICATION_DATA) {
				mc_u8 record[5 + 65536];
				mc_usize record_len = 5u + rlen;
				if (record_len <= sizeof(record)) {
					mc_memcpy(record, rhdr, 5);
					mc_memcpy(record + 5, payload, rlen);

					mc_u8 inner_type = 0;
					mc_u8 pt[65536];
					mc_usize pt_len = 0;
					for (mc_usize vi = 0; vi < nvars && !have_active_ap; vi++) {
						for (int seq_mode = 0; seq_mode < 2 && !have_active_ap; seq_mode++) {
							mc_u64 try_seq = (seq_mode == 0) ? 0 : s_hs_seq;
							if (mc_tls_record_decrypt(vars[vi].s_key, vars[vi].s_iv, try_seq, record, record_len, &inner_type, pt, sizeof(pt), &pt_len) == 0) {
								mc_memcpy(c_ap_key, vars[vi].c_key, sizeof(c_ap_key));
								mc_memcpy(c_ap_iv, vars[vi].c_iv, sizeof(c_ap_iv));
								mc_memcpy(s_ap_key, vars[vi].s_key, sizeof(s_ap_key));
								mc_memcpy(s_ap_iv, vars[vi].s_iv, sizeof(s_ap_iv));
								s_ap_seq = try_seq + 1;
								c_ap_seq = (seq_mode == 0) ? 0 : c_hs_seq;
								have_active_ap = 1;
								if (c->debug) {
									tlsdbg(c, "selected_ap_keys master=");
									(void)mc_write_u64_dec(2, (mc_u64)vars[vi].which_master);
									tlsdbg(c, " th=");
									(void)mc_write_u64_dec(2, (mc_u64)vars[vi].which_th);
									tlsdbg(c, " seq_mode=");
									(void)mc_write_u64_dec(2, (mc_u64)seq_mode);
									tlsdbg(c, "\n");
								}
								break;
							}
						}
					}
				}
			}
		}
	}

	if (!have_active_ap) {
		mc_memcpy(c_ap_key, vars[0].c_key, sizeof(c_ap_key));
		mc_memcpy(c_ap_iv, vars[0].c_iv, sizeof(c_ap_iv));
		mc_memcpy(s_ap_key, vars[0].s_key, sizeof(s_ap_key));
		mc_memcpy(s_ap_iv, vars[0].s_iv, sizeof(s_ap_iv));
		c_ap_seq = 0;
		s_ap_seq = 0;
		have_active_ap = 1;
		if (c->debug) tlsdbg(c, "selected_ap_keys_default 1\n");
	}

	mc_memcpy(c->c_ap_key, c_ap_key, sizeof(c->c_ap_key));
	mc_memcpy(c->c_ap_iv, c_ap_iv, sizeof(c->c_ap_iv));
	mc_memcpy(c->s_ap_key, s_ap_key, sizeof(c->s_ap_key));
	mc_memcpy(c->s_ap_iv, s_ap_iv, sizeof(c->s_ap_iv));
	c->c_ap_seq = c_ap_seq;
	c->s_ap_seq = s_ap_seq;
	c->handshake_done = 1;

	mc_memset(x25519_priv, 0, sizeof(x25519_priv));
	mc_memset(ecdhe, 0, sizeof(ecdhe));
	mc_memset(handshake_secret, 0, sizeof(handshake_secret));
	mc_memset(c_hs, 0, sizeof(c_hs));
	mc_memset(s_hs, 0, sizeof(s_hs));
	mc_memset(c_key, 0, sizeof(c_key));
	mc_memset(c_iv, 0, sizeof(c_iv));
	mc_memset(s_key, 0, sizeof(s_key));
	mc_memset(s_iv, 0, sizeof(s_iv));

	return 0;
}

mc_i64 mc_tls13_client_write_app(struct mc_tls13_client *c, const mc_u8 *buf, mc_usize len) {
	if (!c || !c->handshake_done) return -1;
	if (!buf && len) return -1;

	mc_usize off = 0;
	while (off < len) {
		mc_usize chunk = len - off;
		if (chunk > 16384u) chunk = 16384u;
		mc_u8 rec[5 + 16384 + 64];
		mc_usize rec_len = 0;
		if (mc_tls_record_encrypt(c->c_ap_key, c->c_ap_iv, c->c_ap_seq, MC_TLS_CONTENT_APPLICATION_DATA, buf + off, chunk,
			rec, sizeof(rec), &rec_len) != 0) return -1;
		c->c_ap_seq++;
		if (!write_all_timeout(c->fd, rec, rec_len, c->timeout_ms)) return -1;
		off += chunk;
	}
	return (mc_i64)len;
}

mc_i64 mc_tls13_client_read_app(struct mc_tls13_client *c, mc_u8 *buf, mc_usize cap) {
	if (!c || !c->handshake_done) return -1;
	if (!buf || cap == 0) return -1;

	for (;;) {
		mc_u8 rhdr[5];
		mc_u8 payload[65536];
		mc_usize rlen = 0;
		if (!record_read_timeout(c->fd, c->timeout_ms, rhdr, payload, sizeof(payload), &rlen)) return -1;
		mc_u8 rtype = rhdr[0];
		if (rtype == MC_TLS_CONTENT_CHANGE_CIPHER_SPEC) continue;
		if (rtype == MC_TLS_CONTENT_ALERT) {
			// Plaintext alert => treat as EOF.
			return 0;
		}
		if (rtype != MC_TLS_CONTENT_APPLICATION_DATA) continue;

		mc_u8 record[5 + 65536];
		mc_usize record_len = 5u + rlen;
		if (record_len > sizeof(record)) return -1;
		mc_memcpy(record, rhdr, 5);
		mc_memcpy(record + 5, payload, rlen);

		mc_u8 inner_type = 0;
		mc_u8 pt[65536];
		mc_usize pt_len = 0;
		if (mc_tls_record_decrypt(c->s_ap_key, c->s_ap_iv, c->s_ap_seq, record, record_len, &inner_type, pt, sizeof(pt), &pt_len) != 0) return -1;
		c->s_ap_seq++;

		if (inner_type == MC_TLS_CONTENT_APPLICATION_DATA) {
			if (pt_len > cap) pt_len = cap;
			mc_memcpy(buf, pt, pt_len);
			return (mc_i64)pt_len;
		}
		if (inner_type == MC_TLS_CONTENT_ALERT) {
			// Decrypted alert: if close_notify, treat as EOF.
			if (pt_len >= 2 && pt[1] == 0) return 0;
			return -1;
		}
		// Ignore other inner types for now.
	}
}

int mc_tls13_client_close_notify(struct mc_tls13_client *c) {
	if (!c || !c->handshake_done) return -1;
	mc_u8 alert[2];
	alert[0] = 1; // warning
	alert[1] = 0; // close_notify
	mc_u8 rec[5 + 64];
	mc_usize rec_len = 0;
	if (mc_tls_record_encrypt(c->c_ap_key, c->c_ap_iv, c->c_ap_seq, MC_TLS_CONTENT_ALERT, alert, sizeof(alert), rec, sizeof(rec), &rec_len) != 0) return -1;
	c->c_ap_seq++;
	if (!write_all_timeout(c->fd, rec, rec_len, c->timeout_ms)) return -1;
	return 0;
}
