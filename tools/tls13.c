#include "mc.h"
#include "mc_net.h"
#include "mc_hkdf.h"
#include "mc_sha256.h"
#include "mc_tls13.h"
#include "mc_tls13_handshake.h"
#include "mc_tls13_transcript.h"
#include "mc_tls_record.h"
#include "mc_x25519.h"

// Consolidated TLS 1.3 tool.
// Subcommands:
//   tls13 rec   --smoke
//   tls13 kdf   --rfc8448-1rtt
//   tls13 hello --rfc8448-1rtt
//   tls13 hs    [-W TIMEOUT_MS] [-D DNS_SERVER] [-n SNI] [-p PATH] HOST PORT

static MC_NORETURN void tls13_usage(const char *argv0) {
	mc_die_usage(argv0,
		"tls13 <rec|kdf|hello|hs> ...\n"
		"  tls13 rec   --smoke\n"
		"  tls13 kdf   --rfc8448-1rtt\n"
		"  tls13 hello --rfc8448-1rtt\n"
		"  tls13 hs    [-W TIMEOUT_MS] [-D DNS_SERVER] [-n SNI] [-p PATH] HOST PORT\n"
	);
}

static void hex_encode(const mc_u8 *in, mc_usize in_len, char *out, mc_usize out_cap) {
	const char *hex = "0123456789abcdef";
	if (out_cap < in_len * 2u + 1u) return;
	for (mc_usize i = 0; i < in_len; i++) {
		mc_u8 b = in[i];
		out[i * 2u + 0u] = hex[(b >> 4) & 0xFu];
		out[i * 2u + 1u] = hex[b & 0xFu];
	}
	out[in_len * 2u] = 0;
}

static int bytes_eq(const mc_u8 *a, const mc_u8 *b, mc_usize n) {
	if (!a || !b) return 0;
	return mc_memcmp(a, b, n) == 0;
}

// === tls13 rec ===

static MC_NORETURN void tls13_rec_usage(const char *argv0) {
	mc_die_usage(argv0, "tls13 rec --smoke");
}

static int cmd_rec(int argc, char **argv) {
	const char *argv0 = (argc > 0 && argv && argv[0]) ? argv[0] : "tls13";
	if (argc != 3 || !argv[2]) tls13_rec_usage(argv0);
	if (!mc_streq(argv[2], "--smoke")) tls13_rec_usage(argv0);

	// Deterministic smoke vector to validate:
	// - nonce construction (seq XOR iv)
	// - AAD header formatting
	// - inner plaintext type byte
	const mc_u8 *key = (const mc_u8 *)"\xfe\xff\xe9\x92\x86\x65\x73\x1c\x6d\x6a\x8f\x94\x67\x30\x83\x08";
	const mc_u8 *iv = (const mc_u8 *)"\xca\xfe\xba\xbe\xfa\xce\xdb\xad\xde\xca\xf8\x88";
	const mc_u8 *msg = (const mc_u8 *)"hello";
	mc_usize msg_len = 5u;

	mc_u8 record[256];
	mc_usize record_len = 0;
	mc_u64 seq = 1;
	if (mc_tls_record_encrypt(key, iv, seq, (mc_u8)MC_TLS_CONTENT_HANDSHAKE, msg, msg_len,
		record, sizeof(record), &record_len) != 0) return 1;

	mc_u8 pt[64];
	mc_usize pt_len = 0;
	mc_u8 inner_type = 0;
	if (mc_tls_record_decrypt(key, iv, seq, record, record_len, &inner_type, pt, sizeof(pt), &pt_len) != 0) return 2;
	if (inner_type != (mc_u8)MC_TLS_CONTENT_HANDSHAKE) return 3;
	if (pt_len != msg_len) return 4;
	if (mc_memcmp(pt, msg, pt_len) != 0) return 5;

	// Output record hex for test harness pinning.
	char hex[512];
	hex_encode(record, record_len, hex, sizeof(hex));
	(void)mc_write_str(1, hex);
	(void)mc_write_all(1, "\n", 1);
	return 0;
}

// === tls13 kdf ===

static MC_NORETURN void tls13_kdf_usage(const char *argv0) {
	mc_die_usage(argv0, "tls13 kdf --rfc8448-1rtt");
}

static int emit_line(const char *k, const mc_u8 *v, mc_usize n) {
	char hex[256];
	if (n * 2u + 1u > sizeof(hex)) return -1;
	hex_encode(v, n, hex, sizeof(hex));
	mc_write_str(1, k);
	mc_write_str(1, " ");
	mc_write_str(1, hex);
	mc_write_str(1, "\n");
	return 0;
}

static int cmd_kdf(int argc, char **argv) {
	const char *argv0 = (argc > 0 && argv && argv[0]) ? argv[0] : "tls13";
	if (argc != 3 || !argv[2]) tls13_kdf_usage(argv0);
	if (!mc_streq(argv[2], "--rfc8448-1rtt")) tls13_kdf_usage(argv0);

	// RFC 8448, Section 3 (Simple 1-RTT Handshake) intermediate values.
	// We validate early/derived/handshake secrets, traffic secrets, and handshake keys/IVs.
	mc_u8 zeros32[32];
	mc_memset(zeros32, 0, sizeof(zeros32));
	const mc_u8 *hash_empty = (const mc_u8 *)
		"\xe3\xb0\xc4\x42\x98\xfc\x1c\x14\x9a\xfb\xf4\xc8\x99\x6f\xb9\x24"
		"\x27\xae\x41\xe4\x64\x9b\x93\x4c\xa4\x95\x99\x1b\x78\x52\xb8\x55";
	const mc_u8 *expected_early = (const mc_u8 *)
		"\x33\xad\x0a\x1c\x60\x7e\xc0\x3b\x09\xe6\xcd\x98\x93\x68\x0c\xe2"
		"\x10\xad\xf3\x00\xaa\x1f\x26\x60\xe1\xb2\x2e\x10\xf1\x70\xf9\x2a";
	const mc_u8 *expected_derived = (const mc_u8 *)
		"\x6f\x26\x15\xa1\x08\xc7\x02\xc5\x67\x8f\x54\xfc\x9d\xba\xb6\x97"
		"\x16\xc0\x76\x18\x9c\x48\x25\x0c\xeb\xea\xc3\x57\x6c\x36\x11\xba";
	const mc_u8 *shared_secret = (const mc_u8 *)
		"\x8b\xd4\x05\x4f\xb5\x5b\x9d\x63\xfd\xfb\xac\xf9\xf0\x4b\x9f\x0d"
		"\x35\xe6\xd6\x3f\x53\x75\x63\xef\xd4\x62\x72\x90\x0f\x89\x49\x2d";
	const mc_u8 *expected_handshake = (const mc_u8 *)
		"\x1d\xc8\x26\xe9\x36\x06\xaa\x6f\xdc\x0a\xad\xc1\x2f\x74\x1b\x01"
		"\x04\x6a\xa6\xb9\x9f\x69\x1e\xd2\x21\xa9\xf0\xca\x04\x3f\xbe\xac";
	const mc_u8 *ch_sh_hash = (const mc_u8 *)
		"\x86\x0c\x06\xed\xc0\x78\x58\xee\x8e\x78\xf0\xe7\x42\x8c\x58\xed"
		"\xd6\xb4\x3f\x2c\xa3\xe6\xe9\x5f\x02\xed\x06\x3c\xf0\xe1\xca\xd8";
	const mc_u8 *expected_c_hs = (const mc_u8 *)
		"\xb3\xed\xdb\x12\x6e\x06\x7f\x35\xa7\x80\xb3\xab\xf4\x5e\x2d\x8f"
		"\x3b\x1a\x95\x07\x38\xf5\x2e\x96\x00\x74\x6a\x0e\x27\xa5\x5a\x21";
	const mc_u8 *expected_s_hs = (const mc_u8 *)
		"\xb6\x7b\x7d\x69\x0c\xc1\x6c\x4e\x75\xe5\x42\x13\xcb\x2d\x37\xb4"
		"\xe9\xc9\x12\xbc\xde\xd9\x10\x5d\x42\xbe\xfd\x59\xd3\x91\xad\x38";
	const mc_u8 *expected_s_key = (const mc_u8 *)
		"\x3f\xce\x51\x60\x09\xc2\x17\x27\xd0\xf2\xe4\xe8\x6e\xe4\x03\xbc";
	const mc_u8 *expected_s_iv = (const mc_u8 *)
		"\x5d\x31\x3e\xb2\x67\x12\x76\xee\x13\x00\x0b\x30";
	const mc_u8 *expected_c_key = (const mc_u8 *)
		"\xdb\xfa\xa6\x93\xd1\x76\x2c\x5b\x66\x6a\xf5\xd9\x50\x25\x8d\x01";
	const mc_u8 *expected_c_iv = (const mc_u8 *)
		"\x5b\xd3\xc7\x1b\x83\x6e\x0b\x76\xbb\x73\x26\x5f";

	mc_u8 early[32];
	mc_hkdf_extract(zeros32, sizeof(zeros32), zeros32, sizeof(zeros32), early);
	if (!bytes_eq(early, expected_early, 32)) return 10;

	mc_u8 derived[32];
	if (mc_tls13_derive_secret(early, "derived", hash_empty, derived) != 0) return 11;
	if (!bytes_eq(derived, expected_derived, 32)) return 12;

	mc_u8 handshake[32];
	mc_hkdf_extract(derived, sizeof(derived), shared_secret, 32u, handshake);
	if (!bytes_eq(handshake, expected_handshake, 32)) return 13;

	mc_u8 c_hs[32];
	mc_u8 s_hs[32];
	if (mc_tls13_derive_secret(handshake, "c hs traffic", ch_sh_hash, c_hs) != 0) return 14;
	if (mc_tls13_derive_secret(handshake, "s hs traffic", ch_sh_hash, s_hs) != 0) return 15;
	if (!bytes_eq(c_hs, expected_c_hs, 32)) return 16;
	if (!bytes_eq(s_hs, expected_s_hs, 32)) return 17;

	mc_u8 s_key[16];
	mc_u8 s_iv[12];
	mc_u8 c_key[16];
	mc_u8 c_iv[12];
	if (mc_tls13_hkdf_expand_label(s_hs, "key", MC_NULL, 0, s_key, sizeof(s_key)) != 0) return 18;
	if (mc_tls13_hkdf_expand_label(s_hs, "iv", MC_NULL, 0, s_iv, sizeof(s_iv)) != 0) return 19;
	if (mc_tls13_hkdf_expand_label(c_hs, "key", MC_NULL, 0, c_key, sizeof(c_key)) != 0) return 20;
	if (mc_tls13_hkdf_expand_label(c_hs, "iv", MC_NULL, 0, c_iv, sizeof(c_iv)) != 0) return 21;
	if (!bytes_eq(s_key, expected_s_key, 16)) return 22;
	if (!bytes_eq(s_iv, expected_s_iv, 12)) return 23;
	if (!bytes_eq(c_key, expected_c_key, 16)) return 24;
	if (!bytes_eq(c_iv, expected_c_iv, 12)) return 25;

	// Print stable output (useful for debugging and smoke tests).
	if (emit_line("early", early, 32) != 0) return 30;
	if (emit_line("derived", derived, 32) != 0) return 31;
	if (emit_line("handshake", handshake, 32) != 0) return 32;
	if (emit_line("c_hs", c_hs, 32) != 0) return 33;
	if (emit_line("s_hs", s_hs, 32) != 0) return 34;
	if (emit_line("c_key", c_key, 16) != 0) return 35;
	if (emit_line("c_iv", c_iv, 12) != 0) return 36;
	if (emit_line("s_key", s_key, 16) != 0) return 37;
	if (emit_line("s_iv", s_iv, 12) != 0) return 38;

	return 0;
}

// === tls13 hello ===

static MC_NORETURN void tls13_hello_usage(const char *argv0) {
	mc_die_usage(argv0, "tls13 hello --rfc8448-1rtt");
}

static mc_u8 hex_val(mc_u8 c) {
	if (c >= (mc_u8)'0' && c <= (mc_u8)'9') return (mc_u8)(c - (mc_u8)'0');
	c = mc_tolower_ascii(c);
	if (c >= (mc_u8)'a' && c <= (mc_u8)'f') return (mc_u8)(10 + (c - (mc_u8)'a'));
	return 0xff;
}

static int hex_decode(const char *s, mc_u8 *out, mc_usize out_cap, mc_usize *out_len) {
	if (!s || !out_len) return -1;
	mc_usize n = 0;
	mc_u8 hi = 0xff;
	for (mc_usize i = 0; s[i]; i++) {
		mc_u8 c = (mc_u8)s[i];
		if (mc_is_space_ascii(c)) continue;
		mc_u8 v = hex_val(c);
		if (v == 0xff) return -1;
		if (hi == 0xff) {
			hi = v;
		} else {
			if (n >= out_cap) return -1;
			out[n++] = (mc_u8)((hi << 4) | v);
			hi = 0xff;
		}
	}
	if (hi != 0xff) return -1;
	*out_len = n;
	return 0;
}

static int cmd_hello(int argc, char **argv) {
	const char *argv0 = (argc > 0 && argv && argv[0]) ? argv[0] : "tls13";
	if (argc != 3 || !argv[2]) tls13_hello_usage(argv0);
	if (!mc_streq(argv[2], "--rfc8448-1rtt")) tls13_hello_usage(argv0);

	// RFC 8448, Section 3 handshake messages (handshake header included).
	const char *rfc_ch_hex =
		"01 00 00 c0 03 03 cb 34 ec b1 e7 81 63"
		" ba 1c 38 c6 da cb 19 6a 6d ff a2 1a 8d 99 12 ec 18 a2 ef 62 83"
		" 02 4d ec e7 00 00 06 13 01 13 03 13 02 01 00 00 91 00 00 00 0b"
		" 00 09 00 00 06 73 65 72 76 65 72 ff 01 00 01 00 00 0a 00 14 00"
		" 12 00 1d 00 17 00 18 00 19 01 00 01 01 01 02 01 03 01 04 00 23"
		" 00 00 00 33 00 26 00 24 00 1d 00 20 99 38 1d e5 60 e4 bd 43 d2"
		" 3d 8e 43 5a 7d ba fe b3 c0 6e 51 c1 3c ae 4d 54 13 69 1e 52 9a"
		" af 2c 00 2b 00 03 02 03 04 00 0d 00 20 00 1e 04 03 05 03 06 03"
		" 02 03 08 04 08 05 08 06 04 01 05 01 06 01 02 01 04 02 05 02 06"
		" 02 02 02 00 2d 00 02 01 01 00 1c 00 02 40 01";

	const char *rfc_sh_hex =
		"02 00 00 56 03 03 a6 af 06 a4 12 18 60"
		" dc 5e 6e 60 24 9c d3 4c 95 93 0c 8a c5 cb 14 34 da c1 55 77 2e"
		" d3 e2 69 28 00 13 01 00 00 2e 00 33 00 24 00 1d 00 20 c9 82 88"
		" 76 11 20 95 fe 66 76 2b db f7 c6 72 e1 56 d6 cc 25 3b 83 3d f1"
		" dd 69 b1 b0 4e 75 1f 0f 00 2b 00 02 03 04";

	mc_u8 ch[256];
	mc_usize ch_len = 0;
	mc_u8 sh[256];
	mc_usize sh_len = 0;
	if (hex_decode(rfc_ch_hex, ch, sizeof(ch), &ch_len) != 0) return 10;
	if (hex_decode(rfc_sh_hex, sh, sizeof(sh), &sh_len) != 0) return 11;
	if (ch_len != 196u) return 12;
	if (sh_len != 90u) return 13;

	// Validate our ClientHello builder produces the exact RFC bytes.
	const mc_u8 *rfc_random = (const mc_u8 *)
		"\xcb\x34\xec\xb1\xe7\x81\x63\xba\x1c\x38\xc6\xda\xcb\x19\x6a\x6d"
		"\xff\xa2\x1a\x8d\x99\x12\xec\x18\xa2\xef\x62\x83\x02\x4d\xec\xe7";
	const mc_u8 *rfc_pub = (const mc_u8 *)
		"\x99\x38\x1d\xe5\x60\xe4\xbd\x43\xd2\x3d\x8e\x43\x5a\x7d\xba\xfe"
		"\xb3\xc0\x6e\x51\xc1\x3c\xae\x4d\x54\x13\x69\x1e\x52\x9a\xaf\x2c";
	mc_u8 built[256];
	mc_usize built_len = 0;
	if (mc_tls13_build_client_hello_rfc8448_1rtt(rfc_random, rfc_pub, built, sizeof(built), &built_len) != 0) return 20;
	if (built_len != ch_len) return 21;
	if (mc_memcmp(built, ch, ch_len) != 0) return 22;

	// Parse ServerHello and validate extensions.
	struct mc_tls13_server_hello parsed;
	if (mc_tls13_parse_server_hello(sh, sh_len, &parsed) != 0) return 30;
	if (parsed.selected_version != 0x0304) return 31;
	if (parsed.key_share_group != MC_TLS13_GROUP_X25519) return 32;
	if (parsed.key_share_len != 32) return 33;

	// Transcript hash of ClientHello || ServerHello.
	struct mc_tls13_transcript t;
	mc_tls13_transcript_init(&t);
	mc_tls13_transcript_update(&t, ch, ch_len);
	mc_tls13_transcript_update(&t, sh, sh_len);
	mc_u8 hash[32];
	mc_tls13_transcript_final(&t, hash);

	const mc_u8 *expected_hash = (const mc_u8 *)
		"\x86\x0c\x06\xed\xc0\x78\x58\xee\x8e\x78\xf0\xe7\x42\x8c\x58\xed"
		"\xd6\xb4\x3f\x2c\xa3\xe6\xe9\x5f\x02\xed\x06\x3c\xf0\xe1\xca\xd8";
	if (mc_memcmp(hash, expected_hash, 32) != 0) return 40;

	char hex[128];
	hex_encode(hash, 32, hex, sizeof(hex));
	mc_write_str(1, "chsh_hash ");
	mc_write_str(1, hex);
	mc_write_str(1, "\n");
	return 0;
}

// === tls13 hs (live handshake + simple HTTPS GET) ===

static mc_u16 mc_bswap16(mc_u16 x) {
	return (mc_u16)((mc_u16)(x << 8) | (mc_u16)(x >> 8));
}

static mc_u16 mc_htons(mc_u16 x) {
	return mc_bswap16(x);
}

static int mc_hexval(mc_u8 c) {
	if (c >= (mc_u8)'0' && c <= (mc_u8)'9') return (int)(c - (mc_u8)'0');
	if (c >= (mc_u8)'a' && c <= (mc_u8)'f') return 10 + (int)(c - (mc_u8)'a');
	if (c >= (mc_u8)'A' && c <= (mc_u8)'F') return 10 + (int)(c - (mc_u8)'A');
	return -1;
}

// Strict IPv6 literal parser.
// Supports :: compression. No IPv4-embedded form. No zone index (%eth0).
static int parse_ipv6_literal(const char *s, mc_u8 out[16]) {
	if (!s || !*s) return 0;
	for (const char *p = s; *p; p++) {
		if (*p == '%') return 0;
	}

	mc_u16 words[8];
	for (int i = 0; i < 8; i++) words[i] = 0;
	int nwords = 0;
	int compress_at = -1;

	const char *p = s;
	if (*p == ':') {
		p++;
		if (*p != ':') return 0;
		compress_at = 0;
		p++;
	}

	while (*p) {
		if (nwords >= 8) return 0;

		mc_u32 v = 0;
		int nd = 0;
		while (*p) {
			int hv = mc_hexval((mc_u8)*p);
			if (hv < 0) break;
			v = (v << 4) | (mc_u32)hv;
			nd++;
			if (nd > 4) return 0;
			p++;
		}
		if (nd == 0) return 0;
		words[nwords++] = (mc_u16)v;

		if (*p == 0) break;
		if (*p != ':') return 0;
		p++;
		if (*p == 0) return 0;
		if (*p == ':') {
			if (compress_at >= 0) return 0;
			compress_at = nwords;
			p++;
			if (*p == 0) break;
		}
	}

	if (compress_at >= 0) {
		int zeros = 8 - nwords;
		if (zeros < 0) return 0;
		for (int i = nwords - 1; i >= compress_at; i--) {
			words[i + zeros] = words[i];
		}
		for (int i = 0; i < zeros; i++) {
			words[compress_at + i] = 0;
		}
		nwords = 8;
	}

	if (nwords != 8) return 0;

	for (int i = 0; i < 8; i++) {
		out[i * 2 + 0] = (mc_u8)((words[i] >> 8) & 0xFFu);
		out[i * 2 + 1] = (mc_u8)(words[i] & 0xFFu);
	}
	return 1;
}

static int resolv_conf_pick_v6(mc_u8 out_server[16]) {
	mc_i64 fd = mc_sys_openat(MC_AT_FDCWD, "/etc/resolv.conf", MC_O_RDONLY | MC_O_CLOEXEC, 0);
	if (fd < 0) return 0;

	char buf[4096];
	mc_i64 n = mc_sys_read((mc_i32)fd, buf, sizeof(buf) - 1);
	(void)mc_sys_close((mc_i32)fd);
	if (n <= 0) return 0;
	buf[(mc_usize)n] = 0;

	const char *p = buf;
	while (*p) {
		const char *line = p;
		while (*p && *p != '\n') p++;
		const char *end = p;
		if (*p == '\n') p++;

		while (line < end && (*line == ' ' || *line == '\t')) line++;
		if (line >= end || *line == '#') continue;

		const char *kw = "nameserver";
		mc_usize kwlen = 10;
		if ((mc_usize)(end - line) < kwlen) continue;
		int ok = 1;
		for (mc_usize i = 0; i < kwlen; i++) {
			if (line[i] != kw[i]) {
				ok = 0;
				break;
			}
		}
		if (!ok) continue;
		const char *q = line + kwlen;
		if (q >= end || !(*q == ' ' || *q == '\t')) continue;
		while (q < end && (*q == ' ' || *q == '\t')) q++;
		if (q >= end) continue;

		const char *tok = q;
		while (q < end && !(*q == ' ' || *q == '\t' || *q == '#')) q++;
		mc_usize tlen = (mc_usize)(q - tok);
		if (tlen == 0 || tlen >= 128) continue;
		char tmp[128];
		for (mc_usize i = 0; i < tlen; i++) tmp[i] = tok[i];
		tmp[tlen] = 0;
		if (parse_ipv6_literal(tmp, out_server)) return 1;
	}

	return 0;
}

static mc_u16 dns_pick_id(void) {
	mc_u16 id = 0;
	mc_i64 r = mc_sys_getrandom(&id, sizeof(id), 0);
	if (r == (mc_i64)sizeof(id) && id != 0) return id;

	struct mc_timespec ts;
	(void)mc_sys_clock_gettime(MC_CLOCK_MONOTONIC, &ts);
	mc_u64 mix = (mc_u64)ts.tv_nsec ^ ((mc_u64)ts.tv_sec << 32) ^ (mc_u64)(mc_usize)(void *)&id;
	id = (mc_u16)(mix & 0xFFFFu);
	if (id == 0) id = 1;
	return id;
}

static int dns_encode_qname(mc_u8 *dst, mc_usize cap, const char *name, mc_usize *io_off) {
	mc_usize off = *io_off;
	const char *p = name;
	while (*p) {
		const char *label = p;
		mc_usize len = 0;
		while (*p && *p != '.') {
			len++;
			p++;
			if (len > 63) return 0;
		}
		if (off + 1 + len >= cap) return 0;
		dst[off++] = (mc_u8)len;
		for (mc_usize i = 0; i < len; i++) dst[off++] = (mc_u8)label[i];
		if (*p == '.') p++;
	}
	if (off + 1 > cap) return 0;
	dst[off++] = 0;
	*io_off = off;
	return 1;
}

static int dns_name_skip(const mc_u8 *msg, mc_usize msglen, mc_usize off, mc_usize *out_off) {
	mc_usize o = off;
	for (;;) {
		if (o >= msglen) return 0;
		mc_u8 len = msg[o++];
		if (len == 0) {
			*out_off = o;
			return 1;
		}
		if ((len & 0xC0u) == 0xC0u) {
			if (o >= msglen) return 0;
			o++;
			*out_off = o;
			return 1;
		}
		if (len > 63) return 0;
		if (o + len > msglen) return 0;
		o += len;
	}
}

static int dns6_resolve_first_aaaa(const char *argv0, const mc_u8 server_ip[16], mc_u16 server_port, const char *name, mc_u32 timeout_ms,
	mc_u8 out_ip[16]) {
	struct mc_sockaddr_in6 sa;
	mc_memset(&sa, 0, sizeof(sa));
	sa.sin6_family = (mc_u16)MC_AF_INET6;
	sa.sin6_port = mc_htons(server_port);
	for (int i = 0; i < 16; i++) sa.sin6_addr.s6_addr[i] = server_ip[i];

	for (int attempt = 0; attempt < 2; attempt++) {
		int use_tcp = (attempt == 1);
		mc_i32 stype = use_tcp ? MC_SOCK_STREAM : MC_SOCK_DGRAM;
		mc_i32 proto = use_tcp ? MC_IPPROTO_TCP : MC_IPPROTO_UDP;

		mc_i64 fd = mc_sys_socket(MC_AF_INET6, stype | MC_SOCK_CLOEXEC, proto);
		if (fd < 0) mc_die_errno(argv0, "socket", fd);

		mc_i64 r = mc_sys_connect((mc_i32)fd, &sa, (mc_u32)sizeof(sa));
		if (r < 0) {
			(void)mc_sys_close((mc_i32)fd);
			return 0;
		}

		mc_u8 q[512];
		mc_usize qn = 12;
		mc_u16 id = dns_pick_id();
		q[0] = (mc_u8)(id >> 8);
		q[1] = (mc_u8)(id & 0xFFu);
		q[2] = 0x01;
		q[3] = 0x00;
		q[4] = 0;
		q[5] = 1;
		q[6] = 0;
		q[7] = 0;
		q[8] = 0;
		q[9] = 0;
		q[10] = 0;
		q[11] = 0;

		if (!dns_encode_qname(q, sizeof(q), name, &qn)) {
			(void)mc_sys_close((mc_i32)fd);
			return 0;
		}
		if (qn + 4 > sizeof(q)) {
			(void)mc_sys_close((mc_i32)fd);
			return 0;
		}
		q[qn++] = 0x00;
		q[qn++] = 0x1c;
		q[qn++] = 0x00;
		q[qn++] = 0x01;

		mc_u8 tcpbuf[2 + sizeof(q)];
		const void *sendbuf = q;
		mc_usize sendlen = qn;
		if (use_tcp) {
			tcpbuf[0] = (mc_u8)((qn >> 8) & 0xFFu);
			tcpbuf[1] = (mc_u8)(qn & 0xFFu);
			for (mc_usize i = 0; i < qn; i++) tcpbuf[2 + i] = q[i];
			sendbuf = tcpbuf;
			sendlen = 2 + qn;
		}

		r = mc_write_all((mc_i32)fd, sendbuf, sendlen);
		if (r < 0) {
			(void)mc_sys_close((mc_i32)fd);
			return 0;
		}

		mc_u8 resp[1024];
		mc_usize rn = 0;
		if (use_tcp) {
			struct mc_pollfd pfd;
			pfd.fd = (mc_i32)fd;
			pfd.events = MC_POLLIN;
			pfd.revents = 0;
			mc_i64 pr = mc_sys_poll(&pfd, 1, (mc_i32)timeout_ms);
			if (pr <= 0 || (pfd.revents & MC_POLLIN) == 0) {
				(void)mc_sys_close((mc_i32)fd);
				return 0;
			}

			mc_u8 len2[2];
			mc_i64 rr = mc_sys_read((mc_i32)fd, len2, 2);
			if (rr != 2) {
				(void)mc_sys_close((mc_i32)fd);
				return 0;
			}
			mc_u16 mlen = (mc_u16)(((mc_u16)len2[0] << 8) | (mc_u16)len2[1]);
			if (mlen > sizeof(resp)) {
				(void)mc_sys_close((mc_i32)fd);
				return 0;
			}
			rr = mc_sys_read((mc_i32)fd, resp, mlen);
			(void)mc_sys_close((mc_i32)fd);
			if (rr != (mc_i64)mlen) return 0;
			rn = (mc_usize)rr;
		} else {
			struct mc_pollfd pfd;
			pfd.fd = (mc_i32)fd;
			pfd.events = MC_POLLIN;
			pfd.revents = 0;
			mc_i64 pr = mc_sys_poll(&pfd, 1, (mc_i32)timeout_ms);
			if (pr <= 0 || (pfd.revents & MC_POLLIN) == 0) {
				(void)mc_sys_close((mc_i32)fd);
				return 0;
			}

			mc_i64 rr = mc_sys_read((mc_i32)fd, resp, sizeof(resp));
			(void)mc_sys_close((mc_i32)fd);
			if (rr <= 0) return 0;
			rn = (mc_usize)rr;
		}

		if (rn < 12) return 0;
		if (resp[0] != (mc_u8)(id >> 8) || resp[1] != (mc_u8)(id & 0xFFu)) return 0;
		mc_u16 flags = (mc_u16)(((mc_u16)resp[2] << 8) | (mc_u16)resp[3]);
		if ((flags & 0x8000u) == 0) return 0;
		mc_u16 qd = (mc_u16)(((mc_u16)resp[4] << 8) | (mc_u16)resp[5]);
		mc_u16 an = (mc_u16)(((mc_u16)resp[6] << 8) | (mc_u16)resp[7]);
		if (qd != 1 || an == 0) return 0;

		mc_usize off = 12;
		mc_usize noff = 0;
		if (!dns_name_skip(resp, rn, off, &noff)) return 0;
		off = noff;
		if (off + 4 > rn) return 0;
		off += 4; // qtype+qclass

		for (mc_u16 i = 0; i < an; i++) {
			if (!dns_name_skip(resp, rn, off, &noff)) return 0;
			off = noff;
			if (off + 10 > rn) return 0;
			mc_u16 atype = (mc_u16)(((mc_u16)resp[off] << 8) | (mc_u16)resp[off + 1]);
			mc_u16 aclass = (mc_u16)(((mc_u16)resp[off + 2] << 8) | (mc_u16)resp[off + 3]);
			mc_u16 rdlen = (mc_u16)(((mc_u16)resp[off + 8] << 8) | (mc_u16)resp[off + 9]);
			off += 10;
			if (off + rdlen > rn) return 0;
			if (atype == 0x001cu && aclass == 0x0001u && rdlen == 16) {
				mc_memcpy(out_ip, resp + off, 16);
				return 1;
			}
			off += rdlen;
		}

		return 0;
	}

	return 0;
}

static int set_nonblock(mc_i32 fd, int enabled) {
	mc_i64 fl = mc_sys_fcntl(fd, MC_F_GETFL, 0);
	if (fl < 0) return 0;
	if (enabled) fl |= MC_O_NONBLOCK;
	else fl &= ~((mc_i64)MC_O_NONBLOCK);
	mc_i64 r = mc_sys_fcntl(fd, MC_F_SETFL, fl);
	return r >= 0;
}

static int connect_with_timeout(const char *argv0, mc_i32 fd, const void *sa, mc_u32 salen, mc_u32 timeout_ms) {
	if (timeout_ms == 0) {
		mc_i64 r = mc_sys_connect(fd, sa, salen);
		return r >= 0;
	}

	if (!set_nonblock(fd, 1)) return 0;
	mc_i64 r = mc_sys_connect(fd, sa, salen);
	if (r >= 0) {
		(void)set_nonblock(fd, 0);
		return 1;
	}
	if (r != (mc_i64)-MC_EINPROGRESS) {
		(void)set_nonblock(fd, 0);
		return 0;
	}

	struct mc_pollfd pfd;
	pfd.fd = fd;
	pfd.events = MC_POLLOUT;
	pfd.revents = 0;
	mc_i64 pr = mc_sys_poll(&pfd, 1, (mc_i32)timeout_ms);
	if (pr <= 0 || (pfd.revents & MC_POLLOUT) == 0) {
		(void)set_nonblock(fd, 0);
		return 0;
	}

	mc_i32 err = 0;
	mc_u32 errlen = (mc_u32)sizeof(err);
	r = mc_sys_getsockopt(fd, MC_SOL_SOCKET, MC_SO_ERROR, &err, &errlen);
	(void)set_nonblock(fd, 0);
	if (r < 0) return 0;
	if (err != 0) return 0;
	return 1;
}

static int poll_in(mc_i32 fd, mc_u32 timeout_ms) {
	struct mc_pollfd pfd;
	pfd.fd = fd;
	pfd.events = MC_POLLIN;
	pfd.revents = 0;
	mc_i64 pr = mc_sys_poll(&pfd, 1, (mc_i32)timeout_ms);
	if (pr <= 0) return 0;
	if ((pfd.revents & MC_POLLIN) == 0) return 0;
	return 1;
}

static int read_exact_timeout(mc_i32 fd, void *buf, mc_usize len, mc_u32 timeout_ms) {
	mc_u8 *p = (mc_u8 *)buf;
	mc_usize got = 0;
	while (got < len) {
		if (!poll_in(fd, timeout_ms)) return 0;
		mc_i64 r = mc_sys_read(fd, p + got, len - got);
		if (r < 0) return 0;
		if (r == 0) return 0;
		got += (mc_usize)r;
	}
	return 1;
}

static void write_hex_bytes(mc_i32 fd, const mc_u8 *p, mc_usize n) {
	const char *hex = "0123456789abcdef";
	char out[2];
	for (mc_usize i = 0; i < n; i++) {
		out[0] = hex[(p[i] >> 4) & 0xF];
		out[1] = hex[p[i] & 0xF];
		(void)mc_write_all(fd, out, 2);
	}
}

static void getrandom_or_die(const char *argv0, void *buf, mc_usize len) {
	mc_u8 *p = (mc_u8 *)buf;
	mc_usize off = 0;
	while (off < len) {
		mc_i64 r = mc_sys_getrandom(p + off, len - off, 0);
		if (r < 0) mc_die_errno(argv0, "getrandom", r);
		if (r == 0) mc_die_errno(argv0, "getrandom", (mc_i64)-MC_EINVAL);
		off += (mc_usize)r;
	}
}

static const mc_u8 *sha256_empty_hs_ptr(void) {
	return (const mc_u8 *)
		"\xe3\xb0\xc4\x42\x98\xfc\x1c\x14\x9a\xfb\xf4\xc8\x99\x6f\xb9\x24"
		"\x27\xae\x41\xe4\x64\x9b\x93\x4c\xa4\x95\x99\x1b\x78\x52\xb8\x55";
}

struct ap_variant {
	mc_u8 c_key[16];
	mc_u8 c_iv[12];
	mc_u8 s_key[16];
	mc_u8 s_iv[12];
	mc_u8 which_master;
	mc_u8 which_th;
};

#define MC_TLS13_HS_ENCRYPTED_EXTENSIONS 8
#define MC_TLS13_HS_CERTIFICATE 11
#define MC_TLS13_HS_CERTIFICATE_VERIFY 15
#define MC_TLS13_HS_FINISHED 20

static int record_read(mc_i32 fd, mc_u32 timeout_ms, mc_u8 hdr[5], mc_u8 *payload, mc_usize payload_cap, mc_usize *out_len) {
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
	if (*io_len < 4u) return 1; // need more
	mc_u8 ht = buf[0];
	mc_u32 hl = ((mc_u32)buf[1] << 16) | ((mc_u32)buf[2] << 8) | (mc_u32)buf[3];
	mc_usize total = 4u + (mc_usize)hl;
	if (total > *io_len) return 1; // need more
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

static MC_NORETURN void tls13_hs_usage(const char *argv0) {
	mc_die_usage(argv0,
		"tls13 hs [-W TIMEOUT_MS] [-D DNS_SERVER] [-n SNI] [-p PATH] HOST PORT\n"
		"  HOST: IPv6 literal or hostname (AAAA)\n"
		"  PORT: usually 443\n"
	);
}

static int cmd_hs(int argc, char **argv, char **envp) {
	(void)envp;
	const char *argv0 = (argc > 0 && argv && argv[0]) ? argv[0] : "tls13";

	mc_u32 timeout_ms = 5000;
	const char *sni = 0;
	const char *path = "/";

	mc_u8 dns_server[16];
	int have_dns_server = 0;

	int i = 2;
	for (; i < argc; i++) {
		const char *a = argv[i];
		if (!a) break;
		if (mc_streq(a, "--")) {
			i++;
			break;
		}
		if (mc_streq(a, "-W")) {
			i++;
			if (i >= argc) tls13_hs_usage(argv0);
			mc_u32 v = 0;
			if (mc_parse_u32_dec(argv[i], &v) != 0) tls13_hs_usage(argv0);
			timeout_ms = v;
			continue;
		}
		if (mc_streq(a, "-D")) {
			i++;
			if (i >= argc) tls13_hs_usage(argv0);
			if (!parse_ipv6_literal(argv[i], dns_server)) tls13_hs_usage(argv0);
			have_dns_server = 1;
			continue;
		}
		if (mc_streq(a, "-n")) {
			i++;
			if (i >= argc) tls13_hs_usage(argv0);
			sni = argv[i];
			continue;
		}
		if (mc_streq(a, "-p")) {
			i++;
			if (i >= argc) tls13_hs_usage(argv0);
			path = argv[i];
			continue;
		}
		if (a[0] == '-' && a[1] != 0) tls13_hs_usage(argv0);
		break;
	}

	if (i + 2 != argc) tls13_hs_usage(argv0);
	const char *host = argv[i];
	mc_u32 pv = 0;
	if (mc_parse_u32_dec(argv[i + 1], &pv) != 0 || pv == 0 || pv > 65535u) tls13_hs_usage(argv0);
	mc_u16 port = (mc_u16)pv;

	if (!sni) sni = host;
	mc_usize sni_len = mc_strlen(sni);
	if (sni_len == 0 || sni_len > 255u) tls13_hs_usage(argv0);
	mc_usize path_len = mc_strlen(path);
	if (path_len == 0 || path[0] != '/' || path_len > 2048u) tls13_hs_usage(argv0);

	mc_u8 dst_ip[16];
	if (!parse_ipv6_literal(host, dst_ip)) {
		if (!have_dns_server) {
			if (!resolv_conf_pick_v6(dns_server)) {
				(void)parse_ipv6_literal("2001:4860:4860::8888", dns_server);
			}
			have_dns_server = 1;
		}
		if (!dns6_resolve_first_aaaa(argv0, dns_server, 53, host, timeout_ms, dst_ip)) {
			mc_u8 dns2[16];
			(void)parse_ipv6_literal("2001:4860:4860::8844", dns2);
			if (!dns6_resolve_first_aaaa(argv0, dns2, 53, host, timeout_ms, dst_ip)) {
				(void)mc_write_str(2, argv0);
				(void)mc_write_str(2, ": resolve failed\n");
				return 1;
			}
		}
	}

	struct mc_sockaddr_in6 dst;
	mc_memset(&dst, 0, sizeof(dst));
	dst.sin6_family = (mc_u16)MC_AF_INET6;
	dst.sin6_port = mc_htons(port);
	for (int k = 0; k < 16; k++) dst.sin6_addr.s6_addr[k] = dst_ip[k];

	mc_i64 fd = mc_sys_socket(MC_AF_INET6, MC_SOCK_STREAM | MC_SOCK_CLOEXEC, MC_IPPROTO_TCP);
	if (fd < 0) mc_die_errno(argv0, "socket", fd);

	if (!connect_with_timeout(argv0, (mc_i32)fd, &dst, (mc_u32)sizeof(dst), timeout_ms)) {
		mc_print_errno(argv0, "connect", (mc_i64)-MC_ETIMEDOUT);
		(void)mc_sys_close((mc_i32)fd);
		return 1;
	}

	// Build ClientHello
	mc_u8 ch_random[32];
	mc_u8 ch_sid[32];
	mc_u8 x25519_priv[32];
	mc_u8 x25519_pub[32];
	getrandom_or_die(argv0, ch_random, sizeof(ch_random));
	getrandom_or_die(argv0, ch_sid, sizeof(ch_sid));
	getrandom_or_die(argv0, x25519_priv, sizeof(x25519_priv));
	mc_x25519_public(x25519_pub, x25519_priv);

	mc_u8 ch[2048];
	mc_usize ch_len = 0;
	if (mc_tls13_build_client_hello(sni, sni_len, ch_random, ch_sid, sizeof(ch_sid), x25519_pub, ch, sizeof(ch), &ch_len) != 0) {
		(void)mc_write_str(2, argv0);
		(void)mc_write_str(2, ": ClientHello build failed\n");
		(void)mc_sys_close((mc_i32)fd);
		return 1;
	}

	// TLSPlaintext record wrapping the handshake message.
	mc_u8 rec[5 + 2048];
	if (ch_len > 2048) {
		(void)mc_sys_close((mc_i32)fd);
		return 1;
	}
	rec[0] = 22; // handshake
	rec[1] = 0x03;
	rec[2] = 0x01; // legacy_record_version
	rec[3] = (mc_u8)((ch_len >> 8) & 0xFFu);
	rec[4] = (mc_u8)(ch_len & 0xFFu);
	mc_memcpy(rec + 5, ch, ch_len);

	mc_i64 wr = mc_write_all((mc_i32)fd, rec, 5 + ch_len);
	if (wr < 0) mc_die_errno(argv0, "write", wr);

	// Read records until we see ServerHello.
	mc_u8 rhdr[5];
	mc_u8 payload[65536];
	mc_u8 sh_msg[2048];
	mc_usize sh_len = 0;
	int got_sh = 0;

	for (int iter = 0; iter < 32; iter++) {
		if (!read_exact_timeout((mc_i32)fd, rhdr, 5, timeout_ms)) break;
		mc_u8 rtype = rhdr[0];
		mc_u16 rlen = (mc_u16)(((mc_u16)rhdr[3] << 8) | (mc_u16)rhdr[4]);
		if (rlen > sizeof(payload)) break;
		if (!read_exact_timeout((mc_i32)fd, payload, (mc_usize)rlen, timeout_ms)) break;

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

	if (!got_sh) {
		(void)mc_write_str(2, argv0);
		(void)mc_write_str(2, ": did not receive ServerHello\n");
		(void)mc_sys_close((mc_i32)fd);
		return 1;
	}

	struct mc_tls13_server_hello sh;
	if (mc_tls13_parse_server_hello(sh_msg, sh_len, &sh) != 0) {
		(void)mc_write_str(2, argv0);
		(void)mc_write_str(2, ": ServerHello parse failed\n");
		return 1;
	}

	struct mc_tls13_transcript t;
	mc_tls13_transcript_init(&t);
	mc_tls13_transcript_update(&t, ch, ch_len);
	mc_tls13_transcript_update(&t, sh_msg, sh_len);
	mc_u8 chsh_hash[32];
	mc_tls13_transcript_final(&t, chsh_hash);

	if (sh.key_share_group != MC_TLS13_GROUP_X25519 || sh.key_share_len != 32) {
		(void)mc_write_str(2, argv0);
		(void)mc_write_str(2, ": unsupported server key_share\n");
		(void)mc_sys_close((mc_i32)fd);
		return 1;
	}
	if (sh.selected_version != 0x0304) {
		(void)mc_write_str(2, argv0);
		(void)mc_write_str(2, ": server did not select TLS 1.3\n");
		(void)mc_sys_close((mc_i32)fd);
		return 1;
	}

	mc_u8 ecdhe[32];
	if (mc_x25519_shared(ecdhe, x25519_priv, sh.key_share) != 0) {
		(void)mc_write_str(2, argv0);
		(void)mc_write_str(2, ": x25519_shared failed\n");
		(void)mc_sys_close((mc_i32)fd);
		return 1;
	}

	mc_u8 early[32];
	mc_u8 zeros32[32];
	mc_memset(zeros32, 0, sizeof(zeros32));
	mc_hkdf_extract(zeros32, sizeof(zeros32), zeros32, sizeof(zeros32), early);

	mc_u8 derived[32];
	if (mc_tls13_derive_secret(early, "derived", sha256_empty_hs_ptr(), derived) != 0) {
		(void)mc_sys_close((mc_i32)fd);
		return 1;
	}

	mc_u8 handshake_secret[32];
	mc_hkdf_extract(derived, sizeof(derived), ecdhe, sizeof(ecdhe), handshake_secret);

	mc_u8 c_hs[32];
	mc_u8 s_hs[32];
	if (mc_tls13_derive_secret(handshake_secret, "c hs traffic", chsh_hash, c_hs) != 0) {
		(void)mc_sys_close((mc_i32)fd);
		return 1;
	}
	if (mc_tls13_derive_secret(handshake_secret, "s hs traffic", chsh_hash, s_hs) != 0) {
		(void)mc_sys_close((mc_i32)fd);
		return 1;
	}

	mc_u8 c_key[16];
	mc_u8 c_iv[12];
	if (mc_tls13_hkdf_expand_label(c_hs, "key", MC_NULL, 0, c_key, sizeof(c_key)) != 0) {
		(void)mc_sys_close((mc_i32)fd);
		return 1;
	}
	if (mc_tls13_hkdf_expand_label(c_hs, "iv", MC_NULL, 0, c_iv, sizeof(c_iv)) != 0) {
		(void)mc_sys_close((mc_i32)fd);
		return 1;
	}

	mc_u8 s_key[16];
	mc_u8 s_iv[12];
	if (mc_tls13_hkdf_expand_label(s_hs, "key", MC_NULL, 0, s_key, sizeof(s_key)) != 0) {
		(void)mc_sys_close((mc_i32)fd);
		return 1;
	}
	if (mc_tls13_hkdf_expand_label(s_hs, "iv", MC_NULL, 0, s_iv, sizeof(s_iv)) != 0) {
		(void)mc_sys_close((mc_i32)fd);
		return 1;
	}

	mc_u64 s_hs_seq = 0;
	mc_u64 c_hs_seq = 0;
	int verified_server_finished = 0;

	mc_u8 hs_buf[131072];
	mc_usize hs_buf_len = 0;

	for (int iter = 0; iter < 256; iter++) {
		mc_usize rlen = 0;
		if (!record_read((mc_i32)fd, timeout_ms, rhdr, payload, sizeof(payload), &rlen)) {
			break;
		}
		mc_u8 rtype = rhdr[0];
		if (rtype == MC_TLS_CONTENT_CHANGE_CIPHER_SPEC) continue;
		if (rtype == MC_TLS_CONTENT_ALERT) {
			(void)mc_write_str(2, argv0);
			(void)mc_write_str(2, ": got alert\n");
			break;
		}
		if (rtype != MC_TLS_CONTENT_APPLICATION_DATA) continue;

		mc_u8 record[5 + 65536];
		mc_usize record_len = 5u + rlen;
		if (record_len > sizeof(record)) break;
		mc_memcpy(record, rhdr, 5);
		mc_memcpy(record + 5, payload, rlen);

		mc_u8 inner_type = 0;
		mc_u8 pt[65536];
		mc_usize pt_len = 0;
		if (mc_tls_record_decrypt(s_key, s_iv, s_hs_seq, record, record_len, &inner_type, pt, sizeof(pt), &pt_len) != 0) {
			(void)mc_write_str(2, argv0);
			(void)mc_write_str(2, ": record decrypt failed\n");
			break;
		}
		s_hs_seq++;

		if (inner_type != MC_TLS_CONTENT_HANDSHAKE) {
			continue;
		}
		if (hs_append(hs_buf, sizeof(hs_buf), &hs_buf_len, pt, pt_len) != 0) {
			(void)mc_write_str(2, argv0);
			(void)mc_write_str(2, ": handshake buffer overflow\n");
			break;
		}

		for (;;) {
			mc_u8 msg_type = 0;
			mc_u32 msg_body_len = 0;
			mc_u8 msg[65536];
			mc_usize msg_len = 0;
			int cr = hs_consume_one(hs_buf, &hs_buf_len, &msg_type, &msg_body_len, msg, sizeof(msg), &msg_len);
			if (cr == 1) break;
			if (cr != 0) {
				(void)mc_write_str(2, argv0);
				(void)mc_write_str(2, ": handshake parse failed\n");
				iter = 9999;
				break;
			}

			(void)mc_write_str(2, "hs_type ");
			(void)mc_write_u64_dec(2, (mc_u64)msg_type);
			(void)mc_write_str(2, " hs_len ");
			(void)mc_write_u64_dec(2, (mc_u64)msg_body_len);
			(void)mc_write_str(2, "\n");

			if (msg_type == MC_TLS13_HS_FINISHED) {
				mc_u8 th_pre[32];
				mc_tls13_transcript_final(&t, th_pre);
				mc_u8 s_finished_key[32];
				if (mc_tls13_finished_key(s_hs, s_finished_key) != 0) {
					(void)mc_write_str(2, argv0);
					(void)mc_write_str(2, ": finished_key failed\n");
					iter = 9999;
					break;
				}
				mc_u8 expected_verify[32];
				mc_tls13_finished_verify_data(s_finished_key, th_pre, expected_verify);
				mc_memset(s_finished_key, 0, sizeof(s_finished_key));
				if (msg_body_len != 32 || msg_len != 36) {
					(void)mc_write_str(2, argv0);
					(void)mc_write_str(2, ": bad Finished length\n");
					iter = 9999;
					break;
				}
				if (!bytes_eq(expected_verify, msg + 4, 32)) {
					(void)mc_write_str(2, argv0);
					(void)mc_write_str(2, ": server Finished verify failed\n");
					iter = 9999;
					break;
				}
				verified_server_finished = 1;
			}

			mc_tls13_transcript_update(&t, msg, msg_len);
			if (msg_type == MC_TLS13_HS_FINISHED) break;
		}

		if (verified_server_finished) break;
	}

	if (!verified_server_finished) {
		(void)mc_write_str(2, argv0);
		(void)mc_write_str(2, ": handshake did not reach verified server Finished\n");
		(void)mc_sys_close((mc_i32)fd);
		return 1;
	}

	mc_u8 th_post_server_finished[32];
	mc_tls13_transcript_final(&t, th_post_server_finished);

	mc_u8 c_finished_key[32];
	if (mc_tls13_finished_key(c_hs, c_finished_key) != 0) {
		(void)mc_sys_close((mc_i32)fd);
		return 1;
	}
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
	if (mc_tls_record_encrypt(c_key, c_iv, c_hs_seq, MC_TLS_CONTENT_HANDSHAKE, cfin, sizeof(cfin), cfin_record, sizeof(cfin_record),
		&cfin_record_len) != 0) {
		(void)mc_write_str(2, argv0);
		(void)mc_write_str(2, ": encrypt client Finished failed\n");
		(void)mc_sys_close((mc_i32)fd);
		return 1;
	}
	c_hs_seq++;
	wr = mc_write_all((mc_i32)fd, cfin_record, cfin_record_len);
	if (wr < 0) mc_die_errno(argv0, "write", wr);

	mc_tls13_transcript_update(&t, cfin, sizeof(cfin));
	(void)mc_write_str(2, "sent_client_finished 1\n");

	mc_u8 th_post_client_finished[32];
	mc_tls13_transcript_final(&t, th_post_client_finished);

	// Derive application traffic keys.
	mc_u8 derived2[32];
	if (mc_tls13_derive_secret(handshake_secret, "derived", sha256_empty_hs_ptr(), derived2) != 0) {
		(void)mc_sys_close((mc_i32)fd);
		return 1;
	}

	struct ap_variant vars[4];
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
			if (mc_tls13_derive_secret(master_secret, "c ap traffic", th, c_ap) != 0) {
				(void)mc_sys_close((mc_i32)fd);
				return 1;
			}
			if (mc_tls13_derive_secret(master_secret, "s ap traffic", th, s_ap) != 0) {
				(void)mc_sys_close((mc_i32)fd);
				return 1;
			}

			struct ap_variant *v = &vars[nvars++];
			v->which_master = (mc_u8)master_mode;
			v->which_th = (mc_u8)th_mode;
			if (mc_tls13_hkdf_expand_label(c_ap, "key", MC_NULL, 0, v->c_key, sizeof(v->c_key)) != 0) {
				(void)mc_sys_close((mc_i32)fd);
				return 1;
			}
			if (mc_tls13_hkdf_expand_label(c_ap, "iv", MC_NULL, 0, v->c_iv, sizeof(v->c_iv)) != 0) {
				(void)mc_sys_close((mc_i32)fd);
				return 1;
			}
			if (mc_tls13_hkdf_expand_label(s_ap, "key", MC_NULL, 0, v->s_key, sizeof(v->s_key)) != 0) {
				(void)mc_sys_close((mc_i32)fd);
				return 1;
			}
			if (mc_tls13_hkdf_expand_label(s_ap, "iv", MC_NULL, 0, v->s_iv, sizeof(v->s_iv)) != 0) {
				(void)mc_sys_close((mc_i32)fd);
				return 1;
			}
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
		if (record_read((mc_i32)fd, timeout_ms, rhdr, payload, sizeof(payload), &rlen)) {
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
								(void)mc_write_str(2, "selected_ap_keys master=");
								(void)mc_write_u64_dec(2, (mc_u64)vars[vi].which_master);
								(void)mc_write_str(2, " th=");
								(void)mc_write_u64_dec(2, (mc_u64)vars[vi].which_th);
								(void)mc_write_str(2, " seq_mode=");
								(void)mc_write_u64_dec(2, (mc_u64)seq_mode);
								(void)mc_write_str(2, "\n");
								break;
							}
						}
					}

					if (!have_active_ap) {
						(void)mc_write_str(2, "post_handshake_record_decrypt_failed 1\n");
					} else {
						if (inner_type == MC_TLS_CONTENT_HANDSHAKE) {
							hs_buf_len = 0;
							(void)hs_append(hs_buf, sizeof(hs_buf), &hs_buf_len, pt, pt_len);
							for (;;) {
								mc_u8 msg_type = 0;
								mc_u32 msg_body_len = 0;
								mc_u8 msg[65536];
								mc_usize msg_len = 0;
								int cr = hs_consume_one(hs_buf, &hs_buf_len, &msg_type, &msg_body_len, msg, sizeof(msg), &msg_len);
								if (cr == 1) break;
								if (cr != 0) break;
								(void)mc_write_str(2, "post_hs_type ");
								(void)mc_write_u64_dec(2, (mc_u64)msg_type);
								(void)mc_write_str(2, " post_hs_len ");
								(void)mc_write_u64_dec(2, (mc_u64)msg_body_len);
								(void)mc_write_str(2, "\n");
							}
						}
					}
				}
			}
		}
	}

	if (!have_active_ap) {
		// Default to the tls.md diagram: master IKM=0^32, th=ServerFinished, new epoch.
		mc_memcpy(c_ap_key, vars[0].c_key, sizeof(c_ap_key));
		mc_memcpy(c_ap_iv, vars[0].c_iv, sizeof(c_ap_iv));
		mc_memcpy(s_ap_key, vars[0].s_key, sizeof(s_ap_key));
		mc_memcpy(s_ap_iv, vars[0].s_iv, sizeof(s_ap_iv));
		c_ap_seq = 0;
		s_ap_seq = 0;
		have_active_ap = 1;
		(void)mc_write_str(2, "selected_ap_keys_default 1\n");
	}

	// Send a minimal HTTP/1.1 request as application data.
	char req[4096];
	mc_usize req_len = 0;
	{
		const char *p0 = "GET ";
		const char *p1 = " HTTP/1.1\r\nHost: ";
		const char *p2 = "\r\nUser-Agent: monacc-tls13\r\nAccept: */*\r\nConnection: close\r\n\r\n";
		mc_usize l0 = 4u;
		mc_usize l1 = 17u;
		mc_usize l2 = 62u;
		mc_usize need = l0 + path_len + l1 + sni_len + l2;
		if (need > sizeof(req)) {
			(void)mc_write_str(2, argv0);
			(void)mc_write_str(2, ": request too large\n");
			(void)mc_sys_close((mc_i32)fd);
			return 1;
		}
		mc_memcpy(req + req_len, p0, l0);
		req_len += l0;
		mc_memcpy(req + req_len, path, path_len);
		req_len += path_len;
		mc_memcpy(req + req_len, p1, l1);
		req_len += l1;
		mc_memcpy(req + req_len, sni, sni_len);
		req_len += sni_len;
		mc_memcpy(req + req_len, p2, l2);
		req_len += l2;
	}

	mc_u8 req_record[5 + 4096 + 64];
	mc_usize req_record_len = 0;
	if (mc_tls_record_encrypt(c_ap_key, c_ap_iv, c_ap_seq, MC_TLS_CONTENT_APPLICATION_DATA, (const mc_u8 *)req, req_len, req_record,
		sizeof(req_record), &req_record_len) != 0) {
		(void)mc_write_str(2, argv0);
		(void)mc_write_str(2, ": encrypt http request failed\n");
		(void)mc_sys_close((mc_i32)fd);
		return 1;
	}
	c_ap_seq++;
	wr = mc_write_all((mc_i32)fd, req_record, req_record_len);
	if (wr < 0) mc_die_errno(argv0, "write", wr);
	(void)mc_write_str(2, "sent_http_request 1\n");

	hs_buf_len = 0;
	for (int iter = 0; iter < 4096; iter++) {
		mc_usize rlen = 0;
		if (!record_read((mc_i32)fd, timeout_ms, rhdr, payload, sizeof(payload), &rlen)) {
			break;
		}
		mc_u8 rtype = rhdr[0];
		if (rtype == MC_TLS_CONTENT_CHANGE_CIPHER_SPEC) continue;
		if (rtype == MC_TLS_CONTENT_ALERT) {
			(void)mc_write_str(2, argv0);
			(void)mc_write_str(2, ": got plaintext alert\n");
			break;
		}
		if (rtype != MC_TLS_CONTENT_APPLICATION_DATA) continue;

		mc_u8 record[5 + 65536];
		mc_usize record_len = 5u + rlen;
		if (record_len > sizeof(record)) break;
		mc_memcpy(record, rhdr, 5);
		mc_memcpy(record + 5, payload, rlen);

		mc_u8 inner_type = 0;
		mc_u8 pt[65536];
		mc_usize pt_len = 0;
		if (mc_tls_record_decrypt(s_ap_key, s_ap_iv, s_ap_seq, record, record_len, &inner_type, pt, sizeof(pt), &pt_len) != 0) {
			(void)mc_write_str(2, argv0);
			(void)mc_write_str(2, ": app record decrypt failed\n");
			break;
		}
		s_ap_seq++;

		if (inner_type == MC_TLS_CONTENT_APPLICATION_DATA) {
			if (pt_len) (void)mc_write_all(1, pt, pt_len);
			continue;
		}
		if (inner_type == MC_TLS_CONTENT_HANDSHAKE) {
			if (hs_append(hs_buf, sizeof(hs_buf), &hs_buf_len, pt, pt_len) != 0) {
				(void)mc_write_str(2, argv0);
				(void)mc_write_str(2, ": post-handshake buffer overflow\n");
				break;
			}
			for (;;) {
				mc_u8 msg_type = 0;
				mc_u32 msg_body_len = 0;
				mc_u8 msg[65536];
				mc_usize msg_len = 0;
				int cr = hs_consume_one(hs_buf, &hs_buf_len, &msg_type, &msg_body_len, msg, sizeof(msg), &msg_len);
				if (cr == 1) break;
				if (cr != 0) {
					(void)mc_write_str(2, argv0);
					(void)mc_write_str(2, ": post-handshake parse failed\n");
					iter = 9999;
					break;
				}
				(void)mc_write_str(2, "post_hs_type ");
				(void)mc_write_u64_dec(2, (mc_u64)msg_type);
				(void)mc_write_str(2, " post_hs_len ");
				(void)mc_write_u64_dec(2, (mc_u64)msg_body_len);
				(void)mc_write_str(2, "\n");
			}
			continue;
		}
		if (inner_type == MC_TLS_CONTENT_ALERT) {
			(void)mc_write_str(2, "got_encrypted_alert 1\n");
			break;
		}
	}

	(void)mc_sys_close((mc_i32)fd);

	(void)mc_write_str(2, "server_version ");
	mc_write_hex_u64(2, (mc_u64)sh.selected_version);
	(void)mc_write_str(2, "\n");
	(void)mc_write_str(2, "cipher_suite ");
	mc_write_hex_u64(2, (mc_u64)sh.cipher_suite);
	(void)mc_write_str(2, "\n");
	(void)mc_write_str(2, "key_share_group ");
	mc_write_hex_u64(2, (mc_u64)sh.key_share_group);
	(void)mc_write_str(2, "\n");
	(void)mc_write_str(2, "server_key_share ");
	write_hex_bytes(2, sh.key_share, sh.key_share_len);
	(void)mc_write_str(2, "\n");
	(void)mc_write_str(2, "chsh_hash ");
	write_hex_bytes(2, chsh_hash, sizeof(chsh_hash));
	(void)mc_write_str(2, "\n");

	return 0;
}

__attribute__((used)) int main(int argc, char **argv, char **envp) {
	if (argc < 2 || !argv || !argv[0] || !argv[1]) tls13_usage("tls13");
	if (mc_streq(argv[1], "rec")) return cmd_rec(argc, argv);
	if (mc_streq(argv[1], "kdf")) return cmd_kdf(argc, argv);
	if (mc_streq(argv[1], "hello")) return cmd_hello(argc, argv);
	if (mc_streq(argv[1], "hs")) return cmd_hs(argc, argv, envp);
	tls13_usage(argv[0]);
	return 1;
}
