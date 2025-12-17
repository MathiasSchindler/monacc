#include "mc.h"
#include "mc_sha256.h"
#include "mc_tls13_handshake.h"
#include "mc_tls13_transcript.h"

static MC_NORETURN void tls13hello_usage(const char *argv0) {
	mc_die_usage(argv0, "tls13hello --rfc8448-1rtt");
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

static void hex_encode(const mc_u8 *in, mc_usize in_len, char *out, mc_usize out_cap) {
	static const char hex[] = "0123456789abcdef";
	if (out_cap < in_len * 2u + 1u) return;
	for (mc_usize i = 0; i < in_len; i++) {
		mc_u8 b = in[i];
		out[i * 2u + 0u] = hex[(b >> 4) & 0xFu];
		out[i * 2u + 1u] = hex[b & 0xFu];
	}
	out[in_len * 2u] = 0;
}

__attribute__((used)) int main(int argc, char **argv, char **envp) {
	(void)envp;
	const char *argv0 = (argc > 0 && argv && argv[0]) ? argv[0] : "tls13hello";
	if (argc != 2 || !argv[1]) tls13hello_usage(argv0);
	if (!mc_streq(argv[1], "--rfc8448-1rtt")) tls13hello_usage(argv0);

	// RFC 8448, Section 3 handshake messages (handshake header included).
	static const char rfc_ch_hex[] =
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

	static const char rfc_sh_hex[] =
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
	static const mc_u8 rfc_random[32] = {
		0xcb,0x34,0xec,0xb1,0xe7,0x81,0x63,0xba,0x1c,0x38,0xc6,0xda,0xcb,0x19,0x6a,0x6d,
		0xff,0xa2,0x1a,0x8d,0x99,0x12,0xec,0x18,0xa2,0xef,0x62,0x83,0x02,0x4d,0xec,0xe7,
	};
	static const mc_u8 rfc_pub[32] = {
		0x99,0x38,0x1d,0xe5,0x60,0xe4,0xbd,0x43,0xd2,0x3d,0x8e,0x43,0x5a,0x7d,0xba,0xfe,
		0xb3,0xc0,0x6e,0x51,0xc1,0x3c,0xae,0x4d,0x54,0x13,0x69,0x1e,0x52,0x9a,0xaf,0x2c,
	};
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

	static const mc_u8 expected_hash[32] = {
		0x86,0x0c,0x06,0xed,0xc0,0x78,0x58,0xee,0x8e,0x78,0xf0,0xe7,0x42,0x8c,0x58,0xed,
		0xd6,0xb4,0x3f,0x2c,0xa3,0xe6,0xe9,0x5f,0x02,0xed,0x06,0x3c,0xf0,0xe1,0xca,0xd8,
	};
	if (mc_memcmp(hash, expected_hash, 32) != 0) return 40;

	char hex[128];
	hex_encode(hash, 32, hex, sizeof(hex));
	mc_write_str(1, "chsh_hash ");
	mc_write_str(1, hex);
	mc_write_str(1, "\n");
	return 0;
}
