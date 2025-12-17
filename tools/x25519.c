#include "mc.h"
#include "mc_x25519.h"

static MC_NORETURN void x_usage(const char *argv0) {
	mc_die_usage(argv0, "x25519 --rfc7748-1");
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

static int streq(const char *a, const char *b) {
	return mc_streq(a, b);
}

__attribute__((used)) int main(int argc, char **argv, char **envp) {
	(void)envp;
	const char *argv0 = (argc > 0 && argv && argv[0]) ? argv[0] : "x25519";
	if (argc != 2 || !argv[1]) x_usage(argv0);
	if (!streq(argv[1], "--rfc7748-1")) x_usage(argv0);

	// RFC 7748, section 5.2.
	static const mc_u8 a_priv[32] = {
		0x77,0x07,0x6d,0x0a,0x73,0x18,0xa5,0x7d,0x3c,0x16,0xc1,0x72,0x51,0xb2,0x66,0x45,
		0xdf,0x4c,0x2f,0x87,0xeb,0xc0,0x99,0x2a,0xb1,0x77,0xfb,0xa5,0x1d,0xb9,0x2c,0x2a,
	};
	static const mc_u8 b_priv[32] = {
		0x5d,0xab,0x08,0x7e,0x62,0x4a,0x8a,0x4b,0x79,0xe1,0x7f,0x8b,0x83,0x80,0x0e,0xe6,
		0x6f,0x3b,0xb1,0x29,0x26,0x18,0xb6,0xfd,0x1c,0x2f,0x8b,0x27,0xff,0x88,0xe0,0xeb,
	};
	static const mc_u8 exp_shared[32] = {
		0x4a,0x5d,0x9d,0x5b,0xa4,0xce,0x2d,0xe1,0x72,0x8e,0x3b,0xf4,0x80,0x35,0x0f,0x25,
		0xe0,0x7e,0x21,0xc9,0x47,0xd1,0x9e,0x33,0x76,0xf0,0x9b,0x3c,0x1e,0x16,0x17,0x42,
	};

	mc_u8 a_pub[32];
	mc_u8 b_pub[32];
	mc_x25519_public(a_pub, a_priv);
	mc_x25519_public(b_pub, b_priv);

	mc_u8 s1[32];
	mc_u8 s2[32];
	if (mc_x25519_shared(s1, a_priv, b_pub) != 0) return 1;
	if (mc_x25519_shared(s2, b_priv, a_pub) != 0) return 2;
	if (mc_memcmp(s1, s2, 32) != 0) return 3;
	if (mc_memcmp(s1, exp_shared, 32) != 0) return 4;

	char hex[32 * 2 + 1];
	hex_encode(s1, 32, hex, sizeof(hex));
	(void)mc_write_str(1, "shared ");
	(void)mc_write_str(1, hex);
	(void)mc_write_all(1, "\n", 1);
	return 0;
}
