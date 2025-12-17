#include "mc.h"
#include "mc_hkdf.h"

static MC_NORETURN void hkdf_usage(const char *argv0) {
	mc_die_usage(argv0, "hkdf --rfc5869-1");
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
	const char *argv0 = (argc > 0 && argv && argv[0]) ? argv[0] : "hkdf";

	if (argc != 2) hkdf_usage(argv0);
	if (!argv[1]) hkdf_usage(argv0);

	if (!streq(argv[1], "--rfc5869-1")) hkdf_usage(argv0);

	// RFC 5869 - Test Case 1
	static const mc_u8 ikm[22] = {
		0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
		0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
	};
	static const mc_u8 salt[13] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c};
	static const mc_u8 info[10] = {0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9};

	mc_u8 prk[32];
	mc_u8 okm[42];
	mc_hkdf_extract(salt, sizeof(salt), ikm, sizeof(ikm), prk);
	mc_hkdf_expand(prk, info, sizeof(info), okm, sizeof(okm));

	char prk_hex[32 * 2 + 1];
	char okm_hex[42 * 2 + 1];
	hex_encode(prk, sizeof(prk), prk_hex, sizeof(prk_hex));
	hex_encode(okm, sizeof(okm), okm_hex, sizeof(okm_hex));

	(void)mc_write_str(1, "prk ");
	(void)mc_write_str(1, prk_hex);
	(void)mc_write_all(1, "\n", 1);
	(void)mc_write_str(1, "okm ");
	(void)mc_write_str(1, okm_hex);
	(void)mc_write_all(1, "\n", 1);

	return 0;
}
