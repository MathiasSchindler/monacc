#include "mc.h"
#include "mc_aes.h"

static MC_NORETURN void aes_usage(const char *argv0) {
	mc_die_usage(argv0, "aes128 --fips197");
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

#ifdef MC_AES_TRACE
static void u16_hex(mc_u32 v, char out[5]) {
	static const char hex[] = "0123456789abcdef";
	v &= 0xffffu;
	out[0] = hex[(v >> 12) & 0xfu];
	out[1] = hex[(v >> 8) & 0xfu];
	out[2] = hex[(v >> 4) & 0xfu];
	out[3] = hex[(v >> 0) & 0xfu];
	out[4] = 0;
}

// Tracing hook for core/mc_aes.c when compiled with -DMC_AES_TRACE.
void mc_aes_trace(mc_u32 tag, const mc_u8 st[16]) {
	char tag_hex[5];
	u16_hex(tag, tag_hex);

	char st_hex[33];
	hex_encode(st, 16, st_hex, sizeof(st_hex));

	char line[40];
	line[0] = tag_hex[0];
	line[1] = tag_hex[1];
	line[2] = tag_hex[2];
	line[3] = tag_hex[3];
	line[4] = ' ';
	for (mc_usize i = 0; i < 32; i++) line[5 + i] = st_hex[i];
	line[37] = '\n';
	line[38] = 0;
	(void)mc_write_all(1, line, 38);
}
#endif

__attribute__((used)) int main(int argc, char **argv, char **envp) {
	(void)envp;
	const char *argv0 = (argc > 0 && argv && argv[0]) ? argv[0] : "aes128";
	if (argc != 2 || !argv[1]) aes_usage(argv0);
	if (!mc_streq(argv[1], "--fips197")) aes_usage(argv0);

	// FIPS 197, Appendix C.1 (AES-128)
	static const mc_u8 key[16] = {
		0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
	};
	static const mc_u8 pt[16] = {
		0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff,
	};
	static const mc_u8 exp_ct[16] = {
		0x69,0xc4,0xe0,0xd8,0x6a,0x7b,0x04,0x30,0xd8,0xcd,0xb7,0x80,0x70,0xb4,0xc5,0x5a,
	};

	mc_aes128_ctx ctx;
	mc_aes128_init(&ctx, key);

	mc_u8 ct[16];
	mc_aes128_encrypt_block(&ctx, pt, ct);

	// Verify ciphertext matches.
	if (mc_memcmp(ct, exp_ct, 16) != 0) return 1;

	// Verify decrypt round-trip.
	mc_u8 rt[16];
	mc_aes128_decrypt_block(&ctx, ct, rt);
	if (mc_memcmp(rt, pt, 16) != 0) return 2;

	char hex[33];
	hex_encode(ct, 16, hex, sizeof(hex));
	(void)mc_write_str(1, hex);
	(void)mc_write_all(1, "\n", 1);
	return 0;
}
