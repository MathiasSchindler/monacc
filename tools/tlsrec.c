#include "mc.h"
#include "mc_tls_record.h"

static MC_NORETURN void tlsrec_usage(const char *argv0) {
	mc_die_usage(argv0, "tlsrec --smoke");
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
	const char *argv0 = (argc > 0 && argv && argv[0]) ? argv[0] : "tlsrec";
	if (argc != 2 || !argv[1]) tlsrec_usage(argv0);
	if (!mc_streq(argv[1], "--smoke")) tlsrec_usage(argv0);

	// Deterministic smoke vector to validate:
	// - nonce construction (seq XOR iv)
	// - AAD header formatting
	// - inner plaintext type byte
	static const mc_u8 key[16] = {
		0xfe,0xff,0xe9,0x92,0x86,0x65,0x73,0x1c,0x6d,0x6a,0x8f,0x94,0x67,0x30,0x83,0x08,
	};
	static const mc_u8 iv[12] = {
		0xca,0xfe,0xba,0xbe,0xfa,0xce,0xdb,0xad,0xde,0xca,0xf8,0x88,
	};
	static const mc_u8 msg[] = "hello";

	mc_u8 record[256];
	mc_usize record_len = 0;
	mc_u64 seq = 1;
	if (mc_tls_record_encrypt(key, iv, seq, (mc_u8)MC_TLS_CONTENT_HANDSHAKE, msg, sizeof(msg) - 1u,
		record, sizeof(record), &record_len) != 0) return 1;

	mc_u8 pt[64];
	mc_usize pt_len = 0;
	mc_u8 inner_type = 0;
	if (mc_tls_record_decrypt(key, iv, seq, record, record_len, &inner_type, pt, sizeof(pt), &pt_len) != 0) return 2;
	if (inner_type != (mc_u8)MC_TLS_CONTENT_HANDSHAKE) return 3;
	if (pt_len != sizeof(msg) - 1u) return 4;
	if (mc_memcmp(pt, msg, pt_len) != 0) return 5;

	// Output record hex for test harness pinning.
	char hex[512];
	hex_encode(record, record_len, hex, sizeof(hex));
	(void)mc_write_str(1, hex);
	(void)mc_write_all(1, "\n", 1);
	return 0;
}
