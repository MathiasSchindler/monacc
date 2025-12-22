#include "mc.h"
#include "mc_aes.h"

#ifdef MC_AES_TRACE
void mc_aes_trace(mc_u32 tag, const mc_u8 st[16]);
#endif

static const mc_u8 *aes_sbox_ptr(void) {
	return (const mc_u8 *)
		"\x63\x7c\x77\x7b\xf2\x6b\x6f\xc5\x30\x01\x67\x2b\xfe\xd7\xab\x76"
		"\xca\x82\xc9\x7d\xfa\x59\x47\xf0\xad\xd4\xa2\xaf\x9c\xa4\x72\xc0"
		"\xb7\xfd\x93\x26\x36\x3f\xf7\xcc\x34\xa5\xe5\xf1\x71\xd8\x31\x15"
		"\x04\xc7\x23\xc3\x18\x96\x05\x9a\x07\x12\x80\xe2\xeb\x27\xb2\x75"
		"\x09\x83\x2c\x1a\x1b\x6e\x5a\xa0\x52\x3b\xd6\xb3\x29\xe3\x2f\x84"
		"\x53\xd1\x00\xed\x20\xfc\xb1\x5b\x6a\xcb\xbe\x39\x4a\x4c\x58\xcf"
		"\xd0\xef\xaa\xfb\x43\x4d\x33\x85\x45\xf9\x02\x7f\x50\x3c\x9f\xa8"
		"\x51\xa3\x40\x8f\x92\x9d\x38\xf5\xbc\xb6\xda\x21\x10\xff\xf3\xd2"
		"\xcd\x0c\x13\xec\x5f\x97\x44\x17\xc4\xa7\x7e\x3d\x64\x5d\x19\x73"
		"\x60\x81\x4f\xdc\x22\x2a\x90\x88\x46\xee\xb8\x14\xde\x5e\x0b\xdb"
		"\xe0\x32\x3a\x0a\x49\x06\x24\x5c\xc2\xd3\xac\x62\x91\x95\xe4\x79"
		"\xe7\xc8\x37\x6d\x8d\xd5\x4e\xa9\x6c\x56\xf4\xea\x65\x7a\xae\x08"
		"\xba\x78\x25\x2e\x1c\xa6\xb4\xc6\xe8\xdd\x74\x1f\x4b\xbd\x8b\x8a"
		"\x70\x3e\xb5\x66\x48\x03\xf6\x0e\x61\x35\x57\xb9\x86\xc1\x1d\x9e"
		"\xe1\xf8\x98\x11\x69\xd9\x8e\x94\x9b\x1e\x87\xe9\xce\x55\x28\xdf"
		"\x8c\xa1\x89\x0d\xbf\xe6\x42\x68\x41\x99\x2d\x0f\xb0\x54\xbb\x16";
}

static const mc_u8 *aes_inv_sbox_ptr(void) {
	return (const mc_u8 *)
		"\x52\x09\x6a\xd5\x30\x36\xa5\x38\xbf\x40\xa3\x9e\x81\xf3\xd7\xfb"
		"\x7c\xe3\x39\x82\x9b\x2f\xff\x87\x34\x8e\x43\x44\xc4\xde\xe9\xcb"
		"\x54\x7b\x94\x32\xa6\xc2\x23\x3d\xee\x4c\x95\x0b\x42\xfa\xc3\x4e"
		"\x08\x2e\xa1\x66\x28\xd9\x24\xb2\x76\x5b\xa2\x49\x6d\x8b\xd1\x25"
		"\x72\xf8\xf6\x64\x86\x68\x98\x16\xd4\xa4\x5c\xcc\x5d\x65\xb6\x92"
		"\x6c\x70\x48\x50\xfd\xed\xb9\xda\x5e\x15\x46\x57\xa7\x8d\x9d\x84"
		"\x90\xd8\xab\x00\x8c\xbc\xd3\x0a\xf7\xe4\x58\x05\xb8\xb3\x45\x06"
		"\xd0\x2c\x1e\x8f\xca\x3f\x0f\x02\xc1\xaf\xbd\x03\x01\x13\x8a\x6b"
		"\x3a\x91\x11\x41\x4f\x67\xdc\xea\x97\xf2\xcf\xce\xf0\xb4\xe6\x73"
		"\x96\xac\x74\x22\xe7\xad\x35\x85\xe2\xf9\x37\xe8\x1c\x75\xdf\x6e"
		"\x47\xf1\x1a\x71\x1d\x29\xc5\x89\x6f\xb7\x62\x0e\xaa\x18\xbe\x1b"
		"\xfc\x56\x3e\x4b\xc6\xd2\x79\x20\x9a\xdb\xc0\xfe\x78\xcd\x5a\xf4"
		"\x1f\xdd\xa8\x33\x88\x07\xc7\x31\xb1\x12\x10\x59\x27\x80\xec\x5f"
		"\x60\x51\x7f\xa9\x19\xb5\x4a\x0d\x2d\xe5\x7a\x9f\x93\xc9\x9c\xef"
		"\xa0\xe0\x3b\x4d\xae\x2a\xf5\xb0\xc8\xeb\xbb\x3c\x83\x53\x99\x61"
		"\x17\x2b\x04\x7e\xba\x77\xd6\x26\xe1\x69\x14\x63\x55\x21\x0c\x7d";
}

static mc_u32 load_be32(const mc_u8 *p) {
	return ((mc_u32)p[0] << 24) | ((mc_u32)p[1] << 16) | ((mc_u32)p[2] << 8) | ((mc_u32)p[3]);
}

static mc_u32 rot_word(mc_u32 w) {
	return (w << 8) | (w >> 24);
}

static mc_u32 sub_word(mc_u32 w) {
	const mc_u8 *sbox = aes_sbox_ptr();
	mc_u32 out = 0;
	out |= (mc_u32)sbox[(w >> 24) & 0xFFu] << 24;
	out |= (mc_u32)sbox[(w >> 16) & 0xFFu] << 16;
	out |= (mc_u32)sbox[(w >> 8) & 0xFFu] << 8;
	out |= (mc_u32)sbox[(w >> 0) & 0xFFu] << 0;
	return out;
}

static mc_u8 xtime(mc_u8 x) {
	return (mc_u8)((x << 1) ^ ((x & 0x80u) ? 0x1bu : 0x00u));
}

void mc_aes128_init(mc_aes128_ctx *ctx, const mc_u8 key[MC_AES128_KEY_SIZE]) {
	// Key expansion, AES-128: 4 words key, 44 words total.
	for (mc_u32 i = 0; i < 4; i++) {
		ctx->rk[i] = load_be32(key + (mc_usize)(i * 4u));
	}
	mc_u8 rc = 0x01u;
	for (mc_u32 i = 4; i < 44; i++) {
		mc_u32 temp = ctx->rk[i - 1];
		if ((i & 3u) == 0u) {
			temp = sub_word(rot_word(temp)) ^ ((mc_u32)rc << 24);
			rc = xtime(rc);
		}
		ctx->rk[i] = ctx->rk[i - 4] ^ temp;
	}
}

static mc_u8 gf_mul(mc_u8 a, mc_u8 b) {
	mc_u8 r = 0;
	for (mc_u32 i = 0; i < 8; i++) {
		if (b & 1u) r ^= a;
		mc_u8 hi = (mc_u8)(a & 0x80u);
		a <<= 1;
		if (hi) a ^= 0x1bu;
		b >>= 1;
	}
	return r;
}

static void add_round_key(mc_u8 st[16], const mc_u32 *rk) {
	for (mc_u32 c = 0; c < 4; c++) {
		mc_u32 w = rk[c];
		st[c*4u + 0u] ^= (mc_u8)(w >> 24);
		st[c*4u + 1u] ^= (mc_u8)(w >> 16);
		st[c*4u + 2u] ^= (mc_u8)(w >> 8);
		st[c*4u + 3u] ^= (mc_u8)(w);
	}
}

static void sub_bytes(mc_u8 st[16]) {
	const mc_u8 *sbox = aes_sbox_ptr();
	for (mc_u32 i = 0; i < 16; i++) st[i] = sbox[st[i]];
}

static void inv_sub_bytes(mc_u8 st[16]) {
	const mc_u8 *inv_sbox = aes_inv_sbox_ptr();
	for (mc_u32 i = 0; i < 16; i++) st[i] = inv_sbox[st[i]];
}

static void shift_rows(mc_u8 st[16]) {
	mc_u8 t;
	// Row 1 shift left 1
	t = st[1]; st[1]=st[5]; st[5]=st[9]; st[9]=st[13]; st[13]=t;
	// Row 2 shift left 2
	t = st[2]; st[2]=st[10]; st[10]=t; t = st[6]; st[6]=st[14]; st[14]=t;
	// Row 3 shift left 3
	t = st[3]; st[3]=st[15]; st[15]=st[11]; st[11]=st[7]; st[7]=t;
}

static void inv_shift_rows(mc_u8 st[16]) {
	mc_u8 t;
	// Row 1 shift right 1
	t = st[13]; st[13]=st[9]; st[9]=st[5]; st[5]=st[1]; st[1]=t;
	// Row 2 shift right 2
	t = st[2]; st[2]=st[10]; st[10]=t; t = st[6]; st[6]=st[14]; st[14]=t;
	// Row 3 shift right 3 (left 1)
	t = st[3]; st[3]=st[7]; st[7]=st[11]; st[11]=st[15]; st[15]=t;
}

static void mix_columns(mc_u8 st[16]) {
	for (mc_u32 c = 0; c < 4; c++) {
		mc_u8 *col = &st[c*4u];
		mc_u8 a0 = col[0], a1 = col[1], a2 = col[2], a3 = col[3];
		mc_u8 r0 = (mc_u8)(xtime(a0) ^ (xtime(a1) ^ a1) ^ a2 ^ a3);
		mc_u8 r1 = (mc_u8)(a0 ^ xtime(a1) ^ (xtime(a2) ^ a2) ^ a3);
		mc_u8 r2 = (mc_u8)(a0 ^ a1 ^ xtime(a2) ^ (xtime(a3) ^ a3));
		mc_u8 r3 = (mc_u8)((xtime(a0) ^ a0) ^ a1 ^ a2 ^ xtime(a3));
		col[0] = r0; col[1] = r1; col[2] = r2; col[3] = r3;
	}
}

static void inv_mix_columns(mc_u8 st[16]) {
	for (mc_u32 c = 0; c < 4; c++) {
		mc_u8 *col = &st[c*4u];
		mc_u8 a0 = col[0], a1 = col[1], a2 = col[2], a3 = col[3];
		col[0] = (mc_u8)(gf_mul(a0,0x0e) ^ gf_mul(a1,0x0b) ^ gf_mul(a2,0x0d) ^ gf_mul(a3,0x09));
		col[1] = (mc_u8)(gf_mul(a0,0x09) ^ gf_mul(a1,0x0e) ^ gf_mul(a2,0x0b) ^ gf_mul(a3,0x0d));
		col[2] = (mc_u8)(gf_mul(a0,0x0d) ^ gf_mul(a1,0x09) ^ gf_mul(a2,0x0e) ^ gf_mul(a3,0x0b));
		col[3] = (mc_u8)(gf_mul(a0,0x0b) ^ gf_mul(a1,0x0d) ^ gf_mul(a2,0x09) ^ gf_mul(a3,0x0e));
	}
}

void mc_aes128_encrypt_block(const mc_aes128_ctx *ctx, const mc_u8 in[MC_AES128_BLOCK_SIZE], mc_u8 out[MC_AES128_BLOCK_SIZE]) {
	mc_u8 st[16];
	mc_memcpy(st, in, 16);
	#ifdef MC_AES_TRACE
	mc_aes_trace(0x0000u, st);
	#endif

	add_round_key(st, &ctx->rk[0]);
	#ifdef MC_AES_TRACE
	mc_aes_trace(0x0100u, st);
	#endif

	for (mc_u32 round = 1; round < MC_AES128_ROUNDS; round++) {
		sub_bytes(st);
		#ifdef MC_AES_TRACE
		mc_aes_trace(0x0200u | round, st);
		#endif
		shift_rows(st);
		#ifdef MC_AES_TRACE
		mc_aes_trace(0x0300u | round, st);
		#endif
		mix_columns(st);
		#ifdef MC_AES_TRACE
		mc_aes_trace(0x0400u | round, st);
		#endif
		add_round_key(st, &ctx->rk[round * 4u]);
		#ifdef MC_AES_TRACE
		mc_aes_trace(0x0500u | round, st);
		#endif
	}

	sub_bytes(st);
	#ifdef MC_AES_TRACE
	mc_aes_trace(0x0200u | MC_AES128_ROUNDS, st);
	#endif
	shift_rows(st);
	#ifdef MC_AES_TRACE
	mc_aes_trace(0x0300u | MC_AES128_ROUNDS, st);
	#endif
	add_round_key(st, &ctx->rk[MC_AES128_ROUNDS * 4u]);
	#ifdef MC_AES_TRACE
	mc_aes_trace(0x0500u | MC_AES128_ROUNDS, st);
	#endif

	mc_memcpy(out, st, 16);
	mc_memset(st, 0, sizeof(st));
}

void mc_aes128_decrypt_block(const mc_aes128_ctx *ctx, const mc_u8 in[MC_AES128_BLOCK_SIZE], mc_u8 out[MC_AES128_BLOCK_SIZE]) {
	mc_u8 st[16];
	mc_memcpy(st, in, 16);

	add_round_key(st, &ctx->rk[MC_AES128_ROUNDS * 4u]);

	for (mc_u32 round = MC_AES128_ROUNDS - 1; round > 0; round--) {
		inv_shift_rows(st);
		inv_sub_bytes(st);
		add_round_key(st, &ctx->rk[round * 4u]);
		inv_mix_columns(st);
	}

	inv_shift_rows(st);
	inv_sub_bytes(st);
	add_round_key(st, &ctx->rk[0]);

	mc_memcpy(out, st, 16);
	mc_memset(st, 0, sizeof(st));
}
