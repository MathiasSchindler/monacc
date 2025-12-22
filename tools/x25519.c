#include "mc.h"
#include "mc_x25519.h"

static MC_NORETURN void x_usage(const char *argv0) {
	mc_die_usage(argv0, "x25519 --rfc7748-1 | --pub-test | --index-test | --i64-index-test | --fe-index-test | --u16-pack-test | --mul-loop-test | --signed-shift-test | --stack-layout-test | --inv-cond-test | --carry-test | --clamp-test | --ladder-step-test | --memtest | --dec-loop-test | --dec-loop-gt0-test");
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

static void hash_bytes(mc_u64 *acc, const mc_u8 *p, mc_usize n) {
	for (mc_usize i = 0; i < n; i++) {
		*acc ^= (mc_u64)p[i] + 0x9e3779b97f4a7c15ULL;
		*acc = (*acc << 13) | (*acc >> (64 - 13));
		*acc *= 0xbf58476d1ce4e5b9ULL;
	}
}

static int first_diff_byte(const mc_u8 *p, mc_usize n, mc_u8 want) {
	for (mc_usize i = 0; i < n; i++) {
		if (p[i] != want) return (int)i;
	}
	return -1;
}

static int check_fill(const char *name, const void *ptr, mc_usize len, mc_u8 want) {
	int di = first_diff_byte((const mc_u8 *)ptr, len, want);
	if (di < 0) return 0;
	(void)mc_write_str(2, "stack_layout_invariant_fail ");
	(void)mc_write_str(2, name);
	(void)mc_write_str(2, " idx=");
	(void)mc_write_u64_dec(2, (mc_u64)di);
	(void)mc_write_str(2, " got=");
	mc_write_hex_u64(2, (mc_u64)((const mc_u8 *)ptr)[di]);
	(void)mc_write_str(2, " want=");
	mc_write_hex_u64(2, (mc_u64)want);
	(void)mc_write_all(2, "\n", 1);
	return 90;
}

static int index_test(void) {
	mc_u8 s[32];
	mc_memset(s, 0x40, sizeof(s));
	for (int i = 0; i < 16; i++) {
		s[2 * i + 0] = (mc_u8)i;
		s[2 * i + 1] = 0xaa;
	}
	char hex[32 * 2 + 1];
	hex_encode(s, 32, hex, sizeof(hex));
	(void)mc_write_str(1, "index_test ");
	(void)mc_write_str(1, hex);
	(void)mc_write_all(1, "\n", 1);
	return 0;
}

static int mem_test(void) {
	static const mc_usize lens[] = {0,1,2,3,7,8,9,15,16,31,32,33,63,64,65,127,128,129,255,256};
	for (mc_usize li = 0; li < (mc_usize)(sizeof(lens) / sizeof(lens[0])); li++) {
		mc_usize n = lens[li];
		mc_u8 src[256];
		mc_u8 dst[256];
		for (mc_usize i = 0; i < 256; i++) src[i] = (mc_u8)(i ^ 0x5au);
		mc_memset(dst, 0x40, sizeof(dst));
		mc_memcpy(dst, src, n);
		for (mc_usize i = 0; i < n; i++) {
			if (dst[i] != src[i]) {
				(void)mc_write_str(2, "memcpy mismatch at n=");
				(void)mc_write_u64_dec(2, (mc_u64)n);
				(void)mc_write_str(2, " i=");
				(void)mc_write_u64_dec(2, (mc_u64)i);
				(void)mc_write_all(2, "\n", 1);
				return 10;
			}
		}
		for (mc_usize i = n; i < 256; i++) {
			if (dst[i] != 0x40) {
				(void)mc_write_str(2, "memcpy clobber at n=");
				(void)mc_write_u64_dec(2, (mc_u64)n);
				(void)mc_write_str(2, " i=");
				(void)mc_write_u64_dec(2, (mc_u64)i);
				(void)mc_write_all(2, "\n", 1);
				return 11;
			}
		}

		mc_memset(dst, 0x40, sizeof(dst));
		mc_memset(dst, 0x00, n);
		for (mc_usize i = 0; i < n; i++) {
			if (dst[i] != 0x00) {
				(void)mc_write_str(2, "memset mismatch at n=");
				(void)mc_write_u64_dec(2, (mc_u64)n);
				(void)mc_write_str(2, " i=");
				(void)mc_write_u64_dec(2, (mc_u64)i);
				(void)mc_write_all(2, "\n", 1);
				return 12;
			}
		}
		for (mc_usize i = n; i < 256; i++) {
			if (dst[i] != 0x40) {
				(void)mc_write_str(2, "memset clobber at n=");
				(void)mc_write_u64_dec(2, (mc_u64)n);
				(void)mc_write_str(2, " i=");
				(void)mc_write_u64_dec(2, (mc_u64)i);
				(void)mc_write_all(2, "\n", 1);
				return 13;
			}
		}
	}
	(void)mc_write_str(1, "memtest ok\n");
	return 0;
}

static int i64_index_test(void) {
	mc_i64 a[16];
	for (int i = 0; i < 16; i++) a[i] = (mc_i64)0x4040404040404040ULL;
	for (int i = 0; i < 16; i++) {
		mc_u64 v = 0;
		v |= (mc_u64)(mc_u8)i;
		v |= (mc_u64)0xaaU << 8;
		v |= (mc_u64)0xbbU << 16;
		v |= (mc_u64)0xccU << 24;
		v |= (mc_u64)0xddU << 32;
		v |= (mc_u64)0xeeU << 40;
		v |= (mc_u64)0x11U << 48;
		v |= (mc_u64)0x22U << 56;
		a[i] = (mc_i64)v;
	}
	char hex[16 * 8 * 2 + 1];
	hex_encode((const mc_u8 *)a, 16 * 8, hex, sizeof(hex));
	(void)mc_write_str(1, "i64_index_test ");
	(void)mc_write_str(1, hex);
	(void)mc_write_all(1, "\n", 1);
	return 0;
}

static int fe_index_test(void) {
	struct fe_like { mc_i64 v[16]; } a;
	for (int i = 0; i < 16; i++) a.v[i] = (mc_i64)0x4040404040404040ULL;
	for (int i = 0; i < 16; i++) {
		mc_u64 v = 0;
		v |= (mc_u64)(mc_u8)i;
		v |= (mc_u64)0xaaU << 8;
		v |= (mc_u64)0xbbU << 16;
		v |= (mc_u64)0xccU << 24;
		v |= (mc_u64)0xddU << 32;
		v |= (mc_u64)0xeeU << 40;
		v |= (mc_u64)0x11U << 48;
		v |= (mc_u64)0x22U << 56;
		a.v[i] = (mc_i64)v;
	}
	char hex[16 * 8 * 2 + 1];
	hex_encode((const mc_u8 *)&a, 16 * 8, hex, sizeof(hex));
	(void)mc_write_str(1, "fe_index_test ");
	(void)mc_write_str(1, hex);
	(void)mc_write_all(1, "\n", 1);
	return 0;
}

static int dec_loop_test(void) {
	mc_i64 acc = 0;
	for (int pos = 9; pos >= 0; pos--) {
		acc = acc * 10 + (mc_i64)pos;
	}
	(void)mc_write_str(1, "dec_loop_test ");
	(void)mc_write_i64_dec(1, acc);
	(void)mc_write_all(1, "\n", 1);
	return 0;
}

static int dec_loop_gt0_test(void) {
	mc_i64 acc = 0;
	for (int pos = 9; pos > 0; pos--) {
		acc = acc * 10 + (mc_i64)pos;
	}
	(void)mc_write_str(1, "dec_loop_gt0_test ");
	(void)mc_write_i64_dec(1, acc);
	(void)mc_write_all(1, "\n", 1);
	return 0;
}

static int u16_pack_test(void) {
	mc_i64 t[16];
	for (int i = 0; i < 16; i++) {
		// Stay within 16-bit.
		t[i] = (mc_i64)(((mc_u16)i << 8) | (mc_u16)0xaa);
	}
	mc_u8 s[32];
	for (int i = 0; i < 16; i++) {
		mc_u16 v = (mc_u16)t[i];
		s[2 * i + 0] = (mc_u8)(v & 0xffu);
		s[2 * i + 1] = (mc_u8)(v >> 8);
	}
	char hex[32 * 2 + 1];
	hex_encode(s, 32, hex, sizeof(hex));
	(void)mc_write_str(1, "u16_pack_test ");
	(void)mc_write_str(1, hex);
	(void)mc_write_all(1, "\n", 1);
	return 0;
}

static int mul_loop_test(void) {
	// Model the key structure of fe_mul: nested i/j loops and t[i+j] accumulation.
	mc_i64 t[31];
	mc_memset(t, 0, sizeof(t));

	for (int i = 0; i < 16; i++) {
		for (int j = 0; j < 16; j++) {
			// Keep values small but non-trivial.
			t[i + j] += (mc_i64)(i + 1) * (mc_i64)(j + 1);
		}
	}

	for (int i = 0; i < 15; i++) {
		t[i] += (mc_i64)38 * t[i + 16];
	}

	// Hash-like fold into a printable hex string (avoid printing 31 i64 decimals).
	mc_u64 acc = 0x123456789abcdef0ULL;
	for (int i = 0; i < 16; i++) {
		acc ^= (mc_u64)t[i] + (acc << 1) + (acc >> 3);
		acc *= 0x9e3779b97f4a7c15ULL;
	}
	char hex[8 * 2 + 1];
	hex_encode((const mc_u8 *)&acc, 8, hex, sizeof(hex));
	(void)mc_write_str(1, "mul_loop_test ");
	(void)mc_write_str(1, hex);
	(void)mc_write_all(1, "\n", 1);
	return 0;
}

static int signed_shift_test(void) {
	// Exercise signed right shifts and borrow-style extraction used in fe_tobytes.
	static const mc_i64 xs[] = {
		0,
		1,
		-1,
		-2,
		(mc_i64)-65536,
		(mc_i64)-65537,
		(mc_i64)65535,
		(mc_i64)65536,
		(mc_i64)0x12345678,
		(mc_i64)-0x12345678,
	};

	mc_u64 acc = 0;
	for (mc_usize i = 0; i < (mc_usize)(sizeof(xs) / sizeof(xs[0])); i++) {
		mc_i64 x = xs[i];
		mc_i64 s = x >> 16; // must be arithmetic shift for negatives
		mc_i64 b = (s & 1);
		mc_i64 m = (-b) & (x ^ (x + 0x1111));
		acc ^= (mc_u64)s;
		acc ^= (mc_u64)(b * 0x9d);
		acc ^= (mc_u64)m + (acc << 7) + (acc >> 5);
	}

	char hex[8 * 2 + 1];
	hex_encode((const mc_u8 *)&acc, 8, hex, sizeof(hex));
	(void)mc_write_str(1, "signed_shift_test ");
	(void)mc_write_str(1, hex);
	(void)mc_write_all(1, "\n", 1);
	return 0;
}

static int stack_layout_test(void) {
	// Try to catch stack-frame offset/alignment bugs by creating lots of locals
	// with different sizes, then hashing their contents.
	struct fe_like { mc_i64 v[16]; } f0, f1, f2, f3, f4, f5, f6, f7;
	mc_u8 e[32];
	mc_u8 pad7[7];
	mc_i64 t[31];

	// Initialize with distinct byte patterns.
	mc_memset(&f0, 0x10, sizeof(f0));
	mc_memset(&f1, 0x11, sizeof(f1));
	mc_memset(&f2, 0x12, sizeof(f2));
	mc_memset(&f3, 0x13, sizeof(f3));
	mc_memset(&f4, 0x14, sizeof(f4));
	mc_memset(&f5, 0x15, sizeof(f5));
	mc_memset(&f6, 0x16, sizeof(f6));
	mc_memset(&f7, 0x17, sizeof(f7));
	mc_memset(e, 0xe0, sizeof(e));
	mc_memset(pad7, 0xa7, sizeof(pad7));
	for (int i = 0; i < 31; i++) t[i] = (mc_i64)(0x2020202020202020ULL + (mc_u64)i);

	// Do some writes that resemble real code (indexing, i+j, 64-bit arith).
	for (int i = 0; i < 16; i++) {
		f0.v[i] ^= (mc_i64)(i * 3);
		f7.v[15 - i] += (mc_i64)(i * 7);
	}
	for (int i = 0; i < 16; i++) {
		for (int j = 0; j < 16; j++) {
			t[i + j] += (mc_i64)(i + 1) * (mc_i64)(j + 2);
		}
	}
	for (int pos = 31; pos >= 0; pos--) {
		e[pos] = (mc_u8)(e[pos] ^ (mc_u8)(pos * 13));
	}

	// Invariants: f1..f6 are never written after their memset.
	int rc;
	rc = check_fill("f1", &f1, sizeof(f1), 0x11); if (rc) return rc;
	rc = check_fill("f2", &f2, sizeof(f2), 0x12); if (rc) return rc;
	rc = check_fill("f3", &f3, sizeof(f3), 0x13); if (rc) return rc;
	rc = check_fill("f4", &f4, sizeof(f4), 0x14); if (rc) return rc;
	rc = check_fill("f5", &f5, sizeof(f5), 0x15); if (rc) return rc;
	rc = check_fill("f6", &f6, sizeof(f6), 0x16); if (rc) return rc;
	rc = check_fill("pad7", pad7, sizeof(pad7), 0xa7); if (rc) return rc;

	// Hash per-local, then hash everything (helps localize stack layout bugs).
	const mc_u64 seed = 0x6a09e667f3bcc908ULL;
	mc_u64 h0 = seed; hash_bytes(&h0, (const mc_u8 *)&f0, sizeof(f0));
	mc_u64 h1 = seed; hash_bytes(&h1, (const mc_u8 *)&f1, sizeof(f1));
	mc_u64 h2 = seed; hash_bytes(&h2, (const mc_u8 *)&f2, sizeof(f2));
	mc_u64 h3 = seed; hash_bytes(&h3, (const mc_u8 *)&f3, sizeof(f3));
	mc_u64 h4 = seed; hash_bytes(&h4, (const mc_u8 *)&f4, sizeof(f4));
	mc_u64 h5 = seed; hash_bytes(&h5, (const mc_u8 *)&f5, sizeof(f5));
	mc_u64 h6 = seed; hash_bytes(&h6, (const mc_u8 *)&f6, sizeof(f6));
	mc_u64 h7 = seed; hash_bytes(&h7, (const mc_u8 *)&f7, sizeof(f7));
	mc_u64 he = seed; hash_bytes(&he, (const mc_u8 *)e, sizeof(e));
	mc_u64 hp = seed; hash_bytes(&hp, (const mc_u8 *)pad7, sizeof(pad7));
	mc_u64 ht = seed; hash_bytes(&ht, (const mc_u8 *)t, sizeof(t));

	mc_u64 acc = seed;
	hash_bytes(&acc, (const mc_u8 *)&f0, sizeof(f0));
	hash_bytes(&acc, (const mc_u8 *)&f1, sizeof(f1));
	hash_bytes(&acc, (const mc_u8 *)&f2, sizeof(f2));
	hash_bytes(&acc, (const mc_u8 *)&f3, sizeof(f3));
	hash_bytes(&acc, (const mc_u8 *)&f4, sizeof(f4));
	hash_bytes(&acc, (const mc_u8 *)&f5, sizeof(f5));
	hash_bytes(&acc, (const mc_u8 *)&f6, sizeof(f6));
	hash_bytes(&acc, (const mc_u8 *)&f7, sizeof(f7));
	hash_bytes(&acc, (const mc_u8 *)e, sizeof(e));
	hash_bytes(&acc, (const mc_u8 *)pad7, sizeof(pad7));
	hash_bytes(&acc, (const mc_u8 *)t, sizeof(t));

	(void)mc_write_str(1, "stack_layout_test");
	(void)mc_write_str(1, " f0="); mc_write_hex_u64(1, h0);
	(void)mc_write_str(1, " f1="); mc_write_hex_u64(1, h1);
	(void)mc_write_str(1, " f2="); mc_write_hex_u64(1, h2);
	(void)mc_write_str(1, " f3="); mc_write_hex_u64(1, h3);
	(void)mc_write_str(1, " f4="); mc_write_hex_u64(1, h4);
	(void)mc_write_str(1, " f5="); mc_write_hex_u64(1, h5);
	(void)mc_write_str(1, " f6="); mc_write_hex_u64(1, h6);
	(void)mc_write_str(1, " f7="); mc_write_hex_u64(1, h7);
	(void)mc_write_str(1, " e="); mc_write_hex_u64(1, he);
	(void)mc_write_str(1, " pad7="); mc_write_hex_u64(1, hp);
	(void)mc_write_str(1, " t="); mc_write_hex_u64(1, ht);
	(void)mc_write_str(1, " all="); mc_write_hex_u64(1, acc);
	(void)mc_write_all(1, "\n", 1);
	return 0;
}

static int inv_cond_test(void) {
	// Mirrors fe_inv's loop condition: if (a != 2 && a != 4) ...
	mc_i64 acc = 0x1234;
	for (int a = 253; a >= 0; a--) {
		acc = acc * 3 + (mc_i64)(a & 7);
		if (a != 2 && a != 4) {
			acc ^= (mc_i64)0x55aa55aa55aa55aaULL;
		} else {
			acc += (mc_i64)0x1111;
		}
	}
	(void)mc_write_str(1, "inv_cond_test ");
	mc_write_hex_u64(1, (mc_u64)acc);
	(void)mc_write_all(1, "\n", 1);
	return 0;
}

static void fe_carry_like(mc_i64 v[16]) {
	for (int i = 0; i < 16; i++) {
		v[i] += ((mc_i64)1 << 16);
		mc_i64 c = v[i] >> 16;
		v[i] -= c << 16;
		if (i == 15) v[0] += (c - 1) * 38;
		else v[i + 1] += (c - 1);
	}
}

static int carry_test(void) {
	mc_i64 v[16];
	v[0] = 0;
	v[1] = 1;
	v[2] = 65535;
	v[3] = 65536;
	v[4] = 65537;
	v[5] = -1;
	v[6] = -2;
	v[7] = -65535;
	v[8] = -65536;
	v[9] = -65537;
	v[10] = ((mc_i64)1 << 20) + 123;
	v[11] = -(((mc_i64)1 << 20) + 456);
	v[12] = ((mc_i64)1 << 32) + 7;
	v[13] = -(((mc_i64)1 << 32) + 9);
	v[14] = ((mc_i64)1 << 48) + 11;
	v[15] = -(((mc_i64)1 << 48) + 13);
	fe_carry_like(v);
	fe_carry_like(v);
	// Hash bytes of the final limbs.
	mc_u64 acc = 0xfeedfacedeadbeefULL;
	hash_bytes(&acc, (const mc_u8 *)v, sizeof(v));
	(void)mc_write_str(1, "carry_test ");
	mc_write_hex_u64(1, acc);
	(void)mc_write_all(1, "\n", 1);
	return 0;
}

// Minimal local reimplementation of the field + ladder step, so we can hash
// intermediate states and find the first divergence.
typedef struct { mc_i64 v[16]; } tfe;
static void tfe_0(tfe *o) { mc_memset(o, 0, sizeof(*o)); }
static void tfe_1(tfe *o) { tfe_0(o); o->v[0] = 1; }
static void tfe_copy(tfe *o, const tfe *a) { mc_memcpy(o, a, sizeof(*o)); }
static void tfe_add(tfe *o, const tfe *a, const tfe *b) {
	for (int i = 0; i < 16; i++) o->v[i] = a->v[i] + b->v[i];
}
static void tfe_sub(tfe *o, const tfe *a, const tfe *b) {
	for (int i = 0; i < 16; i++) o->v[i] = a->v[i] - b->v[i];
}
static void tfe_cswap(tfe *a, tfe *b, mc_i64 swap) {
	mc_i64 mask = -swap;
	for (int i = 0; i < 16; i++) {
		mc_i64 t = mask & (a->v[i] ^ b->v[i]);
		a->v[i] ^= t;
		b->v[i] ^= t;
	}
}
static void tfe_carry(tfe *o) {
	for (int i = 0; i < 16; i++) {
		o->v[i] += ((mc_i64)1 << 16);
		mc_i64 c = o->v[i] >> 16;
		o->v[i] -= c << 16;
		if (i == 15) o->v[0] += (c - 1) * 38;
		else o->v[i + 1] += (c - 1);
	}
}
static void tfe_mul(tfe *o, const tfe *a, const tfe *b) {
	mc_i64 t[31];
	mc_memset(t, 0, sizeof(t));
	for (int i = 0; i < 16; i++) {
		for (int j = 0; j < 16; j++) {
			t[i + j] += a->v[i] * b->v[j];
		}
	}
	for (int i = 0; i < 15; i++) {
		t[i] += 38 * t[i + 16];
	}
	for (int i = 0; i < 16; i++) o->v[i] = t[i];
	tfe_carry(o);
	tfe_carry(o);
}
static void tfe_sq(tfe *o, const tfe *a) { tfe_mul(o, a, a); }
static void tfe_frombytes(tfe *o, const mc_u8 s[32]) {
	for (int i = 0; i < 16; i++) {
		o->v[i] = (mc_i64)((mc_u32)s[2 * i] | ((mc_u32)s[2 * i + 1] << 8));
	}
	o->v[15] &= 0x7fffu;
}
static void clamp_scalar_local(mc_u8 k[32]) {
	k[0] &= 248u;
	k[31] &= 127u;
	k[31] |= 64u;
}

static int ladder_step_test(void) {
	// Use RFC7748 scalar, basepoint u=9.
	static const mc_u8 a_priv[32] = {
		0x77,0x07,0x6d,0x0a,0x73,0x18,0xa5,0x7d,0x3c,0x16,0xc1,0x72,0x51,0xb2,0x66,0x45,
		0xdf,0x4c,0x2f,0x87,0xeb,0xc0,0x99,0x2a,0xb1,0x77,0xfb,0xa5,0x1d,0xb9,0x2c,0x2a,
	};
	mc_u8 e[32];
	mc_memcpy(e, a_priv, 32);
	clamp_scalar_local(e);

	mc_u8 u_in[32];
	mc_memset(u_in, 0, sizeof(u_in));
	u_in[0] = 9;

	tfe x1, x2, z2, x3, z3;
	tfe_frombytes(&x1, u_in);
	tfe_1(&x2);
	tfe_0(&z2);
	tfe_copy(&x3, &x1);
	tfe_1(&z3);

	tfe a, aa, b, bb, e_fe;
	tfe c, d, da, cb;
	tfe tmp0, tmp1;

	mc_i64 swap = 0;
	tfe a24;
	tfe_0(&a24);
	a24.v[0] = 0xdb41;
	a24.v[1] = 1;

	// Trace the very first ladder iteration (pos=254) with checkpoints.
	const int pos = 254;
	(void)mc_write_str(1, "ladder254 e31=");
	mc_write_hex_u64(1, (mc_u64)e[31]);
	(void)mc_write_all(1, "\n", 1);
	int idx = (pos >> 3);
	int sh = (pos & 7);
	(void)mc_write_str(1, "ladder254 idx=");
	(void)mc_write_i64_dec(1, (mc_i64)idx);
	(void)mc_write_str(1, " sh=");
	(void)mc_write_i64_dec(1, (mc_i64)sh);
	(void)mc_write_all(1, "\n", 1);
	mc_i64 bit = (mc_i64)((e[idx] >> sh) & 1u);
	(void)mc_write_str(1, "ladder254 bit=");
	(void)mc_write_i64_dec(1, bit);
	(void)mc_write_all(1, "\n", 1);
	swap ^= bit;
	(void)mc_write_str(1, "ladder254 swap=");
	(void)mc_write_i64_dec(1, swap);
	(void)mc_write_all(1, "\n", 1);
	tfe_cswap(&x2, &x3, swap);
	tfe_cswap(&z2, &z3, swap);
	swap = bit;
	{
		mc_u64 h = 0x0123456789abcdefULL;
		hash_bytes(&h, (const mc_u8 *)&x2, sizeof(x2));
		hash_bytes(&h, (const mc_u8 *)&z2, sizeof(z2));
		hash_bytes(&h, (const mc_u8 *)&x3, sizeof(x3));
		hash_bytes(&h, (const mc_u8 *)&z3, sizeof(z3));
		(void)mc_write_str(1, "ladder254 cswap h=");
		mc_write_hex_u64(1, h);
		(void)mc_write_all(1, "\n", 1);
	}

	tfe_add(&a, &x2, &z2);
	tfe_sq(&aa, &a);
	tfe_sub(&b, &x2, &z2);
	tfe_sq(&bb, &b);
	tfe_sub(&e_fe, &aa, &bb);
	{
		mc_u64 h = 0x0123456789abcdefULL;
		hash_bytes(&h, (const mc_u8 *)&aa, sizeof(aa));
		hash_bytes(&h, (const mc_u8 *)&bb, sizeof(bb));
		hash_bytes(&h, (const mc_u8 *)&e_fe, sizeof(e_fe));
		(void)mc_write_str(1, "ladder254 aa_bb h=");
		mc_write_hex_u64(1, h);
		(void)mc_write_all(1, "\n", 1);
	}

	tfe_add(&c, &x3, &z3);
	tfe_sub(&d, &x3, &z3);
	tfe_mul(&da, &d, &a);
	tfe_mul(&cb, &c, &b);
	{
		mc_u64 h = 0x0123456789abcdefULL;
		hash_bytes(&h, (const mc_u8 *)&da, sizeof(da));
		hash_bytes(&h, (const mc_u8 *)&cb, sizeof(cb));
		(void)mc_write_str(1, "ladder254 da_cb h=");
		mc_write_hex_u64(1, h);
		(void)mc_write_all(1, "\n", 1);
	}

	tfe_add(&tmp0, &da, &cb);
	tfe_sq(&x3, &tmp0);
	tfe_sub(&tmp1, &da, &cb);
	tfe_sq(&tmp1, &tmp1);
	tfe_mul(&z3, &tmp1, &x1);
	{
		mc_u64 h = 0x0123456789abcdefULL;
		hash_bytes(&h, (const mc_u8 *)&x3, sizeof(x3));
		hash_bytes(&h, (const mc_u8 *)&z3, sizeof(z3));
		(void)mc_write_str(1, "ladder254 x3z3 h=");
		mc_write_hex_u64(1, h);
		(void)mc_write_all(1, "\n", 1);
	}

	tfe_mul(&x2, &aa, &bb);
	tfe_mul(&tmp0, &e_fe, &a24);
	tfe_add(&tmp0, &tmp0, &aa);
	tfe_mul(&z2, &e_fe, &tmp0);
	{
		mc_u64 h = 0x0123456789abcdefULL;
		hash_bytes(&h, (const mc_u8 *)&x2, sizeof(x2));
		hash_bytes(&h, (const mc_u8 *)&z2, sizeof(z2));
		(void)mc_write_str(1, "ladder254 x2z2 h=");
		mc_write_hex_u64(1, h);
		(void)mc_write_all(1, "\n", 1);
	}
	return 0;
}

static int clamp_test(void) {
	static const mc_u8 a_priv[32] = {
		0x77,0x07,0x6d,0x0a,0x73,0x18,0xa5,0x7d,0x3c,0x16,0xc1,0x72,0x51,0xb2,0x66,0x45,
		0xdf,0x4c,0x2f,0x87,0xeb,0xc0,0x99,0x2a,0xb1,0x77,0xfb,0xa5,0x1d,0xb9,0x2c,0x2a,
	};
	mc_u8 e[32];
	mc_memcpy(e, a_priv, 32);
	(void)mc_write_str(1, "clamp_test before e31=");
	mc_write_hex_u64(1, (mc_u64)e[31]);
	(void)mc_write_all(1, "\n", 1);
	clamp_scalar_local(e);
	(void)mc_write_str(1, "clamp_test after  e31=");
	mc_write_hex_u64(1, (mc_u64)e[31]);
	(void)mc_write_all(1, "\n", 1);
	mc_i64 bit = (mc_i64)((e[31] >> 6) & 1u);
	(void)mc_write_str(1, "clamp_test bit254=");
	(void)mc_write_i64_dec(1, bit);
	(void)mc_write_all(1, "\n", 1);
	return 0;
}

__attribute__((used)) int main(int argc, char **argv, char **envp) {
	(void)envp;
	const char *argv0 = (argc > 0 && argv && argv[0]) ? argv[0] : "x25519";
	if (argc != 2 || !argv[1]) x_usage(argv0);
	if (streq(argv[1], "--index-test")) return index_test();
	if (streq(argv[1], "--i64-index-test")) return i64_index_test();
	if (streq(argv[1], "--fe-index-test")) return fe_index_test();
	if (streq(argv[1], "--u16-pack-test")) return u16_pack_test();
	if (streq(argv[1], "--mul-loop-test")) return mul_loop_test();
	if (streq(argv[1], "--signed-shift-test")) return signed_shift_test();
	if (streq(argv[1], "--stack-layout-test")) return stack_layout_test();
	if (streq(argv[1], "--inv-cond-test")) return inv_cond_test();
	if (streq(argv[1], "--carry-test")) return carry_test();
	if (streq(argv[1], "--clamp-test")) return clamp_test();
	if (streq(argv[1], "--ladder-step-test")) return ladder_step_test();
	if (streq(argv[1], "--memtest")) return mem_test();
	if (streq(argv[1], "--dec-loop-test")) return dec_loop_test();
	if (streq(argv[1], "--dec-loop-gt0-test")) return dec_loop_gt0_test();
	int want_pub = streq(argv[1], "--pub-test");
	if (!want_pub && !streq(argv[1], "--rfc7748-1")) x_usage(argv0);

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
	if (want_pub) {
		char ha[32 * 2 + 1];
		char hb[32 * 2 + 1];
		hex_encode(a_pub, 32, ha, sizeof(ha));
		hex_encode(b_pub, 32, hb, sizeof(hb));
		(void)mc_write_str(1, "a_pub ");
		(void)mc_write_str(1, ha);
		(void)mc_write_str(1, "\nb_pub ");
		(void)mc_write_str(1, hb);
		(void)mc_write_str(1, "\n");
		return 0;
	}

	mc_u8 s1[32];
	mc_u8 s2[32];
	int rc1 = mc_x25519_shared(s1, a_priv, b_pub);
	int rc2 = mc_x25519_shared(s2, b_priv, a_pub);
	if (rc1 != 0 || rc2 != 0) {
		char ha[32 * 2 + 1];
		char hb[32 * 2 + 1];
		char h1[32 * 2 + 1];
		char h2[32 * 2 + 1];
		hex_encode(a_pub, 32, ha, sizeof(ha));
		hex_encode(b_pub, 32, hb, sizeof(hb));
		hex_encode(s1, 32, h1, sizeof(h1));
		hex_encode(s2, 32, h2, sizeof(h2));
		(void)mc_write_str(2, "mc_x25519_shared failed\n");
		(void)mc_write_str(2, "rc1=");
		(void)mc_write_i64_dec(2, (mc_i64)rc1);
		(void)mc_write_str(2, " rc2=");
		(void)mc_write_i64_dec(2, (mc_i64)rc2);
		(void)mc_write_str(2, "\n");
		(void)mc_write_str(2, "a_pub ");
		(void)mc_write_str(2, ha);
		(void)mc_write_str(2, "\nb_pub ");
		(void)mc_write_str(2, hb);
		(void)mc_write_str(2, "\ns1 ");
		(void)mc_write_str(2, h1);
		(void)mc_write_str(2, "\ns2 ");
		(void)mc_write_str(2, h2);
		(void)mc_write_str(2, "\n");
		return 1;
	}
	if (mc_memcmp(s1, s2, 32) != 0) {
		char h1[32 * 2 + 1];
		char h2[32 * 2 + 1];
		hex_encode(s1, 32, h1, sizeof(h1));
		hex_encode(s2, 32, h2, sizeof(h2));
		(void)mc_write_str(2, "mismatch s1!=s2\n");
		(void)mc_write_str(2, "s1 ");
		(void)mc_write_str(2, h1);
		(void)mc_write_str(2, "\ns2 ");
		(void)mc_write_str(2, h2);
		(void)mc_write_str(2, "\n");
		return 3;
	}
	if (mc_memcmp(s1, exp_shared, 32) != 0) {
		char h1[32 * 2 + 1];
		char he[32 * 2 + 1];
		hex_encode(s1, 32, h1, sizeof(h1));
		hex_encode(exp_shared, 32, he, sizeof(he));
		(void)mc_write_str(2, "mismatch expected\n");
		(void)mc_write_str(2, "got ");
		(void)mc_write_str(2, h1);
		(void)mc_write_str(2, "\nexp ");
		(void)mc_write_str(2, he);
		(void)mc_write_str(2, "\n");
		return 4;
	}

	char hex[32 * 2 + 1];
	hex_encode(s1, 32, hex, sizeof(hex));
	(void)mc_write_str(1, "shared ");
	(void)mc_write_str(1, hex);
	(void)mc_write_all(1, "\n", 1);
	return 0;
}
