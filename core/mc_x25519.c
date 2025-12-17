#include "mc.h"
#include "mc_x25519.h"

// Field arithmetic mod p = 2^255 - 19.
// Representation: 16 limbs, base 2^16, little-endian.
//
// This keeps multiplication within 64-bit ranges without relying on 128-bit.

typedef struct {
	mc_i64 v[16];
} fe;

static void fe_0(fe *o) { mc_memset(o, 0, sizeof(*o)); }
static void fe_1(fe *o) { fe_0(o); o->v[0] = 1; }
static void fe_copy(fe *o, const fe *a) { mc_memcpy(o, a, sizeof(*o)); }

static void fe_add(fe *o, const fe *a, const fe *b) {
	for (int i = 0; i < 16; i++) o->v[i] = a->v[i] + b->v[i];
}

static void fe_sub(fe *o, const fe *a, const fe *b) {
	for (int i = 0; i < 16; i++) o->v[i] = a->v[i] - b->v[i];
}

static void fe_cswap(fe *a, fe *b, mc_i64 swap) {
	// swap is 0 or 1
	mc_i64 mask = -swap;
	for (int i = 0; i < 16; i++) {
		mc_i64 t = mask & (a->v[i] ^ b->v[i]);
		a->v[i] ^= t;
		b->v[i] ^= t;
	}
}

static void fe_carry(fe *o) {
	// Normalize limbs to [0, 2^16).
	for (int i = 0; i < 16; i++) {
		o->v[i] += ((mc_i64)1 << 16);
		mc_i64 c = o->v[i] >> 16;
		o->v[i] -= c << 16;
		if (i == 15) o->v[0] += (c - 1) * 38;
		else o->v[i + 1] += (c - 1);
	}
}

static void fe_mul(fe *o, const fe *a, const fe *b) {
	mc_i64 t[31];
	mc_memset(t, 0, sizeof(t));

	for (int i = 0; i < 16; i++) {
		for (int j = 0; j < 16; j++) {
			t[i + j] += a->v[i] * b->v[j];
		}
	}

	// Fold high limbs via 2^256 ≡ 38 (mod p)
	for (int i = 0; i < 15; i++) {
		t[i] += 38 * t[i + 16];
	}

	for (int i = 0; i < 16; i++) o->v[i] = t[i];
	fe_carry(o);
	fe_carry(o);
}

static void fe_sq(fe *o, const fe *a) {
	fe_mul(o, a, a);
}

static void fe_frombytes(fe *o, const mc_u8 s[32]) {
	for (int i = 0; i < 16; i++) {
		o->v[i] = (mc_i64)((mc_u32)s[2 * i] | ((mc_u32)s[2 * i + 1] << 8));
	}
	o->v[15] &= 0x7fffu;
}

static void fe_select(fe *o, const fe *a, const fe *b, mc_i64 sel) {
	// sel: 0 => a, 1 => b
	mc_i64 mask = -sel;
	for (int i = 0; i < 16; i++) {
		mc_i64 x = a->v[i];
		mc_i64 y = b->v[i];
		o->v[i] = x ^ (mask & (x ^ y));
	}
}

static void fe_tobytes(mc_u8 s[32], const fe *n) {
	fe t;
	fe m;
	fe_copy(&t, n);

	// Ensure t is reduced.
	fe_carry(&t);
	fe_carry(&t);
	fe_carry(&t);

	static const mc_i64 p[16] = {
		0xffed,0xffff,0xffff,0xffff,0xffff,0xffff,0xffff,0xffff,
		0xffff,0xffff,0xffff,0xffff,0xffff,0xffff,0xffff,0x7fff,
	};

	// m = t - p (with borrows)
	m.v[0] = t.v[0] - p[0];
	for (int i = 1; i < 16; i++) {
		mc_i64 borrow = (m.v[i - 1] >> 16) & 1;
		m.v[i] = t.v[i] - p[i] - borrow;
	}

	mc_i64 neg = (m.v[15] >> 16) & 1; // 1 if negative
	// If m is non-negative, select m; else keep t.
	fe_select(&t, &t, &m, 1 - neg);

	for (int i = 0; i < 16; i++) {
		mc_u16 v = (mc_u16)t.v[i];
		s[2 * i + 0] = (mc_u8)(v & 0xffu);
		s[2 * i + 1] = (mc_u8)(v >> 8);
	}
}

static void fe_inv(fe *o, const fe *i) {
	// Exponentiation to p-2.
	fe c;
	fe_copy(&c, i);
	for (int a = 253; a >= 0; a--) {
		fe_sq(&c, &c);
		if (a != 2 && a != 4) {
			fe_mul(&c, &c, i);
		}
	}
	fe_copy(o, &c);
}

static void clamp_scalar(mc_u8 k[32]) {
	k[0] &= 248u;
	k[31] &= 127u;
	k[31] |= 64u;
}

static void x25519_scalar_mult(mc_u8 out[32], const mc_u8 scalar_in[32], const mc_u8 u_in[32]) {
	mc_u8 e[32];
	mc_memcpy(e, scalar_in, 32);
	clamp_scalar(e);

	fe x1, x2, z2, x3, z3;
	fe_frombytes(&x1, u_in);
	fe_1(&x2);
	fe_0(&z2);
	fe_copy(&x3, &x1);
	fe_1(&z3);

	fe a, aa, b, bb, e_fe;
	fe c, d, da, cb;
	fe tmp0, tmp1;

	mc_i64 swap = 0;

	// a24 = 121665 = 0x1db41
	fe a24;
	fe_0(&a24);
	a24.v[0] = 0xdb41;
	a24.v[1] = 1;

	for (int pos = 254; pos >= 0; pos--) {
		mc_i64 bit = (mc_i64)((e[pos >> 3] >> (pos & 7)) & 1u);
		swap ^= bit;
		fe_cswap(&x2, &x3, swap);
		fe_cswap(&z2, &z3, swap);
		swap = bit;

		fe_add(&a, &x2, &z2);
		fe_sq(&aa, &a);
		fe_sub(&b, &x2, &z2);
		fe_sq(&bb, &b);
		fe_sub(&e_fe, &aa, &bb);

		fe_add(&c, &x3, &z3);
		fe_sub(&d, &x3, &z3);
		fe_mul(&da, &d, &a);
		fe_mul(&cb, &c, &b);

		fe_add(&tmp0, &da, &cb);
		fe_sq(&x3, &tmp0);
		fe_sub(&tmp1, &da, &cb);
		fe_sq(&tmp1, &tmp1);
		fe_mul(&z3, &tmp1, &x1);

		fe_mul(&x2, &aa, &bb);
		fe_mul(&tmp0, &e_fe, &a24);
		fe_add(&tmp0, &tmp0, &aa);
		fe_mul(&z2, &e_fe, &tmp0);
	}

	fe_cswap(&x2, &x3, swap);
	fe_cswap(&z2, &z3, swap);

	fe_inv(&z2, &z2);
	fe_mul(&x2, &x2, &z2);
	fe_tobytes(out, &x2);
}

void mc_x25519_public(mc_u8 public_key[MC_X25519_KEY_SIZE], const mc_u8 private_key[MC_X25519_KEY_SIZE]) {
	mc_u8 base[32];
	mc_memset(base, 0, sizeof(base));
	base[0] = 9;
	x25519_scalar_mult(public_key, private_key, base);
}

int mc_x25519_shared(
	mc_u8 shared[MC_X25519_KEY_SIZE],
	const mc_u8 private_key[MC_X25519_KEY_SIZE],
	const mc_u8 peer_public[MC_X25519_KEY_SIZE]
) {
	x25519_scalar_mult(shared, private_key, peer_public);
	mc_u8 acc = 0;
	for (int i = 0; i < 32; i++) acc |= shared[i];
	return acc ? 0 : -1;
}
