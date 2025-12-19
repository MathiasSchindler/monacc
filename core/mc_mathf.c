#include "mc_mathf.h"

MC_INLINE mc_u32 mc_f32_bits(float x)
{
	mc_u32 b;
	const mc_u8 *s = (const mc_u8 *)&x;
	mc_u8 *d = (mc_u8 *)&b;
	d[0] = s[0];
	d[1] = s[1];
	d[2] = s[2];
	d[3] = s[3];
	return b;
}

MC_INLINE float mc_f32_from_bits(mc_u32 b)
{
	float x;
	const mc_u8 *s = (const mc_u8 *)&b;
	mc_u8 *d = (mc_u8 *)&x;
	d[0] = s[0];
	d[1] = s[1];
	d[2] = s[2];
	d[3] = s[3];
	return x;
}

static float mc_ldexpf(float x, int k)
{
	mc_u32 b = mc_f32_bits(x);
	mc_u32 exp = (b >> 23) & 0xFFu;
	if (exp == 0) {
		/* zero/subnormal: keep it simple for our use (exp(r) is normal) */
		return x;
	}
	int newexp = (int)exp + k;
	if (newexp <= 0) {
		return 0.0f;
	}
	if (newexp >= 255) {
		mc_u32 inf = (b & 0x80000000u) | (0xFFu << 23);
		return mc_f32_from_bits(inf);
	}
	b = (b & 0x807FFFFFu) | ((mc_u32)newexp << 23);
	return mc_f32_from_bits(b);
}

/* Fast approximate exp using Taylor series with base-2 range reduction.
 * Accuracy is "good enough" for softmax/layernorm style workloads.
 */
float mc_expf(float x)
{
	/* Clamp to avoid overflow. expf(88) ~ 1.65e38 (near float max). */
	if (x > 88.0f) x = 88.0f;
	if (x < -88.0f) return 0.0f;

	/* Range reduction: x = k*ln2 + r, exp(x) = 2^k * exp(r) */
	float ln2 = 0.6931471805599453f;
	float fk = x / ln2;
	int k = (int)fk;
	/* floor(fk) without libc: if trunc overshoots, decrement */
	if ((float)k > fk) k--;
	float r = x - (float)k * ln2;

	/* exp(r) for small r via truncated Taylor series */
	float result = 1.0f;
	float term = 1.0f;
	for (int i = 1; i <= 12; i++) {
		term *= r / (float)i;
		result += term;
	}

	return mc_ldexpf(result, k);
}

/* Fast approximate sqrt using Newton-Raphson */
float mc_sqrtf(float x)
{
	if (x <= 0.0f) return 0.0f;

	float guess = x;
	mc_u32 bits = mc_f32_bits(guess);
	bits = (1u << 29) + (bits >> 1) - (1u << 22);
	guess = mc_f32_from_bits(bits);

	for (int i = 0; i < 4; i++) {
		guess = 0.5f * (guess + x / guess);
	}

	return guess;
}

/* Approximate tanh using exp */
float mc_tanhf(float x)
{
	if (x > 10.0f) return 1.0f;
	if (x < -10.0f) return -1.0f;
	float e2x = mc_expf(2.0f * x);
	return (e2x - 1.0f) / (e2x + 1.0f);
}

mc_i64 mc_write_transposed_f32(mc_i32 out_fd, const float *src, mc_u32 in_dim, mc_u32 out_dim)
{
	/* Chunked to avoid large stack buffers; tuned for typical GPT-2 dims. */
	float buf[1024];

	if (!src) return (mc_i64)-MC_EINVAL;
	if (in_dim == 0 || out_dim == 0) return (mc_i64)-MC_EINVAL;

	for (mc_u32 out = 0; out < out_dim; out++) {
		mc_u32 in_off = 0;
		while (in_off < in_dim) {
			mc_u32 chunk = in_dim - in_off;
			if (chunk > (mc_u32)(sizeof(buf) / sizeof(buf[0]))) {
				chunk = (mc_u32)(sizeof(buf) / sizeof(buf[0]));
			}

			for (mc_u32 i = 0; i < chunk; i++) {
				mc_u32 in = in_off + i;
				buf[i] = src[in * out_dim + out];
			}

			mc_i64 r = mc_write_all(out_fd, buf, (mc_usize)chunk * (mc_usize)4);
			if (r < 0) return r;
			in_off += chunk;
		}
	}

	return 0;
}
