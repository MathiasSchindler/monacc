#include "mc.h"
#include "mc_mathf.h"

static mc_u32 fbits(float x)
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

static float ffrombits(mc_u32 b)
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

static float fabsf_local(float x)
{
	mc_u32 b = fbits(x);
	b &= 0x7FFFFFFFu;
	return ffrombits(b);
}

static int feq_eps(float a, float b, float eps)
{
	float d = a - b;
	if (d < 0.0f) d = -d;
	return d <= eps;
}

static void die(const char *msg)
{
	(void)mc_write_str(2, msg);
	(void)mc_write_str(2, "\n");
	mc_exit(1);
}

int main(void)
{
	(void)mc_write_str(1, "=== mc_mathf tests ===\n");

	/* exp */
	if (!feq_eps(mc_expf(0.0f), 1.0f, 0.01f)) die("exp(0) != 1");
	if (!feq_eps(mc_expf(0.69314718f), 2.0f, 0.05f)) die("exp(ln2) != 2");
	if (!feq_eps(mc_expf(-0.69314718f), 0.5f, 0.03f)) die("exp(-ln2) != 0.5");
	if (!feq_eps(mc_expf(1.0f), 2.71828f, 0.10f)) die("exp(1) not approx e");

	/* sqrt */
	if (!feq_eps(mc_sqrtf(0.0f), 0.0f, 0.001f)) die("sqrt(0) != 0");
	if (!feq_eps(mc_sqrtf(1.0f), 1.0f, 0.01f)) die("sqrt(1) != 1");
	if (!feq_eps(mc_sqrtf(4.0f), 2.0f, 0.02f)) die("sqrt(4) != 2");
	if (!feq_eps(mc_sqrtf(2.0f), 1.41421f, 0.03f)) die("sqrt(2) not approx");

	/* tanh */
	if (!feq_eps(mc_tanhf(0.0f), 0.0f, 0.01f)) die("tanh(0) != 0");
	if (!feq_eps(mc_tanhf(1.0f), 0.76159f, 0.08f)) die("tanh(1) not approx");
	if (!feq_eps(mc_tanhf(-1.0f), -0.76159f, 0.08f)) die("tanh(-1) not approx");

	/* sanity: |tanh(x)| <= 1 for some points */
	{
		float v = mc_tanhf(3.0f);
		if (fabsf_local(v) > 1.001f) die("tanh(3) magnitude > 1");
	}

	(void)mc_write_str(1, "OK\n");
	mc_exit(0);
	return 0;
}
