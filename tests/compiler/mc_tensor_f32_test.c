#include "mc.h"
#include "mc_mathf.h"

/* Writes a small matrix using transpose-writer, mmaps it back, and verifies bytes. */

#define PROT_READ 1
#define MAP_PRIVATE 2

static void die(const char *msg)
{
	(void)mc_write_str(2, msg);
	(void)mc_write_str(2, "\n");
	mc_exit(1);
}

static int feq(float a, float b)
{
	mc_u32 ba;
	mc_u32 bb;
	{
		const mc_u8 *s = (const mc_u8 *)&a;
		mc_u8 *d = (mc_u8 *)&ba;
		d[0] = s[0];
		d[1] = s[1];
		d[2] = s[2];
		d[3] = s[3];
	}
	{
		const mc_u8 *s = (const mc_u8 *)&b;
		mc_u8 *d = (mc_u8 *)&bb;
		d[0] = s[0];
		d[1] = s[1];
		d[2] = s[2];
		d[3] = s[3];
	}
	return ba == bb;
}

int main(void)
{
	(void)mc_write_str(1, "=== transpose tests ===\n");

	/* src is [in_dim=3][out_dim=2]
	 * [ [1,2],
	 *   [3,4],
	 *   [5,6] ]
	 * Transposed output should be [out_dim=2][in_dim=3]:
	 * [ [1,3,5],
	 *   [2,4,6] ]
	 */
	float src[6];
	src[0] = 1.0f;
	src[1] = 2.0f;
	src[2] = 3.0f;
	src[3] = 4.0f;
	src[4] = 5.0f;
	src[5] = 6.0f;

	const char *path = "build/transpose_test.bin";
	mc_i64 fd = mc_sys_openat(MC_AT_FDCWD, path, MC_O_WRONLY | MC_O_CREAT | MC_O_TRUNC, 0644);
	if (fd < 0) die("openat failed");

	mc_i64 wr = mc_write_transposed_f32((mc_i32)fd, src, 3, 2);
	if (wr < 0) die("transpose write failed");
	mc_sys_close((mc_i32)fd);

	mc_i64 rfd = mc_sys_openat(MC_AT_FDCWD, path, MC_O_RDONLY, 0);
	if (rfd < 0) die("reopen failed");

	struct mc_stat st;
	if (mc_sys_fstat((mc_i32)rfd, &st) < 0) die("fstat failed");
	if ((mc_usize)st.st_size != (mc_usize)(6 * 4)) die("bad output size");

	mc_i64 addr = mc_sys_mmap(MC_NULL, (mc_usize)st.st_size, PROT_READ, MAP_PRIVATE, (mc_i32)rfd, 0);
	mc_sys_close((mc_i32)rfd);
	if (addr < 0) die("mmap failed");

	float *dst = (float *)addr;
	if (!feq(dst[0], 1.0f)) die("dst[0] != 1");
	if (!feq(dst[1], 3.0f)) die("dst[1] != 3");
	if (!feq(dst[2], 5.0f)) die("dst[2] != 5");
	if (!feq(dst[3], 2.0f)) die("dst[3] != 2");
	if (!feq(dst[4], 4.0f)) die("dst[4] != 4");
	if (!feq(dst[5], 6.0f)) die("dst[5] != 6");

	(void)mc_write_str(1, "OK\n");
	mc_exit(0);
	return 0;
}
