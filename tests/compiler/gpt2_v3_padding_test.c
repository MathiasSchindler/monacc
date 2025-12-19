#include "mc.h"

#define PROT_READ 1
#define MAP_PRIVATE 2

#define GPT2_MAGIC 0x32545047u /* "GPT2" little-endian */
#define GPT2_VERSION_Q 3u
#define GPT2_QTYPE_Q8 1u

static void die(const char *msg)
{
	(void)mc_write_str(2, msg);
	(void)mc_write_str(2, "\n");
	mc_exit(1);
}

static void usage(void)
{
	(void)mc_write_str(2, "Usage: gpt2_v3_padding_test <model.bin>\n");
	mc_exit(2);
}

static mc_u32 pad16_u32(mc_u32 n)
{
	return (16u - (n & 15u)) & 15u;
}

int main(int argc, char **argv)
{
	if (argc != 2) usage();
	const char *path = argv[1];

	mc_i64 fd = mc_sys_openat(MC_AT_FDCWD, path, MC_O_RDONLY, 0);
	if (fd < 0) die("openat failed");

	struct mc_stat st;
	if (mc_sys_fstat((mc_i32)fd, &st) < 0) die("fstat failed");
	mc_usize size = (mc_usize)st.st_size;

	mc_i64 addr = mc_sys_mmap(MC_NULL, size, PROT_READ, MAP_PRIVATE, (mc_i32)fd, 0);
	mc_sys_close((mc_i32)fd);
	if (addr < 0) die("mmap failed");

	if (size < 64) die("file too small");
	mc_u8 *data = (mc_u8 *)addr;
	mc_u32 *hdr = (mc_u32 *)data;

	if (hdr[0] != GPT2_MAGIC) die("bad magic");
	if (hdr[1] != GPT2_VERSION_Q) die("not v3");

	mc_u32 n_vocab = hdr[2];
	mc_u32 n_embd = hdr[4];
	mc_u32 qtype = hdr[7];
	mc_u32 wte_quant = hdr[8] & 1u;

	if (qtype != GPT2_QTYPE_Q8) die("not q8");
	if (!wte_quant) die("wte not quantized (expected for q8)");

	mc_u32 stride = 4u + n_embd;
	mc_u32 wte_q_bytes = n_vocab * stride;
	mc_u32 pad = pad16_u32(wte_q_bytes);

	mc_u64 off_pad = 64u + (mc_u64)wte_q_bytes;
	mc_u64 off_wpe = off_pad + (mc_u64)pad;
	if (off_wpe > (mc_u64)size) die("file truncated");
	if ((off_wpe & 15u) != 0u) die("wpe not 16-byte aligned");

	for (mc_u32 i = 0; i < pad; i++) {
		if (data[off_pad + i] != 0) die("pad16 bytes are not zero");
	}

	(void)mc_write_str(1, "OK\n");
	mc_exit(0);
	return 0;
}
